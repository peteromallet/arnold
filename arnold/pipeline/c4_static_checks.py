"""C4 static authoring-API checks.

A pure, side-effect-free static validation pass over a :class:`Pipeline`
declaration. Returns a list of :class:`StaticCheckFinding` records that the
acceptance gate / CLI verb can render. The check is intentionally
declaration-only — it does not execute the pipeline.

Four passes (in order):

1. ``ports`` — every consumer ``PortRef`` resolves to a producer that
   actually declares the named port, and producer/consumer logical-types
   agree.
2. ``schemas`` — every typed port declares a JSON schema (when the
   underlying type carries one) and the schema is hash-stable.
3. ``structural-subset`` — for each producer→consumer edge, the
   producer's emitted schema is a structural subset of the consumer's
   accepted schema, via :func:`is_structural_subset`.
4. ``call-sites`` — every authored stage is invocable through the
   :class:`StepInvocationAdapterRegistry` (default registry) — i.e.
   has a registered adapter for its ``kind``.

Each finding carries a stable ``locus`` of the form ``pipeline:<name>``,
``stage:<step_id>``, ``port:<step>.<port>``, or ``edge:<from>→<to>``,
together with a short ``code`` and a human-readable ``detail``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from arnold.pipeline.declaration_lowering import lower_stage_declarations
from arnold.pipeline.schema_registry import (
    AcceptedVersionRange,
    SchemaRegistryError,
)


@dataclass(frozen=True)
class StaticCheckFinding:
    """One static-check failure with stable locus."""

    pass_name: str
    code: str
    locus: str
    detail: str


@dataclass
class StaticCheckReport:
    """Outcome of :func:`run_c4_static_checks`.

    ``findings`` are hard failures (``ok`` is ``False`` when any exist).
    ``warnings`` are non-fatal advisory findings that never affect ``ok``.
    """

    findings: list[StaticCheckFinding] = field(default_factory=list)
    warnings: list[StaticCheckFinding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.findings


# ---------------------------------------------------------------------------
# Structural-subset helper
# ---------------------------------------------------------------------------


_JSON_TYPE_WIDENING: dict[str, frozenset[str]] = {
    "integer": frozenset({"integer", "number"}),
    "number": frozenset({"number"}),
    "string": frozenset({"string"}),
    "boolean": frozenset({"boolean"}),
    "array": frozenset({"array"}),
    "object": frozenset({"object"}),
    "null": frozenset({"null"}),
}


def _normalize_type(t: Any) -> frozenset[str]:
    if t is None:
        return frozenset()
    if isinstance(t, str):
        return frozenset({t})
    if isinstance(t, (list, tuple)):
        return frozenset(str(x) for x in t)
    return frozenset()


def is_structural_subset(
    producer_schema: Mapping[str, Any] | None,
    consumer_schema: Mapping[str, Any] | None,
) -> bool:
    """Return True iff every value matching ``producer_schema`` also matches
    ``consumer_schema``.

    Conservative — handles a working JSON-Schema subset: ``type``,
    ``required``, ``properties``, ``items``, ``enum``, ``nullable``,
    ``additionalProperties``. Treats missing keys on the consumer side
    as "no constraint" (consumer is wider).

    Direction matters: producer is the value-space; consumer is the
    accepted-space. The check is "producer ⊆ consumer".
    """
    if consumer_schema is None or not consumer_schema:
        return True
    if producer_schema is None:
        return False

    # Type widening: producer types must be a subset of consumer's
    # allowed types (with integer→number widening permitted because
    # every integer IS a number).
    p_types = _normalize_type(producer_schema.get("type"))
    c_types = _normalize_type(consumer_schema.get("type"))
    if c_types:
        if not p_types:
            return False
        for pt in p_types:
            widenings = _JSON_TYPE_WIDENING.get(pt, frozenset({pt}))
            if not (widenings & c_types):
                return False

    # Nullability: if producer permits null but consumer does not, fail.
    p_nullable = bool(producer_schema.get("nullable")) or "null" in p_types
    c_nullable = bool(consumer_schema.get("nullable")) or "null" in c_types
    if p_nullable and not c_nullable:
        return False

    # Enum subset: producer's enum must be ⊆ consumer's enum.
    p_enum = producer_schema.get("enum")
    c_enum = consumer_schema.get("enum")
    if c_enum is not None:
        if p_enum is None:
            return False
        if not set(_hashable(x) for x in p_enum).issubset(
            set(_hashable(x) for x in c_enum)
        ):
            return False

    # Required-subset: consumer's required keys must all be in producer's
    # required keys (producer must at least promise everything the consumer
    # demands).
    p_required = set(producer_schema.get("required", []) or [])
    c_required = set(consumer_schema.get("required", []) or [])
    if not c_required.issubset(p_required):
        return False

    # Properties recursion.
    p_props = producer_schema.get("properties") or {}
    c_props = consumer_schema.get("properties") or {}
    for prop_name, c_prop_schema in c_props.items():
        if prop_name not in p_props:
            # If the consumer demands a typed property the producer doesn't
            # declare, treat as a violation (producer might emit anything).
            if prop_name in c_required:
                return False
            continue
        if not is_structural_subset(p_props[prop_name], c_prop_schema):
            return False

    # additionalProperties: if consumer forbids them, producer must too.
    c_addl = consumer_schema.get("additionalProperties")
    p_addl = producer_schema.get("additionalProperties")
    if c_addl is False and p_addl is not False:
        # Producer might allow extra keys consumer rejects. If producer's
        # properties is a strict subset of consumer's properties AND producer
        # also forbids additionalProperties implicitly, allow it; otherwise
        # require an explicit match.
        if p_addl is not False:
            return False

    # items recursion for arrays.
    p_items = producer_schema.get("items")
    c_items = consumer_schema.get("items")
    if c_items is not None and p_items is not None:
        if not is_structural_subset(p_items, c_items):
            return False

    return True


def _hashable(x: Any) -> Any:
    if isinstance(x, (list, tuple)):
        return tuple(_hashable(v) for v in x)
    if isinstance(x, dict):
        return tuple(sorted((k, _hashable(v)) for k, v in x.items()))
    return x


# ---------------------------------------------------------------------------
# Helpers: stage iteration and port-name access
# ---------------------------------------------------------------------------


def _iter_stages(pipeline: Any):
    """Yield (stage_id, stage) pairs from *pipeline.stages*.

    Supports both mapping-shaped stages (``Mapping[str, Stage]``) and
    list-like fixtures (``Sequence[Stage]``).  Stage identity is taken from
    the mapping key or from ``stage.id`` / ``stage.name`` for list inputs.
    """
    stages = getattr(pipeline, "stages", None)
    if stages is None:
        return
    if isinstance(stages, Mapping):
        for key, stage in stages.items():
            yield key, stage
    else:
        for stage in stages:
            stage_id = getattr(stage, "id", None) or getattr(stage, "name", "")
            yield stage_id, stage


def _get_port_name(port: Any) -> str | None:
    """Return the name of *port*, supporting both ``Port.name`` and ``PortRef.port_name``."""
    name = getattr(port, "name", None)
    if name is not None:
        return name
    return getattr(port, "port_name", None)


def _stage_port_map(stage: Any, attr: str) -> dict[str | None, Any]:
    """Return ``{port_name: port}`` for *stage.<attr>* using :func:`_get_port_name`."""
    ports = getattr(stage, attr, None) or ()
    return {_get_port_name(p): p for p in ports}


def _effective_stage_ports(stage: Any, attr: str) -> tuple[Any, ...]:
    lowered = lower_stage_declarations(stage)
    if attr == "produces":
        return tuple(lowered.effective_produces)
    if attr == "consumes":
        return tuple(lowered.effective_consumes)
    raise ValueError(f"unsupported port attr {attr!r}")


def _effective_stage_port_map(stage: Any, attr: str) -> dict[str | None, Any]:
    return {_get_port_name(p): p for p in _effective_stage_ports(stage, attr)}


# ---------------------------------------------------------------------------
# The four passes
# ---------------------------------------------------------------------------


def _pass_ports(pipeline: Any, findings: list[StaticCheckFinding]) -> None:
    binding_map = getattr(pipeline, "binding_map", None) or {}
    stages_by_id: dict[str, Any] = dict(_iter_stages(pipeline))
    for (consumer_step, consumer_port), bind in binding_map.items():
        producer_step = getattr(bind, "producer_step", None) or (
            bind[0] if isinstance(bind, tuple) else None
        )
        producer_port = getattr(bind, "producer_port", None) or (
            bind[1] if isinstance(bind, tuple) else None
        )
        prod = stages_by_id.get(producer_step)
        cons = stages_by_id.get(consumer_step)
        if prod is None:
            findings.append(
                StaticCheckFinding(
                    "ports",
                    "unknown_producer",
                    f"edge:{producer_step}→{consumer_step}",
                    f"binding refers to unknown producer step {producer_step!r}",
                )
            )
            continue
        if cons is None:
            findings.append(
                StaticCheckFinding(
                    "ports",
                    "unknown_consumer",
                    f"edge:{producer_step}→{consumer_step}",
                    f"binding refers to unknown consumer step {consumer_step!r}",
                )
            )
            continue
        produces = _effective_stage_port_map(prod, "produces")
        consumes = _effective_stage_port_map(cons, "consumes")
        if producer_port not in produces:
            findings.append(
                StaticCheckFinding(
                    "ports",
                    "missing_produced_port",
                    f"port:{producer_step}.{producer_port}",
                    f"producer step does not declare port {producer_port!r}",
                )
            )
        if consumer_port not in consumes:
            findings.append(
                StaticCheckFinding(
                    "ports",
                    "missing_consumed_port",
                    f"port:{consumer_step}.{consumer_port}",
                    f"consumer step does not declare port {consumer_port!r}",
                )
            )
        if producer_port in produces and consumer_port in consumes:
            _append_port_metadata_mismatch(
                findings,
                producer_step=producer_step,
                producer_port_name=producer_port,
                producer_port=produces[producer_port],
                consumer_step=consumer_step,
                consumer_port_name=consumer_port,
                consumer_port=consumes[consumer_port],
            )


def _append_port_metadata_mismatch(
    findings: list[StaticCheckFinding],
    *,
    producer_step: str,
    producer_port_name: str,
    producer_port: Any,
    consumer_step: str,
    consumer_port_name: str,
    consumer_port: Any,
) -> None:
    for attr in ("content_type", "cardinality", "logical_type", "accepted_version_range"):
        producer_value = getattr(producer_port, attr, None)
        consumer_value = getattr(consumer_port, attr, None)
        if producer_value != consumer_value:
            findings.append(
                StaticCheckFinding(
                    "ports",
                    f"{attr}_mismatch",
                    f"edge:{producer_step}.{producer_port_name}→{consumer_step}.{consumer_port_name}",
                    (
                        f"producer {attr} {producer_value!r} does not match "
                        f"consumer {attr} {consumer_value!r}"
                    ),
                )
            )


def _pass_schemas(pipeline: Any, findings: list[StaticCheckFinding]) -> None:
    for stage_id, stage in _iter_stages(pipeline):
        for port in list(_effective_stage_ports(stage, "produces")) + list(
            _effective_stage_ports(stage, "consumes")
        ):
            schema = getattr(port, "schema", None)
            logical_type = getattr(port, "logical_type", None)
            if logical_type is None and schema is None:
                continue
            if schema is not None and not isinstance(schema, Mapping):
                port_name = _get_port_name(port) or "?"
                findings.append(
                    StaticCheckFinding(
                        "schemas",
                        "schema_not_mapping",
                        f"port:{stage_id}.{port_name}",
                        "declared schema must be a JSON-object mapping",
                    )
                )


def _pass_structural_subset(pipeline: Any, findings: list[StaticCheckFinding]) -> None:
    binding_map = getattr(pipeline, "binding_map", None) or {}
    stages_by_id: dict[str, Any] = dict(_iter_stages(pipeline))
    for (consumer_step, consumer_port), bind in binding_map.items():
        producer_step = getattr(bind, "producer_step", None) or (
            bind[0] if isinstance(bind, tuple) else None
        )
        producer_port = getattr(bind, "producer_port", None) or (
            bind[1] if isinstance(bind, tuple) else None
        )
        prod = stages_by_id.get(producer_step)
        cons = stages_by_id.get(consumer_step)
        if prod is None or cons is None:
            continue
        if prod is None:
            findings.append(
                StaticCheckFinding(
                    "structural-subset",
                    "unknown_producer",
                    f"edge:{producer_step}→{consumer_step}",
                    f"binding refers to unknown producer step {producer_step!r}",
                )
            )
            continue
        if cons is None:
            findings.append(
                StaticCheckFinding(
                    "structural-subset",
                    "unknown_consumer",
                    f"edge:{producer_step}→{consumer_step}",
                    f"binding refers to unknown consumer step {consumer_step!r}",
                )
            )
            continue
        prod_port = _effective_stage_port_map(prod, "produces").get(producer_port)
        cons_port = _effective_stage_port_map(cons, "consumes").get(consumer_port)
        if prod_port is None:
            findings.append(
                StaticCheckFinding(
                    "structural-subset",
                    "missing_produced_port",
                    f"port:{producer_step}.{producer_port}",
                    f"producer step does not declare port {producer_port!r}",
                )
            )
            continue
        if cons_port is None:
            findings.append(
                StaticCheckFinding(
                    "structural-subset",
                    "missing_consumed_port",
                    f"port:{consumer_step}.{consumer_port}",
                    f"consumer step does not declare port {consumer_port!r}",
                )
            )
            continue
        p_schema = getattr(prod_port, "schema", None)
        c_schema = getattr(cons_port, "schema", None)
        if not is_structural_subset(p_schema, c_schema):
            findings.append(
                StaticCheckFinding(
                    "structural-subset",
                    "not_subset",
                    f"edge:{producer_step}.{producer_port}→{consumer_step}.{consumer_port}",
                    "producer schema is not a structural subset of consumer schema",
                )
            )


def _pass_schema_versions(
    pipeline: Any,
    findings: list[StaticCheckFinding],
    *,
    registry: Any = None,
) -> None:
    if registry is None:
        return
    binding_map = getattr(pipeline, "binding_map", None) or {}
    stages_by_id: dict[str, Any] = dict(_iter_stages(pipeline))
    for (consumer_step, consumer_port), bind in binding_map.items():
        producer_step = getattr(bind, "producer_step", None) or (
            bind[0] if isinstance(bind, tuple) else None
        )
        producer_port = getattr(bind, "producer_port", None) or (
            bind[1] if isinstance(bind, tuple) else None
        )
        prod = stages_by_id.get(producer_step)
        cons = stages_by_id.get(consumer_step)
        if prod is None or cons is None:
            continue
        prod_port = _effective_stage_port_map(prod, "produces").get(producer_port)
        cons_port = _effective_stage_port_map(cons, "consumes").get(consumer_port)
        if prod_port is None or cons_port is None:
            continue
        logical_type = getattr(prod_port, "logical_type", None) or getattr(
            cons_port, "logical_type", None
        )
        if not logical_type:
            continue
        try:
            schema_version = registry.latest(logical_type)
        except SchemaRegistryError as exc:
            findings.append(
                StaticCheckFinding(
                    "schema-versions",
                    "schema_version_unavailable",
                    f"edge:{producer_step}.{producer_port}→{consumer_step}.{consumer_port}",
                    str(exc),
                )
            )
            continue
        if not schema_version:
            findings.append(
                StaticCheckFinding(
                    "schema-versions",
                    "schema_version_unavailable",
                    f"edge:{producer_step}.{producer_port}→{consumer_step}.{consumer_port}",
                    f"logical_type {logical_type!r} has no registered schema_version",
                )
            )
            continue
        accepted_range = getattr(cons_port, "accepted_version_range", None)
        if accepted_range is None:
            continue
        if not isinstance(accepted_range, AcceptedVersionRange):
            findings.append(
                StaticCheckFinding(
                    "schema-versions",
                    "invalid_accepted_version_range",
                    f"port:{consumer_step}.{consumer_port}",
                    "consumer accepted_version_range must be an AcceptedVersionRange",
                )
            )
            continue
        if accepted_range.logical_type != logical_type:
            findings.append(
                StaticCheckFinding(
                    "schema-versions",
                    "logical_type_mismatch",
                    f"edge:{producer_step}.{producer_port}→{consumer_step}.{consumer_port}",
                    (
                        f"consumer accepted_version_range logical_type "
                        f"{accepted_range.logical_type!r} does not match producer logical_type "
                        f"{logical_type!r}"
                    ),
                )
            )
            continue
        try:
            accepted = registry.accepts_version(logical_type, schema_version, accepted_range)
        except SchemaRegistryError as exc:
            findings.append(
                StaticCheckFinding(
                    "schema-versions",
                    "schema_version_unresolvable",
                    f"port:{consumer_step}.{consumer_port}",
                    str(exc),
                )
            )
            continue
        if not accepted:
            findings.append(
                StaticCheckFinding(
                    "schema-versions",
                    "schema_version_not_accepted",
                    f"edge:{producer_step}.{producer_port}→{consumer_step}.{consumer_port}",
                    "producer schema_version is outside the consumer accepted_version_range",
                )
            )


def _pass_call_sites(
    pipeline: Any,
    findings: list[StaticCheckFinding],
    *,
    registry: Any = None,
) -> None:
    if registry is None or not hasattr(registry, "registered_kinds"):
        try:
            from arnold.execution.step_invocation import get_default_adapter_registry

            registry = get_default_adapter_registry()
        except Exception:  # pragma: no cover - defensive
            return
    for stage_id, stage in _iter_stages(pipeline):
        invocation = getattr(stage, "invocation", None)
        kind = getattr(invocation, "kind", None) if invocation is not None else None
        if kind is None:
            continue
        if kind not in registry.registered_kinds:
            findings.append(
                StaticCheckFinding(
                    "call-sites",
                    "unknown_adapter",
                    f"stage:{stage_id}",
                    f"no invocation adapter registered for kind={kind!r}",
                )
            )


def _pass_media_pricing(pipeline: Any, warnings: list[StaticCheckFinding]) -> None:
    """Advisory pass: detect media-producing ports and warn when pricing is missing.

    Scans every stage's ``produces`` / ``consumes`` ports for content types
    that fall under ``image/*``, ``video/*``, or ``audio/*``.  For each
    detected media category the pass maps it to a semantic pricing unit and
    checks whether :data:`arnold.agent.costing.media_cost.DEFAULT_MEDIA_PRICING`
    contains at least one row for that unit.

    Warnings are **advisory only** — they are added to the report's
    ``warnings`` list and never affect ``StaticCheckReport.ok``.
    Pipelines without any media ports produce no warnings.
    """

    # ── collect media content-type categories from ports ─────────────
    media_categories: set[str] = set()
    for _stage_id, stage in _iter_stages(pipeline):
        for port in list(_effective_stage_ports(stage, "produces")) + list(
            _effective_stage_ports(stage, "consumes")
        ):
            ct = getattr(port, "content_type", None)
            if ct and isinstance(ct, str):
                if ct.startswith("image/"):
                    media_categories.add("image")
                elif ct.startswith("video/"):
                    media_categories.add("video")
                elif ct.startswith("audio/"):
                    media_categories.add("audio")

    if not media_categories:
        return  # no media ports — nothing to advise

    # ── map categories to semantic pricing units ─────────────────────
    # The mapping is *orientational only* (see media_cost.py docstring).
    _CATEGORY_TO_PRICING_UNIT: dict[str, str] = {
        "image": "image",
        "video": "video_second",
        "audio": "audio_second",
    }

    needed_units: set[str] = set()
    for cat in media_categories:
        needed_units.add(_CATEGORY_TO_PRICING_UNIT[cat])

    # ── check DEFAULT_MEDIA_PRICING coverage ─────────────────────────
    from arnold.agent.costing.media_cost import DEFAULT_MEDIA_PRICING

    priced_units: set[str] = {entry.unit.lower() for entry in DEFAULT_MEDIA_PRICING}

    # If *any* pricing rows exist we still flag individual missing units.
    for unit in sorted(needed_units - priced_units):
        warnings.append(
            StaticCheckFinding(
                pass_name="media-pricing",
                code="missing_media_pricing",
                locus=f"pipeline:{getattr(pipeline, 'name', None) or '?'}",
                detail=(
                    f"No media pricing row found for unit={unit!r}; "
                    f"pipeline declares media-producing ports but "
                    f"pricing is not configured for this unit"
                ),
            )
        )

    # If the pricing table is entirely empty (no rows at all), emit a
    # broader advisory as well.
    if not DEFAULT_MEDIA_PRICING:
        warnings.append(
            StaticCheckFinding(
                pass_name="media-pricing",
                code="no_media_pricing_configured",
                locus=f"pipeline:{getattr(pipeline, 'name', None) or '?'}",
                detail=(
                    "Pipeline declares media content-type ports but no "
                    "media pricing configuration (DEFAULT_MEDIA_PRICING) "
                    "is visible"
                ),
            )
        )


def run_c4_static_checks(
    pipeline: Any,
    *,
    registry: Any = None,
) -> StaticCheckReport:
    """Run all four C4 static passes against ``pipeline``.

    Returns a :class:`StaticCheckReport`. Never raises on authoring
    issues — surfaces them as ``findings``. Raises only on programmer
    errors (e.g. ``pipeline`` of the wrong type).
    """
    findings: list[StaticCheckFinding] = []
    warnings: list[StaticCheckFinding] = []
    _pass_ports(pipeline, findings)
    _pass_schemas(pipeline, findings)
    _pass_structural_subset(pipeline, findings)
    _pass_schema_versions(pipeline, findings, registry=registry)
    _pass_call_sites(pipeline, findings, registry=registry)
    _pass_media_pricing(pipeline, warnings)
    return StaticCheckReport(findings=findings, warnings=warnings)


__all__ = [
    "StaticCheckFinding",
    "StaticCheckReport",
    "is_structural_subset",
    "run_c4_static_checks",
]
