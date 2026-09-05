"""Neutral control-flow and graph-shape validator for pipeline definitions.

Pure graph-shape validation with zero megaplan imports.  Checks:

* ``Pipeline.entry`` names a real stage in ``Pipeline.stages``;
* every :class:`Edge`.``target`` names a real stage or the reserved
  terminal ``"halt"``;
* ``"halt"`` is never used as an :class:`Edge`.``label`` (it is reserved
  as a target only), except for the conventional ``label='halt' target='halt'``
  terminal pair;
* every stage's ``decision_routes`` values are validated against outgoing
  edge labels (``None`` values for terminal decisions are accepted);
* every stage that emits at least one ``kind == "decision"`` edge must cover
  the declared ``decision_vocabulary`` when non-empty;
* every stage that emits at least one ``kind == "override"`` edge must cover
  the declared ``override_vocabulary`` when non-empty;
* no stage is unreachable from :attr:`Pipeline.entry`;
* cycles are detected — a cycle is valid only when at least one edge
  in the cycle targets a stage with a ``loop_condition`` (guarded cycle);
  unguarded cycles are flagged as defects.
* every stage's prompt/resource dependencies are checked — a non-None
  ``prompt_key`` referencing an unknown resource bundle is flagged.

All access to stage/edge/pipeline fields is duck-typed via ``getattr``
so both Arnold and Megaplan shapes are accepted.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Mapping

from arnold.pipeline.contracts import BindResult, RepairGradient, bind
from arnold.pipeline.declaration_lowering import lower_stage_declarations
from arnold.pipeline.types import Port, PortRef, ReadRef, WriteRef
from arnold.workflow.invocation_validation import (
    DefaultInvocationRegistryView,
    InvocationRegistryView,
)


CONTRACT_ERROR_CODE_MAP: dict[str, str] = {
    "no_match": "contract.no_match",
    "typo_name": "contract.no_match",
    "content_type_mismatch": "contract.content_type_mismatch",
    "cardinality_mismatch": "contract.cardinality_mismatch",
    "schema_mismatch": "contract.schema_mismatch",
}
DECLARATION_DRIFT_CODE = "contract.declaration_drift"
MISSING_BINDING_CODE = "dataflow.missing_binding"
UNKNOWN_ADAPTER_CODE = "invocation.unknown_adapter"
MALFORMED_NATIVE_BUNDLE_CODE = "execution.native_bundle_malformed"
PLACEHOLDER_EXECUTION_RESOURCE_CODE = "execution.placeholder_resource"
NATIVE_MANIFEST_MISSING_EXECUTION_CODE = "manifest.native_execution_missing"
NATIVE_MANIFEST_GRAPH_COMPAT_CODE = "manifest.native_graph_compatibility"
DIRECT_NATIVE_DRIVER_CLAIM_CODE = "manifest.direct_native_driver_claim"
NATIVE_MANIFEST_INVALID_METADATA_CODE = "manifest.native_metadata_invalid"


def contract_diagnostic_code(error_kind: str) -> str:
    """Map binder/contract failure kinds to stable validator diagnostic codes."""
    return CONTRACT_ERROR_CODE_MAP.get(error_kind, f"contract.{error_kind}")


@dataclass(frozen=True)
class ValidationIssue:
    """Structured validator issue with a stable machine-readable code."""

    code: str
    message: str
    severity: str = "error"
    stage: str | None = None
    edge: dict[str, Any] | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class Diagnostics:
    """Result of :func:`validate` over a pipeline.

    Each defect is a short human-readable string naming the offending
    stage/edge so ``pipelines check`` can echo it on a non-zero exit.
    """

    defects: list[str] = field(default_factory=list)
    issues: list[ValidationIssue] = field(default_factory=list)

    def add_defect(
        self,
        message: str,
        *,
        code: str,
        severity: str = "error",
        stage: str | None = None,
        edge: Any = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        """Append a legacy defect string and its structured companion issue."""
        issue_edge: dict[str, Any] | None = None
        if edge is not None:
            issue_edge = {
                "label": getattr(edge, "label", None),
                "target": getattr(edge, "target", None),
                "kind": getattr(edge, "kind", None),
            }
            recommendation = getattr(edge, "recommendation", None)
            if recommendation is not None:
                issue_edge["recommendation"] = recommendation
        self.defects.append(message)
        self.issues.append(
            ValidationIssue(
                code=code,
                message=message,
                severity=severity,
                stage=stage,
                edge=issue_edge,
                details=dict(details or {}),
            )
        )

    def extend(self, other: "Diagnostics") -> None:
        """Merge diagnostics while preserving structured issues when present."""
        self.defects.extend(other.defects)
        if other.issues:
            self.issues.extend(other.issues)

    @property
    def structured_defects(self) -> list[ValidationIssue]:
        """Compatibility alias for callers that want defect-shaped issues."""
        return self.issues

    @property
    def ok(self) -> bool:
        return not self.defects


@dataclass
class ValidationOptions:
    """Options controlling validation behaviour.

    ``decision_vocabulary_fallback``: when a stage has no declared
    ``decision_vocabulary`` but has decision edges, use this fallback
    set.  The default is the canonical planning vocabulary.  Set to
    ``None`` to suppress fallback (only declared vocabularies are checked).

    ``override_vocabulary_fallback``: same for override edges.

    ``detect_cycles``: when ``True`` (default), perform DFS-based
    cycle detection and flag unguarded cycles.
    """

    # M4 neutralization: the neutral validator must not ship Megaplan decision
    # vocabulary (boundary gate forbids these literals). Plugins declare their own
    # decision_vocabulary; default suppresses fallback (see docstring).
    decision_vocabulary_fallback: frozenset[str] | None = None
    override_vocabulary_fallback: frozenset[str] | None = None
    detect_cycles: bool = True


@dataclass(frozen=True)
class ManifestValidationContext:
    """Manifest-owned validation context for non-local policy checks.

    Bare :func:`validate` calls remain pipeline-local.  Discovery, registry,
    and CLI surfaces that have manifest metadata pass this context to enforce
    manifest driver claims and graph-compatibility policy.
    """

    manifest_driver: tuple[str, ...]
    package: str
    name: str
    manifest_path: Path | str
    compatibility_classification: str = "native"
    source_entrypoint: str | None = None
    default_profile: str | None = None
    supported_modes: tuple[str, ...] = ()
    source_entrypoint_metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def driver_family(self) -> str | None:
        if not self.manifest_driver:
            return None
        return self.manifest_driver[0]

    @property
    def is_graph_compatible(self) -> bool:
        return self.compatibility_classification in {
            "graph",
            "graph_compat",
            "graph-compatible",
            "legacy_graph",
            "legacy-graph",
        }


# ── Duck-typed accessors ──────────────────────────────────────────────────


def _stage_edges(stage: Any) -> tuple:
    """Return the tuple of edges from *stage* (duck-typed)."""
    return tuple(getattr(stage, "edges", ()) or ())


def _stage_name(stage: Any) -> str:
    return getattr(stage, "name", "?")


def _stage_decision_vocabulary(
    stage: Any, options: ValidationOptions
) -> frozenset[str] | None:
    """Return the stage's decision vocabulary or fallback."""
    declared: frozenset[str] = frozenset(
        getattr(stage, "decision_vocabulary", frozenset()) or frozenset()
    )
    if declared:
        return declared
    return options.decision_vocabulary_fallback


def _stage_override_vocabulary(
    stage: Any, options: ValidationOptions
) -> frozenset[str] | None:
    """Return the stage's override vocabulary or fallback."""
    declared: frozenset[str] = frozenset(
        getattr(stage, "override_vocabulary", frozenset()) or frozenset()
    )
    if declared:
        return declared
    return options.override_vocabulary_fallback


# ── Suspension-schema enum extraction ──────────────────────────────────────

# Reserved extension keys that signal schema intent unrelated to decisions.
_X_EXTENSION_KEYS: frozenset[str] = frozenset({"x-arnold-resume"})


def _decision_enum_from_suspension_schema(schema: Any) -> frozenset[str] | None:
    """Extract decision enum values from a suspension schema.

    Only two conservative patterns are recognised:

    1. **Simple key/value maps** — a ``Mapping`` whose values are all
       ``str`` type-hint literals (e.g. ``{"approved": "str", "rejected":
       "str"}``) AND whose keys do **not** include any ``x-`` extension
       keys.  The returned frozenset is the set of keys.

    2. **JSON Schema ``properties.choice.enum``** — a JSON Schema object
       with a ``properties.choice`` sub-object that carries an ``enum``
       array of string values.  Only ``choice`` is recognised; enums on
       other property names are ignored.

    Returns ``None`` for:

    * Non-mappings (including ``None``)
    * Loose schemas (mappings that match neither pattern)
    * Empty enums (the enum array exists but is empty or has no strings)
    * Unrelated property enums (enum on a property other than ``choice``)
    * Schemas whose only signal is an ``x-`` extension key (e.g.
      ``x-arnold-resume``) with no other decision-bearing shape
    """
    if not isinstance(schema, Mapping):
        return None

    # ── Pattern 1: simple key/value map with string type hints ────────
    if _is_simple_kv_map_with_string_types(schema):
        return frozenset(schema.keys())

    # ── Pattern 2: JSON Schema properties.choice.enum ─────────────────
    enum_values = _extract_choice_enum_from_json_schema(schema)
    if enum_values is not None:
        return enum_values

    # ── Check if the schema has ONLY x- extension keys (no other signal)
    if _only_x_extension_keys(schema):
        return None

    return None


def _is_simple_kv_map_with_string_types(schema: Mapping) -> bool:
    """Return True when *schema* is a key/value map with string type hints.

    Every value must be a ``str`` (conventionally type-hint literals like
    ``"str"``, ``"int"``, ``"bool"``), no key may start with ``x-``, and
    there must be at least one key.
    """
    if not schema:
        return False
    for key, value in schema.items():
        if isinstance(key, str) and key.startswith("x-"):
            return False
        if not isinstance(value, str):
            return False
    return True


def _extract_choice_enum_from_json_schema(schema: Mapping) -> frozenset[str] | None:
    """Extract ``properties.choice.enum`` string values from a JSON Schema.

    Requires the top-level ``type`` to be ``"object"``, ``properties`` to
    be a ``Mapping``, ``properties.choice`` to be a ``Mapping`` with
    ``type: "string"``, and ``choice.enum`` to be a non-empty sequence of
    strings.

    Returns ``None`` when the schema does not satisfy this shape.
    """
    if schema.get("type") != "object":
        return None
    properties = schema.get("properties")
    if not isinstance(properties, Mapping):
        return None
    choice = properties.get("choice")
    if not isinstance(choice, Mapping):
        return None
    if choice.get("type") != "string":
        return None
    enum = choice.get("enum")
    if not isinstance(enum, (list, tuple)) or not enum:
        return None
    strings: set[str] = set()
    for item in enum:
        if isinstance(item, str):
            strings.add(item)
        else:
            # Non-string enum value — bail out conservatively
            return None
    if not strings:
        return None
    return frozenset(strings)


def _only_x_extension_keys(schema: Mapping) -> bool:
    """Return True when every key in *schema* is an ``x-`` extension key."""
    if not schema:
        return False
    for key in schema:
        if not (isinstance(key, str) and key.startswith("x-")):
            return False
    return True


# ── Validation ────────────────────────────────────────────────────────────


def validate_control_flow(
    pipeline: Any, options: ValidationOptions | None = None
) -> Diagnostics:
    """Run control-flow validation over *pipeline*.

    Checks: entry existence, edge targets, reserved halt label,
    decision/override vocabulary coverage, decision_route target
    validation against outgoing edge labels, reachability from entry,
    and unguarded cycle detection.

    Returns a :class:`Diagnostics` whose ``defects`` list is empty iff
    every check passes.
    """
    if options is None:
        options = ValidationOptions()

    diag = Diagnostics()
    stages: Mapping[str, Any] = getattr(pipeline, "stages", {})
    entry: str = getattr(pipeline, "entry", "")
    stage_names = set(stages.keys())

    # ── entry check ──────────────────────────────────────────────────
    if entry not in stage_names:
        diag.add_defect(
            f"entry stage {entry!r} not present in pipeline.stages",
            code="entry_stage_missing",
            stage=entry or None,
            details={"entry": entry, "known_stages": sorted(stage_names)},
        )

    for stage_name, stage in stages.items():
        edges = _stage_edges(stage)
        # Match both kind='gate' (legacy) and kind='decision' (current)
        decision_edges = [e for e in edges if getattr(e, "kind", "normal") in ("gate", "decision")]
        override_edges_list = [e for e in edges if getattr(e, "kind", "normal") == "override"]

        for edge in edges:
            label = getattr(edge, "label", "")
            target = getattr(edge, "target", "")

            # 'halt' is a reserved target sentinel; flagged as a label
            # only when the edge does NOT also resolve to the terminal target.
            if label == "halt" and target != "halt":
                diag.add_defect(
                    f"stage {stage_name!r}: edge uses reserved label 'halt' "
                    "(halt is a target sentinel, not an edge label)",
                    code="edge_reserved_halt_label",
                    stage=stage_name,
                    edge=edge,
                    details={"reserved_label": "halt"},
                )
            if target != "halt" and target not in stage_names:
                diag.add_defect(
                    f"stage {stage_name!r}: edge {label!r} targets "
                    f"unknown stage {target!r}",
                    code="edge_target_unknown_stage",
                    stage=stage_name,
                    edge=edge,
                    details={"known_stages": sorted(stage_names)},
                )

        # ── decision_route target validation ──────────────────────────
        decision_routes = getattr(stage, "decision_routes", None)
        if decision_routes:
            edge_labels = {getattr(e, "label", "") for e in edges}
            for decision_key, route_target in decision_routes.items():
                if route_target is not None and route_target not in edge_labels:
                    diag.add_defect(
                        f"stage {stage_name!r}: decision_route {decision_key!r} "
                        f"targets unknown edge label {route_target!r}",
                        code="decision_route_target_unknown",
                        stage=stage_name,
                        details={
                            "decision_key": decision_key,
                            "route_target": route_target,
                            "available_edge_labels": sorted(edge_labels),
                        },
                    )

            # ── suspension-schema decision enum conformance ───────────
            schema_enum = _decision_enum_from_suspension_schema(
                getattr(stage, "suspension_schema", None)
            )
            if schema_enum is not None:
                route_keys = set(decision_routes.keys())
                # Extra keys: present in decision_routes but not in schema enum
                extra = route_keys - schema_enum
                for key in sorted(extra):
                    diag.add_defect(
                        f"stage {stage_name!r}: decision_route key {key!r} "
                        f"is not in the suspension-schema enum "
                        f"{sorted(schema_enum)}",
                        code="decision_route_schema_key_unknown",
                        stage=stage_name,
                        details={
                            "decision_key": key,
                            "schema_enum": sorted(schema_enum),
                        },
                    )
                # Missing keys: in schema enum but not in decision_routes
                missing = schema_enum - route_keys
                for key in sorted(missing):
                    diag.add_defect(
                        f"stage {stage_name!r}: suspension-schema choice "
                        f"{key!r} is missing from decision_routes",
                        code="decision_route_schema_key_missing",
                        stage=stage_name,
                        details={
                            "decision_key": key,
                            "schema_enum": sorted(schema_enum),
                        },
                    )

        # ── decision vocabulary check ────────────────────────────────
        if decision_edges:
            vocab = _stage_decision_vocabulary(stage, options)
            if vocab is not None:
                covered: set[str] = set()
                for edge in decision_edges:
                    kind = getattr(edge, "kind", "normal")
                    label = getattr(edge, "label", "")
                    # label is the decision key for kind='decision';
                    # recommendation is checked for legacy kind='gate' edges.
                    key = label if kind == "decision" else getattr(edge, "recommendation", None)
                    if not key:
                        diag.add_defect(
                            f"stage {stage_name!r}: decision edge {label!r} has "
                            "no recommendation set (label/recommendation is None)",
                            code="decision_edge_missing_key",
                            stage=stage_name,
                            edge=edge,
                            details={"vocabulary": sorted(vocab)},
                        )
                    elif key not in vocab:
                        diag.add_defect(
                            f"stage {stage_name!r}: decision edge {label!r} has "
                            f"decision key {key!r} not in "
                            f"declared vocabulary {sorted(vocab)}",
                            code="decision_key_outside_vocabulary",
                            stage=stage_name,
                            edge=edge,
                            details={"decision_key": key, "vocabulary": sorted(vocab)},
                        )
                    else:
                        covered.add(key)
                missing = vocab - covered
                if missing:
                    diag.add_defect(
                        f"stage {stage_name!r}: decision vocabulary "
                        f"{sorted(vocab)} declares {sorted(missing)} "
                        f"but no decision edge covers them",
                        code="decision_vocabulary_uncovered",
                        stage=stage_name,
                        details={
                            "vocabulary": sorted(vocab),
                            "missing_keys": sorted(missing),
                        },
                    )

        # ── override vocabulary check ────────────────────────────────
        if override_edges_list:
            vocab = _stage_override_vocabulary(stage, options)
            if vocab is not None:
                covered: set[str] = set()
                for edge in override_edges_list:
                    label = getattr(edge, "label", "")
                    # label format is "override <action>"
                    if not label.startswith("override "):
                        diag.add_defect(
                            f"stage {stage_name!r}: override edge {label!r} "
                            "does not follow 'override <action>' label format",
                            code="override_edge_invalid_label",
                            stage=stage_name,
                            edge=edge,
                        )
                        continue
                    action = label[len("override "):]
                    if action not in vocab:
                        diag.add_defect(
                            f"stage {stage_name!r}: override edge {label!r} has "
                            f"action {action!r} not in "
                            f"declared override_vocabulary {sorted(vocab)}",
                            code="override_action_outside_vocabulary",
                            stage=stage_name,
                            edge=edge,
                            details={"action": action, "vocabulary": sorted(vocab)},
                        )
                    else:
                        covered.add(action)
                missing = vocab - covered
                if missing:
                    diag.add_defect(
                        f"stage {stage_name!r}: override vocabulary "
                        f"{sorted(vocab)} declares {sorted(missing)} "
                        f"but no override edge covers them",
                        code="override_vocabulary_uncovered",
                        stage=stage_name,
                        details={
                            "vocabulary": sorted(vocab),
                            "missing_actions": sorted(missing),
                        },
                    )

    # ── Reachability from entry ──────────────────────────────────────
    if entry in stage_names:
        reachable: set[str] = set()
        frontier = [entry]
        while frontier:
            current = frontier.pop()
            if current in reachable:
                continue
            reachable.add(current)
            stage = stages.get(current)
            if stage is None:
                continue
            for edge in _stage_edges(stage):
                target = getattr(edge, "target", "")
                if target != "halt" and target in stage_names:
                    frontier.append(target)
        unreachable = stage_names - reachable
        for name in sorted(unreachable):
            diag.add_defect(
                f"stage {name!r} is unreachable from entry {entry!r}",
                code="stage_unreachable",
                stage=name,
                details={"entry": entry},
            )

    # ── Unguarded cycle detection ────────────────────────────────────
    if options.detect_cycles:
        _detect_unguarded_cycles(stages, entry, diag)

    return diag


def validate(
    pipeline: Any,
    options: ValidationOptions | None = None,
    *,
    adapter_registry: InvocationRegistryView | None = None,
    context: ManifestValidationContext | None = None,
) -> Diagnostics:
    """Run the full graph-shape validation over *pipeline*.

    Delegates to :func:`validate_control_flow`, :func:`validate_dataflow_paths`,
    and :func:`validate_resource_dependencies`.  When *context* is provided,
    manifest-owned policy is checked after pipeline-local validation.

    When *adapter_registry* is ``None`` a fresh fail-closed default registry
    is constructed so existing callers get the same reserved-``model``-only
    behaviour.

    Returns a :class:`Diagnostics` whose ``defects`` list is empty iff
    every check passes.
    """
    diag = validate_control_flow(pipeline, options)
    # Merge dataflow defects — dataflow validation runs even when
    # control-flow defects exist so callers get the full picture.
    df_diag = validate_dataflow_paths(pipeline, options)
    diag.extend(df_diag)
    invocation_diag = validate_invocation_requirements(
        pipeline, adapter_registry=adapter_registry
    )
    diag.extend(invocation_diag)
    # Merge prompt/resource defects
    res_diag = validate_resource_dependencies(pipeline, options)
    diag.extend(res_diag)
    exec_diag = validate_execution_resources(pipeline)
    diag.extend(exec_diag)
    if context is not None:
        manifest_diag = validate_manifest_context(pipeline, context=context)
        diag.extend(manifest_diag)
    return diag


def _is_native_program_instance(value: Any) -> bool:
    from arnold.pipeline.native.ir import NativeProgram

    return isinstance(value, NativeProgram)


def _native_dispatch_evidence(pipeline: Any) -> bool:
    if _is_native_program_instance(getattr(pipeline, "native_program", None)):
        return True
    for bundle in _pipeline_resource_bundles(pipeline):
        if _is_native_program_instance(bundle):
            return True
        runner = getattr(bundle, "run_native_pipeline", None)
        if callable(runner):
            return True
    return False


_PLACEHOLDER_STRINGS: frozenset[str] = frozenset(
    {"todo", "tbd", "placeholder", "changeme", "fill-me", "fill_me", "example"}
)


def _is_placeholder_string(value: Any) -> bool:
    return isinstance(value, str) and value.strip().lower() in _PLACEHOLDER_STRINGS


def _coerce_context_str_tuple(value: Any) -> tuple[str, ...] | None:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return None
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            return None
        normalized = item.strip()
        if not normalized or _is_placeholder_string(normalized):
            return None
        result.append(normalized)
    return tuple(result)


def _context_claims_native_driver(context: ManifestValidationContext) -> bool:
    raw_driver = context.manifest_driver
    if isinstance(raw_driver, str):
        return raw_driver.strip().lower() == "native"
    driver = _coerce_context_str_tuple(raw_driver)
    return bool(driver and driver[0] == "native")


def _validate_native_manifest_metadata(
    context: ManifestValidationContext,
) -> tuple[list[str], dict[str, Any]]:
    reasons: list[str] = []
    detail_overrides: dict[str, Any] = {}

    driver = _coerce_context_str_tuple(context.manifest_driver)
    if driver is None or len(driver) < 2 or driver[0] != "native":
        reasons.append(
            "driver must be a non-placeholder sequence of strings beginning with 'native'"
        )
        detail_overrides["manifest_driver"] = context.manifest_driver

    default_profile = context.default_profile
    if not isinstance(default_profile, str) or not default_profile.strip():
        reasons.append("default_profile must be a non-empty string for native manifests")
        detail_overrides["default_profile"] = default_profile
    elif _is_placeholder_string(default_profile):
        reasons.append("default_profile must not be a placeholder string")
        detail_overrides["default_profile"] = default_profile

    supported_modes = _coerce_context_str_tuple(context.supported_modes)
    if not supported_modes or "native" not in supported_modes:
        reasons.append("supported_modes must include 'native' for native manifests")
        detail_overrides["supported_modes"] = context.supported_modes

    source_entrypoint = context.source_entrypoint
    if source_entrypoint != "build_pipeline":
        reasons.append("native manifests must declare build_pipeline as the entrypoint")
        detail_overrides["source_entrypoint"] = source_entrypoint

    return reasons, detail_overrides


def _looks_like_placeholder_execution_resource(bundle: Any) -> bool:
    if not hasattr(bundle, "run_native_pipeline"):
        return False
    runner = getattr(bundle, "run_native_pipeline", None)
    return not callable(runner)


def validate_execution_resources(pipeline: Any) -> Diagnostics:
    """Validate pipeline-local execution resource shapes.

    This pass rejects local malformed native-program claims and placeholder
    runner resources.  It does not enforce manifest driver policy.
    """

    diag = Diagnostics()
    native_program = getattr(pipeline, "native_program", None)
    if native_program is not None and not _is_native_program_instance(native_program):
        diag.add_defect(
            "pipeline.native_program must be a NativeProgram when present",
            code=MALFORMED_NATIVE_BUNDLE_CODE,
            details={"field": "native_program", "type": type(native_program).__name__},
        )

    direct_driver = getattr(pipeline, "driver", None)
    if direct_driver is not None:
        direct_driver_tuple = (
            tuple(direct_driver)
            if isinstance(direct_driver, Sequence)
            and not isinstance(direct_driver, (str, bytes))
            else (str(direct_driver),)
        )
        if direct_driver_tuple and direct_driver_tuple[0] == "native":
            diag.add_defect(
                "pipeline-local driver='native' claims must be expressed through a manifest context",
                code=DIRECT_NATIVE_DRIVER_CLAIM_CODE,
                details={"pipeline_driver": list(direct_driver_tuple)},
            )

    for index, bundle in enumerate(_pipeline_resource_bundles(pipeline)):
        if _looks_like_placeholder_execution_resource(bundle):
            diag.add_defect(
                f"resource_bundles[{index}] exposes non-callable run_native_pipeline",
                code=PLACEHOLDER_EXECUTION_RESOURCE_CODE,
                details={
                    "bundle_index": index,
                    "bundle_type": type(bundle).__name__,
                    "attribute": "run_native_pipeline",
                },
            )
        if _looks_like_native_program(bundle) and not _is_native_program_instance(bundle):
            diag.add_defect(
                f"resource_bundles[{index}] looks like a native program but is malformed",
                code=MALFORMED_NATIVE_BUNDLE_CODE,
                details={
                    "bundle_index": index,
                    "bundle_type": type(bundle).__name__,
                },
            )
    return diag


def validate_manifest_context(
    pipeline: Any,
    *,
    context: ManifestValidationContext,
) -> Diagnostics:
    """Validate manifest-owned policy that cannot be inferred from a pipeline."""

    diag = Diagnostics()
    details = {
        "manifest_driver": (
            list(context.manifest_driver)
            if isinstance(context.manifest_driver, Sequence)
            and not isinstance(context.manifest_driver, (str, bytes))
            else context.manifest_driver
        ),
        "package": context.package,
        "name": context.name,
        "manifest_path": str(context.manifest_path),
        "compatibility_classification": context.compatibility_classification,
        "source_entrypoint": context.source_entrypoint,
        "default_profile": context.default_profile,
        "supported_modes": list(context.supported_modes),
        "source_entrypoint_metadata": dict(context.source_entrypoint_metadata),
    }
    if _context_claims_native_driver(context):
        reasons, detail_overrides = _validate_native_manifest_metadata(context)
        if reasons:
            diag.add_defect(
                f"manifest for {context.package}/{context.name} declares native driver "
                "but native metadata is incomplete or malformed",
                code=NATIVE_MANIFEST_INVALID_METADATA_CODE,
                details={**details, **detail_overrides, "reasons": reasons},
            )
        if context.is_graph_compatible:
            diag.add_defect(
                f"manifest for {context.package}/{context.name} declares native driver "
                "but is classified graph-compatible",
                code=NATIVE_MANIFEST_GRAPH_COMPAT_CODE,
                details=details,
            )
        if not _native_dispatch_evidence(pipeline):
            diag.add_defect(
                f"manifest for {context.package}/{context.name} declares native driver "
                "but built pipeline has no native execution resource",
                code=NATIVE_MANIFEST_MISSING_EXECUTION_CODE,
                details=details,
            )

    return diag


# ── Dataflow validation ───────────────────────────────────────────────────


def validate_invocation_requirements(
    pipeline: Any,
    *,
    adapter_registry: InvocationRegistryView | None = None,
) -> Diagnostics:
    """Validate invocation kinds against the supplied adapter registry.

    When *adapter_registry* is ``None`` a fresh fail-closed default registry
    is constructed so existing callers get the same reserved-``model``-only
    behaviour.  Callers that supply a non-model registry can prove that
    non-``model`` invocation kinds pass validation.
    """
    diag = Diagnostics()
    stages: Mapping[str, Any] = getattr(pipeline, "stages", {}) or {}
    registry = (
        adapter_registry
        if adapter_registry is not None
        else DefaultInvocationRegistryView()
    )

    for stage_name in sorted(stages):
        stage = stages[stage_name]
        invocation = getattr(stage, "invocation", None)
        if invocation is not None:
            try:
                registry.resolve(invocation.kind)
            except KeyError:
                diag.add_defect(
                    f"stage {stage_name!r}: invocation kind {invocation.kind!r} does not "
                    "resolve to a registered adapter",
                    code=UNKNOWN_ADAPTER_CODE,
                    stage=stage_name,
                    details={
                        "invocation_kind": invocation.kind,
                        "registered_kinds": list(registry.registered_kinds),
                    },
                )

    return diag


def _normalize_dependency(
    dep: Any,
) -> tuple[str, bool, bool, bool]:
    """Normalize a single dependency item into (name, optional, external, late_bound).

    * Plain strings become required wildcard refs (``optional=False``,
      ``external=False``, ``late_bound=False``) with content type ``*/*``.
    * :class:`ReadRef`, :class:`WriteRef`, and :class:`BindingRef` instances
      preserve their metadata.
    * ``Port`` and ``PortRef`` instances expose ``name`` / ``port_name``
      and are treated as required unless tainted optional.

    Returns ``(name, optional, external, late_bound)``.
    """
    if isinstance(dep, str):
        # Plain string — required wildcard ref
        return (dep, False, False, False)

    # Duck-type dataclass wrappers — check known field names
    name: str | None = getattr(dep, "name", None)
    optional: bool = bool(getattr(dep, "optional", False))
    external: bool = bool(getattr(dep, "external", False))
    late_bound: bool = bool(getattr(dep, "late_bound", False))

    # PortRef uses port_name instead of name
    if name is None:
        name = getattr(dep, "port_name", None)

    if name is None:
        # Fallback: try string coercion
        name = str(dep)

    return (name, optional, external, late_bound)


def _is_typed_dependency(dep: Any) -> bool:
    return isinstance(dep, (Port, PortRef))


def _is_legacy_dependency(dep: Any) -> bool:
    return isinstance(dep, (str, ReadRef, WriteRef)) or not _is_typed_dependency(dep)


def _edge_targets_by_stage(stages: Mapping[str, Any]) -> dict[str, list[str]]:
    edges_by_src: dict[str, list[str]] = {name: [] for name in stages}
    for src_name, stage in stages.items():
        for edge in _stage_edges(stage):
            target = getattr(edge, "target", "")
            if target != "halt" and target in stages:
                edges_by_src[src_name].append(target)
    return edges_by_src


def _typed_binding_stage(stage: Any) -> Any:
    lowered = lower_stage_declarations(stage)
    typed_produces = tuple(
        produce for produce in lowered.effective_produces if isinstance(produce, Port)
    )
    typed_consumes = tuple(
        consume for consume in lowered.effective_consumes if isinstance(consume, PortRef)
    )
    return replace(
        stage,
        reads=lowered.legacy_reads,
        writes=lowered.legacy_writes,
        produces=typed_produces if lowered.clean_binding else (),
        consumes=typed_consumes if lowered.clean_binding else (),
    )


def _typed_binding_stages(stages: Mapping[str, Any]) -> dict[str, Any]:
    return {stage_name: _typed_binding_stage(stage) for stage_name, stage in stages.items()}


def _find_stage_for_wanted_consume(
    stages: Mapping[str, Any],
    wanted: Any,
) -> str | None:
    for stage_name, stage in stages.items():
        if wanted in tuple(getattr(stage, "consumes", ()) or ()):
            return stage_name
    return None


def _candidate_contract_details(candidates: tuple[tuple[str, Any], ...]) -> list[dict[str, Any]]:
    return [
        {
            "stage": stage_name,
            "name": getattr(port, "name", getattr(port, "port_name", "")),
            "content_type": getattr(port, "content_type", None),
            "cardinality": getattr(port, "cardinality", None),
            "logical_type": getattr(port, "logical_type", None),
            "accepted_version_range": getattr(port, "accepted_version_range", None),
        }
        for stage_name, port in candidates
    ]


def _schema_mismatch_reason(
    wanted: Any,
    candidates: tuple[tuple[str, Any], ...],
) -> tuple[str, str]:
    wanted_logical_type = getattr(wanted, "logical_type", None)
    candidate_logical_types = [
        getattr(port, "logical_type", None) for _, port in candidates
    ]
    if wanted_logical_type is not None and any(
        logical_type != wanted_logical_type for logical_type in candidate_logical_types
    ):
        return (
            "logical_type_mismatch",
            (
                f"typed dependency {getattr(wanted, 'port_name', getattr(wanted, 'name', '?'))!r} "
                f"declares logical_type {wanted_logical_type!r} but upstream producers expose "
                f"{candidate_logical_types!r}"
            ),
        )

    wanted_version = getattr(wanted, "accepted_version_range", None)
    candidate_versions = [
        getattr(port, "accepted_version_range", None) for _, port in candidates
    ]
    if wanted_version is not None and any(
        version != wanted_version for version in candidate_versions
    ):
        return (
            "accepted_version_range_mismatch",
            (
                f"typed dependency {getattr(wanted, 'port_name', getattr(wanted, 'name', '?'))!r} "
                "declares an accepted_version_range that does not match any upstream producer"
            ),
        )

    return (
        "schema_mismatch",
        (
            f"typed dependency {getattr(wanted, 'port_name', getattr(wanted, 'name', '?'))!r} "
            "does not match upstream producer schema metadata"
        ),
    )


def _contract_failure_message_and_details(
    gradient: RepairGradient,
) -> tuple[str, dict[str, Any]]:
    wanted_name = getattr(gradient.wanted, "port_name", getattr(gradient.wanted, "name", "?"))
    details: dict[str, Any] = {
        "dependency": wanted_name,
        "error_kind": gradient.error_kind,
        "wanted": {
            "name": wanted_name,
            "content_type": getattr(gradient.wanted, "content_type", None),
            "cardinality": getattr(gradient.wanted, "cardinality", None),
            "logical_type": getattr(gradient.wanted, "logical_type", None),
            "accepted_version_range": getattr(
                gradient.wanted, "accepted_version_range", None
            ),
        },
        "candidates": _candidate_contract_details(gradient.candidates),
    }

    if gradient.error_kind in {"no_match", "typo_name"}:
        if gradient.suggested_moves:
            details["suggested_moves"] = list(gradient.suggested_moves)
            return (
                (
                    f"typed dependency {wanted_name!r} does not match any upstream producer; "
                    f"did you mean {list(gradient.suggested_moves)!r}?"
                ),
                details,
            )
        return (
            f"typed dependency {wanted_name!r} does not match any upstream producer",
            details,
        )

    if gradient.error_kind == "content_type_mismatch":
        return (
            (
                f"typed dependency {wanted_name!r} expects content_type "
                f"{getattr(gradient.wanted, 'content_type', None)!r} but upstream producers "
                f"provide {[candidate['content_type'] for candidate in details['candidates']]}"
            ),
            details,
        )

    if gradient.error_kind == "cardinality_mismatch":
        return (
            (
                f"typed dependency {wanted_name!r} expects cardinality "
                f"{getattr(gradient.wanted, 'cardinality', None)!r} but upstream producers "
                f"provide {[candidate['cardinality'] for candidate in details['candidates']]}"
            ),
            details,
        )

    if gradient.error_kind == "schema_mismatch":
        reason, message = _schema_mismatch_reason(gradient.wanted, gradient.candidates)
        details["mismatch_reason"] = reason
        return message, details

    return (
        f"typed dependency {wanted_name!r} failed contract binding ({gradient.error_kind})",
        details,
    )


def _remove_typed_consume(stages: Mapping[str, Any], stage_name: str, wanted: Any) -> dict[str, Any]:
    updated = dict(stages)
    stage = updated[stage_name]
    updated[stage_name] = replace(
        stage,
        consumes=tuple(
            consume for consume in tuple(getattr(stage, "consumes", ()) or ()) if consume != wanted
        ),
    )
    return updated


def validate_dataflow_paths(
    pipeline: Any, options: ValidationOptions | None = None
) -> Diagnostics:
    """Run path-sensitive dataflow validation over *pipeline*.

    Uses deterministic fixed-point analysis over the graph:

    1. Track available artifact/port names as sets per stage.
    2. At join points (stages with multiple predecessors), use
       **intersection** of predecessor availability — a consume is valid
       only when every incoming path provides it.
    3. Normalize reads/writes/produces/consumes via
       :func:`_normalize_dependency`: plain strings become required
       wildcard refs, while ``ReadRef``/``WriteRef``/``BindingRef``
       preserve their metadata.
    4. ``pipeline.binding_map`` entries and explicit ``external`` /
       ``late_bound`` refs are treated as satisfiers (they are provided
       from outside the pipeline or at runtime).
    5. Emits deterministic defects naming the stage, the dependency,
       and at least one predecessor route through which the dependency
       is missing.

    Returns a :class:`Diagnostics` whose ``defects`` list is empty iff
    every dataflow dependency is satisfiable.
    """
    if options is None:
        options = ValidationOptions()

    diag = Diagnostics()
    stages: dict[str, Any] = dict(getattr(pipeline, "stages", {}) or {})
    entry: str = getattr(pipeline, "entry", "")
    binding_map: dict | None = getattr(pipeline, "binding_map", None)

    if not stages or entry not in stages:
        # Control-flow validation already flags these; nothing to do here.
        return diag

    # ── Build predecessor map ────────────────────────────────────────────
    edges_by_src = _edge_targets_by_stage(stages)
    predecessors: dict[str, list[str]] = {name: [] for name in stages}
    for src_name, targets in edges_by_src.items():
        for target in targets:
            predecessors[target].append(src_name)

    lowered_by_stage = {
        stage_name: lower_stage_declarations(stage) for stage_name, stage in stages.items()
    }
    for stage_name in sorted(lowered_by_stage):
        lowered = lowered_by_stage[stage_name]
        for defect in lowered.drift_defects:
            diag.add_defect(
                defect.detail,
                code=DECLARATION_DRIFT_CODE,
                stage=stage_name,
                details={"direction": defect.direction, "name": defect.name},
            )

    def _stage_produces(stage_name: str, stage: Any) -> list[tuple[str, bool, bool, bool]]:
        """Return the effective set of names that *stage* produces."""
        result: list[tuple[str, bool, bool, bool]] = []
        lowered = lowered_by_stage[stage_name]
        if lowered.clean_binding:
            for produce in lowered.effective_produces:
                if _is_typed_dependency(produce):
                    result.append(_normalize_dependency(produce))
        for p in getattr(stage, "produces", ()) or ():
            if _is_legacy_dependency(p):
                result.append(_normalize_dependency(p))
        for w in getattr(stage, "writes", ()) or ():
            if _is_legacy_dependency(w):
                result.append(_normalize_dependency(w))
        return result

    def _stage_consumes(stage_name: str, stage: Any) -> list[tuple[str, bool, bool, bool]]:
        """Return the effective set of names that *stage* consumes."""
        result: list[tuple[str, bool, bool, bool]] = []
        lowered = lowered_by_stage[stage_name]
        if lowered.clean_binding:
            for consume in lowered.effective_consumes:
                if _is_typed_dependency(consume):
                    result.append(_normalize_dependency(consume))
        for c in getattr(stage, "consumes", ()) or ():
            if _is_legacy_dependency(c):
                result.append(_normalize_dependency(c))
        for r in getattr(stage, "reads", ()) or ():
            if _is_legacy_dependency(r):
                result.append(_normalize_dependency(r))
        return result

    # Seed initial availability from binding_map and external/late_bound refs
    initial_available: set[str] = set()
    if isinstance(binding_map, dict):
        for key in binding_map:
            if isinstance(key, tuple) and len(key) >= 2:
                initial_available.add(str(key[1]))
            else:
                initial_available.add(str(key))

    # ── Compute per-stage produces/consumes ───────────────────────────────
    produces: dict[str, set[str]] = {}
    consumes: dict[str, list[tuple[str, bool, bool, bool]]] = {}
    for name, stage in stages.items():
        produces[name] = {n for n, *_ in _stage_produces(name, stage)}
        consumes[name] = _stage_consumes(name, stage)
        # External/late-bound consumptions are always satisfied
        for c_name, c_opt, c_ext, c_late in consumes[name]:
            if c_ext or c_late:
                initial_available.add(c_name)

    # ── Fixed-point availability analysis ────────────────────────────────
    # available_at[stage] = set of names guaranteed available when entering stage
    available_at: dict[str, set[str]] = {name: set() for name in stages}

    # Seed entry with initial availability
    available_at[entry] = set(initial_available)

    changed = True
    while changed:
        changed = False
        # Topological-ish: iterate stages in a fixed order for determinism
        for name in sorted(stages):
            preds = predecessors.get(name, [])
            if name == entry:
                # Entry already seeded; skip recomputation from preds
                new_incoming = set(initial_available)
            elif preds:
                # Join: intersection of predecessor out-sets
                pred_out_sets = [
                    available_at[p] | produces.get(p, set()) for p in preds
                ]
                if pred_out_sets:
                    new_incoming = pred_out_sets[0].copy()
                    for s in pred_out_sets[1:]:
                        new_incoming &= s
                else:
                    new_incoming = set()
            else:
                new_incoming = set()

            # Merge with current available
            combined = available_at[name] | new_incoming
            if combined != available_at[name]:
                available_at[name] = combined
                changed = True

    # ── Check each stage's consumes against availability ─────────────────
    # Also track which predecessor route(s) fail for reporting
    missing_binding_keys: set[tuple[str, str]] = set()
    for name in sorted(stages):
        incoming = available_at.get(name, set())
        for c_name, c_opt, c_ext, c_late in consumes.get(name, []):
            if c_opt or c_ext or c_late:
                # Optional/external/late-bound always satisfied
                continue
            if c_name in incoming:
                continue
            if c_name in produces.get(name, set()):
                # Stage produces what it consumes — self-satisfying
                continue
            # Build a route hint: find a predecessor where it's missing
            route_hint = ""
            preds = predecessors.get(name, [])
            if preds:
                # Find first predecessor that doesn't provide this dep
                for p in preds:
                    p_available = available_at.get(p, set()) | produces.get(p, set())
                    if c_name not in p_available:
                        route_hint = f" (missing from predecessor {p!r})"
                        break
                if not route_hint and preds:
                    route_hint = f" (available at all predecessors but not after join)"
            diag.add_defect(
                f"stage {name!r}: dependency {c_name!r} is unsatisfied"
                f"{route_hint}",
                code=MISSING_BINDING_CODE,
                stage=name,
                details={
                    "dependency": c_name,
                    "route_hint": route_hint.strip() or None,
                },
            )
            missing_binding_keys.add((name, c_name))

    typed_stages = _typed_binding_stages(stages)
    while True:
        typed_result = bind(typed_stages, edges_by_src, typed_ports=True)
        if isinstance(typed_result, BindResult):
            break
        stage_name = _find_stage_for_wanted_consume(typed_stages, typed_result.wanted)
        if stage_name is None:
            break
        wanted_name = getattr(
            typed_result.wanted,
            "port_name",
            getattr(typed_result.wanted, "name", "?"),
        )
        if typed_result.error_kind == "no_match" and (stage_name, wanted_name) in missing_binding_keys:
            typed_stages = _remove_typed_consume(typed_stages, stage_name, typed_result.wanted)
            continue
        message, details = _contract_failure_message_and_details(typed_result)
        diag.add_defect(
            f"stage {stage_name!r}: {message}",
            code=contract_diagnostic_code(typed_result.error_kind),
            stage=stage_name,
            details=details,
        )
        typed_stages = _remove_typed_consume(typed_stages, stage_name, typed_result.wanted)

    return diag


# ── Prompt / resource dependency validation ──────────────────────────────────


def _stage_step(stage: Any) -> Any:
    """Duck-typed accessor for the step inside a stage.

    Handles both ``Stage.step`` (single step) and ``ParallelStage.steps``
    (tuple of steps).  For parallel stages the first step is returned as
    the representative for prompt_key lookups.
    """
    step = getattr(stage, "step", None)
    if step is not None:
        return step
    steps = getattr(stage, "steps", None)
    if steps is not None and len(steps) > 0:
        return steps[0]
    return None


def _step_prompt_key(stage: Any) -> str | None:
    """Duck-typed accessor for ``prompt_key`` on a stage's step.

    Returns the ``prompt_key`` from ``stage.step`` (or first step in
    ``stage.steps``), or ``None`` when no step carries one.
    """
    step = _stage_step(stage)
    if step is None:
        return None
    return getattr(step, "prompt_key", None)


def _pipeline_resource_bundles(pipeline: Any) -> tuple[Any, ...]:
    """Duck-typed accessor for ``resource_bundles`` on a pipeline."""
    bundles = getattr(pipeline, "resource_bundles", ()) or ()
    if isinstance(bundles, tuple):
        return bundles
    if isinstance(bundles, (list, set)):
        return tuple(bundles)
    return ()


def _looks_like_native_program(bundle: Any) -> bool:
    """Return True for compiled native execution bundles.

    Native programs live in ``resource_bundles`` for dispatch, but they
    are not prompt/resource bundles and their ``name`` field should not
    satisfy or constrain prompt-key validation.
    """
    return (
        hasattr(bundle, "instructions")
        and hasattr(bundle, "phases")
        and hasattr(bundle, "decisions")
    )


def _prompt_key_covered_by_bundle_prompts(
    prompt_key: str,
    bundle_prompt_keys: set[str],
) -> bool:
    """Return whether a bundle-owned prompt mapping can satisfy *prompt_key*."""
    if prompt_key in bundle_prompt_keys:
        return True
    scoped_suffix = f"/{prompt_key}"
    return any(key.endswith(scoped_suffix) for key in bundle_prompt_keys)


def validate_resource_dependencies(
    pipeline: Any, options: ValidationOptions | None = None
) -> Diagnostics:
    """Validate prompt/resource dependencies for every stage.

    Checks performed:

    1. Every stage whose step declares a ``prompt_key`` must have that
       key resolvable — by convention the pipeline's ``resource_bundles``
       tuple carries bundle objects that downstream prompt resolution
       uses.  A missing prompt key (non-None ``prompt_key`` with no
       matching resource bundle) is flagged.

    2. Every ``resource_bundle`` name declared on the pipeline is
       reported for coverage (bundle-scoped validation).

    3. Deterministic ordering: defects are emitted in sorted stage-name
       order so callers see stable output.

    This function performs **NO global mutable prompt registry** lookup.
    It duck-types ``prompt_key`` from both Arnold and Megaplan step
    shapes via :func:`_step_prompt_key`.

    Parameters
    ----------
    pipeline:
        A pipeline whose stages carry steps with optional ``prompt_key``
        and whose ``resource_bundles`` tuple carries bundle descriptors.
    options:
        Optional :class:`ValidationOptions` (unused for now; accepted for
        signature consistency).

    Returns
    -------
    Diagnostics:
        A :class:`Diagnostics` whose ``defects`` list is empty iff
        every prompt/resource dependency is satisfiable.
    """
    if options is None:
        options = ValidationOptions()

    diag = Diagnostics()
    stages: dict[str, Any] = dict(getattr(pipeline, "stages", {}) or {})
    if not stages:
        return diag

    bundles = _pipeline_resource_bundles(pipeline)

    # Collect known bundle identifiers — a bundle may be a string name,
    # an object carrying a ``name`` / ``bundle_key`` attribute, or a
    # PipelineResourceBundle-style object with a prompt mapping.
    known_bundle_names: set[str] = set()
    bundle_prompt_keys: set[str] = set()
    for b in bundles:
        if isinstance(b, str):
            known_bundle_names.add(b)
        else:
            prompts = getattr(b, "prompts", None)
            if isinstance(prompts, Mapping):
                bundle_prompt_keys.update(
                    key for key in prompts if isinstance(key, str)
                )
                continue
            if _looks_like_native_program(b):
                continue
            bname = getattr(b, "name", None) or getattr(b, "bundle_key", None)
            if bname is not None and isinstance(bname, str):
                known_bundle_names.add(bname)

    # ── Walk stages in deterministic (sorted) order ────────────────────
    for stage_name in sorted(stages):
        stage = stages[stage_name]
        prompt_key = _step_prompt_key(stage)

        if prompt_key is not None and isinstance(prompt_key, str) and prompt_key.strip():
            # A step declares it needs a prompt_key — check against bundles
            if known_bundle_names or bundle_prompt_keys:
                resolved = _prompt_key_covered_by_bundle_prompts(
                    prompt_key,
                    bundle_prompt_keys,
                )
                if not resolved:
                    resolved = any(
                        name == prompt_key or prompt_key.startswith(name)
                        for name in known_bundle_names
                    )
                if not resolved:
                    available = sorted(known_bundle_names | bundle_prompt_keys)
                    diag.add_defect(
                        f"stage {stage_name!r}: prompt_key {prompt_key!r} references "
                        f"no known resource bundle (available: {available})",
                        code="prompt_key_unknown_resource_bundle",
                        stage=stage_name,
                        details={
                            "prompt_key": prompt_key,
                            "available_bundles": available,
                        },
                    )

            # Also report bundle-scoped coverage: flag stages that have prompt_keys
            # but no bundles at all on the pipeline (soft defect — the pipeline
            # may rely on a separate prompt registry).
            if not bundles:
                diag.add_defect(
                    f"stage {stage_name!r}: declares prompt_key {prompt_key!r} "
                    f"but pipeline has no resource_bundles",
                    code="prompt_key_missing_resource_bundles",
                    stage=stage_name,
                    details={"prompt_key": prompt_key},
                )

    return diag


# ── Cycle detection ───────────────────────────────────────────────────────


def _detect_unguarded_cycles(
    stages: Mapping[str, Any],
    entry: str,
    diag: Diagnostics,
) -> None:
    """DFS-based unguarded-cycle detection.

    A cycle is *guarded* when at least one edge in the cycle targets a
    stage that declares a ``loop_condition``.  Unguarded cycles are
    flagged as defects.
    """
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {name: WHITE for name in stages}
    # parent_edge tracks (src, target) for each DFS-tree edge
    parent_edge: dict[str, tuple[str, str] | None] = {name: None for name in stages}

    def _edge_targets(src_name: str) -> list[tuple[str, Any]]:
        """Return list of (target_name, edge) for non-halt edges from src."""
        stage = stages.get(src_name)
        if stage is None:
            return []
        result: list[tuple[str, Any]] = []
        for edge in _stage_edges(stage):
            target = getattr(edge, "target", "")
            if target != "halt" and target in stages:
                result.append((target, edge))
        return result

    def _dfs(node: str) -> None:
        color[node] = GRAY
        for neighbor, edge in _edge_targets(node):
            if color[neighbor] == GRAY:
                # Back edge found — extract the cycle
                cycle = _extract_cycle(node, neighbor, parent_edge)
                if not _cycle_has_guard(cycle, stages):
                    cycle_str = " → ".join(cycle)
                    diag.add_defect(
                        f"unguarded cycle detected: {cycle_str} "
                        "(add a loop_condition to at least one stage in the cycle)",
                        code="unguarded_cycle_detected",
                        stage=neighbor,
                        details={"cycle": cycle},
                    )
            elif color[neighbor] == WHITE:
                parent_edge[neighbor] = (node, neighbor)
                _dfs(neighbor)
        color[node] = BLACK

    # Start DFS from entry and any other unvisited nodes
    if entry in color:
        _dfs(entry)
    for name in stages:
        if color.get(name) == WHITE:
            _dfs(name)


def _extract_cycle(
    start: str,
    back_target: str,
    parent_edge: dict[str, tuple[str, str] | None],
) -> list[str]:
    """Extract the cycle path from *start* back to *back_target* via parent edges."""
    # Walk from start up the parent chain to back_target
    path: list[str] = [start]
    current = start
    while current != back_target:
        pe = parent_edge.get(current)
        if pe is None:
            break
        src, _ = pe
        path.append(src)
        current = src
    path.append(start)  # close the cycle
    path.reverse()
    return path


def _cycle_has_guard(
    cycle: list[str],
    stages: Mapping[str, Any],
) -> bool:
    """Return True if any stage in *cycle* has a ``loop_condition``."""
    for name in cycle:
        stage = stages.get(name)
        if stage is not None:
            lc = getattr(stage, "loop_condition", None)
            if lc is not None:
                return True
    return False
