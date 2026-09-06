"""Private support for immutable completion-binding codecs.

The public binding records remain defined in binding.py.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Sequence

from arnold.workflow.completion.hashing import hash_canonical

_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")


class BindingVersionError(ValueError):
    """An unsupported binding version was encountered before body use."""


class AmbiguousBindingError(ValueError):
    """Legacy and canonical coordinate shapes were supplied together."""


def _digest(value: str, field: str) -> None:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ValueError(f"{field} must be a sha256: digest")


def _freeze(value: Any, field: str) -> Any:
    if isinstance(value, Mapping):
        return tuple(sorted((str(k), _freeze(v, f"{field}.{k}")) for k, v in value.items()))
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return tuple(_freeze(v, f"{field}[]") for v in value)
    if isinstance(value, (str, int, bool, float)) or value is None:
        return value
    raise TypeError(f"{field} must be JSON-like")


def _thaw(value: Any) -> Any:
    if isinstance(value, tuple):
        if value and all(isinstance(v, tuple) and len(v) == 2 and isinstance(v[0], str) for v in value):
            return {k: _thaw(v) for k, v in value}
        return [_thaw(v) for v in value]
    return value


def _coalesce(*values: Any) -> Any:
    meaningful = [v for v in values if v is not None and v != ""]
    if meaningful and any(v != meaningful[0] for v in meaningful[1:]):
        raise ValueError("conflicting binding field aliases")
    if meaningful:
        return meaningful[0]
    return next((v for v in values if v is not None), None)



def _looks_scope(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    has_identity = (
        {"subject_id", "occurrence_id"}.issubset(value)
        or {"subject", "occurrence"}.issubset(value)
    )
    return has_identity and any(
        key in value for key in ("evidence_window", "window", "cursor_window")
    )


def _legacy_window(value: Any, start: Any = None, end: Any = None) -> tuple[str, str]:
    raw = ("" if start is None else start, "" if end is None else end) if start is not None or end is not None else (value if value is not None else ("", ""))
    if isinstance(raw, Mapping):
        raw = (raw.get("start", raw.get("evidence_window_start")), raw.get("end", raw.get("evidence_window_end")))
    if isinstance(raw, str) or not isinstance(raw, Sequence):
        raise ValueError("legacy evidence_window must retain two string coordinates")
    result = tuple(raw)
    if len(result) != 2 or any(not isinstance(v, str) for v in result):
        raise ValueError("legacy evidence_window must retain two string coordinates")
    return result


def _materialize(values: Any) -> tuple[Any, ...]:
    """Materialize a collection once so hashing and construction agree."""
    if values is None:
        return ()
    if isinstance(values, (str, bytes, Mapping)):
        return (values,)
    if isinstance(values, Sequence):
        return tuple(values)
    try:
        return tuple(values)
    except TypeError:
        return (values,)



def _artifacts(values: Iterable[Any]) -> tuple[Any, ...]:
    return tuple(_freeze(v, "bound_artifacts[]") for v in _materialize(values))


def _legacy_artifacts(values: Iterable[Any]) -> tuple[str, ...]:
    return tuple(str(value) for value in _materialize(values))


def _legacy_payload(spec_hash: str, subject: SubjectInstanceId, window: tuple[str, str], obligation_id: str, source: str, artifacts: Iterable[Any], schema: str) -> dict[str, Any]:
    return {
        "spec_hash": spec_hash,
        "subject_instance_id": subject.to_dict(),
        "evidence_window": list(window),
        "obligation_id": obligation_id,
        "admission_source": source,
        "bound_artifacts": list(_legacy_artifacts(artifacts)),
        "schema_version": schema,
    }



_CANONICAL_ALIASES: dict[str, tuple[str, ...]] = {
    "semantic_path": ("semantic_path", "path"),
    "component_lock": (
        "component_lock",
        "component_graph_lock",
        "component_graph",
        "component_digest",
    ),
    "graph_lock": ("graph_lock", "graph_digest"),
    "installed_artifact_digest": (
        "installed_artifact_digest",
        "installed_artifact",
        "installed_artifact_lock",
        "artifact_digest",
    ),
    "prompt_asset_digest": ("prompt_asset_digest", "prompt_asset", "prompt_digest"),
    "tool_asset_digest": ("tool_asset_digest", "tool_asset", "tool_digest"),
    "policy_asset_digest": ("policy_asset_digest", "policy_asset", "policy_digest"),
    "prompt_tool_bindings_digest": (
        "prompt_tool_bindings_digest",
        "prompt_tool_bindings",
        "prompt_tool_binding",
        "prompt_tool_digest",
        "tool_binding_digest",
    ),
    "call_site_policy_digest": (
        "call_site_policy_digest",
        "call_site_policy",
        "callsite_policy_digest",
    ),
    "admission_receipt": (
        "admission_receipt",
        "admission_receipt_ref",
        "admission_receipt_digest",
    ),
    "product_contract_digest": (
        "product_contract_digest",
        "product_contract",
        "product_contract_ref",
    ),
    "asset_digests": (
        "asset_digests",
        "assets",
        "artifact_digests",
        "asset_locks",
        "behavior_asset_digests",
    ),
    "artifact_locks": ("artifact_locks", "artifact_lock"),
}
_ALIASES = frozenset(alias for aliases in _CANONICAL_ALIASES.values() for alias in aliases)
_CANONICAL_CONTROL_FIELDS = frozenset(
    {
        "compatibility",
        "schema_version",
        "additional_locks",
        "evidence_scope",
        "scope",
        "evidence_window",
        "evidence_window_start",
        "evidence_window_end",
    }
)
_CANONICAL_INPUT_FIELDS = _ALIASES | {"additional_locks"}


def _canonical_parts(
    values: Mapping[str, Any],
    *,
    default_artifact_locks: Iterable[Any] = (),
) -> dict[str, Any]:
    get = values.get

    def field(name: str, default: Any = None) -> Any:
        if name == "artifact_locks":
            if "artifact_locks" in values or "artifact_lock" in values:
                return _coalesce(get("artifact_locks"), get("artifact_lock"))
            return default
        return _coalesce(*(get(alias) for alias in _CANONICAL_ALIASES[name]))

    known = _CANONICAL_INPUT_FIELDS | _CANONICAL_CONTROL_FIELDS
    raw_extra = {
        str(key): value for key, value in values.items() if key not in known
    }
    supplied_extra = get("additional_locks")
    if supplied_extra is None:
        supplied_extra = raw_extra
    elif raw_extra:
        if isinstance(supplied_extra, Mapping):
            supplied_extra = {**supplied_extra, **raw_extra}
        else:
            raise TypeError("additional_locks must be a mapping")
    artifact_locks = field("artifact_locks", _materialize(default_artifact_locks))
    return {
        "semantic_path": field("semantic_path") or "",
        "component_lock": _freeze(field("component_lock"), "component_lock"),
        "graph_lock": _freeze(field("graph_lock"), "graph_lock"),
        "installed_artifact_digest": _freeze(field("installed_artifact_digest"), "installed_artifact_digest"),
        "prompt_asset_digest": _freeze(field("prompt_asset_digest"), "prompt_asset_digest"),
        "tool_asset_digest": _freeze(field("tool_asset_digest"), "tool_asset_digest"),
        "policy_asset_digest": _freeze(field("policy_asset_digest"), "policy_asset_digest"),
        "prompt_tool_bindings_digest": _freeze(field("prompt_tool_bindings_digest"), "prompt_tool_bindings_digest"),
        "call_site_policy_digest": _freeze(field("call_site_policy_digest"), "call_site_policy_digest"),
        "admission_receipt": _freeze(field("admission_receipt"), "admission_receipt"),
        "product_contract_digest": _freeze(field("product_contract_digest"), "product_contract_digest"),
        "asset_digests": _freeze(field("asset_digests"), "asset_digests"),
        "artifact_locks": _freeze(artifact_locks, "artifact_locks"),
        "additional_locks": _freeze(supplied_extra, "additional_locks"),
    }
def _canonical_payload(spec_hash: str, subject: SubjectInstanceId, scope: EvidenceScope, obligation_id: str, source: str, parts: Mapping[str, Any], artifacts: Any, schema: str) -> dict[str, Any]:
    return {"spec_hash": spec_hash, "subject_instance_id": subject.to_dict(), "obligation_id": obligation_id, "admission_source": source, "evidence_scope": scope.to_dict(), **{k: _thaw(v) for k, v in parts.items()}, "bound_artifacts": _thaw(artifacts), "schema_version": schema}


def compute_binding_hash_core(spec_hash, subject, evidence_window, evidence_window_start, evidence_window_end, obligation_id, admission_source, bound_artifacts, schema_version, *, evidence_scope=None, scope=None, fields=None, canonical_schema="arnold.workflow.completion_binding.v2", legacy_schema="arnold.workflow.completion_binding.v1"):
    fields = {} if fields is None else fields
    window_scope = evidence_window if _looks_scope(evidence_window) else None
    actual_scope = _coalesce(evidence_scope, scope, window_scope)
    if window_scope is not None:
        evidence_window = None
    if actual_scope is not None:
        if evidence_window not in (None, ("", "")) or evidence_window_start or evidence_window_end:
            raise ValueError("canonical binding cannot use a legacy evidence window")
        actual_schema = fields.get("schema_version", schema_version) or canonical_schema
        if actual_schema != canonical_schema:
            raise ValueError("canonical evidence scope requires the v2 binding schema")
        values = _materialize(bound_artifacts)
        parts = _canonical_parts(fields, default_artifact_locks=values)
        scope_value = actual_scope if hasattr(actual_scope, "to_dict") else actual_scope
        payload = _canonical_payload(spec_hash, subject, scope_value, obligation_id, admission_source, parts, _artifacts(values), actual_schema)
        return hash_canonical(payload)
    if fields:
        raise ValueError("legacy C1 binding cannot carry canonical lock fields")
    actual_schema = schema_version or legacy_schema
    if actual_schema != legacy_schema:
        raise ValueError("legacy coordinates require the C1 binding schema version")
    artifacts = _legacy_artifacts(bound_artifacts)
    return hash_canonical(_legacy_payload(spec_hash, subject, _legacy_window(evidence_window, evidence_window_start, evidence_window_end), obligation_id, admission_source, artifacts, actual_schema))

__all__ = [name for name in globals() if not name.startswith("__")]
