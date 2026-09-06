"""Immutable C2 completion bindings and pure admission/resume decisions.

The C1 two-string shape is retained as ``legacy/unknown``.  Its values are
never converted into cursor coordinates.  C2 bindings use the canonical
``EvidenceScope`` and hash all semantic and artifact locks.  This package is
experimental and non-authoritative.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import re
from typing import Any, Iterable, Mapping, Sequence

from arnold.workflow.completion.evidence import EvidenceScope
from arnold.workflow.completion.hashing import hash_canonical
from arnold.workflow.completion.spec import CompletionSpec, SubjectKind
from ._binding_support import (_ALIASES, _CANONICAL_INPUT_FIELDS, _artifacts, _canonical_parts, _canonical_payload, _coalesce, _digest, _freeze, _legacy_artifacts, _legacy_payload, _legacy_window, _looks_scope, _materialize, _thaw, compute_binding_hash_core)


LEGACY_BINDING_SCHEMA_VERSION = "arnold.workflow.completion_binding.v1"
CANONICAL_BINDING_SCHEMA_VERSION = "arnold.workflow.completion_binding.v2"
BINDING_SCHEMA_VERSION = CANONICAL_BINDING_SCHEMA_VERSION
SUPPORTED_BINDING_SCHEMA_VERSIONS = frozenset({LEGACY_BINDING_SCHEMA_VERSION, CANONICAL_BINDING_SCHEMA_VERSION})


class BindingVersionError(ValueError):
    """An unsupported binding version was encountered before body use."""


class AmbiguousBindingError(ValueError):
    """Legacy and canonical coordinate shapes were supplied together."""


def _subject(value: SubjectInstanceId | str, kind: SubjectKind = SubjectKind.STEP) -> SubjectInstanceId:
    return value if isinstance(value, SubjectInstanceId) else SubjectInstanceId(value, kind)


def _scope(value: EvidenceScope | Mapping[str, Any]) -> EvidenceScope:
    if isinstance(value, EvidenceScope):
        return value
    if isinstance(value, Mapping):
        return EvidenceScope.from_dict(value)
    raise TypeError("evidence_scope must be an EvidenceScope")


@dataclass(frozen=True)
class SubjectInstanceId:
    """Typed identity of one admitted subject occurrence."""

    id: str
    subject_kind: SubjectKind

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id:
            raise ValueError("CompletionBinding.subject_instance_id.id must be non-empty")
        if isinstance(self.subject_kind, str):
            object.__setattr__(self, "subject_kind", SubjectKind(self.subject_kind))
        if not isinstance(self.subject_kind, SubjectKind):
            raise TypeError("SubjectInstanceId.subject_kind must be a SubjectKind")

    def to_dict(self) -> dict[str, str]:
        return {"id": self.id, "subject_kind": self.subject_kind.value}

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return self.id == other
        if isinstance(other, SubjectInstanceId):
            return (self.id, self.subject_kind) == (other.id, other.subject_kind)
        return NotImplemented

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> SubjectInstanceId:
        return cls(str(value["id"]), str(value["subject_kind"]))


def compute_binding_hash(
    spec_hash: str,
    subject_instance_id: SubjectInstanceId | str,
    evidence_window: Any = ("", ""),
    evidence_window_start: str | None = None,
    evidence_window_end: str | None = None,
    obligation_id: str = "legacy",
    admission_source: str = "legacy",
    bound_artifacts: Iterable[Any] = (),
    schema_version: str | None = None,
    *,
    evidence_scope: EvidenceScope | Mapping[str, Any] | None = None,
    scope: EvidenceScope | Mapping[str, Any] | None = None,
    **fields: Any,
) -> str:
    window_scope = evidence_window if isinstance(evidence_window, EvidenceScope) or _looks_scope(evidence_window) else None
    actual_scope = _coalesce(evidence_scope, scope, window_scope)
    if window_scope is not None:
        evidence_window = None
    subject = _subject(subject_instance_id)
    if actual_scope is not None:
        if evidence_window not in (None, ("", "")) or evidence_window_start or evidence_window_end:
            raise AmbiguousBindingError("canonical binding cannot use a legacy evidence window")
        actual_schema = fields.get("schema_version", schema_version) or CANONICAL_BINDING_SCHEMA_VERSION
        if actual_schema != CANONICAL_BINDING_SCHEMA_VERSION:
            raise AmbiguousBindingError("canonical evidence scope requires the v2 binding schema")
        bound_artifact_values = _materialize(bound_artifacts)
        parts = _canonical_parts(fields, default_artifact_locks=bound_artifact_values)
        return hash_canonical(_canonical_payload(spec_hash, subject, _scope(actual_scope), obligation_id, admission_source, parts, _artifacts(bound_artifact_values), actual_schema))
    if fields:
        raise AmbiguousBindingError("legacy C1 binding cannot carry canonical lock fields")
    actual_schema = schema_version or LEGACY_BINDING_SCHEMA_VERSION
    if actual_schema != LEGACY_BINDING_SCHEMA_VERSION:
        raise AmbiguousBindingError("legacy coordinates require the C1 binding schema version")
    artifacts = _legacy_artifacts(bound_artifacts)
    return hash_canonical(_legacy_payload(spec_hash, subject, _legacy_window(evidence_window, evidence_window_start, evidence_window_end), obligation_id, admission_source, artifacts, actual_schema))
@dataclass(frozen=True, init=False)
class CompletionBinding:
    """Immutable C2 binding, or an explicitly legacy/unknown C1 record."""

    binding_hash: str
    spec_hash: str
    subject_instance_id: SubjectInstanceId
    obligation_id: str
    admission_source: str
    evidence_scope: EvidenceScope | None
    semantic_path: str
    component_lock: Any
    graph_lock: Any
    installed_artifact_digest: Any
    prompt_asset_digest: Any
    tool_asset_digest: Any
    policy_asset_digest: Any
    prompt_tool_bindings_digest: Any
    call_site_policy_digest: Any
    admission_receipt: Any
    product_contract_digest: Any
    asset_digests: Any
    artifact_lock_set: Any
    additional_locks: Any
    bound_artifacts: Any
    schema_version: str
    evidence_window: tuple[str, str] | None
    evidence_window_start: str
    evidence_window_end: str
    compatibility: str

    def __init__(self, binding_hash: str, spec_hash: str, subject_instance_id: SubjectInstanceId | str, obligation_id: str = "legacy", admission_source: str = "legacy", evidence_window: Any = None, bound_artifacts: Iterable[Any] = (), schema_version: str | None = None, evidence_window_start: str | None = None, evidence_window_end: str | None = None, *, evidence_scope: EvidenceScope | Mapping[str, Any] | None = None, scope: EvidenceScope | Mapping[str, Any] | None = None, **fields: Any) -> None:
        window_scope = evidence_window if isinstance(evidence_window, EvidenceScope) or _looks_scope(evidence_window) else None
        actual_scope = _coalesce(evidence_scope, scope, window_scope)
        if window_scope is not None:
            evidence_window = None
        canonical = actual_scope is not None
        if canonical and (evidence_window not in (None, ("", "")) or evidence_window_start or evidence_window_end):
            raise AmbiguousBindingError("canonical binding cannot use a legacy evidence window")
        schema = schema_version or (CANONICAL_BINDING_SCHEMA_VERSION if canonical else LEGACY_BINDING_SCHEMA_VERSION)
        if schema not in SUPPORTED_BINDING_SCHEMA_VERSIONS:
            raise BindingVersionError(f"unsupported CompletionBinding schema version: {schema}")
        if canonical and schema != CANONICAL_BINDING_SCHEMA_VERSION:
            raise AmbiguousBindingError("canonical evidence scope requires the v2 binding schema")
        if not canonical and schema != LEGACY_BINDING_SCHEMA_VERSION:
            raise AmbiguousBindingError("legacy coordinates require the C1 binding schema version")
        subject = _subject(subject_instance_id)
        _digest(binding_hash, "CompletionBinding.binding_hash")
        if not spec_hash or not obligation_id or not admission_source:
            raise ValueError("CompletionBinding identity fields must be non-empty")
        bound_artifact_values = _materialize(bound_artifacts)
        artifacts = _artifacts(bound_artifact_values)
        if canonical:
            scope_value = _scope(actual_scope)
            parts = _canonical_parts(fields, default_artifact_locks=bound_artifact_values)
            expected = hash_canonical(_canonical_payload(spec_hash, subject, scope_value, obligation_id, admission_source, parts, artifacts, schema))
            window = None
            status = "canonical"
        else:
            if fields:
                raise AmbiguousBindingError("legacy C1 binding cannot carry canonical lock fields")
            scope_value = None
            window = _legacy_window(evidence_window, evidence_window_start, evidence_window_end)
            expected = hash_canonical(_legacy_payload(spec_hash, subject, window, obligation_id, admission_source, artifacts, schema))
            status = "legacy/unknown"
        if binding_hash != expected:
            raise ValueError(f"CompletionBinding binding_hash mismatch: got {binding_hash!r}, expected {expected!r}")
        if fields.get("compatibility") not in (None, "", status):
            raise ValueError(f"CompletionBinding compatibility must be {status!r}")
        parts = _canonical_parts(fields, default_artifact_locks=bound_artifact_values)
        parts["artifact_lock_set"] = parts.pop("artifact_locks")
        for name, value in {
            "binding_hash": binding_hash, "spec_hash": spec_hash, "subject_instance_id": subject,
            "obligation_id": obligation_id, "admission_source": admission_source, "evidence_scope": scope_value,
            **parts, "bound_artifacts": artifacts, "schema_version": schema, "evidence_window": window,
            "evidence_window_start": window[0] if window else "", "evidence_window_end": window[1] if window else "",
            "compatibility": status,
        }.items():
            object.__setattr__(self, name, value)
    @property
    def is_legacy(self) -> bool:
        return self.compatibility == "legacy/unknown"
    @property
    def is_canonical(self) -> bool:
        return not self.is_legacy
    @property
    def legacy_unknown(self) -> bool:
        return self.is_legacy
    @property
    def compatibility_status(self) -> str:
        return self.compatibility
    @property
    def scope(self) -> EvidenceScope | None:
        return self.evidence_scope
    @property
    def canonical_scope(self) -> EvidenceScope | None:
        return self.evidence_scope
    @property
    def evidence_window_record(self) -> Any:
        return self.evidence_scope.evidence_window if self.evidence_scope else None
    @property
    def occurrence_key(self) -> tuple[Any, ...]:
        if not self.evidence_scope:
            return (self.subject_instance_id.id,)
        return (self.evidence_scope.subject_id, self.evidence_scope.occurrence_id)
    @property
    def installed_artifact(self) -> Any:
        return _thaw(self.installed_artifact_digest)
    @property
    def prompt_digest(self) -> Any:
        return _thaw(self.prompt_asset_digest)
    @property
    def tool_digest(self) -> Any:
        return _thaw(self.tool_asset_digest)
    @property
    def policy_digest(self) -> Any:
        return _thaw(self.policy_asset_digest)
    @property
    def artifact_locks(self) -> Any:
        return _thaw(self.artifact_lock_set)
    def to_dict(self) -> dict[str, Any]:
        if self.is_legacy:
            return {"binding_hash": self.binding_hash, "spec_hash": self.spec_hash, "obligation_id": self.obligation_id, "subject_instance_id": self.subject_instance_id.to_dict(), "admission_source": self.admission_source, "evidence_window": list(self.evidence_window or ("", "")), "bound_artifacts": [_thaw(v) for v in self.bound_artifacts], "schema_version": self.schema_version}
        return {"binding_hash": self.binding_hash, "spec_hash": self.spec_hash, "obligation_id": self.obligation_id, "subject_instance_id": self.subject_instance_id.to_dict(), "admission_source": self.admission_source, "semantic_path": self.semantic_path, "evidence_scope": self.evidence_scope.to_dict() if self.evidence_scope else None, "component_lock": _thaw(self.component_lock), "graph_lock": _thaw(self.graph_lock), "installed_artifact_digest": _thaw(self.installed_artifact_digest), "prompt_asset_digest": _thaw(self.prompt_asset_digest), "tool_asset_digest": _thaw(self.tool_asset_digest), "policy_asset_digest": _thaw(self.policy_asset_digest), "prompt_tool_bindings_digest": _thaw(self.prompt_tool_bindings_digest), "call_site_policy_digest": _thaw(self.call_site_policy_digest), "admission_receipt": _thaw(self.admission_receipt), "product_contract_digest": _thaw(self.product_contract_digest), "asset_digests": _thaw(self.asset_digests), "artifact_locks": _thaw(self.artifact_lock_set), "additional_locks": _thaw(self.additional_locks), "bound_artifacts": [_thaw(v) for v in self.bound_artifacts], "schema_version": self.schema_version}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CompletionBinding:
        schema = str(data.get("schema_version", LEGACY_BINDING_SCHEMA_VERSION))
        if schema not in SUPPORTED_BINDING_SCHEMA_VERSIONS:
            raise BindingVersionError(f"unsupported CompletionBinding schema version: {schema}")
        subject = data["subject_instance_id"]
        subject = SubjectInstanceId.from_dict(subject) if isinstance(subject, Mapping) else _subject(str(subject))
        raw_scope = _coalesce(data.get("evidence_scope"), data.get("scope"))
        if raw_scope is not None:
            if any(k in data for k in ("evidence_window", "evidence_window_start", "evidence_window_end")):
                raise AmbiguousBindingError("binding contains both canonical scope and legacy window")
            extras = {k: data[k] for k in _CANONICAL_INPUT_FIELDS if k in data}
            return cls(str(data["binding_hash"]), str(data["spec_hash"]), subject, str(data.get("obligation_id", "legacy")), str(data.get("admission_source", "legacy")), bound_artifacts=data.get("bound_artifacts", ()), schema_version=schema, evidence_scope=raw_scope, **extras)
        if _ALIASES.intersection(data) or "additional_locks" in data:
            raise AmbiguousBindingError("legacy C1 binding cannot carry canonical lock fields")
        return cls(str(data["binding_hash"]), str(data["spec_hash"]), subject, str(data.get("obligation_id", "legacy")), str(data.get("admission_source", "legacy")), data.get("evidence_window"), data.get("bound_artifacts", ()), schema)


class AdmissionDisposition(StrEnum):
    ADMITTED = "admitted"
    IDEMPOTENT = "idempotent"
    CONFLICT = "conflict"
    LEGACY_UNKNOWN = "legacy/unknown"
    MIGRATION = "migration"
    NEW_ATTEMPT = "new_attempt"
    QUARANTINE = "quarantine"
BindingAdmissionDisposition = AdmissionDisposition


@dataclass(frozen=True)
class BindingAdmission:
    binding: CompletionBinding | None
    disposition: AdmissionDisposition
    accepted: bool
    reason: str = ""
    existing: CompletionBinding | None = None

    @property
    def status(self) -> str:
        return self.disposition.value

    @property
    def idempotent(self) -> bool:
        return self.disposition is AdmissionDisposition.IDEMPOTENT

    @property
    def conflict(self) -> bool:
        return self.disposition is AdmissionDisposition.CONFLICT

    def __bool__(self) -> bool:
        return self.accepted


AdmissionResult = BindingAdmission
BindingAdmissionResult = BindingAdmission


def _coerce(value: CompletionBinding | Mapping[str, Any]) -> CompletionBinding:
    return value if isinstance(value, CompletionBinding) else CompletionBinding.from_dict(value)


def _existing(value: Any) -> tuple[CompletionBinding, ...]:
    if value is None:
        return ()
    if isinstance(value, CompletionBinding):
        return (value,)
    if isinstance(value, Mapping):
        return (_coerce(value),) if "binding_hash" in value else tuple(_coerce(v) for v in value.values())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return tuple(_coerce(v) for v in value)
    raise TypeError("existing bindings must be a binding, mapping, or sequence")


def _same_occurrence(left: CompletionBinding, right: CompletionBinding) -> bool:
    if left.is_canonical and right.is_canonical:
        return (
            left.evidence_scope.subject_id,
            left.evidence_scope.occurrence_id,
        ) == (
            right.evidence_scope.subject_id,
            right.evidence_scope.occurrence_id,
        )
    return left.subject_instance_id.id == right.subject_instance_id.id


def _admission_disposition(value: Any) -> AdmissionDisposition | None:
    if value is None:
        return None
    text = str(value).lower().replace("-", "_")
    aliases = {
        "migration_required": AdmissionDisposition.MIGRATION,
        "new_attempt_required": AdmissionDisposition.NEW_ATTEMPT,
        "quarantine_required": AdmissionDisposition.QUARANTINE,
    }
    if text in aliases:
        return aliases[text]
    return AdmissionDisposition(text)


def admit_binding(candidate: CompletionBinding | Mapping[str, Any], existing: Any = None, *, disposition: AdmissionDisposition | str | None = None) -> BindingAdmission:
    binding = _coerce(candidate)
    selected = _admission_disposition(disposition)
    if binding.is_legacy:
        if selected is None:
            return BindingAdmission(None, AdmissionDisposition.LEGACY_UNKNOWN, False, "C1 binding requires migration, new attempt, or quarantine")
        if selected not in {AdmissionDisposition.MIGRATION, AdmissionDisposition.NEW_ATTEMPT, AdmissionDisposition.QUARANTINE}:
            raise ValueError("legacy binding requires migration, new_attempt, or quarantine")
        return BindingAdmission(binding, selected, True, "explicit disposition selected; legacy coordinates remain uninterpreted")
    for prior in _existing(existing):
        if prior.binding_hash == binding.binding_hash:
            return BindingAdmission(prior, AdmissionDisposition.IDEMPOTENT, True, "identical binding already admitted", prior)
        if _same_occurrence(prior, binding):
            if prior.is_legacy:
                if selected in {AdmissionDisposition.MIGRATION, AdmissionDisposition.NEW_ATTEMPT, AdmissionDisposition.QUARANTINE}:
                    return BindingAdmission(binding, selected, True, "explicit disposition selected for legacy predecessor", prior)
                return BindingAdmission(None, AdmissionDisposition.LEGACY_UNKNOWN, False, "legacy predecessor requires migration, new attempt, or quarantine", prior)
            if selected in {AdmissionDisposition.MIGRATION, AdmissionDisposition.NEW_ATTEMPT, AdmissionDisposition.QUARANTINE}:
                return BindingAdmission(binding, selected, True, "explicit disposition selected for conflicting occurrence", prior)
            return BindingAdmission(None, AdmissionDisposition.CONFLICT, False, "conflicting binding for admitted occurrence", prior)
    return BindingAdmission(binding, AdmissionDisposition.ADMITTED, True, "new immutable binding admitted")


admit = admit_binding
admit_occurrence = admit_binding


class ResumeDisposition(StrEnum):
    PINNED = "pinned"
    MIGRATION = "migration"
    NEW_ATTEMPT = "new_attempt"
    QUARANTINE = "quarantine"
    REQUIRES_EXPLICIT = "requires_explicit_disposition"
    LEGACY_UNKNOWN = "legacy/unknown"
BindingResumeDisposition = ResumeDisposition


@dataclass(frozen=True)
class BindingResume:
    binding: CompletionBinding | None
    disposition: ResumeDisposition
    accepted: bool
    reason: str = ""
    required_dispositions: tuple[str, ...] = ("migration", "new_attempt", "quarantine")

    @property
    def status(self) -> str:
        return self.disposition.value

    @property
    def pinned(self) -> bool:
        return self.disposition is ResumeDisposition.PINNED

    @property
    def requires_explicit_disposition(self) -> bool:
        return self.disposition in {ResumeDisposition.REQUIRES_EXPLICIT, ResumeDisposition.LEGACY_UNKNOWN}

    @property
    def requires_new_binding(self) -> bool:
        return self.requires_explicit_disposition or bool(self.binding and self.binding.is_legacy)

    def __bool__(self) -> bool:
        return self.accepted


ResumeResult = BindingResume
BindingResumeResult = BindingResume


def _resume_disposition(value: Any) -> ResumeDisposition | None:
    if value is None:
        return None
    text = str(value).lower().replace("-", "_")
    aliases = {
        "migration_required": ResumeDisposition.MIGRATION,
        "new_attempt_required": ResumeDisposition.NEW_ATTEMPT,
        "quarantine_required": ResumeDisposition.QUARANTINE,
    }
    if text in aliases:
        return aliases[text]
    return ResumeDisposition(text)


def resume_binding(pinned: CompletionBinding | Mapping[str, Any], requested: CompletionBinding | Mapping[str, Any] | None = None, *, disposition: ResumeDisposition | str | None = None, migration: bool = False, new_attempt: bool = False, quarantine: bool = False) -> BindingResume:
    old, current = _coerce(pinned), _coerce(pinned if requested is None else requested)
    flags = [name for name, enabled in (("migration", migration), ("new_attempt", new_attempt), ("quarantine", quarantine)) if enabled]
    if disposition is not None and flags:
        raise ValueError("resume disposition and boolean flags are mutually exclusive")
    selected = _resume_disposition(disposition or (flags[0] if flags else None))
    if selected and selected not in {ResumeDisposition.MIGRATION, ResumeDisposition.NEW_ATTEMPT, ResumeDisposition.QUARANTINE}:
        raise ValueError("resume requires migration, new_attempt, or quarantine")
    if old.is_legacy or current.is_legacy:
        if selected is None:
            return BindingResume(None, ResumeDisposition.LEGACY_UNKNOWN, False, "legacy C1 binding cannot be resumed by coordinate reinterpretation")
        return BindingResume(current, selected, True, "explicit disposition selected; a canonical binding is still required")
    if old.binding_hash == current.binding_hash:
        return BindingResume(old, ResumeDisposition.PINNED, True, "resume consumes the pinned binding")
    if selected is None:
        return BindingResume(None, ResumeDisposition.REQUIRES_EXPLICIT, False, "changed binding requires migration, new attempt, or quarantine")
    return BindingResume(current, selected, True, "explicit resume disposition selected")


resume = resume_binding
validate_resume = resume_binding


def binding_compatibility(value: CompletionBinding | Mapping[str, Any]) -> str:
    return _coerce(value).compatibility_status


def bind(spec: CompletionSpec, subject_instance_id: SubjectInstanceId | str, evidence_window_start: Any = "", evidence_window_end: Any = "", admission_source: str = "shadow", bound_artifacts: Iterable[Any] = (), *, evidence_window: Any = None, evidence_scope: EvidenceScope | Mapping[str, Any] | None = None, scope: EvidenceScope | Mapping[str, Any] | None = None, **fields: Any) -> CompletionBinding:
    explicit_window = evidence_window
    window_scope = explicit_window if isinstance(explicit_window, EvidenceScope) or _looks_scope(explicit_window) else None
    actual_scope = _coalesce(evidence_scope, scope, window_scope)
    if window_scope is not None:
        explicit_window = None
    if actual_scope is None and (isinstance(evidence_window_start, EvidenceScope) or _looks_scope(evidence_window_start)):
        actual_scope, evidence_window_start = evidence_window_start, ""
    if actual_scope is not None and explicit_window is not None:
        raise AmbiguousBindingError("binding cannot use both a canonical scope and a legacy window")
    if actual_scope is None and explicit_window is not None:
        if evidence_window_start or evidence_window_end:
            raise AmbiguousBindingError("binding cannot use both a legacy window and evidence_window")
        evidence_window_start = explicit_window
    requested_schema = fields.pop("schema_version", None)
    if requested_schema is not None:
        expected_schema = CANONICAL_BINDING_SCHEMA_VERSION if actual_scope is not None else LEGACY_BINDING_SCHEMA_VERSION
        if requested_schema != expected_schema:
            raise AmbiguousBindingError(f"{expected_schema} requires its matching coordinate shape")
    subject = _subject(subject_instance_id, spec.subject_kind)
    bound_artifact_values = _materialize(bound_artifacts)
    if actual_scope is None:
        value = compute_binding_hash(spec.spec_hash, subject, (str(evidence_window_start), str(evidence_window_end)), obligation_id=spec.obligation_id, admission_source=admission_source, bound_artifacts=bound_artifact_values, schema_version=LEGACY_BINDING_SCHEMA_VERSION)
        return CompletionBinding(value, spec.spec_hash, subject, spec.obligation_id, admission_source, (str(evidence_window_start), str(evidence_window_end)), bound_artifact_values, LEGACY_BINDING_SCHEMA_VERSION)
    fields = dict(fields)
    value = compute_binding_hash(spec.spec_hash, subject, evidence_scope=actual_scope, obligation_id=spec.obligation_id, admission_source=admission_source, bound_artifacts=bound_artifact_values, schema_version=CANONICAL_BINDING_SCHEMA_VERSION, **fields)
    return CompletionBinding(value, spec.spec_hash, subject, spec.obligation_id, admission_source, bound_artifacts=bound_artifact_values, schema_version=CANONICAL_BINDING_SCHEMA_VERSION, evidence_scope=actual_scope, **fields)


__all__ = [
    "LEGACY_BINDING_SCHEMA_VERSION", "CANONICAL_BINDING_SCHEMA_VERSION", "BINDING_SCHEMA_VERSION", "SUPPORTED_BINDING_SCHEMA_VERSIONS",
    "BindingVersionError", "AmbiguousBindingError", "SubjectInstanceId", "CompletionBinding", "compute_binding_hash", "bind",
    "AdmissionDisposition", "BindingAdmissionDisposition", "BindingAdmission", "AdmissionResult", "BindingAdmissionResult", "admit_binding", "admit", "admit_occurrence",
    "ResumeDisposition", "BindingResumeDisposition", "BindingResume", "ResumeResult", "BindingResumeResult", "resume_binding", "resume", "validate_resume", "binding_compatibility",
]
