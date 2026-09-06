"""Neutral, non-authoritative C2 shadow generation and evaluation."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from arnold.workflow.completion.binding import CompletionBinding, SubjectInstanceId, bind
from arnold.workflow.completion.evaluation import CompletionVerdict, EvaluationStatus, EvidenceRecord, VerifierIndependence, evaluate_completion
from arnold.workflow.completion.evidence import EvidenceScope, EvidenceWindow, ScalarCursor
from arnold.workflow.completion.hashing import hash_canonical
from arnold.workflow.completion.outcomes import CandidateOutcome
from arnold.workflow.completion.s2f import (
    DEFAULT_S2F_SCAN_DIRS, S2F_SCHEMA_MARKERS, S2FGapReport, S2FMissingTemplateKinds,
    S2FTemplatesUnavailable, generate_shadow_specs_from_s2f, s2f_discovery_gap_report,
)
from arnold.workflow.completion.spec import CompletionSpec, SubjectKind, make_completion_spec
from arnold.workflow.completion.source_declaration import SubjectDeclaration

_REQUIRED_SCOPE_KEYS = frozenset("subject_id occurrence_id attempt_id generation source_lock runtime_lock dependency_lock store_id store_incarnation restore_id restore_generation evidence_window custody authority_fence epoch wbc_version admitted_child_set_digest".split())
_BINDING_KEYS = frozenset("semantic_path path component_lock component_graph_lock component_graph component_digest graph_lock graph_digest installed_artifact_digest installed_artifact installed_artifact_lock artifact_digest prompt_asset_digest prompt_asset prompt_digest tool_asset_digest tool_asset tool_digest policy_asset_digest policy_asset policy_digest prompt_tool_bindings_digest prompt_tool_bindings prompt_tool_binding prompt_tool_digest tool_binding_digest call_site_policy_digest call_site_policy callsite_policy_digest admission_receipt admission_receipt_ref admission_receipt_digest product_contract_digest product_contract product_contract_ref asset_digests assets artifact_digests asset_locks behavior_asset_digests artifact_locks artifact_lock additional_locks".split())
_RECORD_KEYS = frozenset("kind content payload value body evidence_id reference_id id producer provider producer_version provider_version capture_id capture_complete complete_capture complete admitted is_admitted stale stale_evidence scope evidence_scope scope_hash binding_hash cursor details multiplicity obligation_ids links supports obligation_id member_id event_id item_id record evidence receipt".split())


def _json(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _json(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json(item) for item in value]
    return value


def _select(value: Any, declaration: SubjectDeclaration, index: int, *, by_index: bool = True) -> Any:
    if value is None:
        return None
    if isinstance(value, Mapping):
        keys = (declaration.declaration_id, declaration.subject_id, declaration.subject_instance_id,
                declaration.source.source_id, str(index), index)
        return next((value[key] for key in keys if key in value), value)
    if by_index and isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return value[index] if index < len(value) else None
    return value


def _unwrap(value: Any, names: tuple[str, ...]) -> Any:
    if isinstance(value, Mapping):
        return next((value[name] for name in names if name in value), value)
    return value


def _outcome(value: Any) -> CandidateOutcome | str:
    if isinstance(value, Mapping):
        value = value.get("candidate_outcome", value.get("outcome", value))
    try:
        return value if isinstance(value, CandidateOutcome) else CandidateOutcome(str(value))
    except ValueError:
        return str(value)


def _context(value: Any, declaration: SubjectDeclaration, index: int) -> dict[str, Any]:
    context = dict(declaration.admission_context)
    selected = _unwrap(_select(value, declaration, index), ("admission_inputs", "binding_inputs", "binding", "context"))
    if isinstance(selected, Mapping):
        context.update(selected)
    return context


def _default_scope(declaration: SubjectDeclaration) -> dict[str, Any]:
    identity = declaration.declaration_id
    stream = f"shadow:{identity}:evidence"
    return {
        "subject_id": declaration.subject_id, "occurrence_id": declaration.subject_instance_id,
        "attempt_id": f"{declaration.subject_instance_id}:attempt:0", "generation": 0,
        "source_lock": hash_canonical(declaration.source.to_dict()),
        "runtime_lock": hash_canonical({"runtime": "completion-shadow", "version": "c2"}),
        "dependency_lock": hash_canonical({"subject": identity, "kind": declaration.subject_kind.value}),
        "store_id": "completion-shadow-store", "store_incarnation": "completion-shadow-store:1",
        "restore_id": "completion-shadow-restore", "restore_generation": 0,
        "evidence_window": EvidenceWindow(ScalarCursor(0, stream_id=stream), ScalarCursor(1, stream_id=stream), end_inclusive=True),
        "custody": {"source_id": declaration.source.source_id, "declaration_id": identity},
        "authority_fence": {"domain": "completion-shadow", "epoch": 0}, "epoch": 0,
        "wbc_version": "completion-shadow-wbc.v1", "admitted_child_set_digest": hash_canonical([]),
    }


def _scope(value: Any, declaration: SubjectDeclaration) -> EvidenceScope:
    if isinstance(value, EvidenceScope):
        return value
    raw = _unwrap(value, ("evidence_scope", "scope", "coordinates"))
    if isinstance(raw, EvidenceScope):
        return raw
    defaults = _default_scope(declaration)
    if isinstance(raw, Mapping) and _REQUIRED_SCOPE_KEYS.issubset(raw):
        return EvidenceScope.from_dict(raw)
    if isinstance(raw, Mapping):
        locks = raw.get("locks", {}) if isinstance(raw.get("locks"), Mapping) else {}
        aliases = {
            "subject_id": ("subject_id", "subject"), "occurrence_id": ("occurrence_id", "occurrence"),
            "attempt_id": ("attempt_id", "attempt"), "generation": ("generation", "generation_id"),
            "source_lock": ("source_lock",), "runtime_lock": ("runtime_lock",),
            "dependency_lock": ("dependency_lock",), "store_id": ("store_id", "store"),
            "store_incarnation": ("store_incarnation", "incarnation"), "restore_id": ("restore_id", "restore_identity"),
            "restore_generation": ("restore_generation",), "evidence_window": ("evidence_window", "window", "cursor_window"),
            "custody": ("custody", "custody_coordinates"), "authority_fence": ("authority_fence", "fence"),
            "epoch": ("epoch", "authority_epoch"), "wbc_version": ("wbc_version", "wbc"),
            "admitted_child_set_digest": ("admitted_child_set_digest", "child_set_digest"),
        }
        for field, names in aliases.items():
            chosen = next((raw[name] for name in names if name in raw), None)
            if chosen is not None:
                defaults[field] = chosen
        for field in ("source_lock", "runtime_lock", "dependency_lock"):
            if field in locks:
                defaults[field] = locks[field]
    return EvidenceScope(**defaults)


def _scope_for(declaration: SubjectDeclaration, index: int, scopes: Any, context: Mapping[str, Any]) -> EvidenceScope:
    value = _select(scopes, declaration, index)
    if value is None:
        value = next((context[key] for key in ("evidence_scope", "scope", "coordinates") if key in context), None)
    return _scope(value, declaration)


def _binding(spec: CompletionSpec, declaration: SubjectDeclaration, scope: EvidenceScope, context: Mapping[str, Any], *, admission_source: str) -> CompletionBinding:
    fields = {key: context[key] for key in _BINDING_KEYS if key in context}
    fields.setdefault("semantic_path", f"{declaration.source.source_id}:{declaration.subject_instance_id}")
    return bind(
        spec, SubjectInstanceId(declaration.subject_instance_id, declaration.subject_kind),
        admission_source=str(context.get("admission_source", admission_source)),
        bound_artifacts=context.get("bound_artifacts", ()), evidence_scope=scope, **fields,
    )


def _record_collection(value: Any, declaration: SubjectDeclaration, index: int) -> tuple[Any, ...]:
    selected = _unwrap(_select(value, declaration, index, by_index=False),
                       ("primary_evidence", "evidence", "records", "items", "capture_receipts", "receipt"))
    if selected is None:
        return ()
    if isinstance(selected, EvidenceRecord) or isinstance(selected, Mapping) and _RECORD_KEYS.intersection(selected):
        return (selected,)
    if isinstance(selected, (str, bytes)):
        return (selected,)
    try:
        return tuple(selected)
    except TypeError:
        return (selected,)


def _record(raw: Any, binding: CompletionBinding, scope: EvidenceScope, declaration: SubjectDeclaration, index: int, *, capture: bool) -> EvidenceRecord:
    if isinstance(raw, EvidenceRecord):
        return raw
    payload = dict(raw) if isinstance(raw, Mapping) else {"content": raw}
    payload = _unwrap(payload, ("record", "evidence", "receipt"))
    if not isinstance(payload, Mapping):
        payload = {"content": payload}
    payload = dict(payload)
    content = payload.get("content", payload.get("payload", payload.get("value", payload.get("body"))))
    nested = payload.get("capture")
    if payload.get("capture_complete") is None and isinstance(nested, Mapping):
        payload["capture_complete"] = next((bool(nested[key]) for key in ("capture_complete", "complete_capture", "complete") if key in nested), None)
    if payload.get("capture_complete") is None:
        payload["capture_complete"] = next((bool(payload[key]) for key in ("complete_capture", "complete") if key in payload), None)
    payload.setdefault("kind", "capture_receipt" if capture else "primary")
    payload.setdefault("content", content)
    payload.setdefault("binding_hash", binding.binding_hash)
    payload.setdefault("scope_hash", scope.scope_hash)
    payload.setdefault("scope", scope)
    payload.setdefault("evidence_id", f"{declaration.declaration_id}:{'capture' if capture else 'primary'}:{index}")
    payload.setdefault("producer", "shadow-capture" if capture else "shadow-primary")
    payload.setdefault("producer_version", "c2")
    return EvidenceRecord.from_dict(payload)


def _records(value: Any, declaration: SubjectDeclaration, index: int, binding: CompletionBinding, scope: EvidenceScope, *, capture: bool) -> tuple[EvidenceRecord, ...]:
    result: list[EvidenceRecord] = []
    for record_index, raw in enumerate(_record_collection(value, declaration, index)):
        if isinstance(raw, Mapping):
            target = raw.get("declaration_id", raw.get("subject_id", raw.get("subject_instance_id")))
            if target is not None and str(target) not in {declaration.declaration_id, declaration.subject_id, declaration.subject_instance_id}:
                continue
        result.append(_record(raw, binding, scope, declaration, record_index, capture=capture))
    return tuple(result)


@dataclass(frozen=True)
class ShadowGap:
    """A content-addressed qualification; it cannot be used as proof."""

    code: str
    message: str
    discovered_files: tuple[str, ...] = ()
    missing_kinds: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    qualified: bool = True
    gap_hash: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "gap_hash", hash_canonical({
            "code": self.code, "message": self.message, "discovered_files": list(self.discovered_files),
            "missing_kinds": list(self.missing_kinds), "reasons": list(self.reasons), "qualified": self.qualified,
        }))

    @property
    def hash(self) -> str:
        return self.gap_hash

    @property
    def is_qualified(self) -> bool:
        return self.qualified

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "discovered_files": list(self.discovered_files),
                "missing_kinds": list(self.missing_kinds), "reasons": list(self.reasons),
                "qualified": self.qualified, "gap_hash": self.gap_hash}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ShadowGap":
        return cls(
            code=str(data.get("code", "incomplete_discovery")), message=str(data.get("message", "")),
            discovered_files=tuple(str(item) for item in data.get("discovered_files", ())),
            missing_kinds=tuple(str(item) for item in data.get("missing_kinds", ())),
            reasons=tuple(str(item) for item in data.get("reasons", ())), qualified=bool(data.get("qualified", True)),
        )


QualifiedShadowGap = ShadowGap
ShadowDiscoveryGap = ShadowGap


@dataclass(frozen=True)
class ShadowVerdict:
    """One non-authoritative candidate and its optional C2 evaluator result."""

    declaration_id: str
    spec_hash: str
    binding_hash: str
    outcome: CandidateOutcome | str
    verdict_description: str = ""
    verdict: CompletionVerdict | None = None
    primary_evidence: tuple[EvidenceRecord, ...] = ()
    capture_receipts: tuple[EvidenceRecord, ...] = ()
    verifier_provenance: Any = None

    @property
    def candidate_outcome(self) -> CandidateOutcome | str:
        return self.outcome

    @property
    def verdict_hash(self) -> str:
        return self.verdict.verdict_hash if self.verdict else ""

    @property
    def content_hash(self) -> str:
        return self.verdict_hash

    @property
    def status(self) -> Any:
        return self.verdict.status if self.verdict else None

    @property
    def evaluation(self) -> CompletionVerdict | None:
        return self.verdict

    def to_dict(self) -> dict[str, Any]:
        outcome = self.outcome.value if isinstance(self.outcome, CandidateOutcome) else str(self.outcome)
        payload: dict[str, Any] = {"declaration_id": self.declaration_id, "spec_hash": self.spec_hash,
                                   "binding_hash": self.binding_hash, "outcome": outcome}
        if self.verdict_description:
            payload["verdict_description"] = self.verdict_description
        if self.verdict is not None:
            payload["verdict"] = self.verdict.to_dict()
            payload["verdict_hash"] = self.verdict.verdict_hash
        if self.primary_evidence:
            payload["primary_evidence"] = [item.to_dict() for item in self.primary_evidence]
        if self.capture_receipts:
            payload["capture_receipts"] = [item.to_dict() for item in self.capture_receipts]
        if self.verifier_provenance is not None:
            payload["verifier_provenance"] = _json(self.verifier_provenance)
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ShadowVerdict":
        raw = data.get("outcome", "success")
        outcome = _outcome(raw)
        verdict = data.get("verdict")
        return cls(
            declaration_id=str(data["declaration_id"]), spec_hash=str(data["spec_hash"]),
            binding_hash=str(data["binding_hash"]), outcome=outcome,
            verdict_description=str(data.get("verdict_description", "")),
            verdict=CompletionVerdict.from_dict(verdict) if isinstance(verdict, Mapping) else None,
            primary_evidence=tuple(EvidenceRecord.from_dict(item) for item in data.get("primary_evidence", ())),
            capture_receipts=tuple(EvidenceRecord.from_dict(item) for item in data.get("capture_receipts", ())),
            verifier_provenance=(
                VerifierIndependence.from_dict(data["verifier_provenance"])
                if isinstance(data.get("verifier_provenance"), Mapping) else data.get("verifier_provenance")
            ),
        )


def _spec_for_subject(declaration: SubjectDeclaration) -> CompletionSpec:
    return make_completion_spec(
        obligation_id=f"shadow:{declaration.declaration_id}:{declaration.subject_instance_id}",
        subject_kind=declaration.subject_kind, canonical_name=declaration.source.canonical_name,
    )


def _validate_shadow_declaration(declaration: SubjectDeclaration) -> None:
    if not isinstance(declaration, SubjectDeclaration):
        raise TypeError("shadow inventory entries must be SubjectDeclaration instances")
    if declaration.source.kind is None:
        raise ValueError("pure helpers must not enter a shadow inventory")
    if declaration.source.kind != declaration.subject_kind:
        raise ValueError("SubjectDeclaration.subject_kind must match SourceDeclaration.kind")


def _validated_shadow_declarations(inventory: tuple[SubjectDeclaration, ...]) -> tuple[SubjectDeclaration, ...]:
    for declaration in inventory:
        _validate_shadow_declaration(declaration)
    return inventory


def generate_shadow_specs(inventory: tuple[SubjectDeclaration, ...]) -> tuple[CompletionSpec, ...]:
    """Generate one deterministic shadow spec per declaration."""
    return tuple(_spec_for_subject(item) for item in _validated_shadow_declarations(inventory))


def generate_shadow_bindings(specs: tuple[CompletionSpec, ...], instance_ids: tuple[SubjectInstanceId, ...], *, evidence_scopes: Any = None, scopes: Any = None) -> tuple[CompletionBinding, ...]:
    """Keep the low-level C1 helper and add an opt-in canonical scope form."""
    if len(specs) != len(instance_ids):
        raise ValueError(f"specs and instance_ids must have the same length: {len(specs)} vs {len(instance_ids)}")
    selected = evidence_scopes if evidence_scopes is not None else scopes
    if selected is None:
        return tuple(bind(spec=spec, subject_instance_id=instance) for spec, instance in zip(specs, instance_ids))
    result: list[CompletionBinding] = []
    for index, (spec, instance) in enumerate(zip(specs, instance_ids)):
        value = selected[index] if isinstance(selected, Sequence) and not isinstance(selected, (str, bytes)) else selected
        result.append(bind(spec=spec, subject_instance_id=instance, evidence_scope=value))
    return tuple(result)


def _report_from_dict(data: Mapping[str, Any]) -> S2FGapReport:
    diagnostics = tuple(S2FMissingTemplateKinds(
        discovered_kinds=tuple(SubjectKind(item) for item in diagnostic.get("discovered_kinds", ())),
        missing_kinds=tuple(SubjectKind(item) for item in diagnostic.get("missing_kinds", ())),
        code=str(diagnostic.get("code", "S2FMissingTemplateKinds")),
    ) for diagnostic in data.get("diagnostics", ()))
    return S2FGapReport(
        scan_dirs=tuple(str(item) for item in data.get("scan_dirs", ())),
        discovered_files=tuple(Path(item) for item in data.get("discovered_files", ())),
        parsed_declarations=tuple(SubjectDeclaration.from_dict(item) for item in data.get("parsed_declarations", ())),
        gaps=tuple(str(item) for item in data.get("gaps", ())),
        missing_template_kinds=tuple(SubjectKind(item) for item in data.get("missing_template_kinds", ())),
        diagnostics=diagnostics,
    )


@dataclass(frozen=True)
class ShadowEvaluation:
    """A content-addressed informational result; it has no completion power."""

    specs: tuple[CompletionSpec, ...] = ()
    bindings: tuple[CompletionBinding, ...] = ()
    verdicts: tuple[ShadowVerdict, ...] = ()
    gaps: tuple[ShadowGap, ...] = ()
    discovery_report: S2FGapReport | None = None

    @property
    def qualified(self) -> bool:
        return bool(self.gaps)

    @property
    def evaluation_hash(self) -> str:
        return hash_canonical(self.to_dict())

    @property
    def content_hash(self) -> str:
        return self.evaluation_hash

    @property
    def hash(self) -> str:
        return self.evaluation_hash

    @property
    def gap(self) -> ShadowGap | None:
        return self.gaps[0] if self.gaps else None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"specs": [item.to_dict() for item in self.specs],
                                   "bindings": [item.to_dict() for item in self.bindings],
                                   "verdicts": [item.to_dict() for item in self.verdicts]}
        if self.gaps:
            payload["gaps"] = [item.to_dict() for item in self.gaps]
        if self.discovery_report is not None:
            payload["discovery_report"] = self.discovery_report.to_dict()
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ShadowEvaluation":
        report = data.get("discovery_report")
        return cls(
            specs=tuple(CompletionSpec.from_dict(item) for item in data.get("specs", [])),
            bindings=tuple(CompletionBinding.from_dict(item) for item in data.get("bindings", [])),
            verdicts=tuple(ShadowVerdict.from_dict(item) for item in data.get("verdicts", [])),
            gaps=tuple(ShadowGap.from_dict(item) for item in data.get("gaps", [])),
            discovery_report=_report_from_dict(report) if isinstance(report, Mapping) else None,
        )


def _c2_verdict(spec: CompletionSpec, binding: CompletionBinding, primary: tuple[EvidenceRecord, ...], captures: tuple[EvidenceRecord, ...], candidate: Any, kwargs: Mapping[str, Any]) -> CompletionVerdict:
    evaluation = dict(kwargs)
    for key in ("evidence", "primary_evidence", "capture_receipts"):
        evaluation.pop(key, None)
    evaluation["candidate_outcome"] = candidate
    if evaluation.get("verifier_provenance") is not None:
        evaluation.setdefault("require_verifier_independence", True)
    return evaluate_completion(spec, binding, (*primary, *captures), **evaluation)


def _qualify_verdict(verdict: CompletionVerdict) -> CompletionVerdict:
    if not verdict.accepted:
        return verdict
    return CompletionVerdict(
        spec_hash=verdict.spec_hash, binding_hash=verdict.binding_hash, outcome=verdict.outcome,
        obligation_results=verdict.obligation_results, evidence=verdict.evidence,
        diagnostics=verdict.diagnostics, candidate_selection=verdict.candidate_selection,
        exceptional_proof=verdict.exceptional_proof, terminal_policy=verdict.terminal_policy,
        terminal=False, taint=verdict.taint, verifier_independence=verdict.verifier_independence,
        verifier=verdict.verifier, verifier_version=verdict.verifier_version,
        accepted=False, status=EvaluationStatus.UNKNOWN,
    )


def evaluate_shadow(inventory: tuple[SubjectDeclaration, ...], *, candidate_outcome: Any = "success", candidate_outcomes: Any = None, outcome: Any = None, primary_evidence: Any = (), scoped_primary_evidence: Any = None, evidence: Any = None, evidence_scope: Any = None, capture_receipts: Any = (), capture_receipt: Any = None, capture_evidence: Any = None, evidence_scopes: Any = None, scopes: Any = None, admission_inputs: Any = None, admission_context: Any = None, binding_inputs: Any = None, admission_source: str = "shadow", verifier_provenance: Any = None, verifier_provenances: Any = None, discovery_report: S2FGapReport | None = None, **kwargs: Any) -> ShadowEvaluation:
    """Evaluate each candidate over an exact C2 binding and preserve gaps."""
    if not inventory:
        gap = _discovery_gap(discovery_report)
        return ShadowEvaluation(gaps=(gap,) if gap else (), discovery_report=discovery_report)
    declarations = _validated_shadow_declarations(inventory)
    specs = generate_shadow_specs(declarations)
    primary_input = scoped_primary_evidence if scoped_primary_evidence is not None else primary_evidence
    primary_input = primary_input if evidence is None else evidence
    capture_input = capture_receipt if capture_receipt is not None else capture_receipts
    capture_input = capture_input if capture_evidence is None else capture_evidence
    scope_input = evidence_scopes if evidence_scopes is not None else scopes
    scope_input = evidence_scope if scope_input is None else scope_input
    input_context = admission_inputs if admission_context is None else admission_context
    input_context = input_context if binding_inputs is None else binding_inputs
    candidate_input = candidate_outcomes if candidate_outcomes is not None else candidate_outcome
    provenance_input = verifier_provenances if verifier_provenances is not None else verifier_provenance
    gap = _discovery_gap(discovery_report)
    bindings: list[CompletionBinding] = []
    verdicts: list[ShadowVerdict] = []
    for index, (declaration, spec) in enumerate(zip(declarations, specs)):
        context = _context(input_context, declaration, index)
        scope = _scope_for(declaration, index, scope_input, context)
        binding = _binding(spec, declaration, scope, context, admission_source=admission_source)
        primary = _records(primary_input, declaration, index, binding, scope, capture=False)
        captures = _records(capture_input, declaration, index, binding, scope, capture=True)
        selected = _outcome(outcome if outcome is not None else _select(candidate_input, declaration, index))
        verifier = _select(provenance_input, declaration, index)
        evaluation_kwargs = dict(kwargs)
        if verifier is not None:
            evaluation_kwargs["verifier_provenance"] = verifier
        verdict = _c2_verdict(spec, binding, primary, captures, selected, evaluation_kwargs)
        verdict = _qualify_verdict(verdict) if gap else verdict
        bindings.append(binding)
        verdicts.append(ShadowVerdict(
            declaration_id=declaration.declaration_id, spec_hash=spec.spec_hash,
            binding_hash=binding.binding_hash, outcome=selected,
            verdict_description=f"C2 shadow evaluation: {verdict.status.value}", verdict=verdict,
            primary_evidence=primary, capture_receipts=captures, verifier_provenance=verifier,
        ))
    return ShadowEvaluation(specs=specs, bindings=tuple(bindings), verdicts=tuple(verdicts),
                            gaps=(gap,) if gap else (), discovery_report=discovery_report)


def _discovery_gap(report: S2FGapReport | None) -> ShadowGap | None:
    if report is None or not report.has_gaps:
        return None
    return ShadowGap(
        code="incomplete_discovery", message="S2F discovery is incomplete; shadow evidence is qualified",
        discovered_files=tuple(str(path) for path in report.discovered_files),
        missing_kinds=tuple(kind.value for kind in report.missing_template_kinds),
        reasons=tuple(report.gaps) + tuple(item.code for item in report.diagnostics),
    )

__all__ = [
    "DEFAULT_S2F_SCAN_DIRS", "S2F_SCHEMA_MARKERS", "S2FGapReport", "S2FTemplatesUnavailable",
    "ShadowGap", "QualifiedShadowGap", "ShadowDiscoveryGap", "ShadowVerdict", "ShadowEvaluation",
    "evaluate_shadow", "generate_shadow_specs", "generate_shadow_bindings", "generate_shadow_specs_from_s2f",
    "s2f_discovery_gap_report",
]
