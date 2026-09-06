"""Pure, non-authoritative completion evaluation for the C2 shadow kernel.
The records in this module deliberately live beside the neutral completion
schemas.  They do not import the product acceptance path and they never write
authority.  A verdict says what the shadow evaluator could prove for one
exact ``(spec, obligation, binding)`` identity; it is not an acceptance
receipt.
The evaluator admits evidence only when its binding and evidence coordinates
match the pinned binding.  It then content-deduplicates the admitted records
before evaluating the four initial proof modes.  Complete-capture proofs are
unknown until a named producer has supplied a complete capture marker.
"""
from __future__ import annotations
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from arnold.workflow.completion.binding import CompletionBinding
from arnold.workflow.completion.evidence import (
    EvidenceScope,
    EvidenceScopeMismatch,
    scope_mismatches,
)
from arnold.workflow.completion.hashing import hash_canonical
from arnold.workflow.completion.spec import CompletionSpec, Obligation, ProofMode
from ._evaluation_primitives import (
    FrozenMapping as _FrozenMapping,
    as_tuple as _as_tuple,
    choose_alias as _choose_alias,
    enum_value as _enum_value,
    freeze as _freeze,
    hashed_record as _hashed_record,
    text as _text,
    thaw as _thaw,
)
EVIDENCE_SCHEMA_VERSION = "arnold.workflow.completion_evidence.v1"
OBLIGATION_RESULT_SCHEMA_VERSION = "arnold.workflow.completion_obligation_result.v1"
DIAGNOSTIC_SCHEMA_VERSION = "arnold.workflow.completion_diagnostic.v1"
VERDICT_SCHEMA_VERSION = "arnold.workflow.completion_verdict.v1"
class EvaluationStatus(StrEnum):
    """Status of one proof obligation or of the complete shadow verdict."""
    SATISFIED = "satisfied"
    UNSATISFIED = "unsatisfied"
    UNKNOWN = "unknown"
    WAIVED = "waived"
    NOT_APPLICABLE = "not_applicable"
    BLOCKED = "blocked"
    SUSPENDED = "suspended"
    QUARANTINED = "quarantined"
    FAILED = "failed"
ObligationStatus = EvaluationStatus
VerdictStatus = EvaluationStatus
class DiagnosticSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
@dataclass(frozen=True, init=False)
class EvidenceRecord:
    kind: str; content: Any; binding_hash: str; scope_hash: str; evidence_id: str; producer: str; producer_version: str; obligation_ids: tuple[str, ...]; member_id: str; capture_id: str; capture_complete: bool | None; admitted: bool; stale: bool; cursor: Any; details: Any; multiplicity: int; scope: EvidenceScope | None; content_hash: str; evidence_hash: str
    def __init__( self, kind: str, content: Any = None, binding_hash: str = "", scope_hash: str = "", evidence_id: str = "", producer: str = "", producer_version: str = "", obligation_ids: Iterable[str] = (), member_id: Any = None, capture_id: str = "", capture_complete: bool | None = None, admitted: bool = True, stale: bool = False, cursor: Any = None, details: Any = None, multiplicity: int = 1, scope: EvidenceScope | Mapping[str, Any] | None = None, evidence_hash: str = "", *, payload: Any = None, value: Any = None, body: Any = None, content_hash: str = "", hash: str = "", record_hash: str = "", evidence_scope: EvidenceScope | Mapping[str, Any] | None = None, links: Iterable[str] = (), supports: Iterable[str] = (), obligation_id: str | None = None, provider: str = "", provider_version: str = "", capture_producer: str = "", complete_capture: bool | None = None, capture: Mapping[str, Any] | None = None, event_id: Any = None, item_id: Any = None, reference_id: Any = None, status: Any = None, is_admitted: bool | None = None, stale_evidence: bool | None = None, ) -> None:
        EvidenceRecord___init__(**locals())
    @property
    def hash(self) -> str: return EvidenceRecord_hash(**locals())
    @property
    def reference_id(self) -> str: return EvidenceRecord_reference_id(**locals())
    @property
    def obligation_links(self) -> tuple[str, ...]: return EvidenceRecord_obligation_links(**locals())
    @property
    def evidence_scope(self) -> EvidenceScope | None: return EvidenceRecord_evidence_scope(**locals())
    @property
    def is_capture_marker(self) -> bool: return EvidenceRecord_is_capture_marker(**locals())
    @property
    def is_complete_capture(self) -> bool: return EvidenceRecord_is_complete_capture(**locals())
    @property
    def capture_producer(self) -> str: return EvidenceRecord_capture_producer(**locals())
    def to_dict(self) -> dict[str, Any]:
        return EvidenceRecord_to_dict(**locals())
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvidenceRecord": return EvidenceRecord_from_dict(**locals())
HashedEvidence = EvidenceRecord
Evidence = EvidenceRecord
EvidenceItem = EvidenceRecord
EvidenceRef = EvidenceRecord
@dataclass(frozen=True, init=False)
class Diagnostic:
    code: str; message: str; severity: DiagnosticSeverity; obligation_id: str; evidence_ids: tuple[str, ...]; cause: str; repair_frontier: tuple[str, ...]; details: Any; diagnostic_hash: str
    def __init__( self, code: str, message: str = "", severity: DiagnosticSeverity | str = DiagnosticSeverity.ERROR, obligation_id: str = "", evidence_ids: Iterable[str] = (), cause: str = "", repair_frontier: Iterable[str] = (), details: Any = None, diagnostic_hash: str = "", *, causal_occurrence: str = "", frontier: Iterable[str] = (), ) -> None:
        Diagnostic___init__(**locals())
    @property
    def causal_occurrence(self) -> str: return Diagnostic_causal_occurrence(**locals())
    @property
    def frontier(self) -> tuple[str, ...]: return Diagnostic_frontier(**locals())
    @property
    def hash(self) -> str: return Diagnostic_hash(**locals())
    def to_dict(self) -> dict[str, Any]:
        return Diagnostic_to_dict(**locals())
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Diagnostic": return Diagnostic_from_dict(**locals())
EvaluationDiagnostic = Diagnostic
DiagnosticRecord = Diagnostic
@dataclass(frozen=True, init=False)
class ObligationResult:
    obligation_id: str; status: EvaluationStatus; kind: ProofMode; spec_hash: str; binding_hash: str; required: bool; evidence_ids: tuple[str, ...]; diagnostics: tuple[Diagnostic, ...]; observed_count: int; expected_count: int | None; observed_ids: tuple[str, ...]; expected_ids: tuple[str, ...]; aggregate_value: Any; result_hash: str
    def __init__( self, obligation_id: str, status: EvaluationStatus | str, kind: ProofMode | str = ProofMode.PRESENCE, spec_hash: str = "", binding_hash: str = "", required: bool = True, evidence_ids: Iterable[str] = (), diagnostics: Iterable[Diagnostic | Mapping[str, Any]] = (), observed_count: int = 0, expected_count: int | None = None, observed_ids: Iterable[str] = (), expected_ids: Iterable[str] = (), aggregate_value: Any = None, result_hash: str = "", *, proof_mode: ProofMode | str | None = None, result: EvaluationStatus | str | None = None, ) -> None:
        ObligationResult___init__(**locals())
    @property
    def proof_mode(self) -> ProofMode: return ObligationResult_proof_mode(**locals())
    @property
    def satisfied(self) -> bool: return ObligationResult_satisfied(**locals())
    @property
    def accepted(self) -> bool: return ObligationResult_accepted(**locals())
    @property
    def unknown(self) -> bool: return ObligationResult_unknown(**locals())
    @property
    def failed(self) -> bool: return ObligationResult_failed(**locals())
    @property
    def reuse_identity(self) -> tuple[str, str, str]: return ObligationResult_reuse_identity(**locals())
    @property
    def identity(self) -> tuple[str, str, str]: return ObligationResult_identity(**locals())
    @property
    def hash(self) -> str: return ObligationResult_hash(**locals())
    def to_dict(self) -> dict[str, Any]:
        return ObligationResult_to_dict(**locals())
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ObligationResult": return ObligationResult_from_dict(**locals())
ObligationEvaluation = ObligationResult
ObligationResultRecord = ObligationResult
def _hashed_record(schema_version: str, payload: Mapping[str, Any], supplied: str = "") -> str:
    expected = hash_canonical({"schema_version": schema_version, **dict(payload)})
    if supplied and supplied != expected:
        raise ValueError(f"{schema_version} hash mismatch")
    return expected
@dataclass(frozen=True, init=False)
class CandidateSelection:
    declared_candidates: tuple[str, ...]; selected_candidate: str; applicability: Any; selection_hash: str
    def __init__( self, declared_candidates: Iterable[str] = (), selected_candidate: str = "", applicability: Any = None, selection_hash: str = "", *, candidates: Iterable[str] | None = None, selected: str | None = None, ) -> None:
        CandidateSelection___init__(**locals())
    @property
    def selected(self) -> str: return CandidateSelection_selected(**locals())
    @property
    def hash(self) -> str: return CandidateSelection_hash(**locals())
    def to_dict(self) -> dict[str, Any]:
        return CandidateSelection_to_dict(**locals())
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CandidateSelection": return CandidateSelection_from_dict(**locals())
@dataclass(frozen=True, init=False)
class BlockedProof:
    blocker_id: str; causal_evidence_ids: tuple[str, ...]; authority_coordinates: Any; custody_coordinates: Any; next_admission: str; recovery_disposition: str; binding_hash: str; proof_hash: str
    def __init__( self, blocker_id: str = "", causal_evidence_ids: Iterable[str] = (), authority_coordinates: Any = None, custody_coordinates: Any = None, next_admission: str = "", recovery_disposition: str = "", binding_hash: str = "", proof_hash: str = "", *, evidence_ids: Iterable[str] | None = None, authority: Any = None, custody: Any = None, disposition: str | None = None, recovery: str | None = None, ) -> None:
        BlockedProof___init__(**locals())
    @property
    def evidence_ids(self) -> tuple[str, ...]: return BlockedProof_evidence_ids(**locals())
    @property
    def hash(self) -> str: return BlockedProof_hash(**locals())
    def to_dict(self) -> dict[str, Any]:
        return BlockedProof_to_dict(**locals())
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "BlockedProof": return BlockedProof_from_dict(**locals())
@dataclass(frozen=True, init=False)
class WaiverProof:
    authority_provenance: Any; scope: Any; reason: str; evidence_ids: tuple[str, ...]; expiry: Any; taint: frozenset[str]; binding_hash: str; proof_hash: str
    def __init__( self, authority_provenance: Any = None, scope: Any = None, reason: str = "", evidence_ids: Iterable[str] = (), expiry: Any = None, taint: Iterable[str] = (), binding_hash: str = "", proof_hash: str = "", *, authority: Any = None, waiver_scope: Any = None, expires: Any = None, ) -> None:
        WaiverProof___init__(**locals())
    @property
    def hash(self) -> str: return WaiverProof_hash(**locals())
    def to_dict(self) -> dict[str, Any]:
        return WaiverProof_to_dict(**locals())
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "WaiverProof": return WaiverProof_from_dict(**locals())
@dataclass(frozen=True, init=False)
class TerminalPolicy:
    permitted_outcomes: frozenset[str]; evidence_ids: tuple[str, ...]; admitted: bool; independent: bool; producer: str; trust_domain: str; policy_hash: str
    def __init__( self, permitted_outcomes: Iterable[str] = (), evidence_ids: Iterable[str] = (), admitted: bool = False, independent: bool = False, producer: str = "", trust_domain: str = "", policy_hash: str = "", *, outcomes: Iterable[str] | None = None, allowed_outcomes: Iterable[str] | None = None, independently_admitted: bool | None = None, ) -> None:
        TerminalPolicy___init__(**locals())
    def permits(self, outcome: str) -> bool:
        return TerminalPolicy_permits(**locals())
    @property
    def hash(self) -> str: return TerminalPolicy_hash(**locals())
    def to_dict(self) -> dict[str, Any]:
        return TerminalPolicy_to_dict(**locals())
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TerminalPolicy": return TerminalPolicy_from_dict(**locals())
@dataclass(frozen=True, init=False)
class VerifierIndependence:
    implementation_provenance: str; producer_identity: str; trust_domain: str; primary_evidence_access: bool; independent: bool; reasons: tuple[str, ...]; independence_hash: str
    def __init__( self, implementation_provenance: str = "", producer_identity: str = "", trust_domain: str = "", primary_evidence_access: bool = False, independent: bool | None = None, reasons: Iterable[str] = (), independence_hash: str = "", *, implementation: str | None = None, producer: str | None = None, direct_primary_evidence_access: bool | None = None, ) -> None:
        VerifierIndependence___init__(**locals())
    @property
    def valid(self) -> bool: return VerifierIndependence_valid(**locals())
    @property
    def hash(self) -> str: return VerifierIndependence_hash(**locals())
    def to_dict(self) -> dict[str, Any]:
        return VerifierIndependence_to_dict(**locals())
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "VerifierIndependence": return VerifierIndependence_from_dict(**locals())
# Friendly aliases used by callers that name the proof by its outcome.
BlockedOutcomeProof = BlockedProof
WaiverOutcomeProof = WaiverProof
TerminalDispositionPolicy = TerminalPolicy
VerifierIndependenceProof = VerifierIndependence
@dataclass(frozen=True, init=False)
class CompletionVerdict:
    spec_hash: str; binding_hash: str; outcome: str; status: EvaluationStatus; accepted: bool; obligation_results: tuple[ObligationResult, ...]; evidence: tuple[EvidenceRecord, ...]; diagnostics: tuple[Diagnostic, ...]; candidate_selection: CandidateSelection | None; exceptional_proof: BlockedProof | WaiverProof | None; terminal_policy: TerminalPolicy | None; terminal: bool; taint: frozenset[str]; verifier_independence: VerifierIndependence | None; verifier: str; verifier_version: str; verdict_hash: str
    def __init__( self, spec_hash: str = "", binding_hash: str = "", outcome: Any = "success", obligation_results: Iterable[ObligationResult | Mapping[str, Any]] = (), evidence: Iterable[EvidenceRecord | Mapping[str, Any]] = (), diagnostics: Iterable[Diagnostic | Mapping[str, Any]] = (), accepted: bool | None = None, status: EvaluationStatus | str | None = None, verifier: str = "completion-shadow", verifier_version: str = EVIDENCE_SCHEMA_VERSION, verdict_hash: str = "", *, results: Iterable[ObligationResult | Mapping[str, Any]] | None = None, evidence_refs: Iterable[EvidenceRecord | Mapping[str, Any]] | None = None, candidate_outcome: Any = None, overall_status: EvaluationStatus | str | None = None, candidate_selection: CandidateSelection | Mapping[str, Any] | None = None, exceptional_proof: BlockedProof | WaiverProof | Mapping[str, Any] | None = None, terminal_policy: TerminalPolicy | Mapping[str, Any] | None = None, terminal: bool = False, taint: Iterable[str] = (), verifier_independence: VerifierIndependence | Mapping[str, Any] | None = None, ) -> None:
        CompletionVerdict___init__(**locals())
    @property
    def candidate_outcome(self) -> str: return CompletionVerdict_candidate_outcome(**locals())
    @property
    def results(self) -> tuple[ObligationResult, ...]: return CompletionVerdict_results(**locals())
    @property
    def evidence_refs(self) -> tuple[EvidenceRecord, ...]: return CompletionVerdict_evidence_refs(**locals())
    @property
    def selected_candidate(self) -> str | None: return CompletionVerdict_selected_candidate(**locals())
    @property
    def waiver_taint(self) -> frozenset[str]: return CompletionVerdict_waiver_taint(**locals())
    @property
    def independent(self) -> bool | None: return CompletionVerdict_independent(**locals())
    @property
    def unknown(self) -> bool: return CompletionVerdict_unknown(**locals())
    @property
    def satisfied(self) -> bool: return CompletionVerdict_satisfied(**locals())
    @property
    def reuse_identities(self) -> tuple[tuple[str, str, str], ...]: return CompletionVerdict_reuse_identities(**locals())
    @property
    def hash(self) -> str: return CompletionVerdict_hash(**locals())
    def to_dict(self) -> dict[str, Any]:
        return CompletionVerdict_to_dict(**locals())
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CompletionVerdict": return CompletionVerdict_from_dict(**locals())
ShadowCompletionVerdict = CompletionVerdict
CompletionVerdictRecord = CompletionVerdict
def _coerce_spec(value: CompletionSpec | Mapping[str, Any]) -> CompletionSpec:
    return value if isinstance(value, CompletionSpec) else CompletionSpec.from_dict(value)
def _coerce_binding(value: CompletionBinding | Mapping[str, Any]) -> CompletionBinding:
    return value if isinstance(value, CompletionBinding) else CompletionBinding.from_dict(value)
def _coerce_evidence(value: EvidenceRecord | Mapping[str, Any]) -> EvidenceRecord:
    return value if isinstance(value, EvidenceRecord) else EvidenceRecord.from_dict(value)
def _candidate_name(value: Any) -> str:
    if isinstance(value, Mapping):
        for key in ("candidate", "outcome", "name", "id", "candidate_id"):
            if key in value:
                return _text(value[key], "candidate", allow_empty=False)
    return _text(value, "candidate", allow_empty=False)
def select_candidate(
    candidate_outcome: Any = "success",
    *,
    declared_candidates: Any = None,
    candidates: Any = None,
    selected_candidate: str | None = None,
) -> CandidateSelection:
    """Select exactly one declared candidate, before applicability is read."""
    declared_value = candidates if candidates is not None else declared_candidates
    selected_value = selected_candidate
    if isinstance(candidate_outcome, Mapping):
        if selected_value is None:
            selected_value = candidate_outcome.get(
                "selected_candidate",
                candidate_outcome.get("selected", candidate_outcome.get("outcome")),
            )
        if declared_value is None:
            declared_value = candidate_outcome.get(
                "declared_candidates",
                candidate_outcome.get("candidates"),
            )
    if declared_value is None:
        if isinstance(candidate_outcome, (list, tuple, set, frozenset)):
            declared_value = candidate_outcome
        else:
            declared_value = (candidate_outcome,)
    if isinstance(declared_value, Mapping):
        declared_value = declared_value.get(
            "declared_candidates",
            declared_value.get("candidates", tuple(declared_value)),
        )
    declared = tuple(dict.fromkeys(_candidate_name(item) for item in declared_value))
    chosen = _candidate_name(selected_value if selected_value is not None else candidate_outcome)
    return CandidateSelection(declared, chosen)
def verify_verifier_independence(
    provenance: VerifierIndependence | Mapping[str, Any] | None,
    evidence: Iterable[EvidenceRecord | Mapping[str, Any]] = (),
    *,
    verifier: str = "completion-shadow",
) -> VerifierIndependence:
    """Check all four independence dimensions and reject relabelled wrappers."""
    if isinstance(provenance, VerifierIndependence):
        return provenance
    data = dict(provenance or {})
    implementation = str(data.get(
        "implementation_provenance",
        data.get("implementation", data.get("code_provenance", data.get("code", ""))),
    ))
    producer = str(data.get(
        "producer_identity",
        data.get("producer", data.get("verifier_identity", verifier)),
    ))
    trust_domain = str(data.get("trust_domain", data.get("domain", "")))
    direct_access = bool(data.get(
        "primary_evidence_access",
        data.get("direct_primary_evidence_access", data.get("direct_access", False)),
    ))
    primary_implementation = str(data.get(
        "primary_implementation_provenance",
        data.get("producer_implementation", data.get("primary_code_provenance", "")),
    ))
    primary_producer = str(data.get("primary_producer_identity", data.get("primary_producer", "")))
    primary_domain = str(data.get("primary_trust_domain", data.get("primary_domain", "")))
    records = tuple(_coerce_evidence(item) for item in evidence)
    evidence_producers = {item.producer for item in records if item.producer}
    if not primary_producer and len(evidence_producers) == 1:
        primary_producer = next(iter(evidence_producers))
    reasons: list[str] = []
    if not implementation:
        reasons.append("missing implementation provenance")
    if not producer:
        reasons.append("missing producer identity")
    if not trust_domain:
        reasons.append("missing trust domain")
    if not direct_access:
        reasons.append("verifier lacks direct primary-evidence access")
    if primary_implementation and implementation == primary_implementation:
        reasons.append("verifier reuses primary implementation provenance")
    if primary_producer and producer == primary_producer:
        reasons.append("verifier producer identity equals primary producer")
    if primary_domain and trust_domain == primary_domain:
        reasons.append("verifier trust domain equals primary trust domain")
    return VerifierIndependence(
        implementation_provenance=implementation,
        producer_identity=producer,
        trust_domain=trust_domain,
        primary_evidence_access=direct_access,
        independent=not reasons,
        reasons=reasons,
    )
def propagate_waiver_taint(*values: Any) -> frozenset[str]:
    """Join waiver labels through an arbitrary child/result graph immutably."""
    labels: set[str] = set()
    def visit(value: Any) -> None:
        if isinstance(value, WaiverProof):
            labels.update(value.taint)
            return
        if isinstance(value, CompletionVerdict):
            labels.update(value.taint)
            return
        if isinstance(value, Mapping):
            if "taint" in value:
                visit(value["taint"])
            for key in ("children", "results", "obligations", "proof", "waiver_proof"):
                if key in value:
                    visit(value[key])
            return
        if isinstance(value, (str, bytes)):
            labels.add(value.decode() if isinstance(value, bytes) else value)
            return
        if isinstance(value, Iterable):
            for item in value:
                visit(item)
    for value in values:
        visit(value)
    return frozenset(labels)
combine_waiver_taint = propagate_waiver_taint
transitive_waiver_taint = propagate_waiver_taint
def deduplicate_evidence(records: Iterable[EvidenceRecord | Mapping[str, Any]]) -> tuple[EvidenceRecord, ...]:
    """Public content-deduplication helper used by the shadow evaluator."""
    from ._evaluation_admission import _deduplicate
    return _deduplicate(_coerce_evidence(item) for item in records)
def admit_evidence_for_binding(
    binding: CompletionBinding | Mapping[str, Any],
    evidence: Iterable[EvidenceRecord | Mapping[str, Any]],
) -> tuple[tuple[EvidenceRecord, ...], tuple[Diagnostic, ...]]:
    """Return only scope/binding-admitted, content-deduplicated evidence."""
    from ._evaluation_admission import _admit_records
    return _admit_records(_coerce_binding(binding), evidence)
def evaluate_obligation(
    obligation: Obligation,
    evidence: Iterable[EvidenceRecord | Mapping[str, Any]],
    *,
    spec_hash: str = "",
    binding_hash: str = "",
    complete_capture: bool | None = None,
    capture_producer: str | None = None,
    expected_ids: Any = None,
    aggregate: Any = None,
    required_multiplicity: Any = None,
) -> ObligationResult:
    from ._evaluation_completion import evaluate_obligation_impl
    arguments = locals().copy()
    arguments.pop("evaluate_obligation_impl")
    return evaluate_obligation_impl(**arguments)
def evaluate_completion(
    spec: CompletionSpec | Mapping[str, Any],
    binding: CompletionBinding | Mapping[str, Any],
    evidence: Iterable[EvidenceRecord | Mapping[str, Any]] = (),
    *,
    candidate_outcome: Any = "success",
    outcome: Any = None,
    complete_capture: bool | None = None,
    capture_producer: str | None = None,
    expected_ids: Any = None,
    expected_sets: Any = None,
    aggregate: Any = None,
    aggregate_rules: Any = None,
    required_multiplicity: Any = None,
    multiplicity: Any = None,
    verifier: str = "completion-shadow",
    verifier_version: str = EVIDENCE_SCHEMA_VERSION,
    declared_candidates: Any = None,
    candidates: Any = None,
    selected_candidate: str | None = None,
    applicability: Any = None,
    blocked_proof: BlockedProof | Mapping[str, Any] | None = None,
    waiver_proof: WaiverProof | Mapping[str, Any] | None = None,
    terminal_policy: TerminalPolicy | Mapping[str, Any] | None = None,
    verifier_provenance: VerifierIndependence | Mapping[str, Any] | None = None,
    require_verifier_independence: bool = False,
    independence: VerifierIndependence | Mapping[str, Any] | None = None,
    inherited_taint: Iterable[str] = (),
    waiver_taint: Iterable[str] = (),
    exceptional_proof: BlockedProof | WaiverProof | Mapping[str, Any] | None = None,
) -> CompletionVerdict:
    from ._evaluation_completion import evaluate_completion_impl
    arguments = locals().copy()
    arguments.pop("evaluate_completion_impl")
    return evaluate_completion_impl(**arguments)
def evaluate(
    spec: CompletionSpec | Mapping[str, Any],
    binding: CompletionBinding | Mapping[str, Any],
    evidence: Iterable[EvidenceRecord | Mapping[str, Any]] = (),
    **kwargs: Any,
) -> CompletionVerdict:
    """Short alias for :func:`evaluate_completion`."""
    return evaluate_completion(spec, binding, evidence, **kwargs)
evaluate_spec = evaluate_completion
evaluate_binding = evaluate_completion
evaluate_completion_binding = evaluate_completion
def hash_evidence(record: EvidenceRecord | Mapping[str, Any]) -> str:
    """Return the content identity of an evidence record."""
    return _coerce_evidence(record).content_hash
compute_evidence_hash = hash_evidence
class CompletionEvaluator:
    """Small object façade for callers that prefer an evaluator instance."""
    def __init__(self, *, verifier: str = "completion-shadow", verifier_version: str = EVIDENCE_SCHEMA_VERSION) -> None:
        self.verifier = verifier
        self.verifier_version = verifier_version
    def evaluate(self, spec: CompletionSpec | Mapping[str, Any], binding: CompletionBinding | Mapping[str, Any], evidence: Iterable[EvidenceRecord | Mapping[str, Any]] = (), **kwargs: Any) -> CompletionVerdict:
        kwargs.setdefault("verifier", self.verifier)
        kwargs.setdefault("verifier_version", self.verifier_version)
        return evaluate_completion(spec, binding, evidence, **kwargs)
from ._evaluation_models_results import (
    ObligationResult___init__, ObligationResult_accepted, ObligationResult_failed, ObligationResult_from_dict, ObligationResult_hash, ObligationResult_identity, ObligationResult_proof_mode, ObligationResult_reuse_identity, ObligationResult_satisfied, ObligationResult_to_dict, ObligationResult_unknown,
    CandidateSelection___init__, CandidateSelection_from_dict, CandidateSelection_hash, CandidateSelection_selected, CandidateSelection_to_dict,
    BlockedProof___init__, BlockedProof_evidence_ids, BlockedProof_from_dict, BlockedProof_hash, BlockedProof_to_dict,
)
from ._evaluation_models_records import (
    Diagnostic___init__, Diagnostic_causal_occurrence, Diagnostic_from_dict, Diagnostic_frontier, Diagnostic_hash, Diagnostic_to_dict,
    EvidenceRecord___init__, EvidenceRecord_capture_producer, EvidenceRecord_evidence_scope, EvidenceRecord_from_dict, EvidenceRecord_hash, EvidenceRecord_is_capture_marker, EvidenceRecord_is_complete_capture, EvidenceRecord_obligation_links, EvidenceRecord_reference_id, EvidenceRecord_to_dict,
)
from ._evaluation_models_proofs import (
    TerminalPolicy___init__, TerminalPolicy_from_dict, TerminalPolicy_hash, TerminalPolicy_permits, TerminalPolicy_to_dict,
    VerifierIndependence___init__, VerifierIndependence_from_dict, VerifierIndependence_hash, VerifierIndependence_to_dict, VerifierIndependence_valid,
    WaiverProof___init__, WaiverProof_from_dict, WaiverProof_hash, WaiverProof_to_dict,
)
from ._evaluation_models_verdict import (
    CompletionVerdict___init__, CompletionVerdict_candidate_outcome, CompletionVerdict_evidence_refs, CompletionVerdict_from_dict, CompletionVerdict_hash, CompletionVerdict_independent, CompletionVerdict_reuse_identities, CompletionVerdict_results, CompletionVerdict_selected_candidate, CompletionVerdict_satisfied, CompletionVerdict_to_dict, CompletionVerdict_unknown, CompletionVerdict_waiver_taint,
)
__all__ = ['EVIDENCE_SCHEMA_VERSION', 'OBLIGATION_RESULT_SCHEMA_VERSION', 'DIAGNOSTIC_SCHEMA_VERSION', 'VERDICT_SCHEMA_VERSION', 'EvaluationStatus', 'ObligationStatus', 'VerdictStatus', 'DiagnosticSeverity', 'EvidenceRecord', 'HashedEvidence', 'Evidence', 'EvidenceItem', 'EvidenceRef', 'Diagnostic', 'EvaluationDiagnostic', 'DiagnosticRecord', 'ObligationResult', 'ObligationEvaluation', 'ObligationResultRecord', 'CandidateSelection', 'select_candidate', 'BlockedProof', 'BlockedOutcomeProof', 'WaiverProof', 'WaiverOutcomeProof', 'TerminalPolicy', 'TerminalDispositionPolicy', 'VerifierIndependence', 'VerifierIndependenceProof', 'verify_verifier_independence', 'propagate_waiver_taint', 'combine_waiver_taint', 'transitive_waiver_taint', 'CompletionVerdict', 'ShadowCompletionVerdict', 'CompletionVerdictRecord', 'deduplicate_evidence', 'admit_evidence_for_binding', 'evaluate_obligation', 'evaluate_completion', 'evaluate', 'evaluate_spec', 'evaluate_binding', 'evaluate_completion_binding', 'hash_evidence', 'compute_evidence_hash', 'CompletionEvaluator']
