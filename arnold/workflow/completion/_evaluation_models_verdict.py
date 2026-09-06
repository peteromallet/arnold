"""Implementation helpers for evaluation record models.

Public model classes stay defined in evaluation.py; these helpers hold their
validation and serialization bodies so the public module remains auditable.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from . import evaluation as e
from arnold.workflow.completion.evidence import EvidenceScope
from arnold.workflow.completion.hashing import hash_canonical

EVIDENCE_SCHEMA_VERSION = e.EVIDENCE_SCHEMA_VERSION
OBLIGATION_RESULT_SCHEMA_VERSION = e.OBLIGATION_RESULT_SCHEMA_VERSION
DIAGNOSTIC_SCHEMA_VERSION = e.DIAGNOSTIC_SCHEMA_VERSION
VERDICT_SCHEMA_VERSION = e.VERDICT_SCHEMA_VERSION
EvaluationStatus = e.EvaluationStatus
DiagnosticSeverity = e.DiagnosticSeverity
ProofMode = e.ProofMode
CompletionSpec = e.CompletionSpec
CompletionBinding = e.CompletionBinding
EvidenceRecord = e.EvidenceRecord
Diagnostic = e.Diagnostic
ObligationResult = e.ObligationResult
CandidateSelection = e.CandidateSelection
BlockedProof = e.BlockedProof
WaiverProof = e.WaiverProof
TerminalPolicy = e.TerminalPolicy
VerifierIndependence = e.VerifierIndependence
CompletionVerdict = e.CompletionVerdict
_freeze = e._freeze
_thaw = e._thaw
_text = e._text
_as_tuple = e._as_tuple
_choose_alias = e._choose_alias
_enum_value = e._enum_value
_hashed_record = e._hashed_record

def _verdict_records(values: Mapping[str, Any]) -> tuple[tuple[ObligationResult, ...], tuple[EvidenceRecord, ...], tuple[Diagnostic, ...]]:
    raw_results = values["results"] if values["results"] is not None else values["obligation_results"]
    results = tuple(item if isinstance(item, ObligationResult) else ObligationResult.from_dict(item) for item in raw_results)
    raw_evidence = values["evidence_refs"] if values["evidence_refs"] is not None else values["evidence"]
    evidence = tuple(item if isinstance(item, EvidenceRecord) else EvidenceRecord.from_dict(item) for item in raw_evidence)
    diagnostics = tuple(item if isinstance(item, Diagnostic) else Diagnostic.from_dict(item) for item in values["diagnostics"])
    return results, evidence, diagnostics


def _verdict_related(values: Mapping[str, Any]) -> tuple[Any, Any, Any, Any]:
    candidate = values["candidate_selection"]
    candidate = candidate if isinstance(candidate, CandidateSelection) or candidate is None else CandidateSelection.from_dict(candidate)
    exceptional = values["exceptional_proof"]
    if isinstance(exceptional, Mapping):
        kind = str(exceptional.get("outcome", "")).lower()
        exceptional = WaiverProof.from_dict(exceptional) if kind == "waived" or "authority_provenance" in exceptional else BlockedProof.from_dict(exceptional)
    independence = values["verifier_independence"]
    independence = independence if isinstance(independence, VerifierIndependence) or independence is None else VerifierIndependence.from_dict(independence)
    policy = values["terminal_policy"]
    policy = policy if isinstance(policy, TerminalPolicy) or policy is None else TerminalPolicy.from_dict(policy)
    return candidate, exceptional, independence, policy


def _derived_status(accepted: bool, required: tuple[ObligationResult, ...]) -> EvaluationStatus:
    if accepted:
        return EvaluationStatus.SATISFIED
    if any(item.unknown for item in required):
        return EvaluationStatus.UNKNOWN
    if any(item.failed for item in required):
        return EvaluationStatus.UNSATISFIED
    return EvaluationStatus.UNKNOWN


def _verdict_status(values: Mapping[str, Any], results: tuple[ObligationResult, ...], exceptional: Any) -> tuple[str, EvaluationStatus, bool, frozenset[str]]:
    taint = frozenset(str(item) for item in values["taint"])
    if isinstance(exceptional, WaiverProof):
        taint |= exceptional.taint
    outcome = _text(values["candidate_outcome"] if values["candidate_outcome"] is not None else values["outcome"], "outcome") or "success"
    required = tuple(item for item in results if item.required)
    logical = bool(required) and all(item.satisfied for item in required)
    accepted = logical if values["accepted"] is None else bool(values["accepted"])
    if accepted and not logical:
        raise ValueError("CompletionVerdict cannot be accepted with an unsatisfied required obligation")
    supplied = values["overall_status"] if values["overall_status"] is not None else values["status"]
    if supplied is not None:
        status = _enum_value(supplied, EvaluationStatus, "verdict status")
    else:
        status = _derived_status(accepted, required)
    return outcome, status, accepted, taint


def _verdict_normalized(values: Mapping[str, Any]) -> dict[str, Any]:
    results, evidence, diagnostics = _verdict_records(values)
    candidate, exceptional, independence, policy = _verdict_related(values)
    outcome, status, accepted, taint = _verdict_status(values, results, exceptional)
    payload = {"schema_version": VERDICT_SCHEMA_VERSION, "spec_hash": _text(values["spec_hash"], "spec_hash"), "binding_hash": _text(values["binding_hash"], "binding_hash"), "outcome": outcome, "status": status.value, "accepted": accepted, "obligation_results": [item.to_dict() for item in results], "evidence": [item.to_dict() for item in evidence], "diagnostics": [item.to_dict() for item in diagnostics], "candidate_selection": candidate.to_dict() if candidate else None, "exceptional_proof": exceptional.to_dict() if exceptional else None, "terminal_policy": policy.to_dict() if policy else None, "terminal": bool(values["terminal"]), "taint": sorted(taint), "verifier_independence": independence.to_dict() if independence else None, "verifier": _text(values["verifier"], "verifier"), "verifier_version": _text(values["verifier_version"], "verifier_version")}
    expected = hash_canonical(payload)
    if values["verdict_hash"] and values["verdict_hash"] != expected:
        raise ValueError("CompletionVerdict verdict_hash mismatch")
    return {"spec_hash": payload["spec_hash"], "binding_hash": payload["binding_hash"], "outcome": outcome, "status": status, "accepted": accepted, "obligation_results": results, "evidence": evidence, "diagnostics": diagnostics, "candidate_selection": candidate, "exceptional_proof": exceptional, "terminal_policy": policy, "terminal": bool(values["terminal"]), "taint": taint, "verifier_independence": independence, "verifier": payload["verifier"], "verifier_version": payload["verifier_version"], "verdict_hash": expected}


def CompletionVerdict___init__(self, spec_hash: str = "", binding_hash: str = "", outcome: Any = "success", obligation_results: Iterable[ObligationResult | Mapping[str, Any]] = (), evidence: Iterable[EvidenceRecord | Mapping[str, Any]] = (), diagnostics: Iterable[Diagnostic | Mapping[str, Any]] = (), accepted: bool | None = None, status: EvaluationStatus | str | None = None, verifier: str = "completion-shadow", verifier_version: str = EVIDENCE_SCHEMA_VERSION, verdict_hash: str = "", *, results: Iterable[ObligationResult | Mapping[str, Any]] | None = None, evidence_refs: Iterable[EvidenceRecord | Mapping[str, Any]] | None = None, candidate_outcome: Any = None, overall_status: EvaluationStatus | str | None = None, candidate_selection: CandidateSelection | Mapping[str, Any] | None = None, exceptional_proof: BlockedProof | WaiverProof | Mapping[str, Any] | None = None, terminal_policy: TerminalPolicy | Mapping[str, Any] | None = None, terminal: bool = False, taint: Iterable[str] = (), verifier_independence: VerifierIndependence | Mapping[str, Any] | None = None) -> None:
    for name, value in _verdict_normalized(locals()).items():
        object.__setattr__(self, name, value)

def CompletionVerdict_candidate_outcome(self) -> str:
        return self.outcome

def CompletionVerdict_results(self) -> tuple[ObligationResult, ...]:
        return self.obligation_results

def CompletionVerdict_evidence_refs(self) -> tuple[EvidenceRecord, ...]:
        return self.evidence

def CompletionVerdict_selected_candidate(self) -> str | None:
        return self.candidate_selection.selected_candidate if self.candidate_selection else None

def CompletionVerdict_waiver_taint(self) -> frozenset[str]:
        return self.taint

def CompletionVerdict_independent(self) -> bool | None:
        return self.verifier_independence.independent if self.verifier_independence else None

def CompletionVerdict_unknown(self) -> bool:
        return self.status is EvaluationStatus.UNKNOWN

def CompletionVerdict_satisfied(self) -> bool:
        return self.accepted

def CompletionVerdict_reuse_identities(self) -> tuple[tuple[str, str, str], ...]:
        return tuple(item.reuse_identity for item in self.obligation_results)

def CompletionVerdict_hash(self) -> str:
        return self.verdict_hash

def CompletionVerdict_to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": VERDICT_SCHEMA_VERSION,
            "spec_hash": self.spec_hash,
            "binding_hash": self.binding_hash,
            "outcome": self.outcome,
            "candidate_outcome": self.outcome,
            "status": self.status.value,
            "accepted": self.accepted,
            "obligation_results": [item.to_dict() for item in self.obligation_results],
            "results": [item.to_dict() for item in self.obligation_results],
            "evidence": [item.to_dict() for item in self.evidence],
            "evidence_refs": [item.to_dict() for item in self.evidence],
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "candidate_selection": self.candidate_selection.to_dict() if self.candidate_selection else None,
            "exceptional_proof": self.exceptional_proof.to_dict() if self.exceptional_proof else None,
            "terminal_policy": self.terminal_policy.to_dict() if self.terminal_policy else None,
            "terminal": self.terminal,
            "taint": sorted(self.taint),
            "verifier_independence": self.verifier_independence.to_dict() if self.verifier_independence else None,
            "verifier": self.verifier,
            "verifier_version": self.verifier_version,
            "verdict_hash": self.verdict_hash,
        }

def CompletionVerdict_from_dict(cls, data: Mapping[str, Any]) -> "CompletionVerdict":
        return cls(
            spec_hash=str(data.get("spec_hash", "")),
            binding_hash=str(data.get("binding_hash", "")),
            outcome=data.get("outcome", data.get("candidate_outcome", "success")),
            obligation_results=data.get("obligation_results", data.get("results", ())),
            evidence=data.get("evidence", data.get("evidence_refs", ())),
            diagnostics=data.get("diagnostics", ()),
            candidate_selection=data.get("candidate_selection"),
            exceptional_proof=data.get("exceptional_proof"),
            terminal_policy=data.get("terminal_policy"),
            terminal=bool(data.get("terminal", False)),
            taint=data.get("taint", ()),
            verifier_independence=data.get("verifier_independence"),
            accepted=bool(data.get("accepted", False)),
            status=data.get("status"),
            verifier=str(data.get("verifier", "completion-shadow")),
            verifier_version=str(data.get("verifier_version", EVIDENCE_SCHEMA_VERSION)),
            verdict_hash=str(data.get("verdict_hash", "")),
        )
