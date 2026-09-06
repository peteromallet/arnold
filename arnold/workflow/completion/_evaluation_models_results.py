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

def ObligationResult___init__(
        self,
        obligation_id: str,
        status: EvaluationStatus | str,
        kind: ProofMode | str = ProofMode.PRESENCE,
        spec_hash: str = "",
        binding_hash: str = "",
        required: bool = True,
        evidence_ids: Iterable[str] = (),
        diagnostics: Iterable[Diagnostic | Mapping[str, Any]] = (),
        observed_count: int = 0,
        expected_count: int | None = None,
        observed_ids: Iterable[str] = (),
        expected_ids: Iterable[str] = (),
        aggregate_value: Any = None,
        result_hash: str = "",
        *,
        proof_mode: ProofMode | str | None = None,
        result: EvaluationStatus | str | None = None,
    ) -> None:
        actual_kind = _enum_value(proof_mode if proof_mode is not None else kind, ProofMode, "proof mode")
        actual_status = _enum_value(result if result is not None else status, EvaluationStatus, "evaluation status")
        actual_diagnostics = tuple(
            item if isinstance(item, Diagnostic) else Diagnostic.from_dict(item) for item in diagnostics
        )
        if isinstance(observed_count, bool) or observed_count < 0:
            raise ValueError("observed_count must be non-negative")
        if expected_count is not None and (isinstance(expected_count, bool) or expected_count < 0):
            raise ValueError("expected_count must be non-negative or None")
        frozen_aggregate = _freeze(aggregate_value) if aggregate_value is not None else None
        payload = {
            "schema_version": OBLIGATION_RESULT_SCHEMA_VERSION,
            "obligation_id": _text(obligation_id, "obligation_id", allow_empty=False),
            "status": actual_status.value,
            "kind": actual_kind.value,
            "spec_hash": _text(spec_hash, "spec_hash"),
            "binding_hash": _text(binding_hash, "binding_hash"),
            "required": bool(required),
            "evidence_ids": list(_as_tuple(evidence_ids, "evidence_ids")),
            "diagnostics": [item.to_dict() for item in actual_diagnostics],
            "observed_count": observed_count,
            "expected_count": expected_count,
            "observed_ids": list(_as_tuple(observed_ids, "observed_ids")),
            "expected_ids": list(_as_tuple(expected_ids, "expected_ids")),
            "aggregate_value": _thaw(frozen_aggregate),
        }
        expected_hash = hash_canonical(payload)
        if result_hash and result_hash != expected_hash:
            raise ValueError("ObligationResult result_hash mismatch")
        for name, value in {
            "obligation_id": payload["obligation_id"],
            "status": actual_status,
            "kind": actual_kind,
            "spec_hash": payload["spec_hash"],
            "binding_hash": payload["binding_hash"],
            "required": payload["required"],
            "evidence_ids": tuple(payload["evidence_ids"]),
            "diagnostics": actual_diagnostics,
            "observed_count": observed_count,
            "expected_count": expected_count,
            "observed_ids": tuple(payload["observed_ids"]),
            "expected_ids": tuple(payload["expected_ids"]),
            "aggregate_value": frozen_aggregate,
            "result_hash": expected_hash,
        }.items():
            object.__setattr__(self, name, value)

def ObligationResult_proof_mode(self) -> ProofMode:
        return self.kind

def ObligationResult_satisfied(self) -> bool:
        return self.status in {EvaluationStatus.SATISFIED, EvaluationStatus.WAIVED}

def ObligationResult_accepted(self) -> bool:
        return self.satisfied

def ObligationResult_unknown(self) -> bool:
        return self.status is EvaluationStatus.UNKNOWN

def ObligationResult_failed(self) -> bool:
        return self.status is EvaluationStatus.UNSATISFIED

def ObligationResult_reuse_identity(self) -> tuple[str, str, str]:
        return (self.spec_hash, self.obligation_id, self.binding_hash)

def ObligationResult_identity(self) -> tuple[str, str, str]:
        return self.reuse_identity

def ObligationResult_hash(self) -> str:
        return self.result_hash

def ObligationResult_to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": OBLIGATION_RESULT_SCHEMA_VERSION,
            "obligation_id": self.obligation_id,
            "status": self.status.value,
            "kind": self.kind.value,
            "proof_mode": self.kind.value,
            "spec_hash": self.spec_hash,
            "binding_hash": self.binding_hash,
            "required": self.required,
            "evidence_ids": list(self.evidence_ids),
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "observed_count": self.observed_count,
            "expected_count": self.expected_count,
            "observed_ids": list(self.observed_ids),
            "expected_ids": list(self.expected_ids),
            "aggregate_value": _thaw(self.aggregate_value),
            "result_hash": self.result_hash,
        }

def ObligationResult_from_dict(cls, data: Mapping[str, Any]) -> "ObligationResult":
        return cls(
            obligation_id=str(data["obligation_id"]),
            status=str(data["status"]),
            kind=str(data.get("kind", data.get("proof_mode", "presence"))),
            spec_hash=str(data.get("spec_hash", "")),
            binding_hash=str(data.get("binding_hash", "")),
            required=bool(data.get("required", True)),
            evidence_ids=data.get("evidence_ids", ()),
            diagnostics=data.get("diagnostics", ()),
            observed_count=int(data.get("observed_count", 0)),
            expected_count=data.get("expected_count"),
            observed_ids=data.get("observed_ids", ()),
            expected_ids=data.get("expected_ids", ()),
            aggregate_value=data.get("aggregate_value"),
            result_hash=str(data.get("result_hash", "")),
        )

def CandidateSelection___init__(
        self,
        declared_candidates: Iterable[str] = (),
        selected_candidate: str = "",
        applicability: Any = None,
        selection_hash: str = "",
        *,
        candidates: Iterable[str] | None = None,
        selected: str | None = None,
    ) -> None:
        declared = tuple(dict.fromkeys(_as_tuple(
            declared_candidates if candidates is None else candidates,
            "declared_candidates",
        )))
        chosen = _text(selected_candidate if selected is None else selected, "selected_candidate")
        if len(declared) != 1:
            raise ValueError("candidate selection requires exactly one declared candidate")
        if chosen != declared[0]:
            raise ValueError("selected candidate is not the sole declared candidate")
        frozen_applicability = _freeze(applicability) if applicability is not None else None
        payload = {
            "declared_candidates": list(declared),
            "selected_candidate": chosen,
            "applicability": _thaw(frozen_applicability),
        }
        expected = _hashed_record("arnold.workflow.completion_candidate_selection.v1", payload, selection_hash)
        object.__setattr__(self, "declared_candidates", declared)
        object.__setattr__(self, "selected_candidate", chosen)
        object.__setattr__(self, "applicability", frozen_applicability)
        object.__setattr__(self, "selection_hash", expected)

def CandidateSelection_selected(self) -> str:
        return self.selected_candidate

def CandidateSelection_hash(self) -> str:
        return self.selection_hash

def CandidateSelection_to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "arnold.workflow.completion_candidate_selection.v1",
            "declared_candidates": list(self.declared_candidates),
            "selected_candidate": self.selected_candidate,
            "applicability": _thaw(self.applicability),
            "selection_hash": self.selection_hash,
        }

def CandidateSelection_from_dict(cls, data: Mapping[str, Any]) -> "CandidateSelection":
        return cls(
            declared_candidates=data.get("declared_candidates", data.get("candidates", ())),
            selected_candidate=str(data.get("selected_candidate", data.get("selected", ""))),
            applicability=data.get("applicability"),
            selection_hash=str(data.get("selection_hash", data.get("hash", ""))),
        )

def BlockedProof___init__(
        self,
        blocker_id: str = "",
        causal_evidence_ids: Iterable[str] = (),
        authority_coordinates: Any = None,
        custody_coordinates: Any = None,
        next_admission: str = "",
        recovery_disposition: str = "",
        binding_hash: str = "",
        proof_hash: str = "",
        *,
        evidence_ids: Iterable[str] | None = None,
        authority: Any = None,
        custody: Any = None,
        disposition: str | None = None,
        recovery: str | None = None,
    ) -> None:
        ids = tuple(dict.fromkeys(_as_tuple(
            causal_evidence_ids if evidence_ids is None else evidence_ids,
            "causal_evidence_ids",
        )))
        blocker = _text(blocker_id, "blocker_id", allow_empty=False)
        next_step = _text(next_admission, "next_admission", allow_empty=False)
        recovery_step = _text(
            recovery_disposition if recovery is None else recovery,
            "recovery_disposition",
            allow_empty=False,
        )
        authority_value = authority_coordinates if authority is None else authority
        custody_value = custody_coordinates if custody is None else custody
        if not ids or authority_value is None or custody_value is None:
            raise ValueError("blocked proof requires causal evidence, authority, and custody coordinates")
        payload = {
            "blocker_id": blocker,
            "causal_evidence_ids": list(ids),
            "authority_coordinates": authority_value,
            "custody_coordinates": custody_value,
            "next_admission": next_step,
            "recovery_disposition": recovery_step,
            "binding_hash": binding_hash,
        }
        expected = _hashed_record("arnold.workflow.completion_blocked_proof.v1", payload, proof_hash)
        for name, value in {
            "blocker_id": blocker,
            "causal_evidence_ids": ids,
            "authority_coordinates": _freeze(authority_value),
            "custody_coordinates": _freeze(custody_value),
            "next_admission": next_step,
            "recovery_disposition": recovery_step,
            "binding_hash": str(binding_hash),
            "proof_hash": expected,
        }.items():
            object.__setattr__(self, name, value)

def BlockedProof_evidence_ids(self) -> tuple[str, ...]:
        return self.causal_evidence_ids

def BlockedProof_hash(self) -> str:
        return self.proof_hash

def BlockedProof_to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "arnold.workflow.completion_blocked_proof.v1",
            "blocker_id": self.blocker_id,
            "causal_evidence_ids": list(self.causal_evidence_ids),
            "evidence_ids": list(self.causal_evidence_ids),
            "authority_coordinates": _thaw(self.authority_coordinates),
            "custody_coordinates": _thaw(self.custody_coordinates),
            "next_admission": self.next_admission,
            "recovery_disposition": self.recovery_disposition,
            "binding_hash": self.binding_hash,
            "proof_hash": self.proof_hash,
        }

def BlockedProof_from_dict(cls, data: Mapping[str, Any]) -> "BlockedProof":
        return cls(
            blocker_id=str(data.get("blocker_id", data.get("id", ""))),
            causal_evidence_ids=data.get("causal_evidence_ids", data.get("evidence_ids", ())),
            authority_coordinates=data.get("authority_coordinates", data.get("authority")),
            custody_coordinates=data.get("custody_coordinates", data.get("custody")),
            next_admission=str(data.get("next_admission", data.get("next_admission_disposition", ""))),
            recovery_disposition=str(data.get("recovery_disposition", data.get("recovery", data.get("disposition", "")))),
            binding_hash=str(data.get("binding_hash", "")),
            proof_hash=str(data.get("proof_hash", data.get("hash", ""))),
        )

