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

def WaiverProof___init__(
        self,
        authority_provenance: Any = None,
        scope: Any = None,
        reason: str = "",
        evidence_ids: Iterable[str] = (),
        expiry: Any = None,
        taint: Iterable[str] = (),
        binding_hash: str = "",
        proof_hash: str = "",
        *,
        authority: Any = None,
        waiver_scope: Any = None,
        expires: Any = None,
    ) -> None:
        authority_value = authority_provenance if authority is None else authority
        scope_value = scope if waiver_scope is None else waiver_scope
        actual_expiry = expiry if expires is None else expires
        ids = tuple(dict.fromkeys(_as_tuple(evidence_ids, "evidence_ids")))
        actual_taint = frozenset(str(item) for item in taint) | frozenset({"waived"})
        if authority_value is None or scope_value is None or not _text(reason, "reason", allow_empty=False):
            raise ValueError("waiver proof requires authority provenance, scope, and reason")
        if actual_expiry is None:
            raise ValueError("waiver proof requires an expiry")
        if not ids:
            raise ValueError("waiver proof requires evidence")
        payload = {
            "authority_provenance": authority_value,
            "scope": scope_value,
            "reason": str(reason).strip(),
            "evidence_ids": list(ids),
            "expiry": actual_expiry,
            "taint": sorted(actual_taint),
            "binding_hash": binding_hash,
        }
        expected = _hashed_record("arnold.workflow.completion_waiver_proof.v1", payload, proof_hash)
        for name, value in {
            "authority_provenance": _freeze(authority_value),
            "scope": _freeze(scope_value),
            "reason": payload["reason"],
            "evidence_ids": ids,
            "expiry": _freeze(actual_expiry),
            "taint": actual_taint,
            "binding_hash": str(binding_hash),
            "proof_hash": expected,
        }.items():
            object.__setattr__(self, name, value)

def WaiverProof_hash(self) -> str:
        return self.proof_hash

def WaiverProof_to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "arnold.workflow.completion_waiver_proof.v1",
            "authority_provenance": _thaw(self.authority_provenance),
            "scope": _thaw(self.scope),
            "reason": self.reason,
            "evidence_ids": list(self.evidence_ids),
            "expiry": _thaw(self.expiry),
            "taint": sorted(self.taint),
            "binding_hash": self.binding_hash,
            "proof_hash": self.proof_hash,
        }

def WaiverProof_from_dict(cls, data: Mapping[str, Any]) -> "WaiverProof":
        return cls(
            authority_provenance=data.get("authority_provenance", data.get("authority")),
            scope=data.get("scope", data.get("waiver_scope")),
            reason=str(data.get("reason", "")),
            evidence_ids=data.get("evidence_ids", ()),
            expiry=data.get("expiry", data.get("expires")),
            taint=data.get("taint", ()),
            binding_hash=str(data.get("binding_hash", "")),
            proof_hash=str(data.get("proof_hash", data.get("hash", ""))),
        )

def TerminalPolicy___init__(
        self,
        permitted_outcomes: Iterable[str] = (),
        evidence_ids: Iterable[str] = (),
        admitted: bool = False,
        independent: bool = False,
        producer: str = "",
        trust_domain: str = "",
        policy_hash: str = "",
        *,
        outcomes: Iterable[str] | None = None,
        allowed_outcomes: Iterable[str] | None = None,
        independently_admitted: bool | None = None,
    ) -> None:
        raw_outcomes = permitted_outcomes
        if outcomes is not None:
            raw_outcomes = outcomes
        if allowed_outcomes is not None:
            raw_outcomes = allowed_outcomes
        actual_outcomes = frozenset(_as_tuple(raw_outcomes, "permitted_outcomes"))
        actual_independent = independent if independently_admitted is None else independently_admitted
        actual_producer = _text(producer, "producer")
        actual_trust = _text(trust_domain, "trust_domain")
        ids = tuple(dict.fromkeys(_as_tuple(evidence_ids, "evidence_ids")))
        payload = {
            "permitted_outcomes": sorted(actual_outcomes),
            "evidence_ids": list(ids),
            "admitted": bool(admitted),
            "independent": bool(actual_independent),
            "producer": actual_producer,
            "trust_domain": actual_trust,
        }
        expected = _hashed_record("arnold.workflow.completion_terminal_policy.v1", payload, policy_hash)
        for name, value in {
            "permitted_outcomes": actual_outcomes,
            "evidence_ids": ids,
            "admitted": bool(admitted),
            "independent": bool(actual_independent),
            "producer": actual_producer,
            "trust_domain": actual_trust,
            "policy_hash": expected,
        }.items():
            object.__setattr__(self, name, value)

def TerminalPolicy_permits(self, outcome: str) -> bool:
        return self.admitted and self.independent and bool(self.evidence_ids) and outcome in self.permitted_outcomes

def TerminalPolicy_hash(self) -> str:
        return self.policy_hash

def TerminalPolicy_to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "arnold.workflow.completion_terminal_policy.v1",
            "permitted_outcomes": sorted(self.permitted_outcomes),
            "evidence_ids": list(self.evidence_ids),
            "admitted": self.admitted,
            "independent": self.independent,
            "producer": self.producer,
            "trust_domain": self.trust_domain,
            "policy_hash": self.policy_hash,
        }

def TerminalPolicy_from_dict(cls, data: Mapping[str, Any]) -> "TerminalPolicy":
        return cls(
            permitted_outcomes=data.get("permitted_outcomes", data.get("allowed_outcomes", data.get("outcomes", ()))),
            evidence_ids=data.get("evidence_ids", ()),
            admitted=bool(data.get("admitted", False)),
            independent=bool(data.get("independent", data.get("independently_admitted", False))),
            producer=str(data.get("producer", "")),
            trust_domain=str(data.get("trust_domain", "")),
            policy_hash=str(data.get("policy_hash", data.get("hash", ""))),
        )

def VerifierIndependence___init__(
        self,
        implementation_provenance: str = "",
        producer_identity: str = "",
        trust_domain: str = "",
        primary_evidence_access: bool = False,
        independent: bool | None = None,
        reasons: Iterable[str] = (),
        independence_hash: str = "",
        *,
        implementation: str | None = None,
        producer: str | None = None,
        direct_primary_evidence_access: bool | None = None,
    ) -> None:
        actual_implementation = implementation_provenance if implementation is None else implementation
        actual_producer = producer_identity if producer is None else producer
        actual_access = primary_evidence_access if direct_primary_evidence_access is None else direct_primary_evidence_access
        reason_values = tuple(dict.fromkeys(str(item) for item in reasons))
        actual_independent = bool(independent) if independent is not None else bool(
            actual_implementation and actual_producer and trust_domain and actual_access and not reason_values
        )
        payload = {
            "implementation_provenance": str(actual_implementation),
            "producer_identity": str(actual_producer),
            "trust_domain": str(trust_domain),
            "primary_evidence_access": bool(actual_access),
            "independent": actual_independent,
            "reasons": list(reason_values),
        }
        expected = _hashed_record("arnold.workflow.completion_verifier_independence.v1", payload, independence_hash)
        for name, value in {
            "implementation_provenance": payload["implementation_provenance"],
            "producer_identity": payload["producer_identity"],
            "trust_domain": payload["trust_domain"],
            "primary_evidence_access": payload["primary_evidence_access"],
            "independent": actual_independent,
            "reasons": reason_values,
            "independence_hash": expected,
        }.items():
            object.__setattr__(self, name, value)

def VerifierIndependence_valid(self) -> bool:
        return self.independent

def VerifierIndependence_hash(self) -> str:
        return self.independence_hash

def VerifierIndependence_to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "arnold.workflow.completion_verifier_independence.v1",
            "implementation_provenance": self.implementation_provenance,
            "producer_identity": self.producer_identity,
            "trust_domain": self.trust_domain,
            "primary_evidence_access": self.primary_evidence_access,
            "independent": self.independent,
            "reasons": list(self.reasons),
            "independence_hash": self.independence_hash,
        }

def VerifierIndependence_from_dict(cls, data: Mapping[str, Any]) -> "VerifierIndependence":
        return cls(
            implementation_provenance=str(data.get("implementation_provenance", data.get("implementation", ""))),
            producer_identity=str(data.get("producer_identity", data.get("producer", ""))),
            trust_domain=str(data.get("trust_domain", "")),
            primary_evidence_access=bool(data.get("primary_evidence_access", data.get("direct_primary_evidence_access", False))),
            independent=bool(data.get("independent", False)),
            reasons=data.get("reasons", ()),
            independence_hash=str(data.get("independence_hash", data.get("hash", ""))),
        )

