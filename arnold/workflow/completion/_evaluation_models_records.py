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

def _evidence_scope_values(values: Mapping[str, Any]) -> tuple[str, str, EvidenceScope | None]:
    actual_scope = _choose_alias(values["scope"], (values["evidence_scope"],), "scope")
    if isinstance(actual_scope, Mapping):
        actual_scope = EvidenceScope.from_dict(actual_scope)
    if actual_scope is not None and not isinstance(actual_scope, EvidenceScope):
        raise TypeError("scope must be an EvidenceScope or mapping")
    actual_binding = _text(values["binding_hash"], "binding_hash")
    actual_scope_hash = _text(values["scope_hash"], "scope_hash")
    if actual_scope is not None:
        if actual_scope.binding_hash and actual_binding and actual_binding != actual_scope.binding_hash:
            raise ValueError("EvidenceRecord binding_hash conflicts with scope")
        if actual_scope.scope_hash and actual_scope_hash and actual_scope_hash != actual_scope.scope_hash:
            raise ValueError("EvidenceRecord scope_hash conflicts with scope")
        if actual_scope.binding_hash:
            actual_binding = actual_scope.binding_hash
        if actual_scope.scope_hash:
            actual_scope_hash = actual_scope.scope_hash
    return actual_binding, actual_scope_hash, actual_scope


def _evidence_capture_values(values: Mapping[str, Any], content: Any) -> tuple[str, str, bool | None, str]:
    producer = _choose_alias(values["producer"], (values["provider"], values["capture_producer"]), "producer")
    version = _choose_alias(values["producer_version"], (values["provider_version"],), "producer_version")
    producer = _text(producer, "producer")
    version = _text(version, "producer_version")
    complete_values = [item for item in (values["capture_complete"], values["complete_capture"]) if item is not None]
    if complete_values and any(item != complete_values[0] for item in complete_values[1:]):
        raise ValueError("capture_complete received conflicting aliases")
    complete = complete_values[0] if complete_values else None
    if complete is not None and not isinstance(complete, bool):
        raise TypeError("capture_complete must be bool or None")
    for source in (values["capture"], content if isinstance(content, Mapping) else None):
        if source and complete is None:
            for key in ("capture_complete", "complete_capture", "complete"):
                if key in source:
                    complete = bool(source[key])
                    break
        if source and not producer:
            producer = _text(source.get("producer", source.get("capture_producer", "")), "producer")
    capture_id = _text(values["capture_id"] or (values["capture"] or {}).get("capture_id", ""), "capture_id")
    return producer, version, complete, capture_id


def _evidence_link_values(values: Mapping[str, Any], content: Any) -> tuple[tuple[str, ...], str, str, bool, bool]:
    links: list[str] = []
    for source in (values["obligation_ids"], values["links"], values["supports"]):
        links.extend(_as_tuple(source, "obligation_ids"))
    if values["obligation_id"]:
        links.append(str(values["obligation_id"]))
    actual_links = tuple(dict.fromkeys(links))
    member = _choose_alias(values["member_id"], (values["event_id"], values["item_id"]), "member_id")
    if member is None and isinstance(content, Mapping):
        member = next((content[key] for key in ("member_id", "event_id", "item_id") if key in content), None)
    reference = _text(_choose_alias(values["evidence_id"], (values["reference_id"],), "evidence_id"), "evidence_id")
    admitted = values["admitted"] if values["is_admitted"] is None else values["is_admitted"]
    stale = values["stale"] if values["stale_evidence"] is None else values["stale_evidence"]
    if values["status"] is not None and str(values["status"]).lower() in {"stale", "stale_evidence"}:
        stale = True
    if not isinstance(admitted, bool) or not isinstance(stale, bool):
        raise TypeError("admitted and stale must be bool")
    return actual_links, "" if member is None else str(member), reference, admitted, stale


def _evidence_normalized(values: Mapping[str, Any]) -> dict[str, Any]:
    content = _choose_alias(values["content"], (values["payload"], values["value"], values["body"]), "content")
    binding, scope_hash, scope = _evidence_scope_values(values)
    producer, version, complete, capture_id = _evidence_capture_values(values, content)
    links, member, reference, admitted, stale = _evidence_link_values(values, content)
    multiplicity = values["multiplicity"]
    if isinstance(multiplicity, bool) or not isinstance(multiplicity, int) or multiplicity < 1:
        raise ValueError("multiplicity must be a positive integer")
    frozen_content = _freeze(content)
    frozen_cursor = _freeze(values["cursor"]) if values["cursor"] is not None else None
    frozen_details = _freeze(values["details"]) if values["details"] is not None else None
    payload = {"schema_version": EVIDENCE_SCHEMA_VERSION, "kind": _text(values["kind"], "kind", allow_empty=False), "content": _thaw(frozen_content), "binding_hash": binding, "scope_hash": scope_hash, "producer": producer, "producer_version": version, "member_id": member, "capture_id": capture_id, "capture_complete": complete, "cursor": _thaw(frozen_cursor), "details": _thaw(frozen_details), "multiplicity": multiplicity}
    expected = hash_canonical(payload)
    supplied = [item for item in (values["evidence_hash"], values["content_hash"], values["hash"], values["record_hash"]) if item]
    if supplied and any(item != expected for item in supplied):
        raise ValueError("EvidenceRecord content/evidence hash mismatch")
    return {"kind": payload["kind"], "content": frozen_content, "binding_hash": binding, "scope_hash": scope_hash, "evidence_id": reference or expected, "producer": producer, "producer_version": version, "obligation_ids": links, "member_id": member, "capture_id": capture_id, "capture_complete": complete, "admitted": admitted, "stale": stale, "cursor": frozen_cursor, "details": frozen_details, "multiplicity": multiplicity, "scope": scope, "content_hash": expected, "evidence_hash": expected}


def EvidenceRecord___init__(self, kind: str, content: Any = None, binding_hash: str = "", scope_hash: str = "", evidence_id: str = "", producer: str = "", producer_version: str = "", obligation_ids: Iterable[str] = (), member_id: Any = None, capture_id: str = "", capture_complete: bool | None = None, admitted: bool = True, stale: bool = False, cursor: Any = None, details: Any = None, multiplicity: int = 1, scope: EvidenceScope | Mapping[str, Any] | None = None, evidence_hash: str = "", *, payload: Any = None, value: Any = None, body: Any = None, content_hash: str = "", hash: str = "", record_hash: str = "", evidence_scope: EvidenceScope | Mapping[str, Any] | None = None, links: Iterable[str] = (), supports: Iterable[str] = (), obligation_id: str | None = None, provider: str = "", provider_version: str = "", capture_producer: str = "", complete_capture: bool | None = None, capture: Mapping[str, Any] | None = None, event_id: Any = None, item_id: Any = None, reference_id: Any = None, status: Any = None, is_admitted: bool | None = None, stale_evidence: bool | None = None) -> None:
    for name, value in _evidence_normalized(locals()).items():
        object.__setattr__(self, name, value)

def EvidenceRecord_hash(self) -> str:
        return self.content_hash

def EvidenceRecord_reference_id(self) -> str:
        return self.evidence_id

def EvidenceRecord_obligation_links(self) -> tuple[str, ...]:
        return self.obligation_ids

def EvidenceRecord_evidence_scope(self) -> EvidenceScope | None:
        return self.scope

def EvidenceRecord_is_capture_marker(self) -> bool:
        kind = self.kind.lower().replace("-", "_")
        return self.capture_complete is not None or kind in {
            "capture",
            "capture_marker",
            "capture_receipt",
            "complete_capture",
            "complete_capture_receipt",
        }

def EvidenceRecord_is_complete_capture(self) -> bool:
        return self.is_capture_marker and self.capture_complete is True

def EvidenceRecord_capture_producer(self) -> str:
        return self.producer

def EvidenceRecord_to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "kind": self.kind,
            "content": _thaw(self.content),
            "binding_hash": self.binding_hash,
            "scope_hash": self.scope_hash,
            "evidence_id": self.evidence_id,
            "producer": self.producer,
            "producer_version": self.producer_version,
            "obligation_ids": list(self.obligation_ids),
            "member_id": self.member_id,
            "capture_id": self.capture_id,
            "capture_complete": self.capture_complete,
            "admitted": self.admitted,
            "stale": self.stale,
            "cursor": _thaw(self.cursor),
            "details": _thaw(self.details),
            "multiplicity": self.multiplicity,
            "content_hash": self.content_hash,
            "evidence_hash": self.evidence_hash,
        }
        if self.scope is not None:
            result["scope"] = self.scope.to_dict()
        return result

def EvidenceRecord_from_dict(cls, data: Mapping[str, Any]) -> "EvidenceRecord":
        return cls(
            kind=data["kind"],
            content=data.get("content", data.get("payload")),
            binding_hash=str(data.get("binding_hash", "")),
            scope_hash=str(data.get("scope_hash", "")),
            evidence_id=str(data.get("evidence_id", data.get("reference_id", ""))),
            producer=str(data.get("producer", data.get("provider", ""))),
            producer_version=str(data.get("producer_version", data.get("provider_version", ""))),
            obligation_ids=data.get("obligation_ids", data.get("links", ())),
            member_id=data.get("member_id", data.get("event_id", data.get("item_id"))),
            capture_id=str(data.get("capture_id", "")),
            capture_complete=data.get("capture_complete", data.get("complete_capture")),
            admitted=bool(data.get("admitted", True)),
            stale=bool(data.get("stale", False)),
            cursor=data.get("cursor"),
            details=data.get("details"),
            multiplicity=int(data.get("multiplicity", 1)),
            scope=data.get("scope", data.get("evidence_scope")),
            evidence_hash=str(data.get("evidence_hash", data.get("content_hash", ""))),
        )

def Diagnostic___init__(
        self,
        code: str,
        message: str = "",
        severity: DiagnosticSeverity | str = DiagnosticSeverity.ERROR,
        obligation_id: str = "",
        evidence_ids: Iterable[str] = (),
        cause: str = "",
        repair_frontier: Iterable[str] = (),
        details: Any = None,
        diagnostic_hash: str = "",
        *,
        causal_occurrence: str = "",
        frontier: Iterable[str] = (),
    ) -> None:
        actual_cause = _choose_alias(cause, (causal_occurrence,), "cause") or str(code)
        actual_frontier = _choose_alias(repair_frontier, (frontier,), "repair_frontier")
        actual_severity = _enum_value(severity, DiagnosticSeverity, "severity")
        frozen_details = _freeze(details) if details is not None else None
        payload = {
            "schema_version": DIAGNOSTIC_SCHEMA_VERSION,
            "code": _text(code, "code", allow_empty=False),
            "message": _text(message or code, "message", allow_empty=False),
            "severity": actual_severity.value,
            "obligation_id": _text(obligation_id, "obligation_id"),
            "evidence_ids": list(_as_tuple(evidence_ids, "evidence_ids")),
            "cause": _text(actual_cause, "cause", allow_empty=False),
            "repair_frontier": list(_as_tuple(actual_frontier, "repair_frontier")),
            "details": _thaw(frozen_details),
        }
        expected_hash = hash_canonical(payload)
        if diagnostic_hash and diagnostic_hash != expected_hash:
            raise ValueError("Diagnostic diagnostic_hash mismatch")
        object.__setattr__(self, "code", payload["code"])
        object.__setattr__(self, "message", payload["message"])
        object.__setattr__(self, "severity", actual_severity)
        object.__setattr__(self, "obligation_id", payload["obligation_id"])
        object.__setattr__(self, "evidence_ids", tuple(payload["evidence_ids"]))
        object.__setattr__(self, "cause", payload["cause"])
        object.__setattr__(self, "repair_frontier", tuple(payload["repair_frontier"]))
        object.__setattr__(self, "details", frozen_details)
        object.__setattr__(self, "diagnostic_hash", expected_hash)

def Diagnostic_causal_occurrence(self) -> str:
        return self.cause

def Diagnostic_frontier(self) -> tuple[str, ...]:
        return self.repair_frontier

def Diagnostic_hash(self) -> str:
        return self.diagnostic_hash

def Diagnostic_to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": DIAGNOSTIC_SCHEMA_VERSION,
            "code": self.code,
            "message": self.message,
            "severity": self.severity.value,
            "obligation_id": self.obligation_id,
            "evidence_ids": list(self.evidence_ids),
            "cause": self.cause,
            "causal_occurrence": self.cause,
            "repair_frontier": list(self.repair_frontier),
            "details": _thaw(self.details),
            "diagnostic_hash": self.diagnostic_hash,
        }

def Diagnostic_from_dict(cls, data: Mapping[str, Any]) -> "Diagnostic":
        return cls(
            code=str(data["code"]),
            message=str(data.get("message", data["code"])),
            severity=str(data.get("severity", "error")),
            obligation_id=str(data.get("obligation_id", "")),
            evidence_ids=data.get("evidence_ids", ()),
            cause=str(data.get("cause", data.get("causal_occurrence", data["code"]))),
            repair_frontier=data.get("repair_frontier", data.get("frontier", ())),
            details=data.get("details"),
            diagnostic_hash=str(data.get("diagnostic_hash", "")),
        )
