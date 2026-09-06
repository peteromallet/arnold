"""Explicit admission and diagnostic helpers for completion evaluation.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from arnold.workflow.completion.binding import CompletionBinding
from arnold.workflow.completion.evidence import EvidenceScopeMismatch, scope_mismatches
from arnold.workflow.completion.spec import Obligation, ProofMode
from .evaluation import (Diagnostic, DiagnosticSeverity, EvidenceRecord, EvaluationStatus, _as_tuple, _coerce_binding, _coerce_evidence, _coerce_spec, _text, _thaw)

def _applicable_obligations(
    selection: CandidateSelection,
    applicability: Any,
    obligations: Sequence[Obligation],
) -> tuple[tuple[Obligation, ...], Diagnostic | None]:
    """Resolve applicability only after candidate selection.

    Applicability is declarative.  Callables and references to evidence,
    results, or the selected candidate are rejected because they make the
    candidate/obligation decision circular or observer-dependent.
    """

    if applicability is None:
        return tuple(obligations), None
    if callable(applicability):
        return (), _diagnostic(
            "CIRCULAR_APPLICABILITY",
            "callable applicability could observe evaluation results",
            cause="circular-applicability",
            repair_frontier=(f"candidate:{selection.selected_candidate}:applicability",),
        )
    source = applicability
    if isinstance(source, Mapping) and selection.selected_candidate in source:
        source = source[selection.selected_candidate]
    if isinstance(source, Mapping):
        depends = source.get("depends_on", source.get("based_on", ()))
        dependency_names = {str(item).lower() for item in _as_tuple(depends, "depends_on")}
        if dependency_names & {
            "candidate",
            "selected_candidate",
            "outcome",
            "verdict",
            "evidence",
            "results",
            "obligation_results",
        }:
            return (), _diagnostic(
                "CIRCULAR_APPLICABILITY",
                "obligation applicability depends on candidate or evaluation results",
                cause="circular-applicability",
                repair_frontier=(f"candidate:{selection.selected_candidate}:applicability",),
            )
        source = source.get("obligations", source.get("applicable_obligations", source))
    if isinstance(source, bool):
        source = [item.obligation_id for item in obligations] if source else []
    if isinstance(source, str):
        source = (source,)
    if not isinstance(source, Iterable):
        return (), _diagnostic(
            "APPLICABILITY_INVALID",
            "applicability must be a static obligation-id collection",
            cause="invalid-applicability",
            repair_frontier=(f"candidate:{selection.selected_candidate}:applicability",),
        )
    names = {str(item) for item in source}
    applicable = tuple(item for item in obligations if item.obligation_id in names)
    unknown = names - {item.obligation_id for item in obligations}
    if unknown:
        return (), _diagnostic(
            "APPLICABILITY_UNKNOWN_OBLIGATION",
            "applicability names an obligation outside the declared spec",
            cause="unknown-applicability-obligation",
            repair_frontier=(f"candidate:{selection.selected_candidate}:applicability",),
            details={"unknown_obligations": sorted(unknown)},
        )
    return applicable, None

def _diagnostic(
    code: str,
    message: str,
    *,
    obligation_id: str = "",
    evidence_ids: Iterable[str] = (),
    cause: str | None = None,
    repair_frontier: Iterable[str] = (),
    details: Any = None,
    severity: DiagnosticSeverity | str = DiagnosticSeverity.ERROR,
) -> Diagnostic:
    return Diagnostic(
        code=code,
        message=message,
        severity=severity,
        obligation_id=obligation_id,
        evidence_ids=evidence_ids,
        cause=cause or code,
        repair_frontier=repair_frontier,
        details=details,
    )

def _deduplicate(records: Iterable[EvidenceRecord]) -> tuple[EvidenceRecord, ...]:
    """Deduplicate by content identity while retaining first-seen order.

    Obligation links are relationship metadata and are therefore unioned when
    duplicate references carry different explicit links.  No other content is
    merged, so duplicate receipts still contribute only one proof item.
    """

    selected: dict[str, EvidenceRecord] = {}
    for record in records:
        previous = selected.get(record.content_hash)
        if previous is None:
            selected[record.content_hash] = record
            continue
        links = tuple(dict.fromkeys(previous.obligation_ids + record.obligation_ids))
        if links != previous.obligation_ids:
            payload = previous.to_dict()
            payload["obligation_ids"] = list(links)
            selected[record.content_hash] = EvidenceRecord.from_dict(payload)
    return tuple(selected.values())

def _basic_admission(record: EvidenceRecord, binding: CompletionBinding) -> Diagnostic | None:
    if not record.admitted:
        return _diagnostic("EVIDENCE_NOT_ADMITTED", f"evidence {record.evidence_id} is not admitted", evidence_ids=(record.evidence_id,), cause="evidence-not-admitted", repair_frontier=(f"evidence:{record.evidence_id}",))
    if record.stale:
        return _diagnostic("STALE_EVIDENCE", f"evidence {record.evidence_id} is stale", evidence_ids=(record.evidence_id,), cause="stale-evidence", repair_frontier=(f"evidence:{record.evidence_id}",))
    if record.binding_hash != binding.binding_hash:
        return _diagnostic("EVIDENCE_BINDING_MISMATCH", f"evidence {record.evidence_id} is bound to a different binding", evidence_ids=(record.evidence_id,), cause="binding-mismatch", repair_frontier=(f"binding:{binding.binding_hash}",))
    return None


def _scope_admission(record: EvidenceRecord, binding: CompletionBinding) -> Diagnostic | None:
    expected = binding.evidence_scope
    if expected is None:
        return _diagnostic("LEGACY_BINDING_UNKNOWN", "legacy C1 binding has no admissible C2 evidence scope", evidence_ids=(record.evidence_id,), cause="legacy-binding-unknown", repair_frontier=("binding:migrate",))
    if not record.scope_hash:
        return _diagnostic("EVIDENCE_SCOPE_MISSING", f"evidence {record.evidence_id} has no bound evidence scope", evidence_ids=(record.evidence_id,), cause="scope-missing", repair_frontier=(f"evidence:{record.evidence_id}",))
    if record.scope is not None:
        try:
            mismatches = scope_mismatches(expected, record.scope)
        except (TypeError, ValueError, EvidenceScopeMismatch) as exc:
            mismatches = (f"scope-invalid:{exc}",)
    else:
        mismatches = () if record.scope_hash == expected.scope_hash else ("scope_hash",)
    if record.scope_hash != expected.scope_hash:
        mismatches = tuple(dict.fromkeys((*mismatches, "scope_hash")))
    if mismatches:
        return _diagnostic("EVIDENCE_OUT_OF_SCOPE", f"evidence {record.evidence_id} is outside the pinned evidence scope", evidence_ids=(record.evidence_id,), cause="out-of-scope-evidence", repair_frontier=(f"scope:{expected.scope_hash}",), details={"mismatches": list(mismatches)})
    if record.cursor is not None and not expected.evidence_window.contains(record.cursor):
        return _diagnostic("EVIDENCE_CURSOR_OUT_OF_SCOPE", f"evidence {record.evidence_id} has a cursor outside the pinned window", evidence_ids=(record.evidence_id,), cause="cursor-out-of-scope", repair_frontier=(f"scope:{expected.scope_hash}",))
    return None


def _admit_records(binding: CompletionBinding, evidence: Iterable[EvidenceRecord | Mapping[str, Any]]) -> tuple[tuple[EvidenceRecord, ...], tuple[Diagnostic, ...]]:
    admitted: list[EvidenceRecord] = []
    diagnostics: list[Diagnostic] = []
    for index, raw in enumerate(evidence):
        try:
            record = _coerce_evidence(raw)
        except (TypeError, ValueError, KeyError) as exc:
            diagnostics.append(_diagnostic("INVALID_EVIDENCE", f"evidence item {index} is invalid: {exc}", cause="invalid-evidence", repair_frontier=(f"evidence:{index}",)))
            continue
        diagnostic = _basic_admission(record, binding) or _scope_admission(record, binding)
        if diagnostic is None:
            admitted.append(record)
        else:
            diagnostics.append(diagnostic)
    return _deduplicate(admitted), tuple(diagnostics)

def _capture_state(
    records: Sequence[EvidenceRecord],
    *,
    complete_capture: bool | None,
    capture_producer: str | None,
) -> tuple[bool | None, str, tuple[Diagnostic, ...]]:
    markers = tuple(record for record in records if record.is_capture_marker)
    explicit_producer = _text(capture_producer, "capture_producer")
    if complete_capture is not None and not isinstance(complete_capture, bool):
        raise TypeError("complete_capture must be bool or None")
    values = [record.capture_complete for record in markers if record.capture_complete is not None]
    values = list(dict.fromkeys(values))
    if complete_capture is not None:
        values.append(complete_capture)
        values = list(dict.fromkeys(values))
    if len(values) > 1:
        return (
            None,
            "",
            (
                _diagnostic(
                    "CAPTURE_COMPLETENESS_CONFLICT",
                    "capture evidence contains conflicting completeness declarations",
                    cause="capture-completeness-conflict",
                    repair_frontier=("capture:complete",),
                ),
            ),
        )
    if not values:
        # Presence and aggregate proofs do not need a capture marker.  The
        # absence/set evaluators issue their mode-specific unknown diagnostic
        # when they observe this ``None`` state.
        return None, "", ()
    actual_complete = values[0]
    producers = tuple(dict.fromkeys(record.capture_producer for record in markers if record.capture_producer))
    if explicit_producer:
        producers = tuple(dict.fromkeys((*producers, explicit_producer)))
    if actual_complete and not producers:
        return True, "", ()
    if len(producers) > 1:
        return (
            None,
            "",
            (
                _diagnostic(
                    "CAPTURE_PRODUCER_CONFLICT",
                    "capture evidence names more than one producer",
                    cause="capture-producer-conflict",
                    repair_frontier=("capture:producer",),
                    details={"producers": list(producers)},
                ),
            ),
        )
    if not actual_complete:
        return False, producers[0] if producers else "", ()
    return True, producers[0], ()

__all__ = ["_applicable_obligations", "_diagnostic", "_deduplicate", "_admit_records", "_capture_state"]
