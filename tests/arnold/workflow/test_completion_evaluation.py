"""Focused C2 completion-evaluation tests.

These tests exercise only the neutral shadow evaluator.  They intentionally
bind every positive evidence item to the same immutable scope as the binding;
matching display content without that identity is not admissible.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from arnold.workflow.completion.binding import bind
from arnold.workflow.completion.evidence import EvidenceScope, EvidenceWindow, ScalarCursor
from arnold.workflow.completion.evaluation import (
    BlockedProof,
    CompletionVerdict,
    Diagnostic,
    EvidenceRecord,
    EvaluationStatus,
    ObligationResult,
    TerminalPolicy,
    WaiverProof,
    deduplicate_evidence,
    evaluate_completion,
    propagate_waiver_taint,
)
from arnold.workflow.completion.spec import Obligation, ProofMode, SubjectKind, make_completion_spec


def _scope(**changes: object) -> EvidenceScope:
    values: dict[str, object] = {
        "subject_id": "subject:1",
        "occurrence_id": "occurrence:1",
        "attempt_id": "attempt:1",
        "generation": 1,
        "source_lock": "source:v1",
        "runtime_lock": "runtime:v1",
        "dependency_lock": "deps:v1",
        "store_id": "store:primary",
        "store_incarnation": "incarnation:1",
        "restore_id": "restore:1",
        "restore_generation": 1,
        "evidence_window": EvidenceWindow(ScalarCursor(10), ScalarCursor(20)),
        "custody": {"run_id": "run:1", "receipt": "sha256:" + "a" * 64},
        "authority_fence": {"token": 4, "epoch": 2},
        "epoch": 2,
        "wbc_version": "wbc:v1",
        "admitted_child_set_digest": "sha256:" + "b" * 64,
    }
    values.update(changes)
    return EvidenceScope(**values)


def _setup(*obligations: Obligation):
    spec = make_completion_spec(
        "completion:1",
        SubjectKind.STEP,
        obligations=tuple(obligations),
        canonical_name="shadow-test",
    )
    scope = _scope()
    binding = bind(spec, "subject:1", evidence_scope=scope)
    return spec, scope, binding


def _evidence(
    binding,
    scope,
    evidence_id: str,
    kind: str,
    content: object,
    **kwargs: object,
) -> EvidenceRecord:
    return EvidenceRecord(
        kind=kind,
        content=content,
        evidence_id=evidence_id,
        binding_hash=binding.binding_hash,
        scope=scope,
        **kwargs,
    )


def _capture(binding, scope, *, complete: bool = True, producer: str = "capture-scanner") -> EvidenceRecord:
    return _evidence(
        binding,
        scope,
        "capture:1",
        "capture",
        {"complete": complete},
        producer=producer,
        capture_complete=complete,
    )


def test_hashed_records_are_immutable_and_round_trip() -> None:
    obligation = Obligation("present", ProofMode.PRESENCE, "a receipt", ("receipt",))
    spec, scope, binding = _setup(obligation)
    record = _evidence(binding, scope, "receipt:1", "receipt", {"ok": True})
    assert record.content_hash == record.evidence_hash == record.hash
    assert record.from_dict(record.to_dict()) == record
    with pytest.raises(FrozenInstanceError):
        record.evidence_id = "other"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        record.content = {"ok": False}  # type: ignore[misc]
    with pytest.raises(ValueError, match="hash mismatch"):
        EvidenceRecord.from_dict({**record.to_dict(), "content": {"ok": False}})

    verdict = evaluate_completion(spec, binding, (record,))
    assert verdict.accepted
    assert verdict.reuse_identities == ((spec.spec_hash, "present", binding.binding_hash),)
    assert CompletionVerdict.from_dict(verdict.to_dict()) == verdict


def test_presence_uses_only_exactly_admitted_scope() -> None:
    obligation = Obligation("present", ProofMode.PRESENCE, "a receipt", ("receipt",))
    spec, scope, binding = _setup(obligation)
    outside = _scope(store_incarnation="incarnation:2")
    record = _evidence(binding, outside, "receipt:outside", "receipt", {"ok": True})
    verdict = evaluate_completion(spec, binding, (record,))
    assert not verdict.accepted
    assert verdict.obligation_results[0].status is EvaluationStatus.UNSATISFIED
    assert any(item.code == "EVIDENCE_OUT_OF_SCOPE" for item in verdict.diagnostics)


def test_absence_requires_named_complete_capture() -> None:
    obligation = Obligation("absent", ProofMode.COMPLETE_CAPTURE_ABSENCE, "no mutation", ("mutation",))
    spec, scope, binding = _setup(obligation)
    incomplete = evaluate_completion(spec, binding, (_capture(binding, scope, complete=False),))
    assert incomplete.status is EvaluationStatus.UNKNOWN
    assert incomplete.obligation_results[0].unknown
    assert any(item.code == "INCOMPLETE_CAPTURE" for item in incomplete.diagnostics)

    complete = evaluate_completion(spec, binding, (_capture(binding, scope),))
    assert complete.accepted
    present = evaluate_completion(
        spec,
        binding,
        (_capture(binding, scope), _evidence(binding, scope, "mutation:1", "mutation", {"id": 1})),
    )
    assert not present.accepted
    assert any(item.code == "UNEXPECTED_EVIDENCE" for item in present.diagnostics)


def test_set_equality_requires_complete_capture_and_exact_membership() -> None:
    obligation = Obligation("members", ProofMode.SET_EQUALITY, "all members", ("member",))
    spec, scope, binding = _setup(obligation)
    members = (
        _capture(binding, scope),
        _evidence(binding, scope, "member:1", "member", {"value": "one"}, member_id="1"),
        _evidence(binding, scope, "member:2", "member", {"value": "two"}, member_id="2"),
    )
    exact = evaluate_completion(spec, binding, members, expected_ids=("2", "1"))
    assert exact.accepted
    assert exact.obligation_results[0].expected_ids == ("2", "1")

    missing = evaluate_completion(spec, binding, members[:2], expected_ids=("1", "2"))
    assert missing.status is EvaluationStatus.UNSATISFIED
    assert any(item.code == "SET_MISMATCH" for item in missing.diagnostics)

    unknown = evaluate_completion(spec, binding, members[1:], expected_ids=("1", "2"))
    assert unknown.status is EvaluationStatus.UNKNOWN


def test_aggregate_deduplicates_content_and_does_not_fake_multiplicity() -> None:
    aggregate_obligation = Obligation("total", ProofMode.AGGREGATE, "sum values", ("value",))
    spec, scope, binding = _setup(aggregate_obligation)
    first = _evidence(binding, scope, "value:1", "value", {"value": 2})
    duplicate = _evidence(binding, scope, "value:1-copy", "value", {"value": 2})
    second = _evidence(binding, scope, "value:2", "value", {"value": 3})
    verdict = evaluate_completion(
        spec,
        binding,
        (first, duplicate, second),
        aggregate={"total": {"operator": "sum", "expected": 5}},
    )
    assert verdict.accepted
    assert verdict.obligation_results[0].observed_count == 2

    multiplicity = evaluate_completion(
        spec,
        binding,
        (first, duplicate),
        aggregate={"total": {"operator": "sum", "expected": 4}},
        required_multiplicity={"total": 2},
    )
    assert not multiplicity.accepted
    assert multiplicity.obligation_results[0].observed_count == 1
    assert any(item.code == "MULTIPLICITY_UNSATISFIED" for item in multiplicity.diagnostics)


def test_one_content_item_can_support_two_explicit_obligations() -> None:
    first = Obligation("first", ProofMode.PRESENCE, "first use", ("receipt",))
    second = Obligation("second", ProofMode.PRESENCE, "second use", ("receipt",))
    spec, scope, binding = _setup(first, second)
    shared = _evidence(binding, scope, "receipt:shared", "receipt", {"ok": True}, obligation_ids=("first",))
    linked = _evidence(binding, scope, "receipt:shared-copy", "receipt", {"ok": True}, obligation_ids=("second",))
    admitted = deduplicate_evidence((shared, linked))
    assert len(admitted) == 1
    assert admitted[0].obligation_ids == ("first", "second")
    verdict = evaluate_completion(spec, binding, (shared, linked))
    assert verdict.accepted
    assert all(result.evidence_ids == ("receipt:shared",) for result in verdict.results)


def test_legacy_binding_and_exact_spec_reuse_fail_closed_with_causal_diagnostics() -> None:
    obligation = Obligation("present", ProofMode.PRESENCE, "a receipt", ("receipt",))
    spec, _scope_record, binding = _setup(obligation)
    # Rebuild a C1 binding deliberately; its two strings are not cursor data.
    legacy = bind(spec, "subject:1", "old-start", "old-end")
    record = EvidenceRecord("receipt", {"ok": True}, binding_hash=legacy.binding_hash, evidence_id="receipt:1")
    verdict = evaluate_completion(spec, legacy, (record,))
    assert verdict.status is EvaluationStatus.UNKNOWN
    assert any(item.cause == "legacy-binding-unknown" for item in verdict.diagnostics)

    other_obligation = Obligation("other", ProofMode.PRESENCE, "other receipt", ("receipt",))
    other_spec, scope, other_binding = _setup(other_obligation)
    mismatch = evaluate_completion(other_spec, binding, (_evidence(binding, scope, "receipt:1", "receipt", True),))
    assert mismatch.status is EvaluationStatus.UNKNOWN
    assert any(item.code == "REUSE_IDENTITY_MISMATCH" for item in mismatch.diagnostics)


def test_candidate_selection_precedes_static_applicability() -> None:
    obligation = Obligation("present", ProofMode.PRESENCE, "a receipt", ("receipt",))
    spec, scope, binding = _setup(obligation)
    record = _evidence(binding, scope, "receipt:1", "receipt", {"ok": True})

    ambiguous = evaluate_completion(
        spec,
        binding,
        (record,),
        candidate_outcome="success",
        declared_candidates=("success", "blocked"),
    )
    assert ambiguous.status is EvaluationStatus.UNKNOWN
    assert any(item.code == "CANDIDATE_SELECTION_INVALID" for item in ambiguous.diagnostics)

    circular = evaluate_completion(
        spec,
        binding,
        (record,),
        candidate_outcome="success",
        applicability={"success": {"depends_on": ("evidence",), "obligations": ("present",)}},
    )
    assert circular.status is EvaluationStatus.UNKNOWN
    assert any(item.code == "CIRCULAR_APPLICABILITY" for item in circular.diagnostics)


def test_exceptional_proofs_terminal_policy_taint_and_independence_are_typed() -> None:
    obligation = Obligation("present", ProofMode.PRESENCE, "a receipt", ("receipt",))
    spec, scope, binding = _setup(obligation)
    record = _evidence(binding, scope, "receipt:1", "receipt", {"ok": True}, producer="primary")

    blocked = BlockedProof(
        blocker_id="blocker:1",
        causal_evidence_ids=("receipt:1",),
        authority_coordinates={"run": "run:1"},
        custody_coordinates={"action": "retry"},
        next_admission="after-recovery",
        recovery_disposition="retry",
        binding_hash=binding.binding_hash,
    )
    blocked_verdict = evaluate_completion(spec, binding, (record,), candidate_outcome="blocked", blocked_proof=blocked)
    assert blocked_verdict.status is EvaluationStatus.BLOCKED
    assert not blocked_verdict.accepted
    assert blocked_verdict.from_dict(blocked_verdict.to_dict()) == blocked_verdict
    waiver = WaiverProof(
        authority_provenance={"authority": "run-authority"},
        scope={"scope_hash": scope.scope_hash},
        reason="operator-approved exception",
        evidence_ids=("receipt:1",),
        expiry="2026-12-31T00:00:00Z",
        taint=("deep-child",),
        binding_hash=binding.binding_hash,
    )
    waived = evaluate_completion(spec, binding, (record,), candidate_outcome="waived", waiver_proof=waiver)
    assert waived.status is EvaluationStatus.WAIVED
    assert waived.accepted
    assert waived.taint == frozenset({"deep-child", "waived"})
    assert waived.from_dict(waived.to_dict()) == waived
    assert "deep-child" in propagate_waiver_taint({"children": [{"taint": ["deep-child"]}]})

    policy = TerminalPolicy(
        permitted_outcomes=("suspended",),
        evidence_ids=("receipt:1",),
        admitted=True,
        independent=True,
        producer="policy-authority",
        trust_domain="policy-domain",
    )
    suspended = evaluate_completion(spec, binding, (record,), candidate_outcome="suspended", terminal_policy=policy)
    assert suspended.status is EvaluationStatus.SUSPENDED
    assert suspended.terminal
    assert not evaluate_completion(spec, binding, (record,), candidate_outcome="suspended").terminal

    independent = evaluate_completion(
        spec,
        binding,
        (record,),
        verifier_provenance={
            "implementation_provenance": "shadow-implementation",
            "producer_identity": "shadow-producer",
            "trust_domain": "shadow-domain",
            "primary_evidence_access": True,
            "primary_implementation_provenance": "primary-implementation",
            "primary_producer_identity": "primary",
            "primary_trust_domain": "primary-domain",
        },
        require_verifier_independence=True,
    )
    assert independent.independent is True

    relabeled = evaluate_completion(
        spec,
        binding,
        (record,),
        verifier_provenance={
            "implementation_provenance": "primary-implementation",
            "producer_identity": "shadow-producer",
            "trust_domain": "shadow-domain",
            "primary_evidence_access": True,
            "primary_implementation_provenance": "primary-implementation",
            "primary_producer_identity": "primary",
            "primary_trust_domain": "primary-domain",
        },
        require_verifier_independence=True,
    )
    assert relabeled.independent is False; assert any(item.code == "VERIFIER_NOT_INDEPENDENT" for item in relabeled.diagnostics)
