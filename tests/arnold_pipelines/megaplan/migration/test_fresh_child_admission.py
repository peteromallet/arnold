"""Tests for independent fresh-child admission.

These fakes model owner boundaries only; they are not production stores.  The
important assertions are that the request is a new identity, all authority
records are durable before owner handoff, and a crash-safe replay never
creates another WBC reservation or Custody lease.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from arnold.workflow.attempt_ledger_store import GlobalEffectReservation
from arnold_pipelines.megaplan.custody.contracts import CustodyLease
from arnold_pipelines.megaplan.migration.occurrence_child_migration import (
    ChildAuthority,
    WbcReservation,
)
from arnold_pipelines.megaplan.migration.fresh_child_admission import (
    FreshChildAdmission,
    FreshChildConflict,
    FreshChildRequest,
    FreshChildIndeterminate,
)
from arnold_pipelines.run_authority.contracts import (
    CapabilityGrant,
    Claim,
    CoordinatorFence,
    Decision,
    EvidenceEnvelope,
    IdempotencyKey,
    SubjectAttempt,
)


@dataclass(frozen=True)
class _View:
    records: tuple[Any, ...]
    cursor: int


@dataclass(frozen=True)
class _Append:
    record: Any
    cursor: int


class _Journal:
    def __init__(self) -> None:
        self.records: list[Any] = []
        self.calls = 0
        self.fail_after_append = False

    def read_view(self, run_id: str, revision: str) -> _View:
        return _View(tuple(self.records), len(self.records))

    def compare_and_append(
        self,
        run_id: str,
        revision: str,
        expected_cursor: int,
        record: Any,
        *,
        idempotency_key: str | None = None,
        glek: str | None = None,
    ) -> _Append:
        self.calls += 1
        key = idempotency_key or getattr(record, "idempotency_key", None) or record.to_json()
        for index, existing in enumerate(self.records, start=1):
            existing_key = getattr(existing, "idempotency_key", None) or {
                "evidence": "evidence",
                "coordinator_fence": "fence",
                "capability_grant": "grant",
                "subject_attempt": "attempt",
            }.get(getattr(existing, "contract_type", ""), "")
            # Non-payload records are only addressed by their generated IDs in
            # this fake; the production journal persists the supplied key.
            if existing_key == key or (getattr(existing, "to_json", lambda: "")() == record.to_json()):
                return _Append(existing, index)
        if expected_cursor != len(self.records):
            raise RuntimeError("stale cursor")
        self.records.append(record)
        result = _Append(record, len(self.records))
        if self.fail_after_append:
            self.fail_after_append = False
            raise RuntimeError("ack lost after durable append")
        return result


class _Wbc:
    def __init__(self) -> None:
        self.reservations: dict[tuple[str, str], WbcReservation] = {}
        self.calls = 0

    def read_reservation(self, attempt_id: str, glek: str) -> WbcReservation | None:
        return self.reservations.get((attempt_id, glek))

    def reserve_child(self, *, attempt_id: str, effect_identity: Any, migration_idempotency_key: str) -> WbcReservation:
        self.calls += 1
        reservation = GlobalEffectReservation(
            attempt_id=attempt_id,
            effect_identity=effect_identity,
            global_logical_effect_key=effect_identity.global_logical_effect_key,
            first_reserved_ns=1,
            reservation_count=1,
            is_new=True,
        )
        result = WbcReservation(attempt_id, reservation)
        self.reservations[(attempt_id, result.glek)] = result
        return result


class _Custody:
    def __init__(self) -> None:
        self.leases: dict[str, CustodyLease] = {}
        self.calls = 0

    def read_lease(self, lease_id: str) -> CustodyLease | None:
        return self.leases.get(lease_id)

    def acquire_child(self, *, lease_id: str, occurrence: Any, authority: ChildAuthority, wbc: WbcReservation, idempotency_key: str) -> CustodyLease:
        self.calls += 1
        lease = CustodyLease(
            lease_id=lease_id,
            occurrence_key=occurrence,
            owner_host="test-host",
            owner_pid="1",
            owner_boot_id="boot",
            run_authority_grant_id=authority.grant.grant_id,
            coordinator_fence_token=authority.fence.token,
            wbc_attempt_reference=wbc.attempt_id,
            custody_epoch=1,
            acquired_at="2026-08-05T00:00:00Z",
            expires_at="2026-08-05T01:00:00Z",
            idempotency_key=idempotency_key,
        )
        self.leases[lease_id] = lease
        return lease


def _request() -> FreshChildRequest:
    return FreshChildRequest(
        run_id="critique-fresh-child-001",
        run_revision="commit-child-001",
        coordinator_attempt_id="coord-child-001",
        subject_id="critique-ledger",
        subject_attempt_id="attempt-child-001",
        child_selector={"profile": "partnered-5-glm", "phase": "execute"},
        environment="cloud",
        session="critique-ledger-accountability-v3-r6-child-20260805",
        chain="cl2-wbc-backed-ledger",
        phase="execute",
        task="critique-ledger",
        normalized_failure_kind="stalled",
        blocker_or_phase_result_hash="sha256:blocker-child",
        chain_identity="critique-ledger-child-001",
        plan_artifact_digest="sha256:plan-child",
        runtime_binding_digest="sha256:runtime-child",
        source_revision="commit-child-001",
        approval_receipt="sha256:operator-approval",
        approval_actor="operator",
        parent_occurrence_digest="sha256:legacy-r6-lineage-only",
    )


def _admission(journal: _Journal | None = None) -> tuple[FreshChildAdmission, _Journal, _Wbc, _Custody]:
    j = journal or _Journal()
    wbc = _Wbc()
    custody = _Custody()
    return FreshChildAdmission(journal=j, wbc=wbc, custody=custody), j, wbc, custody


def test_fresh_child_admission_binds_all_three_owners_before_first_phase() -> None:
    admission, journal, wbc, custody = _admission()
    receipt = admission.admit(_request())
    receipt.assert_ready()
    assert len(journal.records) == 8
    assert isinstance(journal.records[0], EvidenceEnvelope)
    assert isinstance(journal.records[1], CoordinatorFence)
    assert isinstance(journal.records[2], CapabilityGrant)
    assert isinstance(journal.records[3], SubjectAttempt)
    assert isinstance(journal.records[4], IdempotencyKey)
    assert isinstance(journal.records[5], Claim)
    assert isinstance(journal.records[6], IdempotencyKey)
    assert isinstance(journal.records[7], Decision)
    assert receipt.authority.decision is not None
    assert receipt.authority.decision.outcome == "accepted"
    assert receipt.wbc.attempt_id == "attempt-child-001"
    assert receipt.custody.custody_epoch == 1
    assert wbc.calls == 1
    assert custody.calls == 1


def test_replay_after_ack_loss_is_idempotent_and_does_not_reallocate() -> None:
    journal = _Journal()
    journal.fail_after_append = True
    admission, journal, wbc, custody = _admission(journal)
    with pytest.raises(FreshChildIndeterminate):
        admission.admit(_request())
    receipt = admission.admit(_request())
    receipt.assert_ready()
    assert len(journal.records) == 8
    assert wbc.calls == 1
    assert custody.calls == 1


def test_occupied_run_id_with_divergent_content_is_rejected() -> None:
    journal = _Journal()
    journal.records.append(
        EvidenceEnvelope(
            evidence_id="different",
            run_id="critique-fresh-child-001",
            run_revision="commit-child-001",
            evidence_type="other",
            source="other",
            payload={"request": {"request_digest": "different"}},
        )
    )
    admission, _, _, _ = _admission(journal)
    with pytest.raises(FreshChildConflict):
        admission.admit(_request())
