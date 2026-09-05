from __future__ import annotations

from pathlib import Path

from arnold.runtime.durable_ops import FileBackedDurableOpsStore, OperationState
from arnold_pipelines.megaplan.cloud.worker_dispatch import (
    AdmissionRefusal,
    WorkerAdmissionReceipt,
    LaunchResult,
    dispatch_with_admission,
    require_production_worker_dispatch_runtime,
)
from arnold_pipelines.megaplan.orchestration.phase_result import DispatchOutcome, SchedulingCondition
from arnold_pipelines.megaplan.incident.ledger import IncidentLedger

from tests.cloud.dispatch_test_helpers import request


WORKER = {"host": "host", "pid": 123, "boot_id": "boot"}


def test_cooldown_retries_without_launch_and_then_admits(tmp_path: Path) -> None:
    waits: list[float] = []
    launches: list[int] = []
    now = [0.0]
    cooldowns = iter((2.0, 0.0))

    def clock() -> float:
        return now[0]

    def sleep(seconds: float) -> None:
        waits.append(seconds)
        now[0] += seconds

    def gate(req):
        from arnold_pipelines.megaplan.cloud.worker_dispatch import require_production_worker_dispatch_runtime
        return require_production_worker_dispatch_runtime(
            req,
            # consume the injected cooldown deterministically per attempt
        )

    original = request(tmp_path, cooldown_reader=lambda *_: next(cooldowns))
    from arnold_pipelines.megaplan.workers import WorkerResult
    typed_worker = WorkerResult(
        payload={}, raw_output="", duration_ms=1, cost_usd=0.0,
        worker_identity=WORKER,
    )
    result = dispatch_with_admission(
        original,
        lambda _context: (launches.append(1), LaunchResult(True, typed_worker))[1],
        gate=gate,
        clock=clock,
        sleeper=sleep,
        deadline_s=10,
    )
    assert isinstance(result, DispatchOutcome)
    assert result.kind == "success"
    assert waits == [2.0]
    assert len(launches) == 1


def test_scheduling_expiry_returns_condition_without_launch(tmp_path: Path) -> None:
    launches: list[int] = []
    result = dispatch_with_admission(
        request(tmp_path, cooldown_reader=lambda *_: 5.0),
        lambda _context: launches.append(1),
        clock=lambda: 0.0,
        sleeper=lambda _seconds: None,
        deadline_s=1.0,
    )
    assert isinstance(result, SchedulingCondition)
    assert result.reason == "memory_cooldown"
    assert launches == []


def test_gate_refusal_prevents_final_launch(tmp_path: Path) -> None:
    launches: list[int] = []
    result = dispatch_with_admission(
        request(tmp_path, seed_identity=""),
        lambda _context: launches.append(1),
    )
    assert isinstance(result, AdmissionRefusal)
    assert launches == []


def test_gate_refusal_is_the_only_pre_entry_suppression(tmp_path: Path) -> None:
    launches: list[int] = []

    result = dispatch_with_admission(
        request(tmp_path),
        lambda _context: launches.append(1),
        gate=lambda _request: AdmissionRefusal(
            code="preflight_rejected",
            reason="observed capacity is unknown",
            plan_id="plan",
            phase="run",
            logical_dispatch_id="logical",
            admission_attempt=1,
        ),
    )
    assert isinstance(result, AdmissionRefusal)
    assert result.code == "preflight_rejected"
    assert launches == []


def test_explicit_worker_terminal_outcome_preserves_kind_and_identity(tmp_path: Path) -> None:
    from arnold_pipelines.megaplan.workers import WorkerResult

    worker = WORKER
    terminal = {
        "kind": "ordinary_terminal_failure",
        "launch_state": "accepted",
        "worker_identity": worker,
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:00:01+00:00",
        "terminal_failure": {"error": "typed failure"},
    }
    value = WorkerResult(
        payload={"dispatch_outcome": terminal},
        raw_output="",
        duration_ms=1,
        cost_usd=0.0,
    )
    result = dispatch_with_admission(request(tmp_path), lambda _context: LaunchResult(True, value))
    assert isinstance(result, DispatchOutcome)
    assert result.kind == "ordinary_terminal_failure"
    assert result.terminal_failure == {"error": "typed failure"}
    assert result.worker_identity == worker


def test_failure_shaped_worker_result_never_projects_as_success(tmp_path: Path) -> None:
    from arnold_pipelines.megaplan.workers import WorkerResult

    ledger = IncidentLedger(tmp_path)
    result = dispatch_with_admission(
        request(tmp_path, ledger=ledger),
        lambda _context: LaunchResult(
            True,
            WorkerResult(payload={"error": "worker failed"}, raw_output="", duration_ms=1, cost_usd=0.0),
        ),
        ledger=ledger,
    )
    assert isinstance(result, DispatchOutcome)
    assert result.kind == "unresolved_launch"
    assert not ledger.projection()["terminals"]


def test_launch_store_acceptance_does_not_depend_on_incident_ledger(tmp_path: Path) -> None:
    ledger = IncidentLedger(tmp_path)
    from arnold_pipelines.megaplan.workers import WorkerResult
    result = dispatch_with_admission(
        request(tmp_path, ledger=ledger),
        lambda _context: LaunchResult(
            True,
            WorkerResult(
                payload={}, raw_output="", duration_ms=1, cost_usd=0.0,
                worker_identity=WORKER,
            ),
            WORKER,
        ),
        ledger=ledger,
    )
    assert isinstance(result, DispatchOutcome)
    assert result.kind == "success"
    assert FileBackedDurableOpsStore(tmp_path / "ops").load_operation_run("logical").state is OperationState.RUNNING
    assert ledger.read_nbf_events() == []


def test_pre_entry_release_requires_receipt_bound_physical_operation_evidence(tmp_path: Path) -> None:
    ledger = IncidentLedger(tmp_path)
    request_value = request(tmp_path, ledger=ledger)
    receipt = require_production_worker_dispatch_runtime(request_value)
    assert isinstance(receipt, WorkerAdmissionReceipt)

    def launch(_context):
        raise AssertionError("pre-entry proof must not invoke the launch closure")

    def pre_entry(_context):
        marker_id = ledger.read_nbf_events()[-1]["payload"]["event_id"]
        return LaunchResult(False, {"evidence_event_ids": (marker_id,)})

    launch.pre_entry = pre_entry
    result = dispatch_with_admission(
        request_value,
        launch,
        ledger=ledger,
        gate=lambda _request: receipt,
    )
    assert isinstance(result, DispatchOutcome)
    assert result.kind == "unresolved_launch"
    assert not ledger.projection()["terminals"]


def test_identical_retry_never_relaunches_unresolved_or_accepted_state(tmp_path: Path) -> None:
    from arnold_pipelines.megaplan.workers import WorkerResult

    ledger = IncidentLedger(tmp_path)
    launches: list[int] = []

    def launch(_context):
        launches.append(1)
        return WorkerResult(
            payload={}, raw_output="", duration_ms=1, cost_usd=0.0,
            worker_identity=WORKER,
        )

    first = dispatch_with_admission(request(tmp_path, ledger=ledger), launch, ledger=ledger)
    second = dispatch_with_admission(request(tmp_path, ledger=ledger), launch, ledger=ledger)
    assert isinstance(first, DispatchOutcome)
    assert first.kind == "success"
    assert isinstance(second, DispatchOutcome)
    assert second.kind == "success"
    assert launches == [1]
