from __future__ import annotations

from pathlib import Path
from dataclasses import replace

from arnold.runtime.durable_ops import FileBackedDurableOpsStore, OperationState
from arnold_pipelines.megaplan.cloud.worker_dispatch import (
    LaunchResult,
    ManagedCommandResult,
    dispatch_with_admission,
    require_production_worker_dispatch_runtime,
)
from arnold_pipelines.megaplan.incident.ledger import IncidentLedger
from tests.cloud.dispatch_test_helpers import request


def test_worker_physical_door_is_once_and_operation_store_is_authority(tmp_path: Path) -> None:
    ledger = IncidentLedger(tmp_path)
    req = request(tmp_path, logical_dispatch_id="canonical-worker", ledger=ledger)
    receipt = require_production_worker_dispatch_runtime(req)
    calls: list[int] = []

    def launch(_context):
        calls.append(1)
        identity = {
            "host": "worker-host",
            "pid": 123,
            "boot_id": "boot",
            "process_start_identity": "start-123",
        }
        return LaunchResult(True, ManagedCommandResult(0, identity), identity)

    first = dispatch_with_admission(req, launch, gate=lambda _request: receipt, ledger=ledger)
    replay = dispatch_with_admission(req, launch, gate=lambda _request: receipt, ledger=ledger)
    store = FileBackedDurableOpsStore(tmp_path / "ops")

    assert first.kind == "success"
    assert replay.kind == "success"
    assert calls == [1]
    run = store.load_operation_run(receipt.operation_id)
    assert run.state is OperationState.RUNNING
    assert len(store.list_typed_resources(receipt.operation_id)) == 1
    assert ledger.read_nbf_events() == []


def test_worker_missing_exact_process_identity_stays_unresolved(tmp_path: Path) -> None:
    ledger = IncidentLedger(tmp_path)
    req = request(tmp_path, logical_dispatch_id="canonical-unknown", ledger=ledger)
    receipt = replace(require_production_worker_dispatch_runtime(req), production_intent=True)

    def launch(_context):
        identity = {"host": "worker-host", "pid": 123, "boot_id": "boot"}
        return LaunchResult(True, ManagedCommandResult(0, identity), identity)

    result = dispatch_with_admission(req, launch, gate=lambda _request: receipt, ledger=ledger)
    assert result.kind == "unresolved_launch"
    assert FileBackedDurableOpsStore(tmp_path / "ops").load_operation_run(receipt.operation_id).state is OperationState.PENDING
    assert ledger.read_nbf_events() == []
