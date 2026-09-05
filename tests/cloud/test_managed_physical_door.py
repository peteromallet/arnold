"""Managed physical door uses canonical operation authority."""

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


def test_managed_physical_door_is_once_and_has_no_ledger_launch_projection(tmp_path: Path) -> None:
    ledger = IncidentLedger(tmp_path)
    req = request(tmp_path, physical_door_id="cloud.babysitter.launch", ledger=ledger)
    receipt = replace(require_production_worker_dispatch_runtime(req), production_intent=True)
    calls: list[int] = []

    def launch(_context):
        calls.append(1)
        identity = {
            "host": "managed-host",
            "pid": 321,
            "boot_id": "managed-boot",
            "process_start_identity": "managed-start",
        }
        return LaunchResult(True, ManagedCommandResult(0, identity), identity)

    first = dispatch_with_admission(req, launch, ledger=ledger, gate=lambda _request: receipt)
    replay = dispatch_with_admission(req, launch, ledger=ledger, gate=lambda _request: receipt)
    store = FileBackedDurableOpsStore(tmp_path / "ops")
    assert first.kind == "success"
    assert replay.kind == "success"
    assert calls == [1]
    assert store.load_operation_run(receipt.operation_id).state is OperationState.RUNNING
    resources = store.list_typed_resources(receipt.operation_id)
    assert len(resources) == 1
    assert resources[0].details["worker_identity"]["process_start_identity"] == "managed-start"
    events = store.list_operation_events(receipt.operation_id)
    assert sum(event.event_type == "launch.accepted" for event in events) == 1
    assert ledger.read_nbf_events() == []


def test_managed_identity_ambiguity_is_unknown_without_redispatch(tmp_path: Path) -> None:
    ledger = IncidentLedger(tmp_path)
    req = request(tmp_path, physical_door_id="cloud.babysitter.launch", ledger=ledger)
    receipt = replace(require_production_worker_dispatch_runtime(req), production_intent=True)
    calls: list[int] = []

    def launch(_context):
        calls.append(1)
        identity = {"host": "managed-host", "pid": 321, "boot_id": "managed-boot"}
        return LaunchResult(True, ManagedCommandResult(0, identity), identity)

    result = dispatch_with_admission(req, launch, ledger=ledger, gate=lambda _request: receipt)
    assert result.kind == "unresolved_launch"
    assert calls == [1]
    assert FileBackedDurableOpsStore(tmp_path / "ops").load_operation_run(receipt.operation_id).state is OperationState.PENDING
    assert ledger.read_nbf_events() == []
