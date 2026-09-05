"""Canonical physical-door contract tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from arnold.runtime.durable_ops import FileBackedDurableOpsStore, OperationState
from dataclasses import replace
from arnold_pipelines.megaplan.cloud.worker_dispatch import (
    LaunchResult,
    ManagedCommandResult,
    dispatch_with_admission,
    require_production_worker_dispatch_runtime,
)
from arnold_pipelines.megaplan.incident.ledger import IncidentLedger
from tests.cloud.dispatch_test_helpers import request


@pytest.mark.parametrize("door", ("native", "omp", "managed"))
def test_physical_door_valid_admission_dispatches_once(door: str, tmp_path: Path) -> None:
    root = tmp_path / door
    ledger = IncidentLedger(root)
    req = request(root, physical_door_id=door, ledger=ledger)
    receipt = replace(require_production_worker_dispatch_runtime(req), production_intent=True)
    calls: list[int] = []
    identity = {
        "host": f"{door}-host",
        "pid": 123,
        "boot_id": "boot",
        "process_start_identity": f"{door}-start",
    }

    def launch(_context):
        calls.append(1)
        return LaunchResult(True, ManagedCommandResult(0, identity), identity)

    first = dispatch_with_admission(req, launch, ledger=ledger, gate=lambda _request: receipt)
    replay = dispatch_with_admission(req, launch, ledger=ledger, gate=lambda _request: receipt)
    store = FileBackedDurableOpsStore(root / "ops")
    assert first.kind == "success"
    assert replay.kind == "success"
    assert calls == [1]
    assert store.load_operation_run(receipt.operation_id).state is OperationState.RUNNING
    resources = store.list_typed_resources(receipt.operation_id)
    assert len(resources) == 1
    assert resources[0].details["worker_identity"] == identity
    assert ledger.read_nbf_events() == []


def test_physical_door_missing_process_incarnation_is_unknown_without_retry(tmp_path: Path) -> None:
    ledger = IncidentLedger(tmp_path)
    req = request(tmp_path, ledger=ledger)
    receipt = replace(require_production_worker_dispatch_runtime(req), production_intent=True)
    calls: list[int] = []

    def launch(_context):
        calls.append(1)
        identity = {"host": "worker-host", "pid": 123, "boot_id": "boot"}
        return LaunchResult(True, ManagedCommandResult(0, identity), identity)

    result = dispatch_with_admission(req, launch, ledger=ledger, gate=lambda _request: receipt)
    assert result.kind == "unresolved_launch"
    assert calls == [1]
    assert FileBackedDurableOpsStore(tmp_path / "ops").load_operation_run(receipt.operation_id).state is OperationState.PENDING
    assert ledger.read_nbf_events() == []


def test_physical_door_wrong_worker_identity_is_unknown_without_resource_or_retry(tmp_path: Path) -> None:
    ledger = IncidentLedger(tmp_path)
    req = request(tmp_path, ledger=ledger)
    receipt = replace(require_production_worker_dispatch_runtime(req), production_intent=True)
    calls: list[int] = []

    def launch(_context):
        calls.append(1)
        identity = {"host": "", "pid": 0, "boot_id": "boot", "process_start_identity": "start"}
        return LaunchResult(True, ManagedCommandResult(0, identity), identity)

    result = dispatch_with_admission(req, launch, ledger=ledger, gate=lambda _request: receipt)
    store = FileBackedDurableOpsStore(tmp_path / "ops")
    assert result.kind == "unresolved_launch"
    assert calls == [1]
    assert store.load_operation_run(receipt.operation_id).state is OperationState.PENDING
    assert store.list_typed_resources(receipt.operation_id) == ()
    assert ledger.read_nbf_events() == []
