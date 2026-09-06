"""Canonical physical-door contract tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from arnold.runtime.durable_ops import FileBackedDurableOpsStore, OperationState
from dataclasses import replace
from arnold_pipelines.megaplan.cloud.worker_dispatch import (
    AdmissionRefusal,
    LaunchResult,
    ManagedCommandResult,
    dispatch_with_admission,
    require_production_worker_dispatch_runtime,
)
from arnold_pipelines.megaplan.cloud import worker_dispatch
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


@pytest.mark.parametrize("mutation", ("missing", "tamper", "marker_mismatch"))
def test_physical_door_manifest_binding_fails_closed(
    mutation: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The raw production-door manifest check rejects missing or drifted pins."""
    req = request(tmp_path)
    receipt = replace(require_production_worker_dispatch_runtime(req), production_intent=True)
    manifest_path = Path(os.environ["ARNOLD_RUNTIME_MANIFEST"])
    marker_path = Path(os.environ["ARNOLD_BABYSITTER_MARKER_PATH"])
    if mutation == "missing":
        monkeypatch.delenv("ARNOLD_RUNTIME_MANIFEST")
    elif mutation == "tamper":
        manifest_path.write_bytes(b"tampered-runtime-manifest\n")
    else:
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        marker["manifest_identity"] = "0" * 64
        marker_path.write_text(json.dumps(marker) + "\n", encoding="utf-8")

    launches: list[int] = []
    result = dispatch_with_admission(
        req,
        lambda _context: launches.append(1),
        gate=lambda _request: receipt,
    )
    assert isinstance(result, AdmissionRefusal)
    assert result.code == "launch_rejected"
    assert result.reason == "dispatch_rejected"
    assert launches == []
    store = FileBackedDurableOpsStore(tmp_path / "ops")
    assert store.load_operation_run(receipt.operation_id).state is OperationState.PENDING
    assert store.list_typed_resources(receipt.operation_id) == ()


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


def test_worker_physical_preflight_fails_closed_on_unknown_venue_observations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request_value = request(tmp_path)
    receipt = replace(
        require_production_worker_dispatch_runtime(request_value),
        production_intent=True,
        provider="",
    )
    monkeypatch.setattr(
        worker_dispatch,
        "read_only_capacity_observation",
        lambda *args, **kwargs: {"status": "unknown"},
    )
    monkeypatch.setattr(
        worker_dispatch,
        "read_only_network_observation",
        lambda *args, **kwargs: {"status": "unknown", "transport": "local"},
    )

    report = worker_dispatch._worker_launch_preflight(
        receipt, worker_dispatch._worker_launch_envelope(receipt)
    )

    assert report.accepted is False
    assert {"credentials", "capacity", "network"}.issubset(
        {failure.split(":", 1)[0] for failure in report.failures}
    )


def test_worker_provider_label_alone_does_not_prove_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request_value = request(tmp_path)
    receipt = replace(
        require_production_worker_dispatch_runtime(request_value),
        production_intent=True,
        provider="codex",
    )
    monkeypatch.setattr(
        worker_dispatch.agentbox_detect,
        "scan_providers",
        lambda: SimpleNamespace(
            providers=(SimpleNamespace(id="openai-codex", status="missing"),)
        ),
    )
    report = worker_dispatch._worker_launch_preflight(
        receipt, worker_dispatch._worker_launch_envelope(receipt)
    )
    assert report.accepted is False
    assert any(failure.startswith("credentials:") for failure in report.failures)
