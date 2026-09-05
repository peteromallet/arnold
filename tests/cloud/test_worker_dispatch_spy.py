from __future__ import annotations

import argparse
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from arnold_pipelines.megaplan.workers import _impl
from arnold_pipelines.megaplan.workers._impl import AgentMode
from arnold_pipelines.megaplan.cloud.worker_dispatch import (
    WorkerAdmissionReceipt,
    dispatch_with_admission,
    require_production_worker_dispatch_runtime,
)
from arnold_pipelines.megaplan.incident.ledger import IncidentLedger
from arnold_pipelines.megaplan.incident.schema import ProviderFailureKey
from arnold_pipelines.megaplan.orchestration.phase_result import DispatchOutcome, SchedulingCondition
from tests.cloud.dispatch_test_helpers import native_proof, request


def test_native_public_door_delegates_to_canonical_production_dispatch(tmp_path: Path, monkeypatch) -> None:
    calls: list[object] = []
    expected = (object(), "codex", "fresh", True)
    monkeypatch.setattr(_impl, "_production_worker_dispatch", lambda *args, **kwargs: calls.append(kwargs) or expected)
    result = _impl.run_step_with_worker(
        "plan", {"meta": {}}, tmp_path, argparse.Namespace(), root=tmp_path,
        resolved=AgentMode("codex", "fresh", True, "gpt-5.5", None, "gpt-5.5"),
        worker_options={"production_intent": True},
    )
    assert result == expected
    assert len(calls) == 1


def test_door_source_has_one_shared_dispatch_loop() -> None:
    source = Path(_impl.__file__).read_text(encoding="utf-8")
    assert source.count("def dispatch_with_admission") == 0
    assert source.count("dispatch_with_admission(") == 1


def test_native_selected_construction_seam_admits_exactly_once(tmp_path: Path) -> None:
    calls: list[tuple[str, str, str]] = []
    proof = native_proof(observed_at=datetime.now(timezone.utc).isoformat())

    def construction_seam(provider: str, model: str, route: str) -> dict[str, object]:
        calls.append((provider, model, route))
        return proof

    result = require_production_worker_dispatch_runtime(
        request(
            tmp_path,
            native_construction_seam=construction_seam,
            route_liveness_resolver=lambda *_: proof,
        )
    )
    assert isinstance(result, WorkerAdmissionReceipt)
    assert calls == [("codex", "gpt-5.5", "codex:gpt-5.5")]


def _typed_terminal(receipt: WorkerAdmissionReceipt, kind: str) -> DispatchOutcome:
    common = dict(
        kind=kind,
        launch_state="accepted",
        plan_id=receipt.plan_id,
        phase=receipt.phase,
        dispatch_family_id=receipt.dispatch_family_id,
        logical_dispatch_id=receipt.logical_dispatch_id,
        admission_receipt_id=receipt.admission_receipt_id,
        semantic_dispatch_fingerprint=receipt.semantic_dispatch_fingerprint,
        selected_spec=receipt.normalized_spec,
        worker_identity={"host": "host", "pid": 123, "boot_id": "boot"},
        started_at="2026-08-30T00:00:00+00:00",
        finished_at="2026-08-30T00:00:01+00:00",
    )
    if kind == "success":
        common["success_payload"] = {"ok": True}
    elif kind == "ordinary_terminal_failure":
        common["terminal_failure"] = {"error": "ordinary"}
    elif kind == "provider_exhausted":
        provider_failure_key = ProviderFailureKey.derive(
            phase=receipt.phase,
            selected_spec=receipt.normalized_spec,
            provider_failure_class="availability",
            provider_epoch_identity="epoch",
        ).value
        common["provider_evidence"] = {
            "observation_id": "observation",
            "retryability_class": "availability",
            "exhausted_attempt_count": 1,
            "terminal_provider_evidence_id": "provider-evidence",
            "precondition_identity": "precondition",
            "provider_epoch_identity": "epoch",
            "provider_failure_key": provider_failure_key,
            "observed_at": "2026-08-30T00:00:00+00:00",
        }
        common["provider_failure_key"] = provider_failure_key
    else:
        common["disposition_id"] = "disposition"
    return DispatchOutcome(**common)


def test_all_physical_doors_use_operation_store_once(tmp_path: Path) -> None:
    """Native, OMP, and managed callbacks share one canonical transaction."""
    for door in ("native", "omp", "managed"):
        root = tmp_path / door
        ledger = IncidentLedger(root)
        req = request(root, ledger=ledger, physical_door_id=door)
        receipt = require_production_worker_dispatch_runtime(req)
        calls: list[int] = []

        def launch(_context, *, receipt=receipt):
            calls.append(1)
            identity = {"host": "host", "pid": 123, "boot_id": "boot", "process_start_identity": f"{door}-start"}
            from arnold_pipelines.megaplan.cloud.worker_dispatch import LaunchResult, ManagedCommandResult
            return LaunchResult(True, ManagedCommandResult(0, identity), identity)

        result = dispatch_with_admission(req, launch, ledger=ledger, gate=lambda _request, receipt=receipt: receipt)
        replay = dispatch_with_admission(req, launch, ledger=ledger, gate=lambda _request, receipt=receipt: receipt)
        assert isinstance(result, DispatchOutcome) and result.kind == "success"
        assert isinstance(replay, DispatchOutcome) and replay.kind == "success"
        assert calls == [1]
        assert ledger.read_nbf_events() == []


def test_unknown_process_identity_never_retries(tmp_path: Path) -> None:
    root = tmp_path / "unknown"
    ledger = IncidentLedger(root)
    req = request(root, ledger=ledger)
    receipt = replace(require_production_worker_dispatch_runtime(req), production_intent=True)
    calls: list[int] = []

    def launch(_context):
        calls.append(1)
        identity = {"host": "host", "pid": 123, "boot_id": "boot"}
        from arnold_pipelines.megaplan.cloud.worker_dispatch import LaunchResult, ManagedCommandResult
        return LaunchResult(True, ManagedCommandResult(0, identity), identity)

    result = dispatch_with_admission(req, launch, ledger=ledger, gate=lambda _request: receipt)
    assert isinstance(result, DispatchOutcome) and result.kind == "unresolved_launch"
    assert calls == [1]
    assert ledger.read_nbf_events() == []
