"""ControlledFinalLaunch is a custody adapter, not launch authority."""

from __future__ import annotations

from pathlib import Path

import pytest

from arnold_pipelines.megaplan.cloud.controlled_final_launch import ControlledFinalLaunch
from arnold_pipelines.megaplan.cloud.worker_dispatch import (
    require_production_worker_dispatch_runtime,
)
from arnold_pipelines.megaplan.incident.ledger import IncidentLedger
from arnold_pipelines.megaplan.orchestration.phase_result import DispatchOutcome
from tests.cloud.dispatch_test_helpers import request


def _adapter(tmp_path: Path) -> tuple[IncidentLedger, ControlledFinalLaunch]:
    ledger = IncidentLedger(tmp_path)
    receipt = require_production_worker_dispatch_runtime(request(tmp_path, ledger=ledger))
    return ledger, ControlledFinalLaunch(receipt, ledger=ledger, canonical=True)


def _accepted(adapter: ControlledFinalLaunch) -> DispatchOutcome:
    receipt = adapter.receipt
    return DispatchOutcome(
        kind="success",
        launch_state="accepted",
        plan_id=receipt.plan_id,
        phase=receipt.phase,
        dispatch_family_id=receipt.dispatch_family_id,
        logical_dispatch_id=receipt.logical_dispatch_id,
        admission_receipt_id=receipt.admission_receipt_id,
        semantic_dispatch_fingerprint=receipt.semantic_dispatch_fingerprint,
        selected_spec=receipt.normalized_spec,
        worker_identity={"host": "host", "pid": 123, "boot_id": "boot", "process_start_identity": "start"},
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01+00:00",
    )


def test_canonical_adapter_does_not_write_lifecycle_markers(tmp_path: Path) -> None:
    ledger, adapter = _adapter(tmp_path)
    value = adapter.run(lambda _context: _accepted(adapter))
    assert value.kind == "success"
    assert adapter.state == "accepted"
    assert ledger.read_nbf_events() == []


def test_canonical_adapter_is_single_use_without_redispatch(tmp_path: Path) -> None:
    _ledger, adapter = _adapter(tmp_path)
    calls: list[int] = []
    adapter.run(lambda _context: calls.append(1) or _accepted(adapter))
    with pytest.raises(RuntimeError, match="only once"):
        adapter.run(lambda _context: calls.append(1))
    assert calls == [1]


def test_canonical_timeout_is_read_only_custody_hold(tmp_path: Path) -> None:
    ledger, adapter = _adapter(tmp_path)
    result = adapter.immediate_timeout(object())
    assert result["state"] == "unresolved"
    assert ledger.read_nbf_events() == []
