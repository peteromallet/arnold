"""Babysitter launch telemetry must not become launch authority."""

from __future__ import annotations

import json
from pathlib import Path

from arnold_pipelines.megaplan.cloud.babysitter import launch


def _context(tmp_path: Path) -> dict[str, object]:
    return {
        "session": "demo",
        "occurrence": "occurrence-1",
        "run_id": "babysitter-demo-occurrence-1",
        "run_root": tmp_path / "run",
        "repair_data_dir": tmp_path / "repair-data",
        "plan": "plan",
        "run_kind": "chain",
        "workspace": str(tmp_path),
        "remote_spec": "",
        "mode": "superfixer",
        "model": "codex:gpt-5.6-luna",
        "launched_at": "2026-09-05T00:00:00Z",
    }


def test_receipt_is_terminal_telemetry_and_is_not_mirrored(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    launch._write_receipts(ctx, launch._receipt_payload(ctx, status="completed"))

    telemetry = ctx["repair_data_dir"] / "demo.babysitter-launch-receipt.json"
    mirror = ctx["run_root"] / "demo.babysitter-launch-receipt.json"
    assert telemetry.is_file()
    assert not mirror.exists()
    payload = json.loads(telemetry.read_text(encoding="utf-8"))
    assert payload["authority"] == "telemetry_only"
    assert payload["status"] == "completed"


def test_receipt_pid_dedup_gate_is_deleted() -> None:
    assert not hasattr(launch, "_dedup_already_running")
    assert not hasattr(launch, "_receipt_candidates")
