"""Babysitter launch telemetry must not become launch authority."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from arnold_pipelines.megaplan.cloud.babysitter import launch
from arnold_pipelines.megaplan.orchestration.phase_result import DispatchOutcome


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


def test_marker_manifest_identity_is_bytes_bound_and_receipted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "runtime-manifest.json"
    manifest.write_bytes(b"successor-runtime\n")
    identity = hashlib.sha256(manifest.read_bytes()).hexdigest()
    marker = tmp_path / "session.json"
    marker.write_text(
        json.dumps(
            {
                "bootstrap_manifest_path": str(manifest),
                "manifest_sha256": identity,
                "manifest_identity": identity,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(manifest))
    monkeypatch.setenv("ARNOLD_BABYSITTER_MARKER_PATH", str(marker))
    monkeypatch.setenv("ARNOLD_BABYSITTER_MANIFEST_IDENTITY", identity)

    assert launch._manifest_identity_for_dispatch() == identity
    payload = launch._receipt_payload(
        {**_context(tmp_path), "manifest_identity": identity}, status="completed"
    )
    assert payload["manifest_identity"] == identity


def test_valid_successor_marker_identity_reaches_admission_and_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "runtime-manifest.json"
    manifest.write_bytes(b"successor-runtime\n")
    identity = hashlib.sha256(manifest.read_bytes()).hexdigest()
    marker = tmp_path / "session.json"
    marker.write_text(
        json.dumps(
            {
                "bootstrap_manifest_path": str(manifest),
                "manifest_sha256": identity,
                "manifest_identity": identity,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(manifest))
    monkeypatch.setenv("ARNOLD_BABYSITTER_MARKER_PATH", str(marker))
    monkeypatch.setenv("ARNOLD_BABYSITTER_MANIFEST_IDENTITY", identity)
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_provenance.runtime_provenance",
        lambda: {"source_revision": "r", "runtime": "runtime"},
    )
    captured: dict[str, object] = {}

    def fake_dispatch(request, *_args, **_kwargs):
        captured["request"] = request
        return DispatchOutcome(
            kind="success",
            launch_state="accepted",
            plan_id=request.plan_id,
            phase=request.phase,
            dispatch_family_id=request.dispatch_family_id,
            logical_dispatch_id=request.logical_dispatch_id,
            admission_receipt_id="receipt",
            semantic_dispatch_fingerprint="f" * 64,
            selected_spec=request.selected_spec,
            worker_identity={"host": "test", "pid": 1, "boot_id": "boot"},
            started_at="2026-09-05T00:00:00Z",
            finished_at="2026-09-05T00:00:01Z",
        )

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.worker_dispatch.dispatch_with_admission",
        fake_dispatch,
    )
    ctx = {
        **_context(tmp_path),
        "managed_run_id": "managed-run",
        "configured_fallback_specs": ("codex:gpt-5.6-luna",),
    }
    assert launch._admit_managed_launch(
        ctx, SimpleNamespace(model="codex:gpt-5.6-luna")
    ) == 0
    request = captured["request"]
    assert request.manifest_identity == identity
    assert ctx["manifest_identity"] == identity
    assert launch._receipt_payload(ctx, status="completed")["manifest_identity"] == identity


@pytest.mark.parametrize("mutation", ["tamper", "missing"])
def test_marker_manifest_identity_rejects_tamper_or_missing_before_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    manifest = tmp_path / "runtime-manifest.json"
    manifest.write_bytes(b"successor-runtime\n")
    identity = hashlib.sha256(manifest.read_bytes()).hexdigest()
    marker = tmp_path / "session.json"
    marker.write_text(
        json.dumps(
            {
                "bootstrap_manifest_path": str(manifest),
                "manifest_sha256": identity,
                "manifest_identity": identity,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(manifest))
    monkeypatch.setenv("ARNOLD_BABYSITTER_MARKER_PATH", str(marker))
    monkeypatch.setenv("ARNOLD_BABYSITTER_MANIFEST_IDENTITY", identity)
    if mutation == "tamper":
        manifest.write_bytes(b"tampered-runtime\n")
    else:
        marker_payload = json.loads(marker.read_text(encoding="utf-8"))
        marker_payload.pop("manifest_identity")
        marker.write_text(json.dumps(marker_payload), encoding="utf-8")

    with pytest.raises(RuntimeError, match="manifest identity|manifest binding"):
        launch._manifest_identity_for_dispatch()


def test_receipt_pid_dedup_gate_is_deleted() -> None:
    assert not hasattr(launch, "_dedup_already_running")
    assert not hasattr(launch, "_receipt_candidates")
