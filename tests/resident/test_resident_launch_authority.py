"""Canonical resident supervisor launch-door coverage."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from arnold.runtime.durable_ops import FileBackedDurableOpsStore, OperationState
from arnold_pipelines.megaplan.resident import subagent


class _Process:
    def __init__(self, pid: int) -> None:
        self.pid = pid

    def poll(self) -> None:
        return None


def _manifest(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    root = tmp_path / "resident-subagents"
    run = root / "subagent-20260905-120000-abcdef12"
    run.mkdir(parents=True)
    manifest_path = run / "manifest.json"
    manifest: dict[str, object] = {
        "run_id": run.name,
        "project_dir": str(tmp_path),
        "backend": "codex",
        "launch_idempotency_key": "resident-test-launch",
        "custody_id": "resident-custody-test",
        "status": "launching",
        "log_path": str(run / "run.log"),
        "full_log_path": str(run / "run.log"),
        "launch_provenance": {
            "schema_version": "arnold-resident-delegation-provenance-v1",
            "transport": "non_discord",
            "applicability": "not_applicable",
            "source_kind": "explicit_non_discord",
        },
        "status_history": [],
    }
    (run / "run.log").touch()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path, manifest


def test_supervisor_door_admits_once_and_replays_without_popen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_path, manifest = _manifest(tmp_path)
    calls: list[object] = []
    monkeypatch.setattr(
        subagent.subprocess,
        "Popen",
        lambda *args, **kwargs: calls.append(args) or _Process(os.getpid()),
    )
    monkeypatch.setattr(subagent, "_pid_start_ticks", lambda _pid: "start-1")
    monkeypatch.setattr(subagent, "_pid_live", lambda _pid: True)
    monkeypatch.setattr(subagent, "_git_revision_without_process", lambda _root: "rev-1")

    first_process, first = subagent._spawn_managed_supervisor(manifest_path, manifest)
    second_process, second = subagent._spawn_managed_supervisor(manifest_path, first)

    assert first_process is not None
    assert second_process is None
    assert len(calls) == 1
    assert first["status"] == second["status"] == "running"
    store = FileBackedDurableOpsStore(Path(first["operation_store_root"]))
    operation = store.load_operation_run(str(first["operation_id"]))
    assert operation.state is OperationState.RUNNING
    assert len(store.list_operation_events(operation.id)) == 2
    assert len(store.list_typed_resources(operation.id)) == 1


def test_identity_loss_leaves_pending_ownerless_and_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_path, manifest = _manifest(tmp_path)
    monkeypatch.setattr(
        subagent.subprocess,
        "Popen",
        lambda *args, **kwargs: _Process(os.getpid()),
    )
    monkeypatch.setattr(subagent, "_git_revision_without_process", lambda _root: "rev-1")
    monkeypatch.setattr(subagent, "_pid_live", lambda _pid: False)

    with pytest.raises(subagent._ResidentLaunchUnresolved):
        subagent._spawn_managed_supervisor(manifest_path, manifest)

    current = json.loads(manifest_path.read_text(encoding="utf-8"))
    store = FileBackedDurableOpsStore(Path(current["operation_store_root"]))
    operation = store.load_operation_run(str(current["operation_id"]))
    assert operation.state is OperationState.PENDING
    assert store.list_typed_resources(operation.id) == ()
    assert current["launch_outcome"] == "UNKNOWN"
    assert current["status"] == "launching"


def test_missing_source_prerequisite_rejects_before_popen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_path, manifest = _manifest(tmp_path)
    monkeypatch.setattr(subagent, "_git_revision_without_process", lambda _root: None)
    monkeypatch.setattr(
        subagent.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("preflight rejection must not Popen"),
    )

    with pytest.raises(subagent._ResidentLaunchUnresolved):
        subagent._spawn_managed_supervisor(manifest_path, manifest)
    current = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert current["launch_outcome"] == "REJECTED"
    assert current["launch_reason"] == "preflight_rejected"
