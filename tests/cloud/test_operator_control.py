from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from arnold_pipelines.megaplan.cloud import operator_control


def test_resume_injects_managed_repair_route_into_tmux_session(
    tmp_path: Path, monkeypatch
) -> None:
    # The production target runner deliberately exports the managed queue root.
    # This test covers the fallback derived from the marker location.
    monkeypatch.delenv("ARNOLD_REPAIR_QUEUE_ROOT", raising=False)
    workspace = tmp_path / "workspace"
    marker_dir = tmp_path / ".megaplan" / "cloud-sessions"
    marker_path = marker_dir / "demo.json"
    marker_dir.mkdir(parents=True)
    marker_path.write_text(
        json.dumps(
            {
                "session": "demo",
                "run_kind": "chain",
                "relaunch_command": "python -m demo",
                "operator_pause": {"active": True},
            }
        ),
        encoding="utf-8",
    )
    resume_calls: list[dict[str, object]] = []
    resume_authority = {
        "schema_version": "arnold.megaplan.operator-pause.v1",
        "resumed_at": "2026-08-04T00:00:00+00:00",
        "actor": "test",
        "plan": "demo-plan",
        "restored_plan_state": "gated",
    }

    def fake_resume_chain(*args, **kwargs):
        resume_calls.append(dict(kwargs))
        return {"changed": True, "paused": False, "resume_authority": resume_authority}

    monkeypatch.setattr(operator_control, "resume_chain", fake_resume_chain)
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        if argv[1] == "new-session":
            launching = json.loads(marker_path.read_text(encoding="utf-8"))
            assert "operator_pause" not in launching
            assert launching["should_run"] is True
        if argv[1] == "has-session":
            has_calls = sum(1 for call in calls if call[1] == "has-session")
            return subprocess.CompletedProcess(argv, 1 if has_calls == 1 else 0)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(operator_control.subprocess, "run", fake_run)
    sleeps: list[float] = []
    monkeypatch.setattr(operator_control.time, "sleep", sleeps.append)

    result = operator_control.resume_session(
        spec=tmp_path / "chain.yaml",
        workspace=workspace,
        session="demo",
        marker_path=marker_path,
        actor="test",
    )

    launch = calls[1]
    assert result["runner_started"] is True
    assert (
        f"ARNOLD_REPAIR_QUEUE_ROOT={tmp_path / '.megaplan' / 'repair-queue'}" in launch
    )
    assert f"ARNOLD_REPAIR_MARKER_DIR={marker_dir}" in launch
    assert "ARNOLD_REPAIR_SESSION=demo" in launch
    assert "ARNOLD_REPAIR_RUN_KIND=chain" in launch
    assert resume_calls == [{"actor": "test", "verify_execution_binding": True}]
    assert not any(item.startswith("MEGAPLAN_CHAIN_NO_PUSH=") for item in launch)
    assert launch[-1] == "python -m demo"
    updated = json.loads(marker_path.read_text(encoding="utf-8"))
    assert "operator_pause" not in updated
    assert updated["should_run"] is True
    assert sleeps == [operator_control._POST_LAUNCH_GRACE_SECONDS]


@pytest.mark.parametrize("reservation_status", ["authorized", "claimed"])
def test_pause_marker_door_does_not_mutate_launch_reservation_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reservation_status: str,
) -> None:
    workspace = tmp_path / "workspace"
    marker_path = tmp_path / ".megaplan" / "cloud-sessions" / "demo.json"
    marker_path.parent.mkdir(parents=True)
    marker_path.write_text(
        json.dumps(
            {
                "session": "demo",
                "workspace": str(workspace),
                "should_run": True,
                "babysitter_launch_reservation": {
                    "reservation_id": "reservation",
                    "status": reservation_status,
                },
            }
        ),
        encoding="utf-8",
    )
    authority = {"schema_version": "arnold.megaplan.operator-pause.v1", "active": True, "plan": "demo-plan"}
    monkeypatch.setattr(operator_control, "pause_chain", lambda *a, **k: {"authority": authority})
    monkeypatch.setattr(operator_control, "_stop_tmux_session", lambda *a, **k: False)
    monkeypatch.setattr(operator_control, "_stop_owned_pidfile", lambda *a, **k: False)
    monkeypatch.setattr(operator_control, "reconcile_quiesced_plan_pause", lambda *a, **k: False)
    monkeypatch.setattr(operator_control.time, "sleep", lambda *_: None)

    operator_control.pause_session(
        spec=tmp_path / "chain.yaml",
        workspace=workspace,
        session="demo",
        marker_path=marker_path,
        reason="hold",
        actor="test",
    )
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    assert marker["should_run"] is False
    # Marker pause state is operator custody only; canonical launch authority
    # lives in OperationRun and is never cancelled or accepted here.
    assert marker["babysitter_launch_reservation"]["status"] == reservation_status


def test_resume_no_push_preserves_dirty_milestone_checkout(
    tmp_path: Path, monkeypatch
) -> None:
    workspace = tmp_path / "workspace"
    marker_dir = tmp_path / ".megaplan" / "cloud-sessions"
    marker_path = marker_dir / "demo.json"
    marker_dir.mkdir(parents=True)
    marker_path.write_text(
        json.dumps(
            {
                "session": "demo",
                "run_kind": "chain",
                "relaunch_command": "python -m demo",
                "operator_pause": {"active": True},
            }
        ),
        encoding="utf-8",
    )
    resume_calls: list[dict[str, object]] = []
    resume_authority = {
        "schema_version": "arnold.megaplan.operator-pause.v1",
        "resumed_at": "2026-08-04T00:00:00+00:00",
        "actor": "test",
        "plan": "demo-plan",
        "restored_plan_state": "gated",
    }

    def fake_resume_chain(*args, **kwargs):
        resume_calls.append(dict(kwargs))
        return {"changed": True, "paused": False, "resume_authority": resume_authority}

    monkeypatch.setattr(operator_control, "resume_chain", fake_resume_chain)
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        if argv[1] == "has-session":
            has_calls = sum(1 for call in calls if call[1] == "has-session")
            return subprocess.CompletedProcess(argv, 1 if has_calls == 1 else 0)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(operator_control.subprocess, "run", fake_run)

    result = operator_control.resume_session(
        spec=tmp_path / "chain.yaml",
        workspace=workspace,
        session="demo",
        marker_path=marker_path,
        actor="test",
        no_push=True,
    )

    launch = calls[1]
    assert result["runner_started"] is True
    assert result["no_push"] is True
    assert "MEGAPLAN_CHAIN_NO_PUSH=1" in launch
    assert launch[-1] == "python -m demo"


def test_resume_authority_only_does_not_start_runner(
    tmp_path: Path, monkeypatch
) -> None:
    workspace = tmp_path / "workspace"
    marker_path = tmp_path / ".megaplan" / "cloud-sessions" / "demo.json"
    marker_path.parent.mkdir(parents=True)
    marker_path.write_text(
        json.dumps(
            {
                "session": "demo",
                "operator_pause": {"active": True},
                "should_run": False,
            }
        ),
        encoding="utf-8",
    )
    resume_calls: list[dict[str, object]] = []
    resume_authority = {
        "schema_version": "arnold.megaplan.operator-pause.v1",
        "resumed_at": "2026-08-04T00:00:00+00:00",
        "actor": "test",
        "plan": "demo-plan",
        "restored_plan_state": "gated",
    }

    def fake_resume_chain(*args, **kwargs):
        resume_calls.append(dict(kwargs))
        return {"changed": True, "paused": False, "resume_authority": resume_authority}

    monkeypatch.setattr(operator_control, "resume_chain", fake_resume_chain)
    calls: list[list[str]] = []
    monkeypatch.setattr(
        operator_control.subprocess,
        "run",
        lambda argv, **kwargs: calls.append(list(argv)),
    )

    result = operator_control.resume_session(
        spec=tmp_path / "chain.yaml",
        workspace=workspace,
        session="demo",
        marker_path=marker_path,
        actor="test",
        start_runner=False,
    )

    assert calls == []
    assert resume_calls == [{"actor": "test", "verify_execution_binding": False}]
    assert result["runner_started"] is False
    assert result["authority_only"] is True
    updated = json.loads(marker_path.read_text(encoding="utf-8"))
    assert "operator_pause" not in updated
    assert updated["should_run"] is False
    assert updated["operator_resume_hold"] == {
        "schema_version": "arnold.megaplan.operator-resume-hold.v1",
        "active": True,
        "session": "demo",
        "spec": str((tmp_path / "chain.yaml").resolve()),
        "workspace": str(workspace.resolve()),
        "resume_authority": resume_authority,
    }


def test_resume_fails_closed_when_marker_changes_concurrently(
    tmp_path: Path, monkeypatch
) -> None:
    workspace = tmp_path / "workspace"
    marker_path = tmp_path / ".megaplan" / "cloud-sessions" / "demo.json"
    marker_path.parent.mkdir(parents=True)
    marker_path.write_text(
        json.dumps(
            {
                "session": "demo",
                "run_kind": "chain",
                "relaunch_command": "python -m demo",
                "operator_pause": {"active": True},
                "should_run": False,
            }
        ),
        encoding="utf-8",
    )

    def fake_resume_chain(*args, **kwargs):
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        marker["runtime_binding"] = {"current_identity": {"source_revision": "c" * 40}}
        marker_path.write_text(json.dumps(marker), encoding="utf-8")
        return {"changed": True, "paused": False}

    monkeypatch.setattr(operator_control, "resume_chain", fake_resume_chain)
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 1)

    monkeypatch.setattr(operator_control.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="session marker changed concurrently"):
        operator_control.resume_session(
            spec=tmp_path / "chain.yaml",
            workspace=workspace,
            session="demo",
            marker_path=marker_path,
            actor="test",
        )

    assert calls == [["tmux", "has-session", "-t", "demo"]]


def test_resume_rejects_stale_marker_command_after_runtime_cutover(
    tmp_path: Path, monkeypatch
) -> None:
    marker_path = tmp_path / ".megaplan" / "cloud-sessions" / "demo.json"
    marker_path.parent.mkdir(parents=True)
    marker_path.write_text(
        json.dumps(
            {"run_kind": "chain", "relaunch_command": "git pull && python -m old"}
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(operator_control, "resume_chain", lambda *a, **k: {})
    monkeypatch.setattr(operator_control.subprocess, "run", lambda *a, **k: None)

    with pytest.raises(RuntimeError, match="stale or unavailable"):
        operator_control.resume_session(
            spec=tmp_path / "chain.yaml",
            workspace=tmp_path,
            session="demo",
            marker_path=marker_path,
            actor="test",
        )


def test_resume_restores_authority_hold_when_runner_dies_before_handshake(
    tmp_path: Path, monkeypatch
) -> None:
    workspace = tmp_path / "workspace"
    marker_path = tmp_path / ".megaplan" / "cloud-sessions" / "demo.json"
    marker_path.parent.mkdir(parents=True)
    marker_path.write_text(
        json.dumps(
            {
                "session": "demo",
                "run_kind": "chain",
                "relaunch_command": "python -m demo",
                "operator_pause": {"active": True},
                "should_run": False,
            }
        )
    )
    authority = {
        "schema_version": "arnold.megaplan.operator-pause.v1",
        "resumed_at": "2026-08-04T00:00:00+00:00",
        "actor": "test",
        "plan": "demo-plan",
        "restored_plan_state": "finalized",
    }
    monkeypatch.setattr(
        operator_control,
        "resume_chain",
        lambda *a, **k: {
            "changed": True,
            "paused": False,
            "resume_authority": authority,
        },
    )
    calls: list[list[str]] = []

    def run(argv, **kwargs):
        calls.append(list(argv))
        if argv[1] == "has-session":
            return subprocess.CompletedProcess(argv, 1)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(operator_control.subprocess, "run", run)
    with pytest.raises(RuntimeError, match="exited before post-launch"):
        operator_control.resume_session(
            spec=tmp_path / "chain.yaml",
            workspace=workspace,
            session="demo",
            marker_path=marker_path,
            actor="test",
        )

    stopped = json.loads(marker_path.read_text())
    assert stopped["should_run"] is False
    assert stopped["operator_resume_hold"]["resume_authority"] == authority
    assert sum(1 for call in calls if call[1] == "new-session") == 1


def test_post_launch_failure_does_not_overwrite_concurrent_marker_change(
    tmp_path: Path, monkeypatch
) -> None:
    workspace = tmp_path / "workspace"
    marker_path = tmp_path / ".megaplan" / "cloud-sessions" / "demo.json"
    marker_path.parent.mkdir(parents=True)
    marker_path.write_text(
        json.dumps(
            {
                "session": "demo",
                "relaunch_command": "python -m demo",
                "operator_pause": {"active": True},
                "should_run": False,
            }
        )
    )
    authority = {
        "schema_version": "arnold.megaplan.operator-pause.v1",
        "resumed_at": "2026-08-04T00:00:00+00:00",
        "actor": "test",
        "plan": "demo-plan",
        "restored_plan_state": "finalized",
    }
    monkeypatch.setattr(
        operator_control,
        "resume_chain",
        lambda *a, **k: {"resume_authority": authority},
    )
    has_calls = 0

    def run(argv, **kwargs):
        nonlocal has_calls
        if argv[1] == "has-session":
            has_calls += 1
            if has_calls == 2:
                concurrent = json.loads(marker_path.read_text())
                concurrent["concurrent_owner"] = "new-operator"
                marker_path.write_text(json.dumps(concurrent))
            return subprocess.CompletedProcess(argv, 1)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(operator_control.subprocess, "run", run)
    with pytest.raises(RuntimeError, match="changed concurrently after launch"):
        operator_control.resume_session(
            spec=tmp_path / "chain.yaml",
            workspace=workspace,
            session="demo",
            marker_path=marker_path,
            actor="test",
        )

    concurrent = json.loads(marker_path.read_text())
    assert concurrent["concurrent_owner"] == "new-operator"
    assert concurrent["should_run"] is True
    assert "operator_resume_hold" not in concurrent
