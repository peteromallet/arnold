from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
from shutil import which

import pytest

from agentbox.config import AgentBoxConfig
from agentbox.operations import create_agentbox_operation, open_operation_store
from agentbox.run_dirs import ensure_run_dir
from agentbox.tmux import (
    command_file_session_argv,
    materialize_command_file,
    SessionStatus,
    TmuxResult,
    capture_pane_argv,
    has_session_argv,
    inspect_session,
    new_session_argv,
    record_process_session_resource,
    run_tmux,
    send_keys_argv,
    session_name,
    start_session,
    stop_session,
)
from arnold.runtime.durable_ops import ResourceType


def test_tmux_helpers_build_argv_lists_with_deterministic_session_names(
    tmp_path: Path,
) -> None:
    name = session_name("op/with spaces")
    stdout = tmp_path / "stdout.log"
    stderr = tmp_path / "stderr.log"

    assert name == "agentbox-op-with-spaces"
    assert has_session_argv(name) == ["tmux", "has-session", "-t", name]
    assert capture_pane_argv(name, lines=50) == [
        "tmux",
        "capture-pane",
        "-p",
        "-t",
        name,
        "-S",
        "-50",
    ]
    assert new_session_argv(
        name,
        ("python", "-m", "agentbox_worker"),
        cwd=tmp_path,
        stdout_path=stdout,
        stderr_path=stderr,
    ) == [
        "tmux",
        "new-session",
        "-d",
        "-s",
        name,
        "-c",
        str(tmp_path),
        f"python -m agentbox_worker >> {stdout} 2>> {stderr}",
    ]
    assert send_keys_argv(name, ("C-c",)) == ["tmux", "send-keys", "-t", name, "C-c"]


def test_run_tmux_uses_argv_list_commands(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(argv, 0, stdout="ok\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = run_tmux(["tmux", "has-session", "-t", "agentbox-op"])

    assert result.stdout == "ok"
    assert captured["argv"] == ["tmux", "has-session", "-t", "agentbox-op"]
    assert captured["kwargs"]["shell"] is not True if "shell" in captured["kwargs"] else True


def test_start_session_uses_quoted_argv_list_command(tmp_path: Path, monkeypatch) -> None:
    config = AgentBoxConfig(workspace_root=tmp_path / "workspace")
    paths = ensure_run_dir(config, "op with spaces")
    captured: dict[str, list[str]] = {}

    def fake_run_tmux(argv, *, check=True):
        captured["argv"] = list(argv)
        return TmuxResult(tuple(argv), 0, "", "")

    monkeypatch.setattr("agentbox.tmux.run_tmux", fake_run_tmux)

    name = start_session(
        "op with spaces",
        ("python", "-c", "print('hello world')"),
        cwd=tmp_path / "repo with spaces",
        run_paths=paths,
    )

    assert name == "agentbox-op-with-spaces"
    assert captured["argv"][:7] == [
        "tmux",
        "new-session",
        "-d",
        "-s",
        "agentbox-op-with-spaces",
        "-c",
        str(tmp_path / "repo with spaces"),
    ]
    assert captured["argv"][-1] == (
        "python -c 'print('\\''hello world'\\'')' "
        f">> '{paths.stdout_path}' 2>> '{paths.stderr_path}'"
    )


def test_inspect_session_returns_structured_live_missing_and_dead_statuses(
    monkeypatch,
) -> None:
    responses = [
        TmuxResult(("tmux",), 0, "", ""),
        TmuxResult(("tmux",), 1, "", "can't find session: missing"),
        TmuxResult(("tmux",), 1, "", "no server running on /tmp/tmux"),
    ]

    def fake_run_tmux(argv, *, check=True):
        return responses.pop(0)

    monkeypatch.setattr("agentbox.tmux.run_tmux", fake_run_tmux)

    assert inspect_session("live") == SessionStatus("live", "running", True)
    assert inspect_session("missing").state == "missing"
    assert inspect_session("dead").state == "dead"


def test_start_session_wires_run_logs_into_new_session_command(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = AgentBoxConfig(workspace_root=tmp_path / "workspace")
    paths = ensure_run_dir(config, "op")
    captured: dict[str, list[str]] = {}

    def fake_run_tmux(argv, *, check=True):
        captured["argv"] = list(argv)
        return TmuxResult(tuple(argv), 0, "", "")

    monkeypatch.setattr("agentbox.tmux.run_tmux", fake_run_tmux)

    name = start_session("op", "echo hello", cwd=tmp_path, run_paths=paths)

    assert name == "agentbox-op"
    assert captured["argv"][-1] == (
        f"echo hello >> {paths.stdout_path} 2>> {paths.stderr_path}"
    )


def test_materialize_command_file_binds_large_payload_and_reuses_equal_bytes(
    tmp_path: Path,
) -> None:
    payload = "printf exact-identity; " + ("# payload\n" * 5000)
    path = materialize_command_file(
        payload,
        durable_root=tmp_path,
        operation_id="op-1",
        request_id="req-1",
        envelope_digest="sha256:env-1",
    )
    assert path.read_text() == payload
    assert path.stat().st_mode & 0o777 == 0o600
    assert materialize_command_file(
        payload,
        durable_root=tmp_path,
        operation_id="op-1",
        request_id="req-1",
        envelope_digest="sha256:env-1",
    ) == path
    assert command_file_session_argv("agentbox-op", path)[-1].startswith("exec /bin/sh ")


def test_materialize_command_file_rejects_tampering_and_symlink_occupancy(
    tmp_path: Path,
) -> None:
    payload = "echo safe"
    path = materialize_command_file(
        payload,
        durable_root=tmp_path,
        operation_id="op-2",
        request_id="req-2",
        envelope_digest="sha256:env-2",
    )
    path.write_text("echo tampered")
    with pytest.raises(ValueError, match="bytes differ"):
        materialize_command_file(
            payload,
            durable_root=tmp_path,
            operation_id="op-2",
            request_id="req-2",
            envelope_digest="sha256:env-2",
        )

    other = tmp_path / "other"
    other.write_text(payload)
    target = tmp_path / "command-files" / "op-3" / "req-3" / "sha256:env-3"
    target.mkdir(parents=True)
    digest = hashlib.sha256(payload.encode()).hexdigest()
    (target / f"command-{digest}.sh").symlink_to(other)
    with pytest.raises(ValueError, match="private regular file"):
        materialize_command_file(
            payload,
            durable_root=tmp_path,
            operation_id="op-3",
            request_id="req-3",
            envelope_digest="sha256:env-3",
        )


def test_materialize_command_file_rejects_symlinked_ancestor(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    (root / "command-files").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="ancestor"):
        materialize_command_file(
            "echo safe",
            durable_root=root,
            operation_id="op",
            request_id="req",
            envelope_digest="sha256:env",
        )

def test_stop_session_returns_missing_status_without_sending_keys(monkeypatch) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run_tmux(argv, *, check=True):
        calls.append(tuple(argv))
        return TmuxResult(tuple(argv), 1, "", "can't find session: agentbox-op")

    monkeypatch.setattr("agentbox.tmux.run_tmux", fake_run_tmux)

    status = stop_session("agentbox-op")

    assert status.state == "missing"
    assert calls == [("tmux", "has-session", "-t", "agentbox-op")]


def test_record_process_session_resource_is_idempotent(tmp_path: Path) -> None:
    config = AgentBoxConfig(workspace_root=tmp_path / "workspace")
    create_agentbox_operation(config, "op", command="echo hi")
    status = SessionStatus("agentbox-op", "running", True)

    first = record_process_session_resource(
        config,
        "op",
        name="agentbox-op",
        status=status,
        details={"pane": "0"},
    )
    second = record_process_session_resource(
        config,
        "op",
        name="agentbox-op",
        status=status,
    )

    assert first == second
    resources = open_operation_store(config).list_typed_resources("op")
    assert len(resources) == 1
    assert resources[0].resource_type is ResourceType.PROCESS_SESSION
    assert resources[0].details["session_name"] == "agentbox-op"


@pytest.mark.skipif(
    os.environ.get("AGENTBOX_LIVE_TMUX") != "1",
    reason="set AGENTBOX_LIVE_TMUX=1 to run live tmux smoke",
)
@pytest.mark.skipif(which("tmux") is None, reason="tmux is not installed")
def test_live_tmux_smoke_is_opt_in(tmp_path: Path) -> None:
    name = session_name(f"smoke-{tmp_path.name}")
    command = (
        "printf agentbox-live-smoke; "
        "while :; do sleep 1; done"
    )

    try:
        start_session(name.removeprefix("agentbox-"), command, cwd=tmp_path)
        status = inspect_session(name)
        assert status == SessionStatus(name, "running", True)
        assert "agentbox-live-smoke" in run_tmux(capture_pane_argv(name)).stdout
    finally:
        subprocess.run(
            ["tmux", "kill-session", "-t", name],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
