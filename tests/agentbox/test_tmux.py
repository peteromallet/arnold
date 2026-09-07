from __future__ import annotations

import hashlib
import os
import subprocess
import time
from pathlib import Path
from shutil import which

import pytest

from agentbox.config import AgentBoxConfig
from agentbox.operations import create_agentbox_operation, open_operation_store
from agentbox.run_dirs import ensure_run_dir
from agentbox.tmux import (
    TMUX_COMMAND_INLINE_LIMIT,
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


def _identity_directory(root: Path, operation: str, request: str, envelope: str) -> Path:
    def component(label: str, value: str) -> str:
        return f"{label}-{hashlib.sha256(value.encode()).hexdigest()}"

    return root / "command-files" / component("operation", operation) / component(
        "request", request
    ) / component("envelope", envelope)


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
    binding = materialize_command_file(
        payload,
        durable_root=tmp_path,
        operation_id="op-1",
        request_id="req-1",
        envelope_digest="sha256:env-1",
    )
    assert binding.path.read_text() == payload
    assert binding.path.stat().st_mode & 0o777 == 0o600
    assert materialize_command_file(
        payload,
        durable_root=tmp_path,
        operation_id="op-1",
        request_id="req-1",
        envelope_digest="sha256:env-1",
    ) == binding
    assert command_file_session_argv("agentbox-op", binding)[-1].startswith("exec ")


def test_command_file_identity_components_are_bounded_and_separated(
    tmp_path: Path,
) -> None:
    operation_id = "launch:v3:" + ("canonical-operation-identity/雪:" * 20)
    assert len(operation_id.encode("utf-8")) > 255
    first = materialize_command_file(
        "printf bound",
        durable_root=tmp_path,
        operation_id=operation_id,
        request_id="request:v3:one",
        envelope_digest="sha256:envelope-one",
    )
    wrong_identity = materialize_command_file(
        "printf bound",
        durable_root=tmp_path,
        operation_id=operation_id + "-different",
        request_id="request:v3:one",
        envelope_digest="sha256:envelope-one",
    )

    name_max = os.pathconf(tmp_path, "PC_NAME_MAX")
    assert all(len(component.encode("utf-8")) <= name_max for component in first.components)
    assert first.components[1].startswith("operation-")
    assert first.components[1] != wrong_identity.components[1]
    assert first.path != wrong_identity.path
    verifier_command = command_file_session_argv("agentbox-op", first)[-1]
    assert "/bin/bash" in verifier_command
    assert operation_id not in verifier_command
    assert "request:v3:one" not in verifier_command
    assert "sha256:envelope-one" not in verifier_command


def test_materialize_command_file_rejects_tampering_and_symlink_occupancy(
    tmp_path: Path,
) -> None:
    payload = "echo safe"
    binding = materialize_command_file(
        payload,
        durable_root=tmp_path,
        operation_id="op-2",
        request_id="req-2",
        envelope_digest="sha256:env-2",
    )
    binding.path.write_text("echo tampered")
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
    target = _identity_directory(tmp_path, "op-3", "req-3", "sha256:env-3")
    target.mkdir(parents=True, mode=0o700)
    for directory in (target.parent.parent, target.parent, target):
        directory.chmod(0o700)
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


def _run_bound_command(binding, *, cwd: Path) -> subprocess.CompletedProcess[str]:
    shell_command = command_file_session_argv("agentbox-test", binding)[-1]
    return subprocess.run(
        ["/bin/sh", "-c", shell_command],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def test_command_file_verified_fd_executes_exact_payload(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir(mode=0o755)
    binding = materialize_command_file(
        "printf verified-success",
        durable_root=root,
        operation_id="op",
        request_id="req",
        envelope_digest="sha256:env",
    )

    result = _run_bound_command(binding, cwd=tmp_path)

    assert result.returncode == 0, result.stderr
    assert result.stdout == "verified-success"


@pytest.mark.skipif(which("tmux") is None, reason="tmux is not installed")
def test_command_file_real_tmux_executes_bash_boundary_payload_once(
    tmp_path: Path,
) -> None:
    """The fd-bound command seam must run the Bash-shaped launch boundary."""

    command = (
        "set -e; "
        "stub=$(mktemp); "
        "printf '%s\\n' '#!/usr/bin/env bash' "
        "'boundary_stub() {' "
        "'  local value=$1' "
        "'  [[ $value == expected ]] && printf bash-boundary-success' "
        "'}' >\"$stub\"; "
        "source \"$stub\"; "
        "boundary_stub expected; rm -f \"$stub\"; sleep 1; "
        + ("# harmless-long-payload\\n" * 4000)
    )
    assert len(command.encode("utf-8")) > TMUX_COMMAND_INLINE_LIMIT

    # macOS ships a Bash-derived /bin/sh; use dash when /bin/sh is not the
    # POSIX shell used by the production Linux runtime to prove the old seam.
    sh_path = "/bin/sh"
    if Path(sh_path).resolve().name != "dash":
        sh_path = "/bin/dash"
    sh_result = subprocess.run(
        [sh_path, "-c", command],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )
    assert sh_result.returncode != 0

    binding = materialize_command_file(
        command,
        durable_root=tmp_path / "root",
        operation_id="bash-op",
        request_id="bash-req",
        envelope_digest="sha256:bash-env",
    )
    name = session_name(f"bash-boundary-{tmp_path.name}")
    try:
        run_tmux(command_file_session_argv(name, binding, cwd=tmp_path))
        pane = ""
        for _ in range(40):
            pane = run_tmux(capture_pane_argv(name)).stdout
            if "bash-boundary-success" in pane:
                break
            time.sleep(0.05)
        assert "bash-boundary-success" in pane
    finally:
        subprocess.run(
            ["tmux", "kill-session", "-t", name],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )


@pytest.mark.parametrize("mode", (0o775, 0o777))
def test_materialize_command_file_rejects_writable_trusted_root(
    tmp_path: Path, mode: int
) -> None:
    root = tmp_path / "root"
    root.mkdir(mode=mode)
    root.chmod(mode)

    with pytest.raises(ValueError, match="trusted directory"):
        materialize_command_file(
            "echo safe",
            durable_root=root,
            operation_id="op",
            request_id="req",
            envelope_digest="sha256:env",
        )


def test_command_file_ancestor_swap_cannot_escape_or_execute(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    swapped = tmp_path / "held-command-files"

    def swap(stage: str, component: str, _fd: int) -> None:
        if stage == "directory_opened" and component == "command-files":
            (root / component).rename(swapped)
            (root / component).symlink_to(outside, target_is_directory=True)

    monkeypatch.setattr("agentbox.tmux._COMMAND_FILE_TEST_HOOK", swap)
    binding = materialize_command_file(
        "printf owned",
        durable_root=root,
        operation_id="op",
        request_id="req",
        envelope_digest="sha256:env",
    )

    assert not list(outside.rglob("command-*.sh"))
    result = _run_bound_command(binding, cwd=tmp_path)
    assert result.returncode != 0
    assert result.stdout == ""


def test_command_file_final_swap_cannot_redirect_execution(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    attacker = tmp_path / "attacker.sh"
    attacker.write_text("printf attacker", encoding="utf-8")
    attacker.chmod(0o600)

    final_directory = _identity_directory(root, "op", "req", "sha256:env")

    def swap(stage: str, component: str, _fd: int) -> None:
        if stage == "final_verified":
            final_path = final_directory / component
            final_path.rename(final_path.with_suffix(".held"))
            final_path.symlink_to(attacker)

    monkeypatch.setattr("agentbox.tmux._COMMAND_FILE_TEST_HOOK", swap)
    binding = materialize_command_file(
        "printf admitted",
        durable_root=root,
        operation_id="op",
        request_id="req",
        envelope_digest="sha256:env",
    )

    result = _run_bound_command(binding, cwd=tmp_path)
    assert result.returncode != 0
    assert result.stdout == ""


def test_materialize_command_file_rejects_non_private_owned_directory(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    (root / "command-files").mkdir(mode=0o755)
    with pytest.raises(ValueError, match="owner-private"):
        materialize_command_file(
            "echo safe",
            durable_root=root,
            operation_id="op",
            request_id="req",
            envelope_digest="sha256:env",
        )


def test_materialize_command_file_rejects_foreign_directory_owner(
    tmp_path: Path, monkeypatch
) -> None:
    real_uid = os.geteuid()
    monkeypatch.setattr("agentbox.tmux.os.geteuid", lambda: real_uid + 1)
    with pytest.raises(ValueError, match="trusted directory"):
        materialize_command_file(
            "echo safe",
            durable_root=tmp_path,
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
def test_live_tmux_long_command_file_smoke_is_opt_in(tmp_path: Path) -> None:
    name = session_name(f"smoke-{tmp_path.name}")
    command = (
        "printf agentbox-live-smoke;\n"
        + ("# long-payload\n" * 4000)
        + "while :; do sleep 1; done"
    )
    binding = materialize_command_file(
        command,
        durable_root=tmp_path,
        operation_id="live-op",
        request_id="live-req",
        envelope_digest="sha256:live-env",
    )

    try:
        argv = command_file_session_argv(name, binding, cwd=tmp_path)
        assert len(argv[-1].encode("utf-8")) < TMUX_COMMAND_INLINE_LIMIT
        run_tmux(argv)
        status = inspect_session(name)
        assert status == SessionStatus(name, "running", True)
        pane = ""
        for _ in range(20):
            pane = run_tmux(capture_pane_argv(name)).stdout
            if "agentbox-live-smoke" in pane:
                break
            time.sleep(0.05)
        assert "agentbox-live-smoke" in pane
    finally:
        subprocess.run(
            ["tmux", "kill-session", "-t", name],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
