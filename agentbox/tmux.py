"""Tmux process-session helpers for AgentBox host runs."""

from __future__ import annotations

from dataclasses import dataclass
import re
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

from arnold.runtime.durable_ops import (
    ResourceType,
    TypedResource,
    TypedResourceAlreadyExists,
)

from agentbox.config import AgentBoxConfig
from agentbox.operations import open_operation_store
from agentbox.run_dirs import RunDirPaths


TMUX_BIN = "tmux"


class TmuxError(RuntimeError):
    """Raised for tmux command failures that are not structured statuses."""


@dataclass(frozen=True)
class TmuxResult:
    """Completed tmux invocation details."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class SessionStatus:
    """Structured process-session status."""

    session_name: str
    state: str
    exists: bool
    detail: str | None = None
    operation_id: str | None = None
    request_id: str | None = None
    envelope_digest: str | None = None
    process_session_identity: str | None = None
    identity_available: bool = False


def session_name(operation_id: str) -> str:
    """Return a deterministic tmux-safe session name for an operation."""

    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "-", operation_id).strip("-")
    if not normalized:
        normalized = "operation"
    return f"agentbox-{normalized}"[:80]


def new_session_argv(
    name: str,
    command: Sequence[str] | str,
    *,
    cwd: Path | str | None = None,
    stdout_path: Path | str | None = None,
    stderr_path: Path | str | None = None,
    environment: Mapping[str, str] | None = None,
) -> list[str]:
    """Build argv for a detached tmux session."""

    argv = [TMUX_BIN, "new-session", "-d", "-s", name]
    if cwd is not None:
        argv.extend(["-c", str(cwd)])
    for key, value in sorted((environment or {}).items()):
        argv.extend(["-e", f"{key}={value}"])
    argv.append(_command_for_shell(command, stdout_path=stdout_path, stderr_path=stderr_path))
    return argv


def has_session_argv(name: str) -> list[str]:
    return [TMUX_BIN, "has-session", "-t", name]


def show_environment_argv(name: str) -> list[str]:
    return [TMUX_BIN, "show-environment", "-t", name]


def capture_pane_argv(name: str, *, lines: int = 200) -> list[str]:
    return [TMUX_BIN, "capture-pane", "-p", "-t", name, "-S", f"-{lines}"]


def attach_argv(name: str) -> list[str]:
    return [TMUX_BIN, "attach-session", "-t", name]


def stop_argv(name: str) -> list[str]:
    return [TMUX_BIN, "send-keys", "-t", name, "C-c"]


def send_keys_argv(name: str, keys: Sequence[str]) -> list[str]:
    return [TMUX_BIN, "send-keys", "-t", name, *keys]


def run_tmux(argv: Sequence[str], *, check: bool = True) -> TmuxResult:
    """Run a tmux argv-list command with captured output."""

    completed = subprocess.run(
        list(argv),
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    result = TmuxResult(
        argv=tuple(argv),
        returncode=completed.returncode,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
    )
    if check and result.returncode != 0:
        raise TmuxError(result.stderr or result.stdout or f"tmux exited {result.returncode}")
    return result


def start_session(
    operation_id: str,
    command: Sequence[str] | str,
    *,
    cwd: Path | str | None = None,
    run_paths: RunDirPaths | None = None,
    identity: Mapping[str, str] | None = None,
) -> str:
    """Start a detached tmux session and return its deterministic name."""

    name = session_name(operation_id)
    run_tmux(
        new_session_argv(
            name,
            command,
            cwd=cwd,
            stdout_path=run_paths.stdout_path if run_paths else None,
            stderr_path=run_paths.stderr_path if run_paths else None,
            environment=identity,
        )
    )
    return name


def inspect_session(name: str, *, expected_identity: Mapping[str, str] | None = None) -> SessionStatus:
    """Return live state and exact tmux-provided launch identity.

    The tmux server environment is the query surface.  No marker, receipt, or
    sidecar file is consulted; missing or mismatched identity is unavailable.
    """

    result = run_tmux(has_session_argv(name), check=False)
    if result.returncode == 0 and expected_identity is None:
        return SessionStatus(session_name=name, state="running", exists=True)
    if result.returncode == 0:
        env_result = run_tmux(show_environment_argv(name), check=False)
        if env_result.returncode != 0:
            return SessionStatus(
                session_name=name,
                state="unavailable",
                exists=True,
                detail=env_result.stderr or env_result.stdout or "tmux identity query failed",
            )
        values: dict[str, str] = {}
        for line in env_result.stdout.splitlines():
            if "=" in line and not line.startswith("-"):
                key, value = line.split("=", 1)
                values[key] = value
        identity = {
            "operation_id": values.get("ARNOLD_LAUNCH_OPERATION_ID"),
            "request_id": values.get("ARNOLD_LAUNCH_REQUEST_ID"),
            "envelope_digest": values.get("ARNOLD_LAUNCH_ENVELOPE_DIGEST"),
            "process_session_identity": values.get("ARNOLD_LAUNCH_PROCESS_IDENTITY"),
        }
        available = all(isinstance(value, str) and value for value in identity.values())
        expected_keys = {
            "operation_id": "ARNOLD_LAUNCH_OPERATION_ID",
            "request_id": "ARNOLD_LAUNCH_REQUEST_ID",
            "envelope_digest": "ARNOLD_LAUNCH_ENVELOPE_DIGEST",
            "process_session_identity": "ARNOLD_LAUNCH_PROCESS_IDENTITY",
        }
        matches = available and all(
            values.get(expected_keys.get(key, key)) == value
            for key, value in (expected_identity or {}).items()
        )
        return SessionStatus(
            session_name=name,
            state="running" if matches else "unavailable",
            exists=True,
            detail=None if matches else "exact launch identity unavailable or mismatched",
            operation_id=identity["operation_id"],
            request_id=identity["request_id"],
            envelope_digest=identity["envelope_digest"],
            process_session_identity=identity["process_session_identity"],
            identity_available=bool(matches),
        )
    detail = result.stderr or result.stdout or None
    if detail and "no server running" in detail.lower():
        return SessionStatus(session_name=name, state="dead", exists=False, detail=detail)
    return SessionStatus(session_name=name, state="missing", exists=False, detail=detail)


def capture_pane(name: str, *, lines: int = 200) -> str:
    """Capture a tmux pane when it exists; raise for missing/dead sessions."""

    status = inspect_session(name)
    if not status.exists:
        raise TmuxError(status.detail or f"session {name!r} is {status.state}")
    return run_tmux(capture_pane_argv(name, lines=lines)).stdout


def stop_session(name: str) -> SessionStatus:
    """Send Ctrl-C to a session if it exists, otherwise return its status."""

    status = inspect_session(name)
    if not status.exists:
        return status
    run_tmux(stop_argv(name))
    return inspect_session(name)


def record_process_session_resource(
    config: AgentBoxConfig,
    operation_id: str,
    *,
    name: str,
    status: SessionStatus,
    details: Mapping[str, Any] | None = None,
    resource_id: str | None = None,
) -> TypedResource:
    """Record a PROCESS_SESSION durable resource for the tmux session."""

    resource = TypedResource(
        id=resource_id or f"{operation_id}:process-session",
        operation_id=operation_id,
        resource_type=ResourceType.PROCESS_SESSION,
        name=name,
        details={
            "provider": "tmux",
            "session_name": name,
            "state": status.state,
            "exists": status.exists,
            **dict(details or {}),
        },
    )
    store = open_operation_store(config)
    try:
        return store.create_typed_resource(resource)
    except TypedResourceAlreadyExists:
        for existing in store.list_typed_resources(operation_id):
            if existing.id == resource.id:
                return existing
        raise


def _command_for_shell(
    command: Sequence[str] | str,
    *,
    stdout_path: Path | str | None,
    stderr_path: Path | str | None,
) -> str:
    if isinstance(command, str):
        rendered = command
    else:
        rendered = " ".join(_shell_quote(part) for part in command)
    if stdout_path is not None:
        rendered += f" >> {_shell_quote(str(stdout_path))}"
    if stderr_path is not None:
        rendered += f" 2>> {_shell_quote(str(stderr_path))}"
    return rendered


def _shell_quote(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_@%+=:,./-]+", value):
        return value
    return "'" + value.replace("'", "'\\''") + "'"


__all__ = [
    "SessionStatus",
    "TmuxError",
    "TmuxResult",
    "attach_argv",
    "capture_pane",
    "capture_pane_argv",
    "has_session_argv",
    "inspect_session",
    "new_session_argv",
    "record_process_session_resource",
    "run_tmux",
    "show_environment_argv",
    "send_keys_argv",
    "session_name",
    "start_session",
    "stop_argv",
    "stop_session",
]
