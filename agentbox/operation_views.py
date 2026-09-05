"""Shared AgentBox operation status and log projections."""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Literal, Sequence

from arnold.runtime.durable_ops import (
    ResourceType,
    TypedResource,
    inspect_launch,
)

from agentbox.adapters import list_operation_adapters
from agentbox.operations import (
    list_agentbox_operations,
    load_agentbox_operation,
    open_operation_store,
)
from agentbox.redaction import redact_payload, redact_text
from agentbox.run_dirs import run_dir_paths
from agentbox.tmux import capture_pane, inspect_session
from agentbox.worktrees import branch_name


LogStream = Literal["stdout", "stderr", "all"]


def launch_custody_view(
    config: Any,
    operation_id: str,
    *,
    observe: Any = None,
) -> dict[str, Any]:
    """Return the canonical launch custody projection without ticking state.

    Unlike ``status_view`` this path never invokes an operation adapter.  It
    reads the existing OperationRun, launch events, and typed resources and
    optionally delegates one non-mutating process/session observation to the
    durable-ops audit operation.
    """

    inspection = inspect_launch(
        operation_id,
        store=open_operation_store(config),
        observe=observe,
    )
    return redact_payload(
        {
            "operation_id": operation_id,
            "result": inspection.result.value,
            "reason": inspection.reason.value,
            "envelope": inspection.envelope.to_json() if inspection.envelope else None,
            "operation": jsonable(inspection.operation),
            "events": [jsonable(event) for event in inspection.events],
            "resources": [jsonable(resource) for resource in inspection.resources],
            "observation": jsonable(dict(inspection.observation))
            if inspection.observation is not None
            else None,
        }
    )


def status_view(config: Any, operation_id: str | None = None) -> dict[str, Any] | list[dict[str, Any]]:
    """Return one or more AgentBox operation status payloads."""

    if operation_id:
        run = load_agentbox_operation(config, operation_id)
        return redact_payload(operation_status(config, _tick_operation_for_status(config, run)))

    return [
        redact_payload(operation_status(config, _tick_operation_for_status(config, run)))
        for run in list_agentbox_operations(config)
    ]


def operation_status(config: Any, run: Any) -> dict[str, Any]:
    """Return the shared status projection for one operation run."""

    resources = open_operation_store(config).list_typed_resources(run.id)
    session_resource = process_session_resource(resources)
    session_status = None
    session_name = (
        resource_session_name(session_resource)
        if session_resource
        else run.metadata.get("session_name")
    )
    if session_name:
        try:
            session_status = inspect_session(str(session_name))
        except FileNotFoundError as exc:
            session_status = {
                "session_name": str(session_name),
                "state": "tmux_unavailable",
                "exists": False,
                "detail": str(exc),
            }
        except Exception as exc:
            session_status = {
                "session_name": str(session_name),
                "state": "inspect_failed",
                "exists": False,
                "detail": str(exc),
            }
    paths = run_dir_paths(config, run.id)
    repo_names = run.metadata.get("repo_names", []) or []
    first_repo = repo_names[0] if repo_names else None
    first_branch = branch_name(run.id, first_repo) if first_repo else None
    pr_info = (run.metadata.get("pr_info") or {}).get(first_repo) or {}
    ci_status = (run.metadata.get("ci_status") or {}).get(first_repo)
    cleanup_state = (run.metadata.get("cleanup_state") or {}).get(first_repo)
    return {
        "operation_id": run.id,
        "operation_type": run.operation_type,
        "operation_state": run.state.value,
        "launch_state": run.metadata.get("launch_state"),
        "command": run.metadata.get("command"),
        "repo_names": repo_names,
        "run_dir": str(paths.root),
        "run_dir_exists": paths.root.exists(),
        "resource_count": len(resources),
        "session": jsonable(session_status),
        "branch": first_branch,
        "pr_number": pr_info.get("number"),
        "pr_url": pr_info.get("url"),
        "ci_status": ci_status,
        "cleanup_state": cleanup_state.get("state") if isinstance(cleanup_state, dict) else cleanup_state,
    }


def logs_view(
    config: Any,
    operation_id: str,
    *,
    lines: int,
    stream: LogStream = "all",
) -> dict[str, Any]:
    """Return bounded logs for an AgentBox operation."""

    run = load_agentbox_operation(config, operation_id)
    resources = open_operation_store(config).list_typed_resources(operation_id)
    selected = ("stdout", "stderr") if stream == "all" else (stream,)
    entries = [
        log_entry(config, operation_id, resources, name, lines=lines)
        for name in selected
    ]

    if not any(entry["text"] for entry in entries):
        fallback = tmux_capture_fallback(run, resources, lines=lines)
        if fallback is not None:
            entries = [fallback]

    return {
        "operation_id": operation_id,
        "lines": lines,
        "logs": entries,
    }


def log_entry(
    config: Any,
    operation_id: str,
    resources: tuple[TypedResource, ...],
    stream: str,
    *,
    lines: int,
) -> dict[str, Any]:
    """Return one bounded log entry for ``stream``."""

    path = log_path(config, operation_id, resources, stream)
    tail = (
        _bounded_tail_text(path, lines)
        if path is not None and path.exists()
        else {"text": "", "returned_lines": 0, "truncated": False}
    )
    return {
        "stream": stream,
        "path": str(path) if path is not None else None,
        "exists": bool(path is not None and path.exists()),
        "text": redact_text(tail["text"]),
        "requested_lines": lines,
        "returned_lines": tail["returned_lines"],
        "truncated": tail["truncated"],
        "source": "file" if path is not None and path.exists() else "missing",
    }


def tmux_capture_fallback(
    run: Any,
    resources: tuple[TypedResource, ...],
    *,
    lines: int,
) -> dict[str, Any] | None:
    """Return bounded tmux pane text when file logs are empty and a session exists."""

    session_resource = process_session_resource(resources)
    session_name = resource_session_name(session_resource) if session_resource else None
    if not session_name:
        return None
    status = inspect_session(session_name)
    if not status.exists:
        return None
    text = capture_pane(session_name, lines=lines)
    return {
        "stream": "tmux",
        "path": None,
        "exists": True,
        "text": redact_text(text),
        "session_name": session_name,
        "operation_id": run.id,
        "requested_lines": lines,
        "returned_lines": _line_count(text),
        "truncated": False,
        "source": "tmux",
    }


def log_path(
    config: Any,
    operation_id: str,
    resources: tuple[TypedResource, ...],
    stream: str,
) -> Path:
    """Return the recorded or conventional log path for ``stream``."""

    for resource in resources:
        if resource.resource_type is ResourceType.LOG and resource.details.get("stream") == stream:
            path = resource.details.get("path")
            if path:
                return Path(str(path))
    paths = run_dir_paths(config, operation_id)
    return paths.stdout_path if stream == "stdout" else paths.stderr_path


def single_process_session_resource(config: Any, operation_id: str) -> TypedResource | None:
    """Return the operation's process-session resource, if any."""

    return process_session_resource(open_operation_store(config).list_typed_resources(operation_id))


def process_session_resource(resources: tuple[TypedResource, ...]) -> TypedResource | None:
    """Return the first process-session resource from ``resources``."""

    for resource in resources:
        if resource.resource_type is ResourceType.PROCESS_SESSION:
            return resource
    return None


def resource_session_name(resource: TypedResource | None) -> str | None:
    """Return the durable tmux session name from a process-session resource."""

    if resource is None:
        return None
    value = resource.details.get("session_name") or resource.name
    return str(value) if value else None


def jsonable(value: Any) -> Any:
    """Return a stable JSON-ready form for common dataclass and enum values."""

    if is_dataclass(value) and not isinstance(value, type):
        return jsonable(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]
    return value


def _tick_operation_for_status(config: Any, run: Any) -> Any:
    registration = _operation_adapter_for_type(run.operation_type)
    if registration is None:
        return run

    handler = registration.load()
    tick = getattr(handler, "tick", None)
    if not callable(tick):
        return run

    updated = tick(config, run.id)
    return updated if getattr(updated, "id", None) == run.id else load_agentbox_operation(
        config,
        run.id,
        operation_types=(registration.operation_type,),
    )


def _operation_adapter_for_type(operation_type: str) -> Any | None:
    for registration in list_operation_adapters():
        if registration.operation_type == operation_type:
            return registration
    return None


def _bounded_tail_text(path: Path, lines: int) -> dict[str, Any]:
    if lines <= 0:
        return {"text": "", "returned_lines": 0, "truncated": path.stat().st_size > 0}

    window: deque[str] = deque(maxlen=lines + 1)
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            window.append(line)

    truncated = len(window) > lines
    if truncated:
        window.popleft()
    text = "".join(window)
    return {
        "text": text,
        "returned_lines": len(window),
        "truncated": truncated,
    }


def _line_count(text: str) -> int:
    if not text:
        return 0
    return len(text.splitlines())


def print_log_entries(entries: Sequence[dict[str, Any]]) -> None:
    """Print log entries in the CLI's human-readable format."""

    for index, entry in enumerate(entries):
        if len(entries) > 1:
            if index:
                print()
            print(f"==> {entry['stream']} <==")
        print(entry["text"], end="" if str(entry["text"]).endswith("\n") else "\n")


__all__ = [
    "LogStream",
    "jsonable",
    "log_entry",
    "log_path",
    "logs_view",
    "operation_status",
    "launch_custody_view",
    "print_log_entries",
    "process_session_resource",
    "resource_session_name",
    "single_process_session_resource",
    "status_view",
    "tmux_capture_fallback",
]
