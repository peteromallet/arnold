"""Canonical local terminal tool.

The agent terminal is deliberately a small local surface. Remote/container
backends and the old top-level ``tools`` import aliases are retired; callers
must use :class:`LocalEnvironment` through this module's factory.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import re
import threading
import time
from typing import Any, Optional

from arnold.agent.agent.redact import redact_sensitive_text
from arnold.agent.tools.ansi_strip import strip_ansi
from arnold.agent.tools.environments.local import LocalEnvironment
from arnold.agent.tools.interrupt import _interrupt_event, is_interrupted
from arnold.agent.tools.registry import registry

logger = logging.getLogger(__name__)
MAX_TOOL_RESULT_CHARS = 50_000


def _truncate_tool_result(output: str, limit: int = MAX_TOOL_RESULT_CHARS) -> str:
    if len(output) <= limit:
        return output
    total = len(output)
    marker = f"\n[truncated {max(0, limit - 40)} of {total} chars]"
    kept = max(0, limit - len(marker))
    marker = f"\n[truncated {kept} of {total} chars]"
    return output[:kept] + marker


_cached_sudo_password = ""
_sudo_password_callback = None
_approval_callback = None


def set_sudo_password_callback(callback):
    global _sudo_password_callback
    _sudo_password_callback = callback


def set_approval_callback(callback):
    global _approval_callback
    _approval_callback = callback


def _prompt_for_sudo_password(timeout_seconds: int = 45) -> str:
    if _sudo_password_callback is not None:
        try:
            return _sudo_password_callback() or ""
        except Exception:
            return ""
    if not os.getenv("HERMES_INTERACTIVE"):
        return ""
    try:
        import getpass
        return getpass.getpass("Sudo password (leave blank to skip): ")
    except (EOFError, KeyboardInterrupt, OSError):
        return ""


def _transform_sudo_command(command: str) -> tuple[str, str | None]:
    """Make sudo consume a password from the private stdin channel."""
    global _cached_sudo_password
    if not re.search(r"\bsudo\b", command):
        return command, None
    password = os.getenv("SUDO_PASSWORD", "") or _cached_sudo_password
    if not password:
        password = _prompt_for_sudo_password()
        if password:
            _cached_sudo_password = password
    if not password:
        return command, None
    return re.sub(r"\bsudo\b", "sudo -S -p ''", command), password + "\n"


def _parse_env_var(name: str, default: str, converter=int, type_label: str = "integer"):
    raw = os.getenv(name, default)
    try:
        return converter(raw)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid value for {name}: {raw!r} (expected {type_label})") from exc


def _get_env_config() -> dict[str, Any]:
    """Read supported terminal configuration without mutating runtime state."""
    env_type = os.getenv("TERMINAL_ENV", "local").strip().lower()
    if env_type != "local":
        raise ValueError(
            f"Unsupported TERMINAL_ENV={env_type!r}; only the local terminal is supported"
        )
    try:
        from arnold.agent.tools.sandbox import get_sandbox_cwd
        sandbox_cwd = get_sandbox_cwd()
    except Exception:
        sandbox_cwd = None
    cwd = str(sandbox_cwd) if sandbox_cwd is not None else os.getenv("TERMINAL_CWD", os.getcwd())
    return {
        "env_type": "local",
        "cwd": cwd,
        "timeout": _parse_env_var("TERMINAL_TIMEOUT", "180"),
        "lifetime_seconds": _parse_env_var("TERMINAL_LIFETIME_SECONDS", "300"),
        "local_persistent": os.getenv("TERMINAL_LOCAL_PERSISTENT", "false").lower() in {"true", "1", "yes"},
    }


_active_environments: dict[str, LocalEnvironment] = {}
_last_activity: dict[str, float] = {}
_env_lock = threading.RLock()
_creation_locks: dict[str, threading.Lock] = {}
_creation_locks_lock = threading.Lock()
_task_env_overrides: dict[str, dict[str, Any]] = {}
_cleanup_thread: threading.Thread | None = None
_cleanup_running = False


def register_task_env_overrides(task_id: str, overrides: dict[str, Any]):
    _task_env_overrides[task_id] = dict(overrides)


def clear_task_env_overrides(task_id: str):
    _task_env_overrides.pop(task_id, None)


def _create_environment(env_type: str, image: str = "", cwd: str = "", timeout: int = 180, **kwargs) -> LocalEnvironment:
    """Create the one supported execution environment."""
    if env_type != "local":
        raise ValueError(f"Unsupported terminal environment: {env_type!r}; use 'local'")
    local_config = kwargs.get("local_config") or {}
    return LocalEnvironment(cwd=cwd or os.getcwd(), timeout=timeout, persistent=bool(local_config.get("persistent", False)))


def _environment_for(task_id: str, *, timeout: int | None = None) -> LocalEnvironment:
    config = _get_env_config()
    task_id = task_id or "default"
    overrides = _task_env_overrides.get(task_id, {})
    cwd = str(overrides.get("cwd") or config["cwd"])
    with _env_lock:
        existing = _active_environments.get(task_id)
        if existing is not None:
            _last_activity[task_id] = time.time()
            return existing
    with _creation_locks_lock:
        lock = _creation_locks.setdefault(task_id, threading.Lock())
    with lock:
        with _env_lock:
            existing = _active_environments.get(task_id)
            if existing is not None:
                _last_activity[task_id] = time.time()
                return existing
        environment = _create_environment(
            "local", cwd=cwd, timeout=timeout or config["timeout"],
            local_config={"persistent": config["local_persistent"]}, task_id=task_id,
        )
        with _env_lock:
            _active_environments[task_id] = environment
            _last_activity[task_id] = time.time()
        return environment


def _check_disk_usage_warning():
    """Retained no-op export for old lifecycle callers; local has no sandbox."""
    return False


def _cleanup_inactive_envs(lifetime_seconds: int = 300):
    now = time.time()
    stale: list[tuple[str, LocalEnvironment]] = []
    with _env_lock:
        for task_id, last_used in list(_last_activity.items()):
            if now - last_used > lifetime_seconds:
                environment = _active_environments.pop(task_id, None)
                _last_activity.pop(task_id, None)
                if environment is not None:
                    stale.append((task_id, environment))
    for task_id, environment in stale:
        try:
            from arnold.agent.tools.file_tools import clear_file_ops_cache
            clear_file_ops_cache(task_id)
        except Exception:
            pass
        try:
            environment.cleanup()
        except Exception:
            logger.warning("Error cleaning local environment for %s", task_id, exc_info=True)


def _cleanup_thread_worker():
    global _cleanup_running
    while _cleanup_running:
        try:
            _cleanup_inactive_envs(_get_env_config()["lifetime_seconds"])
        except Exception:
            logger.debug("Local terminal cleanup skipped", exc_info=True)
        for _ in range(60):
            if not _cleanup_running:
                break
            time.sleep(1)


def _start_cleanup_thread():
    global _cleanup_thread, _cleanup_running
    with _env_lock:
        if _cleanup_thread is None or not _cleanup_thread.is_alive():
            _cleanup_running = True
            _cleanup_thread = threading.Thread(target=_cleanup_thread_worker, daemon=True)
            _cleanup_thread.start()


def _stop_cleanup_thread():
    global _cleanup_running
    _cleanup_running = False
    if _cleanup_thread is not None:
        _cleanup_thread.join(timeout=5)


def get_active_environments_info() -> dict[str, Any]:
    with _env_lock:
        return {
            "count": len(_active_environments),
            "task_ids": list(_active_environments),
            "workdirs": {key: value.cwd for key, value in _active_environments.items()},
            "total_disk_usage_mb": 0.0,
        }


def cleanup_vm(task_id: str):
    with _env_lock:
        environment = _active_environments.pop(task_id, None)
        _last_activity.pop(task_id, None)
    with _creation_locks_lock:
        _creation_locks.pop(task_id, None)
    try:
        from arnold.agent.tools.file_tools import clear_file_ops_cache
        clear_file_ops_cache(task_id)
    except Exception:
        pass
    if environment is not None:
        environment.cleanup()


def cleanup_all_environments():
    with _env_lock:
        task_ids = list(_active_environments)
    cleaned = 0
    for task_id in task_ids:
        try:
            cleanup_vm(task_id)
            cleaned += 1
        except Exception:
            logger.warning("Error cleaning local environment %s", task_id, exc_info=True)
    return cleaned


def _atexit_cleanup():
    _stop_cleanup_thread()
    cleanup_all_environments()


atexit.register(_atexit_cleanup)


def _dangerous_command(command: str) -> bool:
    """Classify commands requiring an external approval authority."""
    return bool(re.search(
        r"(?:^|[;&|]\s*|\s)(?:rm\s+-rf|rmdir\b|mkfs\b|shutdown\b|reboot\b|git\s+(?:push|reset|clean|checkout)\b|sudo\b)",
        command, re.IGNORECASE,
    )) or bool(re.search(r"[^>]>(?!>)", command))


def _check_dangerous_command(command: str, env_type: str) -> dict[str, Any]:
    if not _dangerous_command(command):
        return {"approved": True, "status": "allowed"}
    if _approval_callback is None:
        return {
            "approved": False,
            "status": "approval_required",
            "message": "Command requires approval, but no supported approval authority is available",
            "description": "dangerous local command",
        }
    try:
        decision = _approval_callback(command, "dangerous local command")
    except Exception:
        decision = "deny"
    approved = decision in {"once", "session", "always", True}
    return {
        "approved": approved,
        "status": "allowed" if approved else "blocked",
        "message": "Command denied by approval authority" if not approved else "",
        "description": "dangerous local command",
    }


def _check_all_guards(command: str, env_type: str) -> dict[str, Any]:
    return _check_dangerous_command(command, env_type)


def _handle_sudo_failure(output: str, env_type: str) -> str:
    if os.getenv("HERMES_GATEWAY_SESSION") and "sudo: a password is required" in output:
        return output + "\n\nSet SUDO_PASSWORD in ~/.hermes/.env to enable sudo over messaging."
    return output


def terminal_tool(command: str, background: bool = False, timeout: Optional[int] = None,
                 task_id: Optional[str] = None, force: bool = False,
                 workdir: Optional[str] = None, check_interval: Optional[int] = None,
                 pty: bool = False) -> str:
    """Execute one foreground command in the canonical local environment."""
    try:
        config = _get_env_config()
        if background:
            return json.dumps({
                "output": "", "exit_code": -1,
                "error": "Background terminal processes are unsupported; use a foreground command",
                "status": "unsupported",
            })
        if not isinstance(command, str) or not command.strip():
            return json.dumps({"output": "", "exit_code": -1, "error": "command is required"})
        if not force:
            approval = _check_all_guards(command, "local")
            if not approval.get("approved"):
                return json.dumps({
                    "output": "", "exit_code": -1,
                    "error": approval.get("message", "Command denied"),
                    "status": approval.get("status", "blocked"),
                    "description": approval.get("description", "command flagged"),
                }, ensure_ascii=False)
        effective_timeout = timeout or config["timeout"]
        environment = _environment_for(task_id or "default", timeout=effective_timeout)
        _start_cleanup_thread()
        result = environment.execute(command, cwd=workdir or config["cwd"], timeout=effective_timeout)
        output = _handle_sudo_failure(result.get("output", ""), "local")
        output = redact_sensitive_text(strip_ansi(_truncate_tool_result(output).strip())) if output else ""
        return json.dumps({"output": output, "exit_code": result.get("returncode", 0), "error": None}, ensure_ascii=False)
    except ValueError as exc:
        return json.dumps({"output": "", "exit_code": -1, "error": str(exc), "status": "unsupported"})
    except Exception as exc:
        logger.exception("Local terminal execution failed")
        return json.dumps({"output": "", "exit_code": -1, "error": f"Failed to execute command: {exc}", "status": "error"})


def check_terminal_requirements() -> bool:
    try:
        _get_env_config()
        return True
    except Exception:
        return False


TERMINAL_TOOL_DESCRIPTION = """Execute a foreground shell command on the local environment.
Filesystem persists between calls. Background/process-registry execution and
remote/container environments are unsupported; use a generous timeout for
long-running foreground commands."""

TERMINAL_SCHEMA = {
    "name": "terminal", "description": TERMINAL_TOOL_DESCRIPTION,
    "parameters": {
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "The command to execute locally"},
            "background": {"type": "boolean", "description": "Unsupported; use foreground execution", "default": False},
            "timeout": {"type": "integer", "minimum": 1, "description": "Maximum seconds to wait"},
            "workdir": {"type": "string", "description": "Working directory"},
            "check_interval": {"type": "integer", "minimum": 30, "description": "Unsupported with background execution"},
            "pty": {"type": "boolean", "description": "Unsupported; local foreground execution only", "default": False},
        },
        "required": ["command"],
    },
}


def _handle_terminal(args, **kwargs):
    return terminal_tool(command=args.get("command"), background=args.get("background", False),
                         timeout=args.get("timeout"), task_id=kwargs.get("task_id"),
                         workdir=args.get("workdir"), check_interval=args.get("check_interval"),
                         pty=args.get("pty", False))


registry.register(name="terminal", toolset="terminal", schema=TERMINAL_SCHEMA,
                  handler=_handle_terminal, check_fn=check_terminal_requirements, emoji="💻")
