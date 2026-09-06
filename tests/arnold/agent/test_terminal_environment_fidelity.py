"""Focused B2.1 regressions for task-bound terminal environments."""

import json
import threading
import time
from pathlib import Path

import pytest


@pytest.fixture
def terminal_state():
    from arnold.agent.tools import terminal_tool as terminal
    from arnold.agent.tools import file_tools

    terminal.cleanup_all_environments()
    file_tools.clear_file_ops_cache()
    terminal._task_env_overrides.clear()
    yield terminal, file_tools
    terminal.cleanup_all_environments()
    file_tools.clear_file_ops_cache()
    terminal._task_env_overrides.clear()


def _pwd(terminal, task_id: str, **kwargs) -> str:
    result = json.loads(terminal.terminal_tool("pwd", task_id=task_id, **kwargs))
    assert result["error"] is None
    assert result["exit_code"] == 0
    return result["output"]


def test_task_override_owns_cwd_across_global_config_changes(
    tmp_path: Path, monkeypatch, terminal_state
) -> None:
    terminal, _ = terminal_state
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    monkeypatch.setattr(
        "arnold.agent.tools.sandbox.get_sandbox_cwd", lambda: None,
    )
    monkeypatch.setenv("TERMINAL_CWD", str(second))
    terminal.register_task_env_overrides("task-one", {"cwd": str(first)})
    assert _pwd(terminal, "task-one") == str(first)
    monkeypatch.setenv("TERMINAL_CWD", str(second))
    assert _pwd(terminal, "task-one") == str(first)


def test_distinct_task_file_ops_keep_their_task_bound_directories(
    tmp_path: Path, monkeypatch, terminal_state
) -> None:
    terminal, file_tools = terminal_state
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    monkeypatch.setattr(
        "arnold.agent.tools.sandbox.get_sandbox_cwd", lambda: None,
    )
    monkeypatch.setenv("TERMINAL_CWD", str(second))
    terminal.register_task_env_overrides("task-first", {"cwd": str(first)})
    terminal.register_task_env_overrides("task-second", {"cwd": str(second)})

    first_ops = file_tools._get_file_ops("task-first")
    second_ops = file_tools._get_file_ops("task-second")
    assert first_ops is not second_ops
    assert first_ops.write_file("marker.txt", "first").error is None
    assert second_ops.write_file("marker.txt", "second").error is None
    assert (first / "marker.txt").read_text() == "first"
    assert (second / "marker.txt").read_text() == "second"
    assert _pwd(terminal, "task-first") == str(first)
    assert _pwd(terminal, "task-second") == str(second)


def test_explicit_workdir_does_not_replace_task_cwd(
    tmp_path: Path, monkeypatch, terminal_state
) -> None:
    terminal, _ = terminal_state
    task_dir = tmp_path / "task"
    explicit_dir = tmp_path / "explicit"
    task_dir.mkdir()
    explicit_dir.mkdir()
    monkeypatch.setattr(
        "arnold.agent.tools.sandbox.get_sandbox_cwd", lambda: None,
    )
    terminal.register_task_env_overrides("task", {"cwd": str(task_dir)})
    assert _pwd(terminal, "task", workdir=str(explicit_dir)) == str(explicit_dir)
    assert _pwd(terminal, "task") == str(task_dir)


def test_persistent_shell_keeps_directory_and_cleanup_removes_session(
    tmp_path: Path, monkeypatch, terminal_state
) -> None:
    terminal, _ = terminal_state
    task_dir = tmp_path / "task"
    child_dir = task_dir / "child"
    task_dir.mkdir()
    child_dir.mkdir()
    monkeypatch.setattr(
        "arnold.agent.tools.sandbox.get_sandbox_cwd", lambda: None,
    )
    monkeypatch.setenv("TERMINAL_LOCAL_PERSISTENT", "true")
    terminal.register_task_env_overrides("persistent", {"cwd": str(task_dir)})
    assert _pwd(terminal, "persistent") == str(task_dir)
    # A shell cd is persistent across subsequent calls.
    assert json.loads(
        terminal.terminal_tool("cd child", task_id="persistent")
    )["exit_code"] == 0
    assert _pwd(terminal, "persistent") == str(child_dir)
    environment = terminal._active_environments["persistent"]
    session_prefix = environment._temp_prefix
    terminal.cleanup_vm("persistent")
    assert "persistent" not in terminal._active_environments
    assert not Path(f"{session_prefix}-stdout").exists()


def test_invalid_config_is_rejected_before_cached_file_ops_return(
    tmp_path: Path, monkeypatch, terminal_state
) -> None:
    terminal, file_tools = terminal_state
    task_dir = tmp_path / "task"
    task_dir.mkdir()
    monkeypatch.setattr(
        "arnold.agent.tools.sandbox.get_sandbox_cwd", lambda: None,
    )
    terminal.register_task_env_overrides("cached", {"cwd": str(task_dir)})
    file_tools._get_file_ops("cached")
    monkeypatch.setenv("TERMINAL_TIMEOUT", "not-an-integer")
    with pytest.raises(ValueError, match="Invalid value for TERMINAL_TIMEOUT"):
        file_tools._get_file_ops("cached")


def test_interruption_returns_130_and_cleanup_remains_available(tmp_path: Path) -> None:
    from arnold.agent.tools.environments.local import LocalEnvironment
    from arnold.agent.tools.interrupt import set_interrupt

    for persistent in (False, True):
        environment = LocalEnvironment(
            cwd=str(tmp_path), timeout=10, persistent=persistent,
        )
        result = {}
        worker = threading.Thread(
            target=lambda: result.update(environment.execute("sleep 5")),
        )
        try:
            worker.start()
            time.sleep(0.25)
            set_interrupt(True)
            worker.join(timeout=5)
            assert not worker.is_alive()
            assert result["returncode"] == 130
        finally:
            set_interrupt(False)
            environment.cleanup()
