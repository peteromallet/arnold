from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from arnold.runtime.durable_ops import OperationState, ResourceType

from agentbox.config import AgentBoxConfig
from agentbox.git_worktree import has_local_branch
from agentbox.host import launch_host
from agentbox.operations import load_agentbox_operation, open_operation_store
from agentbox.repos import register_repo
from agentbox.run_dirs import read_metadata
from agentbox.tmux import SessionStatus
from agentbox.worktrees import branch_name, worktree_path


def test_launch_host_provisions_all_repos_before_tmux_and_records_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config_with_repos(tmp_path, "app", "infra")
    calls: list[tuple[str, object]] = []

    def fake_start_session(operation_id, command, *, cwd=None, run_paths=None, identity=None):
        calls.append(("start_session", {"cwd": cwd, "stdout": run_paths.stdout_path}))
        assert worktree_path(config, operation_id, "app").exists()
        assert worktree_path(config, operation_id, "infra").exists()
        return "agentbox-op-1"

    monkeypatch.setattr("agentbox.host.start_session", fake_start_session)

    def inspect(name, *, expected_identity=None):
        if expected_identity is None:
            return SessionStatus(name, "missing", False)
        return SessionStatus(
            name,
            "running",
            True,
            operation_id=expected_identity["ARNOLD_LAUNCH_OPERATION_ID"],
            request_id=expected_identity["ARNOLD_LAUNCH_REQUEST_ID"],
            envelope_digest=expected_identity["ARNOLD_LAUNCH_ENVELOPE_DIGEST"],
            process_session_identity=expected_identity["ARNOLD_LAUNCH_PROCESS_IDENTITY"],
            identity_available=True,
        )

    monkeypatch.setattr("agentbox.host.inspect_session", inspect)

    result = launch_host(
        config,
        "op-1",
        command=("python", "-m", "worker"),
        repo_names=("app", "infra"),
    )
    resources = open_operation_store(config).list_typed_resources("op-1")
    run = load_agentbox_operation(config, "op-1")
    events = _events(result.run_paths.events_path)

    assert calls and calls[0][0] == "start_session"
    assert result.launch_state == "accepted"
    assert run.state is OperationState.RUNNING
    assert run.metadata["launch_state"] == "accepted"
    assert run.metadata["session_name"] == "agentbox-op-1"
    assert {resource.resource_type for resource in resources} == {
        ResourceType.GIT_WORKTREE,
        ResourceType.LOG,
        ResourceType.PROCESS_SESSION,
    }
    assert sum(resource.resource_type is ResourceType.GIT_WORKTREE for resource in resources) == 2
    assert sum(resource.resource_type is ResourceType.LOG for resource in resources) == 2
    assert sum(resource.resource_type is ResourceType.PROCESS_SESSION for resource in resources) == 1
    assert read_metadata(result.run_paths)["launch_outcome"] == "ACCEPTED"
    assert [event["event_type"] for event in events] == ["host_launch.accepted"]


def test_launch_host_persists_partial_diagnostics_and_does_not_start_tmux(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config_with_repos(tmp_path, "app", "infra")
    conflicting_branch = branch_name("op-1", "infra")
    infra_repo = config.repos_root / "infra"
    _git(infra_repo, "update-ref", f"refs/remotes/origin/{conflicting_branch}", "HEAD")

    def fail_if_called(*args, **kwargs):
        raise AssertionError("tmux must not start when a repo worktree fails")

    monkeypatch.setattr("agentbox.host.start_session", fail_if_called)

    result = launch_host(config, "op-1", command="echo hi", repo_names=("app", "infra"))

    run = load_agentbox_operation(config, "op-1")
    resources = open_operation_store(config).list_typed_resources("op-1")
    metadata = read_metadata(_run_paths(config, "op-1"))
    events = _events(config.runs_root / "op-1" / "events.ndjson")

    assert result.launch_state == "rejected"
    assert result.diagnostics["reason"] == "dispatch_rejected"
    assert run.state is OperationState.PENDING
    assert "launch_outcome" not in metadata
    assert {resource.resource_type for resource in resources} == {
        ResourceType.GIT_WORKTREE,
        ResourceType.LOG,
    }
    assert sum(resource.resource_type is ResourceType.PROCESS_SESSION for resource in resources) == 0
    assert events[-1]["event_type"] == "host_launch.outcome"


def test_launch_host_retry_reuses_successful_worktree_after_partial_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config_with_repos(tmp_path, "app", "infra")
    infra_repo = config.repos_root / "infra"
    conflicting_branch = branch_name("op-1", "infra")
    _git(infra_repo, "update-ref", f"refs/remotes/origin/{conflicting_branch}", "HEAD")
    monkeypatch.setattr(
        "agentbox.host.start_session",
        lambda *args, **kwargs: "agentbox-op-1",
    )
    monkeypatch.setattr(
        "agentbox.host.inspect_session",
        lambda name, *, expected_identity=None: (
            SessionStatus(name, "missing", False)
            if expected_identity is None
            else SessionStatus(
                name,
                "running",
                True,
                operation_id=expected_identity["ARNOLD_LAUNCH_OPERATION_ID"],
                request_id=expected_identity["ARNOLD_LAUNCH_REQUEST_ID"],
                envelope_digest=expected_identity["ARNOLD_LAUNCH_ENVELOPE_DIGEST"],
                process_session_identity=expected_identity["ARNOLD_LAUNCH_PROCESS_IDENTITY"],
                identity_available=True,
            )
        ),
    )

    first = launch_host(config, "op-1", command="echo hi", repo_names=("app", "infra"))
    assert first.launch_state == "rejected"
    first_resources = open_operation_store(config).list_typed_resources("op-1")
    first_app_resource = [
        resource for resource in first_resources
        if resource.resource_type is ResourceType.GIT_WORKTREE
        and resource.details["repo_name"] == "app"
    ][0]

    _git(infra_repo, "update-ref", "-d", f"refs/remotes/origin/{conflicting_branch}")
    result = launch_host(config, "op-1", command="echo hi", repo_names=("app", "infra"))
    resources = open_operation_store(config).list_typed_resources("op-1")
    app_resource = [
        resource for resource in resources
        if resource.resource_type is ResourceType.GIT_WORKTREE
        and resource.details["repo_name"] == "app"
    ][0]

    assert result.launch_state == "unknown"
    assert result.worktrees == ()
    assert app_resource == first_app_resource
    assert load_agentbox_operation(config, "op-1").state is OperationState.PENDING


def test_launch_host_records_tmux_failure_without_marking_running(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config_with_repos(tmp_path, "app")

    def fail_start(*args, **kwargs):
        raise RuntimeError("tmux unavailable")

    monkeypatch.setattr("agentbox.host.start_session", fail_start)

    result = launch_host(config, "op-1", command="echo hi", repo_names=("app",))

    run = load_agentbox_operation(config, "op-1")
    resources = open_operation_store(config).list_typed_resources("op-1")

    assert result.launch_state == "rejected"
    assert result.diagnostics["reason"] == "dispatch_rejected"
    assert run.state is OperationState.PENDING
    assert sum(resource.resource_type is ResourceType.PROCESS_SESSION for resource in resources) == 0


def _config_with_repos(tmp_path: Path, *repo_names: str) -> AgentBoxConfig:
    config = AgentBoxConfig(workspace_root=tmp_path / "workspace")
    for repo_name in repo_names:
        repo = _init_repo(config.repos_root / repo_name)
        register_repo(config, repo_name, path=repo)
    return config


def _init_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    _git(path, "init", "-b", "main")
    _git(path, "config", "user.email", "agentbox@example.test")
    _git(path, "config", "user.name", "AgentBox Tests")
    (path / "README.md").write_text("# test\n", encoding="utf-8")
    _git(path, "add", "README.md")
    _git(path, "commit", "-m", "initial")
    return path


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ("git", *args),
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()


def _events(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def _run_paths(config: AgentBoxConfig, operation_id: str):
    from agentbox.run_dirs import run_dir_paths

    return run_dir_paths(config, operation_id)
