from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
import subprocess as _subprocess
from pathlib import Path

import pytest

from arnold_pipelines.megaplan.resident import subagent as subagent_module
from arnold_pipelines.megaplan.resident import profile as profile_module
from arnold_pipelines.megaplan.resident.agent_loop import AgentResponse, FakeAgentRunner, FakeAgentStep
from arnold_pipelines.megaplan.resident.auth import AuthorizationSubject, ResidentAuthorizer
from arnold_pipelines.megaplan.resident.config import ResidentConfig
from arnold_pipelines.megaplan.resident.profile import MegaplanResidentProfile
from arnold_pipelines.megaplan.resident.runtime import InboundEvent, ResidentRuntime
from arnold_pipelines.megaplan.resident.provenance import DELEGATION_CONTEXT_ENV
from arnold_pipelines.megaplan.resident.subagent import (
    DELEGATION_DELIVERY_INSTRUCTION_HEADER,
    DELEGATION_DELIVERY_INSTRUCTION_SCHEMA,
    FINAL_SUMMARY_INSTRUCTION,
    ManagedCompletionTurnResult,
    SubagentResult,
    launch_subagent_task,
    list_managed_resident_agents,
    sweep_managed_agent_deliveries,
)
from arnold_pipelines.megaplan.store import FileStore


@pytest.fixture(autouse=True)
def _fake_worker_process_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    """Model only this module's fake worker PID at the OS custody seam."""

    real_start_ticks = subagent_module._pid_start_ticks
    real_pid_live = subagent_module._pid_live
    monkeypatch.setattr(
        subagent_module,
        "_pid_start_ticks",
        lambda pid: "test-start-4321" if pid == 4321 else real_start_ticks(pid),
    )
    monkeypatch.setattr(
        subagent_module,
        "_pid_live",
        lambda pid: True if pid == 4321 else real_pid_live(pid),
    )


def test_local_resident_launch_seam_uses_injected_provenance(tmp_path, monkeypatch, capsys) -> None:
    import arnold_pipelines.megaplan.resident.subagent as module
    from arnold_pipelines.megaplan.resident.provenance import DELEGATION_CONTEXT_ENV

    task_file = tmp_path / "task.md"
    task_file.write_text("do durable work")
    provenance = {
        "schema_version": "arnold-resident-delegation-provenance-v1",
        "applicability": "applicable",
        "transport": "discord",
        "correlation_id": "corr-1",
        "custody_id": "custody-1",
        "resident_conversation_id": "rconv_1",
        "resident_turn_id": "turn_1",
        "source_record_id": "msg_1",
        "conversation_key": "discord:dm:123",
        "discord_message_id": "456",
        "reply_to_message_id": "456",
        "dm_user_id": "123",
        "source_kind": "discord_inbound_message",
    }
    monkeypatch.setenv(DELEGATION_CONTEXT_ENV, json.dumps(provenance))
    observed = {}

    def fake_launch(**kwargs):
        observed.update(kwargs)
        inherited = module.provenance_from_environment(strict=True)
        assert inherited["source_record_id"] == "msg_1"
        return module.SubagentResult(
            ok=True, final_text="", stderr="", returncode=0,
            run_id="run-1", status="running", manifest_path="manifest.json",
        )

    monkeypatch.setattr(module, "launch_codex_subagent_detached", fake_launch)
    rc = module._main([
        "launch", "--task-file", str(task_file), "--project-dir", str(tmp_path),
        "--task-kind", "coding", "--work-intent", "speculative", "--difficulty", "7",
    ])
    assert rc == 0
    assert observed["task"] == "do durable work"
    assert observed["work_intent"] == "speculative"
    assert observed["difficulty"] == 7
    assert json.loads(capsys.readouterr().out)["run_id"] == "run-1"
class _Completed:
    def __init__(self, *, stdout: str, stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


@pytest.fixture(autouse=True)
def _isolate_process_provenance(monkeypatch) -> None:
    """These compatibility tests provide their launch provenance directly."""

    monkeypatch.delenv(DELEGATION_CONTEXT_ENV, raising=False)


def test_builds_argv_and_reads_stdout(tmp_path, monkeypatch) -> None:
    captured: dict = {}

    def fake_run(argv, **kwargs):
        # Cloud-status collection can issue an unrelated ``ps`` while this
        # process-wide subprocess monkeypatch is active. Capture only the
        # omp launcher invocation owned by this test.
        if "--query-file" in argv:
            captured["argv"] = list(argv)
            captured["kwargs"] = kwargs
            qf = argv[argv.index("--query-file") + 1]
            captured["query"] = Path(qf).read_text()
        return _Completed(stdout="FINAL ANSWER\n", stderr="diag", returncode=0)

    monkeypatch.setattr(subagent_module.subprocess, "run", fake_run)

    config = ResidentConfig(
        subagent_model_name="deepseek:deepseek-v4-pro",
        special_requests_subagent_toolsets="file,web",
        special_requests_subagent_max_tokens=12345,
    )
    result = asyncio.run(
        launch_subagent_task(
            config,
            task="hello\nworld",
            project_dir=str(tmp_path),
            backend="omp",
            background=False,
        )
    )

    assert result.ok is True
    assert result.final_text == "FINAL ANSWER"
    assert result.returncode == 0
    argv = captured["argv"]
    assert argv[1].endswith("launch_omp_agent.py")
    assert "--model" in argv and "deepseek:deepseek-v4-pro" in argv
    assert "--toolsets" in argv and "file,web" in argv
    assert "--max-tokens" in argv and "12345" in argv
    assert "--project-dir" in argv and str(tmp_path) in argv
    assert "--query-file" in argv
    assert captured["query"].startswith("hello\nworld\n\n")
    assert captured["query"].count(DELEGATION_DELIVERY_INSTRUCTION_HEADER) == 1
    assert "- resolved work intent: execution" in captured["query"]
    assert "does not authorize push, remote merge, deployment, restart" in captured["query"]
    assert FINAL_SUMMARY_INSTRUCTION in captured["query"]
    # query file cleaned up after the run
    qf = argv[argv.index("--query-file") + 1]
    assert not Path(qf).exists()


def test_nonzero_exit_is_failure(monkeypatch) -> None:
    monkeypatch.setattr(
        subagent_module.subprocess,
        "run",
        lambda argv, **kw: _Completed(stdout="", stderr="boom", returncode=6),
    )
    result = asyncio.run(
        launch_subagent_task(ResidentConfig(), task="x", backend="omp", background=False)
    )
    assert result.ok is False
    assert result.returncode == 6
    assert "exit 6" in (result.error or "")


def test_empty_stdout_is_failure(monkeypatch) -> None:
    monkeypatch.setattr(
        subagent_module.subprocess,
        "run",
        lambda argv, **kw: _Completed(stdout="   \n", stderr="", returncode=0),
    )
    result = asyncio.run(
        launch_subagent_task(ResidentConfig(), task="x", backend="omp", background=False)
    )
    assert result.ok is False


def test_timeout_is_failure(monkeypatch) -> None:
    def raise_timeout(argv, **kw):
        raise _subprocess.TimeoutExpired(cmd=argv, timeout=0.01)

    monkeypatch.setattr(subagent_module.subprocess, "run", raise_timeout)
    result = asyncio.run(
        launch_subagent_task(ResidentConfig(), task="x", backend="omp", background=False)
    )
    assert result.ok is False
    assert "timed out" in (result.error or "")


def test_missing_launcher_raises(tmp_path) -> None:
    config = ResidentConfig()
    monkeypatch_path = tmp_path / "ghost.py"
    # Point the module's OMP_LAUNCHER_PATH at a non-existent file.
    original = subagent_module.OMP_LAUNCHER_PATH
    subagent_module.OMP_LAUNCHER_PATH = monkeypatch_path
    try:
        with pytest.raises(FileNotFoundError):
            asyncio.run(
                launch_subagent_task(config, task="x", backend="omp", background=False)
            )
    finally:
        subagent_module.OMP_LAUNCHER_PATH = original


def test_codex_background_launch_writes_durable_manifest(tmp_path, monkeypatch) -> None:
    captured: dict = {}

    class _Process:
        pid = 4321

        def poll(self):
            return None

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _Process()

    monkeypatch.setattr(subagent_module.subprocess, "Popen", fake_popen)
    monkeypatch.chdir(tmp_path)
    source_record_id = "msg_durablelaunch1"
    messages_dir = tmp_path / ".megaplan/resident/messages"
    messages_dir.mkdir(parents=True)
    (messages_dir / f"{source_record_id}.json").write_text(
        json.dumps(
            {
                "id": source_record_id,
                "conversation_id": "rconv_conversation1",
                "direction": "inbound",
                "discord_message_id": "987",
            }
        )
    )
    result = asyncio.run(
        launch_subagent_task(
            ResidentConfig(model_name="gpt-5.6-terra"),
            task="do the work",
            project_dir=str(tmp_path),
            model="gpt-5.6-terra",
            reasoning_effort="xhigh",
            launch_origin={
                "transport": "discord",
                "conversation_id": "rconv_conversation1",
                "conversation_key": "discord:guild:12:channel:34:thread:56",
                "message_id": "987",
                "reply_to_message_id": "987",
                "guild_id": "12",
                "channel_id": "34",
                "thread_id": "56",
                "dm_user_id": None,
                "source_record_id": source_record_id,
            },
        )
    )

    assert result.ok is True
    assert result.status == "running"
    assert result.pid == 4321
    manifest = json.loads(Path(result.manifest_path).read_text())
    assert manifest["schema_version"] == "arnold-managed-agent-run-v2"
    assert manifest["run_kind"] == "resident_delegated_agent"
    assert manifest["custodian"] == "arnold.megaplan.managed_agent"
    assert manifest["supervisor_start_ticks"] == "test-start-4321"
    assert manifest["sandbox"] == "danger-full-access"
    assert manifest["model"] == "gpt-5.6-terra"
    assert manifest["task_kind"] == "routine"
    assert manifest["difficulty"] == 4
    assert manifest["route_class"] == "explicit_override"
    assert manifest["status"] == "running"
    assert manifest["manifest_path"] == result.manifest_path
    assert manifest["full_log_path"] == result.log_path
    assert Path(manifest["result_path"]).is_file()
    prompt = Path(manifest["prompt_path"]).read_text()
    assert prompt.startswith("do the work\n\n")
    assert prompt.count(DELEGATION_DELIVERY_INSTRUCTION_HEADER) == 1
    assert "- resolved work intent: execution" in prompt
    assert manifest["work_intent"] == "execution"
    instruction = manifest["delegation_delivery_instruction"]
    assert instruction["schema_version"] == DELEGATION_DELIVERY_INSTRUCTION_SCHEMA
    assert instruction["resolved_work_intent"] == "execution"
    assert len(instruction["sha256"]) == 64
    assert "[Delegated context directory]" in prompt
    assert "full resident/cloud/conversation state is deliberately not embedded" in prompt
    assert "resident context --node root" in prompt
    assert "context-search --scope '<scope>'" in prompt
    assert manifest["context_directory"]["project_worktree"] == str(tmp_path)
    assert manifest["context_directory"]["resident_conversation_id"] == "rconv_conversation1"
    assert "resident_runtime_source" in manifest["context_directory"]
    assert manifest["git_custody"]["schema_version"] == "arnold-resident-git-custody-v1"
    assert manifest["git_custody"]["evidence_path"].endswith("git-custody-evidence.json")
    assert "[Git implementation custody contract — deterministic v1]" in prompt
    assert "implementation.base_revision is the actual feature base" in prompt
    assert "only with strict containment proof" in prompt
    assert "Missing or inconsistent evidence fails the delegated run" in prompt
    assert FINAL_SUMMARY_INSTRUCTION in prompt
    assert manifest["discord_origin"]["conversation_key"] == "discord:guild:12:channel:34:thread:56"
    assert manifest["discord_origin"]["reply_to_message_id"] == "987"
    assert manifest["completion_delivery"]["status"] == "pending"
    assert manifest["completion_delivery"]["attempt_count"] == 0
    assert manifest["completion_delivery"]["outbox_id"].startswith("discord-outbox-")
    assert manifest["correlation_id"].startswith("discord-corr-")
    assert manifest["custody_id"].startswith("discord-custody-")
    assert manifest["source_record_id"] == source_record_id
    assert "arnold_pipelines.megaplan.resident.subagent_worker" in captured["argv"]
    assert captured["kwargs"]["stdin"] is _subprocess.DEVNULL
    assert captured["kwargs"]["start_new_session"] is True


def test_managed_launch_rejects_oversized_task_before_creating_run(tmp_path) -> None:
    with pytest.raises(ValueError, match="delegated task exceeds"):
        asyncio.run(
            launch_subagent_task(
                ResidentConfig(),
                task="x" * (subagent_module.MAX_DELEGATED_TASK_CHARS + 1),
                project_dir=str(tmp_path),
            )
        )

    assert not (tmp_path / ".megaplan/plans/resident-subagents").exists()


def test_scheduled_standalone_dm_manifest_has_no_reply_or_source_custody(
    tmp_path, monkeypatch
) -> None:
    class _Process:
        pid = 4321

        def poll(self):
            return None

    monkeypatch.setattr(subagent_module.subprocess, "Popen", lambda *args, **kwargs: _Process())
    result = asyncio.run(
        launch_subagent_task(
            ResidentConfig(model_name="gpt-test"),
            task="inspect scheduled state",
            project_dir=str(tmp_path),
            request_id="occ_standalone_1",
            launch_origin={"applicability": "not_applicable", "source_kind": "schedule"},
            schedule_context={
                "schema_version": "arnold-resident-schedule-occurrence-v1",
                "schedule_id": "sched_standalone_dm",
                "schedule_revision": 1,
                "generation": 1,
                "occurrence_id": "occ_standalone_1",
                "occurrence_key": "sha256:test",
                "nominal_at": "2026-07-20T08:00:00+00:00",
                "authorization_digest": "sha256:auth",
                "pinned_definition_digest": "sha256:def",
                "delivery": {"mode": "standalone", "route_ref": "discord:dm:42"},
            },
        )
    )

    manifest = json.loads(Path(result.manifest_path).read_text())
    assert manifest["launch_provenance"]["applicability"] == "not_applicable"
    assert manifest["discord_delivery_target"] == {
        "transport": "discord",
        "conversation_key": "discord:dm:42",
        "mode": "standalone",
    }
    assert "discord_origin" not in manifest
    assert "source_record_id" not in manifest
    assert manifest["completion_delivery"]["destination"] == {
        "conversation_key": "discord:dm:42"
    }
    assert "reply_target" not in manifest["completion_delivery"]


def test_codex_background_launch_resolves_resident_message_record_to_discord_id(
    tmp_path, monkeypatch
) -> None:
    record_id = "msg_d850bec6f741"
    messages_dir = tmp_path / ".megaplan/resident/messages"
    messages_dir.mkdir(parents=True)
    (messages_dir / f"{record_id}.json").write_text(
        json.dumps(
            {
                "id": record_id,
                "conversation_id": "rconv_conversation1",
                "direction": "inbound",
                "discord_message_id": "1525241553721884822",
            }
        )
    )

    class _Process:
        pid = 4321

    monkeypatch.setattr(subagent_module.subprocess, "Popen", lambda *args, **kwargs: _Process())
    monkeypatch.chdir(tmp_path)
    result = asyncio.run(
        launch_subagent_task(
            ResidentConfig(model_name="gpt-test"),
            task="do the work",
            project_dir=str(tmp_path),
            launch_origin={
                "transport": "discord",
                "conversation_id": "rconv_conversation1",
                "conversation_key": "discord:dm:42",
                "message_id": record_id,
                "reply_to_message_id": record_id,
                "channel_id": "42",
                "dm_user_id": "42",
            },
        )
    )

    manifest = json.loads(Path(result.manifest_path).read_text())
    assert manifest["discord_origin"]["message_id"] == "1525241553721884822"
    assert manifest["discord_origin"]["reply_to_message_id"] == "1525241553721884822"
    assert manifest["discord_origin"]["reply_target_source_record_id"] == record_id


def test_codex_background_launch_recovers_origin_from_resident_request_id(
    tmp_path, monkeypatch
) -> None:
    record_id = "msg_request1234"
    _resident_discord_request(
        tmp_path,
        message_id=record_id,
        discord_message_id="1525245026865778718",
    )

    class _Process:
        pid = 4321

    monkeypatch.setattr(subagent_module.subprocess, "Popen", lambda *args, **kwargs: _Process())
    monkeypatch.chdir(tmp_path)
    result = asyncio.run(
        launch_subagent_task(
            ResidentConfig(model_name="gpt-test"),
            task="do the work",
            project_dir=str(tmp_path),
            request_id=record_id,
        )
    )

    manifest = json.loads(Path(result.manifest_path).read_text())
    assert {
        key: manifest["discord_origin"][key]
        for key in (
            "transport", "conversation_id", "conversation_key", "message_id",
            "reply_to_message_id", "guild_id", "channel_id", "thread_id",
            "dm_user_id", "reply_target_source_record_id",
        )
    } == {
        "transport": "discord",
        "conversation_id": "rconv_conversation1",
        "conversation_key": "discord:dm:42",
        "message_id": "1525245026865778718",
        "reply_to_message_id": "1525245026865778718",
        "guild_id": None,
        "channel_id": "42",
        "thread_id": None,
        "dm_user_id": "42",
        "reply_target_source_record_id": record_id,
    }
    serialized_origin = json.dumps(manifest["discord_origin"])
    assert "must not be copied" not in serialized_origin
    assert "must-not-be-copied" not in serialized_origin


def test_codex_background_launch_rejects_unresolvable_non_discord_reply_id(
    tmp_path, monkeypatch
) -> None:
    popen_called = False

    def fake_popen(*args, **kwargs):
        nonlocal popen_called
        popen_called = True
        raise AssertionError("invalid provenance must fail before launch")

    monkeypatch.setattr(subagent_module.subprocess, "Popen", fake_popen)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError, match="exact, resolvable reply target"):
        asyncio.run(
            launch_subagent_task(
                ResidentConfig(model_name="gpt-test"),
                task="do the work",
                project_dir=str(tmp_path),
                launch_origin={
                    "transport": "discord",
                    "conversation_id": "rconv_conversation1",
                    "conversation_key": "discord:dm:42",
                    "message_id": "msg_missing1234",
                    "reply_to_message_id": "msg_missing1234",
                },
            )
        )

    assert popen_called is False
    assert not (tmp_path / ".megaplan/plans/resident-subagents").exists()


def test_codex_worker_finalizes_manifest_with_actual_worker_pid(tmp_path, monkeypatch) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    prompt_path = run_dir / "prompt.md"
    result_path = run_dir / "result.md"
    manifest_path = run_dir / "manifest.json"
    prompt_path.write_text("do it")
    manifest_path.write_text(json.dumps({
        "schema_version": "arnold-resident-agent-run-v1",
        "run_kind": "resident_delegated_agent",
        "custodian": "arnold.megaplan.resident",
        "status": "running",
        "pid": 111,
        "prompt_path": str(prompt_path),
        "result_path": str(result_path),
        "project_dir": str(tmp_path),
        "model": "gpt-test",
        "reasoning_effort": "xhigh",
    }))

    class _Worker:
        pid = 222

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

    monkeypatch.setattr(subagent_module.subprocess, "Popen", lambda *args, **kwargs: _Worker())

    assert subagent_module._run_codex_manifest(manifest_path) == 0

    manifest = json.loads(manifest_path.read_text())
    assert manifest["pid"] == 111
    assert manifest["worker_pid"] == 222
    assert manifest["status"] == "completed"
    assert manifest["returncode"] == 0
    assert manifest["finished_at"]
    assert result_path.is_file()


@pytest.mark.parametrize("control_status", ["cancelled", "superseded"])
def test_codex_worker_preserves_manifest_bound_control_terminal_on_signal_race(
    tmp_path, monkeypatch, control_status
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    prompt_path = run_dir / "prompt.md"
    result_path = run_dir / "result.md"
    manifest_path = run_dir / "manifest.json"
    prompt_path.write_text("do it")
    manifest_path.write_text(json.dumps({
        "schema_version": "arnold-resident-agent-run-v1",
        "run_kind": "resident_delegated_agent",
        "custodian": "arnold.megaplan.resident",
        "status": "running",
        "pid": 111,
        "prompt_path": str(prompt_path),
        "result_path": str(result_path),
        "project_dir": str(tmp_path),
        "model": "gpt-test",
        "reasoning_effort": "xhigh",
    }))

    class _Worker:
        pid = 222

        def wait(self, timeout=None):
            manifest = json.loads(manifest_path.read_text())
            manifest.update({
                "status": control_status,
                "terminal_outcome": control_status,
                "finished_at": "2026-07-15T10:41:38+00:00",
                "returncode": 143,
                "status_history": [{
                    "status": control_status,
                    "at": "2026-07-15T10:41:38+00:00",
                    "evidence": "managed_agent_explicit_transition",
                }],
            })
            manifest_path.write_text(json.dumps(manifest))
            raise KeyboardInterrupt

        def poll(self):
            return 0

    monkeypatch.setattr(subagent_module.subprocess, "Popen", lambda *args, **kwargs: _Worker())

    assert subagent_module._run_codex_manifest(manifest_path) == 143
    manifest = json.loads(manifest_path.read_text())
    assert manifest["status"] == control_status
    assert manifest["terminal_outcome"] == control_status
    assert manifest["finished_at"] == "2026-07-15T10:41:38+00:00"
    assert manifest["status_history"][-1]["evidence"] == (
        "managed_codex_supervisor_acknowledged_control_terminal"
    )


def test_managed_agent_hot_context_separates_running_and_recent(tmp_path, monkeypatch) -> None:
    run_root = tmp_path / ".megaplan/plans/resident-subagents"
    running = run_root / "running"
    completed = run_root / "completed"
    running.mkdir(parents=True)
    completed.mkdir(parents=True)
    (running / "manifest.json").write_text(json.dumps({
        "schema_version": "arnold-resident-agent-run-v1",
        "run_kind": "resident_delegated_agent",
        "custodian": "arnold.megaplan.resident",
        "run_id": "running",
        "status": "running",
        "pid": 123,
        "created_at": "2026-07-10T02:00:00Z",
        "usage": {"total_tokens": 12_345},
        "log_path": "/logs/running.log",
    }))
    (completed / "manifest.json").write_text(json.dumps({
        "schema_version": "arnold-resident-agent-run-v1",
        "run_kind": "resident_delegated_agent",
        "custodian": "arnold.megaplan.resident",
        "run_id": "completed",
        "status": "completed",
        "created_at": "2026-07-10T01:00:00Z",
        "log_path": "/logs/completed.log",
        "discord_origin": {
            "transport": "discord",
            "conversation_key": "discord:dm:42",
            "reply_to_message_id": "1001",
        },
        "completion_delivery": {
            "transport": "discord",
            "status": "delivered",
            "discord_message_ids": ["reply-1"],
        },
    }))
    monkeypatch.setattr(subagent_module, "_pid_matches_manifest", lambda pid, path: pid == 123)

    status = list_managed_resident_agents(project_root=tmp_path, workspace_root=None)

    assert status["running_count"] == 1
    assert status["running"][0]["run_id"] == "running"
    assert status["running"][0]["usage"] == {"total_tokens": 12_345}
    assert status["running"][0]["full_log_path"] == "/logs/running.log"
    assert status["recent"][0]["run_id"] == "completed"
    assert status["recent"][0]["completion_delivery"]["status"] == "delivered"
    assert status["recent_total_count"] == 1
    assert status["recent_omitted_count"] == 0
    assert status["delivery_status_counts"] == {"not_applicable": 1, "delivered": 1}
    assert status["terminal_delivery_status_counts"] == {"delivered": 1}
    assert status["delivery_attention_count"] == 0


def test_managed_agent_inventory_accounts_for_bounded_recent_rows(tmp_path) -> None:
    run_root = tmp_path / ".megaplan/plans/resident-subagents"
    for index in range(3):
        run_dir = run_root / f"completed-{index}"
        run_dir.mkdir(parents=True)
        (run_dir / "manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": "arnold-resident-agent-run-v1",
                    "run_kind": "resident_delegated_agent",
                    "custodian": "arnold.megaplan.resident",
                    "run_id": f"completed-{index}",
                    "status": "completed",
                    "created_at": f"2026-07-10T0{index}:00:00Z",
                }
            )
        )

    status = list_managed_resident_agents(
        project_root=tmp_path, workspace_root=None, recent_limit=2
    )

    assert [row["run_id"] for row in status["recent"]] == [
        "completed-2",
        "completed-1",
    ]
    assert status["recent_count"] == 2
    assert status["recent_total_count"] == 3
    assert status["recent_omitted_count"] == 1


def test_hot_context_excludes_workflow_internal_manifest(tmp_path, monkeypatch) -> None:
    run_root = tmp_path / ".megaplan/plans/resident-subagents"
    internal = run_root / "internal"
    internal.mkdir(parents=True)
    (internal / "manifest.json").write_text(json.dumps({
        "schema_version": "arnold-resident-agent-run-v1",
        "run_kind": "workflow_internal_subagent",
        "custodian": "arnold.workflow",
        "status": "running",
        "pid": 123,
    }))
    monkeypatch.setattr(subagent_module, "_pid_matches_manifest", lambda pid, path: True)

    status = list_managed_resident_agents(project_root=tmp_path, workspace_root=None)

    assert status["running"] == []
    assert status["recent"] == []


def test_hot_context_counts_terminal_pending_delivery_as_attention(tmp_path, monkeypatch) -> None:
    run_root = tmp_path / ".megaplan/plans/resident-subagents"
    for run_id, run_status in (("active", "running"), ("done", "completed")):
        run_dir = run_root / run_id
        run_dir.mkdir(parents=True)
        (run_dir / "manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": "arnold-resident-agent-run-v1",
                    "run_kind": "resident_delegated_agent",
                    "custodian": "arnold.megaplan.resident",
                    "run_id": run_id,
                    "status": run_status,
                    "pid": 123 if run_status == "running" else None,
                    "created_at": f"2026-07-10T0{1 if run_id == 'active' else 2}:00:00Z",
                    "completion_delivery": {
                        "transport": "discord",
                        "status": "pending",
                        "attempt_count": 0,
                    },
                }
            )
        )

    monkeypatch.setattr(subagent_module, "_pid_matches_manifest", lambda pid, path: pid == 123)
    status = list_managed_resident_agents(project_root=tmp_path, workspace_root=None)

    assert status["delivery_status_counts"] == {"pending": 2}
    assert status["terminal_delivery_status_counts"] == {"pending": 1}
    assert status["delivery_attention_count"] == 1


def test_discord_origin_flows_from_inbound_turn_into_managed_launch(tmp_path, monkeypatch) -> None:
    captured: dict = {}

    async def fake_launch(config, **kwargs):
        captured.update(kwargs)
        return SubagentResult(
            ok=True,
            final_text="",
            stderr="",
            returncode=0,
            run_id="subagent-origin",
            status="running",
        )

    monkeypatch.setattr(profile_module, "launch_subagent_task", fake_launch)
    store = FileStore(tmp_path / "store")
    config = ResidentConfig(
        allowed_user_ids=("user-1",),
        burst_idle_delay_s=0,
        burst_max_delay_s=1,
    )
    authorizer = ResidentAuthorizer(config)
    profile = MegaplanResidentProfile(store=store, authorizer=authorizer, config=config)

    class _Outbound:
        async def send(self, message):
            pass

    runtime = ResidentRuntime(
        config=config,
        authorizer=authorizer,
        store=store,
        profile=profile,
        runner=FakeAgentRunner(
            [
                    FakeAgentStep.call(
                        "launch_subagent",
                        {"task": "do it", "description": "Do the requested work"},
                    ),
                FakeAgentStep.final("Started it."),
            ]
        ),
        outbound=_Outbound(),
    )
    asyncio.run(
        runtime.receive(
            InboundEvent(
                idempotency_key="discord:message:987",
                conversation_key="discord:guild:12:channel:34:thread:56",
                subject=AuthorizationSubject(user_id="user-1", guild_id="12", channel_id="34"),
                content="please do it",
                raw={"discord_message_id": "987", "thread_id": "56"},
            )
        )
    )
    asyncio.run(runtime.coalescer.flush_all())

    assert {
        key: captured["launch_origin"][key]
        for key in (
            "transport", "conversation_id", "conversation_key", "message_id",
            "reply_to_message_id", "guild_id", "channel_id", "thread_id", "dm_user_id",
        )
    } == {
        "transport": "discord",
        "conversation_id": captured["launch_origin"]["conversation_id"],
        "conversation_key": "discord:guild:12:channel:34:thread:56",
        "message_id": "987",
        "reply_to_message_id": "987",
        "guild_id": "12",
        "channel_id": "34",
        "thread_id": "56",
        "dm_user_id": None,
    }
    assert captured["launch_origin"]["source_record_id"].startswith("msg_")
    assert captured["launch_origin"]["delegation_id"] == "fake_tool_0001"


def _terminal_manifest(
    tmp_path: Path,
    *,
    status: str = "completed",
    result: str = "Done safely.",
    run_id: str = "subagent-delivery",
    request_id: str | None = None,
    created_at: str | None = None,
) -> Path:
    source_record_id = request_id or "msg_terminalrequest1"
    source_path = tmp_path / ".megaplan/resident/messages" / f"{source_record_id}.json"
    if source_path.exists():
        source_discord_message_id = str(json.loads(source_path.read_text())["discord_message_id"])
    else:
        source_discord_message_id = "1001"
        _resident_discord_request(
            tmp_path,
            message_id=source_record_id,
            discord_message_id=source_discord_message_id,
        )
    run_dir = tmp_path / ".megaplan/plans/resident-subagents" / run_id
    run_dir.mkdir(parents=True)
    result_path = run_dir / "result.md"
    result_path.write_text(result)
    manifest_path = run_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": "arnold-resident-agent-run-v1",
                "run_kind": "resident_delegated_agent",
                "custodian": "arnold.megaplan.resident",
                "run_id": run_id,
                "status": status,
                "result_path": str(result_path),
                "project_dir": str(tmp_path),
                "request_id": source_record_id,
                "source_record_id": source_record_id,
                "resident_conversation_id": "rconv_conversation1",
                "correlation_id": "discord-corr-test-terminal",
                "custody_id": "discord-custody-test-terminal",
                **({"created_at": created_at} if created_at else {}),
                "launch_provenance": {
                    "schema_version": "arnold-resident-delegation-provenance-v1",
                    "applicability": "applicable",
                    "transport": "discord",
                    "correlation_id": "discord-corr-test-terminal",
                    "custody_id": "discord-custody-test-terminal",
                    "resident_conversation_id": "rconv_conversation1",
                    "source_record_id": source_record_id,
                    "conversation_key": "discord:dm:42",
                    "discord_message_id": source_discord_message_id,
                    "reply_to_message_id": source_discord_message_id,
                    "guild_id": None,
                    "channel_id": "42",
                    "thread_id": None,
                    "dm_user_id": "42",
                },
                "discord_origin": {
                    "transport": "discord",
                    "conversation_id": "rconv_conversation1",
                    "conversation_key": "discord:dm:42",
                    "message_id": source_discord_message_id,
                    "reply_to_message_id": source_discord_message_id,
                    "guild_id": None,
                    "channel_id": "42",
                    "thread_id": None,
                    "dm_user_id": "42",
                    "reply_target_source_record_id": source_record_id,
                },
                "completion_delivery": {
                    "transport": "discord",
                    "status": "pending",
                    "attempt_count": 0,
                },
            }
        )
    )
    return manifest_path


def _resident_discord_request(
    tmp_path: Path,
    *,
    message_id: str,
    discord_message_id: str,
    conversation_id: str = "rconv_conversation1",
) -> None:
    resident_root = tmp_path / ".megaplan/resident"
    messages_dir = resident_root / "messages"
    conversations_dir = resident_root / "resident_conversations"
    messages_dir.mkdir(parents=True, exist_ok=True)
    conversations_dir.mkdir(parents=True, exist_ok=True)
    (messages_dir / f"{message_id}.json").write_text(
        json.dumps(
            {
                "id": message_id,
                "conversation_id": conversation_id,
                "direction": "inbound",
                "discord_message_id": discord_message_id,
                "content": "must not be copied to run provenance",
                "idempotency_key": "must-not-be-copied",
            }
        )
    )
    (conversations_dir / f"{conversation_id}.json").write_text(
        json.dumps(
            {
                "id": conversation_id,
                "transport": "discord",
                "conversation_key": "discord:dm:42",
                "guild_id": None,
                "channel_id": "42",
                "thread_id": None,
                "dm_user_id": "42",
                "last_inbound_message_id": message_id,
                "last_outbound_message_id": None,
            }
        )
    )


def test_completion_sweep_replies_once_and_persists_evidence(tmp_path) -> None:
    manifest_path = _terminal_manifest(tmp_path)

    class _Outbound:
        def __init__(self) -> None:
            self.sent = []

        async def send(self, message):
            self.sent.append(message)
            message.metadata["discord_message_ids"] = ["reply-1"]

    outbound = _Outbound()
    first = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=outbound,
            project_root=tmp_path,
            workspace_root=None,
        )
    )
    second = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=outbound,
            project_root=tmp_path,
            workspace_root=None,
        )
    )

    assert first.delivered == 1
    assert second.delivered == 0
    assert len(outbound.sent) == 1
    assert outbound.sent[0].content == "Done safely."
    assert outbound.sent[0].metadata["discord_reply_to_message_id"] == "1001"
    assert outbound.sent[0].metadata["discord_processing_message_ids"] == ["1001"]
    manifest = json.loads(manifest_path.read_text())
    assert manifest["completion_delivery"]["status"] == "delivered"
    assert manifest["completion_delivery"]["discord_message_ids"] == ["reply-1"]
    assert manifest["completion_delivery"]["result_kind"] == "final_result"
    custody_events = [
        json.loads(line)
        for line in Path(manifest["custody_evidence_path"]).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(
        event["event_kind"] == "effect"
        and event["evidence"] == "provider_attempt_claimed"
        for event in custody_events
    )
    assert any(
        event["event_kind"] == "delivery_custody"
        and event["evidence"] == "provider_reply_message_ids_persisted"
        for event in custody_events
    )


@pytest.mark.parametrize(
    ("delegated_status", "summary", "expected_outcome"),
    [
        ("completed", "Work and tests match the claim. The verification outcome is success.", "success"),
        ("completed", "Core work exists, but one check is missing. The verification outcome is partial.", "partial"),
        ("failed", "The delegated run failed before completion. The verification outcome is failed.", "failed"),
        ("completed", "Available evidence is inconclusive. The verification outcome is unknown.", "unknown"),
    ],
)
def test_terminal_run_triggers_verified_resident_turn_and_exact_reply(
    tmp_path, delegated_status, summary, expected_outcome
) -> None:
    manifest_path = _terminal_manifest(tmp_path, status=delegated_status)
    store = FileStore(tmp_path / ".megaplan/resident")
    config = ResidentConfig(allowed_user_ids=("42",))
    authorizer = ResidentAuthorizer(config)

    class _Runner:
        def __init__(self) -> None:
            self.requests = []

        async def run(self, request, _tools):
            self.requests.append(request)
            assert "never proof" in request.system_prompt
            assert "must begin with exactly" not in request.system_prompt
            assert "begin with what happened" in request.system_prompt
            assert "sole current request" in request.system_prompt
            assert "must not be copied to run provenance" in request.system_prompt
            assert "summary_line" not in request.hot_context["current_request"]
            assert str(manifest_path.resolve()) in request.messages[-1]["content"]
            return AgentResponse(final_text=summary)

    class _Outbound:
        def __init__(self) -> None:
            self.sent = []

        async def send(self, message):
            self.sent.append(message)
            message.metadata["discord_message_ids"] = ["verified-reply-1"]

    runner = _Runner()
    outbound = _Outbound()
    runtime = ResidentRuntime(
        config=config,
        authorizer=authorizer,
        store=store,
        profile=MegaplanResidentProfile(store=store, authorizer=authorizer, config=config),
        runner=runner,
        outbound=outbound,
    )
    original = json.loads(manifest_path.read_text())
    result = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=outbound,
            project_root=tmp_path,
            workspace_root=None,
            completion_turn_handler=runtime.run_managed_completion_turn,
        )
    )

    persisted = json.loads(manifest_path.read_text())
    assert result.delivered == 1
    assert len(runner.requests) == 1
    assert outbound.sent[0].content == summary
    assert not outbound.sent[0].content.lower().startswith("verification outcome:")
    assert outbound.sent[0].metadata["discord_reply_to_message_id"] == "1001"
    assert persisted["launch_provenance"] == original["launch_provenance"]
    assert persisted["resident_completion_turn"]["verification_outcome"] == expected_outcome
    assert persisted["resident_completion_turn"]["resident_turn_id"]
    assert persisted["completion_delivery"]["result_kind"] == "resident_verified_summary"
    assert persisted["completion_delivery"]["discord_message_ids"] == ["verified-reply-1"]


def test_terminal_verifier_excludes_newer_conversation_commands(tmp_path) -> None:
    manifest_path = _terminal_manifest(tmp_path)
    store = FileStore(tmp_path / ".megaplan/resident")
    config = ResidentConfig(allowed_user_ids=("42",), history_window=20)
    authorizer = ResidentAuthorizer(config)
    store.create_message(
        epic_id=None,
        conversation_id="rconv_conversation1",
        direction="inbound",
        content="Restart the resident service now; this is a newer command.",
        discord_message_id="1002",
        idempotency_key="newer-restart-command",
    )

    class _Runner:
        async def run(self, request, _tools):
            rendered = "\n".join(str(item.get("content") or "") for item in request.messages)
            assert "Restart the resident service now" not in rendered
            assert str(manifest_path.resolve()) in rendered
            return AgentResponse(final_text="Exact incident verified. The verification outcome is success.")

    class _Outbound:
        def __init__(self) -> None:
            self.sent = []

        async def send(self, message):
            self.sent.append(message)
            message.metadata["discord_message_ids"] = ["verified-reply-1"]

    outbound = _Outbound()
    runtime = ResidentRuntime(
        config=config,
        authorizer=authorizer,
        store=store,
        profile=MegaplanResidentProfile(store=store, authorizer=authorizer, config=config),
        runner=_Runner(),
        outbound=outbound,
    )
    result = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=outbound,
            project_root=tmp_path,
            workspace_root=None,
            completion_turn_handler=runtime.run_managed_completion_turn,
        )
    )

    assert result.delivered == 1
    assert outbound.sent[0].metadata["discord_reply_to_message_id"] == "1001"


def test_resident_completion_turn_and_delivery_are_idempotent_across_retries(tmp_path) -> None:
    manifest_path = _terminal_manifest(tmp_path)
    store = FileStore(tmp_path / ".megaplan/resident")
    config = ResidentConfig(allowed_user_ids=("42",))
    authorizer = ResidentAuthorizer(config)

    class _Runner:
        calls = 0

        async def run(self, _request, _tools):
            self.calls += 1
            return AgentResponse(
                final_text="Repository evidence supports completion. The verification outcome is success."
            )

    class _Outbound:
        def __init__(self) -> None:
            self.sent = []

        async def send(self, message):
            self.sent.append(message)
            message.metadata["discord_message_ids"] = ["one-provider-message"]

    runner = _Runner()
    outbound = _Outbound()
    runtime = ResidentRuntime(
        config=config,
        authorizer=authorizer,
        store=store,
        profile=MegaplanResidentProfile(store=store, authorizer=authorizer, config=config),
        runner=runner,
        outbound=outbound,
    )

    async def sweep():
        return await sweep_managed_agent_deliveries(
            outbound=outbound,
            project_root=tmp_path,
            workspace_root=None,
            completion_turn_handler=runtime.run_managed_completion_turn,
        )

    first = asyncio.run(sweep())
    second = asyncio.run(sweep())
    persisted = json.loads(manifest_path.read_text())

    assert first.delivered == 1
    assert second.delivered == 0
    assert runner.calls == 1
    assert len(outbound.sent) == 1
    assert persisted["resident_completion_turn"]["attempt_count"] == 1
    completion_turn_id = persisted["resident_completion_turn"]["resident_turn_id"]
    assert sum(turn.id == completion_turn_id for turn in store.list_recent_turns(n=20)) == 1


def test_restart_reclaims_stale_completion_turn_claim_without_duplicate_delivery(tmp_path) -> None:
    manifest_path = _terminal_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text())
    manifest["resident_completion_turn"] = {
        "schema_version": "arnold-resident-completion-turn-v1",
        "trigger_id": "resident-completion-turn-stable",
        "status": "running",
        "attempt_count": 1,
        "claimed_at": "2026-07-10T00:00:00+00:00",
    }
    manifest_path.write_text(json.dumps(manifest))

    class _Outbound:
        def __init__(self) -> None:
            self.sent = []

        async def send(self, message):
            self.sent.append(message)
            message.metadata["discord_message_ids"] = ["restart-reply"]

    handler_calls = []

    async def handler(path, claimed):
        handler_calls.append((path, claimed["resident_completion_turn"]["attempt_count"]))
        return ManagedCompletionTurnResult(
            final_text="Restart recovery verified the evidence. The verification outcome is success.",
            verification_outcome="success",
            turn_id="turn-existing",
            outbound_message_id="msg-existing",
        )

    outbound = _Outbound()

    async def sweep():
        return await sweep_managed_agent_deliveries(
            outbound=outbound,
            project_root=tmp_path,
            workspace_root=None,
            now=datetime(2026, 7, 11, tzinfo=timezone.utc),
            completion_turn_handler=handler,
        )

    first = asyncio.run(sweep())
    second = asyncio.run(sweep())
    persisted = json.loads(manifest_path.read_text())

    assert first.delivered == 1
    assert second.delivered == 0
    assert handler_calls == [(manifest_path, 2)]
    assert len(outbound.sent) == 1
    assert persisted["resident_completion_turn"]["attempt_count"] == 2
    assert persisted["completion_delivery"]["discord_message_ids"] == ["restart-reply"]


def test_failed_resident_verifier_delivers_truthful_unknown_summary(tmp_path) -> None:
    manifest_path = _terminal_manifest(tmp_path)
    store = FileStore(tmp_path / ".megaplan/resident")
    config = ResidentConfig(allowed_user_ids=("42",))
    authorizer = ResidentAuthorizer(config)

    class _Runner:
        async def run(self, _request, _tools):
            raise RuntimeError("model unavailable")

    class _Outbound:
        def __init__(self) -> None:
            self.sent = []

        async def send(self, message):
            self.sent.append(message)
            message.metadata["discord_message_ids"] = ["unknown-reply"]

    outbound = _Outbound()
    runtime = ResidentRuntime(
        config=config,
        authorizer=authorizer,
        store=store,
        profile=MegaplanResidentProfile(store=store, authorizer=authorizer, config=config),
        runner=_Runner(),
        outbound=outbound,
    )
    result = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=outbound,
            project_root=tmp_path,
            workspace_root=None,
            completion_turn_handler=runtime.run_managed_completion_turn,
        )
    )

    persisted = json.loads(manifest_path.read_text())
    assert result.delivered == 1
    assert not outbound.sent[0].content.lower().startswith("verification outcome:")
    assert "verification outcome is unknown" in outbound.sent[0].content.lower()
    assert "not being reported as proof" in outbound.sent[0].content
    assert persisted["resident_completion_turn"]["verification_outcome"] == "unknown"


def test_terminal_verifier_cannot_lead_with_handoff_success_when_recovery_blocked(
    tmp_path,
) -> None:
    manifest_path = _terminal_manifest(tmp_path)
    store = FileStore(tmp_path / ".megaplan/resident")
    config = ResidentConfig(allowed_user_ids=("42",))
    authorizer = ResidentAuthorizer(config)

    class _Runner:
        async def run(self, _request, _tools):
            return AgentResponse(
                final_text=(
                    "The message was durably sent, and the verification outcome for the handoff "
                    "is successful.\n\n"
                    "The underlying recovery remains blocked at a genuine authorization gate: "
                    "human approval is required."
                )
            )

    class _Outbound:
        def __init__(self) -> None:
            self.sent = []

        async def send(self, message):
            self.sent.append(message)
            message.metadata["discord_message_ids"] = ["blocked-reply"]

    outbound = _Outbound()
    runtime = ResidentRuntime(
        config=config,
        authorizer=authorizer,
        store=store,
        profile=MegaplanResidentProfile(store=store, authorizer=authorizer, config=config),
        runner=_Runner(),
        outbound=outbound,
    )
    result = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=outbound,
            project_root=tmp_path,
            workspace_root=None,
            completion_turn_handler=runtime.run_managed_completion_turn,
        )
    )

    persisted = json.loads(manifest_path.read_text())
    delivered = outbound.sent[0].content
    assert result.delivered == 1
    assert delivered.startswith("Forward motion remains blocked")
    assert "handoff is successful" not in delivered
    assert "human approval is required" in delivered
    assert persisted["resident_completion_turn"]["verification_outcome"] == "blocked"
    assert persisted["completion_delivery"]["payload"]["verification_outcome"] == "blocked"


def test_terminal_verifier_fails_closed_on_active_repair_goal(tmp_path) -> None:
    manifest_path = _terminal_manifest(tmp_path)
    goal_path = tmp_path / "repair-goal.json"
    goal_path.write_text(
        json.dumps({"status": "active", "goal_id": "goal-1"}), encoding="utf-8"
    )
    manifest = json.loads(manifest_path.read_text())
    manifest["links"] = {"repair_goal_path": str(goal_path)}
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    store = FileStore(tmp_path / ".megaplan/resident")
    config = ResidentConfig(allowed_user_ids=("42",))
    authorizer = ResidentAuthorizer(config)

    class _Runner:
        async def run(self, _request, _tools):
            return AgentResponse(
                final_text="Everything completed. The verification outcome is success."
            )

    class _Outbound:
        def __init__(self) -> None:
            self.sent = []

        async def send(self, message):
            self.sent.append(message)
            message.metadata["discord_message_ids"] = ["goal-blocked-reply"]

    outbound = _Outbound()
    runtime = ResidentRuntime(
        config=config,
        authorizer=authorizer,
        store=store,
        profile=MegaplanResidentProfile(store=store, authorizer=authorizer, config=config),
        runner=_Runner(),
        outbound=outbound,
    )
    asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=outbound,
            project_root=tmp_path,
            workspace_root=None,
            completion_turn_handler=runtime.run_managed_completion_turn,
        )
    )

    persisted = json.loads(manifest_path.read_text())
    assert outbound.sent[0].content.startswith("Forward motion remains blocked")
    assert persisted["resident_completion_turn"]["verification_outcome"] == "blocked"


def test_production_completion_sweep_suppresses_pytest_fixture_manifest(tmp_path) -> None:
    manifest_path = _terminal_manifest(tmp_path)

    class _ProductionOutbound:
        delivery_environment = "production"

        async def send(self, _message):
            raise AssertionError("pytest fixture outbox reached Discord delivery")

    result = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=_ProductionOutbound(),
            project_root=tmp_path,
            workspace_root=None,
        )
    )

    manifest = json.loads(manifest_path.read_text())
    assert result.delivered == 0
    assert result.skipped == 1
    assert manifest["completion_delivery"]["status"] == "suppressed"
    assert manifest["completion_delivery"]["suppression_reason"].startswith("pytest_workspace")


def test_production_completion_sweep_preserves_genuine_discord_reply(tmp_path) -> None:
    manifest_path = _terminal_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text())
    manifest["project_dir"] = "/workspace/production-chain"
    manifest_path.write_text(json.dumps(manifest))

    class _ProductionOutbound:
        delivery_environment = "production"

        def __init__(self) -> None:
            self.sent = []

        async def send(self, message):
            self.sent.append(message)
            message.metadata["discord_message_ids"] = ["reply-production"]

    outbound = _ProductionOutbound()
    result = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=outbound,
            project_root=tmp_path,
            workspace_root=None,
        )
    )

    assert result.delivered == 1
    assert len(outbound.sent) == 1
    assert outbound.sent[0].metadata["discord_reply_to_message_id"] == "1001"
    assert json.loads(manifest_path.read_text())["completion_delivery"]["status"] == "delivered"


def test_completion_sweep_repairs_legacy_resident_record_reply_target(tmp_path) -> None:
    manifest_path = _terminal_manifest(tmp_path)
    record_id = "msg_e2f96baa6c5e"
    messages_dir = tmp_path / ".megaplan/resident/messages"
    messages_dir.mkdir(parents=True, exist_ok=True)
    (messages_dir / f"{record_id}.json").write_text(
        json.dumps(
            {
                "id": record_id,
                "conversation_id": "rconv_conversation1",
                "direction": "inbound",
                "discord_message_id": "1525241277644406895",
            }
        )
    )
    manifest = json.loads(manifest_path.read_text())
    manifest["project_dir"] = str(tmp_path)
    manifest["request_id"] = record_id
    manifest.pop("launch_provenance")
    manifest.pop("source_record_id")
    manifest["discord_origin"].pop("reply_target_source_record_id")
    manifest["discord_origin"]["message_id"] = record_id
    manifest["discord_origin"]["reply_to_message_id"] = record_id
    manifest_path.write_text(json.dumps(manifest))

    class _Outbound:
        def __init__(self) -> None:
            self.reply_target = None

        async def send(self, message):
            self.reply_target = message.metadata["discord_reply_to_message_id"]
            message.metadata["discord_message_ids"] = ["reply-legacy"]

    outbound = _Outbound()
    result = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=outbound,
            project_root=tmp_path,
            workspace_root=None,
        )
    )

    repaired = json.loads(manifest_path.read_text())
    assert result.delivered == 1
    assert outbound.reply_target == "1525241277644406895"
    assert repaired["discord_origin"]["message_id"] == "1525241277644406895"
    assert repaired["discord_origin"]["reply_to_message_id"] == "1525241277644406895"
    assert repaired["discord_origin"]["reply_target_source_record_id"] == record_id


def test_completion_sweep_recovers_request_provenance_after_acknowledgement_interleaving(
    tmp_path,
) -> None:
    request_id = "msg_original1234"
    original_discord_id = "1525245026865778718"
    _resident_discord_request(
        tmp_path,
        message_id=request_id,
        discord_message_id=original_discord_id,
    )
    manifest_path = _terminal_manifest(tmp_path, request_id=request_id)
    manifest = json.loads(manifest_path.read_text())
    manifest["project_dir"] = str(tmp_path)
    manifest.pop("discord_origin")
    manifest.pop("completion_delivery")
    manifest_path.write_text(json.dumps(manifest))

    # The resident acknowledgement and a later inbound message supersede the
    # conversation's mutable cursors. Completion must still use the immutable
    # request record captured by request_id.
    conversation_path = (
        tmp_path
        / ".megaplan/resident/resident_conversations/rconv_conversation1.json"
    )
    conversation = json.loads(conversation_path.read_text())
    conversation.update(
        {
            "last_outbound_message_id": "msg_acknowledgement1",
            "delivery_cursor": "msg_acknowledgement1",
            "last_inbound_message_id": "msg_newerrequest1",
        }
    )
    conversation_path.write_text(json.dumps(conversation))

    class _Outbound:
        def __init__(self) -> None:
            self.sent = []

        async def send(self, message):
            self.sent.append(message)
            message.metadata["discord_message_ids"] = ["reply-original"]

    outbound = _Outbound()
    result = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=outbound,
            project_root=tmp_path,
            workspace_root=None,
        )
    )

    repaired = json.loads(manifest_path.read_text())
    assert result.delivered == 1
    assert outbound.sent[0].metadata["discord_reply_to_message_id"] == original_discord_id
    assert repaired["discord_origin"]["reply_to_message_id"] == original_discord_id
    assert repaired["discord_origin"]["reply_target_source_record_id"] == request_id
    assert repaired["completion_delivery"]["provenance_recovered"] is True


@pytest.mark.parametrize(
    ("request_id", "expected_status", "expected_applicability"),
    [
        ("msg_missinglegacy1", "unknown", None),
        ("internal-legacy-run", "not_applicable", "not_applicable"),
    ],
)
def test_legacy_manifest_backfill_never_guesses_reply_target(
    tmp_path, request_id, expected_status, expected_applicability
) -> None:
    run_dir = tmp_path / ".megaplan/plans/resident-subagents/legacy-backfill"
    run_dir.mkdir(parents=True)
    result_path = run_dir / "result.md"
    result_path.write_text("legacy result")
    manifest_path = run_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": "arnold-resident-agent-run-v1",
                "run_kind": "resident_delegated_agent",
                "custodian": "arnold.megaplan.resident",
                "run_id": "legacy-backfill",
                "request_id": request_id,
                "status": "completed",
                "project_dir": str(tmp_path),
                "result_path": str(result_path),
            }
        )
    )

    class _Outbound:
        async def send(self, message):
            raise AssertionError("unproven legacy target must not be sent")

    asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=_Outbound(), project_root=tmp_path, workspace_root=None
        )
    )
    migrated = json.loads(manifest_path.read_text())
    assert migrated["completion_delivery"]["status"] == expected_status
    assert "discord_origin" not in migrated
    if expected_applicability is not None:
        assert migrated["launch_provenance"]["applicability"] == expected_applicability


def test_historical_provider_evidence_is_never_downgraded_or_redriven(tmp_path) -> None:
    manifest_path = _terminal_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text())
    manifest["launch_provenance"] = {}
    manifest["discord_origin"]["reply_to_message_id"] = "invalid-legacy-target"
    manifest["completion_delivery"].update(
        {
            "status": "failed",
            "attempt_count": 1,
            "delivered_at": "2026-07-10T20:44:05+00:00",
            "discord_message_ids": ["provider-message-1"],
            "last_error_class": "InvalidDelegationProvenance",
            "last_error_category": "invalid_reply_target",
        }
    )
    manifest_path.write_text(json.dumps(manifest))

    class _Outbound:
        async def send(self, message):
            raise AssertionError("provider-accepted historical delivery was redriven")

    result = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=_Outbound(), project_root=tmp_path, workspace_root=None
        )
    )

    delivery = json.loads(manifest_path.read_text())["completion_delivery"]
    assert result.delivered == 0
    assert delivery["status"] == "delivered"
    assert delivery["attempt_count"] == 1
    assert delivery["discord_message_ids"] == ["provider-message-1"]
    assert delivery["migration_diagnostic"]["last_error_class"] == (
        "InvalidDelegationProvenance"
    )
    assert "no redrive" in delivery["migration_evidence"]


def test_newer_run_supersedes_duplicate_completion_for_same_original_request(tmp_path) -> None:
    request_id = "msg_duplicate1234"
    original_discord_id = "1525245026865778718"
    older_path = _terminal_manifest(
        tmp_path,
        run_id="subagent-older",
        result="stale completion",
        request_id=request_id,
        created_at="2026-07-10T20:00:00Z",
    )
    newer_path = _terminal_manifest(
        tmp_path,
        run_id="subagent-newer",
        result="current completion",
        request_id=request_id,
        created_at="2026-07-10T20:01:00Z",
    )
    _resident_discord_request(
        tmp_path,
        message_id=request_id,
        discord_message_id=original_discord_id,
    )
    for path in (older_path, newer_path):
        manifest = json.loads(path.read_text())
        manifest["discord_origin"]["message_id"] = original_discord_id
        manifest["discord_origin"]["reply_to_message_id"] = original_discord_id
        manifest["launch_provenance"]["discord_message_id"] = original_discord_id
        manifest["launch_provenance"]["reply_to_message_id"] = original_discord_id
        path.write_text(json.dumps(manifest))

    class _Outbound:
        def __init__(self) -> None:
            self.sent = []

        async def send(self, message):
            self.sent.append(message)
            message.metadata["discord_message_ids"] = ["reply-current"]

    outbound = _Outbound()
    result = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=outbound,
            project_root=tmp_path,
            workspace_root=None,
        )
    )

    older = json.loads(older_path.read_text())["completion_delivery"]
    newer = json.loads(newer_path.read_text())["completion_delivery"]
    assert result.delivered == 1
    assert [message.content for message in outbound.sent] == [
        "current completion"
    ]
    assert outbound.sent[0].metadata["discord_reply_to_message_id"] == original_discord_id
    assert older["status"] == "superseded"
    assert older["superseded_by_run_id"] == "subagent-newer"
    assert newer["status"] == "delivered"


def test_completion_sweep_retries_inflight_restart_with_stable_nonce(tmp_path) -> None:
    manifest_path = _terminal_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text())
    manifest["completion_delivery"].update(
        {
            "status": "sending",
            "attempt_count": 1,
            "discord_nonce": "stable-restart-nonce",
        }
    )
    manifest_path.write_text(json.dumps(manifest))

    class _Outbound:
        def __init__(self) -> None:
            self.sent = []

        async def send(self, message):
            self.sent.append(message)
            message.metadata["discord_message_ids"] = ["existing-or-new-reply"]

    outbound = _Outbound()
    result = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=outbound,
            project_root=tmp_path,
            workspace_root=None,
        )
    )

    assert result.delivered == 1
    assert outbound.sent[0].metadata["discord_nonce"] == "stable-restart-nonce"
    delivered = json.loads(manifest_path.read_text())["completion_delivery"]
    assert delivered["status"] == "delivered"
    assert delivered["attempt_count"] == 2
    assert delivered["discord_nonce"] == "stable-restart-nonce"
    assert any(
        item["status"] == "unknown"
        and item["evidence"] == "process_restarted_with_inflight_provider_attempt"
        for item in delivered["state_history"]
    )


def test_completion_fallback_acceptance_is_durable_and_not_redriven(tmp_path) -> None:
    manifest_path = _terminal_manifest(tmp_path)

    class _Outbound:
        def __init__(self) -> None:
            self.sent = []

        async def send(self, message):
            self.sent.append(message)
            message.metadata["discord_message_ids"] = ["fallback-reply-1"]
            message.metadata["discord_delivery_evidence"] = {
                "schema_version": "arnold-discord-delivery-evidence-v1",
                "authoritative_conversation_key": message.conversation_key,
                "delivery_mode": "fallback_plain",
                "fallback_reason": "reply_reference_rejected",
                "provider_outcome": "accepted",
                "provider_message_ids": ["fallback-reply-1"],
                "provider_rejections": [
                    {
                        "outcome": "rejected",
                        "scope": "reply_reference",
                        "error_class": "NotFound",
                        "http_status": 404,
                        "discord_error_code": 10008,
                    }
                ],
                "resolved_channel_id": "301463647895683072",
                "resolved_thread_id": None,
                "user_notification_visibility": "unknown",
            }

    outbound = _Outbound()
    first = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=outbound, project_root=tmp_path, workspace_root=None
        )
    )
    second = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=outbound, project_root=tmp_path, workspace_root=None
        )
    )

    delivery = json.loads(manifest_path.read_text())["completion_delivery"]
    assert first.delivered == 1
    assert second.delivered == 0
    assert len(outbound.sent) == 1
    assert delivery["status"] == "delivered"
    assert delivery["provider_outcome"] == "accepted"
    assert delivery["user_notification_visibility"] == "unknown"
    assert delivery["delivery_evidence"]["delivery_mode"] == "fallback_plain"
    assert delivery["delivery_evidence"]["authoritative_conversation_key"] == (
        outbound.sent[0].conversation_key
    )
    assert any(
        item["status"] == "rejected"
        and item["evidence"] == "provider_rejected_reply_or_thread_target"
        for item in delivery["state_history"]
    )
    assert any(
        item["status"] == "delivered"
        and item["evidence"] == "provider_fallback_message_ids_persisted"
        for item in delivery["state_history"]
    )


def test_completion_delivery_failure_is_persisted_and_retried(tmp_path) -> None:
    manifest_path = _terminal_manifest(tmp_path)
    first_now = datetime(2026, 7, 10, tzinfo=timezone.utc)

    class _Outbound:
        def __init__(self) -> None:
            self.calls = 0

        async def send(self, message):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("Discord API unavailable token=secret-value")
            message.metadata["discord_message_ids"] = ["reply-2"]

    outbound = _Outbound()
    first = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=outbound,
            project_root=tmp_path,
            workspace_root=None,
            now=first_now,
        )
    )
    retry_manifest = json.loads(manifest_path.read_text())
    assert first.retry_pending == 1
    assert retry_manifest["completion_delivery"]["status"] == "retry_pending"
    assert retry_manifest["completion_delivery"]["attempt_count"] == 1
    assert "secret-value" not in retry_manifest["completion_delivery"]["last_error"]
    assert retry_manifest["completion_delivery"]["last_error_category"] == "runtime_error"
    assert retry_manifest["completion_delivery"]["last_http_status"] is None
    assert retry_manifest["completion_delivery"]["last_http_body_category"] == "not_applicable"
    assert len(retry_manifest["completion_delivery"]["error_history"]) == 1
    # The outbox payload is immutable across retries even if a local result
    # artifact is edited after the first provider attempt.
    Path(retry_manifest["result_path"]).write_text("mutated after outbox commit")

    second = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=outbound,
            project_root=tmp_path,
            workspace_root=None,
            now=first_now + timedelta(seconds=31),
        )
    )
    final_manifest = json.loads(manifest_path.read_text())
    assert second.delivered == 1
    assert outbound.calls == 2
    assert final_manifest["completion_delivery"]["status"] == "delivered"
    assert final_manifest["completion_delivery"]["attempt_count"] == 2
    assert len(final_manifest["completion_delivery"]["error_history"]) == 1
    assert final_manifest["completion_delivery"]["payload"]["content"] == "Done safely."


def test_completion_timeout_records_unknown_provider_outcome(tmp_path) -> None:
    manifest_path = _terminal_manifest(tmp_path)

    class _Outbound:
        async def send(self, message):
            raise TimeoutError("provider response timed out")

    result = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=_Outbound(),
            project_root=tmp_path,
            workspace_root=None,
            now=datetime(2026, 7, 10, tzinfo=timezone.utc),
        )
    )

    delivery = json.loads(manifest_path.read_text())["completion_delivery"]
    assert result.retry_pending == 1
    assert delivery["status"] == "retry_pending"
    assert delivery["provider_outcome"] == "unknown"
    assert delivery["user_notification_visibility"] == "unknown"
    assert any(
        item["status"] == "unknown"
        and item["evidence"] == "provider_acceptance_outcome_unknown"
        for item in delivery["state_history"]
    )


def test_completion_delivery_persists_redacted_discord_http_evidence(tmp_path) -> None:
    manifest_path = _terminal_manifest(tmp_path)

    class _DiscordHTTPError(RuntimeError):
        status = 403
        code = 50013
        text = {"message": "Missing Permissions", "token": "top-secret-token"}

    class _Outbound:
        async def send(self, message):
            raise _DiscordHTTPError("Authorization: Bot top-secret-token")

    result = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=_Outbound(),
            project_root=tmp_path,
            workspace_root=None,
            now=datetime(2026, 7, 10, tzinfo=timezone.utc),
        )
    )

    delivery = json.loads(manifest_path.read_text())["completion_delivery"]
    serialized = json.dumps(delivery)
    assert result.failed == 1
    assert delivery["status"] == "failed"
    assert delivery["last_error"] == (
        "Discord delivery failed: forbidden (HTTP 403; Discord code 50013; body=json)"
    )
    assert delivery["last_error_category"] == "forbidden"
    assert delivery["last_http_status"] == 403
    assert delivery["last_discord_error_code"] == 50013
    assert delivery["last_http_body_category"] == "json"
    assert "top-secret-token" not in serialized
    assert "Authorization" not in serialized


def test_deleted_discord_source_message_is_permanent_failed_custody(tmp_path) -> None:
    manifest_path = _terminal_manifest(tmp_path)

    class _DiscordNotFound(RuntimeError):
        status = 404
        code = 10008
        text = {"message": "Unknown Message"}

    class _Outbound:
        async def send(self, message):
            raise _DiscordNotFound("Unknown Message")

    result = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=_Outbound(),
            project_root=tmp_path,
            workspace_root=None,
        )
    )
    delivery = json.loads(manifest_path.read_text())["completion_delivery"]
    assert result.failed == 1
    assert delivery["status"] == "failed"
    assert delivery["last_error_category"] == "not_found"
    assert delivery["last_http_status"] == 404
    assert "next_attempt_at" not in delivery


def test_completion_delivery_with_unavailable_reply_target_is_failed_visibly(tmp_path) -> None:
    manifest_path = _terminal_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text())
    manifest["discord_origin"]["conversation_key"] = ""
    manifest["launch_provenance"]["conversation_key"] = ""
    manifest_path.write_text(json.dumps(manifest))
    (tmp_path / ".megaplan/resident/messages/msg_terminalrequest1.json").unlink()
    (tmp_path / ".megaplan/resident/resident_conversations/rconv_conversation1.json").unlink()

    class _Outbound:
        async def send(self, message):
            raise AssertionError("invalid target must not be sent")

    asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=_Outbound(),
            project_root=tmp_path,
            workspace_root=None,
        )
    )
    failed = json.loads(manifest_path.read_text())["completion_delivery"]
    assert failed["status"] == "failed"
    assert failed["last_error_class"] == "InvalidDelegationProvenance"


def test_completion_delivery_refuses_tampered_compatibility_target(tmp_path) -> None:
    manifest_path = _terminal_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text())
    manifest["discord_origin"]["message_id"] = "1525300000000000991"
    manifest["discord_origin"]["reply_to_message_id"] = "1525300000000000991"
    manifest_path.write_text(json.dumps(manifest))

    class _Outbound:
        async def send(self, message):
            raise AssertionError("tampered target must never be sent")

    result = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=_Outbound(), project_root=tmp_path, workspace_root=None
        )
    )
    repaired = json.loads(manifest_path.read_text())
    assert result.failed == 1
    assert repaired["completion_delivery"]["status"] == "failed"
    assert repaired["completion_delivery"]["last_error_class"] == "ProvenanceCustodyMismatch"
    assert repaired["launch_provenance"]["reply_to_message_id"] == "1001"


@pytest.mark.parametrize(
    ("status", "result", "result_kind", "content_fragment"),
    [
        ("completed", "", "missing_result", "produced no deliverable final message"),
        ("failed", "partial output", "terminal_failure", "did not complete this request successfully"),
        ("interrupted", "", "terminal_failure", "status: interrupted"),
    ],
)
def test_terminal_agents_without_successful_result_send_honest_notice(
    tmp_path, status, result, result_kind, content_fragment
) -> None:
    manifest_path = _terminal_manifest(tmp_path, status=status, result=result)

    class _Outbound:
        def __init__(self) -> None:
            self.sent = []

        async def send(self, message):
            self.sent.append(message)
            message.metadata["discord_message_ids"] = ["honest-terminal-notice"]

    outbound = _Outbound()
    sweep = asyncio.run(
        sweep_managed_agent_deliveries(
            outbound=outbound,
            project_root=tmp_path,
            workspace_root=None,
        )
    )
    manifest = json.loads(manifest_path.read_text())
    assert sweep.delivered == 1
    assert content_fragment in outbound.sent[0].content
    assert manifest["completion_delivery"]["result_kind"] == result_kind
