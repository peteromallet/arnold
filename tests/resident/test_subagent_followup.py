from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import threading

import pytest

from arnold_pipelines.megaplan.resident import subagent
from arnold_pipelines.megaplan import managed_agent
from arnold_pipelines.megaplan.resident.agent_loop import (
    AgentRequest,
    FakeAgentRunner,
    FakeAgentStep,
)
from arnold_pipelines.megaplan.resident.auth import ResidentAuthorizer
from arnold_pipelines.megaplan.resident.config import ResidentConfig
from arnold_pipelines.megaplan.resident.profile import MegaplanResidentProfile
from arnold_pipelines.megaplan.resident.provenance import (
    DELEGATION_CONTEXT_ENV,
    encoded_provenance,
    normalize_delegation_provenance,
)
from arnold_pipelines.megaplan.store import FileStore


SESSION_ID = "019f5d2e-d5da-75f3-a617-4712a1c57cc4"
TARGET_RUN_ID = "subagent-20260713-203257-59552356"
QUEUED_OWNER_RUN_ID = "subagent-20260713-203300-aaaaaaaa"
SECOND_PREDECESSOR_RUN_ID = "subagent-20260713-203258-bbbbbbbb"


def _provenance(*, source: str, message: str, conversation: str = "rconv_followuptest") -> dict:
    return normalize_delegation_provenance(
        {
            "schema_version": "arnold-resident-delegation-provenance-v1",
            "applicability": "applicable",
            "transport": "discord",
            "resident_conversation_id": conversation,
            "source_record_id": source,
            "conversation_key": "discord:dm:42",
            "discord_message_id": message,
            "reply_to_message_id": message,
            "dm_user_id": "42",
            "source_kind": "discord_inbound_message",
        }
    )


def _write_run(
    root: Path,
    *,
    run_id: str = TARGET_RUN_ID,
    status: str = "completed",
    provenance: dict | None = None,
    session_id: str | None = SESSION_ID,
    pid: int | None = None,
    lineage_root_run_id: str | None = None,
    parent_run_id: str | None = None,
    backend: str = "codex",
    model: str = "gpt-5.6-sol",
) -> Path:
    run_dir = root / ".megaplan/plans/resident-subagents" / run_id
    run_dir.mkdir(parents=True)
    log_path = run_dir / "run.log"
    log_path.write_text(f"session id: {session_id}\n" if session_id else "starting\n")
    manifest = {
        "schema_version": "arnold-managed-agent-run-v2",
        "run_kind": "resident_delegated_agent",
        "custodian": "arnold.megaplan.managed_agent",
        "run_id": run_id,
        "backend": backend,
        "status": status,
        "pid": pid,
        "project_dir": str(root),
        "model": model,
        "model_spec": f"{backend}:{model}",
        "provider_options": {
            "toolsets": "file,web,terminal",
            "max_tokens": 32768,
            "timeout_s": 321,
        },
        "timeout_policy": {
            "mode": "explicit",
            "source": "trusted_cli",
            "timeout_s": 321,
        },
        "reasoning_effort": "high",
        "task_kind": "architecture",
        "difficulty": 8,
        "route_class": "ambiguous_or_high_risk",
        "log_path": str(log_path),
        "launch_provenance": provenance
        or _provenance(source="msg_originalsource", message="1001"),
        "created_at": "2026-07-13T20:32:57+00:00",
    }
    if lineage_root_run_id:
        manifest["lineage_root_run_id"] = lineage_root_run_id
    if parent_run_id:
        manifest["parent_run_id"] = parent_run_id
    if session_id:
        manifest["model_session"] = {
            "provider": backend,
            "session_id": session_id,
            "state": "persisted",
        }
    path = run_dir / "manifest.json"
    path.write_text(json.dumps(manifest))
    return path


def _write_queued_synthesis_owner(root: Path) -> tuple[Path, Path]:
    target_path = _write_run(root, status="running", session_id=None, pid=111)
    second_path = _write_run(
        root,
        run_id=SECOND_PREDECESSOR_RUN_ID,
        status="completed",
        session_id=None,
    )
    aggregation_key = "resident-synthesis-group-test"
    synthesis_group = "queued-owner-test"
    for path in (target_path, second_path):
        manifest = json.loads(path.read_text())
        manifest["aggregation"] = {
            "schema_version": "arnold-resident-agent-aggregation-v1",
            "key": aggregation_key,
            "synthesis_group": synthesis_group,
            "role": "internal_contributor",
            "delivery_owner_run_id": QUEUED_OWNER_RUN_ID,
        }
        manifest["completion_delivery"] = {"status": "suppressed"}
        path.write_text(json.dumps(manifest))

    owner_dir = root / ".megaplan/plans/resident-subagents" / QUEUED_OWNER_RUN_ID
    owner_dir.mkdir(parents=True)
    prompt_path = owner_dir / "prompt.md"
    prompt = "Synthesize both successful recovery runs and deliver once.\n"
    prompt_path.write_text(prompt)
    owner_path = owner_dir / "manifest.json"
    owner = {
        "schema_version": "arnold-managed-agent-run-v2",
        "run_kind": "resident_delegated_agent",
        "custodian": "arnold.megaplan.managed_agent",
        "run_id": QUEUED_OWNER_RUN_ID,
        "status": "queued",
        "project_dir": str(root),
        "prompt_path": str(prompt_path),
        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
        "launch_provenance": _provenance(
            source="msg_originalsource", message="1001"
        ),
        "parent_run_id": TARGET_RUN_ID,
        "lineage_root_run_id": TARGET_RUN_ID,
        "aggregation": {
            "schema_version": "arnold-resident-agent-aggregation-v1",
            "key": aggregation_key,
            "synthesis_group": synthesis_group,
            "role": "synthesis_delivery_owner",
            "delivery_owner_run_id": QUEUED_OWNER_RUN_ID,
            "contributors": [
                {"run_id": TARGET_RUN_ID},
                {"run_id": SECOND_PREDECESSOR_RUN_ID},
            ],
        },
        "completion_delivery": {"status": "pending"},
        "queue": {
            "schema_version": "arnold-resident-subagent-queue-v1",
            "state": "waiting_predecessors",
            "predecessor_run_ids": [TARGET_RUN_ID, SECOND_PREDECESSOR_RUN_ID],
            "predecessor_states": [
                {"run_id": TARGET_RUN_ID, "status": "running"},
                {"run_id": SECOND_PREDECESSOR_RUN_ID, "status": "completed"},
            ],
        },
        "created_at": "2026-07-13T20:33:00+00:00",
    }
    owner_path.write_text(json.dumps(owner))
    return target_path, owner_path


class _Supervisor:
    pid = 4321


@pytest.fixture
def caller_provenance(monkeypatch) -> dict:
    caller = _provenance(source="msg_newfollowupsrc", message="2002")
    monkeypatch.setenv(DELEGATION_CONTEXT_ENV, encoded_provenance(caller))
    return caller


@pytest.mark.parametrize("terminal_status", ["completed", "failed", "interrupted"])
def test_terminal_followup_creates_auditable_session_continuation(
    tmp_path: Path, monkeypatch, caller_provenance: dict, terminal_status: str
) -> None:
    target_path = _write_run(tmp_path, status=terminal_status)
    launches: list[list[str]] = []

    def fake_popen(argv, **kwargs):
        if "arnold_pipelines.megaplan.resident.subagent_worker" in argv:
            launches.append(list(argv))
        return _Supervisor()

    monkeypatch.setattr(subagent.subprocess, "Popen", fake_popen)
    result = subagent.follow_up_managed_subagent(
        run_id=TARGET_RUN_ID,
        message="Add the authoritative request and factual session summaries.",
        project_dir=tmp_path,
        workspace_root=None,
    )

    assert result.ok is True
    assert result.target_run_id == TARGET_RUN_ID
    assert result.parent_run_id == TARGET_RUN_ID
    assert result.lineage_root_run_id == TARGET_RUN_ID
    assert result.model_session_id == SESSION_ID
    assert result.status == "continuation_started"
    assert len(launches) == 1

    record = json.loads(Path(result.evidence_path).read_text())
    child = json.loads(Path(result.continuation_manifest_path).read_text())
    assert Path(record["message_path"]).read_text().strip() == (
        "Add the authoritative request and factual session summaries."
    )
    assert record["state_history"][-1]["evidence"] == (
        "terminal_lineage_continuation_supervisor_started"
    )
    assert child["parent_run_id"] == TARGET_RUN_ID
    assert child["lineage_root_run_id"] == TARGET_RUN_ID
    assert child["continued_session_id"] == SESSION_ID
    assert child["followup_id"] == result.followup_id
    assert Path(child["parent_manifest_path"]) == target_path
    assert child["launch_provenance"] == caller_provenance
    assert child["work_intent"] == "review"
    child_prompt = Path(child["prompt_path"]).read_text()
    assert child_prompt.count(
        subagent.DELEGATION_DELIVERY_INSTRUCTION_HEADER
    ) == 1
    assert "- resolved work intent: review" in child_prompt
    assert child["discord_origin"]["reply_to_message_id"] == "2002"
    assert child["discord_origin"]["reply_target_source_record_id"] == (
        "msg_newfollowupsrc"
    )


def test_registered_followup_tool_returns_durable_receipt(
    tmp_path: Path, monkeypatch, caller_provenance: dict
) -> None:
    _write_run(tmp_path)
    monkeypatch.setattr(subagent.subprocess, "Popen", lambda *a, **k: _Supervisor())
    store = FileStore(tmp_path / "store")
    config = ResidentConfig()
    profile = MegaplanResidentProfile(
        store=store,
        authorizer=ResidentAuthorizer(config),
        config=config,
    )
    runner = FakeAgentRunner(
        [
            FakeAgentStep.call(
                "follow_up_subagent",
                {
                    "run_id": TARGET_RUN_ID,
                    "message": "Expose dependency state in hot context.",
                    "project_dir": str(tmp_path),
                },
            ),
            FakeAgentStep.final("The follow-up has a durable receipt."),
        ]
    )
    request = AgentRequest(
        conversation_id="rconv_followuptest",
        messages=({"role": "user", "content": "attach this"},),
        system_prompt="test",
        launch_origin={**caller_provenance, "resident_turn_id": "turn_123456789abc"},
    )

    response = asyncio.run(runner.run(request, profile.tools()))

    assert response.final_text == "The follow-up has a durable receipt."
    assert len(response.tool_calls) == 1
    result = response.tool_calls[0].result
    assert result["ok"] is True, result
    receipt = result["data"]
    assert receipt["followup_id"].startswith("followup-")
    assert receipt["continuation_run_id"].startswith("subagent-")
    assert receipt["status"] == "continuation_started"
    assert Path(receipt["evidence_path"]).is_file()
    assert Path(receipt["continuation_manifest_path"]).is_file()


def test_registered_followup_tool_returns_explicit_failure_without_receipt(
    tmp_path: Path, caller_provenance: dict
) -> None:
    store = FileStore(tmp_path / "store")
    config = ResidentConfig()
    profile = MegaplanResidentProfile(
        store=store,
        authorizer=ResidentAuthorizer(config),
        config=config,
    )
    runner = FakeAgentRunner(
        [
            FakeAgentStep.call(
                "follow_up_subagent",
                {
                    "run_id": TARGET_RUN_ID,
                    "message": "This target does not exist.",
                    "project_dir": str(tmp_path),
                },
            ),
            FakeAgentStep.final("The follow-up was rejected explicitly."),
        ]
    )
    request = AgentRequest(
        conversation_id="rconv_followuptest",
        messages=({"role": "user", "content": "attach this"},),
        system_prompt="test",
        launch_origin={**caller_provenance, "resident_turn_id": "turn_123456789abc"},
    )

    response = asyncio.run(runner.run(request, profile.tools()))

    result = response.tool_calls[0].result
    assert result["ok"] is False
    assert result["data"]["error"] == "resident_followup_rejected"
    assert result["data"]["target_run_id"] == TARGET_RUN_ID
    assert "unknown resident-managed run_id" in result["message"]


def test_local_followup_cli_honors_explicit_project_scope(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    captured: dict = {}

    def fake_followup(**kwargs):
        captured.update(kwargs)
        return subagent.SubagentFollowupResult(
            ok=True,
            followup_id="followup-cli-scope",
            target_run_id=TARGET_RUN_ID,
            parent_run_id=TARGET_RUN_ID,
            lineage_root_run_id=TARGET_RUN_ID,
            continuation_run_id="subagent-20260716-140000-aaaaaaaa",
            status="continuation_started",
            evidence_path=str(tmp_path / "receipt.json"),
            message_path=str(tmp_path / "message.md"),
            continuation_manifest_path=str(tmp_path / "manifest.json"),
        )

    monkeypatch.setattr(subagent, "follow_up_managed_subagent", fake_followup)

    result = subagent._main(
        [
            "follow-up",
            "--run-id",
            TARGET_RUN_ID,
            "--message",
            "Use exact project custody.",
            "--project-dir",
            str(tmp_path),
        ]
    )

    assert result == 0
    assert captured["project_dir"] == str(tmp_path)
    assert captured["workspace_root"] is None
    assert json.loads(capsys.readouterr().out)["followup_id"] == "followup-cli-scope"


def test_internal_contributor_followup_preserves_single_delivery_owner(
    tmp_path: Path, monkeypatch, caller_provenance: dict
) -> None:
    _write_run(tmp_path)
    monkeypatch.setattr(subagent.subprocess, "Popen", lambda *a, **k: _Supervisor())

    result = subagent.follow_up_managed_subagent(
        run_id=TARGET_RUN_ID,
        message="Add the hot-context regression without owning Discord delivery.",
        project_dir=tmp_path,
        workspace_root=None,
        aggregation_role="internal_contributor",
        synthesis_group="current-root-delivery",
    )

    record = json.loads(Path(result.evidence_path).read_text())
    child = json.loads(Path(result.continuation_manifest_path).read_text())
    assert record["aggregation_role"] == "internal_contributor"
    assert record["synthesis_group"] == "current-root-delivery"
    assert child["aggregation"]["role"] == "internal_contributor"
    assert child["completion_delivery"]["status"] == "suppressed"


@pytest.mark.parametrize(
    ("backend", "model", "session_id"),
    [
        ("omp", "zai/glm-5.2", "resident_0123456789abcdef0123456789abcdef"),
        ("claude", "opus", "019f5d2e-d5da-75f3-a617-4712a1c57cc5"),
    ],
)
def test_non_codex_followup_preserves_provider_session_and_controls(
    tmp_path: Path,
    monkeypatch,
    caller_provenance: dict,
    backend: str,
    model: str,
    session_id: str,
) -> None:
    _write_run(tmp_path, backend=backend, model=model, session_id=session_id)
    monkeypatch.setattr(subagent.subprocess, "Popen", lambda *a, **k: _Supervisor())

    result = subagent.follow_up_managed_subagent(
        run_id=TARGET_RUN_ID,
        message=f"Continue the exact {backend} session.",
        project_dir=tmp_path,
        workspace_root=None,
    )
    child = json.loads(Path(result.continuation_manifest_path).read_text())

    assert child["backend"] == backend
    assert child["continued_session_id"] == session_id
    assert child["provider_options"] == {
        "toolsets": "file,web,terminal",
        "max_tokens": 32768,
        "timeout_s": 321.0,
    }
    assert child["model_session"]["provider"] == backend
    assert child["model_session"]["session_id"] == session_id


def test_terminal_followup_rejects_unconfirmed_provider_persistence(
    tmp_path: Path, caller_provenance: dict
) -> None:
    target_path = _write_run(
        tmp_path,
        status="failed",
        backend="claude",
        model="opus",
        session_id="019f5d2e-d5da-75f3-a617-4712a1c57cc5",
    )
    manifest = json.loads(target_path.read_text())
    manifest["model_session"]["state"] = "reserved_unconfirmed"
    target_path.write_text(json.dumps(manifest))

    with pytest.raises(
        subagent.SubagentFollowupError,
        match="session persistence is unconfirmed",
    ):
        subagent.follow_up_managed_subagent(
            run_id=TARGET_RUN_ID,
            message="Do not pretend this session can resume.",
            project_dir=tmp_path,
            workspace_root=None,
        )


@pytest.mark.parametrize(
    ("backend", "model", "session_id", "resume_flag"),
    [
        (
            "omp",
            "zai/glm-5.2",
            "resident_0123456789abcdef0123456789abcdef",
            "--resume-session",
        ),
        (
            "claude",
            "opus",
            "019f5d2e-d5da-75f3-a617-4712a1c57cc5",
            "--resume",
        ),
    ],
)
def test_non_codex_continuation_worker_resumes_exact_session(
    tmp_path: Path,
    monkeypatch,
    caller_provenance: dict,
    backend: str,
    model: str,
    session_id: str,
    resume_flag: str,
) -> None:
    _write_run(
        tmp_path,
        backend=backend,
        model=model,
        session_id=session_id,
    )
    monkeypatch.setattr(subagent.subprocess, "Popen", lambda *a, **k: _Supervisor())
    result = subagent.follow_up_managed_subagent(
        run_id=TARGET_RUN_ID,
        message=f"Resume {backend} now.",
        project_dir=tmp_path,
        workspace_root=None,
    )
    captured: dict[str, object] = {}

    class _Provider:
        pid = 9877

        def wait(self, timeout=None):
            captured["timeout"] = timeout
            return 0

        def poll(self):
            return 0

    def fake_provider(argv, **kwargs):
        # Skip the post-session summarizer (launches with --query-file and
        # no session-resume flags).
        if "--session-id" in argv or "--resume" in argv:
            captured["argv"] = list(argv)
            captured["env"] = kwargs["env"]
        output = kwargs["stdout"]
        if backend == "omp":
            output.write(b"CONTINUED\n")
            Path(argv[argv.index("--metadata-file") + 1]).write_text(
                json.dumps(
                    {
                        "session_id": session_id,
                        "resolved_model": model,
                        "toolsets": ["file", "web", "terminal"],
                        "usage": {"output_tokens": 2},
                        "events": [],
                    }
                )
            )
        else:
            output.write(
                (
                    json.dumps(
                        {
                            "type": "system",
                            "subtype": "init",
                            "session_id": session_id,
                            "model": model,
                            "tools": ["Read", "Bash"],
                        }
                    )
                    + "\n"
                    + json.dumps(
                        {
                            "type": "result",
                            "subtype": "success",
                            "session_id": session_id,
                            "is_error": False,
                            "result": "CONTINUED",
                            "usage": {"output_tokens": 2},
                        }
                    )
                    + "\n"
                ).encode()
            )
        output.flush()
        return _Provider()

    monkeypatch.setattr(subagent.subprocess, "Popen", fake_provider)
    child_path = Path(result.continuation_manifest_path)
    assert subagent._run_managed_manifest(child_path) == 0

    child = json.loads(child_path.read_text())
    argv = captured["argv"]
    assert resume_flag in argv
    assert session_id in argv
    assert captured["timeout"] == 321.0
    assert child["model_session"]["session_id"] == session_id
    assert child["session_dispatch"]["mode"] == "resume"
    assert Path(child["result_path"]).read_text().strip() == "CONTINUED"
    if backend == "claude":
        assert captured["env"]["CLAUDE_CODE_MAX_OUTPUT_TOKENS"] == "32768"


def test_contributor_followup_attaches_to_existing_queued_synthesis_owner(
    tmp_path: Path, monkeypatch, caller_provenance: dict
) -> None:
    target_path, owner_path = _write_queued_synthesis_owner(tmp_path)
    monkeypatch.setattr(
        subagent.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("queued owner attachment launched a worker"),
    )
    message = (
        "Use exact epic revision 28d54763 and change only upcoming M6A-M11; "
        "completed M5/M5A and current M6 are immutable."
    )

    result = subagent.follow_up_managed_subagent(
        run_id=TARGET_RUN_ID,
        message=message,
        project_dir=tmp_path,
        workspace_root=None,
        idempotency_key="custody-revision-28d54763",
    )

    assert result.ok is True
    assert result.route == "queued_synthesis_owner"
    assert result.delivery_owner_run_id == QUEUED_OWNER_RUN_ID
    assert result.continuation_run_id is None
    assert result.continuation_manifest_path is None
    assert result.status == "accepted"
    receipt = json.loads(Path(result.evidence_path).read_text())
    owner = json.loads(owner_path.read_text())
    target = json.loads(target_path.read_text())
    prompt = Path(owner["prompt_path"]).read_text()
    assert message in prompt
    assert receipt["state_history"][-1]["evidence"] == (
        "material_bound_to_existing_queued_synthesis_owner_prompt"
    )
    assert owner["prompt_sha256"] == hashlib.sha256(prompt.encode()).hexdigest()
    assert owner["queue"]["predecessor_run_ids"] == [
        TARGET_RUN_ID,
        SECOND_PREDECESSOR_RUN_ID,
    ]
    assert owner["queue"]["predecessor_states"] == [
        {"run_id": TARGET_RUN_ID, "status": "running"},
        {"run_id": SECOND_PREDECESSOR_RUN_ID, "status": "completed"},
    ]
    assert owner["queue"]["inbound_material"] == [
        {
            "schema_version": subagent.QUEUED_OWNER_MATERIAL_SCHEMA,
            "followup_id": result.followup_id,
            "target_run_id": TARGET_RUN_ID,
            "message_path": result.message_path,
            "message_sha256": hashlib.sha256(message.encode()).hexdigest(),
            "evidence_path": result.evidence_path,
            "accepted_at": receipt["accepted_at"],
        }
    ]
    assert owner["status"] == "queued"
    assert owner["completion_delivery"]["status"] == "pending"
    assert target["status"] == "running"
    assert target["completion_delivery"]["status"] == "suppressed"


def test_queued_synthesis_owner_attachment_is_idempotent_and_directly_addressable(
    tmp_path: Path, caller_provenance: dict
) -> None:
    _, owner_path = _write_queued_synthesis_owner(tmp_path)
    kwargs = {
        "run_id": QUEUED_OWNER_RUN_ID,
        "message": "Reconcile the active worktree before consuming upcoming milestones.",
        "project_dir": tmp_path,
        "workspace_root": None,
        "idempotency_key": "queued-owner-material-1",
    }

    first = subagent.follow_up_managed_subagent(**kwargs)
    second = subagent.follow_up_managed_subagent(**kwargs)

    assert first.followup_id == second.followup_id
    assert second.idempotent_replay is True
    owner = json.loads(owner_path.read_text())
    prompt = Path(owner["prompt_path"]).read_text()
    assert prompt.count("Reconcile the active worktree") == 1
    assert len(owner["queue"]["inbound_material"]) == 1


def test_running_synthesis_owner_attachment_preserves_material_without_launch(
    tmp_path: Path, monkeypatch, caller_provenance: dict
) -> None:
    target_path, owner_path = _write_queued_synthesis_owner(tmp_path)
    target = json.loads(target_path.read_text())
    target["status"] = "completed"
    target_path.write_text(json.dumps(target))
    owner = json.loads(owner_path.read_text())
    owner["status"] = "running"
    owner["queue"]["state"] = "running"
    owner["queue"]["predecessor_states"][0]["status"] = "completed"
    owner_path.write_text(json.dumps(owner))
    monkeypatch.setattr(
        subagent.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("running owner inbox launched a worker"),
    )

    result = subagent.follow_up_managed_subagent(
        run_id=TARGET_RUN_ID,
        message="Preserve the exact upcoming-milestone revision for synthesis.",
        project_dir=tmp_path,
        workspace_root=None,
        idempotency_key="running-owner-material-1",
    )

    assert result.route == "running_synthesis_owner_inbox"
    assert result.delivery_owner_run_id == QUEUED_OWNER_RUN_ID
    assert result.continuation_run_id is None
    receipt = json.loads(Path(result.evidence_path).read_text())
    owner = json.loads(owner_path.read_text())
    assert receipt["parent_status_at_acceptance"] == "running"
    assert receipt["launch_visibility"] == (
        "durable_owner_inbox_requires_process_observation"
    )
    assert receipt["state_history"][-1]["evidence"] == (
        "material_bound_to_existing_running_synthesis_owner_inbox"
    )
    assert len(owner["queue"]["inbound_material"]) == 1
    assert owner["status"] == "running"
    assert owner["completion_delivery"]["status"] == "pending"


def test_queued_synthesis_owner_attachment_rejects_conflicting_custody(
    tmp_path: Path, caller_provenance: dict
) -> None:
    _, owner_path = _write_queued_synthesis_owner(tmp_path)
    owner = json.loads(owner_path.read_text())
    owner["aggregation"]["key"] = "different-aggregation"
    owner_path.write_text(json.dumps(owner))

    with pytest.raises(subagent.SubagentFollowupError, match="aggregation custody"):
        subagent.follow_up_managed_subagent(
            run_id=TARGET_RUN_ID,
            message="Do not bypass ownership.",
            project_dir=tmp_path,
            workspace_root=None,
        )


def test_continuation_worker_resumes_exact_parent_session_and_records_acceptance(
    tmp_path: Path, monkeypatch, caller_provenance: dict
) -> None:
    _write_run(tmp_path)
    monkeypatch.setattr(subagent.subprocess, "Popen", lambda *a, **k: _Supervisor())
    result = subagent.follow_up_managed_subagent(
        run_id=TARGET_RUN_ID,
        message="Use both summaries.",
        project_dir=tmp_path,
        workspace_root=None,
    )
    captured: dict[str, object] = {}

    class _Codex:
        pid = 9876

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

    def fake_codex(argv, **kwargs):
        # The post-session summarizer launches the omp launcher too; capture
        # only the codex continuation invocation under test.
        if argv[:3] == ["codex", "exec", "resume"]:
            captured["argv"] = list(argv)
            captured["env"] = kwargs["env"]
        return _Codex()

    monkeypatch.setattr(subagent.subprocess, "Popen", fake_codex)
    child_path = Path(result.continuation_manifest_path)
    assert subagent._run_codex_manifest(child_path) == 0

    child = json.loads(child_path.read_text())
    argv = captured["argv"]
    assert argv[:3] == ["codex", "exec", "resume"]
    assert SESSION_ID in argv
    assert child["session_dispatch"] == {
        "status": "accepted",
        "mode": "resume",
        "session_id": SESSION_ID,
        "accepted_at": child["worker_started_at"],
        "evidence": "codex_resume_process_started",
    }
    assert child["model_session"]["session_id"] == SESSION_ID
    inherited = json.loads(captured["env"][DELEGATION_CONTEXT_ENV])
    assert inherited["source_record_id"] == "msg_newfollowupsrc"
    custody_events = [
        json.loads(line)
        for line in Path(child["custody_evidence_path"]).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(
        event["event_kind"] == "start"
        and event["evidence"] == "manifest_committed_before_process_launch"
        for event in custody_events
    )
    assert any(
        event["event_kind"] == "effect"
        and event["evidence"] == "codex_resume_process_started"
        for event in custody_events
    )
    assert any(
        event["event_kind"] == "terminal"
        and event["evidence"] == "managed_codex_worker_waited"
        for event in custody_events
    )


def test_live_followup_queues_exact_parent_interrupt_and_retry_is_idempotent(
    tmp_path: Path, monkeypatch, caller_provenance: dict
) -> None:
    target_path = _write_run(tmp_path, status="running", pid=111)
    parent = json.loads(target_path.read_text())
    parent["supervisor_start_ticks"] = "start-111"
    target_path.write_text(json.dumps(parent))
    monkeypatch.setattr(
        subagent,
        "_pid_matches_manifest",
        lambda pid, path: pid == 111 and path == target_path,
    )
    monkeypatch.setattr(
        subagent,
        "_pid_start_ticks",
        lambda pid: "start-111" if pid == 111 else "start-supervisor",
    )
    calls = 0

    def fake_popen(*args, **kwargs):
        nonlocal calls
        calls += 1
        return _Supervisor()

    monkeypatch.setattr(subagent.subprocess, "Popen", fake_popen)
    exact_message = "  Interrupt the current turn and continue in this session.  "
    kwargs = {
        "run_id": TARGET_RUN_ID,
        "message": exact_message,
        "project_dir": tmp_path,
        "workspace_root": None,
        "idempotency_key": "request-42",
        "require_live": True,
    }
    first = subagent.follow_up_managed_subagent(**kwargs)
    second = subagent.follow_up_managed_subagent(**kwargs)

    assert calls == 1
    assert first.continuation_run_id == second.continuation_run_id
    assert second.idempotent_replay is True
    record = json.loads(Path(first.evidence_path).read_text())
    assert record["parent_status_at_acceptance"] == "running"
    assert record["state_history"][-1]["evidence"] == (
        "continuation_queued_to_interrupt_active_parent"
    )
    assert Path(record["message_path"]).read_text() == exact_message + "\n"
    child = json.loads(Path(first.continuation_manifest_path).read_text())
    assert child["continuation_wait"]["status"] == "pending_parent_terminal"
    assert child["continuation_wait"]["interrupt_parent_on_session_ready"] is True
    assert child["parent_run_id"] == TARGET_RUN_ID


def test_live_only_followup_rejects_terminal_target_without_launch(
    tmp_path: Path, monkeypatch, caller_provenance: dict
) -> None:
    _write_run(tmp_path, status="completed")
    monkeypatch.setattr(
        subagent.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("terminal target launched a continuation"),
    )

    with pytest.raises(subagent.SubagentFollowupError, match="is not live"):
        subagent.follow_up_managed_subagent(
            run_id=TARGET_RUN_ID,
            message="Do not resume a terminal target from the live-only surface.",
            project_dir=tmp_path,
            workspace_root=None,
            require_live=True,
        )


def test_continuation_interrupts_only_exact_active_supervisor_before_resume(
    tmp_path: Path, monkeypatch, caller_provenance: dict
) -> None:
    target_path = _write_run(tmp_path, status="running", pid=111)
    parent = json.loads(target_path.read_text())
    parent["worker_start_ticks"] = "start-111"
    target_path.write_text(json.dumps(parent))
    monkeypatch.setattr(
        subagent,
        "_pid_matches_manifest",
        lambda pid, path: pid == 111 and path == target_path,
    )
    monkeypatch.setattr(subagent.subprocess, "Popen", lambda *a, **k: _Supervisor())
    result = subagent.follow_up_managed_subagent(
        run_id=TARGET_RUN_ID,
        message="Use this message now.",
        project_dir=tmp_path,
        workspace_root=None,
    )
    door_calls: list[dict[str, object]] = []

    monkeypatch.setattr(managed_agent, "_pid_start_ticks", lambda _pid: "start-111")
    monkeypatch.setattr(managed_agent.os, "getpgid", lambda _pid: 111)
    def lowest_signal_boundary(pid: int, signum: int) -> None:
        door_calls.append({"pid": pid, "signum": signum})
        parent = json.loads(target_path.read_text())
        parent["status"] = "interrupted"
        target_path.write_text(json.dumps(parent))

    monkeypatch.setattr(managed_agent.os, "kill", lowest_signal_boundary)
    monkeypatch.setattr(subagent.time, "sleep", lambda _seconds: None)
    child_path = Path(result.continuation_manifest_path)
    child = json.loads(child_path.read_text())

    resolved, session_id = subagent._await_continuation_parent(child_path, child)

    assert len(door_calls) == 1
    assert door_calls[0]["pid"] == 111
    assert door_calls[0]["signum"] == subagent.signal.SIGINT
    assert session_id == SESSION_ID
    assert resolved["continuation_wait"]["status"] == "parent_terminal"
    parent = json.loads(target_path.read_text())
    assert parent["followup_interrupt"]["evidence"] == (
        "exact_manifest_supervisor_identity_verified"
    )


def test_continuation_refuses_to_wait_when_supervisor_signal_is_refused(
    tmp_path: Path, monkeypatch, caller_provenance: dict
) -> None:
    target_path = _write_run(tmp_path, status="running", pid=111)
    parent = json.loads(target_path.read_text())
    parent["worker_start_ticks"] = "start-111"
    target_path.write_text(json.dumps(parent))
    monkeypatch.setattr(
        subagent,
        "_pid_matches_manifest",
        lambda pid, path: pid == 111 and path == target_path,
    )
    monkeypatch.setattr(subagent.subprocess, "Popen", lambda *a, **k: _Supervisor())
    result = subagent.follow_up_managed_subagent(
        run_id=TARGET_RUN_ID,
        message="Use this message now.",
        project_dir=tmp_path,
        workspace_root=None,
    )
    calls: list[dict[str, object]] = []

    def refuse_signal(path, manifest, pid, signum, **kwargs):
        calls.append({"path": path, "manifest": manifest, "pid": pid, "signum": signum, **kwargs})
        return False

    monkeypatch.setattr(subagent, "signal_managed_process", refuse_signal)
    monkeypatch.setattr(subagent.time, "sleep", lambda _seconds: pytest.fail("refused signal must not wait"))
    child_path = Path(result.continuation_manifest_path)
    child = json.loads(child_path.read_text())

    with pytest.raises(subagent.SubagentFollowupError, match="signal was refused"):
        subagent._await_continuation_parent(child_path, child)

    assert len(calls) == 1
    assert calls[0]["worker"] is False
    assert json.loads(child_path.read_text())["continuation_wait"]["status"] == (
        "pending_parent_terminal"
    )


def test_followup_rejects_unknown_malformed_or_cross_conversation_targets(
    tmp_path: Path, monkeypatch, caller_provenance: dict
) -> None:
    with pytest.raises(subagent.SubagentFollowupError, match="malformed"):
        subagent.follow_up_managed_subagent(
            run_id="../../manifest.json",
            message="unsafe",
            project_dir=tmp_path,
            workspace_root=None,
        )
    with pytest.raises(subagent.SubagentFollowupError, match="unknown"):
        subagent.follow_up_managed_subagent(
            run_id=TARGET_RUN_ID,
            message="unknown",
            project_dir=tmp_path,
            workspace_root=None,
        )

    _write_run(
        tmp_path,
        provenance=_provenance(
            source="msg_othersource", message="3003", conversation="rconv_otherconversation"
        ),
    )
    with pytest.raises(subagent.SubagentFollowupError, match="conversation"):
        subagent.follow_up_managed_subagent(
            run_id=TARGET_RUN_ID,
            message="wrong owner",
            project_dir=tmp_path,
            workspace_root=None,
        )

    monkeypatch.setenv(DELEGATION_CONTEXT_ENV, "{malformed")
    with pytest.raises(Exception, match="malformed or ambiguous provenance"):
        subagent.follow_up_managed_subagent(
            run_id=TARGET_RUN_ID,
            message="bad provenance",
            project_dir=tmp_path,
            workspace_root=None,
        )


def test_followup_revalidates_exact_source_after_discord_match(
    tmp_path: Path, monkeypatch, caller_provenance: dict
) -> None:
    _write_run(tmp_path)
    monkeypatch.setattr(
        subagent.subprocess,
        "Popen",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not launch")),
    )

    with pytest.raises(subagent.SubagentFollowupError, match="source custody changed"):
        subagent.follow_up_managed_subagent(
            run_id=TARGET_RUN_ID,
            message="do not attach after a target swap",
            project_dir=tmp_path,
            workspace_root=None,
            expected_target_source_record_id="msg_different_source",
            expected_target_discord_message_id="1001",
        )


def test_followup_rejects_ambiguous_model_session_ownership(
    tmp_path: Path, monkeypatch, caller_provenance: dict
) -> None:
    _write_run(tmp_path)
    _write_run(
        tmp_path,
        run_id="subagent-20260713-203300-aaaaaaaa",
        provenance=caller_provenance,
    )
    monkeypatch.setattr(
        subagent.subprocess,
        "Popen",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not launch")),
    )

    with pytest.raises(subagent.SubagentFollowupError, match="ambiguous"):
        subagent.follow_up_managed_subagent(
            run_id=TARGET_RUN_ID,
            message="do not branch an ambiguous session",
            project_dir=tmp_path,
            workspace_root=None,
        )


def test_model_session_identity_reads_only_bounded_log_prefix(
    tmp_path: Path, monkeypatch
) -> None:
    manifest_path = _write_run(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    log_path = Path(manifest["log_path"])
    with log_path.open("r+b") as handle:
        handle.seek(subagent.MAX_MODEL_SESSION_LOG_PREFIX_BYTES + 1024)
        handle.write(b"large-tail-marker\n")

    original_read_text = Path.read_text

    def reject_whole_log_read(path: Path, *args, **kwargs):
        if path == log_path:
            raise AssertionError("session ownership must not read the complete run log")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", reject_whole_log_read)

    assert subagent._manifest_session_ids(manifest_path, manifest) == {SESSION_ID}


def test_active_followup_without_session_evidence_falls_back_before_interrupt(
    tmp_path: Path, monkeypatch, caller_provenance: dict
) -> None:
    target_path = _write_run(tmp_path, status="running", session_id=None, pid=111)
    monkeypatch.setattr(
        subagent,
        "_pid_matches_manifest",
        lambda pid, path: pid == 111 and path == target_path,
    )
    monkeypatch.setattr(
        subagent.subprocess,
        "Popen",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not launch")),
    )
    monkeypatch.setattr(
        subagent.os,
        "kill",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not interrupt")),
    )

    with pytest.raises(subagent.SubagentFollowupError, match="active target has no"):
        subagent.follow_up_managed_subagent(
            run_id=TARGET_RUN_ID,
            message="Cannot safely continue yet.",
            project_dir=tmp_path,
            workspace_root=None,
        )


def test_concurrent_duplicate_followups_create_one_continuation(
    tmp_path: Path, monkeypatch, caller_provenance: dict
) -> None:
    _write_run(tmp_path)
    calls = 0
    calls_lock = threading.Lock()

    def fake_spawn(manifest_path, manifest):
        nonlocal calls
        with calls_lock:
            calls += 1
        current = dict(manifest)
        current["status"] = "running"
        return _Supervisor(), current

    # Patch the resident launch seam, not subprocess.Popen on Python's shared
    # subprocess module. Full-suite background activity may legitimately use
    # Popen and must not be counted as a duplicate continuation launch.
    monkeypatch.setattr(subagent, "_spawn_managed_supervisor", fake_spawn)
    kwargs = {
        "run_id": TARGET_RUN_ID,
        "message": "Only one continuation may own this Discord reply.",
        "project_dir": tmp_path,
        "workspace_root": None,
        "idempotency_key": "discord:message:2002",
    }
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: subagent.follow_up_managed_subagent(**kwargs), range(2)))

    assert calls == 1
    assert {result.continuation_run_id for result in results} == {
        results[0].continuation_run_id
    }
    assert sum(result.idempotent_replay for result in results) == 1


def test_followup_requires_inherited_provenance(
    tmp_path: Path, monkeypatch
) -> None:
    _write_run(tmp_path)
    monkeypatch.delenv(DELEGATION_CONTEXT_ENV, raising=False)
    with pytest.raises(subagent.SubagentFollowupError, match="requires inherited"):
        subagent.follow_up_managed_subagent(
            run_id=TARGET_RUN_ID,
            message="no caller custody",
            project_dir=tmp_path,
            workspace_root=None,
        )


def test_followup_cli_help_describes_active_and_terminal_semantics() -> None:
    help_text = " ".join(subagent._build_local_seam_parser().format_help().split())
    assert "active parents are safely interrupted" in help_text
    assert "terminal parents resume" in help_text
