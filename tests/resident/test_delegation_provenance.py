from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from arnold_pipelines.megaplan._core.state import write_plan_state
from arnold_pipelines.megaplan.chain.spec import ChainState, save_chain_state
from arnold_pipelines.megaplan.cloud.repair_contract import atomic_write_json
from arnold_pipelines.megaplan.cloud import cli as cloud_cli
from arnold_pipelines.megaplan.resident import profile as profile_module
from arnold_pipelines.megaplan.resident import subagent as subagent_module
from arnold_pipelines.megaplan.resident.auth import ResidentAuthorizer
from arnold_pipelines.megaplan.resident.config import ResidentConfig
from arnold_pipelines.megaplan.resident.profile import LaunchSubagentInput, MegaplanResidentProfile
from arnold_pipelines.megaplan.resident.provenance import (
    DELEGATION_CONTEXT_ENV,
    DelegationProvenanceError,
    encoded_provenance,
    normalize_delegation_provenance,
)
from arnold_pipelines.megaplan.resident.subagent import SubagentResult, launch_subagent_task
from arnold_pipelines.megaplan.resident import vp_todo
from arnold_pipelines.megaplan.store import FileStore, ResidentConversationInput


def _origin(*, source: str, message: str, conversation: str = "rconv_testconversation") -> dict:
    return {
        "transport": "discord",
        "applicability": "applicable",
        "resident_conversation_id": conversation,
        "conversation_id": conversation,
        "source_record_id": source,
        "conversation_key": "discord:dm:42",
        "discord_message_id": message,
        "message_id": message,
        "reply_to_message_id": message,
        "guild_id": None,
        "channel_id": "dm-channel-ignored-for-key-validation",
        "thread_id": None,
        "dm_user_id": "42",
        "source_kind": "discord_inbound_message",
    }


def _persist_source(root: Path, *, source: str, message: str, conversation: str = "rconv_testconversation") -> None:
    messages = root / ".megaplan/resident/messages"
    conversations = root / ".megaplan/resident/resident_conversations"
    messages.mkdir(parents=True, exist_ok=True)
    conversations.mkdir(parents=True, exist_ok=True)
    (messages / f"{source}.json").write_text(
        json.dumps(
            {
                "id": source,
                "conversation_id": conversation,
                "direction": "inbound",
                "discord_message_id": message,
            }
        )
    )
    (conversations / f"{conversation}.json").write_text(
        json.dumps(
            {
                "id": conversation,
                "transport": "discord",
                "conversation_key": "discord:dm:42",
                "channel_id": "dm-channel-ignored-for-key-validation",
                "dm_user_id": "42",
            }
        )
    )


class _Process:
    pid = 4321

    def poll(self):
        return None


@pytest.fixture(autouse=True)
def _isolate_process_provenance(monkeypatch) -> None:
    """Keep the fake worker's custody narrow and preserve real process checks."""

    monkeypatch.delenv(DELEGATION_CONTEXT_ENV, raising=False)
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


def test_launch_time_duplicate_is_idempotent(tmp_path, monkeypatch) -> None:
    source, message = "msg_duplicateorigin1", "1525300000000000001"
    _persist_source(tmp_path, source=source, message=message)
    calls: list[object] = []

    def fake_popen(*args, **kwargs):
        calls.append(args[0] if args else None)
        return _Process()

    monkeypatch.setattr(subagent_module.subprocess, "Popen", fake_popen)
    first = asyncio.run(
        launch_subagent_task(
            ResidentConfig(), task="same work", project_dir=str(tmp_path),
            request_id=source, launch_origin=_origin(source=source, message=message),
            mutation_claim="none",
            work_intent="review",
        )
    )
    second = asyncio.run(
        launch_subagent_task(
            ResidentConfig(), task="same work", project_dir=str(tmp_path),
            request_id=source, launch_origin=_origin(source=source, message=message),
            mutation_claim="none",
            work_intent="review",
        )
    )

    # Other test-owned background work can finish while this monkeypatch is
    # active. Count only the worker command rooted in this test's project.
    owned_calls = [call for call in calls if str(tmp_path) in str(call)]
    assert len(owned_calls) == 1
    assert first.run_id == second.run_id
    assert first.manifest_path == second.manifest_path
    manifest = json.loads(Path(first.manifest_path).read_text(encoding="utf-8"))
    assert manifest["supervisor_start_ticks"] == "test-start-4321"


def test_two_concurrent_messages_keep_distinct_exact_reply_targets(tmp_path, monkeypatch) -> None:
    origins = [
        ("msg_concurrentone1", "1525300000000000011"),
        ("msg_concurrenttwo2", "1525300000000000022"),
    ]
    for source, message in origins:
        _persist_source(tmp_path, source=source, message=message)
    monkeypatch.setattr(subagent_module.subprocess, "Popen", lambda *a, **k: _Process())

    async def launch_all():
        return await asyncio.gather(
            *(
                launch_subagent_task(
                    ResidentConfig(),
                    task=f"work for {source}",
                    project_dir=str(tmp_path),
                    request_id=source,
                    launch_origin=_origin(source=source, message=message),
                )
                for source, message in origins
            )
        )

    results = asyncio.run(launch_all())
    manifests = [json.loads(Path(result.manifest_path).read_text()) for result in results]
    assert {item["source_record_id"] for item in manifests} == {item[0] for item in origins}
    assert {
        item["completion_delivery"]["reply_target"]["message_id"] for item in manifests
    } == {item[1] for item in origins}
    assert len({item["correlation_id"] for item in manifests}) == 2


def test_ambiguous_burst_provenance_fails_before_process_launch(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        subagent_module.subprocess,
        "Popen",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not launch")),
    )
    with pytest.raises(DelegationProvenanceError, match="ambiguous"):
        asyncio.run(
            launch_subagent_task(
                ResidentConfig(),
                task="ambiguous work",
                project_dir=str(tmp_path),
                launch_origin={
                    "transport": "discord",
                    "applicability": "ambiguous",
                    "source_kind": "discord_burst",
                },
            )
        )


def test_non_discord_launch_is_explicitly_not_applicable(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(subagent_module.subprocess, "Popen", lambda *a, **k: _Process())
    result = asyncio.run(
        launch_subagent_task(
            ResidentConfig(), task="internal work", project_dir=str(tmp_path)
        )
    )
    manifest = json.loads(Path(result.manifest_path).read_text())
    assert manifest["launch_provenance"]["applicability"] == "not_applicable"
    assert manifest["completion_delivery"]["status"] == "not_applicable"
    assert "discord_origin" not in manifest


def test_inherited_discord_custody_commits_pending_outbox_before_process_start(
    tmp_path, monkeypatch
) -> None:
    source, message = "msg_inheritedorigin1", "1525300000000000088"
    _persist_source(tmp_path, source=source, message=message)
    inherited = normalize_delegation_provenance(_origin(source=source, message=message))
    monkeypatch.setenv(DELEGATION_CONTEXT_ENV, encoded_provenance(inherited))
    observed: dict[str, object] = {}

    def fake_popen(argv, **kwargs):
        manifest_path = Path(argv[-1])
        assert manifest_path.is_file()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        delivery = manifest["completion_delivery"]
        assert manifest["status"] == "launching"
        assert delivery["transport"] == "discord"
        assert delivery["status"] == "pending"
        assert delivery["reply_target"] == {
            "conversation_key": "discord:dm:42",
            "message_id": message,
            "source_record_id": source,
        }
        assert delivery["state_history"][-1]["evidence"] == "outbox_committed_before_launch"
        observed["manifest"] = manifest
        observed["child_provenance"] = json.loads(kwargs["env"][DELEGATION_CONTEXT_ENV])
        return _Process()

    monkeypatch.setattr(subagent_module.subprocess, "Popen", fake_popen)
    result = asyncio.run(
        launch_subagent_task(
            ResidentConfig(),
            task="work inherited from Discord",
            project_dir=str(tmp_path),
            request_id="caller-selected-request",
            mutation_claim="none",
            work_intent="review",
        )
    )

    manifest = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))
    assert observed["manifest"]
    assert manifest["request_id"] == source
    assert manifest["caller_request_id"] == "caller-selected-request"
    assert manifest["launch_provenance"]["source_record_id"] == source
    assert manifest["discord_origin"]["reply_to_message_id"] == message
    assert observed["child_provenance"]["source_record_id"] == source
    assert manifest["supervisor_start_ticks"] == "test-start-4321"


def test_caller_request_id_cannot_change_discord_launch_identity(tmp_path, monkeypatch) -> None:
    source, message = "msg_requestidentity1", "1525300000000000099"
    _persist_source(tmp_path, source=source, message=message)
    inherited = normalize_delegation_provenance(_origin(source=source, message=message))
    monkeypatch.setenv(DELEGATION_CONTEXT_ENV, encoded_provenance(inherited))
    calls = 0

    def fake_popen(*args, **kwargs):
        nonlocal calls
        calls += 1
        return _Process()

    monkeypatch.setattr(subagent_module.subprocess, "Popen", fake_popen)
    first = asyncio.run(
        launch_subagent_task(
            ResidentConfig(), task="same work", project_dir=str(tmp_path), request_id="first",
            mutation_claim="none",
            work_intent="review",
        )
    )
    second = asyncio.run(
        launch_subagent_task(
            ResidentConfig(), task="same work", project_dir=str(tmp_path), request_id="second",
            mutation_claim="none",
            work_intent="review",
        )
    )

    assert calls == 1
    assert first.run_id == second.run_id
    manifest = json.loads(Path(first.manifest_path).read_text(encoding="utf-8"))
    assert manifest["request_id"] == source
    assert manifest["caller_request_id"] == "first"
    assert manifest["supervisor_start_ticks"] == "test-start-4321"


def test_caller_origin_cannot_override_inherited_reply_route(tmp_path, monkeypatch) -> None:
    source, message = "msg_inheritedroute1", "1525300000000000101"
    _persist_source(tmp_path, source=source, message=message)
    inherited = normalize_delegation_provenance(_origin(source=source, message=message))
    monkeypatch.setenv(DELEGATION_CONTEXT_ENV, encoded_provenance(inherited))
    launched = False

    def fake_popen(*args, **kwargs):
        nonlocal launched
        launched = True
        return _Process()

    monkeypatch.setattr(subagent_module.subprocess, "Popen", fake_popen)
    conflicting = _origin(source=source, message=message)
    conflicting.update(
        {
            "conversation_key": "discord:dm:99",
            "dm_user_id": "99",
        }
    )
    with pytest.raises(DelegationProvenanceError, match="conversation_key conflicts"):
        asyncio.run(
            launch_subagent_task(
                ResidentConfig(),
                task="must keep the inherited route",
                project_dir=str(tmp_path),
                launch_origin=conflicting,
            )
        )
    assert launched is False


def test_omp_override_cannot_discard_inherited_discord_custody(
    tmp_path, monkeypatch
) -> None:
    source, message = "msg_ompcustody1", "1525300000000000111"
    _persist_source(tmp_path, source=source, message=message)
    inherited = normalize_delegation_provenance(_origin(source=source, message=message))
    monkeypatch.setenv(DELEGATION_CONTEXT_ENV, encoded_provenance(inherited))
    launched = False

    def fake_run(*args, **kwargs):
        nonlocal launched
        launched = True
        raise AssertionError("omp must not start for Discord-origin work")

    monkeypatch.setattr(subagent_module.subprocess, "run", fake_run)
    with pytest.raises(DelegationProvenanceError, match="cannot discard inherited custody"):
        asyncio.run(
            launch_subagent_task(
                ResidentConfig(),
                task="must remain durable",
                project_dir=str(tmp_path),
                backend="omp",
                background=False,
                launch_origin={
                    "transport": "non_discord",
                    "applicability": "not_applicable",
                    "source_kind": "caller_override",
                },
            )
        )
    assert launched is False


@pytest.mark.parametrize(
    "launch_origin",
    [
        None,
        {
            "transport": "non_discord",
            "applicability": "not_applicable",
            "source_kind": "scheduled_turn",
        },
    ],
)
def test_unbound_discord_shaped_request_fails_closed(
    tmp_path, monkeypatch, launch_origin
) -> None:
    launched = False

    def fake_popen(*args, **kwargs):
        nonlocal launched
        launched = True
        return _Process()

    monkeypatch.setattr(subagent_module.subprocess, "Popen", fake_popen)
    with pytest.raises(DelegationProvenanceError, match="cannot be bound"):
        asyncio.run(
            launch_subagent_task(
                ResidentConfig(),
                task="must not launch",
                project_dir=str(tmp_path),
                request_id="msg_missingcustody1",
                launch_origin=launch_origin,
            )
        )
    assert launched is False
    assert not (tmp_path / ".megaplan/plans/resident-subagents").exists()


def test_todo_sweep_launch_recovers_original_discord_provenance(tmp_path, monkeypatch) -> None:
    message = "1525300000000000033"
    store = FileStore(tmp_path / "store")
    conversation = store.upsert_resident_conversation(
        ResidentConversationInput(
            conversation_key="discord:dm:42",
            channel_id="dm-channel-ignored-for-key-validation",
            dm_user_id="42",
        )
    )
    source_record = store.create_message(
        epic_id=None,
        conversation_id=conversation.id,
        direction="inbound",
        content="Launch scheduled work.",
        discord_message_id=message,
        idempotency_key="todo-origin",
    )
    source = source_record.id
    provenance = normalize_delegation_provenance(
        _origin(source=source, message=message, conversation=conversation.id)
    )
    todo_path = tmp_path / "todo.json"
    item = vp_todo.add_item(
        todo_path, "scheduled work", launch_provenance=provenance
    )
    config = ResidentConfig(special_requests_todo_path=todo_path)
    profile = MegaplanResidentProfile(
        store=store,
        authorizer=ResidentAuthorizer(config),
        config=config,
    )
    captured: dict = {}

    async def fake_launch(config, **kwargs):
        captured.update(kwargs)
        return SubagentResult(
            ok=True, final_text="", stderr="", returncode=0,
            run_id="todo-run", status="running",
            manifest_path=str(tmp_path / "runs" / "todo-run" / "manifest.json"),
        )

    monkeypatch.setattr(profile_module, "launch_subagent_task", fake_launch)
    result = asyncio.run(
        profile._launch_subagent(
            LaunchSubagentInput(
                task="scheduled work",
                description="Run the scheduled work",
                request_id=item["id"],
            )
        )
    )
    assert result.ok
    assert captured["launch_origin"]["source_record_id"] == source
    assert captured["launch_origin"]["reply_to_message_id"] == message
    resolved = vp_todo.load_items(todo_path)[0]
    assert resolved["status"] == vp_todo.DELEGATED
    assert resolved["canonical_run_id"] == "todo-run"


def test_child_plan_chain_and_repair_records_retain_safe_projection(tmp_path, monkeypatch) -> None:
    provenance = normalize_delegation_provenance(
        _origin(source="msg_repairorigin12", message="1525300000000000044")
    )
    monkeypatch.setenv(DELEGATION_CONTEXT_ENV, encoded_provenance(provenance))

    plan_dir = tmp_path / ".megaplan/plans/repair-plan"
    plan_dir.mkdir(parents=True)
    write_plan_state(
        plan_dir,
        mode="replace",
        state={"current_state": "initialized", "meta": {}},
    )
    plan_state = json.loads((plan_dir / "state.json").read_text())

    spec_path = tmp_path / "chain.yaml"
    spec_path.write_text("milestones: []\n")
    save_chain_state(spec_path, ChainState())
    chain_path = next((tmp_path / ".megaplan/plans/.chains").glob("*.json"))
    chain_state = json.loads(chain_path.read_text())

    repair_path = tmp_path / "repair-data/attempts/attempt.json"
    atomic_write_json(repair_path, {"attempt_id": "repair-1", "status": "running"})
    repair = json.loads(repair_path.read_text())

    for projection in (
        plan_state["meta"]["resident_delegation"],
        chain_state["metadata"]["resident_delegation"],
        repair["resident_delegation"],
    ):
        assert projection["correlation_id"] == provenance["correlation_id"]
        assert projection["custody_id"] == provenance["custody_id"]
        serialized = json.dumps(projection)
        assert "content" not in serialized
        assert "token" not in serialized.lower()


def test_cloud_tmux_launch_exports_custody_to_remote_chain(monkeypatch) -> None:
    provenance = normalize_delegation_provenance(
        _origin(source="msg_cloudorigin123", message="1525300000000000077")
    )
    monkeypatch.setenv(DELEGATION_CONTEXT_ENV, encoded_provenance(provenance))
    command = cloud_cli._tmux_chain_launch_command(
        "/workspace/demo",
        "/workspace/demo/chain.yaml",
        session_name="demo-chain",
        marker_path="/workspace/.megaplan/cloud-sessions/demo-chain.json",
        identity_digest="digest-1",
        marker_payload={
            "session": "demo-chain",
            "workspace": "/workspace/demo",
            "remote_spec": "/workspace/demo/chain.yaml",
            "identity_digest": "digest-1",
            "run_kind": "chain",
        },
    )
    assert DELEGATION_CONTEXT_ENV in command
    assert provenance["correlation_id"] in command
    assert provenance["custody_id"] in command


def test_provenance_rejects_conflicts_and_drops_unapproved_metadata() -> None:
    value = _origin(source="msg_securityorigin1", message="1525300000000000055")
    value["authorization"] = "Bot secret-value"
    value["message_content"] = "private user text"
    normalized = normalize_delegation_provenance(value)
    serialized = json.dumps(normalized)
    assert "secret-value" not in serialized
    assert "private user text" not in serialized

    conflicting = dict(value)
    conflicting["reply_to_message_id"] = "1525300000000000099"
    with pytest.raises(DelegationProvenanceError, match="original Discord message"):
        normalize_delegation_provenance(conflicting)
