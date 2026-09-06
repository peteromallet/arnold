from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from arnold_pipelines.megaplan.resident.agent_loop import (
    AgentRequest,
    _durable_launch_handoff_response,
)
from arnold_pipelines.megaplan.resident.auth import AuthorizationSubject
from arnold_pipelines.megaplan.resident.provenance import normalize_delegation_provenance
from arnold_pipelines.megaplan.resident import subagent as subagent_module
from arnold_pipelines.megaplan.resident.query_relationship import (
    classify_query_relationship,
    correlate_semantic_follow_up,
    relationship_store_root,
)
import pytest
from arnold_pipelines.megaplan.resident.reply_chain import build_reply_provenance
from arnold_pipelines.megaplan.resident.subagent import (
    _completion_payload,
    _delivery_claim,
    launch_codex_subagent_detached,
    list_managed_resident_agents,
)
from arnold_pipelines.megaplan.resident.tool_schemas import ToolCallAuditRecord
from arnold_pipelines.megaplan.store import FileStore, ResidentConversationInput


CONVERSATION_KEY = "discord:dm:42"


@pytest.fixture(autouse=True)
def _fake_worker_process_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bind this module's synthetic Popen PIDs to real custody checks only."""

    real_start_ticks = subagent_module._pid_start_ticks
    real_pid_live = subagent_module._pid_live
    fake_pids = {4201, 4301, 4401}
    monkeypatch.setattr(
        subagent_module,
        "_pid_start_ticks",
        lambda pid: f"test-start-{pid}" if pid in fake_pids else real_start_ticks(pid),
    )
    monkeypatch.setattr(
        subagent_module,
        "_pid_live",
        lambda pid: True if pid in fake_pids else real_pid_live(pid),
    )


def _conversation_and_queries(tmp_path: Path):
    store = FileStore(tmp_path / "store")
    conversation = store.upsert_resident_conversation(
        ResidentConversationInput(
            conversation_key=CONVERSATION_KEY,
            channel_id="42",
            dm_user_id="42",
        )
    )
    parent_provenance = build_reply_provenance(
        source_message_id="1526369073418731653",
        source_author_id="42",
        conversation_key=CONVERSATION_KEY,
        scope={"dm_user_id": "42"},
        raw_chain=None,
        reference_message_id=None,
        reference_author_id=None,
        reference_content=None,
    )
    parent = store.create_message(
        epic_id=None,
        conversation_id=conversation.id,
        direction="inbound",
        content="Implement resident launch and delivery behavior.",
        discord_message_id="1526369073418731653",
        discord_reply_provenance=parent_provenance,
        idempotency_key="parent",
    )
    current_provenance = build_reply_provenance(
        source_message_id="1526369712806563840",
        source_author_id="42",
        conversation_key=CONVERSATION_KEY,
        scope={"dm_user_id": "42"},
        raw_chain={
            "ancestors": [
                {
                    "message_id": "1526369073418731653",
                    "author_id": "42",
                    "content": parent.content,
                    "status": "available",
                }
            ],
            "chain_complete": True,
            "termination_reason": "root",
        },
        reference_message_id="1526369073418731653",
        reference_author_id="42",
        reference_content=parent.content,
        stored_parent=parent,
    )
    current = store.create_message(
        epic_id=None,
        conversation_id=conversation.id,
        direction="inbound",
        content="Also consolidate reviewer results into one reply.",
        discord_message_id="1526369712806563840",
        discord_reply_provenance=current_provenance,
        idempotency_key="current",
    )
    return store, conversation, parent, current


def test_query_relationship_uses_authoritative_reply_records_and_persists(tmp_path: Path) -> None:
    store, conversation, parent, current = _conversation_and_queries(tmp_path)
    parent_relation = classify_query_relationship(
        store=store,
        conversation=conversation,
        current=parent,
        project_root=tmp_path,
    )
    relation = classify_query_relationship(
        store=store,
        conversation=conversation,
        current=current,
        project_root=tmp_path,
    )

    assert parent_relation["classification"] == "independent"
    assert relation["classification"] == "follow_up"
    assert relation["classification_basis"] == "immutable_reply_to_inbound_query"
    assert relation["root_request"]["source_record_id"] == parent.id
    assert relation["root_request"]["discord_message_id"] == "1526369073418731653"
    assert len(relation["root_request"]["source_content_sha256"]) == 64
    assert relation["current_request"] == relation["delivery_owner"]
    assert relation["current_request"]["source_record_id"] == current.id
    assert Path(relation["evidence_path"]).is_file()
    assert Path(relation["evidence_path"]).parent == (
        relationship_store_root(store, tmp_path) / "query_relationships"
    )


def test_newest_launch_is_single_synthesis_delivery_owner_with_descriptions(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("ARNOLD_RESIDENT_DELEGATION_CONTEXT", raising=False)
    store, conversation, parent, current = _conversation_and_queries(tmp_path)
    classify_query_relationship(
        store=store,
        conversation=conversation,
        current=parent,
        project_root=tmp_path,
    )
    relation = classify_query_relationship(
        store=store,
        conversation=conversation,
        current=current,
        project_root=tmp_path,
    )
    provenance = normalize_delegation_provenance(
        {
            "transport": "discord",
            "applicability": "applicable",
            "resident_conversation_id": conversation.id,
            "source_record_id": current.id,
            "conversation_key": CONVERSATION_KEY,
            "discord_message_id": current.discord_message_id,
            "reply_to_message_id": current.discord_message_id,
            "dm_user_id": "42",
            "source_kind": "discord_inbound_message",
        }
    )

    class Process:
        def __init__(self, pid: int) -> None:
            self.pid = pid

    pids = iter((4101, 4102))

    def spawn(manifest_path, manifest):
        process = Process(next(pids))
        current = dict(manifest)
        current.update({"status": "running", "pid": process.pid})
        manifest_path.write_text(json.dumps(current))
        return process, current

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.resident.subagent._spawn_managed_supervisor",
        spawn,
    )
    first = launch_codex_subagent_detached(
        task="Review the proposed resident relationship contract.",
        description="Review the resident query-folding contract",
        aggregation_role="internal_contributor",
        synthesis_group="resident-correlation",
        project_dir=str(tmp_path),
        launch_origin=provenance,
        query_relationship=relation,
    )
    second = launch_codex_subagent_detached(
        task="Synthesize the implementation and reviewer evidence.",
        description="Synthesize implementation and reviewer evidence",
        synthesis_group="resident-correlation",
        project_dir=str(tmp_path),
        launch_origin=provenance,
        query_relationship=relation,
    )

    first_manifest = json.loads(Path(first.manifest_path).read_text())
    second_manifest = json.loads(Path(second.manifest_path).read_text())
    assert first_manifest["description"] == "Review the resident query-folding contract."
    assert first_manifest["aggregation"]["role"] == "internal_contributor"
    assert first_manifest["completion_delivery"]["status"] == "suppressed"
    assert first_manifest["aggregation"]["delivery_owner_run_id"] == second.run_id
    assert _delivery_claim(Path(first.manifest_path), now=datetime.now(UTC)) is None
    assert second_manifest["description"] == "Synthesize implementation and reviewer evidence."
    assert second_manifest["aggregation"]["role"] == "synthesis_delivery_owner"
    assert second_manifest["completion_delivery"]["status"] == "pending"
    assert second_manifest["query_relationship"]["root_request"]["discord_message_id"] == (
        "1526369073418731653"
    )
    assert "root request source/message" in Path(second_manifest["prompt_path"]).read_text()
    assert second_manifest["aggregation"]["contributors"][0]["run_id"] == first.run_id
    assert str(Path(first.result_path).resolve()) in Path(
        second_manifest["prompt_path"]
    ).read_text()

    status = list_managed_resident_agents(project_root=tmp_path, workspace_root=None)
    rows = {row["run_id"]: row for row in status["recent"] + status["running"]}
    assert rows[second.run_id]["description"] == (
        "Synthesize implementation and reviewer evidence."
    )
    assert rows[second.run_id]["aggregation"]["delivery_owner_run_id"] == second.run_id

    payload = _completion_payload(
        second_manifest,
        {"content": "Verification outcome: success.", "result_kind": "test"},
    )
    assert payload["content"].splitlines()[0] == (
        "Related Discord messages: root request 1526369073418731653; current follow-up "
        "and delivery target 1526369712806563840."
    )
    assert payload["content"].splitlines()[2] == "Verification outcome: success."
    assert payload["result_kind"] == "test"
    assert len(payload["content_sha256"]) == 64


def test_semantic_followup_promotion_preserves_provenance_and_is_idempotent(
    tmp_path: Path,
) -> None:
    store, conversation, parent, current = _conversation_and_queries(tmp_path)
    # Create an independent newer message to exercise semantic correlation.
    current_provenance = build_reply_provenance(
        source_message_id="1526369712806563999",
        source_author_id="42",
        conversation_key=CONVERSATION_KEY,
        scope={"dm_user_id": "42"},
        raw_chain=None,
        reference_message_id=None,
        reference_author_id=None,
        reference_content=None,
    )
    current = store.create_message(
        epic_id=None,
        conversation_id=conversation.id,
        direction="inbound",
        content="Please consolidate the related review results.",
        discord_message_id="1526369712806563999",
        discord_reply_provenance=current_provenance,
        idempotency_key="semantic-current",
    )
    classify_query_relationship(
        store=store, conversation=conversation, current=parent, project_root=tmp_path
    )
    classify_query_relationship(
        store=store, conversation=conversation, current=current, project_root=tmp_path
    )
    kwargs = {
        "store": store,
        "conversation": conversation,
        "current_source_record_id": current.id,
        "earlier_source_record_id": parent.id,
        "semantic_description": "Consolidate resident reviewer results",
        "rationale": "The newer request extends the same delivery contract.",
        "project_root": tmp_path,
    }

    first = correlate_semantic_follow_up(**kwargs)
    second = correlate_semantic_follow_up(**kwargs)

    assert first["classification_basis"] == "resident_model_semantic_judgment"
    assert first["root_request"]["source_record_id"] == parent.id
    assert first["current_request"]["description"] == (
        "Consolidate resident reviewer results."
    )
    assert second["root_request"] == first["root_request"]
    assert second["current_request"]["source_record_id"] == current.id
    assert "content" not in first["current_request"]


def test_semantic_followup_rejects_cross_author_candidate(tmp_path: Path) -> None:
    store, conversation, parent, current = _conversation_and_queries(tmp_path)
    other_provenance = build_reply_provenance(
        source_message_id="1526369073418731666",
        source_author_id="99",
        conversation_key=CONVERSATION_KEY,
        scope={"dm_user_id": "99"},
        raw_chain=None,
        reference_message_id=None,
        reference_author_id=None,
        reference_content=None,
    )
    other = store.create_message(
        epic_id=None,
        conversation_id=conversation.id,
        direction="inbound",
        content="Another user's request",
        discord_message_id="1526369073418731666",
        discord_reply_provenance=other_provenance,
        idempotency_key="other-user",
    )

    with pytest.raises(ValueError, match="custody"):
        correlate_semantic_follow_up(
            store=store,
            conversation=conversation,
            current_source_record_id=current.id,
            earlier_source_record_id=other.id,
            semantic_description="Unsafe cross-user grouping",
            rationale="Looks nearby",
            project_root=tmp_path,
        )


def test_independent_launches_do_not_share_delivery_ownership(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("ARNOLD_RESIDENT_DELEGATION_CONTEXT", raising=False)
    store, conversation, _parent, current = _conversation_and_queries(tmp_path)
    relation = classify_query_relationship(
        store=store, conversation=conversation, current=current, project_root=tmp_path
    )
    provenance = normalize_delegation_provenance(
        {
            "transport": "discord",
            "applicability": "applicable",
            "resident_conversation_id": conversation.id,
            "source_record_id": current.id,
            "conversation_key": CONVERSATION_KEY,
            "discord_message_id": current.discord_message_id,
            "reply_to_message_id": current.discord_message_id,
            "dm_user_id": "42",
            "source_kind": "discord_inbound_message",
        }
    )

    class Process:
        pid = 4201

        def poll(self):
            return None

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.resident.subagent.subprocess.Popen",
        lambda *args, **kwargs: Process(),
    )
    first = launch_codex_subagent_detached(
        task="Implement A", description="Implement independent A", project_dir=str(tmp_path),
        launch_origin=provenance, query_relationship=relation,
    )
    second = launch_codex_subagent_detached(
        task="Implement B", description="Implement independent B", project_dir=str(tmp_path),
        launch_origin=provenance, query_relationship=relation,
    )

    first_manifest = json.loads(Path(first.manifest_path).read_text())
    second_manifest = json.loads(Path(second.manifest_path).read_text())
    assert first_manifest["aggregation"]["key"] != second_manifest["aggregation"]["key"]
    assert first_manifest["aggregation"]["role"] == "synthesis_delivery_owner"
    assert first_manifest["completion_delivery"]["status"] == "pending"


def test_launch_retry_identity_includes_canonical_description(
    tmp_path: Path, monkeypatch
) -> None:
    calls = 0

    class Process:
        pid = 4301

        def poll(self):
            return None

    def launch(*args, **kwargs):
        nonlocal calls
        calls += 1
        return Process()

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.resident.subagent.subprocess.Popen", launch
    )
    kwargs = {
        "task": "Implement the contract",
        "description": "Implement canonical summaries",
        "project_dir": str(tmp_path),
    }
    first = launch_codex_subagent_detached(**kwargs)
    replay = launch_codex_subagent_detached(**kwargs)
    changed = launch_codex_subagent_detached(
        **{**kwargs, "description": "Implement semantic correlation"}
    )

    assert replay.run_id == first.run_id
    assert changed.run_id != first.run_id
    assert calls == 2
    changed_manifest = json.loads(Path(changed.manifest_path).read_text())
    assert changed_manifest["supervisor_start_ticks"] == "test-start-4301"


def test_delivered_synthesis_group_rejects_second_owner(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("ARNOLD_RESIDENT_DELEGATION_CONTEXT", raising=False)
    class Process:
        pid = 4401

        def poll(self):
            return None

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.resident.subagent.subprocess.Popen",
        lambda *args, **kwargs: Process(),
    )
    provenance = normalize_delegation_provenance(
        {
            "transport": "discord",
            "applicability": "applicable",
            "resident_conversation_id": "rconv_deliveredgroup",
            "source_record_id": "msg_deliveredgroup",
            "conversation_key": "discord:dm:42",
            "discord_message_id": "1526369073418731999",
            "reply_to_message_id": "1526369073418731999",
            "dm_user_id": "42",
            "source_kind": "discord_inbound_message",
        }
    )
    first = launch_codex_subagent_detached(
        task="Synthesize applicable once",
        description="Synthesize the applicable resident batch",
        synthesis_group="applicable-batch",
        project_dir=str(tmp_path),
        launch_origin=provenance,
    )
    manifest_path = Path(first.manifest_path)
    manifest = json.loads(manifest_path.read_text())
    manifest["completion_delivery"]["status"] = "delivered"
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(ValueError, match="delivered owner"):
        launch_codex_subagent_detached(
            task="Synthesize applicable twice",
            description="Replace the delivered resident batch",
            synthesis_group="applicable-batch",
            project_dir=str(tmp_path),
            launch_origin=provenance,
        )


def test_reply_to_resident_output_does_not_cross_author_boundary(
    tmp_path: Path,
) -> None:
    store, conversation, parent, _current = _conversation_and_queries(tmp_path)
    turn = store.create_turn(
        epic_id=None,
        triggered_by_message_ids=[parent.id],
        idempotency_key="parent-turn",
    )
    outbound = store.create_message(
        epic_id=None,
        conversation_id=conversation.id,
        direction="outbound",
        content="Resident response",
        discord_message_id="1526369073418731777",
        bot_turn_id=turn.id,
        idempotency_key="resident-output",
    )
    provenance = build_reply_provenance(
        source_message_id="1526369073418731888",
        source_author_id="99",
        conversation_key=CONVERSATION_KEY,
        scope={"channel_id": "42"},
        raw_chain={
            "ancestors": [
                {
                    "message_id": outbound.discord_message_id,
                    "author_id": "resident",
                    "content": outbound.content,
                    "status": "available",
                }
            ],
            "chain_complete": True,
            "termination_reason": "root",
        },
        reference_message_id=outbound.discord_message_id,
        reference_author_id="resident",
        reference_content=outbound.content,
        stored_parent=outbound,
    )
    other_user = store.create_message(
        epic_id=None,
        conversation_id=conversation.id,
        direction="inbound",
        content="Unrelated user reply",
        discord_message_id="1526369073418731888",
        discord_reply_provenance=provenance,
        idempotency_key="other-user-reply",
    )

    relation = classify_query_relationship(
        store=store,
        conversation=conversation,
        current=other_user,
        project_root=tmp_path,
    )

    assert relation["classification"] == "independent"


def test_launch_acknowledgement_names_run_description_and_synthesis_owner() -> None:
    request = AgentRequest(
        conversation_id="rconv_testquery",
        messages=(),
        system_prompt="test",
        subject=AuthorizationSubject(user_id="42", channel_id="42"),
        launch_origin={"applicability": "applicable"},
    )
    call = ToolCallAuditRecord(
        id="call-1",
        tool_name="launch_subagent",
        operation_kind="write",
        arguments={
            "task": "do work",
            "description": "  Implement query folding sk-abcdefghijklmnopqrstuvwxyz1234567890  ",
            "aggregation_role": "synthesis_delivery_owner",
        },
        result={
            "ok": True,
            "data": {
                "run_id": "subagent-20260713-120000-aaaaaaaa",
                "status": "running",
                "description": "Implement query folding.",
            },
        },
        duration_ms=1,
    )

    response = _durable_launch_handoff_response(
        request=request,
        current_tool_calls=[call],
        all_tool_calls=[call],
        steps_executed=1,
    )

    assert response is not None
    assert "Implement query folding." in response.final_text
    assert "sk-" not in response.final_text
    assert "One synthesis owner will consolidate terminal results" in response.final_text
