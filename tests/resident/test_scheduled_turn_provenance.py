from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from arnold_pipelines.megaplan.resident.agent_loop import AgentResponse
from arnold_pipelines.megaplan.resident.auth import AuthorizationSubject, ResidentAuthorizer
from arnold_pipelines.megaplan.resident.config import ResidentConfig
from arnold_pipelines.megaplan.resident.profile import MegaplanResidentProfile
from arnold_pipelines.megaplan.resident.provenance import DelegationProvenanceError
from arnold_pipelines.megaplan.resident.runtime import (
    InboundEvent,
    OutboundMessage,
    PersistedInboundEvent,
    ResidentRuntime,
)
from arnold_pipelines.megaplan.resident.scheduler import (
    HOURLY_SUPERFIXER_ENABLED_ENV,
    make_store_scheduler,
)
from arnold_pipelines.megaplan.resident.schedules import (
    ScheduleDefinition,
    ScheduleService,
)
from arnold_pipelines.megaplan.resident.subagent import _canonical_launch_provenance
from arnold_pipelines.megaplan.store import FileStore


class _Runner:
    request = None

    async def run(self, request, tools):
        self.request = request
        return AgentResponse(final_text="audited")


class _Outbound:
    async def send(self, message: OutboundMessage) -> None:
        return None


def _runtime(tmp_path):
    store = FileStore(tmp_path / "store")
    config = ResidentConfig(
        allowed_user_ids=("owner",), burst_idle_delay_s=0, burst_max_delay_s=1
    )
    authorizer = ResidentAuthorizer(config)
    runner = _Runner()
    runtime = ResidentRuntime(
        config=config,
        authorizer=authorizer,
        store=store,
        profile=MegaplanResidentProfile(store=store, authorizer=authorizer, config=config),
        runner=runner,
        outbound=_Outbound(),
        project_root=tmp_path,
    )
    return runtime, runner, store


def test_scheduled_turn_uses_exact_inbound_content_without_a_summary_field(tmp_path) -> None:
    async def run_case() -> None:
        runtime, runner, _ = _runtime(tmp_path)
        await runtime.receive(
            InboundEvent(
                idempotency_key="scheduled:1",
                conversation_key="discord:dm:owner",
                subject=AuthorizationSubject(user_id="owner"),
                content="synthetic audit prompt",
                raw={"source_kind": "scheduled_turn"},
            )
        )
        await runtime.coalescer.flush_all()

        current = runner.request.hot_context["current_request"]
        assert "summary_line" not in current
        assert current["authority"] == "persisted inbound records triggering this turn"
        assert len(current["source_record_ids"]) == 1
        assert '"content": "synthetic audit prompt"' in runner.request.system_prompt
        assert runner.request.launch_origin["applicability"] == "not_applicable"
        assert runner.request.launch_origin["source_kind"] == "scheduled_turn"
        assert runner.request.report_only is False

    asyncio.run(run_case())


def test_scheduled_audit_propagates_report_only_custody(tmp_path) -> None:
    async def run_case() -> None:
        runtime, runner, _ = _runtime(tmp_path)
        await runtime.receive(
            InboundEvent(
                idempotency_key="scheduled:report-only",
                conversation_key="discord:dm:owner",
                subject=AuthorizationSubject(user_id="owner"),
                content="bounded todo audit",
                raw={"source_kind": "scheduled_turn", "report_only": True},
            )
        )
        await runtime.coalescer.flush_all()

        assert runner.request.report_only is True
        assert runner.request.launch_origin["report_only"] is True

    asyncio.run(run_case())


def test_scheduled_turn_needs_no_parallel_request_summary(tmp_path) -> None:
    async def run_case() -> None:
        runtime, runner, store = _runtime(tmp_path)
        await runtime.receive(
            InboundEvent(
                idempotency_key="scheduled:missing",
                conversation_key="discord:dm:owner",
                subject=AuthorizationSubject(user_id="owner"),
                content="synthetic audit prompt",
                raw={"source_kind": "scheduled_turn"},
            )
        )
        await runtime.coalescer.flush_all()
        assert runner.request is not None
        assert store.get_resident_conversation_by_key(
            transport="discord", conversation_key="discord:dm:owner"
        ) is not None

    asyncio.run(run_case())


def test_mixed_scheduler_and_discord_burst_cannot_borrow_discord_provenance(tmp_path) -> None:
    runtime, _, _ = _runtime(tmp_path)
    subject = AuthorizationSubject(user_id="owner")
    scheduled = InboundEvent(
        idempotency_key="scheduled:mixed",
        conversation_key="discord:dm:owner",
        subject=subject,
        content="scheduled",
        raw={
            "source_kind": "scheduled_turn",
        },
    )
    discord = InboundEvent(
        idempotency_key="discord:mixed",
        conversation_key="discord:dm:owner",
        subject=subject,
        content="user request",
        raw={"discord_message_id": "1526500000000000000"},
    )
    conversation = type("Conversation", (), {"conversation_key": "discord:dm:owner"})()
    message = type("Message", (), {"id": "msg_mixed"})()
    items = (
        PersistedInboundEvent(scheduled, conversation, message),
        PersistedInboundEvent(discord, conversation, message),
    )

    origin = runtime._managed_subagent_launch_origin(
        items, turn_id="turn_mixed", timezone_name="UTC"
    )

    assert origin["applicability"] == "ambiguous"
    assert origin["source_kind"] == "mixed_scheduler_discord_burst"


# ── superfixer_proactive launch provenance (Phase 4, action-off) ─────────────


SFX_NOW = datetime(2026, 8, 7, 12, 0, tzinfo=UTC)


def _sfx_row() -> ScheduleDefinition:
    prompt = "Inspect the pinned chain and fix what is broken."
    return ScheduleDefinition.model_validate(
        {
            "schema": "arnold-resident-schedule-v1",
            "schedule_id": "sched_superfixer_provenance_test",
            "revision": 1,
            "generation": 1,
            "state": "active",
            "owner": {"principal_id": "resident_role:test", "custody_scope": "tests"},
            "authorization": {
                "grant_id": "grant_superfixer_v1",
                "source_envelope_digest": "sha256:" + "a" * 64,
                "approved_at": "2026-08-07T00:00:00Z",
                "expires_at": "2027-08-07T00:00:00Z",
                "maximum_work_intent": "execution",
                "launch_origin": {"applicability": "not_applicable"},
                "route_ref": "inherited-source-route",
            },
            "schedule": {"kind": "at", "at": SFX_NOW.isoformat(), "timezone": "UTC"},
            "bounds": {"max_occurrences": 2},
            "policies": {
                "misfire": "latest_once", "catch_up_limit": 1, "grace": "PT5M",
                "overlap": "forbid", "max_active": 1,
            },
            "target": {
                "kind": "resident_orchestrator_turn",
                "prompt_ref": "resident-prompt://superfixer/v1",
                "prompt": prompt,
                "prompt_digest": "sha256:" + hashlib.sha256(prompt.encode()).hexdigest(),
                "model": "omp:deepseek/deepseek-v4-flash",
                "profile": "resident-subagent-standard",
                "toolsets": ["repo_read"],
                "work_intent": "execution",
                "task_kind": "autonomous",
                "operation": "superfixer_proactive",
            },
            "delivery": {
                "synthesis_owner": "schedule_root",
                "route_ref": "inherited-source-route",
                "mode": "exact_authorized_route",
            },
            "retry": {
                "launch_max_attempts": 3, "initial_backoff": "PT1S", "maximum_backoff": "PT1M",
            },
            "quota": {"max_runs_per_day": 10, "max_concurrent_runs": 1},
            "created_at": "2026-08-07T00:00:00Z",
            "updated_at": "2026-08-07T00:00:00Z",
            "audit_reason": "superfixer provenance test fixture",
        }
    )


def test_superfixer_launch_origin_is_scheduled_turn_with_occurrence_custody(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The superfixer launch never borrows Discord custody: the occurrence
    claim is the only authority (non-discord, scheduled_turn)."""
    store = FileStore(tmp_path / "store")
    service = ScheduleService(tmp_path / "store")
    row = _sfx_row()
    service.create(row, idempotency_key="sfx-provenance")
    receipt = asyncio.run(service.run_due_once(now=SFX_NOW, worker_id="superfixer-schedule"))
    assert receipt.launched == 1
    projection = service.repo.occurrences(row.schedule_id)[0]
    job = store.load_scheduled_job(projection.run_id.removeprefix("scheduled-job:"))

    monkeypatch.setenv(HOURLY_SUPERFIXER_ENABLED_ENV, "1")
    monkeypatch.delenv("ARNOLD_RESIDENT_DELEGATION_CONTEXT", raising=False)
    monkeypatch.delenv("ARNOLD_RUNTIME_MANIFEST", raising=False)
    import arnold_pipelines.megaplan.resident.scheduler as scheduler_module

    monkeypatch.setattr(
        scheduler_module, "_runtime_manifest_path", lambda: tmp_path / "no-such-manifest.json"
    )
    captured: dict = {}
    manifest = tmp_path / "sfx-manifest.json"

    def fake_launch(**kwargs):
        captured.update(kwargs)
        manifest.write_text(json.dumps({"status": "launching"}), encoding="utf-8")
        return SimpleNamespace(
            ok=True,
            returncode=0,
            run_id="sfx-provenance-run", manifest_path=str(manifest), status="running"
        )

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.resident.subagent.launch_superfixer_proactive_managed",
        fake_launch,
    )
    worker = make_store_scheduler(
        store=store, config=ResidentConfig(), cloud_backend=None, worker_id="sfx-consumer"
    )
    result = asyncio.run(worker.run_due_once(now=SFX_NOW))
    assert result.fired == 1

    origin = captured["launch_origin"]
    assert origin["applicability"] == "not_applicable"
    assert origin["transport"] == "non_discord"
    assert origin["source_kind"] == "scheduled_turn"
    assert origin["superfixer_proactive"] is True
    assert origin["occurrence_id"] == projection.occurrence.occurrence_id
    # No Discord reply-chain fields: nothing borrowable from a user turn.
    assert "resident_conversation_id" not in origin
    assert "discord_message_id" not in origin
    assert "reply_to_message_id" not in origin
    assert "conversation_key" not in origin
    # Occurrence custody rides in the schedule context (durable manifest).
    context = captured["schedule_context"]
    assert context["occurrence_id"] == projection.occurrence.occurrence_id
    assert context["occurrence_key"] == projection.occurrence.occurrence_key
    assert context["claim"]["claim_owner"] == "sfx-consumer"
    assert context["claim"]["fence"] >= 1
    assert context["superfixer"] is True
    assert captured["request_id"] == projection.occurrence.occurrence_id


def test_superfixer_launch_fails_closed_when_discord_custody_inherited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An inherited Discord envelope can never be discarded by the backstop:
    the launch fails closed instead of borrowing or reclassifying custody."""
    monkeypatch.setenv(
        "ARNOLD_RESIDENT_DELEGATION_CONTEXT",
        json.dumps(
            {
                "schema_version": "arnold-resident-delegation-provenance-v1",
                "applicability": "applicable",
                "transport": "discord",
                "resident_conversation_id": "conv_1",
                "source_record_id": "msg_1",
                "discord_message_id": "1526500000000000000",
                "reply_to_message_id": "1526500000000000000",
                "conversation_key": "discord:dm:42",
                "dm_user_id": "42",
            }
        ),
    )
    with pytest.raises(DelegationProvenanceError, match="cannot discard inherited custody"):
        _canonical_launch_provenance(
            {
                "applicability": "not_applicable",
                "transport": "non_discord",
                "source_kind": "scheduled_turn",
                "superfixer_proactive": True,
                "occurrence_id": "occ_1",
            },
            project_root=tmp_path,
            request_id="occ_1",
        )


def test_superfixer_launch_origin_normalizes_to_non_discord_scheduled_turn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ARNOLD_RESIDENT_DELEGATION_CONTEXT", raising=False)
    normalized = _canonical_launch_provenance(
        {
            "applicability": "not_applicable",
            "transport": "non_discord",
            "source_kind": "scheduled_turn",
            "superfixer_proactive": True,
            "occurrence_id": "occ_1",
            "claim_owner": "sfx-consumer",
            "fence": 3,
        },
        project_root=tmp_path,
        request_id="occ_1",
    )
    assert normalized["applicability"] == "not_applicable"
    assert normalized["transport"] == "non_discord"
    assert normalized["source_kind"] == "scheduled_turn"
    assert "discord_message_id" not in normalized
    assert "resident_conversation_id" not in normalized
