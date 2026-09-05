from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from arnold_pipelines.megaplan.resident import scheduler as scheduler_module
from arnold_pipelines.megaplan.resident import schedules as schedules_module
from arnold_pipelines.megaplan.resident.cloud import CloudToolRequest, CloudToolResult
from arnold_pipelines.megaplan.resident.config import ResidentConfig
from arnold_pipelines.megaplan.resident.runtime import OutboundMessage
from arnold_pipelines.megaplan.resident.scheduler import (
    HOURLY_SUPERFIXER_ENABLED_ENV,
    _todo_authoritative_inbound,
    hourly_superfixer_enabled,
    make_store_scheduler,
)
from arnold_pipelines.megaplan.store import (
    CloudRunInput,
    FileStore,
    ResidentConversationInput,
    ScheduledJobInput,
)


class FakeCloudBackend:
    async def run(self, request: CloudToolRequest) -> CloudToolResult:
        return CloudToolResult(
            classification="running",
            summary="chain is still running",
            details={"request": request.arguments},
        )


@dataclass
class CapturingOutbound:
    sent: list[OutboundMessage] = field(default_factory=list)

    async def send(self, message: OutboundMessage) -> None:
        self.sent.append(message)


def test_cloud_check_can_notify_every_fire(tmp_path) -> None:
    store = FileStore(tmp_path / "store")
    conversation = store.upsert_resident_conversation(
        ResidentConversationInput(
            transport="discord",
            conversation_key="discord:dm:user-1",
            dm_user_id="user-1",
        )
    )
    run = store.create_cloud_run(
        CloudRunInput(
            operation="chain",
            conversation_id=conversation.id,
            provider="megaplan-cloud-cli",
            target_id=".megaplan/initiatives/demo/chain.yaml",
            command_summary="cloud chain",
        )
    )
    run = store.update_cloud_run(run.id, status="running")
    now = datetime(2026, 6, 30, 12, 0, tzinfo=UTC)
    store.create_scheduled_job(
        ScheduledJobInput(
            job_type="cloud_check",
            conversation_id=conversation.id,
            cloud_run_id=run.id,
            payload={
                "project_root": ".",
                "cloud_yaml": "cloud.yaml",
                "check_interval_s": 21600,
                "notify_every_check": True,
            },
            scheduled_for=now - timedelta(seconds=1),
        )
    )
    outbound = CapturingOutbound()
    worker = make_store_scheduler(
        store=store,
        config=ResidentConfig(),
        cloud_backend=FakeCloudBackend(),
        outbound=outbound,
        worker_id="test-worker",
    )

    result = asyncio.run(worker.run_due_once(now=now))

    assert result.fired == 1
    assert len(outbound.sent) == 1
    sent = outbound.sent[0]
    assert sent.conversation_key == "discord:dm:user-1"
    assert "Cloud check every 6h ran" in sent.content
    assert "running" in sent.content
    messages = store.load_messages([store.load_resident_conversation(conversation.id).last_outbound_message_id])
    assert messages[0].content == sent.content


def test_authoritative_todo_inbound_exposes_reply_chain_custody(tmp_path) -> None:
    store = FileStore(tmp_path / "store")
    conversation = store.upsert_resident_conversation(
        ResidentConversationInput(
            transport="discord",
            conversation_key="discord:dm:user-1",
            dm_user_id="user-1",
        )
    )
    message = store.create_message(
        epic_id=None,
        conversation_id=conversation.id,
        direction="inbound",
        content="launch it",
        discord_message_id="discord-msg-1",
        discord_reply_provenance={
            "schema_version": "discord-reply-provenance-v1",
            "transport": "discord",
            "source_message_id": "discord-msg-1",
            "source_author_id": "user-1",
            "conversation_key": "discord:dm:user-1",
            "ancestors": [],
            "captured_ancestor_count": 0,
            "chain_complete": True,
            "capture_truncated": False,
            "termination_reason": "root",
        },
        idempotency_key="message-1",
    )

    inbound = _todo_authoritative_inbound(
        store,
        {
            "launch_provenance": {
                "applicability": "applicable",
                "resident_conversation_id": conversation.id,
                "source_record_id": message.id,
                "conversation_key": conversation.conversation_key,
                "reply_to_message_id": "discord-msg-1",
            }
        },
    )

    assert inbound["state"] == "verified"
    assert inbound["reply_chain_custody"]["source_message_id"] == "discord-msg-1"
    assert inbound["reply_chain_custody"]["termination_reason"] == "root"


# ── superfixer_proactive consumer (Phase 4, action-off) ─────────────────────


SFX_NOW = datetime(2026, 8, 7, 12, 0, tzinfo=UTC)


def _superfixer_schedule_definition(
    *, schedule_id: str = "sched_superfixer_consumer_test",
) -> schedules_module.ScheduleDefinition:
    prompt = "Inspect the pinned chain and fix what is broken."
    return schedules_module.ScheduleDefinition.model_validate(
        {
            "schema": "arnold-resident-schedule-v1",
            "schedule_id": schedule_id,
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
            "audit_reason": "superfixer consumer test fixture",
        }
    )


def _committed_superfixer_occurrence(tmp_path: Path, *, now: datetime | None = None):
    """Create the superfixer schedule and commit ONE schedule-owned job."""
    now = now or SFX_NOW
    store = FileStore(tmp_path / "store")
    service = schedules_module.ScheduleService(tmp_path / "store")
    row = _superfixer_schedule_definition()
    service.create(row, idempotency_key="sfx-schedule")
    receipt = asyncio.run(service.run_due_once(now=now, worker_id="superfixer-schedule"))
    assert receipt.launched == 1
    projection = service.repo.occurrences(row.schedule_id)[0]
    job_id = projection.run_id.removeprefix("scheduled-job:")
    job = store.load_scheduled_job(job_id)
    assert job is not None
    return store, service, row, projection, job


def _fake_superfixer_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    captured: dict,
    *,
    result_status: str = "accepted",
):
    manifest = tmp_path / "sfx-manifest.json"

    def fake_launch(**kwargs):
        captured.update(kwargs)
        manifest.write_text(
            json.dumps({"status": "launching", "run_id": "sfx-run-1"}),
            encoding="utf-8",
        )
        return SimpleNamespace(
            ok=result_status in {"accepted", "running"},
            run_id="sfx-run-1", manifest_path=str(manifest), status=result_status
        )

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.resident.subagent.launch_superfixer_proactive_managed",
        fake_launch,
    )
    return manifest


def _consumer_worker(store: FileStore, *, worker_id: str = "sfx-consumer"):
    return make_store_scheduler(
        store=store,
        config=ResidentConfig(),
        cloud_backend=FakeCloudBackend(),
        worker_id=worker_id,
    )


def test_hourly_superfixer_enabled_fails_closed_by_default(monkeypatch) -> None:
    monkeypatch.delenv(HOURLY_SUPERFIXER_ENABLED_ENV, raising=False)
    assert hourly_superfixer_enabled() is False
    for off in ("", "0", "false", "no", "off", "OFF", "False"):
        assert hourly_superfixer_enabled({"ARNOLD_HOURLY_SUPERFIXER_ENABLED": off}) is False
    for on in ("1", "true", "yes", "on", "TRUE", "On"):
        assert hourly_superfixer_enabled({"ARNOLD_HOURLY_SUPERFIXER_ENABLED": on}) is True


def test_superfixer_proactive_consumer_launches_once_with_receipt_linkage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, service, row, projection, job = _committed_superfixer_occurrence(tmp_path)
    monkeypatch.setenv(HOURLY_SUPERFIXER_ENABLED_ENV, "1")
    monkeypatch.delenv("ARNOLD_RUNTIME_MANIFEST", raising=False)
    monkeypatch.setattr(
        scheduler_module, "_runtime_manifest_path", lambda: tmp_path / "no-such-manifest.json"
    )
    captured: dict = {}
    manifest = _fake_superfixer_launch(tmp_path, monkeypatch, captured)
    worker = _consumer_worker(store)

    result = asyncio.run(worker.run_due_once(now=SFX_NOW))

    assert result.fired == 1
    assert captured["schedule_context"]["occurrence_id"] == projection.occurrence.occurrence_id
    assert captured["schedule_context"]["claim"]["fence"] >= 1
    assert captured["schedule_context"]["claim"]["claim_owner"] == "sfx-consumer"
    assert captured["request_id"] == projection.occurrence.occurrence_id
    assert captured["launch_origin"]["source_kind"] == "scheduled_turn"
    assert captured["launch_origin"]["superfixer_proactive"] is True
    assert captured["launch_origin"]["occurrence_id"] == projection.occurrence.occurrence_id
    assert captured["model_spec"] == "omp:deepseek/deepseek-v4-flash"
    # Durable launch receipt linkage on the occurrence.
    launched = service.load_occurrence(projection.occurrence.occurrence_id)
    assert launched.state == "launched"
    assert launched.run_id == "sfx-run-1"
    assert launched.manifest_path == str(manifest)
    assert launched.manifest_digest == "sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert launched.decision == "superfixer_managed_launch_committed"
    # ONE launch per occurrence: a second pass claims and launches nothing.
    before = dict(captured)
    result2 = asyncio.run(worker.run_due_once(now=SFX_NOW + timedelta(minutes=1)))
    assert result2.fired == 0
    assert captured == before
    # Final receipt: the terminal manifest reconciles the occurrence terminal.
    manifest.write_text(
        json.dumps({"status": "completed", "delivery": {"status": "delivered"}}),
        encoding="utf-8",
    )
    assert service.reconcile_terminal_runs() == 1
    terminal = service.load_occurrence(projection.occurrence.occurrence_id)
    assert terminal.state == "terminal"
    assert terminal.decision == "managed_run_completed"
    # No schedule mutation anywhere in the chain.
    current = service.repo.read_definition(row.schedule_id)
    assert current.state == "active"
    assert current.revision == row.revision


def test_superfixer_rejected_managed_launch_never_projects_launched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, service, row, projection, job = _committed_superfixer_occurrence(tmp_path)
    monkeypatch.setenv(HOURLY_SUPERFIXER_ENABLED_ENV, "1")
    monkeypatch.delenv("ARNOLD_RUNTIME_MANIFEST", raising=False)
    monkeypatch.setattr(
        scheduler_module, "_runtime_manifest_path", lambda: tmp_path / "no-such-manifest.json"
    )
    captured: dict = {}
    _fake_superfixer_launch(tmp_path, monkeypatch, captured, result_status="rejected")
    with pytest.raises(RuntimeError, match="canonical managed launch was not accepted"):
        asyncio.run(
            _consumer_worker(store).handlers["superfixer_proactive"](
                job.model_dump(mode="json")
            )
        )

    current = service.load_occurrence(projection.occurrence.occurrence_id)
    assert current.state != "launched"


def test_superfixer_proactive_duplicate_delivery_never_double_launches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, service, row, projection, job = _committed_superfixer_occurrence(tmp_path)
    monkeypatch.setenv(HOURLY_SUPERFIXER_ENABLED_ENV, "1")
    monkeypatch.delenv("ARNOLD_RUNTIME_MANIFEST", raising=False)
    monkeypatch.setattr(
        scheduler_module, "_runtime_manifest_path", lambda: tmp_path / "no-such-manifest.json"
    )
    captured: dict = {}
    _fake_superfixer_launch(tmp_path, monkeypatch, captured)
    handlers = scheduler_module.ResidentJobHandlers(
        store=store, config=ResidentConfig(), cloud_backend=FakeCloudBackend(),
        worker_id="sfx-consumer",
    )
    payload = job.model_dump(mode="json")

    asyncio.run(handlers.handle_superfixer_proactive(payload))
    assert captured  # exactly one launch
    before = dict(captured)
    asyncio.run(handlers.handle_superfixer_proactive(payload))  # duplicate delivery
    assert captured == before  # still exactly one launch
    launched = service.load_occurrence(projection.occurrence.occurrence_id)
    assert launched.run_id == "sfx-run-1"
    assert launched.decision == "superfixer_managed_launch_committed"


def test_superfixer_proactive_consumer_keeps_cancelled_when_flag_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, service, row, projection, job = _committed_superfixer_occurrence(tmp_path)
    monkeypatch.delenv(HOURLY_SUPERFIXER_ENABLED_ENV, raising=False)  # default OFF
    monkeypatch.delenv("ARNOLD_RUNTIME_MANIFEST", raising=False)
    monkeypatch.setattr(
        scheduler_module, "_runtime_manifest_path", lambda: tmp_path / "no-such-manifest.json"
    )
    captured: dict = {}
    _fake_superfixer_launch(tmp_path, monkeypatch, captured)
    worker = _consumer_worker(store)

    result = asyncio.run(worker.run_due_once(now=SFX_NOW))

    assert result.fired == 1
    assert captured == {}  # zero launches even with a due occurrence
    fired = store.load_scheduled_job(job.id)
    assert fired.payload["keep_cancelled"] is True
    assert fired.payload["keep_cancelled_decision"] == "keep_cancelled_flag_disabled"
    assert fired.payload["superfixer_occurrence_state"] == "kept_cancelled"
    # Durable single-shot record (explicit non-enablement).
    lines = (tmp_path / "store" / "schedules" / "superfixer-singleshots.jsonl").read_text(
        encoding="utf-8"
    ).splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["keep_cancelled"] is True
    assert record["occurrence_id"] == projection.occurrence.occurrence_id
    assert record["decision"] == "keep_cancelled_flag_disabled"
    # Final receipt: the occurrence reconciles terminal as keep_cancelled.
    assert service.reconcile_terminal_runs() == 1
    terminal = service.load_occurrence(projection.occurrence.occurrence_id)
    assert terminal.state == "terminal"
    assert terminal.decision == "keep_cancelled_single_shot"
    # No schedule mutation.
    current = service.repo.read_definition(row.schedule_id)
    assert current.state == "active"
    assert current.revision == row.revision


def test_superfixer_proactive_never_launches_for_cancelled_schedule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = FileStore(tmp_path / "store")
    service = schedules_module.ScheduleService(tmp_path / "store")
    row = _superfixer_schedule_definition(schedule_id="sched_superfixer_cancelled_test")
    service.create(row, idempotency_key="sfx-cancelled")
    service.set_state(
        row.schedule_id, "cancelled", if_revision=1,
        audit_reason="operator keeps the hourly backstop cancelled",
    )
    monkeypatch.setenv(HOURLY_SUPERFIXER_ENABLED_ENV, "1")  # even with the flag ON
    monkeypatch.delenv("ARNOLD_RUNTIME_MANIFEST", raising=False)
    captured: dict = {}
    _fake_superfixer_launch(tmp_path, monkeypatch, captured)
    worker = _consumer_worker(store)

    result = asyncio.run(worker.run_due_once(now=SFX_NOW))

    assert result.claimed == 0
    assert result.fired == 0
    assert captured == {}  # zero launches
    assert service.repo.occurrences(row.schedule_id) == []  # never materialized
    # The schedule stays cancelled — the consumer never uncancels.
    current = service.repo.read_definition(row.schedule_id)
    assert current.state == "cancelled"
    assert current.revision == 2


def test_superfixer_proactive_crash_reclaim_launches_once_after_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, service, row, projection, job = _committed_superfixer_occurrence(tmp_path)
    monkeypatch.setenv(HOURLY_SUPERFIXER_ENABLED_ENV, "1")
    monkeypatch.delenv("ARNOLD_RUNTIME_MANIFEST", raising=False)
    monkeypatch.setattr(
        scheduler_module, "_runtime_manifest_path", lambda: tmp_path / "no-such-manifest.json"
    )
    clock = {"value": SFX_NOW}

    def fake_now():
        return clock["value"]

    monkeypatch.setattr(scheduler_module, "utc_now", fake_now)
    monkeypatch.setattr(schedules_module, "utc_now", fake_now)
    captured: dict = {}
    _fake_superfixer_launch(tmp_path, monkeypatch, captured)

    # A crashed consumer already holds a live claim (no launch receipt yet).
    crashed = service.claim_superfixer_occurrence(
        projection.occurrence.occurrence_id,
        job_id=job.id,
        worker_id="crashed-consumer",
        now=SFX_NOW,
        lease_seconds=scheduler_module.SUPERFIXER_CONSUMER_LEASE_SECONDS,
    )
    worker = _consumer_worker(store)

    # First delivery sees the live foreign claim: retried, never launched.
    result = asyncio.run(worker.run_due_once(now=SFX_NOW))
    assert result.fired == 0
    assert result.retried == 1
    assert captured == {}  # no launch while the crashed claim is live

    # After the lease expires the next delivery reclaims with a newer fence
    # and launches exactly once.
    clock["value"] = SFX_NOW + timedelta(seconds=61)
    result2 = asyncio.run(worker.run_due_once(now=clock["value"]))
    assert result2.fired == 1
    assert captured  # exactly one launch after reclaim
    assert captured["schedule_context"]["claim"]["fence"] > crashed.fence
    assert captured["schedule_context"]["claim"]["claim_owner"] == "sfx-consumer"
    launched = service.load_occurrence(projection.occurrence.occurrence_id)
    assert launched.state == "launched"
    assert launched.run_id == "sfx-run-1"


def test_superfixer_proactive_managed_launch_routes_omp_with_custody(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arnold_pipelines.megaplan.resident import subagent as subagent_module

    captured: dict = {}

    def fake_detached(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            run_id="sfx-run", manifest_path="/tmp/m.json", status="launching"
        )

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.resident.subagent.launch_managed_subagent_detached",
        fake_detached,
    )
    result = subagent_module.launch_superfixer_proactive_managed(
        task="fix the chain",
        request_id="occ_1",
        launch_origin={
            "applicability": "not_applicable",
            "source_kind": "scheduled_turn",
        },
        schedule_context={
            "schema_version": "arnold-resident-schedule-occurrence-v1",
            "occurrence_key": "k",
            "occurrence_id": "occ_1",
        },
    )
    assert captured["backend"] == "omp"
    assert captured["model"] == "deepseek/deepseek-v4-flash"
    assert captured["model_spec"] == "omp:deepseek/deepseek-v4-flash"
    assert captured["task_kind"] == "autonomous"
    assert captured["work_intent"] == "execution"
    assert captured["request_id"] == "occ_1"
    assert captured["launch_origin"]["source_kind"] == "scheduled_turn"
    assert result.run_id == "sfx-run"


def test_superfixer_proactive_managed_launch_rejects_non_omp_spec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from arnold_pipelines.megaplan.resident import subagent as subagent_module

    with pytest.raises(ValueError, match="omp"):
        subagent_module.launch_superfixer_proactive_managed(
            task="x", model_spec="codex:gpt-5"
        )
