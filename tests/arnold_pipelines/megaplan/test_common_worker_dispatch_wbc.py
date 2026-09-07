from __future__ import annotations

import argparse
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, replace as dc_replace
from pathlib import Path
from typing import Any

import pytest

from arnold.workflow.attempt_ledger_store import GateStatus, SqliteAttemptLedgerStore
from arnold.workflow.execution_attempt_ledger import (
    AdapterKind,
    AttemptEventType,
    AttemptIdentity,
    AttemptOutcome,
    AttemptProvenance,
    GrantRef,
    LedgerEvent,
    PersistenceStatus,
    RuntimeAdapter,
    VersionSet,
)
from arnold_pipelines.megaplan.custody.action_validator import ActionBoundaryContext, GateResult
from arnold_pipelines.megaplan.custody.common_worker_dispatch import (
    COMMON_WORKER_DISPATCH_SURFACE,
    COMMON_WORKER_DISPATCH_WRITER_ID,
    CommonWorkerDispatchSpec,
    PostLaunchIndeterminateError,
)
from arnold_pipelines.megaplan.custody.controlled_writer_registry import Cohort, ControlledWriter, _clear_registry, register_writer
from arnold_pipelines.megaplan.custody.phase_wbc import activate_phase_wbc
from arnold_pipelines.megaplan.custody.worker_dispatch_wbc import (
    build_worker_dispatch_spec,
    query_worker_dispatch_manifest,
)
from arnold_pipelines.megaplan.custody.contracts import CustodyLease, CustodyTargetKey
from arnold_pipelines.megaplan.custody.outbox import OutboxRecord, OutboxRecordStatus, OutboxRecordType
from arnold_pipelines.megaplan.custody.wbc_runtime import (
    ActionBoundaryDeniedError,
    AttemptArtifact,
    ExactSourceRecord,
    ExactSourceLookupError,
    ImmutableAttemptArtifacts,
    PromotionMode,
    WbcRuntimeProducerFacade,
)
from arnold_pipelines.megaplan.handlers import shared as shared_handlers
from arnold_pipelines.megaplan.orchestration.phase_result import (
    DispatchOutcome,
    ExitKind,
    read_phase_result,
)
from arnold_pipelines.megaplan.types import CliError
from arnold_pipelines.megaplan.workers import _impl as worker_impl
from arnold_pipelines.run_authority import CapabilityGrant, CoordinatorFence


TARGET = CustodyTargetKey("phase", "plan", "dispatch", "worker", "common", "common-dispatch")
CAPABILITY = "megaplan.task.dispatch"
GRANT = CapabilityGrant(
    grant_id="grant-T13",
    run_id="run-T13",
    run_revision="rev-T13",
    coordinator_attempt_id="coord-T13",
    fence_token=9,
    subject_ids=(TARGET.subject_id,),
    capabilities=(CAPABILITY,),
    evidence_ids=("evidence-T13",),
)
FENCE = CoordinatorFence("run-T13", "rev-T13", "coord-T13", 9)


@dataclass
class FakeLeaseStore:
    leases: tuple[CustodyLease, ...]

    def current_lease(self, lease_id: str) -> CustodyLease | None:
        for lease in self.leases:
            if lease.lease_id == lease_id:
                return lease
        return None

    def find_by_target_key(
        self,
        subject_type: str,
        subject_id: str,
        action: str,
        target_kind: str,
        target_id: str,
        contract_id: str,
    ) -> tuple[CustodyLease, ...]:
        return tuple(
            lease
            for lease in self.leases
            if lease.target_key is not None
            and lease.target_key.subject_type == subject_type
            and lease.target_key.subject_id == subject_id
            and lease.target_key.action == action
            and lease.target_key.target_kind == target_kind
            and lease.target_key.target_id == target_id
            and lease.target_key.contract_id == contract_id
        )


@dataclass
class FakeOutbox:
    records: tuple[OutboxRecord, ...]

    def list_records(self) -> tuple[OutboxRecord, ...]:
        return self.records


@pytest.fixture(autouse=True)
def _reset_writer_registry() -> None:
    _clear_registry()
    yield
    _clear_registry()


def _register_writer() -> None:
    register_writer(
        ControlledWriter(
            writer_id=COMMON_WORKER_DISPATCH_WRITER_ID,
            surface_name=COMMON_WORKER_DISPATCH_SURFACE,
            cohort=Cohort.ACTIVE,
            contract_ids=(TARGET.contract_id,),
            source_file="arnold_pipelines/megaplan/workers/_impl.py",
            function_name="run_step_with_worker",
            required_wbc_phases=("start", "terminal"),
            action_kind="dispatch",
        )
    )


def _lease(*, epoch: int = 5, grant_id: str = GRANT.grant_id) -> CustodyLease:
    return CustodyLease(
        lease_id="lease-T13",
        target_key=TARGET,
        owner=("runtime-host", "4321", "boot-1"),
        epoch=epoch,
        acquired_at="2026-07-20T00:00:00+00:00",
        expires_at="2999-01-01T00:00:00+00:00",
        fence_token=str(FENCE.token),
        status="active",
        run_authority_grant_id=grant_id,
        wbc_attempt_reference="wbc-T13",
    )


def _record(*, version: str = "source.v1", grant_id: str = GRANT.grant_id) -> OutboxRecord:
    return OutboxRecord(
        outbox_id="outbox-T13",
        lease_id="lease-T13",
        record_type=OutboxRecordType.LEASE_ACQUIRE,
        status=OutboxRecordStatus.PENDING,
        occurred_at="2026-07-20T00:00:00+00:00",
        idempotency_key="idem-T13-outbox",
        wbc_attempt_reference="wbc-T13",
        run_authority_grant_id=grant_id,
        coordinator_fence_token=FENCE.token,
        custody_epoch=5,
        payload={"schema_version": version, "target_digest": TARGET.target_digest},
    )


def _context(
    action_type: str,
    *,
    grant: CapabilityGrant | None = GRANT,
    fence: CoordinatorFence | None = FENCE,
    expected_epoch: int = 5,
    lease_id: str = "lease-T13",
    wbc_reference: str = "wbc-T13",
) -> ActionBoundaryContext:
    return ActionBoundaryContext(
        action_type=action_type,  # type: ignore[arg-type]
        target=TARGET,
        run_authority_grant_id=GRANT.grant_id,
        coordinator_fence_token=FENCE.token,
        wbc_attempt_reference=wbc_reference,
        owner_host="runtime-host",
        owner_pid="4321",
        owner_boot_id="boot-1",
        expected_custody_epoch=expected_epoch,
        expected_lease_id=lease_id,
        run_authority_grant=grant,
        coordinator_fence=fence,
        required_capability=CAPABILITY,
        required_wbc_evidence_version="source.v1",
    )


def _identity(attempt_id: str) -> AttemptIdentity:
    return AttemptIdentity(
        workflow_id="wf-T13",
        run_id="run-T13",
        graph_revision="graph-T13",
        step_id="plan",
        invocation_id="inv-T13",
        attempt_ordinal=1,
        attempt_id=attempt_id,
    )


def _event(
    *,
    attempt_id: str,
    sequence: int,
    event_type: AttemptEventType,
    idempotency_key: str,
    outcome: AttemptOutcome | None = None,
    payload: dict[str, object] | None = None,
) -> LedgerEvent:
    return LedgerEvent(
        idempotency_key=idempotency_key,
        event_type=event_type,
        identity=_identity(attempt_id),
        provenance=AttemptProvenance(actor_id="actor-T13", tool_id="tool-T13"),
        adapter=RuntimeAdapter(adapter_kind=AdapterKind.MEGAPLAN_PHASE, adapter_version="1"),
        versions=VersionSet(code_version="source.v1", config_version="cfg.v1", template_version="tmpl.v1"),
        grant_ref=GrantRef(grant_id=GRANT.grant_id),
        sequence=sequence,
        causal_predecessor_sequence=max(sequence - 1, 0),
        append_position=sequence,
        occurred_at=f"2026-07-20T00:00:0{sequence}+00:00",
        observed_at=f"2026-07-20T00:00:0{sequence}+00:00",
        persistence_status=PersistenceStatus.DURABLE,
        outcome=outcome,
        payload=payload or {"sequence": sequence},
    )


def _artifacts(attempt_id: str) -> ImmutableAttemptArtifacts:
    return ImmutableAttemptArtifacts(
        attempt_id=attempt_id,
        artifacts=(
            AttemptArtifact(
                artifact_id="artifact-T13",
                artifact_kind="dispatch",
                version="artifact.v1",
                locator="memory://artifact-T13",
                metadata={"family": "common-dispatch"},
            ),
        ),
        metadata={"family": "common-dispatch"},
    )


def _facade(tmp_path: Path) -> tuple[SqliteAttemptLedgerStore, WbcRuntimeProducerFacade]:
    store = SqliteAttemptLedgerStore(tmp_path / "attempt-ledger.sqlite3")
    facade = WbcRuntimeProducerFacade(
        store,
        source_lookup=lambda key: ExactSourceRecord(
            lookup_key=key,
            version="source.v1",
            source_uri="git+file:///repo#source.v1",
            observed_at="2026-07-20T00:00:00+00:00",
            metadata={"key": key},
        ),
        lease_store=FakeLeaseStore((_lease(),)),
        outbox=FakeOutbox((_record(),)),
        promotion_mode=PromotionMode.ACTION_OFF,
        enforcement_enabled=True,
    )
    return store, facade


def _wire_dispatch_custody(spec: CommonWorkerDispatchSpec) -> CommonWorkerDispatchSpec:
    """Wire valid custody stores into a production-built dispatch facade.

    ``build_worker_dispatch_spec`` constructs its facade without lease/outbox
    stores; under default enforcement (deny-by-default) the action boundary
    must see valid custody to be AUTHORIZED.  This helper injects a lease and
    outbox record for each boundary action type on the spec so the dispatch
    runs end-to-end as an authorized worker dispatch.
    """
    leases: list[CustodyLease] = []
    records: list[OutboxRecord] = []
    for ctx in (
        spec.start_action_context,
        spec.success_action_context,
        spec.failure_action_context,
    ):
        digest = ctx.target.target_digest
        lease_id = f"custody-lease-{digest[:16]}"
        leases.append(
            CustodyLease(
                lease_id=lease_id,
                target_key=ctx.target,
                owner=(
                    ctx.owner_host or "runtime-host",
                    ctx.owner_pid or "4321",
                    ctx.owner_boot_id or "boot-1",
                ),
                epoch=5,
                acquired_at="2026-07-20T00:00:00+00:00",
                expires_at="2999-01-01T00:00:00+00:00",
                fence_token=str(ctx.coordinator_fence_token),
                status="active",
                run_authority_grant_id=ctx.run_authority_grant_id,
                wbc_attempt_reference=ctx.wbc_attempt_reference,
            )
        )
        records.append(
            OutboxRecord(
                outbox_id=f"outbox-{ctx.action_type}-{spec.attempt_id}",
                lease_id=lease_id,
                record_type=OutboxRecordType.LEASE_ACQUIRE,
                status=OutboxRecordStatus.PENDING,
                occurred_at="2026-07-20T00:00:00+00:00",
                idempotency_key=f"idem-{ctx.action_type}-{spec.attempt_id}",
                wbc_attempt_reference=ctx.wbc_attempt_reference,
                run_authority_grant_id=ctx.run_authority_grant_id,
                coordinator_fence_token=ctx.coordinator_fence_token,
                custody_epoch=5,
                payload={
                    "schema_version": spec.expected_source_version,
                    "target_digest": digest,
                },
            )
        )
    wired = WbcRuntimeProducerFacade(
        spec.facade._ledger_store,
        source_lookup=spec.facade._source_lookup,
        lease_store=FakeLeaseStore(tuple(leases)),
        outbox=FakeOutbox(tuple(records)),
        promotion_mode=PromotionMode.ACTION_OFF,
        enforcement_enabled=True,
    )
    return dc_replace(spec, facade=wired)


def _worker() -> worker_impl.WorkerResult:
    return worker_impl.WorkerResult(
        payload={"success": True},
        raw_output="ok",
        duration_ms=12,
        cost_usd=0.0,
        session_id="session-T13",
        worker_channel="codex_cli",
    )


def _spec(
    facade: WbcRuntimeProducerFacade,
    attempt_id: str,
    *,
    start_context: ActionBoundaryContext | None = None,
    success_context: ActionBoundaryContext | None = None,
    failure_context: ActionBoundaryContext | None = None,
    certificate: Any = None,
) -> CommonWorkerDispatchSpec:
    return CommonWorkerDispatchSpec(
        facade=facade,
        attempt_id=attempt_id,
        start_event=_event(
            attempt_id=attempt_id,
            sequence=1,
            event_type=AttemptEventType.STARTED,
            idempotency_key=f"{attempt_id}:start",
        ),
        success_event_factory=lambda _result: _event(
            attempt_id=attempt_id,
            sequence=2,
            event_type=AttemptEventType.COMPLETED,
            idempotency_key=f"{attempt_id}:complete",
            outcome=AttemptOutcome.SUCCEEDED,
            payload={"phase": "plan", "status": "completed"},
        ),
        failure_event_factory=lambda exc: _event(
            attempt_id=attempt_id,
            sequence=2,
            event_type=AttemptEventType.FAILED,
            idempotency_key=f"{attempt_id}:failed",
            outcome=AttemptOutcome.FAILED,
            payload={"detail": str(exc)},
        ),
        indeterminate_event_factory=lambda exc: _event(
            attempt_id=attempt_id,
            sequence=2,
            event_type=AttemptEventType.FAILED,
            idempotency_key=f"{attempt_id}:indeterminate",
            outcome=AttemptOutcome.INDETERMINATE,
            payload={"detail": str(exc), "indeterminate": True},
        ),
        start_action_context=start_context or _context("dispatch"),
        success_action_context=success_context or _context("completion"),
        failure_action_context=failure_context or _context("completion"),
        artifacts=_artifacts(attempt_id),
        post_dispatch_certificate=certificate,
    )


def test_run_step_with_worker_commits_wbc_start_before_provider_dispatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _register_writer()
    attempt_id = "13131313-1313-4313-8313-131313131313"
    store, facade = _facade(tmp_path)
    seen = {"called": 0}

    def fake_legacy(*args: Any, **kwargs: Any) -> tuple[worker_impl.WorkerResult, str, str, bool]:
        del args, kwargs
        seen["called"] += 1
        events = store.read_events(attempt_id)
        assert [event.event_type for event in events] == [AttemptEventType.STARTED]
        assert store.start_verified(attempt_id).status == GateStatus.VERIFIED
        return _worker(), "codex", "persistent", False

    monkeypatch.setattr(worker_impl, "_run_step_with_worker_legacy", fake_legacy)
    worker, agent, mode, refreshed = worker_impl.run_step_with_worker(
        "plan",
        {},
        tmp_path,
        argparse.Namespace(),
        root=tmp_path,
        wbc_dispatch=_spec(facade, attempt_id),
    )

    assert seen["called"] == 1
    assert (agent, mode, refreshed) == ("codex", "persistent", False)
    assert worker.auth_metadata is not None
    assert worker.auth_metadata["wbc_dispatch"]["start_event_sequence"] == 1
    assert worker.auth_metadata["wbc_dispatch"]["terminal_event_sequence"] == 2
    assert [event.event_type for event in store.read_events(attempt_id)] == [
        AttemptEventType.STARTED,
        AttemptEventType.COMPLETED,
    ]
    assert store.terminal_or_indeterminate_verified(attempt_id).status == GateStatus.VERIFIED


def test_run_step_with_worker_blocks_before_dispatch_when_action_validator_denies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _register_writer()
    attempt_id = "14141414-1414-4414-8414-141414141414"
    store, facade = _facade(tmp_path)
    called = {"legacy": False}

    def fake_legacy(*args: Any, **kwargs: Any) -> tuple[worker_impl.WorkerResult, str, str, bool]:
        del args, kwargs
        called["legacy"] = True
        return _worker(), "codex", "persistent", False

    monkeypatch.setattr(worker_impl, "_run_step_with_worker_legacy", fake_legacy)

    with pytest.raises(ActionBoundaryDeniedError):
        worker_impl.run_step_with_worker(
            "plan",
            {},
            tmp_path,
            argparse.Namespace(),
            root=tmp_path,
            wbc_dispatch=_spec(facade, attempt_id, start_context=_context("dispatch", grant=None)),
        )

    assert not called["legacy"]
    assert store.read_events(attempt_id) == []


def test_run_step_with_worker_records_indeterminate_terminal_when_post_launch_certification_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _register_writer()
    attempt_id = "15151515-1515-4515-8515-151515151515"
    store, facade = _facade(tmp_path)

    def fake_legacy(*args: Any, **kwargs: Any) -> tuple[worker_impl.WorkerResult, str, str, bool]:
        del args, kwargs
        return _worker(), "codex", "persistent", False

    monkeypatch.setattr(worker_impl, "_run_step_with_worker_legacy", fake_legacy)

    with pytest.raises(PostLaunchIndeterminateError) as caught:
        worker_impl.run_step_with_worker(
            "plan",
            {},
            tmp_path,
            argparse.Namespace(),
            root=tmp_path,
            wbc_dispatch=_spec(
                facade,
                attempt_id,
                certificate=lambda _result: (_ for _ in ()).throw(RuntimeError("receipt append unavailable")),
            ),
        )

    assert caught.value.terminal_result.authoritative_reread is not None
    assert caught.value.terminal_result.authoritative_reread.terminal_gate is not None
    assert caught.value.terminal_result.authoritative_reread.terminal_gate.status == GateStatus.VERIFIED
    events = store.read_events(attempt_id)
    assert [event.event_type for event in events] == [AttemptEventType.STARTED, AttemptEventType.FAILED]
    assert events[-1].outcome == AttemptOutcome.INDETERMINATE


def test_run_worker_passes_wbc_dispatch_to_run_step_with_worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _register_writer()
    _store, facade = _facade(tmp_path)
    dispatch_spec = _spec(facade, "16161616-1616-4616-8616-161616161616")
    captured: dict[str, Any] = {}

    @contextmanager
    def fake_phase_result_guard(_plan_dir: Path):
        yield

    def fake_run_step_with_worker(*args: Any, **kwargs: Any) -> tuple[worker_impl.WorkerResult, str, str, bool]:
        captured["wbc_dispatch"] = kwargs.get("wbc_dispatch")
        return _worker(), "codex", "persistent", False

    def fake_set_active_step(current_state: dict[str, Any], *args: Any, **kwargs: Any) -> str:
        del args, kwargs
        current_state["active_step"] = {"run_id": "run-T13"}
        return "run-T13"

    monkeypatch.setattr(shared_handlers, "apply_profile_expansion", lambda *args, **kwargs: None)
    monkeypatch.setattr(shared_handlers, "set_active_step", fake_set_active_step)
    monkeypatch.setattr(shared_handlers, "save_state_merge_meta", lambda *args, **kwargs: None)
    monkeypatch.setattr(shared_handlers, "phase_result_guard", fake_phase_result_guard)
    monkeypatch.setattr(shared_handlers.worker_module, "run_step_with_worker", fake_run_step_with_worker)

    state = {
        "config": {"project_dir": str(tmp_path)},
        "meta": {"current_invocation_id": "inv-T13"},
        "name": "plan-T13",
        "iteration": 1,
    }
    worker, agent, mode, refreshed = shared_handlers._run_worker(
        "plan",
        state,  # type: ignore[arg-type]
        tmp_path,
        argparse.Namespace(),
        root=tmp_path,
        resolved=("codex", "persistent", False, "gpt-5.5"),
        wbc_dispatch=dispatch_spec,
    )

    assert captured["wbc_dispatch"] is dispatch_spec
    assert (worker.session_id, agent, mode, refreshed) == ("session-T13", "codex", "persistent", False)


def test_run_worker_preserves_post_provider_unresolved_outcome_without_finished_at(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A post-provider unresolved terminal remains typed at the phase boundary."""
    _register_writer()
    attempt_id = "17171717-1717-4717-8717-171717171717"
    store, facade = _facade(tmp_path)
    provider_calls = 0
    outcome = DispatchOutcome(
        kind="unresolved_launch",
        launch_state="ambiguous",
        plan_id="plan-T17",
        phase="plan",
        dispatch_family_id="family-T17",
        logical_dispatch_id="logical-T17",
        admission_receipt_id=None,
        semantic_dispatch_fingerprint=None,
        selected_spec="codex:gpt-5.5",
        terminal_outcome_event_id="terminal-T17",
        finished_at=None,
    )

    def post_provider_unresolved(*args: Any, **kwargs: Any) -> tuple[worker_impl.WorkerResult, str, str, bool]:
        nonlocal provider_calls
        del args, kwargs
        provider_calls += 1
        raise CliError(
            "scheduling_condition",
            "canonical worker launch remains unresolved",
            extra={"reason": "unresolved_launch", "dispatch_outcome": outcome.to_dict()},
        )

    monkeypatch.delenv("ARNOLD_RUNTIME_MANIFEST", raising=False)
    monkeypatch.delenv("MEGAPLAN_RUNTIME_LAUNCH_SEED", raising=False)
    monkeypatch.setattr(shared_handlers, "apply_profile_expansion", lambda *args, **kwargs: None)
    monkeypatch.setattr(shared_handlers, "activate_phase_wbc", lambda *args, **kwargs: None)
    monkeypatch.setattr(worker_impl, "_run_step_with_worker_legacy", post_provider_unresolved)

    state = {
        "name": "plan-T17",
        "iteration": 1,
        "config": {"project_dir": str(tmp_path)},
        "history": [],
        "sessions": {},
        "meta": {},
    }
    with pytest.raises(CliError, match="canonical worker launch remains unresolved") as caught:
        shared_handlers._run_worker(
            "plan",
            state,  # type: ignore[arg-type]
            tmp_path,
            argparse.Namespace(phase_model=[]),
            root=tmp_path,
            resolved=("codex", "persistent", False, "gpt-5.5"),
            wbc_dispatch=_spec(facade, attempt_id),
        )

    assert provider_calls == 1
    assert caught.value.code == "scheduling_condition"
    assert caught.value.extra["reason"] == "unresolved_launch"
    assert caught.value.extra["dispatch_outcome"] == outcome.to_dict()
    result = read_phase_result(tmp_path)
    assert result is not None
    assert result.exit_kind == ExitKind.scheduling_condition.value
    assert result.scheduling_condition is not None
    assert result.scheduling_condition.reason == "unresolved_launch"
    assert result.scheduling_condition.observed_at
    assert result.scheduling_condition.cause_event_id == "terminal-T17"
    assert result.dispatch_outcome == outcome
    events = store.read_events(attempt_id)
    assert [event.event_type for event in events] == [
        AttemptEventType.STARTED,
        AttemptEventType.FAILED,
    ]
    assert events[-1].outcome == AttemptOutcome.FAILED


def test_auto_phase_worker_dispatch_rejects_stale_exact_source_before_provider_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {
        "name": "plan-T18",
        "iteration": 2,
        "config": {"project_dir": str(tmp_path)},
        "meta": {"current_invocation_id": "inv-T18"},
        "active_step": {"run_id": "run-T18"},
    }
    activate_phase_wbc(
        state=state,  # type: ignore[arg-type]
        plan_dir=tmp_path,
        step="review",
        agent="reviewer",
    )
    spec = build_worker_dispatch_spec(
        plan_dir=tmp_path,
        state=state,  # type: ignore[arg-type]
        step="critique_evaluator",
        phase_step="review",
        agent="claude",
        selected_spec="claude:claude-sonnet-4-6:high",
        route_kind="subprocess",
        attempt_index=1,
        configured_specs=("codex:gpt-5.5:high", "claude:claude-sonnet-4-6:high"),
        attempted_specs=("codex:gpt-5.5:high", "claude:claude-sonnet-4-6:high"),
        failed_attempt_reasons=("availability",),
        fallback_trigger="availability",
    )
    assert spec is not None

    state["meta"]["current_invocation_id"] = "inv-T18-stale"
    state["active_step"].pop("_phase_wbc", None)
    activate_phase_wbc(
        state=state,  # type: ignore[arg-type]
        plan_dir=tmp_path,
        step="review",
        agent="reviewer",
    )
    called = {"dispatch": False}

    def _dispatch(_start: Any) -> worker_impl.WorkerResult:
        called["dispatch"] = True
        return _worker()

    with pytest.raises(ExactSourceLookupError):
        spec.run(_dispatch)

    assert not called["dispatch"]


def test_worker_dispatch_key_is_collision_free_and_default_identity_is_unchanged(
    tmp_path: Path,
) -> None:
    state = {
        "name": "plan-fanout",
        "iteration": 1,
        "config": {"project_dir": str(tmp_path)},
        "meta": {"current_invocation_id": "inv-fanout"},
        "active_step": {"run_id": "run-fanout"},
    }
    phase = activate_phase_wbc(
        state=state,  # type: ignore[arg-type]
        plan_dir=tmp_path,
        step="critique",
        agent="critic",
    )
    assert phase is not None
    common = {
        "plan_dir": tmp_path,
        "state": state,
        "step": "critique",
        "agent": "hermes",
        "selected_spec": "omp:zai/glm-5.2",
        "route_kind": "subprocess",
    }
    legacy = build_worker_dispatch_spec(**common)
    first = build_worker_dispatch_spec(**common, dispatch_key="critique:scope:initial")
    second = build_worker_dispatch_spec(**common, dispatch_key="critique:safety:initial")
    assert legacy is not None and first is not None and second is not None

    assert legacy.attempt_id == str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"{phase['attempt_id']}::subprocess::critique::omp:zai/glm-5.2::0::inv-fanout::worker-dispatch-v2",
        )
    )
    assert len({legacy.attempt_id, first.attempt_id, second.attempt_id}) == 3
    assert legacy.start_source_lookup_key == "critique:critique:subprocess:0:start"
    assert first.start_source_lookup_key.endswith(":critique:scope:initial:start")
    assert second.start_source_lookup_key.endswith(":critique:safety:initial:start")

    first = _wire_dispatch_custody(first)
    second = _wire_dispatch_custody(second)
    first.run(lambda _start: _worker())
    second.run(lambda _start: _worker())
    manifest = query_worker_dispatch_manifest(
        tmp_path,
        phase_attempt_id=str(phase["attempt_id"]),
    )
    assert [row["dispatch_key"] for row in manifest] == [
        "critique:safety:initial",
        "critique:scope:initial",
    ]
    assert {row["terminal_event"] for row in manifest} == {"completed"}


# ── T-0205: atomic plain-lease acquire + dispatch_key in custody identity ──


def test_plain_lease_acquire_race_has_single_winner_and_zero_mutation(
    tmp_path: Path,
) -> None:
    """T-0205: the plain lease acquire holds ONE lock across load/check/
    append, so concurrent contenders for the same lease produce exactly one
    winner.  Every loser re-reads inside the lock and refuses with a typed
    error and ZERO mutation — no conflict quarantine, no second acquire
    event, no stray conflict events.

    Contenders share the DEFAULT idempotency key (as the production dispatch
    path does) but carry distinct owners, so without the atomic acquire the
    losers would fall through the check and hit the payload-conflict
    quarantine instead of a clean refusal.
    """
    import threading

    from arnold_pipelines.megaplan.custody.lease_store import (
        LeaseIdempotencyConflict,
        LeaseStoreError,
        open_lease_store,
    )

    store = open_lease_store(tmp_path / "leases", flock=True)
    lease_id = "custody-lease-race-target"
    barrier = threading.Barrier(4)
    results: list[tuple[str, str]] = []
    results_lock = threading.Lock()

    def _contend(owner: str) -> None:
        barrier.wait()
        try:
            store.acquire(
                lease_id=lease_id,
                owner_host=owner,
                owner_pid="1",
                owner_boot_id="boot",
                run_authority_grant_id=f"grant-{owner}",
                coordinator_fence_token=0,
                wbc_attempt_reference=f"attempt-{owner}",
                occurrence_digest="sha256:race-target",
                custody_epoch=1,
                # Deliberately OMIT idempotency_key: the production dispatch
                # path relies on the default acquire-<lease_id> key, and the
                # race is exactly two distinct attempts sharing that key.
            )
            outcome = "won"
        except LeaseIdempotencyConflict:
            outcome = "conflict"
        except LeaseStoreError:
            outcome = "refused"
        with results_lock:
            results.append((owner, outcome))

    threads = [
        threading.Thread(target=_contend, args=(f"owner-{i}",))
        for i in range(4)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    outcomes = [outcome for _owner, outcome in results]
    # Exactly one contender won; the rest were CLEANLY refused — never a
    # payload-conflict quarantine from a check-then-append race.
    assert outcomes.count("won") == 1, outcomes
    assert "conflict" not in outcomes, outcomes
    # Zero mutation: one acquire event, no conflict events, no quarantine.
    history = store.load_history(lease_id)
    assert len(history) == 1
    assert history[0].event_type == "acquire"
    assert store.quarantined_conflicts(lease_id) == ()
    # The winner's lease is coherent and owned by exactly one contender.
    lease = store.current_lease(lease_id)
    assert lease is not None
    winners = [owner for owner, outcome in results if outcome == "won"]
    assert winners == [lease.owner_host]


def test_worker_dispatch_different_dispatch_keys_never_collide_on_custody(
    tmp_path: Path,
) -> None:
    """T-0205: dispatch_key is part of the custody target identity, so two
    dispatches that differ ONLY in dispatch key derive distinct target
    digests and distinct leases — they can never collide on custody, even in
    the same runtime."""
    state = {
        "name": "plan-dispatch-key-custody",
        "iteration": 1,
        "config": {"project_dir": str(tmp_path)},
        "meta": {"current_invocation_id": "inv-dispatch-key"},
        "active_step": {"run_id": "run-dispatch-key"},
    }
    phase = activate_phase_wbc(
        state=state,  # type: ignore[arg-type]
        plan_dir=tmp_path,
        step="critique",
        agent="critic",
    )
    assert phase is not None
    common = {
        "plan_dir": tmp_path,
        "state": state,
        "step": "critique",
        "agent": "hermes",
        "selected_spec": "omp:zai/glm-5.2",
        "route_kind": "subprocess",
    }
    first = build_worker_dispatch_spec(**common, dispatch_key="critique:scope:initial")
    second = build_worker_dispatch_spec(**common, dispatch_key="critique:safety:initial")
    assert first is not None and second is not None

    # The target identity itself carries the dispatch key...
    assert first.start_action_context.target.dispatch_key == "critique:scope:initial"
    assert second.start_action_context.target.dispatch_key == "critique:safety:initial"
    # ...so the digests — and therefore the lease ids — never collide.
    first_digests = {
        ctx.target.target_digest
        for ctx in (
            first.start_action_context,
            first.success_action_context,
            first.failure_action_context,
        )
    }
    second_digests = {
        ctx.target.target_digest
        for ctx in (
            second.start_action_context,
            second.success_action_context,
            second.failure_action_context,
        )
    }
    assert first_digests.isdisjoint(second_digests)
    # Every boundary of every dispatch acquired its own lease, and the two
    # dispatches share NO lease file on disk (3 boundaries x 2 keys = 6).
    store = first.facade._lease_store
    for ctx in (
        first.start_action_context,
        first.success_action_context,
        first.failure_action_context,
        second.start_action_context,
        second.success_action_context,
        second.failure_action_context,
    ):
        lease = store.current_lease(f"custody-lease-{ctx.target.target_digest[:16]}")
        assert lease is not None, ctx.action_type
    history_files = sorted(
        path.name
        for path in (tmp_path / "custody" / "leases").glob("*.history.jsonl")
    )
    assert len(history_files) == 6, history_files


def test_worker_dispatch_replay_of_same_key_joins_same_lease(
    tmp_path: Path,
) -> None:
    """T-0205: rebuilding the same dispatch (same dispatch_key) joins the
    SAME custody lease — same lease id, idempotent keep (exactly one acquire
    event), and the replayed lease's occurrence key carries the FULL target
    including dispatch_key."""
    state = {
        "name": "plan-dispatch-key-replay",
        "iteration": 1,
        "config": {"project_dir": str(tmp_path)},
        "meta": {"current_invocation_id": "inv-dispatch-key-replay"},
        "active_step": {"run_id": "run-dispatch-key-replay"},
    }
    phase = activate_phase_wbc(
        state=state,  # type: ignore[arg-type]
        plan_dir=tmp_path,
        step="critique",
        agent="critic",
    )
    assert phase is not None
    common = {
        "plan_dir": tmp_path,
        "state": state,
        "step": "critique",
        "agent": "hermes",
        "selected_spec": "omp:zai/glm-5.2",
        "route_kind": "subprocess",
        "dispatch_key": "critique:scope:initial",
    }
    first = build_worker_dispatch_spec(**common)
    replay = build_worker_dispatch_spec(**common)
    assert first is not None and replay is not None
    assert first.attempt_id == replay.attempt_id

    ctx = first.start_action_context
    lease_id = f"custody-lease-{ctx.target.target_digest[:16]}"
    store = replay.facade._lease_store
    lease = store.current_lease(lease_id)
    assert lease is not None
    # Exactly ONE acquire event — the replay idempotently kept the lease.
    assert len(store.load_history(lease_id)) == 1
    # The replayed occurrence key joins the full dispatch target, including
    # the dispatch key that distinguishes this slice.
    assert lease.occurrence_key.target.dispatch_key == "critique:scope:initial"
    assert lease.occurrence_key.target.target_digest == ctx.target.target_digest


def test_worker_dispatch_attempt_identity_changes_with_new_invocation(
    tmp_path: Path,
) -> None:
    """A retry occurrence cannot reuse a worker WBC attempt stream."""
    state = {
        "name": "plan-invocation-fence",
        "iteration": 1,
        "config": {"project_dir": str(tmp_path)},
        "meta": {"current_invocation_id": "inv-one"},
        "active_step": {"run_id": "run-invocation-fence"},
    }
    phase = activate_phase_wbc(
        state=state,  # type: ignore[arg-type]
        plan_dir=tmp_path,
        step="critique",
        agent="critic",
    )
    assert phase is not None
    kwargs = {
        "plan_dir": tmp_path,
        "state": state,
        "step": "critique",
        "agent": "hermes",
        "selected_spec": "omp:zai/glm-5.2",
        "route_kind": "subprocess",
        "attempt_index": 0,
    }
    first = build_worker_dispatch_spec(**kwargs)
    assert first is not None
    state["meta"]["current_invocation_id"] = "inv-two"
    second = build_worker_dispatch_spec(**kwargs)
    assert second is not None
    assert first.attempt_id != second.attempt_id
    assert first.start_event.identity.invocation_id == "inv-one"
    assert second.start_event.identity.invocation_id == "inv-two"


def test_sequential_fallback_reuses_parallel_phase_without_minting_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {
        "name": "plan-fallback",
        "iteration": 1,
        "config": {"project_dir": str(tmp_path)},
        "meta": {"current_invocation_id": "inv-parallel"},
        "active_step": {"phase": "critique", "run_id": "run-parallel"},
    }
    activate_phase_wbc(
        state=state,  # type: ignore[arg-type]
        plan_dir=tmp_path,
        step="critique",
        agent="hermes",
    )
    captured: dict[str, Any] = {}

    @contextmanager
    def guard(_plan_dir: Path):
        yield

    def run_worker(*args: Any, **kwargs: Any):
        del args
        captured["wbc_dispatch"] = kwargs.get("wbc_dispatch")
        return _worker(), "hermes", "fresh", False

    monkeypatch.setattr(shared_handlers, "apply_profile_expansion", lambda *a, **k: None)
    monkeypatch.setattr(
        shared_handlers,
        "set_active_step",
        lambda *a, **k: pytest.fail("fallback minted a second phase invocation"),
    )
    monkeypatch.setattr(shared_handlers, "save_state_merge_meta", lambda *a, **k: None)
    monkeypatch.setattr(shared_handlers, "phase_result_guard", guard)
    monkeypatch.setattr(shared_handlers.worker_module, "run_step_with_worker", run_worker)

    shared_handlers._run_worker(
        "critique",
        state,  # type: ignore[arg-type]
        tmp_path,
        argparse.Namespace(phase_model=[]),
        root=tmp_path,
        resolved=("hermes", "fresh", False, "zhipu:glm-5.2"),
        reuse_active_phase=True,
    )

    assert state["meta"]["current_invocation_id"] == "inv-parallel"
    assert captured["wbc_dispatch"] is not None


def test_run_step_with_worker_enriches_wbc_metadata_with_worker_and_fallback_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {
        "name": "plan-T18",
        "iteration": 3,
        "config": {"project_dir": str(tmp_path)},
        "meta": {"current_invocation_id": "inv-T18-meta"},
        "active_step": {"run_id": "run-T18-meta"},
    }
    activate_phase_wbc(
        state=state,  # type: ignore[arg-type]
        plan_dir=tmp_path,
        step="review",
        agent="reviewer",
    )
    spec = build_worker_dispatch_spec(
        plan_dir=tmp_path,
        state=state,  # type: ignore[arg-type]
        step="review",
        agent="claude",
        selected_spec="claude:claude-sonnet-4-6:high",
        route_kind="direct",
        attempt_index=1,
        configured_specs=("codex:gpt-5.5:high", "claude:claude-sonnet-4-6:high"),
        attempted_specs=("codex:gpt-5.5:high", "claude:claude-sonnet-4-6:high"),
        failed_attempt_reasons=("availability",),
        fallback_trigger="availability",
    )
    assert spec is not None
    spec = _wire_dispatch_custody(spec)

    def fake_legacy(*args: Any, **kwargs: Any) -> tuple[worker_impl.WorkerResult, str, str, bool]:
        del args, kwargs
        worker = _worker()
        worker.worker_channel = "shannon_stream"
        worker.auth_channel = "api_key"
        worker.auth_metadata = {
            "worker_channel": "shannon_stream",
            "auth_channel": "api_key",
            "session_strategy": "clear",
        }
        return worker, "claude", "persistent", True

    monkeypatch.setattr(worker_impl, "_run_step_with_worker_legacy", fake_legacy)
    worker, _agent, _mode, _refreshed = worker_impl.run_step_with_worker(
        "review",
        state,  # type: ignore[arg-type]
        tmp_path,
        argparse.Namespace(),
        root=tmp_path,
        wbc_dispatch=spec,
        ledger_configured_specs=("codex:gpt-5.5:high", "claude:claude-sonnet-4-6:high"),
        ledger_attempt_index=1,
        ledger_attempted_specs=("codex:gpt-5.5:high", "claude:claude-sonnet-4-6:high"),
        ledger_failed_attempt_reasons=("availability",),
        ledger_fallback_trigger="availability",
    )

    assert worker.auth_metadata is not None
    evidence = worker.auth_metadata["wbc_dispatch"]
    assert evidence["expected_source_version"].endswith(":direct:review:claude:claude-sonnet-4-6:high:1")
    assert evidence["route_kind"] == "direct"
    assert evidence["selected_spec"] == "claude:claude-sonnet-4-6:high"
    assert evidence["configured_specs"] == ["codex:gpt-5.5:high", "claude:claude-sonnet-4-6:high"]
    assert evidence["failed_attempt_reasons"] == ["availability"]
    assert evidence["fallback_trigger"] == "availability"
    assert evidence["worker_channel"] == "shannon_stream"
    assert evidence["auth_channel"] == "api_key"


# ── P7A: worker-dispatch facade is ENFORCED by default ────────────────────


def test_worker_dispatch_spec_is_enforced_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression (P7A): the production dispatch facade must be ENFORCED under
    default env — a valid dispatch yields an AUTHORIZED boundary, not
    shadow_pass."""
    monkeypatch.delenv("ARNOLD_M7_ACTION_VALIDATOR_ENFORCEMENT", raising=False)
    state = {
        "name": "plan-p7a",
        "iteration": 1,
        "config": {"project_dir": str(tmp_path)},
        "meta": {"current_invocation_id": "inv-p7a"},
        "active_step": {"run_id": "run-p7a"},
    }
    activate_phase_wbc(
        state=state,  # type: ignore[arg-type]
        plan_dir=tmp_path,
        step="review",
        agent="reviewer",
    )
    spec = build_worker_dispatch_spec(
        plan_dir=tmp_path,
        state=state,  # type: ignore[arg-type]
        step="review",
        agent="claude",
        selected_spec="claude:claude-sonnet-4-6:high",
        route_kind="direct",
    )
    assert spec is not None
    spec = _wire_dispatch_custody(spec)

    result = spec.run(lambda _start: _worker())

    assert result.reserve.action_boundary is not None
    assert result.reserve.action_boundary.gate_result == GateResult.AUTHORIZED
    assert result.reserve.action_boundary.enforcement_enabled is True
    assert result.reserve.action_boundary.gate_result is not GateResult.SHADOW_PASS
    assert result.reserve.action_boundary.is_shadow is False
    assert [event.event_type for event in spec.facade._ledger_store.read_events(spec.attempt_id)] == [
        AttemptEventType.STARTED,
        AttemptEventType.COMPLETED,
    ]


def test_worker_dispatch_spec_real_builder_acquires_custody_and_is_authorized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P7A regression: the REAL production builder path (no hand-wired fake
    stores) must acquire custody leases + outbox records for every boundary
    action type and yield an AUTHORIZED boundary under default enforcement."""
    monkeypatch.delenv("ARNOLD_M7_ACTION_VALIDATOR_ENFORCEMENT", raising=False)
    state = {
        "name": "plan-p7a-real",
        "iteration": 1,
        "config": {"project_dir": str(tmp_path)},
        "meta": {"current_invocation_id": "inv-p7a-real"},
        "active_step": {"run_id": "run-p7a-real"},
    }
    activate_phase_wbc(
        state=state,  # type: ignore[arg-type]
        plan_dir=tmp_path,
        step="review",
        agent="reviewer",
    )
    spec = build_worker_dispatch_spec(
        plan_dir=tmp_path,
        state=state,  # type: ignore[arg-type]
        step="review",
        agent="claude",
        selected_spec="claude:claude-sonnet-4-6:high",
        route_kind="direct",
    )
    assert spec is not None

    # The production facade carries real stores, not the None-wired stubs.
    assert spec.facade._lease_store is not None
    assert spec.facade._outbox is not None
    # Every boundary action type has an active lease owned by this runtime.
    for ctx in (
        spec.start_action_context,
        spec.success_action_context,
        spec.failure_action_context,
    ):
        lease = spec.facade._lease_store.current_lease(
            f"custody-lease-{ctx.target.target_digest[:16]}"
        )
        assert lease is not None
        assert lease.is_expired is False
        assert lease.owner_host == ctx.owner_host
        assert lease.owner_pid == ctx.owner_pid
        assert lease.owner_boot_id == ctx.owner_boot_id

    result = spec.run(lambda _start: _worker())

    assert result.reserve.action_boundary is not None
    assert result.reserve.action_boundary.gate_result == GateResult.AUTHORIZED
    assert result.reserve.action_boundary.enforcement_enabled is True
    assert result.reserve.action_boundary.is_shadow is False
    assert [event.event_type for event in spec.facade._ledger_store.read_events(spec.attempt_id)] == [
        AttemptEventType.STARTED,
        AttemptEventType.COMPLETED,
    ]
    # The outbox carries one record per boundary action type for this attempt.
    records = spec.facade._outbox.list_records()
    assert len([r for r in records if r.wbc_attempt_reference == spec.attempt_id]) == 3


def test_worker_dispatch_spec_denies_when_custody_is_contended(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Under default enforcement, a dispatch whose custody lease is held by
    another runtime is denied at spec build — the lease is never stolen, and
    no STARTED event is appended."""
    monkeypatch.delenv("ARNOLD_M7_ACTION_VALIDATOR_ENFORCEMENT", raising=False)
    state = {
        "name": "plan-p7a-denied",
        "iteration": 1,
        "config": {"project_dir": str(tmp_path)},
        "meta": {"current_invocation_id": "inv-p7a-denied"},
        "active_step": {"run_id": "run-p7a-denied"},
    }
    phase = activate_phase_wbc(
        state=state,  # type: ignore[arg-type]
        plan_dir=tmp_path,
        step="review",
        agent="reviewer",
    )
    assert phase is not None
    # Pre-seed a lease for the start boundary target owned by a DIFFERENT
    # runtime, so the production builder's idempotent acquisition must deny.
    # The digest is derived exactly as the builder/validator derive it: the
    # legacy six-field CustodyTargetKey over the dispatch action context.
    from datetime import datetime, timedelta, timezone

    from arnold_pipelines.megaplan.custody.contracts import CustodyTargetKey
    from arnold_pipelines.megaplan.custody.lease_store import open_lease_store

    start_target = CustodyTargetKey(
        "phase_worker_dispatch",
        "review",
        "dispatch",
        "direct",
        "review",
        "claude:claude-sonnet-4-6:high",
    )
    foreign_digest = start_target.target_digest
    foreign_lease_id = f"custody-lease-{foreign_digest[:16]}"
    open_lease_store(tmp_path / "custody" / "leases").acquire(
        lease_id=foreign_lease_id,
        owner_host="foreign-host",
        owner_pid="999999",
        owner_boot_id="foreign-boot",
        run_authority_grant_id="foreign-grant",
        coordinator_fence_token=0,
        wbc_attempt_reference="foreign-attempt",
        occurrence_digest=foreign_digest,
        custody_epoch=1,
        expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        idempotency_key="foreign-seed",
    )
    with pytest.raises(ActionBoundaryDeniedError, match="not authorized"):
        build_worker_dispatch_spec(
            plan_dir=tmp_path,
            state=state,  # type: ignore[arg-type]
            step="review",
            agent="claude",
            selected_spec="claude:claude-sonnet-4-6:high",
            route_kind="direct",
        )
    # No event may have been appended by the denied build.
    store = SqliteAttemptLedgerStore(tmp_path / ".worker_dispatch_wbc_attempts.sqlite3")
    try:
        (count,) = store.conn.execute("SELECT COUNT(1) FROM attempt_events").fetchone()
        assert count == 0
    finally:
        store.close()


def test_worker_dispatch_spec_is_shadow_only_when_explicitly_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Shadow mode is reachable only via the explicit disable switch; the
    facade must be constructed with enforcement OFF then."""
    monkeypatch.setenv("ARNOLD_M7_ACTION_VALIDATOR_ENFORCEMENT", "0")
    state = {
        "name": "plan-p7a-shadow",
        "iteration": 1,
        "config": {"project_dir": str(tmp_path)},
        "meta": {"current_invocation_id": "inv-p7a-shadow"},
        "active_step": {"run_id": "run-p7a-shadow"},
    }
    activate_phase_wbc(
        state=state,  # type: ignore[arg-type]
        plan_dir=tmp_path,
        step="review",
        agent="reviewer",
    )
    spec = build_worker_dispatch_spec(
        plan_dir=tmp_path,
        state=state,  # type: ignore[arg-type]
        step="review",
        agent="claude",
        selected_spec="claude:claude-sonnet-4-6:high",
        route_kind="direct",
    )
    assert spec is not None
    assert spec.facade._enforcement_enabled is False


def test_worker_dispatch_spec_shadow_mode_is_denied_with_no_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-0013 deny-by-default lock: ARNOLD_M7_ACTION_VALIDATOR_ENFORCEMENT=0
    is a FUNCTIONAL shadow mode, but SHADOW_PASS NEVER authorizes a WBC
    effect.  The real production builder acquires custody, yet the facade
    DENIES the SHADOW_PASS reserve boundary and no ledger event is appended.
    The previous Option-A behavior of accepting the SHADOW_PASS boundaries
    and recording shadow evidence blessed the unsafe path and is locked out
    here; observation-only rereads remain available."""
    monkeypatch.setenv("ARNOLD_M7_ACTION_VALIDATOR_ENFORCEMENT", "0")
    state = {
        "name": "plan-p7a-shadow-e2e",
        "iteration": 1,
        "config": {"project_dir": str(tmp_path)},
        "meta": {"current_invocation_id": "inv-p7a-shadow-e2e"},
        "active_step": {"run_id": "run-p7a-shadow-e2e"},
    }
    activate_phase_wbc(
        state=state,  # type: ignore[arg-type]
        plan_dir=tmp_path,
        step="review",
        agent="reviewer",
    )
    spec = build_worker_dispatch_spec(
        plan_dir=tmp_path,
        state=state,  # type: ignore[arg-type]
        step="review",
        agent="claude",
        selected_spec="claude:claude-sonnet-4-6:high",
        route_kind="direct",
    )
    assert spec is not None
    assert spec.facade._enforcement_enabled is False

    # The dispatch is denied at the reserve boundary — SHADOW_PASS never
    # authorizes an effect, regardless of enforcement being disabled.
    with pytest.raises(ActionBoundaryDeniedError, match="not authorized: shadow_pass"):
        spec.run(lambda _start: _worker())

    # Fail-closed: no WBC event was appended by the denied dispatch.
    # (Custody leases/outbox records are acquired at spec build, before any
    # boundary validation, and are unchanged — the SHADOW_PASS boundary
    # itself never admits an effect.)
    assert spec.facade._ledger_store.read_events(spec.attempt_id) == []


# ── Codex-gate blockers: crash-atomicity + epoch/expiry recovery ───────────


def _expired_seed_lease(
    tmp_path: Path,
    target: CustodyTargetKey,
    *,
    owner_host: str,
    owner_pid: str,
    owner_boot_id: str,
    idempotency_key: str,
) -> str:
    """Seed an ACTIVE (non-terminal) lease whose TTL expired long ago."""
    from arnold_pipelines.megaplan.custody.lease_store import open_lease_store

    digest = target.target_digest
    lease_id = f"custody-lease-{digest[:16]}"
    open_lease_store(tmp_path / "custody" / "leases").acquire(
        lease_id=lease_id,
        owner_host=owner_host,
        owner_pid=owner_pid,
        owner_boot_id=owner_boot_id,
        run_authority_grant_id="seed-grant",
        coordinator_fence_token=0,
        wbc_attempt_reference="seed-attempt",
        occurrence_digest=digest,
        custody_epoch=1,
        occurred_at="2020-01-01T00:00:00Z",
        expires_at="2020-01-02T00:00:00Z",
        idempotency_key=idempotency_key,
    )
    return lease_id


def test_worker_dispatch_spec_repairs_missing_outbox_record_after_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Blocker 1 (crash-atomicity): a crash between the lease append and the
    outbox write leaves an owned lease with no outbox record; the idempotent
    retry must REPAIR it so the WBC attempt reference is never
    BLOCKED_WBC_MISSING."""
    monkeypatch.delenv("ARNOLD_M7_ACTION_VALIDATOR_ENFORCEMENT", raising=False)
    state = {
        "name": "plan-blocker-1",
        "iteration": 1,
        "config": {"project_dir": str(tmp_path)},
        "meta": {"current_invocation_id": "inv-blocker-1"},
        "active_step": {"run_id": "run-blocker-1"},
    }
    activate_phase_wbc(
        state=state,  # type: ignore[arg-type]
        plan_dir=tmp_path,
        step="review",
        agent="reviewer",
    )
    kwargs = {
        "plan_dir": tmp_path,
        "state": state,
        "step": "review",
        "agent": "claude",
        "selected_spec": "claude:claude-sonnet-4-6:high",
        "route_kind": "direct",
    }
    first = build_worker_dispatch_spec(**kwargs)
    assert first is not None
    # Simulate the crash window: leases are durable, outbox records are lost.
    for record in first.facade._outbox.list_records():
        if record.wbc_attempt_reference == first.attempt_id:
            (tmp_path / "custody" / "outbox" / f"{record.outbox_id}.record.json").unlink()
    # Retry in the same runtime: the lease is ours and active, so the
    # idempotent keep path must repair the missing outbox record.
    second = build_worker_dispatch_spec(**kwargs)
    assert second is not None
    assert second.attempt_id == first.attempt_id
    records = second.facade._outbox.list_records()
    matching = [r for r in records if r.wbc_attempt_reference == second.attempt_id]
    assert len(matching) == 3
    # The repaired dispatch runs end to end under enforcement.
    result = second.run(lambda _start: _worker())
    assert result.reserve.action_boundary.gate_result == GateResult.AUTHORIZED
    assert [event.event_type for event in second.facade._ledger_store.read_events(second.attempt_id)] == [
        AttemptEventType.STARTED,
        AttemptEventType.COMPLETED,
    ]


def test_worker_dispatch_spec_renews_expired_self_lease_with_strictly_greater_epoch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Blocker 2a (epoch correctness): an expired lease owned by THIS runtime
    is renewed with a STRICTLY GREATER epoch (the store enforces monotonic
    epoch) instead of re-passing the current epoch, and the rebuilt dispatch
    stays authorized."""
    monkeypatch.delenv("ARNOLD_M7_ACTION_VALIDATOR_ENFORCEMENT", raising=False)
    from arnold_pipelines.megaplan.custody.worker_dispatch_wbc import _runtime_owner

    host, pid, boot_id = _runtime_owner()
    start_target = CustodyTargetKey(
        "phase_worker_dispatch",
        "review",
        "dispatch",
        "direct",
        "review",
        "claude:claude-sonnet-4-6:high",
    )
    lease_id = _expired_seed_lease(
        tmp_path,
        start_target,
        owner_host=host,
        owner_pid=pid,
        owner_boot_id=boot_id,
        idempotency_key="expired-self-seed",
    )
    state = {
        "name": "plan-blocker-2a",
        "iteration": 1,
        "config": {"project_dir": str(tmp_path)},
        "meta": {"current_invocation_id": "inv-blocker-2a"},
        "active_step": {"run_id": "run-blocker-2a"},
    }
    activate_phase_wbc(
        state=state,  # type: ignore[arg-type]
        plan_dir=tmp_path,
        step="review",
        agent="reviewer",
    )
    spec = build_worker_dispatch_spec(
        plan_dir=tmp_path,
        state=state,  # type: ignore[arg-type]
        step="review",
        agent="claude",
        selected_spec="claude:claude-sonnet-4-6:high",
        route_kind="direct",
    )
    assert spec is not None
    lease = spec.facade._lease_store.current_lease(lease_id)
    assert lease is not None
    # Strictly greater epoch (seeded epoch 1 -> renewed epoch 2), no longer
    # expired, still owned by this runtime.
    assert lease.custody_epoch == 2
    assert lease.is_expired is False
    assert (lease.owner_host, lease.owner_pid, lease.owner_boot_id) == (host, pid, boot_id)
    result = spec.run(lambda _start: _worker())
    assert result.reserve.action_boundary.gate_result == GateResult.AUTHORIZED


def test_worker_dispatch_spec_reclaims_expired_foreign_lease_with_greater_epoch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Blocker 2b (expiry recovery): an EXPIRED lease held by a foreign
    runtime is reclaimed (expire-then-reclaim) with a strictly greater epoch —
    the target is never left wedged — and the dispatch builds + runs under
    enforcement."""
    monkeypatch.delenv("ARNOLD_M7_ACTION_VALIDATOR_ENFORCEMENT", raising=False)
    start_target = CustodyTargetKey(
        "phase_worker_dispatch",
        "review",
        "dispatch",
        "direct",
        "review",
        "claude:claude-sonnet-4-6:high",
    )
    lease_id = _expired_seed_lease(
        tmp_path,
        start_target,
        owner_host="foreign-host",
        owner_pid="999999",
        owner_boot_id="foreign-boot",
        idempotency_key="foreign-expired-seed",
    )
    state = {
        "name": "plan-blocker-2b",
        "iteration": 1,
        "config": {"project_dir": str(tmp_path)},
        "meta": {"current_invocation_id": "inv-blocker-2b"},
        "active_step": {"run_id": "run-blocker-2b"},
    }
    activate_phase_wbc(
        state=state,  # type: ignore[arg-type]
        plan_dir=tmp_path,
        step="review",
        agent="reviewer",
    )
    spec = build_worker_dispatch_spec(
        plan_dir=tmp_path,
        state=state,  # type: ignore[arg-type]
        step="review",
        agent="claude",
        selected_spec="claude:claude-sonnet-4-6:high",
        route_kind="direct",
    )
    assert spec is not None
    lease = spec.facade._lease_store.current_lease(lease_id)
    assert lease is not None
    # Ownership moved to this runtime at a strictly greater epoch; the lease
    # now references this attempt.
    assert lease.custody_epoch == 2
    assert lease.is_expired is False
    assert (lease.owner_host, lease.owner_pid, lease.owner_boot_id) == (
        spec.start_action_context.owner_host,
        spec.start_action_context.owner_pid,
        spec.start_action_context.owner_boot_id,
    )
    assert lease.wbc_attempt_reference == spec.attempt_id
    # Crash-atomicity: the reclaim path also wrote the outbox records.
    records = spec.facade._outbox.list_records()
    assert len([r for r in records if r.wbc_attempt_reference == spec.attempt_id]) == 3
    result = spec.run(lambda _start: _worker())
    assert result.terminal.action_boundary.gate_result == GateResult.AUTHORIZED


def test_worker_dispatch_spec_renews_lease_before_completion_boundary_after_ttl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Blocker 2c (TTL coverage): a worker that outlived the 1h lease TTL is
    not denied at the completion boundary — the facade renews the self-owned
    lease immediately before the boundary re-read, so reserve/start/complete
    all see an active lease and the run completes end to end."""
    import json

    monkeypatch.delenv("ARNOLD_M7_ACTION_VALIDATOR_ENFORCEMENT", raising=False)
    state = {
        "name": "plan-blocker-2c",
        "iteration": 1,
        "config": {"project_dir": str(tmp_path)},
        "meta": {"current_invocation_id": "inv-blocker-2c"},
        "active_step": {"run_id": "run-blocker-2c"},
    }
    activate_phase_wbc(
        state=state,  # type: ignore[arg-type]
        plan_dir=tmp_path,
        step="review",
        agent="reviewer",
    )
    spec = build_worker_dispatch_spec(
        plan_dir=tmp_path,
        state=state,  # type: ignore[arg-type]
        step="review",
        agent="claude",
        selected_spec="claude:claude-sonnet-4-6:high",
        route_kind="direct",
    )
    assert spec is not None
    store = spec.facade._lease_store
    leases_dir = tmp_path / "custody" / "leases"
    # Model the worker running past the 1h TTL: advance every boundary
    # lease's cached expiry into the past.  The durable history is untouched,
    # so the store's owner/epoch invariants still hold for renewal.
    for ctx in (
        spec.start_action_context,
        spec.success_action_context,
        spec.failure_action_context,
    ):
        lease_id = f"custody-lease-{ctx.target.target_digest[:16]}"
        state_path = leases_dir / f"{lease_id}.state.json"
        data = json.loads(state_path.read_text(encoding="utf-8"))
        # Both timestamps move into the past together (the contract requires
        # expires_at > acquired_at); the lease is valid but long expired.
        data["acquired_at"] = "2020-01-01T00:00:00+00:00"
        data["expires_at"] = "2020-01-02T00:00:00+00:00"
        state_path.write_text(json.dumps(data), encoding="utf-8")
        current = store.current_lease(lease_id)
        assert current is not None
        assert current.is_expired is True

    result = spec.run(lambda _start: _worker())

    # The reserve boundary renewed the start lease; the completion boundary
    # renewed the success lease — both stayed active across the run.
    for ctx in (spec.start_action_context, spec.success_action_context):
        lease = store.current_lease(f"custody-lease-{ctx.target.target_digest[:16]}")
        assert lease is not None
        assert lease.is_expired is False
        assert lease.custody_epoch == 2  # 1 (build) -> 2 (boundary renew)
    assert result.reserve.action_boundary.gate_result == GateResult.AUTHORIZED
    assert result.terminal.action_boundary.gate_result == GateResult.AUTHORIZED
    assert [event.event_type for event in spec.facade._ledger_store.read_events(spec.attempt_id)] == [
        AttemptEventType.STARTED,
        AttemptEventType.COMPLETED,
    ]


# ── Fence + custody-epoch carry (T-0101e) ───────────────────────────────────


def _build_dispatch_spec_with_state(
    tmp_path: Path,
    *,
    state: dict[str, object],
    step: str = "critique",
) -> object:
    from arnold_pipelines.megaplan.custody.phase_wbc import activate_phase_wbc
    from arnold_pipelines.megaplan.custody.worker_dispatch_wbc import build_worker_dispatch_spec

    phase = activate_phase_wbc(
        state=state,  # type: ignore[arg-type]
        plan_dir=tmp_path,
        step=step,
        agent="critic",
    )
    assert phase is not None
    return build_worker_dispatch_spec(
        plan_dir=tmp_path,
        state=state,  # type: ignore[arg-type]
        step=step,
        agent="hermes",
        selected_spec="omp:zai/glm-5.2",
        route_kind="subprocess",
    )


def test_worker_dispatch_leases_carry_repair_identity_fence_and_epoch(
    tmp_path: Path,
) -> None:
    """When the plan runs inside a repair occurrence, every dispatch lease,
    outbox record and action-boundary context carries the occurrence's
    AUTHORITATIVE fence token + custody epoch instead of a fabricated 0/1."""
    from tests.cloud.repair_identity_fixtures import repair_identity

    identity = repair_identity(
        session="dispatch-carry-session",
        plan="dispatch-plan",
        failure_kind="deterministic_phase_failure",
        phase="critique",
        task="phase:critique",
        fence_token=7,
        custody_epoch=3,
        coordinator_attempt_id="coord-carry",
    )
    state: dict[str, object] = {
        "name": "plan-dispatch-carry",
        "iteration": 1,
        "config": {"project_dir": str(tmp_path)},
        "meta": {"current_invocation_id": "inv-carry", "repair_identity": identity},
        "active_step": {"run_id": "run-carry"},
    }
    spec = _build_dispatch_spec_with_state(tmp_path, state=state)
    assert spec is not None

    # The action-boundary contexts carry the same fence as the leases.
    assert spec.start_action_context.coordinator_fence_token == 7

    lease_store = spec.facade._lease_store
    seen_leases = 0
    for ctx in (
        spec.start_action_context,
        spec.success_action_context,
        spec.failure_action_context,
    ):
        lease = lease_store.current_lease(
            f"custody-lease-{ctx.target.target_digest[:16]}"
        )
        assert lease is not None, ctx.action_type
        assert lease.coordinator_fence_token == 7, ctx.action_type
        assert lease.custody_epoch == 3, ctx.action_type
        seen_leases += 1
    assert seen_leases == 3

    # Outbox records mirror the ACTUAL recorded lease state (fence + epoch).
    records = spec.facade._outbox.list_records()
    assert records
    for record in records:
        assert record.coordinator_fence_token == 7
        assert record.custody_epoch == 3


def test_worker_dispatch_leases_default_fence_zero_epoch_one_without_identity(
    tmp_path: Path,
) -> None:
    """Plans without a repair identity keep the neutral fence=0 / epoch=1
    dispatch contract (unchanged behavior)."""
    state: dict[str, object] = {
        "name": "plan-plain",
        "iteration": 1,
        "config": {"project_dir": str(tmp_path)},
        "meta": {"current_invocation_id": "inv-plain"},
        "active_step": {"run_id": "run-plain"},
    }
    spec = _build_dispatch_spec_with_state(tmp_path, state=state)
    assert spec is not None
    assert spec.start_action_context.coordinator_fence_token == 0

    lease_store = spec.facade._lease_store
    ctx = spec.start_action_context
    lease = lease_store.current_lease(f"custody-lease-{ctx.target.target_digest[:16]}")
    assert lease is not None
    assert lease.coordinator_fence_token == 0
    assert lease.custody_epoch == 1
