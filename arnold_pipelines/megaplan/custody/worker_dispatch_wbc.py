"""Auto-built WBC dispatch specs for provider-backed worker families."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import socket
import uuid
from typing import Any, Iterable, Mapping

from arnold.workflow.attempt_ledger_store import SqliteAttemptLedgerStore
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
from arnold_pipelines.megaplan.cloud.feature_flags import production_enforcement_enabled
from arnold_pipelines.megaplan.types import PlanState

from .action_validator import ActionBoundaryContext
from .common_worker_dispatch import CommonWorkerDispatchSpec
from .controlled_writer_registry import Cohort, ControlledWriter, register_writer
from .contracts import (
    CustodyTargetKey,
    RepairOccurrenceKey,
    normalize_repair_occurrence_key,
    owner_observably_dead,
    process_birth_identity,
)
from .lease_store import (
    CustodyLeaseStore,
    LeaseStoreError,
    TerminalLeaseError,
    open_lease_store,
)
from .outbox import CustodyOutbox, OutboxRecord, OutboxRecordStatus, OutboxRecordType, open_outbox
from .phase_wbc import phase_wbc_state
from .wbc_runtime import (
    ActionBoundaryDeniedError,
    ExactSourceRecord,
    ImmutableAttemptArtifacts,
    PromotionMode,
    WbcRuntimeProducerFacade,
)

WORKER_DISPATCH_WBC_LEDGER_FILENAME = ".worker_dispatch_wbc_attempts.sqlite3"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class WorkerDispatchWriterSpec:
    route_kind: str
    writer_id: str
    surface_name: str
    contract_ids: tuple[str, ...]
    source_file: str
    function_name: str


_WRITER_SPECS: tuple[WorkerDispatchWriterSpec, ...] = (
    WorkerDispatchWriterSpec(
        route_kind="direct",
        writer_id="megaplan.worker_dispatch.direct",
        surface_name="megaplan.worker_dispatch.direct",
        contract_ids=(
            "provider_dispatch",
            "fallback_chain",
            "omp_dispatch",
            "shannon_dispatch",
            "shannon_stream_dispatch",
            "shannon_session_dispatch",
        ),
        source_file="arnold_pipelines/megaplan/handlers/shared.py",
        function_name="_run_worker",
    ),
    WorkerDispatchWriterSpec(
        route_kind="subprocess",
        writer_id="megaplan.worker_dispatch.subprocess",
        surface_name="megaplan.worker_dispatch.subprocess",
        contract_ids=(
            "worker_subprocess_dispatch",
            "fallback_chain",
            "omp_dispatch",
            "shannon_dispatch",
            "shannon_stream_dispatch",
            "shannon_session_dispatch",
        ),
        source_file="arnold_pipelines/megaplan/_core/worker_fanout.py",
        function_name="_dispatch_worker_unit_attempt",
    ),
)
_WRITER_SPEC_BY_ROUTE = {spec.route_kind: spec for spec in _WRITER_SPECS}


def register_worker_dispatch_wbc_writers() -> None:
    for spec in _WRITER_SPECS:
        try:
            register_writer(
                ControlledWriter(
                    writer_id=spec.writer_id,
                    surface_name=spec.surface_name,
                    cohort=Cohort.ACTIVE,
                    contract_ids=spec.contract_ids,
                    source_file=spec.source_file,
                    function_name=spec.function_name,
                    required_wbc_phases=("start", "terminal"),
                    action_kind="dispatch",
                )
            )
        except ValueError:
            continue


def build_worker_dispatch_spec(
    *,
    plan_dir: Path,
    state: PlanState,
    step: str,
    agent: str,
    selected_spec: str,
    route_kind: str,
    attempt_index: int = 0,
    configured_specs: Iterable[str] = (),
    attempted_specs: Iterable[str] = (),
    failed_attempt_reasons: Iterable[str] = (),
    fallback_trigger: str | None = None,
    phase_step: str | None = None,
    dispatch_key: str | None = None,
) -> CommonWorkerDispatchSpec | None:
    phase = phase_wbc_state(state, step=phase_step or step) or phase_wbc_state(state)
    if phase is None:
        return None
    writer_spec = _WRITER_SPEC_BY_ROUTE.get(route_kind)
    if writer_spec is None:
        raise ValueError(f"unsupported worker dispatch route kind: {route_kind!r}")
    register_worker_dispatch_wbc_writers()

    selected_spec = str(selected_spec or agent).strip()
    phase_attempt_id = str(phase.get("attempt_id") or "").strip()
    phase_source_version = str(phase.get("source_version") or "").strip()
    phase_name = str(phase.get("step") or step).strip() or step
    if not phase_attempt_id or not phase_source_version:
        return None
    normalized_dispatch_key: str | None = None
    if dispatch_key is not None:
        normalized_dispatch_key = str(dispatch_key).strip()
        if not normalized_dispatch_key:
            raise ValueError("dispatch_key must be non-empty when provided")

    identity_parts = (
        f"{phase_source_version}:{route_kind}:{phase_name}:{selected_spec}:{int(attempt_index)}"
    )
    expected_source_version = (
        identity_parts
        if normalized_dispatch_key is None
        else f"{identity_parts}:{normalized_dispatch_key}"
    )
    dispatch_invocation_id = str(
        (state.get("meta") or {}).get("current_invocation_id") or "worker-dispatch"
    )
    legacy_attempt_identity = (
        f"{phase_attempt_id}::{route_kind}::{phase_name}::{selected_spec}::{int(attempt_index)}"
    )
    if normalized_dispatch_key is not None:
        legacy_attempt_identity = f"{legacy_attempt_identity}::{normalized_dispatch_key}"
    legacy_attempt_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            legacy_attempt_identity,
        )
    )
    attempt_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"{legacy_attempt_identity}::{dispatch_invocation_id}::worker-dispatch-v2",
        )
    )
    legacy_idempotency_key = False
    legacy_store = SqliteAttemptLedgerStore(plan_dir / WORKER_DISPATCH_WBC_LEDGER_FILENAME)
    try:
        legacy_events = legacy_store.read_events(legacy_attempt_id)
        if legacy_events:
            expected_legacy_identity = _identity(
                state=state,
                attempt_id=legacy_attempt_id,
                phase_step=phase_name,
                worker_step=step,
                attempt_index=int(attempt_index),
                dispatch_key=normalized_dispatch_key,
                invocation_id=dispatch_invocation_id,
            )
            legacy_idempotency_key = legacy_events[0].identity == expected_legacy_identity
    finally:
        legacy_store.close()
    if legacy_idempotency_key:
        attempt_id = legacy_attempt_id
    configured_specs_tuple = tuple(str(item) for item in configured_specs)
    attempted_specs_tuple = tuple(str(item) for item in attempted_specs)
    failed_attempt_reasons_tuple = tuple(str(item) for item in failed_attempt_reasons)
    metadata = {
        "route_kind": route_kind,
        "phase_step": phase_name,
        "worker_step": step,
        "worker_agent": agent,
        "selected_spec": selected_spec,
        "attempt_index": int(attempt_index),
        "configured_specs": list(configured_specs_tuple),
        "attempted_specs": list(attempted_specs_tuple),
        "failed_attempt_reasons": list(failed_attempt_reasons_tuple),
        "fallback_trigger": fallback_trigger,
        "phase_attempt_id": phase_attempt_id,
    }
    fresh_child_authority_check = None
    if bool(phase.get("projected_from_fresh_child")):
        binding = phase.get("authority_binding")
        pointer = phase.get("fresh_child_pointer")
        if not isinstance(binding, Mapping) or not isinstance(pointer, Mapping):
            raise ValueError("fresh-child worker dispatch projection is malformed")
        for key in (
            "run_id", "run_revision", "subject_attempt_id", "grant_id",
            "fence_token", "wbc_attempt_id", "glek", "custody_lease_id",
            "custody_epoch", "custody_ref",
        ):
            metadata[f"fresh_child_{key}"] = binding[key]
        metadata["fresh_child_target_descriptor_digest"] = binding[
            "target_descriptor"
        ]["descriptor_digest"]
        expected_binding = dict(binding)
        child_pointer = dict(pointer)

        def fresh_child_authority_check(stage: str) -> Mapping[str, Any]:
            from arnold_pipelines.megaplan.chain.fresh_child_launch import (
                read_fresh_child_authority,
            )

            observed = read_fresh_child_authority(
                child_pointer, plan_dir=plan_dir, expected=expected_binding
            )
            return {**observed, "dispatch_stage": stage}
    if normalized_dispatch_key is not None:
        metadata["dispatch_key"] = normalized_dispatch_key
    owner_host, owner_pid, owner_boot_id = _runtime_owner()
    # Fence + custody-epoch carry (T-0101e): when the plan runs inside a
    # repair occurrence, its authoritative identity fence/epoch stamp every
    # dispatch lease + outbox record (and the action-boundary contexts)
    # instead of a fabricated 0/1.
    if bool(phase.get("projected_from_fresh_child")):
        fence_token = int(binding["fence_token"])
        dispatch_custody_epoch = int(binding["custody_epoch"])
    else:
        fence_token, dispatch_custody_epoch = _repair_identity_carry(state)
    start_action_context = _shadow_action_context(
        phase_step=phase_name,
        worker_step=step,
        route_kind=route_kind,
        selected_spec=selected_spec,
        expected_source_version=expected_source_version,
        attempt_id=attempt_id,
        action_type="dispatch",
        owner_host=owner_host,
        owner_pid=owner_pid,
        owner_boot_id=owner_boot_id,
        coordinator_fence_token=fence_token,
        dispatch_key=normalized_dispatch_key,
    )
    success_action_context = _shadow_action_context(
        phase_step=phase_name,
        worker_step=step,
        route_kind=route_kind,
        selected_spec=selected_spec,
        expected_source_version=expected_source_version,
        attempt_id=attempt_id,
        action_type="completion",
        owner_host=owner_host,
        owner_pid=owner_pid,
        owner_boot_id=owner_boot_id,
        coordinator_fence_token=fence_token,
        dispatch_key=normalized_dispatch_key,
    )
    failure_action_context = _shadow_action_context(
        phase_step=phase_name,
        worker_step=step,
        route_kind=route_kind,
        selected_spec=selected_spec,
        expected_source_version=expected_source_version,
        attempt_id=attempt_id,
        action_type="repair",
        owner_host=owner_host,
        owner_pid=owner_pid,
        owner_boot_id=owner_boot_id,
        coordinator_fence_token=fence_token,
        dispatch_key=normalized_dispatch_key,
    )
    lease_store, outbox = _ensure_dispatch_leases(
        plan_dir=plan_dir,
        action_contexts=(
            start_action_context,
            success_action_context,
            failure_action_context,
        ),
        attempt_id=attempt_id,
        fence_token=fence_token,
        custody_epoch=dispatch_custody_epoch,
    )
    facade = WbcRuntimeProducerFacade(
        SqliteAttemptLedgerStore(plan_dir / WORKER_DISPATCH_WBC_LEDGER_FILENAME),
        source_lookup=lambda key: _exact_source_record(
            state=state,
            step=step,
            selected_spec=selected_spec,
            route_kind=route_kind,
            attempt_index=int(attempt_index),
            phase_step=phase_step,
            dispatch_key=normalized_dispatch_key,
            lookup_key=key,
        ),
        lease_store=lease_store,
        outbox=outbox,
        promotion_mode=PromotionMode.ACTION_OFF,
        enforcement_enabled=production_enforcement_enabled(),
    )
    artifacts = ImmutableAttemptArtifacts(
        attempt_id=attempt_id,
        metadata=metadata,
    )
    return CommonWorkerDispatchSpec(
        facade=facade,
        attempt_id=attempt_id,
        start_event=_event(
            state=state,
            attempt_id=attempt_id,
            phase_step=phase_name,
            worker_step=step,
            route_kind=route_kind,
            selected_spec=selected_spec,
            dispatch_attempt_index=int(attempt_index),
            dispatch_key=normalized_dispatch_key,
            invocation_id=dispatch_invocation_id,
            sequence=1,
            event_type=AttemptEventType.STARTED,
            idempotency_suffix="started",
            payload={
                **metadata,
                "status": "started",
            },
        ),
        success_event_factory=lambda result: _event(
            state=state,
            attempt_id=attempt_id,
            phase_step=phase_name,
            worker_step=step,
            route_kind=route_kind,
            selected_spec=selected_spec,
            dispatch_attempt_index=int(attempt_index),
            dispatch_key=normalized_dispatch_key,
            invocation_id=dispatch_invocation_id,
            sequence=2,
            event_type=AttemptEventType.COMPLETED,
            idempotency_suffix="completed",
            outcome=AttemptOutcome.SUCCEEDED,
            payload={
                **metadata,
                "status": "completed",
                **_worker_result_summary(result),
            },
        ),
        failure_event_factory=lambda exc: _event(
            state=state,
            attempt_id=attempt_id,
            phase_step=phase_name,
            worker_step=step,
            route_kind=route_kind,
            selected_spec=selected_spec,
            dispatch_attempt_index=int(attempt_index),
            dispatch_key=normalized_dispatch_key,
            invocation_id=dispatch_invocation_id,
            sequence=2,
            event_type=AttemptEventType.FAILED,
            idempotency_suffix="failed",
            outcome=AttemptOutcome.INDETERMINATE,
            payload={
                **metadata,
                "status": "failed",
                "error_type": type(exc).__name__,
                "error": str(exc),
            },
        ),
        start_action_context=start_action_context,
        success_action_context=success_action_context,
        failure_action_context=failure_action_context,
        artifacts=artifacts,
        authority_check=fresh_child_authority_check,
        writer_id=writer_spec.writer_id,
        surface_name=writer_spec.surface_name,
        expected_source_version=expected_source_version,
        start_source_lookup_key=_lookup_key(
            phase_step=phase_name,
            worker_step=step,
            route_kind=route_kind,
            attempt_index=int(attempt_index),
            dispatch_key=normalized_dispatch_key,
            stage="start",
        ),
        success_source_lookup_key=_lookup_key(
            phase_step=phase_name,
            worker_step=step,
            route_kind=route_kind,
            attempt_index=int(attempt_index),
            dispatch_key=normalized_dispatch_key,
            stage="complete",
        ),
        failure_source_lookup_key=_lookup_key(
            phase_step=phase_name,
            worker_step=step,
            route_kind=route_kind,
            attempt_index=int(attempt_index),
            dispatch_key=normalized_dispatch_key,
            stage="failure",
        ),
    )


def _lookup_key(
    *,
    phase_step: str,
    worker_step: str,
    route_kind: str,
    attempt_index: int,
    dispatch_key: str | None,
    stage: str,
) -> str:
    base = f"{phase_step}:{worker_step}:{route_kind}:{attempt_index}"
    if dispatch_key is not None:
        base = f"{base}:{dispatch_key}"
    return f"{base}:{stage}"


def _exact_source_record(
    *,
    state: PlanState,
    step: str,
    selected_spec: str,
    route_kind: str,
    attempt_index: int,
    phase_step: str | None,
    dispatch_key: str | None,
    lookup_key: str,
) -> ExactSourceRecord | None:
    phase = phase_wbc_state(state, step=phase_step or step) or phase_wbc_state(state)
    if phase is None:
        return None
    phase_source_version = str(phase.get("source_version") or "").strip()
    phase_attempt_id = str(phase.get("attempt_id") or "").strip()
    phase_name = str(phase.get("step") or step).strip() or step
    if not phase_source_version or not phase_attempt_id:
        return None
    version = f"{phase_source_version}:{route_kind}:{phase_name}:{selected_spec}:{attempt_index}"
    if dispatch_key is not None:
        version = f"{version}:{dispatch_key}"
    metadata = {
        "phase_step": phase_name,
        "worker_step": step,
        "selected_spec": selected_spec,
        "route_kind": route_kind,
        "attempt_index": attempt_index,
        "phase_attempt_id": phase_attempt_id,
    }
    if dispatch_key is not None:
        metadata["dispatch_key"] = dispatch_key
    return ExactSourceRecord(
        lookup_key=lookup_key,
        version=version,
        source_uri=f"plan://{phase_name}/{route_kind}/{step}",
        observed_at=_utcnow(),
        metadata=metadata,
    )


def _identity(
    *,
    state: PlanState,
    attempt_id: str,
    phase_step: str,
    worker_step: str,
    attempt_index: int,
    dispatch_key: str | None,
    invocation_id: str | None = None,
) -> AttemptIdentity:
    invocation_id = str(
        invocation_id
        or (state.get("meta") or {}).get("current_invocation_id")
        or "worker-dispatch"
    )
    return AttemptIdentity(
        workflow_id="megaplan.worker_dispatch",
        run_id=str(state.get("name") or "megaplan-plan"),
        graph_revision=phase_step,
        step_id=worker_step if dispatch_key is None else f"{worker_step}:{dispatch_key}",
        invocation_id=invocation_id,
        attempt_ordinal=max(attempt_index + 1, 1),
        attempt_id=attempt_id,
    )


def _event(
    *,
    state: PlanState,
    attempt_id: str,
    phase_step: str,
    worker_step: str,
    route_kind: str,
    selected_spec: str,
    dispatch_attempt_index: int,
    dispatch_key: str | None,
    sequence: int,
    event_type: AttemptEventType,
    idempotency_suffix: str,
    invocation_id: str | None = None,
    outcome: AttemptOutcome | None = None,
    payload: Mapping[str, Any] | None = None,
) -> LedgerEvent:
    return LedgerEvent(
        idempotency_key=f"{attempt_id}:{idempotency_suffix}",
        event_type=event_type,
        identity=_identity(
            state=state,
            attempt_id=attempt_id,
            phase_step=phase_step,
            worker_step=worker_step,
            attempt_index=dispatch_attempt_index,
            dispatch_key=dispatch_key,
            invocation_id=invocation_id,
        ),
        provenance=AttemptProvenance(
            actor_id="megaplan.worker_dispatch",
            tool_id=route_kind,
        ),
        adapter=RuntimeAdapter(
            adapter_kind=AdapterKind.MEGAPLAN_PHASE,
            adapter_version="1",
        ),
        versions=VersionSet(
            code_version=f"{phase_step}:{selected_spec}",
            config_version=f"{route_kind}.config.v1",
            template_version=f"{worker_step}.dispatch.v1",
        ),
        grant_ref=GrantRef(grant_id=f"{phase_step}:{route_kind}:{selected_spec}"),
        sequence=sequence,
        causal_predecessor_sequence=max(sequence - 1, 0),
        append_position=sequence,
        occurred_at=_utcnow(),
        observed_at=_utcnow(),
        persistence_status=PersistenceStatus.DURABLE,
        outcome=outcome,
        payload=dict(payload or {}),
    )


def _shadow_action_context(
    *,
    phase_step: str,
    worker_step: str,
    route_kind: str,
    selected_spec: str,
    expected_source_version: str,
    attempt_id: str,
    action_type: str,
    owner_host: str,
    owner_pid: str,
    owner_boot_id: str,
    coordinator_fence_token: int = 0,
    dispatch_key: str | None = None,
) -> ActionBoundaryContext:
    return ActionBoundaryContext(
        action_type=action_type,  # type: ignore[arg-type]
        target=CustodyTargetKey(
            "phase_worker_dispatch",
            phase_step,
            action_type,
            route_kind,
            worker_step,
            selected_spec,
            dispatch_key=dispatch_key or "",
        ),
        run_authority_grant_id=attempt_id,
        coordinator_fence_token=coordinator_fence_token,
        wbc_attempt_reference=attempt_id,
        owner_host=owner_host,
        owner_pid=owner_pid,
        owner_boot_id=owner_boot_id,
        required_capability=route_kind,
        required_wbc_evidence_version=expected_source_version,
    )


def _repair_identity_carry(state: Any) -> tuple[int, int]:
    """Return ``(fence_token, custody_epoch)`` carried from the plan's
    repair identity.

    When the plan runs inside a T-0101 repair occurrence, its
    ``meta.repair_identity`` carries the AUTHORITATIVE fence token and
    custody epoch (the recorded store authority); the dispatch leases and
    outbox records MUST carry those same values instead of fabricating
    fence=0 / epoch=1 per dispatch.  Plans without a repair identity
    (normal operation) keep the neutral ``(0, 1)`` defaults.
    """
    meta = state.get("meta") if isinstance(state, Mapping) else {}
    from arnold_pipelines.megaplan.cloud import repair_requests

    normalized = repair_requests.normalize_repair_identity(meta.get("repair_identity"))
    if normalized is None:
        return 0, 1
    occurrence_raw = normalized.get("occurrence")
    occurrence_key = (
        normalize_repair_occurrence_key(occurrence_raw)
        if isinstance(occurrence_raw, Mapping)
        else None
    )
    fence = int(occurrence_key.fence_token or 0) if occurrence_key is not None else 0
    epoch = int(normalized.get("custody_epoch") or 0)
    return fence, max(epoch, 1)


def _runtime_owner() -> tuple[str, str, str]:
    """Return the (host, pid, boot_id) identity of the current runtime.

    ``boot_id`` is read from ``/proc`` on Linux (the production box); on
    platforms without ``/proc`` (e.g. macOS local runs) it falls back to
    the canonical ``process_birth_identity`` approximation (hostname + PID-1
    process start time) so the lease owner is still a stable per-machine
    identity without /proc support.
    """
    try:
        host = socket.gethostname()
    except Exception:
        host = ""
    pid = str(os.getpid())
    try:
        boot_id = (
            Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
        )
    except Exception:
        try:
            birth = process_birth_identity()
            boot_id = str(birth.get("boot_id") or "")
        except Exception:
            boot_id = ""
    return host, pid, boot_id


def _ensure_dispatch_leases(
    *,
    plan_dir: Path,
    action_contexts: Iterable[ActionBoundaryContext],
    attempt_id: str,
    fence_token: int = 0,
    custody_epoch: int = 1,
) -> tuple[CustodyLeaseStore, CustodyOutbox]:
    """Acquire idempotent custody leases + outbox records for every dispatch
    action boundary (start/success/failure) before the facade is built.

    The lease id is derived exactly as the action validator derives it
    (``custody-lease-{target_digest[:16]}`` over the boundary target key), so
    the reread at validation time hits the same lease.

    Race-safety (no check-then-acquire TOCTOU): acquisition goes through the
    store's ``acquire``, which serializes the append under the lease's flock.
    When a lease is already visible the outcome is adjudicated by ownership:
    self-owned -> keep (or renew with a STRICTLY GREATER epoch when expired);
    expired/terminal foreign -> expire-then-reclaim (never leave a wedged
    target); active foreign -> raise a clear denial — the lease is never
    stolen.  A concurrent winner surfaced by a failed acquire is re-read and
    adjudicated the same way.

    Crash-atomicity: the outbox record for the (attempt, digest) pair is
    (re)written idempotently on EVERY path — fresh acquire, idempotent keep,
    self renewal, and foreign reclaim.  A crash between the lease append and
    the outbox write therefore heals on the next attempt instead of leaving a
    BLOCKED_WBC_MISSING wedge.

    Runs before the ledger-write path: when acquisition fails, no STARTED
    event has been appended yet (the dispatch raises during spec build).
    """
    owner_host, owner_pid, owner_boot_id = _runtime_owner()
    lease_store = open_lease_store(plan_dir / "custody" / "leases")
    outbox = open_outbox(plan_dir / "custody" / "outbox")
    for ctx in action_contexts:
        digest = ctx.target.target_digest
        lease_id = f"custody-lease-{digest[:16]}"
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(hours=1)).isoformat()

        # T-0205: acquire/reclaim payloads carry the FULL target identity —
        # the lossless RepairOccurrenceKey plus the explicit dispatch key — so
        # replaying the lease history reconstructs the exact dispatch target.
        # Every custody join (lease id, outbox occurrence digest, replayed
        # occurrence key) is keyed on the full target including dispatch_key;
        # two dispatches differing only in dispatch key can never collide.
        occurrence_key = RepairOccurrenceKey(
            target=ctx.target,
            run_id=attempt_id,
            run_revision=str(custody_epoch),
            coordinator_attempt_id=attempt_id,
            fence_token=fence_token,
            wbc_attempt_reference=attempt_id,
        )
        lease_payload = {
            "dispatch_key": ctx.target.dispatch_key,
            "occurrence_key": occurrence_key.to_dict(),
        }

        current = lease_store.current_lease(lease_id)
        if current is None:
            # No visible lease — race-safe acquisition: the store serializes
            # the load/check/append under ONE lease flock, so a concurrent
            # winner surfaces as a store error here and is re-adjudicated
            # below instead of being raced in user space.
            try:
                lease_store.acquire(
                    lease_id=lease_id,
                    owner_host=owner_host,
                    owner_pid=owner_pid,
                    owner_boot_id=owner_boot_id,
                    run_authority_grant_id=attempt_id,
                    coordinator_fence_token=fence_token,
                    wbc_attempt_reference=attempt_id,
                    occurrence_digest=digest,
                    custody_epoch=custody_epoch,
                    expires_at=expires_at,
                    payload=lease_payload,
                )
            except LeaseStoreError:
                current = lease_store.current_lease(lease_id)
                if current is None:
                    raise

        if current is not None:
            same_owner = (
                current.owner_host == owner_host
                and current.owner_pid == owner_pid
                and (
                    not owner_boot_id
                    or not current.owner_boot_id
                    or current.owner_boot_id == owner_boot_id
                )
            )
            if same_owner:
                if current.is_expired:
                    try:
                        # Renewal must carry a strictly greater epoch (the
                        # store enforces monotonic epoch, Step 11C).
                        lease_store.renew(
                            lease_id=lease_id,
                            owner_host=owner_host,
                            owner_pid=owner_pid,
                            owner_boot_id=owner_boot_id,
                            custody_epoch=current.custody_epoch + 1,
                            expires_at=expires_at,
                        )
                    except TerminalLeaseError:
                        # Self-owned lease already terminal (released/expired/
                        # fenced): reclaim it with a strictly greater epoch.
                        lease_store.reclaim(
                            lease_id=lease_id,
                            owner_host=owner_host,
                            owner_pid=owner_pid,
                            owner_boot_id=owner_boot_id,
                            run_authority_grant_id=attempt_id,
                            coordinator_fence_token=fence_token,
                            wbc_attempt_reference=attempt_id,
                            occurrence_digest=digest,
                            custody_epoch=max(
                                custody_epoch, current.custody_epoch + 1
                            ),
                            expires_at=expires_at,
                            payload=lease_payload,
                        )
                # else: idempotent retry of the same dispatch — lease is ours.
            elif current.is_expired:
                # Expired or terminal foreign lease: never leave a wedged
                # target.  ``expire`` is the system-driven sweep path (no
                # owner enforcement); ``reclaim`` then enforces old-epoch
                # fencing via the strictly greater epoch.
                try:
                    lease_store.expire(lease_id=lease_id)
                except TerminalLeaseError:
                    pass  # already terminal — reclaim below is still valid
                lease_store.reclaim(
                    lease_id=lease_id,
                    owner_host=owner_host,
                    owner_pid=owner_pid,
                    owner_boot_id=owner_boot_id,
                    run_authority_grant_id=attempt_id,
                    coordinator_fence_token=fence_token,
                    wbc_attempt_reference=attempt_id,
                    occurrence_digest=digest,
                    custody_epoch=max(custody_epoch, current.custody_epoch + 1),
                    expires_at=expires_at,
                    payload=lease_payload,
                )
            else:
                # Terminal-but-not-yet-expired foreign lease (clock skew) is
                # still reclaimable; only an ACTIVE foreign lease denies.
                # An ACTIVE lease whose owner is observably DEAD (process
                # gone, same host, boot unchanged) is also reclaimable: a
                # resume worker that dies mid-batch otherwise wedges the
                # stable per-batch lease until its 1h TTL lapses (grok
                # consult).  Foreign-host and live-owner leases are never
                # stolen.
                owner_dead = owner_observably_dead(
                    host=current.owner_host,
                    pid=current.owner_pid,
                    boot_id=current.owner_boot_id,
                )
                if owner_dead:
                    try:
                        lease_store.expire(lease_id=lease_id)
                    except TerminalLeaseError:
                        pass  # already terminal — reclaim below is still valid
                try:
                    lease_store.reclaim(
                        lease_id=lease_id,
                        owner_host=owner_host,
                        owner_pid=owner_pid,
                        owner_boot_id=owner_boot_id,
                        run_authority_grant_id=attempt_id,
                        coordinator_fence_token=fence_token,
                        wbc_attempt_reference=attempt_id,
                        occurrence_digest=digest,
                        custody_epoch=max(
                            custody_epoch, current.custody_epoch + 1
                        ),
                        expires_at=expires_at,
                        payload=lease_payload,
                    )
                except LeaseStoreError:
                    raise ActionBoundaryDeniedError(
                        f"dispatch not authorized: custody lease {lease_id!r} is held by "
                        f"({current.owner_host!r}, {current.owner_pid!r}, "
                        f"{current.owner_boot_id!r}), not this runtime "
                        f"({owner_host!r}, {owner_pid!r}, {owner_boot_id!r})"
                    ) from None

        # Crash-atomicity repair: the outbox record for this (attempt, digest)
        # must exist on every path.  A record already present for the pair is
        # left untouched (idempotent retry / shared-digest boundary contexts
        # like execute's dispatch/completion/repair all reference the same
        # digest); when absent it is written idempotently, healing a crash
        # between the lease append and the outbox write.
        existing_records = outbox.list_records()
        has_record = any(
            record.wbc_attempt_reference == attempt_id
            and record.occurrence_digest == digest
            for record in existing_records
        )
        if not has_record:
            # The outbox record mirrors the ACTUAL recorded lease state
            # (fence + epoch carried from the plan's repair identity when
            # present, and the post-adjudication epoch) instead of a
            # fabricated 0/1.
            final_lease = lease_store.current_lease(lease_id)
            recorded_fence = (
                int(getattr(final_lease, "coordinator_fence_token", fence_token) or fence_token)
                if final_lease is not None
                else fence_token
            )
            recorded_epoch = (
                int(getattr(final_lease, "custody_epoch", custody_epoch) or custody_epoch)
                if final_lease is not None
                else custody_epoch
            )
            outbox.write_record(
                OutboxRecord(
                    outbox_id=f"dispatch-{attempt_id}-{digest[:16]}",
                    lease_id=lease_id,
                    record_type=OutboxRecordType.LEASE_ACQUIRE,
                    status=OutboxRecordStatus.PENDING,
                    occurred_at=now.isoformat(),
                    idempotency_key=f"dispatch-{attempt_id}-{digest[:16]}",
                    wbc_attempt_reference=attempt_id,
                    run_authority_grant_id=attempt_id,
                    coordinator_fence_token=recorded_fence,
                    occurrence_digest=digest,
                    custody_epoch=recorded_epoch,
                    payload={
                        "target_digest": digest,
                        "action_type": str(ctx.action_type),
                        **(
                            {"dispatch_key": ctx.target.dispatch_key}
                            if ctx.target.dispatch_key
                            else {}
                        ),
                    },
                )
            )
    return lease_store, outbox


def _worker_result_summary(result: Any) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for field_name in ("session_id", "model_actual", "worker_channel", "auth_channel"):
        value = getattr(result, field_name, None)
        if value not in (None, ""):
            summary[field_name] = value
    auth_metadata = getattr(result, "auth_metadata", None)
    if isinstance(auth_metadata, Mapping):
        summary["auth_metadata"] = dict(auth_metadata)
    return summary


def query_worker_dispatch_manifest(
    plan_dir: Path,
    *,
    phase_attempt_id: str,
) -> list[dict[str, Any]]:
    """Return terminally evidenced child dispatches for one phase attempt."""
    store = SqliteAttemptLedgerStore(plan_dir / WORKER_DISPATCH_WBC_LEDGER_FILENAME)
    try:
        rows = store.conn.execute(
            "SELECT DISTINCT attempt_id FROM attempt_events ORDER BY attempt_id"
        ).fetchall()
        manifest: list[dict[str, Any]] = []
        for (attempt_id,) in rows:
            events = store.read_events(str(attempt_id))
            if not events:
                continue
            start = events[0]
            start_payload = dict(start.payload or {})
            if start_payload.get("phase_attempt_id") != phase_attempt_id:
                continue
            terminal = events[-1]
            if terminal.event_type not in {
                AttemptEventType.COMPLETED,
                AttemptEventType.FAILED,
                AttemptEventType.CANCELLED,
            }:
                raise RuntimeError(
                    f"worker dispatch {attempt_id} has no terminal custody event"
                )
            terminal_payload = dict(terminal.payload or {})
            manifest.append(
                {
                    "attempt_id": str(attempt_id),
                    "dispatch_key": start_payload.get("dispatch_key"),
                    "worker_step": start_payload.get("worker_step"),
                    "selected_spec": start_payload.get("selected_spec"),
                    "attempt_index": start_payload.get("attempt_index"),
                    "terminal_event": terminal.event_type.value,
                    "terminal_status": terminal_payload.get("status"),
                    "start_sequence": start.sequence,
                    "terminal_sequence": terminal.sequence,
                }
            )
        return sorted(
            manifest,
            key=lambda row: (
                str(row.get("dispatch_key") or ""),
                int(row.get("attempt_index") or 0),
                str(row["attempt_id"]),
            ),
        )
    finally:
        store.close()


__all__ = [
    "WORKER_DISPATCH_WBC_LEDGER_FILENAME",
    "build_worker_dispatch_spec",
    "query_worker_dispatch_manifest",
    "register_worker_dispatch_wbc_writers",
]
