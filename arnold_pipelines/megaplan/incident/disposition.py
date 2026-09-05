"""Canonical disposition records and the non-signalling disposition CLI.

The helper records evidence; it deliberately never calls ``kill``.  Signal
sites can therefore enforce record-before-signal by invoking this module and
only signalling after a successful acknowledgement.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import signal as _signal
import sys
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any

from .ledger import IncidentLedger
from .schema import (
    CauseKind,
    DispositionMode,
    NonWorkerSignalDisposition,
    ObservedProcessDeath,
    WorkerDisposition,
    confirmation_ttl_s,
    validate_nbf_event,
)


class SignalDispositionError(RuntimeError):
    """A signal could not be admitted by the canonical disposition door.

    Signal sites must treat this as fail-closed: the victim remains alive and
    the caller may report the error, but must not call a lower-level primitive.
    """


@dataclass(frozen=True)
class WorkerSignalContext:
    """The immutable identity needed to attribute an in-band worker signal.

    This is intentionally a small adapter around the admission context.  It
    is not a second receipt or ledger authority; callers still resolve the
    authoritative receipt from ``WorkerExecutionContextRef``/the ledger.
    """

    plan_id: str
    phase: str
    dispatch_family_id: str
    logical_dispatch_id: str
    admission_receipt_id: str
    semantic_dispatch_fingerprint: str
    selected_spec: str
    worker_identity: dict[str, Any]
    victim_pid: int
    victim_process_start_identity: str
    physical_door_id: str = "default-door"
    execution_context_identity: str = ""
    started_at: str | None = None
    operation_store_root: str | None = None

    @classmethod
    def from_ref(cls, ref: Any, *, worker_identity: dict[str, Any], victim_pid: int,
                 victim_process_start_identity: str, started_at: str | None = None) -> "WorkerSignalContext":
        fields = ("plan_id", "phase", "dispatch_family_id", "logical_dispatch_id",
                  "admission_receipt_id", "semantic_dispatch_fingerprint", "selected_spec",
                  "physical_door_id")
        if any(not isinstance(getattr(ref, field, None), str) or not getattr(ref, field, None) for field in fields):
            raise SignalDispositionError("worker execution context is incomplete")
        if not isinstance(worker_identity, dict) or not worker_identity:
            raise SignalDispositionError("worker identity is missing")
        if not isinstance(victim_pid, int) or isinstance(victim_pid, bool) or victim_pid <= 0:
            raise SignalDispositionError("victim PID is invalid")
        if not isinstance(victim_process_start_identity, str) or not victim_process_start_identity:
            raise SignalDispositionError("victim process-start identity is missing")
        identity_pid = worker_identity.get("pid")
        if identity_pid is not None and identity_pid != victim_pid:
            raise SignalDispositionError("victim PID does not match worker identity")
        return cls(**{field: getattr(ref, field) for field in fields},
                   worker_identity=dict(worker_identity), victim_pid=victim_pid,
                   victim_process_start_identity=victim_process_start_identity,
                   started_at=started_at,
                   operation_store_root=str(getattr(ref, "operation_store_root", "") or "") or None)


@dataclass(frozen=True)
class WorkerLadderResult:
    """Durable result of a TERM → wait → KILL worker ladder."""

    state: str
    term_disposition: dict[str, Any] | None = None
    kill_disposition: dict[str, Any] | None = None
    terminal_outcome: dict[str, Any] | None = None
    observation: dict[str, Any] | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "term_disposition": self.term_disposition,
            "kill_disposition": self.kill_disposition,
            "terminal_outcome": self.terminal_outcome,
            "observation": self.observation,
            "reason": self.reason,
        }


def resolve_worker_execution_context(environment: Any = None, *, variable: str = "ARNOLD_WORKER_EXECUTION_CONTEXT") -> Any:
    """Resolve the typed in-band context; never reconstruct it from PID/model.

    Importing lazily keeps the incident package independent from the worker
    adapter while ensuring every signal site uses its canonical decoder.
    """
    from arnold_pipelines.megaplan.cloud.worker_dispatch import WorkerExecutionContextRef
    env = os.environ if environment is None else environment
    try:
        return WorkerExecutionContextRef.from_environment(env, variable=variable)
    except (TypeError, ValueError) as exc:
        raise SignalDispositionError(str(exc)) from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def confirmation_id(*, site_id: str, subject_class: str, victim_pid: int, victim_process_start_identity: str, relevant_progress_identity: str, supervisor_incarnation_identity: str, cause_kind: str, schema_version: int = 1, semantic_dispatch_fingerprint: str | None = None, container_identity: str | None = None, ladder_stage: str | None = None, signal_identity: str | None = None) -> str:
    material = {"confirmation_schema_version": schema_version, "site_id": site_id, "subject_class": subject_class, "victim_pid": victim_pid, "victim_process_start_identity": victim_process_start_identity, "relevant_progress_identity": relevant_progress_identity, "supervisor_incarnation_identity": supervisor_incarnation_identity, "cause_kind": cause_kind}
    if semantic_dispatch_fingerprint is not None:
        material["semantic_dispatch_fingerprint"] = semantic_dispatch_fingerprint
    if container_identity is not None:
        material["container_identity"] = container_identity
    if ladder_stage is not None:
        material["ladder_stage"] = ladder_stage
    if signal_identity is not None:
        material["signal_identity"] = signal_identity
    return _digest(material)


def record_disposition(ledger: IncidentLedger, disposition: WorkerDisposition | ObservedProcessDeath | NonWorkerSignalDisposition | dict[str, Any]) -> dict[str, Any]:
    """Validate and synchronously append a disposition through the ledger."""
    return ledger.append_disposition(disposition)


def record_before_signal(
    ledger: IncidentLedger,
    disposition: WorkerDisposition | NonWorkerSignalDisposition | ObservedProcessDeath | dict[str, Any],
    signal_fn: Any,
    *,
    terminal_outcome: Any = None,
    terminal_kwargs: dict[str, Any] | None = None,
    preflight: Any = None,
    actor: str = "signal-authority",
) -> dict[str, Any]:
    """The sole Python record-before-signal door.

    ``append_disposition`` is synchronous and fsync-backed.  The signal
    callable is reached only after that append succeeds.  A terminal outcome
    is projected after the signal and is idempotent in the ledger; callers can
    recover it by passing the same outcome/kwargs after a crash.  Any terminal append failure
    remains fail-closed and must be reconciled from durable
    signal-claim evidence; intent alone is never treated as a physical signal.
    """
    identity = None
    if hasattr(disposition, "disposition_id"):
        identity = disposition.disposition_id
    elif isinstance(disposition, dict):
        identity = disposition.get("disposition_id") or disposition.get("observation_id")
    if terminal_outcome is not None and terminal_kwargs is None:
        raise SignalDispositionError("terminal_kwargs are required for terminal projection")
    if preflight is not None:
        # The ledger owns the one lock boundary.  In particular, do not do a
        # start-identity check, release the lock, and then claim/signal: that
        # leaves a PID-reuse window between the check and the physical door.
        physical_missing = [False]

        def invoke_locked() -> None:
            try:
                signal_fn()
            except (ProcessLookupError, ChildProcessError):
                physical_missing[0] = True
                raise

        try:
            record = ledger.record_claim_signal_locked(
                disposition,
                signal=_signal_name(disposition),
                signal_fn=invoke_locked,
                preflight=preflight,
                actor=actor,
            )
        except SignalDispositionError:
            raise
        except Exception as exc:
            raise SignalDispositionError(f"signal admission failed: {exc}") from exc
        if physical_missing[0]:
            # A missing process is an observation/reconciliation result, not
            # evidence that a terminal callback completed.
            return record
        if terminal_outcome is not None:
            try:
                ledger.append_terminal_outcome(outcome=terminal_outcome, **terminal_kwargs)
            except Exception as exc:
                raise SignalDispositionError(f"terminal projection failed after signal: {exc}") from exc
        return record
    try:
        # The disposition is the immutable prerequisite committed before taking
        # the durable at-most-once signal claim.  The terminal must remain open
        # until the physical callback has returned: a callback failure can leave
        # a live victim, and must never project a closed/killed reservation.
        record = record_disposition(ledger, disposition)
        if not identity:
            raise ValueError("signal disposition identity is missing")
        _claim, created = ledger.claim_signal(identity, signal=_signal_name(disposition), actor="signal-authority")
    except Exception as exc:
        raise SignalDispositionError(f"disposition append failed: {exc}") from exc
    if not created:
        # A persisted claim proves only that a signal attempt was claimed; it
        # is not evidence that the physical callback ran or that the victim
        # died.  Leave recovery to the typed reconciliation path when the
        # terminal projection is still absent, never resend or infer success.
        if terminal_outcome is not None:
            reservation_event_id = (terminal_kwargs or {}).get("reservation_event_id")
            if reservation_event_id:
                existing = ledger.projection().get("terminals", {})
                terminal_kind = (
                    terminal_outcome.get("kind")
                    if isinstance(terminal_outcome, dict)
                    else getattr(terminal_outcome, "kind", None)
                )
                if not any(
                    item.get("reservation_event_id") == reservation_event_id
                    and item.get("outcome_kind") == terminal_kind
                    for item in existing.values()
                ):
                    raise SignalDispositionError(
                        "signal claim exists without terminal outcome; reconcile before retry"
                    )
        return record
    try:
        signal_fn()
    except (ProcessLookupError, ChildProcessError):
        # The evidence is still durable.  Callers may classify this as an
        # already-dead observation; never fabricate a second worker signal.
        return record
    except OSError as exc:
        raise SignalDispositionError(f"signal failed after disposition append: {exc}") from exc
    if terminal_outcome is not None:
        try:
            ledger.append_terminal_outcome(outcome=terminal_outcome, **terminal_kwargs)
        except Exception as exc:
            raise SignalDispositionError(f"terminal projection failed after signal: {exc}") from exc
    return record


def _signal_name(disposition: Any) -> str:
    value = disposition.get("signal") if isinstance(disposition, dict) else getattr(disposition, "signal", None)
    return getattr(value, "value", getattr(value, "name", str(value)))


def _canonical_worker_acceptance(context: WorkerSignalContext) -> dict[str, Any] | None:
    """Read accepted identity from OperationRun, never an incident marker."""
    try:
        from pathlib import Path
        from arnold.runtime.durable_ops import FileBackedDurableOpsStore

        root = Path(
            context.operation_store_root
            or os.environ.get("ARNOLD_OPS_STORE_ROOT")
            or Path.cwd() / "ops"
        )
        store = FileBackedDurableOpsStore(root)
        run = store.load_operation_run(context.logical_dispatch_id)
        if getattr(run.state, "value", run.state) != "running":
            return None
        for resource in store.list_typed_resources(context.logical_dispatch_id):
            identity = dict(resource.details).get("worker_identity")
            if (
                resource.resource_type.value == "process_session"
                and isinstance(identity, dict)
                and identity == context.worker_identity
                and identity.get("process_start_identity") == context.victim_process_start_identity
            ):
                return {"operation_id": run.id, "worker_identity": identity, "resource_id": resource.id}
    except (OSError, KeyError, TypeError, ValueError):
        return None
    return None


# Descriptive aliases used by signal-site adapters; all names point to the
# same authority and do not create additional persistence or policy doors.
signal_after_record = record_before_signal
record_and_signal = record_before_signal


def worker_disposition_for_signal(
    context: WorkerSignalContext,
    *,
    signal_name: str,
    killer_kind: str,
    killer_identity: str,
    cause_kind: str,
    elapsed_s: float,
    evidence: Any = None,
    mode: str = "in_band",
    process_group_identity: str | None = None,
    timeout_source: str | None = None,
    ladder_step: str | None = None,
    confirmation_event_id: str | None = None,
    observed_at: str | None = None,
    disposition_id: str | None = None,
) -> WorkerDisposition:
    """Build a lossless typed disposition from an admitted worker context."""
    if not isinstance(context, WorkerSignalContext):
        raise SignalDispositionError("worker signal requires WorkerSignalContext")
    signal_value = getattr(signal_name, "name", signal_name)
    signal_value = str(signal_value)
    if signal_value.startswith("SIG") is False:
        signal_value = f"SIG{signal_value}"
    disposition_id = disposition_id or WorkerDisposition.deterministic_id(
        receipt=context.admission_receipt_id, signal=signal_value,
        ladder_step=ladder_step,
    )
    return WorkerDisposition(
        disposition_id=disposition_id,
        mode=mode,
        plan_id=context.plan_id,
        phase=context.phase,
        dispatch_family_id=context.dispatch_family_id,
        logical_dispatch_id=context.logical_dispatch_id,
        admission_receipt_id=context.admission_receipt_id,
        semantic_dispatch_fingerprint=context.semantic_dispatch_fingerprint,
        selected_spec=context.selected_spec,
        killer_kind=killer_kind,
        killer_identity=killer_identity,
        cause_kind=cause_kind,
        signal=signal_value,
        elapsed_s=elapsed_s,
        worker_identity=dict(context.worker_identity),
        victim_pid=context.victim_pid,
        victim_process_start_identity=context.victim_process_start_identity,
        process_group_identity=process_group_identity,
        timeout_source=timeout_source,
        ladder_step=ladder_step,
        confirmation_event_id=confirmation_event_id,
        observed_at=observed_at or datetime.now(timezone.utc).isoformat(),
        evidence=evidence if evidence is not None else {},
    )


def signal_worker(
    ledger: IncidentLedger,
    context: WorkerSignalContext,
    *,
    signal_name: int | str,
    killer_kind: str,
    killer_identity: str,
    cause_kind: str,
    elapsed_s: float = 0.0,
    evidence: Any = None,
    timeout_source: str | None = None,
    ladder_step: str | None = None,
    confirmation_event_id: str | None = None,
    signal_fn: Any = None,
    terminal_outcome: Any = None,
    terminal_kwargs: dict[str, Any] | None = None,
    process_alive_fn: Any = None,
    process_start_identity_fn: Any = None,
    final_signal: bool = False,
) -> dict[str, Any]:
    """Record and, only on success, signal one admitted worker."""
    if final_signal is not True:
        raise SignalDispositionError("single-stage worker signal requires final_signal=True")
    projection = ledger.projection()
    canonical_acceptance = _canonical_worker_acceptance(context)
    reservation = next(
        (value for value in projection.get("reservations", {}).values()
         if value.get("admission_receipt_id") == context.admission_receipt_id),
        None,
    )
    number = getattr(signal_name, "value", signal_name)
    if isinstance(number, str):
        number = getattr(_signal, number, None)
    if not isinstance(number, int):
        raise SignalDispositionError(f"unknown signal {signal_name!r}")
    signal_label = _signal.Signals(number).name
    replay_id = WorkerDisposition.deterministic_id(
        receipt=context.admission_receipt_id, signal=signal_label,
        ladder_step=ladder_step,
    )
    if reservation is None and canonical_acceptance is None:
        raise SignalDispositionError("worker launch is not canonically accepted")
    if reservation is not None and reservation.get("closed"):
        prior = projection.get("dispositions", {}).get(replay_id)
        if prior is not None:
            return {"payload": prior}
        raise SignalDispositionError("worker receipt is not an active ledger reservation")
    if reservation is not None:
        for name in ("plan_id", "phase", "dispatch_family_id", "logical_dispatch_id", "selected_spec", "semantic_dispatch_fingerprint"):
            if reservation.get(name) != getattr(context, name):
                raise SignalDispositionError(f"worker receipt context mismatch: {name}")
    # A liveness/start-identity preflight is intentionally injectable for
    # supervisors and tests.  A failed preflight is an observation, never a
    # delivered worker disposition and never a signal attempt.
    if process_alive_fn is not None:
        try:
            alive = bool(process_alive_fn(context.victim_pid))
        except TypeError:
            alive = bool(process_alive_fn())
        if not alive:
            observed = ObservedProcessDeath(
                observation_id=_digest(("already-dead", context.admission_receipt_id, context.victim_pid, context.victim_process_start_identity)),
                subject="worker", observation_source="worker-signal-preflight",
                known_context_fields={"plan_id": context.plan_id, "phase": context.phase, "admission_receipt_id": context.admission_receipt_id, "semantic_dispatch_fingerprint": context.semantic_dispatch_fingerprint},
                unknown_context_fields=("killer_identity",), victim_identity_evidence={"worker_identity": context.worker_identity, "victim_pid": context.victim_pid, "victim_process_start_identity": context.victim_process_start_identity},
                cause_kind="observed_dead_unknown", killer_kind="external_unknown", signal=None,
                positive_cgroup_delta=None, observed_at=datetime.now(timezone.utc).isoformat(), evidence={"already_dead": True},
            )
            return record_disposition(ledger, observed)
    if process_start_identity_fn is not None:
        try:
            observed_start = process_start_identity_fn(context.victim_pid)
        except TypeError:
            observed_start = process_start_identity_fn()
        if observed_start != context.victim_process_start_identity:
            observed = ObservedProcessDeath(
                observation_id=_digest(("incarnation-mismatch", context.admission_receipt_id, context.victim_pid, context.victim_process_start_identity, observed_start)),
                subject="worker", observation_source="worker-signal-preflight",
                known_context_fields={"plan_id": context.plan_id, "phase": context.phase, "admission_receipt_id": context.admission_receipt_id, "semantic_dispatch_fingerprint": context.semantic_dispatch_fingerprint},
                unknown_context_fields=("killer_identity",), victim_identity_evidence={"worker_identity": context.worker_identity, "victim_pid": context.victim_pid, "expected_process_start_identity": context.victim_process_start_identity, "observed_process_start_identity": observed_start},
                cause_kind="observed_dead_unknown", killer_kind="external_unknown", signal=None,
                positive_cgroup_delta=None, observed_at=datetime.now(timezone.utc).isoformat(), evidence={"incarnation_mismatch": True},
            )
            return record_disposition(ledger, observed)
    sustained = {"wedge", "stall", "idle", "timeout", "cgroup_oom"}
    if cause_kind in sustained and not confirmation_event_id:
        raise SignalDispositionError("sustained worker cause requires two-scan confirmation")
    if confirmation_event_id:
        confirmation = projection.get("confirmations", {}).get(confirmation_event_id)
        if not confirmation or not confirmation.get("consumed") or confirmation.get("expired") or confirmation.get("replaced"):
            raise SignalDispositionError("worker signal requires a consumed, live confirmation")
        for name, expected in (("victim_pid", context.victim_pid), ("victim_process_start_identity", context.victim_process_start_identity), ("admission_receipt_id", context.admission_receipt_id), ("semantic_dispatch_fingerprint", context.semantic_dispatch_fingerprint)):
            actual = confirmation.get(name)
            if actual is not None and actual != expected:
                raise SignalDispositionError(f"confirmation identity mismatch: {name}")
        consumed = next((r.get("payload", {}) for r in ledger.read_nbf_events() if r.get("payload", {}).get("event_type") == "supervision_confirmation_consumed" and r.get("payload", {}).get("confirmation_id") == confirmation_event_id), None)
        if consumed and consumed.get("disposition_id") not in (None, WorkerDisposition.deterministic_id(receipt=context.admission_receipt_id, signal=signal_label, ladder_step=ladder_step)):
            raise SignalDispositionError("confirmation is bound to another disposition")
    disposition = worker_disposition_for_signal(
        context,
        signal_name=signal_label,
        killer_kind=killer_kind,
        killer_identity=killer_identity,
        cause_kind=cause_kind,
        elapsed_s=elapsed_s,
        evidence=evidence,
        timeout_source=timeout_source,
        ladder_step=ladder_step,
        confirmation_event_id=confirmation_event_id,
    )
    marker = {"started_at": context.started_at}
    invoke = signal_fn or (lambda: os.kill(context.victim_pid, number))
    if terminal_outcome is None and reservation is not None:
        from arnold_pipelines.megaplan.orchestration.phase_result import DispatchOutcome
        terminal_outcome = DispatchOutcome(
            kind="worker_disposition", launch_state="accepted",
            plan_id=context.plan_id, phase=context.phase,
            dispatch_family_id=context.dispatch_family_id, logical_dispatch_id=context.logical_dispatch_id,
            admission_receipt_id=context.admission_receipt_id,
            semantic_dispatch_fingerprint=context.semantic_dispatch_fingerprint,
            selected_spec=context.selected_spec, worker_identity=context.worker_identity,
            started_at=marker.get("started_at") or context.started_at or disposition.observed_at,
            finished_at=marker.get("finished_at") or disposition.observed_at,
            disposition_id=disposition.disposition_id,
        )
    if terminal_kwargs is None and reservation is not None:
        terminal_kwargs = {
            "reservation_event_id": reservation.get("event_id"),
            "projection_key": reservation.get("projection_key"),
            "physical_door_id": reservation.get("physical_door_id", context.physical_door_id),
            "execution_context_identity": reservation.get("execution_context_identity", context.execution_context_identity),
            "primary_spec": reservation.get("primary_spec", context.selected_spec),
            "configured_fallback_chain_identity": reservation.get("configured_fallback_chain_identity", ""),
        }
    def final_identity_preflight(_records: list[dict[str, Any]]) -> None:
        if process_start_identity_fn is None:
            raise SignalDispositionError("worker signal requires process-start identity check")
        try:
            observed = process_start_identity_fn(context.victim_pid)
        except TypeError:
            observed = process_start_identity_fn()
        if observed != context.victim_process_start_identity:
            raise SignalDispositionError("worker process incarnation changed before signal")

    return record_before_signal(
        ledger, disposition, invoke,
        terminal_outcome=terminal_outcome if reservation is not None else None,
        terminal_kwargs=terminal_kwargs if reservation is not None else None,
        preflight=final_identity_preflight,
    )


def _worker_liveness(fn: Any, pid: int) -> bool:
    try:
        return bool(fn(pid))
    except TypeError:
        return bool(fn())


def _worker_identity_preflight(
    context: WorkerSignalContext,
    process_start_identity_fn: Any,
) -> Any:
    """Build the final incarnation fence for the locked signal door."""
    def preflight(_records: list[dict[str, Any]]) -> None:
        if process_start_identity_fn is None:
            raise SignalDispositionError(
                "worker signal requires process-start identity check"
            )
        try:
            observed = process_start_identity_fn(context.victim_pid)
        except TypeError:
            observed = process_start_identity_fn()
        if observed != context.victim_process_start_identity:
            raise SignalDispositionError(
                "worker process incarnation changed before signal"
            )

    return preflight


def _worker_observation(context: WorkerSignalContext, *, reason: str, observed: Any = None) -> ObservedProcessDeath:
    return ObservedProcessDeath(
        observation_id=_digest(("ladder-observed-death", context.admission_receipt_id, context.victim_pid, context.victim_process_start_identity, reason)),
        subject="worker", observation_source="worker-signal-ladder",
        known_context_fields={"plan_id": context.plan_id, "phase": context.phase, "admission_receipt_id": context.admission_receipt_id, "semantic_dispatch_fingerprint": context.semantic_dispatch_fingerprint},
        unknown_context_fields=("killer_identity",),
        victim_identity_evidence={"worker_identity": context.worker_identity, "victim_pid": context.victim_pid, "victim_process_start_identity": context.victim_process_start_identity},
        cause_kind="observed_dead_unknown", killer_kind="external_unknown", signal=None,
        positive_cgroup_delta=None, observed_at=datetime.now(timezone.utc).isoformat(),
        evidence={"reason": reason, "observed": observed if observed is not None else {}},
    )


def _ladder_terminal(ledger: IncidentLedger, context: WorkerSignalContext, disposition: WorkerDisposition, marker: dict[str, Any], reservation: dict[str, Any]) -> dict[str, Any]:
    """Project a terminal only for legacy reservations; canonical launches stay in OperationRun."""
    from arnold_pipelines.megaplan.orchestration.phase_result import DispatchOutcome
    outcome = DispatchOutcome(
        kind="worker_disposition", launch_state="accepted", plan_id=context.plan_id,
        phase=context.phase, dispatch_family_id=context.dispatch_family_id,
        logical_dispatch_id=context.logical_dispatch_id,
        admission_receipt_id=context.admission_receipt_id,
        semantic_dispatch_fingerprint=context.semantic_dispatch_fingerprint,
        selected_spec=context.selected_spec, worker_identity=context.worker_identity,
        started_at=marker.get("started_at") or context.started_at or disposition.observed_at,
        finished_at=marker.get("finished_at") or disposition.observed_at,
        disposition_id=disposition.disposition_id,
    )
    if not reservation:
        return outcome.to_dict()
    terminal = ledger.append_terminal_outcome(
        outcome=outcome, reservation_event_id=reservation.get("event_id"),
        projection_key=reservation.get("projection_key"),
        physical_door_id=reservation.get("physical_door_id", context.physical_door_id),
        execution_context_identity=reservation.get("execution_context_identity", context.execution_context_identity),
        primary_spec=reservation.get("primary_spec", context.selected_spec),
        configured_fallback_chain_identity=reservation.get("configured_fallback_chain_identity", ""),
    )
    return terminal.get("payload", terminal)


def _record_ladder_stage(ledger: IncidentLedger, disposition: WorkerDisposition, *, signal_label: str, signal_fn: Any, terminal: Any = None, terminal_kwargs: dict[str, Any] | None = None, preflight: Any = None) -> tuple[dict[str, Any], bool]:
    """Append a stage, signal it, then optionally append its final terminal."""
    had_claim = any(
        (item.get("payload") or {}).get("event_type") == "signal_claimed"
        and (item.get("payload") or {}).get("disposition_id") == disposition.disposition_id
        for item in ledger.read_nbf_events()
    )
    record = record_before_signal(
        ledger,
        disposition,
        signal_fn,
        preflight=preflight,
        actor="signal-ladder",
    )
    created = not had_claim
    if created and terminal is not None:
        if terminal_kwargs is None:
            raise SignalDispositionError("terminal kwargs are required")
        ledger.append_terminal_outcome(outcome=terminal, **terminal_kwargs)
    return record, created


def signal_worker_ladder(
    ledger: IncidentLedger,
    context: WorkerSignalContext,
    *,
    term_signal: int | str = "SIGTERM",
    kill_signal: int | str = "SIGKILL",
    killer_kind: str = "watchdog",
    killer_identity: str,
    cause_kind: str,
    confirmation_event_id: str | None = None,
    term_confirmation_event_id: str | None = None,
    kill_confirmation_event_id: str | None = None,
    term_signal_fn: Any = None,
    kill_signal_fn: Any = None,
    liveness_fn: Any = None,
    process_start_identity_fn: Any = None,
    wait_fn: Any = None,
    elapsed_s: float = 0.0,
    relevant_progress_identity: str | None = None,
    supervisor_incarnation_identity: str | None = None,
    container_identity: str | None = None,
) -> WorkerLadderResult:
    """Own a record-before-signal TERM → wait → KILL escalation.

    The function never manufactures a second scan: confirmation is supplied
    by the durable ``observe_confirmation``/``consume_confirmation`` helpers.
    Missing or invalid proof returns ``confirmation_pending`` without signal.
    """
    projection = ledger.projection()
    canonical_acceptance = _canonical_worker_acceptance(context)
    reservation = next((r for r in projection.get("reservations", {}).values() if r.get("admission_receipt_id") == context.admission_receipt_id), None)
    if not reservation and canonical_acceptance is None:
        raise SignalDispositionError("worker launch is not canonically accepted")
    marker = {"started_at": context.started_at}
    if reservation is not None and reservation.get("closed"):
        existing = [d for d in projection.get("dispositions", {}).values() if d.get("admission_receipt_id") == context.admission_receipt_id]
        terminal = next((t for t in projection.get("terminals", {}).values() if t.get("reservation_event_id") == reservation.get("event_id")), None)
        if terminal is not None:
            state = "already_dead" if any(d.get("ladder_step") == "term" for d in existing) and not any(d.get("ladder_step") == "kill" for d in existing) else "killed"
            return WorkerLadderResult(state, term_disposition=next((d for d in existing if d.get("ladder_step") == "term"), None), kill_disposition=next((d for d in existing if d.get("ladder_step") == "kill"), None), terminal_outcome=terminal)
        raise SignalDispositionError("worker receipt is not an active ledger reservation")
    # Exact worker identity and process incarnation are read from the
    # canonical process-session resource above.  No IncidentLedger marker is
    # consulted or accepted as launch authority.
    sustained = {"wedge", "stall", "idle", "timeout", "cgroup_oom"}
    # ``confirmation_event_id`` remains a compatibility alias for the TERM
    # proof only.  Escalation always needs a distinct later proof.
    term_confirmation_event_id = term_confirmation_event_id or confirmation_event_id
    term_confirmation = projection.get("confirmations", {}).get(term_confirmation_event_id) if term_confirmation_event_id else None
    if cause_kind in sustained and (not term_confirmation or not term_confirmation.get("consumed") or term_confirmation.get("expired") or term_confirmation.get("replaced")):
        return WorkerLadderResult("confirmation_pending", reason="valid separated confirmation is required")
    for name, expected in (("victim_pid", context.victim_pid), ("victim_process_start_identity", context.victim_process_start_identity), ("admission_receipt_id", context.admission_receipt_id), ("semantic_dispatch_fingerprint", context.semantic_dispatch_fingerprint), ("relevant_progress_identity", relevant_progress_identity), ("supervisor_incarnation_identity", supervisor_incarnation_identity), ("container_identity", container_identity)):
        if term_confirmation and term_confirmation.get(name) is not None and term_confirmation.get(name) != expected:
            return WorkerLadderResult("confirmation_pending", reason=f"confirmation identity mismatch: {name}")
    def normalize(value: int | str) -> tuple[int, str]:
        number = getattr(value, "value", value)
        if isinstance(number, str):
            number = getattr(_signal, number, None)
        if not isinstance(number, int):
            raise SignalDispositionError(f"unknown signal {value!r}")
        return number, _signal.Signals(number).name
    term_number, term_label = normalize(term_signal)
    kill_number, kill_label = normalize(kill_signal)
    if cause_kind in sustained and term_confirmation is not None:
        if term_confirmation.get("ladder_stage") != "term" or term_confirmation.get("signal_identity") != term_label:
            return WorkerLadderResult("confirmation_pending", reason="TERM confirmation stage/signal mismatch")
    term_disp = worker_disposition_for_signal(context, signal_name=term_label, killer_kind=killer_kind, killer_identity=killer_identity, cause_kind=cause_kind, elapsed_s=elapsed_s, ladder_step="term", confirmation_event_id=term_confirmation_event_id)
    term_record = {"payload": projection.get("dispositions", {}).get(term_disp.disposition_id)} if term_disp.disposition_id in projection.get("dispositions", {}) else None
    term_claimed = any(r.get("payload", {}).get("event_type") == "signal_claimed" and r.get("payload", {}).get("disposition_id") == term_disp.disposition_id for r in ledger.read_nbf_events())
    term_dead = [False]
    def invoke_term() -> None:
        try:
            (term_signal_fn or (lambda: os.kill(context.victim_pid, term_number)))()
        except (ProcessLookupError, ChildProcessError):
            term_dead[0] = True
    identity_preflight = _worker_identity_preflight(
        context, process_start_identity_fn
    )
    if term_record is None:
        try:
            term_record, _created = _record_ladder_stage(
                ledger, term_disp, signal_label=term_label,
                signal_fn=invoke_term, preflight=identity_preflight,
            )
        except SignalDispositionError as exc:
            raise SignalDispositionError(f"TERM failure: {exc}") from exc
    elif not term_claimed:
        # Crash/restart recovery: a durable disposition without its claim is
        # not evidence that TERM was physically sent.  Claim and send exactly
        # once before considering liveness or escalation.
        try:
            _record_ladder_stage(
                ledger, term_disp, signal_label=term_label,
                signal_fn=invoke_term, preflight=identity_preflight,
            )
        except Exception as exc:
            return WorkerLadderResult("unresolved", term_disposition=term_record, reason=f"TERM claim failed: {exc}")
    if wait_fn is not None:
        wait_fn()
    if liveness_fn is None:
        raise SignalDispositionError("ladder requires same-incarnation liveness check")
    try:
        alive = False if term_dead[0] else _worker_liveness(liveness_fn, context.victim_pid)
    except (ProcessLookupError, ChildProcessError):
        alive = False
    if not alive:
        observation = _worker_observation(context, reason="already-dead-after-term")
        observation_record = record_disposition(ledger, observation)
        try:
            terminal = _ladder_terminal(ledger, context, term_disp, marker, reservation)
        except Exception as exc:
            return WorkerLadderResult("unresolved", term_disposition=term_record, observation=observation_record, reason=f"terminal append failed: {exc}")
        return WorkerLadderResult("already_dead", term_disposition=term_record, terminal_outcome=terminal, observation=observation_record)
    if cause_kind in sustained:
        # A KILL proof must be a different durable confirmation and must have
        # been consumed after the TERM claim.  This prevents a stale first
        # scan, progress reset, restart, or PID reincarnation from authorizing
        # escalation.
        if not kill_confirmation_event_id or kill_confirmation_event_id == term_confirmation_event_id:
            return WorkerLadderResult("confirmation_pending", term_disposition=term_record, reason="distinct later KILL confirmation is required")
        projection = ledger.projection()
        kill_confirmation = projection.get("confirmations", {}).get(kill_confirmation_event_id)
        if not kill_confirmation or not kill_confirmation.get("consumed") or kill_confirmation.get("expired") or kill_confirmation.get("replaced"):
            return WorkerLadderResult("confirmation_pending", term_disposition=term_record, reason="distinct later KILL confirmation is required")
        if kill_confirmation.get("ladder_stage") != "kill" or kill_confirmation.get("signal_identity") != kill_label:
            return WorkerLadderResult("confirmation_pending", term_disposition=term_record, reason="KILL confirmation stage/signal mismatch")
        for name, expected in (("victim_pid", context.victim_pid), ("victim_process_start_identity", context.victim_process_start_identity), ("admission_receipt_id", context.admission_receipt_id), ("semantic_dispatch_fingerprint", context.semantic_dispatch_fingerprint), ("relevant_progress_identity", relevant_progress_identity), ("supervisor_incarnation_identity", supervisor_incarnation_identity), ("container_identity", container_identity)):
            if kill_confirmation.get(name) is not None and kill_confirmation.get(name) != expected:
                return WorkerLadderResult("confirmation_pending", term_disposition=term_record, reason=f"KILL confirmation identity mismatch: {name}")
        term_claim_seq = next((int(r.get("seq", 0)) for r in ledger.read_nbf_events() if r.get("payload", {}).get("event_type") == "signal_claimed" and r.get("payload", {}).get("disposition_id") == term_disp.disposition_id), 0)
        kill_consumed_seq = next((int(r.get("seq", 0)) for r in ledger.read_nbf_events() if r.get("payload", {}).get("event_type") == "supervision_confirmation_consumed" and r.get("payload", {}).get("confirmation_id") == kill_confirmation_event_id), 0)
        if not term_claim_seq or not kill_consumed_seq or kill_consumed_seq <= term_claim_seq:
            return WorkerLadderResult("confirmation_pending", term_disposition=term_record, reason="KILL confirmation was not consumed after TERM")
    if process_start_identity_fn is None:
        raise SignalDispositionError("ladder requires same-incarnation process identity check")
    try:
        current_start = process_start_identity_fn(context.victim_pid)
    except TypeError:
        current_start = process_start_identity_fn()
    if current_start != context.victim_process_start_identity:
        observation = _worker_observation(context, reason="pid-reuse", observed={"observed_process_start_identity": current_start})
        observation_record = record_disposition(ledger, observation)
        return WorkerLadderResult("already_dead", term_disposition=term_record, observation=observation_record, reason="process incarnation changed")
    kill_disp = worker_disposition_for_signal(context, signal_name=kill_label, killer_kind=killer_kind, killer_identity=killer_identity, cause_kind=cause_kind, elapsed_s=elapsed_s, ladder_step="kill", confirmation_event_id=kill_confirmation_event_id or term_confirmation_event_id)
    kill_number = kill_number
    kill_record = {"payload": projection.get("dispositions", {}).get(kill_disp.disposition_id)} if kill_disp.disposition_id in projection.get("dispositions", {}) else None
    # Commit the KILL disposition and claim before the physical signal, but do
    # not close the reservation until the callback returns.  A persisted claim
    # without a terminal is an unresolved crash/failure cutpoint: never resend
    # KILL and never infer that it succeeded.
    try:
        if kill_record is None:
            kill_record = record_disposition(ledger, kill_disp)
        terminal = next((r.get("payload") for r in ledger.read_nbf_events() if r.get("payload", {}).get("event_type") == "worker_terminal_outcome" and r.get("payload", {}).get("disposition_id") == kill_disp.disposition_id), None)
        claimed = any(r.get("payload", {}).get("event_type") == "signal_claimed" and r.get("payload", {}).get("disposition_id") == kill_disp.disposition_id for r in ledger.read_nbf_events())
        if not claimed:
            kill_dead = [False]
            def invoke_kill() -> None:
                try:
                    (kill_signal_fn or (lambda: os.kill(context.victim_pid, kill_number)))()
                except (ProcessLookupError, ChildProcessError):
                    kill_dead[0] = True
                    raise
            record_before_signal(
                ledger, kill_disp, invoke_kill, preflight=identity_preflight,
                actor="signal-ladder",
            )
            if kill_dead[0]:
                observation = _worker_observation(context, reason="already-dead-during-kill")
                observation_record = record_disposition(ledger, observation)
                try:
                    terminal = _ladder_terminal(ledger, context, kill_disp, marker, reservation)
                except Exception as exc:
                    return WorkerLadderResult("unresolved", term_disposition=term_record, kill_disposition=kill_record, observation=observation_record, reason=f"terminal append failed after already-dead KILL: {exc}")
                return WorkerLadderResult("already_dead", term_disposition=term_record, kill_disposition=kill_record, terminal_outcome=terminal, observation=observation_record)
            try:
                terminal = _ladder_terminal(ledger, context, kill_disp, marker, reservation)
            except Exception as exc:
                return WorkerLadderResult("unresolved", term_disposition=term_record, kill_disposition=kill_record, reason=f"terminal append failed after KILL: {exc}")
        elif terminal is None:
            # A crash can leave the durable KILL claim after the physical
            # callback but before terminal projection.  Never resend from that
            # claim.  Instead, re-check current liveness: a confirmed-dead
            # victim can now be linked to the existing KILL disposition; a
            # still-live or unobservable victim remains explicitly unresolved
            # for a later reconciliation pass.
            try:
                replay_alive = _worker_liveness(liveness_fn, context.victim_pid)
            except (ProcessLookupError, ChildProcessError):
                replay_alive = False
            if replay_alive:
                return WorkerLadderResult("unresolved", term_disposition=term_record, kill_disposition=kill_record, reason="KILL signal claim exists without terminal outcome; victim remains live")
            observation = _worker_observation(context, reason="already-dead-during-kill-replay")
            observation_record = None
            try:
                observation_record = record_disposition(ledger, observation)
                terminal = _ladder_terminal(ledger, context, kill_disp, marker, reservation)
            except Exception as exc:
                return WorkerLadderResult("unresolved", term_disposition=term_record, kill_disposition=kill_record, observation=observation_record, reason=f"terminal append failed during KILL replay: {exc}")
            return WorkerLadderResult("already_dead", term_disposition=term_record, kill_disposition=kill_record, terminal_outcome=terminal, observation=observation_record)
    except Exception as exc:
        return WorkerLadderResult("unresolved", term_disposition=term_record, kill_disposition=kill_record, reason=f"KILL prerequisite failed: {exc}")
    return WorkerLadderResult("killed", term_disposition=term_record, kill_disposition=kill_record, terminal_outcome=terminal)


def signal_process_group(
    pid: int,
    signal_name: int,
    *,
    ledger: IncidentLedger | None = None,
    context: WorkerSignalContext | None = None,
    killer_kind: str = "resident_supervisor",
    killer_identity: str | None = None,
    cause_kind: str = "terminate",
    ladder_step: str | None = None,
    elapsed_s: float = 0.0,
    evidence: Any = None,
    final_signal: bool = False,
) -> bool:
    """Signal a process group through the disposition door when admitted.

    The no-context branch is retained for generic/non-worker process groups;
    managed callers must provide both ``ledger`` and ``context`` and therefore
    cannot accidentally signal an unbound PID.
    """
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise SignalDispositionError("process-group PID is invalid")
    if context is not None or ledger is not None:
        if context is None or ledger is None:
            raise SignalDispositionError("worker group signal requires context and ledger")
        signal_worker(
            ledger, context, signal_name=signal_name, killer_kind=killer_kind,
            killer_identity=killer_identity or f"supervisor:{os.getpid()}",
            cause_kind=cause_kind, ladder_step=ladder_step,
            elapsed_s=elapsed_s, evidence=evidence,
            final_signal=final_signal,
            signal_fn=lambda: os.killpg(pid, signal_name),
        )
        return True
    try:
        os.killpg(pid, signal_name)
    except ProcessLookupError:
        return False
    return True


def signal_process(pid: int, signal_name: int, *, signal_fn: Any = None) -> bool:
    """Minimal probe-safe primitive used by non-worker resident lifecycle code.

    Worker callers use :func:`signal_worker`; this function exists so the
    repository's generic process-control paths have one explicit, stub-able
    primitive and do not scatter direct ``os.kill`` calls.
    """
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise SignalDispositionError("process PID is invalid")
    try:
        (signal_fn or (lambda: os.kill(pid, signal_name)))()
    except ProcessLookupError:
        return False
    return True


def signal_non_worker(
    ledger: IncidentLedger,
    disposition: NonWorkerSignalDisposition,
    *,
    signal_fn: Any,
    preflight: Any = None,
) -> dict[str, Any]:
    """Record a lifecycle signal before invoking its primitive."""
    if preflight is not None:
        return ledger.record_claim_signal_locked(
            disposition, signal=_signal_name(disposition), signal_fn=signal_fn,
            preflight=preflight,
        )
    return record_before_signal(ledger, disposition, signal_fn)


def recover_worker_disposition_outcome(
    ledger: IncidentLedger,
    disposition_id: str,
    *,
    started_at: str,
    finished_at: str,
    terminal_outcome_event_id: str | None = None,
) -> Any:
    """Recover one typed ``DispatchOutcome`` from an existing disposition.

    Recovery reads the canonical ledger projection and never appends or
    coerces evidence.  This is the crash-after-signal/before-terminal seam.
    """
    from arnold_pipelines.megaplan.orchestration.phase_result import DispatchOutcome
    payload = ledger.projection().get("dispositions", {}).get(disposition_id)
    if not isinstance(payload, dict) or payload.get("event_type") != "worker_disposition":
        raise SignalDispositionError("worker disposition is not committed")
    required = ("plan_id", "phase", "dispatch_family_id", "logical_dispatch_id",
                "admission_receipt_id", "semantic_dispatch_fingerprint", "selected_spec",
                "worker_identity")
    if any(payload.get(name) in (None, "") for name in required):
        raise SignalDispositionError("committed worker disposition is incomplete")
    return DispatchOutcome(
        kind="worker_disposition", launch_state="accepted",
        plan_id=payload["plan_id"], phase=payload["phase"],
        dispatch_family_id=payload["dispatch_family_id"],
        logical_dispatch_id=payload["logical_dispatch_id"],
        admission_receipt_id=payload["admission_receipt_id"],
        semantic_dispatch_fingerprint=payload["semantic_dispatch_fingerprint"],
        selected_spec=payload["selected_spec"], worker_identity=payload["worker_identity"],
        started_at=started_at, finished_at=finished_at,
        disposition_id=disposition_id,
        terminal_outcome_event_id=terminal_outcome_event_id,
    )


def observe_confirmation(ledger: IncidentLedger, *, site_id: str, subject_class: str, plan_id: str | None, admission_receipt_id: str | None, victim_pid: int, victim_process_start_identity: str, relevant_progress_identity: str, supervisor_incarnation_identity: str, cause_kind: str, scan_interval_s: float, confirmation_policy_identity: str = "default-v1", observed_at: str | None = None, evidence: Any = None, actor: str = "supervisor", semantic_dispatch_fingerprint: str | None = None, container_identity: str | None = None, ladder_stage: str | None = None, signal_identity: str | None = None) -> dict[str, Any]:
    if not isinstance(victim_pid, int) or isinstance(victim_pid, bool) or victim_pid <= 0:
        raise ValueError("victim_pid must be positive")
    ttl = confirmation_ttl_s(scan_interval_s)
    observed = observed_at or datetime.now(timezone.utc).isoformat()
    # ISO strings are compared by callers; timestamps are persisted verbatim
    # to preserve external clock evidence.
    try:
        first = datetime.fromisoformat(observed.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("observed_at must be ISO-8601") from exc
    if ladder_stage is not None and ladder_stage not in {"term", "kill"}:
        raise ValueError("ladder_stage must be term or kill")
    if ladder_stage is not None and not signal_identity:
        raise ValueError("ladder confirmation requires signal_identity")
    cid = confirmation_id(site_id=site_id, subject_class=subject_class, victim_pid=victim_pid, victim_process_start_identity=victim_process_start_identity, relevant_progress_identity=relevant_progress_identity, supervisor_incarnation_identity=supervisor_incarnation_identity, cause_kind=cause_kind, semantic_dispatch_fingerprint=semantic_dispatch_fingerprint, container_identity=container_identity, ladder_stage=ladder_stage, signal_identity=signal_identity)
    payload = {"schema_version": 1, "event_type": "supervision_confirmation_observed", "event_id": _digest(("observed", cid, observed)), "confirmation_id": cid, "site_id": site_id, "subject_class": subject_class, "plan_id": plan_id, "admission_receipt_id": admission_receipt_id, "victim_pid": victim_pid, "victim_process_start_identity": victim_process_start_identity, "relevant_progress_identity": relevant_progress_identity, "supervisor_incarnation_identity": supervisor_incarnation_identity, "cause_kind": cause_kind, "scan_interval_s": scan_interval_s, "confirmation_policy_identity": confirmation_policy_identity, "first_observed_at": observed, "expires_at": (first.timestamp() + ttl), "evidence_digest": _digest(evidence if evidence is not None else {}), "recorded_at": datetime.now(timezone.utc).isoformat(), "actor": actor}
    if semantic_dispatch_fingerprint is not None:
        payload["semantic_dispatch_fingerprint"] = semantic_dispatch_fingerprint
    if container_identity is not None:
        payload["container_identity"] = container_identity
    if ladder_stage is not None:
        payload["ladder_stage"] = ladder_stage
        payload["signal_identity"] = signal_identity
    return ledger.observe_confirmation(payload)


def consume_confirmation(ledger: IncidentLedger, *, confirmation_id_value: str, second_observed_at: str, second_evidence: Any, actor: str = "supervisor", disposition_id: str | None = None, victim_pid: int | None = None, victim_process_start_identity: str | None = None, relevant_progress_identity: str | None = None, supervisor_incarnation_identity: str | None = None, cause_kind: str | None = None, scan_interval_s: float | None = None, expires_at: float | None = None, confirmation_policy_identity: str | None = None, schema_version: int | None = None, semantic_dispatch_fingerprint: str | None = None, container_identity: str | None = None, ladder_stage: str | None = None, signal_identity: str | None = None) -> dict[str, Any]:
    """Consume proof only when every second-scan identity is supplied."""
    required = {
        "victim_pid": victim_pid,
        "victim_process_start_identity": victim_process_start_identity,
        "relevant_progress_identity": relevant_progress_identity,
        "supervisor_incarnation_identity": supervisor_incarnation_identity,
        "cause_kind": cause_kind,
        "scan_interval_s": scan_interval_s,
        "expires_at": expires_at,
        "confirmation_policy_identity": confirmation_policy_identity,
        "schema_version": schema_version,
    }
    if any(value is None for value in required.values()):
        raise ValueError("confirmation identity is mandatory for the second scan")
    return ledger.consume_confirmation(
        confirmation_id=confirmation_id_value,
        second_observed_at=second_observed_at,
        second_evidence_digest=_digest(second_evidence),
        victim_pid=victim_pid,
        victim_process_start_identity=victim_process_start_identity,
        relevant_progress_identity=relevant_progress_identity,
        supervisor_incarnation_identity=supervisor_incarnation_identity,
        cause_kind=cause_kind,
        scan_interval_s=scan_interval_s,
        expires_at=expires_at,
        confirmation_policy_identity=confirmation_policy_identity,
        schema_version=schema_version,
        semantic_dispatch_fingerprint=semantic_dispatch_fingerprint,
        container_identity=container_identity,
        ladder_stage=ladder_stage,
        signal_identity=signal_identity,
        disposition_id=disposition_id,
        actor=actor,
    )


def _record_cli(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="python -m arnold_pipelines.megaplan.incident.disposition record")
    parser.add_argument("record", choices=("record", "signal-non-worker", "resolve-signal-context"))
    parser.add_argument("--ledger-root", required=True)
    parser.add_argument("--marker-dir", default="/workspace/.megaplan/cloud-sessions")
    parser.add_argument("--json-stdin", action="store_true", required=True)
    args = parser.parse_args(argv)
    try:
        raw = sys.stdin.buffer.read()
        if not raw.strip() or not raw.decode("utf-8"):
            raise ValueError("stdin must contain one UTF-8 JSON object")
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("stdin must contain one JSON object")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"disposition schema error: {exc}", file=sys.stderr)
        return 2
    try:
        ledger_root = __import__("pathlib").Path(args.ledger_root)
        if not ledger_root.exists() or not ledger_root.is_dir():
            raise ValueError("ledger root must be an existing directory")
        ledger = IncidentLedger(ledger_root)
    except (OSError, ValueError) as exc:
        print(f"invalid ledger location: {exc}", file=sys.stderr)
        return 4
    # The lifecycle bridge has its own compact request envelope rather than
    # an NBF event.  Keep it behind the same durable ledger-location gate but
    # before event-schema validation.
    if args.record in {"signal-non-worker", "resolve-signal-context"}:
        payload.setdefault("marker_dir", args.marker_dir)
        if args.record == "resolve-signal-context":
            from arnold_pipelines.megaplan.incident.authority import SignalAuthorityError, resolve_signal_authority
            try:
                target_kind = payload.get("target_kind")
                context = resolve_signal_authority(
                    site_id=payload["site_id"], session=payload["session"],
                    marker_path=__import__("pathlib").Path(payload["marker_path"]),
                    target_kind=target_kind,
                    victim_pid=int(payload["victim_pid"]),
                    marker_dir=__import__("pathlib").Path(payload["marker_dir"]),
                    victim_process_start_identity=payload.get("victim_process_start_identity"),
                    bootstrap_manifest_path=__import__("pathlib").Path(payload["bootstrap_manifest_path"]) if payload.get("bootstrap_manifest_path") else None,
                )
                if __import__("pathlib").Path(args.ledger_root).resolve() != __import__("pathlib").Path(context.ledger_root):
                    raise SignalAuthorityError("CLI ledger root does not match marker-bound ledger")
            except (SignalAuthorityError, KeyError, TypeError, ValueError) as exc:
                print(f"signal authority rejected: {exc}", file=sys.stderr)
                return 5
            print(json.dumps(context.to_dict(), sort_keys=True, separators=(",", ":")))
            return 0
        return _signal_non_worker_cli(ledger, payload)
    try:
        # Schema is always the first semantic gate.  This prevents malformed
        # worker payloads from being reclassified as a missing confirmation.
        validate_nbf_event(payload)
    except ValueError as exc:
        print(f"disposition schema error: {exc}", file=sys.stderr)
        return 2
    try:
        # A CLI worker disposition is a sustained-proof consumer.  Confirmation
        # lookup is read-only here; append_disposition rechecks it under the
        # ledger lock before committing the disposition.
        if payload.get("event_type") == "worker_disposition" and not payload.get("confirmation_event_id"):
            print("required confirmation missing", file=sys.stderr)
            return 5
        confirmation_ref = payload.get("confirmation_event_id")
        if confirmation_ref:
            confirmation = ledger.projection().get("confirmations", {}).get(confirmation_ref)
            if not confirmation or not confirmation.get("consumed") or confirmation.get("expired") or confirmation.get("replaced"):
                print("required confirmation missing or not consumed", file=sys.stderr)
                return 5
            if payload.get("event_type") == "worker_disposition":
                evidence = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
                identity_pairs = (
                    ("admission_receipt_id", payload.get("admission_receipt_id")),
                    ("victim_pid", payload.get("victim_pid")),
                    ("victim_process_start_identity", payload.get("victim_process_start_identity")),
                    ("cause_kind", payload.get("cause_kind")),
                    ("relevant_progress_identity", payload.get("relevant_progress_identity", evidence.get("relevant_progress_identity"))),
                    ("supervisor_incarnation_identity", payload.get("supervisor_incarnation_identity", evidence.get("supervisor_incarnation_identity"))),
                )
                if any(value is None or confirmation.get(name) != value for name, value in identity_pairs if name in confirmation):
                    print("required confirmation identity mismatch", file=sys.stderr)
                    return 5
                consumed = next((r.get("payload", {}) for r in ledger.read_nbf_events() if r.get("payload", {}).get("event_type") == "supervision_confirmation_consumed" and r.get("payload", {}).get("confirmation_id") == confirmation_ref), None)
                # A consumed proof is single-use.  The sole successful CLI
                # consumer must be the disposition it was bound to; an
                # unbound or differently bound replay is status 5.
                if not consumed or consumed.get("disposition_id") != payload.get("disposition_id"):
                    print("required confirmation disposition mismatch", file=sys.stderr)
                    return 5
                if any(r.get("payload", {}).get("event_type") == "worker_disposition"
                       and r.get("payload", {}).get("disposition_id") == payload.get("disposition_id")
                       for r in ledger.read_nbf_events()):
                    print("disposition replay already consumed", file=sys.stderr)
                    return 5
        record = ledger.append_disposition(payload)
    except OSError as exc:
        print(f"ledger append failure: {exc}", file=sys.stderr)
        return 3
    except ValueError as exc:
        # At this point payload validation already succeeded.  A ValueError is
        # therefore a durable ledger/context failure, not malformed input.
        message = str(exc)
        if "confirmation" in message:
            print(f"required confirmation unavailable: {exc}", file=sys.stderr)
            return 5
        print(f"ledger append failure: {exc}", file=sys.stderr)
        return 3
    record_payload = record.get("payload", {})
    record_identity = record_payload.get("event_id") or record_payload.get("disposition_id") or record_payload.get("observation_id")
    out = {"disposition_id": payload.get("disposition_id") or payload.get("observation_id"), "ledger_event_id": record_identity, "record_id": record_identity}
    print(json.dumps(out, sort_keys=True, separators=(",", ":")))
    return 0


def _signal_non_worker_cli(ledger: IncidentLedger, payload: dict[str, Any]) -> int:
    """Record and signal one identity-bound lifecycle process.

    Shell supervisors use this single canonical door.  When ``require_confirmation``
    is true, the first invocation persists an observation and returns 75; the
    next matching invocation consumes that durable proof and only then reaches
    ``signal_non_worker``.  A consumed confirmation is replay-only and never
    resends the signal.
    """
    from arnold_pipelines.megaplan.watchdog.worker_identity import read_process_start_identity
    from arnold_pipelines.megaplan.incident.authority import (
        SignalAuthorityError,
        revalidate_signal_payload,
    )

    # The CLI is a fresh authority boundary.  Do not trust the shell's
    # projected lifecycle/progress strings (or its ledger path) as identity;
    # reload the explicit session marker and immutable bootstrap manifest and
    # bind the request to their current bytes before any ledger projection is
    # read.  Missing legacy context is intentionally rejected.
    marker_dir = __import__("pathlib").Path(payload.get("marker_dir") or "/workspace/.megaplan/cloud-sessions")
    try:
        # Hold the same ledger lock used by the NBF projection while resolving
        # the marker/manifest.  This makes a concurrent reservation or source
        # replacement fail closed instead of being paired with a stale view.
        with ledger._locked():
            try:
                authority = revalidate_signal_payload(payload, marker_dir=marker_dir, ledger_root=ledger._root)
            except SignalAuthorityError as initial_error:
                # A process that was already killed is admissible only for an
                # exact replay of a durable prior disposition.  Resolve the
                # marker/manifest in missing-target mode solely to compute the
                # canonical identity, then require that disposition before
                # allowing the normal replay path below.
                if "victim process identity" not in str(initial_error):
                    raise
                authority = revalidate_signal_payload(
                    payload, marker_dir=marker_dir, ledger_root=ledger._root,
                    allow_missing_target=True,
                )
                replay_signal = str(payload.get("signal") or "")
                replay_id = _digest({
                    "schema_version": 1, "site_id": authority.site_id,
                    "lifecycle_identity": authority.lifecycle_identity,
                    "victim_pid": authority.victim_pid,
                    "victim_process_start_identity": authority.victim_process_start_identity,
                    "signal": replay_signal,
                    "ladder_stage": payload.get("ladder_stage"),
                })
                records = ledger.read_nbf_events()
                matching_dispositions = [
                    (record.get("payload") or {}) for record in records
                    if (record.get("payload") or {}).get("event_type") == "non_worker_signal_disposition"
                    and (record.get("payload") or {}).get("disposition_id") == replay_id
                ]
                has_disposition = any(
                    item.get("signal") == replay_signal
                    and item.get("lifecycle_identity") == authority.lifecycle_identity
                    and item.get("victim_pid_or_group") == str(authority.victim_pid)
                    and item.get("victim_process_start_identity") == authority.victim_process_start_identity
                    for item in matching_dispositions
                )
                has_claim = any(
                    (record.get("payload") or {}).get("event_type") == "signal_claimed"
                    and (record.get("payload") or {}).get("disposition_id") == replay_id
                    and (record.get("payload") or {}).get("signal") == replay_signal
                    for record in records
                )
                if not (has_disposition and has_claim):
                    raise initial_error
    except (SignalAuthorityError, TypeError, ValueError) as exc:
        print(f"non-worker signal authority rejected: {exc}", file=sys.stderr)
        return 5
    if authority.target_kind != "non_worker":
        print("signal-non-worker requires a non-worker authority context", file=sys.stderr)
        return 5
    # Canonical values are derived, never caller-selected.  Retain the
    # original payload only for evidence/reason fields and the signal ladder.
    payload = dict(payload)
    payload.update({
        "site_id": authority.site_id,
        "lifecycle_identity": authority.lifecycle_identity,
        "relevant_progress_identity": authority.relevant_progress_identity,
        "supervisor_incarnation_identity": authority.supervisor_incarnation_identity,
        "victim_pid": authority.victim_pid,
        "victim_process_start_identity": authority.victim_process_start_identity,
        "ledger_root": authority.ledger_root,
    })

    required = (
        "site_id", "lifecycle_identity", "killer_identity", "victim_pid",
        "victim_process_start_identity", "signal", "scan_interval_s",
        "relevant_progress_identity", "supervisor_incarnation_identity",
    )
    if any(key not in payload for key in required):
        print("non-worker signal context is incomplete", file=sys.stderr)
        return 5
    if any(
        not isinstance(payload.get(key), str) or not payload.get(key)
        for key in (
            "site_id", "lifecycle_identity", "killer_identity",
            "relevant_progress_identity", "supervisor_incarnation_identity",
        )
    ):
        print("non-worker signal context is incomplete", file=sys.stderr)
        return 5
    try:
        pid = int(payload["victim_pid"])
    except (TypeError, ValueError):
        print("non-worker victim PID is invalid", file=sys.stderr)
        return 5
    if pid <= 0 or not isinstance(payload.get("victim_process_start_identity"), str) or not payload["victim_process_start_identity"]:
        print("non-worker process identity is incomplete", file=sys.stderr)
        return 5
    signal_name = str(payload.get("signal") or "")
    if signal_name not in {"SIGINT", "SIGTERM", "SIGKILL"}:
        print("non-worker signal is invalid", file=sys.stderr)
        return 2
    try:
        scan_interval = float(payload["scan_interval_s"])
    except (TypeError, ValueError):
        print("non-worker scan interval is invalid", file=sys.stderr)
        return 5
    if scan_interval <= 0:
        print("non-worker scan interval must be positive", file=sys.stderr)
        return 5

    expected_start = str(payload["victim_process_start_identity"])
    try:
        observed_start = read_process_start_identity(pid)
    except Exception:
        observed_start = None
    if observed_start != expected_start:
        # A successful signal may have completed before a supervisor restart;
        # replay must be idempotent even though the victim is now gone.  Only
        # an exact durable disposition identity qualifies—missing/stale
        # context still fails closed below.
        replay_id = _digest({
            "schema_version": 1,
            "site_id": str(payload["site_id"]),
            "lifecycle_identity": str(payload["lifecycle_identity"]),
            "victim_pid": pid,
            "victim_process_start_identity": expected_start,
            "signal": signal_name,
            "ladder_stage": payload.get("ladder_stage"),
        })
        records = ledger.read_nbf_events()
        matching_dispositions = [
            (record.get("payload") or {}) for record in records
            if (record.get("payload") or {}).get("event_type") == "non_worker_signal_disposition"
            and (record.get("payload") or {}).get("disposition_id") == replay_id
        ]
        has_disposition = any(
            item.get("signal") == signal_name
            and item.get("lifecycle_identity") == str(payload["lifecycle_identity"])
            and item.get("victim_pid_or_group") == str(pid)
            and item.get("victim_process_start_identity") == expected_start
            for item in matching_dispositions
        )
        has_claim = any(
            (record.get("payload") or {}).get("event_type") == "signal_claimed"
            and (record.get("payload") or {}).get("disposition_id") == replay_id
            and (record.get("payload") or {}).get("signal") == signal_name
            for record in records
        )
        if has_disposition and has_claim:
            print(json.dumps({"replayed": True, "disposition_id": replay_id}, separators=(",", ":")))
            return 0
        print("non-worker process identity is missing or stale", file=sys.stderr)
        return 5

    ladder_stage = payload.get("ladder_stage")
    signal_identity = signal_name
    confirmation_required = bool(payload.get("require_confirmation", True))
    # Non-worker lifecycle dispositions intentionally use the fixed lifecycle
    # cause enum.  More specific shell reason/stall data remains evidence and
    # cannot widen the schema into an untyped second authority.
    disposition_id = _digest({
        "schema_version": 1,
        "site_id": str(payload["site_id"]),
        "lifecycle_identity": str(payload["lifecycle_identity"]),
        "victim_pid": pid,
        "victim_process_start_identity": expected_start,
        "signal": signal_name,
        "ladder_stage": ladder_stage,
    })
    confirmation_id_value = confirmation_id(
        site_id=str(payload["site_id"]),
        subject_class="non_worker_lifecycle",
        victim_pid=pid,
        victim_process_start_identity=expected_start,
        relevant_progress_identity=str(payload.get("relevant_progress_identity") or ""),
        supervisor_incarnation_identity=str(payload.get("supervisor_incarnation_identity") or ""),
        cause_kind="lifecycle_shutdown",
        semantic_dispatch_fingerprint=payload.get("semantic_dispatch_fingerprint"),
        container_identity=payload.get("container_identity"),
        ladder_stage=str(ladder_stage) if ladder_stage is not None else None,
        signal_identity=signal_identity if ladder_stage is not None else None,
    )
    confirmation = ledger.projection().get("confirmations", {}).get(confirmation_id_value)
    if confirmation_required:
        if confirmation is None:
            try:
                observe_confirmation(
                    ledger,
                    site_id=str(payload["site_id"]),
                    subject_class="non_worker_lifecycle",
                    plan_id=payload.get("plan_id"),
                    admission_receipt_id=payload.get("admission_receipt_id"),
                    victim_pid=pid,
                    victim_process_start_identity=expected_start,
                    relevant_progress_identity=str(payload.get("relevant_progress_identity") or ""),
                    supervisor_incarnation_identity=str(payload.get("supervisor_incarnation_identity") or ""),
                    cause_kind="lifecycle_shutdown",
                    scan_interval_s=scan_interval,
                    confirmation_policy_identity=str(payload.get("confirmation_policy_identity") or "shell-nbf05-v1"),
                    evidence=payload.get("evidence") or {},
                    actor=str(payload["killer_identity"]),
                    semantic_dispatch_fingerprint=payload.get("semantic_dispatch_fingerprint"),
                    container_identity=payload.get("container_identity"),
                    ladder_stage=str(ladder_stage) if ladder_stage is not None else None,
                    signal_identity=signal_identity if ladder_stage is not None else None,
                )
            except Exception as exc:
                print(f"non-worker confirmation append failed: {exc}", file=sys.stderr)
                return 3
            print("confirmation_pending", file=sys.stderr)
            return 75
        if confirmation.get("consumed") or confirmation.get("expired") or confirmation.get("replaced"):
            if confirmation.get("consumed"):
                prior = next(
                    (record for record in ledger.read_nbf_events()
                     if record.get("payload", {}).get("event_type") == "non_worker_signal_disposition"
                     and record.get("payload", {}).get("disposition_id") == disposition_id),
                    None,
                )
                if prior is not None:
                    print(json.dumps({"replayed": True, "disposition_id": disposition_id}, separators=(",", ":")))
                    return 0
            print("non-worker confirmation is stale or already consumed", file=sys.stderr)
            return 5
        try:
            consume_confirmation(
                ledger,
                confirmation_id_value=confirmation_id_value,
                second_observed_at=datetime.now(timezone.utc).isoformat(),
                second_evidence=payload.get("evidence") or {},
                actor=str(payload["killer_identity"]),
                disposition_id=disposition_id,
                victim_pid=pid,
                victim_process_start_identity=expected_start,
                relevant_progress_identity=str(payload.get("relevant_progress_identity") or ""),
                supervisor_incarnation_identity=str(payload.get("supervisor_incarnation_identity") or ""),
                cause_kind="lifecycle_shutdown",
                scan_interval_s=scan_interval,
                expires_at=confirmation.get("expires_at"),
                confirmation_policy_identity=confirmation.get("confirmation_policy_identity"),
                schema_version=confirmation.get("schema_version"),
                semantic_dispatch_fingerprint=payload.get("semantic_dispatch_fingerprint"),
                container_identity=payload.get("container_identity"),
                ladder_stage=str(ladder_stage) if ladder_stage is not None else None,
                signal_identity=signal_identity if ladder_stage is not None else None,
            )
        except Exception as exc:
            print(f"non-worker confirmation consume failed: {exc}", file=sys.stderr)
            return 5

    def _final_authority_preflight(_records: list[dict[str, Any]]) -> None:
        # Executed by the ledger's one lock boundary immediately before the
        # disposition and signal claim.  The callback must not write or take a
        # nested ledger lock; it only re-loads the external authority sources.
        latest = revalidate_signal_payload(
            payload, marker_dir=marker_dir, ledger_root=ledger._root,
        )
        if latest.victim_process_start_identity != expected_start:
            raise SignalAuthorityError("target process identity changed before signal")

    try:
        disposition = NonWorkerSignalDisposition(
            disposition_id=disposition_id,
            subject="non_worker_lifecycle",
            lifecycle_identity=str(payload["lifecycle_identity"]),
            killer_identity=str(payload["killer_identity"]),
            cause_kind="lifecycle_shutdown",
            signal=signal_name,
            victim_pid_or_group=str(payload.get("victim_pid_or_group") or pid),
            victim_process_start_identity=expected_start,
            observed_at=datetime.now(timezone.utc).isoformat(),
            evidence=payload.get("evidence") or {},
            confirmation_event_id=confirmation_id_value if confirmation_required else None,
        )
        number = {"SIGINT": _signal.SIGINT, "SIGTERM": _signal.SIGTERM, "SIGKILL": _signal.SIGKILL}[signal_name]
        # Re-read immediately before the canonical record-before-signal door;
        # PID reuse between preflight and append is a hard no-signal result.
        latest_start = read_process_start_identity(pid)
        if latest_start != expected_start:
            print("non-worker process identity changed before signal", file=sys.stderr)
            return 5
        record = signal_non_worker(
            ledger,
            disposition,
            signal_fn=lambda: os.kill(pid, number),
            preflight=_final_authority_preflight,
        )
    except SignalAuthorityError as exc:
        print(f"non-worker signal authority changed before signal: {exc}", file=sys.stderr)
        return 5
    except Exception as exc:
        print(f"non-worker signal blocked: {exc}", file=sys.stderr)
        return 3
    print(json.dumps({"disposition_id": disposition_id, "recorded": True}, separators=(",", ":")))
    return 0


def main(argv: list[str] | None = None) -> int:
    return _record_cli(list(argv) if argv is not None else sys.argv[1:])


__all__ = [
    "WorkerDisposition", "ObservedProcessDeath", "NonWorkerSignalDisposition", "WorkerLadderResult",
    "SignalDispositionError", "WorkerSignalContext", "record_disposition",
    "record_before_signal", "worker_disposition_for_signal", "signal_worker", "signal_worker_ladder",
    "signal_after_record", "record_and_signal",
    "signal_process", "signal_process_group",
    "signal_non_worker",
    "recover_worker_disposition_outcome",
    "resolve_worker_execution_context", "confirmation_id", "confirmation_ttl_s",
    "observe_confirmation", "consume_confirmation", "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
