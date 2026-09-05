"""Persisted, single-use final-launch sequencing."""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import os
import subprocess
from typing import Any, Callable, Mapping

from arnold_pipelines.megaplan.incident.ledger import IncidentLedger
from arnold_pipelines.megaplan.cloud.worker_dispatch import WorkerAdmissionReceipt, WorkerExecutionContextRef, LaunchResult
from arnold_pipelines.megaplan.custody.common_worker_dispatch import SpawnedChildControl


@dataclass(frozen=True)
class LaunchStateRecord:
    state: str
    event_id: str
    receipt_id: str


class ControlledFinalLaunch:
    """The only primitive exposed to a production final-launch closure.

    The legacy adapter can project its historical custody sequence, but the
    canonical adapter is read-only: ``launch_transaction`` writes admission,
    accepted identity, and lifecycle state in the co-located operation store.
    Exceptions after entry are returned as typed uncertainty so the shared
    seam never guesses that no process was created.
    """

    def __init__(self, receipt: WorkerAdmissionReceipt, *, ledger: IncidentLedger | None = None, actor: str = "controlled-final-launch", physical_operation_evidence: dict[str, Any] | None = None, canonical: bool = False) -> None:
        self.receipt = receipt
        # Canonical launches use OperationRun/FileBackedDurableOpsStore for
        # admission, acceptance, and lifecycle.  The IncidentLedger remains
        # available only to legacy custody/disposition paths; do not even
        # construct it for the canonical adapter when no unrelated custody
        # caller supplied one.
        self.ledger = ledger if ledger is not None else (
            None if canonical else IncidentLedger(Path(receipt.execution_context.ledger_root))
        )
        self.actor = actor
        self.physical_operation_evidence = physical_operation_evidence
        self.canonical = canonical
        self._called = False
        self._state = "not_started"
        self.accepted_started_at: str | None = None
        self.accepted_finished_at: str | None = None
        self.accepted_worker_identity: Any = None
        self.registered_worker_identity: dict[str, Any] | None = None
        self.registered_child: dict[str, Any] | None = None
        self._custody_process: Any = None
        self._custody_hold_metadata: dict[str, Any] | None = None
        self.spawn_control = SpawnedChildControl(
            register_impl=self.register_spawned_child,
            signal_impl=self.signal_ladder,
            handoff_impl=self.handoff_spawn_cleanup,
            production=receipt.production_intent,
        )
        # ``ambiguous`` was written by pre-attempt-6 adapters.  It is not a
        # lifecycle state: keep the four-state projection intact and retain a
        # separate, durable hold so a reopen can never manufacture a fresh
        # ``not_started`` marker or expose the launch closure.
        self._permanent_hold_ambiguous = False
        self._permanent_hold_outcome: Any = None
        # Reopen is a full-history validation boundary.  Never select a
        # strongest marker from a contradictory persisted sequence.
        if self.canonical:
            # The durable operation store owns admission/lifecycle/acceptance
            # for migrated launches.  IncidentLedger remains available only
            # to the signal/disposition custody adapter.
            return
        self.ledger.projection()
        matching = [
            record.get("payload", {})
            for record in self.ledger.read_nbf_events()
            if (
                record.get("payload", {}).get("reservation_event_id")
                == receipt.reservation_event_id
                and record.get("payload", {}).get("admission_receipt_id")
                == receipt.admission_receipt_id
            )
        ]
        prior = [
            payload for payload in matching
            if payload.get("event_type") == "controlled_adapter_state"
            and payload.get("launch_state_identity") != "ambiguous"
        ]
        # Reopen from the ordered terminal marker.  Selecting the strongest
        # marker would silently resurrect a stale accepted/closed state after
        # a malformed or conflicting append.
        if prior:
            marker = prior[-1]
            self._state = str(marker.get("launch_state_identity"))
            self._called = self._state in {"entered", "accepted", "closed"}
            if self._state in {"accepted", "closed"}:
                self.accepted_worker_identity = marker.get("worker_identity")
                self.registered_worker_identity = marker.get("worker_identity")
                self.accepted_started_at = marker.get("started_at")
                self.accepted_finished_at = marker.get("finished_at")
        ambiguous_marker = any(
            payload.get("event_type") == "controlled_adapter_state"
            and (
                payload.get("launch_state_identity") == "ambiguous"
                or payload.get("permanent_hold_ambiguous") is True
            )
            for payload in matching
        )
        ambiguous_reconciliation = any(
            payload.get("event_type") == "reservation_reconciled"
            and (
                payload.get("resolution") == "permanent_hold_ambiguous"
                or payload.get("launch_state_identity") == "ambiguous"
                or payload.get("permanent_hold_ambiguous") is True
            )
            for payload in matching
        )
        if ambiguous_marker or ambiguous_reconciliation:
            self._permanent_hold_ambiguous = True
            # The typed outcome is deliberately derived from the original
            # receipt.  This keeps provider/route and execution-context fields
            # stable across byte-identical reopens; a reconciliation identity
            # is included when one was already persisted.
            from arnold_pipelines.megaplan.cloud.worker_dispatch import _unresolved_outcome
            self._permanent_hold_outcome = _unresolved_outcome(receipt)
            reconciliation = next(
                (
                    payload for payload in matching
                    if payload.get("event_type") == "reservation_reconciled"
                    and payload.get("resolution") == "permanent_hold_ambiguous"
                ),
                None,
            )
            if reconciliation:
                from dataclasses import replace
                self._permanent_hold_outcome = replace(
                    self._permanent_hold_outcome,
                    reconciliation_event_id=str(
                        reconciliation.get("reconciliation_id")
                        or reconciliation.get("event_id")
                    ),
                )
            self._called = True
        elif not prior:
            self._persist("not_started")

    @property
    def state(self) -> str:
        return self._state

    @property
    def context(self) -> WorkerExecutionContextRef:
        return self.receipt.execution_context

    @property
    def permanent_hold_ambiguous(self) -> bool:
        """Whether legacy history permanently holds this reservation."""
        return self._permanent_hold_ambiguous

    @property
    def permanent_hold_outcome(self) -> Any:
        """The stable typed unresolved outcome for a legacy hold, if any."""
        return self._permanent_hold_outcome

    def _canonical_process_identity(self) -> dict[str, Any] | None:
        """Read exact accepted worker identity from OperationRun resources."""
        try:
            from arnold.runtime.durable_ops import FileBackedDurableOpsStore
            root = Path(self.receipt.operation_store_root or self.context.operation_store_root or Path(self.context.ledger_root) / "ops")
            store = FileBackedDurableOpsStore(root)
            operation_id = self.receipt.operation_id or self.receipt.logical_dispatch_id
            run = store.load_operation_run(operation_id)
            if getattr(run.state, "value", run.state) != "running":
                return None
            for resource in store.list_typed_resources(operation_id):
                identity = dict(resource.details).get("worker_identity")
                if resource.resource_type.value == "process_session" and isinstance(identity, dict):
                    return identity
        except (OSError, KeyError, TypeError, ValueError):
            return None
        return None

    def _raise_permanent_hold(self) -> None:
        from arnold_pipelines.megaplan.types import CliError
        raise CliError(
            "scheduling_condition",
            "controlled final launch is permanently held for ambiguous legacy history",
            extra={
                "reason": "permanent_hold_ambiguous",
                "dispatch_outcome": self._permanent_hold_outcome.to_dict(),
                "reservation_event_id": self.receipt.reservation_event_id,
                "admission_receipt_id": self.receipt.admission_receipt_id,
                "physical_door_id": self.receipt.physical_door_id,
                "execution_context": self.context.to_dict(),
            },
        )

    def register_spawned_child(self, registration: Mapping[str, Any]) -> Mapping[str, Any]:
        """Capture the exact spawned-child identity before the launch waits.

        The WBC attempt is the durable writer for this evidence.  This method
        is the controlled-launch projection used by signal authority and
        reconciliation while the closure remains blocked in ``wait``; it does
        not emit a second lifecycle marker or admission.
        """
        if self._state != "entered":
            raise RuntimeError("spawned child registration is only valid after launch entry")
        if not isinstance(registration, Mapping):
            raise ValueError("spawned child registration must be a mapping")
        identity = registration.get("worker_identity")
        if not isinstance(identity, Mapping):
            raise ValueError("spawned child registration requires worker_identity")
        identity = dict(identity)
        process_start = identity.get("process_start_identity")
        if not isinstance(process_start, str) or not process_start:
            raise ValueError("spawned child registration requires worker_identity.process_start_identity")
        envelope_start = registration.get("process_start_identity")
        if envelope_start is not None and envelope_start != process_start:
            raise ValueError("spawned child process-start identity conflicts with worker identity")
        prior = self.registered_worker_identity
        if prior is not None and prior != identity:
            raise ValueError("spawned child registration conflicts with prior identity")
        self.registered_worker_identity = identity
        self.registered_child = dict(registration)
        return dict(registration)

    def handoff_spawn_cleanup(
        self,
        process: Any = None,
        *,
        error: BaseException | str | None = None,
        reason: str = "spawned child cleanup handed to custody",
        route_identity: str | None = None,
        hold_metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Persist cleanup custody after an exception escapes supervision.

        This is additive evidence on the admitted reservation. It never
        creates a lifecycle marker, admission, WBC attempt, or signal claim.
        A later supervisor can use the identity-bound handoff to observe
        natural death or place the reservation in a permanent hold.
        """
        from arnold_pipelines.megaplan.watchdog.worker_identity import read_process_start_identity

        wrapped_hold = process
        wrapped_process = getattr(wrapped_hold, "process", wrapped_hold)
        if wrapped_process is not wrapped_hold and callable(getattr(wrapped_process, "poll", None)):
            if hold_metadata is None and callable(getattr(wrapped_hold, "to_dict", None)):
                hold_metadata = wrapped_hold.to_dict()
            process = wrapped_process
        candidate_hold_metadata = dict(hold_metadata) if isinstance(hold_metadata, Mapping) else None

        registration = self.registered_child
        identity = self.registered_worker_identity
        if not isinstance(registration, dict) or not isinstance(identity, dict):
            return {"state": "unresolved", "reason": "spawn identity is not registered"}
        try:
            pid = int(identity.get("pid"))
        except (TypeError, ValueError):
            return {"state": "unresolved", "reason": "spawn identity PID is invalid"}
        expected_start = identity.get("process_start_identity")
        if not isinstance(expected_start, str) or not expected_start:
            return {"state": "unresolved", "reason": "spawn identity process-start is missing"}
        observed_start = None
        handle_pid_valid: bool | None = None
        if process is not None:
            handle_pid = getattr(process, "pid", None)
            handle_pid_valid = isinstance(handle_pid, int) and not isinstance(handle_pid, bool) and handle_pid == pid
            if handle_pid_valid:
                try:
                    observed_start = read_process_start_identity(pid)
                except Exception:
                    observed_start = None
        error_kind = type(error).__name__ if isinstance(error, BaseException) else "cleanup_handoff"
        error_text = str(error) if error is not None else ""
        effective_reason = str(reason or "spawned child cleanup handed to custody")
        pid_start_identity_valid: bool | None = None
        if process is not None:
            pid_start_identity_valid = bool(handle_pid_valid and observed_start == expected_start)
            if not handle_pid_valid:
                # A handle for another process must never enter custody.  We
                # still persist the handoff so an operator can reconcile the
                # admitted PID from durable identity evidence.
                error_kind = "process_pid_mismatch"
                effective_reason = f"{effective_reason}; cleanup handle PID does not match admitted child"
            elif observed_start is None:
                error_kind = "process_start_identity_unavailable"
                effective_reason = f"{effective_reason}; admitted child incarnation could not be revalidated"
            elif observed_start != expected_start:
                error_kind = "process_start_identity_mismatch"
                effective_reason = f"{effective_reason}; observed process incarnation does not match admitted child"
            else:
                # Keep the parent-owned handle only after both identity
                # dimensions have been checked.  A restart may reconcile from
                # durable PID/start evidence, but only this lawful handle may
                # reap the child in-process.
                self._custody_process = process
        if process is None or pid_start_identity_valid:
            if candidate_hold_metadata is not None:
                self._custody_hold_metadata = candidate_hold_metadata
        # Preserve metadata in the durable handoff even for an invalid
        # candidate, while keeping the already-retained in-memory custody
        # metadata untouched until validation succeeds.
        event_hold_metadata = candidate_hold_metadata or self._custody_hold_metadata
        registration_id = str(
            registration.get("spawn_registration_id")
            or registration.get("registration_id")
            or hashlib.sha256(json.dumps(registration, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
        )
        certification_id = str(
            registration.get("spawn_certification_id")
            or registration.get("certification_event_id")
            or registration.get("registration_fingerprint")
            or registration_id
        )
        context = self.context
        execution_context_identity = hashlib.sha256(json.dumps(
            {
                "plan_id": context.plan_id,
                "phase": context.phase,
                "logical_dispatch_id": context.logical_dispatch_id,
                "physical_door_id": context.physical_door_id,
                "semantic_dispatch_fingerprint": context.semantic_dispatch_fingerprint,
            }, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode()).hexdigest()
        try:
            event = self.ledger.append_spawn_cleanup_handoff(
                reservation_event_id=self.receipt.reservation_event_id,
                admission_receipt_id=self.receipt.admission_receipt_id,
                physical_door_id=self.receipt.physical_door_id,
                plan_id=context.plan_id,
                phase=context.phase,
                projection_key=self.receipt.projection_key,
                dispatch_family_id=context.dispatch_family_id,
                logical_dispatch_id=context.logical_dispatch_id,
                semantic_dispatch_fingerprint=context.semantic_dispatch_fingerprint,
                selected_spec=context.selected_spec,
                execution_context_identity=execution_context_identity,
                worker_identity=identity,
                victim_pid=pid,
                victim_process_start_identity=expected_start,
                spawn_registration_id=registration_id,
                spawn_certification_id=certification_id,
                route_identity=str(route_identity or context.selected_spec),
                error_kind=error_kind,
                reason=f"{effective_reason}{(': ' + error_text) if error_text else ''}",
                actor=self.actor,
                started_at=str(registration.get("started_at") or ""),
                hold_metadata=event_hold_metadata,
            )
        except Exception as exc:
            return {"state": "unresolved", "reason": str(exc)}
        payload = event.get("payload", event)
        result = {
            "state": "cleanup_hold",
            "handoff": payload,
            "handoff_id": payload.get("handoff_id"),
            "event_id": payload.get("event_id"),
            "event": event,
            "pid_start_identity_valid": pid_start_identity_valid,
        }
        if event_hold_metadata is not None:
            result["hold_metadata"] = dict(event_hold_metadata)
        return result

    def _handoff_matches_receipt(self, handoff: Mapping[str, Any]) -> bool:
        """Ensure a globally selected handoff belongs to this admission."""
        context = self.context
        execution_context_identity = hashlib.sha256(json.dumps(
            {
                "plan_id": context.plan_id,
                "phase": context.phase,
                "logical_dispatch_id": context.logical_dispatch_id,
                "physical_door_id": context.physical_door_id,
                "semantic_dispatch_fingerprint": context.semantic_dispatch_fingerprint,
            }, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode()).hexdigest()
        expected = {
            "reservation_event_id": self.receipt.reservation_event_id,
            "admission_receipt_id": self.receipt.admission_receipt_id,
            "plan_id": self.receipt.plan_id,
            "phase": self.receipt.phase,
            "projection_key": self.receipt.projection_key,
            "dispatch_family_id": self.receipt.dispatch_family_id,
            "logical_dispatch_id": self.receipt.logical_dispatch_id,
            "semantic_dispatch_fingerprint": self.receipt.semantic_dispatch_fingerprint,
            "selected_spec": self.receipt.normalized_spec,
            "physical_door_id": self.receipt.physical_door_id,
            "execution_context_identity": execution_context_identity,
        }
        return all(handoff.get(name) == expected_value for name, expected_value in expected.items())

    def reconcile_spawn_cleanup(
        self,
        process: Any = None,
        *,
        resolution: str,
        reason: str = "",
        handoff_id: str | None = None,
    ) -> dict[str, Any]:
        """Resolve a prior cleanup handoff by natural death or permanent hold."""
        from arnold_pipelines.megaplan.watchdog.worker_identity import read_process_start_identity

        handoffs = self.ledger.projection().get("cleanup_handoffs", {})
        candidates = [
            value for value in handoffs.values()
            if (handoff_id and value.get("handoff_id") == handoff_id)
            or (not handoff_id and value.get("admission_receipt_id") == self.receipt.admission_receipt_id)
        ]
        if handoff_id and len(candidates) > 1:
            return {"state": "unresolved", "reason": "cleanup handoff identity is not unique"}
        if not handoff_id and len(candidates) != 1:
            return {"state": "unresolved", "reason": "cleanup handoff identity is ambiguous"}
        handoff = candidates[0] if candidates else None
        if not isinstance(handoff, dict):
            return {"state": "unresolved", "reason": "spawn cleanup handoff is missing"}
        if not self._handoff_matches_receipt(handoff):
            # Handoff IDs are globally durable.  The ID alone is not authority;
            # reject cross-adapter records before process custody or writes.
            return {"state": "unresolved", "reason": "cleanup handoff is bound to another admission"}
        from arnold_pipelines.megaplan.watchdog.worker_identity import read_process_start_identity

        pid = int(handoff["victim_pid"])
        expected_start = handoff["victim_process_start_identity"]
        supplied_process = process
        if supplied_process is not None:
            supplied_process = getattr(supplied_process, "process", supplied_process)
            handle_pid = getattr(supplied_process, "pid", None)
            if not (isinstance(handle_pid, int) and not isinstance(handle_pid, bool) and handle_pid == pid):
                return {"state": "cleanup_hold", "reason": "cleanup handle PID does not match admitted child"}
            try:
                supplied_start = read_process_start_identity(pid)
            except Exception:
                supplied_start = None
            # A previously reaped parent handle is still safe to use when the
            # PID has disappeared.  A live/unresolved handle requires a fresh
            # matching incarnation before it can become custody.
            if supplied_start is not None and supplied_start != expected_start:
                if resolution == "natural_death":
                    return self.reconcile_spawn_cleanup(
                        None, resolution="permanent_hold", handoff_id=handoff["handoff_id"],
                        reason="process incarnation changed during cleanup reconciliation",
                    )
                return {"state": "permanent_hold", "reason": "process incarnation changed during cleanup reconciliation"}
            if supplied_start is None and getattr(supplied_process, "returncode", None) is None:
                return {"state": "cleanup_hold", "reason": "cleanup handle process-start identity is unavailable"}
            self._custody_process = supplied_process
        custody_process = self._custody_process
        if resolution == "natural_death":
            observed_start = read_process_start_identity(pid)
            if observed_start is not None and observed_start != expected_start:
                return self.reconcile_spawn_cleanup(
                    None, resolution="permanent_hold", handoff_id=handoff["handoff_id"],
                    reason="process incarnation changed during cleanup reconciliation",
                )
            if custody_process is not None:
                # Revalidate immediately before touching the handle.  This
                # closes the PID-reuse race between initial validation and
                # poll/reap.  A disappeared PID is acceptable only as a
                # death observation; a changed incarnation is a hold.
                before_poll_start = read_process_start_identity(pid)
                if before_poll_start is not None and before_poll_start != expected_start:
                    return self.reconcile_spawn_cleanup(
                        None, resolution="permanent_hold", handoff_id=handoff["handoff_id"],
                        reason="process incarnation changed before cleanup poll",
                    )
                if custody_process.poll() is None:
                    return {"state": "cleanup_hold", "reason": "admitted child remains live"}
            elif observed_start is not None:
                # A matching incarnation is still present, so a restart-style
                # reconciler must not assume death or attempt a signal.
                return {"state": "cleanup_hold", "reason": "admitted child remains live"}
            else:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    pass
                except (PermissionError, OSError):
                    return {"state": "cleanup_hold", "reason": "PID liveness cannot be safely established"}
                else:
                    return {"state": "cleanup_hold", "reason": "PID exists but process-start identity is unavailable"}
            return self._reconcile_cleanup_natural_death(handoff, custody_process)
        if resolution != "permanent_hold":
            return {"state": "unresolved", "reason": "unsupported cleanup reconciliation"}
        from arnold_pipelines.megaplan.incident.schema import ReservationReconciled
        prior = next(
            (record["payload"] for record in self.ledger.read_nbf_events()
             if record.get("payload", {}).get("event_type") == "reservation_reconciled"
             and record.get("payload", {}).get("reservation_event_id") == handoff["reservation_event_id"]
             and record.get("payload", {}).get("resolution") == "permanent_hold_ambiguous"
             and handoff["handoff_id"] in record.get("payload", {}).get("evidence_event_ids", [])),
            None,
        )
        if prior is not None:
            return {"state": "permanent_hold", "reconciliation": prior, "replayed": True}
        reconciliation_id = hashlib.sha256(
            f"spawn-cleanup-reconciliation:{handoff['handoff_id']}:{resolution}".encode()
        ).hexdigest()
        stable_time = str(handoff.get("recorded_at") or datetime.now(timezone.utc).isoformat())
        event = ReservationReconciled(
            reconciliation_id=reconciliation_id,
            plan_id=handoff["plan_id"],
            phase=handoff["phase"],
            projection_key=handoff["projection_key"],
            logical_dispatch_id=handoff["logical_dispatch_id"],
            admission_receipt_id=handoff["admission_receipt_id"],
            reservation_event_id=handoff["reservation_event_id"],
            semantic_dispatch_fingerprint=handoff["semantic_dispatch_fingerprint"],
            resolution="permanent_hold_ambiguous",
            evidence_kind="spawn_cleanup_handoff",
            evidence_event_ids=(handoff["handoff_id"],),
            launch_state_identity="ambiguous",
            observed_at=stable_time,
            recorded_at=stable_time,
            actor=self.actor,
            worker_identity=handoff["worker_identity"],
            victim_pid=handoff["victim_pid"],
            victim_process_start_identity=handoff["victim_process_start_identity"],
            running_receipt_identity=self.receipt.admission_receipt_id,
        )
        try:
            result = self.ledger.reconcile_reservation(event)
        except Exception as exc:
            return {"state": "unresolved", "reason": str(exc)}
        return {"state": "permanent_hold", "reconciliation": result.get("payload", result)}

    def _reconcile_cleanup_natural_death(self, handoff: Mapping[str, Any], process: Any = None) -> dict[str, Any]:
        """Append one observation and ordinary terminal for a dead child.

        This path is used after a durable handoff proves the child died.  An
        accepted-launch marker is still required before attributing an
        ordinary worker terminal; before acceptance the reservation remains a
        permanent custody hold.  No signal disposition or physical signal is
        created here; an available parent handle is only reaped after the
        durable terminal append.
        """
        if self.canonical:
            return {"state": "unresolved", "reason": "canonical launch custody requires operation-store reconciliation"}
        from arnold_pipelines.megaplan.incident.disposition import record_disposition
        from arnold_pipelines.megaplan.incident.schema import ObservedProcessDeath
        from arnold_pipelines.megaplan.orchestration.phase_result import DispatchOutcome

        observation_id = hashlib.sha256(f"spawn-cleanup-natural-death:{handoff['handoff_id']}".encode()).hexdigest()
        observed_at = str(handoff.get("recorded_at") or datetime.now(timezone.utc).isoformat())
        observation = ObservedProcessDeath(
            observation_id=observation_id,
            subject="worker",
            observation_source="spawn-cleanup-reconciler",
            known_context_fields={
                "plan_id": handoff["plan_id"],
                "phase": handoff["phase"],
                "admission_receipt_id": handoff["admission_receipt_id"],
                "semantic_dispatch_fingerprint": handoff["semantic_dispatch_fingerprint"],
            },
            unknown_context_fields=("killer_identity",),
            victim_identity_evidence={
                "worker_identity": handoff["worker_identity"],
                "victim_pid": handoff["victim_pid"],
                "victim_process_start_identity": handoff["victim_process_start_identity"],
            },
            cause_kind="observed_dead_unknown",
            killer_kind="external_unknown",
            signal=None,
            positive_cgroup_delta=None,
            observed_at=observed_at,
            evidence={"spawn_cleanup_handoff_id": handoff["handoff_id"], "natural_death": True},
        )
        projection = self.ledger.projection()
        reservation = next(
            r for r in projection["reservations"].values()
            if r.get("event_id") == handoff["reservation_event_id"]
        )
        canonical_identity = self._canonical_process_identity()
        if not canonical_identity:
            # Before the closure returns there is no accepted-launch marker,
            # hence no lawful worker terminal attribution.  Preserve custody
            # as a durable hold for an operator/restart reconciler; do not
            # infer success, failure, or a signal disposition from death.
            return self.reconcile_spawn_cleanup(
                process, resolution="permanent_hold", handoff_id=handoff["handoff_id"],
                reason="child died before accepted launch marker",
            )
        prior_terminal = next(
            (record["payload"] for record in self.ledger.read_nbf_events()
             if record.get("payload", {}).get("event_type") == "worker_terminal_outcome"
             and record.get("payload", {}).get("reservation_event_id") == handoff["reservation_event_id"]),
            None,
        )
        if prior_terminal is not None:
            prior_observation = next(
                (record for record in self.ledger.read_nbf_events()
                 if record.get("payload", {}).get("event_type") == "observed_process_death"
                 and record.get("payload", {}).get("observation_id") == (prior_terminal.get("terminal_failure") or {}).get("observation_id")),
                None,
            )
            return {
                "state": "already_dead",
                "observation": prior_observation,
                "terminal_outcome": prior_terminal,
                "replayed": True,
            }
        observation_record = record_disposition(self.ledger, observation)
        # Re-read the committed JSON representation so tuple/list fields have
        # the same shape on the first call and every restart/replay.
        observation_record = next(
            record for record in self.ledger.read_nbf_events()
            if record.get("payload", {}).get("observation_id") == observation_id
        )
        finished_at = observed_at
        # Only an accepted marker authorizes an ordinary worker terminal.
        outcome = DispatchOutcome(
            kind="ordinary_terminal_failure",
            launch_state="accepted",
            plan_id=handoff["plan_id"], phase=handoff["phase"],
            dispatch_family_id=handoff["dispatch_family_id"],
            logical_dispatch_id=handoff["logical_dispatch_id"],
            admission_receipt_id=handoff["admission_receipt_id"],
            semantic_dispatch_fingerprint=handoff["semantic_dispatch_fingerprint"],
            selected_spec=handoff["selected_spec"],
            worker_identity=canonical_identity,
            started_at=handoff.get("started_at") or observed_at,
            finished_at=finished_at,
            terminal_failure={"code": "observed_dead_unknown", "observation_id": observation_id, "reason": "spawned child died during cleanup custody"},
        )
        terminal = self.ledger.append_terminal_outcome(
            outcome=outcome,
            reservation_event_id=handoff["reservation_event_id"],
            projection_key=handoff["projection_key"],
            physical_door_id=handoff["physical_door_id"],
            execution_context_identity=handoff.get("execution_context_identity", ""),
            primary_spec=reservation.get("primary_spec", handoff["selected_spec"]),
            configured_fallback_chain_identity=reservation.get("configured_fallback_chain_identity", ""),
            preacceptance_observation_id=observation_id,
            actor=self.actor,
        )
        if process is not None and process.poll() is not None:
            process.wait(timeout=0)
        return {"state": "already_dead", "observation": observation_record, "terminal_outcome": terminal.get("payload", terminal)}

    @staticmethod
    def _validate_admitted_process_handle(
        process: Any,
        *,
        victim_pid: int,
        expected_process_start_identity: str,
        read_process_start_identity: Callable[[int], str],
    ) -> bool:
        """Fence the caller's handle before any liveness or signal operation."""
        handle_pid = getattr(process, "pid", None)
        if (
            not isinstance(handle_pid, int)
            or isinstance(handle_pid, bool)
            or handle_pid <= 0
            or handle_pid != victim_pid
        ):
            raise ValueError("cleanup process handle does not match admitted PID")
        observed = read_process_start_identity(victim_pid)
        if observed == expected_process_start_identity:
            return True
        # A Popen handle can outlive the OS start-token record.  Once the
        # token check has failed, poll only to distinguish this safe,
        # already-dead replay path from a live process that must remain held.
        if process.poll() is not None:
            return False
        raise ValueError("process incarnation changed before process handle use")

    def signal_ladder(self, process: Any = None, *, cause_kind: str = "timeout", **kwargs: Any) -> Any:
        """Invoke the canonical ladder using only this admitted child identity.

        A control created outside this launch cannot supply the persisted
        receipt/registration pair, so it fails closed before any primitive.
        Confirmation IDs are intentionally explicit; native timeout paths
        therefore return pending when proof has not been supplied.
        """
        from arnold_pipelines.megaplan.incident.disposition import WorkerSignalContext, signal_worker_ladder
        from arnold_pipelines.megaplan.watchdog.worker_identity import read_process_start_identity
        registration = self.registered_child
        identity = self.registered_worker_identity
        start_identity = (identity or {}).get("process_start_identity") if isinstance(identity, dict) else None
        if not isinstance(registration, dict) or not isinstance(identity, dict) or not start_identity:
            return {"state": "unresolved", "reason": "spawn identity is not registered"}
        victim_pid = identity.get("pid")
        try:
            context = WorkerSignalContext.from_ref(
                self.context,
                worker_identity=identity,
                victim_pid=victim_pid,
                victim_process_start_identity=start_identity,
                started_at=registration.get("started_at"),
            )
            self._validate_admitted_process_handle(
                process,
                victim_pid=context.victim_pid,
                expected_process_start_identity=context.victim_process_start_identity,
                read_process_start_identity=read_process_start_identity,
            )
            return signal_worker_ladder(
                self.ledger,
                context,
                killer_identity=self.actor,
                cause_kind=cause_kind,
                term_signal_fn=(lambda: process.send_signal(15)) if process is not None else None,
                kill_signal_fn=(lambda: process.send_signal(9)) if process is not None else None,
                liveness_fn=(lambda _pid: process.poll() is None) if process is not None else None,
                # Re-read the neutral process-start identity on every ladder
                # check.  Capturing the registration token here would make a
                # PID-reuse incarnation look like the admitted child.
                process_start_identity_fn=lambda pid: read_process_start_identity(pid),
                **kwargs,
            )
        except Exception as exc:
            return {"state": "unresolved", "reason": str(exc)}

    def immediate_timeout(self, process: Any, *, timeout_source: str = "native-timeout") -> dict[str, Any]:
        """Perform an explicitly-authorized native timeout teardown.

        Native command supervision has already established the timeout (or a
        guard has converted a stall into an explicit teardown request), so it
        cannot manufacture a two-scan progress proof at this point.  Keep the
        action on the same WBC/disposition ledger, however: TERM and KILL are
        each recorded and claimed before their physical callback, and the
        terminal is appended only after the child is observed dead.
        """
        from arnold_pipelines.megaplan.incident.disposition import (
            SignalDispositionError,
            WorkerSignalContext,
            _ladder_terminal,
            record_before_signal,
            worker_disposition_for_signal,
        )
        from arnold_pipelines.megaplan.watchdog.worker_identity import read_process_start_identity

        if self.canonical:
            # A timeout is an observation/custody concern.  This adapter does
            # not reopen the old ledger signal/terminal authority; a typed
            # operation-store reconciliation must own any later action.
            return {"state": "unresolved", "reason": "canonical timeout requires operation-store reconciliation"}

        registration = self.registered_child
        identity = self.registered_worker_identity
        start_identity = (identity or {}).get("process_start_identity") if isinstance(identity, dict) else None
        if not isinstance(registration, dict) or not isinstance(identity, dict) or not start_identity:
            return {"state": "unresolved", "reason": "spawn identity is not registered"}
        try:
            context = WorkerSignalContext.from_ref(
                self.context,
                worker_identity=identity,
                victim_pid=int(identity.get("pid")),
                victim_process_start_identity=str(start_identity),
                started_at=registration.get("started_at"),
            )
            self._validate_admitted_process_handle(
                process,
                victim_pid=context.victim_pid,
                expected_process_start_identity=context.victim_process_start_identity,
                read_process_start_identity=read_process_start_identity,
            )
            projection = self.ledger.projection()
            reservation = next(
                (r for r in projection.get("reservations", {}).values()
                 if r.get("admission_receipt_id") == context.admission_receipt_id),
                None,
            )
            if not isinstance(reservation, dict):
                return {"state": "unresolved", "reason": "worker receipt is not an active ledger reservation"}
            canonical_identity = self._canonical_process_identity()
            if not isinstance(canonical_identity, dict) or canonical_identity != context.worker_identity:
                return {"state": "unresolved", "reason": "canonical launch identity is incomplete or mismatched"}

            def existing_terminal(disposition_id: str) -> dict[str, Any] | None:
                return next(
                    (value for value in self.ledger.projection().get("terminals", {}).values()
                     if value.get("disposition_id") == disposition_id),
                    None,
                )

            reservation_terminal = next(
                (value for value in self.ledger.projection().get("terminals", {}).values()
                 if value.get("reservation_event_id") == reservation.get("event_id")),
                None,
            )
            if reservation_terminal is not None:
                return {
                    "state": "already_dead",
                    "terminal_outcome": reservation_terminal,
                    "replayed": True,
                }

            def claimed(disposition_id: str) -> bool:
                return any(
                    event.get("payload", {}).get("event_type") == "signal_claimed"
                    and event.get("payload", {}).get("disposition_id") == disposition_id
                    for event in self.ledger.read_nbf_events()
                )

            # This is the plan-authorized immediate-timeout exception to the
            # sustained two-scan rule.  The authorization is explicit and
            # durable in each disposition's timeout_source/evidence fields;
            # it is never inferred from a pending confirmation.
            authorization = {
                "authorization_kind": "native-immediate-timeout",
                "timeout_source": timeout_source,
                "confirmation_policy": "explicit-timeout-v1",
            }
            term = worker_disposition_for_signal(
                context, signal_name="SIGTERM", killer_kind="watchdog",
                killer_identity=self.actor, cause_kind="timeout", elapsed_s=0.0,
                timeout_source=timeout_source, ladder_step="term", evidence=authorization,
            )
            kill = worker_disposition_for_signal(
                context, signal_name="SIGKILL", killer_kind="watchdog",
                killer_identity=self.actor, cause_kind="timeout", elapsed_s=0.0,
                timeout_source=timeout_source, ladder_step="kill", evidence=authorization,
            )

            # Crash/replay recovery: an existing terminal is authoritative,
            # and an existing claim is never re-sent.  A terminal may be
            # reconstructed after a crash that happened after the physical
            # callback but before terminal projection.
            terminal = existing_terminal(kill.disposition_id)
            if terminal is not None:
                return {"state": "killed", "terminal_outcome": terminal, "replayed": True}
            terminal = existing_terminal(term.disposition_id)
            if terminal is not None:
                return {"state": "already_dead", "terminal_outcome": terminal, "replayed": True}

            if process.poll() is not None:
                # Crash/replay cutpoint: if the child died after a durable
                # TERM/KILL disposition or claim but before terminal
                # projection, link the terminal to that already-recorded
                # disposition.  Never manufacture a signal disposition when
                # no physical teardown attempt was recorded.
                # A disposition records intent, not a physical attempt.  Only
                # the durable pre-signal claim proves that this authority
                # reached the callback boundary; never reconstruct a worker
                # terminal from a disposition left behind before claim.
                dispositions = self.ledger.projection().get("dispositions", {})
                if kill.disposition_id in dispositions and claimed(kill.disposition_id):
                    terminal = _ladder_terminal(self.ledger, context, kill, marker, reservation)
                    return {"state": "killed", "terminal_outcome": terminal, "replayed": True}
                if term.disposition_id in dispositions and claimed(term.disposition_id):
                    terminal = _ladder_terminal(self.ledger, context, term, marker, reservation)
                    return {"state": "already_dead", "terminal_outcome": terminal, "replayed": True}
                # No signal was needed. Record an explicit unknown-death
                # observation and link it to one ordinary terminal outcome;
                # never manufacture TERM/KILL evidence for a callback that
                # never ran.
                from arnold_pipelines.megaplan.incident.disposition import record_disposition
                from arnold_pipelines.megaplan.incident.schema import ObservedProcessDeath
                from arnold_pipelines.megaplan.orchestration.phase_result import DispatchOutcome
                observed_at = datetime.now(timezone.utc).isoformat()
                observation_id = hashlib.sha256(
                    f"already-dead:{context.admission_receipt_id}:{context.victim_pid}:{context.victim_process_start_identity}".encode()
                ).hexdigest()
                observation = ObservedProcessDeath(
                    observation_id=observation_id,
                    subject="worker",
                    observation_source="controlled-final-launch-immediate-timeout",
                    known_context_fields={
                        "plan_id": context.plan_id,
                        "phase": context.phase,
                        "admission_receipt_id": context.admission_receipt_id,
                        "semantic_dispatch_fingerprint": context.semantic_dispatch_fingerprint,
                    },
                    unknown_context_fields=("killer_identity",),
                    victim_identity_evidence={
                        "worker_identity": context.worker_identity,
                        "victim_pid": context.victim_pid,
                        "victim_process_start_identity": context.victim_process_start_identity,
                    },
                    cause_kind="observed_dead_unknown",
                    killer_kind="external_unknown",
                    signal=None,
                    positive_cgroup_delta=None,
                    observed_at=observed_at,
                    evidence={"already_dead": True, "before_timeout_teardown": True},
                )
                observation_record = record_disposition(self.ledger, observation)
                outcome = DispatchOutcome(
                    kind="ordinary_terminal_failure",
                    launch_state="accepted",
                    plan_id=context.plan_id,
                    phase=context.phase,
                    dispatch_family_id=context.dispatch_family_id,
                    logical_dispatch_id=context.logical_dispatch_id,
                    admission_receipt_id=context.admission_receipt_id,
                    semantic_dispatch_fingerprint=context.semantic_dispatch_fingerprint,
                    selected_spec=context.selected_spec,
                    worker_identity=context.worker_identity,
                    started_at=context.started_at or observed_at,
                    finished_at=observed_at,
                    terminal_failure={
                        "code": "observed_dead_unknown",
                        "observation_id": observation_id,
                        "reason": "child exited before timeout teardown",
                    },
                )
                terminal_record = self.ledger.append_terminal_outcome(
                    outcome=outcome,
                    reservation_event_id=reservation.get("event_id"),
                    projection_key=reservation.get("projection_key"),
                    physical_door_id=reservation.get("physical_door_id", context.physical_door_id),
                    execution_context_identity=reservation.get("execution_context_identity", context.execution_context_identity),
                    primary_spec=reservation.get("primary_spec", context.selected_spec),
                    configured_fallback_chain_identity=reservation.get("configured_fallback_chain_identity", ""),
                )
                return {
                    "state": "already_dead",
                    "observation": observation_record,
                    "terminal_outcome": terminal_record.get("payload", terminal_record),
                }
            if read_process_start_identity(context.victim_pid) != context.victim_process_start_identity:
                return {"state": "unresolved", "reason": "process incarnation changed before timeout teardown"}

            def final_timeout_preflight(_records: list[dict[str, Any]]) -> None:
                # The ledger lock is held across this final identity check,
                # claim, and physical callback.  A check performed before
                # record_before_signal would leave a PID-reuse TOCTOU window.
                if getattr(process, "pid", None) != context.victim_pid:
                    raise SignalDispositionError(
                        "cleanup process handle does not match admitted PID"
                    )
                if process.poll() is not None:
                    raise SignalDispositionError(
                        "admitted child exited before timeout signal"
                    )
                observed = read_process_start_identity(context.victim_pid)
                if observed != context.victim_process_start_identity:
                    raise SignalDispositionError(
                        "process incarnation changed before timeout signal"
                    )

            if not claimed(term.disposition_id):
                try:
                    record_before_signal(
                        self.ledger, term,
                        lambda: process.send_signal(15),
                        preflight=final_timeout_preflight,
                    )
                except (SignalDispositionError, OSError, ProcessLookupError) as exc:
                    return {"state": "unresolved", "reason": f"TERM teardown failed: {exc}"}
            try:
                process.wait(timeout=5)
            except (subprocess.TimeoutExpired, TimeoutError, ProcessLookupError, ChildProcessError):
                pass
            if process.poll() is not None:
                terminal = _ladder_terminal(self.ledger, context, term, marker, reservation)
                return {"state": "already_dead", "terminal_outcome": terminal}
            if read_process_start_identity(context.victim_pid) != context.victim_process_start_identity:
                return {"state": "unresolved", "reason": "process incarnation changed after TERM"}

            if not claimed(kill.disposition_id):
                try:
                    record_before_signal(
                        self.ledger, kill,
                        lambda: process.send_signal(9),
                        preflight=final_timeout_preflight,
                    )
                except (SignalDispositionError, OSError, ProcessLookupError) as exc:
                    return {"state": "unresolved", "reason": f"KILL teardown failed: {exc}"}
            try:
                process.wait(timeout=5)
            except (subprocess.TimeoutExpired, TimeoutError, ProcessLookupError, ChildProcessError):
                pass
            if process.poll() is None:
                return {"state": "unresolved", "reason": "child remained live after KILL teardown"}
            terminal = _ladder_terminal(self.ledger, context, kill, marker, reservation)
            return {"state": "killed", "terminal_outcome": terminal}
        except Exception as exc:
            return {"state": "unresolved", "reason": str(exc)}

    def _persist(self, state: str, *, worker_identity: Any = None, started_at: str | None = None, finished_at: str | None = None, victim_process_start_identity: str | None = None) -> dict[str, Any]:
        if self._permanent_hold_ambiguous and state != "not_started":
            self._raise_permanent_hold()
        if state == "entered" and self._state != "not_started":
            raise RuntimeError("controlled final launch entered out of order")
        if state == "accepted" and self._state != "entered":
            raise RuntimeError("controlled final launch accepted out of order")
        if state == "closed" and self._state != "accepted":
            raise RuntimeError("controlled final launch closed out of order")
        self._state = state
        if self.canonical:
            return {
                "event_type": "canonical_operation_state",
                "launch_state_identity": state,
                "operation_id": self.receipt.operation_id,
                "request_id": self.receipt.request_id,
                "admission_receipt_id": self.receipt.admission_receipt_id,
            }
        event = self.ledger.append_controlled_adapter_state(
            reservation_event_id=self.receipt.reservation_event_id,
            admission_receipt_id=self.receipt.admission_receipt_id,
            physical_door_id=self.receipt.physical_door_id,
            launch_state_identity=state,
            phase=self.receipt.phase,
            selected_spec=self.receipt.normalized_spec,
            primary_spec=self.receipt.normalized_spec,
            logical_dispatch_id=self.receipt.logical_dispatch_id,
            worker_identity=worker_identity,
            victim_process_start_identity=victim_process_start_identity,
            started_at=started_at,
            finished_at=finished_at,
            physical_operation_evidence=(
                self.physical_operation_evidence if state == "not_started" else None
            ),
            actor=self.actor,
        )
        return event

    def run(self, launch: Callable[[WorkerExecutionContextRef], Any]) -> Any:
        if self._permanent_hold_ambiguous:
            # Keep the historical exception boundary used by dispatchers, but
            # include the exact typed hold for callers that need to reconcile
            # it.  Crucially this occurs before callable validation/entry and
            # therefore cannot trigger WBC, provider, or relaunch effects.
            self._raise_permanent_hold()
        if self._called:
            raise RuntimeError("controlled final launch closure may be called only once")
        if not callable(launch):
            raise TypeError("final launch must be callable")
        self._called = True
        self._persist("entered")
        try:
            launch_context = replace(
                self.context,
                spawn_registration_callback=self.spawn_control,
            )
            value = launch(launch_context)
        except Exception as exc:
            from arnold_pipelines.megaplan.cloud.worker_dispatch import _outcome_from_terminal_exception
            value = _outcome_from_terminal_exception(
                exc,
                self.receipt,
                datetime.now(timezone.utc).isoformat(),
                datetime.now(timezone.utc).isoformat(),
            )
            if value is None:
                raise
        unresolved = self._unresolved_result(value)
        if unresolved is not None:
            unresolved = self._validate_unresolved_context(unresolved)
            if self.canonical:
                # The operation store owns canonical uncertainty and
                # reconciliation.  Do not consult or append IncidentLedger
                # custody projections here.
                return unresolved
            # An unresolved launch is a valid typed custody result, not an
            # accepted worker result.  Preserve the durable handoff identity
            # when the callback already transferred cleanup custody.
            handoffs = self.ledger.projection().get("cleanup_handoffs", {})
            matching = [
                item.get("handoff_id") for item in handoffs.values()
                if item.get("admission_receipt_id") == self.receipt.admission_receipt_id
            ]
            if unresolved.reconciliation_event_id is not None:
                if matching.count(unresolved.reconciliation_event_id) != 1:
                    raise ValueError("unresolved launch reconciliation event is not bound to this admission")
            elif len(matching) == 1:
                unresolved = replace(unresolved, reconciliation_event_id=matching[0])
            elif self.receipt.production_intent:
                raise ValueError("production unresolved launch requires exactly one durable cleanup handoff")
            return unresolved
        if not self._is_accepted_result(value):
            raise TypeError(
                "final launch must return DispatchOutcome or a typed worker result"
            )
        context_value = value.value if hasattr(value, "value") and hasattr(value, "accepted") else value
        payload = getattr(context_value, "payload", None)
        if isinstance(payload, dict) and isinstance(payload.get("dispatch_outcome"), dict):
            context_value = payload["dispatch_outcome"]
        started_at = getattr(context_value, "started_at", None) or datetime.now(timezone.utc).isoformat()
        finished_at = getattr(context_value, "finished_at", None) or datetime.now(timezone.utc).isoformat()
        worker_identity = getattr(context_value, "worker_identity", None)
        if isinstance(value, LaunchResult):
            worker_identity = value.worker_identity or worker_identity
            started_at = value.started_at or started_at
            finished_at = value.finished_at or finished_at
        if isinstance(context_value, dict):
            started_at = context_value.get("started_at") or started_at
            finished_at = context_value.get("finished_at") or finished_at
            worker_identity = context_value.get("worker_identity") or worker_identity
        if not isinstance(worker_identity, dict):
            if self.receipt.production_intent:
                raise TypeError("accepted production launch result must carry authoritative worker identity")
            from arnold_pipelines.megaplan.cloud.worker_dispatch import _worker_identity
            worker_identity = dict(_worker_identity(None))
        if self.receipt.production_intent and not (
            isinstance(worker_identity.get("process_start_identity"), str)
            and worker_identity.get("process_start_identity")
        ):
            raise TypeError(
                "accepted production launch result must carry child process-start identity"
            )
        if (
            self.registered_worker_identity is not None
            and worker_identity != self.registered_worker_identity
        ):
            raise TypeError(
                "terminal worker identity does not match registered spawned child"
            )
        if self.registered_worker_identity is None:
            self.registered_worker_identity = dict(worker_identity)
        self.accepted_started_at = started_at
        self.accepted_finished_at = finished_at
        self.accepted_worker_identity = worker_identity
        self._persist(
            "accepted", worker_identity=worker_identity, started_at=started_at,
            finished_at=finished_at,
            victim_process_start_identity=(worker_identity or {}).get("process_start_identity"),
        )
        return value

    @staticmethod
    def _unresolved_result(value: Any) -> Any:
        from arnold_pipelines.megaplan.orchestration.phase_result import DispatchOutcome
        from arnold_pipelines.megaplan.cloud.worker_dispatch import LaunchResult

        candidate = value.value if isinstance(value, LaunchResult) else value
        if isinstance(candidate, DispatchOutcome):
            return candidate if candidate.kind == "unresolved_launch" else None
        if isinstance(candidate, Mapping):
            try:
                decoded = DispatchOutcome.from_dict(candidate)
            except (TypeError, ValueError):
                return None
            return decoded if decoded.kind == "unresolved_launch" else None
        return None

    def _validate_unresolved_context(self, value: Any) -> Any:
        """Validate an unresolved result against this exact admission.

        Unresolved custody is intentionally allowed to omit worker identity and
        timing: those facts may not exist when a callback unwinds.  The seven
        admission-bound fields, however, are never optional in this production
        authority; accepting one from another reservation would make custody
        evidence cross-attach.
        """
        from arnold_pipelines.megaplan.cloud.worker_dispatch import _validate_outcome_context

        expected = {
            "plan_id": self.receipt.plan_id,
            "phase": self.receipt.phase,
            "dispatch_family_id": self.receipt.dispatch_family_id,
            "logical_dispatch_id": self.receipt.logical_dispatch_id,
            "admission_receipt_id": self.receipt.admission_receipt_id,
            "semantic_dispatch_fingerprint": self.receipt.semantic_dispatch_fingerprint,
            "selected_spec": self.receipt.normalized_spec,
        }
        for name, expected_value in expected.items():
            if getattr(value, name, None) != expected_value:
                raise ValueError(f"dispatch outcome context mismatch: {name}")

        # Reuse the canonical route/provider checks and normalization.  The
        # unresolved contract may omit these transport fields, just as it may
        # omit worker timing, so the canonical helper is invoked only once the
        # worker/timing proof is complete.
        supplied_worker = getattr(value, "worker_identity", None)
        supplied_started = getattr(value, "started_at", None)
        supplied_finished = getattr(value, "finished_at", None)
        proof_present = (supplied_worker is not None, supplied_started is not None, supplied_finished is not None)
        if any(proof_present) and not all(proof_present):
            raise ValueError("unresolved launch worker identity/timing context is incomplete")
        if all(proof_present):
            return _validate_outcome_context(
                value, self.receipt, str(supplied_started), str(supplied_finished), require_accepted=False,
            )
        for name, expected_value in {
            "provider": self.receipt.provider,
            "route_liveness_kind": self.receipt.route_liveness_kind,
            "route_liveness_identity": self.receipt.route_liveness_identity,
            "route_liveness_digest": self.receipt.route_liveness_digest,
        }.items():
            supplied = getattr(value, name, None)
            if supplied is not None and supplied != expected_value:
                raise ValueError(f"dispatch outcome context mismatch: {name}")
        normalized = replace(
            value,
            provider=getattr(value, "provider", None) or self.receipt.provider,
            route_liveness_kind=getattr(value, "route_liveness_kind", None) or self.receipt.route_liveness_kind,
            route_liveness_identity=getattr(value, "route_liveness_identity", None) or self.receipt.route_liveness_identity,
            route_liveness_digest=getattr(value, "route_liveness_digest", None) or self.receipt.route_liveness_digest,
        )
        return value if normalized == value else normalized

    @staticmethod
    def _is_accepted_result(value: Any) -> bool:
        from arnold_pipelines.megaplan.orchestration.phase_result import DispatchOutcome
        from arnold_pipelines.megaplan.cloud.worker_dispatch import LaunchResult

        if isinstance(value, LaunchResult):
            return value.accepted and ControlledFinalLaunch._is_accepted_result(value.value)

        if isinstance(value, DispatchOutcome):
            return value.kind not in {"no_launch", "unresolved_launch"}
        if isinstance(value, dict):
            try:
                decoded = DispatchOutcome.from_dict(value)
            except (TypeError, ValueError):
                return False
            return decoded.kind not in {"no_launch", "unresolved_launch"}
        if isinstance(value, tuple) and len(value) == 4:
            worker = value[0]
            from arnold_pipelines.megaplan.cloud.worker_dispatch import _worker_result_is_failure_shaped
            if _worker_result_is_failure_shaped(worker):
                return False
            return (
                type(worker).__name__ == "WorkerResult"
                and type(worker).__module__.endswith("workers._impl")
            )
        if type(value).__name__ == "ManagedCommandResult" and type(value).__module__.endswith("worker_dispatch"):
            return True
        if type(value).__name__ == "WorkerResult":
            from arnold_pipelines.megaplan.cloud.worker_dispatch import _worker_result_is_failure_shaped
            if _worker_result_is_failure_shaped(value):
                return False
        return (
            type(value).__name__ == "WorkerResult"
            and type(value).__module__.endswith("workers._impl")
        )

    def close(self) -> None:
        if self._state == "accepted":
            self._persist("closed")



__all__ = ["ControlledFinalLaunch", "LaunchStateRecord"]
