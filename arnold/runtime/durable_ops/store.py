"""Operation-run store protocol slice for durable operations."""

from __future__ import annotations

import json
import os
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Lock, RLock
from typing import Any, Iterator
from typing import Protocol, runtime_checkable

import fcntl

from .events import OperationEvent
from .launch import LaunchEnvelope, LaunchReason, LaunchResult
from .operation import OperationRun, OperationState, RetryMetadata
from .scheduled_task import ScheduledTask, ScheduledTaskState
from .typed_resources import ResourceType, TypedResource

__all__ = [
    "DurableOpsStore",
    "FileBackedDurableOpsStore",
    "OperationAlreadyExists",
    "OperationLockConflict",
    "OperationNotFound",
    "OperationEventAlreadyExists",
    "ScheduledTaskAlreadyExists",
    "ScheduledTaskNotFound",
    "ScheduledTaskLeaseConflict",
    "ScheduledTaskLeaseTokenMismatch",
    "TypedResourceAlreadyExists",
    "LaunchStoreResult",
]


class OperationAlreadyExists(ValueError):
    """Raised when creating an operation run would overwrite an existing run."""


class OperationNotFound(KeyError):
    """Raised when an operation run cannot be found."""


class OperationLockConflict(RuntimeError):
    """Raised when an optimistic update uses a stale lock version."""


class TypedResourceAlreadyExists(ValueError):
    """Raised when creating a typed resource would overwrite an existing resource."""


class OperationEventAlreadyExists(ValueError):
    """Raised when appending an operation event would overwrite an existing event."""


class ScheduledTaskAlreadyExists(ValueError):
    """Raised when creating a scheduled task would overwrite an existing task."""


class ScheduledTaskNotFound(KeyError):
    """Raised when a scheduled task cannot be found."""


class ScheduledTaskLeaseConflict(RuntimeError):
    """Raised when a scheduled task cannot be claimed because its lease is active."""


class ScheduledTaskLeaseTokenMismatch(RuntimeError):
    """Raised when completing or failing a task with the wrong lease token."""


@dataclass(frozen=True)
class LaunchStoreResult:
    """Canonical result of an authoritative launch admission/acceptance write."""

    result: LaunchResult
    reason: LaunchReason
    operation: OperationRun
    envelope: LaunchEnvelope
    process_resource: TypedResource | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "result", LaunchResult(self.result))
        object.__setattr__(self, "reason", LaunchReason(self.reason))


class FileBackedDurableOpsStore:
    """JSON current-state store for operation runs, resources, and events."""

    lock_timeout_seconds = 30.0

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self._root = Path(root)
        self._path = self._root / "operation_runs.json"
        self._lock_path = self._root / "operation_runs.lock"
        self._lock = Lock()

    def admit_launch(
        self,
        envelope: LaunchEnvelope,
        *,
        operation_type: str | None = None,
    ) -> LaunchStoreResult:
        """Atomically admit one immutable envelope as a ``PENDING`` operation.

        Admission identity is kept in the existing operation-event substrate.
        The operation and admission event are assembled in memory and become
        visible together through the store's single replacement.
        """

        envelope = _coerce_launch_envelope(envelope)
        with self._lock:
            with interprocess_json_lock(self._lock_path, timeout_seconds=self.lock_timeout_seconds):
                data = self._read_data()
                runs = data["operation_runs"]
                events = data["operation_events"]
                current = _operation_run_from_json(runs[envelope.operation_id]) if envelope.operation_id in runs else None
                admission_id = _launch_admission_event_id(envelope)
                existing_raw = events.get(admission_id)
                if existing_raw is not None:
                    existing = _operation_event_from_json(existing_raw)
                    if not _admission_event_matches(existing, envelope):
                        return _launch_store_conflict(envelope, current)
                    if current is None:
                        return _launch_store_unknown(envelope, None)
                    return LaunchStoreResult(
                        LaunchResult.ACCEPTED,
                        LaunchReason.REPLAY,
                        current,
                        envelope,
                    )

                # Any admission event for this operation is authoritative for
                # its request identity; a second request cannot be appended.
                for raw in events.values():
                    if raw.get("operation_id") != envelope.operation_id:
                        continue
                    if raw.get("event_type") != _LAUNCH_ADMISSION_EVENT:
                        continue
                    prior = _operation_event_from_json(raw)
                    if not _admission_event_matches(prior, envelope):
                        return _launch_store_conflict(envelope, current)

                if current is not None:
                    if current.state is not OperationState.PENDING:
                        return _launch_store_conflict(envelope, current)
                    if current.idempotency_key not in (None, envelope.request_id):
                        return _launch_store_conflict(envelope, current)
                    stored = current
                else:
                    selected_type = operation_type or envelope.launch_spec.get("operation_type", "launch")
                    if not isinstance(selected_type, str) or not selected_type:
                        raise ValueError("operation_type must be a non-empty string")
                    timestamp = _utc_now()
                    stored = OperationRun(
                        id=envelope.operation_id,
                        operation_type=selected_type,
                        state=OperationState.PENDING,
                        idempotency_key=envelope.request_id,
                        created_at=timestamp,
                        updated_at=timestamp,
                    )

                event = OperationEvent(
                    id=admission_id,
                    operation_id=envelope.operation_id,
                    event_type=_LAUNCH_ADMISSION_EVENT,
                    summary="launch envelope admitted",
                    sequence=_next_event_sequence(events, operation_id=envelope.operation_id),
                    payload=_launch_admission_payload(envelope),
                )
                data["operation_runs"][stored.id] = _operation_run_to_json(stored)
                data["operation_events"][event.id] = _operation_event_to_json(event)
                try:
                    self._write_data(data)
                except Exception:
                    return self._resolve_admission_write_failure(envelope, current)
                return LaunchStoreResult(
                    LaunchResult.ACCEPTED,
                    LaunchReason.ADMITTED,
                    stored,
                    envelope,
                )

    def accept_launch(
        self,
        envelope: LaunchEnvelope,
        *,
        process_resource: TypedResource,
        owner_evidence: dict[str, Any],
        owner: str | None = None,
    ) -> LaunchStoreResult:
        """Atomically persist strict accepted identity and transition to RUNNING.

        The resource identifier and acceptance event identifier are derived
        from operation/request identity.  ``owner_evidence`` is persisted in
        the acceptance event and must carry the same owner on exact replay.
        """

        envelope = _coerce_launch_envelope(envelope)
        if not isinstance(process_resource, TypedResource):
            raise TypeError("process_resource must be a TypedResource")
        if not isinstance(owner_evidence, dict):
            raise TypeError("owner_evidence must be a JSON object")
        evidence_owner = owner or owner_evidence.get("owner") or owner_evidence.get("owner_id")
        if not isinstance(evidence_owner, str) or not evidence_owner:
            raise ValueError("owner_evidence must contain a non-empty owner")
        if any(
            key in owner_evidence and owner_evidence[key] != evidence_owner
            for key in ("owner", "owner_id")
        ):
            return _launch_store_conflict(envelope, None)

        expected_resource_id = _launch_process_resource_id(envelope)
        if process_resource.operation_id != envelope.operation_id:
            return _launch_store_conflict(envelope, None)
        if process_resource.resource_type is not ResourceType.PROCESS_SESSION:
            return _launch_store_conflict(envelope, None)
        if not process_resource.name:
            return _launch_store_conflict(envelope, None)

        with self._lock:
            with interprocess_json_lock(self._lock_path, timeout_seconds=self.lock_timeout_seconds):
                data = self._read_data()
                runs = data["operation_runs"]
                events = data["operation_events"]
                resources = data["typed_resources"]
                current = runs.get(envelope.operation_id)
                if current is None:
                    return _launch_store_conflict(envelope, None)
                operation = _operation_run_from_json(current)
                admission_raw = events.get(_launch_admission_event_id(envelope))
                if admission_raw is None or not _admission_event_matches(
                    _operation_event_from_json(admission_raw), envelope
                ):
                    return _launch_store_conflict(envelope, operation)

                acceptance_id = _launch_acceptance_event_id(envelope)
                existing_event_raw = events.get(acceptance_id)
                existing_resource_raw = resources.get(expected_resource_id)
                if existing_event_raw is not None or existing_resource_raw is not None:
                    existing_event = (
                        _operation_event_from_json(existing_event_raw)
                        if existing_event_raw is not None
                        else None
                    )
                    existing_resource = (
                        _typed_resource_from_json(existing_resource_raw)
                        if existing_resource_raw is not None
                        else None
                    )
                    if operation.state is OperationState.RUNNING:
                        if existing_event is not None and existing_resource is not None:
                            if _acceptance_matches(
                                existing_event,
                                existing_resource,
                                envelope,
                                process_resource,
                                evidence_owner,
                                owner_evidence,
                            ):
                                return LaunchStoreResult(
                                    LaunchResult.ACCEPTED,
                                    LaunchReason.REPLAY,
                                    operation,
                                    envelope,
                                    existing_resource,
                                )
                            return _launch_store_conflict(envelope, operation, existing_resource)
                        return _launch_store_unknown(envelope, operation, existing_resource)
                    if operation.state is not OperationState.PENDING:
                        return _launch_store_conflict(envelope, operation, existing_resource)

                    # A replacement can be commit-unknown after one of the
                    # accepted facts reached disk.  Validate the fact that is
                    # present, then complete only the missing pieces in the
                    # same idempotent composite write; never redispatch.
                    stored_resource = _canonical_process_resource(
                        process_resource,
                        envelope,
                        owner=evidence_owner,
                    )
                    if existing_resource is not None and not _resource_matches(
                        existing_resource, stored_resource
                    ):
                        return _launch_store_conflict(envelope, operation, existing_resource)
                    accepted_resource = existing_resource or stored_resource
                    if existing_event is not None and not _acceptance_event_matches(
                        existing_event,
                        accepted_resource,
                        envelope,
                        process_resource,
                        evidence_owner,
                        owner_evidence,
                    ):
                        return _launch_store_conflict(envelope, operation, existing_resource)
                    acceptance_event = existing_event or OperationEvent(
                        id=acceptance_id,
                        operation_id=envelope.operation_id,
                        event_type=_LAUNCH_ACCEPTANCE_EVENT,
                        summary="launch accepted",
                        sequence=_next_event_sequence(events, operation_id=envelope.operation_id),
                        payload=_launch_acceptance_payload(
                            envelope,
                            accepted_resource,
                            owner=evidence_owner,
                            owner_evidence=owner_evidence,
                        ),
                    )
                    running = replace(
                        operation.transition_to(OperationState.RUNNING),
                        lock_version=operation.lock_version + 1,
                    )
                    data["operation_runs"][running.id] = _operation_run_to_json(running)
                    data["typed_resources"][accepted_resource.id] = _typed_resource_to_json(accepted_resource)
                    data["operation_events"][acceptance_event.id] = _operation_event_to_json(acceptance_event)
                    try:
                        self._write_data(data)
                    except Exception:
                        return self._resolve_acceptance_write_failure(
                            envelope,
                            process_resource,
                            evidence_owner,
                            owner_evidence,
                            operation,
                        )
                    return LaunchStoreResult(
                        LaunchResult.ACCEPTED,
                        LaunchReason.DISPATCH_ACCEPTED,
                        running,
                        envelope,
                        accepted_resource,
                    )
                if operation.state is not OperationState.PENDING:
                    return _launch_store_conflict(envelope, operation)

                stored_resource = _canonical_process_resource(
                    process_resource,
                    envelope,
                    owner=evidence_owner,
                )
                acceptance_event = OperationEvent(
                    id=acceptance_id,
                    operation_id=envelope.operation_id,
                    event_type=_LAUNCH_ACCEPTANCE_EVENT,
                    summary="launch accepted",
                    sequence=_next_event_sequence(events, operation_id=envelope.operation_id),
                    payload=_launch_acceptance_payload(
                        envelope,
                        stored_resource,
                        owner=evidence_owner,
                        owner_evidence=owner_evidence,
                    ),
                )
                running = replace(
                    operation.transition_to(OperationState.RUNNING),
                    lock_version=operation.lock_version + 1,
                )
                data["operation_runs"][running.id] = _operation_run_to_json(running)
                data["typed_resources"][stored_resource.id] = _typed_resource_to_json(stored_resource)
                data["operation_events"][acceptance_event.id] = _operation_event_to_json(acceptance_event)
                try:
                    self._write_data(data)
                except Exception:
                    return self._resolve_acceptance_write_failure(
                        envelope,
                        process_resource,
                        evidence_owner,
                        owner_evidence,
                        operation,
                    )
                return LaunchStoreResult(
                    LaunchResult.ACCEPTED,
                    LaunchReason.DISPATCH_ACCEPTED,
                    running,
                    envelope,
                    stored_resource,
                )

    def create_operation_run(self, run: OperationRun) -> OperationRun:
        with self._lock:
            with interprocess_json_lock(self._lock_path, timeout_seconds=self.lock_timeout_seconds):
                data = self._read_data()
                runs = data["operation_runs"]
                if run.id in runs:
                    raise OperationAlreadyExists(run.id)
                stored = replace(run, lock_version=0)
                runs[stored.id] = _operation_run_to_json(stored)
                self._write_data(data)
                return stored

    def load_operation_run(self, operation_id: str) -> OperationRun:
        with self._lock:
            with interprocess_json_lock(self._lock_path, timeout_seconds=self.lock_timeout_seconds):
                return self._load_operation_run_unlocked(operation_id)

    def list_operation_runs(self) -> tuple[OperationRun, ...]:
        with self._lock:
            with interprocess_json_lock(self._lock_path, timeout_seconds=self.lock_timeout_seconds):
                data = self._read_data()
                return tuple(
                    _operation_run_from_json(data["operation_runs"][operation_id])
                    for operation_id in sorted(data["operation_runs"])
                )

    def update_operation_run(
        self,
        run: OperationRun,
        *,
        expected_lock_version: int,
    ) -> OperationRun:
        with self._lock:
            with interprocess_json_lock(self._lock_path, timeout_seconds=self.lock_timeout_seconds):
                data = self._read_data()
                runs = data["operation_runs"]
                try:
                    current = _operation_run_from_json(runs[run.id])
                except KeyError as exc:
                    raise OperationNotFound(run.id) from exc
                if current.lock_version != expected_lock_version:
                    raise OperationLockConflict(run.id)
                stored = replace(run, lock_version=current.lock_version + 1)
                runs[stored.id] = _operation_run_to_json(stored)
                self._write_data(data)
                return stored

    def create_typed_resource(self, resource: TypedResource) -> TypedResource:
        with self._lock:
            with interprocess_json_lock(self._lock_path, timeout_seconds=self.lock_timeout_seconds):
                data = self._read_data()
                self._load_operation_run_unlocked(resource.operation_id, data=data)
                resources = data["typed_resources"]
                if resource.id in resources:
                    raise TypedResourceAlreadyExists(resource.id)
                resources[resource.id] = _typed_resource_to_json(resource)
                self._write_data(data)
                return resource

    def list_typed_resources(self, operation_id: str) -> tuple[TypedResource, ...]:
        with self._lock:
            with interprocess_json_lock(self._lock_path, timeout_seconds=self.lock_timeout_seconds):
                data = self._read_data()
                return tuple(
                    _typed_resource_from_json(data["typed_resources"][resource_id])
                    for resource_id in sorted(data["typed_resources"])
                    if data["typed_resources"][resource_id].get("operation_id")
                    == operation_id
                )

    def append_operation_event(self, event: OperationEvent) -> OperationEvent:
        with self._lock:
            with interprocess_json_lock(self._lock_path, timeout_seconds=self.lock_timeout_seconds):
                data = self._read_data()
                self._load_operation_run_unlocked(event.operation_id, data=data)
                events = data["operation_events"]
                if event.id in events:
                    raise OperationEventAlreadyExists(event.id)
                sequence = _next_event_sequence(events, operation_id=event.operation_id)
                stored = replace(event, sequence=sequence)
                events[stored.id] = _operation_event_to_json(stored)
                self._write_data(data)
                return stored

    def list_operation_events(self, operation_id: str) -> tuple[OperationEvent, ...]:
        with self._lock:
            with interprocess_json_lock(self._lock_path, timeout_seconds=self.lock_timeout_seconds):
                data = self._read_data()
                events = (
                    _operation_event_from_json(raw)
                    for raw in data["operation_events"].values()
                    if raw.get("operation_id") == operation_id
                )
                return tuple(sorted(events, key=lambda event: event.sequence))

    def create_scheduled_task(self, task: ScheduledTask) -> ScheduledTask:
        with self._lock:
            with interprocess_json_lock(self._lock_path, timeout_seconds=self.lock_timeout_seconds):
                data = self._read_data()
                tasks = data["scheduled_tasks"]
                if task.id in tasks:
                    raise ScheduledTaskAlreadyExists(task.id)
                stored = replace(task, lock_version=0)
                tasks[stored.id] = _scheduled_task_to_json(stored)
                self._write_data(data)
                return stored

    def load_scheduled_task(self, task_id: str) -> ScheduledTask:
        with self._lock:
            with interprocess_json_lock(self._lock_path, timeout_seconds=self.lock_timeout_seconds):
                return self._load_scheduled_task_unlocked(task_id)

    def list_scheduled_tasks(self) -> tuple[ScheduledTask, ...]:
        with self._lock:
            with interprocess_json_lock(self._lock_path, timeout_seconds=self.lock_timeout_seconds):
                data = self._read_data()
                return tuple(
                    _scheduled_task_from_json(data["scheduled_tasks"][task_id])
                    for task_id in sorted(data["scheduled_tasks"])
                )

    def claim_scheduled_task(
        self,
        task_id: str,
        *,
        lease_owner: str,
        lease_token: str,
        lease_seconds: int,
        now: datetime | None = None,
    ) -> ScheduledTask:
        with self._lock:
            with interprocess_json_lock(self._lock_path, timeout_seconds=self.lock_timeout_seconds):
                data = self._read_data()
                task = self._load_scheduled_task_unlocked(task_id, data=data)
                timestamp = now or _utc_now()
                if lease_seconds <= 0:
                    raise ScheduledTaskLeaseConflict(task_id)
                if task.has_active_lease(timestamp):
                    raise ScheduledTaskLeaseConflict(task_id)
                try:
                    claimed = task.claim(
                        lease_owner=lease_owner,
                        lease_token=lease_token,
                        lease_expires_at=timestamp + timedelta(seconds=lease_seconds),
                        now=timestamp,
                    )
                except ValueError as exc:
                    raise ScheduledTaskLeaseConflict(task_id) from exc
                stored = replace(claimed, lock_version=task.lock_version + 1)
                data["scheduled_tasks"][stored.id] = _scheduled_task_to_json(stored)
                self._write_data(data)
                return stored

    def complete_scheduled_task(
        self,
        task_id: str,
        *,
        lease_token: str,
        result: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> ScheduledTask:
        with self._lock:
            with interprocess_json_lock(self._lock_path, timeout_seconds=self.lock_timeout_seconds):
                data = self._read_data()
                raw = self._load_scheduled_task_json_unlocked(task_id, data=data)
                task = _scheduled_task_from_json(raw)
                if raw.get("_last_completed_lease_token") == lease_token:
                    return task
                try:
                    completed = task.complete(
                        lease_token=lease_token,
                        result=result,
                        now=now,
                    )
                except ValueError as exc:
                    raise ScheduledTaskLeaseTokenMismatch(task_id) from exc
                stored = replace(completed, lock_version=task.lock_version + 1)
                data["scheduled_tasks"][stored.id] = {
                    **_scheduled_task_to_json(stored),
                    "_last_completed_lease_token": lease_token,
                }
                self._write_data(data)
                return stored

    def fail_scheduled_task(
        self,
        task_id: str,
        *,
        lease_token: str,
        result: dict[str, Any],
        now: datetime | None = None,
    ) -> ScheduledTask:
        with self._lock:
            with interprocess_json_lock(self._lock_path, timeout_seconds=self.lock_timeout_seconds):
                data = self._read_data()
                task = self._load_scheduled_task_unlocked(task_id, data=data)
                try:
                    failed = task.fail(
                        lease_token=lease_token,
                        result=result,
                        now=now,
                    )
                except ValueError as exc:
                    raise ScheduledTaskLeaseTokenMismatch(task_id) from exc
                stored = replace(failed, lock_version=task.lock_version + 1)
                data["scheduled_tasks"][stored.id] = _scheduled_task_to_json(stored)
                self._write_data(data)
                return stored

    def cancel_scheduled_task(
        self,
        task_id: str,
        *,
        now: datetime | None = None,
    ) -> ScheduledTask:
        with self._lock:
            with interprocess_json_lock(self._lock_path, timeout_seconds=self.lock_timeout_seconds):
                data = self._read_data()
                task = self._load_scheduled_task_unlocked(task_id, data=data)
                cancelled = task.cancel(now=now)
                stored = replace(cancelled, lock_version=task.lock_version + 1)
                data["scheduled_tasks"][stored.id] = _scheduled_task_to_json(stored)
                self._write_data(data)
                return stored

    def _resolve_admission_write_failure(
        self,
        envelope: LaunchEnvelope,
        prior_operation: OperationRun | None,
    ) -> LaunchStoreResult:
        """Resolve a replacement exception without ever issuing a rollback."""

        data = self._read_data()
        operation = _operation_run_from_json(data["operation_runs"][envelope.operation_id]) if envelope.operation_id in data["operation_runs"] else None
        raw = data["operation_events"].get(_launch_admission_event_id(envelope))
        if operation is not None and raw is not None and _admission_event_matches(
            _operation_event_from_json(raw), envelope
        ):
            return LaunchStoreResult(
                LaunchResult.ACCEPTED,
                LaunchReason.REPLAY,
                operation,
                envelope,
            )
        if operation is None and raw is None:
            raise
        return _launch_store_unknown(envelope, operation or prior_operation)

    def _resolve_acceptance_write_failure(
        self,
        envelope: LaunchEnvelope,
        process_resource: TypedResource,
        owner: str,
        owner_evidence: dict[str, Any],
        prior_operation: OperationRun,
    ) -> LaunchStoreResult:
        """Read back the exact accepted identity after a commit-unknown error."""

        data = self._read_data()
        raw_operation = data["operation_runs"].get(envelope.operation_id)
        raw_event = data["operation_events"].get(_launch_acceptance_event_id(envelope))
        raw_resource = data["typed_resources"].get(_launch_process_resource_id(envelope))
        if raw_operation is None or raw_event is None or raw_resource is None:
            if raw_event is None and raw_resource is None and raw_operation is not None:
                operation = _operation_run_from_json(raw_operation)
                if operation.state is OperationState.PENDING:
                    raise
            return _launch_store_unknown(
                envelope,
                _operation_run_from_json(raw_operation) if raw_operation is not None else prior_operation,
            )
        operation = _operation_run_from_json(raw_operation)
        resource = _typed_resource_from_json(raw_resource)
        event = _operation_event_from_json(raw_event)
        if operation.state is OperationState.RUNNING and _acceptance_matches(
            event, resource, envelope, process_resource, owner, owner_evidence
        ):
            return LaunchStoreResult(
                LaunchResult.ACCEPTED,
                LaunchReason.REPLAY,
                operation,
                envelope,
                resource,
            )
        return _launch_store_unknown(envelope, operation, resource)

    def claim_due_scheduled_tasks(
        self,
        owner_id: str,
        task_types: tuple[str, ...],
        *,
        lease_owner: str,
        lease_seconds: int,
        max_count: int,
        now: datetime | None = None,
    ) -> tuple[ScheduledTask, ...]:
        """Atomically claim up to ``max_count`` due scheduled tasks.

        Tasks are filtered by ``owner_id`` and ``task_types`` and must be
        claimable at ``now``.  Each claimed task receives a unique lease token.
        """

        with self._lock:
            with interprocess_json_lock(self._lock_path, timeout_seconds=self.lock_timeout_seconds):
                data = self._read_data()
                timestamp = now or _utc_now()
                due_tasks = [
                    (task_id, _scheduled_task_from_json(raw))
                    for task_id, raw in data["scheduled_tasks"].items()
                ]
                due_tasks = [
                    (task_id, task)
                    for task_id, task in due_tasks
                    if task.owner_id == owner_id
                    and task.task_type in task_types
                    and task.is_claimable(timestamp)
                ]
                due_tasks.sort(key=lambda item: (item[1].next_run_at or timestamp, item[0]))
                claimed: list[ScheduledTask] = []
                for task_id, task in due_tasks[:max_count]:
                    lease_token = f"{lease_owner}:{task_id}:{uuid.uuid4().hex}"
                    claimed_task = task.claim(
                        lease_owner=lease_owner,
                        lease_token=lease_token,
                        lease_expires_at=timestamp + timedelta(seconds=lease_seconds),
                        now=timestamp,
                    )
                    stored = replace(claimed_task, lock_version=task.lock_version + 1)
                    data["scheduled_tasks"][task_id] = _scheduled_task_to_json(stored)
                    claimed.append(stored)
                self._write_data(data)
                return tuple(sorted(claimed, key=lambda task: task.id))

    def heartbeat_scheduled_task(
        self,
        task_id: str,
        lease_token: str,
        *,
        lease_seconds: int,
        now: datetime | None = None,
    ) -> ScheduledTask:
        """Extend the lease of an actively leased scheduled task."""

        with self._lock:
            with interprocess_json_lock(self._lock_path, timeout_seconds=self.lock_timeout_seconds):
                data = self._read_data()
                task = self._load_scheduled_task_unlocked(task_id, data=data)
                timestamp = now or _utc_now()
                if task.state is not ScheduledTaskState.LEASED:
                    raise ScheduledTaskLeaseTokenMismatch(task_id)
                if task.lease_token != lease_token:
                    raise ScheduledTaskLeaseTokenMismatch(task_id)
                if not task.has_active_lease(timestamp):
                    raise ScheduledTaskLeaseConflict(task_id)
                stored = replace(
                    task,
                    lease_expires_at=timestamp + timedelta(seconds=lease_seconds),
                    updated_at=timestamp,
                    lock_version=task.lock_version + 1,
                )
                data["scheduled_tasks"][task_id] = _scheduled_task_to_json(stored)
                self._write_data(data)
                return stored

    def _load_operation_run_unlocked(
        self,
        operation_id: str,
        *,
        data: dict[str, dict[str, dict[str, Any]]] | None = None,
    ) -> OperationRun:
        data = data or self._read_data()
        try:
            return _operation_run_from_json(data["operation_runs"][operation_id])
        except KeyError as exc:
            raise OperationNotFound(operation_id) from exc

    def _load_scheduled_task_unlocked(
        self,
        task_id: str,
        *,
        data: dict[str, dict[str, dict[str, Any]]] | None = None,
    ) -> ScheduledTask:
        raw = self._load_scheduled_task_json_unlocked(task_id, data=data)
        return _scheduled_task_from_json(raw)

    def _load_scheduled_task_json_unlocked(
        self,
        task_id: str,
        *,
        data: dict[str, dict[str, dict[str, Any]]] | None = None,
    ) -> dict[str, Any]:
        data = data or self._read_data()
        try:
            return data["scheduled_tasks"][task_id]
        except KeyError as exc:
            raise ScheduledTaskNotFound(task_id) from exc

    def _read_data(self) -> dict[str, dict[str, dict[str, Any]]]:
        if not self._path.exists():
            return {
                "operation_runs": {},
                "typed_resources": {},
                "operation_events": {},
                "scheduled_tasks": {},
            }
        with self._path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        data = {
            "operation_runs": raw.get("operation_runs", {}),
            "typed_resources": raw.get("typed_resources", {}),
            "operation_events": raw.get("operation_events", {}),
            "scheduled_tasks": raw.get("scheduled_tasks", {}),
        }
        for key, value in data.items():
            if not isinstance(value, dict):
                raise ValueError(f"{key} must be a JSON object")
        return data

    def _write_data(self, data: dict[str, dict[str, dict[str, Any]]]) -> None:
        write_json_atomically(self._path, data)


_PROCESS_LOCKS_GUARD = Lock()
_PROCESS_LOCKS: dict[Path, RLock] = {}


def _process_lock_for(path: Path) -> RLock:
    resolved = path.resolve()
    with _PROCESS_LOCKS_GUARD:
        lock = _PROCESS_LOCKS.get(resolved)
        if lock is None:
            lock = RLock()
            _PROCESS_LOCKS[resolved] = lock
        return lock


@contextmanager
def interprocess_json_lock(
    lock_path: Path,
    *,
    timeout_seconds: float = 30.0,
    poll_seconds: float = 0.05,
) -> Iterator[None]:
    """Acquire a process-local and flock-backed lock for shared JSON state."""

    lock_path.parent.mkdir(parents=True, exist_ok=True)
    process_lock = _process_lock_for(lock_path)
    with process_lock:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            deadline = time.monotonic() + timeout_seconds
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"timed out acquiring lock {lock_path}")
                    time.sleep(poll_seconds)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def write_json_atomically(path: Path, data: Any) -> None:
    """Write JSON through a unique temp path before replacing ``path``."""

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        tmp_path.replace(path)
    finally:
        tmp_path.unlink(missing_ok=True)


@runtime_checkable
class DurableOpsStore(Protocol):
    """Operation-run current-state, resource, and event store."""

    def create_operation_run(self, run: OperationRun) -> OperationRun:  # pragma: no cover - protocol
        ...

    def load_operation_run(self, operation_id: str) -> OperationRun:  # pragma: no cover - protocol
        ...

    def list_operation_runs(self) -> tuple[OperationRun, ...]:  # pragma: no cover - protocol
        ...

    def update_operation_run(
        self,
        run: OperationRun,
        *,
        expected_lock_version: int,
    ) -> OperationRun:  # pragma: no cover - protocol
        ...

    def create_typed_resource(self, resource: TypedResource) -> TypedResource:  # pragma: no cover - protocol
        ...

    def list_typed_resources(self, operation_id: str) -> tuple[TypedResource, ...]:  # pragma: no cover - protocol
        ...

    def append_operation_event(self, event: OperationEvent) -> OperationEvent:  # pragma: no cover - protocol
        ...

    def list_operation_events(self, operation_id: str) -> tuple[OperationEvent, ...]:  # pragma: no cover - protocol
        ...

    def create_scheduled_task(self, task: ScheduledTask) -> ScheduledTask:  # pragma: no cover - protocol
        ...

    def load_scheduled_task(self, task_id: str) -> ScheduledTask:  # pragma: no cover - protocol
        ...

    def list_scheduled_tasks(self) -> tuple[ScheduledTask, ...]:  # pragma: no cover - protocol
        ...

    def claim_scheduled_task(
        self,
        task_id: str,
        *,
        lease_owner: str,
        lease_token: str,
        lease_seconds: int,
        now: datetime | None = None,
    ) -> ScheduledTask:  # pragma: no cover - protocol
        ...

    def complete_scheduled_task(
        self,
        task_id: str,
        *,
        lease_token: str,
        result: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> ScheduledTask:  # pragma: no cover - protocol
        ...

    def fail_scheduled_task(
        self,
        task_id: str,
        *,
        lease_token: str,
        result: dict[str, Any],
        now: datetime | None = None,
    ) -> ScheduledTask:  # pragma: no cover - protocol
        ...

    def cancel_scheduled_task(
        self,
        task_id: str,
        *,
        now: datetime | None = None,
    ) -> ScheduledTask:  # pragma: no cover - protocol
        ...


_LAUNCH_ADMISSION_EVENT = "launch.admitted"
_LAUNCH_ACCEPTANCE_EVENT = "launch.accepted"


def _coerce_launch_envelope(envelope: LaunchEnvelope) -> LaunchEnvelope:
    if not isinstance(envelope, LaunchEnvelope):
        raise TypeError("envelope must be a LaunchEnvelope")
    return envelope


def _launch_admission_event_id(envelope: LaunchEnvelope) -> str:
    return f"launch-admission:{envelope.operation_id}:{envelope.request_id}"


def _launch_acceptance_event_id(envelope: LaunchEnvelope) -> str:
    return f"launch-acceptance:{envelope.operation_id}:{envelope.request_id}"


def _launch_process_resource_id(envelope: LaunchEnvelope) -> str:
    return f"launch-process-session:{envelope.operation_id}:{envelope.request_id}"


def _launch_admission_payload(envelope: LaunchEnvelope) -> dict[str, Any]:
    return {
        "version": envelope.version,
        "request_id": envelope.request_id,
        "envelope_digest": envelope.digest,
        "envelope": envelope.to_json(),
    }


def _launch_acceptance_payload(
    envelope: LaunchEnvelope,
    resource: TypedResource,
    *,
    owner: str,
    owner_evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "version": envelope.version,
        "request_id": envelope.request_id,
        "envelope_digest": envelope.digest,
        "process_resource_id": resource.id,
        "process_session_identity": resource.details.get("process_session_identity"),
        "owner": owner,
        "owner_evidence": dict(owner_evidence),
    }


def _admission_event_matches(event: OperationEvent, envelope: LaunchEnvelope) -> bool:
    payload = event.payload
    return (
        event.id == _launch_admission_event_id(envelope)
        and event.operation_id == envelope.operation_id
        and event.event_type == _LAUNCH_ADMISSION_EVENT
        and payload.get("version") == envelope.version
        and payload.get("request_id") == envelope.request_id
        and payload.get("envelope_digest") == envelope.digest
        and payload.get("envelope") == envelope.to_json()
    )


def _canonical_process_resource(
    resource: TypedResource,
    envelope: LaunchEnvelope,
    *,
    owner: str,
) -> TypedResource:
    details = dict(resource.details)
    process_session_identity = details.get("process_session_identity", resource.id)
    if not isinstance(process_session_identity, str) or not process_session_identity:
        raise ValueError("process_session_identity must be a non-empty string")
    details.update(
        {
            "launch_operation_id": envelope.operation_id,
            "launch_request_id": envelope.request_id,
            "launch_envelope_digest": envelope.digest,
            "process_session_identity": process_session_identity,
            "owner": owner,
        }
    )
    return TypedResource(
        id=_launch_process_resource_id(envelope),
        operation_id=envelope.operation_id,
        resource_type=ResourceType.PROCESS_SESSION,
        name=resource.name,
        details=details,
        created_at=resource.created_at,
        updated_at=resource.updated_at,
    )


def _resource_matches(expected: TypedResource, candidate: TypedResource) -> bool:
    """Compare persisted resource identity without treating timestamps as identity."""

    return (
        expected.id == candidate.id
        and expected.operation_id == candidate.operation_id
        and expected.resource_type is candidate.resource_type
        and expected.name == candidate.name
        and dict(expected.details) == dict(candidate.details)
    )


def _acceptance_event_matches(
    event: OperationEvent,
    resource: TypedResource,
    envelope: LaunchEnvelope,
    candidate_resource: TypedResource,
    owner: str,
    owner_evidence: dict[str, Any],
) -> bool:
    """Validate the accepted event against the exact canonical resource facts."""

    return _acceptance_matches(
        event,
        resource,
        envelope,
        candidate_resource,
        owner,
        owner_evidence,
    )


def _acceptance_matches(
    event: OperationEvent,
    resource: TypedResource,
    envelope: LaunchEnvelope,
    candidate_resource: TypedResource,
    owner: str,
    owner_evidence: dict[str, Any],
) -> bool:
    expected_identity = candidate_resource.details.get(
        "process_session_identity", candidate_resource.id
    )
    candidate_details = dict(candidate_resource.details)
    stored_details = dict(resource.details)
    for generated_key in (
        "launch_operation_id",
        "launch_request_id",
        "launch_envelope_digest",
        "process_session_identity",
        "owner",
    ):
        candidate_details.pop(generated_key, None)
        stored_details.pop(generated_key, None)
    return (
        resource.id == _launch_process_resource_id(envelope)
        and resource.operation_id == envelope.operation_id
        and resource.resource_type is ResourceType.PROCESS_SESSION
        and resource.details.get("process_session_identity") == expected_identity
        and resource.details.get("launch_envelope_digest") == envelope.digest
        and resource.details.get("owner") == owner
        and resource.name == candidate_resource.name
        and stored_details == candidate_details
        and event.id == _launch_acceptance_event_id(envelope)
        and event.operation_id == envelope.operation_id
        and event.event_type == _LAUNCH_ACCEPTANCE_EVENT
        and event.payload.get("version") == envelope.version
        and event.payload.get("request_id") == envelope.request_id
        and event.payload.get("envelope_digest") == envelope.digest
        and event.payload.get("process_resource_id") == resource.id
        and event.payload.get("process_session_identity") == expected_identity
        and event.payload.get("owner") == owner
        and event.payload.get("owner_evidence") == dict(owner_evidence)
    )


def _launch_store_conflict(
    envelope: LaunchEnvelope,
    operation: OperationRun | None,
    process_resource: TypedResource | None = None,
) -> LaunchStoreResult:
    if operation is None:
        operation = OperationRun(
            id=envelope.operation_id,
            operation_type="launch",
            state=OperationState.PENDING,
            idempotency_key=envelope.request_id,
        )
    return LaunchStoreResult(
        LaunchResult.CONFLICT,
        LaunchReason.REQUEST_CONFLICT,
        operation,
        envelope,
        process_resource,
    )


def _launch_store_unknown(
    envelope: LaunchEnvelope,
    operation: OperationRun | None,
    process_resource: TypedResource | None = None,
) -> LaunchStoreResult:
    if operation is None:
        operation = OperationRun(
            id=envelope.operation_id,
            operation_type="launch",
            state=OperationState.PENDING,
            idempotency_key=envelope.request_id,
        )
    return LaunchStoreResult(
        LaunchResult.UNKNOWN,
        LaunchReason.DISPATCH_UNCERTAIN,
        operation,
        envelope,
        process_resource,
    )


def _operation_run_to_json(run: OperationRun) -> dict[str, Any]:
    return {
        "id": run.id,
        "operation_type": run.operation_type,
        "state": run.state.value,
        "parent_operation_id": run.parent_operation_id,
        "operation_dir": run.operation_dir,
        "retry": {
            "attempt": run.retry.attempt,
            "max_attempts": run.retry.max_attempts,
            "last_error": run.retry.last_error,
        },
        "idempotency_key": run.idempotency_key,
        "metadata": dict(run.metadata),
        "created_at": _datetime_to_json(run.created_at),
        "updated_at": _datetime_to_json(run.updated_at),
        "started_at": _datetime_to_json(run.started_at),
        "completed_at": _datetime_to_json(run.completed_at),
        "lock_version": run.lock_version,
    }


def _operation_run_from_json(data: dict[str, Any]) -> OperationRun:
    retry_data = data.get("retry", {})
    return OperationRun(
        id=data["id"],
        operation_type=data["operation_type"],
        state=OperationState(data["state"]),
        parent_operation_id=data.get("parent_operation_id"),
        operation_dir=data.get("operation_dir"),
        retry=RetryMetadata(
            attempt=retry_data.get("attempt", 0),
            max_attempts=retry_data.get("max_attempts", 1),
            last_error=retry_data.get("last_error"),
        ),
        idempotency_key=data.get("idempotency_key"),
        metadata=data.get("metadata", {}),
        created_at=_datetime_from_json(data["created_at"]),
        updated_at=_datetime_from_json(data["updated_at"]),
        started_at=_datetime_from_json(data.get("started_at")),
        completed_at=_datetime_from_json(data.get("completed_at")),
        lock_version=data.get("lock_version", 0),
    )


def _typed_resource_to_json(resource: TypedResource) -> dict[str, Any]:
    return {
        "id": resource.id,
        "operation_id": resource.operation_id,
        "resource_type": resource.resource_type.value,
        "name": resource.name,
        "details": dict(resource.details),
        "created_at": _datetime_to_json(resource.created_at),
        "updated_at": _datetime_to_json(resource.updated_at),
    }


def _typed_resource_from_json(data: dict[str, Any]) -> TypedResource:
    return TypedResource(
        id=data["id"],
        operation_id=data["operation_id"],
        resource_type=ResourceType(data["resource_type"]),
        name=data["name"],
        details=data.get("details", {}),
        created_at=_datetime_from_json(data["created_at"]),
        updated_at=_datetime_from_json(data["updated_at"]),
    )


def _operation_event_to_json(event: OperationEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "operation_id": event.operation_id,
        "sequence": event.sequence,
        "event_type": event.event_type,
        "summary": event.summary,
        "payload": dict(event.payload),
        "artifact_paths": list(event.artifact_paths),
        "debug_paths": list(event.debug_paths),
        "occurred_at": _datetime_to_json(event.occurred_at),
    }


def _operation_event_from_json(data: dict[str, Any]) -> OperationEvent:
    return OperationEvent(
        id=data["id"],
        operation_id=data["operation_id"],
        sequence=data.get("sequence", 0),
        event_type=data["event_type"],
        summary=data["summary"],
        payload=data.get("payload", {}),
        artifact_paths=tuple(data.get("artifact_paths", ())),
        debug_paths=tuple(data.get("debug_paths", ())),
        occurred_at=_datetime_from_json(data["occurred_at"]),
    )


def _scheduled_task_to_json(task: ScheduledTask) -> dict[str, Any]:
    return {
        "id": task.id,
        "task_type": task.task_type,
        "owner_id": task.owner_id,
        "state": task.state.value,
        "operation_id": task.operation_id,
        "schedule": task.schedule,
        "recurring_interval_seconds": task.recurring_interval_seconds,
        "retry_delay_seconds": task.retry_delay_seconds,
        "jitter_seconds": task.jitter_seconds,
        "payload": dict(task.payload),
        "next_run_at": _datetime_to_json(task.next_run_at),
        "last_result": None if task.last_result is None else dict(task.last_result),
        "failure_count": task.failure_count,
        "max_failures": task.max_failures,
        "lease_owner": task.lease_owner,
        "lease_token": task.lease_token,
        "lease_expires_at": _datetime_to_json(task.lease_expires_at),
        "idempotency_key": task.idempotency_key,
        "created_at": _datetime_to_json(task.created_at),
        "updated_at": _datetime_to_json(task.updated_at),
        "lock_version": task.lock_version,
    }


def _scheduled_task_from_json(data: dict[str, Any]) -> ScheduledTask:
    return ScheduledTask(
        id=data["id"],
        task_type=data["task_type"],
        owner_id=data["owner_id"],
        state=ScheduledTaskState(data["state"]),
        operation_id=data.get("operation_id"),
        schedule=data.get("schedule"),
        recurring_interval_seconds=data.get("recurring_interval_seconds"),
        retry_delay_seconds=data.get("retry_delay_seconds"),
        jitter_seconds=data.get("jitter_seconds", 0),
        payload=data.get("payload", {}),
        next_run_at=_datetime_from_json(data.get("next_run_at")),
        last_result=data.get("last_result"),
        failure_count=data.get("failure_count", 0),
        max_failures=data.get("max_failures", 1),
        lease_owner=data.get("lease_owner"),
        lease_token=data.get("lease_token"),
        lease_expires_at=_datetime_from_json(data.get("lease_expires_at")),
        idempotency_key=data.get("idempotency_key"),
        created_at=_datetime_from_json(data["created_at"]),
        updated_at=_datetime_from_json(data["updated_at"]),
        lock_version=data.get("lock_version", 0),
    )


def _next_event_sequence(
    events: dict[str, dict[str, Any]],
    *,
    operation_id: str,
) -> int:
    sequences = [
        raw.get("sequence", 0)
        for raw in events.values()
        if raw.get("operation_id") == operation_id
    ]
    return max(sequences, default=0) + 1


def _datetime_to_json(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat()


def _datetime_from_json(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value)


def _utc_now() -> datetime:
    return datetime.now(UTC)
