"""Shared WBC adapter for the common worker-dispatch path."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
from types import MappingProxyType
from typing import Any, Callable, Mapping, TypeVar

from arnold.workflow.execution_attempt_ledger import AttemptEventType, LedgerEvent

from .action_validator import ActionBoundaryContext
from .wbc_runtime import ImmutableAttemptArtifacts, RuntimeProducerResult, WbcRuntimeProducerFacade

COMMON_WORKER_DISPATCH_WRITER_ID = "megaplan.common_worker_dispatch"
COMMON_WORKER_DISPATCH_SURFACE = "megaplan.common_worker_dispatch"
COMMON_WORKER_DISPATCH_START_SOURCE_LOOKUP_KEY = "common_worker_dispatch:start"
COMMON_WORKER_DISPATCH_COMPLETE_SOURCE_LOOKUP_KEY = "common_worker_dispatch:complete"
COMMON_WORKER_DISPATCH_FAILURE_SOURCE_LOOKUP_KEY = "common_worker_dispatch:failure"

_ResultT = TypeVar("_ResultT")


def _freeze_json(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze_json(value[key]) for key in sorted(value)})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    return value


def _freeze_mapping(value: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if not value:
        return MappingProxyType({})
    return MappingProxyType({str(key): _freeze_json(item) for key, item in sorted(value.items())})


class PostLaunchIndeterminateError(RuntimeError):
    """Raised when post-launch certification fails after worker code already ran."""

    def __init__(
        self,
        message: str,
        *,
        worker_result: Any,
        terminal_result: RuntimeProducerResult,
    ) -> None:
        super().__init__(message)
        self.worker_result = worker_result
        self.terminal_result = terminal_result


@dataclass
class SpawnedChildControl:
    """One same-authority spawn registration/signal handle.

    WBC owns the certification append; ``delegate`` is the already-bound
    controlled-launch authority.  The object is callable only for legacy
    callback compatibility, while production timeout code must use its
    ``signal_ladder`` method.
    """

    register_impl: Callable[[Mapping[str, Any]], Any]
    delegate: Any = None
    signal_impl: Callable[..., Any] | None = None
    handoff_impl: Callable[..., Any] | None = None
    production: bool = True

    def register(self, registration: Mapping[str, Any]) -> Any:
        result = self.register_impl(registration)
        delegated = getattr(self.delegate, "register", None) or getattr(self.delegate, "register_spawned_child", None)
        if callable(delegated):
            delegated(registration)
        elif self.production and self.delegate is not None:
            raise RuntimeError("production spawn control has no bound registration authority")
        return result

    def signal_ladder(self, process: Any = None, **kwargs: Any) -> Any:
        if callable(self.signal_impl):
            return self.signal_impl(process, **kwargs)
        ladder = getattr(self.delegate, "signal_ladder", None)
        if not callable(ladder):
            return False
        return ladder(process, **kwargs)

    def handoff_spawn_cleanup(self, process: Any = None, **kwargs: Any) -> Any:
        """Transfer cleanup custody to the same bound launch authority."""
        if callable(self.handoff_impl):
            hold = process
            actual_process = getattr(hold, "process", hold)
            if actual_process is not hold and callable(getattr(actual_process, "poll", None)):
                metadata = hold.to_dict() if callable(getattr(hold, "to_dict", None)) else {}
                kwargs.setdefault("hold_metadata", metadata)
                result = self.handoff_impl(actual_process, **kwargs)
                if isinstance(result, Mapping):
                    handoff_id = result.get("handoff_id") or (result.get("handoff") or {}).get("handoff_id")
                    if handoff_id:
                        if hasattr(hold, "spawn_event_id"):
                            hold.spawn_event_id = str(handoff_id)
                        outcome = getattr(hold, "dispatch_outcome", None)
                        if isinstance(outcome, dict):
                            outcome["reconciliation_event_id"] = str(handoff_id)
                return result
            return self.handoff_impl(process, **kwargs)
        handoff = getattr(self.delegate, "handoff_spawn_cleanup", None)
        if callable(handoff):
            return handoff(process, **kwargs)
        return {"state": "unresolved", "reason": "spawn cleanup authority is not bound"}

    def __call__(self, registration: Mapping[str, Any]) -> Any:
        return self.register(registration)


@dataclass(frozen=True)
class CommonWorkerDispatchResult:
    reserve: RuntimeProducerResult
    start: RuntimeProducerResult
    terminal: RuntimeProducerResult
    worker_result: Any
    diagnostics: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "diagnostics", _freeze_mapping(self.diagnostics))


@dataclass(frozen=True)
class CommonWorkerDispatchSpec:
    facade: WbcRuntimeProducerFacade
    attempt_id: str
    start_event: LedgerEvent
    success_event_factory: Callable[[Any], LedgerEvent]
    failure_event_factory: Callable[[BaseException], LedgerEvent]
    start_action_context: ActionBoundaryContext
    success_action_context: ActionBoundaryContext
    failure_action_context: ActionBoundaryContext
    artifacts: ImmutableAttemptArtifacts | None = None
    post_dispatch_certificate: Callable[[Any], None] | None = None
    indeterminate_event_factory: Callable[[BaseException], LedgerEvent] | None = None
    authority_check: Callable[[str], Mapping[str, Any]] | None = None
    writer_id: str = COMMON_WORKER_DISPATCH_WRITER_ID
    surface_name: str = COMMON_WORKER_DISPATCH_SURFACE
    expected_source_version: str = "source.v1"
    start_source_lookup_key: str = COMMON_WORKER_DISPATCH_START_SOURCE_LOOKUP_KEY
    success_source_lookup_key: str = COMMON_WORKER_DISPATCH_COMPLETE_SOURCE_LOOKUP_KEY
    failure_source_lookup_key: str = COMMON_WORKER_DISPATCH_FAILURE_SOURCE_LOOKUP_KEY

    def run(
        self,
        dispatch: Callable[[RuntimeProducerResult], _ResultT],
        *,
        context: Any | None = None,
    ) -> CommonWorkerDispatchResult:
        reserve = self.facade.reserve_attempt(
            attempt_id=self.attempt_id,
            writer_id=self.writer_id,
            surface_name=self.surface_name,
            source_lookup_key=self.start_source_lookup_key,
            expected_source_version=self.expected_source_version,
            action_context=self.start_action_context,
            artifacts=self.artifacts,
        )
        start = self.facade.start_attempt(
            attempt_id=self.attempt_id,
            event=self.start_event,
            writer_id=self.writer_id,
            surface_name=self.surface_name,
            source_lookup_key=self.start_source_lookup_key,
            expected_source_version=self.expected_source_version,
            action_context=self.start_action_context,
            artifacts=self.artifacts,
        )

        registered_identity: dict[str, Any] | None = None
        registered_result: RuntimeProducerResult | None = None

        def register_spawned_child(registration: Mapping[str, Any]) -> RuntimeProducerResult:
            """Append one idempotent child-certification evidence event.

            This callback is process-local and is exposed only on the runtime
            result passed to the already-admitted dispatch closure.  It cannot
            reserve or start another attempt.
            """
            if not isinstance(registration, Mapping):
                raise ValueError("spawned child registration must be a mapping")
            identity = registration.get("worker_identity")
            if not isinstance(identity, Mapping):
                raise ValueError("spawned child registration requires worker_identity")
            identity = dict(identity)
            nonlocal registered_identity
            nonlocal registered_result
            if registered_identity is not None and registered_identity != identity:
                raise ValueError("spawned child registration conflicts with prior identity")
            if registered_result is not None:
                return registered_result
            registered_identity = identity
            for name in ("host", "pid", "boot_id"):
                if not identity.get(name):
                    raise ValueError(f"spawned child worker_identity.{name} is required")
            if isinstance(identity.get("pid"), bool) or not isinstance(identity.get("pid"), int) or identity["pid"] <= 0:
                raise ValueError("spawned child worker_identity.pid must be positive")
            payload_registration = dict(registration)
            payload_registration["worker_identity"] = identity
            payload_registration.setdefault("attempt_id", self.attempt_id)
            payload_registration.setdefault("writer_id", self.writer_id)
            payload_registration.setdefault("surface_name", self.surface_name)
            if context is not None:
                receipt_id = getattr(context, "admission_receipt_id", None)
                fingerprint = getattr(context, "semantic_dispatch_fingerprint", None)
                if receipt_id:
                    payload_registration.setdefault("admission_receipt_id", receipt_id)
                if fingerprint:
                    payload_registration.setdefault("semantic_dispatch_fingerprint", fingerprint)
            canonical = json.dumps(payload_registration, sort_keys=True, separators=(",", ":"), default=str)
            started_at = str(payload_registration.get("started_at") or datetime.now(timezone.utc).isoformat())
            event = replace(
                self.start_event,
                idempotency_key=f"{self.attempt_id}:spawn-certification",
                event_type=AttemptEventType.EXTERNAL_EFFECT_INTENT,
                sequence=2,
                causal_predecessor_sequence=1,
                append_position=0,
                occurred_at=started_at,
                observed_at=started_at,
                payload={
                    "certification_kind": "spawned_child",
                    "registration": payload_registration,
                    "registration_fingerprint": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
                },
            )
            result = self.facade.certify_spawned_child(
                attempt_id=self.attempt_id,
                event=event,
                writer_id=self.writer_id,
                surface_name=self.surface_name,
                source_lookup_key=self.start_source_lookup_key,
                expected_source_version=self.expected_source_version,
                action_context=self.start_action_context,
                artifacts=self.artifacts,
            )
            registered_result = result
            append_result = getattr(result, "append_result", None)
            certified_event = getattr(append_result, "event", None)
            certification_id = getattr(certified_event, "idempotency_key", None)
            if certification_id:
                payload_registration["spawn_certification_id"] = certification_id
            outer_callback = getattr(context, "spawn_registration_callback", None)
            if callable(outer_callback):
                outer_callback(payload_registration)
            return result

        outer_control = getattr(context, "spawn_registration_callback", None)
        control = SpawnedChildControl(
            register_impl=register_spawned_child,
            delegate=outer_control,
            production=bool(getattr(context, "production_intent", True)),
        )
        start = replace(start, spawn_registration_callback=control)
        if self.authority_check is not None:
            try:
                self.authority_check("provider_dispatch")
            except BaseException as exc:
                terminal = self.facade.fail_attempt(
                    attempt_id=self.attempt_id,
                    event=self.failure_event_factory(exc),
                    writer_id=self.writer_id,
                    surface_name=self.surface_name,
                    source_lookup_key=self.failure_source_lookup_key,
                    expected_source_version=self.expected_source_version,
                    action_context=self.failure_action_context,
                    artifacts=self.artifacts,
                )
                raise exc from _FailureEvidenceRecorded(terminal)
        try:
            worker_result = dispatch(start)
        except BaseException as exc:
            if self.authority_check is not None:
                try:
                    self.authority_check("worker_failure_terminal")
                except BaseException as authority_exc:
                    terminal = self.facade.fail_attempt(
                        attempt_id=self.attempt_id,
                        event=self.failure_event_factory(authority_exc),
                        writer_id=self.writer_id,
                        surface_name=self.surface_name,
                        source_lookup_key=self.failure_source_lookup_key,
                        expected_source_version=self.expected_source_version,
                        action_context=self.failure_action_context,
                        artifacts=self.artifacts,
                    )
                    raise exc from _FailureEvidenceRecorded(terminal)
            terminal = self.facade.fail_attempt(
                attempt_id=self.attempt_id,
                event=self.failure_event_factory(exc),
                writer_id=self.writer_id,
                surface_name=self.surface_name,
                source_lookup_key=self.failure_source_lookup_key,
                expected_source_version=self.expected_source_version,
                action_context=self.failure_action_context,
                artifacts=self.artifacts,
            )
            raise exc from _FailureEvidenceRecorded(terminal)

        worker = worker_result[0] if isinstance(worker_result, tuple) and len(worker_result) == 4 else worker_result
        worker_identity = getattr(worker, "worker_identity", None)
        if registered_identity is not None and worker_identity != registered_identity:
            raise ValueError("terminal worker identity does not match registered spawned child")

        if self.post_dispatch_certificate is not None:
            try:
                self.post_dispatch_certificate(worker_result)
            except BaseException as exc:
                if self.authority_check is not None:
                    try:
                        self.authority_check("worker_indeterminate_terminal")
                    except BaseException as authority_exc:
                        exc = authority_exc
                terminal = self.facade.fail_attempt(
                    attempt_id=self.attempt_id,
                    event=(self.indeterminate_event_factory or self.failure_event_factory)(exc),
                    writer_id=self.writer_id,
                    surface_name=self.surface_name,
                    source_lookup_key=self.failure_source_lookup_key,
                    expected_source_version=self.expected_source_version,
                    action_context=self.failure_action_context,
                    artifacts=self.artifacts,
                )
                raise PostLaunchIndeterminateError(
                    "post-launch certification failed after worker dispatch",
                    worker_result=worker_result,
                    terminal_result=terminal,
                ) from exc

        if self.authority_check is not None:
            try:
                self.authority_check("worker_success_terminal")
            except BaseException as exc:
                terminal = self.facade.fail_attempt(
                    attempt_id=self.attempt_id,
                    event=(self.indeterminate_event_factory or self.failure_event_factory)(exc),
                    writer_id=self.writer_id,
                    surface_name=self.surface_name,
                    source_lookup_key=self.failure_source_lookup_key,
                    expected_source_version=self.expected_source_version,
                    action_context=self.failure_action_context,
                    artifacts=self.artifacts,
                )
                raise PostLaunchIndeterminateError(
                    "child authority changed after worker dispatch",
                    worker_result=worker_result,
                    terminal_result=terminal,
                ) from exc
        terminal = self.facade.complete_attempt(
            attempt_id=self.attempt_id,
            event=self.success_event_factory(worker_result),
            writer_id=self.writer_id,
            surface_name=self.surface_name,
            source_lookup_key=self.success_source_lookup_key,
            expected_source_version=self.expected_source_version,
            action_context=self.success_action_context,
            artifacts=self.artifacts,
        )
        return CommonWorkerDispatchResult(
            reserve=reserve,
            start=start,
            terminal=terminal,
            worker_result=worker_result,
            diagnostics={
                "writer_id": self.writer_id,
                "surface_name": self.surface_name,
                "attempt_id": self.attempt_id,
            },
        )


class _FailureEvidenceRecorded(Exception):
    """Internal marker used only to preserve the original failure cause."""

    def __init__(self, terminal_result: RuntimeProducerResult) -> None:
        super().__init__("failure evidence recorded")
        self.terminal_result = terminal_result


__all__ = [
    "COMMON_WORKER_DISPATCH_COMPLETE_SOURCE_LOOKUP_KEY",
    "COMMON_WORKER_DISPATCH_FAILURE_SOURCE_LOOKUP_KEY",
    "COMMON_WORKER_DISPATCH_START_SOURCE_LOOKUP_KEY",
    "COMMON_WORKER_DISPATCH_SURFACE",
    "COMMON_WORKER_DISPATCH_WRITER_ID",
    "CommonWorkerDispatchResult",
    "CommonWorkerDispatchSpec",
    "PostLaunchIndeterminateError",
    "SpawnedChildControl",
]
