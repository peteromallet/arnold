"""Neutral launch identity and admission contracts.

This module deliberately contains no persistence or transport code.  It owns
the immutable request identity that the durable-ops store and venue adapters
will share.  Admission is a pure comparison, so a replay can be answered from
the authoritative record without invoking a physical launcher.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .typed_resources import JSONValue, ensure_json_safe

__all__ = [
    "LAUNCH_ENVELOPE_VERSION",
    "LAUNCH_ENVELOPE_FIELDS",
    "LAUNCH_SPEC_FIELDS",
    "LaunchEnvelope",
    "LaunchEnvelopeError",
    "UnknownLaunchEnvelopeVersion",
    "LaunchMethodResult",
    "LaunchOutcome",
    "LaunchDispatchRejected",
    "LaunchTransactionResult",
    "LaunchReason",
    "LaunchResult",
    "canonical_launch_envelope",
    "evaluate_launch_request",
    "launch_envelope_digest",
    "launch_once",
    "launch_transaction",
]


LAUNCH_ENVELOPE_VERSION = 1
LAUNCH_ENVELOPE_FIELDS = (
    "version",
    "operation_id",
    "request_id",
    "venue",
    "launch_spec",
    "preflight_digest",
)

# These are the current request arguments consumed by the local AgentBox
# adapter/host and the cloud admission request.  They are intentionally a
# closed set: observation results, receipts, markers, and future venue
# metadata do not become launch identity merely because they are JSON-shaped.
LAUNCH_SPEC_FIELDS = frozenset(
    {
        "command",
        "repo_names",
        "base_refs",
        "cwd",
        "metadata",
        "lock_timeout_seconds",
        "operation_type",
        "launch_intent",
        "process_resource_id",
        "repo_name",
        "spec_path",
        "base_ref",
        "plan_id",
        "phase",
        "dispatch_family_id",
        "logical_dispatch_id",
        "physical_door_id",
        "configured_spec",
        "selected_spec",
        "source_revision",
        "runtime_vector",
        "manifest_identity",
        "seed_identity",
        "dependency_interpreter_identity",
        "prompt_or_phase_input_identity",
        "configured_fallback_chain_identity",
        "authorized_route_identity",
        "timeout_budget_s",
        "production_intent",
        "configured_fallback_specs",
        "process_session_identity",
        "expected_session_name",
    }
)

class LaunchEnvelopeError(ValueError):
    """Raised when a launch envelope cannot be trusted or decoded."""


class UnknownLaunchEnvelopeVersion(LaunchEnvelopeError):
    """Raised when a payload uses a launch-envelope version we do not own."""


class LaunchResult(str, Enum):
    """The complete, intentionally small method-result vocabulary."""

    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"
    CONFLICT = "CONFLICT"


# Alias with an explicit method-oriented name for callers that want to avoid
# confusing this result enum with venue-specific result types.
LaunchMethodResult = LaunchResult


class LaunchReason(str, Enum):
    """Bounded reasons returned by launch admission and dispatch."""

    ADMITTED = "admitted"
    REPLAY = "replay"
    MALFORMED = "malformed"
    UNKNOWN_VERSION = "unknown_version"
    OPERATION_MISMATCH = "operation_mismatch"
    PREFLIGHT_MISMATCH = "preflight_mismatch"
    PREFLIGHT_REJECTED = "preflight_rejected"
    REQUEST_CONFLICT = "request_conflict"
    DISPATCH_ACCEPTED = "dispatch_accepted"
    DISPATCH_REJECTED = "dispatch_rejected"
    DISPATCH_UNCERTAIN = "dispatch_uncertain"


def _freeze_json(value: Any, *, field_name: str) -> JSONValue:
    """Validate JSON and recursively detach mutable caller-owned containers."""

    safe = ensure_json_safe(value, field_name=field_name)
    if isinstance(safe, dict):
        return MappingProxyType(
            {key: _freeze_json(item, field_name=f"{field_name}.{key}") for key, item in safe.items()}
        )  # type: ignore[return-value]
    if isinstance(safe, list):
        return tuple(_freeze_json(item, field_name=f"{field_name}[]") for item in safe)  # type: ignore[return-value]
    return safe


def _thaw_json(value: Any) -> JSONValue:
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    if isinstance(value, list):
        return [_thaw_json(item) for item in value]
    return value


@dataclass(frozen=True)
class LaunchEnvelope:
    """Immutable identity for one venue-independent launch request.

    The six dataclass fields are the complete top-level contract.  The digest
    is derived from these fields and is intentionally not stored in the
    envelope itself.
    """

    version: int
    operation_id: str
    request_id: str
    venue: str
    launch_spec: Mapping[str, JSONValue]
    preflight_digest: str

    def __post_init__(self) -> None:
        if isinstance(self.version, bool) or not isinstance(self.version, int):
            raise LaunchEnvelopeError("version must be an integer")
        if self.version != LAUNCH_ENVELOPE_VERSION:
            raise UnknownLaunchEnvelopeVersion(
                f"unsupported launch envelope version: {self.version!r}"
            )
        for name in ("operation_id", "request_id", "venue", "preflight_digest"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise LaunchEnvelopeError(f"{name} must be a non-empty string")
        if not isinstance(self.launch_spec, Mapping):
            raise LaunchEnvelopeError("launch_spec must be a JSON object")
        unknown_spec_fields = set(self.launch_spec) - LAUNCH_SPEC_FIELDS
        if unknown_spec_fields:
            raise LaunchEnvelopeError(
                "unknown launch_spec fields: " + repr(sorted(unknown_spec_fields))
            )
        frozen = _freeze_json(dict(self.launch_spec), field_name="launch_spec")
        if not isinstance(frozen, Mapping):  # pragma: no cover - guarded above
            raise LaunchEnvelopeError("launch_spec must be a JSON object")
        object.__setattr__(self, "launch_spec", frozen)

    @property
    def digest(self) -> str:
        """Return the derived identity digest; it is never serialized as a field."""

        return launch_envelope_digest(self)

    def to_json(self) -> dict[str, JSONValue]:
        """Return the six-field JSON object representation."""

        return {
            "version": self.version,
            "operation_id": self.operation_id,
            "request_id": self.request_id,
            "venue": self.venue,
            "launch_spec": _thaw_json(self.launch_spec),
            "preflight_digest": self.preflight_digest,
        }

    # ``to_dict`` is a convenient neutral alias used by durable contracts.
    to_dict = to_json

    @classmethod
    def from_json(cls, payload: Mapping[str, Any] | str) -> "LaunchEnvelope":
        """Decode one strict six-field JSON object."""

        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise LaunchEnvelopeError("malformed launch envelope JSON") from exc
        if not isinstance(payload, Mapping):
            raise LaunchEnvelopeError("launch envelope must be a JSON object")
        keys = set(payload)
        expected = set(LAUNCH_ENVELOPE_FIELDS)
        if keys != expected:
            missing = sorted(expected - keys)
            unknown = sorted(keys - expected)
            detail = []
            if missing:
                detail.append(f"missing={missing}")
            if unknown:
                detail.append(f"unknown={unknown}")
            raise LaunchEnvelopeError("malformed launch envelope: " + ", ".join(detail))
        return cls(
            version=payload["version"],
            operation_id=payload["operation_id"],
            request_id=payload["request_id"],
            venue=payload["venue"],
            launch_spec=payload["launch_spec"],
            preflight_digest=payload["preflight_digest"],
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "LaunchEnvelope":
        return cls.from_json(payload)


@dataclass(frozen=True)
class LaunchOutcome:
    """A bounded method result with no free-form status vocabulary."""

    result: LaunchResult
    reason: LaunchReason

    def __post_init__(self) -> None:
        object.__setattr__(self, "result", LaunchResult(self.result))
        object.__setattr__(self, "reason", LaunchReason(self.reason))

    @property
    def status(self) -> LaunchResult:
        """Compatibility spelling for callers that call the result a status."""

        return self.result


class LaunchDispatchRejected(RuntimeError):
    """A physical launch was rejected with no process/session side effect."""


@dataclass(frozen=True)
class LaunchTransactionResult:
    """Result of the complete preflight → admission → dispatch → acceptance flow."""

    outcome: LaunchOutcome
    store_result: Any | None = None
    observation: Mapping[str, Any] | None = None

    @property
    def result(self) -> LaunchResult:
        return self.outcome.result

    @property
    def reason(self) -> LaunchReason:
        return self.outcome.reason

    @property
    def operation(self) -> Any | None:
        return getattr(self.store_result, "operation", None)


def _identity_matches(envelope: LaunchEnvelope, observation: Mapping[str, Any]) -> bool:
    """Require every identity fact and liveness before accepting a process."""

    expected_session = envelope.launch_spec.get("expected_session_name")
    expected_process = envelope.launch_spec.get("process_session_identity")
    required = {
        "operation_id": envelope.operation_id,
        "request_id": envelope.request_id,
        "envelope_digest": envelope.digest,
        "liveness": "running",
    }
    if isinstance(expected_session, str) and expected_session:
        required["session_name"] = expected_session
    if isinstance(expected_process, str) and expected_process:
        required["process_session_identity"] = expected_process
    return all(observation.get(key) == value for key, value in required.items())


def launch_transaction(
    envelope: LaunchEnvelope | Mapping[str, Any],
    *,
    store: Any,
    preflight: Any,
    dispatch: Callable[[LaunchEnvelope], Any],
    observe: Callable[[Any, LaunchEnvelope], Mapping[str, Any]],
    resource_factory: Callable[[Any, Mapping[str, Any], LaunchEnvelope], Any],
    operation_type: str | None = None,
) -> LaunchTransactionResult:
    """Run one launch transaction through the existing durable-ops authority.

    ``preflight`` is an already completed observation-only report.  The engine
    does not create custody, worktrees, logs, sessions, or markers itself: the
    adapter's ``dispatch`` performs those physical operations only after the
    atomic store admission.  Exact replay returns without dispatch.  A known
    no-side-effect rejection is ``REJECTED``; every lost acknowledgement,
    unavailable observation, identity mismatch, or dead process is ``UNKNOWN``.
    """

    try:
        candidate = envelope if isinstance(envelope, LaunchEnvelope) else LaunchEnvelope.from_json(envelope)
    except UnknownLaunchEnvelopeVersion:
        return LaunchTransactionResult(LaunchOutcome(LaunchResult.REJECTED, LaunchReason.UNKNOWN_VERSION))
    except (LaunchEnvelopeError, TypeError, ValueError, KeyError):
        return LaunchTransactionResult(LaunchOutcome(LaunchResult.REJECTED, LaunchReason.MALFORMED))

    if not getattr(preflight, "accepted", False):
        return LaunchTransactionResult(
            LaunchOutcome(LaunchResult.REJECTED, LaunchReason.PREFLIGHT_REJECTED)
        )
    preflight_digest = getattr(preflight, "preflight_digest", None)
    if preflight_digest != candidate.preflight_digest:
        return LaunchTransactionResult(LaunchOutcome(LaunchResult.REJECTED, LaunchReason.PREFLIGHT_MISMATCH))

    admission = store.admit_launch(candidate, operation_type=operation_type)
    if admission.result is not LaunchResult.ACCEPTED:
        reason = LaunchReason.REPLAY if admission.reason is LaunchReason.REPLAY else admission.reason
        return LaunchTransactionResult(LaunchOutcome(admission.result, reason), admission)
    if admission.reason is LaunchReason.REPLAY:
        # An admitted-but-not-accepted request has an unknown physical result;
        # replay observes custody and never redispatches it.
        replay_state = getattr(getattr(admission, "operation", None), "state", None)
        if getattr(replay_state, "value", replay_state) == "pending":
            return LaunchTransactionResult(
                LaunchOutcome(LaunchResult.UNKNOWN, LaunchReason.DISPATCH_UNCERTAIN),
                admission,
            )
        return LaunchTransactionResult(LaunchOutcome(LaunchResult.ACCEPTED, LaunchReason.REPLAY), admission)

    try:
        dispatched = dispatch(candidate)
    except LaunchDispatchRejected:
        return LaunchTransactionResult(LaunchOutcome(LaunchResult.REJECTED, LaunchReason.DISPATCH_REJECTED), admission)
    except Exception:
        return LaunchTransactionResult(LaunchOutcome(LaunchResult.UNKNOWN, LaunchReason.DISPATCH_UNCERTAIN), admission)

    try:
        observation = dict(observe(dispatched, candidate))
    except Exception:
        return LaunchTransactionResult(LaunchOutcome(LaunchResult.UNKNOWN, LaunchReason.DISPATCH_UNCERTAIN), admission)
    if not _identity_matches(candidate, observation):
        return LaunchTransactionResult(
            LaunchOutcome(LaunchResult.UNKNOWN, LaunchReason.DISPATCH_UNCERTAIN),
            admission,
            observation,
        )
    try:
        resource = resource_factory(dispatched, observation, candidate)
        accepted = store.accept_launch(
            candidate,
            process_resource=resource,
            owner_evidence={
                "operation_id": candidate.operation_id,
                "request_id": candidate.request_id,
                "envelope_digest": candidate.digest,
                "process_session_identity": observation.get("process_session_identity"),
                "liveness": observation.get("liveness"),
            },
            owner=candidate.venue,
        )
    except Exception:
        return LaunchTransactionResult(LaunchOutcome(LaunchResult.UNKNOWN, LaunchReason.DISPATCH_UNCERTAIN), admission, observation)
    if accepted.result is not LaunchResult.ACCEPTED:
        return LaunchTransactionResult(LaunchOutcome(accepted.result, accepted.reason), accepted, observation)
    return LaunchTransactionResult(LaunchOutcome(LaunchResult.ACCEPTED, accepted.reason), accepted, observation)


def canonical_launch_envelope(envelope: LaunchEnvelope | Mapping[str, Any]) -> str:
    """Serialize an envelope deterministically without embedding its digest."""

    if not isinstance(envelope, LaunchEnvelope):
        envelope = LaunchEnvelope.from_json(envelope)
    return json.dumps(
        envelope.to_json(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def launch_envelope_digest(envelope: LaunchEnvelope | Mapping[str, Any]) -> str:
    """Return a stable SHA-256 digest of canonical envelope bytes."""

    payload = canonical_launch_envelope(envelope).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _reject(reason: LaunchReason) -> LaunchOutcome:
    return LaunchOutcome(LaunchResult.REJECTED, reason)


def evaluate_launch_request(
    envelope: LaunchEnvelope | Mapping[str, Any],
    *,
    operation_id: str,
    preflight_digest: str,
    existing: LaunchEnvelope | Mapping[str, Any] | None = None,
    authoritative_result: LaunchResult | None = None,
) -> LaunchOutcome:
    """Validate identity and compare an optional authoritative replay record.

    This function does not write state and does not call a dispatcher.  A
    caller passes the authoritative existing envelope/result when replaying.
    """

    try:
        candidate = envelope if isinstance(envelope, LaunchEnvelope) else LaunchEnvelope.from_json(envelope)
    except UnknownLaunchEnvelopeVersion:
        return _reject(LaunchReason.UNKNOWN_VERSION)
    except (LaunchEnvelopeError, TypeError, ValueError, KeyError):
        return _reject(LaunchReason.MALFORMED)
    if candidate.version != LAUNCH_ENVELOPE_VERSION:
        return _reject(LaunchReason.UNKNOWN_VERSION)
    if candidate.operation_id != operation_id:
        return _reject(LaunchReason.OPERATION_MISMATCH)
    if candidate.preflight_digest != preflight_digest:
        return _reject(LaunchReason.PREFLIGHT_MISMATCH)
    if existing is None:
        return LaunchOutcome(LaunchResult.ACCEPTED, LaunchReason.ADMITTED)
    try:
        prior = existing if isinstance(existing, LaunchEnvelope) else LaunchEnvelope.from_json(existing)
    except UnknownLaunchEnvelopeVersion:
        return _reject(LaunchReason.UNKNOWN_VERSION)
    except (LaunchEnvelopeError, TypeError, ValueError, KeyError):
        return _reject(LaunchReason.MALFORMED)
    if prior.request_id != candidate.request_id:
        return LaunchOutcome(LaunchResult.CONFLICT, LaunchReason.REQUEST_CONFLICT)
    if prior.digest != candidate.digest:
        return LaunchOutcome(LaunchResult.CONFLICT, LaunchReason.REQUEST_CONFLICT)
    result = authoritative_result or LaunchResult.ACCEPTED
    return LaunchOutcome(result, LaunchReason.REPLAY)


def launch_once(
    envelope: LaunchEnvelope | Mapping[str, Any],
    dispatch: Callable[[LaunchEnvelope], Any],
    *,
    operation_id: str,
    preflight_digest: str,
    existing: LaunchEnvelope | Mapping[str, Any] | None = None,
    authoritative_result: LaunchResult | None = None,
) -> LaunchOutcome:
    """Evaluate identity and invoke ``dispatch`` only for a new request.

    Exact replay and request conflicts return before the callback is touched;
    an exception after dispatch is represented as ``UNKNOWN`` because the
    transport's physical outcome cannot be inferred here.
    """

    decision = evaluate_launch_request(
        envelope,
        operation_id=operation_id,
        preflight_digest=preflight_digest,
        existing=existing,
        authoritative_result=authoritative_result,
    )
    if decision.reason is not LaunchReason.ADMITTED:
        return decision
    candidate = envelope if isinstance(envelope, LaunchEnvelope) else LaunchEnvelope.from_json(envelope)
    try:
        dispatch(candidate)
    except Exception:
        return LaunchOutcome(LaunchResult.UNKNOWN, LaunchReason.DISPATCH_UNCERTAIN)
    return LaunchOutcome(LaunchResult.ACCEPTED, LaunchReason.DISPATCH_ACCEPTED)
