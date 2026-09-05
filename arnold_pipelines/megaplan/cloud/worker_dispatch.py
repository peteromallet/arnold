"""Canonical production worker admission and controlled dispatch.

This module is deliberately small: admission owns pre-launch invariants,
``OperationRun``/``FileBackedDurableOpsStore`` owns launch state and accepted
identity, and ``dispatch_with_admission`` owns the only bounded wait loop.
Door adapters pass an immutable request and a closure; they never perform a
second preflight or consult an incident ledger for launch authority.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from arnold_pipelines.megaplan.incident.ledger import IncidentLedger
from arnold.runtime.durable_ops import FileBackedDurableOpsStore
from arnold.runtime.durable_ops.launch import (
    LaunchEnvelope,
    LaunchResult as DurableLaunchResult,
    launch_transaction,
)
from arnold.runtime.durable_ops.typed_resources import ResourceType, TypedResource
from arnold_pipelines.megaplan.incident.schema import ReservationReconciled, semantic_dispatch_fingerprint
from arnold_pipelines.megaplan.fallback_chains import ExecuteFallbackUnsafe, provider_family
from arnold_pipelines.megaplan.orchestration.provider_resilience import (
    ProviderLedgerView,
    apply_provider_route_decision_locked,
    execute_provider_probe,
    provider_scheduling_condition,
    select_provider_probe,
    select_provider_route,
)
from arnold_pipelines.megaplan.orchestration.phase_result import (
    DispatchOutcome,
    SchedulingCondition,
)
from arnold_pipelines.megaplan.types import AgentSpec, CliError, format_agent_spec, parse_agent_spec

SCHEMA_VERSION = 1
RECEIPT_DERIVATION_VERSION = "1"
DEFAULT_TIMEOUT_BUDGET_S = 3600.0
NATIVE_PROOF_MAX_AGE_S = 24.0 * 60.0 * 60.0
CONTINUATION_PROVIDER_PROBE_SCHEMA = "arnold.megaplan.continuation_provider_probe.v1"
CONTINUATION_PROVIDER_PROBE_OUTPUT = "NBF_MUSE_PROBE_OK"
CONTINUATION_PROVIDER_PROBE_MAX_AGE_S = 15.0 * 60.0


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()).hexdigest()


def _worker_operation_store(request: "WorkerAdmissionRequest", receipt: "WorkerAdmissionReceipt" | None = None) -> Any:
    """Return the one durable operation store for a worker launch.

    The remote worker process owns this root.  In particular, this helper is
    never called by a controller before the provider boundary; it is used by
    the physical door after the request has reached its execution venue.
    Tests and embedded adapters may inject a store object directly.
    """
    injected = request.operation_store
    if injected is not None:
        return injected
    root = request.operation_store_root
    if root is None:
        root = (request.ledger_root or Path.cwd()) / "ops"
    return FileBackedDurableOpsStore(root)


def _worker_launch_envelope(receipt: "WorkerAdmissionReceipt") -> LaunchEnvelope:
    """Build the canonical envelope from one already-admitted worker receipt."""
    operation_id = receipt.operation_id or receipt.logical_dispatch_id
    request_id = receipt.request_id or receipt.admission_receipt_id
    preflight_digest = receipt.preflight_digest or receipt.semantic_dispatch_fingerprint
    spec = {
        "operation_type": "megaplan_worker",
        "launch_intent": "worker",
        "configured_spec": receipt.normalized_spec,
        "selected_spec": receipt.normalized_spec,
        "plan_id": receipt.plan_id,
        "phase": receipt.phase,
        "dispatch_family_id": receipt.dispatch_family_id,
        "logical_dispatch_id": receipt.logical_dispatch_id,
        "physical_door_id": receipt.physical_door_id,
        "source_revision": receipt.source_revision,
        "runtime_vector": receipt.runtime_vector,
        "manifest_identity": receipt.manifest_identity,
        "seed_identity": receipt.seed_identity,
        "dependency_interpreter_identity": receipt.dependency_interpreter_identity,
        "prompt_or_phase_input_identity": receipt.execution_context.to_dict().get("prompt_or_phase_input_identity", ""),
        "configured_fallback_chain_identity": "",
        "authorized_route_identity": receipt.normalized_spec,
        "timeout_budget_s": receipt.timeout_budget_s,
        "production_intent": receipt.production_intent,
        "process_session_identity": receipt.route_liveness_identity,
    }
    # ``process_session_identity`` above is a route proof, not a process
    # identity.  Physical adapters provide it in the observation; do not bind
    # a stale route token into the canonical envelope.
    spec.pop("process_session_identity", None)
    return LaunchEnvelope(
        version=1,
        operation_id=operation_id,
        request_id=request_id,
        venue=receipt.physical_door_id,
        launch_spec=spec,
        preflight_digest=preflight_digest,
    )


class _WorkerPreflight:
    __slots__ = ("accepted", "preflight_digest")

    def __init__(self, preflight_digest: str) -> None:
        self.accepted = True
        self.preflight_digest = preflight_digest


def _continuation_probe_profile_identity(project_dir: Path) -> dict[str, str]:
    """Return the source/profile identity bound into a continuation probe."""
    project = project_dir.resolve()
    profile = project / ".megaplan" / "profiles.toml"
    try:
        profile_sha = hashlib.sha256(profile.read_bytes()).hexdigest()
    except OSError as exc:
        raise CliError(
            "continuation_probe_unavailable",
            f"continuation profile is unreadable: {profile}",
        ) from exc
    return {"source_path": str(project), "profile_sha256": profile_sha}


def _continuation_probe_receipt_path(
    project_dir: Path, *, identity: Mapping[str, str] | None = None
) -> Path:
    """Return the probe receipt path for this execution scope.

    Cloud/managed launches set the existing ``ARNOLD_BASE_DIR`` and one of
    the existing session variables.  Their probe receipt is control-plane
    evidence, not a checkout artifact, so keep it beside the operation roots
    and content-address it by the source/profile identity.  Standalone
    library callers retain the historical project-local path.
    """
    base_dir = str(os.environ.get("ARNOLD_BASE_DIR") or "").strip()
    session = (
        str(os.environ.get("ARNOLD_BABYSITTER_SESSION") or "").strip()
        or str(os.environ.get("ARNOLD_REPAIR_SESSION") or "").strip()
        or str(os.environ.get("ARNOLD_CHAIN_SESSION") or "").strip()
    )
    if base_dir and session:
        safe_session = re.sub(r"[^A-Za-z0-9_.-]+", "-", session).strip(".-") or "session"
        if safe_session != session:
            safe_session = f"{safe_session}-{hashlib.sha256(session.encode()).hexdigest()[:12]}"
        bound_identity = dict(identity or _continuation_probe_profile_identity(project_dir))
        source_digest = _digest(bound_identity)
        return (
            Path(base_dir).expanduser().resolve()
            / "continuation-provider-probes"
            / safe_session
            / f"{source_digest}.json"
        )
    return project_dir.resolve() / ".megaplan" / "continuation-provider-probe.json"


def _continuation_probe_receipt_valid(
    receipt: Mapping[str, Any],
    *,
    identity: Mapping[str, str],
    model_spec: str,
    now: float,
) -> bool:
    """Validate a persisted exact-output probe before allowing dispatch."""
    if receipt.get("schema") != CONTINUATION_PROVIDER_PROBE_SCHEMA:
        return False
    if (
        receipt.get("provider") != "openrouter"
        or receipt.get("model") != "meta/muse-spark-1.3-contributor"
        or receipt.get("model_spec") != model_spec
        or receipt.get("reasoning_effort") != "high"
        or receipt.get("output") != CONTINUATION_PROVIDER_PROBE_OUTPUT
        or receipt.get("source_path") != identity["source_path"]
        or receipt.get("profile_sha256") != identity["profile_sha256"]
        or receipt.get("source_identity") != _digest(identity)
        or not str(receipt.get("probe_session") or "").strip()
        or not str(receipt.get("catalog_digest") or "").strip()
    ):
        return False
    if receipt.get("output_sha256") != hashlib.sha256(
        CONTINUATION_PROVIDER_PROBE_OUTPUT.encode("utf-8")
    ).hexdigest():
        return False
    try:
        observed = datetime.fromisoformat(str(receipt["timestamp"]).replace("Z", "+00:00"))
        age = now - observed.timestamp()
    except (KeyError, TypeError, ValueError, OverflowError):
        return False
    return 0 <= age <= CONTINUATION_PROVIDER_PROBE_MAX_AGE_S


def ensure_continuation_provider_probe(
    project_dir: Path | str,
    model_spec: str,
    *,
    runner: Callable[..., Any] | None = None,
    membership_probe: Callable[[str, str], Mapping[str, Any]] | None = None,
    clock: Callable[[], float] | None = None,
) -> Mapping[str, Any]:
    """Require a credentialed, exact-output Muse probe receipt.

    The receipt is a small project-local authority record.  A recent record is
    replayable only when its model, high-thinking setting, source path, and
    profile digest still match.  A missing/stale/divergent record causes one
    exact ``omp -p`` probe; any non-zero exit or output other than the sentinel
    fails closed before a managed worker can launch.
    """
    from arnold_pipelines.megaplan.profiles import CONTINUATION_RUNTIME_MODEL_SPEC

    if model_spec != CONTINUATION_RUNTIME_MODEL_SPEC:
        raise CliError("continuation_probe_mismatch", "continuation probe model is not canonical")
    project = Path(project_dir)
    identity = _continuation_probe_profile_identity(project)
    now = (clock or time.time)()
    path = _continuation_probe_receipt_path(project, identity=identity)
    try:
        prior = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        prior = None
    membership = (membership_probe or resolve_omp_live_membership)(
        "openrouter", "meta/muse-spark-1.3-contributor"
    )
    if isinstance(prior, Mapping) and _continuation_probe_receipt_valid(
        prior, identity=identity, model_spec=model_spec, now=now
    ) and membership.get("digest") == prior.get("catalog_digest"):
        return dict(prior)
    if (
        membership.get("identity") != "openrouter/meta/muse-spark-1.3-contributor"
        or not membership.get("digest")
    ):
        raise CliError("continuation_probe_unavailable", "Muse route is not an exact live catalog member")
    run = runner or subprocess.run
    try:
        completed = run(
            [
                "omp", "-p", "--no-session", "--no-tools",
                "--model", "openrouter/meta/muse-spark-1.3-contributor",
                "--thinking", "high", f"reply exactly {CONTINUATION_PROVIDER_PROBE_OUTPUT}",
            ], capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CliError("continuation_probe_unavailable", f"exact Muse probe failed: {exc}") from exc
    output = str(getattr(completed, "stdout", "") or "").strip()
    if getattr(completed, "returncode", 1) != 0 or output != CONTINUATION_PROVIDER_PROBE_OUTPUT:
        raise CliError(
            "continuation_probe_failed",
            "credentialed Muse probe did not return the exact sentinel",
            extra={"returncode": getattr(completed, "returncode", None), "output": output},
        )
    observed_at = datetime.fromtimestamp(now, timezone.utc).isoformat()
    receipt: dict[str, Any] = {
        "schema": CONTINUATION_PROVIDER_PROBE_SCHEMA,
        "provider": "openrouter",
        "model": "meta/muse-spark-1.3-contributor",
        "model_spec": model_spec,
        "reasoning_effort": "high",
        "probe_session": f"continuation-muse-probe-{hashlib.sha256((identity['source_path'] + observed_at).encode()).hexdigest()[:16]}",
        "output": output,
        "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        "source_identity": _digest(identity),
        "timestamp": observed_at,
        "observed_at": observed_at,
        "source_path": identity["source_path"],
        "profile_sha256": identity["profile_sha256"],
        "catalog_digest": str(membership["digest"]),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(receipt, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except OSError as exc:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise CliError("continuation_probe_receipt_failed", f"could not persist probe receipt: {path}") from exc
    return receipt


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _refusal(
    request: Any,
    code: str,
    reason: str,
    **evidence: Any,
) -> AdmissionRefusal:
    """Build a lossless typed refusal from a possibly malformed request.

    Admission is a trust boundary.  Invalid caller data must become a typed
    refusal rather than leaking ``AttributeError``/``TypeError`` from the
    dataclass or parser.  Keep the identity fields best-effort so the caller
    can correlate a refusal even when one of them is the field that failed.
    """
    mapping = _as_mapping(request)
    def text(name: str) -> str:
        value = getattr(request, name, mapping.get(name, ""))
        return value.strip() if isinstance(value, str) else str(value or "")

    return AdmissionRefusal(
        code=str(code or "admission_rejected"),
        reason=str(reason),
        plan_id=text("plan_id") or "unknown",
        phase=text("phase") or "unknown",
        logical_dispatch_id=text("logical_dispatch_id") or "unknown",
        admission_attempt=(
            int(getattr(request, "admission_attempt", mapping.get("admission_attempt", 1)))
            if str(getattr(request, "admission_attempt", mapping.get("admission_attempt", 1))).isdigit()
            else 1
        ),
        evidence=evidence,
    )


@dataclass(frozen=True)
class WorkerExecutionContextRef:
    ledger_root: str
    plan_id: str
    phase: str
    dispatch_family_id: str
    logical_dispatch_id: str
    admission_receipt_id: str
    semantic_dispatch_fingerprint: str
    selected_spec: str
    physical_door_id: str
    # Process-local hook installed only while a controlled launch is running.
    # It is intentionally excluded from transport serialization so callers
    # cannot inject authority through an execution-context payload.
    spawn_registration_callback: Callable[[Mapping[str, Any]], Any] | None = field(
        default=None, compare=False, repr=False
    )
    operation_store_root: str | None = field(default=None, compare=True)

    def to_dict(self) -> dict[str, str]:
        result = {
            name: getattr(self, name)
            for name in self.__dataclass_fields__
            if name != "spawn_registration_callback"
        }
        if result.get("operation_store_root") is None:
            result.pop("operation_store_root", None)
        return result
    def to_environment(self, *, variable: str = "ARNOLD_WORKER_EXECUTION_CONTEXT") -> dict[str, str]:
        return {variable: json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))}

    @classmethod
    def from_environment(cls, environment: Mapping[str, Any], *, variable: str = "ARNOLD_WORKER_EXECUTION_CONTEXT") -> "WorkerExecutionContextRef":
        raw = environment.get(variable)
        if not isinstance(raw, str) or not raw:
            raise ValueError("worker execution context is missing from environment")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("worker execution context environment value is invalid JSON") from exc
        if not isinstance(payload, Mapping):
            raise ValueError("worker execution context environment value must be an object")
        return cls.from_dict(payload)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "WorkerExecutionContextRef":
        expected = {
            name for name in cls.__dataclass_fields__
            if name != "spawn_registration_callback"
        }
        unknown = set(payload) - expected
        # Older in-band contexts did not carry the store root; derive that
        # root from ``ledger_root`` at the physical venue.
        expected.discard("operation_store_root")
        missing = expected - set(payload)
        if unknown or missing:
            raise ValueError(f"invalid worker execution context (unknown={sorted(unknown)}, missing={sorted(missing)})")
        values = {name: payload[name] for name in expected}
        if "operation_store_root" in payload:
            values["operation_store_root"] = str(payload["operation_store_root"])
        if any(not isinstance(value, str) or not value for value in values.values()):
            raise ValueError("worker execution context fields must be non-empty strings")
        return cls(**values)


@dataclass(frozen=True)
class WorkerAdmissionRequest:
    plan_id: str
    phase: str
    dispatch_family_id: str
    logical_dispatch_id: str
    physical_door_id: str
    configured_spec: str
    selected_spec: str
    source_revision: str
    runtime_vector: Any
    manifest_identity: str
    seed_identity: str
    dependency_interpreter_identity: str
    prompt_or_phase_input_identity: str
    configured_fallback_chain_identity: str
    authorized_route_identity: str
    projection_key: str
    expected_projection_version: int | None = None
    timeout_budget_s: float = DEFAULT_TIMEOUT_BUDGET_S
    parent_logical_dispatch_id: str | None = None
    authorizing_event_id: str | None = None
    parent_terminal_event_id: str | None = None
    parent_source_spec: str | None = None
    transition_kind: str | None = None
    precondition_identity: str | None = None
    admission_attempt: int = 1
    production_intent: bool = True
    ledger_root: Path | None = None
    # The operation store is the sole launch authority.  A caller may pin the
    # remote root explicitly; otherwise the venue adapter derives it from the
    # request root (never from the controller's cwd).
    operation_store_root: Path | None = None
    operation_store: Any = field(default=None, compare=False, repr=False)
    changed_precondition_event_id: str | None = None
    # The normalized chain is supplied by the configured-fallback authority.
    # It is transport metadata only; target selection still happens at the
    # post-terminal provider seam below.
    configured_fallback_specs: tuple[str, ...] = ()
    route_liveness_resolver: Callable[[str, str, str], Mapping[str, Any]] | None = field(default=None, compare=False, repr=False)
    native_construction_seam: Callable[[str, str, str], Mapping[str, Any]] | None = field(default=None, compare=False, repr=False)
    source_runtime_validator: Callable[["WorkerAdmissionRequest"], Any] | None = field(default=None, compare=False, repr=False)
    memory_headroom_reader: Callable[[str], Mapping[str, Any] | None] | None = field(default=None, compare=False, repr=False)
    cooldown_reader: Callable[[Path | None, str, str], float] | None = field(default=None, compare=False, repr=False)
    ledger: IncidentLedger | None = field(default=None, compare=False, repr=False)

    def to_dict(self) -> dict[str, Any]:
        """Return the transport form, excluding process-local callback hooks."""
        local_only = {
            "route_liveness_resolver", "source_runtime_validator",
            "native_construction_seam",
            "memory_headroom_reader", "cooldown_reader", "ledger", "operation_store",
        }
        result: dict[str, Any] = {}
        for name in self.__dataclass_fields__:
            if name in local_only:
                continue
            value = getattr(self, name)
            result[name] = str(value) if isinstance(value, Path) else value
        return result

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "WorkerAdmissionRequest":
        data = dict(payload)
        if data.get("ledger_root") is not None:
            data["ledger_root"] = Path(str(data["ledger_root"]))
        if data.get("operation_store_root") is not None:
            data["operation_store_root"] = Path(str(data["operation_store_root"]))
        return cls(**data)


@dataclass(frozen=True)
class WorkerAdmissionReceipt:
    admission_receipt_id: str
    plan_id: str
    phase: str
    dispatch_family_id: str
    logical_dispatch_id: str
    parent_logical_dispatch_id: str | None
    authorizing_event_id: str | None
    physical_door_id: str
    admission_attempt: int
    normalized_spec: str
    provider: str
    model: str
    family: str
    route_liveness_kind: str
    route_liveness_identity: str
    route_liveness_digest: str
    timeout_budget_s: float
    source_revision: str
    runtime_vector: Any
    manifest_identity: str
    seed_identity: str
    dependency_interpreter_identity: str
    semantic_dispatch_fingerprint: str
    projection_key: str
    projection_version: int
    reservation_event_id: str
    accepted_changed_precondition_event_id: str | None
    route_transition_event_id: str | None
    admitted_at: str
    execution_context: WorkerExecutionContextRef
    production_intent: bool = True
    # Canonical durable launch identity.  These values are derived at
    # admission and are intentionally carried by the physical-door receipt;
    # they are not a second lifecycle record.
    operation_id: str = ""
    request_id: str = ""
    preflight_digest: str = ""
    operation_store_root: str = ""

    def to_dict(self) -> dict[str, Any]:
        result = {name: getattr(self, name) for name in self.__dataclass_fields__ if name != "execution_context"}
        result["execution_context"] = self.execution_context.to_dict()
        return result

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "WorkerAdmissionReceipt":
        data = dict(payload)
        data["execution_context"] = WorkerExecutionContextRef.from_dict(data.pop("execution_context"))
        return cls(**data)


@dataclass(frozen=True)
class AdmissionRefusal:
    code: str
    reason: str
    plan_id: str
    phase: str
    logical_dispatch_id: str
    admission_attempt: int
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": SCHEMA_VERSION, "kind": "admission_refusal", **{name: getattr(self, name) for name in self.__dataclass_fields__}}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "AdmissionRefusal":
        data = dict(payload)
        if data.pop("schema_version", SCHEMA_VERSION) != SCHEMA_VERSION or data.pop("kind", "admission_refusal") != "admission_refusal":
            raise ValueError("invalid admission refusal schema")
        unknown = set(data) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"unknown AdmissionRefusal fields: {sorted(unknown)}")
        return cls(**data)


@dataclass(frozen=True)
class LaunchResult:
    """Optional adapter result for closures that are not already outcomes."""
    accepted: bool
    value: Any = None
    worker_identity: Mapping[str, Any] | None = None
    started_at: str | None = None
    finished_at: str | None = None


@dataclass(frozen=True)
class ManagedCommandResult:
    """Operation-specific result for the managed command adapter."""

    returncode: int
    worker_identity: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if isinstance(self.returncode, bool) or not isinstance(self.returncode, int):
            raise ValueError("managed command returncode must be an integer")


def _is_worker_result(value: Any) -> bool:
    return type(value).__name__ == "WorkerResult" and type(value).__module__.endswith("workers._impl")


def _is_worker_operation_result(value: Any) -> bool:
    return _is_worker_result(value) or (
        isinstance(value, tuple)
        and len(value) == 4
        and _is_worker_result(value[0])
    )


def _worker_result_is_failure_shaped(value: Any) -> bool:
    payload = getattr(value, "payload", None)
    if not isinstance(payload, Mapping):
        return False
    if payload.get("ok") is False or payload.get("success") is False:
        return True
    status = payload.get("status")
    if isinstance(status, str) and status.lower() in {"failed", "failure", "error", "aborted"}:
        return True
    return any(key in payload for key in ("error", "failure", "exception", "terminal_failure"))


def _outcome_from_terminal_exception(
    exc: BaseException,
    receipt: WorkerAdmissionReceipt,
    started: str,
    finished: str,
) -> DispatchOutcome | None:
    """Translate only explicitly typed adapter failures; never infer one."""
    candidate = getattr(exc, "dispatch_outcome", None)
    if candidate is None:
        candidate = getattr(exc, "outcome", None)
    if isinstance(candidate, DispatchOutcome):
        return _normalize_outcome(candidate, receipt, started, finished)
    if isinstance(candidate, Mapping):
        if not isinstance(candidate.get("worker_identity"), Mapping):
            return None
        return _normalize_outcome(candidate, receipt, started, finished)
    code = str(getattr(exc, "code", ""))
    extra = getattr(exc, "extra", {})
    if not isinstance(extra, Mapping):
        extra = {}
    if code in {"provider_exhausted", "provider_exhaustion"}:
        evidence = extra.get("provider_evidence")
        worker_identity = extra.get("worker_identity")
        if not isinstance(evidence, Mapping) or not isinstance(worker_identity, Mapping):
            return None
        return DispatchOutcome(
            kind="provider_exhausted", launch_state="accepted",
            plan_id=receipt.plan_id, phase=receipt.phase,
            dispatch_family_id=receipt.dispatch_family_id,
            logical_dispatch_id=receipt.logical_dispatch_id,
            admission_receipt_id=receipt.admission_receipt_id,
            semantic_dispatch_fingerprint=receipt.semantic_dispatch_fingerprint,
            selected_spec=receipt.normalized_spec,
            worker_identity=dict(worker_identity),
            started_at=started, finished_at=finished,
            provider_evidence=dict(evidence),
            provider_failure_key=str(extra.get("provider_failure_key") or evidence.get("provider_failure_key")),
        )
    if code in {"ordinary_terminal_failure", "worker_failure"}:
        worker_identity = extra.get("worker_identity")
        if not isinstance(worker_identity, Mapping):
            return None
        return DispatchOutcome(
            kind="ordinary_terminal_failure", launch_state="accepted",
            plan_id=receipt.plan_id, phase=receipt.phase,
            dispatch_family_id=receipt.dispatch_family_id,
            logical_dispatch_id=receipt.logical_dispatch_id,
            admission_receipt_id=receipt.admission_receipt_id,
            semantic_dispatch_fingerprint=receipt.semantic_dispatch_fingerprint,
            selected_spec=receipt.normalized_spec,
            worker_identity=dict(worker_identity),
            started_at=started, finished_at=finished,
            terminal_failure=dict(extra.get("terminal_failure") or {"code": code, "message": str(exc)}),
        )
    if code in {"worker_disposition", "worker_killed", "worker_terminated", "worker_timeout"}:
        disposition_id = extra.get("disposition_id")
        worker_identity = extra.get("worker_identity")
        if not disposition_id or not isinstance(worker_identity, Mapping):
            return None
        return DispatchOutcome(
            kind="worker_disposition", launch_state="accepted",
            plan_id=receipt.plan_id, phase=receipt.phase,
            dispatch_family_id=receipt.dispatch_family_id,
            logical_dispatch_id=receipt.logical_dispatch_id,
            admission_receipt_id=receipt.admission_receipt_id,
            semantic_dispatch_fingerprint=receipt.semantic_dispatch_fingerprint,
            selected_spec=receipt.normalized_spec,
            worker_identity=dict(worker_identity),
            started_at=str(extra.get("started_at") or started),
            finished_at=str(extra.get("finished_at") or finished),
            disposition_id=str(disposition_id),
        )
    return None


def _family(provider: str, model: str, selected_spec: str) -> str:
    """Return the canonical fallback family for an admitted route.

    ``provider_family`` owns aliases and OMP upstream-provider identity.  Keep
    this compatibility shim because a few admission helpers call ``_family``
    directly, but do not maintain a second family heuristic here.
    """
    return provider_family(selected_spec)


def _extract_omp_models(value: Any) -> set[str]:
    models = value.get("models") if isinstance(value, Mapping) else value
    if isinstance(models, Mapping):
        models = list(models.values())
    if not isinstance(models, list):
        return set()
    result: set[str] = set()
    for item in models:
        if isinstance(item, str):
            result.add(item.removeprefix("omp:"))
            continue
        if not isinstance(item, Mapping):
            continue
        provider = item.get("provider") or item.get("provider_id") or item.get("vendor")
        model = item.get("model") or item.get("model_id") or item.get("id")
        if isinstance(provider, str) and isinstance(model, str):
            normalized_model = model.removeprefix("omp:")
            result.add(normalized_model if normalized_model.startswith(f"{provider}/") else f"{provider}/{normalized_model}")
        elif isinstance(model, str) and "/" in model:
            result.add(model.removeprefix("omp:"))
    return result


def resolve_omp_live_membership(provider: str, model: str, *, timeout_s: float = 10.0, runner: Callable[..., Any] | None = None) -> Mapping[str, Any]:
    """Require exact membership in the machine-readable OMP model surface."""
    run = runner or subprocess.run
    try:
        completed = run(["omp", "models", "--json"], capture_output=True, text=True, timeout=timeout_s, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise CliError("route_liveness_unavailable", f"omp models --json failed: {exc}") from exc
    if getattr(completed, "returncode", 1) != 0:
        raise CliError("route_liveness_unavailable", "omp models --json returned non-zero", extra={"stderr": getattr(completed, "stderr", "")})
    try:
        payload = json.loads(getattr(completed, "stdout", ""))
    except (TypeError, json.JSONDecodeError) as exc:
        raise CliError("route_liveness_invalid", "omp models --json returned invalid JSON") from exc
    normalized = f"{provider}/{model}"
    members = _extract_omp_models(payload)
    if normalized not in members:
        raise CliError("route_liveness_missing", f"OMP route {normalized!r} is not an exact live member", extra={"members": sorted(members)})
    digest = _digest(sorted(members))
    return {"kind": "omp_membership", "identity": normalized, "digest": digest, "provider": provider, "model": model, "observed_at": _now()}


def _extract_native_models(value: Any) -> set[str]:
    """Extract exact model identities from a backend-owned catalog response."""
    models = value.get("models") if isinstance(value, Mapping) else value
    if not isinstance(models, list):
        return set()
    result: set[str] = set()
    for item in models:
        if isinstance(item, str) and item.strip():
            result.add(item.strip())
        elif isinstance(item, Mapping):
            slug = item.get("slug") or item.get("id") or item.get("model")
            if isinstance(slug, str) and slug.strip():
                result.add(slug.strip())
    return result


def _default_native_liveness(agent: str, model: str, *, runner: Callable[..., Any] | None = None) -> Mapping[str, Any]:
    """Obtain native capability from the installed backend catalog.

    Executable presence alone is not route proof. ``debug models`` is a
    backend-owned, read-only catalog seam; exact membership is required.
    """
    binary = "claude" if agent in {"claude", "shannon"} else "codex" if agent == "codex" else agent
    path = shutil.which(binary)
    if not path:
        raise CliError("route_liveness_missing", f"native backend {binary!r} is not available")
    resolved = str(Path(path).resolve())
    try:
        stat = Path(resolved).stat()
        executable = {"path": resolved, "st_dev": stat.st_dev, "st_ino": stat.st_ino, "mtime_ns": stat.st_mtime_ns, "size": stat.st_size}
    except OSError as exc:
        raise CliError("route_liveness_unreadable", f"native backend proof is unreadable: {exc}") from exc
    run = runner or subprocess.run
    try:
        probe = run([resolved, "debug", "models"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise CliError("route_liveness_unavailable", f"native model catalog failed: {exc}") from exc
    if getattr(probe, "returncode", 1) != 0:
        raise CliError("route_liveness_unavailable", f"native model catalog failed for {model!r}")
    try:
        catalog = json.loads(getattr(probe, "stdout", ""))
    except (TypeError, json.JSONDecodeError) as exc:
        raise CliError("route_liveness_invalid", "native model catalog was not valid JSON") from exc
    models = sorted(_extract_native_models(catalog))
    if model not in models:
        raise CliError("route_liveness_missing", f"native backend model {model!r} is not an exact catalog member")
    # Catalog membership is only the first half of native admission.  Prepare
    # the actual backend execution capability with its read-only help path;
    # this binds constructability to the installed executable rather than
    # asserting it from a model-name registry.
    try:
        prepare_argv = [resolved, "exec", "--help"] if binary == "codex" else [resolved, "--help"]
        prepared = run(prepare_argv, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise CliError("native_constructor_unavailable", f"native constructor preparation failed: {exc}") from exc
    if getattr(prepared, "returncode", 1) != 0:
        raise CliError("native_constructor_unavailable", f"native constructor preparation failed for {model!r}")
    registry = {"backend": binary, "executable": executable, "models": models}
    preparation = {"ok": True, "backend": agent, "provider": agent, "model": model, "route": f"{agent}:{model}", "operation": "exec --help" if binary == "codex" else "--help", "executable": executable}
    proof = {"constructable": True, "catalog": models, "registry": registry, "preparation": preparation, "seam": "backend constructor preparation"}
    observed_at = _now()
    route = f"{agent}:{model}"
    content = {"backend": agent, "provider": agent, "normalized_model": model, "route": route, "capability_registry": registry, "registry_generation": _digest(registry), "proof": proof, "proof_generation": _digest(proof), "family": _family(agent, model, route)}
    identity = _digest(content)
    return {"kind": "native_backend", **content, "identity": identity, "digest": _digest({**content, "identity": identity, "observed_at": observed_at}), "observed_at": observed_at}


def _runtime_binding_proof(request: WorkerAdmissionRequest) -> Mapping[str, Any]:
    """Resolve current runtime evidence; an injected seam can only attest it."""
    if not request.production_intent:
        validator = request.source_runtime_validator
        if validator is None:
            return {"ok": True, "development": True}
        result = validator(request)
        if result is False or (isinstance(result, Mapping) and result.get("ok") is False):
            raise CliError("source_runtime_invalid", "source/runtime validator rejected dispatch")
        if isinstance(result, Mapping):
            return result
        if result is True:
            raise CliError("source_runtime_invalid", "runtime validator returned an untyped success marker")
        raise CliError("source_runtime_invalid", "source/runtime validator returned an untyped result")

    from arnold_pipelines.megaplan.cloud.runtime_attestation import (
        _json_file,
        configured_seed_path,
        validate_runtime_launch_seed,
    )

    seed_path = configured_seed_path()
    if seed_path is None:
        raise CliError("source_runtime_missing", "production worker dispatch requires a configured runtime seed")
    seed = _json_file(seed_path, label="runtime launch seed")
    validation = validate_runtime_launch_seed(seed, component="worker")
    if not isinstance(validation, Mapping) or validation.get("status") != "ready":
        raise CliError("source_runtime_invalid", "runtime seed validation did not produce ready evidence")
    authoritative = {
        "ok": True,
        "source_revision": seed.get("expected_revision"),
        "runtime_vector": seed.get("runtime_provenance"),
        "runtime_vector_sha256": validation.get("runtime_vector_sha256"),
        "manifest_identity": seed.get("manifest_sha256"),
        "seed_identity": hashlib.sha256(seed_path.read_bytes()).hexdigest(),
        "seed_sha256": seed.get("content_sha256"),
        "dependency_interpreter_identity": (
            (seed.get("dependency_generation") or {}).get("interpreter_path")
            or (seed.get("interpreter") or {}).get("executable")
        ),
        "attestation": validation,
    }
    validator = request.source_runtime_validator
    if validator is not None:
        result = validator(request)
        if result is False or (isinstance(result, Mapping) and result.get("ok") is False):
            raise CliError("source_runtime_invalid", "source/runtime validator rejected dispatch")
        if not isinstance(result, Mapping) or result is True:
            raise CliError("source_runtime_invalid", "source/runtime validator returned an untyped result")
        for name in (
            "source_revision",
            "runtime_vector",
            "manifest_identity",
            "seed_identity",
            "dependency_interpreter_identity",
        ):
            if result.get(name) != authoritative.get(name):
                raise CliError(
                    "runtime_binding_mismatch",
                    f"injected runtime proof does not match current {name}",
                )
    return authoritative


def _validate_runtime_binding(request: WorkerAdmissionRequest) -> None:
    proof = _runtime_binding_proof(request)
    if not isinstance(proof, Mapping) or proof.get("ok") is False:
        raise CliError("source_runtime_invalid", "runtime binding proof is not positive")
    if request.production_intent:
        required_groups = (
            ("source_revision", "expected_revision"),
            ("manifest_identity", "manifest_sha256"),
            ("seed_identity", "seed_sha256"),
            ("dependency_interpreter_identity", "interpreter_path"),
        )
        if any(not any(proof.get(name) not in (None, "") for name in group) for group in required_groups):
            raise CliError("source_runtime_invalid", "runtime binding proof is missing a settled identity")
        if not proof.get("runtime_vector") and not proof.get("runtime_vector_sha256"):
            raise CliError("source_runtime_invalid", "runtime binding proof is missing the runtime vector")
    checks = {
        "source_revision": ("source_revision", "expected_revision"),
        "manifest_identity": ("manifest_identity", "manifest_sha256"),
        "seed_identity": ("seed_identity", "seed_sha256"),
        "dependency_interpreter_identity": ("dependency_interpreter_identity", "interpreter_path"),
    }
    for request_name, proof_names in checks.items():
        values = [proof.get(name) for name in proof_names if proof.get(name) not in (None, "")]
        if values and str(getattr(request, request_name)) not in {str(value) for value in values}:
            raise CliError("runtime_binding_mismatch", f"{request_name} does not match authoritative runtime proof")
    runtime_sha = proof.get("runtime_vector_sha256")
    authoritative_vector = proof.get("runtime_vector")
    if authoritative_vector is not None and authoritative_vector != request.runtime_vector:
        raise CliError("runtime_binding_mismatch", "runtime_vector does not match authoritative runtime proof")
    requested_runtime_sha = (
        request.runtime_vector.get("runtime_vector_sha256")
        if isinstance(request.runtime_vector, Mapping)
        else None
    )
    if runtime_sha and requested_runtime_sha and runtime_sha != requested_runtime_sha:
        raise CliError("runtime_binding_mismatch", "runtime_vector does not match authoritative runtime proof")


def _validate_native_liveness(
    liveness: Mapping[str, Any], *, provider: str, model: str, normalized_spec: str,
    backend: str, authoritative: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    required = ("kind", "identity", "digest", "backend", "provider", "normalized_model", "capability_registry", "proof", "observed_at")
    if any(not liveness.get(name) for name in required):
        raise CliError("route_liveness_invalid", "native route proof is incomplete")
    if liveness.get("kind") != "native_backend":
        raise CliError("route_liveness_invalid", "native route proof kind is invalid")
    if liveness.get("backend") != backend or liveness.get("provider") != provider:
        raise CliError("route_liveness_invalid", "native route proof backend/provider mismatch")
    if liveness.get("normalized_model") != model:
        raise CliError("route_liveness_invalid", "native route proof model/content mismatch")
    # Effort remains in the selected receipt/spec, but native liveness is
    # proved for the route/model coordinate only.
    route_identity = format_agent_spec(AgentSpec(provider, model=model))
    expected_family = _family(provider, model, route_identity)
    if authoritative is not None and liveness.get("family") != expected_family:
        raise CliError("route_liveness_invalid", "native route proof family mismatch")
    proof = liveness.get("proof")
    if authoritative is not None and (not isinstance(proof, Mapping) or proof.get("constructable") is not True):
        raise CliError("route_liveness_invalid", "native construction proof is not positively constructable")
    route = liveness.get("route") or liveness.get("route_identity")
    if route != route_identity:
        raise CliError("route_liveness_invalid", "native route proof selected route mismatch")
    if authoritative is not None:
        # The caller may carry an attestation for diagnostics, but the selected
        # construction seam is the authority.  Compare every proof component,
        # then recompute both identities from the authoritative content so a
        # well-shaped arbitrary digest cannot cross admission.
        proof_fields = (
            "backend", "provider", "normalized_model", "route", "route_identity",
            "family", "capability_registry", "registry_generation", "proof", "proof_generation",
            "identity", "observed_at",
        )
        for name in proof_fields:
            if name in liveness and name in authoritative and liveness.get(name) != authoritative.get(name):
                raise CliError("route_liveness_invalid", f"native route proof {name} disagrees with construction seam")
        liveness = authoritative
        route = liveness.get("route") or liveness.get("route_identity")
        if route != route_identity:
            raise CliError("route_liveness_invalid", "native construction seam selected route mismatch")
        registry = liveness.get("capability_registry")
        proof = liveness.get("proof")
        generation = liveness.get("registry_generation")
        proof_generation = liveness.get("proof_generation")
        if not isinstance(registry, Mapping) or not isinstance(proof, Mapping):
            raise CliError("route_liveness_invalid", "native construction proof content is untyped")
        catalog = registry.get("models") or registry.get("catalog")
        if isinstance(catalog, Mapping):
            catalog = list(catalog.values())
        members: set[str] = set()
        if isinstance(catalog, (list, tuple, set)):
            for item in catalog:
                if isinstance(item, str):
                    members.add(item.removeprefix("omp:").strip())
                elif isinstance(item, Mapping):
                    slug = item.get("slug") or item.get("id") or item.get("model")
                    if isinstance(slug, str):
                        members.add(slug.removeprefix("omp:").strip())
        if model not in members:
            raise CliError("route_liveness_missing", "native model is not an authoritative catalog member")
        if proof.get("constructable") is not True:
            raise CliError("route_liveness_invalid", "native construction proof is not positively constructable")
        preparation = proof.get("preparation")
        if (
            not isinstance(preparation, Mapping)
            or preparation.get("ok") is not True
            or preparation.get("provider") != provider
            or preparation.get("model") != model
            or preparation.get("route") != route_identity
        ):
            raise CliError("route_liveness_invalid", "native constructor preparation is missing or mismatched")
        if isinstance(proof.get("registry"), Mapping) and proof.get("registry") != registry:
            raise CliError("route_liveness_invalid", "native construction proof registry disagrees with capability registry")
        if generation in (None, "") or proof_generation in (None, ""):
            raise CliError("route_liveness_invalid", "native route proof generation is missing")
        try:
            observed = datetime.fromisoformat(str(liveness.get("observed_at")).replace("Z", "+00:00"))
            age_s = time.time() - observed.timestamp()
        except (TypeError, ValueError, OverflowError):
            raise CliError("route_liveness_invalid", "native route proof observation timestamp is invalid")
        if age_s < -300.0 or age_s > NATIVE_PROOF_MAX_AGE_S:
            raise CliError("route_liveness_stale", "native route proof observation is stale")
        identity_content = {
            "backend": backend,
            "provider": provider,
            "normalized_model": model,
            "route": route_identity,
            "capability_registry": registry,
            "registry_generation": generation,
            "proof": proof,
            "proof_generation": proof_generation,
        }
        identity_content["family"] = expected_family
        expected_identity = _digest(identity_content)
        if liveness.get("identity") != expected_identity:
            raise CliError("route_liveness_invalid", "native route proof identity is not recomputed from authoritative content")
        expected_digest = _digest({
            **identity_content,
            "identity": expected_identity,
            "observed_at": liveness.get("observed_at"),
        })
        if liveness.get("digest") != expected_digest:
            raise CliError("route_liveness_invalid", "native route proof digest is not recomputed from authoritative content")
    return liveness


def _validate_basic(request: WorkerAdmissionRequest) -> AdmissionRefusal | None:
    for name in (
        "plan_id", "phase", "dispatch_family_id", "logical_dispatch_id",
        "physical_door_id", "configured_spec", "selected_spec",
        "source_revision", "manifest_identity", "seed_identity",
        "dependency_interpreter_identity", "prompt_or_phase_input_identity",
        "authorized_route_identity",
        "projection_key",
    ):
        if not isinstance(getattr(request, name), str) or not getattr(request, name).strip():
            return _refusal(request, "invalid_request", f"{name} is required")
    if request.runtime_vector is None or request.runtime_vector == "" or request.runtime_vector == {}:
        return _refusal(request, "runtime_binding_missing", "runtime vector is required")
    try:
        configured = parse_agent_spec(request.configured_spec)
        selected = parse_agent_spec(request.selected_spec)
    except (CliError, ValueError) as exc:
        return _refusal(request, "invalid_spec", str(exc))
    if configured.agent != selected.agent and not request.configured_fallback_chain_identity:
        return _refusal(request, "invalid_spec", "configured and selected routes disagree")
    if isinstance(request.admission_attempt, bool) or request.admission_attempt < 1:
        return _refusal(request, "invalid_request", "admission_attempt must be positive")
    if isinstance(request.timeout_budget_s, bool) or not isinstance(request.timeout_budget_s, (int, float)) or request.timeout_budget_s <= 0:
        return _refusal(request, "invalid_timeout", "timeout budget must be finite and positive")
    if request.timeout_budget_s != request.timeout_budget_s or request.timeout_budget_s == float("inf"):
        return _refusal(request, "invalid_timeout", "timeout budget must be finite")
    return None


def require_production_worker_dispatch_runtime(request: WorkerAdmissionRequest | Mapping[str, Any] | None = None, **legacy_kwargs: Any) -> Any:
    """Admit one production logical dispatch, or preserve the old seed API.

    The no-argument/legacy form is intentionally retained for Batch-1 callers.
    Passing a ``WorkerAdmissionRequest`` selects the canonical typed admission
    path and returns ``WorkerAdmissionReceipt | SchedulingCondition | AdmissionRefusal``.
    """
    if request is None:
        from arnold_pipelines.megaplan.cloud.runtime_attestation import _legacy_require_production_worker_dispatch_runtime
        return _legacy_require_production_worker_dispatch_runtime(**legacy_kwargs)
    if not isinstance(request, WorkerAdmissionRequest):
        try:
            request = WorkerAdmissionRequest.from_dict(request)
        except (TypeError, ValueError) as exc:
            return _refusal(request, "invalid_request", f"invalid admission request: {exc}")
    basic = _validate_basic(request)
    if basic:
        return basic
    if request.production_intent and any(
        hook is not None
        for hook in (
            request.route_liveness_resolver,
            request.source_runtime_validator,
            request.memory_headroom_reader,
            request.cooldown_reader,
        )
    ):
        return _refusal(
            request,
            "production_input_substitution",
            "production admission observations are backend/system-owned",
        )
    if request.production_intent and request.native_construction_seam is not None:
        return _refusal(
            request,
            "production_constructor_unauthorized",
            "production construction seam is not a request-supplied capability",
        )
    try:
        parsed = parse_agent_spec(request.selected_spec)
        agent = parsed.agent
        model = parsed.model or request.selected_spec
        if agent == "omp":
            from arnold_pipelines.megaplan.workers.omp import validate_omp_catalog_model
            provider, model_id = model.split("/", 1) if "/" in model else ("", "")
            if not provider or not model_id:
                return _refusal(request, "invalid_spec", "OMP selected spec lacks provider/model")
            normalized_model = validate_omp_catalog_model(provider, model_id)
            normalized_spec = f"omp:{normalized_model}"
            family = _family(provider, model_id, normalized_spec)
            if request.production_intent:
                # The OMP catalog command is the sole live-membership authority.
                # A request callback cannot replace it with caller-shaped data.
                liveness = resolve_omp_live_membership(
                    provider, model_id,
                    timeout_s=min(10.0, float(request.timeout_budget_s)),
                )
            else:
                liveness = (request.route_liveness_resolver or (lambda p, m, _s: resolve_omp_live_membership(p, m, timeout_s=min(10.0, float(request.timeout_budget_s)))))(provider, model_id, normalized_spec)
        else:
            normalized_spec = request.selected_spec.strip()
            provider = agent
            model = model
            route_identity = format_agent_spec(AgentSpec(provider, model=model))
            family = _family(provider, model, route_identity)
            if request.production_intent:
                authoritative = _default_native_liveness(agent, model)
                liveness = _validate_native_liveness(
                    authoritative,
                    provider=provider,
                    model=model,
                    normalized_spec=normalized_spec,
                    backend=agent,
                    authoritative=authoritative,
                )
            elif request.native_construction_seam is not None:
                # Explicitly non-production unit seam.  Production requests
                # are rejected above before this branch can be reached.
                authoritative = request.native_construction_seam(provider, model, normalized_spec)
                supplied = request.route_liveness_resolver(provider, model, normalized_spec) if request.route_liveness_resolver is not None else authoritative
                liveness = _validate_native_liveness(
                    supplied,
                    provider=provider,
                    model=model,
                    normalized_spec=normalized_spec,
                    backend=agent,
                    authoritative=authoritative,
                )
            else:
                liveness = (request.route_liveness_resolver or (lambda p, m, _s: _default_native_liveness(agent, m)))(provider, model, normalized_spec)
                liveness = _validate_native_liveness(liveness, provider=provider, model=model, normalized_spec=normalized_spec, backend=agent)
        if request.authorized_route_identity not in {request.selected_spec.strip(), normalized_spec}:
            return _refusal(request, "route_authorization_invalid", "authorized route does not match selected route")
        if not isinstance(liveness, Mapping) or not liveness.get("identity") or not liveness.get("digest"):
            return _refusal(request, "route_liveness_invalid", "route resolver did not return positive proof")
        expected_kind = "omp_membership" if agent == "omp" else "native_backend"
        if liveness.get("kind") != expected_kind:
            return _refusal(request, "route_liveness_invalid", f"route proof kind must be {expected_kind}")
        # A fallback/return child is a new canonical operation, never an
        # implicit second launch of its parent.  Preserve the existing typed
        # authorization boundary without consulting IncidentLedger: the
        # parent terminal and authorizing event must be supplied explicitly.
        linked_fields = (
            request.parent_logical_dispatch_id,
            request.authorizing_event_id,
            request.parent_terminal_event_id,
        )
        if any(linked_fields) and not all(linked_fields):
            return _refusal(
                request,
                "linked_child_authorization_missing",
                "linked child authority is incomplete",
            )
        _validate_runtime_binding(request)
        cooldown_reader = request.cooldown_reader
        if cooldown_reader is None:
            from arnold_pipelines.megaplan.runtime.memory_headroom import memory_cooldown_wait_secs
            cooldown_reader = lambda root, phase, spec: memory_cooldown_wait_secs(root, phase, spec=spec)
        wait = float(cooldown_reader(request.ledger_root, request.phase, normalized_spec) or 0.0)
        if wait > 0:
            return SchedulingCondition(condition_id=_digest(("memory_cooldown", request.plan_id, request.phase, request.logical_dispatch_id, request.admission_attempt)), reason="memory_cooldown", plan_id=request.plan_id, phase=request.phase, spec=normalized_spec, dispatch_family_id=request.dispatch_family_id, logical_dispatch_id=request.logical_dispatch_id, admission_attempt=request.admission_attempt, retry_after_s=wait, observed_at=_now(), evidence={"reason": "same_phase_spec_cgroup_oom_cooldown", "retry_after_s": wait})
        memory_reader = request.memory_headroom_reader
        if memory_reader is None:
            from arnold_pipelines.megaplan.runtime.memory_headroom import classify_memory_headroom, read_cgroup_memory_snapshot
            memory_reader = lambda spec: classify_memory_headroom(spec, read_cgroup_memory_snapshot())
        memory = memory_reader(normalized_spec)
        if request.production_intent and (not isinstance(memory, Mapping) or memory.get("ok") is not True):
            return _refusal(request, "insufficient_memory_headroom", "positive memory headroom proof is required", memory=dict(memory or {}))
        fingerprint = semantic_dispatch_fingerprint(phase=request.phase, selected_spec=normalized_spec, model_family=family, prompt_or_phase_input_identity=request.prompt_or_phase_input_identity, source_revision=request.source_revision, runtime_vector=request.runtime_vector, manifest_identity=request.manifest_identity, seed_identity=request.seed_identity, dependency_interpreter_identity=request.dependency_interpreter_identity, timeout_policy_identity=_digest(request.timeout_budget_s), configured_fallback_chain_identity=request.configured_fallback_chain_identity, authorized_route_identity=request.authorized_route_identity)
        execution_context_identity = _digest({"plan_id": request.plan_id, "phase": request.phase, "logical_dispatch_id": request.logical_dispatch_id, "physical_door_id": request.physical_door_id, "semantic_dispatch_fingerprint": fingerprint})
        # Admission is deliberately side-effect free.  The canonical launch
        # engine performs the atomic admit at the physical venue after this
        # complete preflight has passed.  The receipt IDs below are stable
        # identities, not a shadow reservation/marker authority.
        operation_id = request.logical_dispatch_id
        request_id = _digest({
            "operation_id": operation_id,
            "plan_id": request.plan_id,
            "phase": request.phase,
            "dispatch_family_id": request.dispatch_family_id,
            "physical_door_id": request.physical_door_id,
            "semantic_dispatch_fingerprint": fingerprint,
            "admission_attempt": request.admission_attempt,
        })
        preflight_digest = _digest({
            "request_id": request_id,
            "operation_id": operation_id,
            "semantic_dispatch_fingerprint": fingerprint,
            "route_liveness_identity": str(liveness.get("identity")),
            "route_liveness_digest": str(liveness.get("digest")),
            "execution_context_identity": execution_context_identity,
        })
        receipt_id = _digest(("worker-admission", operation_id, request_id, fingerprint))
        reservation_event_id = _digest(("launch-admission", operation_id, request_id))
        store_root = request.operation_store_root or ((request.ledger_root or Path.cwd()) / "ops")
        context = WorkerExecutionContextRef(str(request.ledger_root or Path.cwd()), request.plan_id, request.phase, request.dispatch_family_id, request.logical_dispatch_id, receipt_id, fingerprint, normalized_spec, request.physical_door_id, operation_store_root=str(store_root))
        return WorkerAdmissionReceipt(receipt_id, request.plan_id, request.phase, request.dispatch_family_id, request.logical_dispatch_id, request.parent_logical_dispatch_id, request.authorizing_event_id, request.physical_door_id, request.admission_attempt, normalized_spec, provider, model, family, str(liveness.get("kind")), str(liveness.get("identity")), str(liveness.get("digest")), float(request.timeout_budget_s), request.source_revision, request.runtime_vector, request.manifest_identity, request.seed_identity, request.dependency_interpreter_identity, fingerprint, request.projection_key, int(request.expected_projection_version or 0), reservation_event_id, request.changed_precondition_event_id, None, _now(), context, request.production_intent, operation_id, request_id, preflight_digest, str(store_root))
    except (CliError, ValueError, OSError) as exc:
        return _refusal(request, getattr(exc, "code", "admission_rejected"), str(exc))


def _worker_identity(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(
        key in value for key in ("host", "pid", "boot_id")
    ):
        raise ValueError("worker identity is required from the final worker result")
    if (
        not isinstance(value.get("host"), str)
        or not value.get("host")
        or isinstance(value.get("pid"), bool)
        or not isinstance(value.get("pid"), int)
        or value["pid"] <= 0
        or not isinstance(value.get("boot_id"), str)
        or not value.get("boot_id")
    ):
        raise ValueError("worker identity is malformed")
    return dict(value)


def _validate_outcome_context(
    value: DispatchOutcome,
    receipt: WorkerAdmissionReceipt,
    started: str,
    finished: str,
    *,
    require_accepted: bool = True,
) -> DispatchOutcome:
    # Fill transport context from the authoritative admission receipt. This
    # keeps legacy typed outcomes source-compatible while making the canonical
    # provider/route proof survive every boundary.
    for name, expected_value in {
        "provider": receipt.provider,
        "route_liveness_kind": receipt.route_liveness_kind,
        "route_liveness_identity": receipt.route_liveness_identity,
        "route_liveness_digest": receipt.route_liveness_digest,
    }.items():
        supplied = getattr(value, name)
        if supplied is not None and supplied != expected_value:
            raise ValueError(f"dispatch outcome context mismatch: {name}")
    value = replace(
        value,
        provider=value.provider or receipt.provider,
        route_liveness_kind=value.route_liveness_kind or receipt.route_liveness_kind,
        route_liveness_identity=value.route_liveness_identity or receipt.route_liveness_identity,
        route_liveness_digest=value.route_liveness_digest or receipt.route_liveness_digest,
    )
    expected = {
        "plan_id": receipt.plan_id,
        "phase": receipt.phase,
        "dispatch_family_id": receipt.dispatch_family_id,
        "logical_dispatch_id": receipt.logical_dispatch_id,
        "admission_receipt_id": receipt.admission_receipt_id,
        "semantic_dispatch_fingerprint": receipt.semantic_dispatch_fingerprint,
        "selected_spec": receipt.normalized_spec,
    }
    if require_accepted:
        expected["launch_state"] = "accepted"
    for name, expected_value in expected.items():
        if getattr(value, name) != expected_value:
            raise ValueError(f"dispatch outcome context mismatch: {name}")
    if not value.worker_identity or not isinstance(value.worker_identity, Mapping):
        raise ValueError("dispatch outcome requires typed worker identity")
    if not value.started_at or not value.finished_at:
        raise ValueError("dispatch outcome requires complete timing context")
    return value


def _unresolved_outcome(
    receipt: WorkerAdmissionReceipt,
    *,
    worker_identity: Any = None,
    started_at: str | None = None,
    finished_at: str | None = None,
) -> DispatchOutcome:
    return DispatchOutcome(
        kind="unresolved_launch",
        launch_state="ambiguous",
        plan_id=receipt.plan_id,
        phase=receipt.phase,
        dispatch_family_id=receipt.dispatch_family_id,
        logical_dispatch_id=receipt.logical_dispatch_id,
        admission_receipt_id=receipt.admission_receipt_id,
        semantic_dispatch_fingerprint=receipt.semantic_dispatch_fingerprint,
        selected_spec=receipt.normalized_spec,
        provider=receipt.provider,
        route_liveness_kind=receipt.route_liveness_kind,
        route_liveness_identity=receipt.route_liveness_identity,
        route_liveness_digest=receipt.route_liveness_digest,
        worker_identity=worker_identity,
        started_at=started_at,
        finished_at=finished_at,
    )


def _normalize_outcome(value: Any, receipt: WorkerAdmissionReceipt, started: str, finished: str) -> DispatchOutcome:
    launch_metadata: Mapping[str, Any] = {}
    if isinstance(value, DispatchOutcome):
        if value.kind == "no_launch":
            return value
        if value.kind == "unresolved_launch":
            if value.admission_receipt_id is not None:
                return _validate_outcome_context(
                    value, receipt, started, finished, require_accepted=False
                )
            return value
        return _validate_outcome_context(value, receipt, started, finished)
    if isinstance(value, LaunchResult):
        if not value.accepted:
            raise RuntimeError("launch operation did not positively establish no-acceptance")
        launch_metadata = {
            name: item for name, item in {
                "worker_identity": value.worker_identity,
                "started_at": value.started_at,
                "finished_at": value.finished_at,
            }.items() if item is not None
        }
        value = value.value
    if isinstance(value, Mapping) and "kind" in value:
        data = dict(value)
        data.setdefault("schema_version", 1)
        data.setdefault("plan_id", receipt.plan_id)
        data.setdefault("phase", receipt.phase)
        data.setdefault("dispatch_family_id", receipt.dispatch_family_id)
        data.setdefault("logical_dispatch_id", receipt.logical_dispatch_id)
        data.setdefault("admission_receipt_id", receipt.admission_receipt_id)
        data.setdefault("semantic_dispatch_fingerprint", receipt.semantic_dispatch_fingerprint)
        data.setdefault("selected_spec", receipt.normalized_spec)
        data.setdefault("provider", receipt.provider)
        data.setdefault("route_liveness_kind", receipt.route_liveness_kind)
        data.setdefault("route_liveness_identity", receipt.route_liveness_identity)
        data.setdefault("route_liveness_digest", receipt.route_liveness_digest)
        data.setdefault("launch_state", "accepted")
        data.setdefault("started_at", started)
        data.setdefault("finished_at", finished)
        data.setdefault("worker_identity", _worker_identity(data.get("worker_identity")))
        candidate = DispatchOutcome.from_dict(data)
        if candidate.kind == "no_launch":
            return candidate
        if candidate.kind == "unresolved_launch":
            if candidate.admission_receipt_id is None:
                return candidate
            _validate_outcome_context(candidate, receipt, started, finished, require_accepted=False)
            return candidate
        return _validate_outcome_context(candidate, receipt, started, finished)
    if _is_worker_result(value):
        payload = getattr(value, "payload", None)
        embedded = payload.get("dispatch_outcome") if isinstance(payload, Mapping) else None
        if embedded is None:
            metadata = getattr(value, "auth_metadata", None)
            embedded = metadata.get("dispatch_outcome") if isinstance(metadata, Mapping) else None
        own_identity = getattr(value, "worker_identity", None)
        if isinstance(embedded, Mapping) and isinstance(own_identity, Mapping) and embedded.get("worker_identity") is not None and embedded.get("worker_identity") != own_identity:
            raise ValueError("worker identity disagrees with typed terminal outcome")
        if isinstance(embedded, Mapping):
            embedded = {
                "schema_version": 1,
                "kind": embedded.get("kind"),
                "launch_state": embedded.get("launch_state", "accepted"),
                "plan_id": embedded.get("plan_id", receipt.plan_id),
                "phase": embedded.get("phase", receipt.phase),
                "dispatch_family_id": embedded.get("dispatch_family_id", receipt.dispatch_family_id),
                "logical_dispatch_id": embedded.get("logical_dispatch_id", receipt.logical_dispatch_id),
                "admission_receipt_id": embedded.get("admission_receipt_id", receipt.admission_receipt_id),
                "semantic_dispatch_fingerprint": embedded.get("semantic_dispatch_fingerprint", receipt.semantic_dispatch_fingerprint),
                "selected_spec": embedded.get("selected_spec", receipt.normalized_spec),
                "provider": embedded.get("provider", receipt.provider),
                "route_liveness_kind": embedded.get("route_liveness_kind", receipt.route_liveness_kind),
                "route_liveness_identity": embedded.get("route_liveness_identity", receipt.route_liveness_identity),
                "route_liveness_digest": embedded.get("route_liveness_digest", receipt.route_liveness_digest),
                "worker_identity": embedded.get("worker_identity") or getattr(value, "worker_identity", None) or launch_metadata.get("worker_identity"),
                "started_at": embedded.get("started_at") or getattr(value, "started_at", None) or launch_metadata.get("started_at") or started,
                "finished_at": embedded.get("finished_at") or getattr(value, "finished_at", None) or launch_metadata.get("finished_at") or finished,
                "success_payload": embedded.get("success_payload"),
                "terminal_failure": embedded.get("terminal_failure"),
                "provider_evidence": embedded.get("provider_evidence"),
                "provider_failure_key": embedded.get("provider_failure_key"),
                "disposition_id": embedded.get("disposition_id"),
                "reconciliation_event_id": embedded.get("reconciliation_event_id"),
                "terminal_outcome_event_id": embedded.get("terminal_outcome_event_id"),
            }
            return _normalize_outcome(embedded, receipt, started, finished)
    # WorkerResult is the only legacy operation result still accepted: its
    # typed payload is the native worker seam's positive completion proof.  A
    # terminal outcome must use the explicit ``dispatch_outcome`` envelope;
    # arbitrary payload fields never change a successful WorkerResult.
    if _is_worker_result(value):
        if _worker_result_is_failure_shaped(value):
            raise TypeError("failure-shaped WorkerResult requires a typed dispatch_outcome envelope")
        identity = getattr(value, "worker_identity", None) or launch_metadata.get("worker_identity")
        return _validate_outcome_context(DispatchOutcome(kind="success", launch_state="accepted", plan_id=receipt.plan_id, phase=receipt.phase, dispatch_family_id=receipt.dispatch_family_id, logical_dispatch_id=receipt.logical_dispatch_id, admission_receipt_id=receipt.admission_receipt_id, semantic_dispatch_fingerprint=receipt.semantic_dispatch_fingerprint, selected_spec=receipt.normalized_spec, worker_identity=_worker_identity(identity), started_at=getattr(value, "started_at", None) or launch_metadata.get("started_at") or started, finished_at=getattr(value, "finished_at", None) or launch_metadata.get("finished_at") or finished, success_payload=getattr(value, "payload", None)), receipt, started, finished)
    if isinstance(value, tuple) and len(value) == 4 and _is_worker_result(value[0]):
        worker = value[0]
        worker_identity = getattr(worker, "worker_identity", None)
        payload = getattr(worker, "payload", None)
        embedded = payload.get("dispatch_outcome") if isinstance(payload, Mapping) else None
        if embedded is None:
            metadata = getattr(worker, "auth_metadata", None)
            embedded = metadata.get("dispatch_outcome") if isinstance(metadata, Mapping) else None
        if isinstance(embedded, Mapping):
            if (
                isinstance(worker_identity, Mapping)
                and embedded.get("worker_identity") is not None
                and embedded.get("worker_identity") != worker_identity
            ):
                raise ValueError("worker identity disagrees with typed terminal outcome")
            embedded = {
                "schema_version": 1,
                "kind": embedded.get("kind"),
                "launch_state": embedded.get("launch_state", "accepted"),
                "plan_id": embedded.get("plan_id", receipt.plan_id),
                "phase": embedded.get("phase", receipt.phase),
                "dispatch_family_id": embedded.get("dispatch_family_id", receipt.dispatch_family_id),
                "logical_dispatch_id": embedded.get("logical_dispatch_id", receipt.logical_dispatch_id),
                "admission_receipt_id": embedded.get("admission_receipt_id", receipt.admission_receipt_id),
                "semantic_dispatch_fingerprint": embedded.get("semantic_dispatch_fingerprint", receipt.semantic_dispatch_fingerprint),
                "selected_spec": embedded.get("selected_spec", receipt.normalized_spec),
                "provider": embedded.get("provider", receipt.provider),
                "route_liveness_kind": embedded.get("route_liveness_kind", receipt.route_liveness_kind),
                "route_liveness_identity": embedded.get("route_liveness_identity", receipt.route_liveness_identity),
                "route_liveness_digest": embedded.get("route_liveness_digest", receipt.route_liveness_digest),
                "worker_identity": embedded.get("worker_identity") or worker_identity or launch_metadata.get("worker_identity"),
                "started_at": embedded.get("started_at") or getattr(worker, "started_at", None) or launch_metadata.get("started_at") or started,
                "finished_at": embedded.get("finished_at") or getattr(worker, "finished_at", None) or launch_metadata.get("finished_at") or finished,
                "success_payload": embedded.get("success_payload"),
                "terminal_failure": embedded.get("terminal_failure"),
                "provider_evidence": embedded.get("provider_evidence"),
                "provider_failure_key": embedded.get("provider_failure_key"),
                "disposition_id": embedded.get("disposition_id"),
                "reconciliation_event_id": embedded.get("reconciliation_event_id"),
                "terminal_outcome_event_id": embedded.get("terminal_outcome_event_id"),
            }
            return _normalize_outcome(embedded, receipt, started, finished)
        if _worker_result_is_failure_shaped(worker):
            raise TypeError("failure-shaped WorkerResult requires a typed dispatch_outcome envelope")
        identity = getattr(worker, "worker_identity", None) or launch_metadata.get("worker_identity")
        return _validate_outcome_context(DispatchOutcome(kind="success", launch_state="accepted", plan_id=receipt.plan_id, phase=receipt.phase, dispatch_family_id=receipt.dispatch_family_id, logical_dispatch_id=receipt.logical_dispatch_id, admission_receipt_id=receipt.admission_receipt_id, semantic_dispatch_fingerprint=receipt.semantic_dispatch_fingerprint, selected_spec=receipt.normalized_spec, worker_identity=_worker_identity(identity), started_at=getattr(worker, "started_at", None) or launch_metadata.get("started_at") or started, finished_at=getattr(worker, "finished_at", None) or launch_metadata.get("finished_at") or finished, success_payload=getattr(worker, "payload", None)), receipt, started, finished)
    if isinstance(value, ManagedCommandResult):
        kind = "success" if value.returncode == 0 else "ordinary_terminal_failure"
        return _validate_outcome_context(DispatchOutcome(kind=kind, launch_state="accepted", plan_id=receipt.plan_id, phase=receipt.phase, dispatch_family_id=receipt.dispatch_family_id, logical_dispatch_id=receipt.logical_dispatch_id, admission_receipt_id=receipt.admission_receipt_id, semantic_dispatch_fingerprint=receipt.semantic_dispatch_fingerprint, selected_spec=receipt.normalized_spec, worker_identity=_worker_identity(value.worker_identity), started_at=started, finished_at=finished, success_payload=None if value.returncode else {"returncode": 0}, terminal_failure=None if value.returncode == 0 else {"returncode": value.returncode}), receipt, started, finished)
    raise TypeError(f"untyped final-launch result cannot be projected: {type(value).__name__}")


def _canonical_worker_launch(
    receipt: WorkerAdmissionReceipt,
    launch: Callable[[WorkerExecutionContextRef], Any],
    *,
    store: Any,
    ledger: IncidentLedger | None,
) -> tuple[Any, DispatchOutcome | None]:
    """Run a worker physical door through the canonical launch transaction.

    ``ControlledFinalLaunch`` is retained as a thin custody adapter here.  It
    does not write its former lifecycle markers; admission and accepted
    identity are committed only by ``launch_transaction``.
    """
    from arnold_pipelines.megaplan.cloud.controlled_final_launch import ControlledFinalLaunch

    controlled = ControlledFinalLaunch(receipt, ledger=ledger, canonical=True)
    envelope = _worker_launch_envelope(receipt)
    started = _now()
    physical_value: Any = None

    def dispatch(_envelope: LaunchEnvelope) -> Any:
        # The closure is the sole physical door.  The engine invokes it once;
        # replay and reconciliation return before this callback.
        nonlocal physical_value
        physical_value = controlled.run(launch)
        return physical_value

    def observe(value: Any, candidate: LaunchEnvelope) -> Mapping[str, Any]:
        raw = value.value if isinstance(value, LaunchResult) else value
        identity = getattr(raw, "worker_identity", None)
        if identity is None and isinstance(raw, tuple) and len(raw) == 4:
            identity = getattr(raw[0], "worker_identity", None)
        if not isinstance(identity, Mapping):
            identity = controlled.accepted_worker_identity
        if not isinstance(identity, Mapping):
            raise ValueError("physical worker door returned no exact worker identity")
        process_identity = identity.get("process_start_identity")
        if receipt.production_intent and (not isinstance(process_identity, str) or not process_identity):
            raise ValueError("physical worker door returned no process incarnation")
        process_identity = str(process_identity or _digest(identity))
        return {
            "operation_id": candidate.operation_id,
            "request_id": candidate.request_id,
            "envelope_digest": candidate.digest,
            "liveness": "running",
            "process_session_identity": process_identity,
            "worker_identity": dict(identity),
            "observed_at": _now(),
        }

    def resource_factory(value: Any, observation: Mapping[str, Any], candidate: LaunchEnvelope) -> TypedResource:
        identity = observation["process_session_identity"]
        return TypedResource(
            id=f"{candidate.operation_id}:process",
            operation_id=candidate.operation_id,
            resource_type=ResourceType.PROCESS_SESSION,
            name=str(identity),
            details={
                "worker_identity": dict(observation.get("worker_identity") or {}),
                "physical_door_id": receipt.physical_door_id,
                "venue": candidate.venue,
            },
        )

    result = launch_transaction(
        envelope,
        store=store,
        preflight=_WorkerPreflight(receipt.preflight_digest),
        dispatch=dispatch,
        observe=observe,
        resource_factory=resource_factory,
        operation_type="megaplan_worker",
    )
    finished = _now()
    if result.result is not DurableLaunchResult.ACCEPTED:
        return result, None
    if physical_value is None:
        # Exact replay returns from the store before touching the physical
        # closure.  Reconstruct only the typed success view from the accepted
        # process resource; never redispatch or infer a new identity.
        accepted = result.store_result
        operation = getattr(accepted, "operation", None)
        process_resource = getattr(accepted, "process_resource", None)
        if process_resource is None:
            try:
                operation = store.load_operation_run(receipt.operation_id or receipt.logical_dispatch_id)
                process_resource = next(
                    resource for resource in store.list_typed_resources(operation.id)
                    if resource.resource_type is ResourceType.PROCESS_SESSION
                )
            except (OSError, KeyError, StopIteration, TypeError, ValueError):
                process_resource = None
        identity = dict((getattr(process_resource, "details", {}) or {}).get("worker_identity") or {})
        if not identity:
            return result, None
        started_at = getattr(operation, "started_at", None)
        started_text = started_at.isoformat() if hasattr(started_at, "isoformat") else str(started_at or started)
        outcome = DispatchOutcome(
            kind="success",
            launch_state="accepted",
            plan_id=receipt.plan_id,
            phase=receipt.phase,
            dispatch_family_id=receipt.dispatch_family_id,
            logical_dispatch_id=receipt.logical_dispatch_id,
            admission_receipt_id=receipt.admission_receipt_id,
            semantic_dispatch_fingerprint=receipt.semantic_dispatch_fingerprint,
            selected_spec=receipt.normalized_spec,
            provider=receipt.provider,
            route_liveness_kind=receipt.route_liveness_kind,
            route_liveness_identity=receipt.route_liveness_identity,
            route_liveness_digest=receipt.route_liveness_digest,
            worker_identity=identity,
            started_at=started_text,
            finished_at=started_text,
            success_payload={"replayed": True},
        )
        return result, outcome
    outcome = _normalize_outcome(physical_value, receipt, started, finished)
    return result, outcome


def build_authorized_linked_child_request(
    parent: WorkerAdmissionRequest | Mapping[str, Any],
    *,
    selected_spec: str,
    logical_dispatch_id: str,
    authorizing_event_id: str,
    physical_door_id: str | None = None,
    dispatch_family_id: str | None = None,
    **changes: Any,
) -> WorkerAdmissionRequest:
    if isinstance(parent, Mapping) and parent.get("kind") in {"no_launch", "unresolved_launch"}:
        raise ValueError("linked child cannot be created from no-launch or unresolved parent")
    parent_terminal_from_outcome = parent.get("terminal_outcome_event_id") if isinstance(parent, Mapping) else None
    if not isinstance(parent, WorkerAdmissionRequest):
        parent_payload = dict(parent)
        # The terminal-parent marker is authorization context, not part of the
        # admission request wire schema.  Accept it on a request mapping while
        # keeping ``WorkerAdmissionRequest.from_dict`` strict.
        parent_payload.pop("terminal_outcome_event_id", None)
        parent = WorkerAdmissionRequest.from_dict(parent_payload)
    parent_terminal = changes.pop("parent_terminal_event_id", None) or parent_terminal_from_outcome
    if not parent_terminal:
        raise ValueError("linked child requires a canonical terminal parent event")
    if logical_dispatch_id == parent.logical_dispatch_id:
        raise ValueError("linked child must use a fresh logical dispatch id")
    if not authorizing_event_id:
        raise ValueError("linked child requires durable authorizing event")
    parent_source_spec = changes.pop("parent_source_spec", parent.selected_spec)
    return replace(
        parent,
        logical_dispatch_id=logical_dispatch_id,
        parent_logical_dispatch_id=parent.logical_dispatch_id,
        authorizing_event_id=authorizing_event_id,
        parent_terminal_event_id=parent_terminal,
        parent_source_spec=parent_source_spec,
        transition_kind=changes.pop("transition_kind", "provider_recovery"),
        precondition_identity=changes.pop("precondition_identity", authorizing_event_id),
        physical_door_id=physical_door_id or parent.physical_door_id,
        dispatch_family_id=dispatch_family_id or parent.dispatch_family_id,
        selected_spec=selected_spec,
        configured_spec=changes.pop("configured_spec", selected_spec),
        changed_precondition_event_id=changes.pop("changed_precondition_event_id", None),
        admission_attempt=1,
        **changes,
    )


def reconcile_no_launch(
    receipt: WorkerAdmissionReceipt,
    *,
    evidence_event_ids: tuple[str, ...] | list[str],
    ledger: IncidentLedger,
    evidence_kind: str = "controlled_adapter",
    observed_at: str | None = None,
) -> DispatchOutcome:
    """Release a reservation only from positive persisted no-launch proof."""
    ids = tuple(str(item) for item in evidence_event_ids if str(item))
    if not ids:
        raise ValueError("no-launch reconciliation requires positive evidence IDs")
    persisted = ledger.read_nbf_events()
    related = []
    for record in persisted:
        item = record.get("payload", {})
        if (
            item.get("reservation_event_id") == receipt.reservation_event_id
            and item.get("admission_receipt_id") == receipt.admission_receipt_id
        ) or (
            item.get("event_type") == "worker_disposition"
            and item.get("admission_receipt_id") == receipt.admission_receipt_id
            and item.get("logical_dispatch_id") == receipt.logical_dispatch_id
        ):
            related.append(item)
    prior_release = next(
        (item for item in related
         if item.get("event_type") == "reservation_reconciled"
         and item.get("resolution") == "released_no_launch"),
        None,
    )
    if prior_release is not None:
        return DispatchOutcome(
            kind="no_launch", launch_state="not_started",
            plan_id=receipt.plan_id, phase=receipt.phase,
            dispatch_family_id=receipt.dispatch_family_id,
            logical_dispatch_id=receipt.logical_dispatch_id,
            admission_receipt_id=None, semantic_dispatch_fingerprint=None,
            selected_spec=receipt.normalized_spec,
            reconciliation_event_id=str(prior_release.get("reconciliation_id") or prior_release.get("event_id")),
        )
    if any(
        item.get("launch_state_identity") in {"entered", "accepted", "closed", "ambiguous"}
        or item.get("event_type") in {"worker_terminal_outcome", "worker_disposition"}
        or (item.get("event_type") == "reservation_reconciled" and item.get("resolution") != "released_no_launch")
        for item in related
    ):
        raise ValueError("no-launch reconciliation has contradictory persisted launch evidence")
    evidence = [
        record.get("payload", {})
        for record in persisted
        if record.get("payload", {}).get("event_id") in ids
    ]
    valid_physical_evidence = False
    for item in evidence:
        operation = item.get("physical_operation_evidence") or item.get("operation_evidence")
        if (
            item.get("event_type") == "controlled_adapter_state"
            and item.get("reservation_event_id") == receipt.reservation_event_id
            and item.get("admission_receipt_id") == receipt.admission_receipt_id
            and item.get("physical_door_id") == receipt.physical_door_id
            and item.get("launch_state_identity") == "not_started"
            and isinstance(operation, Mapping)
            and operation.get("reservation_event_id") == receipt.reservation_event_id
            and operation.get("admission_receipt_id") == receipt.admission_receipt_id
            and operation.get("physical_door_id") == receipt.physical_door_id
            and operation.get("launch_state_identity") == "not_started"
            and operation.get("observed_at")
        ):
            valid_physical_evidence = True
            break
    if not valid_physical_evidence:
        raise ValueError("no-launch reconciliation requires a bound not_started marker")
    when = observed_at or _now()
    reconciliation_id = _digest((receipt.reservation_event_id, "released_no_launch", ids))
    reconciliation = ReservationReconciled(
        reconciliation_id=reconciliation_id,
        plan_id=receipt.plan_id,
        phase=receipt.phase,
        projection_key=receipt.projection_key,
        logical_dispatch_id=receipt.logical_dispatch_id,
        admission_receipt_id=receipt.admission_receipt_id,
        reservation_event_id=receipt.reservation_event_id,
        semantic_dispatch_fingerprint=receipt.semantic_dispatch_fingerprint,
        resolution="released_no_launch",
        evidence_kind=evidence_kind,
        evidence_event_ids=ids,
        launch_state_identity="not_started",
        observed_at=when,
        recorded_at=when,
        actor="dispatch-with-admission",
    )
    event = ledger.reconcile_reservation(reconciliation)
    return DispatchOutcome(
        kind="no_launch",
        launch_state="not_started",
        plan_id=receipt.plan_id,
        phase=receipt.phase,
        dispatch_family_id=receipt.dispatch_family_id,
        logical_dispatch_id=receipt.logical_dispatch_id,
        admission_receipt_id=None,
        semantic_dispatch_fingerprint=None,
        selected_spec=receipt.normalized_spec,
        reconciliation_event_id=str((event.get("payload", event)).get("reconciliation_id") or reconciliation_id),
    )


_EXECUTE_PHASES = frozenset({"execute", "loop_execute"})


def _clock_ns(clock: Callable[[], float]) -> int:
    value = clock()
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise ValueError("provider dispatch clock must be a non-negative number")
    return int(value * 1_000_000_000)


def _probe_target_spec(probe_request: Any) -> str:
    """Return the admitted child spec a production probe must attest."""
    route = str(getattr(probe_request, "route_identity", "") or "")
    if "->" in route and not route.startswith("__NBF06_PROBE_CLOSED__"):
        _source, target = route.split("->", 1)
        if target and not target.startswith("__NBF06_PROBE_CLOSED__"):
            return target
    selected = getattr(probe_request, "selected_spec", None)
    return str(selected or "")


def production_provider_probe_executor() -> Callable[[Any], Mapping[str, Any]]:
    """Attest the admitted target spec without WBC, client, RPC, or worker launch."""

    def run(probe_request: Any) -> dict[str, Any]:
        spec = _probe_target_spec(probe_request)
        payload: dict[str, Any] = {
            "provider_failure_key": getattr(probe_request, "provider_failure_key", ""),
            "parent_reservation_event_id": getattr(probe_request, "parent_reservation_event_id", None),
            "parent_terminal_event_id": getattr(probe_request, "parent_terminal_event_id", None),
            "phase": getattr(probe_request, "phase", None),
            "route_identity": getattr(probe_request, "route_identity", None),
            "route_liveness_identity": getattr(probe_request, "route_liveness_identity", None),
            "selected_spec": spec,
        }
        if not spec:
            payload.update({"result": "unknown", "passed": False, "evidence_digest": _digest(payload)})
            return payload
        try:
            parsed = parse_agent_spec(spec)
            if parsed.agent == "omp":
                model = parsed.model or ""
                provider, model_id = model.split("/", 1) if "/" in model else ("", "")
                if not provider or not model_id:
                    raise ValueError("OMP probe spec lacks provider/model")
                proof = resolve_omp_live_membership(provider, model_id)
            else:
                proof = _default_native_liveness(parsed.agent, parsed.model or spec)
            if not isinstance(proof, Mapping) or not proof.get("identity") or not proof.get("digest"):
                raise ValueError("provider probe liveness is not positive")
            payload["result"] = "passed"
            payload["passed"] = True
            payload["evidence_digest"] = _digest(
                {"identity": proof.get("identity"), "digest": proof.get("digest"), "spec": spec}
            )
            return payload
        except (CliError, ValueError, OSError, TypeError):
            payload["result"] = "failed"
            payload["passed"] = False
            payload["evidence_digest"] = _digest({"spec": spec, "result": "failed"})
            return payload

    return run


def _rebuild_provider_lifecycle(
    probe_executor: Callable[[Any], Any] | Any | None,
    child_launch: Callable[[WorkerExecutionContextRef], Any] | None,
    launch: Callable[[WorkerExecutionContextRef], Any],
) -> tuple[Any, Callable[[WorkerExecutionContextRef], Any]]:
    """Preserve or rebuild probe/child wiring; never hard-code None recursively."""
    return (
        production_provider_probe_executor() if probe_executor is None else probe_executor,
        launch if child_launch is None else child_launch,
    )


def _committed_terminal(ledger: IncidentLedger | None, receipt: WorkerAdmissionReceipt) -> Mapping[str, Any] | None:
    if ledger is None:
        return None
    for terminal in ledger.projection().get("terminals", {}).values():
        if (
            terminal.get("reservation_event_id") == receipt.reservation_event_id
            and terminal.get("admission_receipt_id") == receipt.admission_receipt_id
            and terminal.get("logical_dispatch_id") == receipt.logical_dispatch_id
        ):
            return terminal
    return None


def _outcome_from_committed_terminal(terminal: Mapping[str, Any], receipt: WorkerAdmissionReceipt) -> DispatchOutcome:
    return DispatchOutcome(
        kind=str(terminal.get("outcome_kind")),
        launch_state=str(terminal.get("launch_state") or "accepted"),
        plan_id=str(terminal.get("plan_id") or receipt.plan_id),
        phase=str(terminal.get("phase") or receipt.phase),
        dispatch_family_id=str(terminal.get("dispatch_family_id") or receipt.dispatch_family_id),
        logical_dispatch_id=str(terminal.get("logical_dispatch_id") or receipt.logical_dispatch_id),
        admission_receipt_id=terminal.get("admission_receipt_id") or receipt.admission_receipt_id,
        semantic_dispatch_fingerprint=terminal.get("semantic_dispatch_fingerprint") or receipt.semantic_dispatch_fingerprint,
        selected_spec=str(terminal.get("selected_spec") or receipt.normalized_spec),
        worker_identity=terminal.get("worker_identity"),
        started_at=terminal.get("started_at"),
        finished_at=terminal.get("finished_at"),
        success_payload=terminal.get("success_payload"),
        terminal_failure=terminal.get("terminal_failure"),
        provider_evidence=terminal.get("provider_evidence"),
        provider_failure_key=terminal.get("provider_failure_key"),
        disposition_id=terminal.get("disposition_id"),
        terminal_outcome_event_id=terminal.get("terminal_outcome_id"),
        provider=terminal.get("provider") or receipt.provider,
        route_liveness_kind=terminal.get("route_liveness_kind") or receipt.route_liveness_kind,
        route_liveness_identity=terminal.get("route_liveness_identity") or receipt.route_liveness_identity,
        route_liveness_digest=terminal.get("route_liveness_digest") or receipt.route_liveness_digest,
    )


def _validate_provider_child_target(
    request: WorkerAdmissionRequest,
    *,
    from_spec: str,
    to_spec: str,
    transition_kind: str,
) -> None:
    """Reject a fallback/return target before WBC, client, or RPC resolution."""
    if not isinstance(to_spec, str) or not to_spec:
        raise ValueError("provider child target spec is required")
    parse_agent_spec(from_spec)
    parse_agent_spec(to_spec)
    from_family = provider_family(from_spec)
    to_family = provider_family(to_spec)
    specs = tuple(request.configured_fallback_specs or ())
    if transition_kind in {"fallback", "configured_fallback"} and from_spec != to_spec:
        if request.phase in _EXECUTE_PHASES:
            raise ExecuteFallbackUnsafe(
                phase=request.phase,
                configured_specs=specs or (from_spec, to_spec),
                attempted_index=1,
            )
        if specs and to_spec not in specs:
            raise ValueError("fallback target is not in the configured chain")
        if from_family == to_family:
            raise ValueError("fallback target must cross provider family")
    if transition_kind in {"return", "return_primary"}:
        primary = specs[0] if specs else request.configured_spec
        if to_spec != primary:
            raise ValueError("return-primary target is not the configured primary")
        if to_spec == from_spec:
            raise ValueError("return-primary target cannot be the source spec")
        if from_family == to_family:
            raise ValueError("return-primary target must not inherit source family identity")


def _select_provider_child_target(
    request: WorkerAdmissionRequest,
    terminal: DispatchOutcome,
    child_launch: Callable[[WorkerExecutionContextRef], Any] | None,
) -> tuple[str, str]:
    selector = getattr(child_launch, "select_target", None)
    if callable(selector):
        chosen = selector(request, terminal)
        if isinstance(chosen, tuple) and len(chosen) == 2:
            return str(chosen[0]), str(chosen[1])
        if isinstance(chosen, str) and chosen:
            transition = "fallback" if chosen != request.selected_spec else "provider_recovery"
            return chosen, transition
        raise ValueError("provider child target callback returned an unsupported target")
    specs = tuple(request.configured_fallback_specs or ())
    if (
        len(specs) > 1
        and request.selected_spec == specs[0]
        and request.phase not in _EXECUTE_PHASES
    ):
        return specs[1], "fallback"
    return request.selected_spec, "provider_recovery"


def _provider_condition(
    reason: str,
    *,
    receipt: WorkerAdmissionReceipt,
    terminal: DispatchOutcome,
    retry_after_s: float = 0.0,
    evidence: Mapping[str, Any] | None = None,
) -> SchedulingCondition:
    return SchedulingCondition(
        condition_id=_digest((reason, terminal.terminal_outcome_event_id, terminal.provider_failure_key, terminal.logical_dispatch_id)),
        reason=reason,
        plan_id=receipt.plan_id,
        phase=receipt.phase,
        spec=receipt.normalized_spec,
        dispatch_family_id=receipt.dispatch_family_id,
        logical_dispatch_id=receipt.logical_dispatch_id,
        admission_attempt=receipt.admission_attempt,
        retry_after_s=retry_after_s,
        observed_at=_now(),
        cause_event_id=terminal.terminal_outcome_event_id,
        evidence=dict(evidence or {}),
    )


def _authorized_linked_child(
    request: WorkerAdmissionRequest,
    receipt: WorkerAdmissionReceipt,
    terminal: DispatchOutcome,
    *,
    from_spec: str,
    to_spec: str,
    transition: str,
    logical_suffix: str,
    launch: Callable[[WorkerExecutionContextRef], Any],
    child_launch: Callable[[WorkerExecutionContextRef], Any] | None,
    probe_executor: Callable[[Any], Any] | Any,
    ledger: IncidentLedger,
    clock: Callable[[], float],
    sleeper: Callable[[float], None],
    deadline: float,
    return_worker: bool,
    retry_after_s: float,
) -> Any:
    """Probe outside the lock, then reserve/admit/launch one composite child."""
    _validate_provider_child_target(request, from_spec=from_spec, to_spec=to_spec, transition_kind=transition)
    effective_probe, effective_child = _rebuild_provider_lifecycle(probe_executor, child_launch, launch)
    skip_child = getattr(child_launch, "skip_admission", False) is True
    now_ns = _clock_ns(clock)
    remain_ns = max(1, int(max(deadline - clock(), 0.000001) * 1_000_000_000))
    deadline_ns = now_ns + remain_ns
    retry_ns = int(max(0.0, retry_after_s) * 1_000_000_000)
    route_identity = f"{from_spec}->{to_spec}"
    probe_request = select_provider_probe(
        {
            "outcome": terminal,
            "parent_reservation_event_id": receipt.reservation_event_id,
            "parent_terminal_event_id": terminal.terminal_outcome_event_id,
            "reservation_event_id": receipt.reservation_event_id,
            "retry_not_before_ns": retry_ns,
            "deadline_ns": deadline_ns,
            "route_identity": route_identity,
            "route_liveness_identity": receipt.route_liveness_identity,
            "logical_dispatch_id": terminal.logical_dispatch_id,
            "selected_spec": from_spec,
            "attempt": 1,
        },
        ProviderLedgerView.from_ledger(ledger),
        now_ns=now_ns,
    )
    probed = None
    if probe_request is not None:
        try:
            probed = execute_provider_probe(ledger, probe_request, effective_probe, now_ns=now_ns, actor="dispatch-with-admission")
        except ValueError:
            probed = None
    lease_payload = ((probed or {}).get("lease") or {}).get("payload") or (probed or {}).get("lease") or {}
    result_payload = ((probed or {}).get("result") or {}).get("payload") or (probed or {}).get("result") or {}
    if not lease_payload.get("probe_lease_id"):
        existing = next(
            (
                lease
                for lease in ProviderLedgerView.from_ledger(ledger).provider_probe_leases.values()
                if lease.get("parent_reservation_event_id") == receipt.reservation_event_id
                and lease.get("provider_failure_key") == terminal.provider_failure_key
                and lease.get("route_identity") == route_identity
            ),
            None,
        )
        if existing is None:
            if now_ns < retry_ns:
                return _provider_condition("provider_observation_wait", receipt=receipt, terminal=terminal, retry_after_s=retry_after_s)
            return _provider_condition("provider_probe_wait", receipt=receipt, terminal=terminal)
        lease_payload = existing
        result_payload = {"passed": existing.get("status") in {"passed", "passed_closed"}}
    result_kind = str(result_payload.get("result") or lease_payload.get("status") or "")
    passed = result_payload.get("passed") is True or lease_payload.get("status") in {"passed", "passed_closed"}
    if not passed:
        reason = "provider_probe_failed"
        if result_kind in {"unknown", "failed"} or result_payload.get("passed") is not True:
            reason = "provider_probe_failed"
        return _provider_condition(reason, receipt=receipt, terminal=terminal, evidence={"passed": False, "result": result_kind or "failed"})
    proof = ledger.record_provider_recovery_verified_locked(
        plan_id=receipt.plan_id,
        phase=receipt.phase,
        probe_lease_id=str(lease_payload.get("probe_lease_id")),
        provider_failure_key=terminal.provider_failure_key,
        parent_reservation_event_id=receipt.reservation_event_id,
        parent_terminal_event_id=terminal.terminal_outcome_event_id,
        route_identity=route_identity,
        logical_dispatch_id=terminal.logical_dispatch_id,
        dispatch_family_id=receipt.dispatch_family_id,
        actor="dispatch-with-admission",
    )
    if skip_child:
        return terminal
    proof_payload = proof.get("payload", proof)
    proof_id = str(proof_payload.get("event_id"))
    child_request = build_authorized_linked_child_request(
        request,
        selected_spec=to_spec,
        logical_dispatch_id=f"{request.logical_dispatch_id}:{logical_suffix}",
        authorizing_event_id=proof_id,
        dispatch_family_id=provider_family(to_spec),
        parent_terminal_event_id=terminal.terminal_outcome_event_id,
        parent_source_spec=from_spec,
        authorized_route_identity=to_spec,
        configured_spec=to_spec,
        configured_fallback_specs=request.configured_fallback_specs,
        configured_fallback_chain_identity=request.configured_fallback_chain_identity,
        transition_kind=transition,
        precondition_identity=proof_id,
        changed_precondition_event_id=proof_id,
        expected_projection_version=ledger.projection()["projection_version"],
    )
    return dispatch_with_admission(
        child_request,
        effective_child,
        gate=require_production_worker_dispatch_runtime,
        ledger=ledger,
        clock=clock,
        sleeper=sleeper,
        deadline_s=max(deadline - clock(), 0.001),
        return_worker=return_worker,
        probe_executor=effective_probe,
        child_launch=effective_child,
    )


def _provider_post_terminal(
    request: WorkerAdmissionRequest,
    receipt: WorkerAdmissionReceipt,
    terminal: DispatchOutcome,
    *,
    launch: Callable[[WorkerExecutionContextRef], Any],
    gate: Callable[[WorkerAdmissionRequest | Mapping[str, Any]], Any],
    ledger: IncidentLedger,
    clock: Callable[[], float],
    sleeper: Callable[[float], None],
    deadline: float,
    return_worker: bool,
    probe_executor: Callable[[Any], Any] | Any | None,
    child_launch: Callable[[WorkerExecutionContextRef], Any] | None,
) -> Any:
    """Continue T8 after the sole parent terminal append, without a second parent launch."""
    view = ProviderLedgerView.from_ledger(ledger)
    decision = select_provider_route(terminal, view)
    decision = apply_provider_route_decision_locked(
        ledger,
        decision,
        outcome=terminal,
        reservation_event_id=receipt.reservation_event_id,
    )
    if decision.kind == "provider_degraded":
        return provider_scheduling_condition(
            decision,
            plan_id=receipt.plan_id,
            dispatch_family_id=receipt.dispatch_family_id,
            admission_attempt=receipt.admission_attempt,
        )
    if decision.kind != "provider_observation_wait":
        return terminal
    if probe_executor is None:
        return provider_scheduling_condition(
            decision,
            plan_id=receipt.plan_id,
            dispatch_family_id=receipt.dispatch_family_id,
            admission_attempt=receipt.admission_attempt,
        )
    effective_child = launch if child_launch is None else child_launch
    from_spec = terminal.selected_spec
    to_spec, transition = _select_provider_child_target(request, terminal, effective_child)
    child_result = _authorized_linked_child(
        request,
        receipt,
        terminal,
        from_spec=from_spec,
        to_spec=to_spec,
        transition=transition,
        logical_suffix="recovery",
        launch=launch,
        child_launch=child_launch,
        probe_executor=probe_executor,
        ledger=ledger,
        clock=clock,
        sleeper=sleeper,
        deadline=deadline,
        return_worker=return_worker,
        retry_after_s=decision.retry_after_s,
    )
    if (
        transition in {"fallback", "configured_fallback"}
        and isinstance(child_result, DispatchOutcome)
        and child_result.kind == "success"
    ):
        return _authorized_linked_child(
            request,
            receipt,
            terminal,
            from_spec=to_spec,
            to_spec=from_spec,
            transition="return",
            logical_suffix="return",
            launch=launch,
            child_launch=child_launch,
            probe_executor=probe_executor,
            ledger=ledger,
            clock=clock,
            sleeper=sleeper,
            deadline=deadline,
            return_worker=return_worker,
            retry_after_s=0.0,
        )
    return child_result


def dispatch_with_admission(
    request: WorkerAdmissionRequest | Mapping[str, Any],
    launch: Callable[[WorkerExecutionContextRef], Any],
    *,
    gate: Callable[[WorkerAdmissionRequest | Mapping[str, Any]], Any] = require_production_worker_dispatch_runtime,
    ledger: IncidentLedger | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
    deadline_s: float | None = None,
    return_worker: bool = False,
    probe_executor: Callable[[Any], Any] | Any | None = None,
    child_launch: Callable[[WorkerExecutionContextRef], Any] | None = None,
    admission_preflight: Callable[[WorkerAdmissionReceipt], Mapping[str, Any] | None] | None = None,
) -> Any:
    """Run one logical dispatch through admission and one controlled closure."""
    if not isinstance(request, WorkerAdmissionRequest):
        request = WorkerAdmissionRequest.from_dict(request)
    if ledger is not None:
        request = replace(request, ledger=ledger)
    started_clock = clock()
    deadline = started_clock + float(deadline_s if deadline_s is not None else request.timeout_budget_s)
    waited_s = 0.0
    attempt = request.admission_attempt
    while True:
        current = replace(request, admission_attempt=attempt)
        decision = gate(current)
        if isinstance(decision, SchedulingCondition):
            # Test and embedded runtimes may inject a sleeper that records a
            # wait without advancing the supplied clock.  Count the requested
            # wait as elapsed as well, otherwise a cooldown can spin forever.
            elapsed = max(clock() - started_clock, waited_s)
            remaining = deadline - started_clock - elapsed
            if remaining <= 0:
                return decision
            wait = min(float(decision.retry_after_s), remaining)
            if wait <= 0:
                attempt += 1
                continue
            sleeper(wait)
            waited_s += wait
            attempt += 1
            continue
        if isinstance(decision, AdmissionRefusal):
            return decision
        if not isinstance(decision, WorkerAdmissionReceipt):
            raise TypeError("admission gate returned an unsupported decision")
        # All production worker doors converge on OperationRun/
        # FileBackedDurableOpsStore.  IncidentLedger is an optional custody
        # adapter for unrelated incident/disposition observations; it is not
        # consulted for launch admission, lifecycle, acceptance, or replay.
        active_ledger = ledger or current.ledger
        canonical_store = _worker_operation_store(current, decision)
        canonical_result, canonical_outcome = _canonical_worker_launch(
            decision,
            launch,
            store=canonical_store,
            ledger=active_ledger,
        )
        if canonical_result.result is DurableLaunchResult.REJECTED:
            return AdmissionRefusal(
                code="launch_rejected",
                reason=str(canonical_result.reason.value),
                plan_id=decision.plan_id,
                phase=decision.phase,
                logical_dispatch_id=decision.logical_dispatch_id,
                admission_attempt=decision.admission_attempt,
                evidence={"operation_id": decision.operation_id},
            )
        if canonical_result.result is DurableLaunchResult.UNKNOWN or canonical_outcome is None:
            return _unresolved_outcome(decision)
        # The canonical store has already committed the exact accepted
        # process identity.  Do not append a shadow reservation/terminal or
        # re-enter the physical door for provider fallback/replay.
        return canonical_outcome

__all__ = ["AdmissionRefusal", "CONTINUATION_PROVIDER_PROBE_SCHEMA", "CONTINUATION_PROVIDER_PROBE_OUTPUT", "LaunchResult", "ManagedCommandResult", "WorkerAdmissionReceipt", "WorkerAdmissionRequest", "WorkerExecutionContextRef", "build_authorized_linked_child_request", "dispatch_with_admission", "ensure_continuation_provider_probe", "production_provider_probe_executor", "reconcile_no_launch", "require_production_worker_dispatch_runtime", "resolve_omp_live_membership"]
