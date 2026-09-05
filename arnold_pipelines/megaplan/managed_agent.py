"""Neutral durable lifecycle for resident and automatic managed agents.

The repair queue, watchdog, and chain runner remain the authorities that decide
*whether* work may run.  This module owns the execution evidence after that
decision: a stable identity, manifest/history, process liveness, logs, result,
lineage, and a truthful terminal state.

It deliberately supervises the real process.  Callers must not create one of
these manifests as a projection for a process launched elsewhere.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from typing import Any

from arnold_pipelines.megaplan.incident.disposition import (
    SignalDispositionError,
    WorkerSignalContext,
    resolve_worker_execution_context,
    signal_non_worker,
    signal_worker_ladder,
)
from arnold_pipelines.megaplan.incident.ledger import IncidentLedger
from arnold_pipelines.megaplan.incident.schema import NonWorkerSignalDisposition


MANAGED_AGENT_SCHEMA = "arnold-managed-agent-run-v2"
MANAGED_AGENT_CUSTODIAN = "arnold.megaplan.managed_agent"
MACHINE_ORIGIN_SCHEMA = "arnold-machine-origin-provenance-v1"
MACHINE_ORIGIN_ENV = "ARNOLD_MANAGED_AGENT_ORIGIN"
MANAGED_DIFFICULTY_CEILING_ENV = "ARNOLD_MANAGED_AGENT_DIFFICULTY_CEILING"
RESIDENT_DELEGATION_ENV = "ARNOLD_RESIDENT_DELEGATION_CONTEXT"
SEALED_STDIN_PLACEHOLDER = "@managed-stdin@"
LEGACY_RESIDENT_SCHEMA = "arnold-resident-agent-run-v1"
LEGACY_RESIDENT_CUSTODIAN = "arnold.megaplan.resident"
DEFAULT_RUN_ROOT = Path(".megaplan/plans/resident-subagents")
ACTIVE_STATUSES = frozenset({"reserved", "launching", "running", "adopting"})
TERMINAL_STATUSES = frozenset(
    {"completed", "failed", "interrupted", "cancelled", "superseded", "unknown"}
)

# Capability profile for automatic repair agents.  Recovery fixers may mutate
# ONLY the canonical engine worktree; the milestone/target worktree is read-only.
# Enforced at process launch with an OS-level read-only bind (bubblewrap) plus a
# post-run git assertion, so a prompt rule or git hook alone is not trusted.
FILESYSTEM_CAPABILITY_RECOVERY_ENGINE_ONLY = "recovery_engine_only"
FILESYSTEM_CAPABILITY_UNRESTRICTED = "unrestricted"
_DEFAULT_FILESYSTEM_CAPABILITY = FILESYSTEM_CAPABILITY_RECOVERY_ENGINE_ONLY


def _resolve_fs_capability(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Return the effective filesystem capability block for an automatic run."""
    raw = manifest.get("filesystem_capability")
    if not isinstance(raw, Mapping):
        return {
            "profile": _DEFAULT_FILESYSTEM_CAPABILITY,
            "writable_roots": [],
            "read_only_roots": [],
            "protected_git_refs": [],
            "sha256": "",
        }
    return dict(raw)

AUTOMATIC_RUN_KINDS = frozenset(
    {
        "automatic_repair",
        "automatic_meta_repair",
        "automatic_meta_repair_worker",
        "automatic_repair_retry",
        "automatic_progress_audit_agent",
        "automatic_root_cause_repair",
        "automatic_watchdog_source_repair",
        "automatic_legacy_fixer",
        "automatic_research_subagent",
        "automatic_reconcile",
    }
)
MACHINE_ORIGIN_KINDS = frozenset(
    {
        "watchdog_repair",
        "watchdog_meta_repair",
        "watchdog_source_repair",
        "repair_loop_worker",
        "meta_repair_worker",
        "meta_repair_retrigger",
        "periodic_progress_auditor",
        "legacy_fixer_wrapper",
        "managed_parent_agent",
        "reconcile_controller",
    }
)
_PROVENANCE_SAFE = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/-"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_write_manifest(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(dict(payload), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def stable_managed_run_id(run_kind: str, identity_key: str) -> str:
    digest = hashlib.sha256(f"{run_kind}\0{identity_key}".encode("utf-8")).hexdigest()[:20]
    return f"managed-{run_kind.replace('_', '-')}-{digest}"


def _provenance_text(value: object, *, field: str, required: bool = True) -> str | None:
    text = str(value or "").strip()
    if not text:
        if required:
            raise ValueError(f"machine launch provenance {field} is required")
        return None
    if len(text) > 240 or any(character not in _PROVENANCE_SAFE for character in text):
        raise ValueError(f"machine launch provenance {field} is malformed")
    return text


def normalize_machine_origin_provenance(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the explicit non-Discord origin of an automatic agent launch."""

    if not isinstance(value, Mapping):
        raise ValueError("machine launch provenance must be an object")
    allowed = {
        "schema_version",
        "applicability",
        "transport",
        "origin_kind",
        "origin_id",
        "component",
        "trigger_id",
    }
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"machine launch provenance contains unknown fields: {unknown}")
    schema = str(value.get("schema_version") or MACHINE_ORIGIN_SCHEMA)
    if schema != MACHINE_ORIGIN_SCHEMA:
        raise ValueError("machine launch provenance schema is unsupported")
    if str(value.get("applicability") or "not_applicable") != "not_applicable":
        raise ValueError("automatic machine origin cannot claim Discord applicability")
    if str(value.get("transport") or "automatic_system") != "automatic_system":
        raise ValueError("automatic machine origin transport must be automatic_system")
    origin_kind = _provenance_text(value.get("origin_kind"), field="origin_kind")
    if origin_kind not in MACHINE_ORIGIN_KINDS:
        raise ValueError(f"machine launch provenance origin_kind is unsupported: {origin_kind}")
    normalized = {
        "schema_version": MACHINE_ORIGIN_SCHEMA,
        "applicability": "not_applicable",
        "transport": "automatic_system",
        "origin_kind": origin_kind,
        "origin_id": _provenance_text(value.get("origin_id"), field="origin_id"),
        "component": _provenance_text(value.get("component"), field="component"),
        "trigger_id": _provenance_text(value.get("trigger_id"), field="trigger_id"),
    }
    return normalized


def machine_origin_provenance(
    *, origin_kind: str, origin_id: str, component: str, trigger_id: str
) -> dict[str, Any]:
    return normalize_machine_origin_provenance(
        {
            "origin_kind": origin_kind,
            "origin_id": origin_id,
            "component": component,
            "trigger_id": trigger_id,
        }
    )


def validate_automatic_managed_manifest(
    value: Mapping[str, Any],
    *,
    manifest_path: Path | None = None,
    verify_stdin: bool = True,
) -> dict[str, Any]:
    """Validate evidence required before an automatic run can support a claim."""

    if not is_managed_manifest(value):
        raise ValueError("automatic managed manifest schema or custodian is invalid")
    run_kind = str(value.get("run_kind") or "")
    if run_kind not in AUTOMATIC_RUN_KINDS:
        raise ValueError("automatic managed manifest run kind is invalid")
    run_id = str(value.get("run_id") or "").strip()
    if not run_id:
        raise ValueError("automatic managed manifest run id is missing")
    if manifest_path is not None and manifest_path.parent.name != run_id:
        raise ValueError("automatic managed manifest path does not match run id")
    provenance = normalize_machine_origin_provenance(value.get("launch_provenance") or {})
    provenance_digest = hashlib.sha256(
        json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if value.get("provenance_sha256") != provenance_digest:
        raise ValueError("automatic managed provenance digest disagrees")
    contract_digest = str(value.get("launch_contract_sha256") or "")
    if len(contract_digest) != 64 or any(character not in "0123456789abcdef" for character in contract_digest):
        raise ValueError("automatic managed launch contract digest is invalid")
    for field in ("task_kind", "model", "route_class", "backend", "log_path", "result_path"):
        if not str(value.get(field) or "").strip():
            raise ValueError(f"automatic managed manifest {field} is missing")
    difficulty = value.get("difficulty")
    if not isinstance(difficulty, int) or not 1 <= difficulty <= 10:
        raise ValueError("automatic managed manifest difficulty is invalid")
    stdin_contract = value.get("stdin")
    if not isinstance(stdin_contract, Mapping) or stdin_contract.get("sealed") is not True:
        raise ValueError("automatic managed stdin contract is not sealed")
    stdin_kind = stdin_contract.get("kind")
    if stdin_kind == "devnull":
        if stdin_contract.get("size_bytes") != 0:
            raise ValueError("automatic managed devnull stdin size is invalid")
    elif stdin_kind == "sealed_file":
        stdin_path = Path(str(stdin_contract.get("path") or ""))
        stdin_digest = str(stdin_contract.get("sha256") or "")
        stdin_size = stdin_contract.get("size_bytes")
        if not stdin_path.is_absolute() or len(stdin_digest) != 64 or not isinstance(stdin_size, int):
            raise ValueError("automatic managed sealed stdin descriptor is invalid")
        if verify_stdin:
            try:
                stdin_bytes = stdin_path.read_bytes()
            except OSError as exc:
                raise ValueError("automatic managed sealed stdin is unavailable") from exc
            if len(stdin_bytes) != stdin_size or hashlib.sha256(stdin_bytes).hexdigest() != stdin_digest:
                raise ValueError("automatic managed sealed stdin disagrees with manifest")
    else:
        raise ValueError("automatic managed stdin kind is invalid")
    return dict(value)


def _append_status(
    manifest: dict[str, Any],
    status: str,
    *,
    evidence: str,
    **extra: Any,
) -> None:
    at = utc_now()
    manifest["status"] = status
    manifest["updated_at"] = at
    history = list(manifest.get("status_history") or [])
    event = {"status": status, "at": at, "evidence": evidence}
    event.update({key: value for key, value in extra.items() if value is not None})
    history.append(event)
    manifest["status_history"] = history[-100:]


def _pid_live(pid: object) -> bool:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        state = stat.rsplit(") ", 1)[1].split()[0]
        if state == "Z":
            return False
    except (OSError, IndexError):
        pass
    return True


def _pid_start_ticks(pid: object) -> str:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return ""
    try:
        # /proc/<pid>/stat field 22 is stable across exec and changes on PID reuse.
        return Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()[21]
    except (OSError, IndexError):
        # macOS has no /proc.  ``ps lstart`` is the strongest portable
        # incarnation token available to this supervisor; hash the complete
        # start timestamp so it cannot be confused with a bare PID.
        try:
            result = subprocess.run(
                ["ps", "-o", "lstart=", "-p", str(pid)],
                capture_output=True,
                text=True,
                check=False,
                timeout=2,
            )
        except (OSError, TypeError, AttributeError, ValueError, subprocess.TimeoutExpired):
            return ""
        started = result.stdout.strip()
        if result.returncode != 0 or not started:
            return ""
        return "ps-lstart:" + hashlib.sha256(started.encode("utf-8")).hexdigest()


def _pid_matches(pid: object, expected_sha256: str, expected_start_ticks: str = "") -> bool:
    if not _pid_live(pid):
        return False
    if expected_start_ticks:
        return _pid_start_ticks(pid) == expected_start_ticks
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return False
    observed = hashlib.sha256(raw).hexdigest()
    return not expected_sha256 or observed == expected_sha256


def _boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown-boot"


def _managed_worker_identity(
    pid: int, process_start_identity: str | None = None
) -> dict[str, Any]:
    """Return the child identity used by the managed signal door.

    The process-start token belongs to the child, not the supervisor.  Keep it
    in the same identity envelope as PID/boot so accepted outcomes cannot
    silently fall back to a supervisor incarnation surrogate.
    """
    return {
        "host": socket.gethostname(),
        "pid": pid,
        "boot_id": _boot_id(),
        "process_start_identity": process_start_identity or "",
    }


def certify_managed_worker_launch(
    manifest_path: Path,
    manifest: Mapping[str, Any],
    *,
    pid: int,
    worker_identity: Mapping[str, Any],
    process_start_identity: str,
    started_at: str,
) -> bool:
    """Verify canonical accepted identity for an admission-backed child.

    Launch acceptance is committed by ``launch_transaction``.  This managed
    adapter is intentionally read-only: it no longer writes or reads an
    IncidentLedger accepted-launch marker.
    """
    raw_context = manifest.get("worker_execution_context")
    if raw_context is None:
        raw_context = os.environ.get("ARNOLD_WORKER_EXECUTION_CONTEXT")
    if raw_context is None or not process_start_identity or not isinstance(worker_identity, Mapping):
        return False
    try:
        ref = (
            resolve_worker_execution_context({"ARNOLD_WORKER_EXECUTION_CONTEXT": json.dumps(raw_context)})
            if isinstance(raw_context, Mapping)
            else resolve_worker_execution_context({"ARNOLD_WORKER_EXECUTION_CONTEXT": raw_context})
        )
        from arnold.runtime.durable_ops import FileBackedDurableOpsStore
        store_root = Path(os.environ.get("ARNOLD_OPS_STORE_ROOT") or Path(ref.ledger_root) / "ops")
        operation = FileBackedDurableOpsStore(store_root).load_operation_run(ref.logical_dispatch_id)
        if getattr(operation.state, "value", operation.state) != "running":
            return False
        resources = FileBackedDurableOpsStore(store_root).list_typed_resources(ref.logical_dispatch_id)
        return any(
            resource.resource_type.value == "process_session"
            and resource.details.get("worker_identity") == dict(worker_identity)
            and resource.details.get("worker_identity", {}).get("process_start_identity") == process_start_identity
            for resource in resources
        )
    except (OSError, TypeError, ValueError, SignalDispositionError, KeyError, json.JSONDecodeError):
        return False


def signal_managed_process(
    manifest_path: Path,
    manifest: Mapping[str, Any],
    pid: int,
    signal_name: int,
    *,
    cause_kind: str,
    ladder_step: str,
    process_group: bool = False,
    worker: bool = True,
    wait_fn: Any = None,
    return_result: bool = False,
) -> bool | Mapping[str, Any]:
    """Signal a managed child only through a typed disposition door.

    A WBC context embedded in the manifest/environment is authoritative.  If
    it is present but malformed, the operation is fail-closed.  Known workers
    without admission context are never signaled; only an explicit parent or
    supervisor lifecycle caller may opt into the non-worker door.
    """
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    raw_context = manifest.get("worker_execution_context")
    if raw_context is None:
        raw_context = os.environ.get("ARNOLD_WORKER_EXECUTION_CONTEXT")
    # Missing context is rejected before any platform probe.  Besides being
    # fail-closed, this keeps an uncertified fake/terminated child from causing
    # a subprocess-based identity probe with no signal authority.
    if raw_context is None and worker:
        return False
    observed_start = _pid_start_ticks(pid)
    start = observed_start or str(manifest.get("worker_start_ticks") or "")
    if raw_context is not None:
        try:
            ref = (
                resolve_worker_execution_context({"ARNOLD_WORKER_EXECUTION_CONTEXT": json.dumps(raw_context)})
                if isinstance(raw_context, Mapping)
                else resolve_worker_execution_context({"ARNOLD_WORKER_EXECUTION_CONTEXT": raw_context})
            )
            worker_identity = manifest.get("worker_identity")
            if not isinstance(worker_identity, dict):
                worker_identity = json.loads(os.environ.get("ARNOLD_WORKER_IDENTITY", "{}"))
            if not isinstance(worker_identity, dict) or not worker_identity:
                return False
            context = WorkerSignalContext.from_ref(
                ref,
                worker_identity=worker_identity,
                victim_pid=pid,
                victim_process_start_identity=start,
                started_at=str(manifest.get("worker_started_at") or "") or None,
            )
            if not start:
                return False
            ledger = IncidentLedger(Path(ref.ledger_root))
            def send(number: int) -> None:
                if process_group:
                    os.killpg(os.getpgid(pid), number)
                else:
                    os.kill(pid, number)

            term_invoke = lambda: send(signal.SIGTERM)
            kill_invoke = lambda: send(signal.SIGKILL)
            def bounded_wait() -> None:
                if not callable(wait_fn):
                    return
                try:
                    wait_fn()
                except (subprocess.TimeoutExpired, ProcessLookupError, ChildProcessError):
                    pass
            term_confirmation = manifest.get("term_confirmation_event_id")
            kill_confirmation = manifest.get("kill_confirmation_event_id")
            result = signal_worker_ladder(
                ledger,
                context,
                term_signal=signal.SIGTERM,
                kill_signal=signal.SIGKILL,
                killer_kind="launcher_timeout" if cause_kind == "timeout" else "resident_supervisor",
                killer_identity=f"managed-supervisor:{os.getpid()}",
                cause_kind=cause_kind,
                term_confirmation_event_id=str(term_confirmation) if term_confirmation else None,
                kill_confirmation_event_id=str(kill_confirmation) if kill_confirmation else None,
                term_signal_fn=term_invoke,
                kill_signal_fn=kill_invoke,
                liveness_fn=_pid_live,
                process_start_identity_fn=_pid_start_ticks,
                wait_fn=bounded_wait if callable(wait_fn) else None,
            )
            if return_result:
                return result.to_dict()
            return result.state in {"killed", "already_dead"}
        except (OSError, TypeError, ValueError, SignalDispositionError, json.JSONDecodeError):
            # Context, ledger, confirmation, or append failure is fail-closed.
            return False

    # A known worker without admission context is never reclassified as
    # lifecycle cleanup.  Parent/supervisor callers explicitly pass worker=False
    # and are recorded through the non-worker door below.
    if worker:
        return False
    # Record parent/supervisor lifecycle cleanup before signaling.
    try:
        # A non-worker lifecycle action still requires a positive incarnation
        # token; unknown PID identity is fail-closed.
        if not start:
            return False
        ledger = IncidentLedger(manifest_path.parent)
        disposition = NonWorkerSignalDisposition(
            disposition_id=hashlib.sha256(
                f"managed-lifecycle\0{manifest.get('run_id', manifest_path.parent.name)}\0{signal_name}\0{ladder_step}".encode()
            ).hexdigest(),
            subject="non_worker_lifecycle",
            lifecycle_identity=f"managed:{manifest.get('run_id', manifest_path.parent.name)}",
            killer_identity=f"managed-supervisor:{os.getpid()}",
            cause_kind="lifecycle_shutdown",
            signal=signal.Signals(signal_name).name,
            victim_pid_or_group=str(os.getpgid(pid) if process_group else pid),
            victim_process_start_identity=start,
            observed_at=utc_now(),
            evidence={"managed_manifest": str(manifest_path), "cause_kind": cause_kind, "ladder_step": ladder_step},
        )
        invoke = (
            (lambda: os.killpg(os.getpgid(pid), signal_name))
            if process_group
            else (lambda: os.kill(pid, signal_name))
        )
        def preflight(_records: list[dict[str, Any]]) -> None:
            # Keep the parent/supervisor adapter on the same locked physical
            # door as the authority-aware CLI.  The supplied manifest remains
            # the explicit lifecycle contract; the process incarnation is
            # re-read while the ledger lock is held immediately before claim.
            current_start = _pid_start_ticks(pid)
            if current_start != start:
                raise SignalDispositionError(
                    "non-worker process identity changed before signal"
                )
        signal_non_worker(ledger, disposition, signal_fn=invoke, preflight=preflight)
        return True
    except (OSError, ValueError, SignalDispositionError):
        return False


def is_managed_manifest(payload: Mapping[str, Any]) -> bool:
    schema = payload.get("schema_version")
    custodian = payload.get("custodian")
    if schema == MANAGED_AGENT_SCHEMA:
        return custodian == MANAGED_AGENT_CUSTODIAN
    return schema == LEGACY_RESIDENT_SCHEMA and custodian == LEGACY_RESIDENT_CUSTODIAN


def observed_status(payload: Mapping[str, Any], manifest_path: Path) -> tuple[str, bool]:
    status = str(payload.get("status") or "unknown")
    if status not in ACTIVE_STATUSES:
        return status, False
    supervisor_pid = payload.get("pid")
    worker_pid = payload.get("worker_pid")
    supervisor_live = _pid_matches(
        supervisor_pid,
        str(payload.get("supervisor_cmdline_sha256") or ""),
        str(payload.get("supervisor_start_ticks") or ""),
    )
    worker_live = _pid_matches(
        worker_pid,
        str(payload.get("worker_cmdline_sha256") or ""),
        str(payload.get("worker_start_ticks") or ""),
    )
    live = supervisor_live or worker_live
    return (status if live else "interrupted"), live


def _repair_goal_semantics(payload: Mapping[str, Any]) -> dict[str, Any] | None:
    links = payload.get("links") if isinstance(payload.get("links"), Mapping) else {}
    goal_path = str(links.get("repair_goal_path") or "").strip()
    if not goal_path:
        return None
    try:
        goal = json.loads(Path(goal_path).read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {
            "goal_id": str(links.get("repair_goal_id") or ""),
            "goal_path": goal_path,
            "checkpoint_digest": str(links.get("repair_checkpoint_digest") or ""),
            "status": "unknown",
            "terminal": False,
            "semantic_completion": False,
            "reason": "durable repair goal evidence is unavailable",
        }
    status = str(goal.get("status") or "unknown")
    terminal = status in {"progressed", "approval_required"}
    semantic_success = status == "progressed"
    return {
        "goal_id": str(goal.get("goal_id") or links.get("repair_goal_id") or ""),
        "goal_path": goal_path,
        "checkpoint_digest": str(
            goal.get("checkpoint_digest") or links.get("repair_checkpoint_digest") or ""
        ),
        "status": status,
        "terminal": terminal,
        "semantic_completion": semantic_success,
        "reason": (
            "authoritative target progress verified"
            if semantic_success
            else (
                "explicit human approval or authorization gate verified"
                if status == "approval_required"
                else "worker lifecycle completion does not complete the durable repair goal"
            )
        ),
    }


def managed_run_roots(
    *, project_root: str | Path, workspace_root: str | Path | None = "/workspace"
) -> set[Path]:
    roots = {Path(project_root).resolve() / DEFAULT_RUN_ROOT}
    workspace = Path(workspace_root).resolve() if workspace_root else None
    if workspace and workspace.is_dir():
        roots.update(workspace.glob("*/.megaplan/plans/resident-subagents"))
        roots.update(workspace.glob("*/*/.megaplan/plans/resident-subagents"))
    return roots


@dataclass(frozen=True)
class ManagedCommandSpec:
    run_kind: str
    identity_key: str
    project_dir: Path
    argv: tuple[str, ...]
    task_kind: str
    difficulty: int
    model: str
    reasoning_effort: str
    route_class: str
    backend: str
    command_display: str
    launch_provenance: Mapping[str, Any]
    links: Mapping[str, Any]
    description: str | None = None
    parent_run_id: str | None = None
    retry_of_run_id: str | None = None
    lineage_key: str | None = None
    run_root: Path | None = None
    stdin_path: Path | None = None
    require_output: bool = False
    tee_output: bool = True
    child_difficulty_ceiling: int | None = None
    filesystem_capability: dict[str, Any] | None = None
    # Set by an admission-backed caller.  It is persisted and propagated to
    # the child so timeout/interrupt handling can use the same receipt rather
    # than reconstructing identity from a PID or model name.
    worker_execution_context: Mapping[str, Any] | None = None


def _root_for(spec: ManagedCommandSpec) -> Path:
    root = spec.run_root or DEFAULT_RUN_ROOT
    return root.resolve() if root.is_absolute() else spec.project_dir.resolve() / root


def _command_hash(argv: Sequence[str]) -> str:
    return hashlib.sha256(json.dumps(list(argv), separators=(",", ":")).encode()).hexdigest()


def _stdin_bytes(spec: ManagedCommandSpec) -> bytes | None:
    if spec.stdin_path is None:
        return None
    return spec.stdin_path.read_bytes()


def _launch_contract(
    spec: ManagedCommandSpec, *, provenance: Mapping[str, Any], stdin_bytes: bytes | None
) -> dict[str, Any]:
    child_ceiling = _effective_child_difficulty_ceiling(spec)
    return {
        "run_kind": spec.run_kind,
        "identity_key": spec.identity_key,
        "project_dir": str(spec.project_dir.resolve()),
        "command_sha256": _command_hash(spec.argv),
        "task_kind": spec.task_kind,
        "difficulty": spec.difficulty,
        "model": spec.model,
        "reasoning_effort": spec.reasoning_effort,
        "route_class": spec.route_class,
        "backend": spec.backend,
        "launch_provenance": dict(provenance),
        "stdin_sha256": hashlib.sha256(stdin_bytes).hexdigest() if stdin_bytes is not None else None,
        "stdin_size_bytes": len(stdin_bytes) if stdin_bytes is not None else 0,
        "links": dict(spec.links),
        "parent_run_id": spec.parent_run_id,
        "retry_of_run_id": spec.retry_of_run_id,
        "lineage_key": spec.lineage_key,
        "require_output": spec.require_output,
        "worker_execution_context": dict(spec.worker_execution_context)
        if isinstance(spec.worker_execution_context, Mapping) else None,
        "authority": {
            "root_difficulty": spec.difficulty,
            "child_difficulty_ceiling": child_ceiling,
            "inherited_ceiling": _inherited_difficulty_ceiling(),
        },
    }


def _contract_hash(contract: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(dict(contract), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _latest_lineage_run(root: Path, lineage_key: str, current_run_id: str) -> str | None:
    candidates: list[tuple[str, str]] = []
    for path in root.glob("*/manifest.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        run_id = str(payload.get("run_id") or path.parent.name)
        if run_id == current_run_id or payload.get("lineage_key") != lineage_key:
            continue
        candidates.append((str(payload.get("created_at") or ""), run_id))
    return max(candidates)[1] if candidates else None


def _new_manifest(
    spec: ManagedCommandSpec,
    manifest_path: Path,
    *,
    provenance: Mapping[str, Any],
    stdin_bytes: bytes | None,
) -> dict[str, Any]:
    run_id = manifest_path.parent.name
    created_at = utc_now()
    retry_of = spec.retry_of_run_id
    if retry_of is None and spec.lineage_key:
        retry_of = _latest_lineage_run(manifest_path.parent.parent, spec.lineage_key, run_id)
    result_path = manifest_path.parent / "result.json"
    log_path = manifest_path.parent / "run.log"
    sealed_stdin_path = manifest_path.parent / "stdin.bin"
    launch_contract = _launch_contract(spec, provenance=provenance, stdin_bytes=stdin_bytes)
    child_ceiling = _effective_child_difficulty_ceiling(spec)
    payload: dict[str, Any] = {
        "schema_version": MANAGED_AGENT_SCHEMA,
        "custodian": MANAGED_AGENT_CUSTODIAN,
        "run_id": run_id,
        "run_kind": spec.run_kind,
        "backend": spec.backend,
        "model": spec.model,
        "reasoning_effort": spec.reasoning_effort,
        "route_class": spec.route_class,
        "task_kind": spec.task_kind,
        "difficulty": spec.difficulty,
        "authority": {
            "root_difficulty": spec.difficulty,
            "child_difficulty_ceiling": child_ceiling,
            "inherited_ceiling": _inherited_difficulty_ceiling(),
            "self_escalation_allowed": False,
        },
        "project_dir": str(spec.project_dir.resolve()),
        "manifest_path": str(manifest_path.resolve()),
        "log_path": str(log_path.resolve()),
        "full_log_path": str(log_path.resolve()),
        "result_path": str(result_path.resolve()),
        "launch_idempotency_key": spec.identity_key,
        "description": spec.description or spec.command_display,
        "command_display": spec.command_display,
        "execution_kind": "agentic" if spec.require_output else "managed_controller",
        "output_required": spec.require_output,
        "command_sha256": _command_hash(spec.argv),
        "launch_contract_sha256": _contract_hash(launch_contract),
        "launch_provenance": dict(provenance),
        "provenance_sha256": hashlib.sha256(
            json.dumps(dict(provenance), sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "stdin": (
            {
                "kind": "sealed_file",
                "sealed": True,
                "path": str(sealed_stdin_path.resolve()),
                "sha256": hashlib.sha256(stdin_bytes).hexdigest(),
                "size_bytes": len(stdin_bytes),
            }
            if stdin_bytes is not None
            else {"kind": "devnull", "sealed": True, "size_bytes": 0}
        ),
        "links": dict(spec.links),
        "lineage_key": spec.lineage_key,
        "parent_run_id": spec.parent_run_id,
        "retry_of_run_id": retry_of,
        "created_at": created_at,
        "updated_at": created_at,
        "completion_delivery": {
            "transport": "non_discord",
            "status": "not_applicable",
            "attempt_count": 0,
            "evidence": "automatic_internal_run_has_no_inbound_reply_contract",
        },
        "status": "reserved",
        "status_history": [
            {"status": "reserved", "at": created_at, "evidence": "manifest_committed_before_process_launch"}
        ],
    }
    if isinstance(spec.worker_execution_context, Mapping):
        payload["worker_execution_context"] = dict(spec.worker_execution_context)
    return {key: value for key, value in payload.items() if value is not None}


def reserve_managed_command(spec: ManagedCommandSpec) -> tuple[Path, dict[str, Any], bool]:
    if spec.run_kind not in AUTOMATIC_RUN_KINDS:
        raise ValueError(f"unsupported automatic managed run kind: {spec.run_kind}")
    if not 1 <= spec.difficulty <= 10:
        raise ValueError("difficulty must be D1-D10")
    _effective_child_difficulty_ceiling(spec)
    provenance = normalize_machine_origin_provenance(spec.launch_provenance)
    stdin_bytes = _stdin_bytes(spec)
    expected_contract = _contract_hash(
        _launch_contract(spec, provenance=provenance, stdin_bytes=stdin_bytes)
    )
    root = _root_for(spec)
    root.mkdir(parents=True, exist_ok=True)
    run_id = stable_managed_run_id(spec.run_kind, spec.identity_key)
    run_dir = root / run_id
    manifest_path = run_dir / "manifest.json"
    with (root / ".launch.lock").open("a+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        if manifest_path.exists():
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            if payload.get("launch_idempotency_key") != spec.identity_key:
                raise RuntimeError(f"managed run identity collision: {run_id}")
            if payload.get("launch_contract_sha256") != expected_contract:
                raise RuntimeError(f"managed run launch contract changed for identity: {run_id}")
            return manifest_path, payload, False
        run_dir.mkdir(parents=False, exist_ok=False)
        if stdin_bytes is not None:
            sealed_path = run_dir / "stdin.bin"
            descriptor = os.open(sealed_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(stdin_bytes)
                handle.flush()
                os.fsync(handle.fileno())
        payload = _new_manifest(
            spec,
            manifest_path,
            provenance=provenance,
            stdin_bytes=stdin_bytes,
        )
        atomic_write_manifest(manifest_path, payload)
        Path(str(payload["result_path"])).touch()
        Path(str(payload["log_path"])).touch()
        return manifest_path, payload, True


def _bind_repair_claim(manifest: dict[str, Any]) -> None:
    links = manifest.get("links")
    if not isinstance(links, dict):
        return
    queue_dir = str(links.get("repair_queue_dir") or "")
    blocker_id = str(links.get("blocker_id") or "")
    request_id = str(links.get("repair_request_id") or "")
    if not queue_dir or not blocker_id or not request_id:
        return
    repair_identity_key = str(links.get("repair_identity_key") or "").strip()
    repair_identity_json = str(links.get("repair_identity_json") or "").strip()
    repair_identity: dict[str, Any] | None = None
    if repair_identity_json:
        try:
            parsed_repair_identity = json.loads(repair_identity_json)
        except json.JSONDecodeError as exc:
            raise RuntimeError("repair claim identity is not valid JSON") from exc
        if not isinstance(parsed_repair_identity, Mapping):
            raise RuntimeError("repair claim identity must be a JSON object")
        repair_identity = dict(parsed_repair_identity)
    from arnold_pipelines.megaplan.cloud.repair_requests import (
        active_repair_claim_lock_dir,
        bind_managed_run_to_active_claim,
        owner_metadata_path,
    )

    bound = bind_managed_run_to_active_claim(
        queue_dir,
        blocker_id=blocker_id,
        request_id=request_id,
        managed_run_id=str(manifest["run_id"]),
        managed_manifest_path=str(manifest["manifest_path"]),
        expected_owner_pid=int(os.environ.get("CLOUD_WATCHDOG_REPAIR_CLAIM_OWNER_PID") or 0) or None,
        new_owner_pid=os.getpid(),
        repair_identity=repair_identity,
        expected_repair_identity_key=repair_identity_key,
    )
    if not bound:
        raise RuntimeError("repair claim could not be fenced to managed run")
    claim_dir = active_repair_claim_lock_dir(queue_dir, blocker_id)
    manifest["repair_claim"] = {
        "kind": "active_repair_request_claim",
        "request_id": request_id,
        "blocker_id": blocker_id,
        "claim_lock_dir": str(claim_dir),
        "owner_metadata_path": str(owner_metadata_path(claim_dir)),
        "fenced_managed_run_id": str(manifest["run_id"]),
        "owner_pid": os.getpid(),
        "bound_at": utc_now(),
        "repair_identity_key": repair_identity_key,
    }
    if repair_identity is not None:
        manifest["repair_claim"]["repair_identity"] = repair_identity


def _emit_attempt(manifest: Mapping[str, Any]) -> tuple[str, str] | None:
    links = manifest.get("links")
    if not isinstance(links, Mapping):
        return None
    incident_id = str(links.get("incident_id") or "")
    if not incident_id:
        return None
    if manifest.get("incident_claim_event_id") and manifest.get("incident_attempt_event_id"):
        return (
            str(manifest["incident_claim_event_id"]),
            str(manifest["incident_attempt_event_id"]),
        )
    from arnold_pipelines.megaplan.cloud import incident_bridge

    evidence = [{
        "kind": "managed_agent_execution",
        "run_id": manifest.get("run_id"),
        "manifest_path": manifest.get("manifest_path"),
        "repair_request_id": links.get("repair_request_id"),
        "blocker_id": links.get("blocker_id"),
    }]
    run_kind = str(manifest.get("run_kind") or "")
    actor = (
        "meta_repair"
        if run_kind.startswith("automatic_meta")
        or run_kind == "automatic_root_cause_repair"
        else "immediate_repair"
    )
    claim_event = incident_bridge.append_managed_repair_claim(
        incident_id=incident_id,
        claim_id=f"managed:{manifest.get('run_id')}",
        actor=actor,
        summary=f"managed {manifest.get('run_kind')} accepted execution custody",
        evidence=evidence,
        session_id=str(links.get("cloud_session") or "") or None,
        problem_id=str(links.get("problem_id") or "") or None,
        next_expected_event=(
            "meta_repair.repair_attempt"
            if actor == "meta_repair"
            else "immediate_repair.repair_attempt"
        ),
        links={"managed_agent": str(manifest.get("manifest_path"))},
        root=str(manifest.get("project_dir") or "."),
    )
    claim_event_id = str(
        claim_event.get("event_id")
        or dict(claim_event.get("payload") or {}).get("event_id")
        or ""
    )
    kwargs = dict(
        incident_id=incident_id,
        summary=f"managed {manifest.get('run_kind')} execution started",
        attempt_id=str(manifest.get("run_id")),
        outcome="attempted",
        evidence=evidence,
        session_id=str(links.get("cloud_session") or "") or None,
        problem_id=str(links.get("problem_id") or "") or None,
        parent_event_ids=[claim_event_id] if claim_event_id else [],
        links={"managed_agent": str(manifest.get("manifest_path"))},
        root=str(manifest.get("project_dir") or "."),
    )
    if manifest.get("run_kind") in {
        "automatic_meta_repair",
        "automatic_root_cause_repair",
    }:
        attempt_event = incident_bridge.append_meta_repair_attempt(**kwargs)
    else:
        attempt_event = incident_bridge.append_immediate_repair_attempt(**kwargs)
    attempt_event_id = str(
        attempt_event.get("event_id")
        or dict(attempt_event.get("payload") or {}).get("event_id")
        or ""
    )
    return claim_event_id, attempt_event_id


def _write_result(manifest: Mapping[str, Any]) -> None:
    log_path = Path(str(manifest["log_path"]))
    try:
        log_bytes = log_path.read_bytes()
    except OSError:
        log_bytes = b""
    result = {
        "schema_version": 1,
        "run_id": manifest.get("run_id"),
        "run_kind": manifest.get("run_kind"),
        "status": manifest.get("status"),
        "terminal_outcome": manifest.get("terminal_outcome"),
        "returncode": manifest.get("returncode"),
        "finished_at": manifest.get("finished_at"),
        "error_class": manifest.get("error_class"),
        "repair_goal": manifest.get("repair_goal"),
        "semantic_completion": manifest.get("semantic_completion"),
        "output_sha256": hashlib.sha256(log_bytes).hexdigest(),
        "output_size_bytes": len(log_bytes),
    }
    path = Path(str(manifest["result_path"]))
    atomic_write_manifest(path, result)


def _wait_for_adopted_worker(manifest_path: Path, manifest: dict[str, Any]) -> int:
    _append_status(manifest, "adopting", evidence="restart_found_live_worker")
    manifest["pid"] = os.getpid()
    atomic_write_manifest(manifest_path, manifest)
    worker_pid = manifest.get("worker_pid")
    while _pid_matches(
        worker_pid,
        str(manifest.get("worker_cmdline_sha256") or ""),
        str(manifest.get("worker_start_ticks") or ""),
    ):
        time.sleep(1)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    _append_status(manifest, "unknown", evidence="adopted_worker_exited_without_wait_status")
    manifest["terminal_outcome"] = "unknown_after_adoption"
    manifest["finished_at"] = utc_now()
    manifest["returncode"] = 1
    atomic_write_manifest(manifest_path, manifest)
    _write_result(manifest)
    return 1


def run_managed_command(spec: ManagedCommandSpec, *, run_id_file: Path | None = None) -> int:
    manifest_path, manifest, created = reserve_managed_command(spec)
    if run_id_file is not None:
        run_id_file.parent.mkdir(parents=True, exist_ok=True)
        run_id_file.write_text(str(manifest["run_id"]) + "\n", encoding="utf-8")
    execution_handle = (manifest_path.parent / ".execution.lock").open("a+b")
    try:
        fcntl.flock(execution_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        execution_handle.close()
        return 0
    try:
        return _run_managed_command_locked(spec, manifest_path, manifest, created)
    finally:
        fcntl.flock(execution_handle.fileno(), fcntl.LOCK_UN)
        execution_handle.close()



def _record_target_git_state(manifest: dict[str, Any], capability: Mapping[str, Any]) -> None:
    """Record the milestone worktree git state before an automatic repair runs, so a
    post-run assertion can prove the fixer did not mutate milestone code."""
    protected_refs = [str(ref) for ref in (capability.get("protected_git_refs") or [])]
    read_only_roots = [
        Path(str(root)).resolve()
        for root in (capability.get("read_only_roots") or [])
    ]
    states: dict[str, dict[str, str]] = {}
    for root in read_only_roots:
        git_root = root / ".git"
        if not git_root.exists():
            states[str(root)] = {"error": "no_git_dir"}
            continue
        try:
            head = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True, timeout=5,
            ).stdout.strip()
            states[str(root)] = {"head": head}
        except Exception as exc:
            states[str(root)] = {"error": str(exc)}
    manifest["target_git_state_before"] = states
    manifest["protected_git_refs"] = protected_refs


def _assert_target_unchanged(manifest: dict[str, Any]) -> None:
    """Fail the run if any protected milestone worktree changed under the fixer."""
    before = manifest.get("target_git_state_before")
    if not isinstance(before, Mapping):
        return
    for root_raw, state in before.items():
        if not isinstance(state, Mapping):
            continue
        if state.get("error"):
            continue
        root = Path(root_raw)
        try:
            head = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True, timeout=5,
            ).stdout.strip()
        except Exception:
            continue
        if head != state.get("head"):
            raise RuntimeError(
                f"automatic repair mutated protected milestone worktree {root}: "
                f"HEAD {state.get('head')} -> {head}"
            )


def _run_managed_command_locked(
    spec: ManagedCommandSpec,
    manifest_path: Path,
    manifest: dict[str, Any],
    created: bool,
) -> int:
    status = str(manifest.get("status") or "unknown")
    if not created:
        observed, live = observed_status(manifest, manifest_path)
        if live and _pid_matches(
            manifest.get("worker_pid"),
            str(manifest.get("worker_cmdline_sha256") or ""),
            str(manifest.get("worker_start_ticks") or ""),
        ):
            if _pid_matches(
                manifest.get("pid"),
                str(manifest.get("supervisor_cmdline_sha256") or ""),
                str(manifest.get("supervisor_start_ticks") or ""),
            ):
                return 0
            return _wait_for_adopted_worker(manifest_path, manifest)
        if status in TERMINAL_STATUSES:
            return int(manifest.get("returncode") or (0 if status == "completed" else 1))
        _append_status(manifest, "launching", evidence="restart_reconciled_dead_supervisor_same_run")
        manifest["restart_count"] = int(manifest.get("restart_count") or 0) + 1
    else:
        _append_status(manifest, "launching", evidence="supervisor_start")

    manifest["pid"] = os.getpid()
    manifest["supervisor_start_ticks"] = _pid_start_ticks(os.getpid())
    try:
        raw = Path(f"/proc/{os.getpid()}/cmdline").read_bytes()
        manifest["supervisor_cmdline_sha256"] = hashlib.sha256(raw).hexdigest()
    except OSError:
        pass
    manifest["started_at"] = manifest.get("started_at") or utc_now()
    atomic_write_manifest(manifest_path, manifest)

    child: subprocess.Popen[bytes] | None = None
    interrupted: int | None = None

    def stop(signum: int, _frame: object) -> None:
        nonlocal interrupted
        interrupted = signum
        if child is not None and child.poll() is None:
            signal_managed_process(
                manifest_path,
                manifest,
                child.pid,
                signal.SIGTERM,
                cause_kind="terminate",
                ladder_step="term",
                worker=True,
                wait_fn=lambda: child.wait(timeout=5),
            )

    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        _bind_repair_claim(manifest)
        atomic_write_manifest(manifest_path, manifest)
        emitted = _emit_attempt(manifest)
        if emitted is not None:
            manifest["incident_claim_event_id"], manifest["incident_attempt_event_id"] = emitted
            atomic_write_manifest(manifest_path, manifest)
        env = os.environ.copy()
        inherited_worker_context = env.get("ARNOLD_WORKER_EXECUTION_CONTEXT")
        if inherited_worker_context and "worker_execution_context" not in manifest:
            try:
                context_ref = resolve_worker_execution_context(env)
            except (TypeError, ValueError, SignalDispositionError) as exc:
                raise RuntimeError("managed launch inherited malformed worker execution context") from exc
            manifest["worker_execution_context"] = context_ref.to_dict()
            atomic_write_manifest(manifest_path, manifest)
        # Automatic agents have machine custody.  A chain marker may carry a
        # Discord envelope for a later explicit reply, but it is not launch
        # authority for this internal child and must not leak into its process.
        inherited_resident = env.pop(RESIDENT_DELEGATION_ENV, None)
        if inherited_resident:
            try:
                inherited_payload = json.loads(inherited_resident)
                from arnold_pipelines.megaplan.resident.provenance import (
                    normalize_delegation_provenance,
                )

                normalized_inherited = normalize_delegation_provenance(inherited_payload)
            except Exception as exc:
                raise RuntimeError("automatic launch inherited malformed resident provenance") from exc
            manifest["upstream_custody"] = normalized_inherited
            manifest["upstream_custody_sha256"] = hashlib.sha256(
                json.dumps(
                    normalized_inherited, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            ).hexdigest()
            atomic_write_manifest(manifest_path, manifest)
        env[MACHINE_ORIGIN_ENV] = json.dumps(
            manifest["launch_provenance"], sort_keys=True, separators=(",", ":")
        )
        env["ARNOLD_MANAGED_AGENT_RUN_ID"] = str(manifest["run_id"])
        env["ARNOLD_MANAGED_AGENT_MANIFEST"] = str(manifest_path)
        env[MANAGED_DIFFICULTY_CEILING_ENV] = str(
            _mapping_int(manifest.get("authority"), "child_difficulty_ceiling")
            or spec.difficulty
        )
        context_payload = manifest.get("worker_execution_context")
        if isinstance(context_payload, Mapping):
            # The exact serialized WBC reference is part of the managed launch
            # envelope; do not synthesize a replacement from the child PID.
            env["ARNOLD_WORKER_EXECUTION_CONTEXT"] = json.dumps(
                dict(context_payload), sort_keys=True, separators=(",", ":")
            )
        if spec.run_kind == "automatic_repair" and env.get("CLOUD_WATCHDOG_REPAIR_REQUEST_ID"):
            env["CLOUD_WATCHDOG_REPAIR_CLAIM_OWNER_PID"] = str(os.getpid())
        stdin_contract = manifest.get("stdin")
        sealed_stdin = (
            Path(str(stdin_contract.get("path")))
            if isinstance(stdin_contract, Mapping) and stdin_contract.get("kind") == "sealed_file"
            else None
        )
        if sealed_stdin is not None:
            observed_stdin = sealed_stdin.read_bytes()
            if hashlib.sha256(observed_stdin).hexdigest() != stdin_contract.get("sha256"):
                raise RuntimeError("sealed managed-agent stdin failed integrity verification")
            child_stdin = sealed_stdin.open("rb")
        else:
            child_stdin = subprocess.DEVNULL
        worker_argv = [
            item.replace(SEALED_STDIN_PLACEHOLDER, str(sealed_stdin))
            if sealed_stdin is not None
            else item
            for item in spec.argv
        ]
        if any(SEALED_STDIN_PLACEHOLDER in item for item in worker_argv):
            raise RuntimeError("managed stdin placeholder used without sealed stdin")
        capability = _resolve_fs_capability(manifest)
        launch_argv = list(worker_argv)
        if (
            spec.run_kind in AUTOMATIC_RUN_KINDS
            and capability.get("profile") == FILESYSTEM_CAPABILITY_RECOVERY_ENGINE_ONLY
        ):
            engine_roots = [
                Path(str(root)).resolve()
                for root in (capability.get("writable_roots") or [])
            ]
            read_only_roots = [
                Path(str(root)).resolve()
                for root in (capability.get("read_only_roots") or [])
            ]
            if not engine_roots:
                engine_roots = [Path(str(spec.project_dir)).resolve()]
            # bwrap needs user-namespace support; inside a docker container
            # (no CAP_SYS_ADMIN / user namespaces) it fails with "Creating
            # new namespace failed: Operation not permitted". Probe once with
            # a no-op and fall back to the direct launch (the container IS
            # the isolation boundary) when bwrap cannot create a namespace.
            bwrap_usable = False
            try:
                probe = subprocess.run(
                    ["bwrap", "--ro-bind", "/", "/", "--", "true"],
                    capture_output=True,
                    timeout=15,
                )
                bwrap_usable = probe.returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                bwrap_usable = False
            if bwrap_usable:
                bwrap_cmd = ["bwrap", "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev"]
                for root in engine_roots:
                    bwrap_cmd += ["--bind", str(root), str(root)]
                for root in read_only_roots:
                    bwrap_cmd += ["--ro-bind", str(root), str(root)]
                bwrap_cmd += ["--"]
                bwrap_cmd += launch_argv
                launch_argv = bwrap_cmd
        child = subprocess.Popen(
            launch_argv,

            cwd=str(spec.project_dir),
            stdin=child_stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
        )
        if spec.stdin_path is not None:
            child_stdin.close()
        raw_cmdline = b"\0".join(os.fsencode(item) for item in worker_argv) + b"\0"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if (
            spec.run_kind in AUTOMATIC_RUN_KINDS
            and capability.get("profile") == FILESYSTEM_CAPABILITY_RECOVERY_ENGINE_ONLY
        ):
            _record_target_git_state(manifest, capability)
        manifest["worker_pid"] = child.pid

        manifest["worker_start_ticks"] = _pid_start_ticks(child.pid)
        manifest["worker_started_at"] = utc_now()
        manifest["worker_identity"] = _managed_worker_identity(
            child.pid, manifest["worker_start_ticks"]
        )
        manifest["worker_launch_certified"] = certify_managed_worker_launch(
            manifest_path,
            manifest,
            pid=child.pid,
            worker_identity=manifest["worker_identity"],
            process_start_identity=str(manifest["worker_start_ticks"] or ""),
            started_at=str(manifest["worker_started_at"]),
        )
        manifest["worker_cmdline_sha256"] = hashlib.sha256(raw_cmdline).hexdigest()
        _append_status(manifest, "running", evidence="worker_process_started")
        atomic_write_manifest(manifest_path, manifest)
        log_path = Path(str(manifest["log_path"]))
        with log_path.open("ab") as log:
            assert child.stdout is not None
            while True:
                chunk = child.stdout.read(65536)
                if not chunk:
                    break
                log.write(chunk)
                log.flush()
                if spec.tee_output:
                    try:
                        sys.stdout.buffer.write(chunk)
                        sys.stdout.buffer.flush()
                    except BrokenPipeError:
                        pass
        returncode = child.wait()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        control_terminal = str(manifest.get("status") or "")
        log_size = Path(str(manifest["log_path"])).stat().st_size
        no_output = spec.require_output and returncode == 0 and log_size == 0
        goal_semantics = _repair_goal_semantics(manifest)
        goal_incomplete = bool(
            goal_semantics
            and not goal_semantics["terminal"]
            and spec.run_kind != "automatic_repair_retry"
            and returncode == 0
        )
        terminal = (
            control_terminal
            if control_terminal in {"cancelled", "superseded"}
            else (
                "interrupted"
                if interrupted is not None
                else (
                    "completed"
                    if returncode == 0 and not no_output and not goal_incomplete
                    else "failed"
                )
            )
        )
        effective_returncode = 75 if goal_incomplete else 74 if no_output else returncode
        _append_status(
            manifest,
            terminal,
            evidence="worker_process_no_output" if no_output else "worker_process_waited",
            returncode=effective_returncode,
        )
        manifest["returncode"] = effective_returncode
        manifest["terminal_outcome"] = terminal
        manifest["finished_at"] = utc_now()
        if goal_semantics is not None:
            manifest["repair_goal"] = goal_semantics
            manifest["semantic_completion"] = {
                "status": (
                    "completed"
                    if goal_semantics["semantic_completion"]
                    else (
                        "blocked"
                        if goal_semantics["status"] == "approval_required"
                        else "continuing"
                    )
                ),
                "complete": goal_semantics["semantic_completion"],
                "authority": "repair_goal",
                "goal_id": goal_semantics["goal_id"],
                "checkpoint_digest": goal_semantics["checkpoint_digest"],
                "reason": goal_semantics["reason"],
            }
        if no_output:
            manifest["error"] = "managed agent produced no durable output"
            manifest["error_class"] = "ManagedAgentNoOutput"
        if goal_incomplete:
            manifest["error"] = "managed repair worker exited before its durable goal completed"
            manifest["error_class"] = "RepairGoalIncomplete"
        if interrupted is not None:
            manifest["signal"] = interrupted
        atomic_write_manifest(manifest_path, manifest)
        _write_result(manifest)
        return effective_returncode
    except BaseException as exc:
        if child is not None and child.poll() is None:
            signal_managed_process(
                manifest_path,
                manifest,
                child.pid,
                signal.SIGTERM,
                cause_kind="terminate",
                ladder_step="term",
                worker=True,
                wait_fn=lambda: child.wait(timeout=5),
            )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        control_terminal = str(manifest.get("status") or "")
        terminal = (
            control_terminal
            if control_terminal in {"cancelled", "superseded"}
            else ("interrupted" if interrupted is not None else "failed")
        )
        _append_status(manifest, terminal, evidence="supervisor_exception")
        manifest["returncode"] = 128 + interrupted if interrupted is not None else 1
        manifest["terminal_outcome"] = terminal
        manifest["error"] = "managed process supervisor failed"
        manifest["error_class"] = exc.__class__.__name__
        manifest["finished_at"] = utc_now()
        atomic_write_manifest(manifest_path, manifest)
        _write_result(manifest)
        return int(manifest["returncode"])
    finally:
        if child is not None and child.stdout is not None:
            child.stdout.close()
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def transition_terminal(manifest_path: Path, status: str, *, reason: str) -> dict[str, Any]:
    if status not in {"cancelled", "superseded"}:
        raise ValueError("terminal transition must be cancelled or superseded")
    with (manifest_path.parent / ".transition.lock").open("a+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        if str(payload.get("status")) in TERMINAL_STATUSES:
            return payload
        for field in ("worker_pid", "pid"):
            pid = payload.get(field)
            prefix = "worker" if field == "worker_pid" else "supervisor"
            if _pid_matches(
                pid,
                str(payload.get(f"{prefix}_cmdline_sha256") or ""),
                str(payload.get(f"{prefix}_start_ticks") or ""),
            ):
                try:
                    signal_managed_process(
                        manifest_path,
                        payload,
                        int(pid),
                        signal.SIGTERM,
                        cause_kind="terminate",
                        ladder_step="term",
                        worker=(field == "worker_pid"),
                    )
                except OSError:
                    pass
        _append_status(payload, status, evidence="explicit_control_plane_transition", reason=reason)
        payload["terminal_outcome"] = status
        payload["returncode"] = 143
        payload["finished_at"] = utc_now()
        atomic_write_manifest(manifest_path, payload)
        _write_result(payload)
        return payload


def _parse_links(values: Sequence[str]) -> dict[str, Any]:
    links: dict[str, Any] = {}
    for value in values:
        key, separator, raw = value.partition("=")
        if not separator or not key.strip():
            raise ValueError(f"link must be KEY=VALUE: {value!r}")
        links[key.strip()] = raw
    return links


def _inherited_difficulty_ceiling() -> int | None:
    raw = str(os.environ.get(MANAGED_DIFFICULTY_CEILING_ENV) or "").strip()
    if not raw:
        return None
    try:
        ceiling = int(raw)
    except ValueError as exc:
        raise ValueError("inherited managed-agent difficulty ceiling is malformed") from exc
    if not 1 <= ceiling <= 10:
        raise ValueError("inherited managed-agent difficulty ceiling must be D1-D10")
    return ceiling


def _effective_child_difficulty_ceiling(spec: ManagedCommandSpec) -> int:
    requested = spec.child_difficulty_ceiling
    if requested is None:
        requested = spec.difficulty
    if not 1 <= requested <= 10:
        raise ValueError("child difficulty ceiling must be D1-D10")
    if requested > spec.difficulty:
        raise ValueError("child difficulty ceiling cannot exceed root difficulty")
    inherited = _inherited_difficulty_ceiling()
    if inherited is not None and spec.difficulty > inherited:
        raise ValueError("managed child difficulty exceeds inherited root ceiling")
    if inherited is not None and requested > inherited:
        raise ValueError("managed child ceiling exceeds inherited root ceiling")
    return requested


def _mapping_int(value: object, key: str) -> int | None:
    if not isinstance(value, Mapping):
        return None
    raw = value.get(key)
    if isinstance(raw, bool):
        return None
    try:
        return int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m arnold_pipelines.megaplan.managed_agent")
    sub = parser.add_subparsers(dest="action", required=True)
    run = sub.add_parser("run")
    run.add_argument("--run-kind", required=True)
    run.add_argument("--identity-key", required=True)
    run.add_argument("--project-dir", required=True)
    run.add_argument("--run-root")
    run.add_argument("--task-kind", required=True)
    run.add_argument("--difficulty", type=int, required=True)
    run.add_argument("--child-difficulty-ceiling", type=int)
    run.add_argument("--model", required=True)
    run.add_argument("--reasoning-effort", required=True)
    run.add_argument("--route-class", required=True)
    run.add_argument("--backend", required=True)
    run.add_argument("--command-display", required=True)
    run.add_argument("--description")
    run.add_argument("--origin-kind", choices=sorted(MACHINE_ORIGIN_KINDS), required=True)
    run.add_argument("--origin-id", required=True)
    run.add_argument("--origin-component", required=True)
    run.add_argument("--trigger-id", required=True)
    run.add_argument("--parent-run-id")
    run.add_argument("--retry-of-run-id")
    run.add_argument("--lineage-key")
    run.add_argument("--run-id-file")
    run.add_argument("--stdin-file")
    run.add_argument("--require-output", action="store_true")
    run.add_argument("--link", action="append", default=[])
    run.add_argument("command", nargs=argparse.REMAINDER)
    transition = sub.add_parser("transition")
    transition.add_argument("manifest")
    transition.add_argument("status", choices=("cancelled", "superseded"))
    transition.add_argument("--reason", required=True)
    identity = sub.add_parser("identity")
    identity.add_argument("run_kind")
    identity.add_argument("identity_key")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.action == "identity":
        print(stable_managed_run_id(args.run_kind, args.identity_key))
        return 0
    if args.action == "transition":
        transition_terminal(Path(args.manifest), args.status, reason=args.reason)
        return 0
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("managed command is required after --")
    if not 1 <= args.difficulty <= 10:
        raise SystemExit("difficulty must be D1-D10")
    _fs_capability: dict[str, Any] | None = None
    if args.run_kind in AUTOMATIC_RUN_KINDS:
        _target_root = None
        if getattr(args, "target_root", None):
            _target_root = Path(args.target_root).resolve()
        elif getattr(args, "project_dir", None):
            _target_root = Path(args.project_dir).resolve()
        _fs_capability = {
            "profile": FILESYSTEM_CAPABILITY_RECOVERY_ENGINE_ONLY,
            "writable_roots": [],
            "read_only_roots": [str(_target_root)] if _target_root else [],
            "protected_git_refs": [],
            "sha256": "",
        }
    spec = ManagedCommandSpec(
        run_kind=args.run_kind,

        identity_key=args.identity_key,
        project_dir=Path(args.project_dir).resolve(),
        argv=tuple(command),
        task_kind=args.task_kind,
        difficulty=args.difficulty,
        model=args.model,
        reasoning_effort=args.reasoning_effort,
        route_class=args.route_class,
        backend=args.backend,
        command_display=args.command_display,
        description=args.description,
        launch_provenance=machine_origin_provenance(
            origin_kind=args.origin_kind,
            origin_id=args.origin_id,
            component=args.origin_component,
            trigger_id=args.trigger_id,
        ),
        links=_parse_links(args.link),
        parent_run_id=args.parent_run_id,
        retry_of_run_id=args.retry_of_run_id,
        lineage_key=args.lineage_key,
        run_root=Path(args.run_root).resolve() if args.run_root else None,
        stdin_path=Path(args.stdin_file).resolve() if args.stdin_file else None,
        require_output=args.require_output,
        child_difficulty_ceiling=args.child_difficulty_ceiling,
        filesystem_capability=_fs_capability,
    )
    return run_managed_command(
        spec,
        run_id_file=Path(args.run_id_file) if args.run_id_file else None,
    )


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ACTIVE_STATUSES",
    "AUTOMATIC_RUN_KINDS",
    "DEFAULT_RUN_ROOT",
    "LEGACY_RESIDENT_CUSTODIAN",
    "LEGACY_RESIDENT_SCHEMA",
    "MANAGED_AGENT_CUSTODIAN",
    "MANAGED_AGENT_SCHEMA",
    "MACHINE_ORIGIN_KINDS",
    "MACHINE_ORIGIN_ENV",
    "MANAGED_DIFFICULTY_CEILING_ENV",
    "MACHINE_ORIGIN_SCHEMA",
    "SEALED_STDIN_PLACEHOLDER",
    "ManagedCommandSpec",
    "TERMINAL_STATUSES",
    "atomic_write_manifest",
    "is_managed_manifest",
    "managed_run_roots",
    "machine_origin_provenance",
    "normalize_machine_origin_provenance",
    "observed_status",
    "reserve_managed_command",
    "run_managed_command",
    "stable_managed_run_id",
    "transition_terminal",
    "validate_automatic_managed_manifest",
]
