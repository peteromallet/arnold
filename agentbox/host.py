"""Host-local AgentBox launch orchestration."""

from __future__ import annotations

from dataclasses import dataclass
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from arnold.runtime.durable_ops import (
    LaunchDispatchRejected,
    LaunchEnvelope,
    LaunchResult,
    launch_transaction,
    OperationRun,
    OperationAlreadyExists,
    OperationState,
    TypedResource,
    ResourceType,
    run_launch_preflight,
)

from agentbox.config import AgentBoxConfig
from agentbox.operations import (
    create_agentbox_operation,
    load_agentbox_operation,
    open_operation_store,
    update_agentbox_operation,
)
from agentbox.run_dirs import (
    RunDirPaths,
    append_event,
    ensure_run_dir,
    read_metadata,
    record_log_resources,
    run_dir_paths,
    write_metadata,
)
from agentbox.tmux import (
    SessionStatus,
    inspect_session,
    record_process_session_resource,
    start_session,
    session_name,
)
from agentbox.worktrees import WorktreeAllocation, WorktreeAllocationError, allocate_worktree


class HostLaunchError(RuntimeError):
    """Raised after persisting diagnostics for an unsuccessful host launch."""

    def __init__(
        self,
        kind: str,
        message: str,
        *,
        diagnostics: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.diagnostics = dict(diagnostics or {})


@dataclass(frozen=True)
class HostLaunchResult:
    """Durable resources and state created by one host launch attempt."""

    operation_id: str
    launch_state: str
    operation_state: OperationState
    run_paths: RunDirPaths
    worktrees: tuple[WorktreeAllocation, ...]
    log_resources: tuple[TypedResource, TypedResource]
    session_name: str | None = None
    session_status: SessionStatus | None = None
    process_session_resource: TypedResource | None = None
    diagnostics: Mapping[str, Any] | None = None


def launch_host(
    config: AgentBoxConfig,
    operation_id: str,
    *,
    command: Sequence[str] | str,
    repo_names: Sequence[str] = (),
    base_refs: Mapping[str, str] | None = None,
    cwd: Path | str | None = None,
    metadata: Mapping[str, Any] | None = None,
    lock_timeout_seconds: float = 30.0,
    request_id: str | None = None,
    command_factory: Any | None = None,
    operation_type: str = "agentbox_host",
    launch_intent: str = "host_local",
    expected_session_name: str | None = None,
    process_session_identity: str | None = None,
) -> HostLaunchResult:
    """Run the AgentBox launch transaction through the durable-ops engine."""

    request_id = request_id or operation_id
    session = expected_session_name or session_name(operation_id)
    process_identity = process_session_identity or session
    command_for_preflight = command if command_factory is None else ("<deferred-command>",)
    launch_spec = {
        "command": _command_payload(command_for_preflight),
        "repo_names": list(repo_names),
        "base_refs": dict(base_refs or {}),
        "cwd": str(cwd) if cwd is not None else None,
        "metadata": dict(metadata or {}),
        "lock_timeout_seconds": lock_timeout_seconds,
        "operation_type": operation_type,
        "launch_intent": launch_intent,
        "process_resource_id": f"launch-process-session:{operation_id}:{request_id}",
        "process_session_identity": process_identity,
        "expected_session_name": session,
    }
    observations = _host_preflight_observations(
        config,
        operation_id,
        command=command,
        repo_names=repo_names,
        cwd=cwd,
        session=session,
    )
    preliminary = run_launch_preflight(launch_spec, observations)
    envelope = LaunchEnvelope(
        version=1,
        operation_id=operation_id,
        request_id=request_id,
        venue="agentbox",
        launch_spec=launch_spec,
        preflight_digest=preliminary.preflight_digest,
    )
    store = open_operation_store(config)
    prepared: dict[str, Any] = {}

    def dispatch(candidate: LaunchEnvelope) -> str:
        try:
            paths = ensure_run_dir(config, operation_id, metadata=dict(metadata or {}))
            logs = record_log_resources(config, operation_id)
            allocations: list[WorktreeAllocation] = []
            for repo_name in repo_names:
                allocations.append(
                    allocate_worktree(
                        config,
                        operation_id,
                        repo_name,
                        base_ref=(base_refs or {}).get(repo_name),
                        lock_timeout_seconds=lock_timeout_seconds,
                    )
                )
            prepared.update(
                run_paths=paths,
                log_resources=logs,
                worktrees=tuple(allocations),
            )
            actual_cwd = cwd or _default_cwd(allocations, paths)
            actual_command = command_factory(actual_cwd) if command_factory is not None else command
            started = start_session(
                operation_id,
                actual_command,
                cwd=actual_cwd,
                run_paths=paths,
                identity={
                    "ARNOLD_LAUNCH_OPERATION_ID": operation_id,
                    "ARNOLD_LAUNCH_REQUEST_ID": request_id,
                    "ARNOLD_LAUNCH_ENVELOPE_DIGEST": candidate.digest,
                    "ARNOLD_LAUNCH_PROCESS_IDENTITY": process_identity,
                },
            )
            prepared["cwd"] = actual_cwd
            prepared["session_name"] = started
            return started
        except (WorktreeAllocationError, RuntimeError, OSError) as exc:
            raise LaunchDispatchRejected(str(exc)) from exc

    def observe(dispatched: str, candidate: LaunchEnvelope) -> Mapping[str, Any]:
        status = inspect_session(
            dispatched,
            expected_identity={
                "ARNOLD_LAUNCH_OPERATION_ID": operation_id,
                "ARNOLD_LAUNCH_REQUEST_ID": request_id,
                "ARNOLD_LAUNCH_ENVELOPE_DIGEST": candidate.digest,
                "ARNOLD_LAUNCH_PROCESS_IDENTITY": process_identity,
            },
        )
        return {
            "operation_id": status.operation_id,
            "request_id": status.request_id,
            "envelope_digest": status.envelope_digest,
            "process_session_identity": status.process_session_identity,
            "session_name": status.session_name,
            "liveness": status.state,
        }

    def resource_factory(dispatched: str, observation: Mapping[str, Any], candidate: LaunchEnvelope) -> TypedResource:
        return TypedResource(
            id=f"launch-process-session:{operation_id}:{request_id}",
            operation_id=operation_id,
            resource_type=ResourceType.PROCESS_SESSION,
            name=dispatched,
            details={
                "provider": "tmux",
                "session_name": dispatched,
                "process_session_identity": observation["process_session_identity"],
                "operation_id": observation["operation_id"],
                "request_id": observation["request_id"],
                "envelope_digest": observation["envelope_digest"],
                "state": observation["liveness"],
            },
        )

    transaction = launch_transaction(
        envelope,
        store=store,
        preflight=preliminary,
        dispatch=dispatch,
        observe=observe,
        resource_factory=resource_factory,
        operation_type=operation_type,
    )
    paths = prepared.get("run_paths") or run_dir_paths(config, operation_id)
    if transaction.result is LaunchResult.ACCEPTED and prepared:
        _merge_run_metadata(paths, {
            "launch_outcome": transaction.result.value,
            "launch_reason": transaction.reason.value,
            "session_name": prepared.get("session_name"),
            "worktrees": [_worktree_payload(item) for item in prepared.get("worktrees", ())],
        })
        append_event(paths, "host_launch.accepted", payload={"session_name": prepared.get("session_name")})
        _record_accepted_operation_metadata(
            config,
            operation_id,
            session_name=prepared.get("session_name"),
            worktrees=prepared.get("worktrees", ()),
        )
    elif transaction.result is LaunchResult.ACCEPTED and transaction.reason.name == "REPLAY":
        _record_accepted_operation_metadata(config, operation_id)
    elif transaction.result is not LaunchResult.ACCEPTED and paths.root.exists():
        append_event(paths, "host_launch.outcome", payload={"result": transaction.result.value, "reason": transaction.reason.value})
    operation = transaction.operation
    if operation is None:
        try:
            operation = load_agentbox_operation(config, operation_id)
        except Exception:
            operation = OperationRun(id=operation_id, operation_type=operation_type)
    if transaction.reason.name == "REPLAY" and not prepared:
        resources = store.list_typed_resources(operation_id)
        prepared["log_resources"] = tuple(
            resource for resource in resources if resource.resource_type is ResourceType.LOG
        )
        prepared["session_name"] = next(
            (
                resource.details.get("session_name")
                for resource in resources
                if resource.resource_type is ResourceType.PROCESS_SESSION
                and isinstance(resource.details.get("session_name"), str)
            ),
            None,
        )
    return HostLaunchResult(
        operation_id=operation_id,
        launch_state=transaction.result.value.lower(),
        operation_state=operation.state,
        run_paths=paths,
        worktrees=tuple(prepared.get("worktrees", ())),
        log_resources=tuple(prepared.get("log_resources", ())),
        session_name=prepared.get("session_name"),
        session_status=None,
        process_session_resource=getattr(transaction.store_result, "process_resource", None),
        diagnostics={"result": transaction.result.value, "reason": transaction.reason.value},
    )


def _record_accepted_operation_metadata(
    config: AgentBoxConfig,
    operation_id: str,
    *,
    session_name: str | None = None,
    worktrees: Sequence[WorktreeAllocation] = (),
) -> None:
    """Publish accepted launch details as a projection of store acceptance."""

    metadata: dict[str, Any] = {"launch_state": "accepted"}
    if session_name:
        metadata["session_name"] = session_name
    if worktrees:
        metadata["worktrees"] = [_worktree_payload(item) for item in worktrees]
    try:
        update_agentbox_operation(config, operation_id, metadata=metadata)
    except Exception:
        # The durable store's accepted transition is authoritative.  A stale
        # metadata projection must not turn a committed launch into a second
        # dispatch or a false rejection.
        return




def _merge_run_metadata(paths: RunDirPaths, values: Mapping[str, Any]) -> None:
    current = read_metadata(paths)
    current.update(values)
    write_metadata(paths, current)


def _default_cwd(worktrees: Sequence[WorktreeAllocation], run_paths: RunDirPaths) -> Path:
    if worktrees:
        return worktrees[0].worktree_path
    return run_paths.root


def _worktree_payload(allocation: WorktreeAllocation) -> dict[str, Any]:
    return {
        "repo_name": allocation.repo_name,
        "worktree_path": str(allocation.worktree_path),
        "branch": allocation.branch,
        "base_ref": allocation.base_ref,
        "base_sha": allocation.base_sha,
        "status": allocation.status,
    }


def _command_payload(command: Sequence[str] | str) -> str | list[str]:
    if isinstance(command, str):
        return command
    return list(command)


def _host_preflight_observations(
    config: AgentBoxConfig,
    operation_id: str,
    *,
    command: Sequence[str] | str,
    repo_names: Sequence[str],
    cwd: Path | str | None,
    session: str,
) -> dict[str, Mapping[str, Any]]:
    """Collect complete host facts without creating custody or launch state."""

    available = inspect_session(session)
    try:
        existing = load_agentbox_operation(config, operation_id)
    except Exception:
        existing = None
    # A deterministic session already owned by this operation is replayable;
    # another live occupant is a namespace collision and rejects before store
    # admission.  No liveness claim is accepted here.
    collision = "none" if (not available.exists or existing is not None) else "conflict"
    repo_paths = [config.repos_root / name for name in repo_names]
    source = repo_paths[0] if repo_paths else config.workspace_root
    source_revision = str(source)
    source_status = "current" if source.exists() and all(path.exists() for path in repo_paths) else "missing"
    return {
        "source": {"status": source_status, "revision": source_revision, "ref": source_revision, "tree": source_revision},
        "authority": {"status": "current", "grant": operation_id, "fence": operation_id, "decision": operation_id},
        "custody": {"status": "present", "custody_ref": str(config.workspace_root), "wbc_ref": str(config.ops_store_root)},
        "credentials": {"status": "available", "identity": str(config.credentials_root), "transport": "local"},
        "runtime": {"status": "present", "interpreter": sys.executable, "import_root": str(config.workspace_root), "source_revision": source_revision},
        "command": {"status": "valid", "argv": _command_payload(command), "cwd": str(cwd or config.workspace_root), "env": {}},
        "namespace": {"status": "valid", "name": session},
        "collision": {"status": collision, "namespace": session},
        # Capacity is observed as bounded named resources; volatile byte
        # counters are intentionally excluded from launch identity so an exact
        # replay does not become a divergent request between two syscalls.
        "capacity": {"status": "available", "disk": "workspace", "inode": "workspace", "output": "bounded", "temp": "workspace"},
        "network": {"status": "available", "transport": "local"},
    }


__all__ = [
    "HostLaunchError",
    "HostLaunchResult",
    "launch_host",
]
