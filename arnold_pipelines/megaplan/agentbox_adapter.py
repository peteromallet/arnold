"""AgentBox adapter for Megaplan chain operations."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import os
from pathlib import Path
from typing import Any, Mapping

from arnold.credentials.manifest import CredentialManifest
from arnold.runtime.durable_ops import (
    OperationNotFound,
    OperationState,
    ResourceType,
    can_transition_operation,
    is_terminal_operation_state,
)
from arnold_pipelines.megaplan.chain.spec import load_spec, validate_paths
from arnold_pipelines.megaplan.chain.status import (
    ChainStatusSnapshot,
    build_chain_status_snapshot,
)
from arnold_pipelines.megaplan.custody.process_adapter_wbc import (
    begin_process_adapter_attempt,
)
from arnold_pipelines.megaplan.discord_dm import send_discord_dm
from arnold_pipelines.megaplan.types import CliError

from agentbox.completion import format_completion_dm
from agentbox.config import AgentBoxConfig
from agentbox.credentials.backend import list_credentials
from agentbox.github import ci_status_for_branch as github_ci_status_for_branch
from agentbox.host import (
    HostLaunchError,
    HostLaunchResult,
    HostPreparedResources,
    prepare_host_resources,
    start_host_session,
    launch_host,
)
from agentbox.operations import (
    load_agentbox_operation,
    open_operation_store,
    record_operation_ci_status,
    record_operation_pr,
    update_agentbox_operation,
)
from agentbox.repos import get_repo
from agentbox.run_dirs import (
    RunDirPaths,
    append_event,
    read_metadata,
    run_dir_paths,
    write_metadata,
)
from agentbox.tmux import inspect_session, session_name as agentbox_session_name
from agentbox.worktrees import WorktreeAllocation, branch_name


MEGAPLAN_CHAIN_OPERATION_TYPE = "megaplan_chain"
LOGGER = logging.getLogger(__name__)


class MegaplanChainLaunchError(RuntimeError):
    """Raised after Megaplan chain launch diagnostics have been persisted."""

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
class MegaplanChainLaunchResult:
    """Result of preparing, validating, and starting a Megaplan chain."""

    host_result: HostLaunchResult
    resolved_spec_path: Path
    project_root: Path

    @property
    def operation_id(self) -> str:
        return self.host_result.operation_id

    @property
    def launch_state(self) -> str:
        return self.host_result.launch_state


class MegaplanChainHandler:
    """Launch Megaplan chains through AgentBox-owned durable resources."""

    operation_type = MEGAPLAN_CHAIN_OPERATION_TYPE

    def launch(
        self,
        config: AgentBoxConfig,
        operation_id: str,
        *,
        repo_name: str,
        spec_path: Path | str,
        base_ref: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        lock_timeout_seconds: float = 30.0,
    ) -> MegaplanChainLaunchResult:
        """Prepare AgentBox resources, validate the chain spec, then start tmux."""

        # The durable launch engine owns preflight, admission, exactly-one
        # dispatch, identity observation, and accepted-store transition.  The
        # adapter only validates the immutable request and supplies the command
        # factory for the physical AgentBox door.
        canonical_root = get_repo(config, repo_name).path.expanduser().resolve()
        resolved_canonical_spec = _resolve_spec_path(spec_path, canonical_root)
        try:
            spec = load_spec(resolved_canonical_spec)
            validate_paths(spec, canonical_root)
        except CliError as exc:
            raise MegaplanChainLaunchError(
                exc.code,
                exc.message,
                diagnostics=_validation_diagnostics(
                    kind=exc.code,
                    message=exc.message,
                    spec_path=resolved_canonical_spec,
                    project_root=canonical_root,
                    extra=exc.extra,
                ),
            ) from exc
        except Exception as exc:
            raise MegaplanChainLaunchError(
                "validation_failed",
                str(exc),
                diagnostics=_validation_diagnostics(
                    kind=type(exc).__name__,
                    message=str(exc),
                    spec_path=resolved_canonical_spec,
                    project_root=canonical_root,
                ),
            ) from exc
        manifest = _load_credential_manifest(resolved_canonical_spec)
        if manifest is not None:
            ok, message, fix_commands = _check_required_credentials(config, manifest)
            if not ok:
                raise MegaplanChainLaunchError(
                    "credential_preflight_failed",
                    message,
                    diagnostics=_credential_diagnostics(
                        message=message,
                        fix_commands=fix_commands,
                        manifest=manifest,
                    ),
                )
        launch_metadata = {
            "adapter": "megaplan_chain",
            "spec_path": str(spec_path),
            "resolved_spec_path_relative": str(Path(spec_path)),
            "validation": {
                "status": "passed",
                "spec_path": str(resolved_canonical_spec),
                "project_root": str(canonical_root),
            },
        }
        if metadata:
            launch_metadata.update(dict(metadata))
        relative_spec = Path(spec_path) if not Path(spec_path).is_absolute() else Path(spec_path).name
        host_result = launch_host(
            config,
            operation_id,
            command=("<deferred-command>",),
            repo_names=(repo_name,),
            base_refs={repo_name: base_ref} if base_ref else None,
            metadata=launch_metadata,
            lock_timeout_seconds=lock_timeout_seconds,
            operation_type=MEGAPLAN_CHAIN_OPERATION_TYPE,
            launch_intent="megaplan_chain",
            command_factory=lambda project_root: _chain_start_command(
                (project_root / relative_spec).resolve(), project_root
            ),
        )
        project_root = _primary_worktree(
            HostPreparedResources(
                operation_id=host_result.operation_id,
                run_paths=host_result.run_paths,
                requested_repo_names=(repo_name,),
                worktrees=host_result.worktrees,
                log_resources=host_result.log_resources,
            )
        ) if host_result.worktrees else canonical_root
        return MegaplanChainLaunchResult(
            host_result=host_result,
            resolved_spec_path=(project_root / relative_spec).resolve(),
            project_root=project_root,
        )

        existing = _load_existing_megaplan_operation(config, operation_id)
        if existing is not None:
            if is_terminal_operation_state(existing.state):
                message = (
                    f"operation {operation_id!r} is terminal "
                    f"({existing.state.value}) and cannot be relaunched"
                )
                diagnostics = {
                    "phase": "retry",
                    "kind": "terminal_operation",
                    "message": message,
                    "operation_state": existing.state.value,
                    "launch_state": existing.metadata.get("launch_state"),
                }
                _record_retry_refusal(config, operation_id, diagnostics)
                raise MegaplanChainLaunchError(
                    "terminal_operation",
                    message,
                    diagnostics=diagnostics,
                )
            running_result = _summarize_live_running_session(config, existing)
            if running_result is not None:
                if metadata:
                    update_agentbox_operation(
                        config,
                        operation_id,
                        metadata=metadata,
                        expected_lock_version=existing.lock_version,
                    )
                return MegaplanChainLaunchResult(
                    host_result=running_result,
                    resolved_spec_path=_resolved_spec_from_metadata(existing.metadata),
                    project_root=_project_root_from_metadata(existing.metadata),
                )

        launch_metadata = {
            "adapter": "megaplan_chain",
            "spec_path": str(spec_path),
        }
        if metadata:
            launch_metadata.update(dict(metadata))
        prepared = prepare_host_resources(
            config,
            operation_id,
            operation_type=MEGAPLAN_CHAIN_OPERATION_TYPE,
            command=_prevalidation_command(spec_path),
            repo_names=(repo_name,),
            base_refs={repo_name: base_ref} if base_ref else None,
            launch_intent="megaplan_chain",
            metadata=launch_metadata,
            lock_timeout_seconds=lock_timeout_seconds,
        )
        project_root = _primary_worktree(prepared)
        resolved_spec_path = _resolve_spec_path(spec_path, project_root)
        wbc_attempt = _begin_agentbox_process_attempt(
            prepared.run_paths,
            surface="launch",
            details={
                "operation_id": operation_id,
                "repo_name": repo_name,
                "spec_path": str(resolved_spec_path),
                "project_root": str(project_root),
            },
        )

        manifest = _load_credential_manifest(resolved_spec_path)
        if manifest is not None:
            ok, message, fix_commands = _check_required_credentials(config, manifest)
            if not ok:
                diagnostics = _credential_diagnostics(
                    message=message,
                    fix_commands=fix_commands,
                    manifest=manifest,
                )
                _record_credential_failure(
                    config, operation_id, prepared.run_paths, diagnostics
                )
                wbc_attempt.terminal(
                    status="failed_before_dispatch",
                    outcome="blocked",
                    details={
                        "phase": "credential_preflight",
                        "diagnostics": dict(diagnostics),
                    },
                )
                raise MegaplanChainLaunchError(
                    "credential_preflight_failed",
                    message,
                    diagnostics=diagnostics,
                ) from None

        try:
            spec = load_spec(resolved_spec_path)
            validate_paths(spec, project_root)
        except CliError as exc:
            diagnostics = _validation_diagnostics(
                kind=exc.code,
                message=exc.message,
                spec_path=resolved_spec_path,
                project_root=project_root,
                extra=exc.extra,
            )
            _record_validation_failure(
                config, operation_id, prepared.run_paths, diagnostics
            )
            wbc_attempt.terminal(
                status="failed_before_dispatch",
                outcome="blocked",
                details={"phase": "validation", "diagnostics": dict(diagnostics)},
            )
            raise MegaplanChainLaunchError(
                exc.code, exc.message, diagnostics=diagnostics
            ) from exc
        except Exception as exc:
            diagnostics = _validation_diagnostics(
                kind=type(exc).__name__,
                message=str(exc),
                spec_path=resolved_spec_path,
                project_root=project_root,
            )
            _record_validation_failure(
                config, operation_id, prepared.run_paths, diagnostics
            )
            wbc_attempt.terminal(
                status="failed_before_dispatch",
                outcome="blocked",
                details={"phase": "validation", "diagnostics": dict(diagnostics)},
            )
            raise MegaplanChainLaunchError(
                "validation_failed", str(exc), diagnostics=diagnostics
            ) from exc

        managed_session = agentbox_session_name(operation_id)
        command = _chain_start_command(
            resolved_spec_path,
            project_root,
            session=managed_session,
        )
        validation = {
            "status": "passed",
            "spec_path": str(resolved_spec_path),
            "project_root": str(project_root),
        }
        update_agentbox_operation(
            config,
            operation_id,
            metadata={
                "command": list(command),
                "resolved_spec_path": str(resolved_spec_path),
                "project_root": str(project_root),
                "validation": validation,
            },
            launch_state="accepted",
        )
        _merge_run_metadata(
            prepared.run_paths,
            {
                "command": list(command),
                "resolved_spec_path": str(resolved_spec_path),
                "project_root": str(project_root),
                "validation": validation,
            },
        )
        append_event(
            prepared.run_paths,
            "megaplan_chain.validation_passed",
            payload={
                "spec_path": str(resolved_spec_path),
                "project_root": str(project_root),
            },
        )
        wbc_attempt.effect(
            "validation_passed",
            details={
                "command": list(command),
                "resolved_spec_path": str(resolved_spec_path),
                "project_root": str(project_root),
            },
        )
        try:
            host_result = start_host_session(
                config,
                prepared,
                command=command,
                cwd=project_root,
            )
        except HostLaunchError as exc:
            wbc_attempt.terminal(
                status="failed",
                outcome="indeterminate",
                details={
                    "phase": "host_launch",
                    "kind": exc.kind,
                    "diagnostics": dict(exc.diagnostics),
                },
            )
            raise MegaplanChainLaunchError(
                exc.kind,
                str(exc),
                diagnostics=exc.diagnostics,
            ) from exc
        wbc_attempt.effect(
            "session_started",
            details={
                "session_name": host_result.session_name,
                "launch_state": host_result.launch_state,
            },
        )
        wbc_attempt.terminal(
            status="running",
            outcome="started",
            details={
                "session_name": host_result.session_name,
                "launch_state": host_result.launch_state,
            },
        )
        return MegaplanChainLaunchResult(
            host_result=host_result,
            resolved_spec_path=resolved_spec_path,
            project_root=project_root,
        )

    def status(self, config: AgentBoxConfig, operation_id: str) -> ChainStatusSnapshot:
        """Return a provider-independent chain status snapshot."""

        run = load_agentbox_operation(
            config,
            operation_id,
            operation_types=(MEGAPLAN_CHAIN_OPERATION_TYPE,),
        )
        resources = open_operation_store(config).list_typed_resources(operation_id)
        return build_chain_status_snapshot(
            run,
            resources=resources,
            inspect_runner=inspect_session,
        )

    def tick(self, config: AgentBoxConfig, operation_id: str) -> Any:
        """Refresh persisted operation state from the chain classifier."""

        snapshot = self.status(config, operation_id)
        wbc_attempt = _begin_agentbox_process_attempt(
            run_dir_paths(config, operation_id),
            surface="tick",
            details={"operation_id": operation_id},
        )
        classification = snapshot.classification
        current = load_agentbox_operation(
            config,
            operation_id,
            operation_types=(MEGAPLAN_CHAIN_OPERATION_TYPE,),
        )
        previous = _classification_metadata(current.metadata)
        current_summary = classification.to_dict()
        metadata = {
            "chain_status": current_summary,
            "chain_status_snapshot": {
                "effective_status": classification.effective_status,
                "reason": classification.reason,
                "runner": snapshot.runner,
                "plan_status": snapshot.plan_status,
            },
        }
        target_state = classification.operation_state
        update_state: OperationState | None = None
        if target_state is not current.state and can_transition_operation(
            current.state, target_state
        ):
            update_state = target_state
        updated = update_agentbox_operation(
            config,
            operation_id,
            metadata=metadata,
            state=update_state,
        )
        if previous != current_summary:
            paths = run_dir_paths(config, operation_id)
            append_event(
                paths,
                "megaplan_chain.status_changed",
                payload={
                    "previous": previous,
                    "current": current_summary,
                    "persisted_operation_state": updated.state.value,
                },
            )
        _record_pr_and_ci(config, operation_id, updated, snapshot)
        if (
            is_terminal_operation_state(updated.state)
            and "completion_dm" not in updated.metadata
        ):
            refreshed = load_agentbox_operation(
                config,
                operation_id,
                operation_types=(MEGAPLAN_CHAIN_OPERATION_TYPE,),
            )
            _record_completion_dm(config, operation_id, refreshed)
        wbc_attempt.terminal(
            status=updated.state.value,
            outcome="succeeded",
            details={
                "effective_status": classification.effective_status,
                "reason": classification.reason,
            },
        )
        return updated

    def resume(self, config: AgentBoxConfig, operation_id: str) -> Any:
        """Report custody only; replay/reconcile never redispatches a process."""

        raise MegaplanChainLaunchError(
            "resume_not_allowed",
            f"operation {operation_id!r} cannot be redispatched by replay or reconciliation",
            diagnostics={"phase": "resume", "kind": "redispatch_forbidden"},
        )

        snapshot = self.status(config, operation_id)
        classification = snapshot.classification
        if (
            classification.operation_state is OperationState.PENDING
            and snapshot.launch_state == "rejected"
        ):
            message = (
                f"operation {operation_id!r} failed before the chain runner started; "
                "retry the launch with `agentbox run --operation-id`"
            )
            diagnostics = {
                "phase": "resume",
                "kind": "pre_running_retry_required",
                "message": message,
                "launch_state": snapshot.launch_state,
            }
            _record_resume_refusal(config, operation_id, diagnostics)
            raise MegaplanChainLaunchError(
                "pre_running_retry_required",
                message,
                diagnostics=diagnostics,
            )

        if not _is_stale_runner_resume(snapshot):
            message = (
                f"operation {operation_id!r} is {classification.effective_status!r} "
                f"({classification.reason}) and is not a stale runner resume candidate"
            )
            diagnostics = {
                "phase": "resume",
                "kind": "resume_not_allowed",
                "message": message,
                "classification": classification.to_dict(),
                "runner": snapshot.runner,
            }
            _record_resume_refusal(config, operation_id, diagnostics)
            raise MegaplanChainLaunchError(
                "resume_not_allowed", message, diagnostics=diagnostics
            )

        run = load_agentbox_operation(
            config,
            operation_id,
            operation_types=(MEGAPLAN_CHAIN_OPERATION_TYPE,),
        )
        resources = open_operation_store(config).list_typed_resources(operation_id)
        # Validate the persisted shape before migrating it. Resume always
        # rebuilds the owner route from authoritative operation metadata so a
        # legacy command cannot bypass lease publication and a stale process
        # incarnation cannot be inherited by the replacement.
        _stored_chain_command(run.metadata)
        resolved_spec_path = _resolved_spec_from_metadata(run.metadata)
        managed_session = agentbox_session_name(operation_id)
        command = _chain_start_command(
            resolved_spec_path,
            snapshot.project_root,
            session=managed_session,
        )
        update_agentbox_operation(
            config,
            operation_id,
            metadata={"command": list(command)},
        )
        prepared = HostPreparedResources(
            operation_id=operation_id,
            run_paths=run_dir_paths(config, operation_id),
            requested_repo_names=tuple(
                str(name) for name in run.metadata.get("repo_names", ())
            ),
            worktrees=_worktrees_from_resources(config, operation_id, list(resources)),
            log_resources=tuple(
                resource
                for resource in resources
                if resource.resource_type is ResourceType.LOG
            ),
        )
        wbc_attempt = _begin_agentbox_process_attempt(
            prepared.run_paths,
            surface="resume",
            details={
                "operation_id": operation_id,
                "project_root": str(snapshot.project_root),
                "reason": classification.reason,
            },
        )
        try:
            result = start_host_session(
                config,
                prepared,
                command=command,
                cwd=snapshot.project_root,
            )
        except HostLaunchError as exc:
            wbc_attempt.terminal(
                status="failed",
                outcome="indeterminate",
                details={
                    "phase": "host_launch",
                    "kind": exc.kind,
                    "diagnostics": dict(exc.diagnostics),
                },
            )
            raise MegaplanChainLaunchError(
                exc.kind,
                str(exc),
                diagnostics=exc.diagnostics,
            ) from exc
        append_event(
            result.run_paths,
            "megaplan_chain.resumed",
            payload={
                "reason": classification.reason,
                "runner": snapshot.runner,
                "session_name": result.session_name,
            },
        )
        wbc_attempt.effect(
            "session_started",
            details={"session_name": result.session_name},
        )
        wbc_attempt.terminal(
            status="running",
            outcome="started",
            details={"session_name": result.session_name},
        )
        return load_agentbox_operation(
            config,
            operation_id,
            operation_types=(MEGAPLAN_CHAIN_OPERATION_TYPE,),
        )

    def summarize(self, config: AgentBoxConfig, operation_id: str) -> str:
        """Return compact CLI-oriented status text for a chain operation."""

        snapshot = self.status(config, operation_id)
        classification = snapshot.classification
        parts = [
            f"{snapshot.operation_id}: {classification.effective_status}",
            f"state={classification.operation_state.value}",
            f"reason={classification.reason}",
        ]
        current_plan = snapshot.chain_state.get("current_plan_name")
        if current_plan:
            parts.append(f"plan={current_plan}")
        runner_status = snapshot.runner.get("status")
        if runner_status:
            parts.append(f"runner={runner_status}")
        if snapshot.spec_path is not None:
            parts.append(f"spec={snapshot.spec_path}")
        return " ".join(parts)

    def cleanup_descriptor(
        self, config: AgentBoxConfig, operation_id: str
    ) -> dict[str, Any]:
        """Describe operation-owned resources without deleting anything."""

        run = load_agentbox_operation(
            config,
            operation_id,
            operation_types=(MEGAPLAN_CHAIN_OPERATION_TYPE,),
        )
        resources = open_operation_store(config).list_typed_resources(operation_id)
        paths = run_dir_paths(config, operation_id)
        return {
            "operation_id": operation_id,
            "operation_type": run.operation_type,
            "operation_state": run.state.value,
            "non_destructive": True,
            "run_dir": str(paths.root),
            "paths": {
                "events": str(paths.events_path),
                "metadata": str(paths.metadata_path),
                "stdout": str(paths.stdout_path),
                "stderr": str(paths.stderr_path),
            },
            "resources": [
                {
                    "id": resource.id,
                    "type": resource.resource_type.value,
                    "name": resource.name,
                    "details": dict(resource.details),
                }
                for resource in resources
            ],
        }


def get_agentbox_adapter() -> MegaplanChainHandler:
    """Factory used by the lazy AgentBox adapter registry."""

    return MegaplanChainHandler()


def _prevalidation_command(spec_path: Path | str) -> list[str]:
    return [
        "python",
        "-m",
        "arnold_pipelines.megaplan",
        "chain",
        "start",
        "--spec",
        str(spec_path),
    ]


def _chain_start_command(
    spec_path: Path,
    project_root: Path,
    *,
    session: str | None = None,
) -> tuple[str, ...]:
    return (
        "python",
        "-m",
        "arnold_pipelines.megaplan",
        "chain",
        "start",
        "--spec",
        str(spec_path),
        "--project-dir",
        str(project_root),
    )


def _primary_worktree(prepared: HostPreparedResources) -> Path:
    if not prepared.worktrees:
        raise MegaplanChainLaunchError(
            "missing_worktree",
            "megaplan_chain launch requires at least one prepared worktree",
            diagnostics={"phase": "prepare", "kind": "missing_worktree"},
        )
    return prepared.worktrees[0].worktree_path.expanduser().resolve()


def _resolve_spec_path(spec_path: Path | str, project_root: Path) -> Path:
    path = Path(spec_path).expanduser()
    if not path.is_absolute():
        path = project_root / path
    return path.resolve()


def _validation_diagnostics(
    *,
    kind: str,
    message: str,
    spec_path: Path,
    project_root: Path,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    diagnostics = {
        "phase": "validation",
        "kind": kind,
        "message": message,
        "spec_path": str(spec_path),
        "project_root": str(project_root),
    }
    if extra:
        diagnostics["extra"] = dict(extra)
    return diagnostics


def _record_validation_failure(
    config: AgentBoxConfig,
    operation_id: str,
    run_paths: RunDirPaths,
    diagnostics: Mapping[str, Any],
) -> None:
    validation = {"status": "failed", **dict(diagnostics)}
    update_agentbox_operation(
        config,
        operation_id,
        metadata={"launch_diagnostics": dict(diagnostics), "validation": validation},
        launch_state="rejected",
    )
    _merge_run_metadata(
        run_paths,
        {
            "launch_outcome": "REJECTED",
            "launch_diagnostics": dict(diagnostics),
            "validation": validation,
        },
    )
    append_event(
        run_paths, "megaplan_chain.validation_failed", payload=dict(diagnostics)
    )


def _load_existing_megaplan_operation(
    config: AgentBoxConfig, operation_id: str
) -> Any | None:
    try:
        return load_agentbox_operation(
            config,
            operation_id,
            operation_types=(MEGAPLAN_CHAIN_OPERATION_TYPE,),
        )
    except OperationNotFound:
        return None


def _record_retry_refusal(
    config: AgentBoxConfig,
    operation_id: str,
    diagnostics: Mapping[str, Any],
) -> None:
    paths = run_dir_paths(config, operation_id)
    if paths.root.exists():
        _merge_run_metadata(paths, {"retry_refusal": dict(diagnostics)})
        append_event(paths, "megaplan_chain.retry_refused", payload=dict(diagnostics))


def _record_resume_refusal(
    config: AgentBoxConfig,
    operation_id: str,
    diagnostics: Mapping[str, Any],
) -> None:
    paths = run_dir_paths(config, operation_id)
    if paths.root.exists():
        _merge_run_metadata(paths, {"resume_refusal": dict(diagnostics)})
        append_event(paths, "megaplan_chain.resume_refused", payload=dict(diagnostics))


def _summarize_live_running_session(
    config: AgentBoxConfig, run: Any
) -> HostLaunchResult | None:
    if run.state is not OperationState.RUNNING:
        return None
    resources = open_operation_store(config).list_typed_resources(run.id)
    process_resources = [
        resource
        for resource in resources
        if resource.resource_type is ResourceType.PROCESS_SESSION
    ]
    session_name = _session_name_from_run(run.metadata, process_resources)
    if not session_name:
        return None
    status = inspect_session(session_name)
    if not status.exists or status.state != "running":
        return None

    run_paths = run_dir_paths(config, run.id)
    payload = {"session_name": session_name, "session_state": status.state}
    append_event(run_paths, "megaplan_chain.replay_observed", payload=payload)
    _merge_run_metadata(run_paths, {"duplicate_launch": payload})
    return HostLaunchResult(
        operation_id=run.id,
        launch_state="accepted",
        operation_state=run.state,
        run_paths=run_paths,
        worktrees=_worktrees_from_resources(config, run.id, resources),
        log_resources=tuple(
            resource
            for resource in resources
            if resource.resource_type is ResourceType.LOG
        ),
        session_name=session_name,
        session_status=status,
        process_session_resource=process_resources[0] if process_resources else None,
        diagnostics={
            "phase": "retry",
            "kind": "replay_observed",
            "message": f"operation {run.id!r} already has an accepted session",
            "session_name": session_name,
        },
    )


def _session_name_from_run(
    metadata: Mapping[str, Any], process_resources: list[Any]
) -> str | None:
    value = metadata.get("session_name")
    if isinstance(value, str) and value:
        return value
    for resource in process_resources:
        value = resource.details.get("session_name")
        if isinstance(value, str) and value:
            return value
    return None


def _worktrees_from_resources(
    config: AgentBoxConfig,
    operation_id: str,
    resources: list[Any],
) -> tuple[WorktreeAllocation, ...]:
    worktrees: list[WorktreeAllocation] = []
    for resource in resources:
        if resource.resource_type is not ResourceType.GIT_WORKTREE:
            continue
        repo_name = str(resource.details["repo_name"])
        repo = get_repo(config, repo_name)
        worktrees.append(
            WorktreeAllocation(
                operation_id=operation_id,
                repo_name=repo_name,
                canonical_repo_path=Path(str(resource.details["canonical_repo_path"])),
                worktree_path=Path(str(resource.details["worktree_path"])),
                branch=str(resource.details["branch"]),
                base_ref=str(resource.details["base_ref"]),
                base_sha=str(resource.details["base_sha"]),
                status=str(resource.details["status"]),
                resource=resource,
                worktree=None,
            )
        )
        if worktrees[-1].canonical_repo_path != repo.path:
            raise MegaplanChainLaunchError(
                "git_worktree_resource_conflict",
                f"existing git worktree resource does not match registered repo {repo_name!r}",
                diagnostics={
                    "phase": "retry",
                    "kind": "git_worktree_resource_conflict",
                    "repo_name": repo_name,
                },
            )
    return tuple(worktrees)


def _resolved_spec_from_metadata(metadata: Mapping[str, Any]) -> Path:
    value = metadata.get("resolved_spec_path") or metadata.get("spec_path")
    if not isinstance(value, str) or not value:
        raise MegaplanChainLaunchError(
            "missing_resolved_spec_path",
            "running megaplan_chain operation is missing resolved spec path metadata",
            diagnostics={"phase": "retry", "kind": "missing_resolved_spec_path"},
        )
    return Path(value)


def _project_root_from_metadata(metadata: Mapping[str, Any]) -> Path:
    value = metadata.get("project_root")
    if not isinstance(value, str) or not value:
        raise MegaplanChainLaunchError(
            "missing_project_root",
            "running megaplan_chain operation is missing project root metadata",
            diagnostics={"phase": "retry", "kind": "missing_project_root"},
        )
    return Path(value)


def _classification_metadata(metadata: Mapping[str, Any]) -> dict[str, Any] | None:
    value = metadata.get("chain_status")
    return dict(value) if isinstance(value, Mapping) else None


def _is_stale_runner_resume(snapshot: ChainStatusSnapshot) -> bool:
    classification = snapshot.classification
    return (
        classification.operation_state is OperationState.SUSPENDED
        and classification.effective_status == "stale_bookkeeping"
        and classification.reason
        in {
            "active_plan_without_live_runner",
            "running_operation_without_live_runner",
            "human_verification_satisfied_runner_inactive",
        }
        and snapshot.runner.get("status")
        in {"dead", "missing", "unknown", "unavailable"}
    )


def _stored_chain_command(metadata: Mapping[str, Any]) -> tuple[str, ...]:
    command = metadata.get("command")
    if isinstance(command, list) and all(isinstance(part, str) for part in command):
        parts = tuple(command)
        python_at = 0
        if parts and parts[0] == "env":
            required_prefixes = (
                "ARNOLD_LAUNCH_OPERATION_ID=",
                "ARNOLD_LAUNCH_REQUEST_ID=",
                "ARNOLD_LAUNCH_ENVELOPE_DIGEST=",
                "ARNOLD_LAUNCH_PROCESS_IDENTITY=",
            )
            env_values = parts[1:6]
            if len(env_values) != len(required_prefixes) or any(
                not value.startswith(prefix)
                for value, prefix in zip(env_values, required_prefixes, strict=True)
            ):
                parts = ()
            python_at = 6
        if parts[python_at : python_at + 4] == (
            "python",
            "-m",
            "arnold_pipelines.megaplan",
            "chain",
        ):
            return tuple(command)

    message = "megaplan_chain operation is missing a stored chain command"
    raise MegaplanChainLaunchError(
        "missing_stored_chain_command",
        message,
        diagnostics={"phase": "resume", "kind": "missing_stored_chain_command"},
    )


def _begin_agentbox_process_attempt(
    run_paths: RunDirPaths,
    *,
    surface: str,
    details: Mapping[str, Any] | None = None,
):
    return begin_process_adapter_attempt(
        run_paths.root,
        producer_family="agentbox_adapter",
        adapter_name="megaplan_chain",
        surface=surface,
        start_details=details,
    )


def _merge_run_metadata(paths: RunDirPaths, values: Mapping[str, Any]) -> None:
    current = read_metadata(paths)
    current.update(values)
    write_metadata(paths, current)


def _load_credential_manifest(spec_path: Path) -> CredentialManifest | None:
    path = spec_path.parent / "credentials.yaml"
    if not path.exists():
        return None
    return CredentialManifest.from_path(path)


def _check_required_credentials(
    config: AgentBoxConfig,
    manifest: CredentialManifest,
    environ: Mapping[str, str] | None = None,
) -> tuple[bool, str, list[str]]:
    records = {
        record.name: record for record in list_credentials(config, environ=environ)
    }
    missing: list[str] = []
    stale: list[str] = []

    for requirement in manifest.credentials:
        if not requirement.required:
            continue
        record = records.get(requirement.name)
        if record is None or not record.present:
            missing.append(requirement.name)
            continue
        if record.test_status != "passed":
            stale.append(requirement.name)

    if not missing and not stale:
        return True, "", []

    fix_commands: list[str] = []
    for name in missing:
        fix_commands.append(f"agentbox creds push {name}")
    for name in stale:
        fix_commands.append(f"agentbox creds test {name}")

    parts: list[str] = []
    if missing:
        parts.append(f"missing: {', '.join(missing)}")
    if stale:
        parts.append(f"stale: {', '.join(stale)}")
    message = f"Required credentials are {', '.join(parts)}. Fix with: {'; '.join(fix_commands)}"
    return False, message, fix_commands


def _credential_diagnostics(
    *,
    message: str,
    fix_commands: list[str],
    manifest: CredentialManifest,
) -> dict[str, Any]:
    return {
        "phase": "credential_preflight",
        "kind": "credential_preflight_failed",
        "message": message,
        "fix_commands": fix_commands,
        "required_credentials": [
            {"name": req.name, "provider": req.provider, "required": req.required}
            for req in manifest.credentials
        ],
    }


def _agentbox_delivery_gate_check():
    """Build the explicit current delivery gate for AgentBox notifications.

    Discord delivery is only possible with a configured bot token; without
    one, the durable owner must deny before any provider contact.  The
    predicate is re-read on every delivery, so the verdict tracks the
    current process configuration.
    """

    from arnold_pipelines.megaplan.resident.delivery_effects import (
        current_delivery_gate_check,
    )

    return current_delivery_gate_check(
        lambda: bool(str(os.environ.get("DISCORD_BOT_TOKEN") or "").strip())
    )


def _record_completion_dm(config: AgentBoxConfig, operation_id: str, run: Any) -> None:
    paths = run_dir_paths(config, operation_id)
    dm = _build_completion_dm(run)
    update_agentbox_operation(config, operation_id, metadata={"completion_dm": dm})
    append_event(
        paths, "megaplan_chain.completion_dm_ready", payload={"completion_dm": dm}
    )
    # Completion ticks are autonomous operational notifications.  They must
    # share the resident's durable effect owner so a concurrent tick or a
    # restarted AgentBox process adopts the accepted outcome instead of
    # contacting Discord again.
    delivery_effects = None
    try:
        from arnold_pipelines.megaplan.resident.delivery_effects import (
            open_resident_delivery_effects,
        )

        configured_root = str(
            os.environ.get("MEGAPLAN_RESIDENT_STORE_ROOT") or ""
        ).strip()
        resident_root = (
            Path(configured_root).expanduser().resolve()
            if configured_root
            else config.workspace_root / "resident_store"
        )
        delivery_effects = open_resident_delivery_effects(
            resident_root / "delivery_effects",
            production_enabled=True,
            action_gate_check=_agentbox_delivery_gate_check(),
        )
        result = _send_completion_dm(
            run,
            fallback_text=dm,
            delivery_effects=delivery_effects,
        )
        append_event(
            paths,
            "megaplan_chain.completion_dm_delivery",
            payload={
                "ok": bool(result.get("ok")),
                "reason": result.get("reason"),
                "outcome_kind": result.get("outcome_kind"),
                "glek": result.get("glek"),
            },
        )
    except Exception as exc:
        # Fail closed: absence/corruption of the sole durable owner never
        # falls through to the direct Discord transport.
        LOGGER.warning(
            "Completion Discord DM has no usable durable effect owner for operation %s",
            run.id,
            exc_info=True,
        )
        append_event(
            paths,
            "megaplan_chain.completion_dm_delivery",
            payload={
                "ok": False,
                "reason": "durable_delivery_owner_unavailable",
                "error": f"{type(exc).__name__}: {exc}",
            },
        )
    finally:
        if delivery_effects is not None:
            delivery_effects.close()


def _build_completion_dm(run: Any) -> str:
    repo_names = run.metadata.get("repo_names") or []
    first_repo = repo_names[0] if repo_names else None
    branch = branch_name(run.id, first_repo) if first_repo else None
    pr_info = (run.metadata.get("pr_info") or {}).get(first_repo) or {}
    ci_status = (run.metadata.get("ci_status") or {}).get(first_repo)
    operation_status = {
        "operation_id": run.id,
        "operation_state": run.state.value,
        "branch": branch,
        "pr_number": pr_info.get("number"),
        "pr_url": pr_info.get("url"),
        "ci_status": ci_status,
    }
    branch_status = {
        "branch": branch,
        "pr_number": pr_info.get("number"),
        "pr_url": pr_info.get("url"),
        "ci_status": ci_status,
    }
    return format_completion_dm(
        operation_status,
        validation=run.metadata.get("validation"),
        branch_status=branch_status,
        next_action="Run `agentbox cleanup survey` to review branch/PR cleanup options.",
    )


def _send_completion_dm(
    run: Any,
    *,
    fallback_text: str,
    delivery_effects: Any | None = None,
) -> dict[str, Any]:
    """Send an autonomous completion DM through the sole durable owner."""
    if delivery_effects is None:
        raise RuntimeError(
            "AgentBox completion DM has no durable DeliveryEffects owner"
        )
    try:
        payload = _build_completion_dm_payload(run, fallback_text=fallback_text)
        payload["idempotency_key"] = (
            f"agentbox-completion:{run.id}:{run.state.value}"
        )
        return send_discord_dm(payload, delivery_effects=delivery_effects)
    except Exception as exc:
        LOGGER.warning(
            "Completion Discord DM send crashed for operation %s", run.id, exc_info=True
        )
        return {
            "ok": False,
            "reason": "delivery_adapter_indeterminate",
            "outcome_kind": "INDETERMINATE",
            "error": f"{type(exc).__name__}: {exc}",
            "message_count": 0,
        }


def _build_completion_dm_payload(run: Any, *, fallback_text: str) -> dict[str, Any]:
    repo_names = run.metadata.get("repo_names") or []
    first_repo = repo_names[0] if repo_names else None
    branch = branch_name(run.id, first_repo) if first_repo else None
    pr_info = (run.metadata.get("pr_info") or {}).get(first_repo) or {}
    ci_status = (run.metadata.get("ci_status") or {}).get(first_repo)
    validation = run.metadata.get("validation") or {}

    fields: list[dict[str, Any]] = [
        {"label": "Operation", "value": run.id, "style": "code"},
        {"label": "State", "value": run.state.value, "style": "code"},
    ]
    if validation:
        fields.append(
            {
                "label": "Validation",
                "value": validation.get("status", "unknown"),
                "style": "code",
            }
        )
    if branch:
        fields.append({"label": "Branch", "value": branch, "style": "code"})
    if pr_info.get("number") is not None:
        fields.append({"label": "PR", "value": str(pr_info["number"]), "style": "code"})
    if ci_status:
        fields.append({"label": "CI", "value": ci_status, "style": "code"})

    links: list[dict[str, str]] = []
    pr_url = pr_info.get("url")
    if isinstance(pr_url, str) and pr_url:
        links.append({"label": "PR", "url": pr_url})

    return {
        "title": f"Megaplan chain complete - {run.id}",
        "summary": fallback_text.splitlines()[0] if fallback_text else "",
        "fields": fields,
        "links": links,
        "next_action": "Run `agentbox cleanup survey` to review branch/PR cleanup options.",
    }


def _build_reconcile_pr_ready_dm(
    *,
    chain_label: str,
    pr_number: int,
    pr_url: str,
    branch: str,
) -> str:
    """Plain-text summary for the reconcile-pr-ready DM."""
    url = pr_url if isinstance(pr_url, str) and pr_url else f"PR #{pr_number}"
    return (
        f"Reconcile PR #{pr_number} for megaplan chain `{chain_label}` is ready "
        f"for human review.\n"
        f"Branch: `{branch}`\n"
        f"{url}"
    )


def _build_reconcile_pr_ready_payload(
    *,
    chain_label: str,
    pr_number: int,
    pr_url: str,
    branch: str,
) -> dict[str, Any]:
    """Structured Discord payload for the reconcile-pr-ready DM."""
    fields: list[dict[str, Any]] = [
        {"label": "Chain", "value": chain_label, "style": "code"},
        {"label": "Branch", "value": branch, "style": "code"},
        {"label": "PR", "value": str(pr_number), "style": "code"},
    ]
    links: list[dict[str, str]] = []
    if isinstance(pr_url, str) and pr_url:
        links.append({"label": "Review PR", "url": pr_url})
    return {
        "title": f"Reconcile PR ready - {chain_label}",
        "summary": (
            f"End-of-epic reconcile milestone `{chain_label}` opened PR "
            f"#{pr_number} for human review on branch `{branch}`."
        ),
        "fields": fields,
        "links": links,
        "next_action": (
            "Review and merge or close the reconcile PR; the chain parks at "
            "awaiting_pr_merge until the PR is merged or intentionally closed."
        ),
    }


def _send_reconcile_pr_ready_dm(
    *,
    chain_label: str,
    pr_number: int,
    pr_url: str,
    branch: str,
    fallback_text: str,
    delivery_effects: Any | None = None,
) -> dict[str, Any]:
    """Send the reconcile-pr-ready DM through the sole durable owner."""
    if delivery_effects is None:
        raise RuntimeError(
            "AgentBox reconcile PR DM has no durable DeliveryEffects owner"
        )
    try:
        payload = _build_reconcile_pr_ready_payload(
            chain_label=chain_label,
            pr_number=pr_number,
            pr_url=pr_url,
            branch=branch,
        )
        payload["idempotency_key"] = f"reconcile-pr:{chain_label}:{pr_number}"
        return send_discord_dm(payload, delivery_effects=delivery_effects)
    except Exception as exc:
        LOGGER.warning(
            "Reconcile PR ready DM send crashed for %s PR #%s",
            chain_label,
            pr_number,
            exc_info=True,
        )
        return {
            "ok": False,
            "reason": "delivery_adapter_indeterminate",
            "outcome_kind": "INDETERMINATE",
            "error": f"{type(exc).__name__}: {exc}",
            "message_count": 0,
        }


def record_reconcile_pr_ready_dm(
    config: AgentBoxConfig,
    operation_id: str,
    *,
    chain_label: str,
    pr_number: int,
    pr_url: str,
    branch: str,
) -> dict[str, Any]:
    """Send the reconcile-pr-ready operator DM once per (chain, PR).

    Mirrors the completion-DM delivery contract (:func:`_record_completion_dm`):
    the message is routed through the resident's durable delivery-effects owner
    (never direct Discord), keyed by ``reconcile-pr:<chain>:<pr_number>`` for
    idempotent redelivery, and the attempt is recorded in the operation run
    directory.
    """
    paths = run_dir_paths(config, operation_id)
    dm = _build_reconcile_pr_ready_dm(
        chain_label=chain_label,
        pr_number=pr_number,
        pr_url=pr_url,
        branch=branch,
    )
    update_agentbox_operation(
        config,
        operation_id,
        metadata={"reconcile_pr_ready_dm": dm},
    )
    append_event(
        paths,
        "megaplan_chain.reconcile_pr_ready",
        payload={
            "chain_label": chain_label,
            "pr_number": pr_number,
            "pr_url": pr_url,
            "branch": branch,
            "dm": dm,
        },
    )
    delivery_effects = None
    try:
        from arnold_pipelines.megaplan.resident.delivery_effects import (
            open_resident_delivery_effects,
        )

        configured_root = str(
            os.environ.get("MEGAPLAN_RESIDENT_STORE_ROOT") or ""
        ).strip()
        resident_root = (
            Path(configured_root).expanduser().resolve()
            if configured_root
            else config.workspace_root / "resident_store"
        )
        delivery_effects = open_resident_delivery_effects(
            resident_root / "delivery_effects",
            production_enabled=True,
            action_gate_check=_agentbox_delivery_gate_check(),
        )
        result = _send_reconcile_pr_ready_dm(
            chain_label=chain_label,
            pr_number=pr_number,
            pr_url=pr_url,
            branch=branch,
            fallback_text=dm,
            delivery_effects=delivery_effects,
        )
        append_event(
            paths,
            "megaplan_chain.reconcile_pr_ready_delivery",
            payload={
                "ok": bool(result.get("ok")),
                "reason": result.get("reason"),
                "outcome_kind": result.get("outcome_kind"),
                "glek": result.get("glek"),
            },
        )
        return result
    except Exception as exc:
        # Fail closed: absence/corruption of the sole durable owner never
        # falls through to the direct Discord transport.
        LOGGER.warning(
            "Reconcile PR ready DM has no usable durable effect owner for operation %s",
            operation_id,
            exc_info=True,
        )
        append_event(
            paths,
            "megaplan_chain.reconcile_pr_ready_delivery",
            payload={
                "ok": False,
                "reason": "durable_delivery_owner_unavailable",
                "error": f"{type(exc).__name__}: {exc}",
            },
        )
        return {
            "ok": False,
            "reason": "durable_delivery_owner_unavailable",
            "outcome_kind": "INDETERMINATE",
            "error": f"{type(exc).__name__}: {exc}",
            "message_count": 0,
        }
    finally:
        if delivery_effects is not None:
            delivery_effects.close()


def _record_pr_and_ci(
    config: AgentBoxConfig,
    operation_id: str,
    run: Any,
    snapshot: Any,
) -> None:
    repo_names = run.metadata.get("repo_names") or []
    if not repo_names:
        return
    repo_name = repo_names[0]
    try:
        repo = get_repo(config, repo_name)
    except Exception:
        return
    branch = branch_name(operation_id, repo_name)
    pr_number = snapshot.pr.get("pr_number")
    if pr_number is not None:
        stored_pr = (run.metadata.get("pr_info") or {}).get(repo_name) or {}
        if stored_pr.get("number") != pr_number:
            record_operation_pr(
                config,
                operation_id,
                repo_name=repo_name,
                branch=branch,
                pr_number=pr_number,
                pr_url=None,
            )
    stored_pr_number = ((run.metadata.get("pr_info") or {}).get(repo_name) or {}).get(
        "number"
    )
    if stored_pr_number is None and pr_number is None:
        return
    try:
        status_result = github_ci_status_for_branch(repo.path, branch)
    except Exception:
        return
    ci_status = status_result.get("status")
    if ci_status and ci_status != "unknown":
        record_operation_ci_status(
            config,
            operation_id,
            repo_name=repo_name,
            ci_status=ci_status,
        )


def _record_credential_failure(
    config: AgentBoxConfig,
    operation_id: str,
    run_paths: RunDirPaths,
    diagnostics: Mapping[str, Any],
) -> None:
    update_agentbox_operation(
        config,
        operation_id,
        metadata={
            "launch_diagnostics": dict(diagnostics),
            "validation": {"status": "failed", "phase": "credential_preflight"},
        },
        launch_state="rejected",
    )
    _merge_run_metadata(
        run_paths,
        {
            "launch_outcome": "REJECTED",
            "launch_diagnostics": dict(diagnostics),
            "validation": {"status": "failed", "phase": "credential_preflight"},
        },
    )
    append_event(
        run_paths,
        "megaplan_chain.credential_preflight_failed",
        payload=dict(diagnostics),
    )


__all__ = [
    "MEGAPLAN_CHAIN_OPERATION_TYPE",
    "MegaplanChainHandler",
    "MegaplanChainLaunchError",
    "MegaplanChainLaunchResult",
    "get_agentbox_adapter",
    "record_reconcile_pr_ready_dm",
]
