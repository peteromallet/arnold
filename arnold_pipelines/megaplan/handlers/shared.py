from __future__ import annotations

import argparse
import inspect
import json
import logging
import shutil
import subprocess
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Callable

import arnold_pipelines.megaplan.workers as worker_module
from arnold.workflow.boundary_evidence import AuthorityRecord, BoundaryOutcome, BoundaryReceipt
from arnold_pipelines.megaplan.execute.batch import build_monitor_hint
from arnold_pipelines.megaplan.fallback_chains import (
    configured_fallback_chain_for_phase,
    fallback_observability_fields,
)
from arnold_pipelines.megaplan.observability.routing_ledger import format_selected_spec
from arnold_pipelines.megaplan.profiles import apply_profile_expansion
from arnold_pipelines.megaplan.prompts import create_claude_prompt, create_codex_prompt
from arnold_pipelines.megaplan.receipts import build_receipt
from arnold_pipelines.megaplan.receipts.writer import write_boundary_receipt, write_receipt
from arnold_pipelines.megaplan.execute.step_edit import next_plan_artifact_name
from arnold_pipelines.megaplan.custody.phase_wbc import (
    activate_phase_wbc,
    complete_phase_wbc,
    fail_phase_wbc,
    phase_wbc_required,
    phase_wbc_state,
    suspend_phase_wbc,
)
from arnold_pipelines.megaplan.custody.worker_dispatch_wbc import build_worker_dispatch_spec
from arnold_pipelines.megaplan.types import (
    AgentMode,
    CliError,
    MOCK_ENV_VAR,
    PlanState,
    StepResponse,
    parse_agent_spec,
)
from arnold_pipelines.megaplan.orchestration.phase_result import (
    _emit_phase_result,
    phase_result_guard,
    BlockedTask,
    Deviation,
    ExitKind,
    DispatchOutcome,
    SchedulingCondition,
)
from arnold_pipelines.megaplan.workflows.handler_contract import (
    apply_response_projection,
    resolve_next_steps,
)
from arnold_pipelines.megaplan._core import (
    append_history,
    apply_session_update,
    atomic_write_json,
    atomic_write_text,
    build_next_step_runtime,
    clear_active_step,
    configured_robustness,
    get_effective,
    infer_next_steps,
    make_history_entry,
    now_utc,
    record_step_failure,
    save_state,
    save_state_merge_meta,
    set_active_step,
    sha256_file,
    sha256_text,
    write_immutable_json,
    workflow_next,
)
from arnold_pipelines.megaplan._core.plan_integrity import verify_prior_plan_versions
from arnold_pipelines.megaplan._core.phase_runtime import (
    DEFAULT_NON_EXECUTE_TIMEOUT_CAP_SECONDS,
    PHASE_RUNTIME_POLICY,
    format_duration_hint,
)
from arnold_pipelines.megaplan.orchestration.plan_structure import PLAN_STRUCTURE_REQUIRED_STEP_ISSUE, validate_plan_structure
from arnold_pipelines.megaplan.workflows.planning import resolve_lowered_route_target_for_signal
from arnold_pipelines.megaplan.workers import WorkerResult

log = logging.getLogger("megaplan")

_BOUNDARY_EXPECTED_NEXT_STEP_BY_ID = {
    "prep_to_plan": "plan",
    "plan_to_critique": "critique",
    "critique_to_gate": "gate",
    "gate_to_revise": "revise",
    "revise_to_critique": "critique",
}

_FRONT_HALF_BOUNDARY_ID_BY_PHASE = {
    "prep": "prep_to_plan",
    "plan": "plan_to_critique",
    "critique": "critique_to_gate",
    "gate": "gate_to_revise",
    "revise": "revise_to_critique",
}

_TIEBREAKER_BOUNDARY_ID_BY_PHASE = {
    "tiebreaker_researcher": "tiebreaker_researcher_to_challenger",
    "tiebreaker_challenger": "tiebreaker_challenger_to_synthesis",
    "tiebreaker_synthesis": "tiebreaker_synthesis_to_decision",
    "tiebreaker_decision": "tiebreaker_decision_to_parent",
}

_TIEBREAKER_EXPECTED_NEXT_STEPS = {
    "tiebreaker_researcher": frozenset({"tiebreaker_challenger"}),
    "tiebreaker_challenger": frozenset({"tiebreaker_synthesis"}),
    "tiebreaker_synthesis": frozenset({"tiebreaker_decision"}),
    "tiebreaker_decision": frozenset({"finalize", "revise", "override"}),
}

_FINALIZE_BOUNDARY_ID_BY_NEXT_STEP = {
    "execute": "finalize_artifacts",
    "revise": "finalize_fallback",
}

_ROUTE_SIGNAL_AUTHORITY_STEP_ALIASES = {
    "tiebreaker_run": "tiebreaker_researcher",
    "tiebreaker_decide": "tiebreaker_decision",
}


def _agent_mode_parts(resolved: AgentMode | tuple[str, str, bool, str | None]) -> tuple[str, str, bool, str | None]:
    if isinstance(resolved, AgentMode):
        return resolved.agent, resolved.mode, resolved.refreshed, resolved.model
    return resolved


def _active_step_fallback_fields(
    step: str,
    args: argparse.Namespace,
    *,
    agent: str,
    model: str | None,
    effort: str | None = None,
) -> dict[str, Any]:
    configured = configured_fallback_chain_for_phase(getattr(args, "phase_model", None), step)
    selected_spec = format_selected_spec(agent, model, effort) or agent
    fields = fallback_observability_fields(
        configured.specs if configured is not None else selected_spec,
        attempt_index=(
            configured.specs.index(selected_spec)
            if configured is not None and selected_spec in configured.specs
            else 0
        ),
    )
    return {
        "configured_specs": fields["configured_specs"],
        "attempt_index": fields["selected_spec_index"],
        "attempted_specs": fields["attempted_specs"],
        "failed_attempt_reasons": fields["failed_attempt_reasons"],
        "fallback_trigger": fields["fallback_trigger"],
    }


def _append_to_meta(state: PlanState, field: str, value: Any) -> None:
    state["meta"].setdefault(field, []).append(value)


def _merge_imported_decision_criteria(
    state: PlanState,
    criteria: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    imported_decisions = state["meta"].get("imported_decisions", [])
    if not imported_decisions:
        return criteria

    merged = list(criteria)
    referenced_ids = {
        decision_id
        for decision in imported_decisions
        for decision_id in [decision.get("id")]
        if isinstance(decision_id, str)
        and decision_id
        and any(
            decision_id in criterion_text
            for criterion in merged
            for criterion_text in [criterion.get("criterion")]
            if isinstance(criterion, dict) and isinstance(criterion_text, str)
        )
    }
    for decision in imported_decisions:
        decision_id = decision.get("id")
        if not isinstance(decision_id, str) or not decision_id or decision_id in referenced_ids:
            continue
        decision_text = decision.get("decision", "")
        if not isinstance(decision_text, str):
            decision_text = str(decision_text)
        load_bearing = bool(decision.get("load_bearing"))
        merged.append(
            {
                "criterion": f"Plan adheres to imported decision {decision_id}: {decision_text}",
                "priority": "must" if load_bearing else "info",
                "requires": ["subjective_judgment"] if load_bearing else [],
            }
        )
        referenced_ids.add(decision_id)
    return merged


def _load_bearing_decision_criteria_issues(
    state: PlanState,
    criteria: list[dict[str, Any]],
) -> list[str]:
    """Return exact imported-decision bindings that are not mechanically closed.

    Initial planning still uses ``_merge_imported_decision_criteria`` as a
    fail-safe so an imported decision cannot disappear.  A revision is
    different: silently synthesizing a human-only criterion after the worker
    returns makes the revision appear successful while deterministically
    recreating the blocker it was asked to remove.  Revision callers use this
    validator before merging so the next attempt receives an honest,
    actionable failure instead.
    """
    from arnold_pipelines.megaplan.runtime.capabilities import CONTAINER_CAPABILITIES

    issues: list[str] = []
    imported_decisions = state["meta"].get("imported_decisions", [])
    for decision in imported_decisions:
        if not isinstance(decision, dict) or not bool(decision.get("load_bearing")):
            continue
        decision_id = decision.get("id")
        if not isinstance(decision_id, str) or not decision_id:
            continue
        bound = [
            criterion
            for criterion in criteria
            if isinstance(criterion, dict)
            and isinstance(criterion.get("criterion"), str)
            and decision_id in criterion["criterion"]
        ]
        if not bound:
            issues.append(f"{decision_id}: no success criterion references the exact decision ID")
            continue
        mechanical = [
            criterion
            for criterion in bound
            if criterion.get("priority") == "must"
            and isinstance(criterion.get("requires"), list)
            and bool(set(criterion["requires"]) & CONTAINER_CAPABILITIES)
        ]
        if not mechanical:
            issues.append(
                f"{decision_id}: referenced criterion must use priority='must' "
                "and at least one container-verifiable requires capability"
            )
    return issues


def _validate_relative_path(project_dir: Path, raw: str, flag_name: str) -> str:
    candidate = Path(raw)
    if candidate.is_absolute():
        raise CliError(
            "invalid_args",
            f"{flag_name} must be a relative path inside the project directory",
        )
    if any(part == ".." for part in candidate.parts):
        raise CliError("invalid_args", f"{flag_name} must not contain '..' path traversal")
    resolved_path = (project_dir / candidate).resolve()
    try:
        return resolved_path.relative_to(project_dir).as_posix()
    except ValueError as exc:
        raise CliError(
            "invalid_args",
            f"{flag_name} must stay within the project directory",
        ) from exc


def attach_agent_fallback(response: StepResponse, args: argparse.Namespace) -> None:
    if hasattr(args, "_agent_fallback"):
        response["agent_fallback"] = args._agent_fallback


def _attach_next_step_runtime(response: StepResponse) -> None:
    runtime = build_next_step_runtime(
        response.get("next_step"),
        configured_timeout_seconds=int(get_effective("execution", "worker_timeout_seconds")),
    )
    if runtime is not None:
        response["next_step_runtime"] = runtime


def _warn_best_effort_emit_failure(
    token: str,
    *,
    action: str,
    plan_dir: Path | None = None,
    phase: str | None = None,
    event_kind: str | None = None,
    context: dict[str, Any] | None = None,
) -> None:
    try:
        details: list[str] = [f"action={action}"]
        if event_kind:
            details.append(f"event_kind={event_kind}")
        if phase:
            details.append(f"phase={phase}")
        if plan_dir is not None:
            details.append(f"plan_dir={plan_dir}")
        if context:
            for key in sorted(context):
                details.append(f"{key}={context[key]!r}")
        log.warning(
            "%s best-effort observability emit failed (%s)",
            token,
            ", ".join(details),
            exc_info=True,
        )
    except Exception:
        pass


def _warn_read_fallback(
    token: str,
    *,
    path: Path | None = None,
    reason: str,
    context: dict[str, Any] | None = None,
) -> None:
    try:
        details: list[str] = [f"reason={reason}"]
        if path is not None:
            details.append(f"path={path}")
        if context:
            for key in sorted(context):
                details.append(f"{key}={context[key]!r}")
        log.warning("%s read fallback (%s)", token, ", ".join(details), exc_info=True)
    except Exception:
        pass


_AUTO_NEXT_STEP = object()


def _emit_phase_notice(step: str) -> None:
    if step not in PHASE_RUNTIME_POLICY:
        return
    duration_hint = format_duration_hint(
        step,
        configured_timeout_seconds=DEFAULT_NON_EXECUTE_TIMEOUT_CAP_SECONDS,
    )
    log.info("[megaplan] Starting %s... %s", step, duration_hint)


def _run_worker(
    step: str,
    state: PlanState,
    plan_dir: Path,
    args: argparse.Namespace,
    *,
    root: Path,
    iteration: int | None = None,
    resolved: tuple[str, str, bool, str | None] | None = None,
    prompt_override: str | None = None,
    prompt_kwargs: dict[str, Any] | None = None,
    read_only: bool = False,
    wbc_dispatch: Any = None,
    reuse_active_phase: bool = False,
) -> tuple[WorkerResult, str, str, bool]:
    failure_iteration = state["iteration"] if iteration is None else iteration
    from arnold_pipelines.megaplan import handlers as _handlers_pkg

    apply_profile_expansion(args, Path(state["config"]["project_dir"]), state=state)
    res = resolved or _handlers_pkg.resolve_agent_mode(step, args)
    agent = res.agent if isinstance(res, AgentMode) else res[0]
    mode = res.mode if isinstance(res, AgentMode) else res[1]
    refreshed = res.refreshed if isinstance(res, AgentMode) else res[2]
    model = res.resolved_model if isinstance(res, AgentMode) else res[3]
    effort = res.effort if isinstance(res, AgentMode) else None
    _canonical_production = bool(
        os.environ.get("ARNOLD_RUNTIME_MANIFEST")
        or os.environ.get("MEGAPLAN_RUNTIME_LAUNCH_SEED")
        or getattr(args, "production_intent", False)
    )
    _selected_spec = format_selected_spec(agent, model, effort) or agent
    if _canonical_production:
        _configured_specs = (_selected_spec,)
        _safe_spec = _selected_spec
    else:
        from arnold_pipelines.megaplan.fallback_chains import configured_fallback_chain_for_phase
        from arnold_pipelines.megaplan.runtime.memory_headroom import (
            read_cgroup_memory_snapshot,
            record_dispatch_memory_marker,
            select_memory_safe_spec,
        )
        _configured_chain = configured_fallback_chain_for_phase(getattr(args, "phase_model", None), step)
        _configured_specs = tuple(_configured_chain.specs) if _configured_chain is not None else (_selected_spec,)
        _safe_spec, _headroom_decision = select_memory_safe_spec(
            _configured_specs, phase=step, plan_dir=plan_dir,
            snapshot=read_cgroup_memory_snapshot(),
        )
        if _safe_spec is None:
            _block_error = CliError(
                "insufficient_memory_headroom",
                f"refusing to dispatch {_selected_spec} for phase {step}: {_headroom_decision.get('reason')}",
                extra={"phase": step, "selected_spec": _selected_spec, "configured_specs": list(_configured_specs), "decision": _headroom_decision},
            )
            record_step_failure(plan_dir, state, step=step, iteration=failure_iteration, error=_block_error)
            raise _block_error
        if _safe_spec != _selected_spec:
            _fallback_parsed = parse_agent_spec(_safe_spec)
            agent = _fallback_parsed.agent or agent
            model = _fallback_parsed.model
            effort = _fallback_parsed.effort
            res = AgentMode(agent=agent, mode=mode, refreshed=refreshed, model=model, effort=effort, resolved_model=model)
        record_dispatch_memory_marker(plan_dir, step, _safe_spec)
    if reuse_active_phase:
        active_step = state.get("active_step")
        phase = phase_wbc_state(state, step=step)
        invocation_id = str((state.get("meta") or {}).get("current_invocation_id") or "")
        if (
            not isinstance(active_step, dict)
            or active_step.get("phase") != step
            or phase is None
            or phase.get("invocation_id") != invocation_id
            or not isinstance(active_step.get("run_id"), str)
        ):
            raise RuntimeError(
                f"cannot reuse {step!r}: matching active phase WBC custody is unavailable"
            )
        run_id = str(active_step["run_id"])
    else:
        run_id = set_active_step(
            state,
            step=step,
            agent=agent,
            mode=mode,
            model=model,
            **_active_step_fallback_fields(step, args, agent=agent, model=model, effort=effort),
        )
    # Fresh-child admission owns the initial WBC reservation.  In canonical
    # production, project that child-scoped identity into the exact phase
    # state consumed by the common worker-dispatch adapter; never activate a
    # second local phase owner here.
    if _canonical_production and not reuse_active_phase:
        child_admission = (state.get("meta") or {}).get("fresh_child_admission")
        if isinstance(child_admission, dict):
            from arnold_pipelines.megaplan.chain.fresh_child_launch import phase_wbc_handoff
            active = state.get("active_step")
            if not isinstance(active, dict):
                raise RuntimeError("fresh-child WBC handoff requires an active step")
            active["_phase_wbc"] = phase_wbc_handoff(
                child_admission,
                plan_dir=plan_dir,
                step=step,
                invocation_id=str(
                    (state.get("meta") or {}).get("current_invocation_id") or ""
                ),
            )
    _emit_phase_notice(step)
    try:
        if phase_wbc_required(step) and not reuse_active_phase and not _canonical_production:
            activate_phase_wbc(state=state, plan_dir=plan_dir, step=step, agent=agent)
        if wbc_dispatch is None:
            selected_spec = format_selected_spec(agent, model, effort) or agent
            wbc_dispatch = build_worker_dispatch_spec(
                plan_dir=plan_dir,
                state=state,
                step=step,
                agent=agent,
                selected_spec=selected_spec,
                route_kind="direct",
            )
            if _canonical_production and wbc_dispatch is None:
                raise CliError(
                    "wbc_dispatch_required",
                    "canonical production worker dispatch requires an active common WBC",
                    extra={"phase": step, "selected_spec": selected_spec},
                )
        # Phases hold the lock for many minutes; merge meta to avoid clobbering
        # concurrent override appends to ``meta.notes`` / ``meta.overrides``.
        save_state_merge_meta(plan_dir, state)
        with phase_result_guard(plan_dir):
            run_step_kwargs: dict[str, Any] = {
                "root": root,
                "resolved": res,
                "prompt_override": prompt_override,
            }
            if prompt_kwargs is not None and _supports_prompt_kwargs(worker_module.run_step_with_worker):
                run_step_kwargs["prompt_kwargs"] = prompt_kwargs
            if read_only:
                run_step_kwargs["read_only"] = True
            if wbc_dispatch is not None:
                run_step_kwargs["wbc_dispatch"] = wbc_dispatch
            worker_result = worker_module.run_step_with_worker(
                step,
                state,
                plan_dir,
                args,
                **run_step_kwargs,
            )
            # Native/OMP physical doors may return the canonical typed
            # terminal directly.  Handlers historically unpack a four-tuple,
            # so project that terminal into a compatibility WorkerResult here
            # while preserving its complete outcome envelope and identity.
            if isinstance(worker_result, DispatchOutcome):
                if worker_result.kind == "unresolved_launch":
                    raise CliError(
                        "scheduling_condition",
                        "canonical worker launch remains unresolved",
                        extra={
                            "reason": "unresolved_launch",
                            "dispatch_outcome": worker_result.to_dict(),
                        },
                    )
                if worker_result.kind == "no_launch":
                    raise CliError(
                        "internal_error",
                        "canonical worker dispatch completed without a worker launch",
                        extra=worker_result.to_dict(),
                    )
                payload: dict[str, Any] = {}
                if isinstance(worker_result.success_payload, Mapping):
                    payload.update(worker_result.success_payload)
                if worker_result.kind != "success":
                    payload.setdefault("success", False)
                    if worker_result.terminal_failure is not None:
                        payload.setdefault("terminal_failure", dict(worker_result.terminal_failure))
                    if worker_result.provider_evidence is not None:
                        payload.setdefault("provider_evidence", dict(worker_result.provider_evidence))
                    if worker_result.disposition_id is not None:
                        payload.setdefault("disposition_id", worker_result.disposition_id)
                compatibility_worker = WorkerResult(
                    payload=payload,
                    raw_output="",
                    duration_ms=0,
                    cost_usd=0.0,
                    worker_identity=dict(worker_result.worker_identity or {}),
                    auth_metadata={"dispatch_outcome": worker_result.to_dict()},
                )
                return compatibility_worker, agent, mode, refreshed
            return worker_result
    except CliError as error:
        clear_active_step(state, run_id=run_id)
        raw_outcome = (error.extra or {}).get("dispatch_outcome")
        if isinstance(raw_outcome, dict):
            try:
                unresolved = DispatchOutcome.from_dict(raw_outcome)
                condition = SchedulingCondition(
                    condition_id=f"unresolved:{unresolved.logical_dispatch_id}",
                    reason="unresolved_launch",
                    plan_id=unresolved.plan_id,
                    phase=unresolved.phase,
                    spec=unresolved.selected_spec,
                    dispatch_family_id=unresolved.dispatch_family_id,
                    logical_dispatch_id=unresolved.logical_dispatch_id,
                    admission_attempt=1,
                    retry_after_s=0.0,
                    observed_at=unresolved.finished_at or now_utc(),
                    cause_event_id=unresolved.terminal_outcome_event_id,
                    evidence={"dispatch_outcome": unresolved.to_dict()},
                )
                _emit_phase_result(
                    phase=step,
                    state=state,
                    plan_dir=plan_dir,
                    exit_kind="scheduling_condition",
                    cli_provenance={"error_code": error.code},
                    scheduling_condition=condition,
                    dispatch_outcome=unresolved,
                )
            except (TypeError, ValueError):
                # Preserve the original typed error if a producer supplied an
                # invalid payload; do not manufacture a terminal result.
                pass
        if error.code != "scheduling_condition":
            record_step_failure(plan_dir, state, step=step, iteration=failure_iteration, error=error)
        raise
    except Exception:
        clear_active_step(state, run_id=run_id)
        save_state_merge_meta(plan_dir, state)
        raise


def _supports_prompt_kwargs(run_step: Callable[..., Any]) -> bool:
    params = inspect.signature(run_step).parameters.values()
    return any(param.name == "prompt_kwargs" for param in params) or any(
        param.kind == inspect.Parameter.VAR_KEYWORD for param in params
    )


def _build_gate_prompt_override(
    agent_type: str,
    state: PlanState,
    plan_dir: Path,
    *,
    root: Path,
    missing_flag_ids: list[str],
) -> str:
    """Build a targeted gate reprompt that is scratch-file-aware.

    Does NOT rebuild the full base gate prompt (which would call
    ``_write_gate_template`` and overwrite the model's filled
    ``gate_output.json`` from the first attempt).  Instead, the reprompt
    references the **same** scratch path, instructs the model to read and
    **completely replace** its contents, and warns against writing to
    ``gate.json`` directly.
    """
    from arnold_pipelines.megaplan.prompts import _NESTED_HARNESS_GUARD

    scratch_path = plan_dir / "gate_output.json"
    missing_flags = ", ".join(missing_flag_ids)
    reprompt_body = (
        "GATE REPROMPT — SAME ITERATION, SAME SCRATCH FILE\n\n"
        "Your previous gate response recommended PROCEED but left blocking "
        "flags unresolved.  The scratch file at the path below still contains "
        "your prior attempt.\n\n"
        f"SCRATCH FILE: {scratch_path}\n\n"
        "WORKFLOW:\n"
        "1. Read the scratch file to see the template and your previous "
        "response.\n"
        "2. Produce a COMPLETE REPLACEMENT response — do NOT append or "
        "patch the existing content.  Every field must be filled fresh.\n"
        "3. Write the complete replacement JSON back to the SAME scratch "
        "file.\n\n"
        f"Missing blocking flag IDs that must be resolved: {missing_flags}\n\n"
        "REQUIREMENTS:\n"
        "- Return a complete gate response.  If you recommend PROCEED, you "
        "MUST include ``flag_resolutions`` entries for every blocking flag.\n"
        "- For addressed-but-unverified flags, the action MUST be "
        "``verify_fixed`` with concrete evidence from the revised plan; "
        "``dispute`` and ``accept_tradeoff`` do not clear addressed flags.\n"
        "- If you cannot resolve every blocking flag, return ITERATE or "
        "ESCALATE instead.\n"
        "- Write ONLY to the scratch file above.  Do NOT write to "
        "``gate.json`` or any other path — those are ignored by the "
        "harness.\n"
        "- If you cannot use file tools, return the populated JSON "
        "structure inline as your response instead."
    )
    return f"{_NESTED_HARNESS_GUARD}\n\n{reprompt_body}"


# ---------------------------------------------------------------------------
# Phase-result helpers for funneled handlers
# ---------------------------------------------------------------------------


def _derive_exit_kind_funneled(step: str, result: str, state: PlanState) -> str:
    """Derive ``exit_kind`` for the 6 funneled handlers.

    * ``step == "gate"`` and the result indicates a quality-gate block →
      ``blocked_by_quality``.
    * Everything else → ``success`` (funneled handlers don't have prereq
      blocks / timeouts — those come from execute).
    """
    if step == "gate" and result not in ("success",):
        return ExitKind.blocked_by_quality.value
    return ExitKind.success.value


def _extract_deviations_from_state(state: PlanState) -> tuple[Deviation, ...]:
    """Return explicit blocker deviations carried by *state*.

    ``last_gate.warnings`` are advisory operator notes, not execute blockers.
    Serializing them as ``quality_gate`` deviations causes successful
    ``finalize`` runs to strand themselves in status/repair loops before the
    first execute step. Real quality blockers must be emitted explicitly by the
    phase that discovered them.
    """
    return ()


def _snapshot_cli_provenance(state: PlanState) -> dict[str, Any]:
    """Snapshot CLI-originated config keys so the driver can rehydrate them."""
    config = state.get("config", {})
    return {
        k: config.get(k)
        for k in (
            "phase_model",
            "profile",
            "auto_approve",
            "mode",
            "robustness",
            "max_execute_tier",
            "tier_models",
            "prep_models",
            "prep_model_resolver_trace",
        )
        if k in config
    }


# ---------------------------------------------------------------------------


def _emit_receipt(
    *,
    plan_dir: Path,
    state: PlanState,
    args: argparse.Namespace,
    worker: WorkerResult,
    agent: str,
    mode: str,
    phase: str,
    output_file: str,
    artifact_hash: str,
    verdict: Any = None,
) -> None:
    """Emit a receipt for *phase*, best-effort (warns on failure)."""
    try:
        project_dir = Path(state["config"]["project_dir"])
        receipt = build_receipt(
            phase=phase,
            state=state,
            plan_dir=plan_dir,
            args=args,
            worker=worker,
            agent=agent,
            mode=mode,
            output_file=output_file,
            artifact_hash=artifact_hash,
            verdict=verdict,
        )
        write_receipt(plan_dir, receipt, project_dir=project_dir)
    except Exception:
        log.warning("Receipt emission failed for step %s", phase, exc_info=True)


def _boundary_contract_by_phase(step: str):
    from arnold_pipelines.megaplan.workflows.boundary_contracts import BOUNDARY_CONTRACTS_BY_ID

    boundary_id = _FRONT_HALF_BOUNDARY_ID_BY_PHASE.get(step) or _TIEBREAKER_BOUNDARY_ID_BY_PHASE.get(step)
    if boundary_id is None:
        return None
    return BOUNDARY_CONTRACTS_BY_ID.get(boundary_id)


def _boundary_contract_from_id(boundary_id: str):
    from arnold_pipelines.megaplan.workflows.boundary_contracts import BOUNDARY_CONTRACTS_BY_ID

    return BOUNDARY_CONTRACTS_BY_ID.get(boundary_id)


def _boundary_contract_for_response(
    step: str,
    response: StepResponse,
):
    if step == "finalize":
        boundary_id = _FINALIZE_BOUNDARY_ID_BY_NEXT_STEP.get(str(response.get("next_step") or ""))
        if boundary_id is None:
            return None
        return _boundary_contract_from_id(boundary_id)
    contract = _boundary_contract_by_phase(step)
    if contract is None:
        return None
    if step in _TIEBREAKER_EXPECTED_NEXT_STEPS:
        next_step = response.get("next_step")
        if next_step not in _TIEBREAKER_EXPECTED_NEXT_STEPS[step]:
            return None
        return contract
    expected_next_step = _BOUNDARY_EXPECTED_NEXT_STEP_BY_ID.get(contract.boundary_id)
    if expected_next_step is not None and response.get("next_step") != expected_next_step:
        return None
    return contract


def _boundary_history_snapshot(state: PlanState) -> dict[str, Any]:
    history = state.get("history")
    if not isinstance(history, list) or not history:
        return {}
    entry = history[-1]
    return dict(entry) if isinstance(entry, dict) else {}


def _boundary_session_snapshot(
    state: PlanState,
    *,
    session_id: str | None,
) -> dict[str, Any]:
    if not session_id:
        return {}
    sessions = state.get("sessions")
    if not isinstance(sessions, dict):
        return {}
    for session_key, session in sessions.items():
        if not isinstance(session, dict) or session.get("id") != session_id:
            continue
        snapshot = dict(session)
        snapshot["session_key"] = session_key
        return snapshot
    return {"id": session_id}


def _boundary_artifact_refs(
    *,
    plan_dir: Path,
    contract: Any,
    artifacts: list[str],
    output_file: str,
) -> tuple[str, ...]:
    refs: list[str] = []
    for ref in [*artifacts, output_file]:
        if isinstance(ref, str) and ref and ref not in refs:
            refs.append(ref)
    if contract.phase_result_required and "phase_result.json" not in refs:
        refs.append("phase_result.json")
    for required_artifact in contract.required_artifacts:
        if (
            isinstance(required_artifact, str)
            and required_artifact
            and (plan_dir / required_artifact).exists()
            and required_artifact not in refs
        ):
            refs.append(required_artifact)
    return tuple(refs)


def _boundary_authority_records(
    *,
    plan_dir: Path,
    contract: Any,
    worker: WorkerResult,
    agent: str,
    response: StepResponse,
) -> tuple[AuthorityRecord, ...]:
    if not contract.authority_required:
        return ()
    auth_metadata = worker.auth_metadata if isinstance(worker.auth_metadata, dict) else {}
    actor = str(auth_metadata.get("actor") or auth_metadata.get("authority_id") or worker.auth_channel or agent)
    role = str(auth_metadata.get("role") or auth_metadata.get("authority_role") or "boundary_observer")
    recommendation = response.get("recommendation")
    decision = str(recommendation) if isinstance(recommendation, str) and recommendation else None
    debt_payload = response.get("debt_payload")
    debt_entries_added = None
    if isinstance(debt_payload, dict):
        debt_entries_added = debt_payload.get("debt_entries_added")
    evidence_refs = tuple(
        ref
        for ref in ("gate.json", "gate_carry.json", "phase_result.json")
        if ref == "phase_result.json" or (plan_dir / ref).exists()
    )
    return (
        AuthorityRecord(
            actor=actor,
            role=role,
            decision=decision,
            scope=contract.boundary_id,
            evidence_refs=evidence_refs,
            details={
                "passed": response.get("passed"),
                "rationale": response.get("rationale"),
                "warnings": response.get("warnings"),
                "settled_decisions": response.get("settled_decisions"),
                "debt_entries_added": debt_entries_added,
                "auth_channel": worker.auth_channel,
                "auth_metadata": auth_metadata,
                "worker_channel": worker.worker_channel,
            },
        ),
    )


def _emit_boundary_receipt(
    *,
    plan_dir: Path,
    state: PlanState,
    step: str,
    worker: WorkerResult,
    agent: str,
    mode: str,
    artifacts: list[str],
    output_file: str,
    artifact_hash: str,
    response: StepResponse,
    run_id: str | None = None,
    gate_summary: dict[str, Any] | None = None,
    strict: bool = False,
) -> BoundaryReceipt | None:
    contract = _boundary_contract_for_response(step, response)
    if contract is None:
        return None
    return _emit_boundary_receipt_for_contract(
        contract=contract,
        plan_dir=plan_dir,
        state=state,
        step=step,
        worker=worker,
        agent=agent,
        mode=mode,
        artifacts=artifacts,
        output_file=output_file,
        artifact_hash=artifact_hash,
        response=response,
        run_id=run_id,
        gate_summary=gate_summary,
        strict=strict,
    )


def _emit_named_boundary_receipt(
    *,
    boundary_id: str,
    plan_dir: Path,
    state: PlanState,
    step: str,
    worker: WorkerResult,
    agent: str,
    mode: str,
    artifacts: list[str],
    output_file: str,
    artifact_hash: str,
    response: StepResponse,
    run_id: str | None = None,
    gate_summary: dict[str, Any] | None = None,
    strict: bool = False,
) -> BoundaryReceipt | None:
    contract = _boundary_contract_from_id(boundary_id)
    if contract is None:
        if strict:
            raise RuntimeError(f"unknown boundary contract {boundary_id!r}")
        return None
    return _emit_boundary_receipt_for_contract(
        contract=contract,
        plan_dir=plan_dir,
        state=state,
        step=step,
        worker=worker,
        agent=agent,
        mode=mode,
        artifacts=artifacts,
        output_file=output_file,
        artifact_hash=artifact_hash,
        response=response,
        run_id=run_id,
        gate_summary=gate_summary,
        strict=strict,
    )


def _emit_boundary_receipt_for_contract(
    *,
    contract: Any,
    plan_dir: Path,
    state: PlanState,
    step: str,
    worker: WorkerResult,
    agent: str,
    mode: str,
    artifacts: list[str],
    output_file: str,
    artifact_hash: str,
    response: StepResponse,
    run_id: str | None = None,
    gate_summary: dict[str, Any] | None = None,
    strict: bool = False,
) -> BoundaryReceipt | None:
    try:
        project_dir = Path(state["config"]["project_dir"])
        history_entry = _boundary_history_snapshot(state)
        session_entry = _boundary_session_snapshot(state, session_id=worker.session_id)
        details_dict: dict[str, Any] = {
            "artifact_hash": artifact_hash,
            "artifacts_written": list(artifacts),
            "history": {
                "step": history_entry.get("step"),
                "result": history_entry.get("result"),
                "timestamp": history_entry.get("timestamp"),
                "output_file": history_entry.get("output_file"),
            },
            "session": {
                "id": session_entry.get("id"),
                "session_key": session_entry.get("session_key"),
                "mode": mode,
                "worker_channel": session_entry.get("worker_channel") or worker.worker_channel,
                "auth_channel": session_entry.get("auth_channel") or worker.auth_channel,
            },
        }
        if run_id:
            details_dict["run_id"] = run_id
        # For gate_to_revise boundary, include gate_summary authority data
        # as receipt metadata so downstream consumers can cross-reference
        # gate decisions with boundary evidence without re-reading gate.json.
        if (
            gate_summary is not None
            and isinstance(gate_summary, dict)
            and contract.boundary_id == "gate_to_revise"
        ):
            details_dict["gate_authority"] = {
                "recommendation": gate_summary.get("recommendation"),
                "passed": gate_summary.get("passed"),
                "rationale": gate_summary.get("rationale"),
                "warnings": gate_summary.get("warnings"),
                "settled_decisions": gate_summary.get("settled_decisions"),
                "reprompted": gate_summary.get("reprompted"),
            }
        receipt = BoundaryReceipt(
            boundary_id=contract.boundary_id,
            workflow_id=contract.workflow_id,
            row_id=contract.row_id,
            invocation_id=(state.get("meta") or {}).get("current_invocation_id"),
            artifact_refs=_boundary_artifact_refs(
                plan_dir=plan_dir,
                contract=contract,
                artifacts=artifacts,
                output_file=output_file,
            ),
            state_observation={
                "current_phase": step,
                "current_state": state.get("current_state"),
                "iteration": state.get("iteration"),
                "next_step": response.get("next_step"),
            },
            history_ref=contract.expected_history_entry,
            phase_result_ref="phase_result.json" if contract.phase_result_required else None,
            outcome=BoundaryOutcome.COMPLETE,
            authority_records=_boundary_authority_records(
                plan_dir=plan_dir,
                contract=contract,
                worker=worker,
                agent=agent,
                response=response,
            ),
            details=details_dict,
        )
        history_path = write_boundary_receipt(plan_dir, receipt, project_dir=project_dir)
        if strict:
            receipt_path = plan_dir / "boundary_receipts" / f"{contract.boundary_id}.json"
            if history_path is None or not receipt_path.exists():
                raise RuntimeError(f"boundary receipt {contract.boundary_id!r} was not durably persisted")
            persisted = json.loads(receipt_path.read_text(encoding="utf-8"))
            expected = receipt.to_dict()
            historical = json.loads(history_path.read_text(encoding="utf-8"))
            if persisted != expected or historical != expected:
                raise RuntimeError(
                    f"boundary receipt reread mismatch for {contract.boundary_id!r}"
                )
        return receipt
    except Exception:
        if strict:
            raise
        _warn_best_effort_emit_failure(
            "M3A_WARN_EMIT_BOUNDARY_RECEIPT",
            action="boundary-receipt",
            plan_dir=plan_dir,
            phase=step,
            context={"boundary_id": contract.boundary_id},
        )
        return None


def _finish_step(
    plan_dir: Path,
    state: PlanState,
    args: argparse.Namespace,
    *,
    step: str,
    worker: WorkerResult,
    agent: str,
    mode: str,
    refreshed: bool,
    summary: str,
    artifacts: list[str],
    output_file: str,
    artifact_hash: str,
    result: str = "success",
    success: bool = True,
    next_step: object | str | None = _AUTO_NEXT_STEP,
    response_fields: dict[str, Any] | None = None,
    history_fields: dict[str, Any] | None = None,
    run_id: str | None = None,
    gate_summary: dict[str, Any] | None = None,
    extra_boundary_ids: tuple[str, ...] = (),
) -> StepResponse:
    # Capture run_id before the active step is cleared so downstream
    # evidence writes can join on the same lifecycle identity.
    effective_run_id = run_id
    if effective_run_id is None:
        active = state.get("active_step")
        if isinstance(active, dict):
            effective_run_id = active.get("run_id")
    if success and result == "success":
        state["latest_failure"] = None
        state.pop("resume_cursor", None)
    apply_session_update(
        state,
        step,
        agent,
        worker.session_id,
        mode=mode,
        refreshed=refreshed,
        worker_channel=worker.worker_channel,
        auth_channel=worker.auth_channel,
        auth_metadata=worker.auth_metadata,
    )
    append_history(
        state,
        make_history_entry(
            step,
            duration_ms=worker.duration_ms,
            cost_usd=worker.cost_usd,
            result=result,
            worker=worker,
            agent=agent,
            mode=mode,
            output_file=output_file,
            artifact_hash=artifact_hash,
            prompt_tokens=worker.prompt_tokens,
            completion_tokens=worker.completion_tokens,
            total_tokens=worker.total_tokens,
            **(history_fields or {}),
        ),
    )
    if step not in {"execute", "review"}:
        _emit_receipt(
            plan_dir=plan_dir,
            state=state,
            args=args,
            worker=worker,
            agent=agent,
            mode=mode,
            phase=step,
            output_file=output_file,
            artifact_hash=artifact_hash,
            verdict=(history_fields or {}).get("verdict"),
        )
    resolved_next = next_step
    if resolved_next is _AUTO_NEXT_STEP:
        next_steps = resolve_next_steps(state)
        resolved_next = next_steps[0] if next_steps else None
    response: StepResponse = {
        "success": success,
        "step": step,
        "summary": summary,
        "artifacts": artifacts,
        "monitor_hint": build_monitor_hint(plan_dir),
        "next_step": resolved_next,
        "state": state["current_state"],
    }
    dispatch_outcome = None
    metadata = worker.auth_metadata if isinstance(worker.auth_metadata, dict) else {}
    raw_dispatch_outcome = metadata.get("dispatch_outcome")
    if isinstance(raw_dispatch_outcome, dict):
        dispatch_outcome = DispatchOutcome.from_dict(raw_dispatch_outcome)
        response["dispatch_outcome"] = dispatch_outcome.to_dict()
    if response_fields:
        response.update(response_fields)
    route_signal = response.get("route_signal")
    route_target = None
    if isinstance(route_signal, str) and route_signal:
        authority_step = _ROUTE_SIGNAL_AUTHORITY_STEP_ALIASES.get(step, step)
        route_target = resolve_lowered_route_target_for_signal(authority_step, route_signal)
    if route_target is not None:
        apply_response_projection(
            response,
            route_signal=route_signal,
            next_step=route_target,
        )
    _attach_next_step_runtime(response)
    attach_agent_fallback(response, args)
    # Emit the canonical phase_result.json for the auto driver
    _emit_phase_result(
        phase=step,
        state=state,
        plan_dir=plan_dir,
        exit_kind=_derive_exit_kind_funneled(step, result, state),
        blocked_tasks=(),
        deviations=_extract_deviations_from_state(state),
        artifacts_written=tuple(artifacts),
        cli_provenance=_snapshot_cli_provenance(state),
        dispatch_outcome=dispatch_outcome,
    )
    try:
        phase_projection = phase_wbc_state(state, step=step)
        strict_boundary_receipt = (
            phase_wbc_required(step)
            and phase_projection is not None
            and not bool(phase_projection.get("projected_from_fresh_child"))
        )
        receipt = _emit_boundary_receipt(
            plan_dir=plan_dir,
            state=state,
            step=step,
            worker=worker,
            agent=agent,
            mode=mode,
            artifacts=artifacts,
            output_file=output_file,
            artifact_hash=artifact_hash,
            response=response,
            run_id=effective_run_id,
            gate_summary=gate_summary,
            strict=strict_boundary_receipt,
        )
        extra_receipts = tuple(
            _emit_named_boundary_receipt(
                boundary_id=boundary_id,
                plan_dir=plan_dir,
                state=state,
                step=step,
                worker=worker,
                agent=agent,
                mode=mode,
                artifacts=artifacts,
                output_file=output_file,
                artifact_hash=artifact_hash,
                response=response,
                run_id=effective_run_id,
                gate_summary=gate_summary,
                strict=strict_boundary_receipt,
            )
            for boundary_id in extra_boundary_ids
        )
    except Exception as exc:
        if not bool((phase_wbc_state(state, step=step) or {}).get("projected_from_fresh_child")):
            fail_phase_wbc(
                state=state,
                plan_dir=plan_dir,
                step=step,
                agent=agent,
                payload={
                    "phase": step,
                    "status": "failed",
                    "failure_stage": "result_evidence",
                    "error_class": type(exc).__name__,
                    "message": str(exc),
                    "phase_result_ref": "phase_result.json",
                },
            )
        raise
    else:
        if phase_wbc_required(step) and not bool((phase_wbc_state(state, step=step) or {}).get("projected_from_fresh_child")):
            receipt_ids = [
                emitted.boundary_id
                for emitted in (receipt, *extra_receipts)
                if emitted is not None
            ]
            if step == "prep" and str(response.get("prep_outcome")) == "awaiting_human":
                clarification = state.get("clarification")
                suspend_phase_wbc(
                    state=state,
                    plan_dir=plan_dir,
                    step=step,
                    agent=agent,
                    checkpoint={
                        "phase": step,
                        "state": state.get("current_state"),
                        "phase_result_ref": "phase_result.json",
                        "output_file": output_file,
                        "artifact_hash": artifact_hash,
                        "clarification": (
                            dict(clarification)
                            if isinstance(clarification, dict)
                            else None
                        ),
                    },
                    cursor={
                        "phase": step,
                        "resume_action": "override:resume-clarify",
                        "resume_state": "prepped",
                        "next_phase": "plan",
                    },
                )
            else:
                complete_phase_wbc(
                    state=state,
                    plan_dir=plan_dir,
                    step=step,
                    agent=agent,
                    payload={
                        "phase": step,
                        "status": "completed",
                        "summary": summary,
                        "next_step": response.get("next_step"),
                        "phase_result_ref": "phase_result.json",
                        "boundary_receipt_id": receipt.boundary_id if receipt is not None else None,
                        "boundary_receipt_ids": receipt_ids,
                        "artifacts_written": list(artifacts),
                        "output_file": output_file,
                        "artifact_hash": artifact_hash,
                    },
                )
    clear_active_step(state, run_id=run_id)
    save_state_merge_meta(plan_dir, state)
    return response


def _raise_step_validation_error(
    *,
    plan_dir: Path,
    state: PlanState,
    step: str,
    iteration: int,
    worker: WorkerResult,
    code: str,
    message: str,
) -> None:
    error = CliError(code, message, valid_next=infer_next_steps(state), extra={"raw_output": worker.raw_output})
    record_step_failure(plan_dir, state, step=step, iteration=iteration, error=error, duration_ms=worker.duration_ms)
    raise error


def _write_json_artifact(plan_dir: Path, filename: str, payload: dict[str, Any]) -> str:
    atomic_write_json(plan_dir / filename, payload, _plan_dir=plan_dir)
    return sha256_file(plan_dir / filename)


def _write_gate_json(
    plan_dir: Path,
    payload: dict[str, Any],
    *,
    iteration: int | None = None,
) -> str:
    """Write the legacy gate projection and, when known, immutable evidence."""
    if iteration is not None:
        versioned = plan_dir / f"gate_v{iteration}.json"
        if versioned.exists() and not versioned.is_symlink():
            try:
                stale = json.loads(versioned.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                stale = None
            if not isinstance(stale, dict) or stale.get("recommendation") != payload.get("recommendation"):
                # Re-entry at the same iteration (disposition-consume re-run,
                # post-revise gate, provider retry): the stale immutable
                # gate_v projection must be archived (the documented
                # gate_retry invalidation) before the fresh gate publishes
                # new evidence — otherwise the immutable write collides and
                # the phase crashes after publishing gate_carry but before
                # committing state.
                from arnold_pipelines.megaplan.replan_state import (
                    invalidate_replan_derived_artifacts,
                )

                try:
                    invalidate_replan_derived_artifacts(
                        plan_dir,
                        timestamp=now_utc(),
                        scope="gate_retry",
                    )
                except Exception:
                    logging.getLogger(__name__).warning(
                        "gate epoch archive skipped (best effort)", exc_info=True
                    )
        write_immutable_json(versioned, payload)
    return _write_json_artifact(plan_dir, "gate.json", payload)


def _normalize_plan_text(plan_text: str) -> str:
    """Decode escaped newlines some models emit inside JSON plan strings.

    When a model returns a JSON object whose ``plan`` field contains literal
    ``\\n`` (or ``\\r\\n``) characters instead of real newlines, the Markdown
    validator sees a single physical line and fails to find step headings.
    Detect that pattern and decode the escapes so the plan is valid Markdown.
    """
    # Fast path: already contains real newlines; leave it alone.
    if "\n" in plan_text:
        return plan_text
    # Decode only the JSON escapes that can make a one-line Markdown plan
    # structurally invalid.  ``unicode_escape`` is deliberately not used here:
    # it can turn a valid ``\\u00a3`` escape into a lone 0xa3 byte during its
    # raw-unicode repair round trip, raising UnicodeDecodeError and aborting an
    # otherwise valid execute phase.
    if "\\n" in plan_text or "\\r" in plan_text:
        decoded_parts: list[str] = []
        index = 0
        while index < len(plan_text):
            char = plan_text[index]
            if char != "\\" or index + 1 >= len(plan_text):
                decoded_parts.append(char)
                index += 1
                continue

            escape = plan_text[index + 1]
            if escape == "n":
                decoded_parts.append("\n")
                index += 2
                continue
            if escape == "r":
                if index + 3 < len(plan_text) and plan_text[index + 2 : index + 4] == "\\n":
                    decoded_parts.append("\n")
                    index += 4
                else:
                    decoded_parts.append("\n")
                    index += 2
                continue
            if escape == "u" and index + 5 < len(plan_text):
                digits = plan_text[index + 2 : index + 6]
                try:
                    codepoint = int(digits, 16)
                except ValueError:
                    codepoint = -1
                # Decode valid scalar values, leaving malformed and surrogate
                # escapes literal rather than constructing invalid text.
                if codepoint >= 0 and not 0xD800 <= codepoint <= 0xDFFF:
                    decoded_parts.append(chr(codepoint))
                    index += 6
                    continue

            # Do not reinterpret unrelated escapes (for example ``\\t`` or
            # ``\\\\`` in a code sample).  They are not required to restore
            # Markdown structure and decoding them changes user content.
            decoded_parts.append(char)
            index += 1

        decoded = "".join(decoded_parts)
        if "\n" in decoded:
            return decoded
    return plan_text


def _write_plan_version(
    *,
    plan_dir: Path,
    state: PlanState,
    step: str,
    version: int,
    worker: WorkerResult,
    plan_text: str,
    meta_fields: dict[str, Any],
    plan_filename: str | None = None,
) -> tuple[str, str, dict[str, Any]]:
    plan_text = _normalize_plan_text(plan_text)
    # Verify the immutable predecessor chain before structural validation or
    # any new plan/meta bytes are emitted.  A model or external process that
    # mutates plan_v2 must fail closed before plan_v3 can hide that mutation.
    verify_prior_plan_versions(plan_dir=plan_dir, state=state)
    resolved_plan_filename = plan_filename or next_plan_artifact_name(plan_dir, version)
    meta_filename = (
        f"plan_v{version}.meta.json"
        if resolved_plan_filename == f"plan_v{version}.md"
        else resolved_plan_filename.replace(".md", ".meta.json")
    )
    structure_warnings = _validate_generated_plan_or_raise(
        plan_dir=plan_dir,
        state=state,
        step=step,
        iteration=version,
        worker=worker,
        plan_text=plan_text,
    )
    new_hash = sha256_text(plan_text)
    prior_version = (
        state.get("plan_versions", [])[-1]
        if state.get("plan_versions")
        else None
    )
    is_primary_plan_artifact = resolved_plan_filename == f"plan_v{version}.md"
    if (
        is_primary_plan_artifact
        and isinstance(prior_version, dict)
        and prior_version.get("hash") == new_hash
    ):
        raise CliError(
            "cache_hit_suspected",
            "revise produced byte-identical content to prior plan version - likely a session-cache replay. See ticket.",
            valid_next=infer_next_steps(state),
            extra={
                "step": step,
                "prior_version": prior_version.get("version"),
                "prior_hash": prior_version.get("hash"),
                "new_hash": new_hash,
                "session_id": worker.session_id,
                "duration_ms": worker.duration_ms,
                "prompt_tokens": worker.prompt_tokens,
                "completion_tokens": worker.completion_tokens,
                "ticket": "01KRXNZZGRV17PHZRJ2Q56SPS3",
                "message": "revise produced byte-identical content to prior plan version - likely a session-cache replay. See ticket.",
            },
        )
    atomic_write_text(plan_dir / resolved_plan_filename, plan_text, _plan_dir=plan_dir)
    meta = {
        "version": version,
        "timestamp": now_utc(),
        "hash": new_hash,
        **meta_fields,
        "structure_warnings": structure_warnings,
    }
    atomic_write_json(plan_dir / meta_filename, meta, _plan_dir=plan_dir)
    return resolved_plan_filename, meta_filename, meta


def _validate_generated_plan_or_raise(
    *,
    plan_dir: Path,
    state: PlanState,
    step: str,
    iteration: int,
    worker: WorkerResult,
    plan_text: str,
) -> list[str]:
    structure_warnings = validate_plan_structure(plan_text)
    if PLAN_STRUCTURE_REQUIRED_STEP_ISSUE in structure_warnings:
        retry_next = [step] if step in {"plan", "revise"} else infer_next_steps(state)
        error = CliError(
            "structure_error",
            f"{step.title()} output failed structural validation: {PLAN_STRUCTURE_REQUIRED_STEP_ISSUE}",
            valid_next=retry_next,
            extra={"raw_output": worker.raw_output},
        )
        record_step_failure(
            plan_dir,
            state,
            step=step,
            iteration=iteration,
            error=error,
            duration_ms=worker.duration_ms,
        )
        raise error
    return structure_warnings
