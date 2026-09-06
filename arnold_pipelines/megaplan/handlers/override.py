from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from arnold_pipelines.megaplan.feature_flags import control_interface_routing_on
from arnold_pipelines.megaplan.profiles import (
    CONTINUATION_RUNTIME_MODEL_SPEC,
    CONTINUATION_RUNTIME_PROFILE,
    DEFAULT_AGENT_ROUTING,
    ROBUSTNESS_ACCEPTED,
    effective_premium_vendor,
    normalize_robustness,
)
from arnold_pipelines.megaplan.fallback_chains import decode_phase_model_value, select_fallback_spec
from arnold_pipelines.megaplan.types import (
    AgentSpec,
    CliError,
    PlanState,
    StepResponse,
    _PREMIUM_EFFORT_TOKENS,
    _PREMIUM_VENDORS,
    is_premium_placeholder_spec,
    parse_agent_spec,
    format_agent_spec,
    resolve_premium_placeholder_spec,
)
from arnold_pipelines.megaplan.planning.state import (
    STATE_ABORTED,
    STATE_AWAITING_HUMAN,
    STATE_BLOCKED,
    STATE_CRITIQUED,
    STATE_DONE,
    STATE_EXECUTED,
    STATE_FAILED,
    STATE_FINALIZED,
    STATE_GATED,
    STATE_PLANNED,
    STATE_PREPPED,
)
from arnold_pipelines.megaplan.runtime.execution_environment import (
    preflight_mutating_phase,
    preflight_phase,
)
from arnold_pipelines.megaplan.custody.phase_wbc import (
    resume_clarification_phase_wbc_if_present,
)
from arnold_pipelines.megaplan._core import (
    append_history,
    infer_next_steps,
    latest_plan_path,
    load_plan,
    now_utc,
    read_json,
    save_state_merge_meta,
    sha256_file,
    workflow_next,
)
from arnold_pipelines.megaplan._core import topology as _topology
from arnold.control.interface import ControlTransition, RunStateView
from arnold_pipelines.megaplan.control_interface import (
    apply_transition,
    emit_override_authority_receipt,
)
from arnold_pipelines.megaplan.blocker_recovery import (
    command_blocker_details,
    commit_bound_phase_repair_required,
    compact_failure_identity,
    evaluate_blocker_recovery,
    validated_deterministic_phase_repair,
)
from arnold_pipelines.megaplan.orchestration.gate_checks import (
    has_high_complexity_unverifiable_checks,
    is_operational_unverifiable_check,
    only_agent_availability_preflight_failed,
)
from arnold_pipelines.megaplan.workflows.handler_contract import (
    apply_response_projection,
    apply_state_projection,
)
from arnold_pipelines.megaplan.orchestration.phase_result import (
    ExitKind,
    PhaseResult,
    atomic_write_phase_result,
    read_phase_result,
)
from arnold_pipelines.megaplan.replan_state import (
    CAP_REVISE_ONCE_GRANT_KEY,
    blocked_iterate_gate_replan_allowed,
    cap_revise_once_override_allowed,
    events_max_seq,
    gate_signals_baseline,
    invalidate_replan_derived_artifacts,
    reset_replan_loop_state,
)
from .shared import _append_to_meta, _attach_next_step_runtime, _warn_best_effort_emit_failure


_REVISE_STRUCTURAL_OVERRIDE_ACTIONS = {"step-add", "step-remove", "step-move", "replan"}
@dataclass(frozen=True)
class UnknownOverrideActionError(ValueError):
    action: str

    def __str__(self) -> str:
        return f"Unknown override action: {self.action}"


@dataclass(frozen=True)
class OverrideActionOutput:
    summary: str
    state: str
    route_signal: str | None = None
    next_step: str | None = None
    extras: tuple[tuple[str, Any], ...] = ()


def _override_action_entry(action: str):
    from arnold_pipelines.megaplan.workflows.override_matrix import get_entry

    return get_entry(action)


def _control_routed_override_actions() -> frozenset[str]:
    from arnold_pipelines.megaplan.workflows.override_matrix import CONTROL_ROUTED_ACTIONS

    return CONTROL_ROUTED_ACTIONS


def _route_signal_for_override_action(action: str) -> str | None:
    from arnold_pipelines.megaplan.workflows.override_matrix import ROUTE_SIGNAL_BY_ACTION

    return ROUTE_SIGNAL_BY_ACTION.get(action)


def _archive_stale_phase_result_for_resume(plan_dir: Path) -> str | None:
    """Move the terminal phase_result aside before resuming a blocked plan.

    ``recover-blocked`` changes ``state.current_state`` back to the predecessor
    phase. Keeping the old terminal ``phase_result.json`` in place makes status
    and blocker-recovery read contradictory evidence from the superseded blocked
    phase.
    """

    phase_result_path = plan_dir / "phase_result.json"
    if not phase_result_path.exists():
        return None
    stamp = (
        now_utc()
        .replace("-", "")
        .replace(":", "")
        .replace(".", "")
    )
    backup_path = plan_dir / f"phase_result.recovered-{stamp}.json"
    suffix = 1
    while backup_path.exists():
        backup_path = plan_dir / f"phase_result.recovered-{stamp}-{suffix}.json"
        suffix += 1
    phase_result_path.replace(backup_path)
    return backup_path.name


def _override_response_owns_next_step(action: str) -> bool:
    try:
        return _override_action_entry(action).family != "terminal_route"
    except KeyError:
        return action not in _control_routed_override_actions()


def _build_override_action_output(
    action: str,
    *,
    plan_dir: Path,
    state: PlanState,
    args: argparse.Namespace,
    artifacts: dict[str, Any] | None = None,
) -> OverrideActionOutput:
    next_steps = infer_next_steps(state)
    try:
        route_signal = _override_action_entry(action).route_signal
    except KeyError as error:
        raise UnknownOverrideActionError(action) from error
    if action == "add-note":
        return OverrideActionOutput(
            summary="Attached note to the plan.",
            state=state["current_state"],
            route_signal=route_signal,
            next_step=next_steps[0] if next_steps else None,
        )
    if action == "abort":
        return OverrideActionOutput(
            summary="Plan aborted.",
            state=STATE_ABORTED,
            route_signal=route_signal,
        )
    if action == "force-proceed":
        meta = state.get("meta")
        overrides = meta.get("overrides", []) if isinstance(meta, dict) else []
        latest_override = next(
            (
                entry
                for entry in reversed(overrides)
                if isinstance(entry, dict) and entry.get("action") == "force-proceed"
            ),
            {},
        )
        if state["current_state"] == STATE_DONE:
            return OverrideActionOutput(
                summary="Force-proceeded past review into done state.",
                state=STATE_DONE,
                route_signal=route_signal,
            )
        return OverrideActionOutput(
            summary="Force-proceeded past gate judgment into gated state.",
            state=STATE_GATED,
            route_signal=route_signal,
            next_step="finalize",
            extras=(
                (
                    "orchestrator_guidance",
                    (artifacts or {}).get(
                        "orchestrator_guidance",
                        "Force-proceed override applied. Proceed to finalize.",
                    ),
                ),
                (
                    "debt_entries_added",
                    (artifacts or {}).get(
                        "debt_entries_added",
                        latest_override.get("debt_entries_added", 0),
                    ),
                ),
            ),
        )
    if action == "set-robustness":
        previous_level = "standard"
        meta = state.get("meta")
        overrides = meta.get("overrides", []) if isinstance(meta, dict) else []
        for entry in reversed(overrides):
            if isinstance(entry, dict) and entry.get("action") == "set-robustness":
                previous_level = entry.get("from", "standard")
                break
        new_level = state["config"].get("robustness", "standard")
        summary = (
            f"Robustness unchanged at '{new_level}'."
            if previous_level == new_level
            else f"Robustness changed from '{previous_level}' to '{new_level}'. Takes effect on the next phase."
        )
        return OverrideActionOutput(
            summary=summary,
            state=state["current_state"],
            route_signal=route_signal,
            next_step=next_steps[0] if next_steps else None,
            extras=(("previous_robustness", previous_level), ("robustness", new_level)),
        )
    if action == "recover-blocked":
        meta = state.get("meta")
        overrides = meta.get("overrides", []) if isinstance(meta, dict) else []
        latest_override = next(
            entry
            for entry in reversed(overrides)
            if isinstance(entry, dict) and entry.get("action") == "recover-blocked"
        )
        resume_cursor = latest_override.get("resume_cursor")
        phase = (
            resume_cursor.get("phase")
            if isinstance(resume_cursor, dict)
            else latest_override.get("phase")
        )
        return OverrideActionOutput(
            summary=(
                f"Recovered blocked plan to state '{state['current_state']}' for phase "
                f"{phase!r}. Reason: {latest_override.get('reason')}"
            ),
            state=state["current_state"],
            route_signal=route_signal,
            next_step=next_steps[0] if next_steps else None,
            extras=(
                ("action", "recover-blocked"),
                ("previous_state", latest_override.get("from_state")),
                ("phase", phase),
                ("resume_cursor", resume_cursor),
                ("blockers", (artifacts or {}).get("blockers", [])),
            ),
        )
    if action == "resume-clarify":
        warnings = (artifacts or {}).get("warnings", [])
        extras: list[tuple[str, Any]] = []
        if warnings:
            extras.append(("warnings", warnings))
        reentry_invocation_id = (artifacts or {}).get(
            "phase_wbc_reentry_invocation_id"
        )
        if isinstance(reentry_invocation_id, str) and reentry_invocation_id:
            extras.append(
                (
                    "phase_wbc_reentry_invocation_id",
                    reentry_invocation_id,
                )
            )
        return OverrideActionOutput(
            summary="Prep clarification resolved; plan phase is now ready to run.",
            state=STATE_PREPPED,
            route_signal=route_signal,
            next_step=next_steps[0] if next_steps else None,
            extras=tuple(extras),
        )
    if action == "replan":
        reason = getattr(args, "reason", None) or getattr(args, "note", None) or "Re-entering planning loop"
        plan_file_raw = (artifacts or {}).get("plan_file")
        plan_file = Path(plan_file_raw) if isinstance(plan_file_raw, str) and plan_file_raw else latest_plan_path(plan_dir, state)
        return OverrideActionOutput(
            summary=f"Re-entered planning loop at iteration {state['iteration']}. Reason: {reason}",
            state=STATE_PLANNED,
            route_signal=route_signal,
            extras=(
                ("plan_file", str(plan_file)),
                ("message", f"Edit {plan_file.name} to incorporate your changes, then run the next step."),
            ),
        )
    if action == "set-profile":
        previous_profile = None
        meta = state.get("meta")
        overrides = meta.get("overrides", []) if isinstance(meta, dict) else []
        for entry in reversed(overrides):
            if isinstance(entry, dict) and entry.get("action") == "set-profile":
                previous_profile = entry.get("from")
                break
        new_profile = state["config"].get("profile")
        summary = (
            f"Profile unchanged at '{new_profile}'."
            if previous_profile == new_profile
            else f"Profile changed from '{previous_profile}' to '{new_profile}'. Takes effect on the next phase."
        )
        return OverrideActionOutput(
            summary=summary,
            state=state["current_state"],
            route_signal=route_signal,
            next_step=next_steps[0] if next_steps else None,
            extras=(
                ("previous_profile", previous_profile),
                ("profile", new_profile),
                (
                    "profile_refresh_receipt",
                    (artifacts or {}).get("profile_refresh_receipt"),
                ),
            ),
        )
    if action in {"set-model", "set-vendor"}:
        meta = state.get("meta")
        overrides = meta.get("overrides", []) if isinstance(meta, dict) else []
        latest_override = next(
            entry
            for entry in reversed(overrides)
            if isinstance(entry, dict) and entry.get("action") == action
        )
        phase = latest_override.get("phase")
        previous_spec = latest_override.get("previous_spec")
        new_spec = latest_override.get("new_spec")
        summary = (
            f"{'Model' if action == 'set-model' else 'Vendor'} for phase '{phase}' "
            f"changed from '{previous_spec}' to '{new_spec}'. Takes effect on the next phase."
        )
        return OverrideActionOutput(
            summary=summary,
            state=state["current_state"],
            route_signal=route_signal,
            next_step=next_steps[0] if next_steps else None,
            extras=(("phase", phase), ("previous_spec", previous_spec), ("new_spec", new_spec)),
        )
    raise UnknownOverrideActionError(action)


def _routed_override_response(
    action: str,
    *,
    plan_dir: Path,
    state: PlanState,
    args: argparse.Namespace,
    artifacts: dict[str, Any] | None = None,
) -> StepResponse:
    try:
        action_output = _build_override_action_output(
            action,
            plan_dir=plan_dir,
            state=state,
            args=args,
            artifacts=artifacts,
        )
    except UnknownOverrideActionError as error:
        raise CliError("invalid_override", str(error)) from error
    response: StepResponse = {
        "success": True,
        "step": "override",
        "override_action": action,
        "summary": action_output.summary,
        "state": action_output.state,
    }
    if _override_response_owns_next_step(action) and action_output.next_step is not None:
        apply_response_projection(
            response,
            route_signal=str(action_output.route_signal or action),
            next_step=action_output.next_step,
        )
    if action_output.route_signal is not None:
        response["route_signal"] = action_output.route_signal
    for key, value in action_output.extras:
        response[key] = value
    if "next_step" in response:
        _attach_next_step_runtime(response)
    return response


def _emit_routed_override_events(
    action: str,
    *,
    plan_dir: Path,
    state: PlanState,
    args: argparse.Namespace,
) -> None:
    try:
        from arnold_pipelines.megaplan.observability.events import EventKind, emit

        if action == "add-note":
            note = getattr(args, "note", None)
            source = getattr(args, "source", None) or "user"
            emit(
                EventKind.OVERRIDE_APPLIED,
                plan_dir=plan_dir,
                payload={"action": "add-note", "reason": note, "source": source},
            )
            emit(
                EventKind.NOTE_ADDED,
                plan_dir=plan_dir,
                payload={"note": note, "source": source},
            )
            return
        if action == "abort":
            emit(
                EventKind.OVERRIDE_APPLIED,
                plan_dir=plan_dir,
                payload={"action": "abort", "reason": args.reason},
            )
            return
        if action == "force-proceed":
            emit(
                EventKind.OVERRIDE_APPLIED,
                plan_dir=plan_dir,
                payload={"action": "force-proceed", "reason": args.reason},
            )
            return
        if action == "set-robustness":
            meta = state.get("meta")
            overrides = meta.get("overrides", []) if isinstance(meta, dict) else []
            latest_override = next(
                entry
                for entry in reversed(overrides)
                if isinstance(entry, dict) and entry.get("action") == "set-robustness"
            )
            emit(
                EventKind.OVERRIDE_APPLIED,
                plan_dir=plan_dir,
                payload={
                    "action": "set-robustness",
                    "from": latest_override.get("from"),
                    "to": latest_override.get("to"),
                    "reason": latest_override.get("reason"),
                },
            )
            return
        if action == "set-profile":
            meta = state.get("meta")
            overrides = meta.get("overrides", []) if isinstance(meta, dict) else []
            latest_override = next(
                entry
                for entry in reversed(overrides)
                if isinstance(entry, dict) and entry.get("action") == "set-profile"
            )
            emit(
                EventKind.OVERRIDE_APPLIED,
                plan_dir=plan_dir,
                payload={
                    "action": "set-profile",
                    "from": latest_override.get("from"),
                    "to": latest_override.get("to"),
                    "reason": latest_override.get("reason"),
                },
            )
            return
        if action == "recover-blocked":
            return
        if action == "resume-clarify":
            emit(EventKind.OVERRIDE_APPLIED, plan_dir=plan_dir, payload={"action": "resume-clarify"})
            return
        if action == "replan":
            reason = getattr(args, "reason", None) or getattr(args, "note", None) or "Re-entering planning loop"
            emit(EventKind.OVERRIDE_APPLIED, plan_dir=plan_dir, payload={"action": "replan", "reason": reason})
            return
        if action in {"set-model", "set-vendor"}:
            return
    except StopIteration:
        pass
    except Exception:
        if action == "add-note":
            _warn_best_effort_emit_failure(
                "M3A_WARN_EMIT_OVERRIDE_ADD_NOTE",
                action="override-add-note",
                plan_dir=plan_dir,
                event_kind="override_applied,note_added",
                context={"source": getattr(args, "source", None) or "user"},
            )
            return
        if action == "abort":
            _warn_best_effort_emit_failure(
                "M3A_WARN_EMIT_OVERRIDE_ABORT",
                action="override-abort",
                plan_dir=plan_dir,
                event_kind="override_applied",
            )
            return
        if action == "force-proceed":
            _warn_best_effort_emit_failure(
                "M3A_WARN_EMIT_OVERRIDE_FORCE_PROCEED",
                action="override-force-proceed",
                plan_dir=plan_dir,
                event_kind="override_applied",
            )
            return
        if action == "set-robustness":
            _warn_best_effort_emit_failure(
                "M3A_WARN_EMIT_OVERRIDE_ROBUSTNESS",
                action="override-set-robustness",
                plan_dir=plan_dir,
                event_kind="override_applied",
            )
            return
        if action == "set-profile":
            _warn_best_effort_emit_failure(
                "M3A_WARN_EMIT_OVERRIDE_PROFILE",
                action="override-set-profile",
                plan_dir=plan_dir,
                event_kind="override_applied",
            )
            return
        if action == "replan":
            _warn_best_effort_emit_failure(
                "M3A_WARN_EMIT_OVERRIDE_REPLAN",
                action="override-replan",
                plan_dir=plan_dir,
                event_kind="override_applied",
            )
            return


def _normalize_override_response(action: str, response: StepResponse) -> StepResponse:
    normalized = dict(response)
    normalized.setdefault("override_action", action)
    route_signal = _route_signal_for_override_action(action)
    if route_signal is not None:
        normalized.setdefault("route_signal", route_signal)
    if not _override_response_owns_next_step(action):
        normalized.pop("next_step", None)
        normalized.pop("next_step_runtime", None)
    return normalized


def _handle_routed_override(
    root: Path,
    plan_dir: Path,
    state: PlanState,
    args: argparse.Namespace,
) -> StepResponse:
    if args.override_action == "replan":
        from arnold_pipelines.megaplan.planning.source_binding import (
            reconcile_canonical_source_for_replan,
        )

        reason = (
            getattr(args, "reason", None)
            or getattr(args, "note", None)
            or "Re-entering planning loop"
        )
        reconcile_canonical_source_for_replan(plan_dir, state, reason=reason)
        save_state_merge_meta(plan_dir, state)
    if args.override_action == "cutover":
        # CL5 Step 8c: the cutover reaches the SAME deferred cutover logic as
        # the default-path _override_cutover handler (Step 8b). Combined
        # authority (human-gate operator approval AND lifecycle mutation
        # authority via repair_queue) is enforced fail-closed FIRST, then the
        # deferred cutover orchestration runs before the control transition is
        # constructed. The deferred import inside _invoke_cutover_orchestration
        # keeps this special case Phase 1 safe (registration does not invoke
        # the not-yet-built package); invocation is Phase 2+ only. Both paths
        # therefore fail closed when either required authority is absent.
        _enforce_cutover_combined_authority(state, args)
        _invoke_cutover_orchestration(root, plan_dir, state, args)
    transition = ControlTransition(
        op="override",
        target_id=args.override_action,
        payload={
            "note": getattr(args, "note", None),
            "reason": getattr(args, "reason", None),
            "repair_commit": getattr(args, "repair_commit", None),
            "failure_fingerprint": getattr(args, "failure_fingerprint", None),
            "repair_scope": getattr(args, "repair_scope", None),
            "occurrence": getattr(args, "occurrence", None),
            "handoff_id": getattr(args, "handoff_id", None),
            "source": getattr(args, "source", None),
            "robustness": getattr(args, "robustness", None),
            "profile": getattr(args, "profile", None),
            "expected_profile_source": getattr(args, "expected_profile_source", None),
            "expected_profile_sha256": getattr(args, "expected_profile_sha256", None),
            "phase": getattr(args, "phase", None),
            "model": getattr(args, "model", None),
            "effort": getattr(args, "effort", None),
            "vendor": getattr(args, "vendor", None),
            "user_approved": getattr(args, "user_approved", False),
            "expected_state": getattr(args, "expected_state", None),
            "expected_iteration": getattr(args, "expected_iteration", None),
            "expected_max_event_seq": getattr(args, "expected_max_event_seq", None),
            "root": str(root),
            "plan_dir": str(plan_dir),
        },
    )
    run_state = RunStateView(
        run_id=state.get("name", plan_dir.name),
        cursor=state.get("current_state"),
        raw_state=state,
    )
    result = apply_transition(
        run_state,
        transition,
        "megaplan",
        plan_dir=plan_dir,
    )
    if not result.accepted:
        if result.reason == "control_transition_conflict":
            raise CliError(
                "invalid_transition",
                result.reason,
                extra={"conflict": result.artifacts.get("conflict")},
            )
        raise CliError("invalid_transition", result.reason or "routed override rejected")
    persisted_state = load_plan(root, args.plan)[1]
    archived_phase_result: str | None = None
    if args.override_action == "recover-blocked":
        archived_phase_result = _archive_stale_phase_result_for_resume(plan_dir)
        if archived_phase_result is not None:
            meta = persisted_state.get("meta")
            overrides = meta.get("overrides") if isinstance(meta, dict) else None
            if isinstance(overrides, list) and overrides:
                latest_override = overrides[-1]
                if (
                    isinstance(latest_override, dict)
                    and latest_override.get("action") == "recover-blocked"
                ):
                    latest_override["archived_phase_result"] = archived_phase_result
                    from arnold_pipelines.megaplan._core.state import write_plan_state

                    write_plan_state(plan_dir, mode="replace", state=persisted_state)
    _emit_routed_override_events(args.override_action, plan_dir=plan_dir, state=persisted_state, args=args)
    response = _routed_override_response(
        args.override_action,
        plan_dir=plan_dir,
        state=persisted_state,
        args=args,
        artifacts=dict(result.artifacts),
    )
    if archived_phase_result is not None:
        response["archived_phase_result"] = archived_phase_result
    return response


def _resolved_default_phase_spec(phase: str, state: PlanState, root: Path) -> str:
    """Return the concrete default routing spec for *phase*."""
    from arnold_pipelines.megaplan.profiles import effective_premium_vendor

    raw_spec = DEFAULT_AGENT_ROUTING.get(phase, "")
    if not raw_spec:
        return raw_spec
    project_dir = Path(state.get("config", {}).get("project_dir", str(root)))
    config = dict(state.get("config", {}))
    config.setdefault("project_dir", str(project_dir))
    resolved = resolve_premium_placeholder_spec(
        raw_spec,
        effective_premium_vendor(config=config),
    )
    return format_agent_spec(resolved)


def _resolved_default_phase_agent(phase: str, state: PlanState, root: Path) -> str:
    """Return the concrete default routing agent for *phase*."""
    default_spec = _resolved_default_phase_spec(phase, state, root)
    return parse_agent_spec(default_spec).agent if default_spec else ""


def _resolved_profile_phase_spec(phase: str, state: PlanState, root: Path) -> str:
    """Return the concrete expanded profile spec for *phase*, if any."""
    from arnold_pipelines.megaplan.profiles import apply_profile_expansion

    profile_name = state.get("config", {}).get("profile")
    if not profile_name:
        return ""

    project_dir = Path(state.get("config", {}).get("project_dir", str(root)))
    args = argparse.Namespace(
        profile=profile_name,
        phase_model=[],
        vendor=state.get("config", {}).get("vendor"),
        critic=state.get("config", {}).get("critic"),
        depth=state.get("config", {}).get("depth"),
        deepseek_provider=state.get("config", {}).get("deepseek_provider"),
        agent=None,
        omp=None,
        _profile_applied=False,
    )
    try:
        apply_profile_expansion(args, project_dir, state=state)
    except Exception:
        return ""

    for pm in args.phase_model or []:
        if isinstance(pm, str) and "=" in pm:
            pm_phase, pm_spec = pm.split("=", 1)
            if pm_phase == phase:
                return pm_spec
    return ""


def _last_gate_is_agent_availability_preflight_block(state: PlanState) -> bool:
    last_gate = state.get("last_gate") or {}
    if not isinstance(last_gate, dict):
        return False
    if last_gate.get("recommendation") != "PROCEED" or last_gate.get("passed", False):
        return False
    preflight_results = last_gate.get("preflight_results")
    return (
        isinstance(preflight_results, dict)
        and only_agent_availability_preflight_failed(preflight_results)
    )


def _latest_revise_start_iso(plan_dir: Path, state: PlanState) -> str | None:
    """Return the ISO-8601 timestamp of the most recent "absorption" event for
    user notes — i.e., the start of the latest revise, or the timestamp of the
    most recent structural-edit/replan override. Returns None when no
    absorption event has happened yet (in that case, every user note is
    unabsorbed).

    Notes with timestamps strictly greater than the returned cutoff are
    considered unabsorbed. When the cutoff is None, all user notes are
    treated as unabsorbed regardless of timestamp.
    """
    candidates: list[str] = []
    # Revise receipts: prefer metrics["start_timestamp_utc"] (added by the
    # strict-notes audit-fields change) but fall back to the receipt's
    # top-level timestamp_utc for back-compat with pre-existing receipts.
    for receipt_path in plan_dir.glob("step_receipt_revise_v*.json"):
        try:
            import json as _json

            data = _json.loads(receipt_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        metrics = data.get("metrics") if isinstance(data, dict) else None
        ts = None
        if isinstance(metrics, dict):
            ts = metrics.get("start_timestamp_utc")
        if not isinstance(ts, str) or not ts:
            ts = data.get("timestamp_utc") if isinstance(data, dict) else None
        if isinstance(ts, str) and ts:
            candidates.append(ts)
    # Structural-edit / replan overrides also "absorb" notes, since the user
    # can no longer be reasoning about a stale step list after a structural
    # change.
    for entry in state.get("meta", {}).get("overrides", []):
        if not isinstance(entry, dict):
            continue
        if entry.get("action") in _REVISE_STRUCTURAL_OVERRIDE_ACTIONS:
            ts = entry.get("timestamp")
            if isinstance(ts, str) and ts:
                candidates.append(ts)
    if candidates:
        return max(candidates)
    return None


def _unabsorbed_user_notes(plan_dir: Path, state: PlanState) -> list[dict]:
    cutoff = _latest_revise_start_iso(plan_dir, state)
    notes = state.get("meta", {}).get("notes", [])
    user_notes = [
        n
        for n in notes
        if isinstance(n, dict)
        and n.get("source", "user") == "user"
        and isinstance(n.get("timestamp"), str)
    ]
    if cutoff is None:
        return user_notes
    return [n for n in user_notes if n["timestamp"] > cutoff]


def _override_add_note(
    root: Path, plan_dir: Path, state: PlanState, args: argparse.Namespace
) -> StepResponse:
    note = args.note
    source = getattr(args, "source", None) or "user"
    note_entry: dict[str, Any] = {
        "timestamp": now_utc(),
        "note": note,
        "source": source,
    }
    _append_to_meta(state, "notes", note_entry)
    _append_to_meta(
        state,
        "overrides",
        {"action": "add-note", "timestamp": now_utc(), "note": note, "source": source},
    )
    # Merge so a phase that saves between our load and write doesn't clobber
    # this note (and so we don't clobber any concurrent-override appends).
    save_state_merge_meta(plan_dir, state, preserve_disk_non_meta=True)
    next_steps = infer_next_steps(state)
    # Emit observability events
    try:
        from arnold_pipelines.megaplan.observability.events import emit, EventKind
        emit(EventKind.OVERRIDE_APPLIED, plan_dir=plan_dir, payload={"action": "add-note", "reason": note, "source": source})
        emit(EventKind.NOTE_ADDED, plan_dir=plan_dir, payload={"note": note, "source": source})
    except Exception:
        _warn_best_effort_emit_failure(
            "M3A_WARN_EMIT_OVERRIDE_ADD_NOTE",
            action="override-add-note",
            plan_dir=plan_dir,
            event_kind="override_applied,note_added",
            context={"source": source},
        )
    response: StepResponse = {
        "success": True,
        "step": "override",
        "summary": "Attached note to the plan.",
        "next_step": next_steps[0] if next_steps else None,
        "state": state["current_state"],
    }
    _attach_next_step_runtime(response)
    return response


def _override_abort(
    root: Path, plan_dir: Path, state: PlanState, args: argparse.Namespace
) -> StepResponse:
    apply_state_projection(state, STATE_ABORTED, route_signal="abort")
    _append_to_meta(
        state,
        "overrides",
        {"action": "abort", "timestamp": now_utc(), "reason": args.reason},
    )
    save_state_merge_meta(plan_dir, state)
    try:
        from arnold_pipelines.megaplan.observability.events import emit, EventKind
        emit(EventKind.OVERRIDE_APPLIED, plan_dir=plan_dir, payload={"action": "abort", "reason": args.reason})
    except Exception:
        _warn_best_effort_emit_failure(
            "M3A_WARN_EMIT_OVERRIDE_ABORT",
            action="override-abort",
            plan_dir=plan_dir,
            event_kind="override_applied",
        )
    return {
        "success": True,
        "step": "override",
        "summary": "Plan aborted.",
        "state": STATE_ABORTED,
    }


def _execution_adoption_summary(plan_dir: Path) -> dict[str, Any]:
    execution_path = plan_dir / "execution.json"
    finalize_path = plan_dir / "finalize.json"
    if not execution_path.exists():
        raise CliError(
            "incomplete_execution_artifact",
            "adopt-execution requires execution.json to exist",
            extra={"missing": ["execution.json"]},
        )
    if not finalize_path.exists():
        raise CliError(
            "incomplete_execution_artifact",
            "adopt-execution requires finalize.json to exist",
            extra={"missing": ["finalize.json"]},
        )

    execution = read_json(execution_path)
    finalize = read_json(finalize_path)
    if not isinstance(execution, dict) or not isinstance(finalize, dict):
        raise CliError(
            "incomplete_execution_artifact",
            "adopt-execution requires object execution.json and finalize.json payloads",
        )

    finalize_tasks = [task for task in finalize.get("tasks", []) if isinstance(task, dict)]
    task_ids = {
        str(task.get("id"))
        for task in finalize_tasks
        if isinstance(task.get("id"), str) and task.get("id")
    }
    updates = [
        update
        for update in execution.get("task_updates", [])
        if isinstance(update, dict)
    ]
    updates_by_id: dict[str, dict[str, Any]] = {}
    blocked_task_ids: set[str] = set()
    for update in updates:
        task_id = update.get("task_id") or update.get("id")
        if not isinstance(task_id, str) or not task_id:
            continue
        updates_by_id[task_id] = update
        if update.get("status") == "blocked":
            blocked_task_ids.add(task_id)

    missing_task_updates = sorted(task_ids - set(updates_by_id))
    incomplete_task_updates = sorted(
        task_id
        for task_id in task_ids & set(updates_by_id)
        if updates_by_id[task_id].get("status") != "done"
    )
    incomplete_finalize_tasks = sorted(
        str(task.get("id"))
        for task in finalize_tasks
        if isinstance(task.get("id"), str) and task.get("status") != "done"
    )
    blocked_task_ids.update(
        str(task.get("id"))
        for task in finalize_tasks
        if isinstance(task.get("id"), str) and task.get("status") == "blocked"
    )

    finalize_checks = [
        check for check in finalize.get("sense_checks", []) if isinstance(check, dict)
    ]
    sense_check_ids = {
        str(check.get("id"))
        for check in finalize_checks
        if isinstance(check.get("id"), str) and check.get("id")
    }
    ack_ids: set[str] = set()
    for ack in execution.get("sense_check_acknowledgments", []):
        if not isinstance(ack, dict):
            continue
        check_id = ack.get("sense_check_id") or ack.get("id")
        if isinstance(check_id, str) and check_id:
            ack_ids.add(check_id)
    missing_sense_check_acknowledgments = sorted(sense_check_ids - ack_ids)

    failures = {
        "missing_task_updates": missing_task_updates,
        "incomplete_task_updates": incomplete_task_updates,
        "incomplete_finalize_tasks": incomplete_finalize_tasks,
        "blocked_task_ids": sorted(blocked_task_ids),
        "missing_sense_check_acknowledgments": missing_sense_check_acknowledgments,
    }
    failures = {key: value for key, value in failures.items() if value}
    if failures:
        raise CliError(
            "incomplete_execution_artifact",
            "adopt-execution refused because execution.json is not complete",
            extra=failures,
        )

    return {
        "task_count": len(task_ids),
        "sense_check_count": len(sense_check_ids),
        "execution_hash": sha256_file(execution_path),
        "finalize_hash": sha256_file(finalize_path),
    }


def _override_adopt_execution(
    root: Path, plan_dir: Path, state: PlanState, args: argparse.Namespace
) -> StepResponse:
    previous_state = state["current_state"]
    summary = _execution_adoption_summary(plan_dir)
    reason = args.reason or "Adopted complete execution artifact after post-worker recovery."
    timestamp = now_utc()

    apply_state_projection(state, STATE_EXECUTED, route_signal="adopt-execution")
    state.pop("resume_cursor", None)
    state.pop("active_step", None)
    adoption_record = {
        "action": "adopt-execution",
        "timestamp": timestamp,
        "reason": reason,
        "from_state": previous_state,
        "to_state": STATE_EXECUTED,
        **summary,
    }
    _append_to_meta(state, "overrides", adoption_record)
    append_history(
        state,
        {
            "step": "execute",
            "timestamp": timestamp,
            "duration_ms": 0,
            "cost_usd": 0.0,
            "result": "success",
            "output_file": "execution.json",
            "artifact_hash": summary["execution_hash"],
            "finalize_hash": summary["finalize_hash"],
            "message": f"adopted complete execution artifact via override: {reason}",
        },
    )
    save_state_merge_meta(plan_dir, state)

    existing_phase_result = read_phase_result(plan_dir)
    invocation_id = (
        existing_phase_result.invocation_id
        if existing_phase_result is not None and existing_phase_result.phase == "execute"
        else f"adopt-execution:{timestamp}"
    )
    artifacts = ["execution.json", "finalize.json"]
    for optional_name in ("execution_audit.json", "final.md"):
        if (plan_dir / optional_name).exists():
            artifacts.append(optional_name)
    atomic_write_phase_result(
        plan_dir,
        PhaseResult(
            phase="execute",
            invocation_id=invocation_id,
            exit_kind=ExitKind.success.value,
            artifacts_written=tuple(artifacts),
            cli_provenance={
                "command": "override adopt-execution",
                "reason": reason,
                "previous_state": previous_state,
                "adopted": True,
                **summary,
            },
        ),
    )

    response: StepResponse = {
        "success": True,
        "step": "override",
        "action": "adopt-execution",
        "summary": (
            "Adopted complete execution.json and promoted plan state to executed "
            f"({summary['task_count']} tasks, {summary['sense_check_count']} sense checks)."
        ),
        "state": STATE_EXECUTED,
        "previous_state": previous_state,
    }
    return response


def _override_replan(
    root: Path, plan_dir: Path, state: PlanState, args: argparse.Namespace
) -> StepResponse:
    allowed = {STATE_GATED, STATE_FINALIZED, STATE_CRITIQUED, STATE_FAILED}
    previous_state = state["current_state"]
    blocked_gate_replan = blocked_iterate_gate_replan_allowed(state)
    if previous_state not in allowed and not blocked_gate_replan:
        raise CliError(
            "invalid_transition",
            f"replan requires state {', '.join(sorted(allowed))}, got '{previous_state}'",
            valid_next=infer_next_steps(state),
        )
    reason = args.reason or args.note or "Re-entering planning loop"
    plan_file = latest_plan_path(plan_dir, state)
    timestamp = now_utc()
    _append_to_meta(
        state,
        "overrides",
        {
            "action": "replan",
            "timestamp": timestamp,
            "reason": reason,
            "from_state": previous_state,
            "plan_file": plan_file.name,
        },
    )
    if args.note:
        _append_to_meta(state, "notes", {"timestamp": timestamp, "note": args.note})
    from arnold_pipelines.megaplan.planning.source_binding import (
        reconcile_canonical_source_for_replan,
    )

    source_reconciliation = reconcile_canonical_source_for_replan(
        plan_dir,
        state,
        reason=reason,
    )
    artifact_invalidation = invalidate_replan_derived_artifacts(
        plan_dir,
        timestamp=timestamp,
        include_critique_epoch=True,
        include_gate_epoch=True,
    )
    reset_replan_loop_state(state, target_state=STATE_PLANNED)
    save_state_merge_meta(plan_dir, state)
    try:
        from arnold_pipelines.megaplan.observability.events import emit, EventKind
        emit(EventKind.OVERRIDE_APPLIED, plan_dir=plan_dir, payload={"action": "replan", "reason": reason})
    except Exception:
        _warn_best_effort_emit_failure(
            "M3A_WARN_EMIT_OVERRIDE_REPLAN",
            action="override-replan",
            plan_dir=plan_dir,
            event_kind="override_applied",
        )
    response: StepResponse = {
        "success": True,
        "step": "override",
        "summary": f"Re-entered planning loop at iteration {state['iteration']}. Reason: {reason}",
        "state": STATE_PLANNED,
        "plan_file": str(plan_file),
        "message": f"Edit {plan_file.name} to incorporate your changes, then run the next step.",
    }
    if source_reconciliation is not None:
        response["canonical_source_binding"] = source_reconciliation
    if artifact_invalidation is not None:
        response["artifact_invalidation"] = artifact_invalidation
    return response


def _verify_cap_revise_once_fence(
    state: PlanState, plan_dir: Path, args: argparse.Namespace
) -> None:
    """CAS fences for ``cap-revise-once``: state, iteration, events seq.

    The events fence tolerates exactly one self-write: handle_override
    persists preflight isolation metadata via ``save_state_merge_meta``
    BEFORE the handler runs, recording one ``state_written`` event per
    invocation. A concurrent driver/worker produces far more journal
    progress than one event, so the fence still fails closed on genuine
    third-party mutation.
    """

    expected_state = getattr(args, "expected_state", None)
    if expected_state is not None and state.get("current_state") != expected_state:
        raise CliError(
            "state_drift",
            f"cap-revise-once fence: expected state '{expected_state}', found "
            f"'{state.get('current_state')}'",
        )
    expected_iteration = getattr(args, "expected_iteration", None)
    if (
        expected_iteration is not None
        and state.get("iteration") != expected_iteration
    ):
        raise CliError(
            "iteration_drift",
            f"cap-revise-once fence: expected iteration {expected_iteration}, "
            f"found {state.get('iteration')}",
        )
    expected_seq = getattr(args, "expected_max_event_seq", None)
    if expected_seq is not None:
        live_seq = events_max_seq(plan_dir)
        if live_seq is None or live_seq > int(expected_seq) + 1:
            raise CliError(
                "event_seq_drift",
                "cap-revise-once fence: events advanced past the fenced seq "
                f"(expected max {expected_seq} (+1 self-write), found "
                f"{live_seq})",
            )


def _override_cap_revise_once(
    root: Path, plan_dir: Path, state: PlanState, args: argparse.Namespace
) -> StepResponse:
    """Grant exactly one revise round after a critique-cap blocked park.

    Sol-adjudicated bounded operator correction seam (occurrence
    7ce9c04b5100): the override lands in ``critiqued`` with the gate/critique
    custody PRESERVED so ordinary revise authors the next revision; the global
    critique cap, the terminate guard, and every flag stay untouched. The
    grant is one-shot, CAS-fenced via the --expected-* flags, and records the
    open-significant baseline the consuming gate must strictly decrease.
    """

    if not cap_revise_once_override_allowed(state):
        raise CliError(
            "invalid_transition",
            (
                "cap-revise-once requires a critique-cap blocked park: state "
                "'blocked', last_gate recommendation 'ITERATE' with passed=false, "
                "cap termination as the newest history entry, no resume cursor "
                "or failure record, and no unconsumed grant; got state "
                f"'{state.get('current_state')}'"
            ),
            valid_next=infer_next_steps(state),
        )
    _verify_cap_revise_once_fence(state, plan_dir, args)
    try:
        baseline = gate_signals_baseline(plan_dir, state.get("iteration"))
    except ValueError as error:
        raise CliError("cap_revise_once_baseline_missing", str(error))
    reason = (
        getattr(args, "reason", None)
        or "Grant one bounded revise round after critique-cap block"
    )
    occurrence = getattr(args, "occurrence", None)
    timestamp = now_utc()
    prior_grants = 0
    meta = state.get("meta")
    if isinstance(meta, Mapping):
        prior = meta.get(CAP_REVISE_ONCE_GRANT_KEY)
        if isinstance(prior, Mapping):
            prior_grants = int(prior.get("grant_seq") or 0)
    grant = {
        "schema": "megaplan.cap_revise_once_grant.v1",
        "grant_seq": prior_grants + 1,
        "granted_at": timestamp,
        "reason": reason,
        "occurrence": occurrence,
        "iteration_at_grant": state.get("iteration"),
        "consumed": False,
        **baseline,
    }
    _append_to_meta(
        state,
        "overrides",
        {
            "action": "cap-revise-once",
            "timestamp": timestamp,
            "reason": reason,
            "from_state": state["current_state"],
            "occurrence": occurrence,
            "baseline_flag_count": baseline["baseline_flag_count"],
            "baseline_digest": baseline["baseline_digest"],
        },
    )
    state["meta"][CAP_REVISE_ONCE_GRANT_KEY] = grant
    # Keep the route transition on the workflow-owned projection surface; the
    # handler records the grant, but does not make a local route decision.
    apply_state_projection(state, STATE_CRITIQUED, route_signal="cap_revise_once")
    save_state_merge_meta(plan_dir, state)
    try:
        from arnold_pipelines.megaplan.observability.events import emit, EventKind

        emit(
            EventKind.OVERRIDE_APPLIED,
            plan_dir=plan_dir,
            payload={"action": "cap-revise-once", "reason": reason},
        )
    except Exception:
        _warn_best_effort_emit_failure(
            "M3A_WARN_EMIT_OVERRIDE_CAP_REVISE_ONCE",
            action="override-cap-revise-once",
            plan_dir=plan_dir,
            event_kind="override_applied",
        )
    return {
        "success": True,
        "step": "override",
        "summary": (
            "Granted exactly one revise → critique → gate round after the "
            f"critique-cap block (baseline {baseline['baseline_flag_count']} "
            f"open significant flags, digest {baseline['baseline_digest']}). "
            "The cap still applies at the consuming gate; without a strict "
            "significant-flag decrease it blocks as cap_revise_no_progress."
        ),
        "state": STATE_CRITIQUED,
        "grant": grant,
        "message": (
            "Ordinary revise authors the next revision from the preserved "
            "critique custody; the consuming gate re-blocks unless it proceeds."
        ),
    }


_EXTERNAL_ERROR_RETRY_STRATEGIES = {"wait_and_retry", "check_provider_and_retry"}


def _external_error_requires_resume(
    state: PlanState,
    resume_cursor: dict[str, Any],
    phase_result: Any | None,
) -> bool:
    latest_failure = state.get("latest_failure")
    # Deterministic provider response-contract failures have their own
    # commit/fingerprint-bound recovery gate below.  A generic provider resume
    # would bypass that evidence and replay the same invalid request.
    if (
        isinstance(latest_failure, dict)
        and latest_failure.get("kind") == "provider_contract_failure"
        and resume_cursor.get("retry_strategy") == "repair_provider_contract"
    ):
        return False
    if (
        isinstance(latest_failure, dict)
        and latest_failure.get("kind") == "external_error"
    ):
        return True
    if getattr(phase_result, "exit_kind", None) == "external_error":
        return True
    return resume_cursor.get("retry_strategy") in _EXTERNAL_ERROR_RETRY_STRATEGIES


def _last_gate_is_operational_unverifiable_block(state: PlanState) -> bool:
    last_gate = state.get("last_gate")
    if not isinstance(last_gate, dict):
        return False
    if last_gate.get("recommendation") != "ITERATE" or last_gate.get("passed") is not False:
        return False

    signals = last_gate.get("signals")
    if not isinstance(signals, dict):
        history = state.get("meta", {}).get("critique_unverifiable_checks", [])
        if isinstance(history, list) and history:
            latest = history[-1]
            if isinstance(latest, dict):
                signals = {"unverifiable_checks": latest.get("checks", [])}
    if not isinstance(signals, dict):
        return False

    checks = signals.get("unverifiable_checks", [])
    if not isinstance(checks, list):
        return False
    high_complexity = [
        check
        for check in checks
        if isinstance(check, dict)
        and check.get("attention") == "high_complexity_unverifiable"
    ]
    return bool(high_complexity) and (
        not has_high_complexity_unverifiable_checks(signals)
        and all(is_operational_unverifiable_check(check) for check in high_complexity)
    )


def _blocked_plan_has_operational_unverifiable_evidence(
    plan_dir: Path, state: PlanState
) -> bool:
    if _last_gate_is_operational_unverifiable_block(state):
        return True

    history = state.get("meta", {}).get("critique_unverifiable_checks", [])
    if not isinstance(history, list) or not history:
        return False
    latest = history[-1]
    if not isinstance(latest, dict):
        return False
    checks = latest.get("checks", [])
    if not isinstance(checks, list):
        return False

    for check in checks:
        if not isinstance(check, dict):
            continue
        if check.get("attention") != "high_complexity_unverifiable":
            continue
        check_id = str(check.get("id", "")).strip()
        if not check_id:
            continue
        raw_path = plan_dir / f"critique_check_{check_id}_raw.txt"
        if not raw_path.exists():
            continue
        try:
            raw_text = raw_path.read_text(encoding="utf-8")
        except OSError:
            continue
        if is_operational_unverifiable_check({"reason": raw_text}):
            return True
    return False


_LEGACY_DETERMINISTIC_PHASE_ADMISSION_SCHEMA = (
    "arnold.superfixer.phase_repair_admission.v1"
)


def _engine_root_for_admission() -> str:
    """Return the running megaplan engine root for the admission record."""
    try:
        from arnold_pipelines.megaplan.runtime.process import megaplan_engine_root

        return str(megaplan_engine_root())
    except Exception:
        return ""


def _reconstruct_failure_occurrence_digest(
    latest_failure: Mapping[str, Any],
) -> str:
    """Reconstruct the watchdog occurrence digest for a latest_failure.

    Mirrors ``arnold-watchdog`` ``_failure_digest_src`` exactly (kind /
    phase / message / phase_or_step / blocked_task_id) so a recovery
    admission can be CAS-fenced against the occurrence the watchdog bound
    at dispatch time.
    """

    metadata = latest_failure.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    source = {
        "kind": str(latest_failure.get("kind") or ""),
        "phase": str(latest_failure.get("phase") or ""),
        "message": str(latest_failure.get("message") or ""),
        "phase_or_step": str(metadata.get("phase_or_step") or ""),
        "blocked_task_id": str(metadata.get("blocked_task_id") or ""),
    }
    return hashlib.sha256(
        json.dumps(source, sort_keys=True).encode("utf-8")
    ).hexdigest()[:12]


def _materialize_legacy_deterministic_phase_cursor(
    plan_dir: Path,
    state: PlanState,
    args: argparse.Namespace,
    *,
    root: Path | None = None,
) -> dict[str, Any] | None:
    """CAS-fenced compatibility admission for an exact blocked
    ``deterministic_phase_failure`` whose reconstructed occurrence digest
    matches and whose cursor is absent.

    Legacy/synthetic producers (and manual state surgery) can persist
    ``current_state=blocked`` with a ``deterministic_phase_failure`` but no
    ``resume_cursor``/retry metadata.  The supported recover-blocked seam
    fails closed on those states even though the no-op guard permits
    recovery.  When the caller binds the exact occurrence digest (watchdog
    ``_failure_digest_src`` reconstruction) and the content-addressed
    recovery handoff id, atomically materialize the missing repair identity
    and ``resume_cursor {phase, retry_strategy: repair_phase_contract}``
    WITHOUT clearing the failure or changing ``current_state``.

    Returns the durable admission record when the admission was applied, or
    None when it does not apply (the caller keeps the existing fail-closed
    ``missing_resume_cursor`` behavior).  Raises CliError when the fence is
    engaged but the occurrence/state does not match.
    """

    latest_failure = state.get("latest_failure")
    if not isinstance(latest_failure, dict):
        return None
    if latest_failure.get("kind") != "deterministic_phase_failure":
        return None
    phase = str(latest_failure.get("phase") or "").strip()
    if not phase:
        return None
    if isinstance(state.get("resume_cursor"), dict):
        return None
    occurrence = getattr(args, "occurrence", None)
    handoff_id = getattr(args, "handoff_id", None)
    if not isinstance(occurrence, str) or not occurrence.strip():
        return None
    if not isinstance(handoff_id, str) or not handoff_id.strip():
        return None
    reconstructed = _reconstruct_failure_occurrence_digest(latest_failure)
    if reconstructed != occurrence.strip():
        raise CliError(
            "occurrence_digest_mismatch",
            "legacy deterministic-phase admission is CAS-fenced to the exact "
            "bound occurrence digest",
            extra={
                "expected_occurrence": occurrence.strip(),
                "reconstructed_occurrence": reconstructed,
                "latest_failure": dict(latest_failure),
            },
        )
    # CAS re-read: the on-disk state must still be the same minimal legacy
    # shape (no resume_cursor, same digest).  A concurrent writer that
    # already repaired the cursor must not be double-admitted.
    try:
        raw = (plan_dir / "state.json").read_text(encoding="utf-8")
    except OSError:
        raw = ""
    if raw:
        try:
            disk_state = json.loads(raw)
        except ValueError:
            disk_state = {}
        if isinstance(disk_state, dict):
            disk_failure = disk_state.get("latest_failure")
            if isinstance(disk_failure, dict) and (
                isinstance(disk_state.get("resume_cursor"), dict)
                or _reconstruct_failure_occurrence_digest(disk_failure)
                != reconstructed
            ):
                raise CliError(
                    "admission_state_drift",
                    "on-disk plan state changed between load and legacy "
                    "deterministic-phase admission",
                    extra={
                        "occurrence": occurrence.strip(),
                        "reconstructed_occurrence": reconstructed,
                    },
                )
    resume_cursor = {
        "phase": phase,
        "retry_strategy": "repair_phase_contract",
    }
    admission = {
        "schema": _LEGACY_DETERMINISTIC_PHASE_ADMISSION_SCHEMA,
        "occurrence_digest": occurrence.strip(),
        "handoff_id": handoff_id.strip(),
        "plan": state.get("name") or plan_dir.name,
        "admitted_at": now_utc(),
        "failure": {
            "kind": latest_failure.get("kind"),
            "phase": phase,
            "message": str(latest_failure.get("message") or ""),
        },
        "failure_fingerprint": str(
            compact_failure_identity(latest_failure).get("fingerprint") or ""
        ),
        "materialized": {"resume_cursor": dict(resume_cursor)},
        "engine_root": _engine_root_for_admission(),
        "repair_scope": "engine_runtime",
        "repair_commit": str(getattr(args, "repair_commit", None) or ""),
    }
    state["resume_cursor"] = dict(resume_cursor)
    # The legacy/synthetic record may also lack the minimal config the worker
    # preflight requires (config.project_dir).  Materialize it bound to the
    # plan's own project root so the supported seam can execute — the failure
    # and current_state remain untouched.
    config = state.setdefault("config", {})
    if not isinstance(config, dict):
        config = {}
        state["config"] = config
    if not str(config.get("project_dir") or "").strip() and root is not None:
        config["project_dir"] = str(root)
        admission["materialized"]["project_dir"] = str(root)
    meta = state.setdefault("meta", {})
    if not isinstance(meta, dict):
        meta = {}
        state["meta"] = meta
    meta.setdefault("phase_repair_admissions", []).append(admission)
    return admission


def _override_recover_blocked(
    root: Path, plan_dir: Path, state: PlanState, args: argparse.Namespace
) -> StepResponse:
    latest_failure = state.get("latest_failure")
    aborted_with_blocked_failure = (
        state["current_state"] == STATE_ABORTED
        and isinstance(latest_failure, dict)
        and latest_failure.get("state") == STATE_BLOCKED
    )
    if state["current_state"] != STATE_BLOCKED and not aborted_with_blocked_failure:
        raise CliError(
            "invalid_transition",
            f"recover-blocked requires state '{STATE_BLOCKED}', got '{state['current_state']}'",
            valid_next=infer_next_steps(state),
        )
    reason = getattr(args, "reason", None)
    if not isinstance(reason, str) or not reason.strip():
        raise CliError("invalid_args", "override recover-blocked requires --reason")
    resume_cursor = state.get("resume_cursor")
    if not isinstance(resume_cursor, dict):
        # Legacy/synthetic blocked deterministic-phase states may lack the
        # resume_cursor the current producer persists.  The supported
        # recover-blocked seam must not fail closed on those states when the
        # caller binds the exact occurrence digest and the content-addressed
        # handoff id — the CAS-fenced compatibility admission materializes
        # the missing repair identity and cursor WITHOUT clearing the
        # failure or changing current_state (see
        # _materialize_legacy_deterministic_phase_cursor).
        admission = _materialize_legacy_deterministic_phase_cursor(
            plan_dir, state, args
        )
        if admission is None:
            raise CliError(
                "missing_resume_cursor",
                "recover-blocked requires a stored resume_cursor",
            )
        resume_cursor = state.get("resume_cursor")
    phase = resume_cursor.get("phase")
    if not isinstance(phase, str) or not phase:
        raise CliError(
            "invalid_resume_cursor",
            "recover-blocked requires resume_cursor.phase",
            extra={"resume_cursor": resume_cursor},
        )
    recovered_state = _topology.predecessors(phase, policy="recovery")
    if recovered_state is None:
        raise CliError(
            "invalid_resume_cursor",
            f"recover-blocked does not know how to resume phase {phase!r}",
            extra={"resume_cursor": resume_cursor},
        )
    if isinstance(latest_failure, dict) and latest_failure.get("kind") == "authority_divergence":
        plan_name = state.get("name") or getattr(args, "plan", None) or plan_dir.name
        rerun_command = f"megaplan {phase} --plan {plan_name}"
        if phase == "execute":
            rerun_command += " --confirm-destructive --user-approved"
        raise CliError(
            "rerun_phase_required",
            (
                "recover-blocked is only for explicit task or quality blockers. "
                "This blocked plan needs a fresh phase rerun to regenerate "
                "authority evidence; do not use recover-blocked here."
            ),
            extra={
                "resume_cursor": resume_cursor,
                "latest_failure": dict(latest_failure),
                "rerun_command": rerun_command,
                "suggested_recovery_commands": [rerun_command],
            },
        )

    finalize_path = plan_dir / "finalize.json"
    finalize_data = read_json(finalize_path) if finalize_path.exists() else {}
    phase_result = read_phase_result(plan_dir)
    if _external_error_requires_resume(state, resume_cursor, phase_result):
        plan_name = state.get("name") or getattr(args, "plan", None) or plan_dir.name
        resume_command = f"megaplan resume --plan {plan_name}"
        raise CliError(
            "external_error_resume_required",
            (
                "recover-blocked is for explicit task or quality blockers. "
                "This blocked plan stopped on an external provider error; "
                f"fix provider/profile settings if needed, then run `{resume_command}`."
            ),
            extra={
                "resume_cursor": resume_cursor,
                "phase_result_exit_kind": (
                    getattr(phase_result, "exit_kind", None)
                    if phase_result is not None
                    else None
                ),
                "latest_failure": state.get("latest_failure"),
                "resume_command": resume_command,
                "suggested_recovery_commands": [resume_command],
            },
        )
    phase_repair_evidence: dict[str, str] | None = None
    artifact_invalidation: dict[str, Any] | None = None
    deterministic_phase_repair_required = commit_bound_phase_repair_required(
        latest_failure,
        resume_cursor,
    )
    if deterministic_phase_repair_required:
        # A deterministic phase failure is recorded specifically because the
        # current phase did not emit a usable phase_result.  A plan directory
        # can still contain phase_result.json from an earlier successful phase
        # or attempt (the r5 incident retained `revise` while `critique`
        # failed).  That stale artifact must not bypass the commit- and
        # failure-fingerprint-bound repair gate.
        phase_repair_evidence = validated_deterministic_phase_repair(
            root,
            state,
            resume_cursor,
            getattr(args, "repair_commit", None),
            getattr(args, "failure_fingerprint", None),
            getattr(args, "repair_scope", None),
        )
        if phase_repair_evidence is None:  # defensive: predicate above is exact
            raise CliError("missing_phase_result", "deterministic repair evidence is missing")
        blocker_details: list[dict[str, Any]] = []
        blocker_ids: list[str] = []
        # Re-entering a phase after a deterministic phase-contract repair
        # collides with the immutable versioned artifacts (critique_custody_v*.json
        # receipts for the critique phase, gate_v*.json projections for the gate
        # phase) published by the superseded attempt at the same iteration.
        # Archive the corresponding versioned phase family durably so the fresh
        # run can publish new evidence; the create-once/immutable invariant
        # still holds within the new planning epoch.
        if phase == "critique":
            artifact_invalidation = invalidate_replan_derived_artifacts(
                plan_dir,
                timestamp=now_utc(),
                include_critique_epoch=True,
            )
        elif phase == "gate":
            artifact_invalidation = invalidate_replan_derived_artifacts(
                plan_dir,
                timestamp=now_utc(),
                include_gate_epoch=True,
            )
    elif phase_result is None:
        raise CliError(
            "missing_phase_result",
            "recover-blocked requires phase_result.json with current blocker details",
            extra={"resume_cursor": resume_cursor},
        )
    else:
        evaluation = evaluate_blocker_recovery(
            finalize_data,
            state,
            plan_dir=plan_dir,
            blocked_tasks=phase_result.blocked_tasks,
            deviations=phase_result.deviations,
        )
        blocker_details = command_blocker_details(evaluation)
        blocker_ids = [blocker.blocker_id for blocker in evaluation.blockers]
    if not deterministic_phase_repair_required and phase_result is not None and not evaluation.can_continue:
        unresolved_blockers = [
            blocker
            for blocker in blocker_details
            if not blocker.get("is_non_terminal", False)
        ]
        raise CliError(
            "blocked_recovery_not_resolved",
            "recover-blocked requires every current blocker to be explicitly resolved as non-terminal",
            extra={
                "resume_cursor": resume_cursor,
                "phase_result_exit_kind": (
                    phase_result.exit_kind if phase_result is not None else None
                ),
                "blocker_ids": [
                    blocker["blocker_id"] for blocker in unresolved_blockers
                ],
                "unresolved_blockers": unresolved_blockers,
                "blockers": blocker_details,
                "can_continue": evaluation.can_continue,
                "requires_rerun": evaluation.requires_rerun,
            },
        )

    previous_state = state["current_state"]
    # Re-entering the critique or gate phase after ANY recover-blocked recovery
    # collides with the immutable versioned artifacts (critique_custody_v*.json
    # receipts for the critique phase, gate_v*.json projections for the gate
    # phase) published by the superseded attempt at the same iteration.
    # The deterministic-phase-repair branch above already archives them; the
    # human-decision/gate-escalated branch (r7 CL2 gate escalation) must too,
    # otherwise the fresh phase run fails on the create-once/immutable guard.
    if artifact_invalidation is None and phase in {"critique", "gate"}:
        artifact_invalidation = invalidate_replan_derived_artifacts(
            plan_dir,
            timestamp=now_utc(),
            include_critique_epoch=(phase == "critique"),
            include_gate_epoch=(phase == "gate"),
        )
    apply_state_projection(
        state, recovered_state, route_signal="recover-blocked"
    )
    state.pop("latest_failure", None)
    state.pop("active_step", None)
    archived_phase_result = _archive_stale_phase_result_for_resume(plan_dir)
    _append_to_meta(
        state,
        "overrides",
        {
            "action": "recover-blocked",
            "timestamp": now_utc(),
            "reason": reason,
            "from_state": previous_state,
            "to_state": recovered_state,
            "resume_cursor": dict(resume_cursor),
            "blocker_ids": blocker_ids,
            "archived_phase_result": archived_phase_result,
            **(
                {"phase_contract_repair": phase_repair_evidence}
                if phase_repair_evidence is not None
                else {}
            ),
            **(
                {"artifact_invalidation": artifact_invalidation}
                if artifact_invalidation is not None
                else {}
            ),
        },
    )
    if (
        phase_repair_evidence is not None
        and phase_repair_evidence.get("failure_kind")
        == "provider_contract_failure"
    ):
        meta = state.setdefault("meta", {})
        meta["provider_contract_repair_retry"] = {
            **phase_repair_evidence,
            "status": "available",
        }
    save_state_merge_meta(plan_dir, state)
    response: StepResponse = {
        "success": True,
        "step": "override",
        "action": "recover-blocked",
        "summary": (
            f"Recovered blocked plan to state '{recovered_state}' for phase "
            f"{phase!r}. Reason: {reason}"
        ),
        "state": recovered_state,
        "previous_state": previous_state,
        "phase": phase,
        "resume_cursor": resume_cursor,
        "blockers": blocker_details,
        **(
            {"artifact_invalidation": artifact_invalidation}
            if artifact_invalidation is not None
            else {}
        ),
    }
    if phase_repair_evidence is not None:
        response["phase_contract_repair"] = phase_repair_evidence
    if archived_phase_result is not None:
        response["archived_phase_result"] = archived_phase_result
    return response


def _override_set_robustness(
    root: Path, plan_dir: Path, state: PlanState, args: argparse.Namespace
) -> StepResponse:
    from arnold_pipelines.megaplan.profiles import ROBUSTNESS_ACCEPTED, normalize_robustness

    raw_level = getattr(args, "robustness", None)
    if raw_level not in ROBUSTNESS_ACCEPTED:
        raise CliError(
            "invalid_args",
            f"override set-robustness requires --robustness {'|'.join(ROBUSTNESS_ACCEPTED)}",
        )
    new_level = normalize_robustness(raw_level)
    if state["current_state"] in {STATE_DONE, STATE_ABORTED}:
        raise CliError(
            "invalid_transition",
            f"set-robustness cannot be applied to a plan in terminal state '{state['current_state']}'",
        )
    previous_level = state["config"].get("robustness", "standard")
    state["config"]["robustness"] = new_level
    _append_to_meta(
        state,
        "overrides",
        {
            "action": "set-robustness",
            "timestamp": now_utc(),
            "from": previous_level,
            "to": new_level,
            "reason": args.reason,
        },
    )
    save_state_merge_meta(plan_dir, state)
    try:
        from arnold_pipelines.megaplan.observability.events import emit, EventKind
        emit(EventKind.OVERRIDE_APPLIED, plan_dir=plan_dir, payload={"action": "set-robustness", "from": previous_level, "to": new_level, "reason": args.reason})
    except Exception:
        _warn_best_effort_emit_failure(
            "M3A_WARN_EMIT_OVERRIDE_ROBUSTNESS",
            action="override-set-robustness",
            plan_dir=plan_dir,
            event_kind="override_applied",
            context={"from_level": previous_level, "to_level": new_level},
        )
    next_steps = infer_next_steps(state)
    summary = (
        f"Robustness unchanged at '{new_level}'."
        if previous_level == new_level
        else f"Robustness changed from '{previous_level}' to '{new_level}'. Takes effect on the next phase."
    )
    response: StepResponse = {
        "success": True,
        "step": "override",
        "summary": summary,
        "next_step": next_steps[0] if next_steps else None,
        "state": state["current_state"],
        "previous_robustness": previous_level,
        "robustness": new_level,
    }
    _attach_next_step_runtime(response)
    return response


def _override_set_profile(
    root: Path, plan_dir: Path, state: PlanState, args: argparse.Namespace
) -> StepResponse:
    from arnold_pipelines.megaplan.profiles import (
        _canonicalize_tier_models_for_json,
        _resolve_prep_models_with_inheritance,
        _resolve_tier_models_with_inheritance,
        _prep_flat_spec_from_profile,
        apply_depth_rewrite,
        apply_vendor_rewrite,
        load_profile_metadata,
        load_profiles,
        resolve_prep_models,
        resolve_profile,
        profile_to_phase_models,
    )
    from arnold_pipelines.megaplan.profiles.policy import _profile_has_premium_slots

    new_profile = getattr(args, "profile", None)
    if not new_profile:
        raise CliError("invalid_args", "override set-profile requires --profile NAME")
    if state["current_state"] in {STATE_DONE, STATE_ABORTED}:
        raise CliError(
            "invalid_transition",
            f"set-profile cannot be applied to a plan in terminal state '{state['current_state']}'",
        )
    project_dir = Path(state["config"].get("project_dir", str(root)))
    profiles = load_profiles(project_dir=project_dir)
    metadata = load_profile_metadata(project_dir=project_dir)
    resolved = resolve_profile(new_profile, profiles)
    try:
        tier_models = _resolve_tier_models_with_inheritance(
            new_profile,
            system_profiles=profiles,
            system_metadata=metadata,
            pipeline_local_profiles={},
            pipeline_local_metadata={},
        )
    except CliError:
        tier_models = {}
    try:
        inherited_prep_models = _resolve_prep_models_with_inheritance(
            new_profile,
            system_profiles=profiles,
            system_metadata=metadata,
            pipeline_local_profiles={},
            pipeline_local_metadata={},
        )
    except CliError:
        inherited_prep_models = {}
    vendor = effective_premium_vendor(config=state.get("config", {}))
    if _profile_has_premium_slots(resolved) or inherited_prep_models:
        resolved = apply_vendor_rewrite(
            resolved,
            vendor,
            prep_models=inherited_prep_models,
        )
    depth = state["config"].get("depth")
    if depth is not None:
        resolved = apply_depth_rewrite(resolved, depth)
    phase_models = profile_to_phase_models(resolved)
    prep_models, prep_trace = resolve_prep_models(
        flat_prep_spec=_prep_flat_spec_from_profile(resolved),
        prep_models=inherited_prep_models,
        canonical_model=(
            CONTINUATION_RUNTIME_MODEL_SPEC
            if new_profile == CONTINUATION_RUNTIME_PROFILE
            else None
        ),
    )

    previous_profile = state["config"].get("profile")
    state["config"]["profile"] = new_profile
    state["config"]["phase_model"] = phase_models
    if _profile_has_premium_slots(resolved):
        state["config"]["vendor"] = vendor
    else:
        state["config"].pop("vendor", None)
    if tier_models:
        state["config"]["tier_models"] = _canonicalize_tier_models_for_json(tier_models)
    else:
        state["config"].pop("tier_models", None)
    if prep_models:
        state["config"]["prep_models"] = prep_models
        state["config"]["prep_model_resolver_trace"] = prep_trace
    else:
        state["config"].pop("prep_models", None)
        state["config"].pop("prep_model_resolver_trace", None)
    exec_spec = next(
        (phase_model.split("=", 1)[1] for phase_model in phase_models if phase_model.startswith("execute=")),
        "",
    )
    if exec_spec:
        _phase, exec_chain = decode_phase_model_value(f"execute={exec_spec}")
        exec_spec = exec_chain.selected()
    exec_spec = exec_spec.lower()
    exec_family = None
    if exec_spec.startswith("claude"):
        exec_family = "claude"
    elif exec_spec.startswith("codex") or "gpt-5" in exec_spec:
        exec_family = "codex"
    if exec_family is not None and state["config"].get("vendor") != exec_family:
        state["config"]["vendor"] = exec_family
    _append_to_meta(
        state,
        "overrides",
        {
            "action": "set-profile",
            "timestamp": now_utc(),
            "from": previous_profile,
            "to": new_profile,
            "reason": args.reason,
        },
    )
    save_state_merge_meta(plan_dir, state)
    try:
        from arnold_pipelines.megaplan.observability.events import emit, EventKind
        emit(EventKind.OVERRIDE_APPLIED, plan_dir=plan_dir, payload={"action": "set-profile", "from": previous_profile, "to": new_profile, "reason": args.reason})
    except Exception:
        _warn_best_effort_emit_failure(
            "M3A_WARN_EMIT_OVERRIDE_PROFILE",
            action="override-set-profile",
            plan_dir=plan_dir,
            event_kind="override_applied",
            context={"from_profile": previous_profile, "to_profile": new_profile},
        )
    next_steps = infer_next_steps(state)
    summary = (
        f"Profile unchanged at '{new_profile}'."
        if previous_profile == new_profile
        else f"Profile changed from '{previous_profile}' to '{new_profile}'. Takes effect on the next phase."
    )
    response: StepResponse = {
        "success": True,
        "step": "override",
        "summary": summary,
        "next_step": next_steps[0] if next_steps else None,
        "state": state["current_state"],
        "previous_profile": previous_profile,
        "profile": new_profile,
    }
    _attach_next_step_runtime(response)
    return response

def _override_set_model(root: Path, plan_dir: Path, state: PlanState, args: argparse.Namespace) -> StepResponse:
    """Override: change the model for a specific phase."""
    phase = getattr(args, "phase", None)
    model_arg = getattr(args, "model", None)
    effort = getattr(args, "effort", None)

    # Validate required args
    if not phase:
        raise CliError("invalid_args", "override set-model requires --phase PHASE")
    if not model_arg:
        raise CliError("invalid_args", "override set-model requires --model MODEL")
    if model_arg in _PREMIUM_VENDORS:
        raise CliError(
            "invalid_args",
            f"override set-model --model {model_arg!r} names an agent, not a model. "
            f"Use `override set-vendor --vendor {model_arg}` to switch vendors, "
            "or pass an actual model name/spec.",
        )

    # Validate known phase names
    if phase not in DEFAULT_AGENT_ROUTING:
        raise CliError(
            "invalid_args",
            f"Unknown phase '{phase}'. Valid phases: {', '.join(sorted(DEFAULT_AGENT_ROUTING))}",
        )

    # Infer the target agent for this phase
    # Priority: (1) persisted phase_model entry, (2) active profile, (3) DEFAULT_AGENT_ROUTING
    current_phase_spec = _current_phase_spec(phase, state, root)
    agent = parse_agent_spec(current_phase_spec).agent

    explicit_spec = parse_agent_spec(model_arg) if ":" in model_arg else None
    if explicit_spec is not None and explicit_spec.agent in _PREMIUM_VENDORS:
        target_agent = explicit_spec.agent
        target_model = explicit_spec.model
        target_effort = explicit_spec.effort
        if target_model is None:
            raise CliError(
                "invalid_args",
                f"'{model_arg}' does not name a model. "
                f"Use --model {target_agent}:MODEL or --model MODEL --effort {target_effort or 'EFFORT'}.",
            )
        if effort is not None and target_effort is not None:
            raise CliError(
                "invalid_args",
                "Effort was provided twice: once in --model and once via --effort.",
            )
        if effort is not None:
            target_effort = effort
    elif explicit_spec is not None:
        raise CliError(
            "invalid_args",
            f"set-model only supports claude/codex specs; got '{explicit_spec.agent}'. "
            "Use --phase-model on the phase command for omp/shannon routing.",
        )
    else:
        # Bare model strings normally keep the phase's current premium vendor.
        # If the current phase is non-premium, allow an unambiguous vendor-prefixed
        # premium model name to move the phase onto that vendor.
        inferred_agent = None
        if str(model_arg).startswith("claude-"):
            inferred_agent = "claude"
        elif str(model_arg).startswith(("gpt-", "o1", "o3", "o4")):
            inferred_agent = "codex"
        if agent == "shannon":
            inferred_agent = None
        if agent not in _PREMIUM_VENDORS and inferred_agent is None:
            raise CliError(
                "invalid_args",
                f"set-model is only supported for claude/codex phases. "
                f"Phase '{phase}' resolves to agent '{agent}'.",
            )
        target_agent = inferred_agent or agent
        target_model = model_arg
        target_effort = effort

    # Reject reserved effort tokens as --model values
    if target_model in _PREMIUM_EFFORT_TOKENS:
        raise CliError(
            "invalid_args",
            f"'{target_model}' is a reserved effort token and cannot be used as a model name. "
            f"Use --effort to set effort level.",
        )

    # Validate effort if provided
    if target_effort is not None and target_effort not in _PREMIUM_EFFORT_TOKENS:
        raise CliError(
            "invalid_args",
            f"Unknown effort level '{target_effort}'. Valid: {', '.join(sorted(_PREMIUM_EFFORT_TOKENS))}",
        )

    # Build the new spec string
    new_spec = format_agent_spec(AgentSpec(target_agent, model=target_model, effort=target_effort))

    # Find and update the phase_model entry
    phase_models = list(state["config"].get("phase_model") or [])
    previous_spec = None
    found = False
    for i, pm in enumerate(phase_models):
        if "=" in pm and pm.split("=", 1)[0] == phase:
            previous_spec = pm.split("=", 1)[1]
            phase_models[i] = f"{phase}={new_spec}"
            found = True
            break
    if not found:
        # No existing entry — append a new one
        previous_spec = current_phase_spec
        phase_models.append(f"{phase}={new_spec}")

    state["config"]["phase_model"] = phase_models
    tier_models = state["config"].get("tier_models")
    if isinstance(tier_models, dict) and phase in tier_models:
        next_tier_models = dict(tier_models)
        next_tier_models.pop(phase, None)
        state["config"]["tier_models"] = next_tier_models

    # Append override meta entry
    _append_to_meta(
        state,
        "overrides",
        {
            "action": "set-model",
            "phase": phase,
            "previous_spec": previous_spec,
            "new_spec": new_spec,
            "timestamp": now_utc(),
            "reason": getattr(args, "reason", "") or "",
        },
    )
    save_state_merge_meta(plan_dir, state)

    next_steps = infer_next_steps(state)
    summary = (
        f"Model for phase '{phase}' changed from '{previous_spec}' to '{new_spec}'. "
        f"Takes effect on the next phase."
    )
    response: StepResponse = {
        "success": True,
        "step": "override",
        "summary": summary,
        "next_step": next_steps[0] if next_steps else None,
        "state": state["current_state"],
        "phase": phase,
        "previous_spec": previous_spec,
        "new_spec": new_spec,
    }
    _attach_next_step_runtime(response)
    return response


def _current_phase_spec(phase: str, state: PlanState, root: Path) -> str:
    """Resolve the spec currently in force for *phase*.

    Priority mirrors :func:`_infer_phase_agent`: persisted ``phase_model``
    entry, then active profile, then ``DEFAULT_AGENT_ROUTING``.
    """
    phase_models = state.get("config", {}).get("phase_model") or []
    for pm in phase_models:
        if isinstance(pm, str) and "=" in pm:
            pm_phase, chain = decode_phase_model_value(pm)
            if pm_phase == phase:
                return _resolve_symbolic_phase_spec(chain.selected(), state)
    profile_name = state.get("config", {}).get("profile")
    if profile_name:
        try:
            from arnold_pipelines.megaplan.profiles import load_profiles, resolve_profile

            project_dir = Path(state["config"].get("project_dir", str(root)))
            profiles = load_profiles(project_dir=project_dir)
            resolved = resolve_profile(profile_name, profiles)
            if phase in resolved:
                resolved_spec = resolved[phase]
                if isinstance(resolved_spec, list):
                    resolved_spec = select_fallback_spec(resolved_spec, 0, path=f"profile.{phase}")
                return _resolve_symbolic_phase_spec(resolved_spec, state)
        except Exception:
            pass
    return _resolve_symbolic_phase_spec(DEFAULT_AGENT_ROUTING.get(phase, ""), state)


def _resolve_symbolic_phase_spec(spec: str, state: PlanState) -> str:
    if not spec or not is_premium_placeholder_spec(spec):
        return spec
    vendor = effective_premium_vendor(config=state.get("config", {}))
    return format_agent_spec(resolve_premium_placeholder_spec(spec, vendor))


def _override_set_vendor(root: Path, plan_dir: Path, state: PlanState, args: argparse.Namespace) -> StepResponse:
    """Override: re-point a phase's premium vendor (claude <-> codex) cleanly.

    Mirrors ``set-model``'s clean construction: it resolves the spec currently
    in force for the phase and swaps only the vendor via the same
    ``_swap_premium_spec`` logic the ``--vendor`` profile rewrite uses, then
    re-formats through ``parse_agent_spec``/``format_agent_spec``. This removes
    the hand-edit vector that produced the malformed ``codex:claude:sonnet``
    pin (the original bug): an operator no longer needs to hand-write a spec.
    """
    phase = getattr(args, "phase", None)
    vendor = getattr(args, "vendor", None)

    if not phase:
        raise CliError("invalid_args", "override set-vendor requires --phase PHASE")
    if not vendor:
        raise CliError("invalid_args", "override set-vendor requires --vendor VENDOR")
    if phase not in DEFAULT_AGENT_ROUTING:
        raise CliError(
            "invalid_args",
            f"Unknown phase '{phase}'. Valid phases: {', '.join(sorted(DEFAULT_AGENT_ROUTING))}",
        )

    from arnold_pipelines.megaplan.profiles import _swap_premium_spec
    from arnold_pipelines.megaplan._core.user_config import VALID_VENDORS

    if vendor not in VALID_VENDORS:
        raise CliError(
            "invalid_args",
            f"set-vendor --vendor must be one of {', '.join(VALID_VENDORS)}; got {vendor!r}",
        )

    current_spec = _current_phase_spec(phase, state, root)
    parsed = parse_agent_spec(current_spec)
    if parsed.agent not in _PREMIUM_VENDORS:
        raise CliError(
            "invalid_args",
            f"set-vendor is only supported for claude/codex phases. "
            f"Phase '{phase}' resolves to agent '{parsed.agent}' ({current_spec!r}).",
        )

    # _swap_premium_spec raises vendor_swap_model_conflict on an explicit model
    # pin with no cross-vendor equivalent; re-format through the parser so the
    # persisted spec is always canonical (and re-validated).
    swapped = _swap_premium_spec(current_spec, vendor)
    new_spec = format_agent_spec(parse_agent_spec(swapped))

    phase_models = list(state["config"].get("phase_model") or [])
    previous_spec = None
    found = False
    for i, pm in enumerate(phase_models):
        if "=" in pm and pm.split("=", 1)[0] == phase:
            previous_spec = pm.split("=", 1)[1]
            phase_models[i] = f"{phase}={new_spec}"
            found = True
            break
    if not found:
        previous_spec = current_spec or _resolved_default_phase_spec(phase, state, root)
        phase_models.append(f"{phase}={new_spec}")
    state["config"]["phase_model"] = phase_models

    _append_to_meta(
        state,
        "overrides",
        {
            "action": "set-vendor",
            "phase": phase,
            "previous_spec": previous_spec,
            "new_spec": new_spec,
            "timestamp": now_utc(),
            "reason": getattr(args, "reason", "") or "",
        },
    )
    save_state_merge_meta(plan_dir, state)

    next_steps = infer_next_steps(state)
    summary = (
        f"Vendor for phase '{phase}' changed from '{previous_spec}' to '{new_spec}'. "
        f"Takes effect on the next phase."
    )
    response: StepResponse = {
        "success": True,
        "step": "override",
        "summary": summary,
        "next_step": next_steps[0] if next_steps else None,
        "state": state["current_state"],
        "phase": phase,
        "previous_spec": previous_spec,
        "new_spec": new_spec,
    }
    _attach_next_step_runtime(response)
    return response


def _infer_phase_agent(phase: str, state: PlanState, root: Path) -> str | None:
    """Infer the agent for a phase from persisted state or defaults."""
    # Check persisted phase_model for an explicit spec
    phase_models = state.get("config", {}).get("phase_model") or []
    for pm in phase_models:
        if isinstance(pm, str) and "=" in pm:
            pm_phase, chain = decode_phase_model_value(pm)
            if pm_phase == phase:
                parsed = parse_agent_spec(chain.selected())
                return parsed.agent

    # Check active profile
    profile_name = state.get("config", {}).get("profile")
    if profile_name:
        try:
            from arnold_pipelines.megaplan.profiles import load_profiles, resolve_profile
            project_dir = Path(state["config"].get("project_dir", str(root)))
            profiles = load_profiles(project_dir=project_dir)
            resolved = resolve_profile(profile_name, profiles)
            if phase in resolved:
                resolved_spec = resolved[phase]
                if isinstance(resolved_spec, list):
                    resolved_spec = select_fallback_spec(resolved_spec, 0, path=f"profile.{phase}")
                parsed = parse_agent_spec(_resolve_symbolic_phase_spec(resolved_spec, state))
                return parsed.agent
        except Exception:
            pass

    # Fall back to DEFAULT_AGENT_ROUTING
    default = DEFAULT_AGENT_ROUTING.get(phase)
    if default is None:
        return None
    return parse_agent_spec(_resolve_symbolic_phase_spec(default, state)).agent


def _override_resume_clarify(
    root: Path, plan_dir: Path, state: PlanState, args: argparse.Namespace
) -> StepResponse:
    clarification = state.get("clarification")
    has_prep_clarification = (
        isinstance(clarification, dict)
        and clarification.get("source") == "prep"
    )
    if state["current_state"] not in {STATE_AWAITING_HUMAN, STATE_BLOCKED}:
        raise CliError(
            "invalid_transition",
            f"resume-clarify requires state '{STATE_AWAITING_HUMAN}', got '{state['current_state']}'",
            valid_next=infer_next_steps(state),
        )
    if not has_prep_clarification:
        raise CliError(
            "invalid_transition",
            "resume-clarify can only resume a prep-sourced clarification halt; "
            "use verify-human for criteria-verification awaiting_human states",
            valid_next=infer_next_steps(state),
        )
    notes = state.get("meta", {}).get("notes") or []
    user_notes = [n for n in notes if isinstance(n, dict) and n.get("source", "user") == "user"]
    warnings: list[str] = []
    if not user_notes:
        warnings.append(
            "No answers found in notes; consider adding answers via "
            "'override add-note' before the plan phase."
        )
    reentry_invocation_id = resume_clarification_phase_wbc_if_present(
        state=state,
        plan_dir=plan_dir,
        agent=str(getattr(args, "actor", None) or "override:resume-clarify"),
    )
    apply_state_projection(state, STATE_PREPPED, route_signal="resume-clarify")
    state.pop("clarification", None)
    _append_to_meta(
        state,
        "overrides",
        {
            "action": "resume-clarify",
            "timestamp": now_utc(),
            **(
                {"phase_wbc_reentry_invocation_id": reentry_invocation_id}
                if reentry_invocation_id is not None
                else {}
            ),
        },
    )
    save_state_merge_meta(plan_dir, state)
    try:
        from arnold_pipelines.megaplan.observability.events import emit, EventKind
        emit(EventKind.OVERRIDE_APPLIED, plan_dir=plan_dir, payload={"action": "resume-clarify"})
    except Exception:
        pass
    response: StepResponse = {
        "success": True,
        "step": "override",
        "summary": "Prep clarification resolved; plan phase is now ready to run.",
        "state": STATE_PREPPED,
    }
    if warnings:
        response["warnings"] = warnings
    if reentry_invocation_id is not None:
        response["phase_wbc_reentry_invocation_id"] = reentry_invocation_id
    return response


def _override_reconcile_plan_ledger(
    root: Path, plan_dir: Path, state: PlanState, args: argparse.Namespace
) -> StepResponse:
    """Append-only ledger repair for a drifted plan version (Sol Tier 1).

    Records an audited reconciliation on plan_versions for the latest
    recorded plan artifact whose on-disk content drifted from its attestation
    (worker in-place mutation now forbidden by prompt contract).  Preserves
    the original attestation; appends reconciliation metadata; requires the
    current on-disk hash to equal the supplied replacement hash.
    """
    from arnold_pipelines.megaplan._core.plan_integrity import (
        reconcile_drifted_plan_version,
    )

    version = getattr(args, "plan_version", None)
    replacement_sha = getattr(args, "replacement_sha256", None)
    reason = args.reason or "worker in-place mutation of plan artifact (prompt-fixed)"
    repair_ref = getattr(args, "repair_ref", "") or ""
    if not isinstance(version, int) or version < 1:
        raise CliError(
            "invalid_override",
            "reconcile-plan-ledger requires --plan-version (int)",
            valid_next=infer_next_steps(state),
        )
    if not isinstance(replacement_sha, str) or not replacement_sha.strip():
        raise CliError(
            "invalid_override",
            "reconcile-plan-ledger requires --replacement-sha256",
            valid_next=infer_next_steps(state),
        )
    result = reconcile_drifted_plan_version(
        plan_dir=plan_dir,
        state=state,
        version=version,
        replacement_sha256=replacement_sha.strip(),
        expected_previous_sha256="",
        reason=reason,
        repair_ref=repair_ref,
    )
    from arnold_pipelines.megaplan.handlers.shared import save_state_merge_meta

    save_state_merge_meta(plan_dir, state)
    return {
        "success": True,
        "step": "override",
        "override_action": "reconcile-plan-ledger",
        "summary": (
            f"reconciled plan_v{version} ledger attestation to on-disk "
            f"content (append-only repair; previous hash preserved)"
        ),
        "reconciled": result,
        "route_signal": "reconcile_plan_ledger",
    }


def _enforce_cutover_combined_authority(
    state: PlanState, args: argparse.Namespace
) -> None:
    """Fail-closed combined-authority check for the legacy-to-canonical cutover.

    The cutover (CL5) overrides the entire critique-loop architecture in one
    all-at-once transition. Per the override matrix
    ``workflow.route_binding`` combined-authority declaration (Step 8a) and the
    cross-domain ownership boundary in ``source_to_owner_matrix.json``, it
    requires BOTH owner domains to authorize dispatch before any cutover
    orchestration runs:

      * ``run_authority`` / human-gate operator approval
        (``args.user_approved`` -- the operator explicitly approves the
        destructive cutover), AND
      * ``maintenance`` / ``repair_queue`` lifecycle mutation authority
        (a validated lifecycle binding via ``args.repair_commit`` AND
        ``args.failure_fingerprint``; ``--repair-scope`` binds the validated
        cutover revision surface).

    Missing EITHER authority fails closed with an explicit ``CliError`` so a
    partially-authorized invocation can never reach the (not-yet-built) cutover
    orchestration package. This check is shared by both the default dispatch
    path (``_override_cutover``) and the control-routed special case in
    ``_handle_routed_override`` (CL5 Step 8b/8c), so both override paths reach
    the same authority logic.
    """
    if not bool(getattr(args, "user_approved", False)):
        raise CliError(
            "cutover_authority_missing",
            "cutover requires combined authority: human-gate operator approval "
            "(--user-approved) is absent; run_authority has not authorized the "
            "legacy-to-canonical cutover.",
        )
    repair_commit = getattr(args, "repair_commit", None)
    failure_fingerprint = getattr(args, "failure_fingerprint", None)
    if not (isinstance(repair_commit, str) and repair_commit.strip()) or not (
        isinstance(failure_fingerprint, str) and failure_fingerprint.strip()
    ):
        raise CliError(
            "cutover_authority_missing",
            "cutover requires combined authority: lifecycle mutation authority "
            "via repair_queue (maintenance) is absent; supply --repair-commit and "
            "--failure-fingerprint binding the validated cutover revision.",
        )


def _invoke_cutover_orchestration(
    root: Path, plan_dir: Path, state: PlanState, args: argparse.Namespace
) -> dict[str, Any]:
    """Deferred import + invocation of the legacy-to-canonical cutover.

    The cutover orchestration package ``arnold.critique_ledger.cutover`` is
    built in Steps 11-16 (Phase 2). The import is deferred to invocation time
    (inside this function body, matching the ``_override_replan`` convention at
    L1058/L567), so registering the handler in ``_OVERRIDE_ACTIONS`` and the
    routed special-case branch is Phase 1 safe: the import does not execute at
    registration time. Until the package exists, invoking this function raises
    ``ImportError`` -- the expected Phase 1 state. The dispatch wiring is
    verified by the Phase 3 dispatch tests (T31).

    This is the single deferred cutover entry point reached by BOTH override
    paths (CL5 Step 8b/8c): the default-path ``_override_cutover`` handler and
    the control-routed special case in ``_handle_routed_override`` both call it
    after the combined-authority check passes, so both paths reach the same
    deferred cutover logic.
    """
    # Deferred import (Phase 2+ entry point): do NOT hoist to module scope.
    from arnold.critique_ledger.cutover import run_cutover

    return run_cutover(root=Path(root), plan_dir=plan_dir, state=state, args=args)


def _override_cutover(
    root: Path, plan_dir: Path, state: PlanState, args: argparse.Namespace
) -> StepResponse:
    """Default-dispatch-path cutover override handler (CL5 Step 8b).

    Wires the legacy-to-canonical cutover onto the flag-off default dispatch
    path so ``_OVERRIDE_ACTIONS.get('cutover')`` resolves to a handler instead
    of raising ``CliError('invalid_override')``. The cutover requires COMBINED
    authority (human-gate operator approval AND lifecycle mutation authority
    via repair_queue), enforced fail-closed before the deferred cutover
    orchestration runs.

    See ``_enforce_cutover_combined_authority`` and
    ``_invoke_cutover_orchestration`` for the shared deferred cutover logic
    also reached by the control-routed special case in
    ``_handle_routed_override`` (Step 8c).
    """
    _enforce_cutover_combined_authority(state, args)
    cutover_result = _invoke_cutover_orchestration(root, plan_dir, state, args)
    timestamp = now_utc()
    _append_to_meta(
        state,
        "overrides",
        {
            "action": "cutover",
            "timestamp": timestamp,
            "reason": getattr(args, "reason", None),
            "repair_commit": getattr(args, "repair_commit", None),
            "user_approved": bool(getattr(args, "user_approved", False)),
        },
    )
    save_state_merge_meta(plan_dir, state)
    response: StepResponse = {
        "success": True,
        "step": "override",
        "override_action": "cutover",
        "summary": "Legacy-to-canonical cutover executed.",
        "state": state["current_state"],
        "cutover_result": cutover_result,
    }
    return response


_OVERRIDE_ACTIONS: dict[
    str, Callable[[Path, Path, PlanState, argparse.Namespace], StepResponse]
] = {
    "add-note": _override_add_note,
    "abort": _override_abort,
    "adopt-execution": _override_adopt_execution,
    "cutover": _override_cutover,
    "replan": _override_replan,
    "cap-revise-once": _override_cap_revise_once,
    "recover-blocked": _override_recover_blocked,
    "resume-clarify": _override_resume_clarify,
    "set-robustness": _override_set_robustness,
    "set-profile": _override_set_profile,
    "set-model": _override_set_model,
    "set-vendor": _override_set_vendor,
    "reconcile-plan-ledger": _override_reconcile_plan_ledger,
}


def handle_override(root: Path, args: argparse.Namespace) -> StepResponse:
    plan_dir, state = load_plan(root, args.plan)
    action = args.override_action
    if action in {"adopt-execution"}:
        pass
    elif action in {"force-proceed", "recover-blocked", "resume-clarify"}:
        # The worker preflight requires config.project_dir and the recovery
        # handler requires a stored resume_cursor.  A structurally incomplete
        # legacy/synthetic blocked deterministic-phase state (no cursor, no
        # config) must be admitted BEFORE the preflight when the caller binds
        # the exact occurrence digest + handoff id; without the fence the
        # fail-closed errors below are preserved unchanged.
        if action == "recover-blocked" and not isinstance(
            state.get("resume_cursor"), dict
        ):
            _materialize_legacy_deterministic_phase_cursor(
                plan_dir, state, args, root=root
            )
        preflight_mutating_phase(root=root, state=state, phase=f"override:{action}")
    else:
        preflight_phase(root=root, state=state, phase=f"override:{action}")
    if action in {"force-proceed", "set-profile"}:
        # These controls have one mutation owner: the CAS-backed control
        # binding.  In particular, set-profile is also the recovery operation
        # that refreshes persisted tier routing when the selected profile name
        # is unchanged.  Letting it fall back to the legacy writer would omit
        # the routing receipt and could race the paused cutover state.
        # Preflight isolation metadata is carried in ``state`` and committed by
        # that same CAS; do not persist an out-of-band pre-transition write.
        return _handle_routed_override(root, plan_dir, state, args)
    save_state_merge_meta(plan_dir, state)
    if control_interface_routing_on() and action in _control_routed_override_actions():
        return _handle_routed_override(root, plan_dir, state, args)
    handler = _OVERRIDE_ACTIONS.get(action)
    if handler is None:
        raise CliError("invalid_override", f"Unknown override action: {action}")
    response = _normalize_override_response(action, handler(root, plan_dir, state, args))
    emit_override_authority_receipt(plan_dir, state, action)
    return response
