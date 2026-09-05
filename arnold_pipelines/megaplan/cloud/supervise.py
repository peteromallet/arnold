"""Cloud chain supervisor — one-shot tick logic.

The supervisor observes a chain and makes safe progress decisions without
human approval.  It may restart missing runners and surface recoverable
blockers but must not invent approvals or force destructive git operations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from arnold_pipelines.megaplan.custody.process_adapter_wbc import begin_process_adapter_attempt


# ---------------------------------------------------------------------------
# Shared command helpers (imported from cli to keep session/log/env/quotes
# consistent across all entry points).
# ---------------------------------------------------------------------------

def _chain_tick_command(remote_spec_path: str, *, one_shot: bool = False) -> str:
    """Canonical ``megaplan chain start`` command string.

    session name, log path, trusted env, and quoting are shared with
    ``_run_chain_wrapper()`` via the same helper in ``megaplan.cloud.cli``.

    **M5d boundary note:** This function lives in the cloud tier, which is a
    long-lived host *above* the supervisor tier.  Cloud wraps the supervisor
    as a tick host and is explicitly anti-scope for M5d — it continues to
    construct and execute ``megaplan chain start`` commands regardless of
    whether the chain runner routes through the old engine or the new
    ``MEGAPLAN_SUPERVISOR_TIER=1`` path.  Cloud is not ported in M5d.
    """
    from arnold_pipelines.megaplan.cloud.cli import _chain_start_command as _cmd

    return _cmd(remote_spec_path, one_shot=one_shot)


def _canonical_resume_command(workspace: str, remote_spec: str, *, session_name: str) -> str:
    """Invoke the operator resume adapter, whose physical door is canonical.

    The supervisor must not manufacture a raw ``tmux new-session`` command.
    The remote operator-control module performs the complete preflight and
    routes the physical session through ``launch_transaction``.
    """
    marker = str(PurePosixPath(workspace) / ".megaplan" / "cloud-sessions" / f"{session_name}.json")
    return shlex.join([
        "python3", "-P", "-m", "arnold_pipelines.megaplan.cloud.operator_control",
        "resume", "--spec", remote_spec, "--workspace", workspace,
        "--session", session_name, "--marker", marker, "--actor", "supervisor",
    ])


def _remote_sync_refresh_command(
    workspace: str,
    remote_spec: str,
    *,
    branch: str | None = None,
    pr_number: int | None = None,
    extra_repos: list[str] | None = None,
    resolved_workspace: str | None = None,
    chain_session: str | None = None,
) -> str:
    """Construct a remote Python one-liner that calls ``_capture_sync_state``
    on the cloud runner.

    Every value interpolated into the Python snippet is a Python literal
    (via :func:`json.dumps` or :func:`repr`) — **not** :func:`shlex.quote`,
    which would produce bare identifiers instead of string literals.
    ``shlex.quote`` is used only for shell boundaries (``cd <workspace>``,
    ``python3 -c <snippet>``).
    """
    snippet = (
        "from arnold_pipelines.megaplan.chain import _capture_sync_state, ChainState, save_chain_state, load_chain_state; "
        "from pathlib import Path; "
        "_capture_sync_state("
        f"Path({json.dumps(workspace)}), Path({json.dumps(remote_spec)}), "
        f"branch={json.dumps(branch) if branch is not None else 'None'}, "
        f"pr_number={repr(pr_number)}, "
        f"extra_repos={json.dumps(extra_repos) if extra_repos is not None else 'None'}); "
    )
    # Persist resolved workspace and session into remote chain state so
    # subsequent status reads pick them up even without marker/chain_state
    # pre-population.
    if resolved_workspace or chain_session:
        snippet += (
            "s = load_chain_state(Path({})); ".format(json.dumps(remote_spec))
        )
        if resolved_workspace:
            snippet += (
                "s.resolved_workspace = {}; ".format(json.dumps(resolved_workspace))
            )
        if chain_session:
            snippet += (
                "s.chain_session = {}; ".format(json.dumps(chain_session))
            )
        snippet += (
            "save_chain_state(Path({}), s)".format(json.dumps(remote_spec))
        )
    return f"cd {shlex.quote(workspace)} && python3 -c {shlex.quote(snippet)}"


def _remote_pr_state_command(workspace: str, pr_number: int) -> str:
    """Return a shell command that probes the remote PR merge state."""
    return (
        f"cd {shlex.quote(workspace)} && "
        f"gh pr view {pr_number} --json state --jq .state 2>/dev/null "
        f"|| echo unknown"
    )


# ---------------------------------------------------------------------------
# Tick report builder
# ---------------------------------------------------------------------------

def _tick_report(
    *,
    success: bool,
    event: str,
    spec: str,
    effective_status: str,
    next_action: str,
    acted: bool,
    refused_reason: str | None,
    runner: dict[str, Any],
    sync: dict[str, Any],
    pr: dict[str, Any],
    logs: dict[str, Any],
    sync_refresh: dict[str, Any] | None = None,
    provider_consistency: dict[str, Any] | None = None,
    extra_repo_sync: list[dict[str, Any]] | None = None,
    human_verification: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the canonical supervisor tick report dict."""
    report: dict[str, Any] = {
        "success": success,
        "event": event,
        "spec": spec,
        "effective_status": effective_status,
        "next_action": next_action,
        "acted": acted,
        "refused_reason": refused_reason,
        "runner": runner,
        "sync": sync,
        "pr": pr,
        "logs": logs,
    }
    if sync_refresh is not None:
        report["sync_refresh"] = sync_refresh
    if provider_consistency is not None:
        report["provider_consistency"] = provider_consistency
    if extra_repo_sync is not None:
        report["extra_repo_sync"] = extra_repo_sync
    if human_verification is not None:
        report["human_verification"] = human_verification
    return report


# ---------------------------------------------------------------------------
# Safe action policy
# ---------------------------------------------------------------------------

# Statuses the supervisor will **never** mutate.
READ_ONLY_STATUSES = frozenset({
    "running",
    "complete",
    "human_prerequisite",
    "quality_gate",
})

# Statuses that trigger a read-only refusal (no mutation).
BLOCKED_REFUSAL_REASONS: dict[str, str] = {
    "human_prerequisite": "human prerequisite policy is 'required' and unmet; "
    "a human operator must resolve it via `megaplan user-action resolve` "
    "or `megaplan chain override`",
    "quality_gate": "validation policy is 'required' and quality gate is failing; "
    "a human operator must resolve the blocker or accept with debt",
}


def _canonical_runner_mutation_gate(
    runner: Any,
    *,
    require_dead: bool,
) -> tuple[bool, str]:
    """Authorize supervisor effects only from the exact canonical target.

    The cloud status payload deliberately carries tmux/``ps`` observations as
    diagnostics.  This gate never reads them.  A known canonical live target
    may authorize benign sync refresh, while restart/advance/wake additionally
    require canonical death so a second runner cannot be created.
    """

    if not isinstance(runner, dict):
        return False, "canonical current-target runner evidence is missing"
    if runner.get("authority") != "canonical_current_target":
        return False, "runner evidence is not canonical current-target authority"
    if runner.get("exact_target") is not True:
        return False, "canonical runner does not match the exact session/workspace/spec/plan"
    if runner.get("mutation_permitted") is not True:
        return False, "canonical current-target liveness is UNKNOWN or malformed"
    state = str(runner.get("state") or "").lower()
    if state not in {"live", "dead"}:
        return False, "canonical current-target liveness is not known"
    if require_dead and state != "dead":
        return False, "canonical current target is live; duplicate launch refused"
    return True, "canonical exact-target liveness permits mutation"


def _supervisor_problem_signature(
    *, reason: str, current_plan_name: str
) -> dict[str, str]:
    """Preserve a deterministic supervised failure as repair identity.

    ``arnold-supervise`` stops retrying known deterministic failures.  Its
    queue handoff must retain that exact failure instead of collapsing it to
    the generic exhausted-process identity used for retry-budget exhaustion.
    """
    """Preserve a deterministic supervised failure as repair identity."""

    prefix = "deterministic supervised failure:"
    normalized_reason = str(reason or "").strip()
    signature = {
        "failure_kind": "supervised_run_exhausted",
        "current_state": "process_exited",
        "phase_or_step": "arnold-supervise",
        "milestone_or_plan": current_plan_name,
        "gate_recommendation": "",
        "blocked_task_id": "phase:arnold-supervise",
        "event_signature": "",
    }
    if not normalized_reason.startswith(prefix):
        return signature

    detail = normalized_reason[len(prefix) :].strip()
    failure_kind, separator, evidence = detail.partition(";")
    failure_kind = failure_kind.strip()
    if not failure_kind:
        return signature

    signature.update(
        {
            "failure_kind": failure_kind,
            "phase_or_step": "chain_execution_binding"
            if failure_kind == "chain_execution_binding_drift"
            else "arnold-supervise",
            "phase_or_step": (
                "chain_execution_binding"
                if failure_kind == "chain_execution_binding_drift"
                else "arnold-supervise"
            ),
            "blocked_task_id": f"deterministic:{failure_kind}",
            "event_signature": detail,
        }
    )
    if failure_kind == "chain_execution_binding_drift":
        active_errors = ""
        if separator:
            key, equals, value = evidence.strip().partition("=")
            if equals and key.strip() == "active_errors":
                active_errors = value.strip()
        if active_errors:
            signature["blocked_task_id"] = (
                f"chain_execution_binding:{active_errors}"
            )
        signature["gate_recommendation"] = (
            "Explicit operator-authorized content-addressed rebind is required; "
            "do not retry the unchanged chain start."
        )
    return signature


def enqueue_supervisor_repair_request(
    *,
    queue_root: str | Path,
    marker_dir: str | Path,
    session: str,
    workspace: str | Path,
    remote_spec: str,
    run_kind: str,
    reason: str,
    log_path: str,
) -> dict[str, Any]:
    """Queue an exhausted supervised run in the validated central queue."""

    from arnold_pipelines.megaplan.cloud.current_target import resolve_current_target
    from arnold_pipelines.megaplan.cloud.repair_requests import (
        derive_repair_identity,
        enqueue_occurrence_bound_repair_request,
    )

    # ``remote_spec`` identifies the chain, not its current repair target.  The
    # central queue compares ``target.plan_name``/``milestone_or_plan`` with the
    # authoritative current plan and correctly rejects mismatches as stale.
    # Resolve that identity at enqueue time so a deterministic supervisor exit
    # cannot be discarded merely because the producer substituted a spec path.
    current_plan_name = ""
    current: dict[str, Any] | None = None
    try:
        current = resolve_current_target(
            session,
            marker_dir=Path(marker_dir),
            repair_data_dir=Path(marker_dir) / "repair-data",
        )
        refs = current.get("current_refs") if isinstance(current, dict) else {}
        if isinstance(refs, dict):
            current_plan_name = str(
                refs.get("current_plan_name")
                or refs.get("chain_current_plan_name")
                or refs.get("marker_plan_name")
                or ""
            ).strip()
    except (OSError, ValueError, TypeError):
        # An empty target is intentionally safer than the wrong target: intake
        # will bind it to its own authoritative observation instead of
        # terminalizing a valid request as advanced/stale.
        current_plan_name = ""

    target = {
        "workspace": str(workspace),
        "remote_spec": remote_spec,
        "supervise_log": log_path,
    }
    if current_plan_name:
        target["plan_name"] = current_plan_name

    problem_signature = _supervisor_problem_signature(
        reason=reason,
        current_plan_name=current_plan_name,
    )

    # Supervisor liveness and log metadata are evidence, not authority.  Only
    # reuse the complete identity persisted by the current-target owner.
    occurrence_identity = derive_repair_identity(current_target=current)

    return enqueue_occurrence_bound_repair_request(
        queue_root=queue_root,
        marker_dir=marker_dir,
        session=session,
        source="arnold_supervise_exit",
        workspace=workspace,
        run_kind=run_kind,
        target=target,
        problem_signature=problem_signature,
        root_cause_hint={"reason": reason, "supervise_log": log_path},
        occurrence_identity=occurrence_identity,
        evidence_cursor_digest=_derive_supervise_evidence_cursor_digest(
            log_path, marker_dir
        ),
        terminal_receipt_expectations=[
            "five_minute",
            "one_hour",
            "next_three_hour",
        ],
    )


def _derive_supervise_evidence_cursor_digest(
    log_path: str, marker_dir: str | Path
) -> str:
    """Derive evidence cursor digest from supervise and marker state."""
    parts: list[str] = []
    for path_str in (log_path, str(marker_dir)):
        try:
            stat = Path(path_str).stat()
            parts.append(f"{path_str}:{stat.st_mtime_ns}:{stat.st_size}")
        except OSError:
            parts.append(f"{path_str}:absent")
    if not parts:
        return ""
    digest = hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Main tick logic
# ---------------------------------------------------------------------------

def cloud_supervise_tick(
    root: Path,
    args: argparse.Namespace,
    spec: Any,
    provider: Any,
) -> dict[str, Any]:
    """Run a single supervisor tick and return a structured report.

    (a) Read chain status via ``cloud_chain_status_payload()``.
    (b) Refresh branch/PR/extra-repo sync (before any decisions).
    (c) Re-read ``cloud_chain_status_payload()``.
    (d) Block if provider consistency is mismatched.
    (e) Map refreshed ``effective_status`` to safe actions.
    (f) Execute only safe mutations.
    (g) Produce tick report with sync_refresh, provider_consistency,
        and extra_repo_sync always included.
    """
    # ── deferred imports to keep the module's top-level light ──────────
    from arnold_pipelines.megaplan.cloud.cli import (
        _resolve_remote_chain_spec,
        cloud_chain_status_payload,
    )
    from arnold_pipelines.megaplan.cloud import feature_flags

    attempt = begin_process_adapter_attempt(
        root,
        producer_family="cloud_supervision_adapter",
        adapter_name="cloud_supervise_tick",
        surface="tick",
        start_details={
            "spec_provider": getattr(spec, "provider", None),
            "session": getattr(args, "session", None),
        },
    )

    def _report(**kwargs: Any) -> dict[str, Any]:
        report = _tick_report(**kwargs)
        if report.get("acted"):
            attempt.effect(
                "mutation_requested",
                details={
                    "event": report.get("event"),
                    "next_action": report.get("next_action"),
                    "effective_status": report.get("effective_status"),
                },
            )
        attempt.terminal(
            status=str(report.get("effective_status") or "unknown"),
            outcome="succeeded" if bool(report.get("success")) else "indeterminate",
            details={
                "event": report.get("event"),
                "next_action": report.get("next_action"),
                "acted": bool(report.get("acted")),
                "refused_reason": report.get("refused_reason"),
            },
        )
        return report

    # ------------------------------------------------------------------
    # (a) Read initial chain status
    # ------------------------------------------------------------------
    try:
        payload = cloud_chain_status_payload(root, args, spec, provider)
    except Exception as exc:
        return _report(
            success=False,
            event="supervisor_error",
            spec="",
            effective_status="unknown",
            next_action="none",
            acted=False,
            refused_reason=f"chain status read failed: {exc}",
            runner={},
            sync={},
            pr={},
            logs={},
        )

    remote_spec = _resolve_remote_chain_spec(root, args, spec)
    # Use resolved workspace/session from the payload for all downstream work.
    resolved_workspace: str = payload.get("resolved_workspace", spec.repo.workspace)
    resolved_session: str = payload.get("resolved_session", "megaplan-chain")
    extra_repos: list[str] = (
        payload.get("resolved_context", {}).get("extra_repos", [])
    )
    status = payload.get("effective_status", "unknown")
    runner = payload.get("runner", {})
    sync_info = payload.get("sync", {})
    pr_info = payload.get("pr", {})
    logs_info = payload.get("logs", {})
    provider_consistency = payload.get("provider_consistency", {})
    extra_repo_sync_info = payload.get("chain_state", {}).get("extra_repo_sync", [])
    # Human-verification status from the cloud status payload (T11).
    # When the payload already probed the remote chain, use its data.
    # Section (c2) refreshes this for human-verification-relevant statuses.
    human_verification: dict[str, Any] = payload.get(
        "human_verification",
        {"status": "unavailable", "reason": "not probed"},
    )

    def l1_mutation_blocked_report(action: str) -> dict[str, Any]:
        """Return a truthful observation when an L1 effect is unauthorized."""
        return _report(
            success=True,
            event="supervisor_blocked",
            spec=remote_spec,
            effective_status=status,
            next_action="blocked",
            acted=False,
            refused_reason=(
                f"observed {action}; L1 mutation requires ARNOLD_AUTONOMY "
                "and ARNOLD_REPAIR_TRIGGER_ENABLED"
            ),
            runner=runner,
            sync=sync_info,
            pr=pr_info,
            logs=logs_info,
            sync_refresh=sync_refresh,
            provider_consistency=provider_consistency,
            extra_repo_sync=extra_repo_sync_info,
            human_verification=human_verification,
        )

    # ------------------------------------------------------------------
    # (b) Refresh branch/PR sync — BEFORE any restart/advance/wake decisions
    # ------------------------------------------------------------------
    ssh_meth = getattr(provider, "ssh_exec", None)
    sync_refresh: dict[str, Any] = {"status": "skipped", "reason": "no ssh_exec"}
    sync_refreshed = False
    sync_liveness_ok, sync_liveness_reason = _canonical_runner_mutation_gate(
        runner, require_dead=False
    )
    if (
        ssh_meth is not None
        and feature_flags.mutation_authorized(feature_flags.MUTATION_PATH_L1)
        and sync_liveness_ok
    ):
        try:
            chain_state_raw = payload.get("chain_state", {})
            pr_number_raw = (
                chain_state_raw.get("pr_number")
                if isinstance(chain_state_raw, dict)
                else None
            )
            pr_number: int | None = (
                int(pr_number_raw) if pr_number_raw is not None else None
            )
            sync_cmd = _remote_sync_refresh_command(
                resolved_workspace,
                remote_spec,
                branch=None,
                pr_number=pr_number,
                extra_repos=extra_repos if extra_repos else None,
                resolved_workspace=resolved_workspace,
                chain_session=resolved_session,
            )
            ssh_meth(sync_cmd)
            sync_refreshed = True
            sync_refresh = {"status": "ok"}
        except Exception as exc:
            # Sync refresh failure is now visible in the tick report.
            sync_refresh = {"status": "failed", "reason": str(exc)}
    elif ssh_meth is not None and not feature_flags.mutation_authorized(
        feature_flags.MUTATION_PATH_L1
    ):
        sync_refresh = {
            "status": "blocked",
            "reason": "L1 mutation authorization required for remote sync-state refresh",
        }
    elif ssh_meth is not None:
        sync_refresh = {
            "status": "blocked",
            "reason": sync_liveness_reason,
        }

    # ------------------------------------------------------------------
    # (c) Re-read chain status after sync refresh
    # ------------------------------------------------------------------
    if sync_refreshed:
        try:
            payload = cloud_chain_status_payload(root, args, spec, provider)
            status = payload.get("effective_status", status)
            runner = payload.get("runner", runner)
            sync_info = payload.get("sync", sync_info)
            pr_info = payload.get("pr", pr_info)
            logs_info = payload.get("logs", logs_info)
            provider_consistency = payload.get("provider_consistency", provider_consistency)
            extra_repo_sync_info = (
                payload.get("chain_state", {}).get("extra_repo_sync", extra_repo_sync_info)
            )
            human_verification = payload.get(
                "human_verification", human_verification
            )
        except Exception:
            # Re-read failed; keep the pre-refresh values.
            sync_refresh["re_read"] = "failed"

    # ------------------------------------------------------------------
    # (c2) Probe remote human-verification status (T11)
    #
    # Only probe when the effective status is human-verification-related
    # (``awaiting_human_verify``, ``human_prerequisite``) so that mock-based
    # tests with ordered ``ssh_exec`` results are not disrupted when the
    # supervisor tick handles a non-human-verification status.
    # ------------------------------------------------------------------
    from arnold_pipelines.megaplan.cloud.cli import _remote_human_verification_status_command

    current_plan_name = (
        payload.get("chain_state", {}).get("current_plan_name")
        if isinstance(payload.get("chain_state"), dict)
        else None
    )
    _hv_relevant_statuses = {"awaiting_human_verify", "human_prerequisite"}
    if (
        ssh_meth is not None
        and current_plan_name
        and status in _hv_relevant_statuses
    ):
        try:
            cmd = _remote_human_verification_status_command(
                resolved_workspace, current_plan_name
            )
            result = ssh_meth(cmd)
            stdout = (result.stdout or "").strip()
            if not stdout:
                human_verification = {
                    "status": "unavailable", "reason": "empty stdout"
                }
            else:
                hv_payload = json.loads(stdout)
                semantics = hv_payload.get("semantics")
                if semantics != "latest_verdict":
                    human_verification = {
                        "status": "unavailable",
                        "reason": (
                            f"remote payload semantics {semantics!r} != "
                            "'latest_verdict'; facts may be stale"
                        ),
                        "raw_semantics": semantics,
                    }
                else:
                    human_verification = {
                        "status": "available",
                        "pending": hv_payload.get("pending", 0),
                        "verified": hv_payload.get("verified", 0),
                        "all_deferred_must_verified": hv_payload.get(
                            "all_deferred_must_verified", False
                        ),
                        "rows": hv_payload.get("rows", []),
                        "semantics": semantics,
                    }
        except json.JSONDecodeError as exc:
            human_verification = {
                "status": "unavailable", "reason": f"invalid JSON: {exc}"
            }
        except Exception as exc:
            human_verification = {"status": "unavailable", "reason": str(exc)}

    # ------------------------------------------------------------------
    # (d) Block mutations on provider consistency mismatch
    # ------------------------------------------------------------------
    if provider_consistency.get("status") == "mismatch":
        return _report(
            success=True,
            event="supervisor_blocked",
            spec=remote_spec,
            effective_status=status,
            next_action="blocked",
            acted=False,
            refused_reason=(
                f"provider consistency mismatch: "
                f"{provider_consistency.get('reason', 'unknown')}"
            ),
            runner=runner,
            sync=sync_info,
            pr=pr_info,
            logs=logs_info,
            sync_refresh=sync_refresh,
            provider_consistency=provider_consistency,
            extra_repo_sync=extra_repo_sync_info,
            human_verification=human_verification,
        )

    # ------------------------------------------------------------------
    # (e) Map effective_status to safe actions
    # ------------------------------------------------------------------

    # --- running → noop ---
    if status == "running":
        return _report(
            success=True,
            event="supervisor_tick",
            spec=remote_spec,
            effective_status=status,
            next_action="noop",
            acted=False,
            refused_reason=None,
            runner=runner,
            sync=sync_info,
            pr=pr_info,
            logs=logs_info,
            sync_refresh=sync_refresh,
            provider_consistency=provider_consistency,
            extra_repo_sync=extra_repo_sync_info,
            human_verification=human_verification,
        )

    # --- complete / done → done ---
    if status == "complete":
        return _report(
            success=True,
            event="supervisor_tick",
            spec=remote_spec,
            effective_status=status,
            next_action="done",
            acted=False,
            refused_reason=None,
            runner=runner,
            sync=sync_info,
            pr=pr_info,
            logs=logs_info,
            sync_refresh=sync_refresh,
            provider_consistency=provider_consistency,
            extra_repo_sync=extra_repo_sync_info,
            human_verification=human_verification,
        )

    # --- human_prerequisite → blocked ---
    if status == "human_prerequisite":
        return _report(
            success=True,
            event="supervisor_blocked",
            spec=remote_spec,
            effective_status=status,
            next_action="blocked",
            acted=False,
            refused_reason=BLOCKED_REFUSAL_REASONS["human_prerequisite"],
            runner=runner,
            sync=sync_info,
            pr=pr_info,
            logs=logs_info,
            sync_refresh=sync_refresh,
            provider_consistency=provider_consistency,
            extra_repo_sync=extra_repo_sync_info,
            human_verification=human_verification,
        )

    # --- quality_gate → blocked ---
    if status == "quality_gate":
        return _report(
            success=True,
            event="supervisor_blocked",
            spec=remote_spec,
            effective_status=status,
            next_action="blocked",
            acted=False,
            refused_reason=BLOCKED_REFUSAL_REASONS["quality_gate"],
            runner=runner,
            sync=sync_info,
            pr=pr_info,
            logs=logs_info,
            sync_refresh=sync_refresh,
            provider_consistency=provider_consistency,
            extra_repo_sync=extra_repo_sync_info,
            human_verification=human_verification,
        )

    # --- awaiting_pr_merge → probe PR ---
    if status == "awaiting_pr_merge":
        pr_number_val = pr_info.get("pr_number") if isinstance(pr_info, dict) else None
        if pr_number_val is not None and ssh_meth is not None:
            try:
                pr_state_cmd = _remote_pr_state_command(resolved_workspace, int(pr_number_val))
                result = ssh_meth(pr_state_cmd)
                pr_state_output = (result.stdout or "").strip().lower()
            except Exception:
                pr_state_output = "unknown"
        else:
            pr_state_output = "unknown"

        if pr_state_output == "merged":
            # PR merged — advance with one-shot tick
            liveness_ok, liveness_reason = _canonical_runner_mutation_gate(
                runner, require_dead=True
            )
            if not liveness_ok:
                return _report(
                    success=True,
                    event="supervisor_blocked",
                    spec=remote_spec,
                    effective_status=status,
                    next_action="blocked",
                    acted=False,
                    refused_reason=(
                        "merged PR cannot advance without canonical exact-target "
                        f"dead liveness: {liveness_reason}"
                    ),
                    runner=runner,
                    sync=sync_info,
                    pr=pr_info,
                    logs=logs_info,
                    sync_refresh=sync_refresh,
                    provider_consistency=provider_consistency,
                    extra_repo_sync=extra_repo_sync_info,
                    human_verification=human_verification,
                )
            if not feature_flags.mutation_authorized(feature_flags.MUTATION_PATH_L1):
                return l1_mutation_blocked_report("merged PR eligible for advance")
            try:
                restart_cmd = _canonical_resume_command(
                    resolved_workspace, remote_spec, session_name=resolved_session
                )
                ssh_meth(restart_cmd)
                return _report(
                    success=True,
                    event="supervisor_advanced",
                    spec=remote_spec,
                    effective_status=status,
                    next_action="advance",
                    acted=True,
                    refused_reason=None,
                    runner=runner,
                    sync=sync_info,
                    pr=pr_info,
                    logs=logs_info,
                    sync_refresh=sync_refresh,
                    provider_consistency=provider_consistency,
                    extra_repo_sync=extra_repo_sync_info,
                    human_verification=human_verification,
                )
            except Exception as exc:
                return _report(
                    success=False,
                    event="supervisor_error",
                    spec=remote_spec,
                    effective_status=status,
                    next_action="blocked",
                    acted=False,
                    refused_reason=f"PR merged but restart failed: {exc}",
                    runner=runner,
                    sync=sync_info,
                    pr=pr_info,
                    logs=logs_info,
                    sync_refresh=sync_refresh,
                    provider_consistency=provider_consistency,
                    extra_repo_sync=extra_repo_sync_info,
                    human_verification=human_verification,
                )
        else:
            # PR not merged — blocked
            return _report(
                success=True,
                event="supervisor_blocked",
                spec=remote_spec,
                effective_status=status,
                next_action="blocked",
                acted=False,
                refused_reason=(
                    f"awaiting PR merge (PR #{pr_number_val} state={pr_state_output}); "
                    "supervisor will not advance until PR is merged"
                ),
                runner=runner,
                sync=sync_info,
                pr=pr_info,
                logs=logs_info,
                sync_refresh=sync_refresh,
                provider_consistency=provider_consistency,
                extra_repo_sync=extra_repo_sync_info,
                human_verification=human_verification,
            )

    # --- stale_bookkeeping with dead/missing runner → restart ---
    if status == "stale_bookkeeping":
        liveness_ok, liveness_reason = _canonical_runner_mutation_gate(
            runner, require_dead=True
        )
        if liveness_ok and ssh_meth is not None:
            if not feature_flags.mutation_authorized(feature_flags.MUTATION_PATH_L1):
                return l1_mutation_blocked_report("stale bookkeeping eligible for restart")
            try:
                restart_cmd = _canonical_resume_command(
                    resolved_workspace, remote_spec, session_name=resolved_session
                )
                ssh_meth(restart_cmd)
                return _report(
                    success=True,
                    event="supervisor_restarted",
                    spec=remote_spec,
                    effective_status=status,
                    next_action="restart",
                    acted=True,
                    refused_reason=None,
                    runner=runner,
                    sync=sync_info,
                    pr=pr_info,
                    logs=logs_info,
                    sync_refresh=sync_refresh,
                    provider_consistency=provider_consistency,
                    extra_repo_sync=extra_repo_sync_info,
                    human_verification=human_verification,
                )
            except Exception as exc:
                return _report(
                    success=False,
                    event="supervisor_error",
                    spec=remote_spec,
                    effective_status=status,
                    next_action="blocked",
                    acted=False,
                    refused_reason=f"stale bookkeeping restart failed: {exc}",
                    runner=runner,
                    sync=sync_info,
                    pr=pr_info,
                    logs=logs_info,
                    sync_refresh=sync_refresh,
                    provider_consistency=provider_consistency,
                    extra_repo_sync=extra_repo_sync_info,
                    human_verification=human_verification,
                )
        else:
            # Canonical target is live/unknown, or no ssh_exec — blocked.
            if ssh_meth is None:
                reason = "stale bookkeeping but provider lacks ssh_exec; cannot restart runner"
            else:
                reason = f"stale bookkeeping restart refused: {liveness_reason}"
            return _report(
                success=True,
                event="supervisor_blocked",
                spec=remote_spec,
                effective_status=status,
                next_action="blocked",
                acted=False,
                refused_reason=reason,
                runner=runner,
                sync=sync_info,
                pr=pr_info,
                logs=logs_info,
                sync_refresh=sync_refresh,
                provider_consistency=provider_consistency,
                extra_repo_sync=extra_repo_sync_info,
                human_verification=human_verification,
            )

    # --- awaiting_human_verify → observe verification state ---
    #
    # The supervisor NEVER writes verification records or transitions plan
    # state — it only observes ``human_verifications.json`` via the remote
    # ``verify-human --list --json`` probe (populated above in (c2)).
    if status == "awaiting_human_verify":
        # (a) Verification facts unavailable / invalid / missing semantics → block
        if human_verification.get("status") != "available":
            return _report(
                success=True,
                event="supervisor_blocked",
                spec=remote_spec,
                effective_status=status,
                next_action="blocked",
                acted=False,
                refused_reason=(
                    "awaiting human verification but verification facts are "
                    f"unavailable: {human_verification.get('reason', 'unknown')}"
                ),
                runner=runner,
                sync=sync_info,
                pr=pr_info,
                logs=logs_info,
                sync_refresh=sync_refresh,
                provider_consistency=provider_consistency,
                extra_repo_sync=extra_repo_sync_info,
                human_verification=human_verification,
            )

        # (b) Pending deferred-must criteria remain (including latest-verdict
        #     ``fail`` records) → block with pending details
        if not human_verification.get("all_deferred_must_verified", False):
            pending_count: int = human_verification.get("pending", 0)
            verified_count: int = human_verification.get("verified", 0)
            return _report(
                success=True,
                event="supervisor_blocked",
                spec=remote_spec,
                effective_status=status,
                next_action="blocked",
                acted=False,
                refused_reason=(
                    f"awaiting human verification: {pending_count} pending, "
                    f"{verified_count} verified of deferred-must criteria; "
                    "latest-verdict semantics require a 'pass' verdict on "
                    "every criterion before the chain can wake"
                ),
                runner=runner,
                sync=sync_info,
                pr=pr_info,
                logs=logs_info,
                sync_refresh=sync_refresh,
                provider_consistency=provider_consistency,
                extra_repo_sync=extra_repo_sync_info,
                human_verification=human_verification,
            )

        # (c) All deferred-must criteria verified by latest ``pass`` records
        #     AND the resolved runner session is dead / unavailable → wake
        liveness_ok, liveness_reason = _canonical_runner_mutation_gate(
            runner, require_dead=True
        )
        if liveness_ok and ssh_meth is not None:
            if not feature_flags.mutation_authorized(feature_flags.MUTATION_PATH_L1):
                return l1_mutation_blocked_report("verified runner eligible for wake")
            try:
                restart_cmd = _canonical_resume_command(
                    resolved_workspace,
                    remote_spec,
                    session_name=resolved_session,
                )
                ssh_meth(restart_cmd)
                return _report(
                    success=True,
                    event="supervisor_restarted",
                    spec=remote_spec,
                    effective_status=status,
                    next_action="restart",
                    acted=True,
                    refused_reason=None,
                    runner=runner,
                    sync=sync_info,
                    pr=pr_info,
                    logs=logs_info,
                    sync_refresh=sync_refresh,
                    provider_consistency=provider_consistency,
                    extra_repo_sync=extra_repo_sync_info,
                    human_verification=human_verification,
                )
            except Exception as exc:
                return _report(
                    success=False,
                    event="supervisor_error",
                    spec=remote_spec,
                    effective_status=status,
                    next_action="blocked",
                    acted=False,
                    refused_reason=(
                        "all human-verification criteria satisfied but wake "
                        f"restart failed: {exc}"
                    ),
                    runner=runner,
                    sync=sync_info,
                    pr=pr_info,
                    logs=logs_info,
                    sync_refresh=sync_refresh,
                    provider_consistency=provider_consistency,
                    extra_repo_sync=extra_repo_sync_info,
                    human_verification=human_verification,
                )

        # (d) All verified but target is live/unknown → no mutation.
        if ssh_meth is None:
            return _report(
                success=True,
                event="supervisor_blocked",
                spec=remote_spec,
                effective_status=status,
                next_action="blocked",
                acted=False,
                refused_reason=(
                    "all human-verification criteria satisfied but provider "
                    "lacks ssh_exec; cannot wake runner"
                ),
                runner=runner,
                sync=sync_info,
                pr=pr_info,
                logs=logs_info,
                sync_refresh=sync_refresh,
                provider_consistency=provider_consistency,
                extra_repo_sync=extra_repo_sync_info,
                human_verification=human_verification,
            )
        if not liveness_ok:
            return _report(
                success=True,
                event="supervisor_blocked",
                spec=remote_spec,
                effective_status=status,
                next_action="blocked",
                acted=False,
                refused_reason=(
                    "human-verification wake refused without canonical exact-target "
                    f"dead liveness: {liveness_reason}"
                ),
                runner=runner,
                sync=sync_info,
                pr=pr_info,
                logs=logs_info,
                sync_refresh=sync_refresh,
                provider_consistency=provider_consistency,
                extra_repo_sync=extra_repo_sync_info,
                human_verification=human_verification,
            )
        return _report(
            success=True,
            event="supervisor_tick",
            spec=remote_spec,
            effective_status=status,
            next_action="noop",
            acted=False,
            refused_reason=None,
            runner=runner,
            sync=sync_info,
            pr=pr_info,
            logs=logs_info,
            sync_refresh=sync_refresh,
            provider_consistency=provider_consistency,
            extra_repo_sync=extra_repo_sync_info,
            human_verification=human_verification,
        )

    # ------------------------------------------------------------------
    # Fallback — unknown status
    # ------------------------------------------------------------------
    return _report(
        success=True,
        event="supervisor_tick",
        spec=remote_spec,
        effective_status=status,
        next_action="noop",
        acted=False,
        refused_reason=f"unknown effective_status: {status}",
        runner=runner,
        sync=sync_info,
        pr=pr_info,
        logs=logs_info,
        sync_refresh=sync_refresh,
        provider_consistency=provider_consistency,
        extra_repo_sync=extra_repo_sync_info,
        human_verification=human_verification,
    )
