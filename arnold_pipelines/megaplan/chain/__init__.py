"""Chain driver — run a pipeline of milestone plans with state kept in megaplan.

This replaces ad-hoc bash orchestration (`chain.sh`). A YAML spec declares an
optional seed plan and an ordered list of milestones; each milestone is
initialized from an idea file, then driven to `done` via the same auto-loop
entry point used by `megaplan auto`.

Plan state stays in megaplan. Bash is no longer responsible for polling or
deciding the next step — only for process/container liveness.

Spec format (YAML)::

    base_branch: main
    seed:
      plan: milestone-m0-from-docs-state-20260415-0217
    milestones:
      - label: m1
        idea: /workspace/ideas/M1-foundation-store.txt
        branch: megaplan/m1-foundation-store   # optional, currently informational
        profile: thoughtful                     # optional init rubric knobs
        robustness: standard
        vendor: claude
        depth: high
        critic: kimi
        with_prep: true
        with_feedback: true
        prep_direction: |               # optional steering for the prep phase
          focus on the worker shutdown path and how cancel signals propagate
          to inflight tasks; skip CLI plumbing.
        deepseek_provider: direct
      - label: m1a
        idea: /workspace/ideas/M1a-settings-store.txt
    on_failure:
      abort: stop_chain          # stop_chain | skip_milestone | retry_milestone
    on_escalate:
      abort: stop_chain          # stop_chain | skip_milestone | retry_milestone

Progress is persisted under ``.megaplan/plans/.chains/`` so a relaunched
process can resume where the previous run left off without dirtying milestone
branches.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from arnold_pipelines.megaplan.auto import (
    DEFAULT_MAX_ITERATIONS,
    DEFAULT_PHASE_TIMEOUT_SECONDS,
    DEFAULT_POLL_SLEEP_SECONDS,
    DEFAULT_STALL_THRESHOLD,
    DEFAULT_STATUS_TIMEOUT_SECONDS,
    DriverOutcome,
    ESCALATE_ACTIONS,
    drive as auto_drive,
)
from arnold_pipelines.megaplan.feature_flags import supervisor_tier_routing_on
from arnold_pipelines.megaplan._core.phase_runtime import active_step_has_live_worker
from arnold_pipelines.megaplan.runtime.execution_environment import (
    merge_isolation_evidence,
    resolve_execution_environment,
)
from arnold_pipelines.megaplan._core import (
    list_batch_artifacts,
    atomic_write_json,
    atomic_write_text,
    resolve_plan_dir,
    save_state_merge_meta,
)
from arnold_pipelines.megaplan._core.user_config import VALID_VENDORS
from arnold_pipelines.megaplan.layout import retired_chain_marker
from arnold_pipelines.megaplan.orchestration.authority_readers import (
    _is_explained_noop_completion,
    AuthorityDecision,
    accepted_attempt_execution_projection,
    effective_execute_completed_task_ids,
    load_evidence_nucleus,
)
from arnold_pipelines.megaplan.profiles import (
    VALID_CRITIC_CHOICES,
    VALID_DEEPSEEK_PROVIDER_CHOICES,
    VALID_DEPTH_CHOICES,
    _resolve_default_vendor,
    load_profile_metadata,
)
from arnold_pipelines.megaplan.runtime.process import (
    megaplan_engine_env,
    megaplan_engine_root,
)
from arnold_pipelines.megaplan.anchors import AnchorCaptureRequest, attach_anchor_documents, resolve_anchor_path
from arnold_pipelines.megaplan.resolutions import effective_user_action_resolutions
from arnold_pipelines.megaplan.user_actions import action_resolution_status
from arnold_pipelines.megaplan.types import CliError
from arnold_pipelines.megaplan.planning.state import (
    STATE_AWAITING_PR_MERGE,
    STATE_AWAITING_HUMAN_VERIFY,
    STATE_BLOCKED,
    STATE_DONE,
    STATE_EXECUTED,
    STATE_FINALIZED,
    STATE_PREPPED,
)
from arnold_pipelines.megaplan.workflows.boundary_contracts import (
    CHAIN_COMPLETE_ROW_ID,
    CHAIN_MILESTONE_COMPLETION_ROW_ID,
    CHAIN_MILESTONE_START_ROW_ID,
)
from . import spec as chain_spec
from .advancement import policy_for_spec

APEX_EXTREME_RETRY_CAP = chain_spec.APEX_EXTREME_RETRY_CAP
BLOCKED_EXECUTE_OUTCOME_STATUSES = chain_spec.BLOCKED_EXECUTE_OUTCOME_STATUSES
ChainSpec = chain_spec.ChainSpec
ChainState = chain_spec.ChainState
FreshChildAdmissionSpec = chain_spec.FreshChildAdmissionSpec
DEFAULT_MILESTONE_RETRY_CAP = chain_spec.DEFAULT_MILESTONE_RETRY_CAP
DEPTH_BUMP_ORDER = chain_spec.DEPTH_BUMP_ORDER
FailurePolicy = chain_spec.FailurePolicy
MilestoneSpec = chain_spec.MilestoneSpec
PROFILE_BUMP_ORDER = chain_spec.PROFILE_BUMP_ORDER
ROBUSTNESS_BUMP_ORDER = chain_spec.ROBUSTNESS_BUMP_ORDER


def _admit_fresh_child_for_plan(
    *,
    root: Path,
    spec_path: Path,
    spec: ChainSpec,
    state: ChainState,
    milestone: MilestoneSpec,
    milestone_index: int,
    plan_name: str,
) -> dict[str, Any] | None:
    """Admit an opted-in independent child before any phase/model dispatch.

    The import is intentionally lazy: legacy chain specs do not instantiate
    Run Authority/WBC/Custody owners and therefore retain their historical
    launch path.  Enabled admission fails closed when the canonical owner
    implementation or any configured binding is unavailable.
    """

    config = spec.fresh_child_admission
    if config is None or not config.enabled:
        return None
    from .fresh_child_launch import FreshChildLaunchError, admit_fresh_child

    try:
        return admit_fresh_child(
            root=root,
            spec_path=spec_path,
            spec=config,
            state=state,
            milestone=milestone,
            milestone_index=milestone_index,
            plan_name=plan_name,
        )
    except FreshChildLaunchError as exc:
        raise CliError("fresh_child_admission_failed", str(exc)) from exc


def _ensure_fresh_child_for_plan(
    *,
    root: Path,
    spec_path: Path,
    spec: ChainSpec,
    state: ChainState,
    milestone: MilestoneSpec,
    milestone_index: int,
    plan_name: str,
) -> dict[str, Any] | None:
    """Complete a pending fresh-child admission, including crash replay.

    Chain state is persisted before the first owner call.  If the process dies
    after owner writes but before the state metadata write, the next launch
    enters this function with the same ``current_plan_name`` and the canonical
    owner transaction replays idempotently.  A recorded summary is the only
    successful skip condition; no PID/status sidecar is treated as admission.
    """

    config = spec.fresh_child_admission
    if config is None or not config.enabled:
        return None
    metadata = state.metadata if isinstance(state.metadata, dict) else {}
    records = metadata.get("fresh_child_admissions")
    if isinstance(records, dict) and isinstance(records.get(milestone.label), dict):
        from arnold_pipelines.megaplan._core.state import write_plan_state
        plan_dir = resolve_plan_dir(root, plan_name)
        recorded = dict(records[milestone.label])

        def _reproject_child(current: dict[str, Any]) -> bool:
            meta = current.setdefault("meta", {})
            if not isinstance(meta, dict):
                current["meta"] = meta = {}
            existing = meta.get("fresh_child_admission")
            if existing is not None and existing != recorded:
                raise CliError(
                    "fresh_child_admission_failed",
                    "child admission replay identity conflict",
                )
            meta["fresh_child_admission"] = recorded
            return True
        write_plan_state(
            plan_dir, mode="patch-many", patch={}, mutation=_reproject_child
        )
        return None
    admission = _admit_fresh_child_for_plan(
        root=root,
        spec_path=spec_path,
        spec=spec,
        state=state,
        milestone=milestone,
        milestone_index=milestone_index,
        plan_name=plan_name,
    )
    if admission is None:
        return None
    state.metadata = dict(metadata)
    admissions = dict(state.metadata.get("fresh_child_admissions") or {})
    admissions[milestone.label] = admission
    state.metadata["fresh_child_admissions"] = admissions
    # Carry the owner-admitted child tuple into the initialized plan.  This is
    # an additive projection; it does not activate or write a phase ledger.
    from arnold_pipelines.megaplan._core.state import write_plan_state
    plan_dir = resolve_plan_dir(root, plan_name)

    def _project_child(current: dict[str, Any]) -> bool:
        meta = current.setdefault("meta", {})
        if not isinstance(meta, dict):
            current["meta"] = meta = {}
        existing = meta.get("fresh_child_admission")
        if existing is not None and existing != admission:
            raise CliError(
                "fresh_child_admission_failed",
                "child admission projection identity conflict",
            )
        meta["fresh_child_admission"] = dict(admission)
        return True
    write_plan_state(plan_dir, mode="patch-many", patch={}, mutation=_project_child)
    return admission


def _terminalize_fresh_child_for_plan(
    *,
    root: Path,
    state: ChainState,
    milestone: MilestoneSpec,
    milestone_index: int,
    plan_name: str,
    outcome_kind: str,
    outcome_status: str,
) -> None:
    """Close the admitted child lifecycle once the milestone is terminal."""
    records = (
        state.metadata.get("fresh_child_admissions")
        if isinstance(state.metadata, dict)
        else None
    )
    if not isinstance(records, dict):
        return
    pointer = records.get(milestone.label)
    if not isinstance(pointer, dict):
        return
    from arnold_pipelines.megaplan.chain.fresh_child_launch import (
        terminalize_fresh_child,
    )

    terminalize_fresh_child(
        pointer,
        plan_dir=resolve_plan_dir(root, plan_name),
        outcome_kind=outcome_kind,
        outcome_payload={
            "schema": "arnold.megaplan.fresh_child_terminal.v1",
            "milestone_label": milestone.label,
            "milestone_index": milestone_index,
            "plan_name": plan_name,
            "outcome_status": outcome_status,
        },
    )


def _automatic_pr_progression_permitted(
    spec: ChainSpec, spec_path: Path
) -> bool:
    """Return the shared effective PR review/merge policy decision."""

    return policy_for_spec(
        spec,
        runtime_overrides=chain_spec.load_runtime_policy(spec_path),
    ).automatic_pr_progression
VALID_FAILURE_ACTIONS = chain_spec.VALID_FAILURE_ACTIONS
VALID_CLEAN_MILESTONE_PR_POLICIES = chain_spec.VALID_CLEAN_MILESTONE_PR_POLICIES
VALID_PREREQUISITE_POLICIES = chain_spec.VALID_PREREQUISITE_POLICIES
VALID_VALIDATION_POLICIES = chain_spec.VALID_VALIDATION_POLICIES
RESUMABLE_RETRY_STATES = frozenset(
    {STATE_FINALIZED, STATE_EXECUTED, "critiqued", "gated"}
)
_bump_one_tier = chain_spec._bump_one_tier
_legacy_state_path_for = chain_spec._legacy_state_path_for
_optional_bool = chain_spec._optional_bool
_optional_choice = chain_spec._optional_choice
_runtime_policy_path_for = chain_spec._runtime_policy_path_for
_state_path_for = chain_spec._state_path_for
_warn_chain_fallback = chain_spec._warn_chain_fallback
effective_chain_policy = chain_spec.effective_chain_policy
load_chain_state = chain_spec.load_chain_state
load_runtime_policy = chain_spec.load_runtime_policy
load_spec = chain_spec.load_spec
require_runtime_manifest_permit = chain_spec.require_runtime_manifest_permit
save_chain_state = chain_spec.save_chain_state
save_runtime_policy = chain_spec.save_runtime_policy
validate_paths = chain_spec.validate_paths

log = logging.getLogger("megaplan")


TERMINAL_SKIP_STATES = ("done", "aborted", "failed")
NOOP_COMPLETION_SCHEMA = "megaplan.noop_completion"
NOOP_COMPLETION_SCOPES = frozenset(
    {"docs_only", "already_satisfied_by_base", "planning_only", "infra_only"}
)
# P6 end-of-epic reconciliation. A ``kind: reconcile`` milestone selects
# engine-source commits for a reviewed PR onto its ``target_branch``; the
# controller-side skip detection writes ``reconcile-verification.json`` (this
# schema) into the plan dir when the engine change set is empty or already
# promoted, and the completion guard accepts it exactly like the no-op waiver.
RECONCILE_VERIFICATION_SCHEMA = "reconcile-verification/1"
# Durable skip record for the generated ``kind: reconcile`` milestone: when a
# legacy chain's terminal milestone declares a ``final_conformance_gate``, the
# reconcile milestone is RECORDED as skipped in an atomic sidecar next to the
# spec (this schema) instead of being a log-only event. The sidecar is read on
# restart so the skip survives crashes and is never silently re-run.
RECONCILE_SKIP_FILENAME = "reconcile-skip.json"
RECONCILE_SKIP_SCHEMA = "reconcile-skip/1"
# Engine-source allowlist: paths whose changes are the reconcile milestone's
# subject. Everything else in the epic's commit range is chain/bookkeeping
# work that promotion already covers or that never reaches the shared base.
ENGINE_SOURCE_ROOTS = ("arnold_pipelines/", "arnold/")
GH_TRANSIENT_ERROR_PATTERNS = (
    " 500",
    " 502",
    " 503",
    " 504",
    "deadline exceeded",
    "http 500",
    "http 502",
    "http 503",
    "http 504",
    "gateway timeout",
    "i/o timeout",
    "net/http:",
    "service unavailable",
    "bad gateway",
    "graphql: timeout",
    "graphql timeout",
    "temporary failure",
    "temporarily unavailable",
    "timed out",
    "try again",
)
GH_PR_STATE_ATTEMPTS = 3


def _write_chain_policy_into_plan_meta(
    root: Path,
    plan_name: str,
    spec: ChainSpec,
    spec_path: Path,
    milestone_label: str,
) -> None:
    """Record effective chain policy in the plan's ``state.json`` metadata.

    Reads the plan's state.json, merges ``meta.chain_policy``, and writes
    back atomically.  Does nothing if the plan directory cannot be resolved
    (best-effort, non-critical).
    """
    from arnold_pipelines.megaplan._core import read_json
    from arnold_pipelines.megaplan._core.state import write_plan_state

    try:
        plan_dir = resolve_plan_dir(root, plan_name)
    except CliError:
        _warn_chain_fallback(
            "M3A_WARN_CHAIN_POLICY_WRITE",
            reason="plan_dir_unavailable",
            context={"plan": plan_name},
        )
        return
    state_path = plan_dir / "state.json"
    if not state_path.exists():
        return
    try:
        state = read_json(state_path)
    except FileNotFoundError:
        return
    except json.JSONDecodeError:
        _warn_chain_fallback(
            "M3A_WARN_CHAIN_META_WRITE",
            reason="corrupt_json",
            path=state_path,
        )
        return
    except (OSError, UnicodeDecodeError):
        _warn_chain_fallback(
            "M3A_WARN_CHAIN_META_WRITE",
            reason="unreadable",
            path=state_path,
        )
        return
    if not isinstance(state, dict):
        return
    runtime_overrides = chain_spec.load_runtime_policy(spec_path)
    effective = chain_spec.effective_chain_policy(spec, runtime_overrides)
    chain_policy = {
        "prerequisite_policy": effective["prerequisite_policy"],
        "validation_policy": effective["validation_policy"],
        "review_policy": effective["review_policy"],
        "driver_auto_approve": bool(spec.auto_approve),
        "source": effective["source"],
        "milestone_label": milestone_label,
    }
    # A paused-checkout source cutover records the canonical binding on the
    # chain/marker while the historical aborted plan remains byte-preserved.
    # Carry that binding into the next materialized plan so the existing
    # chain/plan binding assertion has one authoritative projection.
    try:
        chain_state = chain_spec.load_chain_state(spec_path)
        source_binding = chain_state.metadata.get("project_source_binding")
        if isinstance(source_binding, Mapping):
            chain_policy["project_source_binding"] = dict(source_binding)
    except (CliError, OSError, ValueError, TypeError):
        pass
    try:
        chain_policy["milestone_base_sha"] = _current_head_sha(root)
    except CliError:
        pass

    def _patch_chain_policy(current: dict[str, Any]) -> bool:
        meta = current.setdefault("meta", {})
        if not isinstance(meta, dict):
            current["meta"] = meta = {}
        meta["chain_policy"] = chain_policy
        if isinstance(chain_policy.get("project_source_binding"), Mapping):
            meta["project_source_binding"] = dict(chain_policy["project_source_binding"])
        return True

    write_plan_state(
        plan_dir, mode="patch-many", patch={}, mutation=_patch_chain_policy
    )


def _attach_chain_anchors_to_plan(root: Path, spec_path: Path, plan_name: str, spec: ChainSpec, milestone: MilestoneSpec) -> None:
    from arnold_pipelines.megaplan._core import read_json
    from arnold_pipelines.megaplan._core.state import write_plan_state

    requests: list[AnchorCaptureRequest] = []
    if spec.anchors.north_star:
        requests.append(
            AnchorCaptureRequest(
                anchor_type="north_star",
                scope="epic",
                source_path=resolve_anchor_path(spec_path, spec.anchors.north_star),
                source_kind="chain",
                source_spec_path=spec_path,
            )
        )
    if milestone.anchors.north_star:
        requests.append(
            AnchorCaptureRequest(
                anchor_type="north_star",
                scope="plan",
                source_path=resolve_anchor_path(spec_path, milestone.anchors.north_star),
                source_kind="milestone",
                label=milestone.label,
                source_spec_path=spec_path,
            )
        )
    if not requests:
        return
    plan_dir = resolve_plan_dir(root, plan_name)
    state = read_json(plan_dir / "state.json")
    if not isinstance(state, dict):
        return

    def _patch_anchors(current: dict[str, Any]) -> bool:
        attach_anchor_documents(plan_dir=plan_dir, state=current, documents=requests, project_root=root)
        return True

    write_plan_state(plan_dir, mode="patch-many", patch={}, mutation=_patch_anchors)


# ---------------------------------------------------------------------------
# Driving
# ---------------------------------------------------------------------------


def _plan_state(root: Path, plan: str, *, timeout: float) -> str:
    """Read just the `state` field of a plan via `megaplan status`.

    Returns "missing" if the plan is not found. Used to decide whether to skip
    driving (plan already terminal) vs. run the full auto loop.
    """
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-P",
                "-m",
                "arnold_pipelines.megaplan",
                "status",
                "--project-dir",
                str(root),
                "--plan",
                plan,
            ],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            env=megaplan_engine_env(),
        )
    except subprocess.TimeoutExpired:
        return "unknown"
    if proc.returncode != 0:
        return "missing"
    try:
        return json.loads(proc.stdout).get("state", "unknown")
    except json.JSONDecodeError:
        return "unknown"


from .git_ops import (
    _branch_head,
    _capture_pr_merged_evidence,
    _capture_pr_ready_evidence,
    _capture_sync_state,
    _checkout_milestone_branch,
    _claimed_nested_repo_paths,
    _claimed_nested_repos,
    _claimed_paths,
    _claimed_root_paths,
    _classify_sync_state,
    _command_env,
    _commit_and_push_phase,
    _commit_phase,
    _cherry_pick_reconcile_selection,
    _delete_reconcile_pr_branch,
    _dirty_nested_repos_from_claimed_paths,
    _dirty_worktree_paths,
    _enable_auto_merge,
    _ensure_milestone_pr,
    _ensure_reconcile_pr,
    _fetch_base_branch,
    _is_transient_gh_error,
    _is_worktree_dirty,
    _list_open_pr_for_branch,
    _mark_pr_ready,
    _parse_pr_number_from_url,
    _pr_state,
    _require_git_worktree_root,
    _reconcile_terminal_pr_state,
    _refresh_base_branch,
    _remote_branch_exists,
    _remote_branch_head,
    _reset_staged_paths,
    _run_command,
    _run_git_push_command,
    _should_retry_gh_without_env,
)


def _init_plan(
    root: Path,
    idea_path: str,
    *,
    robustness: str,
    auto_approve: bool,
    profile: str | None = None,
    vendor: str | None = None,
    depth: str | None = None,
    critic: str | None = None,
    deepseek_provider: str | None = None,
    with_prep: bool = False,
    with_feedback: bool = False,
    prep_clarify: bool = True,
    prep_direction: str | None = None,
    phase_model: list[str] | None = None,
    writer,
) -> str:
    """Run `megaplan init --idea-file ...` and return the plan name."""
    # The init subprocess does not run from the engine root, but a spec-relative
    # idea path must be resolved against the project root here — otherwise init
    # depends on caller cwd and can fail with a misleading BRIEF_MISSING.
    root = root.resolve(strict=False)
    idea_path = str(_resolve_idea_path(root, idea_path))
    _warn_vendor_ignored_for_locked_profile(
        root,
        profile=profile,
        vendor=vendor,
        writer=writer,
    )
    args = [
        sys.executable,
        "-P",
        "-m",
        "arnold_pipelines.megaplan",
        "init",
        "--project-dir",
        str(root),
    ]
    if auto_approve:
        args.append("--auto-approve")
    args.extend(["--robustness", robustness])
    if profile:
        args.extend(["--profile", profile])
    if vendor:
        args.extend(["--vendor", vendor])
    if depth:
        args.extend(["--depth", depth])
    if critic:
        args.extend(["--critic", critic])
    if deepseek_provider:
        args.extend(["--deepseek-provider", deepseek_provider])
    if with_prep:
        args.append("--with-prep")
    if with_feedback:
        args.append("--with-feedback")
    if not prep_clarify:
        args.append("--no-prep-clarify")
    if prep_direction:
        args.extend(["--prep-direction", prep_direction])
    for override in phase_model or []:
        args.extend(["--phase-model", override])
    args.extend(["--idea-file", str(idea_path)])
    writer(f"[chain] initializing plan from {idea_path}\n")
    proc = subprocess.run(
        args,
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
        env=megaplan_engine_env(),
    )
    if proc.returncode != 0:
        raise CliError(
            "init_failed",
            f"megaplan init failed (rc={proc.returncode}): "
            f"{proc.stderr.strip() or proc.stdout.strip()[-400:]}",
        )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise CliError(
            "init_failed", f"megaplan init produced non-JSON output: {exc}"
        ) from exc
    plan = payload.get("plan")
    if not isinstance(plan, str) or not plan:
        raise CliError("init_failed", "megaplan init did not return a plan name")
    writer(f"[chain] launched plan={plan}\n")
    return plan


def _warn_vendor_ignored_for_locked_profile(
    root: Path,
    *,
    profile: str | None,
    vendor: str | None,
    writer,
) -> None:
    if not profile:
        return
    try:
        metadata = load_profile_metadata(project_dir=root)
    except Exception as exc:
        raise CliError(
            "vendor_lock_profile_load",
            "M3B_HALT_VENDOR_LOCK_PROFILE_LOAD: "
            f"failed to load profile metadata while evaluating vendor lock for profile {profile}: {exc}",
            extra={"profile": profile},
        ) from exc
    if not bool((metadata.get(profile) or {}).get("vendor_locked", False)):
        return
    effective_vendor = vendor
    inherited = False
    if effective_vendor is None:
        try:
            effective_vendor = _resolve_default_vendor()
            inherited = True
        except Exception as exc:
            raise CliError(
                "vendor_lock_resolve",
                "M3B_HALT_VENDOR_LOCK_RESOLVE: "
                f"failed to resolve the default vendor while evaluating vendor lock for profile {profile}: {exc}",
                extra={"profile": profile},
            ) from exc
    if effective_vendor not in VALID_VENDORS:
        return
    source = "inherited " if inherited else ""
    writer(
        f"[chain] WARNING: profile {profile} is vendor-locked; "
        f"{source}vendor={effective_vendor} is ignored.\n"
    )


def _seed_plan_phase_timeout(root: Path, plan: str, timeout_seconds: float) -> None:
    """Seed the plan's execute-phase budget from the chain driver's phase timeout.

    The chain spec's ``driver.phase_timeout`` is the chain-authoritative per-phase
    budget.  Feasibility derives the execute-phase budget from the plan config
    (``phase_timeout_seconds`` / ``phase_timeout``) and falls back to the engine
    default when the plan config does not carry it, which can reject a graph the
    chain owner explicitly sized for a longer phase.  Idempotent: never overwrites
    an explicit plan-level setting.
    """
    try:
        state_path = root / ".megaplan" / "plans" / plan / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    config = state.get("config")
    if not isinstance(config, dict):
        return
    if (
        config.get("phase_timeout_seconds") is not None
        or config.get("phase_timeout") is not None
    ):
        return
    config["phase_timeout_seconds"] = float(timeout_seconds)
    atomic_write_json(state_path, state)


def _sync_plan_auto_approve(root: Path, plan: str, auto_approve: bool) -> None:
    """Synchronize the chain-owned plan's ``config.auto_approve`` with the spec.

    ``driver.auto_approve`` is chain-authoritative (``_init_plan`` passes it at
    birth; there is no supported per-plan override).  A plan resumed after the
    chain adopted a successor spec can carry a stale pre-adoption snapshot that
    would wrongly suppress the auto-approve discharge
    (``auto._auto_verify_deferred_must_criteria``).  Synchronize BOTH directions
    (false -> true and true -> false) so this is policy propagation, not guard
    weakening.  Idempotent: writes only when a value differs; preserves any
    existing ``meta.chain_policy`` provenance.
    """
    try:
        state_path = root / ".megaplan" / "plans" / plan / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    config = state.get("config")
    if not isinstance(config, dict):
        return
    target = bool(auto_approve)
    changed = config.get("auto_approve") != target
    meta = state.get("meta")
    if not isinstance(meta, dict):
        meta = None
    chain_policy = meta.get("chain_policy") if isinstance(meta, dict) else None
    if not isinstance(chain_policy, dict):
        chain_policy = None
    if chain_policy is not None and chain_policy.get("driver_auto_approve") != target:
        changed = True
    if not changed:
        return
    config["auto_approve"] = target
    if isinstance(meta, dict):
        cp = meta.setdefault("chain_policy", {})
        if not isinstance(cp, dict):
            meta["chain_policy"] = cp = {}
        cp["driver_auto_approve"] = target
    atomic_write_json(state_path, state)


def _drive_plan(
    root: Path,
    plan: str,
    spec: ChainSpec,
    *,
    on_phase_complete: Callable[[str, int, str, str], None] | None = None,
    writer,
) -> DriverOutcome:
    """Run the auto driver for a single plan."""
    original_cwd = Path.cwd()
    previous_provider = os.environ.get("MEGAPLAN_ENGINE_ISOLATION_PROVIDER")
    self_hosted = False
    if not previous_provider:
        try:
            self_hosted = root.resolve() == megaplan_engine_root()
        except Exception:
            self_hosted = False
        if self_hosted:
            os.environ["MEGAPLAN_ENGINE_ISOLATION_PROVIDER"] = "self_hosted_editable"
    try:
        # Align the plan's execute-phase budget with the chain-authoritative
        # driver.phase_timeout before any phase runs (idempotent seeding).
        _seed_plan_phase_timeout(root, plan, spec.phase_timeout)
        _sync_plan_auto_approve(root, plan, bool(getattr(spec, "auto_approve", False)))
        return auto_drive(
            plan,
            cwd=root,
            stall_threshold=spec.stall_threshold,
            max_iterations=spec.max_iterations,
            on_escalate=spec.escalate_action,
            poll_sleep=spec.poll_sleep,
            phase_timeout=spec.phase_timeout,
            status_timeout=spec.status_timeout,
            on_phase_complete=on_phase_complete,
            writer=writer,
        )
    finally:
        try:
            os.chdir(original_cwd)
        except FileNotFoundError:
            pass
        if self_hosted:
            if previous_provider is None:
                os.environ.pop("MEGAPLAN_ENGINE_ISOLATION_PROVIDER", None)
            else:
                os.environ["MEGAPLAN_ENGINE_ISOLATION_PROVIDER"] = previous_provider


def _execution_batch_sort_key(path: Path) -> tuple[int, str]:
    match = re.fullmatch(r"execution_batch_(\d+)\.json", path.name)
    if match:
        return (int(match.group(1)), path.name)
    return (-1, path.name)


def _latest_execute_result(plan_dir: Path) -> str | None:
    try:
        state = json.loads((plan_dir / "state.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        chain_spec._warn_chain_fallback(
            "M3A_WARN_EXECUTE_RESULT_READ",
            reason="corrupt_json",
            path=plan_dir / "state.json",
        )
        return None
    except (OSError, UnicodeDecodeError):
        chain_spec._warn_chain_fallback(
            "M3A_WARN_EXECUTE_RESULT_READ",
            reason="unreadable",
            path=plan_dir / "state.json",
        )
        return None
    history = state.get("history")
    if not isinstance(history, list):
        return None
    for entry in reversed(history):
        if isinstance(entry, dict) and entry.get("step") == "execute":
            result = entry.get("result")
            return result if isinstance(result, str) else None
    return None


def _completed_records_by_label(chain_state: ChainState) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for record in chain_state.completed:
        if not isinstance(record, dict):
            continue
        label = record.get("label")
        if isinstance(label, str):
            records[label] = record
    return records


def _plan_dir_for_completed_record(root: Path, record: dict[str, Any]) -> Path | None:
    plan_name = record.get("plan")
    if not isinstance(plan_name, str) or not plan_name.strip():
        return None
    try:
        return resolve_plan_dir(root, plan_name)
    except CliError:
        fallback = root / ".megaplan" / "plans" / plan_name
        return fallback if fallback.exists() else None


def _read_plan_state_payload_from_dir(plan_dir: Path | None) -> dict[str, Any]:
    if plan_dir is None:
        return {}
    try:
        raw = json.loads((plan_dir / "state.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def _project_dir_from_plan_state(root: Path, state: dict[str, Any]) -> Path:
    config = state.get("config") if isinstance(state.get("config"), dict) else {}
    project_dir_str = config.get("project_dir") if isinstance(config, dict) else None
    if isinstance(project_dir_str, str) and project_dir_str.strip():
        return Path(project_dir_str)
    return root


def _verify_completed_chain(
    root: Path,
    spec_path: Path,
    spec: ChainSpec,
    chain_state: ChainState,
) -> dict[str, Any]:
    from arnold_pipelines.megaplan.orchestration.completion_contract import (
        CompletionSubject,
        LandedDiffProvider,
        compute_verdict,
        normalize_contract_mode,
    )

    verify_mode = normalize_contract_mode(chain_state.completion_contract_mode)
    completed_records = _completed_records_by_label(chain_state)
    milestones_payload: list[dict[str, Any]] = []
    divergence_count = 0

    for milestone in spec.milestones:
        record = completed_records.get(milestone.label)
        if not isinstance(record, dict):
            continue
        status = record.get("status")
        if status not in {"done", "finalized"}:
            continue
        plan_name = record.get("plan")
        if not isinstance(plan_name, str) or not plan_name.strip():
            continue
        plan_dir = _plan_dir_for_completed_record(root, record)
        state = _read_plan_state_payload_from_dir(plan_dir)
        project_dir = _project_dir_from_plan_state(root, state)
        meta = state.get("meta") if isinstance(state.get("meta"), dict) else {}
        policy = (
            meta.get("chain_policy")
            if isinstance(meta.get("chain_policy"), dict)
            else {}
        )
        milestone_base_sha = policy.get("milestone_base_sha")
        verdict = compute_verdict(
            plan_dir=plan_dir or (root / ".megaplan" / "plans" / plan_name),
            project_dir=project_dir,
            state=state,
            subject=CompletionSubject(
                kind="milestone",
                name=milestone.label,
                to_state="done",
                plan_name=plan_name,
                milestone_label=milestone.label,
            ),
            mode=verify_mode,
            providers=(LandedDiffProvider(),),
            git_base_ref=(
                milestone_base_sha if isinstance(milestone_base_sha, str) else None
            ),
        )
        landed_diff = next(
            (ref for ref in verdict.evidence if ref.kind == "landed_diff"), None
        )
        details = landed_diff.details if landed_diff is not None else {}
        if not verdict.accepted:
            divergence_count += 1
        milestones_payload.append(
            {
                "label": milestone.label,
                "plan": plan_name,
                "status": status,
                "accepted": verdict.accepted,
                "would_block": verdict.would_block,
                "failures": list(verdict.failures),
                "files_claimed": list(details.get("files_claimed") or []),
                "files_in_diff": list(details.get("files_in_diff") or []),
                "files_in_committed_range": list(
                    details.get("files_in_committed_range") or []
                ),
                "files_claimed_worktree_only": list(
                    details.get("files_claimed_worktree_only") or []
                ),
                "evidence_window": dict(details.get("evidence_window") or {}),
                "diff_source": details.get("diff_source"),
            }
        )

    return {
        "success": True,
        "spec": str(spec_path),
        "mode": verify_mode,
        "milestone_count": len(spec.milestones),
        "verified_count": len(milestones_payload),
        "divergence_count": divergence_count,
        "milestones": milestones_payload,
    }


def _sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _project_relative_path(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError as exc:
        raise CliError(
            "invalid_args",
            f"path is outside project root {root}: {path}",
        ) from exc


def _load_manifest_proof_map(path: Path) -> dict[str, list[str]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CliError("invalid_args", f"proof map not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise CliError("invalid_args", f"proof map is invalid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise CliError("invalid_args", "proof map must be a JSON object")
    if isinstance(raw.get("milestones"), dict):
        raw = raw["milestones"]
    proof_map: dict[str, list[str]] = {}
    for label, value in raw.items():
        if not isinstance(label, str) or not label:
            raise CliError("invalid_args", "proof map milestone labels must be strings")
        if not isinstance(value, list) or not value:
            raise CliError(
                "invalid_args",
                f"proof map for milestone {label!r} must be a non-empty list",
            )
        paths: list[str] = []
        for item in value:
            if isinstance(item, str) and item.strip():
                paths.append(item.strip())
                continue
            if isinstance(item, dict):
                candidate = item.get("path")
                if isinstance(candidate, str) and candidate.strip():
                    paths.append(candidate.strip())
                    continue
            raise CliError(
                "invalid_args",
                f"proof map for milestone {label!r} contains an invalid path entry",
            )
        proof_map[label] = paths
    return proof_map


def _validation_receipt_path(
    spec_path: Path, *, milestone_label: str, validation_kind: str
) -> Path:
    safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "-", milestone_label).strip("-")
    safe_kind = re.sub(r"[^A-Za-z0-9_.-]+", "-", validation_kind).strip("-")
    return spec_path.with_name(f"validation-{safe_label}-{safe_kind}.json")


def _validation_receipt_rel_path(
    root: Path, spec_path: Path, *, milestone_label: str, validation_kind: str
) -> str:
    return _project_relative_path(
        root,
        _validation_receipt_path(
            spec_path,
            milestone_label=milestone_label,
            validation_kind=validation_kind,
        ),
    )


def _append_validation_receipt_to_proof_map(
    *,
    root: Path,
    proof_map_path: Path,
    milestone_label: str,
    receipt_path: Path,
) -> None:
    try:
        raw = json.loads(proof_map_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CliError("validation_failed", f"proof map not found: {proof_map_path}") from exc
    except json.JSONDecodeError as exc:
        raise CliError("validation_failed", f"proof map is invalid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise CliError("validation_failed", "proof map must be a JSON object")
    if isinstance(raw.get("milestones"), dict):
        target = raw["milestones"]
    else:
        target = raw
    existing = target.get(milestone_label)
    if existing is None:
        target[milestone_label] = []
        existing = target[milestone_label]
    if not isinstance(existing, list):
        raise CliError(
            "validation_failed",
            f"proof map for milestone {milestone_label!r} must be a list",
        )
    receipt_rel = _project_relative_path(root, receipt_path)
    existing_paths: set[str] = set()
    for item in existing:
        if isinstance(item, str):
            existing_paths.add(item)
        elif isinstance(item, dict) and isinstance(item.get("path"), str):
            existing_paths.add(item["path"])
    if receipt_rel not in existing_paths:
        existing.append(receipt_rel)
        proof_map_path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")


def _validation_receipt_artifact(
    *,
    root: Path,
    spec_path: Path,
    milestone: MilestoneSpec,
    validation: Any,
    proof_map: dict[str, list[str]],
) -> tuple[Path, str]:
    receipt_rel = _validation_receipt_rel_path(
        root,
        spec_path,
        milestone_label=milestone.label,
        validation_kind=validation.kind,
    )
    if receipt_rel not in proof_map.get(milestone.label, []):
        raise CliError(
            "invalid_args",
            f"proof map for milestone {milestone.label!r} missing validation receipt {receipt_rel}",
        )
    receipt_path = (root / receipt_rel).resolve()
    if not receipt_path.is_file():
        raise CliError(
            "invalid_args",
            f"validation receipt for milestone {milestone.label!r} not found: {receipt_path}",
        )
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CliError(
            "invalid_args",
            f"validation receipt for milestone {milestone.label!r} is invalid JSON: {exc}",
        ) from exc
    if not isinstance(receipt, dict):
        raise CliError("invalid_args", f"validation receipt {receipt_path} must be an object")
    expected = {
        "schema": "arnold.megaplan.milestone_validation_receipt.v1",
        "milestone": milestone.label,
        "kind": validation.kind,
        "returncode": 0,
        "conformance": validation.conformance,
        "traceability": validation.traceability,
        "proof_map": validation.proof_map,
    }
    for key, expected_value in expected.items():
        if receipt.get(key) != expected_value:
            raise CliError(
                "invalid_args",
                f"validation receipt {receipt_rel} has invalid {key}; expected {expected_value!r}",
            )
    for key, rel_path in (
        ("validator_sha256", validation.validator),
        ("conformance_sha256", validation.conformance),
        ("traceability_sha256", validation.traceability),
    ):
        if not isinstance(rel_path, str):
            raise CliError("invalid_args", f"validation receipt {receipt_rel} missing source path for {key}")
        path = (root / rel_path).resolve()
        if not path.is_file() or receipt.get(key) != _sha256_path(path):
            raise CliError(
                "invalid_args",
                f"validation receipt {receipt_rel} has stale {key}",
            )
    return receipt_path, receipt_rel


def _ensure_validation_receipts_in_proof_map(
    *,
    root: Path,
    spec_path: Path,
    milestone: MilestoneSpec,
    proof_map: dict[str, list[str]],
) -> None:
    for validation in milestone.validate:
        _validation_receipt_artifact(
            root=root,
            spec_path=spec_path,
            milestone=milestone,
            validation=validation,
            proof_map=proof_map,
        )


def _current_git_head(root: Path) -> str | None:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def _require_validation_checkout_at_ref(
    *,
    root: Path,
    spec: ChainSpec,
    expected_sha: str,
) -> None:
    head = _current_git_head(root)
    if head != expected_sha:
        raise CliError(
            "validation_failed",
            f"validation requires local HEAD to match refreshed origin/{spec.base_branch} "
            f"after merge sync; expected {expected_sha}, got {head or 'unknown'}",
        )


def _run_milestone_validations(
    *,
    root: Path,
    spec_path: Path,
    milestone: MilestoneSpec,
    writer: Callable[[str], None],
) -> None:
    if not milestone.validate:
        return
    for validation in milestone.validate:
        if validation.kind != "final_conformance_gate":
            raise CliError(
                "validation_failed",
                f"unsupported validation kind {validation.kind!r} for {milestone.label}",
            )
        assert validation.validator is not None
        assert validation.conformance is not None
        assert validation.traceability is not None
        assert validation.proof_map is not None
        validator_path = (root / validation.validator).resolve()
        conformance_path = (root / validation.conformance).resolve()
        traceability_path = (root / validation.traceability).resolve()
        proof_map_path = (root / validation.proof_map).resolve()
        for label, path in (
            ("validator", validator_path),
            ("conformance", conformance_path),
            ("traceability", traceability_path),
            ("proof_map", proof_map_path),
        ):
            if not path.is_file():
                raise CliError(
                    "validation_failed",
                    f"{validation.kind} for {milestone.label} missing {label}: {path}",
                )
        receipt_path = _validation_receipt_path(
            spec_path,
            milestone_label=milestone.label,
            validation_kind=validation.kind,
        )
        started_at = datetime.now(timezone.utc).isoformat()
        cmd = [
            sys.executable,
            _project_relative_path(root, validator_path),
            "--conformance",
            _project_relative_path(root, conformance_path),
            "--traceability",
            _project_relative_path(root, traceability_path),
            "--repo-root",
            str(root),
        ]
        writer(f"[chain] validating {milestone.label}: {' '.join(cmd)}\n")
        proc_returncode: int
        stdout = ""
        stderr = ""
        runner_status = "completed"
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(root),
                capture_output=True,
                text=True,
                check=False,
                timeout=300,
                env=megaplan_engine_env(),
            )
            proc_returncode = proc.returncode
            stdout = proc.stdout
            stderr = proc.stderr
        except subprocess.TimeoutExpired as exc:
            proc_returncode = 124
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else str(exc)
            runner_status = "timeout"
        except OSError as exc:
            proc_returncode = 127
            stderr = str(exc)
            runner_status = "runner_error"
        finished_at = datetime.now(timezone.utc).isoformat()
        receipt = {
            "schema": "arnold.megaplan.milestone_validation_receipt.v1",
            "milestone": milestone.label,
            "kind": validation.kind,
            "command": cmd,
            "returncode": proc_returncode,
            "runner_status": runner_status,
            "stdout": stdout,
            "stderr": stderr,
            "conformance": _project_relative_path(root, conformance_path),
            "traceability": _project_relative_path(root, traceability_path),
            "proof_map": _project_relative_path(root, proof_map_path),
            "validator": _project_relative_path(root, validator_path),
            "validator_sha256": _sha256_path(validator_path),
            "conformance_sha256": _sha256_path(conformance_path),
            "traceability_sha256": _sha256_path(traceability_path),
            "proof_map_sha256_before": _sha256_path(proof_map_path),
            "git_head": _current_git_head(root),
            "started_at": started_at,
            "finished_at": finished_at,
        }
        receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        if proc_returncode != 0:
            detail = (stderr or stdout or "").strip()
            raise CliError(
                "validation_failed",
                f"{validation.kind} for {milestone.label} failed; receipt={receipt_path}"
                + (f"; {detail}" if detail else ""),
            )


def _finalize_validation_artifacts_after_done_append(
    *,
    root: Path,
    spec_path: Path,
    spec: ChainSpec,
    state: ChainState,
    milestone: MilestoneSpec,
    writer: Callable[[str], None],
) -> str | None:
    if not milestone.validate:
        return None
    proof_map_paths: dict[Path, bytes] = {}
    for validation in milestone.validate:
        if validation.proof_map is None:
            continue
        proof_map_path = (root / validation.proof_map).resolve()
        if proof_map_path not in proof_map_paths:
            proof_map_paths[proof_map_path] = proof_map_path.read_bytes()
    rolled_back_record: dict[str, Any] | None = None
    try:
        for validation in milestone.validate:
            if validation.proof_map is None:
                continue
            receipt_path = _validation_receipt_path(
                spec_path,
                milestone_label=milestone.label,
                validation_kind=validation.kind,
            )
            _append_validation_receipt_to_proof_map(
                root=root,
                proof_map_path=(root / validation.proof_map).resolve(),
                milestone_label=milestone.label,
                receipt_path=receipt_path,
            )
        if state.current_milestone_index >= len(spec.milestones):
            proof_map = milestone.validate[-1].proof_map
            if proof_map is not None:
                proof_map_path = (root / proof_map).resolve()
                writer(
                    "[chain] writing completion manifest after validated final milestone "
                    f"{milestone.label}\n"
                )
                result = _write_completion_manifest(
                    root=root,
                    spec_path=spec_path,
                    spec=spec,
                    state=state,
                    proof_map_path=proof_map_path,
                    output_path=None,
                )
                writer(
                    "[chain] completion manifest written "
                    f"{result['manifest']} sha256={result['manifest_sha256']}\n"
                )
    except CliError as exc:
        for proof_map_path, original in proof_map_paths.items():
            proof_map_path.write_bytes(original)
        kept: list[dict[str, Any]] = []
        for record in state.completed:
            if isinstance(record, dict) and record.get("label") == milestone.label:
                rolled_back_record = record
                continue
            kept.append(record)
        state.completed = kept
        state.current_milestone_index = max(len(spec.milestones) - 1, 0)
        if rolled_back_record is not None:
            plan = rolled_back_record.get("plan")
            state.current_plan_name = plan if isinstance(plan, str) else None
            pr_number = rolled_back_record.get("pr_number")
            state.pr_number = pr_number if isinstance(pr_number, int) else None
            pr_state = rolled_back_record.get("pr_state")
            state.pr_state = pr_state if isinstance(pr_state, str) else None
        state.last_state = "validation_failed"
        chain_spec.save_chain_state(spec_path, state)
        return (
            f"milestone {milestone.label} validation finalization failed: "
            f"{exc.message}"
        )
    state.metadata.pop("pending_validation", None)
    chain_spec.save_chain_state(spec_path, state)
    return None


def _run_milestone_validations_blocking(
    *,
    root: Path,
    spec_path: Path,
    spec: ChainSpec,
    state: ChainState,
    milestone: MilestoneSpec,
    writer: Callable[[str], None],
    refresh_base: bool,
    no_git_refresh: bool,
) -> str | None:
    if not milestone.validate:
        return None
    try:
        if refresh_base:
            refreshed = _refresh_base_branch(
                root,
                spec.base_branch,
                writer=writer,
                no_git_refresh=no_git_refresh,
                expected_sha=None,
            )
            if isinstance(refreshed, str) and refreshed:
                state.target_base_ref = refreshed
                chain_spec.save_chain_state(spec_path, state)
            if not no_git_refresh:
                expected_sha = refreshed or _remote_branch_head(root, spec.base_branch)
                if expected_sha:
                    _require_validation_checkout_at_ref(
                        root=root,
                        spec=spec,
                        expected_sha=expected_sha,
                    )
                    state.target_base_ref = expected_sha
                    chain_spec.save_chain_state(spec_path, state)
        _run_milestone_validations(
            root=root,
            spec_path=spec_path,
            milestone=milestone,
            writer=writer,
        )
    except CliError as exc:
        state.last_state = "validation_failed"
        state.metadata["pending_validation"] = {
            "milestone": milestone.label,
            "phase": "validator_failed",
            "reason": exc.message,
        }
        chain_spec.save_chain_state(spec_path, state)
        return f"milestone {milestone.label} validation failed: {exc.message}"
    return None


def _completion_records_by_label_strict(state: ChainState) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    duplicates: set[str] = set()
    for record in state.completed:
        if not isinstance(record, dict):
            continue
        label = record.get("label")
        if not isinstance(label, str) or not label:
            continue
        if label in records:
            duplicates.add(label)
        records[label] = record
    if duplicates:
        raise CliError(
            "invalid_chain_state",
            f"chain state has duplicate completed records for {sorted(duplicates)}",
        )
    return records


def _record_pr_merge_sha(root: Path, record: dict[str, Any]) -> str:
    merge_sha, source = _published_pr_target_from_record(record)
    if merge_sha:
        return merge_sha
    pr_number = record.get("pr_number")
    if not isinstance(pr_number, int):
        raise CliError(
            "invalid_chain_state",
            f"completed record {record.get('label')!r} is missing PR number",
        )
    merge_sha, reason = _published_pr_target_from_gh(root, pr_number)
    if merge_sha:
        return merge_sha
    raise CliError(
        "invalid_chain_state",
        f"completed record {record.get('label')!r} has no merge SHA ({source}; {reason})",
    )


def _build_completion_manifest(
    *,
    root: Path,
    spec_path: Path,
    spec: ChainSpec,
    state: ChainState,
    proof_map: dict[str, list[str]],
) -> dict[str, Any]:
    if state.current_plan_name is not None:
        raise CliError(
            "invalid_chain_state",
            f"chain still has active plan {state.current_plan_name!r}",
        )
    if state.current_milestone_index < len(spec.milestones):
        raise CliError(
            "invalid_chain_state",
            "chain has not advanced past all milestones",
        )
    records_by_label = _completion_records_by_label_strict(state)
    manifest: dict[str, Any] = {
        "schema": "arnold.megaplan.chain_completion_manifest.v1",
        "chain": {
            "path": _project_relative_path(root, spec_path),
            "sha256": _sha256_path(spec_path),
        },
        "milestones": [],
    }
    if spec.anchors.north_star:
        north_star_path = resolve_anchor_path(spec_path, spec.anchors.north_star)
        if not north_star_path.is_file():
            raise CliError(
                "invalid_spec",
                f"chain North Star not found: {north_star_path}",
            )
        manifest["north_star"] = {
            "path": _project_relative_path(root, north_star_path),
            "sha256": _sha256_path(north_star_path),
        }
    for milestone in spec.milestones:
        record = records_by_label.get(milestone.label)
        if not record:
            raise CliError(
                "invalid_chain_state",
                f"chain state missing completed record for {milestone.label!r}",
            )
        if record.get("status") != "done":
            raise CliError(
                "invalid_chain_state",
                f"completed record {milestone.label!r} status must be 'done'",
            )
        plan = record.get("plan")
        if not isinstance(plan, str) or not plan.strip():
            raise CliError(
                "invalid_chain_state",
                f"completed record {milestone.label!r} missing plan name",
            )
        brief_path = (root / milestone.idea).resolve()
        if not brief_path.is_file():
            raise CliError(
                "invalid_spec",
                f"milestone {milestone.label!r} brief not found: {brief_path}",
            )
        proof_entries: list[dict[str, str]] = []
        for proof in proof_map.get(milestone.label, []):
            proof_path = (root / proof).resolve()
            if not proof_path.is_file():
                raise CliError(
                    "invalid_args",
                    f"proof artifact for milestone {milestone.label!r} not found: {proof_path}",
                )
            proof_entries.append(
                {
                    "path": _project_relative_path(root, proof_path),
                    "sha256": _sha256_path(proof_path),
                }
            )
        _ensure_validation_receipts_in_proof_map(
            root=root,
            spec_path=spec_path,
            milestone=milestone,
            proof_map=proof_map,
        )
        if not proof_entries:
            raise CliError(
                "invalid_args",
                f"proof map missing proof artifacts for milestone {milestone.label!r}",
            )
        milestone_entry: dict[str, Any] = {
            "label": milestone.label,
            "brief_path": _project_relative_path(root, brief_path),
            "brief_sha256": _sha256_path(brief_path),
            "status": "done",
            "plan": plan,
            "proof_artifacts": proof_entries,
        }
        if spec.merge_policy == "review":
            pr_number = record.get("pr_number")
            pr_state = record.get("pr_state")
            local_commit_sha = record.get("local_commit_sha")
            publication_evidence = record.get("publication_evidence")
            if isinstance(pr_number, int) and pr_state == "merged":
                milestone_entry["pr_number"] = pr_number
                milestone_entry["pr_state"] = "merged"
                milestone_entry["pr_merge_sha"] = _record_pr_merge_sha(root, record)
            elif isinstance(local_commit_sha, str) and local_commit_sha.strip():
                milestone_entry["local_commit_sha"] = local_commit_sha
            elif publication_evidence == "chain_state_only":
                milestone_entry["publication_evidence"] = "chain_state_only"
            else:
                raise CliError(
                    "invalid_chain_state",
                    f"completed record {milestone.label!r} missing merged PR or explicit publication evidence",
                )
        manifest["milestones"].append(milestone_entry)
    return manifest


def _write_completion_manifest(
    *,
    root: Path,
    spec_path: Path,
    spec: ChainSpec,
    state: ChainState,
    proof_map_path: Path,
    output_path: Path | None,
) -> dict[str, Any]:
    proof_map = _load_manifest_proof_map(proof_map_path)
    manifest = _build_completion_manifest(
        root=root,
        spec_path=spec_path,
        spec=spec,
        state=state,
        proof_map=proof_map,
    )
    out_path = output_path or spec_path.with_name("completion-manifest.json")
    out_path = out_path.expanduser().resolve()
    if out_path.parent != spec_path.parent.resolve():
        raise CliError(
            "invalid_args",
            "completion manifest output must live beside the chain spec",
        )
    out_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    manifest_hash = _sha256_path(out_path)
    metadata = dict(state.metadata)
    metadata["completion_manifest"] = {
        "path": _project_relative_path(root, out_path),
        "sha256": manifest_hash,
        "schema": "arnold.megaplan.chain_completion_manifest.v1",
    }
    state.metadata = metadata
    chain_spec.save_chain_state(spec_path, state)
    return {
        "success": True,
        "spec": str(spec_path),
        "manifest": str(out_path),
        "manifest_sha256": manifest_hash,
        "milestone_count": len(spec.milestones),
    }


def _shadow_milestone_completion_verdict(
    root: Path,
    plan_name: str,
    milestone_label: str,
    outcome_status: str,
    contract_mode: str,
    *,
    log_fn: Callable[[str], None],
) -> bool:
    """Compute + persist + log a milestone-level completion verdict.

    FAIL-OPEN. Returns True only when enforce mode should block the milestone.
    """
    try:
        from arnold_pipelines.megaplan.orchestration.completion_contract import (
            CONTRACT_MODE_ENFORCE,
            CONTRACT_MODE_OFF,
            CONTRACT_MODE_SHADOW,
            CONTRACT_MODE_WARN,
            CompletionSubject,
            compute_verdict,
            extract_green_suite_info,
            normalize_contract_mode,
        )
        from arnold_pipelines.megaplan.orchestration.completion_io import (
            write_completion_verdict,
        )

        mode = normalize_contract_mode(contract_mode)
        if mode == CONTRACT_MODE_OFF:
            return False
        # Only compute a milestone verdict for an accepted/done milestone — a
        # stopped/blocked milestone already failed loudly through normal paths.
        if outcome_status != "done":
            return False

        plan_dir = resolve_plan_dir(root, plan_name)
        if plan_dir is None:
            return False

        state: dict[str, Any] = {}
        try:
            raw = json.loads((plan_dir / "state.json").read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                state = raw
        except Exception:
            state = {}

        config = state.get("config") if isinstance(state.get("config"), dict) else {}
        project_dir_str = (
            config.get("project_dir") if isinstance(config, dict) else None
        )
        if isinstance(project_dir_str, str) and project_dir_str:
            project_dir = Path(project_dir_str)
        else:
            project_dir = root

        subject = CompletionSubject(
            kind="milestone",
            name=milestone_label,
            to_state="done",
            plan_name=plan_name,
            milestone_label=milestone_label,
        )
        verdict = compute_verdict(
            plan_dir=plan_dir,
            project_dir=project_dir,
            state=state,
            subject=subject,
            mode=mode,
        )
        try:
            write_completion_verdict(plan_dir, verdict)
        except Exception:
            pass

        try:
            log_fn(verdict.one_line())
        except Exception:
            pass
        if mode in ("warn", "enforce") and verdict.would_block:
            pass
        if mode == CONTRACT_MODE_SHADOW:
            return False
        if mode == CONTRACT_MODE_WARN:
            if verdict.would_block:
                delta_dict, _ = extract_green_suite_info(verdict)
                newly_failing = (
                    (delta_dict or {}).get("newly_failing", [])
                    if delta_dict
                    else list(verdict.failures)
                )
                log.warning(
                    "completion_contract_mode=warn: advisory — verdict would block "
                    "milestone %r; newly_failing=%r failures=%r",
                    milestone_label,
                    newly_failing,
                    list(verdict.failures),
                )
            return False
        if mode == CONTRACT_MODE_ENFORCE:
            delta_dict, result_status = extract_green_suite_info(verdict)
            if result_status in {"runner_error", "timeout", "not_applicable"}:
                log.warning(
                    "completion_contract_mode=enforce: milestone %r verification "
                    "status=%r — not blocking (non-deterministic result); would_block=%r",
                    milestone_label,
                    result_status,
                    verdict.would_block,
                )
                return False
            if delta_dict is None or not delta_dict.get("computable", False):
                log.warning(
                    "completion_contract_mode=enforce: milestone %r delta not "
                    "computable — not blocking; would_block=%r",
                    milestone_label,
                    verdict.would_block,
                )
                return False
            newly_failing = delta_dict.get("newly_failing") or []
            deleted_tests = delta_dict.get("deleted_tests") or []
            if not newly_failing and not deleted_tests and not verdict.would_block:
                return False
            failing_refs: list[dict[str, str]] = []
            for ref in verdict.evidence:
                ev_status = getattr(ref.status, "value", str(ref.status))
                if ev_status in ("unsatisfied", "blocked"):
                    failing_refs.append({"kind": ref.kind, "summary": ref.summary})
            log.warning(
                "completion_contract_mode=enforce: blocking milestone %r; "
                "newly_failing=%r deleted_tests=%r would_block=%r "
                "failures=%r failing_evidence=%r",
                milestone_label,
                list(newly_failing),
                list(deleted_tests),
                verdict.would_block,
                list(verdict.failures),
                failing_refs,
            )
            return True
        return False
    except Exception as exc:  # fail-open: never break a chain
        log.debug(
            "shadow milestone completion verdict failed for %r: %s",
            milestone_label,
            exc,
        )
        return False


def _full_suite_backstop_completed_summary(
    result: dict[str, Any],
    evaluation: dict[str, Any],
) -> dict[str, Any]:
    failing_tests = result.get("failing_tests")
    if not isinstance(failing_tests, list):
        failing_tests = []
    newly_failing = result.get("newly_failing")
    if not isinstance(newly_failing, list):
        newly_failing = []
    deleted_tests = result.get("deleted_tests")
    if not isinstance(deleted_tests, list):
        deleted_tests = []
    return {
        "mode": evaluation.get("mode"),
        "status": result.get("status"),
        "blocks": bool(evaluation.get("blocks")),
        "reason": evaluation.get("reason"),
        "passed": result.get("passed"),
        "failed": result.get("failed"),
        "failing_tests": list(failing_tests),
        "newly_failing": list(newly_failing),
        "deleted_tests": list(deleted_tests),
        "baseline_failing_count": result.get("baseline_failing_count", 0),
        "current_failing_count": result.get("current_failing_count", 0),
        "delta_computed": bool(result.get("delta_computed")),
        "command": result.get("command", ""),
        "duration_s": result.get("duration_s"),
        "ran": bool(result.get("ran")),
        "artifact": "full_suite_backstop.json",
    }


def _full_suite_backstop_baseline_path_for(spec_path: Path) -> Path:
    return _state_path_for(spec_path).parent / "full_suite_baseline.json"


def _current_head_sha(root: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    sha = proc.stdout.strip()
    return sha or None


def _persist_full_suite_backstop_baseline(
    spec_path: Path,
    result: dict[str, Any],
    *,
    captured_at_sha: str | None,
    milestone_label: str,
    captured_at: str | None = None,
) -> bool:
    from arnold_pipelines.megaplan.orchestration.full_suite_backstop import (
        build_full_suite_baseline,
    )

    baseline = build_full_suite_baseline(
        result,
        captured_at_sha=captured_at_sha,
        milestone=milestone_label,
        captured_at=captured_at,
    )
    if baseline is None:
        return False
    path = _full_suite_backstop_baseline_path_for(spec_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(path, baseline)
    return True


def _full_suite_backstop_uncertain(result: dict[str, Any] | None) -> bool:
    return not isinstance(result, dict) or result.get("delta_computed") is not True


def _run_full_suite_backstop_gate(
    root: Path,
    spec_path: Path,
    plan_name: str,
    milestone_label: str,
    mode: str,
    *,
    log_fn: Callable[[str], None],
) -> dict[str, Any]:
    """Run the full-suite backstop gate for a completed milestone."""
    from arnold_pipelines.megaplan.orchestration.full_suite_backstop import (
        FULL_SUITE_BACKSTOP_MODE_ENFORCE,
        FULL_SUITE_BACKSTOP_MODE_OFF,
        evaluate_full_suite_backstop,
        normalize_full_suite_backstop_mode,
        run_full_suite_backstop,
    )

    normalized_mode = normalize_full_suite_backstop_mode(mode)
    if normalized_mode == FULL_SUITE_BACKSTOP_MODE_OFF:
        return {
            "blocks": False,
            "reason": "full_suite_backstop_mode=off: backstop disabled",
            "summary": None,
            "result": None,
        }

    try:
        plan_dir = resolve_plan_dir(root, plan_name)
        if plan_dir is None:
            raise FileNotFoundError(f"plan directory not found for {plan_name!r}")

        try:
            raw_state = json.loads(
                (plan_dir / "state.json").read_text(encoding="utf-8")
            )
        except Exception:
            raw_state = {}
        config = raw_state.get("config", {}) if isinstance(raw_state, dict) else {}
        if not isinstance(config, dict):
            config = {}
        project_dir_value = config.get("project_dir")
        project_dir = (
            Path(project_dir_value)
            if isinstance(project_dir_value, str) and project_dir_value
            else root
        )
        baseline_path = _full_suite_backstop_baseline_path_for(spec_path)

        result = run_full_suite_backstop(
            plan_dir,
            project_dir,
            config,
            baseline=baseline_path,
            writer=log_fn,
        )
        atomic_write_json(plan_dir / "full_suite_backstop.json", result)
        evaluation = evaluate_full_suite_backstop(result, normalized_mode)
        if (
            normalized_mode == FULL_SUITE_BACKSTOP_MODE_ENFORCE
            and evaluation.get("blocks")
            and _full_suite_backstop_uncertain(result)
        ):
            log_fn("full_suite_backstop enforce uncertainty; retrying full suite once")
            result = run_full_suite_backstop(
                plan_dir,
                project_dir,
                config,
                baseline=baseline_path,
                writer=log_fn,
            )
            atomic_write_json(plan_dir / "full_suite_backstop.json", result)
            evaluation = evaluate_full_suite_backstop(result, normalized_mode)
        summary = _full_suite_backstop_completed_summary(result, evaluation)

        newly_failing = summary["newly_failing"]
        deleted_tests = summary["deleted_tests"]
        failure_suffix = (
            f"; newly_failing={newly_failing[:5]}"
            if newly_failing
            else f"; deleted_tests={deleted_tests[:5]}" if deleted_tests else ""
        )
        log_fn(
            "full_suite_backstop "
            f"mode={normalized_mode} status={summary['status']} "
            f"blocks={summary['blocks']} artifact=full_suite_backstop.json"
            f"{failure_suffix}"
        )
        return {
            "blocks": bool(evaluation.get("blocks")),
            "reason": str(evaluation.get("reason") or ""),
            "summary": summary,
            "result": result,
        }
    except Exception as exc:
        log.warning(
            "full_suite_backstop failed open for milestone %r: %s",
            milestone_label,
            exc,
        )
        result = {
            "status": "error",
            "passed": None,
            "failed": None,
            "failing_tests": None,
            "command": "",
            "duration_s": None,
            "ran": False,
            "note": f"fail-open: {type(exc).__name__}: {exc}",
        }
        try:
            log_fn(
                "full_suite_backstop "
                f"mode={normalized_mode} status=error blocks=False "
                f"note={result['note']}"
            )
        except Exception:
            pass
        return {
            "blocks": False,
            "reason": (
                "full_suite_backstop failed open after unexpected error; not blocking"
            ),
            "summary": None,
            "result": result,
        }


def _full_suite_backstop_block_reason(
    milestone_label: str,
    plan_name: str,
    result: dict[str, Any] | None,
) -> str:
    newly_failing = result.get("newly_failing") if isinstance(result, dict) else None
    deleted_tests = result.get("deleted_tests") if isinstance(result, dict) else None
    failing_suffix = (
        f"; newly_failing={newly_failing[:10]}"
        if isinstance(newly_failing, list) and newly_failing
        else (
            f"; deleted_tests={deleted_tests[:10]}"
            if isinstance(deleted_tests, list) and deleted_tests
            else ""
        )
    )
    return (
        "full_suite_backstop_mode=enforce: milestone "
        f"{milestone_label!r} blocked before reconciliation advance; see "
        f"{plan_name}/full_suite_backstop.json{failing_suffix}"
    )


def _run_pending_reconciliation_backstops(
    root: Path,
    spec_path: Path,
    state: ChainState,
    *,
    writer,
) -> str | None:
    """Verify provisional completed records before reconciliation trusts them.

    A terminal plan projection may leave a ``finalized`` completed record in
    chain state before the cursor has advanced.  Reconciliation must not turn
    that projection into completion authority without replaying the same
    full-suite gate used by the ordinary advancement path.
    """

    fail_closed, _ = _reconciliation_fail_closed(state)
    if fail_closed:
        return None

    changed = False
    for record in state.completed:
        if not isinstance(record, dict):
            continue
        if record.get("status") in {STATE_DONE, "complete"}:
            continue
        if isinstance(record.get("full_suite_backstop"), dict):
            continue
        milestone_label = record.get("label")
        plan_name = record.get("plan")
        if not isinstance(milestone_label, str) or not milestone_label:
            continue
        if not isinstance(plan_name, str) or not plan_name:
            continue
        gate = _run_full_suite_backstop_gate(
            root,
            spec_path,
            plan_name,
            milestone_label,
            state.full_suite_backstop_mode,
            log_fn=lambda message: writer(f"[chain] {message}\n"),
        )
        if gate.get("blocks"):
            chain_spec.save_chain_state(spec_path, state)
            result = gate.get("result")
            return _full_suite_backstop_block_reason(
                milestone_label,
                plan_name,
                result if isinstance(result, dict) else None,
            )
        summary = gate.get("summary")
        if isinstance(summary, dict):
            record["full_suite_backstop"] = dict(summary)
            changed = True
        result = gate.get("result")
        if isinstance(result, dict):
            _persist_full_suite_backstop_baseline(
                spec_path,
                result,
                captured_at_sha=_current_head_sha(root),
                milestone_label=milestone_label,
            )
    if changed:
        chain_spec.save_chain_state(spec_path, state)
    return None


def _latest_execution_batch_all_tasks_done(
    plan_dir: Path,
    *,
    chain_state: ChainState | None = None,
    completion_record: Mapping[str, Any] | None = None,
) -> tuple[bool, str]:
    try:
        state_payload = json.loads((plan_dir / "state.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError):
        state_payload = {}
    config = state_payload.get("config") if isinstance(state_payload, dict) else {}
    meta = state_payload.get("meta") if isinstance(state_payload, dict) else {}
    raw_project_dir = config.get("project_dir") if isinstance(config, dict) else None
    project_dir = Path(raw_project_dir) if isinstance(raw_project_dir, str) and raw_project_dir else None
    execution_baseline = (
        meta.get("execution_baseline")
        if isinstance(meta, dict) and isinstance(meta.get("execution_baseline"), dict)
        else {}
    )
    baseline_head = execution_baseline.get("head")
    current_head = _resolve_authority_current_head(
        plan_dir,
        project_dir=project_dir,
        baseline_head=baseline_head if isinstance(baseline_head, str) and baseline_head.strip() else None,
    )
    # Whether the live git HEAD was observable. When it is NOT (e.g. rev-parse
    # failed), there is no execution window to defer finalize authority to, so
    # finalize.json must be evaluated directly even if it contains pending rows.
    actual_git_head = _best_effort_git_head(project_dir) if project_dir is not None else None
    execution_window_available = actual_git_head is not None
    evidence_nucleus = load_evidence_nucleus(plan_dir, default_head=current_head)

    def _authoritative_batch_task_overrides() -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
        overrides: dict[str, dict[str, Any]] = {}
        sources: dict[str, str] = {}
        for batch_path in sorted(
            list_batch_artifacts(plan_dir),
            key=_execution_batch_sort_key,
        ):
            try:
                batch_payload = json.loads(batch_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError):
                continue
            if not isinstance(batch_payload, dict):
                continue
            batch_records = [
                item
                for item in (batch_payload.get("task_updates") or [])
                if isinstance(item, dict)
            ]
            if not batch_records:
                continue
            batch_decisions: dict[str, AuthorityDecision] = {}
            batch_completed = effective_execute_completed_task_ids(
                batch_records,
                plan_dir=plan_dir,
                project_dir=project_dir,
                state=state_payload,
                evidence_nucleus=evidence_nucleus,
                current_head=current_head,
                decisions=batch_decisions,
            )
            for record in batch_records:
                task_id = str(record.get("task_id") or record.get("id") or "")
                if task_id and task_id in batch_completed:
                    if not _task_record_can_override_finalize(record):
                        continue
                    overrides[task_id] = dict(record)
                    sources[task_id] = _plan_relative_source(plan_dir, batch_path)
        return overrides, sources

    authoritative_batch_overrides, authoritative_batch_override_sources = (
        _authoritative_batch_task_overrides()
    )
    batches = sorted(
        list_batch_artifacts(plan_dir),
        key=_execution_batch_sort_key,
    )
    # P6 reconcile selection envelope: a read-only reconcile selector's
    # authoritative output is the selection JSON (selected_shas +
    # verification_evidence) carried in the batch artifact; that IS the
    # corroborated completion evidence for the milestone's tasks, so the
    # per-task finalize corroboration checks do not apply (occurrence
    # 47671addc195).
    try:
        for batch_path in batches:
            raw = json.loads(batch_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and (
                "selected_shas" in raw or "verification_evidence" in raw
            ):
                return (
                    True,
                    "reconcile selection payload corroborates batch completion",
                )
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError):
        pass
    if not batches:
        return False, "no execution_batch_*.json artifact found"
    latest = batches[-1]
    try:
        payload = json.loads(latest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return False, f"{latest.name} could not be read: {error}"
    if not isinstance(payload, dict):
        return False, f"{latest.name} payload is not an object"

    finalize_path = plan_dir / "finalize.json"
    finalize_payload: dict[str, Any] | None = None
    authoritative_finalize_records: list[dict[str, Any]] | None = None
    baseline_unavailable_task_ids: set[str] = set()
    if finalize_path.exists():
        try:
            loaded_finalize_payload = json.loads(
                finalize_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as error:
            return False, f"finalize.json could not be read: {error}"
        if isinstance(loaded_finalize_payload, dict):
            finalize_payload = loaded_finalize_payload
            finalize_tasks = finalize_payload.get("tasks")
            if isinstance(finalize_tasks, list) and finalize_tasks:
                finalize_records = [
                    task for task in finalize_tasks if isinstance(task, dict)
                ]
                from arnold_pipelines.megaplan.execute.batch import (
                    baseline_unavailable_checkpoint_ids,
                )

                finalize_ids = {
                    str(task.get("id"))
                    for task in finalize_records
                    if isinstance(task.get("id"), str)
                }
                baseline_unavailable_task_ids = baseline_unavailable_checkpoint_ids(
                    finalize_payload, finalize_ids
                )
                authoritative_finalize_records = [
                    task
                    for task in finalize_records
                    if str(task.get("id") or "") not in baseline_unavailable_task_ids
                ]

                def _overlay_authoritative_batch_updates(
                    records: list[dict[str, Any]],
                ) -> list[dict[str, Any]]:
                    """Apply guarded authoritative batch overrides to finalize rows.

                    A later execution batch may supersede stale per-task finalize
                    rows, but durable terminal evidence already reconciled into
                    finalize.json is never erased by a replayed/partial batch.
                    """
                    if not authoritative_batch_overrides:
                        return list(records)
                    from arnold_pipelines.megaplan.orchestration.authority_readers import (
                        has_durable_terminal_task_evidence,
                    )

                    overlaid: list[dict[str, Any]] = []
                    for task in records:
                        task_id = str(task.get("id") or "")
                        override = authoritative_batch_overrides.get(task_id)
                        if override is None:
                            overlaid.append(task)
                            continue
                        if has_durable_terminal_task_evidence(task):
                            # A replayed/partial batch may omit outputs already
                            # reconciled into finalize.json. Never let that erase
                            # terminal corroboration at chain completion.
                            overlaid.append(task)
                            continue
                        merged = dict(task)
                        for field in (
                            "files_changed",
                            "commands_run",
                            "evidence_files",
                            "sections_written",
                            "evidence",
                        ):
                            if field not in override:
                                merged.pop(field, None)
                        for key, value in override.items():
                            if key == "task_id":
                                continue
                            merged[key] = value
                        overlaid.append(merged)
                    return overlaid

                # Closure must see the COMPLETE canonical finalize universe
                # (including baseline-unavailable checkpoints, per 7416687dd)
                # WITH authoritative batch overrides applied, so stale finalize
                # rows never contradict the batch-authority contract.
                complete_finalize_records = _overlay_authoritative_batch_updates(
                    finalize_records
                )
                authoritative_finalize_records = _overlay_authoritative_batch_updates(
                    authoritative_finalize_records
                )

    from arnold_pipelines.megaplan.orchestration.authority_readers import (
        has_durable_terminal_task_evidence,
    )

    # A branch replay changes commit IDs while retaining the milestone diff.
    # Re-anchor terminal finalize evidence only when every claimed file is
    # present in the declared milestone range; arbitrary stale claims stay
    # non-authoritative.
    if authoritative_finalize_records and project_dir is not None and current_head:
        chain_policy = meta.get("chain_policy") if isinstance(meta, dict) else None
        base_ref = chain_policy.get("milestone_base_sha") if isinstance(chain_policy, dict) else None
        if isinstance(base_ref, str) and base_ref.strip():
            try:
                from arnold_pipelines.megaplan.loop.git import _collect_committed_range_paths
                from arnold_pipelines.megaplan.orchestration.authority_readers import (
                    _evidence_from_task_record,
                )
                committed_paths = _collect_committed_range_paths(project_dir, base_ref=base_ref)
                reanchored_refs = []
                reanchored_records: list[dict[str, Any]] = []
                for task in authoritative_finalize_records:
                    files = {
                        str(path).lstrip("./")
                        for path in task.get("files_changed", [])
                        if isinstance(path, str) and path.strip()
                    }
                    if (
                        has_durable_terminal_task_evidence(task)
                        and files
                        and files.issubset(committed_paths)
                    ):
                        task = dict(task)
                        task["head_sha"] = current_head
                        reanchored_refs.extend(
                            _evidence_from_task_record(
                                task, finalize_path, root=plan_dir, default_head=current_head
                            )
                        )
                    reanchored_records.append(task)
                authoritative_finalize_records = reanchored_records
                evidence_nucleus = (*evidence_nucleus, *reanchored_refs)
            except Exception:
                pass

    # finalize.json defines the required task universe. A later execution batch
    # may override stale finalize rows for individual tasks, but it may not
    # shrink the universe to just the latest touched task. This is the incident
    # class where T1/T2/T6 completed, T3+ stayed pending, and the chain accepted
    # the latest execution_batch_N.json anyway.
    if authoritative_finalize_records and batches and execution_window_available:
        pending_without_batch_override = [
            str(task.get("id") or "")
            for task in authoritative_finalize_records
            if _optional_finalize_status(task) == "pending"
            and str(task.get("id") or "") not in authoritative_batch_overrides
        ]
        if pending_without_batch_override:
            return (
                False,
                "finalize.json has pending tasks without authoritative execution "
                f"updates: {', '.join(pending_without_batch_override)}",
            )

    if authoritative_finalize_records:
        finalize_decisions: dict[str, AuthorityDecision] = {}
        # Dependency closure must run over the COMPLETE canonical finalize
        # universe (including baseline-unavailable checkpoints such as
        # T11_impl/T11_proof). A partial universe (baseline-unavailable tasks
        # excluded) makes every dependent task fail closure with a false
        # accepted_attempt_dependency_unresolved cascade. Baseline-unavailable
        # tasks stay excluded from the authoritative REPORTING set below, so
        # they are never reported as pending.
        finalize_completed = effective_execute_completed_task_ids(
            complete_finalize_records,
            plan_dir=plan_dir,
            project_dir=project_dir,
            state=state_payload,
            evidence_nucleus=evidence_nucleus,
            current_head=current_head,
            decisions=finalize_decisions,
        )
        pending = _non_authoritative_task_reasons(
            authoritative_finalize_records,
            finalize_completed,
            finalize_decisions,
            source_by_task=authoritative_batch_override_sources,
        )
        pending.extend(
            _chain_completion_shadow_disagreements(
                authoritative_finalize_records,
                finalize_completed,
                finalize_decisions,
                source_by_task=authoritative_batch_override_sources,
                plan_dir=plan_dir,
                chain_state=chain_state,
                completion_record=completion_record,
                default_source="finalize.json",
                default_source_kind="finalize data",
            )
        )
        pending.extend(
            _finalize_records_missing_authority_fields(
                authoritative_finalize_records
            )
        )
        if pending:
            return (
                False,
                f"finalize.json has non-authoritative tasks: {', '.join(pending)}",
            )
        return True, "finalize.json"

    task_records: list[dict[str, Any]] = []
    for key in ("task_updates", "tasks"):
        raw_records = payload.get(key)
        if isinstance(raw_records, list):
            task_records.extend(item for item in raw_records if isinstance(item, dict))
    if not task_records:
        return False, f"{latest.name} has no task records"

    authoritative_task_records = [
        task
        for task in task_records
        if str(task.get("task_id") or task.get("id") or "")
        not in baseline_unavailable_task_ids
    ]
    if authoritative_task_records:
        batch_decisions: dict[str, AuthorityDecision] = {}
        completed = effective_execute_completed_task_ids(
            authoritative_task_records,
            plan_dir=plan_dir,
            project_dir=project_dir,
            state=state_payload,
            evidence_nucleus=evidence_nucleus,
            current_head=current_head,
            decisions=batch_decisions,
        )
        if not completed:
            return False, f"{latest.name} has no corroborated completed task IDs"
        incomplete = _non_authoritative_task_reasons(
            authoritative_task_records, completed, batch_decisions
        )
        incomplete.extend(
            _chain_completion_shadow_disagreements(
                authoritative_task_records,
                completed,
                batch_decisions,
                source_by_task={},
                plan_dir=plan_dir,
                chain_state=chain_state,
                completion_record=completion_record,
                default_source=_plan_relative_source(plan_dir, latest),
                default_source_kind="execution batch",
            )
        )
        if incomplete:
            return (
                False,
                f"{latest.name} has non-authoritative tasks: {', '.join(incomplete)}",
            )
    return True, latest.name


def _resolve_authority_current_head(
    plan_dir: Path,
    *,
    project_dir: Path | None,
    baseline_head: str | None,
) -> str | None:
    actual_head = _best_effort_git_head(project_dir) if project_dir is not None else None
    recorded_head = _latest_recorded_execution_head(plan_dir)
    if actual_head and recorded_head:
        if actual_head == recorded_head:
            return actual_head
        if project_dir is not None:
            if _git_is_ancestor(project_dir, recorded_head, actual_head):
                return actual_head
            if _git_is_ancestor(project_dir, actual_head, recorded_head):
                return recorded_head
    return actual_head or recorded_head or baseline_head


def _best_effort_git_head(project_dir: Path) -> str | None:
    try:
        actual_head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_dir,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return actual_head or None


def _latest_recorded_execution_head(plan_dir: Path) -> str | None:
    for path in sorted(
        list_batch_artifacts(plan_dir),
        key=_execution_batch_sort_key,
        reverse=True,
    ):
        head = _latest_head_in_artifact(path)
        if head:
            return head
    return _latest_head_in_artifact(plan_dir / "finalize.json")


def _latest_head_in_artifact(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    latest_head: str | None = None
    for key in ("task_updates", "tasks"):
        raw_records = payload.get(key)
        if not isinstance(raw_records, list):
            continue
        for record in raw_records:
            if not isinstance(record, dict):
                continue
            observed = record.get("head_sha") or record.get("head")
            if isinstance(observed, str) and observed.strip():
                latest_head = observed.strip()
    return latest_head


def _git_is_ancestor(project_dir: Path, ancestor: str, descendant: str) -> bool:
    try:
        completed = subprocess.run(
            ["git", "merge-base", "--is-ancestor", ancestor, descendant],
            cwd=project_dir,
            check=False,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def _plan_terminal_completion_is_authoritative(
    root: Path, plan_name: str
) -> tuple[bool, str]:
    try:
        plan_dir = resolve_plan_dir(root, plan_name)
    except CliError:
        return (
            True,
            f"plan {plan_name} directory unavailable; no chain artifacts to inspect",
        )
    return _latest_execution_batch_all_tasks_done(plan_dir)


def _record_chain_authority_divergence_cursor(
    root: Path, plan_name: str, reason: str, *, writer,
) -> None:
    """Persist a plan-level rerun cursor for a terminal plan whose task
    completion lacks authority, so the standard recovery loop (override
    recover-blocked -> execute) can re-dispatch the blocked tasks.  This is
    an append-only lifecycle record; it does not fabricate completion or
    weaken the fail-closed authority gate."""
    try:
        plan_dir = resolve_plan_dir(root, plan_name)
    except CliError:
        writer(f"[chain] cannot resolve plan dir for {plan_name}; skipping rerun cursor\n")
        return
    try:
        payload = json.loads((plan_dir / "state.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        writer(f"[chain] cannot read plan state for {plan_name}; skipping rerun cursor\n")
        return
    if not isinstance(payload, dict):
        return
    from datetime import datetime, timezone
    payload["latest_failure"] = {
        "kind": "authority_divergence",
        "message": "execute terminal success lacks corroborated task completion: " + reason,
        "phase": "execute",
        "state": "blocked",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "suggested_action": "Rerun execute so task completion can be corroborated.",
    }
    payload["resume_cursor"] = {"phase": "execute", "retry_strategy": "rerun_phase"}
    try:
        (plan_dir / "state.json").write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )
        writer(f"[chain] recorded rerun cursor for {plan_name} (authority divergence)\n")
    except OSError as exc:
        writer(f"[chain] failed to write rerun cursor for {plan_name}: {exc}\n")


def _finalized_plan_has_successful_review(plan_state: dict[str, Any]) -> bool:
    """Return true when a finalized plan has already completed review successfully."""

    if plan_state.get("current_state") != STATE_FINALIZED:
        return False
    if plan_state.get("latest_failure"):
        return False
    if plan_state.get("active_step"):
        return False
    history = plan_state.get("history")
    if not isinstance(history, list):
        return False
    saw_execute = False
    for entry in history:
        if not isinstance(entry, dict):
            continue
        step = str(entry.get("step") or "").strip().lower()
        result = str(entry.get("result") or "").strip().lower()
        if step == "execute":
            saw_execute = True
        if saw_execute and step == "review" and result == "success":
            return True
    return False


def _read_typed_noop_completion_waiver(
    plan_dir: Path,
    *,
    expected_base_sha: str | None = None,
    expected_plan: str | None = None,
    expected_milestone: str | None = None,
) -> tuple[bool, str]:
    """Return whether an explicit typed no-op completion waiver is valid."""

    candidates = (
        plan_dir / "completion_noop.json",
        plan_dir / "no_op_completion.json",
    )
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            return False, f"{candidate.name} could not be read: {error}"
        if not isinstance(payload, dict):
            return False, f"{candidate.name} payload is not an object"
        if payload.get("schema") != NOOP_COMPLETION_SCHEMA:
            return False, f"{candidate.name} schema must be {NOOP_COMPLETION_SCHEMA!r}"
        plan = payload.get("plan")
        if expected_plan and plan != expected_plan:
            return (
                False,
                f"{candidate.name} plan {plan!r} does not match {expected_plan!r}",
            )
        milestone = payload.get("milestone_label")
        if expected_milestone and milestone != expected_milestone:
            return (
                False,
                f"{candidate.name} milestone_label {milestone!r} does not match "
                f"{expected_milestone!r}",
            )
        reason = payload.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            return False, f"{candidate.name} requires a non-empty reason"
        scope = payload.get("scope")
        if scope not in NOOP_COMPLETION_SCOPES:
            allowed = ", ".join(sorted(NOOP_COMPLETION_SCOPES))
            return False, f"{candidate.name} scope must be one of: {allowed}"
        base_sha = payload.get("base_sha")
        if not isinstance(base_sha, str) or not base_sha.strip():
            return False, f"{candidate.name} requires a non-empty base_sha"
        if expected_base_sha and base_sha != expected_base_sha:
            return (
                False,
                f"{candidate.name} base_sha {base_sha!r} does not match "
                f"milestone_base_sha {expected_base_sha!r}",
            )
        return True, f"{candidate.name} scope={scope} reason={reason.strip()}"
    return False, "no typed no-op completion waiver found"


def _read_reconcile_verification_waiver(
    plan_dir: Path,
    *,
    expected_base_sha: str | None = None,
    expected_plan: str | None = None,
    expected_milestone: str | None = None,
) -> tuple[bool, str]:
    """Return whether the reconcile no-op verification waiver is valid.

    The waiver is the controller-side skip evidence: the engine-source change
    set in the reconcile range was empty (or fully covered by promotion
    evidence), so the reconcile milestone is a verified no-op.  The guard
    accepts it exactly like ``completion_noop.json`` — same shape contract,
    own schema so the two waivers cannot be confused.
    """

    candidate = plan_dir / "reconcile-verification.json"
    if not candidate.exists():
        return False, "no reconcile verification waiver found"
    try:
        payload = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return False, f"{candidate.name} could not be read: {error}"
    if not isinstance(payload, dict):
        return False, f"{candidate.name} payload is not an object"
    if payload.get("schema") != RECONCILE_VERIFICATION_SCHEMA:
        return (
            False,
            f"{candidate.name} schema must be {RECONCILE_VERIFICATION_SCHEMA!r}",
        )
    plan = payload.get("plan")
    if expected_plan and plan != expected_plan:
        return (
            False,
            f"{candidate.name} plan {plan!r} does not match {expected_plan!r}",
        )
    milestone = payload.get("milestone_label")
    if expected_milestone and milestone != expected_milestone:
        return (
            False,
            f"{candidate.name} milestone_label {milestone!r} does not match "
            f"{expected_milestone!r}",
        )
    scope = payload.get("scope")
    if scope not in {"no_engine_changes", "already_promoted"}:
        return False, f"{candidate.name} scope must be no_engine_changes or already_promoted"
    reason = payload.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        return False, f"{candidate.name} requires a non-empty reason"
    base_sha = payload.get("base_sha")
    if not isinstance(base_sha, str) or not base_sha.strip():
        return False, f"{candidate.name} requires a non-empty base_sha"
    if expected_base_sha and base_sha != expected_base_sha:
        return (
            False,
            f"{candidate.name} base_sha {base_sha!r} does not match "
            f"milestone_base_sha {expected_base_sha!r}",
        )
    if not isinstance(payload.get("engine_changes"), list):
        return False, f"{candidate.name} requires an engine_changes list"
    if not isinstance(payload.get("promotion_evidence"), list):
        return False, f"{candidate.name} requires a promotion_evidence list"
    return True, f"{candidate.name} scope={scope} reason={reason.strip()}"


def _write_reconcile_verification_waiver(
    plan_dir: Path,
    *,
    plan: str,
    milestone_label: str,
    base_sha: str,
    scope: str,
    engine_changes: list[dict[str, Any]],
    promotion_evidence: list[dict[str, Any]],
    reason: str,
) -> Path:
    """Atomically write the reconcile no-op verification waiver into a plan dir.

    The payload carries the engine change set and the promotion evidence that
    justified the no-op, so the completion guard's acceptance is evidence-
    backed rather than a bare marker.
    """

    plan_dir.mkdir(parents=True, exist_ok=True)
    target = plan_dir / "reconcile-verification.json"
    payload = {
        "schema": RECONCILE_VERIFICATION_SCHEMA,
        "plan": plan,
        "milestone_label": milestone_label,
        "base_sha": base_sha,
        "scope": scope,
        "engine_changes": engine_changes,
        "promotion_evidence": promotion_evidence,
        "reason": reason,
        "verified_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    tmp = plan_dir / ".reconcile-verification.json.tmp"
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.replace(target)
    return target


def _finalize_payload_has_empty_tasks(plan_dir: Path) -> tuple[bool, str]:
    candidates = (
        ("finalize.json", plan_dir / "finalize.json"),
        ("finalize_output.json", plan_dir / "finalize_output.json"),
    )
    for label, path in candidates:
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            return True, f"{label} could not be read: {error}"
        if not isinstance(payload, dict):
            return True, f"{label} payload is not an object"
        tasks = payload.get("tasks")
        if isinstance(tasks, list) and not tasks:
            return True, f"{label} tasks is empty"
        return False, f"{label} tasks is non-empty or absent"
    return False, "no finalize artifact present"


def _milestone_base_sha_from_plan_state(state: dict[str, Any]) -> str | None:
    meta = state.get("meta") if isinstance(state.get("meta"), dict) else {}
    policy = (
        meta.get("chain_policy") if isinstance(meta.get("chain_policy"), dict) else {}
    )
    base_sha = policy.get("milestone_base_sha")
    return base_sha if isinstance(base_sha, str) and base_sha.strip() else None


def _semantic_diff_nonempty_between_refs(
    root: Path, base_sha: str | None, target_ref: str, *, target_label: str
) -> tuple[bool, str]:
    if not base_sha:
        return False, "milestone_base_sha unavailable"
    target_ref = target_ref.strip()
    if not target_ref:
        return False, f"{target_label} unavailable"
    proc = _diff_name_only_between_refs(root, base_sha, target_ref)
    if proc.returncode != 0:
        return (
            False,
            f"git diff from milestone_base_sha to {target_label} failed: "
            f"{proc.stderr.strip() or proc.stdout.strip()}",
        )
    changed = [
        line.strip()
        for line in proc.stdout.splitlines()
        if line.strip()
        and line.strip() != ".megaplan"
        and not line.strip().startswith(".megaplan/")
    ]
    if not changed:
        return (
            False,
            f"no semantic diff from milestone_base_sha {base_sha} to {target_label}",
        )
    return True, f"{target_label} semantic diff files: {', '.join(changed[:10])}"


def _raw_diff_nonempty_between_refs(
    root: Path, base_sha: str | None, target_ref: str, *, target_label: str
) -> tuple[bool | None, str]:
    if not base_sha:
        return None, "milestone_base_sha unavailable"
    target_ref = target_ref.strip()
    if not target_ref:
        return None, f"{target_label} unavailable"
    proc = _diff_name_only_between_refs(root, base_sha, target_ref)
    if proc.returncode != 0:
        return (
            None,
            f"git diff from milestone_base_sha to {target_label} failed: "
            f"{proc.stderr.strip() or proc.stdout.strip()}",
        )
    changed = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not changed:
        return False, f"no raw diff from milestone_base_sha {base_sha} to {target_label}"
    return True, f"{target_label} raw diff files: {', '.join(changed[:10])}"


def _semantic_diff_nonempty_from_base(
    root: Path, base_sha: str | None
) -> tuple[bool, str]:
    return _semantic_diff_nonempty_between_refs(
        root, base_sha, "HEAD", target_label="local HEAD"
    )


def _diff_name_only_between_refs(
    root: Path, base_sha: str, target_ref: str
) -> subprocess.CompletedProcess[str]:
    """Run ``git diff --name-only`` between two refs with one fetch-and-retry.

    If the initial diff fails with a ref-resolution error (bad object, unknown
    revision, bad revision, could not resolve, etc.), ``git fetch origin
    --prune`` is executed once and the diff is retried.  If the retry still
    fails, the real error is surfaced unchanged — there is no silent swallowing
    or second fetch attempt.
    """
    proc = subprocess.run(
        ["git", "diff", "--name-only", base_sha, target_ref, "--"],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if proc.returncode == 0:
        return proc
    combined = f"{proc.stderr or ''}\n{proc.stdout or ''}".lower()
    if not _is_git_ref_resolution_error(combined):
        return proc
    subprocess.run(
        ["git", "fetch", "origin", "--prune"],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    return subprocess.run(
        ["git", "diff", "--name-only", base_sha, target_ref, "--"],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def _is_git_ref_resolution_error(combined_lower: str) -> bool:
    """Return *True* when *combined_lower* matches a known ref-resolution error.

    These are fatal errors that ``git fetch origin --prune`` can potentially
    resolve (stale remote-tracking branches, missing objects, race conditions
    after upstream force-pushes, etc.).
    """
    _REF_RESOLUTION_ERROR_PATTERNS: tuple[str, ...] = (
        "bad object",
        "unknown revision",
        "bad revision",
        "could not resolve",
        "does not point to a valid object",
        "not a valid object name",
        "not our ref",
        "could not read",
        "fatal: ambiguous argument",
        "fatal: not a commit",
        "fatal: not a tree",
    )
    return any(pattern in combined_lower for pattern in _REF_RESOLUTION_ERROR_PATTERNS)


def _string_value(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _sha_from_payload_value(value: Any) -> str | None:
    direct = _string_value(value)
    if direct:
        return direct
    if isinstance(value, dict):
        for key in ("oid", "sha", "id"):
            nested = _string_value(value.get(key))
            if nested:
                return nested
    return None


def _published_pr_target_from_record(
    record: dict[str, Any],
    chain_state: ChainState | None = None,
) -> tuple[str | None, str]:
    merge_sha_keys = (
        "pr_merge_sha",
        "merge_commit_sha",
        "merge_commit",
        "mergeCommit",
        "published_merge_sha",
    )
    head_sha_keys = (
        "pr_head_sha",
        "pr_head",
        "head_ref_oid",
        "headRefOid",
        "published_head_sha",
        "published_commit_sha",
    )
    for key in merge_sha_keys:
        sha = _sha_from_payload_value(record.get(key))
        if sha:
            return sha, f"record.{key}"
    pr_payload = record.get("pr")
    if isinstance(pr_payload, dict):
        for key in merge_sha_keys:
            sha = _sha_from_payload_value(pr_payload.get(key))
            if sha:
                return sha, f"record.pr.{key}"
    for key in head_sha_keys:
        sha = _sha_from_payload_value(record.get(key))
        if sha:
            return sha, f"record.{key}"
    if isinstance(pr_payload, dict):
        for key in head_sha_keys:
            sha = _sha_from_payload_value(pr_payload.get(key))
            if sha:
                return sha, f"record.pr.{key}"
    if chain_state is not None:
        sha = _string_value(chain_state.pr_head)
        if sha:
            return sha, "chain_state.pr_head"
    return None, "record/chain_state"


def _published_pr_target_from_gh(
    root: Path, pr_number: int
) -> tuple[str | None, str]:
    try:
        proc = subprocess.run(
            [
                "gh",
                "pr",
                "view",
                str(pr_number),
                "--json",
                "state,mergedAt,mergeCommit,headRefOid",
            ],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return None, f"gh pr view #{pr_number} failed: {error}"
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "gh pr view failed"
        return None, f"gh pr view #{pr_number} failed: {detail}"
    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as error:
        return None, f"gh pr view #{pr_number} produced non-JSON output: {error}"
    if not isinstance(payload, dict):
        return None, f"gh pr view #{pr_number} payload is not an object"
    state = _string_value(payload.get("state"))
    if not state or state.lower() != "merged":
        return None, f"gh pr view #{pr_number} state={state!r} is not merged"
    merged_at = _string_value(payload.get("mergedAt"))
    if not merged_at:
        return None, f"gh pr view #{pr_number} has no mergedAt timestamp"
    merge_sha = _sha_from_payload_value(payload.get("mergeCommit"))
    if merge_sha:
        return merge_sha, f"gh.pr#{pr_number}.mergeCommit"
    head_sha = _sha_from_payload_value(payload.get("headRefOid"))
    if head_sha:
        return head_sha, f"gh.pr#{pr_number}.headRefOid"
    return None, f"gh pr view #{pr_number} did not return a mergeCommit/headRefOid"


def _completion_record_is_merged_pr(record: dict[str, Any]) -> bool:
    pr_state = _string_value(record.get("pr_state"))
    return bool(pr_state and pr_state.lower() == "merged")


def _record_is_reconcile(record: dict[str, Any]) -> bool:
    """True when a completion record belongs to a ``kind: reconcile`` milestone.

    The generated reconcile milestone stamps ``kind`` on its completion
    record; the boolean marker is accepted for hand-authored records.
    """

    if record.get("reconcile") is True:
        return True
    return record.get("kind") == "reconcile"


def _record_is_intentionally_rejected(record: dict[str, Any]) -> bool:
    """True when a reconcile completion record carries an intentional rejection.

    Slice B's ``_ensure_reconcile_pr`` records an intentionally rejected PR as
    ``pr_state: closed`` plus a ``rejection_reason``.  This is a terminal,
    close-worthy outcome per the P6 terminal-state rules — never the
    ``_stop_for_closed_pr`` accidental-close path.
    """

    if not _record_is_reconcile(record):
        return False
    pr_state = _string_value(record.get("pr_state"))
    if not pr_state or pr_state.lower() != "closed":
        return False
    reason = record.get("rejection_reason")
    return isinstance(reason, str) and bool(reason.strip())


def _resolve_recorded_target_ref(root: Path, target_branch: str) -> str | None:
    """Resolve a recorded milestone ``target_branch`` to a local SHA.

    The reconcile PR's base is the recorded target (main by default), which
    may differ from ``spec.base_branch``.  ``origin/<branch>`` is preferred
    because the reconcile target is a shared branch; the local ref is the
    fallback for offline fixtures.
    """

    for ref in (f"origin/{target_branch}", target_branch):
        try:
            proc = subprocess.run(
                ["git", "rev-parse", "--verify", ref],
                cwd=str(root),
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
        if proc.returncode == 0:
            sha = proc.stdout.strip()
            if sha:
                return sha
    return None


def _published_target_is_in_chain_target(
    root: Path,
    target: str,
    chain_state: ChainState | None,
    *,
    target_branch: str | None = None,
) -> tuple[bool | None, str]:
    if target_branch:
        # P6: the reconcile milestone's PR targets its RECORDED target branch
        # (main by default), not the chain's launch-time base.  Validate the
        # published merge target against that recorded target's lineage.
        target_ref = _resolve_recorded_target_ref(root, target_branch)
        if not target_ref:
            return None, f"recorded reconcile target branch {target_branch!r} unresolvable"
        # Either direction proves the merge landed on the recorded target's
        # lineage: the recorded target was the PR base (ancestor of the merge
        # target) or the merge target has since been advanced past (the merge
        # commit is an ancestor of the recorded target's current head).
        if _git_is_ancestor(root, target_ref, target):
            return (
                True,
                f"recorded target {target_branch} {target_ref[:12]} is contained "
                f"in published PR target {target[:12]}",
            )
        if _git_is_ancestor(root, target, target_ref):
            return (
                True,
                f"published PR target {target[:12]} is contained in recorded "
                f"target {target_branch} {target_ref[:12]}",
            )
        return (
            False,
            f"published PR target {target[:12]} is not contained in recorded "
            f"target {target_branch} {target_ref}",
        )
    if chain_state is None:
        return None, "chain target unavailable"
    target_ref = _string_value(chain_state.target_base_ref)
    if not target_ref:
        return None, "chain target ref unavailable"
    # ``target_base_ref`` is the chain's launch-time base.  A valid merged PR
    # advances beyond that snapshot, so the snapshot must be an ancestor of the
    # published merge target (not the other way around).
    if _git_is_ancestor(root, target_ref, target):
        return True, f"chain target {target_ref[:12]} is contained in published PR target {target[:12]}"
    return (
        False,
        f"published PR target {target[:12]} is not contained in chain target {target_ref}",
    )


def _published_pr_semantic_diff_nonempty_from_base(
    root: Path,
    base_sha: str | None,
    record: dict[str, Any],
    *,
    chain_state: ChainState | None = None,
) -> tuple[bool | None, str]:
    target, source = _published_pr_target_from_record(record)
    if target is None:
        pr_number = record.get("pr_number")
        if isinstance(pr_number, int):
            target, source = _published_pr_target_from_gh(root, pr_number)
        elif isinstance(pr_number, str) and pr_number.strip().isdigit():
            target, source = _published_pr_target_from_gh(root, int(pr_number.strip()))
    if target is None and chain_state is not None:
        target, source = _published_pr_target_from_record(record, chain_state)
    if target is None:
        return None, f"published PR target unavailable: {source}"
    target_branch = _string_value(record.get("target_branch"))
    landed_ok, landed_reason = _published_target_is_in_chain_target(
        root,
        target,
        chain_state,
        target_branch=target_branch,
    )
    if landed_ok is False:
        return False, landed_reason
    if landed_ok is None and target_branch:
        # The recorded reconcile target could not be resolved — the merged PR
        # cannot be validated against it, so the outcome is UNKNOWN (the
        # guard fails closed for reconcile records instead of accepting).
        return None, landed_reason
    return _semantic_diff_nonempty_between_refs(
        root,
        base_sha,
        target,
        target_label=f"published PR target {target[:12]} ({source})",
    )


def _chain_completion_guard(
    root: Path,
    record: dict[str, Any],
    *,
    implementation_milestone: bool,
    chain_state: ChainState | None = None,
) -> tuple[bool, str]:
    plan_name = record.get("plan")
    if not isinstance(plan_name, str) or not plan_name.strip():
        return False, "completion record has no plan name"
    try:
        plan_dir = resolve_plan_dir(root, plan_name)
    except CliError as error:
        return False, f"plan {plan_name} directory unavailable: {error.message}"

    plan_state = _read_plan_state_payload_from_dir(plan_dir)
    current_state = plan_state.get("current_state")
    current_state_note = ""
    is_merged_pr = _completion_record_is_merged_pr(record)
    if is_merged_pr and not implementation_milestone:
        return True, "merged PR milestone accepted without implementation checks"
    is_reconcile = _record_is_reconcile(record)
    # P6 terminal-state rules: an INTENTIONALLY rejected reconcile PR is a
    # terminal, close-worthy outcome (history preserves everything; no ticket
    # ceremony) — never the accidental-close path.  Unknown PR state, missing
    # gh auth, and cherry-pick conflicts must fail closed instead.
    if is_reconcile and _record_is_intentionally_rejected(record):
        return (
            True,
            "intentionally rejected reconcile PR accepted; terminal for close/sweep",
        )
    merged_pr_internal_state_bypass = is_merged_pr and current_state in {
        STATE_BLOCKED,
        STATE_EXECUTED,
        STATE_FINALIZED,
    }
    merged_pr_state_bypass_reason = ""
    if (
        implementation_milestone
        and current_state != STATE_DONE
        and not merged_pr_internal_state_bypass
        and not is_reconcile
    ):
        return (
            False,
            f"plan {plan_name} current_state={current_state!r} is not terminal-success "
            f"{STATE_DONE!r}",
        )
    if implementation_milestone and current_state != STATE_DONE and merged_pr_internal_state_bypass:
        merged_pr_state_bypass_reason = (
            f"merged PR milestone; internal plan state {current_state!r} bypassed "
            "because PR is merged"
        )
        if current_state_note:
            merged_pr_state_bypass_reason = (
                f"{current_state_note}; {merged_pr_state_bypass_reason}"
            )

    if not implementation_milestone:
        return True, "non-implementation completion guard passed"

    milestone_base_sha = _milestone_base_sha_from_plan_state(plan_state)
    waiver_ok, waiver_reason = _read_typed_noop_completion_waiver(
        plan_dir,
        expected_base_sha=milestone_base_sha,
        expected_plan=plan_name,
        expected_milestone=(
            record.get("label") if isinstance(record.get("label"), str) else None
        ),
    )
    # P6: the reconcile milestone's skip evidence.  The no-op path never runs
    # the agent, so the plan may sit at ``prepped`` — the waiver is the
    # terminal evidence and is accepted before any plan-state requirement.
    reconcile_waiver_ok = False
    reconcile_waiver_reason = "no reconcile verification waiver found"
    if is_reconcile:
        reconcile_waiver_ok, reconcile_waiver_reason = (
            _read_reconcile_verification_waiver(
                plan_dir,
                expected_base_sha=milestone_base_sha,
                expected_plan=plan_name,
                expected_milestone=(
                    record.get("label") if isinstance(record.get("label"), str) else None
                ),
            )
        )
    if is_reconcile and reconcile_waiver_ok:
        return True, f"reconcile verification waiver accepted: {reconcile_waiver_reason}"

    if is_merged_pr:
        published_diff_ok, published_diff_reason = (
            _published_pr_semantic_diff_nonempty_from_base(
                root,
                milestone_base_sha,
                record,
                chain_state=chain_state,
            )
        )
        if (
            published_diff_ok is False
            and "not contained in chain target" in published_diff_reason
        ):
            return False, published_diff_reason
        local_diff_ok = False
        local_diff_reason = ""
        local_raw_diff_ok: bool | None = None
        local_raw_diff_reason = ""
        if is_reconcile and published_diff_ok is not True:
            # A merged reconcile PR MUST validate against its recorded target
            # (main by default).  Unknown or unresolvable target state fails
            # closed — never fall back to local-diff acceptance for reconcile.
            return False, (
                f"reconcile merged PR not validated against recorded target "
                f"{record.get('target_branch') or 'chain base'}: "
                f"{published_diff_reason}"
            )
        if published_diff_ok is not True:
            local_diff_ok, local_diff_reason = _semantic_diff_nonempty_from_base(
                root, milestone_base_sha
            )
            local_raw_diff_ok, local_raw_diff_reason = _raw_diff_nonempty_between_refs(
                root,
                milestone_base_sha,
                "HEAD",
                target_label="local HEAD",
            )
        if published_diff_ok is True:
            if waiver_ok:
                return True, f"typed no-op waiver accepted: {waiver_reason}"
            reason_parts: list[str] = []
            if merged_pr_state_bypass_reason:
                reason_parts.append(merged_pr_state_bypass_reason)
            if local_diff_reason:
                if local_diff_ok:
                    reason_parts.append(local_diff_reason)
                else:
                    reason_parts.append(f"local HEAD advisory: {local_diff_reason}")
            reason_parts.append(published_diff_reason)
            return True, f"completion guard passed: {'; '.join(reason_parts)}"
        if published_diff_ok is None:
            if not local_diff_ok and not waiver_ok:
                return False, f"{local_diff_reason}; {published_diff_reason}; {waiver_reason}"
            if waiver_ok:
                return True, f"typed no-op waiver accepted: {waiver_reason}"
            return True, f"completion guard passed: {local_diff_reason}; {published_diff_reason}"
        if (
            published_diff_ok is False
            and not local_diff_ok
            and local_raw_diff_ok is False
        ):
            authoritative, authority_reason = _latest_execution_batch_all_tasks_done(
                plan_dir,
                chain_state=chain_state,
                completion_record=record,
            )
            empty_finalize_tasks, finalize_reason = _finalize_payload_has_empty_tasks(
                plan_dir
            )
            if authoritative and not empty_finalize_tasks:
                if waiver_ok:
                    return True, f"typed no-op waiver accepted: {waiver_reason}"
                reason_parts = []
                if merged_pr_state_bypass_reason:
                    reason_parts.append(merged_pr_state_bypass_reason)
                reason_parts.extend(
                    [
                        authority_reason,
                        finalize_reason,
                        "merged PR accepted with authoritative execution and true no-op diff",
                        local_diff_reason,
                        published_diff_reason,
                    ]
                )
                return True, f"completion guard passed: {'; '.join(reason_parts)}"
        if not waiver_ok:
            return False, f"{published_diff_reason}; {waiver_reason}"
        if waiver_ok:
            return True, f"typed no-op waiver accepted: {waiver_reason}"
        return True, f"completion guard passed: {published_diff_reason}"

    authoritative, reason = _latest_execution_batch_all_tasks_done(
        plan_dir,
        chain_state=chain_state,
        completion_record=record,
    )
    if not authoritative and not waiver_ok:
        detail_reason = reconcile_waiver_reason if is_reconcile else waiver_reason
        return (
            False,
            f"execution evidence blocked completion: {reason}; {detail_reason}",
        )

    empty_finalize_tasks, finalize_reason = _finalize_payload_has_empty_tasks(plan_dir)
    if empty_finalize_tasks and not waiver_ok:
        return False, f"{finalize_reason}; {waiver_reason}"

    diff_ok, diff_reason = _semantic_diff_nonempty_from_base(root, milestone_base_sha)
    if not diff_ok and not waiver_ok:
        return False, f"{diff_reason}; {waiver_reason}"

    published_diff_reason: str | None = None
    if is_merged_pr:
        published_diff_ok, published_diff_reason = (
            _published_pr_semantic_diff_nonempty_from_base(
                root,
                milestone_base_sha,
                record,
                chain_state=chain_state,
            )
        )
        if not published_diff_ok and not waiver_ok:
            return False, f"{published_diff_reason}; {waiver_reason}"

    if waiver_ok:
        return True, f"typed no-op waiver accepted: {waiver_reason}"
    reason_parts = [reason, finalize_reason, diff_reason]
    if current_state_note:
        reason_parts.insert(0, current_state_note)
    if published_diff_reason is not None:
        reason_parts.append(published_diff_reason)
    return True, f"completion guard passed: {'; '.join(reason_parts)}"


def _is_failed_no_next_step_blocked_execute(plan_state: dict[str, Any]) -> bool:
    current_state = plan_state.get("current_state")
    if current_state != "failed":
        return False
    latest_failure = plan_state.get("latest_failure")
    if not isinstance(latest_failure, dict):
        return False
    if latest_failure.get("kind") != "no_next_step":
        return False
    history = plan_state.get("history")
    if not isinstance(history, list):
        return False
    return any(
        isinstance(entry, dict)
        and entry.get("step") == "execute"
        and entry.get("result") == "blocked"
        for entry in history
    )


def _finalize_has_only_terminal_status_rows(plan_dir: Path) -> tuple[bool, str]:
    try:
        payload = json.loads((plan_dir / "finalize.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False, "finalize.json unavailable"
    if not isinstance(payload, dict):
        return False, "finalize.json is not an object"
    tasks = payload.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        return False, "finalize.json has no tasks"
    saw_terminal = False
    for task in tasks:
        if not isinstance(task, dict):
            return False, "finalize.json contains non-object task rows"
        status = _optional_finalize_status(task)
        if status not in {"done", "skipped", "waived", "not_applicable"}:
            return False, f"finalize.json has non-terminal task status {status!r}"
        if _task_record_has_authority_payload(task):
            return False, "finalize.json terminal rows still carry authority payload"
        saw_terminal = True
    if not saw_terminal:
        return False, "finalize.json has no terminal task rows"
    return True, "terminal finalize task statuses"


def _is_chain_control_path(path: str) -> bool:
    return path in {"chain.yaml", "idea.md", "NORTHSTAR.md"}


def _current_branch_name(root: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "symbolic-ref", "--short", "HEAD"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    branch = proc.stdout.strip()
    return branch or None


def _root_relative_dirty_paths(root: Path) -> list[str]:
    root_abs = root.resolve()
    dirty_paths: list[str] = []
    for path in _dirty_worktree_paths(root):
        try:
            rel = path.resolve().relative_to(root_abs).as_posix()
        except (OSError, ValueError):
            continue
        dirty_paths.append(rel)
    return dirty_paths


def _ensure_published_claimed_changes_for_pr_progression(
    root: Path,
    spec_path: Path,
    state: ChainState,
    milestone: MilestoneSpec,
    *,
    writer,
    allow_publish: bool,
) -> tuple[bool, str]:
    """Publish (or refuse to advance past) unpublished claimed milestone work.

    A previously buggy chain could leave a finalized/done plan with claimed
    local changes that never made it onto the milestone branch before the PR
    merged (or before auto-merge is enabled). Refusing to advance here prevents
    a false-completion drop of unfinished work. When ``allow_publish`` is set
    and we are on the milestone branch, the changes are pushed under the
    ``resume-publish`` phase so the normal awaiting-merge path can continue.
    """

    plan_name = state.current_plan_name
    if not plan_name or not milestone.branch or state.pr_number is None:
        return True, "no active milestone PR publish guard needed"

    plan_state = _plan_state_payload_from_name(root, plan_name)
    current_state = plan_state.get("current_state")
    if current_state not in {STATE_FINALIZED, STATE_DONE}:
        return True, f"plan {plan_name} current_state={current_state!r} does not require PR publish guard"

    claimed_root_paths = _claimed_root_paths(root, plan_name)
    if not claimed_root_paths:
        return True, f"plan {plan_name} has no claimed root paths to publish"

    dirty_paths = _root_relative_dirty_paths(root)
    dirty_claimed = sorted(path for path in dirty_paths if path in claimed_root_paths)
    if not dirty_claimed:
        return True, f"plan {plan_name} has no unpublished claimed changes"

    unrelated_dirty = sorted(
        path
        for path in dirty_paths
        if path not in claimed_root_paths
        and not _is_chain_control_path(path)
        and path != ".megaplan"
        and not path.startswith(".megaplan/")
    )
    claimed_sample = ", ".join(dirty_claimed[:5])
    if unrelated_dirty:
        unrelated_sample = ", ".join(unrelated_dirty[:5])
        return (
            False,
            f"plan {plan_name} has unpublished claimed changes ({claimed_sample}) plus "
            f"unrelated dirty paths ({unrelated_sample}); refusing PR progression",
        )

    current_branch = _current_branch_name(root)
    if not allow_publish:
        return (
            False,
            f"plan {plan_name} has unpublished claimed changes after PR merged: "
            f"{claimed_sample}; current branch={current_branch or 'detached HEAD'} "
            f"milestone branch={milestone.branch}",
        )
    if current_branch != milestone.branch:
        return (
            False,
            f"plan {plan_name} has unpublished claimed changes on "
            f"{current_branch or 'detached HEAD'}, not milestone branch "
            f"{milestone.branch}: {claimed_sample}",
        )

    _commit_and_push_phase(
        root,
        milestone.branch,
        plan_name,
        "resume-publish",
        writer=writer,
        preexisting_dirty_paths=[],
    )
    _capture_sync_state(
        root, spec_path, branch=milestone.branch, pr_number=state.pr_number
    )
    remaining_dirty = _root_relative_dirty_paths(root)
    remaining_claimed = sorted(path for path in remaining_dirty if path in claimed_root_paths)
    if remaining_claimed:
        return (
            False,
            f"claimed milestone changes remain dirty after resume-publish: "
            f"{', '.join(remaining_claimed[:5])}",
        )
    return (
        True,
        f"published {len(dirty_claimed)} claimed milestone change(s) before PR progression: "
        f"{claimed_sample}",
    )


def _validate_pr_progression_wbc(
    *,
    root: Path,
    spec_path: Path,
    state: ChainState,
    milestone: MilestoneSpec,
    plan_name: str,
    pr_number: int,
    transition_name: str,
) -> dict[str, Any]:
    from arnold_pipelines.megaplan.chain.execution_binding import (
        execution_binding_report,
    )
    from arnold_pipelines.megaplan.chain.wbc import (
        GIT_PR_READY_SURFACE,
        GIT_PR_READY_WRITER_ID,
        ChainWbcRule,
        finalize_artifact_candidates,
        finalize_receipt_candidates,
        record_chain_wbc_evidence,
        validate_chain_wbc_transition,
    )

    binding = execution_binding_report(spec_path, state)
    if not binding.get("required"):
        # Legacy unbound chain specs predate the controlled-writer contract.
        # Their existing completion guard remains authoritative; WBC becomes
        # mandatory once execution_binding is declared required.
        return {
            "schema": "arnold.megaplan.chain_wbc_transition_evidence.v1",
            "transition": transition_name,
            "subject": f"{milestone.label}:pr#{pr_number}",
            "migration_status": "legacy_unbound_spec",
            "execution_binding": binding,
        }

    try:
        plan_dir = resolve_plan_dir(root, plan_name)
    except CliError:
        # Preserve a failed, inspectable WBC result for synthetic/recovery
        # callers whose plan record is absent. The artifact/receipt rules below
        # remain false; no completion guard is relaxed.
        plan_dir = root / ".megaplan" / "plans" / plan_name
    plan_state = _plan_state_payload_from_name(root, plan_name)
    current_state = plan_state.get("current_state")
    finalize_receipts = finalize_receipt_candidates(plan_dir)
    finalize_artifacts = finalize_artifact_candidates(plan_dir)
    binding_ok = (
        binding.get("status") in {"match", "reconcile_required"}
        if binding.get("required")
        else True
    )
    evidence = validate_chain_wbc_transition(
        writer_id=GIT_PR_READY_WRITER_ID,
        surface_name=GIT_PR_READY_SURFACE,
        transition_name=transition_name,
        subject=f"{milestone.label}:pr#{pr_number}",
        source_path=spec_path,
        project_dir=root,
        rules=(
            ChainWbcRule(
                "plan_state_terminal",
                f"{STATE_FINALIZED}|{STATE_DONE}|{STATE_AWAITING_PR_MERGE}",
                current_state,
                current_state in {STATE_FINALIZED, STATE_DONE, STATE_AWAITING_PR_MERGE},
            ),
            ChainWbcRule(
                "finalize_receipt_present",
                True,
                bool(finalize_receipts),
                bool(finalize_receipts),
                "finalize promotion must persist a durable receipt before PR actions",
            ),
            ChainWbcRule(
                "finalize_artifacts_present",
                True,
                bool(finalize_artifacts),
                bool(finalize_artifacts),
                "finalize promotion must leave canonical artifacts behind",
            ),
            ChainWbcRule(
                "execution_binding_current",
                True,
                binding.get("status"),
                binding_ok,
                "chain execution binding must still match before PR progression",
            ),
            ChainWbcRule(
                "pr_number_bound",
                pr_number,
                state.pr_number,
                state.pr_number == pr_number,
            ),
        ),
        extra={
            "milestone_label": milestone.label,
            "plan_name": plan_name,
            "plan_dir": str(plan_dir),
            "finalize_receipts": finalize_receipts,
            "finalize_artifacts": finalize_artifacts,
            "execution_binding_status": binding.get("status"),
        },
    )
    record_chain_wbc_evidence(
        state.metadata,
        entry_key=f"{transition_name}:{milestone.label}:{pr_number}",
        evidence=evidence,
    )
    return evidence


def _recover_stale_merged_pr_for_unfinished_plan(
    root: Path,
    spec_path: Path,
    state: ChainState,
    milestone: MilestoneSpec,
    plan_state: dict[str, Any],
    *,
    writer,
) -> tuple[ChainState | None, str]:
    """Retire a merged PR cursor that points at a plan that still must run.

    A previously buggy chain could squash-merge a draft PR while execute output
    was still local-only. On restart, live GitHub says "merged" but state.json
    still says finalized/executing. Advancing would drop unfinished tasks; a
    plain resume would clean the dirty worktree during branch checkout. Preserve
    claimed local output on the milestone branch first, then clear the stale PR
    cursor so the normal resume path can continue and create a fresh PR.
    """

    plan_name = state.current_plan_name
    if not plan_name or not milestone.branch:
        return None, "missing active plan or milestone branch for stale merged PR recovery"

    current_state = plan_state.get("current_state")
    canonical_current_state = current_state
    if current_state == STATE_DONE:
        return None, f"plan {plan_name} is already {STATE_DONE!r}"
    if not isinstance(canonical_current_state, str) or not canonical_current_state:
        return None, f"plan {plan_name} has no usable current_state for stale merged PR recovery"
    if canonical_current_state not in {STATE_PREPPED, STATE_FINALIZED, STATE_EXECUTED}:
        return (
            None,
            f"plan {plan_name} current_state={current_state!r} is not recoverable "
            f"before terminal-success {STATE_DONE!r}; stale merged PR cannot advance",
        )

    claimed_root_paths = _claimed_root_paths(root, plan_name)
    dirty_paths = _root_relative_dirty_paths(root)
    dirty_claimed = sorted(path for path in dirty_paths if path in claimed_root_paths)
    unrelated_dirty = sorted(
        path
        for path in dirty_paths
        if path not in claimed_root_paths
        and not _is_chain_control_path(path)
        and path != ".megaplan"
        and not path.startswith(".megaplan/")
    )
    active_step = plan_state.get("active_step")
    active_phase = (
        active_step.get("phase")
        if isinstance(active_step, dict) and isinstance(active_step.get("phase"), str)
        else None
    )
    if unrelated_dirty:
        if active_phase != "execute":
            sample = ", ".join(unrelated_dirty[:5])
            return (
                None,
                f"plan {plan_name} has stale merged PR #{state.pr_number} but unrelated "
                f"dirty paths prevent recovery: {sample}",
            )
        writer(
            f"[chain] stale merged PR recovery for {plan_name} will preserve "
            f"{len(unrelated_dirty)} unclaimed dirty path(s) from active execute: "
            f"{', '.join(unrelated_dirty[:5])}\n"
        )

    old_pr_number = state.pr_number
    dirty_recovery_paths = sorted({*dirty_claimed, *unrelated_dirty})
    if dirty_recovery_paths:
        current_branch = _current_branch_name(root)
        if current_branch != milestone.branch:
            _run_command(
                root,
                ["git", "checkout", "-B", milestone.branch, "HEAD"],
                writer=writer,
                error_code="git_branch_failed",
            )
        _commit_and_push_phase(
            root,
            milestone.branch,
            plan_name,
            "stale-merged-pr-recovery",
            writer=writer,
            preexisting_dirty_paths=[],
        )
        _capture_sync_state(root, spec_path, branch=milestone.branch, pr_number=None)
        state = chain_spec.load_chain_state(spec_path)

    plan_dir = resolve_plan_dir(root, plan_name)
    authoritative, authority_reason = _latest_execution_batch_all_tasks_done(plan_dir)
    empty_finalize_tasks, finalize_reason = _finalize_payload_has_empty_tasks(plan_dir)
    terminal_finalize_only, terminal_finalize_reason = _finalize_has_only_terminal_status_rows(
        plan_dir
    )
    if (
        canonical_current_state == STATE_EXECUTED
        and terminal_finalize_only
    ):
        _mark_plan_completed_by_chain(
            root,
            plan_name,
            milestone_label=milestone.label,
            completion_reason=(
                "stale merged PR recovery accepted terminal finalize task statuses: "
                f"{terminal_finalize_reason}"
            ),
            writer=writer,
            state=state,
        )
        state.last_state = STATE_DONE
        state.metadata["stale_merged_pr_recovery"] = {
            "recovered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "milestone": milestone.label,
            "plan": plan_name,
            "stale_pr_number": old_pr_number,
            "plan_current_state": current_state,
            "canonical_plan_current_state": canonical_current_state,
            "dirty_claimed_paths": dirty_claimed,
            "unclaimed_execute_dirty_paths": unrelated_dirty,
        }
        chain_spec.save_chain_state(spec_path, state)
        return (
            state,
            "recovered stale merged PR with terminal finalize task statuses; "
            f"{terminal_finalize_reason}",
        )

    state.pr_number = None
    state.pr_state = None
    state.last_state = canonical_current_state
    state.metadata["stale_merged_pr_recovery"] = {
        "recovered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "milestone": milestone.label,
        "plan": plan_name,
        "stale_pr_number": old_pr_number,
        "plan_current_state": current_state,
        "canonical_plan_current_state": canonical_current_state,
        "dirty_claimed_paths": dirty_claimed,
        "unclaimed_execute_dirty_paths": unrelated_dirty,
    }
    chain_spec.save_chain_state(spec_path, state)

    if dirty_recovery_paths:
        return (
            state,
            f"recovered stale merged PR #{old_pr_number} for unfinished plan {plan_name}; "
            f"published {len(dirty_recovery_paths)} local change(s) to {milestone.branch} "
            f"({len(dirty_claimed)} claimed, {len(unrelated_dirty)} unclaimed active-execute)",
        )
    return (
        state,
        f"recovered stale merged PR #{old_pr_number} for unfinished plan {plan_name}; "
        "cleared stale PR cursor with no claimed local changes to publish",
    )


def _block_pr_progression_guard_failure(
    *,
    spec_path: Path,
    spec: ChainSpec,
    state: ChainState,
    milestone: MilestoneSpec,
    reason: str,
    events: list[dict[str, Any]],
    writer,
) -> dict[str, Any]:
    writer(f"[chain] PR progression blocked {milestone.label}: {reason}\n")
    state.last_state = "authority_divergence"
    chain_spec.save_chain_state(spec_path, state)
    return _result(
        "blocked",
        state,
        events,
        spec=spec,
        reason=reason,
    )


def _apply_committed_acceptance_state(
    state: ChainState, new_state: dict[str, Any]
) -> None:
    """Mirror a durably-committed acceptance state into the in-memory state.

    :func:`prepare_acceptance_commit` / :func:`commit_acceptance_commit`
    atomically wrote *new_state* (completed record, cursor advance, and
    milestone-boundary evidence) under the CAS guard.  Reflect only the fields
    the acceptance commit owns into the live state object so subsequent
    in-memory work (further mutations plus a final ``save_chain_state``) stays
    consistent with the committed durable state.  All other state attributes
    are left exactly as the caller set them.
    """
    completed_raw = new_state.get("completed")
    if isinstance(completed_raw, list):
        state.completed = [
            dict(r) if isinstance(r, dict) else r for r in completed_raw
        ]
    idx_raw = new_state.get("current_milestone_index")
    if isinstance(idx_raw, int):
        state.current_milestone_index = idx_raw
    evidence_raw = new_state.get("milestone_boundary_evidence")
    if isinstance(evidence_raw, dict):
        state.milestone_boundary_evidence = {
            key: dict(val) if isinstance(val, dict) else val
            for key, val in evidence_raw.items()
        }


def _append_completed_with_guard(
    root: Path,
    state: ChainState,
    record: dict[str, Any],
    *,
    implementation_milestone: bool,
    writer,
    # T16 — atomic/enforce-mode acceptance-commit wiring.  Every parameter
    # below is optional; when they are absent (all legacy callers today) the
    # function falls back to the original shadow-mode behavior exactly.
    acceptance_result: Any = None,
    spec_path: "Path | None" = None,
    plan_dir: "Path | None" = None,
    milestone_index: "int | None" = None,
    predicate_failures: "list[dict[str, Any]] | None" = None,
    acceptance_transaction_id: str = "",
    acceptance_snapshot_hash: str = "",
) -> tuple[bool, str]:
    label = record.get("label") or "unknown"
    if any(
        isinstance(item, dict)
        and item.get("label") == label
        and item.get("status") in {"done", "completed"}
        for item in state.completed
    ):
        from arnold_pipelines.megaplan.incident.chain_control import ChainControlHold

        raise ChainControlHold("terminal_completed", "terminal completed milestones cannot be appended")
    ok, reason = _chain_completion_guard(
        root,
        record,
        implementation_milestone=implementation_milestone,
        chain_state=state,
    )

    from arnold_pipelines.megaplan.orchestration.completion_contract import (
        PREDICATE_KIND_DIVERGENT,
        PREDICATE_KIND_UNKNOWN_ACCEPTANCE_FAILURE,
        is_fail_closed_mode,
        normalize_contract_mode,
    )

    fail_closed = is_fail_closed_mode(
        normalize_contract_mode(state.completion_contract_mode)
    )

    if not fail_closed:
        # ── Shadow / warn / off: preserve legacy behavior exactly ─────────
        if not ok:
            state.last_state = "authority_divergence"
            writer(f"[chain] completion guard blocked {label}: {reason}\n")
            # Same repair seam as the terminal-authority path: record a
            # plan-level rerun cursor so recover-blocked / execute can
            # re-dispatch the genuinely-blocked tasks whose work landed but
            # whose execution evidence was not corroborated.
            if record.get("plan"):
                try:
                    _record_chain_authority_divergence_cursor(
                        root, str(record["plan"]), reason, writer=writer
                    )
                except Exception:
                    pass
            return False, reason
        if spec_path is not None and plan_dir is not None:
            from arnold_pipelines.megaplan.chain.wbc import (
                CHAIN_ADVANCE_SURFACE,
                CHAIN_ADVANCE_WRITER_ID,
                ChainWbcRule,
                record_chain_wbc_evidence,
                validate_chain_wbc_transition,
            )

            validation_evidence = validate_chain_wbc_transition(
                writer_id=CHAIN_ADVANCE_WRITER_ID,
                surface_name=CHAIN_ADVANCE_SURFACE,
                transition_name="chain_milestone_advance",
                subject=label,
                source_path=Path(spec_path),
                project_dir=root,
                rules=(
                    ChainWbcRule("completion_guard", True, ok, ok),
                    ChainWbcRule(
                        "plan_name_bound",
                        True,
                        bool(record.get("plan")),
                        bool(record.get("plan")),
                    ),
                    ChainWbcRule(
                        "milestone_index_known",
                        True,
                        milestone_index is not None,
                        milestone_index is not None,
                    ),
                ),
                extra={
                    "plan_name": str(record.get("plan") or ""),
                    "milestone_index": milestone_index,
                    "guard_reason": reason,
                },
            )
            record_chain_wbc_evidence(
                state.metadata,
                entry_key=f"chain_advance:{label}:{milestone_index}",
                evidence=validation_evidence,
            )
        if any(item.get("label") == label and item.get("status") in {"done", "completed"} for item in state.completed):
            from arnold_pipelines.megaplan.incident.chain_control import ChainControlHold

            raise ChainControlHold("terminal_completed", "terminal completed milestones cannot be appended")
        state.completed.append(record)
        if spec_path is not None:
            from arnold_pipelines.megaplan.incident.chain_control import apply_chain_lifecycle

            apply_chain_lifecycle(
                spec_path,
                root,
                intent_kind="completion",
                actor={"id": "chain", "class": "system"},
                linked_receipts=[
                    item
                    for item in (acceptance_transaction_id, acceptance_snapshot_hash)
                    if item
                ],
                effect=lambda _txn: {
                    "actual_cursor": milestone_index,
                    "pre_state_digest": "incomplete",
                    "post_state_digest": "completed",
                    "label": label,
                    "linked_receipts": [
                        item
                        for item in (acceptance_transaction_id, acceptance_snapshot_hash)
                        if item
                    ],
                },
            )
        return True, reason

    # ── Atomic / enforce (fail-closed) mode ──────────────────────────────
    def _record_repair_target(
        kind: str,
        summary: str,
        *,
        details: "dict[str, Any] | None" = None,
        evidence_kind: str = "completion_guard",
    ) -> None:
        """Record a typed acceptance repair target without mutating completion
        or cursor state (prior state stays unchanged on failure)."""
        targets = list(state.metadata.get("completion_guard_repair_targets") or [])
        target: dict[str, Any] = {
            "kind": str(kind),
            "evidence_kind": str(evidence_kind),
            "summary": str(summary),
            "details": dict(details or {}),
        }
        if acceptance_transaction_id:
            target["acceptance_transaction_id"] = acceptance_transaction_id
        if acceptance_snapshot_hash:
            target["acceptance_snapshot_hash"] = acceptance_snapshot_hash
        targets.append(target)
        state.metadata["completion_guard_repair_targets"] = targets

    # (1) Predicate failure -> fail closed; prior state unchanged.
    if not ok:
        writer(f"[chain] completion guard blocked {label} (atomic): {reason}\n")
        if predicate_failures:
            for pf in predicate_failures:
                if not isinstance(pf, dict):
                    continue
                _record_repair_target(
                    str(pf.get("kind") or PREDICATE_KIND_UNKNOWN_ACCEPTANCE_FAILURE),
                    str(pf.get("summary") or reason),
                    details=dict(pf.get("details") or {}),
                    evidence_kind=str(pf.get("evidence_kind") or "completion_guard"),
                )
        else:
            _record_repair_target(
                PREDICATE_KIND_UNKNOWN_ACCEPTANCE_FAILURE,
                reason,
                details={
                    "legacy": True,
                    "plan_name": str(record.get("plan") or ""),
                    "milestone_label": label,
                    "predicate_reason": reason,
                },
            )
        return False, reason

    # (2) Predicate passed.  Atomic completion requires a durably committed
    #     accepted boundary to advance the completion cursor.  Without one the
    #     cursor must never advance (fail-closed: never complete without
    #     accepted acceptance evidence).
    if acceptance_result is None or spec_path is None or plan_dir is None:
        block_reason = (
            f"atomic completion for {label} requires an accepted acceptance "
            "boundary; none provided (fail-closed)"
        )
        writer(f"[chain] {block_reason}\n")
        _record_repair_target(
            PREDICATE_KIND_UNKNOWN_ACCEPTANCE_FAILURE,
            block_reason,
            details={
                "legacy": True,
                "plan_name": str(record.get("plan") or ""),
                "milestone_label": label,
                "missing_acceptance_evidence": True,
            },
        )
        return False, block_reason

    # (3) Stage the acceptance commit as one CAS-backed journal transaction.
    from arnold_pipelines.megaplan.orchestration.completion_io import (
        commit_acceptance_commit,
        discard_acceptance_commit,
        prepare_acceptance_commit,
    )

    try:
        commit_plan = prepare_acceptance_commit(
            plan_dir=Path(plan_dir),
            spec_path=Path(spec_path),
            result=acceptance_result,
            state=state,
            milestone_index=milestone_index,
        )
    except ValueError as exc:
        # Boundary precondition rejected (not accepted, unbound identity, ...).
        prep_reason = f"acceptance commit prepare rejected for {label}: {exc}"
        writer(f"[chain] {prep_reason}\n")
        _record_repair_target(
            PREDICATE_KIND_UNKNOWN_ACCEPTANCE_FAILURE,
            prep_reason,
            details={
                "plan_name": str(record.get("plan") or ""),
                "milestone_label": label,
                "prepare_error": str(exc),
            },
        )
        return False, prep_reason

    # (4) Apply durably under the CAS guard.
    cas_result = commit_acceptance_commit(commit_plan)
    if not getattr(cas_result, "committed", False):
        # CAS violation -> prior durable state unchanged (the journal already
        # discarded the staged transaction).  Discard any remaining staged
        # prepare and emit a typed divergent repair target.
        discard_acceptance_commit(commit_plan)
        violations = getattr(cas_result, "violations", ()) or ()
        viol_summary = (
            "; ".join(
                f"{v.guard}@{Path(v.target_path).name}" for v in violations
            )
            or "cas guard mismatch"
        )
        cas_reason = (
            f"acceptance commit CAS violation for {label} (prior state "
            f"unchanged): {viol_summary}"
        )
        writer(f"[chain] {cas_reason}\n")
        _record_repair_target(
            PREDICATE_KIND_DIVERGENT,
            cas_reason,
            details={
                "plan_name": str(record.get("plan") or ""),
                "milestone_label": label,
                "cas_violations": [v.to_dict() for v in violations],
            },
            evidence_kind="acceptance_commit",
        )
        return False, cas_reason

    # (5) Commit succeeded.  Mirror the durably-committed completion fields
    #     into the in-memory state so downstream callers observe the same
    #     state that was just written under the CAS guard.
    from arnold_pipelines.megaplan.chain.wbc import (
        CHAIN_ADVANCE_SURFACE,
        CHAIN_ADVANCE_WRITER_ID,
        ChainWbcRule,
        record_chain_wbc_evidence,
        validate_chain_wbc_transition,
    )

    validation_evidence = validate_chain_wbc_transition(
        writer_id=CHAIN_ADVANCE_WRITER_ID,
        surface_name=CHAIN_ADVANCE_SURFACE,
        transition_name="chain_milestone_advance",
        subject=label,
        source_path=Path(spec_path),
        project_dir=root,
        rules=(
            ChainWbcRule("completion_guard", True, ok, ok),
            ChainWbcRule(
                "acceptance_commit_committed",
                True,
                bool(getattr(cas_result, "committed", False)),
                bool(getattr(cas_result, "committed", False)),
            ),
            ChainWbcRule(
                "accepted_boundary_present",
                True,
                acceptance_result is not None,
                acceptance_result is not None,
            ),
            ChainWbcRule(
                "milestone_index_known",
                True,
                milestone_index is not None,
                milestone_index is not None,
            ),
        ),
        extra={
            "plan_name": str(record.get("plan") or ""),
            "milestone_index": milestone_index,
            "acceptance_transaction_id": acceptance_transaction_id,
            "acceptance_snapshot_hash": acceptance_snapshot_hash,
            "guard_reason": reason,
        },
    )
    record_chain_wbc_evidence(
        state.metadata,
        entry_key=f"chain_advance:{label}:{milestone_index}",
        evidence=validation_evidence,
    )
    if any(item.get("label") == label and item.get("status") in {"done", "completed"} for item in state.completed):
        from arnold_pipelines.megaplan.incident.chain_control import ChainControlHold

        raise ChainControlHold("terminal_completed", "terminal completed milestones cannot be appended")
    _apply_committed_acceptance_state(state, commit_plan.new_state)
    if spec_path is not None:
        from arnold_pipelines.megaplan.incident.chain_control import apply_chain_lifecycle

        apply_chain_lifecycle(
            spec_path,
            root,
            intent_kind="completion",
            actor={"id": "chain", "class": "system"},
            linked_receipts=[
                item
                for item in (
                    acceptance_transaction_id,
                    acceptance_snapshot_hash,
                    getattr(cas_result, "transaction_id", None),
                )
                if item
            ],
            effect=lambda _txn: {
                "actual_cursor": milestone_index,
                "pre_state_digest": "incomplete",
                "post_state_digest": "completed",
                "label": label,
                "prepare_commit": True,
            },
        )
    return True, reason


def _emit_milestone_start_evidence(
    state: ChainState,
    *,
    milestone_label: str,
    milestone_index: int,
    plan_name: str,
) -> None:
    """Record durable milestone-start boundary evidence in chain state."""
    evidence = chain_spec.build_milestone_boundary_evidence(
        milestone_label=milestone_label,
        milestone_index=milestone_index,
        plan_name=plan_name,
        contract_id=CHAIN_MILESTONE_START_ROW_ID,
        contract_boundary_id="chain_milestone_start",
        state=state,
    )
    state.set_milestone_evidence(evidence)


def _emit_milestone_completion_evidence(
    state: ChainState,
    *,
    milestone_label: str,
    milestone_index: int,
    plan_name: str,
) -> None:
    """Record durable milestone-completion boundary evidence in chain state."""
    evidence = chain_spec.build_milestone_boundary_evidence(
        milestone_label=milestone_label,
        milestone_index=milestone_index,
        plan_name=plan_name,
        contract_id=CHAIN_MILESTONE_COMPLETION_ROW_ID,
        contract_boundary_id="chain_milestone_completion",
        state=state,
    )
    state.set_milestone_evidence(evidence)


def _emit_chain_complete_evidence(
    state: ChainState,
    *,
    spec: ChainSpec,
) -> None:
    """Record durable chain-complete boundary evidence in chain state."""
    plan_name = "chain_complete"
    evidence = chain_spec.build_milestone_boundary_evidence(
        milestone_label="chain_complete",
        milestone_index=len(spec.milestones),
        plan_name=plan_name,
        contract_id=CHAIN_COMPLETE_ROW_ID,
        contract_boundary_id="chain_complete",
        state=state,
    )
    state.set_milestone_evidence(evidence)


def _reconciliation_fail_closed(state: ChainState) -> tuple[bool, str]:
    """Return ``(True, reason)`` when reconciliation operates in fail-closed mode.

    In atomic/enforce mode, reconciliation must never grant completion
    authority from a ground-truth projection (terminal plan state, merged PR
    state, reviewed finalized state, or any other derived observation).  Only
    an accepted acceptance transaction recorded through the CAS-backed commit
    helper can advance the completion cursor.  This helper lets the
    reconciliation append primitives short-circuit before mutating
    ``state.completed`` so projections cannot masquerade as acceptance
    authority.
    """
    from arnold_pipelines.megaplan.orchestration.completion_contract import (
        is_fail_closed_mode,
        normalize_contract_mode,
    )

    mode = normalize_contract_mode(state.completion_contract_mode)
    if is_fail_closed_mode(mode):
        return True, (
            "reconciliation cannot grant atomic-mode completion authority "
            "from a ground-truth projection without an accepted acceptance "
            "transaction (fail-closed)"
        )
    return False, ""


def _append_reconciled_completed_record(
    root: Path,
    state: ChainState,
    *,
    plan_name: str,
    milestone: MilestoneSpec,
    pr_number: int | None,
    pr_state: str | None,
    completion_reason: str,
    writer,
) -> bool:
    # T17 — reconciliation cannot grant atomic-mode completion authority from
    # ground-truth projections without an accepted acceptance transaction.
    fail_closed, reason = _reconciliation_fail_closed(state)
    if fail_closed:
        writer(
            f"[chain] reconciliation blocked completed record for "
            f"{milestone.label} in atomic mode: {reason}\n"
        )
        return False
    state.completed.append(
        {
            "label": milestone.label,
            "plan": plan_name,
            "status": STATE_DONE,
            "pr_number": pr_number,
            "pr_state": pr_state,
        }
    )
    _mark_plan_completed_by_chain(
        root,
        plan_name,
        milestone_label=milestone.label,
        completion_reason=completion_reason,
        writer=writer,
        state=state,
    )
    # Emit milestone completion boundary evidence for the reconciled record.
    _emit_milestone_completion_evidence(
        state,
        milestone_label=milestone.label,
        milestone_index=-1,  # caller is responsible for setting the right index
        plan_name=plan_name,
    )
    return True


def _revalidate_local_no_push_completed_record(
    root: Path,
    state: ChainState,
    record: dict[str, Any],
) -> tuple[bool, str]:
    """Revalidate an explicitly accepted local-only completion record."""

    if record.get("status") != STATE_DONE:
        return False, "local/no-push completion record is not terminal done"
    if record.get("pr_number") is not None:
        return False, "local/no-push completion record unexpectedly has PR metadata"
    if record.get("publication_evidence") != "local_no_push_reconciliation":
        return False, "completed record has no explicit local/no-push publication evidence"
    local_commit_sha = record.get("local_commit_sha")
    if not isinstance(local_commit_sha, str) or not local_commit_sha.strip():
        return False, "local/no-push completion record has no local commit SHA"
    return _chain_completion_guard(
        root,
        record,
        implementation_milestone=True,
        chain_state=state,
    )


def _append_reconciled_completed_record_with_guard(
    root: Path,
    state: ChainState,
    *,
    spec_path: Path | None = None,
    plan_name: str,
    milestone: MilestoneSpec,
    pr_number: int | None,
    pr_state: str | None,
    completion_reason: str,
    writer,
) -> tuple[bool, str]:
    # T17 — reconciliation cannot grant atomic-mode completion authority from
    # ground-truth projections without an accepted acceptance transaction.
    # Short-circuit before delegating to _append_completed_with_guard so the
    # projection is never turned into completion authority and no spurious
    # repair target is recorded for an expected reconciliation block.
    fail_closed, fail_reason = _reconciliation_fail_closed(state)
    if fail_closed:
        writer(
            f"[chain] reconciliation blocked completed record for "
            f"{milestone.label} in atomic mode: {fail_reason}\n"
        )
        return False, fail_reason
    backstop_gate: dict[str, Any] = {
        "blocks": False,
        "summary": None,
        "result": None,
    }
    if spec_path is not None:
        backstop_gate = _run_full_suite_backstop_gate(
            root,
            spec_path,
            plan_name,
            milestone.label,
            state.full_suite_backstop_mode,
            log_fn=lambda message: writer(f"[chain] {message}\n"),
        )
    if backstop_gate.get("blocks"):
        result = backstop_gate.get("result")
        state.metadata["reconciliation_full_suite_backstop_block"] = {
            "milestone": milestone.label,
            "plan": plan_name,
            "result": dict(result) if isinstance(result, dict) else {},
        }
        return False, _full_suite_backstop_block_reason(
            milestone.label,
            plan_name,
            result if isinstance(result, dict) else None,
        )
    state.metadata.pop("reconciliation_full_suite_backstop_block", None)
    record = {
        "label": milestone.label,
        "plan": plan_name,
        "status": STATE_DONE,
        "pr_number": pr_number,
        "pr_state": pr_state,
    }
    summary = backstop_gate.get("summary")
    if isinstance(summary, dict):
        record["full_suite_backstop"] = dict(summary)
    result = backstop_gate.get("result")
    if spec_path is not None and isinstance(result, dict):
        _persist_full_suite_backstop_baseline(
            spec_path,
            result,
            captured_at_sha=_current_head_sha(root),
            milestone_label=milestone.label,
        )
    if pr_number is None:
        local_commit_sha = _current_git_head(root)
        if local_commit_sha is not None:
            record["local_commit_sha"] = local_commit_sha
            record["publication_evidence"] = "local_no_push_reconciliation"
    appended, reason = _append_completed_with_guard(
        root,
        state,
        record,
        implementation_milestone=True,
        writer=writer,
    )
    if not appended:
        return False, reason
    _mark_plan_completed_by_chain(
        root,
        plan_name,
        milestone_label=milestone.label,
        completion_reason=completion_reason if completion_reason else reason,
        writer=writer,
        state=state,
    )
    writer(
        f"[chain] reconciled terminal plan {plan_name} into completed "
        f"milestone {milestone.label}\n"
    )
    return True, reason


# ──────────────────────────────────────────────────────────────────────────────
# M2 (T19): non-enforcing Maintenance shadow diagnostics beside the guard
# ──────────────────────────────────────────────────────────────────────────────
#
# ``_chain_completion_guard`` itself is untouched: every legacy input keeps its
# exact (ok, reason) return value.  The wrapper below evaluates the shared
# coherent Maintenance envelope *alongside* the guard and records read-only
# match/would-block diagnostics.  Stale or incoherent Maintenance evidence can
# never serialize as terminal (the diagnostic reports terminal=False), no
# plan/chain state is written, and an attempted direct plan/chain write is
# routed to the typed M7 bypass finding — no lifecycle writer is ever imported
# or invoked from this path.


def evaluate_completion_guard_with_maintenance(
    root: Path,
    record: Mapping[str, Any],
    *,
    implementation_milestone: bool,
    chain_state: Any | None = None,
    maintenance_envelope: Any | None = None,
    diagnostics: list[dict[str, Any]] | None = None,
) -> tuple[bool, str]:
    """Run the completion guard and record Maintenance shadow diagnostics.

    Delegates to :func:`_chain_completion_guard` and returns its result
    UNCHANGED — the wrapper never alters the guard's return value.  When
    ``maintenance_envelope`` is supplied, the guard verdict is compared to
    the coherent envelope and one read-only diagnostic row is recorded:

    * ``bucket == "match"`` — the guard verdict agrees with an eligible
      envelope (stale/incoherent evidence can never produce a match);
    * ``bucket == "would_block"`` — the guard would promote while the
      envelope is non-eligible (stale, incomplete, incoherent,
      cross-environment, or digest-mismatched evidence);

    ``terminal`` in the diagnostic is True ONLY for a match on an eligible
    envelope.  Diagnostics are appended to *diagnostics* when supplied and
    are always returned in the result dict.  No plan/chain state is read or
    written beyond what the guard itself already does, and no lifecycle
    writer is imported from this path.
    """
    ok, reason = _chain_completion_guard(
        root,
        dict(record),
        implementation_milestone=implementation_milestone,
        chain_state=chain_state,
    )
    shadow_rows: list[dict[str, Any]] = []
    if maintenance_envelope is not None:
        from arnold_pipelines.megaplan.maintenance.shadow import compare_shadow

        comparison = compare_shadow(
            {
                "green": bool(ok),
                "dispatchable": bool(ok),
                "terminal": bool(ok),
            },
            maintenance_envelope,
        )
        shadow_rows.append(
            {
                "schema_version": 1,
                "bucket": comparison.bucket.value,
                "reasons": list(comparison.reasons),
                "comparison_digest": comparison.digest,
                "envelope_digest": comparison.envelope_digest,
                "guard_ok": ok,
                "guard_reason": reason,
                "green": comparison.green,
                "dispatchable": comparison.dispatchable,
                "terminal": comparison.terminal,
                "envelope_eligible": comparison.envelope_eligible,
                "cross_environment": comparison.cross_environment,
            }
        )
    if diagnostics is not None:
        diagnostics.extend(shadow_rows)
    return ok, reason


def chain_direct_write_finding(
    kind: str,
    request: str,
    *,
    finding_id: str | None = None,
) -> Any:
    """Typed M7 bypass finding for an attempted direct plan/chain write.

    ``kind`` is ``"plan"`` or ``"chain"``.  The finding names the M7
    controlled-writer-inventory seam and is guaranteed inert: zero
    invocations of ``write_plan_state`` / ``save_chain_state`` /
    ``TransitionWriter`` / raw plan/chain writers.  This module never
    imports lifecycle writers from a Maintenance path.
    """
    from arnold_pipelines.megaplan.maintenance.boundaries import (
        chain_write_finding,
        plan_write_finding,
    )

    if kind == "plan":
        return plan_write_finding(request, finding_id=finding_id)
    if kind == "chain":
        return chain_write_finding(request, finding_id=finding_id)
    raise ValueError(f"direct write kind must be 'plan' or 'chain', got {kind!r}")


def _handle_completion_guard_failure(
    *,
    root: Path,
    spec_path: Path,
    spec: ChainSpec,
    state: ChainState,
    milestone: MilestoneSpec,
    plan_name: str,
    outcome_status: str,
    reason: str,
    events: list[dict[str, Any]],
    writer,
    predicate_failures: list[dict[str, Any]] | None = None,
    acceptance_transaction_id: str = "",
    acceptance_snapshot_hash: str = "",
) -> dict[str, Any]:
    writer(
        f"[chain] milestone {milestone.label} completion guard rejected terminal "
        f"claim for {plan_name}: {reason}\n"
    )

    # ── Build typed acceptance repair targets ──────────────────────────
    from arnold_pipelines.megaplan.orchestration.completion_contract import (
        PREDICATE_KIND_UNKNOWN_ACCEPTANCE_FAILURE,
    )

    repair_targets: list[dict[str, Any]] = []
    if predicate_failures:
        # Caller provided typed V2 context — use it directly.
        for pf in predicate_failures:
            if not isinstance(pf, dict):
                continue
            target: dict[str, Any] = {
                "kind": str(pf.get("kind") or PREDICATE_KIND_UNKNOWN_ACCEPTANCE_FAILURE),
                "evidence_kind": str(pf.get("evidence_kind") or "completion_guard"),
                "summary": str(pf.get("summary") or reason),
                "details": dict(pf.get("details") or {}),
            }
            if acceptance_transaction_id:
                target["acceptance_transaction_id"] = acceptance_transaction_id
            if acceptance_snapshot_hash:
                target["acceptance_snapshot_hash"] = acceptance_snapshot_hash
            repair_targets.append(target)
    else:
        # Legacy caller — no V2 context available.  Emit a fail-closed
        # unknown acceptance failure so downstream repair tooling knows
        # the guard blocked but cannot yet attribute it to a specific
        # predicate.
        legacy_target: dict[str, Any] = {
            "kind": PREDICATE_KIND_UNKNOWN_ACCEPTANCE_FAILURE,
            "evidence_kind": "completion_guard",
            "summary": reason,
            "details": {
                "legacy": True,
                "plan_name": plan_name,
                "milestone_label": milestone.label,
                "outcome_status": outcome_status,
            },
        }
        if acceptance_transaction_id:
            legacy_target["acceptance_transaction_id"] = acceptance_transaction_id
        if acceptance_snapshot_hash:
            legacy_target["acceptance_snapshot_hash"] = acceptance_snapshot_hash
        repair_targets.append(legacy_target)

    state.metadata["completion_guard_repair_targets"] = repair_targets

    # ── T14 — invalidate prior acceptance candidates ───────────────────
    # After a completion guard blocks, any prior uncommitted acceptance
    # candidate is stale.  The caller must produce a new snapshot and run
    # the full acceptance boundary before committing.
    try:
        plan_path = resolve_plan_dir(root, plan_name) if plan_name else None
    except Exception:
        plan_path = None
    if plan_path is not None and plan_path.is_dir():
        now_iso = datetime.now(timezone.utc).isoformat()
        state.invalidate_candidate(
            milestone.label,
            transaction_id=acceptance_transaction_id or "",
            reason=reason or "completion guard blocked",
            superseded_by="",
            invalidated_at=now_iso,
        )
        # Also call the cloud-level candidate invalidation to discard
        # any uncommitted candidate files on disk.
        try:
            from arnold_pipelines.megaplan.cloud.repair_revalidation import (
                invalidate_acceptance_candidates_after_repair,
            )
            invalidate_acceptance_candidates_after_repair(
                plan_path,
                milestone_label=milestone.label,
                repair_reason=f"completion guard blocked: {reason}",
            )
        except Exception:
            pass

    synthetic = DriverOutcome(
        plan=plan_name,
        status="blocked",
        final_state=outcome_status,
        iterations=0,
        reason=f"completion guard rejected terminal claim: {reason}",
        last_phase="completion_guard",
    )
    decision = _handle_outcome(
        synthetic,
        spec=spec,
        writer=writer,
        milestone=milestone,
        state=state,
        root=root,
        spec_path=spec_path,
    )
    if decision == "retry":
        resumable_state = _resumable_retry_state(root, state.current_plan_name)
        if resumable_state is not None:
            writer(
                f"[chain] retrying milestone {milestone.label} by resuming plan "
                f"{state.current_plan_name} from {resumable_state}\n"
            )
        else:
            writer(f"[chain] retrying milestone {milestone.label}\n")
            state.current_plan_name = None
        state.last_state = "blocked"
        state.pr_number = None
        state.pr_state = None
        chain_spec.save_chain_state(spec_path, state)
        return _result(
            "stopped",
            state,
            events,
            spec=spec,
            reason=f"milestone {milestone.label} completion guard retrying: {reason}",
        )
    if decision == "stop":
        state.last_state = "blocked"
        _maybe_file_ladder_ticket(
            root,
            spec_path,
            milestone,
            synthetic,
            state,
            writer=writer,
        )
        chain_spec.save_chain_state(spec_path, state)
        return _result(
            "stopped",
            state,
            events,
            spec=spec,
            reason=f"milestone {milestone.label} completion guard blocked append: {reason}",
        )
    state.last_state = "authority_divergence"
    chain_spec.save_chain_state(spec_path, state)
    return _result(
        "blocked",
        state,
        events,
        spec=spec,
        reason=f"milestone {milestone.label} completion guard blocked append: {reason}",
    )


def _finalize_records_missing_authority_fields(
    task_records: list[dict[str, Any]],
) -> list[str]:
    from arnold_pipelines.megaplan.orchestration.rubber_stamp import is_rubber_stamp

    missing: list[str] = []
    for task in task_records:
        task_id = str(task.get("task_id") or task.get("id") or "?")
        if any(
            task.get(field)
            for field in (
                "files_changed",
                "commands_run",
                "evidence_files",
                "sections_written",
                "evidence",
            )
        ):
            continue
        kind = task.get("kind")
        notes = task.get("executor_notes")
        reviewer_verdict = task.get("reviewer_verdict")
        if (
            task.get("status") == "skipped"
            and isinstance(notes, str)
            and notes.strip()
            and not is_rubber_stamp(notes, strict=True)
        ):
            continue
        if _is_explained_noop_completion(task):
            continue
        if reviewer_verdict == "deferred_baseline_unavailable":
            continue
        if (
            kind in {"audit", "research"}
            and isinstance(notes, str)
            and len(notes.strip()) >= 100
            and not is_rubber_stamp(notes, strict=True)
        ):
            continue
        if task.get("status") in {"waived", "not_applicable"}:
            continue
        missing.append(f"{task_id}='unknown':missing_finalize_authority_fields")
    return missing


def _optional_finalize_status(task: dict[str, Any]) -> str:
    raw = task.get("status")
    return str(raw).strip().lower() if isinstance(raw, str) else ""


def _task_record_has_authority_payload(task: dict[str, Any]) -> bool:
    return any(
        task.get(field)
        for field in (
            "files_changed",
            "commands_run",
            "evidence_files",
            "sections_written",
            "evidence",
        )
    )


def _task_record_can_override_finalize(task: dict[str, Any]) -> bool:
    status = str(task.get("status") or "").strip().lower()
    if status in {"done", "waived", "not_applicable", "skipped"}:
        return True
    return _task_record_has_authority_payload(task)


_CHAIN_SHADOW_TERMINAL_STATUSES = frozenset(
    {"done", "completed", "skipped", "waived", "not_applicable"}
)


def _plan_relative_source(plan_dir: Path, path: Path) -> str:
    try:
        return str(path.relative_to(plan_dir))
    except ValueError:
        return str(path)


def _decision_shadow_reason(decision: AuthorityDecision | None) -> str:
    if decision is None:
        return "no compatibility-adapter decision"
    reason = next(iter(decision.would_block_reasons), "")
    if reason:
        return reason
    raw = decision.diagnostics.get("reason")
    if isinstance(raw, str) and raw:
        return raw
    return decision.status.value


def _decision_shadow_sources(
    decision: AuthorityDecision | None,
    *,
    projection_sources: tuple[str, ...],
) -> str:
    sources: set[str] = set(projection_sources)
    if decision is not None:
        diagnostics = decision.diagnostics
        for key in ("source_path", "source"):
            value = diagnostics.get(key)
            if isinstance(value, str) and value:
                sources.add(value)
        raw_source_paths = diagnostics.get("source_paths")
        if isinstance(raw_source_paths, list):
            sources.update(str(item) for item in raw_source_paths if str(item))
        validation = diagnostics.get("authority_validation")
        if isinstance(validation, Mapping):
            value = validation.get("source_path")
            if isinstance(value, str) and value:
                sources.add(value)
        raw_projection_diagnostics = diagnostics.get("projection_diagnostics")
        if isinstance(raw_projection_diagnostics, list):
            for item in raw_projection_diagnostics:
                if not isinstance(item, Mapping):
                    continue
                value = item.get("source")
                if isinstance(value, str) and value:
                    sources.add(value)
    return ", ".join(sorted(sources)) or "accepted-attempt projection unavailable"


def _chain_completion_shadow_disagreements(
    task_records: list[dict[str, Any]],
    completed: set[str],
    decisions: Mapping[str, AuthorityDecision],
    *,
    source_by_task: Mapping[str, str],
    plan_dir: Path,
    chain_state: ChainState | None,
    completion_record: Mapping[str, Any] | None,
    default_source: str,
    default_source_kind: str,
) -> list[str]:
    """Name legacy/projection disagreement sources without granting authority."""

    projection = accepted_attempt_execution_projection(task_records, plan_dir=plan_dir)
    projection_sources = projection.source_paths if projection is not None else ()
    diagnostics: list[str] = []
    incomplete_task_sources: list[str] = []
    for task in task_records:
        task_id = str(task.get("task_id") or task.get("id") or "")
        if not task_id:
            continue
        status = _optional_finalize_status(task)
        if not status:
            continue
        label_source = source_by_task.get(task_id, default_source)
        label_kind = "batch overlay" if task_id in source_by_task else default_source_kind
        accepted = task_id in completed
        if not accepted:
            incomplete_task_sources.append(f"{task_id} from {label_source}")
        decision = decisions.get(task_id)
        authority_sources = _decision_shadow_sources(
            decision,
            projection_sources=projection_sources,
        )
        reason = _decision_shadow_reason(decision)
        if status in _CHAIN_SHADOW_TERMINAL_STATUSES and not accepted:
            diagnostics.append(
                f"chain_authority_shadow[{task_id}]: {label_kind} source "
                f"{label_source} status={status!r} disagrees with "
                "dispatch-grant/accepted-attempt authority "
                f"({authority_sources}): {reason}"
            )

    if completion_record is not None and incomplete_task_sources:
        label = str(completion_record.get("label") or "unknown")
        record_status = str(completion_record.get("status") or "").strip().lower()
        if record_status in _CHAIN_SHADOW_TERMINAL_STATUSES:
            source = f"chain_state.completed[{label}]"
            if chain_state is not None:
                source = f"{source}@current_milestone_index={chain_state.current_milestone_index}"
            diagnostics.append(
                f"chain_authority_shadow[{label}]: chain state source {source} "
                f"status={record_status!r} disagrees with task authority; "
                f"incomplete sources: {', '.join(sorted(incomplete_task_sources))}"
            )

    return sorted(set(diagnostics))


def _non_authoritative_task_reasons(
    task_records: list[dict[str, Any]],
    completed: set[str],
    decisions: dict[str, AuthorityDecision],
    *,
    source_by_task: Mapping[str, str] | None = None,
) -> list[str]:
    incomplete: list[str] = []
    for task in task_records:
        task_id = str(task.get("task_id") or task.get("id") or "?")
        if task_id in completed:
            continue
        source = (
            source_by_task.get(task_id, "finalize.json")
            if source_by_task is not None
            else None
        )
        decision = decisions.get(task_id)
        if decision is None:
            suffix = f":source={source}" if source else ""
            incomplete.append(f"{task_id}={task.get('status')!r}{suffix}")
            continue
        reason = next(iter(decision.would_block_reasons), decision.status.value)
        suffix = f":source={source}" if source else ""
        incomplete.append(f"{task_id}={decision.status.value!r}:{reason}{suffix}")
    return incomplete


def _mark_blocked_execute_as_executed(plan_dir: Path) -> None:
    from arnold_pipelines.megaplan._core.state import write_plan_state

    def _patch_blocked_execute(current: dict[str, Any]) -> bool:
        current.pop("active_step", None)
        current.pop("latest_failure", None)
        current.pop("resume_cursor", None)
        return True

    write_plan_state(
        plan_dir,
        mode="patch-many",
        patch={"current_state": STATE_EXECUTED},
        mutation=_patch_blocked_execute,
    )


def _has_unresolved_execute_user_actions(plan_dir: Path) -> tuple[bool, str | None]:
    try:
        finalize_payload = json.loads((plan_dir / "finalize.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError, UnicodeDecodeError):
        return False, None
    if not isinstance(finalize_payload, dict):
        return False, None
    user_actions = finalize_payload.get("user_actions")
    if not isinstance(user_actions, list) or not user_actions:
        return False, None

    try:
        state_payload = json.loads((plan_dir / "state.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError, UnicodeDecodeError):
        state_payload = {}
    if not isinstance(state_payload, dict):
        state_payload = {}

    resolutions = effective_user_action_resolutions(plan_dir, state_payload)
    for action in user_actions:
        if not isinstance(action, dict):
            continue
        action_id = action.get("id")
        if not isinstance(action_id, str) or not action_id:
            continue
        status = action_resolution_status(action, resolutions)
        if status.get("resolution") in {"satisfied", "accepted_blocked", "waived"}:
            continue
        return True, action_id
    return False, None


def _mark_plan_completed_by_chain(
    root: Path,
    plan_name: str,
    *,
    milestone_label: str,
    completion_reason: str,
    writer,
    state: "ChainState | None" = None,
) -> None:
    """Mirror an authoritative chain-level milestone completion into plan state.

    T18 — In atomic/enforce (fail-closed) mode the plan-done projection
    requires an accepted acceptance transaction for this milestone.  Without
    one the projection is never written (fail-closed: plan state must not
    signal completion authority that was not accepted).
    """

    from arnold_pipelines.megaplan._core.state import write_plan_state
    from arnold_pipelines.megaplan.observability.events import EventKind, emit as emit_event
    from arnold_pipelines.megaplan.orchestration.completion_contract import (
        is_fail_closed_mode,
        normalize_contract_mode,
    )

    # ── T18: atomic/enforce gate ─────────────────────────────────────────
    if state is not None:
        mode = normalize_contract_mode(state.completion_contract_mode)
        if is_fail_closed_mode(mode):
            if not state.has_acceptance_receipt(milestone_label):
                writer(
                    f"[chain] plan-done marker blocked for {plan_name} "
                    f"milestone={milestone_label} in atomic mode: "
                    f"no accepted acceptance transaction for this milestone "
                    f"(fail-closed — plan-done projection requires accepted evidence)\n"
                )
                return

    try:
        plan_dir = resolve_plan_dir(root, plan_name)
    except CliError:
        return

    def _patch_completed(current: dict[str, Any]) -> bool:
        current["current_state"] = STATE_DONE
        current.pop("active_step", None)
        current.pop("latest_failure", None)
        current.pop("resume_cursor", None)
        meta = current.setdefault("meta", {})
        if not isinstance(meta, dict):
            current["meta"] = meta = {}
        meta["chain_completion"] = {
            "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "milestone_label": milestone_label,
            "reason": completion_reason,
        }
        return True

    try:
        written_state = write_plan_state(
            plan_dir,
            mode="patch-many",
            patch={},
            mutation=_patch_completed,
        )
    except Exception as error:
        writer(
            f"[chain] warning: failed to reconcile completed plan {plan_name}: {error}\n"
        )
        return
    try:
        emit_event(
            EventKind.PLAN_FINISHED,
            plan_dir=plan_dir,
            payload={
                "state": written_state,
                "source": "chain_completion",
                "milestone_label": milestone_label,
                "reason": completion_reason,
            },
        )
    except Exception as error:
        writer(
            f"[chain] warning: failed to emit plan_finished for {plan_name}: {error}\n"
        )


def _mark_plan_missing_base_ref(root: Path, plan_name: str | None, *, failure: dict[str, Any]) -> None:
    if not plan_name:
        return
    try:
        plan_dir = resolve_plan_dir(root, plan_name)
    except CliError:
        return
    state_path = plan_dir / "state.json"
    try:
        raw = json.loads(state_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError, UnicodeDecodeError):
        return
    if not isinstance(raw, dict):
        return
    resume_cursor = raw.get("resume_cursor")
    if not isinstance(resume_cursor, dict):
        resume_cursor = {}
    resume_cursor["phase"] = "recover-base-branch"
    resume_cursor["retry_strategy"] = "manual_review"
    raw["resume_cursor"] = resume_cursor
    raw["current_state"] = "manual_review"
    raw["latest_failure"] = {
        "kind": "missing_base_ref",
        "message": str(failure.get("message") or ""),
        "phase": "chain",
        "recorded_at": str(failure.get("recorded_at") or ""),
    }
    atomic_write_json(state_path, raw)


def _handle_missing_base_ref(
    root: Path,
    spec_path: Path,
    state: ChainState,
    *,
    spec: ChainSpec,
    events: list[dict[str, Any]],
    milestone_label: str | None,
    error: CliError,
) -> dict[str, Any]:
    last_known_sha = None
    if isinstance(error.extra, dict):
        raw_sha = error.extra.get("last_known_sha")
        if isinstance(raw_sha, str) and raw_sha:
            last_known_sha = raw_sha
    if not last_known_sha:
        last_known_sha = state.target_base_ref
    failure = {
        "base_branch": spec.base_branch,
        "last_known_sha": last_known_sha,
        "message": error.message,
        "milestone": milestone_label,
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "retry_strategy": "manual_review",
    }
    state.last_state = "missing_base_ref"
    state.metadata["missing_base_ref"] = failure
    _mark_plan_missing_base_ref(root, state.current_plan_name, failure=failure)
    chain_spec.save_chain_state(spec_path, state)
    events.append({"msg": error.message, "state": "missing_base_ref", "base_branch": spec.base_branch})
    return _result(
        "stopped",
        state,
        events,
        spec=spec,
        reason=error.message,
    )


def _promote_done_plan_to_executed(
    root: Path,
    plan: str,
    *,
    writer,
) -> bool:
    """Promote a pre-execute plan to executed when its work is provably done.

    The execute-reentry loop (grok consult, astrid/mega-main): an operator
    recover-blocked leaves the plan finalized, and the chain driver re-enters
    execute — re-running stale batch artifacts and reopening the quality-gate
    circuit — even when every finalize task is done and execution.json is
    complete.  The existing `_recover_blocked_execute_if_tasks_done` only
    fires when the history's last execute result is literally 'blocked', which
    an adopted/recovered plan no longer shows.  This helper is history-
    independent: it promotes finalized plans whose finalize tasks are all done
    AND whose execution.json task updates are all done.  Returns True when the
    plan was promoted (or was already executed/done), False when there is real
    remaining execute work.
    """
    try:
        plan_dir = resolve_plan_dir(root, plan)
    except CliError:
        return False
    current_state = _plan_current_state_from_payload(root, plan)
    if current_state in {"executed", "done", "review", "awaiting_human_verify"}:
        return True
    if current_state not in {"finalized", "planned"}:
        return False
    finalize_path = plan_dir / "finalize.json"
    execution_path = plan_dir / "execution.json"
    if not finalize_path.exists():
        return False
    try:
        finalize = json.loads(finalize_path.read_text(encoding="utf-8"))
        tasks = finalize.get("tasks") or []
        if not isinstance(tasks, list) or not tasks:
            return False
        if not all(isinstance(t, dict) and t.get("status") == "done" for t in tasks):
            return False
        if execution_path.exists():
            execution = json.loads(execution_path.read_text(encoding="utf-8"))
            updates = execution.get("task_updates") or []
            if isinstance(updates, list) and updates:
                if not all(
                    isinstance(u, dict) and u.get("status") == "done" for u in updates
                ):
                    return False
    except (OSError, ValueError, TypeError):
        return False
    # All finalize tasks done + execution updates done: promote to executed.
    _mark_blocked_execute_as_executed(plan_dir)
    writer(
        f"[chain] plan {plan} finalize+execution fully done; promoting to executed "
        "before drive (no re-execute)\n"
    )
    return True


def _recover_blocked_execute_if_tasks_done(
    root: Path,
    spec_path: Path,
    spec: ChainSpec,
    outcome: DriverOutcome,
    *,
    writer,
) -> bool:
    if outcome.status not in BLOCKED_EXECUTE_OUTCOME_STATUSES:
        return False
    try:
        plan_dir = resolve_plan_dir(root, outcome.plan)
    except CliError:
        chain_spec._warn_chain_fallback(
            "M3A_WARN_BLOCKED_EXECUTE_RECOVERY",
            reason="plan_dir_unavailable",
            context={"plan": outcome.plan},
        )
        return False
    if _latest_execute_result(plan_dir) != "blocked":
        return False
    has_unresolved_user_actions, action_id = _has_unresolved_execute_user_actions(plan_dir)
    if has_unresolved_user_actions:
        reason = (
            f"unresolved user action {action_id}"
            if action_id
            else "unresolved execute user action"
        )
        writer(
            f"[chain] execute result=blocked for {outcome.plan}; treating as real block: {reason}\n"
        )
        return False

    all_done, reason = _latest_execution_batch_all_tasks_done(plan_dir)
    if not all_done:
        if _recover_stale_prerequisite_block(
            root,
            spec_path,
            spec,
            outcome,
            plan_dir=plan_dir,
            reason=reason,
            writer=writer,
        ):
            return True
        writer(
            f"[chain] execute result=blocked for {outcome.plan}; treating as real block: {reason}\n"
        )
        return False

    _mark_blocked_execute_as_executed(plan_dir)
    writer(
        f"[chain] execute result=blocked for {outcome.plan}, but {reason} has all tasks done; "
        "continuing from executed state\n"
    )
    return True


_PREREQUISITE_BLOCK_TOKENS = (
    "blocked_by_prereq",
    "prerequisite",
    "launch gate",
    "launch precondition",
    "completion manifest",
    "proof-map",
    "proof map",
    "chain_completed",
)


def _looks_like_prerequisite_block(
    outcome: DriverOutcome,
    *,
    extra_text: str = "",
) -> bool:
    if outcome.status not in {
        "blocked",
        "worker_blocked",
        "awaiting_human",
        "human_required",
    }:
        return False
    text = " ".join(
        str(part)
        for part in [
            outcome.reason,
            outcome.last_phase,
            *outcome.blocking_reasons,
            extra_text,
        ]
        if part
    ).lower()
    return any(token in text for token in _PREREQUISITE_BLOCK_TOKENS)


def _plan_latest_failure_text(plan_dir: Path) -> str:
    try:
        raw = json.loads((plan_dir / "state.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return ""
    if not isinstance(raw, dict):
        return ""
    latest_failure = raw.get("latest_failure")
    parts: list[str] = []
    if isinstance(latest_failure, dict):
        for key in ("kind", "message", "suggested_action", "phase"):
            value = latest_failure.get(key)
            if isinstance(value, str):
                parts.append(value)
        metadata = latest_failure.get("metadata")
        if isinstance(metadata, dict):
            blocking_reasons = metadata.get("blocking_reasons")
            if isinstance(blocking_reasons, list):
                parts.extend(str(item) for item in blocking_reasons if item)
    resume_cursor = raw.get("resume_cursor")
    if isinstance(resume_cursor, dict):
        parts.extend(str(value) for value in resume_cursor.values() if value)
    return " ".join(parts)


def _clear_execute_task_attempt_fields(task: dict[str, Any]) -> None:
    task["status"] = "pending"
    task["executor_notes"] = ""
    task["files_changed"] = []
    task["commands_run"] = []
    task["evidence_files"] = []
    task["reviewer_verdict"] = ""
    task.pop("recorded_invocation_id", None)


def _reset_stale_prerequisite_blocked_tasks(
    plan_dir: Path,
    outcome: DriverOutcome,
) -> list[str]:
    try:
        from arnold_pipelines.megaplan.orchestration.finalize_authority import (
            FinalizeMutationContext,
            load_finalize_for_update,
            publish_finalize_update,
        )

        finalize_data = load_finalize_for_update(plan_dir)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(finalize_data, dict):
        return []
    tasks = finalize_data.get("tasks")
    if not isinstance(tasks, list):
        return []
    outcome_text = " ".join([outcome.reason, *outcome.blocking_reasons]).lower()
    reset_ids: list[str] = []
    for task in tasks:
        if not isinstance(task, dict) or task.get("status") != "blocked":
            continue
        task_id = task.get("id")
        if not isinstance(task_id, str) or not task_id:
            continue
        task_text = " ".join(
            str(task.get(key) or "")
            for key in ("id", "description", "executor_notes", "reviewer_verdict")
        ).lower()
        if task_id.lower() not in outcome_text and not any(
            token in task_text for token in _PREREQUISITE_BLOCK_TOKENS
        ):
            continue
        _clear_execute_task_attempt_fields(task)
        reset_ids.append(task_id)
    if reset_ids:
        publish_finalize_update(
            plan_dir,
            finalize_data,
            context=FinalizeMutationContext(
                owner="execute",
                operation="reset-stale-prerequisite-blocks",
                attempt_id="chain-recovery:" + ",".join(sorted(reset_ids)),
            ),
        )
    return sorted(reset_ids)


def _recover_stale_prerequisite_block(
    root: Path,
    spec_path: Path,
    spec: ChainSpec,
    outcome: DriverOutcome,
    *,
    plan_dir: Path,
    reason: str,
    writer,
) -> bool:
    """Retry a blocked execute when current chain preconditions now pass.

    Executor workers can block from stale prerequisite evidence captured in an
    earlier plan/gate/audit artifact. The chain has stronger current authority:
    its launch preconditions and completion manifests. If those pass now, clear
    the stale blocked attempt and let execute re-run with an explicit audit note.
    """

    latest_failure_text = _plan_latest_failure_text(plan_dir)
    if not _looks_like_prerequisite_block(outcome, extra_text=latest_failure_text):
        return False
    if not spec.launch_preconditions:
        return False
    try:
        chain_spec.validate_launch_preconditions(spec, root, spec_path)
    except CliError as exc:
        writer(
            "[chain] prerequisite block revalidation did not pass; "
            f"keeping real block: {exc}\n"
        )
        return False

    reset_ids = _reset_stale_prerequisite_blocked_tasks(plan_dir, outcome)
    audit = {
        "schema": "arnold.megaplan.chain_precondition_revalidation.v1",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "plan": outcome.plan,
        "outcome_status": outcome.status,
        "outcome_reason": outcome.reason,
        "blocking_reasons": list(outcome.blocking_reasons),
        "chain_spec_path": str(spec_path),
        "reset_task_ids": reset_ids,
        "result": "launch_preconditions_satisfied_retrying_execute",
    }
    atomic_write_json(plan_dir / "chain_precondition_revalidation.json", audit)
    state_path = plan_dir / "state.json"
    try:
        state_payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        state_payload = {}
    if not isinstance(state_payload, dict):
        state_payload = {}
    state_payload["current_state"] = STATE_FINALIZED
    state_payload.pop("latest_failure", None)
    state_payload.pop("resume_cursor", None)
    state_payload.pop("active_step", None)
    meta = state_payload.setdefault("meta", {})
    if isinstance(meta, dict):
        entries = meta.setdefault("chain_precondition_revalidations", [])
        if isinstance(entries, list):
            entries.append(audit)
    from arnold_pipelines.megaplan._core.state import write_plan_state

    def _patch_revalidated_block(current: dict[str, Any]) -> bool:
        current.pop("latest_failure", None)
        current.pop("resume_cursor", None)
        current.pop("active_step", None)
        meta = current.setdefault("meta", {})
        if isinstance(meta, dict):
            entries = meta.setdefault("chain_precondition_revalidations", [])
            if isinstance(entries, list):
                entries.append(audit)
        return True

    write_plan_state(
        plan_dir,
        mode="patch-many",
        patch={"current_state": STATE_FINALIZED},
        mutation=_patch_revalidated_block,
    )
    writer(
        f"[chain] execute result=blocked for {outcome.plan}, but current launch "
        "preconditions now pass; cleared stale prerequisite block"
    )
    if reset_ids:
        writer(f" for tasks {', '.join(reset_ids)}")
    writer(f" ({reason}); retrying execute\n")
    return True


def _rearm_stale_execute_authority_divergence(
    plan_dir: Path,
    *,
    writer,
) -> bool:
    """Rearm a stale execute-authority block only after current corroboration.

    This is admission recovery for a repaired evidence reader, not a bypass:
    a live completion guard must now corroborate the whole finalized task
    universe before the old authority-divergence marker is cleared.
    """
    state_path = plan_dir / "state.json"
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    if payload.get("current_state") != STATE_BLOCKED or payload.get("active_step"):
        return False
    failure = payload.get("latest_failure")
    if not isinstance(failure, dict):
        return False
    if failure.get("kind") != "authority_divergence" or failure.get("phase") not in {None, "execute"}:
        return False
    message = failure.get("message")
    if not isinstance(message, str) or "execute terminal success lacks corroborated task completion" not in message:
        return False
    authoritative, reason = _latest_execution_batch_all_tasks_done(plan_dir)
    if not authoritative:
        return False

    from arnold_pipelines.megaplan._core.state import write_plan_state

    audit = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "reason": "chain admission revalidated stale execute terminal authority divergence",
        "authority_reason": reason,
    }

    def _patch_rearmed_authority_block(current: dict[str, Any]) -> bool:
        current.pop("latest_failure", None)
        current.pop("resume_cursor", None)
        current.pop("active_step", None)
        meta = current.setdefault("meta", {})
        if isinstance(meta, dict):
            entries = meta.setdefault("authority_divergence_recoveries", [])
            if isinstance(entries, list):
                entries.append(audit)
        return True

    write_plan_state(
        plan_dir,
        mode="patch-many",
        patch={"current_state": STATE_EXECUTED},
        mutation=_patch_rearmed_authority_block,
    )
    writer(
        "[chain] current execute authority now corroborates terminal finalize "
        "evidence; cleared stale authority-divergence block\n"
    )
    return True


def _rearm_fresh_session_execute_block(
    plan_dir: Path,
    *,
    writer,
) -> bool:
    """Reset a blocked execute plan back to finalized for a fresh-session retry.

    ``megaplan auto`` records execute quality/session failures as
    ``current_state=blocked`` with ``resume_cursor={phase: execute,
    retry_strategy: fresh_session}``. A later chain relaunch is the explicit
    signal to honor that cursor and try execute again, not to preserve the
    stale blocked state forever.
    """

    state_path = plan_dir / "state.json"
    try:
        state_payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(state_payload, dict):
        return False
    if state_payload.get("current_state") != STATE_BLOCKED:
        return False
    if state_payload.get("active_step"):
        return False
    resume_cursor = state_payload.get("resume_cursor")
    fresh_session_retry = (
        isinstance(resume_cursor, dict)
        and resume_cursor.get("phase") == "execute"
        and resume_cursor.get("retry_strategy") == "fresh_session"
    )
    latest_failure = state_payload.get("latest_failure")
    typed_deferred_validation_retry = (
        isinstance(resume_cursor, dict)
        and resume_cursor.get("phase") == "execute"
        and resume_cursor.get("retry_strategy") == "repair_validation_failure"
        and isinstance(latest_failure, dict)
        and latest_failure.get("kind") == "pre_dispatch_validation_failed"
        and latest_failure.get("phase") in {None, "execute"}
        and isinstance(latest_failure.get("metadata"), dict)
        and latest_failure["metadata"].get("worker_dispatched") is False
    )
    deferred_validation_retry = typed_deferred_validation_retry
    if not fresh_session_retry and not deferred_validation_retry:
        history = state_payload.get("history")
        latest_execute: Mapping[str, Any] | None = None
        if isinstance(history, list):
            for entry in reversed(history):
                if isinstance(entry, Mapping) and entry.get("step") == "execute":
                    latest_execute = entry
                    break
        message = latest_execute.get("message") if isinstance(latest_execute, Mapping) else None
        if (
            isinstance(latest_execute, Mapping)
            and latest_execute.get("result") == "error"
            and isinstance(message, str)
            and re.match(r"^validation job [^ ]+ exited \d+; expected one of \[", message)
        ):
            try:
                latest_batch = list_batch_artifacts(plan_dir)[-1]
                batch_payload = json.loads(latest_batch.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, IndexError):
                batch_payload = None
            if isinstance(batch_payload, Mapping):
                task_updates = batch_payload.get("task_updates")
                deferred_validation_retry = isinstance(task_updates, list) and any(
                    isinstance(update, Mapping)
                    and update.get("status") == "blocked"
                    and isinstance(update.get("task_id"), str)
                    and update["task_id"].strip()
                    for update in task_updates
                )
    if not fresh_session_retry and not deferred_validation_retry:
        return False
    if isinstance(latest_failure, dict):
        failure_phase = latest_failure.get("phase")
        failure_kind = latest_failure.get("kind")
        if isinstance(failure_phase, str) and failure_phase and failure_phase != "execute":
            return False
        if isinstance(failure_kind, str) and failure_kind not in {
            "execution_blocked",
            "tasks_blocked",
            "external_error",
            "quality_gate_circuit_open",
            "pre_dispatch_validation_failed",
        }:
            return False
    from arnold_pipelines.megaplan._core.state import write_plan_state

    recovery_event = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "reason": (
            "chain relaunch reopened deferred validation retry frontier"
            if deferred_validation_retry
            else "chain relaunch honored execute fresh_session resume cursor"
        ),
    }

    def _patch_blocked_execute(current: dict[str, Any]) -> bool:
        current.pop("latest_failure", None)
        current.pop("resume_cursor", None)
        current.pop("active_step", None)
        meta = current.setdefault("meta", {})
        if isinstance(meta, dict):
            entries = meta.setdefault("fresh_session_execute_recoveries", [])
            if isinstance(entries, list):
                entries.append(recovery_event)
        return True

    write_plan_state(
        plan_dir,
        mode="patch-many",
        patch={"current_state": STATE_FINALIZED},
        mutation=_patch_blocked_execute,
    )
    if deferred_validation_retry:
        writer(
            "[chain] deferred validation left a blocked task frontier; reset blocked "
            "plan back to finalized so execute can retry it\n"
        )
    else:
        writer(
            "[chain] execute block recorded a fresh-session retry; reset blocked plan "
            "back to finalized so execute can re-run\n"
        )
    return True


def _rearm_stale_terminal_execute_cursor_mismatch(
    plan_dir: Path,
    *,
    writer,
) -> bool:
    """Clear only a stale execute->review cursor wrapper after live authority."""
    state_path = plan_dir / "state.json"
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    if payload.get("current_state") != STATE_BLOCKED or payload.get("active_step"):
        return False
    failure = payload.get("latest_failure")
    if not isinstance(failure, dict):
        return False
    if failure.get("kind") != "workflow_cursor_mismatch" or failure.get("phase") != "execute":
        return False
    message = failure.get("message")
    if not isinstance(message, str) or (
        "workflow cursor from last_step expects one of [review]" not in message
        or "control projection offered [execute]" not in message
    ):
        return False
    authoritative, reason = _latest_execution_batch_all_tasks_done(plan_dir)
    if not authoritative:
        return False

    from arnold_pipelines.megaplan._core.state import write_plan_state

    audit = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "reason": "chain admission cleared stale execute-to-review cursor mismatch",
        "authority_reason": reason,
    }

    def _patch_rearmed_cursor(current: dict[str, Any]) -> bool:
        current.pop("latest_failure", None)
        current.pop("resume_cursor", None)
        current.pop("active_step", None)
        meta = current.setdefault("meta", {})
        if isinstance(meta, dict):
            entries = meta.setdefault("terminal_cursor_recoveries", [])
            if isinstance(entries, list):
                entries.append(audit)
        return True

    write_plan_state(
        plan_dir,
        mode="patch-many",
        patch={"current_state": STATE_EXECUTED},
        mutation=_patch_rearmed_cursor,
    )
    writer(
        "[chain] terminal execute authority now passes; cleared stale "
        "execute-to-review cursor mismatch\n"
    )
    return True


def _rearm_stale_incomplete_execute_cursor_mismatch(
    plan_dir: Path,
    *,
    writer,
) -> bool:
    """Reopen the specific cursor failure invalidated by current projection rules.

    A partial or blocked execute intentionally leaves the plan in ``finalized``
    so pending batches can be dispatched again.  Older workflow-backed drivers
    incorrectly promoted that incomplete history record into an execute->review
    cursor and then persisted ``workflow_cursor_mismatch``.  Once that record
    is present, ordinary chain admission stops before the corrected driver can
    observe it.  Reopen only the mechanically identifiable stale shape; a
    genuine cursor mismatch (a different cursor source, route, or outcome)
    remains blocked for repair.
    """

    state_path = plan_dir / "state.json"
    try:
        state_payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(state_payload, dict):
        return False
    if state_payload.get("current_state") != STATE_BLOCKED or state_payload.get("active_step"):
        return False
    latest_failure = state_payload.get("latest_failure")
    resume_cursor = state_payload.get("resume_cursor")
    if not isinstance(latest_failure, dict) or not isinstance(resume_cursor, dict):
        return False
    if latest_failure.get("kind") != "workflow_cursor_mismatch":
        return False
    if latest_failure.get("phase") != "execute":
        return False
    if resume_cursor.get("phase") != "execute":
        return False
    if resume_cursor.get("retry_strategy") != "repair_workflow_projection":
        return False
    metadata = latest_failure.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("observed_phase_source") != "last_step":
        return False
    message = latest_failure.get("message")
    if not isinstance(message, str) or "expects one of [review]" not in message or "offered [execute]" not in message:
        return False
    history = state_payload.get("history")
    last_entry = history[-1] if isinstance(history, list) and history else None
    if not isinstance(last_entry, dict):
        return False
    if last_entry.get("step") != "execute" or last_entry.get("result") not in {"blocked", "partial"}:
        return False

    from arnold_pipelines.megaplan._core.state import write_plan_state

    recovery_event = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "reason": "chain relaunch cleared stale incomplete-execute workflow cursor mismatch",
        "history_result": last_entry.get("result"),
    }

    def _patch_stale_cursor(current: dict[str, Any]) -> bool:
        current.pop("latest_failure", None)
        current.pop("resume_cursor", None)
        current.pop("active_step", None)
        meta = current.setdefault("meta", {})
        if isinstance(meta, dict):
            entries = meta.setdefault("workflow_cursor_recoveries", [])
            if isinstance(entries, list):
                entries.append(recovery_event)
        return True

    write_plan_state(
        plan_dir,
        mode="patch-many",
        patch={"current_state": STATE_FINALIZED},
        mutation=_patch_stale_cursor,
    )
    writer(
        "[chain] cleared stale incomplete-execute workflow cursor mismatch; "
        "reset plan to finalized so pending execute work can resume\n"
    )
    return True


def _drive_plan_with_blocked_execute_recovery(
    root: Path,
    spec_path: Path,
    plan: str,
    spec: ChainSpec,
    *,
    on_phase_complete: Callable[[str, int, str, str], None] | None = None,
    writer,
) -> DriverOutcome:
    _recover_failed_plan_before_drive(root, plan, writer=writer)
    # Done-first (grok consult, astrid/mega-main execute-reentry loop): when the
    # plan was operator-recovered (blocked -> finalized) but its finalize tasks
    # are ALL done + execution.json is complete, promote to executed BEFORE the
    # drive so the chain advances to review instead of re-entering execute.  The
    # previous order ran the done-check only AFTER a blocked drive, so a
    # recover-blocked plan re-entered execute every time and re-opened the
    # quality-gate circuit on stale artifacts — the mechanically-inevitable loop
    # that required manual adopt-execution to break.
    if _promote_done_plan_to_executed(root, plan, writer=writer):
        pass  # promoted (or already executed/done); drive below advances naturally
    outcome = _drive_plan(
        root,
        plan,
        spec,
        on_phase_complete=on_phase_complete,
        writer=writer,
    )
    if not _recover_blocked_execute_if_tasks_done(
        root,
        spec_path,
        spec,
        outcome,
        writer=writer,
    ):
        return outcome
    return _drive_plan(
        root,
        plan,
        spec,
        on_phase_complete=on_phase_complete,
        writer=writer,
    )


def _recover_failed_plan_before_drive(root: Path, plan: str, *, writer) -> None:
    """Let the plan recovery entrypoint clear failed state before chain auto-drive."""

    if _plan_current_state_from_payload(root, plan) != "failed":
        return
    writer(f"[chain] plan {plan} is failed; invoking resume before auto-drive\n")
    _run_command(
        root,
        [
            sys.executable,
            "-P",
            "-m",
            "arnold_pipelines.megaplan",
            "resume",
            "--plan",
            plan,
        ],
        writer=writer,
        error_code="plan_resume_failed",
    )


def _milestone_retry_cap(milestone: "MilestoneSpec | None", spec: ChainSpec) -> int:
    """Per-milestone FRESH-reinit cap.

    Default ``DEFAULT_MILESTONE_RETRY_CAP`` (2); CAPPED at
    ``APEX_EXTREME_RETRY_CAP`` (1) for apex profile or extreme robustness
    milestones to bound the cost of the most-expensive nodes.
    """
    profile = (milestone.profile if milestone else None) or None
    robustness = (
        milestone.robustness if milestone and milestone.robustness else spec.robustness
    ) or "standard"
    if profile == "apex" or robustness == "extreme":
        return APEX_EXTREME_RETRY_CAP
    return DEFAULT_MILESTONE_RETRY_CAP


def _resumable_retry_state(root: Path, plan: str | None) -> str | None:
    """Return a current_state that is safe to resume during a milestone retry."""

    if not plan:
        return None
    try:
        plan_dir = resolve_plan_dir(root, plan)
        raw = json.loads((plan_dir / "state.json").read_text(encoding="utf-8"))
    except (
        CliError,
        FileNotFoundError,
        json.JSONDecodeError,
        OSError,
        UnicodeDecodeError,
    ):
        return None
    if not isinstance(raw, dict):
        return None
    current_state = raw.get("current_state")
    if isinstance(current_state, str) and current_state in RESUMABLE_RETRY_STATES:
        return current_state
    return None


def _awaiting_human_can_retry(root: Path, plan: str | None) -> bool:
    """Return True when an awaiting-human plan is stale and should retry."""

    if not plan:
        return False
    try:
        plan_dir = resolve_plan_dir(root, plan)
        raw = json.loads((plan_dir / "state.json").read_text(encoding="utf-8"))
        finalize = json.loads((plan_dir / "finalize.json").read_text(encoding="utf-8"))
    except (
        CliError,
        FileNotFoundError,
        json.JSONDecodeError,
        OSError,
        UnicodeDecodeError,
    ):
        return False
    if not isinstance(raw, dict):
        return False
    current_state = raw.get("current_state")
    if current_state not in {STATE_AWAITING_HUMAN_VERIFY, STATE_FINALIZED}:
        return False
    if not isinstance(finalize, dict):
        return False
    user_actions = finalize.get("user_actions")
    if not isinstance(user_actions, list) or not user_actions:
        return False
    resolutions = effective_user_action_resolutions(plan_dir, raw)
    saw_retryable = False
    for action in user_actions:
        if not isinstance(action, dict):
            continue
        action_id = action.get("id")
        if not isinstance(action_id, str) or not action_id:
            continue
        resolution = resolutions.get(action_id)
        if not isinstance(resolution, dict):
            return False
        state = resolution.get("state") or resolution.get("resolution")
        if state == "satisfied":
            saw_retryable = True
            continue
        if state in {"accepted_blocked", "waived"}:
            saw_retryable = True
            continue
        return False
    return saw_retryable


def _plan_current_state_from_payload(root: Path, plan: str | None) -> str | None:
    raw = _plan_state_payload_from_name(root, plan)
    current_state = raw.get("current_state")
    if not isinstance(current_state, str):
        return None
    if current_state in {STATE_FINALIZED, STATE_EXECUTED, STATE_DONE} and _plan_has_live_active_step(raw):
        active_step = raw.get("active_step")
        active_phase = (
            active_step.get("phase") or active_step.get("step")
            if isinstance(active_step, Mapping)
            else None
        )
        if isinstance(active_phase, str) and active_phase.strip():
            return active_phase.strip()
    return current_state


def _plan_state_payload_from_name(root: Path, plan: str | None) -> dict[str, Any]:
    if not plan:
        return {}
    try:
        plan_dir = resolve_plan_dir(root, plan)
        from arnold_pipelines.megaplan._core.state import load_plan_from_dir

        _, raw = load_plan_from_dir(plan_dir)
    except (
        CliError,
        FileNotFoundError,
        json.JSONDecodeError,
        OSError,
        UnicodeDecodeError,
    ):
        return {}
    if not isinstance(raw, dict):
        return {}
    return raw


def _plan_has_live_active_step(plan_state: Mapping[str, Any]) -> bool:
    active_step = plan_state.get("active_step")
    return active_step_has_live_worker(active_step)


def _blocked_plan_replay_would_be_redundant(
    state: ChainState,
    *,
    plan_state: Mapping[str, Any],
    root: Path | None = None,
) -> bool:
    """Return whether a blocked plan has no safe retry frontier.

    Deferred validation failures are retryable across chain sessions. Keep
    every other durable block parked, but allow replay when the latest execute
    error names a validation job and the latest canonical batch artifact
    contains a blocked task update.
    """
    current_state = plan_state.get("current_state")
    if not isinstance(current_state, str):
        return False
    blocked_without_worker = (
        state.last_state == STATE_BLOCKED
        and current_state == STATE_BLOCKED
        and not _plan_has_live_active_step(plan_state)
    )
    if not blocked_without_worker:
        return False

    history = plan_state.get("history")
    latest_execute: Mapping[str, Any] | None = None
    if isinstance(history, list):
        for entry in reversed(history):
            if isinstance(entry, Mapping) and entry.get("step") == "execute":
                latest_execute = entry
                break
    if not isinstance(latest_execute, Mapping):
        return True
    if latest_execute.get("result") != "error":
        return True
    message = latest_execute.get("message")
    if not isinstance(message, str) or not re.match(
        r"^validation job [^ ]+ exited \d+; expected one of \[", message
    ):
        return True
    if root is None or not state.current_plan_name:
        return True
    try:
        plan_dir = resolve_plan_dir(root, state.current_plan_name)
        latest_batch = list_batch_artifacts(plan_dir)[-1]
        payload = json.loads(latest_batch.read_text(encoding="utf-8"))
    except (CliError, OSError, UnicodeDecodeError, json.JSONDecodeError, IndexError):
        return True
    if not isinstance(payload, Mapping):
        return True

    blocked_task_ids: list[str] = []
    task_id = payload.get("task_id") or payload.get("id")
    if payload.get("status") == "blocked" and isinstance(task_id, str) and task_id.strip():
        blocked_task_ids.append(task_id)
    task_updates = payload.get("task_updates")
    if isinstance(task_updates, list):
        blocked_task_ids.extend(
            update["task_id"]
            for update in task_updates
            if isinstance(update, Mapping)
            and update.get("status") == "blocked"
            and isinstance(update.get("task_id"), str)
            and update["task_id"].strip()
        )
    return not blocked_task_ids


def _chain_policy_milestone_label(plan_state: dict[str, Any]) -> str | None:
    meta = plan_state.get("meta")
    if not isinstance(meta, dict):
        return None
    policy = meta.get("chain_policy")
    if not isinstance(policy, dict):
        return None
    label = policy.get("milestone_label")
    return label if isinstance(label, str) and label else None


def _record_pr_number(record: dict[str, Any] | None) -> int | None:
    if not isinstance(record, dict):
        return None
    raw = record.get("pr_number")
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _completed_prefix_index(spec: ChainSpec, completed_labels: set[str]) -> int:
    for index, milestone in enumerate(spec.milestones):
        if milestone.label not in completed_labels:
            return index
    return len(spec.milestones)


def _append_reconciliation_audit(
    state: ChainState,
    *,
    plan_name: str | None,
    plan_state: dict[str, Any],
    pr_number: int | None,
    pr_state: str | None,
) -> None:
    current_state = plan_state.get("current_state")
    if not isinstance(current_state, str):
        current_state = None
    state.metadata["ground_truth_reconciliation"] = {
        "reconciled_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "plan": plan_name,
        "current_state": current_state,
        "latest_failure": plan_state.get("latest_failure"),
        "last_gate": plan_state.get("last_gate"),
        "active_step": plan_state.get("active_step"),
        "pr_number": pr_number,
        "pr_state": pr_state,
    }


def _clear_impossible_terminal_last_state(
    state: ChainState,
    *,
    writer,
    reason: str,
) -> None:
    """Clear a terminal-looking chain state when an active plan still exists."""

    if state.last_state not in {"done", "complete"}:
        return
    if not state.current_plan_name:
        return
    writer(
        f"[chain] cleared stale terminal last_state for {state.current_plan_name}: "
        f"{state.last_state} -> unknown ({reason})\n"
    )
    state.last_state = "unknown"


def _mark_chain_after_milestone_advance(
    spec: ChainSpec,
    state: ChainState,
    *,
    next_index: int,
) -> None:
    state.current_milestone_index = next_index
    state.current_plan_name = None
    state.last_state = "done" if next_index >= len(spec.milestones) else "between_milestones"
    state.pr_number = None
    state.pr_state = None


def _reconcile_chain_from_ground_truth(
    root: Path,
    spec_path: Path,
    spec: ChainSpec,
    state: ChainState,
    *,
    writer,
    push_enabled: bool = True,
) -> ChainState:
    """Derive the chain cursor from plan state.json and live GitHub PR state."""

    from arnold_pipelines.megaplan.chain.execution_binding import (
        assert_execution_binding,
    )

    assert_execution_binding(
        spec_path,
        state,
        operation="chain reconciliation",
        allow_unbound_new=True,
    )

    # T17 — In atomic/enforce mode reconciliation must NEVER derive completion
    # authority (cursor advancement, ``last_state = "done"``, completed-record
    # rebuild from live PR state, cursor/last_state sync from plan state.json)
    # from a ground-truth projection. Only an accepted acceptance transaction
    # committed through the CAS-backed helper can advance the completion cursor.
    # We short-circuit here so the projection cannot masquerade as authority,
    # while still persisting an audit trail of the reconciliation attempt.
    fail_closed, fc_reason = _reconciliation_fail_closed(state)
    if fail_closed:
        writer(
            f"[chain] reconciliation skipped in atomic mode for "
            f"{state.current_plan_name or 'current milestone'}: {fc_reason}\n"
        )
        _append_reconciliation_audit(
            state,
            plan_name=state.current_plan_name,
            plan_state={},
            pr_number=state.pr_number,
            pr_state=state.pr_state,
        )
        chain_spec.save_chain_state(spec_path, state)
        return state

    labels_to_index = {
        milestone.label: index for index, milestone in enumerate(spec.milestones)
    }
    completed_by_label = _completed_records_by_label(state)
    reconciled_completed: list[dict[str, Any]] = []
    removed_completed: dict[str, dict[str, Any]] = {}
    current_plan_from_removed_completion = False

    for milestone in spec.milestones:
        record = completed_by_label.get(milestone.label)
        if not isinstance(record, dict):
            continue
        record = dict(record)
        pr_number = _record_pr_number(record)
        if push_enabled and milestone.branch:
            if pr_number is None:
                accepted, accepted_reason = _revalidate_local_no_push_completed_record(
                    root, state, record
                )
                if not accepted:
                    writer(
                        f"[chain] completed record for {milestone.label} is not "
                        "authoritative yet: branch milestone is missing PR context "
                        f"and local/no-push revalidation failed: {accepted_reason}\n"
                    )
                    removed_completed[milestone.label] = dict(record)
                    continue
                writer(
                    f"[chain] preserved accepted local/no-push completion for "
                    f"{milestone.label}: {accepted_reason}\n"
                )
                reconciled_completed.append(record)
                continue
            live_pr_state = _pr_state(root, pr_number, writer=writer)
            if record.get("pr_state") != live_pr_state:
                writer(
                    f"[chain] reconciled completed PR state for {milestone.label} "
                    f"#{pr_number}: {record.get('pr_state') or 'unknown'} -> "
                    f"{live_pr_state}\n"
                )
            record["pr_state"] = live_pr_state
            if live_pr_state != "merged":
                writer(
                    f"[chain] completed record for {milestone.label} is not "
                    f"authoritative yet: PR #{pr_number} state={live_pr_state}\n"
                )
                removed = dict(record)
                removed["pr_state"] = live_pr_state
                removed_completed[milestone.label] = removed
                continue
        reconciled_completed.append(record)

    if reconciled_completed != state.completed:
        state.completed = reconciled_completed

    completed_labels = {
        record.get("label")
        for record in state.completed
        if isinstance(record, dict) and isinstance(record.get("label"), str)
    }
    first_incomplete = _completed_prefix_index(spec, completed_labels)
    if state.current_milestone_index < first_incomplete:
        writer(
            f"[chain] reconciled cursor index: {state.current_milestone_index} "
            f"-> {first_incomplete} from completed milestones\n"
        )
        state.current_milestone_index = first_incomplete
        if first_incomplete >= len(spec.milestones):
            state.current_plan_name = None
            state.pr_number = None
            state.pr_state = None
            state.last_state = "done"
    elif state.current_milestone_index > first_incomplete:
        writer(
            f"[chain] reconciled cursor index: {state.current_milestone_index} "
            f"-> {first_incomplete} from completed milestones\n"
        )
        state.current_milestone_index = first_incomplete
        if first_incomplete < len(spec.milestones):
            milestone = spec.milestones[first_incomplete]
            removed = removed_completed.get(milestone.label)
            plan = removed.get("plan") if isinstance(removed, dict) else None
            state.current_plan_name = plan if isinstance(plan, str) and plan else None
            state.pr_number = _record_pr_number(removed)
            pr_state = removed.get("pr_state") if isinstance(removed, dict) else None
            state.pr_state = pr_state if isinstance(pr_state, str) else None
            state.last_state = "authority_divergence"
            current_plan_from_removed_completion = state.current_plan_name is not None
        else:
            state.current_plan_name = None
            state.pr_number = None
            state.pr_state = None

    plan_name = state.current_plan_name
    plan_state = _plan_state_payload_from_name(root, plan_name)
    if plan_state:
        label = _chain_policy_milestone_label(plan_state)
        plan_index = labels_to_index.get(label) if label is not None else None
        if plan_index is not None and state.current_milestone_index != plan_index:
            writer(
                f"[chain] reconciled cursor index from plan {plan_name}: "
                f"{state.current_milestone_index} -> {plan_index}\n"
            )
            state.current_milestone_index = plan_index
        current_state = plan_state.get("current_state")
        preserve_pr_cursor = (
            state.last_state in {STATE_AWAITING_PR_MERGE, "pr_closed"}
            and state.pr_number is not None
        )
        if (
            isinstance(current_state, str)
            and state.last_state != current_state
            and not current_plan_from_removed_completion
            and not preserve_pr_cursor
        ):
            writer(
                f"[chain] synced last_state for {plan_name}: "
                f"{state.last_state or 'unknown'} -> {current_state}\n"
            )
            state.last_state = current_state
    elif plan_name:
        _clear_impossible_terminal_last_state(
            state,
            writer=writer,
            reason="active plan state unavailable during ground-truth reconciliation",
        )

    active_index = state.current_milestone_index
    active_milestone = (
        spec.milestones[active_index]
        if 0 <= active_index < len(spec.milestones)
        else None
    )
    active_uses_pr = bool(
        push_enabled and active_milestone is not None and active_milestone.branch
    )
    live_active_pr_state: str | None = None
    if (
        active_uses_pr
        and state.pr_number is not None
        and state.last_state != "pr_closed"
    ):
        live_active_pr_state = _pr_state(root, state.pr_number, writer=writer)
        if state.pr_state == "merged" and live_active_pr_state != "merged":
            writer(
                f"[chain] preserved recorded merged PR state for "
                f"{active_milestone.label if active_milestone else 'milestone'} "
                f"#{state.pr_number} despite live state {live_active_pr_state}\n"
            )
            live_active_pr_state = "merged"
        elif state.pr_state != live_active_pr_state:
            writer(
                f"[chain] reconciled live PR state for "
                f"{active_milestone.label if active_milestone else 'milestone'} "
                f"#{state.pr_number}: {state.pr_state or 'unknown'} -> "
                f"{live_active_pr_state}\n"
            )
        state.pr_state = live_active_pr_state

    current_plan_state = plan_state.get("current_state") if plan_state else None
    if (
        bool(plan_name)
        and active_milestone is not None
        and current_plan_state == STATE_DONE
        and active_milestone.label not in completed_labels
        and (
            not active_uses_pr
            or (state.pr_number is not None and live_active_pr_state == "merged")
        )
    ):
        appended, reason = _append_reconciled_completed_record_with_guard(
            root,
            state,
            spec_path=spec_path,
            plan_name=plan_name,
            milestone=active_milestone,
            pr_number=state.pr_number if active_uses_pr else None,
            pr_state="merged" if active_uses_pr else None,
            completion_reason="terminal plan state reconciled from ground truth",
            writer=writer,
        )
        if appended:
            completed_labels.add(active_milestone.label)
        else:
            writer(
                f"[chain] reconciliation completion guard blocked "
                f"{active_milestone.label}: {reason}\n"
            )

    reviewed_finalized_plan = (
        bool(plan_name)
        and bool(plan_state)
        and _finalized_plan_has_successful_review(plan_state)
    )
    if reviewed_finalized_plan and active_milestone is not None:
        if active_uses_pr and state.pr_number is not None:
            if live_active_pr_state == "open" and state.last_state != STATE_AWAITING_PR_MERGE:
                writer(
                    f"[chain] plan {plan_name} is finalized with successful review but PR "
                    f"#{state.pr_number} is open; waiting for merge\n"
                )
                state.last_state = STATE_AWAITING_PR_MERGE
            elif (
                live_active_pr_state == "merged"
                and active_milestone.label not in completed_labels
            ):
                appended, reason = _append_reconciled_completed_record_with_guard(
                    root,
                    state,
                    spec_path=spec_path,
                    plan_name=plan_name,
                    milestone=active_milestone,
                    pr_number=state.pr_number,
                    pr_state="merged",
                    completion_reason="reviewed finalized plan with merged PR",
                    writer=writer,
                )
                if appended:
                    completed_labels.add(active_milestone.label)
                else:
                    writer(
                        f"[chain] reconciliation completion guard blocked "
                        f"{active_milestone.label}: {reason}\n"
                    )
        elif not active_uses_pr and active_milestone.label not in completed_labels:
            appended, reason = _append_reconciled_completed_record_with_guard(
                root,
                state,
                spec_path=spec_path,
                plan_name=plan_name,
                milestone=active_milestone,
                pr_number=None,
                pr_state=None,
                completion_reason="reviewed finalized local plan",
                writer=writer,
            )
            if appended:
                completed_labels.add(active_milestone.label)
            else:
                writer(
                    f"[chain] reconciliation completion guard blocked "
                    f"{active_milestone.label}: {reason}\n"
                )
    if (
        active_uses_pr
        and state.pr_number is not None
        and current_plan_state == STATE_DONE
        and live_active_pr_state == "open"
        and state.last_state != STATE_AWAITING_PR_MERGE
    ):
        writer(
            f"[chain] plan {plan_name} is {current_plan_state} but PR "
            f"#{state.pr_number} is open; waiting for merge\n"
        )
        state.last_state = STATE_AWAITING_PR_MERGE

    if active_milestone is not None and active_milestone.label in completed_labels:
        next_index = _completed_prefix_index(spec, completed_labels)
        if next_index != state.current_milestone_index:
            writer(
                f"[chain] reconciled cursor past completed milestone "
                f"{active_milestone.label}: {state.current_milestone_index} "
                f"-> {next_index}\n"
            )
            state.current_milestone_index = next_index
            state.current_plan_name = None
            state.pr_number = None
            state.pr_state = None
            if next_index >= len(spec.milestones):
                state.last_state = "done"
            else:
                state.last_state = "between_milestones"

    _append_reconciliation_audit(
        state,
        plan_name=plan_name,
        plan_state=plan_state,
        pr_number=state.pr_number,
        pr_state=state.pr_state,
    )
    chain_spec.save_chain_state(spec_path, state)
    return state


def _sync_chain_last_state_from_plan(
    root: Path,
    spec_path: Path,
    state: ChainState,
    *,
    writer,
) -> ChainState:
    """Refresh chain.last_state from the current plan's authoritative state.json."""

    plan_name = state.current_plan_name
    if not plan_name:
        return state
    plan_state = _plan_current_state_from_payload(root, plan_name)
    if not plan_state:
        previous = state.last_state
        _clear_impossible_terminal_last_state(
            state,
            writer=writer,
            reason="active plan state unavailable while syncing chain last_state",
        )
        if state.last_state != previous:
            chain_spec.save_chain_state(spec_path, state)
        return state
    if plan_state == state.last_state:
        return state
    # Preserve a recorded authority divergence: when the plan reports a
    # terminal state but its tasks lack corroborated completion, syncing
    # last_state to the plan's naive terminal value would erase the repair
    # seam (the divergence + rerun cursor) that recover-blocked/execute
    # re-dispatch depends on.  Re-verify task authority before overwriting.
    if state.last_state == "authority_divergence" and plan_state == "done":
        from arnold_pipelines.megaplan.chain import _plan_terminal_completion_is_authoritative

        authoritative, _ = _plan_terminal_completion_is_authoritative(root, plan_name)
        if not authoritative:
            return state
    previous = state.last_state
    state.last_state = plan_state
    writer(
        f"[chain] synced last_state for {plan_name}: "
        f"{previous or 'unknown'} -> {plan_state}\n"
    )
    chain_spec.save_chain_state(spec_path, state)
    return state


def _record_chain_last_state_after_plan_run(
    root: Path,
    spec_path: Path,
    state: ChainState,
    outcome: DriverOutcome,
    *,
    writer,
) -> ChainState:
    """Persist the chain cursor, then reconcile it from live plan state.json."""

    state.last_state = outcome.status
    chain_spec.save_chain_state(spec_path, state)
    return _sync_chain_last_state_from_plan(root, spec_path, state, writer=writer)


def _resolve_idea_path(root: Path, idea: str) -> Path:
    idea_path = Path(idea).expanduser()
    if idea_path.is_absolute():
        return idea_path
    return root / idea_path


def _plan_artifact_paths_for_milestone(
    root: Path,
    plan_name: str,
    milestone: MilestoneSpec,
) -> list[Path]:
    plan_dir = root / ".megaplan" / "plans" / plan_name
    artifacts = [
        plan_dir / "final.md",
        plan_dir / "finalize.json",
        plan_dir / "state.json",
        plan_dir / "contract.json",
    ]
    idea_path = _resolve_idea_path(root, milestone.idea)
    if idea_path.exists():
        resolved_idea = idea_path.resolve()
        root_resolved = root.resolve()
        if resolved_idea.is_relative_to(root_resolved):
            artifacts.append(idea_path)
        else:
            idea_copy = plan_dir / "idea.md"
            idea_copy.parent.mkdir(parents=True, exist_ok=True)
            new_content = resolved_idea.read_bytes()
            if not idea_copy.exists() or idea_copy.read_bytes() != new_content:
                idea_copy.write_bytes(new_content)
            artifacts.append(idea_copy)
    return artifacts


def _milestone_uses_omp_backend(milestone: "MilestoneSpec") -> str | None:
    for entry in milestone.phase_model or []:
        if "=" not in entry:
            continue
        phase_step, spec = entry.split("=", 1)
        if spec.strip().startswith("omp:") or spec.strip() == "omp":
            return phase_step
    if milestone.with_prep:
        return "prep"
    return None


def _preflight_agent_backends(
    spec: "ChainSpec",
    *,
    writer,
    current_milestone_index: int | None = None,
) -> None:
    # A resumed chain must only preflight the milestone it is about to run.
    # Completed milestones may legitimately reference an optional backend that
    # is no longer installed; scanning the whole historical spec would block
    # seed creation before the active milestone can be dispatched.
    milestones = spec.milestones
    if current_milestone_index is not None:
        if 0 <= current_milestone_index < len(spec.milestones):
            milestones = (spec.milestones[current_milestone_index],)
        elif current_milestone_index < 0 and spec.milestones:
            milestones = (spec.milestones[0],)
        else:
            milestones = ()
    offenders: list[tuple[str, str]] = []
    for milestone in milestones:
        phase = _milestone_uses_omp_backend(milestone)
        if phase is not None:
            offenders.append((milestone.label, phase))
    if not offenders:
        return

    from arnold_pipelines.megaplan.workers import _is_agent_available

    if _is_agent_available("omp"):
        return
    names = ", ".join(f"{label}:{phase}" for label, phase in offenders)
    raise CliError(
        "agent_deps_missing",
        "Chain requires the omp/agent backend for "
        f"{names}, but it is not importable. Install with `uv pip install -e '.[agent]'`.",
    )


def _journal_production_ladder(
    spec_path: Path | None,
    root: Path | None,
    state: ChainState,
    *,
    intent_kind: str,
    label: str,
) -> None:
    if spec_path is None or root is None:
        return
    from arnold_pipelines.megaplan.incident.chain_control import apply_chain_lifecycle, cas_chain_state_effect

    apply_chain_lifecycle(
        spec_path,
        root,
        intent_kind=intent_kind,
        actor={"id": "chain", "class": "system"},
        expected_revision=(state.metadata or {}).get("_nbf08_revision"),
        effect=lambda txn: {
            **cas_chain_state_effect(txn, spec_path, state.to_dict()),
            "label": label,
        },
    )


def _apply_ladder_action(
    action: str,
    *,
    milestone: "MilestoneSpec | None",
    state: ChainState,
    spec: ChainSpec,
    writer,
    spec_path: Path | None = None,
    root: Path | None = None,
) -> str:
    """Translate a single ladder action into a chain decision.

    Returns one of "advance"/"stop"/"retry"/"skip". For the bump actions the
    escalated tier is persisted into ``state.*_bumps`` keyed by milestone label
    so the next FRESH re-init picks it up, then the milestone is retried once.
    ``bump_profile`` at apex (the top tier) is a no-op + warning that falls
    through to ``stop`` since there is nothing left to escalate.
    """
    label = milestone.label if milestone else "seed"
    if action == "stop_chain":
        return "stop"
    if action == "skip_milestone":
        _journal_production_ladder(spec_path, root, state, intent_kind="skip", label=label)
        return "skip"
    if action in ("retry_milestone", "resume_milestone"):
        _journal_production_ladder(spec_path, root, state, intent_kind="retry", label=label)
        return "retry"
    if action == "bump_profile":
        current = state.profile_bumps.get(label) or (
            milestone.profile if milestone else None
        )
        nxt, bumped = chain_spec._bump_one_tier(current, PROFILE_BUMP_ORDER)
        if not bumped:
            writer(
                f"[chain] {label}: bump_profile requested but already at top tier "
                f"({current or 'apex'}); no tier above apex — stopping\n"
            )
            return "stop"
        state.profile_bumps[label] = nxt or ""
        # Couple a depth bump so a harder retry also thinks deeper.
        cur_depth = state.depth_bumps.get(label) or (
            milestone.depth if milestone else None
        )
        d_next, d_bumped = chain_spec._bump_one_tier(cur_depth, DEPTH_BUMP_ORDER)
        if d_bumped and d_next:
            state.depth_bumps[label] = d_next
        writer(f"[chain] {label}: bumping profile → {nxt}; retrying once\n")
        return "retry"
    if action == "bump_robustness":
        current = state.robustness_bumps.get(label) or (
            (
                milestone.robustness
                if milestone and milestone.robustness
                else spec.robustness
            )
        )
        nxt, bumped = chain_spec._bump_one_tier(current, ROBUSTNESS_BUMP_ORDER)
        if not bumped:
            writer(
                f"[chain] {label}: bump_robustness requested but already at top tier "
                f"({current or 'extreme'}); stopping\n"
            )
            return "stop"
        state.robustness_bumps[label] = nxt or ""
        writer(f"[chain] {label}: bumping robustness → {nxt}; retrying once\n")
        return "retry"
    return "stop"


def _handle_outcome(
    outcome: DriverOutcome,
    *,
    spec: ChainSpec,
    writer,
    milestone: "MilestoneSpec | None" = None,
    state: ChainState | None = None,
    root: Path | None = None,
    spec_path: Path | None = None,
) -> str:
    """Decide the next action given a DriverOutcome, walking the ladder.

    Returns one of: "advance" (move to next milestone), "stop" (chain halts),
    "retry" (re-run the same milestone FRESH), "skip" (advance without waiting),
    "authority_blocked" (terminal claim was not corroborated).

    On a failure/escalate outcome the structured ladder is walked with a
    BOUNDED, persisted per-milestone retry counter:

      retry_milestone (up to cap; 1 for apex/extreme) →
      bump_profile / bump_robustness (once) →
      abort (stop_chain by default).

    The counter is keyed by milestone label in ``state`` so it survives resume
    and CANNOT loop forever on a deterministic failure.
    """
    status = outcome.status
    if status == "finalized":
        writer(
            f"[chain] plan {outcome.plan} is finalized but not executed; "
            "stopping before PR progression\n"
        )
        return "stop"
    if status == "done":
        if root is not None:
            authoritative, reason = _plan_terminal_completion_is_authoritative(
                root, outcome.plan
            )
            if not authoritative:
                writer(
                    f"[chain] plan {outcome.plan} outcome={status} lacks task authority: "
                    f"{reason}\n"
                )
                return "authority_blocked"
        return "advance"
    if status == "awaiting_human":
        if root is not None and _awaiting_human_can_retry(root, outcome.plan):
            writer(
                f"[chain] plan {outcome.plan} reported awaiting_human, but all user-action "
                "resolutions allow resume; retrying milestone\n"
            )
            policy = spec.on_failure_policy
        else:
            writer(
                f"[chain] plan {outcome.plan} paused awaiting human action: "
                f"{outcome.reason}\n"
            )
            return "stop"
    if status == "infrastructure_error":
        writer(
            f"[chain] plan {outcome.plan} stopped on infrastructure error: "
            f"{outcome.reason}\n"
        )
        return "stop"
    outcome_reason_lower = outcome.reason.lower()
    if (
        status == "blocked"
        and "prerequisite-blocked" in outcome_reason_lower
        and (
            "not satisfied" in outcome_reason_lower
            or "settled" in outcome_reason_lower
        )
    ):
        writer(
            f"[chain] plan {outcome.plan} stopped on unresolved explicit blocker: "
            f"{outcome.reason}\n"
        )
        return "stop"
    if status in ("aborted", "escalated"):
        if status == "aborted":
            writer(f"[chain] plan {outcome.plan} ended aborted\n")
        else:
            writer(
                f"[chain] plan {outcome.plan} escalated — applying on_escalate policy\n"
            )
        policy = spec.on_escalate_policy
    else:
        # failed, stalled, cap, awaiting_human, blocked, … → treat as failure
        writer(f"[chain] plan {outcome.plan} ended {status}: {outcome.reason}\n")
        policy = spec.on_failure_policy

    # No state to track the counter (e.g. legacy seed path) → honor abort only.
    if state is None:
        action = policy.retry or policy.escalate or policy.abort
        if action in ("retry_milestone", "resume_milestone"):
            # Without a counter a bare retry is unsafe; degrade to abort.
            action = policy.abort
        return _apply_ladder_action(
            action,
            milestone=milestone,
            state=ChainState(),
            spec=spec,
            writer=writer,
            spec_path=spec_path,
            root=root,
        )

    label = milestone.label if milestone else "seed"
    stage = state.ladder_stage.get(label, "retry")

    if stage == "retry" and policy.retry in ("retry_milestone", "resume_milestone"):
        cap = _milestone_retry_cap(milestone, spec)
        spent = state.retry_counts.get(label, 0)
        if spent < cap:
            state.retry_counts[label] = spent + 1
            writer(f"[chain] {label}: retry {spent + 1}/{cap}\n")
            return "retry"
        # Retries exhausted → climb to the bump rung.
        writer(f"[chain] {label}: retries exhausted ({spent}/{cap})\n")
        state.ladder_stage[label] = "bump"
        stage = "bump"

    if stage in ("retry", "bump") and policy.escalate:
        # Take the escalate rung once, then mark terminal so the next failure
        # aborts (no infinite bump loop).
        state.ladder_stage[label] = "terminal"
        decision = _apply_ladder_action(
            policy.escalate,
            milestone=milestone,
            state=state,
            spec=spec,
            writer=writer,
            spec_path=spec_path,
            root=root,
        )
        if decision == "retry":
            # Reset the retry counter so the post-bump run gets a fresh re-init
            # but the ladder will not re-enter the retry rung (stage=terminal).
            return "retry"
        return decision

    # No retry/escalate rungs left (or already terminal) → abort action.
    return _apply_ladder_action(
        policy.abort,
        milestone=milestone,
        state=state,
        spec=spec,
        writer=writer,
        spec_path=spec_path,
        root=root,
    )


def _carried_wip_paths(root: Path) -> list[Path]:
    """Dirty worktree paths that are NOT megaplan's own ``.megaplan/`` artifacts.

    These represent carried working-state (the recurring carried-WIP review
    false-positive class). ``.megaplan/`` runtime artifacts are expected to be
    dirty mid-chain and never count as a dirty base.
    """
    carried: list[Path] = []
    for path in _dirty_worktree_paths(root):
        try:
            rel = path.resolve().relative_to(root.resolve()).as_posix()
        except (OSError, ValueError):
            rel = path.as_posix()
        if rel.startswith(".megaplan/") or rel == ".megaplan":
            continue
        carried.append(path)
    return carried


def _assert_clean_base(
    root: Path,
    milestone: "MilestoneSpec",
    *,
    no_push: bool,
    writer,
) -> None:
    """Assert the working base is a clean fork off main (no carried WIP).

    With ``driver.require_clean_base: true`` this runs before each milestone's
    plan init. Carried WIP (non-``.megaplan/`` dirty paths) is the documented
    source of the review false-positive halt class. We auto-clean by stashing
    when running locally (``--no-push`` / no-network), and fail loud otherwise
    so a CI/orchestrator run never silently discards real work.
    """
    carried = _carried_wip_paths(root)
    if not carried:
        return
    sample = ", ".join(p.name for p in carried[:5])
    if no_push:
        # Local/no-network: auto-clean by stashing the carried WIP.
        writer(
            f"[chain] require_clean_base: {milestone.label} base has carried WIP "
            f"({sample}); auto-stashing before init\n"
        )
        proc = subprocess.run(
            [
                "git",
                "stash",
                "push",
                "--include-untracked",
                "-m",
                f"megaplan-chain require_clean_base {milestone.label}",
            ],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        if proc.returncode != 0:
            raise CliError(
                "unclean_base",
                f"require_clean_base: failed to auto-clean carried WIP for "
                f"{milestone.label}: {proc.stderr.strip() or proc.stdout.strip()}",
            )
        remaining = _carried_wip_paths(root)
        if remaining:
            raise CliError(
                "unclean_base",
                f"require_clean_base: carried WIP persists after auto-clean for "
                f"{milestone.label}: {', '.join(p.name for p in remaining[:5])}",
            )
        return
    raise CliError(
        "unclean_base",
        f"require_clean_base: milestone {milestone.label} cannot start — the "
        f"working base carries uncommitted WIP ({sample}). Commit, stash, or run "
        f"off a clean fork of {root.name}.",
    )


def _preserve_carried_wip_before_retry(
    root: Path,
    spec_path: Path,
    state: ChainState,
    milestone: "MilestoneSpec",
    plan_name: str | None,
    *,
    writer,
) -> None:
    """Stash abandoned attempt WIP before re-initializing a milestone retry.

    This runs only when the chain has decided the current plan is not resumable
    and will force a fresh init. Without preserving the failed attempt's working
    tree, the next ``require_clean_base`` check reports the abandoned WIP as the
    root failure and hides the original blocker.
    """
    carried = _carried_wip_paths(root)
    if not carried:
        return

    sample = ", ".join(p.name for p in carried[:5])
    message = (
        f"megaplan-chain retry-preserve {milestone.label}"
        + (f" plan={plan_name}" if plan_name else "")
    )
    writer(
        f"[chain] retry for {milestone.label} would re-init over carried WIP "
        f"({sample}); preserving via git stash before retry\n"
    )
    proc = subprocess.run(
        ["git", "stash", "push", "--include-untracked", "-m", message],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if proc.returncode != 0:
        raise CliError(
            "retry_preserve_failed",
            "retry could not preserve carried WIP before re-init for "
            f"{milestone.label}: {proc.stderr.strip() or proc.stdout.strip()}",
        )

    stash_proc = subprocess.run(
        ["git", "stash", "list", "--format=%gd", "-n", "1"],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if stash_proc.returncode != 0:
        raise CliError(
            "retry_preserve_failed",
            "retry preserved carried WIP but could not resolve the stash ref: "
            f"{stash_proc.stderr.strip() or stash_proc.stdout.strip()}",
        )
    stash_ref = stash_proc.stdout.strip()
    metadata = state.metadata.setdefault("retry_preserved_wip", [])
    if isinstance(metadata, list):
        metadata.append(
            {
                "milestone": milestone.label,
                "plan": plan_name,
                "stash_ref": stash_ref,
                "sample_paths": [p.as_posix() for p in carried[:20]],
            }
        )
    chain_spec.save_chain_state(spec_path, state)


def _maybe_file_ladder_ticket(
    root: Path,
    spec_path: Path,
    milestone: "MilestoneSpec",
    outcome: DriverOutcome,
    state: ChainState,
    *,
    writer,
) -> None:
    """Auto-file a megaplan ticket when a milestone halts after exhausting the
    autonomy ladder. Best-effort + fail-open: a ticketing failure never changes
    the chain outcome (the chain is already stopping)."""
    if state.ladder_stage.get(milestone.label) != "terminal":
        # Only file when the ladder was actually walked to exhaustion.
        return
    try:
        ticket = {
            "kind": "chain_ladder_exhaustion",
            "milestone": milestone.label,
            "plan": outcome.plan,
            "status": outcome.status,
            "reason": outcome.reason,
            "retries": state.retry_counts.get(milestone.label, 0),
            "profile_bump": state.profile_bumps.get(milestone.label),
            "robustness_bump": state.robustness_bumps.get(milestone.label),
            "needs": "human attention — milestone halted after retry+bump ladder",
        }
        ticket_dir = chain_spec._state_path_for(spec_path).parent / "tickets"
        ticket_dir.mkdir(parents=True, exist_ok=True)
        ticket_path = ticket_dir / f"{milestone.label}-ladder-exhaustion.json"
        ticket_path.write_text(json.dumps(ticket, indent=2) + "\n", encoding="utf-8")
        writer(
            f"[chain] filed ladder-exhaustion ticket for {milestone.label} "
            f"at {ticket_path}\n"
        )
    except Exception as exc:  # fail-open
        writer(
            f"[chain] note: could not auto-file ladder ticket for "
            f"{milestone.label}: {exc}\n"
        )


def _soft_git(root: Path, *args: str) -> str | None:
    """Run git and return stdout, or ``None`` on ANY failure.

    Used by controller-side skip detection where a hard failure must degrade
    to ``uncertain`` (PR required) instead of raising — a silent no-op is
    never emitted from incomplete information.
    """

    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def _changed_paths_for_commit(root: Path, sha: str) -> list[str]:
    """Return the paths a commit touched (name-only, no renames resolved)."""

    out = _soft_git(root, "diff-tree", "--no-commit-id", "--name-only", "-r", sha)
    if not out:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def _promoted_refs(
    manifest: Mapping[str, Any] | None,
    *,
    manifest_path: Path | None = None,
) -> list[str] | None:
    """Collect promotion evidence SHAs: ``manifest.promotions`` plus the
    ``promotion-journal.jsonl`` sibling of the bound manifest.

    Returns ``None`` when the promotion journal exists but cannot be read
    (uncertain => PR required).  An empty list means "no promotion evidence"
    — the caller treats engine changes without promotion as PR-required.
    """

    refs: list[str] = []
    if isinstance(manifest, Mapping):
        indirection = manifest.get("indirection")
        if isinstance(indirection, Mapping):
            verified_head = indirection.get("verified_head")
            if isinstance(verified_head, str) and verified_head.strip():
                refs.append(verified_head.strip())
        promotions = manifest.get("promotions")
        if isinstance(promotions, list):
            for entry in promotions:
                if not isinstance(entry, Mapping):
                    continue
                for key in ("previous_commit", "from_sha", "to_sha"):
                    value = entry.get(key)
                    if isinstance(value, str) and value.strip():
                        refs.append(value.strip())
    journal: Path | None = None
    if manifest_path is not None:
        candidate = Path(manifest_path).parent / "promotion-journal.jsonl"
        if candidate.exists():
            journal = candidate
    if journal is not None:
        try:
            lines = journal.read_text(encoding="utf-8").splitlines()
        except OSError:
            return None
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            for key in ("from_sha", "to_sha", "previous_commit"):
                value = record.get(key)
                if isinstance(value, str) and value.strip():
                    refs.append(value.strip())
    return refs


def _reconcile_scope_manifest(
    manifest_path: Path | None, *, milestone_label: str
) -> Mapping[str, Any] | None:
    """Load the bound session runtime manifest for reconcile skip detection.

    Distinguishes ABSENT from INVALID (T-0024).  A ``None`` path or a
    genuinely never-existing file (stat and lstat both report ENOENT) is
    absent and yields ``None`` — the scope computation then degrades to
    ``pr_required``/``uncertain`` (never a silent no-op).  A PRESENT entry —
    including a DANGLING SYMLINK (the link itself exists even though its
    target is gone) and a stat-inaccessible path (e.g. EACCES on a parent
    directory) — fails closed with a typed :class:`CliError`
    (``reconcile_manifest_invalid``) so the reconcile is BLOCKED: a
    present-but-unreadable manifest is never collapsed to ``None``, which
    would let ``compute_reconcile_scope`` treat it as absent and waive the
    reconcile (``noop``) on top of a broken manifest.
    """
    if manifest_path is None:
        return None
    path = Path(manifest_path)

    def _blocked(exc: Exception | None = None) -> None:
        """Fail closed: the manifest entry is PRESENT but unusable."""
        detail = f": {exc}" if exc is not None else " (dangling symlink)"
        raise CliError(
            "reconcile_manifest_invalid",
            f"reconcile milestone {milestone_label} blocked: session runtime "
            f"manifest {manifest_path} is present but unreadable/invalid{detail}",
        ) from exc

    try:
        path.stat()
    except FileNotFoundError:
        # stat() FOLLOWS symlinks, so a dangling symlink (target missing)
        # reports ENOENT even though the link entry itself exists.  lstat()
        # sees the entry itself: a link with a missing target is PRESENT but
        # unreadable and must fail closed — only a genuinely never-existing
        # path (lstat ENOENT too) counts as absent.
        try:
            path.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:  # noqa: BLE001 - lstat itself inaccessible
            _blocked(exc)
        _blocked()
    except OSError as exc:  # noqa: BLE001 - EACCES etc: absence unprovable
        _blocked(exc)

    from arnold_pipelines.megaplan.cloud.runtime_manifest import load_manifest

    try:
        return load_manifest(path).to_dict()
    except Exception as exc:  # noqa: BLE001 - fail closed on unreadable manifest
        _blocked(exc)


def compute_reconcile_scope(
    spec: ChainSpec,
    manifest: Mapping[str, Any] | None,
    *,
    root: Path,
    chain_base_sha: str | None = None,
    manifest_path: Path | None = None,
    plan_dir: Path | None = None,
    plan_name: str | None = None,
    milestone_label: str | None = None,
) -> dict[str, Any]:
    """Controller-side skip detection for the ``kind: reconcile`` milestone.

    Engine-source changes (commits in the reconcile range touching
    ``arnold_pipelines/`` or ``arnold/``) minus promotion evidence
    (``manifest.promotions`` / ``promotion-journal.jsonl``).  Returns::

        {"decision": "noop" | "pr_required" | "uncertain",
         "engine_changes": [{"sha", "subject", "paths"}],
         "promotion_evidence": [...],
         "waiver_path": str | None,
         "reason": str}

    ``noop`` writes ``reconcile-verification.json`` into ``plan_dir`` when
    ``plan_name`` / ``milestone_label`` are provided (the completion guard
    accepts it).  Any uncertainty degrades to ``pr_required`` — never a
    silent no-op.
    """

    def _engine_change_commits() -> list[dict[str, Any]] | None:
        base = chain_base_sha or spec.base_branch
        if not base:
            return None
        raw_log = _soft_git(
            root,
            "log",
            "--first-parent",
            "--format=%H%x09%s",
            f"{base}..HEAD",
        )
        if raw_log is None:
            return None
        changes: list[dict[str, Any]] = []
        for line in raw_log.splitlines():
            line = line.strip()
            if not line:
                continue
            sha, _, subject = line.partition("\t")
            sha = sha.strip()
            if not sha:
                continue
            touched = [
                path
                for path in _changed_paths_for_commit(root, sha)
                if path.startswith(ENGINE_SOURCE_ROOTS)
            ]
            if touched:
                changes.append(
                    {"sha": sha, "subject": subject.strip(), "paths": touched}
                )
        return changes

    engine_changes = _engine_change_commits()
    if engine_changes is None:
        decision = "uncertain"
        reason = "engine change set could not be computed (git log failed)"
    elif not engine_changes:
        decision = "noop"
        reason = "no engine-source changes in reconcile range"
    else:
        promoted_refs = _promoted_refs(manifest, manifest_path=manifest_path)
        if promoted_refs is None:
            decision = "uncertain"
            reason = "engine changes present but promotion journal unreadable"
        else:
            unpromoted = [
                change
                for change in engine_changes
                if not any(
                    _git_is_ancestor(root, change["sha"], ref)
                    for ref in promoted_refs
                )
            ]
            if unpromoted:
                decision = "pr_required"
                reason = (
                    f"{len(unpromoted)} engine-source change(s) not covered by "
                    "promotion evidence"
                )
            else:
                decision = "noop"
                reason = "all engine-source changes already promoted"

    promotion_evidence = _promoted_refs(manifest, manifest_path=manifest_path) or []
    waiver_path: str | None = None
    if (
        decision == "noop"
        and plan_dir is not None
        and plan_name
        and milestone_label
    ):
        base_sha = (
            _current_head_sha(root)
            or chain_base_sha
            or ""
        )
        if base_sha:
            path = _write_reconcile_verification_waiver(
                plan_dir,
                plan=plan_name,
                milestone_label=milestone_label,
                base_sha=base_sha,
                scope=(
                    "no_engine_changes"
                    if not engine_changes
                    else "already_promoted"
                ),
                engine_changes=engine_changes or [],
                promotion_evidence=promotion_evidence,
                reason=reason,
            )
            waiver_path = str(path)
    return {
        "decision": decision,
        "engine_changes": engine_changes or [],
        "promotion_evidence": promotion_evidence,
        "waiver_path": waiver_path,
        "reason": reason,
    }


def _declares_final_conformance_gate(milestone: "MilestoneSpec") -> bool:
    """True when *milestone* explicitly declares a ``final_conformance_gate``.

    The reconcile-skip trigger is the DECLARED gate kind, not the mere
    presence of any terminal ``validate`` block: a terminal validate of
    another kind must not silently suppress reconciliation.
    """
    return any(
        getattr(validation, "kind", None) == "final_conformance_gate"
        for validation in milestone.validate
    )


def _chain_state_is_durably_complete(spec: ChainSpec, state: ChainState) -> bool:
    """Return True when *state* DURABLY records *spec* as complete.

    A chain is durably complete when the persisted chain state carries a
    terminal ``last_state`` ("done" / "complete") AND every milestone in
    *spec* has a completed record.  This is the idempotent-terminal
    observation: rerunning a completed chain must never regress it to a
    pending milestone — a completed legacy epic WITHOUT a reconcile
    milestone is DONE, not "pending reconcile" (P6).
    """
    if state.last_state not in {"done", "complete"}:
        return False
    if not spec.milestones:
        return False
    completed_labels = {
        str(record.get("label"))
        for record in state.completed
        if isinstance(record, dict) and isinstance(record.get("label"), str)
    }
    return all(milestone.label in completed_labels for milestone in spec.milestones)


def ensure_reconcile_milestone(
    spec_path: Path,
    *,
    root: Path | None = None,
    writer: Callable[[str], Any] | None = None,
    now: datetime | None = None,
) -> ChainSpec:
    """Idempotently materialize the generated ``kind: reconcile`` milestone.

    For legacy chains (no ``kind: reconcile`` milestone yet): appends the
    generated reconcile milestone — label ``reconcile``, idea
    ``briefs/reconcile.md``, branch ``reconcile/<slug>-<date>``,
    ``target_branch: main``, ``merge_policy: review``, ``phase_model:
    [execute=codex]``, ``depends_on`` the previous terminal milestone — and
    writes the ``briefs/reconcile.md`` rubric brief.  The date/branch are
    persisted on FIRST run and never recomputed: a chain that already carries
    the milestone (or has ``reconciliation.enabled: false``) is returned
    untouched.  A chain that is DURABLY COMPLETE (terminal ``last_state``
    with every milestone recorded — see
    :func:`_chain_state_is_durably_complete`) is returned untouched too:
    rerunning a completed legacy epic is an idempotent terminal observation,
    never a regression to pending reconcile (the append below would re-open
    a finished epic by leaving the generated reconcile milestone pending).
    Returns the (possibly reloaded) spec.
    """

    write = writer or (lambda _msg: None)
    spec = chain_spec.load_spec(spec_path)
    if not spec.reconciliation.get("enabled", True):
        return spec
    if any(milestone.kind == "reconcile" for milestone in spec.milestones):
        return spec
    spec_path = spec_path.expanduser().resolve()
    # P6 durable-completion guard — checked BEFORE any synthetic append.
    # The chain's terminal completion is authoritative DURABLE evidence
    # (state.last_state == done + all milestones recorded); appending the
    # generated reconcile milestone after completion would regress a finished
    # epic to pending reconcile.  Read the chain state OBSERVE-ONLY
    # (verify_execution_binding=False: no binding assertion, no
    # normalization/save side effects) — a completed chain has nothing to
    # bind and the observation must not mutate the cursor.  This is the
    # relocated form of the milestone-loop completion guard in ``run_chain``
    # (``idx >= len(spec.milestones)`` → terminal), which was DEAD for
    # completed legacy chains because the append happened before it ran.
    state = chain_spec.load_chain_state(spec_path, verify_execution_binding=False)
    if _chain_state_is_durably_complete(spec, state):
        write(
            f"[chain] chain {spec_path} is already durably complete "
            f"(last_state={state.last_state!r}, every milestone completed); "
            "reconcile milestone NOT appended — idempotent terminal "
            "observation, not a regression to pending reconcile\n"
        )
        return spec
    if spec.milestones and _declares_final_conformance_gate(spec.milestones[-1]):
        # A final_conformance_gate must stay the FINAL milestone (serial
        # order is asserted loudly).  Appending the generated reconcile
        # milestone would violate that contract, so reconciliation is
        # RECORDED as skipped for this chain rather than breaking the gate.
        # The record is DURABLE: an atomic ``reconcile-skip.json`` sidecar
        # next to the spec, read on restart, so a crash after the record
        # write (or after materialization) never re-inserts a duplicate
        # milestone or re-runs the skip silently.
        skip_path = spec_path.parent / RECONCILE_SKIP_FILENAME
        if not skip_path.exists():
            atomic_write_json(
                skip_path,
                {
                    "schema": RECONCILE_SKIP_SCHEMA,
                    "epic": spec_path.parent.name,
                    "terminal_milestone": spec.milestones[-1].label,
                    "gate": "final_conformance_gate",
                    "reason": (
                        "terminal milestone declares a final_conformance_gate; "
                        "the generated reconcile milestone would violate the "
                        "final-milestone invariant"
                    ),
                    "recorded_at": (now or datetime.now(timezone.utc)).isoformat(),
                },
            )
        write(
            f"[chain] reconciliation skipped for {spec_path}: previous terminal "
            f"milestone {spec.milestones[-1].label!r} declares a final "
            "conformance gate; the generated reconcile milestone would violate "
            "the final-milestone invariant (durable record "
            f"{RECONCILE_SKIP_FILENAME})\n"
        )
        return spec
    if root is None:
        root = spec_path.parent.parent.parent
    root = Path(root).expanduser().resolve()
    from arnold_pipelines.megaplan.briefs import (
        write_markdown_artifact as _write_brief_artifact,
    )

    directory = spec_path.parent
    date = (now or datetime.now(timezone.utc)).strftime("%Y%m%d")
    reconcile_brief = directory / "briefs" / "reconcile.md"
    reconcile_brief.parent.mkdir(parents=True, exist_ok=True)
    _write_brief_artifact(
        reconcile_brief,
        "\n".join(
            [
                "# Reconcile",
                "",
                "## Outcome",
                "",
                "Select and publish the epic's engine-source commits that were",
                "not already promoted, as a reviewed PR onto `main`.",
                "",
                "## Rubric",
                "",
                "This milestone is governed by the per-epic runtime end-state",
                "and megaplan reference architecture docs:",
                "",
                "- `docs/megaplan-reference-architecture-20260807.md`",
                "- `docs/per-epic-runtime-end-state-20260809.md`",
                "",
                "## Scope",
                "",
                "Engine-source changes (`arnold_pipelines/`, `arnold/`) not",
                "covered by promotion evidence.",
                "",
                "## Constraints",
                "",
                "- Selection is evidence, not narrative: output the chosen",
                "  commit SHAs plus verification evidence.",
                "- A verified no-op still records `reconcile-verification.json`.",
                "",
                "## Done Criteria",
                "",
                "- Selected commits are cherry-picked onto",
                "  `reconcile/<slug>-<date>` from `main`.",
                "- PR merged, intentionally rejected, or verified no-op.",
                "",
            ]
        ),
        metadata={
            "type": "brief",
            "slug": "reconcile",
            "title": "Reconcile",
            "epic": directory.name,
            "created_at": datetime.now(timezone.utc),
        },
    )
    try:
        import yaml

        raw = yaml.safe_load(spec_path.read_text(encoding="utf-8")) or {}
        milestones = list(raw.get("milestones") or [])
        previous_terminal = milestones[-1].get("label") if milestones else None
        reconcile_milestone: dict[str, Any] = {
            "label": "reconcile",
            "kind": "reconcile",
            "idea": str(reconcile_brief.relative_to(root)),
            "branch": f"reconcile/{directory.name}-{date}",
            "target_branch": "main",
            "merge_policy": "review",
            "phase_model": ["execute=codex"],
        }
        if previous_terminal:
            reconcile_milestone["depends_on"] = [previous_terminal]
        milestones.append(reconcile_milestone)
        raw["milestones"] = milestones
        # Atomic tmp+rename (same dir, fsync, os.replace): a crash mid-persist
        # leaves either the old valid spec or the new valid spec on disk —
        # never a truncated/corrupt spec.  A re-run heals.
        atomic_write_text(spec_path, yaml.safe_dump(raw, sort_keys=False))
    except Exception as exc:
        raise CliError(
            "reconcile_milestone_persist_failed",
            f"could not persist generated reconcile milestone for {spec_path}: {exc}",
        ) from exc
    write(
        f"[chain] appended generated kind=reconcile milestone "
        f"reconcile/{directory.name}-{date} to {spec_path}\n"
    )
    return chain_spec.load_spec(spec_path)


def _reconcile_would_mutate_protected_spec(
    spec: ChainSpec,
    *,
    root: Path,
    spec_path: Path,
) -> bool:
    """Return whether implicit reconciliation would dirty a protected input.

    ``ensure_reconcile_milestone`` is intentionally allowed to materialize the
    generated milestone for legacy chains. A source-bound launch is a
    different contract, however: a ``git_tracked`` precondition may protect
    the chain spec (or its initiative directory) and requires that input to
    remain byte-identical and clean. Letting the materializer run first would
    make that precondition fail on the engine's own write. Explicit opt-out
    and already-materialized reconciliation are handled here, so the caller
    only rejects the conflicting implicit case.
    """
    if not spec.reconciliation.get("enabled", True):
        return False
    if any(milestone.kind == "reconcile" for milestone in spec.milestones):
        return False
    root = root.expanduser().resolve()
    spec_path = spec_path.expanduser().resolve()
    for precondition in spec.launch_preconditions:
        if precondition.kind != "git_tracked" or precondition.path is None:
            continue
        target = Path(precondition.path).expanduser()
        if not target.is_absolute():
            target = root / target
        target = target.resolve(strict=False)
        if target == spec_path:
            return True
        if target.is_dir():
            try:
                spec_path.relative_to(target)
            except ValueError:
                continue
            return True
    return False


def _chain_session_marker_path(state: Any, project_root: Path) -> Path:
    """Resolve the cloud-session marker for the chain's session.

    Mirrors the canonical cloud resolution (execution_binding.py).  An
    explicit ``ARNOLD_CHAIN_SESSION_MARKER_DIR`` is authoritative for a
    managed operation: it is never followed by a fallback to a shared/global
    marker root, which could select another operation's marker.  Unmanaged
    local launches retain the historical canonical/project-relative fallbacks.
    """
    env_marker_dir = os.environ.get("ARNOLD_CHAIN_SESSION_MARKER_DIR", "").strip()
    managed_marker_dir = Path(env_marker_dir).expanduser() if env_marker_dir else None
    session = str(getattr(state, "chain_session", "") or "").strip()
    if not session:
        # Direct `chain start` (non-cloud) does not carry a launch_ctx, so
        # chain_session is unset even though a cloud-session marker exists.
        # Fall back to the watchdog's session env (the cloud chain launch
        # sets ARNOLD_CHAIN_SESSION), then to the canonical marker dir scan:
        # with no session name at all, adopt the marker whose chain_slug
        # matches the project's initiative (the marker filename encodes the
        # session).  A single-marker canonical dir is unambiguous.
        session = os.environ.get("ARNOLD_CHAIN_SESSION", "").strip()
        if not session:
            from arnold_pipelines.megaplan.cloud.runtime_attestation import (
                CLOUD_SESSION_MARKER_DIR_DEFAULT,
            )

            try:
                marker_scan_dir = managed_marker_dir or CLOUD_SESSION_MARKER_DIR_DEFAULT
                markers = sorted(marker_scan_dir.glob("*.json"))
            except OSError:
                markers = []
            if len(markers) == 1:
                session = markers[0].stem
            elif markers:
                # Multiple markers: prefer the one whose chain_slug matches
                # the project dir name or whose marker references this spec.
                for marker_file in markers:
                    try:
                        payload = json.loads(
                            marker_file.read_text(encoding="utf-8")
                        )
                    except Exception:
                        continue
                    remote_spec = str(
                        payload.get("remote_spec") or payload.get("spec") or ""
                    )
                    if remote_spec and str(remote_spec).startswith(
                        str(project_root)
                    ):
                        session = marker_file.stem
                        break
    if not session:
        raise CliError(
            "runtime_launch_attestation_mismatch",
            "chain launch-seed build refused: chain session is unresolved",
        )
    candidate_dirs: list[Path] = []
    if managed_marker_dir is not None:
        candidate_dirs.append(managed_marker_dir)
    else:
        from arnold_pipelines.megaplan.cloud.runtime_attestation import (
            CLOUD_SESSION_MARKER_DIR_DEFAULT,
        )

        candidate_dirs.append(CLOUD_SESSION_MARKER_DIR_DEFAULT)
        candidate_dirs.append(project_root / ".megaplan" / "cloud-sessions")
    for candidate_dir in candidate_dirs:
        probe = candidate_dir / (session + ".json")
        if probe.exists():
            return probe
    if managed_marker_dir is not None:
        raise CliError(
            "runtime_launch_attestation_mismatch",
            f"cloud-session marker is missing for managed marker root {session!r} "
            f"(searched {candidate_dirs})",
        )
    # Last resort: scan the canonical marker dir for the marker whose
    # chain_slug matches the project's initiative slug, so a direct
    # (non-cloud) chain start can still bind its launch seed.
    from arnold_pipelines.megaplan.cloud.runtime_attestation import (
        CLOUD_SESSION_MARKER_DIR_DEFAULT,
    )

    try:
        for marker_file in CLOUD_SESSION_MARKER_DIR_DEFAULT.glob("*.json"):
            try:
                payload = json.loads(marker_file.read_text(encoding="utf-8"))
            except Exception:
                continue
            if str(payload.get("chain_slug") or "").strip() == session:
                return marker_file
    except OSError:
        pass
    raise CliError(
        "runtime_launch_attestation_mismatch",
        f"cloud-session marker is missing for session {session!r} "
        f"(searched {candidate_dirs})",
    )


def run_chain(
    spec_path: Path,
    root: Path,
    *,
    writer=sys.stdout.write,
    no_git_refresh: bool = False,
    no_push: bool = False,
    one: bool = False,
    mode: str = "start",
    full_suite_backstop_mode: str | None = None,
    fresh: bool = False,
    require_anchor_override: bool | None = None,
    missing_anchor_ack_override: str | None = None,
) -> dict[str, Any]:
    """Drive the full chain. Returns a structured JSON-serializable result."""
    root = root.resolve(strict=False)
    spec_path = spec_path.resolve(strict=False)
    _require_active_initiative_chain(root, spec_path)
    _require_git_worktree_root(root, operation="chain start")
    spec = chain_spec.load_spec(spec_path)
    anchor_requirement = chain_spec.validate_anchor_requirement(
        spec,
        spec_path,
        require_anchor_override=require_anchor_override,
        missing_anchor_ack_override=missing_anchor_ack_override,
    )
    if anchor_requirement.warning:
        writer(f"[chain] WARNING: {anchor_requirement.warning}\n")
    chain_spec.validate_paths(spec, root, spec_path=spec_path)
    # P1 admission gate: fires BEFORE any chain state load or execution
    # identity binding. Manifest present+valid passes; a manifestless session
    # passes only with a valid unexpired allow_manifestless permit; else block.
    chain_spec.require_runtime_manifest_permit(spec_path)
    if _reconcile_would_mutate_protected_spec(
        spec,
        root=root,
        spec_path=spec_path,
    ):
        raise CliError(
            "reconcile_requires_committed_spec",
            "implicit reconciliation would mutate a chain spec protected by "
            "a git_tracked launch precondition; commit reconciliation explicitly "
            "or set reconciliation.enabled: false",
        )
    # P6: materialize the generated ``kind: reconcile`` terminal milestone for
    # legacy chains BEFORE any state load or execution identity binding, so
    # the loaded state and the bound identity both see the final milestone.
    # Idempotent: the date/branch are persisted on first run, never recomputed.
    spec = ensure_reconcile_milestone(spec_path, root=root, writer=writer)
    chain_spec.validate_paths(spec, root, spec_path=spec_path)
    from arnold_pipelines.megaplan.incident.chain_control import apply_chain_lifecycle

    apply_chain_lifecycle(
        spec_path,
        root,
        intent_kind="start" if mode in {"start", "run", None} else str(mode),
        actor={"id": "chain", "class": "system"},
        effect=lambda _txn: {
            "actual_cursor": 0,
            "pre_state_digest": None,
            "post_state_digest": "started",
            "mode": mode,
        },
    )
    # Load without execution-binding verification first, so the bootstrap can
    # populate an empty current_identity from the launch seed before the
    # strict binding check runs.
    state = chain_spec.load_chain_state(
        spec_path, verify_execution_binding=False
    )

    # Bootstrap: populate empty current_identity from the configured launch
    # seed when the chain has progressed state with a valid launch binding
    # but no runtime identity yet.  This is a one-time initialization, not a
    # runtime rebind — it preserves the existing launched_identity, bound_at,
    # schemas, and rebind_events.
    from arnold_pipelines.megaplan.chain.execution_binding import (
        _bootstrap_runtime_identity_from_seed,
    )

    _bootstrapped = _bootstrap_runtime_identity_from_seed(spec_path, state)
    if _bootstrapped:
        chain_spec.save_chain_state(spec_path, state)
        # Reload with verification now that current_identity is populated.
        state = chain_spec.load_chain_state(spec_path, verify_execution_binding=True)

    _preflight_agent_backends(
        spec,
        writer=writer,
        current_milestone_index=state.current_milestone_index,
    )
    from arnold_pipelines.megaplan.chain.execution_binding import (
        bind_execution_identity,
    )

    # Bind before the first state save or milestone initialization. Existing
    # progressed state without a launch binding is refused by the loader.
    bind_execution_identity(spec_path, state)
    # Runtime-launch seed (G14): build/refresh the content-addressed launch
    # seed for the per-epic runtime and export it so every child worker and
    # watchdog relaunch finds MEGAPLAN_RUNTIME_LAUNCH_SEED.  The manifest pin
    # is the runtime selector; local/dev runs without a bound manifest skip
    # the seed (no per-epic runtime to attest).
    _manifest_pin = chain_spec.session_runtime_manifest_path()
    if _manifest_pin is not None:
        from arnold_pipelines.megaplan.cloud.runtime_attestation import (
            ensure_runtime_launch_seed as _ensure_runtime_launch_seed,
        )

        _chain_binding_metadata = (getattr(state, "metadata", {}) or {}).get(
            "execution_binding"
        )
        _chain_binding_metadata = (
            _chain_binding_metadata
            if isinstance(_chain_binding_metadata, Mapping)
            else {}
        )
        _chain_runtime_binding = _chain_binding_metadata.get("runtime_binding")
        _chain_runtime_binding = (
            _chain_runtime_binding
            if isinstance(_chain_runtime_binding, Mapping)
            else {}
        )
        _bound_identity = _chain_runtime_binding.get("current_identity")
        _bound_identity = (
            dict(_bound_identity) if isinstance(_bound_identity, Mapping) else None
        )
        # Blocked-plan auto-adopt (5f34c4a202): when the chain's plan is
        # blocked with no live worker, the recorded runtime binding may lag
        # the current manifest head. Nothing is mid-flight to protect, so the
        # seed should bind to the LIVE manifest-pinned identity instead of the
        # stale chain binding — the engine advance is a non-event, exactly like
        # the immutable-seed per-dispatch refresh. An ACTIVE plan keeps the
        # strict stale-binding check (mid-execution swaps must not silently
        # rebind).
        from arnold_pipelines.megaplan.chain.execution_binding import (
            _state_blocked_no_live_work,
        )

        if _state_blocked_no_live_work(state):
            from arnold_pipelines.megaplan.cloud.runtime_manifest import (
                load_manifest,
            )

            try:
                _manifest_state = load_manifest(_manifest_pin)
                _expected_head = str(
                    (_manifest_state.epic or {}).get("expected_head") or ""
                )
                if _expected_head:
                    from arnold_pipelines.megaplan.cloud.runtime_attestation import (
                        _live_runtime_identity,
                    )

                    _live = _live_runtime_identity(
                        root=root,
                        expected_revision=_expected_head,
                    )
                    if isinstance(_live, Mapping) and _live.get("source_revision"):
                        _bound_identity = dict(_live)
            except Exception:
                pass  # fall back to the recorded binding; the strict check will surface any real mismatch
        _launch_seed_path = _ensure_runtime_launch_seed(
            manifest_path=_manifest_pin,
            chain_spec_path=spec_path,
            marker_path=_chain_session_marker_path(state, root),
            chain_runtime_identity=_bound_identity,
        )
        os.environ["MEGAPLAN_RUNTIME_LAUNCH_SEED"] = str(_launch_seed_path)
    from arnold_pipelines.megaplan.chain.operator_pause import is_paused

    if is_paused(state):
        return _result(
            "paused",
            state,
            [],
            spec=spec,
            reason="durable operator pause is active; explicit chain resume required",
        )
    env = resolve_execution_environment(
        root=root,
        state={"config": {"project_dir": str(root), "base_branch": spec.base_branch}},
    )
    state.metadata = merge_isolation_evidence(state.metadata, env, phase="chain_start")
    if state.current_milestone_index < 0 and not state.completed:
        from arnold_pipelines.megaplan._core.io import get_effective
        from arnold_pipelines.megaplan.orchestration.full_suite_backstop import (
            normalize_full_suite_backstop_mode,
        )

        state.full_suite_backstop_mode = normalize_full_suite_backstop_mode(
            full_suite_backstop_mode
            if full_suite_backstop_mode is not None
            else get_effective("execution", "full_suite_backstop_mode")
        )
    chain_spec.save_chain_state(spec_path, state)
    preexisting_dirty_paths = _dirty_worktree_paths(root)
    push_enabled = not no_push and os.environ.get("MEGAPLAN_CHAIN_NO_PUSH") not in {
        "1",
        "true",
        "TRUE",
        "yes",
        "YES",
    }
    reconciliation_backstop_block = _run_pending_reconciliation_backstops(
        root,
        spec_path,
        state,
        writer=writer,
    )
    if reconciliation_backstop_block is not None:
        return _result(
            "blocked",
            state,
            [],
            spec=spec,
            reason=reconciliation_backstop_block,
        )
    completed_before_reconciliation = len(state.completed)
    state = _reconcile_chain_from_ground_truth(
        root,
        spec_path,
        spec,
        state,
        writer=writer,
        push_enabled=push_enabled,
    )
    reconciliation_block = state.metadata.get(
        "reconciliation_full_suite_backstop_block"
    )
    if isinstance(reconciliation_block, dict):
        result = reconciliation_block.get("result")
        return _result(
            "blocked",
            state,
            [],
            spec=spec,
            reason=_full_suite_backstop_block_reason(
                str(reconciliation_block.get("milestone") or "unknown"),
                str(reconciliation_block.get("plan") or "unknown"),
                result if isinstance(result, dict) else None,
            ),
        )

    events: list[dict[str, Any]] = []

    if one and len(state.completed) > completed_before_reconciliation:
        return _result(
            "done",
            state,
            events,
            spec=spec,
            reason="one-milestone limit reached during ground-truth reconciliation",
        )

    def log(msg: str, **fields: Any) -> None:
        events.append({"msg": msg, **fields})
        writer(f"[chain] {msg}\n")

    def _emit_chain_work_boundary(
        kind: str,
        *,
        plan_name: str | None = None,
        phase: str | None = "chain",
        elapsed_ms: int | None = None,
        operation: str | None = None,
        from_state: str | None = None,
        to_state: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        target_plan = plan_name or state.current_plan_name
        if not target_plan:
            return
        try:
            plan_dir = resolve_plan_dir(root, target_plan)
        except CliError:
            return
        payload = {
            "boundary": kind,
            "chain_spec": str(spec_path),
            "current_plan_name": target_plan,
            **dict(metadata or {}),
        }
        try:
            from arnold_pipelines.megaplan.observability.work_ledger import (
                emit_git_activity,
                emit_replay,
                emit_retry_wait,
                emit_session_start,
                emit_transition_activity,
            )

            if kind == "chain_session_start":
                emit_session_start(
                    plan_dir,
                    phase=phase,
                    session_id=f"chain:{os.getpid()}:{spec_path.name}",
                    agent="chain",
                    metadata=payload,
                )
            elif kind == "git":
                emit_git_activity(
                    plan_dir,
                    phase=phase or "chain",
                    operation=operation or "chain_git_boundary",
                    elapsed_ms=elapsed_ms,
                    metadata=payload,
                )
            elif kind == "retry_wait":
                emit_retry_wait(
                    plan_dir,
                    elapsed_ms=elapsed_ms,
                    unavailable_reason="chain_retry_boundary_no_model",
                    metadata=payload,
                )
            elif kind == "replay":
                emit_replay(
                    plan_dir,
                    elapsed_ms=elapsed_ms,
                    unavailable_reason="chain_replay_boundary_usage_unavailable",
                    metadata=payload,
                )
            elif kind == "transition":
                emit_transition_activity(
                    plan_dir,
                    phase=phase,
                    transition=str(payload.get("transition") or "chain_transition"),
                    from_state=from_state,
                    to_state=to_state,
                    elapsed_ms=elapsed_ms,
                    metadata=payload,
                )
        except Exception:
            logging.getLogger("megaplan").debug(
                "Work ledger chain event emission skipped", exc_info=True
            )

    # ---- Seed phase ----
    if spec.seed_plan and state.current_milestone_index < 0:
        seed_state = _plan_state(root, spec.seed_plan, timeout=spec.status_timeout)
        log(f"seed plan {spec.seed_plan} state={seed_state}")
        if seed_state not in TERMINAL_SKIP_STATES:
            state.current_plan_name = spec.seed_plan
            chain_spec.save_chain_state(spec_path, state)
            _emit_chain_work_boundary(
                "chain_session_start",
                plan_name=spec.seed_plan,
                metadata={"boundary": "seed_plan_start", "seed_state": seed_state},
            )
            _emit_chain_work_boundary(
                "transition",
                plan_name=spec.seed_plan,
                from_state=seed_state,
                to_state="chain_driving_seed",
                metadata={"transition": "chain_seed_start"},
            )
            outcome = _drive_plan_with_blocked_execute_recovery(
                root,
                spec_path,
                spec.seed_plan,
                spec,
                writer=writer,
            )
            state = _record_chain_last_state_after_plan_run(
                root,
                spec_path,
                state,
                outcome,
                writer=writer,
            )
            decision = _handle_outcome(
                outcome, spec=spec, writer=writer, root=root, spec_path=spec_path
            )
            if decision == "authority_blocked":
                state.last_state = "authority_divergence"
                chain_spec.save_chain_state(spec_path, state)
                return _result(
                    "blocked",
                    state,
                    events,
                    spec=spec,
                    reason=f"seed plan terminal outcome lacks authority",
                )
            if decision == "stop":
                return _result(
                    "stopped",
                    state,
                    events,
                    spec=spec,
                    reason=f"seed plan {outcome.status}",
                )
            if decision == "retry":
                # Recursive retry kept simple: re-drive seed once.
                _emit_chain_work_boundary(
                    "retry_wait",
                    plan_name=spec.seed_plan,
                    elapsed_ms=0,
                    metadata={
                        "milestone_label": "seed",
                        "retry_strategy": "seed_recursive_retry",
                    },
                )
                outcome = _drive_plan_with_blocked_execute_recovery(
                    root,
                    spec_path,
                    spec.seed_plan,
                    spec,
                    writer=writer,
                )
                state = _record_chain_last_state_after_plan_run(
                    root,
                    spec_path,
                    state,
                    outcome,
                    writer=writer,
                )
                if outcome.status != "done":
                    return _result(
                        "stopped", state, events, spec=spec, reason="seed retry failed"
                    )
                authoritative, reason = _plan_terminal_completion_is_authoritative(
                    root, spec.seed_plan
                )
                if not authoritative:
                    writer(
                        f"[chain] seed retry {spec.seed_plan} outcome=done lacks authority; "
                        f"stopping: {reason}\n"
                    )
                    state.last_state = "authority_divergence"
                    chain_spec.save_chain_state(spec_path, state)
                    return _result(
                        "blocked",
                        state,
                        events,
                        spec=spec,
                        reason=f"seed retry terminal outcome lacks authority: {reason}",
                    )
            # skip / advance both proceed to milestones
        else:
            authoritative, reason = _plan_terminal_completion_is_authoritative(
                root, spec.seed_plan
            )
            if not authoritative:
                writer(
                    f"[chain] seed plan {spec.seed_plan} terminal state={seed_state} "
                    f"lacks authority; stopping: {reason}\n"
                )
                state.last_state = "authority_divergence"
                state.current_plan_name = spec.seed_plan
                chain_spec.save_chain_state(spec_path, state)
                return _result(
                    "blocked",
                    state,
                    events,
                    spec=spec,
                    reason=f"seed plan terminal state lacks authority: {reason}",
                )
        appended, reason = _append_completed_with_guard(
            root,
            state,
            {
                "label": "seed",
                "plan": spec.seed_plan,
                "status": state.last_state or seed_state,
            },
            implementation_milestone=False,
            writer=writer,
        )
        if not appended:
            chain_spec.save_chain_state(spec_path, state)
            return _result(
                "blocked",
                state,
                events,
                spec=spec,
                reason=f"seed completion guard blocked append: {reason}",
            )
        state.current_milestone_index = 0
        state.current_plan_name = None
        chain_spec.save_chain_state(spec_path, state)

    elif state.current_milestone_index < 0:
        state.current_milestone_index = 0
        chain_spec.save_chain_state(spec_path, state)

    # ---- Milestones ----
    # Terminal observation for an already-completed chain: when the cursor is
    # past every milestone in the spec, the chain is DONE and the loop never
    # starts (the finalizer + successor gate + ``done`` result below still
    # run).  For a completed LEGACY chain this guard is only reachable
    # because ``ensure_reconcile_milestone`` (above) checked durable
    # completion BEFORE appending the generated reconcile milestone — with
    # the append happening first the cursor would sit mid-spec here and the
    # chain would regress to driving a pending reconcile milestone.
    idx = max(state.current_milestone_index, 0)
    if idx >= len(spec.milestones):
        try:
            state = _reconcile_terminal_pr_state(
                root,
                spec_path,
                state,
                writer=writer,
            )
        except CliError as exc:
            log(f"terminal PR reconciliation skipped: {exc.message}")
    while idx < len(spec.milestones):
        state = chain_spec.load_chain_state(spec_path)
        if is_paused(state):
            return _result(
                "paused",
                state,
                events,
                spec=spec,
                reason="durable operator pause is active; explicit chain resume required",
            )
        state = _reconcile_chain_from_ground_truth(
            root,
            spec_path,
            spec,
            state,
            writer=writer,
            push_enabled=push_enabled,
        )
        idx = max(state.current_milestone_index, 0)
        if idx >= len(spec.milestones):
            break
        milestone = spec.milestones[idx]
        log(f"milestone {milestone.label} starting")
        use_pr = push_enabled and bool(milestone.branch)

        if (
            use_pr
            and state.current_milestone_index == idx
            and state.last_state == "pr_closed"
        ):
            state = _clear_stale_closed_pr_state(
                spec_path=spec_path,
                state=state,
                milestone_label=milestone.label,
                log_fn=log,
            )

        if state.current_milestone_index == idx and state.pr_number is not None and use_pr:
            pr_state = _pr_state(root, state.pr_number, writer=writer)
            if (
                pr_state == "closed"
                and state.last_state == "blocked"
                and not _is_reconcile_milestone(milestone)
            ):
                log(
                    f"clearing stale closed PR context for {milestone.label} while "
                    "resuming blocked plan"
                )
                state.last_state = "pr_closed"
                state.pr_state = "closed"
                chain_spec.save_chain_state(spec_path, state)
                state = _clear_stale_closed_pr_state(
                    spec_path=spec_path,
                    state=state,
                    milestone_label=milestone.label,
                    log_fn=log,
                )
                continue
            if pr_state == "merged":
                state.pr_state = "merged"
                chain_spec.save_chain_state(spec_path, state)
                merged_pr_plan_state = _plan_state_payload_from_name(
                    root, state.current_plan_name
                )
                if merged_pr_plan_state.get("current_state") != STATE_DONE:
                    recovered_state, recovery_reason = (
                        _recover_stale_merged_pr_for_unfinished_plan(
                            root,
                            spec_path,
                            state,
                            milestone,
                            merged_pr_plan_state,
                            writer=writer,
                        )
                    )
                    if recovered_state is None:
                        return _block_pr_progression_guard_failure(
                            spec_path=spec_path,
                            spec=spec,
                            state=state,
                            milestone=milestone,
                            reason=recovery_reason,
                            events=events,
                            writer=writer,
                        )
                    state = recovered_state
                    log(recovery_reason)
                    continue
                publish_ok, publish_reason = _ensure_published_claimed_changes_for_pr_progression(
                    root,
                    spec_path,
                    state,
                    milestone,
                    writer=writer,
                    allow_publish=False,
                )
                if not publish_ok:
                    return _block_pr_progression_guard_failure(
                        spec_path=spec_path,
                        spec=spec,
                        state=state,
                        milestone=milestone,
                        reason=publish_reason,
                        events=events,
                        writer=writer,
                    )
                log(f"PR #{state.pr_number} merged; advancing past {milestone.label}")
                if _is_reconcile_milestone(milestone):
                    _delete_reconcile_pr_branch_for(milestone, root, writer=writer)
                    _record_reconcile_outcome(
                        state,
                        outcome="merged",
                        reason=f"reconcile PR #{state.pr_number} merged into "
                        f"{_reconcile_target_branch(milestone, spec)}",
                    )
                validation_reason = _run_milestone_validations_blocking(
                    root=root,
                    spec_path=spec_path,
                    spec=spec,
                    state=state,
                    milestone=milestone,
                    writer=writer,
                    refresh_base=True,
                    no_git_refresh=no_git_refresh,
                )
                if validation_reason is not None:
                    return _result(
                        "blocked",
                        state,
                        events,
                        spec=spec,
                        reason=validation_reason,
                    )
                appended, reason = _append_completed_with_guard(
                    root,
                    state,
                    {
                        "label": milestone.label,
                        "plan": state.current_plan_name,
                        "status": "done",
                        "pr_number": state.pr_number,
                        "pr_state": "merged",
                        **_reconcile_record_fields(milestone, spec),
                    },
                    implementation_milestone=True,
                    writer=writer,
                )
                if not appended:
                    authoritative, _authority_reason = _plan_terminal_completion_is_authoritative(
                        root, state.current_plan_name
                    )
                    if not authoritative:
                        chain_spec.save_chain_state(spec_path, state)
                        return _result(
                            "blocked",
                            state,
                            events,
                            spec=spec,
                            reason=f"milestone {milestone.label} completion guard blocked append: {reason}",
                        )
                    return _handle_completion_guard_failure(
                        root=root,
                        spec_path=spec_path,
                        spec=spec,
                        state=state,
                        milestone=milestone,
                        plan_name=state.current_plan_name or "",
                        outcome_status="done",
                        reason=reason,
                        events=events,
                        writer=writer,
                    )
                if state.current_plan_name:
                    _mark_plan_completed_by_chain(
                        root,
                        state.current_plan_name,
                        milestone_label=milestone.label,
                        completion_reason=reason,
                        writer=writer,
                        state=state,
                    )
                _emit_milestone_completion_evidence(
                    state,
                    milestone_label=milestone.label,
                    milestone_index=idx,
                    plan_name=state.current_plan_name or "",
                )
                idx += 1
                _mark_chain_after_milestone_advance(spec, state, next_index=idx)
                if idx >= len(spec.milestones):
                    _emit_chain_complete_evidence(state, spec=spec)
                chain_spec.save_chain_state(spec_path, state)
                manifest_reason = _finalize_validation_artifacts_after_done_append(
                    root=root,
                    spec_path=spec_path,
                    spec=spec,
                    state=state,
                    milestone=milestone,
                    writer=writer,
                )
                if manifest_reason is not None:
                    return _result(
                        "blocked",
                        state,
                        events,
                        spec=spec,
                        reason=manifest_reason,
                    )
                continue

        if (
            state.last_state == STATE_AWAITING_PR_MERGE
            and state.current_milestone_index == idx
        ):
            local_publication_sha: str | None = None
            if not use_pr or state.pr_number is None:
                log(
                    f"review merge wait for {milestone.label} has no PR context; advancing"
                )
                if not use_pr and state.pr_number is not None:
                    local_publication_sha = _current_git_head(root)
                    if local_publication_sha is None:
                        return _result(
                            "blocked",
                            state,
                            events,
                            spec=spec,
                            reason=(
                                f"milestone {milestone.label} cannot reconcile its open PR "
                                "to a local-only run without a readable local HEAD"
                            ),
                        )
                    state.metadata["local_pr_reconciliation"] = {
                        "milestone": milestone.label,
                        "pr_number": state.pr_number,
                        "observed_pr_state": state.pr_state,
                        "local_commit_sha": local_publication_sha,
                    }
                    state.pr_number = None
                state.pr_state = None
                chain_spec.save_chain_state(spec_path, state)
            else:
                if _is_reconcile_milestone(milestone):
                    # Reconcile PR lifecycle: merged and intentionally-closed
                    # are BOTH terminal, close-worthy outcomes (per the P6
                    # terminal-state rules).  Unknown/open states keep the
                    # chain parked awaiting human review — never close.
                    pr_state = _pr_state(root, state.pr_number, writer=writer)
                    if pr_state == "closed":
                        blocked = _advance_reconcile_rejected(
                            root,
                            spec_path,
                            spec,
                            state,
                            milestone,
                            events,
                            pr_number=state.pr_number,
                            writer=writer,
                            log=log,
                        )
                        if blocked is not None:
                            return blocked
                        continue
                    if pr_state != "merged":
                        state.pr_state = pr_state
                        chain_spec.save_chain_state(spec_path, state)
                        log(
                            f"reconcile PR #{state.pr_number} state={pr_state}; "
                            "awaiting human review/merge"
                        )
                        return _result(
                            STATE_AWAITING_PR_MERGE,
                            state,
                            events,
                            spec=spec,
                            reason=(
                                f"reconcile milestone {milestone.label} PR "
                                f"#{state.pr_number} is {pr_state}"
                            ),
                        )
                pr_state = _pr_state(root, state.pr_number, writer=writer)
                if pr_state == "closed":
                    log(f"PR #{state.pr_number} closed while awaiting merge; stopping chain")
                    return _stop_for_closed_pr(
                        spec_path=spec_path,
                        state=state,
                        events=events,
                        spec=spec,
                        milestone_label=milestone.label,
                        pr_number=state.pr_number,
                    )
                state.pr_state = pr_state
                chain_spec.save_chain_state(spec_path, state)
                if pr_state != "merged":
                    publish_ok, publish_reason = _ensure_published_claimed_changes_for_pr_progression(
                        root,
                        spec_path,
                        state,
                        milestone,
                        writer=writer,
                        allow_publish=True,
                    )
                    if not publish_ok:
                        return _block_pr_progression_guard_failure(
                            spec_path=spec_path,
                            spec=spec,
                            state=state,
                            milestone=milestone,
                            reason=publish_reason,
                            events=events,
                            writer=writer,
                        )
                    if publish_reason.startswith("published "):
                        state = chain_spec.load_chain_state(spec_path)
                    if _automatic_pr_progression_permitted(spec, spec_path):
                        validation_evidence = _validate_pr_progression_wbc(
                            root=root,
                            spec_path=spec_path,
                            state=state,
                            milestone=milestone,
                            plan_name=state.current_plan_name or "",
                            pr_number=state.pr_number,
                            transition_name="chain_pr_ready",
                        )
                        _pr_ready_evidence = _capture_pr_ready_evidence(
                            root,
                            state.pr_number,
                            writer=writer,
                            ci_readiness_state="ready",
                            validation_evidence=validation_evidence,
                        )
                        _mark_pr_ready(root, state.pr_number, writer=writer)
                        state.pr_state = _enable_auto_merge(
                            root, state.pr_number, writer=writer
                        )
                        _pr_merged_evidence = _capture_pr_merged_evidence(
                            root,
                            state.pr_number,
                            writer=writer,
                            validation_evidence=validation_evidence,
                        )
                        chain_spec.save_chain_state(spec_path, state)
                        pr_state = _pr_state(root, state.pr_number, writer=writer)
                        state.pr_state = pr_state
                        chain_spec.save_chain_state(spec_path, state)
                        if pr_state == "closed":
                            log(
                                f"PR #{state.pr_number} closed while awaiting merge; "
                                "stopping chain"
                            )
                            return _stop_for_closed_pr(
                                spec_path=spec_path,
                                state=state,
                                events=events,
                                spec=spec,
                                milestone_label=milestone.label,
                                pr_number=state.pr_number,
                            )
                        if pr_state == "merged":
                            log(
                                f"PR #{state.pr_number} merged; advancing past "
                                f"{milestone.label}"
                            )
                        else:
                            log(
                                f"PR #{state.pr_number} auto-merge enabled; "
                                f"state={pr_state}; awaiting merge"
                            )
                            return _result(
                                STATE_AWAITING_PR_MERGE,
                                state,
                                events,
                                spec=spec,
                                reason=(
                                    f"milestone {milestone.label} PR "
                                    f"#{state.pr_number} is {pr_state}"
                                ),
                            )
                    else:
                        policy = policy_for_spec(
                            spec,
                            runtime_overrides=chain_spec.load_runtime_policy(spec_path),
                        )
                        log(
                            f"PR #{state.pr_number} state={pr_state}; awaiting human "
                            f"review/merge (merge_policy={policy.merge_policy}, "
                            f"clean_milestone_pr={policy.clean_milestone_pr})"
                        )
                        return _result(
                            STATE_AWAITING_PR_MERGE,
                            state,
                            events,
                            spec=spec,
                            reason=f"milestone {milestone.label} PR #{state.pr_number} is {pr_state}",
                        )
                if pr_state != "merged":
                    log(f"PR #{state.pr_number} state={pr_state}; awaiting merge")
                    return _result(
                        STATE_AWAITING_PR_MERGE,
                        state,
                        events,
                        spec=spec,
                        reason=f"milestone {milestone.label} PR #{state.pr_number} is {pr_state}",
                    )
                merged_pr_plan_state = _plan_state_payload_from_name(
                    root, state.current_plan_name
                )
                if merged_pr_plan_state.get("current_state") != STATE_DONE:
                    recovered_state, recovery_reason = (
                        _recover_stale_merged_pr_for_unfinished_plan(
                            root,
                            spec_path,
                            state,
                            milestone,
                            merged_pr_plan_state,
                            writer=writer,
                        )
                    )
                    if recovered_state is None:
                        return _block_pr_progression_guard_failure(
                            spec_path=spec_path,
                            spec=spec,
                            state=state,
                            milestone=milestone,
                            reason=recovery_reason,
                            events=events,
                            writer=writer,
                        )
                    state = recovered_state
                    log(recovery_reason)
                    continue
                publish_ok, publish_reason = _ensure_published_claimed_changes_for_pr_progression(
                    root,
                    spec_path,
                    state,
                    milestone,
                    writer=writer,
                    allow_publish=False,
                )
                if not publish_ok:
                    return _block_pr_progression_guard_failure(
                        spec_path=spec_path,
                        spec=spec,
                        state=state,
                        milestone=milestone,
                        reason=publish_reason,
                        events=events,
                        writer=writer,
                    )
                log(f"PR #{state.pr_number} merged; advancing past {milestone.label}")
                if _is_reconcile_milestone(milestone):
                    _delete_reconcile_pr_branch_for(milestone, root, writer=writer)
                    _record_reconcile_outcome(
                        state,
                        outcome="merged",
                        reason=f"reconcile PR #{state.pr_number} merged into "
                        f"{_reconcile_target_branch(milestone, spec)}",
                    )
            validation_reason = _run_milestone_validations_blocking(
                root=root,
                spec_path=spec_path,
                spec=spec,
                state=state,
                milestone=milestone,
                writer=writer,
                refresh_base=True,
                no_git_refresh=no_git_refresh,
            )
            if validation_reason is not None:
                return _result(
                    "blocked",
                    state,
                    events,
                    spec=spec,
                    reason=validation_reason,
                )
            completion_record = {
                "label": milestone.label,
                "plan": state.current_plan_name,
                "status": "done",
                "pr_number": state.pr_number,
                "pr_state": "merged" if state.pr_number is not None else None,
                **_reconcile_record_fields(milestone, spec),
            }
            if local_publication_sha is not None:
                completion_record["local_commit_sha"] = local_publication_sha
                completion_record["publication_evidence"] = "local_no_push_reconciliation"
            appended, reason = _append_completed_with_guard(
                root,
                state,
                completion_record,
                implementation_milestone=True,
                writer=writer,
            )
            if not appended:
                authoritative, _authority_reason = _plan_terminal_completion_is_authoritative(
                    root, state.current_plan_name
                )
                if not authoritative:
                    chain_spec.save_chain_state(spec_path, state)
                    return _result(
                        "blocked",
                        state,
                        events,
                        spec=spec,
                        reason=f"milestone {milestone.label} completion guard blocked append: {reason}",
                    )
                return _handle_completion_guard_failure(
                    root=root,
                    spec_path=spec_path,
                    spec=spec,
                    state=state,
                    milestone=milestone,
                    plan_name=state.current_plan_name or "",
                    outcome_status="done",
                    reason=reason,
                    events=events,
                    writer=writer,
                )
            if state.current_plan_name:
                _mark_plan_completed_by_chain(
                    root,
                    state.current_plan_name,
                    milestone_label=milestone.label,
                    completion_reason=reason,
                    writer=writer,
                    state=state,
                )
            _emit_milestone_completion_evidence(
                state,
                milestone_label=milestone.label,
                milestone_index=idx,
                plan_name=state.current_plan_name or "",
            )
            idx += 1
            _mark_chain_after_milestone_advance(spec, state, next_index=idx)
            if idx >= len(spec.milestones):
                _emit_chain_complete_evidence(state, spec=spec)
            chain_spec.save_chain_state(spec_path, state)
            manifest_reason = _finalize_validation_artifacts_after_done_append(
                root=root,
                spec_path=spec_path,
                spec=spec,
                state=state,
                milestone=milestone,
                writer=writer,
            )
            if manifest_reason is not None:
                return _result(
                    "blocked",
                    state,
                    events,
                    spec=spec,
                    reason=manifest_reason,
                )
            continue

        # Resume mid-milestone if we already have a plan name recorded.
        try:
            if (
                state.current_plan_name
                and state.current_milestone_index == idx
                and _plan_state(root, state.current_plan_name, timeout=spec.status_timeout)
                not in ("missing",)
            ):
                plan_name = state.current_plan_name
                try:
                    plan_dir = resolve_plan_dir(root, plan_name)
                except CliError:
                    plan_dir = None
                if plan_dir is not None:
                    _rearm_stale_terminal_execute_cursor_mismatch(plan_dir, writer=writer)
                    _rearm_stale_incomplete_execute_cursor_mismatch(plan_dir, writer=writer)
                    _rearm_stale_execute_authority_divergence(plan_dir, writer=writer)
                    _rearm_fresh_session_execute_block(plan_dir, writer=writer)
                plan_state = _plan_state_payload_from_name(root, plan_name)
                if _blocked_plan_replay_would_be_redundant(
                    state,
                    plan_state=plan_state,
                    root=root,
                ):
                    _emit_chain_work_boundary(
                        "replay",
                        plan_name=plan_name,
                        elapsed_ms=0,
                        metadata={
                            "milestone_label": milestone.label,
                            "replay_boundary": "blocked_plan_replay_suppressed",
                            "plan_state": plan_state.get("current_state"),
                        },
                    )
                    _append_reconciliation_audit(
                        state,
                        plan_name=plan_name,
                        plan_state=dict(plan_state),
                        pr_number=state.pr_number,
                        pr_state=state.pr_state,
                    )
                    chain_spec.save_chain_state(spec_path, state)
                    writer(
                        f"[chain] plan {plan_name} is already durably blocked with no "
                        "active step; preserving the stop without replaying the plan\n"
                    )
                    return _result(
                        "stopped",
                        state,
                        events,
                        spec=spec,
                        reason=f"milestone {milestone.label} remains blocked",
                    )
                state = _sync_chain_last_state_from_plan(
                    root,
                    spec_path,
                    state,
                    writer=writer,
                )
                log(f"resuming existing plan {plan_name} for {milestone.label}")
                _emit_chain_work_boundary(
                    "chain_session_start",
                    plan_name=plan_name,
                    metadata={
                        "boundary": "milestone_resume",
                        "milestone_label": milestone.label,
                        "milestone_index": idx,
                    },
                )
                _emit_chain_work_boundary(
                    "transition",
                    plan_name=plan_name,
                    from_state=str(plan_state.get("current_state") or ""),
                    to_state="chain_resuming_milestone",
                    metadata={
                        "transition": "chain_milestone_resume",
                        "milestone_label": milestone.label,
                        "milestone_index": idx,
                    },
                )
                _emit_milestone_start_evidence(
                    state,
                    milestone_label=milestone.label,
                    milestone_index=idx,
                    plan_name=plan_name,
                )
                if use_pr and milestone.branch:
                    project_source_binding = state.metadata.get(
                        "project_source_binding"
                    )
                    if isinstance(project_source_binding, Mapping):
                        from arnold_pipelines.megaplan.chain.target_rebind import (
                            publish_bound_project_source_branch,
                        )

                        publish_bound_project_source_branch(
                            root,
                            state,
                            plan_name=plan_name,
                            milestone_branch=milestone.branch,
                        )
                    else:
                        base_ref = _checkout_milestone_branch(
                            root,
                            milestone.branch or "",
                            base_branch=_reconcile_target_branch(milestone, spec),
                            writer=writer,
                            from_origin=push_enabled and not no_git_refresh,
                            expected_base_ref=state.target_base_ref,
                        )
                        if isinstance(base_ref, str) and base_ref:
                            state.target_base_ref = base_ref
                            chain_spec.save_chain_state(spec_path, state)
                    _capture_sync_state(
                        root, spec_path, branch=milestone.branch, pr_number=state.pr_number
                    )
                    if state.pr_number is None:
                        state = chain_spec.load_chain_state(spec_path)
                        state.pr_number = _ensure_pr_for_milestone(
                            root,
                            spec,
                            state,
                            milestone,
                            writer=writer,
                        )
                        state.pr_state = "open" if state.pr_number is not None else None
                        chain_spec.save_chain_state(spec_path, state)
            else:
                base_ref = _refresh_base_branch(
                    root,
                    _reconcile_target_branch(milestone, spec),
                    writer=writer,
                    no_git_refresh=no_git_refresh,
                    expected_sha=state.target_base_ref,
                )
                if isinstance(base_ref, str) and base_ref:
                    state.target_base_ref = base_ref
                    chain_spec.save_chain_state(spec_path, state)
                if spec.require_clean_base:
                    _assert_clean_base(
                        root,
                        milestone,
                        no_push=not push_enabled,
                        writer=writer,
                    )
                eff_profile = state.profile_bumps.get(milestone.label) or milestone.profile
                eff_robustness = (
                    state.robustness_bumps.get(milestone.label)
                    or milestone.robustness
                    or spec.robustness
                )
                eff_depth = state.depth_bumps.get(milestone.label) or milestone.depth
                if milestone.kind == "reconcile":
                    # P6 controller-side skip detection.  A verified no-op
                    # (empty engine-source change set, or every change already
                    # covered by promotion evidence) writes the
                    # reconcile-verification.json waiver and advances WITHOUT
                    # running the agent; any uncertainty degrades to
                    # ``pr_required`` (never a silent no-op).
                    manifest_path = chain_spec.session_runtime_manifest_path()
                    manifest = _reconcile_scope_manifest(
                        manifest_path, milestone_label=milestone.label
                    )
                    scope = compute_reconcile_scope(
                        spec,
                        manifest,
                        root=root,
                        chain_base_sha=state.target_base_ref,
                        manifest_path=manifest_path,
                    )
                    log(
                        f"milestone {milestone.label} reconcile scope: "
                        f"{scope['decision']} ({scope['reason']})"
                    )
                    if scope["decision"] == "noop":
                        plan_name = _init_plan(
                            root,
                            milestone.idea,
                            robustness=eff_robustness,
                            auto_approve=spec.auto_approve,
                            profile=eff_profile,
                            vendor=milestone.vendor,
                            depth=eff_depth,
                            critic=milestone.critic,
                            deepseek_provider=milestone.deepseek_provider,
                            with_prep=milestone.with_prep,
                            with_feedback=milestone.with_feedback,
                            prep_clarify=milestone.prep_clarify,
                            prep_direction=milestone.prep_direction,
                            phase_model=milestone.phase_model,
                            writer=writer,
                        )
                        _write_chain_policy_into_plan_meta(
                            root, plan_name, spec, spec_path, milestone.label
                        )
                        _attach_chain_anchors_to_plan(
                            root, spec_path, plan_name, spec, milestone
                        )
                        plan_dir = resolve_plan_dir(root, plan_name)
                        compute_reconcile_scope(
                            spec,
                            manifest,
                            root=root,
                            chain_base_sha=state.target_base_ref,
                            manifest_path=manifest_path,
                            plan_dir=plan_dir,
                            plan_name=plan_name,
                            milestone_label=milestone.label,
                        )
                        # Deliberately NOT persisted as the active plan before
                        # the completion append: a crash in this window must
                        # re-run the fresh-path skip (idempotent re-init +
                        # re-write of the waiver) instead of resuming the plan
                        # and driving the agent for a verified no-op.
                        _emit_milestone_start_evidence(
                            state,
                            milestone_label=milestone.label,
                            milestone_index=idx,
                            plan_name=plan_name,
                        )
                        completed_record = {
                            "label": milestone.label,
                            "plan": plan_name,
                            "status": STATE_DONE,
                            "pr_number": None,
                            "pr_state": None,
                            "kind": "reconcile",
                            "target_branch": milestone.target_branch,
                            "reconcile_verification": scope["decision"],
                        }
                        appended, reason = _append_completed_with_guard(
                            root,
                            state,
                            completed_record,
                            implementation_milestone=True,
                            writer=writer,
                        )
                        if not appended:
                            return _handle_completion_guard_failure(
                                root=root,
                                spec_path=spec_path,
                                spec=spec,
                                state=state,
                                milestone=milestone,
                                plan_name=plan_name,
                                outcome_status="reconcile_noop",
                                reason=reason,
                                events=events,
                                writer=writer,
                            )
                        _mark_plan_completed_by_chain(
                            root,
                            plan_name,
                            milestone_label=milestone.label,
                            completion_reason=reason,
                            writer=writer,
                            state=state,
                        )
                        idx += 1
                        _mark_chain_after_milestone_advance(
                            spec, state, next_index=idx
                        )
                        chain_spec.save_chain_state(spec_path, state)
                        _emit_milestone_completion_evidence(
                            state,
                            milestone_label=milestone.label,
                            milestone_index=idx - 1,
                            plan_name=plan_name,
                        )
                        if idx >= len(spec.milestones):
                            _emit_chain_complete_evidence(state, spec=spec)
                        chain_spec.save_chain_state(spec_path, state)
                        if one:
                            return _result(
                                "paused",
                                state,
                                events,
                                spec=spec,
                                reason=(
                                    f"completed one milestone: {milestone.label}"
                                ),
                            )
                        continue
                if use_pr:
                    base_ref = _checkout_milestone_branch(
                        root,
                        milestone.branch or "",
                        base_branch=_reconcile_target_branch(milestone, spec),
                        writer=writer,
                        from_origin=push_enabled and not no_git_refresh,
                        expected_base_ref=state.target_base_ref,
                    )
                    if isinstance(base_ref, str) and base_ref:
                        state.target_base_ref = base_ref
                        chain_spec.save_chain_state(spec_path, state)
                    _capture_sync_state(
                        root, spec_path, branch=milestone.branch, pr_number=None
                    )
                    state = chain_spec.load_chain_state(spec_path)
                if (
                    eff_profile != milestone.profile
                    or eff_robustness != (milestone.robustness or spec.robustness)
                    or eff_depth != milestone.depth
                ):
                    log(
                        f"milestone {milestone.label} using bumped tiers "
                        f"profile={eff_profile} robustness={eff_robustness} depth={eff_depth}"
                    )
                plan_name = _init_plan(
                    root,
                    milestone.idea,
                    robustness=eff_robustness,
                    auto_approve=spec.auto_approve,
                    profile=eff_profile,
                    vendor=milestone.vendor,
                    depth=eff_depth,
                    critic=milestone.critic,
                    deepseek_provider=milestone.deepseek_provider,
                    with_prep=milestone.with_prep,
                    with_feedback=milestone.with_feedback,
                    prep_clarify=milestone.prep_clarify,
                    prep_direction=milestone.prep_direction,
                    phase_model=milestone.phase_model,
                    writer=writer,
                )
                # Record effective chain policy in the newly initialized plan's
                # state.json metadata so downstream consumers can introspect it.
                _write_chain_policy_into_plan_meta(
                    root, plan_name, spec, spec_path, milestone.label
                )
                _attach_chain_anchors_to_plan(root, spec_path, plan_name, spec, milestone)
                # P6 reconcile executor inputs: a kind:reconcile milestone's
                # execute step is a SELECTION task — write the rubric docs +
                # git log --first-parent + candidate commits marker so the
                # execute path renders the reconcile prompt.
                _write_reconcile_plan_inputs(
                    root,
                    plan_name,
                    spec,
                    milestone,
                    state=state,
                    writer=writer,
                )
                state.current_milestone_index = idx
                state.current_plan_name = plan_name
                # The chain cursor and lifecycle projection must move together.
                # Leaving the predecessor's terminal ``last_state`` in place
                # makes a live successor look canonically complete to repair
                # and resident consumers until the entire plan driver returns.
                state.last_state = (
                    _plan_current_state_from_payload(root, plan_name) or "initialized"
                )
                _emit_milestone_start_evidence(
                    state,
                    milestone_label=milestone.label,
                    milestone_index=idx,
                    plan_name=plan_name,
                )
                chain_spec.save_chain_state(spec_path, state)
                fresh_admission = _ensure_fresh_child_for_plan(
                    root=root,
                    spec_path=spec_path,
                    spec=spec,
                    state=state,
                    milestone=milestone,
                    milestone_index=idx,
                    plan_name=plan_name,
                )
                if fresh_admission is not None:
                    chain_spec.save_chain_state(spec_path, state)
                _emit_chain_work_boundary(
                    "chain_session_start",
                    plan_name=plan_name,
                    metadata={
                        "boundary": "milestone_init",
                        "milestone_label": milestone.label,
                        "milestone_index": idx,
                    },
                )
                _emit_chain_work_boundary(
                    "transition",
                    plan_name=plan_name,
                    from_state=None,
                    to_state=STATE_PREPPED,
                    metadata={
                        "transition": "chain_milestone_init",
                        "milestone_label": milestone.label,
                        "milestone_index": idx,
                    },
                )
                if use_pr:
                    _git_start = time.monotonic()
                    _commit_and_push_phase(
                        root,
                        milestone.branch or "",
                        plan_name,
                        "init",
                        writer=writer,
                        preexisting_dirty_paths=preexisting_dirty_paths,
                    )
                    _emit_chain_work_boundary(
                        "git",
                        plan_name=plan_name,
                        operation="chain_commit_and_push_init",
                        elapsed_ms=max(0, int((time.monotonic() - _git_start) * 1000)),
                        metadata={
                            "milestone_label": milestone.label,
                            "milestone_index": idx,
                            "branch": milestone.branch,
                        },
                    )
                    _capture_sync_state(
                        root, spec_path, branch=milestone.branch, pr_number=state.pr_number
                    )
                    state = chain_spec.load_chain_state(spec_path)
                    state.pr_number = _ensure_pr_for_milestone(
                        root,
                        spec,
                        state,
                        milestone,
                        writer=writer,
                    )
                    state.pr_state = "open"
                    chain_spec.save_chain_state(spec_path, state)
        except CliError as exc:
            if exc.code == "missing_base_ref":
                return _handle_missing_base_ref(
                    root,
                    spec_path,
                    state,
                    spec=spec,
                    events=events,
                    milestone_label=milestone.label,
                    error=exc,
                )
            raise

        from arnold_pipelines.megaplan.chain.target_rebind import (
            assert_chain_project_source_binding,
        )

        assert_chain_project_source_binding(
            root,
            state,
            plan_name=plan_name,
            operation=f"resume milestone {milestone.label}",
        )

        fresh_admission = _ensure_fresh_child_for_plan(
            root=root,
            spec_path=spec_path,
            spec=spec,
            state=state,
            milestone=milestone,
            milestone_index=idx,
            plan_name=plan_name,
        )
        if fresh_admission is not None:
            chain_spec.save_chain_state(spec_path, state)

        def terminal_child(outcome_kind: str, outcome_status: str) -> None:
            _terminalize_fresh_child_for_plan(
                root=root,
                state=state,
                milestone=milestone,
                milestone_index=idx,
                plan_name=plan_name,
                outcome_kind=outcome_kind,
                outcome_status=outcome_status,
            )

        # P6 reconcile executor inputs (idempotent re-write covers both the
        # fresh-init and the crash-resume path; harmless for other kinds).
        _write_reconcile_plan_inputs(
            root,
            plan_name,
            spec,
            milestone,
            state=state,
            writer=writer,
        )

        def phase_callback(phase: str, _code: int, _out: str, _err: str) -> None:
            if use_pr and milestone.branch:
                _git_start = time.monotonic()
                _commit_and_push_phase(
                    root,
                    milestone.branch,
                    plan_name,
                    phase,
                    writer=writer,
                    preexisting_dirty_paths=preexisting_dirty_paths,
                )
                _emit_chain_work_boundary(
                    "git",
                    plan_name=plan_name,
                    operation=f"chain_commit_and_push_{phase}",
                    phase=phase,
                    elapsed_ms=max(0, int((time.monotonic() - _git_start) * 1000)),
                    metadata={
                        "milestone_label": milestone.label,
                        "milestone_index": idx,
                        "branch": milestone.branch,
                        "phase_returncode": _code,
                    },
                )
                _capture_sync_state(
                    root, spec_path, branch=milestone.branch, pr_number=state.pr_number
                )

        outcome = _drive_plan_with_blocked_execute_recovery(
            root,
            spec_path,
            plan_name,
            spec,
            on_phase_complete=phase_callback if use_pr else None,
            writer=writer,
        )
        if outcome.status == "stalled":
            reconciled_state = _plan_current_state_from_payload(root, plan_name)
            terminal_good = {"done", STATE_FINALIZED}
            if reconciled_state in terminal_good:
                writer(
                    f"[chain] driver reported {outcome.status!r} for {plan_name}, "
                    f"but plan state.json is {reconciled_state!r}; reconciling "
                    "to advance\n"
                )
                outcome.reason = (
                    f"reconciled from {outcome.status} via plan "
                    f"state.json={reconciled_state}"
                )
                outcome.status = "done"
        state = _record_chain_last_state_after_plan_run(
            root,
            spec_path,
            state,
            outcome,
            writer=writer,
        )
        decision = _handle_outcome(
            outcome,
            spec=spec,
            writer=writer,
            milestone=milestone,
            state=state,
            root=root,
            spec_path=spec_path,
        )
        if decision == "authority_blocked":
            terminal_child("BLOCKED", "authority_divergence")
            state.last_state = "authority_divergence"
            chain_spec.save_chain_state(spec_path, state)
            return _result(
                "blocked",
                state,
                events,
                spec=spec,
                reason=f"milestone {milestone.label} terminal outcome lacks authority",
            )
        if decision in {"advance", "skip"}:
            authoritative, reason = _plan_terminal_completion_is_authoritative(
                root, plan_name
            )
            if not authoritative:
                terminal_child("BLOCKED", "task_authority_divergence")
                writer(
                    f"[chain] milestone {milestone.label} outcome={outcome.status} "
                    f"lacks task authority; stopping: {reason}\n"
                )
                # Record a plan-level rerun cursor so the standard
                # recover-blocked / resume loop can re-dispatch the genuinely
                # blocked tasks instead of stranding the plan terminal-done
                # with no recovery seam (shadow contract publishes done before
                # the chain's fail-closed task-authority check runs).
                _record_chain_authority_divergence_cursor(
                    root, plan_name, reason, writer=writer
                )
                state.last_state = "authority_divergence"
                chain_spec.save_chain_state(spec_path, state)
                return _result(
                    "blocked",
                    state,
                    events,
                    spec=spec,
                    reason=(
                        f"milestone {milestone.label} terminal outcome lacks authority: "
                        f"{reason}"
                    ),
                )

        if decision == "stop":
            terminal_child(
                (
                    "BLOCKED"
                    if outcome.status in {"blocked", "stalled", "awaiting_human"}
                    else "FAILED"
                ),
                outcome.status,
            )
            _maybe_file_ladder_ticket(
                root, spec_path, milestone, outcome, state, writer=writer
            )
            chain_spec.save_chain_state(spec_path, state)
            return _result(
                "stopped",
                state,
                events,
                spec=spec,
                reason=f"milestone {milestone.label} ended {outcome.status}",
            )
        if decision == "retry":
            resumable_state = _resumable_retry_state(root, state.current_plan_name)
            if resumable_state is not None:
                log(
                    f"retrying milestone {milestone.label} by resuming plan "
                    f"{state.current_plan_name} from {resumable_state}"
                )
                _emit_chain_work_boundary(
                    "retry_wait",
                    plan_name=state.current_plan_name,
                    elapsed_ms=0,
                    metadata={
                        "milestone_label": milestone.label,
                        "retry_strategy": "resume_milestone",
                        "resumable_state": resumable_state,
                    },
                )
            else:
                log(f"retrying milestone {milestone.label}")
                _emit_chain_work_boundary(
                    "retry_wait",
                    plan_name=state.current_plan_name,
                    elapsed_ms=0,
                    metadata={
                        "milestone_label": milestone.label,
                        "retry_strategy": "reinit_milestone",
                    },
                )
                _preserve_carried_wip_before_retry(
                    root,
                    spec_path,
                    state,
                    milestone,
                    state.current_plan_name,
                    writer=writer,
                )
                state.current_plan_name = None  # force re-init next loop
            state.pr_number = None
            state.pr_state = None
            chain_spec.save_chain_state(spec_path, state)
            continue
        full_suite_backstop_gate: dict[str, Any] | None = None
        full_suite_backstop_summary: dict[str, Any] | None = None
        if decision == "advance" and outcome.status == "done":
            full_suite_backstop_gate = _run_full_suite_backstop_gate(
                root,
                spec_path,
                plan_name,
                milestone.label,
                state.full_suite_backstop_mode,
                log_fn=log,
            )
            full_suite_backstop_summary = full_suite_backstop_gate.get("summary")
            if full_suite_backstop_gate.get("blocks"):
                result = full_suite_backstop_gate.get("result")
                newly_failing = []
                deleted_tests = []
                if isinstance(result, dict):
                    if isinstance(result.get("newly_failing"), list):
                        newly_failing = result["newly_failing"]
                    if isinstance(result.get("deleted_tests"), list):
                        deleted_tests = result["deleted_tests"]
                failing_suffix = (
                    f"; newly_failing={newly_failing[:10]}"
                    if newly_failing
                    else (
                        f"; deleted_tests={deleted_tests[:10]}" if deleted_tests else ""
                    )
                )
                terminal_child("BLOCKED", "full_suite_backstop_blocked")
                chain_spec.save_chain_state(spec_path, state)
                return _result(
                    "blocked",
                    state,
                    events,
                    spec=spec,
                    reason=(
                        f"full_suite_backstop_mode=enforce: milestone "
                        f"{milestone.label!r} blocked before advance; see "
                        f"{plan_name}/full_suite_backstop.json{failing_suffix}"
                    ),
                )
        local_commit_sha: str | None = None
        if decision == "advance" and outcome.status == "done":
            current_source_state = chain_spec.load_chain_state(spec_path)
            assert_chain_project_source_binding(
                root,
                current_source_state,
                plan_name=plan_name,
                operation=f"complete milestone {milestone.label}",
            )
        if (
            decision == "advance"
            and outcome.status == "done"
            and not use_pr
            and mode != "plan"
        ):
            _git_start = time.monotonic()
            local_commit_sha = _commit_phase(
                root,
                plan_name,
                "done",
                writer=writer,
                preexisting_dirty_paths=preexisting_dirty_paths,
            )
            _emit_chain_work_boundary(
                "git",
                plan_name=plan_name,
                operation="chain_commit_done",
                elapsed_ms=max(0, int((time.monotonic() - _git_start) * 1000)),
                metadata={
                    "milestone_label": milestone.label,
                    "milestone_index": idx,
                    "commit_sha": local_commit_sha,
                },
            )
        if (
            decision == "advance"
            and use_pr
            and _is_reconcile_milestone(milestone)
        ):
            # P6: a reconcile milestone's PR must carry the cherry-picked
            # engine commits, so the controller publishes the executor's
            # selection AFTER the plan completes and BEFORE the PR-ready /
            # await-merge flow.  Fail-closed: no selection evidence, an
            # unreachable SHA, a cherry-pick conflict, or a missing gh
            # executable blocks the milestone (never a silent no-op).
            state = chain_spec.load_chain_state(spec_path)
            publish_reason = _publish_reconcile_selection(
                root,
                spec_path,
                spec,
                state,
                milestone,
                plan_dir=resolve_plan_dir(root, plan_name),
                writer=writer,
                log=log,
            )
            if publish_reason is not None:
                terminal_child("BLOCKED", "reconcile_publication_blocked")
                state.last_state = STATE_BLOCKED
                chain_spec.save_chain_state(spec_path, state)
                return _result(
                    "blocked",
                    state,
                    events,
                    spec=spec,
                    reason=publish_reason,
                )
            state = chain_spec.load_chain_state(spec_path)
        if decision == "advance" and use_pr and state.pr_number is not None:
            _git_start = time.monotonic()
            _commit_and_push_phase(
                root,
                milestone.branch or "",
                plan_name,
                "done",
                writer=writer,
                preexisting_dirty_paths=preexisting_dirty_paths,
            )
            _emit_chain_work_boundary(
                "git",
                plan_name=plan_name,
                operation="chain_commit_and_push_done",
                elapsed_ms=max(0, int((time.monotonic() - _git_start) * 1000)),
                metadata={
                    "milestone_label": milestone.label,
                    "milestone_index": idx,
                    "branch": milestone.branch,
                    "pr_number": state.pr_number,
                },
            )
            _capture_sync_state(
                root, spec_path, branch=milestone.branch, pr_number=state.pr_number
            )
            state = chain_spec.load_chain_state(spec_path)
            # The atomic acceptance transaction may have committed the
            # completed record and advanced the durable cursor before the
            # publication/sync refresh above reloaded ChainState. In that
            # case PR context is intentionally cleared by the same
            # transaction. Re-check the accepted durable boundary instead of
            # passing ``None`` to gh and manufacturing a closed PR.
            accepted_during_sync = next(
                (
                    record
                    for record in state.completed
                    if isinstance(record, dict)
                    and record.get("label") == milestone.label
                    and record.get("status") == STATE_DONE
                    and record.get("pr_number") is None
                    and record.get("publication_evidence")
                    == "local_no_push_reconciliation"
                    and record.get("local_commit_sha")
                ),
                None,
            )
            if (
                accepted_during_sync is not None
                and state.current_milestone_index > idx
                and state.pr_number is None
            ):
                accepted, accepted_reason = _chain_completion_guard(
                    root,
                    accepted_during_sync,
                    implementation_milestone=True,
                    chain_state=state,
                )
                if not accepted:
                    terminal_child("BLOCKED", "completion_revalidation_blocked")
                    state.last_state = STATE_BLOCKED
                    chain_spec.save_chain_state(spec_path, state)
                    return _result(
                        "blocked",
                        state,
                        events,
                        spec=spec,
                        reason=(
                            f"milestone {milestone.label} durable local completion "
                            f"failed revalidation after sync: {accepted_reason}"
                        ),
                    )
                log(
                    f"milestone {milestone.label} advanced by accepted local "
                    "completion during sync; continuing without PR metadata"
                )
                terminal_child("COMPLETED", outcome.status)
                _mark_plan_completed_by_chain(
                    root,
                    plan_name,
                    milestone_label=milestone.label,
                    completion_reason=accepted_reason,
                    writer=writer,
                    state=state,
                )
                idx = state.current_milestone_index
                _emit_milestone_completion_evidence(
                    state,
                    milestone_label=milestone.label,
                    milestone_index=idx - 1,
                    plan_name=plan_name,
                )
                chain_spec.save_chain_state(spec_path, state)
                if one:
                    return _result(
                        "paused",
                        state,
                        events,
                        spec=spec,
                        reason=f"completed one milestone: {milestone.label}",
                    )
                continue
            current_pr_state = _pr_state(root, state.pr_number, writer=writer)
            if current_pr_state == "merged":
                state.pr_state = "merged"
                chain_spec.save_chain_state(spec_path, state)
                if _is_reconcile_milestone(milestone):
                    _delete_reconcile_pr_branch_for(milestone, root, writer=writer)
                    _record_reconcile_outcome(
                        state,
                        outcome="merged",
                        reason=f"reconcile PR #{state.pr_number} merged into "
                        f"{_reconcile_target_branch(milestone, spec)}",
                    )
            elif current_pr_state == "closed":
                if _is_reconcile_milestone(milestone):
                    blocked = _advance_reconcile_rejected(
                        root,
                        spec_path,
                        spec,
                        state,
                        milestone,
                        events,
                        pr_number=state.pr_number,
                        writer=writer,
                        log=log,
                    )
                    if blocked is not None:
                        return blocked
                    continue
                log(f"PR #{state.pr_number} closed during milestone completion; stopping chain")
                terminal_child("BLOCKED", "pull_request_closed")
                return _stop_for_closed_pr(
                    spec_path=spec_path,
                    state=state,
                    events=events,
                    spec=spec,
                    milestone_label=milestone.label,
                    pr_number=state.pr_number,
                )
            else:
                pending_merge_record = {
                    "label": milestone.label,
                    "plan": plan_name,
                    "status": outcome.status,
                    "pr_number": state.pr_number,
                    "pr_state": current_pr_state,
                }
                premerge_ok, premerge_reason = _chain_completion_guard(
                    root,
                    pending_merge_record,
                    implementation_milestone=True,
                    chain_state=state,
                )
                if not premerge_ok:
                    # Auto-merge can complete between the first PR observation
                    # and this (potentially expensive) authority check.  A
                    # merged PR has stronger publication evidence than an open
                    # one, so re-read external truth before persisting a stale
                    # blocked cursor.  The normal completed-record guard below
                    # still validates the merged publication; no authority
                    # requirement is weakened here.
                    latest_pr_state = _pr_state(
                        root, state.pr_number, writer=writer
                    )
                    if latest_pr_state == "merged":
                        state.pr_state = "merged"
                        chain_spec.save_chain_state(spec_path, state)
                        log(
                            f"PR #{state.pr_number} merged while completion guard "
                            f"was evaluating; reconciling {milestone.label} from "
                            "published evidence"
                        )
                    else:
                        terminal_child("BLOCKED", "premerge_completion_guard_blocked")
                        writer(
                            f"[chain] completion guard blocked {milestone.label} before "
                            f"PR merge: {premerge_reason}\n"
                        )
                        state.last_state = STATE_BLOCKED
                        state.pr_state = latest_pr_state
                        chain_spec.save_chain_state(spec_path, state)
                        return _result(
                            "stopped",
                            state,
                            events,
                            spec=spec,
                            reason=(
                                f"milestone {milestone.label} completion guard blocked "
                                f"before PR merge: {premerge_reason}"
                            ),
                        )
                else:
                    validation_evidence = _validate_pr_progression_wbc(
                        root=root,
                        spec_path=spec_path,
                        state=state,
                        milestone=milestone,
                        plan_name=plan_name,
                        pr_number=state.pr_number,
                        transition_name="chain_pr_ready",
                    )
                    _pr_ready_evidence = _capture_pr_ready_evidence(
                        root,
                        state.pr_number,
                        writer=writer,
                        ci_readiness_state="ready",
                        validation_evidence=validation_evidence,
                    )
                    _mark_pr_ready(root, state.pr_number, writer=writer)
                    if not _automatic_pr_progression_permitted(spec, spec_path):
                        state.last_state = STATE_AWAITING_PR_MERGE
                        state.pr_state = current_pr_state
                        chain_spec.save_chain_state(spec_path, state)
                        policy = policy_for_spec(
                            spec,
                            runtime_overrides=chain_spec.load_runtime_policy(spec_path),
                        )
                        log(
                            f"PR #{state.pr_number} ready; awaiting human review/merge "
                            f"(merge_policy={policy.merge_policy}, "
                            f"clean_milestone_pr={policy.clean_milestone_pr})"
                        )
                        _capture_sync_state(
                            root,
                            spec_path,
                            branch=milestone.branch,
                            pr_number=state.pr_number,
                        )
                        return _result(
                            STATE_AWAITING_PR_MERGE,
                            state,
                            events,
                            spec=spec,
                            reason=f"milestone {milestone.label} PR #{state.pr_number} awaiting merge",
                        )
                    state.pr_state = _enable_auto_merge(
                        root, state.pr_number, writer=writer
                    )
                    _pr_merged_evidence = _capture_pr_merged_evidence(
                        root,
                        state.pr_number,
                        writer=writer,
                        validation_evidence=validation_evidence,
                    )
                    chain_spec.save_chain_state(spec_path, state)
                    if state.pr_state != "merged":
                        # Enabling auto-merge is not publication evidence. GitHub
                        # may leave the PR open while checks or the merge queue
                        # run, so never append completion until external truth
                        # reports the PR as merged.
                        latest_pr_state = _pr_state(
                            root, state.pr_number, writer=writer
                        )
                        if latest_pr_state == "merged":
                            state.pr_state = "merged"
                            chain_spec.save_chain_state(spec_path, state)
                        else:
                            state.last_state = STATE_AWAITING_PR_MERGE
                            state.pr_state = latest_pr_state
                            chain_spec.save_chain_state(spec_path, state)
                            return _result(
                                STATE_AWAITING_PR_MERGE,
                                state,
                                events,
                                spec=spec,
                                reason=(
                                    f"milestone {milestone.label} PR "
                                    f"#{state.pr_number} auto-merge pending"
                                ),
                            )
        # Completion-verification contract (SHADOW-MODE, fail-open): compute +
        # persist + log a milestone-level verdict. NEVER alters the append,
        # NEVER blocks the chain, NEVER runs the suite. See
        # megaplan/orchestration/completion_contract.py.
        enforce_blocked = _shadow_milestone_completion_verdict(
            root,
            plan_name,
            milestone.label,
            outcome.status,
            state.completion_contract_mode,
            log_fn=log,
        )
        if enforce_blocked:
            max_retries = 2
            try:
                plan_dir = resolve_plan_dir(root, plan_name)
                raw_state = json.loads(
                    (plan_dir / "state.json").read_text(encoding="utf-8")
                )
                if isinstance(raw_state, dict):
                    cfg = (
                        raw_state.get("config", {})
                        if isinstance(raw_state.get("config"), dict)
                        else {}
                    )
                    max_retries = int(cfg.get("enforce_revise_max_retries", 2))
            except Exception:
                pass

            milestone_retry_count = int(
                state.enforce_revise_counts.get(milestone.label, 0)
            )
            if milestone_retry_count >= max_retries:
                terminal_child("BLOCKED", "completion_contract_retry_exhausted")
                log(
                    f"completion_contract_mode=enforce: milestone {milestone.label!r} "
                    f"blocked; retry cap {max_retries} exhausted — operator action required"
                )
                chain_spec.save_chain_state(spec_path, state)
                return _result(
                    "blocked",
                    state,
                    events,
                    spec=spec,
                    reason=(
                        f"enforce block: milestone {milestone.label!r} revise retry cap "
                        f"({max_retries}) exhausted — operator action required"
                    ),
                )

            state.enforce_revise_counts[milestone.label] = milestone_retry_count + 1
            log(
                f"completion_contract_mode=enforce: milestone {milestone.label!r} blocked — "
                f"retry {milestone_retry_count + 1}/{max_retries}"
            )
            state.current_plan_name = None
            state.pr_number = None
            state.pr_state = None
            chain_spec.save_chain_state(spec_path, state)
            continue
        if (
            decision == "advance"
            and full_suite_backstop_gate is not None
            and not full_suite_backstop_gate.get("blocks")
        ):
            result = full_suite_backstop_gate.get("result")
            if isinstance(result, dict):
                if _persist_full_suite_backstop_baseline(
                    spec_path,
                    result,
                    captured_at_sha=_current_head_sha(root),
                    milestone_label=milestone.label,
                ):
                    log(
                        "full_suite_backstop baseline updated "
                        f"milestone={milestone.label}"
                    )
        # advance or skip
        completed_record = {
            "label": milestone.label,
            "plan": plan_name,
            "status": outcome.status,
            "pr_number": state.pr_number,
            "pr_state": state.pr_state,
            **_reconcile_record_fields(milestone, spec),
        }
        if local_commit_sha is not None:
            completed_record["local_commit_sha"] = local_commit_sha
            completed_record["plan_branch"] = spec.base_branch
        if full_suite_backstop_summary is not None:
            completed_record["full_suite_backstop"] = full_suite_backstop_summary
        validation_reason = _run_milestone_validations_blocking(
            root=root,
            spec_path=spec_path,
            spec=spec,
            state=state,
            milestone=milestone,
            writer=writer,
            refresh_base=False,
            no_git_refresh=no_git_refresh,
        )
        if validation_reason is not None:
            terminal_child("BLOCKED", "milestone_validation_blocked")
            return _result(
                "blocked",
                state,
                events,
                spec=spec,
                reason=validation_reason,
            )
        appended, reason = _append_completed_with_guard(
            root,
            state,
            completed_record,
            implementation_milestone=True,
            writer=writer,
        )
        if not appended:
            terminal_child("BLOCKED", "completion_guard_blocked")
            return _handle_completion_guard_failure(
                root=root,
                spec_path=spec_path,
                spec=spec,
                state=state,
                milestone=milestone,
                plan_name=plan_name,
                outcome_status=outcome.status,
                reason=reason,
                events=events,
                writer=writer,
            )
        terminal_child("COMPLETED", outcome.status)
        _mark_plan_completed_by_chain(
            root,
            plan_name,
            milestone_label=milestone.label,
            completion_reason=reason,
            writer=writer,
            state=state,
        )
        idx += 1
        _mark_chain_after_milestone_advance(spec, state, next_index=idx)
        chain_spec.save_chain_state(spec_path, state)
        manifest_reason = _finalize_validation_artifacts_after_done_append(
            root=root,
            spec_path=spec_path,
            spec=spec,
            state=state,
            milestone=milestone,
            writer=writer,
        )
        if manifest_reason is not None:
            return _result(
                "blocked",
                state,
                events,
                spec=spec,
                reason=manifest_reason,
            )
        _emit_milestone_completion_evidence(
            state,
            milestone_label=milestone.label,
            milestone_index=idx - 1,
            plan_name=plan_name,
        )
        if idx >= len(spec.milestones):
            _emit_chain_complete_evidence(state, spec=spec)
        chain_spec.save_chain_state(spec_path, state)
        if one:
            log(f"paused after milestone {milestone.label}")
            return _result(
                "paused",
                state,
                events,
                spec=spec,
                reason=f"completed one milestone: {milestone.label}",
            )

    log("all milestones complete")
    # ── P6 terminal finalizer ─────────────────────────────────────────
    # Close + sweep the epic runtime ONLY after the reconcile milestone
    # reached a terminal outcome (merged / intentionally rejected / verified
    # no-op) with no PR awaiting — never after unknown PR state, missing gh
    # auth, or interrupted publication (P6 terminal-state rules, correction
    # #6).  Runs arnold-close then arnold-gc-sweep --restore-proven
    # --fixer-branch; idempotent across crashes (manifest state=closed +
    # worktree gone ⇒ already finalized).
    finalizer_block = _run_reconcile_terminal_finalizer(
        root=root,
        spec_path=spec_path,
        spec=spec,
        state=state,
        events=events,
        writer=writer,
        log=log,
    )
    if finalizer_block is not None:
        return finalizer_block
    # ── Successor gate check ──────────────────────────────────────────
    # In fail-closed (atomic/enforce) mode a completed chain must carry a
    # validated acceptance receipt for its final milestone before any
    # declared successor may be initialised.  The gate is generic – it
    # reads SuccessorSpec declarations from the chain YAML rather than
    # hardcoding initiative names (M5→M5A→M6 is the first consumer).
    successor_block = _check_successor_gate_at_chain_completion(
        state, spec, spec_path, events, writer=writer
    )
    if successor_block is not None:
        return successor_block
    return _result("done", state, events, spec=spec)


RECONCILE_INPUTS_FILENAME = "reconcile_inputs.json"


def _write_reconcile_plan_inputs(
    root: Path,
    plan_name: str,
    spec: ChainSpec,
    milestone: MilestoneSpec,
    *,
    state: ChainState,
    writer,
) -> None:
    """Write ``reconcile_inputs.json`` into a reconcile milestone's plan dir.

    The execute worker for a ``kind: reconcile`` milestone is a SELECTION task
    (JSON of chosen commit SHAs + verification evidence), not a generic
    implementation batch: the generic execute prompt cannot carry the rubric
    docs, ``git log --first-parent``, and the candidate commit list.  This
    marker file lets the execute path (``execute/batch.py``) switch to
    ``render_reconcile_prompt`` for this plan.  Best-effort: any failure
    leaves the plan on the generic prompt rather than blocking the chain.
    """
    if not _is_reconcile_milestone(milestone):
        return
    try:
        plan_dir = resolve_plan_dir(root, plan_name)
    except CliError:
        return
    rubric_paths = [
        root / "docs" / "megaplan-reference-architecture-20260807.md",
        root / "docs" / "per-epic-runtime-end-state-20260809.md",
    ]
    rubric_docs: list[str] = []
    for path in rubric_paths:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if text.strip():
            rubric_docs.append(text)
    first_parent_log = ""
    proc = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "log",
            "--first-parent",
            "--format=%H %s",
            "-n",
            "200",
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode == 0:
        first_parent_log = (proc.stdout or "").strip()
    # Candidate commits: the controller-side engine-source change set (same
    # allowlist the skip detector uses); empty on any compute failure.
    candidate_commits: list[dict[str, Any]] = []
    try:
        scope = compute_reconcile_scope(
            spec,
            None,
            root=root,
            chain_base_sha=state.target_base_ref,
        )
        engine_changes = scope.get("engine_changes")
        if isinstance(engine_changes, list):
            candidate_commits = [
                change
                for change in engine_changes
                if isinstance(change, dict)
                and isinstance(change.get("sha"), str)
                and change["sha"].strip()
            ]
    except Exception:  # noqa: BLE001 - best-effort marker
        candidate_commits = []
    payload = {
        "rubric_docs": rubric_docs,
        "first_parent_log": first_parent_log,
        "candidate_commits": candidate_commits,
        "target_branch": (
            milestone.target_branch
            if isinstance(milestone.target_branch, str) and milestone.target_branch.strip()
            else spec.base_branch
        ),
    }
    try:
        from arnold_pipelines.megaplan._core.io import atomic_write_json

        atomic_write_json(plan_dir / RECONCILE_INPUTS_FILENAME, payload)
    except Exception as exc:  # noqa: BLE001 - best-effort marker
        writer(
            f"[chain] warning: could not write {RECONCILE_INPUTS_FILENAME} "
            f"for {milestone.label}: {exc}\n"
        )


_GC_SWEEP_STANDALONE_MARKER_RE = re.compile(
    r"(?:gc-sweep:\s*)?SWEPT=(YES|NO(?::[A-Z0-9_-]+)?)\s+'([^']+)'"
)
_GC_SWEEP_EMBEDDED_MARKER_RE = re.compile(r"SWEPT=(YES|NO(?::[A-Z0-9_-]+)?)")
_GC_SWEEP_DECISION_RE = re.compile(
    r"^gc-sweep:\s+(SWEPT|SKIP|NEEDS-RECONCILE|UNKNOWN|REFUSE)\s+'([^']+)'"
)


def _sweep_reason_tail(text: str) -> str:
    rest = text.strip().lstrip("\u2014\u2013-").strip()
    return rest[:2000]


def _parse_gc_sweep_outcome(output: str, slug: str) -> tuple[str, str]:
    """Extract the sweep's decision for *slug* from its combined output.

    Keys on the machine-readable per-slug ``SWEPT=`` marker the sweep emits
    (G6 round-3 finding 1 protocol): ``SWEPT=YES '<slug>'`` as a standalone
    line on real deletion, and ``SWEPT=NO:<verdict>`` (REFERENCED /
    DANGLING / …) embedded in the SKIP / NEEDS-RECONCILE decision line on
    skip-but-alive.  UNKNOWN / REFUSE abort on stderr with no marker (they
    also exit non-zero).  Legacy ``gc-sweep: SWEPT/SKIP/NEEDS-RECONCILE/
    UNKNOWN/REFUSE '<slug>'`` decision lines without a marker are honored as
    a fallback, with marker-absent SKIP/NEEDS-RECONCILE treated as
    not-swept.  Returns ``(outcome, reason)``; defaults to ``UNKNOWN`` with
    an empty reason when no decision line names the slug (fail-closed:
    absence of proof that the runtime was removed is not removal — G6
    round-3 finding 2 / E5-F collapse-to-success).  ``SWEPT=YES`` outranks
    any later no-marker SKIP (e.g. a compatibility pointer manifest echoing
    the same slug after the real manifest was swept).
    """
    swept_yes_reason: str | None = None
    swept_no: tuple[str, str] | None = None
    decision: tuple[str, str] | None = None
    for line in output.splitlines():
        standalone = _GC_SWEEP_STANDALONE_MARKER_RE.match(line)
        if standalone and standalone.group(2) == slug:
            token = standalone.group(1)
            reason = _sweep_reason_tail(line[standalone.end() :])
            if token == "YES":
                swept_yes_reason = reason
            else:
                verdict = (
                    token[3:].strip().upper() or "SKIP"
                    if token.startswith("NO")
                    else "SKIP"
                )
                swept_no = (verdict if verdict.isalnum() else "SKIP", reason)
            continue
        matched = _GC_SWEEP_DECISION_RE.match(line)
        if not matched or matched.group(2) != slug:
            continue
        embedded = _GC_SWEEP_EMBEDDED_MARKER_RE.search(line)
        reason = _sweep_reason_tail(line[matched.end() :])
        if embedded:
            token = embedded.group(1)
            if token == "YES":
                swept_yes_reason = reason
            else:
                verdict = (
                    token[3:].strip().upper() or "SKIP"
                    if token.startswith("NO")
                    else "SKIP"
                )
                swept_no = (verdict if verdict.isalnum() else "SKIP", reason)
        else:
            decision = (matched.group(1), reason)
    if swept_yes_reason is not None:
        return "SWEPT", swept_yes_reason
    if swept_no is not None:
        return swept_no
    if decision is not None:
        return decision
    return "UNKNOWN", ""


def _run_reconcile_terminal_finalizer(
    *,
    root: Path,
    spec_path: Path,
    spec: ChainSpec,
    state: ChainState,
    events: list[dict[str, Any]],
    writer,
    log: Callable[[str], None],
) -> dict[str, Any] | None:
    """Idempotent terminal close+sweep once a ``kind: reconcile`` milestone is done.

    P6 terminal-state rules (correction #6): close+sweep run ONLY after the
    reconcile milestone reached a terminal outcome — PR **merged**,
    intentionally **rejected**, or **verified no-op** — with no PR awaiting.
    Never after unknown PR state, missing gh auth, or interrupted
    publication: any record that is not one of those three terminal outcomes
    (or an absent manifest binding) leaves the runtime untouched and returns
    ``None`` (the chain result is unaffected).

    On a terminal outcome it runs, in order:
      1. ``arnold-close <slug> <manifest>`` — verifies the fixer branch is
         pushed, creates + pushes the backstop tag, sets manifest
         state=closed (fail-loud: an epic is never closed without an
         origin-resolvable backstop snapshot).
      2. ``arnold-gc-sweep --restore-proven --fixer-branch <branch>
         <manifest-dir>`` — removes the worktree/venv and deletes the
         manifest-declared fixer branch local + remote (refuses while a pull
         ref still points at the branch head).

    Idempotent: a crash between close and sweep is healed on the next
    ``run_chain`` — close on a closed manifest is a no-op re-verify and the
    sweep SKIPs already-gone worktrees.  Returns a ``blocked`` result dict
    when close or sweep fails (the runtime must not be left half-torn), or
    ``None`` when there is nothing to finalize.

    ``swept: True`` is recorded ONLY when the sweep's output proves the
    runtime was actually removed (``SWEPT`` decision line for the slug — a
    CLEAR census outcome).  A skipped sweep (REFERENCED / DANGLING census
    verdicts or any other SKIP, exit 0) or a blocked sweep (UNKNOWN
    census / open-PR REFUSE / nonzero exit) records ``swept: False`` with
    the sweep outcome/reason and returns a ``blocked`` result — the
    completion guard never treats a skipped sweep as a successful close
    (G6 round-3 finding 2, E5/F collapse-to-success).
    """
    reconcile_milestones = [
        milestone for milestone in spec.milestones if _is_reconcile_milestone(milestone)
    ]
    if not reconcile_milestones:
        return None
    # The generated reconcile milestone is terminal; use the LAST one (a
    # hand-authored chain could only ever have one, but stay deterministic).
    milestone = reconcile_milestones[-1]
    record = None
    for candidate in state.completed:
        if (
            isinstance(candidate, dict)
            and candidate.get("label") == milestone.label
            and _record_is_reconcile(candidate)
        ):
            record = candidate
            break
    if record is None:
        log(
            f"[chain] reconcile milestone {milestone.label} has no terminal "
            "completion record; skipping close/sweep (nothing to finalize)"
        )
        return None

    merged = _completion_record_is_merged_pr(record)
    rejected = _record_is_intentionally_rejected(record)
    noop = record.get("reconcile_verification") == "noop"
    if not (merged or rejected or noop):
        log(
            f"[chain] reconcile milestone {milestone.label} record is not terminal "
            f"(pr_state={record.get('pr_state')!r}, status={record.get('status')!r}, "
            "reconcile_verification="
            f"{record.get('reconcile_verification')!r}); refusing close/sweep "
            "(P6 terminal-state rules: never close on unknown PR state)"
        )
        return None

    # No PR may be awaiting: a reconcile PR that is still open/unknown must
    # keep the chain parked, never trigger cleanup.
    if state.pr_number is not None or state.last_state == STATE_AWAITING_PR_MERGE:
        log(
            f"[chain] reconcile milestone {milestone.label} still has PR context "
            f"(pr_number={state.pr_number!r}, last_state={state.last_state!r}); "
            "deferring close/sweep"
        )
        return None

    manifest_path = chain_spec.session_runtime_manifest_path()
    if manifest_path is None:
        log(
            f"[chain] no session runtime manifest bound; skipping terminal "
            "close/sweep for reconcile milestone "
            f"{milestone.label} (local/dev run has no runtime to close)"
        )
        return None
    manifest_path = Path(manifest_path)
    try:
        manifest_path.stat()
    except FileNotFoundError:
        # stat() FOLLOWS symlinks, so a dangling symlink (target missing)
        # reports ENOENT even though the link entry itself exists.  lstat()
        # sees the entry itself: a link with a missing target is PRESENT but
        # unreadable and must fail closed — only a genuinely never-existing
        # path (lstat ENOENT too) counts as "already gone" (idempotent skip;
        # G5 round-5 finding 3(a): a dangling manifest must never collapse
        # to done on top of a broken runtime).
        try:
            manifest_path.lstat()
        except FileNotFoundError:
            log(
                f"[chain] runtime manifest {manifest_path} already gone — "
                "close/sweep already finalized (idempotent skip)"
            )
            return None
        except OSError as exc:  # noqa: BLE001 - lstat itself inaccessible
            return _result(
                "blocked",
                state,
                events,
                spec=spec,
                reason=(
                    f"reconcile terminal finalizer blocked: runtime manifest "
                    f"{manifest_path} present but unreadable (lstat failed: {exc})"
                ),
            )
        return _result(
            "blocked",
            state,
            events,
            spec=spec,
            reason=(
                f"reconcile terminal finalizer blocked: runtime manifest "
                f"{manifest_path} present but unreadable (dangling symlink)"
            ),
        )
    except OSError as exc:  # noqa: BLE001 - EACCES etc: absence unprovable
        return _result(
            "blocked",
            state,
            events,
            spec=spec,
            reason=(
                f"reconcile terminal finalizer blocked: runtime manifest "
                f"{manifest_path} present but unreadable (stat failed: {exc})"
            ),
        )

    try:
        from arnold_pipelines.megaplan.cloud.runtime_manifest import load_manifest

        manifest = load_manifest(manifest_path).to_dict()
    except Exception as exc:  # noqa: BLE001 - fail closed on unreadable manifest
        return _result(
            "blocked",
            state,
            events,
            spec=spec,
            reason=(
                f"reconcile terminal finalizer blocked: runtime manifest "
                f"{manifest_path} unreadable: {exc}"
            ),
        )
    slug = str(manifest.get("epic_id") or "").strip()
    fixer_branch = str((manifest.get("epic") or {}).get("branch") or "").strip()
    worktree = str((manifest.get("epic") or {}).get("worktree_path") or "").strip()
    manifest_state = str(manifest.get("state") or "").strip()
    if not slug or not fixer_branch:
        return _result(
            "blocked",
            state,
            events,
            spec=spec,
            reason=(
                f"reconcile terminal finalizer blocked: runtime manifest "
                f"{manifest_path} missing epic_id/epic.branch"
            ),
        )

    outcome = "merged" if merged else ("rejected" if rejected else "noop")
    log(
        f"[chain] reconcile milestone {milestone.label} terminal ({outcome}); "
        f"running close+sweep for runtime {slug} (fixer branch {fixer_branch})"
    )

    def _wrapper_binary(name: str) -> str | None:
        found = shutil.which(name)
        if found:
            return found
        candidate = Path(__file__).resolve().parents[1] / "cloud" / "wrappers" / name
        return str(candidate) if candidate.is_file() else None

    close_bin = _wrapper_binary("arnold-close")
    sweep_bin = _wrapper_binary("arnold-gc-sweep")
    if close_bin is None or sweep_bin is None:
        return _result(
            "blocked",
            state,
            events,
            spec=spec,
            reason=(
                "reconcile terminal finalizer blocked: lifecycle wrappers "
                f"arnold-close={'missing' if close_bin is None else 'ok'}, "
                f"arnold-gc-sweep={'missing' if sweep_bin is None else 'ok'} not "
                "found on PATH or in the package wrapper dir"
            ),
        )

    # ── 1. arnold-close ───────────────────────────────────────────────
    # Skip only when the manifest is ALREADY closed and the worktree is gone
    # (fully swept).  A closed manifest with a surviving worktree still needs
    # the sweep, so re-run close harmlessly (it re-verifies and no-ops).
    if manifest_state != "closed" or (worktree and Path(worktree).is_dir()):
        close = subprocess.run(
            [close_bin, slug, str(manifest_path)],
            capture_output=True,
            text=True,
        )
        if close.returncode != 0:
            return _result(
                "blocked",
                state,
                events,
                spec=spec,
                reason=(
                    f"reconcile terminal finalizer blocked: arnold-close failed "
                    f"(exit {close.returncode}): "
                    f"{(close.stderr or close.stdout or '').strip()[:2000]}"
                ),
            )
        log(f"[chain] arnold-close completed for runtime {slug}")
    else:
        log(
            f"[chain] arnold-close already complete for runtime {slug} "
            "(manifest closed, worktree gone)"
        )

    # ── 2. arnold-gc-sweep --restore-proven --fixer-branch ───────────
    sweep = subprocess.run(
        [
            sweep_bin,
            "--restore-proven",
            "--fixer-branch",
            fixer_branch,
            str(manifest_path.parent),
        ],
        capture_output=True,
        text=True,
    )
    sweep_output = (sweep.stdout or "") + "\n" + (sweep.stderr or "")
    sweep_outcome, sweep_reason = _parse_gc_sweep_outcome(sweep_output, slug)

    def _sweep_not_swept_evidence() -> dict[str, Any]:
        return {
            "milestone": milestone.label,
            "outcome": outcome,
            "slug": slug,
            "fixer_branch": fixer_branch,
            "manifest_path": str(manifest_path),
            "closed": True,
            "swept": False,
            "sweep_outcome": sweep_outcome,
            "sweep_reason": sweep_reason,
            "finalized_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    if sweep.returncode != 0:
        # Blocked: UNKNOWN census (exit 5), open-PR REFUSE (exit 3), or any
        # sweep failure.  The runtime was NOT removed — record the false
        # swept evidence and never report terminal completion (fail-closed;
        # G6 round-3 finding 2: a blocked sweep must not collapse to done).
        state.metadata["reconcile_terminal_finalizer"] = _sweep_not_swept_evidence()
        chain_spec.save_chain_state(spec_path, state)
        return _result(
            "blocked",
            state,
            events,
            spec=spec,
            reason=(
                f"reconcile terminal finalizer blocked: arnold-gc-sweep failed "
                f"(exit {sweep.returncode}): "
                f"{(sweep.stderr or sweep.stdout or '').strip()[:2000]}"
            ),
        )
    if sweep_outcome != "SWEPT":
        # The sweep exited 0 but did NOT remove this runtime (REFERENCED /
        # DANGLING census skips, schedule-store/origin/restore-proven skips,
        # already-gone root, or no decision line for the slug).  Record
        # swept:false and block — the completion guard must never treat a
        # skipped sweep as a successful close (E5/F collapse-to-success).
        state.metadata["reconcile_terminal_finalizer"] = _sweep_not_swept_evidence()
        chain_spec.save_chain_state(spec_path, state)
        return _result(
            "blocked",
            state,
            events,
            spec=spec,
            reason=(
                f"reconcile terminal finalizer blocked: arnold-gc-sweep did not "
                f"remove runtime {slug} (outcome {sweep_outcome}): "
                f"{sweep_reason or 'sweep skipped the runtime (see sweep output)'}"
            ),
        )
    log(f"[chain] arnold-gc-sweep completed for runtime {slug}")

    state.metadata["reconcile_terminal_finalizer"] = {
        "milestone": milestone.label,
        "outcome": outcome,
        "slug": slug,
        "fixer_branch": fixer_branch,
        "manifest_path": str(manifest_path),
        "closed": True,
        "swept": True,
        "sweep_outcome": sweep_outcome,
        "finalized_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    chain_spec.save_chain_state(spec_path, state)
    return None


def _check_successor_gate_at_chain_completion(
    state: ChainState,
    spec: ChainSpec,
    spec_path: Path,
    events: list[dict[str, Any]],
    *,
    writer,
) -> dict[str, Any] | None:
    """Check the successor gate when a chain completes all milestones.

    Returns a blocked result dict when the gate is closed (successor
    requires an accepted transaction but none is present), or ``None``
    when the gate is open / not applicable / not in fail-closed mode.

    The gate is generic: it reads ``SuccessorSpec`` declarations from
    the chain YAML rather than hardcoding initiative names.
    """
    successors = getattr(spec, "successors", None) or []
    if not successors:
        return None

    from arnold_pipelines.megaplan.orchestration.completion_contract import (
        is_fail_closed_mode,
        normalize_contract_mode,
    )

    mode = normalize_contract_mode(state.completion_contract_mode)
    if not is_fail_closed_mode(mode):
        return None  # shadow / warn / off — gate is always open

    any_require = any(
        getattr(s, "require_accepted_transaction", True) for s in successors
    )
    if not any_require:
        return None

    if not spec.milestones:
        return None

    final_milestone = spec.milestones[-1]
    has_receipt = state.has_acceptance_receipt(final_milestone.label)

    if has_receipt:
        # Gate is open — chain may advertise completion to successor init.
        return None

    writer(
        f"[chain] successor gate closed: chain is complete but no validated "
        f"acceptance receipt for final milestone {final_milestone.label!r}; "
        f"declared successors require acceptance evidence before initialisation\n"
    )
    return _result(
        "blocked",
        state,
        events,
        spec=spec,
        reason=(
            f"successor gate closed: chain complete but no acceptance receipt "
            f"for final milestone {final_milestone.label!r}"
        ),
    )


def _result(
    status: str,
    state: ChainState,
    events: list[dict[str, Any]],
    *,
    spec: ChainSpec | None = None,
    reason: str = "",
) -> dict[str, Any]:
    result = {
        "status": status,
        "reason": reason,
        "chain_state": state.to_dict(),
        "events": events,
    }
    if spec is not None:
        result["base_branch"] = spec.base_branch
    return result


def _stop_for_closed_pr(
    *,
    spec_path: Path,
    state: ChainState,
    events: list[dict[str, Any]],
    spec: ChainSpec,
    milestone_label: str,
    pr_number: int,
) -> dict[str, Any]:
    state.last_state = "pr_closed"
    state.pr_state = "closed"
    chain_spec.save_chain_state(spec_path, state)
    return _result(
        "stopped",
        state,
        events,
        spec=spec,
        reason=f"milestone {milestone_label} PR #{pr_number} is closed",
    )


def _clear_stale_closed_pr_state(
    *,
    spec_path: Path,
    state: ChainState,
    milestone_label: str,
    log_fn: Callable[[str], None],
) -> ChainState:
    """Drop persisted PR context after a restart if the prior PR was closed.

    A closed milestone PR is a valid stop signal for the live run that observed
    it, but persisting that state as terminal wedges every later restart on the
    same milestone. Clearing the stale PR binding lets the chain resume the
    existing plan and recreate PR context if needed.
    """

    if state.last_state != "pr_closed":
        return state
    if state.pr_number is None and state.pr_state not in {None, "closed"}:
        return state
    log_fn(
        f"clearing stale closed PR context for {milestone_label}; "
        "resuming milestone with a fresh PR binding"
    )
    state.last_state = None
    state.pr_number = None
    state.pr_state = None
    chain_spec.save_chain_state(spec_path, state)
    return state


# ── kind: reconcile milestone PR lifecycle ───────────────────────────────

def _is_reconcile_milestone(milestone: MilestoneSpec) -> bool:
    """Whether a milestone is the generated end-of-epic reconcile milestone."""
    return getattr(milestone, "kind", "product") == "reconcile"


def _reconcile_target_branch(milestone: MilestoneSpec, spec: ChainSpec) -> str:
    """The PR base for a reconcile milestone (recorded target, default chain base)."""
    target = getattr(milestone, "target_branch", None)
    if isinstance(target, str) and target.strip():
        return target.strip()
    return spec.base_branch


def _reconcile_record_fields(milestone: MilestoneSpec, spec: ChainSpec) -> dict[str, Any]:
    """Fields stamped onto completed records for reconcile milestones."""
    if not _is_reconcile_milestone(milestone):
        return {}
    return {
        "kind": "reconcile",
        "target_branch": _reconcile_target_branch(milestone, spec),
    }


def _record_reconcile_target_metadata(
    state: ChainState,
    milestone: MilestoneSpec,
    spec: ChainSpec,
    *,
    base_ref: str | None = None,
) -> None:
    """Record the reconcile PR's target branch as durable evidence.

    Completion validation reads the recorded ``target_branch`` off the
    completed record (see ``_published_target_is_in_chain_target``); this
    metadata entry keeps the publication-time fork point available to
    operators and watchers.
    """
    state.metadata["reconcile_target"] = {
        "branch": _reconcile_target_branch(milestone, spec),
        "base_ref": base_ref or "",
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def _reconcile_pr_url(root: Path, pr_number: int) -> str:
    """Best-effort ``https://github.com/<owner>/<repo>/pull/<n>`` from origin."""
    try:
        proc = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    url = (proc.stdout or "").strip()
    if not url:
        return ""
    if url.startswith("git@github.com:"):
        slug = url[len("git@github.com:") :].removesuffix(".git")
    elif "github.com/" in url:
        slug = url.split("github.com/", 1)[1].removesuffix(".git")
    else:
        return ""
    return f"https://github.com/{slug}/pull/{pr_number}"


def _record_reconcile_pr_ready_dm_best_effort(
    root: Path,
    milestone: MilestoneSpec,
    *,
    pr_number: int,
    writer,
) -> None:
    """Notify operators that a reconcile PR is ready for human review.

    Best-effort and never blocking: the AgentBox adapter is only present on
    controller hosts and requires an operation context (workspace root +
    operation id via env).  When unavailable the PR readiness remains durably
    recorded in chain state metadata and the chain continues.
    """
    if not _is_reconcile_milestone(milestone):
        return
    workspace = os.environ.get("MEGAPLAN_AGENTBOX_WORKSPACE") or ""
    operation_id = os.environ.get("MEGAPLAN_AGENTBOX_OPERATION_ID") or ""
    if not workspace or not operation_id:
        writer(
            "[chain] reconcile PR ready DM skipped: no agentbox operation context "
            "in environment\n"
        )
        return
    try:
        from arnold_pipelines.megaplan.agentbox_adapter import (
            record_reconcile_pr_ready_dm,
        )
        from agentbox.config import AgentBoxConfig

        record_reconcile_pr_ready_dm(
            AgentBoxConfig(workspace_root=Path(workspace)),
            operation_id,
            chain_label=milestone.label,
            pr_number=pr_number,
            pr_url=_reconcile_pr_url(root, pr_number),
            branch=milestone.branch or "",
        )
    except Exception as exc:  # never block the chain on a notification
        writer(f"[chain] reconcile PR ready DM failed (non-blocking): {exc}\n")


def _ensure_pr_for_milestone(
    root: Path,
    spec: ChainSpec,
    state: ChainState,
    milestone: MilestoneSpec,
    *,
    writer,
) -> int | None:
    """Create or reuse the milestone's review PR.

    Reconcile milestones target their RECORDED branch (``target_branch``,
    default ``main``) with fail-closed PR creation, record the target as
    durable evidence, and notify operators via a best-effort DM.  Product
    milestones keep the historical ``_ensure_milestone_pr`` behavior.
    """
    if _is_reconcile_milestone(milestone):
        pr_number = _ensure_reconcile_pr(
            root,
            milestone,
            base_branch=_reconcile_target_branch(milestone, spec),
            writer=writer,
        )
        if pr_number is not None:
            _record_reconcile_target_metadata(state, milestone, spec)
            _record_reconcile_pr_ready_dm_best_effort(
                root, milestone, pr_number=pr_number, writer=writer
            )
        return pr_number
    return _ensure_milestone_pr(
        root, milestone, base_branch=spec.base_branch, writer=writer
    )


def _read_reconcile_selection(plan_dir: Path) -> dict[str, Any] | None:
    """Read the executor's JSON selection from plan execution evidence.

    The ``automatic_reconcile`` executor returns ``selected_shas`` (a list of
    commit SHAs) plus ``verification_evidence``; that payload flows into the
    plan's execution batch artifacts (Slice C capture seam).  This scans every
    batch artifact — the payload itself, or any task ``output``/``result``
    mapping — and returns the first non-empty selection.
    """
    from arnold_pipelines.megaplan._core import list_batch_artifacts

    def _candidates(payload: Any):
        if isinstance(payload, dict):
            yield payload
            tasks = payload.get("tasks") or payload.get("task_updates") or []
            if isinstance(tasks, list):
                for task in tasks:
                    if not isinstance(task, dict):
                        continue
                    for key in ("output", "result", "payload"):
                        value = task.get(key)
                        if isinstance(value, dict):
                            yield value

    for artifact in reversed(list_batch_artifacts(plan_dir)):
        try:
            payload = json.loads(artifact.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            continue
        for candidate in _candidates(payload):
            selected = candidate.get("selected_shas")
            if not isinstance(selected, list):
                continue
            shas = [
                str(sha).strip()
                for sha in selected
                if isinstance(sha, str) and sha.strip()
            ]
            if not shas:
                continue
            verification = candidate.get("verification_evidence")
            return {
                "selected_shas": shas,
                "verification_evidence": (
                    dict(verification) if isinstance(verification, dict) else None
                ),
                "source": str(artifact),
            }
    return None


def _publish_reconcile_selection(
    root: Path,
    spec_path: Path,
    spec: ChainSpec,
    state: ChainState,
    milestone: MilestoneSpec,
    *,
    plan_dir: Path,
    writer,
    log: Callable[[str], None],
) -> str | None:
    """Cherry-pick the reconcile selection and ensure the review PR exists.

    Controller-side step between the reconcile executor and PR review:
    reads ``selected_shas`` from the plan's execution evidence, validates
    reachability / excludes chain-control commits via
    :func:`_cherry_pick_reconcile_selection`, pushes the reconcile branch,
    and ensures the review PR (base = the recorded target branch) exists,
    recording the target metadata and notifying operators via a best-effort
    DM.  Returns ``None`` on success or a fail-closed reason string.
    """
    if state.pr_number is not None:
        # PR already published; a re-run must not re-cherry-pick (idempotent
        # per-SHA skip in the cherry-pick helper makes this safe anyway).
        return None
    target = _reconcile_target_branch(milestone, spec)
    selection = _read_reconcile_selection(plan_dir)
    if selection is None:
        return (
            f"reconcile milestone {milestone.label}: no selected_shas found in "
            "plan execution evidence; cannot publish the reconcile PR"
        )
    log(
        f"reconcile milestone {milestone.label}: {len(selection['selected_shas'])} "
        f"selected commit(s) from {selection['source']}"
    )
    try:
        head = _cherry_pick_reconcile_selection(
            root,
            milestone,
            base_branch=target,
            selected_shas=selection["selected_shas"],
            writer=writer,
        )
    except CliError as exc:
        return (
            f"reconcile milestone {milestone.label} cherry-pick failed "
            f"fail-closed: {exc.message}"
        )
    _run_git_push_command(
        root,
        ["git", "push", "origin", milestone.branch or ""],
        writer=writer,
        error_code="git_push_reconcile_branch_failed",
    )
    writer(
        f"[chain] pushed reconcile branch {milestone.branch} at {head[:12]}\n"
    )
    state.pr_number = _ensure_reconcile_pr(
        root,
        milestone,
        base_branch=target,
        writer=writer,
    )
    if state.pr_number is None:
        return (
            f"reconcile milestone {milestone.label}: review PR could not be "
            "created after cherry-pick"
        )
    state.pr_state = "open"
    _record_reconcile_target_metadata(state, milestone, spec)
    _record_reconcile_pr_ready_dm_best_effort(
        root, milestone, pr_number=state.pr_number, writer=writer
    )
    chain_spec.save_chain_state(spec_path, state)
    log(
        f"reconcile PR #{state.pr_number} opened for {milestone.branch} "
        f"(base {target})"
    )
    return None


def _record_reconcile_outcome(
    state: ChainState, *, outcome: str, reason: str
) -> None:
    state.metadata["reconcile_outcome"] = {
        "outcome": outcome,
        "reason": reason,
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def _reconcile_rejection_reason(pr_number: int, spec: ChainSpec) -> str:
    return (
        f"reconcile PR #{pr_number} was closed without merging; the chain records "
        f"the intentional rejection per on_failure={spec.on_failure}"
    )


def _delete_reconcile_pr_branch_for(
    milestone: MilestoneSpec, root: Path, *, writer
) -> None:
    """Delete a reconcile PR head branch (best-effort only for non-reconcile)."""
    if not _is_reconcile_milestone(milestone) or not milestone.branch:
        return
    _delete_reconcile_pr_branch(root, milestone.branch, writer=writer)


def _advance_reconcile_rejected(
    root: Path,
    spec_path: Path,
    spec: ChainSpec,
    state: ChainState,
    milestone: MilestoneSpec,
    events: list[dict[str, Any]],
    *,
    pr_number: int,
    writer,
    log: Callable[[str], None],
) -> dict[str, Any]:
    """Record an intentionally rejected reconcile PR and advance to close.

    A closed reconcile PR is a deliberate human rejection, not an accident:
    the per-phase commit history is preserved in the repository, so the chain
    records the rejection (per the chain's ``on_failure`` policy) and proceeds
    to terminal cleanup instead of stopping at the closed PR.

    Returns a ``blocked`` result dict when the rejection record cannot be
    appended, or ``None`` after the milestone advanced (callers ``continue``
    the milestone loop).
    """
    rejection_reason = _reconcile_rejection_reason(pr_number, spec)
    log(
        f"reconcile PR #{pr_number} rejected (closed without merge); "
        f"recording rejection and proceeding to close"
    )
    _delete_reconcile_pr_branch_for(milestone, root, writer=writer)
    record = {
        "label": milestone.label,
        "plan": state.current_plan_name,
        "status": "rejected",
        "pr_number": pr_number,
        "pr_state": "closed",
        "rejection_reason": rejection_reason,
        **_reconcile_record_fields(milestone, spec),
    }
    appended, reason = _append_completed_with_guard(
        root,
        state,
        record,
        implementation_milestone=False,
        writer=writer,
    )
    if not appended:
        chain_spec.save_chain_state(spec_path, state)
        return _result(
            "blocked",
            state,
            events,
            spec=spec,
            reason=(
                f"reconcile milestone {milestone.label} rejection record "
                f"blocked append: {reason}"
            ),
        )
    _record_reconcile_outcome(
        state, outcome="rejected", reason=rejection_reason
    )
    if state.current_plan_name:
        _mark_plan_completed_by_chain(
            root,
            state.current_plan_name,
            milestone_label=milestone.label,
            completion_reason=rejection_reason,
            writer=writer,
            state=state,
        )
    _emit_milestone_completion_evidence(
        state,
        milestone_label=milestone.label,
        milestone_index=state.current_milestone_index,
        plan_name=state.current_plan_name or "",
    )
    idx = state.current_milestone_index + 1
    _mark_chain_after_milestone_advance(spec, state, next_index=idx)
    if idx >= len(spec.milestones):
        _emit_chain_complete_evidence(state, spec=spec)
    chain_spec.save_chain_state(spec_path, state)
    # ``None`` means "advanced"; the caller continues the milestone loop.  The
    # reconcile milestone is generated last, so this normally ends the chain.
    return None


def format_chain_status(
    spec: ChainSpec,
    state: ChainState,
    *,
    spec_path: Path | None = None,
) -> dict[str, Any]:
    completed_labels = {
        entry.get("label")
        for entry in state.completed
        if isinstance(entry, dict) and isinstance(entry.get("label"), str)
    }
    current_milestone: dict[str, Any] | None = None
    if 0 <= state.current_milestone_index < len(spec.milestones):
        milestone = spec.milestones[state.current_milestone_index]
        current_milestone = {
            "label": milestone.label,
            "index": state.current_milestone_index,
        }
        if milestone.branch:
            current_milestone["branch"] = milestone.branch

    per_milestone: list[dict[str, Any]] = []
    completed: list[dict[str, Any]] = []
    remaining: list[dict[str, Any]] = []
    for index, milestone in enumerate(spec.milestones):
        if milestone.label in completed_labels:
            status = "completed"
        elif index == state.current_milestone_index and state.current_plan_name:
            status = "in_progress"
        else:
            status = "pending"
        entry = {"label": milestone.label, "index": index, "status": status}
        per_milestone.append(entry)
        if status == "completed":
            completed.append({"label": milestone.label, "index": index})
        else:
            remaining.append({"label": milestone.label, "index": index})

    sync: dict[str, Any] = {
        "branch_head": state.branch_head,
        "pr_head": state.pr_head,
        "last_pushed_commit": state.last_pushed_commit,
        "dirty_flag": state.dirty_flag,
        "sync_state": state.sync_state,
    }
    milestone_boundary_evidence: dict[str, Any] = {}
    if state.milestone_boundary_evidence:
        milestone_boundary_evidence = {
            label: {
                "milestone_label": entry.get("milestone_label"),
                "milestone_index": entry.get("milestone_index"),
                "plan_name": entry.get("plan_name"),
                "contract_id": entry.get("contract_id"),
                "contract_boundary_id": entry.get("contract_boundary_id"),
                "commit_ref": entry.get("commit_ref"),
                "tip_ref": entry.get("tip_ref"),
                "pr_head": entry.get("pr_head"),
                "pr_number": entry.get("pr_number"),
                "pr_state": entry.get("pr_state"),
            }
            for label, entry in state.milestone_boundary_evidence.items()
            if isinstance(entry, dict)
        }
    summary = {
        "current_milestone": current_milestone,
        "completed": completed,
        "remaining": remaining,
        "per_milestone": per_milestone,
        "seed_plan": spec.seed_plan,
        "base_branch": spec.base_branch,
        "current_plan_name": state.current_plan_name,
        "last_state": state.last_state,
        "sync": sync,
        "milestone_boundary_evidence": milestone_boundary_evidence,
        "policy": {
            "prerequisite_policy": spec.prerequisite_policy,
            "validation_policy": spec.validation_policy,
            "review_policy": dict(spec.review_policy or {}),
        },
    }
    if state.pr_number is not None:
        summary["pr_number"] = state.pr_number
        summary["pr_state"] = state.pr_state
    if spec_path is not None:
        from arnold_pipelines.megaplan.chain.execution_binding import (
            execution_binding_report,
        )

        summary["execution_binding"] = execution_binding_report(spec_path, state)
    return summary


def _write_chain_status_pretty(summary: dict[str, Any], *, writer) -> None:
    current = summary.get("current_milestone")
    current_label = "none"
    if isinstance(current, dict):
        current_label = f"{current['label']} (index {current['index']})"
    completed = summary.get("completed") or []
    remaining = summary.get("remaining") or []
    completed_labels = (
        ", ".join(item["label"] for item in completed) if completed else "none"
    )
    remaining_labels = (
        ", ".join(item["label"] for item in remaining) if remaining else "none"
    )
    writer(f"Current milestone: {current_label}\n")
    writer(f"Completed: {completed_labels}\n")
    writer(f"Remaining: {remaining_labels}\n")
    if summary.get("seed_plan"):
        writer(f"Seed plan: {summary['seed_plan']}\n")
    writer(f"Base branch: {summary.get('base_branch') or 'main'}\n")
    if summary.get("current_plan_name"):
        writer(f"Current plan: {summary['current_plan_name']}\n")
    if summary.get("last_state"):
        writer(f"Last state: {summary['last_state']}\n")
    if summary.get("pr_number"):
        writer(
            f"Current PR: #{summary['pr_number']} ({summary.get('pr_state') or 'unknown'})\n"
        )
    binding = summary.get("execution_binding")
    if isinstance(binding, dict) and binding.get("required"):
        expected = binding.get("expected") or {}
        active = binding.get("active") or {}
        writer(
            "Execution binding: "
            f"{binding.get('status')} "
            f"expected={str(expected.get('bundle_sha256') or 'missing')[:12]} "
            f"active={str(active.get('bundle_sha256') or 'missing')[:12]}\n"
        )
        runtime_binding = binding.get("runtime_binding")
        if isinstance(runtime_binding, dict) and runtime_binding.get("required"):
            runtime_expected = runtime_binding.get("expected") or {}
            runtime_active = runtime_binding.get("active") or {}
            writer(
                "Runtime binding: "
                f"{runtime_binding.get('status')} "
                f"expected={str(runtime_expected.get('content_sha256') or 'missing')[:12]} "
                f"active={str(runtime_active.get('content_sha256') or 'missing')[:12]}\n"
            )
    # Sync section (branch/PR sync state)
    sync = summary.get("sync") or {}
    if any(v is not None for v in sync.values()) or sync.get("dirty_flag"):
        writer("Sync:\n")
        if sync.get("branch_head"):
            writer(f"  Branch head: {sync['branch_head']}\n")
        if sync.get("pr_head"):
            writer(f"  PR head: {sync['pr_head']}\n")
        if sync.get("last_pushed_commit"):
            writer(f"  Last pushed: {sync['last_pushed_commit']}\n")
        if sync.get("dirty_flag"):
            writer("  Dirty: yes\n")
        if sync.get("sync_state"):
            writer(f"  Sync state: {sync['sync_state']}\n")
    # Policy section (chain-level policies)
    policy = summary.get("policy") or {}
    if policy:
        writer("Policy:\n")
        writer(f"  Prerequisite: {policy.get('prerequisite_policy', 'none')}\n")
        writer(f"  Validation: {policy.get('validation_policy', 'none')}\n")
        review_policy = policy.get("review_policy") or {}
        writer(
            f"  Review (clean_milestone_pr): {review_policy.get('clean_milestone_pr', 'auto')}\n"
        )
    writer("Per-milestone:\n")
    for item in summary.get("per_milestone") or []:
        writer(f"  - [{item['status']}] {item['label']} (index {item['index']})\n")


# ---------------------------------------------------------------------------
# CLI plumbing
# ---------------------------------------------------------------------------


def build_chain_parser(subparsers: Any) -> None:
    chain_parser = subparsers.add_parser(
        "chain",
        help="Drive a pipeline of milestone plans described by a YAML spec",
    )
    chain_sub = chain_parser.add_subparsers(dest="chain_action")
    # No action == run. `start` is the explicit spelling, kept in sync with the
    # backcompat top-level alias.
    chain_parser.add_argument(
        "--spec",
        required=False,
        help="Path to the chain spec YAML (required at top-level or on subcommands)",
    )
    chain_parser.add_argument(
        "--project-dir",
        required=False,
        help="Run the chain against this project directory instead of discovering from CWD.",
    )
    _add_chain_worktree_args(chain_parser)
    chain_parser.add_argument(
        "--no-git-refresh",
        action="store_true",
        help=(
            "Skip the automatic base-branch checkout and pull that runs "
            "before each milestone. Use this on developer checkouts where "
            "you do not want chain to stomp on the currently checked-out "
            "branch. Default: refresh enabled (preserves CI/orchestrator "
            "behavior)."
        ),
    )
    chain_parser.add_argument(
        "--no-push",
        action="store_true",
        help=(
            "Disable milestone branch creation, PR creation, commits, and pushes. "
            "Also enabled by MEGAPLAN_CHAIN_NO_PUSH=1; intended for local/no-network tests."
        ),
    )
    chain_parser.add_argument(
        "--one",
        action="store_true",
        help="Drive at most one pending milestone, persist progress, then stop cleanly.",
    )
    _add_chain_anchor_args(chain_parser)

    start_parser = chain_sub.add_parser("start", help="Drive a chain spec")
    start_parser.add_argument(
        "--spec", required=True, help="Path to the chain spec YAML"
    )
    start_parser.add_argument(
        "--project-dir",
        required=False,
        help="Run the chain against this project directory instead of discovering from CWD.",
    )
    _add_chain_worktree_args(start_parser)
    start_parser.add_argument(
        "--no-git-refresh",
        action="store_true",
        help=(
            "Skip the automatic base-branch checkout and pull that runs "
            "before each milestone."
        ),
    )
    start_parser.add_argument(
        "--no-push",
        action="store_true",
        help="Disable branch/PR/push lifecycle for no-network runs.",
    )
    start_parser.add_argument(
        "--one",
        action="store_true",
        help="Drive at most one pending milestone, persist progress, then stop cleanly.",
    )
    _add_chain_anchor_args(start_parser)

    status_parser = chain_sub.add_parser(
        "status", help="Show persisted chain progress without driving"
    )
    status_parser.add_argument(
        "--spec", required=True, help="Path to the chain spec YAML"
    )
    status_parser.add_argument(
        "--project-dir",
        required=False,
        help="Read chain state from this project directory instead of discovering from CWD.",
    )

    reconcile_source_parser = chain_sub.add_parser(
        "reconcile-source",
        help="Register a content-addressed canonical source update for a future milestone",
    )
    reconcile_source_parser.add_argument("--spec", required=True)
    reconcile_source_parser.add_argument("--project-dir", required=False)
    reconcile_source_parser.add_argument("--milestone", required=True)
    reconcile_source_parser.add_argument("--authoritative-source", required=True)
    reconcile_source_parser.add_argument("--reason", required=True)

    reconcile_aborted_parser = chain_sub.add_parser(
        "reconcile-aborted-c2-authority",
        help="Admit one exact paused, null-plan aborted C2 authority projection without dispatch",
    )
    reconcile_aborted_parser.add_argument("--spec", required=True)
    reconcile_aborted_parser.add_argument("--project-dir", required=False)
    reconcile_aborted_parser.add_argument("--marker", required=True)
    reconcile_aborted_parser.add_argument("--aborted-plan", required=True)
    reconcile_aborted_parser.add_argument("--session-id", required=True)
    reconcile_aborted_parser.add_argument("--plan-name", required=True)
    reconcile_aborted_parser.add_argument("--chain-state-sha256", required=True)
    reconcile_aborted_parser.add_argument("--plan-state-sha256", required=True)
    reconcile_aborted_parser.add_argument("--marker-sha256", required=True)
    reconcile_aborted_parser.add_argument("--spec-sha256", required=True)
    reconcile_aborted_parser.add_argument("--historical-spec-sha256", required=True)
    reconcile_aborted_parser.add_argument("--chain-revision", required=True, type=int)
    reconcile_aborted_parser.add_argument("--completed-prefix", required=True)
    reconcile_aborted_parser.add_argument("--source-binding", required=True)
    reconcile_aborted_parser.add_argument("--runtime-identity", required=True)
    reconcile_aborted_parser.add_argument("--hold", required=True)
    reconcile_aborted_parser.add_argument("--operation-rows", required=True)
    reconcile_aborted_parser.add_argument("--operation-rows-sha256", required=True)
    reconcile_aborted_parser.add_argument("--runtime-manifest")
    reconcile_aborted_parser.add_argument("--runtime-manifest-sha256")
    reconcile_aborted_parser.add_argument("--reason", required=True)
    reconcile_aborted_parser.add_argument("--actor", default="operator")
    reconcile_aborted_parser.add_argument("--operation-id")

    rebind_parser = chain_sub.add_parser(
        "rebind",
        help="Guardedly adopt a content-addressed successor chain without moving its cursor",
    )
    rebind_parser.add_argument("--spec", required=True)
    rebind_parser.add_argument("--project-dir", required=False)
    rebind_parser.add_argument("--from-bundle-sha256", required=True)
    rebind_parser.add_argument("--to-bundle-sha256", required=True)
    rebind_parser.add_argument("--expected-current-milestone", required=True)
    rebind_parser.add_argument(
        "--expected-current-plan",
        required=True,
        help="Exact current plan name, or @none when the cursor has no plan yet.",
    )
    rebind_parser.add_argument("--expected-next-milestone", required=True)
    rebind_parser.add_argument("--reason", required=True)
    rebind_parser.add_argument("--actor", default="operator")

    runtime_rebind_parser = chain_sub.add_parser(
        "runtime-rebind",
        help="Guardedly cut over or roll back the bound runtime without changing the chain spec binding",
    )
    runtime_rebind_parser.add_argument("--spec", required=True)
    runtime_rebind_parser.add_argument("--project-dir", required=False)
    runtime_rebind_parser.add_argument("--from-runtime-sha256", required=True)
    runtime_rebind_parser.add_argument("--to-runtime-sha256", required=True)
    runtime_rebind_parser.add_argument("--expected-current-milestone", required=True)
    runtime_rebind_parser.add_argument(
        "--expected-current-plan",
        required=True,
        help=(
            "Exact current plan name, or @none when no plan is active. A fully "
            "completed chain uses --expected-current-milestone @terminal with "
            "--expected-current-plan @none; terminal state and the exact "
            "completed milestone set are then verified."
        ),
    )
    runtime_rebind_parser.add_argument("--direction", choices=("cutover", "rollback"), default="cutover")
    runtime_rebind_parser.add_argument("--reason", required=True)
    runtime_rebind_parser.add_argument("--actor", default="operator")
    runtime_rebind_parser.add_argument(
        "--runtime-identity",
        help=(
            "Content-addressed offline runtime identity JSON. Requires "
            "--runtime-provenance-receipt and is freshly reverified by the "
            "receipt's independent interpreter."
        ),
    )
    runtime_rebind_parser.add_argument(
        "--runtime-provenance-receipt",
        help=(
            "Digest-bound runtime_provenance receipt emitted by the offline "
            "runtime's interpreter. Requires --runtime-identity."
        ),
    )
    runtime_rebind_parser.add_argument(
        "--allow-optional-policy",
        action="store_true",
        help=(
            "Allow metadata-only replacement on an optional-policy chain. "
            "Requires an active durable pause, an independently verified "
            "runtime identity/receipt, and --expected-chain-spec-sha256."
        ),
    )
    runtime_rebind_parser.add_argument(
        "--expected-chain-spec-sha256",
        help=(
            "Exact on-disk and persisted chain-spec SHA-256 CAS guard; "
            "required with --allow-optional-policy."
        ),
    )
    runtime_rebind_parser.add_argument(
        "--released-hold-receipt",
        help=(
            "Exact receipt emitted by `chain release-hold` for the prior failed "
            "runtime-rebind operation. Required to retry a released hold."
        ),
    )
    runtime_rebind_parser.add_argument(
        "--attested-hold-context-receipt",
        help=(
            "Exact receipt emitted by `chain attest-hold-context` for a "
            "legacy contextless runtime-rebind hold."
        ),
    )

    attest_hold_context_parser = chain_sub.add_parser(
        "attest-hold-context",
        help="Record an auditable operator attestation for a legacy contextless runtime hold",
    )
    attest_hold_context_parser.add_argument("--spec", required=True)
    attest_hold_context_parser.add_argument("--project-dir", required=True)
    attest_hold_context_parser.add_argument("--chain-id", required=True)
    attest_hold_context_parser.add_argument("--operation-id", required=True)
    attest_hold_context_parser.add_argument(
        "--expected-hold-event-hash", "--expected-hold-event-sha256",
        dest="expected_hold_event_hash", required=True,
    )
    attest_hold_context_parser.add_argument("--released-hold-receipt", required=True)
    attest_hold_context_parser.add_argument(
        "--expected-release-event-hash", "--expected-release-event-sha256",
        dest="expected_release_event_hash", required=True,
    )
    attest_hold_context_parser.add_argument("--expected-chain-spec-sha256", required=True)
    attest_hold_context_parser.add_argument("--expected-state-digest", required=True)
    attest_revision_group = attest_hold_context_parser.add_mutually_exclusive_group(required=True)
    attest_revision_group.add_argument("--expected-state-revision", type=int)
    attest_revision_group.add_argument("--expect-missing-state-revision", action="store_true")
    attest_hold_context_parser.add_argument("--expected-cursor", required=True, type=int)
    attest_hold_context_parser.add_argument("--expected-current-milestone", required=True)
    attest_hold_context_parser.add_argument("--expected-current-plan", required=True)
    attest_hold_context_parser.add_argument("--from-runtime-sha256", required=True)
    attest_hold_context_parser.add_argument("--to-runtime-sha256", required=True)
    attest_hold_context_parser.add_argument("--direction", choices=("cutover", "rollback"), default="cutover")
    attest_hold_context_parser.add_argument("--runtime-identity", required=True)
    attest_hold_context_parser.add_argument("--runtime-provenance-receipt", required=True)
    attest_hold_context_parser.add_argument("--recovery-evidence", required=True)
    attest_hold_context_parser.add_argument("--receipt", required=True)
    attest_hold_context_parser.add_argument("--reason", required=True)
    attest_hold_context_parser.add_argument("--actor", default="operator")

    release_hold_parser = chain_sub.add_parser(
        "release-hold",
        help="Auditedly release one exact durable chain-control hold without changing chain state",
    )
    release_hold_parser.add_argument("--spec", required=True)
    release_hold_parser.add_argument("--project-dir", required=True)
    release_hold_parser.add_argument("--chain-id", required=True)
    release_hold_parser.add_argument("--operation-id", required=True)
    release_hold_parser.add_argument(
        "--expected-hold-event-hash",
        "--expected-hold-event-sha256",
        dest="expected_hold_event_hash",
        required=True,
    )
    release_hold_parser.add_argument("--expected-chain-spec-sha256", required=True)
    release_hold_parser.add_argument("--expected-state-digest", required=True)
    release_revision_group = release_hold_parser.add_mutually_exclusive_group(required=True)
    release_revision_group.add_argument("--expected-state-revision", type=int)
    release_revision_group.add_argument(
        "--expect-missing-state-revision",
        action="store_true",
        help="Require the legacy chain state to have no _nbf08_revision value.",
    )
    release_hold_parser.add_argument("--expected-cursor", required=True, type=int)
    release_hold_parser.add_argument("--expected-current-milestone", required=True)
    release_hold_parser.add_argument("--expected-current-plan", required=True)
    release_hold_parser.add_argument("--recovery-evidence", required=True)
    release_hold_parser.add_argument("--receipt", required=True)
    release_hold_parser.add_argument("--reason", required=True)
    release_hold_parser.add_argument("--actor", default="operator")

    runtime_cutover_parser = chain_sub.add_parser(
        "runtime-cutover",
        help=(
            "Guardedly cut over or roll back the bound runtime AND the recorded "
            "metadata.execution_environment.engine_root atomically"
        ),
    )
    runtime_cutover_parser.add_argument("--spec", required=True)
    runtime_cutover_parser.add_argument("--project-dir", required=False)
    runtime_cutover_parser.add_argument("--from-runtime-sha256", required=True)
    runtime_cutover_parser.add_argument("--to-runtime-sha256", required=True)
    runtime_cutover_parser.add_argument("--expected-current-milestone", required=True)
    runtime_cutover_parser.add_argument(
        "--expected-current-plan",
        required=True,
        help=(
            "Exact current plan name, or @none when no plan is active. A fully "
            "completed chain uses --expected-current-milestone @terminal with "
            "--expected-current-plan @none; terminal state and the exact "
            "completed milestone set are then verified."
        ),
    )
    runtime_cutover_parser.add_argument(
        "--direction", choices=("cutover", "rollback"), default="cutover"
    )
    runtime_cutover_parser.add_argument("--reason", required=True)
    runtime_cutover_parser.add_argument("--actor", default="operator")
    runtime_cutover_parser.add_argument(
        "--runtime-identity",
        help=(
            "Content-addressed offline runtime identity JSON. Requires "
            "--runtime-provenance-receipt and is freshly reverified by the "
            "receipt's independent interpreter. The adopted identity's "
            "import_root becomes the new engine_root."
        ),
    )
    runtime_cutover_parser.add_argument(
        "--runtime-provenance-receipt",
        help=(
            "Digest-bound runtime_provenance receipt emitted by the offline "
            "runtime's interpreter. Requires --runtime-identity."
        ),
    )

    failed_prechain_parser = chain_sub.add_parser(
        "failed-prechain-recover",
        help=(
            "Recover one failed, non-advanced cloud bootstrap in the same "
            "session without creating chain authority"
        ),
    )
    failed_prechain_parser.add_argument("--spec", required=True)
    failed_prechain_parser.add_argument("--project-dir", required=True)
    failed_prechain_parser.add_argument("--marker", required=True)
    failed_prechain_parser.add_argument("--manifest", required=True)
    failed_prechain_parser.add_argument("--source", required=True)
    failed_prechain_parser.add_argument("--workspace", required=True)
    failed_prechain_parser.add_argument("--staged-runtime", required=True)
    failed_prechain_parser.add_argument("--custody-dir", required=True)
    failed_prechain_parser.add_argument("--expected-session-id", required=True)
    failed_prechain_parser.add_argument("--expected-marker-sha256", required=True)
    failed_prechain_parser.add_argument("--expected-manifest-sha256", required=True)
    failed_prechain_parser.add_argument("--expected-spec-sha256", required=True)
    failed_prechain_parser.add_argument("--expected-old-sha", required=True)
    failed_prechain_parser.add_argument("--reviewed-new-sha", required=True)
    failed_prechain_parser.add_argument(
        "--quarantine-state",
        help="Quarantine one exact empty/parse-fragment chain state left by a failed pre-chain launch",
    )
    failed_prechain_parser.add_argument(
        "--expected-state-sha256",
        help="Expected SHA-256 of the empty/parse-fragment chain state",
    )
    failed_prechain_parser.add_argument(
        "--failed-operation-id",
        help="Exact failed host operation identity bound to the state artifact",
    )
    failed_prechain_parser.add_argument(
        "--occupancy",
        help="Optional canonical occupancy evidence proving no owner/supervisor/current plan",
    )
    failed_prechain_parser.add_argument(
        "--reconcile-held",
        metavar="OPERATION_ID",
        help="Close one exact prior failed-prechain hold with an auditable no-effect disposition",
    )
    failed_prechain_parser.add_argument(
        "--retry-after",
        metavar="OPERATION_ID",
        help=(
            "Start one deterministic new recovery attempt only after this "
            "exact operation has a terminal no-effect hold reconciliation"
        ),
    )
    failed_prechain_parser.add_argument(
        "--expected-held-event-hash",
        help="Exact SHA-256 event hash of the held operation's durable hold",
    )
    failed_prechain_parser.add_argument(
        "--recovery-evidence",
        help="Exact linked custody archive manifest for a held-operation reconciliation",
    )
    failed_prechain_parser.add_argument("--reason", required=True)
    failed_prechain_parser.add_argument("--actor", default="operator")

    execution_binding_migrate_parser = chain_sub.add_parser(
        "execution-binding-migrate",
        help=(
            "Initialize the execution binding for a durably-paused, progressed, "
            "unbound chain from its independently verified legacy runtime"
        ),
    )
    execution_binding_migrate_parser.add_argument("--spec", required=True)
    execution_binding_migrate_parser.add_argument("--project-dir", required=True)
    execution_binding_migrate_parser.add_argument(
        "--old-runtime-identity",
        required=True,
        help=(
            "Content-addressed offline runtime identity JSON for the legacy "
            "runtime. Requires --old-runtime-provenance-receipt and is freshly "
            "reverified by the receipt's independent interpreter."
        ),
    )
    execution_binding_migrate_parser.add_argument(
        "--old-runtime-provenance-receipt",
        required=True,
        help=(
            "Digest-bound runtime_provenance receipt emitted by the legacy "
            "runtime's interpreter. Requires --old-runtime-identity."
        ),
    )
    execution_binding_migrate_parser.add_argument(
        "--expected-current-milestone",
        required=True,
        help=(
            "Exact current milestone label, or @terminal for a fully completed "
            "chain (with --expected-current-plan @none)."
        ),
    )
    execution_binding_migrate_parser.add_argument(
        "--expected-current-plan",
        required=True,
        help="Exact current plan name, or @none when the cursor has no plan yet.",
    )
    execution_binding_migrate_parser.add_argument(
        "--expected-branch",
        required=True,
        help="Exact current git branch of the project checkout.",
    )
    execution_binding_migrate_parser.add_argument(
        "--expect-marker-sha256",
        help=(
            "Exact sha256 of the cloud-session marker file.  REQUIRED when the "
            "marker is identity-less (no runtime identity fields): that form is "
            "accepted only under this CAS plus the relaunch-root guard.  "
            "Optional for markers already carrying a runtime identity form."
        ),
    )
    execution_binding_migrate_parser.add_argument(
        "--promote-legacy-runtime-only",
        action="store_true",
        help=(
            "Promote an existing legacy runtime-only binding through the "
            "canonical NBF08 journal/CAS transaction. Requires the exact "
            "spec, state, marker, and manifest guards below."
        ),
    )
    execution_binding_migrate_parser.add_argument(
        "--released-hold-receipt",
        help=(
            "Exact receipt emitted by `chain release-hold` for the prior failed "
            "legacy-runtime promotion. Required to retry a released hold."
        ),
    )
    execution_binding_migrate_parser.add_argument(
        "--expected-chain-spec-sha256",
        help="Exact old on-disk and persisted chain-spec SHA-256 for legacy promotion.",
    )
    execution_binding_migrate_parser.add_argument(
        "--expected-state-digest",
        help="Exact canonical chain-state digest for legacy promotion.",
    )
    execution_binding_migrate_parser.add_argument(
        "--expected-state-revision",
        type=int,
        help="Exact _nbf08_revision value for legacy promotion.",
    )
    execution_binding_migrate_parser.add_argument(
        "--expect-manifest-sha256",
        help="Exact active runtime-manifest SHA-256 for legacy promotion.",
    )
    execution_binding_migrate_parser.add_argument("--reason", required=True)
    execution_binding_migrate_parser.add_argument("--actor", default="operator")

    target_rebind_parser = chain_sub.add_parser(
        "target-rebind",
        help=(
            "Guardedly cut over or roll back the paused pre-execute project "
            "checkout and milestone baseline"
        ),
    )
    target_rebind_parser.add_argument("--spec", required=True)
    target_rebind_parser.add_argument("--project-dir", required=True)
    target_rebind_parser.add_argument(
        "--direction",
        choices=("cutover", "rollback"),
        default="cutover",
    )
    target_rebind_parser.add_argument("--expected-session-id", required=True)
    target_rebind_parser.add_argument("--expected-current-milestone", required=True)
    target_rebind_parser.add_argument("--expected-current-plan", required=True)
    target_rebind_parser.add_argument("--from-branch", required=True)
    target_rebind_parser.add_argument("--from-head", required=True)
    target_rebind_parser.add_argument("--from-milestone-base", required=True)
    target_rebind_parser.add_argument("--from-ref", required=True)
    target_rebind_parser.add_argument("--to-branch", required=True)
    target_rebind_parser.add_argument("--to-head", required=True)
    target_rebind_parser.add_argument("--to-ref", required=True)
    target_rebind_parser.add_argument("--expected-spec-sha256", required=True)
    target_rebind_parser.add_argument(
        "--expected-target-spec-sha256",
        required=False,
        help=(
            "Exact chain-spec hash after target checkout; defaults to "
            "--expected-spec-sha256 when the spec is unchanged"
        ),
    )
    target_rebind_parser.add_argument("--expected-chain-state-sha256", required=True)
    target_rebind_parser.add_argument("--expected-plan-state-sha256", required=True)
    target_rebind_parser.add_argument("--reason", required=True)
    target_rebind_parser.add_argument("--actor", default="operator")
    target_rebind_parser.add_argument(
        "--runtime-identity",
        help="Verified external runtime identity used by a newer paused control interpreter",
    )
    target_rebind_parser.add_argument(
        "--runtime-provenance-receipt",
        help="Independent interpreter receipt paired with --runtime-identity",
    )

    restart_current_attempt_parser = chain_sub.add_parser(
        "restart-current-attempt",
        help=(
            "Retire the paused unfinished current plan so chain start can "
            "rematerialize the same milestone"
        ),
    )
    restart_current_attempt_parser.add_argument("--spec", required=True)
    restart_current_attempt_parser.add_argument("--project-dir", required=True)
    restart_current_attempt_parser.add_argument("--marker", required=True)
    restart_current_attempt_parser.add_argument("--expected-session-id", required=True)
    restart_current_attempt_parser.add_argument("--expected-cursor", required=True, type=int)
    restart_current_attempt_parser.add_argument("--expected-current-milestone", required=True)
    restart_current_attempt_parser.add_argument("--expected-current-plan", required=True)
    restart_current_attempt_parser.add_argument("--expected-spec-sha256", required=True)
    restart_current_attempt_parser.add_argument("--expected-chain-state-sha256", required=True)
    restart_current_attempt_parser.add_argument("--expected-plan-state-sha256", required=True)
    restart_current_attempt_parser.add_argument("--expected-state-revision", required=True, type=int)
    restart_current_attempt_parser.add_argument("--expected-marker-sha256", required=True)
    restart_current_attempt_parser.add_argument("--expected-binding-sha256", required=True)
    restart_current_attempt_parser.add_argument("--expected-source-head", required=True)
    restart_current_attempt_parser.add_argument("--reason", required=True)
    restart_current_attempt_parser.add_argument("--actor", default="operator")
    restart_current_attempt_parser.add_argument(
        "--promote-legacy-receipt",
        action="store_true",
        help=(
            "Promote one exact archived restart receipt into the paused live "
            "boundary without rerunning the retired attempt."
        ),
    )
    restart_current_attempt_parser.add_argument("--expected-operation-id")
    restart_current_attempt_parser.add_argument("--archived-journal")
    restart_current_attempt_parser.add_argument("--expected-archived-journal-sha256")
    restart_current_attempt_parser.add_argument("--archive-manifest")
    restart_current_attempt_parser.add_argument("--expected-archive-manifest-sha256")
    restart_current_attempt_parser.add_argument("--expected-legacy-event-hash")
    restart_current_attempt_parser.add_argument("--expected-state-digest")
    restart_current_attempt_parser.add_argument("--expected-physical-sequence-start", type=int)

    paused_checkout_parser = chain_sub.add_parser(
        "cutover-paused-checkout",
        help=(
            "Guardedly cut over a paused null-plan aborted-C2 checkout and "
            "record its content-addressed source binding"
        ),
    )
    paused_checkout_parser.add_argument("--spec", required=True)
    paused_checkout_parser.add_argument("--project-dir", required=True)
    paused_checkout_parser.add_argument("--marker", required=True)
    paused_checkout_parser.add_argument("--aborted-plan", required=True)
    paused_checkout_parser.add_argument("--session-id", required=True)
    paused_checkout_parser.add_argument("--current-milestone", required=True)
    paused_checkout_parser.add_argument("--cursor", required=True, type=int)
    paused_checkout_parser.add_argument("--completed-prefix", required=True)
    paused_checkout_parser.add_argument("--hold", required=True)
    paused_checkout_parser.add_argument("--runtime-identity", required=True)
    paused_checkout_parser.add_argument("--from-branch", required=True)
    paused_checkout_parser.add_argument("--from-head", required=True)
    paused_checkout_parser.add_argument("--from-milestone-base", required=True)
    paused_checkout_parser.add_argument("--from-ref", required=True)
    paused_checkout_parser.add_argument("--to-branch", required=True)
    paused_checkout_parser.add_argument("--to-head", required=True)
    paused_checkout_parser.add_argument("--to-milestone-base", required=True)
    paused_checkout_parser.add_argument("--to-ref", required=True)
    paused_checkout_parser.add_argument("--expected-chain-state-sha256", required=True)
    paused_checkout_parser.add_argument("--expected-plan-state-sha256", required=True)
    paused_checkout_parser.add_argument("--expected-marker-sha256", required=True)
    paused_checkout_parser.add_argument("--expected-spec-sha256", required=True)
    paused_checkout_parser.add_argument("--expected-target-spec-sha256")
    paused_checkout_parser.add_argument("--expected-chain-revision", required=True, type=int)
    paused_checkout_parser.add_argument("--reason", required=True)
    paused_checkout_parser.add_argument("--actor", default="operator")
    paused_checkout_parser.add_argument("--operation-id")

    seed_rematerialize_parser = chain_sub.add_parser(
        "seed-rematerialize",
        help=(
            "Archive a paused pre-execute plan and rematerialize the same "
            "milestone from an exact seed manifest"
        ),
    )
    seed_rematerialize_parser.add_argument("--spec", required=True)
    seed_rematerialize_parser.add_argument("--project-dir", required=True)
    seed_rematerialize_parser.add_argument(
        "--direction",
        choices=("cutover", "rollback"),
        default="cutover",
    )
    seed_rematerialize_parser.add_argument("--expected-session-id", required=True)
    seed_rematerialize_parser.add_argument("--expected-current-milestone", required=True)
    seed_rematerialize_parser.add_argument("--expected-current-plan", required=True)
    seed_rematerialize_parser.add_argument("--expected-branch", required=True)
    seed_rematerialize_parser.add_argument("--expected-head", required=True)
    seed_rematerialize_parser.add_argument("--expected-spec-sha256", required=True)
    seed_rematerialize_parser.add_argument("--expected-chain-state-sha256", required=True)
    seed_rematerialize_parser.add_argument("--expected-plan-state-sha256", required=True)
    seed_rematerialize_parser.add_argument("--seed-manifest", required=True)
    seed_rematerialize_parser.add_argument(
        "--expected-seed-manifest-sha256",
        required=True,
    )
    seed_rematerialize_parser.add_argument("--expected-cutover-event-sha256")
    seed_rematerialize_parser.add_argument("--expected-archive-manifest-sha256")
    seed_rematerialize_parser.add_argument("--reason", required=True)
    seed_rematerialize_parser.add_argument("--actor", default="operator")
    seed_rematerialize_parser.add_argument(
        "--runtime-identity",
        help="Verified external runtime identity used by a newer paused control interpreter",
    )
    seed_rematerialize_parser.add_argument(
        "--runtime-provenance-receipt",
        help="Independent interpreter receipt paired with --runtime-identity",
    )
    pause_parser = chain_sub.add_parser(
        "pause", help="Durably pause a chain and disable automatic recovery"
    )
    pause_parser.add_argument("--spec", required=True, help="Path to the chain spec YAML")
    pause_parser.add_argument("--project-dir", required=False)
    pause_parser.add_argument("--reason", required=True)
    pause_parser.add_argument("--actor", default="operator")

    resume_chain_parser = chain_sub.add_parser(
        "resume", help="Explicitly clear a durable operator pause"
    )
    resume_chain_parser.add_argument("--spec", required=True, help="Path to the chain spec YAML")
    resume_chain_parser.add_argument("--project-dir", required=False)
    resume_chain_parser.add_argument("--actor", default="operator")

    occurrence_join_parser = chain_sub.add_parser(
        "occurrence-join",
        help=(
            "Operator-only: join the EXACT blocked repair occurrence of the "
            "current plan and acquire a fenced claim/lease for it (T-0101e)"
        ),
    )
    occurrence_join_parser.add_argument("--spec", required=True, help="Path to the chain spec YAML")
    occurrence_join_parser.add_argument("--project-dir", required=False)
    occurrence_join_parser.add_argument("--session", required=True, help="Recorded repair session id")
    occurrence_join_parser.add_argument(
        "--occurrence",
        required=True,
        help="Exact recorded occurrence id (the repair request repair_identity_key)",
    )
    occurrence_join_parser.add_argument(
        "--request", required=True, help="Exact recorded repair request id"
    )
    occurrence_join_parser.add_argument(
        "--decision", required=True, help="Exact recorded repair decision id"
    )
    occurrence_join_parser.add_argument(
        "--claim", required=True, help="Claim id to acquire for the exact occurrence"
    )
    occurrence_join_parser.add_argument("--reason", required=True)
    occurrence_join_parser.add_argument("--actor", default="operator")
    occurrence_join_parser.add_argument(
        "--receipt",
        required=True,
        help="Durable receipt JSON output path (written only on success)",
    )

    occurrence_adopt_parser = chain_sub.add_parser(
        "occurrence-adopt",
        help=(
            "Operator-only: adopt the SINGULAR identity-less blocked "
            "occurrence of the current plan with an occurrence-exact "
            "owner-boundary adoption identity, enqueue its exact repair "
            "request, and record ONE accepted decision (T-0101e')"
        ),
    )
    occurrence_adopt_parser.add_argument("--spec", required=True, help="Path to the chain spec YAML")
    occurrence_adopt_parser.add_argument("--project-dir", required=False)
    occurrence_adopt_parser.add_argument(
        "--session", required=True, help="Chain session of the blocked occurrence"
    )
    occurrence_adopt_parser.add_argument(
        "--expected-current-plan", required=True, help="Exact current plan name"
    )
    occurrence_adopt_parser.add_argument(
        "--expected-phase", required=True, help="Exact blocked phase"
    )
    occurrence_adopt_parser.add_argument(
        "--expected-failure-kind", required=True, help="Exact latest failure kind"
    )
    occurrence_adopt_parser.add_argument(
        "--expected-failure-code", required=True, help="Exact latest failure code"
    )
    occurrence_adopt_parser.add_argument(
        "--expected-failure-recorded-at", required=True, help="Exact failure recorded_at"
    )
    occurrence_adopt_parser.add_argument(
        "--expected-resume-phase", required=True, help="Exact resume cursor phase"
    )
    occurrence_adopt_parser.add_argument(
        "--expected-retry-strategy", required=True, help="Exact resume cursor retry strategy"
    )
    occurrence_adopt_parser.add_argument(
        "--expected-chain-state-sha256", required=True, help="Exact sha256 of the chain state file"
    )
    occurrence_adopt_parser.add_argument(
        "--expected-plan-state-sha256", required=True, help="Exact sha256 of the plan state.json"
    )
    occurrence_adopt_parser.add_argument(
        "--expected-latest-failure-sha256", required=True, help="Exact canonical sha256 of latest_failure"
    )
    occurrence_adopt_parser.add_argument(
        "--expected-resume-cursor-sha256", required=True, help="Exact canonical sha256 of resume_cursor"
    )
    occurrence_adopt_parser.add_argument(
        "--expected-pause-authority-sha256", required=True, help="Exact canonical sha256 of the pause authority"
    )
    occurrence_adopt_parser.add_argument(
        "--runtime-manifest", required=True, help="Path to the runtime manifest JSON"
    )
    occurrence_adopt_parser.add_argument(
        "--expected-runtime-manifest-sha256", required=True, help="Exact sha256 of the runtime manifest file"
    )
    occurrence_adopt_parser.add_argument(
        "--marker", required=True, help="Path to the cloud-session marker JSON"
    )
    occurrence_adopt_parser.add_argument(
        "--expected-marker-sha256", required=True, help="Exact sha256 of the marker file"
    )
    occurrence_adopt_parser.add_argument(
        "--runtime-identity", required=True, help="Verified runtime identity JSON (independently receipted)"
    )
    occurrence_adopt_parser.add_argument(
        "--runtime-provenance-receipt", required=True, help="Runtime provenance receipt paired with --runtime-identity"
    )
    occurrence_adopt_parser.add_argument(
        "--candidate-root", required=True, help="The candidate runtime root (one of the six equal roots)"
    )
    occurrence_adopt_parser.add_argument(
        "--expected-runtime-roots-sha256", required=True, help="Exact canonical sha256 of the six-root payload"
    )
    occurrence_adopt_parser.add_argument("--reason", required=True)
    occurrence_adopt_parser.add_argument("--actor", default="operator")
    occurrence_adopt_parser.add_argument(
        "--receipt",
        required=True,
        help="Durable receipt JSON output path (written only on success)",
    )

    verify_parser = chain_sub.add_parser(
        "verify", help="Replay landed-diff completion evidence for completed milestones"
    )
    verify_parser.add_argument(
        "--spec", required=True, help="Path to the chain spec YAML"
    )
    verify_parser.add_argument(
        "--project-dir",
        required=False,
        help="Read chain plans from this project directory instead of discovering from CWD.",
    )

    manifest_parser = chain_sub.add_parser(
        "manifest", help="Write a content-addressed completion manifest"
    )
    manifest_parser.add_argument(
        "--spec", required=True, help="Path to the completed chain spec YAML"
    )
    manifest_parser.add_argument(
        "--project-dir",
        required=False,
        help="Read chain state from this project directory instead of discovering from CWD.",
    )
    manifest_parser.add_argument(
        "--proof-map",
        required=True,
        help=(
            "JSON mapping milestone labels to proof artifact paths. "
            "May also be an object with a top-level `milestones` mapping."
        ),
    )
    manifest_parser.add_argument(
        "--output",
        required=False,
        help=(
            "Output path for completion-manifest.json. Defaults beside chain.yaml; "
            "custom paths must stay in the chain spec directory."
        ),
    )

    override_parser = chain_sub.add_parser(
        "override", help="Set runtime policy overrides without editing chain.yaml"
    )
    override_parser.add_argument(
        "--spec", required=True, help="Path to the chain spec YAML"
    )
    override_parser.add_argument(
        "--project-dir",
        required=False,
        help="Apply chain overrides against this project directory instead of discovering from CWD.",
    )
    override_parser.add_argument(
        "--set-prerequisite-policy",
        choices=VALID_PREREQUISITE_POLICIES,
        default=None,
        help="Set prerequisite policy at runtime (e.g. none, required)",
    )
    override_parser.add_argument(
        "--set-validation-policy",
        choices=VALID_VALIDATION_POLICIES,
        default=None,
        help="Set validation policy at runtime (e.g. none, required)",
    )
    override_parser.add_argument(
        "--set-review-clean-milestone-pr",
        choices=VALID_CLEAN_MILESTONE_PR_POLICIES,
        default=None,
        help="Set review clean_milestone_pr policy at runtime (e.g. auto, manual)",
    )
    override_parser.add_argument(
        "--allow-manifestless",
        action="store_true",
        default=False,
        help="Grant an expiring allow_manifestless permit (admission exception "
        "for manifest-less chain execution) recorded in the runtime policy sidecar.",
    )
    override_parser.add_argument(
        "--reason",
        default=None,
        help="Required with --allow-manifestless: why the deviation is granted.",
    )
    override_parser.add_argument(
        "--expires-at",
        default=None,
        metavar="ISO8601",
        help="Required with --allow-manifestless: UTC expiry timestamp. Must be "
        "within 24 hours of issuance.",
    )
    override_parser.add_argument(
        "--actor",
        default=None,
        help="Required with --allow-manifestless: attribution for the permit "
        "(caller-supplied, not authentication).",
    )
    override_parser.add_argument(
        "--evidence",
        action="append",
        default=None,
        metavar="TEXT",
        help="Repeatable evidence string attached to the permit record.",
    )
    override_parser.add_argument(
        "--revoke",
        action="store_true",
        default=False,
        help="Revoke the active allow_manifestless permit by stamping an auditable "
        "revoked_at tombstone (the record is never deleted).",
    )


def _add_chain_worktree_args(parser: Any) -> None:
    parser.add_argument(
        "--in-worktree",
        default=None,
        metavar="NAME",
        help=(
            "Create a new git worktree at ~/Documents/.megaplan-worktrees/<name>/ "
            "on a new branch and run the whole chain inside it. Name must match "
            "^[a-z0-9][a-z0-9._-]{0,63}$. Substitutes for --project-dir."
        ),
    )
    parser.add_argument(
        "--worktree-from",
        default=None,
        metavar="GITREF",
        help=(
            "Base ref for the new worktree (default: current HEAD of the repo "
            "where `megaplan chain` was invoked). Only valid with --in-worktree."
        ),
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        default=False,
        help=(
            "With --in-worktree: remove an existing registered worktree/branch "
            "for this name before creating the new chain worktree."
        ),
    )
    parser.add_argument(
        "--clean-worktree",
        action="store_true",
        default=False,
        help=(
            "With --in-worktree: fork from a clean base ref and leave any "
            "uncommitted state behind in the source repo (no carry)."
        ),
    )
    parser.add_argument(
        "--carry-dirty",
        action="store_true",
        default=False,
        help=(
            "With --in-worktree: explicitly opt into carrying uncommitted state "
            "from the source repo into the new worktree. Mutually exclusive "
            "with --clean-worktree."
        ),
    )


def _add_chain_anchor_args(parser: Any) -> None:
    anchor_group = parser.add_mutually_exclusive_group()
    anchor_group.add_argument(
        "--require-anchor",
        dest="require_anchor",
        action="store_true",
        default=None,
        help="Require top-level anchors.north_star for this chain run (default unless spec opts out).",
    )
    anchor_group.add_argument(
        "--no-require-anchor",
        dest="require_anchor",
        action="store_false",
        default=None,
        help="Opt out of the default top-level anchors.north_star requirement for this chain run.",
    )
    parser.add_argument(
        "--missing-anchor-ack",
        default=None,
        help="Acknowledgement reason required when opting out and no top-level anchors.north_star is declared.",
    )


def run_chain_cli(
    root: Path, args: argparse.Namespace, *, writer=sys.stderr.write
) -> int:
    action = getattr(args, "chain_action", None)
    spec_arg = getattr(args, "spec", None)
    if not spec_arg:
        sys.stderr.write("megaplan chain: --spec is required\n")
        return 64
    spec_path = Path(spec_arg).expanduser().resolve()

    def _guard_json(path_arg: str, label: str) -> Any:
        try:
            return json.loads(Path(path_arg).expanduser().resolve(strict=True).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CliError("invalid_args", f"{label} JSON is unavailable or malformed: {exc}") from exc

    if action == "reconcile-aborted-c2-authority":
        project_root = root
        project_dir_arg = getattr(args, "project_dir", None)
        if isinstance(project_dir_arg, str) and project_dir_arg.strip():
            project_root = Path(project_dir_arg).expanduser().resolve()
        try:
            from arnold_pipelines.megaplan.chain.current_attempt import (
                AbortedC2AuthorityGuards,
                reconcile_aborted_c2_authority,
            )
            from arnold_pipelines.megaplan.incident.chain_control import ChainControlHold

            prefix = _guard_json(args.completed_prefix, "completed-prefix")
            source = _guard_json(args.source_binding, "source-binding")
            runtime = _guard_json(args.runtime_identity, "runtime-identity")
            hold = _guard_json(args.hold, "hold")
            rows = _guard_json(args.operation_rows, "operation-rows")
            if not isinstance(prefix, list) or not isinstance(rows, list):
                raise CliError("invalid_args", "completed-prefix and operation-rows must contain JSON lists")
            if not all(isinstance(item, Mapping) for item in prefix + rows):
                raise CliError("invalid_args", "completed-prefix and operation-rows must contain JSON objects")
            if not isinstance(source, Mapping) or not isinstance(runtime, Mapping) or not isinstance(hold, Mapping):
                raise CliError("invalid_args", "source-binding, runtime-identity, and hold must contain JSON objects")
            result = reconcile_aborted_c2_authority(
                spec_path=spec_path,
                project_dir=project_root,
                marker_path=Path(args.marker).expanduser().resolve(),
                aborted_plan_path=Path(args.aborted_plan).expanduser().resolve(),
                guards=AbortedC2AuthorityGuards(
                    expected_session_id=args.session_id,
                    expected_plan_name=args.plan_name,
                    expected_chain_state_sha256=args.chain_state_sha256,
                    expected_plan_state_sha256=args.plan_state_sha256,
                    expected_marker_sha256=args.marker_sha256,
                    expected_spec_sha256=args.spec_sha256,
                    expected_chain_revision=args.chain_revision,
                    expected_completed_prefix=tuple(dict(item) for item in prefix),
                    expected_source_binding=dict(source),
                    expected_runtime_identity=dict(runtime),
                    expected_hold=dict(hold),
                    expected_operation_rows=tuple(dict(item) for item in rows),
                    expected_historical_spec_sha256=args.historical_spec_sha256,
                    expected_runtime_manifest_sha256=args.runtime_manifest_sha256,
                    expected_operation_rows_sha256=args.operation_rows_sha256,
                ),
                expected_operation_rows_path=Path(args.operation_rows).expanduser().resolve(),
                runtime_manifest_path=(Path(args.runtime_manifest).expanduser().resolve() if args.runtime_manifest else None),
                reason=args.reason,
                actor=args.actor,
                operation_id=args.operation_id,
            )
        except ChainControlHold as exc:
            return _emit_error(CliError(exc.code, str(exc), extra=exc.details))
        except CliError as exc:
            return _emit_error(exc)
        sys.stdout.write(json.dumps({"success": True, "spec": str(spec_path), "action": action, **result}, indent=2) + "\n")
        return 0

    if action in {"pause", "resume"}:
        from arnold_pipelines.megaplan.chain.operator_pause import pause_chain, resume_chain

        project_root = root
        project_dir_arg = getattr(args, "project_dir", None)
        if isinstance(project_dir_arg, str) and project_dir_arg.strip():
            project_root = Path(project_dir_arg).expanduser().resolve()
        try:
            if action == "pause":
                payload = pause_chain(
                    spec_path,
                    project_root,
                    reason=args.reason,
                    actor=args.actor,
                )
            else:
                payload = resume_chain(spec_path, project_root, actor=args.actor)
        except CliError as exc:
            return _emit_error(exc)
        sys.stdout.write(
            json.dumps({"success": True, "spec": str(spec_path), **payload}, indent=2) + "\n"
        )
        return 0

    if action == "release-hold":
        project_root = root
        project_dir_arg = getattr(args, "project_dir", None)
        if isinstance(project_dir_arg, str) and project_dir_arg.strip():
            project_root = Path(project_dir_arg).expanduser().resolve()
        try:
            from arnold_pipelines.megaplan.incident.chain_control import (
                ChainControlError,
                chain_id_for_spec,
                journal_for,
            )

            if args.chain_id != chain_id_for_spec(spec_path):
                raise CliError(
                    "chain_mismatch",
                    "release-hold chain id does not match the spec",
                )
            expect_missing_revision = bool(
                getattr(args, "expect_missing_state_revision", False)
            )
            expected_revision = getattr(args, "expected_state_revision", None)
            if expect_missing_revision and expected_revision is not None:
                raise CliError(
                    "revision_expectation_conflict",
                    "--expect-missing-state-revision cannot be combined with "
                    "--expected-state-revision",
                )
            if not expect_missing_revision and expected_revision is None:
                raise CliError(
                    "missing_revision_expectation",
                    "release-hold requires --expected-state-revision or "
                    "--expect-missing-state-revision",
                )
            release_kwargs = {
                "chain_id": args.chain_id,
                "operation_id": args.operation_id,
                "expected_hold_event_hash": args.expected_hold_event_hash,
                "expected_chain_spec_sha256": args.expected_chain_spec_sha256,
                "spec_path": spec_path,
                "expected_state_digest": args.expected_state_digest,
                "expected_cursor": args.expected_cursor,
                "expected_current_milestone": args.expected_current_milestone,
                "expected_current_plan": args.expected_current_plan,
                "recovery_evidence": Path(args.recovery_evidence).expanduser().resolve(),
                "actor": args.actor,
                "reason": args.reason,
                "expect_missing_state_revision": expect_missing_revision,
            }
            if not expect_missing_revision:
                release_kwargs["expected_state_revision"] = expected_revision
            result = journal_for(project_root).release_hold(
                **release_kwargs,
            )
            receipt_path = Path(args.receipt).expanduser().resolve()
            receipt_path.parent.mkdir(parents=True, exist_ok=True)
            receipt_path.write_text(
                json.dumps(
                    {"schema": "nbf08-chain-control-hold-release-v1", "event": result["event"]},
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
        except ChainControlError as exc:
            return _emit_error(
                CliError(
                    exc.code,
                    str(exc),
                    extra=exc.details,
                )
            )
        except CliError as exc:
            return _emit_error(exc)
        sys.stdout.write(
            json.dumps(
                {"success": True, "spec": str(spec_path), "action": "release-hold", **result},
                indent=2,
            )
            + "\n"
        )
        return 0

    if action == "attest-hold-context":
        project_root = root
        project_dir_arg = getattr(args, "project_dir", None)
        if isinstance(project_dir_arg, str) and project_dir_arg.strip():
            project_root = Path(project_dir_arg).expanduser().resolve()
        try:
            from arnold_pipelines.megaplan.incident.chain_control import ChainControlError, chain_id_for_spec
            from arnold_pipelines.megaplan.chain.execution_binding import (
                attest_hold_context,
                verify_external_runtime_identity,
            )

            if args.chain_id != chain_id_for_spec(spec_path):
                raise CliError("chain_mismatch", "hold context attestation chain does not match the spec")
            identity_path = Path(args.runtime_identity).expanduser().resolve(strict=False)
            provenance_path = Path(args.runtime_provenance_receipt).expanduser().resolve(strict=False)
            verified_identity = verify_external_runtime_identity(identity_path, provenance_path)
            expected_revision = getattr(args, "expected_state_revision", None)
            expect_missing_revision = bool(getattr(args, "expect_missing_state_revision", False))
            if not expect_missing_revision and expected_revision is None:
                raise CliError(
                    "missing_revision_expectation",
                    "hold context attestation requires --expected-state-revision or "
                    "--expect-missing-state-revision",
                )
            chain_state = chain_spec.load_chain_state(spec_path, verify_execution_binding=False)
            result = attest_hold_context(
                spec_path,
                chain_state,
                released_hold_receipt=args.released_hold_receipt,
                expected_chain_id=args.chain_id,
                expected_operation_id=args.operation_id,
                expected_hold_event_hash=args.expected_hold_event_hash,
                expected_release_event_hash=args.expected_release_event_hash,
                expected_chain_spec_sha256=args.expected_chain_spec_sha256,
                expected_state_digest=args.expected_state_digest,
                expected_current_milestone=args.expected_current_milestone,
                expected_current_plan=args.expected_current_plan,
                expected_cursor=args.expected_cursor,
                expected_previous_runtime_sha256=args.from_runtime_sha256,
                expected_active_runtime_sha256=args.to_runtime_sha256,
                direction=args.direction,
                runtime_identity=verified_identity,
                runtime_provenance_receipt=str(provenance_path),
                recovery_evidence=Path(args.recovery_evidence).expanduser().resolve(),
                reason=args.reason,
                actor=args.actor,
                expected_state_revision=expected_revision,
                expect_missing_state_revision=expect_missing_revision,
                _external_identity_verified=True,
            )
            receipt_path = Path(args.receipt).expanduser().resolve()
            receipt_path.parent.mkdir(parents=True, exist_ok=True)
            receipt_path.write_text(
                json.dumps({"schema": "nbf08-chain-control-hold-context-attestation-v1", "event": result["event"]}, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        except ChainControlError as exc:
            return _emit_error(CliError(exc.code, str(exc), extra=exc.details))
        except CliError as exc:
            return _emit_error(exc)
        sys.stdout.write(json.dumps({"success": True, "spec": str(spec_path), "action": "attest-hold-context", **result}, indent=2) + "\n")
        return 0

    if action == "occurrence-join":
        project_root = root
        project_dir_arg = getattr(args, "project_dir", None)
        if isinstance(project_dir_arg, str) and project_dir_arg.strip():
            project_root = Path(project_dir_arg).expanduser().resolve()
        receipt_arg = getattr(args, "receipt", None)
        if not isinstance(receipt_arg, str) or not receipt_arg.strip():
            return _emit_error(CliError("invalid_args", "--receipt is required"))
        try:
            from arnold_pipelines.megaplan.chain.occurrence_join import (
                join_exact_occurrence,
            )

            payload = join_exact_occurrence(
                spec_path=spec_path,
                project_dir=project_root,
                session=args.session,
                occurrence_id=args.occurrence,
                request_id=args.request,
                decision_id=args.decision,
                claim_id=args.claim,
                reason=args.reason,
                actor=args.actor,
                receipt_path=Path(receipt_arg).expanduser(),
            )
        except CliError as exc:
            return _emit_error(exc)
        sys.stdout.write(
            json.dumps({"success": True, "spec": str(spec_path), **payload}, indent=2) + "\n"
        )
        return 0

    if action == "occurrence-adopt":
        project_root = root
        project_dir_arg = getattr(args, "project_dir", None)
        if isinstance(project_dir_arg, str) and project_dir_arg.strip():
            project_root = Path(project_dir_arg).expanduser().resolve()
        receipt_arg = getattr(args, "receipt", None)
        if not isinstance(receipt_arg, str) or not receipt_arg.strip():
            return _emit_error(CliError("invalid_args", "--receipt is required"))
        try:
            from arnold_pipelines.megaplan.chain.occurrence_adopt import (
                adopt_occurrence,
            )

            payload = adopt_occurrence(
                spec_path=spec_path,
                project_dir=project_root,
                session=args.session,
                expected_current_plan=args.expected_current_plan,
                expected_phase=args.expected_phase,
                expected_failure_kind=args.expected_failure_kind,
                expected_failure_code=args.expected_failure_code,
                expected_failure_recorded_at=args.expected_failure_recorded_at,
                expected_resume_phase=args.expected_resume_phase,
                expected_retry_strategy=args.expected_retry_strategy,
                expected_chain_state_sha256=args.expected_chain_state_sha256,
                expected_plan_state_sha256=args.expected_plan_state_sha256,
                expected_latest_failure_sha256=args.expected_latest_failure_sha256,
                expected_resume_cursor_sha256=args.expected_resume_cursor_sha256,
                expected_pause_authority_sha256=args.expected_pause_authority_sha256,
                runtime_manifest_path=args.runtime_manifest,
                expected_runtime_manifest_sha256=args.expected_runtime_manifest_sha256,
                marker_path=args.marker,
                expected_marker_sha256=args.expected_marker_sha256,
                runtime_identity_path=args.runtime_identity,
                runtime_provenance_receipt_path=args.runtime_provenance_receipt,
                candidate_root=args.candidate_root,
                expected_runtime_roots_sha256=args.expected_runtime_roots_sha256,
                actor=args.actor,
                reason=args.reason,
                receipt_path=Path(receipt_arg).expanduser(),
            )
        except CliError as exc:
            return _emit_error(exc)
        sys.stdout.write(
            json.dumps({"success": True, "spec": str(spec_path), **payload}, indent=2) + "\n"
        )
        return 0

    if action == "reconcile-source":
        try:
            spec = chain_spec.load_spec(spec_path)
            chain_state = chain_spec.load_chain_state(
                spec_path,
                verify_execution_binding=False,
            )
            from arnold_pipelines.megaplan.chain.source_admission import (
                require_milestone_source_update,
            )

            requirement = require_milestone_source_update(
                spec_path=spec_path,
                state=chain_state,
                spec=spec,
                milestone_label=args.milestone,
                authoritative_source=Path(args.authoritative_source).expanduser().resolve(),
                reason=args.reason,
            )
            chain_spec.save_chain_state(spec_path, chain_state)
        except CliError as exc:
            return _emit_error(exc)
        sys.stdout.write(
            json.dumps(
                {
                    "success": True,
                    "spec": str(spec_path),
                    "action": "reconcile-source",
                    "requirement": requirement,
                },
                indent=2,
            )
            + "\n"
        )
        return 0

    if action == "rebind":
        try:
            chain_state = chain_spec.load_chain_state(
                spec_path,
                verify_execution_binding=False,
            )
            before = chain_state.to_dict()
            from arnold_pipelines.megaplan.chain.execution_binding import (
                rebind_execution_identity,
            )

            result = rebind_execution_identity(
                spec_path,
                chain_state,
                expected_previous_bundle_sha256=args.from_bundle_sha256,
                expected_active_bundle_sha256=args.to_bundle_sha256,
                expected_current_milestone=args.expected_current_milestone,
                expected_current_plan=args.expected_current_plan,
                expected_next_milestone=args.expected_next_milestone,
                reason=args.reason,
                actor=args.actor,
            )
            after = chain_state.to_dict()
            for field in before:
                if field != "metadata" and before[field] != after[field]:
                    raise CliError(
                        "chain_execution_binding_drift",
                        f"chain rebind refused: operational field {field!r} changed",
                    )
            chain_spec.save_chain_state(spec_path, chain_state)
        except CliError as exc:
            return _emit_error(exc)
        sys.stdout.write(
            json.dumps(
                {
                    "success": True,
                    "spec": str(spec_path),
                    "action": "rebind",
                    **result,
                },
                indent=2,
            )
            + "\n"
        )
        return 0

    if action == "runtime-rebind":
        try:
            from arnold_pipelines.megaplan.incident.chain_control import (
                ChainControlError,
            )
            chain_state = chain_spec.load_chain_state(
                spec_path,
                verify_execution_binding=False,
            )
            before = chain_state.to_dict()
            from arnold_pipelines.megaplan.chain.execution_binding import (
                rebind_runtime_identity,
                verify_external_runtime_identity,
            )

            identity_arg = str(getattr(args, "runtime_identity", "") or "").strip()
            receipt_arg = str(
                getattr(args, "runtime_provenance_receipt", "") or ""
            ).strip()
            if bool(identity_arg) != bool(receipt_arg):
                raise CliError(
                    "chain_runtime_binding_drift",
                    "chain runtime rebind refused: --runtime-identity and "
                    "--runtime-provenance-receipt must be supplied together",
                )
            external_identity = (
                verify_external_runtime_identity(
                    Path(identity_arg).expanduser().resolve(strict=False),
                    Path(receipt_arg).expanduser().resolve(strict=False),
                )
                if identity_arg
                else None
            )
            result = rebind_runtime_identity(
                spec_path,
                chain_state,
                expected_previous_runtime_sha256=args.from_runtime_sha256,
                expected_active_runtime_sha256=args.to_runtime_sha256,
                expected_current_milestone=args.expected_current_milestone,
                expected_current_plan=args.expected_current_plan,
                direction=args.direction,
                reason=args.reason,
                actor=args.actor,
                verified_external_runtime_identity=external_identity,
                verified_external_runtime_receipt=receipt_arg or None,
                _external_identity_verified=bool(identity_arg),
                allow_optional_policy=bool(
                    getattr(args, "allow_optional_policy", False)
                ),
                expected_chain_spec_sha256=(
                    getattr(args, "expected_chain_spec_sha256", None) or None
                ),
                released_hold_receipt=(
                    getattr(args, "released_hold_receipt", None) or None
                ),
                attested_hold_context_receipt=(
                    getattr(args, "attested_hold_context_receipt", None) or None
                ),
            )
            after = chain_state.to_dict()
            for field in before:
                if field != "metadata" and before[field] != after[field]:
                    raise CliError(
                        "chain_runtime_binding_drift",
                        f"chain runtime rebind refused: operational field {field!r} changed",
                    )
            if bool(getattr(args, "allow_optional_policy", False)):
                before_metadata = before.get("metadata") or {}
                after_metadata = after.get("metadata") or {}
                expected_spec_sha = str(
                    getattr(args, "expected_chain_spec_sha256", "") or ""
                )
                if (
                    before_metadata.get("chain_spec_sha256") != expected_spec_sha
                    or after_metadata.get("chain_spec_sha256") != expected_spec_sha
                ):
                    raise CliError(
                        "chain_runtime_binding_drift",
                        "chain runtime rebind refused: chain spec SHA-256 changed",
                    )
                before_binding = before_metadata.get("execution_binding") or {}
                after_binding = after_metadata.get("execution_binding") or {}
                if (
                    before_binding.get("launched_identity")
                    != after_binding.get("launched_identity")
                    or before_metadata.get("execution_environment")
                    != after_metadata.get("execution_environment")
                ):
                    raise CliError(
                        "chain_runtime_binding_drift",
                        "chain runtime rebind refused: launch or engine metadata changed",
                    )
            # Optional-policy replacement performs its sole state mutation via
            # the canonical NBF-08 journal/CAS transaction.  Required-policy
            # runtime-rebind retains the legacy save path for compatibility.
            if not bool(getattr(args, "allow_optional_policy", False)):
                chain_spec.save_chain_state(spec_path, chain_state)
        except ChainControlError as exc:
            return _emit_error(
                CliError(
                    exc.code,
                    str(exc),
                    extra=exc.details,
                )
            )
        except CliError as exc:
            return _emit_error(exc)
        sys.stdout.write(
            json.dumps(
                {
                    "success": True,
                    "spec": str(spec_path),
                    "action": "runtime-rebind",
                    **result,
                },
                indent=2,
            )
            + "\n"
        )
        return 0

    if action == "failed-prechain-recover":
        try:
            from arnold_pipelines.megaplan.chain.failed_prechain_recovery import (
                quarantine_failed_prechain_state,
                reconcile_failed_prechain_hold,
                recover_failed_prechain,
            )

            if args.quarantine_state:
                if not args.expected_state_sha256 or not args.failed_operation_id:
                    raise CliError(
                        "invalid_args",
                        "--quarantine-state requires --expected-state-sha256 and --failed-operation-id",
                    )
                result = quarantine_failed_prechain_state(
                    Path(args.spec).expanduser().resolve(),
                    Path(args.project_dir).expanduser().resolve(),
                    state_path=Path(args.quarantine_state).expanduser().resolve(),
                    expected_state_sha256=args.expected_state_sha256,
                    expected_spec_sha256=args.expected_spec_sha256,
                    expected_session_id=args.expected_session_id,
                    failed_operation_id=args.failed_operation_id,
                    custody_dir=Path(args.custody_dir).expanduser().resolve(),
                    occupancy_path=(Path(args.occupancy).expanduser().resolve() if args.occupancy else None),
                    reason=args.reason,
                    actor=args.actor,
                )
                sys.stdout.write(
                    json.dumps(
                        {"success": True, "spec": str(spec_path), "action": action, **result},
                        indent=2,
                    )
                    + "\n"
                )
                return 0

            common = dict(
                marker_path=Path(args.marker).expanduser().resolve(),
                manifest_path=Path(args.manifest).expanduser().resolve(),
                source_path=Path(args.source).expanduser().resolve(),
                workspace_path=Path(args.workspace).expanduser().resolve(),
                custody_dir=Path(args.custody_dir).expanduser().resolve(),
                expected_session_id=args.expected_session_id,
                expected_marker_sha256=args.expected_marker_sha256,
                expected_manifest_sha256=args.expected_manifest_sha256,
                expected_spec_sha256=args.expected_spec_sha256,
                expected_old_sha=args.expected_old_sha,
                reason=args.reason,
                actor=args.actor,
            )
            if args.reconcile_held:
                if args.retry_after:
                    raise CliError(
                        "invalid_recovery_mode",
                        "--reconcile-held and --retry-after are mutually exclusive",
                    )
                if not args.expected_held_event_hash:
                    raise CliError(
                        "missing_held_event_hash",
                        "--reconcile-held requires --expected-held-event-hash",
                    )
                evidence = (
                    Path(args.recovery_evidence).expanduser().resolve()
                    if args.recovery_evidence
                    else Path(args.custody_dir).expanduser().resolve()
                    / args.reconcile_held
                    / "manifest.json"
                )
                result = reconcile_failed_prechain_hold(
                    spec_path,
                    Path(args.project_dir).expanduser().resolve(),
                    held_operation_id=args.reconcile_held,
                    expected_hold_event_hash=args.expected_held_event_hash,
                    held_reviewed_new_sha=args.reviewed_new_sha,
                    recovery_evidence=evidence,
                    **common,
                )
            else:
                result = recover_failed_prechain(
                    spec_path,
                    Path(args.project_dir).expanduser().resolve(),
                    staged_runtime_path=Path(args.staged_runtime).expanduser().resolve(),
                    reviewed_new_sha=args.reviewed_new_sha,
                    retry_after_operation_id=args.retry_after,
                    **common,
                )
        except CliError as exc:
            return _emit_error(exc)
        sys.stdout.write(
            json.dumps(
                {
                    "success": True,
                    "spec": str(spec_path),
                    "action": "failed-prechain-recover",
                    **result,
                },
                indent=2,
            )
            + "\n"
        )
        return 0

    if action == "runtime-cutover":
        try:
            chain_state = chain_spec.load_chain_state(
                spec_path,
                verify_execution_binding=False,
            )
            before = chain_state.to_dict()
            from arnold_pipelines.megaplan.chain.execution_binding import (
                cutover_runtime_identity,
                verify_external_runtime_identity,
            )

            identity_arg = str(getattr(args, "runtime_identity", "") or "").strip()
            receipt_arg = str(
                getattr(args, "runtime_provenance_receipt", "") or ""
            ).strip()
            if bool(identity_arg) != bool(receipt_arg):
                raise CliError(
                    "chain_runtime_binding_drift",
                    "chain runtime cutover refused: --runtime-identity and "
                    "--runtime-provenance-receipt must be supplied together",
                )
            external_identity = (
                verify_external_runtime_identity(
                    Path(identity_arg).expanduser().resolve(strict=False),
                    Path(receipt_arg).expanduser().resolve(strict=False),
                )
                if identity_arg
                else None
            )
            result = cutover_runtime_identity(
                spec_path,
                chain_state,
                expected_previous_runtime_sha256=args.from_runtime_sha256,
                expected_active_runtime_sha256=args.to_runtime_sha256,
                expected_current_milestone=args.expected_current_milestone,
                expected_current_plan=args.expected_current_plan,
                direction=args.direction,
                reason=args.reason,
                actor=args.actor,
                verified_external_runtime_identity=external_identity,
            )
            after = chain_state.to_dict()
            for field in before:
                if field != "metadata" and before[field] != after[field]:
                    raise CliError(
                        "chain_runtime_binding_drift",
                        f"chain runtime cutover refused: operational field {field!r} changed",
                    )
            chain_spec.save_chain_state(spec_path, chain_state)
        except CliError as exc:
            return _emit_error(exc)
        sys.stdout.write(
            json.dumps(
                {
                    "success": True,
                    "spec": str(spec_path),
                    "action": "runtime-cutover",
                    **result,
                },
                indent=2,
            )
            + "\n"
        )
        return 0

    if action == "execution-binding-migrate":
        project_root = Path(args.project_dir).expanduser().resolve()
        try:
            from arnold_pipelines.megaplan.chain.execution_binding import (
                migrate_execution_binding,
                promote_legacy_runtime_binding,
                verify_external_runtime_identity,
            )

            identity_arg = str(
                getattr(args, "old_runtime_identity", "") or ""
            ).strip()
            receipt_arg = str(
                getattr(args, "old_runtime_provenance_receipt", "") or ""
            ).strip()
            if not identity_arg or not receipt_arg:
                raise CliError(
                    "chain_execution_binding_migrate_refused",
                    "execution-binding-migrate requires --old-runtime-identity "
                    "and --old-runtime-provenance-receipt together",
                )
            if bool(getattr(args, "promote_legacy_runtime_only", False)):
                identity_path = Path(identity_arg).expanduser().resolve(strict=False)
                try:
                    identity_payload = json.loads(identity_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise CliError(
                        "chain_execution_binding_migrate_refused",
                        "legacy promotion runtime identity is unreadable",
                    ) from exc
                if not isinstance(identity_payload, Mapping):
                    raise CliError(
                        "chain_execution_binding_migrate_refused",
                        "legacy promotion runtime identity must be a JSON object",
                    )
                result = promote_legacy_runtime_binding(
                    spec_path,
                    project_root,
                    expected_current_milestone=args.expected_current_milestone,
                    expected_current_plan=args.expected_current_plan,
                    expected_branch=args.expected_branch,
                    expected_chain_spec_sha256=(
                        getattr(args, "expected_chain_spec_sha256", None) or ""
                    ),
                    expected_state_digest=(
                        getattr(args, "expected_state_digest", None) or ""
                    ),
                    expected_state_revision=getattr(args, "expected_state_revision", None),
                    expected_marker_sha256=(
                        getattr(args, "expect_marker_sha256", None) or ""
                    ),
                    expected_manifest_sha256=(
                        getattr(args, "expect_manifest_sha256", None) or ""
                    ),
                    reason=args.reason,
                    actor=args.actor,
                    verified_external_runtime_identity=identity_payload,
                    verified_external_runtime_receipt=receipt_arg,
                    released_hold_receipt=(
                        getattr(args, "released_hold_receipt", None) or None
                    ),
                )
            else:
                if getattr(args, "released_hold_receipt", None):
                    raise CliError(
                        "chain_execution_binding_migrate_refused",
                        "--released-hold-receipt requires --promote-legacy-runtime-only",
                    )
                external_identity = verify_external_runtime_identity(
                    Path(identity_arg).expanduser().resolve(strict=False),
                    Path(receipt_arg).expanduser().resolve(strict=False),
                )
                result = migrate_execution_binding(
                    spec_path,
                    project_root,
                    expected_current_milestone=args.expected_current_milestone,
                    expected_current_plan=args.expected_current_plan,

                    expected_branch=args.expected_branch,
                    reason=args.reason,
                    actor=args.actor,
                    expected_marker_sha256=(
                        getattr(args, "expect_marker_sha256", None) or None
                    ),
                    verified_external_runtime_identity=external_identity,
                )
        except CliError as exc:
            return _emit_error(exc)
        sys.stdout.write(
            json.dumps(
                {
                    "success": True,
                    "spec": str(spec_path),
                    "action": "execution-binding-migrate",
                    **result,
                },
                indent=2,
            )
            + "\n"
        )
        return 0
    if action == "restart-current-attempt":
        project_root = Path(args.project_dir).expanduser().resolve()
        try:
            from arnold_pipelines.megaplan.chain.restart_current_attempt import (
                promote_legacy_restart_receipt,
                restart_current_attempt,
            )

            if args.promote_legacy_receipt:
                required = {
                    "--expected-operation-id": args.expected_operation_id,
                    "--archived-journal": args.archived_journal,
                    "--expected-archived-journal-sha256": args.expected_archived_journal_sha256,
                    "--archive-manifest": args.archive_manifest,
                    "--expected-archive-manifest-sha256": args.expected_archive_manifest_sha256,
                    "--expected-legacy-event-hash": args.expected_legacy_event_hash,
                }
                missing = [name for name, value in required.items() if not str(value or "").strip()]
                if missing:
                    raise CliError(
                        "current_attempt_restart_refused",
                        "--promote-legacy-receipt requires " + ", ".join(missing),
                    )
                result = promote_legacy_restart_receipt(
                    spec_path,
                    project_root,
                    marker_path=Path(args.marker).expanduser().resolve(),
                    expected_session_id=args.expected_session_id,
                    expected_cursor=args.expected_cursor,
                    expected_current_milestone=args.expected_current_milestone,
                    expected_current_plan=args.expected_current_plan,
                    expected_spec_sha256=args.expected_spec_sha256,
                    expected_chain_state_sha256=args.expected_chain_state_sha256,
                    expected_plan_state_sha256=args.expected_plan_state_sha256,
                    expected_state_revision=args.expected_state_revision,
                    expected_marker_sha256=args.expected_marker_sha256,
                    expected_binding_sha256=args.expected_binding_sha256,
                    expected_source_head=args.expected_source_head,
                    expected_operation_id=args.expected_operation_id,
                    archived_journal_path=Path(args.archived_journal).expanduser().resolve(),
                    expected_archived_journal_sha256=args.expected_archived_journal_sha256,
                    archive_manifest_path=Path(args.archive_manifest).expanduser().resolve(),
                    expected_archive_manifest_sha256=args.expected_archive_manifest_sha256,
                    expected_legacy_event_hash=args.expected_legacy_event_hash,
                    reason=args.reason,
                    actor=args.actor,
                    expected_state_digest=args.expected_state_digest,
                    expected_physical_sequence_start=args.expected_physical_sequence_start,
                )
            else:
                result = restart_current_attempt(
                    spec_path,
                    project_root,
                    marker_path=Path(args.marker).expanduser().resolve(),
                    expected_session_id=args.expected_session_id,
                    expected_cursor=args.expected_cursor,
                    expected_current_milestone=args.expected_current_milestone,
                    expected_current_plan=args.expected_current_plan,
                    expected_spec_sha256=args.expected_spec_sha256,
                    expected_chain_state_sha256=args.expected_chain_state_sha256,
                    expected_plan_state_sha256=args.expected_plan_state_sha256,
                    expected_state_revision=args.expected_state_revision,
                    expected_marker_sha256=args.expected_marker_sha256,
                    expected_binding_sha256=args.expected_binding_sha256,
                    expected_source_head=args.expected_source_head,
                    reason=args.reason,
                    actor=args.actor,
                )
        except CliError as exc:
            return _emit_error(exc)
        sys.stdout.write(
            json.dumps(
                {
                    "success": True,
                    "spec": str(spec_path),
                    "action": "restart-current-attempt",
                    **result,
                },
                indent=2,
            )
            + "\n"
        )
        return 0

    if action == "cutover-paused-checkout":
        project_root = Path(args.project_dir).expanduser().resolve()
        try:
            from arnold_pipelines.megaplan.chain.target_rebind import cutover_paused_checkout
            from arnold_pipelines.megaplan.incident.chain_control import ChainControlHold

            prefix = _guard_json(args.completed_prefix, "completed-prefix")
            hold = _guard_json(args.hold, "hold")
            runtime = _guard_json(args.runtime_identity, "runtime-identity")
            if not isinstance(prefix, list) or not all(isinstance(item, Mapping) for item in prefix):
                raise CliError("invalid_args", "completed-prefix must contain JSON objects")
            if not isinstance(hold, Mapping) or not isinstance(runtime, Mapping):
                raise CliError("invalid_args", "hold and runtime-identity must contain JSON objects")
            result = cutover_paused_checkout(
                spec_path,
                project_root,
                marker_path=Path(args.marker).expanduser().resolve(),
                aborted_plan_path=Path(args.aborted_plan).expanduser().resolve(),
                expected_session_id=args.session_id,
                expected_current_milestone=args.current_milestone,
                expected_cursor=args.cursor,
                expected_completed_prefix=[dict(item) for item in prefix],
                expected_chain_state_sha256=args.expected_chain_state_sha256,
                expected_plan_state_sha256=args.expected_plan_state_sha256,
                expected_marker_sha256=args.expected_marker_sha256,
                expected_spec_sha256=args.expected_spec_sha256,
                expected_target_spec_sha256=args.expected_target_spec_sha256,
                expected_chain_revision=args.expected_chain_revision,
                expected_hold=dict(hold),
                expected_runtime_identity=dict(runtime),
                from_branch=args.from_branch,
                from_head=args.from_head,
                from_milestone_base=args.from_milestone_base,
                from_ref=args.from_ref,
                to_branch=args.to_branch,
                to_head=args.to_head,
                to_milestone_base=args.to_milestone_base,
                to_ref=args.to_ref,
                reason=args.reason,
                actor=args.actor,
                operation_id=args.operation_id,
            )
        except ChainControlHold as exc:
            return _emit_error(CliError(exc.code, str(exc), extra=exc.details))
        except CliError as exc:
            return _emit_error(exc)
        sys.stdout.write(json.dumps({"success": True, "spec": str(spec_path), "action": action, **result}, indent=2) + "\n")
        return 0

    if action == "target-rebind":
        project_root = Path(args.project_dir).expanduser().resolve()
        try:
            from arnold_pipelines.megaplan.chain.target_rebind import target_rebind
            from arnold_pipelines.megaplan.chain.execution_binding import (
                verify_external_runtime_identity,
            )

            identity_arg = str(getattr(args, "runtime_identity", "") or "").strip()
            receipt_arg = str(
                getattr(args, "runtime_provenance_receipt", "") or ""
            ).strip()
            if bool(identity_arg) != bool(receipt_arg):
                raise CliError(
                    "project_source_rebind_refused",
                    "target rebind requires --runtime-identity and "
                    "--runtime-provenance-receipt together",
                )
            external_identity = (
                verify_external_runtime_identity(
                    Path(identity_arg).expanduser().resolve(strict=False),
                    Path(receipt_arg).expanduser().resolve(strict=False),
                )
                if identity_arg
                else None
            )

            result = target_rebind(
                spec_path,
                project_root,
                direction=args.direction,
                expected_session_id=args.expected_session_id,
                expected_current_milestone=args.expected_current_milestone,
                expected_current_plan=args.expected_current_plan,
                from_branch=args.from_branch,
                from_head=args.from_head,
                from_milestone_base=args.from_milestone_base,
                from_ref=args.from_ref,
                to_branch=args.to_branch,
                to_head=args.to_head,
                to_ref=args.to_ref,
                expected_spec_sha256=args.expected_spec_sha256,
                expected_target_spec_sha256=args.expected_target_spec_sha256,
                expected_chain_state_sha256=args.expected_chain_state_sha256,
                expected_plan_state_sha256=args.expected_plan_state_sha256,
                reason=args.reason,
                actor=args.actor,
                verified_external_runtime_identity=external_identity,
            )
        except CliError as exc:
            return _emit_error(exc)
        sys.stdout.write(
            json.dumps(
                {
                    "success": True,
                    "spec": str(spec_path),
                    "action": "target-rebind",
                    **result,
                },
                indent=2,
            )
            + "\n"
        )
        return 0

    if action == "seed-rematerialize":
        project_root = Path(args.project_dir).expanduser().resolve()
        try:
            from arnold_pipelines.megaplan.chain.seed_rematerialize import (
                seed_rematerialize,
            )
            from arnold_pipelines.megaplan.chain.execution_binding import (
                verify_external_runtime_identity,
            )

            identity_arg = str(getattr(args, "runtime_identity", "") or "").strip()
            receipt_arg = str(
                getattr(args, "runtime_provenance_receipt", "") or ""
            ).strip()
            if bool(identity_arg) != bool(receipt_arg):
                raise CliError(
                    "seed_rematerialize_refused",
                    "seed rematerialize requires --runtime-identity and "
                    "--runtime-provenance-receipt together",
                )
            external_identity = (
                verify_external_runtime_identity(
                    Path(identity_arg).expanduser().resolve(strict=False),
                    Path(receipt_arg).expanduser().resolve(strict=False),
                )
                if identity_arg
                else None
            )

            result = seed_rematerialize(
                spec_path,
                project_root,
                expected_session_id=args.expected_session_id,
                expected_current_milestone=args.expected_current_milestone,
                expected_current_plan=args.expected_current_plan,
                expected_branch=args.expected_branch,
                expected_head=args.expected_head,
                expected_spec_sha256=args.expected_spec_sha256,
                expected_chain_state_sha256=args.expected_chain_state_sha256,
                expected_plan_state_sha256=args.expected_plan_state_sha256,
                seed_manifest_path=Path(args.seed_manifest).expanduser().resolve(),
                expected_seed_manifest_sha256=args.expected_seed_manifest_sha256,
                direction=args.direction,
                expected_cutover_event_sha256=args.expected_cutover_event_sha256,
                expected_archive_manifest_sha256=args.expected_archive_manifest_sha256,
                reason=args.reason,
                actor=args.actor,
                verified_external_runtime_identity=external_identity,
            )
        except CliError as exc:
            return _emit_error(exc)
        sys.stdout.write(
            json.dumps(
                {
                    "success": True,
                    "spec": str(spec_path),
                    "action": "seed-rematerialize",
                    **result,
                },
                indent=2,
            )
            + "\n"
        )
        return 0
    if action == "override":
        set_prereq = getattr(args, "set_prerequisite_policy", None)
        set_valid = getattr(args, "set_validation_policy", None)
        set_clean = getattr(args, "set_review_clean_milestone_pr", None)
        allow_manifestless = bool(getattr(args, "allow_manifestless", False))
        revoke_permit = bool(getattr(args, "revoke", False))
        if (
            set_prereq is None
            and set_valid is None
            and set_clean is None
            and not allow_manifestless
            and not revoke_permit
        ):
            return _emit_error(
                CliError(
                    "invalid_spec",
                    "At least one --set-* flag, --allow-manifestless, or --revoke "
                    "is required for chain override. Use --set-prerequisite-policy, "
                    "--set-validation-policy, --set-review-clean-milestone-pr, "
                    "--allow-manifestless, or --revoke.",
                )
            )
        try:
            spec = chain_spec.load_spec(spec_path)
        except CliError as exc:
            return _emit_error(exc)
        overrides: dict[str, Any] = chain_spec.load_runtime_policy(spec_path)
        if set_prereq is not None:
            overrides["prerequisite_policy"] = set_prereq
        if set_valid is not None:
            overrides["validation_policy"] = set_valid
        if set_clean is not None:
            review_from_overrides = overrides.get("review_policy") or {}
            review_from_overrides["clean_milestone_pr"] = set_clean
            overrides["review_policy"] = review_from_overrides
        chain_spec.save_runtime_policy(spec_path, overrides)
        revoked: dict[str, Any] | None = None
        if revoke_permit:
            try:
                revoked = chain_spec.revoke_allow_manifestless_permit(spec_path)
            except CliError as exc:
                return _emit_error(exc)
            if revoked is None:
                return _emit_error(
                    CliError(
                        "no_active_permit",
                        "chain override --revoke: no active allow_manifestless "
                        "permit is on record for this chain.",
                    )
                )
        permit: dict[str, Any] | None = None
        if allow_manifestless:
            reason = getattr(args, "reason", None)
            expires_at = getattr(args, "expires_at", None)
            actor = getattr(args, "actor", None)
            evidence = list(getattr(args, "evidence", None) or [])
            missing = [
                name
                for name, value in (
                    ("--reason", reason),
                    ("--expires-at", expires_at),
                    ("--actor", actor),
                )
                if not value
            ]
            if missing:
                return _emit_error(
                    CliError(
                        "invalid_permit",
                        "chain override --allow-manifestless requires "
                        + ", ".join(missing)
                        + ".",
                    )
                )
            try:
                permit = chain_spec.issue_allow_manifestless_permit(
                    spec_path,
                    reason=reason,
                    expires_at=expires_at,
                    actor=actor,
                    evidence=evidence,
                )
            except CliError as exc:
                return _emit_error(exc)
        effective = chain_spec.effective_chain_policy(spec, overrides)
        payload: dict[str, Any] = {
            "success": True,
            "spec": str(spec_path),
            "effective_policy": effective,
            "runtime_overrides": overrides,
        }
        if revoked is not None:
            payload["revoked_permit"] = revoked
        if permit is not None:
            payload["permit"] = permit
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return 0

    if action == "status":
        try:
            spec = chain_spec.load_spec(spec_path)
            anchor_requirement = chain_spec.validate_anchor_requirement(
                spec,
                spec_path,
                require_anchor_override=getattr(args, "require_anchor", None),
                missing_anchor_ack_override=getattr(args, "missing_anchor_ack", None),
            )
            chain_spec.validate_paths(spec, root, spec_path=spec_path)
            # Status must remain observable during drift. It reports expected
            # versus active identity without normalizing or adopting either.
            chain_state = chain_spec.load_chain_state(
                spec_path,
                verify_execution_binding=False,
            )
        except CliError as exc:
            return _emit_error(exc)
        if anchor_requirement.warning:
            writer(f"[chain] WARNING: {anchor_requirement.warning}\n")
        runtime_overrides = chain_spec.load_runtime_policy(spec_path)
        effective_policy = chain_spec.effective_chain_policy(spec, runtime_overrides)
        summary = format_chain_status(spec, chain_state, spec_path=spec_path)
        _write_chain_status_pretty(summary, writer=writer)
        payload = {
            "success": True,
            "spec": str(spec_path),
            "milestone_count": len(spec.milestones),
            "seed_plan": spec.seed_plan,
            "base_branch": spec.base_branch,
            "chain_state": chain_state.to_dict(),
            "summary": summary,
            "policy": effective_policy,
            "anchor_requirement": {
                "require_anchor": anchor_requirement.require_anchor,
                "missing_anchor_ack": anchor_requirement.missing_anchor_ack,
                "warning": anchor_requirement.warning,
            },
        }
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return 0

    if action == "verify":
        project_root = root
        project_dir_arg = getattr(args, "project_dir", None)
        if isinstance(project_dir_arg, str) and project_dir_arg.strip():
            project_root = Path(project_dir_arg).expanduser().resolve()
        try:
            spec = chain_spec.load_spec(spec_path)
            chain_spec.validate_paths(spec, project_root, spec_path=spec_path)
            chain_state = chain_spec.load_chain_state(spec_path)
        except CliError as exc:
            return _emit_error(exc)
        sys.stdout.write(
            json.dumps(
                _verify_completed_chain(project_root, spec_path, spec, chain_state),
                indent=2,
            )
            + "\n"
        )
        return 0

    if action == "manifest":
        project_root = root
        project_dir_arg = getattr(args, "project_dir", None)
        if isinstance(project_dir_arg, str) and project_dir_arg.strip():
            project_root = Path(project_dir_arg).expanduser().resolve()
        proof_map_arg = getattr(args, "proof_map", None)
        if not isinstance(proof_map_arg, str) or not proof_map_arg.strip():
            return _emit_error(CliError("invalid_args", "--proof-map is required"))
        proof_map_path = Path(proof_map_arg).expanduser()
        if not proof_map_path.is_absolute():
            proof_map_path = (project_root / proof_map_path).resolve()
        output_arg = getattr(args, "output", None)
        output_path: Path | None = None
        if isinstance(output_arg, str) and output_arg.strip():
            output_path = Path(output_arg).expanduser()
            if not output_path.is_absolute():
                output_path = (project_root / output_path).resolve()
        try:
            spec = chain_spec.load_spec(spec_path)
            chain_spec.validate_paths(spec, project_root, spec_path=spec_path)
            chain_state = chain_spec.load_chain_state(spec_path)
            payload = _write_completion_manifest(
                root=project_root,
                spec_path=spec_path,
                spec=spec,
                state=chain_state,
                proof_map_path=proof_map_path,
                output_path=output_path,
            )
        except CliError as exc:
            return _emit_error(exc)
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return 0

    if action not in (None, "start"):
        return _emit_error(CliError("invalid_args", f"Unknown chain action: {action}"))

    no_git_refresh = bool(getattr(args, "no_git_refresh", False))
    no_push = bool(getattr(args, "no_push", False))
    one = bool(getattr(args, "one", False))
    fresh = bool(getattr(args, "fresh", False))
    require_anchor_override = getattr(args, "require_anchor", None)
    missing_anchor_ack_override = getattr(args, "missing_anchor_ack", None)
    try:
        _require_active_initiative_chain(root, spec_path)
        spec_for_anchor_check = chain_spec.load_spec(spec_path)
        chain_spec.validate_anchor_requirement(
            spec_for_anchor_check,
            spec_path,
            require_anchor_override=require_anchor_override,
            missing_anchor_ack_override=missing_anchor_ack_override,
        )
        if supervisor_tier_routing_on():
            from arnold_pipelines.megaplan.supervisor.chain_runner import (
                run_chain as supervisor_run_chain,
            )

            result = supervisor_run_chain(
                spec_path,
                root,
                writer=writer,
                one=one,
                require_anchor_override=require_anchor_override,
                missing_anchor_ack_override=missing_anchor_ack_override,
            )
        else:
            result = run_chain(
                spec_path,
                root,
                no_git_refresh=no_git_refresh,
                no_push=no_push,
                one=one,
                fresh=fresh,
                require_anchor_override=require_anchor_override,
                missing_anchor_ack_override=missing_anchor_ack_override,
            )
    except CliError as exc:
        return _emit_error(exc)
    sys.stdout.write(json.dumps(result, indent=2) + "\n")
    if result["status"] in {"done", "paused", "awaiting_pr_merge"}:
        return 0
    return 1


def _emit_error(error: CliError) -> int:
    payload = {"success": False, "error": error.code, "message": error.message}
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    return error.exit_code or 1


def _require_active_initiative_chain(root: Path, spec_path: Path) -> None:
    """Reject a retired canonical initiative before any chain preflight."""

    marker = retired_chain_marker(spec_path, root)
    if marker is not None:
        raise CliError(
            "initiative_retired",
            f"Retired initiative chain cannot be started: {spec_path}; "
            f"retirement marker: {marker}",
        )
