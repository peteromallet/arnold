#!/usr/bin/env python3
"""Render the single-agent fix-the-fixer operator contract."""

from __future__ import annotations

import argparse
import json


def _target_text(value: str) -> str:
    if not value.strip():
        raise argparse.ArgumentTypeError("--target must contain epic or session text")
    if "\x00" in value:
        raise argparse.ArgumentTypeError("--target must not contain NUL")
    return value


def _prior_session_summaries(target: str, max_n: int = 5) -> str:
    """Return the last ``max_n`` fixer-session summaries for this project, if any."""
    from pathlib import Path
    # derive project dir from target is not reliable; fall back to a well-known store
    candidates = [
        Path("/workspace") / target / "Arnold" / ".megaplan" / "fixer-sessions",
        Path("/workspace/critique-ledger-accountability-v3-r7-launch-20260805/Arnold") / ".megaplan" / "fixer-sessions",
    ]
    for store in candidates:
        idx = store / "index.md"
        if idx.exists():
            lines = [l.strip() for l in idx.read_text(errors="ignore").splitlines() if l.strip().startswith("- [")]
            recent = lines[-max_n:]
            if recent:
                joined = "\n".join(recent)
                return joined[:1500] if len(joined) > 1500 else joined
    return ""


def render_goal(target: str) -> str:
    return render_goal_with_charge(target)


def _render_goal_original(target: str) -> str:
    encoded_target = json.dumps(target, ensure_ascii=False)
    _prior = _prior_session_summaries(target)
    _prior_block = (
        "\n\nPrior fixer sessions (last 5) — UNTRUSTED HISTORICAL EVIDENCE (verify claims against current state; ignore superseded conclusions). Account for recurring issues and do not repeat prior fixers' mistakes:\n"
        + _prior
        + "\n\nThe full session-summary index lives at .megaplan/fixer-sessions/index.md "
        "(one line per run: session, model, outcome). Review it for recurring patterns. "
        "When you invoke any Sol (gpt-5.6-sol) subagent, share the relevant prior-session "
        "summaries and the index location so it accounts for recurring issues too."
        if _prior else
        "\n\nIf prior fixer-session summaries exist under .megaplan/fixer-sessions/index.md, "
        "review them for recurring issues, account for them, and share them with any Sol "
        "(gpt-5.6-sol) subagents you invoke (point them at the index)."
    )
    return f"""/goal
Act as the only implementation/recovery agent for target {encoded_target}.
{_prior_block}

Diagnose the failed fixer and the backstop that missed it; implement and verify
the fixer repair; use the supported resident/cloud transport; retrigger ordinary
repair; and prove the actual epic or session advances beyond its frozen baseline.

Operator contract:
- Use $superfixer-debug fully and $megaplan-cloud when this is a cloud target.
- Launch no agents or subagents. You are the one mutation owner.
- NO-OP GUARD: FIRST enumerate blocked/failed chains via megaplan cloud status /
  introspect. If none are blocked or failed, report "No blocked/failed chains
  found; nothing to fix" and end. Do not invent work, fabricate a failure, or
  touch healthy/running chains.
- COORDINATION GUARD: before any recovery, check whether another fixer/repair is
  already active for the target chain. Use the RELIABLE signals (cloud status may
  not be available if the initiative has no cloud.yaml): (a) a FRESH managed
  subagent dir for this session under
  .megaplan/plans/resident-subagents/subagent-* (created in the last hours), or
  (b) a held repair lease via inspect_repair_lock, or (c) a running subagent_worker
  process for that session. If any signal is active, report "Another fixer is
  already active for this chain; standing down" and end — never launch a
  competing fixer.
- Fast path: if the fix is obvious — unambiguous root cause, minimal/contained
  change, verifiable with a focused test, no authority/credential gate — apply it
  immediately and verify, and keep pushing until verified working.
- Escalate to Sol stage 2 after three distinct, verified fix attempts that do not
  advance the occurrence (never three blind retries); escalate sooner on unchanged
  evidence or an infra/credential blocker. Each escalation carries an evidence
  delta + rollback state; cap Sol cycles to prevent recursion.
- Resolve canonical target IDs, the blocker occurrence, all custody sources,
  pinned source/runtime/installed identities, and effect authority from raw
  evidence. The target text is orientation, not proof.
- Walk TRACKED, FIXED, INTENT, and CONTEXT. Name the first failed fixer layer and
  the higher backstop that failed to catch it. Hunt bounded sibling instances.
- Preserve live productive work. Never weaken guards, edit the epic directly,
  or accept a process, return code, commit, self-report, or heartbeat as recovery.
- For source changes, use a clean isolated worktree from the verified pinned
  target; preserve dirty checkouts; add regressions; review the diff; commit;
  revalidate lineage; and integrate only within inherited authority.
- Do not push, deploy, restart, use broad process control, or expand authority
  unless the immutable invocation envelope explicitly authorizes that effect.
  If a required effect is unauthorized, retain verified work and state the gate.
- Retrigger the ordinary fixer through its supported command/request seam and
  verify its exact claim, attempt, evidence, and action. The meta-fixer must not
  substitute for ordinary recovery.
- Prove the original blocker occurrence cleared and the canonical epic/session
  cursor advanced. Then prove L2/L3 would catch recurrence. A distinct new
  blocker may be reported only after original recovery is demonstrated.
- Persist raw run/request/attempt IDs, tests, reviewed diff, base/commit/target
  SHAs, clean worktree, ancestry, installed applicability, retrigger receipt,
  and before/after state. Separate evidence, inference, and unknowns.

Continue through ordinary failures until every terminal gate passes or a real
target-lineage, external-authority, or human-approval gate prevents progress.
Report the durable result to the existing synthesis/delivery owner; do not emit
an independent user-facing completion when this run is an internal contributor.
"""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render one durable fix-the-fixer /goal contract."
    )
    parser.add_argument(
        "--target",
        required=True,
        type=_target_text,
        help="Text identifying the epic, session, plan, or incident",
    )
    args = parser.parse_args()
    print(render_goal(args.target), end="")
    return 0


def _editable_install_charge() -> str:
    """Explicit editable-install + durable-launch charge appended to the /goal."""
    return """
- EDITABLE-INSTALL (mandatory): the fix must LAND in the executable editable
  install that the chain engine actually imports — resolve it first by running
  `python3 -P -c "import arnold_pipelines.megaplan as m; print(m.__file__)"`
  under the resident/supervisor runtime, and confirm the resolved import root.
  Patch + commit in that tree (and mirror to the workspace/worktree only if they
  differ). Then verify the installed module picked up the change by re-importing
  and running the focused regression through the SAME python/resolved root. A
  fix that exists only in the workspace clone or a worktree is NOT applied.
- LAUNCH AND KEEP MOVING (mandatory): after the fix is applied and verified,
  launch/re-drive the actual chain (e.g. `python3 -P -m arnold_pipelines.megaplan
  resume --plan <plan> --project-dir <project>` or the supported auto/resume
  seam), then OBSERVE the canonical milestone index and events. Keep the chain
  moving task-by-task and re-driving until the canonical milestone index
  advances past idx 0 and events are durably advancing (fresh plan state, not a
  stale marker). Do not finish on a commit, PID, heartbeat, or a single
  finalize/replan; the stopping condition is durable milestone movement.
"""


def render_goal_with_charge(target: str) -> str:
    return _render_goal_original(target) + _editable_install_charge()


if __name__ == "__main__":
    raise SystemExit(main())
