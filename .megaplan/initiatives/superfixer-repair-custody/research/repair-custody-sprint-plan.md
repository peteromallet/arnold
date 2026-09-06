---
superseded_by: custody-control-plane
---

# Superfixer Repair Custody Sprint Plan

## Context

On 2026-07-03, `agentic-replay-viewer` entered a repairable blocked state but the superfixer stack did not continue custody correctly.

The original infra failures were repaired:

- `git_push_failed` caused by an undersized 120 second push timeout.
- `module 'arnold_pipelines.megaplan.chain' has no attribute '_run_git_push_command'` caused by a missing package-facade re-export after the `git_ops` split.

After those repairs, the chain hit a real product-quality blocker: the PR had frontend/harness work, but the backend agent replay routes and route tests were missing. Plan state became:

- `current_state=blocked`
- `resume_cursor.retry_strategy=manual_review`
- `latest_failure.kind=blocked_recovery_not_resolved`

The plan-local repair queue accepted a repair request, but the watchdog's dispatch path treated this `manual_review` state as human-only and sent a Discord notification instead of dispatching the L1 repair loop. The immediate watchdog branch has since been patched so `blocked_recovery_not_resolved` dispatches repair before `needs_human`.

This sprint is about closing the structural category, not only the single branch.

## Objective

Make superfixer repair custody explicit and verifiable end to end: every repairable blocker has one canonical custody record, the dispatcher consumes it, at most one actor works it, and higher backstops flag broken custody as a system failure instead of letting work fall between local queues, derived labels, locks, and reports.

## Scope

In scope:

- Define a canonical repair custody projection over the existing repair request/decision artifacts.
- Make watchdog and repair-trigger consume the same custody projection so no accepted repair request can be invisible to the dispatcher.
- Add explicit repairability/human-gate semantics to blocker state.
- Move dispatch classification into a shared typed Python classifier and make it exhaustive over emitted state tokens and failure kinds.
- Add invariants that detect repairable blockers without queued/running/failed repair custody.
- Define the lock ownership hardening needed to close this class, but split broad lock-service extraction if it exceeds the core custody sprint.
- Extend L3 progress-auditor checks for broken repair custody.
- Improve `cloud status` buckets so operators see running, repairing, repairable-but-not-repairing, human-gated, complete, and broken-superfixer states.

Out of scope:

- Completing the `agentic-replay-viewer` product work itself.
- Replacing the whole watchdog shell wrapper with a new service architecture.
- Reworking unrelated chain execution semantics.
- Broad changes to model routing or provider selection.
- Completing full watchdog lock-service extraction if it expands beyond observable lock metadata and safe stale-lock reclaim.
- Broad deployment/CI overhaul beyond the minimum checks needed to prove the custody fix is actually installed.

## Design Principles

1. Ground truth beats derived labels.
2. Repairability is a typed decision, not a guess from `manual_review`.
3. A repairable blocker without custody is a superfixer failure.
4. Local queues and global dispatch must converge through one canonical record.
5. Lock ownership must be observable and self-healing.
6. Backstops must check custody, not only session liveness.
7. Dispatch rules belong in typed Python helpers; shell wrappers should orchestrate, not own policy.
8. Unknown or unclassified blockers default to safe escalation, not aggressive auto-repair.

## Canonical Store And Projection

The canonical custody layer should not start by deleting existing artifacts. Existing repair queue files and repair-data files already encode useful history. The sprint should add a typed projection module, tentatively `arnold_pipelines.megaplan.cloud.repair_custody`, that reads the existing sources and exposes a single coherent view.

Authoritative inputs:

- Repair requests and decisions under the existing `repair-queue/requests` and `repair-queue/decisions` layout.
- Plan `state.json`, chain state, event cursors, current-target evidence, watchdog report, repair lock metadata, and repair-data attempt records.

Canonical output:

- A versioned `RepairCustodySnapshot` keyed by a stable blocker identity.
- Append-only transition records for custody state changes.
- Durable repair attempt records. `dispatched`, `claimed`, and `running` are not terminal outcomes; custody remains open until an attempt records verified recovery, retryable failure, terminal failure, or true human requirement.

Migration shape:

1. Add read-only projection over current artifacts.
2. Dual-write transition/attempt records from enqueue, trigger, watchdog dispatch, and repair-loop exits.
3. Make watchdog/repair-trigger consume the projection for repairability decisions.
4. Keep legacy queue files readable until compatibility fixtures prove old sessions classify correctly.

## Proposed Workstreams

### 1. Canonical Repair Request Model

Create a canonical repair custody model per session/blocker. Keep request identity separate from repair attempts.

Minimum fields:

- `schema_version`
- `request_id`
- `run_kind`
- `session`
- `workspace`
- `remote_spec`
- `plan_name`
- `chain_or_plan_generation`
- `blocker_fingerprint`
- `blocker_id`
- `blocker_kind`
- `plan_current_state`
- `retry_strategy`
- `failure_kind`
- `failure_message`
- `repairable`
- `blocker_verdict`
- `custody_state`
- `source_artifacts` with paths, mtimes, event cursors, and content hashes
- `state_snapshot_sha256`
- `dispatch_decision` with matched rule, evidence snapshot, and watchdog/source version
- `queued_at`
- `claimed_at`
- `claimed_by`
- `process_pid`
- `last_heartbeat_at`
- `deadline_at`
- `attempts`
- `superseded_by_request_id`
- `outcome`
- `outcome_reason`

`custody_state` describes the request lifecycle. Plan-level state tokens are snapshots used for dispatch context; the plan's `state.json` remains the authority for plan state.

`attempts` is a list of repair-attempt records. Each attempt should include `attempt_id`, `started_at`, `finished_at`, `command`, `exit_code`, `stdout/stderr` references or summarized paths, `files_changed`, `commit_sha`, `push_state`, checkpoints, verification evidence, and final attempt outcome.

`blocker_fingerprint` should be a formal tuple, not a free-form string. At minimum: `workspace`, `remote_spec`, `run_kind`, `plan_name`, `chain_or_plan_generation`, `plan_state_fingerprint`, `failure_kind`, blocked task/gate identity, and target session. This is what prevents stale blockers and new blockers from collapsing incorrectly.

Lifecycle:

- `observed`
- `queued`
- `claimed`
- `running`
- `recovered`
- `failed_retryable`
- `failed_terminal`
- `human_required`
- `superseded`

Acceptance checks:

- Existing plan-local repair requests are consumed by the canonical projection. Mirroring alone is not acceptable if watchdog still ignores the canonical view.
- A request accepted by a plan-local component is visible to watchdog dispatch in the same pass or the next pass, with measurable propagation timestamps.
- Duplicate requests for the same blocker fingerprint collapse to one active custody record.
- A repair attempt launched via `Popen` cannot be considered terminal until heartbeat or terminal outcome evidence is written.

### 2. Typed Blocker Intent

Add explicit semantics to blocked/gated states.

The dispatcher should not infer policy only from `manual_review`. Intent should be written by plan/recovery state where possible and consumed by watchdog with a legacy fallback:

- `repairable=true|false`
- `human_required=true|false`
- `terminal=true|false`
- `blocker_kind`
- `blocker_verdict=true_blocker|stale_mismatch|ambiguous_blocker|mechanical_blocker|none`
- `recovery_command`
- `retry_policy`
- `repair_safety_tier=safe_config|safe_import|safe_retry|codegen_risky|unknown`

Rules:

- `manual_review` is a UI/operator posture, not a dispatch policy.
- `blocked_recovery_not_resolved` is repairable unless a typed blocker says `human_required=true`.
- Unknown blocker kinds default to `human_required=true` or `broken_superfixer`, never unbounded auto-repair.
- True human gates, including manual PR merge policy, must remain human-gated and must not be "repaired" as failures.

### 3. Shared Dispatch Classifier

Build a typed Python classifier, not another shell-only branch table. The classifier input should include:

- `current_state`
- `resume_cursor.phase`
- `resume_cursor.retry_strategy`
- `latest_failure.kind`
- `latest_gate.kind`
- chain-level `last_state`
- typed blocker intent
- canonical custody snapshot
- live process and lock evidence

Every observed combination must map to exactly one of:

- `run_or_relaunch`
- `repair`
- `repair_running`
- `wait`
- `human_required`
- `terminal`
- `broken_superfixer`

The shell watchdog should call the classifier and render/execute the returned decision. `arnold-repair-trigger`, L3, and `cloud status` should use the same classifier or projection rather than reimplementing independent string heuristics.

Shell/Python boundary:

- Shell keeps environment loading, source/installed drift detection, global tick lock acquisition, invoking the classifier, executing the returned action, report rendering, and notification delivery.
- Python owns reading plan/chain state, failure evidence, custody snapshots, process and lock evidence, state-token classification, matched-rule reporting, and `broken_superfixer` fallback.
- No new dispatch policy branches should be added in shell; new policy belongs in the classifier with table-driven tests.

Acceptance checks:

- Unit tests cover every known failure kind and retry strategy.
- Unknown combinations produce `broken_superfixer` instead of silent `observe`.
- `blocked_recovery_not_resolved + manual_review` remains covered by a regression fixture.
- Dispatch decisions record the matched rule and evidence snapshot so L3 can audit decisions without replaying stale state.

### 4. Custody Invariants

Add invariant checks in watchdog and L3:

- If a repairable blocker exists, then within one watchdog pass exactly one must be true:
  - canonical request is queued
  - repair loop is running for that request
  - repair recently failed with a concrete retry/terminal reason
  - `human_required=true`
- If a plan-local repair request exists but no canonical/global request exists, emit `broken_superfixer`.
- If `needs_human` is emitted for a repairable blocker, emit `broken_superfixer`.
- If report age exceeds expected cadence while sessions exist, emit stale-watchdog evidence.
- If `human_required=true`, require notification evidence and an acknowledgement deadline.
- If `broken_superfixer` is emitted, actively notify and halt autonomous repair dispatch for the affected session until the broken custody condition is cleared.

### 5. Atomic Claim And Lock Ownership

Separate the global watchdog tick lock from per-target repair custody locks. The exactly-one-actor invariant is about the target request claim, not the global report lock.

Claim protocol:

- One shared `claim_request(request_id, actor_id, expected_revision)` operation must be used by watchdog, repair-trigger, repair-loop, and L3-triggered repair.
- Claim must be atomic using an existing directory-lock or compare-and-swap style operation; no coordination should rely on read-modify-write JSON alone.
- Concurrent claim tests must prove only one actor transitions `queued` to `claimed`.

Lock observability:

Record:

- lock file path
- holder process pid
- holder command
- holder process start time
- process group
- container pid namespace
- host boot id or equivalent process-identity discriminator
- started_at
- last_heartbeat_at
- watchdog version/source hash

Recovery:

- If the lock owner process is gone, rotate or reclaim through a helper that tombstones the old lock before acquiring a new one.
- If heartbeat is stale beyond threshold and remains stale across a second observation or lease expiry, emit `broken_superfixer` and recover.
- Never let an orphaned lock freeze reports without a visible issue.

### 6. L3 Progress Auditor Coverage

Extend the 6h auditor to check repair custody, not only work progress.

It should detect:

- repairable blocker but no canonical request
- canonical request queued but no dispatcher action
- claimed/running request with dead process
- stale watchdog report
- stale or orphaned lock
- repeated human notifications for repairable blockers
- missing human notification for `human_required=true`
- plan-local/global repair queue disagreement
- dispatch decision made from stale state
- custody record stuck in `dispatched`, `claimed`, or `running` without attempt heartbeat/outcome evidence

The auditor's finding should name the broken layer and the missing custody transition.

### 7. Durable Deployment Verification

Add deployment and status checks:

- Compare source wrapper hash and `/usr/local/bin/arnold-watchdog` hash.
- Report `wrapper_drift` if they differ.
- Refuse to report a source-only or installed-only patch as fully fixed.
- Require repair-infra fixes to land on a branch with CI evidence before they are considered durable. Auto-generated repair commits must not be silently merged to protected branches.

### 8. Operator-Facing Status Buckets

Improve status output so operator attention goes to the right place.

Buckets:

- `running`
- `repairing`
- `repairable_not_repairing`
- `human_gated`
- `awaiting_pr_merge`
- `complete_recent`
- `complete_old`
- `broken_superfixer`
- `unknown_inconsistent`

The status view should explain the difference between "should be running" and "is running" using custody evidence, not only tmux/process liveness.

Bucket precedence:

1. `broken_superfixer`
2. `repairing`
3. `repairable_not_repairing`
4. `human_gated`
5. `awaiting_pr_merge`
6. `running`
7. terminal complete/failed states

`cloud status --all` should work from the cloud box without relying on the current working directory having `/workspace/cloud.yaml`; it should discover the shared marker directory and report the same buckets.

### 9. Safety Guardrails

Stronger automation must not erase human review or push unsafe changes.

Existing gates to preserve and surface:

- `ARNOLD_AUTONOMY=0` is the master kill switch for autonomous trigger/meta/auditor actions.
- Per-path feature flags control repair-trigger, meta-repair, audit autofix, and commit behavior.
- Repair locks, repair budgets, command allowlists, recursion guards, verified recovery classification, push gates, redaction, and watchdog self-integrity checks already constrain repair.
- The sprint should integrate with these gates and make them visible in custody/status evidence rather than bypassing or duplicating them.

Required guardrails:

- Hard cap consecutive repair attempts per blocker fingerprint, with backoff and escalation after exhaustion.
- Repair safety tiers control what can be auto-applied. Risky code generation must remain in a PR awaiting review.
- Unknown blocker kinds default to `human_required` or `broken_superfixer`.
- Transition to `recovered` requires re-evaluating the original blocker condition, not only repair-loop exit code.
- Every auto-pushed repair records pre-repair head SHA, repair commit SHA, push state, and rollback/revert guidance.
- Repair loops may not modify watchdog/superfixer internals unless the session is explicitly a repair-infrastructure session.

## Suggested Milestone Split

The reviewed scope is larger than one clean sprint if taken literally. Split it unless the brief is narrowed before launch.

### M1: Repair Custody Core

Scope:

- Canonical custody projection over existing request/decision artifacts.
- Request identity and attempt records.
- Typed blocker intent for the known repairable/human-gated paths.
- Shared Python dispatch classifier.
- Atomic claim protocol for active repair requests.
- Regression fixture for `blocked_recovery_not_resolved + manual_review`.
- Minimal status bucket changes needed to expose `repairing`, `repairable_not_repairing`, and `broken_superfixer`.

### M2: Repair Custody Observability

Scope:

- Custody invariants across watchdog and L3.
- Richer status presentation and recent-complete buckets.
- Auditor rebuild from append-only evidence.
- Human notification acknowledgement evidence.
- Remaining edge-case fixtures.

### Follow-Ups

- Watchdog lock observability/extraction if the lock work becomes broader than M1's atomic claim and safe stale reclaim.
- Deployment verification/CI hardening beyond source-vs-installed drift detection.

## Edge Cases To Challenge

- A blocker is repairable but also has a stale `needs-human` marker from a prior blocker.
- A chain advances to a new blocker while an old repair loop is still running.
- A repair loop starts, forks a child, and the parent exits.
- Two watchdog passes race and try to claim the same request.
- A session is alive but blocked in a phase with no progress.
- A chain is complete but stale marker or stale sidecar suggests it should run.
- Manual review is genuinely human-required.
- A repair loop fixes infra and the remaining blocker is product quality.
- A repair produces a commit but does not push or update plan state.
- A PR is open with merge policy manual; this should not be repaired as a failure.
- Source wrapper and installed wrapper diverge.
- The remote editable checkout is dirty and cannot pull latest watchdog changes.
- The lock owner is outside the container PID namespace.
- An orphaned lock entry appears in `/proc/locks` but no process is inspectable.
- L3 runs before a blocker is created and therefore cannot catch it yet.
- L3 runs after a blocker is created but sees stale watchdog data.
- Global queue and plan-local queue disagree.
- Duplicate markers point at the same workspace.
- A stale chain pointer says done while a live process is running a newer plan.
- Missing cloud config makes `cloud status --all` unavailable from the container cwd.
- A plan-local enqueue succeeds but the watchdog never reads the repair queue directory.
- The exact `blocked_recovery_not_resolved` patch masks future repairable `manual_review` failure kinds that still fall through to `needs_human`.
- Two locking domains disagree: queue claim files say one thing while watchdog flock/process checks say another.
- A repair attempt is dispatched but the child exits before writing heartbeat or outcome evidence.
- A stale `needs-human` marker refers to a different blocker fingerprint than the current repairable blocker.
- A `broken_superfixer` bucket exists but no active notification is sent.

## Acceptance Criteria

- A fixture reproducing the `agentic-replay-viewer` failure dispatches L1 repair and never emits DM-only `needs_human`.
- A plan-local accepted repair request becomes visible through the canonical custody projection and is consumed by watchdog/repair-trigger.
- Exactly one repair actor claims a given active blocker.
- `dispatched`, `claimed`, and `running` are not terminal without attempt outcome evidence.
- Concurrent claim tests prove the atomic claim operation prevents split-brain repair.
- Legacy v1 repair queue artifacts still classify correctly.
- Killing watchdog mid-pass does not leave an unrecoverable stale lock.
- L3 detects deliberate custody breaks and names the broken transition.
- Status output has explicit buckets for repairing, repairable-but-not-repairing, and broken-superfixer, with precedence tests.
- Wrapper/source drift is visible and fails the deployment verification check.
- Tests cover known state/failure/retry combinations and unknown-token fallback.
- Risky or unknown repair types do not auto-push/auto-merge without review evidence.

## Candidate Megaplan Shape

This should be launched as an epic or narrowed to M1 before launch. The full document spans state semantics, dispatch, queue convergence, lock recovery, L3 auditing, status, and deployment hygiene. M1 alone is a defensible sprint-sized megaplan if held to repair-custody core.

Suggested sprint title: `superfixer-repair-custody-hardening`.

Suggested M1 title: `repair-custody-core`.

Suggested profile before final sizing: high planning sensitivity because this crosses state semantics, watchdog shell behavior, custody data contracts, and autonomous repair safety.
