---
superseded_by: custody-control-plane
---

# Load-Bearing Questions: Superfixer Repair Custody

These are the decisions that determine the shape of the sprint. Each answer is the current working position before the second DeepSeek review pass.

## 1. What is the canonical source of repair custody?

Answer: Add a canonical custody projection over plan state (`state.json`, chain state), repair queue/request/decision artifacts, and repair-data records. The watchdog currently reads plan state directly and ignores the repair queue; the repair-trigger reads the repair queue but has limited plan-state context. The projection must consume both sources and expose a single `RepairCustodySnapshot`. Plan state and repair queue artifacts remain authoritative inputs during migration; neither is replaced. The projection becomes the single read model for watchdog, repair-trigger, status, and L3.

Why it matters: If watchdog keeps inferring from plan state while plan-local queues keep writing elsewhere, the original failure class remains.

## 2. Is `manual_review` a dispatch policy or a presentation/state posture?

Answer: It is a posture set by plan/recovery code, but it is currently consumed as a dispatch gate by the watchdog shell. The sprint must move dispatch to typed blocker intent (`repairable`, `human_required`, `terminal`, `blocker_kind`, safety tier) and demote `manual_review` to a presentation-only signal for status/operators.

Why it matters: The incident happened because `manual_review` was treated as human-only in dispatch even when the blocker was repairable. The hotfix patched one branch; the structural fix is to stop using `manual_review` as a dispatch boolean.

## 3. Should dispatch logic live in shell wrappers or typed Python?

Answer: Typed Python. Shell wrappers should gather environment, hold wrapper-level locks, call a Python classifier, and execute/report the returned decision.

Why it matters: More shell branching would repeat the current fragility and make exhaustive testing hard.

## 4. What is the identity of a blocker?

Answer: A blocker's identity is a stable `blocker_id` derived deterministically from a formal `blocker_fingerprint` tuple. The fingerprint must include workspace, remote spec, run kind, plan/chain generation, plan-state fingerprint, failure kind, blocked task/gate identity, and target session. The `blocker_id` is the lookup key; the fingerprint is the evidence tuple. Neither is a free-form string. Current plan-local IDs lack enough session/workspace scope and can collide across sessions.

Why it matters: Dedupe, supersession, stale `needs-human` markers, and new blocker emergence all depend on identity. Without session-scoped fingerprints, two chains can produce the same local blocker ID for different blockers, breaking custody tracking.

## 5. What is the distinction between a repair request and a repair attempt?

Answer: A repair request is the durable, idempotent intent to repair one blocker — an immutable queue marker with a stable request identity. A repair attempt is one concrete invocation of the repair loop, recorded with its own attempt_id, process evidence, commit SHAs, exit code, push state, and verification outcome. A request may have zero, one, or multiple attempts. `dispatched`, `claimed`, and `running` are not terminal outcomes; custody remains open until an attempt records verified recovery, retryable failure, terminal failure, or true human requirement.

Why it matters: The current system can mark dispatch as terminal even if the child dies before doing useful work.

## 6. How do we guarantee exactly one repair actor?

Answer: Introduce one shared atomic claim operation, `claim_request(request_id, actor_id, expected_revision)`, that transitions the canonical custody record from `queued` to `claimed` using directory-lock/CAS-style semantics. All dispatchers — watchdog, repair-trigger, and L3 — must call this primitive before launching repair. The claim writes `claimed_at`, `claimed_by`, and heartbeat metadata into the custody record so there is one source of truth, not a separate lock artifact that can drift. JSON read-modify-write is not enough. Concurrent claimers must be tested to prove exactly one wins.

Why it matters: Watchdog, repair-trigger, and L3 must not launch split-brain repairs for the same blocker. Today the trigger has a global mutex, the repair loop has a per-session lock, and watchdog has its own heuristics — three locking domains with no shared claim primitive.

## 7. What should happen to unknown or ambiguous blockers?

Answer: Never auto-repair. Unknown blockers (classifier cannot determine blocker kind) default to `human_required=true` with active notification; if the unknown stems from an unhandled state/failure combination in the classifier, also emit `broken_superfixer` because the classifier must be exhaustive. Ambiguous blockers (signals match multiple categories) default to `human_required` (conservative) and record the ambiguity for classifier improvement. Both cases require durable records so L3 and operators can audit them.

Why it matters: Stronger repair automation must not erase real human gates. The distinction between `human_required` and `broken_superfixer` matters for operator triage and system health.

## 8. What should L3 audit: progress, custody, or both?

Answer: Both, but custody must become explicit. L3 should retain progress auditing while adding custody checks for repairable blocker without request, queued request without dispatch, running request with dead process, stale watchdog report, plan-local/global disagreement, and repeated human notifications for repairable blockers.

Why it matters: The first backstop can fail; L3 must catch broken custody rather than only summarize stuck sessions.

## 9. What is in M1 versus later milestones?

Answer: M1 should be `repair-custody-core`: custody projection, request/attempt identity, typed blocker intent for known paths, Python classifier, atomic claim, exact regression fixture, and minimal status buckets. Custody invariants across watchdog and L3, full status presentation, human acknowledgement evidence, remaining edge-case fixtures, lock-service extraction, and CI/deploy hardening are later.

Why it matters: The full document is too broad for one sprint. Over-scoping M1 risks not landing the core fix.

## 10. What safety gates constrain autonomous repair?

Answer: The plan must preserve existing gates and add the missing ones.

Existing gates include: `ARNOLD_AUTONOMY=0` as the master kill switch; per-path feature flags for repair-trigger, meta-repair, audit autofix, and commit behavior; repair locks with stale detection; repair and meta-repair wall-clock budgets; command allowlisting; recursion prevention; verified recovery classification; commit/push gates such as `CLOUD_WATCHDOG_PUSH_REPAIRS=0`; redaction; and watchdog self-integrity checks.

Sprint additions include: attempt caps and backoff per blocker fingerprint, safety tiers, verified pre/post head SHAs, rollback guidance, auditable push state, and a ban on modifying superfixer internals unless the session is explicitly repair-infrastructure work.

Why it matters: Closing the missed-repair class must not create unsafe auto-repair or auto-push behavior. The existing gates are substantial but incomplete; the sprint fills the gaps around blocker-scoped attempt limits, safety-tier classification, and auditable push evidence.
