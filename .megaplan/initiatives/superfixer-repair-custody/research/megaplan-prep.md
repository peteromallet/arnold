---
superseded_by: custody-control-plane
---

# Megaplan Prep: Superfixer Repair Custody

## Input

Brief candidate:

- `.megaplan/initiatives/superfixer-repair-custody/repair-custody-sprint-plan.md`

Review process completed before sizing:

- 20 DeepSeek V4 Pro lens reviews via `fan.py`: 20/20 completed.
- 3 Codex GPT-5.5 reviews: data consistency, structural consistency, technical abstractions.
- The plan was revised after review to add canonical store/projection, request-vs-attempt separation, atomic claim semantics, typed dispatch classifier, safety guardrails, and a milestone split.

## Sizing Decision

The full document is bigger than a single two-week sprint if implemented literally. It spans:

- custody data model and migration
- queue/dispatch convergence
- typed blocker semantics
- shared dispatch classifier
- atomic claim and lock ownership
- watchdog/L3 invariants
- status buckets
- deployment verification and safety policy

Recommended shape: run this as an epic with at least two milestones, or narrow the launch to M1 only.

## Recommended First Megaplan

Title: `repair-custody-core`

Outcome:

Implement the core repair-custody contract so repairable blockers cannot fall between plan-local queueing and watchdog dispatch. The sprint should produce a typed custody projection, durable attempt records, atomic request claiming, a shared Python dispatch classifier, and regression coverage for `blocked_recovery_not_resolved + manual_review`.

In scope:

- Canonical custody projection over existing repair request/decision artifacts.
- Request identity and repair-attempt records.
- Typed blocker intent for known repairable and human-gated paths.
- Shared Python `DispatchInput -> DispatchDecision` classifier.
- Atomic claim operation for active repair requests.
- Regression fixture for the `agentic-replay-viewer` failure shape.
- Minimal status exposure for `repairing`, `repairable_not_repairing`, and `broken_superfixer`.

Out of scope for M1:

- Full L3 auditor rebuild from append-only evidence.
- Full watchdog lock-service extraction.
- Full deployment/CI hardening beyond proving the installed/source fix is not divergent.
- Completing the `agentic-replay-viewer` product feature.

## Profile Recommendation

Overall plan difficulty: 5/5; selected profile: `partnered-5`; because a bad plan here can pass local tests while silently weakening autonomous repair safety, dispatch custody, or human-gate semantics.

Planning complexity: `full`.

Reasoning depth: `high`.

Recommended invocation if you approve M1:

```bash
python -m arnold_pipelines.megaplan init \
  .megaplan/initiatives/superfixer-repair-custody/repair-custody-sprint-plan.md \
  --profile partnered-5 \
  --robustness full \
  --depth high \
  --vendor codex
```

Consider `--with-prep` only if the launch brief is further narrowed and we want the harness itself to re-survey the exact implementation files. The current pre-brief review already covered the main architecture risks, so prep is useful but not mandatory.

## Epic Alternative

If you want the full document executed rather than M1 only, use an epic:

- M1: `repair-custody-core`
- M2: `repair-custody-observability`
- Follow-up: `watchdog-lock-observability`
- Follow-up: `deployment-verification`

For the full epic, keep M1 at `partnered-5/full/high`. M2 can likely be `partnered-4/full` after M1 produces the custody model.

## Awaiting Decision

No megaplan has been started. Awaiting operator word on whether to launch:

- M1 only: `repair-custody-core`
- the broader epic
- a narrower variant
- no run yet
