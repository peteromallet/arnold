"""Closed Megaplan workflow outcome StrEnum classes.

Each StrEnum captures the exact routing vocabulary for one workflow domain
(gate, tiebreaker, review, override, execution, finalize, suspension/halt).
The enum values are required to match the authoritative RUNTIME_BRANCH_VOCABULARY
defined in ``workflows.components``, but these enums live here to avoid
reusing ``arnold/runtime/outcome.py`` as the workflow authority.

North Star compatibility quarantine: raw strings may only remain at explicit
enum-to-string serialization adapters (manifests, CLI compat, persisted
payloads, external schema boundaries) — never in workflow routing authority.
"""

from __future__ import annotations

from enum import StrEnum


class PrepOutcome(StrEnum):
    """Closed routing vocabulary for the prep step."""

    CONTINUE = "continue"
    AWAITING_HUMAN = "awaiting_human"


class CritiqueOutcome(StrEnum):
    """Closed routing vocabulary for the critique step."""

    COMPLETED = "completed"


class GateOutcome(StrEnum):
    """Closed routing vocabulary for the gate step."""

    PROCEED = "proceed"
    ITERATE = "iterate"
    TIEBREAKER = "tiebreaker"
    ESCALATE = "escalate"
    ABORT = "abort"
    SUSPEND = "suspend"
    BLOCKED_PREFLIGHT = "blocked_preflight"
    FORCE_PROCEED = "force_proceed"
    RETRY_GATE = "retry_gate"
    REPROMPT_DOWNGRADE = "reprompt_downgrade"


class TiebreakerOutcome(StrEnum):
    """Closed routing vocabulary for the tiebreaker subpipeline.

    Canonical alias: TiebreakerDecisionOutcome.
    """

    ITERATE = "iterate"
    PROCEED = "proceed"
    ESCALATE = "escalate"
    REPLAN = "replan"


# Canonical alias — TiebreakerDecisionOutcome is the preferred name for the
# decision-phase outcome. TiebreakerOutcome is retained for backward
# compatibility (e.g. AST-based tests that introspect __name__).
TiebreakerDecisionOutcome = TiebreakerOutcome


class TiebreakerResearcherOutcome(StrEnum):
    """Closed routing vocabulary for the tiebreaker researcher child phase."""

    COMPLETED = "completed"


class TiebreakerChallengerOutcome(StrEnum):
    """Closed routing vocabulary for the tiebreaker challenger child phase."""

    COMPLETED = "completed"


class TiebreakerSynthesisOutcome(StrEnum):
    """Closed routing vocabulary for the tiebreaker synthesis child phase."""

    COMPLETED = "completed"


class ReviewOutcome(StrEnum):
    """Closed routing vocabulary for the review step."""

    PASS = "pass"
    REWORK = "rework"
    BLOCKED = "blocked"
    FORCE_PROCEEDED = "force_proceeded"
    DEFERRED_HUMAN = "deferred_human"


class ReviewDecisionResult(StrEnum):
    """Typed review handler result values.

    These values are intentionally distinct from ``ReviewOutcome`` route
    signals: the handler may emit a successful review result while still using
    a terminal route signal such as ``pass`` or ``deferred_human``.
    """

    SUCCESS = "success"
    NEEDS_REWORK = "needs_rework"
    BLOCKED = "blocked"
    FORCE_PROCEEDED = "force_proceeded"
    POLICY_DENIED = "policy_denied"


class OverrideOutcome(StrEnum):
    """Closed routing vocabulary for the override step."""

    ABORT = "abort"
    CAP_REVISE_ONCE = "cap_revise_once"
    CUTOVER = "cutover"
    FORCE_PROCEED = "force_proceed"
    REPLAN = "replan"


class OverridePolicyRoute(StrEnum):
    """Declared native policy routes for override actions outside direct branches.

    These routes remain source-visible in ``workflow.pypeline`` even when the
    action resumes through persisted state or recovery policy instead of a
    direct ``OverrideOutcome`` branch.
    """

    ADOPT_EXECUTION = "adopt_execution"
    RECONCILE_PLAN_LEDGER = "reconcile_plan_ledger"
    RECOVER_BLOCKED = "recover_blocked"
    RESUME_CLARIFY = "resume_clarify"


class ExecuteOutcome(StrEnum):
    """Closed routing vocabulary for the execute step.

    Execute is a terminal-or-loop step; the routing vocabulary is the set
    of outcomes that may be emitted by the execution phase.
    """

    SUCCESS = "success"
    BLOCKED = "blocked"
    FAILED = "failed"


class FinalizeOutcome(StrEnum):
    """Closed routing vocabulary for the finalize step.

    Finalize is a terminal step; its outcomes describe the final disposition
    of the workflow run.
    """

    FINALIZED = "finalized"
    BLOCKED = "blocked"


class ReviseOutcome(StrEnum):
    """Closed routing vocabulary for the revise step."""

    COMPLETED = "completed"


class SuspensionOutcome(StrEnum):
    """Closed routing vocabulary for suspension transitions."""

    SUSPEND = "suspend"
    RESUME = "resume"


class HaltOutcome(StrEnum):
    """Closed routing vocabulary for halt transitions."""

    HALT = "halt"


class SuspensionHaltOutcome(StrEnum):
    """Closed routing vocabulary for suspension and halt transitions."""

    SUSPEND = "suspend"
    HALT = "halt"
    AWAITING_HUMAN = "awaiting_human"


# ── Aggregate mapping for RUNTIME_BRANCH_VOCABULARY parity checks ───────────

# Each key matches a RUNTIME_BRANCH_VOCABULARY key in workflows.components.
# Each value is the StrEnum class whose .values() must match the tuple.
OUTCOME_CLASS_BY_VOCABULARY_KEY: dict[str, type[StrEnum]] = {
    "prep": PrepOutcome,
    "critique": CritiqueOutcome,
    "gate": GateOutcome,
    "tiebreaker_researcher": TiebreakerResearcherOutcome,
    "tiebreaker_challenger": TiebreakerChallengerOutcome,
    "tiebreaker_synthesis": TiebreakerSynthesisOutcome,
    "tiebreaker_decision": TiebreakerDecisionOutcome,
    "tiebreaker_decide": TiebreakerDecisionOutcome,  # compatibility bridge; canonical is tiebreaker_decision
    "review": ReviewOutcome,
    "override": OverrideOutcome,
    "revise": ReviseOutcome,
}


def assert_vocabulary_parity() -> None:
    """Assert that all outcome enum values match RUNTIME_BRANCH_VOCABULARY.

    This function is called by components.py at import time to ensure that
    the outcome enums stay in sync with the authoritative vocabulary.
    """
    from arnold_pipelines.megaplan.workflows.components import RUNTIME_BRANCH_VOCABULARY

    for key, enum_cls in OUTCOME_CLASS_BY_VOCABULARY_KEY.items():
        expected = tuple(enum_cls.__members__.values())  # type: ignore[attr-defined]
        actual = RUNTIME_BRANCH_VOCABULARY.get(key)
        if actual is None:
            raise AssertionError(
                f"Outcome key '{key}' has enum {enum_cls.__name__} "
                f"but is missing from RUNTIME_BRANCH_VOCABULARY"
            )
        if expected != actual:
            raise AssertionError(
                f"Vocabulary mismatch for '{key}': "
                f"enum values {expected!r} != RUNTIME_BRANCH_VOCABULARY {actual!r}"
            )


def all_vocabulary_keys_covered() -> set[str]:
    """Return the set of RUNTIME_BRANCH_VOCABULARY keys NOT covered by an enum."""
    from arnold_pipelines.megaplan.workflows.components import RUNTIME_BRANCH_VOCABULARY

    covered = set(OUTCOME_CLASS_BY_VOCABULARY_KEY)
    actual = set(RUNTIME_BRANCH_VOCABULARY)
    return actual - covered


__all__ = [
    "CritiqueOutcome",
    "ExecuteOutcome",
    "FinalizeOutcome",
    "GateOutcome",
    "HaltOutcome",
    "OverrideOutcome",
    "OverridePolicyRoute",
    "PrepOutcome",
    "ReviewOutcome",
    "ReviewDecisionResult",
    "ReviseOutcome",
    "SuspensionHaltOutcome",
    "SuspensionOutcome",
    "TiebreakerChallengerOutcome",
    "TiebreakerDecisionOutcome",
    "TiebreakerOutcome",
    "TiebreakerResearcherOutcome",
    "TiebreakerSynthesisOutcome",
    "OUTCOME_CLASS_BY_VOCABULARY_KEY",
    "all_vocabulary_keys_covered",
    "assert_vocabulary_parity",
]
