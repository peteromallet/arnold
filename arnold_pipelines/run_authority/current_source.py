"""Authoritative current-source checker over Run Authority records (Step 12A).

The Run Authority *reducer* (:mod:`arnold_pipelines.run_authority.reducer`)
collapses the append-only journal into a :class:`RunAuthorityView`.  This
module answers the narrow question that the custody action validator
needs: *for this exact run/revision/attempt/decision, is there an
authoritative current grant, fence, and accepted decision?*

The answer is ``SATISFIED`` **only** when every component matches
exactly.  Any stale, conflicting, missing, superseded, or quarantined
record denies.  There is no "partial" or "shadow" satisfied state.

This replaces the old syntax-only Run Authority checks that accepted a
grant by its shape alone without verifying it is the *current* grant for
the *current* revision and attempt.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from arnold_pipelines.run_authority import reducer
from arnold_pipelines.run_authority.contracts import (
    CapabilityGrant,
    CoordinatorFence,
    Decision,
    QuarantineRecord,
    SubjectAttempt,
)

__all__ = [
    "CurrentSourceStatus",
    "SATISFIED",
    "DENIED",
    "CurrentSourceRequest",
    "CurrentSourceResult",
    "evaluate_current_source",
    "is_current_source_satisfied",
]


@dataclass(frozen=True)
class CurrentSourceStatus:
    """Two-valued outcome: only ``SATISFIED`` authorizes an action."""

    value: str
    is_satisfied: bool

    def __str__(self) -> str:
        return self.value


SATISFIED = CurrentSourceStatus("SATISFIED", True)
DENIED = CurrentSourceStatus("DENIED", False)


@dataclass(frozen=True)
class CurrentSourceRequest:
    """The exact authority identity an action claims to hold."""

    run_id: str
    run_revision: str
    coordinator_attempt_id: str
    grant_id: str
    fence_token: str
    subject_attempt_id: str
    decision_id: str
    # Launch effects bind the current tuple to an exact subject and
    # capability.  These remain optional for historical read-only callers.
    subject_id: str | None = None
    capability: str | None = None


@dataclass(frozen=True)
class CurrentSourceResult:
    """Outcome of evaluating a :class:`CurrentSourceRequest`."""

    status: CurrentSourceStatus
    reason: str
    detail: dict[str, Any]


def _denied(reason: str, **detail: Any) -> CurrentSourceResult:
    return CurrentSourceResult(DENIED, reason, dict(detail))


def _latest_revision(records: Iterable[Any]) -> str | None:
    best: str | None = None
    for rec in records:
        rev = getattr(rec, "run_revision", None)
        if rev is None:
            continue
        if best is None or str(rev) > str(best):
            best = str(rev)
    return best


def _active_grant(
    view: reducer.RunAuthorityView, request: CurrentSourceRequest
) -> CapabilityGrant | None:
    """Return the grant matching the request iff it is the *current* one."""
    latest_revision = _latest_revision(view.grants) or view.run_revision
    for grant in view.grants:
        if grant.grant_id != request.grant_id:
            continue
        if grant.run_id != request.run_id:
            continue
        # The grant must belong to the current (latest) revision — a grant
        # from an older revision is stale and must not authorize.
        if str(grant.run_revision) != str(latest_revision):
            return None
        return grant
    return None


def _active_fence(
    view: reducer.RunAuthorityView, request: CurrentSourceRequest
) -> CoordinatorFence | None:
    for fence in view.fences:
        if fence.run_id != request.run_id:
            continue
        if str(fence.run_revision) != str(request.run_revision):
            continue
        if fence.coordinator_attempt_id != request.coordinator_attempt_id:
            continue
        if str(fence.token) != str(request.fence_token):
            continue
        return fence
    return None


def _active_attempt(
    view: reducer.RunAuthorityView, request: CurrentSourceRequest
) -> SubjectAttempt | None:
    for attempt in view.attempts:
        if attempt.run_id != request.run_id:
            continue
        if str(attempt.run_revision) != str(request.run_revision):
            continue
        if attempt.attempt_id != request.subject_attempt_id:
            continue
        return attempt
    return None


def _accepted_decision(
    view: reducer.RunAuthorityView, request: CurrentSourceRequest
) -> Decision | None:
    for decision in view.decisions:
        if decision.run_id != request.run_id:
            continue
        if str(decision.run_revision) != str(request.run_revision):
            continue
        if decision.decision_id != request.decision_id:
            continue
        # Only an *accepted* decision authorizes; anything else denies.
        outcome = str(decision.outcome).strip().lower()
        if outcome != "accepted":
            return None
        return decision
    return None


def evaluate_current_source(
    view: reducer.RunAuthorityView,
    request: CurrentSourceRequest,
) -> CurrentSourceResult:
    """Return ``SATISFIED`` only when every authority component matches exactly.

    Order of checks (each denies on the first failure):

    1. The view's ``run_revision`` must equal the requested revision — a
       view for a different revision is stale.
    2. An *active* grant for the requested grant id at the current
       revision must exist.
    3. A matching coordinator fence (revision + attempt + token) must exist.
    4. The requested subject attempt must exist for this revision.
    5. An *accepted* decision for the requested decision id must exist.
    6. No quarantine record may reference any of the matched identities.

    A *satisfied* result carries the matched records so callers can
    attach them as durable evidence.  Every non-satisfied result is
    ``DENIED`` with a specific reason.
    """
    if str(view.run_id) != str(request.run_id):
        return _denied("run_id mismatch", expected=request.run_id, observed=view.run_id)

    if str(view.run_revision) != str(request.run_revision):
        return _denied(
            "run_revision is not the current view revision",
            expected=request.run_revision,
            observed=view.run_revision,
        )

    grant = _active_grant(view, request)
    if grant is None:
        return _denied("no active grant for the requested grant id at the current revision",
                       grant_id=request.grant_id)

    if request.subject_id is not None and request.subject_id not in grant.subject_ids:
        return _denied(
            "active grant does not cover the requested subject",
            subject_id=request.subject_id,
            grant_subject_ids=grant.subject_ids,
        )
    if request.capability is not None and request.capability not in grant.capabilities:
        return _denied(
            "active grant does not cover the requested capability",
            capability=request.capability,
            grant_capabilities=grant.capabilities,
        )

    fence = _active_fence(view, request)
    if fence is None:
        return _denied("no matching coordinator fence", fence_token=request.fence_token,
                       coordinator_attempt_id=request.coordinator_attempt_id)

    attempt = _active_attempt(view, request)
    if attempt is None:
        return _denied("no matching subject attempt", subject_attempt_id=request.subject_attempt_id)

    decision = _accepted_decision(view, request)
    if decision is None:
        return _denied("no accepted decision for the requested decision id",
                       decision_id=request.decision_id)

    quarantined_ids = _quarantined_target_ids(view.quarantines)
    for identity in (
        request.grant_id,
        request.fence_token,
        request.subject_attempt_id,
        request.decision_id,
    ):
        if identity in quarantined_ids:
            return _denied("a matched authority record is quarantined", quarantined_identity=identity)

    return CurrentSourceResult(
        SATISFIED,
        "current grant, fence, attempt, and accepted decision all match",
        {
            "grant_id": grant.grant_id,
            "fence_token": fence.token,
            "subject_attempt_id": attempt.attempt_id,
            "decision_id": decision.decision_id,
            "view_hash": view.view_hash,
        },
    )


def is_current_source_satisfied(
    view: reducer.RunAuthorityView,
    request: CurrentSourceRequest,
) -> bool:
    """Convenience boolean for the satisfied status only."""
    return evaluate_current_source(view, request).status.is_satisfied


def _quarantined_target_ids(
    quarantines: tuple[QuarantineRecord, ...],
) -> frozenset[str]:
    """Collect every record id referenced by a quarantine record."""
    ids: set[str] = set()
    for q in quarantines:
        raw = getattr(q, "payload", None)
        # Contract payloads are immutable MappingProxyType instances after
        # construction, not plain dicts.  Treat every Mapping as authoritative
        # quarantine payload evidence; otherwise a quarantine can be present in
        # the reduced view while the current-source gate silently ignores its
        # referenced grant/attempt/decision identities.
        if isinstance(raw, Mapping):
            for value in raw.values():
                if isinstance(value, str):
                    ids.add(value)
        # Also surface the quarantine's own id and any referenced record id.
        target = getattr(q, "record_id", None) or getattr(q, "quarantine_id", None)
        if isinstance(target, str):
            ids.add(target)
    return frozenset(ids)
