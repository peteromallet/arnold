"""Durable SQLite-backed store for ``ExecutionAttemptLedger`` event streams.

This module provides the M6A transactional store boundary for WBC ledger
events. It does NOT modify the ``ExecutionAttemptLedger`` schema — it reads
and writes the same frozen dataclasses via their existing ``to_dict()``
serialization contract.

Key invariants:
* SQLite WAL mode for concurrent readers and atomic writes.
* Contract-version binding to ``LEDGER_SCHEMA_VERSION`` in metadata.
* Durable serialization uses ``LedgerEvent.to_dict()`` and json.
* Readback reconstructs ``LedgerEvent`` and ``ExecutionAttemptLedger``
  without mutating schema fields.

Step 4 transactional append invariants (enforced inside ONE SQLite
``BEGIN IMMEDIATE`` transaction per append):

* **Monotonic sequence** — an appended event's ``sequence`` must be
  strictly greater than the largest persisted sequence for the same
  ``attempt_id``. A regression raises :class:`MonotonicSequenceError`.
* **Idempotency-key uniqueness with dedup** — appending an event whose
  ``(attempt_id, idempotency_key)`` already exists does not raise; the
  store returns the existing persisted event with ``is_duplicate=True``.
  Two different events with the same idempotency key can never coexist.
* **Exactly one terminal event** — once a terminal event
  (``completed``/``failed``/``cancelled``) is persisted for an attempt,
  any further append with a new idempotency key raises
  :class:`PostTerminalAppendError`. A second terminal therefore cannot
  land, and neither can any post-terminal non-terminal event.
* **Dedup wins over rejection** — when a duplicate idempotency key is
  presented, the existing event is returned even if the attempt has
  since reached a terminal state. Retries of the same logical append
  are therefore safe and observable.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Optional

from arnold.workflow.execution_attempt_ledger import (
    LEDGER_SCHEMA_VERSION,
    AdapterKind,
    AttemptEventType,
    AttemptIdentity,
    AttemptOutcome,
    AttemptProvenance,
    ExecutionAttemptLedger,
    GlobalEffectIdentity,
    GrantRef,
    LedgerEvent,
    PersistenceStatus,
    RuntimeAdapter,
    VersionSet,
)

# ── Store metadata constants ──────────────────────────────────────────────

_STORE_VERSION: str = "arnold.workflow.attempt_ledger_store.v1"
_METADATA_TABLE_DDL: str = """\
CREATE TABLE IF NOT EXISTS _store_metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

_EVENTS_TABLE_DDL: str = """\
CREATE TABLE IF NOT EXISTS attempt_events (
    attempt_id         TEXT    NOT NULL,
    sequence           INTEGER NOT NULL,
    idempotency_key    TEXT    NOT NULL,
    event_type         TEXT    NOT NULL,
    event_json         TEXT    NOT NULL,
    appended_at_ns     INTEGER NOT NULL,
    PRIMARY KEY (attempt_id, sequence)
);
"""

_EVENTS_IDEMPOTENCY_INDEX_DDL: str = """\
CREATE UNIQUE INDEX IF NOT EXISTS idx_attempt_events_idempotency
    ON attempt_events(attempt_id, idempotency_key);
"""

# Reservations are coordination state, not authority. They record that a
# caller has declared intent to start (or has already started) an attempt
# stream. They never mint completion, dispatch, or authority decisions.
_RESERVATIONS_TABLE_DDL: str = """\
CREATE TABLE IF NOT EXISTS attempt_reservations (
    attempt_id         TEXT    PRIMARY KEY,
    first_reserved_ns  INTEGER NOT NULL,
    last_reserved_ns   INTEGER NOT NULL,
    reservation_count  INTEGER NOT NULL DEFAULT 1
);
"""

# ── Diagnostic tables (Step 8) ────────────────────────────────────────────
#
# These tables persist ``PersistenceFailureDiagnostic`` and
# ``ReconciliationDiagnostic`` payloads as evidence, not authority.
# They are joinable to the event stream via ``attempt_id`` but never
# grant append or completion power — they are observable projections
# that the store records when persistence operations fail or are
# reconciled.
#
# Source-cursor tracking records where the source system has observed
# the attempt stream up to, enabling gap detection and reconciliation
# resumption without requiring re-scan of the full event history.

_PERSISTENCE_FAILURE_DIAGNOSTICS_TABLE_DDL: str = """\
CREATE TABLE IF NOT EXISTS persistence_failure_diagnostics (
    attempt_id              TEXT    NOT NULL,
    diagnostic_id           TEXT    NOT NULL PRIMARY KEY,
    target_event_sequence   INTEGER NOT NULL,
    failure_mode            TEXT    NOT NULL,
    observed_error          TEXT    NOT NULL,
    diagnostic_json         TEXT    NOT NULL,
    recorded_at_ns          INTEGER NOT NULL
);
"""

_RECONCILIATION_DIAGNOSTICS_TABLE_DDL: str = """\
CREATE TABLE IF NOT EXISTS reconciliation_diagnostics (
    attempt_id                   TEXT    NOT NULL,
    diagnostic_id                TEXT    NOT NULL PRIMARY KEY,
    reconciled_event_sequence    INTEGER NOT NULL,
    outcome                      TEXT    NOT NULL,
    outcome_detail               TEXT    NOT NULL,
    diagnostic_json              TEXT    NOT NULL,
    recorded_at_ns               INTEGER NOT NULL
);
"""

_SOURCE_CURSORS_TABLE_DDL: str = """\
CREATE TABLE IF NOT EXISTS source_cursors (
    attempt_id    TEXT    NOT NULL,
    cursor_key    TEXT    NOT NULL DEFAULT 'default',
    last_sequence INTEGER NOT NULL DEFAULT 0,
    last_position TEXT,
    updated_at_ns INTEGER NOT NULL,
    PRIMARY KEY (attempt_id, cursor_key)
);
"""

# ── Global effect reservation table (Step 8B1) ────────────────────────────
#
# Stores snapshotted GLEK inputs alongside the attempt reservation so a
# crash between writes cannot produce a torn snapshot.  The snapshot is
# written inside the same ``BEGIN IMMEDIATE`` transaction as the
# reservation, satisfying the Step 8B1 atomic co-persistence requirement.
#
# The primary key is ``(attempt_id, global_logical_effect_key)`` because a
# single attempt may carry multiple distinct global effects (Step 8B2).
_GLOBAL_EFFECT_RESERVATIONS_TABLE_DDL: str = """\
CREATE TABLE IF NOT EXISTS global_effect_reservations (
    attempt_id                  TEXT    NOT NULL,
    global_logical_effect_key   TEXT    NOT NULL,
    environment_id              TEXT    NOT NULL,
    action_target               TEXT    NOT NULL,
    action_version              TEXT    NOT NULL,
    effect_family               TEXT    NOT NULL,
    provider_target             TEXT    NOT NULL,
    canonical_request_identity  TEXT    NOT NULL,
    boundary_schema_hash        TEXT    NOT NULL,
    first_reserved_ns           INTEGER NOT NULL,
    reservation_count           INTEGER NOT NULL DEFAULT 1,
    snapshot_json               TEXT    NOT NULL,
    PRIMARY KEY (attempt_id, global_logical_effect_key)
);
"""

_GLOBAL_EFFECT_ATTEMPT_INDEX_DDL: str = """\
CREATE INDEX IF NOT EXISTS idx_global_effect_attempt
    ON global_effect_reservations(attempt_id);
"""

# ── Global effect terminal outcomes (Step 8B2) ─────────────────────────────
#
# Stores the single accepted terminal outcome per ``(attempt_id,
# global_logical_effect_key)``. The composite primary key enforces
# one-terminal-per-attempt-per-effect (the CAS). The unique index on
# ``global_logical_effect_key`` enforces cross-attempt exclusivity: once any
# attempt accepts a terminal outcome for a global effect, no other attempt
# may accept one for the same effect. This prevents two attempts from
# holding dispatch eligibility for the same global effect.
#
# Accepted outcomes are evidence/projection only — recording that a terminal
# outcome was durably accepted does not grant authority, dispatch, or
# completion beyond the CAS record itself. Resolution of indeterminate
# outcomes or cross-attempt conflicts requires the reconciliation policy in
# Step 10B.
_GLOBAL_EFFECT_OUTCOMES_TABLE_DDL: str = """\
CREATE TABLE IF NOT EXISTS global_effect_outcomes (
    attempt_id                  TEXT    NOT NULL,
    global_logical_effect_key   TEXT    NOT NULL,
    outcome_kind                TEXT    NOT NULL,
    outcome_payload_json        TEXT    NOT NULL,
    accepted_at_ns              INTEGER NOT NULL,
    PRIMARY KEY (attempt_id, global_logical_effect_key)
);
"""

_GLOBAL_EFFECT_OUTCOME_GLEK_UNIQUE_INDEX_DDL: str = """\
CREATE UNIQUE INDEX IF NOT EXISTS idx_global_effect_outcome_glek
    ON global_effect_outcomes(global_logical_effect_key);
"""

# ── Occurrence claim admission table (T-0101e occurrence exclusivity) ────────
#
# Stores the single admitted claim per repair occurrence.  The PK on
# ``occurrence_id`` is the cross-attempt CAS (mirrors the
# ``global_effect_outcomes`` UNIQUE(global_logical_effect_key) precedent):
# once any attempt's STARTED append admits the occurrence, no other attempt
# may admit a claim for it.  The second contender's admission raises
# ``OccurrenceClaimAdmissionConflict`` and rolls back its whole append
# transaction (zero mutation).
#
# The row is written in the SAME transaction as the admitting STARTED event
# so a claim is either fully admitted or not at all.  Applies only to
# occurrence-join claims (STARTED payload ``kind == "occurrence_join"``);
# phase/worker-dispatch attempts are keyed by their own targets and are not
# occurrence-exclusive.
_OCCURRENCE_CLAIM_KIND: str = "occurrence_join"

_OCCURRENCE_CLAIM_ADMISSIONS_TABLE_DDL: str = """\
CREATE TABLE IF NOT EXISTS occurrence_claim_admissions (
    occurrence_id   TEXT    PRIMARY KEY,
    attempt_id      TEXT    NOT NULL,
    claim_id        TEXT    NOT NULL,
    admitted_at_ns  INTEGER NOT NULL
);
"""

# ── Global effect conflict quarantine (Step 8B2) ────────────────────────────
#
# Quarantined conflicts are evidence-only: a cross-attempt outcome conflict,
# divergent outcome, or reservation-vs-outcome conflict is recorded here so
# the reconciliation policy (Step 10B) can inspect it. Quarantining never
# grants authority, dispatch, or completion — and never clears an
# indeterminate effect.
_GLOBAL_EFFECT_CONFLICT_QUARANTINE_TABLE_DDL: str = """\
CREATE TABLE IF NOT EXISTS global_effect_conflict_quarantine (
    conflict_id                 TEXT    NOT NULL PRIMARY KEY,
    attempt_id                  TEXT    NOT NULL,
    global_logical_effect_key   TEXT    NOT NULL,
    conflict_kind               TEXT    NOT NULL,
    conflict_detail_json        TEXT    NOT NULL,
    quarantined_at_ns           INTEGER NOT NULL
);
"""

_GLOBAL_EFFECT_CONFLICT_ATTEMPT_INDEX_DDL: str = """\
CREATE INDEX IF NOT EXISTS idx_global_effect_conflict_attempt
    ON global_effect_conflict_quarantine(attempt_id);
"""

# ── Cutover quiesce tables (Step 12b) ────────────────────────────────────────
#
# During cutover quiesce every in-flight attempt that fails to drain to a
# natural terminal event within the drain timeout is resolved fail-closed to
# ``INDETERMINATE``. The resolution mark is durable evidence (not authority):
# it records WHY the attempt could not drain (its last non-terminal event type
# and the exhaustive drain-category classification) so a post-cutover operator
# or reconciliation policy can inspect it. The mark never grants dispatch or
# completion — it only makes the fail-closed outcome observable and crash-safe.
_CUTOVER_INDETERMINATE_MARKS_TABLE_DDL: str = """\
CREATE TABLE IF NOT EXISTS cutover_indeterminate_marks (
    attempt_id          TEXT    NOT NULL PRIMARY KEY,
    last_event_type     TEXT    NOT NULL,
    last_event_sequence INTEGER NOT NULL,
    drain_category      TEXT    NOT NULL,
    resolved_outcome    TEXT    NOT NULL,
    mark_reason         TEXT    NOT NULL,
    marked_at_ns        INTEGER NOT NULL
);
"""

#: Metadata key persisting the ``cutover_in_progress`` admission fence. The
#: fence is stored in the durable ``_store_metadata`` table (NOT in-memory) so a
#: crash during cutover preserves the admission-closed state: reopening the
#: database sees the fence still set and continues to reject new admissions.
_CUTOVER_IN_PROGRESS_KEY: str = "cutover_in_progress"
_CUTOVER_IN_PROGRESS_SET: str = "1"

# String literal set of terminal event types. Mirrors the schema-private
# ``_TERMINAL_EVENT_TYPES`` frozenset (COMPLETED/FAILED/CANCELLED) but is
# kept as SQL string literals so it is fully self-contained in DML.
_TERMINAL_EVENT_TYPE_VALUES: tuple[str, ...] = (
    AttemptEventType.COMPLETED.value,
    AttemptEventType.FAILED.value,
    AttemptEventType.CANCELLED.value,
)

_REQUIRED_PREDECESSOR_EVENT: dict[str, str] = {
    AttemptEventType.COMPLETED.value: AttemptEventType.STARTED.value,
    AttemptEventType.FAILED.value: AttemptEventType.STARTED.value,
    AttemptEventType.RETRY_SCHEDULED.value: AttemptEventType.STARTED.value,
    AttemptEventType.SUSPENDED.value: AttemptEventType.STARTED.value,
    AttemptEventType.RESUMED.value: AttemptEventType.SUSPENDED.value,
    AttemptEventType.CANCELLED.value: AttemptEventType.STARTED.value,
    AttemptEventType.EXTERNAL_EFFECT_INTENT.value: AttemptEventType.STARTED.value,
    AttemptEventType.EXTERNAL_EFFECT_OUTCOME.value: (
        AttemptEventType.EXTERNAL_EFFECT_INTENT.value
    ),
    AttemptEventType.RECONCILIATION.value: AttemptEventType.PERSISTENCE_FAILED.value,
}


# ── Typed errors ──────────────────────────────────────────────────────────


class AttemptLedgerError(Exception):
    """Base class for typed attempt-ledger store errors.

    All store-generated invariant violations derive from this class so
    callers can distinguish store policy enforcement from generic
    ``sqlite3`` errors or schema ``ValueError`` raises.
    """


class MonotonicSequenceError(AttemptLedgerError):
    """Raised when an appended event violates strict sequence monotonicity.

    The appended event's ``sequence`` must be greater than the highest
    sequence already persisted for the same ``attempt_id``.
    """


class SequenceGapError(AttemptLedgerError):
    """Raised when an append would create a gap in an attempt event stream."""


class CausalPredecessorError(AttemptLedgerError):
    """Raised when an event does not name the immediately preceding sequence."""


class PostTerminalAppendError(AttemptLedgerError):
    """Raised when any append is attempted after a terminal event.

    Covers both second-terminal attempts and post-terminal non-terminal
    events. The single terminal event is final.
    """


class IdempotencyConflictError(AttemptLedgerError):
    """Compatibility name for a same-key divergent retry.

    The stricter WBC comparator reports field-level
    :class:`DivergentDuplicateError` evidence; that error subclasses this
    public name so older CL2 callers still fail closed without losing the
    richer quarantine record.
    """


def canonical_event_json(event: "LedgerEvent") -> str:
    """Return the historical exact JSON serialization for callers that need it.

    Store append paths use the WBC semantic comparator, which deliberately
    ignores only observation clocks and binds immutable identity.
    """
    return json.dumps(event.to_dict(), sort_keys=True, ensure_ascii=False)


class DuplicateTerminalError(PostTerminalAppendError):
    """Raised when a second terminal outcome is proposed for one attempt."""


class MissingStartEventError(AttemptLedgerError):
    """Raised when a terminal event is appended before a durable STARTED event.

    A terminal receipt cannot establish that an attempt was admitted or
    started.  Requiring the STARTED event in the same durable stream prevents a
    terminal label or imported result from manufacturing attempt completion.
    """


class DivergentDuplicateError(IdempotencyConflictError):
    """Raised when a duplicate idempotency key has divergent canonical content.

    An idempotency key already exists in the store, but the new event's
    canonical payload, outcome, schema hash, or terminal status differs
    from the stored event.  Exact duplicates remain idempotent; divergent
    duplicates are quarantined and this error is raised so callers can
    escalate rather than silently accepting a possibly different outcome.
    """

    def __init__(
        self,
        attempt_id: str,
        idempotency_key: str,
        divergences: list[str],
        stored_event_json: str,
        new_event_json: str,
    ) -> None:
        self.attempt_id = attempt_id
        self.idempotency_key = idempotency_key
        self.divergences = divergences
        self.stored_event_json = stored_event_json
        self.new_event_json = new_event_json
        super().__init__(
            f"Duplicate idempotency key {idempotency_key!r} for attempt "
            f"{attempt_id!r} has divergent content: {', '.join(divergences)}"
        )


class GlobalEffectConflictError(AttemptLedgerError):
    """Raised when a cross-attempt or divergent terminal-outcome conflict occurs.

    The conflicting reservation or outcome has been quarantined (in
    ``global_effect_conflict_quarantine``) before this error is raised.
    Callers must escalate — the conflict cannot be cleared by a new Run
    Authority grant or Custody epoch alone; only the reconciliation policy
    in Step 10B may resolve it.

    Step 8B2: this error enforces cross-attempt reservation CAS. Only one
    attempt may accept a terminal outcome per global effect. A second
    attempt attempting to accept the same GLEK after another attempt has
    already done so is quarantined and rejected.
    """

    def __init__(
        self,
        attempt_id: str,
        global_logical_effect_key: str,
        conflict_kind: str,
        detail: dict[str, Any],
    ) -> None:
        self.attempt_id = attempt_id
        self.global_logical_effect_key = global_logical_effect_key
        self.conflict_kind = conflict_kind
        self.detail = detail
        super().__init__(
            f"Global-effect conflict for attempt_id={attempt_id!r}, "
            f"glek={global_logical_effect_key!r}: {conflict_kind}"
        )


class OccurrenceClaimAdmissionConflict(AttemptLedgerError):
    """Raised when a second claim attempts STARTED admission for an occurrence.

    Cross-attempt occurrence exclusivity CAS (T-0101e): exactly ONE claim may
    be admitted per occurrence across ALL attempt streams.  The occurrence is
    keyed by the STARTED payload's ``occurrence_id`` for occurrence-join
    claims (``kind == "occurrence_join"``).  A second contender's admission
    INSERT violates the ``occurrence_claim_admissions`` UNIQUE(occurrence_id)
    constraint (mirroring the ``global_effect_outcomes`` UNIQUE-GLEK
    precedent) and the whole append transaction rolls back — zero mutation
    beyond nothing.

    The admission row is written in the SAME transaction as the STARTED event
    append, so a claim is either fully admitted (event + admission row) or not
    admitted at all.  Callers must escalate with a typed ``claim_denied``; the
    conflict cannot be cleared by retrying the same occurrence with a new
    claim id.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)


class CutoverInProgressError(AttemptLedgerError):
    """Raised when a new attempt admission is attempted during cutover quiesce.

    Once the durable ``cutover_in_progress`` admission fence is engaged
    (Step 12b), no NEW attempt stream may be admitted. Appends that
    CONTINUE an existing in-flight attempt — in particular the natural
    terminal events that drain an attempt to completion — remain allowed
    so the cutover can reach a quiescent state.

    This error is raised at the admission boundary (``reserve_attempt`` for a
    brand-new attempt and ``append_event`` for the first event of a new stream)
    and is therefore observable to every admission caller. The fence itself is
    persisted in ``_store_metadata`` so it survives a crash: reopening the
    database continues to reject new admissions until the cutover completes and
    clears the fence.
    """


# ── Gate types (Step 5: durable start and terminal verification) ───────────


class GateStatus(Enum):
    """Outcome of a durable gate verification.

    Gates never return optimistic defaults — they require durable evidence
    and fail closed when evidence is missing, ambiguous, or contradictory.
    """

    VERIFIED = "verified"
    """Durable evidence confirms the gate condition — a matching event exists
    and its persisted fields are coherent."""

    INCOMPLETE = "incomplete"
    """The gate condition has not been met — no matching event is present
    in the durable store. This is a normal non-terminal state, not a failure."""

    INDETERMINATE = "indeterminate"
    """Persistence is ambiguous — the store may have a matching row but its
    content cannot be verified (corrupt JSON, unexpected schema, etc.), or
    the query itself could not be completed. Callers must not treat this as
    success or as a definitive empty result."""

    INCOHERENT = "incoherent"
    """Durable evidence contradicts the gate's contract — for example,
    multiple events of a type that should appear at most once. This indicates
    a store invariant violation or bypass and must be surfaced, never
    silently resolved."""


@dataclass(frozen=True)
class StartGateResult:
    """Result of ``start_verified`` — a durable gate on the STARTED event.

    This is a non-authoritative projection. It does not grant dispatch or
    completion power — it only reports whether durable evidence for the
    STARTED event exists and is coherent.

    When ``status`` is ``VERIFIED``, ``started_event`` carries the
    deserialized and type-checked STARTED event. For all other statuses,
    ``started_event`` is ``None`` and ``evidence`` describes the reason.
    """

    attempt_id: str
    status: GateStatus
    started_event: Optional[LedgerEvent]
    evidence: str


@dataclass(frozen=True)
class TerminalGateResult:
    """Result of ``terminal_or_indeterminate_verified`` — a durable gate on
    the terminal event.

    This is a non-authoritative projection. It does not grant completion or
    dispatch power — it only reports whether durable evidence for a terminal
    event exists and is coherent.

    When ``status`` is ``VERIFIED``, ``terminal_event`` carries the
    deserialized and type-checked terminal event (COMPLETED, FAILED, or
    CANCELLED). For ``INCOMPLETE`` the attempt is still in-flight.
    ``INDETERMINATE`` and ``INCOHERENT`` signal that the durable store
    cannot be trusted for this attempt and the caller must not proceed.
    """

    attempt_id: str
    status: GateStatus
    terminal_event: Optional[LedgerEvent]
    evidence: str


# ── Result types ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AttemptReservation:
    """Result of reserving an attempt_id in the durable store.

    Captures the post-reservation observable state so callers can decide
    whether to proceed with ``append_started`` or short-circuit. This is
    evidence/projection only — it does not grant authority, dispatch, or
    completion.
    """

    attempt_id: str
    is_new: bool
    event_count: int
    last_sequence: int
    has_terminal: bool
    first_reserved_ns: int
    last_reserved_ns: int
    reservation_count: int


@dataclass(frozen=True)
class AppendResult:
    """Result of an append operation.

    ``event`` is the persisted event (the existing one when
    ``is_duplicate`` is True) so callers always see what is durable.
    """

    attempt_id: str
    event: LedgerEvent
    sequence: int
    is_duplicate: bool


# ── Diagnostic result types (Step 8) ───────────────────────────────────────


@dataclass(frozen=True)
class GapEntry:
    """A detected gap in the event sequence for an attempt.

    This is evidence only — it does not grant authority, dispatch, or
    completion.  Gaps are derived from comparing persisted ``sequence``
    values against the expected monotonic range.
    """

    attempt_id: str
    gap_start: int
    """The highest persisted sequence before the gap (0 if gap starts at 1)."""

    gap_end: int
    """The lowest persisted sequence after the gap (exclusive bound)."""

    missing_count: int
    """Number of sequences missing in this gap (``gap_end - gap_start - 1``)."""


@dataclass(frozen=True)
class SourceCursor:
    """A source cursor tracking observed upstream progress for an attempt.

    The cursor records where the source system has observed the event
    stream up to.  It is evidence, not authority — it does not grant
    append or completion power.  Callers use it to detect gaps, resume
    reconciliation, or determine whether the source has observed a
    terminal event.
    """

    attempt_id: str
    cursor_key: str
    last_sequence: int
    last_position: str | None
    updated_at_ns: int


@dataclass(frozen=True)
class GlobalEffectReservation:
    """Result of atomically reserving a global effect identity (Step 8B1).

    Captures the persisted GLEK snapshot so callers can verify that retries
    read the snapshotted identity rather than re-deriving from the current
    inventory schema.

    This is evidence/projection only — it does not grant authority,
    dispatch, or completion.
    """

    attempt_id: str
    effect_identity: GlobalEffectIdentity
    global_logical_effect_key: str
    first_reserved_ns: int
    reservation_count: int
    is_new: bool


@dataclass(frozen=True)
class GlobalEffectOutcome:
    """Accepted terminal outcome for a ``(attempt_id, GLEK)`` pair (Step 8B2).

    Records that a terminal outcome was durably accepted via the CAS.
    Evidence/projection only — does not grant authority, dispatch, or
    completion beyond recording that a terminal outcome was accepted.

    ``is_duplicate`` is ``True`` when an identical outcome already existed
    for the same ``(attempt_id, GLEK)`` (exact-duplicate idempotency).
    """

    attempt_id: str
    global_logical_effect_key: str
    outcome_kind: str
    outcome_payload: dict[str, Any]
    accepted_at_ns: int
    is_duplicate: bool


@dataclass(frozen=True)
class GlobalEffectConflict:
    """Quarantined global-effect conflict (Step 8B2).

    Evidence/projection only — quarantined conflicts do not grant
    authority or clear indeterminate effects. Only the reconciliation
    policy in Step 10B may resolve them.

    ``conflict_kind`` is one of:

    * ``cross_attempt_outcome`` — another attempt has already accepted a
      terminal outcome for the same GLEK.
    * ``divergent_outcome`` — the same ``(attempt_id, GLEK)`` already has
      a terminal outcome but with a different ``outcome_kind`` or
      canonical payload.
    """

    conflict_id: str
    attempt_id: str
    global_logical_effect_key: str
    conflict_kind: str
    detail: dict[str, Any]
    quarantined_at_ns: int


@dataclass(frozen=True)
class CutoverIndeterminateMark:
    """Durable resolution mark for an in-flight attempt that failed to drain.

    Recorded by cutover quiesce (Step 12b) when an attempt does not reach a
    natural terminal event within the drain timeout. The mark is evidence only
    — it makes the fail-closed ``INDETERMINATE`` outcome observable and
    crash-safe. It never grants dispatch or completion; resolution of an
    indeterminate attempt requires the post-cutover reconciliation policy.

    ``drain_category`` is one of the :class:`~arnold.critique_ledger.cutover.drain_map.DrainCategory`
    values (``indeterminate`` or ``persistence_fail_closed`` for a marked
    attempt — a terminal-drain attempt is never marked because it drained).
    """

    attempt_id: str
    last_event_type: str
    last_event_sequence: int
    drain_category: str
    resolved_outcome: str
    mark_reason: str
    marked_at_ns: int


# ── Public API ─────────────────────────────────────────────────────────────


class AttemptLedgerStore(ABC):
    """Abstract interface for durable attempt-ledger storage.

    Implementations must bind to the pinned ``LEDGER_SCHEMA_VERSION`` and
    round-trip ``LedgerEvent`` / ``ExecutionAttemptLedger`` without mutating
    any frozen dataclasses.

    Step 4 transactional semantics:

    * ``reserve_attempt`` is a coordination primitive. It does NOT mint
      authority, dispatch, or completion — it records intent and returns
      the current observable event state so callers can decide whether to
      proceed.
    * ``append_event`` is the authoritative append. It returns an
      :class:`AppendResult`. The result's ``is_duplicate`` flag is ``True``
      and ``event`` is the existing persisted event when an event with the
      same ``(attempt_id, idempotency_key)`` is already present. Otherwise
      the event is appended and ``is_duplicate`` is ``False``.
    * The four Step 4 invariants — monotonic sequence, idempotency-key
      uniqueness, exactly one terminal, and post-terminal rejection — are
      enforced inside a single transaction per append. Dedup is checked
      before any rejection, so a duplicate of an event that has since
      become post-terminal still returns the existing event rather than
      raising.
    """

    @abstractmethod
    def initialize_attempt(self, attempt_id: str) -> None:
        """Prepare durable storage for *attempt_id*.

        Must be idempotent — safe to call more than once per attempt.
        """
        ...

    @abstractmethod
    def reserve_attempt(self, attempt_id: str) -> AttemptReservation:
        """Reserve *attempt_id* and return its current observable state.

        Idempotent. Repeated calls for the same ``attempt_id`` increment
        ``reservation_count`` and refresh ``last_reserved_ns`` but never
        raise for normal re-reservation.

        The returned :class:`AttemptReservation` is a non-authoritative
        projection of the current event stream (count, last sequence,
        has-terminal). It carries no grant, dispatch, or completion power.
        """
        ...

    @abstractmethod
    def append_event(
        self, attempt_id: str, event: LedgerEvent
    ) -> AppendResult:
        """Append *event* to the durable event stream.

        Enforces, inside a single SQLite transaction:

        * ``event.identity.attempt_id == attempt_id`` (else ``ValueError``);
        * monotonic sequence — ``event.sequence`` must be strictly greater
          than the largest persisted sequence for *attempt_id*
          (else :class:`MonotonicSequenceError`);
        * exactly one terminal event — once a terminal event is persisted,
          any further append with a new idempotency key raises
          :class:`PostTerminalAppendError`;
        * idempotency-key dedup — if ``(attempt_id, idempotency_key)``
          already exists, returns the existing event with
          ``is_duplicate=True`` and does NOT raise, even when the attempt
          is already terminal (dedup wins over post-terminal rejection).

        Returns:
            AppendResult whose ``event`` is the persisted event (the
            existing one when ``is_duplicate`` is True).
        """
        ...

    @abstractmethod
    def append_started(
        self, attempt_id: str, event: LedgerEvent
    ) -> AppendResult:
        """Append a ``STARTED`` event via :meth:`append_event`.

        Validates ``event.event_type == AttemptEventType.STARTED`` before
        delegating, then enforces all Step 4 transactional invariants.
        """
        ...

    @abstractmethod
    def append_completed(
        self, attempt_id: str, event: LedgerEvent
    ) -> AppendResult:
        """Append a ``COMPLETED`` event via :meth:`append_event`.

        Validates ``event.event_type == AttemptEventType.COMPLETED`` before
        delegating. Post-terminal rejection applies — a second terminal
        raises :class:`PostTerminalAppendError`.
        """
        ...

    @abstractmethod
    def append_failed(
        self, attempt_id: str, event: LedgerEvent
    ) -> AppendResult:
        """Append a ``FAILED`` event via :meth:`append_event`.

        Validates ``event.event_type == AttemptEventType.FAILED`` before
        delegating. Post-terminal rejection applies.
        """
        ...

    @abstractmethod
    def append_cancelled(
        self, attempt_id: str, event: LedgerEvent
    ) -> AppendResult:
        """Append a ``CANCELLED`` event via :meth:`append_event`.

        Validates ``event.event_type == AttemptEventType.CANCELLED`` before
        delegating. Post-terminal rejection applies.
        """
        ...

    @abstractmethod
    def read_events(
        self, attempt_id: str
    ) -> list[LedgerEvent]:
        """Return all events for *attempt_id* in append order (`sequence`)."""
        ...

    @abstractmethod
    def read_ledger(
        self, attempt_id: str
    ) -> ExecutionAttemptLedger:
        """Return a fully reconstructed ``ExecutionAttemptLedger``.

        The returned ledger carries the pinned ``ledger_schema_version``.
        """
        ...

    @abstractmethod
    def event_count(self, attempt_id: str) -> int:
        """Return the number of persisted events for *attempt_id*."""
        ...

    @abstractmethod
    def has_terminal_event(self, attempt_id: str) -> bool:
        """Return ``True`` when a terminal event exists for *attempt_id*."""
        ...

    @abstractmethod
    def last_sequence(self, attempt_id: str) -> int:
        """Return the highest persisted sequence number (0 if empty)."""
        ...

    @abstractmethod
    def get_reservation(
        self, attempt_id: str
    ) -> Optional[AttemptReservation]:
        """Return the current :class:`AttemptReservation` or ``None``.

        Does not reserve. Returns the persisted reservation projection
        without bumping ``reservation_count``.
        """
        ...

    # ── Step 8B1: global effect identity ───────────────────────────────

    @abstractmethod
    def reserve_global_effect(
        self, attempt_id: str, effect_identity: GlobalEffectIdentity
    ) -> GlobalEffectReservation:
        """Atomically reserve an attempt and persist a GLEK snapshot.

        The GLEK snapshot and the attempt reservation MUST be written in
        the same SQLite transaction, so a crash between writes cannot
        produce a torn snapshot.

        Idempotent for the same ``(attempt_id, global_logical_effect_key)``:
        re-calls return the persisted snapshot with an incremented
        ``reservation_count`` and never re-derive from the current schema.

        A different ``effect_identity`` for the same ``(attempt_id,
        global_logical_effect_key)`` raises ``ValueError`` (divergent
        snapshot).
        """
        ...

    @abstractmethod
    def get_global_effect_reservation(
        self, attempt_id: str, global_logical_effect_key: str
    ) -> Optional[GlobalEffectReservation]:
        """Return the persisted GLEK snapshot for a single effect.

        Returns ``None`` if no reservation exists for the given
        ``(attempt_id, global_logical_effect_key)``.
        """
        ...

    @abstractmethod
    def get_global_effect_reservations_for_attempt(
        self, attempt_id: str
    ) -> tuple[GlobalEffectReservation, ...]:
        """Return all GLEK snapshots persisted for *attempt_id*.

        Returns an empty tuple if none exist.  Used by the index joining
        attempts to their global-effect identities.
        """
        ...

    # ── Step 8B2: terminal outcome CAS ──────────────────────────────────

    @abstractmethod
    def accept_terminal_outcome(
        self,
        attempt_id: str,
        global_logical_effect_key: str,
        outcome_kind: str,
        outcome_payload: dict[str, Any] | None = None,
    ) -> GlobalEffectOutcome:
        """Atomically accept one terminal outcome per ``(attempt_id, GLEK)``.

        Enforces, inside a single ``BEGIN IMMEDIATE`` transaction:

        * **Reservation gate** — ``(attempt_id, GLEK)`` must have a
          persisted reservation (Step 8B1).  An unreserved outcome raises
          ``ValueError``.
        * **Same-attempt CAS** — if a terminal outcome already exists for
          ``(attempt_id, GLEK)``, an exact duplicate (same ``outcome_kind``
          and canonical payload) is returned idempotently with
          ``is_duplicate=True``.  A divergent outcome is quarantined and
          raises :class:`GlobalEffectConflictError`.
        * **Cross-attempt exclusivity** — if any *other* attempt has
          already accepted a terminal outcome for the same GLEK, this
          outcome is quarantined and raises
          :class:`GlobalEffectConflictError`.  Only one attempt may reach
          terminal per global effect.

        The accepted outcome is evidence/projection only.  Resolution of
        indeterminate outcomes or cross-attempt conflicts requires the
        reconciliation policy in Step 10B; a new Run Authority grant or
        Custody epoch alone cannot clear an indeterminate effect.
        """
        ...

    @abstractmethod
    def get_global_effect_outcome(
        self, attempt_id: str, global_logical_effect_key: str
    ) -> Optional[GlobalEffectOutcome]:
        """Return the accepted terminal outcome for ``(attempt_id, GLEK)``.

        Returns ``None`` if no outcome has been accepted.
        """
        ...

    @abstractmethod
    def get_global_effect_outcome_by_glek(
        self, global_logical_effect_key: str
    ) -> Optional[GlobalEffectOutcome]:
        """Return the accepted terminal outcome for *GLEK* across all attempts.

        Cross-attempt query — returns the single accepted outcome
        regardless of which attempt accepted it, or ``None`` if no outcome
        exists.
        """
        ...

    @abstractmethod
    def is_dispatch_eligible(
        self, attempt_id: str, global_logical_effect_key: str
    ) -> bool:
        """Return whether *attempt_id* may still dispatch for *GLEK*.

        ``False`` when:

        * no reservation exists for ``(attempt_id, GLEK)``, or
        * a terminal outcome has been accepted for *GLEK* (by this or any
          other attempt).

        Evidence/projection only — does not grant dispatch authority.
        """
        ...

    @abstractmethod
    def list_global_effect_conflicts(
        self, attempt_id: str
    ) -> tuple[GlobalEffectConflict, ...]:
        """Return all quarantined global-effect conflicts for *attempt_id*.

        Returns an empty tuple if none exist.
        """
        ...

    @abstractmethod
    def get_terminal_event(
        self, attempt_id: str
    ) -> Optional[LedgerEvent]:
        """Return the single terminal event for *attempt_id*, if any.

        Returns ``None`` if no terminal event has been persisted.
        """
        ...

    # ── Step 12b: cutover quiesce ──────────────────────────────────────

    @abstractmethod
    def list_in_flight_attempts(self) -> list[str]:
        """Return the attempt_ids that have NOT reached a terminal event.

        An attempt is in-flight when it has at least one persisted event but
        no terminal event (``COMPLETED``/``FAILED``/``CANCELLED``). Attempts
        that have drained to a terminal event are excluded. The list is
        ordered for stable, deterministic enumeration during quiesce.

        This is evidence only — it does not grant authority.
        """
        ...

    @abstractmethod
    def set_cutover_in_progress(self) -> bool:
        """Atomically engage the durable ``cutover_in_progress`` admission fence.

        The fence is persisted in ``_store_metadata`` (not in-memory) so a
        crash during cutover preserves the admission-closed state: reopening
        the database continues to reject new admissions.

        Returns ``True`` when the fence was already engaged before this call
        (so callers can detect a resumption after a crash) and ``False`` when
        the fence was newly engaged.
        """
        ...

    @abstractmethod
    def is_cutover_in_progress(self) -> bool:
        """Return whether the durable ``cutover_in_progress`` fence is engaged.

        Reads the persisted metadata value, so the result reflects a freshly
        reopened store (e.g. after a crash) and not just in-process state.
        """
        ...

    @abstractmethod
    def clear_cutover_in_progress(self) -> bool:
        """Disengage the durable ``cutover_in_progress`` admission fence.

        Called once the cutover has completed. Returns ``True`` when the fence
        was engaged before this call (so callers can detect a spurious double
        completion) and ``False`` when it was already clear.
        """
        ...

    @abstractmethod
    def mark_attempt_indeterminate(
        self,
        attempt_id: str,
        last_event_type: str,
        last_event_sequence: int,
        drain_category: str,
        resolved_outcome: str,
        mark_reason: str,
    ) -> CutoverIndeterminateMark:
        """Durablely mark an in-flight attempt resolved to ``INDETERMINATE``.

        Idempotent per ``attempt_id`` (UPSERT on the primary key). The mark is
        evidence only — it never grants dispatch or completion. An attempt that
        has since drained to a terminal event is not marked (the call is a
        no-op that returns the existing terminal-coherent state).

        Raises:
            ValueError: if *attempt_id* is empty.
        """
        ...

    @abstractmethod
    def get_cutover_indeterminate_marks(self) -> list[CutoverIndeterminateMark]:
        """Return all durable cutover-indeterminate resolution marks.

        Ordered by ``marked_at_ns``. Evidence only.
        """
        ...

    # ── Step 8: diagnostic persistence and queries ──────────────────────

    @abstractmethod
    def record_persistence_failure_diagnostic(
        self, attempt_id: str, diagnostic: Any
    ) -> None:
        """Persist a :class:`PersistenceFailureDiagnostic` as evidence.

        The diagnostic is stored alongside the event stream and is
        joinable via ``attempt_id``.  It does NOT grant append or
        completion authority — it is observable evidence only.

        Raises:
            ValueError: if *diagnostic* is not a
                ``PersistenceFailureDiagnostic``.

        """
        ...

    @abstractmethod
    def record_reconciliation_diagnostic(
        self, attempt_id: str, diagnostic: Any
    ) -> None:
        """Persist a :class:`ReconciliationDiagnostic` as evidence.

        The diagnostic is stored alongside the event stream and is
        joinable via ``attempt_id``.  It does NOT grant append or
        completion authority.

        Raises:
            ValueError: if *diagnostic* is not a
                ``ReconciliationDiagnostic``.

        """
        ...

    @abstractmethod
    def query_gaps(self, attempt_id: str) -> list[GapEntry]:
        """Return sequence gaps in the persisted event stream.

        Gaps are detected by comparing persisted ``sequence`` values
        against the expected monotonic range [1, max_sequence].  Each
        :class:`GapEntry` describes one contiguous range of missing
        sequences.  An empty list means no gaps exist.

        This is evidence only — it does not grant authority.
        """
        ...

    @abstractmethod
    def query_persistence_diagnostics(
        self, attempt_id: str
    ) -> list[Any]:
        """Return all :class:`PersistenceFailureDiagnostic` records for
        *attempt_id*, ordered by ``recorded_at_ns``.

        Returns an empty list when no diagnostics have been recorded.
        """
        ...

    @abstractmethod
    def query_reconciliation_state(
        self, attempt_id: str
    ) -> list[Any]:
        """Return all :class:`ReconciliationDiagnostic` records for
        *attempt_id*, ordered by ``recorded_at_ns``.

        Returns an empty list when no reconciliation has been recorded.
        """
        ...

    @abstractmethod
    def query_source_cursor(
        self, attempt_id: str, cursor_key: str = "default"
    ) -> Optional[SourceCursor]:
        """Return the source cursor position for *attempt_id*.

        Returns ``None`` when no cursor has been recorded for the
        given ``cursor_key``.  The cursor is evidence only — it does
        not grant append or completion authority.
        """
        ...

    @abstractmethod
    def update_source_cursor(
        self,
        attempt_id: str,
        last_sequence: int,
        cursor_key: str = "default",
        last_position: str | None = None,
    ) -> SourceCursor:
        """Record (or update) the source cursor position for *attempt_id*.

        Returns the :class:`SourceCursor` as persisted.  The cursor is
        evidence only.
        """
        ...

    # ── Step 5: durable gates ──────────────────────────────────────────

    def start_verified(self, attempt_id: str) -> StartGateResult:
        """Verify that a STARTED event is durably persisted for *attempt_id*.

        This is a **durable gate** — it reads the persisted event stream and
        returns a typed :class:`StartGateResult`. It never returns an
        optimistic default:

        * ``VERIFIED`` — exactly one STARTED event exists and its deserialized
          ``event_type`` matches ``AttemptEventType.STARTED``.
        * ``INCOMPLETE`` — no STARTED event has been persisted yet. The attempt
          may still be in-flight (or may never have been started).
        * ``INDETERMINATE`` — the store has rows that *might* be a STARTED
          event but the evidence is ambiguous (corrupt JSON, unexpected
          event type after deserialization, or a query error).
        * ``INCOHERENT`` — multiple STARTED events exist for the same
          attempt, violating the ledger contract.

        The default implementation delegates to :meth:`read_events`.
        Subclasses may override for efficiency (e.g. a targeted SQL query).
        """
        try:
            events = self.read_events(attempt_id)
        except Exception as exc:
            return StartGateResult(
                attempt_id=attempt_id,
                status=GateStatus.INDETERMINATE,
                started_event=None,
                evidence=f"Failed to read events: {exc}",
            )

        started_events = [
            e for e in events if e.event_type == AttemptEventType.STARTED
        ]

        if len(started_events) == 0:
            return StartGateResult(
                attempt_id=attempt_id,
                status=GateStatus.INCOMPLETE,
                started_event=None,
                evidence="No STARTED event found in durable store.",
            )
        elif len(started_events) == 1:
            return StartGateResult(
                attempt_id=attempt_id,
                status=GateStatus.VERIFIED,
                started_event=started_events[0],
                evidence="Exactly one STARTED event verified in durable store.",
            )
        else:
            return StartGateResult(
                attempt_id=attempt_id,
                status=GateStatus.INCOHERENT,
                started_event=None,
                evidence=(
                    f"Found {len(started_events)} STARTED events; "
                    f"expected at most one."
                ),
            )

    def terminal_or_indeterminate_verified(
        self, attempt_id: str
    ) -> TerminalGateResult:
        """Verify whether a terminal event is durably persisted for *attempt_id*.

        This is a **durable gate** that reads the persisted event stream and
        returns a typed :class:`TerminalGateResult`. It never returns an
        optimistic default:

        * ``VERIFIED`` — exactly one terminal event (COMPLETED, FAILED, or
          CANCELLED) exists and its deserialized ``event_type`` is confirmed
          as terminal.
        * ``INCOMPLETE`` — no terminal event has been persisted yet. The
          attempt is still in-flight.
        * ``INDETERMINATE`` — the store has rows that *might* be terminal but
          the evidence is ambiguous (corrupt JSON, unexpected event type, or
          a query error).
        * ``INCOHERENT`` — multiple terminal events exist for the same
          attempt, violating the single-terminal invariant.

        The default implementation delegates to :meth:`read_events`.
        Subclasses may override for efficiency.
        """
        _TERMINAL = frozenset({
            AttemptEventType.COMPLETED,
            AttemptEventType.FAILED,
            AttemptEventType.CANCELLED,
        })

        try:
            events = self.read_events(attempt_id)
        except Exception as exc:
            return TerminalGateResult(
                attempt_id=attempt_id,
                status=GateStatus.INDETERMINATE,
                terminal_event=None,
                evidence=f"Failed to read events: {exc}",
            )

        terminal_events = [e for e in events if e.event_type in _TERMINAL]

        if len(terminal_events) == 0:
            return TerminalGateResult(
                attempt_id=attempt_id,
                status=GateStatus.INCOMPLETE,
                terminal_event=None,
                evidence="No terminal event found in durable store.",
            )
        elif len(terminal_events) == 1:
            return TerminalGateResult(
                attempt_id=attempt_id,
                status=GateStatus.VERIFIED,
                terminal_event=terminal_events[0],
                evidence="Exactly one terminal event verified in durable store.",
            )
        else:
            return TerminalGateResult(
                attempt_id=attempt_id,
                status=GateStatus.INCOHERENT,
                terminal_event=None,
                evidence=(
                    f"Found {len(terminal_events)} terminal events; "
                    f"expected at most one."
                ),
            )


# ── SQLite implementation ──────────────────────────────────────────────────


class SqliteAttemptLedgerStore(AttemptLedgerStore):
    """Durable ``AttemptLedgerStore`` backed by a local SQLite database.

    * WAL mode is enabled on open for concurrent readers + single writer.
    * Each ``LedgerEvent`` is serialized via ``event.to_dict()``, stored as
      JSON text, and deserialized back into frozen dataclass instances.
    * The store metadata table captures the pinned contract version
      (``LEDGER_SCHEMA_VERSION``) so readers can detect drift.
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> None:
        db_path = Path(db_path) if isinstance(db_path, str) else db_path
        if connection is None:
            db_path.parent.mkdir(parents=True, exist_ok=True)

        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = connection
        self._contract_version: str = LEDGER_SCHEMA_VERSION
        if connection is not None:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA foreign_keys=OFF")
            self._init_schema()

    # ── connection management ──────────────────────────────────────────

    @property
    def conn(self) -> sqlite3.Connection:
        """Lazily open + initialize the database connection.

        The connection uses ``isolation_level=None`` (autocommit) so that
        Step 4 transactional appends can issue an explicit ``BEGIN
        IMMEDIATE`` and guarantee atomic all-or-nothing enforcement of
        monotonic-sequence, idempotency-dedup, single-terminal, and
        post-terminal-rejection invariants within ONE transaction.
        """
        if self._conn is None:
            self._conn = sqlite3.connect(
                str(self._db_path),
                check_same_thread=False,
                timeout=10.0,
                isolation_level=None,  # explicit BEGIN IMMEDIATE control
            )
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=OFF")
            self._init_schema()
        return self._conn

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ── schema initialization ──────────────────────────────────────────

    def _init_schema(self) -> None:
        """Create tables and write metadata if first open.

        All schema statements are issued inside one ``BEGIN IMMEDIATE``
        transaction so the store's tables either all exist or none do.
        We use individual ``execute()`` calls (not ``executescript``)
        because ``executescript`` issues an implicit ``COMMIT`` before
        executing, which would defeat the surrounding transaction.

        Retry-on-busy: when multiple processes race to open the database
        for the first time, ``BEGIN IMMEDIATE`` may encounter
        ``SQLITE_BUSY``.  We retry with exponential backoff (capped at
        the connection's busy timeout) so the store is safe to open
        concurrently from independent processes.
        """
        max_attempts = 20
        base_delay = 0.05  # 50 ms
        conn = self._conn  # type: ignore[union-attr]

        for attempt in range(max_attempts):
            try:
                conn.execute("BEGIN IMMEDIATE")
                break
            except sqlite3.OperationalError as exc:
                if "locked" in str(exc).lower() and attempt < max_attempts - 1:
                    delay = min(base_delay * (2 ** attempt), 2.0)
                    time.sleep(delay)
                    continue
                raise

        try:
            cur = conn.cursor()
            # Individual execute() calls (NOT executescript, which COMMITs
            # first and would escape our BEGIN IMMEDIATE).
            for ddl in (
                _METADATA_TABLE_DDL,
                _EVENTS_TABLE_DDL,
                _EVENTS_IDEMPOTENCY_INDEX_DDL,
                _RESERVATIONS_TABLE_DDL,
                _PERSISTENCE_FAILURE_DIAGNOSTICS_TABLE_DDL,
                _RECONCILIATION_DIAGNOSTICS_TABLE_DDL,
                _SOURCE_CURSORS_TABLE_DDL,
                _GLOBAL_EFFECT_RESERVATIONS_TABLE_DDL,
                _GLOBAL_EFFECT_ATTEMPT_INDEX_DDL,
                _GLOBAL_EFFECT_OUTCOMES_TABLE_DDL,
                _GLOBAL_EFFECT_OUTCOME_GLEK_UNIQUE_INDEX_DDL,
                _GLOBAL_EFFECT_CONFLICT_QUARANTINE_TABLE_DDL,
                _GLOBAL_EFFECT_CONFLICT_ATTEMPT_INDEX_DDL,
                _CUTOVER_INDETERMINATE_MARKS_TABLE_DDL,
                _OCCURRENCE_CLAIM_ADMISSIONS_TABLE_DDL,
            ):
                for stmt in ddl.split(";"):
                    s = stmt.strip()
                    if s:
                        cur.execute(s)

            # Ensure metadata is populated.
            cur.execute("SELECT value FROM _store_metadata WHERE key = 'store_version'")
            row = cur.fetchone()
            if row is None:
                cur.execute(
                    "INSERT INTO _store_metadata (key, value) VALUES (?, ?)",
                    ("store_version", _STORE_VERSION),
                )
            cur.execute(
                "SELECT value FROM _store_metadata WHERE key = 'contract_version'"
            )
            row = cur.fetchone()
            if row is None:
                cur.execute(
                    "INSERT INTO _store_metadata (key, value) VALUES (?, ?)",
                    ("contract_version", self._contract_version),
                )
            cur.execute(
                "SELECT value FROM _store_metadata WHERE key = 'created_at_ns'"
            )
            row = cur.fetchone()
            if row is None:
                cur.execute(
                    "INSERT INTO _store_metadata (key, value) VALUES (?, ?)",
                    ("created_at_ns", str(time.time_ns())),
                )
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise

    # ── public interface ───────────────────────────────────────────────

    def initialize_attempt(self, attempt_id: str) -> None:
        """Idempotent no-op — table creation happens at DB open time.

        The attempt_id is validated on first append, not here.
        """
        # Touch connection to ensure schema exists.
        _ = self.conn

    # ── reservation ────────────────────────────────────────────────────

    def reserve_attempt(self, attempt_id: str) -> AttemptReservation:
        """Reserve *attempt_id* and return its current observable state.

        Atomicity: the reservation INSERT (or UPDATE on re-reservation)
        and the snapshot read of current event state happen inside one
        ``BEGIN IMMEDIATE`` transaction, so the returned projection is
        consistent with the reservation write.
        """
        conn = self.conn
        self._begin_immediate_retry(conn)
        try:
            now_ns = time.time_ns()
            cur = conn.cursor()

            # Try insert; if it exists, update.
            cur.execute(
                "SELECT first_reserved_ns, reservation_count FROM attempt_reservations WHERE attempt_id = ?",
                (attempt_id,),
            )
            existing = cur.fetchone()
            if existing is None:
                # Cutover admission fence (Step 12b): once the durable
                # ``cutover_in_progress`` fence is engaged, no NEW attempt may
                # be reserved. An attempt that already exists in the store —
                # either via a prior reservation or via persisted events (an
                # in-flight stream that was appended without reserving) — is a
                # CONTINUATION, not a new admission, and may still be
                # re-reserved so the cutover can drain it.
                cur.execute(
                    "SELECT 1 FROM attempt_events WHERE attempt_id = ? LIMIT 1",
                    (attempt_id,),
                )
                already_has_events = cur.fetchone() is not None
                if not already_has_events:
                    cur.execute(
                        "SELECT value FROM _store_metadata WHERE key = ?",
                        (_CUTOVER_IN_PROGRESS_KEY,),
                    )
                    fence_row = cur.fetchone()
                    if (
                        fence_row is not None
                        and fence_row[0] == _CUTOVER_IN_PROGRESS_SET
                    ):
                        conn.execute("ROLLBACK")
                        raise CutoverInProgressError(
                            f"Cannot reserve new attempt {attempt_id!r}: the "
                            f"cutover_in_progress admission fence is engaged. "
                            f"New admissions are rejected until the cutover "
                            f"completes."
                        )
                is_new = True
                cur.execute(
                    "INSERT INTO attempt_reservations (attempt_id, first_reserved_ns, last_reserved_ns, reservation_count) VALUES (?, ?, ?, 1)",
                    (attempt_id, now_ns, now_ns),
                )
                first_reserved_ns = now_ns
                reservation_count = 1
            else:
                is_new = False
                first_reserved_ns = existing[0]
                reservation_count = existing[1] + 1
                cur.execute(
                    "UPDATE attempt_reservations SET last_reserved_ns = ?, reservation_count = ? WHERE attempt_id = ?",
                    (now_ns, reservation_count, attempt_id),
                )

            # Snapshot current event state inside the same transaction.
            cur.execute(
                "SELECT COALESCE(MAX(sequence), 0), COUNT(1) FROM attempt_events WHERE attempt_id = ?",
                (attempt_id,),
            )
            seq_row = cur.fetchone()
            last_sequence = int(seq_row[0]) if seq_row is not None else 0
            event_count = int(seq_row[1]) if seq_row is not None else 0

            cur.execute(
                f"SELECT 1 FROM attempt_events WHERE attempt_id = ? AND event_type IN ({','.join('?' * len(_TERMINAL_EVENT_TYPE_VALUES))}) LIMIT 1",
                (attempt_id, *_TERMINAL_EVENT_TYPE_VALUES),
            )
            has_terminal = cur.fetchone() is not None

            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise

        return AttemptReservation(
            attempt_id=attempt_id,
            is_new=is_new,
            event_count=event_count,
            last_sequence=last_sequence,
            has_terminal=has_terminal,
            first_reserved_ns=first_reserved_ns,
            last_reserved_ns=now_ns,
            reservation_count=reservation_count,
        )

    def admit_occurrence_claim(
        self,
        *,
        attempt_id: str,
        occurrence_id: str,
        claim_id: str,
    ) -> None:
        """Read-only pre-flight probe: refuse when the occurrence is admitted.

        T-0101h round-4 blocker 3: the durable admission row is NO LONGER
        committed here.  The occurrence admission, the attempt reservation
        and the STARTED event are all written inside the SINGLE
        ``_append_tx`` transaction of :meth:`append_started`, so a crash
        between admission and STARTED is impossible and a second contender's
        STARTED append rolls back as a whole — zero mutation.  This method
        only mirrors that CAS as a zero-mutation early-exit probe for callers
        that want to fail before any other work: it raises
        :class:`OccurrenceClaimAdmissionConflict` when a DIFFERENT attempt
        already holds the occurrence and never writes or commits anything.
        """
        cur = self.conn.cursor()
        cur.execute(
            "SELECT attempt_id FROM occurrence_claim_admissions"
            " WHERE occurrence_id = ?",
            (occurrence_id,),
        )
        holder = cur.fetchone()
        if holder is not None and holder[0] != attempt_id:
            raise OccurrenceClaimAdmissionConflict(
                f"occurrence {occurrence_id[:16]}… is already admitted by "
                f"claim attempt {holder[0]!r}; this claim attempt "
                f"{attempt_id!r} is denied"
            )

    def get_reservation(
        self, attempt_id: str
    ) -> Optional[AttemptReservation]:
        """Return the persisted reservation projection without reserving.

        Read-only. Returns ``None`` if no reservation exists.
        """
        conn = self.conn
        cur = conn.cursor()
        cur.execute(
            "SELECT first_reserved_ns, last_reserved_ns, reservation_count FROM attempt_reservations WHERE attempt_id = ?",
            (attempt_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        first_reserved_ns = int(row[0])
        last_reserved_ns = int(row[1])
        reservation_count = int(row[2])

        # Snapshot current event state (read-only).
        cur.execute(
            "SELECT COALESCE(MAX(sequence), 0), COUNT(1) FROM attempt_events WHERE attempt_id = ?",
            (attempt_id,),
        )
        seq_row = cur.fetchone()
        last_sequence = int(seq_row[0]) if seq_row is not None else 0
        event_count = int(seq_row[1]) if seq_row is not None else 0

        cur.execute(
            f"SELECT 1 FROM attempt_events WHERE attempt_id = ? AND event_type IN ({','.join('?' * len(_TERMINAL_EVENT_TYPE_VALUES))}) LIMIT 1",
            (attempt_id, *_TERMINAL_EVENT_TYPE_VALUES),
        )
        has_terminal = cur.fetchone() is not None

        return AttemptReservation(
            attempt_id=attempt_id,
            is_new=False,
            event_count=event_count,
            last_sequence=last_sequence,
            has_terminal=has_terminal,
            first_reserved_ns=first_reserved_ns,
            last_reserved_ns=last_reserved_ns,
            reservation_count=reservation_count,
        )

    # ── Step 8B1: global effect reservation ────────────────────────────

    def reserve_global_effect(
        self, attempt_id: str, effect_identity: GlobalEffectIdentity
    ) -> GlobalEffectReservation:
        """Atomically reserve the attempt and persist the GLEK snapshot.

        The GLEK snapshot INSERT (or UPDATE on re-reservation) and the
        attempt reservation upsert happen inside one ``BEGIN IMMEDIATE``
        transaction, satisfying the Step 8B1 atomic co-persistence
        requirement: a crash between writes cannot produce a torn snapshot.

        On re-reservation with the same ``global_logical_effect_key`` the
        original snapshot is preserved (never re-derived from the current
        schema). A divergent ``effect_identity`` raises ``ValueError``.
        """
        if not attempt_id.strip():
            raise ValueError("attempt_id must be non-empty")
        glek = effect_identity.global_logical_effect_key
        snapshot_json = json.dumps(effect_identity.to_dict(), sort_keys=True)

        conn = self.conn
        self._begin_immediate_retry(conn)
        try:
            now_ns = time.time_ns()
            cur = conn.cursor()

            # Ensure attempt reservation exists (upsert).
            cur.execute(
                "SELECT first_reserved_ns, reservation_count"
                "  FROM attempt_reservations WHERE attempt_id = ?",
                (attempt_id,),
            )
            attemp_row = cur.fetchone()
            if attemp_row is None:
                cur.execute(
                    "INSERT INTO attempt_reservations"
                    "  (attempt_id, first_reserved_ns, last_reserved_ns,"
                    "   reservation_count) VALUES (?, ?, ?, 1)",
                    (attempt_id, now_ns, now_ns),
                )
            else:
                cur.execute(
                    "UPDATE attempt_reservations"
                    "  SET last_reserved_ns = ?,"
                    "      reservation_count = ?"
                    "  WHERE attempt_id = ?",
                    (now_ns, attemp_row[1] + 1, attempt_id),
                )

            # Upsert GLEK snapshot.
            cur.execute(
                "SELECT environment_id, action_target, action_version,"
                "       effect_family, provider_target,"
                "       canonical_request_identity, boundary_schema_hash,"
                "       first_reserved_ns, reservation_count"
                "  FROM global_effect_reservations"
                " WHERE attempt_id = ? AND global_logical_effect_key = ?",
                (attempt_id, glek),
            )
            existing = cur.fetchone()
            if existing is None:
                is_new = True
                cur.execute(
                    "INSERT INTO global_effect_reservations"
                    "  (attempt_id, global_logical_effect_key,"
                    "   environment_id, action_target, action_version,"
                    "   effect_family, provider_target,"
                    "   canonical_request_identity, boundary_schema_hash,"
                    "   first_reserved_ns, reservation_count,"
                    "   snapshot_json)"
                    "  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)",
                    (
                        attempt_id,
                        glek,
                        effect_identity.environment_id,
                        effect_identity.action_target,
                        effect_identity.action_version,
                        effect_identity.effect_family,
                        effect_identity.provider_target,
                        effect_identity.canonical_request_identity,
                        effect_identity.boundary_schema_hash,
                        now_ns,
                        snapshot_json,
                    ),
                )
                first_reserved_ns = now_ns
                reservation_count = 1
            else:
                # Verify the persisted snapshot matches — divergent
                # snapshots are rejected fail-closed.
                persisted = GlobalEffectIdentity(
                    environment_id=existing[0],
                    action_target=existing[1],
                    action_version=existing[2],
                    effect_family=existing[3],
                    provider_target=existing[4],
                    canonical_request_identity=existing[5],
                    boundary_schema_hash=existing[6],
                )
                if persisted.global_logical_effect_key != glek:
                    raise ValueError(
                        f"Divergent GLEK snapshot for attempt_id={attempt_id!r}, "
                        f"glek={glek!r}: persisted inputs do not match"
                    )
                is_new = False
                first_reserved_ns = existing[7]
                reservation_count = existing[8] + 1
                cur.execute(
                    "UPDATE global_effect_reservations"
                    "  SET reservation_count = ?"
                    "  WHERE attempt_id = ? AND global_logical_effect_key = ?",
                    (reservation_count, attempt_id, glek),
                )

            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise

        return GlobalEffectReservation(
            attempt_id=attempt_id,
            effect_identity=effect_identity,
            global_logical_effect_key=glek,
            first_reserved_ns=first_reserved_ns,
            reservation_count=reservation_count,
            is_new=is_new,
        )

    def get_global_effect_reservation(
        self, attempt_id: str, global_logical_effect_key: str
    ) -> Optional[GlobalEffectReservation]:
        """Return the persisted GLEK snapshot for a single effect."""
        conn = self.conn
        cur = conn.cursor()
        cur.execute(
            "SELECT environment_id, action_target, action_version,"
            "       effect_family, provider_target,"
            "       canonical_request_identity, boundary_schema_hash,"
            "       first_reserved_ns, reservation_count"
            "  FROM global_effect_reservations"
            " WHERE attempt_id = ? AND global_logical_effect_key = ?",
            (attempt_id, global_logical_effect_key),
        )
        row = cur.fetchone()
        if row is None:
            return None
        identity = GlobalEffectIdentity(
            environment_id=row[0],
            action_target=row[1],
            action_version=row[2],
            effect_family=row[3],
            provider_target=row[4],
            canonical_request_identity=row[5],
            boundary_schema_hash=row[6],
        )
        return GlobalEffectReservation(
            attempt_id=attempt_id,
            effect_identity=identity,
            global_logical_effect_key=identity.global_logical_effect_key,
            first_reserved_ns=int(row[7]),
            reservation_count=int(row[8]),
            is_new=False,
        )

    def get_global_effect_reservations_for_attempt(
        self, attempt_id: str
    ) -> tuple[GlobalEffectReservation, ...]:
        """Return all GLEK snapshots persisted for *attempt_id*."""
        conn = self.conn
        cur = conn.cursor()
        cur.execute(
            "SELECT environment_id, action_target, action_version,"
            "       effect_family, provider_target,"
            "       canonical_request_identity, boundary_schema_hash,"
            "       first_reserved_ns, reservation_count"
            "  FROM global_effect_reservations"
            " WHERE attempt_id = ?",
            (attempt_id,),
        )
        results: list[GlobalEffectReservation] = []
        for row in cur.fetchall():
            identity = GlobalEffectIdentity(
                environment_id=row[0],
                action_target=row[1],
                action_version=row[2],
                effect_family=row[3],
                provider_target=row[4],
                canonical_request_identity=row[5],
                boundary_schema_hash=row[6],
            )
            results.append(
                GlobalEffectReservation(
                    attempt_id=attempt_id,
                    effect_identity=identity,
                    global_logical_effect_key=identity.global_logical_effect_key,
                    first_reserved_ns=int(row[7]),
                    reservation_count=int(row[8]),
                    is_new=False,
                )
            )
        return tuple(results)

    # ── Step 8B2: terminal outcome CAS ─────────────────────────────────

    def accept_terminal_outcome(
        self,
        attempt_id: str,
        global_logical_effect_key: str,
        outcome_kind: str,
        outcome_payload: dict[str, Any] | None = None,
    ) -> GlobalEffectOutcome:
        """Atomically accept one terminal outcome per ``(attempt_id, GLEK)``.

        See :meth:`AttemptLedgerStore.accept_terminal_outcome` for the full
        contract. The CAS, cross-attempt exclusivity, and quarantine are all
        enforced inside a single ``BEGIN IMMEDIATE`` transaction so two
        concurrent writers cannot both accept a terminal outcome for the
        same GLEK.
        """
        if not attempt_id.strip():
            raise ValueError("attempt_id must be non-empty")
        if not global_logical_effect_key.strip():
            raise ValueError("global_logical_effect_key must be non-empty")

        payload = outcome_payload or {}
        payload_json = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        new_canonical = json.dumps(
            {"outcome_kind": outcome_kind, "outcome_payload": payload},
            sort_keys=True,
            ensure_ascii=False,
        )

        conn = self.conn
        self._begin_immediate_retry(conn)
        try:
            now_ns = time.time_ns()
            cur = conn.cursor()

            # (1) Reservation gate — must have a persisted reservation.
            cur.execute(
                "SELECT 1 FROM global_effect_reservations"
                " WHERE attempt_id = ? AND global_logical_effect_key = ?",
                (attempt_id, global_logical_effect_key),
            )
            if cur.fetchone() is None:
                conn.execute("ROLLBACK")
                raise ValueError(
                    f"Cannot accept terminal outcome for unreserved "
                    f"(attempt_id={attempt_id!r}, "
                    f"glek={global_logical_effect_key!r})"
                )

            # (2) Same-attempt CAS — check if outcome already exists.
            cur.execute(
                "SELECT outcome_kind, outcome_payload_json, accepted_at_ns"
                "  FROM global_effect_outcomes"
                " WHERE attempt_id = ? AND global_logical_effect_key = ?",
                (attempt_id, global_logical_effect_key),
            )
            existing = cur.fetchone()
            if existing is not None:
                stored_canonical = json.dumps(
                    {
                        "outcome_kind": existing[0],
                        "outcome_payload": json.loads(existing[1]),
                    },
                    sort_keys=True,
                    ensure_ascii=False,
                )
                if stored_canonical == new_canonical:
                    # Exact duplicate — idempotent return.
                    conn.execute("ROLLBACK")
                    return GlobalEffectOutcome(
                        attempt_id=attempt_id,
                        global_logical_effect_key=global_logical_effect_key,
                        outcome_kind=existing[0],
                        outcome_payload=json.loads(existing[1]),
                        accepted_at_ns=int(existing[2]),
                        is_duplicate=True,
                    )
                # Divergent outcome — quarantine and raise.
                detail = {
                    "stored_outcome_kind": existing[0],
                    "new_outcome_kind": outcome_kind,
                    "stored_payload_json": existing[1],
                    "new_payload_json": payload_json,
                }
                self._quarantine_conflict(
                    cur, attempt_id, global_logical_effect_key,
                    "divergent_outcome", detail, now_ns,
                )
                conn.execute("COMMIT")
                raise GlobalEffectConflictError(
                    attempt_id=attempt_id,
                    global_logical_effect_key=global_logical_effect_key,
                    conflict_kind="divergent_outcome",
                    detail=detail,
                )

            # (3) Cross-attempt exclusivity — no other attempt may have an
            #     accepted terminal outcome for the same GLEK.
            cur.execute(
                "SELECT attempt_id, outcome_kind, outcome_payload_json,"
                "       accepted_at_ns"
                "  FROM global_effect_outcomes"
                " WHERE global_logical_effect_key = ?",
                (global_logical_effect_key,),
            )
            cross_row = cur.fetchone()
            if cross_row is not None and cross_row[0] != attempt_id:
                detail = {
                    "conflicting_attempt_id": cross_row[0],
                    "conflicting_outcome_kind": cross_row[1],
                    "new_outcome_kind": outcome_kind,
                }
                self._quarantine_conflict(
                    cur, attempt_id, global_logical_effect_key,
                    "cross_attempt_outcome", detail, now_ns,
                )
                conn.execute("COMMIT")
                raise GlobalEffectConflictError(
                    attempt_id=attempt_id,
                    global_logical_effect_key=global_logical_effect_key,
                    conflict_kind="cross_attempt_outcome",
                    detail=detail,
                )

            # (4) INSERT — the unique index on global_logical_effect_key
            #     is the final backstop for cross-attempt exclusivity.
            cur.execute(
                "INSERT INTO global_effect_outcomes"
                "  (attempt_id, global_logical_effect_key, outcome_kind,"
                "   outcome_payload_json, accepted_at_ns)"
                "  VALUES (?, ?, ?, ?, ?)",
                (
                    attempt_id,
                    global_logical_effect_key,
                    outcome_kind,
                    payload_json,
                    now_ns,
                ),
            )
            conn.execute("COMMIT")
        except (GlobalEffectConflictError, ValueError):
            raise
        except Exception as exc:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise

        return GlobalEffectOutcome(
            attempt_id=attempt_id,
            global_logical_effect_key=global_logical_effect_key,
            outcome_kind=outcome_kind,
            outcome_payload=payload,
            accepted_at_ns=now_ns,
            is_duplicate=False,
        )

    @staticmethod
    def _quarantine_conflict(
        cur: sqlite3.Cursor,
        attempt_id: str,
        global_logical_effect_key: str,
        conflict_kind: str,
        detail: dict[str, Any],
        now_ns: int,
    ) -> None:
        """Record a GLEK conflict in the quarantine table.

        This MUST be called inside the caller's ``BEGIN IMMEDIATE``
        transaction so the quarantine is atomic with the conflict
        detection. The quarantine is evidence-only.
        """
        cur.execute(
            "INSERT INTO global_effect_conflict_quarantine"
            "  (conflict_id, attempt_id, global_logical_effect_key,"
            "   conflict_kind, conflict_detail_json, quarantined_at_ns)"
            "  VALUES (?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                attempt_id,
                global_logical_effect_key,
                conflict_kind,
                json.dumps(detail, sort_keys=True, ensure_ascii=False),
                now_ns,
            ),
        )

    def get_global_effect_outcome(
        self, attempt_id: str, global_logical_effect_key: str
    ) -> Optional[GlobalEffectOutcome]:
        """Return the accepted terminal outcome for ``(attempt_id, GLEK)``."""
        conn = self.conn
        cur = conn.cursor()
        cur.execute(
            "SELECT outcome_kind, outcome_payload_json, accepted_at_ns"
            "  FROM global_effect_outcomes"
            " WHERE attempt_id = ? AND global_logical_effect_key = ?",
            (attempt_id, global_logical_effect_key),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return GlobalEffectOutcome(
            attempt_id=attempt_id,
            global_logical_effect_key=global_logical_effect_key,
            outcome_kind=row[0],
            outcome_payload=json.loads(row[1]),
            accepted_at_ns=int(row[2]),
            is_duplicate=False,
        )

    def get_global_effect_outcome_by_glek(
        self, global_logical_effect_key: str
    ) -> Optional[GlobalEffectOutcome]:
        """Return the accepted terminal outcome for *GLEK* across all attempts."""
        conn = self.conn
        cur = conn.cursor()
        cur.execute(
            "SELECT attempt_id, outcome_kind, outcome_payload_json,"
            "       accepted_at_ns"
            "  FROM global_effect_outcomes"
            " WHERE global_logical_effect_key = ?",
            (global_logical_effect_key,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return GlobalEffectOutcome(
            attempt_id=row[0],
            global_logical_effect_key=global_logical_effect_key,
            outcome_kind=row[1],
            outcome_payload=json.loads(row[2]),
            accepted_at_ns=int(row[3]),
            is_duplicate=False,
        )

    def is_dispatch_eligible(
        self, attempt_id: str, global_logical_effect_key: str
    ) -> bool:
        """Return whether *attempt_id* may still dispatch for *GLEK*."""
        conn = self.conn
        cur = conn.cursor()
        # Must have a reservation for (attempt_id, GLEK).
        cur.execute(
            "SELECT 1 FROM global_effect_reservations"
            " WHERE attempt_id = ? AND global_logical_effect_key = ?",
            (attempt_id, global_logical_effect_key),
        )
        if cur.fetchone() is None:
            return False
        # Must not have a terminal outcome for this GLEK in any attempt.
        cur.execute(
            "SELECT 1 FROM global_effect_outcomes"
            " WHERE global_logical_effect_key = ?",
            (global_logical_effect_key,),
        )
        if cur.fetchone() is not None:
            return False
        return True

    def list_global_effect_conflicts(
        self, attempt_id: str
    ) -> tuple[GlobalEffectConflict, ...]:
        """Return all quarantined global-effect conflicts for *attempt_id*."""
        conn = self.conn
        cur = conn.cursor()
        cur.execute(
            "SELECT conflict_id, global_logical_effect_key, conflict_kind,"
            "       conflict_detail_json, quarantined_at_ns"
            "  FROM global_effect_conflict_quarantine"
            " WHERE attempt_id = ?"
            " ORDER BY quarantined_at_ns",
            (attempt_id,),
        )
        results: list[GlobalEffectConflict] = []
        for row in cur.fetchall():
            results.append(
                GlobalEffectConflict(
                    conflict_id=row[0],
                    attempt_id=attempt_id,
                    global_logical_effect_key=row[1],
                    conflict_kind=row[2],
                    detail=json.loads(row[3]),
                    quarantined_at_ns=int(row[4]),
                )
            )
        return tuple(results)

    # ── append (transactional core) ────────────────────────────────────

    def _begin_immediate_retry(self, conn: sqlite3.Connection) -> None:
        """Execute ``BEGIN IMMEDIATE`` with busy-retry for separate-process contention.

        When two independent connections race to acquire the write lock,
        ``BEGIN IMMEDIATE`` may encounter ``SQLITE_BUSY``.  We retry with
        exponential backoff inside a short window so the store surface is
        safe under concurrent writers without relying solely on the
        connection-level busy timeout (which may behave inconsistently
        across Python SQLite builds and WAL lock primitives).
        """
        max_attempts = 30
        base_delay = 0.01  # 10 ms
        for attempt in range(max_attempts):
            try:
                conn.execute("BEGIN IMMEDIATE")
                return
            except sqlite3.OperationalError as exc:
                if "locked" in str(exc).lower() and attempt < max_attempts - 1:
                    delay = min(base_delay * (2 ** attempt), 1.0)
                    time.sleep(delay)
                    continue
                raise

    def _append_tx(
        self, attempt_id: str, event: LedgerEvent
    ) -> AppendResult:
        """Enforce all Step 4 invariants inside ONE ``BEGIN IMMEDIATE``.

        Order of checks (dedup wins over rejection):

        1. attempt_id match (``ValueError`` outside the transaction).
        2. ``BEGIN IMMEDIATE`` — acquire the write lock for this attempt
           (with embedded busy-retry for separate-process contention).
        3. Idempotency-key dedup — if ``(attempt_id, idempotency_key)``
           already exists, return the existing event (no raise).
        4. Post-terminal rejection — if any terminal event exists for
           ``attempt_id``, raise :class:`PostTerminalAppendError`.
        5. Monotonic sequence — ``event.sequence`` must exceed the
           current max sequence, else :class:`MonotonicSequenceError`.
        6. INSERT + COMMIT.
        """
        if event.identity.attempt_id != attempt_id:
            raise ValueError(
                f"Event attempt_id {event.identity.attempt_id!r} "
                f"does not match store attempt_id {attempt_id!r}"
            )

        event_json = json.dumps(event.to_dict(), sort_keys=True, ensure_ascii=False)
        conn = self.conn

        self._begin_immediate_retry(conn)
        try:
            cur = conn.cursor()

            # Cutover admission fence (Step 12b): once the durable
            # ``cutover_in_progress`` fence is engaged, no NEW attempt stream
            # may be admitted. An append that CONTINUES an existing attempt
            # (it already has at least one persisted event) — including the
            # natural terminal events that drain an in-flight attempt —
            # remains allowed. This check reads the fence metadata only when a
            # new stream would be created, so the steady-state append path
            # (fence not set) pays a single tiny metadata SELECT.
            cur.execute(
                "SELECT value FROM _store_metadata WHERE key = ?",
                (_CUTOVER_IN_PROGRESS_KEY,),
            )
            fence_row = cur.fetchone()
            if (
                fence_row is not None
                and fence_row[0] == _CUTOVER_IN_PROGRESS_SET
            ):
                cur.execute(
                    "SELECT COALESCE(MAX(sequence), 0)"
                    " FROM attempt_events WHERE attempt_id = ?",
                    (attempt_id,),
                )
                existing_max = int(cur.fetchone()[0])
                if existing_max == 0:
                    conn.execute("ROLLBACK")
                    raise CutoverInProgressError(
                        f"Cannot admit new attempt {attempt_id!r}: the "
                        f"cutover_in_progress admission fence is engaged. "
                        f"New admissions are rejected until the cutover "
                        f"completes."
                    )

            # (3) Idempotency-key dedup. Checked BEFORE any rejection so
            #     retries of an event that has since become post-terminal
            #     still return the existing event rather than raising.
            cur.execute(
                "SELECT event_json FROM attempt_events WHERE attempt_id = ? AND idempotency_key = ?",
                (attempt_id, event.idempotency_key),
            )
            dup_row = cur.fetchone()
            if dup_row is not None:
                # Step 8A: canonical comparison of duplicate idempotency keys.
                # Exact duplicates (same payload, outcome, event_type, schema_hash)
                # remain idempotent. Divergent duplicates are quarantined and
                # raise DivergentDuplicateError.
                stored_json = dup_row[0]
                divergences = _compare_canonical_signatures(stored_json, event_json)
                if divergences:
                    # End the append transaction before opening the separate
                    # quarantine transaction on this connection.
                    conn.execute("ROLLBACK")
                    _record_divergent_duplicate_quarantine(
                        self, attempt_id, event.idempotency_key,
                        divergences, stored_json, event_json,
                    )
                    raise DivergentDuplicateError(
                        attempt_id=attempt_id,
                        idempotency_key=event.idempotency_key,
                        divergences=divergences,
                        stored_event_json=stored_json,
                        new_event_json=event_json,
                    )
                # Exact duplicate — roll back and return existing.
                conn.execute("ROLLBACK")
                existing = _deserialize_ledger_event(json.loads(stored_json))
                return AppendResult(
                    attempt_id=attempt_id,
                    event=existing,
                    sequence=existing.sequence,
                    is_duplicate=True,
                )

            # (4) Post-terminal rejection — once terminal, no new events.
            cur.execute(
                f"SELECT 1 FROM attempt_events WHERE attempt_id = ? AND event_type IN ({','.join('?' * len(_TERMINAL_EVENT_TYPE_VALUES))}) LIMIT 1",
                (attempt_id, *_TERMINAL_EVENT_TYPE_VALUES),
            )
            if cur.fetchone() is not None:
                conn.execute("ROLLBACK")
                if event.event_type.value in _TERMINAL_EVENT_TYPE_VALUES:
                    raise DuplicateTerminalError(
                        f"Attempt {attempt_id!r} already has a terminal event; "
                        f"a second terminal {event.event_type.value!r} is rejected."
                    )
                raise PostTerminalAppendError(
                    f"Attempt {attempt_id!r} already has a terminal event; "
                    f"no further events are allowed "
                    f"(idempotency_key={event.idempotency_key!r})."
                )

            # Enforce the schema's lifecycle predecessor relation against the
            # durable stream, not merely against the caller's proposed event.
            required_predecessor = _REQUIRED_PREDECESSOR_EVENT.get(
                event.event_type.value
            )
            if required_predecessor is not None:
                cur.execute(
                    "SELECT 1 FROM attempt_events "
                    "WHERE attempt_id = ? AND event_type = ? LIMIT 1",
                    (attempt_id, required_predecessor),
                )
                if cur.fetchone() is None:
                    conn.execute("ROLLBACK")
                    predecessor_label = (
                        "STARTED"
                        if required_predecessor == AttemptEventType.STARTED.value
                        else repr(required_predecessor)
                    )
                    raise MissingStartEventError(
                        f"Event {event.event_type.value!r} for attempt "
                        f"{attempt_id!r} requires a durable "
                        f"{predecessor_label} event."
                    )

            # (5) Monotonic sequence — strictly greater than max.
            cur.execute(
                "SELECT COALESCE(MAX(sequence), 0) FROM attempt_events WHERE attempt_id = ?",
                (attempt_id,),
            )
            last_seq_row = cur.fetchone()
            last_seq = int(last_seq_row[0]) if last_seq_row is not None else 0
            if event.sequence <= last_seq:
                conn.execute("ROLLBACK")
                raise MonotonicSequenceError(
                    f"Event sequence {event.sequence} for attempt {attempt_id!r} "
                    f"is not monotonic; current max is {last_seq}."
                )
            expected_sequence = last_seq + 1
            if event.sequence != expected_sequence:
                conn.execute("ROLLBACK")
                raise SequenceGapError(
                    f"Event sequence {event.sequence} for attempt {attempt_id!r} "
                    f"would create a gap; expected {expected_sequence}."
                )
            if event.causal_predecessor_sequence != last_seq:
                conn.execute("ROLLBACK")
                raise CausalPredecessorError(
                    f"Event causal_predecessor_sequence "
                    f"{event.causal_predecessor_sequence} for attempt "
                    f"{attempt_id!r} must equal current max sequence {last_seq}."
                )

            # (6) INSERT.
            cur.execute(
                """\
INSERT INTO attempt_events
    (attempt_id, sequence, idempotency_key, event_type, event_json, appended_at_ns)
VALUES (?, ?, ?, ?, ?, ?)
""",
                (
                    attempt_id,
                    event.sequence,
                    event.idempotency_key,
                    event.event_type.value,
                    event_json,
                    time.time_ns(),
                ),
            )

            # (7) Occurrence-claim admission CAS (T-0101e): exactly ONE
            #     STARTED claim per occurrence across ALL attempt streams.
            #     Applies only to occurrence-join claims (payload kind
            #     "occurrence_join").  T-0101h round-4 blocker 3: the
            #     admission row AND the attempt reservation are folded into
            #     THIS single transaction together with the STARTED insert —
            #     a crash before STARTED can never leave a stranded admission
            #     row, and the UNIQUE(occurrence_id) PK is the final backstop
            #     for a concurrent second contender whose append rolls back
            #     as a whole (zero mutation).
            payload = event.payload if isinstance(event.payload, Mapping) else {}
            if (
                event.event_type.value == AttemptEventType.STARTED.value
                and str(payload.get("kind") or "").strip() == _OCCURRENCE_CLAIM_KIND
            ):
                occurrence_id = str(payload.get("occurrence_id") or "").strip()
                if occurrence_id:
                    claim_id = str(payload.get("claim_id") or "").strip()
                    cur.execute(
                        "SELECT attempt_id FROM occurrence_claim_admissions"
                        " WHERE occurrence_id = ?",
                        (occurrence_id,),
                    )
                    holder = cur.fetchone()
                    if holder is not None and holder[0] != attempt_id:
                        conn.execute("ROLLBACK")
                        raise OccurrenceClaimAdmissionConflict(
                            f"occurrence {occurrence_id[:16]}… is already admitted by "
                            f"claim attempt {holder[0]!r}; this claim attempt "
                            f"{attempt_id!r} is denied"
                        )
                    if holder is None:
                        try:
                            cur.execute(
                                "INSERT INTO occurrence_claim_admissions"
                                "  (occurrence_id, attempt_id, claim_id, admitted_at_ns)"
                                "  VALUES (?, ?, ?, ?)",
                                (occurrence_id, attempt_id, claim_id, time.time_ns()),
                            )
                        except sqlite3.IntegrityError as exc:
                            conn.execute("ROLLBACK")
                            raise OccurrenceClaimAdmissionConflict(
                                f"occurrence {occurrence_id[:16]}… is already admitted by "
                                f"a different claim attempt; this claim attempt "
                                f"{attempt_id!r} is denied"
                            ) from exc
                        # Fold the attempt reservation into the same
                        # transaction (it previously committed separately via
                        # ``reserve_attempt`` before the admission, which
                        # could strand a reservation on crash).
                        cur.execute(
                            "INSERT OR IGNORE INTO attempt_reservations"
                            "  (attempt_id, first_reserved_ns, last_reserved_ns,"
                            "   reservation_count) VALUES (?, ?, ?, 1)",
                            (attempt_id, time.time_ns(), time.time_ns()),
                        )
            conn.execute("COMMIT")
        except (
            CausalPredecessorError,
            CutoverInProgressError,
            DivergentDuplicateError,
            DuplicateTerminalError,
            MissingStartEventError,
            OccurrenceClaimAdmissionConflict,
            PostTerminalAppendError,
            MonotonicSequenceError,
            SequenceGapError,
            ValueError,
        ):
            # Transaction already rolled back inside the handler for
            # typed store errors and pre-condition ValueErrors.
            raise
        except Exception as exc:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            # Attempt to capture a PersistenceFailureDiagnostic in a
            # separate transaction.  This is best-effort evidence — if
            # it also fails the original exception is still raised.
            _try_record_append_failure_diagnostic(
                self, attempt_id, event.sequence, str(exc)
            )
            raise

        return AppendResult(
            attempt_id=attempt_id,
            event=event,
            sequence=event.sequence,
            is_duplicate=False,
        )

    def append_event(
        self, attempt_id: str, event: LedgerEvent
    ) -> AppendResult:
        """Persist a single ``LedgerEvent`` with all Step 4 invariants.

        See :meth:`AttemptLedgerStore.append_event` for the full contract.

        Returns:
            AppendResult whose ``event`` is the persisted event (the
            existing one when ``is_duplicate`` is True).
        """
        return self._append_tx(attempt_id, event)

    # ── typed append helpers ───────────────────────────────────────────

    @staticmethod
    def _require_event_type(
        event: LedgerEvent, expected: AttemptEventType
    ) -> None:
        """Raise ``ValueError`` if event.event_type does not match."""
        if event.event_type != expected:
            raise ValueError(
                f"Expected event_type {expected.value!r}, got "
                f"{event.event_type.value!r}."
            )

    def append_started(
        self, attempt_id: str, event: LedgerEvent
    ) -> AppendResult:
        """Append a STARTED event. Validates type before delegating."""
        self._require_event_type(event, AttemptEventType.STARTED)
        return self._append_tx(attempt_id, event)

    def append_completed(
        self, attempt_id: str, event: LedgerEvent
    ) -> AppendResult:
        """Append a COMPLETED event. Validates type before delegating."""
        self._require_event_type(event, AttemptEventType.COMPLETED)
        return self._append_tx(attempt_id, event)

    def append_failed(
        self, attempt_id: str, event: LedgerEvent
    ) -> AppendResult:
        """Append a FAILED event. Validates type before delegating."""
        self._require_event_type(event, AttemptEventType.FAILED)
        return self._append_tx(attempt_id, event)

    def append_cancelled(
        self, attempt_id: str, event: LedgerEvent
    ) -> AppendResult:
        """Append a CANCELLED event. Validates type before delegating."""
        self._require_event_type(event, AttemptEventType.CANCELLED)
        return self._append_tx(attempt_id, event)

    def read_events(self, attempt_id: str) -> list[LedgerEvent]:
        """Return all events for *attempt_id* ordered by sequence."""
        cur = self.conn.cursor()
        cur.execute(
            """\
SELECT event_json
FROM   attempt_events
WHERE  attempt_id = ?
ORDER  BY sequence ASC
""",
            (attempt_id,),
        )
        rows = cur.fetchall()
        return [_deserialize_ledger_event(json.loads(row[0])) for row in rows]

    def read_ledger(self, attempt_id: str) -> ExecutionAttemptLedger:
        """Reconstruct an ``ExecutionAttemptLedger`` from stored events.

        The returned ledger binds ``ledger_schema_version`` to the pinned
        ``LEDGER_SCHEMA_VERSION`` (identical to how ``ExecutionAttemptLedger``
        defaults at construction time).
        """
        events = tuple(self.read_events(attempt_id))
        return ExecutionAttemptLedger(
            attempt_id=attempt_id,
            events=events,
            ledger_schema_version=LEDGER_SCHEMA_VERSION,
        )

    def event_count(self, attempt_id: str) -> int:
        """Return the number of persisted events for *attempt_id*."""
        cur = self.conn.cursor()
        cur.execute(
            "SELECT COUNT(1) FROM attempt_events WHERE attempt_id = ?",
            (attempt_id,),
        )
        return cur.fetchone()[0]

    def has_terminal_event(self, attempt_id: str) -> bool:
        """Return ``True`` when a terminal event exists for *attempt_id*."""
        cur = self.conn.cursor()
        cur.execute(
            f"SELECT 1 FROM attempt_events WHERE attempt_id = ? AND event_type IN ({','.join('?' * len(_TERMINAL_EVENT_TYPE_VALUES))}) LIMIT 1",
            (attempt_id, *_TERMINAL_EVENT_TYPE_VALUES),
        )
        return cur.fetchone() is not None

    def last_sequence(self, attempt_id: str) -> int:
        """Return the highest persisted sequence number (0 if empty)."""
        cur = self.conn.cursor()
        cur.execute(
            """\
SELECT COALESCE(MAX(sequence), 0)
FROM   attempt_events
WHERE  attempt_id = ?
""",
            (attempt_id,),
        )
        return cur.fetchone()[0]

    def get_terminal_event(
        self, attempt_id: str
    ) -> Optional[LedgerEvent]:
        """Return the single terminal event for *attempt_id*, if any.

        Returns ``None`` if no terminal event has been persisted. The
        store enforces at most one terminal event, so the returned event
        is unique when present.
        """
        cur = self.conn.cursor()
        cur.execute(
            f"SELECT event_json FROM attempt_events WHERE attempt_id = ? AND event_type IN ({','.join('?' * len(_TERMINAL_EVENT_TYPE_VALUES))}) ORDER BY sequence ASC LIMIT 1",
            (attempt_id, *_TERMINAL_EVENT_TYPE_VALUES),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return _deserialize_ledger_event(json.loads(row[0]))

    # ── Step 12b: cutover quiesce ──────────────────────────────────────

    def list_in_flight_attempts(self) -> list[str]:
        """Return the attempt_ids that have NOT reached a terminal event.

        An attempt is in-flight when it has at least one persisted event but
        no terminal event (``COMPLETED``/``FAILED``/``CANCELLED``). The list
        is ordered by ``attempt_id`` for stable, deterministic enumeration.

        Implementation mirrors the SQL in CL5 Step 12b.1: a ``NOT EXISTS``
        correlated subquery against the terminal event types.
        """
        cur = self.conn.cursor()
        placeholders = ",".join("?" * len(_TERMINAL_EVENT_TYPE_VALUES))
        cur.execute(
            f"""
SELECT DISTINCT ae.attempt_id
FROM   attempt_events AS ae
WHERE NOT EXISTS (
    SELECT 1
    FROM   attempt_events AS terminal
    WHERE  terminal.attempt_id = ae.attempt_id
      AND  terminal.event_type IN ({placeholders})
)
ORDER BY ae.attempt_id ASC
""",
            tuple(_TERMINAL_EVENT_TYPE_VALUES),
        )
        return [row[0] for row in cur.fetchall()]

    def set_cutover_in_progress(self) -> bool:
        """Atomically engage the durable ``cutover_in_progress`` admission fence.

        The fence is persisted in ``_store_metadata`` so it survives a crash.
        Returns ``True`` when the fence was already engaged (resumption after a
        crash) and ``False`` when newly engaged.
        """
        conn = self.conn
        self._begin_immediate_retry(conn)
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT value FROM _store_metadata WHERE key = ?",
                (_CUTOVER_IN_PROGRESS_KEY,),
            )
            row = cur.fetchone()
            previously_engaged = (
                row is not None and row[0] == _CUTOVER_IN_PROGRESS_SET
            )
            if row is None:
                cur.execute(
                    "INSERT INTO _store_metadata (key, value) VALUES (?, ?)",
                    (_CUTOVER_IN_PROGRESS_KEY, _CUTOVER_IN_PROGRESS_SET),
                )
            elif not previously_engaged:
                cur.execute(
                    "UPDATE _store_metadata SET value = ? WHERE key = ?",
                    (_CUTOVER_IN_PROGRESS_SET, _CUTOVER_IN_PROGRESS_KEY),
                )
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise
        return previously_engaged

    def is_cutover_in_progress(self) -> bool:
        """Return whether the durable ``cutover_in_progress`` fence is engaged.

        Reads the persisted metadata value, so the result reflects a freshly
        reopened store (e.g. after a crash) rather than in-process state.
        """
        cur = self.conn.cursor()
        cur.execute(
            "SELECT value FROM _store_metadata WHERE key = ?",
            (_CUTOVER_IN_PROGRESS_KEY,),
        )
        row = cur.fetchone()
        return row is not None and row[0] == _CUTOVER_IN_PROGRESS_SET

    def clear_cutover_in_progress(self) -> bool:
        """Disengage the durable ``cutover_in_progress`` admission fence.

        Returns ``True`` when the fence was engaged before this call and
        ``False`` when it was already clear.
        """
        conn = self.conn
        self._begin_immediate_retry(conn)
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT value FROM _store_metadata WHERE key = ?",
                (_CUTOVER_IN_PROGRESS_KEY,),
            )
            row = cur.fetchone()
            was_engaged = (
                row is not None and row[0] == _CUTOVER_IN_PROGRESS_SET
            )
            # Remove the key entirely so a fresh store (key absent) is
            # indistinguishable from a post-cutover store.
            if row is not None:
                cur.execute(
                    "DELETE FROM _store_metadata WHERE key = ?",
                    (_CUTOVER_IN_PROGRESS_KEY,),
                )
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise
        return was_engaged

    def mark_attempt_indeterminate(
        self,
        attempt_id: str,
        last_event_type: str,
        last_event_sequence: int,
        drain_category: str,
        resolved_outcome: str,
        mark_reason: str,
    ) -> CutoverIndeterminateMark:
        """Durablely mark an in-flight attempt resolved to ``INDETERMINATE``.

        Idempotent per ``attempt_id`` (UPSERT). Evidence only. An attempt that
        has since drained to a terminal event is not marked; the call returns
        the mark reflecting the requested inputs (the caller is responsible for
        not marking drained attempts — the quiesce ``drain`` helper only marks
        non-terminal attempts).
        """
        if not attempt_id or not attempt_id.strip():
            raise ValueError("attempt_id must be non-empty")

        now_ns = time.time_ns()
        conn = self.conn
        self._begin_immediate_retry(conn)
        try:
            cur = conn.cursor()
            cur.execute(
                """
INSERT INTO cutover_indeterminate_marks
    (attempt_id, last_event_type, last_event_sequence,
     drain_category, resolved_outcome, mark_reason, marked_at_ns)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(attempt_id) DO UPDATE SET
    last_event_type     = excluded.last_event_type,
    last_event_sequence = excluded.last_event_sequence,
    drain_category      = excluded.drain_category,
    resolved_outcome    = excluded.resolved_outcome,
    mark_reason         = excluded.mark_reason,
    marked_at_ns        = excluded.marked_at_ns
""",
                (
                    attempt_id,
                    last_event_type,
                    last_event_sequence,
                    drain_category,
                    resolved_outcome,
                    mark_reason,
                    now_ns,
                ),
            )
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise

        return CutoverIndeterminateMark(
            attempt_id=attempt_id,
            last_event_type=last_event_type,
            last_event_sequence=last_event_sequence,
            drain_category=drain_category,
            resolved_outcome=resolved_outcome,
            mark_reason=mark_reason,
            marked_at_ns=now_ns,
        )

    def get_cutover_indeterminate_marks(self) -> list[CutoverIndeterminateMark]:
        """Return all durable cutover-indeterminate resolution marks.

        Ordered by ``marked_at_ns``. Evidence only.
        """
        cur = self.conn.cursor()
        cur.execute(
            """
SELECT attempt_id, last_event_type, last_event_sequence,
       drain_category, resolved_outcome, mark_reason, marked_at_ns
FROM   cutover_indeterminate_marks
ORDER  BY marked_at_ns ASC
"""
        )
        return [
            CutoverIndeterminateMark(
                attempt_id=row[0],
                last_event_type=row[1],
                last_event_sequence=int(row[2]),
                drain_category=row[3],
                resolved_outcome=row[4],
                mark_reason=row[5],
                marked_at_ns=int(row[6]),
            )
            for row in cur.fetchall()
        ]

    # ── Step 5: durable gates (SQLite-optimized) ───────────────────────

    def start_verified(self, attempt_id: str) -> StartGateResult:
        """Verify a STARTED event is durably persisted (SQLite-optimized).

        Uses a targeted query on ``attempt_events`` filtered by
        ``event_type = 'STARTED'``.  After deserialization, the event's
        ``event_type`` is cross-checked to guard against schema drift or
        data corruption.

        Fail-closed semantics:
        * Any query error → ``INDETERMINATE``.
        * Deserialization failure on a matching row → ``INDETERMINATE``.
        * Deserialized event_type ≠ STARTED → ``INDETERMINATE``.
        * Multiple STARTED rows → ``INCOHERENT``.
        * Zero rows → ``INCOMPLETE``.
        * Exactly one coherent row → ``VERIFIED``.
        """
        try:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT event_json FROM attempt_events"
                " WHERE attempt_id = ? AND event_type = ?"
                " ORDER BY sequence ASC",
                (attempt_id, AttemptEventType.STARTED.value),
            )
            rows = cur.fetchall()
        except Exception as exc:
            return StartGateResult(
                attempt_id=attempt_id,
                status=GateStatus.INDETERMINATE,
                started_event=None,
                evidence=f"Query failed: {exc}",
            )

        if len(rows) == 0:
            return StartGateResult(
                attempt_id=attempt_id,
                status=GateStatus.INCOMPLETE,
                started_event=None,
                evidence="No STARTED event found in durable store.",
            )

        if len(rows) > 1:
            return StartGateResult(
                attempt_id=attempt_id,
                status=GateStatus.INCOHERENT,
                started_event=None,
                evidence=(
                    f"Found {len(rows)} STARTED rows; expected at most one."
                ),
            )

        # Exactly one row — verify it round-trips correctly.
        try:
            event = _deserialize_ledger_event(json.loads(rows[0][0]))
        except Exception as exc:
            return StartGateResult(
                attempt_id=attempt_id,
                status=GateStatus.INDETERMINATE,
                started_event=None,
                evidence=f"Deserialization failed for STARTED row: {exc}",
            )

        if event.event_type != AttemptEventType.STARTED:
            return StartGateResult(
                attempt_id=attempt_id,
                status=GateStatus.INDETERMINATE,
                started_event=None,
                evidence=(
                    f"Deserialized event_type={event.event_type.value!r}, "
                    f"expected 'STARTED'; possible store corruption."
                ),
            )

        return StartGateResult(
            attempt_id=attempt_id,
            status=GateStatus.VERIFIED,
            started_event=event,
            evidence="Exactly one STARTED event verified in durable store.",
        )

    def terminal_or_indeterminate_verified(
        self, attempt_id: str
    ) -> TerminalGateResult:
        """Verify a terminal event is durably persisted (SQLite-optimized).

        Uses a targeted query on ``attempt_events`` filtered by terminal
        ``event_type`` values.  After deserialization the event is
        cross-checked to confirm it is genuinely terminal.

        Fail-closed semantics:
        * Any query error → ``INDETERMINATE``.
        * Deserialization failure on a matching row → ``INDETERMINATE``.
        * Deserialized event_type is not terminal → ``INDETERMINATE``.
        * Multiple terminal rows → ``INCOHERENT``.
        * Zero rows → ``INCOMPLETE``.
        * Exactly one coherent terminal row → ``VERIFIED``.
        """
        _TERMINAL_SET = frozenset({
            AttemptEventType.COMPLETED,
            AttemptEventType.FAILED,
            AttemptEventType.CANCELLED,
        })

        try:
            cur = self.conn.cursor()
            cur.execute(
                f"SELECT event_json FROM attempt_events"
                f" WHERE attempt_id = ? AND event_type IN ({','.join('?' * len(_TERMINAL_EVENT_TYPE_VALUES))})"
                f" ORDER BY sequence ASC",
                (attempt_id, *_TERMINAL_EVENT_TYPE_VALUES),
            )
            rows = cur.fetchall()
        except Exception as exc:
            return TerminalGateResult(
                attempt_id=attempt_id,
                status=GateStatus.INDETERMINATE,
                terminal_event=None,
                evidence=f"Query failed: {exc}",
            )

        if len(rows) == 0:
            return TerminalGateResult(
                attempt_id=attempt_id,
                status=GateStatus.INCOMPLETE,
                terminal_event=None,
                evidence="No terminal event found in durable store.",
            )

        if len(rows) > 1:
            return TerminalGateResult(
                attempt_id=attempt_id,
                status=GateStatus.INCOHERENT,
                terminal_event=None,
                evidence=(
                    f"Found {len(rows)} terminal rows; expected at most one."
                ),
            )

        # Exactly one row — verify it round-trips correctly.
        try:
            event = _deserialize_ledger_event(json.loads(rows[0][0]))
        except Exception as exc:
            return TerminalGateResult(
                attempt_id=attempt_id,
                status=GateStatus.INDETERMINATE,
                terminal_event=None,
                evidence=f"Deserialization failed for terminal row: {exc}",
            )

        if event.event_type not in _TERMINAL_SET:
            return TerminalGateResult(
                attempt_id=attempt_id,
                status=GateStatus.INDETERMINATE,
                terminal_event=None,
                evidence=(
                    f"Deserialized event_type={event.event_type.value!r}, "
                    f"not a terminal type; possible store corruption."
                ),
            )

        return TerminalGateResult(
            attempt_id=attempt_id,
            status=GateStatus.VERIFIED,
            terminal_event=event,
            evidence="Exactly one terminal event verified in durable store.",
        )

    # ── Step 8: diagnostic persistence and queries ──────────────────────

    def record_persistence_failure_diagnostic(
        self, attempt_id: str, diagnostic: Any
    ) -> None:
        """Persist a ``PersistenceFailureDiagnostic`` as evidence.

        The diagnostic is written in its own transaction, independent
        of the append transaction that failed.  It is joinable via
        ``attempt_id`` and is evidence only — it never grants append or
        completion authority.

        Raises:
            ValueError: if *diagnostic* is not a
                ``PersistenceFailureDiagnostic``.
        """
        from arnold.workflow.execution_attempt_ledger import (
            PersistenceFailureDiagnostic,
        )

        if not isinstance(diagnostic, PersistenceFailureDiagnostic):
            raise ValueError(
                f"Expected PersistenceFailureDiagnostic, got {type(diagnostic).__name__}"
            )

        diag_id = str(uuid.uuid4())
        diag_json = json.dumps(
            diagnostic.to_dict(), sort_keys=True, ensure_ascii=False
        )
        now_ns = time.time_ns()

        conn = self.conn
        self._begin_immediate_retry(conn)
        try:
            cur = conn.cursor()
            cur.execute(
                """\
INSERT INTO persistence_failure_diagnostics
    (attempt_id, diagnostic_id, target_event_sequence,
     failure_mode, observed_error, diagnostic_json, recorded_at_ns)
VALUES (?, ?, ?, ?, ?, ?, ?)
""",
                (
                    attempt_id,
                    diag_id,
                    diagnostic.target_event_sequence,
                    diagnostic.failure_mode.value,
                    diagnostic.observed_error,
                    diag_json,
                    now_ns,
                ),
            )
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise

    def record_reconciliation_diagnostic(
        self, attempt_id: str, diagnostic: Any
    ) -> None:
        """Persist a ``ReconciliationDiagnostic`` as evidence.

        The diagnostic is written in its own transaction, joinable via
        ``attempt_id``, and is evidence only.

        Raises:
            ValueError: if *diagnostic* is not a
                ``ReconciliationDiagnostic``.
        """
        from arnold.workflow.execution_attempt_ledger import (
            ReconciliationDiagnostic,
        )

        if not isinstance(diagnostic, ReconciliationDiagnostic):
            raise ValueError(
                f"Expected ReconciliationDiagnostic, got {type(diagnostic).__name__}"
            )

        diag_id = str(uuid.uuid4())
        diag_json = json.dumps(
            diagnostic.to_dict(), sort_keys=True, ensure_ascii=False
        )
        now_ns = time.time_ns()

        conn = self.conn
        self._begin_immediate_retry(conn)
        try:
            cur = conn.cursor()
            cur.execute(
                """\
INSERT INTO reconciliation_diagnostics
    (attempt_id, diagnostic_id, reconciled_event_sequence,
     outcome, outcome_detail, diagnostic_json, recorded_at_ns)
VALUES (?, ?, ?, ?, ?, ?, ?)
""",
                (
                    attempt_id,
                    diag_id,
                    diagnostic.reconciled_event_sequence,
                    diagnostic.outcome.value,
                    diagnostic.outcome_detail,
                    diag_json,
                    now_ns,
                ),
            )
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise

    def query_gaps(self, attempt_id: str) -> list[GapEntry]:
        """Return sequence gaps in the persisted event stream.

        Gaps are detected by comparing the ordered persisted sequences
        against the monotonic range [1, max_sequence].  An empty list
        means no gaps.
        """
        cur = self.conn.cursor()
        cur.execute(
            "SELECT sequence FROM attempt_events"
            " WHERE attempt_id = ?"
            " ORDER BY sequence ASC",
            (attempt_id,),
        )
        rows = cur.fetchall()
        if not rows:
            return []

        sequences = [int(r[0]) for r in rows]
        gaps: list[GapEntry] = []

        # Gap before first expected sequence 1.
        if sequences[0] > 1:
            missing = sequences[0] - 1
            gaps.append(
                GapEntry(
                    attempt_id=attempt_id,
                    gap_start=0,
                    gap_end=sequences[0],
                    missing_count=missing,
                )
            )

        # Internal gaps.
        for i in range(len(sequences) - 1):
            expected_next = sequences[i] + 1
            actual_next = sequences[i + 1]
            if actual_next > expected_next:
                missing = actual_next - expected_next
                gaps.append(
                    GapEntry(
                        attempt_id=attempt_id,
                        gap_start=sequences[i],
                        gap_end=actual_next,
                        missing_count=missing,
                    )
                )

        return gaps

    def query_persistence_diagnostics(
        self, attempt_id: str
    ) -> list[Any]:
        """Return all ``PersistenceFailureDiagnostic`` records for *attempt_id*."""
        from arnold.workflow.execution_attempt_ledger import (
            PersistenceFailureDiagnostic,
        )

        cur = self.conn.cursor()
        cur.execute(
            "SELECT diagnostic_json FROM persistence_failure_diagnostics"
            " WHERE attempt_id = ?"
            " ORDER BY recorded_at_ns ASC",
            (attempt_id,),
        )
        rows = cur.fetchall()
        result: list[Any] = []
        for row in rows:
            try:
                d = json.loads(row[0])
                result.append(
                    _deserialize_persistence_failure_diagnostic(d)
                )
            except Exception:
                # Corrupt diagnostic — skip; caller can detect gaps
                # via query_gaps if needed.
                pass
        return result

    def query_reconciliation_state(
        self, attempt_id: str
    ) -> list[Any]:
        """Return all ``ReconciliationDiagnostic`` records for *attempt_id*."""
        from arnold.workflow.execution_attempt_ledger import (
            ReconciliationDiagnostic,
        )

        cur = self.conn.cursor()
        cur.execute(
            "SELECT diagnostic_json FROM reconciliation_diagnostics"
            " WHERE attempt_id = ?"
            " ORDER BY recorded_at_ns ASC",
            (attempt_id,),
        )
        rows = cur.fetchall()
        result: list[Any] = []
        for row in rows:
            try:
                d = json.loads(row[0])
                result.append(
                    _deserialize_reconciliation_diagnostic(d)
                )
            except Exception:
                pass
        return result

    def query_source_cursor(
        self, attempt_id: str, cursor_key: str = "default"
    ) -> Optional[SourceCursor]:
        """Return the source cursor position for *attempt_id*."""
        cur = self.conn.cursor()
        cur.execute(
            "SELECT last_sequence, last_position, updated_at_ns"
            " FROM source_cursors"
            " WHERE attempt_id = ? AND cursor_key = ?",
            (attempt_id, cursor_key),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return SourceCursor(
            attempt_id=attempt_id,
            cursor_key=cursor_key,
            last_sequence=int(row[0]),
            last_position=row[1],
            updated_at_ns=int(row[2]),
        )

    def update_source_cursor(
        self,
        attempt_id: str,
        last_sequence: int,
        cursor_key: str = "default",
        last_position: str | None = None,
    ) -> SourceCursor:
        """Record (or update) the source cursor position for *attempt_id*."""
        now_ns = time.time_ns()
        conn = self.conn
        self._begin_immediate_retry(conn)
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO source_cursors"
                " (attempt_id, cursor_key, last_sequence, last_position, updated_at_ns)"
                " VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT(attempt_id, cursor_key) DO UPDATE SET"
                " last_sequence = excluded.last_sequence,"
                " last_position = excluded.last_position,"
                " updated_at_ns = excluded.updated_at_ns",
                (attempt_id, cursor_key, last_sequence, last_position, now_ns),
            )
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise
        return SourceCursor(
            attempt_id=attempt_id,
            cursor_key=cursor_key,
            last_sequence=last_sequence,
            last_position=last_position,
            updated_at_ns=now_ns,
        )

    # ── metadata introspection ─────────────────────────────────────────

    def get_contract_version(self) -> str:
        """Return the pinned contract version from metadata."""
        cur = self.conn.cursor()
        cur.execute(
            "SELECT value FROM _store_metadata WHERE key = 'contract_version'"
        )
        row = cur.fetchone()
        if row is None:
            return self._contract_version
        return row[0]

    def get_store_version(self) -> str:
        """Return the store version from metadata."""
        cur = self.conn.cursor()
        cur.execute(
            "SELECT value FROM _store_metadata WHERE key = 'store_version'"
        )
        row = cur.fetchone()
        if row is None:
            return _STORE_VERSION
        return row[0]


# ── Deserialization helpers ────────────────────────────────────────────────


def _record_divergent_duplicate_quarantine(
    store: "SqliteAttemptLedgerStore",
    attempt_id: str,
    idempotency_key: str,
    divergences: list[str],
    stored_json: str,
    new_json: str,
) -> None:
    """Record a divergent-duplicate quarantine diagnostic in a separate transaction.

    This is best-effort evidence. If the quarantine write also fails,
    the caller still raises DivergentDuplicateError so the divergence
    is never silently ignored.
    """
    import uuid as _uuid
    try:
        conn = store.conn
        store._begin_immediate_retry(conn)
        diagnostic_json = json.dumps({
            "idempotency_key": idempotency_key,
            "divergences": divergences,
            "stored_event_json": stored_json,
            "new_event_json": new_json,
        }, sort_keys=True)
        conn.execute(
            """INSERT INTO persistence_failure_diagnostics
               (attempt_id, diagnostic_id, target_event_sequence,
                failure_mode, observed_error, diagnostic_json, recorded_at_ns)
               VALUES (?, ?, 0, 'divergent_duplicate', ?, ?, ?)""",
            (
                attempt_id,
                str(_uuid.uuid4()),
                f"Divergent duplicate: {', '.join(divergences)}",
                diagnostic_json,
                time.time_ns(),
            ),
        )
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass


def _try_record_append_failure_diagnostic(
    store: Any,
    attempt_id: str,
    target_sequence: int,
    error_message: str,
) -> None:
    """Best-effort capture of a persistence-failure diagnostic.

    Called from inside ``_append_tx`` after the original transaction has
    been rolled back.  The diagnostic is written in a fresh transaction
    so it is not lost with the failed append.  If the diagnostic write
    also fails the error is silently discarded — the original append
    exception is still raised to the caller.
    """
    try:
        from arnold.workflow.execution_attempt_ledger import (
            PersistenceFailureDiagnostic,
            PersistenceFailureMode,
        )

        diag = PersistenceFailureDiagnostic(
            failure_mode=PersistenceFailureMode.WRITE_FAILED,
            target_event_sequence=target_sequence,
            observed_error=error_message,
        )
        store.record_persistence_failure_diagnostic(attempt_id, diag)
    except Exception:
        # Diagnostic capture is best-effort only.
        pass


def _canonical_event_signature(event_json: str) -> dict[str, Any]:
    """Extract the immutable/semantic portion of a serialized event.

    An event's idempotency key is a claim about one immutable attempt and one
    semantic append.  The old comparator only looked at ``payload`` and
    accidentally treated the volatile WBC observation timestamp as business
    data while ignoring the attempt identity entirely.  That made a retry of
    the same attempt look divergent and allowed a changed attempt identity to
    hide behind an otherwise equal payload.

    The comparison intentionally excludes only observation timestamps:
    top-level ``occurred_at``/``observed_at`` and the WBC source record's
    ``observed_at``.  Fence, invocation, attempt ordinal, source version,
    provenance, and all other runtime metadata remain part of the signature.
    Missing runtime metadata is *not* treated as equivalent to present
    metadata; callers must prepare the same event shape before appending.
    """
    data = json.loads(event_json)
    payload = data.get("payload")
    if isinstance(payload, dict):
        payload = json.loads(json.dumps(payload, sort_keys=True, ensure_ascii=False))
        runtime = payload.get("__wbc_runtime__")
        if isinstance(runtime, dict):
            source_record = runtime.get("source_record")
            if isinstance(source_record, dict):
                source_record.pop("observed_at", None)

    identity = data.get("identity")
    if isinstance(identity, dict):
        identity = {
            key: identity.get(key)
            for key in (
                "workflow_id",
                "run_id",
                "graph_revision",
                "step_id",
                "boundary_id",
                "invocation_id",
                "attempt_ordinal",
                "attempt_id",
            )
        }

    return {
        "identity": identity,
        "payload": payload,
        "outcome": data.get("outcome"),
        "event_type": data.get("event_type", ""),
        "event_schema_version": data.get("event_schema_version"),
        "persistence_status": data.get("persistence_status"),
        "payload_policy_ref": data.get("payload_policy_ref"),
        "provenance": data.get("provenance"),
        "adapter": data.get("adapter"),
        "versions": data.get("versions"),
        "grant_ref": data.get("grant_ref"),
    }


def _compare_canonical_signatures(
    stored_json: str,
    new_json: str,
) -> list[str]:
    """Return list of divergence reasons between two canonical event signatures.

    An empty list means the signatures are identical (exact duplicate).
    Non-empty list identifies which fields differ (divergent duplicate).
    """
    stored = _canonical_event_signature(stored_json)
    new = _canonical_event_signature(new_json)
    divergences: list[str] = []
    for key in (
        "identity",
        "payload",
        "outcome",
        "event_type",
        "event_schema_version",
        "persistence_status",
        "payload_policy_ref",
        "provenance",
        "adapter",
        "versions",
        "grant_ref",
    ):
        if stored.get(key) == new.get(key):
            continue
        if key == "identity" and isinstance(stored.get(key), dict) and isinstance(new.get(key), dict):
            for identity_key in (
                "workflow_id",
                "run_id",
                "graph_revision",
                "step_id",
                "boundary_id",
                "invocation_id",
                "attempt_ordinal",
                "attempt_id",
            ):
                if stored[key].get(identity_key) != new[key].get(identity_key):
                    divergences.append(f"divergent_identity.{identity_key}")
        else:
            divergences.append(f"divergent_{key}")
    return divergences


def _deserialize_ledger_event(d: dict[str, Any]) -> LedgerEvent:
    """Reconstruct a ``LedgerEvent`` from its ``to_dict()`` representation.

    This function is the inverse of ``LedgerEvent.to_dict()`` and does NOT
    mutate the ``LedgerEvent`` or ``ExecutionAttemptLedger`` schema.
    """
    event_type = AttemptEventType(d["event_type"])
    persistence_status = PersistenceStatus(d["persistence_status"])
    outcome = AttemptOutcome(d["outcome"]) if d.get("outcome") is not None else None

    # Identity
    ident = d["identity"]
    identity = AttemptIdentity(
        workflow_id=ident["workflow_id"],
        run_id=ident["run_id"],
        graph_revision=ident["graph_revision"],
        attempt_ordinal=ident.get("attempt_ordinal", 1),
        attempt_id=ident["attempt_id"],
        step_id=ident.get("step_id"),
        boundary_id=ident.get("boundary_id"),
        invocation_id=ident.get("invocation_id"),
    )

    # Provenance
    prov = d["provenance"]
    causal_lineage_raw = prov.get("causal_lineage", [])
    if isinstance(causal_lineage_raw, list):
        causal_lineage = tuple(causal_lineage_raw)
    else:
        causal_lineage = ()
    provenance = AttemptProvenance(
        parent_attempt_id=prov.get("parent_attempt_id"),
        causal_lineage=causal_lineage,
        actor_id=prov.get("actor_id"),
        tool_id=prov.get("tool_id"),
    )

    # Adapter
    adp = d["adapter"]
    adapter_kind = AdapterKind(adp["adapter_kind"])
    adapter = RuntimeAdapter(
        adapter_kind=adapter_kind,
        adapter_version=adp["adapter_version"],
    )

    # Versions
    ver = d["versions"]
    versions = VersionSet(
        code_version=ver.get("code_version", ""),
        config_version=ver.get("config_version", ""),
        template_version=ver.get("template_version", ""),
    )

    # GrantRef
    gr = d["grant_ref"]
    grant_ref = GrantRef(
        grant_id=gr["grant_id"],
        decision_id=gr.get("decision_id"),
    )

    # Payload (may be None, a dict, or a DurableRef dict)
    payload_raw = d.get("payload")
    if payload_raw is not None and isinstance(payload_raw, dict) and "store_id" in payload_raw:
        from arnold.workflow.durable_refs import DurableRef
        payload = DurableRef(
            store_id=payload_raw["store_id"],
            locator=payload_raw["locator"],
            digest=payload_raw.get("digest", ""),
            schema_type=payload_raw.get("schema_type", "application/json"),
            visibility_class=payload_raw.get("visibility_class"),
            encryption_scope=payload_raw.get("encryption_scope"),
        )
    else:
        payload = payload_raw

    return LedgerEvent(
        idempotency_key=d["idempotency_key"],
        event_type=event_type,
        identity=identity,
        provenance=provenance,
        adapter=adapter,
        versions=versions,
        grant_ref=grant_ref,
        sequence=d["sequence"],
        causal_predecessor_sequence=d["causal_predecessor_sequence"],
        append_position=d["append_position"],
        occurred_at=d["occurred_at"],
        observed_at=d["observed_at"],
        persistence_status=persistence_status,
        outcome=outcome,
        payload=payload,
        payload_policy_ref=d.get("payload_policy_ref"),
        event_schema_version=d.get("event_schema_version", LEDGER_SCHEMA_VERSION),
    )


def _deserialize_durable_ref(d: dict[str, Any]) -> Any:
    """Reconstruct a ``DurableRef`` from its ``to_dict()`` representation."""
    from arnold.workflow.durable_refs import DurableRef

    return DurableRef(
        store_id=d["store_id"],
        locator=d["locator"],
        digest=d.get("digest", ""),
        schema_type=d.get("schema_type", "application/octet-stream"),
        media_type=d.get("media_type", "application/octet-stream"),
        size_bytes=d.get("size_bytes"),
        encryption_scope=d.get("encryption_scope", "none"),
        access_scope=d.get("access_scope", "workflow"),
        privacy_class=d.get("privacy_class", "internal"),
        retention_class=d.get("retention_class", "run"),
        availability_class=d.get("availability_class", "standard"),
        tenant_id=d.get("tenant_id"),
        workflow_id=d.get("workflow_id"),
        ref_version=d.get("ref_version", "arnold.workflow.durable_ref.v1"),
        metadata=d.get("metadata", {}),
    )


def _deserialize_persistence_failure_diagnostic(
    d: dict[str, Any],
) -> Any:
    """Reconstruct a ``PersistenceFailureDiagnostic`` from its ``to_dict()``."""
    from arnold.workflow.execution_attempt_ledger import (
        PersistenceFailureDiagnostic,
        PersistenceFailureMode,
    )

    recovery_evidence_ref: Any = None
    if "recovery_evidence_ref" in d and d["recovery_evidence_ref"] is not None:
        recovery_evidence_ref = _deserialize_durable_ref(
            d["recovery_evidence_ref"]
        )

    return PersistenceFailureDiagnostic(
        failure_mode=PersistenceFailureMode(d["failure_mode"]),
        target_event_sequence=d["target_event_sequence"],
        observed_error=d["observed_error"],
        recovery_evidence_ref=recovery_evidence_ref,
        quarantined_authority_advance=d.get(
            "quarantined_authority_advance", False
        ),
        quarantine_reason=d.get("quarantine_reason"),
        diagnostic_schema_version=d.get(
            "diagnostic_schema_version",
            "arnold.workflow.ledger.persistence_failure_diagnostic.v1",
        ),
    )


def _deserialize_reconciliation_diagnostic(
    d: dict[str, Any],
) -> Any:
    """Reconstruct a ``ReconciliationDiagnostic`` from its ``to_dict()``."""
    from arnold.workflow.execution_attempt_ledger import (
        ReconciliationDiagnostic,
        ReconciliationOutcome,
    )

    recovered_refs_raw = d.get("recovered_evidence_refs", [])
    if isinstance(recovered_refs_raw, list):
        recovered_refs: tuple[Any, ...] = tuple(
            _deserialize_durable_ref(r) for r in recovered_refs_raw
        )
    else:
        recovered_refs = ()

    return ReconciliationDiagnostic(
        reconciled_event_sequence=d["reconciled_event_sequence"],
        outcome=ReconciliationOutcome(d["outcome"]),
        outcome_detail=d["outcome_detail"],
        recovered_evidence_refs=recovered_refs,
        authority_disposition=d.get("authority_disposition"),
        diagnostic_schema_version=d.get(
            "diagnostic_schema_version",
            "arnold.workflow.ledger.reconciliation_diagnostic.v1",
        ),
    )


# ── Public API surface ─────────────────────────────────────────────────────


__all__ = [
    "AppendResult",
    "AttemptLedgerError",
    "AttemptLedgerStore",
    "AttemptReservation",
    "CausalPredecessorError",
    "CutoverInProgressError",
    "CutoverIndeterminateMark",
    "DuplicateTerminalError",
    "GapEntry",
    "GateStatus",
    "MissingStartEventError",
    "MonotonicSequenceError",
    "PostTerminalAppendError",
    "SequenceGapError",
    "SourceCursor",
    "SqliteAttemptLedgerStore",
    "StartGateResult",
    "TerminalGateResult",
]
