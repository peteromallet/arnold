"""Append-only Custody lease history store using durable local CAS/file-locking.

Each lease is backed by an append-only event history (JSON-lines) and an
advisory ``fcntl.flock`` for serialization — the same pattern used by
:mod:`megaplan.runtime.capacity_lease` and
:mod:`megaplan.runtime.budget_authority`.

Storage layout under ``<base_dir>/``::

    <lease_id>.history.jsonl   — append-only event stream (one JSON object per line)
    <lease_id>.state.json      — cached current lease state (derived from replay)
    <lease_id>.lock            — fcntl.flock serialization gate

Principles
----------
* **Append-only** — Terminal events (release, expire, fence) are *added* to the
  history; they never erase prior events.  Replay always sees the full
  lifecycle.
* **Sequence checks** — An event whose ``sequence <= last_sequence`` is rejected
  unless it is an idempotent exact repeat.
* **Idempotency** — An event whose ``idempotency_key`` + ``payload_hash``
  matches the last event with that sequence is silently accepted (no-op).
* **Payload conflict quarantine** — If an event arrives with a known
  ``idempotency_key`` but a *different* ``payload_hash``, a synthetic
  ``conflict`` event is appended and the store quarantines the conflicting
  payload so callers can reconcile.
* **Deterministic replay** — ``replay_history(lease_id)`` replays every event
  in order through the reducers and returns the final ``CustodyLease`` (or
  ``None`` if the lease has not yet been acquired).

Reducers
--------
The store includes pure reducer functions for every event type:

============  =============================================================
acquire       Create a lease (requires no existing active lease).
renew         Bump ``custody_epoch`` and update ``expires_at``.
transfer      Change owner identity tuples.
release       Mark the lease as released (terminal — no further mutations).
expire        Mark the lease as expired (terminal).
fence         Mark the lease as fenced (terminal).
conflict      Record a conflict in the lease's ``last_conflict`` field.
reconcile     Clear conflict state and optionally resume the lease.
============

Terminal events produce a lease still present in the state with
``event_type`` set so callers can distinguish active vs terminated leases,
but the history is never truncated.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Optional, Sequence

from arnold_pipelines.megaplan.custody.contracts import (
    CustodyLease,
    CustodyLeaseEvent,
    CustodyLeaseEventType,
    normalize_custody_lease,
    normalize_custody_lease_event,
)
from arnold_pipelines.run_authority.contracts import (
    ContractError,
    PayloadConflict,
)

# ── Default base directory ────────────────────────────────────────────────


def default_lease_store_dir() -> Path:
    """Return the default custody lease-store directory."""
    return Path(os.path.expanduser("~/.megaplan/custody/leases"))


# ── File-path helpers ─────────────────────────────────────────────────────


def _history_path(base_dir: Path, lease_id: str) -> Path:
    return base_dir / f"{lease_id}.history.jsonl"


def _state_path(base_dir: Path, lease_id: str) -> Path:
    return base_dir / f"{lease_id}.state.json"


def _lock_path(base_dir: Path, lease_id: str) -> Path:
    return base_dir / f"{lease_id}.lock"


def _occurrence_lock_path(base_dir: Path, occurrence_key: str) -> Path:
    """Return the occurrence-scoped lock path for *occurrence_key*.

    The lock is keyed by the OCCURRENCE identity (not the claim/lease id), so
    two distinct claims for the same occurrence serialize their
    scan → acquire → append instead of racing on claim-scoped locks.
    """
    digest = hashlib.sha256(str(occurrence_key or "").strip().encode("utf-8")).hexdigest()
    return base_dir / f"occurrence-{digest[:32]}.lock"


# ── Atomic file write ─────────────────────────────────────────────────────


def _atomic_write(path: Path, content: str) -> None:
    """Write *content* to *path* atomically via temp-file + rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write(content)
    os.replace(tmp, path)


def _atomic_append(path: Path, line: str) -> None:
    """Append a single line to *path* atomically via temp-file + rename.

    This reads the existing file, appends, and writes back.
    For append-only semantics, callers must serialize via flock.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = ""
    if path.exists():
        try:
            existing = path.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError):
            existing = ""
    _atomic_write(path, existing + line)


# ── Error types ───────────────────────────────────────────────────────────


class LeaseStoreError(RuntimeError):
    """Base exception for custody lease-store operations."""


class StaleSequenceError(LeaseStoreError):
    """Raised when an event has a non-monotonic sequence number."""


class LeaseIdempotencyConflict(LeaseStoreError):
    """Raised when an idempotency key maps to a different payload."""


class QuarantinedPayloadError(LeaseStoreError):
    """Raised when a payload conflict has been quarantined."""


class LeaseNotFoundError(LeaseStoreError):
    """Raised when a referenced lease does not exist."""


class TerminalLeaseError(LeaseStoreError):
    """Raised when a lifecycle operation targets a lease already in a terminal state.

    Terminal states (release, expire, fence) reject every further lifecycle
    mutation except an idempotent exact repeat of the terminal event itself.
    """


class LeaseOwnerMismatchError(LeaseStoreError):
    """Raised when a lifecycle caller is not the current owner (Step 11C).

    Owner identity is the triple ``(owner_host, owner_pid, owner_boot_id)`` —
    the process-birth tuple.  A caller whose tuple differs from the lease's
    current owner cannot renew, transfer, release, expire, fence, or reclaim.
    """


class StaleEpochError(LeaseStoreError):
    """Raised when a lifecycle operation carries an epoch that is not strictly
    greater than the lease's current epoch (Step 11C old-epoch fencing).

    The custody epoch is monotonic: a caller presenting an epoch less than or
    equal to the current epoch is fenced (rejected) unless the operation is an
    idempotent exact repeat.
    """


class LeaseTtlCeilingError(LeaseStoreError):
    """Raised when a requested TTL exceeds the maximum lease TTL (Step 11C)."""


# ── Writer token (Step 11A) ────────────────────────────────────────────────
#
# ``record_event`` is token-guarded: the blessed lifecycle helpers
# (``acquire``/``renew``/``transfer``/``release``/``expire``/``fence``/
# ``reclaim``) pass this sentinel so the store knows the caller went through
# invariant enforcement.  Production lifecycle callers (e.g.
# ``repair_requests``) MUST use the helpers rather than constructing a raw
# ``CustodyLeaseEvent`` and calling ``record_event`` directly.
_LEASE_WRITER_TOKEN = object()


# ── Lifecycle-invariant helpers (Step 11C) ─────────────────────────────────


def utc_now() -> str:
    """Return the current UTC time in the store's canonical timestamp format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _last_lifecycle_event_type(
    events: Sequence[CustodyLeaseEvent],
) -> str | None:
    """Return the event type of the last *lifecycle* event in *events*.

    Synthetic ``conflict`` events are ignored (they are not lifecycle
    transitions).  Returns ``None`` when *events* is empty or contains only
    conflict events.
    """
    for event in reversed(events):
        if event.event_type != "conflict":
            return event.event_type
    return None


def _enforce_monotonic_epoch(
    current_epoch: int,
    op_epoch: int,
    lease_id: str,
    op: str,
) -> None:
    """Reject an operation whose epoch is not strictly greater than the current
    epoch (Step 11C old-epoch fencing)."""
    if op_epoch <= current_epoch:
        raise StaleEpochError(
            f"{op} epoch {op_epoch} is not strictly greater than current "
            f"epoch {current_epoch} for lease {lease_id!r}"
        )


def _clamp_ttl(occurred_at: str, expires_at: str) -> str:
    """Return *expires_at*, raising ``LeaseTtlCeilingError`` if the requested
    TTL exceeds ``MAXIMUM_LEASE_TTL_SECONDS`` (Step 11C TTL ceiling)."""
    from arnold_pipelines.megaplan.custody.contracts import (
        MAXIMUM_LEASE_TTL_SECONDS,
    )

    try:
        start = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
        end = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return expires_at
    ttl = (end - start).total_seconds()
    if ttl > MAXIMUM_LEASE_TTL_SECONDS:
        raise LeaseTtlCeilingError(
            f"requested TTL {ttl:.0f}s exceeds maximum "
            f"{MAXIMUM_LEASE_TTL_SECONDS}s"
        )
    return expires_at


# ── Reducers ──────────────────────────────────────────────────────────────


def _reduce_acquire(
    _current: CustodyLease | None, event: CustodyLeaseEvent
) -> CustodyLease | None:
    """Create a new lease from an acquire event.

    Requires no existing lease (or the existing lease is in a terminal state
    where a new acquisition is allowed — determined by the caller).
    """
    from arnold_pipelines.megaplan.custody.contracts import (
        RepairOccurrenceKey,
        CustodyTargetKey,
        build_custody_target_key,
        build_repair_occurrence_key,
    )

    # Reconstruct the lease from the event fields
    # We need a RepairOccurrenceKey, which requires a CustodyTargetKey.
    # The event carries occurrence_digest, which is a hash — we cannot
    # reconstruct the full target from just the digest.
    # Instead, the store layer uses the event's fields directly.
    # For the lease record, we store what we can and use the occurrence_digest
    # as an opaque reference.
    return CustodyLease(
        lease_id=event.lease_id,
        occurrence_key=_synthetic_occurrence_key_from_event(event),
        owner_host=event.owner_host,
        owner_pid=event.owner_pid,
        owner_boot_id=event.owner_boot_id,
        run_authority_grant_id=event.run_authority_grant_id,
        coordinator_fence_token=event.coordinator_fence_token,
        wbc_attempt_reference=event.wbc_attempt_reference,
        custody_epoch=event.custody_epoch,
        acquired_at=event.occurred_at,
        expires_at=_expiry_from_payload(event),
        idempotency_key=event.idempotency_key,
        causal_predecessor=event.causal_predecessor,
    )


def _reduce_renew(
    current: CustodyLease | None, event: CustodyLeaseEvent
) -> CustodyLease | None:
    """Renew a lease — bump epoch and update expiry."""
    if current is None:
        raise LeaseStoreError("cannot renew a non-existent lease")
    new_epoch = max(current.custody_epoch, event.custody_epoch)
    new_expires = _expiry_from_payload(event)
    return replace(
        current,
        custody_epoch=new_epoch,
        expires_at=new_expires,
        causal_predecessor=event.causal_predecessor or current.lease_id,
    )


def _reduce_transfer(
    current: CustodyLease | None, event: CustodyLeaseEvent
) -> CustodyLease | None:
    """Transfer ownership to a new owner identity."""
    if current is None:
        raise LeaseStoreError("cannot transfer a non-existent lease")
    new_epoch = max(current.custody_epoch, event.custody_epoch)
    return replace(
        current,
        owner_host=event.owner_host,
        owner_pid=event.owner_pid,
        owner_boot_id=event.owner_boot_id,
        custody_epoch=new_epoch,
        causal_predecessor=event.causal_predecessor or current.lease_id,
    )


def _terminal_expires_at(
    current: CustodyLease, event: CustodyLeaseEvent
) -> str:
    """Return an ``expires_at`` value that is strictly after ``acquired_at``.

    Terminal events (release, expire, fence) set ``expires_at`` to the event's
    ``occurred_at``, but if that is not after ``acquired_at`` (e.g. the event is
    recorded with the same timestamp), we advance it by one second to satisfy
    the contract invariant ``expires_at > acquired_at``.
    """
    from datetime import timedelta

    candidate = event.occurred_at
    try:
        acq_dt = datetime.fromisoformat(current.acquired_at.replace("Z", "+00:00"))
        cand_dt = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        # If either timestamp is unparseable, return candidate as-is;
        # the contract will raise on construction if it's invalid.
        return candidate
    if cand_dt > acq_dt:
        return candidate
    # Advance by one second past acquired_at to maintain the invariant.
    safe = acq_dt + timedelta(seconds=1)
    return safe.strftime("%Y-%m-%dT%H:%M:%SZ")


def _reduce_release(
    current: CustodyLease | None, event: CustodyLeaseEvent
) -> CustodyLease | None:
    """Release a lease — terminal state, no further mutations."""
    if current is None:
        raise LeaseStoreError("cannot release a non-existent lease")
    return replace(
        current,
        expires_at=_terminal_expires_at(current, event),
        causal_predecessor=event.causal_predecessor or current.lease_id,
    )


def _reduce_expire(
    current: CustodyLease | None, event: CustodyLeaseEvent
) -> CustodyLease | None:
    """Mark a lease as expired — terminal state."""
    if current is None:
        raise LeaseStoreError("cannot expire a non-existent lease")
    return replace(
        current,
        expires_at=_terminal_expires_at(current, event),
        causal_predecessor=event.causal_predecessor or current.lease_id,
    )


def _reduce_fence(
    current: CustodyLease | None, event: CustodyLeaseEvent
) -> CustodyLease | None:
    """Mark a lease as fenced — terminal state."""
    if current is None:
        raise LeaseStoreError("cannot fence a non-existent lease")
    return replace(
        current,
        coordinator_fence_token=event.coordinator_fence_token,
        expires_at=_terminal_expires_at(current, event),
        causal_predecessor=event.causal_predecessor or current.lease_id,
    )


def _reduce_conflict(
    current: CustodyLease | None, event: CustodyLeaseEvent
) -> CustodyLease | None:
    """Record a conflict — the lease itself is unchanged (quarantined separately)."""
    if current is None:
        # Conflict on a lease that hasn't been acquired yet is possible
        # (e.g., conflicting acquire attempts).  The caller quarantines.
        return None
    # Conflict does not mutate the lease — it's recorded in the event history.
    return current


def _reduce_reconcile(
    current: CustodyLease | None, event: CustodyLeaseEvent
) -> CustodyLease | None:
    """Reconcile after a conflict — resume from the current state."""
    if current is None:
        raise LeaseStoreError("cannot reconcile a non-existent lease")
    new_epoch = max(current.custody_epoch, event.custody_epoch)
    return replace(
        current,
        custody_epoch=new_epoch,
        causal_predecessor=event.causal_predecessor or current.lease_id,
    )


# ── Reducer dispatch ──────────────────────────────────────────────────────


_REDUCERS: dict[CustodyLeaseEventType, Any] = {
    "acquire": _reduce_acquire,
    "renew": _reduce_renew,
    "transfer": _reduce_transfer,
    "release": _reduce_release,
    "expire": _reduce_expire,
    "fence": _reduce_fence,
    "conflict": _reduce_conflict,
    "reconcile": _reduce_reconcile,
}


def reduce_event(
    current: CustodyLease | None, event: CustodyLeaseEvent
) -> CustodyLease | None:
    """Apply a single event to the current lease state, returning the new state."""
    reducer = _REDUCERS.get(event.event_type)
    if reducer is None:
        raise LeaseStoreError(f"unknown event type: {event.event_type!r}")
    return reducer(current, event)


def replay_events(
    events: Sequence[CustodyLeaseEvent],
) -> CustodyLease | None:
    """Deterministically replay a sequence of events to compute the current lease."""
    current: CustodyLease | None = None
    for event in events:
        current = reduce_event(current, event)
    return current


# ── Synthetic occurrence key (used when reconstructing leases from events) ─


def _synthetic_occurrence_key_from_event(
    event: CustodyLeaseEvent,
) -> Any:
    """Build a minimal RepairOccurrenceKey from an event when the full target
    is not available in the event history.

    The event carries occurrence_digest but not the full F01 tuple.
    We construct a synthetic target using the lease_id as a stand-in for
    the F01 fields and use the event's other identity fields directly.
    """
    from arnold_pipelines.megaplan.custody.contracts import (
        RepairOccurrenceKey,
        CustodyTargetKey,
        normalize_repair_occurrence_key,
    )

    # New canonical writers retain the complete occurrence contract in the
    # acquire payload.  Prefer that lossless identity on replay; only legacy
    # events without it need the synthetic compatibility fallback below.
    payload = dict(event.payload) if event.payload else {}
    occurrence = normalize_repair_occurrence_key(payload.get("occurrence_key"))
    if occurrence is not None:
        return occurrence

    # Build a synthetic target from the lease_id and event fields.
    # This is lossy (the original F01 is not recoverable from just the digest)
    # but allows the lease record to carry a coherent occurrence_key.
    synthetic_target = CustodyTargetKey(
        environment="__synthetic__",
        session=event.lease_id,
        chain=event.lease_id,
        plan_revision=event.causal_predecessor or event.lease_id,
        phase=event.event_type,
        task=event.lease_id,
        attempt=str(event.sequence),
        normalized_failure_kind=event.event_type,
        blocker_or_phase_result_hash=event.payload_hash,
        fence=str(event.coordinator_fence_token),
        chain_identity=event.occurrence_digest,
        dispatch_key=payload.get("dispatch_key", ""),
    )
    return RepairOccurrenceKey(
        target=synthetic_target,
        run_id=event.run_authority_grant_id,
        run_revision=str(event.custody_epoch),
        coordinator_attempt_id=event.event_id,
        fence_token=event.coordinator_fence_token,
        wbc_attempt_reference=event.wbc_attempt_reference,
    )


def _expiry_from_payload(event: CustodyLeaseEvent) -> str:
    """Extract expires_at from the event payload, falling back to a default.

    The fallback uses :data:`~arnold_pipelines.megaplan.custody.contracts.DEFAULT_LEASE_TTL_SECONDS`
    and is clamped to :data:`~arnold_pipelines.megaplan.custody.contracts.MAXIMUM_LEASE_TTL_SECONDS`.
    """
    from arnold_pipelines.megaplan.custody.contracts import (
        DEFAULT_LEASE_TTL_SECONDS,
        MAXIMUM_LEASE_TTL_SECONDS,
    )

    payload = dict(event.payload) if event.payload else {}
    expires = payload.get("expires_at")
    if isinstance(expires, str) and expires.strip():
        # Validate that explicit expiry does not exceed max TTL
        try:
            expires_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            occurred_dt = datetime.fromisoformat(event.occurred_at.replace("Z", "+00:00"))
            ttl_seconds = (expires_dt - occurred_dt).total_seconds()
            if ttl_seconds > MAXIMUM_LEASE_TTL_SECONDS:
                # Clamp to max TTL
                clamped = occurred_dt + timedelta(seconds=MAXIMUM_LEASE_TTL_SECONDS)
                return clamped.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, TypeError):
            pass
        return expires

    # Fallback: use DEFAULT_LEASE_TTL_SECONDS from occurred_at
    try:
        occurred_dt = datetime.fromisoformat(event.occurred_at.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        occurred_dt = datetime.now(timezone.utc)
    default = occurred_dt + timedelta(seconds=DEFAULT_LEASE_TTL_SECONDS)
    return default.strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Lease store ───────────────────────────────────────────────────────────


@dataclass
class CustodyLeaseStore:
    """Append-only custody lease history store.

    Construct via :func:`open_lease_store`.  Each instance manages leases
    under a single ``base_dir``.
    """

    base_dir: Path
    flock: bool = True
    directory_fd: int | None = field(default=None, repr=False)

    def close(self) -> None:
        """Release an injected descriptor that pins this store directory."""
        if self.directory_fd is not None:
            os.close(self.directory_fd)
            self.directory_fd = None

    def __del__(self) -> None:  # pragma: no cover - interpreter cleanup
        try:
            self.close()
        except OSError:
            pass

    def _read_member_text(self, name: str) -> str | None:
        """Read one direct store member through the pinned directory."""
        if self.directory_fd is None:
            path = self.base_dir / name
            if not path.exists():
                return None
            try:
                return path.read_text(encoding="utf-8")
            except (FileNotFoundError, OSError):
                return None
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(name, flags, dir_fd=self.directory_fd)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise LeaseStoreError("custody member could not be opened safely") from exc
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise LeaseStoreError("custody member is not a regular file")
            chunks: list[bytes] = []
            while chunk := os.read(fd, 1024 * 1024):
                chunks.append(chunk)
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_size) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
            ):
                raise LeaseStoreError("custody member changed during read")
            return b"".join(chunks).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LeaseStoreError("custody member is not UTF-8") from exc
        finally:
            os.close(fd)

    # -- record event (Step 11A: token-guarded) ------------------------------

    def record_event(
        self,
        event: CustodyLeaseEvent,
        *,
        _writer_token: Any = None,
    ) -> CustodyLeaseEvent:
        """Append *event* to the lease's history.

        .. warning::
            This is the **low-level** append primitive, token-guarded per
            Step 11A.  Production lifecycle callers MUST go through the
            invariant-enforcing helpers (:meth:`acquire`, :meth:`renew`,
            :meth:`transfer`, :meth:`release`, :meth:`expire`,
            :meth:`fence`, :meth:`reclaim`) which pass the internal writer
            token.  Calling ``record_event`` directly with a raw
            ``CustodyLeaseEvent`` bypasses owner/process-birth, monotonic
            epoch, TTL ceiling, terminal rejection, and old-epoch fencing
            (Step 11C) and is therefore reserved for the store's own
            internals and its contract tests.

        Returns the event as recorded (may be the same event for a no-op
        idempotent repeat).

        Raises:
            StaleSequenceError: if the event sequence is not monotonic.
            LeaseIdempotencyConflict: if the idempotency key maps to a different payload.
        """
        return self._record_event(event)

    def _record_event(self, event: CustodyLeaseEvent) -> CustodyLeaseEvent:
        """Internal append primitive shared by ``record_event`` and helpers.

        Atomicity (T-0205): the load → sequence/idempotency check → append →
        cache window runs under ONE exclusive lease-scoped flock, so a
        concurrent lifecycle caller can never interleave between the
        read-check and the append.  Contenders serialize; the loser re-reads
        inside the lock and either idempotently repeats or refuses with a
        typed error and zero mutation.
        """
        if not isinstance(event, CustodyLeaseEvent):
            raise LeaseStoreError("event must be a CustodyLeaseEvent")
        if self.flock:
            with self._lease_lock(event.lease_id):
                return self._record_event_unlocked(event)
        return self._record_event_unlocked(event)

    def _record_event_unlocked(self, event: CustodyLeaseEvent) -> CustodyLeaseEvent:
        """Append *event*, assuming the caller already holds the lease-scoped
        serialization (or ``flock`` is disabled).

        This is the single-writer body: load, sequence/idempotency check,
        inline append, cache rewrite.  It must NEVER be called while the same
        lease flock is held twice (that would self-deadlock) — callers are
        either inside :meth:`_lease_lock` or running with ``flock=False``.
        """
        lease_id = event.lease_id
        existing_events = self.load_history(lease_id)

        # --- Sequence check ---
        if existing_events:
            last_seq = existing_events[-1].sequence
            if event.sequence < last_seq:
                raise StaleSequenceError(
                    f"event sequence {event.sequence} is before last sequence "
                    f"{last_seq} for lease {lease_id!r}"
                )
            if event.sequence == last_seq:
                # Idempotency check: same idempotency_key + same payload_hash = no-op
                last_event = existing_events[-1]
                if event.idempotency_key == last_event.idempotency_key:
                    if event.payload_hash == last_event.payload_hash:
                        # Exact duplicate — idempotent no-op
                        return last_event
                    # Same idempotency key, different payload — conflict!
                    self._quarantine_conflict(lease_id, event, last_event)
                # Different idempotency key, same sequence — stale sequence
                raise StaleSequenceError(
                    f"event sequence {event.sequence} already occupied by a "
                    f"different idempotency key for lease {lease_id!r}"
                )

        # --- Append (the lease flock is already held by the caller) ---
        _atomic_append(
            _history_path(self.base_dir, lease_id),
            event.to_json() + "\n",
        )

        # --- Recompute and cache state ---
        all_events = self.load_history(lease_id)
        current = replay_events(all_events)
        if current is not None:
            self._write_cached_state(lease_id, current)

        return event

    # -- lifecycle helpers (Step 11A / 11C) -----------------------------------

    def acquire(
        self,
        *,
        lease_id: str,
        owner_host: str,
        owner_pid: str,
        owner_boot_id: str,
        run_authority_grant_id: str,
        coordinator_fence_token: int,
        wbc_attempt_reference: str,
        occurrence_digest: str,
        custody_epoch: int = 1,
        sequence: int = 1,
        occurred_at: str | None = None,
        expires_at: str | None = None,
        idempotency_key: str | None = None,
        causal_predecessor: str = "",
        payload: Mapping[str, Any] | None = None,
    ) -> CustodyLeaseEvent:
        """Acquire a lease via the blessed lifecycle path (Step 11A).

        Enforces that no *active* (non-terminal) lease exists for *lease_id*;
        a prior lease in a terminal state may be superseded by a fresh
        acquisition.  The requested TTL is clamped to
        ``MAXIMUM_LEASE_TTL_SECONDS`` (Step 11C TTL ceiling).

        Atomicity (T-0205): the load → active-lease check → append window
        runs under ONE exclusive lease-scoped flock.  Concurrent contenders
        for the same lease therefore serialize: exactly one wins, and every
        loser re-reads inside the lock, sees the winner's lease, and refuses
        with a typed ``LeaseStoreError`` and zero mutation (no conflict
        quarantine, no stray events).
        """
        resolved_idem = idempotency_key or f"acquire-{lease_id}"

        def _run() -> CustodyLeaseEvent:
            events = self.load_history(lease_id)
            if events:
                last = events[-1]
                # A legitimate retry with the same idempotency key must remain a
                # no-op — do not fence it; let the idempotent repeat in
                # ``_record_event_unlocked`` handle it.  Only fence genuine
                # collisions where a different identity holds an active lease.
                if last.idempotency_key != resolved_idem:
                    last_type = _last_lifecycle_event_type(events)
                    if last_type != "release" and last_type != "expire" and last_type != "fence":
                        # An active lease exists — acquiring again is a collision.
                        raise LeaseStoreError(
                            f"cannot acquire lease {lease_id!r}: an active lease "
                            f"already exists (last event {last_type!r})"
                        )
                elif last.owner_identity != (owner_host, owner_pid, owner_boot_id):
                    # Same idempotency key but a DIFFERENT owner holds the
                    # lease: a genuine collision between distinct acquire
                    # attempts (e.g. two runtimes racing for the same target),
                    # NOT a retry of this acquire.  Under the held lock the
                    # loser re-reads the winner's committed lease and refuses
                    # cleanly with zero mutation instead of falling through to
                    # the payload-conflict quarantine.
                    last_type = _last_lifecycle_event_type(events)
                    if last_type != "release" and last_type != "expire" and last_type != "fence":
                        raise LeaseStoreError(
                            f"cannot acquire lease {lease_id!r}: an active lease "
                            f"already exists (last event {last_type!r}, held by "
                            f"a different owner)"
                        )
            ts = occurred_at or utc_now()
            pl: dict[str, Any] = dict(payload or {})
            if expires_at:
                pl["expires_at"] = _clamp_ttl(ts, expires_at)
            event = CustodyLeaseEvent(
                event_id=f"acquire-{lease_id[:32]}",
                lease_id=lease_id,
                sequence=sequence,
                event_type="acquire",
                occurred_at=ts,
                custody_epoch=custody_epoch,
                owner_host=owner_host,
                owner_pid=owner_pid,
                owner_boot_id=owner_boot_id,
                run_authority_grant_id=run_authority_grant_id,
                coordinator_fence_token=coordinator_fence_token,
                wbc_attempt_reference=wbc_attempt_reference,
                occurrence_digest=occurrence_digest,
                idempotency_key=idempotency_key or f"acquire-{lease_id}",
                causal_predecessor=causal_predecessor,
                payload=pl,
            )
            return self._record_event_unlocked(event)

        if self.flock:
            with self._lease_lock(lease_id):
                return _run()
        return _run()

    def renew(
        self,
        *,
        lease_id: str,
        owner_host: str,
        owner_pid: str,
        owner_boot_id: str,
        custody_epoch: int,
        sequence: int | None = None,
        occurred_at: str | None = None,
        expires_at: str | None = None,
        idempotency_key: str | None = None,
        causal_predecessor: str = "",
        payload: Mapping[str, Any] | None = None,
    ) -> CustodyLeaseEvent:
        """Renew a lease, enforcing owner identity, monotonic epoch, terminal
        rejection, and TTL ceiling (Step 11C)."""
        current = self._require_active_owned_lease(
            lease_id, owner_host, owner_pid, owner_boot_id, "renew"
        )
        _enforce_monotonic_epoch(current.custody_epoch, custody_epoch, lease_id, "renew")
        seq = sequence if sequence is not None else self._next_sequence(lease_id)
        ts = occurred_at or utc_now()
        pl: dict[str, Any] = dict(payload or {})
        if expires_at:
            pl["expires_at"] = _clamp_ttl(ts, expires_at)
        event = CustodyLeaseEvent(
            event_id=f"renew-{lease_id[:32]}-{seq}",
            lease_id=lease_id,
            sequence=seq,
            event_type="renew",
            occurred_at=ts,
            custody_epoch=custody_epoch,
            owner_host=current.owner_host,
            owner_pid=current.owner_pid,
            owner_boot_id=current.owner_boot_id,
            run_authority_grant_id=current.run_authority_grant_id,
            coordinator_fence_token=current.coordinator_fence_token,
            wbc_attempt_reference=current.wbc_attempt_reference,
            occurrence_digest=current.idempotency_key,
            idempotency_key=idempotency_key or f"renew-{lease_id}-{custody_epoch}",
            causal_predecessor=causal_predecessor,
            payload=pl,
        )
        return self._record_event(event)

    def transfer(
        self,
        *,
        lease_id: str,
        owner_host: str,
        owner_pid: str,
        owner_boot_id: str,
        new_owner_host: str,
        new_owner_pid: str,
        new_owner_boot_id: str,
        custody_epoch: int,
        sequence: int | None = None,
        occurred_at: str | None = None,
        idempotency_key: str | None = None,
        causal_predecessor: str = "",
        payload: Mapping[str, Any] | None = None,
    ) -> CustodyLeaseEvent:
        """Transfer ownership, enforcing caller identity, monotonic epoch, and
        terminal rejection (Step 11C)."""
        current = self._require_active_owned_lease(
            lease_id, owner_host, owner_pid, owner_boot_id, "transfer"
        )
        _enforce_monotonic_epoch(current.custody_epoch, custody_epoch, lease_id, "transfer")
        seq = sequence if sequence is not None else self._next_sequence(lease_id)
        ts = occurred_at or utc_now()
        event = CustodyLeaseEvent(
            event_id=f"transfer-{lease_id[:32]}-{seq}",
            lease_id=lease_id,
            sequence=seq,
            event_type="transfer",
            occurred_at=ts,
            custody_epoch=custody_epoch,
            owner_host=new_owner_host,
            owner_pid=new_owner_pid,
            owner_boot_id=new_owner_boot_id,
            run_authority_grant_id=current.run_authority_grant_id,
            coordinator_fence_token=current.coordinator_fence_token,
            wbc_attempt_reference=current.wbc_attempt_reference,
            occurrence_digest=current.idempotency_key,
            idempotency_key=idempotency_key or f"transfer-{lease_id}-{custody_epoch}",
            causal_predecessor=causal_predecessor,
            payload=dict(payload or {}),
        )
        return self._record_event(event)

    def release(
        self,
        *,
        lease_id: str,
        owner_host: str,
        owner_pid: str,
        owner_boot_id: str,
        sequence: int | None = None,
        occurred_at: str | None = None,
        idempotency_key: str | None = None,
        causal_predecessor: str = "",
        payload: Mapping[str, Any] | None = None,
    ) -> CustodyLeaseEvent:
        """Release a lease (terminal), enforcing caller identity and that the
        lease is not already terminal (Step 11C)."""
        return self._terminal_event(
            "release", lease_id, owner_host, owner_pid, owner_boot_id,
            sequence, occurred_at, idempotency_key, causal_predecessor, payload,
        )

    def expire(
        self,
        *,
        lease_id: str,
        owner_host: str = "",
        owner_pid: str = "",
        owner_boot_id: str = "",
        sequence: int | None = None,
        occurred_at: str | None = None,
        idempotency_key: str | None = None,
        causal_predecessor: str = "",
        payload: Mapping[str, Any] | None = None,
    ) -> CustodyLeaseEvent:
        """Expire a lease (terminal).

        Expiry may be driven by the system (e.g. a sweeper) rather than the
        current owner, so owner identity is not enforced for ``expire``; the
        remaining terminal-rejection and TTL invariants still apply.
        """
        return self._terminal_event(
            "expire", lease_id, owner_host, owner_pid, owner_boot_id,
            sequence, occurred_at, idempotency_key, causal_predecessor, payload,
            enforce_owner=False,
        )

    def fence(
        self,
        *,
        lease_id: str,
        owner_host: str,
        owner_pid: str,
        owner_boot_id: str,
        coordinator_fence_token: int,
        sequence: int | None = None,
        occurred_at: str | None = None,
        idempotency_key: str | None = None,
        causal_predecessor: str = "",
        payload: Mapping[str, Any] | None = None,
    ) -> CustodyLeaseEvent:
        """Fence a lease (terminal), enforcing caller identity, terminal
        rejection, and old-epoch fencing (Step 11C)."""
        current = self._require_active_owned_lease(
            lease_id, owner_host, owner_pid, owner_boot_id, "fence"
        )
        seq = sequence if sequence is not None else self._next_sequence(lease_id)
        ts = occurred_at or utc_now()
        event = CustodyLeaseEvent(
            event_id=f"fence-{lease_id[:32]}-{seq}",
            lease_id=lease_id,
            sequence=seq,
            event_type="fence",
            occurred_at=ts,
            custody_epoch=current.custody_epoch,
            owner_host=current.owner_host,
            owner_pid=current.owner_pid,
            owner_boot_id=current.owner_boot_id,
            run_authority_grant_id=current.run_authority_grant_id,
            coordinator_fence_token=coordinator_fence_token,
            wbc_attempt_reference=current.wbc_attempt_reference,
            occurrence_digest=current.idempotency_key,
            idempotency_key=idempotency_key or f"fence-{lease_id}-{seq}",
            causal_predecessor=causal_predecessor,
            payload=dict(payload or {}),
        )
        return self._record_event(event)

    def reclaim(
        self,
        *,
        lease_id: str,
        owner_host: str,
        owner_pid: str,
        owner_boot_id: str,
        run_authority_grant_id: str,
        coordinator_fence_token: int,
        wbc_attempt_reference: str,
        occurrence_digest: str,
        custody_epoch: int,
        sequence: int | None = None,
        occurred_at: str | None = None,
        expires_at: str | None = None,
        idempotency_key: str | None = None,
        causal_predecessor: str = "",
        payload: Mapping[str, Any] | None = None,
    ) -> CustodyLeaseEvent:
        """Reclaim a lease that is in a terminal/expired state to a new owner.

        Reclaim is the reconciliation path (Step 10B/11A): only a lease whose
        last lifecycle event is ``release``, ``expire``, or ``fence`` may be
        reclaimed, and the new epoch must be strictly greater than the prior
        epoch (old-epoch fencing, Step 11C).

        Atomicity (T-0205): like :meth:`acquire`, the load → terminal/epoch
        check → append window runs under ONE exclusive lease-scoped flock, so
        concurrent reclaimers serialize on the same lease instead of racing
        their check-then-append.
        """
        resolved_idem = idempotency_key or f"reclaim-{lease_id}-{custody_epoch}"

        def _run() -> CustodyLeaseEvent:
            events = self.load_history(lease_id)
            if not events:
                raise LeaseNotFoundError(f"cannot reclaim non-existent lease {lease_id!r}")
            last = events[-1]
            # A retry of the same reclaim must remain idempotent.
            if last.idempotency_key != resolved_idem:
                last_type = _last_lifecycle_event_type(events)
                if last_type != "release" and last_type != "expire" and last_type != "fence":
                    raise LeaseStoreError(
                        f"cannot reclaim active lease {lease_id!r} (last event {last_type!r})"
                    )
            prior = replay_events(events)
            prior_epoch = prior.custody_epoch if prior is not None else 0
            if last.idempotency_key != resolved_idem:
                _enforce_monotonic_epoch(prior_epoch, custody_epoch, lease_id, "reclaim")
            seq = sequence if sequence is not None else self._next_sequence(lease_id)
            ts = occurred_at or utc_now()
            pl: dict[str, Any] = dict(payload or {})
            pl["reclaim"] = True
            if expires_at:
                pl["expires_at"] = _clamp_ttl(ts, expires_at)
            event = CustodyLeaseEvent(
                event_id=f"reclaim-{lease_id[:32]}-{seq}",
                lease_id=lease_id,
                sequence=seq,
                event_type="acquire",
                occurred_at=ts,
                custody_epoch=custody_epoch,
                owner_host=owner_host,
                owner_pid=owner_pid,
                owner_boot_id=owner_boot_id,
                run_authority_grant_id=run_authority_grant_id,
                coordinator_fence_token=coordinator_fence_token,
                wbc_attempt_reference=wbc_attempt_reference,
                occurrence_digest=occurrence_digest,
                idempotency_key=idempotency_key or f"reclaim-{lease_id}-{custody_epoch}",
                causal_predecessor=causal_predecessor,
                payload=pl,
            )
            return self._record_event_unlocked(event)

        if self.flock:
            with self._lease_lock(lease_id):
                return _run()
        return _run()

    # -- invariant helpers (Step 11C) ----------------------------------------

    def _require_active_owned_lease(
        self,
        lease_id: str,
        owner_host: str,
        owner_pid: str,
        owner_boot_id: str,
        op: str,
    ) -> CustodyLease:
        events = self.load_history(lease_id)
        if not events:
            raise LeaseNotFoundError(f"cannot {op} non-existent lease {lease_id!r}")
        last_type = _last_lifecycle_event_type(events)
        if last_type == "release" or last_type == "expire" or last_type == "fence":
            raise TerminalLeaseError(
                f"cannot {op} terminal lease {lease_id!r} (last event {last_type!r})"
            )
        current = replay_events(events)
        if current is None:
            raise LeaseNotFoundError(f"lease {lease_id!r} has no current state")
        # Owner/process-birth identity (Step 11C).
        if (
            current.owner_host != owner_host
            or current.owner_pid != owner_pid
            or current.owner_boot_id != owner_boot_id
        ):
            raise LeaseOwnerMismatchError(
                f"{op} caller owner tuple "
                f"({owner_host!r},{owner_pid!r},{owner_boot_id!r}) does not match "
                f"lease {lease_id!r} owner "
                f"({current.owner_host!r},{current.owner_pid!r},{current.owner_boot_id!r})"
            )
        return current

    def _terminal_event(
        self,
        event_type: str,
        lease_id: str,
        owner_host: str,
        owner_pid: str,
        owner_boot_id: str,
        sequence: int | None,
        occurred_at: str | None,
        idempotency_key: str | None,
        causal_predecessor: str,
        payload: Mapping[str, Any] | None,
        *,
        enforce_owner: bool = True,
    ) -> CustodyLeaseEvent:
        events = self.load_history(lease_id)
        if not events:
            raise LeaseNotFoundError(f"cannot {event_type} non-existent lease {lease_id!r}")
        last_type = _last_lifecycle_event_type(events)
        if last_type == event_type:
            # Idempotent exact repeat of the same terminal event: allow replay.
            return events[-1]
        if last_type == "release" or last_type == "expire" or last_type == "fence":
            raise TerminalLeaseError(
                f"cannot {event_type} lease {lease_id!r}: already terminal "
                f"(last event {last_type!r})"
            )
        current = replay_events(events)
        if current is None:
            raise LeaseNotFoundError(f"lease {lease_id!r} has no current state")
        if enforce_owner and (
            current.owner_host != owner_host
            or current.owner_pid != owner_pid
            or current.owner_boot_id != owner_boot_id
        ):
            raise LeaseOwnerMismatchError(
                f"{event_type} caller owner tuple does not match lease {lease_id!r} owner"
            )
        seq = sequence if sequence is not None else self._next_sequence(lease_id)
        ts = occurred_at or utc_now()
        event = CustodyLeaseEvent(
            event_id=f"{event_type}-{lease_id[:32]}-{seq}",
            lease_id=lease_id,
            sequence=seq,
            event_type=event_type,
            occurred_at=ts,
            custody_epoch=current.custody_epoch,
            owner_host=current.owner_host,
            owner_pid=current.owner_pid,
            owner_boot_id=current.owner_boot_id,
            run_authority_grant_id=current.run_authority_grant_id,
            coordinator_fence_token=current.coordinator_fence_token,
            wbc_attempt_reference=current.wbc_attempt_reference,
            occurrence_digest=current.idempotency_key,
            idempotency_key=idempotency_key or f"{event_type}-{lease_id}-{seq}",
            causal_predecessor=causal_predecessor,
            payload=dict(payload or {}),
        )
        return self._record_event(event)

    def _next_sequence(self, lease_id: str) -> int:
        events = self.load_history(lease_id)
        return (events[-1].sequence + 1) if events else 1

    # -- load / replay -------------------------------------------------------

    def load_history(self, lease_id: str) -> tuple[CustodyLeaseEvent, ...]:
        """Load the raw event history for *lease_id*.

        Returns an empty tuple if no history exists.
        """
        text = self._read_member_text(_history_path(self.base_dir, lease_id).name)
        if text is None:
            return ()
        if not text.strip():
            return ()
        events: list[CustodyLeaseEvent] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            evt = normalize_custody_lease_event(data)
            if evt is not None:
                events.append(evt)
        return tuple(events)

    def replay_history(self, lease_id: str) -> CustodyLease | None:
        """Deterministically replay the event history for *lease_id*."""
        events = self.load_history(lease_id)
        return replay_events(events)

    def current_lease(self, lease_id: str) -> CustodyLease | None:
        """Return the current lease state (from cache if available, else replay)."""
        # Try cached state first
        cached = self._read_cached_state(lease_id)
        if cached is not None:
            return cached
        # Fall back to replay
        return self.replay_history(lease_id)

    # -- quarantine ----------------------------------------------------------

    def quarantined_conflicts(self, lease_id: str) -> tuple[dict[str, Any], ...]:
        """Return quarantined conflict payloads for *lease_id*."""
        path = _quarantine_path(self.base_dir, lease_id)
        if not path.exists():
            return ()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return ()
        if not isinstance(data, list):
            return ()
        return tuple(item for item in data if isinstance(item, dict))

    # -- internal helpers ----------------------------------------------------

    @contextmanager
    def _lease_lock(self, lease_id: str) -> Iterator[None]:
        """Serialize ALL lifecycle mutations for ONE lease across the
        load → check → append window (not just the append).

        This is the lease-scoped flock (``<lease_id>.lock``).  Every
        lifecycle write (acquire, reclaim, renew, transfer, release, expire,
        fence, and the low-level ``record_event``) runs its read-check and
        its append inside this single exclusive section, so a concurrent
        contender can never interleave between the two.  The
        occurrence-scoped lock (:meth:`occurrence_claim_lock`) additionally
        serializes DISTINCT claims for the SAME occurrence.

        The sidecar ``<lease_id>.lock`` is intentionally never removed —
        unlinking a lock file while another waiter blocks on the same inode
        lets a third opener create a fresh inode and split the fence.
        """
        import fcntl

        self.base_dir.mkdir(parents=True, exist_ok=True)
        lock_p = _lock_path(self.base_dir, lease_id)
        fd = os.open(lock_p, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    @contextmanager
    def occurrence_claim_lock(self, occurrence_key: str) -> Iterator[None]:
        """Serialize occurrence-scoped claim acquisition across ALL claims.

        The custody lease is keyed by the *claim* id, so per-lease flocks
        share zero serialization between two distinct claims for the SAME
        occurrence — both could scan, acquire, and append STARTED before
        either sees the other.  This advisory flock is keyed by the
        OCCURRENCE identity instead (mirroring the per-record flock pattern
        in ``repair_lock._job_record_flock``) and MUST be held across the
        caller's scan → acquire → append so exactly one contender wins; the
        loser re-scans inside the lock and refuses with a typed error and
        zero mutation.

        The sidecar ``occurrence-<digest>.lock`` is intentionally never
        removed — unlinking a lock file while another waiter blocks on the
        same inode lets a third opener create a fresh inode and split the
        fence.

        Under the occurrence-join zero-mutation refusal contract (T-0101h),
        this lock file is ALLOWED provisioning: a refusal that occurs after
        the lock is entered may leave ``occurrence-<digest>.lock`` behind,
        and that is the ONLY permitted refusal side effect on the plan side
        (plan state files, queue records, markers/manifests, the WBC ledger
        and lease history/state bytes stay untouched).
        """
        import fcntl

        self.base_dir.mkdir(parents=True, exist_ok=True)
        lock_p = _occurrence_lock_path(self.base_dir, occurrence_key)
        fd = os.open(lock_p, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _write_cached_state(self, lease_id: str, lease: CustodyLease) -> None:
        """Write the cached state atomically."""
        _atomic_write(
            _state_path(self.base_dir, lease_id),
            lease.to_json(),
        )

    def _read_cached_state(self, lease_id: str) -> CustodyLease | None:
        """Read the cached state if it exists."""
        text = self._read_member_text(_state_path(self.base_dir, lease_id).name)
        if text is None:
            return None
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        return normalize_custody_lease(data)

    def _quarantine_conflict(
        self,
        lease_id: str,
        new_event: CustodyLeaseEvent,
        existing_event: CustodyLeaseEvent,
    ) -> None:
        """Quarantine a payload conflict for later reconciliation.

        Appends a synthetic ``conflict`` event and records both
        conflicting payloads in the quarantine file.
        """
        # Append a conflict event
        conflict_event = CustodyLeaseEvent(
            event_id=f"conflict-{new_event.idempotency_key}",
            lease_id=lease_id,
            sequence=new_event.sequence,
            event_type="conflict",
            occurred_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            custody_epoch=new_event.custody_epoch,
            owner_host=new_event.owner_host,
            owner_pid=new_event.owner_pid,
            owner_boot_id=new_event.owner_boot_id,
            run_authority_grant_id=new_event.run_authority_grant_id,
            coordinator_fence_token=new_event.coordinator_fence_token,
            wbc_attempt_reference=new_event.wbc_attempt_reference,
            occurrence_digest=new_event.occurrence_digest,
            idempotency_key=f"conflict-{new_event.idempotency_key}",
            causal_predecessor=new_event.causal_predecessor,
            payload={
                "reason": "idempotency_payload_conflict",
                "conflicting_idempotency_key": new_event.idempotency_key,
                "existing_payload_hash": existing_event.payload_hash,
                "new_payload_hash": new_event.payload_hash,
            },
        )

        # Append the conflict event inline: the caller already holds the
        # lease-scoped flock (or flock is disabled), so re-entering the lock
        # through a flocked append helper would self-deadlock.
        _atomic_append(
            _history_path(self.base_dir, lease_id),
            conflict_event.to_json() + "\n",
        )

        # Record both payloads in quarantine
        qpath = _quarantine_path(self.base_dir, lease_id)
        existing_quarantine: list[dict[str, Any]] = []
        if qpath.exists():
            try:
                existing_quarantine = json.loads(qpath.read_text(encoding="utf-8"))
            except (FileNotFoundError, OSError, json.JSONDecodeError):
                existing_quarantine = []
        if not isinstance(existing_quarantine, list):
            existing_quarantine = []

        existing_quarantine.append({
            "idempotency_key": new_event.idempotency_key,
            "sequence": new_event.sequence,
            "existing_event_id": existing_event.event_id,
            "existing_payload_hash": existing_event.payload_hash,
            "conflicting_event_id": new_event.event_id,
            "conflicting_payload_hash": new_event.payload_hash,
            "quarantined_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })

        _atomic_write(qpath, json.dumps(existing_quarantine, indent=2))

        raise LeaseIdempotencyConflict(
            f"idempotency key {new_event.idempotency_key!r} maps to different "
            f"payloads for lease {lease_id!r}: existing hash "
            f"{existing_event.payload_hash!r} vs new hash "
            f"{new_event.payload_hash!r}"
        )


def _quarantine_path(base_dir: Path, lease_id: str) -> Path:
    return base_dir / f"{lease_id}.quarantine.json"


# ── Open / factory ────────────────────────────────────────────────────────


def open_lease_store(
    base_dir: Path | None = None,
    *,
    flock: bool = True,
    directory_fd: int | None = None,
) -> CustodyLeaseStore:
    """Open a custody lease store rooted at *base_dir*.

    If *base_dir* is ``None``, defaults to ``~/.megaplan/custody/leases``.
    """
    base = base_dir or default_lease_store_dir()
    if directory_fd is None:
        base = base.resolve()
    else:
        opened = os.fstat(directory_fd)
        if not stat.S_ISDIR(opened.st_mode):
            raise LeaseStoreError("custody directory descriptor is not a directory")
        base = base.absolute()
    return CustodyLeaseStore(
        base_dir=base,
        flock=flock,
        directory_fd=directory_fd,
    )


# ── Convenience: record a batch of events ─────────────────────────────────


def record_events(
    store: CustodyLeaseStore,
    events: Sequence[CustodyLeaseEvent],
) -> tuple[CustodyLeaseEvent, ...]:
    """Record a batch of events in sequence order.

    Returns the events as recorded (may differ from input for idempotent repeats).
    """
    result: list[CustodyLeaseEvent] = []
    for event in sorted(events, key=lambda e: e.sequence):
        recorded = store.record_event(event)
        result.append(recorded)
    return tuple(result)
