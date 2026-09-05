"""Incident ledger append wrapper for the canonical M1 event stream."""

from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
import argparse
import fcntl
import hashlib
import json
import os
import sys
import uuid
from typing import Any, Callable, Mapping

from arnold.runtime.event_journal import NdjsonEventJournal

from arnold_pipelines.megaplan.incident.schema import (
    lifecycle_idempotency_key,
    validate_incident_event,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_id(*parts: str) -> str:
    return hashlib.sha256(json.dumps(parts, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _valid_nbf(validator: Callable[[dict[str, Any]], dict[str, Any]], payload: dict[str, Any]) -> bool:
    try:
        validator(payload)
    except (TypeError, ValueError):
        return False
    return True


def reservation_key(projection_key: str, semantic_dispatch_fingerprint: str) -> str:
    if not isinstance(projection_key, str) or not projection_key or not isinstance(semantic_dispatch_fingerprint, str) or not semantic_dispatch_fingerprint:
        raise ValueError("reservation key requires projection key and semantic fingerprint")
    return _stable_id("reservation", projection_key, semantic_dispatch_fingerprint)


def derive_receipt_id(**kwargs: Any) -> str:
    from arnold_pipelines.megaplan.incident.schema import receipt_id
    return receipt_id(**kwargs)

_INCIDENT_LEDGER_DIR = Path(".megaplan") / "incident-ledger"
_EVENTS_FILE = "events.jsonl"


# ---------------------------------------------------------------------------
# P2 — typed runtime transition events
# ---------------------------------------------------------------------------
# One typed deviation/fallback event path. Every runtime manifest selection,
# declared deviation, and fallback consideration/decision is appended to the
# incident ledger BEFORE the caller performs any dispatch side effect. The
# append is synchronous and never swallowed: a policy rejection (ValueError)
# or a journal write failure (OSError) propagates to the caller, which MUST
# treat it as "do not dispatch". Emitting is a pure append-only ledger write
# — it never dispatches repair and never triggers a scan.

EVENT_MANIFEST_SELECTED = "runtime.manifest_selected"
EVENT_DEVIATION_DECLARED = "runtime.deviation_declared"
EVENT_FALLBACK_CONSIDERED = "runtime.fallback_considered"
EVENT_FALLBACK_TAKEN = "runtime.fallback_taken"
EVENT_FALLBACK_REJECTED = "runtime.fallback_rejected"

RUNTIME_TRANSITION_EVENT_TYPES: tuple[str, ...] = (
    EVENT_MANIFEST_SELECTED,
    EVENT_DEVIATION_DECLARED,
    EVENT_FALLBACK_CONSIDERED,
    EVENT_FALLBACK_TAKEN,
    EVENT_FALLBACK_REJECTED,
)

# Failure-class policy: a fallback may be TAKEN only for retryable
# availability/infrastructure failures. Auth/config, semantic, schema, test,
# evidence, and post-mutation execute failures are permanent deviations —
# they must be recorded as REJECTED, never masked behind a fallback.
RETRYABLE_FAILURE_CLASSES: frozenset[str] = frozenset(
    {"availability", "infrastructure"}
)
NON_RETRYABLE_FAILURE_CLASSES: frozenset[str] = frozenset(
    {"auth", "config", "semantic", "schema", "test", "evidence", "execute"}
)
KNOWN_FAILURE_CLASSES: frozenset[str] = (
    RETRYABLE_FAILURE_CLASSES | NON_RETRYABLE_FAILURE_CLASSES
)

_EVENT_ID_PREFIXES: dict[str, str] = {
    EVENT_MANIFEST_SELECTED: "runtime-manifest-selected",
    EVENT_DEVIATION_DECLARED: "runtime-deviation-declared",
    EVENT_FALLBACK_CONSIDERED: "runtime-fallback-considered",
    EVENT_FALLBACK_TAKEN: "runtime-fallback-taken",
    EVENT_FALLBACK_REJECTED: "runtime-fallback-rejected",
}

_DEFAULT_OUTCOMES: dict[str, str] = {
    EVENT_MANIFEST_SELECTED: "selected",
    EVENT_DEVIATION_DECLARED: "declared",
    EVENT_FALLBACK_CONSIDERED: "considered",
    EVENT_FALLBACK_TAKEN: "taken",
    EVENT_FALLBACK_REJECTED: "rejected",
}

_DEFAULT_SUMMARIES: dict[str, str] = {
    EVENT_MANIFEST_SELECTED: "runtime manifest selected",
    EVENT_DEVIATION_DECLARED: "runtime deviation declared",
    EVENT_FALLBACK_CONSIDERED: "runtime fallback considered",
    EVENT_FALLBACK_TAKEN: "runtime fallback taken",
    EVENT_FALLBACK_REJECTED: "runtime fallback rejected",
}


def is_retryable_failure_class(failure_class: str | None) -> bool:
    """True iff *failure_class* is a retryable availability/infrastructure class."""
    return failure_class in RETRYABLE_FAILURE_CLASSES


def _normalize_chain_digest(digest: str) -> str:
    """Normalize a ``chain_spec_sha256`` contract digest, or ``\"\"`` when empty."""
    digest = str(digest).strip()
    if not digest:
        return ""
    if digest.startswith("sha256:"):
        hex_part = digest[len("sha256:") :]
        if len(hex_part) != 64 or any(
            char not in "0123456789abcdefABCDEF" for char in hex_part
        ):
            raise ValueError(
                "chain_spec_sha256 must be 'sha256:' followed by 64 hex chars "
                f"(got {digest!r})"
            )
        return "sha256:" + hex_part.lower()
    return digest


# ---------------------------------------------------------------------------
# M3 — lifecycle idempotency across the journal boundary (T4)
# ---------------------------------------------------------------------------
# The strict Maintenance journal compares the canonical lifecycle idempotency
# key recorded at the append boundary (:func:`lifecycle_idempotency_key`):
# operational lifecycle rows (repair request, source change, installation,
# retrigger, progress, checkpoint, terminal, recurrence, escalation) compare
# their strict action key — so DISTINCT actions for ONE occurrence coexist —
# while legacy M2 rows (detection / efficiency_analysis / audit_report) fall
# back to ``occurrence_id`` and keep the exact historical behavior.  Exact
# retries deduplicate (same key + same canonical digest), divergent reuse
# raises :class:`MaintenanceEventConflict` without advancing the journal, and
# the atomic lookup → decide → append critical section is unchanged.


def strict_maintenance_model(payload: dict[str, Any]) -> Any:
    """Strict-decode *payload* as ``MaintenanceEvent`` or ``OperationalEvent``.

    Legacy M2 rows decode as :class:`MaintenanceEvent`; M3 operational
    lifecycle rows decode as :class:`OperationalEvent`.  A malformed payload
    raises ``MaintenanceCodecError`` — a model/digest is never derived from
    guessed values.
    """
    from arnold_pipelines.megaplan.maintenance.events import (
        MaintenanceEvent,
        OperationalEvent,
    )
    from arnold_pipelines.megaplan.maintenance.identity import (
        MaintenanceCodecError,
        strict_loads,
    )

    try:
        return strict_loads(MaintenanceEvent, payload)
    except MaintenanceCodecError:
        return strict_loads(OperationalEvent, payload)


def strict_maintenance_digest(payload: dict[str, Any]) -> str:
    """Return the canonical content digest of a strict Maintenance payload."""
    from arnold_pipelines.megaplan.maintenance.identity import canonical_digest

    return canonical_digest(strict_maintenance_model(payload))


def record_matches_lifecycle_key(stored: dict[str, Any], idempotency_key: str) -> bool:
    """Return whether a stored record's payload carries *idempotency_key*.

    The comparison uses the canonical lifecycle idempotency key recorded at
    the journal boundary (:func:`lifecycle_idempotency_key`): operational
    rows compare their strict action key, legacy rows fall back to
    ``occurrence_id``.  Records that cannot carry a lifecycle key (legacy
    non-Maintenance incident events) never match.
    """
    try:
        return lifecycle_idempotency_key(stored) == idempotency_key
    except ValueError:
        return False


class _IncidentEventJournal(NdjsonEventJournal):
    """Reuse runtime journal locking/seq semantics with the M1 filename."""

    def __init__(self, artifact_root: Path) -> None:
        super().__init__(artifact_root)
        self._ndjson_path = self._root / _EVENTS_FILE
        self._journal_lock_path = self._root / ".events.lock"
        self._ledger_owner: IncidentLedger | None = None

    def _active_generation_paths(self) -> tuple[Path, Path] | None:
        pointer = self._root / ".active-generation.json"
        if not pointer.exists():
            return None
        try:
            if pointer.is_symlink() or not pointer.is_file():
                raise RuntimeError("active incident-ledger generation pointer is not a regular file")
            body = json.loads(pointer.read_text(encoding="utf-8"))
            generation_id = body.get("generation_id") if isinstance(body, dict) else None
            if (
                not isinstance(generation_id, str)
                or not generation_id.startswith("seq-collision-")
                or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789-" for char in generation_id)
            ):
                raise RuntimeError("active incident-ledger generation pointer is malformed")
            generation = self._root / ".nbf08-generations" / generation_id
            events = generation / _EVENTS_FILE
            sidecar = generation / ".events.seq"
            manifest = generation / "manifest.json"
            if any(path.is_symlink() or not path.is_file() for path in (events, sidecar)):
                raise RuntimeError("active incident-ledger generation is incomplete")
            if (
                manifest.is_symlink()
                or not manifest.is_file()
                or hashlib.sha256(manifest.read_bytes()).hexdigest() != body.get("generation_manifest_sha256")
            ):
                raise RuntimeError("active incident-ledger generation manifest differs from its pointer")
            return events, sidecar
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("active incident-ledger generation pointer is unreadable") from exc

    def journal_path(self) -> Path:
        active = self._active_generation_paths()
        return active[0] if active is not None else self._ndjson_path

    def sequence_path(self) -> Path:
        active = self._active_generation_paths()
        return active[1] if active is not None else self._seq_path

    def open_journal_lock(self) -> int:
        return os.open(str(self._journal_lock_path), os.O_RDWR | os.O_CREAT, 0o644)

    def open_sequence_after_lock(self) -> int:
        path = self.sequence_path()
        flags = os.O_RDWR | (0 if self._active_generation_paths() is not None else os.O_CREAT)
        return os.open(str(path), flags, 0o644)

    def recover_structured_reservation_locked(self, seq_fd: int) -> dict[str, Any] | None:
        """Resolve a pending structured reservation before any new allocation."""
        from arnold_pipelines.megaplan.incident.chain_control import (
            ChainControlJournal,
            parse_sidecar_bytes,
            read_sidecar_locked,
        )

        kind, _parsed = parse_sidecar_bytes(read_sidecar_locked(seq_fd))
        if kind == "reservation":
            if self._ledger_owner is None:
                raise RuntimeError("incident journal is not bound to its ledger")
            return ChainControlJournal(self._ledger_owner).recover_reservations_locked(seq_fd)
        return None

    def emit(
        self,
        kind: str,
        *,
        payload: dict[str, Any] | None = None,
        scope: str | None = None,
        phase: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Route legacy incident appends through the same active-generation locks."""
        body = payload if payload is not None else {}
        key = idempotency_key or str(
            body.get("event_id") or body.get("occurrence_id") or _stable_id("incident", kind, json.dumps(body, sort_keys=True))
        )
        init_ts = self._load_init_ts()
        lock_fd = self.open_journal_lock()
        seq_fd: int | None = None
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            seq_fd = self.open_sequence_after_lock()
            fcntl.flock(seq_fd, fcntl.LOCK_EX)
            recovery = self.recover_structured_reservation_locked(seq_fd)
            from arnold_pipelines.megaplan.incident.chain_control import DurabilityUnknown

            for record in self._read_records():
                stored = record.get("payload") if isinstance(record.get("payload"), dict) else {}
                stored_key = record.get("idempotency_key") or stored.get("event_id") or stored.get("occurrence_id")
                if stored_key != key:
                    continue
                if record.get("kind") == kind and stored == body:
                    return record
                raise DurabilityUnknown(
                    "incident idempotency key has divergent durable content",
                    details={"idempotency_key": key, "recovery": recovery},
                )
            appended = self._emit_locked(
                seq_fd,
                kind=kind,
                payload=body,
                idempotency_key=key,
                init_ts=init_ts,
            )
        finally:
            if seq_fd is not None:
                try:
                    fcntl.flock(seq_fd, fcntl.LOCK_UN)
                finally:
                    os.close(seq_fd)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        if init_ts is None:
            self._write_init_ts(datetime.now(timezone.utc))
        return appended

    # ── Maintenance routing: atomic lookup/append keyed by occurrence ──────

    def _read_records(self) -> list[dict[str, Any]]:
        """Parse every committed record from ``events.jsonl`` (append order)."""
        ndjson_path = self.journal_path()
        if not ndjson_path.exists():
            return []
        records: list[dict[str, Any]] = []
        with open(ndjson_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return records

    def _emit_locked(
        self,
        seq_fd: int,
        *,
        kind: str,
        payload: dict[str, Any],
        idempotency_key: str,
        init_ts: datetime | None,
        nbf08_reservation: dict[str, Any] | None = None,
        allocated_seq: int | None = None,
    ) -> dict[str, Any]:
        """Append one record while the caller holds the seq-sidecar flock.

        Ordinary NBF-01 writers keep the integer ``.events.seq`` sidecar
        byte-for-byte. Chain-control / post-genesis writers persist a
        structured reservation before the JSON line so a crash in the
        seq-before-line gap becomes a tombstone rather than a silent hole.
        """
        from arnold_pipelines.megaplan.incident.chain_control import (
            DurabilityUnknown,
            empty_reservation,
            highest_complete_seq,
            ledger_id_for,
            migrate_integer_sidecar,
            parse_sidecar_bytes,
            physical_digest_after,
            read_physical_lines,
            read_sidecar_locked,
            canonical_committed_reservation,
            validate_reservation_tip,
            write_reservation_locked,
            write_sidecar_locked,
        )

        raw = read_sidecar_locked(seq_fd)
        sidecar_kind, parsed = parse_sidecar_bytes(raw)
        ndjson_path = self.journal_path()
        all_physical = read_physical_lines(ndjson_path)
        if any(item.torn for item in all_physical):
            raise DurabilityUnknown("journal has an unrecovered torn tail")
        physical = list(all_physical)
        highest = highest_complete_seq(physical)
        ledger_id = ledger_id_for(self._root)
        previous_digest = physical_digest_after(ledger_id, physical)

        use_reservation = nbf08_reservation is not None or sidecar_kind == "reservation"
        if use_reservation:
            reservation = nbf08_reservation
            if sidecar_kind == "integer":
                reservation = migrate_integer_sidecar(
                    raw=raw,
                    current=parsed,
                    highest_complete=highest,
                    ledger_id=ledger_id,
                    previous_physical_digest=previous_digest,
                )
                if reservation.get("status") == "committed":
                    reservation = canonical_committed_reservation(
                        reservation,
                        ledger_id=ledger_id,
                        physical=physical,
                    )
                write_reservation_locked(seq_fd, reservation)
            elif sidecar_kind == "empty":
                reservation = empty_reservation(
                    ledger_id=ledger_id,
                    physical_sequence=highest,
                    status="committed" if highest >= 0 else "committed",
                    previous_physical_digest=previous_digest,
                )
                write_reservation_locked(seq_fd, reservation)
            elif sidecar_kind == "reservation":
                reservation = parsed
            if reservation is None:
                raise DurabilityUnknown("structured append has no sequence reservation")
            reserved_recovery = reservation.get("status") == "reserved"
            if reserved_recovery:
                from arnold_pipelines.megaplan.incident.chain_control import validate_reservation_integrity

                validate_reservation_integrity(reservation, ledger_id=ledger_id)
                if (
                    reservation.get("physical_sequence") != highest + 1
                    or reservation.get("previous_physical_digest") != previous_digest
                    or allocated_seq != highest + 1
                ):
                    raise DurabilityUnknown("reserved sequence is stale or mismatched before recovery append")
            else:
                validate_reservation_tip(
                    reservation,
                    ledger_id=ledger_id,
                    physical=physical,
                )
            # One allocation only: the verified complete prefix owns N.  The
            # sidecar is checked recovery evidence and can never allocate a
            # competing outer sequence.
            new_seq = highest + 1
            if allocated_seq is not None and allocated_seq != new_seq:
                raise DurabilityUnknown(
                    "preallocated physical sequence disagrees with verified journal prefix",
                    details={"allocated": allocated_seq, "expected": new_seq},
                )
            if str(kind).startswith("chain_control."):
                if payload.get("physical_sequence") != new_seq:
                    raise DurabilityUnknown("chain-control envelope sequence disagrees with outer record")
                if payload.get("previous_physical_digest") != previous_digest:
                    raise DurabilityUnknown("chain-control envelope predecessor is stale")
            pending = (
                dict(reservation)
                if reserved_recovery
                else empty_reservation(
                    ledger_id=ledger_id,
                    physical_sequence=new_seq,
                    status="reserved",
                    previous_physical_digest=previous_digest,
                )
            )
            if not reserved_recovery and reservation.get("migration_receipt") is not None:
                pending["migration_receipt"] = reservation["migration_receipt"]
            pending["byte_offset"] = ndjson_path.stat().st_size if ndjson_path.exists() else 0
            pending["line_number"] = len(physical) + 1
            pending["scope"] = "chain_control" if str(kind).startswith("chain_control.") else "chainless"
            if str(kind).startswith("chain_control.") and isinstance(payload, dict):
                pending["chain_id"] = payload.get("chain_id")
                pending["event_id"] = payload.get("event_id")
                pending["event_kind"] = kind
                pending["operation_id"] = payload.get("operation_id")
                pending["causation_id"] = payload.get("causation_id")
                pending["correlation_id"] = payload.get("correlation_id")
                pending["recovery_id"] = payload.get("recovery_id") or "none"
                pending["evidence_sequence"] = payload.get("evidence_sequence")
                pending["semantic_sequence"] = payload.get("semantic_sequence")
        else:
            try:
                current = parsed if sidecar_kind == "integer" else (
                    int(raw.strip()) if raw.strip() else self._recover_durable_sequence()
                )
            except (TypeError, ValueError, FileNotFoundError):
                current = self._recover_durable_sequence()
            new_seq = current + 1
            write_sidecar_locked(seq_fd, str(new_seq).encode("ascii"))
            pending = None

        ts_utc = datetime.now(timezone.utc)
        event: dict[str, Any] = {
            "seq": new_seq,
            "schema_version": 1,
            "ts_utc": ts_utc.isoformat(),
            "ts_rel_init_s": (
                (ts_utc - init_ts).total_seconds() if init_ts is not None else None
            ),
            "kind": kind,
            "payload": payload,
            "idempotency_key": idempotency_key,
        }
        line = json.dumps(
            event,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        if pending is not None:
            # Authenticate the exact timestamped outer bytes before exposing
            # a reserved sidecar. Recovery may adopt only this exact line.
            pending["intended_record_sha256"] = hashlib.sha256(line.encode("utf-8")).hexdigest()
            write_reservation_locked(seq_fd, pending)
        with open(ndjson_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        if pending is not None:
            pending["status"] = "committed"
            pending["intended_record_sha256"] = hashlib.sha256(line.encode("utf-8")).hexdigest()
            write_reservation_locked(seq_fd, pending)
        return event

    def lookup_maintenance(self, idempotency_key: str) -> dict[str, Any] | None:
        """Return the committed record for *idempotency_key*, or ``None``.

        *idempotency_key* is the canonical lifecycle idempotency key recorded
        at the journal boundary (SD2 + M3 Step 2): the strict action key for
        operational lifecycle rows, with a legacy fallback to ``occurrence_id``
        for M2 detection / efficiency_analysis / audit_report rows.  Only
        records whose payload carries the exact lifecycle key are considered;
        other records (legacy non-Maintenance incident events) are skipped.
        """
        for record in self._read_records():
            stored = record.get("payload") or {}
            if record_matches_lifecycle_key(stored, idempotency_key):
                return record
        return None

    def append_maintenance(
        self,
        *,
        kind: str,
        payload: dict[str, Any],
        idempotency_key: str,
        digest: str,
    ) -> dict[str, Any]:
        """Atomically append one strict Maintenance payload with dedupe.

        Runs the full lookup → decide → append critical section under the
        journal's ``fcntl.flock`` on the seq sidecar, so concurrent writers
        cannot interleave between the duplicate check and the append.

        *idempotency_key* is the canonical lifecycle idempotency key of
        *payload* (strict action key for operational rows, ``occurrence_id``
        fallback for legacy M2 rows):

        * an exact duplicate (same lifecycle key AND same canonical digest)
          returns the PRIOR committed record — nothing is appended;
        * a divergent duplicate (same lifecycle key, different canonical
          digest) raises :class:`MaintenanceEventConflict` — nothing is
          appended;
        * otherwise the record is appended once and returned.

        Distinct lifecycle actions for one occurrence carry distinct action
        keys, so they append as separate records while exact retries of the
        same action deduplicate.
        """
        # Canonical validation up front: the payload must strict-decode (as a
        # MaintenanceEvent or an OperationalEvent) and its digest must be
        # reproducible from the canonical codec.
        strict_maintenance_digest(payload)

        init_ts = self._load_init_ts()
        lock_fd = self.open_journal_lock()
        seq_fd: int | None = None
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            seq_fd = self.open_sequence_after_lock()
            fcntl.flock(seq_fd, fcntl.LOCK_EX)
            self.recover_structured_reservation_locked(seq_fd)
            for record in self._read_records():
                stored = record.get("payload") or {}
                if not record_matches_lifecycle_key(stored, idempotency_key):
                    continue
                stored_digest = strict_maintenance_digest(stored)
                if stored_digest == digest:
                    return record
                raise MaintenanceEventConflict(
                    f"maintenance idempotency conflict for lifecycle key "
                    f"{idempotency_key!r}: stored digest {stored_digest} "
                    f"!= incoming digest {digest}; nothing appended"
                )
            appended = self._emit_locked(
                seq_fd,
                kind=kind,
                payload=payload,
                idempotency_key=idempotency_key,
                init_ts=init_ts,
            )
        finally:
            if seq_fd is not None:
                try:
                    fcntl.flock(seq_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                try:
                    os.close(seq_fd)
                except OSError:
                    pass
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        if init_ts is None:
            self._write_init_ts(datetime.now(timezone.utc))
        return appended


class MaintenanceEventConflict(ValueError):
    """Raised when a Maintenance event reuses an occurrence idempotency
    identity with a different canonical digest.

    The conflicting event is NOT appended; the ledger is left unchanged.
    """


class IncidentLedger:
    """Append-only incident ledger rooted at ``<root>/.megaplan/incident-ledger``."""

    def __init__(self, root: Path | None = None) -> None:
        self._root = Path.cwd() if root is None else Path(root)
        if self._root.exists() and not self._root.is_dir():
            raise ValueError("ledger root must be a directory")
        self._ledger_dir = self._root / _INCIDENT_LEDGER_DIR
        self._journal = _IncidentEventJournal(self._ledger_dir)
        self._journal._ledger_owner = self

    @property
    def ledger_dir(self) -> Path:
        return self._ledger_dir

    @property
    def events_path(self) -> Path:
        return self._journal.journal_path()

    # ── NBF single transaction authority ────────────────────────────────
    def read_nbf_events(self) -> list[dict[str, Any]]:
        """Return complete NBF records in append order.

        A physically torn JSON line is an uncommitted write and is ignored;
        valid JSON carrying an invalid NBF payload is corruption and fails
        closed.  Silently dropping the latter would turn forged history into
        an apparently healthy projection.
        """
        from arnold_pipelines.megaplan.incident.schema import validate_nbf_event
        valid = []
        for record in self._journal._read_records():
            payload = record.get("payload")
            if not (isinstance(payload, dict) and str(record.get("kind", "")).startswith("incident.nbf")):
                continue
            validate_nbf_event(payload, _allow_persisted_changed_precondition=True)
            valid.append(record)
        return valid

    def _nbf_event_id(self, payload: dict[str, Any]) -> str:
        event_id = payload.get("event_id") or payload.get("disposition_id") or payload.get("observation_id") or payload.get("reconciliation_id")
        if not isinstance(event_id, str) or not event_id:
            raise ValueError("NBF event requires a canonical event identity")
        return event_id

    def _append_nbf_locked(self, seq_fd: int, payload: dict[str, Any], records: list[dict[str, Any]], *, event_type: str | None = None, _changed_precondition: Any = None, _chain_control: dict[str, Any] | None = None) -> dict[str, Any]:
        """Validate and append with the caller's flock held.

        All compare/read/consume decisions must use ``records`` captured after
        acquiring the sequence-sidecar lock.  This is deliberately a small
        extension of the existing journal door, not a second transaction API.
        Chain-control envelopes share this door; they never open a second
        sequence, lock, or writer.
        """
        if _chain_control is not None or (
            isinstance(payload, dict) and str(payload.get("event_kind") or "").startswith("chain_control.")
        ):
            envelope = _chain_control or payload
            event_id = envelope.get("event_id")
            if not isinstance(event_id, str) or not event_id:
                raise ValueError("chain-control event requires event_id")
            for record in records:
                stored_payload = record.get("payload") or {}
                if stored_payload.get("event_id") == event_id and str(record.get("kind") or "").startswith("chain_control."):
                    if stored_payload == envelope:
                        return record
                    raise ValueError(f"conflicting chain-control event_id: {event_id}")
            return self._journal._emit_locked(
                seq_fd,
                kind=str(envelope.get("event_kind") or "chain_control.unknown"),
                payload=envelope,
                idempotency_key=event_id,
                init_ts=self._journal._load_init_ts(),
                nbf08_reservation={"schema_version": "nbf08-sequence-reservation-v1"},
                allocated_seq=int(envelope["physical_sequence"]),
            )
        from arnold_pipelines.megaplan.incident.schema import validate_nbf_event
        payload = validate_nbf_event(payload, _changed_precondition=_changed_precondition)
        event_id = self._nbf_event_id(payload)
        for record in records:
            stored_payload = record.get("payload") or {}
            if (payload.get("event_type") == "supervision_confirmation_consumed"
                    and stored_payload.get("event_type") == "supervision_confirmation_consumed"
                    and stored_payload.get("confirmation_id") == payload.get("confirmation_id")):
                if stored_payload == payload:
                    return record
                raise ValueError("confirmation was already consumed by another scan")
            stored_id = stored_payload.get("event_id") or stored_payload.get("disposition_id") or stored_payload.get("observation_id") or stored_payload.get("reconciliation_id")
            if stored_id == event_id:
                if stored_payload == payload:
                    return record
                raise ValueError(f"conflicting NBF event_id: {event_id}")
        return self._journal._emit_locked(seq_fd, kind=f"incident.nbf.{event_type or payload['event_type']}", payload=payload, idempotency_key=event_id, init_ts=self._journal._load_init_ts())

    def _append_nbf(self, payload: dict[str, Any], *, event_type: str | None = None, _changed_precondition: Any = None) -> dict[str, Any]:
        """Validate and append one typed record through the single journal door."""
        # Validate before touching the filesystem, then validate again in the
        # locked helper so callers cannot bypass the append authority.
        from arnold_pipelines.megaplan.incident.schema import validate_nbf_event
        validate_nbf_event(payload, _changed_precondition=_changed_precondition)
        lock_fd = self._journal.open_journal_lock()
        seq_fd: int | None = None
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            seq_fd = self._journal.open_sequence_after_lock()
            fcntl.flock(seq_fd, fcntl.LOCK_EX)
            self._journal.recover_structured_reservation_locked(seq_fd)
            return self._append_nbf_locked(seq_fd, payload, self._journal._read_records(), event_type=event_type, _changed_precondition=_changed_precondition)
        finally:
            if seq_fd is not None:
                try:
                    fcntl.flock(seq_fd, fcntl.LOCK_UN)
                finally:
                    os.close(seq_fd)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

    def _locked(self):
        """Context manager for NBF operations needing a projected compare."""
        from contextlib import contextmanager
        @contextmanager
        def cm():
            lock_fd = self._journal.open_journal_lock()
            fd: int | None = None
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                fd = self._journal.open_sequence_after_lock()
                fcntl.flock(fd, fcntl.LOCK_EX)
                self._journal.recover_structured_reservation_locked(fd)
                yield fd, self._journal._read_records()
            finally:
                if fd is not None:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    finally:
                        os.close(fd)
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
        return cm()

    def _project_records(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        """Deterministically rebuild all NBF state from the one journal."""
        from arnold_pipelines.megaplan.incident.schema import validate_nbf_event
        checked: list[dict[str, Any]] = []
        seen_ids: dict[str, dict[str, Any]] = {}
        for record in records:
            payload = record.get("payload")
            if not (isinstance(payload, dict) and str(record.get("kind", "")).startswith("incident.nbf")):
                checked.append(record)
                continue
            validate_nbf_event(payload, _allow_persisted_changed_precondition=True)
            identity = self._nbf_event_id(payload)
            prior = seen_ids.get(identity)
            if prior is not None and prior != payload:
                raise ValueError(f"conflicting committed NBF event: {identity}")
            if prior is None:
                seen_ids[identity] = payload
                checked.append(record)
        records = checked
        reservations: dict[str, dict[str, Any]] = {}
        terminals: dict[str, dict[str, Any]] = {}
        dispositions: dict[str, dict[str, Any]] = {}
        cleanup_handoffs: dict[str, dict[str, Any]] = {}
        changes: dict[str, dict[str, Any]] = {}
        confirmations: dict[str, dict[str, Any]] = {}
        provider_streams: dict[str, dict[str, Any]] = {}
        # NBF06 provider-resilience state is projected from the same journal
        # as reservations and terminals.  Probe leases/results deliberately
        # remain ordinary NBF records; the extra maps are read-only views used
        # by the policy seam and do not introduce a second store.
        provider_observations: dict[str, dict[str, Any]] = {}
        provider_probe_leases: dict[str, dict[str, Any]] = {}
        provider_probe_results: dict[str, dict[str, Any]] = {}
        provider_probe_closures: dict[str, dict[str, Any]] = {}
        provider_recovery_proofs: dict[str, dict[str, Any]] = {}
        provider_holds: dict[str, dict[str, Any]] = {}
        provider_successes: dict[str, dict[str, Any]] = {}
        latest_stream_key: str | None = None
        active_provider_key: str | None = None
        active_base: tuple[Any, ...] | None = None
        for record in records:
            if not (isinstance(record.get("payload"), dict) and str(record.get("kind", "")).startswith("incident.nbf")):
                continue
            p = record["payload"]
            typ = p.get("event_type")
            if typ == "admission_reserved":
                key = p["reservation_key"]
                reservations[key] = {
                    **p,
                    "event_id": p["event_id"],
                    "closed": False,
                    "reconciliation": None,
                }
                consumed = p.get("changed_precondition_event_id")
                if consumed in changes:
                    changes[consumed]["consumed"] = True
            elif typ == "provider_route_child_reserved":
                key = p["reservation_key"]
                reservations[key] = {
                    **p,
                    "event_id": p["event_id"],
                    "logical_dispatch_id": p["child_logical_dispatch_id"],
                    "dispatch_family_id": p["child_dispatch_family_id"],
                    "physical_door_id": p["child_physical_door_id"],
                    "semantic_dispatch_fingerprint": p["child_semantic_dispatch_fingerprint"],
                    "selected_spec": p["to_spec"],
                    "admission_receipt_id": derive_receipt_id(
                        reservation_event_id=p["event_id"],
                        plan_id=p["plan_id"],
                        phase=p["phase"],
                        dispatch_family_id=p["child_dispatch_family_id"],
                        logical_dispatch_id=p["child_logical_dispatch_id"],
                        physical_door_id=p["child_physical_door_id"],
                        semantic_dispatch_fingerprint=p["child_semantic_dispatch_fingerprint"],
                        derivation_version=p["receipt_derivation_version"],
                    ),
                    "closed": False,
                    "reconciliation": None,
                }
                consumed = p.get("consumed_changed_precondition_event_id") or p.get("authorizing_event_id")
                if consumed in changes:
                    changes[consumed]["consumed"] = True
            elif typ == "worker_disposition":
                dispositions[p["disposition_id"]] = p
            elif typ == "worker_terminal_outcome":
                terminals[p["terminal_outcome_id"]] = p
                key = p.get("reservation_key") or reservation_key(p.get("projection_key", ""), p.get("semantic_dispatch_fingerprint", ""))
                k = p.get("provider_failure_key")
                reservation = reservations.get(key, {})
                base = (p.get("plan_id"), p.get("phase"), p.get("primary_spec") or reservation.get("primary_spec") or p.get("selected_spec"), p.get("configured_fallback_chain_identity", "") or reservation.get("configured_fallback_chain_identity", ""))
                outcome_kind = p.get("outcome_kind")
                stream = None
                if k:
                    stream_key = _stable_id("provider-stream", *base, k)
                    stream = provider_streams.setdefault(stream_key, {"provider_failure_key": k, "plan_id": base[0], "phase": base[1], "primary_spec": base[2], "selected_spec": p.get("selected_spec"), "configured_fallback_chain_identity": base[3], "observation_streak": 0, "broken": False})
                    latest_stream_key = stream_key
                    active_base = base
                if outcome_kind == "provider_exhausted" and stream is not None:
                    stream["observation_streak"] = 1 if stream["broken"] else stream["observation_streak"] + 1
                    stream["broken"] = False
                    active_provider_key = k
                elif outcome_kind == "success" and stream is not None:
                    stream["observation_streak"] = 0
                    stream["broken"] = False
                    active_provider_key = None
                elif outcome_kind in {"ordinary_terminal_failure", "worker_disposition"} and stream is not None:
                    stream["observation_streak"] = 0
                    stream["broken"] = True
                # Terminal projection precedes reservation closure.  Keeping
                # this assignment after replaying the terminal's provider
                # transition makes the ordering explicit and deterministic.
                if key in reservations:
                    reservations[key]["closed"] = True
            elif typ == "provider_observation":
                # Observation records are linked to a terminal by the
                # deterministic observation identity where possible.  The
                # terminal projection remains the sole streak authority;
                # replaying an observation can therefore never increment a
                # stream a second time.
                observation_id = p.get("observation_id") or p.get("event_id")
                if observation_id:
                    linked_terminal = next(
                        (
                            terminal
                            for terminal in terminals.values()
                            if terminal.get("provider_failure_key") == p.get("provider_failure_key")
                            and terminal.get("phase") == p.get("phase")
                            and terminal.get("selected_spec") == p.get("selected_spec")
                        ),
                        None,
                    )
                    linked = linked_terminal or {}
                    provider_observations[observation_id] = {
                        **p,
                        "event_id": p.get("event_id"),
                        "terminal_outcome_event_id": p.get("terminal_outcome_event_id") or linked.get("terminal_outcome_id"),
                        "reservation_event_id": p.get("reservation_event_id") or linked.get("reservation_event_id"),
                        "admission_receipt_id": p.get("admission_receipt_id") or linked.get("admission_receipt_id"),
                        "logical_dispatch_id": p.get("logical_dispatch_id") or linked.get("logical_dispatch_id"),
                    }
            elif typ == "provider_probe_started":
                # A close marker uses the existing, schema-closed
                # provider_probe_started shape.  Its route identity is a
                # reserved internal value, while the lease id still points
                # at the original lease.  This keeps closure durable without
                # creating another writer or an unvalidated event family.
                route_identity = p.get("route_identity")
                if isinstance(route_identity, str) and route_identity.startswith("__NBF06_PROBE_CLOSED__:"):
                    marker = route_identity.split(":", 2)
                    closure = {
                        **p,
                        "event_id": p.get("event_id"),
                        "probe_lease_id": p.get("probe_lease_id"),
                        "close_reason": marker[1] if len(marker) > 1 else "closed",
                        "retry_not_before_ns": int(marker[2]) if len(marker) > 2 and marker[2].isdigit() else 0,
                    }
                    provider_probe_closures[p.get("probe_lease_id")] = closure
                    lease = provider_probe_leases.get(p.get("probe_lease_id"))
                    if lease is not None:
                        lease["closed"] = True
                        lease["status"] = (
                            "passed_closed"
                            if provider_probe_results.get(lease.get("result_event_id"), {}).get("passed") is True
                            and closure.get("close_reason") == "passed"
                            else "failed"
                        )
                else:
                    lease_id = p.get("probe_lease_id")
                    monotonic_clock = str(p.get("actor", "")).endswith("::nbf06-monotonic")
                    lease = {
                        **p,
                        "event_id": p.get("event_id"),
                        "probe_lease_id": lease_id,
                        "closed": False,
                        "status": "leased",
                        "result_event_id": None,
                        "clock_mode": "monotonic_ns" if monotonic_clock else "wall_seconds",
                    }
                    provider_probe_leases[lease_id] = lease
                    # If a result was replayed before a projection consumer
                    # saw the lease (possible only in hand-built fixtures),
                    # fold it in deterministically below.
                    for result in provider_probe_results.values():
                        if result.get("probe_lease_id") == lease_id:
                            lease["result_event_id"] = result.get("event_id")
                            lease["status"] = "passed" if result.get("passed") is True else "failed"
                            break
                    closure = provider_probe_closures.get(lease_id)
                    if closure is not None:
                        lease["closed"] = True
                        lease["status"] = (
                            "passed_closed"
                            if lease.get("status") == "passed" and closure.get("close_reason") == "passed"
                            else "failed"
                        )
            elif typ == "provider_probe_result":
                result = {**p, "event_id": p.get("event_id")}
                provider_probe_results[p.get("event_id")] = result
                lease = provider_probe_leases.get(p.get("probe_lease_id"))
                if lease is not None:
                    lease["result_event_id"] = p.get("event_id")
                    lease["status"] = "passed" if p.get("passed") is True else "failed"
                    closure = provider_probe_closures.get(p.get("probe_lease_id"))
                    if closure is not None:
                        lease["closed"] = True
                        lease["status"] = (
                            "passed_closed"
                            if p.get("passed") is True and closure.get("close_reason") == "passed"
                            else "failed"
                        )
            elif typ == "changed_precondition":
                changes[p["event_id"]] = {**p, "consumed": False}
                if p.get("reason") == "provider_recovery_verified":
                    provider_recovery_proofs[p["event_id"]] = changes[p["event_id"]]
                before, after = p.get("provider_failure_key_before"), p.get("provider_failure_key_after")
                if before and after and before != after:
                    matching = [s for s in provider_streams.values() if s.get("provider_failure_key") == before]
                    for old in matching:
                        new_key = _stable_id("provider-stream", old.get("plan_id"), old.get("phase"), old.get("primary_spec"), old.get("configured_fallback_chain_identity", ""), after)
                        provider_streams[new_key] = {**old, "provider_failure_key": after, "observation_streak": 0, "broken": False}
                        latest_stream_key = new_key
                        active_provider_key = after
            elif typ == "changed_precondition_consumed":
                if p.get("changed_precondition_event_id") in changes:
                    changes[p["changed_precondition_event_id"]]["consumed"] = True
            elif typ == "reservation_reconciled":
                for key, value in reservations.items():
                    if value.get("event_id") == p.get("reservation_event_id") or value.get("reservation_event_id") == p.get("reservation_event_id"):
                        value["reconciliation"] = p["resolution"]
                        value["closed"] = p["resolution"] != "permanent_hold_ambiguous"
            elif typ in {"supervision_confirmation_observed", "supervision_confirmation_replaced"}:
                if typ == "supervision_confirmation_replaced" and p.get("prior_confirmation_event_id"):
                    for prior in confirmations.values():
                        if prior.get("event_id") == p["prior_confirmation_event_id"]:
                            prior["replaced"] = True
                            prior["expired"] = True
                confirmations[p["confirmation_id"]] = {**p, "consumed": False, "expired": False, "replaced": False}
            elif typ in {"supervision_confirmation_consumed", "supervision_confirmation_expired"}:
                if p.get("confirmation_id") in confirmations:
                    if typ == "supervision_confirmation_consumed":
                        confirmations[p["confirmation_id"]]["consumed"] = True
                    else:
                        confirmations[p["confirmation_id"]]["expired"] = True
            elif typ == "spawn_cleanup_handoff":
                cleanup_handoffs[p["handoff_id"]] = dict(p)
        latest = provider_streams.get(latest_stream_key, {"provider_failure_key": None, "observation_streak": 0})
        # ``probe_status`` is intentionally a small finite projection.  A
        # passed result remains visibly open (``passed`` plus ``closed=False``
        # on its lease) until the explicit close CAS appends its marker.
        probe_status = "none"
        for lease in provider_probe_leases.values():
            status = lease.get("status")
            if status == "leased":
                probe_status = "leased"
            elif status == "passed" and probe_status not in {"leased"}:
                probe_status = "passed"
            elif status == "passed_closed" and probe_status not in {"leased", "passed"}:
                probe_status = "passed"
            elif status == "failed" and probe_status == "none":
                probe_status = "failed"
        return {
            "projection_version": len(records),
            "reservations": reservations,
            "terminals": terminals,
            "dispositions": dispositions,
            "changed_preconditions": changes,
            "confirmations": confirmations,
            "cleanup_handoffs": cleanup_handoffs,
            "active_provider_failure_key": active_provider_key,
            "observation_streak": latest.get("observation_streak", 0),
            "provider_streaks": provider_streams,
            "provider_observations": provider_observations,
            "provider_probe_leases": provider_probe_leases,
            "provider_probe_results": provider_probe_results,
            "provider_probe_closures": provider_probe_closures,
            "provider_recovery_proofs": provider_recovery_proofs,
            "provider_holds": provider_holds,
            "provider_successes": provider_successes,
            "probe_status": probe_status,
        }

    def projection(self) -> dict[str, Any]:
        return self._project_records(self.read_nbf_events())

    def reserve(self, *, plan_id: str, phase: str, projection_key: str, semantic_dispatch_fingerprint: str, logical_dispatch_id: str, dispatch_family_id: str, physical_door_id: str = "default-door", expected_projection_version: int | None = None, changed_precondition_event_id: str | None = None, selected_spec: str = "unspecified", primary_spec: str | None = None, configured_fallback_chain_identity: str = "", execution_context_identity: str = "", actor: str = "megaplan") -> dict[str, Any]:
        key = reservation_key(projection_key, semantic_dispatch_fingerprint)
        with self._locked() as (fd, records):
            projection = self._project_records(records)
            if expected_projection_version is not None and expected_projection_version != projection["projection_version"]:
                raise ValueError("reservation projection version mismatch")
            current = projection["reservations"].get(key)
            if current and not current.get("closed"):
                raise ValueError("active reservation already exists for projection key and fingerprint")
            if current and not changed_precondition_event_id:
                raise ValueError("terminal fingerprint requires a changed precondition")
            if changed_precondition_event_id:
                change = projection["changed_preconditions"].get(changed_precondition_event_id)
                if not change or change.get("consumed"):
                    raise ValueError("changed precondition is missing or already consumed")
                if change.get("plan_id") != plan_id or change.get("phase") != phase:
                    raise ValueError("changed precondition context mismatch")
                if change.get("logical_dispatch_id") not in (None, logical_dispatch_id):
                    raise ValueError("changed precondition logical identity mismatch")
                if change.get("provider_failure_key_before") and change.get("provider_failure_key_after") and change.get("provider_failure_key_before") == change.get("provider_failure_key_after") and change.get("reason") != "provider_recovery_verified":
                    raise ValueError("unchanged provider key cannot authorize this reservation")
            event_id = _stable_id("admission_reserved", key, logical_dispatch_id, str(projection["projection_version"]))
            payload = {"schema_version": 1, "event_type": "admission_reserved", "event_id": event_id, "plan_id": plan_id, "phase": phase, "projection_key": projection_key, "reservation_key": key, "semantic_dispatch_fingerprint": semantic_dispatch_fingerprint, "logical_dispatch_id": logical_dispatch_id, "dispatch_family_id": dispatch_family_id, "physical_door_id": physical_door_id, "selected_spec": selected_spec, "expected_projection_version": projection["projection_version"], "changed_precondition_event_id": changed_precondition_event_id, "recorded_at": _now(), "actor": actor, "admission_receipt_id": derive_receipt_id(
                    reservation_event_id=event_id,
                    plan_id=plan_id,
                    phase=phase,
                    dispatch_family_id=dispatch_family_id,
                    logical_dispatch_id=logical_dispatch_id,
                    physical_door_id=physical_door_id,
                    semantic_dispatch_fingerprint=semantic_dispatch_fingerprint,
                )}
            payload["primary_spec"] = primary_spec or selected_spec
            payload["configured_fallback_chain_identity"] = configured_fallback_chain_identity
            if execution_context_identity:
                payload["execution_context_identity"] = execution_context_identity
            # The receipt is returned only after _emit_locked has fsynced the
            # reservation.  The payload still carries the deterministic value
            # so replay can validate the exact committed context.
            return self._append_nbf_locked(fd, payload, records)

    def append_spawn_cleanup_handoff(self, *, reservation_event_id: str, admission_receipt_id: str, physical_door_id: str, plan_id: str, phase: str, projection_key: str, dispatch_family_id: str, logical_dispatch_id: str, semantic_dispatch_fingerprint: str, selected_spec: str, execution_context_identity: str, worker_identity: Mapping[str, Any], victim_pid: int, victim_process_start_identity: str, spawn_registration_id: str, spawn_certification_id: str, route_identity: str, error_kind: str, reason: str, started_at: str = "", hold_metadata: Mapping[str, Any] | None = None, actor: str = "controlled-adapter") -> dict[str, Any]:
        """Persist one identity-bound cleanup custody handoff.

        This is evidence on the existing reservation, never a new admission,
        WBC start, or lifecycle state.  The stable handoff ID makes exception
        unwinding and supervisor replay idempotent.
        """
        handoff_id = _stable_id(
            "spawn-cleanup-handoff", reservation_event_id, admission_receipt_id,
            spawn_registration_id, spawn_certification_id,
        )
        payload = {
            "schema_version": 1,
            "event_type": "spawn_cleanup_handoff",
            "event_id": handoff_id,
            "handoff_id": handoff_id,
            "reservation_event_id": reservation_event_id,
            "admission_receipt_id": admission_receipt_id,
            "physical_door_id": physical_door_id,
            "plan_id": plan_id,
            "phase": phase,
            "projection_key": projection_key,
            "dispatch_family_id": dispatch_family_id,
            "logical_dispatch_id": logical_dispatch_id,
            "semantic_dispatch_fingerprint": semantic_dispatch_fingerprint,
            "selected_spec": selected_spec,
            "execution_context_identity": execution_context_identity,
            "worker_identity": dict(worker_identity),
            "victim_pid": victim_pid,
            "victim_process_start_identity": victim_process_start_identity,
            "spawn_registration_id": spawn_registration_id,
            "spawn_certification_id": spawn_certification_id,
            "started_at": started_at,
            "route_identity": route_identity,
            "error_kind": error_kind,
            "reason": reason,
            "cleanup_state": "cleanup_hold",
            "recorded_at": _now(),
            "actor": actor,
        }
        if hold_metadata is not None:
            payload["hold_metadata"] = dict(hold_metadata)
        with self._locked() as (fd, records):
            projection = self._project_records(records)
            reservation = next((r for r in projection["reservations"].values() if r.get("event_id") == reservation_event_id), None)
            if reservation is None:
                raise ValueError("cleanup handoff references unknown reservation")
            prior_handoff = projection.get("cleanup_handoffs", {}).get(handoff_id)
            if prior_handoff is not None:
                return next(
                    record for record in records
                    if record.get("payload", {}).get("handoff_id") == handoff_id
                )
            for name, value in (("plan_id", plan_id), ("phase", phase), ("projection_key", projection_key), ("dispatch_family_id", dispatch_family_id), ("logical_dispatch_id", logical_dispatch_id), ("semantic_dispatch_fingerprint", semantic_dispatch_fingerprint), ("selected_spec", selected_spec), ("physical_door_id", physical_door_id), ("admission_receipt_id", admission_receipt_id), ("execution_context_identity", execution_context_identity)):
                if reservation.get(name) != value:
                    raise ValueError(f"cleanup handoff reservation context mismatch: {name}")
            return self._append_nbf_locked(fd, payload, records)

    def append_terminal_outcome(self, *, outcome: Any, reservation_event_id: str, projection_key: str, physical_door_id: str = "default-door", actor: str = "megaplan", execution_context_identity: str = "", primary_spec: str | None = None, configured_fallback_chain_identity: str | None = None, preacceptance_observation_id: str | None = None) -> dict[str, Any]:
        from arnold_pipelines.megaplan.orchestration.phase_result import DispatchOutcome
        if isinstance(outcome, dict):
            outcome = DispatchOutcome.from_dict(outcome)
        if not isinstance(outcome, DispatchOutcome):
            raise ValueError("terminal outcome must be a DispatchOutcome")
        if outcome.kind == "no_launch" or outcome.kind == "unresolved_launch":
            raise ValueError("scheduling outcomes have no worker terminal event")
        with self._locked() as (fd, records):
            p = self._project_records(records)
            reservation = next((r for r in p["reservations"].values() if r.get("event_id") == reservation_event_id), None)
            if reservation is None:
                raise ValueError("terminal outcome references unknown reservation")
            # Reservation context is authoritative; never let a caller route a
            # terminal to a different phase/fingerprint/logical dispatch.
            expected_receipt = reservation.get("admission_receipt_id") or self.derive_receipt(next(r for r in records if r.get("payload", {}).get("event_id") == reservation_event_id))
            bound_transport = bool(expected_receipt and outcome.admission_receipt_id == expected_receipt)
            context_fields = (("plan_id", outcome.plan_id), ("phase", outcome.phase), ("projection_key", projection_key), ("semantic_dispatch_fingerprint", outcome.semantic_dispatch_fingerprint), ("logical_dispatch_id", outcome.logical_dispatch_id), ("dispatch_family_id", outcome.dispatch_family_id), ("selected_spec", outcome.selected_spec))
            for name, value in context_fields:
                expected = reservation.get(name)
                if expected != value:
                    raise ValueError(f"terminal outcome reservation context mismatch: {name}")
            if not expected_receipt or not bound_transport:
                raise ValueError("terminal outcome receipt is not bound to reservation")
            if reservation.get("physical_door_id", "") != physical_door_id:
                raise ValueError("terminal outcome reservation context mismatch: physical_door_id")
            if outcome.worker_identity is None or not outcome.started_at or not outcome.finished_at:
                raise ValueError("terminal outcome requires persisted accepted-launch context")
            stored_execution = reservation.get("execution_context_identity", "")
            if stored_execution != execution_context_identity:
                raise ValueError("terminal outcome reservation context mismatch: execution_context_identity")
            expected_primary = reservation.get("primary_spec", "")
            if primary_spec is not None and primary_spec != expected_primary:
                raise ValueError("terminal outcome reservation context mismatch: primary_spec")
            expected_chain = reservation.get("configured_fallback_chain_identity", "")
            if configured_fallback_chain_identity is not None and configured_fallback_chain_identity != expected_chain:
                raise ValueError("terminal outcome reservation context mismatch: configured_fallback_chain_identity")
            if outcome.kind == "worker_disposition":
                disp = p["dispositions"].get(outcome.disposition_id)
                if not disp:
                    raise ValueError("worker disposition must already be committed")
                for n in ("admission_receipt_id", "semantic_dispatch_fingerprint", "phase", "selected_spec", "logical_dispatch_id", "worker_identity"):
                    if disp.get(n) != getattr(outcome, n):
                        raise ValueError(f"worker disposition context mismatch: {n}")
            terminal_id = outcome.terminal_outcome_event_id or _stable_id("worker_terminal_outcome", reservation_event_id, outcome.kind)
            for existing in p["terminals"].values():
                if existing.get("reservation_event_id") == reservation_event_id:
                    if existing.get("outcome_kind") == outcome.kind:
                        expected_provider_key = outcome.provider_failure_key
                        if expected_provider_key is None and isinstance(outcome.provider_evidence, dict):
                            expected_provider_key = outcome.provider_evidence.get("provider_failure_key")
                        comparable = {
                            "terminal_outcome_id": terminal_id,
                            "outcome_kind": outcome.kind,
                            "disposition_id": outcome.disposition_id,
                            "admission_receipt_id": outcome.admission_receipt_id,
                            "semantic_dispatch_fingerprint": outcome.semantic_dispatch_fingerprint,
                            "logical_dispatch_id": outcome.logical_dispatch_id,
                            "worker_identity": outcome.worker_identity,
                            "plan_id": outcome.plan_id,
                            "phase": outcome.phase,
                            "projection_key": projection_key,
                            "dispatch_family_id": outcome.dispatch_family_id,
                            "selected_spec": outcome.selected_spec,
                            "provider": outcome.provider,
                            "route_liveness_kind": outcome.route_liveness_kind,
                            "route_liveness_identity": outcome.route_liveness_identity,
                            "route_liveness_digest": outcome.route_liveness_digest,
                            "physical_door_id": physical_door_id,
                            "launch_state": outcome.launch_state,
                            "started_at": outcome.started_at,
                            "finished_at": outcome.finished_at,
                            "success_payload": outcome.success_payload,
                            "terminal_failure": outcome.terminal_failure,
                            "provider_evidence": outcome.provider_evidence if isinstance(outcome.provider_evidence, dict) else {},
                            "provider_failure_key": expected_provider_key,
                            "execution_context_identity": execution_context_identity,
                        }
                        if all(existing.get(name) == value for name, value in comparable.items()):
                            return next(r for r in records if r.get("payload", {}).get("terminal_outcome_id") == existing["terminal_outcome_id"])
                        raise ValueError("conflicting terminal linkage for reservation")
                    raise ValueError("reservation already has a conflicting terminal outcome")
            if reservation.get("closed"):
                raise ValueError("reservation is already closed")
            provider = outcome.provider_evidence if isinstance(outcome.provider_evidence, dict) else {}
            payload = {"schema_version": 1, "event_type": "worker_terminal_outcome", "event_id": terminal_id, "terminal_outcome_id": terminal_id, "outcome_kind": outcome.kind, "plan_id": outcome.plan_id, "phase": outcome.phase, "projection_key": projection_key, "reservation_key": reservation.get("reservation_key"), "dispatch_family_id": outcome.dispatch_family_id, "logical_dispatch_id": outcome.logical_dispatch_id, "admission_receipt_id": outcome.admission_receipt_id, "reservation_event_id": reservation_event_id, "semantic_dispatch_fingerprint": outcome.semantic_dispatch_fingerprint, "selected_spec": outcome.selected_spec, "provider": outcome.provider, "route_liveness_kind": outcome.route_liveness_kind, "route_liveness_identity": outcome.route_liveness_identity, "route_liveness_digest": outcome.route_liveness_digest, "physical_door_id": physical_door_id, "launch_state": outcome.launch_state, "worker_identity": outcome.worker_identity, "started_at": outcome.started_at, "finished_at": outcome.finished_at, "success_payload": outcome.success_payload, "terminal_failure": outcome.terminal_failure, "provider_evidence": provider, "provider_failure_key": outcome.provider_failure_key or provider.get("provider_failure_key"), "disposition_id": outcome.disposition_id, "execution_context_identity": execution_context_identity, "recorded_at": _now(), "actor": actor}
            if preacceptance_observation_id:
                payload["preacceptance_observation_id"] = preacceptance_observation_id
            payload["primary_spec"] = expected_primary
            payload["configured_fallback_chain_identity"] = expected_chain
            return self._append_nbf_locked(fd, payload, records)

    def append_disposition(self, disposition: Any) -> dict[str, Any]:
        payload = disposition.to_dict() if hasattr(disposition, "to_dict") else dict(disposition)
        with self._locked() as (fd, records):
            # Disposition identity is the canonical signal-evidence key.  A
            # replay after a crash returns the original event byte-for-byte;
            # a caller cannot append a conflicting record under the same ID.
            identity = payload.get("disposition_id") or payload.get("observation_id")
            if identity:
                prior = next(
                    (record for record in records
                     if record.get("payload", {}).get("event_type") in {
                         "worker_disposition", "non_worker_signal_disposition",
                         "observed_process_death",
                     }
                     and (record.get("payload", {}).get("disposition_id") == identity
                          or record.get("payload", {}).get("observation_id") == identity)),
                    None,
                )
                if prior is not None:
                    if prior.get("payload") == payload:
                        return prior
                    raise ValueError("conflicting disposition identity already committed")
            if payload.get("event_type") == "worker_disposition" and payload.get("confirmation_event_id"):
                projected = self._project_records(records)
                confirmation = projected["confirmations"].get(payload["confirmation_event_id"])
                if not confirmation or not confirmation.get("consumed"):
                    raise ValueError("required confirmation is missing or not consumed")
            return self._append_nbf_locked(fd, payload, records)

    def record_claim_signal_locked(
        self,
        disposition: Any,
        *,
        signal: str,
        signal_fn: Callable[[], Any],
        preflight: Callable[[list[dict[str, Any]]], Any] | None = None,
        actor: str = "signal-authority",
    ) -> dict[str, Any]:
        """Atomically fence, record, claim, and invoke one physical signal.

        ``preflight`` runs while the journal lock is held and is therefore the
        final source/identity check immediately preceding the record-before-
        signal door.  A persisted claim is never replayed as a second signal.
        """
        payload = disposition.to_dict() if hasattr(disposition, "to_dict") else dict(disposition)
        identity = payload.get("disposition_id") or payload.get("observation_id")
        if not isinstance(identity, str) or not identity:
            raise ValueError("signal disposition identity is missing")
        with self._locked() as (fd, records):
            if preflight is not None:
                preflight(records)
            record = self._append_nbf_locked(fd, payload, records, event_type=payload.get("event_type"))
            claim = next((item for item in records if (item.get("payload") or {}).get("event_type") == "signal_claimed" and (item.get("payload") or {}).get("disposition_id") == identity), None)
            created = False
            if claim is None:
                claim_payload = {
                    "schema_version": 1,
                    "event_type": "signal_claimed",
                    "event_id": _stable_id("signal-claim", identity, signal),
                    "disposition_id": identity,
                    "signal": signal,
                    "recorded_at": _now(),
                    "actor": actor,
                }
                self._append_nbf_locked(fd, claim_payload, records, event_type="signal_claimed")
                created = True
            elif (claim.get("payload") or {}).get("signal") != signal:
                raise ValueError("conflicting signal claim")
            if not created:
                return record
            try:
                signal_fn()
            except (ProcessLookupError, ChildProcessError):
                return record
            except OSError as exc:
                raise RuntimeError(f"signal failed after durable claim: {exc}") from exc
            return record

    def claim_signal(self, disposition_id: str, *, signal: str, actor: str = "supervisor") -> tuple[dict[str, Any], bool]:
        """Atomically claim the one physical signal for a disposition.

        The claim is durable and precedes the operating-system call.  A
        concurrent retry therefore observes ``created=False`` and must not
        invoke the physical primitive a second time.  This is intentionally a
        separate event: disposition and terminal records remain immutable and
        replayable, while the claim records the at-most-once side effect.
        """
        if not isinstance(disposition_id, str) or not disposition_id:
            raise ValueError("signal claim requires disposition identity")
        if not isinstance(signal, str) or not signal:
            raise ValueError("signal claim requires signal identity")
        with self._locked() as (fd, records):
            prior = next((record for record in records
                          if record.get("payload", {}).get("event_type") == "signal_claimed"
                          and record.get("payload", {}).get("disposition_id") == disposition_id), None)
            if prior is not None:
                if prior.get("payload", {}).get("signal") != signal:
                    raise ValueError("conflicting signal claim")
                return prior, False
            payload = {
                "schema_version": 1,
                "event_type": "signal_claimed",
                "event_id": _stable_id("signal-claim", disposition_id, signal),
                "disposition_id": disposition_id,
                "signal": signal,
                "recorded_at": _now(),
                "actor": actor,
            }
            return self._append_nbf_locked(fd, payload, records), True

    def append_changed_precondition(self, event: Any) -> dict[str, Any]:
        from arnold_pipelines.megaplan.incident.schema import ChangedPrecondition, _digest, _validate_producer_binding
        obj = event if isinstance(event, ChangedPrecondition) else ChangedPrecondition.from_dict(event)
        _validate_producer_binding(obj)
        with self._locked() as (fd, records):
            projected = self._project_records(records)
            # Evidence identity is bound to a committed ledger event.  A
            # caller cannot mint a valid-looking change from an arbitrary
            # digest and then consume it as an authorization.
            cited = next((r.get("payload", {}) for r in records if r.get("payload", {}).get("event_id") == obj.evidence_event_id), None)
            if cited is None:
                raise ValueError("changed precondition evidence event is not persisted")
            if _digest(cited) != obj.evidence_digest:
                raise ValueError("changed precondition evidence digest mismatch")
            if obj.evidence_snapshot != cited:
                raise ValueError("changed precondition evidence is not the cited authoritative event")
            if obj.evidence_event_id != cited.get("event_id"):
                raise ValueError("changed precondition evidence identity is not canonical")
            if obj.reason == "provider_recovery_verified":
                if cited.get("event_type") != "provider_probe_result" or cited.get("passed") is not True:
                    raise ValueError("provider recovery requires a passed canonical probe")
                key = cited.get("provider_failure_key")
                if obj.provider_failure_key_before != key or obj.provider_failure_key_after != key:
                    raise ValueError("provider recovery key is not bound to the probe")
                probe_lease_id = cited.get("probe_lease_id")
                lease = projected.get("provider_probe_leases", {}).get(probe_lease_id)
                closure = projected.get("provider_probe_closures", {}).get(probe_lease_id)
                # New NBF06 monotonic leases require an explicit close CAS;
                # legacy wall-clock leases are accepted as already-closed so
                # old durable fixtures remain readable and replayable.
                if lease and lease.get("clock_mode") == "monotonic_ns":
                    if closure is None or closure.get("close_reason") != "passed":
                        raise ValueError("provider recovery requires a passed, closed canonical probe")
            return self._append_nbf_locked(fd, obj.to_dict(), records, _changed_precondition=obj)

    def reserve_provider_route_child(self, *, plan_id: str, phase: str, projection_key: str, expected_projection_version: int, transition_kind: str, from_spec: str, to_spec: str, parent_logical_dispatch_id: str, parent_terminal_event_id: str, authorizing_event_id: str, configured_fallback_chain_identity: str, precondition_identity: str, child_dispatch_family_id: str, child_logical_dispatch_id: str, child_physical_door_id: str, child_semantic_dispatch_fingerprint: str, child_route_liveness_identity: str, consumed_changed_precondition_event_id: str | None = None, receipt_derivation_version: str = "1", execution_context_identity: str = "", actor: str = "megaplan") -> dict[str, Any]:
        with self._locked() as (fd, records):
            event_id = _stable_id("provider_route_child_reserved", plan_id, phase, child_logical_dispatch_id, child_semantic_dispatch_fingerprint)
            # Replaying the exact linked-child request is a read of the
            # already committed admission, not a second reservation.  Do
            # this before the caller's stale projection compare: a worker can
            # safely retry after losing the response race.
            prior_child = self._provider_raw_record(records, event_id)
            if prior_child is not None:
                prior_payload = prior_child.get("payload", {})
                expected_payload = {
                    "schema_version": 1,
                    "event_type": "provider_route_child_reserved",
                    "event_id": event_id,
                    "plan_id": plan_id,
                    "phase": phase,
                    "projection_key": projection_key,
                    "reservation_key": reservation_key(projection_key, child_semantic_dispatch_fingerprint),
                    "expected_projection_version": expected_projection_version,
                    "transition_kind": transition_kind,
                    "from_spec": from_spec,
                    "to_spec": to_spec,
                    "parent_logical_dispatch_id": parent_logical_dispatch_id,
                    "parent_terminal_event_id": parent_terminal_event_id,
                    "authorizing_event_id": authorizing_event_id,
                    "configured_fallback_chain_identity": configured_fallback_chain_identity,
                    "precondition_identity": precondition_identity,
                    "child_dispatch_family_id": child_dispatch_family_id,
                    "child_logical_dispatch_id": child_logical_dispatch_id,
                    "child_physical_door_id": child_physical_door_id,
                    "child_semantic_dispatch_fingerprint": child_semantic_dispatch_fingerprint,
                    "child_route_liveness_identity": child_route_liveness_identity,
                    "consumed_changed_precondition_event_id": consumed_changed_precondition_event_id or authorizing_event_id,
                    "receipt_derivation_version": receipt_derivation_version,
                    "execution_context_identity": execution_context_identity,
                    "primary_spec": to_spec,
                }
                if self._provider_payload_equivalent(prior_payload, expected_payload):
                    return prior_child
                raise ValueError("conflicting provider child replay")
            p = self._project_records(records)
            if expected_projection_version != p["projection_version"]:
                raise ValueError("route child projection version mismatch")
            parent = next((t for t in p["terminals"].values() if t.get("terminal_outcome_id") == parent_terminal_event_id), None)
            if not parent or parent.get("outcome_kind") not in {"provider_exhausted"}:
                raise ValueError("provider child requires a canonical provider terminal parent")
            if parent.get("plan_id") != plan_id or parent.get("phase") != phase or parent.get("projection_key") != projection_key or parent.get("logical_dispatch_id") != parent_logical_dispatch_id:
                raise ValueError("provider child parent context mismatch")
            if transition_kind in {"return", "return_primary"}:
                if from_spec == to_spec:
                    raise ValueError("return-primary target cannot be the source spec")
                if parent.get("selected_spec") not in {from_spec, to_spec}:
                    raise ValueError("return-primary is not bound to the parent source spec")
            elif parent.get("selected_spec") != from_spec:
                raise ValueError("provider child source route mismatch")
            authorizing = next((r.get("payload", {}) for r in records if (r.get("payload", {}).get("event_id") == authorizing_event_id or r.get("payload", {}).get("disposition_id") == authorizing_event_id)), None)
            if not authorizing or authorizing.get("event_type") not in {"provider_recovery_verified", "changed_precondition"}:
                raise ValueError("provider child requires a persisted authorizing recovery event")
            if authorizing.get("event_type") == "changed_precondition" and authorizing.get("reason") != "provider_recovery_verified":
                raise ValueError("provider child authorizer is not provider recovery")
            if authorizing.get("event_type") != "changed_precondition":
                raise ValueError("provider child authorizer must be a producer-derived recovery")
            if authorizing.get("provider_failure_key_before") != authorizing.get("provider_failure_key_after"):
                raise ValueError("provider child recovery changed the provider key")
            provider_key = authorizing.get("provider_failure_key_before")
            if not provider_key or provider_key != parent.get("provider_failure_key"):
                raise ValueError("provider child recovery key does not match parent")
            probe = next((r.get("payload", {}) for r in records
                          if r.get("payload", {}).get("event_type") == "provider_probe_result"
                          and r.get("payload", {}).get("event_id") == authorizing.get("evidence_event_id")), None)
            lease = p.get("provider_probe_leases", {}).get((probe or {}).get("probe_lease_id"))
            expected_route = f"{from_spec}->{to_spec}"
            if not probe or probe.get("passed") is not True or probe.get("provider_failure_key") != provider_key:
                raise ValueError("provider child requires a passed canonical probe result")
            if not lease or lease.get("provider_failure_key") != provider_key or lease.get("parent_reservation_event_id") != parent.get("reservation_event_id") or lease.get("phase") != phase:
                raise ValueError("provider probe lease is not bound to parent context")
            if lease.get("route_identity") not in (None, expected_route):
                raise ValueError("provider probe route context mismatch")
            if lease.get("clock_mode") == "monotonic_ns":
                closure = p.get("provider_probe_closures", {}).get(lease.get("probe_lease_id"))
                if closure is None or closure.get("close_reason") != "passed":
                    raise ValueError("provider child requires a passed, closed canonical probe")
            if authorizing.get("evidence_snapshot") is not None:
                # The changed-precondition append path already proves this is
                # the exact committed probe payload; retain the explicit
                # comparison here as the child authorization door.
                if authorizing.get("evidence_snapshot") != probe:
                    raise ValueError("provider recovery evidence is not the cited probe")
            if any(r.get("payload", {}).get("event_type") == "provider_route_child_reserved" and r.get("payload", {}).get("authorizing_event_id") == authorizing_event_id for r in records):
                raise ValueError("provider recovery authorization already consumed")
            child_key = reservation_key(projection_key, child_semantic_dispatch_fingerprint)
            if child_key in p["reservations"] and not p["reservations"][child_key].get("closed"):
                raise ValueError("duplicate provider child reservation")
            consumed_id = consumed_changed_precondition_event_id or (authorizing_event_id if authorizing.get("event_type") == "changed_precondition" else None)
            if consumed_id:
                change = p["changed_preconditions"].get(consumed_id)
                if not change or change.get("consumed"):
                    raise ValueError("child changed precondition is missing or already consumed")
            payload = {"schema_version": 1, "event_type": "provider_route_child_reserved", "event_id": event_id, "plan_id": plan_id, "phase": phase, "projection_key": projection_key, "reservation_key": child_key, "expected_projection_version": expected_projection_version, "transition_kind": transition_kind, "from_spec": from_spec, "to_spec": to_spec, "parent_logical_dispatch_id": parent_logical_dispatch_id, "parent_terminal_event_id": parent_terminal_event_id, "authorizing_event_id": authorizing_event_id, "configured_fallback_chain_identity": configured_fallback_chain_identity, "precondition_identity": precondition_identity, "child_dispatch_family_id": child_dispatch_family_id, "child_logical_dispatch_id": child_logical_dispatch_id, "child_physical_door_id": child_physical_door_id, "child_semantic_dispatch_fingerprint": child_semantic_dispatch_fingerprint, "child_route_liveness_identity": child_route_liveness_identity, "consumed_changed_precondition_event_id": consumed_id, "receipt_derivation_version": receipt_derivation_version, "execution_context_identity": execution_context_identity, "primary_spec": to_spec, "recorded_at": _now(), "actor": actor}
            child = self._append_nbf_locked(fd, payload, records)
            # Consumption is part of the same locked CAS as linked-child
            # admission.  A crash/replay therefore cannot leave an
            # authorizer reusable after a child was durably admitted.
            if consumed_id:
                records_after_child = [*records, child]
                consumed_event_id = _stable_id("consume", consumed_id)
                consumed_payload = {
                    "schema_version": 1,
                    "event_type": "changed_precondition_consumed",
                    "event_id": consumed_event_id,
                    "changed_precondition_event_id": consumed_id,
                    "recorded_at": _now(),
                    "actor": actor,
                }
                if self._provider_raw_record(records_after_child, consumed_event_id) is None:
                    self._append_nbf_locked(fd, consumed_payload, records_after_child)
            return child

    def derive_receipt(self, event: dict[str, Any]) -> str:
        p = event.get("payload", event)
        return derive_receipt_id(reservation_event_id=p.get("event_id") or p.get("reservation_event_id"), plan_id=p["plan_id"], phase=p["phase"], dispatch_family_id=p.get("dispatch_family_id") or p.get("child_dispatch_family_id"), logical_dispatch_id=p.get("logical_dispatch_id") or p.get("child_logical_dispatch_id"), physical_door_id=p.get("physical_door_id") or p.get("child_physical_door_id"), semantic_dispatch_fingerprint=p.get("semantic_dispatch_fingerprint") or p.get("child_semantic_dispatch_fingerprint"), derivation_version=p.get("receipt_derivation_version", "1"))

    def reconcile_reservation(self, reconciliation: Any) -> dict[str, Any]:
        payload = reconciliation.to_dict() if hasattr(reconciliation, "to_dict") else dict(reconciliation)
        with self._locked() as (fd, records):
            p = self._project_records(records)
            target = next((r for r in p["reservations"].values() if r.get("event_id") == payload.get("reservation_event_id") or r.get("reservation_event_id") == payload.get("reservation_event_id")), None)
            if not target:
                raise ValueError("unknown reservation for reconciliation")
            prior = next((e["payload"] for e in records if e.get("payload", {}).get("event_type") == "reservation_reconciled" and e["payload"].get("reservation_event_id") == payload.get("reservation_event_id")), None)
            if prior is not None:
                if prior == payload:
                    return next(e for e in records if e.get("payload") == prior)
                raise ValueError("conflicting reconciliation for reservation")
            for name in ("plan_id", "phase", "projection_key", "logical_dispatch_id", "semantic_dispatch_fingerprint"):
                if payload.get(name) != target.get(name):
                    raise ValueError(f"reconciliation context mismatch: {name}")
            expected_receipt = target.get("admission_receipt_id") or self.derive_receipt(next(r for r in records if r.get("payload", {}).get("event_id") == target["event_id"]))
            if payload.get("admission_receipt_id") != expected_receipt:
                raise ValueError("reconciliation receipt is not bound to reservation")
            if target.get("closed") and payload.get("resolution") != "terminal_outcome_recovered":
                raise ValueError("closed reservation cannot be reconciled")
            evidence = []
            for evidence_id in payload.get("evidence_event_ids", ()):
                found = next((r.get("payload", {}) for r in records if r.get("payload", {}).get("event_id") == evidence_id or r.get("payload", {}).get("disposition_id") == evidence_id), None)
                if found is None:
                    raise ValueError("reconciliation evidence is not persisted")
                evidence.append(found)
            resolution = payload.get("resolution")
            if resolution == "terminal_outcome_recovered":
                if payload.get("launch_state_identity") != "accepted":
                    raise ValueError("terminal recovery requires accepted launch evidence")
                terminal = next((item for item in evidence if item.get("event_type") == "worker_terminal_outcome" and item.get("terminal_outcome_id") == payload.get("terminal_outcome_event_id") and item.get("reservation_event_id") == target["event_id"] and item.get("admission_receipt_id") == expected_receipt), None)
                if terminal is None:
                    raise ValueError("terminal recovery lacks persisted canonical terminal")
                if terminal.get("outcome_kind") == "worker_disposition" and terminal.get("disposition_id") not in p["dispositions"]:
                    raise ValueError("recovered disposition is not persisted")
            elif resolution == "permanent_hold_ambiguous":
                if payload.get("launch_state_identity") != "ambiguous":
                    raise ValueError("ambiguous reconciliation requires ambiguous launch state")
            else:
                raise ValueError("unsupported reconciliation resolution")
            return self._append_nbf_locked(fd, payload, records)

    def observe_confirmation(self, payload: dict[str, Any]) -> dict[str, Any]:
        typ = payload.get("event_type")
        if typ == "supervision_confirmation_observed":
            with self._locked() as (fd, records):
                # A changed process identity is a durable replacement, not a
                # second timestamp-only observation.  Keep the new proof's
                # complete identity in the replacement event for restart
                # replay and auditability.
                projected = self._project_records(records)
                existing = projected["confirmations"].get(payload.get("confirmation_id"))
                if existing and not existing.get("expired") and not existing.get("consumed"):
                    # The first scan is durable state.  Re-observing the same
                    # identity must not replace its original timestamp/expiry.
                    return next(r for r in records if r.get("payload", {}).get("event_id") == existing.get("event_id"))
                old = next((r.get("payload", {}) for r in reversed(records)
                            if r.get("payload", {}).get("event_type") in {"supervision_confirmation_observed", "supervision_confirmation_replaced"}
                            and r.get("payload", {}).get("site_id") == payload.get("site_id")
                            and r.get("payload", {}).get("subject_class") == payload.get("subject_class")
                            and r.get("payload", {}).get("confirmation_id") != payload.get("confirmation_id")
                            and not projected["confirmations"].get(r.get("payload", {}).get("confirmation_id"), {}).get("consumed")
                            and not projected["confirmations"].get(r.get("payload", {}).get("confirmation_id"), {}).get("expired")), None)
                if old:
                    replacement = dict(payload)
                    replacement.update({"event_type": "supervision_confirmation_replaced", "event_id": _stable_id("confirmation-replaced", old.get("event_id"), payload.get("confirmation_id")), "prior_confirmation_event_id": old.get("event_id"), "replacement_reason": "identity_changed", "second_observed_at": payload.get("first_observed_at"), "second_evidence_digest": payload.get("evidence_digest"), "disposition_id": None})
                    return self._append_nbf_locked(fd, replacement, records)
                return self._append_nbf_locked(fd, payload, records)
        if typ == "supervision_confirmation_consumed":
            with self._locked() as (fd, records):
                p = self._project_records(records)
                prior = p["confirmations"].get(payload.get("confirmation_id"))
                if not prior or prior.get("consumed") or prior.get("expired"):
                    raise ValueError("confirmation missing or already consumed")
                identity_pairs = (
                    ("victim_pid", payload.get("victim_pid")),
                    ("victim_process_start_identity", payload.get("victim_process_start_identity")),
                    ("relevant_progress_identity", payload.get("relevant_progress_identity")),
                    ("supervisor_incarnation_identity", payload.get("supervisor_incarnation_identity")),
                    ("cause_kind", payload.get("cause_kind")),
                )
                if any(value is None or value != prior.get(name) for name, value in identity_pairs):
                    raise ValueError("confirmation identity mismatch")
                if payload.get("second_evidence_digest") != prior.get("evidence_digest"):
                    raise ValueError("confirmation evidence identity mismatch")
                try:
                    first = datetime.fromisoformat(str(prior["first_observed_at"]).replace("Z", "+00:00"))
                    second = datetime.fromisoformat(str(payload["second_observed_at"]).replace("Z", "+00:00"))
                    if second.timestamp() - first.timestamp() < float(prior["scan_interval_s"]):
                        raise ValueError("confirmation second scan is too early")
                    if second.timestamp() > float(prior["expires_at"]):
                        raise ValueError("confirmation expired")
                except (KeyError, TypeError, ValueError) as exc:
                    if isinstance(exc, ValueError) and str(exc) in {"confirmation second scan is too early", "confirmation expired"}:
                        raise
                    raise ValueError("invalid confirmation timestamps") from exc
                return self._append_nbf_locked(fd, payload, records)
        return self._append_nbf(payload)

    def consume_confirmation(self, *, confirmation_id: str, second_observed_at: str, second_evidence_digest: str, victim_pid: int, victim_process_start_identity: str, relevant_progress_identity: str, supervisor_incarnation_identity: str, cause_kind: str, scan_interval_s: float | None = None, expires_at: float | None = None, confirmation_policy_identity: str | None = None, schema_version: int | None = None, semantic_dispatch_fingerprint: str | None = None, container_identity: str | None = None, ladder_stage: str | None = None, signal_identity: str | None = None, disposition_id: str | None = None, actor: str = "supervisor") -> dict[str, Any]:
        """Consume a matching two-scan proof inside the ledger lock."""
        with self._locked() as (fd, records):
            prior = self._project_records(records)["confirmations"].get(confirmation_id)
            if not prior or prior.get("consumed") or prior.get("expired") or prior.get("replaced"):
                raise ValueError("confirmation missing or already consumed")
            identity_pairs = (("victim_pid", victim_pid), ("victim_process_start_identity", victim_process_start_identity), ("relevant_progress_identity", relevant_progress_identity), ("supervisor_incarnation_identity", supervisor_incarnation_identity), ("cause_kind", cause_kind), ("scan_interval_s", scan_interval_s), ("expires_at", expires_at), ("confirmation_policy_identity", confirmation_policy_identity), ("schema_version", schema_version))
            for name, value in identity_pairs:
                if value is None or value != prior.get(name):
                    raise ValueError(f"confirmation identity mismatch: {name}")
            if second_evidence_digest != prior.get("evidence_digest"):
                raise ValueError("confirmation evidence identity mismatch")
            for name, value in (("semantic_dispatch_fingerprint", semantic_dispatch_fingerprint), ("container_identity", container_identity), ("ladder_stage", ladder_stage), ("signal_identity", signal_identity)):
                if value is not None and prior.get(name) != value:
                    raise ValueError(f"confirmation identity mismatch: {name}")
            try:
                first = datetime.fromisoformat(str(prior["first_observed_at"]).replace("Z", "+00:00"))
                second = datetime.fromisoformat(str(second_observed_at).replace("Z", "+00:00"))
                if second.timestamp() - first.timestamp() < float(prior["scan_interval_s"]):
                    raise ValueError("confirmation second scan is too early")
                if second.timestamp() > float(prior["expires_at"]):
                    expiry = {"schema_version": 1, "event_type": "supervision_confirmation_expired", "event_id": _stable_id("confirmation-expired", confirmation_id), "confirmation_id": confirmation_id, "prior_confirmation_event_id": prior.get("event_id"), "site_id": prior.get("site_id"), "replacement_reason": "expired", "second_observed_at": second_observed_at, "second_evidence_digest": second_evidence_digest, "victim_pid": victim_pid, "victim_process_start_identity": victim_process_start_identity, "relevant_progress_identity": relevant_progress_identity, "supervisor_incarnation_identity": supervisor_incarnation_identity, "cause_kind": cause_kind, "disposition_id": None, "recorded_at": _now(), "actor": actor}
                    self._append_nbf_locked(fd, expiry, records)
                    raise ValueError("confirmation expired")
            except (KeyError, TypeError, ValueError) as exc:
                if isinstance(exc, ValueError) and str(exc) in {"confirmation second scan is too early", "confirmation expired"}:
                    raise
                raise ValueError("invalid confirmation timestamps") from exc
            payload = {"schema_version": 1, "event_type": "supervision_confirmation_consumed", "event_id": _stable_id("consumed", confirmation_id, second_observed_at, second_evidence_digest), "confirmation_id": confirmation_id, "prior_confirmation_event_id": prior.get("event_id"), "site_id": prior.get("site_id"), "replacement_reason": None, "second_observed_at": second_observed_at, "second_evidence_digest": second_evidence_digest, "victim_pid": victim_pid, "victim_process_start_identity": victim_process_start_identity, "relevant_progress_identity": relevant_progress_identity, "supervisor_incarnation_identity": supervisor_incarnation_identity, "cause_kind": cause_kind, "scan_interval_s": scan_interval_s, "expires_at": expires_at, "confirmation_policy_identity": confirmation_policy_identity, "disposition_id": disposition_id, "recorded_at": _now(), "actor": actor}
            if semantic_dispatch_fingerprint is not None:
                payload["semantic_dispatch_fingerprint"] = semantic_dispatch_fingerprint
            if container_identity is not None:
                payload["container_identity"] = container_identity
            if ladder_stage is not None:
                payload["ladder_stage"] = ladder_stage
                payload["signal_identity"] = signal_identity
            return self._append_nbf_locked(fd, payload, records)

    def expire_confirmation(self, confirmation_id: str, *, observed_at: str | None = None, actor: str = "supervisor") -> dict[str, Any]:
        """Persist expiry of an unconsumed confirmation under the journal lock."""
        with self._locked() as (fd, records):
            prior = self._project_records(records)["confirmations"].get(confirmation_id)
            if not prior:
                raise ValueError("confirmation missing")
            if prior.get("consumed") or prior.get("expired") or prior.get("replaced"):
                raise ValueError("confirmation cannot be expired after consumption or replacement")
            payload = {"schema_version": 1, "event_type": "supervision_confirmation_expired", "event_id": _stable_id("confirmation-expired", confirmation_id), "confirmation_id": confirmation_id, "prior_confirmation_event_id": prior.get("event_id"), "site_id": prior.get("site_id"), "replacement_reason": "expired", "second_observed_at": observed_at or _now(), "second_evidence_digest": prior.get("evidence_digest"), "victim_pid": prior.get("victim_pid"), "victim_process_start_identity": prior.get("victim_process_start_identity"), "relevant_progress_identity": prior.get("relevant_progress_identity"), "supervisor_incarnation_identity": prior.get("supervisor_incarnation_identity"), "cause_kind": prior.get("cause_kind"), "disposition_id": None, "recorded_at": _now(), "actor": actor}
            return self._append_nbf_locked(fd, payload, records)

    # NBF06 provider lifecycle -------------------------------------------------
    #
    # The methods below intentionally reuse ``_locked`` and ``_append_nbf``.
    # They are named ``*_locked`` because the policy seam treats each call as
    # one lock/CAS door; the public wrappers acquire the existing sequence
    # lock, perform all identity checks, and append before releasing it.  No
    # provider-specific journal or cache is introduced.

    @staticmethod
    def _provider_now_ns(value: int | None) -> int:
        if value is None:
            return int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("provider monotonic time must be a non-negative integer")
        return value

    @staticmethod
    def _provider_is_close_marker(payload: Mapping[str, Any]) -> bool:
        route = payload.get("route_identity")
        return isinstance(route, str) and route.startswith("__NBF06_PROBE_CLOSED__:")

    @staticmethod
    def _provider_close_reason(payload: Mapping[str, Any]) -> str:
        route = payload.get("route_identity")
        if isinstance(route, str) and route.startswith("__NBF06_PROBE_CLOSED__:"):
            bits = route.split(":", 2)
            if len(bits) > 1 and bits[1]:
                return bits[1]
        return "closed"

    @staticmethod
    def _provider_raw_record(records: list[dict[str, Any]], event_id: str) -> dict[str, Any] | None:
        return next((record for record in records if record.get("payload", {}).get("event_id") == event_id), None)

    @staticmethod
    def _provider_payload_equivalent(left: Mapping[str, Any], right: Mapping[str, Any], *, ignored: tuple[str, ...] = ("recorded_at", "actor")) -> bool:
        a = {key: value for key, value in left.items() if key not in ignored}
        b = {key: value for key, value in right.items() if key not in ignored}
        return a == b

    def _provider_find_terminal(
        self,
        projection: Mapping[str, Any],
        *,
        terminal_outcome_event_id: str | None = None,
        reservation_event_id: str | None = None,
        admission_receipt_id: str | None = None,
        logical_dispatch_id: str | None = None,
        phase: str | None = None,
        provider_failure_key: str | None = None,
    ) -> dict[str, Any] | None:
        candidates = list(projection.get("terminals", {}).values())
        for terminal in candidates:
            if terminal_outcome_event_id and terminal.get("terminal_outcome_id") != terminal_outcome_event_id:
                continue
            if reservation_event_id and terminal.get("reservation_event_id") != reservation_event_id:
                continue
            if admission_receipt_id and terminal.get("admission_receipt_id") != admission_receipt_id:
                continue
            if logical_dispatch_id and terminal.get("logical_dispatch_id") != logical_dispatch_id:
                continue
            if phase and terminal.get("phase") != phase:
                continue
            if provider_failure_key and terminal.get("provider_failure_key") != provider_failure_key:
                continue
            return terminal
        return None

    def _provider_find_lease(self, projection: Mapping[str, Any], lease_id: str) -> dict[str, Any] | None:
        lease = projection.get("provider_probe_leases", {}).get(lease_id)
        if lease and not self._provider_is_close_marker(lease):
            return lease
        return None

    def _provider_find_result(self, projection: Mapping[str, Any], lease_id: str) -> dict[str, Any] | None:
        return next(
            (
                result
                for result in projection.get("provider_probe_results", {}).values()
                if result.get("probe_lease_id") == lease_id
            ),
            None,
        )

    def append_provider_observation(
        self,
        *,
        observation_id: str,
        provider_failure_key: str,
        selected_spec: str,
        phase: str,
        provider_failure_class: str,
        provider_epoch_identity: str,
        terminal_outcome_event_id: str | None = None,
        terminal_event_id: str | None = None,
        reservation_event_id: str | None = None,
        admission_receipt_id: str | None = None,
        logical_dispatch_id: str | None = None,
        actor: str = "megaplan",
    ) -> dict[str, Any]:
        """Append one terminal-linked provider observation, idempotently.

        The legacy call shape remains valid for old ledgers.  When terminal
        context is supplied (or can be resolved from the receipt), the
        observation identity is derived from the canonical terminal and key;
        this prevents an observation from becoming a second streak increment.
        """
        terminal_outcome_event_id = terminal_outcome_event_id or terminal_event_id
        terminal_context_requested = any(
            value is not None
            for value in (
                terminal_outcome_event_id,
                reservation_event_id,
                admission_receipt_id,
                logical_dispatch_id,
            )
        )
        with self._locked() as (fd, records):
            projection = self._project_records(records)
            terminal = self._provider_find_terminal(
                projection,
                terminal_outcome_event_id=terminal_outcome_event_id,
                reservation_event_id=reservation_event_id,
                admission_receipt_id=admission_receipt_id,
                logical_dispatch_id=logical_dispatch_id,
                phase=phase,
                provider_failure_key=provider_failure_key,
            ) if terminal_context_requested else None
            # A receipt/phase/key is enough to recover the terminal id when a
            # DispatchOutcome was created before the ledger assigned its
            # deterministic terminal id.
            if terminal_context_requested and terminal is None and terminal_outcome_event_id is None:
                terminal = self._provider_find_terminal(
                    projection,
                    admission_receipt_id=admission_receipt_id,
                    logical_dispatch_id=logical_dispatch_id,
                    phase=phase,
                    provider_failure_key=provider_failure_key,
                )
            if terminal_outcome_event_id is None and terminal is not None:
                terminal_outcome_event_id = terminal.get("terminal_outcome_id")
            if terminal is not None:
                if terminal.get("outcome_kind") != "provider_exhausted":
                    raise ValueError("provider observation must cite a provider terminal")
                evidence = terminal.get("provider_evidence") or {}
                if terminal.get("provider_failure_key") != provider_failure_key or evidence.get("provider_failure_key") != provider_failure_key:
                    raise ValueError("provider observation key is not terminal-bound")
                if terminal.get("selected_spec") != selected_spec or terminal.get("phase") != phase:
                    raise ValueError("provider observation route context mismatch")
                if evidence.get("provider_epoch_identity") != provider_epoch_identity:
                    raise ValueError("provider observation epoch mismatch")
                expected_id = _stable_id("provider-observation", terminal_outcome_event_id, provider_failure_key)
                if observation_id != expected_id:
                    raise ValueError("provider observation id is not terminal-derived")
            payload = {
                "schema_version": 1,
                "event_type": "provider_observation",
                "event_id": observation_id,
                "observation_id": observation_id,
                "provider_failure_key": provider_failure_key,
                "selected_spec": selected_spec,
                "phase": phase,
                "provider_failure_class": provider_failure_class,
                "provider_epoch_identity": provider_epoch_identity,
                "recorded_at": _now(),
                "actor": actor,
            }
            linkage = {
                "terminal_outcome_event_id": terminal_outcome_event_id or (terminal or {}).get("terminal_outcome_id"),
                "reservation_event_id": reservation_event_id or (terminal or {}).get("reservation_event_id"),
                "admission_receipt_id": admission_receipt_id or (terminal or {}).get("admission_receipt_id"),
                "logical_dispatch_id": logical_dispatch_id or (terminal or {}).get("logical_dispatch_id"),
            }
            payload.update({name: value for name, value in linkage.items() if value})
            prior = self._provider_raw_record(records, observation_id)
            if prior is not None:
                if self._provider_payload_equivalent(prior.get("payload", {}), payload):
                    return prior
                raise ValueError("conflicting provider observation replay")
            return self._append_nbf_locked(fd, payload, records)

    # Explicit name used by the worker seam and acceptance fixtures.
    append_provider_observation_link = append_provider_observation

    def _start_provider_probe_locked(
        self,
        fd: int,
        records: list[dict[str, Any]],
        *,
        provider_failure_key: str,
        provider_epoch_identity: str | None,
        observation_id: str | None,
        parent_reservation_event_id: str | None,
        parent_terminal_event_id: str | None,
        phase: str | None,
        route_identity: str | None,
        route_liveness_identity: str | None,
        retry_not_before_ns: int,
        deadline_ns: int,
        attempt: int,
        now_ns: int | None,
        previous_now_ns: int | None,
        actor: str,
    ) -> dict[str, Any] | None:
        if not isinstance(provider_failure_key, str) or not provider_failure_key:
            raise ValueError("provider probe requires provider_failure_key")
        if provider_epoch_identity is not None and not isinstance(provider_epoch_identity, str):
            raise ValueError("provider probe epoch identity must be text")
        if isinstance(retry_not_before_ns, bool) or not isinstance(retry_not_before_ns, int) or retry_not_before_ns < 0:
            raise ValueError("provider probe retry_not_before_ns must be non-negative")
        if isinstance(deadline_ns, bool) or not isinstance(deadline_ns, int) or deadline_ns < 0:
            raise ValueError("provider probe deadline_ns must be non-negative")
        if deadline_ns < retry_not_before_ns:
            raise ValueError("provider probe deadline precedes retry eligibility")
        if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
            raise ValueError("provider probe attempt must be positive")
        now = self._provider_now_ns(now_ns)
        if previous_now_ns is not None and now < self._provider_now_ns(previous_now_ns):
            # A rolled-back monotonic clock cannot authorize a lease.
            return None
        if now < retry_not_before_ns:
            return None
        projection = self._project_records(records)
        parent = self._provider_find_terminal(
            projection,
            terminal_outcome_event_id=parent_terminal_event_id,
            reservation_event_id=parent_reservation_event_id,
            phase=phase,
            provider_failure_key=provider_failure_key,
        ) if (parent_terminal_event_id or parent_reservation_event_id) else None
        if parent_terminal_event_id and parent is None:
            raise ValueError("provider probe parent terminal is not persisted")
        if parent is not None:
            if parent.get("outcome_kind") != "provider_exhausted":
                raise ValueError("provider probe parent is not a provider terminal")
            if parent_reservation_event_id and parent.get("reservation_event_id") != parent_reservation_event_id:
                raise ValueError("provider probe parent reservation mismatch")
            parent_reservation_event_id = parent.get("reservation_event_id")
            parent_terminal_event_id = parent.get("terminal_outcome_id")
            if phase is not None and parent.get("phase") != phase:
                raise ValueError("provider probe parent phase mismatch")
        # Exactly one active lease may exist for a parent/key/epoch/route.
        for lease in projection.get("provider_probe_leases", {}).values():
            if lease.get("status") not in {"leased", "passed"}:
                continue
            if (
                lease.get("provider_failure_key") == provider_failure_key
                and lease.get("parent_reservation_event_id") == parent_reservation_event_id
                and lease.get("phase") == phase
                and lease.get("route_identity") == route_identity
            ):
                if lease.get("expires_at") == deadline_ns:
                    return self._provider_raw_record(records, lease.get("event_id")) or {"payload": lease}
                raise ValueError("provider probe active lease context conflicts")
        lease_id = _stable_id(
            "provider-probe-start",
            provider_failure_key,
            str(parent_reservation_event_id),
            str(parent_terminal_event_id),
            str(phase),
            str(route_identity),
            str(attempt),
        )
        payload = {
            "schema_version": 1,
            "event_type": "provider_probe_started",
            "event_id": lease_id,
            "probe_lease_id": lease_id,
            "provider_failure_key": provider_failure_key,
            "expires_at": deadline_ns,
            "recorded_at": _now(),
            # The actor suffix is an additive, schema-closed clock-mode bit;
            # projection strips it into ``clock_mode`` for policy consumers.
            "actor": f"{actor}::nbf06-monotonic",
        }
        if any(value is not None for value in (parent_reservation_event_id, phase, route_identity)):
            payload.update({
                "parent_reservation_event_id": parent_reservation_event_id,
                "phase": phase,
                "route_identity": route_identity,
            })
        prior = self._provider_raw_record(records, lease_id)
        if prior is not None:
            if self._provider_payload_equivalent(prior.get("payload", {}), payload):
                return prior
            raise ValueError("conflicting provider probe lease replay")
        return self._append_nbf_locked(fd, payload, records)

    def start_provider_probe_locked(
        self,
        *,
        provider_failure_key: str | None = None,
        provider_epoch_identity: str | None = None,
        observation_id: str | None = None,
        parent_reservation_event_id: str | None = None,
        parent_terminal_event_id: str | None = None,
        phase: str | None = None,
        route_identity: str | None = None,
        route_liveness_identity: str | None = None,
        retry_not_before_ns: int = 0,
        deadline_ns: int | None = None,
        attempt: int = 1,
        now_ns: int | None = None,
        previous_now_ns: int | None = None,
        probe_request: Any = None,
        actor: str = "megaplan",
    ) -> dict[str, Any] | None:
        """Acquire one deadline-gated provider probe lease under the CAS door."""
        if probe_request is not None:
            source = probe_request if isinstance(probe_request, Mapping) else vars(probe_request)
            for name in (
                "provider_failure_key", "provider_epoch_identity", "observation_id",
                "parent_reservation_event_id", "parent_terminal_event_id", "phase",
                "route_identity", "route_liveness_identity", "retry_not_before_ns",
                "deadline_ns", "attempt",
            ):
                value = source.get(name)
                if value is not None or name in {"retry_not_before_ns", "deadline_ns", "attempt"}:
                    if name == "provider_failure_key": provider_failure_key = value
                    elif name == "provider_epoch_identity": provider_epoch_identity = value
                    elif name == "observation_id": observation_id = value
                    elif name == "parent_reservation_event_id": parent_reservation_event_id = value
                    elif name == "parent_terminal_event_id": parent_terminal_event_id = value
                    elif name == "phase": phase = value
                    elif name == "route_identity": route_identity = value
                    elif name == "route_liveness_identity": route_liveness_identity = value
                    elif name == "retry_not_before_ns": retry_not_before_ns = value
                    elif name == "deadline_ns": deadline_ns = value
                    elif name == "attempt": attempt = value
        if deadline_ns is None:
            raise ValueError("provider probe requires deadline_ns")
        with self._locked() as (fd, records):
            return self._start_provider_probe_locked(
                fd,
                records,
                provider_failure_key=provider_failure_key or "",
                provider_epoch_identity=provider_epoch_identity,
                observation_id=observation_id,
                parent_reservation_event_id=parent_reservation_event_id,
                parent_terminal_event_id=parent_terminal_event_id,
                phase=phase,
                route_identity=route_identity,
                route_liveness_identity=route_liveness_identity,
                retry_not_before_ns=retry_not_before_ns,
                deadline_ns=deadline_ns,
                attempt=attempt,
                now_ns=now_ns,
                previous_now_ns=previous_now_ns,
                actor=actor,
            )

    def _record_provider_probe_result_locked(
        self,
        fd: int,
        records: list[dict[str, Any]],
        *,
        probe_lease_id: str,
        provider_failure_key: str,
        passed: bool,
        evidence_digest: str,
        parent_reservation_event_id: str | None,
        phase: str | None,
        route_identity: str | None,
        now_ns: int | None,
        idempotent: bool,
        actor: str,
    ) -> dict[str, Any]:
        projection = self._project_records(records)
        lease = self._provider_find_lease(projection, probe_lease_id)
        if lease is None:
            raise ValueError("provider probe result requires a persisted lease")
        if lease.get("closed") or lease.get("status") not in {"leased"}:
            raise ValueError("provider probe lease is stale or already resolved")
        if lease.get("provider_failure_key") != provider_failure_key:
            raise ValueError("provider probe lease key mismatch")
        expected_parent = lease.get("parent_reservation_event_id")
        expected_phase = lease.get("phase")
        expected_route = lease.get("route_identity")
        for name, expected, actual in (
            ("parent_reservation_event_id", expected_parent, parent_reservation_event_id),
            ("phase", expected_phase, phase),
            ("route_identity", expected_route, route_identity),
        ):
            if expected != actual:
                raise ValueError(f"provider probe lease context mismatch: {name}")
        # New leases use monotonic nanoseconds.  Legacy leases retain their
        # wall-clock seconds behavior for replay compatibility.
        expiry = lease.get("expires_at", 0)
        if lease.get("clock_mode") == "monotonic_ns" or now_ns is not None:
            if self._provider_now_ns(now_ns) >= int(expiry):
                raise ValueError("provider probe lease is expired")
        elif float(expiry) <= datetime.now(timezone.utc).timestamp():
            raise ValueError("provider probe lease is expired")
        event_id = _stable_id("provider_probe_result", probe_lease_id, provider_failure_key, str(bool(passed)), evidence_digest)
        payload = {
            "schema_version": 1,
            "event_type": "provider_probe_result",
            "event_id": event_id,
            "probe_lease_id": probe_lease_id,
            "provider_failure_key": provider_failure_key,
            "passed": bool(passed),
            "evidence_digest": evidence_digest,
            "recorded_at": _now(),
            "actor": actor,
        }
        if any(value is not None for value in (parent_reservation_event_id, phase, route_identity)):
            payload.update({
                "parent_reservation_event_id": parent_reservation_event_id,
                "phase": phase,
                "route_identity": route_identity,
            })
        prior = self._provider_raw_record(records, event_id)
        if prior is not None:
            if self._provider_payload_equivalent(prior.get("payload", {}), payload):
                if idempotent:
                    return prior
                raise ValueError("provider probe lease has already been consumed")
            raise ValueError("conflicting provider probe result replay")
        prior_for_lease = self._provider_find_result(projection, probe_lease_id)
        if prior_for_lease is not None:
            if (
                prior_for_lease.get("provider_failure_key") == provider_failure_key
                and prior_for_lease.get("passed") is bool(passed)
                and prior_for_lease.get("evidence_digest") == evidence_digest
            ):
                if idempotent:
                    return self._provider_raw_record(records, prior_for_lease.get("event_id")) or {"payload": prior_for_lease}
            raise ValueError("provider probe lease has already been consumed")
        return self._append_nbf_locked(fd, payload, records)

    def record_provider_probe_result_locked(
        self,
        result: Any = None,
        *,
        probe_lease_id: str | None = None,
        provider_failure_key: str | None = None,
        result_kind: str | None = None,
        passed: bool | None = None,
        evidence_digest: str | None = None,
        parent_reservation_event_id: str | None = None,
        phase: str | None = None,
        route_identity: str | None = None,
        now_ns: int | None = None,
        actor: str = "megaplan",
    ) -> dict[str, Any]:
        """Fence and persist a probe result after execution outside the lock."""
        if result is not None:
            source = result if isinstance(result, Mapping) else vars(result)
            probe_lease_id = source.get("probe_lease_id", probe_lease_id)
            provider_failure_key = source.get("provider_failure_key", provider_failure_key)
            result_kind = source.get("result", source.get("result_kind", result_kind))
            passed = source.get("passed", passed)
            evidence_digest = source.get("evidence_digest", evidence_digest)
            parent_reservation_event_id = source.get("parent_reservation_event_id", parent_reservation_event_id)
            phase = source.get("phase", phase)
            route_identity = source.get("route_identity", route_identity)
        if result_kind is not None:
            if result_kind not in {"passed", "failed", "unknown"}:
                raise ValueError("provider probe result kind is invalid")
            passed = result_kind == "passed"
        if passed is None:
            raise ValueError("provider probe result requires passed/result")
        if not isinstance(passed, bool):
            raise ValueError("provider probe result passed must be boolean")
        if not probe_lease_id or not provider_failure_key or not evidence_digest:
            raise ValueError("provider probe result requires lease, key, and evidence")
        with self._locked() as (fd, records):
            return self._record_provider_probe_result_locked(
                fd,
                records,
                probe_lease_id=probe_lease_id,
                provider_failure_key=provider_failure_key,
                passed=passed,
                evidence_digest=evidence_digest,
                parent_reservation_event_id=parent_reservation_event_id,
                phase=phase,
                route_identity=route_identity,
                now_ns=now_ns,
                idempotent=True,
                actor=actor,
            )

    def append_provider_probe_result(self, **kwargs: Any) -> dict[str, Any]:
        return self.record_provider_probe_result_locked(**kwargs)

    def _close_provider_probe_locked(
        self,
        fd: int,
        records: list[dict[str, Any]],
        *,
        probe_lease_id: str,
        provider_failure_key: str | None,
        parent_reservation_event_id: str | None,
        phase: str | None,
        route_identity: str | None,
        now_ns: int | None,
        close_reason: str | None,
        retry_not_before_ns: int,
        actor: str,
    ) -> dict[str, Any]:
        projection = self._project_records(records)
        lease = self._provider_find_lease(projection, probe_lease_id)
        if lease is None:
            raise ValueError("provider probe closure requires a persisted lease")
        key = provider_failure_key or lease.get("provider_failure_key")
        if key != lease.get("provider_failure_key"):
            raise ValueError("provider probe closure key mismatch")
        for name, expected, actual in (
            ("parent_reservation_event_id", lease.get("parent_reservation_event_id"), parent_reservation_event_id),
            ("phase", lease.get("phase"), phase),
            ("route_identity", lease.get("route_identity"), route_identity),
        ):
            if expected != actual:
                raise ValueError(f"provider probe closure context mismatch: {name}")
        prior_closure = projection.get("provider_probe_closures", {}).get(probe_lease_id)
        if prior_closure is not None:
            prior_reason = prior_closure.get("close_reason") or self._provider_close_reason(prior_closure)
            if close_reason is not None and close_reason != prior_reason:
                raise ValueError("conflicting provider probe closure replay")
            return self._provider_raw_record(records, prior_closure.get("event_id")) or {"payload": prior_closure}
        result = self._provider_find_result(projection, probe_lease_id)
        now = self._provider_now_ns(now_ns) if (lease.get("clock_mode") == "monotonic_ns" or now_ns is not None) else int(datetime.now(timezone.utc).timestamp())
        expiry = int(lease.get("expires_at", 0)) if lease.get("clock_mode") == "monotonic_ns" or now_ns is not None else float(lease.get("expires_at", 0))
        if result is None:
            if now < expiry:
                raise ValueError("provider probe cannot close before a result or deadline")
            reason = "expired"
            result_id = ""
        elif now >= expiry:
            reason = "expired"
            result_id = result.get("event_id", "")
        elif result.get("passed") is True:
            reason = close_reason or "passed"
            if reason != "passed":
                raise ValueError("passed provider probe requires passed closure")
            result_id = result.get("event_id", "")
        else:
            reason = close_reason or "failed"
            if reason not in {"failed", "unknown", "expired"}:
                raise ValueError("failed provider probe closure is invalid")
            result_id = result.get("event_id", "")
        if isinstance(retry_not_before_ns, bool) or not isinstance(retry_not_before_ns, int) or retry_not_before_ns < 0:
            raise ValueError("provider probe retry_not_before_ns must be non-negative")
        marker_id = _stable_id("provider_probe_closed", probe_lease_id, result_id, reason, str(retry_not_before_ns))
        payload = {
            "schema_version": 1,
            "event_type": "provider_probe_started",
            "event_id": marker_id,
            "probe_lease_id": probe_lease_id,
            "provider_failure_key": key,
            "expires_at": lease.get("expires_at"),
            "recorded_at": _now(),
            "actor": actor,
            "route_identity": f"__NBF06_PROBE_CLOSED__:{reason}:{retry_not_before_ns}",
        }
        if lease.get("parent_reservation_event_id") is not None or lease.get("phase") is not None:
            payload.update({
                "parent_reservation_event_id": lease.get("parent_reservation_event_id"),
                "phase": lease.get("phase"),
            })
        prior = self._provider_raw_record(records, marker_id)
        if prior is not None:
            if self._provider_payload_equivalent(prior.get("payload", {}), payload):
                return prior
            raise ValueError("conflicting provider probe closure replay")
        return self._append_nbf_locked(fd, payload, records)

    def close_provider_probe_locked(
        self,
        *,
        probe_lease_id: str,
        provider_failure_key: str | None = None,
        parent_reservation_event_id: str | None = None,
        phase: str | None = None,
        route_identity: str | None = None,
        now_ns: int | None = None,
        close_reason: str | None = None,
        retry_not_before_ns: int = 0,
        actor: str = "megaplan",
    ) -> dict[str, Any]:
        with self._locked() as (fd, records):
            return self._close_provider_probe_locked(
                fd,
                records,
                probe_lease_id=probe_lease_id,
                provider_failure_key=provider_failure_key,
                parent_reservation_event_id=parent_reservation_event_id,
                phase=phase,
                route_identity=route_identity,
                now_ns=now_ns,
                close_reason=close_reason,
                retry_not_before_ns=retry_not_before_ns,
                actor=actor,
            )

    append_provider_probe_closed = close_provider_probe_locked

    def record_provider_recovery_verified_locked(
        self,
        *,
        plan_id: str,
        phase: str,
        probe_lease_id: str,
        provider_failure_key: str | None = None,
        parent_reservation_event_id: str | None = None,
        parent_terminal_event_id: str | None = None,
        route_identity: str | None = None,
        authoritative_subject: str = "provider_probe",
        before: Any = None,
        after: Any = None,
        logical_dispatch_id: str | None = None,
        dispatch_family_id: str | None = None,
        actor: str = "megaplan",
    ) -> dict[str, Any]:
        """Mint one producer-bound ChangedPrecondition after a closed pass.

        This is intentionally a ledger CAS adapter, not a second recovery
        writer.  The existing typed ``produce_provider_recovery_verified``
        producer remains responsible for source identities; this method only
        supplies a probe-derived source when the caller does not provide one.
        """
        from arnold_pipelines.megaplan.incident.schema import (
            ProviderRecoverySource,
            _digest,
            _validate_producer_binding,
            produce_provider_recovery_verified,
        )

        with self._locked() as (fd, records):
            projection = self._project_records(records)
            lease = self._provider_find_lease(projection, probe_lease_id)
            if lease is None:
                raise ValueError("provider recovery requires a persisted probe lease")
            if lease.get("provider_failure_key") != provider_failure_key and provider_failure_key is not None:
                raise ValueError("provider recovery probe key mismatch")
            key = provider_failure_key or lease.get("provider_failure_key")
            if lease.get("parent_reservation_event_id") != parent_reservation_event_id and parent_reservation_event_id is not None:
                raise ValueError("provider recovery parent reservation mismatch")
            if lease.get("phase") != phase:
                raise ValueError("provider recovery phase mismatch")
            if lease.get("route_identity") != route_identity and route_identity is not None:
                raise ValueError("provider recovery route mismatch")
            closure = projection.get("provider_probe_closures", {}).get(probe_lease_id)
            if lease.get("clock_mode") == "monotonic_ns" and (closure is None or closure.get("close_reason") != "passed"):
                raise ValueError("provider recovery requires a passed, closed probe")
            result = self._provider_find_result(projection, probe_lease_id)
            if result is None or result.get("passed") is not True:
                raise ValueError("provider recovery requires a passed canonical probe")
            if parent_terminal_event_id is not None:
                terminal = self._provider_find_terminal(
                    projection,
                    terminal_outcome_event_id=parent_terminal_event_id,
                    reservation_event_id=parent_reservation_event_id,
                    phase=phase,
                    provider_failure_key=key,
                )
                if terminal is None:
                    raise ValueError("provider recovery parent terminal is not persisted")
            if before is None:
                before = ProviderRecoverySource(
                    "provider-probe-v1",
                    authoritative_subject,
                    f"{probe_lease_id}:before",
                    {"provider_failure_key": key, "probe_status": "failed"},
                    key,
                )
            if after is None:
                after = ProviderRecoverySource(
                    "provider-probe-v1",
                    authoritative_subject,
                    f"{probe_lease_id}:after",
                    {"provider_failure_key": key, "probe_status": "passed"},
                    key,
                )
            proof = produce_provider_recovery_verified(
                plan_id=plan_id,
                phase=phase,
                authoritative_subject=authoritative_subject,
                before=before,
                after=after,
                evidence_event_id=result.get("event_id"),
                evidence=result,
                actor=actor,
                dispatch_family_id=dispatch_family_id,
                logical_dispatch_id=logical_dispatch_id,
                route_identity=route_identity,
            )
            existing = projection.get("changed_preconditions", {}).get(proof.event_id)
            if existing is not None:
                return self._provider_raw_record(records, proof.event_id) or {"payload": existing}
            _validate_producer_binding(proof)
            cited = result
            if _digest(cited) != proof.evidence_digest or proof.evidence_snapshot != cited:
                raise ValueError("provider recovery evidence is not the cited probe")
            return self._append_nbf_locked(fd, proof.to_dict(), records, _changed_precondition=proof)

    def record_provider_hold_locked(
        self,
        *,
        provider_failure_key: str,
        phase: str,
        reason: str = "provider_observation_wait",
        terminal_outcome_event_id: str | None = None,
        retry_not_before_ns: int | None = None,
        actor: str = "megaplan",
    ) -> dict[str, Any]:
        """Return a projected hold proof without creating a second store."""
        with self._locked() as (_fd, records):
            projection = self._project_records(records)
            return {
                "status": "held",
                "reason": reason,
                "provider_failure_key": provider_failure_key,
                "phase": phase,
                "terminal_outcome_event_id": terminal_outcome_event_id,
                "retry_not_before_ns": retry_not_before_ns,
                "projection_version": projection["projection_version"],
                "actor": actor,
            }

    def record_provider_success_locked(
        self,
        *,
        provider_failure_key: str | None = None,
        phase: str | None = None,
        terminal_outcome_event_id: str | None = None,
        actor: str = "megaplan",
    ) -> dict[str, Any]:
        """Read the terminal-derived success reset through the ledger door."""
        with self._locked() as (_fd, records):
            projection = self._project_records(records)
            stream = next(
                (
                    value for value in projection.get("provider_streaks", {}).values()
                    if (provider_failure_key is None or value.get("provider_failure_key") == provider_failure_key)
                    and (phase is None or value.get("phase") == phase)
                ),
                None,
            )
            return {
                "status": "success",
                "provider_failure_key": provider_failure_key,
                "phase": phase,
                "terminal_outcome_event_id": terminal_outcome_event_id,
                "observation_streak": (stream or {}).get("observation_streak", 0),
                "actor": actor,
            }

    def append_probe_result(
        self,
        *,
        probe_lease_id: str,
        provider_failure_key: str,
        passed: bool,
        evidence_digest: str,
        parent_reservation_event_id: str | None = None,
        phase: str | None = None,
        route_identity: str | None = None,
        now_ns: int | None = None,
        actor: str = "megaplan",
    ) -> dict[str, Any]:
        """Legacy result door retaining its historical duplicate rejection."""
        if not probe_lease_id or not provider_failure_key or not evidence_digest:
            raise ValueError("provider probe result requires lease, key, and evidence")
        with self._locked() as (fd, records):
            return self._record_provider_probe_result_locked(
                fd,
                records,
                probe_lease_id=probe_lease_id,
                provider_failure_key=provider_failure_key,
                passed=passed,
                evidence_digest=evidence_digest,
                parent_reservation_event_id=parent_reservation_event_id,
                phase=phase,
                route_identity=route_identity,
                now_ns=now_ns,
                idempotent=False,
                actor=actor,
            )

    def consume_changed_precondition(self, event: Any, *, actor: str = "megaplan") -> dict[str, Any]:
        from arnold_pipelines.megaplan.incident.schema import ChangedPrecondition, _validate_producer_binding
        obj = event if isinstance(event, ChangedPrecondition) else ChangedPrecondition.from_dict(event)
        _validate_producer_binding(obj)
        with self._locked() as (fd, records):
            projected = self._project_records(records)
            persisted = projected["changed_preconditions"].get(obj.event_id)
            if persisted is None or any(persisted.get(k) != obj.to_dict().get(k) for k in obj.to_dict()):
                raise ValueError("changed precondition is not the persisted authoritative event")
            if persisted.get("consumed"):
                raise ValueError("changed precondition already consumed")
            return self._append_nbf_locked(fd, {"schema_version": 1, "event_type": "changed_precondition_consumed", "event_id": _stable_id("consume", obj.event_id), "changed_precondition_event_id": obj.event_id, "recorded_at": _now(), "actor": actor}, records)

    def create_probe_lease(self, *, provider_failure_key: str, expires_at: float, parent_reservation_event_id: str | None = None, phase: str | None = None, route_identity: str | None = None, retry_not_before_ns: int | None = None, deadline_ns: int | None = None, now_ns: int | None = None, parent_terminal_event_id: str | None = None, provider_epoch_identity: str | None = None, attempt: int = 1, actor: str = "megaplan") -> dict[str, Any] | None:
        # New callers use the explicit monotonic contract.  Keep the original
        # wall-clock API below so old persisted fixtures remain byte-stable.
        if deadline_ns is not None or retry_not_before_ns is not None or now_ns is not None or parent_terminal_event_id is not None or provider_epoch_identity is not None:
            return self.start_provider_probe_locked(
                provider_failure_key=provider_failure_key,
                provider_epoch_identity=provider_epoch_identity,
                parent_reservation_event_id=parent_reservation_event_id,
                parent_terminal_event_id=parent_terminal_event_id,
                phase=phase,
                route_identity=route_identity,
                retry_not_before_ns=retry_not_before_ns or 0,
                deadline_ns=deadline_ns if deadline_ns is not None else int(expires_at),
                now_ns=now_ns,
                attempt=attempt,
                actor=actor,
            )
        with self._locked() as (fd, records):
            if any(r.get("payload", {}).get("event_type") == "provider_probe_started" and not self._provider_is_close_marker(r.get("payload", {})) and r.get("payload", {}).get("provider_failure_key") == provider_failure_key for r in records):
                raise ValueError("provider probe lease already exists")
            projection = self._project_records(records)
            lease_id = _stable_id("probe", provider_failure_key, str(projection["projection_version"]))
            payload = {"schema_version": 1, "event_type": "provider_probe_started", "event_id": lease_id, "probe_lease_id": lease_id, "provider_failure_key": provider_failure_key, "expires_at": expires_at, "recorded_at": _now(), "actor": actor}
            if any(value is not None for value in (parent_reservation_event_id, phase, route_identity)):
                payload.update({"parent_reservation_event_id": parent_reservation_event_id, "phase": phase, "route_identity": route_identity})
            return self._append_nbf_locked(fd, payload, records)

    def append_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Redact, validate, and append one incident event to the canonical ledger."""
        payload = validate_incident_event(event)
        kind = payload.get("type") or payload.get("event_kind") or "event"
        return self._journal.emit(
            f"incident.{kind}",
            payload=payload,
        )

    def append_maintenance_event(
        self,
        event: dict[str, Any] | Any,
    ) -> dict[str, Any]:
        """Strict-route one Maintenance event with atomic idempotency.

        *event* may be a :class:`MaintenanceEvent` or
        :class:`OperationalEvent` model, or its canonical dict form.  It is
        strict-decoded through the shared Maintenance codec (unknown/missing
        fields and identity mismatches fail before any write), then appended
        atomically keyed by the canonical lifecycle idempotency key plus
        digest:

        * the recorded key is the strict action key for operational lifecycle
          rows (so distinct request/source-change/installation/retrigger/
          progress/checkpoint/terminal/recurrence/escalation records coexist
          for ONE occurrence) with the legacy ``occurrence_id`` fallback for
          M2 detection / efficiency_analysis / audit_report rows;
        * an exact duplicate returns the PRIOR committed record (same seq);
        * a divergent duplicate raises :class:`MaintenanceEventConflict`
          without appending;
        * otherwise exactly one record is appended.

        Never touches runtime ``.megaplan/incident-ledger`` data: the caller
        supplies the root.
        """
        from arnold_pipelines.megaplan.maintenance.events import (
            MaintenanceEvent,
            OperationalEvent,
        )
        from arnold_pipelines.megaplan.maintenance.identity import (
            MaintenanceCodecError,
            canonical_digest,
            canonical_dumps,
            strict_loads,
        )

        if isinstance(event, (MaintenanceEvent, OperationalEvent)):
            model = event
        else:
            try:
                model = strict_loads(MaintenanceEvent, event)
            except MaintenanceCodecError:
                try:
                    model = strict_loads(OperationalEvent, event)
                except MaintenanceCodecError as exc:
                    raise ValueError(
                        f"maintenance event strict decode failed: {exc}"
                    ) from exc
        payload = json.loads(canonical_dumps(model))
        digest = canonical_digest(model)
        kind_name = getattr(model, "event_kind", None) or getattr(
            model, "action_kind", None
        )
        return self._journal.append_maintenance(
            kind=f"incident.{kind_name.value}",
            payload=payload,
            idempotency_key=lifecycle_idempotency_key(payload),
            digest=digest,
        )

    def lookup_maintenance_event(self, idempotency_key: str) -> dict[str, Any] | None:
        """Return the committed record for *idempotency_key*, or ``None``.

        *idempotency_key* is the canonical lifecycle idempotency key: the
        strict action key for operational lifecycle rows, or ``occurrence_id``
        for legacy M2 rows.
        """
        return self._journal.lookup_maintenance(idempotency_key)

    def append_authorized_lifecycle_event(
        self,
        *,
        occurrence_id: str,
        transition: str,
        owner: str,
        grant_id: str,
        custody_epoch: int,
        run_authority_check: Callable[[str, str], bool],
        custody_check: Callable[[str, int, str], bool],
        session_id: str = "",
    ) -> dict[str, Any]:
        """Append an acknowledged/resolved event after live authority rereads.

        The notification store intentionally has no lifecycle writer. This
        method is the canonical incident-owned writer: the current Run
        Authority and Custody sources validate the owner/grant/epoch before
        an append-only event is committed. A card or caller-supplied JSON
        authority blob cannot satisfy either check.
        """
        if transition not in {"acknowledged", "resolved"}:
            raise ValueError("incident lifecycle transition must be acknowledged or resolved")
        if not isinstance(owner, str) or not owner.strip():
            raise ValueError("owner must be a non-empty canonical identity")
        if not isinstance(grant_id, str) or not grant_id.strip():
            raise ValueError("grant_id must be a non-empty current grant identity")
        if not isinstance(custody_epoch, int) or isinstance(custody_epoch, bool) or custody_epoch < 1:
            raise ValueError("custody_epoch must be a positive current epoch")
        if not callable(run_authority_check) or not run_authority_check(grant_id, owner):
            raise ValueError("Run Authority grant/owner is not current")
        if not callable(custody_check) or not custody_check(owner, custody_epoch, occurrence_id):
            raise ValueError("Custody owner/epoch is not current")
        occurrence_id = str(occurrence_id).strip()
        if not occurrence_id:
            raise ValueError("occurrence_id must be a non-empty canonical identity")
        event_key = hashlib.sha256(
            json.dumps(
                [occurrence_id, transition, owner, grant_id, custody_epoch],
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        now = datetime.now(timezone.utc).isoformat()
        return self.append_event(
            {
                "schema_version": 1,
                "event_id": f"incident-lifecycle-{event_key}",
                "ts": now,
                "type": transition,
                "actor": owner,
                "scope": f"incident:{occurrence_id}",
                "outcome": "accepted",
                "summary": f"Incident {transition} through canonical Run Authority and Custody",
                "evidence": [
                    f"run-authority:{grant_id}",
                    f"custody:{owner}:{custody_epoch}",
                ],
                "parent_event_ids": [],
                "next_expected_event": None,
                "deadline_ts": None,
                "trigger_event_id": None,
                "incident_id": occurrence_id,
                "session_id": session_id or None,
                "run_authority_grant_id": grant_id,
                "custody_epoch": custody_epoch,
            }
        )


class RuntimeTransitionWriter:
    """Append-only writer for the five typed runtime transition events.

    Every emit is a pure ledger append routed through :class:`IncidentLedger`
    (validate -> redact -> flocked monotonic append). Emitting NEVER performs
    a dispatch side effect and never triggers a scan — mirror the
    side-effect-free watchdog bridge event pattern.

    Failures propagate and MUST block dispatch:

    * ``ValueError`` — policy rejection (non-retryable ``fallback_taken``,
      unknown failure class, missing required field, malformed digest).
    * ``OSError`` — journal write failure.

    A caller MUST treat either exception as "the transition was not durably
    recorded, so do not perform the dispatch side effect".
    """

    def __init__(
        self,
        root: Path | None = None,
        *,
        ledger: IncidentLedger | None = None,
    ) -> None:
        self._ledger = ledger if ledger is not None else IncidentLedger(root)

    # ── public emit methods ────────────────────────────────────────────

    def emit_manifest_selected(
        self,
        *,
        scope: str,
        candidate_to: str | dict[str, Any],
        candidate_from: str | dict[str, Any] | None = None,
        error: str = "",
        attempt: int | str = "",
        chain_spec_sha256: str = "",
        evidence: list[Any] | None = None,
        actor: str = "runtime",
        session_id: str = "",
        summary: str | None = None,
    ) -> dict[str, Any]:
        """Record ``runtime.manifest_selected`` before a runtime selection."""
        return self._emit(
            EVENT_MANIFEST_SELECTED,
            scope=scope,
            failure_class=None,
            chain_spec_sha256=chain_spec_sha256,
            attempt=attempt,
            error=error,
            evidence=evidence if evidence is not None else [],
            candidate_from=candidate_from,
            candidate_to=candidate_to,
            actor=actor,
            session_id=session_id,
            summary=summary,
        )

    def emit_deviation_declared(
        self,
        *,
        scope: str,
        failure_class: str,
        error: str,
        chain_spec_sha256: str,
        candidate_from: str | dict[str, Any] | None = None,
        candidate_to: str | dict[str, Any] | None = None,
        attempt: int | str = "",
        evidence: list[Any] | None = None,
        actor: str = "runtime",
        session_id: str = "",
        summary: str | None = None,
    ) -> dict[str, Any]:
        """Record ``runtime.deviation_declared`` for a declared deviation."""
        return self._emit(
            EVENT_DEVIATION_DECLARED,
            scope=scope,
            failure_class=failure_class,
            chain_spec_sha256=chain_spec_sha256,
            attempt=attempt,
            error=error,
            evidence=evidence if evidence is not None else [],
            candidate_from=candidate_from,
            candidate_to=candidate_to,
            actor=actor,
            session_id=session_id,
            summary=summary,
        )

    def emit_fallback_considered(
        self,
        *,
        scope: str,
        failure_class: str,
        chain_spec_sha256: str,
        candidate_from: str | dict[str, Any] | None = None,
        candidate_to: str | dict[str, Any] | None = None,
        error: str = "",
        attempt: int | str = "",
        evidence: list[Any] | None = None,
        actor: str = "runtime",
        session_id: str = "",
        summary: str | None = None,
    ) -> dict[str, Any]:
        """Record ``runtime.fallback_considered`` before a fallback decision."""
        return self._emit(
            EVENT_FALLBACK_CONSIDERED,
            scope=scope,
            failure_class=failure_class,
            chain_spec_sha256=chain_spec_sha256,
            attempt=attempt,
            error=error,
            evidence=evidence if evidence is not None else [],
            candidate_from=candidate_from,
            candidate_to=candidate_to,
            actor=actor,
            session_id=session_id,
            summary=summary,
        )

    def emit_fallback_taken(
        self,
        *,
        scope: str,
        failure_class: str,
        chain_spec_sha256: str,
        candidate_from: str | dict[str, Any] | None = None,
        candidate_to: str | dict[str, Any] | None = None,
        error: str = "",
        attempt: int | str = "",
        evidence: list[Any] | None = None,
        actor: str = "runtime",
        session_id: str = "",
        summary: str | None = None,
    ) -> dict[str, Any]:
        """Record ``runtime.fallback_taken`` — only for retryable classes.

        Raises
        ------
        ValueError
            When *failure_class* is not in :data:`RETRYABLE_FAILURE_CLASSES`.
            Non-retryable deviations MUST be recorded with
            :meth:`emit_fallback_rejected` instead.
        """
        return self._emit(
            EVENT_FALLBACK_TAKEN,
            scope=scope,
            failure_class=failure_class,
            chain_spec_sha256=chain_spec_sha256,
            attempt=attempt,
            error=error,
            evidence=evidence if evidence is not None else [],
            candidate_from=candidate_from,
            candidate_to=candidate_to,
            actor=actor,
            session_id=session_id,
            summary=summary,
        )

    def emit_fallback_rejected(
        self,
        *,
        scope: str,
        failure_class: str,
        chain_spec_sha256: str,
        candidate_from: str | dict[str, Any] | None = None,
        candidate_to: str | dict[str, Any] | None = None,
        error: str = "",
        attempt: int | str = "",
        evidence: list[Any] | None = None,
        actor: str = "runtime",
        session_id: str = "",
        summary: str | None = None,
    ) -> dict[str, Any]:
        """Record ``runtime.fallback_rejected`` for a declined fallback."""
        return self._emit(
            EVENT_FALLBACK_REJECTED,
            scope=scope,
            failure_class=failure_class,
            chain_spec_sha256=chain_spec_sha256,
            attempt=attempt,
            error=error,
            evidence=evidence if evidence is not None else [],
            candidate_from=candidate_from,
            candidate_to=candidate_to,
            actor=actor,
            session_id=session_id,
            summary=summary,
        )

    # ── shared emit + failure-class gate ───────────────────────────────

    def _emit(
        self,
        event_type: str,
        *,
        scope: str,
        failure_class: str | None,
        chain_spec_sha256: str,
        attempt: int | str,
        error: str,
        evidence: list[Any],
        candidate_from: str | dict[str, Any] | None,
        candidate_to: str | dict[str, Any] | None,
        actor: str,
        session_id: str,
        summary: str | None,
    ) -> dict[str, Any]:
        if event_type not in _EVENT_ID_PREFIXES:
            raise ValueError(f"unknown runtime transition event type: {event_type!r}")
        if not isinstance(scope, str) or not scope.strip():
            raise ValueError("scope must be a non-empty canonical identity")
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("actor must be a non-empty canonical identity")
        if not isinstance(session_id, str):
            raise ValueError("session_id must be a string")
        if not isinstance(error, str):
            raise ValueError("error must be a normalized string")
        if not isinstance(attempt, (int, str)) or isinstance(attempt, bool):
            raise ValueError("attempt must be an int or a string")
        if not isinstance(evidence, list):
            raise ValueError("evidence must be a list")
        for label, value in (
            ("candidate_from", candidate_from),
            ("candidate_to", candidate_to),
        ):
            if value is not None and not isinstance(value, (str, dict)):
                raise ValueError(f"{label} must be a string, a dict, or None")
            if isinstance(value, dict):
                try:
                    json.dumps(value, sort_keys=True, separators=(",", ":"))
                except (TypeError, ValueError) as exc:
                    raise ValueError(
                        f"{label} must be JSON serializable"
                    ) from exc
        chain_spec_sha256 = _normalize_chain_digest(chain_spec_sha256)

        # ── failure-class policy ───────────────────────────────────────
        if failure_class is not None:
            if not isinstance(failure_class, str) or not failure_class.strip():
                raise ValueError("failure_class must be a non-empty string")
            failure_class = failure_class.strip()
            if failure_class not in KNOWN_FAILURE_CLASSES:
                raise ValueError(
                    f"failure_class must be one of {sorted(KNOWN_FAILURE_CLASSES)} "
                    f"(got {failure_class!r})"
                )
        if event_type in {
            EVENT_DEVIATION_DECLARED,
            EVENT_FALLBACK_CONSIDERED,
            EVENT_FALLBACK_TAKEN,
            EVENT_FALLBACK_REJECTED,
        }:
            if not failure_class:
                raise ValueError(f"{event_type} requires a failure_class")
            if not chain_spec_sha256:
                raise ValueError(f"{event_type} requires chain_spec_sha256")
        if event_type == EVENT_FALLBACK_TAKEN and not is_retryable_failure_class(
            failure_class
        ):
            raise ValueError(
                f"runtime.fallback_taken requires a retryable failure class "
                f"(one of {sorted(RETRYABLE_FAILURE_CLASSES)}); non-retryable "
                f"deviations must be recorded with emit_fallback_rejected "
                f"(got {failure_class!r})"
            )

        # ── event assembly ─────────────────────────────────────────────
        base_summary = _DEFAULT_SUMMARIES[event_type]
        if failure_class:
            base_summary = f"{base_summary} (failure_class={failure_class})"
        now = datetime.now(timezone.utc).isoformat()
        event: dict[str, Any] = {
            "schema_version": 1,
            "event_id": f"{_EVENT_ID_PREFIXES[event_type]}-{uuid.uuid4().hex[:12]}",
            "ts": now,
            "type": event_type,
            "actor": actor,
            "scope": scope,
            "outcome": _DEFAULT_OUTCOMES[event_type],
            "summary": summary if summary is not None else base_summary,
            "evidence": evidence,
            "parent_event_ids": [],
            "next_expected_event": None,
            "deadline_ts": None,
            "trigger_event_id": None,
            "candidate_from": candidate_from,
            "candidate_to": candidate_to,
            "error": error,
            "attempt": attempt,
            "chain_spec_sha256": chain_spec_sha256,
            "failure_class": failure_class,
            "session_id": session_id or None,
        }
        return self._ledger.append_event(event)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for bash wrappers: append one typed runtime transition.

    A non-zero exit (or a raised exception) means the transition was NOT
    durably recorded — callers MUST treat it as "do not dispatch". On
    success the full journal envelope (with ``seq`` and ``kind``) is printed
    as one JSON line to stdout.

    Exit codes: 0 = appended; 1 = policy rejection / ledger write failure
    (nothing written); 2 = usage error (argparse).
    """
    short_names = {
        event_type.removeprefix("runtime."): event_type
        for event_type in RUNTIME_TRANSITION_EVENT_TYPES
    }
    choices = list(short_names) + list(RUNTIME_TRANSITION_EVENT_TYPES)

    parser = argparse.ArgumentParser(
        prog="megaplan runtime-transition",
        description=(
            "Append one typed runtime transition event to the incident ledger "
            "BEFORE any dispatch side effect. Non-zero exit = do not dispatch."
        ),
    )
    parser.add_argument(
        "event",
        choices=choices,
        help=(
            "manifest_selected | deviation_declared | fallback_considered | "
            "fallback_taken | fallback_rejected (dotted form also accepted)"
        ),
    )
    parser.add_argument(
        "--root",
        default=None,
        help="workspace root for the incident ledger (default: cwd)",
    )
    parser.add_argument(
        "--scope",
        required=True,
        help="session-scoped identity, e.g. chain:<session-id>",
    )
    parser.add_argument("--actor", default="runtime", help="attribution identity")
    parser.add_argument(
        "--session-id", default="", help="optional session id for the payload"
    )
    parser.add_argument(
        "--candidate-from",
        default=None,
        help="previous candidate: plain string or JSON value",
    )
    parser.add_argument(
        "--candidate-to",
        default=None,
        help="selected/fallback candidate: plain string or JSON value",
    )
    parser.add_argument("--error", default="", help="normalized error string")
    parser.add_argument(
        "--attempt", default="", help="attempt number or attempt id"
    )
    parser.add_argument(
        "--chain-spec-sha256",
        default="",
        help="contract digest 'sha256:<64 hex>' (required for deviation/fallback events)",
    )
    parser.add_argument(
        "--failure-class",
        default=None,
        help="one of availability, infrastructure, auth, config, semantic, schema, test, evidence, execute",
    )
    parser.add_argument(
        "--evidence",
        default="[]",
        help="JSON array of evidence references (default: '[]')",
    )
    parser.add_argument("--summary", default=None, help="override the summary text")

    args = parser.parse_args(argv)
    event_type = short_names.get(args.event, args.event)

    try:
        evidence = json.loads(args.evidence)
        if not isinstance(evidence, list):
            raise ValueError("--evidence must decode to a JSON array")
    except json.JSONDecodeError as exc:
        print(f"invalid --evidence JSON: {exc}", file=sys.stderr)
        return 1

    def _candidate(value: str | None) -> str | dict[str, Any] | None:
        if value is None:
            return None
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value

    writer = RuntimeTransitionWriter(Path(args.root) if args.root else None)
    try:
        if event_type == EVENT_MANIFEST_SELECTED:
            appended = writer.emit_manifest_selected(
                scope=args.scope,
                candidate_to=_candidate(args.candidate_to),
                candidate_from=_candidate(args.candidate_from),
                error=args.error,
                attempt=args.attempt,
                chain_spec_sha256=args.chain_spec_sha256,
                evidence=evidence,
                actor=args.actor,
                session_id=args.session_id,
                summary=args.summary,
            )
        else:
            emit = {
                EVENT_DEVIATION_DECLARED: writer.emit_deviation_declared,
                EVENT_FALLBACK_CONSIDERED: writer.emit_fallback_considered,
                EVENT_FALLBACK_TAKEN: writer.emit_fallback_taken,
                EVENT_FALLBACK_REJECTED: writer.emit_fallback_rejected,
            }[event_type]
            appended = emit(
                scope=args.scope,
                failure_class=args.failure_class,
                chain_spec_sha256=args.chain_spec_sha256,
                candidate_from=_candidate(args.candidate_from),
                candidate_to=_candidate(args.candidate_to),
                error=args.error,
                attempt=args.attempt,
                evidence=evidence,
                actor=args.actor,
                session_id=args.session_id,
                summary=args.summary,
            )
    except (ValueError, OSError) as exc:
        print(f"runtime transition not recorded ({event_type}): {exc}", file=sys.stderr)
        return 1

    print(json.dumps(appended, sort_keys=True, separators=(",", ":")))
    return 0


__all__ = [
    "IncidentLedger",
    "MaintenanceEventConflict",
    "RuntimeTransitionWriter",
    "EVENT_MANIFEST_SELECTED",
    "EVENT_DEVIATION_DECLARED",
    "EVENT_FALLBACK_CONSIDERED",
    "EVENT_FALLBACK_TAKEN",
    "EVENT_FALLBACK_REJECTED",
    "RUNTIME_TRANSITION_EVENT_TYPES",
    "RETRYABLE_FAILURE_CLASSES",
    "NON_RETRYABLE_FAILURE_CLASSES",
    "KNOWN_FAILURE_CLASSES",
    "is_retryable_failure_class",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
