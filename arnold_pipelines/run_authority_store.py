"""Durable owner boundary for the generic Run Authority contracts.

The contract package intentionally remains persistence-neutral.  This module is
the small adapter that gives those contracts a real owner-backed journal:

* ``read_view(run_id, revision)`` returns the exact contract records and a
  strictly integer journal cursor;
* ``compare_and_append(...)`` performs an atomic cursor compare-and-swap in a
  SQLite transaction; and
* retries are content-safe and deterministic (one idempotency identity and
  one GLEK per journal record).

Custody and WBC remain separate canonical stores.  This adapter stores only
actual Run Authority contract instances; it never turns a projection, source
cursor, or arbitrary mapping into authority.  In particular, a
``SourceCursorVector.vector_id`` is never accepted or converted as a cursor.
The only value accepted for CAS ordering is a non-negative ``int`` (``bool``
is rejected as a Python integer subclass).
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import time
from typing import Any, Callable, Iterable, TypeAlias

from arnold_pipelines.run_authority.contracts import (
    CapabilityGrant,
    Claim,
    Contract,
    ContractError,
    CoordinatorFence,
    Decision,
    EvidenceEnvelope,
    IdempotencyKey,
    ObservationEnvelope,
    QuarantineRecord,
    SubjectAttempt,
    contract_from_dict,
)


GENESIS_HASH = "0" * 64
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _HEX_DIGEST.fullmatch(value) is not None

AuthorityRecord: TypeAlias = (
    EvidenceEnvelope
    | ObservationEnvelope
    | CoordinatorFence
    | CapabilityGrant
    | SubjectAttempt
    | IdempotencyKey
    | Claim
    | Decision
    | QuarantineRecord
)

_AUTHORITY_RECORD_TYPES: tuple[type[Contract], ...] = (
    EvidenceEnvelope,
    ObservationEnvelope,
    CoordinatorFence,
    CapabilityGrant,
    SubjectAttempt,
    IdempotencyKey,
    Claim,
    Decision,
    QuarantineRecord,
)


class AuthorityJournalError(ContractError):
    """Base error for the owner journal adapter."""


class InvalidAuthorityRecordError(AuthorityJournalError):
    """The append input is not an admitted Run Authority contract."""


class InvalidCursorError(AuthorityJournalError):
    """The CAS cursor is not a real non-negative integer."""


class StaleCursorError(AuthorityJournalError):
    """The caller's integer cursor no longer names the current journal head."""


class IdempotencyConflictError(AuthorityJournalError):
    """One idempotency identity was reused with different durable content."""


class GLEKConflictError(AuthorityJournalError):
    """A GLEK was reused for a different owner-journal record."""


class JournalCorruptionError(AuthorityJournalError):
    """The durable journal cannot be replayed or its hash chain is invalid."""


class JournalStorageError(AuthorityJournalError):
    """A storage operation failed before its outcome became authoritative."""


class JournalCommitIndeterminateError(JournalStorageError):
    """Commit acknowledgement was lost; callers must reread and reconcile."""


@dataclass(frozen=True)
class JournalView:
    """Immutable read result: records plus the authoritative integer cursor.

    The object is intentionally unpackable as ``records, cursor`` so callers
    can use either the named form or the compact API promised by the owner
    boundary.
    """

    run_id: str
    revision: str
    records: tuple[AuthorityRecord, ...]
    cursor: int

    def __iter__(self):
        yield self.records
        yield self.cursor

    @property
    def journal_cursor(self) -> int:
        """Compatibility name used by authority projections."""

        return self.cursor


@dataclass(frozen=True)
class AppendResult:
    """Result of a durable append, including exact-retry information."""

    run_id: str
    revision: str
    record: AuthorityRecord
    cursor: int
    idempotency_key: str
    glek: str
    is_duplicate: bool


def _required_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AuthorityJournalError(f"{name} must be a non-empty string")
    return value


def _cursor(value: Any, name: str = "expected_cursor") -> int:
    """Validate, but never coerce, a CAS cursor."""

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InvalidCursorError(f"{name} must be a non-negative integer")
    return value


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _record_identity(record: AuthorityRecord) -> str:
    """Return the stable identity used to namespace idempotency keys."""

    if isinstance(record, EvidenceEnvelope):
        return record.evidence_id
    if isinstance(record, ObservationEnvelope):
        return record.observation_id
    if isinstance(record, CoordinatorFence):
        return f"{record.coordinator_attempt_id}:{record.token}"
    if isinstance(record, CapabilityGrant):
        return record.grant_id
    if isinstance(record, SubjectAttempt):
        return record.attempt_id
    if isinstance(record, IdempotencyKey):
        return record.value
    if isinstance(record, Claim):
        return record.claim_id
    if isinstance(record, Decision):
        return record.decision_id
    if isinstance(record, QuarantineRecord):
        return record.quarantine_id
    raise InvalidAuthorityRecordError(
        f"unsupported authority record {type(record).__name__}"
    )


def _validate_record(record: Any, run_id: str, revision: str) -> AuthorityRecord:
    """Admit only real generic authority contracts, never synthetic mappings."""

    if not isinstance(record, _AUTHORITY_RECORD_TYPES):
        raise InvalidAuthorityRecordError(
            "append requires a concrete Run Authority contract instance; "
            "projections, source cursors, and mappings are not authority"
        )

    record_run = getattr(record, "run_id", None)
    if record_run is not None and record_run != run_id:
        raise InvalidAuthorityRecordError("record run_id does not match journal run_id")
    record_revision = getattr(record, "run_revision", None)
    if record_revision is not None and record_revision != revision:
        raise InvalidAuthorityRecordError(
            "record run_revision does not match journal revision"
        )
    if isinstance(record, ObservationEnvelope):
        # Non-coherent observations are preservable evidence, never authority;
        # every appended observation must carry an explicit typed coherence
        # verdict and a coherent verdict requires the capture that backs it.
        if record.coherence not in ("COHERENT", "UNKNOWN", "INCOHERENT"):
            raise InvalidAuthorityRecordError("observation coherence is not typed")
        if record.is_dispatchable and record.runtime_observation is None:
            raise InvalidAuthorityRecordError(
                "dispatchable observation requires a runtime observation"
            )
    # Force canonical serialisation now.  This catches unsupported payloads
    # before the transaction starts and makes the persisted bytes the exact
    # contract bytes that reducers later replay.
    try:
        record.to_json()
        record.digest()
    except Exception as exc:  # pragma: no cover - defensive contract guard
        raise InvalidAuthorityRecordError("record is not canonically serializable") from exc
    return record


def derive_glek(run_id: str, revision: str, idempotency_identity: str) -> str:
    """Derive one stable GLEK for one owner-journal identity."""

    material = json.dumps(
        {"run_id": run_id, "revision": revision, "idempotency": idempotency_identity},
        sort_keys=True,
        separators=(",", ":"),
    )
    return "glek:" + _digest_text(material)


def _entry_material(
    *,
    run_id: str,
    revision: str,
    cursor: int,
    idempotency_identity: str,
    idempotency_key: str,
    glek: str,
    record_type: str,
    record_json: str,
    record_digest: str,
    prior_hash: str,
    created_at_ns: int,
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "revision": revision,
        "cursor": cursor,
        "idempotency_identity": idempotency_identity,
        "idempotency_key": idempotency_key,
        "glek": glek,
        "record_type": record_type,
        "record_json": record_json,
        "record_digest": record_digest,
        "prior_hash": prior_hash,
        "created_at_ns": created_at_ns,
    }


class RunAuthorityJournal:
    """SQLite owner journal for generic Run Authority records.

    The store is deliberately not a replacement for Custody or WBC.  It is a
    single writer/read boundary for the generic authority contracts and keeps
    their source records content-addressed.  ``BEGIN IMMEDIATE`` serialises
    competing owners, while a unique identity index makes retries safe.
    """

    schema_version = 1

    def __init__(
        self,
        database: str | Path,
        *,
        fault_hook: Callable[[str], None] | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> None:
        self.database = Path(database).expanduser().absolute()
        self._fault_hook = fault_hook
        self._owned_connection = connection
        if connection is None:
            self._assert_safe_database_path()
            self.database.parent.mkdir(parents=True, exist_ok=True)
        else:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=30000")
        self._initialize_schema()

    def _assert_safe_database_path(self) -> None:
        if self.database.exists() and self.database.is_symlink():
            raise JournalStorageError("authority journal database may not be a symlink")

    def _fault(self, stage: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(stage)

    def _connect(self) -> sqlite3.Connection:
        if self._owned_connection is not None:
            return self._owned_connection
        self._assert_safe_database_path()
        try:
            connection = sqlite3.connect(
                str(self.database), timeout=30.0, isolation_level=None
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=30000")
            return connection
        except sqlite3.Error as exc:
            raise JournalStorageError("authority journal could not be opened") from exc

    def _release_connection(self, connection: sqlite3.Connection) -> None:
        if connection is not self._owned_connection:
            connection.close()

    def close(self) -> None:
        """Close an injected persistent connection; default journals are stateless."""
        if self._owned_connection is not None:
            self._owned_connection.close()
            self._owned_connection = None

    def _initialize_schema(self) -> None:
        connection = self._connect()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS authority_journal_records (
                    run_id TEXT NOT NULL,
                    revision TEXT NOT NULL,
                    cursor INTEGER NOT NULL CHECK(cursor >= 1),
                    idempotency_identity TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    glek TEXT NOT NULL UNIQUE,
                    record_type TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    record_digest TEXT NOT NULL,
                    prior_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL,
                    created_at_ns INTEGER NOT NULL,
                    PRIMARY KEY (run_id, revision, cursor),
                    UNIQUE (run_id, revision, idempotency_identity)
                );
                CREATE INDEX IF NOT EXISTS idx_authority_journal_view
                    ON authority_journal_records(run_id, revision, cursor);
                """
            )
        except sqlite3.Error as exc:
            raise JournalStorageError("authority journal schema could not be initialized") from exc
        finally:
            self._release_connection(connection)

    @staticmethod
    def _rows_for_view(
        connection: sqlite3.Connection, run_id: str, revision: str
    ) -> list[sqlite3.Row]:
        rows = list(
            connection.execute(
                """
                SELECT run_id, revision, cursor, idempotency_identity,
                       idempotency_key, glek, record_type, record_json,
                       record_digest, prior_hash, record_hash, created_at_ns
                  FROM authority_journal_records
                 WHERE run_id = ? AND revision = ?
                 ORDER BY cursor ASC
                """,
                (run_id, revision),
            )
        )
        return rows

    @staticmethod
    def _decode_rows(
        rows: Iterable[sqlite3.Row], run_id: str, revision: str
    ) -> tuple[tuple[AuthorityRecord, ...], int, str]:
        records: list[AuthorityRecord] = []
        expected_cursor = 1
        prior_hash = GENESIS_HASH
        for row in rows:
            cursor = row["cursor"]
            if (
                isinstance(cursor, bool)
                or not isinstance(cursor, int)
                or cursor != expected_cursor
            ):
                raise JournalCorruptionError("authority journal cursor sequence is not contiguous")
            if row["run_id"] != run_id or row["revision"] != revision:
                raise JournalCorruptionError("authority journal row identity does not match its view")
            if not _is_digest(row["prior_hash"]) or row["prior_hash"] != prior_hash:
                raise JournalCorruptionError("authority journal prior hash does not match")
            record_json = row["record_json"]
            if (
                not isinstance(record_json, str)
                or not _is_digest(row["record_digest"])
                or _digest_text(record_json) != row["record_digest"]
            ):
                raise JournalCorruptionError("authority record digest does not match bytes")
            try:
                decoded = json.loads(record_json)
                record = contract_from_dict(decoded)
            except Exception as exc:
                raise JournalCorruptionError("authority journal record cannot be decoded") from exc
            if not isinstance(record, _AUTHORITY_RECORD_TYPES):
                raise JournalCorruptionError("journal contains a non-authority contract")
            try:
                canonical_json = record.to_json()
                canonical_digest = record.digest()
            except Exception as exc:
                raise JournalCorruptionError("authority record is not canonically serializable") from exc
            if canonical_json != record_json or canonical_digest != row["record_digest"]:
                raise JournalCorruptionError("authority record bytes are not canonical")
            if (
                getattr(record, "run_id", run_id) != run_id
                or getattr(record, "run_revision", revision) != revision
            ):
                raise JournalCorruptionError("journal record identity does not match its view")
            if (
                not isinstance(row["idempotency_identity"], str)
                or not isinstance(row["idempotency_key"], str)
                or row["idempotency_identity"]
                != f"{record.contract_type}:{row['idempotency_key']}"
            ):
                raise JournalCorruptionError("journal idempotency identity drifted")
            intrinsic_key = getattr(record, "idempotency_key", None)
            if intrinsic_key is not None and intrinsic_key != row["idempotency_key"]:
                raise JournalCorruptionError("journal intrinsic idempotency key drifted")
            if not isinstance(row["glek"], str) or not row["glek"].strip():
                raise JournalCorruptionError("journal GLEK is invalid")
            if not isinstance(row["created_at_ns"], int) or row["created_at_ns"] < 1:
                raise JournalCorruptionError("journal creation timestamp is invalid")
            material = _entry_material(
                run_id=row["run_id"],
                revision=row["revision"],
                cursor=cursor,
                idempotency_identity=row["idempotency_identity"],
                idempotency_key=row["idempotency_key"],
                glek=row["glek"],
                record_type=row["record_type"],
                record_json=record_json,
                record_digest=row["record_digest"],
                prior_hash=row["prior_hash"],
                created_at_ns=row["created_at_ns"],
            )
            expected_hash = _digest_text(json.dumps(material, sort_keys=True, separators=(",", ":")))
            if not _is_digest(row["record_hash"]) or row["record_hash"] != expected_hash:
                raise JournalCorruptionError("authority journal hash chain is invalid")
            if row["record_type"] != record.contract_type:
                raise JournalCorruptionError("authority journal contract discriminator drifted")
            records.append(record)
            prior_hash = row["record_hash"]
            expected_cursor += 1
        return tuple(records), expected_cursor - 1, prior_hash

    def read_view(self, run_id: str, revision: str) -> JournalView:
        """Read canonical records and the durable integer cursor."""

        run_id = _required_text(run_id, "run_id")
        revision = _required_text(revision, "revision")
        connection = self._connect()
        try:
            rows = self._rows_for_view(connection, run_id, revision)
            records, cursor, _ = self._decode_rows(rows, run_id, revision)
            return JournalView(run_id, revision, records, cursor)
        except JournalCorruptionError:
            raise
        except sqlite3.Error as exc:
            raise JournalStorageError("authority journal view could not be read") from exc
        finally:
            self._release_connection(connection)

    def compare_and_append(
        self,
        run_id: str,
        revision: str,
        expected_cursor: int,
        record: AuthorityRecord,
        *,
        idempotency_key: str | None = None,
        glek: str | None = None,
    ) -> AppendResult:
        """Atomically append one contract iff ``expected_cursor`` is current.

        The cursor check compares the caller's value with a fresh durable
        read inside the write transaction.  It is intentionally not a
        self-comparison and never uses a content hash as a cursor.  Exact
        retries return the original row even when the caller retained a stale
        cursor; divergent retries raise and do not create a synthetic record.
        """

        run_id = _required_text(run_id, "run_id")
        revision = _required_text(revision, "revision")
        expected_cursor = _cursor(expected_cursor)
        record = _validate_record(record, run_id, revision)
        intrinsic_key = getattr(record, "idempotency_key", None)
        if idempotency_key is None:
            idempotency_key = intrinsic_key or _record_identity(record)
        idempotency_key = _required_text(idempotency_key, "idempotency_key")
        if intrinsic_key is not None and intrinsic_key != idempotency_key:
            raise IdempotencyConflictError(
                "idempotency_key does not match the contract's intrinsic key"
            )
        idempotency_identity = f"{record.contract_type}:{idempotency_key}"
        derived_glek = derive_glek(run_id, revision, idempotency_identity)
        if glek is None:
            glek = derived_glek
        glek = _required_text(glek, "glek")
        record_json = record.to_json()
        record_digest = _digest_text(record_json)
        connection: sqlite3.Connection | None = None
        committed = False
        try:
            self._fault("before_connect")
            connection = self._connect()
            self._fault("before_begin")
            connection.execute("BEGIN IMMEDIATE")
            self._fault("after_begin")
            rows = self._rows_for_view(connection, run_id, revision)
            decoded_records, current_cursor, prior_hash = self._decode_rows(
                rows, run_id, revision
            )

            existing = connection.execute(
                """
                SELECT run_id, revision, cursor, idempotency_identity,
                       idempotency_key, glek, record_type, record_json,
                       record_digest, prior_hash, record_hash, created_at_ns
                  FROM authority_journal_records
                 WHERE run_id = ? AND revision = ? AND idempotency_identity = ?
                """,
                (run_id, revision, idempotency_identity),
            ).fetchone()
            if existing is not None:
                # ``rows`` is the fully validated stream.  Decode by the
                # durable cursor rather than treating a later row as a new
                # genesis record; the latter would accept cursor one only and
                # make retries of older records fail spuriously.
                existing_cursor = _cursor(existing["cursor"], "stored cursor")
                existing_record = decoded_records[existing_cursor - 1]
                if existing["record_digest"] != record_digest or existing["record_json"] != record_json:
                    raise IdempotencyConflictError(
                        "idempotency identity already names different authority content"
                    )
                if existing["glek"] != glek:
                    raise GLEKConflictError(
                        f"idempotency identity already names GLEK {existing['glek']!r}"
                    )
                connection.execute("COMMIT")
                committed = True
                return AppendResult(
                    run_id,
                    revision,
                    existing_record,
                    existing_cursor,
                    idempotency_key,
                    str(existing["glek"]),
                    True,
                )

            if current_cursor != expected_cursor:
                raise StaleCursorError(
                    f"stale authority cursor: expected {expected_cursor}, current {current_cursor}"
                )

            glek_owner = connection.execute(
                "SELECT run_id, revision, cursor, idempotency_identity, record_digest FROM authority_journal_records WHERE glek = ?",
                (glek,),
            ).fetchone()
            if glek_owner is not None:
                raise GLEKConflictError(
                    f"GLEK {glek!r} is already bound to an authority record"
                )

            next_cursor = current_cursor + 1
            created_at_ns = time.time_ns()
            material = _entry_material(
                run_id=run_id,
                revision=revision,
                cursor=next_cursor,
                idempotency_identity=idempotency_identity,
                idempotency_key=idempotency_key,
                glek=glek,
                record_type=record.contract_type,
                record_json=record_json,
                record_digest=record_digest,
                prior_hash=prior_hash,
                created_at_ns=created_at_ns,
            )
            record_hash = _digest_text(json.dumps(material, sort_keys=True, separators=(",", ":")))
            self._fault("before_insert")
            connection.execute(
                """
                INSERT INTO authority_journal_records(
                    run_id, revision, cursor, idempotency_identity,
                    idempotency_key, glek, record_type, record_json,
                    record_digest, prior_hash, record_hash, created_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    revision,
                    next_cursor,
                    idempotency_identity,
                    idempotency_key,
                    glek,
                    record.contract_type,
                    record_json,
                    record_digest,
                    prior_hash,
                    record_hash,
                    created_at_ns,
                ),
            )
            self._fault("after_insert")
            self._fault("before_commit")
            connection.execute("COMMIT")
            committed = True
            self._fault("after_commit")
            return AppendResult(
                run_id, revision, record, next_cursor, idempotency_key, glek, False
            )
        except Exception as exc:
            if connection is not None and connection.in_transaction:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            if isinstance(exc, AuthorityJournalError):
                raise
            if committed:
                raise JournalCommitIndeterminateError(
                    "authority journal commit acknowledgement is indeterminate"
                ) from exc
            raise JournalStorageError("authority journal append failed") from exc
        finally:
            if connection is not None:
                self._release_connection(connection)


__all__ = [
    "GENESIS_HASH",
    "AuthorityRecord",
    "AuthorityJournalError",
    "InvalidAuthorityRecordError",
    "InvalidCursorError",
    "StaleCursorError",
    "IdempotencyConflictError",
    "GLEKConflictError",
    "JournalCorruptionError",
    "JournalStorageError",
    "JournalCommitIndeterminateError",
    "JournalView",
    "AppendResult",
    "derive_glek",
    "RunAuthorityJournal",
]
