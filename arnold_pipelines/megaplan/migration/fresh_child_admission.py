"""Canonical admission of a *new*, independent Megaplan child.

The occurrence migration coordinator in :mod:`occurrence_child_migration`
requires an authoritative parent.  That is the right contract for a real
migration, but it deliberately cannot help a legacy occurrence such as r6:
the r6 evidence has no Run Authority owner records.  This module is the
separate, explicitly approved route for that case.

It does not revive, repair, or quarantine the legacy occurrence.  The caller
supplies a new child run identity and an operator/policy approval receipt;
the module then admits the child through the canonical Run Authority journal,
reserves a GLEK in the canonical WBC store, and acquires the canonical
Custody lease.  Every write is content-addressed and retriable.  A crash
between records is a recoverable prefix, never a reason to mint a second
identity or to fall back to a projection.

The journal protocol is intentionally the low-level owner boundary already
provided by ``RunAuthorityJournal`` (``read_view`` plus
``compare_and_append``).  No local shadow journal is created here.  The
production caller must pass the real owner instance.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping, Protocol, runtime_checkable
import uuid

from arnold.workflow.attempt_ledger_store import GlobalEffectIdentity
from arnold_pipelines.megaplan.custody.contracts import (
    CustodyTargetKey,
    RepairOccurrenceKey,
    CustodyLease,
)
from arnold_pipelines.megaplan.migration.occurrence_child_migration import (
    ChildAuthority,
    CustodyOwner,
    WbcOwner,
    WbcReservation,
)
from arnold_pipelines.run_authority.contracts import (
    CapabilityGrant,
    Claim,
    CoordinatorFence,
    Decision,
    EvidenceEnvelope,
    SubjectAttempt,
    canonical_json,
    validate_relationships,
)


FRESH_CHILD_SCHEMA = "arnold.megaplan.fresh_child_admission.v1"
_NAMESPACE = uuid.UUID("7f25e7be-4e50-5e9c-9c0b-9cfe5e8b0d4f")


class FreshChildAdmissionError(RuntimeError):
    """Base class for fail-closed fresh-child admission errors."""


class FreshChildConflict(FreshChildAdmissionError):
    """The requested child identity is already bound to different content."""


class FreshChildIndeterminate(FreshChildAdmissionError):
    """An owner write may have happened but could not be verified."""


class FreshChildOwnerUnavailable(FreshChildAdmissionError):
    """A canonical owner adapter was not supplied."""


DEFAULT_FRESH_CHILD_CAPABILITIES = ("execute",)
CURRENT_AUTHORITY_BINDING_SCHEMA = "arnold.megaplan.current_authority_binding.v1"


@runtime_checkable
class FreshChildJournal(Protocol):
    """The canonical Run Authority journal used for fresh-run admission.

    ``read_view`` must return an object with ``records`` and integer
    ``cursor`` (the existing ``JournalView`` contract).  ``compare_and_append``
    must implement owner-side idempotency and cursor CAS.  A projection,
    status sidecar, or locally-created fake journal is not a valid production
    implementation.
    """

    def read_view(self, run_id: str, revision: str) -> Any: ...

    def compare_and_append(
        self,
        run_id: str,
        revision: str,
        expected_cursor: int,
        record: Any,
        *,
        idempotency_key: str | None = None,
        glek: str | None = None,
    ) -> Any: ...


def _required_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _canonical(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _canonical(value[key]) for key in sorted(value)}
    if isinstance(value, (tuple, list)):
        return [_canonical(item) for item in value]
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _canonical(value.to_dict())
    return value


@dataclass(frozen=True)
class FreshChildRequest:
    """Explicit request for a new child run.

    ``parent_occurrence_digest`` is lineage metadata only.  It never grants
    permission to mutate or resume the parent.  ``approval_receipt`` is the
    persisted operator/policy decision that this is a new independent child;
    an empty value is rejected so a fixer cannot silently turn a legacy
    blocker into a second run.
    """

    run_id: str
    run_revision: str
    coordinator_attempt_id: str
    subject_id: str
    subject_attempt_id: str
    child_selector: Mapping[str, Any]
    environment: str
    session: str
    chain: str
    phase: str
    task: str
    normalized_failure_kind: str
    blocker_or_phase_result_hash: str
    chain_identity: str
    plan_artifact_digest: str
    runtime_binding_digest: str
    source_revision: str
    approval_receipt: str
    approval_actor: str
    parent_occurrence_digest: str
    fence_token: int = 1
    capabilities: tuple[str, ...] = DEFAULT_FRESH_CHILD_CAPABILITIES

    def __post_init__(self) -> None:
        for name in (
            "run_id",
            "run_revision",
            "coordinator_attempt_id",
            "subject_id",
            "subject_attempt_id",
            "environment",
            "session",
            "chain",
            "phase",
            "task",
            "normalized_failure_kind",
            "blocker_or_phase_result_hash",
            "chain_identity",
            "plan_artifact_digest",
            "runtime_binding_digest",
            "source_revision",
            "approval_receipt",
            "approval_actor",
            "parent_occurrence_digest",
        ):
            _required_text(getattr(self, name), name)
        if isinstance(self.fence_token, bool) or not isinstance(self.fence_token, int) or self.fence_token < 1:
            raise ValueError("fence_token must be a positive integer")
        if not isinstance(self.child_selector, Mapping):
            raise ValueError("child_selector must be a mapping")
        if not isinstance(self.capabilities, (tuple, list)) or not self.capabilities:
            raise ValueError("capabilities must be a non-empty sequence")
        capabilities = tuple(_required_text(value, "capability") for value in self.capabilities)
        if len(set(capabilities)) != len(capabilities):
            raise ValueError("capabilities must not contain duplicates")
        object.__setattr__(self, "capabilities", capabilities)
        frozen_selector = json.loads(canonical_json(_canonical(self.child_selector)))
        object.__setattr__(self, "child_selector", frozen_selector)

    @property
    def request_digest(self) -> str:
        return _digest(self.to_dict(include_digest=False))

    @property
    def idempotency_key(self) -> str:
        return f"{FRESH_CHILD_SCHEMA}:{self.request_digest}"

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        result = {
            "schema": FRESH_CHILD_SCHEMA,
            "run_id": self.run_id,
            "run_revision": self.run_revision,
            "coordinator_attempt_id": self.coordinator_attempt_id,
            "subject_id": self.subject_id,
            "subject_attempt_id": self.subject_attempt_id,
            "child_selector": _canonical(self.child_selector),
            "environment": self.environment,
            "session": self.session,
            "chain": self.chain,
            "phase": self.phase,
            "task": self.task,
            "normalized_failure_kind": self.normalized_failure_kind,
            "blocker_or_phase_result_hash": self.blocker_or_phase_result_hash,
            "chain_identity": self.chain_identity,
            "plan_artifact_digest": self.plan_artifact_digest,
            "runtime_binding_digest": self.runtime_binding_digest,
            "source_revision": self.source_revision,
            "approval_receipt": self.approval_receipt,
            "approval_actor": self.approval_actor,
            "parent_occurrence_digest": self.parent_occurrence_digest,
            "fence_token": self.fence_token,
            "capabilities": list(self.capabilities),
        }
        if include_digest:
            result["request_digest"] = self.request_digest
        return result


@dataclass(frozen=True)
class FreshChildIdentity:
    """Deterministic identities allocated from one fresh request."""

    request_digest: str
    migration_idempotency_key: str
    run_id: str
    run_revision: str
    coordinator_attempt_id: str
    subject_attempt_id: str
    wbc_attempt_id: str
    glek: str
    grant_id: str
    claim_id: str
    decision_id: str
    evidence_id: str


@dataclass(frozen=True)
class FreshChildAdmissionReceipt:
    """Evidence that all three owners admitted one independent child."""

    request: FreshChildRequest
    identity: FreshChildIdentity
    authority: ChildAuthority
    wbc: WbcReservation
    custody: CustodyLease
    occurrence: RepairOccurrenceKey

    def assert_ready(self) -> None:
        self.authority.validate()
        if self.authority.fence.run_id != self.identity.run_id:
            raise FreshChildConflict("Run Authority fence and child identity differ")
        if self.authority.attempt.attempt_id != self.identity.subject_attempt_id:
            raise FreshChildConflict("Run Authority attempt and child identity differ")
        if self.wbc.attempt_id != self.identity.wbc_attempt_id:
            raise FreshChildConflict("WBC attempt differs from child identity")
        if self.custody.wbc_attempt_reference != self.wbc.attempt_id:
            raise FreshChildConflict("Custody lease is not bound to WBC attempt")
        if self.custody.run_authority_grant_id != self.authority.grant.grant_id:
            raise FreshChildConflict("Custody lease is not bound to RA grant")
        if self.custody.occurrence_key.occurrence_digest != self.occurrence.occurrence_digest:
            raise FreshChildConflict("Custody lease is not bound to admitted occurrence")


def _contract_digest(record: Any) -> str:
    digest = getattr(record, "digest", None)
    if not callable(digest):
        raise FreshChildOwnerUnavailable("authority owner returned an undigestible record")
    value = digest()
    if not isinstance(value, str) or len(value) != 64:
        raise FreshChildOwnerUnavailable("authority owner returned an invalid record digest")
    return value


class FreshChildAuthorityContext:
    """Read current authority from the existing RA, WBC, and Custody owners.

    The context is a verifier and reference builder only.  It never appends,
    reserves, or acquires.  Callers bind the returned immutable references to
    the launch envelope and call :meth:`read` again at each effect boundary.
    """

    def __init__(
        self,
        *,
        receipt: FreshChildAdmissionReceipt,
        journal: FreshChildJournal,
        wbc: WbcOwner,
        custody: CustodyOwner,
    ) -> None:
        self.receipt = receipt
        self.journal = journal
        self.wbc = wbc
        self.custody = custody
        self._expected: dict[str, Any] | None = None

    def bind(self, authority: Mapping[str, Any]) -> None:
        """Freeze the first owner observation for later effect re-reads."""
        if not isinstance(authority, Mapping) or authority.get("schema") != CURRENT_AUTHORITY_BINDING_SCHEMA:
            raise FreshChildOwnerUnavailable("cannot bind a malformed current authority observation")
        self._expected = dict(authority)

    def authorize(self, *, boundary: str, target_key: str, capability: str) -> Any:
        """Return the canonical gate verdict for one exact transport target."""
        from arnold_pipelines.megaplan.custody.action_validator import GateResult

        if not capability:
            return GateResult.BLOCKED_MISSING_GRANT
        try:
            expected = self._expected
            if expected is not None and not expected.get("target_binding"):
                expected = dict(expected)
                expected.pop("target_binding", None)
            observed = self.read(
                capability=capability,
                target_binding={"boundary": str(boundary), "target_key": target_key},
                expected=expected,
            )
            if self._expected is None or not self._expected.get("target_binding"):
                self.bind(observed)
            return GateResult.AUTHORIZED
        except FreshChildAdmissionError:
            return GateResult.BLOCKED_STALE_GRANT
        except Exception:
            return GateResult.ERROR

    def read(
        self,
        *,
        capability: str,
        target_binding: Mapping[str, Any] | None = None,
        expected: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Return a coherent current-owner observation or fail closed."""
        from arnold_pipelines.run_authority.current_source import CurrentSourceRequest
        from arnold_pipelines.run_authority.reducer import reduce_run_authority
        from arnold_pipelines.megaplan.maintenance.sources import RunAuthorityAdapter

        request = self.receipt.request
        raw = self.journal.read_view(request.run_id, request.run_revision)
        records = getattr(raw, "records", None)
        cursor = getattr(raw, "cursor", getattr(raw, "journal_cursor", None))
        if not isinstance(records, tuple) or not isinstance(cursor, int) or cursor < 0:
            raise FreshChildOwnerUnavailable("Run Authority owner returned an invalid current view")
        view = reduce_run_authority(
            records,
            run_id=request.run_id,
            run_revision=request.run_revision,
            journal_cursor=cursor,
        )
        source_request = CurrentSourceRequest(
            run_id=request.run_id,
            run_revision=request.run_revision,
            coordinator_attempt_id=request.coordinator_attempt_id,
            grant_id=self.receipt.identity.grant_id,
            fence_token=str(self.receipt.authority.fence.token),
            subject_attempt_id=request.subject_attempt_id,
            decision_id=self.receipt.identity.decision_id,
            subject_id=request.subject_id,
            capability=capability,
        )
        ra = RunAuthorityAdapter(lambda: view).read(source_request)
        current = ra.current_source
        if ra.torn or current is None or not current.satisfied:
            reason = current.reason if current is not None else "current source observation missing"
            raise FreshChildOwnerUnavailable(f"G5A_REMOTE_BLOCKED: {reason}")

        reservation = self.wbc.read_reservation(
            self.receipt.identity.wbc_attempt_id, self.receipt.identity.glek
        )
        if reservation is None or reservation.attempt_id != self.receipt.identity.wbc_attempt_id:
            raise FreshChildOwnerUnavailable("G5A_REMOTE_BLOCKED: WBC reservation is missing or stale")
        lease = self.custody.read_lease(self.receipt.custody.lease_id)
        if lease is None or lease.is_expired:
            raise FreshChildOwnerUnavailable("G5A_REMOTE_BLOCKED: Custody lease is missing or expired")
        if (
            lease.run_authority_grant_id != self.receipt.identity.grant_id
            or lease.coordinator_fence_token != self.receipt.authority.fence.token
            or lease.wbc_attempt_reference != reservation.attempt_id
            or lease.occurrence_key.occurrence_digest != self.receipt.occurrence.occurrence_digest
        ):
            raise FreshChildOwnerUnavailable("G5A_REMOTE_BLOCKED: Custody owner identity drift")

        refs = {ref.locator: ref.digest for ref in current.references}
        authority = {
            "schema": CURRENT_AUTHORITY_BINDING_SCHEMA,
            "run_id": request.run_id,
            "run_revision": request.run_revision,
            "coordinator_attempt_id": request.coordinator_attempt_id,
            "subject_id": request.subject_id,
            "subject_attempt_id": request.subject_attempt_id,
            "capability": capability,
            "grant_id": self.receipt.identity.grant_id,
            "fence_token": self.receipt.authority.fence.token,
            "claim_id": self.receipt.identity.claim_id,
            "decision_id": self.receipt.identity.decision_id,
            "journal_cursor": ra.journal_cursor,
            "view_hash": ra.view_hash,
            "grant_ref": refs.get(f"grant://{self.receipt.identity.grant_id}"),
            "fence_ref": refs.get(
                f"fence://{request.coordinator_attempt_id}/{self.receipt.authority.fence.token}"
            ),
            "attempt_ref": refs.get(f"attempt://{request.subject_attempt_id}"),
            "decision_ref": refs.get(f"decision://{self.receipt.identity.decision_id}"),
            "wbc_attempt_id": reservation.attempt_id,
            "glek": reservation.glek,
            "custody_lease_id": lease.lease_id,
            "custody_epoch": lease.custody_epoch,
            "custody_ref": _contract_digest(lease),
            "target_binding": dict(target_binding or {}),
            "owner_paths": {
                "authority_journal": str(getattr(self.journal, "database", "")),
                "wbc_ledger": str(getattr(getattr(self.wbc, "store", None), "_db_path", "")),
                "custody_lease_dir": str(getattr(getattr(self.custody, "store", None), "base_dir", "")),
            },
        }
        owner_paths = authority["owner_paths"]
        if not all(isinstance(value, str) and value for value in owner_paths.values()):
            raise FreshChildOwnerUnavailable("G5A_REMOTE_BLOCKED: canonical owner locations are unavailable")
        if any(not isinstance(authority[key], str) or not authority[key] for key in (
            "grant_ref", "fence_ref", "attempt_ref", "decision_ref", "custody_ref"
        )):
            raise FreshChildOwnerUnavailable("G5A_REMOTE_BLOCKED: owner record references are incomplete")
        if expected is not None:
            for key, value in expected.items():
                if authority.get(key) != value:
                    raise FreshChildOwnerUnavailable(
                        f"G5A_REMOTE_BLOCKED: authority reference drift at {key}"
                    )
        return authority


def _identity(request: FreshChildRequest) -> tuple[FreshChildIdentity, GlobalEffectIdentity]:
    digest = request.request_digest
    child_suffix = digest[:24]
    child_run_id = request.run_id
    # These IDs are content addressed to the explicit fresh request.  The
    # launcher still owns the human-facing run label; this module never reuses
    # the legacy run ID as an authority parent.
    attempt_id = request.subject_attempt_id
    effect = GlobalEffectIdentity(
        environment_id=request.environment,
        action_target="megaplan-fresh-child",
        action_version="v1",
        effect_family=FRESH_CHILD_SCHEMA,
        provider_target=child_run_id,
        canonical_request_identity=digest,
        boundary_schema_hash=hashlib.sha256(FRESH_CHILD_SCHEMA.encode("utf-8")).hexdigest(),
    )
    evidence_id = f"evidence:fresh-child:{child_suffix}"
    grant_id = f"grant:fresh-child:{child_suffix}"
    claim_id = f"claim:fresh-child:{child_suffix}"
    decision_id = f"decision:fresh-child:{child_suffix}"
    identity = FreshChildIdentity(
        request_digest=digest,
        migration_idempotency_key=request.idempotency_key,
        run_id=child_run_id,
        run_revision=request.run_revision,
        coordinator_attempt_id=request.coordinator_attempt_id,
        subject_attempt_id=attempt_id,
        wbc_attempt_id=attempt_id,
        glek=effect.global_logical_effect_key,
        grant_id=grant_id,
        claim_id=claim_id,
        decision_id=decision_id,
        evidence_id=evidence_id,
    )
    return identity, effect


def _records(request: FreshChildRequest, identity: FreshChildIdentity) -> tuple[Any, ...]:
    prefix = identity.migration_idempotency_key
    evidence = EvidenceEnvelope(
        evidence_id=identity.evidence_id,
        run_id=identity.run_id,
        run_revision=identity.run_revision,
        evidence_type="fresh_child_admission",
        source="operator-approved-independent-child",
        payload={
            "schema": FRESH_CHILD_SCHEMA,
            "request": request.to_dict(),
            "lineage_only_parent_occurrence_digest": request.parent_occurrence_digest,
        },
    )
    fence = CoordinatorFence(
        run_id=identity.run_id,
        run_revision=identity.run_revision,
        coordinator_attempt_id=identity.coordinator_attempt_id,
        token=request.fence_token,
    )
    grant = CapabilityGrant(
        grant_id=identity.grant_id,
        run_id=identity.run_id,
        run_revision=identity.run_revision,
        coordinator_attempt_id=identity.coordinator_attempt_id,
        fence_token=fence.token,
        subject_ids=(request.subject_id,),
        capabilities=request.capabilities,
        evidence_ids=(evidence.evidence_id,),
    )
    attempt = SubjectAttempt(
        attempt_id=identity.subject_attempt_id,
        run_id=identity.run_id,
        run_revision=identity.run_revision,
        subject_id=request.subject_id,
        grant_id=grant.grant_id,
        coordinator_attempt_id=identity.coordinator_attempt_id,
        fence_token=fence.token,
        ordinal=1,
    )
    claim = Claim(
        claim_id=identity.claim_id,
        run_id=identity.run_id,
        run_revision=identity.run_revision,
        subject_id=request.subject_id,
        attempt_id=attempt.attempt_id,
        grant_id=grant.grant_id,
        coordinator_attempt_id=identity.coordinator_attempt_id,
        fence_token=fence.token,
        claim_type="fresh_child_admission",
        evidence_ids=(evidence.evidence_id,),
        idempotency_key=f"{prefix}:claim",
        payload={"request_digest": identity.request_digest},
    )
    decision = Decision(
        decision_id=identity.decision_id,
        run_id=identity.run_id,
        run_revision=identity.run_revision,
        subject_id=request.subject_id,
        attempt_id=attempt.attempt_id,
        grant_id=grant.grant_id,
        coordinator_attempt_id=identity.coordinator_attempt_id,
        fence_token=fence.token,
        claim_id=claim.claim_id,
        outcome="accepted",
        evidence_ids=(evidence.evidence_id,),
        idempotency_key=f"{prefix}:decision",
        payload={
            "request_digest": identity.request_digest,
            "independent_child": True,
            "parent_mutation": False,
        },
    )
    validate_relationships(
        fence=fence,
        grant=grant,
        attempt=attempt,
        claim=claim,
        evidence=(evidence,),
        decision=decision,
    )
    return evidence, fence, grant, attempt, claim, decision


def _record_key(record: Any, identity: FreshChildIdentity) -> str:
    prefix = identity.migration_idempotency_key
    if isinstance(record, EvidenceEnvelope):
        return f"{prefix}:evidence"
    if isinstance(record, CoordinatorFence):
        return f"{prefix}:fence"
    if isinstance(record, CapabilityGrant):
        return f"{prefix}:grant"
    if isinstance(record, SubjectAttempt):
        return f"{prefix}:attempt"
    if isinstance(record, Claim):
        return record.idempotency_key
    if isinstance(record, Decision):
        return record.idempotency_key
    raise TypeError(f"unsupported fresh-child record {type(record).__name__}")


def _record_matches(record: Any, identity: FreshChildIdentity) -> bool:
    """Detect an occupied run ID before adding a fresh generation."""
    if getattr(record, "run_id", None) != identity.run_id or getattr(record, "run_revision", None) != identity.run_revision:
        return False
    if isinstance(record, EvidenceEnvelope):
        return record.evidence_id == identity.evidence_id and record.payload.get("request", {}).get("request_digest") == identity.request_digest
    if isinstance(record, CoordinatorFence):
        return record.coordinator_attempt_id == identity.coordinator_attempt_id
    if isinstance(record, CapabilityGrant):
        return record.grant_id == identity.grant_id
    if isinstance(record, SubjectAttempt):
        return record.attempt_id == identity.subject_attempt_id
    if isinstance(record, Claim):
        return record.claim_id == identity.claim_id and record.idempotency_key == f"{identity.migration_idempotency_key}:claim"
    if isinstance(record, Decision):
        return record.decision_id == identity.decision_id and record.idempotency_key == f"{identity.migration_idempotency_key}:decision"
    return False


class FreshChildAdmission:
    """Provider-free, idempotent fresh-child admission transaction."""

    def __init__(self, *, journal: FreshChildJournal, wbc: WbcOwner, custody: CustodyOwner) -> None:
        if not isinstance(journal, FreshChildJournal):
            raise FreshChildOwnerUnavailable("fresh child admission requires the canonical Run Authority journal")
        self.journal = journal
        self.wbc = wbc
        self.custody = custody

    def _read_view(self, request: FreshChildRequest) -> Any:
        try:
            view = self.journal.read_view(request.run_id, request.run_revision)
        except Exception as exc:
            raise FreshChildIndeterminate("Run Authority fresh-child view could not be read") from exc
        cursor = getattr(view, "cursor", getattr(view, "journal_cursor", None))
        records = getattr(view, "records", None)
        if isinstance(cursor, bool) or not isinstance(cursor, int) or cursor < 0 or not isinstance(records, tuple):
            raise FreshChildOwnerUnavailable("Run Authority view is not an authoritative cursor/record view")
        return view

    def _append(self, request: FreshChildRequest, identity: FreshChildIdentity, record: Any) -> None:
        view = self._read_view(request)
        for existing in view.records:
            if not _record_matches(existing, identity):
                raise FreshChildConflict(
                    "requested child run identity is already occupied by divergent Run Authority content"
                )
        key = _record_key(record, identity)
        try:
            result = self.journal.compare_and_append(
                request.run_id,
                request.run_revision,
                view.cursor,
                record,
                idempotency_key=key,
            )
        except Exception as exc:
            # The canonical journal's exact idempotency retry is safe, but an
            # arbitrary exception leaves the outcome unknown to this process.
            raise FreshChildIndeterminate(f"Run Authority append failed for {key}") from exc
        persisted = getattr(result, "record", None)
        if persisted is not None and persisted != record:
            raise FreshChildConflict(f"Run Authority returned divergent content for {key}")

    def admit(self, request: FreshChildRequest) -> FreshChildAdmissionReceipt:
        identity, effect = _identity(request)
        records = _records(request, identity)
        # These six records form the smallest complete admission chain.  A
        # crash after any append is replayed by the same idempotency keys.
        for record in records:
            self._append(request, identity, record)

        authority = ChildAuthority(
            fence=records[1],
            grant=records[2],
            attempt=records[3],
            claim=records[4],
            evidence=(records[0],),
            decision=records[5],
        )
        authority.validate()

        try:
            wbc = self.wbc.read_reservation(identity.wbc_attempt_id, identity.glek)
            if wbc is None:
                wbc = self.wbc.reserve_child(
                    attempt_id=identity.wbc_attempt_id,
                    effect_identity=effect,
                    migration_idempotency_key=identity.migration_idempotency_key,
                )
        except FreshChildAdmissionError:
            raise
        except Exception as exc:
            raise FreshChildIndeterminate("WBC child attempt reservation is unknown") from exc
        if wbc.attempt_id != identity.wbc_attempt_id or wbc.glek != identity.glek:
            raise FreshChildConflict("WBC owner returned divergent child attempt/GLEK")

        target = CustodyTargetKey(
            environment=request.environment,
            session=request.session,
            chain=request.chain,
            plan_revision=request.run_revision,
            phase=request.phase,
            task=request.task,
            attempt=f"child:{identity.subject_attempt_id}",
            normalized_failure_kind=request.normalized_failure_kind,
            blocker_or_phase_result_hash=request.blocker_or_phase_result_hash,
            fence=str(authority.fence.token),
            chain_identity=request.chain_identity,
        )
        occurrence = RepairOccurrenceKey(
            target=target,
            run_id=identity.run_id,
            run_revision=identity.run_revision,
            coordinator_attempt_id=identity.coordinator_attempt_id,
            fence_token=authority.fence.token,
            wbc_attempt_reference=wbc.attempt_id,
        )
        lease_id = f"lease:{identity.migration_idempotency_key}"
        try:
            custody = self.custody.read_lease(lease_id)
            if custody is None:
                custody = self.custody.acquire_child(
                    lease_id=lease_id,
                    occurrence=occurrence,
                    authority=authority,
                    wbc=wbc,
                    idempotency_key=identity.migration_idempotency_key,
                )
        except FreshChildAdmissionError:
            raise
        except Exception as exc:
            raise FreshChildIndeterminate("Custody child lease outcome is unknown") from exc
        receipt = FreshChildAdmissionReceipt(
            request=request,
            identity=identity,
            authority=authority,
            wbc=wbc,
            custody=custody,
            occurrence=occurrence,
        )
        receipt.assert_ready()
        return receipt


__all__ = [
    "FRESH_CHILD_SCHEMA",
    "FreshChildAdmission",
    "FreshChildAdmissionError",
    "FreshChildAdmissionReceipt",
    "FreshChildAuthorityContext",
    "FreshChildConflict",
    "FreshChildIdentity",
    "FreshChildIndeterminate",
    "FreshChildJournal",
    "FreshChildOwnerUnavailable",
    "FreshChildRequest",
    "DEFAULT_FRESH_CHILD_CAPABILITIES",
    "CURRENT_AUTHORITY_BINDING_SCHEMA",
]
