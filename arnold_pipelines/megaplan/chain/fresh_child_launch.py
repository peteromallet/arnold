"""Strict production admission for a newly initialised chain child.

This module is deliberately a small boundary around the provider-free
``FreshChildAdmission`` transaction.  It is only called for chain specs that
opt in with ``fresh_child_admission.enabled: true``.  The normal/legacy chain
path does not import or instantiate any of the owner stores.

The first chain ``init`` creates an ``idea_snapshot.md`` but does not yet
create ``plan.md`` (the plan model phase creates that later).  Consequently
the admission's ``plan_artifact_digest`` is an immutable input-manifest digest
over that snapshot and the chain spec.  The generated plan bytes remain
validated by the existing plan/custody acceptance gates; this boundary never
pretends that a model artifact already exists.
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import threading
from typing import Any, Mapping

from arnold_pipelines.megaplan._core import resolve_plan_dir
from arnold_pipelines.megaplan._core.io import write_immutable_json
from arnold_pipelines.megaplan.migration.fresh_child_admission import (
    FRESH_CHILD_SCHEMA,
    FreshChildAdmission,
    FreshChildAdmissionError,
    FreshChildAdmissionReceipt,
    FreshChildAuthorityContext,
    FreshChildIdentity,
    FreshChildRequest,
    action_descriptor,
)
from arnold_pipelines.megaplan.migration.occurrence_child_migration import ChildAuthority
from arnold_pipelines.run_authority.contracts import (
    CapabilityGrant,
    Claim,
    CoordinatorFence,
    Decision,
    EvidenceEnvelope,
    SubjectAttempt,
)


FRESH_CHILD_LAUNCH_SCHEMA = "arnold.megaplan.fresh_child_launch_receipt.v1"
RECEIPT_FILENAME = "fresh_child_admission.json"
_MAX_RECEIPT_BYTES = 1024 * 1024
_SQLITE_OPEN_CUSTODY = threading.Lock()


class FreshChildLaunchError(RuntimeError):
    """The opt-in launch could not be admitted by all canonical owners."""


def _canonical(value: Any) -> Any:
    """Convert owner contracts and mappings to JSON-safe sorted structures."""

    if isinstance(value, Mapping):
        return {str(key): _canonical(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, (tuple, list)):
        return [_canonical(item) for item in value]
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _canonical(value.to_dict())
    if is_dataclass(value):
        return _canonical(asdict(value))
    return value


def _digest(value: Any) -> str:
    encoded = json.dumps(
        _canonical(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sha256_regular(path: Path, label: str) -> str:
    if path.is_symlink() or not path.is_file():
        raise FreshChildLaunchError(f"{label} must be a regular non-symlink file: {path}")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise FreshChildLaunchError(f"unable to hash {label}: {path}") from exc
    return digest.hexdigest()


def _resolve_owned_path(root: Path, raw: str | None, label: str) -> Path:
    """Lexically confine an owner path below the child workspace."""

    if not isinstance(raw, str) or not raw.strip():
        raise FreshChildLaunchError(f"{label} is required for fresh-child admission")
    workspace = Path(os.path.abspath(os.fspath(root)))
    configured = Path(raw.strip()).expanduser()
    candidate = Path(
        os.path.abspath(
            os.fspath(configured if configured.is_absolute() else workspace / configured)
        )
    )
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise FreshChildLaunchError(
            f"{label} must resolve below the child workspace {workspace}: {candidate}"
        ) from exc
    if candidate == workspace:
        raise FreshChildLaunchError(f"{label} cannot be the child workspace itself")

    # This is an early diagnostic for provisioning.  Dispatch re-opens every
    # component through held directory descriptors before trusting it.
    current = workspace
    relative_parts = candidate.relative_to(workspace).parts
    for part in relative_parts:
        current = current / part
        try:
            observed = os.lstat(current)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(observed.st_mode):
            raise FreshChildLaunchError(f"{label} cannot contain symlink component: {current}")
    return candidate


def _prepare_private_owner_directory(path: Path, *, label: str) -> None:
    """Create a new owner directory privately or reject an existing loose one."""

    try:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
        observed = os.lstat(path)
    except OSError as exc:
        raise FreshChildLaunchError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISDIR(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or observed.st_uid != os.geteuid()
        or stat.S_IMODE(observed.st_mode) & 0o077
    ):
        raise FreshChildLaunchError(
            f"{label} must be an effective-owner private directory"
        )


def _assert_private_owner_directory(fd: int, *, label: str) -> None:
    """Exclude different-credential path swaps; same-process/euid code is trusted."""
    observed = os.fstat(fd)
    if (
        not stat.S_ISDIR(observed.st_mode)
        or observed.st_uid != os.geteuid()
        or stat.S_IMODE(observed.st_mode) & 0o077
    ):
        raise FreshChildLaunchError(
            f"{label} must remain an effective-owner private directory"
        )


def _open_nofollow(path: Path, *, directory: bool, label: str) -> int:
    """Open an absolute path one component at a time without following links."""

    candidate = Path(os.path.abspath(os.fspath(path)))
    if not candidate.is_absolute():  # pragma: no cover - abspath guarantees this
        raise FreshChildLaunchError(f"{label} must be absolute")
    base_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    dir_flags = base_flags | getattr(os, "O_DIRECTORY", 0)
    try:
        current = os.open(os.path.sep, dir_flags)
        for index, part in enumerate(candidate.parts[1:]):
            if part in {"", ".", ".."}:
                raise FreshChildLaunchError(f"{label} contains an unsafe path component")
            final = index == len(candidate.parts[1:]) - 1
            flags = dir_flags if (not final or directory) else base_flags
            try:
                opened = os.open(part, flags, dir_fd=current)
            finally:
                os.close(current)
            current = opened
        observed = os.fstat(current)
        expected = stat.S_ISDIR(observed.st_mode) if directory else stat.S_ISREG(observed.st_mode)
        if not expected:
            os.close(current)
            raise FreshChildLaunchError(f"{label} has the wrong filesystem type")
        return current
    except FreshChildLaunchError:
        raise
    except (FileNotFoundError, OSError) as exc:
        raise FreshChildLaunchError(f"{label} is unavailable or unsafe") from exc


def _read_held_regular(fd: int, *, label: str, maximum: int) -> bytes:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise FreshChildLaunchError(f"{label} is not a bounded regular file")
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining > 0:
        chunk = os.read(fd, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    after = os.fstat(fd)
    if (
        (before.st_dev, before.st_ino, before.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
        or len(raw) != before.st_size
        or len(raw) > maximum
    ):
        raise FreshChildLaunchError(f"{label} changed during descriptor read")
    return raw


def _open_fd_identities() -> dict[int, tuple[int, int]]:
    for inventory in (Path("/proc/self/fd"), Path("/dev/fd")):
        try:
            result: dict[int, tuple[int, int]] = {}
            for item in inventory.iterdir():
                if not item.name.isdecimal():
                    continue
                number = int(item.name)
                try:
                    observed = os.fstat(number)
                except OSError:
                    continue
                result[number] = (observed.st_dev, observed.st_ino)
            return result
        except OSError:
            continue
    raise FreshChildLaunchError("descriptor inventory is unavailable on this runtime")


def _open_verified_sqlite(
    path: Path,
    held_fd: int,
    *,
    label: str,
    timeout: float,
) -> tuple[sqlite3.Connection, int]:
    """Open SQLite, then prove its persistent main-db fd is the held inode."""

    expected = os.fstat(held_fd)
    with _SQLITE_OPEN_CUSTODY:
        before = _open_fd_identities()
        try:
            connection = sqlite3.connect(
                path.as_uri() + "?mode=rw",
                uri=True,
                timeout=timeout,
                check_same_thread=False,
                isolation_level=None,
            )
        except sqlite3.Error as exc:
            raise FreshChildLaunchError(f"{label} could not be opened") from exc
        try:
            # Force SQLite to open the main database in query-only mode.  The
            # process-local lock makes the identity multiset delta attributable
            # to this connection; arbitrary in-process code is trusted.
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA schema_version").fetchone()
            expected_identity = (expected.st_dev, expected.st_ino)
            candidates = [
                number
                for number, identity in _open_fd_identities().items()
                if identity == expected_identity and before.get(number) != expected_identity
            ]
            if len(candidates) != 1:
                raise FreshChildLaunchError(
                    f"{label} SQLite connection retained {len(candidates)} new "
                    "descriptor-verified inodes instead of one"
                )
            connection.execute("PRAGMA query_only=OFF")
            return connection, candidates[0]
        except Exception:
            connection.close()
            raise


class _HeldOwnerCustody:
    """Keep the exact owner inodes and SQLite connections alive for a read/CAS."""

    def __init__(self, fds: list[int], connection_fds: tuple[int, int]) -> None:
        self.fds = fds
        self.connection_fds = connection_fds
        self.identities = tuple(
            (os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in connection_fds
        )

    def assert_connected(self) -> None:
        for fd, identity in zip(self.connection_fds, self.identities, strict=True):
            try:
                observed = os.fstat(fd)
            except OSError as exc:
                raise FreshChildLaunchError("canonical owner connection was lost") from exc
            if (observed.st_dev, observed.st_ino) != identity:
                raise FreshChildLaunchError("canonical owner connection identity drift")

    def close(self) -> None:
        while self.fds:
            try:
                os.close(self.fds.pop())
            except OSError:
                pass

    def __del__(self) -> None:  # pragma: no cover - interpreter cleanup
        self.close()


def _hold_existing_sqlite_sidecars(
    parent_fd: int, name: str, *, label: str, held: list[int]
) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    for suffix in ("-journal", "-wal", "-shm"):
        try:
            fd = os.open(name + suffix, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise FreshChildLaunchError(f"{label} sidecar is unsafe") from exc
        observed = os.fstat(fd)
        if not stat.S_ISREG(observed.st_mode):
            os.close(fd)
            raise FreshChildLaunchError(f"{label} sidecar is not a regular file")
        held.append(fd)


def _without_volatile(value: Any) -> Any:
    """Remove process/time fields before hashing a runtime binding manifest."""

    volatile = {
        "timestamp",
        "created_at",
        "updated_at",
        "bound_at",
        "rebound_at",
        "last_rebound_at",
        "observed_at",
        "started_at",
        "finished_at",
    }
    if isinstance(value, Mapping):
        return {
            str(key): _without_volatile(raw)
            for key, raw in sorted(value.items(), key=lambda item: str(item[0]))
            if str(key) not in volatile
        }
    if isinstance(value, (tuple, list)):
        return [_without_volatile(item) for item in value]
    return _canonical(value)


def _required_config_text(spec: Any, name: str) -> str:
    value = getattr(spec, name, None)
    if not isinstance(value, str) or not value.strip():
        raise FreshChildLaunchError(f"fresh_child_admission.{name} is required")
    return value.strip()


def _owner_bundle(root: Path, spec: Any) -> tuple[Any, Any, Any]:
    """Construct the three canonical owner adapters, with no local fallback."""

    authority_path = _resolve_owned_path(
        root, spec.authority_journal_path, "fresh_child_admission.authority_journal_path"
    )
    wbc_path = _resolve_owned_path(
        root, spec.wbc_ledger_path, "fresh_child_admission.wbc_ledger_path"
    )
    custody_dir = _resolve_owned_path(
        root, spec.custody_lease_dir, "fresh_child_admission.custody_lease_dir"
    )
    _prepare_private_owner_directory(
        authority_path.parent, label="fresh-child authority journal directory"
    )
    _prepare_private_owner_directory(
        wbc_path.parent, label="fresh-child WBC ledger directory"
    )
    _prepare_private_owner_directory(
        custody_dir, label="fresh-child Custody lease directory"
    )
    try:
        from arnold.workflow.attempt_ledger_store import SqliteAttemptLedgerStore
        from arnold_pipelines.megaplan.custody.lease_store import open_lease_store
        from arnold_pipelines.megaplan.migration.owner_adapters import (
            AttemptLedgerWbcOwner,
            CustodyLeaseStoreOwner,
        )
        from arnold_pipelines.run_authority.journal import RunAuthorityJournal

        journal = RunAuthorityJournal(authority_path)
        wbc = AttemptLedgerWbcOwner(SqliteAttemptLedgerStore(wbc_path))
        custody = CustodyLeaseStoreOwner(
            open_lease_store(custody_dir),
            lease_ttl_seconds=spec.lease_ttl_seconds,
        )
        return journal, wbc, custody
    except Exception as exc:
        # ImportError means the canonical RA implementation has not been
        # deployed; all other errors include owner construction/schema errors.
        # Never downgrade to a projection or an in-memory owner.
        raise FreshChildLaunchError(
            f"canonical fresh-child owners unavailable: {type(exc).__name__}: {exc}"
        ) from exc


def provision_fresh_child_authority(
    *,
    root: Path,
    spec_path: Path,
    spec: Any,
    launch_context: Mapping[str, Any],
    provider: Any,
    operation_id: str,
    request_id: str,
    upload_destinations: tuple[str, ...] = (),
) -> tuple[Any, Any, dict[str, Any]]:
    """Admit and bind the real launch authority before the first effect.

    This is the production cloud seam.  It only appends the existing RA
    records, WBC reservation, and Custody lease; repository/runtime/upload and
    launch effects remain owned by the caller after this function returns.
    """
    if spec is None or not bool(getattr(spec, "enabled", False)):
        raise FreshChildLaunchError("fresh_child_admission must be enabled for a production launch")
    workspace = Path(root).resolve(strict=True)
    chain_spec = Path(spec_path).resolve(strict=True)
    chain_spec_digest = _sha256_regular(chain_spec, "chain spec")
    approval_receipt = _required_config_text(spec, "approval_receipt")
    approval_digest = approval_receipt.removeprefix("sha256:")
    if len(approval_digest) != 64 or any(char not in "0123456789abcdefABCDEF" for char in approval_digest):
        raise FreshChildLaunchError(
            "fresh_child_admission.approval_receipt must be a sha256 approval receipt digest"
        )
    source_revision = _required_config_text(spec, "source_revision")
    base_target = dict(launch_context)
    base_target.update({"operation": operation_id, "request": request_id})
    # Request and target identities are deterministic and do not require any
    # repository/runtime effect.  The exact operation is admitted up front.
    capabilities = tuple(
        item
        for item in (
            "repository_prepare",
            "file_upload" if upload_destinations else None,
            "ssh_engine_invocation",
            "launch_dispatch",
        )
        if item is not None
    )
    target_bindings: list[tuple[str, str, Mapping[str, Any]]] = [
        ("repository_prepare", "controller", {**base_target, "boundary": "controller", "operation": "repository_prepare"}),
    ]
    target_bindings.extend(
        ("file_upload", "controller", {**base_target, "boundary": "controller", "operation": "file_upload", "destination": destination})
        for destination in upload_destinations
    )
    target_bindings.extend(
        (
            capability,
            boundary,
            {**base_target, "operation": operation_id, "boundary": boundary},
        )
        for capability, boundary in (("ssh_engine_invocation", "engine"), ("launch_dispatch", "dispatch"))
    )
    host = str(getattr(provider, "_validated_host", ""))
    container = str(getattr(getattr(provider, "_ssh", None), "container", ""))
    if host and container:
        target_bindings.append(
            (
                "ssh_engine_invocation",
                "dispatch",
                {"boundary": "dispatch", "target_key": f"ssh:ssh_exec:{host}:{container}"},
            )
        )
        target_bindings.extend(
            (
                "file_upload",
                "dispatch",
                {"boundary": "dispatch", "target_key": f"ssh:upload_file:{host}:{container}"},
            )
            for _destination in upload_destinations
        )
    descriptors = [
        action_descriptor(capability=capability, boundary=boundary, target_binding=target)
        for capability, boundary, target in target_bindings
    ]
    descriptors.sort(key=lambda item: item["descriptor_digest"])
    chain_identity = _required_config_text(spec, "chain_identity")
    run_revision = (getattr(spec, "run_revision", None) or source_revision).strip()
    request = FreshChildRequest(
        run_id=f"{chain_identity}:launch:{operation_id}",
        run_revision=run_revision,
        coordinator_attempt_id=f"{chain_identity}:launch-coordinator:1",
        subject_id=f"{chain_identity}:launch",
        subject_attempt_id=f"{chain_identity}:launch-attempt:1",
        child_selector={
            "schema": "arnold.megaplan.fresh_child_selector.v1",
            "workspace": str(workspace),
            "chain_spec": str(chain_spec),
            "chain_spec_digest": chain_spec_digest,
            "operation_id": operation_id,
            "request_id": request_id,
            "authorized_action_descriptors": descriptors,
        },
        environment=getattr(spec, "environment", "cloud"),
        session=getattr(spec, "session", "megaplan"),
        chain=getattr(spec, "chain", "chain"),
        phase=getattr(spec, "phase", "launch"),
        task=getattr(spec, "task", "launch"),
        normalized_failure_kind=_required_config_text(spec, "normalized_failure_kind"),
        blocker_or_phase_result_hash=_required_config_text(spec, "blocker_or_phase_result_hash"),
        chain_identity=chain_identity,
        plan_artifact_digest=_digest({"chain_spec": chain_spec_digest, "target": base_target}),
        runtime_binding_digest=_digest({"source_revision": source_revision, "workspace": str(launch_context.get("workspace", "")), "operation_id": operation_id}),
        source_revision=source_revision,
        approval_receipt=approval_receipt,
        approval_actor=_required_config_text(spec, "approval_actor"),
        parent_occurrence_digest=_required_config_text(spec, "parent_occurrence_digest"),
        capabilities=capabilities,
    )
    journal, wbc, custody = _owner_bundle(workspace, spec)
    try:
        receipt = FreshChildAdmission(journal=journal, wbc=wbc, custody=custody).admit(request)
        context = FreshChildAuthorityContext(receipt=receipt, journal=journal, wbc=wbc, custody=custody)
        authority = context.read(
            capability="repository_prepare",
            target_binding={**base_target, "operation": "repository_prepare"},
        )
        context.bind(authority)
        binder = getattr(provider, "bind_authority_context", None)
        if not callable(binder):
            raise FreshChildLaunchError("provider cannot bind canonical fresh-child authority")
        binder(context)
    except FreshChildLaunchError:
        raise
    except FreshChildAdmissionError as exc:
        raise FreshChildLaunchError(f"canonical launch authority admission failed: {exc}") from exc
    except Exception as exc:
        raise FreshChildLaunchError(f"canonical launch authority binding failed: {type(exc).__name__}: {exc}") from exc
    return context, receipt, authority


def _wbc_dict(reservation: Any) -> dict[str, Any]:
    raw = getattr(reservation, "reservation", None)
    stable = _canonical(raw)
    # ``is_new`` describes this read/reservation call, not durable ledger
    # identity.  A retry reads the existing row and legitimately flips it
    # from True to False; retaining it would make an otherwise exact receipt
    # appear divergent and defeat idempotent admission.
    if isinstance(stable, dict):
        stable.pop("is_new", None)
    return {
        "attempt_id": reservation.attempt_id,
        "glek": reservation.glek,
        "reservation": stable,
    }


def _receipt_payload(
    receipt: Any, *, owner_paths: Mapping[str, str] | None = None
) -> dict[str, Any]:
    """Serialize the owner receipt without throwing away contract evidence."""

    payload = {
        "schema": FRESH_CHILD_LAUNCH_SCHEMA,
        "admission_schema": FRESH_CHILD_SCHEMA,
        "request": receipt.request.to_dict(),
        "identity": _canonical(receipt.identity),
        "authority": _canonical(receipt.authority),
        "wbc": _wbc_dict(receipt.wbc),
        "custody": _canonical(receipt.custody),
        "occurrence": _canonical(receipt.occurrence),
    }
    if owner_paths is not None:
        payload["owner_paths"] = _canonical(owner_paths)
    return payload


def _write_receipt(path: Path, payload: dict[str, Any]) -> str:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise FreshChildLaunchError(f"fresh-child receipt path is not a regular file: {path}")
    try:
        write_immutable_json(path, payload)
    except (OSError, RuntimeError) as exc:
        raise FreshChildLaunchError(f"could not durably write fresh-child receipt: {path}") from exc
    return _digest(payload)


def admit_fresh_child(
    *,
    root: Path,
    spec_path: Path,
    spec: Any,
    state: Any,
    milestone: Any,
    milestone_index: int,
    plan_name: str,
) -> dict[str, Any]:
    """Admit one independent child and persist its receipt before model drive.

    The caller must invoke this only after ``_init_plan`` has successfully
    created the child plan directory and before any phase/model dispatch.
    ``spec`` is a parsed ``FreshChildAdmissionSpec``; passing a disabled or
    absent section is a programming error rather than a silent success.
    """

    if spec is None or not bool(getattr(spec, "enabled", False)):
        raise FreshChildLaunchError("admit_fresh_child requires enabled fresh_child_admission config")
    if isinstance(milestone_index, bool) or not isinstance(milestone_index, int) or milestone_index < 0:
        raise FreshChildLaunchError("milestone_index must be a non-negative integer")
    if not isinstance(plan_name, str) or not plan_name.strip():
        raise FreshChildLaunchError("plan_name must be non-empty")

    workspace = Path(root).resolve(strict=True)
    chain_spec = Path(spec_path).resolve(strict=True)
    try:
        chain_spec.relative_to(workspace)
    except ValueError as exc:
        raise FreshChildLaunchError(
            f"chain spec must be inside the child workspace: {chain_spec}"
        ) from exc
    chain_spec_digest = _sha256_regular(chain_spec, "chain spec")
    source_revision = _required_config_text(spec, "source_revision")
    plan_dir = resolve_plan_dir(workspace, plan_name)
    if plan_dir.is_symlink() or not plan_dir.is_dir():
        raise FreshChildLaunchError(f"child plan directory is not a regular directory: {plan_dir}")
    idea_snapshot = plan_dir / "idea_snapshot.md"
    idea_digest = _sha256_regular(idea_snapshot, "idea snapshot")

    input_manifest = {
        "schema": "arnold.megaplan.fresh_child_input_manifest.v1",
        "chain_spec_sha256": chain_spec_digest,
        "idea_snapshot_sha256": idea_digest,
        "plan_name": plan_name,
        "milestone_label": milestone.label,
        "milestone_index": milestone_index,
        "source_revision": source_revision,
    }
    plan_artifact_digest = _digest(input_manifest)
    execution_binding = getattr(state, "metadata", {})
    if not isinstance(execution_binding, Mapping):
        execution_binding = {}
    runtime_manifest = {
        "schema": "arnold.megaplan.fresh_child_runtime_binding.v1",
        "chain_spec_sha256": chain_spec_digest,
        "plan_name": plan_name,
        "milestone_label": milestone.label,
        "milestone_index": milestone_index,
        "environment": spec.environment,
        "session": spec.session,
        "chain": spec.chain,
        "phase": spec.phase,
        "task": spec.task,
        "execution_binding": _without_volatile(execution_binding.get("execution_binding", {})),
    }
    runtime_binding_digest = _digest(runtime_manifest)
    worker_dispatch_target = {
        "boundary": "child_worker_dispatch",
        "workspace": str(workspace),
        "chain_spec": str(chain_spec),
        "plan_name": plan_name,
        "milestone_label": milestone.label,
        "milestone_index": milestone_index,
        "runtime_binding_digest": runtime_binding_digest,
        "source_revision": source_revision,
    }
    worker_dispatch_descriptor = action_descriptor(
        capability="execute",
        boundary="child_worker_dispatch",
        target_binding=worker_dispatch_target,
    )

    chain_identity = _required_config_text(spec, "chain_identity")
    run_revision = spec.run_revision or f"milestone-{milestone_index}:{plan_name}"
    if not isinstance(run_revision, str) or not run_revision.strip():
        raise FreshChildLaunchError("fresh_child_admission.run_revision is required when supplied")
    run_revision = run_revision.strip()
    child_run_id = f"{chain_identity}:child:{plan_name}"
    coordinator_attempt_id = f"{child_run_id}:coordinator:1"
    subject_id = f"{chain_identity.strip()}:{milestone.label}"
    subject_attempt_id = f"{child_run_id}:attempt:1"
    request = FreshChildRequest(
        run_id=child_run_id,
        run_revision=run_revision,
        coordinator_attempt_id=coordinator_attempt_id,
        subject_id=subject_id,
        subject_attempt_id=subject_attempt_id,
        child_selector={
            "schema": "arnold.megaplan.fresh_child_selector.v1",
            "workspace": str(workspace),
            "chain_spec": str(chain_spec),
            "plan_name": plan_name,
            "milestone_label": milestone.label,
            "milestone_index": milestone_index,
            "input_manifest_digest": plan_artifact_digest,
            "runtime_binding_digest": runtime_binding_digest,
            "authorized_action_descriptors": [worker_dispatch_descriptor],
        },
        environment=spec.environment,
        session=spec.session,
        chain=spec.chain,
        phase=spec.phase,
        task=spec.task,
        normalized_failure_kind=_required_config_text(spec, "normalized_failure_kind"),
        blocker_or_phase_result_hash=_required_config_text(
            spec, "blocker_or_phase_result_hash"
        ),
        chain_identity=chain_identity,
        plan_artifact_digest=plan_artifact_digest,
        runtime_binding_digest=runtime_binding_digest,
        source_revision=source_revision,
        approval_receipt=_required_config_text(spec, "approval_receipt"),
        approval_actor=_required_config_text(spec, "approval_actor"),
        parent_occurrence_digest=_required_config_text(
            spec, "parent_occurrence_digest"
        ),
    )
    journal, wbc, custody = _owner_bundle(workspace, spec)
    try:
        try:
            receipt = FreshChildAdmission(journal=journal, wbc=wbc, custody=custody).admit(request)
        except FreshChildAdmissionError as exc:
            raise FreshChildLaunchError(f"fresh-child owner admission failed: {exc}") from exc

        context = FreshChildAuthorityContext(
            receipt=receipt, journal=journal, wbc=wbc, custody=custody
        )
        payload = _receipt_payload(receipt, owner_paths=context.owner_paths)
        receipt_path = plan_dir / RECEIPT_FILENAME
        receipt_digest = _write_receipt(receipt_path, payload)
        return {
            "schema": "arnold.megaplan.fresh_child_pointer.v1",
            "receipt_path": str(receipt_path),
            "receipt_digest": receipt_digest,
            "request_digest": request.request_digest,
            "plan_name": plan_name,
        }
    finally:
        store = getattr(wbc, "store", None)
        if store is not None and callable(getattr(store, "close", None)):
            store.close()


def _load_admitted_child(
    pointer: Mapping[str, Any], *, plan_dir: Path
) -> tuple[FreshChildAuthorityContext, dict[str, Any]]:
    """Rehydrate a child receipt and its canonical owners without writing."""
    if (
        not isinstance(pointer, Mapping)
        or pointer.get("schema") != "arnold.megaplan.fresh_child_pointer.v1"
    ):
        raise FreshChildLaunchError("fresh-child authority pointer is malformed")
    canonical_plan_dir = Path(os.path.abspath(os.fspath(plan_dir)))
    expected_path = canonical_plan_dir / RECEIPT_FILENAME
    raw_receipt_path = Path(str(pointer.get("receipt_path") or ""))
    receipt_path = Path(os.path.abspath(os.fspath(raw_receipt_path)))
    if (
        not raw_receipt_path.is_absolute()
        or raw_receipt_path != receipt_path
        or receipt_path != expected_path
    ):
        raise FreshChildLaunchError("fresh-child receipt pointer is outside its plan")
    plan_fd = _open_nofollow(canonical_plan_dir, directory=True, label="fresh-child plan directory")
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        receipt_fd = os.open(RECEIPT_FILENAME, flags, dir_fd=plan_fd)
        try:
            receipt_raw = _read_held_regular(
                receipt_fd, label="fresh-child receipt", maximum=_MAX_RECEIPT_BYTES
            )
        finally:
            os.close(receipt_fd)
    except (OSError, FreshChildLaunchError) as exc:
        raise FreshChildLaunchError("fresh-child receipt is unavailable or unsafe") from exc
    finally:
        os.close(plan_fd)
    try:
        payload = json.loads(receipt_raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise FreshChildLaunchError("fresh-child receipt is unreadable") from exc
    if not isinstance(payload, dict) or _digest(payload) != pointer.get("receipt_digest"):
        raise FreshChildLaunchError("fresh-child receipt digest drift")
    request_raw = payload.get("request")
    identity_raw = payload.get("identity")
    authority_raw = payload.get("authority")
    owner_paths = payload.get("owner_paths")
    if not all(
        isinstance(value, Mapping)
        for value in (request_raw, identity_raw, authority_raw, owner_paths)
    ):
        raise FreshChildLaunchError("fresh-child receipt is incomplete")
    held: list[int] = []
    authority_connection: sqlite3.Connection | None = None
    wbc_connection: sqlite3.Connection | None = None
    custody = None
    owner_custody = None
    try:
        request_values = dict(request_raw)
        request_values.pop("schema", None)
        request_digest = request_values.pop("request_digest", None)
        request = FreshChildRequest(**request_values)
        identity = FreshChildIdentity(**dict(identity_raw))
        if (
            request.request_digest != request_digest
            or request_digest != pointer.get("request_digest")
        ):
            raise FreshChildLaunchError("fresh-child request identity drift")
        if identity.request_digest != request.request_digest:
            raise FreshChildLaunchError("fresh-child receipt identity drift")
        decision_raw = authority_raw.get("decision")
        authority = ChildAuthority(
            fence=CoordinatorFence.from_dict(authority_raw["fence"]),
            grant=CapabilityGrant.from_dict(authority_raw["grant"]),
            attempt=SubjectAttempt.from_dict(authority_raw["attempt"]),
            claim=Claim.from_dict(authority_raw["claim"]),
            evidence=tuple(
                EvidenceEnvelope.from_dict(item) for item in authority_raw["evidence"]
            ),
            decision=(
                Decision.from_dict(decision_raw)
                if isinstance(decision_raw, Mapping)
                else None
            ),
        )
        from arnold.workflow.attempt_ledger_store import SqliteAttemptLedgerStore
        from arnold_pipelines.megaplan.custody.contracts import (
            normalize_custody_lease,
            normalize_repair_occurrence_key,
        )
        from arnold_pipelines.megaplan.custody.lease_store import open_lease_store
        from arnold_pipelines.megaplan.migration.owner_adapters import (
            AttemptLedgerWbcOwner,
            CustodyLeaseStoreOwner,
        )
        from arnold_pipelines.run_authority.journal import RunAuthorityJournal

        workspace = Path(
            os.path.abspath(str(request.child_selector.get("workspace") or ""))
        )
        canonical_plan_dir.relative_to(workspace)
        authority_path = _resolve_owned_path(
            workspace, str(owner_paths["authority_journal"]), "authority journal"
        )
        wbc_path = _resolve_owned_path(
            workspace, str(owner_paths["wbc_ledger"]), "WBC ledger"
        )
        custody_path = _resolve_owned_path(
            workspace,
            str(owner_paths["custody_lease_dir"]),
            "Custody lease directory",
        )
        try:
            authority_parent_fd = _open_nofollow(
                authority_path.parent, directory=True, label="authority journal directory"
            )
            held.append(authority_parent_fd)
            _assert_private_owner_directory(
                authority_parent_fd, label="authority journal directory"
            )
            try:
                authority_fd = os.open(
                    authority_path.name,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=authority_parent_fd,
                )
            except OSError as exc:
                raise FreshChildLaunchError(
                    "canonical authority journal is unavailable or unsafe"
                ) from exc
            if not stat.S_ISREG(os.fstat(authority_fd).st_mode):
                raise FreshChildLaunchError("canonical authority journal is not a regular file")
            held.append(authority_fd)
            _hold_existing_sqlite_sidecars(
                authority_parent_fd, authority_path.name, label="authority journal", held=held
            )

            wbc_parent_fd = _open_nofollow(
                wbc_path.parent, directory=True, label="WBC ledger directory"
            )
            held.append(wbc_parent_fd)
            _assert_private_owner_directory(
                wbc_parent_fd, label="WBC ledger directory"
            )
            try:
                wbc_fd = os.open(
                    wbc_path.name,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=wbc_parent_fd,
                )
            except OSError as exc:
                raise FreshChildLaunchError(
                    "canonical WBC ledger is unavailable or unsafe"
                ) from exc
            if not stat.S_ISREG(os.fstat(wbc_fd).st_mode):
                raise FreshChildLaunchError("canonical WBC ledger is not a regular file")
            held.append(wbc_fd)
            _hold_existing_sqlite_sidecars(
                wbc_parent_fd, wbc_path.name, label="WBC ledger", held=held
            )

            custody_fd = _open_nofollow(
                custody_path, directory=True, label="Custody lease directory"
            )
            held.append(custody_fd)
            _assert_private_owner_directory(
                custody_fd, label="Custody lease directory"
            )
            authority_connection, authority_connection_fd = _open_verified_sqlite(
                authority_path, authority_fd, label="authority journal", timeout=30.0
            )
            wbc_connection, wbc_connection_fd = _open_verified_sqlite(
                wbc_path, wbc_fd, label="WBC ledger", timeout=10.0
            )
            journal = RunAuthorityJournal(
                authority_path, connection=authority_connection
            )
            wbc = AttemptLedgerWbcOwner(
                SqliteAttemptLedgerStore(wbc_path, connection=wbc_connection)
            )
            custody = CustodyLeaseStoreOwner(
                open_lease_store(custody_path, directory_fd=os.dup(custody_fd))
            )
            _hold_existing_sqlite_sidecars(
                authority_parent_fd, authority_path.name, label="authority journal", held=held
            )
            _hold_existing_sqlite_sidecars(
                wbc_parent_fd, wbc_path.name, label="WBC ledger", held=held
            )
            owner_custody = _HeldOwnerCustody(
                held, (authority_connection_fd, wbc_connection_fd)
            )
            owner_custody.assert_connected()
            reservation = wbc.read_reservation(identity.wbc_attempt_id, identity.glek)
            owner_custody.assert_connected()
        except Exception:
            if authority_connection is not None:
                authority_connection.close()
            if wbc_connection is not None:
                wbc_connection.close()
            while held:
                try:
                    os.close(held.pop())
                except OSError:
                    pass
            raise
        admitted_lease = normalize_custody_lease(payload.get("custody"))
        occurrence = normalize_repair_occurrence_key(payload.get("occurrence"))
        if reservation is None or admitted_lease is None or occurrence is None:
            raise FreshChildLaunchError("fresh-child receipt contracts are incomplete")
        receipt = FreshChildAdmissionReceipt(
            request=request,
            identity=identity,
            authority=authority,
            wbc=reservation,
            custody=admitted_lease,
            occurrence=occurrence,
        )
        receipt.assert_ready()
        context = FreshChildAuthorityContext(
            receipt=receipt, journal=journal, wbc=wbc, custody=custody
        )
        context._held_owner_custody = owner_custody
        return context, payload
    except Exception as exc:
        if custody is not None:
            custody_store = getattr(custody, "store", None)
            if custody_store is not None and callable(getattr(custody_store, "close", None)):
                custody_store.close()
        if isinstance(owner_custody, _HeldOwnerCustody):
            owner_custody.close()
        for connection in (authority_connection, wbc_connection):
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass
        while held:
            try:
                os.close(held.pop())
            except OSError:
                pass
        if isinstance(exc, FreshChildLaunchError):
            raise
        raise FreshChildLaunchError(
            f"fresh-child canonical owner rehydration failed: {type(exc).__name__}: {exc}"
        ) from exc


def _read_context_authority(
    context: FreshChildAuthorityContext,
    *,
    expected: Mapping[str, Any] | None,
    require_dispatch_eligible: bool,
) -> dict[str, Any]:
    descriptors = context.receipt.request.child_selector.get(
        "authorized_action_descriptors"
    )
    if not isinstance(descriptors, list) or len(descriptors) != 1:
        raise FreshChildLaunchError("fresh-child worker scope is not an exact singleton")
    descriptor = descriptors[0]
    if not isinstance(descriptor, Mapping) or descriptor.get("capability") != "execute":
        raise FreshChildLaunchError("fresh-child worker scope is malformed")
    target = descriptor.get("target_binding")
    if not isinstance(target, Mapping) or target.get("boundary") != "child_worker_dispatch":
        raise FreshChildLaunchError("fresh-child worker target is malformed")
    owner_custody = getattr(context, "_held_owner_custody", None)
    if not isinstance(owner_custody, _HeldOwnerCustody):
        raise FreshChildLaunchError("fresh-child owner descriptor custody is unavailable")
    try:
        owner_custody.assert_connected()
        try:
            authority = context.read(
                capability="execute", target_binding=target, expected=expected
            )
            store = getattr(context.wbc, "store", None)
            if require_dispatch_eligible and (
                store is None
                or not store.is_dispatch_eligible(
                    context.receipt.identity.wbc_attempt_id, context.receipt.identity.glek
                )
            ):
                raise FreshChildLaunchError("fresh-child WBC attempt is terminal or ineligible")
            return authority
        finally:
            owner_custody.assert_connected()
    except FreshChildLaunchError:
        raise
    except FreshChildAdmissionError as exc:
        raise FreshChildLaunchError(str(exc)) from exc


def read_fresh_child_authority(
    pointer: Mapping[str, Any],
    *,
    plan_dir: Path,
    expected: Mapping[str, Any] | None = None,
    require_dispatch_eligible: bool = True,
) -> dict[str, Any]:
    """Read the exact admitted grant, WBC reservation, and live Custody lease.

    The verifier deliberately never renews the admitted lease.  Expiry during
    or between phases is an authority loss that must fail closed.
    """
    context, _payload = _load_admitted_child(pointer, plan_dir=plan_dir)
    try:
        return _read_context_authority(
            context,
            expected=expected,
            require_dispatch_eligible=require_dispatch_eligible,
        )
    finally:
        _close_loaded_context(context)


def _close_loaded_context(context: FreshChildAuthorityContext) -> None:
    if callable(getattr(context.journal, "close", None)):
        context.journal.close()
    store = getattr(context.wbc, "store", None)
    if store is not None and callable(getattr(store, "close", None)):
        store.close()
    custody_store = getattr(context.custody, "store", None)
    if custody_store is not None and callable(getattr(custody_store, "close", None)):
        custody_store.close()
    held = getattr(context, "_held_owner_custody", None)
    if isinstance(held, _HeldOwnerCustody):
        held.close()


def phase_wbc_handoff(
    pointer: Mapping[str, Any],
    *,
    plan_dir: Path,
    step: str,
    invocation_id: str | None = None,
) -> dict[str, Any]:
    """Project a verified child pointer into one common worker-dispatch phase."""
    if not isinstance(step, str) or not step.strip():
        raise FreshChildLaunchError("fresh-child WBC handoff requires a phase step")
    authority = read_fresh_child_authority(pointer, plan_dir=plan_dir)
    projection = {
        "step": step.strip(),
        "attempt_id": authority["wbc_attempt_id"],
        "source_version": (
            f"fresh-child:{pointer['request_digest']}:{authority['run_revision']}"
        ),
        "projected_from_fresh_child": True,
        "fresh_child_pointer": dict(pointer),
        "authority_binding": authority,
    }
    if isinstance(invocation_id, str) and invocation_id:
        projection["invocation_id"] = invocation_id
    return projection


def terminalize_fresh_child(
    pointer: Mapping[str, Any],
    *,
    plan_dir: Path,
    outcome_kind: str,
    outcome_payload: Mapping[str, Any],
) -> dict[str, Any]:
    """CAS one truthful terminal outcome for the admitted child lifecycle."""
    if outcome_kind not in {"COMPLETED", "FAILED", "BLOCKED"}:
        raise FreshChildLaunchError("unsupported fresh-child terminal outcome")
    context, _payload = _load_admitted_child(pointer, plan_dir=plan_dir)
    try:
        _read_context_authority(
            context, expected=None, require_dispatch_eligible=False
        )
        store = getattr(context.wbc, "store", None)
        if store is None:
            raise FreshChildLaunchError("canonical fresh-child WBC store is unavailable")
        owner_custody = getattr(context, "_held_owner_custody", None)
        if not isinstance(owner_custody, _HeldOwnerCustody):
            raise FreshChildLaunchError("fresh-child owner descriptor custody is unavailable")
        owner_custody.assert_connected()
        try:
            result = store.accept_terminal_outcome(
                context.receipt.identity.wbc_attempt_id,
                context.receipt.identity.glek,
                outcome_kind,
                dict(outcome_payload),
            )
        finally:
            owner_custody.assert_connected()
        return _canonical(result)
    finally:
        _close_loaded_context(context)


__all__ = [
    "FRESH_CHILD_LAUNCH_SCHEMA",
    "FreshChildLaunchError",
    "RECEIPT_FILENAME",
    "admit_fresh_child",
    "phase_wbc_handoff",
    "provision_fresh_child_authority",
    "read_fresh_child_authority",
    "terminalize_fresh_child",
]
