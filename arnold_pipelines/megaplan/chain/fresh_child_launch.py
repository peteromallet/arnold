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
from pathlib import Path
from typing import Any, Mapping

from arnold_pipelines.megaplan._core import resolve_plan_dir
from arnold_pipelines.megaplan._core.io import write_immutable_json
from arnold_pipelines.megaplan.migration.fresh_child_admission import (
    FRESH_CHILD_SCHEMA,
    FreshChildAuthorityContext,
    FreshChildAdmission,
    FreshChildAdmissionError,
    FreshChildRequest,
    action_descriptor,
)


FRESH_CHILD_LAUNCH_SCHEMA = "arnold.megaplan.fresh_child_launch_receipt.v1"
RECEIPT_FILENAME = "fresh_child_admission.json"


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
    """Resolve an owner path and prove it remains inside this child workspace."""

    if not isinstance(raw, str) or not raw.strip():
        raise FreshChildLaunchError(f"{label} is required for fresh-child admission")
    workspace = root.resolve(strict=True)
    configured = Path(raw.strip())
    candidate = (configured if configured.is_absolute() else workspace / configured).resolve(
        strict=False
    )
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise FreshChildLaunchError(
            f"{label} must resolve below the child workspace {workspace}: {candidate}"
        ) from exc
    if candidate == workspace:
        raise FreshChildLaunchError(f"{label} cannot be the child workspace itself")

    # Do not allow an existing symlink in the owner path.  ``resolve`` above
    # prevents escape, but accepting a symlink would make ownership mutable by
    # an external process between validation and open.
    current = workspace
    relative_parts = candidate.relative_to(workspace).parts
    for part in relative_parts:
        current = current / part
        if current.is_symlink():
            raise FreshChildLaunchError(f"{label} cannot contain symlink component: {current}")
    return candidate


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


def _receipt_payload(receipt: Any) -> dict[str, Any]:
    """Serialize the owner receipt without throwing away contract evidence."""

    return {
        "schema": FRESH_CHILD_LAUNCH_SCHEMA,
        "admission_schema": FRESH_CHILD_SCHEMA,
        "request": receipt.request.to_dict(),
        "identity": _canonical(receipt.identity),
        "authority": _canonical(receipt.authority),
        "wbc": _wbc_dict(receipt.wbc),
        "custody": _canonical(receipt.custody),
        "occurrence": _canonical(receipt.occurrence),
    }


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
        receipt = FreshChildAdmission(journal=journal, wbc=wbc, custody=custody).admit(request)
    except FreshChildAdmissionError as exc:
        raise FreshChildLaunchError(f"fresh-child owner admission failed: {exc}") from exc

    payload = _receipt_payload(receipt)
    receipt_path = plan_dir / RECEIPT_FILENAME
    receipt_digest = _write_receipt(receipt_path, payload)
    return {
        "schema": FRESH_CHILD_LAUNCH_SCHEMA,
        "receipt_path": str(receipt_path),
        "receipt_digest": receipt_digest,
        "request_digest": request.request_digest,
        "run_id": request.run_id,
        "run_revision": request.run_revision,
        "plan_artifact_digest": request.plan_artifact_digest,
        "runtime_binding_digest": request.runtime_binding_digest,
        "occurrence_digest": receipt.occurrence.occurrence_digest,
        "wbc_attempt_id": receipt.wbc.attempt_id,
        "glek": receipt.wbc.glek,
        "authority_grant_id": receipt.authority.grant.grant_id,
        "custody_lease_id": receipt.custody.lease_id,
    }


__all__ = [
    "FRESH_CHILD_LAUNCH_SCHEMA",
    "FreshChildLaunchError",
    "RECEIPT_FILENAME",
    "admit_fresh_child",
    "provision_fresh_child_authority",
]
