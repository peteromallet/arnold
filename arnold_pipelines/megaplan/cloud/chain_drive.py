"""Authoritative cloud launch engine.

This module is executed in the provider's engine container (or directly by a
co-located local provider). The controller sends a JSON request and receives a
typed response; it never creates a receipt, marker, synthetic operation id,
replacement session, or retry attempt.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
from typing import Any, Mapping, Sequence

from arnold.runtime.durable_ops import (
    LaunchDispatchRejected,
    LaunchEnvelope,
    LaunchResult,
    ResourceType,
    TypedResource,
    inspect_launch,
    launch_transaction,
    run_launch_preflight,
)

from agentbox.config import load_agentbox_config
from agentbox.operations import open_operation_store
from agentbox.tmux import inspect_session, new_session_argv, run_tmux
from arnold_pipelines.megaplan.cloud.runtime_manifest import (
    DEPENDENCY_GENERATION_REQUIRED,
    EPIC_REQUIRED,
    ManifestError,
    MANIFEST_SCHEMA_VERSION,
    RuntimeManifest,
    TOP_LEVEL_REQUIRED,
)
from arnold_pipelines.megaplan.cloud.install_sync import compute_venv_digest
from arnold_pipelines.megaplan.cloud.runtime_provenance import runtime_provenance


class ChainDriveError(RuntimeError):
    """A malformed or unplaceable authoritative launch request."""


def _runtime_binding_from_envelope(envelope: LaunchEnvelope) -> Mapping[str, Any]:
    metadata = envelope.launch_spec.get("metadata")
    binding = metadata.get("runtime_binding") if isinstance(metadata, Mapping) else None
    if not isinstance(binding, Mapping):
        raise ValueError("missing runtime manifest binding")
    return binding


def _envelope_has_runtime_binding(envelope: LaunchEnvelope) -> bool:
    metadata = envelope.launch_spec.get("metadata")
    return isinstance(metadata, Mapping) and "runtime_binding" in metadata


def _authority_binding_from_envelope(envelope: LaunchEnvelope) -> Mapping[str, Any]:
    metadata = envelope.launch_spec.get("metadata")
    binding = metadata.get("authority_binding") if isinstance(metadata, Mapping) else None
    if not isinstance(binding, Mapping):
        raise ValueError("missing current authority binding")
    required = {
        "schema", "run_id", "run_revision", "coordinator_attempt_id",
        "subject_id", "subject_attempt_id", "capability", "grant_id",
        "fence_token", "claim_id", "decision_id", "journal_cursor",
        "view_hash", "grant_ref", "fence_ref", "attempt_ref", "decision_ref",
        "wbc_attempt_id", "glek", "custody_lease_id", "custody_epoch",
        "custody_ref", "target_binding",
    }
    if binding.get("schema") != "arnold.megaplan.current_authority_binding.v1":
        raise ValueError("current authority binding schema mismatch")
    missing = sorted(key for key in required if key not in binding)
    if missing:
        raise ValueError("current authority binding missing fields: " + ", ".join(missing))
    for key in (
        "run_id", "run_revision", "coordinator_attempt_id", "subject_id",
        "subject_attempt_id", "capability", "grant_id", "claim_id",
        "decision_id", "view_hash", "grant_ref", "fence_ref", "attempt_ref",
        "decision_ref", "wbc_attempt_id", "glek", "custody_lease_id", "custody_ref",
    ):
        if not isinstance(binding.get(key), str) or not binding[key]:
            raise ValueError(f"current authority binding field {key} is invalid")
    if not isinstance(binding.get("target_binding"), Mapping) or not binding["target_binding"]:
        raise ValueError("current authority binding target is invalid")
    if not isinstance(binding.get("journal_cursor"), int) or binding["journal_cursor"] < 0:
        raise ValueError("current authority binding journal cursor is invalid")
    if not isinstance(binding.get("custody_epoch"), int) or binding["custody_epoch"] < 0:
        raise ValueError("current authority binding custody epoch is invalid")
    return binding


def _canonical_runtime_identity(runtime_source: str, runtime_revision: str) -> dict[str, Any]:
    identity: dict[str, Any] = {
        "import_root": runtime_source,
        "source_revision": runtime_revision,
        "editable_root": "",
        "editable_revision": "",
        "direct_url": {},
        "pth": [],
        "imports": {
            "arnold": runtime_source + "/arnold/__init__.py",
            "arnold_pipelines": runtime_source + "/arnold_pipelines/__init__.py",
            "megaplan": runtime_source + "/arnold_pipelines/megaplan/__init__.py",
        },
    }
    core = dict(identity)
    for key in ("editable_root", "editable_revision", "direct_url", "pth", "imports"):
        core[key] = None
    identity["content_sha256"] = hashlib.sha256(
        json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return identity


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_json(item) for item in value]
    return value


def _validate_runtime_manifest_binding(envelope: LaunchEnvelope) -> dict[str, Any]:
    """Validate the envelope's immutable runtime binding before admission."""
    binding = _runtime_binding_from_envelope(envelope)
    required = {
        "manifest_path",
        "manifest_sha256",
        "manifest_identity",
        "runtime_id",
        "runtime_source",
        "runtime_revision",
        "runtime_identity",
        "runtime_identity_raw",
    }
    missing = sorted(required - set(binding))
    if missing:
        raise ValueError("runtime manifest binding missing fields: " + ", ".join(missing))

    manifest_text = binding.get("manifest_path")
    if not isinstance(manifest_text, str) or not manifest_text or not Path(manifest_text).is_absolute():
        raise ValueError("runtime manifest binding path must be absolute")
    manifest_path = Path(manifest_text).expanduser().resolve(strict=False)

    digest = binding.get("manifest_sha256")
    identity_digest = binding.get("manifest_identity")
    if (
        not isinstance(digest, str)
        or not isinstance(identity_digest, str)
        or digest != identity_digest
        or len(digest) != 64
        or any(char not in "0123456789abcdef" for char in digest)
    ):
        raise ValueError("runtime manifest binding has an invalid byte hash")
    try:
        raw = manifest_path.read_bytes()
    except OSError as exc:
        raise ValueError(f"runtime manifest binding unreadable: {manifest_path}") from exc
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("runtime manifest binding byte hash mismatch")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("runtime manifest binding is not valid UTF-8 JSON") from exc
    if not (
        isinstance(payload, dict)
        and payload.get("schema") == MANIFEST_SCHEMA_VERSION
        and all(field in payload for field in TOP_LEVEL_REQUIRED)
    ):
        raise ValueError("runtime manifest binding schema mismatch")
    try:
        manifest = RuntimeManifest.from_dict(payload)
    except (ManifestError, TypeError, ValueError) as exc:
        raise ValueError(f"runtime manifest binding schema invalid: {exc}") from exc
    if manifest.compatibility_only:
        raise ValueError("runtime manifest binding points to compatibility-only content")
    if manifest.state != "active":
        raise ValueError("runtime manifest binding is not active")
    epic = manifest.epic
    if not all(field in epic for field in EPIC_REQUIRED):
        raise ValueError("runtime manifest binding missing epic schema")
    for field in ("runtime_root", "expected_head"):
        if not isinstance(epic.get(field), str) or not epic[field]:
            raise ValueError(f"runtime manifest binding missing epic.{field}")

    runtime_id = binding.get("runtime_id")
    runtime_source = binding.get("runtime_source")
    runtime_revision = binding.get("runtime_revision")
    if (
        not isinstance(runtime_id, str)
        or not runtime_id
        or manifest.runtime_id != runtime_id
        or not isinstance(runtime_source, str)
        or not Path(runtime_source).is_absolute()
        or not Path(runtime_source).is_dir()
        or runtime_source != str(Path(epic["runtime_root"]).expanduser().resolve(strict=False))
        or not isinstance(runtime_revision, str)
        or len(runtime_revision) != 40
        or any(char not in "0123456789abcdef" for char in runtime_revision)
        or runtime_revision != epic["expected_head"]
    ):
        raise ValueError("runtime manifest binding runtime identity mismatch")

    raw_identity = binding.get("runtime_identity_raw")
    if not isinstance(raw_identity, Mapping):
        raise ValueError("runtime manifest binding missing raw runtime identity")
    expected_raw = {
        "runtime_id": runtime_id,
        "epic_id": manifest.epic_id,
        "runtime_source": runtime_source,
        "runtime_revision": runtime_revision,
    }
    if dict(raw_identity) != expected_raw:
        raise ValueError("runtime manifest binding raw runtime identity mismatch")
    canonical = binding.get("runtime_identity")
    if not isinstance(canonical, Mapping) or _plain_json(canonical) != _canonical_runtime_identity(runtime_source, runtime_revision):
        raise ValueError("runtime manifest binding canonical runtime identity mismatch")

    return {
        "manifest_path": str(manifest_path),
        "manifest_sha256": digest,
        "manifest_identity": digest,
        "runtime_id": runtime_id,
        "runtime_source": runtime_source,
        "runtime_revision": runtime_revision,
        "runtime_identity": dict(canonical),
        "runtime_identity_raw": expected_raw,
        "dependency_generation": dict(epic.get("dependency_generation") or {}),
    }


def _validate_launch_attestation(
    envelope: LaunchEnvelope, binding: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate the existing runtime/packet/model evidence before admission."""
    metadata = envelope.launch_spec.get("metadata")
    attestation = metadata.get("launch_attestation") if isinstance(metadata, Mapping) else None
    if not isinstance(attestation, Mapping):
        raise ValueError("launch attestation is missing")
    if attestation.get("schema") != "arnold.megaplan.launch_attestation.v1":
        raise ValueError("launch attestation schema mismatch")
    if attestation.get("manifest_identity") != binding["manifest_identity"]:
        raise ValueError("launch attestation manifest identity mismatch")
    runtime_vector = attestation.get("runtime_vector")
    if not isinstance(runtime_vector, Mapping) or _plain_json(runtime_vector) != _plain_json(binding["runtime_identity"]):
        raise ValueError("launch attestation runtime vector mismatch")
    provenance = attestation.get("provenance")
    if not isinstance(provenance, Mapping) or provenance.get("status") != "verified":
        raise ValueError("launch attestation provenance is not verified")
    if (
        str(provenance.get("root") or "") != binding["runtime_source"]
        or str(provenance.get("revision") or "") != binding["runtime_revision"]
    ):
        raise ValueError("launch attestation provenance identity mismatch")
    dependency = attestation.get("dependency_generation")
    if not isinstance(dependency, Mapping) or not dependency:
        raise ValueError("launch attestation dependency proof is missing")
    manifest_dependency = binding.get("dependency_generation")
    if isinstance(manifest_dependency, Mapping) and dict(dependency) != dict(manifest_dependency):
        raise ValueError("launch attestation dependency proof mismatch")
    interpreter = str(attestation.get("dependency_interpreter_identity") or "")
    if not interpreter or str(dependency.get("interpreter_path") or "") != interpreter:
        raise ValueError("launch attestation interpreter proof mismatch")
    interpreter_path = Path(interpreter).expanduser().resolve(strict=False)
    if not interpreter_path.is_absolute() or not interpreter_path.is_file() or not os.access(interpreter_path, os.X_OK):
        raise ValueError("launch attestation interpreter is not executable")
    seed_identity = str(attestation.get("seed_identity") or "")
    if len(seed_identity) != 64 or any(char not in "0123456789abcdef" for char in seed_identity):
        raise ValueError("launch attestation seed identity is invalid")
    packet = attestation.get("execution_packet")
    if not isinstance(packet, Mapping):
        raise ValueError("launch attestation execution packet is missing")
    expected_packet = {
        "command": envelope.launch_spec.get("command"),
        "cwd": envelope.launch_spec.get("cwd"),
        "session": envelope.launch_spec.get("expected_session_name"),
        "manifest_path": binding["manifest_path"],
        "manifest_identity": binding["manifest_identity"],
    }
    command = expected_packet["command"]
    command_bytes = (
        command.encode("utf-8")
        if isinstance(command, str)
        else json.dumps(command, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    expected_packet["command_sha256"] = hashlib.sha256(command_bytes).hexdigest()
    if any(packet.get(key) != value for key, value in expected_packet.items()):
        raise ValueError("launch attestation execution packet mismatch")
    expected_packet_digest = hashlib.sha256(
        json.dumps(expected_packet, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if packet.get("sha256") != expected_packet_digest:
        raise ValueError("launch attestation execution packet digest mismatch")
    policy = attestation.get("model_policy")
    if not isinstance(policy, Mapping) or policy.get("status") != "resolved":
        raise ValueError("launch attestation model policy is missing")
    route = str(policy.get("route") or "")
    if route:
        if route != "omp:openrouter/meta/muse-spark-1.3-contributor:high":
            raise ValueError("launch attestation model policy route mismatch")
        if policy.get("fallback") is not False:
            raise ValueError("launch attestation model policy permits fallback")
        roles = policy.get("roles")
        required_roles = {
            "babysitter", "fixer", "controller", "researcher", "oracle", "superfixer"
        }
        if not isinstance(roles, Mapping) or set(roles) != required_roles or any(
            roles.get(role) != route for role in required_roles
        ):
            raise ValueError("launch attestation model policy role closure is incomplete")
    return dict(attestation)


def _validate_live_runtime(binding: Mapping[str, Any]) -> None:
    """Re-attest imports, source HEAD and the immutable dependency generation."""
    try:
        provenance = runtime_provenance(
            expected_root=Path(binding["runtime_source"]),
            expected_revision=str(binding["runtime_revision"]),
        )
    except Exception as exc:  # noqa: BLE001 - unknown physical fact blocks launch
        raise ValueError(f"live runtime provenance probe failed: {type(exc).__name__}") from exc
    if not isinstance(provenance, Mapping) or provenance.get("ok") is not True:
        errors = provenance.get("errors") if isinstance(provenance, Mapping) else None
        raise ValueError(f"live runtime provenance is not verified: {errors or 'unknown'}")

    dependency = binding.get("dependency_generation")
    try:
        from arnold_pipelines.megaplan.cloud.runtime_manifest import validate_dependency_generation

        proof = validate_dependency_generation(dependency)
        interpreter = Path(str(proof["interpreter_path"])).expanduser().resolve(strict=False)
        generation = interpreter.parent.parent
        if not interpreter.is_file() or not os.access(interpreter, os.X_OK):
            raise ValueError("dependency-generation interpreter is not executable")
        if generation.name != str(proof["id"]):
            raise ValueError("dependency-generation interpreter is not content-addressed")
        if compute_venv_digest(interpreter) != str(proof["venv_digest"]):
            raise ValueError("dependency-generation content digest mismatch")
        if set(proof) < set(DEPENDENCY_GENERATION_REQUIRED):
            raise ValueError("dependency-generation proof is incomplete")
    except Exception as exc:  # noqa: BLE001 - unknown dependency state blocks launch
        raise ValueError(f"live dependency generation probe failed: {exc}") from exc


def _validate_launch_observations(
    observations: Mapping[str, Any],
    envelope: LaunchEnvelope,
    binding: Mapping[str, Any],
    attestation: Mapping[str, Any],
) -> None:
    """Reject preflight rows that contradict live facts and the envelope.

    The controller's rows are transport projections only.  In particular, a
    caller cannot turn a declaration into source/dependency/authority or
    collision evidence by changing JSON before it reaches the engine.
    """
    source = observations.get("source")
    requested_source = str(envelope.launch_spec.get("source_revision") or "")
    if not isinstance(source, Mapping) or source.get("status") != "current":
        raise ValueError("source observation is not current")
    if str(source.get("revision") or "") != binding["runtime_revision"]:
        raise ValueError("source observation contradicts live runtime revision")
    if requested_source and len(requested_source) == 40 and requested_source != binding["runtime_revision"]:
        raise ValueError("requested source revision contradicts live runtime revision")

    # These inspect the imports, Git HEAD and immutable dependency generation
    # at the engine venue; manifest declarations alone are not sufficient.
    _validate_live_runtime(binding)

    runtime = observations.get("runtime")
    if not isinstance(runtime, Mapping):
        raise ValueError("runtime observation is missing")
    if (
        str(runtime.get("import_root") or runtime.get("runtime_root") or "")
        != binding["runtime_source"]
        or str(runtime.get("source_revision") or runtime.get("revision") or "")
        != binding["runtime_revision"]
        or str(runtime.get("interpreter") or runtime.get("runtime_python") or "")
        != str(attestation["dependency_interpreter_identity"])
    ):
        raise ValueError("runtime observation contradicts launch attestation")

    command = observations.get("command")
    if (
        not isinstance(command, Mapping)
        or command.get("status") != "valid"
        or command.get("argv") != envelope.launch_spec.get("command")
        or command.get("cwd") != envelope.launch_spec.get("cwd")
    ):
        raise ValueError("execution packet observation contradicts launch envelope")

    binding = _authority_binding_from_envelope(envelope)
    authority = observations.get("authority")
    authority_evidence = authority.get("evidence") if isinstance(authority, Mapping) else None
    if (
        not isinstance(authority, Mapping)
        or authority.get("status") != "current"
        or not isinstance(authority_evidence, Mapping)
        or authority_evidence.get("verified") is not True
        or authority_evidence.get("source") != "run-authority"
        or authority.get("grant") != binding["grant_id"]
        or str(authority.get("fence")) != str(binding["fence_token"])
        or authority.get("decision") != binding["decision_id"]
        or authority.get("attempt") != binding["subject_attempt_id"]
        or authority.get("subject") != binding["subject_id"]
        or authority.get("capability") != binding["capability"]
        or authority_evidence.get("journal_cursor") != binding["journal_cursor"]
        or authority_evidence.get("view_hash") != binding["view_hash"]
        or authority_evidence.get("grant_ref") != binding["grant_ref"]
        or authority_evidence.get("fence_ref") != binding["fence_ref"]
        or authority_evidence.get("attempt_ref") != binding["attempt_ref"]
        or authority_evidence.get("decision_ref") != binding["decision_ref"]
        or authority_evidence.get("custody_ref") != binding["custody_ref"]
        or authority_evidence.get("wbc_attempt_id") != binding["wbc_attempt_id"]
        or authority_evidence.get("glek") != binding["glek"]
        or authority_evidence.get("custody_lease_id") != binding["custody_lease_id"]
        or authority_evidence.get("custody_epoch") != binding["custody_epoch"]
    ):
        raise ValueError("authority observation is not bound to the current owner binding")

    custody = observations.get("custody")
    if (
        not isinstance(custody, Mapping)
        or custody.get("status") not in {"present", "current"}
        or custody.get("custody_ref") != envelope.launch_spec.get("cwd")
        or not str(custody.get("wbc_ref") or "")
    ):
        raise ValueError("custody observation is not bound to the launch envelope")
    collision = observations.get("collision")
    evidence = collision.get("evidence") if isinstance(collision, Mapping) else None
    if (
        not isinstance(evidence, Mapping)
        or evidence.get("verified") is not True
        or evidence.get("exists") is not False
        or str(evidence.get("session") or "")
        != str(envelope.launch_spec.get("expected_session_name") or "")
    ):
        raise ValueError("collision observation is not verified for the envelope session")


def _reread_current_authority(binding: Mapping[str, Any]) -> None:
    """Re-open the same RA/WBC/Custody owners immediately before admission."""
    locations = binding.get("owner_paths")
    if not isinstance(locations, Mapping) or not all(
        isinstance(locations.get(key), str) and Path(locations[key]).is_absolute()
        for key in ("authority_journal", "wbc_ledger", "custody_lease_dir")
    ):
        raise ValueError("current authority owner locations are missing")
    from arnold.workflow.attempt_ledger_store import SqliteAttemptLedgerStore
    from arnold_pipelines.megaplan.custody.lease_store import open_lease_store
    from arnold_pipelines.megaplan.maintenance.sources import RunAuthorityAdapter
    from arnold_pipelines.run_authority.current_source import CurrentSourceRequest
    from arnold_pipelines.run_authority.journal import RunAuthorityJournal
    from arnold_pipelines.run_authority.reducer import reduce_run_authority

    journal = RunAuthorityJournal(locations["authority_journal"])
    view = journal.read_view(binding["run_id"], binding["run_revision"])
    reduced = reduce_run_authority(
        view.records,
        run_id=binding["run_id"],
        run_revision=binding["run_revision"],
        journal_cursor=view.cursor,
    )
    source_request = CurrentSourceRequest(
        run_id=binding["run_id"],
        run_revision=binding["run_revision"],
        coordinator_attempt_id=binding["coordinator_attempt_id"],
        grant_id=binding["grant_id"],
        fence_token=str(binding["fence_token"]),
        subject_attempt_id=binding["subject_attempt_id"],
        decision_id=binding["decision_id"],
        subject_id=binding["subject_id"],
        capability=binding["capability"],
    )
    authority = RunAuthorityAdapter(lambda: reduced).read(source_request)
    current = authority.current_source
    if authority.torn or current is None or not current.satisfied:
        raise ValueError("G5A_REMOTE_BLOCKED: current Run Authority read is denied or torn")
    if authority.journal_cursor != binding["journal_cursor"] or authority.view_hash != binding["view_hash"]:
        raise ValueError("G5A_REMOTE_BLOCKED: Run Authority cursor or view hash drifted")
    refs = {ref.locator: ref.digest for ref in current.references}
    expected_refs = {
        f"grant://{binding['grant_id']}": binding["grant_ref"],
        f"fence://{binding['coordinator_attempt_id']}/{binding['fence_token']}": binding["fence_ref"],
        f"attempt://{binding['subject_attempt_id']}": binding["attempt_ref"],
        f"decision://{binding['decision_id']}": binding["decision_ref"],
    }
    if any(refs.get(locator) != digest for locator, digest in expected_refs.items()):
        raise ValueError("G5A_REMOTE_BLOCKED: Run Authority record digest drifted")

    store = SqliteAttemptLedgerStore(locations["wbc_ledger"])
    reservation = store.get_global_effect_reservation(binding["wbc_attempt_id"], binding["glek"])
    if reservation is None or reservation.attempt_id != binding["wbc_attempt_id"]:
        raise ValueError("G5A_REMOTE_BLOCKED: WBC reservation is missing or stale")
    lease = open_lease_store(locations["custody_lease_dir"]).current_lease(binding["custody_lease_id"])
    if lease is None or lease.is_expired:
        raise ValueError("G5A_REMOTE_BLOCKED: Custody lease is missing or expired")
    if (
        lease.run_authority_grant_id != binding["grant_id"]
        or str(lease.coordinator_fence_token) != str(binding["fence_token"])
        or lease.wbc_attempt_reference != binding["wbc_attempt_id"]
        or lease.custody_epoch != binding["custody_epoch"]
        or lease.digest() != binding["custody_ref"]
    ):
        raise ValueError("G5A_REMOTE_BLOCKED: Custody owner identity drifted")


def _probe_live_collision(session: str) -> None:
    """Probe the engine's live process namespace before durable admission."""
    try:
        status = inspect_session(session)
    except Exception as exc:  # noqa: BLE001 - probe errors fail closed
        raise ValueError(f"live collision probe failed: {type(exc).__name__}") from exc
    if not getattr(status, "exists", False) and getattr(status, "state", "") in {"missing", "dead"}:
        return
    if getattr(status, "exists", False):
        raise ValueError("launch session namespace is already occupied")
    raise ValueError("live collision probe is unknown")


def _json_response(
    *,
    result: LaunchResult | str,
    reason: str,
    operation_id: str,
    request_id: str,
    envelope_digest: str | None = None,
    detail: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": "arnold.megaplan.cloud_launch_response.v1",
        "result": LaunchResult(result).value,
        "reason": reason,
        "operation_id": operation_id,
        "request_id": request_id,
    }
    if envelope_digest:
        payload["envelope_digest"] = envelope_digest
    if detail:
        payload["detail"] = detail
    return payload


def _request_mapping(raw: Mapping[str, Any] | str) -> dict[str, Any]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ChainDriveError("launch request is not JSON") from exc
    if not isinstance(raw, Mapping):
        raise ChainDriveError("launch request must be a JSON object")
    request = dict(raw)
    required = {"envelope", "preflight_observations", "command", "cwd", "session"}
    missing = required - set(request)
    if missing:
        raise ChainDriveError("launch request missing fields: " + ", ".join(sorted(missing)))
    return request


def execute_authoritative_launch(request: Mapping[str, Any]) -> dict[str, Any]:
    """Execute exactly one launch at the store's physical location."""

    request = _request_mapping(request)
    envelope = LaunchEnvelope.from_json(request["envelope"])
    config = load_agentbox_config()
    configured_store_root = str(request.get("ops_store_root") or "").strip()
    actual_store_root = str(config.ops_store_root)
    if configured_store_root and Path(configured_store_root).resolve() != Path(actual_store_root).resolve():
        return _json_response(
            result=LaunchResult.REJECTED,
            reason="store_placement_mismatch",
            operation_id=envelope.operation_id,
            request_id=envelope.request_id,
            envelope_digest=envelope.digest,
            detail="engine store does not match the configured authoritative store",
        )
    try:
        runtime_binding = _validate_runtime_manifest_binding(envelope)
        launch_attestation = _validate_launch_attestation(envelope, runtime_binding)
    except ValueError as exc:
        # Pre-binding envelopes from an older engine may be replayed only when
        # durable custody already proves acceptance.  This is read-only and
        # deliberately happens before preflight/admission, so an unaccepted
        # legacy request remains a zero-mutation rejection.
        if not _envelope_has_runtime_binding(envelope):
            legacy = inspect_launch(envelope, store=open_operation_store(config))
            if legacy.result is LaunchResult.ACCEPTED:
                return _json_response(
                    result=LaunchResult.ACCEPTED,
                    reason="replay",
                    operation_id=envelope.operation_id,
                    request_id=envelope.request_id,
                    envelope_digest=envelope.digest,
                )
        return _json_response(
            result=LaunchResult.REJECTED,
            reason="runtime_manifest_binding_invalid",
            operation_id=envelope.operation_id,
            request_id=envelope.request_id,
            envelope_digest=envelope.digest,
            detail=str(exc),
        )
    observations = request["preflight_observations"]
    if not isinstance(observations, Mapping):
        raise ChainDriveError("preflight_observations must be an object")
    try:
        _validate_launch_observations(observations, envelope, runtime_binding, launch_attestation)
    except ValueError as exc:
        return _json_response(
            result=LaunchResult.REJECTED,
            reason="runtime_manifest_binding_invalid",
            operation_id=envelope.operation_id,
            request_id=envelope.request_id,
            envelope_digest=envelope.digest,
            detail=str(exc),
        )
    store = open_operation_store(config)
    existing = inspect_launch(envelope, store=store)
    if existing.result is LaunchResult.ACCEPTED:
        return _json_response(
            result=LaunchResult.ACCEPTED,
            reason="replay",
            operation_id=envelope.operation_id,
            request_id=envelope.request_id,
            envelope_digest=envelope.digest,
        )
    try:
        _probe_live_collision(str(envelope.launch_spec.get("expected_session_name") or ""))
    except ValueError as exc:
        return _json_response(
            result=LaunchResult.REJECTED,
            reason="preflight_rejected",
            operation_id=envelope.operation_id,
            request_id=envelope.request_id,
            envelope_digest=envelope.digest,
            detail=str(exc),
        )
    preflight = run_launch_preflight(envelope.launch_spec, observations)
    if not preflight.accepted:
        return _json_response(
            result=LaunchResult.REJECTED,
            reason="preflight_rejected",
            operation_id=envelope.operation_id,
            request_id=envelope.request_id,
            envelope_digest=envelope.digest,
        )
    try:
        _reread_current_authority(_authority_binding_from_envelope(envelope))
    except ValueError as exc:
        return _json_response(
            result=LaunchResult.REJECTED,
            reason="G5A_REMOTE_BLOCKED",
            operation_id=envelope.operation_id,
            request_id=envelope.request_id,
            envelope_digest=envelope.digest,
            detail=str(exc),
        )

    # Request-side command/cwd/session fields are transport projections.  The
    # immutable envelope is authoritative, so a contradictory projection can
    # never redirect dispatch.
    command = envelope.launch_spec.get("command")
    if not isinstance(command, (str, list, tuple)):
        raise ChainDriveError("command must be a string or argv sequence")
    cwd = envelope.launch_spec.get("cwd")
    session = envelope.launch_spec.get("expected_session_name")
    if not isinstance(cwd, str) or not cwd or not isinstance(session, str) or not session:
        raise ChainDriveError("cwd and session must be non-empty strings")
    identity = {
        "ARNOLD_LAUNCH_OPERATION_ID": envelope.operation_id,
        "ARNOLD_LAUNCH_REQUEST_ID": envelope.request_id,
        "ARNOLD_LAUNCH_ENVELOPE_DIGEST": envelope.digest,
        "ARNOLD_LAUNCH_PROCESS_IDENTITY": str(envelope.launch_spec.get("process_session_identity") or session),
        # The envelope binding is the only authority.  This is a single
        # process-session projection used by the runtime gate and command.
        "ARNOLD_RUNTIME_MANIFEST": runtime_binding["manifest_path"],
    }

    def dispatch(candidate: LaunchEnvelope) -> str:
        try:
            run_tmux(new_session_argv(session, command, cwd=Path(cwd), environment=identity))
        except Exception as exc:
            raise LaunchDispatchRejected(str(exc)) from exc
        return session

    def observe(dispatched: str, candidate: LaunchEnvelope) -> Mapping[str, Any]:
        status = inspect_session(dispatched, expected_identity=identity)
        return {
            "operation_id": status.operation_id,
            "request_id": status.request_id,
            "envelope_digest": status.envelope_digest,
            "process_session_identity": status.process_session_identity,
            "session_name": status.session_name,
            "liveness": status.state,
        }

    def resource_factory(dispatched: str, observation: Mapping[str, Any], candidate: LaunchEnvelope) -> TypedResource:
        return TypedResource(
            id=f"launch-process-session:{candidate.operation_id}:{candidate.request_id}",
            operation_id=candidate.operation_id,
            resource_type=ResourceType.PROCESS_SESSION,
            name=dispatched,
            details={dict_key: observation.get(dict_key) for dict_key in (
                "operation_id", "request_id", "envelope_digest", "process_session_identity", "session_name", "liveness"
            )},
        )

    transaction = launch_transaction(
        envelope,
        store=store,
        preflight=preflight,
        dispatch=dispatch,
        observe=observe,
        resource_factory=resource_factory,
        operation_type=str(envelope.launch_spec.get("operation_type") or "megaplan_chain"),
    )
    return _json_response(
        result=transaction.result,
        reason=transaction.reason.value,
        operation_id=envelope.operation_id,
        request_id=envelope.request_id,
        envelope_digest=envelope.digest,
    )


def build_launch_request(
    *,
    envelope: LaunchEnvelope,
    command: str | Sequence[str],
    cwd: str,
    session: str,
    preflight_observations: Mapping[str, Any],
    ops_store_root: str | None = None,
) -> dict[str, Any]:
    """Build the controller-to-engine request without opening the store."""

    return {
        "envelope": envelope.to_json(),
        "command": list(command) if not isinstance(command, str) else command,
        "cwd": cwd,
        "session": session,
        "preflight_observations": dict(preflight_observations),
        "ops_store_root": ops_store_root,
    }


def encode_launch_request(request: Mapping[str, Any]) -> str:
    raw = json.dumps(dict(request), sort_keys=True, separators=(",", ":")).encode()
    return base64.b64encode(raw).decode("ascii")


def launch_engine_command(encoded_request: str) -> str:
    """Return a fixed command that runs the co-located engine."""

    return (
        "python -P -m arnold_pipelines.megaplan.cloud.chain_drive "
        "--request-b64 " + shlex.quote(encoded_request)
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-b64", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        raw = base64.b64decode(args.request_b64, validate=True)
        payload = execute_authoritative_launch(json.loads(raw.decode("utf-8")))
    except Exception as exc:
        payload = {
            "schema": "arnold.megaplan.cloud_launch_response.v1",
            "result": LaunchResult.UNKNOWN.value,
            "reason": "engine_error",
            "detail": f"{type(exc).__name__}: {exc}",
        }
    print(json.dumps(payload, sort_keys=True))
    # A typed UNKNOWN is still a successful engine response.  The controller
    # must not reinterpret a remote result as transport failure or retry it.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
