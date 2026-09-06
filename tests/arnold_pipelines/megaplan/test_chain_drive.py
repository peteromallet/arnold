"""Canonical cloud engine replay and identity tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from agentbox.config import AgentBoxConfig
from agentbox.tmux import SessionStatus
from arnold.runtime.durable_ops import (
    FileBackedDurableOpsStore,
    LaunchEnvelope,
    OperationState,
    ResourceType,
    TypedResource,
    run_launch_preflight,
)
from arnold_pipelines.megaplan.cloud import chain_drive


def _request(tmp_path: Path):
    session = "chain"
    runtime_source = (tmp_path / "runtime").resolve()
    runtime_source.mkdir()
    manifest = tmp_path / "runtime-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "1",
                "runtime_id": "runtime-1",
                "generation": 1,
                "epic_id": "chain",
                "state": "active",
                "owner": "test",
                "base": {"ref": "main", "commit": "a" * 40, "editable_install_path": "", "venv_path": ""},
                "epic": {
                    "branch": "epic/chain",
                    "worktree_path": str(runtime_source),
                    "venv_path": "",
                    "runtime_root": str(runtime_source),
                    "expected_head": "a" * 40,
                    "repair_bin": "",
                    "deps_lockfile": "",
                },
                "indirection": {"host_path": "", "container_path": "", "mount_table": [], "execution_namespace": "", "verified_head": "", "last_verified_at": "", "attestation": {"module_file": "", "module_digest": "", "mount_id": ""}},
                "policy": {"policy_sha": "", "model_policy_sha": "", "sync_policy": ""},
                "promotions": [],
                "timestamps": {"created": "", "updated": "", "closed": ""},
                "gc_policy": "",
                "commands": [],
            }
        ),
        encoding="utf-8",
    )
    manifest_hash = hashlib.sha256(manifest.read_bytes()).hexdigest()
    runtime_identity = {
        "import_root": str(runtime_source),
        "source_revision": "a" * 40,
        "editable_root": "",
        "editable_revision": "",
        "direct_url": {},
        "pth": [],
        "imports": {
            "arnold": str(runtime_source / "arnold/__init__.py"),
            "arnold_pipelines": str(runtime_source / "arnold_pipelines/__init__.py"),
            "megaplan": str(runtime_source / "arnold_pipelines/megaplan/__init__.py"),
        },
    }
    identity_core = dict(runtime_identity)
    for key in ("editable_root", "editable_revision", "direct_url", "pth", "imports"):
        identity_core[key] = None
    runtime_identity["content_sha256"] = hashlib.sha256(
        json.dumps(identity_core, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    spec = {
        "command": "echo chain",
        "cwd": str(tmp_path),
        "operation_type": "megaplan_chain",
        "launch_intent": "megaplan_chain",
        "process_session_identity": session,
        "expected_session_name": session,
        "metadata": {
            "runtime_binding": {
                "manifest_path": str(manifest),
                "manifest_sha256": manifest_hash,
                "manifest_identity": manifest_hash,
                "runtime_id": "runtime-1",
                "runtime_source": str(runtime_source),
                "runtime_revision": "a" * 40,
                "runtime_identity": runtime_identity,
                "runtime_identity_raw": {
                    "runtime_id": "runtime-1",
                    "epic_id": "chain",
                    "runtime_source": str(runtime_source),
                    "runtime_revision": "a" * 40,
                },
            }
        },
    }
    observations = {
        "source": {"status": "current", "revision": "r", "ref": "r", "tree": "t"},
        "authority": {"status": "current", "grant": "g", "fence": "f", "decision": "d"},
        "custody": {"status": "present", "custody_ref": "c", "wbc_ref": "w"},
        "credentials": {"status": "available", "identity": "i", "transport": "local"},
        "runtime": {"status": "present", "interpreter": "python", "import_root": "/x", "source_revision": "r"},
        "command": {"status": "valid", "argv": "echo chain", "cwd": str(tmp_path), "env": {}},
        "namespace": {"status": "valid", "name": session},
        "collision": {"status": "none", "namespace": session},
        "capacity": {"status": "available", "disk": "d", "inode": "i", "output": "o", "temp": "t"},
        "network": {"status": "available", "transport": "local"},
    }
    report = run_launch_preflight(spec, observations)
    envelope = LaunchEnvelope(1, "op", "req", "cloud:ssh", spec, report.preflight_digest)
    config = AgentBoxConfig(
        workspace_root=tmp_path,
        ops_store_root=tmp_path / "ops",
        runs_root=tmp_path / "runs",
        locks_root=tmp_path / "locks",
    )
    request = chain_drive.build_launch_request(
        envelope=envelope,
        command="echo chain",
        cwd=str(tmp_path),
        session=session,
        preflight_observations=observations,
        ops_store_root=str(config.ops_store_root),
    )
    return config, request, envelope


def test_exact_replay_returns_authority_without_redispatch(tmp_path: Path, monkeypatch) -> None:
    config, request, envelope = _request(tmp_path)
    dispatches: list[object] = []
    monkeypatch.setattr(chain_drive, "load_agentbox_config", lambda: config)
    monkeypatch.setattr(chain_drive, "run_tmux", lambda argv: dispatches.append(argv))
    monkeypatch.setattr(
        chain_drive,
        "inspect_session",
        lambda name, expected_identity=None: SessionStatus(
            name,
            "running",
            True,
            operation_id=envelope.operation_id,
            request_id=envelope.request_id,
            envelope_digest=envelope.digest,
            process_session_identity="chain",
            identity_available=True,
        ),
    )
    first = chain_drive.execute_authoritative_launch(request)
    replay = chain_drive.execute_authoritative_launch(request)
    assert first["result"] == "ACCEPTED"
    assert replay["reason"] == "replay"
    assert len(dispatches) == 1
    argv = dispatches[0]
    assert argv.count("ARNOLD_RUNTIME_MANIFEST=" + str(tmp_path / "runtime-manifest.json")) == 1


def test_legacy_accepted_replay_without_binding_never_redispatches(tmp_path: Path, monkeypatch) -> None:
    config, request, envelope = _request(tmp_path)
    legacy_spec = dict(envelope.launch_spec)
    legacy_spec.pop("metadata")
    legacy = LaunchEnvelope(
        envelope.version,
        envelope.operation_id,
        envelope.request_id,
        envelope.venue,
        legacy_spec,
        envelope.preflight_digest,
    )
    request["envelope"] = legacy.to_json()
    store = FileBackedDurableOpsStore(config.ops_store_root)
    store.admit_launch(legacy)
    store.accept_launch(
        legacy,
        process_resource=TypedResource(
            id=f"launch-process-session:{legacy.operation_id}:{legacy.request_id}",
            operation_id=legacy.operation_id,
            resource_type=ResourceType.PROCESS_SESSION,
            name="chain",
            details={},
        ),
        owner_evidence={
            "operation_id": legacy.operation_id,
            "request_id": legacy.request_id,
            "envelope_digest": legacy.digest,
            "process_session_identity": "chain",
            "liveness": "running",
        },
        owner=legacy.venue,
    )
    dispatches: list[object] = []
    monkeypatch.setattr(chain_drive, "load_agentbox_config", lambda: config)
    monkeypatch.setattr(chain_drive, "run_tmux", lambda argv: dispatches.append(argv))

    result = chain_drive.execute_authoritative_launch(request)

    assert result["result"] == "ACCEPTED"
    assert result["reason"] == "replay"
    assert dispatches == []


@pytest.mark.parametrize("tamper", ["missing", "bytes", "invalid_schema"])
def test_invalid_runtime_binding_rejects_before_admission_or_dispatch(
    tmp_path: Path, monkeypatch, tamper: str
) -> None:
    config, request, envelope = _request(tmp_path)
    dispatches: list[object] = []
    monkeypatch.setattr(chain_drive, "load_agentbox_config", lambda: config)
    monkeypatch.setattr(chain_drive, "run_tmux", lambda argv: dispatches.append(argv))
    if tamper == "missing":
        spec = dict(envelope.launch_spec)
        spec.pop("metadata")
        broken = LaunchEnvelope(
            envelope.version,
            envelope.operation_id,
            envelope.request_id,
            envelope.venue,
            spec,
            envelope.preflight_digest,
        )
        request["envelope"] = broken.to_json()
    else:
        manifest = tmp_path / "runtime-manifest.json"
        if tamper == "bytes":
            manifest.write_bytes(manifest.read_bytes() + b"tampered")
        else:
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["state"] = "not-a-runtime-state"
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            updated_hash = hashlib.sha256(manifest.read_bytes()).hexdigest()
            spec = dict(envelope.launch_spec)
            metadata = dict(spec["metadata"])
            binding = dict(metadata["runtime_binding"])
            binding["manifest_sha256"] = updated_hash
            binding["manifest_identity"] = updated_hash
            metadata["runtime_binding"] = binding
            spec["metadata"] = metadata
            envelope = LaunchEnvelope(
                envelope.version,
                envelope.operation_id,
                envelope.request_id,
                envelope.venue,
                spec,
                envelope.preflight_digest,
            )
            request["envelope"] = envelope.to_json()

    result = chain_drive.execute_authoritative_launch(request)

    assert result["result"] == "REJECTED"
    assert result["reason"] == "runtime_manifest_binding_invalid"
    assert dispatches == []
    store = FileBackedDurableOpsStore(config.ops_store_root)
    assert not any(run.operation_id == envelope.operation_id for run in store.list_operation_runs())


def test_ambient_manifest_is_ignored_in_favor_of_envelope_binding(
    tmp_path: Path, monkeypatch
) -> None:
    config, request, envelope = _request(tmp_path)
    dispatches: list[object] = []
    request["command"] = "echo ambient-command"
    request["cwd"] = "/ambient/cwd"
    request["session"] = "ambient-session"
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", "/ambient/wrong.json")
    monkeypatch.setattr(chain_drive, "load_agentbox_config", lambda: config)
    monkeypatch.setattr(chain_drive, "run_tmux", lambda argv: dispatches.append(argv))
    monkeypatch.setattr(
        chain_drive,
        "inspect_session",
        lambda name, expected_identity=None: SessionStatus(
            name,
            "running",
            True,
            operation_id=envelope.operation_id,
            request_id=envelope.request_id,
            envelope_digest=envelope.digest,
            process_session_identity="chain",
            identity_available=True,
        ),
    )

    result = chain_drive.execute_authoritative_launch(request)

    assert result["result"] == "ACCEPTED"
    assert dispatches[0].count("ARNOLD_RUNTIME_MANIFEST=" + str(tmp_path / "runtime-manifest.json")) == 1
    assert "/ambient/wrong.json" not in dispatches[0]


def test_identity_query_loss_is_unknown_without_replacement(tmp_path: Path, monkeypatch) -> None:
    config, request, _ = _request(tmp_path)
    dispatches: list[object] = []
    monkeypatch.setattr(chain_drive, "load_agentbox_config", lambda: config)
    monkeypatch.setattr(chain_drive, "run_tmux", lambda argv: dispatches.append(argv))
    monkeypatch.setattr(
        chain_drive,
        "inspect_session",
        lambda name, expected_identity=None: SessionStatus(name, "unavailable", True),
    )
    result = chain_drive.execute_authoritative_launch(request)
    assert result["result"] == "UNKNOWN"
    assert len(dispatches) == 1
    store = FileBackedDurableOpsStore(config.ops_store_root)
    operation = store.load_operation_run("op")
    assert operation.state is OperationState.PENDING
    assert "owner" not in operation.metadata
    assert "owner_id" not in operation.metadata
    assert store.list_typed_resources("op") == ()
    assert not any(
        event.event_type == "launch.accepted"
        for event in store.list_operation_events("op")
    )
