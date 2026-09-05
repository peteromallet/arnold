"""Canonical cloud engine replay and identity tests."""

from __future__ import annotations

from pathlib import Path

from agentbox.config import AgentBoxConfig
from agentbox.tmux import SessionStatus
from arnold.runtime.durable_ops import FileBackedDurableOpsStore, LaunchEnvelope, OperationState, run_launch_preflight
from arnold_pipelines.megaplan.cloud import chain_drive


def _request(tmp_path: Path):
    session = "chain"
    spec = {
        "command": "echo chain",
        "cwd": str(tmp_path),
        "operation_type": "megaplan_chain",
        "launch_intent": "megaplan_chain",
        "process_session_identity": session,
        "expected_session_name": session,
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
