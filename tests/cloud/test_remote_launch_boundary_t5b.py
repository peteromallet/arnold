from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from agentbox.config import AgentBoxConfig
from agentbox.tmux import SessionStatus
from arnold.runtime.durable_ops import LaunchEnvelope, run_launch_preflight
from arnold_pipelines.megaplan.cloud import chain_drive


def _request(tmp_path: Path, *, session: str = "chain"):
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
    return config, chain_drive.build_launch_request(
        envelope=envelope,
        command="echo chain",
        cwd=str(tmp_path),
        session=session,
        preflight_observations=observations,
        ops_store_root=str(config.ops_store_root),
    ), envelope


def test_remote_engine_legacy_unaccepted_request_rejects_without_dispatch(tmp_path, monkeypatch):
    config, request, envelope = _request(tmp_path)
    calls: list[object] = []
    monkeypatch.setattr(chain_drive, "load_agentbox_config", lambda: config)
    monkeypatch.setattr(chain_drive, "run_tmux", lambda argv: calls.append(argv))
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
    second = chain_drive.execute_authoritative_launch(request)

    assert first["result"] == "REJECTED"
    assert second["result"] == "REJECTED"
    assert first["reason"] == "runtime_manifest_binding_invalid"
    assert second["reason"] == "runtime_manifest_binding_invalid"
    assert calls == []


def test_remote_engine_preflight_rejects_before_store_admission(tmp_path, monkeypatch):
    config, request, _ = _request(tmp_path)
    request["preflight_observations"]["credentials"]["status"] = "unavailable"
    monkeypatch.setattr(chain_drive, "load_agentbox_config", lambda: config)
    monkeypatch.setattr(chain_drive, "run_tmux", lambda argv: (_ for _ in ()).throw(AssertionError("dispatch")))

    result = chain_drive.execute_authoritative_launch(request)

    assert result["result"] == "REJECTED"
    assert result["reason"] == "runtime_manifest_binding_invalid"
    assert not (config.ops_store_root / "operation_runs.json").exists()


def test_identity_query_loss_is_unknown_without_replacement(tmp_path, monkeypatch):
    config, request, _ = _request(tmp_path)
    calls: list[object] = []
    monkeypatch.setattr(chain_drive, "load_agentbox_config", lambda: config)
    monkeypatch.setattr(chain_drive, "run_tmux", lambda argv: calls.append(argv))
    monkeypatch.setattr(
        chain_drive,
        "inspect_session",
        lambda name, expected_identity=None: SessionStatus(name, "unavailable", True),
    )

    result = chain_drive.execute_authoritative_launch(request)

    assert result["result"] == "REJECTED"
    assert result["reason"] == "runtime_manifest_binding_invalid"
    assert calls == []
