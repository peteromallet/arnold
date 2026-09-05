from __future__ import annotations

from pathlib import Path

from arnold.runtime.durable_ops import (
    FileBackedDurableOpsStore,
    LaunchDispatchRejected,
    LaunchEnvelope,
    LaunchResult,
    ResourceType,
    TypedResource,
    run_launch_preflight,
    launch_transaction,
)
from agentbox.config import AgentBoxConfig
from agentbox.host import launch_host
from agentbox.tmux import SessionStatus, TmuxResult, inspect_session


EXPECTED = {
    "ARNOLD_LAUNCH_OPERATION_ID": "op-1",
    "ARNOLD_LAUNCH_REQUEST_ID": "req-1",
    "ARNOLD_LAUNCH_ENVELOPE_DIGEST": "sha256:envelope",
    "ARNOLD_LAUNCH_PROCESS_IDENTITY": "agentbox-op-1",
}


def _fake_tmux(monkeypatch, *, env: str, has_rc: int = 0, env_rc: int = 0, env_err: str = ""):
    calls: list[list[str]] = []

    def run(argv, *, check=True):
        calls.append(list(argv))
        if argv[1] == "has-session":
            return TmuxResult(tuple(argv), has_rc, "", "can't find session" if has_rc else "")
        return TmuxResult(tuple(argv), env_rc, env, env_err)

    monkeypatch.setattr("agentbox.tmux.run_tmux", run)
    return calls


def _env(**changes: str) -> str:
    values = {**EXPECTED, **changes}
    return "\n".join(f"{key}={value}" for key, value in values.items()) + "\n"


def test_identity_query_accepts_exact_live_session(monkeypatch) -> None:
    calls = _fake_tmux(monkeypatch, env=_env())
    status = inspect_session("agentbox-op-1", expected_identity=EXPECTED)
    assert status == SessionStatus(
        "agentbox-op-1", "running", True, None, "op-1", "req-1", "sha256:envelope", "agentbox-op-1", True
    )
    assert [argv[1] for argv in calls] == ["has-session", "show-environment"]


def test_identity_query_missing_fact_is_unavailable(monkeypatch) -> None:
    _fake_tmux(monkeypatch, env=_env(ARNOLD_LAUNCH_REQUEST_ID=""))
    status = inspect_session("agentbox-op-1", expected_identity=EXPECTED)
    assert status.state == "unavailable"
    assert status.identity_available is False


def test_identity_query_mismatch_is_unavailable(monkeypatch) -> None:
    _fake_tmux(monkeypatch, env=_env(ARNOLD_LAUNCH_ENVELOPE_DIGEST="sha256:other"))
    status = inspect_session("agentbox-op-1", expected_identity=EXPECTED)
    assert status.state == "unavailable"
    assert status.envelope_digest == "sha256:other"


def test_dead_session_never_queries_or_accepts_identity(monkeypatch) -> None:
    calls = _fake_tmux(monkeypatch, env="", has_rc=1)
    status = inspect_session("agentbox-op-1", expected_identity=EXPECTED)
    assert status.state == "missing"
    assert len(calls) == 1


def test_dead_tmux_server_is_not_treated_as_missing_live_identity(monkeypatch) -> None:
    calls = _fake_tmux(monkeypatch, env="", has_rc=1)

    def run(argv, *, check=True):
        calls.append(list(argv))
        return TmuxResult(tuple(argv), 1, "", "no server running on /tmp/tmux")

    monkeypatch.setattr("agentbox.tmux.run_tmux", run)
    status = inspect_session("agentbox-op-1", expected_identity=EXPECTED)
    assert status.state == "dead"
    assert status.exists is False
    assert len(calls) == 1


def test_unavailable_identity_query_is_not_treated_as_live(monkeypatch) -> None:
    _fake_tmux(monkeypatch, env="", env_rc=1, env_err="tmux server unavailable")
    status = inspect_session("agentbox-op-1", expected_identity=EXPECTED)
    assert status.state == "unavailable"
    assert status.exists is True


def _engine_facts() -> dict[str, dict[str, str]]:
    return {
        "source": {"status": "current", "revision": "sha", "ref": "main", "tree": "sha"},
        "authority": {"status": "current", "grant": "grant", "fence": "fence", "decision": "allow"},
        "custody": {"status": "present", "custody_ref": "/workspace", "wbc_ref": "/ops"},
        "credentials": {"status": "available", "identity": "agent", "transport": "local"},
        "runtime": {"status": "present", "interpreter": "python", "import_root": "/workspace", "source_revision": "sha"},
        "command": {"status": "valid", "argv": "worker", "cwd": "/workspace", "env": ""},
        "namespace": {"status": "valid", "name": "agentbox-op-1"},
        "collision": {"status": "none", "namespace": "agentbox-op-1"},
        "capacity": {"status": "available", "disk": "workspace", "inode": "workspace", "output": "bounded", "temp": "workspace"},
        "network": {"status": "available", "transport": "local"},
    }


def _engine_request() -> tuple[LaunchEnvelope, object]:
    spec = {
        "command": ["worker"],
        "operation_type": "agentbox_host",
        "expected_session_name": "agentbox-op-1",
        "process_session_identity": "agentbox-op-1",
    }
    preflight = run_launch_preflight(spec, _engine_facts())
    envelope = LaunchEnvelope(
        version=1,
        operation_id="op-1",
        request_id="req-1",
        venue="agentbox",
        launch_spec=spec,
        preflight_digest=preflight.preflight_digest,
    )
    return envelope, preflight


def test_launch_engine_acceptance_requires_all_identity_facts(tmp_path: Path) -> None:
    envelope, preflight = _engine_request()
    store = FileBackedDurableOpsStore(tmp_path)
    dispatches: list[str] = []

    result = launch_transaction(
        envelope,
        store=store,
        preflight=preflight,
        dispatch=lambda _: dispatches.append("one") or "agentbox-op-1",
        observe=lambda *_: {
            "operation_id": "op-1",
            "request_id": "req-1",
            "envelope_digest": envelope.digest,
            "process_session_identity": "agentbox-op-1",
            "session_name": "agentbox-op-1",
            "liveness": "running",
        },
        resource_factory=lambda name, observation, _: TypedResource(
            id="session",
            operation_id="op-1",
            resource_type=ResourceType.PROCESS_SESSION,
            name=name,
            details=dict(observation),
        ),
        operation_type="agentbox_host",
    )

    assert result.result is LaunchResult.ACCEPTED
    assert result.operation.state.value == "running"
    assert dispatches == ["one"]


def test_launch_engine_identity_loss_is_unknown_without_redispatch(tmp_path: Path) -> None:
    envelope, preflight = _engine_request()
    store = FileBackedDurableOpsStore(tmp_path)
    dispatches: list[str] = []

    def observe(*_args):
        return {
            "operation_id": "op-1",
            "request_id": "req-1",
            "envelope_digest": envelope.digest,
            "process_session_identity": "agentbox-op-1",
            "session_name": "agentbox-op-1",
            "liveness": "unavailable",
        }

    result = launch_transaction(
        envelope,
        store=store,
        preflight=preflight,
        dispatch=lambda _: dispatches.append("one") or "agentbox-op-1",
        observe=observe,
        resource_factory=lambda *_: None,
        operation_type="agentbox_host",
    )

    assert result.result is LaunchResult.UNKNOWN
    assert dispatches == ["one"]


def test_launch_engine_known_dispatch_rejection_is_rejected(tmp_path: Path) -> None:
    envelope, preflight = _engine_request()
    store = FileBackedDurableOpsStore(tmp_path)
    result = launch_transaction(
        envelope,
        store=store,
        preflight=preflight,
        dispatch=lambda _: (_ for _ in ()).throw(LaunchDispatchRejected("collision")),
        observe=lambda *_: {},
        resource_factory=lambda *_: None,
        operation_type="agentbox_host",
    )
    assert result.result is LaunchResult.REJECTED


def test_launch_engine_rejected_preflight_has_no_admission_or_dispatch(tmp_path: Path) -> None:
    envelope, _ = _engine_request()
    rejected = run_launch_preflight(
        envelope.launch_spec,
        {**_engine_facts(), "collision": {"status": "conflict", "namespace": "agentbox-op-1"}},
    )
    assert rejected.accepted is False
    store = FileBackedDurableOpsStore(tmp_path)
    result = launch_transaction(
        envelope,
        store=store,
        preflight=rejected,
        dispatch=lambda _: (_ for _ in ()).throw(AssertionError("dispatch")),
        observe=lambda *_: {},
        resource_factory=lambda *_: None,
        operation_type="agentbox_host",
    )
    assert result.result is LaunchResult.REJECTED
    assert store.list_operation_runs() == ()


def test_host_launch_admits_before_one_physical_dispatch_and_replays(monkeypatch, tmp_path: Path) -> None:
    config = AgentBoxConfig(workspace_root=tmp_path / "workspace")
    config.workspace_root.mkdir()
    dispatches: list[str] = []
    expected_session = "agentbox-op-host"

    def fake_inspect(name: str, *, expected_identity=None) -> SessionStatus:
        if expected_identity is None:
            return SessionStatus(name, "missing", False)
        return SessionStatus(
            name,
            "running",
            True,
            operation_id=expected_identity["ARNOLD_LAUNCH_OPERATION_ID"],
            request_id=expected_identity["ARNOLD_LAUNCH_REQUEST_ID"],
            envelope_digest=expected_identity["ARNOLD_LAUNCH_ENVELOPE_DIGEST"],
            process_session_identity=expected_identity["ARNOLD_LAUNCH_PROCESS_IDENTITY"],
            identity_available=True,
        )

    def fake_start(*_args, **_kwargs) -> str:
        dispatches.append("one")
        return expected_session

    monkeypatch.setattr("agentbox.host.inspect_session", fake_inspect)
    monkeypatch.setattr("agentbox.host.start_session", fake_start)

    first = launch_host(config, "op-host", command=("worker",))
    second = launch_host(config, "op-host", command=("worker",))

    assert first.launch_state == "accepted"
    assert second.launch_state == "accepted"
    assert second.diagnostics["reason"] == "replay"
    assert dispatches == ["one"]
    assert first.operation_state.value == "running"
