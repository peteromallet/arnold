from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from arnold_pipelines.megaplan.resident import subagent
from arnold_pipelines.megaplan.resident.config import ResidentConfig
from arnold_pipelines.megaplan.resident.provenance import DELEGATION_CONTEXT_ENV


class _DetachedProcess:
    pid = 4321

    def poll(self):
        return None


@pytest.fixture(autouse=True)
def _isolate_resident_provenance(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(DELEGATION_CONTEXT_ENV, raising=False)
    real_start_ticks = subagent._pid_start_ticks
    real_pid_live = subagent._pid_live
    monkeypatch.setattr(
        subagent,
        "_pid_start_ticks",
        lambda pid: (
            f"test-start-{pid}"
            if pid in {4321, 223}
            else real_start_ticks(pid)
        ),
    )
    monkeypatch.setattr(
        subagent,
        "_pid_live",
        lambda pid: True if pid in {4321, 223} else real_pid_live(pid),
    )
    # The parameterized route test explicitly owns provider-admission coverage.
    # Supply only its two intentionally synthetic provider credentials; all
    # other tests and all other providers retain the real read-only scan.
    if request.node.name.startswith("test_auto_route_creates_one_durable_provider_manifest"):
        monkeypatch.setenv("ZAI_API_KEY", "c1-test-zai-key")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "c1-test-anthropic-key")
        real_has_keys = subagent.key_pool.has_keys
        monkeypatch.setattr(
            subagent.key_pool,
            "has_keys",
            lambda provider: True if provider == "zai" else real_has_keys(provider),
        )


@pytest.mark.parametrize(
    ("model_spec", "backend", "runtime_model"),
    [
        ("omp:zai/glm-5.2", "omp", "zai/glm-5.2"),
        ("codex:gpt-5.6-terra", "codex", "gpt-5.6-terra"),
        ("claude:opus", "claude", "opus"),
    ],
)
def test_auto_route_creates_one_durable_provider_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    model_spec: str,
    backend: str,
    runtime_model: str,
) -> None:
    launches: list[list[str]] = []

    def fake_popen(argv, **kwargs):
        launches.append(list(argv))
        return _DetachedProcess()

    monkeypatch.setattr(subagent.subprocess, "Popen", fake_popen)
    result = asyncio.run(
        subagent.launch_subagent_task(
            ResidentConfig(),
            task=f"bounded {backend} smoke",
            description=f"Run the bounded {backend} smoke",
            project_dir=str(tmp_path),
            model=model_spec,
        )
    )

    manifest = json.loads(Path(result.manifest_path or "").read_text(encoding="utf-8"))
    assert result.status == "running"
    assert manifest["backend"] == backend
    assert manifest["supervisor_start_ticks"] == "test-start-4321"
    assert manifest["model"] == runtime_model
    assert manifest["model_spec"] == (
        "omp:zai/glm-5.2" if backend == "omp" else model_spec
    )
    assert manifest["provider_route"] == {
        "backend": backend,
        "runtime_model": runtime_model,
        "model_spec": manifest["model_spec"],
    }
    assert manifest["provider_contract"]["capabilities"]["persistent_session"] is True
    assert manifest["provider_contract"]["capabilities"]["exact_session_resume"] is True
    for field in (
        "prompt_path",
        "result_path",
        "log_path",
        "manifest_path",
        "provider_raw_output_path",
        "provider_events_path",
    ):
        assert Path(manifest[field]).exists()
    assert manifest["telemetry"]["raw_streams_are_provider_specific"] is True
    if backend in {"omp", "claude"}:
        assert manifest["model_session"]["provider"] == backend
        assert manifest["model_session"]["state"] == "reserved"
    assert launches and "--run-managed" in launches[0]


def test_explicit_mismatch_fails_before_manifest_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        subagent.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("mismatched route started a process"),
    )

    with pytest.raises(ValueError, match="backend/model mismatch"):
        asyncio.run(
            subagent.launch_subagent_task(
                ResidentConfig(),
                task="must not launch",
                project_dir=str(tmp_path),
                backend="codex",
                model="omp:zai/glm-5.2",
            )
        )

    assert not (tmp_path / ".megaplan/plans/resident-subagents").exists()


def test_provider_and_control_changes_are_part_of_launch_idempotency(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        subagent.subprocess, "Popen", lambda *args, **kwargs: _DetachedProcess()
    )

    omp_run = asyncio.run(
        subagent.launch_subagent_task(
            ResidentConfig(),
            task="same bounded task",
            project_dir=str(tmp_path),
            model="omp:zai/glm-5.2",
        )
    )
    claude = asyncio.run(
        subagent.launch_subagent_task(
            ResidentConfig(),
            task="same bounded task",
            project_dir=str(tmp_path),
            model="claude:opus",
        )
    )

    assert omp_run.run_id != claude.run_id
    assert omp_run.manifest_path != claude.manifest_path


def test_omp_auto_route_preserves_discord_custody_and_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        subagent.subprocess,
        "Popen",
        lambda *args, **kwargs: _DetachedProcess(),
    )
    result = asyncio.run(
        subagent.launch_subagent_task(
            ResidentConfig(),
            task="durable Hermes work",
            description="Run durable Hermes work",
            project_dir=str(tmp_path),
            model="omp:zai/glm-5.2",
            launch_origin={
                "transport": "discord",
                "applicability": "applicable",
                "resident_conversation_id": "rconv_providerroute1",
                "source_record_id": "msg_providerroute1",
                "conversation_key": "discord:dm:123456789012345678",
                "discord_message_id": "987654321098765432",
                "reply_to_message_id": "987654321098765432",
                "dm_user_id": "123456789012345678",
                "source_kind": "discord_inbound_message",
            },
        )
    )

    manifest = json.loads(Path(result.manifest_path or "").read_text(encoding="utf-8"))
    assert manifest["backend"] == "omp"
    assert manifest["launch_provenance"]["source_record_id"] == "msg_providerroute1"
    assert manifest["completion_delivery"]["transport"] == "discord"
    assert manifest["completion_delivery"]["status"] == "pending"


def _worker_manifest(tmp_path: Path, *, backend: str, model: str) -> Path:
    run_dir = tmp_path / backend
    run_dir.mkdir()
    prompt_path = run_dir / "prompt.md"
    prompt_path.write_text("Reply with the single word READY.", encoding="utf-8")
    result_path = run_dir / "result.md"
    log_path = run_dir / "run.log"
    log_path.touch()
    raw_output_path = run_dir / "provider.raw"
    raw_output_path.touch()
    metadata_path = run_dir / "provider-metadata.json"
    events_path = run_dir / "events.jsonl"
    events_path.touch()
    manifest_path = run_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": "arnold-managed-agent-run-v2",
                "run_kind": "resident_delegated_agent",
                "custodian": "arnold.megaplan.managed_agent",
                "run_id": backend,
                "status": "running",
                "prompt_path": str(prompt_path),
                "result_path": str(result_path),
                "log_path": str(log_path),
                "provider_raw_output_path": str(raw_output_path),
                "provider_metadata_path": str(metadata_path),
                "provider_events_path": str(events_path),
                "project_dir": str(tmp_path),
                "backend": backend,
                "model": model,
                "reasoning_effort": "medium",
                "provider_options": {
                    "toolsets": "file",
                    "max_tokens": 128,
                    "timeout_s": 30,
                },
                "timeout_policy": {
                    "mode": "explicit",
                    "source": "trusted_cli",
                    "timeout_s": 30,
                },
                "status_history": [],
                "completion_delivery": {"status": "not_applicable"},
            }
        ),
        encoding="utf-8",
    )
    return manifest_path


@pytest.mark.parametrize(
    ("backend", "model", "launcher_name", "effective_uid", "permission_flag"),
    [
        ("omp", "zai/glm-5.2", "launch_omp_agent.py", 0, None),
        ("claude", "opus", "launch_claude_agent.py", 0, "--permission-mode"),
        (
            "claude",
            "opus",
            "launch_claude_agent.py",
            1000,
            "--dangerously-skip-permissions",
        ),
    ],
)
def test_managed_worker_dispatches_non_codex_provider_and_captures_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    model: str,
    launcher_name: str,
    effective_uid: int,
    permission_flag: str | None,
) -> None:
    manifest_path = _worker_manifest(tmp_path, backend=backend, model=model)
    captured: dict[str, object] = {}

    class _Worker:
        pid = 222

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

    def fake_popen(argv, **kwargs):
        # Skip the post-session summarizer (launches without --session-id and
        # without --resume).
        if "--session-id" in argv or "--resume" in argv:
            captured["argv"] = list(argv)
            captured["env"] = kwargs.get("env")
        output = kwargs.get("stdout")
        assert output is not None
        if backend == "claude":
            session_id = argv[argv.index("--session-id") + 1]
            output.write(
                (
                    json.dumps(
                        {
                            "type": "system",
                            "subtype": "init",
                            "session_id": session_id,
                            "model": model,
                            "tools": ["Read"],
                        }
                    )
                    + "\n"
                    + json.dumps(
                        {
                            "type": "result",
                            "subtype": "success",
                            "session_id": session_id,
                            "is_error": False,
                            "result": "READY",
                            "usage": {"output_tokens": 1},
                        }
                    )
                    + "\n"
                ).encode()
            )
        else:
            output.write(b"READY\n")
            session_id = argv[argv.index("--session-id") + 1]
            Path(argv[argv.index("--metadata-file") + 1]).write_text(
                json.dumps(
                    {
                        "session_id": session_id,
                        "resolved_model": model,
                        "toolsets": ["file"],
                        "usage": {"output_tokens": 1},
                        "events": [],
                    }
                ),
                encoding="utf-8",
            )
        output.flush()
        return _Worker()

    monkeypatch.setattr(subagent.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(subagent.os, "geteuid", lambda: effective_uid)

    assert subagent._run_managed_manifest(manifest_path) == 0
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    argv = captured["argv"]
    assert isinstance(argv, list)
    assert any(str(item).endswith(launcher_name) for item in argv)
    assert model in argv
    if permission_flag is not None:
        assert permission_flag in argv
    if backend == "claude" and effective_uid == 0:
        assert argv[argv.index("--permission-mode") + 1] == "auto"
        assert "--dangerously-skip-permissions" not in argv
    assert manifest["status"] == "completed"
    assert Path(manifest["result_path"]).read_text(encoding="utf-8").strip() == "READY"
    assert manifest["model_session"]["provider"] == backend
    assert manifest["model_session"]["state"] == "persisted"
    assert Path(manifest["provider_events_path"]).read_text(encoding="utf-8").strip()
    assert manifest["telemetry"]["status"] == "captured"
    if backend == "claude":
        assert "--no-session-persistence" not in argv
        assert argv[argv.index("--tools") + 1] == "Read,Edit,Write,Glob,Grep"
        assert captured["env"]["CLAUDE_CODE_MAX_OUTPUT_TOKENS"] == "128"


@pytest.mark.parametrize(
    ("backend", "model"),
    [("omp", "zai/glm-5.2"), ("claude", "opus")],
)
def test_managed_worker_completion_emits_git_custody_event_without_unbound_local(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    model: str,
) -> None:
    """The managed-provider path must finish after custody verification.

    The Codex-only supervisor had a local named ``custody`` from its launch
    path.  The generic managed-provider supervisor did not, so an otherwise
    successful worker crashed with ``NameError`` after its strict receipt had
    already verified.  Exercise the generic path and require the durable
    verification event, not merely a zero provider return code.  Both managed
    provider launchers share this completion path, so exercise both.
    """

    manifest_path = _worker_manifest(tmp_path, backend=backend, model=model)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["git_custody"] = {
        "schema_version": "arnold-resident-git-custody-v1",
        "target_resolution": {"status": "resolved"},
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    class _Worker:
        pid = 225

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

    def fake_popen(argv, **kwargs):
        output = kwargs["stdout"]
        session_id = argv[argv.index("--session-id") + 1]
        if backend == "claude":
            output.write(
                (
                    json.dumps(
                        {
                            "type": "system",
                            "subtype": "init",
                            "session_id": session_id,
                            "model": model,
                            "tools": ["Read"],
                        }
                    )
                    + "\n"
                    + json.dumps(
                        {
                            "type": "result",
                            "subtype": "success",
                            "session_id": session_id,
                            "is_error": False,
                            "result": "READY",
                            "usage": {"output_tokens": 1},
                        }
                    )
                    + "\n"
                ).encode()
            )
        else:
            output.write(b"READY\n")
            Path(argv[argv.index("--metadata-file") + 1]).write_text(
                json.dumps(
                    {
                        "session_id": session_id,
                        "resolved_model": model,
                        "toolsets": ["file"],
                        "usage": {"output_tokens": 1},
                        "events": [],
                    }
                ),
                encoding="utf-8",
            )
        output.flush()
        return _Worker()

    monkeypatch.setattr(subagent.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        subagent,
        "_verify_managed_completion_contract",
        lambda *_args: {
            "status": "success",
            "evidence": {"status": "verified_integrated"},
        },
    )

    assert subagent._run_managed_manifest(manifest_path) == 0
    terminal = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert terminal["status"] == "completed"
    assert terminal["git_custody_verification"] == {
        "status": "verified_integrated"
    }
    custody_events = [
        json.loads(line)
        for line in (manifest_path.parent / "managed-child-custody.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert any(
        event["surface"] == "resident.git_custody.verify"
        and event["evidence"] == "git_custody_verified"
        and event["details"]["git_custody"]["available"] is True
        for event in custody_events
    )


def test_managed_non_codex_worker_rejects_empty_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_path = _worker_manifest(
        tmp_path, backend="omp", model="zai/glm-5.2"
    )

    class _Worker:
        pid = 222

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

    monkeypatch.setattr(
        subagent.subprocess, "Popen", lambda *args, **kwargs: _Worker()
    )

    assert subagent._run_managed_manifest(manifest_path) == 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"
    assert manifest["failure"]["category"] == "empty_result"
    assert "without a final response" in manifest["failure"]["message"]


def test_markerless_legacy_timeout_is_not_a_supervisor_deadline() -> None:
    legacy = {"provider_options": {"timeout_s": 600}}
    admitted = {
        "provider_options": {"timeout_s": 17},
        "timeout_policy": {
            "mode": "explicit",
            "source": "trusted_cli",
            "timeout_s": 17,
        },
    }

    assert subagent._explicit_manifest_timeout(legacy) is None
    assert subagent._explicit_manifest_timeout_source(legacy) is None
    assert subagent._explicit_manifest_timeout(admitted) == 17.0
    assert subagent._explicit_manifest_timeout_source(admitted) == "trusted_cli"


def test_provider_timeout_is_enforced_and_captured_durably(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_path = _worker_manifest(tmp_path, backend="omp", model="zai/glm-5.2")

    class _TimedOutWorker:
        pid = 223
        terminated = False

        def wait(self, timeout=None):
            if not self.terminated:
                raise subagent.subprocess.TimeoutExpired(cmd="omp", timeout=timeout)
            return -15

        def poll(self):
            return None if not self.terminated else -15

        def terminate(self):
            self.terminated = True

        def kill(self):
            self.terminated = True

    monkeypatch.setattr(
        subagent.subprocess, "Popen", lambda *args, **kwargs: _TimedOutWorker()
    )

    # A timeout whose managed signal door cannot certify the child is held
    # for custody reconciliation rather than misreported as a terminal 124.
    assert subagent._run_managed_manifest(manifest_path) == 75
    manifest = json.loads(manifest_path.read_text())
    assert manifest["status"] == "running"
    assert manifest["cleanup_hold"]["classification"] == "cleanup_held"
    assert manifest["error_class"] == "WorkerCleanupHeld"
    assert "signal_result" in manifest["cleanup_hold"]
    assert Path(manifest["provider_events_path"]).is_file()


def test_claude_auth_failure_remains_terminal_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_path = _worker_manifest(tmp_path, backend="claude", model="opus")
    manifest = json.loads(manifest_path.read_text())
    Path(manifest["log_path"]).write_text("Not logged in · Please run /login\n")

    class _Unauthenticated:
        pid = 224

        def wait(self, timeout=None):
            return 1

        def poll(self):
            return 1

    monkeypatch.setattr(
        subagent.subprocess, "Popen", lambda *args, **kwargs: _Unauthenticated()
    )

    assert subagent._run_managed_manifest(manifest_path) == 1
    manifest = json.loads(manifest_path.read_text())
    assert manifest["status"] == "failed"
    assert manifest["failure"]["category"] == "authentication_failed"
    assert Path(manifest["failure"]["log_path"]).read_text().startswith("Not logged in")
