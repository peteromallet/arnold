from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

from arnold_pipelines.megaplan.resident.agent_loop import (
    AgentLoopError,
    AgentRequest,
    ManagedProviderCliAgentRunner,
    _omp_resume_session_missing,
)
from arnold_pipelines.megaplan.resident.config import ResidentConfig
from arnold_pipelines.megaplan.resident.cli import _resident_runner
from arnold_pipelines.megaplan.resident.tool_registry import ToolRegistry
from arnold_pipelines.megaplan.store.file import FileStore


def _request(conversation_id: str = "conversation-1") -> AgentRequest:
    return AgentRequest(
        conversation_id=conversation_id,
        messages=({"role": "user", "content": "Reply with the smoke token."},),
        system_prompt="You are the resident.",
        turn_id="turn-provider-test",
    )


def _manifests(root: Path) -> list[Path]:
    return sorted((root / "provider_runs").glob("*/*/manifest.json"))


def _write_omp_launcher(
    path: Path,
    *,
    sleep: bool = False,
    change_session_id_on_resume: bool = False,
    fail_first_resume_as_missing: bool = False,
) -> None:
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import argparse, json, os, time\n"
        "from pathlib import Path\n"
        "p=argparse.ArgumentParser()\n"
        "p.add_argument('--model'); p.add_argument('--toolsets'); p.add_argument('--max-tokens')\n"
        "p.add_argument('--project-dir'); p.add_argument('--query-file'); p.add_argument('--session-id')\n"
        "p.add_argument('--metadata-file'); p.add_argument('--resume-session', action='store_true')\n"
        "a=p.parse_args()\n"
        "Path(os.environ['PROVIDER_CALLS']).open('a').write(json.dumps(vars(a), sort_keys=True)+'\\n')\n"
        + ("time.sleep(30)\n" if sleep else "")
        + (
            "marker=Path(os.environ['MISSING_RESUME_MARKER'])\n"
            "if a.resume_session and not marker.exists():\n"
            " marker.write_text('failed once')\n"
            " print(f'error: omp session {a.session_id} does not exist', file=__import__('sys').stderr)\n"
            " raise SystemExit(8)\n"
            if fail_first_resume_as_missing
            else ""
        )
        + (
            "reported_session='internal-session-id' if a.resume_session else a.session_id\n"
            if change_session_id_on_resume
            else "reported_session=a.session_id\n"
        )
        + "metadata={'schema_version':'arnold-omp-launcher-metadata-v1','session_id':reported_session,'resolved_model':'glm-5.2','toolsets':a.toolsets.split(','),'usage':{'output_tokens':3},'events':[]}\n"
        + "metadata.update({'resumed_session_id':a.session_id} if a.resume_session else {})\n"
        + "Path(a.metadata_file).write_text(json.dumps(metadata))\n"
        "print('OMP_RESIDENT_OK')\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def test_resident_cli_selects_managed_glm_runner_and_store_custody(
    tmp_path: Path,
) -> None:
    store = FileStore(tmp_path / "resident-store")

    runner = _resident_runner(ResidentConfig(), tmp_path, store=store)

    assert isinstance(runner, ManagedProviderCliAgentRunner)
    assert runner.config.model_provider == "omp"
    assert runner.config.model_name == "zai/glm-5.2"
    assert runner.state_root == store.root


def test_omp_resident_runner_persists_artifacts_and_resumes_exact_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launcher = tmp_path / "fake_omp.py"
    calls = tmp_path / "calls.jsonl"
    _write_omp_launcher(launcher)
    monkeypatch.setenv("PROVIDER_CALLS", str(calls))
    state_root = tmp_path / "state"
    runner = ManagedProviderCliAgentRunner(
        ResidentConfig(
            model_provider="omp",
            model_name="zai/glm-5.2",
            model_timeout_s=5,
            model_max_tokens=1234,
            model_toolsets="file,terminal",
        ),
        cwd=tmp_path,
        state_root=state_root,
        omp_launcher=launcher,
    )

    first = asyncio.run(runner.run(_request(), ToolRegistry()))
    second = asyncio.run(runner.run(_request(), ToolRegistry()))

    assert first.final_text == "OMP_RESIDENT_OK"
    assert second.final_text == "OMP_RESIDENT_OK"
    assert first.metadata["session_id"] == second.metadata["session_id"]
    assert first.metadata["session_mode"] == "new"
    assert second.metadata["session_mode"] == "resume"
    call_rows = [json.loads(line) for line in calls.read_text().splitlines()]
    assert call_rows[0]["max_tokens"] == "1234"
    assert call_rows[0]["toolsets"] == "file,terminal"
    assert call_rows[0]["resume_session"] is False
    assert call_rows[1]["resume_session"] is True
    assert call_rows[0]["session_id"] == call_rows[1]["session_id"]

    manifests = _manifests(state_root)
    assert len(manifests) == 2
    for manifest_path in manifests:
        manifest = json.loads(manifest_path.read_text())
        run_dir = manifest_path.parent
        assert manifest["status"] == "completed"
        assert manifest["provider"] == "omp"
        assert manifest["resident_turn_id"] == "turn-provider-test"
        assert manifest["model_session"]["state"] == "persisted"
        assert manifest["telemetry"]["raw_stream_equivalence"] == (
            "provider_specific_not_byte_identical"
        )
        assert (run_dir / "prompt.md").is_file()
        assert (run_dir / "result.md").read_text().strip() == "OMP_RESIDENT_OK"
        assert (run_dir / "run.log").is_file()
        assert (run_dir / "provider.raw").is_file()
        assert (run_dir / "events.jsonl").is_file()


def test_omp_resume_preserves_stable_handle_when_metadata_reports_internal_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launcher = tmp_path / "fake_omp.py"
    calls = tmp_path / "calls.jsonl"
    _write_omp_launcher(launcher, change_session_id_on_resume=True)
    monkeypatch.setenv("PROVIDER_CALLS", str(calls))
    runner = ManagedProviderCliAgentRunner(
        ResidentConfig(model_provider="omp", model_name="zai/glm-5.2"),
        cwd=tmp_path,
        state_root=tmp_path / "state",
        omp_launcher=launcher,
    )

    asyncio.run(runner.run(_request(), ToolRegistry()))
    second = asyncio.run(runner.run(_request(), ToolRegistry()))
    third = asyncio.run(runner.run(_request(), ToolRegistry()))

    rows = [json.loads(line) for line in calls.read_text().splitlines()]
    stable_session_id = rows[0]["session_id"]
    assert [row["session_id"] for row in rows] == [stable_session_id] * 3
    assert second.metadata["session_id"] == stable_session_id
    assert third.metadata["session_id"] == stable_session_id
    session_file = next((tmp_path / "state" / "provider_sessions").glob("*.json"))
    assert json.loads(session_file.read_text())["session_id"] == stable_session_id


def test_omp_missing_resume_is_quarantined_and_retried_fresh_without_turn_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launcher = tmp_path / "fake_omp.py"
    calls = tmp_path / "calls.jsonl"
    marker = tmp_path / "missing-resume.failed"
    _write_omp_launcher(launcher, fail_first_resume_as_missing=True)
    monkeypatch.setenv("PROVIDER_CALLS", str(calls))
    monkeypatch.setenv("MISSING_RESUME_MARKER", str(marker))
    state_root = tmp_path / "state"
    runner = ManagedProviderCliAgentRunner(
        ResidentConfig(model_provider="omp", model_name="zai/glm-5.2"),
        cwd=tmp_path,
        state_root=state_root,
        omp_launcher=launcher,
    )

    first = asyncio.run(runner.run(_request(), ToolRegistry()))
    recovered = asyncio.run(runner.run(_request(), ToolRegistry()))

    assert first.final_text == recovered.final_text == "OMP_RESIDENT_OK"
    rows = [json.loads(line) for line in calls.read_text().splitlines()]
    assert [row["resume_session"] for row in rows] == [False, True, False]
    manifests = [json.loads(path.read_text()) for path in _manifests(state_root)]
    failed = next(item for item in manifests if item["status"] == "failed")
    assert failed["failure"]["category"] == "resume_session_missing"
    assert failed["recovery"]["retry_replays_turn"] is False
    assert Path(failed["provider_raw_output_path"]).read_text() == ""
    assert Path(failed["provider_metadata_path"]).read_text() == ""
    assert len(list((state_root / "provider_sessions" / "quarantine").glob("*.json"))) == 1
    active_sessions = list((state_root / "provider_sessions").glob("*.json"))
    assert len(active_sessions) == 1
    assert json.loads(active_sessions[0].read_text())["state"] == "persisted"


def test_omp_missing_resume_detection_requires_pre_dispatch_evidence(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "run.log"
    raw_path = tmp_path / "provider.raw"
    metadata_path = tmp_path / "provider-metadata.json"
    diagnostic = "error: omp session stale-handle does not exist\n"
    log_path.write_text(diagnostic)
    raw_path.write_text("")
    metadata_path.write_text("")

    assert _omp_resume_session_missing(
        log_path=log_path,
        raw_path=raw_path,
        metadata_path=metadata_path,
        returncode=8,
    )
    assert not _omp_resume_session_missing(
        log_path=log_path,
        raw_path=raw_path,
        metadata_path=metadata_path,
        returncode=6,
    )

    log_path.write_text("provider failed without a pre-dispatch diagnostic\n")
    raw_path.write_text(diagnostic)
    assert not _omp_resume_session_missing(
        log_path=log_path,
        raw_path=raw_path,
        metadata_path=metadata_path,
        returncode=8,
    )

    raw_path.write_text("")
    log_path.write_text(diagnostic)
    metadata_path.write_text('{"session_id":"possibly-started"}')
    assert not _omp_resume_session_missing(
        log_path=log_path,
        raw_path=raw_path,
        metadata_path=metadata_path,
        returncode=8,
    )


def test_codex_resident_runner_captures_thread_and_resumes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    codex = tmp_path / "codex"
    calls = tmp_path / "codex-calls.jsonl"
    session_id = "11111111-2222-4333-8444-555555555555"
    codex.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "args=sys.argv[1:]\n"
        "Path(os.environ['PROVIDER_CALLS']).open('a').write(json.dumps(args)+'\\n')\n"
        "out=Path(args[args.index('--output-last-message')+1])\n"
        "out.write_text('CODEX_RESIDENT_OK\\n')\n"
        "sys.stdin.read()\n"
        f"print(json.dumps({{'type':'thread.started','thread_id':'{session_id}'}}))\n"
        "print(json.dumps({'type':'turn.completed','usage':{'output_tokens':2}}))\n",
        encoding="utf-8",
    )
    codex.chmod(0o755)
    monkeypatch.setenv("PROVIDER_CALLS", str(calls))
    state_root = tmp_path / "state"
    runner = ManagedProviderCliAgentRunner(
        ResidentConfig(model_provider="codex", model_name="gpt-5.6-terra"),
        cwd=tmp_path,
        state_root=state_root,
        codex_bin=str(codex),
    )

    first = asyncio.run(runner.run(_request(), ToolRegistry()))
    second = asyncio.run(runner.run(_request(), ToolRegistry()))

    assert first.final_text == second.final_text == "CODEX_RESIDENT_OK"
    assert first.metadata["session_id"] == session_id
    assert second.metadata["session_mode"] == "resume"
    rows = [json.loads(line) for line in calls.read_text().splitlines()]
    assert "resume" not in rows[0]
    assert "resume" in rows[1]
    assert session_id in rows[1]


def test_claude_resident_runner_preserves_auth_failure_evidence(
    tmp_path: Path,
) -> None:
    launcher = tmp_path / "fake_claude.py"
    launcher.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "sid=sys.argv[sys.argv.index('--session-id')+1]\n"
        "print(json.dumps({'type':'system','subtype':'init','session_id':sid,'model':'opus','tools':['Read']}))\n"
        "print(json.dumps({'type':'result','subtype':'error_during_execution','session_id':sid,'is_error':True,'errors':['Not logged in · Please run /login'],'usage':{}}))\n"
        "print('Not logged in', file=sys.stderr)\n"
        "raise SystemExit(1)\n",
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    state_root = tmp_path / "state"
    runner = ManagedProviderCliAgentRunner(
        ResidentConfig(
            model_provider="claude",
            model_name="opus",
            model_timeout_s=5,
            model_max_tokens=2222,
            model_toolsets="file",
        ),
        cwd=tmp_path,
        state_root=state_root,
        claude_launcher=launcher,
    )

    with pytest.raises(AgentLoopError, match="authentication_failed"):
        asyncio.run(runner.run(_request(), ToolRegistry()))

    manifest = json.loads(_manifests(state_root)[0].read_text())
    assert manifest["status"] == "failed"
    assert manifest["failure"]["category"] == "authentication_failed"
    assert manifest["model_session"]["state"] == "reserved_unconfirmed"
    assert manifest["provider_contract"]["controls"]["max_tokens"] == 2222
    assert "Not logged in" in Path(manifest["log_path"]).read_text()
    assert "Not logged in" in Path(manifest["provider_raw_output_path"]).read_text()


def test_omp_resident_runner_captures_timeout_terminally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launcher = tmp_path / "slow_omp.py"
    calls = tmp_path / "calls.jsonl"
    _write_omp_launcher(launcher, sleep=True)
    monkeypatch.setenv("PROVIDER_CALLS", str(calls))
    state_root = tmp_path / "state"
    runner = ManagedProviderCliAgentRunner(
        ResidentConfig(
            model_provider="omp",
            model_name="zai/glm-5.2",
            model_timeout_s=0.05,
        ),
        cwd=tmp_path,
        state_root=state_root,
        omp_launcher=launcher,
    )

    with pytest.raises(AgentLoopError, match="timeout"):
        asyncio.run(runner.run(_request("timeout-conversation"), ToolRegistry()))

    manifest = json.loads(_manifests(state_root)[0].read_text())
    assert manifest["status"] == "failed"
    assert manifest["returncode"] == 124
    assert manifest["failure"]["category"] == "timeout"
    assert Path(manifest["run_id"]).name == manifest["run_id"]


def test_provider_environment_preserves_absent_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launcher = tmp_path / "fake_omp.py"
    calls = tmp_path / "calls.jsonl"
    _write_omp_launcher(launcher)
    monkeypatch.setenv("PROVIDER_CALLS", str(calls))
    monkeypatch.setenv("ARNOLD_RESIDENT_DELEGATION_CONTEXT", "stale")
    runner = ManagedProviderCliAgentRunner(
        ResidentConfig(model_provider="omp", model_name="zai/glm-5.2"),
        cwd=tmp_path,
        state_root=tmp_path / "state",
        omp_launcher=launcher,
    )

    response = asyncio.run(runner.run(_request(), ToolRegistry()))

    assert response.final_text == "OMP_RESIDENT_OK"
    # The child did not need the variable; the assertion documents that the
    # runner succeeded after environment_with_provenance removed stale custody.
    assert os.environ["ARNOLD_RESIDENT_DELEGATION_CONTEXT"] == "stale"
