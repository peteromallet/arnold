from __future__ import annotations

import json
from pathlib import Path

import pytest

from arnold_pipelines.megaplan._core.workflow import resume_plan
from arnold_pipelines.megaplan.cli import main as cli_main
from arnold_pipelines.megaplan.store import FileStore, RevisionConflict
from arnold_pipelines.megaplan.types import CliError


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    (project / ".git").mkdir()
    return project


def _plan_dir(project: Path, name: str, *, phase: str = "execute", batch_index: int | None = 2, epic_id: str | None = None) -> Path:
    plan_dir = project / ".megaplan" / "plans" / name
    plan_dir.mkdir(parents=True)
    cursor = {"phase": phase, "retry_strategy": "rerun_phase"}
    if batch_index is not None:
        cursor["batch_index"] = batch_index
    state = {
        "name": name,
        "idea": "idea",
        "current_state": "blocked",
        "iteration": 1,
        "created_at": "2026-05-05T00:00:00Z",
        "config": {},
        "sessions": {},
        "plan_versions": [],
        "history": [],
        "meta": {},
        "last_gate": {},
        "latest_failure": {"kind": "execution_blocked"},
        "resume_cursor": cursor,
    }
    if epic_id is not None:
        state["epic_id"] = epic_id
    (plan_dir / "state.json").write_text(json.dumps(state), encoding="utf-8")
    return plan_dir


def test_resume_plan_reenters_cursor_and_clears_failure_after_success(tmp_path: Path) -> None:
    project = _project(tmp_path)
    plan_dir = _plan_dir(project, "blocked-plan")
    calls: list[list[str]] = []

    def runner(args: list[str], cwd: Path | None = None):
        calls.append(args)
        state = json.loads((plan_dir / "state.json").read_text(encoding="utf-8"))
        assert state["current_state"] == "finalized"
        assert state["latest_failure"] == {"kind": "execution_blocked"}
        (plan_dir / "finalize.json").write_text(
            json.dumps(
                {
                    "tasks": [
                        {
                            "id": "T1",
                            "status": "done",
                            "commands_run": [
                                "pytest tests/editorial_run_lifecycle.py"
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (plan_dir / "phase_result.json").write_text(
            json.dumps({"phase": "execute", "exit_kind": "success"}),
            encoding="utf-8",
        )
        state["current_state"] = "executed"
        (plan_dir / "state.json").write_text(json.dumps(state), encoding="utf-8")
        return 0, "ok", ""

    result = resume_plan(project, "blocked-plan", runner=runner)

    assert result["success"] is True
    assert calls == [["execute", "--plan", "blocked-plan", "--confirm-destructive", "--user-approved", "--batch", "2"]]
    state = json.loads((plan_dir / "state.json").read_text(encoding="utf-8"))
    assert state["current_state"] == "executed"
    assert "latest_failure" not in state
    assert "resume_cursor" not in state


def test_resume_plan_rejects_later_phase_without_execute_authority(tmp_path: Path) -> None:
    project = _project(tmp_path)
    plan_dir = _plan_dir(project, "failed-resume", phase="review", batch_index=None)
    called = False

    def runner(args: list[str], cwd: Path | None = None):
        nonlocal called
        called = True
        return 0, "", ""

    with pytest.raises(CliError) as exc:
        resume_plan(project, "failed-resume", runner=runner)

    assert exc.value.code == "resume_execute_authority_blocked"
    assert exc.value.extra["guard"] == "before_later_phase_dispatch"
    assert exc.value.extra["reason"] == "execute_authority_unavailable"
    assert called is False
    state = json.loads((plan_dir / "state.json").read_text(encoding="utf-8"))
    assert state["current_state"] == "blocked"
    assert state["latest_failure"] == {"kind": "execution_blocked"}
    assert state["resume_cursor"]["phase"] == "review"


def test_resume_plan_requires_cursor(tmp_path: Path) -> None:
    project = _project(tmp_path)
    plan_dir = _plan_dir(project, "no-cursor")
    state = json.loads((plan_dir / "state.json").read_text(encoding="utf-8"))
    state.pop("resume_cursor")
    (plan_dir / "state.json").write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(CliError, match="no resume cursor"):
        resume_plan(project, "no-cursor", runner=lambda args, cwd=None: (0, "", ""))


def test_resume_revision_conflict_records_epic_progress_event(tmp_path: Path) -> None:
    project = _project(tmp_path)
    store = FileStore(tmp_path / "store")
    epic = store.create_epic(title="Epic", goal="Goal", body="Body")
    _plan_dir(project, "conflict-plan", epic_id=epic.id)

    def runner(args: list[str], cwd: Path | None = None):
        raise RevisionConflict("expected revision 1, found 2")

    with pytest.raises(CliError, match="revision conflict"):
        resume_plan(project, "conflict-plan", store=store, runner=runner)

    events = store.list_progress_events(epic_id=epic.id, plan_id="conflict-plan")
    assert len(events) == 1
    assert events[0].kind == "execution_blocked"
    assert "expected revision" in events[0].details["message"]


def test_resume_cli_dispatches_minimal_entry_point(tmp_path: Path, monkeypatch, capsys) -> None:
    project = _project(tmp_path)
    _plan_dir(project, "cli-resume", phase="review", batch_index=None)
    monkeypatch.chdir(project)

    def fake_resume(root: Path, plan: str, *, store=None):
        return {"success": True, "step": "resume", "plan": plan, "phase": "review", "state": "done"}

    monkeypatch.setattr("arnold_pipelines.megaplan.cli.resume_plan", fake_resume)

    exit_code = cli_main(["resume", "--plan", "cli-resume"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["step"] == "resume"
    assert payload["phase"] == "review"
