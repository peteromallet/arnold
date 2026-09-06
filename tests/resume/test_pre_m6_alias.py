from __future__ import annotations

import json
from pathlib import Path

import pytest

from arnold.runtime.envelope import RuntimeEnvelope
from arnold_pipelines.megaplan._core.workflow import resume_plan
from arnold_pipelines.megaplan import registry
from arnold_pipelines.megaplan.registry import get_pipeline
from arnold_pipelines.megaplan.runtime.discovery import _NAME_ALIASES, canonical_pipeline_name
from arnold_pipelines.megaplan.types import CliError


def _write_execute_authority(plan_dir: Path, *, task_id: str = "legacy-task") -> None:
    (plan_dir / "finalize.json").write_text(
        json.dumps({"tasks": [{"id": task_id, "status": "waived"}]}),
        encoding="utf-8",
    )
    (plan_dir / "phase_result.json").write_text(
        json.dumps({"phase": "execute", "exit_kind": "success"}),
        encoding="utf-8",
    )


def test_pre_m6_planning_name_alias_resolves_registry_pipeline() -> None:
    assert _NAME_ALIASES["planning"] == "megaplan"
    assert canonical_pipeline_name("planning") == "megaplan"
    pipeline = get_pipeline("planning")
    assert pipeline is not None
    assert pipeline.id == "megaplan"
    assert "prep" in {step.id for step in pipeline.steps}


def test_resume_plan_with_pre_m6_planning_cursor_runs(tmp_path: Path) -> None:
    plan = "legacy-planning"
    plan_dir = tmp_path / ".megaplan" / "plans" / plan
    plan_dir.mkdir(parents=True)
    (plan_dir / "state.json").write_text(
        json.dumps(
            {
                "name": plan,
                "idea": "legacy",
                "current_state": "blocked",
                "iteration": 1,
                "created_at": "2026-01-01T00:00:00Z",
                "_pipeline_name": "planning",
                "resume_cursor": {
                    "phase": "execute",
                    "pipeline": "planning",
                    "batch_index": 1,
                },
                "history": [],
                "config": {},
                "sessions": {},
                "plan_versions": [],
                "meta": {},
                "last_gate": {},
            }
        ),
        encoding="utf-8",
    )
    calls: list[list[str]] = []

    def runner(args: list[str], *, cwd: Path) -> tuple[int, str, str]:
        calls.append(list(args))
        _write_execute_authority(plan_dir, task_id="legacy-resume")
        state_path = plan_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["current_state"] = "done"
        state_path.write_text(json.dumps(state), encoding="utf-8")
        return 0, "", ""

    result = resume_plan(tmp_path, plan, runner=runner)

    assert result["success"] is True
    assert calls == [
        [
            "execute",
            "--plan",
            plan,
            "--confirm-destructive",
            "--user-approved",
            "--batch",
            "1",
        ]
    ]
    state = json.loads((plan_dir / "state.json").read_text(encoding="utf-8"))
    assert state["current_state"] == "done"
    assert "resume_cursor" not in state
    assert state["meta"]["pipeline_alias_migrations"] == [
        {"from": "planning", "to": "megaplan", "phase": "execute"}
    ]
    envelope = RuntimeEnvelope.from_json(json.dumps(state["runtime_envelope"]))
    assert envelope.plugin_id == "megaplan"
    assert envelope.run_id == plan
    assert envelope.resume_cursor is not None
    assert envelope.resume_cursor.cursor["phase"] == "execute"
    assert envelope.resume_cursor.cursor["pipeline"] == "planning"


def test_resume_plan_refuses_pipeline_manifest_chimera(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MEGAPLAN_M6_MANIFEST_DISCOVERY", "1")
    registry._GLOBAL_REGISTRY = registry.PipelineRegistry()
    current_hash = registry.pipeline_metadata("planning")["manifest_hash"]
    assert isinstance(current_hash, str)

    plan = "chimera-planning"
    plan_dir = tmp_path / ".megaplan" / "plans" / plan
    plan_dir.mkdir(parents=True)
    original_state = {
        "name": plan,
        "idea": "legacy",
        "current_state": "blocked",
        "iteration": 1,
        "created_at": "2026-01-01T00:00:00Z",
        "_pipeline_name": "planning",
        "_pipeline_manifest_hash": "sha256:not-the-current-manifest",
        "resume_cursor": {"phase": "execute", "pipeline": "planning"},
        "history": [],
        "config": {"project_dir": str(tmp_path)},
        "sessions": {},
        "plan_versions": [],
        "meta": {},
        "last_gate": {},
    }
    (plan_dir / "state.json").write_text(json.dumps(original_state), encoding="utf-8")

    called = False

    def runner(args: list[str], *, cwd: Path) -> tuple[int, str, str]:
        nonlocal called
        called = True
        return 0, "", ""

    with pytest.raises(CliError) as exc:
        resume_plan(tmp_path, plan, runner=runner)

    assert exc.value.code == "pipeline_manifest_mismatch"
    assert called is False
    state = json.loads((plan_dir / "state.json").read_text(encoding="utf-8"))
    assert state["current_state"] == "blocked"
    envelope = RuntimeEnvelope.from_json(json.dumps(state["runtime_envelope"]))
    assert envelope.plugin_id == "megaplan"
    assert envelope.trust_state == "quarantined-manifest-mismatch"
    assert state["meta"]["pipeline_alias_migrations"] == [
        {"from": "planning", "to": "megaplan", "phase": "execute"}
    ]


def test_resume_plan_accepts_matching_pipeline_manifest_hash(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MEGAPLAN_M6_MANIFEST_DISCOVERY", "1")
    registry._GLOBAL_REGISTRY = registry.PipelineRegistry()
    current_hash = registry.pipeline_metadata("planning")["manifest_hash"]

    plan = "hashed-planning"
    plan_dir = tmp_path / ".megaplan" / "plans" / plan
    plan_dir.mkdir(parents=True)
    (plan_dir / "state.json").write_text(
        json.dumps(
            {
                "name": plan,
                "idea": "legacy",
                "current_state": "blocked",
                "iteration": 1,
                "created_at": "2026-01-01T00:00:00Z",
                "_pipeline_name": "planning",
                "_pipeline_manifest_hash": current_hash,
                "resume_cursor": {"phase": "execute", "pipeline": "planning"},
                "history": [],
                "config": {},
                "sessions": {},
                "plan_versions": [],
                "meta": {},
                "last_gate": {},
            }
        ),
        encoding="utf-8",
    )
    def runner(args: list[str], *, cwd: Path) -> tuple[int, str, str]:
        _write_execute_authority(plan_dir, task_id="hashed-resume")
        state_path = plan_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["current_state"] = "done"
        state_path.write_text(json.dumps(state), encoding="utf-8")
        return 0, "", ""

    result = resume_plan(tmp_path, plan, runner=runner)
    assert result["success"] is True


def test_resume_plan_rollback_preserves_runtime_envelope_on_failed_operation(tmp_path: Path) -> None:
    plan = "legacy-failed-resume"
    plan_dir = tmp_path / ".megaplan" / "plans" / plan
    plan_dir.mkdir(parents=True)
    (plan_dir / "state.json").write_text(
        json.dumps(
            {
                "name": plan,
                "idea": "legacy",
                "current_state": "blocked",
                "iteration": 1,
                "created_at": "2026-01-01T00:00:00Z",
                "_pipeline_name": "planning",
                "resume_cursor": {"phase": "execute", "pipeline": "planning"},
                "history": [],
                "config": {},
                "sessions": {},
                "plan_versions": [],
                "meta": {},
                "last_gate": {},
            }
        ),
        encoding="utf-8",
    )

    def runner(args: list[str], *, cwd: Path) -> tuple[int, str, str]:
        state_path = plan_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["current_state"] = "executing"
        state_path.write_text(json.dumps(state), encoding="utf-8")
        return 2, "", "failed"

    result = resume_plan(tmp_path, plan, runner=runner)

    assert result["success"] is False
    state = json.loads((plan_dir / "state.json").read_text(encoding="utf-8"))
    assert state["current_state"] == "blocked"
    assert state["resume_cursor"] == {"phase": "execute", "pipeline": "planning"}
    assert "runtime_envelope" not in state
    assert "pipeline_alias_migrations" not in state["meta"]


def test_resume_plan_refuses_non_builtin_missing_runtime_envelope(tmp_path: Path) -> None:
    plan = "creative-without-envelope"
    plan_dir = tmp_path / ".megaplan" / "plans" / plan
    plan_dir.mkdir(parents=True)
    (plan_dir / "state.json").write_text(
        json.dumps(
            {
                "name": plan,
                "idea": "legacy",
                "current_state": "blocked",
                "iteration": 1,
                "created_at": "2026-01-01T00:00:00Z",
                "_pipeline_name": "creative",
                "resume_cursor": {"phase": "draft", "pipeline": "creative"},
                "history": [],
                "config": {"project_dir": str(tmp_path)},
                "sessions": {},
                "plan_versions": [],
                "meta": {},
                "last_gate": {},
            }
        ),
        encoding="utf-8",
    )

    called = False

    def runner(args: list[str], *, cwd: Path) -> tuple[int, str, str]:
        nonlocal called
        called = True
        return 0, "", ""

    with pytest.raises(CliError) as exc:
        resume_plan(tmp_path, plan, runner=runner)

    assert exc.value.code == "pipeline_identity_unavailable"
    assert called is False
