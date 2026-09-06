from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import yaml


def _load_adopt_plan_module():
    script = Path(__file__).resolve().parents[1] / "scripts" / "adopt_plan.py"
    spec = importlib.util.spec_from_file_location("adopt_plan_script", script)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_adopt_rebinds_plan_project_dir_and_clears_active_step(tmp_path: Path) -> None:
    adopt_plan = _load_adopt_plan_module()
    project_dir = tmp_path / "target"
    source_root = tmp_path / "paf"
    project_dir.mkdir()
    source_root.mkdir()

    spec_path = tmp_path / "chain.yaml"
    spec_path.write_text(
        yaml.safe_dump(
            {
                "milestones": [
                    {
                        "label": "m6-strangler",
                        "vendor": "codex",
                        "depth": "max",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    chain_state_path = adopt_plan._compute_chain_state_path(spec_path)
    chain_state_path.parent.mkdir(parents=True)
    chain_state_path.write_text(
        json.dumps({"completed": [], "retry_counts": {"m6-strangler": 3}}),
        encoding="utf-8",
    )

    source_plan_dir = source_root / "m6-plan"
    source_plan_dir.mkdir()
    stale_project_dir = source_root / "old-worktree"
    (source_plan_dir / "state.json").write_text(
        json.dumps(
            {
                "current_state": "finalized",
                "latest_failure": {"kind": "old"},
                "last_failure": {"kind": "older"},
                "active_step": {"phase": "execute", "worker_pid": 12345},
                "config": {
                    "project_dir": str(stale_project_dir),
                    "vendor": "claude",
                    "depth": "low",
                    "phase_model": ["plan=claude:low", "execute=claude:high"],
                    "tier_models": {
                        "execute": {
                            "1": "omp:deepseek/deepseek-v4-pro",
                            "4": "claude:low",
                        }
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    changes = adopt_plan.adopt(
        project_dir=project_dir,
        spec_path=spec_path,
        milestone_label="m6-strangler",
        from_plan_dir=source_plan_dir,
    )

    target_state_path = project_dir / ".megaplan" / "plans" / "m6-plan" / "state.json"
    target_state = json.loads(target_state_path.read_text(encoding="utf-8"))
    assert target_state["config"]["project_dir"] == str(project_dir)
    assert target_state["config"]["vendor"] == "codex"
    assert target_state["config"]["depth"] == "max"
    assert target_state["config"]["phase_model"] == [
        "plan=codex:low",
        "execute=codex:high",
    ]
    assert target_state["config"]["tier_models"]["execute"]["4"] == "codex:low"
    assert target_state["config"]["tier_models"]["execute"]["1"].startswith("omp:")
    assert "active_step" not in target_state
    assert target_state["latest_failure"] is None
    assert target_state["last_failure"] is None
    assert any(
        change["action"] == "patch_plan_state"
        and change["config.project_dir"]["before"] == str(stale_project_dir)
        and change["config.project_dir"]["after"] == str(project_dir)
        for change in changes
    )
