from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_megaplan(argv: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    env.pop("MEGAPLAN_BACKEND", None)
    return subprocess.run(
        [sys.executable, "-m", "arnold_pipelines.megaplan", *argv],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=env,
    )


def test_brief_new_writes_canonical_file(tmp_path: Path) -> None:
    proc = _run_megaplan(
        ["brief", "new", "My Idea", "-b", "Do the thing."],
        cwd=tmp_path,
    )

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    path = tmp_path / ".megaplan" / "initiatives" / "my-idea" / "briefs" / "my-idea.md"
    assert payload["path"] == str(path)
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\ntype: brief\nslug: my-idea\n")
    assert text.endswith("\nDo the thing.\n")


def test_brief_new_init_runs_from_created_brief(tmp_path: Path) -> None:
    proc = _run_megaplan(
        ["brief", "new", "Launch Me", "-b", "write a tiny plan", "--init"],
        cwd=tmp_path,
    )

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["initialized"] is True
    assert payload["init"]["success"] is True
    plan = payload["init"]["plan"]
    state = json.loads(
        (tmp_path / ".megaplan" / "plans" / plan / "state.json").read_text(
            encoding="utf-8"
        )
    )
    assert state["idea"] == "write a tiny plan"


def test_brief_epic_scaffolds_chain_and_milestones(tmp_path: Path) -> None:
    proc = _run_megaplan(
        [
            "brief",
            "epic",
            "Artifact Store",
            "--milestone",
            "m1-schema=Schema",
            "--milestone",
            "m2-api=API",
        ],
        cwd=tmp_path,
    )

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    epic_dir = tmp_path / ".megaplan" / "initiatives" / "artifact-store"
    assert payload["chain"] == str(epic_dir / "chain.yaml")
    assert (epic_dir / "briefs" / "m1-schema.md").exists()
    assert (epic_dir / "briefs" / "m2-api.md").exists()
    chain = yaml.safe_load((epic_dir / "chain.yaml").read_text(encoding="utf-8"))
    assert chain["base_branch"] == "main"
    assert chain["anchors"] == {"north_star": "NORTHSTAR.md"}
    assert chain["milestones"] == [
        {
            "label": "m1-schema",
            "idea": ".megaplan/initiatives/artifact-store/briefs/m1-schema.md",
            "branch": "megaplan/artifact-store/m1-schema",
            "profile": "partnered-5",
            "vendor": "codex",
            "robustness": "full",
            "depth": "high",
            "with_prep": True,
        },
        {
            "label": "m2-api",
            "idea": ".megaplan/initiatives/artifact-store/briefs/m2-api.md",
            "branch": "megaplan/artifact-store/m2-api",
            "profile": "partnered-5",
            "vendor": "codex",
            "robustness": "full",
            "depth": "high",
            "with_prep": True,
        },
        {
            "label": "reconcile",
            "kind": "reconcile",
            "idea": ".megaplan/initiatives/artifact-store/briefs/reconcile.md",
            "branch": "reconcile/artifact-store-20260905",
            "target_branch": "main",
            "merge_policy": "review",
            "phase_model": ["execute=codex"],
            "depends_on": ["m2-api"],
        },
    ]
    assert chain["merge_policy"] == "auto"
    assert chain["driver"]["auto_approve"] is True


def test_brief_list_show_and_search_use_common_artifact_shape(tmp_path: Path) -> None:
    create = _run_megaplan(
        ["brief", "new", "Shared Shape", "-b", "Searchable artifact body"],
        cwd=tmp_path,
    )
    assert create.returncode == 0, create.stderr

    listed = _run_megaplan(["brief", "list"], cwd=tmp_path)
    assert listed.returncode == 0, listed.stderr
    list_payload = json.loads(listed.stdout)
    assert list_payload["briefs"][0]["id"] == "shared-shape/briefs/shared-shape"
    assert list_payload["briefs"][0]["title"] == "Shared Shape"

    shown = _run_megaplan(["brief", "show", "shared-shape"], cwd=tmp_path)
    assert shown.returncode == 0, shown.stderr
    show_payload = json.loads(shown.stdout)
    assert show_payload["brief"]["body"] == "Searchable artifact body"
    assert show_payload["brief"]["metadata"]["type"] == "brief"

    searched = _run_megaplan(["brief", "search", "artifact"], cwd=tmp_path)
    assert searched.returncode == 0, searched.stderr
    search_payload = json.loads(searched.stdout)
    assert [item["id"] for item in search_payload["briefs"]] == ["shared-shape/briefs/shared-shape"]
    assert "snippet" in search_payload["briefs"][0]


def test_initiative_new_rejects_existing_and_searches_description(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    created = _run_megaplan(
        [
            "initiative",
            "new",
            "Cloud Agents",
            "--title",
            "Cloud Agents",
            "--description",
            "Discord worker routing and durable planning context.",
            "--chain",
        ],
        cwd=tmp_path,
    )
    assert created.returncode == 0, created.stderr
    payload = json.loads(created.stdout)
    initiative = payload["initiative"]
    assert initiative["slug"] == "cloud-agents"
    assert initiative["title"] == "Cloud Agents"
    assert initiative["description"] == "Discord worker routing and durable planning context."

    duplicate = _run_megaplan(
        ["initiative", "new", "Cloud Agents", "--description", "Replacement text"],
        cwd=tmp_path,
    )
    assert duplicate.returncode != 0
    duplicate_payload = json.loads(duplicate.stdout)
    assert duplicate_payload["error"] == "initiative_exists"

    listed = _run_megaplan(["initiative", "list"], cwd=tmp_path)
    assert listed.returncode == 0, listed.stderr
    list_payload = json.loads(listed.stdout)
    assert list_payload["initiatives"][0]["description"] == "Discord worker routing and durable planning context."

    searched = _run_megaplan(["initiative", "search", "routing"], cwd=tmp_path)
    assert searched.returncode == 0, searched.stderr
    search_payload = json.loads(searched.stdout)
    assert [item["slug"] for item in search_payload["initiatives"]] == ["cloud-agents"]

    fuzzy = _run_megaplan(["initiative", "search", "clod", "agnts", "--keywords-all"], cwd=tmp_path)
    assert fuzzy.returncode == 0, fuzzy.stderr
    fuzzy_payload = json.loads(fuzzy.stdout)
    assert [item["slug"] for item in fuzzy_payload["initiatives"]] == ["cloud-agents"]
    assert fuzzy_payload["initiatives"][0]["matched_terms"] == ["clod", "agnts"]


def test_initiative_new_defaults_description_and_rejects_blank(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    missing = _run_megaplan(["initiative", "new", "No Description"], cwd=tmp_path)
    assert missing.returncode == 0, missing.stderr
    missing_payload = json.loads(missing.stdout)
    expected = (
        "TODO_INITIATIVE_DESCRIPTION: Describe the outcome for No Description, "
        "why it matters, and the boundary of the work."
    )
    assert missing_payload["initiative"]["description"] == expected
    readme = tmp_path / ".megaplan" / "initiatives" / "no-description" / "README.md"
    assert expected in readme.read_text(encoding="utf-8")

    blank = _run_megaplan(
        ["initiative", "new", "Blank Description", "--description", "   "],
        cwd=tmp_path,
    )
    assert blank.returncode != 0
    assert "description must not be empty" in blank.stderr
