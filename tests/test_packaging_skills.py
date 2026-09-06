from pathlib import Path

from arnold_pipelines.megaplan.cli.skills import (
    _CODEX_SINGLE_FILE_SKILLS,
    _GLOBAL_TARGETS,
    _resolve_bundle_path,
    bundled_global_file,
)


def test_subagent_launcher_skill_bundle_is_portable() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    skill_dir = repo_root / "arnold_pipelines" / "megaplan" / "skills" / "subagent-launcher"
    skill_file = skill_dir / "SKILL.md"

    assert skill_file.is_file()
    assert not skill_file.is_symlink()
    assert (skill_dir / "launch_omp_agent.py").is_file()
    assert (skill_dir / "fan.py").is_file()


def test_subagent_launcher_is_synced_to_agent_skill_dirs() -> None:
    targets = [
        target
        for target in _GLOBAL_TARGETS
        if target.get("data") == "skills/subagent-launcher"
    ]

    assert {
        (target["agent"], target["path"], target["install"])
        for target in targets
    } == {
        ("claude", ".claude/skills/subagent-launcher", "symlink"),
        ("codex", ".codex/skills/subagent-launcher", "symlink"),
        ("agents", ".agents/skills/subagent-launcher", "symlink"),
    }

    skill_dir = _resolve_bundle_path("skills/subagent-launcher")
    assert skill_dir.is_dir()
    assert (skill_dir / "SKILL.md").is_file()
    assert (skill_dir / "launch_omp_agent.py").is_file()


def test_fix_the_fixer_skill_bundle_is_portable() -> None:
    skill_dir = _resolve_bundle_path("skills/fix-the-fixer")

    assert skill_dir.is_dir()
    assert (skill_dir / "SKILL.md").is_file()
    assert (skill_dir / "agents/openai.yaml").is_file()
    assert (skill_dir / "scripts/render_goal.py").is_file()
    assert (skill_dir / "references/historical-runs.md").is_file()


def test_fix_the_fixer_is_synced_to_agent_skill_dirs() -> None:
    targets = [
        target
        for target in _GLOBAL_TARGETS
        if target.get("data") == "skills/fix-the-fixer"
    ]

    assert {
        (target["agent"], target["path"], target["install"])
        for target in targets
    } == {
        ("claude", ".claude/skills/fix-the-fixer", "symlink"),
        ("codex", ".codex/skills/fix-the-fixer", "symlink"),
        ("agents", ".agents/skills/fix-the-fixer", "symlink"),
    }


def test_all_generated_codex_skill_targets_have_generator_entries() -> None:
    generated_targets = {
        target["data"].removeprefix("_codex_skills/")
        for target in _GLOBAL_TARGETS
        if target["agent"] == "codex"
        and target["data"].startswith("_codex_skills/")
        and target["data"] != "_codex_skills/megaplan"
    }

    assert generated_targets == set(_CODEX_SINGLE_FILE_SKILLS)


def test_superfixer_debug_codex_bundle_matches_canonical_skill() -> None:
    targets = [
        target
        for target in _GLOBAL_TARGETS
        if target["agent"] == "codex"
        and target["path"] == ".codex/skills/superfixer-debug"
    ]
    assert [target["data"] for target in targets] == ["skills/superfixer-debug"]

    bundle = _resolve_bundle_path("skills/superfixer-debug") / "SKILL.md"

    assert bundle.is_file()
    assert bundle.read_text(encoding="utf-8") == bundled_global_file(
        "superfixer_debug_skill.md"
    )
