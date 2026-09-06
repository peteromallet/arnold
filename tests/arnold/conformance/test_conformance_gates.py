from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from arnold.conformance import (
    ConformanceCheckResult,
    ConformanceSuiteResult,
    assert_conformance,
    assert_suite_compliant,
    run_conformance_suite,
)
from arnold.conformance.checks import (
    ACTIVE_MEGAPLAN_PACKAGE_NAMES,
    check_import_coupling,
    check_megaplan_artifact_layout,
    check_never_port_artifacts,
    check_package_name_staleness,
    check_public_workflow_layering,
    check_semantic_coupling,
    validate_collection_artifact_placements,
    validate_canonical_artifact_placements,
    validate_canonical_root_artifacts,
)
from arnold.conformance.deleted_surfaces import (
    DELETED_IMPORT_MODULES,
    DELETED_IMPORT_PREFIXES,
)
from arnold_pipelines.megaplan.layout import is_canonical_chain_spec, is_collection_chain_spec


def _clear_deleted_megaplan_modules() -> None:
    """Remove deleted megaplan modules from sys.modules to keep tests hermetic."""
    for name in list(sys.modules):
        if name == "megaplan" or name.startswith("megaplan."):
            sys.modules.pop(name, None)
        if name == "arnold.pipelines.megaplan" or name.startswith("arnold.pipelines.megaplan."):
            sys.modules.pop(name, None)


def _arnold_root(tmp_path: Path) -> Path:
    root = tmp_path / "arnold"
    root.mkdir()
    (root / "__init__.py").write_text("", encoding="utf-8")
    return root


def _write(root: Path, relative: str, content: str = "") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")
    return path


def test_conformance_public_symbols_are_importable() -> None:
    result = ConformanceCheckResult(check_id="example", passed=True)
    suite = ConformanceSuiteResult(suite_id="example", checks=(result,))

    assert result.passed is True
    assert suite.passed is True
    assert suite.check_count == 1
    assert suite.failure_count == 0
    assert_conformance(result)
    assert_suite_compliant(suite)


def test_current_tree_wires_conformance_suite_and_legacy_reference_gate() -> None:
    suite = run_conformance_suite()

    checks_by_id = {check.check_id: check for check in suite.checks}
    assert {
        "import-coupling",
        "package-name-staleness",
        "semantic-coupling",
        "public-workflow-layering",
        "never-port-artifacts",
        "megaplan-artifact-layout",
        "legacy-reference-allowlist",
    }.issubset(checks_by_id)

    legacy_gate = checks_by_id["legacy-reference-allowlist"]
    assert legacy_gate.details["stale_allowlist"] == []
    assert legacy_gate.details["invalid_entries"] == []
    assert legacy_gate.details["duplicates"] == []

    layout_gate = checks_by_id["megaplan-artifact-layout"]
    assert layout_gate.passed is True
    assert layout_gate.details["unexpected"] == {}


def test_normative_initiative_artifacts_use_canonical_semantic_subdirectories() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    canonical = {
        ".megaplan/initiatives/megaplan-native-parity-corrective/"
        "validation/GOLDEN_TRACE_CONTRACT.md",
        ".megaplan/initiatives/megaplan-north-star-sense-checks-revise-design/"
        "research/research.md",
        ".megaplan/initiatives/native-workflow-platformization/"
        "decisions/PLATFORM_CONTRACT.md",
        ".megaplan/initiatives/standardized-completion-specifications/"
        "evidence/SUPERSESSION_CROSSWALK.yaml",
    }
    preserved_historical = {
        ".megaplan/initiatives/megaplan-native-parity-corrective/"
        "GOLDEN_TRACE_CONTRACT.md",
        ".megaplan/initiatives/megaplan-north-star-sense-checks-revise-design/"
        "docs/research.md",
        ".megaplan/initiatives/native-workflow-platformization/"
        "PLATFORM_CONTRACT.md",
        ".megaplan/initiatives/standardized-completion-specifications/"
        "SUPERSESSION_CROSSWALK.yaml",
    }

    assert all((repo_root / path).is_file() for path in canonical)
    assert all((repo_root / path).is_file() for path in preserved_historical)
    for source, destination in zip(sorted(preserved_historical), sorted(canonical)):
        if source.endswith("PLATFORM_CONTRACT.md"):
            assert (repo_root / source).read_bytes() != (repo_root / destination).read_bytes()
        else:
            assert (repo_root / source).read_bytes() == (repo_root / destination).read_bytes()


def test_typed_canonical_placement_rows_fail_closed_on_unknown_fields() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    record = json.loads(
        (repo_root / "docs/megaplan/post-m11-release-evidence-20260731.json").read_text(
            encoding="utf-8"
        )
    )
    validate_canonical_artifact_placements(record, repo_root=repo_root)
    declared = validate_canonical_root_artifacts(record, repo_root=repo_root)
    assert len(declared) == 20
    record["canonical_artifact_moves"][0]["untrusted_allowlist"] = True
    with pytest.raises(ValueError, match="unknown or missing fields"):
        validate_canonical_artifact_placements(record, repo_root=repo_root)
    root_record = json.loads(
        (repo_root / "docs/megaplan/post-m11-release-evidence-20260731.json").read_text(
            encoding="utf-8"
        )
    )
    root_record["canonical_root_artifacts"][0]["generator"] = "glob"
    with pytest.raises(ValueError, match="generator is unknown"):
        validate_canonical_root_artifacts(root_record, repo_root=repo_root)


def test_ownerless_collection_promotions_are_typed_and_source_preserving() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    record = json.loads(
        (repo_root / "docs/megaplan/post-m11-release-evidence-20260731.json").read_text(
            encoding="utf-8"
        )
    )
    covered = validate_collection_artifact_placements(record, repo_root=repo_root)
    assert len(record["canonical_artifact_moves"]) == 28
    assert covered == (
        ".megaplan/collection/authority.json",
        ".megaplan/initiatives/CLOUD.md",
        ".megaplan/collection/CLOUD.md",
        ".megaplan/initiatives/chain.yaml",
        ".megaplan/collection/chain.yaml",
    )

    for field, value in (
        ("collection_scope", "invented_scope"),
        ("artifact_type", "invented_type"),
    ):
        candidate = json.loads(json.dumps(record))
        row = candidate["canonical_artifact_moves"][-2]
        row[field] = value
        with pytest.raises(ValueError):
            validate_collection_artifact_placements(candidate, repo_root=repo_root)

    missing_authority = json.loads(json.dumps(record))
    del missing_authority["canonical_artifact_moves"][-1]["authority"]
    with pytest.raises(ValueError, match="unknown or missing fields"):
        validate_canonical_artifact_placements(missing_authority, repo_root=repo_root)


def test_collection_layout_rejects_unregistered_files_and_keeps_root_paths_visible(
    tmp_path: Path,
) -> None:
    _write(tmp_path, ".megaplan/initiatives/CLOUD.md", "cloud\n")
    _write(tmp_path, ".megaplan/initiatives/chain.yaml", "milestones: []\n")
    _write(tmp_path, ".megaplan/collection/unknown.txt", "unregistered\n")

    default = check_megaplan_artifact_layout(repo_root=tmp_path)
    explicit = check_megaplan_artifact_layout(repo_root=tmp_path, allowlist=set())
    assert default.details["unexpected"] == explicit.details["unexpected"]
    assert ".megaplan/collection" in default.details["unexpected"]
    assert ".megaplan/initiatives/CLOUD.md" in default.details["unexpected"]
    assert ".megaplan/initiatives/chain.yaml" in default.details["unexpected"]


def test_collection_chain_is_not_an_initiative_or_canonical_cloud_chain() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    collection_chain = repo_root / ".megaplan/collection/chain.yaml"
    assert collection_chain.is_file()
    assert is_collection_chain_spec(collection_chain, repo_root)
    assert not is_canonical_chain_spec(collection_chain, repo_root)


def test_conformance_package_import_does_not_import_megaplan() -> None:
    script = """
import sys

class BlockMegaplan:
    def find_spec(self, fullname, path=None, target=None):
        blocked = (
            fullname == "megaplan"
            or fullname.startswith("arnold_pipelines.megaplan.")
            or fullname == "arnold_pipelines.megaplan"
            or fullname.startswith("arnold_pipelines.megaplan.")
            or fullname == "arnold_pipelines.megaplan"
            or fullname.startswith("arnold_pipelines.megaplan.")
        )
        if blocked:
            raise ModuleNotFoundError(fullname)
        return None

sys.meta_path.insert(0, BlockMegaplan())
import arnold.conformance
assert not any("megaplan" in name for name in sys.modules)
"""
    completed = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script)],
        check=False,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 0, completed.stderr


def test_active_megaplan_package_names_are_scanned() -> None:
    assert ACTIVE_MEGAPLAN_PACKAGE_NAMES == (
        "megaplan",
        "arnold_pipelines.megaplan",
    )


def test_import_coupling_fails_on_new_generic_megaplan_import(tmp_path: Path) -> None:
    root = _arnold_root(tmp_path)
    _write(
        root,
        "generic_surface.py",
        """
        from arnold_pipelines.megaplan.runtime import Driver
        """,
    )

    result = check_import_coupling(package_root=root, allowlist=set())

    assert result.passed is False
    assert result.details["unexpected"] == {
        "arnold.generic_surface": (
            "arnold_pipelines.megaplan.runtime",
            "arnold_pipelines.megaplan.runtime.Driver",
        )
    }


def test_package_name_staleness_fails_on_runtime_string_reference(tmp_path: Path) -> None:
    root = _arnold_root(tmp_path)
    _write(
        root,
        "launcher.py",
        """
        COMMAND = "python -m arnold_pipelines.megaplan run"
        """,
    )

    result = check_package_name_staleness(package_root=root, allowlist=set())

    assert result.passed is False
    assert result.details["unexpected"] == {
        "arnold.launcher": ("arnold_pipelines.megaplan",)
    }


def test_semantic_coupling_fails_on_megaplan_workflow_vocabulary(tmp_path: Path) -> None:
    root = _arnold_root(tmp_path)
    _write(
        root,
        "workflow.py",
        """
        NEXT_HANDLER = "handle_tiebreaker"
        PHASE = "tiebreaker"
        STATE_CLASS = "PlanState"
        PLAN_ROOT = ".megaplan/plans/example"
        """,
    )

    result = check_semantic_coupling(package_root=root, allowlist=set())

    assert result.passed is False
    assert result.details["unexpected"] == {
        "arnold.workflow": (
            ".megaplan",
            "PlanState",
            "handler-name",
            "phase:tiebreaker",
            "tiebreaker",
        )
    }


def test_public_workflow_layering_fails_on_public_stage_export(tmp_path: Path) -> None:
    root = _arnold_root(tmp_path)
    _write(root, "pipelines/__init__.py")
    _write(
        root,
        "pipelines/example/__init__.py",
        """
        from arnold.pipeline import Stage

        __all__ = ["Stage", "build"]

        def build(stage: Stage) -> Stage:
            return stage
        """,
    )

    result = check_public_workflow_layering(package_root=root, allowlist=set())

    assert result.passed is False
    assert result.details["unexpected"] == {
        "arnold.pipelines.example": (
            "annotation-Stage",
            "exports-Stage",
            "package-imports-Stage",
        )
    }


def test_never_port_artifacts_fails_on_runtime_artifact_files(tmp_path: Path) -> None:
    _write(tmp_path, ".megaplan/_archived-plans/old/state.json", "{}")
    _write(tmp_path, ".hermes_state", "{}")
    _write(tmp_path, "data/run.db-wal", "")
    _write(tmp_path, "logs/driver-001.log", "")
    _write(tmp_path, "runs/prompt_dump.txt", "")
    _write(tmp_path, "runs/runtime_state.json", "{}")
    _write(tmp_path, "runs/receipt.json", "{}")

    result = check_never_port_artifacts(repo_root=tmp_path, allowlist=set())

    assert result.passed is False
    assert set(result.details["unexpected"]) == {
        ".hermes_state",
        ".megaplan/_archived-plans/old/state.json",
        "data/run.db-wal",
        "logs/driver-001.log",
        "runs/prompt_dump.txt",
        "runs/receipt.json",
        "runs/runtime_state.json",
    }


def test_active_megaplan_runtime_dirs_are_not_source_artifacts(tmp_path: Path) -> None:
    _write(tmp_path, ".megaplan/plans/current/step_receipt_execute_v2.json", "{}")
    _write(tmp_path, ".megaplan/verification/verification/raw_latest.log", "")
    _write(tmp_path, ".megaplan/.state-locks/current.lock", "")
    _write(tmp_path, ".megaplan/_archived-plans/old/state.json", "{}")

    result = check_never_port_artifacts(repo_root=tmp_path, allowlist=set())

    assert result.passed is False
    assert result.details["unexpected"] == {
        ".megaplan/_archived-plans/old/state.json": (".megaplan archived plan",)
    }


def test_megaplan_artifact_layout_fails_on_loose_planning_files(tmp_path: Path) -> None:
    _write(tmp_path, "briefs/demo/chain.yaml", "milestones: []\n")
    _write(tmp_path, "chain.yaml", "milestones: []\n")
    _write(tmp_path, ".megaplan/plan_v4.md", "plan\n")
    _write(tmp_path, ".megaplan/briefs/demo/chain.yaml", "milestones: []\n")

    result = check_megaplan_artifact_layout(repo_root=tmp_path, allowlist=set())

    assert result.passed is False
    assert result.details["unexpected"] == {
        ".megaplan/briefs/demo/chain.yaml": ("legacy .megaplan/briefs tree",),
        ".megaplan/plan_v4.md": ("loose plan version outside .megaplan/plans",),
        "briefs/demo/chain.yaml": ("legacy top-level briefs tree",),
        "chain.yaml": ("root chain spec",),
    }


def test_megaplan_artifact_layout_accepts_initiative_docs(tmp_path: Path) -> None:
    _write(tmp_path, ".megaplan/initiatives/demo/chain.yaml", "milestones: []\n")
    _write(tmp_path, ".megaplan/initiatives/demo/cloud.yaml", "provider: ssh\n")
    _write(tmp_path, ".megaplan/initiatives/demo/NORTHSTAR.md", "# North Star\n")
    _write(tmp_path, ".megaplan/initiatives/demo/STRATEGY.md", "# Strategy\n")
    _write(
        tmp_path,
        ".megaplan/initiatives/demo/proof-map.json",
        '{"m1": [".megaplan/initiatives/demo/validation-receipt.json"]}\n',
    )
    _write(tmp_path, ".megaplan/initiatives/demo/completion-manifest.json", "{}\n")
    _write(tmp_path, ".megaplan/initiatives/demo/dependency-completion-proof.json", "{}\n")
    _write(tmp_path, ".megaplan/initiatives/demo/validation-receipt.json", "{}\n")
    _write(tmp_path, ".megaplan/initiatives/demo/.retired", "retired_at: now\n")
    _write(tmp_path, ".megaplan/initiatives/demo/briefs/m1.md", "# M1\n")
    _write(tmp_path, ".megaplan/initiatives/demo/research/audit.md", "# Audit\n")
    _write(tmp_path, ".megaplan/initiatives/demo/decisions/route.md", "# Decision\n")
    _write(tmp_path, ".megaplan/initiatives/demo/notes/status.md", "# Status\n")
    _write(tmp_path, ".megaplan/initiatives/demo/assets/data.json", "{}\n")
    _write(tmp_path, ".megaplan/initiatives/demo/archive/old/chain.yaml", "milestones: []\n")
    _write(tmp_path, ".megaplan/initiatives/demo/annexes/context.md", "# Annex\n")
    _write(tmp_path, ".megaplan/initiatives/demo/validation/m1.md", "# Validation\n")
    _write(tmp_path, ".megaplan/initiatives/demo/handoff/subagent.md", "# Handoff\n")
    _write(tmp_path, ".megaplan/initiatives/demo/handoffs/m1/receipt.json", "{}\n")
    _write(tmp_path, ".megaplan/initiatives/demo/evidence/runtime.json", "{}\n")

    result = check_megaplan_artifact_layout(repo_root=tmp_path, allowlist=set())

    assert result.passed is True
    assert result.details["unexpected"] == {}


def test_megaplan_artifact_layout_rejects_loose_initiative_doc(tmp_path: Path) -> None:
    _write(tmp_path, ".megaplan/initiatives/demo/random.md", "# Loose\n")

    result = check_megaplan_artifact_layout(repo_root=tmp_path, allowlist=set())

    assert result.passed is False
    assert result.details["unexpected"] == {
        ".megaplan/initiatives/demo/random.md": ("initiative artifact outside canonical subdirectories",)
    }


def test_allowlist_entries_are_ratchets_and_stale_entries_fail(tmp_path: Path) -> None:
    root = _arnold_root(tmp_path)
    _write(root, "neutral.py", "VALUE = 1\n")

    result = check_import_coupling(
        package_root=root,
        allowlist={"arnold.neutral"},
    )

    assert result.passed is False
    assert result.details["stale_allowlist"] == ["arnold.neutral"]


def test_dynamic_import_paths_fail_for_deleted_surfaces() -> None:
    """Every module in the canonical deleted-import inventory must not resolve.

    Uses ``DELETED_IMPORT_MODULES`` and ``DELETED_IMPORT_PREFIXES`` from
    ``arnold.conformance.deleted_surfaces`` so coverage scales with the
    canonical list rather than being locked to Megaplan-only hardcodes.
    """
    import importlib

    for module_name in DELETED_IMPORT_MODULES:
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(module_name)

    for prefix in DELETED_IMPORT_PREFIXES:
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(prefix)
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(f"{prefix}.nonexistent_sub")


def test_eval_exec_cannot_resolve_deleted_surfaces() -> None:
    """All canonical deleted-import modules must fail via eval/exec __import__.

    Drives the check from ``DELETED_IMPORT_MODULES`` and
    ``DELETED_IMPORT_PREFIXES`` so every deleted surface is covered,
    not just the old Megaplan old-path prefix.
    """
    for module_name in DELETED_IMPORT_MODULES:
        with pytest.raises(ModuleNotFoundError):
            eval(f"__import__('{module_name}')")  # noqa: S307

    for prefix in DELETED_IMPORT_PREFIXES:
        with pytest.raises(ModuleNotFoundError):
            eval(f"__import__('{prefix}')")  # noqa: S307


def test_sys_modules_audit_finds_no_deleted_modules_after_conformance() -> None:
    """After the conformance suite, no canonically-deleted module is loaded.

    Drives the audit from ``DELETED_IMPORT_MODULES`` (exact matches) and
    ``DELETED_IMPORT_PREFIXES`` (prefix matches) so every deleted surface
    in the canonical inventory is covered.
    """
    run_conformance_suite()

    exact_hits = [name for name in sys.modules if name in DELETED_IMPORT_MODULES]
    prefix_hits = [
        name
        for name in sys.modules
        if any(
            name == prefix or name.startswith(prefix + ".")
            for prefix in DELETED_IMPORT_PREFIXES
        )
    ]
    assert exact_hits == [], f"deleted modules loaded: {exact_hits}"
    assert prefix_hits == [], f"deleted-prefix modules loaded: {prefix_hits}"


def test_filesystem_reads_of_legacy_megaplan_state_are_blocked(tmp_path: Path) -> None:
    """Instrumentation blocks reads of old .megaplan runtime state outside migration modules.

    This test verifies the guard can be attached to ``Path.open`` and that it
    rejects legacy state paths while permitting ordinary files.
    """
    from pathlib import Path

    legacy_state = tmp_path / ".megaplan" / "plans" / "current" / "state.json"
    legacy_state.parent.mkdir(parents=True)
    legacy_state.write_text('{"old": true}', encoding="utf-8")

    ordinary = tmp_path / "ok.txt"
    ordinary.write_text("ok", encoding="utf-8")

    original_open = Path.open

    def _guarded_open(self, *args, **kwargs):
        path = str(self)
        if ".megaplan/plans/" in path and "migrat" not in path:
            raise PermissionError(f"blocked legacy .megaplan state read: {path}")
        return original_open(self, *args, **kwargs)

    Path.open = _guarded_open  # type: ignore[assignment]
    try:
        with pytest.raises(PermissionError):
            legacy_state.read_text(encoding="utf-8")
        assert ordinary.read_text(encoding="utf-8") == "ok"
    finally:
        Path.open = original_open  # type: ignore[assignment]
