"""Validator CLI tests — M1 dispatch substrate proof (migrated from archive).

Covers ``pipelines check`` validator scenarios using current CLI/import paths:
fail-closed manifest validation, graph compatibility acceptance,
contract mismatch vs missing-binding distinction, declaration drift,
non-model invocation fail-closed, and judge-manifest validation.
"""

from __future__ import annotations

import os
from argparse import Namespace
import importlib.util
from pathlib import Path
from typing import Any

import pytest

from arnold.execution.step_invocation import StepInvocation
from arnold.pipeline.types import Edge, Pipeline, Port, PortRef, ReadRef, Stage, WriteRef
from arnold.workflow.validator import (
    DECLARATION_DRIFT_CODE,
    Diagnostics,
    MISSING_BINDING_CODE,
    UNKNOWN_ADAPTER_CODE,
    ValidationIssue,
    contract_diagnostic_code,
    validate,
)
from arnold.pipelines._authoring import validate_package_module


# ── helpers ────────────────────────────────────────────────────────────────


class _NoopStep:
    name = "noop"
    kind = "produce"
    prompt_key = None
    slot = None

    @property
    def produces(self) -> tuple:
        return ()

    @property
    def consumes(self) -> tuple:
        return ()

    def run(self, ctx):  # pragma: no cover
        raise RuntimeError("static validator must not dispatch")


def _stage(name: str, *edges: Edge) -> Stage:
    return Stage(name=name, step=_NoopStep(), edges=tuple(edges))


def _assert_issue(
    diag: Diagnostics,
    *,
    code: str,
    stage: str,
    detail_items: dict[str, object] | None = None,
    edge_items: dict[str, object] | None = None,
    message_contains: str | None = None,
) -> None:
    matches = [
        issue
        for issue in diag.issues
        if issue.code == code
        and issue.stage == stage
        and (
            detail_items is None
            or all(issue.details.get(key) == value for key, value in detail_items.items())
        )
    ]
    assert matches, diag.issues
    issue = matches[0]
    assert issue.message in diag.defects
    if message_contains is not None:
        assert message_contains in issue.message
    if edge_items is not None:
        assert issue.edge is not None
        for key, value in edge_items.items():
            assert issue.edge.get(key) == value


# ── validator shim type/code re-exports ────────────────────────────────────


def test_m1_dispatch_substrate_validator_shim_reexports_neutral_diagnostic_types() -> None:
    """M1 dispatch substrate proof: validator shim exposes diagnostic types and codes."""
    issue = ValidationIssue(code=MISSING_BINDING_CODE, message="x")
    assert issue.code == "dataflow.missing_binding"
    assert contract_diagnostic_code("no_match") == "contract.no_match"


def test_m1_dispatch_substrate_diagnostics_ok_property() -> None:
    """M1 dispatch substrate proof: Diagnostics.ok reflects defect presence."""
    assert Diagnostics(defects=[]).ok is True
    assert Diagnostics(defects=["x"]).ok is False


# ── contract mismatch vs missing binding distinction ───────────────────────


def test_m1_dispatch_substrate_validator_distinguishes_contract_mismatch_from_missing_binding() -> None:
    """M1 dispatch substrate proof: typed contract mismatches are distinct from missing bindings."""
    pipeline = Pipeline(
        stages={
            "start": Stage(
                name="start",
                step=_NoopStep(),
                writes=(Port(name="draft", content_type="text/plain"),),
                edges=(
                    Edge(label="to-contract", target="needs-contract"),
                    Edge(label="to-missing", target="needs-missing"),
                ),
            ),
            "needs-contract": Stage(
                name="needs-contract",
                step=_NoopStep(),
                reads=(PortRef(port_name="draft", content_type="text/markdown"),),
                edges=(Edge(label="halt", target="halt"),),
            ),
            "needs-missing": Stage(
                name="needs-missing",
                step=_NoopStep(),
                reads=(ReadRef(name="missing.md"),),
                edges=(Edge(label="halt", target="halt"),),
            ),
        },
        entry="start",
    )

    diag = validate(pipeline)

    _assert_issue(
        diag,
        code="contract.content_type_mismatch",
        stage="needs-contract",
        detail_items={"dependency": "draft", "error_kind": "content_type_mismatch"},
        message_contains="expects content_type 'text/markdown'",
    )
    _assert_issue(
        diag,
        code=MISSING_BINDING_CODE,
        stage="needs-missing",
        detail_items={
            "dependency": "missing.md",
            "route_hint": "(missing from predecessor 'start')",
        },
        message_contains="dependency 'missing.md' is unsatisfied",
    )


def test_m1_dispatch_substrate_validator_preserves_legacy_untyped_passthrough() -> None:
    """M1 dispatch substrate proof: untyped ReadRef/WriteRef pipelines pass validation."""
    pipeline = Pipeline(
        stages={
            "start": Stage(
                name="start",
                step=_NoopStep(),
                writes=(WriteRef(name="draft.md"),),
                edges=(Edge(label="next", target="end"),),
            ),
            "end": Stage(
                name="end",
                step=_NoopStep(),
                reads=(ReadRef(name="draft.md"),),
                edges=(Edge(label="halt", target="halt"),),
            ),
        },
        entry="start",
    )

    diag = validate(pipeline)
    assert diag.ok, diag.issues


# ── invocation codes ───────────────────────────────────────────────────────


def test_m1_dispatch_substrate_validator_surfaces_invocation_code() -> None:
    """M1 dispatch substrate proof: unknown adapter is reported."""
    pipeline = Pipeline(
        stages={
            "review": Stage(
                name="review",
                step=_NoopStep(),
                invocation=StepInvocation(kind="custom-collector-v2"),
                edges=(Edge(label="halt", target="halt"),),
            ),
        },
        entry="review",
    )

    diag = validate(pipeline)

    _assert_issue(
        diag,
        code=UNKNOWN_ADAPTER_CODE,
        stage="review",
        detail_items={
            "invocation_kind": "custom-collector-v2",
            "registered_kinds": ["model"],
        },
        message_contains="registered adapter",
    )
# ── graph structure validation ─────────────────────────────────────────────


def test_m1_dispatch_substrate_edge_to_nonexistent_stage_is_flagged() -> None:
    """M1 dispatch substrate proof: edge targeting unknown stage produces defect."""
    pipeline = Pipeline(
        stages={
            "start": _stage("start", Edge(label="go", target="missing")),
        },
        entry="start",
    )
    diag = validate(pipeline)
    assert not diag.ok
    _assert_issue(
        diag,
        code="edge_target_unknown_stage",
        stage="start",
        detail_items={"known_stages": ["start"]},
        edge_items={"label": "go", "target": "missing", "kind": "normal"},
        message_contains="missing",
    )


def test_m1_dispatch_substrate_simple_valid_pipeline_passes_validation() -> None:
    """M1 dispatch substrate proof: simple valid pipeline passes structural validation."""
    pipeline = Pipeline(
        stages={
            "start": _stage("start", Edge(label="halt", target="halt")),
        },
        entry="start",
    )
    diag = validate(pipeline)
    assert diag.ok, diag.defects


def test_m1_dispatch_substrate_unreachable_stage_is_flagged() -> None:
    """M1 dispatch substrate proof: unreachable stage is reported."""
    pipeline = Pipeline(
        stages={
            "start": _stage("start", Edge(label="halt", target="halt")),
            "orphan": _stage("orphan", Edge(label="halt", target="halt")),
        },
        entry="start",
    )
    diag = validate(pipeline)
    assert not diag.ok
    _assert_issue(
        diag,
        code="stage_unreachable",
        stage="orphan",
        detail_items={"entry": "start"},
        message_contains="unreachable",
    )


def test_m1_dispatch_substrate_halt_label_is_ok_when_target_is_halt() -> None:
    """M1 dispatch substrate proof: conventional halt→halt edge is valid."""
    pipeline = Pipeline(
        stages={
            "start": _stage("start", Edge(label="halt", target="halt")),
        },
        entry="start",
    )
    diag = validate(pipeline)
    assert diag.ok, diag.defects


def test_m1_dispatch_substrate_halt_label_with_non_halt_target_is_flagged() -> None:
    """M1 dispatch substrate proof: reserved 'halt' label with wrong target is flagged."""
    pipeline = Pipeline(
        stages={
            "start": _stage("start", Edge(label="halt", target="end")),
            "end": _stage("end", Edge(label="halt", target="halt")),
        },
        entry="start",
    )
    diag = validate(pipeline)
    assert not diag.ok
    _assert_issue(
        diag,
        code="edge_reserved_halt_label",
        stage="start",
        detail_items={"reserved_label": "halt"},
        edge_items={"label": "halt", "target": "end", "kind": "normal"},
        message_contains="reserved label 'halt'",
    )


# ── CLI-level validator scenarios (monkeypatch) ───────────────────────────


def test_m1_dispatch_substrate_cli_check_distinguishes_contract_mismatch_from_missing_binding(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """M1 dispatch substrate proof: 'pipelines check' reports distinct diagnostic codes."""
    from arnold_pipelines.megaplan import cli as cli_mod
    from arnold_pipelines.megaplan import registry as registry_mod

    pipeline = Pipeline(
        stages={
            "start": Stage(
                name="start",
                step=_NoopStep(),
                writes=(Port(name="draft", content_type="text/plain"),),
                edges=(
                    Edge(label="to-contract", target="needs-contract"),
                    Edge(label="to-missing", target="needs-missing"),
                ),
            ),
            "needs-contract": Stage(
                name="needs-contract",
                step=_NoopStep(),
                reads=(PortRef(port_name="draft", content_type="text/markdown"),),
                edges=(Edge(label="halt", target="halt"),),
            ),
            "needs-missing": Stage(
                name="needs-missing",
                step=_NoopStep(),
                reads=(ReadRef(name="missing.md"),),
                edges=(Edge(label="halt", target="halt"),),
            ),
        },
        entry="start",
    )

    monkeypatch.setattr(registry_mod, "scan_python_pipelines", lambda: [])
    monkeypatch.setattr(registry_mod, "get_pipeline", lambda name: pipeline)

    rc = cli_mod._handle_pipelines(
        os.getcwd(),
        Namespace(pipelines_action="check", pipeline_name="typed-diagnostics"),
    )

    captured = capsys.readouterr()
    assert rc == 1
    assert "pipelines check: 'typed-diagnostics' has 2 defect(s):" in captured.err
    assert "[contract.content_type_mismatch]" in captured.err
    assert "[dataflow.missing_binding]" in captured.err
    assert "typed dependency 'draft' expects content_type 'text/markdown'" in captured.err
    assert "dependency 'missing.md' is unsatisfied" in captured.err


def test_m1_dispatch_substrate_cli_check_reports_declaration_drift_with_stable_code(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """M1 dispatch substrate proof: 'pipelines check' reports declaration drift."""
    from arnold_pipelines.megaplan import cli as cli_mod
    from arnold_pipelines.megaplan import registry as registry_mod

    pipeline = Pipeline(
        stages={
            "start": Stage(
                name="start",
                step=_NoopStep(),
                writes=(Port(name="draft", content_type="text/plain"),),
                produces=(Port(name="draft", content_type="text/markdown"),),
                edges=(Edge(label="halt", target="halt"),),
            ),
        },
        entry="start",
    )

    monkeypatch.setattr(registry_mod, "scan_python_pipelines", lambda: [])
    monkeypatch.setattr(registry_mod, "get_pipeline", lambda name: pipeline)

    rc = cli_mod._handle_pipelines(
        os.getcwd(),
        Namespace(pipelines_action="check", pipeline_name="drifted-authoring"),
    )

    captured = capsys.readouterr()
    assert rc == 1
    assert "[contract.declaration_drift]" in captured.err
    assert "conflicting explicit and typed produces declarations" in captured.err


def test_m1_dispatch_substrate_cli_check_preserves_existing_graph_validation_codes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """M1 dispatch substrate proof: 'pipelines check' preserves edge-target validation."""
    from arnold_pipelines.megaplan import cli as cli_mod
    from arnold_pipelines.megaplan import registry as registry_mod

    pipeline = Pipeline(
        stages={
            "start": _stage("start", Edge(label="go", target="missing")),
        },
        entry="start",
    )

    monkeypatch.setattr(registry_mod, "scan_python_pipelines", lambda: [])
    monkeypatch.setattr(registry_mod, "get_pipeline", lambda name: pipeline)

    rc = cli_mod._handle_pipelines(
        os.getcwd(),
        Namespace(pipelines_action="check", pipeline_name="broken-graph"),
    )

    captured = capsys.readouterr()
    assert rc == 1
    assert "[edge_target_unknown_stage]" in captured.err
    assert "edge 'go' targets unknown stage 'missing'" in captured.err


def test_m1_dispatch_substrate_cli_check_non_model_invocation_is_authorable_but_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """M1 dispatch substrate proof: non-model invocation is authorable but fail-closed in check."""
    from arnold_pipelines.megaplan import cli as cli_mod
    from arnold_pipelines.megaplan import registry as registry_mod

    run_attempted = False

    class _ExplodingStep:
        name = "exploding"
        kind = "produce"
        prompt_key = None
        slot = None

        @property
        def produces(self) -> tuple:
            return ()

        @property
        def consumes(self) -> tuple:
            return ()

        def run(self, ctx):
            nonlocal run_attempted
            run_attempted = True
            raise AssertionError("pipelines check must not execute authored steps")

    pipeline = Pipeline(
        stages={
            "review": Stage(
                name="review",
                step=_ExplodingStep(),
                invocation=StepInvocation.with_adapter_config(
                    kind="external_tool",
                    adapter_config={"action": "approve"},
                ),
                edges=(Edge(label="halt", target="halt"),),
            ),
        },
        entry="review",
    )

    monkeypatch.setattr(registry_mod, "scan_python_pipelines", lambda: [])
    monkeypatch.setattr(registry_mod, "get_pipeline", lambda name: pipeline)

    rc = cli_mod._handle_pipelines(
        os.getcwd(),
        Namespace(pipelines_action="check", pipeline_name="tool-review"),
    )

    captured = capsys.readouterr()
    assert rc == 1
    assert "[invocation.unknown_adapter]" in captured.err
    assert (
        "invocation kind 'external_tool' does not resolve to a registered adapter"
        in captured.err
    )
    assert run_attempted is False


def test_pipelines_new_emits_native_first_projected_shell(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """`pipelines new` writes the native-first projected-shell scaffold."""
    from arnold_pipelines.megaplan import cli as cli_mod
    from arnold_pipelines.megaplan.runtime import discovery as discovery_mod

    pipelines_dir = tmp_path / "pipelines"
    pipelines_dir.mkdir()
    monkeypatch.setattr(
        discovery_mod,
        "_SCAN_ROOTS",
        ((tmp_path, "arnold_pipelines"), (pipelines_dir, "arnold_pipelines.megaplan.pipelines")),
    )

    rc = cli_mod._handle_pipelines(
        os.getcwd(),
        Namespace(pipelines_action="new", pipeline_name="native-scaffold", driver=None),
    )

    assert rc == 0
    module_path = pipelines_dir / "native_scaffold.py"
    skill_path = pipelines_dir / "native-scaffold" / "SKILL.md"
    assert module_path.exists()
    assert skill_path.exists()

    content = module_path.read_text(encoding="utf-8")
    assert "@pipeline" in content
    assert "@phase" in content
    assert "@decision" in content
    assert "compile_pipeline(" in content
    assert "project_graph(" in content
    assert 'supported_modes: tuple[str, ...] = ("native",)' in content
    assert 'driver: tuple[str, str] = ("native", "project+validate")' in content

    spec = importlib.util.spec_from_file_location("native_scaffold", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    validate_package_module(module)

    pipeline = module.build_pipeline()
    assert pipeline.native_program is not None


def test_pipelines_new_refuses_overwrite_via_handler(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`pipelines new` preserves overwrite refusal for existing module paths."""
    from arnold_pipelines.megaplan import cli as cli_mod
    from arnold_pipelines.megaplan.runtime import discovery as discovery_mod

    pipelines_dir = tmp_path / "pipelines"
    pipelines_dir.mkdir()
    monkeypatch.setattr(
        discovery_mod,
        "_SCAN_ROOTS",
        ((tmp_path, "arnold_pipelines"), (pipelines_dir, "arnold_pipelines.megaplan.pipelines")),
    )

    first = cli_mod._handle_pipelines(
        os.getcwd(),
        Namespace(pipelines_action="new", pipeline_name="native-exists", driver=None),
    )
    second = cli_mod._handle_pipelines(
        os.getcwd(),
        Namespace(pipelines_action="new", pipeline_name="native-exists", driver=None),
    )

    assert first == 0
    assert second == 1
    assert "already exists" in capsys.readouterr().err


def test_pipelines_new_rejects_legacy_graph_driver(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`--driver graph` is rejected as legacy input."""
    from arnold_pipelines.megaplan import cli as cli_mod
    from arnold_pipelines.megaplan.runtime import discovery as discovery_mod

    pipelines_dir = tmp_path / "pipelines"
    pipelines_dir.mkdir()
    monkeypatch.setattr(
        discovery_mod,
        "_SCAN_ROOTS",
        ((tmp_path, "arnold_pipelines"), (pipelines_dir, "arnold_pipelines.megaplan.pipelines")),
    )

    rc = cli_mod._handle_pipelines(
        os.getcwd(),
        Namespace(pipelines_action="new", pipeline_name="legacy-graph", driver="graph"),
    )

    assert rc == 1
    captured = capsys.readouterr()
    assert "unsupported legacy driver 'graph'" in captured.err
    assert not (pipelines_dir / "legacy_graph.py").exists()


# ── judge manifest validation ──────────────────────────────────────────────


def test_m1_dispatch_substrate_judge_manifest_shape_validates() -> None:
    """M1 dispatch substrate proof: well-formed judge manifest passes validation."""
    from arnold_pipelines.megaplan.judge_manifest import (
        EVALUAND_RECORD_CONTENT_TYPE,
        JudgeManifestPort,
        make_judge_manifest,
    )
    from arnold_pipelines.megaplan.runtime.judge_manifest_discovery import (
        validate_judge_manifest,
    )

    manifest = make_judge_manifest(
        name="m5-wrapper-eval",
        implementation="arnold_pipelines.megaplan.eval.wrapper:Judge",
        arnold_api_version="2026-05-31",
        model_identity="model:gpt-5.4",
        rubric_body={"rubric": "return an EvaluandRecord judgment"},
        consumes=(JudgeManifestPort("candidate", "text/markdown"),),
        produces=(JudgeManifestPort("evaluand", EVALUAND_RECORD_CONTENT_TYPE),),
        source_hash="sha256:cafebabe",
    )

    diag = validate_judge_manifest(manifest, path="m5-wrapper-eval.judge.json")
    assert diag.ok, diag.defects
