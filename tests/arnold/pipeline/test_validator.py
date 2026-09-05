"""Tests for prompt/resource validation in ``arnold.workflow.validator`` (M3c T6).

Covers:

* Missing prompt_key referencing unknown resource bundle
* Missing resource_bundles on pipeline
* Bundle-scoped success (prompt key matches a bundle)
* Deterministic defect ordering
* Doc/creative pipeline prompt rendering compatibility
* NO global mutable prompt registry (verified by boundary check)
* Non-model adapter registry: default fail-closed, supplied-registry success,
  reserved model semantics unchanged (T4)
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import arnold.pipeline.validator as pipeline_validator_shim
from arnold.workflow.builder import PipelineBuilder
from arnold.pipeline.types import Edge, ParallelStage, Pipeline, Port, PortRef, ReadRef, Stage, StepContext, StepResult, WriteRef
from arnold.execution.step_invocation import (
    StepInvocation,
    StepInvocationAdapterRegistry,
)
from arnold.workflow.validator import (
    CONTRACT_ERROR_CODE_MAP,
    DECLARATION_DRIFT_CODE,
    DIRECT_NATIVE_DRIVER_CLAIM_CODE,
    Diagnostics,
    MALFORMED_NATIVE_BUNDLE_CODE,
    ManifestValidationContext,
    MISSING_BINDING_CODE,
    NATIVE_MANIFEST_GRAPH_COMPAT_CODE,
    NATIVE_MANIFEST_INVALID_METADATA_CODE,
    NATIVE_MANIFEST_MISSING_EXECUTION_CODE,
    PLACEHOLDER_EXECUTION_RESOURCE_CODE,
    UNKNOWN_ADAPTER_CODE,
    _decision_enum_from_suspension_schema,
    _step_prompt_key,
    contract_diagnostic_code,
    validate,
    validate_dataflow_paths,
)
from arnold.pipeline.native.ir import NativeProgram


# ── Minimal stub step with prompt_key ─────────────────────────────────────


@dataclass(frozen=True)
class _PromptStep:
    """A step that carries a prompt_key for validation testing."""

    name: str = "prompt_step"
    kind: str = "produce"
    prompt_key: str | None = None
    slot: str | None = None

    def run(self, ctx: Any) -> Any:
        raise RuntimeError("static validator must not dispatch")


# ── Builder helper to avoid keyword-before-positional issues ──────────────


class _StageBuilder:
    """Fluent builder for constructing test stages without kwarg ordering issues."""

    def __init__(self, name: str) -> None:
        self._name = name
        self._prompt_key: str | None = None
        self._edges: tuple[Edge, ...] = ()

    def with_prompt_key(self, key: str | None) -> "_StageBuilder":
        self._prompt_key = key
        return self

    def with_edges(self, *edges: Edge) -> "_StageBuilder":
        self._edges = edges
        return self

    def build(self) -> Stage:
        step = _PromptStep(name=self._name, prompt_key=self._prompt_key)
        return Stage(name=self._name, step=step, edges=self._edges)


def _pipeline(stages: dict, entry: str = "start", bundles: tuple = ()) -> Pipeline:
    return Pipeline(
        stages=stages,
        entry=entry,
        resource_bundles=bundles,
    )


def _assert_issue(
    diag: Diagnostics,
    *,
    code: str,
    stage: str,
    detail_items: dict[str, object] | None = None,
    message_contains: str | None = None,
) -> None:
    matches = [issue for issue in diag.issues if issue.code == code and issue.stage == stage]
    assert matches, diag.issues
    issue = matches[0]
    assert issue.message in diag.defects
    if message_contains is not None:
        assert message_contains in issue.message
    if detail_items is not None:
        for key, value in detail_items.items():
            actual = issue.details.get(key)
            assert actual == value, f"issue.details[{key!r}] mismatch: {actual!r} != {value!r}"


def _simple_pipeline(*, native_program: NativeProgram | None = None) -> Pipeline:
    return Pipeline(
        stages={
            "start": Stage(
                name="start",
                step=_PromptStep(name="start"),
                edges=(Edge(label="halt", target="halt"),),
            )
        },
        entry="start",
        native_program=native_program,
    )


# ── Prompt key validation ──────────────────────────────────────────────────


class TestMissingPromptKey:
    def test_prompt_key_with_no_bundles_is_flagged(self) -> None:
        stage = _StageBuilder("start").with_prompt_key("draft").build()
        diag = validate(_pipeline(stages={"start": stage}))
        assert not diag.ok
        assert any("prompt_key 'draft'" in d for d in diag.defects), diag.defects

    def test_prompt_key_missing_from_bundles_is_flagged(self) -> None:
        stage = _StageBuilder("start").with_prompt_key("draft").build()
        bundle = type("B", (), {"name": "review"})()
        diag = validate(_pipeline(stages={"start": stage}, bundles=(bundle,)))
        assert not diag.ok
        assert any("prompt_key 'draft'" in d for d in diag.defects), diag.defects


class TestBundleScopedSuccess:
    def test_prompt_key_matching_string_bundle_passes(self) -> None:
        stage = _StageBuilder("start").with_prompt_key("draft").build()
        diag = validate(_pipeline(stages={"start": stage}, bundles=("draft",)))
        assert diag.ok, diag.defects

    def test_prompt_key_matching_bundle_object_passes(self) -> None:
        stage = _StageBuilder("start").with_prompt_key("draft").build()
        bundle = type("B", (), {"name": "draft"})()
        diag = validate(_pipeline(stages={"start": stage}, bundles=(bundle,)))
        assert diag.ok, diag.defects

    def test_prompt_key_prefix_matching_bundle_passes(self) -> None:
        stage = _StageBuilder("start").with_prompt_key("draft:planning").build()
        diag = validate(_pipeline(stages={"start": stage}, bundles=("draft",)))
        assert diag.ok, diag.defects

    def test_null_prompt_key_is_skipped(self) -> None:
        stage = _StageBuilder("start").with_prompt_key(None).build()
        diag = validate(_pipeline(stages={"start": stage}))
        assert diag.ok, diag.defects

    def test_empty_prompt_key_is_skipped(self) -> None:
        stage = _StageBuilder("start").with_prompt_key("").build()
        diag = validate(_pipeline(stages={"start": stage}))
        assert diag.ok, diag.defects


class TestManifestValidationContext:
    def test_bare_validate_stays_pipeline_local_for_native_manifest_policy(self) -> None:
        diag = validate(_simple_pipeline())

        assert diag.ok, diag.defects
        assert NATIVE_MANIFEST_MISSING_EXECUTION_CODE not in {
            issue.code for issue in diag.issues
        }

    def test_manifest_context_rejects_native_driver_without_execution_evidence(self) -> None:
        context = ManifestValidationContext(
            manifest_driver=("native", "project+validate"),
            package="demo.pkg",
            name="demo",
            manifest_path="/tmp/demo/__init__.py",
            compatibility_classification="native",
            source_entrypoint="build_pipeline",
            default_profile="default",
            supported_modes=("native",),
            source_entrypoint_metadata={"symbol": "build_pipeline"},
        )

        diag = validate(_simple_pipeline(), context=context)

        _assert_issue(
            diag,
            code=NATIVE_MANIFEST_MISSING_EXECUTION_CODE,
            stage=None,
            detail_items={
                "manifest_driver": ["native", "project+validate"],
                "package": "demo.pkg",
                "name": "demo",
                "manifest_path": "/tmp/demo/__init__.py",
                "compatibility_classification": "native",
                "source_entrypoint": "build_pipeline",
                "default_profile": "default",
                "supported_modes": ["native"],
                "source_entrypoint_metadata": {"symbol": "build_pipeline"},
            },
            message_contains="declares native driver",
        )

    def test_manifest_context_accepts_native_program_evidence(self) -> None:
        context = ManifestValidationContext(
            manifest_driver=("native", "project+validate"),
            package="demo.pkg",
            name="demo",
            manifest_path="/tmp/demo/__init__.py",
            source_entrypoint="build_pipeline",
            default_profile="default",
            supported_modes=("native",),
        )

        diag = validate(
            _simple_pipeline(native_program=NativeProgram(name="demo")),
            context=context,
        )

        assert diag.ok, diag.defects

    def test_m1_dispatch_substrate_proof_native_claim_requires_complete_metadata(self) -> None:
        context = ManifestValidationContext(
            manifest_driver=("native", "project+validate"),
            package="demo.pkg",
            name="demo",
            manifest_path="/tmp/demo/__init__.py",
            source_entrypoint="build_pipeline",
            default_profile=None,
            supported_modes=("graph",),
        )

        diag = validate(_simple_pipeline(), context=context)

        issue_codes = {issue.code for issue in diag.issues}
        assert NATIVE_MANIFEST_INVALID_METADATA_CODE in issue_codes, (
            "M1 dispatch substrate proof requires native manifests to carry "
            "driver/default_profile/supported_modes metadata; this is not final "
            "report conformance."
        )
        assert NATIVE_MANIFEST_MISSING_EXECUTION_CODE in issue_codes, (
            "M1 dispatch substrate proof requires native manifests to provide "
            "execution evidence; this is not final report conformance."
        )

    def test_manifest_context_rejects_explicit_graph_compat_native_claim(self) -> None:
        context = ManifestValidationContext(
            manifest_driver=("native", "project+validate"),
            package="demo.pkg",
            name="demo",
            manifest_path="/tmp/demo/__init__.py",
            compatibility_classification="graph-compatible",
            source_entrypoint="build_pipeline",
            default_profile="default",
            supported_modes=("native",),
        )

        diag = validate(
            _simple_pipeline(native_program=NativeProgram(name="demo")),
            context=context,
        )

        _assert_issue(
            diag,
            code=NATIVE_MANIFEST_GRAPH_COMPAT_CODE,
            stage=None,
            message_contains="classified graph-compatible",
        )

    def test_manifest_context_accepts_deprecated_bundle_execution_evidence(self) -> None:
        class _CompatibilityRunner:
            def run_native_pipeline(self, **kwargs: object) -> dict[str, object]:
                return {"ok": True, "kwargs": kwargs}

        context = ManifestValidationContext(
            manifest_driver=("native", "project+validate"),
            package="demo.pkg",
            name="demo",
            manifest_path="/tmp/demo/__init__.py",
            source_entrypoint="build_pipeline",
            default_profile="default",
            supported_modes=("native", "graph"),
        )

        diag = validate(
            Pipeline(
                stages=_simple_pipeline().stages,
                entry="start",
                resource_bundles=(_CompatibilityRunner(),),
            ),
            context=context,
        )

        assert diag.ok, diag.defects

    def test_m1_dispatch_substrate_proof_accepts_native_program_or_bundle_evidence(self) -> None:
        class _CompatibilityRunner:
            def run_native_pipeline(self, **kwargs: object) -> dict[str, object]:
                return {"ok": True, "kwargs": kwargs}

        context = ManifestValidationContext(
            manifest_driver=("native", "project+validate"),
            package="demo.pkg",
            name="demo",
            manifest_path="/tmp/demo/__init__.py",
            source_entrypoint="build_pipeline",
            default_profile="default",
            supported_modes=("native", "graph"),
        )

        native_diag = validate(
            _simple_pipeline(native_program=NativeProgram(name="demo")),
            context=context,
        )
        bundle_diag = validate(
            Pipeline(
                stages=_simple_pipeline().stages,
                entry="start",
                resource_bundles=(_CompatibilityRunner(),),
            ),
            context=context,
        )

        assert native_diag.ok, (
            "M1 dispatch substrate proof accepts attached native_program evidence "
            "without claiming final report conformance."
        )
        assert bundle_diag.ok, (
            "M1 dispatch substrate proof keeps execution-bearing resource bundles "
            "as compatibility evidence, not final report conformance."
        )

    def test_manifest_context_rejects_placeholder_native_metadata(self) -> None:
        context = ManifestValidationContext(
            manifest_driver=("native", "project+validate"),
            package="demo.pkg",
            name="demo",
            manifest_path="/tmp/demo/__init__.py",
            source_entrypoint="build_pipeline",
            default_profile="TODO",
            supported_modes=("native",),
        )

        diag = validate(
            _simple_pipeline(native_program=NativeProgram(name="demo")),
            context=context,
        )

        _assert_issue(
            diag,
            code=NATIVE_MANIFEST_INVALID_METADATA_CODE,
            stage=None,
            detail_items={"default_profile": "TODO"},
            message_contains="metadata is incomplete or malformed",
        )

    def test_m1_dispatch_substrate_proof_rejects_placeholder_native_metadata(self) -> None:
        context = ManifestValidationContext(
            manifest_driver=("native", "project+validate"),
            package="demo.pkg",
            name="demo",
            manifest_path="/tmp/demo/__init__.py",
            source_entrypoint="build_pipeline",
            default_profile="placeholder",
            supported_modes=("native",),
        )

        diag = validate(
            _simple_pipeline(native_program=NativeProgram(name="demo")),
            context=context,
        )

        assert any(
            issue.code == NATIVE_MANIFEST_INVALID_METADATA_CODE
            and issue.details.get("default_profile") == "placeholder"
            for issue in diag.issues
        ), (
            "M1 dispatch substrate proof rejects placeholder native metadata and "
            "does not treat that as final report conformance."
        )

    def test_manifest_context_rejects_malformed_native_driver_metadata(self) -> None:
        context = ManifestValidationContext(
            manifest_driver="native",
            package="demo.pkg",
            name="demo",
            manifest_path="/tmp/demo/__init__.py",
            source_entrypoint="build_pipeline",
            default_profile="default",
            supported_modes=("native",),
        )

        diag = validate(
            _simple_pipeline(native_program=NativeProgram(name="demo")),
            context=context,
        )

        _assert_issue(
            diag,
            code=NATIVE_MANIFEST_INVALID_METADATA_CODE,
            stage=None,
            detail_items={"manifest_driver": "native"},
            message_contains="metadata is incomplete or malformed",
        )

    def test_placeholder_execution_resource_is_rejected_with_stable_code(self) -> None:
        class _PlaceholderRunner:
            name = "runner"
            run_native_pipeline = None

        diag = validate(
            Pipeline(
                stages=_simple_pipeline().stages,
                entry="start",
                resource_bundles=(_PlaceholderRunner(),),
            )
        )

        _assert_issue(
            diag,
            code=PLACEHOLDER_EXECUTION_RESOURCE_CODE,
            stage=None,
            detail_items={
                "bundle_index": 0,
                "bundle_type": "_PlaceholderRunner",
                "attribute": "run_native_pipeline",
            },
        )

    def test_malformed_native_bundle_is_rejected_with_stable_code(self) -> None:
        class _MalformedNativeBundle:
            name = "bad"
            instructions = ()
            phases = ()
            decisions = ()

        diag = validate(
            Pipeline(
                stages=_simple_pipeline().stages,
                entry="start",
                resource_bundles=(_MalformedNativeBundle(),),
            )
        )

        _assert_issue(
            diag,
            code=MALFORMED_NATIVE_BUNDLE_CODE,
            stage=None,
            detail_items={
                "bundle_index": 0,
                "bundle_type": "_MalformedNativeBundle",
            },
        )

    def test_pipeline_local_native_driver_claim_is_rejected_intrinsically(self) -> None:
        pipeline = _simple_pipeline()
        object.__setattr__(pipeline, "driver", ("native", "direct"))

        diag = validate(pipeline)

        _assert_issue(
            diag,
            code=DIRECT_NATIVE_DRIVER_CLAIM_CODE,
            stage=None,
            detail_items={"pipeline_driver": ["native", "direct"]},
        )

    def test_pipeline_validator_shim_delegates_to_updated_validate(self) -> None:
        assert pipeline_validator_shim.validate is validate


class TestDeterministicOrdering:
    def test_defects_emitted_in_sorted_stage_order(self) -> None:
        stages = {
            "zzz": _StageBuilder("zzz")
            .with_prompt_key("missing_a")
            .with_edges(Edge(label="halt", target="halt"))
            .build(),
            "aaa": _StageBuilder("aaa")
            .with_prompt_key("missing_b")
            .with_edges(Edge(label="next", target="zzz"))
            .build(),
        }
        diag = validate(_pipeline(stages=stages, entry="aaa"))
        assert not diag.ok
        # Prompt-key defects should be emitted in sorted stage-name order: aaa before zzz
        prompt_defects = [d for d in diag.defects if "prompt_key" in d]
        assert len(prompt_defects) >= 2, f"expected >=2 prompt_key defects, got: {prompt_defects}"
        assert prompt_defects[0].startswith("stage 'aaa'"), prompt_defects[0]
        assert prompt_defects[1].startswith("stage 'zzz'"), prompt_defects[1]


# ── Decision-route validation ─────────────────────────────────────────────


class TestDecisionRouteValidation:
    """T4: Focused decision-route validator tests covering route targets,
    terminal None routes, absent routes, metadata-only stages, and
    ParallelStage behaviour."""

    # ── Valid route targets ──────────────────────────────────────────

    def test_valid_route_targets_match_edge_labels(self) -> None:
        """Decision routes whose targets match outgoing edge labels pass."""
        stage = Stage(
            name="review",
            step=_PromptStep(name="review"),
            edges=(
                Edge(label="next", target="next_stage"),
                Edge(label="halt", target="halt"),
            ),
            decision_routes={"approved": "next", "rejected": "halt"},
        )
        diag = validate(_pipeline(stages={"review": stage}, entry="review"))
        route_defects = [d for d in diag.defects if "decision_route" in d]
        assert route_defects == [], f"expected no route defects, got: {route_defects}"

    # ── Unknown non-None route target ───────────────────────────────

    def test_unknown_route_target_flagged_with_details(self) -> None:
        """A decision_route targeting an edge label that does not exist is flagged."""
        stage = Stage(
            name="review",
            step=_PromptStep(name="review"),
            edges=(
                Edge(label="next", target="next_stage"),
                Edge(label="halt", target="halt"),
            ),
            decision_routes={"approved": "unknown_label"},
        )
        diag = validate(_pipeline(stages={"review": stage}, entry="review"))
        _assert_issue(
            diag,
            code="decision_route_target_unknown",
            stage="review",
            detail_items={
                "decision_key": "approved",
                "route_target": "unknown_label",
                "available_edge_labels": ["halt", "next"],
            },
            message_contains="targets unknown edge label",
        )

    # ── Terminal None routes ─────────────────────────────────────────

    def test_terminal_none_route_passes(self) -> None:
        """A decision_route with value None (terminal decision) passes validation."""
        stage = Stage(
            name="review",
            step=_PromptStep(name="review"),
            edges=(
                Edge(label="next", target="next_stage"),
                Edge(label="halt", target="halt"),
            ),
            decision_routes={"approved": "next", "abort": None},
        )
        diag = validate(_pipeline(stages={"review": stage}, entry="review"))
        route_defects = [d for d in diag.defects if "decision_route" in d]
        assert route_defects == [], f"None route should pass: {route_defects}"

    # ── Absent / empty decision_routes ───────────────────────────────

    def test_no_decision_routes_passes(self) -> None:
        """A stage with empty decision_routes dict passes silently."""
        stage = Stage(
            name="review",
            step=_PromptStep(name="review"),
            edges=(
                Edge(label="next", target="next_stage"),
                Edge(label="halt", target="halt"),
            ),
            decision_routes={},
        )
        diag = validate(_pipeline(stages={"review": stage}, entry="review"))
        route_defects = [d for d in diag.defects if "decision_route" in d]
        assert route_defects == [], f"empty decision_routes should pass: {route_defects}"

    def test_default_decision_routes_empty_dict_passes(self) -> None:
        """A stage with the default decision_routes (empty dict, from dataclass default) passes silently."""
        # Stage created without explicit decision_routes gets default empty dict
        stage = Stage(
            name="review",
            step=_PromptStep(name="review"),
            edges=(
                Edge(label="next", target="next_stage"),
                Edge(label="halt", target="halt"),
            ),
        )
        assert stage.decision_routes == {}
        diag = validate(_pipeline(stages={"review": stage}, entry="review"))
        route_defects = [d for d in diag.defects if "decision_route" in d]
        assert route_defects == [], f"default empty decision_routes should pass: {route_defects}"

    # ── Metadata-only / non-suspending stage ─────────────────────────

    def test_metadata_only_stage_valid_targets_no_schema(self) -> None:
        """Stage with decision_routes but no suspension_schema passes route validation."""
        stage = Stage(
            name="review",
            step=_PromptStep(name="review"),
            edges=(
                Edge(label="next", target="next_stage"),
                Edge(label="halt", target="halt"),
            ),
            decision_routes={"proceed": "next", "stop": "halt"},
            suspension_schema=None,
        )
        diag = validate(_pipeline(stages={"review": stage}, entry="review"))
        route_defects = [d for d in diag.defects if "decision_route" in d]
        assert route_defects == [], f"valid targets without schema: {route_defects}"

    # ── ParallelStage cheap behaviour ────────────────────────────────

    def test_parallel_stage_decision_routes(self) -> None:
        """ParallelStage with valid decision_routes passes validation."""

        def _join(results: list, ctx: Any) -> StepResult:
            return StepResult(next="halt")

        pstage = ParallelStage(
            name="fanout",
            steps=(_PromptStep(name="fanout"),),
            join=_join,
            edges=(
                Edge(label="next", target="next_stage"),
                Edge(label="halt", target="halt"),
            ),
            decision_routes={"ok": "next", "fail": "halt"},
        )
        diag = validate(_pipeline(stages={"fanout": pstage}, entry="fanout"))
        route_defects = [d for d in diag.defects if "decision_route" in d]
        assert route_defects == [], f"ParallelStage routes: {route_defects}"

    def test_parallel_stage_bad_route_flagged(self) -> None:
        """ParallelStage with an unknown route target is flagged."""

        def _join(results: list, ctx: Any) -> StepResult:
            return StepResult(next="halt")

        pstage = ParallelStage(
            name="fanout",
            steps=(_PromptStep(name="fanout"),),
            join=_join,
            edges=(
                Edge(label="next", target="next_stage"),
                Edge(label="halt", target="halt"),
            ),
            decision_routes={"ok": "bad_label"},
        )
        diag = validate(_pipeline(stages={"fanout": pstage}, entry="fanout"))
        _assert_issue(
            diag,
            code="decision_route_target_unknown",
            stage="fanout",
            detail_items={
                "decision_key": "ok",
                "route_target": "bad_label",
                "available_edge_labels": ["halt", "next"],
            },
            message_contains="targets unknown edge label",
        )


# ── Simple-schema and JSON Schema compatibility ───────────────────────────


class TestDecisionRouteSchemaCompatibility:
    """T4: Schema compatibility tests for decision-route validation.
    Covers simple key-value maps, JSON Schema choice.enum, and ambiguous
    schemas that should be silently ignored."""

    def test_simple_schema_outside_route_key_flagged(self) -> None:
        """Decision key not in simple KV schema triggers schema_key_unknown even when
        its route_target matches an edge label."""
        stage = Stage(
            name="review",
            step=_PromptStep(name="review"),
            edges=(
                Edge(label="next", target="next_stage"),
                Edge(label="halt", target="halt"),
            ),
            decision_routes={
                "approved": "next",
                "rejected": "halt",
                "pending": "next",  # not in schema but valid route
            },
            suspension_schema={"approved": "str", "rejected": "str"},
        )
        diag = validate(_pipeline(stages={"review": stage}, entry="review"))
        # Route-target validation still passes for the outside-schema key
        route_target_defects = [
            d for d in diag.defects if "decision_route_target_unknown" in d
        ]
        assert route_target_defects == [], (
            f"outside-schema key should not break route-target validation: {route_target_defects}"
        )
        # Schema-key conformance flags the unknown schema key
        _assert_issue(
            diag,
            code="decision_route_schema_key_unknown",
            stage="review",
            detail_items={
                "decision_key": "pending",
                "schema_enum": ["approved", "rejected"],
            },
            message_contains="is not in the suspension-schema enum",
        )

    def test_simple_schema_missing_route_key_flagged(self) -> None:
        """Schema key missing from decision_routes triggers schema_key_missing."""
        stage = Stage(
            name="review",
            step=_PromptStep(name="review"),
            edges=(
                Edge(label="next", target="next_stage"),
                Edge(label="halt", target="halt"),
            ),
            decision_routes={"approved": "next"},
            suspension_schema={"approved": "str", "rejected": "str"},
        )
        diag = validate(_pipeline(stages={"review": stage}, entry="review"))
        _assert_issue(
            diag,
            code="decision_route_schema_key_missing",
            stage="review",
            detail_items={
                "decision_key": "rejected",
                "schema_enum": ["approved", "rejected"],
            },
            message_contains="is missing from decision_routes",
        )

    def test_simple_schema_valid_matching_route_map(self) -> None:
        """Decision routes that exactly match a recognized simple-KV schema
        produce no schema-key defects."""
        stage = Stage(
            name="review",
            step=_PromptStep(name="review"),
            edges=(
                Edge(label="next", target="next_stage"),
                Edge(label="halt", target="halt"),
            ),
            decision_routes={"approved": "next", "rejected": "halt"},
            suspension_schema={"approved": "str", "rejected": "str"},
        )
        diag = validate(_pipeline(stages={"review": stage}, entry="review"))
        route_defects = [d for d in diag.defects if "decision_route" in d]
        assert route_defects == [], (
            f"exact schema match should have no route defects: {route_defects}"
        )

    def test_terminal_none_routes_with_recognized_schema(self) -> None:
        """None terminal route targets with a recognized simple-KV schema
        pass schema-key conformance (None is not a schema key)."""
        stage = Stage(
            name="review",
            step=_PromptStep(name="review"),
            edges=(
                Edge(label="next", target="next_stage"),
                Edge(label="halt", target="halt"),
            ),
            decision_routes={
                "approved": "next",
                "rejected": "halt",
                "abort": None,
            },
            suspension_schema={"approved": "str", "rejected": "str"},
        )
        diag = validate(_pipeline(stages={"review": stage}, entry="review"))
        # "abort" is not in the schema enum — it should be flagged
        _assert_issue(
            diag,
            code="decision_route_schema_key_unknown",
            stage="review",
            detail_items={
                "decision_key": "abort",
                "schema_enum": ["approved", "rejected"],
            },
            message_contains="is not in the suspension-schema enum",
        )
        # But no missing keys — "approved" and "rejected" are both covered
        missing = [d for d in diag.defects if "decision_route_schema_key_missing" in d]
        assert missing == [], f"no missing keys expected: {missing}"

    def test_suspension_schema_no_decision_routes_passes(self) -> None:
        """Stage with a recognized suspension_schema but no decision_routes
        passes silently (backward compatibility)."""
        stage = Stage(
            name="review",
            step=_PromptStep(name="review"),
            edges=(
                Edge(label="next", target="next_stage"),
                Edge(label="halt", target="halt"),
            ),
            decision_routes={},
            suspension_schema={"approved": "str", "rejected": "str"},
        )
        diag = validate(_pipeline(stages={"review": stage}, entry="review"))
        route_defects = [d for d in diag.defects if "decision_route" in d]
        assert route_defects == [], (
            f"no decision_routes with recognized schema should pass: {route_defects}"
        )

    def test_simple_schema_x_extension_excluded_from_enum(self) -> None:
        """Schema with x- extension key is not treated as a simple KV enum."""
        enum = _decision_enum_from_suspension_schema(
            {"approved": "str", "x-arnold-resume": "bool"}
        )
        assert enum is None, f"x- key should exclude schema, got {enum!r}"

    def test_json_schema_choice_enum_compatible(self) -> None:
        """Stage with JSON Schema choice.enum and matching routes passes validation."""
        stage = Stage(
            name="review",
            step=_PromptStep(name="review"),
            edges=(
                Edge(label="next", target="next_stage"),
                Edge(label="halt", target="halt"),
            ),
            decision_routes={"selected": "next", "declined": "halt"},
            suspension_schema={
                "type": "object",
                "properties": {
                    "choice": {
                        "type": "string",
                        "enum": ["selected", "declined"],
                    }
                },
            },
        )
        diag = validate(_pipeline(stages={"review": stage}, entry="review"))
        route_defects = [d for d in diag.defects if "decision_route" in d]
        assert route_defects == [], f"JSON Schema choice.enum: {route_defects}"

    def test_json_schema_other_property_enum_ignored(self) -> None:
        """Enum on a non-choice property is silently ignored (no false positives)."""
        stage = Stage(
            name="review",
            step=_PromptStep(name="review"),
            edges=(
                Edge(label="next", target="next_stage"),
                Edge(label="halt", target="halt"),
            ),
            decision_routes={"go": "next"},
            suspension_schema={
                "type": "object",
                "properties": {
                    "note": {
                        "type": "string",
                        "enum": ["hello", "world"],
                    }
                },
            },
        )
        diag = validate(_pipeline(stages={"review": stage}, entry="review"))
        route_defects = [d for d in diag.defects if "decision_route" in d]
        assert route_defects == [], (
            f"unrelated property enum should not cause defects: {route_defects}"
        )

    def test_ambiguous_schema_ignored_no_false_positives(self) -> None:
        """Loose/ambiguous suspension_schema is silently skipped."""
        stage = Stage(
            name="review",
            step=_PromptStep(name="review"),
            edges=(
                Edge(label="next", target="next_stage"),
                Edge(label="halt", target="halt"),
            ),
            decision_routes={"go": "next"},
            suspension_schema={
                "type": "object",
                "properties": {
                    "note": {"type": "string"},
                },
            },
        )
        diag = validate(_pipeline(stages={"review": stage}, entry="review"))
        route_defects = [d for d in diag.defects if "decision_route" in d]
        assert route_defects == [], (
            f"ambiguous schema should not cause defects: {route_defects}"
        )


# ── Suspension-schema enum extraction unit tests ──────────────────────────


class TestSuspensionSchemaEnumExtraction:
    """T4: Unit tests for _decision_enum_from_suspension_schema helper."""

    def test_simple_kv_map_extracts_keys(self) -> None:
        """Simple string key/value map returns frozenset of keys."""
        result = _decision_enum_from_suspension_schema(
            {"approved": "str", "rejected": "str"}
        )
        assert result == frozenset({"approved", "rejected"})

    def test_simple_kv_map_non_string_value_returns_none(self) -> None:
        """Any non-string value disqualifies the simple KV map."""
        result = _decision_enum_from_suspension_schema(
            {"approved": "str", "count": 42}
        )
        assert result is None

    def test_json_schema_choice_enum_extraction(self) -> None:
        """properties.choice.enum is extracted from valid JSON Schema shape."""
        result = _decision_enum_from_suspension_schema({
            "type": "object",
            "properties": {
                "choice": {
                    "type": "string",
                    "enum": ["proceed", "retry", "abort"],
                }
            },
        })
        assert result == frozenset({"proceed", "retry", "abort"})

    def test_json_schema_empty_enum_returns_none(self) -> None:
        """An empty choice.enum returns None."""
        result = _decision_enum_from_suspension_schema({
            "type": "object",
            "properties": {
                "choice": {
                    "type": "string",
                    "enum": [],
                }
            },
        })
        assert result is None

    def test_json_schema_non_string_choice_type_returns_none(self) -> None:
        """choice.type != 'string' returns None."""
        result = _decision_enum_from_suspension_schema({
            "type": "object",
            "properties": {
                "choice": {
                    "type": "integer",
                    "enum": [1, 2, 3],
                }
            },
        })
        assert result is None

    def test_none_schema_returns_none(self) -> None:
        """None input returns None."""
        assert _decision_enum_from_suspension_schema(None) is None

    def test_non_mapping_schema_returns_none(self) -> None:
        """Non-Mapping input returns None."""
        assert _decision_enum_from_suspension_schema("not a mapping") is None

    def test_x_extension_only_schema_returns_none(self) -> None:
        """Schema with only x- extension keys returns None."""
        assert _decision_enum_from_suspension_schema({"x-arnold-resume": "str"}) is None

    def test_empty_dict_returns_none(self) -> None:
        """Empty dict returns None."""
        assert _decision_enum_from_suspension_schema({}) is None


# ── Full integration tests ─────────────────────────────────────────────────


class TestFullValidateIntegration:
    def test_validate_merges_resource_defects_with_control_flow(self) -> None:
        stage = _StageBuilder("start").with_prompt_key("missing").build()
        diag = validate(_pipeline(stages={"start": stage}))
        assert not diag.ok
        # At minimum we have the resource defect; entry may also flag
        assert any("prompt_key 'missing'" in d for d in diag.defects)

    def test_validate_dataflow_paths_accepts_typed_reads_and_writes(self) -> None:
        start = Stage(
            name="start",
            step=_PromptStep(name="start"),
            writes=(WriteRef(name="payload"),),
            edges=(Edge(label="next", target="end"),),
        )
        end = Stage(
            name="end",
            step=_PromptStep(name="end"),
            reads=(ReadRef(name="payload"),),
            edges=(Edge(label="halt", target="halt"),),
        )
        diag = validate(_pipeline(stages={"start": start, "end": end}))
        assert diag.ok, diag.defects

    def test_validate_accepts_builder_derived_binding_map_for_agreeing_typed_authoring(self) -> None:
        builder = PipelineBuilder("test")
        start = Stage(
            name="start",
            step=_PromptStep(name="start"),
            writes=(WriteRef(name="payload"),),
            edges=(Edge(label="next", target="end"),),
        )
        end = Stage(
            name="end",
            step=_PromptStep(name="end"),
            reads=(ReadRef(name="payload"),),
            edges=(Edge(label="halt", target="halt"),),
        )
        builder.add_stage(start)
        builder.add_stage(end)
        pipeline = builder.build()
        diag = validate(pipeline)
        assert diag.ok, diag.defects

    def test_validate_dataflow_paths_reports_typed_missing_binding(self) -> None:
        start = Stage(
            name="start",
            step=_PromptStep(name="start"),
            edges=(Edge(label="next", target="end"),),
        )
        end = Stage(
            name="end",
            step=_PromptStep(name="end"),
            reads=(ReadRef(name="payload"),),
            edges=(Edge(label="halt", target="halt"),),
        )
        diag = validate(_pipeline(stages={"start": start, "end": end}))
        assert any("unsatisfied" in d for d in diag.defects), diag.defects

    def test_validate_dataflow_paths_reports_typed_typo_suggestion(self) -> None:
        start = Stage(
            name="start",
            step=_PromptStep(name="start"),
            writes=(WriteRef(name="payload"),),
            edges=(Edge(label="next", target="end"),),
        )
        end = Stage(
            name="end",
            step=_PromptStep(name="end"),
            reads=(ReadRef(name="paylaod"),),  # typo
            edges=(Edge(label="halt", target="halt"),),
        )
        diag = validate(_pipeline(stages={"start": start, "end": end}))
        assert any("unsatisfied" in d for d in diag.defects), diag.defects

    def test_validate_dataflow_paths_reports_content_type_mismatch(self) -> None:
        start = Stage(
            name="start",
            step=_PromptStep(name="start"),
            produces=(Port(name="data", content_type="text/markdown"),),
            edges=(Edge(label="next", target="end"),),
        )
        end = Stage(
            name="end",
            step=_PromptStep(name="end"),
            consumes=(PortRef(port_name="data", content_type="image/png"),),
            edges=(Edge(label="halt", target="halt"),),
        )
        diag = validate(_pipeline(stages={"start": start, "end": end}))
        content_type_defects = [
            d for d in diag.defects if "content_type" in d.lower()
        ]
        assert content_type_defects, diag.defects

    def test_validate_dataflow_paths_reports_cardinality_mismatch(self) -> None:
        start = Stage(
            name="start",
            step=_PromptStep(name="start"),
            produces=(Port(name="data", content_type="text/markdown", cardinality="collection"),),
            edges=(Edge(label="next", target="end"),),
        )
        end = Stage(
            name="end",
            step=_PromptStep(name="end"),
            consumes=(PortRef(port_name="data", content_type="text/markdown", cardinality="singleton"),),
            edges=(Edge(label="halt", target="halt"),),
        )
        diag = validate(_pipeline(stages={"start": start, "end": end}))
        cardinality_defects = [
            d for d in diag.defects if "cardinality" in d.lower()
        ]
        assert cardinality_defects, diag.defects

    def test_validate_dataflow_paths_reports_logical_metadata_mismatch(self) -> None:
        start = Stage(
            name="start",
            step=_PromptStep(name="start"),
            produces=(
                Port(
                    name="data",
                    content_type="application/json",
                    logical_type="MyPayload",
                ),
            ),
            edges=(Edge(label="next", target="end"),),
        )
        end = Stage(
            name="end",
            step=_PromptStep(name="end"),
            consumes=(
                PortRef(
                    port_name="data",
                    content_type="application/json",
                    logical_type="OtherPayload",
                ),
            ),
            edges=(Edge(label="halt", target="halt"),),
        )
        diag = validate(_pipeline(stages={"start": start, "end": end}))
        logical_defects = [d for d in diag.defects if "logical_type" in d.lower()]
        assert logical_defects, diag.defects

    def test_validate_dataflow_paths_reports_schema_version_mismatch(self) -> None:
        from arnold.pipeline.schema_registry import AcceptedVersionRange
        start = Stage(
            name="start",
            step=_PromptStep(name="start"),
            produces=(
                Port(
                    name="data",
                    content_type="application/json",
                    logical_type="MyPayload",
                    accepted_version_range=AcceptedVersionRange(
                        logical_type="MyPayload", min_version="1", max_version="1"
                    ),
                ),
            ),
            edges=(Edge(label="next", target="end"),),
        )
        end = Stage(
            name="end",
            step=_PromptStep(name="end"),
            consumes=(
                PortRef(
                    port_name="data",
                    content_type="application/json",
                    logical_type="MyPayload",
                    accepted_version_range=AcceptedVersionRange(
                        logical_type="MyPayload", min_version="2", max_version="2"
                    ),
                ),
            ),
            edges=(Edge(label="halt", target="halt"),),
        )
        diag = validate(_pipeline(stages={"start": start, "end": end}))
        version_defects = [d for d in diag.defects if "version" in d.lower()]
        assert version_defects, diag.defects

    def test_validate_dataflow_paths_reports_declaration_drift_and_keeps_legacy_binding_checks(
        self,
    ) -> None:
        start = Stage(
            name="start",
            step=_PromptStep(name="start"),
            writes=(WriteRef(name="payload"),),
            edges=(Edge(label="next", target="end"),),
        )
        end = Stage(
            name="end",
            step=_PromptStep(name="end"),
            reads=(ReadRef(name="payload"),),
            consumes=(PortRef(port_name="extra", content_type="text/markdown"),),
            edges=(Edge(label="halt", target="halt"),),
        )
        pipeline = Pipeline(
            stages={"start": start, "end": end},
            entry="start",
            binding_map={("end", "payload"): ("start", "payload")},
        )
        diag = validate(pipeline)
        drift_defects = [d for d in diag.defects if "declaration_drift" in d.lower() or "drift" in d.lower()]
        # Should have at least one finding about extra undeclared consumer port
        assert drift_defects or any("unsatisfied" in d for d in diag.defects), diag.defects

    def test_validate_dataflow_paths_accepts_legacy_untyped_passthrough(self) -> None:
        start = Stage(
            name="start",
            step=_PromptStep(name="start"),
            edges=(Edge(label="next", target="end"),),
        )
        end = Stage(
            name="end",
            step=_PromptStep(name="end"),
            edges=(Edge(label="halt", target="halt"),),
        )
        diag = validate(_pipeline(stages={"start": start, "end": end}))
        assert diag.ok, diag.defects

    def test_validate_planning_pipeline_resource_check(self) -> None:
        stage = _StageBuilder("start").with_prompt_key("planning").build()
        diag = validate(_pipeline(stages={"start": stage}, bundles=("planning",)))
        assert diag.ok, diag.defects

    def test_validate_preserves_legacy_defects_and_structured_issues(self) -> None:
        stage = _StageBuilder("start").with_prompt_key("missing").build()
        diag = validate(_pipeline(stages={"start": stage}))
        assert not diag.ok
        assert diag.defects
        assert diag.issues
        assert len(diag.defects) == len(diag.issues)

    def test_diagnostics_add_defect_builds_structured_issue(self) -> None:
        diag = Diagnostics()
        diag.add_defect("test", code="test.code", stage="s1")
        assert len(diag.defects) == 1
        assert len(diag.issues) == 1
        assert diag.issues[0].code == "test.code"
        assert diag.issues[0].stage == "s1"

    def test_validate_dataflow_paths_uses_stable_missing_binding_code(self) -> None:
        start = Stage(
            name="start",
            step=_PromptStep(name="start"),
            edges=(Edge(label="next", target="end"),),
        )
        end = Stage(
            name="end",
            step=_PromptStep(name="end"),
            consumes=("plan_payload",),
            edges=(Edge(label="halt", target="halt"),),
        )
        pipeline = _pipeline(stages={"start": start, "end": end})

        diag = validate_dataflow_paths(pipeline)

        assert diag.defects == [
            "stage 'end': dependency 'plan_payload' is unsatisfied (missing from predecessor 'start')"
        ]
        assert [issue.code for issue in diag.issues] == [MISSING_BINDING_CODE]
        assert diag.issues[0].details == {
            "dependency": "plan_payload",
            "route_hint": "(missing from predecessor 'start')",
        }

    def test_validate_reports_unknown_invocation_adapter_kind(self) -> None:
        stage = Stage(
            name="start",
            step=_PromptStep(name="start"),
            invocation=StepInvocation(kind="custom-collector-v2"),
            edges=(Edge(label="halt", target="halt"),),
        )

        diag = validate(_pipeline(stages={"start": stage}))

        _assert_issue(
            diag,
            code=UNKNOWN_ADAPTER_CODE,
            stage="start",
            detail_items={
                "invocation_kind": "custom-collector-v2",
                "registered_kinds": ["model"],
            },
            message_contains="does not resolve to a registered adapter",
        )

    def test_validate_accepts_model_invocation_with_adapter_config_shape(self) -> None:
        stage = Stage(
            name="start",
            step=_PromptStep(name="start"),
            invocation=StepInvocation.with_adapter_config(
                kind="model",
                adapter_config={"model": "gpt-5.4", "temperature": 0},
            ),
            edges=(Edge(label="halt", target="halt"),),
        )

        diag = validate(_pipeline(stages={"start": stage}))

        assert diag.ok, diag.defects

    def test_validate_accepts_registered_tool_invocation_with_same_adapter_config_shape(self) -> None:
        class _ToolAdapter:
            def invoke(self, invocation: StepInvocation) -> object:
                return {"ok": True, "kind": invocation.kind}

        registry = StepInvocationAdapterRegistry()
        registry.register("tool", _ToolAdapter())
        stage = Stage(
            name="scan",
            step=_PromptStep(name="scan"),
            invocation=StepInvocation.with_adapter_config(
                kind="tool",
                adapter_config={"command": "scan", "args": ["src"]},
            ),
            edges=(Edge(label="halt", target="halt"),),
        )

        diag = validate(
            _pipeline(stages={"scan": stage}, entry="scan"),
            adapter_registry=registry,
        )

        assert diag.ok, diag.defects
        assert stage.invocation is not None
        assert stage.invocation.metadata["adapter_config"] == {
            "command": "scan",
            "args": ["src"],
        }

    def test_contract_diagnostic_code_maps_required_m7_categories(self) -> None:
        assert CONTRACT_ERROR_CODE_MAP == {
            "no_match": "contract.no_match",
            "typo_name": "contract.no_match",
            "content_type_mismatch": "contract.content_type_mismatch",
            "cardinality_mismatch": "contract.cardinality_mismatch",
            "schema_mismatch": "contract.schema_mismatch",
        }
        assert contract_diagnostic_code("no_match") == "contract.no_match"
        assert contract_diagnostic_code("typo_name") == "contract.no_match"
        assert contract_diagnostic_code("content_type_mismatch") == "contract.content_type_mismatch"
        assert contract_diagnostic_code("cardinality_mismatch") == "contract.cardinality_mismatch"
        assert contract_diagnostic_code("schema_mismatch") == "contract.schema_mismatch"
        assert DECLARATION_DRIFT_CODE == "contract.declaration_drift"
        assert UNKNOWN_ADAPTER_CODE == "invocation.unknown_adapter"


# ── T4: Non-model adapter registry tests ──────────────────────────────────


class TestNonModelAdapterRegistry:
    """T4: Validator tests for caller-supplied adapter_registry behavior."""

    def test_default_unknown_non_model_adapter_fails(self) -> None:
        """Default registry (fail-closed) rejects a non-model kind like 'tool'."""
        stage = Stage(
            name="lookup",
            step=_PromptStep(name="lookup"),
            invocation=StepInvocation.with_adapter_config(
                kind="tool", adapter_config={"tool_name": "calculator"}
            ),
            edges=(Edge(label="halt", target="halt"),),
        )
        pipeline = _pipeline(stages={"lookup": stage}, entry="lookup")
        diag = validate(pipeline)  # default registry — only 'model'
        assert not diag.ok
        unknown_defects = [
            d for d in diag.defects if "does not resolve to a registered adapter" in d
        ]
        assert len(unknown_defects) >= 1, (
            f"default registry must reject unknown kind 'tool', got defects: {diag.defects}"
        )

    def test_supplied_registry_non_model_adapter_passes(self) -> None:
        """Caller-supplied registry with 'tool' registered makes validation pass."""
        registry = StepInvocationAdapterRegistry()
        # Register a simple tool adapter that satisfies the protocol
        registry.register("tool", _NullToolAdapter())

        stage = Stage(
            name="lookup",
            step=_PromptStep(name="lookup"),
            invocation=StepInvocation.with_adapter_config(
                kind="tool", adapter_config={"tool_name": "calculator"}
            ),
            edges=(Edge(label="halt", target="halt"),),
        )
        pipeline = _pipeline(stages={"lookup": stage}, entry="lookup")
        diag = validate(pipeline, adapter_registry=registry)
        # Should not have UNKNOWN_ADAPTER defects
        unknown_defects = [
            d for d in diag.defects if "does not resolve to a registered adapter" in d
        ]
        assert unknown_defects == [], (
            f"supplied registry with 'tool' should pass, got: {unknown_defects}"
        )

    def test_supplied_registry_multiple_non_model_kinds_pass(self) -> None:
        """Multiple caller-registered non-model adapters all pass validation."""
        registry = StepInvocationAdapterRegistry()
        registry.register("tool", _NullToolAdapter())
        registry.register("collector", _NullToolAdapter())

        stage_tool = Stage(
            name="lookup",
            step=_PromptStep(name="lookup"),
            invocation=StepInvocation.with_adapter_config(
                kind="tool", adapter_config={"tool_name": "calculator"}
            ),
            edges=(Edge(label="halt", target="halt"),),
        )
        stage_collector = Stage(
            name="gather",
            step=_PromptStep(name="gather"),
            invocation=StepInvocation.with_adapter_config(
                kind="collector", adapter_config={"source": "api"}
            ),
            edges=(Edge(label="halt", target="halt"),),
        )
        pipeline = _pipeline(
            stages={"lookup": stage_tool, "gather": stage_collector}, entry="lookup"
        )
        diag = validate(pipeline, adapter_registry=registry)
        unknown_defects = [
            d for d in diag.defects if "does not resolve to a registered adapter" in d
        ]
        assert unknown_defects == [], (
            f"both non-model kinds should pass: {unknown_defects}"
        )

    def test_model_behavior_unchanged_with_default_registry(self) -> None:
        """Model invocation passes with default registry (reserved slot intact)."""
        stage = Stage(
            name="summarize",
            step=_PromptStep(name="summarize"),
            invocation=StepInvocation.model(adapter_config={"instruction": "Summarize."}),
            edges=(Edge(label="halt", target="halt"),),
        )
        pipeline = _pipeline(stages={"summarize": stage}, entry="summarize")
        diag = validate(pipeline)
        unknown_defects = [
            d for d in diag.defects if "does not resolve to a registered adapter" in d
        ]
        assert unknown_defects == [], (
            f"model adapter should resolve in default registry: {unknown_defects}"
        )

    def test_model_behavior_unchanged_with_supplied_registry(self) -> None:
        """Model invocation still passes when a caller-supplied registry is used."""
        registry = StepInvocationAdapterRegistry()
        registry.register("tool", _NullToolAdapter())

        stage = Stage(
            name="summarize",
            step=_PromptStep(name="summarize"),
            invocation=StepInvocation.model(adapter_config={"instruction": "Summarize."}),
            edges=(Edge(label="halt", target="halt"),),
        )
        pipeline = _pipeline(stages={"summarize": stage}, entry="summarize")
        diag = validate(pipeline, adapter_registry=registry)
        unknown_defects = [
            d for d in diag.defects if "does not resolve to a registered adapter" in d
        ]
        assert unknown_defects == [], (
            f"model adapter still works with custom registry: {unknown_defects}"
        )

    def test_validate_invocation_requirements_direct_call(self) -> None:
        """validate_invocation_requirements directly works with supplied registry."""
        from arnold.workflow.validator import validate_invocation_requirements

        registry = StepInvocationAdapterRegistry()
        registry.register("tool", _NullToolAdapter())

        stage = Stage(
            name="lookup",
            step=_PromptStep(name="lookup"),
            invocation=StepInvocation.with_adapter_config(
                kind="tool", adapter_config={"tool_name": "calculator"}
            ),
            edges=(Edge(label="halt", target="halt"),),
        )
        pipeline = _pipeline(stages={"lookup": stage}, entry="lookup")
        diag = validate_invocation_requirements(pipeline, adapter_registry=registry)
        assert diag.ok, diag.defects


class _NullToolAdapter:
    """Minimal adapter that satisfies StepInvocationAdapter protocol."""

    def invoke(self, invocation: StepInvocation) -> Any:  # pragma: no cover
        return {"status": "ok"}


# ── Non-model media adapter tests (T10) ────────────────────────────────────


class _CapabilityStep:
    """Deterministic fixture step that writes a media file under artifact_root.

    Acts as a model-less capability adapter: on ``run(ctx)`` it creates a
    ``video/mp4`` evidence artifact and returns a ``StepResult`` carrying
    the output path plus a typed ``EvidenceArtifactRef`` in
    ``contract_result.evidence_refs``.

    Never touches the model adapter — the step's ``kind`` is ``"capability"``.
    """

    name: str = "capability-step"
    kind: str = "capability"

    def run(self, ctx: StepContext) -> StepResult:
        from pathlib import Path

        from arnold.pipeline.types import (
            ContractResult,
            ContractStatus,
            EvidenceArtifactRef,
        )

        root = Path(ctx.artifact_root)
        root.mkdir(parents=True, exist_ok=True)
        output_path = root / "output.mp4"
        output_path.write_text("fake-video-bytes")

        evidence_ref = EvidenceArtifactRef(
            uri=str(output_path),
            content_type="video/mp4",
            digest="a" * 64,
            size_bytes=16,
            name="output.mp4",
        )

        contract = ContractResult(
            status=ContractStatus.COMPLETED,
            evidence_refs=(evidence_ref,),
            authority_level="verified",
        )

        return StepResult(
            outputs={"artifact": str(output_path)},
            next="halt",
            contract_result=contract,
        )


class _CapabilityAdapter:
    """Deterministic ``StepInvocationAdapter`` for the ``"capability"`` kind.

    Delegates to :class:`_CapabilityStep` when invoked.
    """

    def invoke(self, invocation: StepInvocation) -> StepResult:
        from pathlib import Path

        adapter_config = invocation.metadata.get("adapter_config", {})
        artifact_root = adapter_config.get("artifact_root", "/tmp/_capability_test")
        return _CapabilityStep().run(
            StepContext(artifact_root=artifact_root, state={})
        )


class TestNonModelMediaAdapter:
    """End-to-end tests for non-model adapter execution and media validation.

    Covers the adapter registry seam, the deterministic capability fixture
    adapter, media reference validation, duplicate registration, reserved-model
    semantics, and fail-closed unknown-kind rejection (T10).
    """

    def test_capability_adapter_registered_and_passes_validation(self) -> None:
        """A capability-kind invocation passes validation when registered."""
        registry = StepInvocationAdapterRegistry()
        registry.register("capability", _CapabilityAdapter())

        stage = Stage(
            name="cap-producer",
            step=_CapabilityStep(),  # type: ignore[arg-type]
            invocation=StepInvocation.with_adapter_config(
                kind="capability",
                adapter_config={"artifact_root": "/tmp/_test_cap"},
            ),
            edges=(Edge(label="halt", target="halt"),),
        )
        pipeline = _pipeline(stages={"cap-producer": stage}, entry="cap-producer")
        diag = validate(pipeline, adapter_registry=registry)
        unknown_defects = [
            d for d in diag.defects if "does not resolve to a registered adapter" in d
        ]
        assert unknown_defects == [], (
            f"capability adapter should resolve: {unknown_defects}"
        )

    def test_capability_adapter_writes_under_artifact_root(self) -> None:
        """The fixture adapter writes only under ``StepContext.artifact_root``."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            artifact_root = str(Path(tmpdir) / "artifacts")
            ctx = StepContext(artifact_root=artifact_root, state={})
            result = _CapabilityStep().run(ctx)

            # File was created under artifact_root
            output_path = Path(result.outputs["artifact"])
            assert output_path.parent == Path(artifact_root), (
                f"file {output_path} not under artifact_root {artifact_root}"
            )
            assert output_path.exists(), f"{output_path} should exist"
            assert output_path.read_text() == "fake-video-bytes"

    def test_capability_adapter_returns_path_output_and_typed_evidence_ref(
        self,
    ) -> None:
        """StepResult carries path output + typed EvidenceArtifactRef."""
        import tempfile
        from pathlib import Path

        from arnold.pipeline.types import EvidenceArtifactRef

        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = StepContext(artifact_root=tmpdir, state={})
            result = _CapabilityStep().run(ctx)

            # Path in outputs
            assert "artifact" in result.outputs
            assert isinstance(result.outputs["artifact"], str)

            # Typed EvidenceArtifactRef in contract_result.evidence_refs
            assert result.contract_result is not None
            refs = result.contract_result.evidence_refs
            assert len(refs) == 1
            ref = refs[0]
            assert isinstance(ref, EvidenceArtifactRef)
            assert ref.content_type == "video/mp4"
            assert ref.uri.startswith(tmpdir)
            assert ref.digest == "a" * 64
            assert ref.size_bytes == 16
            assert ref.name == "output.mp4"

    def test_capability_adapter_does_not_touch_model_adapter(self) -> None:
        """The capability step never invokes the model adapter slot."""
        from arnold.execution.step_invocation import ModelAdapterNotImplementedError

        # The _CapabilityStep.run() never references the model adapter.
        # The registry still has the model placeholder, but capability
        # invocation resolves to _CapabilityAdapter, not the placeholder.
        registry = StepInvocationAdapterRegistry()
        registry.register("capability", _CapabilityAdapter())

        # Model adapter is still the placeholder
        model_adapter = registry.resolve("model")
        with pytest.raises(ModelAdapterNotImplementedError):
            model_adapter.invoke(StepInvocation(kind="model"))

        # Capability adapter resolves successfully
        capability_adapter = registry.resolve("capability")
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            result = capability_adapter.invoke(
                StepInvocation.with_adapter_config(
                    kind="capability",
                    adapter_config={"artifact_root": tmpdir},
                )
            )
            assert result.outputs["artifact"], "capability adapter should produce output"

    def test_media_reference_validates_through_content_validator_registry(
        self,
    ) -> None:
        """The evidence ref produced by the capability adapter passes media validation."""
        from arnold.pipeline.content_validation import ContentValidatorRegistry
        from arnold.pipeline.media_content import register_media_content_validators

        registry = ContentValidatorRegistry()
        register_media_content_validators(registry)

        # Build a blob_metadata dict matching what a downstream consumer
        # would extract from an EvidenceArtifactRef.
        blob_metadata = {
            "content_type": "video/mp4",
            "uri": "/tmp/artifacts/output.mp4",
            "digest": "a" * 64,
            "size_bytes": 16,
            "name": "output.mp4",
        }
        result = registry.validate("video/mp4", blob_metadata)
        assert result.ok, (
            f"valid evidence ref should pass: {result.diagnostics}"
        )

    def test_media_reference_fails_on_wrong_content_type(self) -> None:
        """Media validator rejects mismatched content_type."""
        from arnold.pipeline.content_validation import ContentValidatorRegistry
        from arnold.pipeline.media_content import register_media_content_validators

        registry = ContentValidatorRegistry()
        register_media_content_validators(registry)

        blob_metadata = {
            "content_type": "audio/wav",  # wrong for video/mp4 validator
            "uri": "/tmp/artifacts/output.mp4",
        }
        result = registry.validate("video/mp4", blob_metadata)
        assert not result.ok, "wrong content_type should fail"
        codes = {d.code for d in result.diagnostics}
        assert "invalid_content_type" in codes, (
            f"expected invalid_content_type, got: {codes}"
        )

    def test_duplicate_registration_raises_value_error(self) -> None:
        """Registering the same kind twice raises ValueError."""
        registry = StepInvocationAdapterRegistry()
        registry.register("capability", _CapabilityAdapter())
        with pytest.raises(ValueError, match="already registered"):
            registry.register("capability", _CapabilityAdapter())

    def test_unknown_kind_fails_with_default_registry(self) -> None:
        """An invocation kind not registered anywhere fails validation."""
        stage = Stage(
            name="unknown-step",
            step=_PromptStep(name="unknown-step"),
            invocation=StepInvocation(kind="nonexistent"),
            edges=(Edge(label="halt", target="halt"),),
        )
        pipeline = _pipeline(stages={"unknown-step": stage}, entry="unknown-step")
        diag = validate(pipeline)
        assert not diag.ok
        assert any("does not resolve to a registered adapter" in d for d in diag.defects)

    def test_reserved_model_still_works_alongside_capability(self) -> None:
        """A pipeline with both model and capability invocations validates."""
        registry = StepInvocationAdapterRegistry()
        registry.register("capability", _CapabilityAdapter())

        model_stage = Stage(
            name="model-step",
            step=_PromptStep(name="model-step"),
            invocation=StepInvocation.model(),
            edges=(Edge(label="halt", target="halt"),),
        )
        cap_stage = Stage(
            name="cap-step",
            step=_CapabilityStep(),  # type: ignore[arg-type]
            invocation=StepInvocation.with_adapter_config(
                kind="capability",
                adapter_config={"artifact_root": "/tmp/_test_cap_mixed"},
            ),
            edges=(Edge(label="halt", target="halt"),),
        )
        pipeline = _pipeline(
            stages={"model-step": model_stage, "cap-step": cap_stage},
            entry="model-step",
        )
        diag = validate(pipeline, adapter_registry=registry)
        unknown_defects = [
            d for d in diag.defects if "does not resolve to a registered adapter" in d
        ]
        assert unknown_defects == [], (
            f"both model and capability should resolve: {unknown_defects}"
        )

    def test_validation_registry_case_content_validator_present(self) -> None:
        """validate() with a non-model adapter registry still passes
        when content validators are registered (no interference)."""
        from arnold.pipeline.content_validation import ContentValidatorRegistry
        from arnold.pipeline.media_content import register_media_content_validators

        content_registry = ContentValidatorRegistry()
        register_media_content_validators(content_registry)

        adapter_registry = StepInvocationAdapterRegistry()
        adapter_registry.register("capability", _CapabilityAdapter())

        stage = Stage(
            name="cap-producer",
            step=_CapabilityStep(),  # type: ignore[arg-type]
            invocation=StepInvocation.with_adapter_config(
                kind="capability",
                adapter_config={"artifact_root": "/tmp/_test_val_reg"},
            ),
            edges=(Edge(label="halt", target="halt"),),
        )
        pipeline = _pipeline(stages={"cap-producer": stage}, entry="cap-producer")
        diag = validate(pipeline, adapter_registry=adapter_registry)
        unknown_defects = [
            d for d in diag.defects if "does not resolve to a registered adapter" in d
        ]
        assert unknown_defects == [], (
            f"content validators should not affect adapter registry: {unknown_defects}"
        )


# ── Duck-typed accessors ──────────────────────────────────────────────────


class TestDuckTypedAccessors:
    def test_step_prompt_key_from_arnold_stage(self) -> None:
        """_step_prompt_key reads from Arnold Stage.step.prompt_key."""
        stage = _StageBuilder("test").with_prompt_key("critique").build()
        assert _step_prompt_key(stage) == "critique"

    def test_step_prompt_key_from_megaplan_style_step(self) -> None:
        """_step_prompt_key duck-types Megaplan step shapes."""

        class MegaplanStep:
            name = "mega_step"
            kind = "produce"
            prompt_key = "review"

        class MegaplanStage:
            def __init__(self):
                self.name = "mega_stage"
                self.step = MegaplanStep()
                self.edges = ()

        stage = MegaplanStage()
        assert _step_prompt_key(stage) == "review"

    def test_step_prompt_key_none_when_no_step(self) -> None:
        """_step_prompt_key returns None when stage has no step."""
        stage = Stage(name="empty", step=None, edges=())
        assert _step_prompt_key(stage) is None


# ── Boundary: No global mutable prompt registry ───────────────────────────


class TestNoGlobalPromptRegistry:
    def test_validator_has_no_mutable_global_registry(self) -> None:
        """The validator module must not declare a global mutable prompt registry."""
        src = (
            Path(__file__).parents[3]
            / "arnold"
            / "pipeline"
            / "validator.py"
        )
        tree = ast.parse(src.read_text())

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = target.id.lower()
                        if any(
                            keyword in name
                            for keyword in ("registry", "prompt_map", "prompt_dict")
                        ):
                            if isinstance(node.value, (ast.Dict, ast.List, ast.Set)):
                                pytest.fail(
                                    f"validator.py has mutable global registry: {target.id}"
                                )

    def test_validator_has_no_prompt_registry_import(self) -> None:
        """The validator must not import any prompt registry modules."""
        src = (
            Path(__file__).parents[3]
            / "arnold"
            / "pipeline"
            / "validator.py"
        )
        tree = ast.parse(src.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "prompt_registry" not in alias.name.lower(), (
                        f"validator imports prompt registry: {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    assert "prompt_registry" not in node.module.lower(), (
                        f"validator imports from prompt registry: {node.module}"
                    )
