from __future__ import annotations

from dataclasses import asdict, fields

import importlib

import pytest

import arnold.pipeline as pipeline
import arnold.pipeline.native as native
import arnold.execution.step_invocation as step_invocation
from arnold.workflow.builder import PipelineBuilder
from arnold.pipeline.native import NativeInstruction, NativeProgram, project_graph
from arnold.pipeline.types import Edge, Stage, StepContext, StepResult


class _Step:
    name = "only"
    kind = "test"

    def run(self, ctx: StepContext) -> StepResult:
        return StepResult(next="halt")


def test_native_authoring_decorators_are_re_exported_from_pipeline() -> None:
    """Public native authoring decorators (step, phase, workflow, pipeline, decision)
    must be importable from arnold.pipeline and appear in its __all__."""
    names = ("step", "phase", "workflow", "pipeline", "decision")
    for name in names:
        assert hasattr(pipeline, name), f"{name} missing from arnold.pipeline"
        assert name in pipeline.__all__, f"{name} missing from arnold.pipeline.__all__"
        # Verify they resolve to the same object as from arnold.pipeline.native
        assert getattr(pipeline, name) is getattr(native, name), (
            f"{name} from arnold.pipeline differs from arnold.pipeline.native"
        )


def test_native_first_import_surface_is_available_from_pipeline_and_native() -> None:
    names = (
        "NativeProgram",
        "compile_pipeline",
        "project_graph",
        "run_native_pipeline",
        "persist_native_cursor",
        "read_native_cursor",
        "upgrade_graph_cursor_to_native",
    )

    for name in names:
        assert getattr(pipeline, name) is getattr(native, name)
        assert name in pipeline.__all__
        assert name in native.__all__


def test_legacy_namespace_raises_module_not_found_error() -> None:
    """M7: arnold.pipeline.legacy is removed — import must raise ModuleNotFoundError."""
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("arnold.pipeline.legacy")


def test_every_all_name_is_backed_by_an_import() -> None:
    """Every name in arnold.pipeline.__all__ must resolve to an actual object."""
    missing = [name for name in pipeline.__all__ if not hasattr(pipeline, name)]
    assert not missing, f"__all__ names without import: {missing}"


def test_graph_era_symbols_absent_from_root_all() -> None:
    """Graph-era construction/execution names must not appear in pipeline.__all__."""
    graph_era = [
        "Edge", "Stage", "ParallelStage",
        "PipelineBuilder", "PipelineRegistry",
        "ExecutorHooks", "NullExecutorHooks",
        "run_pipeline", "run_pipeline_resume",
    ]
    present = [g for g in graph_era if g in pipeline.__all__]
    assert not present, f"graph-era symbols in root __all__: {present}"


def test_step_invocation_exports_are_retained_and_canonical() -> None:
    names = (
        "StepInvocation",
        "StepInvocationAdapter",
        "StepInvocationAdapterRegistry",
        "StepInvocationResult",
        "unwrap_step_invocation_result",
    )
    for name in names:
        assert name in pipeline.__all__
        assert getattr(pipeline, name) is getattr(step_invocation, name)


def test_discovery_names_in_root_all() -> None:
    """Neutral discovery names must be in pipeline.__all__ and resolve."""
    discovery = ["Manifest", "ManifestError", "TrustGrade", "classify", "read_manifest", "derive_tenant_id"]
    for name in discovery:
        assert name in pipeline.__all__, f"{name} missing from __all__"
        assert hasattr(pipeline, name), f"{name} not resolvable"


def test_pipeline_native_program_is_preserved_by_dataclass_and_builder_helpers() -> None:
    program = NativeProgram(
        name="contract",
        instructions=(NativeInstruction(pc=0, op="phase", name="only", func=_Step().run),),
    )
    builder = PipelineBuilder("contract")
    builder.add_stage(
        Stage(
            name="only",
            step=_Step(),
            edges=(Edge(label="done", target="halt"),),
        )
    )

    built = builder.build(native_program=program)
    payload = asdict(built)

    assert "native_program" in {field.name for field in fields(type(built))}
    assert built.native_program is program
    assert payload["native_program"]["name"] == "contract"


def test_project_graph_attaches_native_program_to_projected_pipeline() -> None:
    program = NativeProgram(
        name="projected",
        instructions=(NativeInstruction(pc=0, op="phase", name="only", func=_Step().run),),
    )

    projected = project_graph(program)

    assert projected.native_program is program
