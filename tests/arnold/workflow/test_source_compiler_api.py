from __future__ import annotations

import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict, is_dataclass
from pathlib import Path

import pytest

from arnold.manifest.refs import ImportRef
import arnold.workflow as workflow
from arnold.workflow import authoring, diagnostics
from arnold.workflow import source_compiler


PUBLIC_SOURCE_APIS = (
    "check_workflow_source",
    "check_workflow_file",
    "lower_workflow_source",
    "lower_workflow_file",
    "compile_workflow_source",
    "compile_workflow_file",
)
FIXTURE_DIR = Path("tests/fixtures/workflow_authoring")
M0_FIXTURE_DIR = Path("tests/fixtures/workflow_authoring/m0")
M3_FIXTURE_DIR = Path("tests/fixtures/workflow_authoring/m3")
M0_VALID_FIXTURES = (
    "valid_m0_single_workflow",
    "valid_m0_nested_child_workflow",
    "valid_m0_repeated_call_sites",
)
M3_VALID_FIXTURES = (
    "valid_m3_canonical_megaplan_topology",
    "valid_m3_branch_routes",
    "valid_m3_bounded_loop",
    "valid_m3_policy_refs",
    "valid_m3_subflow_ref",
    "valid_m3_subflow_control_flow",
    "valid_m3_parallel_map_loop_policy",
)
M3_INVALID_FIXTURES = (
    "invalid_m3_non_literal_routing",
    "invalid_m3_repeated_route_comparison",
    "invalid_m3_missing_fallthrough_route",
    "invalid_m3_mismatched_route_metadata",
    "invalid_m3_ambiguous_route_metadata",
    "invalid_m3_malformed_capability_metadata",
    "invalid_m3_malformed_retry_policy_config",
    "invalid_m3_malformed_timing_policy_config",
    "invalid_m3_unsupported_step_policy_carrier",
    "invalid_m3_unsupported_workflow_policy_carrier",
    "invalid_m3_unsupported_mutation",
    "invalid_m3_ambiguous_loop",
    "invalid_m3_loop_missing_bounds",
    "invalid_m3_loop_dynamic_bounds",
    "invalid_m3_loop_non_true_test",
    "invalid_m3_unsupported_policy_carrier",
    "invalid_m3_dynamic_subflow_identity",
    "invalid_m3_unreachable_path",
    "invalid_m3_dynamic_dispatch",
    "invalid_m3_single_handler_wrapper",
    "invalid_m3_nonliteral_path_construction",
    "invalid_m3_megaplan_helper_fanout",
    "invalid_m3_tiebreaker_single_call_carrier",
)
M3_SPECIALIZED_INVALID_FIXTURES = (
    "invalid_m3_single_handler_review_fanout",
    "invalid_m3_handler_owned_review_cap",
    "invalid_m3_hidden_finalize_fallback",
)


def _clone_step_component_with_metadata(
    component: authoring.StepComponent,
    metadata: Mapping[str, object],
) -> authoring.StepComponent:
    return authoring.StepComponent(
        id=component.id,
        provenance=component.provenance,
        label=component.label,
        step_type=component.step_type,
        prompt=component.prompt,
        policy=component.policy,
        input_schema=component.input_schema,
        output_schema=component.output_schema,
        metadata=metadata,
    )


def _clone_workflow_component_with_metadata(
    component: authoring.ComponentContract,
    metadata: Mapping[str, object],
) -> authoring.ComponentContract:
    return authoring.ComponentContract(
        id=component.id,
        kind=component.kind,
        provenance=component.provenance,
        label=component.label,
        metadata=metadata,
    )


def test_source_compiler_public_api_names_are_exported() -> None:
    for name in PUBLIC_SOURCE_APIS:
        assert hasattr(workflow, name), name
        assert name in workflow.__all__
    assert hasattr(workflow, "SourceCompileError")
    assert "SourceCompileError" in workflow.__all__


def test_source_compiler_identity_adapters_are_exported_for_hook_and_policy_refs() -> None:
    """Source-compiler parity relies on the same durable ref adapters as patterns."""

    assert hasattr(workflow, "as_hook_ref")
    assert hasattr(workflow, "as_import_ref")
    assert hasattr(workflow, "as_optional_hook_ref")
    assert "as_hook_ref" in workflow.__all__
    assert "as_import_ref" in workflow.__all__
    assert "as_optional_hook_ref" in workflow.__all__


def test_source_compiler_public_api_call_shapes_accept_source_and_file_inputs() -> None:
    source = Path("tests/fixtures/workflow_authoring/valid_direct_linear.py").read_text(
        encoding="utf-8"
    )
    source_path = Path("tests/fixtures/workflow_authoring/valid_direct_linear.py")

    workflow.check_workflow_source(source, source_path=source_path)
    workflow.lower_workflow_source(source, source_path=source_path)
    workflow.compile_workflow_source(source, source_path=source_path)
    workflow.check_workflow_file(source_path)
    workflow.lower_workflow_file(source_path)
    workflow.compile_workflow_file(source_path)


def test_source_compiler_accepts_pypeline_suffix_with_same_ast_semantics_and_spans() -> None:
    """``.pypeline`` files accept Python-shaped AST source and preserve source spans."""
    pypeline_path = Path("tests/fixtures/workflow_authoring/valid_direct_linear.pypeline")
    py_path = Path("tests/fixtures/workflow_authoring/valid_direct_linear.py")

    pypeline_source = pypeline_path.read_text(encoding="utf-8")
    py_source = py_path.read_text(encoding="utf-8")

    # Same source text
    assert pypeline_source == py_source

    # All six public APIs accept the .pypeline path
    workflow.check_workflow_source(pypeline_source, source_path=pypeline_path)
    workflow.lower_workflow_source(pypeline_source, source_path=pypeline_path)
    workflow.compile_workflow_source(pypeline_source, source_path=pypeline_path)
    workflow.check_workflow_file(pypeline_path)
    workflow.lower_workflow_file(pypeline_path)
    manifest = workflow.compile_workflow_file(pypeline_path)

    # Manifest identity is independent of suffix
    assert manifest.id == "linear-direct"

    # Source spans are preserved (path carries .pypeline suffix)
    py_manifest = workflow.compile_workflow_file(py_path)
    for node in manifest.nodes:
        assert node.source_span is not None
        assert node.source_span.path.endswith(".pypeline")
    for edge in manifest.edges:
        if edge.source_span:
            assert edge.source_span.path.endswith(".pypeline")
    # Manifest hashes match between .py and .pypeline (content-identical)
    assert manifest.manifest_hash == py_manifest.manifest_hash


def test_source_compiler_supported_suffixes_includes_pypeline() -> None:
    """The ``_SUPPORTED_SOURCE_SUFFIXES`` constant names both ``.py`` and ``.pypeline``."""
    assert hasattr(workflow, "_SUPPORTED_SOURCE_SUFFIXES")
    assert ".py" in workflow._SUPPORTED_SOURCE_SUFFIXES
    assert ".pypeline" in workflow._SUPPORTED_SOURCE_SUFFIXES


def test_source_compiler_m3_diagnostic_registry_pins_control_flow_policy_codes() -> None:
    expected = {
        diagnostics.DiagnosticCode.ROUTE_METADATA_MISMATCH: (
            "AWF018_ROUTE_METADATA_MISMATCH",
            diagnostics.DiagnosticFamily.ROUTE_METADATA_MISMATCH,
        ),
        diagnostics.DiagnosticCode.MALFORMED_POLICY_CONFIG: (
            "AWF019_MALFORMED_POLICY_CONFIG",
            diagnostics.DiagnosticFamily.MALFORMED_POLICY_CONFIG,
        ),
        diagnostics.DiagnosticCode.MALFORMED_CAPABILITY_METADATA: (
            "AWF020_MALFORMED_CAPABILITY_METADATA",
            diagnostics.DiagnosticFamily.MALFORMED_CAPABILITY_METADATA,
        ),
        diagnostics.DiagnosticCode.LOOP_POLICY_BINDING_MISMATCH: (
            "AWF021_LOOP_POLICY_BINDING_MISMATCH",
            diagnostics.DiagnosticFamily.LOOP_POLICY_BINDING_MISMATCH,
        ),
        diagnostics.DiagnosticCode.MISSING_PROMPT_DEPENDENCY: (
            "AWF022_MISSING_PROMPT_DEPENDENCY",
            diagnostics.DiagnosticFamily.MISSING_PROMPT_DEPENDENCY,
        ),
        diagnostics.DiagnosticCode.MISSING_RESOURCE_DEPENDENCY: (
            "AWF023_MISSING_RESOURCE_DEPENDENCY",
            diagnostics.DiagnosticFamily.MISSING_RESOURCE_DEPENDENCY,
        ),
    }

    assert diagnostics.DIAGNOSTIC_SPECS is diagnostics.DIAGNOSTIC_CODE_SPECS
    for code, (stable_name, family) in expected.items():
        spec = diagnostics.diagnostic_spec(code)

        assert spec.code is code
        assert spec.code.value == stable_name
        assert spec.family is family
        assert spec.severity is diagnostics.DiagnosticSeverity.ERROR
        assert spec.message_template
        assert spec.remediation


def test_source_compiler_resolves_components_through_static_resolver_boundary() -> None:
    source = """
from __future__ import annotations

from arnold.workflow.authoring import workflow
from project.workflow_components import plan

workflow(id="custom-resolver", steps=[plan(id="plan")])
"""
    resolver = _Resolver(
        {
            "project.workflow_components:plan": authoring.StepComponent(
                id="plan",
                provenance=authoring.ComponentProvenance(
                    module="project.workflow_components",
                    qualname="plan",
                    export_name="plan",
                ),
            )
        }
    )

    pipeline = workflow.lower_workflow_source(
        source,
        source_path="tests/fixtures/workflow_authoring/custom_resolver.py",
        resolver=resolver,
    )

    assert pipeline.steps[0].metadata["component_ref"] == "project.workflow_components:plan"
    assert resolver.resolved == (ImportRef("project.workflow_components", "plan"),)


def test_source_compiler_normalizes_relative_import_modules_for_absolute_hyphenated_paths() -> None:
    source = """
from __future__ import annotations

from .workflow_components import plan
from arnold.workflow.authoring import workflow

workflow(id="relative-import", steps=[plan(id="plan")])
"""
    resolver = _Resolver(
        {
            "_.tmp.hyphenated_root.pkg.workflow_components:plan": authoring.StepComponent(
                id="plan",
                provenance=authoring.ComponentProvenance(
                    module="_.tmp.hyphenated_root.pkg.workflow_components",
                    qualname="plan",
                    export_name="plan",
                ),
            )
        }
    )
    source_path = Path("/tmp/hyphenated-root/pkg/relative_import.pypeline")

    pipeline = workflow.lower_workflow_source(source, source_path=source_path, resolver=resolver)

    assert pipeline.steps[0].metadata["component_ref"] == (
        "_.tmp.hyphenated_root.pkg.workflow_components:plan"
    )
    assert resolver.resolved == (ImportRef("_.tmp.hyphenated_root.pkg.workflow_components", "plan"),)


def test_source_compiler_lowers_direct_form_to_linear_pipeline_with_call_site_spans() -> None:
    source_path = Path("tests/fixtures/workflow_authoring/valid_direct_linear.py")
    source = source_path.read_text(encoding="utf-8")

    pipeline = workflow.lower_workflow_source(source, source_path=source_path)

    assert [step.id for step in pipeline.steps] == ["plan", "execute", "review"]
    assert [step.kind for step in pipeline.steps] == ["agent", "agent", "agent"]
    assert [step.source_span.start_line for step in pipeline.steps if step.source_span] == [
        10,
        11,
        12,
    ]
    assert [step.metadata["component_ref"] for step in pipeline.steps] == [
        "tests.fixtures.workflow_authoring.components:plan",
        "tests.fixtures.workflow_authoring.components:execute",
        "tests.fixtures.workflow_authoring.components:review",
    ]
    assert [(route.id, route.source, route.target) for route in pipeline.routes] == [
        ("plan-execute", "plan", "execute"),
        ("execute-review", "execute", "review"),
    ]
    assert [route.source_span.start_line for route in pipeline.routes if route.source_span] == [
        11,
        12,
    ]


def test_source_compiler_compiles_direct_form_through_existing_manifest_contract() -> None:
    source_path = Path("tests/fixtures/workflow_authoring/valid_direct_linear.py")
    source = source_path.read_text(encoding="utf-8")

    manifest = workflow.compile_workflow_source(source, source_path=source_path)

    assert manifest.id == "linear-direct"
    assert [node.id for node in manifest.nodes] == ["execute", "plan", "review"]
    assert [(edge.id, edge.source, edge.target) for edge in manifest.edges] == [
        ("execute-review", "execute", "review"),
        ("plan-execute", "plan", "execute"),
    ]
    assert {edge.id: edge.source_span.start_line for edge in manifest.edges if edge.source_span} == {
        "execute-review": 12,
        "plan-execute": 11,
    }
    assert {node.id: node.source_span.start_line for node in manifest.nodes if node.source_span} == {
        "plan": 10,
        "execute": 11,
        "review": 12,
    }


def test_source_compiler_rejects_invalid_import_forms_and_intrinsic_provenance_loss() -> None:
    invalid_sources = {
        "future": "from __future__ import division\n",
        "intrinsic_alias": "from arnold.workflow.authoring import workflow as wf\nwf(id='x', steps=[])\n",
        "intrinsic_unknown": "from arnold.workflow.authoring import not_an_intrinsic\n",
        "dynamic": (
            "from arnold.workflow.authoring import workflow\n"
            "plan = __import__('project.workflow_components').plan\n"
            "workflow(id='x', steps=[plan(id='plan')])\n"
        ),
        "assigned_workflow": (
            "from arnold.workflow.authoring import workflow\n"
            "value = workflow(id='not-direct', steps=[])\n"
        ),
    }

    results = {
        name: workflow.check_workflow_source(source, source_path=f"{name}.py")
        for name, source in invalid_sources.items()
    }

    assert diagnostics.DiagnosticCode.INVALID_IMPORT_SOURCE in _codes(results["future"])
    assert diagnostics.DiagnosticCode.RESERVED_INTRINSIC_SHADOWING in _codes(
        results["intrinsic_alias"]
    )
    assert diagnostics.DiagnosticCode.INVALID_IMPORT_SOURCE in _codes(results["intrinsic_unknown"])
    assert diagnostics.DiagnosticCode.UNSUPPORTED_SYNTAX in _codes(results["dynamic"])
    assert diagnostics.DiagnosticCode.MISSING_WORKFLOW_DECLARATION in _codes(
        results["assigned_workflow"]
    )


def test_source_compiler_accepts_exactly_one_direct_or_function_workflow_source_form() -> None:
    direct_source = Path("tests/fixtures/workflow_authoring/valid_direct_linear.py").read_text(
        encoding="utf-8"
    )
    function_source = Path("tests/fixtures/workflow_authoring/valid_function_linear.py").read_text(
        encoding="utf-8"
    )
    mixed_source = direct_source + "\n" + function_source

    direct = workflow.check_workflow_source(
        direct_source,
        source_path="tests/fixtures/workflow_authoring/valid_direct_linear.py",
    )
    function = workflow.check_workflow_source(
        function_source,
        source_path="tests/fixtures/workflow_authoring/valid_function_linear.py",
    )
    mixed = workflow.check_workflow_source(
        mixed_source,
        source_path="tests/fixtures/workflow_authoring/mixed.py",
    )

    assert direct.ok
    assert direct.parsed_source.workflow is not None
    assert direct.parsed_source.workflow.source_form == "direct"
    assert function.ok
    assert function.parsed_source.workflow is not None
    assert function.parsed_source.workflow.source_form == "function"
    assert [step.id for step in function.parsed_source.workflow.steps] == [
        "plan",
        "execute",
        "review",
    ]
    assert diagnostics.DiagnosticCode.MULTIPLE_WORKFLOW_DECLARATIONS in _codes(mixed)


@pytest.mark.parametrize(
    ("fixture_name", "expected_code", "expected_remediation"),
    [
        (
            "invalid_missing_workflow",
            diagnostics.DiagnosticCode.MISSING_WORKFLOW_DECLARATION,
            "add exactly one top-level workflow(...) declaration",
        ),
        (
            "invalid_multiple_workflows",
            diagnostics.DiagnosticCode.MULTIPLE_WORKFLOW_DECLARATIONS,
            "keep a single top-level workflow(...) declaration per source file",
        ),
    ],
)
def test_source_compiler_workflow_declaration_diagnostics_pin_spans_and_remediation(
    fixture_name: str,
    expected_code: diagnostics.DiagnosticCode,
    expected_remediation: str,
) -> None:
    source_path = FIXTURE_DIR / f"{fixture_name}.py"
    expected = json.loads(
        (FIXTURE_DIR / f"{fixture_name}.expected.json").read_text(encoding="utf-8")
    )["expected_diagnostics"][0]

    result = workflow.check_workflow_file(source_path)

    assert not result.ok
    assert len(result.diagnostics) == 1
    diagnostic = result.diagnostics[0]
    assert diagnostic.code is expected_code
    assert diagnostic.remediation == expected_remediation
    payload = _diagnostic_payloads(result)[0]
    assert payload["code"] == expected["code"]
    assert payload["message"] == expected["message"]
    assert payload["source_span"] == {
        "path": source_path.as_posix(),
        **expected["source_span"],
    }


def test_source_compiler_parses_function_header_metadata_and_ordered_scope() -> None:
    source = Path("tests/fixtures/workflow_authoring/valid_function_linear.py").read_text(
        encoding="utf-8"
    )

    result = workflow.check_workflow_source(
        source,
        source_path="tests/fixtures/workflow_authoring/valid_function_linear.py",
    )

    assert result.ok
    assert result.parsed_source.workflow is not None
    assert result.parsed_source.workflow.id == "linear-function"
    assert result.parsed_source.workflow.version == "1.0"
    assert result.parsed_source.workflow.function_name == "linear"
    assert result.parsed_source.workflow.parameters == ("brief",)
    assert result.parsed_source.scope.parameters == ("brief",)


def test_source_compiler_lowers_function_body_dataflow_in_source_order() -> None:
    source = Path("tests/fixtures/workflow_authoring/valid_function_linear.py").read_text(
        encoding="utf-8"
    )

    pipeline = workflow.lower_workflow_source(
        source,
        source_path="tests/fixtures/workflow_authoring/valid_function_linear.py",
    )

    assert [step.id for step in pipeline.steps] == ["plan", "execute", "review"]
    assert [
        [(input_binding.name, input_binding.value_ref) for input_binding in step.inputs]
        for step in pipeline.steps
    ] == [
        [("brief", "param:brief")],
        [("plan", "output:plan_output")],
        [("evidence", "output:evidence")],
    ]
    assert [[output.name for output in step.outputs] for step in pipeline.steps] == [
        ["plan_output"],
        ["execute_output", "evidence"],
        [],
    ]
    assert [(route.id, route.source, route.target) for route in pipeline.routes] == [
        ("plan-execute", "plan", "execute"),
        ("execute-review", "execute", "review"),
    ]


def test_source_compiler_reserved_step_keywords_are_not_dataflow_inputs() -> None:
    source = """
from arnold.workflow.authoring import workflow
from tests.fixtures.workflow_authoring.components import plan

@workflow(id="reserved-step-keyword")
def flow(brief):
    plan_output = plan(id="plan", policy=brief)
    plan(id="schema-step", schema=plan_output)
    plan(id="policies-step", policies=brief)
"""

    result = workflow.check_workflow_source(source, source_path="reserved_step_keyword.py")

    assert _diagnostic_payloads(result) == [
        {
            "code": "AWF010_RESERVED_CALL_KEYWORD",
            "message": "step call keyword 'policy' is reserved for compiler-owned authoring syntax",
            "source_span": {
                "path": "reserved_step_keyword.py",
                "start_line": 7,
                "start_column": 35,
                "end_line": 7,
                "end_column": 47,
            },
        },
        {
            "code": "AWF010_RESERVED_CALL_KEYWORD",
            "message": "step call keyword 'schema' is reserved for compiler-owned authoring syntax",
            "source_span": {
                "path": "reserved_step_keyword.py",
                "start_line": 8,
                "start_column": 28,
                "end_line": 8,
                "end_column": 46,
            },
        },
        {
            "code": "AWF010_RESERVED_CALL_KEYWORD",
            "message": "step call keyword 'policies' is reserved for compiler-owned authoring syntax",
            "source_span": {
                "path": "reserved_step_keyword.py",
                "start_line": 9,
                "start_column": 30,
                "end_line": 9,
                "end_column": 44,
            },
        },
    ]
    assert result.parsed_source.workflow is not None
    assert result.parsed_source.workflow.steps == ()


def test_source_compiler_lowers_reserved_step_policy_keywords() -> None:
    source = """
from arnold.workflow.authoring import workflow
from tests.fixtures.workflow_authoring.components import fast_retry, plan, review, review_timeout

@workflow(id="reserved-policy-keywords")
def flow(brief):
    plan_output = plan(id="plan", brief=brief)
    review(id="review", evidence=plan_output, policy=fast_retry, policies=[review_timeout])
"""

    pipeline = workflow.lower_workflow_source(source, source_path="reserved_policy_keywords.py")

    review_step = {step.id: step for step in pipeline.steps}["review"]
    assert [(input_binding.name, input_binding.value_ref) for input_binding in review_step.inputs] == [
        ("evidence", "output:plan_output")
    ]
    assert review_step.policy is not None
    assert review_step.policy.retry is not None
    assert review_step.policy.retry.max_attempts == 2
    assert review_step.policy.retry.retry_on == ("transient",)
    assert review_step.policy.timing is not None
    assert review_step.policy.timing.timeout_seconds == 60


def test_source_compiler_lowers_authority_and_control_policy_keywords() -> None:
    source = """
from arnold.workflow.authoring import workflow
from tests.fixtures.workflow_authoring.components import handoff_transition, plan, review, review_approval

@workflow(id="authority-policy-keywords")
def flow(brief):
    plan_output = plan(id="plan", brief=brief)
    review(id="review", evidence=plan_output, policies=[review_approval, handoff_transition])
"""

    pipeline = workflow.lower_workflow_source(source, source_path="authority_policy_keywords.py")

    review_step = {step.id: step for step in pipeline.steps}["review"]
    assert review_step.policy is not None
    assert list(review_step.policy.authority) == [
        workflow.AuthorityRequirement(
            authority_id="review-approval",
            action="approve-review",
            capability_id="human.review",
        )
    ]
    assert list(review_step.policy.control_transitions) == [
        workflow.ControlTransitionSlot(
            transition_id="handoff",
            transition_type="approval-handoff",
            trigger_ref="review.needs_approval",
            target_ref="reviewer",
            policy_ref="review_approval",
        )
    ]


def test_source_compiler_lowers_workflow_control_policy_keywords() -> None:
    source = """
from arnold.workflow.authoring import workflow
from tests.fixtures.workflow_authoring.components import handoff_transition, operator_suspend, plan, review_approval

@workflow(id="workflow-control-policy", policies=[operator_suspend, review_approval, handoff_transition])
def flow(brief):
    plan(id="plan", brief=brief)
"""

    pipeline = workflow.lower_workflow_source(source, source_path="workflow_control_policy.py")

    assert pipeline.policy is not None
    assert list(pipeline.policy.suspension_routes) == [
        workflow.SuspensionRoute(
            route_id="operator",
            capability_id="human.review",
            reentry_id="execute",
            resume_schema_ref="operator.resume",
        )
    ]
    assert list(pipeline.policy.authority) == [
        workflow.AuthorityRequirement(
            authority_id="review-approval",
            action="approve-review",
            capability_id="human.review",
        )
    ]
    assert list(pipeline.policy.control_transitions) == [
        workflow.ControlTransitionSlot(
            transition_id="handoff",
            transition_type="approval-handoff",
            trigger_ref="review.needs_approval",
            target_ref="reviewer",
            policy_ref="review_approval",
        )
    ]


def test_source_compiler_lowers_workflow_retry_and_timing_policy_keywords() -> None:
    source = """
from arnold.workflow.authoring import workflow
from tests.fixtures.workflow_authoring.components import fast_retry, plan, review_timeout

@workflow(id="workflow-retry-timing", policies=[fast_retry, review_timeout])
def flow(brief):
    plan(id="plan", brief=brief)
"""

    pipeline = workflow.lower_workflow_source(source, source_path="workflow_retry_timing.py")

    assert pipeline.policy is not None
    assert pipeline.policy.retry == workflow.RetryPolicy(
        max_attempts=2,
        backoff="none",
        retry_on=("transient",),
    )
    assert pipeline.policy.timing == workflow.TimingPolicy(timeout_seconds=60)

    manifest = workflow.compile_workflow_source(source, source_path="workflow_retry_timing.py")

    assert manifest.policy is not None
    assert manifest.policy.retry == pipeline.policy.retry
    assert manifest.policy.timing == pipeline.policy.timing


def test_source_compiler_rejects_malformed_retry_and_timing_policy_configs() -> None:
    source = """
from arnold.workflow.authoring import workflow
from project.workflow_components import bad_retry, bad_timing, plan

@workflow(id="malformed-workflow-policy", policies=[bad_retry, bad_timing])
def flow(brief):
    plan(id="plan", brief=brief)
"""
    resolver = _Resolver(
        {
            "project.workflow_components:plan": _step_component("plan"),
            "project.workflow_components:bad_retry": authoring.PolicyComponent(
                id="bad_retry",
                provenance=authoring.ComponentProvenance(
                    module="project.workflow_components",
                    qualname="bad_retry",
                    export_name="bad_retry",
                ),
                policy_type="retry",
                config={"max_attempts": 0, "retry_on": ("transient", 7)},
            ),
            "project.workflow_components:bad_timing": authoring.PolicyComponent(
                id="bad_timing",
                provenance=authoring.ComponentProvenance(
                    module="project.workflow_components",
                    qualname="bad_timing",
                    export_name="bad_timing",
                ),
                policy_type="timing",
                config={"timeout_seconds": "soon", "deadline_ref": 30},
            ),
        }
    )

    result = workflow.check_workflow_source(
        source,
        source_path="malformed_workflow_policy.py",
        resolver=resolver,
    )

    assert [
        (diagnostic.code.value, diagnostic.message, diagnostic.details)
        for diagnostic in result.diagnostics
    ] == [
        (
            "AWF019_MALFORMED_POLICY_CONFIG",
            "policy 'bad_retry' has malformed retry config",
            {
                "policy_type": "retry",
                "invalid_fields": ("max_attempts", "retry_on"),
            },
        ),
        (
            "AWF019_MALFORMED_POLICY_CONFIG",
            "policy 'bad_timing' has malformed timing config",
            {
                "policy_type": "timing",
                "invalid_fields": ("timeout_seconds", "deadline_ref"),
            },
        ),
    ]


def test_source_compiler_rejects_unsupported_workflow_policy_families() -> None:
    source = """
from arnold.workflow.authoring import workflow
from tests.fixtures.workflow_authoring.components import dynamic_model_router, plan, robustness_guard

@workflow(id="unsupported-workflow-policy", policies=[dynamic_model_router, robustness_guard])
def flow(brief):
    plan(id="plan", brief=brief)
"""

    result = workflow.check_workflow_source(source, source_path="unsupported_workflow_policy.py")

    assert _diagnostic_payloads(result) == [
        {
            "code": "AWF014_UNSUPPORTED_POLICY_CARRIER",
            "message": "workflow policy type 'model-routing' does not map to an existing workflow-level control carrier",
            "source_span": {
                "path": "unsupported_workflow_policy.py",
                "start_line": 5,
                "start_column": 55,
                "end_line": 5,
                "end_column": 75,
            },
        },
        {
            "code": "AWF014_UNSUPPORTED_POLICY_CARRIER",
            "message": "workflow policy type 'robustness' does not map to an existing workflow-level control carrier",
            "source_span": {
                "path": "unsupported_workflow_policy.py",
                "start_line": 5,
                "start_column": 77,
                "end_line": 5,
                "end_column": 93,
            },
        },
    ]


def test_source_compiler_rejects_unsupported_policy_families() -> None:
    source = """
from arnold.workflow.authoring import workflow
from tests.fixtures.workflow_authoring.components import plan, reprompt_guard, review, robustness_guard

@workflow(id="unsupported-policy-families")
def flow(brief):
    plan_output = plan(id="plan", brief=brief)
    review(id="review", evidence=plan_output, policies=[robustness_guard, reprompt_guard])
"""

    result = workflow.check_workflow_source(source, source_path="unsupported_policy_families.py")

    assert _diagnostic_payloads(result) == [
        {
            "code": "AWF014_UNSUPPORTED_POLICY_CARRIER",
            "message": "policy type 'robustness' does not map to an existing manifest carrier",
            "source_span": {
                "path": "unsupported_policy_families.py",
                "start_line": 8,
                "start_column": 57,
                "end_line": 8,
                "end_column": 73,
            },
        },
        {
            "code": "AWF014_UNSUPPORTED_POLICY_CARRIER",
            "message": "policy type 'reprompt' does not map to an existing manifest carrier",
            "source_span": {
                "path": "unsupported_policy_families.py",
                "start_line": 8,
                "start_column": 75,
                "end_line": 8,
                "end_column": 89,
            },
        },
    ]


def test_source_compiler_merge_workflow_policies_preserves_fields_deterministically() -> None:
    first = workflow.WorkflowPolicy(
        budget=workflow.BudgetPolicy(max_seconds=10),
        retry=workflow.RetryPolicy(max_attempts=1),
        loop=workflow.LoopPolicy(max_iterations=2),
        fanout=workflow.FanoutPolicy(width=2),
        timing=workflow.TimingPolicy(timeout_seconds=30),
        idempotency=workflow.IdempotencyPolicy(key_ref="first"),
        effects=(workflow.EffectRef("effect.first"),),
        reducers=(workflow.ReducerRef("reducer.first"),),
        compensation=workflow.CompensationPolicy(scope_ref="first"),
        escalation=workflow.EscalationPolicy(targets=("first",)),
        control_transitions=(workflow.ControlTransitionSlot("transition-first", "halt"),),
        topology_overlays=(workflow.TopologyOverlaySlot("overlay-first", "dynamic"),),
        authority=(workflow.AuthorityRequirement("authority-first", "approve"),),
        suspension_routes=(workflow.SuspensionRoute("suspend-first"),),
    )
    second = workflow.WorkflowPolicy(
        budget=workflow.BudgetPolicy(max_seconds=20),
        retry=workflow.RetryPolicy(max_attempts=3, retry_on=("network",)),
        loop=workflow.LoopPolicy(max_iterations=4),
        fanout=workflow.FanoutPolicy(width=4),
        timing=workflow.TimingPolicy(timeout_seconds=60),
        idempotency=workflow.IdempotencyPolicy(key_ref="second"),
        effects=(workflow.EffectRef("effect.second"),),
        reducers=(workflow.ReducerRef("reducer.second"),),
        compensation=workflow.CompensationPolicy(scope_ref="second"),
        escalation=workflow.EscalationPolicy(targets=("second",)),
        control_transitions=(workflow.ControlTransitionSlot("transition-second", "override"),),
        topology_overlays=(workflow.TopologyOverlaySlot("overlay-second", "dynamic"),),
        authority=(workflow.AuthorityRequirement("authority-second", "approve"),),
        suspension_routes=(workflow.SuspensionRoute("suspend-second"),),
    )

    assert source_compiler._merge_workflow_policies(None, None) is None

    merged = source_compiler._merge_workflow_policies(None, first, None, second)

    assert merged is not None
    assert merged.budget == second.budget
    assert merged.retry == second.retry
    assert merged.loop == second.loop
    assert merged.fanout == second.fanout
    assert merged.timing == second.timing
    assert merged.idempotency == second.idempotency
    assert merged.compensation == second.compensation
    assert merged.escalation == second.escalation
    assert merged.effects == (*first.effects, *second.effects)
    assert merged.reducers == (*first.reducers, *second.reducers)
    assert merged.control_transitions == (
        *first.control_transitions,
        *second.control_transitions,
    )
    assert merged.topology_overlays == (*first.topology_overlays, *second.topology_overlays)
    assert merged.authority == (*first.authority, *second.authority)
    assert merged.suspension_routes == (*first.suspension_routes, *second.suspension_routes)


def test_source_compiler_rejects_policy_components_as_ordinary_inputs() -> None:
    source = """
from arnold.workflow.authoring import workflow
from tests.fixtures.workflow_authoring.components import fast_retry, plan, review

@workflow(id="policy-as-dataflow")
def flow(brief):
    plan_output = plan(id="plan", brief=brief)
    review(id="review", evidence=plan_output, retry=fast_retry)
"""

    result = workflow.check_workflow_source(source, source_path="policy_as_dataflow.py")

    assert _diagnostic_payloads(result) == [
        {
            "code": "AWF010_RESERVED_CALL_KEYWORD",
            "message": "policy components must be passed with reserved policy= or policies= syntax",
            "source_span": {
                "path": "policy_as_dataflow.py",
                "start_line": 8,
                "start_column": 53,
                "end_line": 8,
                "end_column": 63,
            },
        }
    ]


def test_source_compiler_normal_step_keywords_remain_dataflow_inputs() -> None:
    source = """
from arnold.workflow.authoring import workflow
from tests.fixtures.workflow_authoring.components import plan, review

@workflow(id="normal-keyword-dataflow")
def flow(brief):
    evidence = plan(id="plan", brief=brief)
    review(id="review", evidence=evidence)
"""

    result = workflow.check_workflow_source(source, source_path="normal_keyword_dataflow.py")

    assert result.ok
    assert result.parsed_source.workflow is not None
    assert [
        [(input_binding.name, input_binding.value_ref) for input_binding in step.inputs]
        for step in result.parsed_source.workflow.steps
    ] == [
        [("brief", "param:brief")],
        [("evidence", "output:evidence")],
    ]


def test_source_compiler_compiles_function_body_bindings_through_manifest_contract() -> None:
    source_path = Path("tests/fixtures/workflow_authoring/valid_function_linear.py")
    manifest = workflow.compile_workflow_file(source_path)

    nodes = {node.id: node for node in manifest.nodes}
    assert nodes["plan"].inputs == ("brief",)
    assert nodes["plan"].outputs == ("plan_output",)
    assert nodes["plan"].metadata["input_bindings"]["brief"]["value_ref"] == "param:brief"
    assert nodes["execute"].inputs == ("plan",)
    assert nodes["execute"].outputs == ("execute_output", "evidence")
    assert nodes["execute"].metadata["input_bindings"]["plan"]["value_ref"] == "output:plan_output"
    assert nodes["review"].inputs == ("evidence",)
    assert nodes["review"].outputs == ()
    assert nodes["review"].metadata["input_bindings"]["evidence"]["value_ref"] == "output:evidence"


def test_source_compiler_compiles_and_validates_single_step_linear_workflow() -> None:
    source_path = FIXTURE_DIR / "valid_linear_single_step.py"

    check_result = workflow.check_workflow_file(source_path)
    pipeline = workflow.lower_workflow_file(source_path)
    manifest = workflow.compile_workflow_file(source_path)

    workflow.validate_manifest(manifest)
    assert check_result.ok
    assert pipeline.id == "linear-single-step"
    assert [step.id for step in pipeline.steps] == ["plan"]
    assert pipeline.routes == ()
    assert manifest.id == "linear-single-step"
    assert [node.id for node in manifest.nodes] == ["plan"]
    assert manifest.edges == ()


def test_source_compiler_allows_tuple_assignment_outputs_to_remain_unused() -> None:
    source_path = FIXTURE_DIR / "valid_linear_tuple_unused_outputs.py"

    check_result = workflow.check_workflow_file(source_path)
    pipeline = workflow.lower_workflow_file(source_path)
    manifest = workflow.compile_workflow_file(source_path)

    workflow.validate_manifest(manifest)
    assert check_result.ok
    assert [step.id for step in pipeline.steps] == ["plan", "execute", "review"]
    execute_step = {step.id: step for step in pipeline.steps}["execute"]
    assert [output.name for output in execute_step.outputs] == ["execute_output", "evidence"]
    review_step = {step.id: step for step in pipeline.steps}["review"]
    assert [(binding.name, binding.value_ref) for binding in review_step.inputs] == [
        ("evidence", "output:evidence")
    ]
    manifest_nodes = {node.id: node for node in manifest.nodes}
    assert manifest_nodes["execute"].outputs == ("execute_output", "evidence")
    assert manifest_nodes["review"].metadata["input_bindings"]["evidence"]["value_ref"] == (
        "output:evidence"
    )


@pytest.mark.parametrize(
    ("source_name", "halt_call"),
    [
        ("intrinsic_missing_required_keyword", "halt()"),
        ("intrinsic_wrong_keyword_set", "halt(route_id='human_gate')"),
    ],
)
def test_source_compiler_rejects_malformed_intrinsic_keyword_sets(
    source_name: str,
    halt_call: str,
) -> None:
    source = f"""
from arnold.workflow.authoring import halt, workflow

@workflow(id="{source_name}", version="1.0")
def flow() -> None:
    {halt_call}
"""

    result = workflow.check_workflow_source(source, source_path=f"{source_name}.py")

    assert not result.ok
    assert _codes(result) == {diagnostics.DiagnosticCode.UNSUPPORTED_SYNTAX}
    assert [
        diagnostic.message
        for diagnostic in result.diagnostics
        if diagnostic.code is diagnostics.DiagnosticCode.UNSUPPORTED_SYNTAX
    ] == [
        "compiler intrinsic call is outside the V1 authoring grammar",
        "compiler intrinsic calls are not workflow component steps",
    ]
    with pytest.raises(workflow.SourceCompileError) as source_error:
        workflow.compile_workflow_source(source, source_path=f"{source_name}.py")
    assert _diagnostic_codes(source_error.value.diagnostics) == {
        diagnostics.DiagnosticCode.UNSUPPORTED_SYNTAX
    }


@pytest.mark.parametrize(
    ("fixture_name", "expected_topology_hash", "expected_manifest_hash"),
    [
        (
            "valid_direct_linear",
            "sha256:b8241316a814bb9145914b9fa079363215a7b71b7b634390374edb0174a47bc5",
            "sha256:a1d884c2d6116aa82d1d8304b36f6c728b81e71ca2a69dd51d37d6bcdfec8585",
        ),
        (
            "valid_function_linear",
            "sha256:552872e0ffacd32b29cd25ad55298ef4866d186be0326d3f7c90293f70ad866e",
            "sha256:63846e02a691f11141d8a439f647eda7f25609f1a9f9e803b86d0b6ca6a18ada",
        ),
    ],
)
def test_source_compiler_valid_fixture_manifest_goldens_are_stable(
    fixture_name: str,
    expected_topology_hash: str,
    expected_manifest_hash: str,
) -> None:
    source_path = Path(f"tests/fixtures/workflow_authoring/{fixture_name}.py")

    manifest = workflow.compile_workflow_file(source_path)
    manifest_payload = json.loads(manifest.to_json())

    assert manifest.topology_hash == expected_topology_hash
    assert manifest.manifest_hash == expected_manifest_hash
    assert manifest_payload["topology_hash"] == expected_topology_hash
    assert manifest_payload["manifest_hash"] == expected_manifest_hash
    assert [node["id"] for node in manifest_payload["nodes"]] == ["execute", "plan", "review"]
    assert [edge["id"] for edge in manifest_payload["edges"]] == [
        "execute-review",
        "plan-execute",
    ]
    assert all(node["metadata"]["component_ref"].endswith(f":{node['id']}") for node in manifest_payload["nodes"])


def test_source_compiler_m3_expectation_fixture_set_is_complete() -> None:
    source_cases = {path.stem for path in M3_FIXTURE_DIR.glob("*.py")}
    sidecar_cases = {
        path.name.removesuffix(".expected.json")
        for path in M3_FIXTURE_DIR.glob("*.expected.json")
    }

    assert source_cases == (
        set(M3_VALID_FIXTURES)
        | set(M3_INVALID_FIXTURES)
        | set(M3_SPECIALIZED_INVALID_FIXTURES)
    )
    assert sidecar_cases == source_cases


@pytest.mark.parametrize("fixture_name", M3_VALID_FIXTURES)
def test_source_compiler_m3_valid_expectation_fixtures_lower_to_pinned_contract(
    fixture_name: str,
) -> None:
    sidecar = _load_m3_sidecar(fixture_name)
    source_path = M3_FIXTURE_DIR / f"{fixture_name}.py"
    expected = sidecar["expected_lowering"]

    pipeline = workflow.lower_workflow_file(source_path)

    assert sidecar["outcome"] == "valid"
    assert pipeline.id == expected["workflow_id"]
    assert [step.id for step in pipeline.steps] == expected["nodes"]

    expected_routes = expected.get("routes", [])
    if expected_routes:
        _assert_ordered_contracts(
            [_route_contract(route, include_extended=True) for route in pipeline.routes],
            expected_routes,
        )

    expected_loop = expected.get("loop_policy")
    if expected_loop is not None:
        loop_nodes = [
            step for step in pipeline.steps
            if step.policy is not None and step.policy.loop is not None
        ]
        assert len(loop_nodes) == 1
        assert loop_nodes[0].policy is not None
        assert loop_nodes[0].policy.loop is not None
        loop_slot_contract = {
            key: expected_loop[key]
            for key in ("max_iterations", "until_ref")
            if key in expected_loop
        }
        _assert_contract(_policy_contract(loop_nodes[0].policy), {"loop": loop_slot_contract})
        assert any(
            route.source == expected["backedge"]["source"]
            and route.target == expected["backedge"]["target"]
            and route.condition_ref == expected["backedge"]["condition_ref"]
            for route in pipeline.routes
        )

    expected_loop_policies = (
        expected.get("loop_policies")
        or expected.get("loop_policy_carriers")
        or expected.get("loop_policy_nodes")
        or {}
    )
    if expected_loop_policies:
        nodes = {step.id: step for step in pipeline.steps}
        for node_id, loop_contract in _node_contract_items(expected_loop_policies):
            assert nodes[node_id].policy is not None
            _assert_contract(_policy_contract(nodes[node_id].policy), {"loop": loop_contract})

    expected_node_policies = expected.get("node_policies", {})
    if expected_node_policies:
        nodes = {step.id: step for step in pipeline.steps}
        for node_id, policy_contract in expected_node_policies.items():
            assert nodes[node_id].policy is not None
            _assert_contract(_policy_contract(nodes[node_id].policy), policy_contract)

    expected_workflow_policy = expected.get("workflow_policy")
    if expected_workflow_policy:
        assert pipeline.policy is not None
        _assert_contract(_policy_contract(pipeline.policy), expected_workflow_policy)

    expected_step_metadata = expected.get("step_metadata", expected.get("metadata", {}))
    if expected_step_metadata:
        nodes = {step.id: step for step in pipeline.steps}
        for node_id, metadata_contract in expected_step_metadata.items():
            _assert_contract(dict(nodes[node_id].metadata), metadata_contract)

    expected_fanout_policies = expected.get("fanout_policies", {})
    if expected_fanout_policies:
        nodes = {step.id: step for step in pipeline.steps}
        for node_id, fanout_contract in expected_fanout_policies.items():
            assert nodes[node_id].policy is not None
            _assert_contract(_policy_contract(nodes[node_id].policy), {"fanout": fanout_contract})

    expected_capabilities = expected.get("capabilities", {})
    if expected_capabilities:
        nodes = {step.id: step for step in pipeline.steps}
        for node_id, capability_contracts in expected_capabilities.items():
            _assert_ordered_contracts(
                [_capability_contract(capability) for capability in nodes[node_id].capabilities],
                capability_contracts,
            )

    expected_workflow_capabilities = expected.get("workflow_capabilities", [])
    if expected_workflow_capabilities:
        _assert_ordered_contracts(
            [_capability_contract(capability) for capability in pipeline.capabilities],
            expected_workflow_capabilities,
        )

    expected_subflows = expected.get("subflows", {})
    if expected_subflows:
        nodes = {step.id: step for step in pipeline.steps}
        for node_id, subflow_contract in expected_subflows.items():
            assert nodes[node_id].kind == "subpipeline"
            assert nodes[node_id].subpipeline is not None
            _assert_contract(
                _compact_contract(nodes[node_id].subpipeline),
                subflow_contract,
            )


@pytest.mark.parametrize("fixture_name", M3_INVALID_FIXTURES)
def test_source_compiler_m3_negative_sidecars_pin_source_diagnostics(
    fixture_name: str,
) -> None:
    sidecar = _load_m3_sidecar(fixture_name)
    source_path = M3_FIXTURE_DIR / f"{fixture_name}.py"

    result = workflow.check_workflow_file(source_path)
    if result.ok:
        try:
            workflow.lower_workflow_file(source_path)
        except workflow.SourceCompileError as error:
            result = error

    assert sidecar["outcome"] == "invalid"
    assert _diagnostic_payloads(result) == sidecar["expected_diagnostics"]


@pytest.mark.parametrize("fixture_name", M3_SPECIALIZED_INVALID_FIXTURES)
def test_source_compiler_m3_specialized_negative_sidecars_pin_s5_checker_diagnostics(
    fixture_name: str,
) -> None:
    sidecar = _load_m3_sidecar(fixture_name)
    source_path = M3_FIXTURE_DIR / f"{fixture_name}.py"

    result = _check_specialized_m3_fixture(source_path)

    assert sidecar["outcome"] == "invalid"
    assert _diagnostic_payloads(result) == sidecar["expected_diagnostics"]


def test_source_compiler_m0_expectation_fixture_set_is_complete() -> None:
    source_cases = {path.stem for path in M0_FIXTURE_DIR.glob("*.py")}
    sidecar_cases = {
        path.name.removesuffix(".expected.json")
        for path in M0_FIXTURE_DIR.glob("*.expected.json")
    }

    assert set(M0_VALID_FIXTURES).issubset(source_cases)
    assert sidecar_cases == source_cases


@pytest.mark.parametrize("fixture_name", M0_VALID_FIXTURES)
def test_source_compiler_m0_valid_expectation_fixtures_lower_to_pinned_contract(
    fixture_name: str,
) -> None:
    sidecar = _load_m0_sidecar(fixture_name)
    source_path = M0_FIXTURE_DIR / f"{fixture_name}.py"
    expected = sidecar.get("expected_lowering")
    if expected is None:
        provenance = sidecar["expected_provenance"]
        expected = {
            "workflow_id": provenance["workflow"]["id"],
            "nodes": [step["id"] for step in provenance["steps"]],
        }

    pipeline = workflow.lower_workflow_file(source_path)

    assert sidecar["outcome"] == "valid"
    assert pipeline.id == expected["workflow_id"]
    assert [step.id for step in pipeline.steps] == expected["nodes"]

    expected_subflows = expected.get("subflows", {})
    if expected_subflows:
        nodes = {step.id: step for step in pipeline.steps}
        for node_id, subflow_contract in expected_subflows.items():
            assert nodes[node_id].kind == "subpipeline"
            assert nodes[node_id].subpipeline is not None
            _assert_contract(
                _compact_contract(nodes[node_id].subpipeline),
                subflow_contract,
            )


def test_source_compiler_m3_regression_keeps_existing_direct_and_function_linear_contracts() -> None:
    direct = workflow.lower_workflow_file(FIXTURE_DIR / "valid_direct_linear.py")
    function = workflow.lower_workflow_file(FIXTURE_DIR / "valid_function_linear.py")

    assert [step.id for step in direct.steps] == ["plan", "execute", "review"]
    assert [route.id for route in direct.routes] == ["plan-execute", "execute-review"]
    assert [step.id for step in function.steps] == ["plan", "execute", "review"]
    assert [route.id for route in function.routes] == ["plan-execute", "execute-review"]


def test_source_compiler_m3_parses_subflow_calls_before_generic_steps() -> None:
    source_path = M3_FIXTURE_DIR / "valid_m3_subflow_ref.py"

    result = workflow.check_workflow_file(source_path)

    assert result.diagnostics == ()
    assert result.parsed_source.workflow is not None
    block = result.parsed_source.workflow.source_block
    assert [type(statement).__name__ for statement in block.statements] == [
        "ParsedStepCall",
        "ParsedStepCall",
        "ParsedSubflowCall",
    ]
    subflow = block.subflows[0]
    assert subflow.id == "nested-review"
    assert subflow.manifest_hash == (
        "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    )
    assert subflow.alias == "review"
    assert [(binding.name, binding.value_ref) for binding in subflow.inputs] == [
        ("evidence", "output:evidence")
    ]


def test_source_compiler_m3_subflow_uses_resolver_provided_manifest_identity() -> None:
    source = """
from arnold.workflow.authoring import workflow
from tests.fixtures.workflow_authoring.components import execute, plan, review_subflow

@workflow(id="metadata-subflow")
def flow(brief):
    plan_output = plan(id="plan", brief=brief)
    evidence = execute(id="execute", plan=plan_output)
    review_subflow(id="nested-review", evidence=evidence)
"""

    pipeline = workflow.lower_workflow_source(source, source_path="metadata_subflow.py")

    subflow = pipeline.steps[-1]
    assert subflow.kind == "subpipeline"
    assert subflow.subpipeline is not None
    assert subflow.subpipeline.manifest_hash == (
        "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    )
    assert subflow.subpipeline.alias is None
    assert [(input.name, input.value_ref) for input in subflow.inputs] == [
        ("evidence", "output:evidence")
    ]


def test_source_compiler_m3_subflow_resolver_identity_does_not_import_child_workflow() -> None:
    source = """
from arnold.workflow.authoring import workflow
from project.workflow_components import plan, review_subflow

@workflow(id="resolver-subflow")
def flow(brief):
    evidence = plan(id="plan", brief=brief)
    review_subflow(id="nested-review", evidence=evidence)
"""
    child_module = "project.child_workflows.review"
    sys.modules.pop(child_module, None)
    resolver = _Resolver(
        {
            "project.workflow_components:plan": authoring.StepComponent(
                id="plan",
                provenance=authoring.ComponentProvenance(
                    module="project.workflow_components",
                    qualname="plan",
                    export_name="plan",
                ),
            ),
            "project.workflow_components:review_subflow": authoring.SubflowComponent(
                id="review_subflow",
                provenance=authoring.ComponentProvenance(
                    module="project.workflow_components",
                    qualname="review_subflow",
                    export_name="review_subflow",
                ),
                workflow_id=child_module,
                version="1.0",
                metadata={
                    "manifest_hash": (
                        "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                    )
                },
            ),
        }
    )

    pipeline = workflow.lower_workflow_source(
        source,
        source_path="resolver_subflow.py",
        resolver=resolver,
    )

    subflow = pipeline.steps[-1]
    assert subflow.kind == "subpipeline"
    assert subflow.subpipeline is not None
    assert subflow.subpipeline.manifest_hash == (
        "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    )
    assert resolver.resolved == (
        ImportRef("project.workflow_components", "plan"),
        ImportRef("project.workflow_components", "review_subflow"),
    )
    assert child_module not in sys.modules


def test_source_compiler_m3_subflow_rejects_workflow_id_version_without_manifest_hash() -> None:
    source = """
from arnold.workflow.authoring import workflow
from project.workflow_components import plan, review_subflow

@workflow(id="workflow-id-only-subflow")
def flow(brief):
    evidence = plan(id="plan", brief=brief)
    review_subflow(id="nested-review", evidence=evidence)
"""
    resolver = _Resolver(
        {
            "project.workflow_components:plan": authoring.StepComponent(
                id="plan",
                provenance=authoring.ComponentProvenance(
                    module="project.workflow_components",
                    qualname="plan",
                    export_name="plan",
                ),
            ),
            "project.workflow_components:review_subflow": authoring.SubflowComponent(
                id="review_subflow",
                provenance=authoring.ComponentProvenance(
                    module="project.workflow_components",
                    qualname="review_subflow",
                    export_name="review_subflow",
                ),
                workflow_id="nested-review",
                version="1.0",
            ),
        }
    )

    result = workflow.check_workflow_source(
        source,
        source_path="workflow_id_only_subflow.py",
        resolver=resolver,
    )

    assert _diagnostic_payloads(result) == [
        {
            "code": "AWF015_UNSUPPORTED_SUBFLOW_REFERENCE",
            "message": "subflow manifest_hash must be a literal or resolver-provided identity",
            "source_span": {
                "path": "workflow_id_only_subflow.py",
                "start_line": 8,
                "start_column": 5,
                "end_line": 8,
                "end_column": 58,
            },
        }
    ]
    assert result.parsed_source.workflow is not None
    assert result.parsed_source.workflow.source_block.subflows == ()


def test_source_compiler_m3_subflow_rejects_non_canonical_resolver_manifest_hash() -> None:
    source = """
from arnold.workflow.authoring import workflow
from project.workflow_components import plan, review_subflow

@workflow(id="bad-resolver-subflow")
def flow(brief):
    evidence = plan(id="plan", brief=brief)
    review_subflow(id="nested-review", evidence=evidence)
"""
    resolver = _Resolver(
        {
            "project.workflow_components:plan": authoring.StepComponent(
                id="plan",
                provenance=authoring.ComponentProvenance(
                    module="project.workflow_components",
                    qualname="plan",
                    export_name="plan",
                ),
            ),
            "project.workflow_components:review_subflow": authoring.SubflowComponent(
                id="review_subflow",
                provenance=authoring.ComponentProvenance(
                    module="project.workflow_components",
                    qualname="review_subflow",
                    export_name="review_subflow",
                ),
                workflow_id="nested-review",
                version="1.0",
                metadata={"manifest_hash": "nested-review:1.0"},
            ),
        }
    )

    result = workflow.check_workflow_source(
        source,
        source_path="bad_resolver_subflow.py",
        resolver=resolver,
    )

    assert _diagnostic_payloads(result) == [
        {
            "code": "AWF015_UNSUPPORTED_SUBFLOW_REFERENCE",
            "message": "subflow manifest_hash must be a literal or resolver-provided identity",
            "source_span": {
                "path": "bad_resolver_subflow.py",
                "start_line": 8,
                "start_column": 5,
                "end_line": 8,
                "end_column": 58,
            },
        }
    ]


def test_source_compiler_m3_rejects_executable_child_workflow_code_in_subflow_calls() -> None:
    source = """
from arnold.workflow.authoring import workflow
from tests.fixtures.workflow_authoring.components import execute, plan, review_subflow

@workflow(id="child-code-subflow")
def flow(brief):
    plan_output = plan(id="plan", brief=brief)
    evidence = execute(id="execute", plan=plan_output)
    review_subflow(id="nested-review", steps=[plan(id="child")], evidence=evidence)
"""

    result = workflow.check_workflow_source(source, source_path="child_code_subflow.py")

    assert _diagnostic_payloads(result) == [
        {
            "code": "AWF015_UNSUPPORTED_SUBFLOW_REFERENCE",
            "message": (
                "subflow calls must reference a manifest identity, not executable child workflow code"
            ),
            "source_span": {
                "path": "child_code_subflow.py",
                "start_line": 9,
                "start_column": 5,
                "end_line": 9,
                "end_column": 84,
            },
        }
    ]


def test_source_compiler_m3_native_nested_workflow_requires_literal_call_site_id() -> None:
    source = """
from arnold.pipeline import step, workflow

@step(id="child_step", inputs={"draft"}, outputs={"verdict"})
def child_step(draft):
    ...

@workflow(id="child", inputs={"draft"}, outputs={"verdict"})
def child(draft):
    return child_step(id="child_step", draft=draft)

@workflow(id="parent", inputs={"draft"}, outputs={"verdict"})
def parent(draft):
    verdict = child(draft=draft)
    return verdict
"""

    result = workflow.check_workflow_source(source, source_path="missing_nested_id.py")

    assert _diagnostic_payloads(result) == [
        {
            "code": "AWF220_MISSING_CALL_SITE_ID",
            "message": "nested workflow calls must include a literal id keyword",
            "component_ref": "missing_nested_id:child",
            "source_span": {
                "path": "missing_nested_id.py",
                "start_line": 14,
                "start_column": 15,
                "end_line": 14,
                "end_column": 33,
            },
        }
    ]


def test_source_compiler_m3_native_nested_workflow_validates_child_input_schema() -> None:
    source = """
from arnold.pipeline import step, workflow

@step(id="child_step", inputs={"draft"}, outputs={"verdict"})
def child_step(draft):
    ...

@workflow(id="child", inputs={"draft"}, outputs={"verdict"})
def child(draft):
    return child_step(id="child_step", draft=draft)

@workflow(id="parent", inputs={"brief"}, outputs={"verdict"})
def parent(brief):
    verdict = child(id="child_call", missing=brief)
    return verdict
"""

    result = workflow.check_workflow_source(source, source_path="bad_nested_schema.py")

    assert _diagnostic_payloads(result) == [
        {
            "code": "AWF230_CHILD_INPUT_SCHEMA_MISMATCH",
            "message": "nested workflow input bindings must exactly match the child workflow inputs",
            "component_ref": "bad_nested_schema:child",
            "source_span": {
                "path": "bad_nested_schema.py",
                "start_line": 14,
                "start_column": 15,
                "end_line": 14,
                "end_column": 52,
            },
        }
    ]


def test_source_compiler_m3_parses_literal_branch_blocks_without_lowering_routes() -> None:
    source_path = M3_FIXTURE_DIR / "valid_m3_branch_routes.py"

    result = workflow.check_workflow_file(source_path)

    assert result.diagnostics == ()
    assert result.parsed_source.workflow is not None
    block = result.parsed_source.workflow.source_block
    assert [type(statement).__name__ for statement in block.statements] == [
        "ParsedStepCall",
        "ParsedBranchBlock",
    ]
    branch = block.branches[0]
    assert branch.decision_output == "decision"
    assert [
        arm.condition.literal if arm.condition is not None else "else"
        for arm in branch.arms
    ] == ["approve", "revise", "else"]
    assert [arm.terminal for arm in branch.arms] == [False, False, False]
    assert branch.merged_outputs == {}


def test_source_compiler_m3_merges_only_outputs_from_every_reachable_branch() -> None:
    source = """
from arnold.workflow.authoring import workflow
from tests.fixtures.workflow_authoring.components import execute, review, route

@workflow(id="merge-branch")
def flow(brief):
    decision = route(id="route", brief=brief)
    if decision == "approve":
        shared = execute(id="execute-approved", plan=decision)
    else:
        shared = execute(id="execute-fallback", plan=decision)
    review(id="review", evidence=shared)
"""

    result = workflow.check_workflow_source(source, source_path="merge_branch.py")

    assert result.diagnostics == ()
    assert result.parsed_source.workflow is not None
    block = result.parsed_source.workflow.source_block
    assert [type(statement).__name__ for statement in block.statements] == [
        "ParsedStepCall",
        "ParsedBranchBlock",
        "ParsedStepCall",
    ]
    assert set(block.branches[0].merged_outputs) == {"shared"}
    assert block.steps[-1].inputs[0].value_ref == "output:shared"

    pipeline = workflow.lower_workflow_source(source, source_path="merge_branch.py")
    assert [step.id for step in pipeline.steps] == [
        "route",
        "execute-approved",
        "execute-fallback",
        "review",
    ]
    assert [_route_contract(route) for route in pipeline.routes] == [
        {
            "source": "route",
            "target": "execute-approved",
            "label": "approve",
            "condition_ref": "route.decision.eq.approve",
        },
        {
            "source": "route",
            "target": "execute-fallback",
            "label": "else",
            "condition_ref": "route.decision.else",
        },
        {"source": "execute-approved", "target": "review"},
        {"source": "execute-fallback", "target": "review"},
    ]


def test_source_compiler_m3_applies_visible_default_route_metadata_bindings() -> None:
    source = """
from arnold.workflow.authoring import workflow
from project.workflow_components import execute, plan

@workflow(id="bound-default-route")
def flow() -> None:
    plan(id="plan")
    execute(id="execute")
"""
    resolver = _Resolver(
        {
            "project.workflow_components:plan": _step_component(
                "plan",
                route_bindings=(
                    {
                        "id": "plan:execute",
                        "label": "default",
                        "target_ref": "execute",
                        "condition_ref": "ready",
                    },
                ),
            ),
            "project.workflow_components:execute": _step_component("execute"),
        }
    )

    pipeline = workflow.lower_workflow_source(
        source,
        source_path="bound_default_route.py",
        resolver=resolver,
    )

    assert [(route.id, route.source, route.target, route.label, route.condition_ref) for route in pipeline.routes] == [
        ("plan:execute", "plan", "execute", "default", "ready")
    ]


def test_source_compiler_m3_applies_visible_branch_route_metadata_bindings() -> None:
    source = """
from arnold.workflow.authoring import workflow
from project.workflow_components import decide, execute, stop

@workflow(id="bound-branch-route")
def flow() -> None:
    decision = decide(id="decide")
    if decision == "approve":
        execute(id="execute")
    else:
        stop(id="stop")
"""
    resolver = _Resolver(
        {
            "project.workflow_components:decide": _step_component(
                "decide",
                route_bindings=(
                    {
                        "id": "decide:execute",
                        "label": "approve",
                        "target_ref": "execute",
                        "condition_ref": "approved",
                    },
                    {
                        "id": "decide:halt",
                        "label": "else",
                        "target_ref": "stop",
                        "condition_ref": "fallback",
                    },
                ),
            ),
            "project.workflow_components:execute": _step_component("execute"),
            "project.workflow_components:stop": _step_component("stop"),
        }
    )

    pipeline = workflow.lower_workflow_source(
        source,
        source_path="bound_branch_route.py",
        resolver=resolver,
    )

    assert [(route.id, route.label, route.condition_ref) for route in pipeline.routes] == [
        ("decide:execute", "approve", "approved"),
        ("decide:halt", "else", "fallback"),
    ]


def test_source_compiler_m3_lowers_capabilities_and_whitelisted_step_metadata() -> None:
    source = """
from arnold.workflow.authoring import workflow
from project.workflow_components import execute

@workflow(id="capability-metadata")
def flow() -> None:
    execute(id="execute")
"""
    resolver = _Resolver(
        {
            "project.workflow_components:execute": _step_component(
                "execute",
                metadata={
                    "capability_requirements": (
                        {"id": "artifact:write"},
                        {"id": "human:review", "route": "operator", "required": False},
                    ),
                    "handler_ref": "project.handlers:execute",
                    "terminal": True,
                    "policy_id": "project:implicit-policy",
                    "unapproved": "ignored",
                },
            ),
        }
    )

    pipeline = workflow.lower_workflow_source(
        source,
        source_path="capability_metadata.py",
        resolver=resolver,
    )

    step = pipeline.steps[0]
    assert [(capability.id, capability.route, capability.required) for capability in step.capabilities] == [
        ("artifact:write", "default", True),
        ("human:review", "operator", False),
    ]
    assert step.metadata["handler_ref"] == "project.handlers:execute"
    assert step.metadata["terminal"] is True
    assert "policy_id" not in step.metadata
    assert "unapproved" not in step.metadata
    assert step.policy is None


def test_source_compiler_m3_rejects_malformed_capability_metadata() -> None:
    source = """
from arnold.workflow.authoring import workflow
from project.workflow_components import execute

@workflow(id="malformed-capability-metadata")
def flow() -> None:
    execute(id="execute")
"""
    resolver = _Resolver(
        {
            "project.workflow_components:execute": _step_component(
                "execute",
                metadata={"capability_requirements": ({"id": "artifact:write", "required": "yes"},)},
            ),
        }
    )

    with pytest.raises(workflow.SourceCompileError) as source_error:
        workflow.lower_workflow_source(
            source,
            source_path="malformed_capability_metadata.py",
            resolver=resolver,
        )

    assert _diagnostic_payloads(source_error.value)[0]["code"] == (
        "AWF020_MALFORMED_CAPABILITY_METADATA"
    )
    assert _diagnostic_payloads(source_error.value)[0]["message"] == (
        "capability requirement metadata must declare string id, optional string route, and optional boolean required"
    )


@pytest.mark.parametrize(
    ("route_bindings", "expected_message"),
    [
        (
            (
                {"id": "plan:execute", "label": "default", "target_ref": "execute"},
                {"id": "plan:execute-again", "label": "default", "target_ref": "execute"},
            ),
            "route binding metadata is ambiguous for a visible lowered route",
        ),
        (
            (
                {"id": "plan:review", "label": "default", "target_ref": "review"},
            ),
            "route binding metadata does not match a visible lowered route",
        ),
        (
            (
                {"id": "plan:execute", "label": "approve", "target_ref": "execute"},
            ),
            "route binding metadata does not match a visible lowered route",
        ),
    ],
)
def test_source_compiler_m3_rejects_ambiguous_or_stale_route_metadata_bindings(
    route_bindings: tuple[dict[str, str], ...],
    expected_message: str,
) -> None:
    source = """
from arnold.workflow.authoring import workflow
from project.workflow_components import execute, plan

@workflow(id="invalid-route-binding")
def flow() -> None:
    plan(id="plan")
    execute(id="execute")
"""
    resolver = _Resolver(
        {
            "project.workflow_components:plan": _step_component(
                "plan",
                route_bindings=route_bindings,
            ),
            "project.workflow_components:execute": _step_component("execute"),
        }
    )

    with pytest.raises(workflow.SourceCompileError) as source_error:
        workflow.lower_workflow_source(
            source,
            source_path="invalid_route_binding.py",
            resolver=resolver,
        )

    assert _diagnostic_payloads(source_error.value)[0]["code"] == "AWF018_ROUTE_METADATA_MISMATCH"
    assert _diagnostic_payloads(source_error.value)[0]["message"] == expected_message


def test_source_compiler_m3_accepts_unique_branch_local_target_for_route_metadata() -> None:
    source = """
from arnold.workflow.authoring import workflow
from project.workflow_components import decide, finalize

@workflow(id="branch-local-route-binding")
def flow() -> None:
    decision = decide(id="decide")
    if decision == "approve":
        finalize(id="approve_finalize")
    else:
        finalize(id="reject_finalize")
"""
    resolver = _Resolver(
        {
            "project.workflow_components:decide": _step_component(
                "decide",
                route_bindings=(
                    {"id": "decide:finalize", "label": "approve", "target_ref": "finalize"},
                ),
            ),
            "project.workflow_components:finalize": _step_component("finalize"),
        }
    )

    lowered = workflow.lower_workflow_source(
        source,
        source_path="branch_local_route_binding.py",
        resolver=resolver,
    )

    assert tuple((route.id, route.source, route.target, route.label) for route in lowered.routes) == (
        ("decide:finalize", "decide", "approve_finalize", "approve"),
        ("decide-reject_finalize", "decide", "reject_finalize", "else"),
    )


def test_source_compiler_m3_binds_route_metadata_to_parallel_map_reducer_target() -> None:
    source = """
from arnold.pipeline import parallel_map
from arnold.workflow.authoring import workflow
from project.workflow_components import decide, execute, execute_child, finalize

@workflow(id="parallel-map-route-binding")
def flow() -> None:
    decision = decide(id="decide")
    if decision == "approve":
        finalize_payload = finalize(id="approve_finalize")
        parallel_map(
            id="approve_execute_batches",
            items="project.items",
            step=execute_child,
            reducer=execute,
            path_template="execute/{index}",
        )
    else:
        return None
"""
    resolver = _Resolver(
        {
            "project.workflow_components:decide": _step_component("decide"),
            "project.workflow_components:execute": _step_component("execute"),
            "project.workflow_components:execute_child": authoring.ComponentContract(
                id="execute_child",
                kind=authoring.ComponentKind.WORKFLOW,
                provenance=authoring.ComponentProvenance(
                    module="project.workflow_components",
                    qualname="execute_child",
                    export_name="execute_child",
                ),
            ),
            "project.workflow_components:finalize": _step_component(
                "finalize",
                route_bindings=(
                    {"id": "finalize:execute", "label": "default", "target_ref": "execute"},
                ),
            ),
        }
    )

    lowered = workflow.lower_workflow_source(
        source,
        source_path="parallel_map_route_binding.py",
        resolver=resolver,
    )

    assert (
        "finalize:execute",
        "approve_finalize",
        "approve_execute_batches",
        "default",
    ) in tuple((route.id, route.source, route.target, route.label) for route in lowered.routes)


@pytest.mark.parametrize(
    ("condition", "expected_message"),
    [
        (
            'decision == "approve" or decision == "revise"',
            "branch route conditions must compare a decision output to a literal string",
        ),
        (
            "decision == 1",
            "branch route comparisons must use a literal string target",
        ),
    ],
)
def test_source_compiler_m3_rejects_unsupported_branch_conditions(
    condition: str,
    expected_message: str,
) -> None:
    source = f"""
from arnold.workflow.authoring import workflow
from tests.fixtures.workflow_authoring.components import execute, route

@workflow(id="invalid-branch")
def flow(brief):
    decision = route(id="route", brief=brief)
    if {condition}:
        execute(id="execute", plan=decision)
"""

    result = workflow.check_workflow_source(source, source_path="invalid_branch.py")

    assert _diagnostic_payloads(result)[0]["code"] == "AWF011_DYNAMIC_ROUTING_CONDITION"
    assert _diagnostic_payloads(result)[0]["message"] == expected_message


def test_source_compiler_m3_accepts_imported_strenum_branch_targets() -> None:
    source = """
from arnold.workflow.authoring import workflow
from project.workflow_components import execute, route
from arnold_pipelines.megaplan.outcomes import GateOutcome

@workflow(id="enum-branch")
def flow(brief):
    decision = route(id="route", brief=brief)
    if decision == GateOutcome.PROCEED:
        execute(id="execute", plan=decision)
    else:
        execute(id="fallback", plan=decision)
"""

    resolver = _Resolver(
        {
            "project.workflow_components:route": _step_component("route"),
            "project.workflow_components:execute": _step_component("execute"),
        }
    )
    result = workflow.check_workflow_source(
        source,
        source_path="enum_branch.py",
        resolver=resolver,
    )

    assert result.diagnostics == ()


def test_source_compiler_m3_rejects_repeated_branch_conditions() -> None:
    source = """
from arnold.workflow.authoring import workflow
from tests.fixtures.workflow_authoring.components import execute, route

@workflow(id="repeated-branch")
def flow(brief):
    decision = route(id="route", brief=brief)
    if decision == "approve":
        execute(id="execute-approved", plan=decision)
    elif decision == "approve":
        execute(id="execute-repeated", plan=decision)
"""

    result = workflow.check_workflow_source(source, source_path="repeated_branch.py")

    assert _diagnostic_payloads(result)[0]["code"] == "AWF011_DYNAMIC_ROUTING_CONDITION"
    assert (
        _diagnostic_payloads(result)[0]["message"]
        == "branch route comparisons must not repeat literal targets"
    )


def test_source_compiler_m3_route_ambiguity_diagnostics_are_explicit() -> None:
    expected_codes = {}
    for fixture_name in (
        "invalid_m3_repeated_route_comparison",
        "invalid_m3_ambiguous_route_metadata",
        "invalid_m3_ambiguous_loop",
    ):
        expected = json.loads(
            (M3_FIXTURE_DIR / f"{fixture_name}.expected.json").read_text(encoding="utf-8")
        )["expected_diagnostics"][0]
        expected_codes[fixture_name] = expected["code"]

    assert expected_codes == {
        "invalid_m3_repeated_route_comparison": "AWF011_DYNAMIC_ROUTING_CONDITION",
        "invalid_m3_ambiguous_route_metadata": "AWF018_ROUTE_METADATA_MISMATCH",
        "invalid_m3_ambiguous_loop": "AWF013_AMBIGUOUS_LOOP",
    }
    assert (
        diagnostics.diagnostic_spec(diagnostics.DiagnosticCode.DYNAMIC_ROUTING_CONDITION).remediation
        == "compare one prior decision output to one unique literal string per branch arm"
    )
    assert (
        diagnostics.diagnostic_spec(diagnostics.DiagnosticCode.ROUTE_METADATA_MISMATCH).remediation
        == "preserve route ids, labels, condition refs, and whitelisted metadata during lowering"
    )
    assert "while True" in diagnostics.diagnostic_spec(
        diagnostics.DiagnosticCode.AMBIGUOUS_LOOP
    ).remediation


def test_source_compiler_reports_static_prompt_resource_dependency_diagnostics() -> None:
    source_path = FIXTURE_DIR / "invalid_static_prompt_resource_dependencies.py"

    result = workflow.check_workflow_file(source_path)

    assert [diagnostic.code for diagnostic in result.diagnostics] == [
        diagnostics.DiagnosticCode.MISSING_PROMPT_DEPENDENCY,
        diagnostics.DiagnosticCode.MISSING_RESOURCE_DEPENDENCY,
    ]
    assert [diagnostic.source_span.start_line for diagnostic in result.diagnostics if diagnostic.source_span] == [
        10,
        11,
    ]
    assert result.diagnostics[0].remediation == (
        "attach a PromptComponent to the StepComponent or remove the static prompt_key metadata"
    )
    assert result.diagnostics[0].details["prompt_key"] == "review"
    assert result.diagnostics[1].remediation == (
        "declare the required resource in component metadata resources or remove the dependency"
    )
    assert result.diagnostics[1].details["missing_resources"] == ("model",)
    assert result.diagnostics[1].details["available_resources"] == ("cache",)


def test_source_compiler_does_not_render_runtime_prompt_templates_as_awf_diagnostics() -> None:
    source = """
from arnold.workflow.authoring import workflow
from project.workflow_components import runtime_prompt_step

workflow(id="runtime-prompt-boundary", steps=[runtime_prompt_step(id="draft")])
"""
    prompt = authoring.PromptComponent(
        id="runtime_prompt",
        provenance=authoring.ComponentProvenance(
            module="project.workflow_components",
            qualname="runtime_prompt",
            export_name="runtime_prompt",
        ),
        template="{runtime_value_missing_until_dispatch}",
        parameters=("runtime_value",),
    )
    resolver = _Resolver(
        {
            "project.workflow_components:runtime_prompt_step": authoring.StepComponent(
                id="runtime_prompt_step",
                provenance=authoring.ComponentProvenance(
                    module="project.workflow_components",
                    qualname="runtime_prompt_step",
                    export_name="runtime_prompt_step",
                ),
                prompt=prompt,
                metadata={"prompt_key": "runtime_prompt"},
            )
        }
    )

    result = workflow.check_workflow_source(
        source,
        source_path="runtime_prompt_boundary.py",
        resolver=resolver,
    )

    assert result.ok
    assert result.diagnostics == ()


def test_source_compiler_m3_rejects_implicit_branch_fallthrough() -> None:
    source = """
from arnold.workflow.authoring import workflow
from tests.fixtures.workflow_authoring.components import execute, review, route

@workflow(id="missing-fallthrough")
def flow(brief):
    decision = route(id="route", brief=brief)
    if decision == "approve":
        execute_output = execute(id="execute", plan=decision)
        review(id="review-approved", evidence=execute_output)
"""

    result = workflow.check_workflow_source(source, source_path="missing_fallthrough.py")

    assert _diagnostic_payloads(result)[0]["code"] == "AWF017_MISSING_FALLTHROUGH_ROUTE"
    assert (
        _diagnostic_payloads(result)[0]["message"]
        == "branch routes require an else arm to avoid implicit fallthrough"
    )


def test_source_compiler_m3_parses_bounded_loop_block_before_backedge_lowering() -> None:
    source_path = M3_FIXTURE_DIR / "valid_m3_bounded_loop.py"

    result = workflow.check_workflow_file(source_path)

    assert result.diagnostics == ()
    assert result.parsed_source.workflow is not None
    block = result.parsed_source.workflow.source_block
    assert [type(statement).__name__ for statement in block.statements] == [
        "ParsedStepCall",
        "ParsedLoopBlock",
    ]
    loop = block.loops[0]
    assert loop.policy.policy_ref.endswith(":bounded_review_loop")
    assert loop.policy.max_iterations == 3
    assert loop.policy.reentry_id == "execute"
    assert loop.policy.until_ref == "review.approved"
    assert type(loop.entry_statement).__name__ == "ParsedStepCall"
    assert loop.entry_statement is not None
    assert loop.entry_statement.id == "execute"
    assert [type(statement).__name__ for statement in loop.body.statements] == [
        "ParsedStepCall",
        "ParsedStepCall",
        "ParsedBranchBlock",
        "ParsedStepCall",
    ]
    assert [statement.id for statement in loop.body_tail_statements] == ["revise"]
    assert loop.follow_statement is None
    branch = loop.body.branches[0]
    assert [arm.condition.literal for arm in branch.arms if arm.condition] == ["approved"]
    assert [arm.terminal for arm in branch.arms] == [True]


def test_source_compiler_m3_lowers_bounded_loop_backedge_and_policy_for_cycle_validation() -> None:
    source_path = M3_FIXTURE_DIR / "valid_m3_bounded_loop.py"
    sidecar = _load_m3_sidecar("valid_m3_bounded_loop")
    expected = sidecar["expected_lowering"]

    pipeline = workflow.lower_workflow_file(source_path)

    assert [step.id for step in pipeline.steps] == expected["nodes"]
    routes = [_route_contract(route) for route in pipeline.routes]
    assert routes == [
        {"source": "plan", "target": "execute"},
        {"source": "execute", "target": "review"},
        {"source": "review", "target": "revise"},
        {
            "source": expected["backedge"]["source"],
            "target": expected["backedge"]["target"],
            "label": "reentry",
            "condition_ref": expected["backedge"]["condition_ref"],
        },
    ]

    loop_nodes = [
        step for step in pipeline.steps
        if step.policy is not None and step.policy.loop is not None
    ]
    assert [step.id for step in loop_nodes] == [expected["backedge"]["target"]]
    loop_policy = loop_nodes[0].policy
    assert loop_policy is not None
    assert loop_policy.loop is not None
    assert loop_policy.loop.max_iterations == expected["loop_policy"]["max_iterations"]
    assert loop_policy.loop.until_ref == expected["loop_policy"]["until_ref"]
    assert len(loop_policy.suspension_routes) == 1
    assert (
        loop_policy.suspension_routes[0].reentry_id
        == expected["backedge"]["condition_ref"]
    )

    manifest = workflow.compile_workflow_file(source_path)

    nodes = {node.id: node for node in manifest.nodes}
    edges = {edge.id: edge for edge in manifest.edges}
    assert nodes["execute"].policy is not None
    assert nodes["execute"].policy.loop is not None
    assert nodes["execute"].policy.suspension_routes[0].reentry_id == edges[
        "revise-execute"
    ].condition_ref


def test_source_compiler_m3_lowers_explicit_loop_tail_carriers_without_losing_policy_slots() -> None:
    source = """
from __future__ import annotations

from arnold.workflow.authoring import loop, workflow
from project.workflow_components import critique, gate, revise, tiebreaker_decide
from project.workflow_components import critique_loop, fast_retry, tiebreaker_transition, timeout

@workflow(id="explicit-tail-loop")
def flow(brief):
    loop(policy=critique_loop, reentry_id="critique")
    while True:
        critique_payload = critique(id="critique", brief=brief)
        recommendation = gate(id="gate", critique=critique_payload)
        if recommendation == "iterate":
            revise_payload = revise(id="revise", gate=recommendation, policy=fast_retry)
        elif recommendation == "tiebreaker":
            decision = tiebreaker_decide(
                id="tiebreaker_decide",
                gate=recommendation,
                policies=[timeout, tiebreaker_transition],
            )
        else:
            return None
"""
    resolver = _Resolver(
        {
            "project.workflow_components:critique": _step_component("critique"),
            "project.workflow_components:gate": _step_component("gate"),
            "project.workflow_components:revise": _step_component(
                "revise",
                route_bindings=(
                    {
                        "id": "revise:critique",
                        "label": "default",
                        "target_ref": "critique",
                        "condition_ref": "revise:loop",
                    },
                ),
            ),
            "project.workflow_components:tiebreaker_decide": _step_component(
                "tiebreaker_decide",
                route_bindings=(
                    {
                        "id": "tiebreaker_decide:critique",
                        "label": "iterate",
                        "target_ref": "critique",
                        "condition_ref": "tiebreaker:loop",
                    },
                ),
            ),
            "project.workflow_components:critique_loop": authoring.PolicyComponent(
                id="critique_loop",
                provenance=authoring.ComponentProvenance(
                    module="project.workflow_components",
                    qualname="critique_loop",
                    export_name="critique_loop",
                ),
                policy_type="loop",
                config={"max_iterations": 4, "until_ref": "critique_gate_pass"},
            ),
            "project.workflow_components:fast_retry": authoring.PolicyComponent(
                id="fast_retry",
                provenance=authoring.ComponentProvenance(
                    module="project.workflow_components",
                    qualname="fast_retry",
                    export_name="fast_retry",
                ),
                policy_type="retry",
                config={"max_attempts": 2, "retry_on": ("transient",)},
            ),
            "project.workflow_components:timeout": authoring.PolicyComponent(
                id="timeout",
                provenance=authoring.ComponentProvenance(
                    module="project.workflow_components",
                    qualname="timeout",
                    export_name="timeout",
                ),
                policy_type="timing",
                config={"timeout_seconds": 60},
            ),
            "project.workflow_components:tiebreaker_transition": authoring.PolicyComponent(
                id="tiebreaker_transition",
                provenance=authoring.ComponentProvenance(
                    module="project.workflow_components",
                    qualname="tiebreaker_transition",
                    export_name="tiebreaker_transition",
                ),
                policy_type="control-transition",
                config={
                    "transition_id": "tiebreaker:iterate",
                    "transition_type": "override",
                    "trigger_ref": "tiebreaker_decide.decision",
                    "target_ref": "critique",
                    "policy_ref": "critique_loop",
                },
            ),
        }
    )

    pipeline = workflow.lower_workflow_source(
        source,
        source_path="explicit_tail_loop.py",
        resolver=resolver,
    )

    assert [step.id for step in pipeline.steps] == [
        "critique",
        "gate",
        "revise",
        "tiebreaker_decide",
    ]
    assert [
        (route.id, route.source, route.target, route.label, route.condition_ref)
        for route in pipeline.routes
    ] == [
        ("critique-gate", "critique", "gate", "default", None),
        ("gate-revise", "gate", "revise", "iterate", "gate.recommendation.eq.iterate"),
        (
            "gate-tiebreaker_decide",
            "gate",
            "tiebreaker_decide",
            "tiebreaker",
            "gate.recommendation.eq.tiebreaker",
        ),
        ("revise:critique", "revise", "critique", "default", "revise:loop"),
        (
            "tiebreaker_decide:critique",
            "tiebreaker_decide",
            "critique",
            "iterate",
            "tiebreaker:loop",
        ),
    ]
    nodes = {step.id: step for step in pipeline.steps}
    assert nodes["critique"].policy is None

    revise_policy = nodes["revise"].policy
    assert revise_policy is not None
    assert revise_policy.retry is not None
    assert revise_policy.retry.max_attempts == 2
    assert revise_policy.loop is not None
    assert revise_policy.loop.max_iterations == 4
    assert revise_policy.loop.until_ref == "critique_gate_pass"
    assert revise_policy.suspension_routes[0].route_id == "revise:loop"
    assert revise_policy.suspension_routes[0].reentry_id == "revise:loop"

    tiebreaker_policy = nodes["tiebreaker_decide"].policy
    assert tiebreaker_policy is not None
    assert tiebreaker_policy.timing is not None
    assert tiebreaker_policy.timing.timeout_seconds == 60
    assert [transition.transition_id for transition in tiebreaker_policy.control_transitions] == [
        "tiebreaker:iterate"
    ]
    assert tiebreaker_policy.loop is not None
    assert tiebreaker_policy.loop.max_iterations == 4
    assert tiebreaker_policy.suspension_routes[0].route_id == "tiebreaker:loop"
    assert tiebreaker_policy.suspension_routes[0].reentry_id == "tiebreaker:loop"


@pytest.mark.parametrize(
    ("revise_bindings", "tiebreaker_bindings", "expected_message"),
    [
        (
            (
                {
                    "id": "revise:critique",
                    "label": "default",
                    "target_ref": "critique",
                    "condition_ref": "revise:loop",
                },
            ),
            (),
            "loop backedge route binding metadata is missing for an explicit tail carrier",
        ),
        (
            (
                {
                    "id": "revise:critique",
                    "label": "default",
                    "target_ref": "critique",
                    "condition_ref": "revise:loop",
                },
                {
                    "id": "revise:critique:duplicate",
                    "label": "reentry",
                    "target_ref": "critique",
                    "condition_ref": "revise:loop",
                },
            ),
            (
                {
                    "id": "tiebreaker_decide:critique",
                    "label": "iterate",
                    "target_ref": "critique",
                    "condition_ref": "tiebreaker:loop",
                },
            ),
            "loop backedge route binding metadata is ambiguous for an explicit tail carrier",
        ),
    ],
)
def test_source_compiler_m3_rejects_invalid_explicit_loop_tail_bindings(
    revise_bindings: tuple[dict[str, str], ...],
    tiebreaker_bindings: tuple[dict[str, str], ...],
    expected_message: str,
) -> None:
    source = """
from __future__ import annotations

from arnold.workflow.authoring import loop, workflow
from project.workflow_components import critique, gate, revise, tiebreaker_decide
from project.workflow_components import critique_loop

@workflow(id="invalid-tail-loop")
def flow(brief):
    loop(policy=critique_loop, reentry_id="critique")
    while True:
        critique_payload = critique(id="critique", brief=brief)
        recommendation = gate(id="gate", critique=critique_payload)
        if recommendation == "iterate":
            revise_payload = revise(id="revise", gate=recommendation)
        elif recommendation == "tiebreaker":
            decision = tiebreaker_decide(id="tiebreaker_decide", gate=recommendation)
        else:
            return None
"""
    resolver = _Resolver(
        {
            "project.workflow_components:critique": _step_component("critique"),
            "project.workflow_components:gate": _step_component("gate"),
            "project.workflow_components:revise": _step_component(
                "revise",
                route_bindings=revise_bindings,
            ),
            "project.workflow_components:tiebreaker_decide": _step_component(
                "tiebreaker_decide",
                route_bindings=tiebreaker_bindings,
            ),
            "project.workflow_components:critique_loop": authoring.PolicyComponent(
                id="critique_loop",
                provenance=authoring.ComponentProvenance(
                    module="project.workflow_components",
                    qualname="critique_loop",
                    export_name="critique_loop",
                ),
                policy_type="loop",
                config={"max_iterations": 4},
            ),
        }
    )

    result = source_compiler._lower_workflow_source_result(
        source,
        source_path="invalid_tail_loop.py",
        resolver=resolver,
    )

    assert result.pipeline is None
    payloads = _diagnostic_payloads(result)
    assert len(payloads) == 1
    assert payloads[0]["code"] == "AWF021_LOOP_POLICY_BINDING_MISMATCH"
    assert payloads[0]["message"] == expected_message
    assert payloads[0]["component_ref"] == (
        "project.workflow_components:tiebreaker_decide"
        if "missing" in expected_message
        else "project.workflow_components:revise"
    )


@pytest.mark.parametrize(
    ("fixture_name", "expected_message"),
    [
        (
            "invalid_m3_loop_missing_bounds",
            "loop policy requires a positive literal max_iterations bound",
        ),
        (
            "invalid_m3_loop_dynamic_bounds",
            "loop policy must reference an imported literal PolicyComponent",
        ),
        (
            "invalid_m3_loop_non_true_test",
            "bounded loops must use while True with an adjacent literal loop policy",
        ),
    ],
)
def test_source_compiler_m3_rejects_unsupported_loop_contracts(
    fixture_name: str,
    expected_message: str,
) -> None:
    result = workflow.check_workflow_file(M3_FIXTURE_DIR / f"{fixture_name}.py")

    assert _diagnostic_payloads(result)[0]["code"] == "AWF013_AMBIGUOUS_LOOP"
    assert _diagnostic_payloads(result)[0]["message"] == expected_message


@pytest.mark.parametrize(
    ("body", "expected_message"),
    [
        (
            "        break\n",
            None,
        ),
        (
            "        continue\n",
            "bounded loop bodies do not support continue",
        ),
        (
            "        return verdict\n",
            "bounded loop bodies only support return None as a terminal exit",
        ),
        (
            "        while True:\n            execute(id=\"nested\", plan=plan_output)\n",
            "nested while loops require a separate adjacent literal loop policy",
        ),
    ],
)
def test_source_compiler_m3_rejects_unsupported_loop_body_controls(
    body: str,
    expected_message: str,
) -> None:
    source = f"""
from arnold.workflow.authoring import loop, workflow
from tests.fixtures.workflow_authoring.components import bounded_review_loop, execute, plan, review

@workflow(id="invalid-loop-control")
def flow(brief):
    plan_output = plan(id="plan", brief=brief)
    loop(policy=bounded_review_loop, reentry_id="execute")
    while True:
        evidence = execute(id="execute", plan=plan_output)
        verdict = review(id="review", evidence=evidence)
{body}
"""

    result = workflow.check_workflow_source(source, source_path="invalid_loop_control.py")

    if expected_message is None:
        assert result.ok
        return
    assert _diagnostic_payloads(result)[0]["code"] == "AWF013_AMBIGUOUS_LOOP"
    assert _diagnostic_payloads(result)[0]["message"] == expected_message


def test_source_compiler_parsed_statement_wrappers_preserve_linear_fixture_parity() -> None:
    expected = {
        "valid_direct_linear": {
            "nodes": ["plan", "execute", "review"],
            "routes": ["plan-execute", "execute-review"],
            "bindings": {
                "plan": {},
                "execute": {},
                "review": {},
            },
            "topology_hash": "sha256:b8241316a814bb9145914b9fa079363215a7b71b7b634390374edb0174a47bc5",
            "manifest_hash": "sha256:a1d884c2d6116aa82d1d8304b36f6c728b81e71ca2a69dd51d37d6bcdfec8585",
        },
        "valid_function_linear": {
            "nodes": ["plan", "execute", "review"],
            "routes": ["plan-execute", "execute-review"],
            "bindings": {
                "plan": {"brief": "param:brief"},
                "execute": {"plan": "output:plan_output"},
                "review": {"evidence": "output:evidence"},
            },
            "topology_hash": "sha256:552872e0ffacd32b29cd25ad55298ef4866d186be0326d3f7c90293f70ad866e",
            "manifest_hash": "sha256:63846e02a691f11141d8a439f647eda7f25609f1a9f9e803b86d0b6ca6a18ada",
        },
    }

    for fixture_name, contract in expected.items():
        source_path = FIXTURE_DIR / f"{fixture_name}.py"
        checked = workflow.check_workflow_file(source_path)
        pipeline = workflow.lower_workflow_file(source_path)
        manifest = workflow.compile_workflow_file(source_path)

        assert checked.diagnostics == ()
        assert checked.parsed_source.workflow is not None
        parsed_workflow = checked.parsed_source.workflow
        assert all(
            isinstance(statement, source_compiler.ParsedStepCall)
            for statement in parsed_workflow.source_block.statements
        )
        assert parsed_workflow.source_block.steps == parsed_workflow.steps
        assert parsed_workflow.source_block.intrinsics == ()
        assert parsed_workflow.source_block.unsupported == ()

        assert [step.id for step in pipeline.steps] == contract["nodes"]
        assert [route.id for route in pipeline.routes] == contract["routes"]
        assert {
            step.id: {
                input_binding.name: input_binding.value_ref
                for input_binding in step.inputs
            }
            for step in pipeline.steps
        } == contract["bindings"]
        assert manifest.topology_hash == contract["topology_hash"]
        assert manifest.manifest_hash == contract["manifest_hash"]


def test_source_compiler_function_fixture_pins_parameter_local_and_tuple_ordering() -> None:
    source_path = Path("tests/fixtures/workflow_authoring/valid_function_linear.py")

    pipeline = workflow.lower_workflow_file(source_path)
    manifest = workflow.compile_workflow_file(source_path)

    assert [
        (
            step.id,
            [(input_binding.name, input_binding.value_ref) for input_binding in step.inputs],
            [output.name for output in step.outputs],
        )
        for step in pipeline.steps
    ] == [
        ("plan", [("brief", "param:brief")], ["plan_output"]),
        ("execute", [("plan", "output:plan_output")], ["execute_output", "evidence"]),
        ("review", [("evidence", "output:evidence")], []),
    ]
    assert {
        node.id: (
            node.inputs,
            node.outputs,
            {
                name: binding["value_ref"]
                for name, binding in node.metadata.get("input_bindings", {}).items()
            },
        )
        for node in manifest.nodes
    } == {
        "execute": (("plan",), ("execute_output", "evidence"), {"plan": "output:plan_output"}),
        "plan": (("brief",), ("plan_output",), {"brief": "param:brief"}),
        "review": (("evidence",), (), {"evidence": "output:evidence"}),
    }


def test_source_compiler_repeated_compiles_are_deterministic() -> None:
    source_path = Path("tests/fixtures/workflow_authoring/valid_function_linear.py")
    source = source_path.read_text(encoding="utf-8")

    manifests = [
        workflow.compile_workflow_source(source, source_path=source_path)
        for _ in range(3)
    ]

    assert {manifest.topology_hash for manifest in manifests} == {
        "sha256:552872e0ffacd32b29cd25ad55298ef4866d186be0326d3f7c90293f70ad866e"
    }
    assert {manifest.manifest_hash for manifest in manifests} == {
        "sha256:63846e02a691f11141d8a439f647eda7f25609f1a9f9e803b86d0b6ca6a18ada"
    }
    assert len({manifest.to_json() for manifest in manifests}) == 1


def test_source_compiler_megaplan_declared_step_interfaces_survive_metadata_stripping(
    monkeypatch,
) -> None:
    from arnold_pipelines.megaplan.workflows import components as megaplan_components
    from arnold_pipelines.megaplan.workflows import planning as megaplan_planning

    source_path = megaplan_planning.AUTHORING_SOURCE_PATH
    baseline_manifest = workflow.compile_workflow_file(source_path)
    baseline_execute_contract = megaplan_planning.declared_workflow_topology_contract("execute_batch")
    baseline_review_contract = megaplan_planning.declared_workflow_topology_contract("review_panel")
    baseline_tiebreaker_contract = megaplan_planning.declared_workflow_topology_contract(
        "tiebreaker_child"
    )

    stripped_exports = {
        "AUTHORING_PREP": {"handler_ref"},
        "AUTHORING_PLAN": {"handler_ref"},
        "AUTHORING_CRITIQUE": {"handler_ref"},
        "AUTHORING_GATE": {"handler_ref", "capability_requirements"},
        "AUTHORING_REVISE": {"handler_ref", "capability_requirements"},
        "AUTHORING_FINALIZE": {"handler_ref", "policy_refs"},
        "AUTHORING_EXECUTE": {"handler_ref", "policy_refs", "capability_requirements"},
        "AUTHORING_REVIEW": {"handler_ref", "policy_refs", "capability_requirements"},
        "AUTHORING_HALT": {"terminal"},
        "AUTHORING_OVERRIDE": {"handler_ref", "policy_refs", "override_actions"},
        "TIEBREAKER_RESEARCHER": {"handler_ref"},
        "TIEBREAKER_CHALLENGER": {"handler_ref"},
        "TIEBREAKER_SYNTHESIS": {"handler_ref"},
        "TIEBREAKER_DECISION": {"handler_ref", "capability_requirements"},
    }

    for export_name, stripped_keys in stripped_exports.items():
        component = getattr(megaplan_components, export_name)
        monkeypatch.setattr(
            megaplan_components,
            export_name,
            _clone_step_component_with_metadata(
                component,
                {
                    key: value
                    for key, value in component.metadata.items()
                    if key not in stripped_keys
                },
            ),
        )

    for export_name in (
        "SOURCE_EXECUTE_BATCH_WORKFLOW",
        "SOURCE_REVIEW_PANEL_WORKFLOW",
        "SOURCE_TIEBREAKER_WORKFLOW",
    ):
        component = getattr(megaplan_components, export_name)
        monkeypatch.setattr(
            megaplan_components,
            export_name,
            _clone_workflow_component_with_metadata(
                component,
                {
                    key: value
                    for key, value in component.metadata.items()
                    if key not in {"topology_contract", "fan_in_ref", "policy_refs"}
                },
            ),
        )

    pipeline = workflow.lower_workflow_file(source_path)
    manifest = workflow.compile_workflow_file(source_path)
    steps = {step.id: step for step in pipeline.steps}

    assert steps["gate"].metadata["handler_ref"] == "arnold_pipelines.megaplan.handlers:handle_gate"
    assert [(capability.id, capability.route, capability.required) for capability in steps["gate"].capabilities] == [("human:gate", "default", False)]
    assert steps["finalize"].metadata["policy_refs"] == (
        "megaplan:default",
        "megaplan:finalize",
        "megaplan:artifact-contract",
    )
    assert steps["override"].metadata["override_actions"] == (
            "abort",
            "add-note",
            "adopt-execution",
            "cap-revise-once",
            "cutover",
        "force-proceed",
        "reconcile-plan-ledger",
        "recover-blocked",
        "replan",
        "resume-clarify",
        "set-model",
        "set-profile",
        "set-robustness",
        "set-vendor",
    )
    assert steps["halt"].metadata["terminal"] is True
    assert [(capability.id, capability.route, capability.required) for capability in steps["tiebreaker_decision"].capabilities] == [("megaplan:planning", "default", True)]
    assert megaplan_planning.declared_workflow_topology_contract("execute_batch") == baseline_execute_contract
    assert megaplan_planning.declared_workflow_topology_contract("review_panel") == baseline_review_contract
    assert (
        megaplan_planning.declared_workflow_topology_contract("tiebreaker_child")
        == baseline_tiebreaker_contract
    )
    assert manifest.to_json() == baseline_manifest.to_json()


def test_source_compiler_rejects_future_and_unknown_dataflow_with_precise_spans() -> None:
    source = (
        "from arnold.workflow.authoring import workflow\n"
        "from tests.fixtures.workflow_authoring.components import plan, execute\n"
        "@workflow(id='x')\n"
        "def flow(brief):\n"
        "    execute_output = execute(id='execute', plan=plan_output)\n"
        "    plan_output = plan(id='plan', brief=brief)\n"
    )

    result = workflow.check_workflow_source(source, source_path="future_output.py")

    assert _diagnostic_payloads(result) == [
        {
            "code": "AWF005_UNKNOWN_COMPONENT",
            "message": "keyword dataflow reference is not a workflow parameter or prior local output",
            "source_span": {
                "path": "future_output.py",
                "start_line": 5,
                "start_column": 44,
                "end_line": 5,
                "end_column": 60,
            },
        }
    ]


def test_source_compiler_lowers_canonical_intrinsics_to_existing_policy_slots() -> None:
    source = """
from arnold.workflow.authoring import workflow, halt, suspend, transition
from tests.fixtures.workflow_authoring.components import plan, execute

@workflow(id="intrinsic-linear")
def flow(brief):
    plan_output = plan(id="plan", brief=brief)
    execute(id="execute", plan=plan_output)
    suspend(route_id="operator", capability_id="human.review", reentry_id="execute", resume_schema_ref="operator.resume")
    transition(id="operator-resume", type="override", trigger_ref="operator.resume", target_ref="execute", policy_ref="review_approval")
    halt(id="operator-stop", trigger_ref="operator.stop", payload_schema_hash="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
"""

    pipeline = workflow.lower_workflow_source(source, source_path="intrinsic_linear.py")

    assert pipeline.policy is not None
    assert list(pipeline.policy.suspension_routes) == [
        workflow.SuspensionRoute(
            route_id="operator",
            capability_id="human.review",
            reentry_id="execute",
            resume_schema_ref="operator.resume",
        )
    ]
    assert [
        (
            transition.transition_id,
            transition.transition_type,
            transition.trigger_ref,
            transition.target_ref,
            transition.payload_schema_hash,
            transition.policy_ref,
        )
        for transition in pipeline.policy.control_transitions
    ] == [
        ("operator-resume", "override", "operator.resume", "execute", None, "review_approval"),
        (
            "operator-stop",
            "halt",
            "operator.stop",
            None,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            None,
        ),
    ]

    manifest = workflow.compile_workflow_source(source, source_path="intrinsic_linear.py")

    assert manifest.policy is not None
    assert manifest.policy.suspension_routes[0].route_id == "operator"
    assert manifest.policy.control_transitions[1].transition_type == "halt"


def test_source_compiler_rejects_malformed_intrinsic_usage() -> None:
    invalid_sources = {
        "aliased": (
            "from arnold.workflow.authoring import workflow, halt as stop\n"
            "@workflow(id='x')\n"
            "def flow():\n"
            "    stop(id='stop')\n"
        ),
        "assigned": (
            "from arnold.workflow.authoring import workflow, halt\n"
            "@workflow(id='x')\n"
            "def flow():\n"
            "    result = halt(id='stop')\n"
        ),
        "ordinary_component": (
            "from arnold.workflow.authoring import workflow, halt\n"
            "workflow(id='x', steps=[halt(id='stop')])\n"
        ),
        "shadowed_output": (
            "from arnold.workflow.authoring import workflow\n"
            "from tests.fixtures.workflow_authoring.components import plan\n"
            "@workflow(id='x')\n"
            "def flow(brief):\n"
            "    halt = plan(id='plan', brief=brief)\n"
        ),
        "value_passed": (
            "from arnold.workflow.authoring import workflow, halt\n"
            "from tests.fixtures.workflow_authoring.components import plan\n"
            "@workflow(id='x')\n"
            "def flow(brief):\n"
            "    plan_output = plan(id='plan', brief=halt)\n"
        ),
        "nonliteral": (
            "from arnold.workflow.authoring import workflow, suspend\n"
            "ROUTE = 'operator'\n"
            "@workflow(id='x')\n"
            "def flow():\n"
            "    suspend(route_id=ROUTE)\n"
        ),
        "unknown_keyword": (
            "from arnold.workflow.authoring import workflow, transition\n"
            "@workflow(id='x')\n"
            "def flow():\n"
            "    transition(id='operator-resume', type='override', unsupported='x')\n"
        ),
        "dynamic_transition": (
            "from arnold.workflow.authoring import workflow, transition\n"
            "TYPE = 'override'\n"
            "@workflow(id='x')\n"
            "def flow():\n"
            "    transition(id='operator-resume', type=TYPE)\n"
        ),
    }

    results = {
        name: workflow.check_workflow_source(source, source_path=f"{name}.py")
        for name, source in invalid_sources.items()
    }

    assert diagnostics.DiagnosticCode.RESERVED_INTRINSIC_SHADOWING in _codes(results["aliased"])
    assert diagnostics.DiagnosticCode.UNSUPPORTED_SYNTAX in _codes(results["assigned"])
    assert diagnostics.DiagnosticCode.UNSUPPORTED_SYNTAX in _codes(results["ordinary_component"])
    assert diagnostics.DiagnosticCode.RESERVED_INTRINSIC_SHADOWING in _codes(
        results["shadowed_output"]
    )
    assert diagnostics.DiagnosticCode.RESERVED_INTRINSIC_SHADOWING in _codes(
        results["value_passed"]
    )
    assert diagnostics.DiagnosticCode.UNSUPPORTED_SYNTAX in _codes(results["nonliteral"])
    assert diagnostics.DiagnosticCode.UNSUPPORTED_SYNTAX in _codes(results["unknown_keyword"])
    assert diagnostics.DiagnosticCode.UNSUPPORTED_SYNTAX in _codes(results["dynamic_transition"])


def test_source_compiler_rejects_function_body_dataflow_outside_linear_subset() -> None:
    invalid_sources = {
        "future_output": (
            "from arnold.workflow.authoring import workflow\n"
            "from tests.fixtures.workflow_authoring.components import plan, execute\n"
            "@workflow(id='x')\n"
            "def flow(brief):\n"
            "    execute_output = execute(id='execute', plan=plan_output)\n"
            "    plan_output = plan(id='plan', brief=brief)\n"
        ),
        "self_reference": (
            "from arnold.workflow.authoring import workflow\n"
            "from tests.fixtures.workflow_authoring.components import plan\n"
            "@workflow(id='x')\n"
            "def flow(brief):\n"
            "    plan_output = plan(id='plan', brief=plan_output)\n"
        ),
        "literal_keyword": (
            "from arnold.workflow.authoring import workflow\n"
            "from tests.fixtures.workflow_authoring.components import plan\n"
            "@workflow(id='x')\n"
            "def flow(brief):\n"
            "    plan_output = plan(id='plan', brief='literal')\n"
        ),
        "call_keyword": (
            "from arnold.workflow.authoring import workflow\n"
            "from tests.fixtures.workflow_authoring.components import plan\n"
            "@workflow(id='x')\n"
            "def flow(brief):\n"
            "    plan_output = plan(id='plan', brief=str(brief))\n"
        ),
        "attribute_keyword": (
            "from arnold.workflow.authoring import workflow\n"
            "from tests.fixtures.workflow_authoring.components import plan\n"
            "@workflow(id='x')\n"
            "def flow(brief):\n"
            "    plan_output = plan(id='plan', brief=brief.text)\n"
        ),
        "unsupported_local": (
            "from arnold.workflow.authoring import workflow\n"
            "from tests.fixtures.workflow_authoring.components import plan\n"
            "@workflow(id='x')\n"
            "def flow(brief):\n"
            "    local = brief\n"
            "    plan_output = plan(id='plan', brief=local)\n"
        ),
    }

    results = {
        name: workflow.check_workflow_source(source, source_path=f"{name}.py")
        for name, source in invalid_sources.items()
    }

    assert diagnostics.DiagnosticCode.UNKNOWN_COMPONENT in _codes(results["future_output"])
    assert diagnostics.DiagnosticCode.UNKNOWN_COMPONENT in _codes(results["self_reference"])
    assert diagnostics.DiagnosticCode.UNSUPPORTED_SYNTAX in _codes(results["literal_keyword"])
    assert diagnostics.DiagnosticCode.UNSUPPORTED_SYNTAX in _codes(results["call_keyword"])
    assert diagnostics.DiagnosticCode.UNSUPPORTED_SYNTAX in _codes(results["attribute_keyword"])
    assert diagnostics.DiagnosticCode.UNSUPPORTED_SYNTAX in _codes(results["unsupported_local"])


def test_source_compiler_rejects_function_header_features_outside_m2_subset() -> None:
    invalid_sources = {
        "positional_decorator": (
            "from arnold.workflow.authoring import workflow\n"
            "@workflow('x')\n"
            "def flow(brief):\n"
            "    return None\n"
        ),
        "default_parameter": (
            "from arnold.workflow.authoring import workflow\n"
            "@workflow(id='x')\n"
            "def flow(brief='default'):\n"
            "    return None\n"
        ),
        "vararg": (
            "from arnold.workflow.authoring import workflow\n"
            "@workflow(id='x')\n"
            "def flow(*briefs):\n"
            "    return None\n"
        ),
        "keyword_only": (
            "from arnold.workflow.authoring import workflow\n"
            "@workflow(id='x')\n"
            "def flow(*, brief):\n"
            "    return None\n"
        ),
        "dynamic_version": (
            "from arnold.workflow.authoring import workflow\n"
            "VERSION = '1.0'\n"
            "@workflow(id='x', version=VERSION)\n"
            "def flow(brief):\n"
            "    return None\n"
        ),
    }

    for name, source in invalid_sources.items():
        result = workflow.check_workflow_source(source, source_path=f"{name}.py")
        assert diagnostics.DiagnosticCode.UNSUPPORTED_SYNTAX in _codes(result), name


def test_source_compiler_rejects_initial_scope_parameter_shadowing() -> None:
    source = """
from arnold.workflow.authoring import workflow
from tests.fixtures.workflow_authoring.components import plan

@workflow(id="shadowing")
def flow(workflow, plan, brief):
    missing(id="not-lowered", brief=brief)
"""

    result = workflow.check_workflow_source(source, source_path="shadowing.py")

    assert _codes(result) == {diagnostics.DiagnosticCode.RESERVED_INTRINSIC_SHADOWING}
    assert result.parsed_source.workflow is not None
    assert result.parsed_source.workflow.parameters == ("workflow", "plan", "brief")
    assert result.parsed_source.workflow.steps == ()


def test_source_compiler_does_not_execute_workflow_source() -> None:
    source = """
from __future__ import annotations

from arnold.workflow.authoring import workflow
from project.workflow_components import plan

raise RuntimeError("source execution leaked into static parsing")

workflow(id="no-exec", steps=[plan(id="plan")])
"""
    resolver = _Resolver(
        {
            "project.workflow_components:plan": authoring.StepComponent(
                id="plan",
                provenance=authoring.ComponentProvenance(
                    module="project.workflow_components",
                    qualname="plan",
                    export_name="plan",
                ),
            )
        }
    )

    result = workflow.check_workflow_source(source, source_path="no_exec.py", resolver=resolver)

    assert result.ok


def test_source_compiler_compile_apis_raise_source_compile_error_with_diagnostics() -> None:
    source = "from arnold.workflow.authoring import workflow\nworkflow(id='x', steps=[missing(id='x')])\n"

    with pytest.raises(workflow.SourceCompileError) as source_error:
        workflow.compile_workflow_source(source, source_path="invalid.py")
    assert diagnostics.DiagnosticCode.UNKNOWN_COMPONENT in {
        diagnostic.code for diagnostic in source_error.value.diagnostics
    }

    with pytest.raises(workflow.SourceCompileError) as lower_error:
        workflow.lower_workflow_source(source, source_path="invalid.py")
    assert diagnostics.DiagnosticCode.UNKNOWN_COMPONENT in {
        diagnostic.code for diagnostic in lower_error.value.diagnostics
    }


def test_source_compiler_file_apis_read_text_without_executing_source_files(tmp_path: Path) -> None:
    source_path = tmp_path / "no_exec_file.py"
    source_path.write_text(
        """
from arnold.workflow.authoring import workflow
from project.workflow_components import plan

raise RuntimeError("source execution leaked into file API")

workflow(id="no-exec-file", steps=[plan(id="plan")])
""",
        encoding="utf-8",
    )
    resolver = _Resolver(
        {
            "project.workflow_components:plan": authoring.StepComponent(
                id="plan",
                provenance=authoring.ComponentProvenance(
                    module="project.workflow_components",
                    qualname="plan",
                    export_name="plan",
                ),
            )
        }
    )

    check_result = workflow.check_workflow_file(source_path, resolver=resolver)
    pipeline = workflow.lower_workflow_file(source_path, resolver=resolver)
    manifest = workflow.compile_workflow_file(source_path, resolver=resolver)

    assert check_result.ok
    assert pipeline.id == "no-exec-file"
    assert manifest.id == "no-exec-file"


def test_source_compiler_file_apis_accept_absolute_paths_with_non_identifier_dirs(
    tmp_path: Path,
) -> None:
    source_dir = tmp_path / "megaplan-native-parity-corrective"
    source_dir.mkdir()
    source_path = source_dir / "local_workflow.py"
    source_path.write_text(
        """
from arnold.pipeline import step, workflow

@step(id="local-step")
def local_step():
    return {}

workflow(id="absolute-path-ok", steps=[local_step(id="s1")])
""",
        encoding="utf-8",
    )

    check_result = workflow.check_workflow_file(source_path)
    pipeline = workflow.lower_workflow_file(source_path)
    manifest = workflow.compile_workflow_file(source_path)

    assert check_result.ok
    assert pipeline.id == "absolute-path-ok"
    assert manifest.id == "absolute-path-ok"


def _codes(result: workflow.CheckWorkflowSourceResult) -> set[diagnostics.DiagnosticCode]:
    return {diagnostic.code for diagnostic in result.diagnostics}


def _diagnostic_codes(diagnostic_list) -> set[diagnostics.DiagnosticCode]:
    return {diagnostic.code for diagnostic in diagnostic_list}


def _diagnostic_payloads(result: workflow.CheckWorkflowSourceResult) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    for diagnostic in result.diagnostics:
        payload: dict[str, object] = {
            "code": diagnostic.code.value,
            "message": diagnostic.message,
        }
        if diagnostic.source_span is not None:
            payload["source_span"] = {
                "path": diagnostic.source_span.path,
                "start_line": diagnostic.source_span.start_line,
                "start_column": diagnostic.source_span.start_column,
                "end_line": diagnostic.source_span.end_line,
                "end_column": diagnostic.source_span.end_column,
            }
        if diagnostic.import_ref is not None:
            payload["import_ref"] = {
                "module": diagnostic.import_ref.module,
                "qualname": diagnostic.import_ref.qualname,
            }
        if diagnostic.component_ref is not None:
            payload["component_ref"] = diagnostic.component_ref
        payloads.append(payload)
    return payloads


def _load_m3_sidecar(fixture_name: str) -> dict[str, object]:
    with (M3_FIXTURE_DIR / f"{fixture_name}.expected.json").open(encoding="utf-8") as handle:
        return json.load(handle)


def _check_specialized_m3_fixture(source_path: Path):
    fixture_name = source_path.stem
    original_topology_contract = source_compiler._megaplan_review_topology_contract
    original_route_surface = source_compiler._megaplan_policy_route_surface
    try:
        if fixture_name == "invalid_m3_handler_owned_review_cap":
            source_compiler._megaplan_review_topology_contract = lambda: {
                "retry_and_cap": {"cap_thresholds": {"max_review_rework_cycles": 1}},
            }
        elif fixture_name == "invalid_m3_hidden_finalize_fallback":
            source_compiler._megaplan_policy_route_surface = (
                lambda export_name: {}
                if export_name == "FINALIZE_POLICY"
                else original_route_surface(export_name)
            )
        return workflow.check_workflow_file(source_path)
    finally:
        source_compiler._megaplan_review_topology_contract = original_topology_contract
        source_compiler._megaplan_policy_route_surface = original_route_surface


def _load_m0_sidecar(fixture_name: str) -> dict[str, object]:
    with (M0_FIXTURE_DIR / f"{fixture_name}.expected.json").open(encoding="utf-8") as handle:
        return json.load(handle)


def _route_contract(route: workflow.Route, *, include_extended: bool = False) -> dict[str, object]:
    payload: dict[str, object] = {
        "source": route.source,
        "target": route.target,
    }
    if include_extended:
        payload["id"] = route.id
    if route.label != "default":
        payload["label"] = route.label
    if route.condition_ref is not None:
        payload["condition_ref"] = route.condition_ref
    if include_extended and route.metadata:
        payload["metadata"] = dict(route.metadata)
    return payload


def _capability_contract(capability: workflow.Capability) -> dict[str, object]:
    payload: dict[str, object] = {
        "id": capability.id,
        "route": capability.route,
        "required": capability.required,
    }
    if capability.metadata:
        payload["metadata"] = dict(capability.metadata)
    return payload


def _policy_contract(policy: object) -> dict[str, object]:
    payload = _compact_contract(policy)
    assert isinstance(payload, dict)
    return payload


def _compact_contract(value: object) -> object:
    if is_dataclass(value):
        return _compact_contract(asdict(value))
    if isinstance(value, Mapping):
        return {
            str(key): _compact_contract(subvalue)
            for key, subvalue in value.items()
            if subvalue is not None and subvalue != () and subvalue != []
        }
    if isinstance(value, tuple):
        return [_compact_contract(item) for item in value]
    if isinstance(value, list):
        return [_compact_contract(item) for item in value]
    return value


def _assert_ordered_contracts(
    actual_contracts: Sequence[object],
    expected_contracts: Sequence[object],
) -> None:
    assert len(actual_contracts) == len(expected_contracts)
    for actual_contract, expected_contract in zip(actual_contracts, expected_contracts):
        _assert_contract(actual_contract, expected_contract)


def _assert_contract(actual: object, expected: object) -> None:
    if isinstance(expected, Mapping):
        assert isinstance(actual, Mapping)
        for key, expected_value in expected.items():
            assert key in actual
            _assert_contract(actual[key], expected_value)
        return
    if isinstance(expected, list):
        assert isinstance(actual, Sequence)
        assert not isinstance(actual, (str, bytes))
        assert len(actual) == len(expected)
        for actual_item, expected_item in zip(actual, expected):
            _assert_contract(actual_item, expected_item)
        return
    assert actual == expected


def _node_contract_items(
    node_contracts: Mapping[str, object] | Sequence[Mapping[str, object]],
) -> list[tuple[str, object]]:
    if isinstance(node_contracts, Mapping):
        return list(node_contracts.items())
    return [
        (str(contract["node"]), {key: value for key, value in contract.items() if key != "node"})
        for contract in node_contracts
    ]


def _step_component(
    name: str,
    *,
    route_bindings: tuple[dict[str, str], ...] = (),
    metadata: dict[str, object] | None = None,
) -> authoring.StepComponent:
    component_metadata: dict[str, object] = {"route_bindings": route_bindings}
    if metadata:
        component_metadata.update(metadata)
    return authoring.StepComponent(
        id=name,
        provenance=authoring.ComponentProvenance(
            module="project.workflow_components",
            qualname=name,
            export_name=name,
        ),
        metadata=component_metadata,
    )


class _Resolver:
    def __init__(self, components: dict[str, authoring.ComponentContract]) -> None:
        self._components = components
        self._resolved: list[ImportRef] = []

    @property
    def resolved(self) -> tuple[ImportRef, ...]:
        return tuple(self._resolved)

    def resolve(self, import_ref: ImportRef) -> authoring.ComponentContract | None:
        self._resolved.append(import_ref)
        return self._components.get(import_ref.spec)
