from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

import arnold.patterns as patterns
import arnold.workflow as workflow_api
from arnold.workflow import (
    BudgetPolicy,
    Pipeline,
    Route,
    SourceSpan,
    Step,
    WorkflowPolicy,
    compile_pipeline,
)

HASH_A = "sha256:" + "a" * 64
FIXTURE_PATH = Path(__file__).parent.parent.parent / "fixtures" / "workflow" / "canonical_megaplan_shapes.yaml"


def _load_shapes() -> dict[str, Any]:
    with FIXTURE_PATH.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)["shapes"]


def _load_fixture_matrix() -> dict[str, Any]:
    with FIXTURE_PATH.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


EXPECTED_SHAPES_DIR = FIXTURE_PATH.parent


def _load_expected_shape(name: str) -> dict[str, Any]:
    path = EXPECTED_SHAPES_DIR / name
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _build_pattern_blocks() -> tuple[patterns.PatternBlock, ...]:
    """Return the composite pattern blocks used by the canonical fixture."""

    return (
        patterns.branch(
            "branch-decide",
            condition_ref="tests.arnold.patterns._fixtures:decide_condition",
            then_id="branch-plan",
            else_id="branch-fallback",
        ),
        patterns.loop(
            "loop",
            "loop-body",
            until_ref="tests.arnold.patterns._fixtures:decide_condition",
            max_iterations=3,
            reentry_id="retry",
        ),
        patterns.revise(
            "revise",
            "draft",
            revise_ref="tests.arnold.patterns._fixtures:agent_prompt",
            until_ref="tests.arnold.patterns._fixtures:decide_condition",
            max_iterations=4,
            reentry_id="retry-revise",
        ),
        patterns.panel(
            "fan",
            branch_ids=("fan-branch-a", "fan-branch-b"),
            merge_id="fan-merged",
            reducer_ref="tests.arnold.patterns._fixtures:reducer",
        ),
        patterns.retry(
            "retry",
            target_id="retry-fragile",
            max_attempts=3,
            retry_on=("error",),
        ),
        patterns.tournament(
            "tourney",
            candidate_ids=("tourney-candidate-a", "tourney-candidate-b"),
            merge_id="tourney-winner",
            winner_ref="tests.arnold.patterns._fixtures:judge_winner",
            tie_ref="tests.arnold.patterns._fixtures:decide_condition",
        ),
    )


def _build_pipeline() -> Pipeline:
    """Return the explicit-step/r portion of the canonical fixture.

    Composite pattern blocks are returned separately so tests exercise the
    real ``compile_pipeline(..., patterns=...)`` expansion path.
    """

    sub_step = patterns.subpipeline("inner", manifest_hash=HASH_A, alias="nested")
    gate_step = patterns.human_gate("gate", capability_id="human:operator", reentry_id="resume")

    override_decide = Step(
        id="override-decide",
        kind="branch",
        metadata={"condition_ref": "tests.arnold.patterns._fixtures:decide_condition"},
    )
    override_routes = (
        Route(id="override-decide-override-primary", source="override-decide", target="override-primary", label="default"),
        Route(id="override-decide-override-fallback", source="override-decide", target="override-fallback", label="fallback"),
    )

    escalate_review = Step(id="escalate-review", kind="review")
    escalate_route = Route(
        id="escalate-review-escalate-supervisor",
        source="escalate-review",
        target="escalate-supervisor",
        label="escalate",
    )

    compensate_fragile = Step(id="compensate-fragile", kind="agent")
    compensate_target = Step(id="compensate-target", kind="agent")
    compensate_route = Route(
        id="compensate-fragile-compensate-target",
        source="compensate-fragile",
        target="compensate-target",
        label="compensate",
    )

    promote_gate = Step(id="promote-gate", kind="suspension")
    promote_route = Route(
        id="promote-gate-promote-supervisor",
        source="promote-gate",
        target="promote-supervisor",
        label="promote",
    )

    feedback_review = Step(id="feedback-review", kind="review")
    feedback_plan = Step(id="feedback-plan", kind="agent")
    feedback_route = Route(
        id="feedback-review-feedback-plan",
        source="feedback-review",
        target="feedback-plan",
        label="feedback",
    )

    robust_plan = patterns.agent(
        "robust-plan",
        task="robust",
        prompt_ref="tests.arnold.patterns._fixtures:agent_prompt",
        policy=WorkflowPolicy(
            budget=BudgetPolicy(max_cost=1.0, max_seconds=30.0, max_attempts=2, token_budget=1000),
        ),
    )
    overlay = patterns.agent(
        "overlay",
        task="overlay",
        prompt_ref="tests.arnold.patterns._fixtures:agent_prompt",
        metadata={
            "dynamic_events": [
                {"event": "on_branch", "slot": "branch"},
                {"event": "on_suspend", "slot": "suspension"},
            ],
        },
    )

    steps = [
        Step(id="branch-plan", kind="agent"),
        Step(id="branch-fallback", kind="agent"),
        Step(id="loop-body", kind="agent"),
        Step(id="draft", kind="agent"),
        Step(id="fan-branch-a", kind="agent"),
        Step(id="fan-branch-b", kind="agent"),
        Step(id="retry-fragile", kind="agent"),
        sub_step,
        gate_step,
        override_decide,
        Step(id="override-primary", kind="agent"),
        Step(id="override-fallback", kind="agent"),
        escalate_review,
        Step(id="escalate-supervisor", kind="agent"),
        compensate_fragile,
        compensate_target,
        promote_gate,
        Step(id="promote-supervisor", kind="agent"),
        feedback_review,
        feedback_plan,
        robust_plan,
        overlay,
        Step(id="tourney-candidate-a", kind="agent"),
        Step(id="tourney-candidate-b", kind="agent"),
    ]
    routes = [
        Route(id="loop-loop-body", source="loop", target="loop-body", label="go"),
        *override_routes,
        escalate_route,
        compensate_route,
        promote_route,
        feedback_route,
    ]
    return Pipeline(
        id="canonical-megaplan",
        version="conformance-v1",
        steps=steps,
        routes=routes,
        source_span=SourceSpan("pipeline.py", 1),
    )


def _normalize_capabilities(capabilities: list[dict[str, Any]]) -> tuple[dict[str, Any], ...]:
    return tuple(
        {"capability_id": cap.get("capability_id"), "route": cap.get("route", "default"), "required": cap.get("required", True)}
        for cap in capabilities
    )


def _assert_shape_matches(manifest, shape: dict[str, Any]) -> None:
    nodes_by_id = {node.id: node for node in manifest.nodes}
    edges_by_id = {edge.id: edge for edge in manifest.edges}

    for expected_node in shape["nodes"]:
        node = nodes_by_id.get(expected_node["id"])
        assert node is not None, f"missing node {expected_node['id']}"
        assert node.kind == expected_node["kind"], f"node {node.id} kind mismatch"
        if "capabilities" in expected_node:
            assert _normalize_capabilities(expected_node["capabilities"]) == tuple(
                {"capability_id": cap.capability_id, "route": cap.route, "required": cap.required}
                for cap in node.capabilities
            )
        if expected_node["id"] in shape.get("subpipelines", {}):
            expected = shape["subpipelines"][expected_node["id"]]
            assert node.subpipeline is not None
            assert node.subpipeline.manifest_hash == expected["manifest_hash"]
            assert node.subpipeline.alias == expected["alias"]

    for expected_edge in shape.get("edges", ()):
        edge = edges_by_id.get(expected_edge["id"])
        assert edge is not None, f"missing edge {expected_edge['id']}"
        assert edge.source == expected_edge["source"]
        assert edge.target == expected_edge["target"]
        assert edge.label == expected_edge["label"]
        assert edge.condition_ref == expected_edge.get("condition_ref")

    for node_id, expected_policy in shape.get("policies", {}).items():
        node = nodes_by_id[node_id]
        assert node.policy is not None, f"node {node_id} missing expected policy"
        if "loop" in expected_policy:
            assert node.policy.loop is not None
            assert node.policy.loop.max_iterations == expected_policy["loop"]["max_iterations"]
            assert node.policy.loop.until_ref == expected_policy["loop"].get("until_ref")
        if "retry" in expected_policy:
            assert node.policy.retry is not None
            assert node.policy.retry.max_attempts == expected_policy["retry"]["max_attempts"]
            assert node.policy.retry.backoff == expected_policy["retry"]["backoff"]
            assert node.policy.retry.retry_on == tuple(expected_policy["retry"]["retry_on"])
        if "fanout" in expected_policy:
            assert node.policy.fanout is not None
            assert node.policy.fanout.mode == expected_policy["fanout"]["mode"]
            assert node.policy.fanout.reducer_ref == expected_policy["fanout"].get("reducer_ref")
        if "budget" in expected_policy:
            assert node.policy.budget is not None
            assert node.policy.budget.max_cost == expected_policy["budget"]["max_cost"]
        if "suspension_routes" in expected_policy:
            expected_routes = expected_policy["suspension_routes"]
            actual = [
                {
                    "route_id": route.route_id,
                    "capability_id": route.capability_id,
                    "reentry_id": route.reentry_id,
                }
                for route in node.policy.suspension_routes
            ]
            assert actual == expected_routes, f"suspension routes mismatch for {node_id}"

    for node_id, expected_metadata in shape.get("metadata", {}).items():
        node = nodes_by_id[node_id]
        for key, value in expected_metadata.items():
            assert node.metadata.get(key) == value, f"metadata mismatch for {node_id}.{key}"


def _assert_subset(expected: dict[str, Any], actual: dict[str, Any]) -> None:
    assert {key: actual.get(key) for key in expected} == expected


def _authority_contract(requirement) -> dict[str, Any]:
    return {
        "authority_id": requirement.authority_id,
        "action": requirement.action,
        "capability_id": requirement.capability_id,
    }


def _control_transition_contract(slot) -> dict[str, Any]:
    return {
        "transition_id": slot.transition_id,
        "transition_type": slot.transition_type,
        "trigger_ref": slot.trigger_ref,
        "target_ref": slot.target_ref,
        "policy_ref": slot.policy_ref,
    }


def _suspension_route_contract(route) -> dict[str, Any]:
    return {
        "route_id": route.route_id,
        "capability_id": route.capability_id,
        "reentry_id": route.reentry_id,
        "resume_schema_ref": route.resume_schema_ref,
    }


def _assert_m3_policy_matches(policy, expected_policy: dict[str, Any], *, subject: str) -> None:
    assert policy is not None, f"{subject} missing expected policy"
    if "loop" in expected_policy:
        assert policy.loop is not None
        _assert_subset(
            expected_policy["loop"],
            {
                "max_iterations": policy.loop.max_iterations,
                "until_ref": policy.loop.until_ref,
            },
        )
    if "retry" in expected_policy:
        assert policy.retry is not None
        _assert_subset(
            expected_policy["retry"],
            {
                "max_attempts": policy.retry.max_attempts,
                "backoff": policy.retry.backoff,
                "retry_on": list(policy.retry.retry_on),
            },
        )
    if "timing" in expected_policy:
        assert policy.timing is not None
        _assert_subset(
            expected_policy["timing"],
            {
                "timeout_seconds": policy.timing.timeout_seconds,
                "deadline_ref": policy.timing.deadline_ref,
                "ttl_seconds": policy.timing.ttl_seconds,
            },
        )
    if "authority" in expected_policy:
        assert [_authority_contract(requirement) for requirement in policy.authority] == expected_policy[
            "authority"
        ]
    if "control_transitions" in expected_policy:
        assert [
            _control_transition_contract(slot)
            for slot in policy.control_transitions
        ] == expected_policy["control_transitions"]
    if "suspension_routes" in expected_policy:
        actual_routes = [_suspension_route_contract(route) for route in policy.suspension_routes]
        expected_routes = expected_policy["suspension_routes"]
        assert len(actual_routes) == len(expected_routes)
        for expected_route, actual_route in zip(expected_routes, actual_routes, strict=True):
            _assert_subset(expected_route, actual_route)


def _assert_m3_supported_subset_matches(manifest, contract: dict[str, Any]) -> None:
    assert manifest.topology_hash == contract["topology_hash"]
    assert manifest.manifest_hash == contract["manifest_hash"]

    nodes_by_id = {node.id: node for node in manifest.nodes}
    edges_by_id = {edge.id: edge for edge in manifest.edges}

    for expected_node in contract["nodes"]:
        node = nodes_by_id.get(expected_node["id"])
        assert node is not None, f"missing node {expected_node['id']}"
        assert node.kind == expected_node["kind"]

    for expected_edge in contract["edges"]:
        edge = edges_by_id.get(expected_edge["id"])
        assert edge is not None, f"missing edge {expected_edge['id']}"
        assert edge.source == expected_edge["source"]
        assert edge.target == expected_edge["target"]
        assert edge.label == expected_edge["label"]
        assert edge.condition_ref == expected_edge["condition_ref"]

    for node_id, expected_policy in contract.get("policies", {}).items():
        _assert_m3_policy_matches(nodes_by_id[node_id].policy, expected_policy, subject=node_id)

    if "workflow_policy" in contract:
        _assert_m3_policy_matches(
            manifest.policy,
            contract["workflow_policy"],
            subject=f"{manifest.id} workflow",
        )

    for node_id, expected_subpipeline in contract.get("subpipelines", {}).items():
        node = nodes_by_id[node_id]
        assert node.subpipeline is not None
        assert node.subpipeline.manifest_hash == expected_subpipeline["manifest_hash"]
        assert node.subpipeline.alias == expected_subpipeline["alias"]


@pytest.mark.parametrize("shape_name", list(_load_shapes().keys()))
def test_canonical_shape(shape_name: str) -> None:
    shapes = _load_shapes()
    pipeline = _build_pipeline()
    manifest = compile_pipeline(pipeline, patterns=_build_pattern_blocks())
    _assert_shape_matches(manifest, shapes[shape_name])


def test_compiled_manifest_validates_and_hashes_stably() -> None:
    pipeline = _build_pipeline()
    patterns = _build_pattern_blocks()
    first = compile_pipeline(pipeline, patterns=patterns)
    second = compile_pipeline(pipeline, patterns=patterns)

    assert first.manifest_hash == second.manifest_hash
    assert first.topology_hash == second.topology_hash
    validate_manifest = __import__("arnold.workflow", fromlist=["validate_manifest"]).validate_manifest
    validate_manifest(first)


def test_tournament_has_two_full_tiebreaker_rounds() -> None:
    shapes = _load_shapes()
    pipeline = _build_pipeline()
    manifest = compile_pipeline(pipeline, patterns=_build_pattern_blocks())
    _assert_shape_matches(manifest, shapes["tournament"])

    tie_routes = [
        edge for edge in manifest.edges
        if edge.label == "tie"
    ]
    assert len(tie_routes) == 2
    assert tie_routes[0].source == "tourney-judge"
    assert tie_routes[0].target == "tourney-tiebreak-1"
    assert tie_routes[1].source == "tourney-tiebreak-1"
    assert tie_routes[1].target == "tourney-tiebreak-2"

    retry_edge = next(
        edge for edge in manifest.edges
        if edge.label == "retry" and edge.source == "tourney-tiebreak-2"
    )
    assert retry_edge.source == "tourney-tiebreak-2"
    assert retry_edge.target == "tourney-judge"
    assert retry_edge.condition_ref == "tourney:tiebreak"

    judge = next(node for node in manifest.nodes if node.id == "tourney-judge")
    assert judge.policy is not None
    assert judge.policy.loop is not None
    assert judge.policy.loop.max_iterations == 2
    assert any(route.reentry_id == "tourney:tiebreak" for route in judge.policy.suspension_routes)


def test_loop_revise_is_explicit_bounded_reentry() -> None:
    shapes = _load_shapes()
    pipeline = _build_pipeline()
    manifest = compile_pipeline(pipeline, patterns=_build_pattern_blocks())
    _assert_shape_matches(manifest, shapes["loop_revise"])

    assert any(edge.condition_ref == "retry" for edge in manifest.edges)
    assert any(edge.condition_ref == "retry-revise" for edge in manifest.edges)


@pytest.mark.parametrize(
    "contract_name",
    list(_load_fixture_matrix()["python_authoring_m3"]["supported_subset"].keys()),
)
def test_python_authoring_m3_supported_subset_matches_canonical_contracts(
    contract_name: str,
) -> None:
    matrix = _load_fixture_matrix()["python_authoring_m3"]["supported_subset"]
    contract = matrix[contract_name]

    result = workflow_api.check_workflow_file(Path(contract["fixture"]))
    manifest = workflow_api.compile_workflow_file(Path(contract["fixture"]))

    assert result.ok
    _assert_m3_supported_subset_matches(manifest, contract)


def test_python_authoring_m3_deferred_canonical_shapes_are_annotated() -> None:
    matrix = _load_fixture_matrix()
    canonical_shapes = set(matrix["shapes"])
    deferred = matrix["python_authoring_m3"]["deferred_canonical_shapes"]
    diagnostic_codes = {code.value for code in workflow_api.diagnostics.DiagnosticCode}

    assert set(deferred) <= canonical_shapes
    for shape_name, annotation in deferred.items():
        assert annotation["reason"], shape_name
        if "expected_diagnostic" in annotation:
            assert annotation["expected_diagnostic"] in diagnostic_codes


def _canonical_manifest():
    pipeline = _build_pipeline()
    patterns = _build_pattern_blocks()
    return compile_pipeline(pipeline, patterns=patterns)


def test_locked_expected_nodes_match_compiled_manifest() -> None:
    manifest = _canonical_manifest()
    expected = _load_expected_shape("canonical_megaplan_nodes.yaml")["nodes"]
    nodes_by_id = {node.id: node for node in manifest.nodes}

    assert len(expected) == len(manifest.nodes)
    for expected_node in expected:
        node = nodes_by_id[expected_node["id"]]
        assert node.kind == expected_node["kind"]
        assert list(node.inputs) == expected_node["inputs"]
        assert list(node.outputs) == expected_node["outputs"]


def test_locked_expected_refs_match_compiled_manifest() -> None:
    manifest = _canonical_manifest()
    from arnold.workflow import inspect_manifest

    view = inspect_manifest(manifest)
    expected = _load_expected_shape("canonical_megaplan_refs.yaml")

    assert set(view["refs"]["nodes"]) == set(expected["nodes"])
    assert set(view["refs"]["edges"]) == set(expected["edges"])


def test_locked_expected_capabilities_match_compiled_manifest() -> None:
    manifest = _canonical_manifest()
    from arnold.workflow import inspect_manifest

    view = inspect_manifest(manifest)
    expected = _load_expected_shape("canonical_megaplan_capabilities.yaml")

    assert [dict(c) for c in view["capabilities"]["manifest"]] == expected["manifest"]
    assert {
        node_id: [dict(c) for c in caps]
        for node_id, caps in view["capabilities"]["nodes"].items()
    } == expected["nodes"]


def test_locked_expected_suspension_points_match_compiled_manifest() -> None:
    manifest = _canonical_manifest()
    from arnold.workflow import inspect_manifest

    view = inspect_manifest(manifest)
    expected = _load_expected_shape("canonical_megaplan_suspension_points.yaml")[
        "suspension_points"
    ]

    assert [dict(sp) for sp in view["suspension_points"]] == expected


def test_locked_expected_control_routes_match_compiled_manifest() -> None:
    manifest = _canonical_manifest()
    from arnold.workflow import inspect_manifest

    view = inspect_manifest(manifest)
    expected = _load_expected_shape("canonical_megaplan_control_routes.yaml")[
        "control_routes"
    ]

    assert [dict(cr) for cr in view["control_routes"]] == expected


def test_locked_expected_overlay_slots_match_compiled_manifest() -> None:
    manifest = _canonical_manifest()
    expected = _load_expected_shape("canonical_megaplan_overlay_slots.yaml")["overlay_slots"]

    actual = []
    for node in manifest.nodes:
        dynamic_events = node.metadata.get("dynamic_events")
        if dynamic_events:
            actual.append({"node_id": node.id, "dynamic_events": dynamic_events})
        if node.policy is not None:
            for slot in node.policy.topology_overlays:
                actual.append(
                    {
                        "node_id": node.id,
                        "overlay_id": slot.overlay_id,
                        "overlay_type": slot.overlay_type,
                        "source_ref": slot.source_ref,
                        "target_refs": list(slot.target_refs),
                        "condition_ref": slot.condition_ref,
                        "payload_schema_hash": slot.payload_schema_hash,
                    }
                )
    if manifest.policy is not None:
        for slot in manifest.policy.topology_overlays:
            actual.append(
                {
                    "node_id": None,
                    "overlay_id": slot.overlay_id,
                    "overlay_type": slot.overlay_type,
                    "source_ref": slot.source_ref,
                    "target_refs": list(slot.target_refs),
                    "condition_ref": slot.condition_ref,
                    "payload_schema_hash": slot.payload_schema_hash,
                }
            )

    assert actual == expected


def test_locked_expected_hashes_match_compiled_manifest() -> None:
    manifest = _canonical_manifest()
    expected = _load_expected_shape("canonical_megaplan_hashes.yaml")

    assert manifest.id == expected["id"]
    assert manifest.schema_version == expected["schema_version"]
    assert manifest.version == expected["version"]
    assert manifest.topology_hash == expected["topology_hash"]


# ── T13: Megaplan boundary contracts reconcile with generic surface ─────────
# Verify that Megaplan boundary contracts from arnold_pipelines.megaplan
# validate through the generic arnold.workflow template/profile surface
# without polluting the generic module with Megaplan-specific details.


def test_megaplan_boundary_contracts_importable_from_workflow_api() -> None:
    """Megaplan contracts must be importable and have expected structure."""
    from arnold_pipelines.megaplan.workflows.boundary_contracts import (
        BOUNDARY_CONTRACTS,
        AdapterTemplateKind,
        BoundaryTemplateKind,
    )

    # Verify imports resolve
    assert len(BOUNDARY_CONTRACTS) == 52
    assert len(list(BoundaryTemplateKind)) == 10
    assert len(list(AdapterTemplateKind)) == 7


def test_generic_boundary_templates_no_megaplan_imports() -> None:
    """arnold.workflow.boundary_templates must not import from arnold_pipelines.megaplan."""
    import ast
    from pathlib import Path

    src = Path(__file__).parents[3] / "arnold" / "workflow" / "boundary_templates.py"
    tree = ast.parse(src.read_text())

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                full = f"{node.module or ''}.{alias.name}" if hasattr(node, 'module') and node.module else alias.name
                assert "megaplan" not in full.lower(), (
                    f"boundary_templates.py must not import megaplan: {full}"
                )
                if isinstance(node, ast.ImportFrom) and node.module:
                    assert "megaplan" not in node.module.lower(), (
                        f"boundary_templates.py must not import megaplan module: {node.module}"
                    )


def test_megaplan_adapter_re_exports_generic_surface() -> None:
    """Megaplan boundary_contracts re-exports generic surface symbols."""
    from arnold.workflow import boundary_templates as bt

    from arnold_pipelines.megaplan.workflows import boundary_contracts as bc

    # Re-exported symbols must be the same object
    assert bc.BoundaryTemplateKind is bt.BoundaryTemplateKind
    assert bc.classify_boundary_kind is bt.classify_boundary_kind
    assert bc.get_required_fields is bt.get_required_fields
    assert bc.get_template is bt.get_template
    assert bc.list_template_kinds is bt.list_template_kinds
    assert bc.select_template is bt.select_template


def test_generic_surface_rejects_unknown_megaplan_kinds() -> None:
    """The generic check_contract_conformance must reject adapter-specific kind strings."""
    import pytest

    from arnold.workflow.boundary_templates import check_contract_conformance

    from arnold_pipelines.megaplan.workflows.boundary_contracts import (
        chain_milestone_template,
    )

    # Adapter-specific kinds should NOT be recognized by generic surface
    with pytest.raises((KeyError, ValueError)):
        check_contract_conformance(chain_milestone_template, "chain_milestone")
