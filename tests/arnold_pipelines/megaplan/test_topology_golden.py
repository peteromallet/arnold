"""Manifest topology fixture lock and amendment enforcement.

The canonical M4 Megaplan topology is locked in
``tests/arnold_pipelines/megaplan/fixtures/megaplan_m4_topology.yaml``.
If the compiled manifest diverges from this fixture, the test fails and
requires an amendment in ``docs/arnold/workflow-manifest-amendments.md``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from arnold.workflow.compiler import compile_pipeline
from arnold_pipelines.megaplan.pipeline import build_and_compile_pipeline, build_pipeline
from arnold_pipelines.megaplan.workflows import planning as workflow_planning

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "megaplan_m4_topology.yaml"
MANIFEST_GOLDEN_PATH = Path(__file__).parent / "fixtures" / "megaplan_m4_manifest_golden.json"
NORMALIZED_SHAPE_PATH = Path(__file__).parent / "fixtures" / "normalized_pipeline_shape.json"
AMENDMENT_PATH = Path(__file__).parents[3] / "docs" / "arnold" / "workflow-manifest-amendments.md"
LOCKED_MANIFEST_HASH = "sha256:962e57e7f8bb15761cc2a6a2e2bb64924eb6681bc86ed5fbf0de295df1ab5504"
LOCKED_TOPOLOGY_HASH = "sha256:295e0ad28430ff465334a36c6ff5add25fba1d21d7ba2449da6b081150098260"


@pytest.fixture
def fixture() -> dict:
    with FIXTURE_PATH.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


@pytest.fixture
def normalized_shape() -> dict[str, Any]:
    with NORMALIZED_SHAPE_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _fixture_has_m4_amendment() -> bool:
    if not AMENDMENT_PATH.exists():
        return False
    text = AMENDMENT_PATH.read_text(encoding="utf-8")
    return "## M4 Megaplan Product Migration" in text


def _normalize_source_span_paths(value: Any) -> Any:
    if isinstance(value, list):
        return [_normalize_source_span_paths(item) for item in value]
    if not isinstance(value, dict):
        return value
    normalized = {
        key: _normalize_source_span_paths(item)
        for key, item in value.items()
    }
    if "path" in normalized and isinstance(normalized["path"], str):
        parts = Path(normalized["path"]).parts
        if "arnold_pipelines" in parts:
            normalized["path"] = "/".join(parts[parts.index("arnold_pipelines"):])
    return normalized


def _canonical_manifest_json_bytes(manifest: Any) -> bytes:
    payload = json.loads(manifest.to_json())
    payload = _normalize_source_span_paths(payload)
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _io_contract(items: tuple[Any, ...]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in items:
        entry: dict[str, Any] = {"name": item.name}
        schema_hash = getattr(item, "schema_hash", None)
        value_ref = getattr(item, "value_ref", None)
        if schema_hash is not None:
            entry["schema_hash"] = schema_hash
        if value_ref is not None:
            entry["value_ref"] = value_ref
        if dict(getattr(item, "metadata", {}) or {}):
            entry["metadata"] = dict(item.metadata)
        result.append(entry)
    return result


def _capability_contract(capability: Any) -> dict[str, Any]:
    capability_id = getattr(capability, "id", None) or getattr(capability, "capability_id")
    return {
        "id": capability_id,
        "route": capability.route,
        "required": capability.required,
    }


def _policy_contract(policy: Any | None) -> dict[str, Any] | None:
    if policy is None:
        return None
    result: dict[str, Any] = {}
    if policy.loop is not None:
        result["loop"] = {
            "max_iterations": policy.loop.max_iterations,
            "until_ref": policy.loop.until_ref,
        }
    if policy.timing is not None:
        result["timing"] = {"timeout_seconds": policy.timing.timeout_seconds}
    if policy.control_transitions:
        result["control_transitions"] = [
            {
                "transition_id": slot.transition_id,
                "transition_type": slot.transition_type,
                "trigger_ref": slot.trigger_ref,
                "target_ref": slot.target_ref,
                "policy_ref": slot.policy_ref,
            }
            for slot in policy.control_transitions
        ]
    if policy.suspension_routes:
        routes: list[dict[str, Any]] = []
        for route in policy.suspension_routes:
            entry = {
                "route_id": route.route_id,
                "capability_id": route.capability_id,
            }
            if route.reentry_id is not None:
                entry["reentry_id"] = route.reentry_id
            routes.append(entry)
        result["suspension_routes"] = routes
    return result


def _subpipeline_contract(subpipeline: Any | None) -> dict[str, Any] | None:
    if subpipeline is None:
        return None
    return {
        "manifest_hash": subpipeline.manifest_hash,
        "alias": subpipeline.alias,
    }


def _normalized_pipeline_contract(pipeline: Any) -> dict[str, Any]:
    payload = {
        "fixture_schema": "arnold.megaplan.normalized_pipeline_shape.v1",
        "source": "arnold_pipelines.megaplan.pipeline:build_pipeline",
        "hash_neutral": True,
        "pipeline": {
            "id": pipeline.id,
            "version": pipeline.version,
            "metadata": dict(pipeline.metadata),
            "policy": _policy_contract(pipeline.policy),
        },
        "counts": {
            "steps": len(pipeline.steps),
            "routes": len(pipeline.routes),
            "capabilities": len(pipeline.capabilities),
        },
        "ordered_step_ids": [step.id for step in pipeline.steps],
        "steps": [
            {
                "id": step.id,
                "kind": step.kind,
                "inputs": _io_contract(step.inputs),
                "outputs": _io_contract(step.outputs),
                "capabilities": [_capability_contract(capability) for capability in step.capabilities],
                "policy": _policy_contract(step.policy),
                "handler_ref": step.metadata.get("handler_ref"),
                "terminal": bool(step.metadata.get("terminal", False)),
                "subpipeline": _subpipeline_contract(step.subpipeline),
                "metadata": dict(step.metadata),
            }
            for step in pipeline.steps
        ],
        "capabilities": [_capability_contract(capability) for capability in pipeline.capabilities],
        "routes": [
            {
                "id": route.id,
                "source": route.source,
                "target": route.target,
                "label": route.label,
                "condition_ref": route.condition_ref,
                "metadata": dict(route.metadata),
            }
            for route in pipeline.routes
        ],
    }
    return json.loads(json.dumps(payload, sort_keys=True, default=str))


def _manifest_policy_contract(policy: Any | None) -> dict[str, Any] | None:
    contract = _policy_contract(policy)
    return contract or None


class TestTopologyFixtureLock:
    def test_compiled_manifest_matches_locked_manifest_golden_bytes(self) -> None:
        manifest = build_and_compile_pipeline()
        assert manifest.manifest_hash == LOCKED_MANIFEST_HASH
        assert manifest.topology_hash == LOCKED_TOPOLOGY_HASH
        assert _canonical_manifest_json_bytes(manifest) == MANIFEST_GOLDEN_PATH.read_bytes()

    def test_workflow_surface_manifest_matches_locked_manifest_golden_bytes(self) -> None:
        manifest = compile_pipeline(workflow_planning.build_pipeline())
        assert manifest.manifest_hash == LOCKED_MANIFEST_HASH
        assert manifest.topology_hash == LOCKED_TOPOLOGY_HASH
        assert _canonical_manifest_json_bytes(manifest) == MANIFEST_GOLDEN_PATH.read_bytes()

    def test_compiled_manifest_matches_locked_topology(self, fixture: dict) -> None:
        manifest = build_and_compile_pipeline()
        assert manifest.id == fixture["manifest_id"]
        assert fixture["manifest_hash"] == LOCKED_MANIFEST_HASH
        assert fixture["topology_hash"] == LOCKED_TOPOLOGY_HASH
        assert manifest.manifest_hash == fixture["manifest_hash"]
        assert manifest.topology_hash == fixture["topology_hash"]

    def test_compiled_nodes_match_fixture(self, fixture: dict) -> None:
        manifest = build_and_compile_pipeline()
        node_ids = {n.id for n in manifest.nodes}
        assert node_ids == set(fixture["nodes"])

    def test_authored_node_order_matches_fixture(self, fixture: dict) -> None:
        pipeline = build_pipeline()
        assert [step.id for step in pipeline.steps] == fixture["nodes"]

    def test_compiled_capabilities_match_fixture(self, fixture: dict) -> None:
        manifest = build_and_compile_pipeline()
        cap_ids = {c.id for c in manifest.capabilities}
        assert cap_ids == set(fixture["capabilities"])

    def test_compiled_gate_edges_match_fixture(self, fixture: dict) -> None:
        manifest = build_and_compile_pipeline()
        gate_edges = {
            (e.label, e.target)
            for e in manifest.edges
            if e.source == "gate"
        }
        expected = {(item["label"], item["target"]) for item in fixture["gate_targets"]}
        assert gate_edges == expected

    def test_compiled_tiebreaker_edges_match_fixture(self, fixture: dict) -> None:
        manifest = build_and_compile_pipeline()
        edges = {
            (e.label, e.target)
            for e in manifest.edges
            if e.source == "tiebreaker_decision"
        }
        expected = {(item["label"], item["target"]) for item in fixture["tiebreaker_targets"]}
        assert edges == expected

    def test_loop_suspension_routes_survive_lowering_and_compilation(self) -> None:
        pipeline = build_pipeline()
        pipeline_loop_routes = {
            route.id: (route.source, route.target, route.label, route.condition_ref)
            for route in pipeline.routes
            if route.id == "tiebreaker_decision:critique"
        }
        assert pipeline_loop_routes == {
            "tiebreaker_decision:critique": (
                "tiebreaker_decision",
                "revise",
                "iterate",
                "tiebreaker:loop",
            ),
        }

        manifest = build_and_compile_pipeline()
        manifest_loop_edges = {
            edge.id: (edge.source, edge.target, edge.label, edge.condition_ref)
            for edge in manifest.edges
            if edge.id == "tiebreaker_decision:critique"
        }
        assert manifest_loop_edges == pipeline_loop_routes

    def test_compiled_review_edges_match_fixture(self, fixture: dict) -> None:
        manifest = build_and_compile_pipeline()
        edges = {
            (e.label, e.target)
            for e in manifest.edges
            if e.source == "review"
        }
        expected = {(item["label"], item["target"]) for item in fixture["review_targets"]}
        assert edges == expected

    def test_route_order_for_branch_nodes_is_stable(self) -> None:
        pipeline = build_pipeline()
        labels_by_source = {
            source: [route.label for route in pipeline.routes if route.source == source]
            for source in ("gate", "tiebreaker_decision", "review")
        }

        assert labels_by_source == {
            "gate": [
                "proceed",
                "iterate",
                "tiebreaker",
                "escalate",
                "abort",
                "suspend",
                "blocked_preflight",
                "force_proceed",
            ],
            "tiebreaker_decision": ["proceed", "iterate", "escalate", "replan"],
            "review": [],
        }

    @pytest.mark.parametrize(
        ("surface", "builder"),
        [
            ("workflow_planning", workflow_planning.build_pipeline),
            ("pipeline_facade", build_pipeline),
        ],
    )
    def test_public_surfaces_match_normalized_explicit_contract(
        self,
        normalized_shape: dict[str, Any],
        surface: str,
        builder: Any,
    ) -> None:
        actual = _normalized_pipeline_contract(builder())
        assert actual == normalized_shape, surface

    def test_compiled_manifest_preserves_explicit_contract_details(
        self,
        normalized_shape: dict[str, Any],
    ) -> None:
        manifest = build_and_compile_pipeline()
        nodes_by_id = {node.id: node for node in manifest.nodes}
        edges_by_id = {edge.id: edge for edge in manifest.edges}

        assert {node.id for node in manifest.nodes} == set(normalized_shape["ordered_step_ids"])
        assert [
            _capability_contract(capability)
            for capability in manifest.capabilities
        ] == normalized_shape["capabilities"]

        for expected_step in normalized_shape["steps"]:
            node = nodes_by_id[expected_step["id"]]
            assert node.kind == expected_step["kind"]
            assert _manifest_policy_contract(node.policy) == expected_step["policy"]
            assert _subpipeline_contract(node.subpipeline) == expected_step["subpipeline"]
            for key in ("handler_ref", "terminal"):
                if key in expected_step["metadata"]:
                    assert node.metadata.get(key) == expected_step["metadata"][key]

        for expected_route in normalized_shape["routes"]:
            edge = edges_by_id[expected_route["id"]]
            assert {
                "id": edge.id,
                "source": edge.source,
                "target": edge.target,
                "label": edge.label,
                "condition_ref": edge.condition_ref,
                "metadata": edge.metadata,
            } == expected_route


class TestM6StructuralPolicyAttachments:
    """M6: verify structure and policy attachments — not just route labels alone.

    These tests ensure the compiled manifest and authored topology expose the
    extraction work from T7-T11: gate routing, critique fanout, review rework
    cycles, execute gates, override dispatch, tiebreaker subworkflow, and
    finalize fallback routes must all be visible as declared policy surfaces.
    """

    # ── compiled manifest policy-attachment tests ────────────────────────

    def test_gate_node_exposes_full_policy_surface(self) -> None:
        manifest = build_and_compile_pipeline()
        gate_node = next(node for node in manifest.nodes if node.id == "gate")

        # Policy timing must be declared
        assert gate_node.policy is not None
        assert gate_node.policy.timing is not None
        assert gate_node.policy.timing.timeout_seconds == 300.0

        # Suspension route to human:gate must be declared
        assert gate_node.policy.suspension_routes is not None
        gate_suspension_ids = {r.route_id for r in gate_node.policy.suspension_routes}
        assert "gate:human" in gate_suspension_ids

        # Control transitions must cover all 5 standard gate outcomes
        transitions = gate_node.policy.control_transitions or []
        transition_ids = {t.transition_id for t in transitions}
        assert transition_ids >= {"gate:proceed", "gate:iterate", "gate:tiebreaker", "gate:escalate", "gate:abort"}

        # Policy refs must be visible on metadata
        # Gate doesn't carry policy_refs in compiled manifest metadata
        # (policy is declared on the workflow component, not the manifest node)

    def test_review_node_exposes_rework_cap_and_escalation_policy(self) -> None:
        manifest = build_and_compile_pipeline()
        review_node = next(node for node in manifest.nodes if node.id == "review")

        # Suspension route to human:review
        assert review_node.policy.suspension_routes is not None
        review_suspension_ids = {r.route_id for r in review_node.policy.suspension_routes}
        assert "review:human" in review_suspension_ids

        # Control transitions for rework, done, blocked, force_proceeded, deferred_human
        transitions = review_node.policy.control_transitions or []
        transition_ids = {t.transition_id for t in transitions}
        assert transition_ids >= {"review:rework", "review:done", "review:blocked", "review:force_proceeded", "review:deferred_human"}

        # Escalation and retry policy surfaces
        assert review_node.policy.escalation is not None
        assert review_node.policy.retry is not None

        # Policy refs
        policy_refs = review_node.metadata.get("policy_refs", [])
        assert "megaplan:review" in policy_refs

    def test_execute_node_exposes_batch_gate_and_escalation_policy(self) -> None:
        manifest = build_and_compile_pipeline()
        execute_node = next(node for node in manifest.nodes if node.id == "execute")

        # Suspension route for execution resume
        assert execute_node.policy.suspension_routes is not None
        execute_suspension_ids = {r.route_id for r in execute_node.policy.suspension_routes}
        assert "execute:resume" in execute_suspension_ids

        # Escalation and retry surfaces
        assert execute_node.policy.escalation is not None
        assert execute_node.policy.retry is not None

        # Policy refs must include execute-specific refs
        policy_refs = execute_node.metadata.get("policy_refs", [])
        assert "megaplan:execute" in policy_refs

    def test_execute_route_bindings_not_authoritative_in_component(self) -> None:
        """Execute route authority lives in policy/pypeline, not in component
        route_bindings.  The compiled execute node must still carry the
        execute→review edge, but the component-level route_bindings must be
        absent (or empty) so they cannot become authoritative."""
        from arnold_pipelines.megaplan import workflows as wf

        execute_component = wf.STEP_COMPONENTS_BY_ID["execute"]
        bindings = execute_component.metadata.get("route_bindings", ())
        assert bindings == (), (
            "EXECUTE step component must not carry authoritative route_bindings; "
            "route authority is in EXECUTE_POLICY.route_surface / workflow.pypeline"
        )

        # The compiled manifest must still carry the execute→review edge.
        manifest = build_and_compile_pipeline()
        execute_edges = [
            e for e in manifest.edges
            if e.source == "execute"
        ]
        assert len(execute_edges) == 1, (
            "compiled manifest must preserve single execute→review edge "
            "derived from the pypeline"
        )
        assert execute_edges[0].target == "review"

    def test_override_node_exposes_full_action_matrix_in_policy_overlays(self) -> None:
        manifest = build_and_compile_pipeline()
        override_node = next(node for node in manifest.nodes if node.id == "override")

        # Topology overlays must exist for all 14 override actions
        overlays = override_node.policy.topology_overlays or []
        overlay_ids = {o.overlay_id for o in overlays}
        expected_overlay_ids = {
            "override:abort", "override:add-note", "override:adopt-execution",
            "override:cap-revise-once",
            "override:cutover", "override:force-proceed",
            "override:reconcile-plan-ledger", "override:recover-blocked",
            "override:replan", "override:resume-clarify", "override:set-model",
            "override:set-profile", "override:set-robustness", "override:set-vendor",
        }
        assert overlay_ids == expected_overlay_ids

        # Terminal route overlays target correct nodes (target_refs are tuples)
        terminal_overlays = {o.overlay_id: o.target_refs for o in overlays if o.overlay_type == "terminal_route"}
        assert terminal_overlays["override:abort"] == ("halt",)
        assert terminal_overlays["override:force-proceed"] == ("finalize",)
        assert terminal_overlays["override:replan"] == ("revise",)
        assert terminal_overlays["override:adopt-execution"] == ("review",)
        assert terminal_overlays["override:resume-clarify"] == ("plan",)

        # Additive config overlays target current-phase
        config_overlays = {o.overlay_id: o.target_refs for o in overlays if o.overlay_type == "additive_config"}
        for overlay_id in ("override:add-note", "override:set-model", "override:set-profile", "override:set-robustness", "override:set-vendor"):
            assert config_overlays[overlay_id] == ("current-phase",)

        # Policy refs
        policy_refs = override_node.metadata.get("policy_refs", [])
        assert "megaplan:override" in policy_refs

    def test_revise_node_exposes_loop_policy(self) -> None:
        manifest = build_and_compile_pipeline()
        revise_node = next(node for node in manifest.nodes if node.id == "revise")

        # Loop policy with max_iterations must be declared
        assert revise_node.policy.loop is not None
        assert revise_node.policy.loop.max_iterations == 4
        assert revise_node.policy.loop.until_ref is not None

        # Suspension route for loop reentry
        revise_suspension_ids = {r.route_id for r in (revise_node.policy.suspension_routes or [])}
        assert "revise:loop" in revise_suspension_ids

    def test_tiebreaker_decide_node_exposes_loop_and_transitions(self) -> None:
        manifest = build_and_compile_pipeline()
        tiebreaker_node = next(node for node in manifest.nodes if node.id == "tiebreaker_decision")

        # Loop policy
        assert tiebreaker_node.policy.loop is not None
        assert tiebreaker_node.policy.loop.max_iterations == 4

        # Control transitions for iterate, proceed, escalate
        transitions = tiebreaker_node.policy.control_transitions or []
        transition_ids = {t.transition_id for t in transitions}
        assert transition_ids >= {"tiebreaker:iterate", "tiebreaker:proceed", "tiebreaker:escalate"}

        # Suspension for loop reentry
        tiebreaker_suspension_ids = {r.route_id for r in (tiebreaker_node.policy.suspension_routes or [])}
        assert "tiebreaker:loop" in tiebreaker_suspension_ids

    def test_manifest_level_policy_surface_declares_suspension_routes(self) -> None:
        manifest = build_and_compile_pipeline()
        assert manifest.policy is not None
        manifest_suspension = {r.route_id for r in (manifest.policy.suspension_routes or [])}
        assert manifest_suspension >= {"gate:human", "review:human", "revise:loop", "tiebreaker:loop", "execute:resume"}

    # ── canonical authoring topology structural tests ────────────────────

    def test_rendered_policy_surface_matches_workflow_policy_declarations(self) -> None:
        """Rendered manifest policy must agree with workflow component policy declarations."""
        manifest = build_and_compile_pipeline()
        nodes_by_id = {node.id: node for node in manifest.nodes}

        # Gate: verify rendered policy matches declared GATE_POLICY
        gate_node = nodes_by_id["gate"]
        assert gate_node.policy is not None
        assert gate_node.policy.suspension_routes

        # Review: verify rendered policy matches declared REVIEW_POLICY
        review_node = nodes_by_id["review"]
        assert review_node.policy.escalation is not None
        assert review_node.policy.retry is not None

        # Execute: verify rendered policy matches declared EXECUTE_POLICY
        execute_node = nodes_by_id["execute"]
        assert execute_node.policy.escalation is not None
        assert execute_node.policy.retry is not None

        # Override: verify topology overlays match OVERRIDE_POLICY
        override_node = nodes_by_id["override"]
        overlays = override_node.policy.topology_overlays or []
        assert len(overlays) == 14  # all 14 override actions

    def test_override_matrix_aligns_with_manifest_topology_overlays(self) -> None:
        """Override matrix classification must agree with manifest topology overlays."""
        from arnold_pipelines.megaplan.workflows.override_matrix import (
            OVERRIDE_ACTION_MATRIX,
            TERMINAL_ROUTE_ACTIONS,
            ADDITIVE_CONFIG_ACTIONS,
        )

        manifest = build_and_compile_pipeline()
        override_node = next(node for node in manifest.nodes if node.id == "override")
        overlays = override_node.policy.topology_overlays or []

        terminal_overlay_actions = {
            o.overlay_id.replace("override:", "")
            for o in overlays
            if o.overlay_type == "terminal_route"
        }
        config_overlay_actions = {
            o.overlay_id.replace("override:", "")
            for o in overlays
            if o.overlay_type == "additive_config"
        }

        # Matrix terminal route actions must match manifest terminal overlays
        assert terminal_overlay_actions == set(TERMINAL_ROUTE_ACTIONS), (
            f"Matrix terminal actions {set(TERMINAL_ROUTE_ACTIONS)} != manifest {terminal_overlay_actions}"
        )
        # Matrix additive config actions must match manifest config overlays
        assert config_overlay_actions == set(ADDITIVE_CONFIG_ACTIONS), (
            f"Matrix config actions {set(ADDITIVE_CONFIG_ACTIONS)} != manifest {config_overlay_actions}"
        )
        # All 14 keys must be covered by manifest overlays
        assert len(OVERRIDE_ACTION_MATRIX) == 14
        assert len(overlays) == 14


class TestAmendmentEnforcement:
    def test_structural_fixture_changes_require_amendment(self, fixture: dict) -> None:
        manifest = build_and_compile_pipeline()
        # If the manifest or topology hash changed from the locked fixture,
        # an M4 amendment must exist explaining the change.
        if (
            manifest.manifest_hash != fixture["manifest_hash"]
            or manifest.topology_hash != fixture["topology_hash"]
        ):
            assert _fixture_has_m4_amendment(), (
                "Manifest/topology hash changed; add an M4 amendment to "
                "docs/arnold/workflow-manifest-amendments.md"
            )
