"""Product-local Megaplan workflow authoring components.

The neutral authoring dataclasses live in :mod:`arnold.workflow.authoring`.
This module binds those primitives to Megaplan's stable product contract:
handler refs, prompt resolver families, route vocabulary, capability
requirements, and terminal metadata. It intentionally references prompt
builders by family/ref only and does not copy prompt strings.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, Mapping

from arnold.workflow.authoring import (
    ComponentContract,
    ComponentKind,
    ComponentProvenance,
    PolicyComponent,
    PromptComponent,
    SchemaComponent,
    StepComponent,
)
from arnold_pipelines.megaplan.outcomes import (
    GateOutcome,
    OUTCOME_CLASS_BY_VOCABULARY_KEY,
    OverrideOutcome,
    ReviewOutcome,
    TiebreakerOutcome,
)
from arnold_pipelines.megaplan.workflows.override_matrix import (
    ADDITIVE_CONFIG_ACTIONS,
    OVERRIDE_ACTION_MATRIX,
    get_entry,
)

PROMPT_RESOLVER_REF = "arnold_pipelines.megaplan.prompts:create_prompt"
PROMPT_COMPONENT_RESOLVER_REF = "arnold_pipelines.megaplan.prompts:create_prompt_components"
HANDLER_MODULE = "arnold_pipelines.megaplan.handlers"
M4_LOOP_MAX_ITERATIONS = 4


class _RouteSignalAlias(str):
    def __new__(cls, value: str, *aliases: str) -> "_RouteSignalAlias":
        obj = str.__new__(cls, value)
        obj._aliases = frozenset(aliases)
        return obj

    def __eq__(self, other: object) -> bool:
        return str.__eq__(self, other) or other in self._aliases

    __hash__ = str.__hash__


class _SupersetComparableMapping(dict):
    __arnold_preserve_mapping__ = True

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Mapping):
            return False
        if set(other).issubset(set(self)):
            return all(self[key] == value for key, value in other.items())
        return dict.__eq__(self, other)


def _superset_mapping(value: Mapping[str, Any]) -> _SupersetComparableMapping:
    return _SupersetComparableMapping(
        {
            key: _superset_mapping(subvalue)
            if isinstance(subvalue, Mapping)
            else tuple(subvalue)
            if isinstance(subvalue, list)
            else subvalue
            for key, subvalue in value.items()
        }
    )


CAPABILITY_REQUIREMENTS = MappingProxyType(
    {
        "megaplan:planning": {"route": "default", "required": True},
        "human:gate": {"route": "default", "required": False},
        "human:review": {"route": "default", "required": False},
    }
)

RUNTIME_BRANCH_VOCABULARY = MappingProxyType(
    {
        "prep": ("continue", "awaiting_human"),
        "critique": ("completed",),
        "gate": (
            "proceed",
            "iterate",
            "tiebreaker",
            "escalate",
            "abort",
            "suspend",
            "blocked_preflight",
            "force_proceed",
            "retry_gate",
            "reprompt_downgrade",
        ),
        "tiebreaker_researcher": ("completed",),
        "tiebreaker_challenger": ("completed",),
        "tiebreaker_synthesis": ("completed",),
        "tiebreaker_decision": ("proceed", "iterate", "escalate", "replan"),
        "tiebreaker_decide": ("proceed", "iterate", "escalate", "replan"),  # compatibility bridge
        "review": ("pass", "rework", "blocked", "force_proceeded", "deferred_human"),
        "override": (
            "abort",
            "cap_revise_once",
            "cutover",
            "force_proceed",
            "replan",
        ),
        "revise": ("completed",),
    }
)

_OUTCOME_VOCABULARY_BY_STEP = OUTCOME_CLASS_BY_VOCABULARY_KEY

_COMPATIBILITY_QUARANTINE = MappingProxyType(
    {
        "compatibility_quarantine": MappingProxyType(
            {
                "kind": "route_metadata_removed",
                "canonical_source": "arnold_pipelines.megaplan.workflows.workflow.pypeline",
            }
        )
    }
)


def _declared_step_interface_quarantine(step_id: str, metadata: Mapping[str, Any]) -> Mapping[str, Any]:
    preserved_fields = tuple(
        field
        for field in (
            "handler_ref",
            "route_bindings",
            "policy_refs",
            "capability_requirements",
            "override_actions",
        )
        if field in metadata and metadata[field] not in ((), None)
    )
    if not preserved_fields:
        return {}
    return MappingProxyType(
        {
            "compatibility_quarantine": MappingProxyType(
                {
                    "kind": "declared_step_interface_bridge",
                    "canonical_refs": (
                        f"arnold_pipelines.megaplan.workflows.workflow.pypeline:{step_id}",
                        f"arnold_pipelines.megaplan.workflows.planning:declared_step_interface({step_id})",
                    ),
                    "preserved_fields": preserved_fields,
                }
            )
        }
    )


def _declared_workflow_topology_quarantine(
    workflow_id: str,
    metadata: Mapping[str, Any],
) -> Mapping[str, Any]:
    preserved_fields = tuple(
        field
        for field in ("topology_contract", "fan_in_ref", "policy_refs")
        if field in metadata and metadata[field] not in ((), None)
    )
    if not preserved_fields:
        return {}
    return MappingProxyType(
        {
            "compatibility_quarantine": MappingProxyType(
                {
                    "kind": "declared_topology_contract_bridge",
                    "canonical_refs": (
                        f"arnold_pipelines.megaplan.workflows.workflow.pypeline:{workflow_id}",
                        "arnold_pipelines.megaplan.workflows.workflow.pypeline:DECLARED_WORKFLOW_TOPOLOGY_CONTRACTS",
                        (
                            "arnold_pipelines.megaplan.workflows.planning:"
                            f"declared_workflow_topology_contract({workflow_id})"
                        ),
                    ),
                    "preserved_fields": preserved_fields,
                }
            )
        }
    )


def _adapter_metadata_quarantine(
    *,
    canonical_refs: tuple[str, ...],
    preserved_fields: tuple[str, ...],
) -> Mapping[str, Any]:
    return MappingProxyType(
        {
            "compatibility_quarantine": MappingProxyType(
                {
                    "kind": "non_authoritative_adapter_metadata",
                    "canonical_refs": canonical_refs,
                    "preserved_fields": preserved_fields,
                }
            )
        }
    )


def _pure_body_carrier_quarantine(
    *,
    canonical_refs: tuple[str, ...],
    preserved_fields: tuple[str, ...],
) -> Mapping[str, Any]:
    return MappingProxyType(
        {
            "compatibility_quarantine": MappingProxyType(
                {
                    "kind": "pure_body_component_metadata_bridge",
                    "canonical_refs": canonical_refs,
                    "preserved_fields": preserved_fields,
                    "sunset_condition": "typed_interfaces_replace_component_metadata",
                }
            )
        }
    )


def check_outcome_vocabulary_parity() -> dict[str, dict[str, tuple[str, ...]]]:
    """Return runtime/typed outcome vocabulary mismatches by step id."""

    mismatches: dict[str, dict[str, tuple[str, ...]]] = {}
    for step_id, outcome_type in _OUTCOME_VOCABULARY_BY_STEP.items():
        runtime_values = set(RUNTIME_BRANCH_VOCABULARY.get(step_id, ()))
        outcome_values = {member.value for member in outcome_type}
        missing_from_runtime = tuple(sorted(outcome_values - runtime_values))
        missing_from_outcome = tuple(sorted(runtime_values - outcome_values))
        if missing_from_runtime or missing_from_outcome:
            mismatches[step_id] = {
                "missing_from_runtime": missing_from_runtime,
                "missing_from_outcome": missing_from_outcome,
            }
    return mismatches


def _provenance(export_name: str) -> ComponentProvenance:
    return ComponentProvenance(
        module=__name__,
        qualname=export_name,
        export_name=export_name,
    )


def _prompt(step_id: str) -> PromptComponent:
    return PromptComponent(
        id=f"megaplan:prompt:{step_id}",
        provenance=ComponentProvenance(
            module="arnold_pipelines.megaplan.prompts",
            qualname="create_prompt",
            export_name="create_prompt",
        ),
        label=f"Megaplan {step_id} prompt resolver",
        parameters=("agent", "step", "state", "plan_dir", "root"),
        metadata={
            "step_id": step_id,
            "resolver_ref": PROMPT_RESOLVER_REF,
            "component_resolver_ref": PROMPT_COMPONENT_RESOLVER_REF,
            "builder_family_refs": (
                "arnold_pipelines.megaplan.prompts:_CLAUDE_PROMPT_BUILDERS",
                "arnold_pipelines.megaplan.prompts:_CODEX_PROMPT_BUILDERS",
            ),
        },
    )


def _policy(
    *,
    export_name: str,
    policy_id: str,
    policy_type: str,
    config: Mapping[str, Any],
    label: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> PolicyComponent:
    return PolicyComponent(
        id=policy_id,
        provenance=_provenance(export_name),
        policy_type=policy_type,
        label=label or f"Megaplan {policy_id.removeprefix('megaplan:')} policy",
        config=config,
        metadata={} if metadata is None else metadata,
    )


def _step(
    *,
    export_name: str,
    step_id: str,
    kind: str,
    prompt: PromptComponent | None = None,
    handler_ref: str | None = None,
    inputs: tuple[Mapping[str, str], ...] = (),
    outputs: tuple[Mapping[str, str], ...] = (),
    policy: PolicyComponent | None = None,
    route_bindings: tuple[Mapping[str, Any], ...] = (),
    capability_ids: tuple[str, ...] = (),
    terminal: bool = False,
    metadata: Mapping[str, Any] | None = None,
    input_schema: SchemaComponent | None = None,
    output_schema: SchemaComponent | None = None,
) -> StepComponent:
    component_metadata: dict[str, Any] = {
        "kind": kind,
        "inputs": inputs,
        "outputs": outputs,
        "policy_id": policy.id if policy is not None else "megaplan:default",
        "route_bindings": route_bindings,
        "capability_requirements": tuple(
            {
                "id": capability_id,
                **CAPABILITY_REQUIREMENTS[capability_id],
            }
            for capability_id in capability_ids
        ),
        "terminal": terminal,
    }
    if handler_ref is not None:
        component_metadata["handler_ref"] = handler_ref
    if step_id in RUNTIME_BRANCH_VOCABULARY:
        component_metadata["runtime_branch_vocabulary"] = RUNTIME_BRANCH_VOCABULARY[step_id]
    if metadata:
        component_metadata.update(metadata)
    if "compatibility_quarantine" not in component_metadata:
        component_metadata.update(_declared_step_interface_quarantine(step_id, component_metadata))
    return StepComponent(
        id=f"megaplan:{step_id}",
        provenance=_provenance(export_name),
        label=f"Megaplan {step_id}",
        step_type=kind,
        prompt=prompt,
        policy=policy,
        input_schema=input_schema,
        output_schema=output_schema,
        metadata=component_metadata,
    )


def _schema(
    *,
    export_name: str,
    schema_id: str,
    schema_type: str,
    fields: Mapping[str, Any],
    label: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> SchemaComponent:
    return SchemaComponent(
        id=f"megaplan:schema:{schema_id}",
        provenance=_provenance(export_name),
        schema_type=schema_type,
        label=label or f"Megaplan {schema_id} schema",
        schema=MappingProxyType(dict(fields)),
        metadata=MappingProxyType({} if metadata is None else dict(metadata)),
    )


def _workflow(
    *,
    export_name: str,
    workflow_id: str,
    inputs: tuple[str, ...],
    outputs: tuple[str, ...],
    label: str,
    metadata: Mapping[str, Any] | None = None,
) -> ComponentContract:
    component_metadata: dict[str, Any] = {
        "workflow_id": workflow_id,
        "input_names": inputs,
        "output_names": outputs,
    }
    if metadata:
        component_metadata.update(metadata)
    if "compatibility_quarantine" not in component_metadata:
        component_metadata.update(_declared_workflow_topology_quarantine(workflow_id, component_metadata))
    return ComponentContract(
        id=f"megaplan:{workflow_id}",
        kind=ComponentKind.WORKFLOW,
        provenance=_provenance(export_name),
        label=label,
        metadata=component_metadata,
    )


def _override_action_target(action: str) -> str:
    entry = get_entry(action)
    if entry.target_ref is not None:
        return entry.target_ref
    return "current-phase"


def _override_action_overlays() -> tuple[Mapping[str, Any], ...]:
    overlays: list[Mapping[str, Any]] = []
    for entry in sorted(OVERRIDE_ACTION_MATRIX, key=lambda item: item.action):
        overlays.append(
            {
                "overlay_id": f"override:{entry.action}",
                "overlay_type": entry.family,
                "source_ref": "override.action",
                "target_refs": (_override_action_target(entry.action),),
                "condition_ref": f"override.action.eq.{entry.action}",
            }
        )
    return tuple(overlays)


def _override_action_effects() -> tuple[Mapping[str, Any], ...]:
    return tuple(
        {
            "effect_id": get_entry(action).effect_id,
            "payload_ref": "override.override_result",
            "idempotency": {"key_ref": f"override.{action.replace('-', '_')}"},
        }
        for action in sorted(ADDITIVE_CONFIG_ACTIONS)
    )


def _override_route_surface() -> Mapping[str, Any]:
    return {
        "matrix_ref": "arnold_pipelines.megaplan.workflows.override_matrix:OVERRIDE_ACTION_MATRIX",
        "actions": tuple(
            {
                "action": entry.action,
                "family": entry.family,
                "route_signal": entry.route_signal,
                "target_ref": entry.target_ref,
                "effect_id": entry.effect_id,
                "dispatch_surface": entry.dispatch_surface,
                "control_routed": entry.control_routed,
            }
            for entry in OVERRIDE_ACTION_MATRIX
        ),
    }


def _review_cap_threshold_surface() -> Mapping[str, Any]:
    return {
        "rework_cycles": {
            "default_config_key": "max_review_rework_cycles",
            "robust_config_key": "max_robust_review_rework_cycles",
            "robustness_levels": ("thorough", "extreme"),
            "history_ref": "state.history.review.needs_rework",
            "on_exhausted_condition_ref": "review.cap_exhausted",
        },
        "force_proceed_blockers": {
            "criteria_ref": "review.criteria",
            "rework_items_ref": "review.rework_items",
            "helper_ref": "arnold_pipelines.megaplan.handlers.review:_force_proceed_blockers",
            "blocking_outcome": "blocked",
            "advisory_outcome": "force_proceeded",
        },
    }


def _review_force_proceed_surface() -> Mapping[str, Any]:
    return {
        "route_signal": "force_proceeded",
        "target_ref": "halt",
        "state_ref": "done",
        "authority": "review_policy",
        "trigger_ref": "review.cap_exhausted",
        "allowed_when": "remaining review items are advisory or cosmetic only",
    }


def _review_human_verification_surface() -> Mapping[str, Any]:
    return {
        "route_signal": "deferred_human",
        "suspension_route_id": "review:human",
        "capability_id": "human:review",
        "state_ref": "awaiting_human_verify",
        "resume_policy_ref": "megaplan:suspension",
        "resume_schema_ref": "arnold_pipelines.megaplan.runtime.resume:ResumeContract",
        "resume_payload_ref": "review.review_payload",
    }


def _review_blocked_and_advisory_surface() -> Mapping[str, Any]:
    return {
        "blocked": {
            "route_signal": "blocked",
            "target_ref": "override",
            "state_ref": "blocked",
            "trigger_refs": (
                "review_incomplete",
                "review_process_error",
                "missing_reviewer_evidence",
                "review.cap_exhausted_with_blockers",
            ),
        },
        "advisory_force_proceed": _review_force_proceed_surface(),
    }


def _review_source_control_transitions() -> tuple[Mapping[str, Any], ...]:
    return (
        {
            "transition_id": "review:pass",
            "route_signal": "pass",
            "target_ref": "halt",
            "topology_ref": "review-fan-in",
            "source_step_id": "review_halt",
        },
        {
            "transition_id": "review:rework",
            "route_signal": "rework",
            "target_ref": "execute",
            "topology_ref": "review-fan-in",
            "source_step_id": "review-rework-execute-batches",
        },
        {
            "transition_id": "review:blocked",
            "route_signal": "blocked",
            "target_ref": "override",
            "topology_ref": "review-fan-in",
            "source_step_id": "review_override",
        },
        {
            "transition_id": "review:force_proceeded",
            "route_signal": "force_proceeded",
            "target_ref": "halt",
            "topology_ref": "review-fan-in",
            "source_step_id": "review_halt",
        },
        {
            "transition_id": "review:deferred_human",
            "route_signal": "deferred_human",
            "target_ref": "halt",
            "topology_ref": "review-fan-in",
            "source_step_id": "review_deferred_human",
        },
        {
            "transition_id": "review_rework:pass",
            "route_signal": "pass",
            "target_ref": "halt",
            "topology_ref": "review-rework-fan-in",
            "source_step_id": "review_rework_halt",
        },
        {
            "transition_id": "review_rework:rework",
            "route_signal": "rework",
            "target_ref": "revise",
            "topology_ref": "review-rework-fan-in",
            "source_step_id": "review_revise",
        },
        {
            "transition_id": "review_rework:blocked",
            "route_signal": "blocked",
            "target_ref": "override",
            "topology_ref": "review-rework-fan-in",
            "source_step_id": "review_rework_override",
        },
        {
            "transition_id": "review_rework:force_proceeded",
            "route_signal": "force_proceeded",
            "target_ref": "halt",
            "topology_ref": "review-rework-fan-in",
            "source_step_id": "review_rework_halt",
        },
        {
            "transition_id": "review_rework:deferred_human",
            "route_signal": "deferred_human",
            "target_ref": "halt",
            "topology_ref": "review-rework-fan-in",
            "source_step_id": "review_rework_deferred_human",
        },
    )


def _review_authored_topology_surface() -> Mapping[str, Any]:
    return {
        "fan_in_ids": {
            "first_pass": "review-fan-in",
            "rework_pass": "review-rework-fan-in",
        },
        "review_prefix_variants": (
            "review",
            "tiebreaker-review",
            "tiebreaker-override-review",
            "override-review",
        ),
        "control_transitions": _review_source_control_transitions(),
    }


def _review_route_surface() -> Mapping[str, Any]:
    return {
        "fan_in_contract": {
            "parallel_map_id": "review-fan-in",
            "fan_in_ref": "review.checks",
            "step_ref": "SOURCE_REVIEW_PANEL_WORKFLOW",
            "reducer_ref": "SOURCE_REVIEW",
            "path_template": "review/{item_id}",
            "route_signal": "review_route_signal",
        },
        "route_groups": {
            "halt": ("pass", "force_proceeded", "deferred_human"),
            "rework": ("rework",),
            "recoverable_block": ("blocked",),
        },
        "rework_cycle": {
            "route_signal": "rework",
            "target_ref": "execute",
            "state_ref": "finalized",
            "fresh_execute_session": True,
        },
        "retry_and_cap": {
            "infrastructure_retry": {
                "route_signal": "blocked",
                "target_ref": "review",
                "state_ref": "executed",
                "retry_on": (
                    "review_incomplete",
                    "review_process_error",
                    "missing_reviewer_evidence",
                ),
            },
            "cap_exhausted_non_blocking": _review_force_proceed_surface(),
            "cap_exhausted_with_blockers": {
                "route_signal": "blocked",
                "target_ref": "override",
                "state_ref": "blocked",
                "resume_cursor": {
                    "phase": "review",
                    "retry_strategy": "manual_review",
                },
            },
        },
        "cap_thresholds": _review_cap_threshold_surface(),
        "blocked_and_advisory_outcomes": _review_blocked_and_advisory_surface(),
        "force_proceed_authority": _review_force_proceed_surface(),
        "human_verification": _review_human_verification_surface(),
        "authored_topology": _review_authored_topology_surface(),
        "escalation": {
            "policy_ref": "megaplan:override",
            "route_signal": "blocked",
            "actions": ("recover-blocked", "force-proceed"),
        },
    }


PREP_INPUT_SCHEMA = _schema(
    export_name="PREP_INPUT_SCHEMA",
    schema_id="prep:input",
    schema_type="input",
    fields={
        "agent": {"type": "string", "description": "Agent specification for the plan run"},
        "root": {"type": "string", "description": "Root directory for plan execution"},
        "config": {"type": "object", "description": "Optional plan configuration overrides"},
    },
)
PREP_OUTPUT_SCHEMA = _schema(
    export_name="PREP_OUTPUT_SCHEMA",
    schema_id="prep:output",
    schema_type="output",
    fields={
        "prep_payload": {"type": "object", "description": "Prepped research context payload"},
    },
)
PLAN_INPUT_SCHEMA = _schema(
    export_name="PLAN_INPUT_SCHEMA",
    schema_id="plan:input",
    schema_type="input",
    fields={
        "prep_payload": {"type": "object", "description": "Prepped research context from prep phase"},
    },
)
PLAN_OUTPUT_SCHEMA = _schema(
    export_name="PLAN_OUTPUT_SCHEMA",
    schema_id="plan:output",
    schema_type="output",
    fields={
        "plan_payload": {"type": "object", "description": "Generated plan payload"},
    },
)
CRITIQUE_INPUT_SCHEMA = _schema(
    export_name="CRITIQUE_INPUT_SCHEMA",
    schema_id="critique:input",
    schema_type="input",
    fields={
        "plan_payload": {"type": "object", "description": "Plan payload to critique"},
    },
)
CRITIQUE_OUTPUT_SCHEMA = _schema(
    export_name="CRITIQUE_OUTPUT_SCHEMA",
    schema_id="critique:output",
    schema_type="output",
    fields={
        "critique_payload": {"type": "object", "description": "Critique analysis payload"},
    },
)
GATE_INPUT_SCHEMA = _schema(
    export_name="GATE_INPUT_SCHEMA",
    schema_id="gate:input",
    schema_type="input",
    fields={
        "critique_payload": {"type": "object", "description": "Critique payload for gate evaluation"},
    },
)
GATE_OUTPUT_SCHEMA = _schema(
    export_name="GATE_OUTPUT_SCHEMA",
    schema_id="gate:output",
    schema_type="output",
    fields={
        "gate_payload": {"type": "object", "description": "Gate evaluation payload"},
        "recommendation": {"type": "string", "description": "Gate routing recommendation"},
    },
)
REVISE_INPUT_SCHEMA = _schema(
    export_name="REVISE_INPUT_SCHEMA",
    schema_id="revise:input",
    schema_type="input",
    fields={
        "gate_payload": {"type": "object", "description": "Gate payload with revision feedback"},
    },
)
REVISE_OUTPUT_SCHEMA = _schema(
    export_name="REVISE_OUTPUT_SCHEMA",
    schema_id="revise:output",
    schema_type="output",
    fields={
        "revise_payload": {"type": "object", "description": "Revised plan payload"},
    },
)
TIEBREAKER_RUN_INPUT_SCHEMA = _schema(
    export_name="TIEBREAKER_RUN_INPUT_SCHEMA",
    schema_id="tiebreaker_run:input",
    schema_type="input",
    fields={
        "gate_payload": {"type": "object", "description": "Gate payload triggering tiebreaker"},
    },
)
TIEBREAKER_RUN_OUTPUT_SCHEMA = _schema(
    export_name="TIEBREAKER_RUN_OUTPUT_SCHEMA",
    schema_id="tiebreaker_run:output",
    schema_type="output",
    fields={
        "tiebreaker_payload": {"type": "object", "description": "Tiebreaker analysis payload"},
    },
)
TIEBREAKER_DECIDE_INPUT_SCHEMA = _schema(
    export_name="TIEBREAKER_DECIDE_INPUT_SCHEMA",
    schema_id="tiebreaker_decide:input",
    schema_type="input",
    fields={
        "tiebreaker_payload": {"type": "object", "description": "Tiebreaker analysis for decision"},
    },
)
TIEBREAKER_DECIDE_OUTPUT_SCHEMA = _schema(
    export_name="TIEBREAKER_DECIDE_OUTPUT_SCHEMA",
    schema_id="tiebreaker_decide:output",
    schema_type="output",
    fields={
        "decision": {"type": "string", "description": "Tiebreaker resolution decision"},
    },
)
TIEBREAKER_RESEARCHER_INPUT_SCHEMA = _schema(
    export_name="TIEBREAKER_RESEARCHER_INPUT_SCHEMA",
    schema_id="tiebreaker_researcher:input",
    schema_type="input",
    fields={
        "gate_payload": {"type": "object", "description": "Gate payload triggering tiebreaker"},
    },
)
TIEBREAKER_RESEARCHER_OUTPUT_SCHEMA = _schema(
    export_name="TIEBREAKER_RESEARCHER_OUTPUT_SCHEMA",
    schema_id="tiebreaker_researcher:output",
    schema_type="output",
    fields={
        "research_findings": {"type": "object", "description": "Researcher analysis findings"},
    },
)
TIEBREAKER_CHALLENGER_INPUT_SCHEMA = _schema(
    export_name="TIEBREAKER_CHALLENGER_INPUT_SCHEMA",
    schema_id="tiebreaker_challenger:input",
    schema_type="input",
    fields={
        "research_findings": {"type": "object", "description": "Researcher findings to challenge"},
    },
)
TIEBREAKER_CHALLENGER_OUTPUT_SCHEMA = _schema(
    export_name="TIEBREAKER_CHALLENGER_OUTPUT_SCHEMA",
    schema_id="tiebreaker_challenger:output",
    schema_type="output",
    fields={
        "challenge_findings": {"type": "object", "description": "Challenger analysis findings"},
    },
)
TIEBREAKER_SYNTHESIS_INPUT_SCHEMA = _schema(
    export_name="TIEBREAKER_SYNTHESIS_INPUT_SCHEMA",
    schema_id="tiebreaker_synthesis:input",
    schema_type="input",
    fields={
        "research_findings": {"type": "object", "description": "Researcher findings for synthesis"},
        "challenge_findings": {"type": "object", "description": "Challenger findings for synthesis"},
    },
)
TIEBREAKER_SYNTHESIS_OUTPUT_SCHEMA = _schema(
    export_name="TIEBREAKER_SYNTHESIS_OUTPUT_SCHEMA",
    schema_id="tiebreaker_synthesis:output",
    schema_type="output",
    fields={
        "tiebreaker_payload": {"type": "object", "description": "Synthesized tiebreaker analysis payload"},
    },
)
TIEBREAKER_DECISION_INPUT_SCHEMA = _schema(
    export_name="TIEBREAKER_DECISION_INPUT_SCHEMA",
    schema_id="tiebreaker_decision:input",
    schema_type="input",
    fields={
        "tiebreaker_payload": {"type": "object", "description": "Tiebreaker analysis for decision"},
    },
)
TIEBREAKER_DECISION_OUTPUT_SCHEMA = _schema(
    export_name="TIEBREAKER_DECISION_OUTPUT_SCHEMA",
    schema_id="tiebreaker_decision:output",
    schema_type="output",
    fields={
        "decision": {"type": "string", "description": "Tiebreaker resolution decision"},
    },
)
FINALIZE_INPUT_SCHEMA = _schema(
    export_name="FINALIZE_INPUT_SCHEMA",
    schema_id="finalize:input",
    schema_type="input",
    fields={
        "gate_payload": {"type": "object", "description": "Gate payload for finalization"},
    },
)
FINALIZE_OUTPUT_SCHEMA = _schema(
    export_name="FINALIZE_OUTPUT_SCHEMA",
    schema_id="finalize:output",
    schema_type="output",
    fields={
        "finalize_payload": {"type": "object", "description": "Finalized execution plan payload"},
    },
)
EXECUTE_INPUT_SCHEMA = _schema(
    export_name="EXECUTE_INPUT_SCHEMA",
    schema_id="execute:input",
    schema_type="input",
    fields={
        "finalize_payload": {"type": "object", "description": "Finalized plan for execution"},
    },
)
EXECUTE_OUTPUT_SCHEMA = _schema(
    export_name="EXECUTE_OUTPUT_SCHEMA",
    schema_id="execute:output",
    schema_type="output",
    fields={
        "execute_payload": {"type": "object", "description": "Execution result payload"},
    },
)
REVIEW_INPUT_SCHEMA = _schema(
    export_name="REVIEW_INPUT_SCHEMA",
    schema_id="review:input",
    schema_type="input",
    fields={
        "execute_payload": {"type": "object", "description": "Execution results for review"},
    },
)
REVIEW_OUTPUT_SCHEMA = _schema(
    export_name="REVIEW_OUTPUT_SCHEMA",
    schema_id="review:output",
    schema_type="output",
    fields={
        "review_payload": {"type": "object", "description": "Review verdict payload"},
    },
)
HALT_OUTPUT_SCHEMA = _schema(
    export_name="HALT_OUTPUT_SCHEMA",
    schema_id="halt:output",
    schema_type="output",
    fields={
        "status": {"type": "string", "description": "Terminal status payload"},
    },
)
OVERRIDE_INPUT_SCHEMA = _schema(
    export_name="OVERRIDE_INPUT_SCHEMA",
    schema_id="override:input",
    schema_type="input",
    fields={
        "gate_payload": {"type": "object", "description": "Gate payload for override dispatch"},
    },
)
OVERRIDE_OUTPUT_SCHEMA = _schema(
    export_name="OVERRIDE_OUTPUT_SCHEMA",
    schema_id="override:output",
    schema_type="output",
    fields={
        "override_result": {"type": "object", "description": "Override action result"},
    },
)
SUSPEND_OUTPUT_SCHEMA = _schema(
    export_name="SUSPEND_OUTPUT_SCHEMA",
    schema_id="suspend:output",
    schema_type="output",
    fields={
        "suspension": {"type": "object", "description": "Suspension cursor payload"},
    },
)


PREP_PROMPT = _prompt("prep")
PLAN_PROMPT = _prompt("plan")
CRITIQUE_PROMPT = _prompt("critique")
GATE_PROMPT = _prompt("gate")
REVISE_PROMPT = _prompt("revise")
FINALIZE_PROMPT = _prompt("finalize")
EXECUTE_PROMPT = _prompt("execute")
REVIEW_PROMPT = _prompt("review")
TIEBREAKER_RESEARCHER_PROMPT = _prompt("tiebreaker_researcher")
TIEBREAKER_CHALLENGER_PROMPT = _prompt("tiebreaker_challenger")
TIEBREAKER_SYNTHESIS_PROMPT = _prompt("tiebreaker_synthesis")
TIEBREAKER_DECISION_PROMPT = _prompt("tiebreaker_decision")

CRITIQUE_TYPED_REDUCER_OUTCOMES = {
    "critique": ("completed",),
    "gate": RUNTIME_BRANCH_VOCABULARY["gate"],
}
CRITIQUE_LENS_CARDINALITY = {
    "minimum": 0,
    "maximum_ref": "len(megaplan.policy.critique_lenses)",
}
CRITIQUE_SELECTION_POLICY = {
    "skip": {
        "when": "robustness == bare",
        "route_signal": "skip_to_finalize",
    },
    "static": {
        "when": "adaptive critique disabled or creative mode enabled",
        "lens_source": "megaplan.policy.critique_lenses",
    },
    "adaptive": {
        "when": "adaptive critique enabled and creative mode disabled",
        "phase": "critique_evaluator",
        "fallback": "static",
    },
}
CRITIQUE_RETRY_POLICY = {
    "phase": "critique_evaluator",
    "max_attempts": 2,
    "on_exhausted": "blocked",
    "recovery_artifact": "critique_output.json",
    "promote_to": "critique_v{iteration}.json",
}
CRITIQUE_EVIDENCE_CONTRACT = {
    "skip": {
        "construct_type": "critique",
        "selection_mode": "skip",
        "route_signal": "skip_to_finalize",
    },
    "static": {
        "construct_type": "critique",
        "selection_mode": "static",
        "lens_source": "megaplan.policy.critique_lenses",
    },
    "adaptive": {
        "construct_type": "critique",
        "selection_mode": "adaptive",
        "phase": "critique_evaluator",
        "fallback": "static",
    },
    "retry_exhausted": {
        "construct_type": "gate",
        "phase": "critique_evaluator",
        "route_signal": "blocked",
    },
}

CRITIQUE_ROUTE_SURFACE = {
    "fanout_contract": {
        "parallel_map_id": "critique-fanout",
        "fanout_ref": "megaplan.policy.critique_lenses",
        "step_ref": "SOURCE_CRITIQUE_PANEL_WORKFLOW",
        "reducer_ref": "SOURCE_CRITIQUE",
        "path_template": "critique/{item_id}",
        "route_signal": "critique_payload",
    },
    "selection_policy": CRITIQUE_SELECTION_POLICY,
    "retry_policy": CRITIQUE_RETRY_POLICY,
    "evidence_contract": CRITIQUE_EVIDENCE_CONTRACT,
    "skip_and_retry": {
        "bare_robustness": {
            "route_signal": "skip_to_finalize",
            "effect": "workflow_handles_plan_to_finalize_without_handler_fanout",
        },
        "evaluator_retry": {
            "phase": "critique_evaluator",
            "max_attempts": 2,
            "on_exhausted": "blocked",
        },
        "payload_recovery": {
            "scratch_ref": "critique_output.json",
            "promote_to": "critique_v{iteration}.json",
        },
    },
    "external_call_surface": {
        "runtime_wrapper_ref": "arnold_pipelines.megaplan.orchestration.critique_runtime",
        "retained_handler_ref": "arnold_pipelines.megaplan.handlers.critique:handle_critique",
        "worker_phase": "critique",
        "evaluator_phase": "critique_evaluator",
    },
}

DEFAULT_POLICY = _policy(
    export_name="DEFAULT_POLICY",
    policy_id="megaplan:default",
    policy_type="timing",
    config={"timeout_seconds_ref": "build_pipeline.timeout_seconds"},
    metadata={
        "canonical_carriers": (
            "prep",
            "plan",
            "critique",
            "tiebreaker_run",  # bridge-only compatibility
            "tiebreaker_researcher",
            "tiebreaker_challenger",
            "tiebreaker_synthesis",
            "finalize",
            "execute",
            "halt",
            "override",
        ),
        "critique_surface": {
            "fanout_contract": {
                "parallel_map_id": "critique-fanout",
                "fanout_ref": "megaplan.policy.critique_lenses",
                "step_ref": "SOURCE_CRITIQUE_PANEL_WORKFLOW",
                "reducer_ref": "SOURCE_CRITIQUE",
                "path_template": "critique/{item_id}",
                "route_signal": "critique_payload",
                "lens_cardinality": CRITIQUE_LENS_CARDINALITY,
                "typed_reducer_outcomes": CRITIQUE_TYPED_REDUCER_OUTCOMES,
            },
            "selection_policy": CRITIQUE_SELECTION_POLICY,
            "retry_policy": CRITIQUE_RETRY_POLICY,
            "evidence_contract": CRITIQUE_EVIDENCE_CONTRACT,
            "skip_and_retry_policy": {
                "bare_robustness": {
                    "route_signal": "skip_to_finalize",
                    "effect": "workflow_handles_plan_to_finalize_without_handler_fanout",
                },
                "evaluator_retry": {
                    "phase": "critique_evaluator",
                    "max_attempts": 2,
                    "on_exhausted": "blocked",
                },
                "payload_recovery": {
                    "scratch_ref": "critique_output.json",
                    "promote_to": "critique_v{iteration}.json",
                },
            },
            "external_call_wrapping": {
                "runtime_wrapper_ref": "arnold_pipelines.megaplan.orchestration.critique_runtime",
                "retained_handler_ref": "arnold_pipelines.megaplan.handlers.critique:handle_critique",
                "worker_phase": "critique",
                "evaluator_phase": "critique_evaluator",
            },
        },
    },
)
PREP_CLARIFY_POLICY = _policy(
    export_name="PREP_CLARIFY_POLICY",
    policy_id="megaplan:prep-clarify",
    policy_type="boundary",
    config={
        "timeout_seconds_ref": "build_pipeline.timeout_seconds",
        "control_transitions": (
            {
                "transition_id": "prep:clarify",
                "transition_type": "suspension",
                "trigger_ref": "prep.open_questions.blocking",
                "target_ref": "awaiting_human",
                "policy_ref": "megaplan:prep-clarify",
            },
            {
                "transition_id": "prep:continue",
                "transition_type": "continue",
                "trigger_ref": "prep.open_questions.none_blocking",
                "target_ref": "plan",
                "policy_ref": "megaplan:prep-clarify",
            },
        ),
    },
    metadata={
        "authoring_surface": True,
        "route_surface": {
            "outcomes": ("continue", "awaiting_human"),
            "state_transitions": {
                "continue": "prepped",
                "awaiting_human": "awaiting_human",
            },
        },
    },
)
GATE_POLICY = _policy(
    export_name="GATE_POLICY",
    policy_id="megaplan:gate",
    policy_type="control",
    config={
        "timeout_seconds_ref": "build_pipeline.timeout_seconds",
        "suspension_routes": (
            {"route_id": "gate:human", "capability_id": "human:gate"},
        ),
        "control_transitions": (
            {
                "transition_id": "gate:proceed",
                "transition_type": "override",
                "trigger_ref": "gate.recommendation",
                "target_ref": "finalize",
                "policy_ref": "megaplan:gate",
            },
            {
                "transition_id": "gate:iterate",
                "transition_type": "override",
                "trigger_ref": "gate.recommendation",
                "target_ref": "revise",
                "policy_ref": "megaplan:gate",
            },
            {
                "transition_id": "gate:tiebreaker",
                "transition_type": "override",
                "trigger_ref": "gate.recommendation",
                "target_ref": "tiebreaker_researcher",
                "policy_ref": "megaplan:gate",
            },
            {
                "transition_id": "gate:escalate",
                "transition_type": "escalation",
                "trigger_ref": "gate.recommendation",
                "target_ref": "override",
                "policy_ref": "megaplan:gate",
            },
            {
                "transition_id": "gate:abort",
                "transition_type": "override",
                "trigger_ref": "gate.recommendation",
                "target_ref": "halt",
                "policy_ref": "megaplan:gate",
            },
        ),
    },
    metadata={
        "canonical_carriers": ("gate",),
        "route_surface": {
            "route_groups": {
                "finalize": ("proceed", "force_proceed"),
                "revise": ("iterate", "retry_gate", "reprompt_downgrade"),
                "tiebreaker": ("tiebreaker",),
                "override": ("escalate", "blocked_preflight"),
                "halt": ("abort", "suspend"),
            },
            "fallback_route_signals": {
                "blocking_flag_reprompt": "retry_gate",
                "reprompt_downgrade": _RouteSignalAlias("reprompt_downgrade", "iterate"),
                "preflight_failed": "blocked_preflight",
                "unknown_recommendation": "escalate",
                "critique_cap": "force_proceed",
            },
            "severity_policy": {
                "blocking_statuses": ("open", "addressed", "disputed"),
                "significant_severities": ("significant", "likely-significant"),
                "cosmetic_severities": ("minor", "likely-minor", "trivial", "cosmetic", "low", "nit"),
                "critical_categories": ("correctness", "security"),
            },
            "normalization_policy": {
                "invalid_recommendation": {
                    "owner": "gate",
                    "effect": "normalize_to_inferred_recommendation",
                    "fallback_recommendations": {
                        "blocking_flags_present": "ITERATE",
                        "preflight_failed": "ESCALATE",
                        "clear_to_proceed": "PROCEED",
                    },
                },
                "empty_payload": {
                    "owner": "gate",
                    "effect": "normalize_to_inferred_recommendation",
                },
            },
            "debt_visibility": {
                "owner": "gate",
                "effect": "publish_debt_payload_on_proceed",
                "payload_fields": ("recommendation", "entries_added", "accepted_tradeoffs"),
            },
            "reprompt_policy": {
                "downgrade_on_unresolved_blockers": {
                    "route_signal": "reprompt_downgrade",
                    "recommendation": "ITERATE",
                    "passed": False,
                    "fallback_kind": "reprompt_downgrade",
                }
            },
            "critique_gate_diagnostics": _superset_mapping(
                {
                "bare_skip": {
                    "owner": "critique-fanout",
                    "effect": "skip_empty_or_bare_findings",
                },
                "evaluator_retry": {
                    "owner": "critique-fanout",
                    "effect": "retry_unverifiable_or_unavailable_evaluators",
                },
                "malformed_payload": {
                    "owner": "gate",
                    "effect": "normalize_to_inferred_recommendation",
                    "fallback_recommendations": {
                        "blocking_flags_present": "ITERATE",
                        "preflight_failed": "ESCALATE",
                        "clear_to_proceed": "PROCEED",
                    },
                },
                "empty_payload": {
                    "owner": "gate",
                    "effect": "normalize_to_inferred_recommendation",
                },
                "worker_unavailable": {
                    "owner": "gate",
                    "effect": "escalate_or_retry_via_preflight_policy",
                },
                "debt_recorded": {
                    "owner": "gate",
                    "effect": "publish_debt_payload_on_proceed",
                    "payload_fields": ("recommendation", "entries_added", "accepted_tradeoffs"),
                },
                }
            ),
        },
    },
)

# Compatibility exports retained for handlers that still import the gate policy
# surfaces directly from this module.
GATE_NORMALIZATION_POLICY = MappingProxyType(
    GATE_POLICY.metadata["route_surface"]["normalization_policy"]
)
GATE_DEBT_VISIBILITY_POLICY = MappingProxyType(
    GATE_POLICY.metadata["route_surface"]["debt_visibility"]
)
GATE_REPROMPT_POLICY = MappingProxyType(
    GATE_POLICY.metadata["route_surface"]["reprompt_policy"]
)

REVISE_LOOP_POLICY = _policy(
    export_name="REVISE_LOOP_POLICY",
    policy_id="megaplan:revise-loop",
    policy_type="loop",
    config={
        "timeout_seconds_ref": "build_pipeline.timeout_seconds",
        "max_iterations": M4_LOOP_MAX_ITERATIONS,
        "until_ref": "critique_gate_pass",
        "suspension_routes": (
            {
                "route_id": "revise:loop",
                "reentry_id": "revise:loop",
                "capability_id": "megaplan:planning",
            },
        ),
    },
    metadata={
        "canonical_carriers": ("revise",),
        "loop_surface": {
            "loop_id": "critique-gate-revise",
            "max_iterations": M4_LOOP_MAX_ITERATIONS,
            "max_iterations_ref": "M4_LOOP_MAX_ITERATIONS",
            "reentry": {
                "route_id": "revise:loop",
                "reentry_id": "critique",
                "target_ref": "critique-fanout",
            },
            "until_exits": {
                "proceed": "finalize",
                "force_proceed": "finalize",
            },
            "unless_exits": {
                "escalate": "override",
                "abort": "halt",
                "blocked_preflight": "override",
                "suspend": "halt",
            },
            "revise_reentries": {
                "iterate": "revise",
                "retry_gate": "gate_retry_revise",
                "reprompt_downgrade": "gate_reprompt_revise",
            },
            "cap_outcomes": {
                "critical_or_security_blockers": "escalate",
                "cosmetic_only": "force_proceed",
                "no_progress_with_blockers": "escalate",
            },
            "termination_policy": {
                "iteration_caps": {
                    "default_config_key": "max_critique_iterations",
                    "robust_config_key": "max_robust_critique_iterations",
                    "robustness_overrides": {
                        "light": {"max_value": 2},
                    },
                },
                "no_progress_cap": {
                    "config_scope": "execution",
                    "config_key": "max_critique_no_progress",
                },
                "severity_policy": {
                    "blocking_statuses": ("open", "addressed", "disputed"),
                    "significant_severities": ("significant", "likely-significant"),
                    "cosmetic_severities": ("minor", "likely-minor", "trivial", "cosmetic", "low", "nit"),
                    "critical_categories": ("correctness", "security"),
                },
                "cap_outcomes": {
                    "critical_or_security_blockers": "escalate",
                    "cosmetic_only": "force_proceed",
                    "no_progress_with_blockers": "escalate",
                },
                "debt_visibility": {
                    "owner": "gate",
                    "effect": "publish_debt_payload_on_proceed",
                    "payload_fields": ("recommendation", "entries_added", "accepted_tradeoffs"),
                },
            },
            "gate_route_signals": RUNTIME_BRANCH_VOCABULARY["gate"],
            "suspension": {
                "route_signal": "suspend",
                "route_id": "gate:human",
                "reentry_id": "revise:loop",
                "resume_target_ref": "gate",
            },
            "tiebreaker": {
                "call_ref": "TIEBREAKER_WORKFLOW",
                "call_id": "tiebreaker",
                "inputs": ("gate_payload",),
                "rejoin": {
                    "proceed": "finalize",
                    "iterate": "revise",
                    "escalate": "override",
                    "fallback": "override",
                },
                "internals": "delegated",
            },
        },
    },
)

REVISE_LOOP_TERMINATION_POLICY = MappingProxyType(
    REVISE_LOOP_POLICY.metadata["loop_surface"]["termination_policy"]
)
TIEBREAKER_POLICY = _policy(
    export_name="TIEBREAKER_POLICY",
    policy_id="megaplan:tiebreaker",
    policy_type="loop",
    config={
        "timeout_seconds_ref": "build_pipeline.timeout_seconds",
        "max_iterations": M4_LOOP_MAX_ITERATIONS,
        "until_ref": "tiebreaker_resolved",
        "suspension_routes": (
            {
                "route_id": "tiebreaker:loop",
                "reentry_id": "tiebreaker:loop",
                "capability_id": "megaplan:planning",
            },
        ),
        "control_transitions": (
            {
                "transition_id": "tiebreaker:iterate",
                "transition_type": "override",
                "trigger_ref": "tiebreaker_decision.decision",
                "target_ref": "revise",
                "policy_ref": "megaplan:tiebreaker",
            },
            {
                "transition_id": "tiebreaker:proceed",
                "transition_type": "override",
                "trigger_ref": "tiebreaker_decision.decision",
                "target_ref": "finalize",
                "policy_ref": "megaplan:tiebreaker",
            },
            {
                "transition_id": "tiebreaker:escalate",
                "transition_type": "escalation",
                "trigger_ref": "tiebreaker_decision.decision",
                "target_ref": "override",
                "policy_ref": "megaplan:tiebreaker",
            },
            {
                "transition_id": "tiebreaker:replan",
                "transition_type": "override",
                "trigger_ref": "tiebreaker_decision.decision",
                "target_ref": "revise",
                "policy_ref": "megaplan:tiebreaker",
            },
        ),
    },
    metadata={
        "canonical_carriers": ("tiebreaker_decision", "tiebreaker_decide"),
        "route_surface": {
            "run_completion_route": {
                "route_signal": "default",
                "target_ref": "tiebreaker_decision",
                "failure_behavior": "complete_decision_cycle_with_recorded_artifacts",
            },
            "decision_routes": {
                "pick": {"route_signal": "proceed", "target_ref": "finalize"},
                "replan": {"route_signal": "replan", "target_ref": "revise"},
                "reiterate": {"route_signal": "iterate", "target_ref": "critique-fanout"},
                "escalate": {"route_signal": "escalate", "target_ref": "override"},
            },
            "fallback_route_signal": "escalate",
        },
    },
)
FINALIZE_POLICY = _policy(
    export_name="FINALIZE_POLICY",
    policy_id="megaplan:finalize",
    policy_type="control",
    config={
        "timeout_seconds_ref": "build_pipeline.timeout_seconds",
        "control_transitions": (
            {
                "transition_id": "finalize:execute",
                "transition_type": "override",
                "trigger_ref": "finalize.result",
                "target_ref": "execute",
                "policy_ref": "megaplan:finalize",
            },
            {
                "transition_id": "finalize:revise",
                "transition_type": "fallback",
                "trigger_ref": "finalize.result",
                "target_ref": "revise",
                "policy_ref": "megaplan:finalize",
            },
        ),
    },
    metadata={
        "authoring_surface": True,
        "carrier_step_ref": "finalize",
        "route_surface": _superset_mapping(
            {
                "success_route": {
                    "route_signal": "default",
                    "target_ref": "execute",
                    "artifact_effect_id": "artifact.finalize.plan",
                    "artifact_policy_ref": "megaplan:artifact-contract",
                    "projection_route_ref": "finalize:execute",
                    "state_ref": "finalized",
                },
                "fallback_routes": {
                    "plan_contract_revise_needed": {
                        "route_signal": "revise",
                        "target_ref": "revise",
                        "reason": "missing_scoped_baseline_test_contract",
                        "projection_route_ref": "finalize:revise",
                        "phase_ref": "revise",
                    },
                },
                "skip_review_routes": {
                    "no_review": {
                        "route_signal": "no_review",
                        "target_ref": "halt",
                        "terminal_state": "done",
                        "branch_ref": "execute:no-review-terminal-done",
                        "projected_status_ref": "status:terminal",
                        "history_entry": "execute_no_review_terminal",
                    },
                    "deferred_human": {
                        "route_signal": "deferred_human",
                        "target_ref": "halt",
                        "terminal_state": "awaiting_human_verify",
                        "branch_ref": "execute:no-review-terminal-awaiting-human",
                        "projected_status_ref": "status:terminal",
                        "resume_cursor_ref": "cursor:suspension",
                        "history_entry": "execute_no_review_terminal",
                    },
                },
                "canonical_artifacts": {
                    "finalize_plan": {
                        "effect_id": "artifact.finalize.plan",
                        "payload_ref": "finalize.finalize_payload",
                        "policy_ref": "megaplan:artifact-contract",
                        "idempotency_key_ref": "artifact_contract.finalize",
                    },
                },
                "final_projection_routes": {
                    "execute": {
                        "route_signal": "default",
                        "target_ref": "execute",
                        "state_ref": "finalized",
                        "artifact_ref": "artifact.finalize.plan",
                        "projected_phase": "execute",
                    },
                    "revise_fallback": {
                        "route_signal": "revise",
                        "target_ref": "revise",
                        "projected_phase": "revise",
                        "reason": "missing_scoped_baseline_test_contract",
                    },
                    "no_review_done": {
                        "route_signal": "no_review",
                        "target_ref": "halt",
                        "terminal_state": "done",
                        "projected_status_ref": "status:terminal",
                    },
                    "no_review_deferred_human": {
                        "route_signal": "deferred_human",
                        "target_ref": "halt",
                        "terminal_state": "awaiting_human_verify",
                        "projected_status_ref": "status:terminal",
                        "resume_cursor_ref": "cursor:suspension",
                    },
                },
            }
        ),
    },
)
REVIEW_POLICY = _policy(
    export_name="REVIEW_POLICY",
    policy_id="megaplan:review",
    policy_type="control",
    config={
        "timeout_seconds_ref": "build_pipeline.timeout_seconds",
        "retry": {
            "max_attempts": M4_LOOP_MAX_ITERATIONS,
            "backoff": "manual_review",
            "retry_on": ("rework", "transient_failure"),
        },
        "escalation": {
            "targets": ("override",),
            "escalate_after_attempts": M4_LOOP_MAX_ITERATIONS,
            "policy_ref": "megaplan:override",
            "backoff": "manual_review",
        },
        "cap_thresholds": _review_cap_threshold_surface(),
        "blocked_and_advisory_outcomes": _review_blocked_and_advisory_surface(),
        "force_proceed_authority": _review_force_proceed_surface(),
        "human_verification": _review_human_verification_surface(),
        "suspension_routes": (
            {
                "route_id": "review:human",
                "capability_id": "human:review",
                "resume_schema_ref": "arnold_pipelines.megaplan.runtime.resume:ResumeContract",
                "resume_payload_ref": "review.review_payload",
            },
        ),
        "control_transitions": (
            {
                "transition_id": "review:rework",
                "transition_type": "fallback",
                "trigger_ref": "review.verdict",
                "target_ref": "execute",
                "policy_ref": "megaplan:review",
            },
            {
                "transition_id": "review:done",
                "transition_type": "override",
                "trigger_ref": "review.verdict",
                "target_ref": "halt",
                "policy_ref": "megaplan:review",
            },
            {
                "transition_id": "review:blocked",
                "transition_type": "escalation",
                "trigger_ref": "review.verdict",
                "target_ref": "override",
                "policy_ref": "megaplan:review",
            },
            {
                "transition_id": "review:force_proceeded",
                "transition_type": "override",
                "trigger_ref": "review.verdict",
                "target_ref": "halt",
                "policy_ref": "megaplan:review",
            },
            {
                "transition_id": "review:deferred_human",
                "transition_type": "fallback",
                "trigger_ref": "review.verdict",
                "target_ref": "halt",
                "policy_ref": "megaplan:review",
            },
        ),
        "authored_topology": _review_authored_topology_surface(),
        "topology_overlays": (
            {
                "overlay_id": "review:cap-exhausted",
                "overlay_type": "review_cap",
                "source_ref": "review.verdict",
                "target_refs": ("override", "halt"),
                "condition_ref": "review.cap_exhausted",
            },
        ),
        "effects": (
            {
                "effect_id": "artifact.review.receipt",
                "payload_ref": "review.review_payload",
                "idempotency": {"key_ref": "review.receipt"},
            },
            {
                "effect_id": "artifact.review.output",
                "payload_ref": "review.review_payload",
                "idempotency": {"key_ref": "review.output"},
            },
        ),
    },
    metadata={
        "canonical_carriers": ("review",),
        "route_surface": _review_route_surface(),
    },
)
OVERRIDE_POLICY = _policy(
    export_name="OVERRIDE_POLICY",
    policy_id="megaplan:override",
    policy_type="control_surface",
    config={
        "timeout_seconds_ref": "build_pipeline.timeout_seconds",
        "authority": (
            {"authority_id": "human.override", "action": "apply", "capability_id": "human:gate"},
            {"authority_id": "human.override", "action": "resume", "capability_id": "human:gate"},
        ),
        "topology_overlays": _override_action_overlays(),
        "effects": _override_action_effects(),
    },
    metadata={
        "canonical_carriers": ("override",),
        "route_surface": _override_route_surface(),
    },
)
EXECUTE_POLICY = _policy(
    export_name="EXECUTE_POLICY",
    policy_id="megaplan:execute",
    policy_type="execution",
    config={
        "timeout_seconds_ref": "build_pipeline.timeout_seconds",
        "deadline_ref": "state.meta.execution_deadline",
        "ttl_seconds": 3600.0,
        "retry": {
            "max_attempts": 2,
            "backoff": "exponential",
            "retry_on": ("timeout", "worker_transient"),
        },
        "escalation": {
            "targets": ("override",),
            "escalate_after_attempts": 2,
            "policy_ref": "megaplan:override",
            "backoff": "exponential",
        },
        "suspension_routes": (
            {
                "route_id": "execute:resume",
                "capability_id": "megaplan:planning",
                "reentry_id": "execute:resume",
                "resume_schema_ref": "arnold_pipelines.megaplan.runtime.resume:ResumeContract",
                "resume_payload_ref": "execute.execute_payload",
            },
        ),
        "topology_overlays": (
            {
                "overlay_id": "execute:task-complexity-route",
                "overlay_type": "model_route",
                "source_ref": "finalize.task_complexity_route",
                "target_refs": ("execute.batch.solo", "execute.batch.standard", "execute.batch.premium"),
                "condition_ref": "task.complexity",
            },
        ),
        "effects": (
            {
                "effect_id": "artifact.execute.receipt",
                "payload_ref": "execute.execute_payload",
                "idempotency": {"key_ref": "execute.receipt"},
            },
            {
                "effect_id": "artifact.execute.checkpoint",
                "payload_ref": "execute.execute_payload",
                "idempotency": {"key_ref": "execute.checkpoint"},
            },
        ),
    },
    metadata={
        "canonical_carriers": ("execute",),
        "route_surface": {
            "approval_gates": {
                "destructive_confirmation": {
                    "required_unless": "prose_mode",
                    "signal_ref": "args.confirm_destructive",
                    "failure_code": "missing_confirmation",
                },
                "operator_approval": {
                    "required_unless": "state.config.auto_approve",
                    "signal_ref": "state.meta.user_approved_gate",
                    "grant_signal_ref": "args.user_approved",
                    "failure_code": "missing_approval",
                },
                "mutating_preflight": {
                    "policy_ref": (
                        "arnold_pipelines.megaplan.runtime.execution_environment:"
                        "preflight_mutating_phase"
                    ),
                    "phase": "execute",
                },
            },
            "fanout_contract": {
                "parallel_map_id": "execute-batches",
                "fanout_ref": "megaplan.execute.batches",
                "step_ref": "SOURCE_EXECUTE_BATCH_WORKFLOW",
                "reducer_ref": "SOURCE_EXECUTE",
                "path_template": "execute/{index}",
                "route_signal": "execute_payload",
            },
            "retry_and_reentry": {
                "review_rework_reexecution": {
                    "detect_ref": "last review history result needs_rework",
                    "effect": "force_fresh_execute_session",
                },
                "blocked_retry": {
                    "detect_ref": "last execute history result blocked",
                    "effect": "force_fresh_execute_session",
                },
                "blocked_route": {
                    "route_signal": "blocked",
                    "target_ref": "override",
                    "recoverable_state": "blocked",
                    "resume_cursor": {
                        "phase": "execute",
                        "retry_strategy": "fresh_session",
                    },
                },
            },
            "skip_review_routes": {
                "bare": {
                    "route_signal": "no_review",
                    "target_ref": "halt",
                    "artifact": None,
                },
                "deferred_human": {
                    "route_signal": "deferred_human",
                    "target_ref": "halt",
                    "artifact": "review.json",
                },
            },
            # ------------------------------------------------- explicit branches
            # Every execute branch point, visible in the workflow policy
            # component.  ``branch_surface_ref`` points to the comprehensive
            # typed enumeration in the policy authority
            # (``EXECUTE_BRANCH_SURFACE``); the inline entries below mirror
            # the workflow-source-visible subset so a reviewer can read the
            # full topology without leaving this component.
            "branch_surface_ref": (
                "arnold_pipelines.megaplan.execute.policy:EXECUTE_BRANCH_SURFACE"
            ),
            "batch_continuation": {
                "route_signal": "execute",
                "target_ref": "execute-batches",
                "transition": "NextExecuteTransition.EXECUTE",
                "policy_helper": (
                    "arnold_pipelines.megaplan.execute.policy:"
                    "resolve_single_batch_next_step"
                ),
                "condition": "current batch complete AND more batches remain",
            },
            "timeout_retry": {
                "route_signal": "retry",
                "target_ref": "execute-batches",
                "outcome": "BlockedRetryOutcome.RETRY",
                "governed_by": "EXECUTE_POLICY.config.retry",
                "budget": {
                    "max_attempts": 2,
                    "retry_on": ("timeout", "worker_transient"),
                },
            },
            "aggregate_promotion": {
                "route_signal": "execute_payload",
                "reducer_ref": "SOURCE_EXECUTE",
                "target_ref": "review-fan-in",
                "condition": "all batch payloads reduced into execute_payload",
            },
            "review_handoff": {
                "route_signal": "review",
                "target_ref": "review-fan-in",
                "transition": "NextExecuteTransition.REVIEW",
                "policy_helper": (
                    "arnold_pipelines.megaplan.execute.policy:"
                    "resolve_single_batch_next_step"
                ),
                "condition": (
                    "final batch complete AND all tasks/sense-checks tracked"
                ),
            },
        },
    },
)
MODEL_ROUTING_POLICY = _policy(
    export_name="MODEL_ROUTING_POLICY",
    policy_id="megaplan:model-routing",
    policy_type="routing",
    config={
        "default_routing_ref": "arnold_pipelines.megaplan.profiles:DEFAULT_AGENT_ROUTING",
        "profile_loader_ref": "arnold_pipelines.megaplan.profiles:load_profile_metadata",
        "phase_model_override_ref": "state.config.phase_model",
        "task_complexity_route_ref": "arnold_pipelines.megaplan.execute.batch:_task_complexity_tier_args",
        "task_complexity_source_ref": "finalize.task_complexity_route",
        "topology_overlays": (
            {
                "overlay_id": "model-routing:phase",
                "overlay_type": "model_route",
                "source_ref": "state.config.phase_model",
                "target_refs": (
                    "prep",
                    "plan",
                    "critique",
                    "gate",
                    "revise",
                    "tiebreaker_run",
                    "tiebreaker_decide",
                    "tiebreaker_researcher",
                    "tiebreaker_challenger",
                    "tiebreaker_synthesis",
                    "tiebreaker_decision",
                    "finalize",
                    "execute",
                    "review",
                ),
                "condition_ref": "phase.route",
            },
            {
                "overlay_id": "model-routing:task-complexity",
                "overlay_type": "model_route",
                "source_ref": "finalize.task_complexity_route",
                "target_refs": ("execute.batch.solo", "execute.batch.standard", "execute.batch.premium"),
                "condition_ref": "task.complexity",
            },
        ),
    },
    metadata={"authoring_surface": True},
)
BLAST_RADIUS_POLICY = _policy(
    export_name="BLAST_RADIUS_POLICY",
    policy_id="megaplan:blast-radius",
    policy_type="boundary",
    config={
        "timeout_seconds_ref": "build_pipeline.timeout_seconds",
        "default_ref": "arnold_pipelines.megaplan.orchestration.test_selection:compute_default_blast_radius",
        "merge_floor_ref": "arnold_pipelines.megaplan.orchestration.test_selection:merge_blast_radius_floor",
        "payload_ref": "plan.test_blast_radius",
    },
    metadata={
        "canonical_carriers": ("plan", "revise", "finalize"),
        "route_surface": {
            "payload": "test_blast_radius",
            "fallback": "deterministic_floor",
            "missing_strategy": "full_suite_fallback",
        },
    },
)
ROBUSTNESS_POLICY = _policy(
    export_name="ROBUSTNESS_POLICY",
    policy_id="megaplan:robustness",
    policy_type="robustness",
    config={
        "levels_ref": "arnold_pipelines.megaplan.profiles:ROBUSTNESS_LEVELS",
        "accepted_ref": "arnold_pipelines.megaplan.profiles:ROBUSTNESS_ACCEPTED",
        "normalizer_ref": "arnold_pipelines.megaplan.profiles:normalize_robustness",
    },
    metadata={"authoring_surface": True},
)
ARTIFACT_CONTRACT_POLICY = _policy(
    export_name="ARTIFACT_CONTRACT_POLICY",
    policy_id="megaplan:artifact-contract",
    policy_type="artifact_contract",
    config={
        "step_contracts_ref": "arnold_pipelines.megaplan.step_contracts:STEP_CONTRACTS",
        "content_types_ref": "arnold_pipelines.megaplan.content_types:CONTENT_TYPE_REGISTRY",
        "effects": (
            {
                "effect_id": "artifact.finalize.plan",
                "payload_ref": "finalize.finalize_payload",
                "idempotency": {"key_ref": "artifact_contract.finalize"},
            },
            {
                "effect_id": "artifact.execute.receipt",
                "payload_ref": "execute.execute_payload",
                "idempotency": {"key_ref": "artifact_contract.execute"},
            },
            {
                "effect_id": "artifact.review.receipt",
                "payload_ref": "review.review_payload",
                "idempotency": {"key_ref": "artifact_contract.review"},
            },
        ),
    },
    metadata={"authoring_surface": True},
)
SUSPENSION_POLICY = _policy(
    export_name="SUSPENSION_POLICY",
    policy_id="megaplan:suspension",
    policy_type="suspension",
    config={
        "runtime_status": "suspended",
        "resume_contract_ref": "arnold_pipelines.megaplan.runtime.resume:ResumeContract",
        "suspension_routes": (
            {
                "route_id": "gate:human",
                "capability_id": "human:gate",
                "resume_schema_ref": "arnold_pipelines.megaplan.runtime.resume:ResumeContract",
                "resume_payload_ref": "gate.gate_payload",
            },
            {
                "route_id": "review:human",
                "capability_id": "human:review",
                "resume_schema_ref": "arnold_pipelines.megaplan.runtime.resume:ResumeContract",
                "resume_payload_ref": "review.review_payload",
            },
            {
                "route_id": "revise:loop",
                "capability_id": "megaplan:planning",
                "reentry_id": "revise:loop",
                "resume_schema_ref": "arnold_pipelines.megaplan.runtime.resume:ResumeContract",
                "resume_payload_ref": "revise.revise_payload",
            },
            {
                "route_id": "tiebreaker:loop",
                "capability_id": "megaplan:planning",
                "reentry_id": "tiebreaker:loop",
                "resume_schema_ref": "arnold_pipelines.megaplan.runtime.resume:ResumeContract",
                "resume_payload_ref": "tiebreaker_decide.decision",
            },
            {
                "route_id": "execute:resume",
                "capability_id": "megaplan:planning",
                "reentry_id": "execute:resume",
                "resume_schema_ref": "arnold_pipelines.megaplan.runtime.resume:ResumeContract",
                "resume_payload_ref": "execute.execute_payload",
            },
        ),
        "topology_overlays": (
            {
                "overlay_id": "suspension:gate-human",
                "overlay_type": "suspension_point",
                "source_ref": "gate.recommendation",
                "target_refs": ("gate:human",),
                "condition_ref": "gate.awaiting_human",
            },
            {
                "overlay_id": "suspension:review-human",
                "overlay_type": "suspension_point",
                "source_ref": "review.verdict",
                "target_refs": ("review:human",),
                "condition_ref": "review.deferred_human",
            },
            {
                "overlay_id": "suspension:execute-resume",
                "overlay_type": "suspension_point",
                "source_ref": "execute.execute_payload",
                "target_refs": ("execute:resume",),
                "condition_ref": "execute.partial_failure",
            },
        ),
    },
    metadata={"authoring_surface": True},
)

PREP = _step(
    export_name="PREP",
    step_id="prep",
    kind="megaplan:prep",
    prompt=PREP_PROMPT,
    handler_ref=f"{HANDLER_MODULE}:handle_prep",
    outputs=({"name": "prep_payload"},),
    policy=DEFAULT_POLICY,
    route_bindings=({"id": "prep:plan", "label": "default", "target_ref": "plan"},),
    input_schema=PREP_INPUT_SCHEMA,
    output_schema=PREP_OUTPUT_SCHEMA,
)
PLAN = _step(
    export_name="PLAN",
    step_id="plan",
    kind="megaplan:plan",
    prompt=PLAN_PROMPT,
    handler_ref=f"{HANDLER_MODULE}:handle_plan",
    inputs=({"name": "prep_payload", "value_ref": "prep.prep_payload"},),
    outputs=({"name": "plan_payload"},),
    policy=DEFAULT_POLICY,
    route_bindings=({"id": "plan:critique", "label": "default", "target_ref": "critique"},),
    input_schema=PLAN_INPUT_SCHEMA,
    output_schema=PLAN_OUTPUT_SCHEMA,
)
CRITIQUE = _step(
    export_name="CRITIQUE",
    step_id="critique",
    kind="megaplan:critique",
    prompt=CRITIQUE_PROMPT,
    handler_ref=f"{HANDLER_MODULE}:handle_critique",
    inputs=({"name": "plan_payload", "value_ref": "plan.plan_payload"},),
    outputs=({"name": "critique_payload"},),
    policy=DEFAULT_POLICY,
    route_bindings=({"id": "critique:gate", "label": "default", "target_ref": "gate"},),
    input_schema=CRITIQUE_INPUT_SCHEMA,
    output_schema=CRITIQUE_OUTPUT_SCHEMA,
    metadata={"route_surface": CRITIQUE_ROUTE_SURFACE},
)
GATE = _step(
    export_name="GATE",
    step_id="gate",
    kind="megaplan:gate",
    prompt=GATE_PROMPT,
    handler_ref=f"{HANDLER_MODULE}:handle_gate",
    inputs=({"name": "critique_payload", "value_ref": "critique.critique_payload"},),
    outputs=({"name": "gate_payload"}, {"name": "recommendation"}),
    policy=GATE_POLICY,
    route_bindings=(
        {"id": "gate:finalize", "label": "proceed", "condition_ref": "proceed", "target_ref": "finalize"},
        {"id": "gate:revise", "label": "iterate", "condition_ref": "iterate", "target_ref": "revise"},
        {
            "id": "gate:tiebreaker",
            "label": "tiebreaker",
            "condition_ref": "tiebreaker",
            "target_ref": "tiebreaker_researcher",
        },
        {"id": "gate:override", "label": "escalate", "condition_ref": "escalate", "target_ref": "override"},
        {"id": "gate:halt", "label": "abort", "condition_ref": "abort", "target_ref": "halt"},
        {"id": "gate:suspend", "label": "suspend", "condition_ref": "suspend", "target_ref": "halt"},
        {
            "id": "gate:blocked",
            "label": "blocked_preflight",
            "condition_ref": "blocked",
            "target_ref": "override",
        },
        {
            "id": "gate:force_proceed",
            "label": "force_proceed",
            "condition_ref": "force_proceed",
            "target_ref": "finalize",
        },
    ),
    capability_ids=("human:gate",),
    input_schema=GATE_INPUT_SCHEMA,
    output_schema=GATE_OUTPUT_SCHEMA,
)
REVISE = _step(
    export_name="REVISE",
    step_id="revise",
    kind="megaplan:revise",
    prompt=REVISE_PROMPT,
    handler_ref=f"{HANDLER_MODULE}:handle_revise",
    inputs=({"name": "gate_payload", "value_ref": "gate.gate_payload"},),
    outputs=({"name": "revise_payload"},),
    policy=REVISE_LOOP_POLICY,
    route_bindings=(
        {"id": "revise:critique", "label": "default", "condition_ref": "revise:loop", "target_ref": "critique"},
    ),
    capability_ids=("megaplan:planning",),
    metadata={"loop_until_ref": "critique_gate_pass"},
    input_schema=REVISE_INPUT_SCHEMA,
    output_schema=REVISE_OUTPUT_SCHEMA,
)
TIEBREAKER_RUN = _step(
    export_name="TIEBREAKER_RUN",
    step_id="tiebreaker_run",
    kind="megaplan:tiebreaker_run",
    handler_ref=f"{HANDLER_MODULE}:handle_tiebreaker_run",
    inputs=({"name": "gate_payload", "value_ref": "gate.gate_payload"},),
    outputs=({"name": "tiebreaker_payload"},),
    policy=DEFAULT_POLICY,
    route_bindings=(
        {"id": "tiebreaker_run:decide", "label": "default", "target_ref": "tiebreaker_decide"},
    ),
    input_schema=TIEBREAKER_RUN_INPUT_SCHEMA,
    output_schema=TIEBREAKER_RUN_OUTPUT_SCHEMA,
)
TIEBREAKER_DECIDE = _step(
    export_name="TIEBREAKER_DECIDE",
    step_id="tiebreaker_decide",
    kind="megaplan:tiebreaker_decide",
    handler_ref=f"{HANDLER_MODULE}:handle_tiebreaker_decide",
    inputs=({"name": "tiebreaker_payload", "value_ref": "tiebreaker_run.tiebreaker_payload"},),
    outputs=({"name": "decision"},),
    policy=TIEBREAKER_POLICY,
    route_bindings=(
        {
            "id": "tiebreaker_decide:critique",
            "label": "iterate",
            "condition_ref": "tiebreaker:loop",
            "target_ref": "critique",
        },
        {
            "id": "tiebreaker_decide:finalize",
            "label": "proceed",
            "condition_ref": "proceed",
            "target_ref": "finalize",
        },
        {
            "id": "tiebreaker_decide:override",
            "label": "escalate",
            "condition_ref": "escalate",
            "target_ref": "override",
        },
        {
            "id": "tiebreaker_decide:revise_replan",
            "label": "replan",
            "condition_ref": "tiebreaker:replan",
            "target_ref": "revise",
        },
    ),
    capability_ids=("megaplan:planning",),
    metadata={"loop_until_ref": "tiebreaker_resolved"},
    input_schema=TIEBREAKER_DECIDE_INPUT_SCHEMA,
    output_schema=TIEBREAKER_DECIDE_OUTPUT_SCHEMA,
)
# ── Canonical four-phase tiebreaker child identities ──
TIEBREAKER_RESEARCHER = _step(
    export_name="TIEBREAKER_RESEARCHER",
    step_id="tiebreaker_researcher",
    kind="megaplan:tiebreaker_researcher",
    prompt=TIEBREAKER_RESEARCHER_PROMPT,
    handler_ref=f"{HANDLER_MODULE}:handle_tiebreaker_run",  # bridge: reuses legacy handler as phase body
    inputs=({"name": "gate_payload", "value_ref": "gate.gate_payload"},),
    outputs=({"name": "research_findings"},),
    policy=DEFAULT_POLICY,
    route_bindings=(
        {"id": "tiebreaker_researcher:challenger", "label": "default", "target_ref": "tiebreaker_challenger"},
    ),
    input_schema=TIEBREAKER_RESEARCHER_INPUT_SCHEMA,
    output_schema=TIEBREAKER_RESEARCHER_OUTPUT_SCHEMA,
)
TIEBREAKER_CHALLENGER = _step(
    export_name="TIEBREAKER_CHALLENGER",
    step_id="tiebreaker_challenger",
    kind="megaplan:tiebreaker_challenger",
    prompt=TIEBREAKER_CHALLENGER_PROMPT,
    handler_ref=f"{HANDLER_MODULE}:handle_tiebreaker_run",  # bridge: reuses legacy handler as phase body
    inputs=({"name": "research_findings", "value_ref": "tiebreaker_researcher.research_findings"},),
    outputs=({"name": "challenge_findings"},),
    policy=DEFAULT_POLICY,
    route_bindings=(
        {"id": "tiebreaker_challenger:synthesis", "label": "default", "target_ref": "tiebreaker_synthesis"},
    ),
    input_schema=TIEBREAKER_CHALLENGER_INPUT_SCHEMA,
    output_schema=TIEBREAKER_CHALLENGER_OUTPUT_SCHEMA,
)
TIEBREAKER_SYNTHESIS = _step(
    export_name="TIEBREAKER_SYNTHESIS",
    step_id="tiebreaker_synthesis",
    kind="megaplan:tiebreaker_synthesis",
    prompt=TIEBREAKER_SYNTHESIS_PROMPT,
    handler_ref=f"{HANDLER_MODULE}:handle_tiebreaker_run",  # bridge: reuses legacy handler as phase body
    inputs=(
        {"name": "research_findings", "value_ref": "tiebreaker_researcher.research_findings"},
        {"name": "challenge_findings", "value_ref": "tiebreaker_challenger.challenge_findings"},
    ),
    outputs=({"name": "tiebreaker_payload"},),
    policy=DEFAULT_POLICY,
    route_bindings=(
        {"id": "tiebreaker_synthesis:decision", "label": "default", "target_ref": "tiebreaker_decision"},
    ),
    input_schema=TIEBREAKER_SYNTHESIS_INPUT_SCHEMA,
    output_schema=TIEBREAKER_SYNTHESIS_OUTPUT_SCHEMA,
)
TIEBREAKER_DECISION = _step(
    export_name="TIEBREAKER_DECISION",
    step_id="tiebreaker_decision",
    kind="megaplan:tiebreaker_decision",
    prompt=TIEBREAKER_DECISION_PROMPT,
    handler_ref=f"{HANDLER_MODULE}:handle_tiebreaker_decide",  # bridge: reuses legacy handler as phase body
    inputs=({"name": "tiebreaker_payload", "value_ref": "tiebreaker_synthesis.tiebreaker_payload"},),
    outputs=({"name": "decision"},),
    policy=TIEBREAKER_POLICY,
    route_bindings=(
        {
            "id": "tiebreaker_decision:critique",
            "label": "iterate",
            "condition_ref": "tiebreaker:loop",
            "target_ref": "tiebreaker_iterate_revise",
        },
        {
            "id": "tiebreaker_decision:finalize",
            "label": "proceed",
            "condition_ref": "proceed",
            "target_ref": "tiebreaker_finalize",
        },
        {
            "id": "tiebreaker_decision:override",
            "label": "escalate",
            "condition_ref": "escalate",
            "target_ref": "tiebreaker_override",
        },
        {
            "id": "tiebreaker_decision:revise_replan",
            "label": "replan",
            "condition_ref": "tiebreaker:replan",
            "target_ref": "tiebreaker_replan_revise",
        },
    ),
    capability_ids=("megaplan:planning",),
    metadata={"loop_until_ref": "tiebreaker_resolved"},
    input_schema=TIEBREAKER_DECISION_INPUT_SCHEMA,
    output_schema=TIEBREAKER_DECISION_OUTPUT_SCHEMA,
)
FINALIZE = _step(
    export_name="FINALIZE",
    step_id="finalize",
    kind="megaplan:finalize",
    prompt=FINALIZE_PROMPT,
    handler_ref=f"{HANDLER_MODULE}:handle_finalize",
    inputs=({"name": "gate_payload", "value_ref": "gate.gate_payload"},),
    outputs=({"name": "finalize_payload"},),
    policy=DEFAULT_POLICY,
    route_bindings=(
        {"id": "finalize:execute", "label": "default", "target_ref": "execute"},
        {"id": "finalize:revise", "label": "revise", "condition_ref": "revise", "target_ref": "revise"},
    ),
    metadata={
        "policy_refs": ("megaplan:default", "megaplan:finalize", "megaplan:artifact-contract"),
        **_adapter_metadata_quarantine(
            canonical_refs=(
                "arnold_pipelines.megaplan.workflows.workflow.pypeline:finalize",
                "FINALIZE_POLICY.metadata.route_surface",
            ),
            preserved_fields=("handler_ref", "policy_refs", "route_bindings"),
        ),
    },
    input_schema=FINALIZE_INPUT_SCHEMA,
    output_schema=FINALIZE_OUTPUT_SCHEMA,
)
EXECUTE = _step(
    export_name="EXECUTE",
    step_id="execute",
    kind="megaplan:execute",
    prompt=EXECUTE_PROMPT,
    handler_ref=f"{HANDLER_MODULE}:handle_execute",
    inputs=({"name": "finalize_payload", "value_ref": "finalize.finalize_payload"},),
    outputs=({"name": "execute_payload"},),
    policy=EXECUTE_POLICY,
    capability_ids=("megaplan:planning",),
    metadata={
        "policy_refs": (
            "megaplan:execute",
            "megaplan:model-routing",
            "megaplan:artifact-contract",
            "megaplan:suspension",
        ),
    },
    input_schema=EXECUTE_INPUT_SCHEMA,
    output_schema=EXECUTE_OUTPUT_SCHEMA,
)
REVIEW = _step(
    export_name="REVIEW",
    step_id="review",
    kind="megaplan:review",
    prompt=REVIEW_PROMPT,
    handler_ref=f"{HANDLER_MODULE}:handle_review",
    inputs=({"name": "execute_payload", "value_ref": "execute.execute_payload"},),
    outputs=({"name": "review_payload"},),
    policy=REVIEW_POLICY,
    route_bindings=(
        {"id": "review:halt", "label": "default", "condition_ref": "pass", "target_ref": "halt"},
        {"id": "review:revise", "label": "rework", "condition_ref": "rework", "target_ref": "execute"},
    ),
    capability_ids=("human:review",),
    metadata={
        "policy_refs": (
            "megaplan:review",
            "megaplan:artifact-contract",
            "megaplan:suspension",
        ),
        **_adapter_metadata_quarantine(
            canonical_refs=(
                "arnold_pipelines.megaplan.workflows.workflow.pypeline:review-fan-in",
                "REVIEW_POLICY.metadata.route_surface",
            ),
            preserved_fields=(
                "handler_ref",
                "policy_refs",
                "route_bindings",
                "runtime_branch_vocabulary",
            ),
        ),
    },
    input_schema=REVIEW_INPUT_SCHEMA,
    output_schema=REVIEW_OUTPUT_SCHEMA,
)
HALT = _step(
    export_name="HALT",
    step_id="halt",
    kind="megaplan:halt",
    outputs=({"name": "status"},),
    policy=DEFAULT_POLICY,
    terminal=True,
    output_schema=HALT_OUTPUT_SCHEMA,
)
OVERRIDE = _step(
    export_name="OVERRIDE",
    step_id="override",
    kind="megaplan:override",
    handler_ref=f"{HANDLER_MODULE}:handle_override",
    inputs=({"name": "gate_payload", "value_ref": "gate.gate_payload"},),
    outputs=({"name": "override_result"},),
    policy=OVERRIDE_POLICY,
    route_bindings=(
        {"id": "override:halt", "label": "abort", "condition_ref": "abort", "target_ref": "halt"},
        {
            "id": "override:finalize",
            "label": "force_proceed",
            "condition_ref": "force_proceed",
            "target_ref": "finalize",
        },
        {"id": "override:revise", "label": "replan", "condition_ref": "replan", "target_ref": "revise"},
        {
            "id": "override:cap-revise-once",
            "label": "cap_revise_once",
            "condition_ref": "cap_revise_once",
            "target_ref": "revise",
        },
    ),
    metadata={
        "policy_refs": (
            "megaplan:override",
            "megaplan:model-routing",
        ),
        "override_actions": tuple(sorted(entry.action for entry in OVERRIDE_ACTION_MATRIX)),
    },
    input_schema=OVERRIDE_INPUT_SCHEMA,
    output_schema=OVERRIDE_OUTPUT_SCHEMA,
)
SUSPEND = _step(
    export_name="SUSPEND",
    step_id="suspend",
    kind="megaplan:suspend",
    outputs=({"name": "suspension"},),
    policy=SUSPENSION_POLICY,
    terminal=True,
    metadata={
        "runtime_status": "suspended",
        "topology_export": False,
    },
    output_schema=SUSPEND_OUTPUT_SCHEMA,
)

SOURCE_PREP = _step(
    export_name="SOURCE_PREP",
    step_id="prep",
    kind="megaplan:prep",
    handler_ref=f"{HANDLER_MODULE}:handle_prep",
    outputs=({"name": "prep_payload"},),
    metadata=_COMPATIBILITY_QUARANTINE,
)
SOURCE_PLAN = _step(
    export_name="SOURCE_PLAN",
    step_id="plan",
    kind="megaplan:plan",
    handler_ref=f"{HANDLER_MODULE}:handle_plan",
    inputs=({"name": "prep_payload", "value_ref": "prep.prep_payload"},),
    outputs=({"name": "plan_payload"},),
    metadata=_COMPATIBILITY_QUARANTINE,
)
SOURCE_CRITIQUE = _step(
    export_name="SOURCE_CRITIQUE",
    step_id="critique",
    kind="megaplan:critique",
    handler_ref=f"{HANDLER_MODULE}:handle_critique",
    inputs=({"name": "plan_payload", "value_ref": "plan.plan_payload"},),
    outputs=({"name": "critique_payload"},),
    metadata=_COMPATIBILITY_QUARANTINE,
)
SOURCE_GATE = _step(
    export_name="SOURCE_GATE",
    step_id="gate",
    kind="megaplan:gate",
    handler_ref=f"{HANDLER_MODULE}:handle_gate",
    inputs=({"name": "critique_payload", "value_ref": "critique.critique_payload"},),
    outputs=({"name": "gate_payload"},),
    capability_ids=("human:gate",),
    metadata=_COMPATIBILITY_QUARANTINE,
)
SOURCE_REVISE = _step(
    export_name="SOURCE_REVISE",
    step_id="revise",
    kind="megaplan:revise",
    handler_ref=f"{HANDLER_MODULE}:handle_revise",
    inputs=({"name": "gate_payload", "value_ref": "gate.gate_payload"},),
    outputs=({"name": "revise_payload"},),
    capability_ids=("megaplan:planning",),
    metadata=_COMPATIBILITY_QUARANTINE,
)
SOURCE_TIEBREAKER_RUN = _step(
    export_name="SOURCE_TIEBREAKER_RUN",
    step_id="tiebreaker_run",
    kind="megaplan:tiebreaker_run",
    handler_ref=f"{HANDLER_MODULE}:handle_tiebreaker_run",
    inputs=({"name": "gate_payload", "value_ref": "gate.gate_payload"},),
    outputs=({"name": "tiebreaker_payload"},),
    metadata=_pure_body_carrier_quarantine(
        canonical_refs=(
            "arnold_pipelines.megaplan.workflows.workflow.pypeline:tiebreaker_researcher",
            "arnold_pipelines.megaplan.workflows.planning:declared_step_interface(tiebreaker_researcher)",
            "arnold_pipelines.megaplan.workflows.planning:declared_workflow_topology_contract(tiebreaker_child)",
        ),
        preserved_fields=("handler_ref", "inputs", "outputs", "runtime_branch_vocabulary"),
    ),
)
SOURCE_TIEBREAKER_DECIDE = _step(
    export_name="SOURCE_TIEBREAKER_DECIDE",
    step_id="tiebreaker_decide",
    kind="megaplan:tiebreaker_decide",
    handler_ref=f"{HANDLER_MODULE}:handle_tiebreaker_decide",
    inputs=({"name": "tiebreaker_payload", "value_ref": "tiebreaker_run.tiebreaker_payload"},),
    outputs=({"name": "decision"},),
    capability_ids=("megaplan:planning",),
    metadata=_pure_body_carrier_quarantine(
        canonical_refs=(
            "arnold_pipelines.megaplan.workflows.workflow.pypeline:tiebreaker_decision",
            "arnold_pipelines.megaplan.workflows.planning:declared_step_interface(tiebreaker_decision)",
            "TIEBREAKER_POLICY.metadata.route_surface",
        ),
        preserved_fields=(
            "handler_ref",
            "inputs",
            "outputs",
            "capability_requirements",
            "runtime_branch_vocabulary",
        ),
    ),
)
SOURCE_FINALIZE = _step(
    export_name="SOURCE_FINALIZE",
    step_id="finalize",
    kind="megaplan:finalize",
    handler_ref=f"{HANDLER_MODULE}:handle_finalize",
    inputs=({"name": "gate_payload", "value_ref": "gate.gate_payload"},),
    outputs=({"name": "finalize_payload"},),
    metadata=_adapter_metadata_quarantine(
        canonical_refs=(
            "arnold_pipelines.megaplan.workflows.workflow.pypeline:finalize",
            "FINALIZE_POLICY.metadata.route_surface",
        ),
        preserved_fields=("handler_ref",),
    ),
)
SOURCE_EXECUTE = _step(
    export_name="SOURCE_EXECUTE",
    step_id="execute",
    kind="megaplan:execute",
    handler_ref=f"{HANDLER_MODULE}:handle_execute",
    inputs=({"name": "finalize_payload", "value_ref": "finalize.finalize_payload"},),
    outputs=({"name": "execute_payload"},),
    metadata=_pure_body_carrier_quarantine(
        canonical_refs=(
            "arnold_pipelines.megaplan.workflows.workflow.pypeline:execute",
            "arnold_pipelines.megaplan.workflows.planning:declared_step_interface(execute)",
            "EXECUTE_POLICY.metadata.route_surface",
        ),
        preserved_fields=("handler_ref", "inputs", "outputs", "runtime_branch_vocabulary"),
    ),
)
SOURCE_REVIEW = _step(
    export_name="SOURCE_REVIEW",
    step_id="review",
    kind="megaplan:review",
    handler_ref=f"{HANDLER_MODULE}:handle_review",
    inputs=({"name": "execute_payload", "value_ref": "execute.execute_payload"},),
    outputs=({"name": "review_payload"},),
    capability_ids=("human:review",),
    metadata=_adapter_metadata_quarantine(
        canonical_refs=(
            "arnold_pipelines.megaplan.workflows.workflow.pypeline:review-fan-in",
            "REVIEW_POLICY.metadata.route_surface",
        ),
        preserved_fields=("handler_ref", "runtime_branch_vocabulary"),
    ),
)
SOURCE_HALT = _step(
    export_name="SOURCE_HALT",
    step_id="halt",
    kind="megaplan:halt",
    outputs=({"name": "status"},),
    terminal=True,
)
SOURCE_OVERRIDE = _step(
    export_name="SOURCE_OVERRIDE",
    step_id="override",
    kind="megaplan:override",
    handler_ref=f"{HANDLER_MODULE}:handle_override",
    inputs=({"name": "gate_payload", "value_ref": "gate.gate_payload"},),
    outputs=({"name": "override_result"},),
    metadata=_pure_body_carrier_quarantine(
        canonical_refs=(
            "arnold_pipelines.megaplan.workflows.workflow.pypeline:override",
            "arnold_pipelines.megaplan.workflows.planning:declared_step_interface(override)",
            "OVERRIDE_POLICY.metadata.route_surface",
        ),
        preserved_fields=("handler_ref", "inputs", "outputs", "runtime_branch_vocabulary"),
    ),
)

SOURCE_CRITIQUE_PANEL_WORKFLOW = _workflow(
    export_name="SOURCE_CRITIQUE_PANEL_WORKFLOW",
    workflow_id="critique_panel",
    inputs=("plan_payload",),
    outputs=("critique_payload",),
    label="Megaplan critique parallel-map child workflow",
    metadata={
        "policy_refs": ("megaplan:robustness", "megaplan:model-routing"),
        "mapper_step_ref": "arnold_pipelines.megaplan.handlers:handle_critique",
        "topology_contract": {
            "kind": "critique_fanout",
            "fanout_ref": "megaplan.policy.critique_lenses",
            "parallel_map_id": "critique-fanout",
            "path_template": "critique/{item_id}",
            "route_signal": "critique_payload",
            "lens_cardinality": CRITIQUE_LENS_CARDINALITY,
            "typed_reducer_outcomes": CRITIQUE_TYPED_REDUCER_OUTCOMES,
            "selection_policy": CRITIQUE_SELECTION_POLICY,
            "retry_policy": CRITIQUE_RETRY_POLICY,
            "evidence_contract": CRITIQUE_EVIDENCE_CONTRACT,
            "skip_and_retry_policy": {
                "bare_robustness": "skip_to_finalize",
                "evaluator_retry_attempts": 2,
                "on_exhausted": "blocked",
                "payload_recovery_ref": "critique_output.json",
            },
            "external_call_wrapping": {
                "runtime_wrapper_ref": "arnold_pipelines.megaplan.orchestration.critique_runtime",
                "retained_handler_ref": "arnold_pipelines.megaplan.handlers.critique:handle_critique",
                "worker_phase": "critique",
                "evaluator_phase": "critique_evaluator",
            },
        },
    },
)
SOURCE_TIEBREAKER_WORKFLOW = _workflow(
    export_name="SOURCE_TIEBREAKER_WORKFLOW",
    workflow_id="tiebreaker_child",
    inputs=("gate_payload",),
    outputs=("decision",),
    label="Megaplan tiebreaker child workflow",
    metadata={
        "policy_refs": ("megaplan:tiebreaker", "megaplan:model-routing"),
        "child_steps": ("tiebreaker_run", "tiebreaker_decide"),
        # Canonical four-phase child identities — these are the semantic authority
        # for the tiebreaker subworkflow. The legacy child_steps tuple above is a
        # compatibility bridge retained for existing tests and migration tooling.
        "canonical_child_phases": (
            "tiebreaker_researcher",
            "tiebreaker_challenger",
            "tiebreaker_synthesis",
            "tiebreaker_decision",
        ),
        "topology_contract": {
            "kind": "child_workflow",
            "entry_step_id": "tiebreaker_run",
            "decision_step_id": "tiebreaker_decide",
            # Canonical four-phase topology — semantic authority for lowered routes.
            "canonical_entry_step_id": "tiebreaker_researcher",
            "canonical_decision_step_id": "tiebreaker_decision",
            "run_completion_route": {
                "route_signal": "default",
                "target_ref": "tiebreaker_decide",
                "failure_behavior": "complete_decision_cycle_with_recorded_artifacts",
            },
            # Canonical four-phase target — semantic authority for lowered routes.
            "canonical_run_completion_target_ref": "tiebreaker_decision",
            "decision_routes": (
                {"action": "pick", "route_signal": "proceed", "target_ref": "finalize"},
                {"action": "replan", "route_signal": "iterate", "target_ref": "critique-fanout"},
                {"action": "escalate", "route_signal": "escalate", "target_ref": "override"},
            ),
            "fallback_route_signal": "escalate",
        },
    },
)
SOURCE_EXECUTE_BATCH_WORKFLOW = _workflow(
    export_name="SOURCE_EXECUTE_BATCH_WORKFLOW",
    workflow_id="execute_batch",
    inputs=("finalize_payload",),
    outputs=("execute_payload",),
    label="Megaplan execute batch child workflow",
    metadata={
        "policy_refs": ("megaplan:default", "megaplan:model-routing"),
        "dag_ref": "megaplan.execute.dag",
        "batch_source_ref": "finalize.task_batches",
        "topology_contract": {
            "kind": "execute_batch_child",
            "approval_gate": {
                "required_ref": "state.meta.user_approved_gate",
                "confirmation_ref": "args.confirm_destructive",
            },
            "approval_gates": {
                "destructive_confirmation": {
                    "required_unless": "prose_mode",
                    "signal_ref": "args.confirm_destructive",
                    "failure_code": "missing_confirmation",
                },
                "operator_approval": {
                    "required_unless": "state.config.auto_approve",
                    "signal_ref": "state.meta.user_approved_gate",
                    "grant_signal_ref": "args.user_approved",
                    "failure_code": "missing_approval",
                },
                "mutating_preflight": {
                    "policy_ref": (
                        "arnold_pipelines.megaplan.runtime.execution_environment:"
                        "preflight_mutating_phase"
                    ),
                    "phase": "execute",
                },
            },
            "fanout_contract": {
                "parallel_map_id": "execute-batches",
                "fanout_ref": "megaplan.execute.batches",
                "step_ref": "SOURCE_EXECUTE_BATCH_WORKFLOW",
                "reducer_ref": "SOURCE_EXECUTE",
                "path_template": "execute/{index}",
                "route_signal": "execute_payload",
            },
            "retry_and_reentry": {
                "review_rework_reexecution": "force_fresh_execute_session",
                "blocked_retry": "force_fresh_execute_session",
                "blocked_route": {
                    "route_signal": "blocked",
                    "recoverable_state": "blocked",
                    "resume_phase": "execute",
                },
            },
            "post_batch_routes": (
                {"route_signal": "review_required", "target_ref": "review-fan-in"},
                {"route_signal": "no_review", "target_ref": "halt"},
                {"route_signal": "deferred_human", "target_ref": "halt"},
            ),
        },
    },
)
SOURCE_REVIEW_PANEL_WORKFLOW = _workflow(
    export_name="SOURCE_REVIEW_PANEL_WORKFLOW",
    workflow_id="review_panel",
    inputs=("execute_payload",),
    outputs=("review_payload",),
    label="Megaplan review parallel-map child workflow",
    metadata={
        "policy_refs": ("megaplan:review", "megaplan:model-routing"),
        "fan_in_ref": "review.checks",
        "compatibility_quarantine": MappingProxyType(
            {
                "kind": "non_authoritative_adapter_metadata",
                "canonical_refs": (
                    "arnold_pipelines.megaplan.workflows.workflow.pypeline:review-fan-in",
                    "arnold_pipelines.megaplan.workflows.planning:declared_workflow_topology_contract(review_panel)",
                    "REVIEW_POLICY.metadata.route_surface",
                ),
                "preserved_fields": ("fan_in_ref", "topology_contract", "policy_refs"),
            }
        ),
        "topology_contract": {
            "kind": "review_fan_in",
            "criteria_ref": "review.criteria",
            "route_signal_ref": "review.route_signal",
            "no_review_route_signal": "pass",
            "fan_in_contract": {
                "parallel_map_id": "review-fan-in",
                "fan_in_ref": "review.checks",
                "step_ref": "SOURCE_REVIEW_PANEL_WORKFLOW",
                "reducer_ref": "SOURCE_REVIEW",
                "path_template": "review/{item_id}",
                "route_signal": "review_route_signal",
            },
            "rework_cycle": {
                "route_signal": "rework",
                "target_ref": "execute",
                "fresh_execute_session": True,
            },
            "retry_and_cap": {
                "infrastructure_retry": "review",
                "cap_exhausted_non_blocking": "force_proceeded",
                "cap_exhausted_with_blockers": "recoverable_block",
            },
            "escalation": {
                "policy_ref": "megaplan:override",
                "actions": ("recover-blocked", "force-proceed"),
            },
            "reducer_routes": (
                {"route_signal": "pass", "target_ref": "halt"},
                {"route_signal": "rework", "target_ref": "execute"},
                {"route_signal": "blocked", "target_ref": "halt"},
                {"route_signal": "force_proceeded", "target_ref": "halt"},
                {"route_signal": "deferred_human", "target_ref": "halt"},
            ),
        },
    },
)

AUTHORING_PREP = _step(
    export_name="AUTHORING_PREP",
    step_id="prep",
    kind="megaplan:prep",
    handler_ref=f"{HANDLER_MODULE}:handle_prep",
    outputs=({"name": "prep_payload"},),
    metadata=_COMPATIBILITY_QUARANTINE,
)
AUTHORING_PLAN = _step(
    export_name="AUTHORING_PLAN",
    step_id="plan",
    kind="megaplan:plan",
    handler_ref=f"{HANDLER_MODULE}:handle_plan",
    inputs=({"name": "prep_payload", "value_ref": "prep.prep_payload"},),
    outputs=({"name": "plan_payload"},),
    metadata=_COMPATIBILITY_QUARANTINE,
)
AUTHORING_CRITIQUE = _step(
    export_name="AUTHORING_CRITIQUE",
    step_id="critique",
    kind="megaplan:critique",
    handler_ref=f"{HANDLER_MODULE}:handle_critique",
    inputs=({"name": "plan_payload", "value_ref": "plan.plan_payload"},),
    outputs=({"name": "critique_payload"},),
    metadata=_COMPATIBILITY_QUARANTINE,
)
AUTHORING_GATE = _step(
    export_name="AUTHORING_GATE",
    step_id="gate",
    kind="megaplan:gate",
    handler_ref=f"{HANDLER_MODULE}:handle_gate",
    inputs=({"name": "critique_payload", "value_ref": "critique.critique_payload"},),
    outputs=({"name": "gate_payload"},),
    capability_ids=("human:gate",),
    metadata=_COMPATIBILITY_QUARANTINE,
)
AUTHORING_REVISE = _step(
    export_name="AUTHORING_REVISE",
    step_id="revise",
    kind="megaplan:revise",
    handler_ref=f"{HANDLER_MODULE}:handle_revise",
    inputs=({"name": "gate_payload", "value_ref": "gate.gate_payload"},),
    outputs=({"name": "revise_payload"},),
    capability_ids=("megaplan:planning",),
    metadata=_COMPATIBILITY_QUARANTINE,
)
AUTHORING_FINALIZE = _step(
    export_name="AUTHORING_FINALIZE",
    step_id="finalize",
    kind="megaplan:finalize",
    handler_ref=f"{HANDLER_MODULE}:handle_finalize",
    inputs=({"name": "gate_payload", "value_ref": "gate.gate_payload"},),
    outputs=({"name": "finalize_payload"},),
    metadata=_adapter_metadata_quarantine(
        canonical_refs=(
            "arnold_pipelines.megaplan.workflows.workflow.pypeline:finalize",
            "FINALIZE_POLICY.metadata.route_surface",
        ),
        preserved_fields=("handler_ref",),
    ),
)
AUTHORING_EXECUTE = _step(
    export_name="AUTHORING_EXECUTE",
    step_id="execute",
    kind="megaplan:execute",
    handler_ref=f"{HANDLER_MODULE}:handle_execute",
    inputs=({"name": "finalize_payload", "value_ref": "finalize.finalize_payload"},),
    outputs=({"name": "execute_payload"},),
)
AUTHORING_REVIEW = _step(
    export_name="AUTHORING_REVIEW",
    step_id="review",
    kind="megaplan:review",
    handler_ref=f"{HANDLER_MODULE}:handle_review",
    inputs=({"name": "execute_payload", "value_ref": "execute.execute_payload"},),
    outputs=({"name": "review_payload"},),
    capability_ids=("human:review",),
    metadata=_adapter_metadata_quarantine(
        canonical_refs=(
            "arnold_pipelines.megaplan.workflows.workflow.pypeline:review-fan-in",
            "REVIEW_POLICY.metadata.route_surface",
        ),
        preserved_fields=("handler_ref", "runtime_branch_vocabulary"),
    ),
)
AUTHORING_HALT = _step(
    export_name="AUTHORING_HALT",
    step_id="halt",
    kind="megaplan:halt",
    outputs=({"name": "status"},),
    terminal=True,
)
AUTHORING_OVERRIDE = _step(
    export_name="AUTHORING_OVERRIDE",
    step_id="override",
    kind="megaplan:override",
    handler_ref=f"{HANDLER_MODULE}:handle_override",
    inputs=({"name": "gate_payload", "value_ref": "gate.gate_payload"},),
    outputs=({"name": "override_result"},),
)
CRITIQUE_PANEL_WORKFLOW = _workflow(
    export_name="CRITIQUE_PANEL_WORKFLOW",
    workflow_id="critique_panel",
    inputs=("plan_payload",),
    outputs=("critique_payload",),
    label="Megaplan critique parallel-map child workflow",
    metadata=SOURCE_CRITIQUE_PANEL_WORKFLOW.metadata,
)
TIEBREAKER_WORKFLOW = _workflow(
    export_name="TIEBREAKER_WORKFLOW",
    workflow_id="tiebreaker_child",
    inputs=("gate_payload",),
    outputs=("decision",),
    label="Megaplan tiebreaker child workflow",
    metadata=SOURCE_TIEBREAKER_WORKFLOW.metadata,
)
EXECUTE_BATCH_WORKFLOW = _workflow(
    export_name="EXECUTE_BATCH_WORKFLOW",
    workflow_id="execute_batch",
    inputs=("finalize_payload",),
    outputs=("execute_payload",),
    label="Megaplan execute batch child workflow",
    metadata=SOURCE_EXECUTE_BATCH_WORKFLOW.metadata,
)
REVIEW_PANEL_WORKFLOW = _workflow(
    export_name="REVIEW_PANEL_WORKFLOW",
    workflow_id="review_panel",
    inputs=("execute_payload",),
    outputs=("review_payload",),
    label="Megaplan review parallel-map child workflow",
    metadata=SOURCE_REVIEW_PANEL_WORKFLOW.metadata,
)

ALL_STEP_COMPONENTS = (
    PREP,
    PLAN,
    CRITIQUE,
    GATE,
    REVISE,
    TIEBREAKER_RUN,  # bridge-only: legacy carrier, no route authority
    TIEBREAKER_DECIDE,  # bridge-only: legacy carrier, no route authority
    TIEBREAKER_RESEARCHER,
    TIEBREAKER_CHALLENGER,
    TIEBREAKER_SYNTHESIS,
    TIEBREAKER_DECISION,
    FINALIZE,
    EXECUTE,
    REVIEW,
    HALT,
    OVERRIDE,
)
STEP_COMPONENTS_BY_ID = MappingProxyType({component.id.removeprefix("megaplan:"): component for component in ALL_STEP_COMPONENTS})
PROMPT_COMPONENTS = (
    PREP_PROMPT,
    PLAN_PROMPT,
    CRITIQUE_PROMPT,
    GATE_PROMPT,
    REVISE_PROMPT,
    TIEBREAKER_RESEARCHER_PROMPT,
    TIEBREAKER_CHALLENGER_PROMPT,
    TIEBREAKER_SYNTHESIS_PROMPT,
    TIEBREAKER_DECISION_PROMPT,
    FINALIZE_PROMPT,
    EXECUTE_PROMPT,
    REVIEW_PROMPT,
)
POLICY_COMPONENTS = (
    DEFAULT_POLICY,
    PREP_CLARIFY_POLICY,
    GATE_POLICY,
    REVISE_LOOP_POLICY,
    TIEBREAKER_POLICY,
    FINALIZE_POLICY,
    REVIEW_POLICY,
    EXECUTE_POLICY,
    OVERRIDE_POLICY,
    MODEL_ROUTING_POLICY,
    BLAST_RADIUS_POLICY,
    ROBUSTNESS_POLICY,
    ARTIFACT_CONTRACT_POLICY,
    SUSPENSION_POLICY,
)
WORKFLOW_COMPONENTS = (
    SOURCE_CRITIQUE_PANEL_WORKFLOW,
    SOURCE_TIEBREAKER_WORKFLOW,
    SOURCE_EXECUTE_BATCH_WORKFLOW,
    SOURCE_REVIEW_PANEL_WORKFLOW,
)

SCHEMA_COMPONENTS = (
    PREP_INPUT_SCHEMA,
    PREP_OUTPUT_SCHEMA,
    PLAN_INPUT_SCHEMA,
    PLAN_OUTPUT_SCHEMA,
    CRITIQUE_INPUT_SCHEMA,
    CRITIQUE_OUTPUT_SCHEMA,
    GATE_INPUT_SCHEMA,
    GATE_OUTPUT_SCHEMA,
    REVISE_INPUT_SCHEMA,
    REVISE_OUTPUT_SCHEMA,
    TIEBREAKER_RUN_INPUT_SCHEMA,  # bridge-only: legacy schema
    TIEBREAKER_RUN_OUTPUT_SCHEMA,  # bridge-only: legacy schema
    TIEBREAKER_DECIDE_INPUT_SCHEMA,  # bridge-only: legacy schema
    TIEBREAKER_DECIDE_OUTPUT_SCHEMA,  # bridge-only: legacy schema
    TIEBREAKER_RESEARCHER_INPUT_SCHEMA,
    TIEBREAKER_RESEARCHER_OUTPUT_SCHEMA,
    TIEBREAKER_CHALLENGER_INPUT_SCHEMA,
    TIEBREAKER_CHALLENGER_OUTPUT_SCHEMA,
    TIEBREAKER_SYNTHESIS_INPUT_SCHEMA,
    TIEBREAKER_SYNTHESIS_OUTPUT_SCHEMA,
    TIEBREAKER_DECISION_INPUT_SCHEMA,
    TIEBREAKER_DECISION_OUTPUT_SCHEMA,
    FINALIZE_INPUT_SCHEMA,
    FINALIZE_OUTPUT_SCHEMA,
    EXECUTE_INPUT_SCHEMA,
    EXECUTE_OUTPUT_SCHEMA,
    REVIEW_INPUT_SCHEMA,
    REVIEW_OUTPUT_SCHEMA,
    HALT_OUTPUT_SCHEMA,
    OVERRIDE_INPUT_SCHEMA,
    OVERRIDE_OUTPUT_SCHEMA,
    SUSPEND_OUTPUT_SCHEMA,
)

__all__ = [
    "ALL_STEP_COMPONENTS",
    "CAPABILITY_REQUIREMENTS",
    "BLAST_RADIUS_POLICY",
    "CRITIQUE",
    "CRITIQUE_INPUT_SCHEMA",
    "CRITIQUE_OUTPUT_SCHEMA",
    "CRITIQUE_PROMPT",
    "DEFAULT_POLICY",
    "EXECUTE_POLICY",
    "EXECUTE",
    "EXECUTE_INPUT_SCHEMA",
    "EXECUTE_OUTPUT_SCHEMA",
    "EXECUTE_PROMPT",
    "FINALIZE",
    "FINALIZE_INPUT_SCHEMA",
    "FINALIZE_OUTPUT_SCHEMA",
    "FINALIZE_POLICY",
    "FINALIZE_PROMPT",
    "GATE",
    "GATE_INPUT_SCHEMA",
    "GATE_OUTPUT_SCHEMA",
    "GATE_PROMPT",
    "GATE_POLICY",
    "GATE_NORMALIZATION_POLICY",
    "GATE_DEBT_VISIBILITY_POLICY",
    "GATE_REPROMPT_POLICY",
    "HALT",
    "HALT_OUTPUT_SCHEMA",
    "ARTIFACT_CONTRACT_POLICY",
    "M4_LOOP_MAX_ITERATIONS",
    "MODEL_ROUTING_POLICY",
    "OVERRIDE",
    "OVERRIDE_INPUT_SCHEMA",
    "OVERRIDE_OUTPUT_SCHEMA",
    "OVERRIDE_POLICY",
    "PLAN",
    "PLAN_INPUT_SCHEMA",
    "PLAN_OUTPUT_SCHEMA",
    "PLAN_PROMPT",
    "POLICY_COMPONENTS",
    "PREP",
    "PREP_CLARIFY_POLICY",
    "PREP_INPUT_SCHEMA",
    "PREP_OUTPUT_SCHEMA",
    "PREP_PROMPT",
    "PROMPT_COMPONENTS",
    "REVIEW",
    "REVIEW_INPUT_SCHEMA",
    "REVIEW_OUTPUT_SCHEMA",
    "REVIEW_PROMPT",
    "REVIEW_POLICY",
    "REVISE",
    "REVISE_INPUT_SCHEMA",
    "REVISE_LOOP_POLICY",
    "REVISE_LOOP_TERMINATION_POLICY",
    "REVISE_OUTPUT_SCHEMA",
    "REVISE_PROMPT",
    "ROBUSTNESS_POLICY",
    "RUNTIME_BRANCH_VOCABULARY",
    "check_outcome_vocabulary_parity",
    "SCHEMA_COMPONENTS",
    "STEP_COMPONENTS_BY_ID",
    "SUSPEND",
    "SUSPEND_OUTPUT_SCHEMA",
    "SUSPENSION_POLICY",
    "TIEBREAKER_CHALLENGER",
    "TIEBREAKER_CHALLENGER_PROMPT",
    "TIEBREAKER_DECIDE",
    "TIEBREAKER_DECIDE_INPUT_SCHEMA",
    "TIEBREAKER_DECIDE_OUTPUT_SCHEMA",
    "TIEBREAKER_DECISION",
    "TIEBREAKER_DECISION_PROMPT",
    "TIEBREAKER_POLICY",
    "TIEBREAKER_RESEARCHER",
    "TIEBREAKER_RESEARCHER_PROMPT",
    "TIEBREAKER_RUN",
    "TIEBREAKER_RUN_INPUT_SCHEMA",
    "TIEBREAKER_RUN_OUTPUT_SCHEMA",
    "TIEBREAKER_SYNTHESIS",
    "TIEBREAKER_SYNTHESIS_PROMPT",
]
