"""S2/S3/S4/S5 boundary contract registry.

Defines immutable ``BoundaryContract`` instances for the S2 front-half
workflow boundaries (prep→plan, plan→critique, critique→gate,
gate→revise, revise→critique) and the S3 tiebreaker/replan boundaries
(researcher→challenger, challenger→synthesis, synthesis→decision,
decision→parent, replan authority, parent rejoin promotion), the S4
execute boundaries, and the S5 review/finalize evidence boundaries.
Each contract references a stable row ID from
``arnold.workflow.semantic_evidence`` and, where the shared enum already
covers the carrier, a ``BoundaryPhase`` value from
``arnold.workflow.boundary_evidence``.

This registry is intentionally declarative: it does not declare route
targets, compute routing predicates, or mutate state.  It is the single
source of truth for downstream checker, receipt-emission, and
semantic-health work.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Collection

from arnold.workflow.boundary_evidence import BoundaryContract, BoundaryPhase
from arnold.workflow.boundary_templates import (
    BoundaryTemplateKind,
    REQUIRED_FIELDS_APPROVAL_BOUNDARY,
    REQUIRED_FIELDS_ARTIFACT_HANDOFF_BOUNDARY,
    REQUIRED_FIELDS_ARTIFACT_PROMOTION,
    REQUIRED_FIELDS_EXECUTION_CUSTODY,
    REQUIRED_FIELDS_EXTERNAL_EFFECT,
    REQUIRED_FIELDS_EXTERNAL_WITNESS,
    REQUIRED_FIELDS_GRAPH_JOIN_FANOUT,
    REQUIRED_FIELDS_HUMAN_APPROVAL_WAIVER,
    REQUIRED_FIELDS_REVISION_BOUNDARY,
    REQUIRED_FIELDS_VALIDATION_BOUNDARY,
    check_contract_conformance as _generic_check_contract_conformance,
    classify_boundary_kind,
    get_required_fields,
    get_template,
    list_template_kinds,
    select_template,
)
from arnold.workflow.semantic_evidence import (
    S2_CRITIQUE_ROW_ID,
    S2_GATE_ROW_ID,
    S2_PLAN_ROW_ID,
    S2_PREP_ROW_ID,
    S2_REVISE_ROW_ID,
    S3_PARENT_REJOIN_ROW_ID,
    S3_REPLAN_AUTHORITY_ROW_ID,
    S3_TIEBREAKER_CHALLENGER_ROW_ID,
    S3_TIEBREAKER_DECISION_ROW_ID,
    S3_TIEBREAKER_RESEARCHER_ROW_ID,
    S3_TIEBREAKER_SYNTHESIS_ROW_ID,
    S4_EXECUTE_ROW_ID,
)

# ── Re-export generic template/profile surface symbols ──────────────────────
# These are imported from arnold.workflow.boundary_templates and re-exported
# so that Megaplan consumers can use the same stable identifiers without
# importing from arnold.workflow directly.  The registry below extends them
# with Megaplan-adapter-specific kinds and templates.

__all__: list[str] = []

# ── S5 review/finalize stable row ID namespace ─────────────────────────────
# These rows remain local to the registry until the downstream checker adds
# first-class S5 row matching. The IDs are still stable so receipts and
# diagnostics can reference them now.

S5_REVIEW_CHILD_OUTPUTS_ROW_ID = "s5.review_child_outputs.1"
S5_REVIEW_REDUCER_PROMOTION_ROW_ID = "s5.review_reducer_promotion.1"
S5_REVIEW_REWORK_EFFECTS_ROW_ID = "s5.review_rework_effects.1"
S5_REVIEW_CAP_AUTHORITY_ROW_ID = "s5.review_cap_authority.1"
S5_REVIEW_HUMAN_VERIFICATION_ROW_ID = "s5.review_human_verification.1"
S5_FINALIZE_ARTIFACTS_ROW_ID = "s5.finalize_artifacts.1"
S5_FINALIZE_FALLBACK_ROW_ID = "s5.finalize_fallback.1"
S5_FINAL_PROJECTION_ROW_ID = "s5.final_projection.1"

# ── S6 override authority stable row ID namespace ────────────────────────

S6_OVERRIDE_ABORT_ROW_ID = "s6.override.abort.1"
S6_OVERRIDE_CAP_REVISE_ONCE_ROW_ID = "s6.override.cap_revise_once.1"
S6_OVERRIDE_FORCE_PROCEED_ROW_ID = "s6.override.force_proceed.1"
S6_OVERRIDE_REPLAN_ROW_ID = "s6.override.replan.1"
S6_OVERRIDE_RECOVER_BLOCKED_ROW_ID = "s6.override.recover_blocked.1"
S6_OVERRIDE_RESUME_CLARIFY_ROW_ID = "s6.override.resume_clarify.1"
S6_OVERRIDE_ADOPT_EXECUTION_ROW_ID = "s6.override.adopt_execution.1"
S6_OVERRIDE_SUSPENSION_ROW_ID = "s6.override.suspension.1"
S6_OVERRIDE_HUMAN_GATE_ROW_ID = "s6.override.human_gate.1"
S6_OVERRIDE_CUTOVER_ROW_ID = "s6.override.cutover.1"
S6_OVERRIDE_RECONCILE_PLAN_LEDGER_ROW_ID = "s6.override.reconcile_plan_ledger.1"

# ── Chain milestone stable row ID namespace ─────────────────────────────

CHAIN_MILESTONE_START_ROW_ID = "chain.milestone.start.1"
CHAIN_MILESTONE_COMPLETION_ROW_ID = "chain.milestone.complete.1"
CHAIN_COMPLETE_ROW_ID = "chain.complete.1"

# ── PR/CI transition stable row ID namespace ────────────────────────────

PR_READY_ROW_ID = "pr.ready.1"
PR_MERGED_ROW_ID = "pr.merged.1"

# ── Repair verdict stable row ID namespace ──────────────────────────────

REPAIR_CLOUD_DISPATCH_ROW_ID = "repair.cloud_dispatch.1"
REPAIR_ORDINARY_COMPLETE_ROW_ID = "repair.ordinary_complete.1"
REPAIR_META_COMPLETE_ROW_ID = "repair.meta_complete.1"

# ── Auditor completion stable row ID namespace ──────────────────────────

AUDITOR_6H_COMPLETE_ROW_ID = "auditor.6h_complete.1"

# ── Next-three-hour reconciliation vocabulary (M11 Step 50) ──────────────
# The six-hour filenames and field names (AUDITOR_6H_COMPLETE_ROW_ID,
# auditor_6h_completion, "6h") are retained as compatibility-only
# identifiers/exact-version evidence. Positive proof of the reconciliation
# cadence now flows through NEXT_THREE_HOUR_RECONCILIATION. The
# reconciliation label is a schedule/evidence fact — it MUST NOT be promoted
# into repair authority, and incomplete reconciliation prerequisites fail
# closed. Mirrors arnold_pipelines.megaplan.cloud.six_hour_auditor (T33).
NEXT_THREE_HOUR_RECONCILIATION = "next_three_hour"
AUDITOR_RECONCILIATION_INTERVAL = NEXT_THREE_HOUR_RECONCILIATION
LEGACY_SIX_HOUR_NAMES_COMPATIBILITY_ONLY = True

# ── Cloud custody stable row ID namespace ───────────────────────────────

CUSTODY_MANAGED_RUNNING_ROW_ID = "custody.managed_running.1"
CUSTODY_COMPLETE_ROW_ID = "custody.complete.1"
CUSTODY_UNMANAGED_WARNING_ROW_ID = "custody.unmanaged_warning.1"
CUSTODY_BLOCKED_RELAUNCH_ROW_ID = "custody.blocked_relaunch.1"
CUSTODY_ESCALATED_UNCHANGED_ROW_ID = "custody.escalated_unchanged.1"

# ── Adapter-specific template kind identifiers ─────────────────────────────
# BoundaryTemplateKind (imported from arnold.workflow.boundary_templates)
# provides 10 generic kinds.  The Megaplan adapter adds 7 more for
# domain-specific boundary shapes that are not part of the generic surface.
# Physical/external evidence and partial acceptance remain adapter details
# — they are NOT promoted into the generic BoundaryTemplateKind enum.


class AdapterTemplateKind(StrEnum):
    """Megaplan-adapter-specific template kind identifiers.

    These extend the generic :class:`BoundaryTemplateKind` with shapes that
    are specific to the Megaplan workflow model: lifecycle transitions,
    reducer fan-in, chain milestones, PR/CI transitions, repair verdicts,
    auditor completions, and cloud custody classifications.

    Physical/external evidence keys (e.g. ``physical_evidence_ref``,
    ``external_artifact_ref``) and partial-acceptance metadata stay in
    adapter ``details`` mappings — they are never promoted into generic
    template profile fields.
    """

    LIFECYCLE_TRANSITION = "lifecycle_transition"
    """Lifecycle transition boundary: phase→phase durable transition."""

    REDUCER = "reducer"
    """Reducer boundary: fan-in aggregation into canonical payload."""

    CHAIN_MILESTONE = "chain_milestone"
    """Chain milestone boundary: milestone start→completion transition."""

    PR_TRANSITION = "pr_transition"
    """PR/CI transition boundary: PR ready→merged durable evidence."""

    REPAIR_VERDICT = "repair_verdict"
    """Repair verdict boundary: cleared/no-fix/escalation verdict."""

    AUDITOR_COMPLETION = "auditor_completion"
    """Auditor completion boundary: auditor verdict set produced."""

    CLOUD_CUSTODY = "cloud_custody"
    """Cloud custody classification boundary: custody classification."""


# ── Required-field profiles ────────────────────────────────────────────────
# The 10 generic profiles are imported from arnold.workflow.boundary_templates
# and re-exported above (REQUIRED_FIELDS_REVISION_BOUNDARY, etc.).
#
# The 7 adapter-specific profiles below cover Megaplan-only boundary shapes.
# Each frozenset enumerates the BoundaryContract top-level fields *and*
# detail keys that must be populated for a contract of that shape.
# Field names prefixed with ``details.`` refer to keys nested inside the
# ``details`` mapping.  Profiles are declarative: they do not route or
# dispatch.

REQUIRED_FIELDS_LIFECYCLE_TRANSITION: frozenset[str] = frozenset(
    {
        "boundary_id",
        "workflow_id",
        "row_id",
        "phase",
        "expected_state_delta",
        "expected_history_entry",
        "phase_result_required",
        "receipt_required",
    }
)

REQUIRED_FIELDS_REDUCER: frozenset[str] = frozenset(
    {
        "boundary_id",
        "workflow_id",
        "row_id",
        "required_artifacts",
        "phase_result_required",
        "receipt_required",
        "details.reducer_promotion",
        "details.reducer_ref",
        "details.fan_in_ref",
    }
)

REQUIRED_FIELDS_CHAIN_MILESTONE: frozenset[str] = frozenset(
    {
        "boundary_id",
        "workflow_id",
        "row_id",
        "required_artifacts",
        "expected_state_delta",
        "expected_history_entry",
        "phase_result_required",
        "receipt_required",
        "details.milestone_kind",
        "details.chain_ref",
    }
)

REQUIRED_FIELDS_PR_TRANSITION: frozenset[str] = frozenset(
    {
        "boundary_id",
        "workflow_id",
        "row_id",
        "required_artifacts",
        "expected_state_delta",
        "expected_history_entry",
        "receipt_required",
        "details.pr_kind",
        "details.branch_ref",
    }
)

REQUIRED_FIELDS_REPAIR_VERDICT: frozenset[str] = frozenset(
    {
        "boundary_id",
        "workflow_id",
        "row_id",
        "required_artifacts",
        "expected_state_delta",
        "phase_result_required",
        "receipt_required",
        "details.verdict_kind",
        "details.repair_ref",
    }
)

REQUIRED_FIELDS_AUDITOR_COMPLETION: frozenset[str] = frozenset(
    {
        "boundary_id",
        "workflow_id",
        "row_id",
        "required_artifacts",
        "phase_result_required",
        "receipt_required",
        "details.auditor_kind",
        "details.time_window",
        "details.verdict_refs",
    }
)

REQUIRED_FIELDS_CLOUD_CUSTODY: frozenset[str] = frozenset(
    {
        "boundary_id",
        "workflow_id",
        "row_id",
        "required_artifacts",
        "authority_required",
        "details.custody_scope",
        "details.custody_classification",
        "details.fresh_session",
    }
)

# ── Typed boundary templates ───────────────────────────────────────────────
# Each template is a canonical BoundaryContract instance that defines the
# expected shape for a class of boundaries.  Templates are declarative
# reference instances, not executable route tables or dispatch objects.
# Downstream code retrieves the template and compares or extends it.

artifact_promotion_template = BoundaryContract(
    boundary_id="template.artifact_promotion",
    workflow_id="megaplan-review",
    row_id="template.artifact_promotion.1",
    phase=None,
    required_artifacts=(),
    expected_state_delta={"promotion_stage": "scratch_to_canonical"},
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={
        "description": "Artifact promotion boundary template: scratch→canonical artifact elevation.",
        "effect_id": "artifact.promotion",
        "artifact_policy_ref": "megaplan:artifact-contract",
        "promotion_kind": "artifact_promotion",
    },
)

lifecycle_transition_template = BoundaryContract(
    boundary_id="template.lifecycle_transition",
    workflow_id="megaplan-review",
    row_id="template.lifecycle_transition.1",
    phase=None,
    required_artifacts=(),
    expected_state_delta={"current_phase": "<source_phase>"},
    expected_history_entry="<transition_event>",
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={
        "description": "Lifecycle transition boundary template: phase→phase durable transition.",
    },
)

reducer_template = BoundaryContract(
    boundary_id="template.reducer",
    workflow_id="megaplan-review",
    row_id="template.reducer.1",
    phase=None,
    required_artifacts=(),
    expected_state_delta={},
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={
        "description": "Reducer boundary template: fan-in aggregation into canonical payload.",
        "reducer_promotion": True,
        "reducer_ref": "<reducer_ref>",
        "fan_in_ref": "<fan_in_ref>",
    },
)

external_effect_template = BoundaryContract(
    boundary_id="template.external_effect",
    workflow_id="megaplan-review",
    row_id="template.external_effect.1",
    phase=None,
    required_artifacts=(),
    expected_state_delta={},
    phase_result_required=False,
    receipt_required=True,
    authority_required=False,
    details={
        "description": "External effect boundary template: side-effect emission as declarative contract.",
        "effect_kind": "external_effect",
        "effect_id": "<effect_id>",
    },
)

execution_custody_template = BoundaryContract(
    boundary_id="template.execution_custody",
    workflow_id="megaplan-review",
    row_id="template.execution_custody.1",
    phase=None,
    required_artifacts=(),
    expected_state_delta={},
    phase_result_required=False,
    receipt_required=False,
    authority_required=True,
    details={
        "description": "Execution custody boundary template: custody handoff with fresh session.",
        "custody_scope": "execute:custody",
        "fresh_session": True,
    },
)

human_approval_waiver_template = BoundaryContract(
    boundary_id="template.human_approval_waiver",
    workflow_id="megaplan-review",
    row_id="template.human_approval_waiver.1",
    phase=None,
    required_artifacts=("approval_record.json",),
    expected_state_delta={},
    phase_result_required=False,
    receipt_required=True,
    authority_required=True,
    details={
        "description": "Human approval/waiver boundary template: deferred human-in-the-loop gate.",
        "approval_scope": "human:approval",
        "suspension_route_id": "human:deferred",
        "resume_policy_ref": "megaplan:suspension",
    },
)

graph_join_fanout_template = BoundaryContract(
    boundary_id="template.graph_join_fanout",
    workflow_id="megaplan-review",
    row_id="template.graph_join_fanout.1",
    phase=None,
    required_artifacts=(),
    expected_state_delta={},
    phase_result_required=False,
    receipt_required=False,
    authority_required=False,
    details={
        "description": "Graph join/fan-out boundary template: declared dependency and fan topology.",
        "fan_out_refs": (),
        "fan_in_ref": "<fan_in_ref>",
        "join_requirements": (),
    },
)

external_witness_template = BoundaryContract(
    boundary_id="template.external_witness",
    workflow_id="megaplan-review",
    row_id="template.external_witness.1",
    phase=None,
    required_artifacts=(),
    expected_state_delta={},
    phase_result_required=False,
    receipt_required=True,
    authority_required=False,
    details={
        "description": "External witness boundary template: external attestation evidence.",
        "witness_ref": "<witness_ref>",
        "witness_kind": "external_attestation",
    },
)

RevisionBoundary = BoundaryContract(
    boundary_id="template.revision_boundary",
    workflow_id="megaplan-review",
    row_id="template.revision_boundary.1",
    phase=None,
    required_artifacts=("revised_content.json",),
    expected_state_delta={"revision_stage": "revised"},
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={
        "description": "Revision boundary template: rework cycle declarative evidence.",
        "revision_kind": "revision",
        "revision_log_ref": "revision_log.md",
    },
)

ValidationBoundary = BoundaryContract(
    boundary_id="template.validation_boundary",
    workflow_id="megaplan-review",
    row_id="template.validation_boundary.1",
    phase=None,
    required_artifacts=("validation_result.json",),
    expected_state_delta={"validation_stage": "validated"},
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={
        "description": "Validation boundary template: validation gate declarative evidence.",
        "validation_kind": "validation",
    },
)

ArtifactHandoffBoundary = BoundaryContract(
    boundary_id="template.artifact_handoff_boundary",
    workflow_id="megaplan-review",
    row_id="template.artifact_handoff_boundary.1",
    phase=None,
    required_artifacts=(),
    expected_state_delta={},
    phase_result_required=False,
    receipt_required=True,
    authority_required=False,
    details={
        "description": "Artifact handoff boundary template: producer→consumer artifact transfer.",
        "handoff_from": "<producer_id>",
        "handoff_to": "<consumer_id>",
        "artifact_policy_ref": "megaplan:artifact-contract",
    },
)

ApprovalBoundary = BoundaryContract(
    boundary_id="template.approval_boundary",
    workflow_id="megaplan-review",
    row_id="template.approval_boundary.1",
    phase=None,
    required_artifacts=("approval_record.json",),
    expected_state_delta={},
    phase_result_required=False,
    receipt_required=True,
    authority_required=True,
    details={
        "description": "Approval boundary template: approval gate with required authority.",
        "approval_scope": "approval:required",
    },
)

chain_milestone_template = BoundaryContract(
    boundary_id="template.chain_milestone",
    workflow_id="megaplan-review",
    row_id="template.chain_milestone.1",
    phase=None,
    required_artifacts=(),
    expected_state_delta={"milestone_stage": "<stage>"},
    expected_history_entry="<milestone_event>",
    phase_result_required=True,
    receipt_required=True,
    authority_required=True,
    details={
        "description": "Chain milestone boundary template: milestone start → completion durable transition.",
        "milestone_kind": "chain_milestone",
        "chain_ref": "<chain_ref>",
    },
)

pr_transition_template = BoundaryContract(
    boundary_id="template.pr_transition",
    workflow_id="megaplan-review",
    row_id="template.pr_transition.1",
    phase=None,
    required_artifacts=(),
    expected_state_delta={"pr_stage": "<stage>"},
    expected_history_entry="<pr_event>",
    phase_result_required=False,
    receipt_required=True,
    authority_required=True,
    details={
        "description": "PR/CI transition boundary template: PR ready → merged durable evidence.",
        "pr_kind": "pr_transition",
        "branch_ref": "<branch_ref>",
    },
)

repair_verdict_template = BoundaryContract(
    boundary_id="template.repair_verdict",
    workflow_id="megaplan-review",
    row_id="template.repair_verdict.1",
    phase=None,
    required_artifacts=(),
    expected_state_delta={"repair_stage": "<verdict>"},
    phase_result_required=True,
    receipt_required=True,
    authority_required=True,
    details={
        "description": "Repair verdict boundary template: cleared / no-fix / escalation verdict tied to original finding.",
        "verdict_kind": "repair_verdict",
        "repair_ref": "<repair_ref>",
    },
)

auditor_completion_template = BoundaryContract(
    boundary_id="template.auditor_completion",
    workflow_id="megaplan-review",
    row_id="template.auditor_completion.1",
    phase=None,
    required_artifacts=(),
    phase_result_required=True,
    receipt_required=True,
    authority_required=True,
    details={
        "description": (
            "Auditor completion boundary template: next-three-hour auditor "
            "reconciliation verdict set produced (six-hour names retained as "
            "compatibility-only exact-version evidence)."
        ),
        "auditor_kind": "auditor_completion",
        "time_window": NEXT_THREE_HOUR_RECONCILIATION,
        "reconciliation_interval": NEXT_THREE_HOUR_RECONCILIATION,
        "legacy_six_hour_names_compatibility_only": (
            LEGACY_SIX_HOUR_NAMES_COMPATIBILITY_ONLY
        ),
        "verdict_refs": (),
    },
)

cloud_custody_template = BoundaryContract(
    boundary_id="template.cloud_custody",
    workflow_id="megaplan-review",
    row_id="template.cloud_custody.1",
    phase=None,
    required_artifacts=(),
    expected_state_delta={},
    phase_result_required=False,
    receipt_required=False,
    authority_required=True,
    details={
        "description": "Cloud custody classification boundary template: custody classification as declarative contract.",
        "custody_scope": "cloud:custody",
        "custody_classification": "<classification>",
        "fresh_session": True,
    },
)

# ── Template registry ──────────────────────────────────────────────────────

TYPED_BOUNDARY_TEMPLATES: tuple[BoundaryContract, ...] = (
    artifact_promotion_template,
    lifecycle_transition_template,
    reducer_template,
    external_effect_template,
    execution_custody_template,
    human_approval_waiver_template,
    graph_join_fanout_template,
    external_witness_template,
    RevisionBoundary,
    ValidationBoundary,
    ArtifactHandoffBoundary,
    ApprovalBoundary,
    chain_milestone_template,
    pr_transition_template,
    repair_verdict_template,
    auditor_completion_template,
    cloud_custody_template,
)

TYPED_BOUNDARY_TEMPLATES_BY_ID: dict[str, BoundaryContract] = {
    t.boundary_id: t for t in TYPED_BOUNDARY_TEMPLATES
}

# ── Combined required-field profiles registry ─────────────────────────────
# The 10 generic profiles from arnold.workflow.boundary_templates PLUS the
# 7 adapter-specific profiles below.  All 17 are presented through the same
# (kind_label, frozenset) tuple shape as before for backward compatibility.
#
# ADAPTER_REQUIRED_FIELD_PROFILES and ADAPTER_REQUIRED_FIELD_PROFILES_BY_KIND
# expose only the 7 adapter-specific kinds keyed by AdapterTemplateKind values.

ADAPTER_REQUIRED_FIELD_PROFILES: tuple[tuple[str, frozenset[str]], ...] = (
    ("lifecycle_transition", REQUIRED_FIELDS_LIFECYCLE_TRANSITION),
    ("reducer", REQUIRED_FIELDS_REDUCER),
    ("chain_milestone", REQUIRED_FIELDS_CHAIN_MILESTONE),
    ("pr_transition", REQUIRED_FIELDS_PR_TRANSITION),
    ("repair_verdict", REQUIRED_FIELDS_REPAIR_VERDICT),
    ("auditor_completion", REQUIRED_FIELDS_AUDITOR_COMPLETION),
    ("cloud_custody", REQUIRED_FIELDS_CLOUD_CUSTODY),
)

ADAPTER_REQUIRED_FIELD_PROFILES_BY_KIND: dict[str, frozenset[str]] = {
    kind: fields for kind, fields in ADAPTER_REQUIRED_FIELD_PROFILES
}

REQUIRED_FIELD_PROFILES: tuple[tuple[str, frozenset[str]], ...] = (
    # ── Generic profiles (from boundary_templates) ─────────────────────
    ("artifact_promotion", REQUIRED_FIELDS_ARTIFACT_PROMOTION),
    ("execution_custody", REQUIRED_FIELDS_EXECUTION_CUSTODY),
    ("external_effect", REQUIRED_FIELDS_EXTERNAL_EFFECT),
    ("external_witness", REQUIRED_FIELDS_EXTERNAL_WITNESS),
    ("graph_join_fanout", REQUIRED_FIELDS_GRAPH_JOIN_FANOUT),
    ("human_approval_waiver", REQUIRED_FIELDS_HUMAN_APPROVAL_WAIVER),
    ("revision_boundary", REQUIRED_FIELDS_REVISION_BOUNDARY),
    ("validation_boundary", REQUIRED_FIELDS_VALIDATION_BOUNDARY),
    ("artifact_handoff_boundary", REQUIRED_FIELDS_ARTIFACT_HANDOFF_BOUNDARY),
    ("approval_boundary", REQUIRED_FIELDS_APPROVAL_BOUNDARY),
    # ── Adapter-specific profiles ──────────────────────────────────────
    *ADAPTER_REQUIRED_FIELD_PROFILES,
)

REQUIRED_FIELD_PROFILES_BY_KIND: dict[str, frozenset[str]] = {
    kind: fields for kind, fields in REQUIRED_FIELD_PROFILES
}

# ── S2 Front-half boundary contracts ───────────────────────────────────────

prep_to_plan = BoundaryContract(
    boundary_id="prep_to_plan",
    workflow_id="megaplan-review",
    row_id=S2_PREP_ROW_ID,
    phase=BoundaryPhase.PREP,
    required_artifacts=("research.md", "brief.md"),
    expected_state_delta={"current_phase": "prep"},
    expected_history_entry="prep_completed",
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={"description": "Prep → Plan boundary: research and brief complete"},
)

# ── S1 prep lifecycle rule (profile/template-driven) ─────────────────────
# This contract expresses the prep rule as a boundary contract instance that
# explicitly references the lifecycle_transition profile and template so that
# semantic-health and downstream evaluators can derive expectations from
# declared metadata rather than hard-coded field values.

prep_lifecycle_rule = BoundaryContract(
    boundary_id="prep_lifecycle_rule",
    workflow_id="megaplan-review",
    row_id=S2_PREP_ROW_ID,
    phase=BoundaryPhase.PREP,
    required_artifacts=("research.md", "brief.md"),
    expected_state_delta={"current_phase": "prep"},
    expected_history_entry="prep_completed",
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={
        "description": (
            "Prep lifecycle rule: prep→plan transition expressed as a "
            "profile/template-driven boundary contract instance."
        ),
        "profile_kind": "lifecycle_transition",
        "template_ref": "template.lifecycle_transition",
        "canonical_outputs": ("research.md", "brief.md"),
        "state_delta_key": "current_phase",
        "state_delta_value": "prep",
        "history_entry": "prep_completed",
    },
)

plan_to_critique = BoundaryContract(
    boundary_id="plan_to_critique",
    workflow_id="megaplan-review",
    row_id=S2_PLAN_ROW_ID,
    phase=BoundaryPhase.PLAN,
    required_artifacts=("plan.md",),
    expected_state_delta={"current_phase": "plan"},
    expected_history_entry="plan_completed",
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={"description": "Plan → Critique boundary: plan artifact produced"},
)

critique_to_gate = BoundaryContract(
    boundary_id="critique_to_gate",
    workflow_id="megaplan-review",
    row_id=S2_CRITIQUE_ROW_ID,
    phase=BoundaryPhase.CRITIQUE,
    required_artifacts=("critique.md", "scores.json"),
    expected_state_delta={"current_phase": "critique"},
    expected_history_entry="critique_completed",
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={"description": "Critique → Gate boundary: critique and scores complete"},
)

gate_to_revise = BoundaryContract(
    boundary_id="gate_to_revise",
    workflow_id="megaplan-review",
    row_id=S2_GATE_ROW_ID,
    phase=BoundaryPhase.GATE,
    required_artifacts=("gate_decision.json", "phase_result.json"),
    expected_state_delta={"current_phase": "gate"},
    expected_history_entry="gate_iterate",
    phase_result_required=True,
    receipt_required=True,
    authority_required=True,
    details={
        "description": (
            "Gate → Revise boundary: gate decision requires revision; "
            "only emitted for iterate/retry/revise outcomes"
        ),
    },
)

revise_to_critique = BoundaryContract(
    boundary_id="revise_to_critique",
    workflow_id="megaplan-review",
    row_id=S2_REVISE_ROW_ID,
    phase=BoundaryPhase.REVISE,
    required_artifacts=("revised_plan.md", "revision_log.md"),
    expected_state_delta={"current_phase": "revise"},
    expected_history_entry="revise_completed",
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={"description": "Revise → Critique boundary: revision complete, loop back"},
)

# ── S3 tiebreaker/replan boundary contracts ────────────────────────────────

researcher_to_challenger = BoundaryContract(
    boundary_id="tiebreaker_researcher_to_challenger",
    workflow_id="megaplan-review",
    row_id=S3_TIEBREAKER_RESEARCHER_ROW_ID,
    phase=BoundaryPhase.TIEBREAKER_RESEARCHER,
    required_artifacts=("research_findings.json",),
    expected_state_delta={"current_phase": "tiebreaker_researcher"},
    expected_history_entry="tiebreaker_researcher_completed",
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={
        "description": "Tiebreaker Researcher → Challenger boundary: research findings produced",
        "child_trace_path": "tiebreaker/researcher",
    },
)

challenger_to_synthesis = BoundaryContract(
    boundary_id="tiebreaker_challenger_to_synthesis",
    workflow_id="megaplan-review",
    row_id=S3_TIEBREAKER_CHALLENGER_ROW_ID,
    phase=BoundaryPhase.TIEBREAKER_CHALLENGER,
    required_artifacts=("challenge_findings.json",),
    expected_state_delta={"current_phase": "tiebreaker_challenger"},
    expected_history_entry="tiebreaker_challenger_completed",
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={
        "description": "Tiebreaker Challenger → Synthesis boundary: challenge findings produced",
        "child_trace_path": "tiebreaker/challenger",
    },
)

synthesis_to_decision = BoundaryContract(
    boundary_id="tiebreaker_synthesis_to_decision",
    workflow_id="megaplan-review",
    row_id=S3_TIEBREAKER_SYNTHESIS_ROW_ID,
    phase=BoundaryPhase.TIEBREAKER_SYNTHESIS,
    required_artifacts=("tiebreaker_payload.json",),
    expected_state_delta={"current_phase": "tiebreaker_synthesis"},
    expected_history_entry="tiebreaker_synthesis_completed",
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={
        "description": "Tiebreaker Synthesis → Decision boundary: reducer payload produced",
        "child_trace_path": "tiebreaker/synthesis",
        "reducer_promotion": True,
    },
)

decision_to_parent = BoundaryContract(
    boundary_id="tiebreaker_decision_to_parent",
    workflow_id="megaplan-review",
    row_id=S3_TIEBREAKER_DECISION_ROW_ID,
    phase=BoundaryPhase.TIEBREAKER_DECISION,
    required_artifacts=("tiebreaker_decisions.json",),
    expected_state_delta={"current_phase": "tiebreaker_decision"},
    expected_history_entry="tiebreaker_decision_produced",
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={
        "description": "Tiebreaker Decision → Parent Rejoin boundary: decision emitted, parent resumes",
        "child_trace_path": "tiebreaker/decision",
        "parent_rejoin_promotion": True,
        "decision_outcomes": ("proceed", "iterate", "escalate"),
    },
)

replan_authority = BoundaryContract(
    boundary_id="replan_authority",
    workflow_id="megaplan-review",
    row_id=S3_REPLAN_AUTHORITY_ROW_ID,
    phase=BoundaryPhase.REPLAN_AUTHORITY,
    required_artifacts=("replan_decision.json",),
    expected_state_delta={"replan_triggered": True},
    expected_history_entry="replan_authorized",
    phase_result_required=True,
    receipt_required=False,
    authority_required=True,
    details={
        "description": "Replan Authority boundary: replan decision authorized with evidence",
    },
)

parent_rejoin_promotion = BoundaryContract(
    boundary_id="parent_rejoin_promotion",
    workflow_id="megaplan-review",
    row_id=S3_PARENT_REJOIN_ROW_ID,
    phase=BoundaryPhase.PARENT_REJOIN,
    required_artifacts=(),
    expected_state_delta={"parent_rejoined": True},
    expected_history_entry="parent_rejoin_completed",
    phase_result_required=False,
    receipt_required=True,
    authority_required=False,
    details={
        "description": "Parent Rejoin Promotion boundary: parent workflow resumes after tiebreaker decision",
    },
)

# ── S4 execute boundary contracts ──────────────────────────────────────────

execute_approval = BoundaryContract(
    boundary_id="execute_approval",
    workflow_id="megaplan-review",
    row_id=S4_EXECUTE_ROW_ID,
    phase=BoundaryPhase.EXECUTE,
    required_artifacts=("approval_record.json",),
    expected_state_delta={"current_phase": "execute", "approval_gate": "cleared"},
    expected_history_entry="execute_approval_cleared",
    phase_result_required=True,
    receipt_required=True,
    authority_required=True,
    details={
        "description": (
            "Execute approval gate: destructive confirmation and operator "
            "approval cleared — proceed to batch execution"
        ),
        "approval_scope": "execute:approval-approved",
        "branch_ref": "execute:approval-approved",
    },
)

execute_approval_denial = BoundaryContract(
    boundary_id="execute_approval_denial",
    workflow_id="megaplan-review",
    row_id=S4_EXECUTE_ROW_ID,
    phase=BoundaryPhase.EXECUTE,
    required_artifacts=(),
    expected_state_delta={"current_phase": "execute", "approval_gate": "denied"},
    expected_history_entry="execute_approval_denied",
    phase_result_required=False,
    receipt_required=True,
    authority_required=False,
    details={
        "description": (
            "Execute approval denial: destructive confirmation or operator "
            "approval missing — halt before batch execution"
        ),
        "approval_scope": "denied",
        "branch_ref": "execute:approval-denied",
    },
)

execute_batch_checkpoint = BoundaryContract(
    boundary_id="execute_batch_checkpoint",
    workflow_id="megaplan-review",
    row_id=S4_EXECUTE_ROW_ID,
    phase=BoundaryPhase.EXECUTE,
    required_artifacts=("batch_checkpoint.json",),
    expected_state_delta={"current_phase": "execute", "batch_stage": "checkpoint"},
    expected_history_entry="execute_batch_checkpoint",
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={
        "description": (
            "Execute batch checkpoint: one batch completed successfully; "
            "additional batches remain for continuation"
        ),
        "batch_index": 0,
        "task_ids": (),
        "branch_ref": "execute:batch-continuation",
    },
)

execute_partial_failure = BoundaryContract(
    boundary_id="execute_partial_failure",
    workflow_id="megaplan-review",
    row_id=S4_EXECUTE_ROW_ID,
    phase=BoundaryPhase.EXECUTE,
    required_artifacts=("blocked_batch_report.json",),
    expected_state_delta={"current_phase": "execute", "batch_stage": "partial_failure"},
    expected_history_entry="execute_partial_failure",
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={
        "description": (
            "Execute partial failure: a batch was blocked by quality gates — "
            "route to override for recovery"
        ),
        "batch_index": 0,
        "task_ids": (),
        "branch_ref": "execute:blocked-recovery",
    },
)

execute_blocked_anchor = BoundaryContract(
    boundary_id="execute_blocked_anchor",
    workflow_id="megaplan-review",
    row_id=S4_EXECUTE_ROW_ID,
    phase=BoundaryPhase.EXECUTE,
    required_artifacts=("retry_decision.json",),
    expected_state_delta={"current_phase": "execute", "retry_stage": "blocked_anchor"},
    expected_history_entry="execute_blocked_anchor",
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={
        "description": (
            "Execute blocked anchor: worker/transient timeout within retry "
            "budget — retry the batch or escalate to override"
        ),
        "retry_anchor": True,
        "branch_ref": "execute:timeout-retry",
    },
)

execute_resume_anchor = BoundaryContract(
    boundary_id="execute_resume_anchor",
    workflow_id="megaplan-review",
    row_id=S4_EXECUTE_ROW_ID,
    phase=BoundaryPhase.EXECUTE,
    required_artifacts=("fresh_session_request.json",),
    expected_state_delta={"current_phase": "execute", "retry_stage": "resume_anchor"},
    expected_history_entry="execute_resume_anchor",
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={
        "description": (
            "Execute resume anchor: retry requires a fresh worker session — "
            "force new execute session"
        ),
        "retry_anchor": True,
        "fresh_session": True,
        "branch_ref": "execute:timeout-retry-fresh",
    },
)

execute_aggregate_promotion = BoundaryContract(
    boundary_id="execute_aggregate_promotion",
    workflow_id="megaplan-review",
    row_id=S4_EXECUTE_ROW_ID,
    phase=BoundaryPhase.EXECUTE,
    required_artifacts=("execute_payload.json",),
    expected_state_delta={"current_phase": "execute", "aggregation_stage": "promoted"},
    expected_history_entry="execute_aggregate_promotion",
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={
        "description": (
            "Execute aggregate promotion: every batch payload aggregated into "
            "a single execute_payload — promoted to review fan-in as items source"
        ),
        "reducer_promotion": True,
        "child_trace_path": "execute/aggregate",
        "branch_ref": "execute:aggregate-promotion",
    },
)

execute_no_review_terminal = BoundaryContract(
    boundary_id="execute_no_review_terminal",
    workflow_id="megaplan-review",
    row_id=S4_EXECUTE_ROW_ID,
    phase=BoundaryPhase.EXECUTE,
    required_artifacts=(),
    expected_state_delta={"current_phase": "execute", "terminal_stage": "no_review"},
    expected_history_entry="execute_no_review_terminal",
    phase_result_required=False,
    receipt_required=True,
    authority_required=False,
    details={
        "description": (
            "Execute no-review terminal: robustness skips review (bare or "
            "light without deferred must criteria) — terminate directly or "
            "await human verification"
        ),
        "terminal_outcomes": ("done", "awaiting_human_verify"),
        "branch_ref": "execute:no-review-terminal",
    },
)

# ── S5 review/finalize boundary contracts ──────────────────────────────────

review_child_outputs = BoundaryContract(
    boundary_id="review_child_outputs",
    workflow_id="megaplan-review",
    row_id=S5_REVIEW_CHILD_OUTPUTS_ROW_ID,
    required_artifacts=("review.json",),
    expected_state_delta={"current_phase": "review"},
    expected_history_entry="review_child_outputs_recorded",
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={
        "description": (
            "Review child outputs boundary: review fanout children produced "
            "durable outputs for the visible review fan-in reducer."
        ),
        "child_trace_template": "review/{item_id}",
        "fan_in_ref": "review-fan-in",
        "evidence_surface_ref": "REVIEW_POLICY.metadata.route_surface.fan_in_contract",
    },
)

review_reducer_promotion = BoundaryContract(
    boundary_id="review_reducer_promotion",
    workflow_id="megaplan-review",
    row_id=S5_REVIEW_REDUCER_PROMOTION_ROW_ID,
    required_artifacts=("review.json",),
    expected_state_delta={"current_phase": "review"},
    expected_history_entry="review_reducer_promoted",
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={
        "description": (
            "Review reducer promotion boundary: the authored review fan-in "
            "promoted child outputs into the canonical review payload."
        ),
        "reducer_promotion": True,
        "effect_id": "artifact.review.output",
        "artifact_policy_ref": "megaplan:artifact-contract",
        "reducer_ref": "SOURCE_REVIEW",
    },
)

review_rework_effects = BoundaryContract(
    boundary_id="review_rework_effects",
    workflow_id="megaplan-review",
    row_id=S5_REVIEW_REWORK_EFFECTS_ROW_ID,
    required_artifacts=("review.json",),
    expected_state_delta={"current_phase": "review"},
    expected_history_entry="review_rework_projected",
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={
        "description": (
            "Review rework effects boundary: a review-directed rework cycle "
            "projects durable re-execute intent without privately routing it."
        ),
        "effect_kind": "review_rework_cycle",
        "fresh_execute_session": True,
        "evidence_surface_ref": "REVIEW_POLICY.metadata.route_surface.rework_cycle",
        "projection_state_ref": "finalized",
    },
)

review_cap_authority = BoundaryContract(
    boundary_id="review_cap_authority",
    workflow_id="megaplan-review",
    row_id=S5_REVIEW_CAP_AUTHORITY_ROW_ID,
    required_artifacts=("review.json",),
    expected_state_delta={"current_phase": "review"},
    expected_history_entry="review_cap_authorized",
    phase_result_required=True,
    receipt_required=True,
    authority_required=True,
    details={
        "description": (
            "Review cap authority boundary: cap exhaustion outcomes carry "
            "explicit authority records instead of handler-owned decisions."
        ),
        "authority_scope": "review.cap_exhausted",
        "authority_outcomes": ("blocked", "force_proceeded"),
        "policy_ref": "megaplan:review",
    },
)

review_human_verification = BoundaryContract(
    boundary_id="review_human_verification",
    workflow_id="megaplan-review",
    row_id=S5_REVIEW_HUMAN_VERIFICATION_ROW_ID,
    required_artifacts=("review.json",),
    expected_state_delta={"current_phase": "review"},
    expected_history_entry="review_human_verification_deferred",
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={
        "description": (
            "Review human verification boundary: deferred-human review "
            "records suspension and resume evidence without becoming a route table."
        ),
        "suspension_route_id": "review:human",
        "resume_policy_ref": "megaplan:suspension",
        "resume_cursor_ref": "cursor:suspension",
        "terminal_state": "awaiting_human_verify",
    },
)

finalize_artifacts = BoundaryContract(
    boundary_id="finalize_artifacts",
    workflow_id="megaplan-review",
    row_id=S5_FINALIZE_ARTIFACTS_ROW_ID,
    required_artifacts=("contract.json", "final.md", "finalize.json"),
    expected_state_delta={"current_phase": "finalize"},
    expected_history_entry="finalize_artifacts_published",
    phase_result_required=True,
    receipt_required=True,
    authority_required=False,
    details={
        "description": (
            "Finalize artifacts boundary: finalize published the canonical "
            "plan artifacts declared by the artifact contract."
        ),
        "effect_id": "artifact.finalize.plan",
        "artifact_policy_ref": "megaplan:artifact-contract",
        "artifact_refs": ("contract.json", "final.md", "finalize.json"),
    },
)

finalize_fallback = BoundaryContract(
    boundary_id="finalize_fallback",
    workflow_id="megaplan-review",
    row_id=S5_FINALIZE_FALLBACK_ROW_ID,
    required_artifacts=("finalize_revise_feedback.json",),
    expected_state_delta={"current_phase": "finalize"},
    expected_history_entry="finalize_revise_fallback",
    phase_result_required=False,
    receipt_required=True,
    authority_required=False,
    details={
        "description": (
            "Finalize fallback boundary: revise fallback evidence is persisted "
            "as a declarative contract rather than a hidden finalize branch."
        ),
        "fallback_reason": "missing_scoped_baseline_test_contract",
        "evidence_surface_ref": (
            "FINALIZE_POLICY.metadata.route_surface.fallback_routes."
            "plan_contract_revise_needed"
        ),
        "projection_ref": "finalize:revise",
    },
)

final_projection = BoundaryContract(
    boundary_id="final_projection",
    workflow_id="megaplan-review",
    row_id=S5_FINAL_PROJECTION_ROW_ID,
    required_artifacts=("finalize.json",),
    expected_state_delta={},
    expected_history_entry="final_projection_recorded",
    phase_result_required=False,
    receipt_required=True,
    authority_required=False,
    details={
        "description": (
            "Final projection boundary: terminal or continuation projection is "
            "visible in finalize policy metadata and durable plan artifacts."
        ),
        "projection_cases": (
            "execute",
            "revise_fallback",
            "no_review_done",
            "no_review_deferred_human",
        ),
        "projected_status_ref": "status:terminal",
        "evidence_surface_ref": "FINALIZE_POLICY.metadata.route_surface.final_projection_routes",
    },
)

# ── S6 override authority boundary contracts ──────────────────────────────

override_abort_authority = BoundaryContract(
    boundary_id="override_abort_authority",
    workflow_id="megaplan-review",
    row_id=S6_OVERRIDE_ABORT_ROW_ID,
    required_artifacts=(),
    expected_state_delta={},
    expected_history_entry=None,
    phase_result_required=False,
    receipt_required=False,
    authority_required=True,
    details={
        "description": (
            "Override abort authority: halting the plan requires a durable "
            "authority record bound to the exact state snapshot being aborted."
        ),
        "authority_transition": "abort",
        "authority_scope": "override.abort",
        "route_signal": "abort",
        "target_ref": "halt",
        "required_evidence_refs": ("state.json",),
        "optional_evidence_refs": ("phase_result.json",),
        "evidence_hashes_ref": "authority_records[].details.evidence_hashes",
        "freshness_token_ref": "state.meta.current_invocation_id",
        "actor_role_ref": "authority_records[].{actor,role}",
        "override_entry_ref": "state.meta.overrides[action=abort]",
    },
)

override_cap_revise_once_authority = BoundaryContract(
    boundary_id="override_cap_revise_once_authority",
    workflow_id="megaplan-review",
    row_id=S6_OVERRIDE_CAP_REVISE_ONCE_ROW_ID,
    required_artifacts=(),
    expected_state_delta={},
    expected_history_entry=None,
    phase_result_required=False,
    receipt_required=False,
    authority_required=True,
    details={
        "description": (
            "Override cap-revise-once authority: granting a single revise "
            "round after a critique-cap park binds the grant to the fenced "
            "state, iteration, and event sequence."
        ),
        "authority_transition": "cap-revise-once",
        "authority_scope": "override.cap_revise_once",
        "route_signal": "cap_revise_once",
        "target_ref": "revise",
        "required_evidence_refs": ("state.json", "events.ndjson"),
        "optional_evidence_refs": ("gate.json", "phase_result.json"),
        "evidence_hashes_ref": "authority_records[].details.evidence_hashes",
        "freshness_token_ref": "state.meta.current_invocation_id",
        "actor_role_ref": "authority_records[].{actor,role}",
        "override_entry_ref": "state.meta.overrides[action=cap-revise-once]",
        "cas_fence_ref": "cap_revise_once_grant.fence",
    },
)

override_force_proceed_authority = BoundaryContract(
    boundary_id="override_force_proceed_authority",
    workflow_id="megaplan-review",
    row_id=S6_OVERRIDE_FORCE_PROCEED_ROW_ID,
    required_artifacts=(),
    expected_state_delta={},
    expected_history_entry=None,
    phase_result_required=False,
    receipt_required=False,
    authority_required=True,
    details={
        "description": (
            "Override force-proceed authority: bypassing a blocking gate or "
            "review verdict must record who accepted the debt against which "
            "durable evidence set."
        ),
        "authority_transition": "force-proceed",
        "authority_scope": "override.force_proceed",
        "route_signal": "force_proceed",
        "route_surface_ref": (
            "arnold_pipelines.megaplan.workflows.override_matrix:"
            "OVERRIDE_ACTION_MATRIX[action=force-proceed]"
        ),
        "required_evidence_refs": ("state.json",),
        "optional_evidence_refs": ("gate.json", "review.json", "phase_result.json"),
        "evidence_hashes_ref": "authority_records[].details.evidence_hashes",
        "freshness_token_ref": "state.meta.current_invocation_id",
        "actor_role_ref": "authority_records[].{actor,role}",
        "override_entry_ref": "state.meta.overrides[action=force-proceed]",
    },
)

override_replan_authority = BoundaryContract(
    boundary_id="override_replan_authority",
    workflow_id="megaplan-review",
    row_id=S6_OVERRIDE_REPLAN_ROW_ID,
    required_artifacts=(),
    expected_state_delta={},
    expected_history_entry=None,
    phase_result_required=False,
    receipt_required=False,
    authority_required=True,
    details={
        "description": (
            "Override replan authority: restarting the planning loop must "
            "record the exact prior state and freshness token that authorized "
            "the re-entry."
        ),
        "authority_transition": "replan",
        "authority_scope": "override.replan",
        "route_signal": "replan",
        "target_ref": "revise",
        "required_evidence_refs": ("state.json",),
        "optional_evidence_refs": ("phase_result.json",),
        "evidence_hashes_ref": "authority_records[].details.evidence_hashes",
        "freshness_token_ref": "state.meta.current_invocation_id",
        "actor_role_ref": "authority_records[].{actor,role}",
        "override_entry_ref": "state.meta.overrides[action=replan]",
    },
)

override_recover_blocked_authority = BoundaryContract(
    boundary_id="override_recover_blocked_authority",
    workflow_id="megaplan-review",
    row_id=S6_OVERRIDE_RECOVER_BLOCKED_ROW_ID,
    required_artifacts=(),
    expected_state_delta={},
    expected_history_entry=None,
    phase_result_required=False,
    receipt_required=False,
    authority_required=True,
    details={
        "description": (
            "Override blocked-recovery authority: resuming from blocked must "
            "bind recovery to the declared resume cursor and blocker evidence."
        ),
        "authority_transition": "recover-blocked",
        "authority_scope": "override.recover_blocked",
        "route_signal": "recover_blocked",
        "policy_route_ref": "megaplan.override.recover_blocked",
        "required_evidence_refs": ("state.json",),
        "optional_evidence_refs": ("phase_result.json",),
        "evidence_hashes_ref": "authority_records[].details.evidence_hashes",
        "freshness_token_ref": "state.meta.current_invocation_id",
        "actor_role_ref": "authority_records[].{actor,role}",
        "override_entry_ref": "state.meta.overrides[action=recover-blocked]",
        "resume_cursor_ref": "state.resume_cursor",
    },
)

override_resume_clarify_authority = BoundaryContract(
    boundary_id="override_resume_clarify_authority",
    workflow_id="megaplan-review",
    row_id=S6_OVERRIDE_RESUME_CLARIFY_ROW_ID,
    required_artifacts=(),
    expected_state_delta={},
    expected_history_entry=None,
    phase_result_required=False,
    receipt_required=False,
    authority_required=True,
    details={
        "description": (
            "Override resume-clarify authority: leaving a clarification halt "
            "must record the answers and freshness token that unlocked plan."
        ),
        "authority_transition": "resume-clarify",
        "authority_scope": "override.resume_clarify",
        "route_signal": "resume_clarify",
        "target_ref": "plan",
        "required_evidence_refs": ("state.json",),
        "optional_evidence_refs": ("phase_result.json",),
        "evidence_hashes_ref": "authority_records[].details.evidence_hashes",
        "freshness_token_ref": "state.meta.current_invocation_id",
        "actor_role_ref": "authority_records[].{actor,role}",
        "override_entry_ref": "state.meta.overrides[action=resume-clarify]",
    },
)

override_adopt_execution_authority = BoundaryContract(
    boundary_id="override_adopt_execution_authority",
    workflow_id="megaplan-review",
    row_id=S6_OVERRIDE_ADOPT_EXECUTION_ROW_ID,
    required_artifacts=(),
    expected_state_delta={},
    expected_history_entry=None,
    phase_result_required=False,
    receipt_required=False,
    authority_required=True,
    details={
        "description": (
            "Override adopt-execution authority: execution adoption must be "
            "anchored to the exact execution/finalize artifacts being adopted."
        ),
        "authority_transition": "adopt-execution",
        "authority_scope": "override.adopt_execution",
        "route_signal": "adopt_execution",
        "target_ref": "review",
        "policy_route_ref": "megaplan.override.adopt_execution",
        "required_evidence_refs": ("state.json", "execution.json", "finalize.json"),
        "optional_evidence_refs": ("execution_audit.json", "final.md"),
        "evidence_hashes_ref": "authority_records[].details.evidence_hashes",
        "freshness_token_ref": "state.meta.current_invocation_id",
        "actor_role_ref": "authority_records[].{actor,role}",
        "override_entry_ref": "state.meta.overrides[action=adopt-execution]",
    },
)

override_suspension_authority = BoundaryContract(
    boundary_id="override_suspension_authority",
    workflow_id="megaplan-review",
    row_id=S6_OVERRIDE_SUSPENSION_ROW_ID,
    required_artifacts=(),
    expected_state_delta={},
    expected_history_entry=None,
    phase_result_required=False,
    receipt_required=False,
    authority_required=True,
    details={
        "description": (
            "Override suspension authority: waiver or deferred-human "
            "suspension must carry durable authority evidence separate from "
            "handler-private state changes."
        ),
        "authority_transition": "suspension-waiver",
        "authority_scope": "override.suspension_waiver",
        "policy_ref": "megaplan:suspension",
        "required_evidence_refs": ("state.json", "human_verifications.json"),
        "optional_evidence_refs": ("review.json",),
        "evidence_hashes_ref": "authority_records[].details.evidence_hashes",
        "freshness_token_ref": "state.meta.current_invocation_id",
        "actor_role_ref": "authority_records[].{actor,role}",
        "waiver_reason_ref": "authority_records[].waiver_reason",
    },
)

override_human_gate_authority = BoundaryContract(
    boundary_id="override_human_gate_authority",
    workflow_id="megaplan-review",
    row_id=S6_OVERRIDE_HUMAN_GATE_ROW_ID,
    required_artifacts=(),
    expected_state_delta={},
    expected_history_entry=None,
    phase_result_required=False,
    receipt_required=False,
    authority_required=True,
    details={
        "description": (
            "Override human-gate authority: protected actions and explicit "
            "human gates must record actor, role, scope, and fresh evidence."
        ),
        "authority_transition": "human-gate",
        "authority_scope": "override.human_gate",
        "required_evidence_refs": ("state.json", "approval_record.json"),
        "optional_evidence_refs": ("human_verifications.json",),
        "evidence_hashes_ref": "authority_records[].details.evidence_hashes",
        "freshness_token_ref": "state.meta.current_invocation_id",
        "actor_role_ref": "authority_records[].{actor,role}",
        "approval_scope_ref": "execute:approval-approved",
        "suspension_policy_ref": "megaplan:suspension",
    },
)

override_cutover_authority = BoundaryContract(
    boundary_id="override_cutover_authority",
    workflow_id="megaplan-review",
    row_id=S6_OVERRIDE_CUTOVER_ROW_ID,
    required_artifacts=(),
    expected_state_delta={},
    expected_history_entry=None,
    phase_result_required=False,
    receipt_required=False,
    authority_required=True,
    details={
        "description": (
            "Override cutover authority: the legacy-to-canonical cutover "
            "requires COMBINED authority (human-gate operator approval AND "
            "lifecycle mutation authority via repair_queue) before any "
            "cutover orchestration runs."
        ),
        "authority_transition": "cutover",
        "authority_scope": "override.cutover",
        "route_signal": "cutover",
        "target_ref": "cutover",
        "required_evidence_refs": ("state.json",),
        "actor_role_ref": "authority_records[].{actor,role}",
        "evidence_hashes_ref": "authority_records[].details.evidence_hashes",
        "freshness_token_ref": "state.meta.current_invocation_id",
    },
)

override_reconcile_plan_ledger_authority = BoundaryContract(
    boundary_id="override_reconcile_plan_ledger_authority",
    workflow_id="megaplan-review",
    row_id=S6_OVERRIDE_RECONCILE_PLAN_LEDGER_ROW_ID,
    required_artifacts=(),
    expected_state_delta={},
    expected_history_entry=None,
    phase_result_required=False,
    receipt_required=False,
    authority_required=True,
    details={
        "description": (
            "Override reconcile-plan-ledger authority: append-only ledger "
            "repair for a drifted plan version preserves the original "
            "attestation and records the replacement hash + cause + repair "
            "ref under an audited authority record."
        ),
        "authority_transition": "reconcile-plan-ledger",
        "authority_scope": "override.reconcile_plan_ledger",
        "route_signal": "reconcile_plan_ledger",
        "target_ref": "plan",
        "required_evidence_refs": ("state.json",),
        "actor_role_ref": "authority_records[].{actor,role}",
        "evidence_hashes_ref": "authority_records[].details.evidence_hashes",
        "freshness_token_ref": "state.meta.current_invocation_id",
    },
)


# ── Chain milestone boundary contracts ──────────────────────────────────

chain_milestone_start = BoundaryContract(
    boundary_id="chain_milestone_start",
    workflow_id="megaplan-review",
    row_id=CHAIN_MILESTONE_START_ROW_ID,
    required_artifacts=("milestone_start.json",),
    expected_state_delta={"milestone_stage": "started"},
    expected_history_entry="chain_milestone_started",
    phase_result_required=True,
    receipt_required=True,
    authority_required=True,
    details={
        "description": "Chain milestone start boundary: durable start-of-milestone evidence.",
        "milestone_kind": "chain_milestone",
        "chain_ref": "chain:milestone",
        "profile_kind": "chain_milestone",
        "template_ref": "template.chain_milestone",
    },
)

chain_milestone_completion = BoundaryContract(
    boundary_id="chain_milestone_completion",
    workflow_id="megaplan-review",
    row_id=CHAIN_MILESTONE_COMPLETION_ROW_ID,
    required_artifacts=("milestone_complete.json",),
    expected_state_delta={"milestone_stage": "completed"},
    expected_history_entry="chain_milestone_completed",
    phase_result_required=True,
    receipt_required=True,
    authority_required=True,
    details={
        "description": "Chain milestone completion boundary: durable end-of-milestone evidence.",
        "milestone_kind": "chain_milestone",
        "chain_ref": "chain:milestone",
        "profile_kind": "chain_milestone",
        "template_ref": "template.chain_milestone",
    },
)

chain_complete = BoundaryContract(
    boundary_id="chain_complete",
    workflow_id="megaplan-review",
    row_id=CHAIN_COMPLETE_ROW_ID,
    required_artifacts=("chain_complete.json",),
    expected_state_delta={"chain_stage": "complete"},
    expected_history_entry="chain_completed",
    phase_result_required=True,
    receipt_required=True,
    authority_required=True,
    details={
        "description": "Chain complete boundary: full chain execution finished with durable evidence.",
        "milestone_kind": "chain_complete",
        "chain_ref": "chain:complete",
        "profile_kind": "chain_milestone",
        "template_ref": "template.chain_milestone",
    },
)

# ── PR/CI transition boundary contracts ────────────────────────────────

pr_ready = BoundaryContract(
    boundary_id="pr_ready",
    workflow_id="megaplan-review",
    row_id=PR_READY_ROW_ID,
    required_artifacts=("pr_ready.json",),
    expected_state_delta={"pr_stage": "ready"},
    expected_history_entry="pr_ready",
    receipt_required=True,
    authority_required=True,
    details={
        "description": "PR ready boundary: PR branch is ready for merge, CI checks passed.",
        "pr_kind": "pr_ready",
        "branch_ref": "pr:ready",
        "profile_kind": "pr_transition",
        "template_ref": "template.pr_transition",
    },
)

pr_merged = BoundaryContract(
    boundary_id="pr_merged",
    workflow_id="megaplan-review",
    row_id=PR_MERGED_ROW_ID,
    required_artifacts=("pr_merged.json",),
    expected_state_delta={"pr_stage": "merged"},
    expected_history_entry="pr_merged",
    receipt_required=True,
    authority_required=True,
    details={
        "description": "PR merged boundary: PR successfully merged with tip containment evidence.",
        "pr_kind": "pr_merged",
        "branch_ref": "pr:merged",
        "profile_kind": "pr_transition",
        "template_ref": "template.pr_transition",
    },
)

# ── Repair verdict boundary contracts ───────────────────────────────────

cloud_repair_dispatch = BoundaryContract(
    boundary_id="cloud_repair_dispatch",
    workflow_id="megaplan-review",
    row_id=REPAIR_CLOUD_DISPATCH_ROW_ID,
    required_artifacts=("repair_dispatch.json",),
    expected_state_delta={"repair_stage": "dispatched"},
    phase_result_required=True,
    receipt_required=True,
    authority_required=True,
    details={
        "description": "Cloud repair dispatch boundary: repair dispatched from cloud to worker.",
        "verdict_kind": "cloud_repair_dispatch",
        "repair_ref": "repair:cloud_dispatch",
        "profile_kind": "repair_verdict",
        "template_ref": "template.repair_verdict",
    },
)

ordinary_repair_completion = BoundaryContract(
    boundary_id="ordinary_repair_completion",
    workflow_id="megaplan-review",
    row_id=REPAIR_ORDINARY_COMPLETE_ROW_ID,
    required_artifacts=("repair_verdict.json",),
    expected_state_delta={"repair_stage": "completed", "verdict": "cleared"},
    phase_result_required=True,
    receipt_required=True,
    authority_required=True,
    details={
        "description": (
            "Ordinary repair completion boundary: cleared/no-fix/escalation "
            "verdict tied to original finding with structured evidence."
        ),
        "verdict_kind": "ordinary_repair",
        "repair_ref": "repair:ordinary",
        "profile_kind": "repair_verdict",
        "template_ref": "template.repair_verdict",
    },
)

meta_repair_completion = BoundaryContract(
    boundary_id="meta_repair_completion",
    workflow_id="megaplan-review",
    row_id=REPAIR_META_COMPLETE_ROW_ID,
    required_artifacts=("meta_repair_verdict.json",),
    expected_state_delta={"repair_stage": "completed", "meta_verdict": "cleared"},
    phase_result_required=True,
    receipt_required=True,
    authority_required=True,
    details={
        "description": (
            "Meta-repair completion boundary: meta-level repair verdict "
            "(e.g. self-repair on repair loop) tied to original finding."
        ),
        "verdict_kind": "meta_repair",
        "repair_ref": "repair:meta",
        "profile_kind": "repair_verdict",
        "template_ref": "template.repair_verdict",
    },
)

# ── Auditor completion boundary contracts ───────────────────────────────

auditor_6h_completion = BoundaryContract(
    boundary_id="auditor_6h_completion",
    workflow_id="megaplan-review",
    row_id=AUDITOR_6H_COMPLETE_ROW_ID,
    required_artifacts=("auditor_verdict.json",),
    phase_result_required=True,
    receipt_required=True,
    authority_required=True,
    details={
        "description": (
            "Auditor reconciliation completion boundary: auditor produces "
            "verdict set within the next-three-hour reconciliation window "
            "(six-hour identifiers retained as compatibility-only "
            "exact-version evidence)."
        ),
        "auditor_kind": "six_hour_auditor",
        "time_window": NEXT_THREE_HOUR_RECONCILIATION,
        "reconciliation_interval": NEXT_THREE_HOUR_RECONCILIATION,
        "legacy_six_hour_names_compatibility_only": (
            LEGACY_SIX_HOUR_NAMES_COMPATIBILITY_ONLY
        ),
        "verdict_refs": ("auditor_verdict.json",),
        "profile_kind": "auditor_completion",
        "template_ref": "template.auditor_completion",
    },
)

# ── Cloud custody classification boundary contracts ─────────────────────

cloud_custody_managed_running = BoundaryContract(
    boundary_id="cloud_custody_managed_running",
    workflow_id="megaplan-review",
    row_id=CUSTODY_MANAGED_RUNNING_ROW_ID,
    required_artifacts=("custody_snapshot.json",),
    authority_required=True,
    details={
        "description": (
            "Managed-running custody classification: cloud-managed process "
            "confirmed running with fresh session markers."
        ),
        "custody_scope": "cloud:custody",
        "custody_classification": "managed-running",
        "fresh_session": True,
        "profile_kind": "cloud_custody",
        "template_ref": "template.cloud_custody",
    },
)

cloud_custody_complete = BoundaryContract(
    boundary_id="cloud_custody_complete",
    workflow_id="megaplan-review",
    row_id=CUSTODY_COMPLETE_ROW_ID,
    required_artifacts=("custody_snapshot.json",),
    authority_required=True,
    details={
        "description": (
            "Complete custody classification: process completed successfully, "
            "custody evidence is final."
        ),
        "custody_scope": "cloud:custody",
        "custody_classification": "complete",
        "fresh_session": False,
        "profile_kind": "cloud_custody",
        "template_ref": "template.cloud_custody",
    },
)

cloud_custody_unmanaged_running_warning = BoundaryContract(
    boundary_id="cloud_custody_unmanaged_running_warning",
    workflow_id="megaplan-review",
    row_id=CUSTODY_UNMANAGED_WARNING_ROW_ID,
    required_artifacts=("custody_snapshot.json",),
    authority_required=True,
    details={
        "description": (
            "Unmanaged-running-with-warning custody classification: process "
            "is running but not under cloud management — warning-level finding."
        ),
        "custody_scope": "cloud:custody",
        "custody_classification": "unmanaged-running-with-warning",
        "fresh_session": False,
        "profile_kind": "cloud_custody",
        "template_ref": "template.cloud_custody",
    },
)

cloud_custody_blocked_relaunch_failure = BoundaryContract(
    boundary_id="cloud_custody_blocked_relaunch_failure",
    workflow_id="megaplan-review",
    row_id=CUSTODY_BLOCKED_RELAUNCH_ROW_ID,
    required_artifacts=("custody_snapshot.json",),
    authority_required=True,
    details={
        "description": (
            "Blocked relaunch failure custody classification: worker/process "
            "is blocked and relaunch attempts have failed."
        ),
        "custody_scope": "cloud:custody",
        "custody_classification": "blocked-relaunch-failure",
        "fresh_session": False,
        "profile_kind": "cloud_custody",
        "template_ref": "template.cloud_custody",
    },
)

cloud_custody_escalated_repeated_unchanged = BoundaryContract(
    boundary_id="cloud_custody_escalated_repeated_unchanged",
    workflow_id="megaplan-review",
    row_id=CUSTODY_ESCALATED_UNCHANGED_ROW_ID,
    required_artifacts=("custody_snapshot.json",),
    authority_required=True,
    details={
        "description": (
            "Escalated repeated unchanged custody classification: repeated "
            "findings with no change — escalated for human intervention."
        ),
        "custody_scope": "cloud:custody",
        "custody_classification": "escalated-repeated-unchanged-findings",
        "fresh_session": False,
        "profile_kind": "cloud_custody",
        "template_ref": "template.cloud_custody",
    },
)

# ── Phase-family coverage matrix ───────────────────────────────────────────
# Each entry maps a phase-family label to one or more ``boundary_id`` values
# that are expected to cover it in :data:`BOUNDARY_CONTRACTS`.  A family is
# *covered* when every listed contract exists in the registry OR when the
# family has a tested exemption in :data:`EXEMPTION_REGISTRY`.
#
# This matrix is declarative and read-only — it documents coverage expectations
# so that semantic-health checks and downstream evaluators can detect gaps
# without hunting through the registry by hand.

PHASE_FAMILY_COVERAGE_MATRIX: dict[str, tuple[str, ...]] = {
    # ── S2 front-half ─────────────────────────────────────────────────
    "s2_prep": ("prep_to_plan",),
    "s2_plan": ("plan_to_critique",),
    "s2_critique": ("critique_to_gate",),
    "s2_gate": ("gate_to_revise",),
    "s2_revise": ("revise_to_critique",),
    # ── S3 tiebreaker / replan ─────────────────────────────────────────
    "s3_tiebreaker_researcher": ("tiebreaker_researcher_to_challenger",),
    "s3_tiebreaker_challenger": ("tiebreaker_challenger_to_synthesis",),
    "s3_tiebreaker_synthesis": ("tiebreaker_synthesis_to_decision",),
    "s3_tiebreaker_decision": ("tiebreaker_decision_to_parent",),
    "s3_replan": ("replan_authority",),
    "s3_parent_rejoin": ("parent_rejoin_promotion",),
    # ── S4 execute ─────────────────────────────────────────────────────
    "s4_execute_approval": ("execute_approval", "execute_approval_denial"),
    "s4_execute_checkpoint": (
        "execute_batch_checkpoint",
        "execute_partial_failure",
    ),
    "s4_execute_retry": ("execute_blocked_anchor", "execute_resume_anchor"),
    "s4_execute_promotion": ("execute_aggregate_promotion",),
    "s4_execute_terminal": ("execute_no_review_terminal",),
    # ── S5 review / finalize ───────────────────────────────────────────
    "s5_review_child_outputs": ("review_child_outputs",),
    "s5_review_reducer_promotion": ("review_reducer_promotion",),
    "s5_review_rework_effects": ("review_rework_effects",),
    "s5_review_cap_authority": ("review_cap_authority",),
    "s5_review_human_verification": ("review_human_verification",),
    "s5_finalize_artifacts": ("finalize_artifacts",),
    "s5_finalize_fallback": ("finalize_fallback",),
    "s5_finalize_projection": ("final_projection",),
    # ── S6 override authority ──────────────────────────────────────────
    "s6_override_abort": ("override_abort_authority",),
    "s6_override_force_proceed": ("override_force_proceed_authority",),
    "s6_override_replan": ("override_replan_authority",),
    "s6_override_recover_blocked": ("override_recover_blocked_authority",),
    "s6_override_resume_clarify": ("override_resume_clarify_authority",),
    "s6_override_adopt_execution": ("override_adopt_execution_authority",),
    "s6_override_suspension": ("override_suspension_authority",),
    "s6_override_human_gate": ("override_human_gate_authority",),
    # ── Chain milestone ────────────────────────────────────────────────
    "chain_milestone": (
        "chain_milestone_start",
        "chain_milestone_completion",
    ),
    "chain_complete": ("chain_complete",),
    # ── PR / CI transition ─────────────────────────────────────────────
    "pr_ready": ("pr_ready",),
    "pr_merged": ("pr_merged",),
    # ── Repair verdicts ────────────────────────────────────────────────
    "repair_cloud_dispatch": ("cloud_repair_dispatch",),
    "repair_ordinary_completion": ("ordinary_repair_completion",),
    "repair_meta_completion": ("meta_repair_completion",),
    # ── Auditor ────────────────────────────────────────────────────────
    "auditor_6h_completion": ("auditor_6h_completion",),
    # ── Cloud custody ──────────────────────────────────────────────────
    "custody_managed_running": ("cloud_custody_managed_running",),
    "custody_complete": ("cloud_custody_complete",),
    "custody_unmanaged_warning": ("cloud_custody_unmanaged_running_warning",),
    "custody_blocked_relaunch": ("cloud_custody_blocked_relaunch_failure",),
    "custody_escalated_unchanged": (
        "cloud_custody_escalated_repeated_unchanged",
    ),
}

# ── Exemption registry ─────────────────────────────────────────────────────
# Each exemption documents a phase-family that is intentionally absent from
# :data:`BOUNDARY_CONTRACTS`.  Exemptions are metadata, not hidden comments:
# they are visible to semantic-health checks, tests, and downstream
# evaluators so that coverage gaps are explicit and auditable.
#
# Every entry is a :class:`dict` with the keys:
#
# * ``family`` — the phase-family label (must match a key in
#   :data:`PHASE_FAMILY_COVERAGE_MATRIX`).
# * ``reason`` — a human-readable justification for the exemption.
# * ``reference`` — a pointer to the decision artifact (e.g. Epic North Star
#   item, sprint OUT section, design doc anchor).

EXEMPTION_REGISTRY: tuple[dict[str, str], ...] = (
    # No exemptions at this time — every covered family has a contract.
    # Exemptions are added here when a family is intentionally uncovered
    # (e.g. a future family that has not yet been implemented, or a
    # family whose coverage is deferred by an explicit Epic decision).
)

# ── Coverage matrix helpers ────────────────────────────────────────────────


def _resolve_covered_families() -> dict[str, tuple[str, ...]]:
    """Return a copy of :data:`PHASE_FAMILY_COVERAGE_MATRIX`.

    This indirection exists so that future versions can merge additional
    coverage sources without changing the public API shape.
    """
    return dict(PHASE_FAMILY_COVERAGE_MATRIX)


def _resolve_exemptions_by_family() -> dict[str, dict[str, str]]:
    """Return exemptions keyed by ``family`` for O(1) lookup."""
    return {entry["family"]: entry for entry in EXEMPTION_REGISTRY}


def families_without_coverage() -> tuple[dict[str, object], ...]:
    """Return every covered family that lacks a contract *and* an exemption.

    Each returned dict has ``family``, ``expected_contracts`` (the IDs the
    matrix declares), ``missing_contracts`` (those not found in the
    registry), and ``exempted`` (whether an exemption exists).

    A family with an exemption is *never* reported as uncovered, even if
    its declared contracts are missing.
    """
    exemptions = _resolve_exemptions_by_family()
    covered = _resolve_covered_families()
    registry_ids = {c.boundary_id for c in BOUNDARY_CONTRACTS}

    gaps: list[dict[str, object]] = []
    for family, expected_ids in covered.items():
        if family in exemptions:
            continue
        missing = [cid for cid in expected_ids if cid not in registry_ids]
        if missing:
            gaps.append(
                {
                    "family": family,
                    "expected_contracts": expected_ids,
                    "missing_contracts": tuple(missing),
                    "exempted": False,
                }
            )
    return tuple(gaps)


# ── Registry ───────────────────────────────────────────────────────────────

BOUNDARY_CONTRACTS: tuple[BoundaryContract, ...] = (
    prep_to_plan,
    plan_to_critique,
    critique_to_gate,
    gate_to_revise,
    revise_to_critique,
    researcher_to_challenger,
    challenger_to_synthesis,
    synthesis_to_decision,
    decision_to_parent,
    replan_authority,
    parent_rejoin_promotion,
    execute_approval,
    execute_approval_denial,
    execute_batch_checkpoint,
    execute_partial_failure,
    execute_blocked_anchor,
    execute_resume_anchor,
    execute_aggregate_promotion,
    execute_no_review_terminal,
    review_child_outputs,
    review_reducer_promotion,
    review_rework_effects,
    review_cap_authority,
    review_human_verification,
    finalize_artifacts,
    finalize_fallback,
    final_projection,
    override_abort_authority,
    override_cap_revise_once_authority,
    override_force_proceed_authority,
    override_replan_authority,
    override_recover_blocked_authority,
    override_resume_clarify_authority,
    override_adopt_execution_authority,
    override_suspension_authority,
    override_human_gate_authority,
    override_cutover_authority,
    override_reconcile_plan_ledger_authority,
    chain_milestone_start,
    chain_milestone_completion,
    chain_complete,
    pr_ready,
    pr_merged,
    cloud_repair_dispatch,
    ordinary_repair_completion,
    meta_repair_completion,
    auditor_6h_completion,
    cloud_custody_managed_running,
    cloud_custody_complete,
    cloud_custody_unmanaged_running_warning,
    cloud_custody_blocked_relaunch_failure,
    cloud_custody_escalated_repeated_unchanged,
)

OVERRIDE_AUTHORITY_CONTRACTS: tuple[BoundaryContract, ...] = (
    override_abort_authority,
    override_cap_revise_once_authority,
    override_force_proceed_authority,
    override_replan_authority,
    override_recover_blocked_authority,
    override_resume_clarify_authority,
    override_adopt_execution_authority,
    override_suspension_authority,
    override_human_gate_authority,
    override_cutover_authority,
    override_reconcile_plan_ledger_authority,
)

BOUNDARY_CONTRACTS_BY_ID: dict[str, BoundaryContract] = {
    c.boundary_id: c for c in BOUNDARY_CONTRACTS
}

# Ensure the registry has exactly fifty-two entries with no duplicates.
assert len(BOUNDARY_CONTRACTS) == 52, (
    f"BOUNDARY_CONTRACTS must have exactly 52 entries, got {len(BOUNDARY_CONTRACTS)}"
)
assert len(BOUNDARY_CONTRACTS_BY_ID) == 52, (
    "BOUNDARY_CONTRACTS_BY_ID must have exactly 52 entries "
    "(duplicate boundary_id detected)"
)

# ── Provider lookup helpers ────────────────────────────────────────────────
# Thin wrappers over the existing registry dicts so callers get consistent
# optional-lookup semantics without importing internal registry shapes.


def get_contract_by_id(contract_id: str) -> BoundaryContract | None:
    """Look up a :class:`BoundaryContract` by its ``boundary_id``.

    Returns ``None`` when *contract_id* is not a key in
    :data:`BOUNDARY_CONTRACTS_BY_ID`.  This preserves the existing
    registry structure while giving callers a named, documented
    entrance point that does not need to know about the internal dict.
    """
    return BOUNDARY_CONTRACTS_BY_ID.get(contract_id)


def get_template_by_id(template_id: str) -> BoundaryContract | None:
    """Look up a typed boundary template by its ``boundary_id``.

    Templates are stored in :data:`TYPED_BOUNDARY_TEMPLATES_BY_ID`
    and use a ``template.*`` namespace prefix.  Returns ``None``
    when no match is found.
    """
    return TYPED_BOUNDARY_TEMPLATES_BY_ID.get(template_id)


def get_profile_by_kind(kind: str) -> frozenset[str] | None:
    """Look up a required-field profile by its kind label.

    Checks both generic (from :mod:`arnold.workflow.boundary_templates`)
    and adapter-specific profiles.  Returns ``None`` when *kind* is not
    a registered profile.
    """
    # Try combined registry first, then adapter-only
    profile = REQUIRED_FIELD_PROFILES_BY_KIND.get(kind)
    if profile is not None:
        return profile
    return ADAPTER_REQUIRED_FIELD_PROFILES_BY_KIND.get(kind)


def list_template_ids() -> tuple[str, ...]:
    """Return all registered template ``boundary_id`` values."""
    return tuple(TYPED_BOUNDARY_TEMPLATES_BY_ID.keys())


def list_profile_kinds() -> tuple[str, ...]:
    """Return all registered profile kind labels (generic + adapter)."""
    return tuple(REQUIRED_FIELD_PROFILES_BY_KIND.keys())


# ── Boundary conformance bridge ────────────────────────────────────────────
# Delegates to the generic check_contract_conformance from boundary_templates
# for generic kinds, and falls back to adapter-specific profile checking for
# Megaplan-only kinds.  Physical/external evidence and partial acceptance
# remain in adapter details — they are not validated through the generic path.


def check_contract_conformance(
    contract: BoundaryContract,
    kind: BoundaryTemplateKind | AdapterTemplateKind | str,
) -> tuple[str, ...]:
    """Check which required fields are missing from *contract* for *kind*.

    For generic :class:`BoundaryTemplateKind` values this delegates to
    :func:`arnold.workflow.boundary_templates.check_contract_conformance`.
    For adapter-specific :class:`AdapterTemplateKind` values it uses the
    adapter profile registry.

    Args:
        contract: The concrete :class:`BoundaryContract` to check.
        kind: A :class:`BoundaryTemplateKind`, :class:`AdapterTemplateKind`,
              or string kind label.

    Returns:
        Tuple of missing field paths (empty if fully conformant).
    """
    kind_str = kind.value if hasattr(kind, "value") else kind

    # Try generic path first
    try:
        return _generic_check_contract_conformance(contract, kind_str)
    except (KeyError, ValueError):
        pass

    # Fall back to adapter-specific
    profile = ADAPTER_REQUIRED_FIELD_PROFILES_BY_KIND.get(kind_str)
    if profile is None:
        raise KeyError(f"Unknown template kind: {kind_str!r}")

    # Use local contract_satisfies_profile for adapter-specific kinds
    _, missing = contract_satisfies_profile(contract, profile)
    return missing


# ── Structural diff helpers ────────────────────────────────────────────────


def diff_contracts(
    a: BoundaryContract,
    b: BoundaryContract,
) -> dict[str, object]:
    """Return a structural diff between two :class:`BoundaryContract` instances.

    The returned dict has these keys:

    * ``matching``: :class:`bool` — ``True`` when the two contracts are
      structurally identical.
    * ``field_diffs``: :class:`dict` — maps field name to ``(old_value, new_value)``
      for every top-level contract field that differs.
    * ``detail_diffs``: :class:`dict` — maps ``details.<key>`` to
      ``(old_value, new_value)`` for every nested detail that differs.
    * ``artifact_diffs``: :class:`dict` — ``{'only_in_a': [...], 'only_in_b': [...]}``
      when ``required_artifacts`` differ (absent when identical).

    Enum values are converted to their ``.value`` strings for readability.
    Empty :class:`MappingProxyType` details are compared as ``{}``.
    """
    field_diffs: dict[str, tuple[object, object]] = {}

    # ── top-level fields ───────────────────────────────────────────────
    _comparable = (
        "boundary_id",
        "workflow_id",
        "row_id",
        "phase",
        "expected_state_delta",
        "expected_history_entry",
        "phase_result_required",
        "receipt_required",
        "authority_required",
        "contract_version",
    )
    for field_name in _comparable:
        old_val = getattr(a, field_name)
        new_val = getattr(b, field_name)
        # Normalize enum → str for comparison and readability
        if hasattr(old_val, "value"):
            old_val = old_val.value
        if hasattr(new_val, "value"):
            new_val = new_val.value
        if old_val != new_val:
            field_diffs[field_name] = (old_val, new_val)

    # ── required_artifacts ─────────────────────────────────────────────
    artifacts_a = set(a.required_artifacts)
    artifacts_b = set(b.required_artifacts)
    artifact_diffs: dict[str, tuple[str, ...]] | None = None
    if artifacts_a != artifacts_b:
        artifact_diffs = {
            "only_in_a": tuple(sorted(artifacts_a - artifacts_b)),
            "only_in_b": tuple(sorted(artifacts_b - artifacts_a)),
        }

    # ── details ────────────────────────────────────────────────────────
    details_a = dict(a.details)
    details_b = dict(b.details)
    detail_diffs: dict[str, tuple[object, object]] = {}
    all_detail_keys = sorted(set(details_a) | set(details_b))
    for key in all_detail_keys:
        old_val = details_a.get(key)
        new_val = details_b.get(key)
        if old_val != new_val:
            detail_diffs[f"details.{key}"] = (old_val, new_val)

    matching = not field_diffs and not detail_diffs and artifact_diffs is None

    result: dict[str, object] = {
        "matching": matching,
        "field_diffs": field_diffs,
        "detail_diffs": detail_diffs,
    }
    if artifact_diffs is not None:
        result["artifact_diffs"] = artifact_diffs
    return result


def contract_satisfies_profile(
    contract: BoundaryContract,
    profile: frozenset[str],
) -> tuple[bool, tuple[str, ...]]:
    """Check whether *contract* satisfies every key in *profile*.

    Returns ``(satisfied, missing_keys)``.  A key is considered missing
    when:

    * Top-level fields (e.g. ``"boundary_id"``, ``"phase"``): the
      attribute is ``None``, ``False``, or an empty tuple / mapping.
    * ``"details.<key>"`` entries: the nested key is absent, ``None``,
      or an empty string / tuple.

    Non-string scalars (e.g. ``True`` for ``phase_result_required``) are
    treated as satisfied even though they are not ``str``-typed.
    """
    missing: list[str] = []
    for key in sorted(profile):
        if key.startswith("details."):
            detail_key = key[len("details."):]
            value = contract.details.get(detail_key)
            if _is_empty_value(value):
                missing.append(key)
        else:
            try:
                value = getattr(contract, key)
            except AttributeError:
                missing.append(key)
                continue
            if _is_empty_value(value):
                missing.append(key)
    satisfied = len(missing) == 0
    return satisfied, tuple(missing)


def _is_empty_value(value: object) -> bool:
    """Return ``True`` when *value* is semantically empty."""
    if value is None:
        return True
    if isinstance(value, bool):
        # Booleans are never "empty" — a required bool is always a value.
        return False
    if isinstance(value, str) and not value:
        return True
    if isinstance(value, (tuple, list)) and len(value) == 0:  # type: ignore[arg-type]
        return True
    if isinstance(value, dict) and len(value) == 0:
        return True
    return False


# ── Step 96 (T46): WBC static/runtime equality gate ────────────────────────
# WBC rows are exact-version evidence only. Equality among generated call
# sites, runtime traces, and exact-version WBC rows is proven ONLY after
# prerequisite readiness (Steps 2, 50, 92, 95). Incomplete prerequisites
# produce only ``m11_prerequisite_incomplete`` — no positive equality is ever
# claimed from a label, liveness, a WBC receipt, or a rebuildable projection.
# This is aggregation/decision data: it never writes authority.


#: Typed outcome emitted when M11 prerequisites are incomplete.
M11_PREREQUISITE_INCOMPLETE = "m11_prerequisite_incomplete"
#: Typed outcome emitted when static/runtime/WBC equality is proven.
WBC_STATIC_RUNTIME_EQUAL = "equal"
#: Typed outcome emitted when the three sources disagree.
WBC_STATIC_RUNTIME_MISMATCH = "mismatch"


@dataclass(frozen=True)
class WbcStaticRuntimeEqualityResult:
    """Step 96: typed WBC static/runtime equality outcome.

    Pure decision data: it is never an authority writer. ``equal`` is a derived
    set comparison over generated call sites, runtime traces, and exact-version
    WBC rows; it is never satisfied by a label, liveness, a WBC receipt, or a
    rebuildable projection alone. The ``outcome`` is one of ``"equal"``,
    ``"mismatch"``, or ``m11_prerequisite_incomplete``.
    """

    outcome: str
    equal: bool
    missing_runtime: tuple[str, ...]
    extra_runtime: tuple[str, ...]
    wbc_not_in_static: tuple[str, ...]
    static_not_in_wbc: tuple[str, ...]
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "outcome": self.outcome,
            "equal": self.equal,
            "missing_runtime": list(self.missing_runtime),
            "extra_runtime": list(self.extra_runtime),
            "wbc_not_in_static": list(self.wbc_not_in_static),
            "static_not_in_wbc": list(self.static_not_in_wbc),
            "reason": self.reason,
        }


def check_wbc_static_runtime_equality(
    *,
    generated_call_sites: Collection[str],
    runtime_traces: Collection[str],
    wbc_rows: Collection[str],
    prerequisites_ready: bool,
) -> WbcStaticRuntimeEqualityResult:
    """Require exact equality among generated call sites, runtime traces, and
    exact-version WBC rows — but only after M11 prerequisites are ready.

    Step 96: WBC rows are exact-version evidence only. If prerequisites are not
    ready the ONLY outcome is ``m11_prerequisite_incomplete``; no positive
    equality is claimed even when the three sources happen to agree (fail
    closed). When prerequisites are ready the three sources must agree exactly
    (as sets); otherwise a typed ``mismatch`` outcome enumerates the
    differences. No authority is created from a label, liveness, a WBC receipt,
    or a rebuildable projection.
    """
    static = frozenset(str(s) for s in generated_call_sites)
    runtime = frozenset(str(s) for s in runtime_traces)
    wbc = frozenset(str(s) for s in wbc_rows)

    missing_runtime = tuple(sorted(runtime - static))
    extra_runtime = tuple(sorted(static - runtime))
    wbc_not_in_static = tuple(sorted(wbc - static))
    static_not_in_wbc = tuple(sorted(static - wbc))

    if not prerequisites_ready:
        return WbcStaticRuntimeEqualityResult(
            outcome=M11_PREREQUISITE_INCOMPLETE,
            equal=False,
            missing_runtime=missing_runtime,
            extra_runtime=extra_runtime,
            wbc_not_in_static=wbc_not_in_static,
            static_not_in_wbc=static_not_in_wbc,
            reason=(
                "M11 prerequisites not ready; WBC static/runtime equality is "
                "not proven — m11_prerequisite_incomplete"
            ),
        )

    if (
        not missing_runtime
        and not extra_runtime
        and not wbc_not_in_static
        and not static_not_in_wbc
    ):
        return WbcStaticRuntimeEqualityResult(
            outcome=WBC_STATIC_RUNTIME_EQUAL,
            equal=True,
            missing_runtime=(),
            extra_runtime=(),
            wbc_not_in_static=(),
            static_not_in_wbc=(),
            reason=(
                "generated call sites, runtime traces, and exact-version WBC "
                "rows agree exactly"
            ),
        )

    reasons: list[str] = []
    if missing_runtime:
        reasons.append(f"runtime not generated: {list(missing_runtime)}")
    if extra_runtime:
        reasons.append(f"generated not exercised at runtime: {list(extra_runtime)}")
    if wbc_not_in_static:
        reasons.append(f"WBC rows not in generated: {list(wbc_not_in_static)}")
    if static_not_in_wbc:
        reasons.append(
            f"generated/runtime not covered by exact-version WBC rows: "
            f"{list(static_not_in_wbc)}"
        )
    return WbcStaticRuntimeEqualityResult(
        outcome=WBC_STATIC_RUNTIME_MISMATCH,
        equal=False,
        missing_runtime=missing_runtime,
        extra_runtime=extra_runtime,
        wbc_not_in_static=wbc_not_in_static,
        static_not_in_wbc=static_not_in_wbc,
        reason="; ".join(reasons),
    )


__all__ = [
    "AdapterTemplateKind",
    "ADAPTER_REQUIRED_FIELD_PROFILES",
    "ADAPTER_REQUIRED_FIELD_PROFILES_BY_KIND",
    "AUDITOR_RECONCILIATION_INTERVAL",
    "LEGACY_SIX_HOUR_NAMES_COMPATIBILITY_ONLY",
    "M11_PREREQUISITE_INCOMPLETE",
    "NEXT_THREE_HOUR_RECONCILIATION",
    "WBC_STATIC_RUNTIME_EQUAL",
    "WBC_STATIC_RUNTIME_MISMATCH",
    "WbcStaticRuntimeEqualityResult",
    "ApprovalBoundary",
    "ArtifactHandoffBoundary",
    "BOUNDARY_CONTRACTS",
    "BOUNDARY_CONTRACTS_BY_ID",
    "BoundaryTemplateKind",
    "EXEMPTION_REGISTRY",
    "OVERRIDE_AUTHORITY_CONTRACTS",
    "PHASE_FAMILY_COVERAGE_MATRIX",
    "REQUIRED_FIELD_PROFILES",
    "REQUIRED_FIELD_PROFILES_BY_KIND",
    "REQUIRED_FIELDS_APPROVAL_BOUNDARY",
    "REQUIRED_FIELDS_ARTIFACT_HANDOFF_BOUNDARY",
    "REQUIRED_FIELDS_ARTIFACT_PROMOTION",
    "REQUIRED_FIELDS_AUDITOR_COMPLETION",
    "REQUIRED_FIELDS_CHAIN_MILESTONE",
    "REQUIRED_FIELDS_CLOUD_CUSTODY",
    "REQUIRED_FIELDS_EXECUTION_CUSTODY",
    "REQUIRED_FIELDS_EXTERNAL_EFFECT",
    "REQUIRED_FIELDS_EXTERNAL_WITNESS",
    "REQUIRED_FIELDS_GRAPH_JOIN_FANOUT",
    "REQUIRED_FIELDS_HUMAN_APPROVAL_WAIVER",
    "REQUIRED_FIELDS_LIFECYCLE_TRANSITION",
    "REQUIRED_FIELDS_PR_TRANSITION",
    "REQUIRED_FIELDS_REDUCER",
    "REQUIRED_FIELDS_REPAIR_VERDICT",
    "REQUIRED_FIELDS_REVISION_BOUNDARY",
    "REQUIRED_FIELDS_VALIDATION_BOUNDARY",
    "RevisionBoundary",
    "TYPED_BOUNDARY_TEMPLATES",
    "TYPED_BOUNDARY_TEMPLATES_BY_ID",
    "ValidationBoundary",
    "artifact_promotion_template",
    "auditor_6h_completion",
    "auditor_completion_template",
    "chain_complete",
    "chain_milestone_completion",
    "chain_milestone_start",
    "chain_milestone_template",
    "challenger_to_synthesis",
    "check_contract_conformance",
    "check_wbc_static_runtime_equality",
    "classify_boundary_kind",
    "cloud_custody_blocked_relaunch_failure",
    "cloud_custody_complete",
    "cloud_custody_escalated_repeated_unchanged",
    "cloud_custody_managed_running",
    "cloud_custody_template",
    "cloud_custody_unmanaged_running_warning",
    "cloud_repair_dispatch",
    "contract_satisfies_profile",
    "critique_to_gate",
    "decision_to_parent",
    "diff_contracts",
    "execute_aggregate_promotion",
    "execute_approval",
    "execute_approval_denial",
    "execute_batch_checkpoint",
    "execute_blocked_anchor",
    "execute_no_review_terminal",
    "execute_partial_failure",
    "execute_resume_anchor",
    "execution_custody_template",
    "external_effect_template",
    "external_witness_template",
    "families_without_coverage",
    "final_projection",
    "finalize_artifacts",
    "finalize_fallback",
    "gate_to_revise",
    "get_contract_by_id",
    "get_profile_by_kind",
    "get_required_fields",
    "get_template",
    "get_template_by_id",
    "graph_join_fanout_template",
    "human_approval_waiver_template",
    "lifecycle_transition_template",
    "list_profile_kinds",
    "list_template_ids",
    "list_template_kinds",
    "meta_repair_completion",
    "ordinary_repair_completion",
    "parent_rejoin_promotion",
    "plan_to_critique",
    "pr_merged",
    "pr_ready",
    "pr_transition_template",
    "prep_lifecycle_rule",
    "prep_to_plan",
    "reducer_template",
    "repair_verdict_template",
    "replan_authority",
    "override_abort_authority",
    "override_adopt_execution_authority",
    "override_force_proceed_authority",
    "override_human_gate_authority",
    "override_recover_blocked_authority",
    "override_replan_authority",
    "override_resume_clarify_authority",
    "override_suspension_authority",
    "review_cap_authority",
    "review_child_outputs",
    "review_human_verification",
    "review_reducer_promotion",
    "review_rework_effects",
    "researcher_to_challenger",
    "revise_to_critique",
    "select_template",
    "synthesis_to_decision",
]
