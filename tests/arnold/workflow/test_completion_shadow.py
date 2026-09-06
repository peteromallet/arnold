"""Tests for shadow engine: spec/binding generation, verdict computation, S2F gap report.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from arnold.workflow.completion.outcomes import CandidateOutcome
from arnold.workflow.completion.shadow import (
    S2FGapReport,
    ShadowEvaluation,
    ShadowVerdict,
    S2FTemplatesUnavailable,
    evaluate_shadow,
    generate_shadow_bindings,
    generate_shadow_specs,
    generate_shadow_specs_from_s2f,
    s2f_discovery_gap_report,
)
from arnold.workflow.completion.spec import CompletionSpec, SubjectKind
from arnold.workflow.completion.source_declaration import (
    SourceDeclaration,
    SubjectDeclaration,
)
from arnold.workflow.completion.binding import CompletionBinding


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def step_declaration() -> SubjectDeclaration:
    source = SourceDeclaration(
        source_id="test-step-001",
        kind=SubjectKind.STEP,
        canonical_name="test_step",
    )
    return SubjectDeclaration(
        source=source,
        subject_kind=SubjectKind.STEP,
        subject_instance_id="test-step-001:inst-1",
        declaration_id="test-step-001:decl-1",
    )


@pytest.fixture
def workflow_declaration() -> SubjectDeclaration:
    source = SourceDeclaration(
        source_id="test-wf-001",
        kind=SubjectKind.WORKFLOW,
        canonical_name="test_workflow",
    )
    return SubjectDeclaration(
        source=source,
        subject_kind=SubjectKind.WORKFLOW,
        subject_instance_id="test-wf-001:inst-1",
        declaration_id="test-wf-001:decl-1",
    )


@pytest.fixture
def dynamic_task_declaration() -> SubjectDeclaration:
    source = SourceDeclaration(
        source_id="test-dt-001",
        kind=SubjectKind.DYNAMIC_TASK,
        canonical_name="test_dynamic_task",
    )
    return SubjectDeclaration(
        source=source,
        subject_kind=SubjectKind.DYNAMIC_TASK,
        subject_instance_id="test-dt-001:inst-1",
        declaration_id="test-dt-001:decl-1",
    )


@pytest.fixture
def effect_declaration() -> SubjectDeclaration:
    source = SourceDeclaration(
        source_id="test-effect-001",
        kind=SubjectKind.EFFECT,
        canonical_name="test_effect",
    )
    return SubjectDeclaration(
        source=source,
        subject_kind=SubjectKind.EFFECT,
        subject_instance_id="test-effect-001:inst-1",
        declaration_id="test-effect-001:decl-1",
    )


@pytest.fixture
def human_boundary_declaration() -> SubjectDeclaration:
    source = SourceDeclaration(
        source_id="test-hb-001",
        kind=SubjectKind.HUMAN_BOUNDARY,
        canonical_name="test_review_gate",
    )
    return SubjectDeclaration(
        source=source,
        subject_kind=SubjectKind.HUMAN_BOUNDARY,
        subject_instance_id="test-hb-001:inst-1",
        declaration_id="test-hb-001:decl-1",
    )


@pytest.fixture
def pure_declaration() -> SubjectDeclaration:
    source = SourceDeclaration(
        source_id="test-pure-001",
        kind=SubjectKind.STEP,
        canonical_name="test_pure_helper",
    )
    return SubjectDeclaration(
        source=source,
        subject_kind=SubjectKind.STEP,
        subject_instance_id="test-pure-001:inst-1",
        declaration_id="test-pure-001:decl-1",
    )


# ---------------------------------------------------------------------------
# generate_shadow_specs — all SubjectKind variants
# ---------------------------------------------------------------------------


class TestGenerateShadowSpecs:
    """generate_shadow_specs produces specs for all SubjectKind variants."""

    @pytest.mark.parametrize(
        "decl_fixture_name",
        [
            "step_declaration",
            "workflow_declaration",
            "dynamic_task_declaration",
            "effect_declaration",
            "human_boundary_declaration",
            "pure_declaration",
        ],
    )
    def test_spec_for_each_kind(
        self, request, decl_fixture_name: str,
    ) -> None:
        decl = request.getfixturevalue(decl_fixture_name)
        specs = generate_shadow_specs((decl,))
        assert len(specs) == 1
        spec = specs[0]
        assert isinstance(spec, CompletionSpec)
        assert spec.spec_hash.startswith("sha256:")
        assert spec.subject_kind == decl.subject_kind

    def test_multiple_declarations(self, step_declaration, workflow_declaration) -> None:
        specs = generate_shadow_specs((step_declaration, workflow_declaration))
        assert len(specs) == 2
        assert specs[0].subject_kind == SubjectKind.STEP
        assert specs[1].subject_kind == SubjectKind.WORKFLOW

    def test_empty_inventory(self) -> None:
        specs = generate_shadow_specs(())
        assert len(specs) == 0


# ---------------------------------------------------------------------------
# generate_shadow_bindings
# ---------------------------------------------------------------------------


class TestGenerateShadowBindings:
    """generate_shadow_bindings produces bindings from specs and instance IDs."""

    def test_binding_count_matches(self, step_declaration) -> None:
        specs = generate_shadow_specs((step_declaration,))
        bindings = generate_shadow_bindings(specs, ("inst-1",))
        assert len(bindings) == 1
        binding = bindings[0]
        assert isinstance(binding, CompletionBinding)
        assert binding.subject_instance_id == "inst-1"

    def test_mismatched_length_raises(self) -> None:
        with pytest.raises(ValueError, match="specs and instance_ids must have"):
            generate_shadow_bindings(
                (CompletionSpec, CompletionSpec),
                ("inst-1",),
            )

    def test_deterministic_binding_hash(self, step_declaration) -> None:
        specs = generate_shadow_specs((step_declaration,))
        b1 = generate_shadow_bindings(specs, ("inst-1",))
        b2 = generate_shadow_bindings(specs, ("inst-1",))
        assert b1[0].binding_hash == b2[0].binding_hash


# ---------------------------------------------------------------------------
# evaluate_shadow — full evaluation
# ---------------------------------------------------------------------------


class TestEvaluateShadow:
    """evaluate_shadow produces specs, bindings, and verdicts."""

    def test_empty_inventory(self) -> None:
        result = evaluate_shadow(())
        assert isinstance(result, ShadowEvaluation)
        assert len(result.specs) == 0
        assert len(result.bindings) == 0
        assert len(result.verdicts) == 0

    def test_single_step(self, step_declaration) -> None:
        result = evaluate_shadow((step_declaration,))
        assert len(result.specs) == 1
        assert len(result.bindings) == 1
        assert len(result.verdicts) == 1
        verdict = result.verdicts[0]
        assert verdict.declaration_id == step_declaration.declaration_id
        assert verdict.spec_hash == result.specs[0].spec_hash
        assert verdict.binding_hash == result.bindings[0].binding_hash
        assert verdict.outcome.value == "success"

    def test_all_kinds_in_one_evaluation(
        self, step_declaration, workflow_declaration,
        dynamic_task_declaration, effect_declaration,
        human_boundary_declaration, pure_declaration,
    ) -> None:
        inventory = (
            step_declaration,
            workflow_declaration,
            dynamic_task_declaration,
            effect_declaration,
            human_boundary_declaration,
            pure_declaration,
        )
        result = evaluate_shadow(inventory)
        assert len(result.specs) == 6
        assert len(result.bindings) == 6
        assert len(result.verdicts) == 6
        kinds = {v.outcome.value for v in result.verdicts}
        assert kinds == {"success"}


# ---------------------------------------------------------------------------
# ShadowVerdict — serialization round-trip
# ---------------------------------------------------------------------------


class TestShadowVerdict:
    """ShadowVerdict to_dict/from_dict round-trip."""

    def test_round_trip(self) -> None:
        original = ShadowVerdict(
            declaration_id="decl-1",
            spec_hash="sha256:abc",
            binding_hash="sha256:def",
            outcome=CandidateOutcome.SUCCESS,
            verdict_description="test verdict",
        )
        d = original.to_dict()
        restored = ShadowVerdict.from_dict(d)
        assert restored == original

    def test_round_trip_no_description(self) -> None:
        original = ShadowVerdict(
            declaration_id="decl-2",
            spec_hash="sha256:abc",
            binding_hash="sha256:def",
            outcome=CandidateOutcome.SUCCESS,
        )
        d = original.to_dict()
        restored = ShadowVerdict.from_dict(d)
        assert restored == original


# ---------------------------------------------------------------------------
# ShadowEvaluation — serialization round-trip
# ---------------------------------------------------------------------------


class TestShadowEvaluation:
    """ShadowEvaluation serialization round-trip."""

    def test_round_trip(self, step_declaration) -> None:
        original = evaluate_shadow((step_declaration,))
        d = original.to_dict()
        restored = ShadowEvaluation.from_dict(d)
        assert len(restored.specs) == len(original.specs)
        assert len(restored.bindings) == len(original.bindings)
        assert len(restored.verdicts) == len(original.verdicts)
        assert restored.verdicts[0].declaration_id == original.verdicts[0].declaration_id


# ---------------------------------------------------------------------------
# Pure helper exclusion from shadow evaluation
# ---------------------------------------------------------------------------


class TestPureHelperExclusion:
    """Pure helpers should not be excluded; they still generate specs and verdicts."""

    def test_pure_generates_spec(self, pure_declaration) -> None:
        result = evaluate_shadow((pure_declaration,))
        assert len(result.specs) == 1
        assert result.specs[0].subject_kind == SubjectKind.STEP

    def test_pure_generates_verdict(self, pure_declaration) -> None:
        result = evaluate_shadow((pure_declaration,))
        assert len(result.verdicts) == 1


# ---------------------------------------------------------------------------
# S2F gap-report behavior
# ---------------------------------------------------------------------------


class TestS2FGapReport:
    """S2FGapReport properties and discovery behavior."""

    def test_empty_report_has_no_gaps(self) -> None:
        report = S2FGapReport()
        assert report.has_gaps is False
        assert report.total_entries_attempted == 0

    def test_report_with_gaps(self) -> None:
        report = S2FGapReport(
            gaps=("missing kind field", "invalid JSON"),
        )
        assert report.has_gaps is True
        assert report.total_entries_attempted == 2

    def test_report_with_declarations(self) -> None:
        source = SourceDeclaration(
            source_id="s2f-test",
            kind=SubjectKind.STEP,
            canonical_name="s2f_step",
        )
        decl = SubjectDeclaration(
            source=source,
            subject_kind=SubjectKind.STEP,
            subject_instance_id="s2f-inst",
            declaration_id="s2f-decl",
        )
        report = S2FGapReport(
            parsed_declarations=(decl,),
        )
        assert report.has_gaps is False
        assert report.total_entries_attempted == 1

    def test_discovery_nonexistent_dirs(self) -> None:
        """Discovery on nonexistent dirs returns empty gracefully."""
        report = s2f_discovery_gap_report(
            scan_dirs=("/nonexistent/path",),
        )
        assert len(report.discovered_files) == 0
        assert len(report.parsed_declarations) == 0
        assert report.has_gaps is True

    def test_s2f_file_parsing(self) -> None:
        """Write a real S2F template and verify it's parsed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpl = {
                "schema_version": "arnold.workflow.source_declaration.v1",
                "declarations": [
                    {
                        "kind": "step",
                        "canonical_name": "s2f_test_step",
                        "source_id": "s2f-file-step",
                    },
                ],
            }
            tmpl_path = Path(tmpdir) / "test_template.json"
            tmpl_path.write_text(json.dumps(tmpl))
            report = s2f_discovery_gap_report(
                scan_dirs=(tmpdir,),
                schema_markers=("arnold.workflow.source_declaration.v1",),
            )
            assert len(report.discovered_files) >= 1
            assert len(report.parsed_declarations) >= 1
            assert report.parsed_declarations[0].source.canonical_name == "s2f_test_step"


# ---------------------------------------------------------------------------
# generate_shadow_specs_from_s2f
# ---------------------------------------------------------------------------


class TestGenerateShadowSpecsFromS2F:
    """S2F artifact discovery generates specs."""

    def test_empty_dirs_produces_empty(self) -> None:
        with pytest.raises(S2FTemplatesUnavailable) as exc_info:
            generate_shadow_specs_from_s2f(scan_dirs=("/nonexistent",))
        assert exc_info.value.report.has_gaps is True

    def test_settled_execution_discovery_defaults(self) -> None:
        from arnold.workflow.completion.shadow import (
            DEFAULT_S2F_SCAN_DIRS,
            S2F_SCHEMA_MARKERS,
        )
        assert "plans" in DEFAULT_S2F_SCAN_DIRS
        assert "plans/*" in DEFAULT_S2F_SCAN_DIRS
        assert "GO-FORMAT" in S2F_SCHEMA_MARKERS
        assert ".pype" in S2F_SCHEMA_MARKERS
        assert "boundary-registry" in S2F_SCHEMA_MARKERS

    def test_s2f_template_produces_specs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpl = {
                "schema_version": "arnold.workflow.s2f_template.v1",
                "declarations": [
                    {
                        "kind": "workflow",
                        "canonical_name": "s2f_wf",
                        "source_id": "s2f-gen-wf",
                    },
                    {
                        "kind": "human",
                        "canonical_name": "s2f_review",
                        "source_id": "s2f-gen-review",
                    },
                ],
            }
            tmpl_path = Path(tmpdir) / "s2f_specs.json"
            tmpl_path.write_text(json.dumps(tmpl))
            specs = generate_shadow_specs_from_s2f(
                scan_dirs=(tmpdir,),
                schema_markers=("arnold.workflow.s2f_template.v1",),
            )
            assert len(specs) == 2
            kinds = {s.subject_kind for s in specs}
            assert SubjectKind.WORKFLOW in kinds
            assert SubjectKind.HUMAN_BOUNDARY in kinds
