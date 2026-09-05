"""Unit tests for C4 static-check helpers.

Covers ``is_structural_subset`` axes (type widening, required-subset,
enum-subset, items recursion, nullability, additionalProperties) plus
the four-pass orchestration via ``run_c4_static_checks``.

Also covers mapping-shaped ``Pipeline.stages`` and ``PortRef(port_name=...)``
regression axes (T2).
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from arnold.pipeline.c4_static_checks import (
    StaticCheckFinding,
    StaticCheckReport,
    is_structural_subset,
    run_c4_static_checks,
)
from arnold.pipeline.schema_registry import AcceptedVersionRange, ContractSchemaRegistry
from arnold.execution.step_invocation import StepInvocation
from arnold.pipeline.types import Edge, Pipeline, Port, PortRef, Stage


# ── Minimal stub step for test stages ────────────────────────────────────


@dataclass(frozen=True)
class _StubStep:
    name: str = "stub"
    kind: str = "model"

    def run(self, ctx):  # pragma: no cover
        raise RuntimeError("static validator must not dispatch")


class TestStructuralSubsetTypes:
    def test_identical_types_subset(self) -> None:
        assert is_structural_subset({"type": "string"}, {"type": "string"})

    def test_integer_widens_to_number(self) -> None:
        assert is_structural_subset({"type": "integer"}, {"type": "number"})

    def test_number_does_not_narrow_to_integer(self) -> None:
        assert not is_structural_subset({"type": "number"}, {"type": "integer"})

    def test_unrelated_types_reject(self) -> None:
        assert not is_structural_subset({"type": "string"}, {"type": "number"})

    def test_empty_consumer_accepts_all(self) -> None:
        assert is_structural_subset({"type": "string"}, {})


class TestStructuralSubsetRequired:
    def test_consumer_required_must_be_in_producer_required(self) -> None:
        prod = {"type": "object", "required": ["a", "b"]}
        cons = {"type": "object", "required": ["a"]}
        assert is_structural_subset(prod, cons)

    def test_consumer_required_not_in_producer_rejects(self) -> None:
        prod = {"type": "object", "required": ["a"]}
        cons = {"type": "object", "required": ["a", "b"]}
        assert not is_structural_subset(prod, cons)


class TestStructuralSubsetEnum:
    def test_producer_enum_subset_of_consumer(self) -> None:
        prod = {"type": "string", "enum": ["a", "b"]}
        cons = {"type": "string", "enum": ["a", "b", "c"]}
        assert is_structural_subset(prod, cons)

    def test_producer_enum_not_subset_rejects(self) -> None:
        prod = {"type": "string", "enum": ["a", "z"]}
        cons = {"type": "string", "enum": ["a", "b"]}
        assert not is_structural_subset(prod, cons)

    def test_producer_open_against_closed_enum_rejects(self) -> None:
        prod = {"type": "string"}
        cons = {"type": "string", "enum": ["a"]}
        assert not is_structural_subset(prod, cons)


class TestStructuralSubsetItems:
    def test_items_recursion(self) -> None:
        prod = {"type": "array", "items": {"type": "integer"}}
        cons = {"type": "array", "items": {"type": "number"}}
        assert is_structural_subset(prod, cons)

    def test_items_recursion_rejects(self) -> None:
        prod = {"type": "array", "items": {"type": "string"}}
        cons = {"type": "array", "items": {"type": "number"}}
        assert not is_structural_subset(prod, cons)


class TestStructuralSubsetNullability:
    def test_nullable_producer_into_strict_consumer_rejects(self) -> None:
        prod = {"type": "string", "nullable": True}
        cons = {"type": "string"}
        assert not is_structural_subset(prod, cons)

    def test_nullable_both_sides(self) -> None:
        prod = {"type": "string", "nullable": True}
        cons = {"type": "string", "nullable": True}
        assert is_structural_subset(prod, cons)


class TestStructuralSubsetAdditionalProperties:
    def test_consumer_forbids_additional_producer_allows_rejects(self) -> None:
        prod = {"type": "object"}
        cons = {"type": "object", "additionalProperties": False}
        assert not is_structural_subset(prod, cons)

    def test_both_forbid_additional(self) -> None:
        prod = {"type": "object", "additionalProperties": False}
        cons = {"type": "object", "additionalProperties": False}
        assert is_structural_subset(prod, cons)


class TestRunC4StaticChecks:
    def test_empty_pipeline_reports_clean(self) -> None:
        class Stub:
            stages: list = []
            binding_map: dict = {}

        report = run_c4_static_checks(Stub())
        assert isinstance(report, StaticCheckReport)
        assert report.ok

    def test_unknown_producer_binding_surfaces_finding(self) -> None:
        class Stub:
            stages: list = []
            binding_map = {("c", "x"): ("ghost", "y")}

        report = run_c4_static_checks(Stub())
        codes = {f.code for f in report.findings}
        assert "unknown_producer" in codes
        # All findings must carry a non-empty locus.
        for f in report.findings:
            assert f.locus
            assert f.pass_name in {
                "ports",
                "schemas",
                "structural-subset",
                "schema-versions",
                "capabilities",
                "call-sites",
            }


# ── T2: Mapping-stage + PortRef regression tests ─────────────────────────


class TestC4MappingStagesAndPortRef:
    """Regression tests for mapping-shaped Pipeline.stages and PortRef.port_name."""

    def test_green_binding_with_mapping_stages_and_ports(self) -> None:
        """A correct binding between two stages with Port/PortRef should produce no findings."""
        prod = Stage(
            name="producer",
            step=_StubStep(name="producer"),
            produces=(Port(name="out", content_type="text/markdown"),),
            invocation=StepInvocation(kind="model"),
        )
        cons = Stage(
            name="consumer",
            step=_StubStep(name="consumer"),
            consumes=(PortRef(port_name="in", content_type="text/markdown"),),
            invocation=StepInvocation(kind="model"),
        )
        pipeline = Pipeline(
            stages={"producer": prod, "consumer": cons},
            entry="producer",
            binding_map={("consumer", "in"): ("producer", "out")},
        )
        report = run_c4_static_checks(pipeline)
        # Should have no port-finding issues — the binding resolves correctly
        port_findings = [f for f in report.findings if f.pass_name == "ports"]
        assert port_findings == [], f"expected no port findings, got: {port_findings}"

    def test_mismatched_port_name_with_portref_surfaces_finding(self) -> None:
        """A binding to a port that doesn't exist on the consumer (PortRef.port_name mismatch)."""
        prod = Stage(
            name="producer",
            step=_StubStep(name="producer"),
            produces=(Port(name="out", content_type="text/markdown"),),
            invocation=StepInvocation(kind="model"),
        )
        cons = Stage(
            name="consumer",
            step=_StubStep(name="consumer"),
            consumes=(PortRef(port_name="in", content_type="text/markdown"),),
            invocation=StepInvocation(kind="model"),
        )
        pipeline = Pipeline(
            stages={"producer": prod, "consumer": cons},
            entry="producer",
            binding_map={("consumer", "wrong_name"): ("producer", "out")},
        )
        report = run_c4_static_checks(pipeline)
        # The consumer declares port "in" but binding references "wrong_name" → missing_consumed_port
        codes = {f.code for f in report.findings}
        assert "missing_consumed_port" in codes, f"expected missing_consumed_port, got: {codes}"

    def test_missing_producer_port_with_portref(self) -> None:
        """A binding referencing a producer port that doesn't exist."""
        prod = Stage(
            name="producer",
            step=_StubStep(name="producer"),
            produces=(Port(name="out", content_type="text/markdown"),),
            invocation=StepInvocation(kind="model"),
        )
        cons = Stage(
            name="consumer",
            step=_StubStep(name="consumer"),
            consumes=(PortRef(port_name="in", content_type="text/markdown"),),
            invocation=StepInvocation(kind="model"),
        )
        pipeline = Pipeline(
            stages={"producer": prod, "consumer": cons},
            entry="producer",
            binding_map={("consumer", "in"): ("producer", "nonexistent")},
        )
        report = run_c4_static_checks(pipeline)
        codes = {f.code for f in report.findings}
        assert "missing_produced_port" in codes, f"expected missing_produced_port, got: {codes}"

    def test_portref_port_name_read_correctly(self) -> None:
        """PortRef uses port_name (not name); C4 helpers must read it correctly."""
        prod = Stage(
            name="src",
            step=_StubStep(name="src"),
            produces=(Port(name="data", content_type="application/json"),),
            invocation=StepInvocation(kind="model"),
        )
        cons = Stage(
            name="dst",
            step=_StubStep(name="dst"),
            consumes=(PortRef(port_name="data", content_type="application/json"),),
            invocation=StepInvocation(kind="model"),
        )
        pipeline = Pipeline(
            stages={"src": prod, "dst": cons},
            entry="src",
            binding_map={("dst", "data"): ("src", "data")},
        )
        report = run_c4_static_checks(pipeline)
        port_findings = [f for f in report.findings if f.pass_name == "ports"]
        assert port_findings == [], f"PortRef.port_name should resolve, got: {port_findings}"

    def test_list_like_stages_still_work(self) -> None:
        """List-like stages (non-mapping) should still be handled via _iter_stages."""
        class Stub:
            stages = [
                type("S", (), {"id": "s1", "produces": (), "consumes": (), "invocation": None})(),
            ]
            binding_map: dict = {}

        report = run_c4_static_checks(Stub())
        assert isinstance(report, StaticCheckReport)
        assert report.ok

    def test_schema_pass_handles_portref_ports(self) -> None:
        """Schema pass iterates over PortRef.consumes ports via _iter_stages and _get_port_name."""
        cons = Stage(
            name="cons",
            step=_StubStep(name="cons"),
            consumes=(PortRef(port_name="in", content_type="text/markdown"),),
            invocation=StepInvocation(kind="model"),
        )
        pipeline = Pipeline(
            stages={"cons": cons},
            entry="cons",
        )
        report = run_c4_static_checks(pipeline)
        # No schema findings expected — PortRef has no schema field, so it's skipped
        schema_findings = [f for f in report.findings if f.pass_name == "schemas"]
        assert schema_findings == [], f"unexpected schema findings: {schema_findings}"

    def test_ports_and_structural_subset_use_lowered_typed_reads_and_writes(self) -> None:
        prod = Stage(
            name="producer",
            step=_StubStep(name="producer"),
            writes=(
                Port(
                    name="out",
                    content_type="application/json",
                    logical_type="payload",
                ),
            ),
            edges=(Edge(label="next", target="consumer"),),
            invocation=StepInvocation(kind="model"),
        )
        cons = Stage(
            name="consumer",
            step=_StubStep(name="consumer"),
            reads=(
                PortRef(
                    port_name="in",
                    content_type="application/json",
                    logical_type="payload",
                ),
            ),
            invocation=StepInvocation(kind="model"),
        )
        pipeline = Pipeline(
            stages={"producer": prod, "consumer": cons},
            entry="producer",
            binding_map={("consumer", "in"): ("producer", "out")},
        )

        report = run_c4_static_checks(pipeline)

        assert report.ok, report.findings

    def test_structural_subset_fails_closed_for_unresolved_lowered_binding_side(self) -> None:
        prod = Stage(
            name="producer",
            step=_StubStep(name="producer"),
            writes=(
                Port(
                    name="out",
                    content_type="application/json",
                    logical_type="payload",
                ),
            ),
            invocation=StepInvocation(kind="model"),
        )
        cons = Stage(
            name="consumer",
            step=_StubStep(name="consumer"),
            reads=(
                PortRef(
                    port_name="in",
                    content_type="application/json",
                    logical_type="payload",
                ),
            ),
            invocation=StepInvocation(kind="model"),
        )
        pipeline = Pipeline(
            stages={"producer": prod, "consumer": cons},
            entry="producer",
            binding_map={("consumer", "missing"): ("producer", "out")},
        )

        report = run_c4_static_checks(pipeline)

        assert "missing_consumed_port" in {
            f.code for f in report.findings if f.pass_name == "structural-subset"
        }

    def test_structural_subset_reports_schema_drift_through_lowered_ports(self) -> None:
        prod = Stage(
            name="producer",
            step=_StubStep(name="producer"),
            writes=(
                Port(
                    name="out",
                    content_type="text/markdown",
                    logical_type="payload",
                ),
            ),
            invocation=StepInvocation(kind="model"),
        )
        cons = Stage(
            name="consumer",
            step=_StubStep(name="consumer"),
            reads=(
                PortRef(
                    port_name="in",
                    content_type="application/json",
                    logical_type="payload",
                ),
            ),
            invocation=StepInvocation(kind="model"),
        )
        pipeline = Pipeline(
            stages={"producer": prod, "consumer": cons},
            entry="producer",
            binding_map={("consumer", "in"): ("producer", "out")},
        )

        report = run_c4_static_checks(pipeline)

        assert "content_type_mismatch" in {
            f.code for f in report.findings if f.pass_name == "ports"
        }


# ── Media content-type C4 edge tests (T12) ─────────────────────────────────


class TestC4MediaVideoEdge:
    """Direct C4 tests proving ``video/mp4`` edges are checked through ``PortRef``.

    Verifies that the typed media content-type passes through the full C4
    static-check pipeline: ports, schemas, structural subset, and call sites
    (T12).
    """

    def test_video_mp4_edge_passes_c4_with_portref(self) -> None:
        """A green binding with ``video/mp4`` Port/PortRef passes all C4 passes."""
        prod = Stage(
            name="producer",
            step=_StubStep(name="producer"),
            produces=(Port(name="video_out", content_type="video/mp4"),),
            invocation=StepInvocation(kind="model"),
        )
        cons = Stage(
            name="consumer",
            step=_StubStep(name="consumer"),
            consumes=(PortRef(port_name="video_in", content_type="video/mp4"),),
            invocation=StepInvocation(kind="model"),
        )
        pipeline = Pipeline(
            stages={"producer": prod, "consumer": cons},
            entry="producer",
            binding_map={("consumer", "video_in"): ("producer", "video_out")},
        )
        report = run_c4_static_checks(pipeline)
        assert report.ok, (
            f"video/mp4 edge should pass C4, got findings: {report.findings}"
        )

    def test_video_mp4_portref_name_is_checked(self) -> None:
        """PortRef.port_name is validated — a mismatch on video/mp4 surfaces a finding."""
        prod = Stage(
            name="producer",
            step=_StubStep(name="producer"),
            produces=(Port(name="video_out", content_type="video/mp4"),),
            invocation=StepInvocation(kind="model"),
        )
        cons = Stage(
            name="consumer",
            step=_StubStep(name="consumer"),
            consumes=(PortRef(port_name="video_in", content_type="video/mp4"),),
            invocation=StepInvocation(kind="model"),
        )
        pipeline = Pipeline(
            stages={"producer": prod, "consumer": cons},
            entry="producer",
            # binding references a port that doesn't exist on the consumer
            binding_map={("consumer", "wrong_video_port"): ("producer", "video_out")},
        )
        report = run_c4_static_checks(pipeline)
        codes = {f.code for f in report.findings}
        assert "missing_consumed_port" in codes, (
            f"expected missing_consumed_port for PortRef mismatch, got: {codes}"
        )

    def test_video_mp4_missing_producer_port_surfaces_finding(self) -> None:
        """Binding to a non-existent producer port on video/mp4 surfaces a C4 finding."""
        prod = Stage(
            name="producer",
            step=_StubStep(name="producer"),
            produces=(Port(name="video_out", content_type="video/mp4"),),
            invocation=StepInvocation(kind="model"),
        )
        cons = Stage(
            name="consumer",
            step=_StubStep(name="consumer"),
            consumes=(PortRef(port_name="video_in", content_type="video/mp4"),),
            invocation=StepInvocation(kind="model"),
        )
        pipeline = Pipeline(
            stages={"producer": prod, "consumer": cons},
            entry="producer",
            binding_map={("consumer", "video_in"): ("producer", "nonexistent_video_port")},
        )
        report = run_c4_static_checks(pipeline)
        codes = {f.code for f in report.findings}
        assert "missing_produced_port" in codes, (
            f"expected missing_produced_port for non-existent producer port, got: {codes}"
        )

    def test_video_mp4_portref_port_name_read_correctly(self) -> None:
        """PortRef(port_name=\"video_in\") with video/mp4 resolves correctly."""
        prod = Stage(
            name="src",
            step=_StubStep(name="src"),
            produces=(Port(name="video_data", content_type="video/mp4"),),
            invocation=StepInvocation(kind="model"),
        )
        cons = Stage(
            name="dst",
            step=_StubStep(name="dst"),
            consumes=(PortRef(port_name="video_data", content_type="video/mp4"),),
            invocation=StepInvocation(kind="model"),
        )
        pipeline = Pipeline(
            stages={"src": prod, "dst": cons},
            entry="src",
            binding_map={("dst", "video_data"): ("src", "video_data")},
        )
        report = run_c4_static_checks(pipeline)
        port_findings = [f for f in report.findings if f.pass_name == "ports"]
        assert port_findings == [], (
            f"PortRef.port_name should resolve for video/mp4, got: {port_findings}"
        )


class TestSchemaVersionPass:
    def test_available_schema_version_within_range_passes(self, tmp_path) -> None:
        registry = ContractSchemaRegistry(tmp_path)
        version = registry.register("payload", {"type": "object"})
        prod = Stage(
            name="producer",
            step=_StubStep(name="producer"),
            writes=(Port(name="out", content_type="application/json", logical_type="payload"),),
            invocation=StepInvocation(kind="model"),
        )
        cons = Stage(
            name="consumer",
            step=_StubStep(name="consumer"),
            reads=(
                PortRef(
                    port_name="in",
                    content_type="application/json",
                    logical_type="payload",
                    accepted_version_range=AcceptedVersionRange(
                        logical_type="payload",
                        min_version=version,
                        max_version=version,
                    ),
                ),
            ),
            invocation=StepInvocation(kind="model"),
        )
        pipeline = Pipeline(
            stages={"producer": prod, "consumer": cons},
            entry="producer",
            binding_map={("consumer", "in"): ("producer", "out")},
        )

        report = run_c4_static_checks(pipeline, registry=registry)

        assert "schema_version_not_accepted" not in {f.code for f in report.findings}

    def test_unavailable_schema_version_surfaces_finding(self, tmp_path) -> None:
        registry = ContractSchemaRegistry(tmp_path)
        prod = Stage(
            name="producer",
            step=_StubStep(name="producer"),
            writes=(Port(name="out", content_type="application/json", logical_type="payload"),),
            invocation=StepInvocation(kind="model"),
        )
        cons = Stage(
            name="consumer",
            step=_StubStep(name="consumer"),
            reads=(PortRef(port_name="in", content_type="application/json", logical_type="payload"),),
            invocation=StepInvocation(kind="model"),
        )
        pipeline = Pipeline(
            stages={"producer": prod, "consumer": cons},
            entry="producer",
            binding_map={("consumer", "in"): ("producer", "out")},
        )

        report = run_c4_static_checks(pipeline, registry=registry)

        assert "schema_version_unavailable" in {f.code for f in report.findings}

    def test_range_mismatch_surfaces_finding(self, tmp_path) -> None:
        registry = ContractSchemaRegistry(tmp_path)
        old_version = registry.register("payload", {"type": "object", "properties": {"v": {"const": 1}}})
        registry.register(
            "payload",
            {"type": "object", "required": ["v"], "properties": {"v": {"const": 2}}},
        )
        prod = Stage(
            name="producer",
            step=_StubStep(name="producer"),
            writes=(Port(name="out", content_type="application/json", logical_type="payload"),),
            invocation=StepInvocation(kind="model"),
        )
        cons = Stage(
            name="consumer",
            step=_StubStep(name="consumer"),
            reads=(
                PortRef(
                    port_name="in",
                    content_type="application/json",
                    logical_type="payload",
                    accepted_version_range=AcceptedVersionRange(
                        logical_type="payload",
                        min_version=old_version,
                        max_version=old_version,
                    ),
                ),
            ),
            invocation=StepInvocation(kind="model"),
        )
        pipeline = Pipeline(
            stages={"producer": prod, "consumer": cons},
            entry="producer",
            binding_map={("consumer", "in"): ("producer", "out")},
        )

        report = run_c4_static_checks(pipeline, registry=registry)

        assert "schema_version_not_accepted" in {f.code for f in report.findings}


# ── T16: Warning infrastructure ───────────────────────────────────────────


class TestStaticCheckReportWarnings:
    """Prove warnings alone do not make ``ok`` false and findings still control failure.

    The ``StaticCheckReport.warnings`` field is a soft-advisory-only list that
    never contributes to the ``ok`` property. Only ``findings`` control failure.
    """

    def test_default_construction_ok(self) -> None:
        """Empty findings + empty warnings → ok=True."""
        report = StaticCheckReport()
        assert report.ok
        assert report.findings == []
        assert report.warnings == []

    def test_warnings_only_ok(self) -> None:
        """Warnings without findings → ok=True regardless of warning count."""
        report = StaticCheckReport(
            warnings=[
                StaticCheckFinding("ports", "deprecated_port", "stage:producer", "port 'old' deprecated"),
            ]
        )
        assert report.ok
        assert len(report.warnings) == 1

    def test_multiple_warnings_only_ok(self) -> None:
        """Multiple warnings with no findings → ok=True."""
        report = StaticCheckReport(
            warnings=[
                StaticCheckFinding("ports", "deprecated_port", "stage:a", "port 'old' deprecated"),
                StaticCheckFinding("schemas", "soft_type_mismatch", "stage:b", "type mismatch (advisory)"),
                StaticCheckFinding("call-sites", "nonstandard_kind", "stage:c", "kind not widely tested"),
            ]
        )
        assert report.ok
        assert len(report.warnings) == 3

    def test_findings_only_not_ok(self) -> None:
        """Findings without warnings → ok=False (findings control failure)."""
        report = StaticCheckReport(
            findings=[
                StaticCheckFinding("ports", "missing_produced_port", "port:producer.out", "producer missing port"),
            ]
        )
        assert not report.ok
        assert report.warnings == []

    def test_findings_override_ok_even_with_warnings(self) -> None:
        """Findings with warnings → ok=False; warnings never mask findings."""
        report = StaticCheckReport(
            findings=[
                StaticCheckFinding("ports", "missing_produced_port", "port:p.out", "missing"),
            ],
            warnings=[
                StaticCheckFinding("ports", "deprecated_port", "stage:x", "advisory"),
            ],
        )
        assert not report.ok
        assert len(report.findings) == 1
        assert len(report.warnings) == 1
        # The finding code must still be discoverable.
        assert "missing_produced_port" in {f.code for f in report.findings}

    def test_empty_findings_with_warnings_is_ok(self) -> None:
        """Explicit empty findings with non-empty warnings → ok=True."""
        report = StaticCheckReport(findings=[], warnings=[StaticCheckFinding("ports", "advisory", "stage:a", "advisory")])
        assert report.ok

    def test_run_c4_static_checks_findings_still_control_ok(self) -> None:
        """run_c4_static_checks never adds warnings; existing findings behavior unchanged."""
        prod = Stage(
            name="producer",
            step=_StubStep(name="producer"),
            produces=(Port(name="out", content_type="text/markdown"),),
            invocation=StepInvocation(kind="model"),
        )
        cons = Stage(
            name="consumer",
            step=_StubStep(name="consumer"),
            consumes=(PortRef(port_name="in", content_type="text/markdown"),),
            invocation=StepInvocation(kind="model"),
        )
        pipeline = Pipeline(
            stages={"producer": prod, "consumer": cons},
            entry="producer",
            binding_map={("consumer", "wrong_name"): ("producer", "out")},
        )
        report = run_c4_static_checks(pipeline)
        # Should have a finding (missing_consumed_port).
        assert not report.ok
        assert len(report.findings) >= 1
        assert "missing_consumed_port" in {f.code for f in report.findings}
        # Warnings should be empty — run_c4_static_checks never populates warnings.
        assert report.warnings == []

    def test_report_keeps_warnings_separate_from_findings(self) -> None:
        """Warnings list is independent; findings list is not affected by warnings."""
        warning = StaticCheckFinding("ports", "advisory", "stage:a", "advisory")
        finding = StaticCheckFinding("ports", "error", "stage:a", "error")
        report = StaticCheckReport(findings=[finding], warnings=[warning])
        # Mutating warnings must not affect findings.
        assert finding in report.findings
        assert warning not in report.findings
        assert warning in report.warnings
        assert finding not in report.warnings


# ── T17: Media-pricing advisory static check ─────────────────────────────


class TestMediaPricingAdvisoryPass:
    """Prove ``_pass_media_pricing`` produces advisory warnings for media ports.

    The pass never affects ``StaticCheckReport.ok`` and only emits warnings
    (never findings).  Pipelines without media ports produce no warnings.
    """

    # ── helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _make_pipeline(*content_types: str) -> Any:
        """Build a minimal pipeline whose stages carry *content_types* on their ports."""
        from arnold.pipeline.types import Pipeline, Port, PortRef, Stage

        produces = tuple(Port(name=f"out_{i}", content_type=ct) for i, ct in enumerate(content_types))
        consumes = tuple(PortRef(port_name=f"in_{i}", content_type=ct) for i, ct in enumerate(content_types))

        prod = Stage(name="producer", step=_StubStep(name="producer"), produces=produces)
        cons = Stage(name="consumer", step=_StubStep(name="consumer"), consumes=consumes)

        return Pipeline(stages={"producer": prod, "consumer": cons}, entry="producer")

    @staticmethod
    def _warning_codes(report: StaticCheckReport) -> set[str]:
        return {w.code for w in report.warnings}

    # ── no-media tests ───────────────────────────────────────────────────

    def test_no_media_ports_produces_no_warnings(self) -> None:
        """A pipeline with text/markdown only → no media-pricing warnings."""
        pipeline = self._make_pipeline("text/markdown")
        report = run_c4_static_checks(pipeline)
        assert report.ok
        assert report.warnings == []

    def test_no_ports_at_all_produces_no_warnings(self) -> None:
        """A pipeline with no ports (empty produces/consumes) → no warnings."""
        from arnold.pipeline.types import Pipeline, Stage

        prod = Stage(name="producer", step=_StubStep(name="producer"))
        cons = Stage(name="consumer", step=_StubStep(name="consumer"))
        pipeline = Pipeline(stages={"producer": prod, "consumer": cons}, entry="producer")
        report = run_c4_static_checks(pipeline)
        assert report.ok
        assert report.warnings == []

    # ── image port tests (priced unit) ───────────────────────────────────

    def test_image_png_port_produces_no_warning(self) -> None:
        """``image/png`` maps to ``image`` unit which IS in DEFAULT_MEDIA_PRICING."""
        pipeline = self._make_pipeline("image/png")
        report = run_c4_static_checks(pipeline)
        assert report.ok
        assert report.warnings == []

    def test_image_jpeg_port_produces_no_warning(self) -> None:
        """``image/jpeg`` also maps to priced ``image`` unit."""
        pipeline = self._make_pipeline("image/jpeg")
        report = run_c4_static_checks(pipeline)
        assert report.ok
        assert report.warnings == []

    def test_multiple_image_ports_no_warning(self) -> None:
        """Multiple image/* types still all map to the priced ``image`` unit."""
        pipeline = self._make_pipeline("image/png", "image/jpeg", "image/webp")
        report = run_c4_static_checks(pipeline)
        assert report.ok
        assert report.warnings == []

    # ── video port tests (missing pricing) ───────────────────────────────

    def test_video_mp4_port_produces_warning(self) -> None:
        """``video/mp4`` maps to ``video_second`` — NOT in DEFAULT_MEDIA_PRICING."""
        pipeline = self._make_pipeline("video/mp4")
        report = run_c4_static_checks(pipeline)
        assert report.ok  # warning only, not a failure
        assert "missing_media_pricing" in self._warning_codes(report)
        # Only one unique unit is missing, so one warning.
        assert len(report.warnings) == 1
        w = report.warnings[0]
        assert w.pass_name == "media-pricing"
        assert "video_second" in w.detail

    def test_multiple_video_ports_still_one_warning(self) -> None:
        """Multiple video/* types all map to ``video_second`` — one warning."""
        pipeline = self._make_pipeline("video/mp4", "video/webm")
        report = run_c4_static_checks(pipeline)
        assert report.ok
        codes = self._warning_codes(report)
        assert "missing_media_pricing" in codes
        # Deduplicated by unit — all video/* map to the same unit.
        assert len(report.warnings) == 1

    # ── audio port tests (missing pricing) ───────────────────────────────

    def test_audio_wav_port_produces_warning(self) -> None:
        """``audio/wav`` maps to ``audio_second`` — NOT in DEFAULT_MEDIA_PRICING."""
        pipeline = self._make_pipeline("audio/wav")
        report = run_c4_static_checks(pipeline)
        assert report.ok
        assert "missing_media_pricing" in self._warning_codes(report)
        assert len(report.warnings) == 1
        w = report.warnings[0]
        assert w.pass_name == "media-pricing"
        assert "audio_second" in w.detail

    def test_audio_mp3_port_produces_warning(self) -> None:
        """``audio/mpeg`` also maps to missing ``audio_second`` unit."""
        pipeline = self._make_pipeline("audio/mpeg")
        report = run_c4_static_checks(pipeline)
        assert report.ok
        assert "missing_media_pricing" in self._warning_codes(report)

    # ── mixed / multi-media tests ────────────────────────────────────────

    def test_video_and_audio_produces_two_warnings(self) -> None:
        """Video + audio → two distinct missing units → two warnings."""
        pipeline = self._make_pipeline("video/mp4", "audio/wav")
        report = run_c4_static_checks(pipeline)
        assert report.ok
        assert len(report.warnings) == 2
        codes = self._warning_codes(report)
        assert codes == {"missing_media_pricing"}

    def test_image_video_audio_mixed(self) -> None:
        """Image (priced) + video (missing) + audio (missing) → 2 warnings only."""
        pipeline = self._make_pipeline("image/png", "video/mp4", "audio/wav")
        report = run_c4_static_checks(pipeline)
        assert report.ok
        assert len(report.warnings) == 2  # only video + audio are missing
        assert "missing_media_pricing" in self._warning_codes(report)

    # ── warning shape invariants ─────────────────────────────────────────

    def test_warning_has_stable_locus(self) -> None:
        """Every media-pricing warning carries a non-empty locus."""
        pipeline = self._make_pipeline("video/mp4")
        report = run_c4_static_checks(pipeline)
        for w in report.warnings:
            assert w.locus
            assert w.pass_name == "media-pricing"
            assert w.code in {"missing_media_pricing", "no_media_pricing_configured"}

    # ── ok invariance ────────────────────────────────────────────────────

    def test_media_warnings_never_affect_ok(self) -> None:
        """Even with media warnings, ``ok`` is still True when there are no findings."""
        pipeline = self._make_pipeline("video/mp4", "audio/wav")
        report = run_c4_static_checks(pipeline)
        assert report.ok
        assert len(report.warnings) >= 1
        assert report.findings == []

    def test_media_warnings_coexist_with_findings(self) -> None:
        """When findings exist alongside media warnings, ``ok`` is still False."""
        from arnold.pipeline.types import Pipeline, Port, PortRef, Stage

        prod = Stage(
            name="producer",
            step=_StubStep(name="producer"),
            produces=(Port(name="out_0", content_type="video/mp4"),),
        )
        cons = Stage(
            name="consumer",
            step=_StubStep(name="consumer"),
            consumes=(PortRef(port_name="in_0", content_type="video/mp4"),),
        )
        # Inject a binding to an unknown consumer to force a finding.
        pipeline = Pipeline(
            stages={"producer": prod, "consumer": cons},
            entry="producer",
            binding_map={("ghost_consumer", "x"): ("producer", "out_0")},
        )
        report = run_c4_static_checks(pipeline)
        assert not report.ok
        assert len(report.findings) >= 1
        assert len(report.warnings) >= 1  # video pricing still warns
        # Warnings never in findings.
        assert all(w not in report.findings for w in report.warnings)

    # ── empty pricing table tests ────────────────────────────────────────

    def test_empty_pricing_table_produces_both_warning_codes(self) -> None:
        """When DEFAULT_MEDIA_PRICING is empty, both ``missing_media_pricing``
        (per-unit) and ``no_media_pricing_configured`` (global) warnings appear."""
        from unittest.mock import patch

        pipeline = self._make_pipeline("video/mp4")
        with patch(
            "arnold.agent.costing.media_cost.DEFAULT_MEDIA_PRICING", ()
        ):
            report = run_c4_static_checks(pipeline)
        assert report.ok  # warnings only
        codes = self._warning_codes(report)
        assert "missing_media_pricing" in codes
        assert "no_media_pricing_configured" in codes
        assert len(report.warnings) == 2

    def test_empty_pricing_table_no_media_pricing_configured_detail(self) -> None:
        """The ``no_media_pricing_configured`` warning explains that no pricing
        configuration is visible."""
        from unittest.mock import patch

        pipeline = self._make_pipeline("audio/wav")
        with patch(
            "arnold.agent.costing.media_cost.DEFAULT_MEDIA_PRICING", ()
        ):
            report = run_c4_static_checks(pipeline)
        assert report.ok
        no_config_warnings = [
            w for w in report.warnings if w.code == "no_media_pricing_configured"
        ]
        assert len(no_config_warnings) == 1
        w = no_config_warnings[0]
        assert w.pass_name == "media-pricing"
        assert "DEFAULT_MEDIA_PRICING" in w.detail
        assert "visible" in w.detail

    def test_empty_pricing_table_still_ok(self) -> None:
        """Even with an empty pricing table, ``ok`` remains True (warnings only)."""
        from unittest.mock import patch

        pipeline = self._make_pipeline("video/mp4", "audio/wav")
        with patch(
            "arnold.agent.costing.media_cost.DEFAULT_MEDIA_PRICING", ()
        ):
            report = run_c4_static_checks(pipeline)
        assert report.ok
        assert report.findings == []
        # Each missing unit + one global "no config" warning.
        assert len(report.warnings) == 3  # video_second, audio_second, no_config

    def test_empty_pricing_table_with_image_still_warns(self) -> None:
        """Even image/* types warn when the pricing table is entirely empty,
        because there are no rows at all to cover any unit."""
        from unittest.mock import patch

        pipeline = self._make_pipeline("image/png")
        with patch(
            "arnold.agent.costing.media_cost.DEFAULT_MEDIA_PRICING", ()
        ):
            report = run_c4_static_checks(pipeline)
        assert report.ok
        codes = self._warning_codes(report)
        assert "missing_media_pricing" in codes
        assert "no_media_pricing_configured" in codes
        assert len(report.warnings) == 2
