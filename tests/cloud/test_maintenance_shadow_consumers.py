"""Cross-consumer Maintenance shadow tests for cloud consumers (M2, T20).

One integration-style module pins the four cloud consumers' pre-M2 legacy
outcomes and their M2 shadow integrations:

* watchdog — :func:`watchdog_legacy_verdict`,
  :func:`build_watchdog_detection_event`, and
  :func:`attach_maintenance_shadow_to_result`;
* six-hour auditor — :func:`six_hour_audit_legacy_verdict`,
  :func:`build_six_hour_audit_report_event`, and
  :func:`adapt_six_hour_audit_report`;
* status snapshot — :func:`render_maintenance_observation` and the sibling
  ``maintenance_observation`` section of
  :func:`build_cloud_status_snapshot`;
* maintenance dispatch — :func:`attach_maintenance_shadow_to_receipt` and
  :func:`direct_write_bypass_finding`.

Every test asserts:

* deterministic comparison buckets and explicit denominators (match /
  would_block / explained_difference / stale_projection /
  missing_denominator — exactly one per row, fail-closed);
* warn/dead-letter diagnostics on append failure, with the legacy verdict
  unchanged;
* unchanged legacy classifications / escalation / authorization fields;
* strict operational-versus-efficiency separation (the six-hour product can
  never emit an ``EfficiencyAnalysis``);
* no process-health recovery inference (PID/tmux/activity/status evidence is
  never treated as recovery);
* zero calls to ``write_plan_state`` / ``save_chain_state`` /
  ``TransitionWriter`` / raw plan/chain writers from any Maintenance path
  (monkeypatched to raise; the typed M7 bypass finding is inert data).
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import shutil
import tempfile
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from arnold_pipelines.megaplan.cloud.maintenance_dispatch import (
    attach_maintenance_shadow_to_receipt,
    direct_write_bypass_finding,
)
from arnold_pipelines.megaplan.cloud.six_hour_auditor import (
    AuditFinding,
    AuditSeverity,
    SixHourAuditReport,
    adapt_six_hour_audit_report,
    build_six_hour_audit_report_event,
    six_hour_audit_legacy_verdict,
)
import arnold_pipelines.megaplan.cloud.status_snapshot as status_snapshot_module
from arnold_pipelines.megaplan.cloud.status_snapshot import (
    build_cloud_status_snapshot,
    render_maintenance_observation,
)
from arnold_pipelines.megaplan.cloud.watchdog import (
    EscalationLevel,
    EvidenceLevel,
    WatchdogResult,
    attach_maintenance_shadow_to_result,
    build_watchdog_detection_event,
    watchdog_legacy_verdict,
)
from arnold_pipelines.megaplan.maintenance.identity import canonical_digest
from arnold_pipelines.megaplan.maintenance.boundaries import (
    FORBIDDEN_DIRECT_WRITERS,
    M7_SEAM,
    M7BypassFinding,
)
from arnold_pipelines.megaplan.maintenance.contracts import (
    CoherenceReason,
    CoherenceState,
    CompletenessState,
    FreshnessState,
    ObservationEnvelope,
    SourceVersionVector,
)
from arnold_pipelines.run_authority import canonical_json
from arnold_pipelines.megaplan.maintenance.events import event_digest
from arnold_pipelines.megaplan.maintenance.identity import EnvironmentId

UTC = timezone.utc


# ---------------------------------------------------------------------------
# Shared fixtures: envelopes, projections, watchdog results, audit reports
# ---------------------------------------------------------------------------


def _ts() -> datetime:
    return datetime(2026, 8, 15, 12, 0, tzinfo=UTC)


def _vector(owner: str, env: str, version: str) -> SourceVersionVector:
    return SourceVersionVector(
        owner=owner,
        source=owner,
        environment=EnvironmentId(env),
        before=version,
        after=version,
    )


def _eligible_envelope(*, green: bool = True) -> ObservationEnvelope:
    """Coherent/complete/fresh single-environment envelope (SC2 eligible)."""
    return ObservationEnvelope.build(
        observed_at=_ts(),
        environment="production",
        version_vectors=[
            _vector("run_authority", "production", "a" * 64),
            _vector("wbc", "production", "b" * 64),
        ],
        completeness=CompletenessState.COMPLETE,
        freshness=FreshnessState.FRESH,
        coherence=CoherenceState.COHERENT,
    )


def _eligible_non_dispatchable_envelope() -> ObservationEnvelope:
    """Eligible envelope whose green flag matches a detection-only consumer.

    Watchdog and auditor legacy verdicts are ``green`` with ``dispatchable``
    and ``terminal`` always ``False`` — these consumers never dispatch or
    terminate.  The shared comparator matches only when the envelope's
    ``dispatchable``/``terminal`` agree, so a ``match`` bucket for these
    consumers requires an eligible envelope that is green but explicitly
    non-dispatchable and non-terminal (an under-claim, which the envelope
    contract permits).
    """
    return ObservationEnvelope(
        schema_version=1,
        observed_at=_ts(),
        environment=EnvironmentId("production"),
        version_vectors=[
            _vector("run_authority", "production", "a" * 64),
            _vector("wbc", "production", "b" * 64),
        ],
        completeness=CompletenessState.COMPLETE,
        freshness=FreshnessState.FRESH,
        coherence=CoherenceState.COHERENT,
        coherence_reasons=(),
        terminal=False,
        green=True,
        dispatchable=False,
    )


def _unknown_envelope() -> ObservationEnvelope:
    return ObservationEnvelope.build(
        observed_at=_ts(),
        completeness=CompletenessState.UNKNOWN,
        freshness=FreshnessState.UNKNOWN,
        coherence=CoherenceState.UNKNOWN,
        coherence_reasons=(CoherenceReason.UNKNOWN,),
    )


def _incoherent_envelope(
    reasons: tuple[CoherenceReason, ...] = (CoherenceReason.UNKNOWN,),
    *,
    cross_env: bool = False,
) -> ObservationEnvelope:
    vectors = [_vector("run_authority", "production", "a" * 64)]
    if cross_env:
        vectors.append(_vector("wbc", "staging", "b" * 64))
    return ObservationEnvelope.build(
        observed_at=_ts(),
        environment="production",
        version_vectors=vectors,
        completeness=CompletenessState.UNKNOWN,
        freshness=FreshnessState.FRESH,
        coherence=CoherenceState.INCOHERENT,
        coherence_reasons=reasons,
    )


def _stale_envelope() -> ObservationEnvelope:
    return ObservationEnvelope.build(
        observed_at=_ts(),
        environment="production",
        version_vectors=[_vector("run_authority", "production", "a" * 64)],
        completeness=CompletenessState.COMPLETE,
        freshness=FreshnessState.STALE,
        coherence=CoherenceState.COHERENT,
    )


def _projection(
    *,
    freshness: str = "fresh",
    denominator: int | None = 100,
    covered_count: int | None = 87,
) -> SimpleNamespace:
    return SimpleNamespace(
        projection="efficiency_analysis",
        freshness=freshness,
        source_digest="a" * 64,
        output_digest="b" * 64,
        coverage_denominator=denominator,
        covered_count=covered_count,
    )


def _watchdog_result(
    *,
    ok: bool = True,
    escalation: EscalationLevel = EscalationLevel.NONE,
    child_present: bool = True,
    matched_expected: bool = True,
    detail: str = "",
) -> WatchdogResult:
    return WatchdogResult(
        ok=ok,
        check_name="check-progress",
        escalation=escalation,
        evidence_level=EvidenceLevel.L1,
        detail=detail,
        evidence={},
        child_present=child_present,
        matched_expected=matched_expected,
    )


def _audit_report(*, ok: bool = True) -> SixHourAuditReport:
    findings = (
        (AuditFinding(
            finding_id="f1",
            severity=AuditSeverity.OK,
            category="missed_events",
            detail="no missed events",
            occurred_at="2026-08-15T11:00:00+00:00",
        ),)
        if ok
        else (AuditFinding(
            finding_id="f1",
            severity=AuditSeverity.FAILED,
            category="missed_events",
            detail="missed event window",
            occurred_at="2026-08-15T11:00:00+00:00",
        ),)
    )
    return SixHourAuditReport(
        audit_id="audit-1",
        started_at="2026-08-15T11:00:00+00:00",
        completed_at="2026-08-15T11:00:05+00:00",
        duration_seconds=5.0,
        findings=findings,
        events_checked=10,
        requests_checked=2,
        slo_violations=0 if ok else 1,
        escalated_count=0 if ok else 1,
    )


class _RaisingLedger:
    """Fake Maintenance ledger whose append always fails."""

    def __init__(self, exc: Exception | None = None) -> None:
        self._exc = exc or OSError("disk full")

    def append(self, event: Any) -> dict[str, Any]:
        raise self._exc


class _RecordingLedger:
    """Fake Maintenance ledger that records appended events."""

    def __init__(self) -> None:
        self.appended: list[Any] = []

    def append(self, event: Any) -> dict[str, Any]:
        self.appended.append(event)
        return {"sequence": len(self.appended)}


# ---------------------------------------------------------------------------
# Watchdog: legacy verdict, strict event, shadow attachment
# ---------------------------------------------------------------------------


def test_watchdog_legacy_verdict_derived_only_from_ok_and_escalation() -> None:
    green = watchdog_legacy_verdict(_watchdog_result(ok=True))
    assert green == {"green": True, "dispatchable": False, "terminal": False}

    blocking = watchdog_legacy_verdict(
        _watchdog_result(ok=True, escalation=EscalationLevel.BLOCKING)
    )
    assert blocking["green"] is False

    critical = watchdog_legacy_verdict(
        _watchdog_result(ok=True, escalation=EscalationLevel.CRITICAL)
    )
    assert critical["green"] is False

    failed = watchdog_legacy_verdict(_watchdog_result(ok=False))
    assert failed["green"] is False


def test_watchdog_verdict_never_infers_recovery_from_process_health() -> None:
    # A present child / matched output with a failed structured verdict is
    # still non-green: process presence is observation data, never recovery.
    present_but_failed = watchdog_legacy_verdict(
        _watchdog_result(ok=False, child_present=True, matched_expected=True)
    )
    assert present_but_failed["green"] is False

    # Conversely, an absent child never turns a passing structured verdict
    # non-green: the watchdog does not treat child absence as failure.
    absent_but_ok = watchdog_legacy_verdict(
        _watchdog_result(ok=True, child_present=False)
    )
    assert absent_but_ok["green"] is True

    # The verdict fields are the only inputs: extra activity/status evidence
    # never changes the normalized result.
    with_activity = watchdog_legacy_verdict(
        _watchdog_result(ok=True, detail="activity: running")
    )
    assert with_activity["green"] is True


def test_watchdog_legacy_verdict_never_dispatchable_or_terminal() -> None:
    verdict = watchdog_legacy_verdict(_watchdog_result(ok=True))
    assert verdict["dispatchable"] is False
    assert verdict["terminal"] is False


def test_build_watchdog_detection_event_is_strict_and_occurrence_scoped() -> None:
    event = build_watchdog_detection_event(
        check_name="check-progress",
        occurrence_id="occ-1",
        severity="blocking",
        description="watchdog failed",
    )
    assert event.event_id == "watchdog-check-progress-occ-1"
    assert event.occurrence_id == "occ-1"
    assert event.idempotency_key == "occ-1"  # SD2: occurrence is the scope
    assert event.payload.kind == "detection"
    assert event.payload.detection_kind == "watchdog:check-progress"
    assert event.payload.subject == "check-progress"
    assert event.payload.severity == "blocking"
    assert event.payload.evidence_refs == ()
    # Deterministic defaults: watermark one second in the past => ON_TIME.
    assert event.lateness == "on_time"


def test_attach_watchdog_shadow_match_for_eligible_envelope() -> None:
    result = _watchdog_result(ok=True)
    # The watchdog legacy verdict is green but never dispatchable/terminal, so
    # a match requires an eligible envelope with the same promotion shape.
    attached = attach_maintenance_shadow_to_result(
        result, envelope=_eligible_non_dispatchable_envelope()
    )

    # Legacy verdict fields are byte-for-byte unchanged.
    assert attached.ok is result.ok
    assert attached.escalation is result.escalation
    assert attached.evidence_level is result.evidence_level
    assert attached.child_present is result.child_present
    assert attached.matched_expected is result.matched_expected

    shadow = attached.maintenance_shadow
    assert shadow is not None
    assert shadow["present"] is True
    assert shadow["bucket"] == "match"
    assert shadow["reasons"] == []
    assert shadow["green"] is True
    assert shadow["dispatchable"] is False  # watchdog never dispatches
    assert shadow["terminal"] is False
    assert shadow["envelope_eligible"] is True
    assert len(shadow["envelope_digest"]) == 64
    assert len(shadow["comparison_digest"]) == 64
    assert len(shadow["legacy_hash"]) == 64


def test_attach_watchdog_shadow_would_block_for_incoherent_envelope() -> None:
    attached = attach_maintenance_shadow_to_result(
        _watchdog_result(ok=True), envelope=_incoherent_envelope()
    )
    shadow = attached.maintenance_shadow
    assert shadow is not None
    assert shadow["bucket"] == "would_block"
    assert "would_block" in shadow["reasons"]
    assert shadow["green"] is False and shadow["dispatchable"] is False
    assert any("envelope_not_eligible" in diag for diag in shadow["diagnostics"])


def test_attach_watchdog_shadow_explained_difference_for_non_promoting_legacy() -> None:
    attached = attach_maintenance_shadow_to_result(
        _watchdog_result(ok=False, escalation=EscalationLevel.BLOCKING),
        envelope=_incoherent_envelope(),
    )
    shadow = attached.maintenance_shadow
    assert shadow is not None
    assert shadow["bucket"] == "explained_difference"
    assert shadow["green"] is False
    # The legacy escalation outcome is unchanged by the shadow.
    assert attached.requires_escalation is True


def test_attach_watchdog_shadow_no_envelope_returns_result_unchanged() -> None:
    result = _watchdog_result(ok=True)
    attached = attach_maintenance_shadow_to_result(result)
    assert attached is result
    assert attached.maintenance_shadow is None


def test_attach_watchdog_shadow_append_success_records_event() -> None:
    ledger = _RecordingLedger()
    attached = attach_maintenance_shadow_to_result(
        _watchdog_result(ok=True),
        envelope=_eligible_envelope(),
        ledger=ledger,
    )
    shadow = attached.maintenance_shadow
    assert shadow is not None
    assert shadow["append_status"] == "appended"
    assert len(ledger.appended) == 1
    assert shadow["detection_event_id"] == ledger.appended[0].event_id
    assert shadow["detection_event_digest"] == event_digest(ledger.appended[0])


def test_attach_watchdog_shadow_append_failure_is_diagnostic_not_escalation() -> None:
    attached = attach_maintenance_shadow_to_result(
        _watchdog_result(ok=True),
        envelope=_eligible_envelope(),
        ledger=_RaisingLedger(),
    )
    shadow = attached.maintenance_shadow
    assert shadow is not None
    assert shadow["append_status"] == "failed"
    assert any(
        diag.startswith("detection_append_failed:") for diag in shadow["diagnostics"]
    )
    # The failed append never changes the watchdog verdict or escalation.
    assert attached.ok is True
    assert attached.requires_escalation is False


# ---------------------------------------------------------------------------
# Six-hour auditor: operational AuditReport only, never efficiency
# ---------------------------------------------------------------------------


def test_six_hour_audit_legacy_verdict_green_only_from_report_ok() -> None:
    assert six_hour_audit_legacy_verdict(_audit_report(ok=True)) == {
        "green": True,
        "dispatchable": False,
        "terminal": False,
    }
    assert six_hour_audit_legacy_verdict(_audit_report(ok=False))["green"] is False


def test_build_six_hour_audit_report_event_is_operational_only() -> None:
    event = build_six_hour_audit_report_event(_audit_report(ok=True))
    assert event.occurrence_id == "audit-1"
    assert event.idempotency_key == "audit-1"
    assert event.payload.kind == "audit_report"
    assert event.payload.report_type == "six_hour_operational"
    assert event.payload.verdict == "ok"
    assert len(event.payload.findings) == 1
    assert event.payload.findings[0].finding_id == "f1"
    # The six-hour product can never carry an efficiency payload.
    assert event.payload.kind != "efficiency_analysis"


def test_adapt_six_hour_audit_report_never_emits_efficiency_or_custody_write() -> None:
    adapted = adapt_six_hour_audit_report(_audit_report(ok=True))
    assert adapted["efficiency_analysis"] is False
    assert adapted["custody_overwrite"] is False
    assert adapted["append_status"] == "skipped"  # no ledger supplied
    assert adapted["event"]["payload"]["kind"] == "audit_report"
    assert adapted["event"]["payload"]["report_type"] == "six_hour_operational"
    assert len(adapted["event_digest"]) == 64


def test_adapt_six_hour_audit_report_shadow_match_and_would_block() -> None:
    match = adapt_six_hour_audit_report(
        _audit_report(ok=True), envelope=_eligible_non_dispatchable_envelope()
    )
    assert match["shadow"]["bucket"] == "match"
    assert match["shadow"]["green"] is True

    block = adapt_six_hour_audit_report(
        _audit_report(ok=True), envelope=_incoherent_envelope()
    )
    assert block["shadow"]["bucket"] == "would_block"
    assert block["shadow"]["green"] is False
    assert any("envelope_not_eligible" in diag for diag in block["diagnostics"])


def test_adapt_six_hour_audit_report_append_success_and_failure() -> None:
    ok_ledger = _RecordingLedger()
    appended = adapt_six_hour_audit_report(
        _audit_report(ok=True), ledger=ok_ledger
    )
    assert appended["append_status"] == "appended"
    assert len(ok_ledger.appended) == 1

    failed = adapt_six_hour_audit_report(
        _audit_report(ok=True), ledger=_RaisingLedger()
    )
    assert failed["append_status"] == "failed"
    assert any(
        diag.startswith("audit_append_failed:") for diag in failed["diagnostics"]
    )
    # A failed append never flips the operational handoff to success.
    assert failed["event"]["payload"]["verdict"] == "ok"


# ---------------------------------------------------------------------------
# Status snapshot: sibling maintenance_observation rendering
# ---------------------------------------------------------------------------


def test_render_maintenance_observation_is_deterministic_and_explicit() -> None:
    comparison = SimpleNamespace(
        bucket=SimpleNamespace(value="match"),
        reasons=(),
        stale_projection=False,
        digest_mismatch=False,
        missing_denominator=False,
        denominator=100,
        covered_count=87,
        coverage=0.87,
        projection_name="efficiency_analysis",
        projection_source_digest="a" * 64,
        projection_output_digest="b" * 64,
        green=True,
        terminal=False,
        dispatchable=False,
    )
    envelope = _eligible_envelope()
    first = render_maintenance_observation(
        envelope, comparison=comparison, projection=_projection()
    )
    second = render_maintenance_observation(
        envelope, comparison=comparison, projection=_projection()
    )
    unsigned = {key: value for key, value in first.items() if key != "view_hash"}
    recomputed = hashlib.sha256(canonical_json(unsigned).encode("utf-8")).hexdigest()
    assert first == second
    assert first["view_hash"] == second["view_hash"] == recomputed
    assert len(first["view_hash"]) == 64
    assert first["verdict"]["green"] is True
    assert first["comparison"]["bucket"] == "match"
    assert first["comparison"]["denominator"] == 100
    assert first["comparison"]["covered_count"] == 87
    assert first["comparison"]["coverage"] == pytest.approx(0.87)
    assert first["progress_inferred_from_process"] is False
    assert first["envelope"]["digest"] == canonical_digest(envelope)

    reordered = ObservationEnvelope.build(
        observed_at=_ts(),
        environment="production",
        version_vectors=[
            _vector("wbc", "production", "b" * 64),
            _vector("run_authority", "production", "a" * 64),
        ],
        completeness=CompletenessState.COMPLETE,
        freshness=FreshnessState.FRESH,
        coherence=CoherenceState.COHERENT,
    )
    assert render_maintenance_observation(
        reordered, comparison=comparison, projection=_projection()
    ) == first


def test_render_maintenance_observation_stale_projection_is_never_green() -> None:
    comparison = SimpleNamespace(
        bucket=SimpleNamespace(value="stale_projection"),
        reasons=("stale_projection",),
        stale_projection=True,
        digest_mismatch=False,
        missing_denominator=False,
        denominator=None,
        covered_count=None,
        coverage=None,
        projection_name="efficiency_analysis",
        projection_source_digest=None,
        projection_output_digest=None,
        green=False,
        terminal=False,
        dispatchable=False,
    )
    rendered = render_maintenance_observation(
        _eligible_envelope(), comparison=comparison, projection=_projection(freshness="stale")
    )
    assert rendered["comparison"]["bucket"] == "stale_projection"
    assert rendered["verdict"]["green"] is False
    assert rendered["verdict"]["terminal"] is False
    assert rendered["projection"]["freshness"] == "stale"


def test_render_maintenance_observation_missing_denominator_stays_explicit() -> None:
    comparison = SimpleNamespace(
        bucket=SimpleNamespace(value="missing_denominator"),
        reasons=("missing_denominator",),
        stale_projection=False,
        digest_mismatch=False,
        missing_denominator=True,
        denominator=None,
        covered_count=None,
        coverage=None,
        projection_name="efficiency_analysis",
        projection_source_digest=None,
        projection_output_digest=None,
        green=False,
        terminal=False,
        dispatchable=False,
    )
    rendered = render_maintenance_observation(
        _eligible_envelope(),
        comparison=comparison,
        projection=_projection(denominator=None, covered_count=None),
    )
    assert rendered["comparison"]["missing_denominator"] is True
    assert rendered["comparison"]["denominator"] is None
    assert rendered["comparison"]["coverage"] is None
    assert rendered["verdict"]["green"] is False


def test_render_maintenance_observation_missing_evidence_stays_unknown() -> None:
    rendered = render_maintenance_observation(_unknown_envelope())

    assert rendered["states"] == {
        "completeness": "unknown",
        "freshness": "unknown",
        "coherence": "unknown",
        "coherence_reasons": ["unknown"],
    }
    assert rendered["comparison"]["present"] is False
    assert rendered["comparison"]["denominator"] is None
    assert rendered["comparison"]["covered_count"] is None
    assert rendered["comparison"]["coverage"] is None
    assert rendered["projection"]["source_digest"] is None
    assert rendered["projection"]["output_digest"] is None
    assert all(rendered["verdict"][key] is False for key in (
        "eligible",
        "green",
        "terminal",
        "dispatchable",
    ))


def test_render_maintenance_observation_contradictions_never_promote() -> None:
    comparison = SimpleNamespace(
        bucket=SimpleNamespace(value="match"),
        reasons=(),
        stale_projection=False,
        digest_mismatch=False,
        missing_denominator=False,
        denominator=10,
        covered_count=10,
        coverage=1.0,
        projection_name="efficiency_analysis",
        projection_source_digest="a" * 64,
        projection_output_digest="b" * 64,
        green=True,
        terminal=True,
        dispatchable=True,
    )
    rendered = render_maintenance_observation(
        _incoherent_envelope(
            (CoherenceReason.CONTRADICTORY_EVIDENCE, CoherenceReason.CROSS_ENVIRONMENT),
            cross_env=True,
        ),
        comparison=comparison,
        projection=_projection(),
    )

    assert rendered["states"]["coherence"] == "incoherent"
    assert rendered["states"]["coherence_reasons"] == [
        "contradictory_evidence",
        "cross_environment",
    ]
    assert rendered["cross_environment"] is True
    assert all(rendered["verdict"][key] is False for key in (
        "eligible",
        "green",
        "terminal",
        "dispatchable",
    ))


def test_render_maintenance_observation_is_pure_and_sibling_call_is_scoped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    renderer_tree = ast.parse(
        textwrap.dedent(inspect.getsource(render_maintenance_observation))
    )
    called_names = {
        node.func.id
        for node in ast.walk(renderer_tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    forbidden = {
        "write_cloud_status_snapshot",
        "build_and_write_snapshot",
        "_compose_repair_decision_projection",
        "classify_repair_dispatch",
        "project_repair_custody",
        "schedule",
        "claim",
        "receipt",
        "ticket",
        "control_plane",
    }
    assert called_names.isdisjoint(forbidden)

    builder_tree = ast.parse(
        textwrap.dedent(inspect.getsource(build_cloud_status_snapshot))
    )
    sibling_calls = {
        node.func.id
        for node in ast.walk(builder_tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "render_maintenance_observation" in sibling_calls
    assert sibling_calls.isdisjoint(forbidden)

    calls: list[str] = []

    def boom(name: str) -> Any:
        def _raise(*args: Any, **kwargs: Any) -> Any:
            calls.append(name)
            raise AssertionError(f"{name} must not be reached by renderer")

        return _raise

    for name in forbidden:
        if hasattr(status_snapshot_module, name):
            monkeypatch.setattr(status_snapshot_module, name, boom(name))
    render_maintenance_observation(_eligible_envelope())
    assert calls == []

    root = Path(tempfile.mkdtemp(prefix="mrc-t1.1-test-", dir="/tmp")).resolve()
    assert root.is_relative_to(Path("/tmp").resolve())
    try:
        snapshot = build_cloud_status_snapshot(
            marker_dir=root / "markers",
            repair_data_dir=root / "repair-data",
            workspace_root=root,
            now=_ts(),
            liveness_probe=lambda marker: {"tmux": False, "process": False},
            maintenance_observation=_eligible_envelope(),
        )
        assert "maintenance_observation" in snapshot
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_build_cloud_status_snapshot_sibling_preserves_legacy_fields() -> None:
    root = Path(tempfile.mkdtemp(prefix="mrc-t1.1-test-", dir="/tmp")).resolve()
    forbidden_roots = {
        Path.cwd().resolve(),
        Path(__file__).resolve().parents[2],
        Path("/workspace").resolve(),
    }
    assert root.is_relative_to(Path("/tmp").resolve())
    assert all(
        root != candidate and not root.is_relative_to(candidate)
        for candidate in forbidden_roots
    )
    try:
        marker_dir = root / "markers"
        repair_dir = root / "repair-data"
        marker_dir.mkdir()
        repair_dir.mkdir()
        now = _ts()

        def probe(marker: dict[str, Any]) -> dict[str, Any]:
            return {"tmux": False, "process": False}

        baseline = build_cloud_status_snapshot(
            marker_dir=marker_dir,
            repair_data_dir=repair_dir,
            workspace_root=root,
            now=now,
            liveness_probe=probe,
        )
        with_observation = build_cloud_status_snapshot(
            marker_dir=marker_dir,
            repair_data_dir=repair_dir,
            workspace_root=root,
            now=now,
            liveness_probe=probe,
            maintenance_observation=_eligible_envelope(),
        )
        # The sibling key appears only when supplied; every legacy key is
        # byte-identical in both snapshots.
        assert "maintenance_observation" not in baseline
        assert "maintenance_observation" in with_observation
        # Without a shadow comparison the observation is non-green; every
        # legacy field remains unchanged.
        assert with_observation["maintenance_observation"]["verdict"]["green"] is False
        for key, value in baseline.items():
            assert with_observation[key] == value, f"legacy key {key!r} changed"
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Maintenance dispatch: shadow data on receipts, never authorization
# ---------------------------------------------------------------------------


def _receipt() -> dict[str, Any]:
    return {
        "dispatch_id": "d-1",
        "action": "restart",
        "maintenance": True,
        "required_runtime_model": "gpt-5.6-sol",
        "subprocess": {"pid": 123},
    }


def test_attach_shadow_to_receipt_unchanged_without_envelope() -> None:
    receipt = _receipt()
    assert attach_maintenance_shadow_to_receipt(receipt) is receipt
    assert attach_maintenance_shadow_to_receipt(receipt, envelope=None) is receipt


def test_attach_shadow_to_receipt_adds_data_without_authorizing() -> None:
    receipt = _receipt()
    updated = attach_maintenance_shadow_to_receipt(
        # The receipt path normalizes a NON-promoting legacy verdict, so even
        # a fully eligible green envelope cannot agree with it: the shadow is
        # data-only and a shadow pass can never authorize an effect.
        receipt, envelope=_eligible_envelope()
    )
    shadow = updated["maintenance_shadow"]
    # Legacy conservative non-promotion is a TYPED explanation: the shadow
    # bucket is explained_difference (never unexplained_difference).
    assert shadow["bucket"] == "explained_difference"
    assert shadow["green"] is False
    assert shadow["dispatchable"] is False
    assert shadow["shadow_authorizes"] is False
    assert shadow["envelope_eligible"] is True
    assert len(shadow["envelope_digest"]) == 64
    assert len(shadow["comparison_digest"]) == 64
    # Authorization fields are untouched by the shadow attachment.
    assert updated["maintenance"] is True
    assert updated["required_runtime_model"] == "gpt-5.6-sol"
    assert updated["subprocess"] == {"pid": 123}
    assert updated["action"] == "restart"


def test_attach_shadow_to_receipt_match_only_for_agreeing_non_promoting_pair() -> None:
    # A non-promoting legacy verdict (the receipt normalization) matches an
    # eligible, non-promoting envelope: the row is a match but still carries
    # no green/dispatchable promotion and never authorizes.
    envelope = ObservationEnvelope(
        schema_version=1,
        observed_at=_ts(),
        environment=EnvironmentId("production"),
        version_vectors=[
            _vector("run_authority", "production", "a" * 64),
            _vector("wbc", "production", "b" * 64),
        ],
        completeness=CompletenessState.COMPLETE,
        freshness=FreshnessState.FRESH,
        coherence=CoherenceState.COHERENT,
        coherence_reasons=(),
        terminal=False,
        green=False,
        dispatchable=False,
    )
    updated = attach_maintenance_shadow_to_receipt(_receipt(), envelope=envelope)
    shadow = updated["maintenance_shadow"]
    assert shadow["bucket"] == "match"
    assert shadow["green"] is False
    assert shadow["shadow_authorizes"] is False


def test_attach_shadow_to_receipt_fail_closed_for_incoherent_envelope() -> None:
    from arnold_pipelines.megaplan.maintenance.shadow import compare_shadow

    # A direct comparison with a PROMOTING legacy verdict against a
    # non-eligible envelope lands in would_block (fail-closed).  The receipt
    # helper itself normalizes a non-promoting legacy verdict, which is an
    # explained_difference; supplying the comparison row makes the
    # would-block semantics explicit.
    comparison = compare_shadow(
        {"green": True, "dispatchable": True, "terminal": False},
        _incoherent_envelope(),
    )
    updated = attach_maintenance_shadow_to_receipt(
        _receipt(), comparison=comparison
    )
    shadow = updated["maintenance_shadow"]
    assert shadow["bucket"] == "would_block"
    assert shadow["dispatchable"] is False
    assert shadow["shadow_authorizes"] is False


def test_direct_write_bypass_finding_is_typed_and_inert() -> None:
    plan_finding = direct_write_bypass_finding("plan", "request plan write")
    assert isinstance(plan_finding, M7BypassFinding)
    assert plan_finding.kind.value == "plan_write"
    assert plan_finding.seam == M7_SEAM
    assert plan_finding.mutation_attempted is False
    assert plan_finding.request == "request plan write"
    assert all(
        plan_finding.writer_call_counts.get(writer, 0) == 0
        for writer in FORBIDDEN_DIRECT_WRITERS
    )
    assert plan_finding.matching_writers  # inventory rows are attached as data

    chain_finding = direct_write_bypass_finding("chain", "request chain write")
    assert isinstance(chain_finding, M7BypassFinding)
    assert chain_finding.kind.value == "chain_write"
    assert chain_finding.mutation_attempted is False

    with pytest.raises(ValueError):
        direct_write_bypass_finding("ledger", "invalid kind")


# ---------------------------------------------------------------------------
# Zero lifecycle/raw writer calls across every Maintenance consumer path
# ---------------------------------------------------------------------------


@pytest.fixture
def _guarded_writers(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Monkeypatch every lifecycle/raw plan/chain writer to raise if called."""
    import arnold_pipelines.megaplan._core.state as core_state
    import arnold_pipelines.megaplan.chain.spec as chain_spec
    import arnold_pipelines.megaplan.orchestration.transition_policy as transition_policy

    calls: list[str] = []

    def _boom(name: str):
        def _raise(*args: Any, **kwargs: Any) -> Any:
            calls.append(name)
            raise AssertionError(f"{name} must never be called from Maintenance")

        return _raise

    monkeypatch.setattr(core_state, "write_plan_state", _boom("write_plan_state"))
    monkeypatch.setattr(chain_spec, "save_chain_state", _boom("save_chain_state"))
    monkeypatch.setattr(
        transition_policy, "TransitionWriter", _boom("TransitionWriter")
    )
    return calls


def test_watchdog_shadow_path_never_calls_plan_chain_writers(
    _guarded_writers: list[str],
) -> None:
    attach_maintenance_shadow_to_result(
        _watchdog_result(ok=True),
        envelope=_eligible_envelope(),
        ledger=_RecordingLedger(),
    )
    attach_maintenance_shadow_to_result(
        _watchdog_result(ok=False), envelope=_incoherent_envelope()
    )
    assert _guarded_writers == []


def test_auditor_shadow_path_never_calls_plan_chain_writers(
    _guarded_writers: list[str],
) -> None:
    adapt_six_hour_audit_report(
        _audit_report(ok=True), envelope=_eligible_envelope(), ledger=_RecordingLedger()
    )
    adapt_six_hour_audit_report(_audit_report(ok=False))
    assert _guarded_writers == []


def test_dispatch_shadow_and_bypass_never_call_plan_chain_writers(
    _guarded_writers: list[str],
) -> None:
    attach_maintenance_shadow_to_receipt(_receipt(), envelope=_eligible_envelope())
    plan_finding = direct_write_bypass_finding("plan", "direct write attempt")
    chain_finding = direct_write_bypass_finding("chain", "direct write attempt")
    assert plan_finding.mutation_attempted is False
    assert chain_finding.mutation_attempted is False
    assert _guarded_writers == []
