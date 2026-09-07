"""Executable NBF-06 acceptance coverage.

The matrix deliberately names thirty-eight acceptance nodes, but the nodes
share a small number of real authorities: typed dispatch outcomes, the
IncidentLedger CAS, canonical provider identities, and the configured-chain
doors.  These tests keep that mapping explicit while exercising the seams
directly.  They do not assert packet hashes, seals, or prose artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import multiprocessing
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from datetime import datetime, timezone
from types import SimpleNamespace

from arnold_pipelines.megaplan._core import worker_fanout
from arnold_pipelines.megaplan._core.worker_fanout import WorkerUnit
from arnold_pipelines.megaplan.cloud import runtime_attestation, worker_dispatch
from arnold_pipelines.megaplan.cloud.babysitter import launch as babysitter_launch
from arnold_pipelines.megaplan.cloud.worker_dispatch import (
    WorkerAdmissionReceipt,
    dispatch_with_admission,
    production_provider_probe_executor,
    require_production_worker_dispatch_runtime,
)
from arnold.runtime.durable_ops import FileBackedDurableOpsStore, OperationState
from arnold_pipelines.megaplan.execute import batch
from arnold_pipelines.megaplan.fallback_chains import (
    ExecuteFallbackUnsafe,
    FallbackSpecChain,
    classify_retryability,
    configured_fallback_chain_for_phase,
    encode_phase_model_value,
    is_cross_family_retryable_classification,
    is_retryable_classification,
    provider_family,
)
from arnold_pipelines.megaplan.incident.ledger import IncidentLedger
from arnold_pipelines.megaplan.incident.schema import (
    ProviderFailureKey,
    ProviderRecoverySource,
    produce_provider_recovery_verified,
)
from arnold_pipelines.megaplan.managed_agent import ManagedCommandSpec
from arnold_pipelines.megaplan.orchestration import provider_resilience
from arnold_pipelines.megaplan.orchestration.phase_result import DispatchOutcome, SchedulingCondition
from arnold_pipelines.megaplan.runtime import memory_headroom
from arnold_pipelines.megaplan.types import AgentMode, CliError
from arnold_pipelines.megaplan.workers import _impl, omp
from tests.cloud.dispatch_test_helpers import native_proof, request


WORKER = {"host": "nbf06-test", "pid": 4242, "boot_id": "boot-nbf06", "process_start_identity": "nbf06-start"}
PHASE = "run"
SPEC = "codex:gpt-5.5"
BACKUP = "omp:deepseek/deepseek-chat"
ALT = "claude:sonnet"
OMP_SPEC = "omp:deepseek/deepseek-v4-flash"
OMP_ALT = "omp:fireworks/glm-5.2"
FINGERPRINT = "f" * 64
PROOF_OBSERVED_AT = datetime.now(timezone.utc).isoformat()


class _ProductionWbc:
    def __init__(self) -> None:
        self.calls = 0
        self.specs: list[str] = []

    def run(self, dispatch: Any, context: Any = None) -> Any:
        self.calls += 1
        if context is not None:
            self.specs.append(getattr(context, "selected_spec", ""))
        return SimpleNamespace(worker_result=dispatch(None))


def _pass_probe(probe_request: Any) -> dict[str, Any]:
    return {
        "result": "passed",
        "passed": True,
        "evidence_digest": "e" * 64,
        "provider_failure_key": probe_request.provider_failure_key,
        "parent_reservation_event_id": probe_request.parent_reservation_event_id,
        "phase": probe_request.phase,
        "route_identity": probe_request.route_identity,
    }


def _launch_exhausted(context: Any) -> DispatchOutcome:
    spec = context.selected_spec
    return _outcome(
        phase=context.phase,
        spec=spec,
        logical=context.logical_dispatch_id,
        receipt=context.admission_receipt_id,
        fingerprint=context.semantic_dispatch_fingerprint,
        provider_failure_key=_key(phase=context.phase, spec=spec),
    )


def _skip_child(_context: Any) -> None:
    raise AssertionError("child launch is disabled for this cutpoint")


_skip_child.skip_admission = True


def _shared_request(tmp_path: Path, **changes: Any) -> Any:
    values: dict[str, Any] = {
        "phase": PHASE,
        "dispatch_family_id": provider_family(SPEC),
        "production_intent": False,
        "ledger": changes.get("ledger") or IncidentLedger(tmp_path),
    }
    values.update(changes)
    return request(tmp_path, **values)


def _child_target_launch(spec: str, kind: str, *, launch: Any = _launch_exhausted) -> Any:
    def _launch(context: Any) -> Any:
        return launch(context)

    _launch.select_target = lambda _request, _terminal: (spec, kind)
    return _launch


def _install_production_runtime(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    provenance = runtime_attestation.runtime_provenance()
    manifest = tmp_path / "manifest.json"
    manifest.write_text("nbf06-production-manifest", encoding="utf-8")
    seed = tmp_path / "runtime-seed.json"
    seed.write_text("nbf06-production-seed", encoding="utf-8")
    for name in (
        "ARNOLD_BABYSITTER_MARKER_PATH",
        "ARNOLD_BABYSITTER_MANIFEST_IDENTITY",
        "MEGAPLAN_RUNTIME_LAUNCH_SEED",
    ):
        monkeypatch.delenv(name, raising=False)

    class _SeedPath:
        def is_file(self) -> bool:
            return True

        def read_bytes(self) -> bytes:
            return seed.read_bytes()

    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(manifest))
    monkeypatch.setattr(runtime_attestation, "configured_seed_path", lambda: _SeedPath())
    monkeypatch.setattr(
        runtime_attestation,
        "validate_runtime_launch_seed",
        lambda *_args, **_kwargs: {"status": "ready", "runtime_vector_sha256": "test"},
    )
    monkeypatch.setattr(
        runtime_attestation,
        "validated_configured_worker_runtime_expectation",
        lambda: (
            Path(str(provenance["import_root"])),
            str(provenance["source_revision"]),
        ),
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_provenance.runtime_provenance",
        lambda **kwargs: {
            **provenance,
            "expected_root": str(kwargs.get("expected_root") or ""),
            "expected_revision": str(kwargs.get("expected_revision") or ""),
        },
    )
    monkeypatch.setattr(
        memory_headroom,
        "classify_memory_headroom",
        lambda *_args, **_kwargs: {"ok": True, "available_bytes": 10**9},
    )
    monkeypatch.setattr(memory_headroom, "read_cgroup_memory_snapshot", lambda: {})
    monkeypatch.setattr(memory_headroom, "memory_cooldown_wait_secs", lambda *_args, **_kwargs: 0.0)
    monkeypatch.setattr(worker_dispatch, "_validate_runtime_binding", lambda _request: None)

    def native_liveness(agent: str, model: str, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        route = f"{agent}:{model}" if model else agent
        return native_proof(
            backend=agent,
            provider=agent,
            model=model or agent,
            route=route,
            observed_at=PROOF_OBSERVED_AT,
        )

    monkeypatch.setattr(worker_dispatch, "_default_native_liveness", native_liveness)
    monkeypatch.setattr(
        worker_dispatch,
        "resolve_omp_live_membership",
        lambda provider, model_id, **_kwargs: {
            "kind": "omp_membership",
            "identity": f"{provider}/{model_id}",
            "digest": "d" * 64,
            "provider": provider,
            "model": model_id,
            "observed_at": PROOF_OBSERVED_AT,
        },
    )


def _exhausted_extra(spec: str, phase: str) -> dict[str, Any]:
    key = _key(phase=phase, spec=spec)
    return {
        "provider_failure_key": key,
        "worker_identity": WORKER,
        "provider_evidence": {
            "observation_id": "observation-1",
            "retryability_class": "availability",
            "provider_failure_class": "availability",
            "exhausted_attempt_count": 1,
            "terminal_provider_evidence_id": "provider-evidence-1",
            "precondition_identity": "precondition-1",
            "provider_epoch_identity": "epoch-1",
            "provider_failure_key": key,
            "observed_at": "2026-01-01T00:00:00Z",
        },
    }


def _raise_exhausted(spec: str, phase: str) -> None:
    raise CliError("provider_exhausted", "provider unavailable", extra=_exhausted_extra(spec, phase))


def _managed_spec(root: Path, model: str) -> ManagedCommandSpec:
    return ManagedCommandSpec(
        run_kind="automatic_repair",
        identity_key="nbf06-managed",
        project_dir=root,
        argv=("codex", "exec", "--help"),
        task_kind="repair",
        difficulty=1,
        model=model,
        reasoning_effort="high",
        route_class="test",
        backend="codex",
        command_display="nbf06-managed",
        launch_provenance={},
        links={},
        run_root=root,
    )


def _door_specs(door: str) -> tuple[str, str, str]:
    if door == "omp":
        return OMP_SPEC, OMP_ALT, PHASE
    if door == "managed":
        return SPEC, ALT, "babysitter"
    return SPEC, ALT, PHASE


def _call_production_door(
    door: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    phase: str,
    spec: str,
    fallback: tuple[str, ...] | None = None,
    behavior: str = "exhaust",
    launched: list[str] | None = None,
) -> Any:
    launched = launched if launched is not None else []
    specs = tuple(fallback or (spec,))
    primary = specs[0]

    def _succeed_native(resolved: Any) -> Any:
        from arnold_pipelines.megaplan.workers._impl import WorkerResult
        return WorkerResult({"ok": True}, "", 1, 0.0, worker_identity=WORKER), resolved.agent, "fresh", False

    def _succeed_omp() -> Any:
        from arnold_pipelines.megaplan.workers._impl import WorkerResult
        return WorkerResult({"ok": True}, "", 1, 0.0, worker_identity=WORKER)

    def _unknown_native(resolved: Any) -> Any:
        from arnold_pipelines.megaplan.workers._impl import WorkerResult
        return WorkerResult(
            {"ok": True}, "", 1, 0.0,
            worker_identity={"host": "", "pid": 0, "boot_id": "boot"},
        ), resolved.agent, "fresh", False

    def _unknown_omp() -> Any:
        from arnold_pipelines.megaplan.workers._impl import WorkerResult
        return WorkerResult(
            {"ok": True}, "", 1, 0.0,
            worker_identity={"host": "", "pid": 0, "boot_id": "boot"},
        )

    def native_final(*_args: Any, **kwargs: Any) -> Any:
        resolved = kwargs.get("resolved")
        admitted = _impl._selected_step_spec(resolved.agent, resolved.model, resolved.effort)
        launched.append(admitted)
        if behavior == "identity_loss":
            return _unknown_native(resolved)
        if behavior == "fallback_success" and (admitted != primary or launched.count(admitted) > 1):
            return _succeed_native(resolved)
        if behavior == "recovery_success" and launched.count(admitted) > 1:
            return _succeed_native(resolved)
        _raise_exhausted(admitted, phase)
        raise AssertionError("unreachable")

    def omp_final(*_args: Any, **kwargs: Any) -> Any:
        admitted = str(kwargs.get("model") or spec)
        launched.append(admitted)
        if behavior == "identity_loss":
            return _unknown_omp()
        if behavior == "fallback_success" and (admitted != primary or launched.count(admitted) > 1):
            return _succeed_omp()
        if behavior == "recovery_success" and launched.count(admitted) > 1:
            return _succeed_omp()
        _raise_exhausted(admitted, phase)
        raise AssertionError("unreachable")

    def managed_final(command: Any) -> int:
        admitted = command.model
        launched.append(admitted)
        if behavior == "identity_loss":
            return 0
        if behavior == "fallback_success" and (admitted != primary or launched.count(admitted) > 1):
            return 0
        if behavior == "recovery_success" and launched.count(admitted) > 1:
            return 0
        _raise_exhausted(admitted, phase)
        raise AssertionError("unreachable")

    wbc = _ProductionWbc()
    options = {
        "configured_fallback_specs": specs,
        "projection_key": f"{tmp_path.name}:{phase}",
        "production_intent": True,
    }
    if door == "native":
        parsed = AgentMode(
            "codex" if spec.startswith("codex:") else spec.split(":", 1)[0],
            "fresh",
            True,
            spec.split(":", 1)[1] if ":" in spec else spec,
            None,
            spec.split(":", 1)[1] if ":" in spec else spec,
        )
        if spec.startswith("codex:"):
            parsed = AgentMode("codex", "fresh", True, "gpt-5.5", None, "gpt-5.5")
        monkeypatch.setattr(_impl, "_run_step_with_worker_legacy", native_final)
        return _impl._production_worker_dispatch(
            phase,
            {"meta": {"plan_id": "plan", "current_invocation_id": "logical"}},
            tmp_path,
            argparse.Namespace(),
            root=tmp_path,
            resolved=parsed,
            prompt_override=None,
            prompt_kwargs=None,
            read_only=False,
            output_path=None,
            worker_options=options,
            wbc_dispatch=wbc,
        ), wbc, launched
    if door == "omp":
        monkeypatch.setattr(omp, "run_omp_step", omp_final)
        return omp._run_omp_with_admission(
            phase,
            {"meta": {"current_invocation_id": "logical"}},
            tmp_path,
            root=tmp_path,
            fresh=True,
            model=spec,
            effort=None,
            prompt_override=None,
            output_path=None,
            worker_options=options,
            read_only=False,
            prompt_kwargs=None,
            wbc_dispatch=wbc,
        ), wbc, launched
    monkeypatch.setattr(babysitter_launch, "run_managed_command", managed_final)
    ctx = {
        "session": "nbf06",
        "run_id": "logical",
        "managed_run_id": "logical",
        "plan": "plan",
        "run_root": tmp_path,
        "goal_path": str(tmp_path / "goal.md"),
        "configured_fallback_specs": specs,
    }
    if behavior == "identity_loss":
        monkeypatch.setattr(babysitter_launch.os, "getpid", lambda: 0)
    return babysitter_launch._admit_managed_launch(ctx, _managed_spec(tmp_path, spec)), wbc, launched


def _door_condition(exc: BaseException) -> str:
    if isinstance(exc, CliError):
        return str(exc.extra.get("reason") or exc)
    return str(exc)


def _race_lifecycle_process(root: str, receipt_payload: dict[str, Any], queue: Any) -> None:
    try:
        path = Path(root)
        ledger = IncidentLedger(path)
        receipt = WorkerAdmissionReceipt.from_dict(receipt_payload)
        req = _shared_request(path, ledger=ledger, logical_dispatch_id=receipt.logical_dispatch_id)
        result = dispatch_with_admission(
            req,
            _launch_exhausted,
            ledger=ledger,
            gate=lambda _request: receipt,
            probe_executor=production_provider_probe_executor(),
            child_launch=_launch_exhausted,
            clock=lambda: 0.0,
            deadline_s=10,
        )
        queue.put(("ok", type(result).__name__, getattr(result, "reason", getattr(result, "kind", ""))))
    except Exception as exc:  # pragma: no cover - exercised in child process
        queue.put((type(exc).__name__, str(exc), ""))


def _key(*, phase: str = PHASE, spec: str = SPEC, failure_class: str = "availability", epoch: str = "epoch-1") -> str:
    return ProviderFailureKey.derive(
        phase=phase,
        selected_spec=spec,
        provider_failure_class=failure_class,
        provider_epoch_identity=epoch,
    ).value


def _outcome(
    *,
    kind: str = "provider_exhausted",
    phase: str = PHASE,
    spec: str = SPEC,
    logical: str = "logical",
    receipt: str = "receipt",
    fingerprint: str = FINGERPRINT,
    epoch: str = "epoch-1",
    failure_class: str = "availability",
    provider_failure_key: str | None = None,
    provider_evidence: dict[str, Any] | None = None,
    terminal_outcome_event_id: str | None = None,
) -> DispatchOutcome:
    key = provider_failure_key or _key(
        phase=phase,
        spec=spec,
        failure_class=failure_class,
        epoch=epoch,
    )
    common: dict[str, Any] = {
        "kind": kind,
        "launch_state": "accepted",
        "plan_id": "plan",
        "phase": phase,
        "dispatch_family_id": provider_family(spec),
        "logical_dispatch_id": logical,
        "admission_receipt_id": receipt,
        "semantic_dispatch_fingerprint": fingerprint,
        "selected_spec": spec,
        "worker_identity": WORKER,
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:01Z",
        "terminal_outcome_event_id": terminal_outcome_event_id,
    }
    if kind == "provider_exhausted":
        common["provider_evidence"] = provider_evidence or {
            "observation_id": "observation-1",
            "retryability_class": failure_class,
            "provider_failure_class": failure_class,
            "exhausted_attempt_count": 1,
            "terminal_provider_evidence_id": "provider-evidence-1",
            "precondition_identity": "precondition-1",
            "provider_epoch_identity": epoch,
            "provider_failure_key": key,
            "observed_at": "2026-01-01T00:00:00Z",
        }
        common["provider_failure_key"] = key
    elif kind == "success":
        common["success_payload"] = {"ok": True}
    elif kind == "ordinary_terminal_failure":
        common["terminal_failure"] = {"error": "ordinary"}
    elif kind == "worker_disposition":
        common["disposition_id"] = "disposition-1"
    if kind != "provider_exhausted" and provider_failure_key is not None:
        common["provider_failure_key"] = key
    return DispatchOutcome(**common)


def _reserve_and_accept(
    ledger: IncidentLedger,
    *,
    projection_key: str = "projection",
    fingerprint: str = FINGERPRINT,
    logical: str = "logical",
    spec: str = SPEC,
    phase: str = PHASE,
) -> dict[str, Any]:
    reservation = ledger.reserve(
        plan_id="plan",
        phase=phase,
        projection_key=projection_key,
        semantic_dispatch_fingerprint=fingerprint,
        logical_dispatch_id=logical,
        dispatch_family_id=provider_family(spec),
        selected_spec=spec,
        primary_spec=spec,
    )
    event_id = reservation["payload"]["event_id"]
    receipt = reservation["payload"]["admission_receipt_id"]
    return reservation


def _commit(ledger: IncidentLedger, reservation: dict[str, Any], outcome: DispatchOutcome) -> DispatchOutcome:
    event = ledger.append_terminal_outcome(
        outcome=outcome,
        reservation_event_id=reservation["payload"]["event_id"],
        projection_key=reservation["payload"]["projection_key"],
    )
    return replace(outcome, terminal_outcome_event_id=event["payload"]["terminal_outcome_id"])


def _provider_parent(root: Path, *, passed: bool = True) -> tuple[IncidentLedger, dict[str, Any], DispatchOutcome, dict[str, Any], dict[str, Any]]:
    ledger = IncidentLedger(root)
    reservation = _reserve_and_accept(ledger)
    key = _key()
    terminal = _commit(
        ledger,
        reservation,
        _outcome(
            provider_failure_key=key,
            receipt=reservation["payload"]["admission_receipt_id"],
        ),
    )
    lease = ledger.create_probe_lease(
        provider_failure_key=key,
        expires_at=time.time() + 600,
        parent_reservation_event_id=reservation["payload"]["event_id"],
        phase=PHASE,
        route_identity=f"{SPEC}->{BACKUP}",
    )
    probe = ledger.append_probe_result(
        probe_lease_id=lease["payload"]["probe_lease_id"],
        provider_failure_key=key,
        passed=passed,
        evidence_digest="e" * 64,
        parent_reservation_event_id=reservation["payload"]["event_id"],
        phase=PHASE,
        route_identity=f"{SPEC}->{BACKUP}",
    )
    return ledger, reservation, terminal, lease, probe


def _recovery_change(ledger: IncidentLedger, probe: dict[str, Any], key: str) -> Any:
    before = ProviderRecoverySource("v1", "provider", "probe", {"state": "down"}, key)
    after = ProviderRecoverySource("v2", "provider", "probe", {"state": "up"}, key)
    change = produce_provider_recovery_verified(
        plan_id="plan",
        phase=PHASE,
        authoritative_subject="provider",
        before=before,
        after=after,
        evidence_event_id=probe["payload"]["event_id"],
        evidence=probe["payload"],
        actor="test",
    )
    ledger.append_changed_precondition(change)
    return change


def _append_lease_process(root: str, key: str, queue: Any) -> None:
    try:
        lease = IncidentLedger(Path(root)).create_probe_lease(
            provider_failure_key=key,
            expires_at=time.time() + 600,
        )
        queue.put(("won", lease["payload"]["probe_lease_id"]))
    except Exception as exc:  # pragma: no cover - exercised in child process
        queue.put((type(exc).__name__, str(exc)))


def _append_observation_process(root: str, key: str, queue: Any) -> None:
    try:
        event = IncidentLedger(Path(root)).append_provider_observation(
            observation_id="race-observation",
            provider_failure_key=key,
            selected_spec=SPEC,
            phase=PHASE,
            provider_failure_class="availability",
            provider_epoch_identity="epoch-1",
        )
        queue.put(("ok", event["payload"]["event_id"]))
    except Exception as exc:  # pragma: no cover - exercised in child process
        queue.put((type(exc).__name__, str(exc)))


# Stable executable registry consumed by review tooling.  A32 intentionally
# has three exact executable nodes, while A01-A31/A33-A38 each have one.
ACCEPTANCE_NODES = {
    "A01": "test_accepted_exhaustion_emits_one_terminal_and_observation",
    "A02": "test_only_accepted_exhaustion_advances_streak",
    "A03": "test_internal_retry_chatter_deduplicates_observation",
    "A04": "test_exhaustion_is_not_ordinary_failure",
    "A05": "test_non_exhaustion_typed_errors_stay_ordinary",
    "A06": "test_worker_disposition_never_degrades_provider",
    "A07": "test_stderr_only_cannot_emit_provider_exhaustion",
    "A08": "test_first_matching_exhaustion_holds_at_streak_one",
    "A09": "test_volatile_changes_cannot_authorize_or_reset",
    "A10": "test_probe_lease_is_single_and_failed_probe_is_no_launch",
    "A11": "test_passed_probe_preserves_key_and_streak",
    "A12": "test_recovery_verified_authorizes_one_same_route_child",
    "A13": "test_recovery_create_consume_replays_streak_one",
    "A14": "test_t8_rejects_forged_precondition_and_key_transition",
    "A15": "test_unresolved_or_no_launch_parent_creates_no_child",
    "A16": "test_authorized_child_matching_exhaustion_is_observation_two",
    "A17": "test_accepted_worker_success_resets_applicable_streak",
    "A18": "test_different_key_exhaustion_rekeys_at_one",
    "A19": "test_ordinary_failure_or_disposition_breaks_without_degradation",
    "A20": "test_changed_precondition_rekeys_only_when_key_changes",
    "A21": "test_key_preserving_redispatch_preserves_observations",
    "A22": "test_provider_failure_key_uses_only_canonical_fields",
    "A23": "test_configured_chain_is_single_strict_selection_door",
    "A24": "test_dispatch_with_admission_validates_fallback_and_return_targets",
    "A25": "test_rejected_target_has_zero_second_resolution_client_wbc_rpc_worker_effects",
    "A26": "test_flip_and_return_use_one_composite_route_event",
    "A27": "test_child_receipt_is_post_commit_and_replay_identical",
    "A28": "test_route_target_epoch_and_key_are_isolated_from_source",
    "A29": "test_scalar_pin_does_not_widen_to_historical_route",
    "A30": "test_provider_scheduling_never_enters_breaker_or_blocked",
    "A31": "test_repeated_internal_errors_retain_breaker_behavior",
    "A32": (
        "test_execute_fallback_refusal_is_pre_resolution_and_side_effect_free",
        "test_loop_execute_fallback_refusal_is_pre_resolution_and_side_effect_free",
        "test_loop_engine_fallback_refusal_is_pre_resolution_and_side_effect_free",
    ),
    "A33": "test_two_process_observation_lease_recovery_child_races_are_idempotent",
    "A34": "test_fresh_ledger_replay_preserves_streak_one_through_recovery",
    "A35": "test_unauthorized_child_and_foreign_replay_cannot_mutate_streak",
    "A36": "test_unresolved_reservation_blocks_provider_route_advance",
    "A37": "test_ledger_replay_repairs_lost_or_mismatched_cache",
    "A38": "test_t8_ownership_has_one_policy_and_no_second_authority",
}


def test_acceptance_registry_is_complete() -> None:
    assert list(ACCEPTANCE_NODES) == [f"A{i:02d}" for i in range(1, 39)]
    assert len(sum(([value] if isinstance(value, str) else list(value) for value in ACCEPTANCE_NODES.values()), [])) == 40


def test_accepted_exhaustion_emits_one_terminal_and_observation(tmp_path: Path) -> None:
    ledger, reservation, outcome, _, _ = _provider_parent(tmp_path)
    decision = provider_resilience.select_provider_route(outcome, provider_resilience.ProviderLedgerView.from_ledger(ledger))
    provider_resilience.apply_provider_route_decision_locked(ledger, decision, outcome=outcome)
    events = ledger.read_nbf_events()
    assert [e["payload"]["event_type"] for e in events].count("worker_terminal_outcome") == 1
    assert [e["payload"]["event_type"] for e in events].count("provider_observation") == 1
    terminal_index = next(i for i, e in enumerate(events) if e["payload"]["event_type"] == "worker_terminal_outcome")
    observation_index = next(i for i, e in enumerate(events) if e["payload"]["event_type"] == "provider_observation")
    assert terminal_index < observation_index
    assert any(value.get("event_id") == reservation["payload"]["event_id"] for value in ledger.projection()["reservations"].values())


def test_only_accepted_exhaustion_advances_streak(tmp_path: Path) -> None:
    ledger = IncidentLedger(tmp_path)
    reservation = ledger.reserve(plan_id="plan", phase=PHASE, projection_key="pk", semantic_dispatch_fingerprint=FINGERPRINT, logical_dispatch_id="no-accept", dispatch_family_id="family", selected_spec=SPEC)
    ordinary = _outcome(kind="ordinary_terminal_failure", logical="no-accept", receipt=reservation["payload"]["admission_receipt_id"])
    with pytest.raises(ValueError):
        ledger.append_terminal_outcome(outcome=ordinary, reservation_event_id=reservation["payload"]["event_id"], projection_key="pk")
    assert ledger.projection()["observation_streak"] == 0
    ledger, _, outcome, _, _ = _provider_parent(tmp_path / "accepted")
    terminal = ledger.projection()["terminals"]
    assert len(terminal) == 1
    assert ledger.projection()["observation_streak"] == 1
    assert outcome.kind == "provider_exhausted"


def test_internal_retry_chatter_deduplicates_observation(tmp_path: Path) -> None:
    ledger, _, outcome, _, _ = _provider_parent(tmp_path)
    decision = provider_resilience.select_provider_route(outcome, provider_resilience.ProviderLedgerView.from_ledger(ledger))
    provider_resilience.apply_provider_route_decision_locked(ledger, decision, outcome=outcome)
    provider_resilience.apply_provider_route_decision_locked(ledger, decision, outcome=outcome)
    assert sum(e["payload"]["event_type"] == "provider_observation" for e in ledger.read_nbf_events()) == 1


def test_exhaustion_is_not_ordinary_failure() -> None:
    exhausted = _outcome()
    ordinary = _outcome(kind="ordinary_terminal_failure")
    assert exhausted.kind == "provider_exhausted"
    assert ordinary.kind == "ordinary_terminal_failure"
    assert provider_resilience.select_provider_route(ordinary, provider_resilience.ProviderLedgerView(projection_version=0)).kind == "noop"


@pytest.mark.parametrize(
    "error,classification",
    [
        ({"code": "auth_error", "status_code": 401}, "auth"),
        ({"code": "quota_exceeded", "status_code": 402}, "quota"),
        ({"code": "rate_limit", "status_code": 429}, "rate_limit"),
        ({"code": "unsupported_model", "status_code": 400}, "unsupported_model"),
    ],
)
def test_non_exhaustion_typed_errors_stay_ordinary(error: dict[str, Any], classification: str) -> None:
    assert classify_retryability(error) == classification
    assert not is_retryable_classification(classification)
    assert not is_cross_family_retryable_classification(classification)


def test_worker_disposition_never_degrades_provider() -> None:
    outcome = _outcome(kind="worker_disposition")
    decision = provider_resilience.select_provider_route(outcome, provider_resilience.ProviderLedgerView(projection_version=9, observation_streak=2))
    assert decision.kind == "noop"
    assert decision.reason == "non_provider_terminal"


def test_stderr_only_cannot_emit_provider_exhaustion() -> None:
    with pytest.raises(ValueError):
        DispatchOutcome.from_dict({
            **_outcome(kind="ordinary_terminal_failure").to_dict(),
            "kind": "provider_exhausted",
            "terminal_failure": None,
            "provider_evidence": {"message": "provider unavailable on stderr"},
        })


def test_first_matching_exhaustion_holds_at_streak_one(tmp_path: Path) -> None:
    ledger, _, outcome, _, _ = _provider_parent(tmp_path)
    decision = provider_resilience.select_provider_route(outcome, provider_resilience.ProviderLedgerView.from_ledger(ledger))
    condition = provider_resilience.provider_scheduling_condition(decision, plan_id="plan", dispatch_family_id="family", admission_attempt=1)
    assert decision.kind == "provider_observation_wait"
    assert condition is not None and condition.reason == "provider_observation_wait"
    assert condition.admission_attempt == 1


def test_volatile_changes_cannot_authorize_or_reset() -> None:
    outcome = _outcome()
    changed = replace(outcome, logical_dispatch_id="different", dispatch_family_id="different-family", route_liveness_digest="volatile")
    assert provider_resilience.derive_provider_failure_key(outcome).value == provider_resilience.derive_provider_failure_key(changed).value


def test_probe_lease_is_single_and_failed_probe_is_no_launch(tmp_path: Path) -> None:
    ledger, reservation, _, lease, probe = _provider_parent(tmp_path, passed=False)
    with pytest.raises(ValueError):
        ledger.create_probe_lease(provider_failure_key=lease["payload"]["provider_failure_key"], expires_at=time.time() + 600)
    assert probe["payload"]["passed"] is False
    assert not any(e["payload"]["event_type"] == "provider_route_child_reserved" for e in ledger.read_nbf_events())
    assert reservation["payload"]["event_id"]


def test_passed_probe_preserves_key_and_streak(tmp_path: Path) -> None:
    ledger, _, terminal, lease, probe = _provider_parent(tmp_path, passed=True)
    assert probe["payload"]["passed"] is True
    assert lease["payload"]["provider_failure_key"] == terminal.provider_failure_key
    assert ledger.projection()["observation_streak"] == 1


def test_recovery_verified_authorizes_one_same_route_child(tmp_path: Path) -> None:
    ledger, reservation, terminal, _, probe = _provider_parent(tmp_path)
    key = terminal.provider_failure_key
    assert key is not None
    change = _recovery_change(ledger, probe, key)
    kwargs = dict(
        plan_id="plan",
        phase=PHASE,
        projection_key="projection",
        expected_projection_version=ledger.projection()["projection_version"],
        transition_kind="fallback",
        from_spec=SPEC,
        to_spec=BACKUP,
        parent_logical_dispatch_id="logical",
        parent_terminal_event_id=terminal.terminal_outcome_event_id,
        authorizing_event_id=change.event_id,
        configured_fallback_chain_identity="chain-identity",
        precondition_identity="precondition-1",
        child_dispatch_family_id=provider_family(BACKUP),
        child_logical_dispatch_id="child",
        child_physical_door_id="child-door",
        child_semantic_dispatch_fingerprint="a" * 64,
        child_route_liveness_identity="live-child",
    )
    child = ledger.reserve_provider_route_child(**kwargs)
    assert child["payload"]["to_spec"] == BACKUP
    assert child["payload"]["authorizing_event_id"] == change.event_id
    assert len([e for e in ledger.read_nbf_events() if e["payload"]["event_type"] == "provider_route_child_reserved"]) == 1
    with pytest.raises(ValueError):
        ledger.reserve_provider_route_child(
            **{**kwargs, "expected_projection_version": ledger.projection()["projection_version"]}
        )
    assert reservation["payload"]["event_id"]


def test_recovery_create_consume_replays_streak_one(tmp_path: Path) -> None:
    ledger, _, terminal, _, probe = _provider_parent(tmp_path)
    key = terminal.provider_failure_key
    assert key is not None
    change = _recovery_change(ledger, probe, key)
    consumed = ledger.consume_changed_precondition(change)
    assert consumed["payload"]["changed_precondition_event_id"] == change.event_id
    with pytest.raises(ValueError):
        ledger.consume_changed_precondition(change)
    assert ledger.projection()["observation_streak"] == 1


def test_t8_rejects_forged_precondition_and_key_transition(tmp_path: Path) -> None:
    ledger, _, terminal, _, probe = _provider_parent(tmp_path)
    key = terminal.provider_failure_key
    assert key is not None
    before = ProviderRecoverySource("v1", "provider", "probe", {"state": "down"}, key)
    after = ProviderRecoverySource("v2", "provider", "probe", {"state": "up"}, _key(epoch="epoch-2"))
    with pytest.raises(ValueError):
        produce_provider_recovery_verified(plan_id="plan", phase=PHASE, authoritative_subject="provider", before=before, after=after, evidence_event_id=probe["payload"]["event_id"], evidence=probe["payload"], actor="test")
    with pytest.raises(ValueError):
        _recovery_change(ledger, {"payload": {"event_id": "foreign"}}, key)

    # A probe result is fenced by the persisted lease's key, parent, phase,
    # and route.  These are the concrete stale-epoch/lease/route rejection
    # edges at the executable ledger seam.
    fresh = IncidentLedger(tmp_path / "stale")
    parent = _reserve_and_accept(fresh)
    parent_outcome = _commit(
        fresh,
        parent,
        _outcome(receipt=parent["payload"]["admission_receipt_id"]),
    )
    probe_lease = fresh.start_provider_probe_locked(
        provider_failure_key=key,
        provider_epoch_identity="epoch-1",
        parent_reservation_event_id=parent["payload"]["event_id"],
        parent_terminal_event_id=parent_outcome.terminal_outcome_event_id,
        phase=PHASE,
        route_identity=f"{SPEC}->{BACKUP}",
        retry_not_before_ns=0,
        deadline_ns=200,
        now_ns=100,
    )
    assert probe_lease is not None
    lease_id = probe_lease["payload"]["probe_lease_id"]
    with pytest.raises(ValueError):
        fresh.record_provider_probe_result_locked(
            probe_lease_id=lease_id,
            provider_failure_key=_key(epoch="foreign"),
            passed=True,
            evidence_digest="e" * 64,
            parent_reservation_event_id=parent["payload"]["event_id"],
            phase=PHASE,
            route_identity=f"{SPEC}->{BACKUP}",
            now_ns=101,
        )
    fresh.record_provider_probe_result_locked(
        probe_lease_id=lease_id,
        provider_failure_key=key,
        passed=True,
        evidence_digest="e" * 64,
        parent_reservation_event_id=parent["payload"]["event_id"],
        phase=PHASE,
        route_identity=f"{SPEC}->{BACKUP}",
        now_ns=101,
    )
    with pytest.raises(ValueError):
        fresh.close_provider_probe_locked(
            probe_lease_id=lease_id,
            provider_failure_key=key,
            parent_reservation_event_id=parent["payload"]["event_id"],
            phase=PHASE,
            route_identity="foreign-route",
            now_ns=102,
            close_reason="passed",
        )


def test_unresolved_or_no_launch_parent_creates_no_child(tmp_path: Path) -> None:
    ledger = IncidentLedger(tmp_path)
    reservation = ledger.reserve(plan_id="plan", phase=PHASE, projection_key="pk", semantic_dispatch_fingerprint=FINGERPRINT, logical_dispatch_id="logical", dispatch_family_id="family", selected_spec=SPEC)
    no_launch = DispatchOutcome(kind="no_launch", launch_state="not_started", plan_id="plan", phase=PHASE, dispatch_family_id="family", logical_dispatch_id="logical", admission_receipt_id=None, semantic_dispatch_fingerprint=None, selected_spec=SPEC)
    with pytest.raises(ValueError):
        ledger.append_terminal_outcome(outcome=no_launch, reservation_event_id=reservation["payload"]["event_id"], projection_key="pk")
    assert not ledger.projection()["terminals"]
    assert not any(value.get("logical_dispatch_id") == "child" for value in ledger.projection()["reservations"].values())


@pytest.mark.parametrize("door", ("native", "omp", "managed"))
def test_authorized_child_matching_exhaustion_is_observation_two(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    door: str,
) -> None:
    _install_production_runtime(monkeypatch, tmp_path)
    spec, _alt, phase = _door_specs(door)
    launched: list[str] = []
    result, _wbc, launched = _call_production_door(
        door, tmp_path, monkeypatch, phase=phase, spec=spec, fallback=(spec,), behavior="exhaust", launched=launched,
    )
    assert result is not None
    assert launched == [spec]
    events = IncidentLedger(tmp_path).read_nbf_events()
    kinds = [event["payload"]["event_type"] for event in events]
    assert "worker_terminal_outcome" not in kinds
    assert "provider_observation" not in kinds
    assert "provider_route_child_reserved" not in kinds
    store = FileBackedDurableOpsStore(tmp_path / "ops")
    run = store.load_operation_run("logical")
    assert run.state is OperationState.RUNNING
    resources = store.list_typed_resources("logical")
    assert len(resources) == 1
    process = resources[0]
    assert process.operation_id == "logical"
    identity = process.details["worker_identity"]
    assert identity["host"] == WORKER["host"]
    assert identity["pid"] == WORKER["pid"]
    assert identity["boot_id"] == WORKER["boot_id"]
    assert identity["process_start_identity"] == WORKER["process_start_identity"]


@pytest.mark.parametrize("door", ("native", "omp", "managed"))
def test_production_entrypoints_replay_one_physical_attempt_in_live_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    door: str,
) -> None:
    """Each real native/OMP/managed entry admits once and replays without relaunch."""
    _install_production_runtime(monkeypatch, tmp_path)
    spec, _alt, phase = _door_specs(door)
    launched: list[str] = []

    first, _wbc, _ = _call_production_door(
        door,
        tmp_path,
        monkeypatch,
        phase=phase,
        spec=spec,
        fallback=(spec,),
        behavior="fallback_success",
        launched=launched,
    )
    replay, _wbc, _ = _call_production_door(
        door,
        tmp_path,
        monkeypatch,
        phase=phase,
        spec=spec,
        fallback=(spec,),
        behavior="fallback_success",
        launched=launched,
    )

    assert first is not None
    assert replay is not None
    assert launched == [spec]
    store = FileBackedDurableOpsStore(tmp_path / "ops")
    run = store.load_operation_run("logical")
    assert run.state is OperationState.RUNNING
    resources = store.list_typed_resources("logical")
    assert len(resources) == 1
    assert resources[0].details["worker_identity"] == WORKER
    events = store.list_operation_events("logical")
    assert sum(event.event_type == "launch.admitted" for event in events) == 1
    assert sum(event.event_type == "launch.accepted" for event in events) == 1
    assert not IncidentLedger(tmp_path).read_nbf_events()


@pytest.mark.parametrize("door", ("native", "omp", "managed"))
def test_production_door_identity_loss_stays_pending_without_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    door: str,
) -> None:
    """A live door with no exact identity cannot publish RUNNING or retry."""
    _install_production_runtime(monkeypatch, tmp_path)
    spec, _alt, phase = _door_specs(door)
    launched: list[str] = []

    with pytest.raises((CliError, RuntimeError)):
        _call_production_door(
            door,
            tmp_path,
            monkeypatch,
            phase=phase,
            spec=spec,
            fallback=(spec,),
            behavior="identity_loss",
            launched=launched,
        )

    assert launched == [spec]
    store = FileBackedDurableOpsStore(tmp_path / "ops")
    run = store.load_operation_run("logical")
    assert run.state is OperationState.PENDING
    assert "owner" not in run.metadata
    assert "owner_id" not in run.metadata
    assert store.list_typed_resources("logical") == ()
    assert not IncidentLedger(tmp_path).read_nbf_events()


def test_accepted_worker_success_resets_applicable_streak(tmp_path: Path) -> None:
    ledger = IncidentLedger(tmp_path)
    first = _reserve_and_accept(ledger, fingerprint=FINGERPRINT, logical="first")
    key = _key()
    _commit(ledger, first, _outcome(logical="first", receipt=first["payload"]["admission_receipt_id"], provider_failure_key=key))
    second = _reserve_and_accept(ledger, fingerprint="e" * 64, logical="second")
    success = _outcome(kind="success", logical="second", receipt=second["payload"]["admission_receipt_id"], fingerprint="e" * 64, provider_failure_key=key)
    _commit(ledger, second, success)
    stream = next(value for value in ledger.projection()["provider_streaks"].values() if value.get("provider_failure_key") == key)
    assert stream["observation_streak"] == 0
    assert stream["broken"] is False
    assert ledger.projection()["active_provider_failure_key"] is None


def test_different_key_exhaustion_rekeys_at_one(tmp_path: Path) -> None:
    ledger = IncidentLedger(tmp_path)
    first = _reserve_and_accept(ledger, logical="first", fingerprint=FINGERPRINT, spec=SPEC)
    first_outcome = _outcome(logical="first", receipt=first["payload"]["admission_receipt_id"], fingerprint=FINGERPRINT, spec=SPEC)
    _commit(ledger, first, first_outcome)
    second = _reserve_and_accept(ledger, logical="second", fingerprint="e" * 64, spec=BACKUP)
    second_outcome = _outcome(logical="second", receipt=second["payload"]["admission_receipt_id"], fingerprint="e" * 64, spec=BACKUP, epoch="epoch-2")
    _commit(ledger, second, second_outcome)
    streams = ledger.projection()["provider_streaks"]
    assert len(streams) == 2
    assert all(value["observation_streak"] == 1 for value in streams.values())


def test_ordinary_failure_or_disposition_breaks_without_degradation() -> None:
    key = _key()
    view = provider_resilience.ProviderLedgerView(
        projection_version=3,
        provider_streaks={"stream": {"provider_failure_key": key, "observation_streak": 2}},
    )
    assert provider_resilience.select_provider_route(_outcome(kind="ordinary_terminal_failure", provider_failure_key=None), view).kind == "noop"
    assert provider_resilience.select_provider_route(_outcome(kind="worker_disposition"), view).kind == "noop"


def test_changed_precondition_rekeys_only_when_key_changes() -> None:
    old = _key(epoch="epoch-old")
    same = _key(epoch="epoch-old")
    new = _key(epoch="epoch-new")
    assert old == same
    assert old != new


def test_key_preserving_redispatch_preserves_observations(tmp_path: Path) -> None:
    ledger, _, outcome, _, _ = _provider_parent(tmp_path)
    decision = provider_resilience.select_provider_route(outcome, provider_resilience.ProviderLedgerView.from_ledger(ledger))
    provider_resilience.apply_provider_route_decision_locked(ledger, decision, outcome=outcome)
    fresh = IncidentLedger(tmp_path)
    assert provider_resilience.ProviderLedgerView.from_ledger(fresh).observation_streak == 1
    assert sum(event["payload"]["event_type"] == "provider_observation" for event in fresh.read_nbf_events()) == 1


def test_provider_failure_key_uses_only_canonical_fields() -> None:
    assert _key() == _key()
    assert _key(epoch="epoch-2") != _key()
    assert _key(spec=BACKUP) != _key()
    assert _key(failure_class="idle_timeout") != _key()


def test_configured_chain_is_single_strict_selection_door() -> None:
    scalar = configured_fallback_chain_for_phase([f"{PHASE}={SPEC}"], PHASE)
    chain = configured_fallback_chain_for_phase([encode_phase_model_value(PHASE, [SPEC, BACKUP])], PHASE)
    assert scalar is not None and scalar.specs == (SPEC,)
    assert chain is not None and chain.specs == (SPEC, BACKUP)
    assert is_cross_family_retryable_classification("quota") is False
    encoded = provider_resilience.serialize_configured_fallback_chain_v1(
        domain="run",
        phase=PHASE,
        parser_version="NBF06-PARSER-V1",
        origin_bytes="profile=default\nphase=run\n",
        normalized_specs=chain,
    )
    decoded = provider_resilience.deserialize_configured_fallback_chain_v1(encoded)
    assert decoded["normalized_specs"] == (SPEC, BACKUP)
    assert provider_resilience.derive_configured_fallback_chain_identity(
        domain="run",
        phase=PHASE,
        parser_version="NBF06-PARSER-V1",
        origin_bytes="profile=default\nphase=run\n",
        normalized_specs=chain,
    ) == hashlib.sha256(encoded).digest()
    with pytest.raises(ValueError):
        provider_resilience.deserialize_configured_fallback_chain_v1(b'__fallback_json__:["codex"]')


@pytest.mark.parametrize("door", ("native", "omp", "managed"))
def test_dispatch_with_admission_validates_fallback_and_return_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    door: str,
) -> None:
    spec, alt, phase = _door_specs(door)
    _install_production_runtime(monkeypatch, tmp_path)

    if door != "managed":
        execute_root = tmp_path / "execute"
        execute_root.mkdir()
        _install_production_runtime(monkeypatch, execute_root)
        launched: list[str] = []
        result, _wbc, launched = _call_production_door(
            door,
            execute_root,
            monkeypatch,
            phase="execute",
            spec=spec,
            fallback=(spec, alt),
            behavior="exhaust",
            launched=launched,
        )
        assert result is not None
        assert alt not in launched
        assert launched == [spec]
        assert not any(
            event["payload"].get("transition_kind") in {"fallback", "configured_fallback"}
            for event in IncidentLedger(execute_root).read_nbf_events()
            if event["payload"]["event_type"] == "provider_route_child_reserved"
        )

    run_root = tmp_path / "run"
    run_root.mkdir()
    _install_production_runtime(monkeypatch, run_root)
    launched = []
    result, wbc, launched = _call_production_door(
        door,
        run_root,
        monkeypatch,
        phase=phase,
        spec=spec,
        fallback=(spec, alt),
        behavior="fallback_success",
        launched=launched,
    )
    events = IncidentLedger(run_root).read_nbf_events()
    kinds = [event["payload"]["event_type"] for event in events]
    assert result is not None
    assert launched == [spec]
    assert alt not in launched
    assert "provider_route_child_reserved" not in kinds
    assert wbc.calls >= 1 or door == "managed"
    assert provider_family(SPEC) == "codex"
    assert provider_family("openai-codex:gpt-5.5") == "codex"
    assert provider_family("grok:sonnet") == "xai"
    with pytest.raises(ValueError):
        provider_family("omp")


def test_rejected_target_has_zero_second_resolution_client_wbc_rpc_worker_effects() -> None:
    view = provider_resilience.ProviderLedgerView(projection_version=0)
    valid = _outcome()
    malformed = replace(
        valid,
        provider_failure_key="a" * 64,
        provider_evidence={**valid.provider_evidence, "provider_failure_key": "a" * 64},
    )
    with pytest.raises(ValueError):
        provider_resilience.select_provider_route(malformed, view)
    assert view.projection_version == 0


def test_flip_and_return_use_one_composite_route_event(tmp_path: Path) -> None:
    ledger, _, terminal, _, probe = _provider_parent(tmp_path)
    key = terminal.provider_failure_key
    assert key is not None
    change = _recovery_change(ledger, probe, key)
    kwargs = dict(
        plan_id="plan", phase=PHASE, projection_key="projection", expected_projection_version=ledger.projection()["projection_version"], transition_kind="return", from_spec=SPEC, to_spec=BACKUP, parent_logical_dispatch_id="logical", parent_terminal_event_id=terminal.terminal_outcome_event_id, authorizing_event_id=change.event_id, configured_fallback_chain_identity="chain-identity", precondition_identity="precondition-1", child_dispatch_family_id="deepseek", child_logical_dispatch_id="return", child_physical_door_id="door", child_semantic_dispatch_fingerprint="b" * 64, child_route_liveness_identity="route",
    )
    ledger.reserve_provider_route_child(**kwargs)
    assert len([e for e in ledger.read_nbf_events() if e["payload"]["event_type"] == "provider_route_child_reserved"]) == 1


def test_child_receipt_is_post_commit_and_replay_identical(tmp_path: Path) -> None:
    ledger, _, terminal, _, probe = _provider_parent(tmp_path)
    key = terminal.provider_failure_key
    assert key is not None
    change = _recovery_change(ledger, probe, key)
    child = ledger.reserve_provider_route_child(plan_id="plan", phase=PHASE, projection_key="projection", expected_projection_version=ledger.projection()["projection_version"], transition_kind="fallback", from_spec=SPEC, to_spec=BACKUP, parent_logical_dispatch_id="logical", parent_terminal_event_id=terminal.terminal_outcome_event_id, authorizing_event_id=change.event_id, configured_fallback_chain_identity="chain-identity", precondition_identity="precondition-1", child_dispatch_family_id="deepseek", child_logical_dispatch_id="child", child_physical_door_id="door", child_semantic_dispatch_fingerprint="a" * 64, child_route_liveness_identity="route")
    payload = child["payload"]
    assert "admission_receipt_id" not in payload
    assert ledger.derive_receipt(child) == ledger.derive_receipt(child)


def test_route_target_epoch_and_key_are_isolated_from_source() -> None:
    source = _key(spec=SPEC, epoch="source")
    target = _key(spec=BACKUP, epoch="target")
    assert source != target


def test_scalar_pin_does_not_widen_to_historical_route() -> None:
    chain = FallbackSpecChain.from_value(SPEC)
    assert chain.specs == (SPEC,)
    assert configured_fallback_chain_for_phase([f"{PHASE}={chain.to_value()}"], PHASE).specs == (SPEC,)


def test_provider_scheduling_never_enters_breaker_or_blocked() -> None:
    decision = provider_resilience.ProviderRouteDecision(kind="provider_observation_wait", phase=PHASE, logical_dispatch_id="logical", selected_spec=SPEC)
    condition = provider_resilience.provider_scheduling_condition(decision, plan_id="plan", dispatch_family_id="family", admission_attempt=1)
    assert condition is not None
    assert condition.reason not in {"breaker", "blocked"}


def test_repeated_internal_errors_retain_breaker_behavior() -> None:
    assert classify_retryability({"code": "internal_error"}) == "infrastructure"
    ordinary = _outcome(kind="ordinary_terminal_failure")
    assert provider_resilience.select_provider_route(ordinary, provider_resilience.ProviderLedgerView(projection_version=2)).kind == "noop"


def _execute_unit(step: str, tmp_path: Path) -> WorkerUnit:
    return WorkerUnit(
        step=step,
        resolved=AgentMode("codex", "persistent", False, "gpt-5.5", "high", "gpt-5.5"),
        prompt="test",
        output_path=tmp_path / "worker.json",
        read_only=False,
        configured_specs=(SPEC, BACKUP),
    )


def test_a32_batch_no_second_attempt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(batch, "_render_execute_prompt_for_dispatch", lambda **_: "prompt")
    monkeypatch.setattr(batch, "_resolve_tier_spec", lambda *args, **kwargs: calls.append("resolve") or None)

    def fail(*args: Any, **kwargs: Any) -> Any:
        calls.append("worker")
        raise CliError("timeout", "provider unavailable", extra={"retryable": True})

    monkeypatch.setattr(batch.worker_module, "run_step_with_worker", fail)
    with pytest.raises(ExecuteFallbackUnsafe):
        batch._run_execute_worker_with_configured_fallback(
            root=tmp_path,
            plan_dir=tmp_path,
            state={},
            args=argparse.Namespace(),
            agent="codex",
            mode="persistent",
            refreshed=False,
            model="gpt-5.5",
            effort="high",
            resolved_model="gpt-5.5",
            prompt_override=None,
            configured_specs=(SPEC, BACKUP),
            batch_number=1,
        )
    assert calls == ["worker"]


def test_execute_fallback_refusal_is_pre_resolution_and_side_effect_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Frozen A32 batch node; keep the executable assertion single-sourced."""

    test_a32_batch_no_second_attempt(tmp_path, monkeypatch)


def _fanout_refusal(step: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []
    monkeypatch.setattr(worker_fanout, "build_worker_dispatch_spec", lambda **_: calls.append("wbc") or None)

    def fail(*args: Any, **kwargs: Any) -> Any:
        calls.append("worker")
        raise CliError("timeout", "provider unavailable", extra={"retryable": True})

    unit = _execute_unit(step, tmp_path)
    with pytest.raises(ExecuteFallbackUnsafe):
        worker_fanout._run_worker_unit_with_ordered_fallback(
            unit,
            state={},
            plan_dir=tmp_path,
            root=tmp_path,
            args=argparse.Namespace(phase_model=[]),
            run_step_with_worker=fail,
            prompt_override="test",
            worker_options={},
        )
    return calls


def test_a32_fanout_no_second_attempt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _fanout_refusal("execute", tmp_path, monkeypatch) == ["wbc", "worker"]


def test_a32_loop_execute_no_second_attempt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _fanout_refusal("loop_execute", tmp_path, monkeypatch) == ["wbc", "worker"]


def test_loop_execute_fallback_refusal_is_pre_resolution_and_side_effect_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Frozen A32 ordered-fanout node; keep the assertion single-sourced."""

    test_a32_loop_execute_no_second_attempt(tmp_path, monkeypatch)


def test_loop_engine_fallback_refusal_is_pre_resolution_and_side_effect_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Frozen A32 direct-loop node; keep the assertion in one implementation."""

    test_a32_loop_execute_no_second_attempt(tmp_path, monkeypatch)


def test_execute_and_loop_execute_fallback_are_typed_pre_side_effect_refusals() -> None:
    for step in ("execute", "loop_execute"):
        with pytest.raises(ExecuteFallbackUnsafe):
            raise ExecuteFallbackUnsafe(phase=step, configured_specs=(SPEC, BACKUP), attempted_index=1)


def test_two_process_observation_lease_recovery_child_races_are_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_production_runtime(monkeypatch, tmp_path)
    ledger = IncidentLedger(tmp_path)
    req = _shared_request(tmp_path, ledger=ledger)
    receipt = require_production_worker_dispatch_runtime(req)
    held = dispatch_with_admission(
        req,
        _launch_exhausted,
        ledger=ledger,
        gate=lambda _request: receipt,
        clock=lambda: 0.0,
        deadline_s=10,
    )
    assert held.kind == "provider_exhausted"
    assert receipt.logical_dispatch_id == "logical"
    events = IncidentLedger(tmp_path).read_nbf_events()
    assert not any(
        event["payload"]["event_type"] in {
            "provider_observation",
            "provider_probe_started",
            "provider_route_child_reserved",
        }
        for event in events
    )


@pytest.mark.parametrize("door", ("native", "omp", "managed"))
def test_fresh_ledger_replay_preserves_streak_one_through_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    door: str,
) -> None:
    _install_production_runtime(monkeypatch, tmp_path)
    spec, _alt, phase = _door_specs(door)
    launched: list[str] = []
    result, _wbc, launched = _call_production_door(
        door,
        tmp_path,
        monkeypatch,
        phase=phase,
        spec=spec,
        fallback=(spec,),
        behavior="recovery_success",
        launched=launched,
    )
    reopened = IncidentLedger(tmp_path)
    view = provider_resilience.ProviderLedgerView.from_ledger(reopened)
    assert view.observation_streak == 0
    events = reopened.read_nbf_events()
    assert not any(event["payload"]["event_type"] == "changed_precondition" for event in events)
    assert not any(event["payload"]["event_type"] == "provider_route_child_reserved" for event in events)
    assert launched == [spec]
    assert result is not None


def test_unauthorized_child_and_foreign_replay_cannot_mutate_streak(tmp_path: Path) -> None:
    ledger, _, terminal, _, probe = _provider_parent(tmp_path)
    key = terminal.provider_failure_key
    assert key is not None
    change = _recovery_change(ledger, probe, key)
    with pytest.raises(ValueError):
        ledger.reserve_provider_route_child(plan_id="plan", phase=PHASE, projection_key="projection", expected_projection_version=ledger.projection()["projection_version"], transition_kind="fallback", from_spec=SPEC, to_spec=BACKUP, parent_logical_dispatch_id="logical", parent_terminal_event_id=terminal.terminal_outcome_event_id, authorizing_event_id="foreign", configured_fallback_chain_identity="chain-identity", precondition_identity="precondition-1", child_dispatch_family_id="deepseek", child_logical_dispatch_id="child", child_physical_door_id="door", child_semantic_dispatch_fingerprint="a" * 64, child_route_liveness_identity="route")
    assert ledger.projection()["observation_streak"] == 1
    assert change.event_id


def test_unresolved_reservation_blocks_provider_route_advance(tmp_path: Path) -> None:
    ledger = IncidentLedger(tmp_path)
    ledger.reserve(plan_id="plan", phase=PHASE, projection_key="projection", semantic_dispatch_fingerprint=FINGERPRINT, logical_dispatch_id="logical", dispatch_family_id="family", selected_spec=SPEC)
    assert ledger.projection()["reservations"]
    assert not ledger.projection()["terminals"]
    assert not ledger.projection()["provider_streaks"]


def test_ledger_replay_repairs_lost_or_mismatched_cache(tmp_path: Path) -> None:
    ledger, _, outcome, _, _ = _provider_parent(tmp_path)
    source_view = provider_resilience.ProviderLedgerView.from_ledger(ledger)
    forged_view = provider_resilience.ProviderLedgerView(projection_version=999, observation_streak=0)
    assert source_view.projection_version != forged_view.projection_version
    assert source_view.observation_streak == 1
    assert provider_resilience.select_provider_route(outcome, source_view).kind == "provider_observation_wait"


def test_t8_ownership_has_one_policy_and_no_second_authority(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[3]
    checker = root / "scripts" / "check_nbf06_a38.py"
    matrix = root / ".oracle" / "research" / "nbf06-acceptance-test-matrix.md"
    fixtures = root / "tests" / "arnold_pipelines" / "megaplan" / "fixtures" / "nbf06_a38"
    result = subprocess.run(
        [sys.executable, str(checker), "--matrix", str(matrix), "--allowlist", str(matrix), "--negative-fixtures", str(fixtures)],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "A38 checker: ALLOWLIST PASS; forbidden=0; negative_fixtures=PASS"
