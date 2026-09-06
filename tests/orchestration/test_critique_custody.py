from __future__ import annotations

from copy import deepcopy
import ast
import inspect
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Sequence

import pytest

from arnold_pipelines.megaplan._core import atomic_write_json, atomic_write_text, load_flag_registry
from arnold_pipelines.megaplan import auto
from arnold_pipelines.megaplan.flags import (
    apply_flag_verifications,
    update_flags_after_critique,
    update_flags_after_gate,
    update_flags_after_revise,
)
from arnold_pipelines.megaplan.handlers.plan import _build_verifiability_flags
from arnold_pipelines.megaplan.handlers.structured_output import promote_scratch
from arnold_pipelines.megaplan.orchestration import critique_custody
from arnold_pipelines.megaplan.orchestration import critique_runtime
from arnold_pipelines.megaplan.orchestration.critique_custody import (
    CritiqueCustodyError,
    assert_finalize_custody,
    bind_finalize_custody,
    migrate_legacy_critique_custody,
    prepare_critique_payload,
    validate_gate_input_custody,
    validate_finalize_resolution_coverage,
    write_critique_clearance,
    write_critique_production_receipt,
)
from arnold_pipelines.megaplan.orchestration.task_feasibility import (
    compile_task_feasibility,
)
from arnold_pipelines.megaplan.workers import WorkerResult
from arnold_pipelines.megaplan.custody.phase_wbc import activate_phase_wbc
from arnold_pipelines.megaplan.custody.worker_dispatch_wbc import (
    build_worker_dispatch_spec,
    query_worker_dispatch_manifest,
)


def _state(project_dir: Path, *, iteration: int = 1, robustness: str = "full") -> dict[str, Any]:
    return {
        "name": "custody-test",
        "iteration": iteration,
        "current_state": "critiqued",
        "config": {
            "mode": "code",
            "project_dir": str(project_dir),
            "robustness": robustness,
        },
        "plan_versions": [{"version": iteration, "file": f"plan_v{iteration}.md"}],
        "history": [],
        "meta": {"current_invocation_id": f"critique-invocation-{iteration}"},
        "last_gate": {},
    }


def test_deterministic_verifiability_flags_carry_source_criterion_evidence() -> None:
    criteria = [
        {
            "criterion": "Architecture remains clear to a human reviewer.",
            "priority": "should",
            "requires": ["subjective_judgment"],
        }
    ]

    flags = _build_verifiability_flags(criteria, {"codex": {"file_read"}})

    assert len(flags) == 1
    assert flags[0]["concern"] == flags[0]["evidence"]
    assert flags[0]["evidence"] == (
        "verifiability_audit: verdict='human_only'; "
        "rationale='Some required capabilities need human verification.'; "
        "missing_capabilities=['subjective_judgment']; "
        "source=success_criteria[0]: criterion='Architecture remains clear to a "
        "human reviewer.'; priority='should'; requires=['subjective_judgment']"
    )
    payload = {
        "checks": [],
        "flags": flags,
        "verified_flag_ids": [],
        "disputed_flag_ids": [],
    }
    prepare_critique_payload(payload, expected_check_ids=[])
    assert payload["flags"][0]["id"].startswith("CF-")


def _oversized_payload(*, two_findings: bool = False) -> dict[str, Any]:
    findings = [
        {
            "detail": "Step 2 combines protocol, migration, and broad test objectives; split it.",
            "flagged": True,
        }
    ]
    flags = [
        {
            "id": "scope-god-task-2",
            "concern": "Step 2 is an oversized god-task.",
            "category": "completeness",
            "severity_hint": "likely-significant",
            "evidence": findings[0]["detail"],
            "source_check_id": "scope",
        }
    ]
    if two_findings:
        findings.append(
            {
                "detail": "Step 8 combines three independently reviewable consumers; split it.",
                "flagged": True,
            }
        )
        flags.append(
            {
                "id": "scope-god-task-8",
                "concern": "Step 8 is an oversized god-task.",
                "category": "completeness",
                "severity_hint": "likely-significant",
                "evidence": findings[1]["detail"],
                "source_check_id": "scope",
            }
        )
    return {
        "checks": [{"id": "scope", "question": "Are tasks bounded?", "findings": findings}],
        "flags": flags,
        "verified_flag_ids": [],
        "disputed_flag_ids": [],
    }


def _producer_binding(
    invocation_id: str = "critique-invocation-1",
    *,
    producer: str = "codex",
    transport: str = "inline_response",
    scratch_status: str = "unmodified",
) -> dict[str, Any]:
    return {
        "schema_version": "megaplan-critique-producer-binding-v1",
        "invocation_id": invocation_id,
        "attempt_index": 0,
        "attempt_id": f"{invocation_id}:0",
        "producer": producer,
        "provider": "openai" if producer == "codex" else None,
        "selected_spec": "codex:gpt-5.4" if producer == "codex" else None,
        "model_actual": "gpt-5.4" if producer == "codex" else None,
        "session_id": None,
        "transport": transport,
        "scratch_status": scratch_status,
        "registered_scratch_artifact": "critique_output.json",
        "output_path_attested": False,
    }


def _persist_critique(
    plan_dir: Path,
    state: dict[str, Any],
    payload: dict[str, Any],
    *,
    reconciliation_artifacts: Sequence[Any] | None = None,
    disposition_artifacts: Sequence[Any] | None = None,
) -> dict[str, Any]:
    iteration = state["iteration"]
    atomic_write_text(plan_dir / f"plan_v{iteration}.md", f"# Plan v{iteration}\n\nOversized work.\n")
    atomic_write_text(plan_dir / f"critique_raw_v{iteration}.txt", "raw producer critique")
    prepare_critique_payload(payload, expected_check_ids=["scope"])
    atomic_write_json(plan_dir / f"critique_v{iteration}.json", payload)
    receipt = write_critique_production_receipt(
        plan_dir,
        state,
        payload,
        expected_check_ids=["scope"],
        producer_binding=_producer_binding(state["meta"]["current_invocation_id"]),
        reconciliation_artifacts=reconciliation_artifacts,
        disposition_artifacts=disposition_artifacts,
    )
    update_flags_after_critique(plan_dir, payload, iteration=iteration)
    return receipt


def _admitted_graph() -> dict[str, Any]:
    payload = {
        "task_contract_version": 2,
        "validation_jobs": [],
        "tasks": [
            {
                "id": "T1",
                "objective": "Implement the bounded critique custody contract.",
                "description": "Implement one independently verifiable contract slice.",
                "kind": "code",
                "complexity": 5,
                "estimated_minutes": 10,
                "depends_on": [],
                "dependency_reasons": {},
                "routing_group": "custody",
                "write_set": {"paths": ["src/custody.py", "tests/test_custody.py"], "complete": True},
                "narrow_tests": {"selectors": ["tests/test_custody.py"], "max_seconds": 120, "max_runs": 2},
                "checkpoint": {"required": False, "max_interval_seconds": 300, "records": []},
            }
        ],
    }
    payload["graph_report"] = compile_task_feasibility(payload, {})
    assert payload["graph_report"]["admitted"] is True
    return payload


def test_valid_oversized_task_finding_survives_normalization_and_reaches_gate(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()

    receipt = _persist_critique(plan_dir, state, payload)
    gate_input = validate_gate_input_custody(plan_dir, state)
    canonical_id = payload["flags"][0]["id"]

    assert canonical_id.startswith("CF-")
    assert payload["flags"][0]["producer_flag_id"] == "scope-god-task-2"
    assert receipt["finding_count"] == 1
    assert receipt["normalization"] == {
        "flagged_check_findings": 1,
        "canonical_flags": 1,
        "loss_count": 0,
    }
    assert gate_input["flag_ids"] == [canonical_id]
    assert gate_input["loss_count"] == 0


def _rewrite_receipt_digest(receipt: dict[str, Any]) -> None:
    receipt.pop("receipt_digest", None)
    receipt["receipt_digest"] = critique_custody._digest(receipt)


def _legacy_unbound_fixture(plan_dir: Path, state: dict[str, Any]) -> Path:
    """Reproduce the exact v1-on-v2-filename shape from the preserved r5 run."""
    payload = _oversized_payload()
    receipt = _persist_critique(plan_dir, state, payload)
    iteration = int(state["iteration"])
    producer_path = plan_dir / f"critique_check_scope_producer_v{iteration}.json"
    atomic_write_json(producer_path, payload)
    receipt["schema_version"] = "megaplan-critique-custody-v1"
    receipt.pop("producer_binding")
    receipt.pop("producer_binding_digest")
    receipt["raw_sources"].append(
        {"artifact": producer_path.name, "sha256": critique_custody.sha256_file(producer_path)}
    )
    _rewrite_receipt_digest(receipt)
    receipt_path = plan_dir / f"critique_custody_v{iteration}.json"
    atomic_write_json(receipt_path, receipt)

    critique_sha = receipt["critique_sha256"]
    state["current_state"] = "gated"
    state["history"] = [
        {
            "step": "critique",
            "result": "success",
            "duration_ms": 1234,
            "output_file": receipt["critique_artifact"],
            "artifact_hash": critique_sha,
        }
    ]
    atomic_write_json(plan_dir / "state.json", state)
    atomic_write_json(
        plan_dir / f"step_receipt_critique_v{iteration}.json",
        {
            "phase": "critique",
            "iteration": iteration,
            "duration_ms": 1234,
            "upstream_artifact_hashes": [receipt["plan_sha256"]],
        },
    )
    custody_binding = {
        "schema_version": "megaplan-critique-custody-v1",
        "receipt": receipt_path.name,
        "receipt_sha256": critique_custody.sha256_file(receipt_path),
        "finding_count": receipt["finding_count"],
        "finding_ids": receipt["finding_ids"],
        "flag_ids": receipt["flag_ids"],
        "loss_count": 0,
        "admitted": True,
    }
    atomic_write_json(
        plan_dir / f"gate_signals_v{iteration}.json",
        {"signals": {"critique_custody": custody_binding}},
    )
    atomic_write_json(
        plan_dir / f"step_receipt_gate_v{iteration}.json",
        {
            "phase": "gate",
            "iteration": iteration,
            "upstream_artifact_hashes": [critique_sha],
        },
    )
    gate_payload = {
        "recommendation": "PROCEED",
        "signals": {"critique_custody": custody_binding},
    }
    atomic_write_json(plan_dir / f"gate_v{iteration}.json", gate_payload)
    atomic_write_json(plan_dir / "gate.json", gate_payload)
    clearance = {
        "schema_version": "megaplan-critique-clearance-v1",
        "source_receipts": [
            {"artifact": receipt_path.name, "sha256": critique_custody.sha256_file(receipt_path)}
        ],
        "admitted": True,
    }
    clearance["clearance_digest"] = critique_custody._digest(clearance)
    atomic_write_json(plan_dir / "critique_clearance.json", clearance)
    return receipt_path


def test_exact_legacy_unbound_fixture_migrates_without_rewriting_source(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path, iteration=2)
    receipt_path = _legacy_unbound_fixture(plan_dir, state)
    source_before = receipt_path.read_bytes()
    source_sha = critique_custody.sha256_file(receipt_path)

    [migration] = migrate_legacy_critique_custody(
        plan_dir,
        iteration=2,
        expected_source_sha256=source_sha,
        actor="operator:test",
        reason="admit preserved pre-v2 custody without inventing provenance",
    )

    assert receipt_path.read_bytes() == source_before
    assert migration["custody_status"] == "legacy_unbound"
    assert migration["producer_binding"]["producer_identity"] is None
    assert migration["producer_binding"]["invocation_identity"] is None
    critique_custody._validate_receipt_at_path(
        plan_dir, receipt_path, json.loads(receipt_path.read_text())
    )


def test_legacy_migration_survives_clearance_rewrite_and_finalize_validation(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path, iteration=2)
    receipt_path = _legacy_unbound_fixture(plan_dir, state)
    old_clearance_sha = critique_custody.sha256_file(
        plan_dir / "critique_clearance.json"
    )
    [migration] = migrate_legacy_critique_custody(
        plan_dir,
        iteration=2,
        expected_source_sha256=critique_custody.sha256_file(receipt_path),
        actor="operator:test",
        reason="admit legacy custody before normal clearance refresh",
    )
    receipt = critique_custody.read_json(receipt_path)
    [finding_id] = receipt["finding_ids"]
    update_flags_after_gate(
        plan_dir,
        [
            {
                "flag_id": finding_id,
                "action": "accept_tradeoff",
                "evidence": "The gate reviewed the exact preserved concern.",
                "rationale": "The remaining risk is explicit, bounded, and accepted.",
            }
        ],
    )

    clearance = write_critique_clearance(plan_dir, state)

    assert critique_custody.sha256_file(plan_dir / "critique_clearance.json") != old_clearance_sha
    stored_clearance_row = next(
        row
        for row in migration["lineage_evidence"]
        if row["role"] == "critique_clearance"
    )
    assert stored_clearance_row["sha256"] == old_clearance_sha
    graph = _admitted_graph()
    graph["critique_resolution_coverage"] = [
        {
            "finding_id": finding_id,
            "task_ids": ["T1"],
            "resolution_evidence": "T1 preserves the bounded accepted-risk contract.",
        }
    ]
    bind_finalize_custody(plan_dir, graph, clearance)

    assert_finalize_custody(plan_dir, graph)


def test_legacy_migration_accepts_bound_post_migration_state_history_append(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    receipt_path = _legacy_unbound_fixture(plan_dir, _state(tmp_path, iteration=2))
    source_before = receipt_path.read_bytes()
    [migration] = migrate_legacy_critique_custody(
        plan_dir,
        iteration=2,
        expected_source_sha256=critique_custody.sha256_file(receipt_path),
        actor="operator:test",
        reason="admit legacy custody before later workflow attempts",
    )
    stored_state_sha = next(
        row["sha256"]
        for row in migration["lineage_evidence"]
        if row["role"] == "state_history"
    )
    state = critique_custody.read_json(plan_dir / "state.json")
    state["history"].append(
        {
            "step": "finalize",
            "result": "failed",
            "invocation_id": "finalize-attempt-9",
            "wbc_attempt_id": "93b18c0b-423b-53e8-b063-523648c5c4aa",
        }
    )
    atomic_write_json(plan_dir / "state.json", state)

    assert critique_custody.sha256_file(plan_dir / "state.json") != stored_state_sha
    assert receipt_path.read_bytes() == source_before
    critique_custody._validate_receipt_at_path(
        plan_dir, receipt_path, critique_custody.read_json(receipt_path)
    )


def test_legacy_migration_rejects_mutated_bound_critique_history_row(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    receipt_path = _legacy_unbound_fixture(plan_dir, _state(tmp_path, iteration=2))
    migrate_legacy_critique_custody(
        plan_dir,
        iteration=2,
        expected_source_sha256=critique_custody.sha256_file(receipt_path),
        actor="operator:test",
        reason="admit legacy custody before later workflow attempts",
    )
    state = critique_custody.read_json(plan_dir / "state.json")
    state["history"][0]["artifact_hash"] = "sha256:" + "0" * 64
    atomic_write_json(plan_dir / "state.json", state)

    with pytest.raises(
        CritiqueCustodyError,
        match="state history lacks exactly one matching successful critique result",
    ):
        critique_custody._validate_receipt_at_path(
            plan_dir, receipt_path, critique_custody.read_json(receipt_path)
        )


def test_legacy_migration_rejects_post_admission_immutable_lineage_mutation(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    receipt_path = _legacy_unbound_fixture(plan_dir, _state(tmp_path, iteration=2))
    migrate_legacy_critique_custody(
        plan_dir,
        iteration=2,
        expected_source_sha256=critique_custody.sha256_file(receipt_path),
        actor="operator:test",
        reason="admit immutable legacy lineage",
    )
    critique_step_path = plan_dir / "step_receipt_critique_v2.json"
    critique_step = critique_custody.read_json(critique_step_path)
    critique_step["untrusted_extra_field"] = "mutation after admission"
    atomic_write_json(critique_step_path, critique_step)

    with pytest.raises(
        CritiqueCustodyError,
        match="legacy immutable lineage changed for critique_step_receipt",
    ):
        critique_custody._validate_receipt_at_path(
            plan_dir, receipt_path, critique_custody.read_json(receipt_path)
        )


def test_legacy_migration_rejects_post_admission_source_artifact_mutation(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    receipt_path = _legacy_unbound_fixture(plan_dir, _state(tmp_path, iteration=2))
    receipt = critique_custody.read_json(receipt_path)
    migrate_legacy_critique_custody(
        plan_dir,
        iteration=2,
        expected_source_sha256=critique_custody.sha256_file(receipt_path),
        actor="operator:test",
        reason="admit immutable legacy source artifacts",
    )
    raw_source_path = plan_dir / receipt["raw_sources"][0]["artifact"]
    atomic_write_text(raw_source_path, "mutated after migration\n")

    with pytest.raises(CritiqueCustodyError, match="raw source hash mismatch"):
        critique_custody._validate_receipt_at_path(
            plan_dir, receipt_path, critique_custody.read_json(receipt_path)
        )


def test_legacy_migration_is_idempotent_across_publish_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    receipt_path = _legacy_unbound_fixture(plan_dir, _state(tmp_path, iteration=2))
    source_sha = critique_custody.sha256_file(receipt_path)
    real_link = critique_custody.os.link
    failed = False

    def crash_once(source: object, target: object) -> None:
        nonlocal failed
        if not failed and str(target).endswith("critique_custody_legacy_migration_v2.json"):
            failed = True
            raise OSError("simulated crash before publish")
        real_link(source, target)

    monkeypatch.setattr(critique_custody.os, "link", crash_once)
    kwargs = {
        "iteration": 2,
        "expected_source_sha256": source_sha,
        "actor": "operator:test",
        "reason": "crash-safe migration",
    }
    with pytest.raises(OSError, match="simulated crash"):
        migrate_legacy_critique_custody(plan_dir, **kwargs)
    assert not (plan_dir / "critique_custody_legacy_migration_v2.json").exists()

    [first] = migrate_legacy_critique_custody(plan_dir, **kwargs)
    sidecar = plan_dir / "critique_custody_legacy_migration_v2.json"
    before = sidecar.read_bytes()
    [second] = migrate_legacy_critique_custody(plan_dir, **kwargs)
    assert second == first
    assert sidecar.read_bytes() == before


def test_legacy_migration_rejects_artifact_hash_divergence(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    receipt_path = _legacy_unbound_fixture(plan_dir, _state(tmp_path, iteration=2))
    receipt = json.loads(receipt_path.read_text())
    receipt["raw_sources"][0]["sha256"] = "sha256:" + "0" * 64
    _rewrite_receipt_digest(receipt)
    atomic_write_json(receipt_path, receipt)

    with pytest.raises(CritiqueCustodyError, match="raw source hash mismatch"):
        migrate_legacy_critique_custody(
            plan_dir,
            iteration=2,
            expected_source_sha256=critique_custody.sha256_file(receipt_path),
            actor="operator:test",
            reason="must reject divergent evidence",
        )


def test_legacy_migration_rejects_wrong_source_cas_and_gate_lineage(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    receipt_path = _legacy_unbound_fixture(plan_dir, _state(tmp_path, iteration=2))
    with pytest.raises(CritiqueCustodyError, match="expected sha256"):
        migrate_legacy_critique_custody(
            plan_dir,
            iteration=2,
            expected_source_sha256="sha256:" + "f" * 64,
            actor="operator:test",
            reason="CAS mismatch",
        )

    gate = json.loads((plan_dir / "gate_v2.json").read_text())
    gate["recommendation"] = "ITERATE"
    gate["signals"]["critique_custody"]["receipt_sha256"] = "sha256:" + "0" * 64
    atomic_write_json(plan_dir / "gate_v2.json", gate)
    with pytest.raises(CritiqueCustodyError, match="versioned gate does not bind"):
        migrate_legacy_critique_custody(
            plan_dir,
            iteration=2,
            expected_source_sha256=critique_custody.sha256_file(receipt_path),
            actor="operator:test",
            reason="lineage mismatch",
        )


def test_gate_rejects_self_consistent_receipt_copied_from_older_iteration(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    _persist_critique(plan_dir, state, payload)
    old_receipt = (plan_dir / "critique_custody_v1.json").read_bytes()
    state["iteration"] = 2
    state["plan_versions"].append({"version": 2, "file": "plan_v2.md"})
    atomic_write_text(plan_dir / "plan_v2.md", "# Plan v2\n")
    atomic_write_json(plan_dir / "critique_v2.json", payload)
    (plan_dir / "critique_custody_v2.json").write_bytes(old_receipt)

    with pytest.raises(CritiqueCustodyError, match="does not match current iteration"):
        validate_gate_input_custody(plan_dir, state)


def test_gate_rejects_rehashed_receipt_pointing_at_wrong_critique_path(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    _persist_critique(plan_dir, state, payload)
    receipt_path = plan_dir / "critique_custody_v1.json"
    receipt = json.loads(receipt_path.read_text())
    atomic_write_json(plan_dir / "copied_critique.json", payload)
    receipt["critique_artifact"] = "copied_critique.json"
    receipt["critique_sha256"] = critique_custody.sha256_file(
        plan_dir / "copied_critique.json"
    )
    _rewrite_receipt_digest(receipt)
    atomic_write_json(receipt_path, receipt)

    with pytest.raises(CritiqueCustodyError, match="exact current canonical artifact"):
        validate_gate_input_custody(plan_dir, state)


def test_gate_rejects_tampered_producer_attempt_even_with_rehashed_receipt(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    _persist_critique(plan_dir, state, _oversized_payload())
    receipt_path = plan_dir / "critique_custody_v1.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["producer_binding"]["attempt_index"] = 9
    receipt["producer_binding"]["attempt_id"] = (
        f"{receipt['producer_binding']['invocation_id']}:9"
    )
    _rewrite_receipt_digest(receipt)
    atomic_write_json(receipt_path, receipt)

    with pytest.raises(CritiqueCustodyError, match="producer binding digest mismatch"):
        validate_gate_input_custody(plan_dir, state)


def test_receipt_restart_is_idempotent_and_never_rewrites(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    first = _persist_critique(plan_dir, state, payload)
    path = plan_dir / "critique_custody_v1.json"
    before = path.read_bytes()

    restarted = write_critique_production_receipt(
        plan_dir,
        state,
        payload,
        expected_check_ids=["scope"],
        producer_binding=_producer_binding(),
    )

    assert restarted == first
    assert path.read_bytes() == before


def test_receipt_restart_rejects_corrupted_existing_receipt(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    _persist_critique(plan_dir, state, payload)
    path = plan_dir / "critique_custody_v1.json"
    existing = json.loads(path.read_text())
    existing["receipt_digest"] = "sha256:" + "0" * 64
    atomic_write_json(path, existing)

    with pytest.raises(CritiqueCustodyError, match="invalid digest"):
        write_critique_production_receipt(
            plan_dir,
            state,
            payload,
            expected_check_ids=["scope"],
            producer_binding=_producer_binding(),
        )


def test_concurrent_receipt_creation_is_create_once(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    atomic_write_text(plan_dir / "plan_v1.md", "# Plan v1\n")
    atomic_write_text(plan_dir / "critique_raw_v1.txt", "raw producer critique")
    prepare_critique_payload(payload, expected_check_ids=["scope"])
    atomic_write_json(plan_dir / "critique_v1.json", payload)

    def publish(invocation: str) -> str:
        try:
            write_critique_production_receipt(
                plan_dir,
                state,
                deepcopy(payload),
                expected_check_ids=["scope"],
                producer_binding=_producer_binding(invocation),
            )
            return "published"
        except CritiqueCustodyError as error:
            assert error.code == "critique_custody_receipt_conflict"
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(publish, ("inv-a", "inv-b")))

    assert sorted(outcomes) == ["conflict", "published"]
    receipt = json.loads((plan_dir / "critique_custody_v1.json").read_text())
    assert receipt["producer_binding"]["invocation_id"] in {"inv-a", "inv-b"}


@pytest.mark.parametrize("producer", ["codex", "shannon"])
def test_inline_critique_producers_ignore_preexisting_valid_scratch(
    tmp_path: Path,
    producer: str,
) -> None:
    scratch_payload = _oversized_payload()
    atomic_write_json(tmp_path / "critique_output.json", scratch_payload)
    inline_payload = {"source": producer}
    worker = WorkerResult(payload=inline_payload, raw_output="", duration_ms=1, cost_usd=0)

    status, promoted = promote_scratch(
        tmp_path,
        "critique_output.json",
        frozenset(scratch_payload),
        worker,
        seed_json="{}",
        file_fill_instructed=False,
    )

    assert status == "unmodified"
    assert promoted is inline_payload


def test_hermes_critique_uses_only_registered_filled_path(tmp_path: Path) -> None:
    scratch_payload = _oversized_payload()
    atomic_write_json(tmp_path / "critique_output.json", scratch_payload)
    atomic_write_json(tmp_path / "wrong_output.json", {"wrong": True})
    worker = WorkerResult(payload={"source": "inline"}, raw_output="", duration_ms=1, cost_usd=0)

    status, promoted = promote_scratch(
        tmp_path,
        "critique_output.json",
        frozenset(scratch_payload),
        worker,
        seed_json="{}",
        file_fill_instructed=True,
    )

    assert status == "filled"
    assert promoted == scratch_payload


def test_hermes_stale_or_wrong_path_scratch_is_not_adopted(tmp_path: Path) -> None:
    seed = json.dumps(_oversized_payload(), sort_keys=True)
    (tmp_path / "critique_output.json").write_text(seed, encoding="utf-8")
    atomic_write_json(tmp_path / "wrong_output.json", _oversized_payload())
    inline_payload = {"source": "fallback"}
    worker = WorkerResult(payload=inline_payload, raw_output="", duration_ms=1, cost_usd=0)

    status, promoted = promote_scratch(
        tmp_path,
        "critique_output.json",
        frozenset(_oversized_payload()),
        worker,
        seed_json=seed,
        file_fill_instructed=True,
    )

    assert status == "unmodified"
    assert promoted is inline_payload


def test_orphan_recovery_quarantines_even_valid_stale_critique_scratch(
    tmp_path: Path,
) -> None:
    atomic_write_json(tmp_path / "critique_output.json", _oversized_payload())

    quarantined = auto._quarantine_phase_outputs(tmp_path, "critique")

    assert quarantined == ["critique_output.json"]
    assert not (tmp_path / "critique_output.json").exists()
    assert (tmp_path / "critique_output.json.orphaned").exists()


def test_runtime_producer_binding_captures_available_hermes_attempt_identity(
    tmp_path: Path,
) -> None:
    atomic_write_json(tmp_path / "critique_output.json", _oversized_payload())
    worker = WorkerResult(
        payload=_oversized_payload(),
        raw_output="",
        duration_ms=1,
        cost_usd=0,
        session_id="session-1",
        model_actual="glm-5.2",
        attempt_index=1,
        attempted_specs=("omp:deepseek/model-a", "omp:zai/glm-5.2"),
    )

    binding = critique_runtime._critique_producer_binding(
        {"meta": {"current_invocation_id": "inv-1"}},
        worker,
        agent="omp",
        scratch_filename="critique_output.json",
        scratch_status="filled",
        plan_dir=tmp_path,
        parallel_reduced=False,
    )

    assert binding["attempt_id"] == "inv-1:1"
    assert binding["selected_spec"] == "omp:zai/glm-5.2"
    assert binding["provider"] == "zai/glm-5.2"
    assert binding["model_actual"] == "glm-5.2"
    assert binding["scratch_sha256"] == critique_custody.sha256_file(
        tmp_path / "critique_output.json"
    )


def test_parallel_reducer_receipt_binds_phase_children_and_rejects_manifest_tamper(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    state["active_step"] = {
        "phase": "critique",
        "run_id": "run-parallel",
    }
    phase = activate_phase_wbc(
        state=state,
        plan_dir=plan_dir,
        step="critique",
        agent="hermes",
    )
    assert phase is not None
    child = build_worker_dispatch_spec(
        plan_dir=plan_dir,
        state=state,
        step="critique",
        agent="hermes",
        selected_spec="omp:zai/glm-5.2",
        route_kind="subprocess",
        dispatch_key="critique:scope:initial",
    )
    assert child is not None
    child.run(
        lambda _start: WorkerResult(
            payload={}, raw_output="", duration_ms=1, cost_usd=0, session_id=None
        )
    )
    payload = _oversized_payload()
    prepare_critique_payload(payload, expected_check_ids=["scope"])
    atomic_write_text(plan_dir / "plan_v1.md", "# Plan v1\n")
    atomic_write_text(plan_dir / "critique_raw_v1.txt", "parallel reducer")
    atomic_write_json(plan_dir / "critique_v1.json", payload)
    producer_path = plan_dir / "critique_check_scope_producer_v1.json"
    atomic_write_json(producer_path, payload)
    manifest = {
        "schema_version": "megaplan-parallel-critique-child-manifest-v1",
        "iteration": 1,
        "invocation_id": state["meta"]["current_invocation_id"],
        "phase_attempt_id": phase["attempt_id"],
        "expected_check_ids": ["scope"],
        "dispatches": query_worker_dispatch_manifest(
            plan_dir, phase_attempt_id=phase["attempt_id"]
        ),
        "producer_artifacts": [
            {
                "check_id": "scope",
                "producer_artifact": producer_path.name,
                "producer_sha256": critique_custody.sha256_file(producer_path),
            }
        ],
    }
    manifest["manifest_digest"] = critique_custody._digest(manifest)
    manifest_path = plan_dir / "critique_parallel_manifest_v1.json"
    atomic_write_json(manifest_path, manifest)
    worker = WorkerResult(
        payload=payload,
        raw_output="parallel",
        duration_ms=1,
        cost_usd=0,
        session_id=None,
        auth_metadata={
            "parallel_critique": {
                "manifest_artifact": manifest_path.name,
                "manifest_sha256": critique_custody.sha256_file(manifest_path),
                "manifest_digest": manifest["manifest_digest"],
                "phase_attempt_id": phase["attempt_id"],
                "invocation_id": state["meta"]["current_invocation_id"],
                "child_dispatch_count": 1,
            }
        },
    )
    binding = critique_runtime._critique_producer_binding(
        state,
        worker,
        agent="hermes",
        scratch_filename="critique_output.json",
        scratch_status="not_applicable",
        plan_dir=plan_dir,
        parallel_reduced=True,
    )
    state["meta"]["current_invocation_id"] = "stale-evaluator-invocation"
    with pytest.raises(CritiqueCustodyError, match="active critique phase"):
        critique_runtime._critique_producer_binding(
            state,
            worker,
            agent="hermes",
            scratch_filename="critique_output.json",
            scratch_status="not_applicable",
            plan_dir=plan_dir,
            parallel_reduced=True,
        )
    state["meta"]["current_invocation_id"] = phase["invocation_id"]
    write_critique_production_receipt(
        plan_dir,
        state,
        payload,
        expected_check_ids=["scope"],
        producer_binding=binding,
    )
    update_flags_after_critique(plan_dir, payload, iteration=1)

    manifest["expected_check_ids"] = ["scope", "injected"]
    manifest["manifest_digest"] = critique_custody._digest(
        {key: value for key, value in manifest.items() if key != "manifest_digest"}
    )
    atomic_write_json(manifest_path, manifest)
    with pytest.raises(CritiqueCustodyError, match="child manifest artifact hash mismatch"):
        validate_gate_input_custody(plan_dir, state)


def test_parallel_critique_establishes_phase_before_scatter() -> None:
    source = inspect.getsource(critique_runtime.handle_critique)
    parallel_dispatch = source.index("worker = run_parallel_critique(")
    assert source.rindex("set_active_step(", 0, parallel_dispatch) < parallel_dispatch
    assert source.rindex("activate_phase_wbc(", 0, parallel_dispatch) < parallel_dispatch
    assert source.rindex("save_state_merge_meta(", 0, parallel_dispatch) < parallel_dispatch


def test_unbound_critique_output_recovery_is_statically_retired() -> None:
    source = inspect.getsource(critique_runtime)
    functions = {
        node.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "_recover_valid_critique_output" not in functions
    assert "_normalize_critique_payload_for_recovery" not in functions


def test_registered_critique_seed_boundary_precedes_each_sequential_dispatch() -> None:
    source = inspect.getsource(critique_runtime.handle_critique)
    tree = ast.parse(source)
    seed_lines = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_seed_registered_critique_scratch"
    ]
    dispatch_lines = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "_run_worker"
        and node.lineno > min(seed_lines)
    ]

    assert len(seed_lines) == len(dispatch_lines) == 2
    assert all(any(0 < dispatch - seed <= 3 for seed in seed_lines) for dispatch in dispatch_lines)


def test_effectively_clean_or_lost_gate_input_fails_closed(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    _persist_critique(plan_dir, state, payload)

    erased = deepcopy(payload)
    erased["flags"] = []
    atomic_write_json(plan_dir / "critique_v1.json", erased)

    with pytest.raises(CritiqueCustodyError, match="hash mismatch"):
        validate_gate_input_custody(plan_dir, state)


def test_partial_mapping_remains_blocking_at_finalize(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload(two_findings=True)
    _persist_critique(plan_dir, state, payload)
    first_id, second_id = [flag["id"] for flag in payload["flags"]]

    atomic_write_text(plan_dir / "plan_v2.md", "# Plan v2\n\nStep 2 is split; Step 8 is not.\n")
    state["iteration"] = 2
    state["plan_versions"].append({"version": 2, "file": "plan_v2.md"})
    update_flags_after_revise(
        plan_dir,
        [{"id": first_id, "resolution": "addressed", "reason": "Split into T2a/T2b.", "where": "Step 2"}],
        plan_file="plan_v2.md",
        summary="Split Step 2.",
    )
    update_flags_after_gate(
        plan_dir,
        [{"flag_id": first_id, "action": "verify_fixed", "evidence": "plan_v2.md Step 2", "rationale": ""}],
    )

    with pytest.raises(CritiqueCustodyError, match=second_id):
        write_critique_clearance(plan_dir, state)


@pytest.mark.parametrize(
    "mutation,code",
    [
        (lambda payload: payload["checks"][0]["findings"][0].update(flagged="yes"), "critique_findings_malformed"),
        (lambda payload: payload["flags"].append(deepcopy(payload["flags"][0])), "critique_finding_identity_invalid"),
        (
            lambda payload: payload["flags"].append(
                {**deepcopy(payload["flags"][0]), "id": "scope-god-task-2-duplicate"}
            ),
            "critique_finding_identity_invalid",
        ),
        (lambda payload: payload["checks"][0]["findings"][0].update(silent_drop=True), "critique_findings_malformed"),
    ],
)
def test_malformed_duplicated_unmapped_or_lossy_findings_fail_closed(
    mutation, code: str
) -> None:
    payload = _oversized_payload()
    mutation(payload)
    with pytest.raises(CritiqueCustodyError) as caught:
        prepare_critique_payload(payload, expected_check_ids=["scope"])
    assert caught.value.code == code


def test_reducer_reassigns_duplicate_worker_local_ids_deterministically() -> None:
    payload = {
        "checks": [
            {
                "id": "correctness",
                "question": "Is it correct?",
                "findings": [{"detail": "Correctness evidence.", "flagged": True}],
            },
            {
                "id": "scope",
                "question": "Is it bounded?",
                "findings": [{"detail": "Scope evidence.", "flagged": True}],
            },
        ],
        "flags": [
            {
                "id": "FLAG-001",
                "concern": "Correctness concern.",
                "category": "correctness",
                "severity_hint": "likely-significant",
                "evidence": "Correctness evidence.",
                "source_check_id": "correctness",
            },
            {
                "id": "FLAG-001",
                "concern": "Scope concern.",
                "category": "completeness",
                "severity_hint": "likely-significant",
                "evidence": "Scope evidence.",
                "source_check_id": "scope",
            },
        ],
        "verified_flag_ids": [],
        "disputed_flag_ids": [],
    }
    replay = deepcopy(payload)

    prepare_critique_payload(payload, expected_check_ids=["correctness", "scope"])
    prepare_critique_payload(replay, expected_check_ids=["correctness", "scope"])

    assert payload == replay
    assert len({flag["id"] for flag in payload["flags"]}) == 2
    assert all(flag["id"].startswith("CF-") for flag in payload["flags"])
    assert [flag["producer_flag_id"] for flag in payload["flags"]] == [
        "FLAG-001",
        "FLAG-001",
    ]


def test_unverifiable_check_flagged_findings_do_not_wedge_mapping() -> None:
    payload = {
        "checks": [
            {
                "id": "scope",
                "question": "Is it bounded?",
                "status": "unverifiable",
                "findings": [
                    {"detail": "Stale metadata persists into Revision 9.", "flagged": True}
                ],
            },
            {
                "id": "correctness",
                "question": "Is it correct?",
                "findings": [{"detail": "Correctness evidence.", "flagged": True}],
            },
        ],
        "flags": [
            {
                "id": "FLAG-001",
                "concern": "Correctness concern.",
                "category": "correctness",
                "severity_hint": "likely-significant",
                "evidence": "Correctness evidence.",
                "source_check_id": "correctness",
            }
        ],
        "verified_flag_ids": [],
        "disputed_flag_ids": [],
    }

    flags = prepare_critique_payload(
        payload, expected_check_ids=["correctness", "scope"]
    )

    assert [flag["source_check_id"] for flag in flags] == ["correctness"]


def test_unverifiable_check_findings_stay_evidence_visible_without_flags() -> None:
    payload = {
        "checks": [
            {
                "id": "scope",
                "question": "Is it bounded?",
                "status": "unverifiable",
                "findings": [
                    {"detail": "Stale metadata persists into Revision 9.", "flagged": True}
                ],
            },
            {
                "id": "correctness",
                "question": "Is it correct?",
                "findings": [{"detail": "Correctness evidence.", "flagged": True}],
            },
        ],
        "flags": [],
        "verified_flag_ids": [],
        "disputed_flag_ids": [],
    }

    flags = prepare_critique_payload(
        payload, expected_check_ids=["correctness", "scope"]
    )

    assert [flag["source_check_id"] for flag in flags] == ["correctness"]
    scope_check = payload["checks"][0]
    assert scope_check["findings"][0]["flagged"] is True
    assert scope_check["findings"][0]["detail"] == (
        "Stale metadata persists into Revision 9."
    )


def test_reducer_preserves_ambiguous_canonical_reference_for_registry_validation() -> None:
    prior_id = "CF-E2E56F8ACC6B03976EA9"
    payload = {
        "checks": [
            {
                "id": "correctness",
                "question": "Is it correct?",
                "findings": [
                    {"detail": "Current correctness evidence.", "flagged": True}
                ],
            },
            {
                "id": "scope",
                "question": "Is it bounded?",
                "findings": [{"detail": "Current scope evidence.", "flagged": True}],
            },
        ],
        "flags": [
            {
                "id": prior_id,
                "concern": "Current correctness concern.",
                "category": "correctness",
                "severity_hint": "likely-significant",
                "evidence": "Current correctness evidence.",
                "source_check_id": "correctness",
            },
            {
                "id": prior_id,
                "concern": "Current scope concern.",
                "category": "completeness",
                "severity_hint": "likely-significant",
                "evidence": "Current scope evidence.",
                "source_check_id": "scope",
            },
        ],
        "verified_flag_ids": [prior_id],
        "disputed_flag_ids": [],
    }

    prepare_critique_payload(payload, expected_check_ids=["correctness", "scope"])

    assert payload["verified_flag_ids"] == [prior_id]
    assert {flag["producer_flag_id"] for flag in payload["flags"]} == {prior_id}
    assert prior_id not in {flag["id"] for flag in payload["flags"]}


def test_reducer_rejects_ambiguous_opaque_reference() -> None:
    payload = {
        "checks": [
            {
                "id": "correctness",
                "question": "Is it correct?",
                "findings": [
                    {"detail": "Current correctness evidence.", "flagged": True}
                ],
            },
            {
                "id": "scope",
                "question": "Is it bounded?",
                "findings": [{"detail": "Current scope evidence.", "flagged": True}],
            },
        ],
        "flags": [
            {
                "id": "FLAG-001",
                "concern": "Current correctness concern.",
                "category": "correctness",
                "severity_hint": "likely-significant",
                "evidence": "Current correctness evidence.",
                "source_check_id": "correctness",
            },
            {
                "id": "FLAG-001",
                "concern": "Current scope concern.",
                "category": "completeness",
                "severity_hint": "likely-significant",
                "evidence": "Current scope evidence.",
                "source_check_id": "scope",
            },
        ],
        "verified_flag_ids": ["FLAG-001"],
        "disputed_flag_ids": [],
    }

    with pytest.raises(
        CritiqueCustodyError, match="critique_finding_reference_ambiguous"
    ):
        prepare_critique_payload(payload, expected_check_ids=["correctness", "scope"])

def test_reducer_reassigns_unique_local_id_reused_for_different_findings() -> None:
    def payload(detail: str) -> dict[str, Any]:
        return {
            "checks": [
                {
                    "id": "verification",
                    "question": "Is the criterion verifiable?",
                    "findings": [{"detail": detail, "flagged": True}],
                }
            ],
            "flags": [
                {
                    "id": "verifiability-0",
                    "concern": detail,
                    "category": "verifiability",
                    "severity_hint": "likely-minor",
                    "evidence": detail,
                    "source_check_id": "verification",
                }
            ],
            "verified_flag_ids": ["verifiability-0"],
            "disputed_flag_ids": [],
        }

    first = payload("Criterion 11 requires human verification.")
    second = payload("Criterion 12 requires human verification.")

    prepare_critique_payload(first, expected_check_ids=["verification"])
    prepare_critique_payload(second, expected_check_ids=["verification"])

    first_id = first["flags"][0]["id"]
    second_id = second["flags"][0]["id"]
    assert first_id.startswith("CF-")
    assert second_id.startswith("CF-")
    assert first_id != second_id
    assert first["flags"][0]["producer_flag_id"] == "verifiability-0"
    assert second["flags"][0]["producer_flag_id"] == "verifiability-0"
    assert first["verified_flag_ids"] == [first_id]
    assert second["verified_flag_ids"] == [second_id]


def test_clearance_migrates_reused_legacy_nonblocking_producer_slot(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)

    def payload(detail: str) -> dict[str, Any]:
        return {
            "checks": [
                {
                    "id": "scope",
                    "question": "Is the criterion verifiable?",
                    "findings": [{"detail": detail, "flagged": True}],
                }
            ],
            "flags": [
                {
                    "id": "verifiability-0",
                    "concern": detail,
                    "category": "verifiability",
                    "severity_hint": "likely-minor",
                    "evidence": detail,
                    "source_check_id": "scope",
                }
            ],
            "verified_flag_ids": ["verifiability-0"],
            "disputed_flag_ids": [],
        }

    canonical_ids: list[str] = []
    for iteration, detail in enumerate(
        (
            "Criterion 11 requires human verification.",
            "Criterion 12 requires human verification.",
        ),
        start=1,
    ):
        state["iteration"] = iteration
        if iteration > 1:
            state["plan_versions"].append(
                {"version": iteration, "file": f"plan_v{iteration}.md"}
            )
        current = payload(detail)
        receipt = _persist_critique(plan_dir, state, current)
        canonical_id = str(receipt["findings"][0]["finding_id"])
        canonical_ids.append(canonical_id)

        critique_path = plan_dir / f"critique_v{iteration}.json"
        persisted = critique_custody.read_json(critique_path)
        persisted["flags"][0]["id"] = "verifiability-0"
        persisted["flags"][0].pop("producer_flag_id", None)
        persisted["verified_flag_ids"] = ["verifiability-0"]
        atomic_write_json(critique_path, persisted)

        receipt_path = plan_dir / f"critique_custody_v{iteration}.json"
        legacy_receipt = critique_custody.read_json(receipt_path)
        legacy_receipt["critique_sha256"] = critique_custody.sha256_file(critique_path)
        legacy_receipt["critique_payload_digest"] = critique_custody._digest(persisted)
        legacy_receipt["flag_ids"] = ["verifiability-0"]
        legacy_receipt["findings"][0]["flag_id"] = "verifiability-0"
        legacy_receipt.pop("receipt_digest", None)
        legacy_receipt["receipt_digest"] = critique_custody._digest(legacy_receipt)
        atomic_write_json(receipt_path, legacy_receipt)

    atomic_write_json(
        plan_dir / "faults.json",
        {
            "flags": [
                {
                    "id": "verifiability-0",
                    "concern": "Criterion 12 requires human verification.",
                    "category": "verifiability",
                    "severity_hint": "likely-minor",
                    "evidence": "Criterion 12 requires human verification.",
                    "raised_in": "critique_v2.json",
                    "status": "open",
                    "severity": "minor",
                    "verified": True,
                    "verified_in": "critique_v2.json",
                }
            ]
        },
    )

    clearance = write_critique_clearance(plan_dir, state)

    assert clearance["finding_ids"] == [canonical_ids[1]]
    assert clearance["resolutions"] == [
        {
            "finding_id": canonical_ids[1],
            "flag_id": "verifiability-0",
            "disposition": "tracked_nonblocking_observation",
            "evidence": "Criterion 12 requires human verification.",
            "verified_in": "critique_v2.json",
        }
    ]


def test_clearance_accepts_explicit_gate_tradeoff_for_significant_finding(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    _persist_critique(plan_dir, state, payload)
    finding_id = payload["flags"][0]["id"]
    update_flags_after_gate(
        plan_dir,
        [
            {
                "flag_id": finding_id,
                "action": "accept_tradeoff",
                "evidence": "The bounded gate reviewed the exact remaining concern.",
                "rationale": "The risk is explicit, bounded, and accepted by the gate.",
            }
        ],
    )

    clearance = write_critique_clearance(plan_dir, state)

    assert clearance["resolutions"] == [
        {
            "finding_id": finding_id,
            "flag_id": finding_id,
            "disposition": "minor_tradeoff",
            "evidence": "The risk is explicit, bounded, and accepted by the gate.",
        }
    ]


def test_clearance_rejects_reused_legacy_slot_with_blocking_occurrence(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    first = _oversized_payload()
    first_receipt = _persist_critique(plan_dir, state, first)
    first_receipt["findings"][0]["flag_id"] = "worker-slot-0"
    first_receipt["flag_ids"] = ["worker-slot-0"]
    first_receipt.pop("receipt_digest", None)
    first_receipt["receipt_digest"] = critique_custody._digest(first_receipt)
    atomic_write_json(plan_dir / "critique_custody_v1.json", first_receipt)
    first_payload = critique_custody.read_json(plan_dir / "critique_v1.json")
    first_payload["flags"][0]["id"] = "worker-slot-0"
    first_payload["flags"][0].pop("producer_flag_id", None)
    atomic_write_json(plan_dir / "critique_v1.json", first_payload)
    first_receipt["critique_sha256"] = critique_custody.sha256_file(
        plan_dir / "critique_v1.json"
    )
    first_receipt["critique_payload_digest"] = critique_custody._digest(first_payload)
    first_receipt.pop("receipt_digest", None)
    first_receipt["receipt_digest"] = critique_custody._digest(first_receipt)
    atomic_write_json(plan_dir / "critique_custody_v1.json", first_receipt)

    state["iteration"] = 2
    state["plan_versions"].append({"version": 2, "file": "plan_v2.md"})
    second = _oversized_payload()
    second["flags"][0]["concern"] = "A different blocking concern."
    second["flags"][0]["evidence"] = second["checks"][0]["findings"][0]["detail"]
    second_receipt = _persist_critique(plan_dir, state, second)
    second_receipt["findings"][0]["flag_id"] = "worker-slot-0"
    second_receipt["flag_ids"] = ["worker-slot-0"]
    second_payload = critique_custody.read_json(plan_dir / "critique_v2.json")
    second_payload["flags"][0]["id"] = "worker-slot-0"
    second_payload["flags"][0].pop("producer_flag_id", None)
    atomic_write_json(plan_dir / "critique_v2.json", second_payload)
    second_receipt["critique_sha256"] = critique_custody.sha256_file(
        plan_dir / "critique_v2.json"
    )
    second_receipt["critique_payload_digest"] = critique_custody._digest(second_payload)
    second_receipt.pop("receipt_digest", None)
    second_receipt["receipt_digest"] = critique_custody._digest(second_receipt)
    atomic_write_json(plan_dir / "critique_custody_v2.json", second_receipt)

    with pytest.raises(CritiqueCustodyError, match="blocking occurrence"):
        write_critique_clearance(plan_dir, state)

def test_clearance_binds_exact_final_graph_and_execute_rejects_missing_or_mutated_custody(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    _persist_critique(plan_dir, state, payload)
    canonical_id = payload["flags"][0]["id"]
    atomic_write_text(plan_dir / "plan_v2.md", "# Plan v2\n\nSplit Step 2 into bounded tasks.\n")
    state["iteration"] = 2
    state["plan_versions"].append({"version": 2, "file": "plan_v2.md"})
    update_flags_after_revise(
        plan_dir,
        [
            {
                "id": canonical_id,
                "resolution": "addressed",
                "reason": "Split into bounded tasks.",
                "where": "Step 2",
            }
        ],
        plan_file="plan_v2.md",
        summary="Split the task.",
    )
    update_flags_after_gate(
        plan_dir,
        [{"flag_id": canonical_id, "action": "verify_fixed", "evidence": "plan_v2.md Step 2", "rationale": ""}],
    )
    clearance = write_critique_clearance(plan_dir, state)
    graph = _admitted_graph()
    graph["critique_resolution_coverage"] = [
        {
            "finding_id": clearance["finding_ids"][0],
            "task_ids": ["T1"],
            "resolution_evidence": "T1 implements the bounded split from plan_v2.md Step 2.",
        }
    ]

    with pytest.raises(CritiqueCustodyError) as missing:
        assert_finalize_custody(plan_dir, graph)
    assert missing.value.code == "finalize_critique_custody_missing"

    bind_finalize_custody(plan_dir, graph, clearance)
    assert_finalize_custody(plan_dir, graph)
    graph["tasks"][0]["objective"] = "Regenerate a different oversized objective after clearance."
    with pytest.raises(CritiqueCustodyError, match="graph hash differs"):
        assert_finalize_custody(plan_dir, graph)


def test_finalizer_partial_or_unknown_finding_mapping_fails_closed() -> None:
    graph = _admitted_graph()
    graph["critique_resolution_coverage"] = [
        {"finding_id": "CF-ONE", "task_ids": ["T1"], "resolution_evidence": "Mapped."}
    ]
    clearance = {"finding_ids": ["CF-ONE", "CF-TWO"]}
    with pytest.raises(CritiqueCustodyError) as partial:
        validate_finalize_resolution_coverage(graph, clearance)
    assert partial.value.code == "finalize_critique_coverage_invalid"

    graph["critique_resolution_coverage"].append(
        {"finding_id": "CF-TWO", "task_ids": ["T404"], "resolution_evidence": "Missing task."}
    )
    with pytest.raises(CritiqueCustodyError, match="unknown task_ids"):
        validate_finalize_resolution_coverage(graph, clearance)


def test_equivalent_35_task_linear_graph_is_deterministically_rejected() -> None:
    tasks: list[dict[str, Any]] = []
    for index in range(1, 36):
        task_id = f"T{index}"
        dependency = f"T{index - 1}" if index > 1 else None
        tasks.append(
            {
                "id": task_id,
                "objective": f"Implement bounded objective {index}.",
                "description": f"Implement slice {index}.",
                "kind": "code",
                "complexity": 4,
                "estimated_minutes": 5,
                "depends_on": [dependency] if dependency else [],
                "dependency_reasons": (
                    {
                        dependency: {
                            "kind": "consumes_output",
                            "reason": "Consumes prior contract.",
                            "required_output": dependency,
                        }
                    }
                    if dependency
                    else {}
                ),
                "routing_group": "",
                "write_set": {"paths": [f"src/task_{index}.py"], "complete": True},
                "narrow_tests": {"selectors": [], "max_seconds": 0, "max_runs": 0},
                "checkpoint": {"required": False, "max_interval_seconds": 300, "records": []},
            }
        )
    report = compile_task_feasibility(
        {"task_contract_version": 2, "validation_jobs": [], "tasks": tasks},
        {"phase_timeout_seconds": 3600},
    )
    assert report["admitted"] is False
    assert report["task_count"] == 35
    assert report["seriality"] == 1.0
    assert "serial_graph_unjustified" in {item["code"] for item in report["diagnostics"]}


# --- CL4 Step 9: reconciliation/disposition artifact SHA-256 bindings ---


def _write_semantic_loop_artifacts(
    plan_dir: Path, *, iteration: int
) -> tuple[str, str]:
    """Persist representative semantic-loop artifacts and return their basenames."""
    reconciliation_name = f"reconciliation_v{iteration}.json"
    disposition_name = f"disposition_v{iteration}.json"
    atomic_write_json(
        plan_dir / reconciliation_name,
        {"occurrence_accounting": [], "accepted": True, "occurrence_count": 0},
    )
    atomic_write_json(
        plan_dir / disposition_name,
        {"disposition_map": {}, "families": []},
    )
    return reconciliation_name, disposition_name


def test_production_receipt_binds_reconciliation_and_disposition_artifacts(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    iteration = state["iteration"]
    reconciliation_name, disposition_name = _write_semantic_loop_artifacts(
        plan_dir, iteration=iteration
    )

    receipt = _persist_critique(
        plan_dir,
        state,
        payload,
        reconciliation_artifacts=[reconciliation_name],
        disposition_artifacts=[disposition_name],
    )

    assert receipt["reconciliation_artifacts"] == [
        {
            "artifact": reconciliation_name,
            "sha256": critique_custody.sha256_file(plan_dir / reconciliation_name),
        }
    ]
    assert receipt["disposition_artifacts"] == [
        {
            "artifact": disposition_name,
            "sha256": critique_custody.sha256_file(plan_dir / disposition_name),
        }
    ]
    # Intact bindings survive the gate-entry custody validation path.
    gate_input = validate_gate_input_custody(plan_dir, state)
    assert gate_input["admitted"] is True


def test_missing_reconciliation_artifact_fails_closed(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    iteration = state["iteration"]
    reconciliation_name, disposition_name = _write_semantic_loop_artifacts(
        plan_dir, iteration=iteration
    )
    _persist_critique(
        plan_dir,
        state,
        payload,
        reconciliation_artifacts=[reconciliation_name],
        disposition_artifacts=[disposition_name],
    )

    (plan_dir / reconciliation_name).unlink()

    with pytest.raises(
        CritiqueCustodyError,
        match="reconciliation_artifacts artifact is missing or unsafe",
    ):
        validate_gate_input_custody(plan_dir, state)


def test_missing_disposition_artifact_fails_closed(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    iteration = state["iteration"]
    reconciliation_name, disposition_name = _write_semantic_loop_artifacts(
        plan_dir, iteration=iteration
    )
    _persist_critique(
        plan_dir,
        state,
        payload,
        reconciliation_artifacts=[reconciliation_name],
        disposition_artifacts=[disposition_name],
    )

    (plan_dir / disposition_name).unlink()

    with pytest.raises(
        CritiqueCustodyError,
        match="disposition_artifacts artifact is missing or unsafe",
    ):
        validate_gate_input_custody(plan_dir, state)


def test_hash_mismatched_reconciliation_artifact_fails_closed(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    iteration = state["iteration"]
    reconciliation_name, disposition_name = _write_semantic_loop_artifacts(
        plan_dir, iteration=iteration
    )
    _persist_critique(
        plan_dir,
        state,
        payload,
        reconciliation_artifacts=[reconciliation_name],
        disposition_artifacts=[disposition_name],
    )

    # Tamper with the bound artifact content after custody was taken.
    atomic_write_json(plan_dir / reconciliation_name, {"mutated": True})

    with pytest.raises(
        CritiqueCustodyError,
        match="reconciliation_artifacts artifact hash mismatch",
    ):
        validate_gate_input_custody(plan_dir, state)


def test_hash_mismatched_disposition_artifact_fails_closed(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    iteration = state["iteration"]
    reconciliation_name, disposition_name = _write_semantic_loop_artifacts(
        plan_dir, iteration=iteration
    )
    _persist_critique(
        plan_dir,
        state,
        payload,
        reconciliation_artifacts=[reconciliation_name],
        disposition_artifacts=[disposition_name],
    )

    atomic_write_json(plan_dir / disposition_name, {"tampered": "disposition"})

    with pytest.raises(
        CritiqueCustodyError,
        match="disposition_artifacts artifact hash mismatch",
    ):
        validate_gate_input_custody(plan_dir, state)


def test_symlinked_reconciliation_artifact_fails_closed(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    iteration = state["iteration"]
    reconciliation_name, disposition_name = _write_semantic_loop_artifacts(
        plan_dir, iteration=iteration
    )
    _persist_critique(
        plan_dir,
        state,
        payload,
        reconciliation_artifacts=[reconciliation_name],
        disposition_artifacts=[disposition_name],
    )

    # Replace the bound artifact with a symlink; custody must reject it.
    target = plan_dir / "outside_reconciliation_target.json"
    atomic_write_json(target, {"outside": True})
    bound_path = plan_dir / reconciliation_name
    bound_path.unlink()
    bound_path.symlink_to(target)

    with pytest.raises(
        CritiqueCustodyError,
        match="reconciliation_artifacts artifact is missing or unsafe",
    ):
        validate_gate_input_custody(plan_dir, state)


def test_unsafe_disposition_artifact_reference_in_receipt_fails_closed(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    _persist_critique(plan_dir, state, payload)

    receipt_path = plan_dir / "critique_custody_v1.json"
    receipt = json.loads(receipt_path.read_text())
    # Inject a path-traversal reference the producer would never have materialized.
    receipt["disposition_artifacts"] = [
        {"artifact": "../escape.json", "sha256": "sha256:" + "0" * 64}
    ]
    _rewrite_receipt_digest(receipt)
    atomic_write_json(receipt_path, receipt)

    with pytest.raises(
        CritiqueCustodyError,
        match="disposition_artifacts artifact reference is unsafe",
    ):
        validate_gate_input_custody(plan_dir, state)


def test_reconciliation_artifact_binding_row_without_object_fails_closed(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    _persist_critique(plan_dir, state, payload)

    receipt_path = plan_dir / "critique_custody_v1.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["reconciliation_artifacts"] = ["not-an-object"]
    _rewrite_receipt_digest(receipt)
    atomic_write_json(receipt_path, receipt)

    with pytest.raises(
        CritiqueCustodyError,
        match="reconciliation_artifacts binding row is not an object",
    ):
        validate_gate_input_custody(plan_dir, state)


def test_receipt_without_artifact_bindings_is_backward_compatible(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    _persist_critique(plan_dir, state, payload)

    # Strip the new fields entirely, simulating a pre-CL4 production receipt.
    receipt_path = plan_dir / "critique_custody_v1.json"
    receipt = json.loads(receipt_path.read_text())
    receipt.pop("reconciliation_artifacts", None)
    receipt.pop("disposition_artifacts", None)
    _rewrite_receipt_digest(receipt)
    atomic_write_json(receipt_path, receipt)

    gate_input = validate_gate_input_custody(plan_dir, state)
    assert gate_input["admitted"] is True


def test_receipt_with_artifact_bindings_restarts_idempotently(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    iteration = state["iteration"]
    reconciliation_name, disposition_name = _write_semantic_loop_artifacts(
        plan_dir, iteration=iteration
    )
    first = _persist_critique(
        plan_dir,
        state,
        payload,
        reconciliation_artifacts=[reconciliation_name],
        disposition_artifacts=[disposition_name],
    )
    path = plan_dir / f"critique_custody_v{iteration}.json"
    before = path.read_bytes()

    restarted = write_critique_production_receipt(
        plan_dir,
        state,
        payload,
        expected_check_ids=["scope"],
        producer_binding=_producer_binding(state["meta"]["current_invocation_id"]),
        reconciliation_artifacts=[reconciliation_name],
        disposition_artifacts=[disposition_name],
    )

    assert restarted == first
    assert path.read_bytes() == before


def test_declared_missing_artifact_is_omitted_not_bound(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    iteration = state["iteration"]
    reconciliation_name, disposition_name = _write_semantic_loop_artifacts(
        plan_dir, iteration=iteration
    )
    # Declare an artifact that does not exist on disk alongside a real one.
    receipt = _persist_critique(
        plan_dir,
        state,
        payload,
        reconciliation_artifacts=[reconciliation_name, "absent_reconciliation.json"],
        disposition_artifacts=[disposition_name],
    )

    # The materializer records only the safe, present artifact; the absent one
    # is omitted so the stored binding set stays truthful.
    assert [row["artifact"] for row in receipt["reconciliation_artifacts"]] == [
        reconciliation_name
    ]
    gate_input = validate_gate_input_custody(plan_dir, state)
    assert gate_input["admitted"] is True


def test_artifact_bindings_propagate_through_clearance_custody(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    iteration = state["iteration"]
    reconciliation_name, disposition_name = _write_semantic_loop_artifacts(
        plan_dir, iteration=iteration
    )
    _persist_critique(
        plan_dir,
        state,
        payload,
        reconciliation_artifacts=[reconciliation_name],
        disposition_artifacts=[disposition_name],
    )
    # Capture the reducer-normalized canonical id *after* persistence.
    canonical_id = payload["flags"][0]["id"]
    atomic_write_text(plan_dir / "plan_v2.md", "# Plan v2\n\nSplit Step 2 into bounded tasks.\n")
    state["iteration"] = 2
    state["plan_versions"].append({"version": 2, "file": "plan_v2.md"})
    update_flags_after_revise(
        plan_dir,
        [
            {
                "id": canonical_id,
                "resolution": "addressed",
                "reason": "Split into bounded tasks.",
                "where": "Step 2",
            }
        ],
        plan_file="plan_v2.md",
        summary="Split the task.",
    )
    update_flags_after_gate(
        plan_dir,
        [{"flag_id": canonical_id, "action": "verify_fixed", "evidence": "plan_v2.md Step 2", "rationale": ""}],
    )
    clearance = write_critique_clearance(plan_dir, state)
    assert clearance["admitted"] is True

    # Clearance re-validates the bound receipt; tampering with a bound artifact
    # must fail closed at clearance time, not only at the gate.
    atomic_write_json(plan_dir / disposition_name, {"mutated": True})
    with pytest.raises(
        CritiqueCustodyError,
        match="disposition_artifacts artifact hash mismatch",
    ):
        write_critique_clearance(plan_dir, state)


def test_production_receipt_carries_bridge_mode_and_carried_blockers(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()

    receipt = _persist_critique(plan_dir, state, payload)

    # Post-CL5-cutover: the module-level BRIDGE markers are disabled, so a fresh
    # production receipt carries bridge_mode=false and no carried blockers.
    assert receipt["bridge_mode"] is False
    assert receipt["carried_blockers"] == list(critique_custody.CL4_CARRIED_BLOCKERS)
    # The gate-entry custody path accepts the receipt as valid integrity
    # evidence (canonical authority is still denied at runtime only when a
    # *source receipt* in the clearance chain carries bridge_mode=true).
    gate_input = validate_gate_input_custody(plan_dir, state)
    assert gate_input["admitted"] is True


def test_bridge_mode_and_carried_blockers_restart_idempotently(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    first = _persist_critique(plan_dir, state, payload)
    path = plan_dir / "critique_custody_v1.json"
    before = path.read_bytes()

    restarted = write_critique_production_receipt(
        plan_dir,
        state,
        payload,
        expected_check_ids=["scope"],
        producer_binding=_producer_binding(state["meta"]["current_invocation_id"]),
    )

    assert restarted == first
    assert path.read_bytes() == before
    # Post-CL5-cutover: a fresh production receipt is bridge_mode=false.
    assert restarted["bridge_mode"] is False
    assert restarted["carried_blockers"] == list(critique_custody.CL4_CARRIED_BLOCKERS)


def test_malformed_bridge_mode_field_in_receipt_fails_closed(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    _persist_critique(plan_dir, state, _oversized_payload())

    receipt_path = plan_dir / "critique_custody_v1.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["bridge_mode"] = "true"  # not a boolean
    _rewrite_receipt_digest(receipt)
    atomic_write_json(receipt_path, receipt)

    with pytest.raises(
        CritiqueCustodyError, match="bridge_mode must be a boolean"
    ):
        validate_gate_input_custody(plan_dir, state)


def test_receipt_without_bridge_mode_is_backward_compatible(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    _persist_critique(plan_dir, state, _oversized_payload())

    # Strip the CL4 BRIDGE provenance entirely, simulating a pre-CL4 receipt.
    # The receipt_digest protects against undetected stripping in transit; a
    # deliberately re-hashed receipt is treated as a pre-CL4 canonical receipt.
    receipt_path = plan_dir / "critique_custody_v1.json"
    receipt = json.loads(receipt_path.read_text())
    receipt.pop("bridge_mode", None)
    receipt.pop("carried_blockers", None)
    _rewrite_receipt_digest(receipt)
    atomic_write_json(receipt_path, receipt)

    gate_input = validate_gate_input_custody(plan_dir, state)
    assert gate_input["admitted"] is True


def test_reconciliation_claims_require_matrix_authorized_producer(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    iteration = state["iteration"]
    reconciliation_name, disposition_name = _write_semantic_loop_artifacts(
        plan_dir, iteration=iteration
    )
    _persist_critique(
        plan_dir,
        state,
        payload,
        reconciliation_artifacts=[reconciliation_name],
        disposition_artifacts=[disposition_name],
    )

    receipt_path = plan_dir / "critique_custody_v1.json"
    receipt = json.loads(receipt_path.read_text())
    # An out-of-scope producer claims reconciliation evidence; its receipt
    # digest is internally consistent but its producer is unauthorized.
    receipt["producer_binding"]["producer"] = "rogue-evaluator"
    receipt["producer_binding_digest"] = critique_custody._digest(
        receipt["producer_binding"]
    )
    _rewrite_receipt_digest(receipt)
    atomic_write_json(receipt_path, receipt)

    with pytest.raises(
        CritiqueCustodyError,
        match="reconciliation claims require a matrix-authorized critique producer",
    ):
        validate_gate_input_custody(plan_dir, state)


def test_out_of_scope_producer_without_reconciliation_claims_is_admitted(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    _persist_critique(plan_dir, state, _oversized_payload())

    receipt_path = plan_dir / "critique_custody_v1.json"
    receipt = json.loads(receipt_path.read_text())
    # The producer is out of scope but the receipt makes NO reconciliation
    # claim, so the negative-authority boundary does not reject it.
    receipt["producer_binding"]["producer"] = "rogue-evaluator"
    receipt["producer_binding_digest"] = critique_custody._digest(
        receipt["producer_binding"]
    )
    _rewrite_receipt_digest(receipt)
    atomic_write_json(receipt_path, receipt)

    gate_input = validate_gate_input_custody(plan_dir, state)
    assert gate_input["admitted"] is True


def test_clearance_propagates_bridge_mode_from_source_receipts(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    _persist_critique(plan_dir, state, payload)
    canonical_id = payload["flags"][0]["id"]
    atomic_write_text(
        plan_dir / "plan_v2.md", "# Plan v2\n\nSplit Step 2 into bounded tasks.\n"
    )
    state["iteration"] = 2
    state["plan_versions"].append({"version": 2, "file": "plan_v2.md"})
    update_flags_after_revise(
        plan_dir,
        [
            {
                "id": canonical_id,
                "resolution": "addressed",
                "reason": "Split into bounded tasks.",
                "where": "Step 2",
            }
        ],
        plan_file="plan_v2.md",
        summary="Split the task.",
    )
    update_flags_after_gate(
        plan_dir,
        [{"flag_id": canonical_id, "action": "verify_fixed", "evidence": "plan_v2.md Step 2", "rationale": ""}],
    )

    clearance = write_critique_clearance(plan_dir, state)

    # Post-CL5-cutover: every fresh source receipt carries bridge_mode=false, so
    # an all-fresh clearance chain aggregates to bridge_mode=false / no blockers.
    assert clearance["bridge_mode"] is False
    assert clearance["carried_blockers"] == list(critique_custody.CL4_CARRIED_BLOCKERS)

    # Mixed old/new chain (Step 10.8): inject ONE stale pre-cutover source
    # receipt (bridge_mode=true) as an older occurrence. The aggregator must
    # fail closed — ANY bridge_mode=true source receipt flips the aggregated
    # clearance to bridge_mode=true and inherits its carried blockers, so a
    # stale receipt can never hide behind fresh ones.
    stale_path = plan_dir / "critique_custody_v1.json"
    stale = json.loads(stale_path.read_text())
    stale["bridge_mode"] = True
    stale["carried_blockers"] = ["stale_pre_cutover_blocker"]
    _rewrite_receipt_digest(stale)
    atomic_write_json(stale_path, stale)

    mixed_clearance = write_critique_clearance(plan_dir, state)
    assert mixed_clearance["bridge_mode"] is True
    assert "stale_pre_cutover_blocker" in mixed_clearance["carried_blockers"]


def test_finalize_custody_denies_canonical_authority_for_bridge_receipt(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    _persist_critique(plan_dir, state, payload)
    canonical_id = payload["flags"][0]["id"]
    atomic_write_text(
        plan_dir / "plan_v2.md", "# Plan v2\n\nSplit Step 2 into bounded tasks.\n"
    )
    state["iteration"] = 2
    state["plan_versions"].append({"version": 2, "file": "plan_v2.md"})
    update_flags_after_revise(
        plan_dir,
        [
            {
                "id": canonical_id,
                "resolution": "addressed",
                "reason": "Split into bounded tasks.",
                "where": "Step 2",
            }
        ],
        plan_file="plan_v2.md",
        summary="Split the task.",
    )
    update_flags_after_gate(
        plan_dir,
        [{"flag_id": canonical_id, "action": "verify_fixed", "evidence": "plan_v2.md Step 2", "rationale": ""}],
    )
    # Mixed old/new chain (Step 10.8): inject ONE stale pre-cutover source
    # receipt (bridge_mode=true) into the clearance chain. The fresh receipt
    # produced above is bridge_mode=false; the stale one makes the aggregated
    # clearance bridge_mode=true so the finalize binding must deny canonical
    # authority even though the module-level BRIDGE markers are now disabled.
    stale_path = plan_dir / "critique_custody_v1.json"
    stale = json.loads(stale_path.read_text())
    stale["bridge_mode"] = True
    stale["carried_blockers"] = ["stale_pre_cutover_blocker"]
    _rewrite_receipt_digest(stale)
    atomic_write_json(stale_path, stale)
    clearance = write_critique_clearance(plan_dir, state)
    assert clearance["bridge_mode"] is True

    graph = _admitted_graph()
    graph["critique_resolution_coverage"] = [
        {
            "finding_id": clearance["finding_ids"][0],
            "task_ids": ["T1"],
            "resolution_evidence": "T1 implements the bounded split from plan_v2.md Step 2.",
        }
    ]

    binding = bind_finalize_custody(plan_dir, graph, clearance)

    # A clearance whose chain contains any bridge_mode=true source receipt must
    # never bind canonical gate authority (one stale receipt denies it).
    assert binding["bridge_mode"] is True
    assert binding["canonical_gate_authority"] is False
    assert "stale_pre_cutover_blocker" in binding["carried_blockers"]

    # finalize custody accepts the bridge receipt as non-canonical integrity
    # evidence: the returned binding explicitly denies canonical authority, so
    # no downstream consumer can mistake it for canonical gate authority.
    finalized = assert_finalize_custody(plan_dir, graph)
    assert finalized["canonical_gate_authority"] is False


def test_all_false_clearance_chain_grants_canonical_authority(
    tmp_path: Path,
) -> None:
    """CL5 (Step 10.10): contrast to the mixed chain — when EVERY source receipt
    in the clearance chain carries bridge_mode=false (the post-cutover steady
    state), the clearance is bridge_mode=false and the finalize binding GRANTS
    canonical gate authority. This is the positive complement to the stale-
    receipt denial: only a bridge_mode=true source receipt denies authority."""
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    _persist_critique(plan_dir, state, payload)
    canonical_id = payload["flags"][0]["id"]
    atomic_write_text(
        plan_dir / "plan_v2.md", "# Plan v2\n\nSplit Step 2 into bounded tasks.\n"
    )
    state["iteration"] = 2
    state["plan_versions"].append({"version": 2, "file": "plan_v2.md"})
    update_flags_after_revise(
        plan_dir,
        [{"id": canonical_id, "resolution": "addressed", "reason": "Split into bounded tasks.", "where": "Step 2"}],
        plan_file="plan_v2.md",
        summary="Split the task.",
    )
    update_flags_after_gate(
        plan_dir,
        [{"flag_id": canonical_id, "action": "verify_fixed", "evidence": "plan_v2.md Step 2", "rationale": ""}],
    )
    clearance = write_critique_clearance(plan_dir, state)
    # All-false chain: no source receipt is bridge_mode=true.
    assert clearance["bridge_mode"] is False
    assert clearance["carried_blockers"] == []

    graph = _admitted_graph()
    graph["critique_resolution_coverage"] = [
        {
            "finding_id": clearance["finding_ids"][0],
            "task_ids": ["T1"],
            "resolution_evidence": "T1 implements the bounded split from plan_v2.md Step 2.",
        }
    ]
    binding = bind_finalize_custody(plan_dir, graph, clearance)
    assert binding["bridge_mode"] is False
    assert binding["canonical_gate_authority"] is True
    finalized = assert_finalize_custody(plan_dir, graph)
    assert finalized["canonical_gate_authority"] is True


def test_finalize_custody_rejects_tampered_canonical_authority_for_bridge_receipt(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    _persist_critique(plan_dir, state, payload)
    canonical_id = payload["flags"][0]["id"]
    atomic_write_text(
        plan_dir / "plan_v2.md", "# Plan v2\n\nSplit Step 2 into bounded tasks.\n"
    )
    state["iteration"] = 2
    state["plan_versions"].append({"version": 2, "file": "plan_v2.md"})
    update_flags_after_revise(
        plan_dir,
        [
            {
                "id": canonical_id,
                "resolution": "addressed",
                "reason": "Split into bounded tasks.",
                "where": "Step 2",
            }
        ],
        plan_file="plan_v2.md",
        summary="Split the task.",
    )
    update_flags_after_gate(
        plan_dir,
        [{"flag_id": canonical_id, "action": "verify_fixed", "evidence": "plan_v2.md Step 2", "rationale": ""}],
    )
    # Mixed old/new chain: inject a stale bridge_mode=true source receipt so the
    # clearance is bridge-mode (the tamper check only fires for a bridge
    # clearance whose canonical authority a malicious finalizer could forge).
    stale_path = plan_dir / "critique_custody_v1.json"
    stale = json.loads(stale_path.read_text())
    stale["bridge_mode"] = True
    stale["carried_blockers"] = ["stale_pre_cutover_blocker"]
    _rewrite_receipt_digest(stale)
    atomic_write_json(stale_path, stale)
    clearance = write_critique_clearance(plan_dir, state)

    graph = _admitted_graph()
    graph["critique_resolution_coverage"] = [
        {
            "finding_id": clearance["finding_ids"][0],
            "task_ids": ["T1"],
            "resolution_evidence": "T1 implements the bounded split from plan_v2.md Step 2.",
        }
    ]
    bind_finalize_custody(plan_dir, graph, clearance)

    # A malicious finalizer flips the binding to claim canonical authority for
    # a bridge_mode=true clearance; finalize custody must fail closed.
    graph["critique_custody"]["canonical_gate_authority"] = True
    with pytest.raises(
        CritiqueCustodyError, match="cannot bind canonical gate authority"
    ):
        assert_finalize_custody(plan_dir, graph)


def test_finalize_custody_rejects_bridge_mode_mismatch_with_clearance(
    tmp_path: Path,
) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    payload = _oversized_payload()
    _persist_critique(plan_dir, state, payload)
    canonical_id = payload["flags"][0]["id"]
    atomic_write_text(
        plan_dir / "plan_v2.md", "# Plan v2\n\nSplit Step 2 into bounded tasks.\n"
    )
    state["iteration"] = 2
    state["plan_versions"].append({"version": 2, "file": "plan_v2.md"})
    update_flags_after_revise(
        plan_dir,
        [
            {
                "id": canonical_id,
                "resolution": "addressed",
                "reason": "Split into bounded tasks.",
                "where": "Step 2",
            }
        ],
        plan_file="plan_v2.md",
        summary="Split the task.",
    )
    update_flags_after_gate(
        plan_dir,
        [{"flag_id": canonical_id, "action": "verify_fixed", "evidence": "plan_v2.md Step 2", "rationale": ""}],
    )
    # Mixed old/new chain: inject a stale bridge_mode=true source receipt so the
    # clearance is bridge-mode (the mismatch check requires a bridge clearance).
    stale_path = plan_dir / "critique_custody_v1.json"
    stale = json.loads(stale_path.read_text())
    stale["bridge_mode"] = True
    stale["carried_blockers"] = ["stale_pre_cutover_blocker"]
    _rewrite_receipt_digest(stale)
    atomic_write_json(stale_path, stale)
    clearance = write_critique_clearance(plan_dir, state)

    graph = _admitted_graph()
    graph["critique_resolution_coverage"] = [
        {
            "finding_id": clearance["finding_ids"][0],
            "task_ids": ["T1"],
            "resolution_evidence": "T1 implements the bounded split from plan_v2.md Step 2.",
        }
    ]
    bind_finalize_custody(plan_dir, graph, clearance)

    # Tamper the binding's bridge_mode to disagree with the (bridge) clearance.
    graph["critique_custody"]["bridge_mode"] = False
    graph["critique_custody"]["canonical_gate_authority"] = True
    with pytest.raises(
        CritiqueCustodyError, match="bridge_mode differs from clearance"
    ):
        assert_finalize_custody(plan_dir, graph)


# ---------------------------------------------------------------------------
# Custody acceptance: verified findings cleared without a revise fixed-claim
# ---------------------------------------------------------------------------

_ACCEPTANCE_FINDING_DETAIL = (
    "Step 10 refuse-ambiguous conversion needs an atomic temp+fsync+rename migration."
)
_ACCEPTANCE_FLAG_CONCERN = (
    "Refuse-ambiguous conversion leaves mixed-import pypelines unconvertible."
)
_ACCEPTANCE_GATE_EVIDENCE = (
    "Plan v2 Step 10B.1 writes a temp file, fsyncs, then renames; EXDEV uses "
    "copy+fsync+unlink with a checksum; ambiguous input is refused with "
    "S2F_CONVERTER_AMBIGUOUS and converter quarantine."
)


def _acceptance_payload(*, flagged: bool, verified: list[str]) -> dict[str, Any]:
    findings = [{"detail": _ACCEPTANCE_FINDING_DETAIL, "flagged": True}] if flagged else []
    return {
        "checks": [{"id": "scope", "question": "Are tasks bounded?", "findings": findings}],
        "flags": [
            {
                "id": "scope-conv-ambiguous",
                "concern": _ACCEPTANCE_FLAG_CONCERN,
                "category": "correctness",
                "severity_hint": "likely-significant",
                "evidence": _ACCEPTANCE_FINDING_DETAIL,
                "source_check_id": "scope",
            }
        ]
        if flagged
        else [],
        "verified_flag_ids": list(verified),
        "disputed_flag_ids": [],
    }


def _advance_iteration(
    plan_dir: Path,
    state: dict[str, Any],
    *,
    iteration: int,
    payload: dict[str, Any],
) -> dict[str, Any]:
    next_state = deepcopy(state)
    next_state["iteration"] = iteration
    next_state["current_state"] = "critiqued"
    next_state["plan_versions"] = [
        {"version": version, "file": f"plan_v{version}.md"}
        for version in range(1, iteration + 1)
    ]
    next_state["meta"]["current_invocation_id"] = f"critique-invocation-{iteration}"
    atomic_write_text(
        plan_dir / f"plan_v{iteration}.md",
        f"# Plan v{iteration}\n\nBounded work slice {iteration}.\n",
    )
    atomic_write_text(plan_dir / f"critique_raw_v{iteration}.txt", "raw producer critique")
    prepare_critique_payload(payload, expected_check_ids=["scope"])
    atomic_write_json(plan_dir / f"critique_v{iteration}.json", payload)
    write_critique_production_receipt(
        plan_dir,
        next_state,
        payload,
        expected_check_ids=["scope"],
        producer_binding=_producer_binding(next_state["meta"]["current_invocation_id"]),
    )
    update_flags_after_critique(plan_dir, payload, iteration=iteration)
    return next_state


def test_clearance_accepts_finding_verified_by_current_critique(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    _persist_critique(plan_dir, state, _acceptance_payload(flagged=True, verified=[]))
    flag_id = load_flag_registry(plan_dir)["flags"][0]["id"]

    next_state = _advance_iteration(
        plan_dir,
        state,
        iteration=2,
        payload=_acceptance_payload(flagged=False, verified=[flag_id]),
    )
    flag = load_flag_registry(plan_dir)["flags"][0]
    assert flag["status"] == "verified"
    assert flag["verified_in"] == "critique_v2.json"
    assert "resolution" not in flag

    clearance = write_critique_clearance(plan_dir, next_state)
    assert clearance["finding_count"] == 1
    resolution = clearance["resolutions"][0]
    assert resolution["disposition"] == "verified_by_current_critique"
    assert resolution["verified_in"] == "critique_v2.json"
    assert resolution["plan_artifact"] == "plan_v2.md"
    assert resolution["verification_receipt"] == "critique_custody_v2.json"
    assert resolution["evidence"].strip()


def test_clearance_still_rejects_verification_receipt_bound_to_older_plan(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    _persist_critique(plan_dir, state, _acceptance_payload(flagged=True, verified=[]))
    flag_id = load_flag_registry(plan_dir)["flags"][0]["id"]
    _advance_iteration(
        plan_dir,
        state,
        iteration=2,
        payload=_acceptance_payload(flagged=False, verified=[flag_id]),
    )
    final_state = _advance_iteration(
        plan_dir,
        state,
        iteration=3,
        payload=_acceptance_payload(flagged=False, verified=[]),
    )
    with pytest.raises(CritiqueCustodyError, match="critique_finding_unresolved"):
        write_critique_clearance(plan_dir, final_state)


def test_clearance_still_rejects_finding_recurring_in_verification_iteration(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    _persist_critique(plan_dir, state, _acceptance_payload(flagged=True, verified=[]))
    flag_id = load_flag_registry(plan_dir)["flags"][0]["id"]
    next_state = _advance_iteration(
        plan_dir,
        state,
        iteration=2,
        payload=_acceptance_payload(flagged=True, verified=[]),
    )
    update_flags_after_gate(
        plan_dir,
        [{"flag_id": flag_id, "action": "verify_fixed", "evidence": _ACCEPTANCE_GATE_EVIDENCE}],
    )
    with pytest.raises(CritiqueCustodyError, match="critique_finding_unresolved"):
        write_critique_clearance(plan_dir, next_state)


def test_clearance_accepts_gate_verify_fixed_with_concrete_evidence(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    _persist_critique(plan_dir, state, _acceptance_payload(flagged=True, verified=[]))
    flag_id = load_flag_registry(plan_dir)["flags"][0]["id"]
    next_state = _advance_iteration(
        plan_dir,
        state,
        iteration=2,
        payload=_acceptance_payload(flagged=False, verified=[]),
    )
    update_flags_after_gate(
        plan_dir,
        [{"flag_id": flag_id, "action": "verify_fixed", "evidence": _ACCEPTANCE_GATE_EVIDENCE}],
    )
    flag = load_flag_registry(plan_dir)["flags"][0]
    assert flag["status"] == "verified"
    assert flag["verified_in"] == "gate.json"
    assert flag["gate_resolution"]["action"] == "verify_fixed"

    clearance = write_critique_clearance(plan_dir, next_state)
    resolution = clearance["resolutions"][0]
    assert resolution["disposition"] == "verified_by_gate_evidence"
    assert resolution["evidence"] == _ACCEPTANCE_GATE_EVIDENCE


def test_clearance_still_rejects_gate_verify_fixed_with_empty_evidence(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    _persist_critique(plan_dir, state, _acceptance_payload(flagged=True, verified=[]))
    flag_id = load_flag_registry(plan_dir)["flags"][0]["id"]
    next_state = _advance_iteration(
        plan_dir,
        state,
        iteration=2,
        payload=_acceptance_payload(flagged=False, verified=[]),
    )
    update_flags_after_gate(
        plan_dir,
        [{"flag_id": flag_id, "action": "verify_fixed", "evidence": None}],
    )
    with pytest.raises(CritiqueCustodyError, match="critique_finding_unresolved"):
        write_critique_clearance(plan_dir, next_state)


def test_clearance_still_rejects_gate_verify_fixed_with_rubber_stamp_evidence(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    _persist_critique(plan_dir, state, _acceptance_payload(flagged=True, verified=[]))
    flag_id = load_flag_registry(plan_dir)["flags"][0]["id"]
    next_state = _advance_iteration(
        plan_dir,
        state,
        iteration=2,
        payload=_acceptance_payload(flagged=False, verified=[]),
    )
    update_flags_after_gate(
        plan_dir,
        [{"flag_id": flag_id, "action": "verify_fixed", "evidence": "looks good"}],
    )
    with pytest.raises(CritiqueCustodyError, match="critique_finding_unresolved"):
        write_critique_clearance(plan_dir, next_state)


def test_clearance_still_rejects_gate_verify_fixed_restating_the_concern(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    _persist_critique(plan_dir, state, _acceptance_payload(flagged=True, verified=[]))
    flag_id = load_flag_registry(plan_dir)["flags"][0]["id"]
    next_state = _advance_iteration(
        plan_dir,
        state,
        iteration=2,
        payload=_acceptance_payload(flagged=False, verified=[]),
    )
    update_flags_after_gate(
        plan_dir,
        [{"flag_id": flag_id, "action": "verify_fixed", "evidence": _ACCEPTANCE_FLAG_CONCERN}],
    )
    with pytest.raises(CritiqueCustodyError, match="critique_finding_unresolved"):
        write_critique_clearance(plan_dir, next_state)


def test_revise_typo_reaches_clearance_through_fixed_claim_without_registry_surgery(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    state = _state(tmp_path)
    _persist_critique(plan_dir, state, _acceptance_payload(flagged=True, verified=[]))
    flag_id = load_flag_registry(plan_dir)["flags"][0]["id"]
    typo_id = flag_id[:-1]

    update_flags_after_revise(
        plan_dir,
        [
            {
                "id": typo_id,
                "resolution": "addressed",
                "reason": "Migration is now atomic.",
                "where": "plan_v2.md Step 10B",
            }
        ],
        plan_file="plan_v2.md",
        summary="split",
    )
    next_state = _advance_iteration(
        plan_dir,
        state,
        iteration=2,
        payload=_acceptance_payload(flagged=False, verified=[flag_id]),
    )
    flag = load_flag_registry(plan_dir)["flags"][0]
    assert flag["status"] == "verified"
    assert flag["resolution"]["kind"] == "fixed"
    assert flag["id_correction"]["from"] == typo_id
    assert flag["id_correction"]["to"] == flag_id

    clearance = write_critique_clearance(plan_dir, next_state)
    assert clearance["resolutions"][0]["disposition"] == "verified_plan_mutation"


# ---------------------------------------------------------------------------
# Producer honesty: exact-first flag reference resolution
# ---------------------------------------------------------------------------


def _seed_registry(plan_dir: Path, flag_ids: list[str]) -> None:
    atomic_write_json(
        plan_dir / "faults.json",
        {
            "flags": [
                {
                    "id": flag_id,
                    "concern": f"Concern for {flag_id}.",
                    "category": "correctness",
                    "severity_hint": "likely-significant",
                    "evidence": f"Evidence for {flag_id}.",
                    "status": "open",
                    "severity": "significant",
                    "verified": False,
                }
                for flag_id in flag_ids
            ]
        },
    )


def test_revise_corrects_unique_dropped_character_flag_reference(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    flag_id = "CF-0123456789ABCDEF0123"
    typo_id = "CF-0123456789ABCDEF012"
    _seed_registry(plan_dir, [flag_id])

    registry = update_flags_after_revise(
        plan_dir,
        [
            {
                "id": typo_id,
                "resolution": "addressed",
                "reason": "Migration is now atomic.",
                "where": "plan_v2.md Step 10B",
            }
        ],
        plan_file="plan_v2.md",
        summary="split",
    )
    flag = registry["flags"][0]
    assert flag["status"] == "addressed"
    assert flag["addressed_in"] == "plan_v2.md"
    assert flag["resolution"] == {
        "kind": "fixed",
        "claim": "Migration is now atomic.",
        "where": "plan_v2.md Step 10B",
    }
    assert flag["id_correction"] == {
        "from": typo_id,
        "to": flag_id,
        "recorded_in": "revise",
        "reference_kind": "addressed",
        "at_iteration": 2,
    }
    assert registry.get("unmatched_flag_references") is None


def test_revise_ambiguous_flag_reference_records_typed_row_and_mutates_nothing(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    flag_a = "CF-0123456789ABCDEF0123"
    flag_b = "CF-0123456789ABCDEF0124"
    typo_id = "CF-0123456789ABCDEF012"
    _seed_registry(plan_dir, [flag_a, flag_b])

    registry = update_flags_after_revise(
        plan_dir,
        [typo_id],
        plan_file="plan_v2.md",
        summary="split",
    )
    unmatched = registry["unmatched_flag_references"]
    assert unmatched == [
        {
            "source": "revise",
            "reference": typo_id,
            "reference_kind": "addressed",
            "reason": "ambiguous",
            "candidates": [flag_a, flag_b],
        }
    ]
    for flag in registry["flags"]:
        assert flag["status"] == "open"
        assert "id_correction" not in flag
        assert "resolution" not in flag
        assert "addressed_in" not in flag


def test_revise_unknown_flag_reference_records_typed_row(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    flag_id = "CF-0123456789ABCDEF0123"
    _seed_registry(plan_dir, [flag_id])

    registry = update_flags_after_revise(
        plan_dir,
        ["CF-99999999999999999999"],
        plan_file="plan_v2.md",
        summary="split",
    )
    assert registry["unmatched_flag_references"] == [
        {
            "source": "revise",
            "reference": "CF-99999999999999999999",
            "reference_kind": "addressed",
            "reason": "no_match",
            "candidates": [],
        }
    ]
    assert registry["flags"][0]["status"] == "open"


def test_exact_flag_reference_creates_no_correction_metadata(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    flag_id = "CF-0123456789ABCDEF0123"
    _seed_registry(plan_dir, [flag_id])

    registry = update_flags_after_revise(
        plan_dir,
        [flag_id],
        plan_file="plan_v2.md",
        summary="split",
    )
    flag = registry["flags"][0]
    assert flag["status"] == "addressed"
    assert "id_correction" not in flag
    assert registry.get("unmatched_flag_references") is None


def test_critique_verified_reference_corrects_and_honors_skip(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    flag_id = "CF-0123456789ABCDEF0123"
    typo_id = "CF-0123456789ABCDEF012"
    _seed_registry(plan_dir, [flag_id])

    payload = {
        "checks": [],
        "flags": [],
        "verified_flag_ids": [typo_id],
        "disputed_flag_ids": [],
    }
    registry = update_flags_after_critique(plan_dir, payload, iteration=2)
    flag = registry["flags"][0]
    assert flag["status"] == "verified"
    assert flag["verified_in"] == "critique_v2.json"
    assert flag["id_correction"]["recorded_in"] == "critique"
    assert flag["id_correction"]["reference_kind"] == "verified"
    assert flag["id_correction"]["at_iteration"] == 2
    assert registry.get("unmatched_flag_references") is None

    _seed_registry(plan_dir, [flag_id])
    registry = update_flags_after_critique(
        plan_dir,
        dict(payload),
        iteration=2,
        skip_flag_ids=frozenset({flag_id}),
    )
    flag = registry["flags"][0]
    assert flag["status"] == "open"
    assert flag["id_correction"]["to"] == flag_id
    assert registry.get("unmatched_flag_references") is None


def test_gate_and_evaluator_references_correct_or_record_typed_rows(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    flag_id = "CF-0123456789ABCDEF0123"
    typo_id = "CF-0123456789ABCDEF012"

    _seed_registry(plan_dir, [flag_id])
    registry = update_flags_after_gate(
        plan_dir,
        [{"flag_id": typo_id, "action": "verify_fixed", "evidence": "Step 10B concrete evidence."}],
    )
    flag = registry["flags"][0]
    assert flag["status"] == "verified"
    assert flag["verified_in"] == "gate.json"
    assert flag["id_correction"] == {
        "from": typo_id,
        "to": flag_id,
        "recorded_in": "gate",
        "reference_kind": "resolution",
    }

    _seed_registry(plan_dir, [flag_id])
    adjudicated = apply_flag_verifications(
        plan_dir,
        [{"flag_id": typo_id, "outcome": "verified", "rationale": "Confirmed atomic."}],
    )
    assert adjudicated == {flag_id}
    registry = load_flag_registry(plan_dir)
    flag = registry["flags"][0]
    assert flag["status"] == "verified"
    assert flag["verified_in"] == "evaluator_verdict.json"
    assert flag["id_correction"]["recorded_in"] == "evaluator"
    assert flag["id_correction"]["reference_kind"] == "verification"

    _seed_registry(plan_dir, [flag_id])
    adjudicated = apply_flag_verifications(
        plan_dir,
        [{"flag_id": "CF-99999999999999999999", "outcome": "verified", "rationale": "Confirmed."}],
    )
    assert adjudicated == set()
    registry = load_flag_registry(plan_dir)
    assert registry["unmatched_flag_references"] == [
        {
            "source": "evaluator",
            "reference": "CF-99999999999999999999",
            "reference_kind": "verification",
            "reason": "no_match",
            "candidates": [],
        }
    ]
    assert registry["flags"][0]["status"] == "open"
