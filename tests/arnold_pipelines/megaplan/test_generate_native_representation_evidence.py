from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.generate_native_representation_evidence import (
    APPROVED_CARRIER_NAMES,
    EVIDENCE_SCHEMA,
    FORBIDDEN_AUTHORITY_SCANS,
    SOURCE_CHECKER,
    generate_evidence_bundle,
)
from scripts.validate_native_representation_conformance import validate_conformance_ledger
from arnold_pipelines.megaplan.workflows.package_fingerprints import (
    canonical_workflow_fingerprints,
)


ROOT = Path(__file__).resolve().parents[3]
CONFORMANCE_PATH = ROOT / "docs/arnold/megaplan-native-representation-conformance.yaml"
TRACEABILITY_PATH = ROOT / "docs/arnold/megaplan-native-representation-traceability.yaml"
RETIRED_COMPATIBILITY_PROOFS = (
    "tests/arnold_pipelines/megaplan/test_compositional_workflow.py",
    "tests/arnold_pipelines/megaplan/workflows/test_workflows_planning.py",
)


def _load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _sha256(path: Path) -> str:
    import hashlib

    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def test_native_evidence_uses_active_proofs_not_retired_skipped_suites() -> None:
    """Generated authority must never point at the retired skip-only suites."""
    authoritative_inputs = (
        CONFORMANCE_PATH,
        ROOT / "docs/arnold/megaplan-native-representation-scenarios.yaml",
        ROOT / "docs/arnold/megaplan-native-representation-evidence.yaml",
    )

    for retired_path in RETIRED_COMPATIBILITY_PROOFS:
        assert not (ROOT / retired_path).exists()
        for artifact in authoritative_inputs:
            assert retired_path not in artifact.read_text(encoding="utf-8")

    assert (
        "tests/arnold_pipelines/megaplan/test_native_contract.py"
        in CONFORMANCE_PATH.read_text(encoding="utf-8")
    )


def test_generate_evidence_bundle_emits_checker_records_and_scoped_boundary_proof() -> None:
    bundle = generate_evidence_bundle(
        conformance_path=CONFORMANCE_PATH,
        traceability_path=TRACEABILITY_PATH,
        repo_root=ROOT,
    )
    conformance = _load_yaml(CONFORMANCE_PATH)
    traceability = _load_yaml(TRACEABILITY_PATH)
    implemented_rows = [row for row in conformance["rows"] if row["status"] == "implemented"]
    boundary_rows = {
        row["id"]: row
        for row in traceability["rows"]
        if row.get("boundary_effects_required") is not None
    }

    assert bundle["schema"] == EVIDENCE_SCHEMA

    expected_record_count = sum(len(row["carrier_evidence"]) for row in implemented_rows)
    assert len(bundle["records"]) == expected_record_count
    assert {record["row_id"] for record in bundle["records"]} == {
        row["id"] for row in implemented_rows
    }

    implemented_rows_by_id = {row["id"]: row for row in implemented_rows}
    for record in bundle["records"]:
        row = implemented_rows_by_id[record["row_id"]]
        carrier_path = record["carrier_path"]
        proof_artifact_path = record["proof_artifact_path"]
        assert record["checker"] == SOURCE_CHECKER
        assert record["kind"] == "source_checker"
        assert record["semantic_carrier"] == row["semantic_carrier"]
        assert carrier_path in row["carrier_evidence"]
        assert proof_artifact_path in row["proof_artifacts"]
        assert record["carrier_name"] == APPROVED_CARRIER_NAMES[carrier_path]
        assert record["policy_object"] == APPROVED_CARRIER_NAMES[carrier_path]
        assert record["carrier_sha256"] == _sha256(ROOT / carrier_path)
        assert record["proof_artifact_sha256"] == _sha256(ROOT / proof_artifact_path)
        assert record["source_span"]["path"] == carrier_path
        assert record["source_span"]["start_line"] == 1
        assert record["source_span"]["end_line"] >= 1

    expected_fixture_paths = sorted(
        {path for row in implemented_rows for path in row["proof_artifacts"]}
    )
    assert [entry["path"] for entry in bundle["fixture_hashes"]] == expected_fixture_paths
    for entry in bundle["fixture_hashes"]:
        assert entry["sha256"] == _sha256(ROOT / entry["path"])
        assert entry["referenced_by_rows"]

    expected_carrier_paths = sorted(
        {path for row in implemented_rows for path in row["carrier_evidence"]}
    )
    assert [entry["path"] for entry in bundle["approved_carriers"]] == expected_carrier_paths
    for entry in bundle["approved_carriers"]:
        assert entry["carrier_name"] == APPROVED_CARRIER_NAMES[entry["path"]]
        assert entry["sha256"] == _sha256(ROOT / entry["path"])
        assert entry["rows"]

    boundary_contract_by_key = {
        (record["row_id"], record["contract_id"]): record
        for record in bundle["boundary_contract_records"]
    }
    boundary_receipt_by_key = {
        (record["row_id"], record["contract_id"]): record
        for record in bundle["boundary_receipt_records"]
    }
    boundary_semantic_health_by_key = {
        (record["row_id"], record["contract_id"]): record
        for record in bundle["boundary_semantic_health_records"]
    }
    boundary_phase_result_by_key = {
        (record["row_id"], record["contract_id"]): record
        for record in bundle["boundary_phase_result_records"]
    }

    assert bundle["boundary_contract_records"]
    assert bundle["boundary_semantic_health_records"]
    assert bundle["boundary_receipt_records"]
    assert bundle["boundary_phase_result_records"]
    assert bundle["boundary_fixture_hashes"]
    assert bundle["scenario_hashes"]
    assert bundle["installed_package_fingerprints"]
    assert bundle["topology_regeneration_checks"]
    assert bundle["handler_purity_checks"]
    assert bundle["compatibility_quarantine_checks"]
    assert bundle["dead_delete_mutation_checks"]

    for row_id, trace_row in boundary_rows.items():
        required_effects = set(trace_row["boundary_effects_required"])
        contract_ids = trace_row["boundary_contract_ids"]
        for contract_id in contract_ids:
            contract_record = boundary_contract_by_key[(row_id, contract_id)]
            assert set(contract_record["covered_effects"]) == required_effects
            assert contract_record["policy_object"] == contract_id
            assert contract_record["contract_sha256"] == _sha256(
                ROOT / contract_record["contract_path"]
            )
            manifest_path = ROOT / contract_record["fixture_manifest_path"]
            assert manifest_path.is_file()
            assert contract_record["fixture_manifest_sha256"] == _sha256(manifest_path)
            assert contract_record["supporting_fixture_id"]
            assert contract_record["observed_boundary_id"]

            health_record = boundary_semantic_health_by_key[(row_id, contract_id)]
            assert set(health_record["covered_effects"]) == required_effects
            assert health_record["status"] == "healthy"
            assert health_record["scoped_error_count"] == 0
            assert health_record["proof_artifact_sha256"] == _sha256(
                ROOT / health_record["proof_artifact_path"]
            )
            manifest_path = ROOT / health_record["fixture_manifest_path"]
            assert manifest_path.is_file()
            assert health_record["fixture_manifest_sha256"] == _sha256(manifest_path)
            assert health_record["supporting_fixture_id"]
            assert health_record["observed_boundary_id"]

            receipt_effects = {effect for effect in required_effects if effect in {"receipt", "authority"}}
            if receipt_effects:
                receipt_record = boundary_receipt_by_key[(row_id, contract_id)]
                assert set(receipt_record["covered_effects"]) == receipt_effects
                assert receipt_record["receipt_sha256"] == _sha256(ROOT / receipt_record["receipt_path"])
                assert receipt_record["supporting_fixture_id"]
            phase_result_effects = {
                effect for effect in required_effects if effect in {"state_history", "phase_result"}
            }
            if phase_result_effects:
                phase_record = boundary_phase_result_by_key[(row_id, contract_id)]
                assert set(phase_record["covered_effects"]) == phase_result_effects
                assert phase_record["phase_result_sha256"] == _sha256(
                    ROOT / phase_record["phase_result_path"]
                )
                assert phase_record["supporting_fixture_id"]

    assert any(record["authority_records"] > 0 for record in bundle["boundary_semantic_health_records"])
    assert any(record["reducer_promotion"] for record in bundle["boundary_semantic_health_records"])
    assert any(record["external_effect_refs"] for record in bundle["boundary_semantic_health_records"])

    for entry in bundle["boundary_fixture_hashes"]:
        manifest_path = ROOT / entry["manifest_path"]
        semantic_health_path = ROOT / entry["semantic_health_path"]
        assert manifest_path.is_file()
        assert semantic_health_path.is_file()
        assert entry["manifest_sha256"] == _sha256(manifest_path)
        assert entry["semantic_health_sha256"] == _sha256(semantic_health_path)
        assert entry["capability_effects"]
        assert entry["row_ids"]
        assert entry["contract_ids"]

    scenario_manifest_path = ROOT / "docs/arnold/megaplan-native-representation-scenarios.yaml"
    for entry in bundle["scenario_hashes"]:
        assert entry["scenario_manifest_path"] == scenario_manifest_path.relative_to(ROOT).as_posix()
        assert entry["scenario_manifest_sha256"] == _sha256(scenario_manifest_path)
        assert entry["record_sha256"].startswith("sha256:")
        assert entry["path_classes"]
        assert entry["row_ids"]
        assert entry["route_authority"] is False
        for module in entry["executable_modules"]:
            assert module["sha256"] == _sha256(ROOT / module["path"])
        for fixture in entry["deterministic_fixture_hashes"]:
            assert fixture["sha256"] == _sha256(ROOT / fixture["path"])
        for warrant in entry["source_warrant_hashes"]:
            assert warrant["sha256"] == _sha256(ROOT / warrant["path"])

    expected_package_fingerprints = canonical_workflow_fingerprints(
        workflow_source_path=ROOT / "arnold_pipelines/megaplan/workflows/workflow.pypeline",
        workflow_module_path=ROOT / "arnold_pipelines/megaplan/workflows/workflow.py",
    )
    assert bundle["installed_package_fingerprints"] == [
        {
            "suite_id": "installed_package_canonical_source",
            "row_ids": ["behavior-parity", "source-path-reconciliation"],
            "proof_artifact_path": "tests/arnold_pipelines/megaplan/test_installed_package_composition_smoke.py",
            "proof_artifact_sha256": _sha256(
                ROOT / "tests/arnold_pipelines/megaplan/test_installed_package_composition_smoke.py"
            ),
            **expected_package_fingerprints,
        }
    ]

    assert bundle["topology_regeneration_checks"] == [
        {
            "check_id": "topology_regeneration",
            "row_ids": ["shadow-topology"],
            "proof_artifact_path": "tests/arnold_pipelines/megaplan/test_native_contract.py",
            "proof_artifact_sha256": _sha256(
                ROOT / "tests/arnold_pipelines/megaplan/test_native_contract.py"
            ),
            "fixture_path": "tests/arnold_pipelines/megaplan/fixtures/megaplan_m4_topology.yaml",
            "fixture_sha256": _sha256(
                ROOT / "tests/arnold_pipelines/megaplan/fixtures/megaplan_m4_topology.yaml"
            ),
            "canonical_source_path": "arnold_pipelines/megaplan/workflows/workflow.pypeline",
            "canonical_source_sha256": _sha256(
                ROOT / "arnold_pipelines/megaplan/workflows/workflow.pypeline"
            ),
            "compiled_manifest_hash": "sha256:962e57e7f8bb15761cc2a6a2e2bb64924eb6681bc86ed5fbf0de295df1ab5504",
            "compiled_topology_hash": "sha256:295e0ad28430ff465334a36c6ff5add25fba1d21d7ba2449da6b081150098260",
            "fixture_manifest_hash": "sha256:962e57e7f8bb15761cc2a6a2e2bb64924eb6681bc86ed5fbf0de295df1ab5504",
            "fixture_topology_hash": "sha256:295e0ad28430ff465334a36c6ff5add25fba1d21d7ba2449da6b081150098260",
            "compiled_node_count": 14,
            "compiled_route_count": 23,
            "matches_fixture": True,
        }
    ]

    handler_purity_record = bundle["handler_purity_checks"][0]
    assert handler_purity_record["check_id"] == "handler_purity_scan"
    assert handler_purity_record["row_ids"] == ["handler-purity-audit"]
    assert handler_purity_record["proof_artifact_path"] == (
        "tests/arnold_pipelines/megaplan/test_semantics_carrier.py"
    )
    assert handler_purity_record["proof_artifact_sha256"] == _sha256(
        ROOT / "tests/arnold_pipelines/megaplan/test_semantics_carrier.py"
    )
    assert isinstance(handler_purity_record["passed"], bool)
    assert isinstance(handler_purity_record["violations"], dict)
    assert isinstance(handler_purity_record["shared_module_violations"], dict)
    assert len(handler_purity_record["retained_handlers"]) == 8
    assert {entry["path"] for entry in handler_purity_record["module_hashes"]} == {
        "arnold_pipelines/megaplan/handlers/_tiebreaker_impl.py",
        "arnold_pipelines/megaplan/handlers/critique.py",
        "arnold_pipelines/megaplan/handlers/execute.py",
        "arnold_pipelines/megaplan/handlers/finalize.py",
        "arnold_pipelines/megaplan/handlers/gate.py",
        "arnold_pipelines/megaplan/handlers/override.py",
        "arnold_pipelines/megaplan/handlers/review.py",
        "arnold_pipelines/megaplan/handlers/shared.py",
    }
    for entry in handler_purity_record["module_hashes"]:
        assert entry["sha256"] == _sha256(ROOT / entry["path"])

    compatibility_record = bundle["compatibility_quarantine_checks"][0]
    assert compatibility_record["check_id"] == "compatibility_quarantine"
    assert compatibility_record["row_ids"] == ["source-path-reconciliation"]
    assert compatibility_record["proof_artifact_path"] == (
        "tests/arnold/conformance/test_megaplan_coupling_gate.py"
    )
    assert compatibility_record["proof_artifact_sha256"] == _sha256(
        ROOT / "tests/arnold/conformance/test_megaplan_coupling_gate.py"
    )
    assert compatibility_record["quarantined_scan_ids"] == [
        scan.scan_id for scan in FORBIDDEN_AUTHORITY_SCANS
    ]
    assert compatibility_record["quarantine_record_count"] == len(FORBIDDEN_AUTHORITY_SCANS)
    assert compatibility_record["authority_conflicts"] == {}
    assert compatibility_record["coupling_gate"]["check_id"] == "generic-arnold-megaplan-coupling"
    assert compatibility_record["coupling_gate"]["details"]["allowlisted_count"] == 7
    assert compatibility_record["coupling_gate"]["details"]["coupled_count"] == 7
    assert compatibility_record["passed"] is (
        compatibility_record["coupling_gate"]["passed"]
        and not compatibility_record["authority_conflicts"]
    )

    dead_delete_record = bundle["dead_delete_mutation_checks"][0]
    assert dead_delete_record["check_id"] == "dead_delete_mutation"
    assert dead_delete_record["row_ids"] == ["source-path-reconciliation"]
    assert dead_delete_record["proof_artifact_path"] == (
        "tests/arnold/conformance/test_deleted_surfaces.py"
    )
    assert dead_delete_record["proof_artifact_sha256"] == _sha256(
        ROOT / "tests/arnold/conformance/test_deleted_surfaces.py"
    )
    assert dead_delete_record["deleted_source_path_count"] >= 1
    assert dead_delete_record["deleted_import_module_count"] >= 1
    assert "product_import_violations" in dead_delete_record
    assert dead_delete_record["passed"] is (
        not dead_delete_record["present_deleted_paths"]
        and not dead_delete_record["present_deleted_modules"]
        and not dead_delete_record["product_import_violations"]
    )


def test_generated_evidence_bundle_satisfies_current_validator(tmp_path: Path) -> None:
    bundle = generate_evidence_bundle(
        conformance_path=CONFORMANCE_PATH,
        traceability_path=TRACEABILITY_PATH,
        repo_root=ROOT,
    )
    evidence_path = tmp_path / "evidence.yaml"
    evidence_path.write_text(yaml.safe_dump(bundle, sort_keys=False), encoding="utf-8")

    assert (
        validate_conformance_ledger(
            repo_root=ROOT,
            conformance_path=CONFORMANCE_PATH,
            traceability_path=TRACEABILITY_PATH,
            evidence_bundle_path=evidence_path,
        )
        == []
    )


def test_generate_evidence_bundle_quarantines_forbidden_authority_surfaces() -> None:
    bundle = generate_evidence_bundle(
        conformance_path=CONFORMANCE_PATH,
        traceability_path=TRACEABILITY_PATH,
        repo_root=ROOT,
    )
    quarantine_by_id = {record["scan_id"]: record for record in bundle["quarantine_records"]}

    assert set(quarantine_by_id) == {scan.scan_id for scan in FORBIDDEN_AUTHORITY_SCANS}
    for scan in FORBIDDEN_AUTHORITY_SCANS:
        record = quarantine_by_id[scan.scan_id]
        assert record["path"] == scan.path
        assert record["sha256"] == _sha256(ROOT / scan.path)
        assert record["authority_allowed"] is False
        assert record["classification"] == "quarantined_authority_surface"
        assert record["rationale"] == scan.rationale
        assert any(match["line_numbers"] for match in record["matched_patterns"])
        if scan.path_conflicts_with_authority:
            assert record["cited_as_authority_rows"] == []
            assert "rows_sharing_file" not in record or record["rows_sharing_file"] == []
        else:
            assert record["cited_as_authority_rows"] == []
            assert record["rows_sharing_file"]


def test_generate_evidence_bundle_rejects_forbidden_authority_carriers(tmp_path: Path) -> None:
    conformance = _load_yaml(CONFORMANCE_PATH)
    modified = deepcopy(conformance)
    modified["rows"][0]["carrier_evidence"] = [
        "arnold_pipelines/megaplan/workflows/components.py"
    ]
    modified_path = tmp_path / "conformance.yaml"
    modified_path.write_text(yaml.safe_dump(modified, sort_keys=False), encoding="utf-8")

    with pytest.raises(ValueError, match="forbidden authority carrier"):
        generate_evidence_bundle(
            conformance_path=modified_path,
            traceability_path=TRACEABILITY_PATH,
            repo_root=ROOT,
        )
