from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from scripts.validate_post_m11_release_evidence import validate


REPO = Path(__file__).resolve().parents[1]
RECORD = REPO / "docs/megaplan/post-m11-release-evidence-20260731.json"
RUNBOOK = REPO / "docs/megaplan/final-cloud-runtime-promotion-runbook-2026-07-31.md"
HASH = "a" * 64
OTHER_HASH = "b" * 64


def _add_source_universe(data: dict) -> None:
    entries = []
    for item in data["source_refs"]:
        entries.append({
            "source_id": item["ref"],
            "source_kind": "git_ref",
            "head_fingerprint": f"sha1:{item['sha']}",
            "unique_delta_count": 0,
            "disposition": "LANDED",
            "disposition_evidence": {"exact_final_proof": f"final:{item['sha']}"},
        })
    entries.sort(key=lambda item: item["source_id"])
    data["source_universe"] = {
        "schema": "arnold.post_m11_source_universe",
        "version": 1,
        "generated_at_utc": "2026-07-31T00:00:00Z",
        "entries": entries,
        "entry_count": len(entries),
        "sha256": __import__("hashlib").sha256(
            json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def test_release_evidence_record_is_structurally_valid() -> None:
    validate(RECORD)


def test_ownerless_collection_promotions_bind_both_preserved_sources(
    tmp_path: Path,
) -> None:
    data = json.loads(RECORD.read_text(encoding="utf-8"))
    rows = data["canonical_artifact_moves"]
    collection_rows = [
        row for row in rows if row.get("collection_scope") == "initiative_collection"
    ]
    assert len(rows) == 28
    assert {(row["artifact_type"], row["from"], row["to"]) for row in collection_rows} == {
        (
            "cloud_guidance",
            ".megaplan/initiatives/CLOUD.md",
            ".megaplan/collection/CLOUD.md",
        ),
        (
            "aggregate_chain_snapshot",
            ".megaplan/initiatives/chain.yaml",
            ".megaplan/collection/chain.yaml",
        ),
    }
    assert all(
        row["authority"]["path"] == ".megaplan/collection/authority.json"
        for row in collection_rows
    )

    candidate = tmp_path / "release-evidence.json"
    mutated = deepcopy(data)
    mutated["canonical_artifact_moves"][-2]["collection_scope"] = "initiative"
    candidate.write_text(json.dumps(mutated), encoding="utf-8")
    with pytest.raises(ValueError):
        validate(candidate)


def test_runtime_promotion_converges_split_authorities_without_fake_prebind() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")

    assert "CHAIN_PREVIOUS_RUNTIME_SHA256" in text
    assert "MARKER_PREVIOUS_RUNTIME_SHA256" in text
    assert 'export PREVIOUS_RUNTIME_SHA256=' not in text
    assert "--from-runtime-sha256 '${CHAIN_PREVIOUS_RUNTIME_SHA256}'" in text
    assert "--from-runtime-sha256 '${MARKER_PREVIOUS_RUNTIME_SHA256}'" in text
    assert "Manufacturing an intermediate equality" in text
    assert "chain-state.before.json" in text
    assert "marker.before.json" in text
    assert "chain-previous-runtime-provenance.json" in text

    chain_rebind = text.index("public/chain-runtime-rebind.json")
    marker_rebind = text.index("public/marker-runtime-rebind.json")
    selector_rewrite = text.index("hot_next=", marker_rebind)
    assert chain_rebind < marker_rebind < selector_rewrite


def test_runtime_promotion_documents_terminal_cas_limit_and_rollback() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")

    assert "currently lacks a state-file-SHA CLI guard" in text
    assert "no runner, repairer, or other chain-state writer is live" in text
    assert "runtime-rebind --direction rollback" in text
    assert "MARKER_PREVIOUS_RUNTIME_SHA256" in text
    assert "Verify both restored identities and receipt hashes" in text


def test_release_evidence_cannot_claim_done_with_pending_gates(
    tmp_path: Path,
) -> None:
    data = json.loads(RECORD.read_text(encoding="utf-8"))
    data["record_status"] = "complete"
    candidate = tmp_path / "release-evidence.json"
    candidate.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError, match="residuals are pending"):
        validate(candidate)


def _write(tmp_path: Path, data: dict) -> Path:
    candidate = tmp_path / "release-evidence.json"
    candidate.write_text(json.dumps(data), encoding="utf-8")
    return candidate


def _completed_record() -> dict:
    data = json.loads(RECORD.read_text(encoding="utf-8"))
    data["record_status"] = "complete"
    authority = data["authority"]
    binding = {
        "bound_commit": authority["evidence_cut_commit"],
        "bound_tree": authority["evidence_cut_tree"],
        "runtime_sha256": HASH,
    }
    for residual in data["residuals"]:
        residual["status"] = "complete"
        residual["completion_evidence"] = "Human-readable projection only."
        residual["completion_receipt"] = {
            "receipt_sha256": OTHER_HASH,
            **binding,
        }
    data["final_acceptance"] = {
        "binding": binding,
        "no_debt": {
            "receipt_sha256": HASH,
            **binding,
            "frozen_collection": [
                "tests/a.py::test_a",
                "tests/b.py::test_b",
                "tests/m11/test_semantics.py::test_contract",
            ],
            "terminal_inventories": [
                {
                    "receipt_sha256": HASH,
                    "inventory": [
                        "tests/a.py::test_a",
                        "tests/b.py::test_b",
                    ],
                    "counts": {
                        "collected": 2,
                        "passed": 2,
                        "failed": 0,
                        "errors": 0,
                        "skipped": 0,
                        "xfailed": 0,
                        "xpassed": 0,
                        "mutations": 0,
                    },
                },
                {
                    "receipt_sha256": OTHER_HASH,
                    "inventory": [
                        "tests/m11/test_semantics.py::test_contract"
                    ],
                    "counts": {
                        "collected": 1,
                        "passed": 1,
                        "failed": 0,
                        "errors": 0,
                        "skipped": 0,
                        "xfailed": 0,
                        "xpassed": 0,
                        "mutations": 0,
                    },
                },
            ],
        },
    }
    _add_source_universe(data)
    return data


def _candidate_ready_record() -> dict:
    data = _completed_record()
    data["record_status"] = "candidate_ready"
    for residual in data["residuals"]:
        if residual["id"] in {
            "production-canary",
            "runtime-selector-promotion",
            "acceptance-tag",
            "critique-runtime-rebind",
            "critique-launch",
        }:
            residual["status"] = "pending"
            residual.pop("completion_evidence", None)
            residual.pop("completion_receipt", None)
    return data


def test_candidate_ready_allows_only_post_deploy_residuals_pending(
    tmp_path: Path,
) -> None:
    validate(_write(tmp_path, _candidate_ready_record()))


def test_candidate_ready_rejects_a_pending_pre_deploy_residual(
    tmp_path: Path,
) -> None:
    data = _candidate_ready_record()
    residual = next(
        item
        for item in data["residuals"]
        if item["id"] == "content-addressed-runtime"
    )
    residual["status"] = "pending"
    residual.pop("completion_evidence", None)
    residual.pop("completion_receipt", None)

    with pytest.raises(ValueError, match="pre-deploy residuals are pending"):
        validate(_write(tmp_path, data))


def test_candidate_ready_requires_bound_acceptance_evidence(
    tmp_path: Path,
) -> None:
    data = _candidate_ready_record()
    data.pop("final_acceptance")

    with pytest.raises(ValueError, match="requires final_acceptance"):
        validate(_write(tmp_path, data))


def test_candidate_ready_requires_complete_source_universe(tmp_path: Path) -> None:
    data = _candidate_ready_record()
    data.pop("source_universe")
    with pytest.raises(ValueError, match="requires source_universe"):
        validate(_write(tmp_path, data))


@pytest.mark.parametrize(
    "mutation",
    [
        "count",
        "digest",
        "duplicate",
        "unmapped_ref",
        "invalid_fingerprint",
        "missing_proof",
        "deferred_fields",
    ],
)
def test_source_universe_completeness_gate_is_fail_closed(tmp_path: Path, mutation: str) -> None:
    data = _candidate_ready_record()
    universe = data["source_universe"]
    if mutation == "count":
        universe["entry_count"] += 1
    elif mutation == "digest":
        universe["sha256"] = OTHER_HASH
    elif mutation == "duplicate":
        universe["entries"].append(deepcopy(universe["entries"][0]))
    elif mutation == "unmapped_ref":
        data["source_refs"][0]["ref"] = "missing-source"
    elif mutation == "invalid_fingerprint":
        universe["entries"][0]["head_fingerprint"] = f"sha1:{'!' * 40}"
    elif mutation == "missing_proof":
        universe["entries"][0]["disposition_evidence"] = {}
    else:
        universe["entries"][0]["disposition"] = "DEFERRED"
        universe["entries"][0]["disposition_evidence"] = {}
    with pytest.raises(ValueError):
        validate(_write(tmp_path, data))


def test_complete_release_requires_one_immutable_acceptance_binding(
    tmp_path: Path,
) -> None:
    data = _completed_record()
    validate(_write(tmp_path, data))

    missing_receipt = deepcopy(data)
    del missing_receipt["residuals"][0]["completion_receipt"]
    with pytest.raises(ValueError, match="immutable completion_receipt"):
        validate(_write(tmp_path, missing_receipt))

    mixed_commit = deepcopy(data)
    mixed_commit["residuals"][0]["completion_receipt"]["bound_commit"] = (
        data["authority"]["origin_base_commit"]
    )
    with pytest.raises(ValueError, match="differs from the final acceptance binding"):
        validate(_write(tmp_path, mixed_commit))

    mixed_runtime = deepcopy(data)
    mixed_runtime["final_acceptance"]["no_debt"]["runtime_sha256"] = OTHER_HASH
    with pytest.raises(ValueError, match="differs from the final acceptance binding"):
        validate(_write(tmp_path, mixed_runtime))


@pytest.mark.parametrize(
    ("status", "acceptance_effect", "message"),
    [
        ("invented", "informational_only", "invalid status"),
        ("historical_pass", "invented", "invalid acceptance_effect"),
        (
            "historical_pass",
            "final_acceptance",
            "invalid acceptance_effect",
        ),
        (
            "acceptance_pass",
            "informational_only",
            "invalid status",
        ),
        (
            "historical_failure",
            "final_acceptance",
            "invalid acceptance_effect",
        ),
        (
            "discovery",
            "final_acceptance",
            "invalid acceptance_effect",
        ),
        (
            "superseded",
            "final_acceptance",
            "invalid acceptance_effect",
        ),
    ],
)
def test_observation_status_and_acceptance_effect_are_fail_closed(
    tmp_path: Path,
    status: str,
    acceptance_effect: str,
    message: str,
) -> None:
    data = json.loads(RECORD.read_text(encoding="utf-8"))
    data["validation_observations"][0]["status"] = status
    data["validation_observations"][0]["acceptance_effect"] = acceptance_effect
    with pytest.raises(ValueError, match=message):
        validate(_write(tmp_path, data))


def test_superseded_attempts_and_artifacts_cannot_be_promoted(
    tmp_path: Path,
) -> None:
    data = json.loads(RECORD.read_text(encoding="utf-8"))
    data["historical_superseded_attempts"][0][
        "acceptance_effect"
    ] = "final_acceptance"
    with pytest.raises(ValueError, match="cannot provide acceptance"):
        validate(_write(tmp_path, data))

    data = json.loads(RECORD.read_text(encoding="utf-8"))
    data["packaging_artifacts"][0]["acceptance_effect"] = "final_acceptance"
    with pytest.raises(ValueError, match="invalid acceptance_effect"):
        validate(_write(tmp_path, data))


def test_final_no_debt_rejects_partial_and_overlapping_shard_sets(
    tmp_path: Path,
) -> None:
    data = _completed_record()

    partial = deepcopy(data)
    partial["final_acceptance"]["no_debt"]["terminal_inventories"].pop()
    with pytest.raises(ValueError, match="differs from terminal inventory union"):
        validate(_write(tmp_path, partial))

    overlap = deepcopy(data)
    overlap["final_acceptance"]["no_debt"]["terminal_inventories"][1][
        "inventory"
    ] = ["tests/a.py::test_a"]
    with pytest.raises(ValueError, match="terminal inventories overlap"):
        validate(_write(tmp_path, overlap))


@pytest.mark.parametrize("field", ["failed", "errors", "skipped", "xfailed", "xpassed", "mutations"])
def test_final_no_debt_rejects_every_non_acceptance_outcome(
    tmp_path: Path,
    field: str,
) -> None:
    data = _completed_record()
    data["final_acceptance"]["no_debt"]["terminal_inventories"][0]["counts"][
        field
    ] = 1
    with pytest.raises(ValueError, match="failure, skip, xfail/xpass, or mutation"):
        validate(_write(tmp_path, data))
