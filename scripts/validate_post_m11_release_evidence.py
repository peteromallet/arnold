#!/usr/bin/env python3
"""Validate the post-M11 release evidence record without interpreting release policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from arnold.conformance.checks import (
    validate_collection_artifact_placements,
    validate_canonical_artifact_placements,
    validate_canonical_root_artifacts,
)


SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_RECORD_STATUS = {"in_progress", "candidate_ready", "complete"}
ALLOWED_RESIDUAL_STATUS = {"pending", "complete"}
POST_DEPLOY_RESIDUAL_IDS = {
    "production-canary",
    "runtime-selector-promotion",
    "acceptance-tag",
    "critique-runtime-rebind",
    "critique-launch",
}
ALLOWED_OBSERVATION_STATUS = {
    "discovery",
    "failure",
    "historical_blocked",
    "historical_discovery",
    "historical_failure",
    "historical_pass",
    "superseded",
}
ALLOWED_ACCEPTANCE_EFFECT = {
    "branch_level_only",
    "conformance_fix_level_only",
    "defect_level_only",
    "evidence_not_acceptance",
    "informational_only",
    "integration_cut_only",
    "packaging_code_gate",
    "packaging_component_only",
    "pinned_runtime_subset_only",
    "superseded_by_followup_fixes",
}
NON_ACCEPTANCE_OBSERVATION_STATUS = {
    "discovery",
    "failure",
    "historical_blocked",
    "historical_discovery",
    "historical_failure",
    "superseded",
}
NON_ACCEPTANCE_EFFECT = {
    "branch_level_only",
    "conformance_fix_level_only",
    "defect_level_only",
    "evidence_not_acceptance",
    "informational_only",
    "integration_cut_only",
    "packaging_code_gate",
    "packaging_component_only",
    "pinned_runtime_subset_only",
    "superseded_by_followup_fixes",
}
ALLOWED_SUPERSEDED_STATUS = {
    "superseded_defect_receipt",
    "superseded_failed_shard_receipt",
    "superseded_seeded_abort_receipt",
}
ALLOWED_PACKAGING_ACCEPTANCE_EFFECT = {
    "packaging_code_gate_artifact",
    "superseded_candidate_artifact",
}
ALLOWED_SOURCE_DISPOSITIONS = {"LANDED", "SUPERSEDED", "REJECTED", "DEFERRED"}
NO_DEBT_COUNT_KEYS = {
    "collected",
    "passed",
    "failed",
    "errors",
    "skipped",
    "xfailed",
    "xpassed",
    "mutations",
}
REPO_ROOT = Path(__file__).resolve().parents[1]


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _require_sha1(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA1.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase 40-character Git SHA")
    return value


def _validate_sha256_fields(value: Any, label: str = "record") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_label = f"{label}.{key}"
            if key == "sha256" or key.endswith("_sha256"):
                if not isinstance(child, str) or not SHA256.fullmatch(child):
                    raise ValueError(
                        f"{child_label} must be a lowercase 64-character SHA-256"
                    )
            else:
                _validate_sha256_fields(child, child_label)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_sha256_fields(child, f"{label}[{index}]")


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase 64-character SHA-256")
    return value


def _require_string_list(value: Any, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise ValueError(f"{label} must be a non-empty list of strings")
    if value != sorted(value) or len(value) != len(set(value)):
        raise ValueError(f"{label} must be sorted and duplicate-free")
    return list(value)


def _validate_release_binding(
    value: Any,
    *,
    label: str,
    expected: tuple[str, str, str] | None = None,
) -> tuple[str, str, str]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    if set(value) != {"bound_commit", "bound_tree", "runtime_sha256"}:
        raise ValueError(f"{label} must bind exactly one commit, tree, and runtime")
    binding = (
        _require_sha1(value["bound_commit"], f"{label}.bound_commit"),
        _require_sha1(value["bound_tree"], f"{label}.bound_tree"),
        _require_sha256(value["runtime_sha256"], f"{label}.runtime_sha256"),
    )
    if expected is not None and binding != expected:
        raise ValueError(f"{label} differs from the final acceptance binding")
    return binding


def _validate_completed_residual_receipts(
    residuals: list[dict[str, Any]],
    *,
    binding: tuple[str, str, str],
) -> None:
    for index, item in enumerate(residuals):
        if item["status"] != "complete":
            continue
        receipt = item.get("completion_receipt")
        label = f"residuals[{index}].completion_receipt"
        if not isinstance(receipt, dict):
            raise ValueError(
                f"residuals[{index}] is complete without an immutable "
                "completion_receipt"
            )
        if set(receipt) != {
            "receipt_sha256",
            "bound_commit",
            "bound_tree",
            "runtime_sha256",
        }:
            raise ValueError(
                f"{label} must contain one receipt hash and one release binding"
            )
        _require_sha256(receipt["receipt_sha256"], f"{label}.receipt_sha256")
        _validate_release_binding(
            {
                "bound_commit": receipt["bound_commit"],
                "bound_tree": receipt["bound_tree"],
                "runtime_sha256": receipt["runtime_sha256"],
            },
            label=label,
            expected=binding,
        )


def _validate_final_no_debt(
    value: Any,
    *,
    binding: tuple[str, str, str],
) -> None:
    label = "final_acceptance.no_debt"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    expected_keys = {
        "receipt_sha256",
        "bound_commit",
        "bound_tree",
        "runtime_sha256",
        "frozen_collection",
        "terminal_inventories",
    }
    if set(value) != expected_keys:
        raise ValueError(f"{label} has missing or unexpected fields")
    _require_sha256(value["receipt_sha256"], f"{label}.receipt_sha256")
    _validate_release_binding(
        {
            "bound_commit": value["bound_commit"],
            "bound_tree": value["bound_tree"],
            "runtime_sha256": value["runtime_sha256"],
        },
        label=label,
        expected=binding,
    )
    frozen = _require_string_list(
        value["frozen_collection"], f"{label}.frozen_collection"
    )
    terminals = value["terminal_inventories"]
    if not isinstance(terminals, list) or not terminals:
        raise ValueError(f"{label}.terminal_inventories must be non-empty")

    observed: set[str] = set()
    for index, terminal in enumerate(terminals):
        terminal_label = f"{label}.terminal_inventories[{index}]"
        if not isinstance(terminal, dict) or set(terminal) != {
            "receipt_sha256",
            "inventory",
            "counts",
        }:
            raise ValueError(f"{terminal_label} has the wrong schema")
        _require_sha256(
            terminal["receipt_sha256"], f"{terminal_label}.receipt_sha256"
        )
        inventory = _require_string_list(
            terminal["inventory"], f"{terminal_label}.inventory"
        )
        overlap = observed.intersection(inventory)
        if overlap:
            raise ValueError(
                f"{label} terminal inventories overlap: {sorted(overlap)!r}"
            )
        observed.update(inventory)

        counts = terminal["counts"]
        if not isinstance(counts, dict) or set(counts) != NO_DEBT_COUNT_KEYS:
            raise ValueError(f"{terminal_label}.counts has the wrong schema")
        if any(
            type(counts[key]) is not int or counts[key] < 0
            for key in NO_DEBT_COUNT_KEYS
        ):
            raise ValueError(
                f"{terminal_label}.counts must contain non-negative integers"
            )
        if counts["collected"] != len(inventory) or counts["passed"] != len(
            inventory
        ):
            raise ValueError(
                f"{terminal_label}.counts do not exactly match its inventory"
            )
        non_acceptance = NO_DEBT_COUNT_KEYS - {"collected", "passed"}
        if any(counts[key] != 0 for key in non_acceptance):
            raise ValueError(
                f"{terminal_label} contains failure, skip, xfail/xpass, "
                "or mutation"
            )

    if sorted(observed) != frozen:
        raise ValueError(
            f"{label} frozen collection differs from terminal inventory union"
        )


def _validate_final_acceptance(
    data: dict[str, Any],
    residuals: list[dict[str, Any]],
    *,
    repo: Path,
) -> None:
    final = data.get("final_acceptance")
    if not isinstance(final, dict) or set(final) != {"binding", "no_debt"}:
        raise ValueError(
            "complete record requires final_acceptance.binding and no_debt"
        )
    binding = _validate_release_binding(
        final["binding"], label="final_acceptance.binding"
    )
    authority = data["authority"]
    if binding[:2] != (
        authority["evidence_cut_commit"],
        authority["evidence_cut_tree"],
    ):
        raise ValueError(
            "final acceptance binding must match the authoritative evidence cut"
        )
    actual_tree = _git("rev-parse", f"{binding[0]}^{{tree}}", cwd=repo)
    if actual_tree != binding[1]:
        raise ValueError("final acceptance commit/tree binding is inconsistent")
    _validate_completed_residual_receipts(residuals, binding=binding)
    _validate_final_no_debt(final["no_debt"], binding=binding)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _validate_source_universe(data: dict[str, Any]) -> None:
    universe = data.get("source_universe")
    if not isinstance(universe, dict) or set(universe) != {
        "schema", "version", "generated_at_utc", "entries", "entry_count", "sha256"
    }:
        raise ValueError("candidate-ready/complete record requires source_universe")
    if universe["schema"] != "arnold.post_m11_source_universe":
        raise ValueError("unsupported source_universe schema")
    if universe["version"] != 1:
        raise ValueError("unsupported source_universe version")
    if not isinstance(universe["generated_at_utc"], str) or not universe["generated_at_utc"].endswith("Z"):
        raise ValueError("source_universe.generated_at_utc must be UTC")
    entries = universe["entries"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("source_universe.entries must be non-empty")
    ids: set[str] = set()
    for index, entry in enumerate(entries):
        label = f"source_universe.entries[{index}]"
        if not isinstance(entry, dict) or set(entry) != {
            "source_id", "source_kind", "head_fingerprint", "unique_delta_count",
            "disposition", "disposition_evidence"
        }:
            raise ValueError(f"{label} has the wrong schema")
        source_id = entry["source_id"]
        if not isinstance(source_id, str) or not source_id or source_id in ids:
            raise ValueError(f"{label}.source_id is missing or duplicated")
        ids.add(source_id)
        if not isinstance(entry["source_kind"], str) or not entry["source_kind"]:
            raise ValueError(f"{label}.source_kind is missing")
        fingerprint = entry["head_fingerprint"]
        if not isinstance(fingerprint, str) or not (
            (fingerprint.startswith("sha1:") and SHA1.fullmatch(fingerprint.removeprefix("sha1:")))
            or (
                fingerprint.startswith("sha256:")
                and SHA256.fullmatch(fingerprint.removeprefix("sha256:"))
            )
        ):
            raise ValueError(f"{label}.head_fingerprint must be content-addressed")
        if type(entry["unique_delta_count"]) is not int or entry["unique_delta_count"] < 0:
            raise ValueError(f"{label}.unique_delta_count must be non-negative")
        disposition = entry["disposition"]
        if disposition not in ALLOWED_SOURCE_DISPOSITIONS:
            raise ValueError(f"{label}.disposition is invalid")
        evidence = entry["disposition_evidence"]
        if not isinstance(evidence, dict) or not evidence:
            raise ValueError(f"{label}.disposition_evidence is missing")
        if disposition == "DEFERRED" and not all(
            isinstance(evidence.get(key), str) and evidence[key]
            for key in ("owner", "reason", "expiry_or_retirement_trigger")
        ):
            raise ValueError(f"{label} DEFERRED evidence needs owner, reason, and expiry_or_retirement_trigger")
        if disposition in {"LANDED", "SUPERSEDED"} and not all(
            isinstance(evidence.get(key), str) and evidence[key]
            for key in ("exact_final_proof",)
        ):
            raise ValueError(f"{label} lacks exact final proof")
        if disposition == "REJECTED" and not all(
            isinstance(evidence.get(key), str) and evidence[key]
            for key in ("reason", "decision_authority", "exact_delta_proof")
        ):
            raise ValueError(f"{label} REJECTED evidence is incomplete")
    if entries != sorted(entries, key=lambda item: item["source_id"]):
        raise ValueError("source_universe.entries must be deterministically sorted")
    if universe["entry_count"] != len(entries):
        raise ValueError("source_universe.entry_count disagrees with entries")
    if _require_sha256(universe["sha256"], "source_universe.sha256") != hashlib.sha256(_canonical_json(entries)).hexdigest():
        raise ValueError("source_universe.sha256 disagrees with canonical entries")

    refs = data.get("source_refs", [])
    by_id = {entry["source_id"]: entry for entry in entries}
    ref_ids = {item.get("ref") for item in refs}
    for index, item in enumerate(refs):
        source_id = item.get("ref")
        if source_id not in by_id:
            raise ValueError(f"source_refs[{index}] is absent from source_universe")
    for entry in entries:
        if entry["unique_delta_count"] and entry["source_id"] not in ref_ids and entry["disposition"] not in {"DEFERRED", "REJECTED"}:
            raise ValueError(f"unique-delta source {entry['source_id']} is not represented or explicitly deferred/rejected")


def validate(path: Path) -> None:
    repo = Path(_git("rev-parse", "--show-toplevel", cwd=REPO_ROOT))
    data = json.loads(path.read_text(encoding="utf-8"))

    digest_path = path.with_name(path.name + ".sha256")
    if digest_path.is_file():
        expected_digest, expected_name = digest_path.read_text(
            encoding="utf-8"
        ).split()
        actual_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if expected_name != path.name or expected_digest != actual_digest:
            raise ValueError("release evidence SHA-256 sidecar mismatch")

    if data.get("schema") != "arnold.post_m11_release_evidence.v1":
        raise ValueError("unsupported schema")
    if data.get("record_status") not in ALLOWED_RECORD_STATUS:
        raise ValueError("invalid record_status")
    _validate_sha256_fields(data)

    authority = data["authority"]
    plan_path = repo / authority["plan_path"]
    if not plan_path.is_file():
        raise ValueError(f"missing plan path: {authority['plan_path']}")

    git_objects: set[str] = set()
    for field in (
        "plan_publication_commit",
        "origin_base_commit",
        "evidence_cut_commit",
        "evidence_cut_tree",
    ):
        git_objects.add(_require_sha1(authority[field], f"authority.{field}"))

    plan_blob = _require_sha1(authority["plan_blob"], "authority.plan_blob")
    actual_plan_blob = _git("hash-object", str(plan_path), cwd=repo)
    if actual_plan_blob != plan_blob:
        raise ValueError(
            f"plan blob mismatch: expected {plan_blob}, got {actual_plan_blob}"
        )
    git_objects.add(plan_blob)
    actual_evidence_tree = _git(
        "rev-parse", f"{authority['evidence_cut_commit']}^{{tree}}", cwd=repo
    )
    if actual_evidence_tree != authority["evidence_cut_tree"]:
        raise ValueError(
            "evidence cut tree mismatch: expected "
            f"{authority['evidence_cut_tree']}, got {actual_evidence_tree}"
        )

    source_refs = data.get("source_refs")
    if not isinstance(source_refs, list) or not source_refs:
        raise ValueError("source_refs must be a non-empty list")
    for index, item in enumerate(source_refs):
        git_objects.add(_require_sha1(item["sha"], f"source_refs[{index}].sha"))
        if item.get("classification") not in {"LAND", "KEEP_CHECKPOINT"}:
            raise ValueError(f"source_refs[{index}] has invalid classification")

    lineage = data.get("integration_lineage")
    if not isinstance(lineage, list) or not lineage:
        raise ValueError("integration_lineage must be a non-empty list")
    for index, item in enumerate(lineage):
        git_objects.add(
            _require_sha1(item["sha"], f"integration_lineage[{index}].sha")
        )

    for index, item in enumerate(data.get("validation_observations", [])):
        status = item.get("status")
        acceptance_effect = item.get("acceptance_effect")
        if status not in ALLOWED_OBSERVATION_STATUS:
            raise ValueError(
                f"validation_observations[{index}] has invalid status"
            )
        if acceptance_effect not in ALLOWED_ACCEPTANCE_EFFECT:
            raise ValueError(
                f"validation_observations[{index}] has invalid acceptance_effect"
            )
        if (
            status in NON_ACCEPTANCE_OBSERVATION_STATUS
            and acceptance_effect not in NON_ACCEPTANCE_EFFECT
        ):
            raise ValueError(
                f"validation_observations[{index}] is a failure, superseded, "
                "or discovery observation and cannot provide acceptance"
            )
        if "bound_commit" in item:
            git_objects.add(
                _require_sha1(
                    item["bound_commit"],
                    f"validation_observations[{index}].bound_commit",
                )
            )
        if "bound_tree" in item:
            git_objects.add(
                _require_sha1(
                    item["bound_tree"],
                    f"validation_observations[{index}].bound_tree",
                )
            )

    for collection_name in (
        "historical_superseded_attempts",
        "packaging_artifacts",
    ):
        for index, item in enumerate(data.get(collection_name, [])):
            if collection_name == "historical_superseded_attempts":
                if item.get("status") not in ALLOWED_SUPERSEDED_STATUS:
                    raise ValueError(
                        f"{collection_name}[{index}] has invalid status"
                    )
                if item.get("acceptance_effect") != "evidence_not_acceptance":
                    raise ValueError(
                        f"{collection_name}[{index}] cannot provide acceptance"
                    )
            elif (
                item.get("acceptance_effect")
                not in ALLOWED_PACKAGING_ACCEPTANCE_EFFECT
            ):
                raise ValueError(
                    f"{collection_name}[{index}] has invalid acceptance_effect"
                )
            if "bound_commit" in item:
                git_objects.add(
                    _require_sha1(
                        item["bound_commit"],
                        f"{collection_name}[{index}].bound_commit",
                    )
                )

    validate_collection_artifact_placements(data, repo_root=repo)
    validate_canonical_artifact_placements(data, repo_root=repo)
    validate_canonical_root_artifacts(data, repo_root=repo)

    for sha in sorted(git_objects):
        _git("cat-file", "-e", f"{sha}^{{object}}", cwd=repo)

    for index, checkpoint in enumerate(data.get("checkpoints", [])):
        digest = checkpoint.get("sha256")
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise ValueError(f"checkpoints[{index}].sha256 is invalid")
        location = checkpoint.get("location", "")
        if not location.startswith(("$LOCAL_CHECKPOINT_ROOT/", "$CLOUD_WORKSPACE/")):
            raise ValueError(f"checkpoints[{index}].location is not redacted")

    residuals = data.get("residuals")
    if not isinstance(residuals, list) or not residuals:
        raise ValueError("residuals must be a non-empty list")
    seen_residuals: set[str] = set()
    for index, item in enumerate(residuals):
        residual_id = item.get("id")
        if not isinstance(residual_id, str) or not residual_id:
            raise ValueError(f"residuals[{index}].id is missing")
        if residual_id in seen_residuals:
            raise ValueError(f"duplicate residual id: {residual_id}")
        seen_residuals.add(residual_id)
        if item.get("status") not in ALLOWED_RESIDUAL_STATUS:
            raise ValueError(f"residuals[{index}] has invalid status")
        if not isinstance(item.get("required_evidence"), str):
            raise ValueError(f"residuals[{index}].required_evidence is missing")
        if item["status"] == "complete" and not isinstance(
            item.get("completion_evidence"), str
        ):
            raise ValueError(
                f"residuals[{index}] is complete without completion_evidence"
            )

    if data["record_status"] == "candidate_ready":
        pending_pre_deploy = [
            item["id"]
            for item in residuals
            if item["status"] != "complete"
            and item["id"] not in POST_DEPLOY_RESIDUAL_IDS
        ]
        if pending_pre_deploy:
            raise ValueError(
                "record_status cannot be candidate_ready while pre-deploy "
                "residuals are pending: "
                + ", ".join(pending_pre_deploy)
            )
        _validate_source_universe(data)
        _validate_final_acceptance(data, residuals, repo=repo)
    elif data["record_status"] == "complete":
        pending = [item["id"] for item in residuals if item["status"] != "complete"]
        if pending:
            raise ValueError(
                "record_status cannot be complete while residuals are pending: "
                + ", ".join(pending)
            )
        _validate_source_universe(data)
        _validate_final_acceptance(data, residuals, repo=repo)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "record",
        nargs="?",
        type=Path,
        default=Path("docs/megaplan/post-m11-release-evidence-20260731.json"),
    )
    parser.add_argument("--print-sha256", action="store_true")
    args = parser.parse_args()
    validate(args.record.resolve())
    if args.print_sha256:
        print(hashlib.sha256(args.record.read_bytes()).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
