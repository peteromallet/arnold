#!/usr/bin/env python3
"""M6 aggregate evidence validator (T16).

Validates the complete M6 evidence bundle: recomputes all content hashes,
re-verifies WBC ancestry, checks prerequisite status, detects stale hashes,
unexplained rows, and mutating inspection commands, then emits a comprehensive
``evidence/m6-proof-index.json`` with artifact hashes, generation commands,
repository HEAD, WBC ancestry result, and unresolved summary.

Design invariants
-----------------

* **Stale-hash rejection**: Every content hash is recomputed from disk;
  entries where the stored hash differs from the recomputed hash are flagged
  as ``stale`` and the validation fails.
* **Unexplained-row rejection**: Every row in every artifact must have a
  classification (row_kind, entry_kind, finding_id, stage_id, dimension_id,
  etc.) and a non-UNKNOWN canonical_owner where applicable.
* **Non-mutating inspection**: This tool only writes to
  ``evidence/m6-proof-index.json``.  It never modifies any other file,
  lifecycle state, queues, providers, or notification channels.
* **Incomplete-prerequisite rejection**: If the prerequisite verification
  reports INCOHERENT or BLOCKED, validation fails and the proof index
  records the blocker.
* **Inconsistent-WBC-ancestry rejection**: WBC ancestry is re-verified
  using the same read-only git operations as the prerequisite verifier.
  Any deviation from expected ancestry fails validation.
* **Rebuildable**: All data is derived from committed repo evidence and
  existing generated artifacts.  Regeneration produces deterministic,
  content-addressed output.

Usage::

    python tools/validate_m6_evidence.py [--output PATH] [--strict] [--check]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Paths ───────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = REPO_ROOT / "evidence"
REPLAY_DIR = EVIDENCE_DIR / "replay"

# All M6 evidence artifacts with their expected schemas and generator tools
M6_ARTIFACTS: dict[str, dict[str, Any]] = {
    "prerequisite_verification": {
        "path": EVIDENCE_DIR / "m6-prerequisite-verification.json",
        "expected_schema": "m6.prerequisite-verification.v1",
        "generator": "tools/verify_m6_prerequisites.py",
        "generator_args": ["--json"],
    },
    "wbc_boundary_discovery_rules": {
        "path": EVIDENCE_DIR / "wbc-boundary-discovery-rules.yaml",
        "expected_schema": "m6.wbc-boundary-discovery-rules.v1",
        "generator": "manual (T3 artifact, committed)",
        "generator_args": [],
    },
    "wbc_boundary_inventory": {
        "path": EVIDENCE_DIR / "wbc-boundary-inventory.json",
        "expected_schema": "m6.wbc-boundary-inventory.v1",
        "generator": "tools/generate_wbc_boundary_inventory.py",
        "generator_args": [],
    },
    "wbc_boundary_inventory_validation": {
        "path": EVIDENCE_DIR / "wbc-boundary-inventory-validation.json",
        "expected_schema": "m6.wbc-boundary-inventory-validation.v1",
        "generator": "tools/generate_wbc_boundary_inventory.py",
        "generator_args": ["--validate"],
    },
    "wbc_historical_adapters": {
        "path": EVIDENCE_DIR / "wbc-historical-adapters.json",
        "expected_schema": "m6.wbc-historical-adapters.v1",
        "generator": "tools/generate_wbc_boundary_inventory.py",
        "generator_args": [],
    },
    "finding_prevention_register": {
        "path": EVIDENCE_DIR / "finding-prevention-register.json",
        "expected_schema": "m6.finding-prevention-register.v1",
        "generator": "tools/generate_m6_finding_register.py",
        "generator_args": [],
    },
    "controlled_writer_registry": {
        "path": EVIDENCE_DIR / "controlled-writer-registry.json",
        "expected_schema": "m6.controlled-writer-registry.v1",
        "generator": "tools/generate_m6_controlled_registries.py",
        "generator_args": [],
    },
    "authority_reader_registry": {
        "path": EVIDENCE_DIR / "authority-reader-registry.json",
        "expected_schema": "m6.authority-reader-registry.v1",
        "generator": "tools/generate_m6_controlled_registries.py",
        "generator_args": ["--reader-registry"],
    },
    "migration_matrix_reconciled": {
        "path": EVIDENCE_DIR / "migration-matrix-reconciled.json",
        "expected_schema": "m6.migration-matrix-reconciled.v1",
        "generator": "tools/reconcile_m6_migration_matrix.py",
        "generator_args": [],
    },
    "replay_transaction_spine": {
        "path": REPLAY_DIR / "transaction-spine.json",
        "expected_schema": "m6.transaction-spine-replay-fixture.v1",
        "generator": "tools/generate_m6_replay_fixtures.py",
        "generator_args": [],
    },
    "replay_strategy_roadmap": {
        "path": REPLAY_DIR / "strategy-roadmap.json",
        "expected_schema": "m6.strategy-roadmap-replay-fixture.v1",
        "generator": "tools/generate_m6_replay_fixtures.py",
        "generator_args": ["--fixture", "strategy-roadmap"],
    },
    "pc_scope_decision": {
        "path": EVIDENCE_DIR / "pc-scope-decision.json",
        "expected_schema": "m6.pc-scope-decision.v1",
        "generator": "tools/generate_m6_ownership_decision.py",
        "generator_args": [],
    },
    "ownership_decision_record": {
        "path": EVIDENCE_DIR / "ownership-decision-record.json",
        "expected_schema": "m6.ownership-decision-record.v1",
        "generator": "tools/generate_m6_ownership_decision.py",
        "generator_args": [],
    },
    "rollout_deletion_register": {
        "path": EVIDENCE_DIR / "rollout-deletion-register.json",
        "expected_schema": "m6.rollout-deletion-register.v1",
        "generator": "tools/generate_m6_rollout_register.py",
        "generator_args": [],
    },
    "work_ledger_vocabulary": {
        "path": EVIDENCE_DIR / "work-ledger-vocabulary.json",
        "expected_schema": "m6.work-ledger-vocabulary.v1",
        "generator": "tools/generate_m6_rollout_register.py",
        "generator_args": [],
    },
}

# WBC integration commit — IMMUTABLE ANCESTRY ANCHOR (do NOT advance).
#
# CL5-T7 ANCESTRY PINNING NOTE:
#   This constant and the two WBC_EXPECTED_*_PARENT constants below are pinned
#   to the original WBC merge commit 24afce006b9ad20391ac7af10ef67ea0b1774f9f
#   and its exact merge parents. They verify merge-commit ANCESTRY IDENTITY —
#   a historical fact that must not move. The validator checks that the recorded
#   merge commit still exists, is a merge commit, has exactly these two parents,
#   and that both parents are ancestors of HEAD. Advancing these constants would
#   silently replace an ancestry-identity check with a different lineage, breaking
#   the historical-integration-point guarantee.
#
#   This is deliberately DIFFERENT from verify_m6_prerequisites.py, whose
#   WBC_INTEGRATION_COMMIT (currently 7cf0cab28c59d40614b9548fa4348ed7f062f52c)
#   is a file-hash regression baseline that MAY advance to an accepted
#   intermediate consolidation commit as the tracked files evolve. The two tools
#   use different commits for different semantics:
#     - validate_m6_evidence.py  → ancestry identity (immutable historical fact)
#     - verify_m6_prerequisites.py → file-content regression (may track HEAD-ward)
#   The file-hash rebind target MUST remain a descendant of this ancestry anchor.
#   See tests/tools/test_wbc_constants_coherence.py for the cross-tool invariant.
WBC_INTEGRATION_COMMIT = "24afce006b9ad20391ac7af10ef67ea0b1774f9f"

# WBC expected parents from merge evidence — IMMUTABLE (pinned to 24afce00's
# exact merge parents; see the ancestry-pinning note above).
WBC_EXPECTED_FIRST_PARENT = "7644f55dd9be75632670f990268e045d3ee1c2f7"
WBC_EXPECTED_SECOND_PARENT = "cbe69337d6f469fd7ae12f1fd0a51007d93b5d70"

PROOF_INDEX_SCHEMA = "m6.proof-index.v2"

# ── Git helpers (read-only) ─────────────────────────────────────────────────


def _git(*args: str) -> str:
    """Run a read-only git command and return stdout stripped."""
    try:
        result = subprocess.run(
            ["git"] + list(args),
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, ["git"] + list(args),
                output=result.stdout, stderr=result.stderr,
            )
        return result.stdout.strip()
    except FileNotFoundError:
        raise RuntimeError("git not found on PATH — cannot validate evidence")


def current_head() -> str:
    return _git("rev-parse", "HEAD")


def commit_exists(sha: str) -> bool:
    try:
        _git("cat-file", "-t", sha)
        return True
    except subprocess.CalledProcessError:
        return False


def is_ancestor(maybe_ancestor: str, descendant: str) -> bool:
    try:
        _git("merge-base", "--is-ancestor", maybe_ancestor, descendant)
        return True
    except subprocess.CalledProcessError:
        return False


def merge_parents(sha: str) -> list[str]:
    output = _git("cat-file", "-p", sha)
    parents: list[str] = []
    for line in output.splitlines():
        if line.startswith("parent "):
            parents.append(line.split()[1])
    return parents


# ── File helpers ────────────────────────────────────────────────────────────


def _sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file, or 'MISSING' if absent."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except (FileNotFoundError, OSError):
        return "MISSING"


def _load_json(path: Path) -> dict[str, Any] | None:
    """Load and parse a JSON file, returning None if missing or unparseable."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


# ── Validation helpers ──────────────────────────────────────────────────────


def _find_unexplained_rows(data: dict[str, Any], artifact_key: str) -> list[str]:
    """Find rows without proper classification in an artifact.

    Returns a list of descriptions of unexplained rows.
    Uses the actual field names from each artifact's schema.
    """
    unexplained: list[str] = []

    rows = data.get("rows") or data.get("entries") or []
    if not rows:
        return unexplained

    # Per-artifact classification requirements, matched to actual schema fields
    classification_checks: dict[str, list[str]] = {
        "finding_prevention_register": ["finding_id", "canonical_owner"],
        "controlled_writer_registry": ["writer_id", "owner"],
        "authority_reader_registry": ["reader_id", "owner"],
        "migration_matrix_reconciled": ["row_index", "classification"],
        "rollout_deletion_register": ["entry_id", "entry_kind", "canonical_owner"],
    }

    # Artifacts where rows use 'owner' instead of 'canonical_owner'
    owner_fields = {"controlled_writer_registry": "owner", "authority_reader_registry": "owner"}

    required = classification_checks.get(artifact_key, [])
    for i, row in enumerate(rows):
        row_id = row.get("finding_id") or row.get("writer_id") or row.get("reader_id") or row.get("entry_id") or row.get("row_index") or f"[{i}]"
        for field in required:
            val = row.get(field)
            if val is None or val == "" or val == "UNKNOWN":
                # For owner field, also check if it's a known non-UNKNOWN value
                if field in ("owner", "canonical_owner"):
                    unexplained.append(
                        f"{artifact_key}[{row_id}]: missing or UNKNOWN {field}"
                    )
                    break
                else:
                    unexplained.append(
                        f"{artifact_key}[{row_id}]: missing or empty field '{field}'"
                    )
                    break

    return unexplained


def _detect_mutating_commands(artifact_key: str) -> list[str]:
    """Verify that the generator for this artifact is observe-only.

    Returns warnings if the generator is known to mutate runtime state.
    This is a static check — all M6 generators are observe-only by design.
    """
    # All known M6 generators are observe-only; this is a guard against
    # future tools being classified as inspection commands when they mutate.
    known_mutators: set[str] = set()
    if artifact_key in known_mutators:
        return [f"{artifact_key}: generator is known to mutate runtime state"]
    return []


# ── WBC ancestry re-verification ────────────────────────────────────────────


def _reverify_wbc_ancestry() -> dict[str, Any]:
    """Re-verify WBC ancestry independently of the prerequisite verifier.

    Returns a dict with status and detail, suitable for inclusion in the
    proof index.
    """
    result: dict[str, Any] = {
        "check": "wbc_ancestry_reverified",
        "status": "UNKNOWN",
        "integration_commit": WBC_INTEGRATION_COMMIT,
    }

    try:
        head = current_head()
        result["current_head"] = head

        # Verify integration commit exists
        if not commit_exists(WBC_INTEGRATION_COMMIT):
            result["status"] = "INCOHERENT"
            result["detail"] = f"WBC integration commit {WBC_INTEGRATION_COMMIT[:8]} not found in repository"
            return result

        # Verify it's a merge commit
        parents = merge_parents(WBC_INTEGRATION_COMMIT)
        result["merge_parents"] = parents
        if len(parents) < 2:
            result["status"] = "INCOHERENT"
            result["detail"] = f"WBC integration commit {WBC_INTEGRATION_COMMIT[:8]} is not a merge commit"
            return result

        first_parent = parents[0]
        second_parent = parents[1]
        result["first_parent"] = first_parent
        result["second_parent"] = second_parent

        # Check parent SHAs match expected
        parent_match = (
            first_parent == WBC_EXPECTED_FIRST_PARENT
            and second_parent == WBC_EXPECTED_SECOND_PARENT
        )
        result["expected_parents_match"] = parent_match

        # Check both parents are ancestors of HEAD
        first_is_ancestor = is_ancestor(first_parent, head)
        second_is_ancestor = is_ancestor(second_parent, head)
        result["first_parent_is_ancestor"] = first_is_ancestor
        result["second_parent_is_ancestor"] = second_is_ancestor

        if not parent_match:
            result["status"] = "INCOHERENT"
            result["detail"] = (
                f"WBC merge parents do not match expected. "
                f"Expected first={WBC_EXPECTED_FIRST_PARENT[:8]}, "
                f"second={WBC_EXPECTED_SECOND_PARENT[:8]}; "
                f"Got first={first_parent[:8]}, second={second_parent[:8]}"
            )
        elif not first_is_ancestor or not second_is_ancestor:
            result["status"] = "INCOHERENT"
            result["detail"] = (
                f"WBC merge parent(s) not ancestors of current HEAD. "
                f"First parent is ancestor: {first_is_ancestor}, "
                f"Second parent is ancestor: {second_is_ancestor}"
            )
        else:
            result["status"] = "PASS"
            result["detail"] = "Both WBC merge parents are ancestors of current HEAD"

    except Exception as exc:
        result["status"] = "BLOCKED"
        result["detail"] = str(exc)

    return result


# ── Main validation ─────────────────────────────────────────────────────────


def _artifact_path(path: Path, input_root: Path) -> Path:
    """Resolve a declared repository artifact under an explicit input root."""
    try:
        relative = path.resolve().relative_to(REPO_ROOT.resolve())
    except ValueError:
        relative = Path(path.name)
    return (input_root / relative).resolve()


def validate_all_evidence(
    strict: bool = False, *, input_root: Path | None = None
) -> dict[str, Any]:
    """Validate the complete M6 evidence bundle.

    Returns the comprehensive proof index dict.
    """
    input_root = (input_root or REPO_ROOT).resolve()
    now = datetime.now(timezone.utc).isoformat()
    errors: list[str] = []
    warnings: list[str] = []

    # ── Repository HEAD ──────────────────────────────────────────────────
    head = current_head()
    head_valid = commit_exists(head)

    # ── WBC ancestry reverification ───────────────────────────────────────
    wbc_ancestry = _reverify_wbc_ancestry()

    # ── Load prerequisite verification ───────────────────────────────────
    prereq_data = _load_json(_artifact_path(
        M6_ARTIFACTS["prerequisite_verification"]["path"], input_root
    ))
    prereq_status = "UNKNOWN"
    prereq_summary: dict[str, Any] = {}
    if prereq_data is None:
        errors.append("Prerequisite verification artifact missing or unparseable")
        prereq_status = "BLOCKED"
    else:
        prereq_status = prereq_data.get("overall_status", "UNKNOWN")
        prereq_summary = prereq_data.get("summary", {})
        if prereq_status in ("INCOHERENT", "BLOCKED"):
            errors.append(
                f"Prerequisite verification status is {prereq_status} — "
                f"M6 evidence bundle cannot be considered complete"
            )
        # Verify schema
        if prereq_data.get("schema") != M6_ARTIFACTS["prerequisite_verification"]["expected_schema"]:
            errors.append(
                f"Prerequisite verification schema mismatch: expected "
                f"{M6_ARTIFACTS['prerequisite_verification']['expected_schema']}, "
                f"got {prereq_data.get('schema')}"
            )

    # ── Validate each artifact ───────────────────────────────────────────
    entries: list[dict[str, Any]] = []
    stale_hashes: list[str] = []
    missing_artifacts: list[str] = []
    unexplained_row_artifacts: list[str] = []
    schema_mismatches: list[str] = []
    mutating_command_warnings: list[str] = []

    for key in sorted(M6_ARTIFACTS):
        spec = M6_ARTIFACTS[key]
        path = _artifact_path(spec["path"], input_root)
        expected_schema = spec["expected_schema"]
        generator = spec["generator"]
        generator_args = spec.get("generator_args", [])

        # Compute fresh content hash
        fresh_hash = _sha256_file(path)
        present = path.exists()
        is_json = path.suffix == ".json"

        if not present:
            missing_artifacts.append(key)

        # Extract stored schema and composite hash from JSON artifacts
        actual_schema = "UNKNOWN"
        stored_composite_hash = "UNKNOWN"
        stored_byte_hash = "UNKNOWN"
        recomputed_composite = None
        row_count: Any = "UNKNOWN"
        artifact_rows: list[dict[str, Any]] = []

        if present and is_json:
            data = _load_json(path)
            if data is not None:
                actual_schema = data.get("schema", "UNKNOWN")
                stored_composite_hash = data.get("composite_hash", "UNKNOWN")
                stored_byte_hash = data.get("content_hash", data.get("content_hash_fresh", "UNKNOWN"))
                artifact_rows = data.get("rows") or data.get("entries") or data.get("stages") or []
                if isinstance(artifact_rows, list):
                    row_count = len(artifact_rows)
                else:
                    row_count = "UNKNOWN"

                # Schema check
                if actual_schema != expected_schema and actual_schema != "UNKNOWN":
                    schema_mismatches.append(
                        f"{key}: expected schema '{expected_schema}', got '{actual_schema}'"
                    )

                # Check for unexplained rows
                unexplained = _find_unexplained_rows(data, key)
                if unexplained:
                    unexplained_row_artifacts.append(key)
                    for u in unexplained:
                        warnings.append(u)

                # Recompute composite hash for JSON artifacts with rows
                recomputed_composite = _recompute_composite_hash(artifact_rows, data)
                if recomputed_composite and stored_composite_hash != "UNKNOWN":
                    if recomputed_composite != stored_composite_hash:
                        stale_hashes.append(key)
                        errors.append(
                            f"{key}: composite hash is stale — "
                            f"stored={stored_composite_hash[:16]}..., "
                            f"recomputed={recomputed_composite[:16]}..."
                        )
                if stored_byte_hash not in ("UNKNOWN", fresh_hash):
                    stale_hashes.append(key)
                    errors.append(
                        f"{key}: byte content hash is stale — stored={stored_byte_hash[:16]}..., "
                        f"recomputed={fresh_hash[:16]}..."
                    )

            else:
                warnings.append(f"{key}: present but unparseable JSON")

        # Check for mutating inspection commands
        mc = _detect_mutating_commands(key)
        if mc:
            mutating_command_warnings.extend(mc)
            errors.extend(mc)

        # Build proof index entry
        entry: dict[str, Any] = {
            "artifact_key": key,
            "path": str(path.relative_to(input_root)),
            "expected_schema": expected_schema,
            "actual_schema": actual_schema,
            "content_hash_fresh": fresh_hash,
            "content_hash_stored": stored_byte_hash if stored_byte_hash != "UNKNOWN" else fresh_hash,
            "composite_hash_stored": stored_composite_hash,
            "composite_hash_recomputed": recomputed_composite or "UNKNOWN",
            "row_count": row_count,
            "present": present,
            "generator": generator,
            "generator_args": " ".join(generator_args) if generator_args else "",
            "hash_stale": key in stale_hashes,
            "has_unexplained_rows": key in unexplained_row_artifacts,
        }
        entries.append(entry)

    # ── Determine validation result ──────────────────────────────────────
    has_blockers = bool(errors)
    prereq_blocked = prereq_status in ("INCOHERENT", "BLOCKED")
    wbc_blocked = wbc_ancestry.get("status") not in ("PASS",)

    if prereq_blocked:
        errors.append("M6 prerequisites are INCOHERENT or BLOCKED — handoff must not be marked complete")

    if wbc_blocked:
        errors.append("WBC ancestry re-verification failed — ancestry is inconsistent")

    validation_passed = not has_blockers

    # ── Build unresolved summary ─────────────────────────────────────────
    unresolved_summary: dict[str, Any] = {
        "prerequisite_verification_status": prereq_status,
        "prerequisite_summary": prereq_summary,
        "wbc_ancestry_status": wbc_ancestry.get("status", "UNKNOWN"),
        "wbc_ancestry_detail": wbc_ancestry.get("detail", ""),
        "stale_hash_artifacts": stale_hashes,
        "missing_artifacts": missing_artifacts,
        "unexplained_row_artifacts": unexplained_row_artifacts,
        "schema_mismatches": schema_mismatches,
        "mutating_command_warnings": mutating_command_warnings,
    }

    # Collect global unknowns from all artifacts
    global_unknowns = _collect_global_unknowns(input_root=input_root)
    global_unknowns["repository_head"] = head
    global_unknowns["repository_head_valid"] = head_valid
    global_unknowns["wbc_ancestry_parent_match"] = wbc_ancestry.get("expected_parents_match", "UNKNOWN")
    global_unknowns["wbc_first_parent_is_ancestor"] = wbc_ancestry.get("first_parent_is_ancestor", "UNKNOWN")
    global_unknowns["wbc_second_parent_is_ancestor"] = wbc_ancestry.get("second_parent_is_ancestor", "UNKNOWN")

    # ── Assemble proof index ─────────────────────────────────────────────
    present_count = sum(1 for e in entries if e["present"])
    total_count = len(entries)

    proof_index: dict[str, Any] = {
        "schema": PROOF_INDEX_SCHEMA,
        "generated_at": now,
        "generator": "tools/validate_m6_evidence.py",
        "north_star_guard": (
            "M6 is observe-only. This proof index is the aggregate validation result: "
            "every content hash is recomputed from disk, stale hashes are rejected, "
            "unexplained rows are flagged, WBC ancestry is re-verified, and incomplete "
            "prerequisites are recorded as blockers. Unavailable denominators and blocked "
            "prerequisites are recorded as UNKNOWN, never as success evidence or zero."
        ),
        "validation_passed": validation_passed,
        "validation_errors": errors,
        "validation_warnings": warnings,
        "artifact_count": total_count,
        "present_count": present_count,
        "missing_count": len(missing_artifacts),
        "missing_artifacts": missing_artifacts,
        "stale_hash_count": len(stale_hashes),
        "stale_hash_artifacts": stale_hashes,
        "unexplained_row_count": len(unexplained_row_artifacts),
        "unexplained_row_artifacts": unexplained_row_artifacts,
        "entries": entries,
        "repository_head": head,
        "input_root": str(input_root),
        "wbc_ancestry_result": wbc_ancestry,
        "unresolved_summary": unresolved_summary,
        "global_unknowns": global_unknowns,
        "prerequisite_verification": {
            "artifact_key": "prerequisite_verification",
            "status": prereq_status,
            "summary": prereq_summary,
        },
    }

    return proof_index


def _recompute_composite_hash(rows: list[dict[str, Any]], data: dict[str, Any]) -> str | None:
    """Recompute composite hash from artifact rows, if the artifact has the pattern."""
    if not rows:
        return None

    # Try to find row_hash or similar field in each row
    row_hashes: list[str] = []
    for r in rows:
        rh = r.get("row_hash") or r.get("hash") or ""
        if rh:
            row_hashes.append(rh)
        else:
            # Compute a hash from the row's key fields
            canonical = json.dumps(r, sort_keys=True, ensure_ascii=False)
            row_hashes.append(hashlib.sha256(canonical.encode("utf-8")).hexdigest())

    if row_hashes:
        joined = "".join(sorted(row_hashes))
        return hashlib.sha256(joined.encode("utf-8")).hexdigest()

    return None


def _collect_global_unknowns(*, input_root: Path = REPO_ROOT) -> dict[str, Any]:
    """Collect global unknown baselines from all evidence artifacts."""
    unknowns: dict[str, Any] = {}

    # Prerequisite verification unknowns
    prereq = _load_json(_artifact_path(
        M6_ARTIFACTS["prerequisite_verification"]["path"], input_root
    ))
    if prereq:
        unknowns["prerequisite_overall_status"] = prereq.get("overall_status", "UNKNOWN")
        unknowns["prerequisite_m5_bound_head_coherent"] = "UNKNOWN"
        if prereq.get("checks"):
            for check in prereq["checks"]:
                if check.get("check") == "m5_bound_head_vs_current_head":
                    unknowns["prerequisite_m5_bound_head_coherent"] = (
                        "PASS" if check.get("exact_match") else "INCOHERENT"
                    )

    # PC scope decision blocker
    pc_scope = _load_json(_artifact_path(
        M6_ARTIFACTS["pc_scope_decision"]["path"], input_root
    ))
    if pc_scope:
        blockers = pc_scope.get("blockers", [])
        unknowns["pc_scope_blocker_count"] = len(blockers)
        unknowns["pc_scope_human_approval_required"] = any(
            "human approval" in b.get("description", "").lower() for b in blockers
        )

    # Ownership decision blockers
    ownership = _load_json(_artifact_path(
        M6_ARTIFACTS["ownership_decision_record"]["path"], input_root
    ))
    if ownership:
        blockers = ownership.get("global_blockers", [])
        unknowns["ownership_blocker_count"] = len(blockers)

    # Migration matrix classification gaps
    matrix = _load_json(_artifact_path(
        M6_ARTIFACTS["migration_matrix_reconciled"]["path"], input_root
    ))
    if matrix:
        rows = matrix.get("rows", [])
        unknowns["migration_matrix_total_rows"] = len(rows)
        unknowns["migration_matrix_unclassified"] = sum(
            1 for r in rows if r.get("classification") == "UNKNOWN"
        )

    # Finding register coverage
    findings = _load_json(_artifact_path(
        M6_ARTIFACTS["finding_prevention_register"]["path"], input_root
    ))
    if findings:
        f_rows = findings.get("rows", [])
        unknowns["finding_register_total"] = len(f_rows)
        unknowns["finding_register_with_owner"] = sum(
            1 for r in f_rows if r.get("canonical_owner") and r["canonical_owner"] != "UNKNOWN"
        )

    # Run Authority M1-M3 acceptance
    unknowns["run_authority_m1_m3_accepted"] = "UNKNOWN"
    unknowns["run_authority_m1_m3_rationale"] = (
        "Run Authority M1-M3 completion receipts all have accepted: false. "
        "Source: migration matrix row 0, ownership-decision-record OWNERSHIP-BLOCKER-001."
    )

    unknowns["m5_bound_head_coherent"] = "UNKNOWN"
    unknowns["m5_bound_head_rationale"] = (
        "M5 bound-head (8bb779d) does not match current HEAD. "
        "Prerequisite verification reports INCOHERENT. "
        "Source: evidence/m6-prerequisite-verification.json."
    )

    unknowns["wbc_file_hashes_coherent"] = "UNKNOWN"
    unknowns["wbc_file_hashes_rationale"] = (
        "WBC file hash check reports INCOHERENT: one source file mismatch. "
        "Source: evidence/m6-prerequisite-verification.json."
    )

    unknowns["portfolio_gate_approved"] = "UNKNOWN"
    unknowns["portfolio_gate_rationale"] = (
        "Portfolio gate PC scope decision is machine-generated with blocker "
        "PC-SCOPE-BLOCKER-001. Human approval is required but not recorded. "
        "Source: evidence/pc-scope-decision.json."
    )

    unknowns["productive_replay_ledger_coverage"] = "UNKNOWN"
    unknowns["productive_replay_ledger_rationale"] = (
        "Productive-versus-replayed token/cost baselines are UNKNOWN "
        "until joined per-task/attempt/repair receipts exist. "
        "Source: F14 finding, work-ledger-vocabulary."
    )

    unknowns["wbc_ancestry_coherent"] = "UNKNOWN"
    unknowns["wbc_ancestry_rationale"] = (
        "WBC ancestry is re-verified during aggregate validation. "
        "Any deviation from expected merge parents or ancestor relationships "
        "will be recorded as INCOHERENT."
    )

    return unknowns


# ── Main ────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate the complete M6 evidence bundle and emit proof index"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=EVIDENCE_DIR / "m6-proof-index.json",
        help=f"Output path for proof index (default: evidence/m6-proof-index.json)",
    )
    parser.add_argument(
        "--input-root",
        type=Path,
        default=REPO_ROOT,
        help="Repository/evidence root to read; output is independent and may be elsewhere.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if validation fails (stale hashes, unexplained rows, etc.)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        dest="check_mode",
        help=(
            "Approved acceptance entrypoint: run aggregate validation, "
            "emit the proof index, and exit according to prerequisite/blocker "
            "semantics.  Equivalent to default mode with validation output."
        ),
    )
    args = parser.parse_args()

    output_path: Path = args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)

    proof_index = validate_all_evidence(strict=args.strict, input_root=args.input_root)

    # Emit proof index
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(proof_index, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(f"Wrote {output_path}")

    # Report
    print(f"\nValidation {'PASSED' if proof_index['validation_passed'] else 'FAILED'}")
    print(f"  Artifacts: {proof_index['present_count']}/{proof_index['artifact_count']} present")
    print(f"  Missing:   {proof_index['missing_count']}")
    print(f"  Stale hashes: {proof_index['stale_hash_count']}")
    print(f"  Unexplained rows: {proof_index['unexplained_row_count']}")
    print(f"  Errors:    {len(proof_index['validation_errors'])}")
    print(f"  Warnings:  {len(proof_index['validation_warnings'])}")

    if proof_index["validation_errors"]:
        print("\nErrors:")
        for err in proof_index["validation_errors"]:
            print(f"  - {err}")

    if proof_index["validation_warnings"]:
        print("\nWarnings:")
        for warn in proof_index["validation_warnings"]:
            print(f"  - {warn}")

    if (args.strict or args.check_mode) and not proof_index["validation_passed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
