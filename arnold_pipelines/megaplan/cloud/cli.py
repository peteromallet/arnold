"""CLI entrypoints for arnold cloud commands."""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import inspect
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import uuid
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, replace
from importlib import resources
from pathlib import Path, PurePosixPath
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import Any, Mapping
from urllib.parse import urlsplit

import yaml

from arnold_pipelines.megaplan.cloud.auth import (
    ON_BOX_GIT_CREDENTIAL_FILE,
    ON_BOX_GIT_CREDENTIAL_FILE_ENV,
    on_box_git_credential_env,
    seed_codex_oauth,
    seed_isolated_git_credentials,
)
from arnold_pipelines.megaplan.cloud.providers.base import (
    DeployReport,
    DeployStepReport,
    _write_redacted_output,
    get_provider,
    megaplan_runtime_invocation,
)
from arnold_pipelines.megaplan.cloud.redact import redact
from arnold_pipelines.megaplan.cloud.spec import CloudSpec, apply_repo_overrides, load_spec as load_cloud_spec
from arnold_pipelines.megaplan.cloud import status_format, status_snapshot
from arnold_pipelines.megaplan.cloud.runtime_manifest import (
    DEPENDENCY_GENERATION_KEYS,
    EPIC_REQUIRED,
    MANIFEST_SCHEMA_VERSION,
    TOP_LEVEL_REQUIRED,
)
from arnold_pipelines.megaplan.cloud.babysitter.routing import (
    CONTINUATION_MUSE_MODEL,
    CONTINUATION_MUSE_PROFILE,
)
from arnold_pipelines.megaplan.fallback_chains import decode_phase_model_value, encode_phase_model_value
from arnold_pipelines.megaplan.finite_canary_policy import (
    finite_canary_policy_is_exact,
)
from arnold_pipelines.megaplan.cloud.template import (
    _sanitise_git_url,
    materialize_deploy_dir,
    render_ensure_repos_block,
)
from arnold_pipelines.megaplan.layout import is_canonical_chain_spec
from arnold_pipelines.megaplan.types import CliError


load_spec = load_cloud_spec
CLOUD_STATUS_CLI_MAX_AGE_S = 5 * 60
_ZERO_RECOVERY_CLOUD_ACTIONS = {
    "build",
    "deploy",
    "capacity-inventory",
    "reclaim-dangling-build-cache",
    "logs",
    "run-zero-recovery-canary",
    "zero-recovery-canary-status",
    "zero-recovery-preflight",
    "resident-recover",
    "resident-down",
    "resident-reconcile-down",
}
_ISOLATED_CHAIN_RUNNER_CLOUD_ACTIONS = {
    "build",
    "deploy",
    "preflight",
    "sync-megaplan",
    "chain",
    "status",
    "logs",
    "chains",
    "capacity-inventory",
}
_ISOLATED_CHAIN_RUNNER_PIN_REQUIRED_ACTIONS = (
    _ISOLATED_CHAIN_RUNNER_CLOUD_ACTIONS - {"build", "capacity-inventory"}
)

# Cloud deployments always drive phases via subprocess (remote SSH exec);
# the substrate is pinned here so the cloud CLI explicitly declares its
# execution model to _phase_command (M3 Step 12 compatibility boundary).
cloud_substrate: str = "subprocess_isolated"

_TEMPLATE_PLACEHOLDER_RE = re.compile(
    r"\bTODO(?:_[A-Z0-9]+)+\b|<box-ip>|TODO_SSH_HOST|TODO_REPO_URL"
)
_RAW_GIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
def _validate_continuation_muse_routes(
    preflight_summary: Mapping[str, Any], *, session: str = ""
) -> dict[str, Any] | None:
    """Validate closed fixer routing from the resolved chain profile.

    Session names are not identity: they rotate between continuation
    generations and can be supplied by an operator.  The resolved profile in
    the preflight evidence is the authoritative workload declaration.
    """
    milestones = [
        item for item in preflight_summary.get("milestones", [])
        if isinstance(item, Mapping)
    ]
    profiles = {str(item.get("profile") or "").strip() for item in milestones}
    if CONTINUATION_MUSE_PROFILE not in profiles:
        return None
    if profiles != {CONTINUATION_MUSE_PROFILE}:
        raise CliError(
            "closed_profile_route_mismatch",
            "closed Muse profile must cover every chain milestone",
            extra={"profiles": sorted(profiles), "session": session},
        )
    bad: list[dict[str, Any]] = []
    for milestone in milestones:
        label = milestone.get("label", "")
        phase_chains = milestone.get("resolved_phase_chains", {})
        for phase, chain in phase_chains.items():
            if chain != [CONTINUATION_MUSE_MODEL]:
                bad.append({"label": label, "phase": phase, "resolved": chain})
    if bad:
        raise CliError(
            "closed_profile_route_mismatch",
            "closed Muse profile requires Muse Spark 1.3 Contributor/high with no fallback",
            extra={"route_failures": bad},
        )
    return {
        "status": "ok",
        "model": CONTINUATION_MUSE_MODEL,
        "profile": CONTINUATION_MUSE_PROFILE,
        "thinking": "high",
        "fallback": False,
    }


_MUSE_PREFLIGHT_MARKER = "ARNOLD_MUSE_PREFLIGHT_OK"
_MUSE_PREFLIGHT_QUERY = f"Reply with exactly: {_MUSE_PREFLIGHT_MARKER}"


def _omp_openrouter_capability_check(
    provider=None, *, local: bool = False
) -> dict[str, Any]:
    """Prove the exact OMP/OpenRouter route without inspecting credentials.

    OMP owns authentication (usually through the box broker/store), so an
    ``OPENROUTER_API_KEY`` environment variable is not itself a launch
    prerequisite.  The bounded no-tools/sessionless probe is deliberately a
    single exact model with no fallback.  Only a typed status and digest of
    stderr are returned; provider output and secrets are never persisted.
    """
    command = (
        "omp -p --model openrouter/meta/muse-spark-1.3-contributor "
        "--thinking high --no-tools --no-session --max-time 90 "
        + shlex.quote(_MUSE_PREFLIGHT_QUERY)
    )
    try:
        if provider is not None and not local:
            result = provider.ssh_exec(command)
        else:
            result = subprocess.run(
                [
                    "omp",
                    "-p",
                    "--model",
                    "openrouter/meta/muse-spark-1.3-contributor",
                    "--thinking",
                    "high",
                    "--no-tools",
                    "--no-session",
                    "--max-time",
                    "90",
                    _MUSE_PREFLIGHT_QUERY,
                ],
                capture_output=True,
                text=True,
                timeout=100,
                check=False,
            )
    except Exception as exc:
        return {
            "status": "unavailable",
            "reason": type(exc).__name__,
            "provider": "openrouter",
            "model": "meta/muse-spark-1.3-contributor",
            "thinking": "high",
            "fallback": False,
            "probe": "omp_sessionless_no_tools",
        }
    returncode = int(getattr(result, "returncode", 1))
    stdout = str(getattr(result, "stdout", "") or "")
    stderr = str(getattr(result, "stderr", "") or "")
    lowered = (stdout + "\n" + stderr).lower()
    if "fallback" in lowered:
        status = "fallback_mismatch"
        reason = "omp_fallback_detected"
    elif any(token in lowered for token in ("auth", "credential", "unauthorized")):
        status = "authentication_failed"
        reason = "omp_authentication_failed"
    elif any(token in lowered for token in ("quota", "credit")):
        status = "quota_exhausted"
        reason = "omp_quota_exhausted"
    elif any(
        token in lowered
        for token in ("model not found", "unknown model", "unsupported model", "resolution")
    ):
        status = "resolution_failed"
        reason = "omp_model_resolution_failed"
    elif returncode == 0 and stdout.rstrip() != _MUSE_PREFLIGHT_MARKER:
        status = "probe_failed"
        reason = "omp_probe_response_mismatch"
    elif returncode == 0:
        status = "ok"
        reason = None
    else:
        status = "probe_failed"
        reason = "omp_probe_nonzero"
    evidence = {
        "status": status,
        "provider": "openrouter",
        "model": "meta/muse-spark-1.3-contributor",
        "thinking": "high",
        "fallback": False,
        "probe": "omp_sessionless_no_tools",
        "returncode": returncode,
        "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
    }
    if reason is not None:
        evidence["reason"] = reason
    return evidence


def _validate_zero_recovery_canary_spec(
    root: Path, raw_path: str, raw_cloud_path: str | None, spec: CloudSpec
) -> dict[str, Any]:
    path = (root / raw_path).resolve() if not Path(raw_path).is_absolute() else Path(raw_path).resolve()
    expected = (
        root
        / ".megaplan/initiatives/critique-ledger-safe-v3-canary/canary.yaml"
    ).resolve()
    if path != expected or not path.is_file():
        raise CliError(
            "zero_recovery_canary_invalid", "the exact tracked canary.yaml is required"
        )
    initiative = expected.parent
    expected_cloud = (initiative / "cloud.yaml").resolve()
    cloud_path = (
        (root / raw_cloud_path).resolve()
        if raw_cloud_path and not Path(raw_cloud_path).is_absolute()
        else Path(raw_cloud_path).resolve()
        if raw_cloud_path
        else (root / "cloud.yaml").resolve()
    )
    if cloud_path != expected_cloud or not cloud_path.is_file():
        raise CliError(
            "zero_recovery_canary_invalid", "the exact tracked canary cloud.yaml is required"
        )
    try:
        node = yaml.compose(path.read_text(encoding="utf-8"))

        def reject_duplicate_yaml(value: yaml.Node) -> None:
            if isinstance(value, yaml.MappingNode):
                keys: set[str] = set()
                for key_node, item_node in value.value:
                    key = key_node.value
                    if key in keys:
                        raise ValueError(f"duplicate YAML field: {key}")
                    keys.add(key)
                    reject_duplicate_yaml(item_node)
            elif isinstance(value, yaml.SequenceNode):
                for item_node in value.value:
                    reject_duplicate_yaml(item_node)

        if node is None:
            raise ValueError("empty YAML")
        reject_duplicate_yaml(node)
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError, ValueError) as exc:
        raise CliError(
            "zero_recovery_canary_invalid", f"canary spec is not strict YAML: {exc}"
        ) from exc
    required = {
        "schema", "canary_id", "engine_commit", "engine_tree", "brief",
        "north_star", "plan_name", "phases", "terminal_state", "model_spec",
        "robustness", "adaptive_critique", "receipts", "policy",
    }
    receipts = payload.get("receipts") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or set(payload) != required
        or payload.get("schema") != "arnold.megaplan.finite_canary.v1"
        or payload.get("canary_id") != "critique-ledger-safe-v3-canary"
        or payload.get("engine_commit") != spec.megaplan.ref
        or not isinstance(payload.get("engine_tree"), str)
        or not re.fullmatch(r"[0-9a-f]{40}", payload.get("engine_tree"))
        or payload.get("brief")
        != ".megaplan/initiatives/critique-ledger-safe-v3-canary/briefs/cl2-ledger-persistence-and-replay.md"
        or payload.get("north_star")
        != ".megaplan/initiatives/critique-ledger-safe-v3-canary/NORTHSTAR.md"
        or payload.get("plan_name") != "critique-ledger-cl2-planning-canary"
        or payload.get("phases") != ["init", "plan", "critique", "gate", "finalize"]
        or payload.get("terminal_state") != "finalized"
        or payload.get("model_spec") != "codex:gpt-5.6-sol:high"
        or payload.get("robustness") != "full"
        or payload.get("adaptive_critique") is not False
        or not finite_canary_policy_is_exact(payload.get("policy"))
        or receipts
        != {
            "directory": ".megaplan/initiatives/critique-ledger-safe-v3-canary/receipts",
            "content_addressed": True,
        }
        or spec.provider != "ssh"
        or spec.mode != "idle"
        or not spec.zero_recovery_canary
        or spec.secrets != []
        or spec.extra_repos != ()
        or spec.megaplan.codex_auth != "chatgpt"
        or spec.codex.model != "gpt-5.6-sol"
        or spec.codex.reasoning != "high"
        or spec.agents != {"default": "codex"}
        or spec.toolchains not in (None, [])
        or not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?", spec.repo.url)
    ):
        raise CliError(
            "zero_recovery_canary_invalid", "canary spec or cloud binding mismatch"
        )
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=False
    )
    tree = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=root, capture_output=True, text=True, check=False
    )
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=root, capture_output=True, text=True, check=False,
    )
    parent = subprocess.run(
        ["git", "rev-parse", "HEAD^"], cwd=root, capture_output=True, text=True, check=False
    )
    engine_tree = subprocess.run(
        ["git", "rev-parse", f"{payload['engine_commit']}^{{tree}}"],
        cwd=root, capture_output=True, text=True, check=False,
    )
    manifest_diff = subprocess.run(
        ["git", "diff", "--name-only", f"{payload['engine_commit']}..HEAD"],
        cwd=root, capture_output=True, text=True, check=False,
    )
    allowed_manifest_delta = {
        ".megaplan/initiatives/critique-ledger-safe-v3-canary/canary.yaml",
        ".megaplan/initiatives/critique-ledger-safe-v3-canary/cloud.yaml",
        ".megaplan/initiatives/critique-ledger-safe-v3-canary/proof-map.json",
        ".megaplan/initiatives/critique-ledger-safe-v3-canary/traceability.json",
    }
    if (
        head.returncode != 0
        or tree.returncode != 0
        or status.returncode != 0
        or parent.returncode != 0
        or engine_tree.returncode != 0
        or manifest_diff.returncode != 0
        or status.stdout
        or not re.fullmatch(r"[0-9a-f]{40}", head.stdout.strip())
        or not re.fullmatch(r"[0-9a-f]{40}", tree.stdout.strip())
        or parent.stdout.strip() != payload["engine_commit"]
        or engine_tree.stdout.strip() != payload["engine_tree"]
        or set(manifest_diff.stdout.splitlines()) != allowed_manifest_delta
    ):
        raise CliError(
            "zero_recovery_canary_invalid",
            "launching checkout must be clean with exact Git commit/tree identity",
        )
    tracked_inputs = {
        payload["brief"],
        payload["north_star"],
        *allowed_manifest_delta,
    }
    for relative in tracked_inputs:
        tracked = subprocess.run(
            ["git", "ls-files", "--error-unmatch", "--", relative],
            cwd=root, capture_output=True, text=True, check=False,
        )
        dirty = subprocess.run(
            ["git", "diff", "--quiet", "--", relative], cwd=root, check=False
        )
        if tracked.returncode != 0 or dirty.returncode != 0:
            raise CliError(
                "zero_recovery_canary_invalid", f"canary input is untracked or dirty: {relative}"
            )
    def strict_json(path_to_read: Path) -> dict[str, Any]:
        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"duplicate JSON field: {key}")
                result[key] = value
            return result

        value = json.loads(
            path_to_read.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicates,
        )
        if not isinstance(value, dict):
            raise ValueError("manifest is not an object")
        return value

    try:
        proof = strict_json(initiative / "proof-map.json")
        trace = strict_json(initiative / "traceability.json")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CliError(
            "zero_recovery_canary_invalid", f"strict proof/trace manifest required: {exc}"
        ) from exc
    proof_implementation = proof.get("implementation")
    proof_launch = proof.get("launch_manifest")
    if (
        set(proof) != {"schema", "implementation", "launch_manifest", "claims", "excluded_claims"}
        or proof.get("schema") != "arnold.megaplan.finite_canary_proof_map.v1"
        or proof_implementation != {
            "commit": payload["engine_commit"], "tree": payload["engine_tree"]
        }
        or not isinstance(proof_launch, dict)
        or proof_launch.get("required_parent") != payload["engine_commit"]
        or proof_launch.get("allowed_delta")
        != ["canary.yaml", "cloud.yaml", "proof-map.json", "traceability.json"]
    ):
        raise CliError("zero_recovery_canary_invalid", "proof-map binding mismatch")
    expected_trace_fields = {
        "schema", "implementation_commit", "implementation_tree",
        "launch_manifest_binding", "launch_manifest_parent",
        "canary_spec", "brief_source", "copied_brief", "fresh_workspace",
        "predecessor_workspace", "workspace_bind_source",
        "predecessor_container", "canary_container",
    }
    if (
        set(trace) != expected_trace_fields
        or trace.get("schema") != "arnold.megaplan.finite_canary_traceability.v1"
        or trace.get("implementation_commit") != payload["engine_commit"]
        or trace.get("implementation_tree") != payload["engine_tree"]
        or trace.get("launch_manifest_binding")
        != {"method": "derived_clean_head_at_admission"}
        or trace.get("launch_manifest_parent") != payload["engine_commit"]
        or trace.get("canary_spec") != str(path.relative_to(root))
        or trace.get("copied_brief") != payload["brief"]
        or trace.get("fresh_workspace") != spec.repo.workspace
        or trace.get("predecessor_workspace")
        != (spec.ssh.workspace_dir if spec.ssh else None)
        or trace.get("workspace_bind_source")
        != spec.zero_recovery_workspace_dir
        or trace.get("predecessor_container") != spec.zero_recovery_predecessor_container
        or trace.get("canary_container") != (spec.ssh.container if spec.ssh else None)
    ):
        raise CliError("zero_recovery_canary_invalid", "traceability binding mismatch")
    payload["_admission_source_commit"] = head.stdout.strip()
    payload["_admission_source_tree"] = tree.stdout.strip()
    payload["_admission_manifest_sha256"] = {
        relative: hashlib.sha256((root / relative).read_bytes()).hexdigest()
        for relative in sorted(allowed_manifest_delta)
    }
    return payload


def _register_cloud_subcommands(cloud_parser: argparse.ArgumentParser) -> None:
    cloud_sub = cloud_parser.add_subparsers(dest="cloud_action", required=True)

    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument(
        "--cloud-yaml",
        default=None,
        help="Path to cloud.yaml (default: <project-root>/cloud.yaml)",
    )

    init_parser = cloud_sub.add_parser(
        "init",
        parents=[shared],
        help="Scaffold a cloud.yaml file at the project root",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing cloud.yaml",
    )

    cloud_sub.add_parser("build", parents=[shared], help="Build the cloud image")
    cloud_sub.add_parser("deploy", parents=[shared], help="Deploy the cloud runner")
    cloud_sub.add_parser(
        "capacity-inventory",
        parents=[shared],
        help="Read fixed host/filesystem/Docker capacity evidence without reclaiming data",
    )
    reclaim_parser = cloud_sub.add_parser(
        "reclaim-dangling-build-cache",
        parents=[shared],
        help="Dry-run or explicitly apply the fixed zero-recovery bootstrap reclaim",
    )
    reclaim_parser.add_argument(
        "--apply",
        action="store_true",
        help="Explicitly apply the freshly prepared fixed proposal",
    )
    run_zero_parser = cloud_sub.add_parser(
        "run-zero-recovery-canary",
        parents=[shared],
        help="Run the one tracked finite canary with fixed auth and command routing",
    )
    run_zero_parser.add_argument("canary_spec")
    zero_status_parser = cloud_sub.add_parser(
        "zero-recovery-canary-status",
        parents=[shared],
        help="Read the fixed finite-canary receipt state without container exec",
    )
    zero_status_parser.add_argument("canary_spec")
    zero_preflight_parser = cloud_sub.add_parser(
        "zero-recovery-preflight",
        parents=[shared],
        help="Issue a fresh read-only zero-recovery predeploy transaction",
    )
    zero_preflight_parser.add_argument("canary_spec")
    resident_recover_parser = cloud_sub.add_parser(
        "resident-recover",
        parents=[shared],
        help="Start one CAS-bound listener-only Discord resident from a preserved SSH container",
    )
    resident_recover_parser.add_argument("--outage-epoch", required=True)
    resident_recover_parser.add_argument("--expected-source-container-id", required=True)
    resident_recover_parser.add_argument("--expected-source-image-id", required=True)
    resident_recover_parser.add_argument("--expected-resident-image-id", required=True)
    resident_recover_parser.add_argument("--expected-runtime-path", required=True)
    resident_recover_parser.add_argument("--expected-runtime-commit", required=True)
    resident_recover_parser.add_argument("--expected-runtime-tree", required=True)
    resident_recover_parser.add_argument("--expected-runtime-python-path", required=True)
    resident_recover_parser.add_argument("--expected-runtime-python-sha256", required=True)
    resident_recover_parser.add_argument(
        "--health-timeout-seconds", type=int, default=45
    )
    resident_down_parser = cloud_sub.add_parser(
        "resident-down",
        parents=[shared],
        help="Stop/remove the exact resident-only container for one durable outage epoch",
    )
    resident_down_parser.add_argument("--outage-epoch", required=True)
    resident_down_parser.add_argument("--expected-source-container-id", required=True)
    resident_down_parser.add_argument("--expected-source-image-id", required=True)
    resident_down_parser.add_argument("--expected-resident-image-id", required=True)
    resident_down_parser.add_argument("--expected-resident-container-id", required=True)
    resident_reconcile_parser = cloud_sub.add_parser(
        "resident-reconcile-down",
        parents=[shared],
        help="Prove, adopt, and remove one exact unreceipted listener-only resident",
    )
    resident_reconcile_parser.add_argument("--outage-epoch", required=True)
    resident_reconcile_parser.add_argument("--expected-source-container-id", required=True)
    resident_reconcile_parser.add_argument("--expected-source-image-id", required=True)
    resident_reconcile_parser.add_argument("--expected-resident-image-id", required=True)
    resident_reconcile_parser.add_argument("--expected-resident-container-id", required=True)
    resident_reconcile_parser.add_argument("--expected-resident-command-sha256", required=True)
    resident_reconcile_parser.add_argument("--expected-resident-env-sha256", required=True)
    resident_reconcile_parser.add_argument("--expected-recovery-seed-host-dir", required=True)
    resident_reconcile_parser.add_argument("--expected-recovery-seed-sha256", required=True)
    resident_reconcile_parser.add_argument("--expected-runtime-path", required=True)
    resident_reconcile_parser.add_argument("--expected-runtime-commit", required=True)
    resident_reconcile_parser.add_argument("--expected-runtime-tree", required=True)
    resident_reconcile_parser.add_argument("--expected-runtime-content-sha256", required=True)
    resident_reconcile_parser.add_argument("--expected-runtime-python-path", required=True)
    resident_reconcile_parser.add_argument("--expected-runtime-python-sha256", required=True)
    resident_reconcile_parser.add_argument("--expected-workspace-device", required=True, type=int)
    resident_reconcile_parser.add_argument("--expected-workspace-inode", required=True, type=int)

    quickstart_parser = cloud_sub.add_parser(
        "quickstart",
        parents=[shared],
        help="Create a cloud-ready one-sprint initiative from one brief, preflight it, and optionally launch",
    )
    quickstart_parser.add_argument("--slug", required=True, help="Initiative slug and default cloud session name")
    quickstart_parser.add_argument("--brief", required=True, help="Markdown/text brief to use as the milestone input")
    quickstart_parser.add_argument(
        "--north-star",
        required=True,
        help="Existing North Star markdown/text file to copy into the generated initiative",
    )
    quickstart_parser.add_argument("--title", default=None, help="Human title for README/North Star")
    quickstart_parser.add_argument("--milestone-title", default="First Sprint", help="Milestone title")
    quickstart_parser.add_argument("--base-branch", default=None, help="Base branch (default: current git branch, else main)")
    quickstart_parser.add_argument("--profile", default="partnered-5", help="Megaplan profile for the generated milestone")
    quickstart_parser.add_argument("--vendor", default="codex", help="Vendor for the generated milestone")
    quickstart_parser.add_argument("--depth", default="high", help="Reasoning depth for the generated milestone")
    quickstart_parser.add_argument("--robustness", default="thorough", help="Robustness setting for chain driver/milestone")
    quickstart_parser.add_argument("--branch", default=None, help="Implementation branch (default: slug)")
    quickstart_parser.add_argument("--repo-url", default=None, help="Repo URL (default: inferred from git remote origin)")
    quickstart_parser.add_argument(
        "--target",
        default="hetzner-agentbox",
        choices=("hetzner-agentbox", "custom"),
        help="Cloud target profile. Use custom with --ssh-host for non-default boxes.",
    )
    quickstart_parser.add_argument(
        "--extra-repo",
        action="append",
        default=[],
        metavar="ROLE=URL[@BRANCH[:WORKSPACE]]",
        help=(
            "Add an extra repo checkout to cloud.yaml. Repeatable. Common form: "
            "worker=https://github.com/org/worker.git. Advanced: "
            "worker=https://github.com/org/worker.git@develop:/workspace/custom-worker. "
            "Legacy URL@branch=/workspace/path is also accepted."
        ),
    )
    quickstart_parser.add_argument("--ssh-host", default=None, help="SSH host override")
    quickstart_parser.add_argument("--ssh-user", default="root", help="SSH user")
    quickstart_parser.add_argument("--ssh-port", type=int, default=22, help="SSH port")
    quickstart_parser.add_argument("--engine-ref", default="editible-install", help="Cloud megaplan engine ref")

    quickstart_parser.add_argument(
        "--launch",
        action="store_true",
        help="After writing and preflighting the initiative, start the cloud chain",
    )
    quickstart_parser.add_argument(
        "--fresh",
        "--reset",
        dest="fresh",
        action="store_true",
        help="When launching, reset this chain's remote state first",
    )
    quickstart_parser.add_argument("--force", action="store_true", help="Overwrite generated initiative/cloud files")
    quickstart_parser.add_argument(
        "--skip-remote",
        action="store_true",
        help="Only run local preflight checks; do not SSH to the worker",
    )

    chain_parser = cloud_sub.add_parser(
        "chain",
        parents=[shared],
        help="Upload a chain spec and start it remotely",
    )
    chain_parser.add_argument("spec", help="Local chain spec path")
    chain_parser.add_argument(
        "--on-box",
        action="store_true",
        help="Launch from inside the agentbox without SSH, preserving cloud tmux/marker/watchdog setup",
    )
    chain_parser.add_argument(
        "--idea-dir",
        default=None,
        help="Directory containing local idea files referenced by the chain spec",
    )
    chain_parser.add_argument(
        "--fresh",
        "--reset",
        dest="fresh",
        action="store_true",
        help="Reset this chain's remote state before launch",
    )
    chain_parser.add_argument(
        "--no-git-refresh",
        action="store_true",
        help=(
            "Pass --no-git-refresh to the remote `python -m arnold_pipelines.megaplan chain start`, "
            "skipping the automatic base-branch refresh."
        ),
    )
    chain_parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="Upload and normalize canonical chain inputs without starting a runner.",
    )
    chain_parser.add_argument(
        "--allow-loose-chain-spec",
        action="store_true",
        help=(
            "Allow launching a chain spec outside .megaplan/initiatives/<initiative>/chain.yaml. "
            "Intended only for temporary compatibility."
        ),
    )
    chain_parser.add_argument(
        "--allow-template-placeholders",
        action="store_true",
        help=(
            "Required override to launch even when initiative/cloud files still contain "
            "template placeholders such as TODO_REPO_URL or TODO_SSH_HOST."
        ),
    )
    chain_parser.add_argument(
        "--allow-human-gates",
        action="store_true",
        help=(
            "Required override to launch a cloud chain whose chain.yaml uses "
            "merge_policy != auto or driver.auto_approve: false."
        ),
    )
    _add_repo_override_args(chain_parser)

    sync_parser = cloud_sub.add_parser(
        "sync-megaplan",
        parents=[shared],
        help="Upload durable .megaplan planning artifacts to the cloud workspace",
    )
    sync_parser.add_argument(
        "spec",
        nargs="?",
        help=(
            "Optional local .megaplan/initiatives/<initiative>/chain.yaml. When supplied, "
            "uses the same derived cloud workspace as `cloud chain`."
        ),
    )
    sync_parser.add_argument(
        "--on-box",
        action="store_true",
        help="Sync from inside the agentbox without SSH.",
    )
    sync_parser.add_argument(
        "--workspace",
        default=None,
        help="Explicit remote workspace override. Use only for manual migration.",
    )
    sync_parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove remote durable .megaplan/initiatives, tickets, and ideas before upload.",
    )
    sync_parser.add_argument(
        "--allow-loose-chain-spec",
        action="store_true",
        help="Allow a sync target chain spec outside .megaplan/initiatives/<initiative>/chain.yaml.",
    )
    _add_repo_override_args(sync_parser)

    launch_epic_parser = cloud_sub.add_parser(
        "launch-epic",
        parents=[shared],
        help="Validate, canonicalize, upload, launch, and watchdog-verify a cloud epic",
    )
    launch_epic_parser.add_argument("spec_or_dir", help="Local chain.yaml or epic brief directory")
    launch_epic_parser.add_argument(
        "--on-box",
        action="store_true",
        help="Launch from inside the agentbox without SSH, preserving cloud tmux/marker/watchdog setup",
    )
    launch_epic_parser.add_argument(
        "--slug",
        default=None,
        help="Override the canonical epic slug (default: chain directory name)",
    )
    launch_epic_parser.add_argument(
        "--fresh",
        "--reset",
        dest="fresh",
        action="store_true",
        help="Reset this chain's remote state before launch",
    )
    launch_epic_parser.add_argument(
        "--no-git-refresh",
        action="store_true",
        help="Pass --no-git-refresh to the remote chain start command",
    )
    _add_repo_override_args(launch_epic_parser)

    preflight_parser = cloud_sub.add_parser(
        "preflight",
        parents=[shared],
        help="Validate a cloud chain spec and probe the worker before launch",
    )
    preflight_parser.add_argument("spec", help="Local .megaplan/initiatives/<initiative>/chain.yaml")
    preflight_parser.add_argument(
        "--skip-remote",
        action="store_true",
        help="Only run local spec/profile validation; do not SSH to the worker",
    )
    preflight_parser.add_argument(
        "--allow-loose-chain-spec",
        action="store_true",
        help="Allow a chain spec outside .megaplan/initiatives/<initiative>/chain.yaml.",
    )
    preflight_parser.add_argument(
        "--allow-template-placeholders",
        action="store_true",
        help=(
            "Required override to pass preflight even when initiative/cloud files still "
            "contain template placeholders."
        ),
    )
    preflight_parser.add_argument(
        "--allow-human-gates",
        action="store_true",
        help=(
            "Required override to pass preflight for cloud chains that intentionally "
            "pause for human PR merges or verification gates."
        ),
    )
    _add_repo_override_args(preflight_parser)

    epic_chain_parser = cloud_sub.add_parser(
        "epic-chain",
        parents=[shared],
        help="Upload durable epic-chain inputs and start the parent epic-chain remotely",
    )
    epic_chain_parser.add_argument("spec", help="Local epic-chain spec path")
    epic_chain_parser.add_argument(
        "--fresh",
        "--reset",
        dest="fresh",
        action="store_true",
        help="Reset this parent epic-chain state before launch",
    )
    epic_chain_parser.add_argument(
        "--one",
        action="store_true",
        help="Advance at most one completed child epic, then stop cleanly",
    )
    _add_repo_override_args(epic_chain_parser)

    bootstrap_parser = cloud_sub.add_parser(
        "bootstrap",
        parents=[shared],
        help="Upload an idea file and start arnold init remotely",
    )
    bootstrap_parser.add_argument("idea_file", help="Local idea file path")
    bootstrap_parser.add_argument("--plan-name", default=None, help="Optional remote plan name")
    bootstrap_parser.add_argument("--robustness", default="standard")
    _add_repo_override_args(bootstrap_parser)

    status_parser = cloud_sub.add_parser(
        "status",
        parents=[shared],
        help="Fetch remote `arnold status` JSON",
    )
    status_parser.add_argument(
        "--chain",
        action="store_true",
        help="Fetch remote chain_state.json and render core chain status",
    )
    status_parser.add_argument(
        "--all",
        action="store_true",
        help="List all known cloud sessions from the marker registry with live/health evidence",
    )
    status_parser.add_argument(
        "--compact",
        action="store_true",
        help="With --all, print a compact operator table before the JSON payload",
    )
    status_parser.add_argument(
        "--since",
        default=None,
        help="With --all, filter sessions to real activity since a duration or ISO timestamp, e.g. 12h",
    )
    status_parser.add_argument(
        "--remote-spec",
        default=None,
        help="Explicit remote chain spec path for `cloud status --chain`",
    )
    status_parser.add_argument("--plan", help="Optional plan name to query remotely")

    attach_parser = cloud_sub.add_parser(
        "attach",
        parents=[shared],
        help="Attach to the remote tmux session",
    )
    attach_parser.add_argument(
        "--session",
        help="Override the remote tmux session name for providers that support sessions",
    )

    logs_parser = cloud_sub.add_parser(
        "logs",
        parents=[shared],
        help="Stream or fetch remote logs",
    )
    logs_parser.add_argument(
        "--no-follow",
        action="store_true",
        help="Fetch recent logs without streaming",
    )

    chains_parser = cloud_sub.add_parser(
        "chains",
        parents=[shared],
        help="List active cloud chain tmux sessions on the shared runner",
    )
    chains_parser.add_argument(
        "--compact",
        action="store_true",
        help="Print a compact operator table before the JSON payload",
    )
    chains_parser.add_argument(
        "--since",
        default=None,
        help="Filter sessions to real activity since a duration or ISO timestamp, e.g. 12h",
    )

    exec_parser = cloud_sub.add_parser(
        "exec",
        parents=[shared],
        help="Run an arbitrary remote command",
    )
    exec_parser.add_argument("command", help="Command string to execute remotely")
    exec_parser.add_argument(
        "--on-box",
        action="store_true",
        help="Run inside the current agentbox without bouncing through SSH.",
    )

    resume_parser = cloud_sub.add_parser(
        "resume",
        parents=[shared],
        help="Resume the remote plan's next step",
    )
    resume_parser.add_argument("--plan", help="Optional plan name to resume")

    pause_chain_parser = cloud_sub.add_parser(
        "pause-chain", parents=[shared], help="Durably pause one chain and stop only its runner"
    )
    pause_chain_parser.add_argument("--reason", required=True)
    pause_chain_parser.add_argument("--actor", default="operator")

    resume_chain_parser = cloud_sub.add_parser(
        "resume-chain", parents=[shared], help="Explicitly resume a durably paused chain"
    )
    resume_chain_parser.add_argument("--actor", default="operator")
    resume_chain_parser.add_argument(
        "--no-start",
        action="store_true",
        help="clear pause authority without starting the remote chain runner",
    )

    retire_chain_parser = cloud_sub.add_parser(
        "retire-chain",
        parents=[shared],
        help="Archive and tombstone one exact zero-progress paused chain superseded by a completed chain",
    )
    retire_chain_parser.add_argument("--session", required=True)
    retire_chain_parser.add_argument("--expect-marker-sha256", required=True)
    retire_chain_parser.add_argument("--superseded-by", required=True)
    retire_chain_parser.add_argument("--expect-superseding-marker-sha256", required=True)
    retire_chain_parser.add_argument("--completion-manifest", required=True)
    retire_chain_parser.add_argument("--completion-manifest-sha256", required=True)
    retire_chain_parser.add_argument("--git-repo", required=True)
    retire_chain_parser.add_argument("--base-ref", default="origin/main")
    retire_chain_parser.add_argument("--landed-commit", action="append", required=True)
    retire_chain_parser.add_argument("--reason", required=True)
    retire_chain_parser.add_argument("--actor", default="operator")
    retire_chain_parser.add_argument(
        "--marker-dir", default="/workspace/.megaplan/cloud-sessions"
    )
    retire_chain_parser.add_argument(
        "--on-box",
        action="store_true",
        help="Run against the local agentbox control plane instead of using SSH transport",
    )

    retire_status_parser = cloud_sub.add_parser(
        "retire-stale-status",
        parents=[shared],
        help="Tombstone one exact deleted-workspace marker in the status projection only",
    )
    retire_status_parser.add_argument("--session", required=True)
    retire_status_parser.add_argument("--expect-marker-sha256", required=True)
    retire_status_parser.add_argument("--reason", required=True)
    retire_status_parser.add_argument("--actor", default="operator")
    retire_status_parser.add_argument(
        "--marker-dir", default="/workspace/.megaplan/cloud-sessions"
    )
    retire_status_parser.add_argument(
        "--on-box",
        action="store_true",
        help="Run against the local agentbox control plane instead of using SSH transport",
    )

    cloud_sub.add_parser("down", parents=[shared], help="Pause the deployment without deleting volume")

    supervise_parser = cloud_sub.add_parser(
        "supervise",
        parents=[shared],
        help="Run a one-shot supervisor tick against a cloud chain",
    )
    supervise_parser.add_argument(
        "--chain",
        action="store_true",
        help="Supervise the remote chain (required)",
    )
    supervise_parser.add_argument(
        "--remote-spec",
        default=None,
        help="Explicit remote chain spec path for supervision",
    )
    supervise_parser.add_argument(
        "--on-box",
        action="store_true",
        help="Run the supervisor tick against the local agentbox control plane "
        "instead of using SSH transport",
    )

    destroy_parser = cloud_sub.add_parser(
        "destroy",
        parents=[shared],
        help="Tear down the deployment and delete the volume if configured",
    )
    destroy_parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip the interactive destroy confirmation",
    )


def build_cloud_parser(subparsers: Any) -> None:
    cloud_parser = subparsers.add_parser(
        "cloud",
        help="Manage provider-backed arnold cloud runners",
    )
    _register_cloud_subcommands(cloud_parser)


def _add_repo_override_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo-url", default=None, help="Override cloud.yaml repo.url in memory")
    parser.add_argument("--repo-branch", default=None, help="Override cloud.yaml repo.branch in memory")
    parser.add_argument("--repo-workspace", default=None, help="Override cloud.yaml repo.workspace in memory")


def run_cloud_cli(root: Path, args: argparse.Namespace) -> int:
    try:
        action = getattr(args, "cloud_action")
        selected_cloud = (
            Path(args.cloud_yaml).expanduser()
            if getattr(args, "cloud_yaml", None)
            else root / "cloud.yaml"
        )
        if action == "init":
            canonical_zero_recovery_cloud = (
                root
                / ".megaplan/initiatives/critique-ledger-safe-v3-canary/cloud.yaml"
            ).resolve()
            if selected_cloud.resolve() == canonical_zero_recovery_cloud:
                raise CliError(
                    "zero_recovery_action_denied",
                    "cloud init cannot create or overwrite the canonical zero-recovery profile",
                )
            if selected_cloud.is_file():
                try:
                    existing_spec = _load_cloud_spec(root, args)
                except CliError:
                    existing_spec = None
                if existing_spec is not None:
                    if existing_spec.zero_recovery_canary:
                        raise CliError(
                            "zero_recovery_action_denied",
                            "cloud init cannot overwrite an admitted zero-recovery profile",
                        )
                    if existing_spec.isolated_chain_runner:
                        raise CliError(
                            "isolated_chain_runner_action_denied",
                            "cloud init cannot overwrite an isolated chain-runner profile",
                        )
            return _run_init(root, args)
        early_spec: CloudSpec | None = None
        if selected_cloud.is_file():
            early_spec = _load_cloud_spec(root, args)
            if (
                early_spec.zero_recovery_canary
                and action not in _ZERO_RECOVERY_CLOUD_ACTIONS
            ):
                raise CliError(
                    "zero_recovery_action_denied",
                    f"cloud {action} is not available in the zero-recovery profile",
                )
            if (
                early_spec.isolated_chain_runner
                and action not in _ISOLATED_CHAIN_RUNNER_CLOUD_ACTIONS
            ):
                raise CliError(
                    "isolated_chain_runner_action_denied",
                    f"cloud {action} is not available in the isolated chain-runner profile",
                )
        if action == "quickstart":
            return _run_quickstart(root, args)

        if action == "retire-chain" and bool(getattr(args, "on_box", False)):
            return _run_session_retirement(args)
        if action == "retire-stale-status" and bool(getattr(args, "on_box", False)):
            return _run_status_retirement(args)

        spec = early_spec or _load_cloud_spec(root, args)
        if spec.zero_recovery_canary and action not in _ZERO_RECOVERY_CLOUD_ACTIONS:
            raise CliError(
                "zero_recovery_action_denied",
                f"cloud {action} is not available in the zero-recovery profile",
            )
        if (
            spec.isolated_chain_runner
            and action not in _ISOLATED_CHAIN_RUNNER_CLOUD_ACTIONS
        ):
            raise CliError(
                "isolated_chain_runner_action_denied",
                f"cloud {action} is not available in the isolated chain-runner profile",
            )
        if spec.isolated_chain_runner:
            if (
                action in _ISOLATED_CHAIN_RUNNER_PIN_REQUIRED_ACTIONS
                and spec.isolated_chain_runner_image_id is None
            ):
                raise CliError(
                    "isolated_chain_runner_image_pin_required",
                    f"cloud {action} requires isolated_chain_runner_image_id: sha256:<64 hex>",
                )
            if action in {"chain", "sync-megaplan"} and bool(
                getattr(args, "on_box", False)
            ):
                raise CliError(
                    "isolated_chain_runner_action_denied",
                    f"cloud {action} --on-box bypasses the isolated SSH launch boundary",
                )
            if (
                action == "chain"
                and not bool(getattr(args, "prepare_only", False))
                and not bool(getattr(args, "fresh", False))
            ):
                raise CliError(
                    "isolated_chain_runner_fresh_required",
                    "isolated cloud chain launches require --fresh",
                )
        canary_admission: dict[str, Any] | None = None
        if spec.zero_recovery_canary:
            raw_canary_spec = getattr(args, "canary_spec", None) or (
                ".megaplan/initiatives/critique-ledger-safe-v3-canary/canary.yaml"
            )
            canary_admission = _validate_zero_recovery_canary_spec(
                root, raw_canary_spec, getattr(args, "cloud_yaml", None), spec
            )
        provider = _provider_for_action(spec, args)
        if spec.isolated_chain_runner and (
            action in {"chain", "sync-megaplan", "status", "logs", "chains"}
            or (action == "preflight" and not bool(getattr(args, "skip_remote", False)))
        ):
            attest_runtime = getattr(
                provider, "attest_isolated_chain_runner_runtime", None
            )
            if attest_runtime is None:
                raise CliError(
                    "isolated_chain_runner_attestation_unavailable",
                    "provider lacks isolated chain-runner runtime attestation",
                )
            attest_runtime()

        if action == "chain":
            with _materialized_deploy_dir(spec):
                return _run_chain_wrapper(root, args, spec, provider)

        if action == "sync-megaplan":
            return _run_sync_megaplan(root, args, spec, provider)

        if action == "launch-epic":
            with _materialized_deploy_dir(spec):
                return _run_launch_epic_wrapper(root, args, spec, provider)

        if action == "preflight":
            return _run_preflight(root, args, spec, provider)

        if action == "epic-chain":
            with _materialized_deploy_dir(spec):
                return _run_epic_chain_wrapper(root, args, spec, provider)

        if action == "bootstrap":
            with _materialized_deploy_dir(spec):
                return _run_bootstrap_wrapper(args, spec, provider)

        if action == "build":
            with _materialized_deploy_dir(spec) as deploy_dir:
                return provider.build(deploy_dir)

        if action == "capacity-inventory":
            if spec.provider != "ssh":
                raise CliError(
                    "capacity_inventory_unavailable",
                    "host capacity inventory is only available for the SSH provider",
                )
            observe = getattr(provider, "observe_capacity_inventory", None)
            if observe is None:
                raise CliError(
                    "capacity_inventory_unavailable",
                    "SSH provider does not expose the fixed capacity inventory",
                )
            payload = observe()
            sys.stdout.write(json.dumps(payload, indent=2) + "\n")
            return 0 if payload.get("status") == "available" else 1

        if action == "reclaim-dangling-build-cache":
            if spec.provider != "ssh" or not spec.zero_recovery_canary:
                raise CliError(
                    "zero_recovery_bootstrap_invalid",
                    "bootstrap reclaim requires SSH zero_recovery_canary=true",
                )
            prepare = getattr(provider, "prepare_zero_recovery_bootstrap_reclaim", None)
            if prepare is None:
                raise CliError(
                    "zero_recovery_bootstrap_invalid",
                    "SSH provider does not expose bootstrap reclaim",
                )
            proposal = prepare()
            if getattr(args, "apply", False):
                apply_reclaim = getattr(
                    provider, "apply_zero_recovery_bootstrap_reclaim", None
                )
                if apply_reclaim is None:
                    raise CliError(
                        "zero_recovery_bootstrap_invalid",
                        "SSH provider does not expose bootstrap reclaim",
                    )
                payload = apply_reclaim(proposal)
            else:
                payload = proposal
            sys.stdout.write(json.dumps(payload, indent=2) + "\n")
            return 0

        if action == "run-zero-recovery-canary":
            auth_path = Path.home() / ".codex" / "auth.json"
            try:
                auth_payload = auth_path.read_text(encoding="utf-8")

                def reject_auth_duplicates(
                    pairs: list[tuple[str, Any]],
                ) -> dict[str, Any]:
                    result: dict[str, Any] = {}
                    for key, value in pairs:
                        if key in result:
                            raise ValueError(f"duplicate auth field: {key}")
                        result[key] = value
                    return result

                parsed_auth = json.loads(
                    auth_payload, object_pairs_hook=reject_auth_duplicates
                )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise CliError(
                    "zero_recovery_auth_unavailable",
                    "a readable strict ~/.codex/auth.json is required",
                ) from exc
            if (
                spec.megaplan.codex_auth != "chatgpt"
                or not isinstance(parsed_auth, dict)
                or parsed_auth.get("auth_mode") != "chatgpt"
            ):
                raise CliError(
                    "zero_recovery_auth_invalid",
                    "finite canary permits only Codex ChatGPT OAuth",
                )
            execute_canary = getattr(provider, "execute_zero_recovery_canary", None)
            if execute_canary is None or canary_admission is None:
                raise CliError(
                    "zero_recovery_canary_unavailable",
                    "provider lacks the fixed finite-canary route",
                )
            return execute_canary(
                auth_payload,
                source_commit=canary_admission["_admission_source_commit"],
                source_tree=canary_admission["_admission_source_tree"],
                manifest_sha256=canary_admission["_admission_manifest_sha256"],
            )

        if action == "zero-recovery-canary-status":
            read_status = getattr(provider, "zero_recovery_canary_status", None)
            if read_status is None:
                raise CliError(
                    "zero_recovery_canary_unavailable",
                    "provider lacks the fixed finite-canary status route",
                )
            if canary_admission is None:
                raise CliError(
                    "zero_recovery_canary_unavailable", "canary admission is required"
                )
            status_payload = read_status(
                source_commit=canary_admission["_admission_source_commit"],
                source_tree=canary_admission["_admission_source_tree"],
            )
            sys.stdout.write(json.dumps(status_payload, indent=2) + "\n")
            return (
                0
                if status_payload.get("status") in {"available", "in_progress"}
                else 1
            )

        if action == "zero-recovery-preflight":
            prepare = getattr(
                provider, "prepare_zero_recovery_predeploy_transaction", None
            )
            if prepare is None:
                raise CliError(
                    "zero_recovery_predeploy_invalid",
                    "provider lacks zero-recovery preflight",
                )
            sys.stdout.write(json.dumps(prepare(), indent=2) + "\n")
            return 0

        if action == "resident-recover":
            if spec.provider != "ssh":
                raise CliError(
                    "resident_recovery_unavailable",
                    "resident-only recovery is available only through the SSH provider",
                )
            recover = getattr(provider, "resident_recover", None)
            if recover is None:
                raise CliError(
                    "resident_recovery_unavailable",
                    "SSH provider does not expose resident-only recovery",
                )
            payload = recover(
                outage_epoch=args.outage_epoch,
                expected_source_container_id=args.expected_source_container_id,
                expected_source_image_id=args.expected_source_image_id,
                expected_resident_image_id=args.expected_resident_image_id,
                expected_runtime_path=args.expected_runtime_path,
                expected_runtime_commit=args.expected_runtime_commit,
                expected_runtime_tree=args.expected_runtime_tree,
                expected_runtime_python_path=args.expected_runtime_python_path,
                expected_runtime_python_sha256=args.expected_runtime_python_sha256,
                health_timeout_seconds=args.health_timeout_seconds,
            )
            sys.stdout.write(json.dumps(payload, indent=2) + "\n")
            return 0 if payload.get("status") == "healthy" else 1

        if action == "resident-down":
            if spec.provider != "ssh":
                raise CliError(
                    "resident_down_unavailable",
                    "resident-only down is available only through the SSH provider",
                )
            down = getattr(provider, "resident_down", None)
            if down is None:
                raise CliError(
                    "resident_down_unavailable",
                    "SSH provider does not expose resident-only down",
                )
            payload = down(
                outage_epoch=args.outage_epoch,
                expected_source_container_id=args.expected_source_container_id,
                expected_source_image_id=args.expected_source_image_id,
                expected_resident_image_id=args.expected_resident_image_id,
                expected_resident_container_id=args.expected_resident_container_id,
            )
            sys.stdout.write(json.dumps(payload, indent=2) + "\n")
            return 0

        if action == "resident-reconcile-down":
            if spec.provider != "ssh":
                raise CliError(
                    "resident_reconcile_unavailable",
                    "resident reconciliation is available only through the SSH provider",
                )
            reconcile = getattr(provider, "resident_reconcile_down", None)
            if reconcile is None:
                raise CliError(
                    "resident_reconcile_unavailable",
                    "SSH provider does not expose resident reconciliation",
                )
            payload = reconcile(
                outage_epoch=args.outage_epoch,
                expected_source_container_id=args.expected_source_container_id,
                expected_source_image_id=args.expected_source_image_id,
                expected_resident_image_id=args.expected_resident_image_id,
                expected_resident_container_id=args.expected_resident_container_id,
                expected_resident_command_sha256=args.expected_resident_command_sha256,
                expected_resident_env_sha256=args.expected_resident_env_sha256,
                expected_recovery_seed_host_dir=args.expected_recovery_seed_host_dir,
                expected_recovery_seed_sha256=args.expected_recovery_seed_sha256,
                expected_runtime_path=args.expected_runtime_path,
                expected_runtime_commit=args.expected_runtime_commit,
                expected_runtime_tree=args.expected_runtime_tree,
                expected_runtime_content_sha256=args.expected_runtime_content_sha256,
                expected_runtime_python_path=args.expected_runtime_python_path,
                expected_runtime_python_sha256=args.expected_runtime_python_sha256,
                expected_workspace_device=args.expected_workspace_device,
                expected_workspace_inode=args.expected_workspace_inode,
            )
            sys.stdout.write(json.dumps(payload, indent=2) + "\n")
            return 0

        if action == "deploy":
            secrets = {name: os.environ.get(name, "") for name in spec.secrets}
            with _materialized_deploy_dir(spec) as deploy_dir:
                if spec.zero_recovery_canary:
                    prepare = getattr(
                        provider, "prepare_zero_recovery_predeploy_transaction", None
                    )
                    if prepare is None:
                        raise CliError(
                            "zero_recovery_predeploy_unavailable",
                            "provider cannot produce a zero-recovery predeploy transaction",
                        )
                    transaction = prepare()
                    result = provider.deploy(
                        deploy_dir,
                        secrets=secrets,
                        predeploy_transaction=transaction,
                    )
                else:
                    result = provider.deploy(deploy_dir, secrets=secrets)
                report = _coerce_deploy_report(result, spec=spec, deploy_dir=deploy_dir)
                report.steps = [
                    *_deploy_context_steps(deploy_dir),
                    *report.steps,
                ]
            if report.exit_code == 0 and not spec.zero_recovery_canary:
                seed_messages: list[str] = []
                seed_result = seed_codex_oauth(spec, provider, writer=seed_messages.append)
                report.steps.append(
                    DeployStepReport(
                        name="seed Codex OAuth",
                        status="ok",
                        detail=_oauth_seed_detail(seed_result),
                        stderr="".join(seed_messages),
                        metadata=seed_result,
                    )
                )
                if spec.isolated_chain_runner:
                    git_seed_messages: list[str] = []
                    git_seed_result = seed_isolated_git_credentials(
                        spec,
                        provider,
                        required=False,
                        writer=git_seed_messages.append,
                    )
                    report.steps.append(
                        DeployStepReport(
                            name="seed isolated Git auth",
                            status="ok",
                            detail=_oauth_seed_detail(git_seed_result),
                            stderr="".join(git_seed_messages),
                            metadata=git_seed_result,
                        )
                    )
            _emit_deploy_report(report, secret_names=spec.secrets, env=os.environ)
            return report.exit_code

        if action == "status":
            if bool(getattr(args, "all", False)):
                return _run_status_all(spec, provider, args=args)
            if _status_should_use_chain(root, args, spec):
                return _run_chain_status(root, args, spec, provider)
            payload = cloud_status_payload(args, spec, provider)
            sys.stdout.write(json.dumps(payload, indent=2) + "\n")
            return 0

        if action == "attach":
            return provider.attach()

        if action == "logs":
            return provider.logs(follow=not bool(getattr(args, "no_follow", False)))

        if action == "chains":
            return _run_cloud_chains(spec, provider, args=args)

        if action == "exec":
            result = provider.ssh_exec(args.command)
            _relay_output(result, secret_names=spec.secrets, env=os.environ)
            return 0

        if action == "resume":
            resume_workspace = _resolve_resume_workspace(root, args, spec, provider)
            payload = provider.status_payload(
                plan=getattr(args, "plan", None),
                workspace=resume_workspace,
            )
            next_step = payload.get("next_step")
            if not isinstance(next_step, str) or not next_step:
                raise CliError("invalid_status", "Remote status did not include a next_step")
            plan_name = getattr(args, "plan", None)
            if payload.get("state") == "failed" and isinstance(plan_name, str) and plan_name:
                argv = ["resume", "--plan", plan_name]
            else:
                from arnold_pipelines.megaplan.auto import _phase_command

                argv = list(_phase_command(next_step, substrate=cloud_substrate))
                if plan_name:
                    argv.extend(["--plan", plan_name])
            command = (
                f"if [ -f {shlex.quote(_CLOUD_HOT_ENV_PATH)} ]; then "
                f"set -a; . {shlex.quote(_CLOUD_HOT_ENV_PATH)}; set +a; fi; "
                f"cd {shlex.quote(resume_workspace)} && "
                f"{megaplan_runtime_invocation(spec)} {shlex.join(argv)}"
            )
            result = provider.ssh_exec(command)
            _relay_output(result, secret_names=spec.secrets, env=os.environ)
            return 0

        if action in {"pause-chain", "resume-chain"}:
            marker = _load_marker(root, args)
            if not isinstance(marker, dict):
                raise CliError("missing_marker", "No canonical last-chain marker is available")
            workspace = str(marker.get("workspace") or "").strip()
            remote_spec = str(marker.get("remote_spec") or "").strip()
            session = str(marker.get("chain_session") or marker.get("session") or "").strip()
            marker_path = str(marker.get("marker_path") or "").strip()
            if not marker_path and session:
                marker_path = str(PurePosixPath(_CHAIN_SESSION_MARKER_DIR) / f"{session}.json")
            if not all((workspace, remote_spec, session, marker_path)):
                raise CliError("invalid_marker", "Chain marker lacks workspace/spec/session custody")
            argv = [
                "python3", "-P", "-m", "arnold_pipelines.megaplan.cloud.operator_control",
                "pause" if action == "pause-chain" else "resume",
                "--spec", remote_spec, "--workspace", workspace,
                "--session", session, "--marker", marker_path,
                "--actor", str(getattr(args, "actor", None) or "operator"),
            ]
            if action == "pause-chain":
                argv.extend(["--reason", str(args.reason)])
            elif bool(getattr(args, "no_start", False)):
                argv.append("--no-start")
            result = provider.ssh_exec(shlex.join(argv))
            _relay_output(result, secret_names=spec.secrets, env=os.environ)
            return result.returncode

        if action == "retire-chain":
            command = shlex.join(
                [
                    "python3",
                    "-P",
                    "-m",
                    "arnold_pipelines.megaplan.cloud.session_retirement",
                    *_session_retirement_argv(args),
                ]
            )
            result = provider.ssh_exec(command)
            _relay_output(result, secret_names=spec.secrets, env=os.environ)
            return result.returncode

        if action == "retire-stale-status":
            command = shlex.join(
                [
                    "python3",
                    "-P",
                    "-m",
                    "arnold_pipelines.megaplan.cloud.status_retirement",
                    *_status_retirement_argv(args),
                ]
            )
            result = provider.ssh_exec(command)
            _relay_output(result, secret_names=spec.secrets, env=os.environ)
            return result.returncode

        if action == "down":
            return provider.down()

        if action == "supervise":
            if bool(getattr(args, "chain", False)):
                return _run_supervise_tick(root, args, spec, provider)
            raise CliError(
                "invalid_args",
                "`cloud supervise` requires --chain. Try `arnold cloud supervise --chain`.",
            )

        if action == "destroy":
            if not bool(getattr(args, "yes", False)) and not _confirm_destroy(spec):
                return 1
            result = provider.destroy(volume=spec.resources.volume)
            _clear_persistent_deploy_dir(spec)
            return result

        raise CliError("invalid_args", f"Unknown cloud action: {action}")
    except CliError as exc:
        return _emit_error(exc)


def _session_retirement_argv(args: argparse.Namespace) -> list[str]:
    argv = [
        "--marker-dir",
        str(args.marker_dir),
        "--session",
        str(args.session),
        "--expect-marker-sha256",
        str(args.expect_marker_sha256),
        "--superseded-by",
        str(args.superseded_by),
        "--expect-superseding-marker-sha256",
        str(args.expect_superseding_marker_sha256),
        "--completion-manifest",
        str(args.completion_manifest),
        "--completion-manifest-sha256",
        str(args.completion_manifest_sha256),
        "--git-repo",
        str(args.git_repo),
        "--base-ref",
        str(args.base_ref),
        "--reason",
        str(args.reason),
        "--actor",
        str(args.actor),
    ]
    for commit in args.landed_commit:
        argv.extend(["--landed-commit", str(commit)])
    return argv


def _run_session_retirement(args: argparse.Namespace) -> int:
    from arnold_pipelines.megaplan.cloud.session_retirement import main

    return main(_session_retirement_argv(args))


def _status_retirement_argv(args: argparse.Namespace) -> list[str]:
    return [
        "--marker-dir",
        str(args.marker_dir),
        "--session",
        str(args.session),
        "--expect-marker-sha256",
        str(args.expect_marker_sha256),
        "--reason",
        str(args.reason),
        "--actor",
        str(args.actor),
    ]


def _run_status_retirement(args: argparse.Namespace) -> int:
    from arnold_pipelines.megaplan.cloud.status_retirement import main

    return main(_status_retirement_argv(args))


def _cloud_yaml_path(root: Path, args: argparse.Namespace) -> Path:
    raw = getattr(args, "cloud_yaml", None)
    if not raw:
        return root / "cloud.yaml"
    return Path(raw).expanduser().resolve()


def _load_cloud_spec(root: Path, args: argparse.Namespace) -> CloudSpec:
    spec = load_spec(_cloud_yaml_path(root, args))
    return apply_repo_overrides(
        spec,
        repo_url=getattr(args, "repo_url", None),
        repo_branch=getattr(args, "repo_branch", None),
        repo_workspace=getattr(args, "repo_workspace", None),
    )


def _status_should_use_chain(root: Path, args: argparse.Namespace, spec: CloudSpec) -> bool:
    if bool(getattr(args, "chain", False)):
        return True
    if getattr(args, "remote_spec", None):
        return True
    if spec.mode == "chain" and spec.chain is not None:
        return True
    marker_path = _marker_path_no_create(_cloud_yaml_path(root, args)) / "last_chain.json"
    try:
        return marker_path.exists()
    except OSError:
        return False


def _provider_for_action(spec: CloudSpec, args: argparse.Namespace):
    if bool(getattr(args, "on_box", False)):
        action = getattr(args, "cloud_action", None)
        if action not in {"chain", "exec", "launch-epic", "sync-megaplan", "supervise"}:
            raise CliError(
                "invalid_args",
                "--on-box is supported only for cloud chain, exec, launch-epic, "
                "sync-megaplan, and supervise",
            )
        from arnold_pipelines.megaplan.cloud.providers.on_box import OnBoxProvider

        return OnBoxProvider(spec)
    # Gate session overrides on provider capability, not on a provider-name special case.
    base_provider = get_provider(spec.provider, spec)
    session_name = getattr(args, "session", None)
    if not session_name:
        return base_provider
    raise CliError("invalid_args", "--session override is not supported by configured providers")


def _ensure_repo_command(spec: CloudSpec) -> str:
    # Clone the primary repo AND every declared `extra_repos` sibling. The
    # container entrypoint clones the full set at boot, but boot only runs once
    # per `cloud deploy`. A `cloud chain` launched against a container that
    # pre-dates an `extra_repos` edit would otherwise silently leave siblings
    # missing on the persistent volume, blocking any milestone that depends on
    # them.
    return render_ensure_repos_block(spec)


def _repo_requires_on_box_git_auth(repo: Any) -> bool:
    """Return whether a repository declaration targets authenticated GitHub.

    This decision is made from the structured URL after the same user-info
    sanitization used by the rendered checkout command.  It intentionally
    handles credentials and an explicit port, while avoiding any inspection
    of arbitrary shell text.
    """
    sanitized = _sanitise_git_url(str(getattr(repo, "url", "")).strip())
    if sanitized.lower().startswith("git@github.com:"):
        return True
    try:
        parsed = urlsplit(sanitized)
        hostname = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    return parsed.scheme.lower() in {"https", "ssh"} and hostname == "github.com"


def _ensure_repo_checkout(spec: CloudSpec, provider, *, relay: bool = True) -> None:
    command = _ensure_repo_command(spec)
    # Repository URLs are structured configuration, so the authenticated Git
    # boundary is selected from the repo declarations rather than by scanning
    # the rendered shell command (which may contain comments, JSON, or
    # wrapper code). Local/file clones retain normal stdout and do not require
    # the AgentBox credential helper.
    repos = [spec.repo, *spec.extra_repos]
    requires_git_auth = any(_repo_requires_on_box_git_auth(repo) for repo in repos)
    if requires_git_auth:
        result = provider.git_auth_exec(command)
    else:
        result = provider.ssh_exec(command)
    if relay:
        _relay_output(result, secret_names=spec.secrets, env=os.environ)
    if result.returncode != 0:
        repos = [spec.repo, *spec.extra_repos]
        targets = ", ".join(
            f"{_sanitise_git_url(r.url)}@{r.branch} into {r.workspace}" for r in repos
        )
        raise CliError(
            "provider_failed",
            f"ensure repo checkout failed for {targets} (exit {result.returncode})",
        )


def _run_init(root: Path, args: argparse.Namespace) -> int:
    target = _cloud_yaml_path(root, args)
    if target.exists() and not bool(getattr(args, "force", False)):
        raise CliError(
            "invalid_args",
            f"cloud spec already exists: {target}. Use --force to overwrite.",
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    template = resources.files("arnold_pipelines.megaplan.cloud.templates").joinpath("cloud.yaml.tmpl")
    target.write_text(template.read_text(encoding="utf-8"), encoding="utf-8")
    sys.stdout.write(json.dumps({"success": True, "cloud_yaml": str(target)}, indent=2) + "\n")
    return 0


_CLOUD_TARGETS: dict[str, dict[str, Any]] = {
    "hetzner-agentbox": {
        "provider": "ssh",
        "ssh": {
            "host_env": "MEGAPLAN_CLOUD_SSH_HOST",
            "host": "159.69.51.216",
            "user": "root",
            "port": 22,
            "remote_dir": "/opt/megaplan-cloud/deploy",
            "workspace_dir": "/opt/megaplan-cloud/workspace",
            "container": "megaplan-cloud-agent",
        },
    }
}


def _git_stdout(root: Path, args: list[str]) -> str | None:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    value = (proc.stdout or "").strip()
    return value or None


def _normalise_git_url(url: str) -> str:
    if url.startswith("git@github.com:"):
        return "https://github.com/" + url.removeprefix("git@github.com:")
    if url.startswith("ssh://git@github.com/"):
        return "https://github.com/" + url.removeprefix("ssh://git@github.com/")
    return url


def _infer_repo_url(root: Path, explicit: str | None) -> str:
    if explicit:
        return explicit
    inferred = _git_stdout(root, ["config", "--get", "remote.origin.url"])
    if not inferred:
        raise CliError(
            "quickstart_missing_repo_url",
            "Could not infer repo URL from git remote origin. Pass --repo-url.",
        )
    return _normalise_git_url(inferred)


def _infer_base_branch(root: Path, explicit: str | None) -> str:
    if explicit:
        return explicit
    return _git_stdout(root, ["branch", "--show-current"]) or "main"


def _quickstart_target_ssh(args: argparse.Namespace) -> dict[str, Any]:
    if args.target == "custom" and not args.ssh_host:
        raise CliError("invalid_args", "--target custom requires --ssh-host")
    target = _CLOUD_TARGETS.get(args.target, {})
    ssh = dict(target.get("ssh") or {})
    env_name = ssh.pop("host_env", None)
    host = args.ssh_host or (os.environ.get(env_name) if env_name else None) or ssh.get("host")
    if not host:
        raise CliError("invalid_args", f"target {args.target!r} has no SSH host; pass --ssh-host")
    return {
        "host": host,
        "user": args.ssh_user or ssh.get("user") or "root",
        "port": args.ssh_port or ssh.get("port") or 22,
        "remote_dir": ssh.get("remote_dir") or "/opt/megaplan-cloud/deploy",
        "workspace_dir": ssh.get("workspace_dir") or "/opt/megaplan-cloud/workspace",
        "container": ssh.get("container") or "megaplan-cloud-agent",
    }


def _split_repo_url_branch(raw_url: str, *, default_branch: str) -> tuple[str, str]:
    url = raw_url.strip()
    branch = default_branch
    at_index = url.rfind("@")
    if at_index > 0 and "/" not in url[at_index:]:
        branch = url[at_index + 1 :] or default_branch
        url = url[:at_index]
    return _normalise_git_url(url), branch


def _parse_quickstart_extra_repo(raw: str, *, slug: str, default_branch: str) -> dict[str, str]:
    value = raw.strip()
    if "=" not in value:
        raise CliError(
            "invalid_args",
            "--extra-repo must be formatted as ROLE=URL[@BRANCH[:WORKSPACE]]",
        )
    left, right = value.split("=", 1)
    left = left.strip()
    right = right.strip()
    if not left or not right:
        raise CliError(
            "invalid_args",
            "--extra-repo must include a non-empty role/URL and repo URL/workspace",
        )

    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", left):
        role = _slugify_chain_identity(left)
        url_part = right
        workspace = f"/workspace/{slug}/{role}"
        colon_index = right.rfind(":")
        scheme_index = right.find("://")
        if colon_index > 0 and right[colon_index + 1 :].startswith("/") and colon_index != scheme_index:
            url_part = right[:colon_index]
            workspace = right[colon_index + 1 :]
        url, branch = _split_repo_url_branch(url_part, default_branch=default_branch)
    else:
        url, branch = _split_repo_url_branch(left, default_branch=default_branch)
        workspace = right

    if not PurePosixPath(workspace).is_absolute():
        raise CliError("invalid_args", f"--extra-repo workspace must be absolute: {workspace}")
    return {"url": url, "branch": branch, "workspace": workspace}


def _write_text_once(path: Path, text: str, *, force: bool, written: list[str], reused: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        reused.append(str(path))
        return
    path.write_text(text.rstrip() + "\n", encoding="utf-8")
    written.append(str(path))


def _call_cloud_step_quietly(func, *call_args) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            rc = int(func(*call_args) or 0)
    except CliError:
        captured_out = stdout.getvalue()
        captured_err = stderr.getvalue()
        if captured_out:
            sys.stdout.write(captured_out)
        if captured_err:
            sys.stderr.write(captured_err)
        raise
    return rc, stdout.getvalue(), stderr.getvalue()


def _json_from_captured_stdout(text: str) -> dict[str, Any] | None:
    decoder = json.JSONDecoder()
    idx = 0
    last: dict[str, Any] | None = None
    while idx < len(text):
        while idx < len(text) and text[idx].isspace():
            idx += 1
        if idx >= len(text):
            break
        try:
            value, end = decoder.raw_decode(text, idx)
        except json.JSONDecodeError:
            break
        if isinstance(value, dict):
            last = value
        idx = end
    return last


def _run_quickstart(root: Path, args: argparse.Namespace) -> int:
    slug = _slugify_chain_identity(str(args.slug))
    if not slug:
        raise CliError("invalid_args", "--slug must contain at least one alphanumeric character")
    brief_source = Path(args.brief).expanduser().resolve()
    if not brief_source.is_file():
        raise CliError("invalid_args", f"--brief does not exist or is not a file: {brief_source}")
    north_star_source = Path(args.north_star).expanduser().resolve()
    if not north_star_source.is_file():
        raise CliError("invalid_args", f"--north-star does not exist or is not a file: {north_star_source}")

    brief_text = brief_source.read_text(encoding="utf-8")
    north_star_text = north_star_source.read_text(encoding="utf-8")
    title = (args.title or slug.replace("-", " ").title()).strip()
    base_branch = _infer_base_branch(root, args.base_branch)
    repo_url = _infer_repo_url(root, args.repo_url)
    ssh = _quickstart_target_ssh(args)
    initiative = root / ".megaplan" / "initiatives" / slug
    cloud_yaml = Path(args.cloud_yaml).expanduser().resolve() if args.cloud_yaml else initiative / "cloud.yaml"
    chain_path = initiative / "chain.yaml"
    milestone_label = f"m1-{slug}"
    milestone_path = initiative / "briefs" / f"{milestone_label}.md"
    branch = args.branch or slug
    written: list[str] = []
    reused: list[str] = []

    readme = f"# {title}\n\nCloud quickstart initiative generated from `{brief_source}`.\n"
    milestone = "\n".join(
        [
            f"# {args.milestone_title}",
            "",
            "This milestone was generated by `megaplan cloud quickstart` from the source brief below.",
            "",
            "## Source Brief",
            "",
            brief_text.rstrip(),
        ]
    )
    chain_payload = {
        "base_branch": base_branch,
        "anchors": {"north_star": "NORTHSTAR.md"},
        "milestones": [
            {
                "label": milestone_label,
                "idea": f".megaplan/initiatives/{slug}/briefs/{milestone_label}.md",
                "profile": args.profile,
                "vendor": args.vendor,
                "robustness": args.robustness,
                "depth": args.depth,
                "branch": branch,
                "prep_clarify": False,
            }
        ],
        "on_failure": {"abort": "stop_chain"},
        "on_escalate": {"abort": "stop_chain"},
        "merge_policy": "auto",
        "driver": {
            "robustness": args.robustness,
            "auto_approve": True,
            "max_iterations": 24,
            "poll_sleep": 8.0,
        },
    }
    workspace = f"/workspace/{slug}/{_repo_dir_name(repo_url)}"
    extra_repos = [
        _parse_quickstart_extra_repo(raw, slug=slug, default_branch=base_branch)
        for raw in (args.extra_repo or [])
    ]
    cloud_payload: dict[str, Any] = {
        "provider": "ssh",
        "repo": {"url": repo_url, "branch": base_branch, "workspace": workspace},
        "agents": {"default": args.vendor},
        "codex": {"model": "gpt-5.6-sol", "reasoning": args.depth},
        "chain_session": slug,
        "mode": "idle",
        "chain": {"spec": f"{workspace}/.megaplan/initiatives/{slug}/chain.yaml"},
        "megaplan": {
            "ref": args.engine_ref,
            "codex_auth": "chatgpt",
            "repo": "https://github.com/peteromallet/Arnold.git",
            "src_path": "/workspace/arnold",
        },
        "resources": {"volume": "agent-volume", "port": 8080},
        "ssh": ssh,
        "secrets": [],
    }
    if extra_repos:
        cloud_payload["extra_repos"] = extra_repos

    force = bool(args.force)
    _write_text_once(initiative / "README.md", readme, force=force, written=written, reused=reused)
    _write_text_once(initiative / "NORTHSTAR.md", north_star_text, force=force, written=written, reused=reused)
    _write_text_once(milestone_path, milestone, force=force, written=written, reused=reused)
    _write_text_once(chain_path, yaml.safe_dump(chain_payload, sort_keys=False), force=force, written=written, reused=reused)
    _write_text_once(cloud_yaml, yaml.safe_dump(cloud_payload, sort_keys=False), force=force, written=written, reused=reused)

    preflight_args = argparse.Namespace(
        cloud_yaml=str(cloud_yaml),
        spec=str(chain_path),
        skip_remote=bool(args.skip_remote),
        allow_loose_chain_spec=False,
        allow_template_placeholders=False,
        allow_human_gates=False,
        repo_url=None,
        repo_branch=None,
        repo_workspace=None,
    )
    spec = _load_cloud_spec(root, preflight_args)
    provider = _provider_for_action(spec, preflight_args)
    preflight_rc, preflight_stdout, preflight_stderr = _call_cloud_step_quietly(
        _run_preflight,
        root,
        preflight_args,
        spec,
        provider,
    )
    if preflight_rc != 0:
        if preflight_stdout:
            sys.stdout.write(preflight_stdout)
        if preflight_stderr:
            sys.stderr.write(preflight_stderr)
        return preflight_rc
    preflight_payload = _json_from_captured_stdout(preflight_stdout) or {}

    launch_payload: dict[str, Any] | None = None
    if bool(args.launch):
        chain_args = argparse.Namespace(
            cloud_yaml=str(cloud_yaml),
            spec=str(chain_path),
            idea_dir=None,
            fresh=bool(args.fresh),
            no_git_refresh=False,
            allow_loose_chain_spec=False,
            allow_template_placeholders=False,
            allow_human_gates=False,
            repo_url=None,
            repo_branch=None,
            repo_workspace=None,
            _canonicalized_epic=True,
            _generated_canonical_files=[],
        )
        with _materialized_deploy_dir(spec):
            rc, launch_stdout, launch_stderr = _call_cloud_step_quietly(
                _run_chain_wrapper,
                root,
                chain_args,
                spec,
                provider,
            )
        if rc != 0:
            if launch_stdout:
                sys.stdout.write(launch_stdout)
            if launch_stderr:
                sys.stderr.write(launch_stderr)
            return rc
        launch_provenance = _json_from_captured_stdout(launch_stdout) or {}
        log_payload = launch_provenance.get("log")
        verification = launch_provenance.get("verification")
        launch_payload = {
            "launched": True,
            "session": slug,
            "workspace": workspace,
            "spec": f"{workspace}/.megaplan/initiatives/{slug}/chain.yaml",
            "chain_log": log_payload.get("chain_log") if isinstance(log_payload, dict) else None,
            "verification": verification if isinstance(verification, dict) else None,
        }

    remote_payload = preflight_payload.get("remote") if isinstance(preflight_payload.get("remote"), dict) else {}
    payload = {
        "success": True,
        "event": "cloud_quickstart",
        "initiative": str(initiative),
        "chain": str(chain_path),
        "cloud_yaml": str(cloud_yaml),
        "milestone": str(milestone_path),
        "written": written,
        "reused": reused,
        "preflight": {
            "success": bool(preflight_payload.get("success", True)),
            "expected_workspace": remote_payload.get("expected_workspace", workspace),
            "expected_session": remote_payload.get("expected_session", slug),
            "warnings": preflight_payload.get("warnings", []),
        },
        "launch": launch_payload
        or {
            "launched": False,
            "next": (
                "Rerun with --launch, or run "
                f"python -m arnold_pipelines.megaplan cloud chain {chain_path} "
                f"--cloud-yaml {cloud_yaml} --fresh"
            ),
        },
    }
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    return 0


def _relative_remote_path(*, workspace: str, remote_path: str) -> Path:
    remote = PurePosixPath(remote_path)
    workspace_path = PurePosixPath(workspace)
    if remote == workspace_path:
        return Path()
    elif str(remote).startswith(f"{workspace_path}/"):
        return Path(*remote.relative_to(workspace_path).parts)
    elif remote.is_absolute():
        return Path(*remote.parts[1:])
    return Path(*remote.parts)


def _append_unique_path(paths: list[Path], candidate: Path) -> None:
    if candidate not in paths:
        paths.append(candidate)


def _local_idea_source_candidates(*, root: Path, idea_dir: Path, workspace: str, remote_path: str) -> list[Path]:
    relative_remote = _relative_remote_path(workspace=workspace, remote_path=remote_path)
    candidates: list[Path] = []
    _append_unique_path(candidates, idea_dir / relative_remote)
    _append_unique_path(candidates, root / relative_remote)

    try:
        idea_dir_tail = idea_dir.relative_to(root)
    except ValueError:
        idea_dir_tail = None
    if idea_dir_tail is not None:
        try:
            deduped_tail = relative_remote.relative_to(idea_dir_tail)
        except ValueError:
            deduped_tail = None
        if deduped_tail is not None:
            _append_unique_path(candidates, idea_dir / deduped_tail)

    remote = PurePosixPath(remote_path)
    if remote.is_absolute() and not str(remote).startswith(f"{PurePosixPath(workspace)}/"):
        _append_unique_path(candidates, idea_dir / remote.name)
    return candidates


def _resolve_local_idea_source(*, root: Path, idea_dir: Path, workspace: str, remote_path: str) -> tuple[Path | None, list[Path]]:
    candidates = _local_idea_source_candidates(root=root, idea_dir=idea_dir, workspace=workspace, remote_path=remote_path)
    for candidate in candidates:
        if candidate.exists():
            return candidate, candidates
    return None, candidates


def _read_chain_yaml(path: Path) -> dict[str, Any]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return raw if isinstance(raw, dict) else {}


def _chain_spec_has_explicit_base_branch(path: Path) -> bool:
    return "base_branch" in _read_chain_yaml(path)


def _rewrite_remote_workspace_path(remote_path: str, *, source_workspace: str, target_workspace: str) -> str:
    source = PurePosixPath(source_workspace)
    target = PurePosixPath(target_workspace)
    path = PurePosixPath(remote_path)
    if path == source:
        return str(target)
    if path.is_absolute() and str(path).startswith(f"{source}/"):
        return str(target / path.relative_to(source))
    return remote_path


def _remote_chain_upload_path(remote_path: str, *, source_workspace: str, target_workspace: str) -> str:
    rewritten = _rewrite_remote_workspace_path(
        remote_path,
        source_workspace=source_workspace,
        target_workspace=target_workspace,
    )
    path = PurePosixPath(rewritten)
    if path.is_absolute():
        return str(path)
    return str(PurePosixPath(target_workspace) / path)


def _remote_chain_anchor_upload_path(anchor_path: str, *, remote_spec_path: str) -> str:
    path = PurePosixPath(anchor_path)
    if path.is_absolute():
        return str(path)
    return str(PurePosixPath(remote_spec_path).parent / path)


def _append_unique_upload(uploads: list[tuple[Path, str]], local_source: Path, remote_path: str) -> None:
    item = (local_source, remote_path)
    if item not in uploads:
        uploads.append(item)


def _chain_anchor_uploads(local_spec_path: Path, remote_spec_path: str, chain_spec: Any) -> list[tuple[Path, str]]:
    from arnold_pipelines.megaplan.anchors import resolve_anchor_path

    uploads: list[tuple[Path, str]] = []
    top_anchor = getattr(getattr(chain_spec, "anchors", None), "north_star", None)
    if isinstance(top_anchor, str) and top_anchor:
        _append_unique_upload(
            uploads,
            resolve_anchor_path(local_spec_path, top_anchor),
            _remote_chain_anchor_upload_path(top_anchor, remote_spec_path=remote_spec_path),
        )
    for milestone in getattr(chain_spec, "milestones", []):
        milestone_anchor = getattr(getattr(milestone, "anchors", None), "north_star", None)
        if isinstance(milestone_anchor, str) and milestone_anchor:
            _append_unique_upload(
                uploads,
                resolve_anchor_path(local_spec_path, milestone_anchor),
                _remote_chain_anchor_upload_path(milestone_anchor, remote_spec_path=remote_spec_path),
            )
    return uploads


def _git_repo_root(path: Path) -> Path | None:
    """Best-effort git toplevel for the repo containing ``path``."""
    import subprocess
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(path.parent if path.is_file() else path),
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    if proc.returncode != 0:
        return None
    top = proc.stdout.strip()
    return Path(top).resolve() if top else None


def _chain_project_root(local_spec_path: Path, fallback_root: Path) -> Path:
    """Return the app/project root that owns a local chain spec.

    Cloud commands are often invoked through an Arnold checkout while the chain
    spec lives in a different application repository.  Chain idea paths are
    project-relative, so validation and upload source resolution must use the
    spec's repository root, not the caller's current working directory.
    """
    return _git_repo_root(local_spec_path) or fallback_root.expanduser().resolve()


def _validate_chain_spec_location(
    local_spec_path: Path,
    project_root: Path,
    *,
    allow_loose: bool = False,
) -> None:
    """Require durable chain specs to live under .megaplan/initiatives/<initiative>/.

    Cloud launches upload the spec and its idea files into a long-lived remote
    checkout. Keeping the local source in the durable initiatives tree is what
    makes the remote copy auditable instead of another loose cloud-only artifact.
    """
    if allow_loose:
        return
    try:
        relative = local_spec_path.expanduser().resolve().relative_to(
            project_root.expanduser().resolve()
        )
    except ValueError as exc:
        raise CliError(
            "chain_spec_outside_project",
            (
                f"chain spec {local_spec_path} is outside project root {project_root}. "
                "Move it under .megaplan/initiatives/<initiative>/chain.yaml or pass "
                "--allow-loose-chain-spec for a temporary compatibility launch."
            ),
        ) from exc
    if is_canonical_chain_spec(local_spec_path, project_root):
        return
    raise CliError(
        "chain_spec_layout_violation",
        (
            "cloud chain specs must live at "
            ".megaplan/initiatives/<initiative>/chain.yaml; got "
            f"{relative.as_posix()}. Move the chain and milestone briefs into "
            "that durable initiative folder or pass --allow-loose-chain-spec "
            "for a temporary compatibility launch."
        ),
        extra={"chain_spec": relative.as_posix()},
    )


def _remote_chain_workspace_path(local_path: Path, *, local_root: Path, target_workspace: str) -> str:
    path = local_path.expanduser().resolve()
    root = local_root.expanduser().resolve()
    relative: PurePosixPath | None = None
    try:
        relative = PurePosixPath(path.relative_to(root))
    except ValueError:
        relative = None
    # local_root isn't always the spec's repo root (it can be a cloud cache dir
    # or a project dir that doesn't contain the spec). Fall back to the spec's
    # OWN git repo root so the spec lands at its repo-relative path on the box —
    # this keeps the chain spec, its north_star anchor, and idea files at the
    # same relative paths, so chain.yaml-dir-relative anchor resolution works
    # identically locally and remotely. Bare path.name is the last resort.
    if relative is None:
        git_root = _git_repo_root(path)
        if git_root is not None:
            try:
                relative = PurePosixPath(path.relative_to(git_root))
            except ValueError:
                relative = None
    if relative is None:
        return str(PurePosixPath(target_workspace) / path.name)
    return str(PurePosixPath(target_workspace).joinpath(*relative.parts))


def _normalized_chain_upload_spec(
    local_spec_path: Path,
    *,
    base_branch: str,
    source_workspace: str | None = None,
    target_workspace: str | None = None,
    driver_overrides: dict[str, Any] | None = None,
    phase_model_by_label: dict[str, list[str]] | None = None,
) -> Path:
    raw = _read_chain_yaml(local_spec_path)
    workspace_changed = (
        bool(source_workspace)
        and bool(target_workspace)
        and source_workspace != target_workspace
    )
    if (
        "base_branch" in raw
        and not workspace_changed
        and not driver_overrides
        and not phase_model_by_label
    ):
        return local_spec_path
    normalized = dict(raw)
    if "base_branch" not in normalized:
        normalized["base_branch"] = base_branch
    if driver_overrides:
        driver = normalized.get("driver")
        driver_mapping = dict(driver) if isinstance(driver, dict) else {}
        driver_mapping.update(driver_overrides)
        normalized["driver"] = driver_mapping
    if (workspace_changed or phase_model_by_label) and isinstance(normalized.get("milestones"), list):
        rewritten: list[Any] = []
        for item in normalized["milestones"]:
            if isinstance(item, dict):
                copied = dict(item)
                if workspace_changed and isinstance(copied.get("idea"), str):
                    copied["idea"] = _rewrite_remote_workspace_path(
                        copied["idea"],
                        source_workspace=source_workspace or "",
                        target_workspace=target_workspace or "",
                    )
                if phase_model_by_label and isinstance(copied.get("label"), str):
                    phase_models = phase_model_by_label.get(copied["label"])
                    if phase_models:
                        copied["phase_model"] = list(phase_models)
                rewritten.append(copied)
            else:
                rewritten.append(item)
        normalized["milestones"] = rewritten
    with NamedTemporaryFile("w", suffix=".yaml", encoding="utf-8", delete=False) as handle:
        yaml.safe_dump(normalized, handle, sort_keys=False)
        return Path(handle.name)


def _missing_configured_secrets(spec: CloudSpec, env: dict[str, str]) -> list[str]:
    return sorted(name for name in spec.secrets if not env.get(name))


def _remote_dependency_check_command(commands: list[str]) -> str:
    quoted_commands = " ".join(shlex.quote(command) for command in commands)
    return (
        "missing=''; "
        f"for cmd in {quoted_commands}; do "
        'if ! command -v "$cmd" >/dev/null 2>&1; then missing="$missing $cmd"; fi; '
        "done; "
        'printf "%s\\n" "$missing"'
    )


def _run_remote_dependency_check(provider, commands: list[str]) -> list[str]:
    if not commands:
        return []
    result = provider.ssh_exec(_remote_dependency_check_command(commands))
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "remote dependency check failed").strip()
        raise CliError("provider_failed", message)
    return sorted({part for part in result.stdout.split() if part})


def _remote_megaplan_import_check_command() -> str:
    script = """
import importlib.util, json

def present(name):
    try:
        return importlib.util.find_spec(name) is not None
    except Exception as exc:
        return {"error": str(exc)}

checks = {
    "arnold_pipelines.megaplan": present("arnold_pipelines.megaplan"),
    "arnold_pipelines.megaplan.cli": present("arnold_pipelines.megaplan.cli"),
    "arnold.pipelines.megaplan": present("arnold.pipelines.megaplan"),
}
errors = []
if checks["arnold_pipelines.megaplan"] is not True:
    errors.append("missing modern arnold_pipelines.megaplan import")
if checks["arnold_pipelines.megaplan.cli"] is not True:
    errors.append("missing modern arnold_pipelines.megaplan.cli import")
print(json.dumps({"checks": checks, "errors": errors}, sort_keys=True))
raise SystemExit(1 if errors else 0)
"""
    return f"python3 - <<'MEGAPLAN_IMPORT_CHECK'\n{script.strip()}\nMEGAPLAN_IMPORT_CHECK"


def _run_remote_megaplan_import_check(provider) -> dict[str, Any]:
    result = provider.ssh_exec(_remote_megaplan_import_check_command())
    raw = (result.stdout or "").strip().splitlines()
    try:
        payload = json.loads(raw[-1] if raw else "{}")
    except json.JSONDecodeError as exc:
        payload = {
            "checks": {},
            "errors": [f"import check output was not JSON: {exc}"],
            "raw": result.stdout,
        }
    if result.returncode != 0:
        payload.setdefault("errors", [])
        if result.stderr:
            payload["errors"].append(result.stderr.strip())
    payload["status"] = "ok" if not payload.get("errors") else "failed"
    return payload


def _provider_container_observation(provider) -> dict[str, Any] | None:
    method = getattr(provider, "observe_container", None)
    if method is None:
        return None
    try:
        payload = method()
    except (CliError, OSError, ValueError) as exc:
        return {
            "schema": "arnold.cloud.ssh_container_observation.v1",
            "status": "unknown",
            "lifecycle": "unknown",
            "collector": {"status": "unavailable", "reason": "container_state_unknown"},
            "diagnostic": str(exc),
        }
    if not isinstance(payload, dict):
        return {
            "schema": "arnold.cloud.ssh_container_observation.v1",
            "status": "unknown",
            "lifecycle": "unknown",
            "collector": {"status": "unavailable", "reason": "container_state_unknown"},
            "diagnostic": "provider returned a non-object container observation",
        }
    return payload


def _provider_prelaunch_capacity(provider) -> dict[str, Any]:
    method = getattr(provider, "observe_prelaunch_capacity", None)
    if method is None:
        return {
            "schema": "arnold.cloud.ssh_workspace_prelaunch.v1",
            "status": "unknown",
            "verdict": "NO-GO",
            "errors": ["provider_prelaunch_capacity_observer_unavailable"],
        }
    try:
        payload = method()
    except (CliError, OSError, ValueError) as exc:
        return {
            "schema": "arnold.cloud.ssh_workspace_prelaunch.v1",
            "status": "unknown",
            "verdict": "NO-GO",
            "errors": [str(exc)],
        }
    if not isinstance(payload, dict):
        return {
            "schema": "arnold.cloud.ssh_workspace_prelaunch.v1",
            "status": "unknown",
            "verdict": "NO-GO",
            "errors": ["provider returned a non-object capacity observation"],
        }
    return payload


def _container_collector_ready(observation: Mapping[str, Any] | None) -> bool:
    if not isinstance(observation, Mapping):
        return False
    collector = observation.get("collector")
    return (
        observation.get("status") == "available"
        and observation.get("lifecycle") == "running"
        and isinstance(collector, Mapping)
        and collector.get("status") == "available"
    )


def _collector_unavailable_error(
    observation: Mapping[str, Any],
    *,
    capacity: Mapping[str, Any] | None = None,
) -> CliError:
    lifecycle = str(observation.get("lifecycle") or "unknown")
    return CliError(
        "provider_collector_unavailable",
        f"container lifecycle is {lifecycle}; docker-exec collector is unavailable",
        extra={
            "container_observation": dict(observation),
            **(
                {"prelaunch_capacity": dict(capacity)}
                if isinstance(capacity, Mapping)
                else {}
            ),
        },
    )


def _cloud_profile_warnings(preflight_summary: Mapping[str, Any], spec: CloudSpec) -> list[str]:
    warnings: list[str] = []
    required_agents = {
        str(agent)
        for agent in preflight_summary.get("required_agents", [])
        if isinstance(agent, str)
    }
    configured_secrets = set(spec.secrets)
    if "claude" in required_agents or "shannon" in required_agents:
        if "ANTHROPIC_API_KEY" not in configured_secrets:
            warnings.append(
                "resolved chain routing includes Claude/Shannon phases. "
                "Codex-only cloud workers should use profile partnered-codex or explicit codex phase_model pins; "
                "mixed profiles need Claude CLI/auth and ANTHROPIC_API_KEY available on the worker."
            )
    if required_agents == {"codex"}:
        warnings.append("resolved chain routing is Codex-only; this is compatible with partnered-codex cloud workers.")
    return warnings


def _phase_model_by_label_from_preflight(preflight_summary: Mapping[str, Any]) -> dict[str, list[str]]:
    """Return phase pins that must be materialized in the uploaded chain spec.

    Cloud chain launch may resolve routing from cloud-only defaults such as
    ``agents.default``. The remote ``chain start`` process only sees the
    uploaded chain YAML, so the resolved routing must be materialized into that
    temporary upload spec or init can fall back to a different local default.

    Do not materialize resolved profile routes for profiled milestones. Profiles
    can carry ``tier_models.execute``/``tier_models.critique`` tables; flattening
    their resolved phase map into ``phase_model`` erases adaptive per-batch
    routing and pins execute to one model.
    """
    phase_model_by_label: dict[str, list[str]] = {}
    for milestone in preflight_summary.get("milestones", []):
        if not isinstance(milestone, Mapping):
            continue
        label = milestone.get("label")
        profile = milestone.get("profile")
        explicit = milestone.get("explicit_phase_model")
        resolved_phase_chains = milestone.get("resolved_phase_chains")
        if isinstance(profile, str) and profile:
            if (
                isinstance(label, str)
                and isinstance(explicit, list)
                and all(isinstance(item, str) for item in explicit)
                and explicit
            ):
                phase_model_by_label[label] = list(explicit)
            continue
        resolved = milestone.get("resolved_phase_map")
        if not isinstance(label, str):
            continue
        phase_models: list[str] = []
        explicit_steps: set[str] = set()
        if isinstance(explicit, list) and all(isinstance(item, str) for item in explicit):
            for entry in explicit:
                if "=" not in entry:
                    continue
                phase, _chain = decode_phase_model_value(entry)
                explicit_steps.add(phase)
                phase_models.append(entry)
        if isinstance(resolved_phase_chains, Mapping):
            for phase, specs in resolved_phase_chains.items():
                if not isinstance(phase, str) or phase in explicit_steps:
                    continue
                if not isinstance(specs, list) or not all(isinstance(item, str) for item in specs) or not specs:
                    continue
                phase_models.append(encode_phase_model_value(phase, specs))
        elif isinstance(resolved, Mapping):
            for phase, spec in resolved.items():
                if isinstance(phase, str) and isinstance(spec, str) and phase and spec and phase not in explicit_steps:
                    phase_models.append(f"{phase}={spec}")
        if phase_models:
            phase_model_by_label[label] = phase_models
    return phase_model_by_label


def _remote_repo_head(provider, workspace: str) -> dict[str, str | None]:
    command = (
        f"git -C {shlex.quote(workspace)} rev-parse --abbrev-ref HEAD 2>/dev/null && "
        f"git -C {shlex.quote(workspace)} rev-parse HEAD 2>/dev/null"
    )
    result = provider.ssh_exec(command)
    if result.returncode != 0:
        return {"branch": None, "head": None}
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return {
        "branch": lines[0] if len(lines) >= 1 else None,
        "head": lines[1] if len(lines) >= 2 else None,
    }


def _remote_chain_sessions(provider) -> list[dict[str, Any]]:
    result = provider.ssh_exec(_cloud_chains_command())
    if result.returncode != 0:
        return []
    try:
        payload = json.loads((result.stdout or "").strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        return []
    sessions = payload.get("sessions") if isinstance(payload, dict) else None
    return [item for item in sessions if isinstance(item, dict)] if isinstance(sessions, list) else []


def _chain_state_for_remote_spec(provider, remote_spec: str):
    from arnold_pipelines.megaplan.chain import epic_chain as epic_chain_module

    state_path = chain_module._state_path_for(Path(remote_spec))
    return chain_module.ChainState.from_dict(json.loads(provider.read_remote_file(str(state_path))))


def _workspace_from_chain_marker(
    spec: CloudSpec,
    marker: Mapping[str, Any],
    provider,
    *,
    plan: str | None,
) -> str | None:
    remote_spec = marker.get("remote_spec")
    workspace = marker.get("workspace")
    if not isinstance(remote_spec, str) or not remote_spec:
        return workspace if isinstance(workspace, str) and workspace.strip() else None
    try:
        chain_state = _chain_state_for_remote_spec(provider, remote_spec)
    except Exception:
        return workspace if isinstance(workspace, str) and workspace.strip() else None
    if plan and chain_state.current_plan_name != plan:
        return None
    ctx = _resolve_chain_execution_context(spec, chain_state, dict(marker), remote_spec)
    resolved = ctx.get("workspace")
    return resolved if isinstance(resolved, str) and resolved.strip() else None


def _resolve_resume_workspace(root: Path, args: argparse.Namespace, spec: CloudSpec, provider) -> str:
    """Resolve the workspace for ``cloud resume``.

    Chain launches can derive a per-chain workspace even when cloud.yaml keeps
    the default ``repo.workspace``. Prefer the local last-chain marker, then
    remote chain session markers, and fall back to the static spec workspace.
    """
    plan = getattr(args, "plan", None)
    marker = _load_marker(root, args)
    if marker:
        workspace = _workspace_from_chain_marker(spec, marker, provider, plan=plan)
        if workspace:
            return workspace

    if plan:
        for session in _remote_chain_sessions(provider):
            workspace = _workspace_from_chain_marker(spec, session, provider, plan=plan)
            if workspace:
                return workspace

    return spec.repo.workspace


def _git_run(
    root: Path,
    args: list[str],
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )
    if check and proc.returncode != 0:
        raise CliError(
            "git_command_failed",
            f"git {' '.join(args)} failed: {(proc.stderr or proc.stdout or '').strip()}",
            extra={
                "command": ["git", *args],
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
            },
        )
    return proc


def _tmux_launch_status(result, *, session_name: str = "megaplan-chain") -> str:
    output = f"{getattr(result, 'stdout', '')}\n{getattr(result, 'stderr', '')}"
    if "already running" in output:
        return "already_running"
    if f"started {session_name} session" in output:
        return "started"
    return "unknown"


def _resolved_phase_map_summary(preflight_summary: dict[str, Any]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for milestone in preflight_summary.get("milestones", []):
        if not isinstance(milestone, dict):
            continue
        summaries.append(
            {
                "label": milestone.get("label"),
                "profile": milestone.get("profile"),
                "explicit_phase_model": milestone.get("explicit_phase_model", []),
                "resolved_phase_map": milestone.get("resolved_phase_map", {}),
                "required_agents": milestone.get("required_agents", []),
                "runtime_commands": milestone.get("runtime_commands", []),
                "env_hints": milestone.get("env_hints", []),
                "provider_requirements": milestone.get("provider_requirements", []),
            }
        )
    return summaries


def _cloud_chain_launch_provenance(
    *,
    spec: CloudSpec,
    ctx: ChainLaunchContext,
    chain_spec,
    preflight_summary: dict[str, Any],
    uploaded_idea_count: int,
    repo_head: dict[str, str | None],
    tmux_result,
    engine_ref_check: dict[str, Any] | None = None,
    verification: dict[str, Any] | None = None,
) -> dict[str, Any]:
    current_milestone = chain_spec.milestones[0].label if chain_spec.milestones else None
    payload = {
        "success": True,
        "event": "cloud_chain_launched",
        "remote_spec": ctx.remote_spec_path,
        "current_milestone": current_milestone,
        "plan_name": None,
        "pr_number": None,
        "repo": {
            "url": spec.repo.url,
            "branch": spec.repo.branch,
            "workspace": ctx.workspace,
            "head": repo_head.get("head"),
            "checked_out_branch": repo_head.get("branch"),
        },
        "chain": {
            "base_branch": chain_spec.base_branch,
            "milestone_count": len(chain_spec.milestones),
            "resolved_phase_map_summary": _resolved_phase_map_summary(preflight_summary),
            "prerequisite_policy": chain_spec.prerequisite_policy,
            "validation_policy": chain_spec.validation_policy,
            "review_policy": dict(chain_spec.review_policy or {}),
        },
        "megaplan": {
            "ref": spec.megaplan.ref,
            "install_source": "cloud_image_runtime",
            "engine_ref_check": engine_ref_check or {"status": "unknown"},
        },
        "uploaded_idea_count": uploaded_idea_count,
        "tmux": {
            "session": ctx.session_name,
            "status": _tmux_launch_status(tmux_result, session_name=ctx.session_name),
        },
        "log": {"chain_log": ctx.log_path},
        "launch": {
            "identity_digest": ctx.digest,
            "session_marker": ctx.marker_path,
            "derived_workspace": not spec.repo.workspace_explicit,
            "derived_session": not spec.chain_session_explicit,
        },
        "verification": verification or {},
    }
    from arnold_pipelines.megaplan.resident.provenance import safe_provenance_projection

    resident_delegation = safe_provenance_projection()
    if resident_delegation is not None:
        payload["resident_delegation"] = resident_delegation
    return payload


# ---------------------------------------------------------------------------
# Shared chain command helper — canonical session / log / env / quoting
# ---------------------------------------------------------------------------

CHAIN_SESSION_NAME = "megaplan-chain"
_CHAIN_LOG_RELATIVE = ".megaplan/cloud-chain.log"
_CLOUD_HOT_ENV_PATH = "/workspace/.cloud-hot-env"
_CHAIN_SESSION_MARKER_DIR = "/workspace/.megaplan/cloud-sessions"
_CHAIN_VERIFY_ATTEMPTS = 6
_CHAIN_VERIFY_SLEEP_SECONDS = 5
_LAUNCH_BOUNDARY_PATH = "/usr/local/bin/arnold-launch-boundary"


@dataclass(frozen=True)
class ChainLaunchContext:
    identity: str
    slug: str
    digest: str
    workspace: str
    remote_spec_path: str
    session_name: str
    log_relative: str
    log_path: str
    state_path: str
    marker_path: str


def _operation_base_dir_for_workspace(workspace: str) -> str | None:
    """Return the operation root for an explicit box workspace.

    AgentBox mounts one shared ``/workspace`` volume, so the unique project
    workspace's parent is the smallest supported isolation boundary for
    runtime manifests, markers, runtime candidates, and probe evidence.
    Local/non-box paths intentionally retain their historical defaults.
    """
    path = PurePosixPath(str(workspace or "").strip())
    if not path.is_absolute() or len(path.parts) < 4 or path.parts[1] != "workspace":
        return None
    return str(path.parent)


def _operation_manifest_dir_for_workspace(workspace: str) -> str | None:
    base = _operation_base_dir_for_workspace(workspace)
    return f"{base}/.megaplan" if base else None


def _operation_marker_dir_for_workspace(workspace: str) -> str:
    return (
        f"{_operation_manifest_dir_for_workspace(workspace)}/cloud-sessions"
        if _operation_manifest_dir_for_workspace(workspace)
        else _CHAIN_SESSION_MARKER_DIR
    )


def _slugify_chain_identity(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip().lower()).strip(".-")
    return slug[:48] or "chain"


def _repo_dir_name(repo_url: str) -> str:
    tail = repo_url.rstrip("/").rsplit("/", 1)[-1] or "app"
    if tail.endswith(".git"):
        tail = tail[:-4]
    return _slugify_chain_identity(tail) or "app"


def _epic_slug_for_spec_path(local_spec_path: Path) -> str:
    if local_spec_path.name == "chain.yaml" and local_spec_path.parent.name:
        return _slugify_chain_identity(local_spec_path.parent.name)
    return _slugify_chain_identity(local_spec_path.stem)


def _chain_identity_for(local_spec_path: Path, chain_spec: Any) -> tuple[str, str, str]:
    labels = ",".join(m.label for m in getattr(chain_spec, "milestones", []) if getattr(m, "label", None))
    seed = getattr(chain_spec, "seed_plan", None) or ""
    slug = _epic_slug_for_spec_path(local_spec_path)
    identity = f"{slug}:{seed}:{labels}"
    digest = hashlib.sha1(identity.encode("utf-8")).hexdigest()[:10]
    return identity, slug, digest


@dataclass(frozen=True)
class CanonicalEpicMaterialization:
    spec_path: Path
    project_root: Path
    slug: str
    brief_dir: Path
    copied_files: list[str]
    created_files: list[str]
    generated_chain: bool


def _copy_if_different(src: Path, dest: Path) -> bool:
    src = src.expanduser().resolve()
    dest = dest.expanduser().resolve()
    if src == dest:
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    return True


def _resolve_chain_local_artifact(
    raw_path: str,
    *,
    project_root: Path,
    spec_dir: Path,
) -> Path:
    path = Path(raw_path).expanduser()
    candidates = [path] if path.is_absolute() else [project_root / path, spec_dir / path]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    tried = "\n".join(f"- {candidate}" for candidate in candidates)
    raise CliError(
        "missing_epic_artifact",
        f"required chain artifact not found: {raw_path}\nTried:\n{tried}",
        extra={"missing_artifact": raw_path, "tried_paths": [str(candidate) for candidate in candidates]},
    )


def _milestone_label_from_brief(path: Path) -> str:
    return _slugify_chain_identity(path.stem)


def _brief_markdown_files(directory: Path) -> list[Path]:
    excluded = {"northstar.md", "north_star.md", "readme.md", "goal.md"}
    files = [
        path
        for path in directory.glob("*.md")
        if path.name.lower() not in excluded and path.is_file()
    ]
    return sorted(files, key=lambda item: item.name)


def _default_generated_chain_yaml(
    *,
    slug: str,
    base_branch: str,
    brief_names: list[str],
) -> dict[str, Any]:
    return {
        "base_branch": base_branch,
        "anchors": {"north_star": "NORTHSTAR.md"},
        "milestones": [
            {
                "label": _milestone_label_from_brief(Path(name)),
                "idea": f".megaplan/initiatives/{slug}/briefs/{name}",
                "branch": f"epic/{slug}/{_milestone_label_from_brief(Path(name))}",
                "vendor": "codex",
                "depth": "high",
                "robustness": "full",
                "with_prep": True,
            }
            for name in brief_names
        ],
        "on_failure": {"abort": "stop_chain"},
        "on_escalate": {"abort": "stop_chain"},
        "merge_policy": "auto",
        "driver": {
            "robustness": "full",
            "auto_approve": True,
            "max_iterations": 80,
            "poll_sleep": 8.0,
        },
    }


def _materialize_canonical_epic_input(
    *,
    root: Path,
    spec: CloudSpec,
    spec_or_dir: str,
    slug_override: str | None = None,
) -> CanonicalEpicMaterialization:
    source = Path(spec_or_dir).expanduser().resolve()
    if not source.exists():
        raise CliError("missing_epic_artifact", f"epic input not found: {source}")

    source_dir = source if source.is_dir() else source.parent
    source_spec = source if source.is_file() else source_dir / "chain.yaml"
    slug_source = slug_override or (source_dir.name if source_spec.name == "chain.yaml" else source_spec.stem)
    slug = _slugify_chain_identity(slug_source)
    if not slug:
        raise CliError("invalid_epic_slug", f"unable to derive epic slug from {source}")

    project_root = _chain_project_root(source_spec if source_spec.exists() else source_dir, root)
    # A canonical initiative is already the reviewed source of truth.  Do not
    # rewrite it as part of launch canonicalization: even a semantically
    # equivalent YAML dump changes bytes and makes the source-bound runtime
    # guard reject the checkout.  Require canonical bytes up front and fail
    # closed before mkdir/copy/write side effects when they drift.
    source_is_canonical = source_spec.exists() and is_canonical_chain_spec(source_spec, project_root)
    if source_is_canonical:
        source_raw = _read_chain_yaml(source_spec)
        canonical_text = yaml.safe_dump(source_raw, sort_keys=False)
        source_text = source_spec.read_text(encoding="utf-8")
        if source_text != canonical_text:
            raise CliError(
                "chain_spec_not_canonical",
                (
                    "canonical chain source has non-canonical YAML bytes; "
                    "format it in a separate working copy before launch"
                ),
                extra={"spec": str(source_spec)},
            )
    canonical_dir = project_root / ".megaplan" / "initiatives" / slug
    canonical_brief_dir = canonical_dir / "briefs"
    canonical_dir.mkdir(parents=True, exist_ok=True)
    canonical_brief_dir.mkdir(parents=True, exist_ok=True)

    copied: list[str] = []
    created: list[str] = []
    generated_chain = False

    if source_spec.exists():
        raw = _read_chain_yaml(source_spec)
        anchors = raw.get("anchors")
        if not isinstance(anchors, dict) or not isinstance(anchors.get("north_star"), str) or not anchors["north_star"].strip():
            raise CliError(
                "missing_north_star",
                "chain.yaml must declare anchors.north_star: NORTHSTAR.md for cloud launch",
                extra={"spec": str(source_spec)},
            )
        north_source = _resolve_chain_local_artifact(
            anchors["north_star"],
            project_root=project_root,
            spec_dir=source_spec.parent,
        )
        if north_source.name != "NORTHSTAR.md":
            north_dest = canonical_dir / "NORTHSTAR.md"
        else:
            north_dest = canonical_dir / north_source.name
        north_existed = north_dest.exists()
        if not source_is_canonical and _copy_if_different(north_source, north_dest):
            copied.append(str(north_dest))
            if not north_existed:
                created.append(str(north_dest))
        raw = dict(raw)
        raw["anchors"] = {"north_star": "NORTHSTAR.md"}
        milestones = raw.get("milestones")
        if not isinstance(milestones, list) or not milestones:
            raise CliError("missing_epic_artifact", "chain.yaml must contain at least one milestone")
        rewritten: list[Any] = []
        seen_dest_names: set[str] = set()
        for idx, item in enumerate(milestones):
            if not isinstance(item, dict):
                raise CliError("invalid_spec", f"milestones[{idx}] must be a mapping")
            idea = item.get("idea")
            if not isinstance(idea, str) or not idea.strip():
                raise CliError("invalid_spec", f"milestones[{idx}].idea is required")
            idea_source = _resolve_chain_local_artifact(
                idea,
                project_root=project_root,
                spec_dir=source_spec.parent,
            )
            dest_name = idea_source.name
            if dest_name in seen_dest_names:
                dest_name = f"{idx + 1:02d}-{dest_name}"
            seen_dest_names.add(dest_name)
            idea_dest = canonical_brief_dir / dest_name
            idea_existed = idea_dest.exists()
            if not source_is_canonical and _copy_if_different(idea_source, idea_dest):
                copied.append(str(idea_dest))
                if not idea_existed:
                    created.append(str(idea_dest))
            copied_item = dict(item)
            copied_item["idea"] = f".megaplan/initiatives/{slug}/briefs/{dest_name}"
            rewritten.append(copied_item)
        raw["milestones"] = rewritten
    else:
        north_source = source_dir / "NORTHSTAR.md"
        if not north_source.is_file():
            raise CliError(
                "missing_north_star",
                f"epic directory must contain NORTHSTAR.md before launch: {source_dir}",
                extra={"missing_artifact": str(north_source)},
            )
        north_dest = canonical_dir / "NORTHSTAR.md"
        north_existed = north_dest.exists()
        if _copy_if_different(north_source, north_dest):
            copied.append(str(north_dest))
            if not north_existed:
                created.append(str(north_dest))
        briefs = _brief_markdown_files(source_dir)
        if not briefs:
            raise CliError(
                "missing_epic_artifact",
                f"epic directory has no milestone markdown briefs: {source_dir}",
            )
        brief_names: list[str] = []
        for brief in briefs:
            dest = canonical_brief_dir / brief.name
            dest_existed = dest.exists()
            if _copy_if_different(brief, dest):
                copied.append(str(dest))
                if not dest_existed:
                    created.append(str(dest))
            brief_names.append(brief.name)
        raw = _default_generated_chain_yaml(
            slug=slug,
            base_branch=spec.repo.branch,
            brief_names=brief_names,
        )
        generated_chain = True

    canonical_spec = source_spec if source_is_canonical else canonical_dir / "chain.yaml"
    if source_is_canonical:
        # The bytes were checked above.  Reuse the path without writing it.
        return CanonicalEpicMaterialization(
            spec_path=canonical_spec,
            project_root=project_root,
            slug=slug,
            brief_dir=canonical_dir,
            copied_files=[],
            created_files=[],
            generated_chain=False,
        )
    canonical_spec_existed = canonical_spec.exists()
    canonical_spec.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    copied.append(str(canonical_spec))
    if not canonical_spec_existed:
        created.append(str(canonical_spec))

    # Validate after materialization so the exact files being uploaded are the
    # files accepted by the chain runner and watchdog contract.
    chain_spec = _read_chain_yaml(canonical_spec)
    if not isinstance(chain_spec.get("anchors"), dict) or chain_spec["anchors"].get("north_star") != "NORTHSTAR.md":
        raise CliError("missing_north_star", "canonical chain.yaml must declare anchors.north_star: NORTHSTAR.md")
    from arnold_pipelines.megaplan import chain as chain_module

    loaded = chain_module.load_spec(canonical_spec)
    chain_module.chain_spec.validate_anchor_requirement(loaded, canonical_spec)
    chain_module.chain_spec.validate_paths(loaded, project_root, spec_path=canonical_spec)

    return CanonicalEpicMaterialization(
        spec_path=canonical_spec,
        project_root=project_root,
        slug=slug,
        brief_dir=canonical_dir,
        copied_files=copied,
        created_files=created,
        generated_chain=generated_chain,
    )


def _derive_chain_launch_context(
    *,
    root: Path,
    spec: CloudSpec,
    local_spec_path: Path,
    chain_spec: Any,
) -> ChainLaunchContext:
    from arnold_pipelines.megaplan import chain as chain_module

    identity, slug, digest = _chain_identity_for(local_spec_path, chain_spec)
    session_name = (
        spec.chain_session
        if spec.chain_session_explicit
        else f"{CHAIN_SESSION_NAME}-{slug}-{digest[:8]}"
    )
    workspace = (
        spec.repo.workspace
        if spec.repo.workspace_explicit
        else f"/workspace/{slug}-{digest[:8]}/{_repo_dir_name(spec.repo.url)}"
    )
    remote_spec_path = _remote_chain_workspace_path(
        local_spec_path,
        local_root=root,
        target_workspace=workspace,
    )
    state_path = str(chain_module._state_path_for(Path(remote_spec_path)))
    log_relative = f".megaplan/cloud-chain-{session_name}.log"
    log_path = str(PurePosixPath(workspace) / log_relative)
    marker_path = str(
        PurePosixPath(_operation_marker_dir_for_workspace(workspace))
        / f"{session_name}.json"
    )
    return ChainLaunchContext(
        identity=identity,
        slug=slug,
        digest=digest,
        workspace=workspace,
        remote_spec_path=remote_spec_path,
        session_name=session_name,
        log_relative=log_relative,
        log_path=log_path,
        state_path=state_path,
        marker_path=marker_path,
    )


def _get_provider_identity(spec: CloudSpec) -> str | None:
    """Return a stable provider-level identity for marker enrichment and
    consistency checks.

    This is the provider's *service/project identity*, never an SSH attach
    session name or chain tmux session name.
    """
    if spec.provider == "local":
        if spec.local is not None:
            return spec.local.compose_project
        return None
    if spec.provider == "ssh":
        if spec.ssh is not None:
            return spec.ssh.host
        return None
    return None


def _deploy_log_hint(spec: CloudSpec) -> dict[str, Any]:
    if spec.provider == "local":
        return {"command": "arnold cloud logs --no-follow"}
    if spec.provider == "ssh":
        return {"command": "arnold cloud logs --no-follow"}
    return {"status": "unknown"}


def _deploy_context_steps(deploy_dir: Path) -> list[DeployStepReport]:
    steps: list[DeployStepReport] = []
    for relative in ("Dockerfile", "entrypoint.sh"):
        path = deploy_dir / relative
        if not path.exists():
            steps.append(
                DeployStepReport(
                    name=f"render {relative}",
                    status="missing",
                    detail=f"{relative} was not materialized",
                )
            )
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()[:12]
        steps.append(
            DeployStepReport(
                name=f"render {relative}",
                status="ok",
                detail=f"sha256={digest}",
                metadata={"path": str(path), "sha256": digest},
            )
        )
    return steps


def _coerce_deploy_report(result: Any, *, spec: CloudSpec, deploy_dir: Path) -> DeployReport:
    if isinstance(result, DeployReport):
        report = result
        report.deploy_dir = str(deploy_dir)
        if not report.logs:
            report.logs = _deploy_log_hint(spec)
        if not report.provider:
            report.provider = spec.provider
        if report.service is None:
            report.service = _get_provider_identity(spec)
        return report

    exit_code = int(result)
    success = exit_code == 0
    return DeployReport(
        success=success,
        provider=spec.provider,
        service=_get_provider_identity(spec),
        deploy_dir=str(deploy_dir),
        steps=[
            DeployStepReport(
                name="provider deploy",
                status="ok" if success else "failed",
                detail="provider returned an exit code only; image rebuild decision is provider-controlled",
            )
        ],
        image_rebuild="unknown",
        no_op=False,
        logs=_deploy_log_hint(spec),
        verdict=(
            "deploy: provider deploy completed; image rebuild outcome unknown"
            if success
            else f"deploy: provider deploy failed with exit {exit_code}"
        ),
        exit_code=exit_code,
    )


def _oauth_seed_detail(seed_result: dict[str, list[dict[str, str]]]) -> str:
    events = seed_result.get("events", [])
    counts: dict[str, int] = {}
    for event in events:
        status = event.get("status", "unknown")
        counts[status] = counts.get(status, 0) + 1
    if not counts:
        return "no oauth seed events"
    return ", ".join(f"{status}={count}" for status, count in sorted(counts.items()))


def _tail_text(text: str, *, max_lines: int = 20, max_chars: int = 4000) -> str:
    if not text:
        return ""
    lines = text.splitlines()
    tail = "\n".join(lines[-max_lines:])
    if len(tail) > max_chars:
        tail = tail[-max_chars:]
    return tail


def _git_ref_probe_env(url: str) -> dict[str, str]:
    """Build the hermetic Git environment used by fresh-launch probes.

    AgentBox has a durable, path-only credential helper on the control
    volume.  Reuse the same builder as ``OnBoxProvider`` for ``ls-remote`` and
    commit probes so the engine-ref gate cannot run ahead of the authenticated
    clone/fetch path.  Local callers without that helper retain the existing
    public-repository/token behavior; an explicitly configured helper fails
    closed through the typed auth error when it is missing.
    """
    env = dict(os.environ)
    configured = env.get(ON_BOX_GIT_CREDENTIAL_FILE_ENV)
    default_helper = Path(ON_BOX_GIT_CREDENTIAL_FILE)
    if configured or default_helper.is_file():
        return on_box_git_credential_env(env=env, required=True)
    token = os.environ.get("GITHUB_TOKEN")
    if (
        token
        and url.startswith("https://github.com/")
        and "@github.com/" not in url
    ):
        try:
            count = int(env.get("GIT_CONFIG_COUNT", "0"))
        except ValueError:
            count = 0
        credentials = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env[f"GIT_CONFIG_KEY_{count}"] = "http.https://github.com/.extraheader"
        env[f"GIT_CONFIG_VALUE_{count}"] = f"Authorization: Basic {credentials}"
        env["GIT_CONFIG_COUNT"] = str(count + 1)
    return env


def _ls_remote_refs(repo: str, refs: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "ls-remote", "--refs", repo, *refs],
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
        env=_git_ref_probe_env(repo),
    )


def _probe_remote_commit(repo: str, commit: str) -> subprocess.CompletedProcess[str]:
    """Prove that a raw configured commit is fetchable from the source remote."""
    with TemporaryDirectory(prefix="megaplan-engine-ref-") as raw_dir:
        worktree = Path(raw_dir)
        initialized = subprocess.run(
            ["git", "init", "--quiet", str(worktree)],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if initialized.returncode != 0:
            return initialized
        return subprocess.run(
            [
                "git",
                "-C",
                str(worktree),
                "fetch",
                "--quiet",
                "--depth=1",
                repo,
                commit,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
            env=_git_ref_probe_env(repo),
        )


def _verify_configured_megaplan_ref_advertised(spec: CloudSpec) -> dict[str, Any]:
    repo = (spec.megaplan.repo or "").strip()
    ref = spec.megaplan.ref.strip()
    if not repo:
        return {
            "status": "skipped",
            "reason": "megaplan.repo not configured",
            "repo": "",
            "requested_ref": ref,
        }
    if not ref:
        raise CliError("engine_ref_invalid", "cloud megaplan.ref must not be empty")
    if _RAW_GIT_SHA_RE.fullmatch(ref):
        result = _probe_remote_commit(repo, ref)
        if result.returncode != 0:
            message = redact(
                _tail_text(result.stderr or result.stdout),
                ("GITHUB_TOKEN",),
                env=os.environ,
            )
            raise CliError(
                "engine_commit_unfetchable",
                (
                    f"Configured cloud megaplan.ref commit {ref!r} cannot be fetched "
                    f"from {repo}: {message or 'git fetch failed'}"
                ),
                extra={
                    "engine_ref_check": {
                        "status": "failed",
                        "repo": repo,
                        "requested_ref": ref,
                        "reason": "raw_sha_unfetchable",
                        "stderr_tail": message,
                    }
                },
            )
        return {
            "status": "ok",
            "repo": repo,
            "requested_ref": ref,
            "commit": ref,
            "ref_kind": "commit",
            "verification": "fetch",
        }

    exact_refs = [ref] if ref.startswith("refs/") else [f"refs/heads/{ref}", f"refs/tags/{ref}"]
    result = _ls_remote_refs(repo, exact_refs)
    lines = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
    if result.returncode != 0 and not lines:
        message = redact(
            _tail_text(result.stderr or result.stdout),
            ("GITHUB_TOKEN",),
            env=os.environ,
        )
        raise CliError(
            "engine_ref_probe_failed",
            (
                f"Could not verify cloud megaplan.ref {ref!r} against {repo}: "
                f"{message or 'git ls-remote failed'}"
            ),
            extra={
                "engine_ref_check": {
                    "status": "failed",
                    "repo": repo,
                    "requested_ref": ref,
                    "reason": "ls_remote_failed",
                    "stderr_tail": message,
                }
            },
        )

    advertised: dict[str, str] = {}
    for line in lines:
        parts = line.split()
        if len(parts) >= 2:
            advertised[parts[1]] = parts[0]
    matches = [(name, sha) for name, sha in advertised.items() if name in exact_refs]
    if ref.startswith("refs/"):
        if not matches:
            raise CliError(
                "engine_ref_not_advertised",
                (
                    f"Configured cloud megaplan.ref {ref!r} is not advertised by "
                    f"{repo}. Use an existing branch, tag, or exact full ref."
                ),
                extra={
                    "engine_ref_check": {
                        "status": "failed",
                        "repo": repo,
                        "requested_ref": ref,
                        "reason": "full_ref_missing",
                        "checked_refs": exact_refs,
                    }
                },
            )
        advertised_ref, sha = matches[0]
        return {
            "status": "ok",
            "repo": repo,
            "requested_ref": ref,
            "advertised_ref": advertised_ref,
            "commit": sha,
            "ref_kind": "full_ref",
        }

    if len(matches) > 1:
        raise CliError(
            "engine_ref_ambiguous",
            (
                f"Configured cloud megaplan.ref {ref!r} matches multiple advertised refs "
                f"on {repo}: {', '.join(name for name, _sha in matches)}. "
                "Use a full refs/heads/* or refs/tags/* name."
            ),
            extra={
                "engine_ref_check": {
                    "status": "failed",
                    "repo": repo,
                    "requested_ref": ref,
                    "reason": "ambiguous_short_ref",
                    "matches": [{"ref": name, "commit": sha} for name, sha in matches],
                }
            },
        )
    if not matches:
        raise CliError(
            "engine_ref_not_advertised",
            (
                f"Configured cloud megaplan.ref {ref!r} is not advertised by {repo}. "
                "Use an existing branch, tag, or exact full ref."
            ),
            extra={
                "engine_ref_check": {
                    "status": "failed",
                    "repo": repo,
                    "requested_ref": ref,
                    "reason": "short_ref_missing",
                    "checked_refs": exact_refs,
                }
            },
        )
    advertised_ref, sha = matches[0]
    return {
        "status": "ok",
        "repo": repo,
        "requested_ref": ref,
        "advertised_ref": advertised_ref,
        "commit": sha,
        "ref_kind": "branch" if advertised_ref.startswith("refs/heads/") else "tag",
    }


def _launch_outcome_payload(
    *,
    status: str,
    code: str,
    detail: str | None = None,
    verification: Mapping[str, Any] | None = None,
    stderr_tail: str | None = None,
    log_tail: list[str] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": status,
        "code": code,
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }
    if detail:
        payload["detail"] = detail
    if verification is not None:
        payload["verification"] = dict(verification)
    if stderr_tail:
        payload["stderr_tail"] = stderr_tail
    if log_tail:
        payload["log_tail"] = log_tail
    return payload


def _atomic_marker_write_command(marker_path: str, marker_payload: dict[str, Any]) -> str:
    payload_json = json.dumps(marker_payload, sort_keys=True)
    script = f"""
import json, os, pathlib, tempfile

path = pathlib.Path({marker_path!r})
payload = json.loads({payload_json!r})
current = {{}}
if path.exists():
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        loaded = {{}}
    if isinstance(loaded, dict):
        current.update(loaded)
current.update(payload)
import hashlib, socket

def _start_identity(pid):
    try:
        fields = pathlib.Path(f"/proc/{{int(pid)}}/stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()
        return str(fields[19])
    except Exception:
        return None

workspace = pathlib.Path(current.get("workspace", "")).expanduser()
manifest_path = pathlib.Path(current.get("bootstrap_manifest_path", ""))
if manifest_path.is_file():
    current["manifest_sha256"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    try:
        from arnold_pipelines.megaplan.cloud.runtime_manifest import bootstrap_manifest
        manifest = bootstrap_manifest(manifest_path)
        current.setdefault("runtime_id", manifest.runtime_id)
        current.setdefault("generation", manifest.generation)
        current.setdefault("expected_head", manifest.epic["expected_head"])
    except Exception:
        pass
progress_path = pathlib.Path(current.get("progress_artifact", ""))
if progress_path.is_file():
    current["progress_content_digest"] = hashlib.sha256(progress_path.read_bytes()).hexdigest()
if not current.get("supervisor_pid"):
    current["supervisor_pid"] = int(os.environ.get("MEGAPLAN_SUPERVISOR_PID", os.getppid()))
if not current.get("supervisor_process_start_identity"):
    current["supervisor_process_start_identity"] = _start_identity(current["supervisor_pid"])
    if not current["supervisor_process_start_identity"]:
        try:
            from arnold_pipelines.megaplan.watchdog.worker_identity import read_process_start_identity
            current["supervisor_process_start_identity"] = read_process_start_identity(current["supervisor_pid"])
        except Exception:
            pass
if not current.get("boot_identity"):
    try:
        from arnold_pipelines.megaplan.watchdog.worker_identity import current_boot_identity
        current["boot_identity"] = current_boot_identity() or "unknown-boot"
    except Exception:
        current["boot_identity"] = "unknown-boot"
if not current.get("container_identity"):
    current["container_identity"] = os.environ.get("ARNOLD_CONTAINER_IDENTITY") or socket.gethostname()
unsigned = dict(current)
unsigned.pop("content_digest", None)
unsigned.pop("marker_sha256", None)
current["content_digest"] = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
path.parent.mkdir(parents=True, exist_ok=True)
fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(current, indent=2, sort_keys=True) + "\\n")
os.replace(tmp_name, path)
"""
    # The marker writer is embedded before ``;`` or ``&&`` in several larger
    # shell commands. Group it so the heredoc terminator remains on a line by
    # itself while the caller can safely append an operator to the closing
    # brace. The group preserves the Python process exit status.
    return (
        "{\n"
        f"python3 - <<'MEGAPLAN_MARKER_WRITE'\n{script.strip()}\n"
        "MEGAPLAN_MARKER_WRITE\n"
        "}"
    )


def _prelaunch_marker_guard_command(ctx: "ChainLaunchContext") -> str:
    script = f"""
import json, pathlib, subprocess

marker_path = pathlib.Path({ctx.marker_path!r})
session = {ctx.session_name!r}
identity_digest = {ctx.digest!r}
session_alive = subprocess.run(
    ["tmux", "has-session", "-t", session],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
).returncode == 0
marker = {{}}
marker_present = marker_path.is_file()
marker_read_error = ""
if marker_present:
    try:
        loaded = json.loads(marker_path.read_text(encoding="utf-8"))
    except Exception as exc:
        marker_read_error = str(exc)
        loaded = {{}}
    if isinstance(loaded, dict):
        marker = loaded
identity_matches = marker.get("identity_digest") == identity_digest if marker else False
print(json.dumps({{
    "session_alive": session_alive,
    "marker_present": marker_present,
    "identity_matches": identity_matches,
    "marker_read_error": marker_read_error,
}}, sort_keys=True))
"""
    return f"python3 - <<'MEGAPLAN_PRELAUNCH_MARKER_GUARD'\n{script.strip()}\nMEGAPLAN_PRELAUNCH_MARKER_GUARD"


def _run_prelaunch_marker_guard(provider, ctx: "ChainLaunchContext") -> dict[str, Any]:
    result = provider.ssh_exec(_prelaunch_marker_guard_command(ctx))
    raw = (result.stdout or "").strip().splitlines()
    try:
        payload = json.loads(raw[-1] if raw else "{}")
    except json.JSONDecodeError as exc:
        payload = {
            "session_alive": False,
            "marker_present": False,
            "identity_matches": False,
            "marker_read_error": f"guard output was not JSON: {exc}",
        }
    return payload


def _persist_remote_launch_outcome(
    provider,
    *,
    ctx: "ChainLaunchContext",
    marker_payload: dict[str, Any],
    launch_outcome: dict[str, Any],
    allow_live_session: bool = True,
) -> None:
    if not allow_live_session:
        guard = _run_prelaunch_marker_guard(provider, ctx)
        if guard.get("session_alive"):
            return
        if guard.get("marker_present") and not guard.get("identity_matches"):
            return
    payload = dict(marker_payload)
    payload["launch_outcome"] = launch_outcome
    payload["updated_at"] = launch_outcome.get("observed_at")
    result = provider.ssh_exec(_atomic_marker_write_command(ctx.marker_path, payload))
    if result.returncode != 0:
        raise CliError(
            "launch_marker_write_failed",
            (result.stderr or result.stdout or f"failed to update session marker {ctx.marker_path}").strip(),
            extra={
                "marker_path": ctx.marker_path,
                "launch_outcome": launch_outcome,
            },
        )


def _step_payload(
    step: DeployStepReport,
    *,
    secret_names: list[str] | tuple[str, ...],
    env: dict[str, str] | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": step.name,
        "status": step.status,
    }
    if step.detail:
        payload["detail"] = step.detail
    if step.log_ref:
        payload["log_ref"] = step.log_ref
    stdout_tail = _tail_text(step.stdout)
    stderr_tail = _tail_text(step.stderr)
    if stdout_tail:
        payload["stdout_tail"] = redact(stdout_tail, secret_names, env=env)
    if stderr_tail:
        payload["stderr_tail"] = redact(stderr_tail, secret_names, env=env)
    if step.metadata:
        payload["metadata"] = step.metadata
    return payload


def _deploy_report_payload(
    report: DeployReport,
    *,
    secret_names: list[str] | tuple[str, ...],
    env: dict[str, str] | None,
) -> dict[str, Any]:
    return {
        "success": report.success,
        "event": "cloud_deploy",
        "provider": report.provider,
        "service": report.service,
        "deploy_dir": report.deploy_dir,
        "steps": [
            _step_payload(step, secret_names=secret_names, env=env)
            for step in report.steps
        ],
        "image_rebuild": report.image_rebuild,
        "image_ref": report.image_ref,
        "no_op": report.no_op,
        "vars_updated": report.vars_updated,
        "logs": report.logs,
        "warnings": report.warnings,
        "verdict": report.verdict,
        "note": (
            "cloud deploy updates the thin runner service. Routine arnold behavior "
            "refreshes from the on-volume source clone during cloud chain launch."
        ),
    }


def _emit_deploy_report(
    report: DeployReport,
    *,
    secret_names: list[str] | tuple[str, ...],
    env: dict[str, str] | None,
) -> None:
    sys.stdout.write(f"cloud deploy: provider={report.provider} service={report.service or '<unknown>'}\n")
    for step in report.steps:
        detail = f" ({step.detail})" if step.detail else ""
        sys.stdout.write(f"- {step.name}: {step.status}{detail}\n")
        stdout_tail = _tail_text(step.stdout)
        stderr_tail = _tail_text(step.stderr)
        if stdout_tail:
            redacted = redact(stdout_tail, secret_names, env=env)
            sys.stdout.write("  stdout tail:\n")
            for line in redacted.splitlines():
                sys.stdout.write(f"    {line}\n")
        if stderr_tail:
            redacted = redact(stderr_tail, secret_names, env=env)
            sys.stdout.write("  stderr tail:\n")
            for line in redacted.splitlines():
                sys.stdout.write(f"    {line}\n")
    if report.logs:
        sys.stdout.write(f"logs: {json.dumps(report.logs, sort_keys=True)}\n")
    for warning in report.warnings:
        sys.stdout.write(f"warning: {warning}\n")
    sys.stdout.write(f"{report.verdict}\n")
    sys.stdout.write(
        json.dumps(
            _deploy_report_payload(report, secret_names=secret_names, env=env),
            indent=2,
        )
        + "\n"
    )


def _pinned_manifest_field_read(field: str) -> str:
    """Shell command substitution reading one ``epic`` field from the pinned
    runtime manifest (``$PINNED_RUNTIME_MANIFEST``).

    Stdlib JSON only, silent on absent/corrupt manifests — the caller's
    unconditional manifest-pin checks fail closed on an empty read.  The
    fields are module constants (``runtime_root`` / ``expected_head``),
    never caller input.

    G6 round-2 finding 2: the read is gated on the CANONICAL manifest
    schema.  The emitted script prints the field only when the pinned file
    is a schema-valid runtime manifest — ``schema`` equals
    ``MANIFEST_SCHEMA_VERSION`` and both the canonical top-level and
    ``epic`` required key sets are present.  The key sets and schema version
    are generated from runtime_manifest's own constants, so the shell gate
    can never drift from the schema definition.  A present-but-schema-
    invalid manifest (schema-less, wrong schema version, or missing required
    sections) yields an EMPTY read, so the pin gate fails closed with exit
    24 instead of deriving a dirty ENGINE_DIR from it.
    """
    return (
        '$(env -u PYTHONHOME PYTHONSAFEPATH=1 python -P -c \'import json,sys; '
        f"d=json.load(open(sys.argv[1])); R={json.dumps(TOP_LEVEL_REQUIRED)}; "
        f"E={json.dumps(EPIC_REQUIRED)}; "
        f"e=d.get(\"epic\") if isinstance(d,dict) and d.get(\"schema\")=={json.dumps(MANIFEST_SCHEMA_VERSION)} and all(k in d for k in R) else None; "
        f"print(e.get(\"{field}\",\"\")) if isinstance(e,dict) and all(k in e for k in E) else None\' "
        '"$PINNED_RUNTIME_MANIFEST" 2>/dev/null || true)'
    )


def _pinned_manifest_generation_interpreter_read() -> str:
    """Shell command substitution reading the dependency-generation
    interpreter from the pinned runtime manifest (T-0301).

    Same canonical-schema gate as :func:`_pinned_manifest_field_read`, PLUS
    the generation-proof completeness gate: ``epic.dependency_generation``
    must carry the full required key set
    (:data:`DEPENDENCY_GENERATION_KEYS`).  An absent, partial, or
    schema-invalid proof yields an EMPTY read, so the launch gate fails
    closed with exit 24 — a runtime without a verifiable immutable
    dependency generation is never launched (G10), and there is no
    editable-install / fixed-python fallback.
    """
    return (
        '$(env -u PYTHONHOME PYTHONSAFEPATH=1 python -P -c \'import json,sys; '
        f"d=json.load(open(sys.argv[1])); R={json.dumps(TOP_LEVEL_REQUIRED)}; "
        f"E={json.dumps(EPIC_REQUIRED)}; G={json.dumps(DEPENDENCY_GENERATION_KEYS)}; "
        f"e=d.get(\"epic\") if isinstance(d,dict) and d.get(\"schema\")=={json.dumps(MANIFEST_SCHEMA_VERSION)} and all(k in d for k in R) else None; "
        f"g=e.get(\"dependency_generation\") if isinstance(e,dict) and all(k in e for k in E) else None; "
        f"print(g.get(\"interpreter_path\",\"\")) if isinstance(g,dict) and all(k in g for k in G) else None\' "
        '"$PINNED_RUNTIME_MANIFEST" 2>/dev/null || true)'
    )


def _generation_interpreter_gate(log_target: str) -> str:
    """Shell fragment reading the dependency-generation interpreter from the
    pinned manifest and failing closed (exit 24,
    ``isolated_chain_runtime_binding_drift``) when the proof is missing,
    incomplete, or the interpreter is not executable.

    T-0301: every launch executes from the generation interpreter with
    worktree-first PYTHONPATH (runtime code from the pinned worktree, frozen
    dependencies from the immutable generation).  There is NO ``python`` /
    ``python3`` launch and NO editable-install fallback — a runtime without
    a verifiable generation is never launched (G10).
    """
    return (
        f'GEN_INTERPRETER="{_pinned_manifest_generation_interpreter_read()}"; '
        'if [ -z "$GEN_INTERPRETER" ]; then '
        f'{{ echo "[megaplan-launch] isolated_chain_runtime_binding_drift: manifest lacks dependency generation interpreter" >> {log_target}; }} 2>/dev/null || '
        'echo "[megaplan-launch] isolated_chain_runtime_binding_drift: manifest lacks dependency generation interpreter" >&2; '
        'exit 24; '
        'fi; '
        'if [ ! -x "$GEN_INTERPRETER" ]; then '
        f'{{ echo "[megaplan-launch] isolated_chain_runtime_binding_drift: dependency generation interpreter not executable ($GEN_INTERPRETER)" >> {log_target}; }} 2>/dev/null || '
        'echo "[megaplan-launch] isolated_chain_runtime_binding_drift: dependency generation interpreter not executable ($GEN_INTERPRETER)" >&2; '
        'exit 24; '
        'fi; '
    )


def _manifest_pin_fail_closed_prefix(
    log_target: str, *, post_pin_checks: str = ""
) -> str:
    """Shell fragment enforcing the manifest-bound runtime pin (T-0021).

    Derives ENGINE_DIR ONLY from the pinned per-session runtime manifest's
    ``epic.runtime_root`` and requires nonempty ``epic.expected_head`` plus a
    successful runtime_provenance check.  Missing, unreadable, or disagreeing
    pins exit 24 (``isolated_chain_runtime_binding_drift``) BEFORE any state
    load or subprocess starts — there is NO fixed-path shared-root fallback
    (no ``megaplan.src_path`` read, no ``/workspace/arnold``).  The caller
    must have exported ``PINNED_RUNTIME_MANIFEST`` (readonly) beforehand and
    must place this fragment before the first state-loading subprocess.  The
    pin existence/readability checks here run before this fragment's own
    manifest JSON-reader subprocesses (G5 round-2 finding 1): on a missing or
    unreadable pin the gate exits 24 with ZERO subprocess starts.  The field
    reads are themselves gated on the CANONICAL manifest schema (G6 round-2
    finding 2): a present-but-schema-invalid manifest (schema-less, wrong
    schema version, missing required sections) yields an empty read and the
    gate exits 24 — it can never derive a dirty ENGINE_DIR from a
    non-canonical manifest.

    ``post_pin_checks`` is an optional shell fragment inserted AFTER the
    missing/unreadable checks and BEFORE the manifest field reads.  G5 round-6
    finding 1a: callers (bootstrap) use it for side-effecting setup such as
    ``mkdir -p`` so those pins still exit 24 with ZERO filesystem side
    effects, while the later ENGINE_DIR reads and the provenance log redirect
    can rely on the created directories on a fresh workspace.
    """
    # Pin existence/readability gate FIRST: no manifest field read (a python
    # subprocess) may run while the pin is missing or unreadable, and no
    # caller side effect (post_pin_checks) may run either.

    def _drift_echo(message: str) -> str:
        # G5 round-6 finding 1a: bootstrap runs this gate BEFORE its mkdir,
        # so the log dir may not exist yet on a fresh workspace — write the
        # drift message to the log when possible, otherwise surface it on
        # stderr so the failure stays observable with zero side effects.
        return (
            f'{{ echo "{message}" >> {log_target}; }} 2>/dev/null || '
            f'echo "{message}" >&2; '
        )

    prefix = (
        'if [ -z "$PINNED_RUNTIME_MANIFEST" ]; then '
        + _drift_echo(
            "[megaplan-launch] isolated_chain_runtime_binding_drift: missing runtime manifest pin"
        )
        + 'exit 24; '
        'fi; '
        'if [ ! -r "$PINNED_RUNTIME_MANIFEST" ]; then '
        + _drift_echo(
            "[megaplan-launch] isolated_chain_runtime_binding_drift: runtime manifest unreadable"
        )
        + 'exit 24; '
        'fi; '
    )
    if post_pin_checks:
        prefix += f"{post_pin_checks}; "
    prefix += f'ENGINE_DIR="{_pinned_manifest_field_read("runtime_root")}"; '
    prefix += (
        'if [ -z "$ENGINE_DIR" ]; then '
        + _drift_echo(
            "[megaplan-launch] isolated_chain_runtime_binding_drift: manifest lacks runtime_root"
        )
        + 'exit 24; '
        'fi; '
        f'_EXPECTED_REVISION="{_pinned_manifest_field_read("expected_head")}"; '
        'if [ -z "$_EXPECTED_REVISION" ]; then '
        + _drift_echo(
            "[megaplan-launch] isolated_chain_runtime_binding_drift: manifest lacks runtime identity"
        )
        + 'exit 24; '
        'fi; '
        # T-0301: the generation interpreter gate (proof completeness +
        # executable check) runs before the provenance check, and BOTH the
        # provenance probe and the launch execute under the generation
        # interpreter — never the ambient python and never an editable
        # install.
        + _generation_interpreter_gate(log_target)
        + 'if ! env -u PYTHONHOME PYTHONSAFEPATH=1 '
        'PYTHONPATH="$ENGINE_DIR" '
        '"$GEN_INTERPRETER" -P -m arnold_pipelines.megaplan.cloud.runtime_provenance '
        '--expected-root "$ENGINE_DIR" '
        '--expected-revision "$_EXPECTED_REVISION" '
        f'>> {log_target} 2>&1; then '
        + _drift_echo(
            "[megaplan-launch] isolated_chain_runtime_binding_drift: active imports disagree with manifest-bound runtime"
        )
        + 'exit 24; '
        'fi; '
    )
    return prefix


def _chain_start_command(
    remote_spec_path: str,
    *,
    project_dir: str | None = None,
    engine_dir: str | None = None,
    one_shot: bool = False,
    no_git_refresh: bool = False,
    log_relative: str = _CHAIN_LOG_RELATIVE,
    repair_session: str | None = None,
    repair_run_kind: str = "chain",
    repair_marker_dir: str = _CHAIN_SESSION_MARKER_DIR,
) -> str:
    """Construct the ``python -m arnold_pipelines.megaplan chain start`` command with canonical quoting.

    Both ``_run_chain_wrapper`` and ``cloud_supervise_tick`` use this helper
    so the session name, log path, trusted env var, and shell quoting stay
    consistent across all entry points.
    """
    flags = f"--spec {shlex.quote(remote_spec_path)}"
    if project_dir:
        flags += f" --project-dir {shlex.quote(project_dir)}"
    if one_shot:
        flags += " --one"
    if no_git_refresh:
        flags += " --no-git-refresh"
    log_target = (
        shlex.quote(str(PurePosixPath(project_dir) / log_relative))
        if project_dir
        else shlex.quote(log_relative)
    )
    # The manifest activation runs immediately before this command and exports
    # the per-epic runtime manifest as ARNOLD_RUNTIME_MANIFEST.  Capture that
    # path as readonly *before* an ordinary launch loads the mutable box-wide
    # hot env: that file legitimately changes resident/watchdog settings and
    # may still advertise an older runtime.  Isolated launches still need
    # provider credentials from the box-wide hot env (for example ZHIPU/GLM
    # keys).  Source it too, then reassert the manifest pin below so a stale
    # hot-env manifest cannot replace the accepted runtime identity.  The
    # engine dir (PYTHONPATH) derives from the pinned manifest's
    # ``epic.runtime_root``; nothing reads SRC selector envs (G4).
    prefix = (
        'PINNED_RUNTIME_MANIFEST="${ARNOLD_RUNTIME_MANIFEST:-}"; '
        'readonly PINNED_RUNTIME_MANIFEST; '
        'PINNED_BABYSITTER_CHAIN_PROFILE="${ARNOLD_BABYSITTER_CHAIN_PROFILE:-}"; '
        'readonly PINNED_BABYSITTER_CHAIN_PROFILE; '
        'PINNED_BABYSITTER_CLOSED_PROFILE="${ARNOLD_BABYSITTER_CLOSED_PROFILE:-}"; '
        'readonly PINNED_BABYSITTER_CLOSED_PROFILE; '
    )
    prefix += (
        f"if [ -f {shlex.quote(_CLOUD_HOT_ENV_PATH)} ]; then "
        f"set -a; . {shlex.quote(_CLOUD_HOT_ENV_PATH)}; set +a; fi; "
        'if [ -n "$PINNED_RUNTIME_MANIFEST" ]; then '
        'export ARNOLD_RUNTIME_MANIFEST="$PINNED_RUNTIME_MANIFEST"; '
        'fi; '
        'unset ARNOLD_BABYSITTER_CHAIN_PROFILE ARNOLD_BABYSITTER_CLOSED_PROFILE; '
        'if [ -n "$PINNED_BABYSITTER_CHAIN_PROFILE" ]; then '
        'export ARNOLD_BABYSITTER_CHAIN_PROFILE="$PINNED_BABYSITTER_CHAIN_PROFILE"; '
        'export ARNOLD_BABYSITTER_CLOSED_PROFILE="$PINNED_BABYSITTER_CLOSED_PROFILE"; '
        'fi; '
    )
    if repair_session:
        prefix += _managed_run_env_prefix(
            repair_session,
            run_kind=repair_run_kind,
            marker_dir=repair_marker_dir,
            base_dir=_operation_base_dir_for_workspace(project_dir or ""),
        )
    if engine_dir:
        # G5 round-6 finding 2: the emitted cd is ALWAYS the manifest-bound
        # accepted root ($ENGINE_DIR, re-read from the pinned manifest and
        # validated by runtime_provenance) — never project_dir and never the
        # launch-time engine_dir guess.  project_dir is the chain workspace
        # and can differ from the accepted runtime root (per-epic runtimes
        # live outside the workspace); the megaplan process receives
        # --project-dir and an absolute log target explicitly, so the shell
        # cwd is only a fallback that must point at the accepted root.
        # Fail closed (T-0011): there is NO fixed-path ENGINE_DIR fallback.
        # Every production chain start requires a readable per-session
        # ARNOLD_RUNTIME_MANIFEST pin with nonempty epic.runtime_root +
        # epic.expected_head and a successful runtime_provenance check,
        # regardless of isolated_chain_runner.  G5 round-2 finding 1: the
        # pin existence/readability checks run BEFORE the manifest field-read
        # subprocesses — on a missing or unreadable pin the gate exits 24
        # with ZERO subprocess starts.
        prefix += (
            'if [ -z "$PINNED_RUNTIME_MANIFEST" ]; then '
            f'echo "[megaplan-launch] isolated_chain_runtime_binding_drift: missing runtime manifest pin" >> {log_target}; '
            'exit 24; '
            'fi; '
            'if [ ! -r "$PINNED_RUNTIME_MANIFEST" ]; then '
            f'echo "[megaplan-launch] isolated_chain_runtime_binding_drift: runtime manifest unreadable" >> {log_target}; '
            'exit 24; '
            'fi; '
        )
        prefix += f'ENGINE_DIR="{_pinned_manifest_field_read("runtime_root")}"; '
        prefix += (
            'if [ -z "$ENGINE_DIR" ]; then '
            f'echo "[megaplan-launch] isolated_chain_runtime_binding_drift: manifest lacks runtime_root" >> {log_target}; '
            'exit 24; '
            'fi; '
            f'_EXPECTED_REVISION="{_pinned_manifest_field_read("expected_head")}"; '
            'if [ -z "$_EXPECTED_REVISION" ]; then '
            f'echo "[megaplan-launch] isolated_chain_runtime_binding_drift: manifest lacks runtime identity" >> {log_target}; '
            'exit 24; '
            'fi; '
            # T-0301: the generation interpreter gate runs before the
            # provenance check; BOTH the provenance probe and the launch run
            # under the generation interpreter (worktree-first PYTHONPATH,
            # frozen deps from the immutable generation).  No ambient-python
            # launch and no editable-install fallback.
            + _generation_interpreter_gate(log_target)
            + 'if ! env -u PYTHONHOME PYTHONSAFEPATH=1 '
            'PYTHONPATH="$ENGINE_DIR" '
            '"$GEN_INTERPRETER" -P -m arnold_pipelines.megaplan.cloud.runtime_provenance '
            '--expected-root "$ENGINE_DIR" '
            '--expected-revision "$_EXPECTED_REVISION" '
            f'>> {log_target} 2>&1; then '
            f'echo "[megaplan-launch] isolated_chain_runtime_binding_drift: active imports disagree with manifest-bound runtime" >> {log_target}; '
            'exit 24; '
            'fi; '
        )
        prefix += _launch_boundary_prefix(
            session=repair_session or CHAIN_SESSION_NAME,
        )
        prefix += (
            'cd "$ENGINE_DIR" && env -u PYTHONHOME PYTHONSAFEPATH=1 '
            'PYTHONPATH="$ENGINE_DIR" '
        )
    # The manifest-pinned path launches from the generation interpreter
    # ($GEN_INTERPRETER, set + verified by the gate above).  The unbound
    # pre-pin branch (engine_dir=None — marker prelude only, never a
    # production chain launch) keeps the ambient python; there is NO
    # editable-install refresh anywhere in this command.
    launch_interpreter = '"$GEN_INTERPRETER"' if engine_dir else "python"
    return (
        f"{prefix}MEGAPLAN_TRUSTED_CONTAINER=1 {launch_interpreter} -P -m "
        f"arnold_pipelines.megaplan chain start {flags} "
        f">> {log_target} 2>&1"
    )


def _write_session_marker_command(marker_path: str, marker_payload: dict[str, Any]) -> str:
    return _atomic_marker_write_command(marker_path, marker_payload)


def _managed_run_env_prefix(
    session: str,
    *,
    run_kind: str,
    marker_dir: str = _CHAIN_SESSION_MARKER_DIR,
    base_dir: str | None = None,
) -> str:
    """Return the one launcher-to-runner owner-lease environment contract."""

    operation_roots = ""
    if base_dir:
        operation_roots = (
            f"export ARNOLD_BASE_DIR={shlex.quote(base_dir)}; "
            f"export ARNOLD_RUNTIME_MANIFEST_DIR={shlex.quote(base_dir + '/.megaplan')}; "
        )
    return (
        # Never accept a box-wide or parent-shell publisher claim. The Python
        # owner sets these only after it has acquired the per-session fence;
        # its genuine children inherit them after launch.
        "unset ARNOLD_LIVENESS_OWNER_PID ARNOLD_LIVENESS_OWNER_PROCESS_START; "
        f"{operation_roots}"
        "export ARNOLD_REPAIR_QUEUE_ROOT="
        '"${ARNOLD_REPAIR_QUEUE_ROOT:-/workspace/.megaplan/repair-queue}"; '
        f"export ARNOLD_REPAIR_MARKER_DIR={shlex.quote(marker_dir)}; "
        # Keep chain/seed readers on the same operation-local marker root as
        # the launch writer.  Without this export they fall back to the
        # shared box root and cannot see the marker just written here.
        f"export ARNOLD_CHAIN_SESSION_MARKER_DIR={shlex.quote(marker_dir)}; "
        f"export ARNOLD_REPAIR_SESSION={shlex.quote(session)}; "
        # Chain startup resolves its canonical cloud-session marker from this
        # exact session name.  Keep it pinned in managed launches so a
        # workspace with multiple historical markers cannot fall back to a
        # stale marker during launch-seed attestation.
        f"export ARNOLD_CHAIN_SESSION={shlex.quote(session)}; "
        f"export ARNOLD_REPAIR_RUN_KIND={shlex.quote(run_kind)}; "
    )


def _launch_boundary_prefix(*, session: str, engine_var: str = "$ENGINE_DIR") -> str:
    """Source and apply the shared post-hot-env launch boundary."""

    # The deployed image installs this beside the other wrappers.  The
    # runtime checkout fallback keeps local/runtime-first launches using the
    # exact same materializer without depending on a host-global install.
    session_q = shlex.quote(session)
    return (
        f'ARNOLD_LAUNCH_BOUNDARY={shlex.quote(_LAUNCH_BOUNDARY_PATH)}; '
        'if [ ! -r "$ARNOLD_LAUNCH_BOUNDARY" ]; then '
        f'ARNOLD_LAUNCH_BOUNDARY={engine_var}/arnold_pipelines/megaplan/cloud/wrappers/arnold-launch-boundary; '
        'fi; '
        'if [ -r "$ARNOLD_LAUNCH_BOUNDARY" ]; then '
        '. "$ARNOLD_LAUNCH_BOUNDARY"; '
        f'if arnold_materialize_launch_boundary {session_q} {engine_var} {engine_var}; then :; '
        'else _arnold_boundary_rc=$?; exit "$_arnold_boundary_rc"; fi; '
        'elif [ -d /workspace/.creds ]; then '
        'echo "[megaplan-launch] launch_boundary_unavailable"; exit 78; '
        'else export PYTHONPATH=' + engine_var + '; cd ' + engine_var + '; fi; '
    )


def _plan_auto_command(
    plan_name: str,
    *,
    workspace: str,
    log_relative: str,
    repair_session: str | None = None,
    repair_marker_dir: str = _CHAIN_SESSION_MARKER_DIR,
) -> str:
    """Build the ``python -P -m arnold_pipelines.megaplan auto`` relaunch command.

    The auto relaunch is manifest-bound like chain start (T-0021): the engine
    dir (PYTHONPATH) derives ONLY from the per-session runtime manifest pin
    (``ARNOLD_RUNTIME_MANIFEST`` -> ``epic.runtime_root``) validated against
    ``epic.expected_head`` by the runtime_provenance check.  There is NO
    ``megaplan.src_path`` read and NO fixed-path ``/workspace/arnold``
    fallback; a missing, unreadable, or disagreeing pin exits 24 BEFORE any
    state load or subprocess starts.
    """
    log_target = shlex.quote(str(PurePosixPath(workspace) / log_relative))
    # Capture the pin before the mutable box-wide hot env is sourced, then
    # reassert it (same ordering as the chain-start launch prefix).
    prefix = (
        'PINNED_RUNTIME_MANIFEST="${ARNOLD_RUNTIME_MANIFEST:-}"; '
        'readonly PINNED_RUNTIME_MANIFEST; '
    )
    prefix += (
        f"if [ -f {shlex.quote(_CLOUD_HOT_ENV_PATH)} ]; then "
        f"set -a; . {shlex.quote(_CLOUD_HOT_ENV_PATH)}; set +a; fi; "
        'if [ -n "$PINNED_RUNTIME_MANIFEST" ]; then '
        'export ARNOLD_RUNTIME_MANIFEST="$PINNED_RUNTIME_MANIFEST"; '
        'fi; '
    )
    if repair_session:
        prefix += _managed_run_env_prefix(
            repair_session,
            run_kind="plan",
            marker_dir=repair_marker_dir,
        )
    prefix += _manifest_pin_fail_closed_prefix(log_target)
    return (
        f"{prefix}cd \"$ENGINE_DIR\" && env -u PYTHONHOME PYTHONSAFEPATH=1 "
        'PYTHONPATH="$ENGINE_DIR" '
        'MEGAPLAN_TRUSTED_CONTAINER=1 "$GEN_INTERPRETER" -P -m '
        'arnold_pipelines.megaplan auto '
        f"--plan {shlex.quote(plan_name)} --project-dir {shlex.quote(workspace)} "
        f">> {log_target} 2>&1"
    )


def _chain_runtime_manifest_dir() -> str:
    """Box-side directory of per-epic runtime manifests (matches the
    arnold-runtime-create wrapper default ``$ARNOLD_BASE_DIR/.megaplan``)."""
    return (
        os.environ.get("ARNOLD_RUNTIME_MANIFEST_DIR", "").strip()
        or "/workspace/.megaplan"
    )


def _chain_runtime_manifest_path(slug: str) -> str:
    """Box-side per-epic runtime manifest path for *slug*."""
    return f"{_chain_runtime_manifest_dir().rstrip('/')}/{slug}.json"


def _chain_runtime_worktree_path(slug: str) -> str:
    """Box-side runtime worktree path for *slug* (matches the wrapper's
    ``$ARNOLD_BASE_DIR/runtime-candidates/<slug>`` default)."""
    base_dir = os.environ.get("ARNOLD_BASE_DIR", "").strip() or "/workspace"
    return f"{base_dir.rstrip('/')}/runtime-candidates/{slug}"


# Reader used by the box-side probe: prints one JSON binding record from the
# per-epic manifest — {"present": true, "created": 0|1, "epic_id",
# "runtime_id", "runtime_src", "runtime_revision"}. The read is schema-gated
# on the CANONICAL runtime-manifest schema (G6 round-9 finding 2): the
# manifest must carry ``schema == MANIFEST_SCHEMA_VERSION`` plus the
# canonical top-level and ``epic`` required key sets — generated from
# runtime_manifest's own constants so this box-side gate can never drift from
# the schema definition. A present-but-schema-invalid manifest exits non-zero
# with NO binding record on stdout (no raw fields); ``set -e`` in the calling
# command then aborts the probe so the launch fails loudly. Any other failure
# also exits non-zero (set -e in the calling command), so the launch fails
# loudly.
_RUNTIME_MANIFEST_BINDING_READER = f"""import hashlib, json, pathlib, sys
TOP_LEVEL_REQUIRED = {json.dumps(list(TOP_LEVEL_REQUIRED))}
EPIC_REQUIRED = {json.dumps(list(EPIC_REQUIRED))}
MANIFEST_SCHEMA_VERSION = {json.dumps(MANIFEST_SCHEMA_VERSION)}
path = pathlib.Path(sys.argv[1])
created = int(sys.argv[2]) if len(sys.argv) > 2 else 0
payload = json.loads(path.read_text(encoding="utf-8"))
epic = payload.get("epic") if isinstance(payload, dict) else None
if not (
    isinstance(payload, dict)
    and payload.get("schema") == MANIFEST_SCHEMA_VERSION
    and all(k in payload for k in TOP_LEVEL_REQUIRED)
    and isinstance(epic, dict)
    and all(k in epic for k in EPIC_REQUIRED)
):
    sys.stderr.write(
        f"per-epic runtime manifest {{path}} is present but schema-invalid; "
        "refusing to read raw fields\\n"
    )
    sys.exit(24)
runtime_root = str(epic.get("runtime_root") or "")
runtime_revision = str(epic.get("expected_head") or "")
runtime_identity = {{
        "import_root": runtime_root,
        "source_revision": runtime_revision,
        "editable_root": "",
        "editable_revision": "",
        "direct_url": {{}},
        "pth": [],
        "imports": {{
            "arnold": runtime_root + "/arnold/__init__.py",
            "arnold_pipelines": runtime_root + "/arnold_pipelines/__init__.py",
            "megaplan": runtime_root + "/arnold_pipelines/megaplan/__init__.py",
        }},
}}
identity_core = dict(runtime_identity)
for key in ("editable_root", "editable_revision", "direct_url", "pth", "imports"):
    identity_core[key] = None
runtime_identity["content_sha256"] = hashlib.sha256(
    json.dumps(identity_core, sort_keys=True, separators=(",", ":")).encode("utf-8")
).hexdigest()
print(json.dumps({{
    "present": True,
    "created": created,
    "epic_id": payload.get("epic_id", ""),
    "runtime_id": payload.get("runtime_id", ""),
    "runtime_src": runtime_root,
    "runtime_revision": runtime_revision,
    "runtime_identity": runtime_identity,
}}, sort_keys=True))
"""


def _chain_runtime_policy_upload(
    local_spec_path: Path,
    *,
    workspace: str,
    provider,
) -> str | None:
    """Upload the per-chain runtime policy sidecar (`.runtime_policy.json`,
    written by ``chain override``) to the box so arnold-runtime-create can
    stamp an ``allow_manifestless`` permit into the manifest. Returns the
    remote path, or None when no sidecar exists."""
    from arnold_pipelines.megaplan.chain.spec import _runtime_policy_path_for

    policy_path = _runtime_policy_path_for(local_spec_path)
    if not policy_path.exists():
        return None
    remote = (
        f"{workspace.rstrip('/')}/.megaplan/plans/.chains/{policy_path.name}"
    )
    provider.upload_file(policy_path, remote)
    return remote


def _chain_runtime_probe_and_create_command(
    *,
    slug: str,
    manifest_path: str,
    runtime_src: str,
    manifest_dir: str,
    base_repo: str,
    base_ref: str,
    policy_path: str | None,
    canonical_origin_url: str | None = None,
    chain_state_path: str | None = None,
    marker_path: str | None = None,
    session_name: str | None = None,
    runtime_python: str | None = None,
    spec_path: str | None = None,
    workspace_path: str | None = None,
    base_dir: str | None = None,
) -> str:
    """Box-side probe for the per-epic runtime manifest; creates the runtime
    when absent and verifies/resumes an exact pre-chain partial runtime.

    Prints one JSON binding record on stdout (see
    ``_RUNTIME_MANIFEST_BINDING_READER``). When the manifest is absent the
    command invokes ``arnold-runtime-create`` ON THE BOX (worktree + pushed
    epic branch + manifest, permit stamped into ``deviations[0]`` when
    ``ARNOLD_RUNTIME_POLICY`` points at a valid sidecar) and then reads the
    binding back. Any failure — unreadable manifest, unresolvable base ref,
    push failure, invalid/expired permit — exits non-zero so the launch fails
    loudly BEFORE the chain session starts (deny-by-default)."""
    create_env = [
        f"export ARNOLD_BASE_REPO={shlex.quote(base_repo)}",
        f"export ARNOLD_RUNTIME_MANIFEST_DIR={shlex.quote(manifest_dir)}",
    ]
    if base_dir:
        create_env.insert(0, f"export ARNOLD_BASE_DIR={shlex.quote(base_dir)}")
    if policy_path:
        create_env.append(f"export ARNOLD_RUNTIME_POLICY={shlex.quote(policy_path)}")
    if canonical_origin_url:
        create_env.append(
            f"export ARNOLD_CANONICAL_ORIGIN_URL={shlex.quote(canonical_origin_url)}"
        )
    if chain_state_path:
        create_env.append(f"CHAIN_STATE={shlex.quote(chain_state_path)}")
    if marker_path:
        create_env.append(f"CHAIN_MARKER={shlex.quote(marker_path)}")
        # Runtime-create's preflight/recovery readers must inspect the same
        # operation-local lease/fence sidecars as the marker writer.
        create_env.append(
            "export ARNOLD_CHAIN_SESSION_MARKER_DIR="
            f"{shlex.quote(str(PurePosixPath(marker_path).parent))}"
        )
    if session_name:
        create_env.append(f"CHAIN_SESSION={shlex.quote(session_name)}")
    # Runtime creation is a source-bound bootstrap operation.  The installed
    # /usr/local/bin wrapper may belong to an older image and can import a
    # different runtime, so never select it by PATH or by ambient image
    # freshness.  The configured megaplan source checkout is the authority;
    # the remote command verifies its exact ref, wrapper blob, and import root
    # before invoking anything that can create state.
    # Runtime creation must never discover an interpreter from PATH: an image
    # can carry a stale Python alongside the reviewed source checkout.  Cloud
    # config therefore has to provide an absolute executable explicitly.
    python_assignment = (
        f"PYTHON_BIN={shlex.quote(runtime_python)}"
        if runtime_python
        else 'PYTHON_BIN=""'
    )
    source_guard = "\n".join(
        [
            f'CREATE_SOURCE={shlex.quote(base_repo)}',
            'CREATE_BIN="$CREATE_SOURCE/arnold_pipelines/megaplan/cloud/wrappers/arnold-runtime-create"',
            f"{python_assignment}",
            'if [ -z "$PYTHON_BIN" ] || [ "' + "${PYTHON_BIN#/}" + '" = "$PYTHON_BIN" ] || [ ! -x "$PYTHON_BIN" ]; then echo "chain_runtime_wrapper_interpreter_unavailable: cloud megaplan.runtime_python must be an absolute executable" >&2; exit 78; fi',
            'SOURCE_ROOT="$(git -C "$CREATE_SOURCE" rev-parse --show-toplevel 2>/dev/null || true)"',
            'if [ -z "$SOURCE_ROOT" ] || [ ! -x "$CREATE_BIN" ]; then echo "chain_runtime_wrapper_unavailable: configured source wrapper is missing or unreadable" >&2; exit 78; fi',
            'SOURCE_HEAD="$(git -C "$CREATE_SOURCE" rev-parse --verify "$BASE_REF^{commit}" 2>/dev/null || true)"',
            'CHECKED_OUT_HEAD="$(git -C "$CREATE_SOURCE" rev-parse --verify HEAD 2>/dev/null || true)"',
            'if [ -z "$SOURCE_HEAD" ] || [ "$SOURCE_HEAD" != "$CHECKED_OUT_HEAD" ]; then echo "chain_runtime_source_binding_mismatch: configured source HEAD does not exactly match base ref" >&2; exit 78; fi',
            'SOURCE_TREE="$(git -C "$CREATE_SOURCE" rev-parse --verify "$SOURCE_HEAD^{tree}" 2>/dev/null || true)"',
            'WRAPPER_BLOB="$(git -C "$CREATE_SOURCE" rev-parse --verify "$SOURCE_HEAD:arnold_pipelines/megaplan/cloud/wrappers/arnold-runtime-create" 2>/dev/null || true)"',
            'WRAPPER_DIGEST="$(git -C "$CREATE_SOURCE" hash-object "$CREATE_BIN" 2>/dev/null || true)"',
            'if [ -z "$SOURCE_TREE" ] || [ -z "$WRAPPER_BLOB" ] || [ "$WRAPPER_BLOB" != "$WRAPPER_DIGEST" ]; then echo "chain_runtime_wrapper_identity_mismatch: configured source wrapper differs from its reviewed commit" >&2; exit 78; fi',
            'SOURCE_DIRTY="$(git -C "$CREATE_SOURCE" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)"',
            'if [ -n "$SOURCE_DIRTY" ]; then echo "chain_runtime_source_dirty: configured reviewed source checkout is not clean" >&2; exit 78; fi',
            'export PYTHONSAFEPATH=1 PYTHONPATH="$CREATE_SOURCE" ARNOLD_RUNTIME_PYTHON="$PYTHON_BIN" ARNOLD_REVIEWED_SOURCE_ROOT="$CREATE_SOURCE" ARNOLD_REVIEWED_SOURCE_REVISION="$SOURCE_HEAD" ARNOLD_REVIEWED_SOURCE_TREE="$SOURCE_TREE"',
            'cd "$CREATE_SOURCE"',
            'if ! env -u PYTHONHOME PYTHONSAFEPATH=1 PYTHONPATH="$CREATE_SOURCE" "$PYTHON_BIN" -P -c \'import arnold_pipelines, pathlib, sys; expected=pathlib.Path(sys.argv[1]).resolve(); actual=pathlib.Path(arnold_pipelines.__file__).resolve().parents[1]; raise SystemExit(0 if actual == expected else 78)\' "$CREATE_SOURCE"; then echo "chain_runtime_source_import_mismatch: reviewed source was not imported" >&2; exit 78; fi',
        ]
    )
    return "\n".join(
        [
            "set -euo pipefail",
            f"SLUG={shlex.quote(slug)}",
            f"MANIFEST={shlex.quote(manifest_path)}",
            f"RUNTIME_SRC={shlex.quote(runtime_src)}",
            f"BASE_REPO={shlex.quote(base_repo)}",
            f"BASE_REF={shlex.quote(base_ref)}",
            f"EXPECTED_SPEC={shlex.quote(spec_path or '')}",
            f"EXPECTED_WORKSPACE={shlex.quote(workspace_path or '')}",
            f"CANONICAL_ORIGIN={shlex.quote(canonical_origin_url or '')}",
            source_guard,
            *create_env,
            'if [ -f "$MANIFEST" ]; then',
            # A present runtime is resumable only before any chain authority
            # exists.  This prevents a second launch from adopting an active
            # chain's runtime while preserving the exact partial pre-chain
            # state created by a failed bootstrap.
            # A recovered failed-prechain marker is the only existing marker
            # admitted here.  The verifier is source-bound and read-only; it
            # returns 77 for an ordinary marker so the generic refusal below
            # remains the compatibility path.
            '  RECOVERED_PRECHAIN=0',
            '  if [ -n "${CHAIN_MARKER:-}" ] && "$PYTHON_BIN" -m arnold_pipelines.megaplan.cloud.recovered_prechain_admission "$MANIFEST" "$CHAIN_MARKER" "${CHAIN_STATE:-}" "$RUNTIME_SRC" "${CHAIN_SESSION:-}" "$SLUG" "$EXPECTED_SPEC" "$EXPECTED_WORKSPACE" "$CANONICAL_ORIGIN"; then RECOVERED_PRECHAIN=1; else admission_rc=$?; if [ "$admission_rc" -ne 77 ]; then exit "$admission_rc"; fi; fi',
            '  if [ "$RECOVERED_PRECHAIN" -ne 1 ]; then',
            '    for authority in "${CHAIN_STATE:-}" "${CHAIN_MARKER:-}" "${CHAIN_SESSION:+$ARNOLD_CHAIN_SESSION_MARKER_DIR/$CHAIN_SESSION.liveness-lease.json}" "${CHAIN_SESSION:+$ARNOLD_CHAIN_SESSION_MARKER_DIR/$CHAIN_SESSION.liveness-fence.json}"; do',
            '    if [ -n "$authority" ] && [ -e "$authority" ]; then echo "chain runtime recovery refused: existing chain authority $authority" >&2; exit 1; fi',
            '    done',
            '  fi',
            '  "$CREATE_BIN" "$SLUG" "$BASE_REF"',
            "else",
            # The source-bound wrapper owns base-ref resolution and its Git
            # operations are independently authenticated/redacted.  Do not
            # inline a fetch in this compound probe: OnBoxProvider correctly
            # treats commands containing fetch/push/clone as Git operations
            # and suppresses their stdout to prevent credential leakage.  A
            # probe must retain its final JSON binding record on stdout.
            '  "$CREATE_BIN" "$SLUG" "$BASE_REF"',
            "fi",
            '"$PYTHON_BIN" - "$MANIFEST" 0 <<\'PY\'',
            _RUNTIME_MANIFEST_BINDING_READER,
            "PY",
        ]
    )


def _parse_chain_runtime_binding(
    result: subprocess.CompletedProcess[str],
    *,
    slug: str,
) -> dict[str, Any]:
    """Strictly parse the probe/create binding record; deny-by-default on any
    unreadable, mismatched, or incomplete record."""
    raw = (result.stdout or "").strip()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CliError(
            "chain_runtime_probe_unreadable",
            (
                "cloud chain runtime probe did not return a binding record"
                f" (stdout={raw[:200]!r})"
            ),
        ) from exc
    if not isinstance(payload, dict) or not payload.get("present"):
        raise CliError(
            "chain_runtime_probe_missing",
            "cloud chain runtime probe reported no per-epic runtime manifest",
        )
    if payload.get("epic_id") != slug:
        raise CliError(
            "chain_runtime_epic_mismatch",
            (
                f"cloud chain runtime manifest epic_id {payload.get('epic_id')!r} "
                f"does not match chain slug {slug!r}"
            ),
        )
    runtime_src = str(payload.get("runtime_src") or "")
    if not runtime_src:
        # G6 round-9 finding 2: NO default runtime source fallback — the
        # per-epic manifest must itself declare epic.runtime_root, or the
        # launch fails closed. Only a canonically-valid manifest's runtime
        # source is ever used.
        raise CliError(
            "chain_runtime_manifest_incomplete",
            "cloud chain runtime manifest declares no epic.runtime_root",
        )
    runtime_revision = str(payload.get("runtime_revision") or "")
    if not runtime_revision:
        raise CliError(
            "chain_runtime_manifest_incomplete",
            "cloud chain runtime manifest declares no epic.expected_head",
        )
    return {
        "runtime_src": runtime_src,
        "runtime_revision": runtime_revision,
        "runtime_id": str(payload.get("runtime_id") or ""),
        "runtime_identity": dict(payload.get("runtime_identity") or {}),
        "created": bool(payload.get("created")),
    }


def _ensure_chain_runtime_binding(
    *,
    provider,
    launch_ctx: ChainLaunchContext,
    launch_spec: CloudSpec,
    local_spec_path: Path,
) -> dict[str, Any]:
    """P1 producer routing: probe for this chain's per-epic runtime manifest
    on the box; create it when absent; return the manifest-bound runtime
    binding (manifest path, worktree, revision). Fails loudly on probe or
    creation failure — the per-epic runtime is mandatory (deny-by-default)."""
    slug = launch_ctx.slug
    manifest_path = _chain_runtime_manifest_path(slug)
    runtime_src = _chain_runtime_worktree_path(slug)
    manifest_dir = _chain_runtime_manifest_dir()
    runtime_python = (launch_spec.megaplan.runtime_python or "").strip()
    if not runtime_python or not PurePosixPath(runtime_python).is_absolute():
        raise CliError(
            "chain_runtime_interpreter_required",
            (
                "cloud chain per-epic runtime bootstrap requires an explicit "
                "absolute megaplan.runtime_python"
            ),
            extra={"runtime_python": runtime_python},
        )
    base_repo = (launch_spec.megaplan.src_path or "/workspace/arnold").rstrip("/")
    base_ref = (launch_spec.megaplan.ref or "").strip() or "main"
    policy_path = _chain_runtime_policy_upload(
        local_spec_path,
        workspace=launch_ctx.workspace,
        provider=provider,
    )
    command = _chain_runtime_probe_and_create_command(
        slug=slug,
        manifest_path=manifest_path,
        runtime_src=runtime_src,
        manifest_dir=manifest_dir,
        base_repo=base_repo,
        base_ref=base_ref,
        policy_path=policy_path,
        canonical_origin_url=(launch_spec.repo.url or "").strip(),
        chain_state_path=launch_ctx.state_path,
        marker_path=launch_ctx.marker_path,
        session_name=launch_ctx.session_name,
        runtime_python=runtime_python,
        spec_path=launch_ctx.remote_spec_path,
        workspace_path=launch_ctx.workspace,
        base_dir=_operation_base_dir_for_workspace(launch_ctx.workspace),
    )
    result = provider.ssh_exec(command)
    if result.returncode != 0:
        _relay_output(result, secret_names=launch_spec.secrets, env=os.environ)
        raise CliError(
            "chain_runtime_create_failed",
            (
                (result.stderr or result.stdout)
                or "remote per-epic runtime probe/creation failed"
            ).strip(),
            extra={
                "runtime_manifest": manifest_path,
                "runtime_src": runtime_src,
            },
        )
    binding = _parse_chain_runtime_binding(
        result,
        slug=slug,
    )
    binding["manifest_path"] = manifest_path
    binding["slug"] = slug
    binding["policy_path"] = policy_path
    return binding


def _chain_runtime_provenance_payload(
    binding: Mapping[str, Any],
    *,
    policy_path: str | None,
) -> dict[str, Any]:
    """Launch provenance: which runtime manifest path this session is bound to
    (recorded in the session marker; G1 per-session binding)."""
    return {
        "path": str(binding["manifest_path"]),
        "runtime_src": str(binding["runtime_src"]),
        "runtime_id": str(binding.get("runtime_id") or ""),
        "expected_head": str(binding["runtime_revision"]),
        "binding": "manifest_bound",
        "created_by_launch": bool(binding.get("created")),
        "policy_path": policy_path,
    }


def _chain_runtime_marker_binding(binding: Mapping[str, Any]) -> dict[str, Any]:
    """Return the strict marker-side identity for a validated runtime.

    ``runtime_manifest`` records the selector and provenance path.  The
    attestation reader deliberately consumes the separate marker binding, so
    launch must publish the canonical identity produced by the manifest
    probe, never reconstructing it from caller/configuration text.
    """
    identity = binding.get("runtime_identity")
    if not isinstance(identity, Mapping) or not identity:
        raise CliError(
            "chain_runtime_manifest_incomplete",
            "cloud chain runtime manifest declares no canonical runtime identity",
        )
    return {
        "schema": "arnold.megaplan.marker_runtime_binding.v1",
        "current_identity": dict(identity),
    }


def _manifest_runtime_activate_command(binding: Mapping[str, Any]) -> str:
    """Validate the manifest-bound runtime exists and export the binding env
    (ARNOLD_RUNTIME_MANIFEST) so the chain start resolves THROUGH this epic's
    manifest path — no editable-install refresh, no SRC selector transport
    (G4). Fail closed (exit 23) when the worktree or manifest is missing."""
    runtime_src = str(binding["runtime_src"])
    runtime_revision = str(binding["runtime_revision"])
    manifest_path = str(binding["manifest_path"])
    return "\n".join(
        [
            "set -e",
            'echo "[megaplan-runtime] $(date -Iseconds) activating manifest-bound runtime"',
            f"RUNTIME_SRC={shlex.quote(runtime_src)}",
            f"RUNTIME_REVISION={shlex.quote(runtime_revision)}",
            f"MANIFEST={shlex.quote(manifest_path)}",
            'if [ ! -e "$RUNTIME_SRC/.git" ]; then',
            '  echo "[megaplan-runtime] manifest-bound runtime worktree missing at $RUNTIME_SRC"',
            "  exit 23",
            "fi",
            'if [ ! -f "$MANIFEST" ]; then',
            '  echo "[megaplan-runtime] manifest-bound runtime manifest missing at $MANIFEST"',
            "  exit 23",
            "fi",
            'export ARNOLD_RUNTIME_MANIFEST="$MANIFEST"',
            'echo "[megaplan-runtime] manifest-bound runtime accepted: $MANIFEST"',
            "true",
        ]
    )


def _refresh_then_chain_start_command(
    remote_spec_path: str,
    *,
    spec: CloudSpec | None = None,
    project_dir: str | None = None,
    one_shot: bool = False,
    no_git_refresh: bool = False,
    log_relative: str = _CHAIN_LOG_RELATIVE,
    repair_session: str | None = None,
    repair_run_kind: str = "chain",
    repair_marker_dir: str = _CHAIN_SESSION_MARKER_DIR,
    runtime_binding: Mapping[str, Any] | None = None,
) -> str:
    # engine_dir only SELECTS the manifest-pinned launch path (the
    # `if engine_dir:` guard in _chain_start_command): it never reaches the
    # emitted command.  PYTHONPATH and the emitted cd both come from the
    # manifest-bound $ENGINE_DIR re-read at runtime (G5 round-6 finding 2).
    engine_dir = spec.megaplan.src_path if spec is not None else "/workspace/arnold"
    if runtime_binding is not None:
        # Manifest-bound per-epic runtime (P1 producer routing): the runtime
        # IS the code. Bind the launch env to the created runtime — no
        # editable-install refresh and no global-pointer fallback.
        refresh = _manifest_runtime_activate_command(runtime_binding)
        return (
            f"{{ {refresh}; }} >> {shlex.quote(log_relative)} 2>&1 && "
            f"{_chain_start_command(remote_spec_path, project_dir=project_dir, engine_dir=engine_dir, one_shot=one_shot, no_git_refresh=no_git_refresh, log_relative=log_relative, repair_session=repair_session, repair_run_kind=repair_run_kind, repair_marker_dir=repair_marker_dir)}"
        )
    # No binding (pre-binding marker write / legacy path): the editable-install
    # machinery is deleted; the manifest pin is mandatory and fails closed —
    # there is no fixed-path engine fallback (T-0011).
    return _chain_start_command(
        remote_spec_path,
        project_dir=project_dir,
        engine_dir=engine_dir,
        one_shot=one_shot,
        no_git_refresh=no_git_refresh,
        log_relative=log_relative,
        repair_session=repair_session,
        repair_run_kind=repair_run_kind,
        repair_marker_dir=repair_marker_dir,
    )


def _tmux_chain_launch_command(
    workspace: str,
    remote_spec_path: str,
    *,
    one_shot: bool = False,
    no_git_refresh: bool = False,
    session_name: str | None = None,
    spec: CloudSpec | None = None,
    log_relative: str = _CHAIN_LOG_RELATIVE,
    marker_path: str | None = None,
    identity_digest: str | None = None,
    marker_payload: dict[str, Any] | None = None,
    runtime_binding: Mapping[str, Any] | None = None,
) -> str:
    """Return a single shell command that ensures a tmux session is running the chain.

    When the session already exists the command is a no-op (prints a notice).
    Otherwise a new detached session is created.

    *session_name* defaults to :data:`CHAIN_SESSION_NAME` (``megaplan-chain``)
    when not provided.
    """
    name = session_name or CHAIN_SESSION_NAME
    if log_relative == _CHAIN_LOG_RELATIVE and name != CHAIN_SESSION_NAME:
        log_relative = f".megaplan/cloud-chain-{name}.log"
    marker = marker_path or str(PurePosixPath(_CHAIN_SESSION_MARKER_DIR) / f"{name}.json")
    chain_cmd = _refresh_then_chain_start_command(
        remote_spec_path,
        spec=spec,
        project_dir=workspace,
        one_shot=one_shot,
        no_git_refresh=no_git_refresh,
        log_relative=log_relative,
        repair_session=name,
        repair_run_kind="chain",
        repair_marker_dir=str(PurePosixPath(marker).parent),
        runtime_binding=runtime_binding,
    )
    digest = identity_digest or ""
    marker_payload = marker_payload or {
        "session": name,
        "workspace": workspace,
        "remote_spec": remote_spec_path,
        "identity_digest": digest,
        "run_kind": "chain",
        "run_id": str(uuid.uuid4()),
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    # The marker is the durable launch identity, while these exports are the
    # process-bound projection consumed by watchdog -> babysitter.  Only an
    # explicit, validated profile is exported; session names never select a
    # model route.
    chain_profile = str(marker_payload.get("babysitter_chain_profile") or "").strip()
    closed_profile = str(marker_payload.get("babysitter_closed_profile") or "").strip()
    if chain_profile or closed_profile:
        if chain_profile != CONTINUATION_MUSE_PROFILE or closed_profile != CONTINUATION_MUSE_PROFILE:
            raise CliError(
                "closed_profile_route_mismatch",
                "babysitter closed-route marker identity is invalid",
                extra={
                    "babysitter_chain_profile": chain_profile,
                    "babysitter_closed_profile": closed_profile,
                },
            )
        chain_cmd = (
            f"export ARNOLD_BABYSITTER_CHAIN_PROFILE={shlex.quote(chain_profile)} "
            f"ARNOLD_BABYSITTER_CLOSED_PROFILE={shlex.quote(closed_profile)}; "
            f"{chain_cmd}"
        )
    from arnold_pipelines.megaplan.notification_safety import (
        notification_context_for_current_execution,
    )

    notification_context = notification_context_for_current_execution()
    if notification_context is not None:
        marker_payload = dict(marker_payload)
        marker_payload.setdefault("notification_context", notification_context)
    from arnold_pipelines.megaplan.resident.provenance import (
        DELEGATION_CONTEXT_ENV,
        encoded_provenance,
        safe_provenance_projection,
    )

    resident_delegation = safe_provenance_projection()
    if resident_delegation is not None:
        marker_payload = dict(marker_payload)
        marker_payload.setdefault("resident_delegation", resident_delegation)
        chain_cmd = (
            f"export {DELEGATION_CONTEXT_ENV}="
            f"{shlex.quote(encoded_provenance(resident_delegation))}; {chain_cmd}"
        )
    return (
        f"mkdir -p {shlex.quote(str(PurePosixPath(workspace) / '.megaplan'))} "
        f"{shlex.quote(str(PurePosixPath(marker).parent))}"
        " && "
        f"if tmux has-session -t {shlex.quote(name)} 2>/dev/null; then "
        f"if [ -f {shlex.quote(marker)} ] && grep -F {shlex.quote(digest)} {shlex.quote(marker)} >/dev/null 2>&1; then "
        f"echo {shlex.quote(f'{name} session already running for this chain')}; "
        "else "
        f"echo {shlex.quote(f'ERROR: {name} session already running for a different chain; refusing to disturb it')}; "
        "exit 17; "
        "fi; "
        "else "
        f"{_write_session_marker_command(marker, marker_payload)}\n"
        f"tmux new-session -d -s {shlex.quote(name)} -c {shlex.quote(workspace)} {shlex.quote(chain_cmd)}; "
        f"echo {shlex.quote(f'started {name} session')}; "
        "fi"
    )


def _epic_chain_identity_for(local_spec_path: Path, epic_chain_spec: Any) -> tuple[str, str, str]:
    child_ids = ",".join(epic.id for epic in getattr(epic_chain_spec, "epics", []))
    slug = _slugify_chain_identity(local_spec_path.stem)
    if local_spec_path.name == "epic-chain.yaml" and local_spec_path.parent.parent.name:
        slug = _slugify_chain_identity(local_spec_path.parent.parent.name)
    identity = f"epic-chain:{slug}:{child_ids}"
    digest = hashlib.sha1(identity.encode("utf-8")).hexdigest()[:10]
    return identity, slug, digest


def _remote_epic_chain_state_path(remote_spec_path: str) -> str:
    spec = PurePosixPath(remote_spec_path)
    digest = hashlib.sha1(remote_spec_path.encode("utf-8")).hexdigest()[:12]
    return str(spec.parent / ".megaplan" / "plans" / ".epic_chains" / f"{spec.stem}-{digest}.json")


def _derive_epic_chain_launch_context(
    *,
    root: Path,
    spec: CloudSpec,
    local_spec_path: Path,
    epic_chain_spec: Any,
) -> ChainLaunchContext:
    identity, slug, digest = _epic_chain_identity_for(local_spec_path, epic_chain_spec)
    session_name = (
        spec.chain_session
        if spec.chain_session_explicit
        else f"{CHAIN_SESSION_NAME}-{slug}-parent-{digest[:8]}"
    )
    workspace = (
        spec.repo.workspace
        if spec.repo.workspace_explicit
        else f"/workspace/{slug}-parent-{digest[:8]}/{_repo_dir_name(spec.repo.url)}"
    )
    remote_spec_path = _remote_chain_workspace_path(
        local_spec_path,
        local_root=root,
        target_workspace=workspace,
    )
    log_relative = f".megaplan/cloud-epic-chain-{session_name}.log"
    log_path = str(PurePosixPath(workspace) / log_relative)
    marker_path = str(
        PurePosixPath(_operation_marker_dir_for_workspace(workspace))
        / f"{session_name}.json"
    )
    return ChainLaunchContext(
        identity=identity,
        slug=slug,
        digest=digest,
        workspace=workspace,
        remote_spec_path=remote_spec_path,
        session_name=session_name,
        log_relative=log_relative,
        log_path=log_path,
        state_path=_remote_epic_chain_state_path(remote_spec_path),
        marker_path=marker_path,
    )


def _epic_chain_start_command(
    remote_spec_path: str,
    *,
    workspace: str,
    one_shot: bool = False,
    log_relative: str,
    repair_session: str | None = None,
    repair_marker_dir: str = _CHAIN_SESSION_MARKER_DIR,
) -> str:
    flags = f"--spec {shlex.quote(remote_spec_path)} --project-dir {shlex.quote(workspace)}"
    if one_shot:
        flags += " --one"
    log_target = shlex.quote(str(PurePosixPath(workspace) / log_relative))
    # The epic-chain runner executes from the manifest-bound runtime
    # (ARNOLD_RUNTIME_MANIFEST -> epic.runtime_root); no SRC selector read
    # (G4).  Capture the pin before the hot-env load, then reassert it so a
    # stale box-wide manifest cannot replace the accepted runtime identity.
    prefix = (
        'PINNED_RUNTIME_MANIFEST="${ARNOLD_RUNTIME_MANIFEST:-}"; '
        'readonly PINNED_RUNTIME_MANIFEST; '
    )
    prefix += (
        f"if [ -f {shlex.quote(_CLOUD_HOT_ENV_PATH)} ]; then "
        f"set -a; . {shlex.quote(_CLOUD_HOT_ENV_PATH)}; set +a; fi; "
        'if [ -n "$PINNED_RUNTIME_MANIFEST" ]; then '
        'export ARNOLD_RUNTIME_MANIFEST="$PINNED_RUNTIME_MANIFEST"; '
        'fi; '
    )
    if repair_session:
        prefix += _managed_run_env_prefix(
            repair_session,
            run_kind="epic_chain",
            marker_dir=repair_marker_dir,
            base_dir=_operation_base_dir_for_workspace(workspace),
        )
    # Fail closed (G2 round 2): there is NO fixed-path ENGINE_DIR fallback
    # for the epic-chain parent launch.  Every epic-chain start requires a
    # readable per-session ARNOLD_RUNTIME_MANIFEST pin with nonempty
    # epic.runtime_root + epic.expected_head and a successful
    # runtime_provenance check; the manifest root is the ONLY directory that
    # reaches PYTHONPATH.  G5 round-2 finding 1: the pin existence/
    # readability checks run BEFORE the manifest field-read subprocesses —
    # on a missing or unreadable pin the gate exits 24 with ZERO subprocess
    # starts.
    prefix += (
        'if [ -z "$PINNED_RUNTIME_MANIFEST" ]; then '
        f'echo "[megaplan-launch] isolated_chain_runtime_binding_drift: missing runtime manifest pin" >> {log_target}; '
        'exit 24; '
        'fi; '
        'if [ ! -r "$PINNED_RUNTIME_MANIFEST" ]; then '
        f'echo "[megaplan-launch] isolated_chain_runtime_binding_drift: runtime manifest unreadable" >> {log_target}; '
        'exit 24; '
        'fi; '
    )
    prefix += f'ENGINE_DIR="{_pinned_manifest_field_read("runtime_root")}"; '
    prefix += (
        'if [ -z "$ENGINE_DIR" ]; then '
        f'echo "[megaplan-launch] isolated_chain_runtime_binding_drift: manifest lacks runtime_root" >> {log_target}; '
        'exit 24; '
        'fi; '
        f'_EXPECTED_REVISION="{_pinned_manifest_field_read("expected_head")}"; '
        'if [ -z "$_EXPECTED_REVISION" ]; then '
        f'echo "[megaplan-launch] isolated_chain_runtime_binding_drift: manifest lacks runtime identity" >> {log_target}; '
        'exit 24; '
        'fi; '
        # T-0301: the generation interpreter gate runs before the provenance
        # check; BOTH the provenance probe and the launch run under the
        # generation interpreter (worktree-first PYTHONPATH, frozen deps
        # from the immutable generation).
        + _generation_interpreter_gate(log_target)
        + 'if ! env -u PYTHONHOME PYTHONSAFEPATH=1 '
        'PYTHONPATH="$ENGINE_DIR" '
        '"$GEN_INTERPRETER" -P -m arnold_pipelines.megaplan.cloud.runtime_provenance '
        '--expected-root "$ENGINE_DIR" '
        '--expected-revision "$_EXPECTED_REVISION" '
        f'>> {log_target} 2>&1; then '
        f'echo "[megaplan-launch] isolated_chain_runtime_binding_drift: active imports disagree with manifest-bound runtime" >> {log_target}; '
        'exit 24; '
        'fi; '
    )
    prefix += (
        'cd "$ENGINE_DIR" && env -u PYTHONHOME PYTHONSAFEPATH=1 '
        'PYTHONPATH="$ENGINE_DIR" '
    )
    return (
        f"{prefix}MEGAPLAN_TRUSTED_CONTAINER=1 \"$GEN_INTERPRETER\" -P -m "
        f"arnold_pipelines.megaplan epic-chain start {flags} "
        f">> {log_target} 2>&1"
    )


def _refresh_then_epic_chain_start_command(
    remote_spec_path: str,
    *,
    workspace: str,
    one_shot: bool = False,
    log_relative: str,
    repair_session: str | None = None,
    repair_marker_dir: str = _CHAIN_SESSION_MARKER_DIR,
) -> str:
    # The editable-install refresh machinery is deleted (P4): the epic-chain
    # runner executes from the manifest-bound runtime.  There is no
    # spec-derived engine dir and no fixed-path engine fallback — the
    # per-session ARNOLD_RUNTIME_MANIFEST pin (epic.runtime_root) is the ONLY
    # accepted engine dir and the launch fails closed on any missing or
    # mismatched pin (G2 round 2).
    return _epic_chain_start_command(
        remote_spec_path,
        workspace=workspace,
        one_shot=one_shot,
        log_relative=log_relative,
        repair_session=repair_session,
        repair_marker_dir=repair_marker_dir,
    )


def _tmux_epic_chain_launch_command(
    workspace: str,
    remote_spec_path: str,
    *,
    one_shot: bool = False,
    session_name: str,
    log_relative: str,
    marker_path: str,
    identity_digest: str,
    marker_payload: dict[str, Any],
) -> str:
    epic_chain_cmd = _refresh_then_epic_chain_start_command(
        remote_spec_path,
        workspace=workspace,
        one_shot=one_shot,
        log_relative=log_relative,
        repair_session=session_name,
        repair_marker_dir=str(PurePosixPath(marker_path).parent),
    )
    from arnold_pipelines.megaplan.resident.provenance import (
        DELEGATION_CONTEXT_ENV,
        encoded_provenance,
        safe_provenance_projection,
    )

    resident_delegation = safe_provenance_projection()
    if resident_delegation is not None:
        marker_payload = dict(marker_payload)
        marker_payload.setdefault("resident_delegation", resident_delegation)
        epic_chain_cmd = (
            f"export {DELEGATION_CONTEXT_ENV}="
            f"{shlex.quote(encoded_provenance(resident_delegation))}; {epic_chain_cmd}"
        )
    return (
        f"mkdir -p {shlex.quote(str(PurePosixPath(workspace) / '.megaplan'))} "
        f"{shlex.quote(str(PurePosixPath(marker_path).parent))}"
        " && "
        f"if tmux has-session -t {shlex.quote(session_name)} 2>/dev/null; then "
        f"if [ -f {shlex.quote(marker_path)} ] && grep -F {shlex.quote(identity_digest)} {shlex.quote(marker_path)} >/dev/null 2>&1; then "
        f"echo {shlex.quote(f'{session_name} session already running for this epic-chain')}; "
        "else "
        f"echo {shlex.quote(f'ERROR: {session_name} session already running for a different run; refusing to disturb it')}; "
        "exit 17; "
        "fi; "
        "else "
        f"{_write_session_marker_command(marker_path, marker_payload)}\n"
        f"tmux new-session -d -s {shlex.quote(session_name)} -c {shlex.quote(workspace)} {shlex.quote(epic_chain_cmd)}; "
        f"echo {shlex.quote(f'started {session_name} session')}; "
        "fi"
    )


def _tmux_chain_stop_for_fresh_command(
    *,
    session_name: str,
    marker_path: str,
    identity_digest: str,
) -> str:
    """Stop only the runner owned by the chain that is about to be reset.

    A fresh launch must never erase durable chain state underneath a live
    driver.  The marker identity check also prevents ``--fresh`` from killing
    an unrelated session that happens to share a tmux name.
    """
    return (
        f"if tmux has-session -t {shlex.quote(session_name)} 2>/dev/null; then "
        f"python3 -P -m arnold_pipelines.megaplan.cloud.operator_control tmux-stop "
        f"--spec /dev/null --workspace $(dirname {shlex.quote(marker_path)}) "
        f"--session {shlex.quote(session_name)} --marker {shlex.quote(marker_path)} "
        f"--identity-digest {shlex.quote(identity_digest)} || "
        "{ echo 'ERROR: exact tmux authority proof failed; refusing fresh reset'; exit 17; }; "
        f"echo {shlex.quote(f'stopped {session_name} session for fresh launch')}; "
        "fi"
    )


def _tmux_chain_restart_command(
    workspace: str,
    remote_spec_path: str,
    *,
    session_name: str | None = None,
    spec: CloudSpec | None = None,
    log_relative: str = _CHAIN_LOG_RELATIVE,
    marker_path: str | None = None,
) -> str:
    """Return a shell command that kills any existing tmux session and starts a
    fresh one-shot tick.

    Only the supervisor uses this path — it is never called from the normal
    ``cloud chain`` launch flow.

    *session_name* defaults to :data:`CHAIN_SESSION_NAME` (``megaplan-chain``)
    when not provided.
    """
    name = session_name or CHAIN_SESSION_NAME
    if log_relative == _CHAIN_LOG_RELATIVE and name != CHAIN_SESSION_NAME:
        log_relative = f".megaplan/cloud-chain-{name}.log"
    marker = marker_path or str(PurePosixPath(_CHAIN_SESSION_MARKER_DIR) / f"{name}.json")
    chain_cmd = _refresh_then_chain_start_command(
        remote_spec_path,
        spec=spec,
        project_dir=workspace,
        one_shot=True,
        log_relative=log_relative,
        repair_session=name,
        repair_run_kind="chain",
        repair_marker_dir=str(PurePosixPath(marker).parent),
    )
    return (
        f"mkdir -p {shlex.quote(str(PurePosixPath(workspace) / '.megaplan'))}"
        " && "
        f"if tmux has-session -t {shlex.quote(name)} 2>/dev/null; then "
        f"python3 -P -m arnold_pipelines.megaplan.cloud.operator_control tmux-stop "
        f"--spec /dev/null --workspace $(dirname {shlex.quote(marker)}) "
        f"--session {shlex.quote(name)} --marker {shlex.quote(marker)} "
        f"--remote-spec {shlex.quote(remote_spec_path)} || "
        "{ echo 'ERROR: exact tmux authority proof failed; refusing restart'; exit 17; }; "
        "fi; "
        f"tmux new-session -d -s {shlex.quote(name)} -c {shlex.quote(workspace)} {shlex.quote(chain_cmd)}; "
        f"echo {shlex.quote(f'restarted {name} session')}"
    )


def _chain_state_reset_command(
    *,
    workspace: str,
    state_path: str,
    log_relative: str,
    force: bool = False,
) -> str:
    script = f"""
import json, os, pathlib, shutil
workspace = pathlib.Path({workspace!r})
state_path = pathlib.Path({state_path!r})
force = {bool(force)!r}
reason = None
state_unreadable = None
removed = []
if state_path.exists():
    try:
        raw = json.loads(state_path.read_text())
    except Exception as exc:
        raw = {{}}
        state_unreadable = "state_unreadable: " + str(exc)
        reason = state_unreadable
    if state_unreadable is None and not isinstance(raw, dict):
        raw = {{}}
        state_unreadable = "state_unreadable: state root is not a JSON object"
        reason = state_unreadable
    completed = raw.get("completed") or []
    last_state = raw.get("last_state")
    current_plan = raw.get("current_plan_name")
    current_index = raw.get("current_milestone_index", -1)
    no_progress = not completed and current_index in (-1, 0)
    if force:
        reason = reason or "forced"
    elif not completed and last_state == "stalled":
        reason = "stalled-without-completed-milestones"
    elif no_progress and last_state is None and not current_plan:
        reason = "empty-no-progress-state"
    if state_unreadable:
        # G6 round-6: a corrupt/unreadable state file means the true
        # plan/target is UNKNOWN.  Block the reset and preserve the state
        # file: the census must never run against an empty-derived target and
        # must never yield CLEAR (delete-on-unknown never happens).
        print(json.dumps({{
            "status": "blocked",
            "reason": state_unreadable,
            "state_path": str(state_path),
            "plan_dir": None,
            "census_reasons": [],
        }}, sort_keys=True))
    elif reason:
        plan_dir = None
        if isinstance(current_plan, str) and current_plan and "/" not in current_plan:
            candidate = workspace / ".megaplan" / "plans" / current_plan
            try:
                candidate.relative_to(workspace / ".megaplan" / "plans")
                plan_dir = candidate
            except ValueError:
                plan_dir = None
        # T-0027: the chain-reset is behind the canonical reference census.
        # A plan dir holding referenced custody/leases must not be removed,
        # and an unreadable/corrupt reference store blocks the reset
        # (fail-closed: delete-on-unknown never happens; --force is NOT
        # evidence of safety).  The census runs BEFORE any deletion so a
        # blocked reset leaves the chain state untouched.
        census_verdict = "CLEAR"
        census_reasons = []
        if plan_dir is not None and plan_dir.exists():
            try:
                from arnold_pipelines.megaplan.cloud.runtime_references import run_census
                census_verdict, census_reasons = run_census(
                    root=str(plan_dir),
                    workspace=os.environ.get("ARNOLD_BASE_DIR", ""),
                    manifest_store=os.environ.get("ARNOLD_RUNTIME_MANIFEST_DIR", "/workspace/.megaplan"),
                    current_manifest="",
                    chain_store=os.environ.get("ARNOLD_REFERENCE_CHAIN_STORE", "/workspace/.megaplan/plans/.chains"),
                    marker_store=os.environ.get("ARNOLD_REFERENCE_MARKER_STORE", "/workspace/.megaplan/cloud-sessions:/workspace/watchdog-reports"),
                    schedule_store=os.environ.get("ARNOLD_REFERENCE_SCHEDULE_STORES", "/workspace/arnold/.megaplan/resident/scheduled_jobs:/workspace/arnold/.megaplan/resident/schedules/heads:/workspace/.megaplan/ops/schedules"),
                    repair_queue=os.environ.get("ARNOLD_REFERENCE_REPAIR_QUEUE", "/workspace/.megaplan/repair-queue"),
                    lease_store=os.environ.get("ARNOLD_REFERENCE_LEASE_STORE", str(pathlib.Path.home() / ".megaplan" / "custody" / "leases")),
                )
            except Exception as exc:
                census_verdict = "UNKNOWN"
                census_reasons = [f"reference census unavailable: {{exc}}"]
        if census_verdict != "CLEAR":
            print(json.dumps({{
                "status": "blocked",
                "reason": "reference-census-" + census_verdict,
                "state_path": str(state_path),
                "plan_dir": str(plan_dir) if plan_dir is not None else None,
                "census_reasons": census_reasons,
            }}, sort_keys=True))
        else:
            state_path.unlink(missing_ok=True)
            removed.append(str(state_path))
            if plan_dir is not None and plan_dir.exists():
                try:
                    shutil.rmtree(plan_dir)
                    removed.append(str(plan_dir))
                except Exception as exc:
                    print("[chain-reset] skipped plan dir:", exc)
            print(json.dumps({{"status": "reset", "reason": reason, "removed": removed}}, sort_keys=True))
    else:
        print(json.dumps({{"status": "preserved", "reason": "resumable-or-progressed-state", "state_path": str(state_path)}}, sort_keys=True))
else:
    print(json.dumps({{"status": "absent", "state_path": str(state_path)}}, sort_keys=True))
"""
    return (
        f"cd {shlex.quote(workspace)} && "
        f"python3 - <<'MEGAPLAN_RESET' >> {shlex.quote(log_relative)} 2>&1\n"
        f"{script.strip()}\n"
        "MEGAPLAN_RESET"
    )


_DURABLE_MEGAPLAN_DIRS = ("initiatives", "tickets", "ideas")


def _is_durable_megaplan_upload_file(path: Path) -> bool:
    if path.name == ".DS_Store":
        return False
    if path.name.startswith("._"):
        return False
    if "__MACOSX" in path.parts:
        return False
    return True


def _durable_megaplan_uploads(project_root: Path, workspace: str) -> list[tuple[Path, str]]:
    """Return local durable .megaplan files and their remote workspace paths."""
    root = project_root.expanduser().resolve()
    uploads: list[tuple[Path, str]] = []
    for name in _DURABLE_MEGAPLAN_DIRS:
        local_dir = root / ".megaplan" / name
        if not local_dir.exists():
            continue
        for path in sorted(local_dir.rglob("*")):
            if not path.is_file():
                continue
            if not _is_durable_megaplan_upload_file(path):
                continue
            relative = path.relative_to(root)
            remote = str(PurePosixPath(workspace).joinpath(*relative.parts))
            uploads.append((path, remote))
    return uploads


def _write_durable_megaplan_archive(project_root: Path, uploads: list[tuple[Path, str]]) -> Path:
    """Write a tar.gz containing uploads at repo-relative archive names."""
    root = project_root.expanduser().resolve()
    handle = NamedTemporaryFile(suffix=".megaplan-durable.tar.gz", delete=False)
    archive_path = Path(handle.name)
    handle.close()
    with tarfile.open(archive_path, "w:gz") as tar:
        for local_source, _remote_path in uploads:
            arcname = local_source.expanduser().resolve().relative_to(root).as_posix()
            tar.add(local_source, arcname=arcname, recursive=False)
    return archive_path


def _clean_remote_durable_megaplan_command(workspace: str) -> str:
    roots = " ".join(
        shlex.quote(str(PurePosixPath(workspace) / ".megaplan" / name))
        for name in _DURABLE_MEGAPLAN_DIRS
    )
    return f"rm -rf {roots} && mkdir -p {shlex.quote(str(PurePosixPath(workspace) / '.megaplan'))}"


def _resolve_sync_megaplan_context(root: Path, args: argparse.Namespace, spec: CloudSpec):
    from arnold_pipelines.megaplan import chain as chain_module

    explicit_workspace = getattr(args, "workspace", None)
    raw_spec = getattr(args, "spec", None)
    if raw_spec:
        local_spec_path = Path(raw_spec).expanduser().resolve()
        project_root = _chain_project_root(local_spec_path, root)
        _validate_chain_spec_location(
            local_spec_path,
            project_root,
            allow_loose=bool(getattr(args, "allow_loose_chain_spec", False)),
        )
        chain_spec = chain_module.load_spec(local_spec_path)
        ctx = _derive_chain_launch_context(
            root=project_root,
            spec=spec,
            local_spec_path=local_spec_path,
            chain_spec=chain_spec,
        )
        workspace = explicit_workspace or ctx.workspace
        return project_root, workspace, ctx.remote_spec_path, ctx.session_name
    project_root = root.expanduser().resolve()
    workspace = explicit_workspace or spec.repo.workspace
    return project_root, workspace, None, None


def _run_sync_megaplan(root: Path, args: argparse.Namespace, spec: CloudSpec, provider) -> int:
    project_root, workspace, remote_spec, session_name = _resolve_sync_megaplan_context(
        root,
        args,
        spec,
    )
    sync_spec = replace(spec, repo=replace(spec.repo, workspace=workspace))
    _ensure_repo_checkout(sync_spec, provider, relay=False)
    uploads = _durable_megaplan_uploads(project_root, workspace)
    if bool(getattr(args, "clean", False)):
        result = provider.ssh_exec(_clean_remote_durable_megaplan_command(workspace))
        if result.returncode != 0:
            _relay_output(result, secret_names=spec.secrets, env=os.environ)
            raise CliError(
                "provider_failed",
                f"remote .megaplan durable clean failed (exit {result.returncode})",
            )
    archive_path: Path | None = None
    try:
        archive_path = _write_durable_megaplan_archive(project_root, uploads)
        provider.upload_archive(archive_path, workspace)
    finally:
        if archive_path is not None:
            archive_path.unlink(missing_ok=True)
    payload = {
        "success": True,
        "project_root": str(project_root),
        "workspace": workspace,
        "remote_spec": remote_spec,
        "chain_session": session_name,
        "uploaded_files": len(uploads),
        "uploaded_roots": list(_DURABLE_MEGAPLAN_DIRS),
        "cleaned": bool(getattr(args, "clean", False)),
    }
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    return 0


def _initiative_template_placeholder_findings(
    local_spec_path: Path,
    *,
    project_root: Path,
    cloud_yaml: Path | None = None,
) -> list[dict[str, Any]]:
    """Return template placeholders that require an explicit launch override."""
    roots: list[Path] = []
    if is_canonical_chain_spec(local_spec_path, project_root):
        roots.append(local_spec_path.parent)
    else:
        roots.append(local_spec_path)
    if cloud_yaml is not None:
        roots.append(cloud_yaml)

    findings: list[dict[str, Any]] = []
    seen: set[Path] = set()
    for root in roots:
        candidates: list[Path]
        if root.is_dir():
            candidates = [
                path
                for path in root.rglob("*")
                if path.is_file() and path.suffix.lower() in {".md", ".yaml", ".yml"}
            ]
        else:
            candidates = [root]
        for path in candidates:
            resolved = path.expanduser().resolve()
            if resolved in seen or not resolved.exists():
                continue
            seen.add(resolved)
            try:
                text = resolved.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for line_no, line in enumerate(text.splitlines(), start=1):
                match = _TEMPLATE_PLACEHOLDER_RE.search(line)
                if match is None:
                    continue
                findings.append(
                    {
                        "path": str(resolved),
                        "line": line_no,
                        "placeholder": match.group(0),
                    }
                )
    return findings


def _human_gate_findings(chain_spec: Any) -> list[dict[str, Any]]:
    """Return chain-policy settings that intentionally require human action."""
    findings: list[dict[str, Any]] = []
    merge_policy = getattr(chain_spec, "merge_policy", None)
    if merge_policy and merge_policy != "auto":
        findings.append(
            {
                "field": "merge_policy",
                "value": merge_policy,
                "impact": (
                    "milestone PRs park instead of auto-merging; unattended cloud "
                    "chains can stop at awaiting_pr_merge"
                ),
            }
        )
    auto_approve = getattr(chain_spec, "auto_approve", None)
    if auto_approve is False:
        findings.append(
            {
                "field": "driver.auto_approve",
                "value": False,
                "impact": (
                    "prep clarification and human verification gates require an "
                    "operator instead of being converted into conservative assumptions"
                ),
            }
        )
    return findings


_NORTH_STAR_TEMPLATE_PHRASES = (
    "Describe the durable destination every milestone must preserve",
    "List invariants the chain must not violate",
    "Name tempting work that is intentionally out of scope",
    "Describe any acceptable short-lived compromises",
    "List signs the chain is solving the wrong problem",
)


def _multi_sprint_north_star_findings(local_spec_path: Path, chain_spec: Any) -> list[dict[str, Any]]:
    """Return blocking findings for multi-sprint chains with stub North Stars."""
    milestones = list(getattr(chain_spec, "milestones", []) or [])
    # P6: the generated ``kind: reconcile`` terminal milestone is a meta-stage
    # (engine PR + close/sweep), not a product sprint.  Counting it would turn
    # every scaffolded single-sprint chain into "multi-sprint" and wrongly
    # demand a filled-in North Star.
    product_milestones = [
        milestone
        for milestone in milestones
        if getattr(milestone, "kind", "product") != "reconcile"
    ]
    if len(product_milestones) <= 1:
        return []
    north_star = getattr(getattr(chain_spec, "anchors", None), "north_star", None)
    if not isinstance(north_star, str) or not north_star.strip():
        return [
            {
                "code": "missing_north_star",
                "message": "multi-sprint cloud chains require anchors.north_star",
            }
        ]
    from arnold_pipelines.megaplan.anchors import resolve_anchor_path

    path = resolve_anchor_path(local_spec_path, north_star)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [
            {
                "code": "north_star_unreadable",
                "path": str(path),
                "message": str(exc),
            }
        ]
    findings: list[dict[str, Any]] = []
    if _TEMPLATE_PLACEHOLDER_RE.search(text):
        findings.append(
            {
                "code": "north_star_template_placeholder",
                "path": str(path),
                "message": "North Star still contains template placeholders",
            }
        )
    for phrase in _NORTH_STAR_TEMPLATE_PHRASES:
        if phrase in text:
            findings.append(
                {
                    "code": "north_star_default_template_text",
                    "path": str(path),
                    "message": f"North Star still contains default template text: {phrase}",
                }
            )
            break
    body_words = [
        word
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
        for word in re.findall(r"[A-Za-z0-9][A-Za-z0-9_-]*", line)
    ]
    if len(body_words) < 40:
        findings.append(
            {
                "code": "north_star_too_thin",
                "path": str(path),
                "message": "Multi-sprint North Star must contain at least 40 non-heading words",
                "word_count": len(body_words),
            }
        )
    return findings


def _run_preflight(root: Path, args: argparse.Namespace, spec: CloudSpec, provider) -> int:
    from arnold_pipelines.megaplan import chain as chain_module
    from arnold_pipelines.megaplan.cloud.preflight import resolve_cloud_chain_runtime_dependencies

    local_spec_path = Path(args.spec).expanduser().resolve()
    project_root = _chain_project_root(local_spec_path, root)
    _validate_chain_spec_location(
        local_spec_path,
        project_root,
        allow_loose=bool(getattr(args, "allow_loose_chain_spec", False)),
    )
    placeholder_findings = _initiative_template_placeholder_findings(
        local_spec_path,
        project_root=project_root,
        cloud_yaml=_cloud_yaml_path(root, args),
    )
    chain_spec = chain_module.load_spec(local_spec_path)
    human_gate_findings = _human_gate_findings(chain_spec)
    north_star_findings = _multi_sprint_north_star_findings(local_spec_path, chain_spec)
    anchor_requirement = chain_module.chain_spec.validate_anchor_requirement(chain_spec, local_spec_path)
    chain_module.chain_spec.validate_paths(chain_spec, project_root, spec_path=local_spec_path)
    launch_ctx = _derive_chain_launch_context(
        root=project_root,
        spec=spec,
        local_spec_path=local_spec_path,
        chain_spec=chain_spec,
    )
    preflight_summary = resolve_cloud_chain_runtime_dependencies(
        chain_spec,
        project_dir=project_root,
        cloud_default_agent=spec.agents.get("default"),
    )
    closed_route = _validate_continuation_muse_routes(
        preflight_summary, session=launch_ctx.session_name
    )
    missing_env = _missing_configured_secrets(spec, os.environ)
    remote: dict[str, Any] = {"skipped": bool(getattr(args, "skip_remote", False))}
    errors: list[str] = []
    import_check: dict[str, Any] = {
        "status": "skipped" if remote["skipped"] else "unavailable",
        "checks": {},
        "errors": [],
        "reason": "remote_checks_skipped" if remote["skipped"] else "host_or_collector_preflight_no_go",
    }
    missing_commands: list[str] = []
    if not remote["skipped"]:
        ssh_host_prelaunch = spec.provider == "ssh"
        if ssh_host_prelaunch:
            container_observation = _provider_container_observation(provider)
            capacity_observation = _provider_prelaunch_capacity(provider)
            if container_observation is None:
                container_observation = {
                    "schema": "arnold.cloud.ssh_container_observation.v1",
                    "status": "unknown",
                    "lifecycle": "unknown",
                    "collector": {"status": "unavailable", "reason": "observer_unavailable"},
                }
            remote["container_observation"] = container_observation
            remote["prelaunch_capacity"] = capacity_observation
            lifecycle = container_observation.get("lifecycle")
            collector_ready = _container_collector_ready(container_observation)
            capacity_ready = capacity_observation.get("verdict") == "GO"
            host_predeploy_ready = (
                lifecycle in {"running", "stopped"}
                and container_observation.get("status") == "available"
                and capacity_ready
            )
            remote["host_predeploy_verdict"] = (
                "GO" if host_predeploy_ready else "NO-GO"
            )
            remote["collector_launch_verdict"] = (
                "GO" if collector_ready else "NO-GO"
            )
            remote_checks_ready = collector_ready and capacity_ready
        else:
            lifecycle = "not-applicable"
            collector_ready = True
            capacity_ready = True
            remote_checks_ready = True
        if not collector_ready:
            errors.append(
                f"container lifecycle is {lifecycle or 'unknown'}; remote exec collector unavailable"
            )
        if not capacity_ready:
            errors.append(
                "host workspace prelaunch capacity/durability observation is NO-GO"
            )
        if remote_checks_ready:
            try:
                engine_ref_check = _verify_configured_megaplan_ref_advertised(spec)
            except CliError as exc:
                engine_ref_check = dict(exc.extra.get("engine_ref_check") or {})
                engine_ref_check.setdefault("status", "failed")
                remote["engine_ref_check"] = engine_ref_check
                errors.append(exc.message)
            else:
                remote["engine_ref_check"] = engine_ref_check
        else:
            remote["engine_ref_check"] = {
                "status": "unavailable",
                "reason": "host_or_collector_preflight_no_go",
            }
        if remote_checks_ready:
            import_check = _run_remote_megaplan_import_check(provider)
            missing_commands = _run_remote_dependency_check(
                provider,
                list(preflight_summary.get("runtime_commands", [])),
            )
        else:
            import_check = {
                "status": "unavailable",
                "checks": {},
                "errors": [],
                "reason": "host_or_collector_preflight_no_go",
            }
            missing_commands = []
    if closed_route is not None:
        # A skipped remote preflight still performs the local OMP capability
        # check.  The box broker/store is authoritative; OPENROUTER_API_KEY
        # in this process is merely one possible implementation detail.
        if remote["skipped"]:
            remote["provider_credentials"] = _omp_openrouter_capability_check(
                local=True
            )
        elif remote_checks_ready:
            remote["provider_credentials"] = _omp_openrouter_capability_check(
                provider
            )
        else:
            remote["provider_credentials"] = {
                "status": "unavailable",
                "reason": "host_or_collector_preflight_no_go",
                "provider": "openrouter",
                "model": "meta/muse-spark-1.3-contributor",
                "thinking": "high",
                "fallback": False,
                "probe": "omp_sessionless_no_tools",
            }
    remote.update(
        {
            "import_check": import_check,
            "missing_commands": missing_commands,
        }
    )
    if placeholder_findings and not bool(getattr(args, "allow_template_placeholders", False)):
        errors.append(
            "template placeholders remain; edit them or pass --allow-template-placeholders"
        )
    if human_gate_findings and not bool(getattr(args, "allow_human_gates", False)):
        errors.append(
            "human-gated cloud chain policy present; use merge_policy: auto and "
            "driver.auto_approve: true for unattended cloud runs, or pass "
            "--allow-human-gates to acknowledge intentional pauses"
        )
    if north_star_findings:
        errors.append(
            "multi-sprint cloud chain North Star is missing or still looks like a template; fill it in before launch"
        )
    if missing_env:
        errors.append("missing configured local secrets: " + ", ".join(missing_env))
    if remote.get("import_check", {}).get("errors"):
        errors.extend(str(item) for item in remote["import_check"]["errors"])
    if remote.get("missing_commands"):
        errors.append("missing remote commands: " + ", ".join(remote["missing_commands"]))
    if (
        closed_route is not None
        and remote.get("provider_credentials", {}).get("status") != "ok"
    ):
        errors.append("closed Muse profile requires an authenticated OMP OpenRouter Muse route")
    payload = {
        "success": not errors,
        "event": "cloud_preflight",
        "project_root": str(project_root),
        "spec": str(local_spec_path),
        "canonical_layout": is_canonical_chain_spec(local_spec_path, project_root),
        "remote": {
            **remote,
            "expected_workspace": launch_ctx.workspace,
            "expected_remote_spec": launch_ctx.remote_spec_path,
            "expected_session": launch_ctx.session_name,
        },
        "anchor": {
            "require_anchor": anchor_requirement.require_anchor,
            "north_star": chain_spec.anchors.north_star,
            "warning": anchor_requirement.warning,
        },
        "preflight": preflight_summary,
        "closed_route": closed_route,
        "warnings": _cloud_profile_warnings(preflight_summary, spec),
        "missing_env": missing_env,
        "template_placeholders": placeholder_findings,
        "human_gates": human_gate_findings,
        "north_star_findings": north_star_findings,
        "errors": errors,
    }
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    return 0 if not errors else 1


def _chain_launch_verification_command(
    *,
    workspace: str,
    session_name: str,
    state_path: str,
    log_path: str,
    attempts: int = _CHAIN_VERIFY_ATTEMPTS,
    sleep_seconds: int = _CHAIN_VERIFY_SLEEP_SECONDS,
) -> str:
    script = f"""
	import json, pathlib, re, subprocess, time
workspace = pathlib.Path({workspace!r})
session = {session_name!r}
state_path = pathlib.Path({state_path!r})
log_path = pathlib.Path({log_path!r})
attempts = {int(attempts)!r}
sleep_seconds = {int(sleep_seconds)!r}
last_state = None
advanced = False
for idx in range(max(1, attempts)):
    alive = subprocess.run(["tmux", "has-session", "-t", session], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    log_size = log_path.stat().st_size if log_path.exists() else 0
    state = None
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text())
        except Exception as exc:
            state = {{"error": str(exc)}}
    plan_dirs = []
    plans_root = workspace / ".megaplan" / "plans"
    if plans_root.exists():
        plan_dirs = sorted(p.name for p in plans_root.iterdir() if p.is_dir() and p.name != ".chains")
    advanced = bool(
        state
        and (
            state.get("current_plan_name")
            or state.get("completed")
            or int(state.get("current_milestone_index", -1)) >= 0
        )
    ) or bool(plan_dirs)
    last_state = {{
        "session_alive": alive,
        "chain_log": str(log_path),
        "chain_log_size": log_size,
        "state_path": str(state_path),
        "state_present": state_path.exists(),
        "advanced_past_init": advanced,
        "plan_dirs": plan_dirs[:5],
        "attempts": idx + 1,
    }}
    if alive and advanced:
        break
    if idx + 1 < attempts:
        time.sleep(sleep_seconds)
likely = None
failure_code = None
log_tail = []
if log_path.exists():
    try:
        log_tail = log_path.read_text(errors="replace").splitlines()[-80:]
    except Exception as exc:
        log_tail = [f"<unable to read chain log: {{exc}}>"]
tail_text = "\\n".join(log_tail)
if not last_state["session_alive"]:
    likely = "driver exited; inspect chain log for missing megaplan or dependency failures"
elif not last_state["advanced_past_init"]:
    likely = "driver stayed at init; inspect chain log for stale state, git refresh conflict, or missing megaplan"
if "[megaplan-refresh] refusing editable install refresh" in tail_text:
    likely = "editable install refresh failed before chain start"
    if "tracked changes in source checkout" in tail_text:
        failure_code = "editable_install_refresh_dirty"
    elif "local commits not contained" in tail_text:
        failure_code = "editable_install_refresh_diverged"
    else:
        failure_code = "editable_install_refresh_failed"
last_state["likely_cause"] = likely
last_state["failure_code"] = failure_code
last_state["log_tail"] = log_tail
print(json.dumps(last_state, sort_keys=True))
"""
    return f"python3 - <<'MEGAPLAN_VERIFY'\n{script.strip()}\nMEGAPLAN_VERIFY"


def _run_chain_launch_verification(provider, ctx: ChainLaunchContext) -> dict[str, Any]:
    result = provider.ssh_exec(
        _chain_launch_verification_command(
            workspace=ctx.workspace,
            session_name=ctx.session_name,
            state_path=ctx.state_path,
            log_path=ctx.log_path,
        )
    )
    raw = (result.stdout or "").strip().splitlines()
    if result.returncode != 0:
        return {
            "session_alive": False,
            "advanced_past_init": False,
            "chain_log": ctx.log_path,
            "status": "verification_failed",
            "likely_cause": (result.stderr or result.stdout or "verification command failed").strip(),
        }
    try:
        payload = json.loads(raw[-1] if raw else "{}")
    except json.JSONDecodeError as exc:
        return {
            "session_alive": None,
            "advanced_past_init": None,
            "chain_log": ctx.log_path,
            "status": "verification_unparseable",
            "likely_cause": f"verification output was not JSON: {exc}",
            "raw": result.stdout,
        }
    payload["status"] = "ok" if payload.get("session_alive") and payload.get("advanced_past_init") else "warning"
    return payload


def _watchdog_tracking_verification_command(ctx: ChainLaunchContext) -> str:
    script = f"""
import json, pathlib, sys
marker_path = pathlib.Path({ctx.marker_path!r})
workspace = pathlib.Path({ctx.workspace!r})
remote_spec = pathlib.Path({ctx.remote_spec_path!r})
session = {ctx.session_name!r}
identity_digest = {ctx.digest!r}
checks = {{
    "marker_path": str(marker_path),
    "workspace": str(workspace),
    "remote_spec": str(remote_spec),
    "session": session,
    "marker_present": marker_path.is_file(),
    "workspace_present": workspace.is_dir(),
    "spec_present": remote_spec.is_file(),
    "tracked": False,
    "errors": [],
}}
payload = {{}}
if not checks["marker_present"]:
    checks["errors"].append("marker missing")
else:
    try:
        payload = json.loads(marker_path.read_text())
    except Exception as exc:
        checks["errors"].append(f"marker unreadable: {{exc}}")
if payload:
    for key, expected in {{
        "session": session,
        "workspace": str(workspace),
        "remote_spec": str(remote_spec),
        "identity_digest": identity_digest,
    }}.items():
        if payload.get(key) != expected:
            checks["errors"].append(f"marker {{key}}={{payload.get(key)!r}} expected {{expected!r}}")
if not checks["workspace_present"]:
    checks["errors"].append("workspace missing")
if not checks["spec_present"]:
    checks["errors"].append("remote_spec missing")
checks["tracked"] = not checks["errors"]
print(json.dumps(checks, sort_keys=True))
sys.exit(0 if checks["tracked"] else 1)
"""
    return f"python3 - <<'MEGAPLAN_WATCHDOG_TRACKING'\n{script.strip()}\nMEGAPLAN_WATCHDOG_TRACKING"


def _run_watchdog_tracking_verification(provider, ctx: ChainLaunchContext) -> dict[str, Any]:
    result = provider.ssh_exec(_watchdog_tracking_verification_command(ctx))
    raw = (result.stdout or "").strip().splitlines()
    try:
        payload = json.loads(raw[-1] if raw else "{}")
    except json.JSONDecodeError as exc:
        payload = {
            "tracked": False,
            "errors": [f"tracking verification output was not JSON: {exc}"],
            "raw": result.stdout,
        }
    if result.returncode != 0:
        payload.setdefault("tracked", False)
        if result.stderr:
            payload.setdefault("errors", []).append(result.stderr.strip())
    payload["status"] = "tracked" if payload.get("tracked") else "not_tracked"
    return payload


def _run_authoritative_chain_wrapper(root: Path, args: argparse.Namespace, spec: CloudSpec, provider) -> int:
    """Prepare remote inputs, then invoke the co-located launch engine once.

    This controller path intentionally has no operation-store, marker, receipt,
    tmux, or relaunch capability.  Those effects belong to
    ``cloud.chain_drive`` inside the provider boundary.
    """
    from arnold_pipelines.megaplan import chain as chain_module
    from arnold.runtime.durable_ops import LaunchEnvelope, run_launch_preflight
    from arnold_pipelines.megaplan.cloud.chain_drive import build_launch_request

    if not bool(getattr(args, "_canonicalized_epic", False)):
        materialized = _materialize_canonical_epic_input(root=root, spec=spec, spec_or_dir=args.spec)
        args = argparse.Namespace(
            **{
                **vars(args),
                "spec": str(materialized.spec_path),
                "idea_dir": str(materialized.project_root),
                "_canonicalized_epic": True,
            }
        )
    local_spec_path = Path(args.spec).expanduser().resolve()
    project_root = _chain_project_root(local_spec_path, root)
    _validate_chain_spec_location(
        local_spec_path,
        project_root,
        allow_loose=bool(getattr(args, "allow_loose_chain_spec", False)),
    )
    chain_spec = chain_module.load_spec(local_spec_path)
    chain_module.chain_spec.validate_anchor_requirement(chain_spec, local_spec_path)
    chain_module.chain_spec.validate_paths(chain_spec, project_root, spec_path=local_spec_path)
    launch_ctx = _derive_chain_launch_context(
        root=project_root,
        spec=spec,
        local_spec_path=local_spec_path,
        chain_spec=chain_spec,
    )
    if bool(getattr(args, "prepare_only", False)):
        # Preparation remains a controller transport operation.  It does not
        # admit or dispatch anything and returns no live launch projection.
        return _prepare_chain_inputs(root, args, spec, provider, local_spec_path, project_root, chain_spec, launch_ctx)

    uploads: list[tuple[Path, str]] = []
    idea_dir = Path(args.idea_dir).expanduser().resolve() if args.idea_dir else local_spec_path.parent.resolve()
    for milestone in chain_spec.milestones:
        source, tried = _resolve_local_idea_source(
            root=project_root,
            idea_dir=idea_dir,
            workspace=spec.repo.workspace,
            remote_path=milestone.idea,
        )
        if source is None:
            raise CliError("missing_idea_file", f"milestone '{milestone.label}' idea not found: {tried}")
        uploads.append((source, _remote_chain_upload_path(
            milestone.idea,
            source_workspace=spec.repo.workspace,
            target_workspace=launch_ctx.workspace,
        )))
    for source, destination in _chain_anchor_uploads(local_spec_path, launch_ctx.remote_spec_path, chain_spec):
        _append_unique_upload(uploads, source, destination)
    _ensure_repo_checkout(spec, provider, relay=False)
    for source, destination in uploads:
        provider.upload_file(source, destination)
    provider.upload_file(local_spec_path, launch_ctx.remote_spec_path)

    command = _chain_start_command(
        launch_ctx.remote_spec_path,
        project_dir=launch_ctx.workspace,
        engine_dir=spec.megaplan.src_path,
        one_shot=bool(getattr(args, "one", False)),
        no_git_refresh=bool(getattr(args, "no_git_refresh", False)),
        log_relative=launch_ctx.log_relative,
        repair_session=launch_ctx.session_name,
        repair_run_kind="chain",
        repair_marker_dir=str(PurePosixPath(launch_ctx.marker_path).parent),
    )
    operation_id = f"cloud-chain:{launch_ctx.identity}"
    request_id = f"cloud-chain-request:{launch_ctx.digest}"
    launch_spec = {
        "command": command,
        "cwd": launch_ctx.workspace,
        "operation_type": "megaplan_chain",
        "launch_intent": "megaplan_chain",
        "process_resource_id": f"launch-process-session:{operation_id}:{request_id}",
        "process_session_identity": launch_ctx.session_name,
        "expected_session_name": launch_ctx.session_name,
        "plan_id": launch_ctx.identity,
        "source_revision": str(spec.megaplan.ref),
        "configured_spec": str(local_spec_path),
    }
    observations = {
        "source": {"status": "current", "revision": str(spec.megaplan.ref), "ref": str(spec.megaplan.ref), "tree": str(project_root)},
        "authority": {"status": "current", "grant": launch_ctx.identity, "fence": launch_ctx.identity, "decision": launch_ctx.identity},
        "custody": {"status": "present", "custody_ref": launch_ctx.workspace, "wbc_ref": launch_ctx.workspace},
        "credentials": {"status": "available", "identity": spec.provider, "transport": spec.provider},
        "runtime": {"status": "present", "interpreter": spec.megaplan.runtime_python or "python", "import_root": spec.megaplan.src_path, "source_revision": str(spec.megaplan.ref)},
        "command": {"status": "valid", "argv": command, "cwd": launch_ctx.workspace, "env": {}},
        "namespace": {"status": "valid", "name": launch_ctx.session_name},
        "collision": {"status": "none", "namespace": launch_ctx.session_name},
        "capacity": {"status": "available", "disk": "remote", "inode": "remote", "output": "bounded", "temp": "remote"},
        "network": {"status": "available", "transport": spec.provider},
    }
    preflight = run_launch_preflight(launch_spec, observations)
    envelope = LaunchEnvelope(
        version=1,
        operation_id=operation_id,
        request_id=request_id,
        venue=f"cloud:{spec.provider}",
        launch_spec=launch_spec,
        preflight_digest=preflight.preflight_digest,
    )
    request = build_launch_request(
        envelope=envelope,
        command=command,
        cwd=launch_ctx.workspace,
        session=launch_ctx.session_name,
        preflight_observations=observations,
        ops_store_root=(
            provider.authoritative_store_root()
            if callable(getattr(provider, "authoritative_store_root", None))
            else None
        ),
    )
    invoke_engine = getattr(provider, "invoke_launch_engine", None)
    if not callable(invoke_engine):
        response = {
            "schema": "arnold.megaplan.cloud_launch_response.v1",
            "result": "UNKNOWN",
            "reason": "transport_unavailable",
            "invoked": False,
            "detail": "provider does not expose the authoritative launch boundary",
        }
    else:
        response = invoke_engine(request)
    sys.stdout.write(json.dumps(response, indent=2, sort_keys=True) + "\n")
    if response.get("result") == "ACCEPTED":
        return 0
    if response.get("result") == "UNKNOWN":
        raise CliError("launch_unknown", "authoritative engine response is UNKNOWN; query the operation view")
    raise CliError("launch_rejected", str(response.get("detail") or response.get("reason") or "launch rejected"))


def _prepare_chain_inputs(root, args, spec, provider, local_spec_path, project_root, chain_spec, launch_ctx):
    """Upload-only preparation helper; it never performs admission/dispatch."""
    for milestone in chain_spec.milestones:
        source, _ = _resolve_local_idea_source(
            root=project_root,
            idea_dir=Path(args.idea_dir).expanduser().resolve() if args.idea_dir else local_spec_path.parent.resolve(),
            workspace=spec.repo.workspace,
            remote_path=milestone.idea,
        )
        if source is None:
            raise CliError("missing_idea_file", f"milestone '{milestone.label}' idea not found")
        provider.upload_file(source, _remote_chain_upload_path(milestone.idea, source_workspace=spec.repo.workspace, target_workspace=launch_ctx.workspace))
    provider.upload_file(local_spec_path, launch_ctx.remote_spec_path)
    sys.stdout.write(json.dumps({"success": True, "event": "cloud_chain_prepared", "remote_spec": launch_ctx.remote_spec_path, "runner_started": False}, indent=2) + "\n")
    return 0


def _run_chain_wrapper(root: Path, args: argparse.Namespace, spec: CloudSpec, provider) -> int:
    return _run_authoritative_chain_wrapper(root, args, spec, provider)
def _run_launch_epic_wrapper(root: Path, args: argparse.Namespace, spec: CloudSpec, provider) -> int:
    materialized = _materialize_canonical_epic_input(
        root=root,
        spec=spec,
        spec_or_dir=args.spec_or_dir,
        slug_override=getattr(args, "slug", None),
    )
    sys.stderr.write(
        "cloud launch-epic canonicalized: "
        f"slug={materialized.slug} "
        f"spec={materialized.spec_path} "
        f"generated_chain={materialized.generated_chain}\n"
    )
    chain_args = argparse.Namespace(
        **{
            **vars(args),
            "spec": str(materialized.spec_path),
            "idea_dir": str(materialized.project_root),
            "_canonicalized_epic": True,
            "_generated_canonical_files": materialized.created_files,
        }
    )
    return _run_chain_wrapper(root, chain_args, spec, provider)


def _validate_epic_chain_local_inputs(
    *,
    project_root: Path,
    local_spec_path: Path,
    epic_chain_spec: Any,
) -> None:
    from arnold_pipelines.megaplan import chain as chain_module

    parent_north_star = getattr(getattr(epic_chain_spec, "anchors", None), "north_star", None)
    if parent_north_star:
        _resolve_chain_local_artifact(
            parent_north_star,
            project_root=project_root,
            spec_dir=local_spec_path.parent,
        )
    for child in getattr(epic_chain_spec, "epics", []):
        child_spec_path = Path(child.spec).expanduser()
        if not child_spec_path.is_absolute():
            child_spec_path = (local_spec_path.parent / child.spec).resolve()
        if not child_spec_path.is_file():
            raise CliError(
                "missing_epic_artifact",
                f"child epic {child.id!r} spec not found: {child_spec_path}",
            )
        chain_spec = chain_module.load_spec(child_spec_path)
        chain_module.chain_spec.validate_anchor_requirement(chain_spec, child_spec_path)
        child_north_star = getattr(getattr(chain_spec, "anchors", None), "north_star", None)
        if child_north_star:
            _resolve_chain_local_artifact(
                child_north_star,
                project_root=project_root,
                spec_dir=child_spec_path.parent,
            )
        for milestone in getattr(chain_spec, "milestones", []):
            _resolve_chain_local_artifact(
                milestone.idea,
                project_root=project_root,
                spec_dir=child_spec_path.parent,
            )
            milestone_north_star = getattr(getattr(milestone, "anchors", None), "north_star", None)
            if milestone_north_star:
                _resolve_chain_local_artifact(
                    milestone_north_star,
                    project_root=project_root,
                    spec_dir=child_spec_path.parent,
                )


def _epic_chain_state_reset_command(*, workspace: str, state_path: str, force: bool) -> str:
    if not force:
        return "true"
    script = f"""
import json, hashlib, os, pathlib, shutil, sys
workspace = pathlib.Path({workspace!r})
state_path = pathlib.Path({state_path!r})
removed = []
reason = None
plan_dir = None
state_unreadable = None
if state_path.exists():
    try:
        raw = json.loads(state_path.read_text())
    except Exception as exc:
        raw = {{}}
        state_unreadable = "state_unreadable: " + str(exc)
        reason = state_unreadable
    if state_unreadable is None and not isinstance(raw, dict):
        raw = {{}}
        state_unreadable = "state_unreadable: state root is not a JSON object"
        reason = state_unreadable
    if state_unreadable:
        # G6 round-6: a corrupt/unreadable state file means the true
        # plan/target is UNKNOWN.  Block the reset and preserve the state
        # file: the census must never run against an empty-derived target and
        # must never yield CLEAR (delete-on-unknown never happens).
        print(json.dumps({{
            "status": "blocked",
            "reason": state_unreadable,
            "state_path": str(state_path),
            "plan_dir": None,
            "census_reasons": [],
        }}, sort_keys=True))
        sys.exit(0)
    # The parent epic-chain drives one child chain at a time.  The plan dir
    # the parent's state live-references is the CURRENT child's plan dir:
    # current_spec_path -> child chain state (.chains/<stem>-<digest>.json
    # next to the child spec) -> current_plan_name -> <workspace>/.megaplan/
    # plans/<plan> (the child runner's project root falls back to the
    # epic-chain workspace cwd).
    current_spec_path = raw.get("current_spec_path")
    if isinstance(current_spec_path, str) and current_spec_path:
        child_spec = pathlib.Path(current_spec_path)
        child_digest = hashlib.sha1(str(child_spec.resolve()).encode("utf-8")).hexdigest()[:12]
        child_state_path = (
            child_spec.parent
            / ".megaplan"
            / "plans"
            / ".chains"
            / f"{{child_spec.stem}}-{{child_digest}}.json"
        )
        child_plan = None
        child_state_unreadable = None
        if child_state_path.exists():
            try:
                child_raw = json.loads(child_state_path.read_text())
            except Exception as exc:
                child_raw = {{}}
                child_state_unreadable = "child_state_unreadable: " + str(exc)
            if child_state_unreadable is None and not isinstance(child_raw, dict):
                child_raw = {{}}
                child_state_unreadable = "child_state_unreadable: child state root is not a JSON object"
            if child_state_unreadable:
                # G6 round-8: the CHILD chain state determines the plan dir /
                # target; unreadable means UNKNOWN.  Block the reset and
                # preserve the parent state + plan dir: the census must never
                # run against an empty-derived target (child_raw={{}} ->
                # plan_dir=None -> CLEAR -> unlink/rmtree never happens).
                print(json.dumps({{
                    "status": "blocked",
                    "reason": child_state_unreadable,
                    "state_path": str(state_path),
                    "plan_dir": None,
                    "census_reasons": [],
                }}, sort_keys=True))
                sys.exit(0)
            child_plan = child_raw.get("current_plan_name")
        if isinstance(child_plan, str) and child_plan and "/" not in child_plan:
            candidate = workspace / ".megaplan" / "plans" / child_plan
            try:
                candidate.relative_to(workspace / ".megaplan" / "plans")
                plan_dir = candidate
            except ValueError:
                plan_dir = None
    # T-0027: the epic-chain reset is behind the canonical reference census,
    # exactly like _chain_state_reset_command.  A plan dir holding referenced
    # custody/leases must not be removed, and an unreadable/corrupt reference
    # store blocks the reset (fail-closed: delete-on-unknown never happens;
    # --fresh is NOT evidence of safety).  The census runs BEFORE any state
    # unlink / rmtree so a blocked reset leaves the chain state untouched.
    census_verdict = "CLEAR"
    census_reasons = []
    if plan_dir is not None and plan_dir.exists():
        try:
            from arnold_pipelines.megaplan.cloud.runtime_references import run_census
            census_verdict, census_reasons = run_census(
                root=str(plan_dir),
                workspace=os.environ.get("ARNOLD_BASE_DIR", ""),
                manifest_store=os.environ.get("ARNOLD_RUNTIME_MANIFEST_DIR", "/workspace/.megaplan"),
                current_manifest="",
                chain_store=os.environ.get("ARNOLD_REFERENCE_CHAIN_STORE", "/workspace/.megaplan/plans/.chains"),
                marker_store=os.environ.get("ARNOLD_REFERENCE_MARKER_STORE", "/workspace/.megaplan/cloud-sessions:/workspace/watchdog-reports"),
                schedule_store=os.environ.get("ARNOLD_REFERENCE_SCHEDULE_STORES", "/workspace/arnold/.megaplan/resident/scheduled_jobs:/workspace/arnold/.megaplan/resident/schedules/heads:/workspace/.megaplan/ops/schedules"),
                repair_queue=os.environ.get("ARNOLD_REFERENCE_REPAIR_QUEUE", "/workspace/.megaplan/repair-queue"),
                lease_store=os.environ.get("ARNOLD_REFERENCE_LEASE_STORE", str(pathlib.Path.home() / ".megaplan" / "custody" / "leases")),
            )
        except Exception as exc:
            census_verdict = "UNKNOWN"
            census_reasons = [f"reference census unavailable: {{exc}}"]
    if census_verdict != "CLEAR":
        print(json.dumps({{
            "status": "blocked",
            "reason": "reference-census-" + census_verdict,
            "state_path": str(state_path),
            "plan_dir": str(plan_dir) if plan_dir is not None else None,
            "census_reasons": census_reasons,
        }}, sort_keys=True))
    else:
        state_path.unlink(missing_ok=True)
        removed.append(str(state_path))
        if plan_dir is not None and plan_dir.exists():
            try:
                shutil.rmtree(plan_dir)
                removed.append(str(plan_dir))
            except Exception as exc:
                print("[epic-chain-reset] skipped plan dir:", exc)
        print(json.dumps({{"status": "reset", "reason": reason, "removed": removed}}, sort_keys=True))
else:
    print(json.dumps({{"status": "absent", "state_path": str(state_path)}}, sort_keys=True))
"""
    return f"python3 - <<'MEGAPLAN_EPIC_CHAIN_RESET'\n{script.strip()}\nMEGAPLAN_EPIC_CHAIN_RESET"


def _epic_chain_launch_verification_command(
    *,
    workspace: str,
    session_name: str,
    remote_spec_path: str,
    state_path: str,
    marker_path: str,
    log_path: str,
    attempts: int = _CHAIN_VERIFY_ATTEMPTS,
    sleep_seconds: int = _CHAIN_VERIFY_SLEEP_SECONDS,
) -> str:
    script = f"""
import json, pathlib, subprocess, time
workspace = pathlib.Path({workspace!r})
session = {session_name!r}
remote_spec = pathlib.Path({remote_spec_path!r})
state_path = pathlib.Path({state_path!r})
marker_path = pathlib.Path({marker_path!r})
log_path = pathlib.Path({log_path!r})
attempts = {int(attempts)!r}
sleep_seconds = {int(sleep_seconds)!r}
last = {{}}
for idx in range(max(1, attempts)):
    alive = subprocess.run(["tmux", "has-session", "-t", session], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    marker = None
    state = None
    if marker_path.exists():
        try:
            marker = json.loads(marker_path.read_text())
        except Exception as exc:
            marker = {{"error": str(exc)}}
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text())
        except Exception as exc:
            state = {{"error": str(exc)}}
    advanced = bool(state and (
        state.get("current_epic_id")
        or state.get("current_spec_path")
        or state.get("completed")
        or int(state.get("current_epic_index", -1)) >= 0
    ))
    last = {{
        "session_alive": alive,
        "workspace_present": workspace.is_dir(),
        "spec_present": remote_spec.is_file(),
        "marker_present": marker_path.is_file(),
        "state_present": state_path.is_file(),
        "advanced_past_init": advanced,
        "epic_chain_log": str(log_path),
        "epic_chain_log_size": log_path.stat().st_size if log_path.exists() else 0,
        "marker": marker,
        "attempts": idx + 1,
    }}
    if alive and last["spec_present"] and last["marker_present"] and advanced:
        break
    if idx + 1 < attempts:
        time.sleep(sleep_seconds)
log_tail = []
if log_path.exists():
    try:
        log_tail = log_path.read_text(errors="replace").splitlines()[-80:]
    except Exception as exc:
        log_tail = [f"<unable to read epic-chain log: {{exc}}>"]
tail_text = "\\n".join(log_tail)
likely = None
failure_code = None
if not last.get("session_alive"):
    likely = "driver exited before epic-chain state advanced; inspect epic-chain log"
elif not last.get("advanced_past_init"):
    likely = "epic-chain stayed at init; inspect epic-chain log for startup failures"
last["likely_cause"] = likely
last["failure_code"] = failure_code
last["log_tail"] = log_tail
last["status"] = "ok" if last.get("session_alive") and last.get("spec_present") and last.get("marker_present") and last.get("advanced_past_init") else "warning"
print(json.dumps(last, sort_keys=True))
"""
    return f"python3 - <<'MEGAPLAN_EPIC_CHAIN_VERIFY'\n{script.strip()}\nMEGAPLAN_EPIC_CHAIN_VERIFY"


def _run_epic_chain_launch_verification(provider, ctx: ChainLaunchContext) -> dict[str, Any]:
    result = provider.ssh_exec(
        _epic_chain_launch_verification_command(
            workspace=ctx.workspace,
            session_name=ctx.session_name,
            remote_spec_path=ctx.remote_spec_path,
            state_path=ctx.state_path,
            marker_path=ctx.marker_path,
            log_path=ctx.log_path,
        )
    )
    raw = (result.stdout or "").strip().splitlines()
    if result.returncode != 0:
        return {
            "status": "verification_failed",
            "session_alive": False,
            "likely_cause": (result.stderr or result.stdout or "verification command failed").strip(),
        }
    try:
        return json.loads(raw[-1] if raw else "{}")
    except json.JSONDecodeError as exc:
        return {
            "status": "verification_unparseable",
            "likely_cause": f"verification output was not JSON: {exc}",
            "raw": result.stdout,
        }


def _legacy_epic_chain_wrapper(root: Path, args: argparse.Namespace, spec: CloudSpec, provider) -> int:
    from arnold_pipelines.megaplan.chain import epic_chain as epic_chain_module

    local_spec_path = Path(args.spec).expanduser().resolve()
    project_root = _chain_project_root(local_spec_path, root)
    epic_chain_spec = epic_chain_module.load_epic_chain_spec(local_spec_path)
    _validate_epic_chain_local_inputs(
        project_root=project_root,
        local_spec_path=local_spec_path,
        epic_chain_spec=epic_chain_spec,
    )

    launch_ctx = _derive_epic_chain_launch_context(
        root=project_root,
        spec=spec,
        local_spec_path=local_spec_path,
        epic_chain_spec=epic_chain_spec,
    )
    launch_spec = replace(
        spec,
        repo=replace(spec.repo, workspace=launch_ctx.workspace),
        chain_session=launch_ctx.session_name,
    )
    _ensure_repo_checkout(launch_spec, provider, relay=False)
    seed_codex_oauth(spec, provider)

    clean_result = provider.ssh_exec(_clean_remote_durable_megaplan_command(launch_ctx.workspace))
    if clean_result.returncode != 0:
        _relay_output(clean_result, secret_names=spec.secrets, env=os.environ)
        raise CliError(
            "provider_failed",
            f"remote .megaplan durable clean failed (exit {clean_result.returncode})",
        )
    uploads = _durable_megaplan_uploads(project_root, launch_ctx.workspace)
    archive_path: Path | None = None
    try:
        archive_path = _write_durable_megaplan_archive(project_root, uploads)
        provider.upload_archive(archive_path, launch_ctx.workspace)
    finally:
        if archive_path is not None:
            archive_path.unlink(missing_ok=True)

    relaunch_command = _refresh_then_epic_chain_start_command(
        launch_ctx.remote_spec_path,
        workspace=launch_ctx.workspace,
        one_shot=bool(getattr(args, "one", False)),
        log_relative=launch_ctx.log_relative,
        repair_session=launch_ctx.session_name,
        repair_marker_dir=str(PurePosixPath(launch_ctx.marker_path).parent),
    )
    marker_payload = {
        "session": launch_ctx.session_name,
        "workspace": launch_ctx.workspace,
        "remote_spec": launch_ctx.remote_spec_path,
        "identity_digest": launch_ctx.digest,
        "chain_slug": launch_ctx.slug,
        "run_kind": "epic_chain",
        "run_id": str(uuid.uuid4()),
        "relaunch_command": relaunch_command,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "launch_outcome": _launch_outcome_payload(
            status="starting",
            code="launch_in_progress",
            detail="cloud epic-chain launch is preparing the remote session",
        ),
        "bootstrap_manifest_path": _chain_runtime_manifest_path(launch_ctx.slug),
        "progress_artifact": launch_ctx.log_path,
        "progress_identity": f"epic-chain:{launch_ctx.identity}",
    }
    if bool(getattr(args, "fresh", False)):
        marker_payload["should_run"] = True
        marker_payload["operator_pause"] = None
    try:
        engine_ref_check = _verify_configured_megaplan_ref_advertised(launch_spec)
    except CliError as exc:
        launch_outcome = _launch_outcome_payload(
            status="failed",
            code=exc.code,
            detail=exc.message,
            verification={
                "status": "pre_tmux_ref_check_failed",
                **(exc.extra.get("engine_ref_check") or {}),
            },
            stderr_tail=str((exc.extra.get("engine_ref_check") or {}).get("stderr_tail") or ""),
        )
        _persist_remote_launch_outcome(
            provider,
            ctx=launch_ctx,
            marker_payload=marker_payload,
            launch_outcome=launch_outcome,
            allow_live_session=False,
        )
        exc.extra.setdefault("launch_outcome", launch_outcome)
        exc.extra.setdefault(
            "launch_custody",
            {
                "workspace": launch_ctx.workspace,
                "remote_spec": launch_ctx.remote_spec_path,
                "marker_path": launch_ctx.marker_path,
                "chain_session": launch_ctx.session_name,
            },
        )
        raise
    marker_payload["engine_ref_check"] = engine_ref_check

    reset_result = provider.ssh_exec(
        _epic_chain_state_reset_command(
            workspace=launch_ctx.workspace,
            state_path=launch_ctx.state_path,
            force=bool(getattr(args, "fresh", False)),
        )
    )
    if reset_result.returncode != 0:
        _relay_output(reset_result, secret_names=spec.secrets, env=os.environ)
        raise CliError(
            "provider_failed",
            f"remote epic-chain state reset failed (exit {reset_result.returncode})",
        )
    if bool(getattr(args, "fresh", False)):
        reset_out: dict[str, Any] = {}
        try:
            raw = (reset_result.stdout or "").strip().splitlines()
            reset_out = json.loads(raw[-1]) if raw else {}
        except (ValueError, json.JSONDecodeError):
            reset_out = {}
        if reset_out.get("status") == "blocked":
            _relay_output(reset_result, secret_names=spec.secrets, env=os.environ)
            raise CliError(
                "epic_chain_state_reset_blocked",
                "epic-chain --fresh refused: "
                f"{reset_out.get('reason') or 'reference-census-UNKNOWN'}; "
                "state file and plan dir left untouched",
                extra={"reset": reset_out},
            )

    result = provider.ssh_exec(
        _tmux_epic_chain_launch_command(
            launch_ctx.workspace,
            launch_ctx.remote_spec_path,
            session_name=launch_ctx.session_name,
            log_relative=launch_ctx.log_relative,
            marker_path=launch_ctx.marker_path,
            identity_digest=launch_ctx.digest,
            marker_payload=marker_payload,
            one_shot=bool(getattr(args, "one", False)),
        )
    )
    _relay_output(result, secret_names=spec.secrets, env=os.environ)
    if result.returncode != 0:
        raise CliError(
            "chain_session_collision" if result.returncode == 17 else "provider_failed",
            (result.stderr or result.stdout or "remote tmux launch failed").strip(),
        )
    tracking = _run_watchdog_tracking_verification(provider, launch_ctx)
    if not tracking.get("tracked"):
        launch_outcome = _launch_outcome_payload(
            status="failed",
            code="watchdog_tracking_failed",
            detail="cloud epic-chain launch completed but watchdog could not prove session custody",
            verification=tracking,
        )
        _persist_remote_launch_outcome(
            provider,
            ctx=launch_ctx,
            marker_payload=marker_payload,
            launch_outcome=launch_outcome,
        )
        raise CliError(
            "watchdog_tracking_failed",
            "cloud epic-chain launch completed but watchdog tracking verification failed: "
            + "; ".join(str(item) for item in tracking.get("errors", []) or ["unknown error"]),
            extra={"watchdog_tracking": tracking, "launch_outcome": launch_outcome},
        )
    verification = _run_epic_chain_launch_verification(provider, launch_ctx)
    if verification.get("status") != "ok":
        launch_outcome = _launch_outcome_payload(
            status="failed",
            code=str(verification.get("failure_code") or "launch_not_advanced"),
            detail=str(
                verification.get("likely_cause")
                or "cloud epic-chain launch did not advance past init"
            ),
            verification={**verification, "watchdog_tracking": tracking},
            log_tail=verification.get("log_tail") if isinstance(verification.get("log_tail"), list) else None,
        )
        _persist_remote_launch_outcome(
            provider,
            ctx=launch_ctx,
            marker_payload=marker_payload,
            launch_outcome=launch_outcome,
        )
        raise CliError(
            "launch_not_advanced",
            (
                "cloud epic-chain launch did not advance past init; "
                + str(verification.get("likely_cause") or "inspect the remote epic-chain log")
            ),
            extra={
                "verification": {**verification, "watchdog_tracking": tracking},
                "launch_outcome": launch_outcome,
            },
        )
    success_outcome = _launch_outcome_payload(
        status="running",
        code="success",
        detail="cloud epic-chain launch verified session liveness and state advancement",
        verification={**verification, "watchdog_tracking": tracking},
        log_tail=verification.get("log_tail") if isinstance(verification.get("log_tail"), list) else None,
    )
    _persist_remote_launch_outcome(
        provider,
        ctx=launch_ctx,
        marker_payload=marker_payload,
        launch_outcome=success_outcome,
    )
    sys.stderr.write(
        "cloud epic-chain launch: "
        f"session={launch_ctx.session_name} "
        f"alive={verification.get('session_alive')} "
        f"advanced={verification.get('advanced_past_init')} "
        f"log={launch_ctx.log_path}\n"
    )
    payload = {
        "success": True,
        "workspace": launch_ctx.workspace,
        "remote_spec": launch_ctx.remote_spec_path,
        "chain_session": launch_ctx.session_name,
        "chain_log": launch_ctx.log_path,
        "state_path": launch_ctx.state_path,
        "uploaded_files": len(uploads),
        "uploaded_roots": list(_DURABLE_MEGAPLAN_DIRS),
        "verification": {**verification, "watchdog_tracking": tracking},
        "engine_ref_check": engine_ref_check,
    }
    from arnold_pipelines.megaplan.resident.provenance import safe_provenance_projection

    resident_delegation = safe_provenance_projection()
    if resident_delegation is not None:
        payload["resident_delegation"] = resident_delegation
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")

    marker_path = _marker_dir(_cloud_yaml_path(root, args)) / "last_chain.json"
    marker_path.write_text(
        json.dumps(
            {
                "remote_spec": launch_ctx.remote_spec_path,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "base_branch": epic_chain_spec.base_branch,
                "provenance": payload,
                "engine_ref_check": engine_ref_check,
                "workspace": launch_ctx.workspace,
                "chain_session": launch_ctx.session_name,
                "chain_log": launch_ctx.log_path,
                "provider": spec.provider,
                "provider_identity": _get_provider_identity(spec),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return 0


def _run_epic_chain_wrapper(root: Path, args: argparse.Namespace, spec: CloudSpec, provider) -> int:
    """Upload an epic-chain spec and invoke its co-located launch engine once."""
    from arnold_pipelines.megaplan.chain import epic_chain as epic_chain_module
    from arnold.runtime.durable_ops import LaunchEnvelope, run_launch_preflight
    from arnold_pipelines.megaplan.cloud.chain_drive import build_launch_request

    local_spec_path = Path(args.spec).expanduser().resolve()
    project_root = _chain_project_root(local_spec_path, root)
    epic_chain_spec = epic_chain_module.load_epic_chain_spec(local_spec_path)
    _validate_epic_chain_local_inputs(
        project_root=project_root,
        local_spec_path=local_spec_path,
        epic_chain_spec=epic_chain_spec,
    )
    launch_ctx = _derive_epic_chain_launch_context(
        root=project_root,
        spec=spec,
        local_spec_path=local_spec_path,
        epic_chain_spec=epic_chain_spec,
    )
    _ensure_repo_checkout(spec, provider, relay=False)
    uploads = _durable_megaplan_uploads(project_root, launch_ctx.workspace)
    archive_path: Path | None = None
    try:
        archive_path = _write_durable_megaplan_archive(project_root, uploads)
        provider.upload_archive(archive_path, launch_ctx.workspace)
    finally:
        if archive_path is not None:
            archive_path.unlink(missing_ok=True)
    provider.upload_file(local_spec_path, launch_ctx.remote_spec_path)

    command = _epic_chain_start_command(
        launch_ctx.remote_spec_path,
        workspace=launch_ctx.workspace,
        one_shot=bool(getattr(args, "one", False)),
        log_relative=launch_ctx.log_relative,
        repair_session=launch_ctx.session_name,
        repair_marker_dir=str(PurePosixPath(launch_ctx.marker_path).parent),
    )
    operation_id = f"cloud-epic-chain:{launch_ctx.identity}"
    request_id = f"cloud-epic-chain-request:{launch_ctx.digest}"
    launch_spec = {
        "command": command,
        "cwd": launch_ctx.workspace,
        "operation_type": "megaplan_epic_chain",
        "launch_intent": "megaplan_epic_chain",
        "process_resource_id": f"launch-process-session:{operation_id}:{request_id}",
        "process_session_identity": launch_ctx.session_name,
        "expected_session_name": launch_ctx.session_name,
        "plan_id": launch_ctx.identity,
        "source_revision": str(spec.megaplan.ref),
        "configured_spec": str(local_spec_path),
    }
    observations = {
        "source": {"status": "current", "revision": str(spec.megaplan.ref), "ref": str(spec.megaplan.ref), "tree": str(project_root)},
        "authority": {"status": "current", "grant": launch_ctx.identity, "fence": launch_ctx.identity, "decision": launch_ctx.identity},
        "custody": {"status": "present", "custody_ref": launch_ctx.workspace, "wbc_ref": launch_ctx.workspace},
        "credentials": {"status": "available", "identity": spec.provider, "transport": spec.provider},
        "runtime": {"status": "present", "interpreter": spec.megaplan.runtime_python or "python", "import_root": spec.megaplan.src_path, "source_revision": str(spec.megaplan.ref)},
        "command": {"status": "valid", "argv": command, "cwd": launch_ctx.workspace, "env": {}},
        "namespace": {"status": "valid", "name": launch_ctx.session_name},
        "collision": {"status": "none", "namespace": launch_ctx.session_name},
        "capacity": {"status": "available", "disk": "remote", "inode": "remote", "output": "bounded", "temp": "remote"},
        "network": {"status": "available", "transport": spec.provider},
    }
    preflight = run_launch_preflight(launch_spec, observations)
    envelope = LaunchEnvelope(
        version=1,
        operation_id=operation_id,
        request_id=request_id,
        venue=f"cloud:{spec.provider}",
        launch_spec=launch_spec,
        preflight_digest=preflight.preflight_digest,
    )
    request = build_launch_request(
        envelope=envelope,
        command=command,
        cwd=launch_ctx.workspace,
        session=launch_ctx.session_name,
        preflight_observations=observations,
        ops_store_root=(
            provider.authoritative_store_root()
            if callable(getattr(provider, "authoritative_store_root", None))
            else None
        ),
    )
    invoke_engine = getattr(provider, "invoke_launch_engine", None)
    response = invoke_engine(request) if callable(invoke_engine) else {
        "schema": "arnold.megaplan.cloud_launch_response.v1",
        "result": "UNKNOWN",
        "reason": "transport_unavailable",
        "invoked": False,
        "detail": "provider does not expose the authoritative launch boundary",
    }
    sys.stdout.write(json.dumps(response, indent=2, sort_keys=True) + "\n")
    if response.get("result") == "ACCEPTED":
        return 0
    if response.get("result") == "UNKNOWN":
        raise CliError("launch_unknown", "authoritative engine response is UNKNOWN; query the operation view")
    raise CliError("launch_rejected", str(response.get("detail") or response.get("reason") or "launch rejected"))


def _derive_bootstrap_session_name(spec: CloudSpec) -> str:
    repo_slug = _repo_dir_name(spec.repo.url)
    workspace_slug = _slugify_chain_identity(PurePosixPath(spec.repo.workspace).name)
    workspace_slug = re.sub(r"-20[0-9]{6}$", "", workspace_slug)
    if repo_slug and workspace_slug.startswith(repo_slug):
        return repo_slug
    return repo_slug or workspace_slug or "megaplan-plan"


def _derive_bootstrap_plan_name(args: argparse.Namespace, *, idea_text: str) -> str:
    explicit = getattr(args, "plan_name", None)
    if explicit:
        return explicit
    from arnold_pipelines.megaplan._core.io import slugify

    timestamp = datetime.now().strftime("%Y%m%d-%H%M")
    return f"{slugify(idea_text)}-{timestamp}"


def _bootstrap_log_relative(plan_name: str) -> str:
    return f".megaplan/cloud-logs/{plan_name}.log"


def _bootstrap_marker_payload(
    *,
    session_name: str,
    workspace: str,
    remote_spec: str,
    plan_name: str,
    relaunch_command: str,
) -> dict[str, Any]:
    # These are producer bindings, not ambient selector inputs.  The remote
    # atomic writer fills the runtime-local supervisor/boot/container values
    # and content digests immediately before publishing the marker.
    workspace_path = Path(workspace).expanduser()
    manifest_path = workspace_path / ".megaplan" / "runtime-manifest.json"
    progress_path = workspace_path / _bootstrap_log_relative(plan_name)
    return {
        "session": session_name,
        "workspace": workspace,
        "remote_spec": remote_spec,
        "run_kind": "plan",
        "run_id": str(uuid.uuid4()),
        "plan_name": plan_name,
        "relaunch_command": relaunch_command,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "bootstrap_manifest_path": str(manifest_path),
        "progress_artifact": str(progress_path),
        "progress_identity": f"plan:{plan_name}",
    }


def _bootstrap_launch_command(
    *,
    workspace: str,
    remote_idea_path: str,
    plan_name: str,
    robustness: str,
    session_name: str,
) -> str:
    marker_path = str(PurePosixPath(_CHAIN_SESSION_MARKER_DIR) / f"{session_name}.json")
    log_relative = _bootstrap_log_relative(plan_name)
    relaunch_command = _plan_auto_command(
        plan_name,
        workspace=workspace,
        log_relative=log_relative,
        repair_session=session_name,
        repair_marker_dir=str(PurePosixPath(marker_path).parent),
    )
    marker_payload = _bootstrap_marker_payload(
        session_name=session_name,
        workspace=workspace,
        remote_spec=remote_idea_path,
        plan_name=plan_name,
        relaunch_command=relaunch_command,
    )
    log_target = shlex.quote(str(PurePosixPath(workspace) / log_relative))
    # Manifest-bound bootstrap (T-0021): the engine dir (PYTHONPATH) derives
    # ONLY from the per-session ARNOLD_RUNTIME_MANIFEST pin; there is no
    # megaplan.src_path read and no /workspace/arnold fallback.  Missing,
    # unreadable, or disagreeing pins exit 24 BEFORE init loads any state.
    prefix = (
        'PINNED_RUNTIME_MANIFEST="${ARNOLD_RUNTIME_MANIFEST:-}"; '
        'readonly PINNED_RUNTIME_MANIFEST; '
    )
    prefix += (
        f"if [ -f {shlex.quote(_CLOUD_HOT_ENV_PATH)} ]; then "
        f"set -a; . {shlex.quote(_CLOUD_HOT_ENV_PATH)}; set +a; fi; "
        'if [ -n "$PINNED_RUNTIME_MANIFEST" ]; then '
        'export ARNOLD_RUNTIME_MANIFEST="$PINNED_RUNTIME_MANIFEST"; '
        'fi; '
    )
    prefix += _managed_run_env_prefix(
        session_name,
        run_kind="plan",
        marker_dir=str(PurePosixPath(marker_path).parent),
    )
    # G5 round-6 finding 1a: the mkdir -p is a side effect, so it must NOT
    # run before the manifest pin gate — a missing/unreadable pin exits 24
    # with ZERO filesystem side effects.  The dir creation is therefore
    # passed INTO the gate as post_pin_checks: it runs only after the pin
    # existence/readability checks pass, and before the ENGINE_DIR reads +
    # provenance so the log redirect still has a cloud-logs dir on a fresh
    # workspace.
    prefix += _manifest_pin_fail_closed_prefix(
        log_target,
        post_pin_checks=(
            f"mkdir -p {shlex.quote(str(PurePosixPath(marker_path).parent))} "
            f"{shlex.quote(str(PurePosixPath(workspace) / '.megaplan' / 'cloud-logs'))} "
            "|| exit 1"
        ),
    )
    command = (
        # G5 round-2 finding 1: the manifest pin gate (pin existence /
        # readability, ENGINE_DIR provenance) runs BEFORE the session-marker
        # write — on a missing/unreadable pin the command exits 24 with ZERO
        # marker side effects.
        f"{prefix}cd {shlex.quote(workspace)} && "
        f"{_write_session_marker_command(marker_path, marker_payload)} && "
        "env -u PYTHONHOME PYTHONSAFEPATH=1 "
        'PYTHONPATH="$ENGINE_DIR" '
        '"$GEN_INTERPRETER" -P -m arnold_pipelines.megaplan init '
        f"--project-dir {shlex.quote(workspace)} "
        f"--idea-file {shlex.quote(remote_idea_path)} --auto-start "
        f"--robustness {shlex.quote(robustness)} --name {shlex.quote(plan_name)}"
    )
    return command


def _run_bootstrap_wrapper(args: argparse.Namespace, spec: CloudSpec, provider) -> int:
    local_idea_path = Path(args.idea_file).expanduser().resolve()
    if not local_idea_path.exists():
        raise CliError("missing_idea_file", f"idea file not found: {local_idea_path}")
    idea_text = local_idea_path.read_text(encoding="utf-8")
    plan_name = _derive_bootstrap_plan_name(args, idea_text=idea_text)
    remote_idea_path = str(PurePosixPath(spec.repo.workspace) / "idea.txt")
    _ensure_repo_checkout(spec, provider)
    provider.upload_file(local_idea_path, remote_idea_path)
    command = _bootstrap_launch_command(
        workspace=spec.repo.workspace,
        remote_idea_path=remote_idea_path,
        plan_name=plan_name,
        robustness=args.robustness,
        session_name=_derive_bootstrap_session_name(spec),
    )
    result = provider.ssh_exec(command)
    _relay_output(result, secret_names=spec.secrets, env=os.environ)
    return 0


def _resolve_remote_chain_spec(root: Path, args: argparse.Namespace, spec: CloudSpec) -> str:
    explicit = getattr(args, "remote_spec", None)
    if explicit:
        return explicit

    marker_path = _marker_path_no_create(_cloud_yaml_path(root, args)) / "last_chain.json"
    try:
        if marker_path.exists():
            try:
                marker = json.loads(marker_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                marker = {}
            remote_spec = marker.get("remote_spec")
            if isinstance(remote_spec, str) and remote_spec:
                return remote_spec
    except OSError:
        pass  # marker dir not accessible, fall through to spec fallback

    if spec.mode == "chain" and spec.chain is not None:
        return spec.chain.spec

    raise CliError(
        "missing_remote_spec",
        "Unable to locate remote chain spec. Pass --remote-spec <path>, run `cloud chain <spec>` first, or set mode: chain in cloud.yaml.",
    )


def _run_chain_status(root: Path, args: argparse.Namespace, spec: CloudSpec, provider) -> int:
    payload = cloud_chain_status_payload(root, args, spec, provider)
    from arnold_pipelines.megaplan import chain as chain_module

    chain_module._write_chain_status_pretty(payload["summary"], writer=sys.stderr.write)
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    return 0


def _run_supervise_tick(root: Path, args: argparse.Namespace, spec: CloudSpec, provider) -> int:
    """Entrypoint for `arnold cloud supervise --chain`.

    Reads chain status, runs supervisor logic, emits JSON on stdout and a
    human-readable summary on stderr.  The full supervision policy is
    implemented in :func:`cloud_supervise_tick`.
    """
    # ── deferred import to keep the CLI module's top-level light ──────────
    from arnold_pipelines.megaplan.cloud.supervise import cloud_supervise_tick  # noqa: F811

    report = cloud_supervise_tick(root, args, spec, provider)

    # Human-readable summary on stderr.
    event = report.get("event", "unknown")
    acted = report.get("acted", False)
    next_action = report.get("next_action", "none")
    refused = report.get("refused_reason")
    status_line = f"supervisor tick: {event} | acted={acted} | next_action={next_action}"
    if refused:
        status_line += f" | refused_reason={refused}"
    sys.stderr.write(status_line + "\n")

    sys.stdout.write(json.dumps(report, indent=2) + "\n")
    return 0 if report.get("success") else 1


def cloud_status_payload(args: argparse.Namespace, spec: CloudSpec, provider) -> dict[str, Any]:
    """Return the same payload printed by `arnold cloud status`."""
    observation = _provider_container_observation(provider)
    capacity = (
        _provider_prelaunch_capacity(provider) if spec.provider == "ssh" else None
    )
    if not _container_collector_ready(observation) or (
        isinstance(capacity, Mapping) and capacity.get("verdict") != "GO"
    ):
        raise _collector_unavailable_error(
            observation
            or {
                "status": "unknown",
                "lifecycle": "unknown",
                "collector": {"status": "unavailable", "reason": "observer_unavailable"},
            },
            capacity=capacity,
        )
    return provider.status_payload(
        plan=getattr(args, "plan", None),
        workspace=spec.repo.workspace,
    )


def _cloud_chains_command() -> str:
    script = f"""
import json, pathlib, re, subprocess, time
from datetime import datetime, timezone
from arnold_pipelines.megaplan.cloud.session_markers import is_canonical_session_marker_path
marker_dir = pathlib.Path({_CHAIN_SESSION_MARKER_DIR!r})
proc = subprocess.run(["tmux", "list-sessions", "-F", "#S"], text=True, capture_output=True)
sessions_by_name = {{}}
tmux_names = set()
untracked_tmux_sessions = []
watchdog_by_session = {{}}

def _mtime_payload(path):
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return {{"mtime": 0.0, "updated_at": ""}}
    return {{
        "mtime": mtime,
        "updated_at": datetime.fromtimestamp(mtime, timezone.utc).isoformat().replace("+00:00", "Z"),
    }}

def _process_status(remote_spec, workspace="", plan_name=""):
    needles = [value for value in (remote_spec, workspace, plan_name) if value]
    if not needles:
        return "unknown"
    ps = subprocess.run(["ps", "-eww", "-o", "args="], text=True, capture_output=True)
    if ps.returncode != 0:
        return "unknown"
    for line in ps.stdout.splitlines():
        if "arnold_pipelines.megaplan" not in line:
            continue
        if all(needle in line for needle in needles[:1]):
            if (
                " chain start" in line
                or " epic-chain start" in line
                or " auto " in line
            ):
                return "alive"
    return "dead"

def _load_health(name):
    path = marker_dir / (name + ".chain-health.progress.json")
    payload = {{"status": "missing", "path": str(path)}}
    if not path.exists():
        return payload
    payload.update(_mtime_payload(path))
    try:
        health = json.loads(path.read_text())
    except Exception as exc:
        payload.update({{"status": "invalid", "error": str(exc)}})
        return payload
    payload.update({{"status": "present", "payload": health}})
    return payload

def _load_watchdog_sessions():
    paths = [
        pathlib.Path("/workspace/watchdog-report.json"),
        pathlib.Path("/workspace/.megaplan/watchdog-report.json"),
    ]
    for path in paths:
        if not path.exists():
            continue
        evidence = {{"status": "present", "path": str(path), **_mtime_payload(path)}}
        try:
            report = json.loads(path.read_text())
        except Exception as exc:
            return {{}}, {{"status": "invalid", "path": str(path), "error": str(exc)}}
        evidence["report_timestamp_utc"] = report.get("timestamp_utc") or report.get("generated_at") or ""
        by_session = {{}}
        for section in ("issues", "items"):
            items = report.get(section)
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                session = item.get("session")
                if not isinstance(session, str) or not session:
                    continue
                by_session[session] = {{
                    "status": "present",
                    "source": section,
                    "path": str(path),
                    "action": item.get("action") or "",
                    "watchdog_status": item.get("status") or "",
                    "message": item.get("message") or "",
                    "remote_spec": item.get("remote_spec") or "",
                    "workspace": item.get("workspace") or "",
                    "report_timestamp_utc": evidence["report_timestamp_utc"],
                }}
        return by_session, evidence
    return {{}}, {{"status": "missing", "path": str(paths[0])}}

def _display_name(payload):
    remote_spec = payload.get("remote_spec") or payload.get("spec") or ""
    if remote_spec:
        parts = pathlib.PurePosixPath(remote_spec).parts
        for marker in (".megaplan",):
            if marker not in parts:
                continue
            idx = parts.index(marker)
            if idx + 2 < len(parts) and parts[idx + 1] in {{"initiatives", "briefs"}}:
                return parts[idx + 2]
        if "/.megaplan/plans/" in remote_spec:
            return pathlib.PurePosixPath(remote_spec).name
    for key in ("plan_name", "name", "chain_slug", "session"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return ""

def _active_step_evidence(workspace, plan_name):
    payload = {{"status": "missing", "path": ""}}
    if not workspace or not plan_name:
        return payload
    path = pathlib.Path(workspace) / ".megaplan" / "plans" / plan_name / "state.json"
    payload["path"] = str(path)
    if not path.exists():
        return payload
    try:
        state = json.loads(path.read_text())
    except Exception as exc:
        return {{"status": "invalid", "path": str(path), "error": str(exc)}}
    current_state = state.get("current_state") or state.get("state") or ""
    config = state.get("config") if isinstance(state.get("config"), dict) else {{}}
    clarification = state.get("clarification") if isinstance(state.get("clarification"), dict) else {{}}
    questions = clarification.get("questions") if isinstance(clarification.get("questions"), list) else []
    common = {{
        "path": str(path),
        "current_state": current_state,
        "auto_approve": config.get("auto_approve"),
        "clarification_source": clarification.get("source") or "",
        "clarification_intent": clarification.get("intent_summary") or "",
        "clarification_question_count": len(questions),
        "clarification_questions": [q for q in questions if isinstance(q, str)][:5],
    }}
    active_step = state.get("active_step")
    if not isinstance(active_step, dict) or not active_step:
        return {{"status": "absent", **common}}
    return {{
        "status": "present",
        **common,
        "phase": active_step.get("phase") or active_step.get("step") or "",
        "name": active_step.get("name") or "",
        "attempt": active_step.get("attempt"),
        "worker_pid": active_step.get("worker_pid"),
        "last_activity_at": active_step.get("last_activity_at") or "",
    }}

def _latest_plan_state_evidence(workspace):
    payload = {{"status": "missing", "path": "", "mtime": 0.0, "updated_at": ""}}
    if not workspace:
        return payload
    plans_dir = pathlib.Path(workspace) / ".megaplan" / "plans"
    if not plans_dir.exists():
        payload["path"] = str(plans_dir)
        return payload
    latest = None
    for path in plans_dir.glob("*/state.json"):
        try:
            stat = path.stat()
        except OSError:
            continue
        if latest is None or stat.st_mtime > latest[0]:
            latest = (stat.st_mtime, path)
    if latest is None:
        payload["path"] = str(plans_dir)
        return payload
    mtime, path = latest
    try:
        state = json.loads(path.read_text())
    except Exception as exc:
        return {{
            "status": "invalid",
            "path": str(path),
            "mtime": mtime,
            "updated_at": datetime.fromtimestamp(mtime, timezone.utc).isoformat().replace("+00:00", "Z"),
            "error": str(exc),
        }}
    current_state = state.get("current_state") or state.get("state") or ""
    active_step = state.get("active_step") if isinstance(state.get("active_step"), dict) else {{}}
    active_phase = active_step.get("phase") or active_step.get("step") or ""
    return {{
        "status": "present",
        "path": str(path),
        "plan": path.parent.name,
        "state": current_state,
        "active_phase": active_phase,
        "mtime": mtime,
        "updated_at": datetime.fromtimestamp(mtime, timezone.utc).isoformat().replace("+00:00", "Z"),
    }}

def _event_activity_evidence(workspace, plan_name):
    payload = {{"status": "missing", "path": "", "mtime": 0.0, "updated_at": ""}}
    if not workspace or not plan_name:
        return payload
    path = pathlib.Path(workspace) / ".megaplan" / "plans" / plan_name / "events.ndjson"
    payload["path"] = str(path)
    if not path.exists():
        return payload
    try:
        mtime = path.stat().st_mtime
        lines = path.read_text(errors="replace").splitlines()[-300:]
    except Exception as exc:
        return {{"status": "invalid", "path": str(path), "error": str(exc)}}
    latest_valid = None
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except Exception:
            continue
        if not isinstance(event, dict):
            continue
        latest_valid = event
        phase = event.get("phase")
        payload_obj = event.get("payload") if isinstance(event.get("payload"), dict) else {{}}
        if not phase:
            phase = payload_obj.get("phase")
        if phase:
            return {{
                "status": "present",
                "path": str(path),
                "plan": plan_name,
                "phase": str(phase),
                "kind": str(event.get("kind") or ""),
                "seq": event.get("seq"),
                "ts_utc": str(event.get("ts_utc") or ""),
                "mtime": mtime,
                "updated_at": str(event.get("ts_utc") or datetime.fromtimestamp(mtime, timezone.utc).isoformat().replace("+00:00", "Z")),
            }}
    if latest_valid is None:
        return {{
            "status": "empty",
            "path": str(path),
            "plan": plan_name,
            "mtime": mtime,
            "updated_at": datetime.fromtimestamp(mtime, timezone.utc).isoformat().replace("+00:00", "Z"),
        }}
    return {{
        "status": "present",
        "path": str(path),
        "plan": plan_name,
        "phase": "",
        "kind": str(latest_valid.get("kind") or ""),
        "seq": latest_valid.get("seq"),
        "ts_utc": str(latest_valid.get("ts_utc") or ""),
        "mtime": mtime,
        "updated_at": str(latest_valid.get("ts_utc") or datetime.fromtimestamp(mtime, timezone.utc).isoformat().replace("+00:00", "Z")),
    }}

def _policy_evidence(remote_spec):
    payload = {{"status": "missing", "path": remote_spec or ""}}
    if not remote_spec:
        return payload
    path = pathlib.Path(remote_spec)
    if not path.exists():
        return payload
    try:
        text = path.read_text()
    except Exception as exc:
        return {{"status": "invalid", "path": str(path), "error": str(exc)}}
    merge_policy = "auto"
    match = re.search(r"(?m)^merge_policy:\\s*([^\\s#]+)", text)
    if match:
        merge_policy = match.group(1).strip().strip("'\\\"")
    driver_auto_approve = True
    driver_match = re.search(r"(?ms)^driver:\\s*\\n(?P<body>(?:[ \\t]+[^\\n]*\\n?)*)", text)
    if driver_match:
        auto_match = re.search(r"(?m)^[ \\t]+auto_approve:\\s*([^\\s#]+)", driver_match.group("body"))
        if auto_match:
            raw = auto_match.group(1).strip().strip("'\\\"").lower()
            driver_auto_approve = raw in {{"1", "true", "yes", "on"}}
    return {{
        "status": "present",
        "path": str(path),
        "merge_policy": merge_policy,
        "driver_auto_approve": driver_auto_approve,
        "human_gated": merge_policy != "auto" or driver_auto_approve is False,
    }}

def _operator_status(payload):
    status = payload.get("status") or "unknown"
    active = payload.get("active_step_evidence") if isinstance(payload.get("active_step_evidence"), dict) else {{}}
    policy = payload.get("policy_evidence") if isinstance(payload.get("policy_evidence"), dict) else {{}}
    if status == "awaiting_human_verify":
        if active.get("clarification_source") == "prep":
            count = int(active.get("clarification_question_count") or 0)
            return {{
                "status": "blocked_prep_clarification",
                "reason": f"prep clarification waiting for operator ({{count}} question(s))",
                "next_action": "answer clarification and run resume-clarify, or relaunch an unattended cloud chain with driver.auto_approve: true",
            }}
        return {{
            "status": "blocked_human_verification",
            "reason": "plan is awaiting human verification records",
            "next_action": "record human verification verdicts, or relaunch an unattended cloud chain with driver.auto_approve: true",
        }}
    if status == "awaiting_pr_merge":
        return {{
            "status": "blocked_pr_review_policy",
            "reason": f"merge_policy={{policy.get('merge_policy') or 'review'}} requires human PR merge",
            "next_action": "merge the PR, or use merge_policy: auto for unattended cloud chains",
        }}
    if status == "running" and _watchdog_is_repairing(payload.get("watchdog_evidence")):
        return {{
            "status": "running_repairing",
            "reason": "runner process is alive, but watchdog has dispatched repair/meta-repair",
            "next_action": "observe repair artifacts and verify the session advances before relaunching",
        }}
    if status == "running":
        return {{
            "status": "running_phase",
            "reason": "runner or worker process is alive",
            "next_action": "observe progress",
        }}
    if status == "complete":
        return {{
            "status": "complete",
            "reason": "chain is complete",
            "next_action": "none",
        }}
    if policy.get("human_gated") and not payload.get("allow_human_gates"):
        return {{
            "status": "human_gate_misconfigured",
            "reason": f"unacknowledged human-gated policy on cloud session: merge_policy={{policy.get('merge_policy')}} driver.auto_approve={{policy.get('driver_auto_approve')}}",
            "next_action": "switch to merge_policy: auto and driver.auto_approve: true, or relaunch with --allow-human-gates",
        }}
    if policy.get("human_gated"):
        return {{
            "status": status,
            "reason": f"human-gated policy: merge_policy={{policy.get('merge_policy')}} driver.auto_approve={{policy.get('driver_auto_approve')}}",
            "next_action": "expect human pauses, or switch to merge_policy: auto and driver.auto_approve: true",
        }}
    return {{
        "status": status,
        "reason": "",
        "next_action": "inspect logs/state",
    }}

def _payload_for(name):
    marker = marker_dir / (name + ".json")
    payload = {{
        "session": name,
        "marker": str(marker),
        "marker_evidence": {{"status": "missing", "path": str(marker)}},
        "tmux_evidence": {{"status": "alive" if name in tmux_names else "missing"}},
    }}
    if marker.exists():
        payload["marker_evidence"].update(_mtime_payload(marker))
        try:
            payload.update(json.loads(marker.read_text()))
            payload["marker_evidence"].update({{"status": "present", "path": str(marker)}})
        except Exception as exc:
            payload["marker_evidence"] = {{"status": "invalid", "path": str(marker), "error": str(exc)}}
    payload["chain_health_evidence"] = _load_health(name)
    health_payload = payload["chain_health_evidence"].get("payload")
    if isinstance(health_payload, dict):
        payload["health"] = health_payload
    payload["process_evidence"] = {{
        "status": _process_status(
            payload.get("remote_spec") or "",
            payload.get("workspace") or "",
            payload.get("plan_name") or "",
        ),
        "remote_spec": payload.get("remote_spec") or "",
    }}
    plan_name = payload.get("plan_name")
    if not plan_name and isinstance(health_payload, dict):
        plan_name = health_payload.get("current_plan_name")
    payload["latest_plan_state"] = _latest_plan_state_evidence(payload.get("workspace"))
    latest_plan_state = payload["latest_plan_state"] if isinstance(payload["latest_plan_state"], dict) else {{}}
    if not plan_name and latest_plan_state.get("status") == "present":
        plan_name = latest_plan_state.get("plan")
    payload["active_step_evidence"] = _active_step_evidence(payload.get("workspace"), plan_name)
    payload["event_activity_evidence"] = _event_activity_evidence(payload.get("workspace"), plan_name)
    payload["policy_evidence"] = _policy_evidence(payload.get("remote_spec") or "")
    payload["display_name"] = _display_name(payload)
    payload["marker_status"] = payload["marker_evidence"]["status"]
    payload["tmux_status"] = payload["tmux_evidence"]["status"]
    payload["process_status"] = payload["process_evidence"]["status"]
    payload["chain_health_status"] = payload["chain_health_evidence"]["status"]
    payload["active_step_status"] = payload["active_step_evidence"]["status"]
    payload["event_activity_status"] = payload["event_activity_evidence"]["status"]
    payload["watchdog_evidence"] = watchdog_by_session.get(
        name,
        {{"status": "missing", "path": "/workspace/watchdog-report.json"}},
    )
    payload["watchdog_action"] = payload["watchdog_evidence"].get("action", "")
    payload["watchdog_status"] = payload["watchdog_evidence"].get("watchdog_status", "")
    payload["status"] = _effective_session_status(payload)
    payload["operator_status"] = _operator_status(payload)
    payload["status_reason"] = payload["operator_status"].get("reason", "")
    payload["next_action"] = payload["operator_status"].get("next_action", "")
    payload["watchdog_repairing"] = _watchdog_is_repairing(payload["watchdog_evidence"])
    payload["should_be_running"] = _should_be_running(payload)
    return payload

def _watchdog_is_repairing(evidence):
    if not isinstance(evidence, dict) or evidence.get("status") != "present":
        return False
    custody = evidence.get("repair_custody")
    if not isinstance(custody, dict):
        return False
    active_requests = {{str(value) for value in custody.get("active_request_ids", []) if str(value)}}
    active_claims = {{str(value) for value in custody.get("active_claim_request_ids", []) if str(value)}}
    if active_requests & active_claims:
        return True
    for attempt in custody.get("attempts", []):
        if not isinstance(attempt, dict) or attempt.get("terminal") is not False:
            continue
        if not attempt.get("attempt_id") or not attempt.get("path"):
            continue
        request_id = str(attempt.get("request_id") or "")
        if request_id and request_id in active_requests:
            return True
        if attempt.get("source") == "repair_queue_dispatch_attempt" and attempt.get("blocker_id"):
            return True
    return False

def _should_be_running(payload):
    # Explicit operator custody outranks status-shape heuristics. A superseded
    # session is commonly both ``stopped`` and ``should_run: false``; treating
    # every stopped session as resumable made the watchdog repeatedly relaunch
    # intentionally retired work.
    if payload.get("should_run") is False:
        return False
    operator_pause = payload.get("operator_pause")
    if isinstance(operator_pause, dict) and operator_pause.get("active") is True:
        return False
    status = payload.get("status")
    if status == "running":
        return True
    if status in {{
        "complete",
        "awaiting_human_verify",
        "awaiting_pr_merge",
        "blocked",
        "failed",
        "needs_human",
        "authority_divergence",
        "missing_base_ref",
        "retrying_failure",
    }}:
        return False
    watchdog_status = payload.get("watchdog_status")
    if watchdog_status in {{"needs_human", "awaiting_pr_merge"}}:
        return False
    if status in {{"initialized", "prepped", "planned", "gated", "finalized", "executed", "reviewed", "stopped"}}:
        return True
    return False

def _effective_session_status(payload):
    if payload.get("tmux_status") == "alive" or payload.get("process_status") == "alive":
        return "running"
    active_step = payload.get("active_step_evidence")
    if isinstance(active_step, dict):
        current_state = active_step.get("current_state")
        if current_state == "done":
            return "complete"
        if active_step.get("status") == "present" and (
            payload.get("tmux_status") == "alive" or payload.get("process_status") == "alive"
        ):
            return "running"
        if current_state in {{
            "awaiting_human_verify",
            "awaiting_pr_merge",
            "blocked",
            "failed",
            "initialized",
            "prepped",
            "planned",
            "gated",
            "finalized",
            "executed",
                "reviewed",
        }}:
            return str(current_state)
    health = payload.get("health")
    if isinstance(health, dict):
        last_state = health.get("last_state")
        chain_complete = health.get("chain_complete")
        if last_state == "done" and chain_complete is not False:
            return "complete"
        if last_state == "done" and chain_complete is False:
            return "stale_bookkeeping"
        if last_state in {{
            "awaiting_human_verify",
            "awaiting_pr_merge",
            "needs_human",
            "blocked",
            "authority_divergence",
            "missing_base_ref",
            "stalled",
            "retrying_failure",
        }}:
            return str(last_state)
    watchdog_status = payload.get("watchdog_status")
    if watchdog_status == "complete":
        return "complete"
    if watchdog_status in {{"awaiting_pr_merge", "needs_human"}}:
        return str(watchdog_status)
    return "stopped"

watchdog_by_session, watchdog_report_evidence = _load_watchdog_sessions()

if proc.returncode == 0:
    for line in proc.stdout.splitlines():
        name = line.strip()
        if not name:
            continue
        tmux_names.add(name)
        marker = marker_dir / (name + ".json")
        if marker.exists():
            sessions_by_name[name] = _payload_for(name)
        else:
            untracked_tmux_sessions.append(name)
if marker_dir.exists():
    for marker in sorted(marker_dir.glob("*.json")):
        if not is_canonical_session_marker_path(marker):
            continue
        name = marker.stem
        sessions_by_name.setdefault(name, _payload_for(name))
sessions = sorted(sessions_by_name.values(), key=lambda item: item.get("session", ""))
summary = {{}}
operator_summary = {{}}
should_be_running_count = 0
watchdog_repairing_count = 0
for item in sessions:
    summary[item.get("status", "unknown")] = summary.get(item.get("status", "unknown"), 0) + 1
    operator = item.get("operator_status") if isinstance(item.get("operator_status"), dict) else {{}}
    operator_key = operator.get("status") or item.get("status", "unknown")
    operator_summary[operator_key] = operator_summary.get(operator_key, 0) + 1
    if item.get("should_be_running"):
        should_be_running_count += 1
    if item.get("watchdog_repairing"):
        watchdog_repairing_count += 1
print(json.dumps({{
    "success": True,
    "marker_dir": str(marker_dir),
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "sessions": sessions,
    "summary": summary,
    "operator_summary": operator_summary,
    "should_be_running_count": should_be_running_count,
    "watchdog_repairing_count": watchdog_repairing_count,
    "watchdog_report_evidence": watchdog_report_evidence,
    "untracked_tmux_sessions": sorted(untracked_tmux_sessions),
}}, sort_keys=True))
"""
    return f"python3 - <<'MEGAPLAN_CHAINS'\n{script.strip()}\nMEGAPLAN_CHAINS"


_SINCE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhd])\s*$", re.IGNORECASE)


def _parse_cloud_status_since(value: str | None, *, now: datetime | None = None) -> datetime | None:
    if not value:
        return None
    now = now or datetime.now(timezone.utc)
    match = _SINCE_RE.match(value)
    if match:
        amount = float(match.group(1))
        unit = match.group(2).lower()
        seconds_by_unit = {"s": 1, "m": 60, "h": 3600, "d": 86400}
        return now - timedelta(seconds=amount * seconds_by_unit[unit])
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise CliError("invalid_args", f"invalid --since value {value!r}; use a duration like 12h or an ISO timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_cloud_status_timestamp(value: Any) -> datetime | None:
    if isinstance(value, (int, float)) and value > 0:
        return datetime.fromtimestamp(float(value), timezone.utc)
    if not isinstance(value, str) or not value:
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _cloud_session_real_activity_at(item: Mapping[str, Any]) -> datetime | None:
    """Return the newest timestamp tied to actual chain/plan activity.

    Watchdog health files can be rewritten after a chain is done, so this
    intentionally prefers plan ``state.json`` evidence and launch markers over
    watchdog mtimes.
    """
    event_activity = item.get("event_activity_evidence")
    if isinstance(event_activity, Mapping) and event_activity.get("status") in {"present", "empty", "invalid"}:
        timestamp = _parse_cloud_status_timestamp(event_activity.get("updated_at")) or _parse_cloud_status_timestamp(
            event_activity.get("mtime")
        )
        if timestamp is not None:
            return timestamp
    latest_state = item.get("latest_plan_state")
    if isinstance(latest_state, Mapping) and latest_state.get("status") in {"present", "invalid"}:
        timestamp = _parse_cloud_status_timestamp(latest_state.get("updated_at")) or _parse_cloud_status_timestamp(
            latest_state.get("mtime")
        )
        if timestamp is not None:
            return timestamp
    active = item.get("active_step_evidence")
    if isinstance(active, Mapping):
        timestamp = _parse_cloud_status_timestamp(active.get("last_activity_at"))
        if timestamp is not None:
            return timestamp
    return _parse_cloud_status_timestamp(item.get("started_at"))


def _cloud_session_plan_state(item: Mapping[str, Any]) -> str:
    event_activity = item.get("event_activity_evidence")
    if isinstance(event_activity, Mapping) and event_activity.get("phase"):
        return str(event_activity.get("phase"))
    active = item.get("active_step_evidence")
    if isinstance(active, Mapping) and active.get("phase"):
        return str(active.get("phase"))
    latest_state = item.get("latest_plan_state")
    if isinstance(latest_state, Mapping) and latest_state.get("active_phase"):
        return str(latest_state.get("active_phase"))
    if isinstance(latest_state, Mapping) and latest_state.get("state"):
        return str(latest_state.get("state"))
    if isinstance(active, Mapping) and active.get("current_state"):
        return str(active.get("current_state"))
    health = item.get("health")
    if isinstance(health, Mapping) and health.get("last_state"):
        return str(health.get("last_state"))
    return ""


def _recount_cloud_sessions(payload: dict[str, Any], sessions: list[Any]) -> None:
    summary: dict[str, int] = {}
    operator_summary: dict[str, int] = {}
    should_be_running_count = 0
    watchdog_repairing_count = 0
    for item in sessions:
        if not isinstance(item, Mapping):
            continue
        status = str(item.get("status") or "unknown")
        summary[status] = summary.get(status, 0) + 1
        operator = item.get("operator_status") if isinstance(item.get("operator_status"), Mapping) else {}
        operator_key = str(operator.get("status") or status)
        operator_summary[operator_key] = operator_summary.get(operator_key, 0) + 1
        if item.get("should_be_running"):
            should_be_running_count += 1
        if item.get("watchdog_repairing"):
            watchdog_repairing_count += 1
    payload["sessions"] = sessions
    payload["summary"] = summary
    payload["operator_summary"] = operator_summary
    payload["should_be_running_count"] = should_be_running_count
    payload["watchdog_repairing_count"] = watchdog_repairing_count


def _filter_cloud_sessions_since(payload: dict[str, Any], since: datetime | None) -> None:
    if since is None:
        return
    sessions = payload.get("sessions")
    if not isinstance(sessions, list):
        return
    filtered = []
    for item in sessions:
        if not isinstance(item, Mapping):
            continue
        activity_at = _cloud_session_real_activity_at(item)
        if activity_at is not None and activity_at >= since:
            copied = dict(item)
            copied["real_activity_at"] = activity_at.isoformat().replace("+00:00", "Z")
            filtered.append(copied)
    payload["unfiltered_session_count"] = len(sessions)
    payload["since"] = since.isoformat().replace("+00:00", "Z")
    _recount_cloud_sessions(payload, filtered)


def _cloud_compact_line(item: Mapping[str, Any]) -> str:
    operator = item.get("operator_status") if isinstance(item.get("operator_status"), Mapping) else {}
    latest_state = item.get("latest_plan_state") if isinstance(item.get("latest_plan_state"), Mapping) else {}
    event_activity = item.get("event_activity_evidence") if isinstance(item.get("event_activity_evidence"), Mapping) else {}
    health = item.get("health") if isinstance(item.get("health"), Mapping) else {}
    current_plan = item.get("plan_name") or health.get("current_plan_name") or ""
    activity_plan = latest_state.get("plan") or current_plan
    activity = item.get("real_activity_at") or event_activity.get("updated_at") or latest_state.get("updated_at") or item.get("started_at") or ""
    return (
        f"- {item.get('display_name') or item.get('session')} "
        f"session={item.get('session')} status={item.get('status')} "
        f"operator={operator.get('status') or item.get('status')} "
        f"should_run={'yes' if item.get('should_be_running') else 'no'} "
        f"repairing={'yes' if item.get('watchdog_repairing') else 'no'} "
        f"current_plan={current_plan} activity_plan={activity_plan or ''} "
        f"activity_state={_cloud_session_plan_state(item)} "
        f"activity={activity} workspace={item.get('workspace')}"
    )


def _emit_cloud_sessions_human(payload: dict[str, Any], *, compact: bool) -> None:
    sessions = payload.get("sessions") if isinstance(payload, dict) else []
    if not isinstance(sessions, list):
        return
    since_detail = f" since={payload.get('since')}" if payload.get("since") else ""
    unfiltered_detail = (
        f" filtered_from={payload.get('unfiltered_session_count')}"
        if payload.get("unfiltered_session_count") is not None
        else ""
    )
    sys.stderr.write(
        f"cloud sessions: {len(sessions)}{since_detail}{unfiltered_detail} "
        f"should_be_running={payload.get('should_be_running_count', 0)} "
        f"watchdog_repairing={payload.get('watchdog_repairing_count', 0)} "
        f"operator_summary={payload.get('operator_summary', {})}\n"
    )
    for item in sessions:
        if not isinstance(item, dict):
            continue
        if compact:
            sys.stderr.write(_cloud_compact_line(item) + "\n")
            continue
        health = item.get("health") if isinstance(item.get("health"), dict) else {}
        active = item.get("active_step_evidence") if isinstance(item.get("active_step_evidence"), dict) else {}
        policy = item.get("policy_evidence") if isinstance(item.get("policy_evidence"), dict) else {}
        operator = item.get("operator_status") if isinstance(item.get("operator_status"), dict) else {}
        latest_state = item.get("latest_plan_state") if isinstance(item.get("latest_plan_state"), dict) else {}
        event_activity = item.get("event_activity_evidence") if isinstance(item.get("event_activity_evidence"), dict) else {}
        display_state = active.get("current_state") or (health.get("last_state") if health else "")
        detail = ""
        if health:
            health_state = health.get("last_state")
            health_detail = ""
            if display_state and health_state and display_state != health_state:
                health_detail = f" health_state={health_state}"
            detail = (
                f" state={display_state}{health_detail} "
                f"plan={health.get('current_plan_name') or ''} "
                f"completed={health.get('completed_count')}"
            )
        elif display_state:
            detail = f" state={display_state}"
        if event_activity.get("status") == "present" and event_activity.get("phase"):
            detail += (
                f" active_phase={event_activity.get('phase') or ''}"
                f" active_event={event_activity.get('kind') or ''}"
                f" active_activity={event_activity.get('updated_at') or ''}"
            )
        if latest_state.get("status") == "present":
            detail += (
                f" latest_plan={latest_state.get('plan') or ''}"
                f" lifecycle_state={latest_state.get('state') or ''}"
                f" latest_activity={latest_state.get('updated_at') or ''}"
            )
        watchdog_detail = ""
        if item.get("watchdog_evidence", {}).get("status") == "present":
            watchdog_detail = (
                f" watchdog={item.get('watchdog_status') or ''}"
                f" watchdog_action={item.get('watchdog_action') or ''}"
            )
        policy_detail = ""
        if policy.get("status") == "present":
            policy_detail = (
                f" merge_policy={policy.get('merge_policy')} "
                f"auto_approve={policy.get('driver_auto_approve')}"
            )
        operator_detail = ""
        if operator:
            operator_detail = (
                f" operator={operator.get('status') or ''}"
                f" reason={operator.get('reason') or ''}"
                f" next={operator.get('next_action') or ''}"
            )
        sys.stderr.write(
            f"- {item.get('display_name') or item.get('session')} "
            f"session={item.get('session')} status={item.get('status')} "
            f"should_run={'yes' if item.get('should_be_running') else 'no'} "
            f"repairing={'yes' if item.get('watchdog_repairing') else 'no'} "
            f"tmux={item.get('tmux_status')} process={item.get('process_status')}"
            f"{watchdog_detail}"
            f"{policy_detail}"
            f"{operator_detail}"
            f"{detail} workspace={item.get('workspace')} spec={item.get('remote_spec')}\n"
        )


def _in_trusted_container() -> bool:
    """True when this process is the cloud worker itself (no SSH needed).

    Delegates to :func:`status_snapshot.is_trusted_container` so the CLI and the
    resident share one definition of "we are the box."
    """
    return status_snapshot.is_trusted_container()


def _emit_cloud_status_human(snapshot: dict[str, Any] | None, *, compact: bool) -> None:
    text = (
        status_format.format_cloud_status_short(snapshot, max_chars=10**9)[0]
        if compact
        else status_format.format_cloud_status_detailed(snapshot)
    )
    if text:
        sys.stderr.write(text + "\n")


def _run_status_all(spec: CloudSpec, provider, *, args: argparse.Namespace | None = None) -> int:
    """``cloud status --all`` against the canonical snapshot.

    Inside the trusted container: read the snapshot the watchdog wrote, or
    rebuild it locally from observation only — never SSH back to our own host.
    From a laptop: fetch the same snapshot from the box; if the box has not
    started producing one yet, fall back to the legacy remote listing so the
    command never hard-fails during the rollout.
    """
    compact = bool(getattr(args, "compact", False)) if args is not None else False

    if _in_trusted_container():
        snapshot, _degraded = status_snapshot.load_cloud_status_snapshot(
            status_snapshot.DEFAULT_SNAPSHOT_PATH, max_age_s=3600
        )
        if snapshot is None:
            snapshot = status_snapshot.build_cloud_status_snapshot()
        _emit_cloud_status_human(snapshot, compact=compact)
        sys.stdout.write(json.dumps(snapshot, indent=2) + "\n")
        return 0

    observation = _provider_container_observation(provider)
    strict_ssh_observation = spec is not None and spec.provider == "ssh"
    capacity = _provider_prelaunch_capacity(provider) if strict_ssh_observation else None
    collector_ready = _container_collector_ready(observation)
    capacity_ready = not isinstance(capacity, Mapping) or capacity.get("verdict") == "GO"
    if strict_ssh_observation and (not collector_ready or not capacity_ready):
        lifecycle = observation.get("lifecycle") if observation is not None else "unknown"
        reason = (
            f"container_{lifecycle or 'unknown'}"
            if not collector_ready
            else "host_prelaunch_capacity_no_go"
        )
        payload = {
            "success": False,
            "source": "ssh-host-observer",
            "container_observation": observation,
            "prelaunch_capacity": capacity,
            "collector": {
                "status": "unavailable",
                "reason": reason,
            },
            "sessions": [],
        }
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return 1

    # Laptop path: ask the box for the same snapshot its watchdog produced.
    try:
        raw = provider.read_remote_file(str(status_snapshot.DEFAULT_SNAPSHOT_PATH))
        snapshot = json.loads(raw)
    except (CliError, OSError, ValueError) as exc:
        if spec is None:
            return _run_cloud_chains(spec, provider, args=args)
        payload = {
            "success": False,
            "source": "ssh-host-observer",
            "container_observation": observation,
            "prelaunch_capacity": capacity,
            "collector": {
                "status": "unavailable",
                "reason": "snapshot_collector_unavailable",
                "diagnostic": str(exc),
            },
            "sessions": [],
        }
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return 1
    if not isinstance(snapshot, dict):
        sys.stderr.write("cloud status: box snapshot malformed; falling back to legacy remote listing\n")
        return _run_cloud_chains(spec, provider, args=args)
    stale_reason = _cloud_status_snapshot_stale_reason(snapshot)
    if stale_reason:
        sys.stderr.write(
            f"cloud status: box snapshot stale ({stale_reason}); "
            "falling back to legacy remote listing\n"
        )
        return _run_cloud_chains(spec, provider, args=args)
    if observation is not None:
        snapshot["container_observation"] = observation
    if capacity is not None:
        snapshot["prelaunch_capacity"] = capacity
    _emit_cloud_status_human(snapshot, compact=compact)
    sys.stdout.write(json.dumps(snapshot, indent=2) + "\n")
    return 0


def _cloud_status_snapshot_stale_reason(snapshot: Mapping[str, Any]) -> str | None:
    generated = status_snapshot._parse_iso(snapshot.get("generated_at"))
    if generated is None:
        return "missing generated_at"
    age = (datetime.now(timezone.utc) - generated).total_seconds()
    if age > CLOUD_STATUS_CLI_MAX_AGE_S:
        return f"{int(age)}s old, limit {CLOUD_STATUS_CLI_MAX_AGE_S}s"
    return None


def _run_cloud_chains(spec: CloudSpec, provider, *, args: argparse.Namespace | None = None) -> int:
    del spec
    result = provider.ssh_exec(_cloud_chains_command())
    if result.returncode != 0:
        _relay_output(result, secret_names=[], env=os.environ)
        raise CliError("provider_failed", "unable to list remote cloud chain sessions")
    try:
        payload = json.loads((result.stdout or "").strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise CliError("provider_failed", f"cloud chains did not return JSON: {exc}") from exc
    since = _parse_cloud_status_since(getattr(args, "since", None) if args is not None else None)
    if isinstance(payload, dict):
        _filter_cloud_sessions_since(payload, since)
        _emit_cloud_sessions_human(payload, compact=bool(getattr(args, "compact", False)) if args is not None else False)
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    return 0


def _try_provider_method(provider, method_name: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
    """Call *method_name* on *provider* and return the result, or a structured
    ``unknown``/``unavailable`` entry on failure."""
    meth = getattr(provider, method_name, None)
    if meth is None:
        return {"status": "unavailable", "reason": f"provider does not implement {method_name}"}
    try:
        result = meth(*args, **kwargs)
    except (CliError, OSError, json.JSONDecodeError) as exc:
        return {"status": "unavailable", "reason": str(exc)}
    if isinstance(result, dict):
        return result
    if isinstance(result, str):
        return {"status": "unknown", "raw": result}
    return {"status": "unknown", "payload": result}


def _provider_plan_status_payload(
    provider: Any,
    *,
    plan: str,
    workspace: str,
    session: str,
) -> dict[str, Any]:
    """Read plan status, passing cloud identity only to aware providers.

    ``session`` was added to the provider contract so the remote Megaplan
    runtime can emit a canonical current-target observation.  Signature
    inspection preserves third-party/read-only provider doubles while keeping
    the production SSH route explicit; no TypeError fallback can mask a real
    provider bug.
    """

    method = getattr(provider, "status_payload", None)
    kwargs: dict[str, Any] = {"plan": plan, "workspace": workspace}
    if method is not None:
        try:
            parameters = inspect.signature(method).parameters.values()
        except (TypeError, ValueError):
            parameters = ()
        if any(
            parameter.name == "session"
            or parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in parameters
        ):
            kwargs["session"] = session
    return _try_provider_method(provider, "status_payload", **kwargs)


def _classify_effective_status(
    chain_state: Any,
    effective: dict[str, Any],
    milestone_count: int,
    plan_status: dict[str, Any],
    runner: dict[str, Any],
    pr: dict[str, Any],
    sync: dict[str, Any],
    human_verification: dict[str, Any] | None = None,
) -> str:
    """Classify the effective chain status into one of seven categories.

    Returns one of:
      ``complete`` — all milestones processed (terminal).
      ``running`` — a plan is executing and the runner is alive.
      ``awaiting_pr_merge`` — merge_policy is 'review' and chain is waiting.
      ``awaiting_human_verify`` — plan is blocked on human verification criteria.
      ``human_prerequisite`` — prerequisite_policy is 'required' and unmet.
      ``quality_gate`` — validation_policy is 'required' and quality gate is failing.
      ``stale_bookkeeping`` — no live runner, no active plan, chain state is stale.
    """
    last_state = getattr(chain_state, "last_state", None)
    current_plan = getattr(chain_state, "current_plan_name", None)

    # Complete/done: all milestones processed (MUST be first — terminal state
    # takes priority over runner liveness checks).
    current_index = getattr(chain_state, "current_milestone_index", -1)
    if milestone_count > 0 and current_index >= milestone_count:
        return "complete"

    # Explicit awaiting_pr_merge state
    if last_state == "awaiting_pr_merge":
        return "awaiting_pr_merge"

    # ── awaiting_human_verify ──────────────────────────────────────────
    # Checked after terminal / pr-merge so those take priority, but BEFORE
    # the generic «running» / «stalled» logic so pending verification does
    # not get misclassified as stale or blocked for other reasons.
    if plan_status.get("status") == "awaiting_human_verify":
        # If verification facts are unavailable, invalid, or missing
        # latest-verdict semantics, fail closed as blocked (do NOT assume
        # the chain is done or recoverable).
        if human_verification is None:
            return "awaiting_human_verify"
        hv_status = human_verification.get("status")
        if hv_status != "available":
            return "awaiting_human_verify"
        if human_verification.get("semantics") != "latest_verdict":
            return "awaiting_human_verify"

        all_verified = human_verification.get("all_deferred_must_verified", False)
        if not all_verified:
            # Pending deferred must criteria (including latest-verdict
            # ``fail`` records) remain — still blocked.
            return "awaiting_human_verify"

        # All deferred must criteria have latest ``pass`` records.
        runner_alive = runner.get("status") in ("alive", "connected")
        if runner_alive:
            return "running"
        # Runner dead but verification satisfied — chain is stale and
        # recoverable (supervisor can wake it).
        return "stale_bookkeeping"

    # Running: plan is active and runner shows signs of life
    plan_running = plan_status.get("status") in ("running", "active", "in_progress")
    runner_alive = runner.get("status") in ("alive", "connected")
    if plan_running and runner_alive:
        return "running"
    if plan_running and runner.get("status") == "unknown":
        # plan reports as running but we can't probe runner; give benefit of doubt
        return "running"

    # If there's a current plan but no runner, it might be stalled
    if current_plan and not plan_running:
        if sync.get("sync_state") in ("stale", "dirty"):
            return "stale_bookkeeping"
        # Check for prerequisite block (use effective policy dict).
        if effective.get("prerequisite_policy") == "required":
            return "human_prerequisite"
        if effective.get("validation_policy") == "required":
            return "quality_gate"

    # No current plan and no runner: stale bookkeeping
    if not current_plan and not runner_alive:
        return "stale_bookkeeping"

    # Default: running (we have state but can't confirm otherwise)
    return "running"


def _latest_failure_from_plan_status(plan_status: Mapping[str, Any]) -> dict[str, Any] | None:
    failure = plan_status.get("latest_failure")
    if not isinstance(failure, Mapping):
        nested_state = plan_status.get("state")
        if isinstance(nested_state, Mapping):
            failure = nested_state.get("latest_failure")
    if not isinstance(failure, Mapping):
        return None

    metadata = failure.get("metadata")
    if not isinstance(metadata, Mapping):
        metadata = {}
    message = failure.get("message") or failure.get("reason") or metadata.get("message")
    summary: dict[str, Any] = {
        "kind": failure.get("kind"),
        "message": message,
        "phase": failure.get("phase") or metadata.get("phase"),
        "raw": dict(failure),
    }
    return {key: value for key, value in summary.items() if value is not None}


def _resolve_chain_execution_context(
    spec: CloudSpec,
    chain_state,
    marker: dict[str, Any] | None,
    remote_spec: str,
) -> dict[str, Any]:
    """Resolve workspace, session, and extra_repos for the chain.

    Resolution order:
      - workspace:  chain_state.resolved_workspace > marker.workspace >
                    parent of *remote_spec* (``<workspace>/chain.yaml``) >
                    spec.repo.workspace
      - session:    chain_state.chain_session > marker.chain_session >
                    spec.chain.chain_session > CHAIN_SESSION_NAME
      - extra_repos: combine spec.extra_repos + chain_state.extra_repos +
                     marker.extra_repos (deduplicated, order preserved).

    Returns a dict with ``workspace``, ``chain_session``, ``extra_repos``,
    ``remote_spec``, and ``source`` (which data source provided each field).
    """
    if marker is None:
        marker = {}

    # --- workspace -------------------------------------------------------------
    workspace: str | None = None
    workspace_source: str = "default"

    # 1. chain_state.resolved_workspace
    if getattr(chain_state, "resolved_workspace", None):
        workspace = chain_state.resolved_workspace
        workspace_source = "chain_state"
    # 2. marker.workspace
    elif isinstance(marker.get("workspace"), str) and marker["workspace"].strip():
        workspace = marker["workspace"]
        workspace_source = "marker"
    # 3. parent of remote_spec (shaped like <workspace>/chain.yaml)
    elif "/" in remote_spec:
        parent = str(PurePosixPath(remote_spec).parent)
        if parent and parent != "/" and parent != ".":
            workspace = parent
            workspace_source = "remote_spec"
    # 4. spec.repo.workspace
    if workspace is None:
        workspace = spec.repo.workspace
        workspace_source = "spec"

    # --- chain_session ---------------------------------------------------------
    chain_session: str | None = None
    session_source: str = "default"

    # 1. chain_state.chain_session
    cs = getattr(chain_state, "chain_session", None)
    if isinstance(cs, str) and cs.strip():
        chain_session = cs
        session_source = "chain_state"
    # 2. marker.chain_session
    elif isinstance(marker.get("chain_session"), str) and marker["chain_session"].strip():
        chain_session = marker["chain_session"]
        session_source = "marker"
    # 3. spec.chain.chain_session
    elif spec.chain is not None and spec.chain.chain_session:
        chain_session = spec.chain.chain_session
        session_source = "spec"
    # 4. CHAIN_SESSION_NAME
    if chain_session is None:
        chain_session = CHAIN_SESSION_NAME
        session_source = "default"

    # --- extra_repos -----------------------------------------------------------
    seen: set[str] = set()
    extra_repos: list[str] = []
    extra_repos_sources: list[str] = []

    for source_label, source_list in (
        ("spec", list(spec.extra_repos)),
        ("chain_state", list(getattr(chain_state, "extra_repos", []))),
        ("marker", list(marker.get("extra_repos", [])) if isinstance(marker.get("extra_repos"), list) else []),
    ):
        for repo in source_list:
            if isinstance(repo, str) and repo.strip() and repo not in seen:
                seen.add(repo)
                extra_repos.append(repo)
                extra_repos_sources.append(source_label)

    return {
        "workspace": workspace,
        "chain_session": chain_session,
        "extra_repos": extra_repos,
        "remote_spec": remote_spec,
        "source": {
            "workspace": workspace_source,
            "session": session_source,
            "extra_repos": extra_repos_sources,
        },
    }


def _marker_path_no_create(cloud_yaml_path: Path) -> Path:
    """Return the marker directory path without creating any directories.

    This is intentionally read-only so that status / supervisor reads do not
    require write access to ``~/.megaplan/cloud/markers/``.
    """
    marker_key = hashlib.sha256(str(cloud_yaml_path.resolve()).encode()).hexdigest()[:16]
    return Path.home() / ".megaplan" / "cloud" / "markers" / marker_key


def _load_marker(root: Path, args: argparse.Namespace) -> dict[str, Any] | None:
    """Load the last_chain.json marker if it exists, or None.

    Does NOT create any marker directories — the read path is intentionally
    non-creating so that ``cloud_chain_status_payload`` and supervisor ticks
    work when ``~/.megaplan/cloud/markers/`` is not writable.
    """
    marker_path = _marker_path_no_create(_cloud_yaml_path(root, args)) / "last_chain.json"
    try:
        if not marker_path.exists():
            return None
        return json.loads(marker_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _provider_consistency_check(
    spec: CloudSpec,
    marker: dict[str, Any] | None,
    ctx: dict[str, Any],
) -> dict[str, Any]:
    """Compare provider identity across spec, marker, and resolved context.

    This compares **provider identity** (compose project, host), NOT SSH attach
    session names or chain tmux session names.

    Returns a dict with ``status`` (``consistent``, ``mismatch``,
    ``unknown``, or ``not_applicable``) and metadata about each source.
    """
    provider_name = spec.provider
    if provider_name in ("local", "ssh"):
        return {
            "status": "not_applicable",
            "reason": f"provider {provider_name!r} has no comparable provider identity",
            "spec_provider": provider_name,
        }

    return {
        "status": "unknown",
        "reason": f"no consistency check defined for provider {provider_name!r}",
        "spec_provider": provider_name,
    }


def _remote_human_verification_status_command(
    workspace: str, plan_name: str
) -> str:
    """Build a shell command that runs ``verify-human --list --json`` inside
    the resolved workspace.
    """
    return (
        f"cd {shlex.quote(workspace)} && "
        f"MEGAPLAN_TRUSTED_CONTAINER=1 python -m arnold_pipelines.megaplan verify-human --list "
        f"--plan {shlex.quote(plan_name)} --json"
    )


def _remote_human_verification_status(
    provider,
    resolved_workspace: str,
    chain_state,
) -> dict[str, Any]:
    """Fetch remote human-verification status via ``verify-human --list --json``.

    Validates that the remote payload declares ``semantics: latest_verdict``.
    If missing or different, facts are classified as ``unavailable``/``stale``.
    Providers without ``ssh_exec`` return ``{status: 'unavailable'}``.
    """
    current_plan = getattr(chain_state, "current_plan_name", None)
    if not current_plan:
        return {"status": "unavailable", "reason": "no current plan"}

    ssh_meth = getattr(provider, "ssh_exec", None)
    if ssh_meth is None:
        return {
            "status": "unavailable",
            "reason": "provider does not implement ssh_exec",
        }

    try:
        cmd = _remote_human_verification_status_command(
            resolved_workspace, current_plan
        )
        result = ssh_meth(cmd)
        stdout = (result.stdout or "").strip()
        if not stdout:
            return {"status": "unavailable", "reason": "empty stdout"}
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return {"status": "unavailable", "reason": f"invalid JSON: {exc}"}
    except Exception as exc:
        return {"status": "unavailable", "reason": str(exc)}

    # Validate semantics marker.
    semantics = payload.get("semantics")
    if semantics != "latest_verdict":
        return {
            "status": "unavailable",
            "reason": (
                f"remote payload semantics {semantics!r} != 'latest_verdict'; "
                "facts may be stale"
            ),
            "raw_semantics": semantics,
        }

    return {
        "status": "available",
        "pending": payload.get("pending", 0),
        "verified": payload.get("verified", 0),
        "all_deferred_must_verified": payload.get("all_deferred_must_verified", False),
        "rows": payload.get("rows", []),
        "semantics": semantics,
    }


def _marker_evidence(marker: dict[str, Any] | None, *, local_marker_path: Path) -> dict[str, Any]:
    if marker is None:
        return {"status": "missing", "path": str(local_marker_path)}
    return {
        "status": "present",
        "path": str(local_marker_path),
        "workspace": marker.get("workspace") if isinstance(marker.get("workspace"), str) else "",
        "remote_spec": marker.get("remote_spec") if isinstance(marker.get("remote_spec"), str) else "",
        "chain_session": marker.get("chain_session") if isinstance(marker.get("chain_session"), str) else "",
    }


def _active_step_evidence_from_plan_status(plan_status: Mapping[str, Any]) -> dict[str, Any]:
    active_step = plan_status.get("active_step")
    if not isinstance(active_step, Mapping) or not active_step:
        return {"status": "absent"}
    return {
        "status": "present",
        "phase": active_step.get("phase") or active_step.get("step") or "",
        "name": active_step.get("name") or "",
        "attempt": active_step.get("attempt"),
        "worker_pid": active_step.get("worker_pid"),
        "last_activity_at": active_step.get("last_activity_at") or "",
        "configured_specs": active_step.get("configured_specs") or [],
        "attempted_specs": active_step.get("attempted_specs") or [],
        "selected_spec_index": active_step.get("selected_spec_index", 0),
        "selected_spec_total": active_step.get("selected_spec_total", 0),
        "fallback_trigger": active_step.get("fallback_trigger"),
        "failed_attempt_reasons": active_step.get("failed_attempt_reasons") or [],
    }


def _canonical_runner_from_plan_status(
    plan_status: Mapping[str, Any],
    *,
    session: str,
    workspace: str,
    remote_spec: str,
    plan_name: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Project runner state only from the exact resolved current target.

    Raw tmux and process probes are intentionally absent from this function.
    They are observer diagnostics and cannot grant or veto control authority.
    """

    from arnold_pipelines.megaplan.cloud.current_target_liveness import (
        control_liveness_from_current_target,
    )

    target = plan_status.get("current_target")
    target = target if isinstance(target, Mapping) else {}
    refs = target.get("current_refs")
    refs = refs if isinstance(refs, Mapping) else {}
    marker = target.get("marker")
    marker = marker if isinstance(marker, Mapping) else {}
    target_plan = target.get("plan_state")
    target_plan = target_plan if isinstance(target_plan, Mapping) else {}

    mismatches: list[str] = []
    if not target:
        mismatches.append("current_target_missing")
    if str(target.get("target_session") or target.get("session") or "") != session:
        mismatches.append("session_mismatch")
    if marker.get("present") is not True:
        mismatches.append("marker_missing")
    if str(marker.get("session") or "") != session:
        mismatches.append("marker_session_mismatch")
    if str(refs.get("workspace") or marker.get("workspace") or "") != workspace:
        mismatches.append("workspace_mismatch")
    if str(refs.get("remote_spec") or marker.get("remote_spec") or "") != remote_spec:
        mismatches.append("remote_spec_mismatch")
    if str(refs.get("current_plan_name") or "") != plan_name:
        mismatches.append("current_plan_mismatch")
    if target_plan.get("present") is not True:
        mismatches.append("plan_state_missing")
    if str(target_plan.get("name") or "") != plan_name:
        mismatches.append("plan_state_name_mismatch")

    liveness = control_liveness_from_current_target(target, action="mutation")
    if not mismatches and liveness.get("action_permitted") is True:
        source = str(liveness.get("source") or "")
        identity = liveness.get("identity")
        identity = identity if isinstance(identity, Mapping) else {}
        lease = liveness.get("lease")
        lease = lease if isinstance(lease, Mapping) else {}
        if source == "matched_local_process_identity":
            required = (
                identity.get("pid"),
                identity.get("pid_namespace_id"),
                identity.get("process_start_identity"),
            )
            if not all(required):
                mismatches.append("local_process_incarnation_incomplete")
        elif source == "fresh_owner_lease":
            required = (
                lease.get("target_pid"),
                lease.get("runner_container_id"),
                lease.get("pid_namespace_id"),
                lease.get("target_process_start_identity"),
                lease.get("run_id"),
                lease.get("attempt_id"),
                lease.get("incarnation_id"),
                lease.get("runner_fence"),
            )
            if not all(value is not None and str(value) for value in required):
                mismatches.append("owner_lease_incarnation_incomplete")
        else:
            mismatches.append("unsupported_liveness_authority_source")
    if mismatches:
        liveness = control_liveness_from_current_target(None, action="mutation")
        liveness["reason"] = "current target did not match the exact chain target"
        liveness["diagnostics"] = mismatches

    state = str(liveness.get("state") or "unknown")
    action_permitted = bool(liveness.get("action_permitted") is True)
    exact_target = not mismatches
    runner_identity = liveness.get("identity")
    runner_identity = runner_identity if isinstance(runner_identity, Mapping) else {}
    runner = {
        "status": state if state in {"alive", "dead"} else "unknown",
        "state": state,
        "authority": "canonical_current_target",
        "exact_target": exact_target,
        "mutation_permitted": bool(exact_target and action_permitted),
        "session": session,
        "workspace": workspace,
        "remote_spec": remote_spec,
        "plan_name": plan_name,
        "reason": str(liveness.get("reason") or ""),
        "identity": dict(runner_identity),
    }
    # The current-target liveness vocabulary is live/dead/unknown, whereas
    # the longstanding runner surface uses alive/dead/unknown.
    if state == "live":
        runner["status"] = "alive"
    return runner, liveness


def cloud_chain_status_payload(root: Path, args: argparse.Namespace, spec: CloudSpec, provider) -> dict[str, Any]:
    """Return the same payload printed by `arnold cloud status --chain`."""
    from arnold_pipelines.megaplan import chain as chain_module
    from arnold_pipelines.megaplan.cloud.current_target import resolve_current_target
    from arnold_pipelines.megaplan.cloud.repair_contract import (
        CUSTODY_BUCKET_BROKEN_SUPERFIXER,
        CUSTODY_BUCKET_REPAIRABLE_NOT_REPAIRING,
        CUSTODY_BUCKET_REPAIRING,
        project_repair_custody,
    )
    from arnold_pipelines.megaplan.run_state.resolver import resolve_run_state

    observation = _provider_container_observation(provider)
    if observation is not None and observation.get("lifecycle") != "running":
        raise _collector_unavailable_error(observation)

    remote_spec = _resolve_remote_chain_spec(root, args, spec)
    marker = _load_marker(root, args)
    state_path = chain_module._state_path_for(Path(remote_spec))
    try:
        chain_state = chain_module.ChainState.from_dict(json.loads(provider.read_remote_file(str(state_path))))
    except json.JSONDecodeError as exc:
        raise CliError("provider_failed", f"Remote chain state was not valid JSON: {exc}") from exc

    with NamedTemporaryFile("w", suffix=".yaml", encoding="utf-8", delete=False) as handle:
        handle.write(provider.read_remote_file(remote_spec))
        temp_spec = Path(handle.name)
    try:
        chain_spec = chain_module.load_spec(temp_spec)
    finally:
        temp_spec.unlink(missing_ok=True)

    # Resolve execution context (workspace, session, extra_repos).
    ctx = _resolve_chain_execution_context(spec, chain_state, marker, remote_spec)
    resolved_workspace: str = ctx["workspace"]
    resolved_session: str = ctx["chain_session"]

    summary = chain_module.format_chain_status(chain_spec, chain_state)

    # Build additive sections alongside the existing top-level keys.
    # Runtime policy (effective, merging any overrides).
    try:
        runtime_path = chain_module._runtime_policy_path_for(Path(remote_spec))
        runtime_raw = provider.read_remote_file(str(runtime_path))
        runtime_overrides = json.loads(runtime_raw) if runtime_raw else {}
    except Exception:
        runtime_overrides = {}
    effective = chain_module.effective_chain_policy(chain_spec, runtime_overrides)
    policy: dict[str, Any] = effective

    # Sync state from chain state fields.
    sync: dict[str, Any] = {
        "branch_head": chain_state.branch_head,
        "pr_head": chain_state.pr_head,
        "last_pushed_commit": chain_state.last_pushed_commit,
        "dirty_flag": chain_state.dirty_flag,
        "sync_state": chain_state.sync_state,
    }

    # Plan status via provider.status_payload when a current plan exists.
    plan_status: dict[str, Any]
    if chain_state.current_plan_name:
        plan_status = _provider_plan_status_payload(
            provider,
            plan=chain_state.current_plan_name,
            workspace=resolved_workspace,
            session=resolved_session,
        )
    else:
        plan_status = {"status": "missing", "reason": "no current plan"}
    latest_failure = _latest_failure_from_plan_status(plan_status)

    # Raw tmux/process evidence remains useful to an operator, but is never
    # projected into canonical runner liveness.  Only the remote resolver's
    # exact current-target record below can authorize control decisions.
    tmux_evidence: dict[str, Any] = {
        "status": "unavailable",
        "reason": "runner probe not implemented",
        "authoritative": False,
    }
    process_evidence: dict[str, Any] = {
        "status": "unavailable",
        "reason": "runner probe not implemented",
        "authoritative": False,
    }
    try:
        ssh_meth = getattr(provider, "ssh_exec", None)
        if ssh_meth is not None:
            session_esc = shlex.quote(resolved_session)
            spec_esc = shlex.quote(remote_spec)
            proc = ssh_meth(
                "if tmux has-session -t "
                + session_esc
                + " 2>/dev/null; then echo tmux_alive; "
                + "elif ps -eww -o args= | grep -E "
                + shlex.quote("[p]ython[0-9.]*([[:space:]]+-P)?[[:space:]]+-m arnold_pipelines.megaplan (chain|epic-chain) start")
                + " | grep -F -- '--spec' | grep -Fq -- "
                + spec_esc
                + "; then echo process_alive; "
                + "else echo dead; fi"
            )
            stdout = proc.stdout or ""
            if proc.returncode == 0 and "tmux_alive" in stdout:
                tmux_evidence = {
                    "status": "alive",
                    "session": resolved_session,
                    "authoritative": False,
                }
                process_evidence = {
                    "status": "unknown",
                    "remote_spec": remote_spec,
                    "authoritative": False,
                }
            elif proc.returncode == 0 and "process_alive" in stdout:
                tmux_evidence = {
                    "status": "missing",
                    "session": resolved_session,
                    "authoritative": False,
                }
                process_evidence = {
                    "status": "alive",
                    "remote_spec": remote_spec,
                    "authoritative": False,
                }
            else:
                tmux_evidence = {
                    "status": "missing",
                    "session": resolved_session,
                    "authoritative": False,
                }
                process_evidence = {
                    "status": "dead",
                    "remote_spec": remote_spec,
                    "authoritative": False,
                }
    except Exception as exc:
        tmux_evidence = {
            "status": "unknown",
            "reason": str(exc),
            "session": resolved_session,
            "authoritative": False,
        }
        process_evidence = {
            "status": "unknown",
            "reason": str(exc),
            "remote_spec": remote_spec,
            "authoritative": False,
        }

    runner, current_target_liveness = _canonical_runner_from_plan_status(
        plan_status,
        session=resolved_session,
        workspace=resolved_workspace,
        remote_spec=remote_spec,
        plan_name=chain_state.current_plan_name or "",
    )
    runner["diagnostic_tmux_status"] = tmux_evidence.get("status")
    runner["diagnostic_process_status"] = process_evidence.get("status")

    # Log paths (structured from the resolved workspace).
    chain_log_name = (
        f"cloud-chain-{resolved_session}.log"
        if resolved_session != CHAIN_SESSION_NAME
        else "cloud-chain.log"
    )
    chain_log_path = (PurePosixPath(resolved_workspace) / ".megaplan" / chain_log_name).as_posix()
    chain_log_info: dict[str, Any] = {"path": chain_log_path}
    try:
        ssh_meth = getattr(provider, "ssh_exec", None)
        if ssh_meth is not None:
            stat_proc = ssh_meth(
                "stat -c '%Y %s' "
                + shlex.quote(chain_log_path)
                + " 2>/dev/null || echo unavailable"
            )
            stat_out = (stat_proc.stdout or "").strip()
            if stat_out and stat_out != "unavailable":
                parts = stat_out.split()
                if len(parts) >= 2:
                    chain_log_info["mtime"] = int(parts[0]) if parts[0].lstrip("-").isdigit() else parts[0]
                    chain_log_info["size"] = int(parts[1]) if parts[1].isdigit() else parts[1]
            else:
                chain_log_info["status"] = "unavailable"
        else:
            chain_log_info["status"] = "unavailable"
            chain_log_info["reason"] = "provider does not implement ssh_exec"
    except Exception as exc:
        chain_log_info["status"] = "unavailable"
        chain_log_info["reason"] = str(exc)
    logs: dict[str, Any] = {
        "workspace": resolved_workspace,
        "plan_log": (PurePosixPath(resolved_workspace) / ".megaplan" / "logs" / "latest.log").as_posix()
        if chain_state.current_plan_name
        else None,
        "agent_log": (PurePosixPath(resolved_workspace) / "agent.log").as_posix(),
        "chain_log": chain_log_info,
    }

    # PR state.
    pr: dict[str, Any] = {}
    if chain_state.pr_number is not None:
        pr["pr_number"] = chain_state.pr_number
        pr["pr_state"] = chain_state.pr_state
        if chain_state.pr_head:
            pr["pr_head"] = chain_state.pr_head
    else:
        pr = {"status": "none"}

    # Provider / session consistency check (read-only).
    provider_consistency = _provider_consistency_check(spec, marker, ctx)

    # Human-verification status via explicit remote command (T11).
    # Probing here means ``cloud_chain_status_payload`` is self-contained
    # and the supervisor tick's (c2) section only needs to refresh when the
    # effective status is human-verification-related.
    human_verification: dict[str, Any] = _remote_human_verification_status(
        provider, resolved_workspace, chain_state,
    )
    marker_evidence = _marker_evidence(
        marker,
        local_marker_path=_marker_path_no_create(_cloud_yaml_path(root, args)) / "last_chain.json",
    )
    active_step_evidence = _active_step_evidence_from_plan_status(plan_status)
    repair_custody: dict[str, Any] = {"status": "unavailable", "reason": "local custody evidence unavailable"}
    local_workspace = Path(resolved_workspace)
    marker_dir = local_workspace / ".megaplan" / "cloud-sessions"
    queue_root = local_workspace / ".megaplan" / "repair-queue"
    repair_data_dir = marker_dir / "repair-data"
    if local_workspace.exists():
        try:
            current_target = resolve_current_target(
                resolved_session,
                marker_dir=marker_dir,
                repair_data_dir=repair_data_dir,
            )
            canonical_run_state = resolve_run_state(current_target)
            projection = project_repair_custody(
                plan_state=plan_status,
                current_target=current_target,
                canonical_run_state=canonical_run_state,
                queue_root=queue_root,
                repair_data_dir=repair_data_dir,
            )
            bucket = projection["custody_bucket"]
            if bucket in {
                CUSTODY_BUCKET_REPAIRING,
                CUSTODY_BUCKET_REPAIRABLE_NOT_REPAIRING,
                CUSTODY_BUCKET_BROKEN_SUPERFIXER,
            }:
                repair_custody = {
                    "status": "available",
                    "bucket": bucket,
                    "blocker_id": projection["blocker_id"],
                    "active_request_ids": projection["active_request_ids"],
                }
        except Exception as exc:
            repair_custody = {"status": "invalid", "reason": str(exc)}

    # Classify effective status.
    effective_status = _classify_effective_status(
        chain_state, effective, len(chain_spec.milestones), plan_status, runner, pr, sync,
        human_verification=human_verification,
    )

    return {
        "success": True,
        "spec": remote_spec,
        "milestone_count": len(chain_spec.milestones),
        "seed_plan": chain_spec.seed_plan,
        "chain_state": chain_state.to_dict(),
        "summary": summary,
        "effective_status": effective_status,
        "policy": policy,
        "sync": sync,
        "plan_status": plan_status,
        "latest_failure": latest_failure,
        "runner": runner,
        "current_target": plan_status.get("current_target")
        if isinstance(plan_status.get("current_target"), Mapping)
        else {},
        "current_target_liveness": current_target_liveness,
        "marker_evidence": marker_evidence,
        "tmux_evidence": tmux_evidence,
        "process_evidence": process_evidence,
        "active_step_evidence": active_step_evidence,
        "repair_custody": repair_custody,
        "logs": logs,
        "pr": pr,
        "provider_consistency": provider_consistency,
        "human_verification": human_verification,
        "resolved_workspace": resolved_workspace,
        "resolved_session": resolved_session,
        "resolved_context": ctx,
    }


def _materialized_deploy_dir(spec: CloudSpec):
    class _DeployDirContext:
        def __enter__(self_inner) -> Path:
            path = _persistent_deploy_dir(spec)
            materialize_deploy_dir(spec, path)
            return path

        def __exit__(self_inner, exc_type, exc, tb) -> None:
            return None

    return _DeployDirContext()


def _cloud_cache_root() -> Path:
    root = Path.home() / ".megaplan" / "cloud"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _persistent_deploy_dir(spec: CloudSpec) -> Path:
    root = _cloud_cache_root()
    if spec.provider == "local":
        compose_project = spec.local.compose_project if spec.local is not None else "megaplan-cloud"
        path = root / compose_project
    elif spec.provider == "ssh":
        host = spec.ssh.host if spec.ssh is not None else "unknown-host"
        path = root / f"ssh-{host}"
    else:
        raise CliError("invalid_spec", f"provider {spec.provider!r} does not use a persistent deploy dir")
    path.mkdir(parents=True, exist_ok=True)
    return path


def _marker_dir(cloud_yaml_path: Path) -> Path:
    marker_key = hashlib.sha256(str(cloud_yaml_path.resolve()).encode()).hexdigest()[:16]
    path = _cloud_cache_root() / "markers" / marker_key
    path.mkdir(parents=True, exist_ok=True)
    return path


def _clear_persistent_deploy_dir(spec: CloudSpec) -> None:
    deploy_dir = _persistent_deploy_dir(spec)
    if deploy_dir.exists():
        shutil.rmtree(deploy_dir)


def _confirm_destroy(spec: CloudSpec) -> bool:
    volume = spec.resources.volume or "<no volume>"
    response = input(
        f"Destroy cloud deployment and delete volume {volume!r}? [y/N]: "
    ).strip().lower()
    return response in {"y", "yes"}


def _relay_output(
    result,
    *,
    secret_names: list[str] | tuple[str, ...] = (),
    env: dict[str, str] | None = None,
) -> None:
    _write_redacted_output(result, secret_names=secret_names, env=env)


def _emit_error(error: CliError) -> int:
    payload = {"success": False, "error": error.code, "message": error.message}
    payload.update(error.extra)
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    return error.exit_code or 1
