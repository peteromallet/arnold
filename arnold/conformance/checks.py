"""Adapter protocol and ``ContractResult`` schema round-trip conformance checks.

This module provides programmatic checks over the public adapter and contract
serialization APIs.  It surfaces failures without normalising schema skew, but
does not change the underlying schema contract.

No ``megaplan`` imports.  No forbidden vocabulary literals.
"""

from __future__ import annotations

import ast
import copy
import fnmatch
import hashlib
import json
import re
import subprocess
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Callable, Collection, Mapping

from arnold.conformance import ConformanceCheckResult
from arnold.execution.registries import CapabilityHandler, ExecutionRegistries
from arnold.pipeline.types import ContractResult, ContractStatus


_DEFAULT_ARNOLD_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_MEGAPLAN_COUPLING_ALLOWLIST = (
    Path(__file__).resolve().parent / "_megaplan_coupling_allowlist.txt"
)
_DEFAULT_LEGACY_REFERENCE_ALLOWLIST = (
    Path(__file__).resolve().parent / "legacy_reference_allowlist.json"
)
ACTIVE_MEGAPLAN_PACKAGE_NAMES = (
    "megaplan",
    "arnold_pipelines.megaplan",
)
_MEGAPLAN_INITIATIVE_SUBDIRS = frozenset(
    {
        "briefs",
        "research",
        "decisions",
        "notes",
        "assets",
        # Historical initiative plans remain durable context but are not active
        # chain inputs.  Keep them under an explicit archive boundary instead
        # of forcing preservation material back into executable root slots.
        "archive",
        # Supporting prose and milestone verification are initiative-owned
        # artifacts with narrower semantics than general notes/evidence.
        "annexes",
        "validation",
        "handoff",
        # Chain completion and custody tooling writes plural handoffs and
        # machine-verifiable evidence under the initiative that owns them.
        "handoffs",
        "evidence",
    }
)

_PLACEMENT_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_PLACEMENT_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PLACEMENT_KINDS = frozenset({"move", "promote_preserving_source"})
_COLLECTION_SCHEMA = "megaplan.collection-layout.v1"
_COLLECTION_SCOPE = "initiative_collection"
_COLLECTION_ROOT = ".megaplan/collection"
_COLLECTION_AUTHORITY = f"{_COLLECTION_ROOT}/authority.json"
_COLLECTION_SOURCE_REVISION = "4023fdd9b2027561e221dac98e234b59289e0ca6"
_COLLECTION_BINDINGS = (
    {
        "artifact_type": "cloud_guidance",
        "source": ".megaplan/initiatives/CLOUD.md",
        "destination": f"{_COLLECTION_ROOT}/CLOUD.md",
    },
    {
        "artifact_type": "aggregate_chain_snapshot",
        "source": ".megaplan/initiatives/chain.yaml",
        "destination": f"{_COLLECTION_ROOT}/chain.yaml",
    },
)
_COLLECTION_PATHS = frozenset(
    path
    for binding in _COLLECTION_BINDINGS
    for path in (binding["source"], binding["destination"])
)
_CANONICAL_ROOT_GENERATORS = frozenset(
    {
        "chain.prelaunch_disposition.v1",
        "critique_ledger_completion.validator.v1",
        "finite_canary.package.v1",
    }
)


def validate_collection_artifact_placements(
    record: Mapping[str, Any],
    *,
    repo_root: Path,
) -> tuple[str, ...]:
    """Validate the ownerless, placement-only collection contract.

    The collection is deliberately a sibling of ``initiatives``.  Its
    authority file names exactly two source-preserving bindings; the release
    record must contain exactly one typed promotion row for each binding.
    """

    def _safe_path(value: Any, label: str) -> str:
        if not isinstance(value, str) or not value:
            raise ValueError(f"{label} must be a non-empty repository-relative path")
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
            raise ValueError(f"{label} must be normalized and repository-relative")
        resolved = (repo_root / Path(*path.parts)).resolve()
        try:
            resolved.relative_to(repo_root.resolve())
        except ValueError as exc:
            raise ValueError(f"{label} escapes the repository") from exc
        return value

    def _sha256(path: Path, label: str) -> str:
        if not path.is_file():
            raise ValueError(f"{label} is missing: {path}")
        return hashlib.sha256(path.read_bytes()).hexdigest()

    authority_path = repo_root / Path(*PurePosixPath(_COLLECTION_AUTHORITY).parts)
    if not authority_path.is_file():
        raise ValueError(f"collection authority is missing: {_COLLECTION_AUTHORITY}")
    try:
        authority = json.loads(authority_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"collection authority is not valid JSON: {exc}") from exc
    if not isinstance(authority, dict) or set(authority) != {
        "schema", "scope", "initiative_owner", "authority_scope", "root", "bindings"
    }:
        raise ValueError("collection authority has unknown or missing fields")
    if authority["schema"] != _COLLECTION_SCHEMA:
        raise ValueError("collection authority schema is unsupported")
    if authority["scope"] != _COLLECTION_SCOPE:
        raise ValueError("collection authority scope is invalid")
    if authority["initiative_owner"] is not None:
        raise ValueError("collection authority must be ownerless")
    if authority["authority_scope"] != "placement_only":
        raise ValueError("collection authority scope must be placement_only")
    if authority["root"] != _COLLECTION_ROOT:
        raise ValueError("collection authority root is invalid")
    bindings = authority["bindings"]
    if not isinstance(bindings, list) or bindings != list(_COLLECTION_BINDINGS):
        raise ValueError("collection authority bindings do not match the exact contract")
    if len({binding["artifact_type"] for binding in bindings}) != len(bindings):
        raise ValueError("collection authority contains duplicate bindings")
    for index, binding in enumerate(bindings):
        for key in ("source", "destination"):
            _safe_path(binding[key], f"collection authority bindings[{index}].{key}")
        if not binding["destination"].startswith(_COLLECTION_ROOT + "/"):
            raise ValueError("collection authority destination escapes collection root")
        if not binding["source"].startswith(".megaplan/initiatives/"):
            raise ValueError("collection authority source is not an initiative artifact")
        source = repo_root / Path(*PurePosixPath(binding["source"]).parts)
        destination = repo_root / Path(*PurePosixPath(binding["destination"]).parts)
        if _sha256(source, f"collection source {binding['source']}") != _sha256(
            destination, f"collection destination {binding['destination']}"
        ):
            raise ValueError(f"collection source/destination bytes differ for {binding['artifact_type']}")

    rows = record.get("canonical_artifact_moves")
    if not isinstance(rows, list):
        raise ValueError("canonical_artifact_moves must be a list")
    collection_rows = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        if any(
            isinstance(row.get(key), str)
            and (
                row[key] in _COLLECTION_PATHS
                or row[key].startswith(_COLLECTION_ROOT + "/")
            )
            for key in ("from", "to")
        ):
            collection_rows.append((index, row))
    if len(collection_rows) != len(_COLLECTION_BINDINGS):
        raise ValueError("collection authority and promotion rows must correspond one-to-one")

    authority_hash = _sha256(authority_path, _COLLECTION_AUTHORITY)
    seen_types: set[str] = set()
    covered: list[str] = [_COLLECTION_AUTHORITY]
    for index, row in collection_rows:
        label = f"canonical_artifact_moves[{index}]"
        expected_fields = {
            "kind", "from", "to", "source_revision", "source_sha256",
            "destination_sha256", "collection_scope", "artifact_type", "authority",
        }
        if set(row) != expected_fields:
            raise ValueError(f"{label} collection row has unknown or missing fields")
        if row["kind"] != "promote_preserving_source":
            raise ValueError(f"{label} collection rows must preserve their sources")
        if row["collection_scope"] != _COLLECTION_SCOPE:
            raise ValueError(f"{label}.collection_scope is invalid")
        artifact_type = row["artifact_type"]
        if artifact_type in seen_types:
            raise ValueError(f"{label} duplicates a collection binding")
        seen_types.add(artifact_type)
        binding = next((item for item in _COLLECTION_BINDINGS if item["artifact_type"] == artifact_type), None)
        if binding is None or row["from"] != binding["source"] or row["to"] != binding["destination"]:
            raise ValueError(f"{label} has an unknown artifact type or exact mapping")
        if row["source_revision"] != _COLLECTION_SOURCE_REVISION:
            raise ValueError(f"{label}.source_revision is not the pinned source revision")
        authority_binding = row["authority"]
        if not isinstance(authority_binding, dict) or set(authority_binding) != {"path", "sha256"}:
            raise ValueError(f"{label}.authority has unknown or missing fields")
        if authority_binding["path"] != _COLLECTION_AUTHORITY or authority_binding["sha256"] != authority_hash:
            raise ValueError(f"{label}.authority does not bind the collection manifest")
        if row["source_sha256"] != row["destination_sha256"]:
            raise ValueError(f"{label} collection promotion must be equal-byte")
        source = repo_root / Path(*PurePosixPath(binding["source"]).parts)
        destination = repo_root / Path(*PurePosixPath(binding["destination"]).parts)
        if _sha256(source, f"{label}.from") != row["source_sha256"]:
            raise ValueError(f"{label}.from hash mismatch")
        if _sha256(destination, f"{label}.to") != row["destination_sha256"]:
            raise ValueError(f"{label}.to hash mismatch")
        source_blob = subprocess.run(
            ["git", "show", f"{_COLLECTION_SOURCE_REVISION}:{binding['source']}"],
            cwd=repo_root, capture_output=True, check=False,
        )
        if source_blob.returncode or hashlib.sha256(source_blob.stdout).hexdigest() != row["source_sha256"]:
            raise ValueError(f"{label}.source_revision hash mismatch")
        covered.extend((binding["source"], binding["destination"]))
    if seen_types != {binding["artifact_type"] for binding in _COLLECTION_BINDINGS}:
        raise ValueError("collection promotion rows do not cover every authority binding")
    return tuple(covered)


def validate_canonical_artifact_placements(
    record: Mapping[str, Any],
    *,
    repo_root: Path,
) -> tuple[str, ...]:
    """Validate and return paths covered by typed post-M11 placements.

    Placement rows are deliberately exact and content-addressed.  This helper
    is shared by the release-evidence validator and the layout check so a
    layout exemption can only be earned by the authoritative placement record.
    """

    rows = record.get("canonical_artifact_moves")
    if not isinstance(rows, list) or not rows:
        raise ValueError("canonical_artifact_moves must be a non-empty list")

    collection_touched = any(
        isinstance(item, dict)
        and any(
            isinstance(item.get(key), str)
            and (
                item[key] in _COLLECTION_PATHS
                or item[key].startswith(_COLLECTION_ROOT + "/")
            )
            for key in ("from", "to")
        )
        for item in rows
    )
    if collection_touched:
        validate_collection_artifact_placements(record, repo_root=repo_root)

    def _safe_path(value: Any, label: str) -> str:
        if not isinstance(value, str) or not value:
            raise ValueError(f"{label} must be a non-empty repository-relative path")
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
            raise ValueError(f"{label} must be normalized and repository-relative")
        resolved = (repo_root / Path(*path.parts)).resolve()
        try:
            resolved.relative_to(repo_root.resolve())
        except ValueError as exc:
            raise ValueError(f"{label} escapes the repository") from exc
        return value

    def _sha256(path: Path, label: str) -> str:
        if not path.is_file():
            raise ValueError(f"{label} is missing: {path}")
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _git_blob(revision: str, path: str, label: str) -> bytes:
        if not isinstance(revision, str) or not _PLACEMENT_SHA1.fullmatch(revision):
            raise ValueError(f"{label} must be a lowercase 40-character Git SHA")
        probe = subprocess.run(
            ["git", "cat-file", "-e", f"{revision}^{{commit}}"],
            cwd=repo_root,
            capture_output=True,
            check=False,
        )
        if probe.returncode:
            raise ValueError(f"{label} does not name a Git commit")
        result = subprocess.run(
            ["git", "show", f"{revision}:{path}"],
            cwd=repo_root,
            capture_output=True,
            check=False,
        )
        if result.returncode:
            raise ValueError(f"{label} does not contain {path}")
        return result.stdout

    covered: list[str] = []
    for index, item in enumerate(rows):
        label = f"canonical_artifact_moves[{index}]"
        if not isinstance(item, dict):
            raise ValueError(f"{label} must be an object")
        kind = item.get("kind")
        if kind not in _PLACEMENT_KINDS:
            raise ValueError(f"{label}.kind is unknown")
        expected = {
            "kind", "from", "to", "source_revision",
            "source_sha256", "destination_sha256",
        }
        if kind == "move" or "destination_revision" in item:
            expected.add("destination_revision")
        if "authority" in item:
            expected.add("authority")
        if kind == "promote_preserving_source":
            source_hash = item.get("source_sha256")
            destination_hash = item.get("destination_sha256")
            if source_hash != destination_hash:
                expected.add("supersession")
        if collection_touched and any(
            isinstance(item.get(key), str)
            and (
                item[key] in _COLLECTION_PATHS
                or item[key].startswith(_COLLECTION_ROOT + "/")
            )
            for key in ("from", "to")
        ):
            expected.update({"collection_scope", "artifact_type", "authority"})
        if set(item) != expected:
            raise ValueError(f"{label} has unknown or missing fields")
        source_rel = _safe_path(item["from"], f"{label}.from")
        destination_rel = _safe_path(item["to"], f"{label}.to")
        if source_rel == destination_rel:
            raise ValueError(f"{label} source and destination must differ")
        for key in ("source_sha256", "destination_sha256"):
            if not isinstance(item[key], str) or not _PLACEMENT_SHA256.fullmatch(item[key]):
                raise ValueError(f"{label}.{key} must be a lowercase SHA-256")

        source = repo_root / Path(*PurePosixPath(source_rel).parts)
        destination = repo_root / Path(*PurePosixPath(destination_rel).parts)
        source_blob = _git_blob(item["source_revision"], source_rel, f"{label}.source_revision")
        if hashlib.sha256(source_blob).hexdigest() != item["source_sha256"]:
            raise ValueError(f"{label}.source_revision hash mismatch")
        if "destination_revision" in item:
            destination_blob = _git_blob(
                item["destination_revision"], destination_rel,
                f"{label}.destination_revision",
            )
            if hashlib.sha256(destination_blob).hexdigest() != item["destination_sha256"]:
                raise ValueError(f"{label}.destination_revision hash mismatch")
        if _sha256(destination, f"{label}.to") != item["destination_sha256"]:
            raise ValueError(f"{label}.to hash mismatch")

        if "authority" in item:
            authority = item["authority"]
            if not isinstance(authority, dict) or set(authority) != {"path", "sha256"}:
                raise ValueError(f"{label}.authority has unknown or missing fields")
            authority_path = _safe_path(authority["path"], f"{label}.authority.path")
            authority_hash = authority["sha256"]
            if not isinstance(authority_hash, str) or not _PLACEMENT_SHA256.fullmatch(authority_hash):
                raise ValueError(f"{label}.authority.sha256 is invalid")
            if _sha256(repo_root / Path(*PurePosixPath(authority_path).parts), f"{label}.authority.path") != authority_hash:
                raise ValueError(f"{label}.authority hash mismatch")

        if kind == "move":
            if source.exists():
                raise ValueError(f"{label}.from must be absent for move")
        else:
            if _sha256(source, f"{label}.from") != item["source_sha256"]:
                raise ValueError(f"{label}.from historical bytes mismatch")
            if item["source_sha256"] == item["destination_sha256"]:
                if "supersession" in item:
                    raise ValueError(f"{label} equal-byte promotion cannot declare supersession")
            else:
                supersession = item.get("supersession")
                if not isinstance(supersession, dict) or set(supersession) != {"relation", "evidence"}:
                    raise ValueError(f"{label} requires an exact supersession relation")
                if supersession["relation"] != "canonical_destination_supersedes_historical_source":
                    raise ValueError(f"{label}.supersession.relation is invalid")
                evidence = supersession["evidence"]
                if (
                    not isinstance(evidence, dict)
                    or set(evidence) != {"commit", "source", "destination"}
                    or "destination_revision" not in item
                    or evidence["commit"] != item["destination_revision"]
                    or evidence["source"] != source_rel
                    or evidence["destination"] != destination_rel
                ):
                    raise ValueError(f"{label}.supersession.evidence is invalid")
        covered.extend((source_rel, destination_rel))
    return tuple(covered)


def validate_canonical_root_artifacts(
    record: Mapping[str, Any],
    *,
    repo_root: Path,
) -> tuple[str, ...]:
    """Validate exact generator-owned initiative-root artifact declarations."""

    rows = record.get("canonical_root_artifacts")
    if not isinstance(rows, list):
        raise ValueError("canonical_root_artifacts must be a list")
    covered: list[str] = []
    for index, item in enumerate(rows):
        label = f"canonical_root_artifacts[{index}]"
        if not isinstance(item, dict) or set(item) != {
            "path", "generator", "authority", "sha256", "authority_sha256"
        }:
            raise ValueError(f"{label} has unknown or missing fields")
        if item["generator"] not in _CANONICAL_ROOT_GENERATORS:
            raise ValueError(f"{label}.generator is unknown")
        path = PurePosixPath(item["path"])
        authority = PurePosixPath(item["authority"])
        for name, value in (("path", path), ("authority", authority)):
            if value.is_absolute() or ".." in value.parts or value.as_posix() != item[name]:
                raise ValueError(f"{label}.{name} must be normalized and repository-relative")
            resolved = (repo_root / Path(*value.parts)).resolve()
            try:
                resolved.relative_to(repo_root.resolve())
            except ValueError as exc:
                raise ValueError(f"{label}.{name} escapes the repository") from exc
        if not isinstance(item["sha256"], str) or not _PLACEMENT_SHA256.fullmatch(item["sha256"]):
            raise ValueError(f"{label}.sha256 is invalid")
        if not isinstance(item["authority_sha256"], str) or not _PLACEMENT_SHA256.fullmatch(item["authority_sha256"]):
            raise ValueError(f"{label}.authority_sha256 is invalid")
        target = repo_root / Path(*path.parts)
        source = repo_root / Path(*authority.parts)
        if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError(f"{label}.path is missing or hash-mismatched")
        if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != item["authority_sha256"]:
            raise ValueError(f"{label}.authority is missing or hash-mismatched")
        covered.append(path.as_posix())
    if len(covered) != len(set(covered)):
        raise ValueError("canonical_root_artifacts contains duplicate paths")
    return tuple(covered)
_MEGAPLAN_INITIATIVE_ROOT_FILES = frozenset(
    {
        "README.md",
        "NORTHSTAR.md",
        "STRATEGY.md",
        "chain.yaml",
        # ``brief epic --cloud-ready`` scaffolds this beside chain.yaml.
        "cloud.yaml",
        "proof-map.json",
        "completion-manifest.json",
        # Dependency repair deliberately emits this beside the proof map.
        "dependency-completion-proof.json",
        # Retirement is initiative-wide state, not a prose handoff.
        ".retired",
    }
)
LEGACY_REFERENCE_PATTERNS = (
    "arnold.pipelines.megaplan",
    "arnold/pipelines/megaplan",
    "python -m arnold.pipelines.megaplan",
)
LEGACY_REFERENCE_CATEGORIES = frozenset(
    {
        "scanner-target",
        "historical-non-shipped",
    }
)
_SECURITY_NATIVE_REPRESENTATION_ROWS = (
    {
        "id": "human-decision-suspension",
        "requirement": "Human decision/suspension",
    },
    {
        "id": "execute-approval-gates",
        "requirement": "Execute approval/no-review/deferred-human gates",
    },
    {
        "id": "override-action-surface",
        "requirement": "Override full action surface",
    },
    {
        "id": "model-routing-policy",
        "requirement": "Model routing by phase/task complexity",
    },
)
_SECURITY_DISCOVERY_MODULE_HINTS = (
    "arnold.agent.agent.auxiliary_client",
    "arnold.agent.providers.env_loader",
    "arnold.agent.providers.pool",
    "arnold.agent.tools.image_generation_tool",
    "arnold.agent.tools.mcp_oauth",
    "arnold.agent.tools.mcp_tool",
    "arnold.agent.tools.skills_hub",
    "arnold.agent.tools.terminal_tool",
    "arnold.agent.tools.transcription_tools",
    "arnold.agent.tools.tts_tool",
    "arnold.agent.tools.web_tools",
    "arnold.security.policy",
)
_SECURITY_DISCOVERY_TEXT_PATTERNS = {
    "gh auth token": "gh-cli-token",
    ".hermes/auth.json": "oauth-auth-json",
    "mcp-tokens": "mcp-oauth-store",
}
_SENSITIVE_ENV_VAR_MARKERS = (
    "_API_KEY",
    "_TOKEN",
    "_SECRET",
    "_PASSWORD",
    "AUTHORIZATION",
)
_COVERED_SECURITY_ISOLATION_REQUIREMENTS = (
    {
        "surface_contains": "arnold.security.policy.SecurityPolicy.evaluate",
        "path": "arnold/security/git.py",
        "required_snippets": (
            "BrokerClient.from_environment()",
            "client.evaluate_action(action_request)",
        ),
        "failure": "git push-class broker evaluation is not wired through BrokerClient",
    },
    {
        "surface_contains": "arnold.security.policy.SecurityPolicy.evaluate",
        "path": "arnold/agent/tools/mcp_tool.py",
        "required_snippets": (
            "authorize_mcp_git_action(server_name, tool_name, args)",
            "_should_strip_github_mcp_credentials",
            "_sanitize_mcp_server_config",
        ),
        "failure": "covered MCP git paths are not isolated from raw GitHub credentials",
    },
    {
        "surface_contains": "arnold.agent.providers.pool.KeyPool.acquire",
        "path": "arnold/agent/providers/pool.py",
        "required_snippets": (
            "broker_production_mode_requested()",
            "resolve_brokered_llm_proxy(",
            "return self._acquire_brokered_key_unlocked(provider)",
        ),
        "failure": "covered provider-pool paths no longer fail closed to broker-scoped credentials",
    },
    {
        "surface_contains": "arnold.agent.agent.auxiliary_client.resolve_provider_client",
        "path": "arnold/agent/agent/auxiliary_client.py",
        "required_snippets": (
            "resolve_brokered_llm_proxy(",
            "warn_deferred_oauth_provider(",
            "broker_production_mode_requested()",
        ),
        "failure": "covered auxiliary provider routing is not broker-isolated in production mode",
    },
)


# ---------------------------------------------------------------------------
# Adapter protocol checks
# ---------------------------------------------------------------------------


def check_adapter_protocol_conformance(
    registry: ExecutionRegistries | None = None,
    *,
    smoke_kind: str | None = None,
    smoke_invocation: Mapping[str, Any] | None = None,
) -> ConformanceCheckResult:
    """Verify execution registry protocol and fail-closed behaviour.

    Parameters
    ----------
    registry:
        The execution registries to check.  When *None* a fresh fail-closed
        ``ExecutionRegistries()`` is constructed.
    smoke_kind:
        An optional registered kind whose adapter should survive a no-op
        smoke invocation.
    smoke_invocation:
        An optional mapping to pass as smoke invocation context.

    Returns
    -------
    ConformanceCheckResult
        ``passed=True`` when the registry behaves correctly.
    """
    if registry is None:
        registry = ExecutionRegistries()

    diagnostics: list[str] = []

    # --- unknown-kind fail-closed ---
    unknown_kind = "_conformance_unknown_kind_"
    try:
        registry.capabilities.get(unknown_kind)
        diagnostics.append(
            f"registry.capabilities.get({unknown_kind!r}) did not raise LookupError "
            f"(fail-closed broken)"
        )
    except LookupError:
        pass  # expected
    except Exception as exc:
        diagnostics.append(
            f"registry.capabilities.get({unknown_kind!r}) raised unexpected "
            f"{type(exc).__name__}: {exc}"
        )

    # --- registered keys expose deterministic ordering for diagnostics ---
    kinds = _registry_keys(registry.capabilities)
    if not isinstance(kinds, tuple):
        diagnostics.append(f"registry keys returned {type(kinds).__name__}, expected tuple")
    elif list(kinds) != sorted(kinds):
        diagnostics.append(f"registry keys are not sorted: {list(kinds)}")

    # --- smoke invocation (if requested) ---
    if smoke_kind is not None and smoke_invocation is not None:
        try:
            _ = registry.capabilities.check(
                smoke_kind,
                context={"invocation": dict(smoke_invocation)},
            )
        except Exception as exc:
            diagnostics.append(
                f"smoke invocation for kind {smoke_kind!r} raised "
                f"{type(exc).__name__}: {exc}"
            )

    # --- resolve returns something satisfying the protocol ---
    for kind in kinds:
        try:
            adapter = registry.capabilities.get(kind)
            if not isinstance(adapter, CapabilityHandler):
                diagnostics.append(
                    f"resolved adapter for {kind!r} is not a "
                    f"CapabilityHandler: {type(adapter).__name__}"
                )
        except Exception as exc:
            diagnostics.append(
                f"registry.capabilities.get({kind!r}) raised {type(exc).__name__}: {exc}"
            )

    if diagnostics:
        return ConformanceCheckResult(
            check_id="adapter-protocol",
            passed=False,
            message="; ".join(diagnostics),
            details=diagnostics,
        )
    return ConformanceCheckResult(check_id="adapter-protocol", passed=True)


def check_adapter_unknown_kind_fail_closed(
    registry: ExecutionRegistries | None = None,
) -> ConformanceCheckResult:
    """Verify that resolving an unknown kind raises ``LookupError`` and that
    the error message names the kind and lists registered kinds.

    This check is deliberately isolated so callers can assert the exact
    fail-closed behaviour that the validator and C4 passes rely on.
    """
    if registry is None:
        registry = ExecutionRegistries()

    unknown_kind = "_conformance_fail_closed_kind_"
    try:
        registry.capabilities.get(unknown_kind)
        return ConformanceCheckResult(
            check_id="adapter-unknown-kind-fail-closed",
            passed=False,
            message=f"registry.capabilities.get({unknown_kind!r}) did not raise LookupError",
        )
    except LookupError as exc:
        message = str(exc)
        registered_kinds = _registry_keys(registry.capabilities)
        if unknown_kind not in message:
            return ConformanceCheckResult(
                check_id="adapter-unknown-kind-fail-closed",
                passed=False,
                message=(
                    f"KeyError message does not name {unknown_kind!r}: {message}"
                ),
                details={"error_message": message, "unknown_kind": unknown_kind},
            )
        if not any(k in message for k in registered_kinds):
            # Acceptable — not all implementations must list kinds
            pass
        return ConformanceCheckResult(check_id="adapter-unknown-kind-fail-closed", passed=True)
    except Exception as exc:
        return ConformanceCheckResult(
            check_id="adapter-unknown-kind-fail-closed",
            passed=False,
            message=(
                f"registry.capabilities.get({unknown_kind!r}) raised unexpected "
                f"{type(exc).__name__}: {exc}"
            ),
        )


# ---------------------------------------------------------------------------
# ContractResult schema round-trip checks
# ---------------------------------------------------------------------------


def check_contract_result_schema_round_trip(
    *,
    contract: ContractResult | None = None,
) -> ConformanceCheckResult:
    """Verify ``ContractResult.to_json()`` → ``from_json()`` round-trip fidelity.

    Constructs a minimal representative ``ContractResult`` (or uses the
    caller-supplied *contract*) and checks that serializing and deserializing
    produces an equal object.

    Parameters
    ----------
    contract:
        An optional pre-built ``ContractResult`` to round-trip.  When *None*
        a default-complete instance is created with all fields populated.

    Returns
    -------
    ConformanceCheckResult
        ``passed=True`` when the round-trip produces an equal value.
    """
    if contract is None:
        contract = _make_representative_contract()

    try:
        json_dict = contract.to_json()
    except Exception as exc:
        return ConformanceCheckResult(
            check_id="contract-result-to-json",
            passed=False,
            message=f"to_json() raised {type(exc).__name__}: {exc}",
            details={"error": str(exc)},
        )

    if not isinstance(json_dict, dict):
        return ConformanceCheckResult(
            check_id="contract-result-to-json",
            passed=False,
            message=f"to_json() returned {type(json_dict).__name__}, expected dict",
        )

    try:
        restored = ContractResult.from_json(json_dict)
    except Exception as exc:
        return ConformanceCheckResult(
            check_id="contract-result-from-json",
            passed=False,
            message=f"from_json() raised {type(exc).__name__}: {exc}",
            details={"error": str(exc), "json_dict": json_dict},
        )

    if not isinstance(restored, ContractResult):
        return ConformanceCheckResult(
            check_id="contract-result-from-json",
            passed=False,
            message=(
                f"from_json() returned {type(restored).__name__}, "
                f"expected ContractResult"
            ),
        )

    if restored != contract:
        diffs = _diff_contracts(contract, restored)
        return ConformanceCheckResult(
            check_id="contract-result-round-trip-fidelity",
            passed=False,
            message=f"round-trip produced different value; diffs: {diffs}",
            details={"original": contract, "restored": restored, "diffs": diffs},
        )

    return ConformanceCheckResult(check_id="contract-result-round-trip-fidelity", passed=True)


def check_contract_result_schema_version_skew() -> ConformanceCheckResult:
    """Verify that ``ContractResult.from_json`` rejects a mismatched schema version.

    This check constructs a valid JSON dict, tampers with ``schema_version``
    to a value that does not match ``CONTRACT_RESULT_SCHEMA_VERSION``, and
    asserts that ``from_json`` raises ``ValueError``.

    The check is loud: it confirms that schema-version skew is surfaced as
    a hard error, not silently normalised.
    """
    contract = _make_representative_contract()
    json_dict = contract.to_json()

    # Tamper with schema_version to something that will never match
    tampered = dict(json_dict)
    tampered["schema_version"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

    try:
        ContractResult.from_json(tampered)
        return ConformanceCheckResult(
            check_id="contract-result-schema-version-skew",
            passed=False,
            message=(
                "from_json() accepted a tampered schema_version without raising ValueError"
            ),
            details={"tampered_schema_version": tampered["schema_version"]},
        )
    except ValueError:
        return ConformanceCheckResult(
            check_id="contract-result-schema-version-skew", passed=True
        )
    except Exception as exc:
        return ConformanceCheckResult(
            check_id="contract-result-schema-version-skew",
            passed=False,
            message=(
                f"from_json() with skew raised unexpected {type(exc).__name__}: {exc}"
            ),
            details={"error": str(exc)},
        )


def check_contract_result_empty_schema_version_accepted() -> ConformanceCheckResult:
    """Verify that ``ContractResult.from_json`` accepts an empty string
    ``schema_version`` as an unspecified/default sentinel.

    An empty ``schema_version`` in persisted JSON means "use the current
    version" — this is the ``__post_init__`` default-fill path.  The check
    confirms that the empty-string case does NOT raise, preserving backward
    compatibility for serialized records that omit the field.
    """
    contract = _make_representative_contract()
    json_dict = contract.to_json()

    tampered = dict(json_dict)
    tampered["schema_version"] = ""

    try:
        restored = ContractResult.from_json(tampered)
    except Exception as exc:
        return ConformanceCheckResult(
            check_id="contract-result-empty-schema-version-accepted",
            passed=False,
            message=(
                f"from_json() with empty schema_version raised "
                f"{type(exc).__name__}: {exc}"
            ),
        )

    from arnold.pipeline.types import CONTRACT_RESULT_SCHEMA_VERSION

    # When schema_version is empty in JSON, from_json fills the current version
    if restored.schema_version != CONTRACT_RESULT_SCHEMA_VERSION:
        return ConformanceCheckResult(
            check_id="contract-result-empty-schema-version-accepted",
            passed=False,
            message=(
                f"from_json() filled schema_version={restored.schema_version!r}, "
                f"expected {CONTRACT_RESULT_SCHEMA_VERSION!r}"
            ),
        )

    return ConformanceCheckResult(
        check_id="contract-result-empty-schema-version-accepted", passed=True
    )


# ---------------------------------------------------------------------------
# Generic Arnold anti-coupling ratchet
# ---------------------------------------------------------------------------


def check_generic_arnold_megaplan_coupling(
    *,
    package_root: Path | None = None,
    allowlist: Collection[str] | None = None,
    allowlist_path: Path | None = None,
) -> ConformanceCheckResult:
    """Fail when neutral ``arnold`` modules add new Megaplan imports.

    The gate is a ratchet: known legacy generic-Arnold modules that still
    import Megaplan are listed in ``_megaplan_coupling_allowlist.txt``.  New
    generic modules that import ``arnold.pipelines.megaplan`` or top-level
    ``megaplan`` fail the check.  Stale allowlist entries also fail so the
    baseline tightens as compatibility shims are retired.
    """
    root = package_root or _DEFAULT_ARNOLD_ROOT
    allowed = (
        set(allowlist)
        if allowlist is not None
        else _read_megaplan_coupling_allowlist(
            allowlist_path or _DEFAULT_MEGAPLAN_COUPLING_ALLOWLIST
        )
    )
    coupled = _scan_generic_arnold_megaplan_imports(root)

    coupled_modules = set(coupled)
    unexpected = {
        module: coupled[module]
        for module in sorted(coupled_modules - allowed)
    }
    stale_allowlist = sorted(allowed - coupled_modules)

    details = {
        "allowlisted_count": len(allowed),
        "coupled_count": len(coupled_modules),
        "unexpected": unexpected,
        "stale_allowlist": stale_allowlist,
    }

    diagnostics: list[str] = []
    if unexpected:
        diagnostics.append(
            "new generic Arnold Megaplan coupling: "
            + ", ".join(sorted(unexpected))
        )
    if stale_allowlist:
        diagnostics.append(
            "stale Megaplan coupling allowlist entries: "
            + ", ".join(stale_allowlist)
        )

    if diagnostics:
        return ConformanceCheckResult(
            check_id="generic-arnold-megaplan-coupling",
            passed=False,
            message="; ".join(diagnostics),
            details=details,
        )

    return ConformanceCheckResult(
        check_id="generic-arnold-megaplan-coupling",
        passed=True,
        details=details,
    )


def check_package_name_staleness(
    *,
    package_root: Path | None = None,
    allowlist: Collection[str] | None = None,
) -> ConformanceCheckResult:
    """Fail when neutral Arnold code carries active Megaplan package literals."""

    root = package_root or _DEFAULT_ARNOLD_ROOT
    allowed = set(allowlist or set())
    unexpected: dict[str, tuple[str, ...]] = {}
    for path in sorted(root.rglob("*.py")):
        if _is_excluded_from_generic_arnold_scan(root, path):
            continue
        module = _module_name_from_path(root, path)
        if module in allowed:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            continue
        hits = sorted(
            {
                package_name
                for value in _string_constants(tree)
                for package_name in ACTIVE_MEGAPLAN_PACKAGE_NAMES
                if package_name in value
                and not (
                    package_name == "megaplan"
                    and (
                        "arnold.pipelines.megaplan" in value
                        or "arnold_pipelines.megaplan" in value
                    )
                )
            }
        )
        if hits:
            unexpected[module] = tuple(hits)

    details = {"unexpected": unexpected}
    if unexpected:
        return ConformanceCheckResult(
            check_id="package-name-staleness",
            passed=False,
            message="stale Megaplan package-name literals: " + ", ".join(sorted(unexpected)),
            details=details,
        )
    return ConformanceCheckResult(check_id="package-name-staleness", passed=True, details=details)


def check_import_coupling(
    *,
    package_root: Path | None = None,
    allowlist: Collection[str] | None = None,
) -> ConformanceCheckResult:
    result = check_generic_arnold_megaplan_coupling(
        package_root=package_root,
        allowlist=allowlist,
    )
    return ConformanceCheckResult(
        check_id="import-coupling",
        passed=result.passed,
        message=result.message,
        details=result.details,
    )


def check_semantic_coupling(
    *,
    package_root: Path | None = None,
    allowlist: Collection[str] | None = None,
) -> ConformanceCheckResult:
    root = package_root or _DEFAULT_ARNOLD_ROOT
    allowed = set(allowlist or set())
    unexpected: dict[str, tuple[str, ...]] = {}
    for path in sorted(root.rglob("*.py")):
        if _is_excluded_from_generic_arnold_scan(root, path):
            continue
        module = _module_name_from_path(root, path)
        if module in allowed:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            continue
        hits: set[str] = set()
        for value in _string_constants(tree):
            if ".megaplan" in value:
                hits.add(".megaplan")
            if "PlanState" in value:
                hits.add("PlanState")
            if "tiebreaker" in value:
                hits.add("tiebreaker")
                hits.add("phase:tiebreaker")
            if value.startswith("handle_"):
                hits.add("handler-name")
        if hits:
            unexpected[module] = tuple(sorted(hits))
    details = {"unexpected": unexpected}
    return ConformanceCheckResult(
        check_id="semantic-coupling",
        passed=not unexpected,
        message="" if not unexpected else "semantic Megaplan coupling: " + ", ".join(sorted(unexpected)),
        details=details,
    )


def check_public_workflow_layering(
    *,
    package_root: Path | None = None,
    allowlist: Collection[str] | None = None,
) -> ConformanceCheckResult:
    root = package_root or _DEFAULT_ARNOLD_ROOT
    allowed = set(allowlist or set())
    unexpected: dict[str, tuple[str, ...]] = {}
    for path in sorted(root.rglob("*.py")):
        if path.name != "__init__.py" or "pipelines" not in path.parts:
            continue
        if _is_excluded_from_generic_arnold_scan(root, path):
            continue
        module = _module_name_from_path(root, path)
        if module in allowed:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            continue
        hits: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "arnold.pipeline":
                if any(alias.name == "Stage" for alias in node.names):
                    hits.add("package-imports-Stage")
            if isinstance(node, ast.AnnAssign | ast.arg | ast.FunctionDef):
                if "Stage" in ast.unparse(node):
                    hits.add("annotation-Stage")
        for value in _string_constants(tree):
            if value == "Stage":
                hits.add("exports-Stage")
        if hits:
            unexpected[module] = tuple(sorted(hits))
    details = {"unexpected": unexpected}
    return ConformanceCheckResult(
        check_id="public-workflow-layering",
        passed=not unexpected,
        message="" if not unexpected else "public workflow layering leak: " + ", ".join(sorted(unexpected)),
        details=details,
    )


def check_never_port_artifacts(
    *,
    repo_root: Path | None = None,
    allowlist: Collection[str] | None = None,
) -> ConformanceCheckResult:
    root = repo_root or _DEFAULT_ARNOLD_ROOT.parent
    allowed = set(allowlist or set())
    unexpected: dict[str, tuple[str, ...]] = {}

    def _is_allowed(rel: str) -> bool:
        for pattern in allowed:
            if pattern == rel:
                return True
            if pattern.endswith("/**") and rel.startswith(pattern[:-3] + "/"):
                return True
            if fnmatch.fnmatch(rel, pattern):
                return True
        return False

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if _is_allowed(rel):
            continue
        reason: str | None = None
        if rel.startswith(".megaplan/_archived-plans/"):
            reason = ".megaplan archived plan"
        elif rel == ".hermes_state" or rel == ".omp_state":
            reason = "agent runtime state"
        elif rel.endswith((".db-wal", ".db-shm")):
            reason = "database sidecar"
        elif rel.startswith("logs/") and rel.endswith(".log"):
            reason = "driver log"
        elif rel.startswith("runs/") and (
            "prompt" in Path(rel).name or Path(rel).name in {"receipt.json", "runtime_state.json"}
        ):
            reason = "runtime artifact"
        if reason:
            unexpected[rel] = (reason,)
    details = {"unexpected": unexpected}
    return ConformanceCheckResult(
        check_id="never-port-artifacts",
        passed=not unexpected,
        message="" if not unexpected else "runtime artifacts present: " + ", ".join(sorted(unexpected)),
        details=details,
    )


def check_megaplan_artifact_layout(
    *,
    repo_root: Path | None = None,
    allowlist: Collection[str] | None = None,
) -> ConformanceCheckResult:
    """Validate durable planning artifacts live in the canonical tree."""
    root = repo_root or _DEFAULT_ARNOLD_ROOT.parent
    allowed = set(allowlist or set())
    unexpected: dict[str, tuple[str, ...]] = {}

    # Proof maps are the authority for initiative-local evidence receipts.
    # Permit only exact, repo-relative root artifacts that a proof map names;
    # this preserves the loose-file ratchet while allowing generated receipts
    # to remain beside the manifest that hashes them.
    declared_proof_paths: set[str] = set()

    def _walk_strings(value: object) -> tuple[str, ...]:
        if isinstance(value, str):
            return (value,)
        if isinstance(value, Mapping):
            return tuple(
                item
                for nested in value.values()
                for item in _walk_strings(nested)
            )
        if isinstance(value, (list, tuple)):
            return tuple(item for nested in value for item in _walk_strings(nested))
        return ()

    initiatives_root = root / ".megaplan" / "initiatives"
    for proof_map in sorted(initiatives_root.glob("*/proof-map.json")):
        try:
            payload = json.loads(proof_map.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        initiative_prefix = proof_map.parent.relative_to(root).as_posix() + "/"
        for candidate in _walk_strings(payload):
            candidate_path = Path(candidate)
            if candidate_path.is_absolute() or ".." in candidate_path.parts:
                continue
            normalized = candidate_path.as_posix()
            if not normalized.startswith(initiative_prefix):
                continue
            if len(candidate_path.parts) == 4:
                declared_proof_paths.add(normalized)

    def _is_allowed(rel: str) -> bool:
        for pattern in allowed:
            if pattern == rel:
                return True
            if pattern.endswith("/**") and rel.startswith(pattern[:-3] + "/"):
                return True
            if fnmatch.fnmatch(rel, pattern):
                return True
        return False

    placement_paths: set[str] = set()
    placement_record = root / "docs" / "megaplan" / "post-m11-release-evidence-20260731.json"
    collection_root = root / Path(*PurePosixPath(_COLLECTION_ROOT).parts)
    if collection_root.exists() or (root / Path(*PurePosixPath(_COLLECTION_AUTHORITY).parts)).is_file():
        try:
            placement_paths.update(
                validate_collection_artifact_placements(
                    json.loads(placement_record.read_text(encoding="utf-8"))
                    if placement_record.is_file()
                    else {},
                    repo_root=root,
                )
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            unexpected[_COLLECTION_ROOT] = (
                f"invalid typed collection layout contract: {exc}",
            )
    if placement_record.is_file():
        try:
            placement_paths.update(
                validate_canonical_artifact_placements(
                    json.loads(placement_record.read_text(encoding="utf-8")),
                    repo_root=root,
                )
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            unexpected[placement_record.relative_to(root).as_posix()] = (
                f"invalid typed canonical placement record: {exc}",
            )
    root_artifact_paths: set[str] = set()
    if placement_record.is_file():
        try:
            root_artifact_paths.update(
                validate_canonical_root_artifacts(
                    json.loads(placement_record.read_text(encoding="utf-8")),
                    repo_root=root,
                )
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            unexpected[placement_record.relative_to(root).as_posix()] = (
                f"invalid typed canonical root-artifact record: {exc}",
            )

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if _is_allowed(rel):
            continue
        if rel in placement_paths:
            continue
        if rel in root_artifact_paths:
            continue
        if rel in declared_proof_paths:
            continue
        reason: str | None = None
        if rel == "chain.yaml":
            reason = "root chain spec"
        elif rel == "cloud.yaml":
            reason = "root cloud runner spec"
        elif rel.startswith("briefs/"):
            reason = "legacy top-level briefs tree"
        elif rel.startswith(".megaplan/briefs/"):
            reason = "legacy .megaplan/briefs tree"
        elif rel.startswith(".megaplan/") and len(Path(rel).parts) == 2 and Path(rel).name.startswith("plan_v"):
            reason = "loose plan version outside .megaplan/plans"
        elif rel.startswith(".megaplan/initiatives/"):
            parts = Path(rel).parts
            if len(parts) < 4 or not parts[2]:
                reason = "invalid initiative path"
            elif len(parts) == 4 and parts[3] in _MEGAPLAN_INITIATIVE_ROOT_FILES:
                reason = None
            elif len(parts) >= 5 and parts[3] in _MEGAPLAN_INITIATIVE_SUBDIRS:
                reason = None
            else:
                reason = "initiative artifact outside canonical subdirectories"
        elif rel.startswith(_COLLECTION_ROOT + "/"):
            reason = "collection artifact outside validated authority bindings"
        elif rel.endswith("/chain.yaml"):
            reason = "chain spec outside .megaplan/initiatives/<initiative>/chain.yaml"
        if reason:
            unexpected[rel] = (reason,)
    details = {"unexpected": unexpected}
    return ConformanceCheckResult(
        check_id="megaplan-artifact-layout",
        passed=not unexpected,
        message="" if not unexpected else "misplaced megaplan artifacts: " + ", ".join(sorted(unexpected)),
        details=details,
    )


def check_legacy_reference_allowlist(
    *,
    repo_root: Path | None = None,
    allowlist_path: Path | None = None,
    allowlist: Collection[Mapping[str, str]] | None = None,
) -> ConformanceCheckResult:
    """Validate the machine-readable legacy Megaplan reference allowlist.

    The JSON allowlist is the milestone authority for any permitted remaining
    references to the deleted ``arnold.pipelines.megaplan`` root.  Entries are
    intentionally narrow: each one names an exact repository path, one scanner
    pattern, an allowed category, and a reason.  The check fails for malformed
    entries, stale entries whose path no longer contains the pattern, and live
    non-archive references missing from the allowlist.
    """

    root = repo_root or _DEFAULT_ARNOLD_ROOT.parent
    records = (
        list(allowlist)
        if allowlist is not None
        else _read_legacy_reference_allowlist(
            allowlist_path or _DEFAULT_LEGACY_REFERENCE_ALLOWLIST
        )
    )
    resolved_allowlist_path = (
        allowlist_path or _DEFAULT_LEGACY_REFERENCE_ALLOWLIST
    ).resolve()
    resolved_root = root.resolve()
    allowlist_rel = (
        resolved_allowlist_path.relative_to(resolved_root).as_posix()
        if resolved_allowlist_path.is_relative_to(resolved_root)
        else None
    )

    invalid_entries: list[dict[str, Any]] = []
    allowed: set[tuple[str, str]] = set()
    duplicates: list[dict[str, str]] = []
    for index, record in enumerate(records):
        normalized, errors = _normalize_legacy_reference_entry(record)
        if errors:
            invalid_entries.append(
                {"index": index, "entry": dict(record), "errors": errors}
            )
            continue
        key = (normalized["path"], normalized["pattern"])
        if key in allowed:
            duplicates.append(
                {"path": normalized["path"], "pattern": normalized["pattern"]}
            )
        allowed.add(key)

    references = _scan_legacy_references(root, allowlist_rel=allowlist_rel)
    observed = {(hit["path"], hit["pattern"]) for hit in references}
    unallowlisted = [
        hit for hit in references if (hit["path"], hit["pattern"]) not in allowed
    ]
    stale = [
        {"path": path, "pattern": pattern}
        for path, pattern in sorted(allowed - observed)
    ]

    details = {
        "allowlisted_count": len(allowed),
        "observed_count": len(observed),
        "unallowlisted": unallowlisted,
        "stale_allowlist": stale,
        "invalid_entries": invalid_entries,
        "duplicates": duplicates,
    }

    diagnostics: list[str] = []
    if invalid_entries:
        diagnostics.append(f"invalid legacy reference allowlist entries: {len(invalid_entries)}")
    if duplicates:
        diagnostics.append(f"duplicate legacy reference allowlist entries: {len(duplicates)}")
    if stale:
        diagnostics.append(
            "stale legacy reference allowlist entries: "
            + ", ".join(f"{item['path']}:{item['pattern']}" for item in stale)
        )
    if unallowlisted:
        diagnostics.append(
            "unallowlisted legacy references: "
            + ", ".join(
                f"{item['path']}:{item['pattern']}" for item in unallowlisted[:20]
            )
        )

    return ConformanceCheckResult(
        check_id="legacy-reference-allowlist",
        passed=not diagnostics,
        message="; ".join(diagnostics),
        details=details,
    )


def check_security_coverage_matrix(
    *,
    repo_root: Path | None = None,
) -> ConformanceCheckResult:
    """Validate security credential coverage classification and broker isolation."""

    from arnold.security.coverage_matrix import (
        CoverageStatus,
        get_coverage_matrix,
        get_uncovered_surfaces,
    )

    root = repo_root or _DEFAULT_ARNOLD_ROOT.parent
    entries = list(get_coverage_matrix())
    discovered = _discover_security_credential_surfaces(root / "arnold")
    missing_classification = [
        item
        for item in discovered
        if not _find_security_coverage_matches(item, entries)
    ]
    covered_failures = _validate_covered_security_isolation(root, entries)
    reported_non_production = [
        {
            "surface": entry.credential_surface,
            "status": entry.m2_status.value,
            "residual_risk": entry.residual_risk.value,
            "deferral_target": entry.deferral_target,
            "notes": entry.notes,
        }
        for entry in get_uncovered_surfaces()
    ]

    details = {
        "affected_native_representation_rows": list(
            _SECURITY_NATIVE_REPRESENTATION_ROWS
        ),
        "covered_surface_count": sum(
            1 for entry in entries if entry.m2_status == CoverageStatus.COVERED
        ),
        "discovered_surface_count": len(discovered),
        "missing_classifications": missing_classification,
        "covered_isolation_failures": covered_failures,
        "reported_non_production_surfaces": reported_non_production,
    }

    diagnostics: list[str] = []
    if covered_failures:
        diagnostics.append(
            "covered production broker isolation failures: "
            + ", ".join(sorted(item["surface"] for item in covered_failures))
        )
    if missing_classification:
        diagnostics.append(
            "discovered credential paths missing coverage-matrix classification: "
            + ", ".join(sorted(item["target"] for item in missing_classification))
        )
    if reported_non_production:
        diagnostics.append(
            f"reported {len(reported_non_production)} deferred/uncovered non-production credential paths"
        )

    return ConformanceCheckResult(
        check_id="security-coverage-matrix",
        passed=not covered_failures and not missing_classification,
        message="; ".join(diagnostics),
        details=details,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _NoOpAdapter:
    """A capability handler fixture for conformance smoke checks."""

    def check(
        self,
        requirement_id: str,
        *,
        route: str,
        context: Mapping[str, Any],
    ):
        from arnold.kernel import CapabilityCheck, CapabilityId

        del route, context
        return CapabilityCheck(
            capability_id=CapabilityId(namespace="conformance", name=requirement_id),
            allowed=True,
        )


def _make_representative_contract() -> ContractResult:
    """Build a ContractResult with all fields populated for round-trip testing."""
    from arnold.pipeline.types import (
        EvidenceArtifactRef,
        Freshness,
        HumanSuspension,
        Provenance,
    )

    return ContractResult(
        payload={"key": "value", "nested": {"a": 1}},
        status=ContractStatus.COMPLETED,
        schema_version="",  # __post_init__ fills this from CONTRACT_RESULT_SCHEMA_VERSION
        suspension=None,
        evidence_refs=(
            EvidenceArtifactRef(
                uri="file:///tmp/test.png",
                content_type="image/png",
                digest="sha256:abcd1234",
                size_bytes=1024,
                name="test.png",
            ),
        ),
        authority_level="verified",
        provenance=Provenance(
            sources=("policy:example",),
            generator="conformance-test@0.1",
            generated_at="2025-01-01T00:00:00Z",
            chain=("claim", "evidence"),
        ),
        freshness=Freshness(
            observed_at="2025-01-01T00:00:00Z",
            ttl_seconds=3600,
            expires_at="2025-01-01T01:00:00Z",
        ),
    )


def _diff_contracts(original: ContractResult, restored: ContractResult) -> dict[str, Any]:
    """Return a dict of differing fields between two ContractResult values."""
    diffs: dict[str, Any] = {}
    fields = (
        "payload",
        "status",
        "schema_version",
        "suspension",
        "evidence_refs",
        "authority_level",
        "provenance",
        "freshness",
    )
    for f in fields:
        orig_val = getattr(original, f)
        rest_val = getattr(restored, f)
        if orig_val != rest_val:
            diffs[f] = {"original": orig_val, "restored": rest_val}
    return diffs


def _read_megaplan_coupling_allowlist(path: Path) -> set[str]:
    allowed: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line:
            allowed.add(line)
    return allowed


def _read_legacy_reference_allowlist(path: Path) -> list[Mapping[str, str]]:
    if not path.exists():
        return []
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(loaded, list):
        return loaded
    if isinstance(loaded, dict) and isinstance(loaded.get("references"), list):
        return loaded["references"]
    return [
        {
            "path": str(path),
            "pattern": "",
            "category": "",
            "reason": (
                "legacy reference allowlist JSON must be a list or an object "
                "with a 'references' list"
            ),
        }
    ]


def _normalize_legacy_reference_entry(
    record: Mapping[str, str],
) -> tuple[dict[str, str], list[str]]:
    required = ("path", "pattern", "category", "reason")
    errors: list[str] = []
    normalized: dict[str, str] = {}
    for key in required:
        value = record.get(key)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"missing or empty {key!r}")
            normalized[key] = ""
        else:
            normalized[key] = value.strip()
    extra = sorted(set(record) - set(required))
    if extra:
        errors.append("unexpected keys: " + ", ".join(extra))
    if normalized.get("pattern") not in LEGACY_REFERENCE_PATTERNS:
        errors.append(f"unsupported pattern {normalized.get('pattern')!r}")
    if normalized.get("category") not in LEGACY_REFERENCE_CATEGORIES:
        errors.append(f"unsupported category {normalized.get('category')!r}")
    if Path(normalized.get("path", "")).is_absolute():
        errors.append("path must be repository-relative")
    return normalized, errors


def _scan_legacy_references(
    root: Path,
    *,
    allowlist_rel: str | None = None,
) -> list[dict[str, str]]:
    references: list[dict[str, str]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel == allowlist_rel or _is_excluded_from_legacy_reference_scan(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for pattern in LEGACY_REFERENCE_PATTERNS:
            if pattern in text:
                references.append({"path": rel, "pattern": pattern})
    return references


def _is_excluded_from_legacy_reference_scan(relative_path: str) -> bool:
    parts = relative_path.split("/")
    if (
        parts[0] in {
            ".git",
            ".megaplan",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            "__pycache__",
        }
        or "__pycache__" in parts
        or relative_path.startswith("tests/archive/")
        or relative_path.startswith("docs/archive/")
        or relative_path.startswith("docs/arnold/workflow-manifest-runtime-review/")
    ):
        return True
    return False


def _registry_keys(registry: Any) -> tuple[str, ...]:
    return tuple(sorted(getattr(registry, "_handlers", {}).keys()))


def _scan_generic_arnold_megaplan_imports(root: Path) -> dict[str, tuple[str, ...]]:
    coupled: dict[str, tuple[str, ...]] = {}
    for path in sorted(root.rglob("*.py")):
        if _is_excluded_from_generic_arnold_scan(root, path):
            continue

        module = _module_name_from_path(root, path)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            coupled[module] = (f"<syntax-error:{exc.msg}>",)
            continue

        imports = sorted(
            {
                imported
                for node in ast.walk(tree)
                for imported in _megaplan_imports_from_node(node, module, path)
            }
        )
        if imports:
            coupled[module] = tuple(imports)
    return coupled


def _is_excluded_from_generic_arnold_scan(root: Path, path: Path) -> bool:
    relative_parts = path.relative_to(root).parts
    if "__pycache__" in relative_parts or "tests" in relative_parts:
        return True
    if path.name.startswith(".") or any(part.startswith(".") for part in relative_parts):
        return True
    return False


def _module_name_from_path(root: Path, path: Path) -> str:
    relative = path.relative_to(root).with_suffix("")
    parts = relative.parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(("arnold", *parts))


def _megaplan_imports_from_node(
    node: ast.AST,
    module_name: str,
    path: Path,
) -> tuple[str, ...]:
    if isinstance(node, ast.Import):
        return tuple(
            alias.name for alias in node.names if _is_megaplan_import(alias.name)
        )
    if isinstance(node, ast.ImportFrom):
        resolved = _resolve_import_from_module(node, module_name, path)
        imports: list[str] = []
        if resolved and _is_megaplan_import(resolved):
            imports.append(resolved)
            if resolved.startswith("arnold_pipelines."):
                for alias in node.names:
                    alias_module = f"{resolved}.{alias.name}"
                    imports.append(alias_module)
        elif resolved:
            for alias in node.names:
                alias_module = f"{resolved}.{alias.name}"
                if _is_megaplan_import(alias_module):
                    imports.append(alias_module)
        return tuple(imports)
    return ()


def _resolve_import_from_module(
    node: ast.ImportFrom,
    module_name: str,
    path: Path,
) -> str:
    if not node.level:
        return node.module or ""

    package_parts = (
        module_name.split(".")
        if path.name == "__init__.py"
        else module_name.split(".")[:-1]
    )
    if node.level > len(package_parts):
        return node.module or ""

    base_parts = package_parts[: len(package_parts) - node.level + 1]
    if node.module:
        base_parts.extend(node.module.split("."))
    return ".".join(base_parts)


def _is_megaplan_import(module: str) -> bool:
    return any(
        module == package_name or module.startswith(package_name + ".")
        for package_name in ACTIVE_MEGAPLAN_PACKAGE_NAMES
    )


def _string_constants(tree: ast.AST) -> set[str]:
    docstring_nodes: set[ast.AST] = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if (
            isinstance(body, list)
            and body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            docstring_nodes.add(body[0].value)
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
        and node not in docstring_nodes
    }


def _discover_security_credential_surfaces(package_root: Path) -> list[dict[str, Any]]:
    discovered: dict[tuple[str, str, str], dict[str, Any]] = {}
    for path in sorted(package_root.rglob("*.py")):
        if _is_excluded_from_generic_arnold_scan(package_root, path):
            continue
        module = _module_name_from_path(package_root, path)
        if not any(module.startswith(prefix) for prefix in _SECURITY_DISCOVERY_MODULE_HINTS):
            continue
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        _walk_security_discovery(tree, module, path, discovered)
        for pattern, reason in _SECURITY_DISCOVERY_TEXT_PATTERNS.items():
            if pattern in source:
                _record_security_discovery(
                    discovered,
                    module=module,
                    path=path,
                    target=module,
                    reason=reason,
                    indicator=pattern,
                )
    return sorted(
        discovered.values(),
        key=lambda item: (item["target"], item["reason"], item["indicator"]),
    )


def _walk_security_discovery(
    node: ast.AST,
    module: str,
    path: Path,
    discovered: dict[tuple[str, str, str], dict[str, Any]],
    scope: tuple[str, ...] = (),
) -> None:
    next_scope = scope
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        next_scope = (*scope, node.name)
        if isinstance(node, ast.ClassDef) and node.name in {"GitHubAuth", "HermesTokenStorage"}:
            _record_security_discovery(
                discovered,
                module=module,
                path=path,
                target=f"{module}.{node.name}",
                reason="auth-surface",
                indicator=node.name,
            )
        if node.name == "load_hermes_dotenv":
            _record_security_discovery(
                discovered,
                module=module,
                path=path,
                target=f"{module}.{node.name}",
                reason="env-loader",
                indicator=node.name,
            )

    env_var = _extract_sensitive_env_var(node)
    if env_var:
        _record_security_discovery(
            discovered,
            module=module,
            path=path,
            target=_module_scope_target(module, next_scope),
            reason="env-credential",
            indicator=env_var,
        )

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        value = node.value
        if value.strip().startswith("git push"):
            _record_security_discovery(
                discovered,
                module=module,
                path=path,
                target=_module_scope_target(module, next_scope),
                reason="git-push-command",
                indicator="git push",
            )

    for child in ast.iter_child_nodes(node):
        _walk_security_discovery(child, module, path, discovered, next_scope)


def _extract_sensitive_env_var(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Call) or not node.args:
        return None
    candidate: str | None = None
    if isinstance(node.func, ast.Name) and node.func.id == "getenv":
        candidate = _string_literal(node.args[0])
    elif isinstance(node.func, ast.Attribute):
        if node.func.attr == "getenv" and _is_os_name(node.func.value):
            candidate = _string_literal(node.args[0])
        elif node.func.attr == "get" and _is_os_environ(node.func.value):
            candidate = _string_literal(node.args[0])
    if candidate and any(marker in candidate for marker in _SENSITIVE_ENV_VAR_MARKERS):
        return candidate
    return None


def _string_literal(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_os_name(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id == "os"


def _is_os_environ(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "environ"
        and _is_os_name(node.value)
    )


def _module_scope_target(module: str, scope: tuple[str, ...]) -> str:
    return ".".join((module, *scope)) if scope else module


def _record_security_discovery(
    discovered: dict[tuple[str, str, str], dict[str, Any]],
    *,
    module: str,
    path: Path,
    target: str,
    reason: str,
    indicator: str,
) -> None:
    key = (target, reason, indicator)
    discovered[key] = {
        "module": module,
        "path": path.as_posix(),
        "target": target,
        "reason": reason,
        "indicator": indicator,
    }


def _find_security_coverage_matches(
    discovered: Mapping[str, Any],
    entries: Collection[Any],
) -> list[str]:
    module = str(discovered["module"])
    target = str(discovered["target"])
    matches = [
        entry.credential_surface
        for entry in entries
        if target in entry.credential_surface or module in entry.credential_surface
    ]
    return sorted(set(matches))


def _validate_covered_security_isolation(
    repo_root: Path,
    entries: Collection[Any],
) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    for requirement in _COVERED_SECURITY_ISOLATION_REQUIREMENTS:
        relevant_entries = [
            entry
            for entry in entries
            if entry.m2_status.value == "covered"
            and requirement["surface_contains"] in entry.credential_surface
        ]
        if not relevant_entries:
            continue
        source_path = repo_root / requirement["path"]
        try:
            source = source_path.read_text(encoding="utf-8")
        except OSError as exc:
            failures.append(
                {
                    "surface": requirement["surface_contains"],
                    "path": requirement["path"],
                    "missing_snippets": ["<unreadable>"],
                    "error": str(exc),
                    "reason": requirement["failure"],
                }
            )
            continue
        missing_snippets = [
            snippet
            for snippet in requirement["required_snippets"]
            if snippet not in source
        ]
        if missing_snippets:
            failures.append(
                {
                    "surface": requirement["surface_contains"],
                    "path": requirement["path"],
                    "missing_snippets": missing_snippets,
                    "reason": requirement["failure"],
                    "classified_rows": [
                        entry.credential_surface for entry in relevant_entries
                    ],
                }
            )
    return failures


def check_adapter_smoke_invocation(
    registry: ExecutionRegistries,
    kind: str,
    invocation: Mapping[str, Any],
) -> ConformanceCheckResult:
    """Run a smoke invocation through a registered adapter and surface failures.

    This is a focused check for adapter implementations that must not raise
    during normal invocation.  It is separate from the broad protocol check
    so callers can target specific adapters.
    """
    try:
        registry.capabilities.get(kind)
    except LookupError as exc:
        return ConformanceCheckResult(
            check_id=f"adapter-smoke-{kind}",
            passed=False,
            message=f"kind {kind!r} not registered: {exc}",
        )

    try:
        registry.capabilities.check(kind, context={"invocation": dict(invocation)})
    except Exception as exc:
        return ConformanceCheckResult(
            check_id=f"adapter-smoke-{kind}",
            passed=False,
            message=(
                f"smoke invocation for kind {kind!r} raised "
                f"{type(exc).__name__}: {exc}"
            ),
            details={"error": str(exc)},
        )

    return ConformanceCheckResult(check_id=f"adapter-smoke-{kind}", passed=True)


def check_adapter_registry_round_trip(
    registry: ExecutionRegistries,
    kind: str,
) -> ConformanceCheckResult:
    """Verify that a registered adapter survives resolve → invoke → re-resolve.

    This checks for state corruption in the registry: registering an adapter
    and resolving it twice should return the same adapter object.
    """
    try:
        adapter1 = registry.capabilities.get(kind)
        adapter2 = registry.capabilities.get(kind)
    except LookupError as exc:
        return ConformanceCheckResult(
            check_id=f"adapter-round-trip-{kind}",
            passed=False,
            message=f"resolve failed: {exc}",
        )

    if adapter1 is not adapter2:
        return ConformanceCheckResult(
            check_id=f"adapter-round-trip-{kind}",
            passed=False,
            message=(
                f"resolve returned different objects: "
                f"{type(adapter1).__name__} vs {type(adapter2).__name__}"
            ),
        )

    return ConformanceCheckResult(check_id=f"adapter-round-trip-{kind}", passed=True)


__all__ = [
    "ACTIVE_MEGAPLAN_PACKAGE_NAMES",
    "LEGACY_REFERENCE_CATEGORIES",
    "LEGACY_REFERENCE_PATTERNS",
    "check_adapter_protocol_conformance",
    "check_adapter_unknown_kind_fail_closed",
    "check_adapter_smoke_invocation",
    "check_adapter_registry_round_trip",
    "check_contract_result_schema_round_trip",
    "check_contract_result_schema_version_skew",
    "check_contract_result_empty_schema_version_accepted",
    "check_generic_arnold_megaplan_coupling",
    "check_import_coupling",
    "check_legacy_reference_allowlist",
    "check_never_port_artifacts",
    "check_megaplan_artifact_layout",
    "check_package_name_staleness",
    "check_public_workflow_layering",
    "check_security_coverage_matrix",
    "check_semantic_coupling",
    "validate_collection_artifact_placements",
    "validate_canonical_artifact_placements",
    "validate_canonical_root_artifacts",
]
