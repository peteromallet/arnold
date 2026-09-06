"""Immutable execution identity for drift-sensitive Megaplan chains.

The persisted chain cursor is mutable operational state.  This module keeps the
identity accepted before the first milestone separate from later observations,
so loading, resuming, or reconciling a cursor cannot silently adopt edited
chain, anchor, brief, source, or runtime inputs.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Any, Iterator, Mapping, NoReturn
from urllib.parse import unquote, urlparse

import yaml

from arnold_pipelines.megaplan.cloud.runtime_provenance import (
    RUNTIME_PROVENANCE_RECEIPT_SCHEMA,
    runtime_provenance,
)
from arnold_pipelines.megaplan.types import CliError


BINDING_SCHEMA = "arnold.megaplan.chain_execution_binding.v1"
REBIND_SCHEMA = "arnold.megaplan.chain_execution_rebind.v1"
RUNTIME_BINDING_SCHEMA = "arnold.megaplan.chain_runtime_binding.v1"
RUNTIME_REBIND_SCHEMA = "arnold.megaplan.chain_runtime_rebind.v1"
RUNTIME_REBIND_CONTEXT_KEY = "runtime_rebind_context.v1"
HOLD_CONTEXT_ATTESTATION_SCHEMA = "nbf08-chain-control-hold-context-attestation-v1"
DRIFT_ERROR = "chain_execution_binding_drift"
RUNTIME_DRIFT_ERROR = "chain_runtime_binding_drift"
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
_FULL_SHA256 = re.compile(r"^[0-9a-f]{64}$")
# Mirrors ``legacy_marker_runtime_migration._RUNTIME_ROOT``: the live-box
# runtime-candidates layout an identity-less marker's relaunch command must
# name, equal to the verified legacy runtime root.
_LEGACY_RELAUNCH_ROOT = re.compile(r"/workspace/runtime-candidates/[A-Za-z0-9._-]+")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def _git_revision(root: Path | None) -> str:
    return _git(root, "rev-parse", "HEAD") if root is not None else ""


def _git_commit_exists(root: Path, revision: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(root), "cat-file", "-e", f"{revision}^{{commit}}"],
        check=False,
        capture_output=True,
    )
    return result.returncode == 0


def _project_root(spec_path: Path) -> Path:
    resolved = spec_path.resolve(strict=False)
    for parent in resolved.parents:
        if parent.name == ".megaplan":
            return parent.parent
    top = _git(resolved.parent, "rev-parse", "--show-toplevel")
    return Path(top).resolve() if top else resolved.parent


def _raw_spec(spec_path: Path) -> dict[str, Any]:
    raw = yaml.safe_load(spec_path.read_text(encoding="utf-8"))
    return raw if isinstance(raw, dict) else {}


def binding_policy(spec_path: Path) -> dict[str, Any]:
    driver = _raw_spec(spec_path).get("driver")
    driver = driver if isinstance(driver, dict) else {}
    mode = str(driver.get("execution_binding") or "optional").strip().lower()
    if mode not in {"optional", "required"}:
        raise CliError(
            "invalid_spec",
            "driver.execution_binding must be `optional` or `required`",
        )
    binding_assets = driver.get("execution_binding_assets", [])
    if not isinstance(binding_assets, list) or any(
        not isinstance(item, str) or not item.strip() for item in binding_assets
    ):
        raise CliError(
            "invalid_spec",
            "driver.execution_binding_assets must be a list of non-empty paths",
        )
    return {
        "required": mode == "required",
        "mode": mode,
        "intended_initiative_revision": str(
            driver.get("intended_initiative_revision") or ""
        ).strip(),
        "initiative_path": str(driver.get("initiative_path") or "").strip(),
        "execution_binding_assets": [item.strip() for item in binding_assets],
        "require_editable_runtime_match": bool(
            driver.get(
                "require_editable_runtime_match",
                # Cloud chain launches run inside the trusted container and
                # must prove the executing runtime matches the launch pin;
                # local dev keeps the explicit opt-in default.
                os.environ.get("MEGAPLAN_TRUSTED_CONTAINER") == "1",
            )
        ),
    }


def runtime_binding_required(spec_path: Path) -> bool:
    """Return the canonical decision for enforcing editable-runtime identity."""

    policy = binding_policy(spec_path)
    return bool(policy["required"] and policy["require_editable_runtime_match"])


def _resolve_asset(path_value: str, *, spec_path: Path, project_root: Path) -> Path:
    value = Path(path_value).expanduser()
    if value.is_absolute():
        return value.resolve(strict=False)
    project_candidate = (project_root / value).resolve(strict=False)
    if project_candidate.exists():
        return project_candidate
    return (spec_path.parent / value).resolve(strict=False)


def _asset_entry(
    kind: str,
    path_value: str,
    *,
    spec_path: Path,
    project_root: Path,
) -> dict[str, Any]:
    path = _resolve_asset(path_value, spec_path=spec_path, project_root=project_root)
    try:
        path.relative_to(project_root.resolve(strict=False))
    except ValueError as exc:
        raise CliError(
            "invalid_spec",
            f"execution binding asset escapes project root: {path_value}",
        ) from exc
    entry = {
        "kind": kind,
        "declared_path": path_value,
        "resolved_path": str(path),
        "sha256": _sha256_file(path) if path.is_file() else "",
        "exists": path.is_file(),
    }
    if path.is_file() and (
        kind == "north_star"
        or kind.startswith("milestone_brief:")
        or kind.startswith("bound_asset:")
    ):
        from arnold_pipelines.megaplan.planning.source_binding import (
            canonical_source_identity,
        )

        entry["semantic_sha256"] = canonical_source_identity(
            path,
            project_dir=project_root,
        )["semantic_sha256"]
    return entry


def _bundle_assets(
    raw: Mapping[str, Any], *, spec_path: Path, project_root: Path
) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    anchors = raw.get("anchors")
    if isinstance(anchors, Mapping):
        north_star = anchors.get("north_star")
        if isinstance(north_star, str) and north_star.strip():
            assets.append(
                _asset_entry(
                    "north_star",
                    north_star.strip(),
                    spec_path=spec_path,
                    project_root=project_root,
                )
            )
    milestones = raw.get("milestones")
    milestones = milestones if isinstance(milestones, list) else []
    for index, milestone in enumerate(milestones):
        if not isinstance(milestone, Mapping):
            continue
        idea = milestone.get("idea")
        if isinstance(idea, str) and idea.strip():
            assets.append(
                _asset_entry(
                    f"milestone_brief:{index}",
                    idea.strip(),
                    spec_path=spec_path,
                    project_root=project_root,
                )
            )
        milestone_anchors = milestone.get("anchors")
        if isinstance(milestone_anchors, Mapping):
            milestone_north_star = milestone_anchors.get("north_star")
            if isinstance(milestone_north_star, str) and milestone_north_star.strip():
                assets.append(
                    _asset_entry(
                        f"milestone_north_star:{index}",
                        milestone_north_star.strip(),
                        spec_path=spec_path,
                        project_root=project_root,
                    )
                )
    driver = raw.get("driver")
    driver = driver if isinstance(driver, Mapping) else {}
    bound_assets = driver.get("execution_binding_assets", [])
    if isinstance(bound_assets, list):
        for index, path_value in enumerate(bound_assets):
            if isinstance(path_value, str) and path_value.strip():
                assets.append(
                    _asset_entry(
                        f"bound_asset:{index}",
                        path_value.strip(),
                        spec_path=spec_path,
                        project_root=project_root,
                    )
                )
    return assets


def _revision_blob(root: Path, revision: str, relative_path: str) -> bytes | None:
    result = subprocess.run(
        ["git", "-C", str(root), "show", f"{revision}:{relative_path}"],
        check=False,
        capture_output=True,
    )
    return result.stdout if result.returncode == 0 else None


def _revision_comparable_spec_sha(value: bytes) -> str:
    """Hash authored spec semantics without the self-referential revision pin."""

    raw = yaml.safe_load(value.decode("utf-8"))
    if not isinstance(raw, dict):
        return ""
    driver = raw.get("driver")
    if isinstance(driver, dict) and "intended_initiative_revision" in driver:
        driver = dict(driver)
        driver["intended_initiative_revision"] = "<CONTENT_ADDRESSED_REVISION_PIN>"
        raw = dict(raw)
        raw["driver"] = driver
    return _sha256_bytes(
        json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _revision_verification(
    *,
    policy: Mapping[str, Any],
    raw: Mapping[str, Any],
    spec_path: Path,
    project_root: Path,
    assets: list[dict[str, Any]],
) -> dict[str, Any]:
    revision = str(policy.get("intended_initiative_revision") or "")
    initiative_path = str(policy.get("initiative_path") or "").strip("/")
    errors: list[str] = []
    if not _FULL_SHA.fullmatch(revision):
        errors.append("intended_initiative_revision_unpinned")
    elif not _git_commit_exists(project_root, revision):
        errors.append("intended_initiative_revision_missing")
    if not initiative_path:
        errors.append("initiative_path_missing")

    checks: list[dict[str, Any]] = []
    if not errors:
        spec_blob = _revision_blob(
            project_root, revision, f"{initiative_path}/chain.yaml"
        )
        active_hash = _revision_comparable_spec_sha(spec_path.read_bytes())
        expected_hash = (
            _revision_comparable_spec_sha(spec_blob) if spec_blob is not None else ""
        )
        checks.append(
            {
                "kind": "chain_spec",
                "revision_path": f"{initiative_path}/chain.yaml",
                "expected_sha256": expected_hash,
                "active_sha256": active_hash,
                "matches": bool(expected_hash) and expected_hash == active_hash,
            }
        )
        if not checks[-1]["matches"]:
            errors.append("chain_spec_not_at_intended_revision")

        for asset in assets:
            declared = str(asset.get("declared_path") or "")
            if declared.startswith(".megaplan/") or str(asset.get("kind")).startswith(
                "bound_asset:"
            ):
                revision_path = declared
            elif str(asset.get("kind")) == "north_star":
                revision_path = f"{initiative_path}/{declared}"
            else:
                revision_path = f"{initiative_path}/{declared}"
            blob = _revision_blob(project_root, revision, revision_path)
            expected = _sha256_bytes(blob) if blob is not None else ""
            active = str(asset.get("sha256") or "")
            check = {
                "kind": asset.get("kind"),
                "revision_path": revision_path,
                "expected_sha256": expected,
                "active_sha256": active,
                "matches": bool(expected) and expected == active,
            }
            checks.append(check)
            if not check["matches"]:
                errors.append(f"asset_not_at_intended_revision:{asset.get('kind')}")

    return {
        "ok": not errors,
        "revision": revision,
        "initiative_path": initiative_path,
        "checks": checks,
        "errors": errors,
    }


def active_execution_identity(spec_path: Path) -> dict[str, Any]:
    spec_path = spec_path.resolve(strict=False)
    raw = _raw_spec(spec_path)
    policy = binding_policy(spec_path)
    project_root = _project_root(spec_path)
    milestones_raw = raw.get("milestones")
    milestones_raw = milestones_raw if isinstance(milestones_raw, list) else []
    milestone_sequence = [
        {
            "index": index,
            "label": str(item.get("label") or "") if isinstance(item, Mapping) else "",
            "idea": str(item.get("idea") or "") if isinstance(item, Mapping) else "",
        }
        for index, item in enumerate(milestones_raw)
    ]
    assets = _bundle_assets(raw, spec_path=spec_path, project_root=project_root)
    bundle_core = {
        "chain_spec_sha256": _sha256_file(spec_path),
        "milestone_sequence": milestone_sequence,
        "assets": assets,
        "intended_initiative_revision": policy["intended_initiative_revision"],
        "initiative_path": policy["initiative_path"],
    }
    bundle_sha256 = _sha256_bytes(
        json.dumps(bundle_core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    runtime = runtime_provenance()
    editable_root_text = str(runtime.get("editable_root") or "")
    editable_root = Path(editable_root_text) if editable_root_text else None
    runtime_identity = {
        "import_root": str(runtime.get("import_root") or ""),
        "source_revision": str(runtime.get("source_revision") or ""),
        "editable_root": editable_root_text,
        "editable_revision": _git_revision(editable_root),
        "direct_url": runtime.get("direct_url") or {},
        "pth": runtime.get("pth") or [],
        "imports": runtime.get("imports") or {},
    }
    runtime_identity["content_sha256"] = _runtime_identity_sha256(runtime_identity)
    revision_verification = _revision_verification(
        policy=policy,
        raw=raw,
        spec_path=spec_path,
        project_root=project_root,
        assets=assets,
    )
    errors = list(revision_verification["errors"])
    if any(not bool(asset.get("exists")) for asset in assets):
        errors.append("bundle_asset_missing")
    if not runtime_identity["source_revision"]:
        errors.append("runtime_revision_missing")
    if policy["require_editable_runtime_match"]:
        errors.extend(
            f"runtime_provenance:{error}" for error in runtime.get("errors") or []
        )
        # T-0301 generation: the executing runtime is a worktree-first
        # PYTHONPATH root with a shared immutable dependency generation, NOT
        # a pip editable install. When provenance is clean (imports resolve
        # to the expected root at the pinned revision), the runtime IS the
        # worktree and the legacy editable_* checks do not apply. The
        # editable requirements only bind when an editable install actually
        # exists (legacy pre-T-0301 runtime).
        if not editable_root_text:
            if runtime.get("errors"):
                errors.append("editable_runtime_missing")
        elif Path(runtime_identity["import_root"]).resolve(
            strict=False
        ) != editable_root.resolve(strict=False):
            errors.append("editable_runtime_import_root_mismatch")
        elif (
            runtime_identity["editable_revision"] != runtime_identity["source_revision"]
        ):
            errors.append("editable_runtime_revision_mismatch")
    return {
        "schema": BINDING_SCHEMA,
        "spec_path": str(spec_path),
        **bundle_core,
        "bundle_sha256": bundle_sha256,
        "runtime": runtime_identity,
        "revision_verification": revision_verification,
        "ready": not errors,
        "errors": errors,
    }


def _runtime_identity_core(identity: Mapping[str, Any]) -> dict[str, Any]:
    core = {
        key: identity.get(key)
        for key in (
            "import_root",
            "source_revision",
            "editable_root",
            "editable_revision",
            "direct_url",
            "pth",
            "imports",
        )
    }
    # T-0301 canonicalization (grok consult, occurrence d58701026410):
    # content_sha256 must be ENV-INDEPENDENT. editable_root / editable_revision
    # / direct_url / pth / imports all derive from the probing interpreter's
    # view (importlib.metadata dist-info, resolved module paths) and drift
    # between the generation-interpreter launch recipe and a leftover
    # candidate .venv. An identity pin that changes with the probing
    # interpreter is not an identity. The launch-relevant identity is
    # import_root + source_revision — the only fields determined by the tree
    # itself, not by which interpreter probed it.
    for key in ("editable_root", "editable_revision", "direct_url", "pth", "imports"):
        core[key] = None
    return core


def _runtime_identity_sha256(identity: Mapping[str, Any]) -> str:
    return _sha256_bytes(
        json.dumps(
            _runtime_identity_core(identity),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def _normalized_runtime_identity(identity: Mapping[str, Any]) -> dict[str, Any]:
    # Persist the complete provenance observation for audit/rebind callers.
    # The digest still projects environment-derived fields away through
    # ``_runtime_identity_sha256``; dropping them here made a valid canary
    # lose its editable-install/import-origin proof at the state boundary.
    value = {
        key: identity.get(key)
        for key in (
            "import_root",
            "source_revision",
            "editable_root",
            "editable_revision",
            "direct_url",
            "pth",
            "imports",
        )
    }
    value["content_sha256"] = _runtime_identity_sha256(value)
    return value


def _persisted_runtime_identity_sha256(identity: Mapping[str, Any]) -> str:
    """Verify and return the digest stored by the authoritative state writer.

    Older runtime identities included the independently verified Shannon
    dependency receipt in their content-addressed payload.  Current semantic
    comparison intentionally projects that field away, but a rebind's
    ``from`` guard must still CAS the exact identity that is byte-persisted in
    chain state.  Only that one known legacy extension is accepted.
    """

    allowed = set(_runtime_identity_core(identity)) | {
        "content_sha256",
        "shannon_dependencies",
    }
    unexpected = sorted(set(identity) - allowed)
    if unexpected:
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "runtime rebind refused: persisted runtime identity has unsupported "
            "fields: " + ", ".join(unexpected),
        )
    supplied = str(identity.get("content_sha256") or "")
    # The stored digest is the CANONICAL one (env-independent core with
    # editable diagnostics excluded — see _runtime_identity_core). Verifying
    # against a raw full-payload hash would reject every canonical identity
    # as "invalid"; recompute with the same canonical builder.
    observed = _runtime_identity_sha256(identity)
    if not _FULL_SHA256.fullmatch(supplied):
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "runtime rebind refused: persisted runtime identity digest is invalid",
        )
    if supplied == observed:
        return supplied
    # Canonical-identity migration bridge (grok consult, d58701026410):
    # markers written BEFORE the env-independent digest landed carry a digest
    # computed over the legacy 7-field payload (editable diagnostics
    # included). Accept that legacy hash so a pre-canonical marker can rebind
    # to the canonical digest; the rebind rewrites the marker canonically.
    payload = {
        key: value for key, value in identity.items() if key != "content_sha256"
    }
    legacy = _sha256_bytes(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    if supplied != legacy:
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "runtime rebind refused: persisted runtime identity digest is invalid",
        )
    return supplied


def _json_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            f"runtime rebind refused: {label} is unreadable or invalid JSON",
        ) from exc
    if not isinstance(value, dict):
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            f"runtime rebind refused: {label} must be a JSON object",
        )
    return value


def _receipt_core(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: receipt.get(key)
        for key in ("schema", "interpreter", "provenance", "runtime_identity")
    }


def _strict_external_runtime_shape(
    identity: Mapping[str, Any],
    provenance: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    import_root_text = str(identity.get("import_root") or "")
    editable_root_text = str(identity.get("editable_root") or "")
    source_revision = str(identity.get("source_revision") or "")
    editable_revision = str(identity.get("editable_revision") or "")
    if not import_root_text:
        errors.append("import_root_missing")
        return errors
    import_root = Path(import_root_text).resolve(strict=False)
    editable_root = Path(editable_root_text).resolve(strict=False)
    if not _FULL_SHA.fullmatch(source_revision):
        errors.append("source_revision_invalid")
    # T-0301 worktree-first: empty editable_root is launch-ready, not a
    # mismatch (the legacy editable checks bind only when an editable install
    # actually exists).
    if editable_root_text and import_root != editable_root:
        errors.append("editable_root_mismatch")
    if editable_root_text and editable_revision != source_revision:
        errors.append("editable_revision_mismatch")
    if str(provenance.get("expected_root") or "") != str(import_root):
        errors.append("receipt_expected_root_mismatch")
    if str(provenance.get("expected_revision") or "") != source_revision:
        errors.append("receipt_expected_revision_mismatch")
    if str(provenance.get("source_revision") or "") != source_revision:
        errors.append("receipt_source_revision_mismatch")
    if not bool(provenance.get("ok")) or provenance.get("errors"):
        errors.append("receipt_provenance_not_ready")

    direct_url = identity.get("direct_url")
    direct_url = direct_url if isinstance(direct_url, Mapping) else {}
    dir_info = direct_url.get("dir_info")
    dir_info = dir_info if isinstance(dir_info, Mapping) else {}
    parsed = urlparse(str(direct_url.get("url") or ""))
    direct_root = (
        Path(unquote(parsed.path)).resolve(strict=False)
        if parsed.scheme == "file"
        else None
    )
    # T-0301 worktree-first runtime (grok consult, d58701026410): when no pip
    # editable install exists (editable_root empty, no pth, no direct_url),
    # the editable requirements do not apply — import_root + source_revision
    # + provenance.ok are the authoritative launch gate. The legacy editable
    # shape (direct_url.editable, pth entries, editable_root == import_root)
    # is pre-T-0301 only.
    pth = identity.get("pth")
    pth = pth if isinstance(pth, list) else []
    worktree_first = not editable_root_text and not pth
    if not worktree_first:
        if not bool(dir_info.get("editable")) or direct_root != import_root:
            errors.append("editable_direct_url_mismatch")
        pth_entries: list[Path] = []
        if not pth:
            errors.append("editable_pth_missing")
        for record in pth:
            if not isinstance(record, Mapping) or not bool(record.get("readable")):
                errors.append("editable_pth_unreadable")
                continue
            entries = record.get("entries")
            if not isinstance(entries, list):
                errors.append("editable_pth_invalid")
                continue
            pth_entries.extend(
                Path(str(entry)).resolve(strict=False)
                for entry in entries
                if isinstance(entry, str) and entry
            )
        if not pth_entries:
            errors.append("editable_pth_entries_missing")
        elif any(entry != import_root for entry in pth_entries):
            errors.append("editable_pth_mismatch")

    # The normalized identity nulls imports (canonical core); use the
    # provenance's populated imports for the set/root check.
    imports = provenance.get("imports")
    imports = imports if isinstance(imports, Mapping) else {}
    if set(imports) != {"arnold", "arnold_pipelines", "megaplan"}:
        errors.append("runtime_import_set_mismatch")
    elif any(
        not Path(str(value)).resolve(strict=False).is_relative_to(import_root)
        for value in imports.values()
    ):
        errors.append("runtime_import_root_mismatch")
    return errors


def verify_external_runtime_identity(
    identity_path: Path,
    receipt_path: Path,
) -> dict[str, Any]:
    """Verify an offline runtime using a fresh observation by its interpreter."""

    identity = _json_object(identity_path, label="runtime identity")
    receipt = _json_object(receipt_path, label="runtime provenance receipt")
    if receipt.get("schema") != RUNTIME_PROVENANCE_RECEIPT_SCHEMA:
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "runtime rebind refused: runtime provenance receipt schema is invalid",
        )
    receipt_digest = str(receipt.get("content_sha256") or "")
    if (
        not _FULL_SHA256.fullmatch(receipt_digest)
        or _sha256_bytes(
            json.dumps(
                _receipt_core(receipt),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        != receipt_digest
    ):
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "runtime rebind refused: runtime provenance receipt digest is invalid",
        )

    normalized = _normalized_runtime_identity(identity)
    supplied_identity_digest = str(identity.get("content_sha256") or "")
    receipt_identity = receipt.get("runtime_identity")
    receipt_identity = (
        receipt_identity if isinstance(receipt_identity, Mapping) else {}
    )
    # Compare launch-relevant identity (grok consult, d58701026410): digest +
    # import_root + source_revision. The receipt's runtime_identity (built by
    # runtime_provenance.normalized_runtime_identity) carries the full
    # diagnostic shape (direct_url/editable_root/pth/imports populated) while
    # _normalized_runtime_identity nulls them — same digest, different shapes,
    # and a full-dict compare false-positives 'identity disagrees with its
    # receipt' on every offline verification.
    if (
        supplied_identity_digest != normalized["content_sha256"]
        or str(receipt_identity.get("import_root") or "").rstrip("/")
        != str(normalized.get("import_root") or "").rstrip("/")
        or str(receipt_identity.get("source_revision") or "")
        != str(normalized.get("source_revision") or "")
    ):
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "runtime rebind refused: runtime identity disagrees with its receipt",
        )

    interpreter = receipt.get("interpreter")
    interpreter = interpreter if isinstance(interpreter, Mapping) else {}
    executable_text = str(interpreter.get("executable") or "")
    executable = Path(executable_text).resolve(strict=False)
    control_executable = Path(sys.executable).resolve(strict=False)
    if (
        not executable.is_absolute()
        or not executable.is_file()
        or not os.access(executable, os.X_OK)
    ):
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "runtime rebind refused: receipt interpreter is unavailable",
        )
    if executable == control_executable:
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "runtime rebind refused: offline runtime interpreter is not independent "
            "from the control runtime",
        )
    if _sha256_file(executable) != str(interpreter.get("sha256") or ""):
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "runtime rebind refused: receipt interpreter changed",
        )

    provenance = receipt.get("provenance")
    provenance = provenance if isinstance(provenance, Mapping) else {}
    shape_errors = _strict_external_runtime_shape(normalized, provenance)
    if shape_errors:
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "runtime rebind refused: external runtime receipt is not launch-ready: "
            + ", ".join(sorted(set(shape_errors))),
        )

    provenance_program = Path(
        sys.modules[runtime_provenance.__module__].__file__ or ""
    ).resolve(strict=True)
    rerun = subprocess.run(
        [
            str(executable),
            "-P",
            str(provenance_program),
            "--expected-root",
            str(normalized["import_root"]),
            "--expected-revision",
            str(normalized["source_revision"]),
            "--emit-receipt",
        ],
        check=False,
        capture_output=True,
        text=True,
        env={
            key: value
            for key, value in os.environ.items()
            if key != "PYTHONPATH"
        }
        | {"PYTHONPATH": str(normalized["import_root"])},
    )
    try:
        observed = json.loads(rerun.stdout)
    except json.JSONDecodeError as exc:
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "runtime rebind refused: external interpreter did not emit a valid "
            "runtime provenance receipt",
        ) from exc
    if (
        rerun.returncode != 0
        or not isinstance(observed, dict)
        or observed.get("content_sha256") != receipt_digest
        or observed != receipt
    ):
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "runtime rebind refused: runtime provenance receipt is stale or forged",
        )
    return normalized


def _state_has_progress(state: Any) -> bool:
    return bool(
        getattr(state, "current_milestone_index", -1) >= 0
        or getattr(state, "current_plan_name", None)
        or getattr(state, "completed", None)
        or getattr(state, "last_state", None)
    )


def _comparable_assets(identity: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            key: item.get(key)
            for key in ("kind", "declared_path", "resolved_path", "sha256", "exists")
        }
        for item in identity.get("assets") or []
        if isinstance(item, Mapping)
    ]


def _comparable(identity: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "chain_spec_sha256": identity.get("chain_spec_sha256"),
        "milestone_sequence": identity.get("milestone_sequence"),
        "assets": _comparable_assets(identity),
        "intended_initiative_revision": identity.get("intended_initiative_revision"),
        "initiative_path": identity.get("initiative_path"),
    }


def _looks_like_legacy_runtime_binding(identity: Mapping[str, Any]) -> bool:
    """True for a pre-canonical runtime-only chain binding.

    Chains bound before the canonical chain-binding fields landed carry a
    runtime-only ``current_identity`` (source_revision / content_sha256 /
    import_root / pth / editable_*) with NONE of the chain-binding fields
    (chain_spec_sha256, milestone_sequence, assets, initiative_path).
    """
    return not (
        identity.get("chain_spec_sha256")
        or identity.get("milestone_sequence")
        or identity.get("initiative_path")
        or identity.get("assets")
    )


def _future_source_reconciliation_is_safe(
    *,
    state: Any,
    expected: Mapping[str, Any],
    active: Mapping[str, Any],
    drift_fields: list[str],
) -> tuple[bool, list[str]]:
    # Legacy runtime-only binding bridge: chains bound before the canonical
    # chain-binding fields landed carry a runtime-only current_identity
    # (source_revision / content_sha256 / import_root / pth / editable_* —
    # no chain_spec_sha256, milestone_sequence, assets, initiative_path).
    # Against the full active identity every comparable field drifts, which
    # is not a spec edit hazard — it is the BINDING UPGRADE itself, the
    # purpose of a runtime-rebind. Treat the legacy -> canonical migration
    # as always safe so a pre-canonical chain can rebind to the current
    # engine instead of being refused forever.
    if _looks_like_legacy_runtime_binding(expected):
        return True, []
    allowed_fields = {
        "bundle_sha256",
        "chain_spec_sha256",
        "assets",
        "intended_initiative_revision",
    }
    if not set(drift_fields).issubset(allowed_fields):
        return False, []
    if expected.get("milestone_sequence") != active.get("milestone_sequence"):
        return False, []
    if expected.get("initiative_path") != active.get("initiative_path"):
        return False, []
    expected_assets = {
        str(item.get("kind")): item
        for item in _comparable_assets(expected)
        if isinstance(item, Mapping)
    }
    active_assets = {
        str(item.get("kind")): item
        for item in _comparable_assets(active)
        if isinstance(item, Mapping)
    }
    changed_kinds = sorted(
        kind
        for kind in set(expected_assets) | set(active_assets)
        if expected_assets.get(kind) != active_assets.get(kind)
    )
    if not changed_kinds:
        # A pure chain-spec CONTENT edit (e.g. profile switch) changes the
        # full-file chain_spec_sha256 but may leave every comparable ASSET
        # kind unchanged (milestone briefs, north star, bound assets all
        # derive from the milestone structure, not the profile pins). With
        # milestone_sequence + initiative_path already verified equal and the
        # only drift being the safe chain_spec_sha256 field, this is the
        # same intentional spec edit — safe for reconciliation. (mega m4,
        # occurrence 35afd4e47587: changed_asset_kinds=[] drift.)
        if set(drift_fields) <= {
            "chain_spec_sha256",
            "bundle_sha256",
            "intended_initiative_revision",
        } and "chain_spec_sha256" in drift_fields:
            return True, []
        return False, []
    cutoff = int(getattr(state, "current_milestone_index", -1))
    if not getattr(state, "current_plan_name", None):
        cutoff -= 1
    for kind in changed_kinds:
        # The chain-spec asset reflects the chain.yaml content hash. When the
        # ONLY substantive drift is chain_spec_sha256 (an intentional, safe
        # spec edit such as a profile switch — milestone_sequence and
        # initiative_path already verified above), the derived chain_spec
        # asset changing is the SAME edit, not a separate hazard. Treat it as
        # safe for reconciliation so an ordinary chain.yaml edit can advance
        # instead of hard-blocking every rebind/resume with
        # chain_spec_not_at_intended_revision.
        if kind == "chain_spec" and "chain_spec_sha256" in drift_fields:
            continue
        if not kind.startswith("milestone_brief:"):
            return False, changed_kinds
        try:
            index = int(kind.split(":", 1)[1])
        except ValueError:
            return False, changed_kinds
        if index <= cutoff:
            return False, changed_kinds
    revision = active.get("revision_verification")
    if not isinstance(revision, Mapping) or not revision.get("ok"):
        requirements = (getattr(state, "metadata", {}) or {}).get(
            "required_canonical_source_updates"
        )
        if not isinstance(requirements, Mapping):
            return False, changed_kinds
    return True, changed_kinds


def _reconciled_requirements_cover_revision_errors(
    state: Any,
    active: Mapping[str, Any],
) -> bool:
    errors = list(active.get("errors") or [])
    if not errors:
        return True
    requirements = (getattr(state, "metadata", {}) or {}).get(
        "required_canonical_source_updates"
    )
    if not isinstance(requirements, Mapping):
        return False
    active_assets = {
        str(item.get("kind")): item
        for item in active.get("assets") or []
        if isinstance(item, Mapping)
    }
    covered: set[str] = set()
    for requirement in requirements.values():
        if (
            not isinstance(requirement, Mapping)
            or requirement.get("status") != "reconciled"
        ):
            continue
        index = requirement.get("milestone_index")
        expected = requirement.get("expected")
        if not isinstance(index, int) or not isinstance(expected, Mapping):
            continue
        kind = f"milestone_brief:{index}"
        active_asset = active_assets.get(kind) or {}
        if active_asset.get("semantic_sha256") == expected.get("semantic_sha256"):
            covered.add(f"asset_not_at_intended_revision:{kind}")
    return bool(errors) and set(errors).issubset(covered)


def _bound_import_root_covers_editable_metadata_mismatch(
    expected: Mapping[str, Any],
    active: Mapping[str, Any],
) -> bool:
    """Accept unrelated global editable metadata only for the bound import root.

    A shared supervisor interpreter can expose ``direct_url.json`` for another
    editable Arnold checkout even though this process was launched with the
    immutable chain runtime first on ``PYTHONPATH``.  Once a chain is bound, the
    imported source root is the execution fact that must remain invariant.  Do
    not make a later, process-global package metadata observation stronger than
    that bound fact; equally, do not accept a different import root or any
    additional launch-readiness error.
    """

    if set(active.get("errors") or []) != {"editable_runtime_import_root_mismatch"}:
        return False
    expected_runtime = expected.get("runtime")
    active_runtime = active.get("runtime")
    if not isinstance(expected_runtime, Mapping) or not isinstance(
        active_runtime, Mapping
    ):
        return False
    expected_import = str(expected_runtime.get("import_root") or "").strip()
    expected_editable = str(expected_runtime.get("editable_root") or "").strip()
    active_import = str(active_runtime.get("import_root") or "").strip()
    active_editable = str(active_runtime.get("editable_root") or "").strip()
    if not expected_import or not active_import:
        return False
    # T-0301 worktree-first: BOTH identities with empty editable_root (no
    # editable install at all) and the same import root are the pure
    # worktree-first shape - the editable_import_root_mismatch error is a
    # stale diagnostic from a leftover candidate .venv, not a real mismatch.
    if not expected_editable and not active_editable:
        return (
            Path(expected_import).resolve(strict=False)
            == Path(active_import).resolve(strict=False)
        )
    # Expected worktree-first (empty editable) but active carries the
    # leftover candidate .venv's editable self-install pointing at the SAME
    # import root: the active editable metadata is the candidate venv's own
    # direct_url, not a different runtime - the bound import root is still
    # the execution fact. Accept when the active editable root equals the
    # active import root and the expected import matches.
    if not expected_editable and active_editable:
        return (
            Path(active_editable).resolve(strict=False)
            == Path(active_import).resolve(strict=False)
            and Path(expected_import).resolve(strict=False)
            == Path(active_import).resolve(strict=False)
        )
    if not expected_editable or not active_import:
        return False
    return (
        Path(expected_import).resolve(strict=False)
        == Path(expected_editable).resolve(strict=False)
        == Path(active_import).resolve(strict=False)
    )


def execution_binding_report(
    spec_path: Path,
    state: Any,
    *,
    active_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    policy = binding_policy(spec_path)
    binding = getattr(state, "metadata", {}).get("execution_binding")
    binding = binding if isinstance(binding, Mapping) else {}
    expected = binding.get("launched_identity")
    expected = expected if isinstance(expected, Mapping) else None
    if not policy["required"] and expected is None:
        return {
            "schema": BINDING_SCHEMA,
            "required": False,
            "status": "not_required",
            "drift_fields": [],
            "expected": None,
            "active": None,
        }
    active = (
        dict(active_identity)
        if isinstance(active_identity, Mapping)
        else active_execution_identity(spec_path)
    )
    if expected is None:
        status = "missing" if policy["required"] else "not_required"
        drift_fields: list[str] = []
    else:
        expected_comparable = _comparable(expected)
        active_comparable = _comparable(active)
        drift_fields = [
            key
            for key in expected_comparable
            if expected_comparable.get(key) != active_comparable.get(key)
        ]
        safe_future, changed_asset_kinds = _future_source_reconciliation_is_safe(
            state=state,
            expected=expected,
            active=active,
            drift_fields=drift_fields,
        )
        bound_import_root_match = _bound_import_root_covers_editable_metadata_mismatch(
            expected,
            active,
        )
        active_ready = (
            bool(active.get("ready"))
            or _reconciled_requirements_cover_revision_errors(state, active)
            or bound_import_root_match
        )
        if safe_future:
            status = "reconcile_required"
        elif not drift_fields and active_ready:
            status = "match"
        elif active_ready:
            # The drift fields are fully covered by operator-recorded
            # reconciliation (required_canonical_source_updates with
            # status=reconciled matching the active asset): the binding
            # errors are acknowledged, so the identity is ready and the
            # drift is reconcilable — not a hard refusal. (astrid m4:
            # milestone_brief:3 amended via replan; RCSU covers the error
            # but drift_fields=['assets'] alone forced status=drift and
            # refused the load.)
            status = "reconcile_required"
        else:
            status = "drift"
    result = {
        "schema": BINDING_SCHEMA,
        "required": policy["required"],
        "status": status,
        "drift_fields": drift_fields,
        "bound_import_root_match": bound_import_root_match
        if expected is not None
        else False,
        "changed_asset_kinds": changed_asset_kinds if expected is not None else [],
        "expected": dict(expected) if expected is not None else None,
        "active": active,
    }
    result["runtime_binding"] = runtime_binding_report(
        spec_path,
        state,
        active_identity=active,
    )
    return result


def _runtime_errors_covered(state: Any, active_execution: Mapping[str, Any]) -> bool:
    """True when every active-execution error is a spec-asset revision error
    covered by an operator-recorded reconciliation.

    active_execution_identity folds SPEC asset errors (e.g.
    asset_not_at_intended_revision:milestone_brief:3) into the same
    ``errors`` list the runtime binding reads for ``ready``. Those are
    reconciled at the SPEC level via required_canonical_source_updates;
    the RUNTIME binding must not refuse the chain for them (astrid m4:
    brief amendment 710ed4a4 -> replan -> RCSU reconciled, but the runtime
    check saw the propagated asset error and refused with
    chain_runtime_binding_drift even though expected==active digest).
    """
    errors = list(active_execution.get("errors") or [])
    if not errors:
        return True
    requirements = (getattr(state, "metadata", {}) or {}).get(
        "required_canonical_source_updates"
    )
    if not isinstance(requirements, Mapping):
        return False
    covered: set[str] = set()
    for requirement in requirements.values():
        if (
            not isinstance(requirement, Mapping)
            or requirement.get("status") != "reconciled"
        ):
            continue
        index = requirement.get("milestone_index")
        if isinstance(index, int):
            covered.add(f"asset_not_at_intended_revision:milestone_brief:{index}")
    return bool(errors) and set(errors).issubset(covered)


def runtime_binding_report(
    spec_path: Path,
    state: Any,
    *,
    active_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compare the mutable runtime tip without changing the spec/asset binding."""

    required = runtime_binding_required(spec_path)
    binding = getattr(state, "metadata", {}).get("execution_binding")
    binding = binding if isinstance(binding, Mapping) else {}
    runtime_binding = binding.get("runtime_binding")
    runtime_binding = runtime_binding if isinstance(runtime_binding, Mapping) else {}
    expected = runtime_binding.get("current_identity")
    # An absent or exactly empty current_identity is "missing", not a
    # content-addressed identity with a synthetic digest that would look like
    # drift. The bootstrap at chain start writes the seed identity into this
    # slot once; everything else fails closed.
    if isinstance(expected, Mapping) and not expected:
        expected = None
    legacy = False
    if not isinstance(expected, Mapping):
        launched = binding.get("launched_identity")
        launched = launched if isinstance(launched, Mapping) else {}
        expected = launched.get("runtime")
        legacy = isinstance(expected, Mapping)
    active_execution = (
        active_identity
        if isinstance(active_identity, Mapping)
        else active_execution_identity(spec_path)
    )
    active_runtime = active_execution.get("runtime")
    active_runtime = active_runtime if isinstance(active_runtime, Mapping) else {}
    active = _normalized_runtime_identity(active_runtime) if active_runtime else None
    normalized_expected = (
        _normalized_runtime_identity(expected)
        if isinstance(expected, Mapping)
        else None
    )
    if not required:
        status = "not_required"
    elif normalized_expected is None:
        status = "missing"
    elif active is None:
        status = "drift"
    elif normalized_expected["content_sha256"] != active["content_sha256"]:
        status = "drift"
    elif not bool(active_execution.get("ready")) and not _runtime_errors_covered(
        state, active_execution
    ):
        status = "invalid"
    else:
        status = "match"
    return {
        "schema": RUNTIME_BINDING_SCHEMA,
        "required": required,
        "status": status,
        "legacy_expected": legacy,
        "expected": normalized_expected,
        "active": active,
        "active_errors": list(active_execution.get("errors") or []),
    }


def _state_blocked_no_live_work(state: Any) -> bool:
    """True when the chain's current plan is blocked with no live worker.

    A blocked plan (chain last_state=blocked, no active step/worker) has
    nothing mid-flight, so adopting the current manifest head on resume is
    safe — the engine advance is a non-event, exactly like the immutable-seed
    per-dispatch refresh. Mid-execution swaps (active worker/step) remain
    refused. The chain state records ``last_state``; the plan state records
    ``current_state``/``active_step`` — either may be present depending on the
    caller, so accept the blocked shape from whichever is available.
    """
    if getattr(state, "current_state", None) is not None:
        if getattr(state, "current_state") != "blocked":
            return False
    elif getattr(state, "last_state", None) != "blocked":
        return False
    if getattr(state, "active_step", None):
        return False
    if getattr(state, "active_worker", None):
        return False
    return True


def assert_execution_binding(
    spec_path: Path,
    state: Any,
    *,
    operation: str,
    allow_unbound_new: bool = True,
) -> dict[str, Any]:
    report = execution_binding_report(spec_path, state)
    if not report["required"]:
        return report
    if (
        report["status"] == "missing"
        and allow_unbound_new
        and not _state_has_progress(state)
    ):
        return report
    if report["status"] not in {"match", "reconcile_required"}:
        # A blocked plan with no live worker may auto-adopt the current
        # manifest head: nothing is executing, so the engine advance is a
        # non-event (seed-refresh philosophy). The strict refusal protects
        # mid-execution swaps only.
        if _state_blocked_no_live_work(state):
            report = dict(report)
            report["status"] = "reconcile_required"
            report["auto_adopted_blocked"] = True
        else:
            active = report["active"]
            raise CliError(
                DRIFT_ERROR,
                f"{operation} refused: immutable chain execution binding is "
                f"{report['status']}; drift_fields={report['drift_fields']}; "
                f"active_errors={active.get('errors')}. Explicit operator-authorized "
                "content-addressed rebind is required.",
            )
    runtime_report = report["runtime_binding"]
    if (
        runtime_report["required"]
        and runtime_report["status"] != "match"
        # A blocked plan with no live worker auto-adopts runtime drift the
        # same way it adopts spec drift: nothing is mid-flight. This must
        # hold even when the SPEC check already reconciled (reconcile_required
        # from a safe spec edit) — the runtime identity still lags the
        # manifest head and the blocked plan must not be refused for it.
        # (mega m4: spec drift -> reconcile_required skipped the auto-adopt
        # branch, leaving auto_adopted_blocked unset, so the runtime carve-out
        # failed with chain_runtime_binding_drift on a blocked plan.)
        and not _state_blocked_no_live_work(state)
    ):
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            f"{operation} refused: runtime binding is "
            f"{runtime_report['status']}; expected="
            f"{str((runtime_report.get('expected') or {}).get('content_sha256') or '')[:12]}; "
            f"active={str((runtime_report.get('active') or {}).get('content_sha256') or '')[:12]}; "
            f"active_errors={runtime_report.get('active_errors')}. Explicit "
            "operator-authorized content-addressed runtime rebind is required.",
        )
    return report


def _bootstrap_runtime_identity_from_seed(
    spec_path: Path,
    state: Any,
) -> bool:
    """Populate an empty ``current_identity`` from the launch seed.

    A progressed chain with a valid immutable launch binding but an absent
    or exactly empty ``current_identity`` (e.g. after a state-format upgrade)
    reads the configured launch seed, validates it, and writes the normalized
    identity into the runtime binding.  This is a one-time initialization, not
    a runtime rebind: it preserves the existing ``launched_identity``,
    ``bound_at``, schemas, and ``rebind_events``.

    Returns ``True`` when the identity was bootstrapped, ``False`` when
    ``current_identity`` was already populated or the seed is absent (no-op).
    Raises ``CliError`` on validation failure.
    """
    binding = getattr(state, "metadata", {}).get("execution_binding")
    binding = binding if isinstance(binding, Mapping) else {}
    runtime_binding = binding.get("runtime_binding")
    runtime_binding = runtime_binding if isinstance(runtime_binding, Mapping) else {}
    current = runtime_binding.get("current_identity")
    # Already populated — nothing to bootstrap.
    if isinstance(current, Mapping) and current:
        return False
    # No launch binding at all — can't bootstrap.
    if not binding.get("launched_identity"):
        return False
    from arnold_pipelines.megaplan.cloud.runtime_attestation import (
        readonly_seed_runtime_identity as _get_seed_identity,
    )

    seed_identity = _get_seed_identity(spec_path)
    if seed_identity is None:
        return False
    normalized = _normalized_runtime_identity(seed_identity)
    metadata = dict(getattr(state, "metadata", {}) or {})
    exec_binding = dict(metadata.get("execution_binding", {}))
    rt_binding = dict(exec_binding.get("runtime_binding", {}))
    rt_binding["current_identity"] = normalized
    exec_binding["runtime_binding"] = rt_binding
    metadata["execution_binding"] = exec_binding
    state.metadata = metadata
    return True


def bind_execution_identity(spec_path: Path, state: Any) -> dict[str, Any]:
    policy = binding_policy(spec_path)
    report = execution_binding_report(spec_path, state)
    # Grok consult (astrid-first 20260814): a per-epic runtime manifest in
    # play (cloud launch / ARNOLD_RUNTIME_MANIFEST / trusted container) means
    # the launch seed REQUIRES a chain binding even when the spec omits
    # driver.execution_binding (defaults optional). Without this stamp the
    # fresh chain record stays unbound, ensure_runtime_launch_seed substitutes
    # live_identity, and the first prep fails 3x with 'chain runtime binding
    # drifted'. Bind whenever a manifest is in play OR policy requires it.
    manifest_in_play = bool(
        os.environ.get("ARNOLD_RUNTIME_MANIFEST")
        or os.environ.get("MEGAPLAN_TRUSTED_CONTAINER")
    )
    if not policy["required"] and not manifest_in_play:
        return report
    if report["status"] != "missing":
        return assert_execution_binding(spec_path, state, operation="chain start")
    if _state_has_progress(state):
        raise CliError(
            DRIFT_ERROR,
            "chain start refused: progressed chain state has no immutable launch binding",
        )
    active = report["active"]
    if not active.get("ready"):
        raise CliError(
            DRIFT_ERROR,
            "chain start refused: execution identity is not launch-ready: "
            + ", ".join(str(item) for item in active.get("errors") or []),
        )
    metadata = dict(getattr(state, "metadata", {}) or {})
    metadata["execution_binding"] = {
        "schema": BINDING_SCHEMA,
        "bound_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "launched_identity": active,
        "runtime_binding": {
            "schema": RUNTIME_BINDING_SCHEMA,
            "bound_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "current_identity": _normalized_runtime_identity(active["runtime"]),
            "rebind_events": [],
        },
    }
    state.metadata = metadata
    return execution_binding_report(spec_path, state)


def _identity_labels(identity: Mapping[str, Any]) -> list[str]:
    sequence = identity.get("milestone_sequence")
    if not isinstance(sequence, list):
        return []
    labels: list[str] = []
    for expected_index, item in enumerate(sequence):
        if not isinstance(item, Mapping):
            return []
        try:
            index = int(item.get("index"))
        except (TypeError, ValueError):
            return []
        label = str(item.get("label") or "").strip()
        if index != expected_index or not label:
            return []
        labels.append(label)
    return labels if len(set(labels)) == len(labels) else []


def _legacy_optional_spec_labels(
    spec_path: Path,
    *,
    spec_report: Mapping[str, Any],
    state: Any,
) -> list[str]:
    """Derive the cursor sequence for the pre-launch optional binding shape.

    Optional chains created before runtime replacement was introduced have no
    ``launched_identity``.  Their canonical frozen spec is still the authority
    for the milestone sequence; runtime identities must never supply it.
    Callers perform the spec SHA guards before invoking this helper (including
    again inside the chain-control transaction).
    """

    if spec_report.get("status") != "not_required":
        return []
    if isinstance(spec_report.get("expected"), Mapping):
        return []
    binding = (getattr(state, "metadata", {}) or {}).get("execution_binding")
    binding = binding if isinstance(binding, Mapping) else {}
    if isinstance(binding.get("launched_identity"), Mapping):
        return []
    runtime_binding = binding.get("runtime_binding")
    runtime_binding = runtime_binding if isinstance(runtime_binding, Mapping) else {}
    if not isinstance(runtime_binding.get("current_identity"), Mapping):
        return []

    from arnold_pipelines.megaplan.chain.spec import load_spec

    labels = [str(milestone.label or "").strip() for milestone in load_spec(spec_path).milestones]
    if not labels or any(not label for label in labels) or len(set(labels)) != len(labels):
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "runtime rebind refused: frozen spec milestone sequence is empty or ambiguous",
        )
    return labels


def _completed_labels(state: Any) -> list[str]:
    completed = getattr(state, "completed", None)
    if not isinstance(completed, list):
        return []
    labels: list[str] = []
    for item in completed:
        if not isinstance(item, Mapping):
            raise CliError(
                DRIFT_ERROR,
                "chain rebind refused: malformed completed milestone record",
            )
        label = str(item.get("label") or item.get("milestone") or "").strip()
        if not label:
            raise CliError(
                DRIFT_ERROR,
                "chain rebind refused: completed milestone label is missing",
            )
        labels.append(label)
    if len(set(labels)) != len(labels):
        raise CliError(
            DRIFT_ERROR,
            "chain rebind refused: completed milestone labels are ambiguous",
        )
    return labels


def rebind_execution_identity(
    spec_path: Path,
    state: Any,
    *,
    expected_previous_bundle_sha256: str,
    expected_active_bundle_sha256: str,
    expected_current_milestone: str,
    expected_current_plan: str,
    expected_next_milestone: str,
    reason: str,
    actor: str = "operator",
) -> dict[str, Any]:
    """Adopt an explicitly content-addressed successor chain without moving its cursor.

    Rebinding is intentionally narrower than ordinary reconciliation.  The
    operator must name both immutable bundle identities and the exact
    current/next cursor.  Completed and current milestones must be an
    unchanged prefix of both identities; only the future suffix may differ.
    """

    no_current_plan_guard = expected_current_plan == "@none"
    arguments = {
        "expected_previous_bundle_sha256": expected_previous_bundle_sha256,
        "expected_active_bundle_sha256": expected_active_bundle_sha256,
        "expected_current_milestone": expected_current_milestone,
        "expected_current_plan": expected_current_plan,
        "expected_next_milestone": expected_next_milestone,
        "reason": reason,
        "actor": actor,
    }
    if any(not str(value or "").strip() for value in arguments.values()):
        raise CliError(
            DRIFT_ERROR, "chain rebind refused: every rebind guard is required"
        )
    guarded_current_plan = "" if no_current_plan_guard else expected_current_plan
    if not _FULL_SHA256.fullmatch(expected_previous_bundle_sha256):
        raise CliError(
            DRIFT_ERROR, "chain rebind refused: previous bundle SHA-256 is invalid"
        )
    if not _FULL_SHA256.fullmatch(expected_active_bundle_sha256):
        raise CliError(
            DRIFT_ERROR, "chain rebind refused: active bundle SHA-256 is invalid"
        )

    report = execution_binding_report(spec_path, state)
    if not report.get("required"):
        raise CliError(
            DRIFT_ERROR, "chain rebind refused: execution binding is not required"
        )
    if report.get("status") not in {"drift", "reconcile_required"}:
        raise CliError(
            DRIFT_ERROR,
            f"chain rebind refused: binding status is {report.get('status')!r}, not drift",
        )
    previous = report.get("expected")
    active = report.get("active")
    if not isinstance(previous, Mapping) or not isinstance(active, Mapping):
        raise CliError(
            DRIFT_ERROR, "chain rebind refused: expected or active identity is missing"
        )
    if previous.get("bundle_sha256") != expected_previous_bundle_sha256:
        raise CliError(
            DRIFT_ERROR,
            "chain rebind refused: previous bundle SHA-256 does not match persisted binding",
        )
    if active.get("bundle_sha256") != expected_active_bundle_sha256:
        raise CliError(
            DRIFT_ERROR,
            "chain rebind refused: active bundle SHA-256 does not match validated source",
        )
    if not active.get("ready"):
        # T-0301 worktree-first waiver: the bound import root may carry
        # unrelated global editable metadata from a leftover candidate .venv
        # even when the chain runtime is genuinely worktree-first via
        # PYTHONPATH. execution_binding_report already accepts this exact
        # single-error shape via _bound_import_root_covers_editable_metadata_mismatch;
        # the rebind path must apply the same waiver or a bound chain can
        # never be rebind after a spec edit (grok consult 2026-08-17,
        # editable_runtime_import_root_mismatch on mega m3 rebind).
        bound_match = _bound_import_root_covers_editable_metadata_mismatch(
            previous, active
        )
        if not bound_match:
            raise CliError(
                DRIFT_ERROR,
                "chain rebind refused: active execution identity is not ready: "
                + ", ".join(str(item) for item in active.get("errors") or []),
            )

    previous_labels = _identity_labels(previous)
    active_labels = _identity_labels(active)
    if not previous_labels or not active_labels:
        raise CliError(
            DRIFT_ERROR,
            "chain rebind refused: milestone sequence is missing, duplicated, or malformed",
        )
    try:
        current_index = int(getattr(state, "current_milestone_index"))
    except (TypeError, ValueError):
        raise CliError(
            DRIFT_ERROR,
            "chain rebind refused: current milestone index is ambiguous",
        ) from None
    if (
        current_index < 0
        or current_index >= len(previous_labels)
        or current_index >= len(active_labels)
    ):
        raise CliError(
            DRIFT_ERROR,
            "chain rebind refused: current milestone index is outside a bound sequence",
        )

    completed_labels = _completed_labels(state)
    if len(completed_labels) != current_index:
        raise CliError(
            DRIFT_ERROR,
            "chain rebind refused: completed prefix does not equal the current cursor",
        )
    if (
        previous_labels[:current_index] != completed_labels
        or active_labels[:current_index] != completed_labels
    ):
        raise CliError(
            DRIFT_ERROR, "chain rebind refused: completed milestone prefix changed"
        )
    if previous_labels[current_index] != expected_current_milestone:
        raise CliError(
            DRIFT_ERROR,
            "chain rebind refused: persisted current milestone does not match the guard",
        )
    if active_labels[current_index] != expected_current_milestone:
        raise CliError(
            DRIFT_ERROR,
            "chain rebind refused: active source changed the current milestone",
        )
    if str(getattr(state, "current_plan_name", "") or "") != guarded_current_plan:
        raise CliError(
            DRIFT_ERROR, "chain rebind refused: current plan does not match the guard"
        )
    next_index = current_index + 1
    if next_index >= len(active_labels):
        raise CliError(
            DRIFT_ERROR, "chain rebind refused: active source has no guarded successor"
        )
    if active_labels[next_index] != expected_next_milestone:
        raise CliError(
            DRIFT_ERROR,
            "chain rebind refused: active next milestone does not match the guard",
        )
    if (
        expected_next_milestone in completed_labels
        or expected_next_milestone == expected_current_milestone
    ):
        raise CliError(
            DRIFT_ERROR,
            "chain rebind refused: guarded successor is already completed or current",
        )

    from arnold_pipelines.megaplan.chain.wbc import (
        ChainWbcRule,
        EXECUTION_REBIND_SURFACE,
        EXECUTION_REBIND_WRITER_ID,
        record_chain_wbc_evidence,
        validate_chain_wbc_transition,
    )

    validation_evidence = validate_chain_wbc_transition(
        writer_id=EXECUTION_REBIND_WRITER_ID,
        surface_name=EXECUTION_REBIND_SURFACE,
        transition_name="execution_rebind",
        subject=f"{expected_current_milestone}->{expected_next_milestone}",
        source_path=spec_path,
        project_dir=_project_root(spec_path),
        rules=(
            ChainWbcRule(
                "binding_required",
                True,
                bool(report.get("required")),
                bool(report.get("required")),
                "execution binding must remain required for guarded rebinds",
            ),
            ChainWbcRule(
                "binding_status",
                "drift|reconcile_required",
                report.get("status"),
                report.get("status") in {"drift", "reconcile_required"},
                "rebinds only repair a drifted or reconcile-required identity",
            ),
            ChainWbcRule(
                "previous_bundle_sha256",
                expected_previous_bundle_sha256,
                previous.get("bundle_sha256"),
                previous.get("bundle_sha256") == expected_previous_bundle_sha256,
            ),
            ChainWbcRule(
                "active_bundle_sha256",
                expected_active_bundle_sha256,
                active.get("bundle_sha256"),
                active.get("bundle_sha256") == expected_active_bundle_sha256,
            ),
            ChainWbcRule(
                "active_ready",
                True,
                bool(active.get("ready")),
                bool(active.get("ready")),
            ),
            ChainWbcRule(
                "current_milestone",
                expected_current_milestone,
                active_labels[current_index],
                active_labels[current_index] == expected_current_milestone,
            ),
            ChainWbcRule(
                "next_milestone",
                expected_next_milestone,
                active_labels[next_index],
                active_labels[next_index] == expected_next_milestone,
            ),
        ),
        extra={
            "actor": actor,
            "reason": reason,
            "completed_prefix": completed_labels,
            "current_plan": guarded_current_plan,
        },
    )

    rebound_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    event_core = {
        "schema": REBIND_SCHEMA,
        "rebound_at": rebound_at,
        "actor": actor,
        "reason": reason,
        "from_bundle_sha256": expected_previous_bundle_sha256,
        "to_bundle_sha256": expected_active_bundle_sha256,
        "current_milestone_index": current_index,
        "current_milestone": expected_current_milestone,
        "current_plan": guarded_current_plan,
        "next_milestone": expected_next_milestone,
        "completed_prefix": completed_labels,
    }
    event = {
        **event_core,
        "content_sha256": _sha256_bytes(
            json.dumps(event_core, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ),
    }
    metadata = dict(getattr(state, "metadata", {}) or {})
    binding = dict(metadata.get("execution_binding") or {})
    events = binding.get("rebind_events")
    events = list(events) if isinstance(events, list) else []
    events.append(event)
    binding.update(
        {
            "schema": BINDING_SCHEMA,
            "launched_identity": dict(active),
            "last_rebound_at": rebound_at,
            "rebind_events": events,
        }
    )
    record_chain_wbc_evidence(
        binding,
        entry_key=f"execution_rebind:{expected_current_milestone}:{expected_next_milestone}",
        evidence=validation_evidence,
    )
    metadata["execution_binding"] = binding
    state.metadata = metadata
    rebound_report = execution_binding_report(spec_path, state)
    if rebound_report.get("status") != "match":
        raise CliError(
            DRIFT_ERROR,
            "chain rebind refused: rebound identity did not verify as an exact match",
        )
    return {"event": event, "execution_binding": rebound_report}


def _rebind_optional_runtime_identity_transaction(
    spec_path: Path,
    state: Any,
    *,
    expected_previous_runtime_sha256: str,
    expected_active_runtime_sha256: str,
    expected_current_milestone: str,
    expected_current_plan: str,
    reason: str,
    actor: str,
    direction: str,
    verified_external_runtime_identity: Mapping[str, Any] | None,
    verified_external_runtime_receipt: str | None,
    expected_chain_spec_sha256: str | None,
    released_hold_receipt: str | None = None,
    attested_hold_context_receipt: str | None = None,
) -> dict[str, Any]:
    """Replace an optional chain's runtime through one NBF-08 transaction.

    This is intentionally a replacement-only path.  It reads and validates
    every mutable authority (spec, chain state, and paused plan) while the
    canonical journal locks are held, then performs the sole state write via
    ``ChainStateAdapter.cas_write``.  In particular, there is no trailing
    legacy ``save_chain_state`` call that could create a second effect.
    """
    from arnold_pipelines.megaplan._core.io import find_plan_dir
    from arnold_pipelines.megaplan.chain.spec import ChainState, _state_path_for
    from arnold_pipelines.megaplan.incident.chain_control import (
        ChainControlCasConflict,
        ChainControlHold,
        ChainStateAdapter,
        _stable_id,
        apply_chain_lifecycle,
        chain_id_for_spec,
        state_digest_for,
    )

    project_root = _project_root(spec_path)
    state_path = _state_path_for(spec_path)
    current_plan = str(getattr(state, "current_plan_name", "") or "").strip()
    plan_dir = find_plan_dir(project_root, current_plan) if current_plan else None
    plan_state_path = (
        plan_dir / "state.json" if plan_dir is not None else None
    )
    chain_id = chain_id_for_spec(spec_path)
    if released_hold_receipt and attested_hold_context_receipt:
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "runtime rebind refused: released-hold and attested-context receipts are mutually exclusive",
        )
    runtime_context = {
        "chain_id": chain_id,
        "policy": "optional",
        "direction": direction,
        "chain_spec_sha256": str(expected_chain_spec_sha256 or ""),
        "cursor": getattr(state, "current_milestone_index", None),
        "current_milestone": expected_current_milestone,
        "current_plan": expected_current_plan,
        "from_runtime_sha256": expected_previous_runtime_sha256,
        "to_runtime_sha256": expected_active_runtime_sha256,
    }
    operation_id = _stable_id(
        "runtime-rebind",
        "optional-policy-replacement",
        chain_id,
        str(expected_chain_spec_sha256 or ""),
        expected_previous_runtime_sha256,
        expected_active_runtime_sha256,
        expected_current_milestone,
        expected_current_plan,
        direction,
        reason,
        actor,
    )
    release_reference: dict[str, Any] | None = None
    attestation_reference: dict[str, Any] | None = None
    if released_hold_receipt:
        receipt_path = Path(released_hold_receipt).expanduser().resolve(strict=False)
        try:
            receipt_payload = json.loads(receipt_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CliError(RUNTIME_DRIFT_ERROR, "released-hold receipt is unreadable") from exc
        candidate = receipt_payload.get("event") if isinstance(receipt_payload, Mapping) else None
        candidate = candidate if isinstance(candidate, Mapping) else receipt_payload
        payload = candidate.get("payload") if isinstance(candidate, Mapping) else None
        if not isinstance(candidate, Mapping) or candidate.get("event_kind") != "chain_control.hold_released" or not isinstance(payload, Mapping):
            raise CliError(RUNTIME_DRIFT_ERROR, "released-hold receipt is not a hold release")
        release_reference = {
            "path": str(receipt_path),
            "event_hash": str(candidate.get("event_hash") or ""),
            "recovery_epoch": str(payload.get("recovery_epoch") or payload.get("release_operation_id") or ""),
            "target_operation_id": str(payload.get("target_operation_id") or ""),
        }
        if not all(
            (
                re.fullmatch(r"[0-9a-f]{64}", release_reference["event_hash"]),
                re.fullmatch(r"[0-9a-f]{64}", release_reference["recovery_epoch"]),
                re.fullmatch(r"[0-9a-f]{64}", release_reference["target_operation_id"]),
            )
        ):
            raise CliError(RUNTIME_DRIFT_ERROR, "released-hold receipt lacks exact recovery identities")
        operation_id = _stable_id(
            "runtime-rebind-released-hold",
            operation_id,
            release_reference["event_hash"],
            release_reference["recovery_epoch"],
        )
    if attested_hold_context_receipt:
        receipt_path = Path(attested_hold_context_receipt).expanduser().resolve(strict=False)
        try:
            receipt_payload = json.loads(receipt_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CliError(RUNTIME_DRIFT_ERROR, "attested hold-context receipt is unreadable") from exc
        candidate = receipt_payload.get("event") if isinstance(receipt_payload, Mapping) else None
        candidate = candidate if isinstance(candidate, Mapping) else receipt_payload
        if not isinstance(receipt_payload, Mapping) or receipt_payload.get("schema") != HOLD_CONTEXT_ATTESTATION_SCHEMA:
            raise CliError(RUNTIME_DRIFT_ERROR, "attested hold-context receipt schema is invalid")
        payload = candidate.get("payload") if isinstance(candidate, Mapping) else None
        effect = payload.get("effect") if isinstance(payload, Mapping) else None
        context = effect.get(RUNTIME_REBIND_CONTEXT_KEY) if isinstance(effect, Mapping) else None
        if (
            not isinstance(candidate, Mapping)
            or candidate.get("event_kind") != "chain_control.hold_context_attested"
            or not isinstance(payload, Mapping)
            or not isinstance(effect, Mapping)
            or not isinstance(context, Mapping)
        ):
            raise CliError(RUNTIME_DRIFT_ERROR, "attested hold-context receipt is invalid")
        event_hash = str(candidate.get("event_hash") or "")
        if not _FULL_SHA256.fullmatch(event_hash):
            raise CliError(RUNTIME_DRIFT_ERROR, "attested hold-context receipt lacks an event hash")
        attestation_reference = {
            "path": str(receipt_path),
            "event_hash": event_hash,
            "target_operation_id": str(effect.get("target_operation_id") or ""),
            "held_event_hash": str(effect.get("held_event_hash") or ""),
            "release_event_hash": str(effect.get("release_event_hash") or ""),
            "context": dict(context),
        }
        if not all(
            _FULL_SHA256.fullmatch(attestation_reference[key])
            for key in ("target_operation_id", "held_event_hash", "release_event_hash")
        ):
            raise CliError(RUNTIME_DRIFT_ERROR, "attested hold-context receipt lacks exact recovery identities")
        if any(attestation_reference["context"].get(key) != value for key, value in runtime_context.items()):
            raise CliError(RUNTIME_DRIFT_ERROR, "attested hold-context receipt does not match rebind guards")
        operation_id = _stable_id(
            "runtime-rebind-attested-hold",
            attestation_reference["event_hash"],
            *[str(runtime_context[key]) for key in (
                "chain_id", "policy", "direction", "chain_spec_sha256", "cursor",
                "current_milestone", "current_plan", "from_runtime_sha256", "to_runtime_sha256",
            )],
        )
    # The operation identity, rather than the mutable revision counter, is the
    # replay key.  The adapter re-reads and CAS-checks the on-disk revision
    # under the lock; keeping this outer value unset lets a second identical
    # CLI invocation replay after the first CAS increments that counter.
    expected_revision = None
    receipt_link = (
        str(Path(verified_external_runtime_receipt).resolve(strict=False))
        if verified_external_runtime_receipt
        else None
    )
    linked_receipts = [receipt_link] if receipt_link else []
    if release_reference:
        linked_receipts.append(release_reference["path"])
    if attestation_reference:
        linked_receipts.append(attestation_reference["path"])

    def _effect(txn: Any) -> dict[str, Any]:
        adapter = ChainStateAdapter(txn, state_path)
        raw_state = adapter.read_expected()
        if not isinstance(raw_state, Mapping):
            raise ChainControlHold(
                "missing_chain_state",
                "optional runtime replacement requires persisted chain state",
            )
        current_revision = (raw_state.get("metadata") or {}).get("_nbf08_revision")
        if expected_revision is not None and current_revision != expected_revision:
            raise ChainControlCasConflict(
                "stale chain-state revision",
                details={"expected": expected_revision, "actual": current_revision},
            )

        # These are the final on-disk/persisted guards, immediately before the
        # state CAS.  The pause and cursor/binding guards are re-run by the
        # existing rebind validator against this freshly read state below.
        observed_spec_sha256 = _sha256_file(spec_path)
        persisted_spec_sha256 = str(
            (raw_state.get("metadata") or {}).get("chain_spec_sha256") or ""
        )
        if not (
            observed_spec_sha256 == str(expected_chain_spec_sha256)
            and persisted_spec_sha256 == str(expected_chain_spec_sha256)
        ):
            raise ChainControlHold(
                RUNTIME_DRIFT_ERROR,
                "runtime rebind refused: chain spec SHA-256 does not match "
                "the supplied and persisted guard",
                details={
                    "expected": expected_chain_spec_sha256,
                    "on_disk": observed_spec_sha256,
                    "persisted": persisted_spec_sha256,
                },
            )
        current_state = ChainState.from_dict(dict(raw_state))
        replay = txn.journal.replay_strict()
        base_operation_id = _stable_id(
            "runtime-rebind", "optional-policy-replacement", chain_id,
            str(expected_chain_spec_sha256 or ""), expected_previous_runtime_sha256,
            expected_active_runtime_sha256, expected_current_milestone,
            expected_current_plan, direction, reason, actor,
        )
        if attestation_reference is not None:
            authoritative = next(
                (
                    event for event in replay["accepted"]
                    if event.get("event_kind") == "chain_control.hold_context_attested"
                    and event.get("event_hash") == attestation_reference["event_hash"]
                ),
                None,
            )
            auth_effect = ((authoritative or {}).get("payload") or {}).get("effect")
            if (
                authoritative is None
                or not isinstance(auth_effect, Mapping)
                or auth_effect.get("target_operation_id") != attestation_reference["target_operation_id"]
                or auth_effect.get("held_event_hash") != attestation_reference["held_event_hash"]
                or auth_effect.get("release_event_hash") != attestation_reference["release_event_hash"]
                or authoritative.get("chain_id") != chain_id
                or auth_effect.get(RUNTIME_REBIND_CONTEXT_KEY) != runtime_context
            ):
                raise ChainControlHold(
                    RUNTIME_DRIFT_ERROR,
                    "runtime rebind refused: attested hold context is not authoritative",
                )
            if attestation_reference["target_operation_id"] == operation_id:
                raise ChainControlHold(
                    RUNTIME_DRIFT_ERROR,
                    "runtime rebind refused: attestation operation collides with held operation",
                )
        elif release_reference is None:
            existing = replay["operations"].get(base_operation_id)
            released_runtime_hold = any(
                event.get("event_kind") == "chain_control.hold_released"
                and isinstance((event.get("payload") or {}).get("target_operation_id"), str)
                and any(
                    prior.get("event_kind") == "chain_control.intent"
                    and prior.get("operation_id") == (event.get("payload") or {}).get("target_operation_id")
                    and (prior.get("payload") or {}).get("intent_kind") == "runtime-rebind"
                    for prior in replay["accepted"]
                )
                for event in replay["accepted"]
            )
            if (existing is not None and existing.get("event_kind") == "chain_control.hold_released") or released_runtime_hold:
                raise ChainControlHold(
                    RUNTIME_DRIFT_ERROR,
                    "runtime rebind refused: released hold receipt is required for a fresh attempt",
                )
        elif release_reference:
            authoritative = next(
                (
                    event for event in replay["accepted"]
                    if event.get("event_kind") == "chain_control.hold_released"
                    and event.get("event_hash") == release_reference["event_hash"]
                ),
                None,
            )
            auth_payload = authoritative.get("payload") if isinstance(authoritative, Mapping) else None
            if (
                authoritative is None
                or not isinstance(auth_payload, Mapping)
                or auth_payload.get("target_operation_id") != base_operation_id
                or auth_payload.get("release_operation_id") != release_reference["recovery_epoch"]
                or authoritative.get("chain_id") != chain_id
            ):
                raise ChainControlHold(
                    RUNTIME_DRIFT_ERROR,
                    "runtime rebind refused: released hold does not target the prior failed operation",
                )
        try:
            rebound = rebind_runtime_identity(
                spec_path,
                current_state,
                expected_previous_runtime_sha256=expected_previous_runtime_sha256,
                expected_active_runtime_sha256=expected_active_runtime_sha256,
                expected_current_milestone=expected_current_milestone,
                expected_current_plan=expected_current_plan,
                reason=reason,
                actor=actor,
                direction=direction,
                verified_external_runtime_identity=verified_external_runtime_identity,
                verified_external_runtime_receipt=verified_external_runtime_receipt,
                allow_optional_policy=True,
                expected_chain_spec_sha256=expected_chain_spec_sha256,
                _inside_transaction=True,
            )
        except CliError as exc:
            raise ChainControlHold(
                exc.code,
                exc.message,
                details=dict(exc.extra),
            ) from exc
        pre_digest = state_digest_for(raw_state)
        written = adapter.cas_write(
            current_state.to_dict(),
            expected_revision=current_revision,
        )
        post_digest = state_digest_for(written)
        state.__dict__.update(ChainState.from_dict(written).__dict__)
        active_identity = dict(
            (rebound.get("runtime_binding") or {}).get("active") or {}
        )
        return {
            "pre_state_digest": pre_digest,
            "post_state_digest": post_digest,
            "actual_revision": (written.get("metadata") or {}).get("_nbf08_revision"),
            "actual_cursor": written.get("current_milestone_index"),
            "current_milestone_index": written.get("current_milestone_index"),
            "current_milestone": expected_current_milestone,
            "current_plan": expected_current_plan if expected_current_plan != "@none" else "",
            "chain_spec_sha256": str(expected_chain_spec_sha256),
            "runtime_identity": {
                "from": dict(
                    ((raw_state.get("metadata") or {}).get("execution_binding") or {})
                    .get("runtime_binding", {})
                    .get("current_identity", {})
                ),
                "to": active_identity,
            },
            "provenance_link": receipt_link,
            "linked_receipts": linked_receipts,
            "runtime_binding": rebound.get("runtime_binding"),
            "verification_mode": rebound.get("verification_mode"),
            "rebind_event": rebound.get("event"),
            RUNTIME_REBIND_CONTEXT_KEY: runtime_context,
            **(
                {
                    "attested_hold_context": {
                        "event_hash": attestation_reference["event_hash"],
                        "target_operation_id": attestation_reference["target_operation_id"],
                        "held_event_hash": attestation_reference["held_event_hash"],
                        "release_event_hash": attestation_reference["release_event_hash"],
                    }
                }
                if attestation_reference
                else {}
            ),
        }

    result = apply_chain_lifecycle(
        spec_path,
        project_root,
        intent_kind="runtime-rebind",
        actor={"id": actor, "class": "operator"},
        operation_id=operation_id,
        # Keep this stable across retries.  The effect checks the caller's
        # revision, while mutate's replay key must remain replayable after the
        # first CAS increments it.
        expected_revision=None,
        expected_cursor=expected_current_milestone,
        linked_receipts=linked_receipts,
        effect=_effect,
        state_paths=[plan_state_path] if plan_state_path is not None else (),
        committed_event_kind="chain_control.runtime_rebound",
        intent_context={RUNTIME_REBIND_CONTEXT_KEY: runtime_context},
    )
    if result.get("outcome") == "committed":
        effect = result.get("effect") or {}
        ledger_event = result.get("event") or result.get("result")
        # Keep the established API's compact rebind event while exposing all
        # canonical envelope fields for NBF-08 consumers.
        event = dict(effect.get("rebind_event") or {})
        if isinstance(ledger_event, Mapping):
            event.update(dict(ledger_event))
        return {
            "outcome": "committed",
            "event": event,
            "receipt": ledger_event,
            "ledger_event": ledger_event,
            "runtime_binding": effect.get("runtime_binding"),
            "verification_mode": effect.get("verification_mode"),
        }
    if result.get("outcome") == "replay":
        prior = result.get("result") or {}
        effect = ((prior.get("payload") or {}).get("effect") or {}) if isinstance(prior, Mapping) else {}
        event = dict(effect.get("rebind_event") or {})
        if isinstance(prior, Mapping):
            event.update(dict(prior))
        return {
            "outcome": "replay",
            "event": event,
            "receipt": prior,
            "ledger_event": prior,
            "replay_event": result.get("replay_event"),
            "runtime_binding": effect.get("runtime_binding"),
            "verification_mode": effect.get("verification_mode", "external_interpreter_receipt"),
        }
    error = result.get("error")
    if isinstance(error, ChainControlHold):
        raise CliError(error.code, str(error), extra=dict(error.details)) from error
    raise CliError(
        RUNTIME_DRIFT_ERROR,
        "runtime rebind refused: canonical chain-control transaction did not commit",
    )


def attest_hold_context(
    spec_path: Path,
    state: Any,
    *,
    released_hold_receipt: str,
    expected_chain_id: str,
    expected_operation_id: str,
    expected_hold_event_hash: str,
    expected_release_event_hash: str,
    expected_chain_spec_sha256: str,
    expected_state_digest: str,
    expected_current_milestone: str,
    expected_current_plan: str,
    expected_cursor: int,
    expected_previous_runtime_sha256: str,
    expected_active_runtime_sha256: str,
    direction: str,
    runtime_identity: Mapping[str, Any],
    runtime_provenance_receipt: str,
    recovery_evidence: Path,
    reason: str,
    actor: str = "operator",
    expected_state_revision: int | None = None,
    expect_missing_state_revision: bool = False,
    _external_identity_verified: bool = False,
) -> dict[str, Any]:
    """Attest immutable context for a legacy, contextless runtime hold.

    This is an evidence-only bridge.  It never writes chain state; the only
    durable effect is a canonical ``hold_context_attested`` event linking the
    original hold and its release.  New context-bearing holds bypass this API.
    """
    from arnold_pipelines.megaplan._core.io import find_plan_dir
    from arnold_pipelines.megaplan.chain.spec import _state_path_for, load_spec
    from arnold_pipelines.megaplan.chain.target_rebind import _assert_pause
    from arnold_pipelines.megaplan.incident.chain_control import (
        ChainControlCasConflict,
        ChainControlHold,
        ChainStateAdapter,
        _stable_id,
        apply_chain_lifecycle,
        chain_id_for_spec,
        state_digest_for,
    )

    if binding_policy(spec_path)["mode"] != "optional":
        raise CliError(RUNTIME_DRIFT_ERROR, "hold context attestation requires optional policy")
    if expected_chain_id != chain_id_for_spec(spec_path):
        raise CliError(RUNTIME_DRIFT_ERROR, "hold context attestation chain does not match the spec")
    for value, label in (
        (expected_operation_id, "operation"),
        (expected_hold_event_hash, "hold event"),
        (expected_release_event_hash, "release event"),
        (expected_chain_spec_sha256, "chain spec"),
        (expected_state_digest, "state"),
        (expected_previous_runtime_sha256, "previous runtime"),
        (expected_active_runtime_sha256, "active runtime"),
    ):
        if not _FULL_SHA256.fullmatch(str(value or "")):
            raise CliError(RUNTIME_DRIFT_ERROR, f"{label} SHA-256 is invalid")
    if direction not in {"cutover", "rollback"}:
        raise CliError(RUNTIME_DRIFT_ERROR, "runtime rebind direction must be cutover or rollback")
    if not all(str(value or "").strip() for value in (expected_current_milestone, expected_current_plan, reason, actor)):
        raise CliError(RUNTIME_DRIFT_ERROR, "every hold context attestation guard is required")
    if expect_missing_state_revision and expected_state_revision is not None:
        raise CliError(RUNTIME_DRIFT_ERROR, "missing-revision mode cannot include a state revision")
    if not expect_missing_state_revision and expected_state_revision is None:
        raise CliError(RUNTIME_DRIFT_ERROR, "hold context attestation requires an explicit revision expectation")
    if not recovery_evidence.is_file():
        raise CliError(RUNTIME_DRIFT_ERROR, "hold context attestation recovery evidence is unavailable")
    evidence_sha = _sha256_file(recovery_evidence)
    release_path = Path(released_hold_receipt).expanduser().resolve(strict=False)
    try:
        receipt_payload = json.loads(release_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CliError(RUNTIME_DRIFT_ERROR, "released-hold receipt is unreadable") from exc
    release_event = receipt_payload.get("event") if isinstance(receipt_payload, Mapping) else None
    release_event = release_event if isinstance(release_event, Mapping) else receipt_payload
    release_payload = release_event.get("payload") if isinstance(release_event, Mapping) else None
    if (
        not isinstance(receipt_payload, Mapping)
        or receipt_payload.get("schema") != "nbf08-chain-control-hold-release-v1"
        or not isinstance(release_event, Mapping)
        or release_event.get("event_kind") != "chain_control.hold_released"
        or not isinstance(release_payload, Mapping)
        or release_event.get("event_hash") != expected_release_event_hash
        or release_payload.get("chain_id") != expected_chain_id
        or release_payload.get("target_operation_id") != expected_operation_id
        or release_payload.get("held_event_hash") != expected_hold_event_hash
    ):
        raise CliError(RUNTIME_DRIFT_ERROR, "released-hold receipt does not match the exact hold tuple")
    receipt_path = Path(runtime_provenance_receipt).expanduser().resolve(strict=False)
    if not receipt_path.is_file():
        raise CliError(RUNTIME_DRIFT_ERROR, "runtime provenance receipt is unavailable")
    receipt_data = _json_object(receipt_path, label="runtime provenance receipt")
    if receipt_data.get("schema") != RUNTIME_PROVENANCE_RECEIPT_SCHEMA:
        raise CliError(RUNTIME_DRIFT_ERROR, "runtime provenance receipt schema is invalid")
    if not isinstance(runtime_identity, Mapping):
        raise CliError(RUNTIME_DRIFT_ERROR, "runtime identity is required")
    verified_identity = dict(runtime_identity)
    if not _external_identity_verified:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".runtime-identity.json") as identity_file:
            json.dump(dict(runtime_identity), identity_file)
            identity_file.flush()
            verified_identity = dict(verify_external_runtime_identity(Path(identity_file.name), receipt_path))
    if verified_identity.get("content_sha256") != expected_active_runtime_sha256:
        raise CliError(RUNTIME_DRIFT_ERROR, "verified runtime identity does not match the attested target")

    context = {
        "chain_id": expected_chain_id,
        "policy": "optional",
        "direction": direction,
        "chain_spec_sha256": expected_chain_spec_sha256,
        "cursor": expected_cursor,
        "current_milestone": expected_current_milestone,
        "current_plan": expected_current_plan,
        "from_runtime_sha256": expected_previous_runtime_sha256,
        "to_runtime_sha256": expected_active_runtime_sha256,
    }
    operation_id = _stable_id(
        "hold-context-attestation",
        expected_release_event_hash,
        *[str(context[key]) for key in (
            "chain_id", "policy", "direction", "chain_spec_sha256", "cursor",
            "current_milestone", "current_plan", "from_runtime_sha256", "to_runtime_sha256",
        )],
    )
    state_path = _state_path_for(spec_path)
    project_root = _project_root(spec_path)
    plan_dir = find_plan_dir(project_root, expected_current_plan)
    plan_state_path = plan_dir / "state.json" if plan_dir is not None else None
    if plan_state_path is None or not plan_state_path.is_file():
        raise CliError(RUNTIME_DRIFT_ERROR, "canonical paused plan state is unavailable")

    def _effect(txn: Any) -> dict[str, Any]:
        replay = txn.journal.replay_strict()
        release = next(
            (
                event for event in replay["accepted"]
                if event.get("event_kind") == "chain_control.hold_released"
                and event.get("event_hash") == expected_release_event_hash
            ),
            None,
        )
        release_inner = release.get("payload") if isinstance(release, Mapping) else None
        if (
            not isinstance(release_inner, Mapping)
            or release.get("chain_id") != expected_chain_id
            or release_inner.get("target_operation_id") != expected_operation_id
            or release_inner.get("held_event_hash") != expected_hold_event_hash
        ):
            raise ChainControlHold("hold_release_mismatch", "released hold is not authoritative")
        operation_events = [
            event for event in replay["accepted"]
            if event.get("chain_id") == expected_chain_id
            and event.get("operation_id") == expected_operation_id
        ]
        hold = next(
            (
                event for event in operation_events
                if event.get("event_kind") == "chain_control.hold"
                and event.get("event_hash") == expected_hold_event_hash
            ),
            None,
        )
        if not isinstance(hold, Mapping) or operation_events[-1].get("event_kind") != "chain_control.hold_released":
            raise ChainControlHold("hold_target_mismatch", "hold context attestation requires the latest exact released hold")
        if any(
            isinstance(event.get("payload"), Mapping)
            and RUNTIME_REBIND_CONTEXT_KEY in event.get("payload", {})
            for event in operation_events
            if event.get("event_kind") == "chain_control.intent"
        ):
            raise ChainControlHold("context_already_present", "context-bearing hold does not require attestation")
        original_intent = next(
            (
                event for event in operation_events
                if event.get("event_kind") == "chain_control.intent"
            ),
            None,
        )
        if not isinstance(original_intent, Mapping) or (original_intent.get("payload") or {}).get("intent_kind") != "runtime-rebind":
            raise ChainControlHold("not_runtime_rebind_hold", "hold is not a runtime-rebind operation")
        for prior_attestation in replay["accepted"]:
            if prior_attestation.get("event_kind") != "chain_control.hold_context_attested":
                continue
            prior_effect = ((prior_attestation.get("payload") or {}).get("effect"))
            if not isinstance(prior_effect, Mapping):
                continue
            if (
                prior_effect.get("target_operation_id") == expected_operation_id
                and prior_effect.get("release_event_hash") == expected_release_event_hash
                and prior_effect.get(RUNTIME_REBIND_CONTEXT_KEY) != context
            ):
                raise ChainControlHold(
                    "attestation_reuse",
                    "hold context has already been attested with a different runtime target",
                )
        current = ChainStateAdapter(txn, state_path).read_expected()
        if not isinstance(current, Mapping):
            raise ChainControlHold("missing_chain_state", "canonical chain state is unavailable")
        metadata = current.get("metadata") or {}
        if hashlib.sha256(spec_path.read_bytes()).hexdigest() != expected_chain_spec_sha256 or str(metadata.get("chain_spec_sha256") or "") != expected_chain_spec_sha256:
            raise ChainControlHold("spec_cas_conflict", "chain spec SHA-256 changed")
        if state_digest_for(current) != expected_state_digest:
            raise ChainControlCasConflict("chain state digest changed")
        observed_revision = metadata.get("_nbf08_revision")
        if expect_missing_state_revision:
            if observed_revision is not None:
                raise ChainControlCasConflict("chain state revision is present; missing-revision guard failed")
        elif observed_revision != expected_state_revision:
            raise ChainControlCasConflict("chain state revision changed")
        if current.get("current_milestone_index") != expected_cursor or str(current.get("current_plan_name") or "") != expected_current_plan:
            raise ChainControlCasConflict("chain cursor or current plan changed")
        spec = load_spec(spec_path)
        if not (0 <= expected_cursor < len(spec.milestones)) or spec.milestones[expected_cursor].label != expected_current_milestone:
            raise ChainControlHold("milestone_mismatch", "current milestone does not match the frozen spec")
        binding = ((metadata.get("execution_binding") or {}).get("runtime_binding") or {})
        current_identity = binding.get("current_identity") if isinstance(binding, Mapping) else None
        if not isinstance(current_identity, Mapping) or current_identity.get("content_sha256") != expected_previous_runtime_sha256:
            raise ChainControlHold("runtime_binding_mismatch", "current runtime does not match the attested from runtime")
        try:
            plan_state = json.loads(plan_state_path.read_text(encoding="utf-8"))
            _assert_pause(current, plan_state, expected_plan=expected_current_plan)
        except (OSError, json.JSONDecodeError) as exc:
            raise ChainControlHold("pause_unreadable", "canonical paused plan state is unreadable") from exc
        except Exception as exc:
            if isinstance(exc, ChainControlHold):
                raise
            raise ChainControlHold("pause_mismatch", str(exc)) from exc
        digest = state_digest_for(current)
        return {
            "pre_state_digest": digest,
            "post_state_digest": digest,
            "actual_revision": observed_revision,
            "actual_cursor": expected_cursor,
            "current_milestone": expected_current_milestone,
            "current_plan": expected_current_plan,
            "chain_spec_sha256": expected_chain_spec_sha256,
            "target_operation_id": expected_operation_id,
            "held_event_hash": expected_hold_event_hash,
            "release_event_hash": expected_release_event_hash,
            RUNTIME_REBIND_CONTEXT_KEY: context,
            "source": "operator_attestation",
            "recovery_evidence": {"path": str(recovery_evidence.resolve()), "sha256": evidence_sha},
            "runtime_identity": {"from": dict(current_identity), "to": dict(verified_identity)},
            "linked_receipts": [str(release_path), str(receipt_path), str(recovery_evidence.resolve())],
        }

    result = apply_chain_lifecycle(
        spec_path,
        project_root,
        intent_kind="hold-context-attestation",
        actor={"id": actor, "class": "operator"},
        operation_id=operation_id,
        expected_revision=None,
        expected_cursor=expected_cursor,
        linked_receipts=[str(release_path), str(receipt_path), str(recovery_evidence.resolve())],
        effect=_effect,
        state_paths=[plan_state_path],
        committed_event_kind="chain_control.hold_context_attested",
        intent_context={RUNTIME_REBIND_CONTEXT_KEY: context},
    )
    if result.get("outcome") == "committed":
        return {"outcome": "committed", "event": result.get("event"), "receipt": result.get("result")}
    if result.get("outcome") == "replay":
        prior = result.get("result") or {}
        return {"outcome": "replay", "event": prior, "receipt": prior, "replay_event": result.get("replay_event")}
    error = result.get("error")
    if isinstance(error, ChainControlHold):
        raise CliError(error.code, str(error), extra=dict(error.details)) from error
    raise CliError(RUNTIME_DRIFT_ERROR, "hold context attestation did not commit")


def rebind_runtime_identity(
    spec_path: Path,
    state: Any,
    *,
    expected_previous_runtime_sha256: str,
    expected_active_runtime_sha256: str,
    expected_current_milestone: str,
    expected_current_plan: str,
    reason: str,
    actor: str = "operator",
    direction: str = "cutover",
    verified_external_runtime_identity: Mapping[str, Any] | None = None,
    update_engine_root: bool = False,
    allow_optional_policy: bool = False,
    expected_chain_spec_sha256: str | None = None,
    verified_external_runtime_receipt: str | None = None,
    released_hold_receipt: str | None = None,
    attested_hold_context_receipt: str | None = None,
    _inside_transaction: bool = False,
    _external_identity_verified: bool = False,
) -> dict[str, Any]:
    """Adopt or roll back an exact runtime without rewriting the spec binding.

    When ``update_engine_root`` is set (the ``chain runtime-cutover`` path),
    ``metadata.execution_environment.engine_root`` is moved old->new in the
    same in-memory transaction: the recorded root must CAS-match the previous
    runtime identity's ``import_root`` before ANY mutation, and the new root
    is taken from the adopted runtime identity's ``import_root``.  Non-metadata
    chain fields are untouched, so the CLI's post-mutation operational-field
    check keeps the write fail-closed.
    """

    if direction not in {"cutover", "rollback"}:
        raise CliError(
            RUNTIME_DRIFT_ERROR, "runtime rebind direction must be cutover or rollback"
        )
    if released_hold_receipt and not allow_optional_policy:
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "runtime rebind refused: released-hold receipt requires optional-policy override",
        )
    if attested_hold_context_receipt and not allow_optional_policy:
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "runtime rebind refused: attested hold-context receipt requires optional-policy override",
        )
    if released_hold_receipt and attested_hold_context_receipt:
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "runtime rebind refused: released-hold and attested-context receipts are mutually exclusive",
        )
    if not _FULL_SHA256.fullmatch(expected_previous_runtime_sha256):
        raise CliError(RUNTIME_DRIFT_ERROR, "previous runtime SHA-256 is invalid")
    if not _FULL_SHA256.fullmatch(expected_active_runtime_sha256):
        raise CliError(RUNTIME_DRIFT_ERROR, "active runtime SHA-256 is invalid")
    if not all(
        str(value or "").strip()
        for value in (expected_current_milestone, expected_current_plan, reason, actor)
    ):
        raise CliError(RUNTIME_DRIFT_ERROR, "every runtime rebind guard is required")

    # Optional-policy replacement has a distinct NBF-08 transaction boundary.
    # Route before inspecting the old binding/cursor so an exact retry can be
    # answered from the durable operation receipt even after the first write
    # changed the persisted current identity and revision.
    if allow_optional_policy and not _inside_transaction:
        if binding_policy(spec_path)["mode"] != "optional":
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime rebind refused: --allow-optional-policy is only valid "
                "when driver.execution_binding is optional",
            )
        if not expected_chain_spec_sha256 or not _FULL_SHA256.fullmatch(
            str(expected_chain_spec_sha256)
        ):
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime rebind refused: --expected-chain-spec-sha256 is "
                "required with --allow-optional-policy",
            )
        if not verified_external_runtime_receipt:
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime rebind refused: optional-policy replacement requires "
                "a runtime provenance receipt",
            )
        receipt_path = Path(str(verified_external_runtime_receipt)).expanduser().resolve(strict=False)
        if not receipt_path.is_file():
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime rebind refused: runtime provenance receipt is unavailable",
            )
        try:
            receipt_payload = _json_object(
                receipt_path, label="runtime provenance receipt"
            )
        except CliError:
            raise
        if receipt_payload.get("schema") != RUNTIME_PROVENANCE_RECEIPT_SCHEMA:
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime rebind refused: runtime provenance receipt schema is invalid",
            )
        if not isinstance(verified_external_runtime_identity, Mapping):
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime rebind refused: optional-policy replacement requires "
                "an independently verified external runtime identity",
            )
        if not _external_identity_verified:
            # Public callers provide the observed identity as a value, while
            # the canonical verifier consumes identity/receipt files. Verify
            # that same value through its independent interpreter before the
            # chain-control transaction can acquire mutation authority.
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", suffix=".runtime-identity.json"
            ) as identity_file:
                json.dump(dict(verified_external_runtime_identity), identity_file)
                identity_file.flush()
                verified_external_runtime_identity = verify_external_runtime_identity(
                    Path(identity_file.name), receipt_path
                )
        # Preserve the public API's fail-closed preflight for callers holding
        # an in-memory state snapshot, while the transaction repeats these
        # checks against the authoritative on-disk state immediately before
        # CAS.  The pause contract itself remains owned by target_rebind.
        snapshot_metadata = dict(getattr(state, "metadata", {}) or {})
        snapshot_binding = snapshot_metadata.get("execution_binding")
        snapshot_binding = snapshot_binding if isinstance(snapshot_binding, Mapping) else {}
        snapshot_runtime = snapshot_binding.get("runtime_binding")
        snapshot_runtime = snapshot_runtime if isinstance(snapshot_runtime, Mapping) else {}
        if not isinstance(snapshot_runtime.get("current_identity"), Mapping):
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime rebind refused: persisted runtime identity is missing",
            )
        snapshot_plan = str(getattr(state, "current_plan_name", "") or "").strip()
        if not snapshot_plan:
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime rebind refused: optional-policy replacement requires a current plan",
            )
        from arnold_pipelines.megaplan._core.io import find_plan_dir
        from arnold_pipelines.megaplan.chain.target_rebind import _assert_pause
        snapshot_plan_dir = find_plan_dir(_project_root(spec_path), snapshot_plan)
        if snapshot_plan_dir is None or not (snapshot_plan_dir / "state.json").is_file():
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime rebind refused: canonical paused plan state is missing",
            )
        try:
            snapshot_plan_state = json.loads(
                (snapshot_plan_dir / "state.json").read_text(encoding="utf-8")
            )
            _assert_pause(state.to_dict(), snapshot_plan_state, expected_plan=snapshot_plan)
        except CliError as exc:
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime rebind refused: " + exc.message,
            ) from exc
        return _rebind_optional_runtime_identity_transaction(
            spec_path,
            state,
            expected_previous_runtime_sha256=expected_previous_runtime_sha256,
            expected_active_runtime_sha256=expected_active_runtime_sha256,
            expected_current_milestone=expected_current_milestone,
            expected_current_plan=expected_current_plan,
            reason=reason,
            actor=actor,
            direction=direction,
            verified_external_runtime_identity=verified_external_runtime_identity,
            verified_external_runtime_receipt=verified_external_runtime_receipt,
            expected_chain_spec_sha256=expected_chain_spec_sha256,
            released_hold_receipt=released_hold_receipt,
            attested_hold_context_receipt=attested_hold_context_receipt,
        )

    policy = binding_policy(spec_path)
    optional_policy = policy["mode"] == "optional"
    if allow_optional_policy and not optional_policy:
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "runtime rebind refused: --allow-optional-policy is only valid "
            "when driver.execution_binding is optional",
        )
    if allow_optional_policy:
        if not expected_chain_spec_sha256 or not _FULL_SHA256.fullmatch(
            str(expected_chain_spec_sha256)
        ):
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime rebind refused: --expected-chain-spec-sha256 is "
                "required with --allow-optional-policy",
            )
        observed_spec_sha256 = _sha256_file(spec_path)
        metadata_spec_sha256 = str(
            (getattr(state, "metadata", {}) or {}).get("chain_spec_sha256") or ""
        ).strip()
        if not (
            observed_spec_sha256 == str(expected_chain_spec_sha256)
            and metadata_spec_sha256 == str(expected_chain_spec_sha256)
        ):
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime rebind refused: chain spec SHA-256 does not match "
                "the supplied and persisted guard",
            )
    elif expected_chain_spec_sha256 is not None:
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "runtime rebind refused: --expected-chain-spec-sha256 requires "
            "--allow-optional-policy",
        )

    metadata = dict(getattr(state, "metadata", {}) or {})
    execution_binding = metadata.get("execution_binding")
    execution_binding = (
        execution_binding if isinstance(execution_binding, Mapping) else {}
    )
    persisted_runtime_binding = execution_binding.get("runtime_binding")
    persisted_runtime_binding = (
        persisted_runtime_binding
        if isinstance(persisted_runtime_binding, Mapping)
        else {}
    )
    persisted_identity = persisted_runtime_binding.get("current_identity")
    if not isinstance(persisted_identity, Mapping):
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "runtime rebind refused: persisted runtime identity is missing",
        )
    persisted_previous_sha256 = _persisted_runtime_identity_sha256(
        persisted_identity
    )

    if allow_optional_policy:
        # Optional chains normally have no runtime authority.  Replacement is
        # deliberately narrower: an operator must first establish the same
        # durable pause authority used by the chain control surface, and the
        # caller must supply a freshly verified independent runtime receipt.
        current_plan = str(getattr(state, "current_plan_name", "") or "").strip()
        if not current_plan:
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime rebind refused: optional-policy replacement requires "
                "a current plan",
            )
        # target_rebind owns the pause contract. Reuse its validator so this
        # path cannot accept a weaker chain-only or forged pause shape.
        from arnold_pipelines.megaplan._core.io import find_plan_dir
        from arnold_pipelines.megaplan.chain.target_rebind import _assert_pause

        plan_dir = find_plan_dir(_project_root(spec_path), current_plan)
        if plan_dir is None or not (plan_dir / "state.json").is_file():
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime rebind refused: canonical paused plan state is missing",
            )
        try:
            plan_state = json.loads(
                (plan_dir / "state.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime rebind refused: canonical paused plan state is unreadable",
            ) from exc
        if not isinstance(plan_state, Mapping) or plan_state.get("name") not in {
            None,
            current_plan,
        }:
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime rebind refused: paused plan identity does not match",
            )
        try:
            _assert_pause(
                state.to_dict(),
                plan_state,
                expected_plan=current_plan,
            )
        except CliError as exc:
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime rebind refused: " + exc.message,
            ) from exc
        if not isinstance(verified_external_runtime_identity, Mapping):
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime rebind refused: optional-policy replacement requires "
                "an independently verified external runtime identity",
            )

    external_identity = (
        _normalized_runtime_identity(verified_external_runtime_identity)
        if isinstance(verified_external_runtime_identity, Mapping)
        else None
    )
    spec_report = execution_binding_report(spec_path, state)
    if external_identity is not None:
        externally_verified_active = dict(spec_report.get("active") or {})
        externally_verified_active["runtime"] = external_identity
        externally_verified_active["ready"] = True
        externally_verified_active["errors"] = []
        spec_report = execution_binding_report(
            spec_path,
            state,
            active_identity=externally_verified_active,
        )
    if (
        spec_report.get("status") not in {"match", "reconcile_required"}
        and not allow_optional_policy
    ):
        # T-0301 worktree-first waiver (grok consult 2026-08-17): a bound
        # chain whose ONLY active error is editable_runtime_import_root_mismatch
        # (leftover candidate .venv editable metadata on a genuinely
        # worktree-first runtime) must still be runtime-rebindable after an
        # engine advance. Without this the chain can never rebind its runtime
        # once the bundle is accepted.
        bound_match = _bound_import_root_covers_editable_metadata_mismatch(
            spec_report.get("expected") or {},
            spec_report.get("active") or {},
        )
        # A blocked plan with no live worker may auto-adopt the current
        # manifest head: the rebind IS the adoption, and nothing is
        # mid-flight to protect (blocked-plan auto-adopt, 5f34c4a202).
        if not bound_match and not _state_blocked_no_live_work(state):
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime rebind refused while the immutable spec binding is not accepted",
            )
    if allow_optional_policy and spec_report.get("status") not in {
        "not_required",
        "match",
    }:
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "runtime rebind refused: optional-policy replacement found "
            "non-runtime immutable execution-binding drift",
        )
    if external_identity is None:
        report = spec_report["runtime_binding"]
    else:
        external_active = dict(spec_report.get("active") or {})
        external_active["runtime"] = external_identity
        external_active["ready"] = True
        external_active["errors"] = []
        report = runtime_binding_report(
            spec_path,
            state,
            active_identity=external_active,
        )
    if not report.get("required") and not allow_optional_policy:
        raise CliError(
            RUNTIME_DRIFT_ERROR, "runtime rebind is not required by this chain"
        )
    if report.get("status") != "drift" and not allow_optional_policy:
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            f"runtime rebind refused: status is {report.get('status')!r}, not drift",
        )
    active = report.get("active") or {}
    if persisted_previous_sha256 != expected_previous_runtime_sha256:
        raise CliError(RUNTIME_DRIFT_ERROR, "previous runtime SHA-256 does not match")
    if active.get("content_sha256") != expected_active_runtime_sha256:
        raise CliError(RUNTIME_DRIFT_ERROR, "active runtime SHA-256 does not match")
    if report.get("active_errors"):
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            "active runtime is not launch-ready: "
            + ", ".join(str(item) for item in report["active_errors"]),
        )

    labels = _identity_labels(spec_report.get("expected") or {})
    if allow_optional_policy and not labels:
        labels = _identity_labels(spec_report.get("active") or {})
    if allow_optional_policy and not labels:
        labels = _legacy_optional_spec_labels(
            spec_path,
            spec_report=spec_report,
            state=state,
        )
    current_index = int(getattr(state, "current_milestone_index", -1))
    terminal_cursor = current_index == len(labels)
    if current_index < 0 or current_index > len(labels):
        raise CliError(
            RUNTIME_DRIFT_ERROR, "current milestone index is outside the bound sequence"
        )
    guarded_plan = "" if expected_current_plan == "@none" else expected_current_plan
    if terminal_cursor:
        if expected_current_milestone != "@terminal":
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "terminal runtime rebind requires the @terminal milestone guard",
            )
        if expected_current_plan != "@none":
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "terminal runtime rebind requires the @none plan guard",
            )
        if str(getattr(state, "current_plan_name", "") or ""):
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "terminal runtime rebind refused while a current plan remains",
            )
        if str(getattr(state, "last_state", "") or "") != "done":
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "terminal runtime rebind requires canonical last_state 'done'",
            )
        completed = list(getattr(state, "completed", []) or [])
        completed_labels = [
            str(record.get("label") or "")
            for record in completed
            if isinstance(record, Mapping)
        ]
        completed_statuses = [
            str(record.get("status") or "")
            for record in completed
            if isinstance(record, Mapping)
        ]
        if (
            len(completed) != len(labels)
            or len(completed_labels) != len(labels)
            or completed_labels != labels
            or completed_statuses != ["done"] * len(labels)
        ):
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "terminal runtime rebind requires the exact ordered milestone set "
                "with status 'done'",
            )
    else:
        if labels[current_index] != expected_current_milestone:
            raise CliError(
                RUNTIME_DRIFT_ERROR, "current milestone does not match the guard"
            )
        if str(getattr(state, "current_plan_name", "") or "") != guarded_plan:
            raise CliError(RUNTIME_DRIFT_ERROR, "current plan does not match the guard")
        if allow_optional_policy:
            completed_labels = _completed_labels(state)
            if (
                len(completed_labels) != current_index
                or labels[:current_index] != completed_labels
            ):
                raise CliError(
                    RUNTIME_DRIFT_ERROR,
                    "runtime rebind refused: completed milestone prefix does not "
                    "match the guarded cursor",
                )

    rebound_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    metadata = dict(getattr(state, "metadata", {}) or {})
    execution_environment = dict(metadata.get("execution_environment") or {})
    from_engine_root = ""
    to_engine_root = ""
    if update_engine_root:
        previous_root_text = str(
            persisted_identity.get("import_root") or ""
        ).strip()
        if not previous_root_text:
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime cutover refused: previous runtime identity has no import_root",
            )
        recorded_root_text = str(
            execution_environment.get("engine_root") or ""
        ).strip()
        if not recorded_root_text:
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime cutover refused: "
                "metadata.execution_environment.engine_root is missing",
            )
        if (
            Path(recorded_root_text).expanduser().resolve()
            != Path(previous_root_text).expanduser().resolve()
        ):
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime cutover refused: recorded engine root does not match "
                "the previous runtime root",
            )
        active_root_text = str(active.get("import_root") or "").strip()
        if not active_root_text:
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime cutover refused: active runtime identity has no import_root",
            )
        from_engine_root = str(Path(recorded_root_text).expanduser().resolve())
        to_engine_root = str(Path(active_root_text).expanduser().resolve())
    event_core = {
        "schema": RUNTIME_REBIND_SCHEMA,
        "rebound_at": rebound_at,
        "actor": actor,
        "reason": reason,
        "direction": direction,
        "from_runtime_sha256": expected_previous_runtime_sha256,
        "to_runtime_sha256": expected_active_runtime_sha256,
        "current_milestone_index": current_index,
        "current_milestone": expected_current_milestone,
        "current_plan": guarded_plan,
    }
    if allow_optional_policy:
        event_core["optional_policy_override"] = True
        event_core["chain_spec_sha256"] = str(expected_chain_spec_sha256)
    if update_engine_root:
        event_core["from_engine_root"] = from_engine_root
        event_core["to_engine_root"] = to_engine_root
    event = {
        **event_core,
        "content_sha256": _sha256_bytes(
            json.dumps(event_core, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ),
    }
    binding = dict(metadata.get("execution_binding") or {})
    runtime_binding = dict(binding.get("runtime_binding") or {})
    events = runtime_binding.get("rebind_events")
    events = list(events) if isinstance(events, list) else []
    events.append(event)
    runtime_binding.update(
        {
            "schema": RUNTIME_BINDING_SCHEMA,
            "current_identity": dict(active),
            "last_rebound_at": rebound_at,
            "rebind_events": events,
        }
    )
    binding["runtime_binding"] = runtime_binding
    metadata["execution_binding"] = binding
    if update_engine_root:
        execution_environment["engine_root"] = to_engine_root
        metadata["execution_environment"] = execution_environment
    state.metadata = metadata
    if external_identity is None:
        rebound_runtime = execution_binding_report(spec_path, state)["runtime_binding"]
    else:
        rebound_active = dict(spec_report.get("active") or {})
        rebound_active["runtime"] = external_identity
        rebound_active["ready"] = True
        rebound_active["errors"] = []
        rebound_runtime = runtime_binding_report(
            spec_path,
            state,
            active_identity=rebound_active,
        )
    if rebound_runtime["status"] != "match" and not allow_optional_policy:
        raise CliError(
            RUNTIME_DRIFT_ERROR, "rebound runtime did not verify as an exact match"
        )
    if update_engine_root:
        recorded = (
            (state.metadata.get("execution_environment") or {}).get(
                "engine_root"
            )
            or ""
        )
        if (
            not recorded
            or Path(str(recorded)).expanduser().resolve()
            != Path(to_engine_root).expanduser().resolve()
        ):
            raise CliError(
                RUNTIME_DRIFT_ERROR,
                "runtime cutover refused: recorded engine root did not follow "
                "the active runtime",
            )
    result = {
        "event": event,
        "runtime_binding": rebound_runtime,
        "verification_mode": (
            "external_interpreter_receipt"
            if external_identity is not None
            else "active_control_runtime"
        ),
    }
    if update_engine_root:
        result["engine_root_transition"] = {
            "from_engine_root": from_engine_root,
            "to_engine_root": to_engine_root,
        }
    return result


def cutover_runtime_identity(
    spec_path: Path,
    state: Any,
    *,
    expected_previous_runtime_sha256: str,
    expected_active_runtime_sha256: str,
    expected_current_milestone: str,
    expected_current_plan: str,
    reason: str,
    actor: str = "operator",
    direction: str = "cutover",
    verified_external_runtime_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Chain runtime cutover: rebind the runtime AND move engine_root atomically.

    T-0101c: like :func:`rebind_runtime_identity` but additionally moves
    ``metadata.execution_environment.engine_root`` old->new inside the same
    CAS-guarded transaction.  The recorded root must match the previous
    runtime identity's ``import_root`` (fail-closed, zero mutation otherwise),
    and the new root is derived from the adopted runtime identity's
    ``import_root`` — the root the relaunch preflight (``epic_chain.py``) will
    subsequently require.  Runs only on chains whose runtime binding already
    exists (post T-0101b migration); a missing persisted identity is refused.
    """

    return rebind_runtime_identity(
        spec_path,
        state,
        expected_previous_runtime_sha256=expected_previous_runtime_sha256,
        expected_active_runtime_sha256=expected_active_runtime_sha256,
        expected_current_milestone=expected_current_milestone,
        expected_current_plan=expected_current_plan,
        reason=reason,
        actor=actor,
        direction=direction,
        verified_external_runtime_identity=verified_external_runtime_identity,
        update_engine_root=True,
    )


def bound_chain_spec_candidates(root: Path, *, plan_name: str = "") -> list[Path]:
    """Return every bound canonical chain spec whose cursor owns a plan."""

    from arnold_pipelines.megaplan.chain.spec import load_chain_state

    matches: list[Path] = []
    for candidate in sorted(
        (root / ".megaplan" / "initiatives").glob("*/chain.yaml")
    ):
        try:
            state = load_chain_state(candidate, verify_execution_binding=False)
        except (CliError, OSError, ValueError):
            continue
        if plan_name and str(state.current_plan_name or "") != plan_name:
            continue
        binding = (state.metadata or {}).get("execution_binding")
        if isinstance(binding, Mapping):
            matches.append(candidate)
    return matches


def find_bound_chain_spec(root: Path, *, plan_name: str = "") -> Path | None:
    """Resolve the one canonical chain spec whose persisted cursor owns a plan."""

    matches = bound_chain_spec_candidates(root, plan_name=plan_name)
    return matches[0] if len(matches) == 1 else None


def require_bound_chain_spec(root: Path, *, plan_name: str = "") -> Path:
    """Fail closed unless exactly one canonical execution binding owns the plan."""

    matches = bound_chain_spec_candidates(root, plan_name=plan_name)
    if len(matches) != 1:
        status = "missing" if not matches else "ambiguous"
        raise CliError(
            "worker_launch_preflight_mismatch",
            f"Canonical worker runtime binding is {status} for plan "
            f"{plan_name or '<unspecified>'}: {len(matches)} candidates.",
            extra={
                "canonical_runtime_binding": {
                    "status": status,
                    "plan_name": plan_name,
                    "candidates": [str(path.resolve(strict=False)) for path in matches],
                }
            },
        )
    return matches[0]


def expected_worker_launch_values(
    spec_path: Path | None = None,
    *,
    root: Path | None = None,
    runtime_vector_available: bool = False,
) -> dict[str, Any]:
    """Extract expected worker launch parameters from the persisted binding.

    Returns expected runtime fields plus the canonical *require_full_vector*
    enforcement decision when a bound chain execution identity and a verified
    launch-seed vector are both available.  The editable-runtime identity is
    still checked when a launch seed is not configured; only the seed-derived
    module/interpreter/path vector is omitted.  Returns empty strings and
    ``False`` when no binding is available (e.g. plan-level dispatch without a
    chain spec).

    Model and configured-spec are runtime dispatch choices not stored in the
    binding, so their expected values are always returned empty.
    """
    empty: dict[str, Any] = {
        "expected_source_ref": "",
        "expected_installed_package_path": "",
        "expected_runtime_revision": "",
        "expected_root": "",
        "expected_runtime_vector_sha256": "",
        "expected_model": None,
        "expected_spec": "",
        "expected_chain_spec": "",
        "require_full_vector": False,
    }
    if spec_path is None or root is None:
        return empty
    required = runtime_binding_required(spec_path)
    try:
        from arnold_pipelines.megaplan.chain.spec import load_chain_state

        state = load_chain_state(spec_path, verify_execution_binding=False)
        if not required:
            return {
                **empty,
                "expected_chain_spec": str(spec_path.resolve(strict=False)),
            }
        binding = (state.metadata or {}).get("execution_binding") or {}
        identity = binding.get("launched_identity") or {}
        runtime_binding = binding.get("runtime_binding") or {}
        runtime = runtime_binding.get("current_identity") or identity.get("runtime")
    except (CliError, OSError, ValueError):
        return empty
    if not isinstance(identity, Mapping) or not isinstance(runtime, Mapping):
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            f"bound chain {spec_path} has no current runtime identity",
        )
    values = {
        "expected_source_ref": str(runtime.get("source_revision") or ""),
        "expected_installed_package_path": str(runtime.get("import_root") or ""),
        "expected_runtime_revision": str(runtime.get("source_revision") or ""),
        "expected_root": str(runtime.get("import_root") or ""),
        "expected_runtime_vector_sha256": "",
        "expected_model": None,
        "expected_spec": "",
        "expected_chain_spec": str(spec_path.resolve(strict=False)),
        # A content-addressed runtime vector exists only in a verified launch
        # seed.  Isolated cloud chains intentionally do not use the resident
        # supervisor seed, but their persisted root/revision/spec identity is
        # still strict.  Requiring a seed-only value here made every such chain
        # fail with expected=<required>, actual=<missing> before its first
        # worker dispatch.
        "require_full_vector": bool(runtime_vector_available),
    }
    missing = [
        field
        for field in (
            "expected_source_ref",
            "expected_installed_package_path",
            "expected_runtime_revision",
        )
        if not values[field]
    ]
    if missing:
        raise CliError(
            RUNTIME_DRIFT_ERROR,
            f"bound chain {spec_path} has incomplete worker runtime expectations: "
            + ", ".join(missing),
        )
    return values


# --- Adopt-existing-tree transaction (Gap 2) ---------------------------------
# Recovery fixers wrote milestone implementation out-of-band (commit 81def9a83,
# 5 modules, 18 test files).  The engine fail-closes on unclaimed code with no
# way to absorb it.  This transaction safely adopts an existing implementation
# tree into a chain-recognized baseline: it CAS-verifies the reconciled plan
# digest and the implementation commit/tree, records a provenance receipt, and
# resets the gate epoch so resume/finalize can run without the exhausted
# iteration counter blocking the milestone.

ADOPTION_RECEIPT_SCHEMA = "arnold.megaplan.existing_tree_adoption.v1"


def adopt_existing_tree_identity(
    spec_path: Path,
    state: Any,
    *,
    plan_name: str,
    plan_sha256: str,
    adopted_commit: str,
    adopted_tree_sha256: str,
    base_commit: str,
    write_set: Mapping[str, Any],
    expected_chain_state_sha256: str,
    expected_plan_state_sha256: str,
    reason: str,
    actor: str = "operator",
) -> dict[str, Any]:
    """Adopt an out-of-band implementation tree as the chain-recognized baseline.

    Safely absorbs recovery-written milestone code: verifies the committed tree
    and reconciled plan digest, records a content-addressed provenance receipt,
    and resets the gate epoch/iteration so the chain can resume past the
    exhausted critique cap.  Mirrors the CAS discipline of rebind_execution_identity.
    """
    import hashlib
    import json
    import subprocess

    args = {
        "plan_name": plan_name,
        "plan_sha256": plan_sha256,
        "adopted_commit": adopted_commit,
        "adopted_tree_sha256": adopted_tree_sha256,
        "base_commit": base_commit,
        "reason": reason,
    }
    if any(not str(v or "").strip() for v in args.values()):
        raise CliError(DRIFT_ERROR, "adopt-existing-tree refused: every guard is required")
    if not _FULL_SHA256.fullmatch(plan_sha256):
        raise CliError(DRIFT_ERROR, "adopt-existing-tree refused: plan SHA-256 is invalid")
    if not _FULL_SHA256.fullmatch(adopted_commit):
        raise CliError(DRIFT_ERROR, "adopt-existing-tree refused: adopted commit is invalid")
    if not _FULL_SHA256.fullmatch(adopted_tree_sha256):
        raise CliError(DRIFT_ERROR, "adopt-existing-tree refused: adopted tree SHA-256 is invalid")
    if not _FULL_SHA256.fullmatch(base_commit):
        raise CliError(DRIFT_ERROR, "adopt-existing-tree refused: base commit is invalid")

    project_dir = spec_path.resolve().parent.parent
    # 1. Verify the adopted commit exists, its tree matches, and base is an ancestor.
    try:
        tree = subprocess.run(
            ["git", "-C", str(project_dir), "rev-parse", f"{adopted_commit}^{{tree}}"],
            check=True, capture_output=True, text=True, timeout=10,
        ).stdout.strip()
    except Exception as exc:
        raise CliError(DRIFT_ERROR, f"adopt-existing-tree refused: adopted commit unusable: {exc}") from exc
    if tree != adopted_tree_sha256:
        raise CliError(
            DRIFT_ERROR,
            f"adopt-existing-tree refused: adopted commit tree {tree} != supplied {adopted_tree_sha256}",
        )
    ancestry = subprocess.run(
        ["git", "-C", str(project_dir), "merge-base", "--is-ancestor", base_commit, adopted_commit],
        check=False, capture_output=True, text=True, timeout=10,
    ).returncode
    if ancestry != 0:
        raise CliError(DRIFT_ERROR, "adopt-existing-tree refused: base commit is not an ancestor of adopted commit")

    # 2. CAS-verify chain + plan state digests against persisted values.
    report = execution_binding_report(spec_path, state)
    persisted_chain = _sha256_file(spec_path)
    if expected_chain_state_sha256 and persisted_chain != expected_chain_state_sha256:
        raise CliError(DRIFT_ERROR, "adopt-existing-tree refused: chain spec digest CAS failed")
    if report.get("status") not in {"drift", "reconcile_required", "required"}:
        # Drift is the normal precondition (chain spec moved off intended revision).
        pass

    # 3. Verify the reconciled plan digest against the active plan artifact.
    plan_dir = project_dir / ".megaplan" / "plans" / plan_name
    plan_artifact = plan_dir / "plan.md"
    if not plan_artifact.exists():
        plan_artifact = plan_dir / "plan_v5.md"
    if not plan_artifact.exists():
        raise CliError(DRIFT_ERROR, f"adopt-existing-tree refused: plan artifact for {plan_name} not found")
    actual_plan_hash = hashlib.sha256(plan_artifact.read_bytes()).hexdigest()
    if actual_plan_hash != plan_sha256:
        raise CliError(
            DRIFT_ERROR,
            f"adopt-existing-tree refused: plan digest mismatch (artifact {actual_plan_hash[:12]}, supplied {plan_sha256[:12]})",
        )

    # 4. Build the content-addressed receipt.
    receipt = {
        "schema": ADOPTION_RECEIPT_SCHEMA,
        "plan_name": plan_name,
        "plan_sha256": plan_sha256,
        "base_commit": base_commit,
        "adopted_commit": adopted_commit,
        "tree_sha256": adopted_tree_sha256,
        "write_set": dict(write_set or {}),
        "provenance": {
            "kind": "out_of_band_recovery",
            "actor": actor,
            "reason": reason,
        },
        "gate_epoch": {
            "epoch_id": "adopt-" + hashlib.sha256(
                (plan_name + "|" + adopted_commit).encode()
            ).hexdigest()[:16],
            "superseded_iteration": int(getattr(state, "iteration", 0) or 0),
            "starting_iteration": 1,
        },
    }
    receipt["content_sha256"] = hashlib.sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    # 5. Persist the receipt in the plan dir; reset the gate epoch + iteration.
    receipt_path = plan_dir / "adoption-receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2))
    try:
        state.iteration = 1
        state.latest_failure = None
        state.active_step = None
    except Exception:
        pass

    return {"receipt": receipt, "adopted_commit": adopted_commit, "tree_sha256": adopted_tree_sha256}


# --- Guarded legacy execution-binding migration (T-0101b) --------------------
# One-time operator migration for a durably-paused, progressed, UNBOUND chain.
# The legacy runtime is independently reverified via its provenance receipt,
# then the spec/state/plan hashes plus the cloud-session marker and the
# per-epic runtime manifest are CAS-guarded before a SINGLE atomic write that
# initializes ``metadata.execution_binding`` AND
# ``metadata.execution_environment.engine_root``.  Any guard mismatch or
# partial failure refuses with zero mutation (the plan/state files are never
# touched until every guard passes).

EXECUTION_BINDING_MIGRATE_ERROR = "chain_execution_binding_migrate_refused"
MIGRATE_EVENT_SCHEMA = "arnold.megaplan.chain_execution_binding_migrate.v1"


@contextmanager
def _migrate_transaction_lock(state_path: Path) -> Iterator[None]:
    """Exclusive advisory lock serializing migrate transactions on one chain."""

    lock_path = state_path.with_suffix(".execution-binding-migrate.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _chain_epic_slug(spec_path: Path) -> str:
    """Derive the per-epic manifest slug for a chain spec (cloud.cli parity).

    Mirrors ``cloud.cli._epic_slug_for_spec_path``: a canonical
    ``<initiative>/chain.yaml`` spec is keyed by its initiative directory
    name; anything else by its stem.
    """

    if spec_path.name == "chain.yaml" and spec_path.parent.name:
        source = spec_path.parent.name
    else:
        source = spec_path.stem
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(source).strip().lower()).strip(".-")
    return slug[:48] or "chain"


def _assert_marker_agrees_with_runtime(
    marker: Mapping[str, Any],
    *,
    session: str,
    spec_path: Path,
    guarded_plan: str,
    external: Mapping[str, Any],
    old_root: Path,
    expected_marker_sha256: str | None = None,
    marker_sha256: str = "",
) -> None:
    """CAS the cloud-session marker against the verified legacy runtime.

    The marker must name this chain/session and must agree that the verified
    legacy runtime is the current content-addressed runtime — either through a
    ``runtime_binding.current_identity`` digest, the legacy
    ``editable_source_head`` / ``editable_install_sync.source`` fields, or the
    EXACT paused identity-less form (T-0101h round-3): no runtime identity
    fields at all, accepted only when the marker's exact sha256 is expected
    (``expected_marker_sha256``) and its relaunch command names a
    ``/workspace/runtime-candidates``-style root equal to the verified legacy
    runtime root. Multiple recognized forms may be present, but every present
    form must independently agree with the same runtime/source/install
    authority; any malformed or mismatching form refuses with zero mutation.
    """

    marker_session = str(marker.get("session") or "").strip()
    if marker_session and marker_session != session:
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            f"marker session {marker_session!r} does not match chain session "
            f"{session!r}",
        )
    marker_spec = str(marker.get("remote_spec") or "").strip()
    if marker_spec and (
        Path(marker_spec).expanduser().resolve(strict=False)
        != spec_path.resolve(strict=False)
    ):
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            "marker remote_spec does not match the migrated chain spec",
        )
    marker_pause = marker.get("operator_pause")
    if isinstance(marker_pause, Mapping) and "active" in marker_pause:
        if marker_pause.get("active") is not True:
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "marker operator_pause is not active",
            )
        recorded_plan = str(marker_pause.get("plan") or "").strip()
        if recorded_plan and recorded_plan != guarded_plan:
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "marker operator_pause plan does not match the current plan guard",
            )
    # Marker-SHA guard: when expected, the on-disk marker bytes must match
    # exactly (mandatory for the identity-less acceptance below).
    if expected_marker_sha256 is not None and (
        not _FULL_SHA256.fullmatch(expected_marker_sha256)
        or marker_sha256 != expected_marker_sha256
    ):
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            "marker SHA-256 does not match the guard",
        )
    # One or more accepted marker identity forms may be present, but every
    # present form must agree with the same verified runtime/source/install
    # authority. A marker carrying no runtime evidence is accepted only via
    # the explicit identity-less guards below (absence never agrees by itself).
    forms_found = 0
    if "runtime_binding" in marker and not isinstance(
        marker.get("runtime_binding"), Mapping
    ):
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            "marker runtime binding form is malformed",
        )
    binding = marker.get("runtime_binding")
    if isinstance(binding, Mapping):
        identity = binding.get("current_identity")
        if not isinstance(identity, Mapping):
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "marker runtime binding carries no current identity",
            )
        observed = _normalized_runtime_identity(identity)
        if observed.get("content_sha256") != external.get("content_sha256"):
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "marker runtime SHA-256 does not match the verified legacy runtime",
            )
        forms_found += 1
    head = str(marker.get("editable_source_head") or "").strip()
    if head:
        if head != str(external.get("source_revision") or ""):
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "marker source head does not match the verified legacy runtime",
            )
        forms_found += 1
    if "editable_install_sync" in marker and not isinstance(
        marker.get("editable_install_sync"), Mapping
    ):
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            "marker install-sync form is malformed",
        )
    sync = marker.get("editable_install_sync")
    if isinstance(sync, Mapping):
        source = str(sync.get("source") or "").strip()
        if source:
            if Path(source).expanduser().resolve(strict=False) != old_root:
                raise CliError(
                    EXECUTION_BINDING_MIGRATE_ERROR,
                    "marker install source does not match the verified legacy "
                    "runtime root",
                )
            forms_found += 1
    if forms_found == 0:
        # T-0101h round-3 blocker 1: the EXACT paused identity-less legacy
        # marker (no runtime_binding, no editable_source_head, no
        # editable_install_sync.source) is an accepted marker identity form
        # ONLY under the explicit marker-SHA + relaunch-root guards — the
        # strong runtime_binding is created by the FOLLOWING
        # legacy-marker migration, so migrate only VERIFIES that the marker
        # agrees with the verified legacy runtime (never binds it).
        if expected_marker_sha256 is None:
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "an exact marker SHA-256 guard is required for an identity-less "
                "marker",
            )
        relaunch = str(marker.get("relaunch_command") or "").strip()
        observed_roots = {
            str(Path(item).resolve(strict=False))
            for item in _LEGACY_RELAUNCH_ROOT.findall(relaunch)
        }
        if observed_roots != {str(old_root)}:
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "marker relaunch command does not name exactly the verified "
                "legacy runtime root",
            )
        forms_found = 1


def migrate_execution_binding(
    spec_path: Path,
    project_root: Path,
    *,
    expected_current_milestone: str,
    expected_current_plan: str,
    expected_branch: str,
    reason: str,
    actor: str = "operator",
    expected_marker_sha256: str | None = None,
    verified_external_runtime_identity: Mapping[str, Any],
) -> dict[str, Any]:
    """Initialize the execution binding for a paused, progressed, unbound chain.

    T-0101b: the one-time legacy migration.  The chain must be durably paused
    (``metadata.operator_pause`` present via :func:`pause_record`), progressed
    past launch, and still UNBOUND (no ``metadata.execution_binding``).  The
    migration IS the transition that creates the binding: it operates on the
    paused PRE-required (``driver.execution_binding: optional``) legacy spec —
    the old policy never demanded a binding, so requiring the new policy here
    would make the transition unrunnable on the very state it exists to move
    off.  Installing the full required bundle and ``chain rebind`` afterwards
    harden the chain.  The OLD runtime is independently reverified by the
    caller through :func:`verify_external_runtime_identity`; this transaction
    then CAS-guards the spec hash (against the hash the chain state recorded
    at last save), the chain-state and plan-state file bytes (stable across
    the transaction), the cloud-session marker (runtime agreement), the
    per-epic runtime manifest (``epic.runtime_root`` / ``epic.expected_head``
    / ``epic_id``), the cursor (milestone + plan), and the project checkout
    branch.

    On success a single atomic ``save_chain_state`` initializes
    ``metadata.execution_binding`` (schema, bound_at, launched_identity from
    the verified identity, runtime_binding with an empty rebind history) and
    ``metadata.execution_environment.engine_root`` = the verified runtime
    root.  Every non-metadata chain field is preserved; ANY guard mismatch
    refuses with zero mutation.

    When the marker is identity-less (no ``runtime_binding``, no
    ``editable_source_head``, no ``editable_install_sync.source``) it is
    accepted ONLY when ``expected_marker_sha256`` names the exact on-disk
    marker bytes and the marker's relaunch command names a
    ``/workspace/runtime-candidates``-style root equal to the verified legacy
    runtime root — the strong ``runtime_binding`` is then created by the
    FOLLOWING legacy-marker migration, so migrate only verifies agreement.
    """

    if not all(
        str(value or "").strip()
        for value in (
            expected_current_milestone,
            expected_current_plan,
            expected_branch,
            reason,
            actor,
        )
    ):
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            "every execution-binding-migrate guard is required",
        )
    if not isinstance(verified_external_runtime_identity, Mapping) or not bool(
        verified_external_runtime_identity
    ):
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            "a verified external runtime identity is required",
        )

    from arnold_pipelines.megaplan._core.io import find_plan_dir
    from arnold_pipelines.megaplan._core.state import driver_lock, plan_lock
    from arnold_pipelines.megaplan.chain import spec as chain_spec
    from arnold_pipelines.megaplan.chain.operator_pause import pause_record
    from arnold_pipelines.megaplan.cloud.runtime_manifest import (
        ManifestError,
        active_manifest_path,
        bootstrap_manifest,
    )

    spec_path = spec_path.resolve(strict=False)
    project_root = project_root.resolve(strict=False)
    try:
        spec_path.relative_to(project_root)
    except ValueError as exc:
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            "chain spec must be inside the guarded project/session root",
        ) from exc

    external = _normalized_runtime_identity(verified_external_runtime_identity)
    old_root_text = str(external.get("import_root") or "").strip()
    if not old_root_text:
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            "verified runtime identity has no import_root",
        )
    old_root = Path(old_root_text).expanduser().resolve()

    guarded_plan = "" if expected_current_plan == "@none" else expected_current_plan
    plan_dir = (
        find_plan_dir(project_root, guarded_plan) if guarded_plan else None
    )
    if guarded_plan and plan_dir is None:
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            "current plan directory is unavailable",
        )
    state_path = chain_spec._state_path_for(spec_path)
    if not state_path.exists():
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            f"chain state file is missing: {state_path}",
        )

    with _migrate_transaction_lock(state_path), (
        driver_lock(plan_dir) if plan_dir is not None else nullcontext()
    ), (plan_lock(plan_dir, step="chain execution-binding-migrate") if plan_dir is not None else nullcontext()):
        try:
            chain_raw = state_path.read_bytes()
        except OSError as exc:
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                f"cannot read chain state: {state_path}",
            ) from exc
        try:
            chain = json.loads(chain_raw)
        except json.JSONDecodeError as exc:
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "chain state is not valid JSON",
            ) from exc
        if not isinstance(chain, dict):
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "chain state must be a JSON object",
            )
        chain_state = chain_spec.ChainState.from_dict(chain)
        before = chain_state.to_dict()

        # ── spec hash CAS: the on-disk spec must be the one the chain state
        # recorded when it last saved progress (zero-mutation otherwise).
        metadata = dict(chain_state.metadata or {})
        recorded_spec_sha = str(metadata.get("chain_spec_sha256") or "").strip()
        observed_spec_sha = _sha256_file(spec_path)
        if (
            not _FULL_SHA256.fullmatch(recorded_spec_sha)
            or recorded_spec_sha != observed_spec_sha
        ):
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "chain spec SHA-256 does not match the hash the persisted chain "
                "state recorded at last save",
            )

        # ── durable pause ──────────────────────────────────────────────────
        pause = pause_record(chain_state)
        if pause is None:
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "migration refused: chain session is not durably paused",
            )
        paused_plan = str(pause.get("plan") or "").strip()
        if paused_plan and paused_plan != guarded_plan:
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "migration refused: pause authority names a different plan than "
                "the current plan guard",
            )

        # ── progressed + unbound ───────────────────────────────────────────
        if not _state_has_progress(chain_state):
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "migration refused: chain has not progressed",
            )
        if "execution_binding" in metadata:
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "migration refused: execution binding already exists",
            )
        execution_environment = metadata.get("execution_environment")
        if execution_environment is None:
            execution_environment = {}
        elif isinstance(execution_environment, Mapping):
            execution_environment = dict(execution_environment)
        else:
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "chain metadata.execution_environment is malformed",
            )
        recorded_root = str(
            execution_environment.get("engine_root") or ""
        ).strip()
        if recorded_root and (
            Path(recorded_root).expanduser().resolve() != old_root
        ):
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "migration refused: recorded engine root disagrees with the "
                "verified legacy runtime root",
            )

        # ── cursor: milestone + plan ───────────────────────────────────────
        active_identity = active_execution_identity(spec_path)
        labels = _identity_labels(active_identity)
        current_index = int(getattr(chain_state, "current_milestone_index", -1))
        terminal_cursor = current_index == len(labels)
        if current_index < 0 or current_index > len(labels):
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "current milestone index is outside the bound sequence",
            )
        if terminal_cursor:
            if expected_current_milestone != "@terminal":
                raise CliError(
                    EXECUTION_BINDING_MIGRATE_ERROR,
                    "terminal migration requires the @terminal milestone guard",
                )
            if expected_current_plan != "@none":
                raise CliError(
                    EXECUTION_BINDING_MIGRATE_ERROR,
                    "terminal migration requires the @none plan guard",
                )
            if str(getattr(chain_state, "current_plan_name", "") or ""):
                raise CliError(
                    EXECUTION_BINDING_MIGRATE_ERROR,
                    "terminal migration refused while a current plan remains",
                )
            if str(getattr(chain_state, "last_state", "") or "") != "done":
                raise CliError(
                    EXECUTION_BINDING_MIGRATE_ERROR,
                    "terminal migration requires canonical last_state 'done'",
                )
            completed = list(getattr(chain_state, "completed", []) or [])
            completed_labels = [
                str(record.get("label") or "")
                for record in completed
                if isinstance(record, Mapping)
            ]
            completed_statuses = [
                str(record.get("status") or "")
                for record in completed
                if isinstance(record, Mapping)
            ]
            if (
                len(completed) != len(labels)
                or len(completed_labels) != len(labels)
                or completed_labels != labels
                or completed_statuses != ["done"] * len(labels)
            ):
                raise CliError(
                    EXECUTION_BINDING_MIGRATE_ERROR,
                    "terminal migration requires the exact ordered milestone "
                    "set with status 'done'",
                )
        else:
            if labels[current_index] != expected_current_milestone:
                raise CliError(
                    EXECUTION_BINDING_MIGRATE_ERROR,
                    "current milestone does not match the guard",
                )
            if str(
                getattr(chain_state, "current_plan_name", "") or ""
            ) != guarded_plan:
                raise CliError(
                    EXECUTION_BINDING_MIGRATE_ERROR,
                    "current plan does not match the guard",
                )

        # ── plan state hash CAS (stable across the transaction) ────────────
        plan_raw: bytes | None = None
        if guarded_plan and plan_dir is not None:
            plan_path = plan_dir / "state.json"
            if not plan_path.exists():
                raise CliError(
                    EXECUTION_BINDING_MIGRATE_ERROR,
                    "current plan state file is missing",
                )
            try:
                plan_raw = plan_path.read_bytes()
            except OSError as exc:
                raise CliError(
                    EXECUTION_BINDING_MIGRATE_ERROR,
                    f"cannot read plan state: {plan_path}",
                ) from exc
            try:
                plan_payload = json.loads(plan_raw)
            except json.JSONDecodeError as exc:
                raise CliError(
                    EXECUTION_BINDING_MIGRATE_ERROR,
                    "plan state is not valid JSON",
                ) from exc
            if isinstance(plan_payload, dict) and plan_payload.get("name") not in {
                None,
                guarded_plan,
            }:
                raise CliError(
                    EXECUTION_BINDING_MIGRATE_ERROR,
                    "plan state name does not match the guard",
                )

        # ── branch guard: the project checkout's current git branch ────────
        current_branch = _git(project_root, "branch", "--show-current")
        if not current_branch or current_branch != expected_branch:
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "project checkout branch does not match the guard",
                extra={
                    "observed_branch": current_branch,
                    "expected_branch": expected_branch,
                },
            )

        # ── marker CAS ─────────────────────────────────────────────────────
        session = str(getattr(chain_state, "chain_session", "") or "").strip()
        if not session:
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "migration refused: chain session is unresolved",
            )
        # T-0101 live-run fix: the cloud-session marker lives in the canonical
        # workspace marker dir unless the managed launcher supplies an
        # operation-local ``ARNOLD_CHAIN_SESSION_MARKER_DIR``.  That explicit
        # root is authoritative: never fall through to a shared/global or
        # project-relative marker, which could attest the wrong operation.
        marker_path = None
        env_marker_dir = os.environ.get("ARNOLD_CHAIN_SESSION_MARKER_DIR", "")
        candidate_dirs = []
        if env_marker_dir.strip():
            candidate_dirs.append(Path(env_marker_dir.strip()).expanduser())
        else:
            candidate_dirs.append(Path("/workspace/.megaplan/cloud-sessions"))
            candidate_dirs.append(project_root / ".megaplan" / "cloud-sessions")
        for candidate_dir in candidate_dirs:
            probe = candidate_dir / (session + ".json")
            if probe.exists():
                marker_path = probe
                break
        if marker_path is None:
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                f"cloud-session marker is missing for session {session!r} "
                f"(searched {candidate_dirs})",
            )
        try:
            marker_raw = marker_path.read_bytes()
            marker = json.loads(marker_raw)
        except (OSError, json.JSONDecodeError) as exc:
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "cloud-session marker is unreadable or invalid JSON",
            ) from exc
        if not isinstance(marker, dict):
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "cloud-session marker must be a JSON object",
            )
        marker_sha256 = _sha256_bytes(marker_raw)
        _assert_marker_agrees_with_runtime(
            marker,
            session=session,
            spec_path=spec_path,
            guarded_plan=guarded_plan,
            external=external,
            old_root=old_root,
            expected_marker_sha256=expected_marker_sha256,
            marker_sha256=marker_sha256,
        )

        # ── per-epic manifest CAS (via the runtime_manifest reader) ────────
        try:
            manifest = bootstrap_manifest(active_manifest_path())
        except ManifestError as exc:
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                f"runtime manifest is unavailable: {exc}",
            ) from exc
        declared_root = str(manifest.epic.get("runtime_root") or "").strip()
        if not declared_root or (
            Path(declared_root).expanduser().resolve() != old_root
        ):
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "runtime manifest epic.runtime_root does not match the verified "
                "legacy runtime root",
            )
        declared_head = str(manifest.epic.get("expected_head") or "").strip()
        if declared_head != str(external.get("source_revision") or ""):
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "runtime manifest epic.expected_head does not match the verified "
                "legacy runtime revision",
            )
        if str(manifest.epic_id or "") != _chain_epic_slug(spec_path):
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                f"runtime manifest epic_id {manifest.epic_id!r} does not match "
                f"chain slug {_chain_epic_slug(spec_path)!r}",
            )

        # ── build the initialized binding (single atomic write) ────────────
        bound_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        launched = dict(active_identity)
        launched["runtime"] = dict(external)
        launched["ready"] = True
        launched["errors"] = []
        metadata["execution_binding"] = {
            "schema": BINDING_SCHEMA,
            "bound_at": bound_at,
            "launched_identity": launched,
            "runtime_binding": {
                "schema": RUNTIME_BINDING_SCHEMA,
                "bound_at": bound_at,
                "current_identity": dict(external),
                "rebind_events": [],
            },
        }
        execution_environment["engine_root"] = str(old_root)
        metadata["execution_environment"] = execution_environment
        chain_state.metadata = metadata

        # ── preserve every non-metadata field ──────────────────────────────
        after = chain_state.to_dict()
        for field in before:
            if field != "metadata" and before[field] != after[field]:
                raise CliError(
                    EXECUTION_BINDING_MIGRATE_ERROR,
                    f"migration refused: operational field {field!r} changed",
                )

        # ── file-byte CAS: nothing may have changed since the guard read ───
        try:
            if state_path.read_bytes() != chain_raw:
                raise CliError(
                    EXECUTION_BINDING_MIGRATE_ERROR,
                    "chain state changed during migration",
                )
            if (
                guarded_plan
                and plan_dir is not None
                and (plan_dir / "state.json").read_bytes() != plan_raw
            ):
                raise CliError(
                    EXECUTION_BINDING_MIGRATE_ERROR,
                    "plan state changed during migration",
                )
        except OSError as exc:
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                f"migration CAS re-read failed: {exc}",
            ) from exc

        chain_spec.save_chain_state(spec_path, chain_state)

    # ── post-condition: the initialized binding must be internally exact ──
    migrated_report = execution_binding_report(spec_path, chain_state)
    external_active = dict(migrated_report.get("active") or {})
    external_active["runtime"] = dict(external)
    external_active["ready"] = True
    external_active["errors"] = []
    runtime_report = runtime_binding_report(
        spec_path,
        chain_state,
        active_identity=external_active,
    )
    if runtime_report["status"] not in {"match", "not_required"}:
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            "migrated runtime binding did not verify as an exact match",
        )
    if (runtime_report.get("expected") or {}).get("content_sha256") != (
        runtime_report.get("active") or {}
    ).get("content_sha256"):
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            "migrated runtime binding expected/active identities diverged",
        )
    recorded = (
        (chain_state.metadata.get("execution_environment") or {}).get(
            "engine_root"
        )
        or ""
    )
    if not recorded or Path(str(recorded)).expanduser().resolve() != old_root:
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            "migrated engine_root does not match the verified legacy runtime root",
        )
    return {
        "schema": MIGRATE_EVENT_SCHEMA,
        "migrated_at": bound_at,
        "actor": actor,
        "reason": reason,
        "expected_current_milestone": expected_current_milestone,
        "expected_current_plan": guarded_plan,
        "expected_branch": expected_branch,
        "old_runtime_sha256": external["content_sha256"],
        "old_runtime_root": str(old_root),
        "engine_root": str(old_root),
        "verification_mode": "external_interpreter_receipt",
        "execution_binding": migrated_report,
        "runtime_binding": runtime_report,
    }


def promote_legacy_runtime_binding(
    spec_path: Path,
    project_root: Path,
    *,
    expected_current_milestone: str,
    expected_current_plan: str,
    expected_branch: str,
    expected_chain_spec_sha256: str,
    expected_state_digest: str,
    expected_state_revision: int,
    expected_marker_sha256: str,
    expected_manifest_sha256: str,
    reason: str,
    actor: str = "operator",
    verified_external_runtime_identity: Mapping[str, Any],
    verified_external_runtime_receipt: str | Path,
    released_hold_receipt: str | Path | None = None,
) -> dict[str, Any]:
    """Promote a legacy runtime-only binding through the NBF08 ledger.

    This is deliberately separate from the historical unbound migration
    above.  A chain that already has ``runtime_binding.current_identity`` is
    an NBF08-bound chain, so its metadata upgrade must use the canonical
    chain-control transaction rather than the legacy ``save_chain_state``
    path.  Only the binding metadata (and the CAS revision) may change.
    """

    from arnold_pipelines.megaplan._core.io import find_plan_dir
    from arnold_pipelines.megaplan.chain.spec import ChainState, _state_path_for, load_chain_state
    from arnold_pipelines.megaplan.chain.target_rebind import _assert_pause
    from arnold_pipelines.megaplan.cloud.operator_control import (
        marker_runtime_cutover_lock,
    )
    from arnold_pipelines.megaplan.cloud.runtime_attestation import (
        CLOUD_SESSION_MARKER_DIR_DEFAULT,
    )
    from arnold_pipelines.megaplan.cloud.runtime_manifest import (
        ManifestError,
        active_manifest_path,
        bootstrap_manifest,
        manifest_promotion_lock,
        manifest_write_lock,
    )
    from arnold_pipelines.megaplan.incident.chain_control import (
        ChainControlCasConflict,
        ChainControlHold,
        ChainStateAdapter,
        _stable_id,
        apply_chain_lifecycle,
        chain_id_for_spec,
        journal_for,
        state_digest_for,
    )

    spec_path = spec_path.resolve(strict=False)
    project_root = project_root.resolve(strict=False)
    if binding_policy(spec_path)["mode"] != "optional":
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            "legacy runtime-only promotion requires optional execution-binding policy",
        )
    for value, label in (
        (expected_chain_spec_sha256, "chain spec SHA-256"),
        (expected_state_digest, "state digest"),
        (expected_marker_sha256, "marker SHA-256"),
        (expected_manifest_sha256, "manifest SHA-256"),
    ):
        if not _FULL_SHA256.fullmatch(str(value or "")):
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                f"promotion requires a valid {label} guard",
            )
    if isinstance(expected_state_revision, bool) or not isinstance(expected_state_revision, int):
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            "promotion requires an integer state revision guard",
        )
    if not all(
        str(value or "").strip()
        for value in (
            expected_current_milestone,
            expected_current_plan,
            expected_branch,
            reason,
            actor,
        )
    ):
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            "every legacy runtime promotion guard is required",
        )
    if not isinstance(verified_external_runtime_identity, Mapping):
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            "legacy runtime promotion requires an external runtime identity",
        )
    receipt_path = Path(str(verified_external_runtime_receipt)).expanduser().resolve(strict=False)
    if not receipt_path.is_file():
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            "legacy runtime promotion requires a runtime provenance receipt",
        )
    # Always reverify at this public API boundary.  A caller-provided mapping
    # is only an input; the independent interpreter receipt is the authority.
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".runtime-identity.json"
    ) as identity_file:
        json.dump(dict(verified_external_runtime_identity), identity_file)
        identity_file.flush()
        verified_external_runtime_identity = verify_external_runtime_identity(
            Path(identity_file.name), receipt_path
        )
    external = _normalized_runtime_identity(verified_external_runtime_identity)
    old_root_text = str(external.get("import_root") or "").strip()
    if not old_root_text:
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            "verified legacy runtime identity has no import_root",
        )
    old_root = Path(old_root_text).expanduser().resolve(strict=False)
    state_path = _state_path_for(spec_path)
    chain_id = chain_id_for_spec(spec_path)
    plan_dir = find_plan_dir(project_root, expected_current_plan)
    if plan_dir is None or not (plan_dir / "state.json").is_file():
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            "legacy runtime promotion requires the current plan state",
        )
    plan_state_path = plan_dir / "state.json"

    # ``apply_chain_lifecycle`` carries the numeric cursor in every intent,
    # claim, and terminal envelope.  Read it only to construct that immutable
    # transaction guard; the effect re-reads and validates the state under the
    # transaction lock immediately before the CAS write.
    try:
        initial_state = load_chain_state(spec_path, verify_execution_binding=False)
        expected_cursor = int(getattr(initial_state, "current_milestone_index", -1))
    except (OSError, ValueError, TypeError) as exc:
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            "legacy runtime promotion requires a readable numeric chain cursor",
        ) from exc
    if expected_cursor < 0:
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            "legacy runtime promotion requires a non-negative chain cursor",
        )

    marker_path: Path | None = None
    # Managed launches may bind an operation-local marker root.  Treat that
    # explicit authority as canonical for this operation; only unmanaged
    # legacy promotion uses the historical workspace root.
    _marker_dir_override = os.environ.get("ARNOLD_CHAIN_SESSION_MARKER_DIR", "").strip()
    canonical_marker_dir = (
        Path(_marker_dir_override).expanduser()
        if _marker_dir_override
        else CLOUD_SESSION_MARKER_DIR_DEFAULT
    )

    def _resolve_marker(session: str) -> Path:
        candidate = canonical_marker_dir / f"{session}.json"
        if candidate.exists():
            return candidate.resolve(strict=False)
        raise CliError(
            EXECUTION_BINDING_MIGRATE_ERROR,
            f"cloud-session marker is missing at canonical path for session {session!r}",
        )

    runtime_context = {
        "promotion": "legacy-runtime-only",
        "chain_spec_sha256": expected_chain_spec_sha256,
        "expected_state_digest": expected_state_digest,
        "expected_state_revision": expected_state_revision,
        "old_runtime_sha256": external.get("content_sha256"),
        "old_runtime_source_revision": external.get("source_revision"),
        "old_runtime_root": str(old_root),
        "current_milestone": expected_current_milestone,
        "current_plan": expected_current_plan,
        "expected_branch": expected_branch,
        "expected_marker_sha256": expected_marker_sha256,
        "expected_manifest_sha256": expected_manifest_sha256,
    }
    base_operation_id = _stable_id(
        "execution-binding-promote",
        chain_id,
        expected_chain_spec_sha256,
        str(external.get("content_sha256") or ""),
        expected_state_digest,
        str(expected_state_revision),
        expected_current_milestone,
        expected_current_plan,
        expected_branch,
        expected_marker_sha256,
        expected_manifest_sha256,
    )
    operation_id = base_operation_id
    released_reference: dict[str, Any] | None = None

    if released_hold_receipt is not None:
        release_path = Path(str(released_hold_receipt)).expanduser().resolve(strict=False)
        try:
            release_wrapper = json.loads(release_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "released-hold receipt is unreadable",
            ) from exc
        release_event = (
            release_wrapper.get("event")
            if isinstance(release_wrapper, Mapping)
            else None
        )
        release_event = release_event if isinstance(release_event, Mapping) else release_wrapper
        release_payload = (
            release_event.get("payload")
            if isinstance(release_event, Mapping)
            else None
        )
        release_schema = (
            release_wrapper.get("schema")
            if isinstance(release_wrapper, Mapping)
            else None
        )
        if (
            release_schema != "nbf08-chain-control-hold-release-v1"
            or not isinstance(release_event, Mapping)
            or release_event.get("event_kind") != "chain_control.hold_released"
            or not isinstance(release_payload, Mapping)
        ):
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "released-hold receipt is not a hold release",
            )
        release_event_hash = str(release_event.get("event_hash") or "")
        release_id = str(release_payload.get("release_operation_id") or "")
        recovery_epoch = str(release_payload.get("recovery_epoch") or "")
        target_operation_id = str(release_payload.get("target_operation_id") or "")
        held_event_hash = str(release_payload.get("held_event_hash") or "")
        if not all(
            _FULL_SHA256.fullmatch(value)
            for value in (
                release_event_hash,
                release_id,
                recovery_epoch,
                target_operation_id,
                held_event_hash,
            )
        ):
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "released-hold receipt lacks exact recovery identities",
            )
        if release_id != recovery_epoch:
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "released-hold receipt has conflicting recovery identities",
            )
        if (
            release_event.get("chain_id") != chain_id
            or release_event.get("operation_id") != target_operation_id
            or release_event.get("recovery_id") != recovery_epoch
            or release_payload.get("chain_id") != chain_id
            or release_payload.get("target_operation_id") != target_operation_id
            or release_payload.get("held_event_hash") != held_event_hash
            or release_payload.get("chain_spec_sha256") != expected_chain_spec_sha256
            or release_payload.get("state_digest") != expected_state_digest
            or release_payload.get("state_revision") != expected_state_revision
            or release_payload.get("cursor") != expected_cursor
            or release_payload.get("current_milestone") != expected_current_milestone
            or release_payload.get("current_plan") != expected_current_plan
        ):
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "released-hold receipt does not match the exact promotion request",
            )

        # Validate the receipt against the immutable journal before opening a
        # new lifecycle operation.  This keeps bad, stale, or second-use
        # recovery inputs state-neutral; the effect repeats these checks under
        # the transaction lock for the race-safe final authority decision.
        replay = journal_for(project_root).replay_strict()
        authoritative_release = next(
            (
                event
                for event in replay["accepted"]
                if event.get("event_kind") == "chain_control.hold_released"
                and event.get("event_hash") == release_event_hash
            ),
            None,
        )
        def _reject_release_chain(message: str) -> NoReturn:
            raise CliError(EXECUTION_BINDING_MIGRATE_ERROR, message)

        def _context_without_link(context: Mapping[str, Any]) -> dict[str, Any]:
            return {
                str(key): value
                for key, value in context.items()
                if key != "released_hold"
            }

        def _context_without_selector(context: Mapping[str, Any]) -> dict[str, Any]:
            return {
                key: value
                for key, value in _context_without_link(context).items()
                if key != "expected_manifest_sha256"
            }

        def _selector_correction_authorized(
            hold: Mapping[str, Any], current_context: Mapping[str, Any]
        ) -> bool:
            payload = hold.get("payload")
            if (
                not isinstance(payload, Mapping)
                or hold.get("failure_class") != EXECUTION_BINDING_MIGRATE_ERROR
                or payload.get("code") != EXECUTION_BINDING_MIGRATE_ERROR
            ):
                return False
            details = payload.get("details")
            structured_expected = structured_actual = ""
            if isinstance(details, Mapping) and details:
                structured_expected = str(details.get("expected_sha256") or "")
                structured_actual = str(details.get("actual_sha256") or "")
                if (
                    details.get("guard") != "manifest_selector"
                    or not _FULL_SHA256.fullmatch(structured_expected)
                    or not _FULL_SHA256.fullmatch(structured_actual)
                    or structured_expected == structured_actual
                ):
                    return False
            context = payload.get("legacy_runtime_promotion.v1")
            if not isinstance(context, Mapping):
                return False
            held_selector = str(context.get("expected_manifest_sha256") or "")
            current_selector = str(current_context.get("expected_manifest_sha256") or "")
            if structured_expected and (
                structured_expected != held_selector
                or structured_actual != current_selector
            ):
                return False
            # The live seq-781 hold predates structured guard details.  Its
            # typed hold/code plus the frozen expected selector and the
            # current CAS selector provide the same non-prose evidence.
            return (
                _FULL_SHA256.fullmatch(held_selector) is not None
                and _FULL_SHA256.fullmatch(current_selector) is not None
                and held_selector != current_selector
            )

        def _base_operation_id_for_context(context: Mapping[str, Any]) -> str:
            return _stable_id(
                "execution-binding-promote",
                chain_id,
                str(context.get("chain_spec_sha256") or ""),
                str(context.get("old_runtime_sha256") or ""),
                str(context.get("expected_state_digest") or ""),
                str(context.get("expected_state_revision")),
                str(context.get("current_milestone") or ""),
                str(context.get("current_plan") or ""),
                str(context.get("expected_branch") or ""),
                str(context.get("expected_marker_sha256") or ""),
                str(context.get("expected_manifest_sha256") or ""),
            )

        accepted = replay["accepted"]
        events_by_operation: dict[str, list[Mapping[str, Any]]] = {}
        for event in accepted:
            if event.get("chain_id") == chain_id and event.get("operation_id"):
                events_by_operation.setdefault(str(event["operation_id"]), []).append(event)

        # A recovery receipt may name the root promotion or the immediately
        # preceding linked retry.  Walk the immutable released-hold links all
        # the way back to the first promotion; never infer a predecessor from
        # ordering alone.
        chain: list[tuple[str, Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]] = []
        seen_operations: set[str] = set()
        walk_operation = target_operation_id
        walk_release_hash = release_event_hash
        walk_held_hash = held_event_hash
        while True:
            if walk_operation in seen_operations:
                _reject_release_chain("released-hold recovery chain contains a cycle")
            seen_operations.add(walk_operation)
            operation_events = events_by_operation.get(walk_operation, [])
            promotion_intents = [
                event
                for event in operation_events
                if event.get("event_kind") == "chain_control.intent"
                and (event.get("payload") or {}).get("intent_kind")
                == "execution-binding-promote"
            ]
            hold = next(
                (
                    event
                    for event in operation_events
                    if event.get("event_kind") == "chain_control.hold"
                    and event.get("event_hash") == walk_held_hash
                ),
                None,
            )
            release = next(
                (
                    event
                    for event in operation_events
                    if event.get("event_kind") == "chain_control.hold_released"
                    and event.get("event_hash") == walk_release_hash
                ),
                None,
            )
            if (
                len(promotion_intents) != 1
                or not isinstance(hold, Mapping)
                or not isinstance(release, Mapping)
                or not operation_events
                or operation_events[-1] != release
            ):
                _reject_release_chain(
                    "released-hold receipt does not target the exact prior promotion hold"
                )
            release_inner = release.get("payload")
            intent_payload = promotion_intents[0].get("payload")
            context = intent_payload.get("legacy_runtime_promotion.v1") if isinstance(intent_payload, Mapping) else None
            if not isinstance(release_inner, Mapping) or not isinstance(context, Mapping):
                _reject_release_chain("released-hold recovery chain evidence is incomplete")
            if (
                release.get("chain_id") != chain_id
                or release.get("operation_id") != walk_operation
                or release_inner.get("chain_id") != chain_id
                or release_inner.get("target_operation_id") != walk_operation
                or release_inner.get("held_event_hash") != walk_held_hash
                or release_inner.get("chain_spec_sha256") != expected_chain_spec_sha256
                or release_inner.get("state_digest") != expected_state_digest
                or release_inner.get("state_revision") != expected_state_revision
                or release_inner.get("cursor") != expected_cursor
                or release_inner.get("current_milestone") != expected_current_milestone
                or release_inner.get("current_plan") != expected_current_plan
            ):
                _reject_release_chain("released-hold recovery chain guard mismatch")
            chain.append((walk_operation, context, hold, release))
            linked = context.get("released_hold")
            if not isinstance(linked, Mapping):
                break
            predecessor = str(linked.get("target_operation_id") or "")
            predecessor_release_hash = str(linked.get("event_hash") or "")
            predecessor_held_hash = str(linked.get("held_event_hash") or "")
            if not all(
                _FULL_SHA256.fullmatch(value)
                for value in (predecessor, predecessor_release_hash, predecessor_held_hash)
            ):
                _reject_release_chain("released-hold recovery chain link is malformed")
            predecessor_release = next(
                (
                    event
                    for event in accepted
                    if event.get("event_kind") == "chain_control.hold_released"
                    and event.get("event_hash") == predecessor_release_hash
                ),
                None,
            )
            if (
                not isinstance(predecessor_release, Mapping)
                or predecessor_release.get("chain_id") != chain_id
                or predecessor_release.get("operation_id") != predecessor
                or (predecessor_release.get("recovery_id") or "")
                != str(linked.get("recovery_epoch") or "")
                or (predecessor_release.get("payload") or {}).get("target_operation_id")
                != predecessor
                or (predecessor_release.get("payload") or {}).get("held_event_hash")
                != predecessor_held_hash
                or (predecessor_release.get("payload") or {}).get("release_operation_id")
                != str(linked.get("release_operation_id") or "")
                or (predecessor_release.get("payload") or {}).get("recovery_epoch")
                != str(linked.get("recovery_epoch") or "")
            ):
                _reject_release_chain("released-hold recovery chain skips or forks a predecessor")
            walk_operation = predecessor
            walk_release_hash = predecessor_release_hash
            walk_held_hash = predecessor_held_hash

        # All generations retain the same promotion request identity.  The
        # only permitted correction is the current manifest selector, and it
        # must be authorized by the newest selector-specific release receipt.
        current_identity = _context_without_selector(runtime_context)
        for _operation, context, _hold, _release in chain:
            if _context_without_selector(context) != current_identity:
                _reject_release_chain("released-hold receipt does not match the exact promotion request")
        historical_selectors = {
            str(context.get("expected_manifest_sha256") or "")
            for _operation, context, _hold, _release in chain
        }
        for index, (operation, context, _hold, _release) in enumerate(chain):
            if index == len(chain) - 1:
                expected_operation = _base_operation_id_for_context(context)
            else:
                linked = context.get("released_hold")
                if not isinstance(linked, Mapping):
                    _reject_release_chain("released-hold recovery chain link is missing")
                expected_operation = _stable_id(
                    "execution-binding-promote-released-hold",
                    _base_operation_id_for_context(context),
                    str(linked.get("event_hash") or ""),
                    str(linked.get("recovery_epoch") or ""),
                    str(context.get("expected_state_revision")),
                )
            if operation != expected_operation:
                _reject_release_chain(
                    "released-hold recovery chain has a tampered promotion operation identity"
                )
        if len(historical_selectors) != 1:
            _reject_release_chain("released-hold recovery chain changes the manifest selector")
        current_selector = str(runtime_context.get("expected_manifest_sha256") or "")
        if current_selector not in historical_selectors and not _selector_correction_authorized(
            chain[0][2], runtime_context
        ):
            _reject_release_chain(
                "manifest selector correction requires a selector-specific released-hold receipt"
            )
        if not isinstance(authoritative_release, Mapping) or authoritative_release != release_event:
            _reject_release_chain("released-hold receipt does not match immutable journal evidence")

        def _recheck_release_chain(replay_state: Mapping[str, Any]) -> None:
            """Repeat the immutable chain checks while the lifecycle lock is held."""
            accepted_state = replay_state.get("accepted")
            if not isinstance(accepted_state, list):
                raise ChainControlHold(
                    EXECUTION_BINDING_MIGRATE_ERROR,
                    "released-hold recovery journal is malformed",
                )
            by_operation: dict[str, list[Mapping[str, Any]]] = {}
            for event in accepted_state:
                if event.get("chain_id") == chain_id and event.get("operation_id"):
                    by_operation.setdefault(str(event["operation_id"]), []).append(event)
            for index, (operation, context, hold, release) in enumerate(chain):
                current_events = by_operation.get(operation, [])
                current_hold = next(
                    (event for event in current_events if event.get("event_hash") == hold.get("event_hash")),
                    None,
                )
                current_release = next(
                    (event for event in current_events if event.get("event_hash") == release.get("event_hash")),
                    None,
                )
                if (
                    not isinstance(current_hold, Mapping)
                    or current_hold != hold
                    or not isinstance(current_release, Mapping)
                    or current_release != release
                    or not current_events
                    or current_events[-1] != current_release
                ):
                    raise ChainControlHold(
                        EXECUTION_BINDING_MIGRATE_ERROR,
                        "released-hold recovery is no longer authoritative",
                    )
                promotion_intents = [
                    event
                    for event in current_events
                    if event.get("event_kind") == "chain_control.intent"
                    and (event.get("payload") or {}).get("intent_kind")
                    == "execution-binding-promote"
                ]
                current_context = (
                    (promotion_intents[0].get("payload") or {}).get(
                        "legacy_runtime_promotion.v1"
                    )
                    if len(promotion_intents) == 1
                    else None
                )
                if current_context != context:
                    raise ChainControlHold(
                        EXECUTION_BINDING_MIGRATE_ERROR,
                        "released-hold recovery promotion identity changed",
                    )
                if index == len(chain) - 1:
                    expected_operation = _base_operation_id_for_context(context)
                else:
                    linked = context.get("released_hold")
                    expected_operation = (
                        _stable_id(
                            "execution-binding-promote-released-hold",
                            _base_operation_id_for_context(context),
                            str(linked.get("event_hash") or ""),
                            str(linked.get("recovery_epoch") or ""),
                            str(context.get("expected_state_revision")),
                        )
                        if isinstance(linked, Mapping)
                        else ""
                    )
                if operation != expected_operation:
                    raise ChainControlHold(
                        EXECUTION_BINDING_MIGRATE_ERROR,
                        "released-hold recovery promotion operation identity changed",
                    )
            historical_selectors = {
                str(context.get("expected_manifest_sha256") or "")
                for _operation, context, _hold, _release in chain
            }
            if (
                len(historical_selectors) != 1
                or str(runtime_context.get("expected_manifest_sha256") or "")
                not in historical_selectors
            ) and not _selector_correction_authorized(chain[0][2], runtime_context):
                raise ChainControlHold(
                    EXECUTION_BINDING_MIGRATE_ERROR,
                    "manifest selector correction is no longer authorized",
                )

        released_reference = {
            "path": str(release_path),
            "event_hash": release_event_hash,
            "release_operation_id": release_id,
            "recovery_epoch": recovery_epoch,
            "target_operation_id": target_operation_id,
            "held_event_hash": held_event_hash,
        }
        def _release_identity(value: Any) -> tuple[str, ...]:
            if not isinstance(value, Mapping):
                return ()
            return tuple(str(value.get(key) or "") for key in (
                "event_hash", "release_operation_id", "recovery_epoch",
                "target_operation_id", "held_event_hash",
            ))

        operation_id = _stable_id(
            "execution-binding-promote-released-hold",
            base_operation_id,
            release_event_hash,
            recovery_epoch,
            str(expected_state_revision),
        )
        prior_use = next(
            (
                event
                for event in replay["accepted"]
                if event.get("event_kind") == "chain_control.runtime_rebound"
                and isinstance((event.get("payload") or {}).get("effect"), Mapping)
                and _release_identity(
                    ((event.get("payload") or {}).get("effect") or {}).get(
                        "released_hold"
                    )
                ) == _release_identity(released_reference)
            ),
            None,
        )
        if prior_use is not None and prior_use.get("operation_id") != operation_id:
            raise CliError(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "released-hold recovery has already been consumed",
            )
        runtime_context = dict(runtime_context)
        runtime_context["released_hold"] = dict(released_reference)
    manifest_path = active_manifest_path().resolve(strict=False)

    def _effect(txn: Any) -> dict[str, Any]:
        if released_reference is not None:
            replay = txn.journal.replay_strict()
            _recheck_release_chain(replay)
            authoritative_release = next(
                (
                    event
                    for event in replay["accepted"]
                    if event.get("event_kind") == "chain_control.hold_released"
                    and event.get("event_hash") == released_reference["event_hash"]
                ),
                None,
            )
            target_events = [
                event
                for event in replay["accepted"]
                if event.get("chain_id") == chain_id
                and event.get("operation_id")
                == released_reference["target_operation_id"]
            ]
            if (
                not isinstance(authoritative_release, Mapping)
                or authoritative_release.get("chain_id") != chain_id
                or authoritative_release.get("event_kind")
                != "chain_control.hold_released"
                or authoritative_release.get("event_hash")
                != released_reference["event_hash"]
                or not target_events
                or target_events[-1].get("event_kind") != "chain_control.hold_released"
                or target_events[-1].get("event_hash") != released_reference["event_hash"]
            ):
                raise ChainControlHold(
                    EXECUTION_BINDING_MIGRATE_ERROR,
                    "released-hold recovery is no longer authoritative",
                )
            prior_use = next(
                (
                    event
                    for event in replay["accepted"]
                    if event.get("event_kind") == "chain_control.runtime_rebound"
                    and event.get("operation_id") != operation_id
                    and isinstance((event.get("payload") or {}).get("effect"), Mapping)
                    and _release_identity(
                        ((event.get("payload") or {}).get("effect") or {}).get(
                            "released_hold"
                        )
                    ) == _release_identity(released_reference)
                ),
                None,
            )
            if prior_use is not None:
                raise ChainControlHold(
                    EXECUTION_BINDING_MIGRATE_ERROR,
                    "released-hold recovery has already been consumed",
                )
        adapter = ChainStateAdapter(txn, state_path)
        raw_state = adapter.read_expected()
        if not isinstance(raw_state, Mapping):
            raise ChainControlHold(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "legacy runtime promotion requires persisted chain state",
            )
        raw_metadata = raw_state.get("metadata")
        metadata = dict(raw_metadata) if isinstance(raw_metadata, Mapping) else {}
        observed_revision = metadata.get("_nbf08_revision")
        if observed_revision != expected_state_revision:
            raise ChainControlCasConflict(
                "legacy runtime promotion state revision changed",
                details={"expected": expected_state_revision, "actual": observed_revision},
            )
        if state_digest_for(raw_state) != expected_state_digest:
            raise ChainControlCasConflict("legacy runtime promotion state digest changed")
        observed_spec_sha = _sha256_file(spec_path)
        persisted_spec_sha = str(metadata.get("chain_spec_sha256") or "").strip()
        if not (
            observed_spec_sha == expected_chain_spec_sha256
            and persisted_spec_sha == expected_chain_spec_sha256
        ):
            raise ChainControlHold(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "legacy runtime promotion chain spec SHA-256 CAS failed",
                details={
                    "expected": expected_chain_spec_sha256,
                    "on_disk": observed_spec_sha,
                    "persisted": persisted_spec_sha,
                },
            )

        current = ChainState.from_dict(dict(raw_state))
        binding = metadata.get("execution_binding")
        binding = dict(binding) if isinstance(binding, Mapping) else {}
        if isinstance(binding.get("launched_identity"), Mapping):
            raise ChainControlHold(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "legacy runtime promotion requires a runtime-only binding",
            )
        runtime_binding = binding.get("runtime_binding")
        runtime_binding = dict(runtime_binding) if isinstance(runtime_binding, Mapping) else {}
        persisted_identity = runtime_binding.get("current_identity")
        if not isinstance(persisted_identity, Mapping):
            raise ChainControlHold(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "legacy runtime promotion requires a persisted current runtime identity",
            )
        if _normalized_runtime_identity(persisted_identity) != external:
            raise ChainControlHold(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "persisted current runtime does not match the verified legacy runtime",
            )
        if not _looks_like_legacy_runtime_binding(persisted_identity):
            raise ChainControlHold(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "persisted runtime identity is not the legacy runtime-only shape",
            )

        labels = _identity_labels(active_execution_identity(spec_path))
        current_index = int(getattr(current, "current_milestone_index", -1))
        if current_index < 0 or current_index >= len(labels):
            raise ChainControlHold(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "legacy runtime promotion cursor is outside the canonical sequence",
            )
        if labels[current_index] != expected_current_milestone:
            raise ChainControlHold(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "legacy runtime promotion current milestone does not match the guard",
            )
        if str(getattr(current, "current_plan_name", "") or "") != expected_current_plan:
            raise ChainControlHold(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "legacy runtime promotion current plan does not match the guard",
            )
        completed = _completed_labels(current)
        if len(completed) != current_index or labels[:current_index] != completed:
            raise ChainControlHold(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "legacy runtime promotion completed prefix does not match the cursor",
            )
        try:
            plan_state = json.loads(plan_state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ChainControlHold(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "legacy runtime promotion plan state is unreadable",
            ) from exc
        if not isinstance(plan_state, Mapping):
            raise ChainControlHold(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "legacy runtime promotion plan state is malformed",
            )
        try:
            _assert_pause(raw_state, plan_state, expected_plan=expected_current_plan)
        except CliError as exc:
            raise ChainControlHold(
                EXECUTION_BINDING_MIGRATE_ERROR,
                str(exc),
            ) from exc

        nonlocal marker_path
        session = str(current.chain_session or "").strip()
        session_from_state = bool(session)
        if not session:
            # The legacy cloud marker is keyed by the canonical epic slug.
            # Do not consult environment or project-relative directories when
            # recovering a missing chain_session.
            session = _chain_epic_slug(spec_path)
        try:
            marker_path = _resolve_marker(session)
        except CliError as exc:
            raise ChainControlHold(exc.code, str(exc), details=dict(exc.extra)) from exc
        try:
            # Global order: chain sequence/scope/state locks, then the
            # runtime-manifest promotion lock, ordinary manifest writer lock,
            # and marker cutover lock.  This matches
            # ``advance_generation_at_path`` and keeps both canonical
            # manifest mutation paths serialized through the final CAS.
            with manifest_promotion_lock(manifest_path), manifest_write_lock(manifest_path):
                try:
                    manifest_raw = manifest_path.read_bytes()
                    manifest_sha = _sha256_bytes(manifest_raw)
                    if manifest_sha != expected_manifest_sha256:
                        raise ChainControlHold(
                            EXECUTION_BINDING_MIGRATE_ERROR,
                            "legacy runtime promotion manifest SHA-256 CAS failed",
                            details={
                                "guard": "manifest_selector",
                                "expected_sha256": expected_manifest_sha256,
                                "actual_sha256": manifest_sha,
                            },
                        )
                    manifest = bootstrap_manifest(manifest_path)
                except (OSError, ManifestError) as exc:
                    raise ChainControlHold(
                        EXECUTION_BINDING_MIGRATE_ERROR,
                        f"legacy runtime promotion manifest is unavailable: {exc}",
                    ) from exc
                with marker_runtime_cutover_lock(marker_path):
                    marker_raw = marker_path.read_bytes()
                    marker_sha = _sha256_bytes(marker_raw)
                    if marker_sha != expected_marker_sha256:
                        raise ChainControlHold(
                            EXECUTION_BINDING_MIGRATE_ERROR,
                            "legacy runtime promotion marker SHA-256 CAS failed",
                        )
                    marker = json.loads(marker_raw)
                    if not isinstance(marker, Mapping):
                        raise ChainControlHold(
                            EXECUTION_BINDING_MIGRATE_ERROR,
                            "legacy runtime promotion marker is malformed",
                        )
                    if not session_from_state:
                        marker_session = str(marker.get("session") or "").strip()
                        marker_slug = str(marker.get("chain_slug") or "").strip()
                        marker_workspace = str(marker.get("workspace") or "").strip()
                        marker_spec = str(marker.get("remote_spec") or "").strip()
                        if marker_session != session or (
                            marker_slug and marker_slug != _chain_epic_slug(spec_path)
                        ):
                            raise ChainControlHold(
                                EXECUTION_BINDING_MIGRATE_ERROR,
                                "legacy runtime promotion canonical marker session identity conflicts with the chain",
                            )
                        if (
                            not marker_workspace
                            or Path(marker_workspace).expanduser().resolve(strict=False) != project_root
                        ):
                            raise ChainControlHold(
                                EXECUTION_BINDING_MIGRATE_ERROR,
                                "legacy runtime promotion canonical marker workspace conflicts with the chain project",
                            )
                        if (
                            not marker_spec
                            or Path(marker_spec).expanduser().resolve(strict=False) != spec_path
                        ):
                            raise ChainControlHold(
                                EXECUTION_BINDING_MIGRATE_ERROR,
                                "legacy runtime promotion canonical marker spec conflicts with the chain spec",
                            )
                    _assert_marker_agrees_with_runtime(
                        marker,
                        session=session,
                        spec_path=spec_path,
                        guarded_plan=expected_current_plan,
                        external=external,
                        old_root=old_root,
                        expected_marker_sha256=expected_marker_sha256,
                        marker_sha256=marker_sha,
                    )

                    declared_root = str(manifest.epic.get("runtime_root") or "").strip()
                    declared_head = str(manifest.epic.get("expected_head") or "").strip()
                    if (
                        not declared_root
                        or Path(declared_root).expanduser().resolve(strict=False) != old_root
                        or declared_head != str(external.get("source_revision") or "")
                        or str(manifest.epic_id or "") != _chain_epic_slug(spec_path)
                    ):
                        raise ChainControlHold(
                            EXECUTION_BINDING_MIGRATE_ERROR,
                            "legacy runtime promotion manifest does not match the verified runtime",
                        )
                    current_branch = _git(project_root, "branch", "--show-current")
                    if current_branch != expected_branch:
                        raise ChainControlHold(
                            EXECUTION_BINDING_MIGRATE_ERROR,
                            "legacy runtime promotion checkout branch does not match the guard",
                        )

                    active = active_execution_identity(spec_path)
                    if active.get("chain_spec_sha256") != expected_chain_spec_sha256:
                        raise ChainControlHold(
                            EXECUTION_BINDING_MIGRATE_ERROR,
                            "legacy runtime promotion active identity has a different spec SHA-256",
                        )
                    active["runtime"] = dict(external)
                    active["ready"] = True
                    active["errors"] = []
                    old_engine_root = str((metadata.get("execution_environment") or {}).get("engine_root") or "").strip()
                    if old_engine_root and Path(old_engine_root).expanduser().resolve(strict=False) != old_root:
                        raise ChainControlHold(
                            EXECUTION_BINDING_MIGRATE_ERROR,
                            "legacy runtime promotion engine root does not match the verified runtime",
                        )
                    execution_environment = dict(metadata.get("execution_environment") or {})
                    execution_environment["engine_root"] = str(old_root)
                    binding["schema"] = BINDING_SCHEMA
                    binding.setdefault("bound_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
                    binding["launched_identity"] = active
                    binding["runtime_binding"] = runtime_binding
                    metadata["execution_binding"] = binding
                    metadata["execution_environment"] = execution_environment
                    promoted = ChainState.from_dict(dict(raw_state))
                    promoted.metadata = metadata
                    before_nonmetadata = {key: raw_state.get(key) for key in raw_state if key != "metadata"}
                    after_nonmetadata = {key: value for key, value in promoted.to_dict().items() if key != "metadata"}
                    if before_nonmetadata != after_nonmetadata:
                        raise ChainControlHold(
                            EXECUTION_BINDING_MIGRATE_ERROR,
                            "legacy runtime promotion changed an operational chain field",
                        )
                    written = adapter.cas_write(promoted.to_dict(), expected_revision=observed_revision)
                    return {
                        "pre_state_digest": state_digest_for(raw_state),
                        "post_state_digest": state_digest_for(written),
                        "actual_revision": (written.get("metadata") or {}).get("_nbf08_revision"),
                        "actual_cursor": written.get("current_milestone_index"),
                        "current_milestone": expected_current_milestone,
                        "current_plan": expected_current_plan,
                        "chain_spec_sha256": expected_chain_spec_sha256,
                        "expected_state_digest": expected_state_digest,
                        "expected_state_revision": expected_state_revision,
                        "runtime_identity": {"from": dict(external), "to": dict(external)},
                        "provenance_link": str(receipt_path),
                        "manifest_sha256": expected_manifest_sha256,
                        "marker_sha256": expected_marker_sha256,
                        "chain_session": session,
                        "marker_path": str(marker_path),
                        "execution_binding": active,
                        **(
                            {"released_hold": dict(released_reference)}
                            if released_reference is not None
                            else {}
                        ),
                    }
        except (BlockingIOError, TimeoutError) as exc:
            raise ChainControlHold(
                EXECUTION_BINDING_MIGRATE_ERROR,
                "legacy runtime promotion marker lock is contended",
            ) from exc

    def _safe_effect(txn: Any) -> dict[str, Any]:
        """Terminalize authority/read failures after the durable claim."""
        try:
            return _effect(txn)
        except ChainControlHold:
            raise
        except (CliError, OSError, ManifestError, RuntimeError, ValueError, TypeError) as exc:
            raise ChainControlHold(
                EXECUTION_BINDING_MIGRATE_ERROR,
                f"legacy runtime promotion authority evidence is unavailable: {exc}",
            ) from exc

    result = apply_chain_lifecycle(
        spec_path,
        project_root,
        intent_kind="execution-binding-promote",
        actor={"id": actor, "class": "operator"},
        operation_id=operation_id,
        expected_revision=expected_state_revision,
        expected_cursor=expected_cursor,
        linked_receipts=[
            str(receipt_path),
            *([released_reference["path"]] if released_reference is not None else []),
        ],
        effect=_safe_effect,
        state_paths=[plan_state_path],
        committed_event_kind="chain_control.runtime_rebound",
        intent_context={"legacy_runtime_promotion.v1": runtime_context},
    )
    if result.get("outcome") == "committed":
        effect = result.get("effect") or {}
        return {
            "outcome": "committed",
            "receipt": result.get("result"),
            "event": result.get("event"),
            "promotion": effect,
        }
    if result.get("outcome") == "replay":
        return {
            "outcome": "replay",
            "receipt": result.get("result"),
            "event": result.get("result"),
            "replay_event": result.get("replay_event"),
        }
    error = result.get("error")
    if isinstance(error, ChainControlHold):
        raise CliError(error.code, str(error), extra=dict(error.details)) from error
    raise CliError(
        EXECUTION_BINDING_MIGRATE_ERROR,
        "legacy runtime promotion did not commit",
    )
