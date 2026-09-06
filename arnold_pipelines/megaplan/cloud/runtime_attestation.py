"""Content-addressed runtime launch seeds and process attestations."""

from __future__ import annotations

import argparse
from datetime import datetime
import fcntl
import hashlib
import importlib
import importlib.metadata
import json
import os
import re
import site
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import unquote, urlparse

from arnold_pipelines.megaplan._core import now_utc
from arnold_pipelines.megaplan.cloud.runtime_provenance import runtime_provenance
from arnold_pipelines.megaplan.cloud.relaunch_resolution import (
    relaunch_matches_runtime,
)
from arnold_pipelines.megaplan.types import CliError


RUNTIME_LAUNCH_SEED_SCHEMA = "arnold.megaplan.runtime_launch_seed.v1"
RUNTIME_LAUNCH_CLOUD_AUTHORITY = "arnold.megaplan.runtime-launch/cloud-chain/v1"
RUNTIME_LAUNCH_STANDALONE_AUTHORITY = "arnold.megaplan.runtime-launch/standalone-resident/v1"
RUNTIME_LAUNCH_AUTHORITIES = frozenset(
    {RUNTIME_LAUNCH_CLOUD_AUTHORITY, RUNTIME_LAUNCH_STANDALONE_AUTHORITY}
)
# Short aliases used by adapters and tests; the serialized values above are
# the compatibility contract.
CLOUD_CHAIN_AUTHORITY = RUNTIME_LAUNCH_CLOUD_AUTHORITY
STANDALONE_RESIDENT_AUTHORITY = RUNTIME_LAUNCH_STANDALONE_AUTHORITY
RUNTIME_PROCESS_ATTESTATION_SCHEMA = "arnold.megaplan.runtime_process_attestation.v1"
# Codex fix 2026-08-17: the mutable per-runtime seed slot is retired. Seeds
# are content-addressed per accepted generation and a separate atomic pointer
# (``dispatch-current.json``) selects the newest ready seed. Running workers
# retain the absolute immutable seed path they were dispatched with.
DISPATCH_POINTER_SCHEMA = "arnold.megaplan.runtime_dispatch_pointer.v1"
DISPATCH_CURRENT_FILENAME = "dispatch-current.json"
STANDALONE_DISPATCH_POINTER_SCHEMA = (
    "arnold.megaplan.standalone_runtime_dispatch_pointer.v1"
)
STANDALONE_ATTESTATION_RECEIPT_SCHEMA = (
    "arnold.megaplan.standalone_runtime_attestation_receipt.v1"
)
STANDALONE_RUNTIME_LAUNCH_RELATIVE = Path(".megaplan/resident/runtime-launch")
RUNTIME_ATTESTATION_ERROR = "runtime_launch_attestation_mismatch"
# Canonical box-side paths for the per-epic launch-seed build (G14): the
# supervisor prepare receipt, the box hot-env file, and the launch-seed store
# (mirrors ARNOLD_RUNTIME_MANIFEST_DIR, which defaults to /workspace/.megaplan).
SUPERVISOR_RECEIPT_DEFAULT_PATH = Path("/workspace/.megaplan/supervisor-python/last-prepare.json")
CLOUD_HOT_ENV_DEFAULT_PATH = Path("/workspace/.cloud-hot-env")
CLOUD_SESSION_MARKER_DIR_DEFAULT = Path("/workspace/.megaplan/cloud-sessions")
RUNTIME_SELECTOR_NAMES = (
    "MEGAPLAN_RUNTIME_SRC",
    "MEGAPLAN_LAUNCH_RUNTIME_SRC",
    "MEGAPLAN_SUPERVISOR_SOURCE",
    "CLOUD_WATCHDOG_ARNOLD_SRC",
    "MEGAPLAN_META_ARNOLD_SRC",
    "MEGAPLAN_AUDIT_ARNOLD_SRC",
    "MEGAPLAN_SUPERVISOR_PYTHON",
    # Retired selectors (T-0023/G5): kept on the deny-list so any
    # re-introduced read is flagged; production derives these from the
    # per-session manifest (ARNOLD_RUNTIME_MANIFEST -> epic.runtime_root).
    "KIMI_GOAL_ARNOLD_SRC",
    "MEGAPLAN_DISCORD_DM_ARNOLD_SRC",
    "MEGAPLAN_DISCOVER_ARNOLD_SRC",
)
_ARNOLD_MODULE_PREFIXES = ("arnold", "arnold_pipelines", "agentbox")
_SUPERVISOR_COMPONENTS = {
    "watchdog",
    "supervisor",
    "repair-loop",
    "meta-repair-loop",
    "progress-auditor",
}

# ``uv venv --seed`` (and virtualenv) installs one executable ``.pth`` file
# which imports its distutils compatibility bootstrap.  It is not owned by a
# distribution in a seeded environment, so treating every unowned executable
# ``.pth`` as hostile would reject an otherwise genuine uv/virtualenv runtime.
#
# This is deliberately a finite, byte-addressed exception.  The pth filename
# and bytes are exact, its adjacent module must be a regular non-symlink file,
# and the complete module must match a known generated bootstrap.  In
# particular, a syntax/AST check is not sufficient: the module is imported by
# Python before this process can attest the environment and an attacker could
# hide arbitrary code behind an apparently similar structure.  These hashes
# are the complete ``_virtualenv.py`` payloads emitted by the uv-bundled
# virtualenv used by the project and by virtualenv 21.2.x respectively.
_VIRTUALENV_PTH_FILENAME = "_virtualenv.pth"
# uv writes this exact 18-byte payload (without a trailing newline).
_VIRTUALENV_PTH_CONTENT = b"import _virtualenv"
_VIRTUALENV_BOOTSTRAP_FILENAME = "_virtualenv.py"
_VIRTUALENV_BOOTSTRAP_SHA256 = frozenset(
    {
        # uv 0.11.x bundled bootstrap (also present in the project .venv).
        "6cf30c56faf2a55228914dbbd17f8088ed371ebb08f5e7fa6fd931f913fcaf1d",
        # virtualenv 21.2.0 bootstrap.
        "e8c426ce260f866254ff35cefedc8b3efbd6d1446d99d7a4cdeb0095f98a8b8f",
    }
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    return _sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _file_identity(path: Path) -> dict[str, Any]:
    resolved = path.expanduser().resolve(strict=False)
    try:
        info = resolved.stat()
        data = resolved.read_bytes()
    except OSError:
        return {
            "path": str(resolved),
            "exists": False,
            "sha256": "",
            "size": 0,
            "mode": "",
        }
    return {
        "path": str(resolved),
        "exists": True,
        "sha256": _sha256_bytes(data),
        "size": len(data),
        "mode": stat.filemode(info.st_mode),
    }


def _json_file(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            f"{label} is unreadable or invalid JSON: {path}",
        ) from exc
    if not isinstance(value, dict):
        raise CliError(RUNTIME_ATTESTATION_ERROR, f"{label} must be a JSON object")
    return value


def _git_revision(root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def _git_branch(root: Path) -> str:
    """Return the current branch name, or empty string on failure."""
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--abbrev-ref", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def _git_ancestry(root: Path, ancestor: str, descendant: str) -> bool:
    """Return True if *ancestor* is reachable from *descendant* (i.e., descendant contains ancestor)."""
    if not ancestor or not descendant:
        return False
    result = subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", ancestor, descendant],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def _git_remote_origin(root: Path) -> str:
    """Return the origin remote URL, or empty string."""
    result = subprocess.run(
        ["git", "-C", str(root), "remote", "get-url", "origin"],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def _collect_revision_components(root: Path) -> dict[str, Any]:
    """Collect complete revision identity: branch, HEAD, ancestry base, and remote origin."""
    head = _git_revision(root)
    branch = _git_branch(root)
    remote = _git_remote_origin(root)
    return {
        "branch": branch,
        "head": head,
        "remote_origin": remote,
    }


def _module_vector(expected_root: Path) -> tuple[list[dict[str, str]], list[str]]:
    entries: list[dict[str, str]] = []
    errors: list[str] = []
    expected = expected_root.resolve(strict=False)
    for name, module in sorted(sys.modules.items()):
        if not any(
            name == prefix or name.startswith(prefix + ".")
            for prefix in _ARNOLD_MODULE_PREFIXES
        ):
            continue
        raw_file = getattr(module, "__file__", None)
        if not isinstance(raw_file, str) or not raw_file:
            continue
        path = Path(raw_file).resolve(strict=False)
        entry = {
            "module": name,
            "path": str(path),
            "root": str(expected) if path.is_relative_to(expected) else "",
        }
        entries.append(entry)
        if not path.is_relative_to(expected):
            errors.append(f"mixed_module_root:{name}")
    return entries, errors


def _supervisor_module_vector(
    expected_runtime: Path,
) -> tuple[list[dict[str, str]], list[str]]:
    """Return the fixed supervisor import contract, independent of CLI imports."""

    import arnold
    import arnold_pipelines
    import arnold_pipelines.megaplan

    runtime_attestation_module = importlib.import_module(
        "arnold_pipelines.megaplan.cloud.runtime_attestation"
    )
    modules = {
        "arnold": arnold,
        "arnold_pipelines": arnold_pipelines,
        "arnold_pipelines.megaplan": arnold_pipelines.megaplan,
        "arnold_pipelines.megaplan.cloud.runtime_attestation": runtime_attestation_module,
    }
    runtime = expected_runtime.resolve(strict=False)
    entries: list[dict[str, str]] = []
    errors: list[str] = []
    for name, module in sorted(modules.items()):
        path = Path(str(module.__file__)).resolve(strict=False)
        inside = path.is_relative_to(runtime)
        entries.append(
            {
                "module": name,
                "path": str(path),
                "root": str(runtime) if inside else "",
            }
        )
        if not inside:
            errors.append(f"mixed_module_root:{name}")
    return entries, errors


def _active_site_dirs() -> list[Path]:
    values: set[Path] = set()
    active_paths = {
        Path(item).expanduser().resolve(strict=False)
        for item in sys.path
        if isinstance(item, str) and item
    }
    candidates: list[str] = []
    try:
        candidates.extend(site.getsitepackages())
    except AttributeError:
        pass
    try:
        user_site = site.getusersitepackages()
        candidates.extend([user_site] if isinstance(user_site, str) else user_site)
    except AttributeError:
        pass
    candidates.extend(
        item
        for item in sys.path
        if isinstance(item, str)
        and ("site-packages" in item or "dist-packages" in item)
    )
    for item in candidates:
        path = Path(item).expanduser().resolve(strict=False)
        if path.is_dir() and path in active_paths:
            values.add(path)
    return sorted(values)


def _pth_owners(site_dir: Path) -> dict[Path, list[str]]:
    owners: dict[Path, list[str]] = {}
    for distribution in importlib.metadata.distributions(path=[str(site_dir)]):
        name = str(distribution.metadata.get("Name") or "unknown")
        for relative in distribution.files or ():
            if not str(relative).endswith(".pth"):
                continue
            path = Path(distribution.locate_file(relative)).resolve(strict=False)
            owners.setdefault(path, []).append(name)
    return owners


def _is_regular_non_symlink(path: Path) -> bool:
    """Return whether *path* is a regular file without following symlinks."""

    try:
        mode = path.lstat().st_mode
    except OSError:
        return False
    return stat.S_ISREG(mode) and not stat.S_ISLNK(mode)


def _is_trusted_virtualenv_bootstrap(path: Path) -> bool:
    """Recognize only the finite uv/virtualenv executable-pth exception.

    This helper intentionally authenticates bytes rather than accepting an
    arbitrary adjacent module.  ``Path.read_bytes`` follows symlinks, so the
    lstat checks are required before reading either file.
    """

    if path.name != _VIRTUALENV_PTH_FILENAME:
        return False
    if not _is_regular_non_symlink(path):
        return False
    bootstrap = path.with_name(_VIRTUALENV_BOOTSTRAP_FILENAME)
    if not _is_regular_non_symlink(bootstrap):
        return False
    try:
        if path.read_bytes() != _VIRTUALENV_PTH_CONTENT:
            return False
        return _sha256_file(bootstrap) in _VIRTUALENV_BOOTSTRAP_SHA256
    except OSError:
        return False


def _arnold_import_root() -> Path | None:
    """Root checkout of the ``arnold_pipelines`` package this interpreter imports.

    ``None`` when the package is not importable; callers then keep strict
    (fail-closed) classification.
    """
    try:
        import arnold_pipelines
    except ImportError:
        return None
    module_file = getattr(arnold_pipelines, "__file__", None)
    if not isinstance(module_file, str) or not module_file:
        return None
    return Path(module_file).resolve().parents[1]


def _pth_vector(expected_root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    expected = expected_root.resolve(strict=False)
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    import_root = _arnold_import_root()
    imports_shadowed = import_root is not None and import_root.is_relative_to(expected)
    for site_dir in _active_site_dirs():
        owners = _pth_owners(site_dir)
        for path in sorted(site_dir.glob("*.pth")):
            identity = _file_identity(path)
            try:
                raw_lines = path.read_text(encoding="utf-8").splitlines()
            except OSError:
                raw_lines = []
                errors.append(f"pth_unreadable:{path}")
            lines: list[dict[str, str]] = []
            for raw in raw_lines:
                value = raw.strip()
                if not value:
                    kind = "blank"
                    resolved = ""
                elif value.startswith("#"):
                    kind = "comment"
                    resolved = ""
                elif value.startswith(("import ", "import\t")):
                    kind = "executable"
                    resolved = ""
                else:
                    kind = "path"
                    candidate = Path(value).expanduser()
                    if not candidate.is_absolute():
                        candidate = site_dir / candidate
                    resolved = str(candidate.resolve(strict=False))
                    if (
                        imports_shadowed
                        and candidate != expected
                        and (
                            (candidate / "arnold").exists()
                            or (candidate / "arnold_pipelines").exists()
                        )
                    ):
                        # Import precedence already resolves arnold under the
                        # expected root, so a .pth entry naming a different
                        # checkout is shadowed inert evidence, never an error
                        # (mirrors runtime_provenance's shadowed-editable rule).
                        kind = "shadowed"
                lines.append({"kind": kind, "raw": raw, "resolved": resolved})
                if (
                    kind == "executable"
                    and not owners.get(path)
                    and not _is_trusted_virtualenv_bootstrap(path)
                ):
                    errors.append(f"unowned_executable_pth:{path}")
                if kind == "path" and resolved:
                    candidate = Path(resolved)
                    if candidate != expected and (
                        (candidate / "arnold").exists()
                        or (candidate / "arnold_pipelines").exists()
                    ):
                        errors.append(f"pth_mixed_arnold_root:{path}")
            records.append(
                {
                    **identity,
                    "site_dir": str(site_dir),
                    "owners": sorted(owners.get(path, [])),
                    "lines": lines,
                }
            )
    return records, errors


def _interpreter_vector(
    *,
    direct_url: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    executable = Path(sys.executable).resolve(strict=True)
    prefix = Path(sys.prefix).resolve(strict=True)
    base_prefix = Path(sys.base_prefix).resolve(strict=True)
    return {
        "executable": str(executable),
        "sha256": _sha256_file(executable),
        "prefix": str(prefix),
        "base_prefix": str(base_prefix),
        "venv": str(prefix) if prefix != base_prefix else "",
        "direct_url": dict(direct_url or {}),
    }


def _distribution_direct_url() -> dict[str, Any]:
    try:
        distribution = importlib.metadata.distribution("arnold")
        return json.loads(distribution.read_text("direct_url.json") or "{}")
    except (
        importlib.metadata.PackageNotFoundError,
        json.JSONDecodeError,
        OSError,
    ):
        return {}


def supervisor_runtime_vector(
    *,
    expected_source: Path,
    expected_revision: str,
    expected_runtime: Path,
    expected_fingerprint: str,
) -> dict[str, Any]:
    """Describe the dedicated, noneditable supervisor interpreter.

    This intentionally does not use :func:`runtime_provenance`: the launch,
    worker, and resident runtimes are editable checkouts, while the supervisor
    is an immutable wheel install in a separate venv.
    """

    source = expected_source.resolve(strict=False)
    runtime = expected_runtime.resolve(strict=False)
    direct_url = _distribution_direct_url()
    modules, module_errors = _supervisor_module_vector(runtime)
    pth, pth_errors = _pth_vector(runtime)
    errors = [*module_errors, *pth_errors]
    interpreter = _interpreter_vector(direct_url=direct_url)
    if Path(sys.prefix).resolve(strict=False) != runtime:
        errors.append("supervisor_runtime_prefix_mismatch")
    parsed = urlparse(str(direct_url.get("url") or ""))
    direct_source = (
        Path(unquote(parsed.path)).resolve(strict=False)
        if parsed.scheme == "file"
        else None
    )
    if direct_source != source:
        errors.append("supervisor_direct_url_source_mismatch")
    if bool((direct_url.get("dir_info") or {}).get("editable")):
        errors.append("supervisor_runtime_is_editable")
    if not modules:
        errors.append("supervisor_module_vector_empty")
    core = {
        "source": str(source),
        "source_revision": expected_revision,
        "source_fingerprint": expected_fingerprint,
        "runtime": str(runtime),
        "runtime_provenance": {
            "install_mode": "noneditable",
            "direct_url": direct_url,
        },
        "loaded_modules": modules,
        "interpreter": interpreter,
        "site_pth": pth,
        "errors": sorted(set(errors)),
        "ready": not errors,
    }
    return {**core, "content_sha256": _canonical_sha256(core)}


def _probe_supervisor_runtime(receipt: Mapping[str, Any]) -> dict[str, Any]:
    runtime = Path(str(receipt.get("runtime") or "")).resolve(strict=False)
    interpreter = runtime / "bin" / "python3"
    command = [
        str(interpreter),
        "-P",
        "-m",
        "arnold_pipelines.megaplan.cloud.runtime_attestation",
        "probe-supervisor",
        "--expected-source",
        str(receipt.get("source") or ""),
        "--expected-revision",
        str(receipt.get("source_revision") or ""),
        "--expected-runtime",
        str(runtime),
        "--expected-fingerprint",
        str(receipt.get("fingerprint") or ""),
    ]
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment["PYTHONSAFEPATH"] = "1"
    try:
        process = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
            env=environment,
        )
        payload = json.loads(process.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "could not inspect the dedicated supervisor runtime",
        ) from exc
    if process.returncode != 0 or not isinstance(payload, dict):
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "dedicated supervisor runtime is not release-ready: "
            + (process.stderr.strip() or str(payload.get("errors") or [])),
        )
    return payload


def _wrapper_vector(expected_root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    wrapper_dir = expected_root / "arnold_pipelines" / "megaplan" / "cloud" / "wrappers"
    wrappers = [
        _file_identity(path)
        for path in sorted(wrapper_dir.glob("arnold-*"))
        if path.is_file()
    ]
    return wrappers, ([] if wrappers else ["wrapper_manifest_empty"])


def _parse_hot_env(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    values: dict[str, str] = {}
    for line in lines:
        value = line.strip()
        if value.startswith("export ") and "=" in value:
            name, raw = value[7:].split("=", 1)
            if name in RUNTIME_SELECTOR_NAMES:
                values[name] = raw.strip().strip("'\"")
    return values


def _chain_binding_runtime_identity(spec_path: Path) -> dict[str, Any]:
    """Extract the immutable runtime identity from the live chain binding.

    The seed pins the RUNTIME (import_root/source_revision), not the mutable
    milestone/plan fields — those legitimately advance while a chain runs, so
    comparing the full binding would false-drift after the first plan is
    created after seed build.
    """
    return dict(_chain_binding(spec_path).get("runtime_identity") or {})


def _chain_binding(spec_path: Path) -> dict[str, Any]:
    from arnold_pipelines.megaplan.chain.spec import load_chain_state

    state = load_chain_state(spec_path, verify_execution_binding=False)
    execution = (state.metadata or {}).get("execution_binding")
    execution = execution if isinstance(execution, Mapping) else {}
    runtime = execution.get("runtime_binding")
    runtime = runtime if isinstance(runtime, Mapping) else {}
    current = runtime.get("current_identity")
    current = current if isinstance(current, Mapping) else {}
    core = {
        "spec_path": str(spec_path.resolve(strict=False)),
        "current_milestone_index": state.current_milestone_index,
        "current_plan_name": state.current_plan_name or "",
        "runtime_identity": dict(current),
    }
    return {**core, "content_sha256": _canonical_sha256(core)}


def _manifest(paths: Iterable[Path]) -> dict[str, Any]:
    entries = [_file_identity(path) for path in sorted(set(paths))]
    core = {"entries": entries}
    return {**core, "content_sha256": _canonical_sha256(core)}


def _manifest_matches(paths: Iterable[Path], stored: Mapping[str, Any]) -> bool:
    """True iff the live manifest over *paths* equals the stored entries for those paths.

    Shape-tolerant: a stored entry whose path is NOT in *paths* (a pre-fix
    ``chain_spec`` entry, now advisory) is ignored.  Only a real change to a
    still-blocking document (hot_env / supervisor_receipt / seed_docs) is drift.
    This is the seed schema-migration bridge: old seeds (built when chain_spec
    was pinned) validate against the post-drop validation shape, and a genuine
    hot_env / supervisor_receipt edit still trips the gate.
    """
    live_entries = _manifest(paths)["entries"]
    stored_entries = stored.get("entries")
    stored_entries = stored_entries if isinstance(stored_entries, list) else []
    stored_by_path = {
        str(entry.get("path")): entry
        for entry in stored_entries
        if isinstance(entry, Mapping)
    }
    return all(stored_by_path.get(entry["path"]) == entry for entry in live_entries)


def _marker_launch_binding(marker: Mapping[str, Any]) -> dict[str, Any]:
    """Return the immutable launch identity carried by a lifecycle marker.

    Session markers are live control-plane documents: pause/resume, launch
    outcomes, timestamps, and notification state all change during an ordinary
    launch.  A release seed therefore binds only the fields that select which
    runtime and durable chain may be launched.
    """

    runtime = marker.get("runtime_binding")
    runtime = runtime if isinstance(runtime, Mapping) else {}
    identity = runtime.get("current_identity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "session": str(marker.get("session") or ""),
        "workspace": str(marker.get("workspace") or ""),
        "remote_spec": str(marker.get("remote_spec") or ""),
        "identity_digest": str(marker.get("identity_digest") or ""),
        "run_kind": str(marker.get("run_kind") or ""),
        "relaunch_command": str(
            marker.get("relaunch_command") or marker.get("launch_command") or ""
        ),
        "editable_source_branch": str(marker.get("editable_source_branch") or ""),
        "editable_source_head": str(marker.get("editable_source_head") or ""),
        "runtime_identity": dict(identity),
    }


def build_runtime_launch_seed(
    *,
    expected_root: Path,
    expected_revision: str,
    supervisor_receipt_path: Path,
    hot_env_path: Path,
    marker_path: Path,
    chain_spec_path: Path,
    seed_doc_paths: Iterable[Path] = (),
    expected_branch: str | None = None,
    expected_ancestry_base: str | None = None,
    manifest_path: Path | None = None,
    chain_runtime_identity: Mapping[str, Any] | None = None,
    manifest_generation: int | None = None,
    manifest_sha256: str | None = None,
    dependency_generation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one strict release seed from current runtime and durable inputs.

    When *expected_branch* is provided, the current branch must match exactly.
    When *expected_ancestry_base* is provided, the current HEAD must descend
    from it (ancestry check).  Mixed-revision modules — where any loaded
    Arnold module originates from a different root — are always blocked.

    The supervisor receipt is attested INDEPENDENTLY of the per-epic runtime:
    the receipt's ``source`` / ``source_revision`` legitimately differ from
    *expected_root* / *expected_revision* (the supervisor wheel is prepared
    from its own consolidated source), so only the probe-ready state,
    fingerprint, import-receipt self-consistency, and runtime-prefix checks
    gate it.

    *manifest_path*, when provided, is the per-session runtime-manifest pin
    that SELECTS this runtime (G4); the six retired SRC selectors in hot-env
    are then recorded but not enforced.  *chain_runtime_identity*, when
    provided, is the freshly bound execution identity (already in memory by
    the time a chain start seeds the runtime); it replaces the persisted
    chain-state read, which is not yet saved on a first launch.
    """

    root = expected_root.resolve(strict=False)
    seed_doc_paths = tuple(seed_doc_paths)
    provenance = runtime_provenance(
        expected_root=root,
        expected_revision=expected_revision,
    )
    modules, module_errors = _module_vector(root)
    pth, pth_errors = _pth_vector(root)
    wrappers, wrapper_errors = _wrapper_vector(root)
    supervisor_receipt = _json_file(
        supervisor_receipt_path,
        label="supervisor receipt",
    )
    supervisor_vector = _probe_supervisor_runtime(supervisor_receipt)
    marker = _json_file(marker_path, label="cloud session marker")
    chain_binding = _chain_binding(chain_spec_path)
    hot_selectors = _parse_hot_env(hot_env_path)
    # ── Step 5A: collect revision components (branch, HEAD, origin) ────
    revision_components = _collect_revision_components(root)
    # The chain spec is a planning input already baked into plan state at
    # init; workers resolve the plan's RECORDED binding, not a live
    # chain.yaml read. Pinning its full content hash here made any
    # legitimate spec edit (e.g. profile switch) hard-block every launch
    # with "seed document manifest drifted" until a seed rebuild. The chain
    # runtime BINDING (chain_binding above) still enforces root/revision at
    # dispatch; the full-file chain-spec hash is advisory only.
    document_paths = {
        supervisor_receipt_path,
        hot_env_path,
        *seed_doc_paths,
    }
    seed_manifest = _manifest(document_paths)
    errors = [
        *list(provenance.get("errors") or []),
        *module_errors,
        *pth_errors,
        *wrapper_errors,
    ]
    for path in document_paths:
        if not _file_identity(path).get("exists"):
            errors.append(f"seed_document_missing:{path}")
    # Independent supervisor attestation: the receipt's source/revision need
    # NOT equal the per-epic worker root (the Jul-31 supervisor wheel is
    # prepared from its own consolidated source).  What IS required: the
    # receipt carries a fingerprint, the probe of the dedicated supervisor
    # runtime is ready (runtime prefix + noneditable direct-url source checks
    # live inside the probe vector), and the receipt's import list is
    # self-consistent with the probed loaded modules.
    if not str(supervisor_receipt.get("fingerprint") or ""):
        errors.append("supervisor_fingerprint_missing")
    if not supervisor_vector.get("ready"):
        errors.extend(
            f"supervisor:{item}" for item in supervisor_vector.get("errors") or []
        )
    receipt_imports = supervisor_receipt.get("imports")
    vector_imports = {
        str(item.get("module")): str(item.get("path"))
        for item in supervisor_vector.get("loaded_modules") or []
        if isinstance(item, Mapping)
        and str(item.get("module")) in {"arnold", "arnold_pipelines", "arnold_pipelines.megaplan"}
    }
    expected_imports = {
        "arnold": vector_imports.get("arnold", ""),
        "arnold_pipelines": vector_imports.get("arnold_pipelines", ""),
        "megaplan": vector_imports.get("arnold_pipelines.megaplan", ""),
    }
    if receipt_imports != expected_imports:
        errors.append("supervisor_import_receipt_mismatch")
    # The per-session runtime manifest is the runtime selector (G4); the six
    # retired SRC selectors in hot-env are inert documentation.  A manifest-
    # pinned build (production path) records them but does not enforce them;
    # the manifestless CLI build still fails closed on a selector that
    # disagrees with the expected root.
    if manifest_path is None:
        for name in RUNTIME_SELECTOR_NAMES[:6]:
            value = hot_selectors.get(name)
            if value and Path(value).resolve(strict=False) != root:
                errors.append(f"hot_env_selector_mismatch:{name}")
    marker_runtime = marker.get("runtime_binding")
    marker_runtime = marker_runtime if isinstance(marker_runtime, Mapping) else {}
    marker_identity = marker_runtime.get("current_identity")
    marker_identity = marker_identity if isinstance(marker_identity, Mapping) else {}
    if str(marker_identity.get("import_root") or "") != str(root):
        errors.append("marker_runtime_root_mismatch")
    if str(marker_identity.get("source_revision") or "") != expected_revision:
        errors.append("marker_runtime_revision_mismatch")
    if chain_runtime_identity is not None:
        chain_identity = dict(chain_runtime_identity)
        chain_binding_record = {
            **chain_binding,
            "runtime_identity": dict(chain_identity),
        }
        chain_binding_record["content_sha256"] = _canonical_sha256(
            {
                key: value
                for key, value in chain_binding_record.items()
                if key != "content_sha256"
            }
        )
    else:
        chain_identity = chain_binding.get("runtime_identity")
        chain_identity = chain_identity if isinstance(chain_identity, Mapping) else {}
        chain_binding_record = chain_binding
    if str(chain_identity.get("import_root") or "") != str(root):
        errors.append("chain_runtime_root_mismatch")
    if str(chain_identity.get("source_revision") or "") != expected_revision:
        errors.append("chain_runtime_revision_mismatch")
    # Compare marker vs chain by launch-relevant identity (grok consult,
    # d58701026410): root+rev. The DIGESTS agree across writers; diagnostic
    # shape (editable_root/pth/direct_url/imports populated vs null depending
    # on which writer stored the identity) legitimately differs and a
    # full-dict compare false-positives marker_chain_runtime_identity_mismatch
    # after every cutover.
    if (
        str(marker_identity.get("import_root") or "").rstrip("/")
        != str(chain_identity.get("import_root") or "").rstrip("/")
        or str(marker_identity.get("source_revision") or "")
        != str(chain_identity.get("source_revision") or "")
    ):
        errors.append("marker_chain_runtime_identity_mismatch")
    # ── Step 5A: branch binding ─────────────────────────────────────────
    if expected_branch is not None:
        current_branch = revision_components["branch"]
        if current_branch != expected_branch:
            errors.append(
                f"branch_mismatch:expected={expected_branch},actual={current_branch}"
            )
    # ── Step 5A: ancestry binding ───────────────────────────────────────
    if expected_ancestry_base is not None:
        current_head = revision_components["head"]
        if not _git_ancestry(root, expected_ancestry_base, current_head):
            errors.append(
                f"ancestry_mismatch:base={expected_ancestry_base},head={current_head}"
            )
    # ── Step 5A: mixed-revision blocking ────────────────────────────────
    for mod in modules:
        mod_root = mod.get("root", "")
        if mod_root and mod_root != str(root):
            errors.append(f"mixed_revision_module:{mod.get('module')}")
    # Occurrence 12f5e50e0107: a seed built by an interpreter other than the
    # bound dependency-generation interpreter used to record ready:true while
    # its embedded interpreter vector pointed elsewhere (the poisoned
    # dispatch-current.json generation-2 seed of 2026-08-26T20:16Z). The
    # builder IS the generation interpreter, or the seed is born not-ready.
    dep_generation_record = (
        dependency_generation if isinstance(dependency_generation, Mapping) else {}
    )
    if dep_generation_record:
        bound_interpreter = str(dep_generation_record.get("interpreter_path") or "")
        if (
            not bound_interpreter
            or os.path.realpath(bound_interpreter)
            != os.path.realpath(sys.executable)
        ):
            errors.append(
                "dependency_generation_builder_interpreter_mismatch:"
                f"builder={sys.executable},bound={bound_interpreter or '<unset>'}"
            )
    core = {
        "schema": RUNTIME_LAUNCH_SEED_SCHEMA,
        "authority": RUNTIME_LAUNCH_CLOUD_AUTHORITY,
        "expected_root": str(root),
        "expected_revision": expected_revision,
        # Codex fix 2026-08-17: the seed is bound to ONE accepted manifest
        # generation (immutable). These fields are the provenance of that
        # binding; dispatch never mutates them and validation never reads a
        # NEWER manifest to reinterpret them.
        "manifest_generation": manifest_generation,
        "manifest_sha256": manifest_sha256 or "",
        "dependency_generation": (
            dict(dependency_generation) if dependency_generation else {}
        ),
        "revision_components": revision_components,
        "expected_branch": expected_branch,
        "expected_ancestry_base": expected_ancestry_base,
        "runtime_provenance": provenance,
        "loaded_modules": modules,
        "interpreter": _interpreter_vector(
            direct_url=(
                provenance.get("direct_url")
                if isinstance(provenance.get("direct_url"), Mapping)
                else {}
            )
        ),
        "site_pth": pth,
        "wrappers": wrappers,
        "supervisor_receipt": {
            "file": _file_identity(supervisor_receipt_path),
            "fingerprint": supervisor_receipt.get("fingerprint"),
            "runtime": supervisor_receipt.get("runtime"),
            "source": supervisor_receipt.get("source"),
            "source_revision": supervisor_receipt.get("source_revision"),
            "imports": supervisor_receipt.get("imports"),
        },
        "supervisor_runtime": supervisor_vector,
        "hot_env": {
            "file": _file_identity(hot_env_path),
            "selectors": hot_selectors,
        },
        "marker": {
            "path": str(marker_path.resolve(strict=False)),
            "launch_binding": _marker_launch_binding(marker),
            "runtime_identity": dict(marker_identity),
        },
        "chain_runtime_binding": chain_binding_record,
        "seed_document_manifest": seed_manifest,
        "input_paths": {
            "supervisor_receipt": str(supervisor_receipt_path.resolve(strict=False)),
            "hot_env": str(hot_env_path.resolve(strict=False)),
            "marker": str(marker_path.resolve(strict=False)),
            "chain_spec": str(chain_spec_path.resolve(strict=False)),
            "manifest": (
                str(manifest_path.resolve(strict=False))
                if manifest_path is not None
                else ""
            ),
            "seed_docs": [
                str(path.resolve(strict=False)) for path in sorted(set(seed_doc_paths))
            ],
        },
        "errors": sorted(set(errors)),
        "ready": not errors,
    }
    return {**core, "content_sha256": _canonical_sha256(core)}


def _launch_seed_store_dir() -> Path:
    return (
        Path(os.environ.get("ARNOLD_RUNTIME_MANIFEST_DIR", "/workspace/.megaplan"))
        / "runtime-launch-seeds"
    )


def _live_runtime_identity(*, root: Path, expected_revision: str) -> dict[str, Any]:
    """Content-addressed identity of the live runtime at the pinned revision."""
    from arnold_pipelines.megaplan.cloud.runtime_provenance import (
        normalized_runtime_identity,
    )

    provenance = runtime_provenance(
        expected_root=root,
        expected_revision=expected_revision,
    )
    if not provenance.get("ok"):
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "live runtime does not satisfy the manifest pin: "
            + ", ".join(str(item) for item in provenance.get("errors") or []),
        )
    return normalized_runtime_identity(provenance)


def _regenerate_relaunch_command(
    command: str,
    *,
    old_revision: str,
    new_revision: str,
    expected_manifest_path: str | None = None,
    expected_interpreter_path: str | None = None,
) -> str:
    """Rewire a persisted relaunch command to the active runtime identity.

    A content-addressed marker relaunch must bind the runtime it restarts.
    When the manifest head advances on the SAME runtime root the only token
    that legitimately changes is the 40-hex revision pin — persisted as
    ``MEGAPLAN_BOUND_RUNTIME_REVISION=<rev>``, ``RUNTIME_REVISION=<rev>``,
    or a bare ``<rev>`` token.  The swap is word-boundary guarded so a
    revision that also appears as a prefix/suffix of another token is left
    untouched.

    When *expected_manifest_path* is given, a stale
    ``ARNOLD_RUNTIME_MANIFEST=<path>`` assignment is rebound to it as well
    (occurrence c2f73c7ddcef, 2026-08-28: the marker command kept selecting
    the creation-time gen-13 session copy after the gen-19 advance, so
    marker-only relaunches failed admission with ``source_revision_mismatch``).
    A command with no such assignment is returned unchanged in that
    dimension (fail-closed admission still validates the resulting bind).
    When the old revision is absent the revision swap is skipped and the
    caller fails closed (the CAS cutover still refuses a command that does
    not bind the active runtime).

    ``expected_interpreter_path`` repairs the other launch selector that can
    survive a same-root cutover: an explicit command may still invoke the
    previous dependency-generation Python even though its source revision and
    manifest selector are current.  The replacement is deliberately limited
    to the interpreter immediately preceding the canonical megaplan module,
    leaving unrelated command paths untouched.
    """
    if not command:
        return command
    if expected_manifest_path:
        expected = str(expected_manifest_path)
        match = re.search(r"(ARNOLD_RUNTIME_MANIFEST=)(\S+)", command)
        if match and match.group(2) != expected:
            command = (
                command[: match.start(2)]
                + expected
                + command[match.end(2) :]
            )
    if expected_interpreter_path:
        match = re.search(
            r"(?P<path>/[^\s\"';&|]+/bin/python(?:[0-9.]*)?)"
            r"(?=\s+-P\s+-m\s+arnold_pipelines\.megaplan(?:\s|$))",
            command,
        )
        if match:
            command = (
                command[: match.start("path")]
                + str(expected_interpreter_path)
                + command[match.end("path") :]
            )
    if not old_revision or not new_revision:
        return command
    if old_revision == new_revision or len(old_revision) != 40:
        return command
    return re.sub(
        rf"(?<![0-9a-f]){re.escape(old_revision)}(?![0-9a-f])",
        new_revision,
        command,
    )


def _rebind_marker_if_stale(
    marker_path: Path,
    marker: Mapping[str, Any],
    *,
    live_identity: Mapping[str, Any],
    source_branch: str,
    expected_manifest_path: str | None = None,
) -> None:
    """CAS-rebind the cloud-session marker when its runtime identity is stale.

    Uses the CAS-protected marker/runtime cutover helper (never hand-edited
    JSON): the marker file SHA-256 and the previous runtime identity SHA-256
    are both guarded, and any concurrent change fails the CAS with a typed
    error instead of being overwritten.
    """
    from arnold_pipelines.megaplan.cloud.runtime_cutover import (
        marker_runtime_identity,
        update_marker_runtime,
    )
    marker_identity = marker_runtime_identity(marker)
    if marker_identity is None:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "cloud session marker has no content-addressable runtime identity",
        )
    # Compare by launch-relevant identity (root+rev), not full dict (grok
    # consult, d58701026410): digest agrees across writers but diagnostic
    # shape (editable/pth/imports) legitimately differs; full-dict compare
    # would rebind every launch.
    same_runtime = (
        str(marker_identity.get("import_root") or "").rstrip("/")
        == str(live_identity.get("import_root") or "").rstrip("/")
        and str(marker_identity.get("source_revision") or "")
        == str(live_identity.get("source_revision") or "")
    )
    relaunch_command = str(
        marker.get("relaunch_command") or marker.get("launch_command") or ""
    ).strip()
    expected_interpreter_path = None
    if expected_manifest_path:
        try:
            from arnold_pipelines.megaplan.cloud.runtime_manifest import load_manifest

            manifest = load_manifest(Path(expected_manifest_path))
            dependency = manifest.epic.get("dependency_generation")
            if isinstance(dependency, Mapping):
                value = str(dependency.get("interpreter_path") or "").strip()
                if value:
                    expected_interpreter_path = value
        except Exception:
            # ensure_runtime_launch_seed has already validated the manifest;
            # this compatibility path is also exercised with synthetic marker
            # tests that intentionally provide a non-file manifest selector.
            expected_interpreter_path = None
    # A same-runtime marker can still carry a STALE LAUNCH SELECTOR: a
    # command that pins ARNOLD_RUNTIME_MANIFEST to the creation-time session
    # copy lags every manifest generation advance and fails admission on the
    # next marker-only relaunch (occurrence c2f73c7ddcef). When the expected
    # authoritative path is known, an equal root+rev marker with a stale
    # selector must still rebind — the early return below fires only when the
    # command binds the authoritative manifest (or none is expected).
    command_manifest_stale = False
    if expected_manifest_path and relaunch_command:
        match = re.search(r"ARNOLD_RUNTIME_MANIFEST=(\S+)", relaunch_command)
        command_manifest_stale = bool(
            match and match.group(1) != str(expected_manifest_path)
        )
    command_interpreter_stale = False
    if expected_interpreter_path and relaunch_command:
        command_interpreter_stale = not relaunch_matches_runtime(
            relaunch_command,
            live_identity,
            expected_interpreter_path=expected_interpreter_path,
        )
    if same_runtime and not command_manifest_stale and not command_interpreter_stale:
        return
    if not relaunch_command:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "cloud session marker drift requires a relaunch command for rebinding",
        )
    # The persisted command was authored for the marker's CURRENT runtime;
    # on a same-root revision advance it still names the OLD revision and
    # the CAS cutover would refuse it (runtime_marker_relaunch_mismatch).
    # Regenerate the revision pin(s) — and any stale manifest selector — so
    # the cutover binds the LIVE runtime; a command that does not name the
    # old revision at all is passed through unchanged and still fails
    # closed in update_marker_runtime.
    relaunch_command = _regenerate_relaunch_command(
        relaunch_command,
        old_revision=str(marker_identity.get("source_revision") or ""),
        new_revision=str(live_identity.get("source_revision") or ""),
        expected_manifest_path=expected_manifest_path,
        expected_interpreter_path=expected_interpreter_path,
    )
    update_marker_runtime(
        marker_path,
        expected_marker_sha256=_sha256_file(marker_path),
        expected_previous_runtime_sha256=str(marker_identity["content_sha256"]),
        active_runtime_identity=live_identity,
        relaunch_command=relaunch_command,
        reason="chain-start launch-seed marker rebind",
        actor="chain",
        direction="cutover",
        source_branch=source_branch,
        expected_interpreter_path=expected_interpreter_path,
    )


def _launch_seed_current(
    seed_path: Path,
    *,
    root: Path,
    expected_revision: str,
    marker_path: Path,
    manifest_path: Path,
    generation: int | None = None,
) -> bool:
    """True when the on-disk seed is release-ready and still pinned to root/revision.

    The seed must also embed the live marker launch binding: a marker rebind
    with unchanged root+revision (e.g. weak→strong identity shape cutover)
    must invalidate a stale seed, otherwise every worker fails
    ``validate_runtime_launch_seed`` with "cloud marker launch binding
    drifted".  The comparison mirrors the worker-side gate exactly.

    The seed's ``input_paths.manifest`` must resolve to the SAME canonical
    manifest path as *manifest_path*: a pointerless legacy seed (CLI build
    without --manifest) or a pointer for another session must never be
    treated as current, so the next chain start rebuilds it (codex consult
    0ae19cc17afd).
    """
    try:
        seed = _json_file(seed_path, label="runtime launch seed")
        _verify_seed_digest(seed)
    except CliError:
        return False
    if seed.get("authority") != RUNTIME_LAUNCH_CLOUD_AUTHORITY:
        return False
    # Codex fix 2026-08-17: a seed built for an EARLIER accepted generation
    # is never reused to dispatch after a promotion. When *generation* is
    # provided it must equal the seed's bound manifest_generation.
    if generation is not None and seed.get("manifest_generation") != generation:
        return False
    # Occurrence 12f5e50e0107: never REUSE across interpreters. A stored
    # seed whose embedded interpreter vector (or its dependency-generation
    # interpreter) does not match the CURRENT dispatching interpreter was
    # built by or for another runtime — treat it as stale so
    # ensure_runtime_launch_seed rebuilds; worker-side
    # validate_runtime_launch_seed would refuse it anyway with "runtime
    # interpreter identity drifted".
    interp = seed.get("interpreter")
    interp = interp if isinstance(interp, Mapping) else {}
    seed_executable = str(interp.get("executable") or "")
    if (
        not seed_executable
        or os.path.realpath(seed_executable)
        != os.path.realpath(sys.executable)
    ):
        return False
    seed_dep = seed.get("dependency_generation")
    seed_dep = seed_dep if isinstance(seed_dep, Mapping) else {}
    if seed_dep:
        seed_dep_interpreter = str(seed_dep.get("interpreter_path") or "")
        if (
            not seed_dep_interpreter
            or os.path.realpath(seed_dep_interpreter)
            != os.path.realpath(sys.executable)
        ):
            return False
    input_paths = seed.get("input_paths")
    input_paths = input_paths if isinstance(input_paths, Mapping) else {}
    seed_manifest = str(input_paths.get("manifest") or "").strip()
    if not seed_manifest:
        return False
    if (
        Path(seed_manifest).expanduser().resolve(strict=False)
        != manifest_path.expanduser().resolve(strict=False)
    ):
        return False
    expected_marker = seed.get("marker")
    expected_marker = expected_marker if isinstance(expected_marker, Mapping) else {}
    if not isinstance(expected_marker.get("launch_binding"), Mapping):
        return False
    try:
        marker = _json_file(marker_path, label="cloud session marker")
    except CliError:
        return False
    if (
        str(marker_path.resolve(strict=False)) != str(expected_marker.get("path") or "")
        or _marker_launch_binding(marker) != expected_marker.get("launch_binding")
    ):
        return False
    # Occurrence 35afd4e47587 (seed document manifest drifted): a seed whose
    # live seed documents (hot-env selector / supervisor receipt / seed docs)
    # no longer match the bound seed_document_manifest is STALE.
    # validate_runtime_launch_seed rejects it at worker launch ("seed document
    # manifest drifted"); the dispatcher must mirror that exact gate here so
    # ensure_runtime_launch_seed REBUILDS the seed instead of re-issuing one
    # every worker would refuse. The chain-spec FULL-FILE hash is advisory
    # only (plan state carries the recorded binding; a spec edit must not
    # hard-block every launch until a rebuild) — chain runtime binding is
    # still enforced separately below.
    doc_paths = [
        Path(str(input_paths.get(name) or ""))
        for name in ("supervisor_receipt", "hot_env")
    ]
    doc_paths.extend(Path(str(path)) for path in input_paths.get("seed_docs") or [])
    if not _manifest_matches(doc_paths, seed.get("seed_document_manifest") or {}):
        return False
    return (
        bool(seed.get("ready"))
        and str(seed.get("expected_root") or "") == str(root)
        and str(seed.get("expected_revision") or "") == expected_revision
    )


def _exclusive_write_json(
    path: Path, payload: Mapping[str, Any], *, mode: int = 0o644
) -> None:
    """Write *payload* to *path* with exclusive-create (``O_EXCL``) semantics.

    Codex fix 2026-08-17: an issued generation seed is IMMUTABLE. The file is
    created only if it does not already exist; a concurrent writer that won
    the race leaves the existing seed intact and the caller treats
    :class:`FileExistsError` as "already dispatched" (the on-disk seed is the
    one to use).
    """
    path = path.resolve(strict=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        str(path),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        mode,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def standalone_runtime_launch_dir(expected_root: Path, *, create: bool = True) -> Path:
    """Return the root-custodied resident launch state directory.

    The root is intentionally resolved strictly: a resident attestation is
    never issued for a missing checkout or through a symlinked repository.

    ``create=False`` is the read-only contract for every load/read path: the
    existing root, state, and parent custody chain are validated without any
    ``mkdir``, ``chmod``, or write, so a rejected load can never repair or
    normalize reused state.  Creation and ``0700`` normalization remain
    exclusive to true publication and process-create callers (the default).
    """
    try:
        root = expected_root.expanduser().resolve(strict=True)
    except OSError as exc:
        raise CliError(RUNTIME_ATTESTATION_ERROR, "resident repository root is unavailable") from exc
    state = root / STANDALONE_RUNTIME_LAUNCH_RELATIVE
    try:
        state.relative_to(root)
    except ValueError as exc:  # defensive; the relative constant is fixed
        raise CliError(RUNTIME_ATTESTATION_ERROR, "resident launch state escaped repository root") from exc
    chain = (root / ".megaplan", root / ".megaplan" / "resident", state)
    if not create:
        # Validate-only: fail closed on missing, symlinked, non-directory, or
        # permissive custody state; never touch the filesystem.
        for directory in chain:
            if directory.is_symlink():
                raise CliError(RUNTIME_ATTESTATION_ERROR, "resident launch state contains a symlink")
            try:
                info = directory.stat()
            except FileNotFoundError as exc:
                raise CliError(RUNTIME_ATTESTATION_ERROR, "resident launch state is unavailable") from None
            except OSError as exc:
                raise CliError(RUNTIME_ATTESTATION_ERROR, "resident launch state is unreadable") from exc
            if not stat.S_ISDIR(info.st_mode):
                raise CliError(RUNTIME_ATTESTATION_ERROR, "resident launch state is not a real directory")
        if stat.S_IMODE(state.stat().st_mode) != 0o700:
            raise CliError(RUNTIME_ATTESTATION_ERROR, "resident launch state permissions are unsafe")
        return state
    for directory in chain:
        if directory.exists() and directory.is_symlink():
            raise CliError(RUNTIME_ATTESTATION_ERROR, "resident launch state contains a symlink")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory == state:
            try:
                directory.chmod(0o700)
            except OSError as exc:
                raise CliError(RUNTIME_ATTESTATION_ERROR, "resident launch state permissions are unsafe") from exc
    return state


def _standalone_path(root: Path, relative: str) -> Path:
    """Resolve a path below the resident state, rejecting symlink escapes."""
    state = standalone_runtime_launch_dir(root)
    path = Path(relative)
    candidate = path if path.is_absolute() else state / path
    try:
        candidate.relative_to(state)
    except ValueError as exc:
        raise CliError(RUNTIME_ATTESTATION_ERROR, "resident launch path escaped state directory") from exc
    # Inspect the lexical candidate before resolving it: resolving first would
    # silently turn a final symlink into its target and erase the custody fact.
    current = state
    for part in candidate.relative_to(state).parts:
        current = current / part
        if current.is_symlink():
            raise CliError(RUNTIME_ATTESTATION_ERROR, "resident launch path contains a symlink")
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(state.resolve(strict=True))
    except ValueError as exc:
        raise CliError(RUNTIME_ATTESTATION_ERROR, "resident launch path escaped state directory") from exc
    return resolved


def _git_toplevel(root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def _validate_full_revision(value: str, *, label: str = "revision") -> str:
    revision = str(value or "")
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", revision):
        raise CliError(RUNTIME_ATTESTATION_ERROR, f"{label} must be a full hexadecimal Git OID")
    return revision


def _standalone_admission(root_value: Path, expected_revision: str) -> tuple[Path, str, str]:
    try:
        root = root_value.expanduser().resolve(strict=True)
    except OSError as exc:
        raise CliError(RUNTIME_ATTESTATION_ERROR, "resident repository root is unavailable") from exc
    top = _git_toplevel(root)
    try:
        top_path = Path(top).resolve(strict=True)
    except OSError as exc:
        raise CliError(RUNTIME_ATTESTATION_ERROR, "resident repository is not a Git checkout") from exc
    if top_path != root:
        raise CliError(RUNTIME_ATTESTATION_ERROR, "Git top-level does not equal resident repository root")
    expected = _validate_full_revision(expected_revision, label="expected HEAD")
    live = _git_revision(root)
    if live != expected:
        raise CliError(RUNTIME_ATTESTATION_ERROR, "resident repository HEAD does not match expected HEAD")
    return root, expected, live


def build_standalone_runtime_launch_seed(
    *,
    project_root: Path,
    expected_project_revision: str,
    runtime_root: Path,
    expected_runtime_revision: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a domain-separated resident seed from local runtime evidence.

    Two independently admitted custody identities feed one fail-closed
    attestation seam: the *project* repository owns Git admission, state
    directory, pointer, receipt, and process-status custody under its exact
    HEAD; the separately imported Arnold *runtime* checkout owns provenance
    and every loaded-code vector under its own exact revision.
    """
    project, expected_project, live_project = _standalone_admission(
        project_root, expected_project_revision
    )
    runtime, expected_runtime, live_runtime = _standalone_admission(
        runtime_root, expected_runtime_revision
    )
    provenance = runtime_provenance(
        expected_root=runtime, expected_revision=expected_runtime
    )
    modules, module_errors = _module_vector(runtime)
    pth, pth_errors = _pth_vector(runtime)
    wrappers, wrapper_errors = _wrapper_vector(runtime)
    errors = [*(provenance.get("errors") or []), *module_errors, *pth_errors, *wrapper_errors]
    if not provenance.get("ok"):
        errors.append("runtime_provenance_not_ready")
    core = {
        "schema": RUNTIME_LAUNCH_SEED_SCHEMA,
        "authority": RUNTIME_LAUNCH_STANDALONE_AUTHORITY,
        "project_root": str(project),
        "expected_project_revision": expected_project,
        "live_project_revision": live_project,
        "runtime_root": str(runtime),
        "expected_runtime_revision": expected_runtime,
        "live_runtime_revision": live_runtime,
        "generated_at": generated_at or now_utc(),
        "runtime_provenance": provenance,
        "loaded_modules": modules,
        "interpreter": _interpreter_vector(
            direct_url=(provenance.get("direct_url") if isinstance(provenance.get("direct_url"), Mapping) else {})
        ),
        "site_pth": pth,
        "wrappers": wrappers,
        "errors": sorted(set(errors)),
        "ready": not errors,
    }
    return {**core, "content_sha256": _canonical_sha256(core)}

def validate_standalone_runtime_launch_seed(
    seed: Mapping[str, Any], *, component: str = "resident"
) -> dict[str, Any]:
    """Validate only resident evidence; this path never reads cloud artifacts.

    Both domains are re-collected live: the project domain re-admits Git
    custody against ``project_root``/HEAD, and the runtime domain re-collects
    provenance plus every loaded-code vector against ``runtime_root``.  There
    is no legacy one-root fallback: retired field names are tampering
    evidence, never alternate inputs.
    """
    _verify_seed_digest(seed)
    if seed.get("authority") != RUNTIME_LAUNCH_STANDALONE_AUTHORITY:
        raise CliError(RUNTIME_ATTESTATION_ERROR, "runtime launch seed authority is not standalone-resident")
    if component != "resident":
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone runtime launch seed is resident-only")
    for field in ("manifest_sha256", "marker", "supervisor_receipt", "supervisor_runtime", "hot_env", "chain_runtime_binding"):
        if seed.get(field):
            raise CliError(RUNTIME_ATTESTATION_ERROR, f"standalone seed contains cloud field: {field}")
    for field in ("expected_root", "expected_revision", "live_revision"):
        if field in seed:
            raise CliError(RUNTIME_ATTESTATION_ERROR, f"standalone seed contains legacy field: {field}")
    required_types = {
        "project_root": str,
        "expected_project_revision": str,
        "live_project_revision": str,
        "runtime_root": str,
        "expected_runtime_revision": str,
        "live_runtime_revision": str,
        "generated_at": str,
        "runtime_provenance": Mapping,
        "loaded_modules": list,
        "interpreter": Mapping,
        "site_pth": list,
        "wrappers": list,
        "errors": list,
    }
    for field, expected_type in required_types.items():
        if not isinstance(seed.get(field), expected_type):
            raise CliError(
                RUNTIME_ATTESTATION_ERROR,
                f"standalone runtime launch seed has invalid {field}",
            )
    if type(seed.get("ready")) is not bool:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "standalone runtime launch seed has invalid ready state",
        )
    try:
        project, expected_project, live_project = _standalone_admission(
            Path(str(seed.get("project_root") or "")),
            str(seed.get("expected_project_revision") or ""),
        )
        runtime, expected_runtime, live_runtime = _standalone_admission(
            Path(str(seed.get("runtime_root") or "")),
            str(seed.get("expected_runtime_revision") or ""),
        )
    except CliError:
        raise
    if (
        str(seed.get("project_root") or "") != str(project)
        or str(seed.get("expected_project_revision") or "") != expected_project
        or str(seed.get("runtime_root") or "") != str(runtime)
        or str(seed.get("expected_runtime_revision") or "") != expected_runtime
    ):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone runtime attestation root or revision changed")
    if (
        str(seed.get("live_project_revision") or "") != live_project
        or str(seed.get("live_runtime_revision") or "") != live_runtime
    ):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone runtime live revision changed")
    generated_at = str(seed.get("generated_at") or "")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", generated_at):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone runtime attestation timestamp is invalid")
    try:
        parsed_generated_at = datetime.fromisoformat(
            generated_at.removesuffix("Z") + "+00:00"
        )
    except ValueError as exc:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "standalone runtime attestation timestamp is invalid",
        ) from exc
    if parsed_generated_at.utcoffset() is None or parsed_generated_at.utcoffset().total_seconds() != 0:
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone runtime attestation timestamp is invalid")
    provenance = runtime_provenance(
        expected_root=runtime, expected_revision=expected_runtime
    )
    if not provenance.get("ok") or provenance != seed.get("runtime_provenance"):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone runtime provenance changed")
    modules, module_errors = _module_vector(runtime)
    pth, pth_errors = _pth_vector(runtime)
    wrappers, wrapper_errors = _wrapper_vector(runtime)
    interpreter = _interpreter_vector(
        direct_url=(provenance.get("direct_url") if isinstance(provenance.get("direct_url"), Mapping) else {})
    )
    if module_errors or modules != seed.get("loaded_modules"):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone loaded module vector changed")
    if pth_errors or pth != seed.get("site_pth"):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone site .pth vector changed")
    if wrapper_errors or wrappers != seed.get("wrappers"):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone wrapper vector changed")
    if interpreter != seed.get("interpreter"):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone interpreter identity changed")
    if not bool(seed.get("ready")) or seed.get("errors"):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone runtime launch seed was not release-ready")
    return {
        "status": "ready",
        "seed_sha256": seed["content_sha256"],
        "authority": RUNTIME_LAUNCH_STANDALONE_AUTHORITY,
        "project_root": str(project),
        "expected_project_revision": expected_project,
        "runtime_root": str(runtime),
        "expected_runtime_revision": expected_runtime,
        "runtime_vector_sha256": runtime_vector_sha256(seed),
    }


def _inspect_standalone_operational_dir(state: Path, name: str) -> bool:
    """Non-mutating check: True when present and safe, False when absent.

    Any existing symlink, non-directory, unreadable entry, or mode other
    than ``0700`` rejects; absence alone is not an error so callers can
    record the entry as eligible for later creation.
    """
    directory = state / name
    try:
        directory.relative_to(state)
    except ValueError as exc:  # defensive; *name* is a fixed component
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            f"resident {name} directory escaped state directory",
        ) from exc
    if directory.is_symlink():
        raise CliError(RUNTIME_ATTESTATION_ERROR, "resident launch state contains a symlink")
    if directory.exists() and not directory.is_dir():
        raise CliError(RUNTIME_ATTESTATION_ERROR, f"resident {name} directory is not a real directory")
    try:
        info = directory.stat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise CliError(RUNTIME_ATTESTATION_ERROR, f"resident {name} directory is unreadable") from exc
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise CliError(RUNTIME_ATTESTATION_ERROR, f"resident {name} directory permissions are unsafe")
    return True


def _require_standalone_operational_dir(state: Path, name: str, *, create: bool) -> None:
    """Require a real, state-contained ``0700`` operational directory.

    Reused directories are validated, never repaired: an existing symlink,
    non-directory, or permissive mode fails closed before any seed, receipt,
    pointer, or attestation bytes change.  Only freshly created directories
    are normalized to ``0700``.
    """
    if _inspect_standalone_operational_dir(state, name):
        return
    if not create:
        raise CliError(RUNTIME_ATTESTATION_ERROR, f"resident {name} directory is unavailable")
    try:
        (state / name).mkdir(mode=0o700)
    except FileExistsError:
        # Concurrent-issuer create race: the winner may be legitimate or
        # hostile. Re-inspect so a symlink, non-directory, or permissive
        # occupant fails closed instead of being adopted or repaired.
        if not _inspect_standalone_operational_dir(state, name):
            raise CliError(
                RUNTIME_ATTESTATION_ERROR,
                f"resident {name} directory is unavailable",
            ) from None
        return
    (state / name).chmod(0o700)


def standalone_dispatch_paths(root: Path, *, head: str, seed_sha256: str) -> dict[str, Path]:
    state = standalone_runtime_launch_dir(root)
    expected = _validate_full_revision(head, label="expected HEAD")
    # Preflight every operational directory non-mutating before creating any:
    # an unsafe reused entry rejects while custody state still lacks siblings.
    missing = [
        name
        for name in ("seeds", "receipts", "status")
        if not _inspect_standalone_operational_dir(state, name)
    ]
    for name in missing:
        _require_standalone_operational_dir(state, name, create=True)
    return {
        "seed": _standalone_path(root, f"seeds/standalone-{expected}-{seed_sha256}.json"),
        "pointer": _standalone_path(root, "seeds/dispatch-current.json"),
        "receipts": _standalone_path(root, "receipts"),
        "status": _standalone_path(root, "status/resident.runtime-process-attestation.json"),
    }


def build_standalone_runtime_attestation_receipt(
    *, seed: Mapping[str, Any], seed_path: Path, pointer_path: Path, generated_at: str | None = None
) -> dict[str, Any]:
    _verify_seed_digest(seed)
    if seed.get("authority") != RUNTIME_LAUNCH_STANDALONE_AUTHORITY:
        raise CliError(RUNTIME_ATTESTATION_ERROR, "receipt requires standalone-resident seed")
    core = {
        "schema": STANDALONE_ATTESTATION_RECEIPT_SCHEMA,
        "authority": RUNTIME_LAUNCH_STANDALONE_AUTHORITY,
        "root": str(Path(str(seed["project_root"])).resolve(strict=True)),
        "expected_head": str(seed["expected_project_revision"]),
        "live_head": str(seed.get("live_project_revision") or ""),
        "generated_at": generated_at or str(seed.get("generated_at") or now_utc()),
        "seed_path": str(seed_path.resolve(strict=False)),
        "seed_sha256": str(seed["content_sha256"]),
        "pointer_path": str(pointer_path.resolve(strict=False)),
    }
    return {**core, "content_sha256": _canonical_sha256(core)}


def load_standalone_runtime_dispatch_pointer(root: Path) -> dict[str, Any]:
    state = standalone_runtime_launch_dir(root, create=False)
    for name in ("seeds", "receipts", "status"):
        _require_standalone_operational_dir(state, name, create=False)
    pointer_path = state / "seeds" / "dispatch-current.json"
    if pointer_path.is_symlink() or pointer_path.parent.is_symlink():
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone dispatch pointer is a symlink")
    try:
        pointer_mode = stat.S_IMODE(pointer_path.stat().st_mode)
    except FileNotFoundError as exc:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR, "standalone dispatch pointer is unavailable"
        ) from exc
    except OSError as exc:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR, "standalone dispatch pointer is unreadable"
        ) from exc
    if pointer_mode != 0o600:
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone dispatch pointer permissions are unsafe")
    pointer = _json_file(pointer_path, label="standalone runtime dispatch pointer")
    if pointer.get("schema") != STANDALONE_DISPATCH_POINTER_SCHEMA or pointer.get("authority") != RUNTIME_LAUNCH_STANDALONE_AUTHORITY:
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone dispatch pointer authority is invalid")
    resolved_root = Path(str(root)).expanduser().resolve(strict=True)
    if str(pointer.get("root") or "") != str(resolved_root):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone dispatch pointer root mismatch")
    seed_path = Path(str(pointer.get("seed_path") or ""))
    receipt_path = Path(str(pointer.get("receipt_path") or ""))
    for path in (seed_path, receipt_path):
        if not path.is_absolute() or not path.exists() or path.is_symlink():
            raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone dispatch pointer path is unsafe")
        try:
            if stat.S_IMODE(path.stat().st_mode) != 0o600:
                raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone dispatch object permissions are unsafe")
        except OSError as exc:
            raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone dispatch object is unreadable") from exc
        state = standalone_runtime_launch_dir(resolved_root, create=False)
        try:
            lexical = path.relative_to(state)
        except ValueError as exc:
            raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone dispatch pointer escaped state directory") from exc
        _require_standalone_operational_dir(state, lexical.parts[0], create=False)
        current = state
        for part in lexical.parts:
            current = current / part
            if current.is_symlink():
                raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone dispatch path contains a symlink")
        try:
            path.resolve(strict=True).relative_to(state.resolve(strict=True))
        except ValueError as exc:
            raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone dispatch pointer escaped state directory") from exc
    seed = _json_file(seed_path, label="standalone runtime launch seed")
    receipt = _json_file(receipt_path, label="standalone runtime attestation receipt")
    _verify_seed_digest(seed)
    if seed.get("content_sha256") != pointer.get("seed_sha256"):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone dispatch seed digest mismatch")
    if seed.get("expected_project_revision") != pointer.get("expected_revision"):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone dispatch seed revision mismatch")
    if receipt.get("content_sha256") != pointer.get("receipt_sha256"):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone dispatch receipt digest mismatch")
    receipt_core = {key: value for key, value in receipt.items() if key != "content_sha256"}
    if receipt.get("schema") != STANDALONE_ATTESTATION_RECEIPT_SCHEMA or receipt.get("authority") != RUNTIME_LAUNCH_STANDALONE_AUTHORITY or receipt.get("content_sha256") != _canonical_sha256(receipt_core):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone attestation receipt is invalid")
    if receipt.get("seed_path") != str(seed_path.resolve(strict=False)) or receipt.get("seed_sha256") != seed.get("content_sha256"):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone attestation receipt seed binding is invalid")
    if receipt.get("pointer_path") != str(pointer_path.resolve(strict=False)):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone attestation receipt pointer binding is invalid")
    if (
        receipt.get("root") != pointer.get("root")
        or receipt.get("expected_head") != pointer.get("expected_revision")
        or receipt.get("live_head") != seed.get("live_project_revision")
        or receipt.get("generated_at") != seed.get("generated_at")
        or pointer.get("generated_at") != seed.get("generated_at")
    ):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone attestation receipt root/revision binding is invalid")
    validate_standalone_runtime_launch_seed(seed)
    return pointer


def _verify_reused_immutable_object(
    path: Path, payload: Mapping[str, Any], *, label: str
) -> None:
    """Accept a ``FileExistsError`` reuse only when custody is intact.

    The existing object must be a regular non-symlink file with mode exactly
    ``0600`` whose canonical digest matches the expected immutable object.
    Anything else rejects without repair, chmod, or mutation so the dispatch
    pointer can never advance onto a tampered custody object.
    """
    try:
        st = path.lstat()
    except OSError as exc:
        raise CliError(RUNTIME_ATTESTATION_ERROR, f"standalone {label} is unreadable") from exc
    if path.is_symlink() or not stat.S_ISREG(st.st_mode):
        raise CliError(RUNTIME_ATTESTATION_ERROR, f"standalone {label} is not a regular file")
    if stat.S_IMODE(st.st_mode) != 0o600:
        raise CliError(RUNTIME_ATTESTATION_ERROR, f"standalone {label} permissions are unsafe")
    existing = _json_file(path, label=f"standalone runtime {label}")
    expected_digest = str(payload.get("content_sha256") or "")
    existing_core = {key: value for key, value in existing.items() if key != "content_sha256"}
    if (
        existing.get("content_sha256") != expected_digest
        or _canonical_sha256(existing_core) != expected_digest
        or existing != dict(payload)
    ):
        raise CliError(RUNTIME_ATTESTATION_ERROR, f"immutable standalone {label} collision")


def write_standalone_runtime_publication(
    *, seed: Mapping[str, Any], seed_path: Path, root: Path, generated_at: str | None = None
) -> dict[str, Any]:
    """Publish a resident seed, issuance receipt, and dispatch pointer."""
    validate_standalone_runtime_launch_seed(seed)
    root, expected, live = _standalone_admission(root, str(seed.get("expected_project_revision") or ""))
    if str(seed.get("project_root") or "") != str(root) or live != str(seed.get("live_project_revision") or ""):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone seed changed during publication")
    paths = standalone_dispatch_paths(root, head=expected, seed_sha256=str(seed["content_sha256"]))
    if paths["seed"].resolve(strict=False) != seed_path.resolve(strict=False):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone seed path is not root-custodied")
    try:
        _exclusive_write_json(paths["seed"], seed, mode=0o600)
    except FileExistsError:
        _verify_reused_immutable_object(paths["seed"], seed, label="launch seed")
    receipt = build_standalone_runtime_attestation_receipt(
        seed=seed, seed_path=paths["seed"], pointer_path=paths["pointer"], generated_at=generated_at
    )
    receipt_path = _standalone_path(
        root, f"receipts/{receipt['content_sha256']}.json"
    )
    try:
        _exclusive_write_json(receipt_path, receipt, mode=0o600)
    except FileExistsError:
        _verify_reused_immutable_object(receipt_path, receipt, label="attestation receipt")
    pointer = {
        "schema": STANDALONE_DISPATCH_POINTER_SCHEMA,
        "authority": RUNTIME_LAUNCH_STANDALONE_AUTHORITY,
        "seed_path": str(paths["seed"].resolve(strict=False)),
        "receipt_path": str(receipt_path.resolve(strict=False)),
        "root": str(root),
        "expected_revision": expected,
        "generated_at": str(seed.get("generated_at") or generated_at or now_utc()),
        "seed_sha256": str(seed["content_sha256"]),
        "receipt_sha256": str(receipt["content_sha256"]),
    }
    # Standalone-specific pointer custody preflight (F2): an existing pointer
    # must be a regular non-symlink ``0600`` file before replacement; shared
    # ``_atomic_write`` semantics stay unchanged.
    try:
        pointer_stat = paths["pointer"].lstat()
    except FileNotFoundError:
        pointer_stat = None  # Missing pointers remain creatable below.
    except OSError as exc:
        raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone dispatch pointer is unreadable") from exc
    if pointer_stat is not None:
        # ``lstat`` never follows the final component, so this rejects symlinks too.
        if not stat.S_ISREG(pointer_stat.st_mode):
            raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone dispatch pointer is not a regular file")
        if stat.S_IMODE(pointer_stat.st_mode) != 0o600:
            raise CliError(RUNTIME_ATTESTATION_ERROR, "standalone dispatch pointer permissions are unsafe")
    _atomic_write(paths["pointer"], pointer)
    # Re-read and validate every published object before handing it to a caller.
    published = load_standalone_runtime_dispatch_pointer(root)
    if published != pointer:
        raise CliError(RUNTIME_ATTESTATION_ERROR, "published standalone dispatch pointer changed")
    return {"seed_path": paths["seed"], "receipt_path": receipt_path, "pointer_path": paths["pointer"], "receipt": receipt, "pointer": pointer}


def _write_dispatch_pointer(
    store_dir: Path,
    seed_path: Path,
    *,
    generation: int,
    expected_revision: str,
    seed_sha256: str,
) -> Path:
    """Atomically point ``dispatch-current.json`` at the newest ready seed."""
    pointer = store_dir / DISPATCH_CURRENT_FILENAME
    _atomic_write(
        pointer,
        {
            "schema": DISPATCH_POINTER_SCHEMA,
            "seed_path": str(seed_path),
            "manifest_generation": generation,
            "expected_revision": expected_revision,
            "seed_sha256": seed_sha256,
        },
    )
    return pointer


def _find_current_seed(
    store_dir: Path,
    *,
    root: Path,
    expected_revision: str,
    marker_path: Path,
    manifest_path: Path,
    generation: int,
) -> Path | None:
    """Return an existing, still-valid immutable seed for this generation."""
    if not store_dir.is_dir():
        return None
    for candidate in sorted(store_dir.glob("*.json")):
        if candidate.name == DISPATCH_CURRENT_FILENAME:
            continue
        if _launch_seed_current(
            candidate,
            root=root,
            expected_revision=expected_revision,
            marker_path=marker_path,
            manifest_path=manifest_path,
            generation=generation,
        ):
            return candidate
    return None


def ensure_runtime_launch_seed(
    *,
    manifest_path: Path,
    chain_spec_path: Path,
    marker_path: Path,
    chain_runtime_identity: Mapping[str, Any] | None = None,
    seed_dir: Path | None = None,
    supervisor_receipt_path: Path | None = None,
    hot_env_path: Path | None = None,
    expected_branch: str | None = None,
    expected_ancestry_base: str | None = None,
) -> Path:
    """Build or refresh the canonical runtime launch seed for one per-epic runtime.

    The per-session runtime manifest (``ARNOLD_RUNTIME_MANIFEST``) is the
    runtime selector (G4): ``epic.runtime_root`` and ``epic.expected_head``
    pin the seeded runtime, and the live checkout HEAD MUST equal the pin
    (else :class:`CliError`).  The marker's
    ``runtime_binding.current_identity`` must agree with the live provenance
    at the expected revision and with the chain execution binding; a stale
    marker is rebound through the CAS-protected marker/runtime cutover helper
    (never hand-edited).  The seed is rebuilt whenever it is missing, not
    release-ready, content-digest-invalid, or pinned to a different
    root/revision.  On success returns the seed path; the caller exports it
    as ``MEGAPLAN_RUNTIME_LAUNCH_SEED`` for every child worker/watchdog.
    """
    from arnold_pipelines.megaplan.cloud.runtime_manifest import (
        ManifestError,
        load_manifest,
    )

    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as exc:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            f"runtime manifest {manifest_path} is invalid: {exc}",
        ) from exc
    epic = manifest.epic
    runtime_root = str(epic.get("runtime_root") or "").strip()
    expected_revision = str(epic.get("expected_head") or "").strip()
    if not runtime_root or not expected_revision:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "runtime manifest lacks nonempty epic.runtime_root and epic.expected_head",
        )
    root = Path(runtime_root).expanduser().resolve()
    live_head = _git_revision(root)
    if not live_head or live_head != expected_revision:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            f"runtime root HEAD does not match the manifest pin: "
            f"expected {expected_revision}, live {live_head or '<unreadable>'}",
        )
    live_identity = _live_runtime_identity(
        root=root,
        expected_revision=expected_revision,
    )
    if chain_runtime_identity is not None:
        from arnold_pipelines.megaplan.cloud.runtime_cutover import (
            normalize_runtime_identity,
        )

        chain_identity = normalize_runtime_identity(chain_runtime_identity)
        # Compare the launch-relevant identity (grok consult, d58701026410):
        # import_root + source_revision, resolved. The digest is a derived
        # view; root+rev are the facts the tree determines. Equal root+rev
        # with different diagnostic shapes (editable/pth/imports populated vs
        # None depending on which writer stored them) is the same runtime.
        # A manifest GENERATION ADVANCE on the same import_root is a normal
        # operator action and must be a NON-EVENT for the next worker launch:
        # the launch adopts the live manifest-pinned head (grok consult
        # 2026-08-18: "JUST RELAUNCH"). A different import_root or a
        # generation downgrade still fail closed.
        bound_identity = _adopt_or_refuse_launch_identity(
            chain_identity,
            live_identity,
            recorded_generation=_recorded_seed_generation(chain_spec_path),
            live_generation=int(manifest.generation),
        )
        if (
            str((bound_identity.get("source_revision") or ""))
            != str((chain_identity.get("source_revision") or ""))
        ):
            _persist_adopted_chain_runtime_identity(
                chain_spec_path=chain_spec_path,
                bound_identity=bound_identity,
                reason="manifest_generation_adopt",
            )
    else:
        bound_identity = live_identity
    marker = _json_file(marker_path, label="cloud session marker")
    _rebind_marker_if_stale(
        marker_path,
        marker,
        live_identity=live_identity,
        source_branch=str(epic.get("branch") or ""),
        expected_manifest_path=str(manifest_path),
    )
    # Codex fix 2026-08-17: content-address the accepted generation. The seed
    # lives at runtime-launch-seeds/<runtime-id>/<generation>-<head>-<sha>.json
    # and is written once (O_EXCL); a separate atomic dispatch-current.json
    # pointer selects the newest ready seed. Running workers retain the
    # absolute immutable path they were dispatched with.
    store_dir = ((seed_dir or _launch_seed_store_dir()) / manifest.runtime_id).resolve(
        strict=False
    )
    generation = int(manifest.generation)
    manifest_sha256 = _canonical_sha256(manifest.to_dict())
    dep_generation = manifest.epic.get("dependency_generation")
    dep_generation = (
        dict(dep_generation) if isinstance(dep_generation, Mapping) else None
    )
    existing = _find_current_seed(
        store_dir,
        root=root,
        expected_revision=expected_revision,
        marker_path=marker_path,
        manifest_path=manifest_path,
        generation=generation,
    )
    if existing is not None:
        return existing
    payload = build_runtime_launch_seed(
        expected_root=root,
        expected_revision=expected_revision,
        supervisor_receipt_path=supervisor_receipt_path
        or SUPERVISOR_RECEIPT_DEFAULT_PATH,
        hot_env_path=hot_env_path or CLOUD_HOT_ENV_DEFAULT_PATH,
        marker_path=marker_path,
        chain_spec_path=chain_spec_path,
        seed_doc_paths=(),
        expected_branch=expected_branch,
        expected_ancestry_base=expected_ancestry_base,
        manifest_path=manifest_path,
        chain_runtime_identity=bound_identity,
        manifest_generation=generation,
        manifest_sha256=manifest_sha256,
        dependency_generation=dep_generation,
    )
    if not bool(payload.get("ready")):
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "runtime launch seed is not release-ready: "
            + ", ".join(str(item) for item in payload.get("errors") or []),
        )
    seed_sha = str(payload.get("content_sha256") or "")
    seed_path = store_dir / f"{generation}-{expected_revision}-{seed_sha}.json"
    try:
        _exclusive_write_json(seed_path, payload)
    except FileExistsError:
        # A concurrent dispatcher may have written this exact immutable seed.
        # Do not mistake a damaged/tampered occupant of the content-addressed
        # pathname for that winner: preserve it as evidence, then recreate the
        # canonical payload with O_EXCL semantics.
        try:
            incumbent = _json_file(seed_path, label="runtime launch seed")
        except CliError:
            incumbent = {}
        if incumbent != payload:
            quarantine = seed_path.with_name(
                f"{seed_path.stem}.invalid-{os.getpid()}.json"
            )
            try:
                os.replace(seed_path, quarantine)
                _exclusive_write_json(seed_path, payload)
            except FileNotFoundError:
                _exclusive_write_json(seed_path, payload)
            except FileExistsError:
                winner = _json_file(seed_path, label="runtime launch seed")
                if winner != payload:
                    raise CliError(
                        RUNTIME_ATTESTATION_ERROR,
                        "content-addressed runtime launch seed collision",
                    )
    _write_dispatch_pointer(
        store_dir,
        seed_path,
        generation=generation,
        expected_revision=expected_revision,
        seed_sha256=seed_sha,
    )
    return seed_path


def _render_launch_identity_diagnostic(
    label: str,
    identity: Mapping[str, Any],
    generation: int | None,
) -> str:
    """Render a concise launch-relevant identity for diagnostic messages.

    Shows ``import_root`` and ``source_revision`` when present; renders as
    ``<empty>`` when both are absent.  ``generation`` is ``None`` when
    unknown (first-launch context).
    """
    root = str((identity.get("import_root") or "")).rstrip("/")
    rev = str(identity.get("source_revision") or "")
    if not root and not rev:
        gen = generation if generation is not None else "no recorded generation"
        return f"{label}=<empty>, generation={gen}"
    gen = generation if generation is not None else "unknown"
    return f"{label}=import_root={root}, source_revision={rev}, generation={gen}"


def _adopt_or_refuse_launch_identity(
    recorded: Mapping[str, Any],
    live: Mapping[str, Any],
    *,
    recorded_generation: int | None,
    live_generation: int,
) -> dict[str, Any]:
    """Decide the launch identity for one worker dispatch.

    The OPERATOR PRINCIPLE (2026-08-18): an engine change must never break
    the epic. The live manifest is authoritative; the chain's recorded
    binding is a snapshot that legitimately lags. ANY engine change on the
    SAME import_root (generation advance, generation downgrade, or a
    same-generation revision change) is a NON-EVENT for the next worker
    launch: the launch adopts the live manifest-pinned head and the chain
    record is persisted to match. Only a DIFFERENT import_root (a genuine
    engine swap) fails closed.
    """
    rec_root = str((recorded.get("import_root") or "")).rstrip("/")
    live_root = str((live.get("import_root") or "")).rstrip("/")
    rec_rev = str(recorded.get("source_revision") or "")
    live_rev = str(live.get("source_revision") or "")
    if rec_root == live_root and rec_rev == live_rev:
        return dict(recorded)
    if rec_root != live_root:
        recorded_diag = _render_launch_identity_diagnostic(
            "recorded_identity", recorded, recorded_generation
        )
        live_diag = _render_launch_identity_diagnostic(
            "live_identity", live, live_generation
        )
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "chain execution binding does not match the live manifest-pinned runtime: "
            f"{recorded_diag}, {live_diag}",
        )
    if recorded_generation is not None and live_generation < recorded_generation:
        # A genuine downgrade (operator rolled the manifest BACK) on the same
        # root is a deliberate re-target: adopt it too — an engine change of
        # ANY direction on the same import_root must never break the epic
        # (operator principle 2026-08-18). Only a different import_root is a
        # real swap that fails closed.
        return dict(live)
    # Same import_root (any generation relation): a NEW launch adopts the
    # live manifest-pinned head — the engine advance is a NON-EVENT, exactly
    # like the blocked-plan auto-adopt (5f34c4a202). A same-generation
    # revision change (head moved at the same gen) is likewise an engine
    # change and must not break the epic.
    return dict(live)


def _recorded_seed_generation(chain_spec_path: Path) -> int | None:
    """Return the generation the CURRENT orchestration seed was built for.

    Reads ``MEGAPLAN_RUNTIME_LAUNCH_SEED`` when set (worker dispatch) and
    falls back to the chain's recorded runtime identity; ``None`` when
    unknown (first launch), in which case adopt is allowed on same-root.
    """
    seed_value = str(os.environ.get("MEGAPLAN_RUNTIME_LAUNCH_SEED") or "").strip()
    if seed_value:
        try:
            seed = _json_file(Path(seed_value), label="runtime launch seed")
            generation = seed.get("manifest_generation")
            if isinstance(generation, int):
                return generation
            input_paths = seed.get("input_paths")
            if isinstance(input_paths, Mapping):
                manifest_value = str(input_paths.get("manifest") or "").strip()
                if manifest_value:
                    from arnold_pipelines.megaplan.cloud.runtime_manifest import (
                        load_manifest,
                    )

                    try:
                        manifest = load_manifest(Path(manifest_value))
                        return int(manifest.generation)
                    except Exception:
                        return None
        except Exception:
            return None
    try:
        from arnold_pipelines.megaplan.chain.spec import load_chain_state

        state = load_chain_state(chain_spec_path, verify_execution_binding=False)
        execution = (state.metadata or {}).get("execution_binding")
        execution = execution if isinstance(execution, Mapping) else {}
        runtime = execution.get("runtime_binding")
        runtime = runtime if isinstance(runtime, Mapping) else {}
        generation = runtime.get("manifest_generation")
        if isinstance(generation, int):
            return generation
    except Exception:
        pass
    return None


def _persist_adopted_chain_runtime_identity(
    *,
    chain_spec_path: Path,
    bound_identity: Mapping[str, Any],
    reason: str,
) -> None:
    """Persist the adopted runtime identity on the chain record.

    Mirrors the rebind write shape (append ``rebind_events``) WITHOUT the
    operator SHA fence: this is a manifest generation adopt (non-event), not
    an operator-authorized cutover. The persist is REQUIRED — a best-effort
    write would leave the chain record lagging the live manifest, so the
    next validate_runtime_launch_seed would raise "chain runtime binding
    drifted" and re-break the epic on the SAME engine change (grok audit
    2026-08-18). An engine change must be a non-event everywhere.
    """
    from arnold_pipelines.megaplan.chain.spec import load_chain_state, save_chain_state

    state = load_chain_state(chain_spec_path, verify_execution_binding=False)
    execution = dict(state.metadata.get("execution_binding") or {})
    runtime = dict(execution.get("runtime_binding") or {})
    runtime["current_identity"] = dict(bound_identity)
    events = list(runtime.get("rebind_events") or [])
    events.append(
        {
            "at": now_utc(),
            "reason": reason,
            "direction": "manifest_generation_adopt",
            "to_source_revision": str(bound_identity.get("source_revision") or ""),
        }
    )
    runtime["rebind_events"] = events
    execution["runtime_binding"] = runtime
    state.metadata["execution_binding"] = execution
    save_chain_state(chain_spec_path, state)


def _live_manifest_generation(chain_spec_path: Path) -> int | None:
    """Return the LIVE manifest generation for the chain's session runtime.

    Reads the session runtime manifest (the same path ensure_runtime_launch
    _seed uses via ARNOLD_RUNTIME_MANIFEST / chain session marker). ``None``
    when unknown — adopt is then allowed on same-root, matching the
    ensure-side rule.
    """
    manifest_value = str(os.environ.get("ARNOLD_RUNTIME_MANIFEST") or "").strip()
    if not manifest_value:
        return None
    from arnold_pipelines.megaplan.cloud.runtime_manifest import (
        ManifestError,
        load_manifest,
    )

    try:
        manifest = load_manifest(Path(manifest_value).expanduser().resolve(strict=False))
        return int(manifest.generation)
    except (ManifestError, TypeError, ValueError):
        return None


def refresh_runtime_launch_seed_for_worker_dispatch() -> Path | None:
    """Select the accepted generation immediately before a worker dispatch.

    The chain's configured seed remains its orchestration seed.  Each worker
    dispatch re-reads the accepted manifest under the promotion lock, resolves
    or creates that generation's immutable seed, and updates the exact seed
    path inherited by the child worker process.
    """
    manifest_value = str(os.environ.get("ARNOLD_RUNTIME_MANIFEST") or "").strip()
    current_path = configured_seed_path()
    if current_path is None:
        return None
    # Custody boundary: a configured seed must prove cloud-chain authority
    # BEFORE any early return, including the no-manifest one, so a
    # standalone-resident seed cannot cross into worker dispatch unchallenged.
    current = _json_file(current_path, label="runtime launch seed")
    if current.get("authority") != RUNTIME_LAUNCH_CLOUD_AUTHORITY:
        raise CliError(RUNTIME_ATTESTATION_ERROR, "worker dispatch requires a cloud-chain runtime seed")
    if not manifest_value:
        return current_path
    input_paths = current.get("input_paths")
    input_paths = input_paths if isinstance(input_paths, Mapping) else {}
    chain_spec_value = str(input_paths.get("chain_spec") or "").strip()
    marker_value = str(input_paths.get("marker") or "").strip()
    if not chain_spec_value or not marker_value:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "orchestration seed lacks chain_spec or marker dispatch inputs",
        )
    manifest_path = Path(manifest_value).expanduser().resolve(strict=False)
    lock_path = Path(f"{manifest_path}.promotion.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_SH)
        selected = ensure_runtime_launch_seed(
            manifest_path=manifest_path,
            chain_spec_path=Path(chain_spec_value),
            marker_path=Path(marker_value),
            chain_runtime_identity=(
                current.get("chain_runtime_binding", {}).get("runtime_identity")
                if isinstance(current.get("chain_runtime_binding"), Mapping)
                else None
            ),
        )
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
    os.environ["MEGAPLAN_RUNTIME_LAUNCH_SEED"] = str(selected)
    return selected


def _verify_seed_digest(seed: Mapping[str, Any]) -> None:
    core = {key: value for key, value in seed.items() if key != "content_sha256"}
    authority = seed.get("authority")
    if (
        seed.get("schema") != RUNTIME_LAUNCH_SEED_SCHEMA
        or not isinstance(authority, str)
        or authority not in RUNTIME_LAUNCH_AUTHORITIES
        or not isinstance(seed.get("content_sha256"), str)
        or seed.get("content_sha256") != _canonical_sha256(core)
    ):
        raise CliError(
            RUNTIME_ATTESTATION_ERROR, "runtime launch seed digest is invalid"
        )


def runtime_vector_sha256(seed: Mapping[str, Any]) -> str:
    """Hash the complete loaded-code vector carried by a verified launch seed."""

    return _canonical_sha256(
        {
            "modules": seed.get("loaded_modules"),
            "interpreter": seed.get("interpreter"),
            "pth": seed.get("site_pth"),
            "wrappers": seed.get("wrappers"),
        }
    )


def _component_runtime_vector_sha256(
    seed: Mapping[str, Any],
    *,
    component: str,
) -> str:
    if component in _SUPERVISOR_COMPONENTS:
        return _canonical_sha256(
            {
                "runtime": seed.get("supervisor_runtime"),
                "wrappers": seed.get("wrappers"),
            }
        )
    return runtime_vector_sha256(seed)


def validate_runtime_launch_seed(
    seed: Mapping[str, Any],
    *,
    component: str,
) -> dict[str, Any]:
    """Revalidate a launch seed against files, imports, and current interpreter.

    Only modules the validating worker actually imported are compared; seed
    entries absent from the worker (e.g. chain-CLI-only builder imports) are
    allowed.  Modules present in both sides must match identically.
    """

    _verify_seed_digest(seed)
    authority = seed.get("authority")
    if authority == RUNTIME_LAUNCH_STANDALONE_AUTHORITY:
        return validate_standalone_runtime_launch_seed(seed, component=component)
    if authority != RUNTIME_LAUNCH_CLOUD_AUTHORITY:
        raise CliError(RUNTIME_ATTESTATION_ERROR, "runtime launch seed authority is invalid")
    if not bool(seed.get("ready")) or seed.get("errors"):
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "runtime launch seed was not release-ready",
        )
    root = Path(str(seed.get("expected_root") or "")).resolve(strict=False)
    revision = str(seed.get("expected_revision") or "")
    is_supervisor = component in _SUPERVISOR_COMPONENTS
    supervisor = seed.get("supervisor_receipt")
    supervisor = supervisor if isinstance(supervisor, Mapping) else {}
    if is_supervisor:
        current_runtime = supervisor_runtime_vector(
            expected_source=root,
            expected_revision=revision,
            expected_runtime=Path(str(supervisor.get("runtime") or "")),
            expected_fingerprint=str(supervisor.get("fingerprint") or ""),
        )
        if current_runtime != seed.get("supervisor_runtime"):
            raise CliError(
                RUNTIME_ATTESTATION_ERROR,
                "dedicated supervisor runtime vector drifted",
            )
        expected_runtime = seed.get("supervisor_runtime")
        expected_runtime = expected_runtime if isinstance(expected_runtime, Mapping) else {}
        expected_modules = expected_runtime.get("loaded_modules")
        module_root = Path(str(supervisor.get("runtime") or "")).resolve(strict=False)
    else:
        # Codex fix 2026-08-17: exact provenance check restored. The seed's
        # ``expected_revision`` is IMMUTABLE once issued — validation must
        # never read the seed's manifest path and silently replace it with a
        # newer accepted head (that mutates the meaning of the signed seed
        # after issuance). The live checkout revision, import root, module
        # identities, and direct_url must equal the seed exactly.
        provenance = runtime_provenance(
            expected_root=root,
            expected_revision=revision,
        )
        if not provenance.get("ok"):
            raise CliError(
                RUNTIME_ATTESTATION_ERROR,
                f"runtime provenance changed: {provenance.get('errors')}",
            )
        if provenance != seed.get("runtime_provenance"):
            raise CliError(
                RUNTIME_ATTESTATION_ERROR,
                "runtime provenance or direct_url identity drifted",
            )
        expected_modules = seed.get("loaded_modules")
        module_root = root
    modules, module_errors = (
        _supervisor_module_vector(module_root)
        if is_supervisor
        else _module_vector(module_root)
    )
    if module_errors:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "loaded Arnold modules escaped the expected root: "
            + ", ".join(module_errors),
        )
    if not isinstance(expected_modules, list):
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "runtime launch seed has no loaded Arnold module vector",
        )
    current_by_name = {item["module"]: item for item in modules}
    for expected_module in expected_modules:
        if not isinstance(expected_module, Mapping):
            raise CliError(
                RUNTIME_ATTESTATION_ERROR,
                "runtime launch seed contains an invalid module identity",
            )
        name = str(expected_module.get("module") or "")
        current = current_by_name.get(name)
        if current is not None and current != expected_module:
            raise CliError(
                RUNTIME_ATTESTATION_ERROR,
                f"loaded module identity changed: {name or '<missing>'}",
            )
    pth, pth_errors = _pth_vector(module_root)
    expected_pth = (
        (seed.get("supervisor_runtime") or {}).get("site_pth")
        if is_supervisor
        else seed.get("site_pth")
    )
    # T-0302 (grok consult 2026-08-17): the seed's site_pth may have been
    # recorded by an older builder with a different dict shape (lines[].raw
    # vs path/sha256/site_dir). The CUSTODY property is: no active .pth
    # resolves to a DIFFERENT Arnold root than the expected module root, and
    # nothing executable is unowned. Compare that semantic predicate instead
    # of exact dict equality, so a shape-drift seed still validates.
    pth_semantic_mismatch = False
    if pth != expected_pth:
        expected_root_resolved = module_root.resolve(strict=False)

        def _pth_targets(records):
            targets = set()
            if not isinstance(records, list):
                return targets
            for record in records:
                if not isinstance(record, dict):
                    continue
                for entry in record.get("lines", []):
                    if not isinstance(entry, dict):
                        continue
                    kind = entry.get("kind")
                    resolved = str(entry.get("resolved") or "")
                    if kind == "path" and resolved:
                        targets.add(resolved)
                    elif kind in ("executable", None):
                        targets.add("executable")
            return targets

        live_targets = _pth_targets(pth)
        seed_targets = _pth_targets(expected_pth)
        foreign = [
            t
            for t in live_targets
            if t != "executable" and not Path(t).is_relative_to(expected_root_resolved)
        ]
        pth_semantic_mismatch = bool(foreign) or (
            bool(seed_targets) and live_targets != seed_targets
        )
    if pth_errors or pth_semantic_mismatch:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "active site .pth vector changed or is unsafe: " + ", ".join(pth_errors),
        )
    wrappers, wrapper_errors = _wrapper_vector(root)
    # Codex fix 2026-08-17: wrapper CONTENT identities must match the seed
    # exactly (digests). The name-only comparison was insufficient — modified
    # wrapper contents could pass an old seed. No revision tolerance.
    if wrapper_errors or wrappers != seed.get("wrappers"):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "runtime wrapper manifest drifted")
    expected_interpreter = seed.get("interpreter")
    if is_supervisor:
        runtime = str(supervisor.get("runtime") or "")
        if not runtime or Path(sys.prefix).resolve(strict=False) != Path(
            runtime
        ).resolve(strict=False):
            raise CliError(
                RUNTIME_ATTESTATION_ERROR,
                "supervisor interpreter does not match its prepared runtime",
            )
    else:
        current_interpreter = _interpreter_vector(
            direct_url=(
                provenance.get("direct_url")
                if isinstance(provenance.get("direct_url"), Mapping)
                else {}
            )
        )
        if current_interpreter != expected_interpreter:
            raise CliError(
                RUNTIME_ATTESTATION_ERROR, "runtime interpreter identity drifted"
            )
        # Codex fix 2026-08-17: the live interpreter must belong to the seed's
        # dependency generation (when the seed carries one). A worker running
        # under a different dependency generation fails closed.
        dep_generation = seed.get("dependency_generation")
        dep_generation = dep_generation if isinstance(dep_generation, Mapping) else {}
        if dep_generation:
            dep_interpreter = str(dep_generation.get("interpreter_path") or "")
            if not dep_interpreter or Path(dep_interpreter).expanduser().resolve(
                strict=False
            ) != Path(sys.executable).resolve(strict=True):
                raise CliError(
                    RUNTIME_ATTESTATION_ERROR,
                    "runtime interpreter does not match the seed's dependency generation",
                )
    paths = seed.get("input_paths")
    paths = paths if isinstance(paths, Mapping) else {}
    # Chain-spec full-file hash is advisory (see build_runtime_launch_seed):
    # the chain RUNTIME BINDING below (chain_spec path -> root/revision)
    # still gates, but an ordinary chain.yaml edit must not hard-block every
    # worker launch with "seed document manifest drifted".
    manifest_paths = [
        Path(str(paths.get(name) or ""))
        for name in ("supervisor_receipt", "hot_env")
    ]
    manifest_paths.extend(Path(str(path)) for path in paths.get("seed_docs") or [])
    if not _manifest_matches(manifest_paths, seed.get("seed_document_manifest") or {}):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "seed document manifest drifted")
    if _file_identity(Path(str(paths.get("supervisor_receipt") or ""))) != (
        seed.get("supervisor_receipt") or {}
    ).get("file"):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "supervisor receipt drifted")
    if _file_identity(Path(str(paths.get("hot_env") or ""))) != (
        seed.get("hot_env") or {}
    ).get("file"):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "hot-env selector file drifted")
    marker_path = Path(str(paths.get("marker") or ""))
    marker = _json_file(marker_path, label="cloud session marker")
    expected_marker = seed.get("marker")
    expected_marker = expected_marker if isinstance(expected_marker, Mapping) else {}
    if (
        str(marker_path.resolve(strict=False)) != str(expected_marker.get("path") or "")
        or _marker_launch_binding(marker) != expected_marker.get("launch_binding")
    ):
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "cloud marker launch binding drifted",
        )
    live_binding_runtime = _chain_binding_runtime_identity(
        Path(str(paths.get("chain_spec") or ""))
    )
    seed_binding_runtime = (seed.get("chain_runtime_binding") or {}).get(
        "runtime_identity"
    ) or {}
    # Engine change is a NON-EVENT (grok audit 2026-08-18): the chain record
    # may lag the seed when a manifest generation advance adopted the live
    # head. Validate with the same adopt-or-refuse rule — same import_root
    # with a generation advance (or unknown recorded gen) passes and persists
    # the adopted identity; a different import_root or a downgrade still
    # fails closed. This is the SECOND enforcement point (after
    # ensure_runtime_launch_seed) and must agree, or the same engine change
    # re-breaks the epic here with "chain runtime binding drifted".
    if (
        str(live_binding_runtime.get("import_root") or "").rstrip("/")
        != str(seed_binding_runtime.get("import_root") or "").rstrip("/")
        or str(live_binding_runtime.get("source_revision") or "")
        != str(seed_binding_runtime.get("source_revision") or "")
    ):
        # The immutable seed is the manifest-pinned live identity; the chain
        # binding is the recorded snapshot that may legitimately lag. Keep
        # the helper's ``recorded, live`` contract in that order so a
        # generation advance is adopted into the chain instead of re-saving
        # its stale identity.
        adopted = _adopt_or_refuse_launch_identity(
            live_binding_runtime,
            seed_binding_runtime,
            recorded_generation=_live_manifest_generation(
                Path(str(paths.get("chain_spec") or ""))
            ),
            live_generation=seed.get("manifest_generation"),
        )
        if (
            str((adopted.get("source_revision") or ""))
            != str((live_binding_runtime.get("source_revision") or ""))
        ):
            _persist_adopted_chain_runtime_identity(
                chain_spec_path=Path(str(paths.get("chain_spec") or "")),
                bound_identity=adopted,
                reason="manifest_generation_adopt_validate",
            )
    return {
        "status": "ready",
        "seed_sha256": seed["content_sha256"],
        "expected_root": str(root),
        "expected_revision": revision,
        "runtime_vector_sha256": _component_runtime_vector_sha256(
            seed,
            component=component,
        ),
    }


def _proc_identity(pid: int) -> dict[str, Any]:
    # Platform-aware process identity (2026-08-22 defect fix): Linux /proc
    # does not exist on macOS, so inspection goes through psutil everywhere.
    # Key names are stable for consumers: create_runtime_process_attestation
    # persists this dict and validate_runtime_process_attestation compares it
    # whole. Only ``start_ticks`` semantics changed — psutil's create_time
    # (seconds since the epoch) replaces Linux stat field 21 clock ticks;
    # both sides of every comparison run this same function, so per-boot
    # PID-reuse protection is preserved.
    import psutil  # lazy: only process inspection needs it (clean-venv imports stay light)

    try:
        process = psutil.Process(pid)
        start_time = str(process.create_time())
        executable_value = str(process.exe() or "")
        raw_environ = process.environ()
    except (psutil.Error, OSError) as exc:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            f"cannot inspect target process {pid}",
        ) from exc
    # psutil can report an empty exe for a just-reaped or restricted
    # target. ``Path("")`` normalizes to "." and is truthy, so emptiness is
    # checked on the raw string BEFORE any Path conversion or digest read;
    # otherwise _sha256_file would leak an untyped IsADirectoryError.
    executable = Path(executable_value)
    if not executable_value:
        raise CliError(RUNTIME_ATTESTATION_ERROR, f"cannot inspect target process {pid}")
    selectors = {
        str(name): str(value)
        for name, value in raw_environ.items()
        if str(name) in RUNTIME_SELECTOR_NAMES
    }
    return {
        "pid": pid,
        "start_ticks": start_time,
        "executable": str(executable),
        "executable_sha256": _sha256_file(executable),
        "selectors": selectors,
    }


def create_runtime_process_attestation(
    seed: Mapping[str, Any],
    *,
    component: str,
    target_pid: int,
) -> dict[str, Any]:
    validation = validate_runtime_launch_seed(seed, component=component)
    process = _proc_identity(target_pid)
    expected_selectors = (seed.get("hot_env") or {}).get("selectors") or {}
    mismatches = {
        name: {"expected": expected, "actual": process["selectors"].get(name, "")}
        for name, expected in expected_selectors.items()
        if process["selectors"].get(name) != expected
    }
    if mismatches:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            f"process inherited stale runtime selectors: {sorted(mismatches)}",
        )
    core = {
        "schema": RUNTIME_PROCESS_ATTESTATION_SCHEMA,
        "authority": seed.get("authority"),
        "component": component,
        "seed_sha256": validation["seed_sha256"],
        "runtime_vector_sha256": validation["runtime_vector_sha256"],
        "process": process,
    }
    return {**core, "content_sha256": _canonical_sha256(core)}


def validate_runtime_process_attestation(
    seed: Mapping[str, Any],
    attestation: Mapping[str, Any],
    *,
    component: str,
    target_pid: int,
) -> dict[str, Any]:
    """Re-confirm a process attestation WITHOUT re-reading a mutable manifest.

    Codex fix 2026-08-17: the full seed validation runs EXACTLY ONCE per
    process, at :func:`create_runtime_process_attestation` (the admission
    point). Subsequent checks in the same process validate only that (a) the
    immutable seed digest still matches, (b) the attestation belongs to the
    same PID/process-start identity, and (c) no Arnold module from a foreign
    root has since been imported. They must NEVER compare against the current
    manifest, the current remote head, or a newly published generation.
    """
    _verify_seed_digest(seed)
    if (
        seed.get("authority") == RUNTIME_LAUNCH_STANDALONE_AUTHORITY
        and component != "resident"
    ):
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "standalone runtime process attestation is resident-only",
        )
    core = {
        key: attestation.get(key)
        for key in (
            "schema",
            "authority",
            "component",
            "seed_sha256",
            "runtime_vector_sha256",
            "process",
        )
    }
    if (
        attestation.get("schema") != RUNTIME_PROCESS_ATTESTATION_SCHEMA
        or attestation.get("authority") != seed.get("authority")
        or attestation.get("content_sha256") != _canonical_sha256(core)
        or attestation.get("component") != component
        or attestation.get("seed_sha256") != seed.get("content_sha256")
        or attestation.get("runtime_vector_sha256")
        != _component_runtime_vector_sha256(seed, component=component)
        or attestation.get("process") != _proc_identity(target_pid)
    ):
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "runtime process attestation is stale or belongs to another process",
        )
    # No mixed-root Arnold modules may have been imported since admission.
    root = Path(str(seed.get("expected_root") or "")).resolve(strict=False)
    is_supervisor = component in _SUPERVISOR_COMPONENTS
    if is_supervisor:
        supervisor = seed.get("supervisor_receipt")
        supervisor = supervisor if isinstance(supervisor, Mapping) else {}
        module_root = Path(str(supervisor.get("runtime") or "")).resolve(strict=False)
    elif seed.get("authority") == RUNTIME_LAUNCH_STANDALONE_AUTHORITY:
        # Standalone seeds separate custody from code: the loaded-module scan
        # binds to the imported Arnold runtime checkout, never the custodied
        # project root.
        module_root = Path(str(seed.get("runtime_root") or "")).resolve(strict=False)
    else:
        module_root = root
    _modules, module_errors = (
        _supervisor_module_vector(module_root)
        if is_supervisor
        else _module_vector(module_root)
    )
    if module_errors:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "loaded Arnold modules escaped the expected root: "
            + ", ".join(module_errors),
        )
    if seed.get("authority") == RUNTIME_LAUNCH_STANDALONE_AUTHORITY:
        return {
            "status": "ready",
            "seed_sha256": seed["content_sha256"],
            "project_root": str(Path(str(seed.get("project_root") or "")).resolve(strict=False)),
            "expected_project_revision": str(seed.get("expected_project_revision") or ""),
            "runtime_root": str(module_root),
            "expected_runtime_revision": str(seed.get("expected_runtime_revision") or ""),
            "runtime_vector_sha256": _component_runtime_vector_sha256(
                seed,
                component=component,
            ),
        }
    return {
        "status": "ready",
        "seed_sha256": seed["content_sha256"],
        "expected_root": str(root),
        "expected_revision": str(seed.get("expected_revision") or ""),
        "runtime_vector_sha256": _component_runtime_vector_sha256(
            seed,
            component=component,
        ),
    }


def _atomic_write(path: Path, payload: Mapping[str, Any]) -> None:
    path = path.resolve(strict=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def configured_runtime_attestation_required() -> bool:
    """Return ``True`` unless runtime attestation is explicitly disabled.

    Deny-by-default: runtime attestation is REQUIRED when
    ``MEGAPLAN_RUNTIME_ATTESTATION_REQUIRED`` is absent or any value other
    than ``"0"``.  Only an explicit ``"0"`` opts out.

    Note: the flag cannot waive the launch-seed requirement — a production
    launch always needs ``MEGAPLAN_RUNTIME_LAUNCH_SEED`` (see
    :func:`require_configured_runtime_launch`, which fails closed on a
    missing seed regardless of this flag).
    """
    return os.environ.get("MEGAPLAN_RUNTIME_ATTESTATION_REQUIRED") != "0"


def configured_seed_path() -> Path | None:
    value = str(os.environ.get("MEGAPLAN_RUNTIME_LAUNCH_SEED") or "").strip()
    return Path(value).expanduser().resolve(strict=False) if value else None


def readonly_seed_runtime_identity(
    spec_path: Path,
) -> dict[str, Any] | None:
    """Read-only extractor for the launch seed's runtime identity.

    Validates the seed digest, readiness, chain-spec path, and runtime-identity
    shape WITHOUT performing the circular chain-binding comparison.  Returns
    the normalized identity dict when the seed is valid and populated, or
    ``None`` when the seed is absent.

    Raises ``CliError`` (``RUNTIME_ATTESTATION_ERROR``) on any validation
    failure: digest mismatch, unready seed, wrong spec, absent or malformed
    runtime identity.
    """
    seed_path = configured_seed_path()
    if seed_path is None or not seed_path.exists():
        return None
    seed = _json_file(seed_path, label="runtime launch seed")
    _verify_seed_digest(seed)
    if not bool(seed.get("ready")) or seed.get("errors"):
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "runtime launch seed is not release-ready for identity bootstrap",
        )
    # Verify the seed points at the active spec.
    input_paths = seed.get("input_paths") or {}
    seed_spec = str(input_paths.get("chain_spec") or "").rstrip("/")
    if seed_spec != str(spec_path.resolve(strict=False)).rstrip("/"):
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            f"runtime launch seed chain_spec {seed_spec} does not match "
            f"the active spec {spec_path}",
        )
    # Extract and validate chain_runtime_binding.runtime_identity.
    chain_binding = seed.get("chain_runtime_binding") or {}
    seed_identity = chain_binding.get("runtime_identity") or {}
    if not isinstance(seed_identity, Mapping) or not seed_identity.get(
        "import_root"
    ) or not seed_identity.get("source_revision"):
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "runtime launch seed chain_runtime_binding.runtime_identity "
            "is absent or incomplete",
        )
    # Verify digest-valid when content_sha256 is present.
    supplied_digest = seed_identity.get("content_sha256")
    if supplied_digest:
        from arnold_pipelines.megaplan.chain.execution_binding import (
            _normalized_runtime_identity,
        )

        computed = _normalized_runtime_identity(seed_identity)
        if computed.get("content_sha256") != supplied_digest:
            raise CliError(
                RUNTIME_ATTESTATION_ERROR,
                "runtime launch seed runtime_identity digest is invalid",
            )
    # Verify root/revision agree with the seed's expected root/revision.
    expected_root = str(seed.get("expected_root") or "").rstrip("/")
    expected_revision = str(seed.get("expected_revision") or "")
    import_root = str(seed_identity.get("import_root") or "").rstrip("/")
    source_revision = str(seed_identity.get("source_revision") or "")
    if expected_root and expected_root != import_root:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            f"runtime launch seed import_root {import_root} does not match "
            f"expected_root {expected_root}",
        )
    if expected_revision and expected_revision != source_revision:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            f"runtime launch seed source_revision {source_revision} does not "
            f"match expected_revision {expected_revision}",
        )
    return dict(seed_identity)


def configured_process_attestation_path(
    component: str, *, seed: Mapping[str, Any] | None = None
) -> Path:
    value = str(os.environ.get("MEGAPLAN_RUNTIME_PROCESS_ATTESTATION") or "").strip()
    if seed is not None and seed.get("authority") == RUNTIME_LAUNCH_STANDALONE_AUTHORITY:
        return standalone_runtime_launch_dir(Path(str(seed.get("project_root") or "")), create=False) / "status" / (
            f"{component}.runtime-process-attestation.json"
        )
    if value:
        return Path(value).expanduser().resolve(strict=False)
    return (
        Path("/workspace/.megaplan/status")
        / f"{component}.runtime-process-attestation.json"
    )


def ensure_standalone_launch_seed_binds_root(project_root: Path | None) -> None:
    """Bind the launching project root to the configured standalone seed.

    Generated launchers, systemd units, and manual invocations reach resident
    startup through :func:`require_configured_runtime_launch`, whose
    standalone branch derives custody solely from ``seed["project_root"]``.
    Without an explicit binding, a valid seed admitted for one project can
    authorize resident startup in another.  This preflight rejects such a
    mismatch, typed and fail-closed, before any process-status mutation or
    downstream profile/runner/service construction.  Cloud-authority seeds
    and absent or unreadable configurations stay under
    :func:`require_configured_runtime_launch`'s canonical handling.
    """
    if project_root is None:
        return
    seed_path = configured_seed_path()
    if seed_path is None:
        # The canonical loader owns the missing-seed error.
        return
    try:
        seed = _json_file(seed_path, label="runtime launch seed")
    except CliError:
        # Deep validation and its typed errors remain canonical.
        return
    if seed.get("authority") != RUNTIME_LAUNCH_STANDALONE_AUTHORITY:
        return
    seeded_root = Path(str(seed.get("project_root") or "")).resolve(strict=False)
    expected_root = Path(project_root).expanduser().resolve(strict=False)
    if seeded_root != expected_root:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "configured resident launch seed was admitted for a different project root",
        )


def _validate_standalone_dispatch_binding(seed: Mapping[str, Any]) -> None:
    """Bind a configured standalone seed to its published dispatch pointer.

    The configured name must be absolute after cwd resolution (a relative
    ``MEGAPLAN_RUNTIME_LAUNCH_SEED`` resolves against the caller's working
    directory exactly like :func:`configured_seed_path`), must not itself be
    a symlink, must be the pointer's published seed, and must carry the
    pointer's digest.
    """
    raw_seed_value = str(os.environ.get("MEGAPLAN_RUNTIME_LAUNCH_SEED") or "").strip()
    raw_seed_path = Path(raw_seed_value).expanduser() if raw_seed_value else None
    if raw_seed_path is not None and not raw_seed_path.is_absolute():
        # Resolve against the cwd WITHOUT following symlinks: the is_symlink
        # check below inspects the configured name itself.
        raw_seed_path = Path(os.path.abspath(raw_seed_path))
    if (
        raw_seed_path is None
        or not raw_seed_path.is_absolute()
        or raw_seed_path.is_symlink()
    ):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "configured resident seed path is a symlink or missing")
    pointer = load_standalone_runtime_dispatch_pointer(Path(str(seed.get("project_root") or "")))
    if Path(str(pointer.get("seed_path") or "")) != raw_seed_path:
        raise CliError(RUNTIME_ATTESTATION_ERROR, "configured resident seed is not the published dispatch seed")
    if pointer.get("seed_sha256") != seed.get("content_sha256"):
        raise CliError(RUNTIME_ATTESTATION_ERROR, "configured resident seed digest does not match dispatch pointer")


def preflight_configured_launch_seed(
    project_root: Path | None = None,
) -> dict[str, Any] | None:
    """Load and validate a CONFIGURED launch seed; require nothing.

    Dry-run deployments keep custody signal without custody obligations: a
    configured seed is loaded and digest/authority-validated (standalone
    seeds additionally re-validate live evidence and their dispatch-pointer
    binding), while an unset configuration behaves exactly as if no
    attestation existed.  No process status is created, and no network,
    token, runner, or service surface is touched.
    """
    ensure_standalone_launch_seed_binds_root(project_root)
    seed_path = configured_seed_path()
    if seed_path is None:
        return None
    seed = _json_file(seed_path, label="runtime launch seed")
    authority = seed.get("authority")
    if not isinstance(authority, str) or authority not in RUNTIME_LAUNCH_AUTHORITIES:
        raise CliError(RUNTIME_ATTESTATION_ERROR, "runtime launch seed authority is invalid")
    if authority == RUNTIME_LAUNCH_STANDALONE_AUTHORITY:
        _validate_standalone_dispatch_binding(seed)
        validate_standalone_runtime_launch_seed(seed)
    else:
        _verify_seed_digest(seed)
    return seed


def require_configured_runtime_launch(
    component: str,
    *,
    target_pid: int | None = None,
    create: bool = False,
) -> dict[str, Any]:
    seed_path = configured_seed_path()
    if seed_path is None:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "canonical runtime launch seed is required but missing",
        )
    seed = _json_file(seed_path, label="runtime launch seed")
    authority = seed.get("authority")
    if not isinstance(authority, str) or authority not in RUNTIME_LAUNCH_AUTHORITIES:
        raise CliError(RUNTIME_ATTESTATION_ERROR, "runtime launch seed authority is invalid")
    if authority == RUNTIME_LAUNCH_STANDALONE_AUTHORITY:
        _validate_standalone_dispatch_binding(seed)
    pid = target_pid or os.getpid()
    attestation_path = configured_process_attestation_path(component, seed=seed)
    if authority == RUNTIME_LAUNCH_STANDALONE_AUTHORITY:
        state = standalone_runtime_launch_dir(Path(str(seed.get("project_root") or "")), create=create)
        _require_standalone_operational_dir(state, "status", create=create)
        if attestation_path.is_symlink():
            raise CliError(RUNTIME_ATTESTATION_ERROR, "resident process attestation path is a symlink")
        try:
            attestation_path.resolve(strict=False).relative_to(state.resolve(strict=True))
        except ValueError as exc:
            raise CliError(RUNTIME_ATTESTATION_ERROR, "resident process attestation path escaped state directory") from exc
    if create:
        attestation = create_runtime_process_attestation(
            seed,
            component=component,
            target_pid=pid,
        )
        _atomic_write(attestation_path, attestation)
    else:
        if authority == RUNTIME_LAUNCH_STANDALONE_AUTHORITY:
            try:
                if stat.S_IMODE(attestation_path.stat().st_mode) != 0o600:
                    raise CliError(
                        RUNTIME_ATTESTATION_ERROR,
                        "resident process attestation permissions are unsafe",
                    )
            except OSError as exc:
                raise CliError(
                    RUNTIME_ATTESTATION_ERROR,
                    "runtime process attestation is unreadable",
                ) from exc
        attestation = _json_file(
            attestation_path,
            label="runtime process attestation",
        )
        validate_runtime_process_attestation(
            seed,
            attestation,
            component=component,
            target_pid=pid,
        )
    return seed


def _legacy_require_production_worker_dispatch_runtime(
    *,
    component: str = "worker",
    create_process_attestation: bool = True,
    demand_seed: bool = True,
) -> dict[str, Any] | None:
    """Admission gate for production phase/backend dispatch.

    Occurrence 12f5e50e0107 (2026-08-26): parallel critique producers and
    gate reached ``workers/omp.py::_write_phase_output_tool`` via backend
    adapters that never pass :func:`run_step_with_worker`, then died late
    with ImportError("omp_rpc host_tools module is unavailable") because the
    DISPATCHING interpreter was not the manifest-bound dependency-generation
    interpreter. This helper serves BOTH boundaries with a single contract:

    * Orchestration boundary (``workers/_impl.py``, ``demand_seed=True``):
      the seed requirement is UNCONDITIONAL — byte-for-byte the previous
      run_step_with_worker contract (refresh + require + attestation).
    * Backend boundary (``run_omp_step``, ``demand_seed=False``): enforcement
      keys off the PRODUCTION binding. With no ``ARNOLD_RUNTIME_MANIFEST``
      and no configured seed the call is a no-op so manifestless development
      and unit harnesses keep working; with the binding present it demands
      the seed and refuses any interpreter that does not realpath-match that
      binding's dependency-generation interpreter and the seed's own
      binding. Fails closed typed and early instead of late and confusing.
    """
    manifest_raw = str(os.environ.get("ARNOLD_RUNTIME_MANIFEST") or "").strip()
    if not demand_seed and not manifest_raw and configured_seed_path() is None:
        return None
    refresh_runtime_launch_seed_for_worker_dispatch()
    seed = require_configured_runtime_launch(
        component,
        create=create_process_attestation,
    )
    if not manifest_raw:
        return seed
    actual = os.path.realpath(sys.executable)
    try:
        from arnold_pipelines.megaplan.cloud.runtime_manifest import (
            ManifestError,
            load_manifest,
        )

        try:
            manifest = load_manifest(Path(manifest_raw))
        except ManifestError as exc:
            raise CliError(
                RUNTIME_ATTESTATION_ERROR,
                f"runtime manifest {manifest_raw} is invalid: {exc}",
            ) from exc
    except OSError as exc:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            f"runtime manifest {manifest_raw} is unreadable: {exc}",
        ) from exc
    dep = manifest.epic.get("dependency_generation")
    dep = dep if isinstance(dep, Mapping) else {}
    expected = os.path.realpath(str(dep.get("interpreter_path") or ""))
    if not expected or expected != actual:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "worker dispatch requires the manifest dependency-generation "
            f"interpreter: expected {expected or '<unset>'}, running "
            f"{actual} (relaunch through arnold-chain)",
        )
    seed_dep = seed.get("dependency_generation")
    seed_dep = seed_dep if isinstance(seed_dep, Mapping) else {}
    seed_dep_interpreter = str(seed_dep.get("interpreter_path") or "")
    if (
        not seed_dep_interpreter
        or os.path.realpath(seed_dep_interpreter) != expected
    ):
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "worker dispatch launch seed is bound to a different "
            "dependency-generation interpreter",
        )
    interp = seed.get("interpreter")
    interp = interp if isinstance(interp, Mapping) else {}
    seed_executable = str(interp.get("executable") or "")
    if not seed_executable or os.path.realpath(seed_executable) != actual:
        raise CliError(
            RUNTIME_ATTESTATION_ERROR,
            "runtime interpreter identity drifted",
        )
    return seed
def require_production_worker_dispatch_runtime(request: Any = None, **legacy_kwargs: Any) -> Any:
    """Single production admission authority.

    The historical seed-only call remains available for startup callers.  A
    typed ``WorkerAdmissionRequest`` is delegated to the canonical admission
    implementation, keeping the public authority name stable for all doors.
    """
    if request is None:
        return _legacy_require_production_worker_dispatch_runtime(**legacy_kwargs)
    from arnold_pipelines.megaplan.cloud.worker_dispatch import (
        require_production_worker_dispatch_runtime as _admit,
    )
    return _admit(request, **legacy_kwargs)




def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    build = sub.add_parser("build")
    build.add_argument("--expected-root", type=Path, required=True)
    build.add_argument("--expected-revision", required=True)
    build.add_argument("--supervisor-receipt", type=Path, required=True)
    build.add_argument("--hot-env", type=Path, required=True)
    build.add_argument("--marker", type=Path, required=True)
    build.add_argument("--chain-spec", type=Path, required=True)
    build.add_argument("--seed-doc", type=Path, action="append", default=[])
    build.add_argument("--manifest", type=Path, default=None)
    build.add_argument("--output", type=Path, required=True)
    startup = sub.add_parser("startup")
    startup.add_argument("--component", required=True)
    startup.add_argument("--target-pid", type=int, required=True)
    verify = sub.add_parser("verify-process")
    verify.add_argument("--component", required=True)
    verify.add_argument("--target-pid", type=int, required=True)
    probe = sub.add_parser("probe-supervisor")
    probe.add_argument("--expected-source", type=Path, required=True)
    probe.add_argument("--expected-revision", required=True)
    probe.add_argument("--expected-runtime", type=Path, required=True)
    probe.add_argument("--expected-fingerprint", required=True)
    args = parser.parse_args(argv)
    if args.action == "build":
        payload = build_runtime_launch_seed(
            expected_root=args.expected_root,
            expected_revision=args.expected_revision,
            supervisor_receipt_path=args.supervisor_receipt,
            hot_env_path=args.hot_env,
            marker_path=args.marker,
            chain_spec_path=args.chain_spec,
            seed_doc_paths=args.seed_doc,
            manifest_path=args.manifest,
        )
        _atomic_write(args.output, payload)
        print(json.dumps(payload, sort_keys=True))
        return 0 if payload["ready"] else 2
    if args.action == "probe-supervisor":
        payload = supervisor_runtime_vector(
            expected_source=args.expected_source,
            expected_revision=args.expected_revision,
            expected_runtime=args.expected_runtime,
            expected_fingerprint=args.expected_fingerprint,
        )
        print(json.dumps(payload, sort_keys=True))
        return 0 if payload["ready"] else 2
    require_configured_runtime_launch(
        args.component,
        target_pid=args.target_pid,
        create=args.action == "startup",
    )
    print(json.dumps({"success": True, "component": args.component}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
