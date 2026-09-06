"""Content-addressed dependency-generation lifecycle (T-0301).

The editable-install sync path is RETIRED.  Dependencies are frozen into ONE
immutable venv per frozen dependency spec — the ``pyproject.toml`` +
``uv.lock`` pair and any in-repository directory/path source bytes — and that
generation is shared by EVERY runtime that resolves to the same spec (the
content address IS the sha256 of the frozen spec). There is no per-worktree
``.venv`` and no ``pip install -e`` anywhere.

This module owns the generation store contract:

* :func:`frozen_spec_sha256` — the content address of a project's frozen
  spec (pyproject.toml + uv.lock + frozen path-source bytes, deterministic).
* :func:`ensure_dependency_generation` — build-or-verify the generation at
  ``<generations_root>/<address>`` ONCE under a single-writer flock
  (``<generations_root>/.build.lock``); concurrent runtimes resolving the
  same spec serialize and share the same immutable venv.
* :func:`verify_generation` — on-disk verification of an existing
  generation: proof file matches the content address, interpreter exists
  and is executable, and (deep) the recomputed pip-list venv digest equals
  the recorded one.
* :func:`compute_venv_digest` — the deterministic sha256 of the installed
  package set (``pip list --format=json``, sorted).

Fail-closed invariants:

* A project WITHOUT a frozen spec (missing pyproject.toml or uv.lock)
  cannot build a generation — :class:`GenerationError`, no manifest without
  proof.
* An EXISTING generation that fails verification is NEVER silently reused
  or overwritten (the store is immutable): :class:`GenerationError`.
* The dependency install is pinned by uv.lock (``name==version`` from
  registry sources plus frozen directory/path sources via pip, or
  ``uv sync --frozen --no-install-project`` when uv is available);
  git/url/editable sources are skipped by the pip path — in particular,
  the editable project root is NEVER installed into the generation
  (worktree-first ``PYTHONPATH`` supplies runtime code at launch).

``apply_install_sync`` survives ONLY as the retired path's fail-closed
landing: it raises :class:`EditableInstallRetiredError` so any residual
caller (the meta-repair loop) fails loudly instead of silently skipping the
sync concept.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from arnold_pipelines.megaplan.cloud.redact import redact_text

Runner = Callable[..., subprocess.CompletedProcess[str]]

# The frozen dependency spec: BOTH files must exist under the project root.
# ``deps_lockfile`` in the runtime manifest names the lockfile; the content
# address covers the pair plus in-repository path-source bytes, so a dependency
# edit, re-lock, or vendored dependency edit yields a NEW generation.
FROZEN_SPEC_FILENAMES = ("pyproject.toml", "uv.lock")

_FULL_HEX64 = __import__("re").compile(r"^[0-9a-f]{64}$")


class GenerationError(RuntimeError):
    """A dependency generation could not be built or verified (T-0301).

    Fail-closed: the generation store is immutable and content-addressed; a
    missing frozen spec, a failed build, or an unverifiable existing
    generation raises this instead of silently reusing or rebuilding.
    """


class EditableInstallRetiredError(RuntimeError):
    """The editable-install sync path is RETIRED (T-0301).

    Dependencies are immutable content-addressed generations built by
    ``arnold-runtime-create``; there is no mutable editable install to sync.
    Any residual caller fails loudly here — the sync concept is retired,
    never silently skipped and never a ``pip install -e``.
    """

    code = "editable_install_retired"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _run(
    command: list[str],
    *,
    cwd: Path,
    runner: Runner,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    kwargs: dict[str, Any] = {
        "cwd": str(cwd),
        "capture_output": True,
        "text": True,
        "check": False,
    }
    if env is not None:
        kwargs["env"] = dict(env)
    return runner(command, **kwargs)


def _tail(text: str, *, max_lines: int = 20) -> str:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text.strip()
    return "\n".join(lines[-max_lines:]).strip()


def _redacted_tail(text: str) -> str:
    return redact_text(_tail(text or ""))


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    """Atomic tmp-file + ``os.replace`` write (fsync before rename)."""
    path = Path(path).expanduser().resolve(strict=False)
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


# ── frozen spec → content address ────────────────────────────────────────────


def frozen_spec_sha256(project_root: Path | str) -> str:
    """The content address of *project_root*'s frozen dependency spec.

    sha256 over the deterministic concatenation of the ``pyproject.toml``
    and ``uv.lock`` bytes plus every file under an in-repository frozen
    directory/path source. A missing file or escaping path raises
    :class:`GenerationError` (fail-closed: no frozen spec, no generation).
    """
    project = Path(project_root).expanduser().resolve()
    digest = hashlib.sha256()
    lock_text = ""
    for filename in FROZEN_SPEC_FILENAMES:
        path = project / filename
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise GenerationError(
                f"frozen dependency spec file {path} is unreadable: {exc} — "
                "a runtime cannot be created without a frozen spec "
                "(pyproject.toml + uv.lock)"
            ) from exc
        digest.update(filename.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content)
        if filename == "uv.lock":
            try:
                lock_text = content.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise GenerationError(
                    f"frozen dependency lock {path} is not UTF-8"
                ) from exc
    for source_path, source_root in _frozen_path_source_roots(project, lock_text):
        digest.update(b"path-source\0")
        digest.update(source_path.encode("utf-8"))
        digest.update(b"\0")
        for path in sorted(source_root.rglob("*")):
            if path.is_symlink():
                raise GenerationError(f"frozen path source contains symlink: {path}")
            if not path.is_file():
                continue
            relative = path.relative_to(source_root).as_posix()
            try:
                content = path.read_bytes()
            except OSError as exc:
                raise GenerationError(
                    f"frozen path source file {path} is unreadable: {exc}"
                ) from exc
            digest.update(relative.encode("utf-8"))
            digest.update(b"\0")
            digest.update(content)
    return digest.hexdigest()


# ── uv.lock freeze ───────────────────────────────────────────────────────────


def _parse_uv_lock_packages(lock_text: str) -> list[dict[str, Any]]:
    """Minimal dependency-free parser for uv.lock ``[[package]]`` blocks.

    Extracts ``name``, ``version`` and the source kind (``registry`` |
    ``git`` | ``editable`` | ``directory`` | ``path`` | ``url``) per
    package.  Robust for the pinned-freeze purpose; not a full TOML parser.
    A package without an explicit source is treated as registry (uv.lock v1
    omits ``source`` for default-index packages).
    """
    packages: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_source = False
    for raw in lock_text.splitlines():
        line = raw.strip()
        if line.startswith("[["):
            current = {"source": "registry"}
            packages.append(current)
            in_source = False
        elif current is None:
            continue
        elif line.startswith("name = "):
            current["name"] = line[len("name = ") :].strip().strip('"')
        elif line.startswith("version = "):
            current["version"] = line[len("version = ") :].strip().strip('"')
        elif line.startswith("source = {"):
            # Both single-line (``source = { registry = "..." }``) and
            # multi-line source blocks occur in uv.lock v1.
            remainder = line[len("source = {") :].strip()
            if remainder.endswith("}"):
                remainder = remainder[:-1].strip()
                in_source = False
                if remainder:
                    key, _, value = remainder.partition("=")
                    _set_package_source(current, key.strip(), value)
            else:
                in_source = True
        elif in_source:
            if line == "}":
                in_source = False
            elif line.startswith(
                ("git", "url", "editable", "directory", "path", "registry", "index")
            ):
                key, _, value = line.partition("=")
                _set_package_source(current, key.strip(), value)
    return packages


def _set_package_source(package: dict[str, Any], key: str, value: str = "") -> None:
    """Record the source kind of a uv.lock package from the source-block
    key (registry/index/git/url/editable/directory/path)."""
    if key in ("registry", "index"):
        package["source"] = "registry"
    elif key in ("git", "url", "editable", "directory", "path"):
        package["source"] = key
        if key in ("directory", "path"):
            source_path = value.strip().rstrip(",").strip().strip("\"'")
            if source_path:
                package["source_path"] = source_path
    # unknown keys leave the default ("registry") — fail-open on the side of
    # trying the frozen pin, which pip will refuse loudly if it is wrong.


def frozen_requirements(uv_lock_text: str) -> list[str]:
    """Pinned ``name==version`` requirements for every REGISTRY-sourced
    package in *uv_lock_text* (sorted, deduped).

    Directory/path sources are returned separately by
    :func:`frozen_path_sources`. Git, URL, and editable sources are omitted;
    in particular, the editable project root must NOT be installed into the
    generation (worktree-first ``PYTHONPATH`` supplies runtime code).
    """
    requirements: list[str] = []
    for package in _parse_uv_lock_packages(uv_lock_text):
        name = str(package.get("name") or "")
        version = str(package.get("version") or "")
        if package.get("source") != "registry" or not name or not version:
            continue
        requirements.append(f"{name}=={version}")
    return sorted(set(requirements))


def _marker_aware_frozen_requirements(uv_lock_text: str) -> list[str]:
    """Return frozen registry pins with lock dependency markers preserved.

    ``uv.lock`` contains packages for every supported interpreter, while the
    old pip fallback flattened every registry package into an unconditional
    ``name==version`` requirement.  That turns a valid conditional edge such
    as discord-py's ``audioop-lts`` dependency (Python >= 3.13) into an
    impossible install on Python 3.11/3.12.  Keep the exact frozen pin but
    carry the marker along each dependency path so pip evaluates it against
    the generation's bound interpreter.

    Only registry packages reachable from an editable workspace package are
    emitted.  Optional dependencies are selected only when the lock includes
    them in the package's ``dependencies`` list; merely declaring an
    ``optional-dependencies`` table does not activate an extra.

    The lock is an executable dependency graph for this fallback.  A missing
    or ambiguous required edge is therefore an invalid frozen spec, not a
    reason to guess or install an unrelated package.
    """
    try:
        lock = tomllib.loads(uv_lock_text)
    except tomllib.TOMLDecodeError as exc:
        raise GenerationError(f"cannot parse frozen uv.lock: {exc}") from exc
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise GenerationError("frozen uv.lock has no package graph")

    def normalize(name: object) -> str:
        return str(name or "").replace("_", "-").replace(".", "-").lower()

    by_name: dict[str, list[dict[str, Any]]] = {}
    for package in packages:
        if not isinstance(package, dict) or not package.get("name"):
            raise GenerationError("frozen uv.lock has a package with no name")
        by_name.setdefault(normalize(package["name"]), []).append(package)
    roots = [
        package
        for package in packages
        if isinstance(package, dict)
        and isinstance(package.get("source"), dict)
        and "editable" in package["source"]
    ]
    if not roots:
        raise GenerationError("frozen uv.lock has no editable project root")

    def source_kind(package: dict[str, Any]) -> str:
        source = package.get("source")
        if source is None or source == {}:
            return "registry"
        if not isinstance(source, dict):
            raise GenerationError(
                f"frozen uv.lock package {package.get('name')!r} has an invalid source"
            )
        kinds = [
            kind
            for kind in ("registry", "git", "url", "editable", "directory", "path")
            if kind in source
        ]
        if len(kinds) != 1:
            raise GenerationError(
                f"frozen uv.lock package {package.get('name')!r} has an ambiguous source"
            )
        return kinds[0]

    for root in roots:
        root_name = normalize(root.get("name"))
        if len(by_name.get(root_name, [])) != 1:
            raise GenerationError(
                f"frozen uv.lock has an ambiguous project root {root.get('name')!r}"
            )

    # Each entry is one marker expression for a path from the editable root.
    # ``None`` means that path is unconditional.  The graph is small enough
    # that keeping all paths is clearer and safer than boolean-expression
    # simplification.
    paths: dict[str, set[str | None]] = {}
    visiting: set[tuple[str, str | None, tuple[str, ...]]] = set()

    def selected_extras(dependency: dict[str, Any]) -> tuple[str, ...]:
        """Read extras requested by a lock dependency edge."""
        if "extra" in dependency and "extras" in dependency:
            raise GenerationError(
                f"frozen uv.lock dependency {dependency.get('name')!r} has ambiguous extras"
            )
        raw = dependency.get("extra", dependency.get("extras", []))
        if raw is None:
            return ()
        if not isinstance(raw, list) or any(not isinstance(item, str) or not item for item in raw):
            raise GenerationError(
                f"frozen uv.lock dependency {dependency.get('name')!r} has invalid extras"
            )
        return tuple(sorted(set(raw)))

    def walk(
        package: dict[str, Any],
        inherited: str | None,
        extras: tuple[str, ...] = (),
    ) -> None:
        package_name = normalize(package.get("name"))
        state = (package_name, inherited, extras)
        if state in visiting:
            return
        visiting.add(state)
        dependencies = package.get("dependencies", [])
        if not isinstance(dependencies, list):
            raise GenerationError(
                f"frozen uv.lock package {package.get('name')!r} has invalid dependencies"
            )
        optional = package.get("optional-dependencies", {})
        if optional is None:
            optional = {}
        if not isinstance(optional, dict):
            raise GenerationError(
                f"frozen uv.lock package {package.get('name')!r} has invalid optional dependencies"
            )
        selected_optional: list[dict[str, Any]] = []
        for extra in extras:
            entries = optional.get(extra)
            if not isinstance(entries, list):
                raise GenerationError(
                    f"frozen uv.lock package {package.get('name')!r} is missing selected extra {extra!r}"
                )
            selected_optional.extend(entries)

        for dependency in [*dependencies, *selected_optional]:
            if not isinstance(dependency, dict) or not dependency.get("name"):
                raise GenerationError(
                    f"frozen uv.lock package {package.get('name')!r} has a missing dependency edge"
                )
            dependency_name = normalize(dependency.get("name"))
            candidates = by_name.get(dependency_name, [])
            if not candidates:
                raise GenerationError(
                    f"frozen uv.lock package {package.get('name')!r} requires missing package "
                    f"{dependency.get('name')!r}"
                )
            if len(candidates) != 1:
                raise GenerationError(
                    f"frozen uv.lock dependency {dependency.get('name')!r} is ambiguous"
                )
            edge_marker = dependency.get("marker")
            if edge_marker is not None and not isinstance(edge_marker, str):
                raise GenerationError(
                    f"frozen uv.lock dependency {dependency.get('name')!r} has an invalid marker"
                )
            if edge_marker == "":
                raise GenerationError(
                    f"frozen uv.lock dependency {dependency.get('name')!r} has an invalid marker"
                )
            edge_marker = edge_marker or None
            child_extras = selected_extras(dependency)
            if inherited and edge_marker:
                marker = f"({inherited}) and ({edge_marker})"
            else:
                marker = inherited or edge_marker
            paths.setdefault(dependency_name, set()).add(marker)
            walk(candidates[0], marker, child_extras)

    for root in roots:
        if source_kind(root) != "editable":
            raise GenerationError(
                f"frozen uv.lock project root {root.get('name')!r} is not editable"
            )
        walk(root, None)

    requirements: list[str] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = str(package.get("name") or "")
        version = str(package.get("version") or "")
        if not name:
            continue
        package_name = normalize(name)
        if package_name not in paths:
            continue
        if source_kind(package) != "registry":
            continue
        if not version:
            raise GenerationError(
                f"frozen uv.lock registry package {name!r} has no pinned version"
            )
        markers = paths[package_name]
        # An unconditional path makes the marker unnecessary; conditional
        # paths are OR-ed for pip in stable lexical order.
        marker = None
        if markers and None not in markers:
            marker_values = sorted(value for value in markers if value)
            if marker_values:
                marker = " or ".join(
                    value if len(marker_values) == 1 else f"({value})"
                    for value in marker_values
                )
        requirement = f"{name}=={version}"
        if marker:
            requirement += f"; {marker}"
        requirements.append(requirement)
    return sorted(set(requirements))


def frozen_path_sources(uv_lock_text: str) -> list[str]:
    """Frozen relative directory/path sources (sorted, deduped).

    Only uv lock entries explicitly sourced by ``directory`` or ``path``
    participate. Editable workspace members (including the project root),
    git sources, and URL sources remain excluded from the pip strategy.
    """
    paths: list[str] = []
    for package in _parse_uv_lock_packages(uv_lock_text):
        if package.get("source") not in {"directory", "path"}:
            continue
        source_path = str(package.get("source_path") or "").strip()
        if source_path:
            paths.append(source_path)
    return sorted(set(paths))


def _frozen_path_source_roots(
    project: Path, uv_lock_text: str
) -> list[tuple[str, Path]]:
    """Resolve frozen path sources, refusing root/absolute/escaping paths."""
    resolved: list[tuple[str, Path]] = []
    for source_path in frozen_path_sources(uv_lock_text):
        candidate = Path(source_path)
        if candidate.is_absolute():
            raise GenerationError(f"frozen path source must be relative: {source_path}")
        source_root = (project / candidate).resolve(strict=False)
        try:
            source_root.relative_to(project)
        except ValueError as exc:
            raise GenerationError(
                f"frozen path source escapes project root: {source_path}"
            ) from exc
        if source_root == project:
            raise GenerationError("frozen path source cannot be the project root")
        if not source_root.is_dir():
            raise GenerationError(
                f"frozen path source is not a directory: {source_path}"
            )
        resolved.append((source_path, source_root))
    return resolved


# ── generation store ─────────────────────────────────────────────────────────


def generation_dir(generations_root: Path | str, spec_digest: str) -> Path:
    """The content-addressed generation dir ``<root>/<spec_digest>``."""
    if not _FULL_HEX64.fullmatch(spec_digest):
        raise GenerationError(
            f"invalid generation content address {spec_digest!r} (must be 64-char hex)"
        )
    return Path(generations_root).expanduser().resolve(strict=False) / spec_digest


def generation_interpreter(generation: Path | str) -> Path:
    """The generation venv's python interpreter."""
    return Path(generation).expanduser() / "bin" / "python"


def _site_packages_dirs(venv: Path) -> list[Path]:
    """``site-packages`` dirs of *venv* (``lib/python*/site-packages`` and
    ``lib64/python*/site-packages`` — the latter appears on some Linux
    layouts)."""
    found: list[Path] = []
    for lib in ("lib", "lib64"):
        base = venv / lib
        if base.is_dir():
            found.extend(sorted(base.glob("python*/site-packages")))
    return found


def _read_dist_metadata(meta_path: Path) -> tuple[str, str]:
    """(Name, Version) from a ``*.dist-info/METADATA`` / ``*.egg-info/PKG-INFO``
    file; ``("", "")`` when unreadable or headers absent."""
    name = ""
    version = ""
    try:
        with meta_path.open(encoding="utf-8", errors="replace") as handle:
            for _ in range(60):
                line = handle.readline()
                if not line or not line.strip():
                    break
                if line.startswith("Name: "):
                    name = line[len("Name: ") :].strip()
                elif line.startswith("Version: "):
                    version = line[len("Version: ") :].strip()
    except OSError:
        return "", ""
    return name or "", version or ""


def _installed_distributions(venv: Path) -> list[tuple[str, str]]:
    """Sorted, deduped ``(name, version)`` of every installed distribution in
    *venv* — read from the package metadata (``*.dist-info/METADATA`` /
    ``*.egg-info/PKG-INFO``), NEVER from pip.  This is the pip-free semantic
    freeze: it reflects exactly what is installed, changes when the venv
    content changes, and works for ``--without-pip`` venvs."""
    found: list[tuple[str, str]] = []
    for site in _site_packages_dirs(venv):
        for meta_dir in sorted(site.glob("*.dist-info")):
            name, version = _read_dist_metadata(meta_dir / "METADATA")
            if name and version:
                found.append((name, version))
        for meta_dir in sorted(site.glob("*.egg-info")):
            name, version = _read_dist_metadata(meta_dir / "PKG-INFO")
            if name and version:
                found.append((name, version))
    return sorted(set(found))


def compute_venv_digest(
    interpreter: Path | str,
    *,
    runner: Runner = subprocess.run,
) -> str:
    """Deterministic sha256 of the generation venv's built content.

    Digests the venv's ``pyvenv.cfg`` (the base-interpreter identity) plus
    the sorted installed-distribution set read from package metadata — no
    pip subprocess, deterministic for a given frozen spec + base
    interpreter, and it changes whenever the venv content changes (a
    rebuilt, modified, or partially installed venv fails deep
    verification).  ``runner`` is accepted for interface uniformity but the
    digest itself runs no subprocesses.
    """
    del runner  # the digest reads metadata directly; no subprocess needed
    interpreter = Path(interpreter).expanduser()
    venv = interpreter.parent.parent
    cfg = venv / "pyvenv.cfg"
    try:
        cfg_text = cfg.read_text(encoding="utf-8", errors="replace")
    except OSError:
        cfg_text = ""
    payload = {
        "pyvenv_cfg": cfg_text,
        "installed": _installed_distributions(venv),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()


def verify_generation(
    generation: Path | str,
    *,
    runner: Runner = subprocess.run,
    deep: bool = True,
) -> dict[str, Any]:
    """Verify the on-disk generation at *generation*.

    Returns ``{"ok": bool, "reasons": [...]}`` (never raises): the dir
    exists, ``pyvenv.cfg`` present, interpreter present + executable,
    ``.generation.json`` parses + validates + its ``id`` equals the dir
    name; with *deep* (default) the venv digest is RECOMPUTED and compared
    against the recorded one.
    """
    gen = Path(generation).expanduser()
    reasons: list[str] = []
    if not gen.is_dir():
        reasons.append(f"generation dir missing: {gen}")
        return {"ok": False, "reasons": reasons}
    if not (gen / "pyvenv.cfg").is_file():
        reasons.append(f"missing pyvenv.cfg at {gen}")
    interpreter = generation_interpreter(gen)
    interpreter_ok = False
    if not interpreter.is_file() or not os.access(interpreter, os.X_OK):
        reasons.append(f"interpreter missing/not executable: {interpreter}")
    else:
        interpreter_ok = True
    proof_file = gen / ".generation.json"
    proof: dict[str, Any] = {}
    if not proof_file.is_file():
        reasons.append(f"missing .generation.json proof at {gen}")
    else:
        try:
            raw = proof_file.read_text(encoding="utf-8")
            parsed = json.loads(raw)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            reasons.append(f"corrupt .generation.json at {gen}: {exc}")
        else:
            if not isinstance(parsed, dict):
                reasons.append(f".generation.json at {gen} is not an object")
            else:
                proof = parsed
                try:
                    from arnold_pipelines.megaplan.cloud.runtime_manifest import (
                        validate_dependency_generation,
                    )

                    validate_dependency_generation(parsed)
                except Exception as exc:  # noqa: BLE001 - validation failures are reasons
                    reasons.append(f"invalid generation proof at {gen}: {exc}")
                if str(parsed.get("id") or "") != gen.name:
                    reasons.append(
                        f"generation proof id {parsed.get('id')!r} does not "
                        f"match its content-addressed dir name {gen.name!r}"
                    )
    if deep and interpreter_ok and proof:
        try:
            observed = compute_venv_digest(interpreter, runner=runner)
        except GenerationError as exc:
            reasons.append(f"venv digest unavailable: {exc}")
        else:
            recorded = str(proof.get("venv_digest") or "")
            if observed != recorded:
                reasons.append(
                    f"venv_digest mismatch: recorded {recorded}, observed "
                    f"{observed} (the immutable generation was modified or "
                    "rebuilt with a different interpreter)"
                )
    return {"ok": not reasons, "reasons": reasons}


def _build_generation(
    project: Path,
    gen_dir: Path,
    spec_digest: str,
    *,
    strategy: str,
    python_executable: str | None,
    runner: Runner,
) -> None:
    """Create the venv, install the frozen dependencies, stamp the proof.

    The runtime code itself is NEVER installed (no ``pip install -e``, no
    project install): the generation holds ONLY the frozen dependencies;
    worktree-first ``PYTHONPATH`` supplies the code at launch.
    """
    base_python = python_executable or sys.executable
    lock_path = project / "uv.lock"
    try:
        lock_text = lock_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GenerationError(
            f"cannot read frozen spec {lock_path}: {exc}"
        ) from exc
    use_uv = strategy == "uv" or (
        strategy == "auto" and shutil.which("uv") is not None
    )
    requirements = [] if use_uv else _marker_aware_frozen_requirements(lock_text)
    path_sources = [] if use_uv else _frozen_path_source_roots(project, lock_text)
    install_args = requirements + [source_path for source_path, _ in path_sources]
    # A dependency-FREE generation needs no pip inside the venv (the digest
    # reads package metadata, never pip): create it with --without-pip so
    # the build is fast and hermetic.  A generation with dependencies needs
    # pip for the install step (or uv, which manages its own packages).
    # The production binding verifier resolves the interpreter path and
    # requires it to remain inside the content-addressed generation.  A
    # platform-default venv symlink resolves back to the base interpreter and
    # would make an otherwise valid generation unverifiable, so generations
    # must carry their own interpreter copy.
    venv_args = [base_python, "-m", "venv", "--copies"]
    if not install_args:
        venv_args.append("--without-pip")
    venv_args.append(str(gen_dir))
    venv_proc = _run(venv_args, cwd=project, runner=runner)
    if venv_proc.returncode != 0:
        raise GenerationError(
            f"venv creation failed for generation {gen_dir}: "
            f"{_redacted_tail(venv_proc.stderr or venv_proc.stdout)}"
        )
    interpreter = generation_interpreter(gen_dir)
    if use_uv:
        # uv installs EXACTLY the uv.lock pins into the ACTIVE venv and
        # never the project itself (--no-install-project).
        env = dict(os.environ)
        env["VIRTUAL_ENV"] = str(gen_dir)
        uv_proc = _run(
            ["uv", "sync", "--frozen", "--no-install-project", "--active"],
            cwd=project,
            runner=runner,
            env=env,
        )
        if uv_proc.returncode != 0:
            raise GenerationError(
                f"uv sync failed for generation {gen_dir}: "
                f"{_redacted_tail(uv_proc.stderr or uv_proc.stdout)}"
            )
    elif install_args:
        # Setuptools and other build backends may write ``*.egg-info`` and
        # ``build/`` into a local source tree. Build from temporary copies so
        # generation creation cannot dirty the attested runtime checkout.
        with tempfile.TemporaryDirectory(prefix="arnold-generation-sources-") as tmp:
            staged_sources: list[str] = []
            for index, (_, source_root) in enumerate(path_sources):
                destination = Path(tmp) / f"{index:04d}-{source_root.name}"
                shutil.copytree(source_root, destination)
                staged_sources.append(str(destination))
            pip_proc = _run(
                [
                    str(interpreter),
                    "-m",
                    "pip",
                    "install",
                    *requirements,
                    *staged_sources,
                ],
                cwd=project,
                runner=runner,
            )
        if pip_proc.returncode != 0:
            raise GenerationError(
                f"dependency install failed for generation {gen_dir}: "
                f"{_redacted_tail(pip_proc.stderr or pip_proc.stdout)}"
            )
    venv_digest = compute_venv_digest(interpreter, runner=runner)
    proof = {
        "id": spec_digest,
        "frozen_spec_sha256": spec_digest,
        "interpreter_path": str(interpreter),
        "venv_digest": venv_digest,
        "created": _utc_now_iso(),
    }
    _atomic_write_json(gen_dir / ".generation.json", proof)


def ensure_dependency_generation(
    project_root: Path | str,
    generations_root: Path | str,
    *,
    python_executable: str | None = None,
    runner: Runner = subprocess.run,
    build_strategy: str | None = None,
) -> dict[str, Any]:
    """Build (or verify) the content-addressed dependency generation for
    *project_root*'s frozen spec and return its proof dict.

    The generation lives at ``<generations_root>/<spec_digest>`` and is
    IMMUTABLE: an existing generation that fails deep verification
    (venv-digest mismatch, missing interpreter, corrupt/mismatched proof) is
    REFUSED with :class:`GenerationError` — never silently reused and never
    overwritten.  Builds run under a single-writer flock on
    ``<generations_root>/.build.lock``, so concurrent runtimes resolving the
    same spec build once and share the venv.

    *build_strategy*: ``"auto"`` (default — uv when on PATH, else pip from
    the uv.lock pins), ``"uv"``, or ``"pip"``; overridable via env
    ``ARNOLD_GENERATION_BUILD_STRATEGY``.
    """
    project = Path(project_root).expanduser().resolve()
    gen_root = Path(generations_root).expanduser().resolve(strict=False)
    spec_digest = frozen_spec_sha256(project)
    gen_dir = generation_dir(gen_root, spec_digest)
    strategy = (
        build_strategy
        or os.environ.get("ARNOLD_GENERATION_BUILD_STRATEGY")
        or "auto"
    ).strip().lower()
    if strategy not in ("auto", "pip", "uv"):
        raise GenerationError(
            f"unknown generation build strategy {strategy!r} (auto|pip|uv)"
        )
    gen_root.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(str(gen_root / ".build.lock"), os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        verification = verify_generation(gen_dir, runner=runner, deep=True)
        if verification["ok"]:
            return json.loads(
                (gen_dir / ".generation.json").read_text(encoding="utf-8")
            )
        if gen_dir.exists():
            raise GenerationError(
                f"generation {gen_dir} exists but failed verification: "
                + "; ".join(verification["reasons"])
                + " — refusing to reuse or overwrite an immutable generation "
                "(reconcile the generation store before recreating the runtime)"
            )
        _build_generation(
            project,
            gen_dir,
            spec_digest,
            strategy=strategy,
            python_executable=python_executable,
            runner=runner,
        )
        return json.loads(
            (gen_dir / ".generation.json").read_text(encoding="utf-8")
        )
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


# ── retired editable-install sync path (T-0301) ──────────────────────────────


def apply_install_sync(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """RETIRED (T-0301): the editable-install sync path no longer exists.

    Dependencies are immutable content-addressed generations
    (``epic.dependency_generation``) built once by ``arnold-runtime-create``
    under a single-writer flock; there is no mutable editable install to
    sync and no ``pip install -e`` fallback.  Any residual caller (the
    meta-repair loop) fails loudly here instead of silently skipping the
    sync concept.
    """
    raise EditableInstallRetiredError(
        "editable install sync is retired (T-0301): dependencies are "
        "immutable content-addressed generations (epic.dependency_generation); "
        "there is no pip install -e path"
    )


__all__ = [
    "EditableInstallRetiredError",
    "GenerationError",
    "apply_install_sync",
    "compute_venv_digest",
    "ensure_dependency_generation",
    "frozen_requirements",
    "frozen_spec_sha256",
    "generation_dir",
    "generation_interpreter",
    "verify_generation",
]
