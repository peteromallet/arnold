"""Schema-versioned per-runtime manifest — the ONLY post-bootstrap runtime resolver.

Phase-2 deliverable of the fixer-unification design (rule 3, §4 Phase 2): one
``runtime-manifest.json`` per runtime is the single post-bootstrap resolver for
repair-bin location, expected head, execution source, indirection, policy, and
promotion history. Something outside the manifest must locate the manifest —
that is the **stable bootstrap path** resolved by :func:`bootstrap_manifest`
(see its docstring for the exact semantics). One authoritative writer: all
writes go through :func:`write_manifest`, which serializes atomically
(tmp file + ``os.replace``) under the canonical ``<name>.promotion.lock`` then
``<name>.lock`` pair, so a concurrent reader never observes a partial file and
no promotion or ordinary writer can interleave.

Invariants from the design brief
--------------------------------
* Schema-versioned: ``schema == MANIFEST_SCHEMA_VERSION`` or the manifest is
  refused (``ManifestError``). A future schema bump is a deliberate, loud
  migration point.
* Generation/rollback contract (design rule 0): ``advance_generation`` builds a
  NEW manifest with ``generation + 1`` and records the previous generation +
  commit in ``promotions`` (the rollback record). Manifests are immutable;
  every transition returns a fresh instance.
* State machine: ``state`` is ``"active"`` or ``"closed"`` only;
  :func:`set_state` stamps ``timestamps.closed`` when closing.
* On startup a launcher emits :func:`attest_runtime` — the actual module
  path/digest and mount identity of ``epic.runtime_root`` — rather than
  trusting declared paths (design rule 7 content attestation).
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from arnold_pipelines.megaplan.cloud.shadow_attestation import attest_target_content
from arnold_pipelines.megaplan.cloud.runtime_provenance import (
    emit_runtime_manifest_cutover_rollback_receipt,
    verify_runtime_manifest_cutover_rollback_receipt,
)
# Codex fix 2026-08-17: dependency-generation proof carry-forward is now
# CONDITIONAL — the proof must bind to the NEW commit's frozen dependency
# spec (recomputed digest) and its interpreter/venv must still verify.
# These are imported at module level so tests can monkeypatch them.
from arnold_pipelines.megaplan.cloud.install_sync import (
    GenerationError,
    compute_venv_digest,
    frozen_spec_sha256,
)
from arnold_pipelines.megaplan.types import CliError

MANIFEST_SCHEMA_VERSION = "1"

# Canonical manifest filename inside a bootstrap *directory*.
MANIFEST_FILENAME = "runtime-manifest.json"

# Marker for a NON-AUTHORITATIVE active pointer (G2 correction 1 + second
# re-run): a manifest pointer file at the bootstrap path whose JSON carries
# ``"compatibility_only": true`` is compatibility telemetry ONLY — every
# resolver treats it as ABSENT for admission (permit check applies; block
# without a valid permit). It can never select a runtime. The marker is an
# EXPLICIT preserved manifest field (schema stays "1", optional, default
# False) so no read/write transition can strip it (G2 second re-run);
# resolvers still check it explicitly (:func:`is_compatibility_only_pointer`)
# because it is per-pointer telemetry, not part of a per-slug authoritative
# manifest.
COMPATIBILITY_ONLY_KEY = "compatibility_only"

# Typed refusal code for the CAS-guarded ``cutover`` command.
CUTOVER_ERROR = "runtime_manifest_cutover_refused"

# Default rollback-receipt path for ``cutover``: ``<manifest-path>`` with this
# suffix appended (callers may override with ``--receipt-out``).
CUTOVER_RECEIPT_SUFFIX = ".cutover-rollback.json"

# Typed refusal code when ``--receipt-out`` realpaths onto protected
# transaction state — the manifest itself, either identity/provenance guard
# input, or the cutover's own transaction lock file (T-0101h round-5
# blocker 3). Without this guard the final manifest write would clobber the
# just-written receipt, letting the cutover "succeed" with no durable
# rollback evidence.
RECEIPT_ALIASES_PROTECTED_STATE = "receipt_aliases_protected_state"

# Typed refusal code when the durable rollback receipt fails post-write
# verification (missing, corrupt, or wrong pre-cutover manifest SHA-256).
# The manifest may already be rewritten at that point — the refusal is a loud
# POST-CONDITION check that the cutover never reports success without durable
# rollback evidence (the receipt write is attempted FIRST, so an operator can
# still recover from the attempted receipt path).
RECEIPT_POST_VERIFY_FAILED = "receipt_post_verify_failed"

_FULL_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_GIT_SHA40 = re.compile(r"^[0-9a-f]{40}$")

_VALID_STATES = frozenset({"active", "closed"})

_TOP_LEVEL_REQUIRED = (
    "runtime_id",
    "schema",
    "generation",
    "epic_id",
    "state",
    "owner",
    "base",
    "epic",
    "indirection",
    "policy",
    "promotions",
    "timestamps",
    "gc_policy",
    "commands",
)

_BASE_REQUIRED = ("ref", "commit", "editable_install_path", "venv_path")
_EPIC_REQUIRED = (
    "branch",
    "worktree_path",
    "venv_path",
    "runtime_root",
    "expected_head",
    "repair_bin",
    "deps_lockfile",
)

# Required keys of the content-addressed dependency-generation proof bound
# into ``epic.dependency_generation`` (T-0301).  The generation is ONE
# immutable venv per frozen dependency spec (the ``pyproject.toml`` +
# ``uv.lock`` pair named by ``epic.deps_lockfile``'s sibling files), shared
# by every runtime that resolves to the same spec.  ``id`` IS the content
# address — the sha256 of the frozen spec — and equals ``frozen_spec_sha256``
# by construction (recorded separately so a reader can verify the binding
# without recomputing the address).  ``interpreter_path`` names the
# generation venv's python (``<venv>/bin/python``), ``venv_digest`` is the
# sha256 of the BUILT venv (the deterministic pip-list freeze of the
# installed set — it changes when the venv content changes), and ``created``
# is the UTC ISO timestamp of the build.  A missing or incomplete proof
# blocks publication (advance/cutover), launch, and GC — fail-closed.
DEPENDENCY_GENERATION_REQUIRED = (
    "id",
    "frozen_spec_sha256",
    "interpreter_path",
    "venv_digest",
    "created",
)

# Public aliases for the canonical required-key sets.  cloud.cli generates
# the stdlib-only, fail-closed shell read of the pinned runtime manifest
# from these (G6 round-2 finding 2), so the shell gate can never drift from
# the canonical schema definition.
TOP_LEVEL_REQUIRED = _TOP_LEVEL_REQUIRED
EPIC_REQUIRED = _EPIC_REQUIRED
DEPENDENCY_GENERATION_KEYS = DEPENDENCY_GENERATION_REQUIRED
_INDIRECTION_REQUIRED = (
    "host_path",
    "container_path",
    "mount_table",
    "execution_namespace",
    "verified_head",
    "last_verified_at",
    "attestation",
)
_INDIRECTION_ATTESTATION_REQUIRED = ("module_file", "module_digest", "mount_id")
_POLICY_REQUIRED = ("policy_sha", "model_policy_sha", "sync_policy")
_TIMESTAMPS_REQUIRED = ("created", "updated", "closed")


class ManifestError(ValueError):
    """Raised when a runtime manifest is missing, corrupt, or schema-mismatched."""


def manifest_bytes_sha256(path: Path) -> str:
    """Return the identity of the exact bytes stored at *path*.

    Launch custody is bound to the file bytes, not to a parsed/re-serialized
    JSON representation.  Keeping this read in the manifest module gives the
    cloud launch paths one authority and makes formatting-only changes
    observable.  Missing/unreadable files fail closed with ``ManifestError``.
    """
    target = Path(path).expanduser().resolve(strict=False)
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise ManifestError(f"cannot read manifest {target}: {exc}") from exc
    return hashlib.sha256(raw).hexdigest()


class ForeignAuthoritativePointerConflict(ManifestError):
    """A valid authoritative pointer belongs to another epic.

    This is deliberately distinct from malformed-pointer and I/O failures.
    Runtime creation may record a compatibility-only degradation for this
    specific, typed condition while continuing to use its per-epic manifest;
    every other :class:`ManifestError` remains fail-closed.
    """

    code = "foreign_authoritative_pointer_conflict"


def _require_keys(label: str, mapping: Any, required: tuple[str, ...]) -> None:
    if not isinstance(mapping, dict):
        raise ManifestError(f"{label} must be an object")
    missing = [key for key in required if key not in mapping]
    if missing:
        raise ManifestError(f"{label} missing required keys: {', '.join(missing)}")


def _require_git_sha40(value: object, *, label: str) -> str:
    """Shape-check *value* as a 40-char lowercase hex git commit SHA.

    This is a pure shape check — it does NOT verify the object exists in any
    repository.  It rejects the observed corruption pattern (41-char heads
    built from a 10-char real prefix plus a fabricated tail) at the boundary
    before any git lookup.
    """
    head = str(value or "").strip()
    if not _GIT_SHA40.fullmatch(head):
        raise ManifestError(
            f"{label} must be a 40-char lowercase hex git SHA, got {value!r}"
        )
    return head


def _require_resolvable_head(runtime_root: str | Path, head: str) -> str:
    """Require *head* to be a 40-hex SHA that RESOLVES to that exact commit
    in the git repository at *runtime_root*.

    The equality check is deliberate: ``^{commit}`` must resolve to the exact
    supplied commit ID, not merely peel some other object such as an
    annotated tag.  Raises :class:`ManifestError` on shape failure, a missing
    runtime root, or an unresolvable head — callers must treat that as a
    hard refusal BEFORE any manifest/pointer write.
    """
    value = _require_git_sha40(head, label="head")
    root_text = str(runtime_root or "").strip()
    if not root_text:
        raise ManifestError("runtime root is required to verify head")
    root = Path(root_text).expanduser().resolve(strict=False)
    try:
        proc = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "rev-parse",
                "--verify",
                "--end-of-options",
                f"{value}^{{commit}}",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise ManifestError(
            f"cannot verify head {value!r} in {root}: {exc}"
        ) from exc
    resolved = proc.stdout.strip() if proc.returncode == 0 else ""
    if resolved != value:
        raise ManifestError(
            f"head {value!r} does not resolve to that commit in {root}"
        )
    return value


def _parse_utc_timestamp(value: Any, label: str) -> datetime:
    """Parse *value* as a UTC ISO8601 timestamp (shared by deviation records
    and dependency-generation proofs)."""
    if not isinstance(value, str) or not value:
        raise ManifestError(f"{label} must be a non-empty ISO8601 string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ManifestError(f"{label} is not ISO8601: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ManifestError(f"{label} must be UTC: {value!r}")
    return parsed


def validate_dependency_generation(record: Any) -> dict[str, Any]:
    """Validate a content-addressed dependency-generation proof (T-0301).

    Refuses (raises :class:`ManifestError`): non-object records; missing
    keys; ``id`` / ``frozen_spec_sha256`` / ``venv_digest`` that are not
    64-char hex SHA-256 strings; ``id != frozen_spec_sha256`` (the content
    address IS the frozen-spec digest by construction — a mismatch is an
    incoherent binding); a non-absolute / empty ``interpreter_path``; or a
    non-UTC, unparsable ``created`` timestamp.  Returns the record unchanged
    on success (unknown extra keys are tolerated and preserved).
    """
    if not isinstance(record, dict):
        raise ManifestError("dependency_generation must be an object")
    missing = [key for key in DEPENDENCY_GENERATION_REQUIRED if key not in record]
    if missing:
        raise ManifestError(
            "dependency_generation missing required keys: " + ", ".join(missing)
        )
    for field_name in ("id", "frozen_spec_sha256", "venv_digest"):
        value = record[field_name]
        if not isinstance(value, str) or not _FULL_SHA256.fullmatch(value):
            raise ManifestError(
                f"dependency_generation.{field_name} must be a 64-char hex "
                f"SHA-256, got {value!r}"
            )
    if record["id"] != record["frozen_spec_sha256"]:
        raise ManifestError(
            "dependency_generation.id must equal frozen_spec_sha256 (the "
            "content address IS the frozen-spec digest), got "
            f"{record['id']!r} vs {record['frozen_spec_sha256']!r}"
        )
    interpreter = record["interpreter_path"]
    if (
        not isinstance(interpreter, str)
        or not interpreter.strip()
        or not Path(interpreter).expanduser().is_absolute()
    ):
        raise ManifestError(
            "dependency_generation.interpreter_path must be a non-empty "
            f"absolute path, got {interpreter!r}"
        )
    _parse_utc_timestamp(record["created"], "dependency_generation.created")
    return record


def dependency_generation_proof(
    manifest: "RuntimeManifest",
) -> dict[str, Any] | None:
    """Return the manifest's dependency-generation proof when present AND
    complete; ``None`` when absent (legacy manifests load without one).

    An INCOMPLETE proof never yields a partial record: a manifest carrying a
    malformed ``epic.dependency_generation`` fails load validation (see
    ``RuntimeManifest.__post_init__``), and this helper returns ``None``
    only for a genuinely absent proof.  Publication (advance/cutover), the
    launch gate, and GC all treat ``None`` as unknown dependency state and
    fail closed.
    """
    record = manifest.epic.get("dependency_generation")
    if record is None:
        return None
    return validate_dependency_generation(record)


@dataclass(frozen=True)
class RuntimeManifest:
    """One per-runtime manifest; immutable — transitions return new instances.

    Nested sections (``base``, ``epic``, ``indirection``, ``policy``,
    ``timestamps``) are plain ``dict[str, Any]`` — read them with key access,
    e.g. ``manifest.epic["repair_bin"]``. Required keys are validated in
    ``__post_init__`` (raises :class:`ManifestError`).

    ``deviations`` is an OPTIONAL list of expiring exception records (typed
    deviation/fallback events, e.g. an ``allow_manifestless`` permit). It is
    preserved verbatim by every read/write transition and serialized on disk;
    old manifests (schema ``"1"`` without the key) load with ``[]``. Expired
    records STAY loadable — expiry is enforced at admission/addition
    (:func:`validate_deviation`, :func:`has_valid_allow_manifestless_permit`),
    never at load time.

    ``compatibility_only`` is an OPTIONAL boolean demotion marker for
    NON-AUTHORITATIVE pointers (G2 correction 1 + second re-run): a manifest
    with it ``True`` is compatibility telemetry ONLY and can never select a
    runtime — every resolver treats it as ABSENT for admission. Per-slug
    authoritative manifests leave it ``False``. It is preserved verbatim by
    every read/write transition (:func:`_reconstruct`) and serialized on
    disk; old manifests (schema ``"1"`` without the key) load with ``False``.
    """

    runtime_id: str
    schema: str
    generation: int
    epic_id: str
    state: str
    owner: str
    base: dict[str, Any]
    epic: dict[str, Any]
    indirection: dict[str, Any]
    policy: dict[str, Any]
    promotions: list[dict[str, Any]]
    timestamps: dict[str, Any]
    gc_policy: str
    commands: list[dict[str, Any]]
    deviations: list[dict[str, Any]] = field(default_factory=list)
    compatibility_only: bool = False

    def __post_init__(self) -> None:
        if self.schema != MANIFEST_SCHEMA_VERSION:
            raise ManifestError(
                f"unsupported manifest schema {self.schema!r}; "
                f"expected {MANIFEST_SCHEMA_VERSION!r}"
            )
        if not isinstance(self.generation, int) or self.generation < 1:
            raise ManifestError(
                f"generation must be an int >= 1, got {self.generation!r}"
            )
        if self.state not in _VALID_STATES:
            raise ManifestError(
                f"state must be one of {sorted(_VALID_STATES)}, got {self.state!r}"
            )
        _require_keys("base", self.base, _BASE_REQUIRED)
        _require_keys("epic", self.epic, _EPIC_REQUIRED)
        # T-0301: a PRESENT but malformed dependency-generation proof is
        # schema-invalid (fail-closed — a partial proof is never partially
        # trusted); a genuinely absent proof is legal for legacy manifests
        # and is enforced at the publication/launch/GC gates instead.
        if "dependency_generation" in self.epic:
            validate_dependency_generation(self.epic["dependency_generation"])
        _require_keys("indirection", self.indirection, _INDIRECTION_REQUIRED)
        _require_keys("policy", self.policy, _POLICY_REQUIRED)
        _require_keys("timestamps", self.timestamps, _TIMESTAMPS_REQUIRED)
        attestation = self.indirection.get("attestation")
        if not isinstance(attestation, dict):
            raise ManifestError("indirection.attestation must be an object")
        _require_keys(
            "indirection.attestation", attestation, _INDIRECTION_ATTESTATION_REQUIRED
        )
        if not isinstance(self.promotions, list) or not isinstance(self.commands, list):
            raise ManifestError("promotions and commands must be lists")
        if not isinstance(self.deviations, list) or not all(
            isinstance(record, dict) for record in self.deviations
        ):
            raise ManifestError("deviations must be a list of objects")
        if not isinstance(self.compatibility_only, bool):
            raise ManifestError("compatibility_only must be a boolean")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RuntimeManifest":
        """Build a manifest from parsed JSON, validating required top-level fields.

        Unknown keys in *data* are ignored (forward-compatible with newer
        schema fields); missing required fields raise :class:`ManifestError`.
        """
        if not isinstance(data, Mapping):
            raise ManifestError("manifest payload must be a JSON object")
        missing = [key for key in _TOP_LEVEL_REQUIRED if key not in data]
        if missing:
            raise ManifestError(
                f"manifest missing required fields: {', '.join(missing)}"
            )
        values: dict[str, Any] = {key: data[key] for key in _TOP_LEVEL_REQUIRED}
        # deviations is OPTIONAL: old manifests (schema "1") load with [].
        values["deviations"] = data.get("deviations", [])
        # compatibility_only is OPTIONAL: old manifests (schema "1") load
        # with False (authoritative); only a pointer explicitly marked True is
        # non-authoritative telemetry. As a real field it is preserved by
        # to_dict/_reconstruct — no transition can strip the marker (G2
        # second re-run).
        values[COMPATIBILITY_ONLY_KEY] = data.get(COMPATIBILITY_ONLY_KEY, False)
        return cls(**values)

    def to_dict(self) -> dict[str, Any]:
        """Plain JSON-serializable dict (deep copy via :func:`dataclasses.asdict`)."""
        return asdict(self)


# ── serialization ───────────────────────────────────────────────────────────


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _atomic_write(path: Path, payload: Mapping[str, Any]) -> None:
    """Atomic tmp-file + ``os.replace`` write; identical pattern to
    ``runtime_attestation._atomic_write`` (fsync before rename, cleanup on
    failure). Callers hold the manifest lock.
    """
    path = path.expanduser().resolve(strict=False)
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


def _write_payload(
    manifest: RuntimeManifest, target: Path, *, pointer_write: bool = False
) -> dict[str, Any]:
    """Serialized payload for writing *manifest* to *target*, enforcing the
    demotion invariant (G2 second re-run): a demoted (``compatibility_only``)
    pointer can never be re-admitted authoritative by ANY writer. This is the
    ONE preservation point — both :func:`write_manifest` (the lowest-level
    writer) and :func:`write_active_pointer` route their payloads through it:

    - Generic write (``pointer_write=False``): only the ACTIVE-generation
      pointer path (:func:`active_manifest_path`) is protected — when *target*
      IS that path and the file already there is a ``compatibility_only``
      pointer, the marker is forced ON even for an authoritative manifest.
    - Pointer write (``pointer_write=True``): every target is a pointer, so
      any path that already holds a ``compatibility_only`` pointer stays
      demoted.

    Any other target (per-slug manifests, retention copies) is written exactly
    as *manifest* declares.
    """
    payload = manifest.to_dict()
    pointer_target = pointer_write or (
        target == active_manifest_path().expanduser().resolve(strict=False)
    )
    if pointer_target and is_compatibility_only_pointer(target):
        payload[COMPATIBILITY_ONLY_KEY] = True
    return payload


def manifest_lock_path(path: Path, *, promotion: bool = False) -> Path:
    """Return the canonical mutation-lock path for *path*.

    Runtime-manifest writers use the ordinary sibling ``.lock`` while
    generation/cutover producers use the sibling ``.promotion.lock``.  Keep
    both derivations here so cross-subsystem transactions cannot drift to a
    look-alike lock file.
    """
    target = Path(path).expanduser().resolve(strict=False)
    suffix = ".promotion.lock" if promotion else ".lock"
    return target.with_name(target.name + suffix)


@contextmanager
def manifest_mutation_lock(
    path: Path,
    *,
    promotion: bool = False,
    blocking: bool = True,
) -> Iterator[int]:
    """Hold one canonical runtime-manifest mutation lock.

    ``promotion=True`` selects the generation promotion lock; otherwise this
    is the ordinary manifest writer lock.  Callers that need both acquire the
    promotion lock first, then the ordinary lock, matching
    :func:`advance_generation_at_path`'s global order.
    """
    lock_path = manifest_lock_path(path, promotion=promotion)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        flags = fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB
        fcntl.flock(lock_fd, flags)
        yield lock_fd
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def manifest_write_lock(path: Path, *, blocking: bool = True) -> Iterator[int]:
    """Canonical context manager for the ordinary ``<manifest>.lock``."""
    return manifest_mutation_lock(path, blocking=blocking)


def manifest_promotion_lock(path: Path, *, blocking: bool = True) -> Iterator[int]:
    """Canonical context manager for ``<manifest>.promotion.lock``."""
    return manifest_mutation_lock(path, promotion=True, blocking=blocking)


@contextmanager
def manifest_transaction_lock(
    *paths: Path, blocking: bool = True
) -> Iterator[tuple[Path, ...]]:
    """Hold the canonical lock pair for every manifest in *paths*.

    Every promotion-capable manifest mutation takes the promotion lock before
    the ordinary writer lock.  When a transaction touches more than one
    manifest (the active pointer plus a per-runtime manifest), all paths are
    sorted first and all promotion locks are acquired before any ordinary
    locks.  That gives the whole mutation domain one deadlock-free order while
    allowing locked helpers below to avoid re-entering either lock.
    """
    targets = tuple(
        sorted(
            {Path(path).expanduser().resolve(strict=False) for path in paths},
            key=str,
        )
    )
    with ExitStack() as stack:
        for target in targets:
            stack.enter_context(
                manifest_promotion_lock(target, blocking=blocking)
            )
        for target in targets:
            stack.enter_context(manifest_write_lock(target, blocking=blocking))
        yield targets


@contextmanager
def _single_manifest_transaction_lock(path: Path) -> Iterator[None]:
    """Hold one canonical pair for the cutover's whole transaction."""
    with manifest_promotion_lock(path):
        with manifest_write_lock(path):
            yield


def _write_manifest_locked(manifest: RuntimeManifest, target: Path) -> None:
    """Write *manifest* assuming *target*'s canonical pair is held."""
    target.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(target, _write_payload(manifest, target))


def write_manifest(manifest: RuntimeManifest, path: Path) -> None:
    """Serialize *manifest* to *path* atomically under an exclusive flock.

    Sibling ``<name>.promotion.lock`` and ``<name>.lock`` files are created
    (and kept) next to *path*; writers take both canonical locks around the
    tmp+rename so concurrent writers serialize and readers never observe a
    partial file.

    Demotion invariant (G2 second re-run): when *path* IS the active-
    generation pointer path and the existing file there is a
    ``compatibility_only`` pointer, the written payload is forced to keep the
    marker (see :func:`_write_payload`) — a generic authoritative write can
    never re-admit a demoted pointer.
    """
    target = Path(path).expanduser().resolve(strict=False)
    with manifest_transaction_lock(target):
        _write_manifest_locked(manifest, target)


def load_manifest(path: Path) -> RuntimeManifest:
    """Parse and validate the manifest at *path*.

    Raises :class:`ManifestError` on unreadable file, corrupt JSON, schema
    mismatch, or missing required fields.
    """
    target = Path(path).expanduser().resolve(strict=False)
    try:
        raw = target.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(f"cannot read manifest {target}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"corrupt manifest JSON at {target}: {exc}") from exc
    return RuntimeManifest.from_dict(data)


def is_compatibility_only_pointer(path: Path) -> bool:
    """True iff *path* is a NON-AUTHORITATIVE ``compatibility_only`` pointer.

    A pointer file at the bootstrap path whose JSON carries
    ``"compatibility_only": true`` at the top level is compatibility telemetry
    (legacy launchers may still read it) and can NEVER select a runtime: every
    resolver treats it as ABSENT for admission (G2 correction 1). The marker
    must be checked explicitly because :func:`load_manifest` ignores unknown
    keys by design. Absent, unreadable, or non-JSON files return False — they
    fail on their own as absent/invalid rather than being compatibility
    telemetry.
    """
    target = Path(path).expanduser()
    if not target.is_file():
        return False
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(payload, dict) and payload.get(COMPATIBILITY_ONLY_KEY) is True


def manifest_present(path: Path) -> bool:
    """True iff *path* resolves to a present, valid, AUTHORITATIVE manifest.

    Admission probe: a ``compatibility_only`` pointer is treated as ABSENT
    (never authoritative), and a missing, corrupt, or schema-invalid file is
    absent too. Returns False on every non-admissible state — callers that
    need to distinguish "absent-for-admission" from "present-but-invalid" can
    combine it with :func:`is_compatibility_only_pointer` and
    :func:`load_manifest`.
    """
    if is_compatibility_only_pointer(path):
        return False
    try:
        load_manifest(path)
    except ManifestError:
        return False
    return True


# ── index ───────────────────────────────────────────────────────────────────


def list_manifests(manifest_dir: Path) -> list[RuntimeManifest]:
    """Read-only index of every valid manifest in *manifest_dir*, sorted by
    ``runtime_id``.

    Files that do not parse as a valid manifest (corrupt JSON, schema
    mismatch, missing fields — e.g. stray JSON in the directory) are skipped
    so they cannot break the index; use :func:`load_manifest` on a specific
    path to surface such errors.
    """
    directory = Path(manifest_dir).expanduser()
    if not directory.is_dir():
        return []
    manifests: list[RuntimeManifest] = []
    for candidate in directory.glob("*.json"):
        try:
            manifests.append(load_manifest(candidate))
        except ManifestError:
            continue
    return sorted(manifests, key=lambda manifest: manifest.runtime_id)


def load_manifest_by_epic(
    epic_id: str, manifest_dir: Path
) -> RuntimeManifest | None:
    """Return the manifest in *manifest_dir* whose ``epic_id`` matches, or
    ``None`` when absent. Invalid/non-manifest files are skipped (see
    :func:`list_manifests`)."""
    for manifest in list_manifests(manifest_dir):
        if manifest.epic_id == epic_id:
            return manifest
    return None


# ── bootstrap ───────────────────────────────────────────────────────────────


def _read_pointer(pointer_path: Path) -> str:
    """First non-comment, non-empty line of *pointer_path* = the manifest path."""
    try:
        text = pointer_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(
            f"cannot read bootstrap pointer {pointer_path}: {exc}"
        ) from exc
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped
    raise ManifestError(f"bootstrap pointer {pointer_path} contains no manifest path")


def _load_authoritative(path: Path) -> RuntimeManifest:
    """Load *path* as the runtime manifest, REFUSING a ``compatibility_only``
    pointer.

    A ``compatibility_only`` pointer is non-authoritative telemetry (G2
    correction 1): the resolver treats it as ABSENT/not-found (raises
    :class:`ManifestError`) so it can never select a runtime — admission falls
    through to the permit check and blocks without a valid permit.
    """
    if is_compatibility_only_pointer(path):
        raise ManifestError(
            f"bootstrap target {path} is a compatibility_only pointer; "
            "non-authoritative — refusing to select a runtime from it"
        )
    return load_manifest(path)


def bootstrap_manifest(bootstrap_path: Path) -> RuntimeManifest:
    """Resolve the active runtime manifest from ONE stable bootstrap path.

    Bootstrap semantics (in order):

    1. Missing path -> :class:`ManifestError`.
    2. Directory -> load ``<dir>/runtime-manifest.json``.
    3. File ending in ``.json`` -> loaded directly as a manifest.
    4. Any other file is a POINTER file: the first non-empty, non-comment
       line names the manifest (relative to the pointer file's parent). If
       that target is a directory, ``<target>/runtime-manifest.json`` is used.

    A ``compatibility_only`` pointer at any resolution step is NON-AUTHORITATIVE
    telemetry (G2 correction 1): it is treated as ABSENT — :class:`ManifestError`
    is raised, so it can never select a runtime.

    This is the single stable entry point every launcher uses post-bootstrap;
    nothing else may locate the runtime manifest.
    """
    bootstrap = Path(bootstrap_path).expanduser()
    if not bootstrap.exists():
        raise ManifestError(f"bootstrap path does not exist: {bootstrap}")
    if bootstrap.is_dir():
        return _load_authoritative(bootstrap / MANIFEST_FILENAME)
    if bootstrap.name.endswith(".json"):
        return _load_authoritative(bootstrap)
    target = Path(_read_pointer(bootstrap))
    if not target.is_absolute():
        target = bootstrap.parent / target
    if target.is_dir():
        target = target / MANIFEST_FILENAME
    if not target.exists():
        raise ManifestError(f"bootstrap pointer target does not exist: {target}")
    return _load_authoritative(target)


# ── active-generation pointer ───────────────────────────────────────────────


def active_manifest_path() -> Path:
    """Stable path of the active-generation pointer.

    The canonical bootstrap path is ``/workspace/.megaplan/runtime-manifest.json``;
    env ``ARNOLD_RUNTIME_MANIFEST`` overrides it. The file AT this path IS the
    active generation — it holds a full manifest JSON (not a sidecar pointer
    file), so ``bootstrap_manifest(active_manifest_path())`` resolves it
    directly. One active pointer, one authoritative writer (the wrapper that
    performs the atomic switch: runtime-create at creation, promote on
    advancement, close on closing).
    """
    env_path = os.environ.get("ARNOLD_RUNTIME_MANIFEST")
    if env_path:
        return Path(env_path).expanduser()
    return Path("/workspace/.megaplan") / MANIFEST_FILENAME


def _retain_previous_generation(pointer: Path, manifest: RuntimeManifest) -> None:
    """Retain the pointer's current manifest before a generation switch.

    Called with the pointer's exclusive flock already held. When *pointer*
    holds a manifest of a strictly EARLIER generation than *manifest*, that
    manifest is written to ``<pointer>.previous-<generation>.json`` (the
    rollback record) BEFORE the pointer moves — a crash between the two writes
    leaves the pointer on the old generation with a harmless duplicate
    retention copy. An existing-but-invalid pointer is REFUSED (fail-closed)
    rather than silently overwritten.
    """
    if not pointer.exists():
        return
    try:
        previous = load_manifest(pointer)
    except ManifestError as exc:
        raise ManifestError(
            f"active pointer {pointer} holds an invalid manifest; refusing to "
            f"overwrite it (fail-closed): {exc}"
        ) from exc
    if previous.generation < manifest.generation:
        retention = Path(str(pointer) + f".previous-{previous.generation}.json")
        _atomic_write(retention, previous.to_dict())


def _write_active_pointer_locked(manifest: RuntimeManifest, pointer: Path) -> None:
    """Write the active pointer assuming its canonical lock pair is held."""
    # Foreign-epic guard (occurrence 0a0ce24c3510 / 0513dbf3f069): the
    # active pointer must NEVER be silently overwritten with a different
    # epic's manifest.  A caller whose ARNOLD_RUNTIME_MANIFEST env (or the
    # absence of it) resolves to the shared default pointer while advancing
    # ANOTHER epic's manifest would clobber the active epic's generation
    # (astrid-first's gen-78 advance overwrote the megaplan-maintenance
    # pointer at 02:07:42Z with no retention because 78 < 119 skipped the
    # rollback copy).  A ``compatibility_only`` pointer is non-authoritative
    # telemetry (G2) and may be replaced; an invalid pointer is left to
    # ``_retain_previous_generation``'s existing fail-closed check.
    if pointer.exists():
        try:
            _current_pointer_manifest = load_manifest(pointer)
        except ManifestError:
            _current_pointer_manifest = None
        if (
            _current_pointer_manifest is not None
            and not _current_pointer_manifest.compatibility_only
        ):
            _current_epic_branch = str(
                (_current_pointer_manifest.epic or {}).get("branch") or ""
            )
            _incoming_epic_branch = str((manifest.epic or {}).get("branch") or "")
            _current_epic_id = str(_current_pointer_manifest.epic_id or "")
            _incoming_epic_id = str(manifest.epic_id or "")
            if (
                (_current_epic_branch
                 and _incoming_epic_branch
                 and _current_epic_branch != _incoming_epic_branch)
                or (_current_epic_id
                    and _incoming_epic_id
                    and _current_epic_id != _incoming_epic_id)
            ):
                raise ForeignAuthoritativePointerConflict(
                    "active pointer holds a different epic's manifest "
                    f"({_current_epic_branch!r}); refusing to overwrite it "
                    f"with {_incoming_epic_branch!r} "
                    "(fail-closed foreign-epic pointer guard)"
                )
    _retain_previous_generation(pointer, manifest)
    _atomic_write(pointer, _write_payload(manifest, pointer, pointer_write=True))


def write_active_pointer(manifest: RuntimeManifest, path: Path | None = None) -> Path:
    """Atomically switch the active-generation pointer to *manifest*.

    The pointer is the manifest file AT the stable bootstrap path (see
    :func:`active_manifest_path`) — the file itself IS the active generation.
    Under the canonical ``<name>.promotion.lock`` then ``<name>.lock`` pair:
    the previous generation (when the pointer already holds an earlier one) is
    retained at ``<path>.previous-<N>.json`` for rollback, then *manifest* is
    written to *path* via atomic tmp+rename. Returns the pointer path.

    The pointer's ``compatibility_only`` demotion is DURABLE (G2 second
    re-run): once the pointer holds a ``compatibility_only`` manifest (as
    ``arnold-runtime-create`` always writes it), EVERY subsequent pointer
    write keeps the marker, so ``advance_generation`` (arnold-promote) and
    pointer ``set_state`` (arnold-close) can never re-admit the global
    pointer as authoritative. Preservation lives in the single shared
    payload builder :func:`_write_payload` — the same one the generic
    :func:`write_manifest` uses, so a demoted pointer can never be re-admitted
    authoritative by ANY writer (G2 final fix).
    """
    pointer = Path(path) if path is not None else active_manifest_path()
    pointer = pointer.expanduser().resolve(strict=False)
    with manifest_transaction_lock(pointer):
        pointer.parent.mkdir(parents=True, exist_ok=True)
        _write_active_pointer_locked(manifest, pointer)
    return pointer


# ── attestation ─────────────────────────────────────────────────────────────


def attest_runtime(
    manifest: RuntimeManifest, *, module_name: str = "arnold_pipelines"
) -> dict[str, Any]:
    """Content attestation of the runtime named by *manifest*.

    Reuses ``shadow_attestation.attest_target_content`` against
    ``manifest.epic["runtime_root"]`` and *module_name*. NEVER raises — probe
    failures are returned in ``errors``. Returns exactly:
    ``{"module_file", "module_digest", "mount_id",
    "declared_vs_observed_match", "errors"}``.
    """
    try:
        attestation = attest_target_content(
            Path(manifest.epic["runtime_root"]), module_name=module_name
        )
        return {
            "module_file": attestation.module_file,
            "module_digest": attestation.module_digest,
            "mount_id": attestation.mount_id,
            "declared_vs_observed_match": attestation.declared_vs_observed_match,
            "errors": list(attestation.errors),
        }
    except Exception as exc:  # noqa: BLE001 - contract: attest_runtime never raises
        return {
            "module_file": "",
            "module_digest": "",
            "mount_id": "",
            "declared_vs_observed_match": False,
            "errors": [f"attestation_failed:{exc}"],
        }


# ── transitions (immutable: every function returns a NEW manifest) ──────────


def _reconstruct(
    manifest: RuntimeManifest, **overrides: Any
) -> RuntimeManifest:
    """New manifest from *manifest* with *overrides* applied to top-level fields."""
    values: dict[str, Any] = {
        "runtime_id": manifest.runtime_id,
        "schema": manifest.schema,
        "generation": manifest.generation,
        "epic_id": manifest.epic_id,
        "state": manifest.state,
        "owner": manifest.owner,
        "base": manifest.base,
        "epic": manifest.epic,
        "indirection": manifest.indirection,
        "policy": manifest.policy,
        "promotions": manifest.promotions,
        "timestamps": manifest.timestamps,
        "gc_policy": manifest.gc_policy,
        "commands": manifest.commands,
        "deviations": manifest.deviations,
        "compatibility_only": manifest.compatibility_only,
    }
    values.update(overrides)
    return RuntimeManifest(**values)


def refresh_legacy_session_copy(
    manifest: RuntimeManifest, authoritative_path: Path
) -> Path | None:
    """Refresh the creation-time legacy session-copy mirror, if one exists.

    ``arnold-runtime-create`` wrote ``{manifest_dir}/{epic_id}.json`` once at
    creation, and generation advances historically never refreshed it —
    leaving a SECOND identity surface that silently lagged the authoritative
    per-slug manifest (occurrence c2f73c7ddcef, 2026-08-28: gen-19 advance
    left the gen-13 copy behind, and the cloud-session marker
    ``relaunch_command`` still selected it, so every launch admitted through
    that copy failed with ``source_revision_mismatch``).

    The authoritative per-slug manifest is the only launch selector; this
    copy is a compatibility mirror. Best-effort: unknown/unrelated files are
    left untouched and write failures are reported, never fatal — the
    advance itself has already succeeded when this runs.

    Returns the refreshed path, or ``None`` when there was nothing to do.
    """
    session_dir = Path(
        os.environ.get("ARNOLD_RUNTIME_MANIFEST_DIR", "/workspace/.megaplan")
    )
    legacy = (session_dir / f"{manifest.epic_id}.json").resolve(strict=False)
    authoritative = Path(authoritative_path).expanduser().resolve(strict=False)
    if legacy == authoritative or not legacy.is_file():
        return None
    try:
        stale = load_manifest(legacy)
    except ManifestError:
        # Not a parseable manifest: an unrelated file owns that name; never
        # overwrite what this seam did not create.
        return None
    if str(stale.runtime_id) != str(manifest.runtime_id):
        return None
    write_manifest(manifest, legacy)
    return legacy


def advance_generation(
    manifest: RuntimeManifest,
    new_commit: str,
    *,
    reason: str,
    dependency_generation: Mapping[str, Any] | None = None,
) -> RuntimeManifest:
    """Return a NEW manifest at ``generation + 1`` pinned to *new_commit*.

    ``epic.expected_head`` and ``indirection.verified_head`` move to
    *new_commit*, ``timestamps.updated`` is stamped, and the PREVIOUS
    generation is retained via ``promotions.append`` — the rollback record::

        {"previous_generation", "previous_commit", "reason", "at"}

    T-0301 publication gate: the dependency-generation proof is REQUIRED —
    *dependency_generation* (a freshly built/verified proof for the new
    head's frozen spec) when given, else the manifest's CURRENT complete
    proof, carried into the new generation.  A manifest with NO complete
    proof (``dependency_generation_proof`` is ``None``) is REFUSED with
    :class:`ManifestError`: promoting a runtime whose dependency state is
    unknown would publish an unverifiable generation (fail-closed, G10).
    The original manifest is untouched.
    """
    if dependency_generation is not None:
        proof = validate_dependency_generation(dependency_generation)
    else:
        proof = dependency_generation_proof(manifest)
    if proof is None:
        raise ManifestError(
            "advance_generation refused: manifest carries no complete "
            "dependency_generation proof; unknown dependency state blocks "
            "publication (T-0301)"
        )
    # Codex fix 2026-08-17: conditional dependency-proof carry-forward. The
    # proposed OR carried proof must bind to the NEW commit's frozen
    # dependency spec — carrying a proof merely because it was valid for the
    # previous source commit is a proof-substitution hole. Recompute the
    # frozen-spec digest from the runtime root and verify the interpreter path
    # and venv digest still resolve to that generation.
    _verify_dependency_generation_binding(
        proof,
        runtime_root=str(manifest.epic.get("runtime_root") or ""),
    )
    # Git-object head guard: the new commit must be a 40-hex SHA that
    # RESOLVES to that exact commit in the runtime root.  This rejects the
    # recurring fake-head corruption (10-char real prefix + fabricated tail)
    # BEFORE any promotion record or pointer write (codex fix 2026-08-17).
    _require_resolvable_head(manifest.epic.get("runtime_root"), new_commit)
    previous_commit = str(manifest.epic.get("expected_head", ""))
    now = _utc_now()
    promotions = list(manifest.promotions) + [
        {
            "previous_generation": manifest.generation,
            "previous_commit": previous_commit,
            "reason": reason,
            "at": now,
        }
    ]
    return _reconstruct(
        manifest,
        generation=manifest.generation + 1,
        epic=dict(
            manifest.epic,
            expected_head=new_commit,
            dependency_generation=dict(proof),
        ),
        indirection=dict(manifest.indirection, verified_head=new_commit),
        promotions=promotions,
        timestamps=dict(manifest.timestamps, updated=now),
    )

def advance_generation_at_path(
    manifest_path: Path,
    new_commit: str,
    *,
    reason: str,
    dependency_generation: Mapping[str, Any] | None = None,
    expected: tuple[str, int, str] | None = None,
    idempotent_when_pinned: bool = False,
) -> tuple[RuntimeManifest, str]:
    """Advance the manifest at *manifest_path* to *new_commit* under lock+CAS.

    Shared producer for the module CLI and the auto-driver publish hook
    (occurrence d51891b51841: the auto-publish commit moves the runtime root
    HEAD, and the bound manifest pin must move with it before the next
    worker launch, or the launch attestation fails closed with
    ``runtime_launch_attestation_mismatch``).

    Discipline (single writer seam, Sol stage-2 d51891b51841):

    1. Acquire the canonical lock pair for the manifest (and active pointer
       when distinct), with every ``.promotion.lock`` acquired before any
       ordinary ``.lock``. The module CLI, cutover, watchdog promotion, and
       ordinary writers therefore share one mutation fence.
    2. Re-load the manifest INSIDE the lock.
    3. CAS-check ``(runtime_id, generation, expected_head)`` against the
       caller's *expected* snapshot when given: a concurrent advance
       between the caller's read and this lock refuses with
       :class:`ManifestError` (ZERO mutation) instead of clobbering it.
    4. With *idempotent_when_pinned* (set by the auto-driver publish hook),
       a pin already at *new_commit* returns ``(current, "current")``
       without bumping the generation; the module CLI keeps its
       re-promotion semantics (a same-commit advance still bumps — its
       committed CLI contract).
    5. Run :func:`advance_generation` inside the lock — the frozen-spec
       dependency-generation proof binding and the resolvable-head guard
       are enforced there.
    6. Persist in the module CLI order: pointer switch first (atomic,
       retains the previous generation for rollback), then the per-path
       manifest when distinct, then best-effort legacy session-copy
       refresh (a hygiene failure is a warning, never a masked advance).

    Returns ``(manifest, status)`` with status ``"advanced"`` or
    ``"current"``.
    """
    path = Path(manifest_path).expanduser().resolve(strict=False)
    pointer = active_manifest_path().expanduser().resolve(strict=False)
    with manifest_transaction_lock(path, pointer):
        current = load_manifest(path)
        if expected is not None:
            snapshot = (
                str(current.runtime_id),
                int(current.generation),
                str(current.epic.get("expected_head") or ""),
            )
            if snapshot != (
                str(expected[0]),
                int(expected[1]),
                str(expected[2]),
            ):
                raise ManifestError(
                    "advance_generation_at_path refused: manifest changed under "
                    f"the caller (snapshot runtime_id={expected[0]} "
                    f"generation={expected[1]} expected_head={expected[2]}; live "
                    f"runtime_id={snapshot[0]} generation={snapshot[1]} "
                    f"expected_head={snapshot[2]})"
                )
        pin = str(current.epic.get("expected_head") or "")
        if pin == str(new_commit) and idempotent_when_pinned:
            return current, "current"
        advanced = advance_generation(
            current,
            new_commit,
            reason=reason,
            dependency_generation=dependency_generation,
        )
        if path == pointer.expanduser().resolve(strict=False):
            # The caller passed the pointer itself — the switch IS the write.
            _write_active_pointer_locked(advanced, pointer)
        else:
            # Pointer switch FIRST (atomic, retains the previous generation
            # for rollback), then the per-path manifest: a retry after a
            # mid-write failure re-reads the pre-advance manifest and lands
            # on the same generation + commit (idempotent).
            _write_active_pointer_locked(advanced, pointer)
            _write_manifest_locked(advanced, path)
    try:
        refreshed = refresh_legacy_session_copy(advanced, path)
        if refreshed is not None:
            print(
                f"refreshed legacy session copy: {refreshed}",
                file=sys.stderr,
            )
    except OSError as exc:  # hygiene failure must not mask the advance
        print(
            f"warning: legacy session copy refresh failed: {exc}",
            file=sys.stderr,
        )
    return advanced, "advanced"


def _verify_dependency_generation_binding(
    proof: Mapping[str, Any],
    *,
    runtime_root: str,
) -> None:
    """Fail-closed proof→commit binding (Codex fix 2026-08-17).

    Recompute the frozen dependency-spec digest from *runtime_root* (the
    checkout AT the new commit) and require the proposed/carried proof to bind
    to it: ``proof["frozen_spec_sha256"] == candidate``, the proof's
    ``interpreter_path`` must live inside the content-addressed generation
    directory named by that digest, and the recomputed ``venv_digest`` must
    match the recorded one.  Any mismatch is :class:`ManifestError` — a proof
    valid only for a previous commit is never carried forward.
    """
    if not runtime_root:
        raise ManifestError(
            "advance_generation refused: epic.runtime_root is empty; cannot "
            "verify the dependency-generation binding"
        )
    try:
        candidate = frozen_spec_sha256(runtime_root)
    except GenerationError as exc:
        raise ManifestError(
            "advance_generation refused: cannot compute the frozen dependency-"
            f"spec digest at {runtime_root}: {exc}"
        ) from exc
    if str(proof.get("frozen_spec_sha256") or "") != candidate:
        raise ManifestError(
            "advance_generation refused: dependency-generation proof is bound "
            f"to frozen_spec_sha256 {proof.get('frozen_spec_sha256')!r} but the "
            f"new commit's frozen spec digest is {candidate!r}; rebuild or "
            "select the matching content-addressed generation before advancing"
        )
    interpreter = Path(str(proof.get("interpreter_path") or "")).expanduser()
    generation_dir = interpreter.resolve(strict=False).parent.parent
    if generation_dir.name != candidate:
        raise ManifestError(
            "advance_generation refused: dependency-generation "
            f"interpreter_path {interpreter} does not live inside the "
            f"content-addressed generation dir named {candidate!r}"
        )
    if not interpreter.is_file():
        raise ManifestError(
            "advance_generation refused: dependency-generation interpreter "
            f"is missing: {interpreter}"
        )
    try:
        observed = compute_venv_digest(interpreter)
    except Exception as exc:  # noqa: BLE001 - any failure blocks publication
        raise ManifestError(
            f"advance_generation refused: cannot recompute venv_digest: {exc}"
        ) from exc
    if observed != str(proof.get("venv_digest") or ""):
        raise ManifestError(
            "advance_generation refused: dependency-generation venv_digest "
            f"mismatch (recorded {proof.get('venv_digest')!r}, observed "
            f"{observed!r}); the immutable generation was modified or rebuilt"
        )


def cutover_runtime_manifest(
    manifest: RuntimeManifest,
    *,
    from_runtime_root: str,
    from_expected_head: str,
    to_runtime_root: str,
    to_expected_head: str,
    to_venv_path: str,
    to_repair_bin: str,
    reason: str,
    to_dependency_generation: Mapping[str, Any] | None = None,
) -> RuntimeManifest:
    """Return a NEW manifest cut over to a receipted runtime at ``generation + 1``.

    Guards (CAS): *from_runtime_root* / *from_expected_head* must equal the
    manifest's current ``epic.runtime_root`` / ``epic.expected_head`` — any
    mismatch raises :class:`ManifestError` and leaves *manifest* untouched.
    On success the manifest moves, atomically as one new instance:

    - ``epic.runtime_root`` / ``epic.worktree_path`` -> *to_runtime_root*
      (the worktree IS the runtime root by schema convention)
    - ``epic.expected_head`` -> *to_expected_head*
    - ``epic.venv_path`` -> *to_venv_path*, ``epic.repair_bin`` -> *to_repair_bin*
    - root-relative fields follow the root: ``epic.deps_lockfile``,
      ``base.venv_path``, and ``base.editable_install_path`` are RELOCATED to
      the same relative offset under *to_runtime_root* when they resolve
      inside the from-root (the staging layout writes ``{root}/pyproject.toml``,
      ``{root}/.venv``, ``{root}/``), so a moved root never leaves them
      stale.  Shared paths OUTSIDE the runtime root (e.g. a base checkout)
      are untouched — they do not go stale.  ``base.ref`` is a git ref NAME,
      not a path: it names the source branch the runtime was created from
      and is source-based, so a cutover deliberately leaves it in place
      (the receipted identity is source-based; only the root moves).
      ``base.editable_install_path == ''`` is preserved as-is ONLY when the
      calling cutover has proven the receipted identity is single-root /
      non-editable (``apply_runtime_manifest_cutover`` refuses otherwise).
    - ``base.commit`` -> *to_expected_head* when it currently pins
      *from_expected_head* (schema-consistent manifests keep the base commit
      in sync with the head; a base pinned to something else is left alone —
      the cutover never silently rewrites a foreign pin)
    - ``indirection.verified_head`` -> *to_expected_head* and
      ``indirection.host_path`` -> *to_runtime_root* (the host side of the
      runtime root follows the epic root, mirroring how
      :func:`advance_generation` moves ``verified_head`` with the head)

    T-0301 publication gate: the dependency-generation proof is REQUIRED —
    *to_dependency_generation* (a freshly built/verified proof for the
    receipted runtime's frozen spec) when given, else the manifest's CURRENT
    complete proof carried into the new generation.  A manifest with NO
    complete proof is REFUSED with :class:`ManifestError`: cutting over a
    runtime whose dependency state is unknown would publish an unverifiable
    generation (fail-closed, G10).  The proof's ``interpreter_path`` follows
    the root when it resolves inside the from-root (legacy staging layout);
    a shared generation outside the runtime root is untouched.

    ``generation`` is incremented and a promotion/rollback record is appended
    (see :func:`advance_generation`; the record additionally carries the
    previous runtime root / venv / repair bin for an in-manifest rollback
    trail). ``timestamps.updated`` is stamped. ``compatibility_only`` and
    ``deviations`` are preserved verbatim via :func:`_reconstruct`.
    """
    if not all(
        str(value or "").strip()
        for value in (
            from_runtime_root,
            from_expected_head,
            to_runtime_root,
            to_expected_head,
            to_venv_path,
            to_repair_bin,
            reason,
        )
    ):
        raise ManifestError("cutover requires every from/to field and a reason")
    epic = dict(manifest.epic)
    if str(epic.get("runtime_root") or "") != from_runtime_root:
        raise ManifestError(
            "cutover refused: from-runtime-root does not match "
            "manifest epic.runtime_root"
        )
    if str(epic.get("expected_head") or "") != from_expected_head:
        raise ManifestError(
            "cutover refused: from-expected-head does not match "
            "manifest epic.expected_head"
        )
    # Git-object head guard: the TARGET head must be a 40-hex SHA that
    # RESOLVES to that exact commit in the TARGET runtime root.  This rejects
    # the recurring fake-head corruption (10-char real prefix + fabricated
    # tail) BEFORE any promotion record or manifest write (codex fix
    # 2026-08-17).  The FROM side is CAS-guarded above by equality; only the
    # TO side is git-verified (a from-side fake head is historical evidence).
    _require_resolvable_head(to_runtime_root, to_expected_head)
    now = _utc_now()
    promotions = list(manifest.promotions) + [
        {
            "previous_generation": manifest.generation,
            "previous_commit": str(epic.get("expected_head") or ""),
            "previous_runtime_root": str(epic.get("runtime_root") or ""),
            "previous_venv_path": str(epic.get("venv_path") or ""),
            "previous_repair_bin": str(epic.get("repair_bin") or ""),
            "reason": reason,
            "at": now,
        }
    ]
    base = dict(manifest.base)
    if str(base.get("commit") or "") == from_expected_head:
        base["commit"] = to_expected_head
    indirection = dict(manifest.indirection)
    indirection["verified_head"] = to_expected_head
    indirection["host_path"] = to_runtime_root
    # Root-relative field coherence (T-0101h round-2): the staging layout
    # writes base.venv_path / epic.deps_lockfile / base.editable_install_path
    # as paths INSIDE the runtime root, so they go STALE when the root moves.
    # Relocate any root-relative path to the same relative offset under the
    # new root; shared paths (a base checkout outside the runtime) are
    # untouched. base.ref is a git ref name — source-based, never rewritten
    # by a root move (documented in the docstring above).
    resolved_from_root = Path(from_runtime_root).expanduser().resolve(strict=False)
    resolved_to_root = Path(to_runtime_root).expanduser().resolve(strict=False)
    base["venv_path"] = _relocate_root_relative(
        base.get("venv_path"), resolved_from_root, resolved_to_root
    )
    base["editable_install_path"] = _relocate_root_relative(
        base.get("editable_install_path"), resolved_from_root, resolved_to_root
    )
    relocated_deps_lockfile = _relocate_root_relative(
        epic.get("deps_lockfile"), resolved_from_root, resolved_to_root
    )
    if to_dependency_generation is not None:
        generation = validate_dependency_generation(to_dependency_generation)
    else:
        generation = dependency_generation_proof(manifest)
    if generation is None:
        raise ManifestError(
            "cutover refused: manifest carries no complete "
            "dependency_generation proof; unknown dependency state blocks "
            "publication (T-0301)"
        )
    # A root-relative generation interpreter (legacy staging layout, venv
    # inside the worktree) follows the root; the shared content-addressed
    # generation store lives OUTSIDE the runtime root and is untouched.
    generation = dict(generation)
    generation["interpreter_path"] = _relocate_root_relative(
        generation.get("interpreter_path"), resolved_from_root, resolved_to_root
    )
    return _reconstruct(
        manifest,
        generation=manifest.generation + 1,
        base=base,
        epic={
            **epic,
            "runtime_root": to_runtime_root,
            "worktree_path": to_runtime_root,
            "expected_head": to_expected_head,
            "venv_path": to_venv_path,
            "repair_bin": to_repair_bin,
            "deps_lockfile": relocated_deps_lockfile,
            "dependency_generation": generation,
        },
        indirection=indirection,
        promotions=promotions,
        timestamps=dict(manifest.timestamps, updated=now),
    )


def set_state(manifest: RuntimeManifest, state: str) -> RuntimeManifest:
    """Return a NEW manifest with ``state`` changed to *state*.

    *state* must be ``"active"`` or ``"closed"`` (else :class:`ManifestError`).
    Closing stamps ``timestamps.closed``; reopening leaves the historical
    ``closed`` timestamp in place (it records the last close, never cleared).
    """
    if state not in _VALID_STATES:
        raise ManifestError(
            f"state must be one of {sorted(_VALID_STATES)}, got {state!r}"
        )
    timestamps = dict(manifest.timestamps)
    if state == "closed":
        timestamps["closed"] = _utc_now()
    return _reconstruct(manifest, state=state, timestamps=timestamps)


def append_promotion(
    manifest: RuntimeManifest, record: dict[str, Any]
) -> RuntimeManifest:
    """Return a NEW manifest with *record* appended to ``promotions``.

    Present, non-empty commit fields (``previous_commit``, ``from_sha``,
    ``to_sha``) are shape-checked as 40-hex git SHAs; a record that omits
    them (or leaves them empty) is still accepted, and no git lookup is
    performed here — a journal record can legitimately describe a commit in
    a source repository other than the manifest's current runtime root
    (codex fix 2026-08-17).
    """
    if not isinstance(record, dict):
        raise ManifestError("promotion record must be an object")
    for key in ("previous_commit", "from_sha", "to_sha"):
        value = record.get(key)
        if value not in (None, ""):
            _require_git_sha40(value, label=key)
    return _reconstruct(manifest, promotions=list(manifest.promotions) + [record])


# ── deviations (expiring exception records) ─────────────────────────────────


_DEVIATION_REQUIRED = (
    "kind",
    "id",
    "issued_at",
    "expires_at",
    "actor",
    "reason",
    "evidence",
    "chain_digest",
)
_DEVIATION_MAX_LIFETIME = timedelta(hours=24)
_ALLOW_MANIFESTLESS_KIND = "allow_manifestless"


def _parse_utc_iso(value: Any, label: str) -> datetime:
    """Parse *value* as a UTC ISO8601 timestamp; raise :class:`ManifestError`
    on anything else (non-string, unparsable, naive, or non-UTC offset)."""
    if not isinstance(value, str) or not value:
        raise ManifestError(f"deviation {label} must be a non-empty ISO8601 string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ManifestError(f"deviation {label} is not ISO8601: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ManifestError(f"deviation {label} must be UTC: {value!r}")
    return parsed


def validate_deviation(record: Any, *, now: str | None = None) -> dict[str, Any]:
    """Validate a deviation/permit record for ADDITION or ADMISSION.

    Rejects (raises :class:`ManifestError`): non-object records; missing or
    empty ``kind``/``id``/``issued_at``/``expires_at``/``actor``/``reason``/
    ``evidence``/``chain_digest``; non-UTC ``issued_at``/``expires_at``;
    lifetimes outside ``0 < expires_at - issued_at <= 24h``; and records
    already expired at *now* (default: UTC now). ``evidence`` must be a list
    of strings. Unknown keys (e.g. a ``revoked_at`` tombstone) are tolerated
    and preserved — the record is returned unchanged on success.

    Expiry is enforced at call time only: an expired record is REFUSED here
    but stays loadable inside a manifest (:func:`load_manifest` never checks
    the clock; admission uses :func:`has_valid_allow_manifestless_permit`).
    """
    if not isinstance(record, dict):
        raise ManifestError("deviation record must be an object")
    missing = [key for key in _DEVIATION_REQUIRED if key not in record]
    if missing:
        raise ManifestError(
            f"deviation missing required fields: {', '.join(missing)}"
        )
    for field_name in ("kind", "id", "actor", "reason", "chain_digest"):
        if not isinstance(record[field_name], str) or not record[field_name]:
            raise ManifestError(
                f"deviation {field_name} must be a non-empty string"
            )
    issued = _parse_utc_iso(record["issued_at"], "issued_at")
    expires = _parse_utc_iso(record["expires_at"], "expires_at")
    evidence = record["evidence"]
    if not isinstance(evidence, list) or not all(
        isinstance(item, str) for item in evidence
    ):
        raise ManifestError("deviation evidence must be a list of strings")
    lifetime = expires - issued
    if lifetime <= timedelta(0) or lifetime > _DEVIATION_MAX_LIFETIME:
        raise ManifestError(
            f"deviation lifetime must be within (0, 24h], got {lifetime}"
        )
    now_dt = _parse_utc_iso(now, "now") if now is not None else datetime.now(timezone.utc)
    if expires <= now_dt:
        raise ManifestError(f"deviation expired at {record['expires_at']}")
    return record


def has_valid_allow_manifestless_permit(manifest: RuntimeManifest) -> bool:
    """True iff *manifest* carries a currently-valid ``allow_manifestless`` permit.

    Admission-time check for manifest-less operation: the manifest must hold a
    deviation with ``kind == "allow_manifestless"`` that is structurally valid
    AND unexpired right now. A revoked permit (a ``revoked_at`` tombstone) or
    an expired one NEVER admits; invalid records are skipped, so one bad record
    cannot admit anything (fail-closed).
    """
    for record in manifest.deviations:
        if record.get("kind") != _ALLOW_MANIFESTLESS_KIND:
            continue
        if record.get("revoked_at"):
            continue
        try:
            validate_deviation(record)
        except ManifestError:
            continue
        return True
    return False


def add_deviation(
    manifest: RuntimeManifest, record: dict[str, Any]
) -> RuntimeManifest:
    """Return a NEW manifest with validated *record* appended to ``deviations``.

    The record is validated (structure, lifetime, current-unexpired) BEFORE
    the append — an invalid record raises :class:`ManifestError` and leaves
    *manifest* untouched. Immutable: the original manifest is never modified.
    """
    validate_deviation(record)
    return _reconstruct(manifest, deviations=list(manifest.deviations) + [record])


def _parse_json_record(arg: str) -> dict[str, Any]:
    """Parse the ``append_promotion`` / ``add_deviation`` CLI *record* argument.

    Accepted forms: inline JSON (``{"from_sha": …}``), ``@FILE`` (read the
    record from FILE), or a bare path to an existing JSON file. Returns the
    parsed record, which MUST be a JSON object.
    """
    if arg.startswith("@"):
        source = Path(arg[1:])
        try:
            raw = source.read_text(encoding="utf-8")
        except OSError as exc:
            raise ManifestError(
                f"cannot read promotion record file {source}: {exc}"
            ) from exc
    else:
        candidate = Path(arg)
        try:
            raw = candidate.read_text(encoding="utf-8")
        except OSError:
            raw = arg
    try:
        record = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"promotion record is not valid JSON: {exc}") from exc
    if not isinstance(record, dict):
        raise ManifestError("promotion record must be a JSON object")
    return record


def _write_manifest_or_pointer(manifest: RuntimeManifest, path: Path) -> None:
    """Write *manifest* to *path*, through the active pointer when *path* IS
    the active-generation pointer (state transitions written to the pointer
    keep the file AT the stable path the active generation); otherwise a
    plain per-runtime manifest write."""
    if Path(path).expanduser().resolve(strict=False) == active_manifest_path().expanduser().resolve(strict=False):
        write_active_pointer(manifest, path)
    else:
        write_manifest(manifest, path)


# ── CAS runtime cutover (T-0101d) ───────────────────────────────────────────


def _relocate_root_relative(
    value: Any, from_root: Path, to_root: Path
) -> str:
    """Relocate a root-relative path to the new runtime root.

    A path that resolves INSIDE *from_root* (the staging layout's
    ``{root}/.venv``, ``{root}/pyproject.toml``, ``{root}/uv.lock``, or the
    root itself) moves WITH the root: the cutover re-roots it at the same
    relative offset under *to_root* — the exact layout a created worktree
    has.  Empty values and paths that resolve OUTSIDE the runtime root (a
    shared base checkout like ``/opt/arnold/base``) are NOT root-relative:
    they return unchanged, because they do not go stale when the runtime
    root moves.  ``resolve(strict=False)`` makes the containment check
    immune to ``..`` escapes.
    """
    text = str(value or "").strip()
    if not text:
        return str(value or "")
    candidate = Path(text).expanduser().resolve(strict=False)
    if not candidate.is_relative_to(from_root):
        return text
    relative = candidate.relative_to(from_root)
    return str(to_root.joinpath(relative).resolve(strict=False))


def _editable_markers_outside_import_root(
    identity: Mapping[str, Any],
) -> list[str]:
    """Editable-install markers in a receipted runtime identity that point
    OUTSIDE its ``import_root``.

    A single-root runtime (the staging layout: a source worktree imported via
    PYTHONPATH / the runtime root itself) collapses every editable marker
    onto ``import_root``.  A marker resolving OUTSIDE it — a distinct
    ``editable_root``, a ``file://`` ``direct_url`` outside the root, or a
    ``.pth`` entry outside it — proves the runtime is editable-installed
    from a SEPARATE location, so a cutover that keeps (or relocates) a
    ``base.editable_install_path`` that disagrees with that identity would
    silently split the runtime.  Returns the offending marker kinds (``[]``
    when the identity proves single-root / non-editable).
    """
    problems: list[str] = []
    import_root_text = str(identity.get("import_root") or "")
    if not import_root_text:
        return ["import_root"]
    import_root = Path(import_root_text).expanduser().resolve(strict=False)
    editable_root = str(identity.get("editable_root") or "")
    if editable_root and (
        Path(editable_root).expanduser().resolve(strict=False) != import_root
    ):
        problems.append("editable_root")
    direct_url = identity.get("direct_url")
    if isinstance(direct_url, Mapping):
        url = str(direct_url.get("url") or "")
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme == "file":
            direct = (
                Path(urllib.parse.unquote(parsed.path))
                .expanduser()
                .resolve(strict=False)
            )
            if not direct.is_relative_to(import_root):
                problems.append("direct_url")
    pth = identity.get("pth")
    if isinstance(pth, list):
        for record in pth:
            if not isinstance(record, Mapping):
                continue
            entries = record.get("entries")
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if isinstance(entry, str) and entry and not (
                    Path(entry)
                    .expanduser()
                    .resolve(strict=False)
                    .is_relative_to(import_root)
                ):
                    problems.append("pth")
                    break
    return sorted(set(problems))


def _verify_external_runtime_identity(
    identity_path: Path, receipt_path: Path
) -> dict[str, Any]:
    """Verify an offline runtime against its independently emitted provenance
    receipt. Lazy import keeps the manifest CLI dependency-light; the verifier
    itself is the accepted chain verifier
    (``execution_binding.verify_external_runtime_identity``), which re-runs the
    receipted interpreter and raises :class:`CliError` on any mismatch."""
    from arnold_pipelines.megaplan.chain.execution_binding import (
        verify_external_runtime_identity,
    )

    return verify_external_runtime_identity(identity_path, receipt_path)


def _validate_receipt_target(
    receipt_path: Path | None,
    *,
    manifest_path: Path,
    runtime_identity_path: Path,
    runtime_provenance_receipt_path: Path,
    lock_path: Path,
) -> Path:
    """Constrain the rollback-receipt destination (T-0101h round-5 blocker 3).

    Returns the LITERAL (unresolved) receipt path — symlink protection
    happens at write time in :func:`emit_runtime_manifest_cutover_rollback_
    receipt`, which replaces a pre-seeded symlink ENTRY at the final path
    rather than following it.  This guard refuses, with a typed
    ``receipt_aliases_protected_state`` error and ZERO mutation, a receipt
    whose REALPATH collides with protected transaction state: the manifest
    itself, either identity/provenance guard input (``--runtime-identity`` /
    ``--runtime-provenance-receipt``), or the cutover's own transaction lock
    file.  Without it a ``--receipt-out`` aliasing the manifest is overwritten
    by the final manifest write and the command "succeeds" without a durable
    rollback receipt.
    """
    receipt = (
        Path(receipt_path).expanduser()
        if receipt_path is not None
        else manifest_path.with_name(manifest_path.name + CUTOVER_RECEIPT_SUFFIX)
    )
    protected = (
        manifest_path,
        Path(runtime_identity_path).expanduser().resolve(strict=False),
        Path(runtime_provenance_receipt_path).expanduser().resolve(strict=False),
        lock_path,
    )
    try:
        resolved = receipt.resolve(strict=False)
    except OSError:
        resolved = None
    if resolved is not None:
        for protected_path in protected:
            if resolved == protected_path:
                raise CliError(
                    RECEIPT_ALIASES_PROTECTED_STATE,
                    f"receipt path {receipt} resolves onto protected "
                    f"transaction state {protected_path}",
                    extra={
                        "receipt_path": str(receipt),
                        "protected_path": str(protected_path),
                    },
                )
    return receipt


def apply_runtime_manifest_cutover(
    manifest_path: Path,
    *,
    expect_manifest_sha256: str,
    expect_generation: int,
    from_runtime_root: str,
    from_expected_head: str,
    to_runtime_root: str,
    to_expected_head: str,
    to_venv_path: str,
    to_repair_bin: str,
    runtime_identity_path: Path,
    runtime_provenance_receipt_path: Path,
    reason: str,
    actor: str = "operator",
    receipt_path: Path | None = None,
    to_dependency_generation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """CAS-guarded, fail-closed runtime cutover of the manifest at *manifest_path*.

    Refuses (typed :class:`CliError`, ZERO mutation — the manifest file, and
    any rollback receipt, are untouched) on ANY of:

    - malformed guards (non-64-hex ``expect_manifest_sha256``,
      ``expect_generation < 1``, empty from/to fields, reason or actor)
    - manifest file bytes not equal to ``expect_manifest_sha256``
    - parsed manifest ``generation`` != ``expect_generation``
    - ``epic.runtime_root``/``epic.expected_head`` != the from-guards
      (enforced by :func:`cutover_runtime_manifest`)
    - the runtime identity/provenance receipt failing
      :func:`_verify_external_runtime_identity`, or the receipted identity's
      ``import_root`` not resolving to *to_runtime_root*
    - the receipted identity's ``source_revision`` != *to_expected_head* (the
      manifest head is bound to the receipt)
    - no complete dependency-generation proof: *to_dependency_generation*
      (when given) or the manifest's current proof must be complete, or the
      cutover refuses (T-0301 — publishing a runtime whose dependency state
      is unknown is forbidden)
    - *to_venv_path* not existing as a DIRECTORY, or its interpreter
      (``<to_venv_path>/bin/python``) not existing as an EXECUTABLE; the
      manifest's generation proof ``interpreter_path`` must equal that
      interpreter (the venv binding and the proof binding must agree — a
      venv OUTSIDE the runtime root is the NORMAL shared content-addressed
      generation layout, so root containment is no longer the coherence
      anchor; the proof is)
    - *to_repair_bin* not existing as an EXECUTABLE, or resolving OUTSIDE
      *to_runtime_root* (a ``..`` escape would point the manifest at a
      runtime the receipt never verified)
    - the receipted identity carrying editable markers (``editable_root``,
      ``direct_url``, ``.pth`` entries) that resolve OUTSIDE its
      ``import_root`` while the manifest's ``base.editable_install_path`` is
      ``''`` — keeping ``''`` is only coherent for a proven single-root
      (non-editable) runtime; refusing here prevents a cutover from silently
      leaving a stale ``editable_install_path`` that splits the runtime
      identity
    - *receipt_path* realpathing onto protected transaction state — the
      manifest itself, either identity/provenance guard input, or the
      cutover's transaction lock file (typed
      ``receipt_aliases_protected_state``, ZERO mutation — checked before any
      mkdir/lock/verifier work)
    - the durable rollback receipt failing post-write verification (missing,
      corrupt, or wrong pre-cutover SHA-256) — typed
      ``receipt_post_verify_failed`` AFTER the manifest write, so the command
      never reports success without durable rollback evidence

    On success, under the canonical promotion-then-ordinary lock pair covering
    the whole read-CAS-write:
    the receipted TO-runtime facts are moved into the manifest
    (:func:`cutover_runtime_manifest` — generation + 1, promotion record,
    root-relative field relocation, ``timestamps.updated``), a rollback
    receipt capturing the old manifest SHA-256 + FULL old field set is
    written first to *receipt_path* (default
    ``<manifest-path>.cutover-rollback.json``) through a hardened atomic
    write that never follows a pre-seeded symlink, then the manifest is
    written atomically through the shared payload builder (so a demoted
    ``compatibility_only`` active pointer can never be re-admitted), and the
    receipt is post-verified before success is reported.
    """
    if not _FULL_SHA256.fullmatch(str(expect_manifest_sha256 or "")):
        raise CliError(
            CUTOVER_ERROR, "expect-manifest-sha256 must be a 64-char hex SHA-256"
        )
    if not isinstance(expect_generation, int) or expect_generation < 1:
        raise CliError(CUTOVER_ERROR, "expect-generation must be an int >= 1")
    required = {
        "from-runtime-root": from_runtime_root,
        "from-expected-head": from_expected_head,
        "to-runtime-root": to_runtime_root,
        "to-expected-head": to_expected_head,
        "to-venv-path": to_venv_path,
        "to-repair-bin": to_repair_bin,
        "reason": reason,
        "actor": actor,
    }
    for label, value in required.items():
        if not str(value or "").strip():
            raise CliError(CUTOVER_ERROR, f"{label} is required")

    target = Path(manifest_path).expanduser().resolve(strict=False)
    lock_path = manifest_lock_path(target)
    # Rollback-receipt destination is validated BEFORE any mutation: a
    # ``--receipt-out`` realpathing onto the manifest, an identity/provenance
    # guard input, or the transaction lock file is refused (typed, zero
    # mutation — no mkdir, no lock file, no receipt) — the final manifest
    # write would otherwise clobber the just-written receipt and the cutover
    # would "succeed" without durable rollback evidence (T-0101h round-5
    # blocker 3).
    receipt_target = _validate_receipt_target(
        receipt_path,
        manifest_path=target,
        runtime_identity_path=runtime_identity_path,
        runtime_provenance_receipt_path=runtime_provenance_receipt_path,
        lock_path=lock_path,
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    transaction_lock = _single_manifest_transaction_lock(target)
    transaction_lock.__enter__()
    try:
        try:
            # The launch/rollback CAS uses the same exact-byte authority
            # exposed to seed, marker, and worker admission paths.
            observed_sha = manifest_bytes_sha256(target)
        except ManifestError as exc:
            raise CliError(CUTOVER_ERROR, f"cannot read manifest: {target}") from exc
        if observed_sha != expect_manifest_sha256:
            raise CliError(
                CUTOVER_ERROR,
                f"manifest changed: expected {expect_manifest_sha256}, "
                f"observed {observed_sha}",
            )
        try:
            manifest = load_manifest(target)
        except ManifestError as exc:
            raise CliError(CUTOVER_ERROR, str(exc)) from exc
        if manifest.generation != expect_generation:
            raise CliError(
                CUTOVER_ERROR,
                f"generation mismatch: expected {expect_generation}, "
                f"observed {manifest.generation}",
            )
        # Exclusive mutable-runtime-root ownership (occurrence 0a0ce24c3510):
        # refuse a cutover into a runtime root already claimed by another
        # ACTIVE epic's manifest. The shared-root layout kills worker dispatch
        # on the shared checkout's HEAD drift (astrid-first drive2 02:58:33Z,
        # drive3 03:13:17Z). Legacy shared bindings stay recoverable: the owner
        # cuts over to a dedicated per-epic worktree first; the same branch
        # rebinding its own root is always allowed. Typed
        # ``runtime_root_ownership_conflict``, zero mutation.
        try:
            from arnold_pipelines.megaplan.cloud.runtime_root_registry import (
                assert_runtime_root_claimable,
            )

            owners = assert_runtime_root_claimable(
                to_runtime_root,
                str((manifest.epic or {}).get("branch") or ""),
                target.parent,
                exclude_manifest=target,
            )
            legacy_shared = [
                root for root, entries in owners.items() if len(entries) > 1
            ]
            if legacy_shared:
                log.warning(
                    "runtime-root legacy inventory: shared mutable roots %s "
                    "(recommended: dedicated per-epic worktrees)",
                    sorted(legacy_shared),
                )
        except CliError as exc:
            raise
        # The runtime identity/provenance receipt is verified BEFORE any write
        # (the verifier re-runs the receipted interpreter; a stale or forged
        # receipt refuses here with zero mutation).
        verified = _verify_external_runtime_identity(
            Path(runtime_identity_path), Path(runtime_provenance_receipt_path)
        )
        verified_root = str(verified.get("import_root") or "").strip()
        to_root = Path(to_runtime_root).expanduser().resolve(strict=False)
        if not verified_root or Path(verified_root).expanduser().resolve(strict=False) != to_root:
            raise CliError(
                CUTOVER_ERROR,
                "receipted runtime identity does not match --to-runtime-root",
            )
        # The manifest's new expected_head is bound to the RECEIPT: the
        # receipted source revision must equal --to-expected-head, so the
        # cutover can never stamp a head the independently verified runtime
        # did not actually resolve to (zero mutation on mismatch).
        verified_source = str(verified.get("source_revision") or "").strip()
        if not verified_source or verified_source != to_expected_head:
            raise CliError(
                CUTOVER_ERROR,
                "receipted runtime source revision does not match "
                "--to-expected-head",
            )
        # ── TO-path coherence (T-0101h round-2 + T-0301) ─────────────────
        # The cutover may only move the manifest onto a runtime that actually
        # EXISTS at the to-paths: the repair wrapper must be a real
        # executable resolving INSIDE the receipted runtime root (a ``..``
        # escape would point the manifest at a runtime outside the verified
        # root).  The venv is now the content-addressed dependency generation
        # (T-0301): it must exist as a directory, its interpreter
        # ``<venv>/bin/python`` must exist and be executable, and the
        # manifest's generation-proof ``interpreter_path`` must equal that
        # interpreter — the venv binding and the proof binding must AGREE.  A
        # shared generation legitimately lives OUTSIDE the runtime root, so
        # root containment is no longer the venv coherence anchor; the proof
        # is.  Any failure is a typed refusal with zero mutation and no
        # rollback receipt.
        venv_resolved = Path(to_venv_path).expanduser().resolve(strict=False)
        repair_resolved = Path(to_repair_bin).expanduser().resolve(strict=False)
        if not venv_resolved.is_dir():
            raise CliError(
                CUTOVER_ERROR,
                f"--to-venv-path is not an existing directory: {to_venv_path}",
            )
        if not repair_resolved.is_file() or not os.access(repair_resolved, os.X_OK):
            raise CliError(
                CUTOVER_ERROR,
                f"--to-repair-bin is not an existing executable: {to_repair_bin}",
            )
        if not repair_resolved.is_relative_to(to_root):
            raise CliError(
                CUTOVER_ERROR,
                "--to-repair-bin must resolve inside --to-runtime-root",
            )
        # The generation proof (override or preserved) is resolved BEFORE
        # the interpreter check so a missing/incomplete proof blocks the
        # cutover with the typed refusal (T-0301 publication gate).
        if to_dependency_generation is not None:
            to_proof = validate_dependency_generation(to_dependency_generation)
        else:
            to_proof = dependency_generation_proof(manifest)
        if to_proof is None:
            raise CliError(
                CUTOVER_ERROR,
                "manifest carries no complete dependency_generation proof and "
                "no --to-dependency-generation was given; unknown dependency "
                "state blocks publication (T-0301)",
            )
        proof_interpreter = str(to_proof.get("interpreter_path") or "")
        expected_interpreter = str(venv_resolved / "bin" / "python")
        if (
            Path(proof_interpreter).expanduser().resolve(strict=False)
            != Path(expected_interpreter).expanduser().resolve(strict=False)
        ):
            raise CliError(
                CUTOVER_ERROR,
                "--to-venv-path interpreter does not match the generation "
                f"proof: proof interpreter_path {proof_interpreter!r} vs "
                f"venv interpreter {expected_interpreter!r}",
            )
        interpreter_resolved = Path(proof_interpreter).expanduser().resolve(strict=False)
        if not interpreter_resolved.is_file() or not os.access(
            interpreter_resolved, os.X_OK
        ):
            raise CliError(
                CUTOVER_ERROR,
                f"--to-venv-path interpreter is not an existing executable: "
                f"{proof_interpreter}",
            )
        # ── base.editable_install_path coherence ─────────────────────────
        # An EMPTY editable_install_path (the staging default) survives the
        # cutover ONLY when the receipted identity proves a single-root
        # runtime — every editable marker collapses onto import_root.  A
        # runtime with editable markers OUTSIDE its import_root is
        # editable-installed from a separate location; keeping '' (or a
        # relocated stale path) would silently split the runtime identity, so
        # the cutover refuses with a typed error.
        outside_markers = _editable_markers_outside_import_root(verified)
        if outside_markers:
            raise CliError(
                CUTOVER_ERROR,
                "receipted runtime identity carries editable markers outside "
                "import_root; refusing a cutover that cannot keep "
                "base.editable_install_path coherent: "
                + ", ".join(outside_markers),
            )
        try:
            updated = cutover_runtime_manifest(
                manifest,
                from_runtime_root=from_runtime_root,
                from_expected_head=from_expected_head,
                to_runtime_root=to_runtime_root,
                to_expected_head=to_expected_head,
                to_venv_path=to_venv_path,
                to_repair_bin=to_repair_bin,
                reason=reason,
                to_dependency_generation=to_proof,
            )
        except ManifestError as exc:
            raise CliError(CUTOVER_ERROR, str(exc)) from exc

        # Deterministic after-image (the exact bytes _atomic_write will emit:
        # sort_keys JSON + trailing newline) so the rollback receipt can carry
        # both the before and after manifest SHA-256.
        payload = _write_payload(updated, target)
        encoded = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
        after_sha = hashlib.sha256(encoded).hexdigest()

        # Rollback receipt FIRST: it captures only pre-cutover facts (old
        # manifest SHA-256 + full old field set), so it stays accurate even if
        # the manifest write below fails — and a guard failure above already
        # refused with no receipt at all (zero mutation).
        receipt = emit_runtime_manifest_cutover_rollback_receipt(
            receipt_target,
            manifest_path=target,
            manifest_before_sha256=observed_sha,
            manifest_after_sha256=after_sha,
            generation_before=manifest.generation,
            generation_after=updated.generation,
            from_runtime_root=from_runtime_root,
            from_expected_head=from_expected_head,
            to_runtime_root=to_runtime_root,
            to_expected_head=to_expected_head,
            to_venv_path=to_venv_path,
            to_repair_bin=to_repair_bin,
            previous_manifest=manifest.to_dict(),
            runtime_identity_sha256=str(verified.get("content_sha256") or ""),
            actor=actor,
            reason=reason,
        )
        _atomic_write(target, payload)
        # Post-verify the DURABLE rollback receipt (T-0101h round-5 blocker
        # 3): the manifest is already rewritten at this point, but the cutover
        # must NOT report success without durable rollback evidence.  A
        # missing, corrupt, or SHA-mismatched receipt refuses with a typed
        # error — the receipt write was attempted FIRST, so an operator can
        # still recover the pre-cutover state from the attempted receipt
        # path.
        try:
            verify_runtime_manifest_cutover_rollback_receipt(
                receipt_target, expected_manifest_before_sha256=observed_sha
            )
        except ValueError as exc:
            raise CliError(
                RECEIPT_POST_VERIFY_FAILED,
                "durable rollback receipt failed post-write verification at "
                f"{receipt_target}: {exc}",
                extra={
                    "receipt_path": str(receipt_target),
                    "expected_manifest_before_sha256": observed_sha,
                },
            ) from exc
    finally:
        transaction_lock.__exit__(*sys.exc_info())
    return {
        "manifest_path": str(target),
        "generation_before": manifest.generation,
        "generation_after": updated.generation,
        "manifest_before_sha256": observed_sha,
        "manifest_after_sha256": after_sha,
        "runtime_identity_sha256": str(verified.get("content_sha256") or ""),
        "rollback_receipt_path": str(receipt_target),
        "rollback_receipt": receipt,
        "promotion": updated.promotions[-1],
    }


# ── CLI ─────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    write_p = sub.add_parser("write", help="validate + atomically write <path>")
    write_p.add_argument("path", type=Path)
    write_p.add_argument(
        "--from",
        dest="from_file",
        type=Path,
        help="read manifest JSON from FILE (default: stdin)",
    )
    read_p = sub.add_parser("read", help="load + validate <path>, print JSON")
    read_p.add_argument("path", type=Path)
    attest_p = sub.add_parser(
        "attest", help="attest the runtime named by the manifest at <path>"
    )
    attest_p.add_argument("path", type=Path)
    set_p = sub.add_parser(
        "set_state",
        help="set <state> on the manifest at <path> and write it atomically",
    )
    set_p.add_argument("path", type=Path)
    set_p.add_argument("state", choices=sorted(_VALID_STATES))
    prom_p = sub.add_parser(
        "append_promotion",
        help="append a promotion record to the manifest at <path> and write it atomically",
    )
    prom_p.add_argument("path", type=Path)
    prom_p.add_argument(
        "record",
        help="promotion record as inline JSON, or @FILE to read it from FILE",
    )
    dev_p = sub.add_parser(
        "add_deviation",
        help="validate + append a deviation record to the manifest at <path> and write it atomically",
    )
    dev_p.add_argument("path", type=Path)
    dev_p.add_argument(
        "record",
        help="deviation record as inline JSON, or @FILE to read it from FILE",
    )
    adv_p = sub.add_parser(
        "advance_generation",
        help="advance the generation at <path> AND atomically switch the active-generation pointer",
    )
    adv_p.add_argument("path", type=Path)
    adv_p.add_argument(
        "new_commit", help="expected_head/verified_head of the new generation"
    )
    adv_p.add_argument(
        "--reason", required=True, help="reason recorded in the rollback record"
    )
    adv_p.add_argument(
        "--dependency-generation",
        help=(
            "the new commit's content-addressed dependency-generation proof "
            "(inline JSON or @FILE). When omitted the manifest's current "
            "complete proof is validated against the new commit's frozen spec "
            "and carried forward ONLY if it binds (T-0301/Codex 2026-08-17)"
        ),
    )
    cut_p = sub.add_parser(
        "cutover",
        help=(
            "CAS-guarded runtime cutover of the manifest at <path>: verify the "
            "receipted TO-runtime identity, move epic/base/indirection runtime "
            "facts to the to-values, bump the generation atomically, and emit a "
            "rollback receipt (old manifest SHA-256 + full old field set)"
        ),
    )
    cut_p.add_argument("path", type=Path)
    cut_p.add_argument("--expect-manifest-sha256", required=True)
    cut_p.add_argument("--expect-generation", type=int, required=True)
    cut_p.add_argument("--from-runtime-root", required=True)
    cut_p.add_argument("--from-expected-head", required=True)
    cut_p.add_argument("--to-runtime-root", required=True)
    cut_p.add_argument("--to-expected-head", required=True)
    cut_p.add_argument("--to-venv-path", required=True)
    cut_p.add_argument("--to-repair-bin", required=True)
    cut_p.add_argument("--runtime-identity", type=Path, required=True)
    cut_p.add_argument(
        "--runtime-provenance-receipt", type=Path, required=True
    )
    cut_p.add_argument("--reason", required=True)
    cut_p.add_argument("--actor", default="operator")
    cut_p.add_argument(
        "--receipt-out",
        type=Path,
        help=(
            f"rollback receipt path (default: <path>{CUTOVER_RECEIPT_SUFFIX})"
        ),
    )
    cut_p.add_argument(
        "--to-dependency-generation",
        help=(
            "the receipted runtime's content-addressed dependency-generation "
            "proof (inline JSON or @FILE); when omitted the manifest's "
            "current complete proof is carried into the new generation "
            "(T-0301 publication gate: no complete proof -> cutover refused)"
        ),
    )
    args = parser.parse_args(argv)
    try:
        if args.action == "write":
            if args.from_file is not None:
                raw = Path(args.from_file).read_text(encoding="utf-8")
            else:
                raw = sys.stdin.read()
            data = json.loads(raw)
            manifest = RuntimeManifest.from_dict(data)
            write_manifest(manifest, args.path)
            print(json.dumps(manifest.to_dict(), sort_keys=True))
        elif args.action == "read":
            manifest = load_manifest(args.path)
            print(json.dumps(manifest.to_dict(), sort_keys=True, indent=2))
        elif args.action == "attest":
            manifest = load_manifest(args.path)
            print(json.dumps(attest_runtime(manifest), sort_keys=True, indent=2))
        elif args.action == "set_state":
            manifest = load_manifest(args.path)
            updated = set_state(manifest, args.state)
            _write_manifest_or_pointer(updated, args.path)
            print(json.dumps(updated.to_dict(), sort_keys=True))
        elif args.action == "append_promotion":
            manifest = load_manifest(args.path)
            record = _parse_json_record(args.record)
            updated = append_promotion(manifest, record)
            write_manifest(updated, args.path)
            print(json.dumps(updated.to_dict(), sort_keys=True))
        elif args.action == "add_deviation":
            manifest = load_manifest(args.path)
            record = _parse_json_record(args.record)
            updated = add_deviation(manifest, record)
            write_manifest(updated, args.path)
            print(json.dumps(updated.to_dict(), sort_keys=True))
        elif args.action == "advance_generation":
            # CAS snapshot read OUTSIDE the lock; advance_generation_at_path
            # re-loads INSIDE the lock and refuses a concurrent advance
            # (occurrence d51891b51841) instead of clobbering it. Same-slug
            # publication serialization (occurrence c2f73c7ddcef): pointer +
            # per-slug manifest + legacy mirror move as one promotion; the
            # watchdog promotion path takes the identical lock.
            pre = load_manifest(args.path)
            advanced, _status = advance_generation_at_path(
                args.path,
                args.new_commit,
                reason=args.reason,
                dependency_generation=(
                    _parse_json_record(args.dependency_generation)
                    if args.dependency_generation
                    else None
                ),
                expected=(
                    str(pre.runtime_id),
                    int(pre.generation),
                    str(pre.epic.get("expected_head") or ""),
                ),
            )
            print(json.dumps(advanced.to_dict(), sort_keys=True))
        elif args.action == "cutover":
            result = apply_runtime_manifest_cutover(
                args.path,
                expect_manifest_sha256=args.expect_manifest_sha256,
                expect_generation=args.expect_generation,
                from_runtime_root=args.from_runtime_root,
                from_expected_head=args.from_expected_head,
                to_runtime_root=args.to_runtime_root,
                to_expected_head=args.to_expected_head,
                to_venv_path=args.to_venv_path,
                to_repair_bin=args.to_repair_bin,
                runtime_identity_path=args.runtime_identity,
                runtime_provenance_receipt_path=args.runtime_provenance_receipt,
                reason=args.reason,
                actor=args.actor,
                receipt_path=args.receipt_out,
                to_dependency_generation=(
                    _parse_json_record(args.to_dependency_generation)
                    if args.to_dependency_generation
                    else None
                ),
            )
            print(json.dumps(result, sort_keys=True))
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
