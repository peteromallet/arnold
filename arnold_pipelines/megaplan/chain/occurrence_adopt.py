"""T-0101e': operator-authorized, occurrence-exact owner-boundary adoption.

``chain occurrence-adopt`` adopts the SINGULAR identity-less blocked
occurrence already recorded for a chain's current plan.  It creates a
deterministic, occurrence-exact repair identity whose authority names a NEW
persisted owner-boundary adoption transaction — never the missing historical
incarnation/attempt/lease/epoch — enqueues the exact repair request through
the narrow owner-adoption wrapper, and records ONE accepted decision.

The v1 identity envelope cannot honestly represent this occurrence: it
requires a historical run incarnation, coordinator attempt, lease, and
custody epoch, while ``derive_repair_identity`` correctly forbids
reconstructing them from failure summaries.  The adoption envelope is a
scoped subtype (``megaplan-repair-identity-owner-adoption-v1``) that carries
the occurrence facts, the full CAS vector, the six runtime roots, and the
deterministic adoption authority block.  ``adopted_at``/``reason``/receipt
path/PID/hostname stay OUTSIDE the normalized identity and therefore outside
its key.

Deterministic authority:

    adoption_basis =
      canonical_json(occurrence + cas + runtime_roots + authority
                     owner/actor/scope)

    adoption_record_id =
      sha256("megaplan.owner-boundary-adoption.v1\\0" + adoption_basis)

    repair_identity_key =
      sha256(canonical_json(normalized repair identity envelope))

A rerun produces the same key.  A different plan, timestamp, failure bytes,
cursor, pause authority, chain/plan state, or runtime vector produces a
different key.

Guards (all fail closed, zero mutation on mismatch; every expected hash is
mandatory — there is no ``--force``/``--fresh``/optional fallback):

* Operator-only: ``--actor`` must be ``operator``.
* The chain must be durably paused (chain-side ``operator_pause`` authority
  plus a paused plan) — the T-0101 flow pauses first.
* Exact occurrence CAS: the current plan, phase, failure kind/code/timestamp,
  resume phase/strategy, and every expected sha256 must match a fresh reread
  of the actual bytes (chain state file, plan state file, canonical
  ``latest_failure``, canonical ``resume_cursor``, canonical pause
  authority, runtime manifest file, cloud-session marker file, runtime
  provenance receipt, and the canonical six-root payload).
* Singular failure: ``plan_state.latest_failure`` must be ONE mapping (a
  list/missing failure is ``ambiguous_failure``).
* All authoritative repair-identity locations must be EMPTY (plan state,
  plan meta, chain metadata, latest-failure metadata, current-target) — an
  already-identity-bound occurrence cannot be re-adopted.
* All six runtime roots (chain execution root, recorded engine root,
  manifest runtime root, marker runtime root, independently observed import
  root, candidate root) must be equal, and the independently verified
  runtime identity's ``import_root`` must agree.
* Every authority reference is durably persisted (flock'd, fsync'd adoption
  record) BEFORE the exact request + accepted decision are enqueued.

Writes on success only: the immutable adoption record under
``<plan dir>/evidence/occurrence-adoptions/<adoption_record_id>.json``, the
immutable repair-queue request + ONE accepted decision, and the durable
receipt at the caller-supplied ``--receipt`` path (constrained to the plan
evidence root, exactly like ``occurrence-join`` receipts).  Chain state.json
and the plan state.json are never modified.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from arnold_pipelines.megaplan._core.state import resolve_plan_dir
from arnold_pipelines.megaplan.chain import spec as chain_spec
from arnold_pipelines.megaplan.chain.execution_binding import (
    verify_external_runtime_identity,
)
from arnold_pipelines.megaplan.chain.occurrence_join import (
    ADOPTIONS_DIRNAME,
    EVIDENCE_DIRNAME,
    _validate_receipt_destination,
    _write_receipt_durably,
)
from arnold_pipelines.megaplan.chain.operator_pause import pause_record
from arnold_pipelines.megaplan.cloud import repair_requests
from arnold_pipelines.megaplan.cloud.runtime_cutover import marker_runtime_identity
from arnold_pipelines.megaplan.cloud.runtime_manifest import load_manifest
from arnold_pipelines.megaplan.types import CliError

SCHEMA = "arnold.megaplan.occurrence-adopt.v1"
IDENTITY_SCHEMA_VERSION = "megaplan-repair-identity-owner-adoption-v1"
IDENTITY_KIND = "owner_boundary_adoption"
OWNER_ADOPTED_OCCURRENCE_CONTRACT = "owner_adopted_blocked_occurrence"
OPERATOR_ACTOR = "operator"
AUTHORITY_KIND = "operator_owner_boundary_adoption"
AUTHORITY_OWNER = "megaplan.chain"
AUTHORITY_SCOPE = ("enqueue_exact_occurrence", "occurrence_join")
ADOPTION_NAMESPACE = "megaplan.owner-boundary-adoption.v1\x00"
ADOPTION_RUN_PREFIX = "repair-adoption:"
ADOPTION_ATTEMPT_PREFIX = "owner-adoption-attempt:"
ADOPTION_FENCE_TOKEN = 1
CLAIM_PREFIX = "t0101-owner-adoption:"
REPAIR_SOURCE = "owner_boundary_occurrence_adoption"
_PAUSED_PLAN_STATE = "paused"
#: Root keys of the canonical six-root payload (order is only for error
#: reporting; canonical_json sorts keys for the digest).
RUNTIME_ROOT_FIELDS = (
    "chain_execution_root",
    "recorded_engine_root",
    "manifest_runtime_root",
    "marker_runtime_root",
    "independent_import_root",
    "candidate_root",
)
CAS_FIELDS = (
    "chain_spec_sha256",
    "chain_state_sha256",
    "plan_state_sha256",
    "latest_failure_sha256",
    "resume_cursor_sha256",
    "pause_authority_sha256",
    "runtime_manifest_sha256",
    "marker_sha256",
    "runtime_provenance_receipt_sha256",
    "runtime_roots_sha256",
)
OCCURRENCE_FIELDS = (
    "contract_type",
    "schema_version",
    "chain_session",
    "plan_name",
    "phase",
    "failure_kind",
    "failure_code",
    "failure_recorded_at",
    "resume_phase",
    "retry_strategy",
)


def canonical_json(value: Any) -> str:
    """Return the deterministic canonical JSON text for *value*."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_str(text: str) -> str:
    return "sha256:" + _sha256_hex(text)


def _file_sha256_str(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _object_sha256_str(value: Any) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json(value).encode("utf-8")
    ).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hostname() -> str:
    try:
        import socket

        return socket.gethostname()
    except OSError:
        return ""


def _required(value: str, flag: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise CliError("invalid_args", f"{flag} is required")
    return normalized


def _sha256_fullmatch(value: str) -> bool:
    return (
        len(value) == 71
        and value.startswith("sha256:")
        and all(char in "0123456789abcdef" for char in value[7:])
    )


def owner_adoption_claim_id(repair_identity_key: str) -> str:
    """Return the deterministic claim id for an adopted occurrence."""
    key = str(repair_identity_key or "").strip()
    return f"{CLAIM_PREFIX}{key.removeprefix('sha256:')}"


def runtime_roots_payload(
    *,
    chain_execution_root: str,
    recorded_engine_root: str,
    manifest_runtime_root: str,
    marker_runtime_root: str,
    independent_import_root: str,
    candidate_root: str,
) -> dict[str, str]:
    """Return the canonical six-root payload (digest input for the CAS)."""
    return {
        "chain_execution_root": str(chain_execution_root or "").strip(),
        "recorded_engine_root": str(recorded_engine_root or "").strip(),
        "manifest_runtime_root": str(manifest_runtime_root or "").strip(),
        "marker_runtime_root": str(marker_runtime_root or "").strip(),
        "independent_import_root": str(independent_import_root or "").strip(),
        "candidate_root": str(candidate_root or "").strip(),
    }


def build_adoption_identity(
    *,
    session: str,
    plan_name: str,
    phase: str,
    failure_kind: str,
    failure_code: str,
    failure_recorded_at: str,
    resume_phase: str,
    retry_strategy: str,
    cas: Mapping[str, str],
    runtime_roots: Mapping[str, str],
    actor: str = OPERATOR_ACTOR,
) -> dict[str, Any]:
    """Build the deterministic owner-boundary adoption identity (pure).

    No I/O.  Returns the full envelope plus every deterministic authority id.
    The SAME inputs always produce the SAME envelope, key, record id and
    claim id; ANY byte change to the occurrence/cas/roots inputs produces a
    different key.  ``adopted_at``/``reason``/receipt path/PID/hostname are
    never inputs here — they stay outside the identity and its key.
    """
    occurrence_facts: dict[str, Any] = {
        "contract_type": OWNER_ADOPTED_OCCURRENCE_CONTRACT,
        "schema_version": 1,
        "chain_session": str(session or "").strip(),
        "plan_name": str(plan_name or "").strip(),
        "phase": str(phase or "").strip(),
        "failure_kind": str(failure_kind or "").strip(),
        "failure_code": str(failure_code or "").strip(),
        "failure_recorded_at": str(failure_recorded_at or "").strip(),
        "resume_phase": str(resume_phase or "").strip(),
        "retry_strategy": str(retry_strategy or "").strip(),
    }
    subject_occurrence_digest = _object_sha256_str(occurrence_facts)
    occurrence = {
        **occurrence_facts,
        "subject_occurrence_digest": subject_occurrence_digest,
    }
    cas_canonical = {
        field: str(cas.get(field) or "").strip() for field in CAS_FIELDS
    }
    roots_canonical = {
        field: str(runtime_roots.get(field) or "").strip()
        for field in RUNTIME_ROOT_FIELDS
    }
    authority_static = {
        "kind": AUTHORITY_KIND,
        "owner": AUTHORITY_OWNER,
        "actor": str(actor or "").strip(),
        "scope": list(AUTHORITY_SCOPE),
        "historical_authority_status": "absent",
    }
    adoption_basis = canonical_json(
        {
            "occurrence": occurrence,
            "cas": cas_canonical,
            "runtime_roots": roots_canonical,
            "authority": authority_static,
        }
    )
    basis_hex = _sha256_hex(adoption_basis)
    adoption_record_id = "sha256:" + basis_hex
    adoption_run_id = f"{ADOPTION_RUN_PREFIX}{basis_hex}"
    adoption_run_revision = "sha256:" + basis_hex
    adoption_attempt_id = f"{ADOPTION_ATTEMPT_PREFIX}{basis_hex}"
    grant_basis = {
        **authority_static,
        "adoption_record_id": adoption_record_id,
        "adoption_run_id": adoption_run_id,
        "adoption_run_revision": adoption_run_revision,
        "adoption_attempt_id": adoption_attempt_id,
        "adoption_fence_token": ADOPTION_FENCE_TOKEN,
    }
    # adoption_grant_id is the digest of the persisted adoption-grant basis
    # (the grant fields excluding the self-referential id field itself).
    adoption_grant_id = _object_sha256_str(grant_basis)
    grant_payload = {**grant_basis, "adoption_grant_id": adoption_grant_id}
    authority_pre = {**grant_payload, "wbc_attempt_reference": adoption_attempt_id}
    envelope_pre = {
        "schema_version": IDENTITY_SCHEMA_VERSION,
        "identity_kind": IDENTITY_KIND,
        "occurrence": occurrence,
        "cas": cas_canonical,
        "runtime_roots": roots_canonical,
        "authority": authority_pre,
    }
    # adoption_run_incarnation_id is the digest of the PERSISTED adoption
    # record's deterministic core: the record minus the mutable runtime
    # labels (adopted_at/reason/receipt path/PID/hostname) and minus the
    # self-referential incarnation field itself.  Deterministic across
    # identical reruns (the retry reuses the persisted record byte-for-byte).
    incarnation_basis = canonical_json(
        {
            "schema": SCHEMA,
            "adoption_record_id": adoption_record_id,
            "identity": envelope_pre,
        }
    )
    adoption_run_incarnation_id = "sha256:" + _sha256_hex(incarnation_basis)
    authority = {
        **authority_pre,
        "adoption_run_incarnation_id": adoption_run_incarnation_id,
    }
    envelope = {
        "schema_version": IDENTITY_SCHEMA_VERSION,
        "identity_kind": IDENTITY_KIND,
        "occurrence": occurrence,
        "cas": cas_canonical,
        "runtime_roots": roots_canonical,
        "authority": authority,
    }
    repair_identity_key = _object_sha256_str(envelope)
    return {
        "identity": envelope,
        "adoption_basis": adoption_basis,
        "adoption_record_id": adoption_record_id,
        "adoption_run_id": adoption_run_id,
        "adoption_run_revision": adoption_run_revision,
        "adoption_run_incarnation_id": adoption_run_incarnation_id,
        "adoption_attempt_id": adoption_attempt_id,
        "adoption_grant_id": adoption_grant_id,
        "adoption_fence_token": ADOPTION_FENCE_TOKEN,
        "repair_identity_key": repair_identity_key,
        "claim_id": owner_adoption_claim_id(repair_identity_key),
    }


def adoption_record_path(plan_dir: Path, adoption_record_id: str) -> Path:
    """Return the immutable adoption record path for an adoption id."""
    return (
        Path(plan_dir) / EVIDENCE_DIRNAME / ADOPTIONS_DIRNAME
    ) / f"{adoption_record_id}.json"


def _write_adoption_record_durably(
    path: Path, record: Mapping[str, Any]
) -> None:
    """Atomically create *path* under an exclusive flock with durable fsync.

    The sibling ``<name>.lock`` file is created and kept (the flock is per
    inode, so unlinking it while another waiter blocks on the same inode
    would split the fence — the same convention as the repair-queue locks).
    The payload is written to an unpredictable sibling temp name opened with
    ``O_CREAT|O_EXCL|O_NOFOLLOW``, fsync-ed before ``os.replace``, and the
    parent directory is fsync-ed after the rename.
    """
    import fcntl

    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+", encoding="utf-8") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        try:
            if path.exists():
                return
            tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
            fd = os.open(
                tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, indent=2) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, path)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
            dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def _load_adoption_record(
    plan_dir: Path, adoption_record_id: str
) -> dict[str, Any] | None:
    path = adoption_record_path(plan_dir, adoption_record_id)
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, Mapping):
        return None
    return dict(payload)


@contextmanager
def _adoption_transaction_lock(state_path: Path) -> Iterator[None]:
    """Exclusive advisory lock serializing adopt transactions on one chain."""
    import fcntl

    lock_path = state_path.with_suffix(".occurrence-adopt.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _independent_import_root() -> str:
    """Observe the import root of the control runtime independently.

    Runs the source-bound runtime interpreter with ``-P`` (isolated: no
    PYTHONPATH, no cwd) so the answer comes from the INSTALLED package
    location, never from the working directory.  ``ARNOLD_RUNTIME_PYTHON``
    is the launch runtime's existing explicit interpreter selector; when it
    is absent, retain the local control interpreter fallback.
    """
    configured = os.environ.get("ARNOLD_RUNTIME_PYTHON", "").strip()
    executable = Path(configured).expanduser() if configured else Path(sys.executable)
    if (
        not executable.is_absolute()
        or not executable.is_file()
        or not os.access(executable, os.X_OK)
    ):
        raise CliError(
            "independent_import_root_unavailable",
            "configured independent runtime interpreter is unavailable: "
            f"{configured or sys.executable}",
        )
    code = (
        "import pathlib, arnold_pipelines; "
        "print(pathlib.Path(arnold_pipelines.__file__).resolve().parents[1])"
    )
    proc = subprocess.run(
        [str(executable.resolve()), "-P", "-c", code],
        check=False,
        capture_output=True,
        text=True,
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
    )
    if proc.returncode != 0:
        raise CliError(
            "independent_import_root_unavailable",
            "cannot independently observe the control runtime import root: "
            f"{proc.stderr.strip() or proc.stdout.strip() or 'unknown error'}",
        )
    observed = proc.stdout.strip()
    if not observed:
        raise CliError(
            "independent_import_root_unavailable",
            "independent import-root observation produced no output",
        )
    return observed


def _expect_object_sha(value: Any, expected: str, label: str) -> None:
    expected = str(expected or "").strip()
    observed = _object_sha256_str(value)
    if not expected or observed != expected:
        raise CliError(
            "cas_mismatch",
            f"occurrence-adopt refused: {label} CAS mismatch",
            extra={"label": label, "expected": expected, "observed": observed},
        )


def _expect_file_sha(path: Path, expected: str, label: str) -> None:
    expected = str(expected or "").strip()
    observed = _file_sha256_str(path)
    if not expected or observed != expected:
        raise CliError(
            "cas_mismatch",
            f"occurrence-adopt refused: {label} CAS mismatch",
            extra={"label": label, "expected": expected, "observed": observed},
        )


def _any_identity_key_in(value: Any) -> bool:
    """Return True when a mapping carries any persisted repair identity key."""
    if not isinstance(value, Mapping):
        return False
    for key in ("repair_identity", "repair_identity_key", "occurrence_identity"):
        if str(value.get(key) or "").strip():
            return True
    for nested in ("meta", "current_refs", "current_target"):
        child = value.get(nested)
        if isinstance(child, Mapping) and _any_identity_key_in(child):
            return True
    latest_failure = value.get("latest_failure")
    if isinstance(latest_failure, Mapping):
        failure_meta = latest_failure.get("metadata")
        if isinstance(failure_meta, Mapping) and _any_identity_key_in(failure_meta):
            return True
    return False


def _assert_identity_locations_empty(
    plan_state: Mapping[str, Any], chain_state: Any
) -> None:
    """Fail closed when any authoritative repair-identity location is filled.

    The occurrence being adopted is identity-less BY CONSTRUCTION: plan
    state, plan meta, chain metadata, latest-failure metadata and the
    current-target projection must all be empty of persisted repair
    identity.  ``derive_repair_identity`` (which reads exactly those
    locations) must also find nothing.
    """
    locations: list[tuple[str, Any]] = [
        ("plan state", plan_state),
        ("chain metadata", getattr(chain_state, "metadata", {})),
        (
            "latest failure metadata",
            (
                plan_state.get("latest_failure", {}).get("metadata")
                if isinstance(plan_state.get("latest_failure"), Mapping)
                else None
            ),
        ),
    ]
    for where, payload in locations:
        if _any_identity_key_in(payload):
            raise CliError(
                "repair_identity_already_present",
                "occurrence-adopt refused: "
                f"{where} already carries a persisted repair identity; only "
                "the singular identity-less blocked occurrence may be adopted",
            )
    derived = repair_requests.derive_repair_identity(
        plan_state=plan_state,
        current_target=plan_state.get("current_target"),
    )
    if derived is not None:
        raise CliError(
            "repair_identity_already_present",
            "occurrence-adopt refused: a normalized repair identity is "
            "already derivable from plan state; only the identity-less "
            "blocked occurrence may be adopted",
        )


def adopt_occurrence(
    *,
    spec_path: Path,
    project_dir: Path,
    session: str,
    expected_current_plan: str,
    expected_phase: str,
    expected_failure_kind: str,
    expected_failure_code: str,
    expected_failure_recorded_at: str,
    expected_resume_phase: str,
    expected_retry_strategy: str,
    expected_chain_state_sha256: str,
    expected_plan_state_sha256: str,
    expected_latest_failure_sha256: str,
    expected_resume_cursor_sha256: str,
    expected_pause_authority_sha256: str,
    runtime_manifest_path: str | Path,
    expected_runtime_manifest_sha256: str,
    marker_path: str | Path,
    expected_marker_sha256: str,
    runtime_identity_path: str | Path,
    runtime_provenance_receipt_path: str | Path,
    candidate_root: str,
    expected_runtime_roots_sha256: str,
    actor: str,
    reason: str,
    receipt_path: str | Path,
) -> dict[str, Any]:
    """Adopt the singular identity-less blocked occurrence (T-0101e').

    Raises :class:`~arnold_pipelines.megaplan.types.CliError` on any guard
    violation.  Every guard is read-only and runs before ANY write; on
    success the only writes are the immutable adoption record, the immutable
    repair-queue request + ONE accepted decision, and the durable receipt.
    """
    actor_n = _required(actor, "--actor")
    if actor_n != OPERATOR_ACTOR:
        raise CliError(
            "actor_forbidden",
            "occurrence-adopt is operator-only: --actor must be 'operator'",
        )
    session_n = _required(session, "--session")
    reason_n = _required(reason, "--reason")
    for flag, value in (
        ("--expected-current-plan", expected_current_plan),
        ("--expected-phase", expected_phase),
        ("--expected-failure-kind", expected_failure_kind),
        ("--expected-failure-code", expected_failure_code),
        ("--expected-failure-recorded-at", expected_failure_recorded_at),
        ("--expected-resume-phase", expected_resume_phase),
        ("--expected-retry-strategy", expected_retry_strategy),
        ("--expected-chain-state-sha256", expected_chain_state_sha256),
        ("--expected-plan-state-sha256", expected_plan_state_sha256),
        ("--expected-latest-failure-sha256", expected_latest_failure_sha256),
        ("--expected-resume-cursor-sha256", expected_resume_cursor_sha256),
        ("--expected-pause-authority-sha256", expected_pause_authority_sha256),
        ("--expected-runtime-manifest-sha256", expected_runtime_manifest_sha256),
        ("--expected-marker-sha256", expected_marker_sha256),
        ("--expected-runtime-roots-sha256", expected_runtime_roots_sha256),
    ):
        _required(value, flag)

    spec_path = Path(spec_path).expanduser().resolve()
    project_dir = Path(project_dir).expanduser().resolve()

    # ── Chain + plan state (observe-only; never rewritten) ────────────────
    chain_state = chain_spec.load_chain_state(
        spec_path, verify_execution_binding=False
    )
    plan_name = str(chain_state.current_plan_name or "").strip()
    if plan_name != expected_current_plan:
        raise CliError(
            "plan_mismatch",
            f"current chain plan {plan_name!r} does not match the expected "
            f"plan {expected_current_plan!r}",
        )
    try:
        plan_dir = resolve_plan_dir(project_dir, plan_name)
    except CliError:
        plan_dir = project_dir / ".megaplan" / "plans" / plan_name
        if not plan_dir.exists():
            raise CliError(
                "plan_dir_unavailable",
                f"plan directory for {plan_name!r} is unavailable under {project_dir}",
            )
    state_path = plan_dir / "state.json"
    if not state_path.exists():
        raise CliError(
            "plan_state_unavailable",
            f"plan state.json is unavailable for {plan_name!r} at {state_path}",
        )
    try:
        plan_state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CliError(
            "plan_state_unreadable",
            f"plan state.json for {plan_name!r} is unreadable: {exc}",
        ) from exc
    if not isinstance(plan_state, Mapping):
        raise CliError(
            "plan_state_unreadable",
            f"plan state.json for {plan_name!r} is not an object",
        )

    chain_state_file = chain_spec._state_path_for(spec_path)
    if not chain_state_file.is_file():
        raise CliError(
            "chain_state_unavailable",
            f"chain state file is unavailable for {spec_path} at {chain_state_file}",
        )
    _expect_file_sha(chain_state_file, expected_chain_state_sha256, "chain state")
    _expect_file_sha(state_path, expected_plan_state_sha256, "plan state")

    # ── Singular identity-less blocked occurrence ─────────────────────────
    latest_failure = plan_state.get("latest_failure")
    if not isinstance(latest_failure, Mapping):
        raise CliError(
            "ambiguous_failure",
            "occurrence-adopt requires a SINGULAR plan-state latest_failure "
            "mapping (the identity-less blocked occurrence); got "
            f"{type(latest_failure).__name__ if latest_failure is not None else 'none'}",
        )
    if str(latest_failure.get("kind") or "").strip() != expected_failure_kind:
        raise CliError(
            "failure_kind_mismatch",
            f"latest failure kind {latest_failure.get('kind')!r} does not match "
            f"the expected kind {expected_failure_kind!r}",
        )
    if str(latest_failure.get("phase") or "").strip() != expected_phase:
        raise CliError(
            "phase_mismatch",
            f"latest failure phase {latest_failure.get('phase')!r} does not "
            f"match the expected phase {expected_phase!r}",
        )
    if (
        str(latest_failure.get("recorded_at") or "").strip()
        != expected_failure_recorded_at
    ):
        raise CliError(
            "failure_recorded_at_mismatch",
            f"latest failure recorded_at {latest_failure.get('recorded_at')!r} "
            f"does not match the expected {expected_failure_recorded_at!r}",
        )
    failure_metadata = (
        latest_failure.get("metadata")
        if isinstance(latest_failure.get("metadata"), Mapping)
        else {}
    )
    failure_message = str(latest_failure.get("message") or "")
    if expected_failure_code not in failure_metadata and (
        expected_failure_code not in failure_message
    ):
        raise CliError(
            "failure_code_mismatch",
            f"latest failure does not carry failure code {expected_failure_code!r}",
        )
    _expect_object_sha(latest_failure, expected_latest_failure_sha256, "latest failure")

    resume_cursor = plan_state.get("resume_cursor")
    if not isinstance(resume_cursor, Mapping):
        raise CliError(
            "resume_cursor_missing",
            "plan state carries no resume_cursor mapping",
        )
    if str(resume_cursor.get("phase") or "").strip() != expected_resume_phase:
        raise CliError(
            "resume_phase_mismatch",
            f"resume cursor phase {resume_cursor.get('phase')!r} does not match "
            f"the expected {expected_resume_phase!r}",
        )
    if (
        str(resume_cursor.get("retry_strategy") or "").strip()
        != expected_retry_strategy
    ):
        raise CliError(
            "retry_strategy_mismatch",
            f"resume cursor retry_strategy {resume_cursor.get('retry_strategy')!r} "
            f"does not match the expected {expected_retry_strategy!r}",
        )
    _expect_object_sha(resume_cursor, expected_resume_cursor_sha256, "resume cursor")

    # ── Durable pause (the T-0101 flow pauses first) ──────────────────────
    pause = pause_record(chain_state)
    if pause is None:
        raise CliError(
            "chain_not_paused",
            "occurrence-adopt requires a durably paused chain (the T-0101 "
            "flow pauses first); no operator_pause authority is recorded",
        )
    if str(plan_state.get("current_state") or "").strip() != _PAUSED_PLAN_STATE:
        raise CliError(
            "chain_not_paused",
            "occurrence-adopt requires the current plan to be durably paused; "
            f"observed plan current_state={plan_state.get('current_state')!r}",
        )
    _expect_object_sha(pause, expected_pause_authority_sha256, "pause authority")

    # ── Runtime manifest + marker (exact bytes) ───────────────────────────
    manifest_path = Path(runtime_manifest_path).expanduser().resolve()
    if not manifest_path.is_file():
        raise CliError(
            "runtime_manifest_unavailable",
            f"runtime manifest is unavailable at {manifest_path}",
        )
    _expect_file_sha(manifest_path, expected_runtime_manifest_sha256, "runtime manifest")
    try:
        manifest = load_manifest(manifest_path)
    except Exception as exc:  # noqa: BLE001 - ManifestError is not a CliError
        raise CliError(
            "runtime_manifest_unreadable",
            f"runtime manifest at {manifest_path} is unreadable: {exc}",
        ) from exc
    manifest_runtime_root = str(manifest.epic.get("runtime_root") or "").strip()

    marker_file = Path(marker_path).expanduser().resolve()
    if not marker_file.is_file():
        raise CliError("marker_unavailable", f"marker is unavailable at {marker_file}")
    _expect_file_sha(marker_file, expected_marker_sha256, "marker")
    try:
        marker = json.loads(marker_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CliError("marker_unreadable", f"marker at {marker_file} is unreadable: {exc}") from exc
    marker_identity = marker_runtime_identity(marker)
    if marker_identity is None:
        raise CliError(
            "marker_unbound",
            "marker carries no runtime_binding current_identity; the marker "
            "must be strong-bound before the occurrence can be adopted",
        )
    marker_runtime_root = str(marker_identity.get("import_root") or "").strip()

    # ── Runtime identity + provenance receipt (independently verified) ────
    identity_file = Path(runtime_identity_path).expanduser().resolve()
    receipt_file = Path(runtime_provenance_receipt_path).expanduser().resolve()
    if not identity_file.is_file() or not receipt_file.is_file():
        raise CliError(
            "runtime_identity_unavailable",
            "runtime identity and provenance receipt must both exist",
        )
    verified_identity = verify_external_runtime_identity(identity_file, receipt_file)
    verified_import_root = str(
        verified_identity.get("import_root") or ""
    ).strip()
    runtime_provenance_receipt_sha256 = _file_sha256_str(receipt_file)

    # ── Six-way runtime root equality ─────────────────────────────────────
    binding = chain_state.metadata.get("execution_binding")
    binding = binding if isinstance(binding, Mapping) else {}
    runtime_binding = binding.get("runtime_binding")
    runtime_binding = runtime_binding if isinstance(runtime_binding, Mapping) else {}
    bound_identity = runtime_binding.get("current_identity")
    bound_identity = bound_identity if isinstance(bound_identity, Mapping) else {}
    chain_execution_root = str(bound_identity.get("import_root") or "").strip()
    if not chain_execution_root:
        raise CliError(
            "chain_runtime_unbound",
            "chain execution binding carries no current runtime identity "
            "import_root; the chain must be runtime-bound before adoption",
        )
    execution_environment = chain_state.metadata.get("execution_environment")
    execution_environment = (
        execution_environment if isinstance(execution_environment, Mapping) else {}
    )
    recorded_engine_root = str(
        execution_environment.get("engine_root") or ""
    ).strip()
    if not recorded_engine_root:
        raise CliError(
            "engine_root_missing",
            "chain metadata.execution_environment.engine_root is empty",
        )
    candidate_root_n = _required(candidate_root, "--candidate-root")
    roots = runtime_roots_payload(
        chain_execution_root=chain_execution_root,
        recorded_engine_root=recorded_engine_root,
        manifest_runtime_root=manifest_runtime_root,
        marker_runtime_root=marker_runtime_root,
        independent_import_root=_independent_import_root(),
        candidate_root=candidate_root_n,
    )
    missing_roots = [name for name, value in roots.items() if not value]
    if missing_roots:
        raise CliError(
            "runtime_roots_incomplete",
            "runtime roots are incomplete: " + ", ".join(missing_roots),
        )
    resolved_roots = [Path(value).expanduser().resolve() for value in roots.values()]
    if len(set(resolved_roots)) != 1:
        raise CliError(
            "runtime_roots_unequal",
            "runtime roots are not all equal: "
            + ", ".join(f"{name}={value}" for name, value in roots.items()),
        )
    if verified_import_root:
        if Path(verified_import_root).expanduser().resolve() != resolved_roots[0]:
            raise CliError(
                "runtime_roots_unequal",
                "independently verified runtime identity import_root "
                f"{verified_import_root!r} disagrees with the recorded runtime "
                f"roots {resolved_roots[0]!r}",
            )
    _expect_object_sha(roots, expected_runtime_roots_sha256, "runtime roots")

    # ── Chain spec guard: the state's recorded spec hash is current ───────
    recorded_spec_sha = str(chain_state.metadata.get("chain_spec_sha256") or "").strip()
    if not recorded_spec_sha:
        raise CliError(
            "chain_spec_sha_missing",
            "chain state records no chain_spec_sha256 guard",
        )
    recorded_spec_hex = recorded_spec_sha.removeprefix("sha256:")
    if recorded_spec_hex != hashlib.sha256(spec_path.read_bytes()).hexdigest():
        raise CliError(
            "chain_spec_mismatch",
            "chain state's recorded chain_spec_sha256 disagrees with the "
            "actual spec file bytes",
        )
    recorded_spec_sha = "sha256:" + recorded_spec_hex

    # ── Identity locations must be EMPTY (the occurrence is identity-less) ─
    _assert_identity_locations_empty(plan_state, chain_state)

    # ── Deterministic adoption authority ──────────────────────────────────
    cas = {
        "chain_spec_sha256": recorded_spec_sha,
        "chain_state_sha256": _file_sha256_str(chain_state_file),
        "plan_state_sha256": _file_sha256_str(state_path),
        "latest_failure_sha256": _object_sha256_str(latest_failure),
        "resume_cursor_sha256": _object_sha256_str(resume_cursor),
        "pause_authority_sha256": _object_sha256_str(pause),
        "runtime_manifest_sha256": _file_sha256_str(manifest_path),
        "marker_sha256": _file_sha256_str(marker_file),
        "runtime_provenance_receipt_sha256": runtime_provenance_receipt_sha256,
        "runtime_roots_sha256": _object_sha256_str(roots),
    }
    built = build_adoption_identity(
        session=session_n,
        plan_name=plan_name,
        phase=expected_phase,
        failure_kind=expected_failure_kind,
        failure_code=expected_failure_code,
        failure_recorded_at=expected_failure_recorded_at,
        resume_phase=expected_resume_phase,
        retry_strategy=expected_retry_strategy,
        cas=cas,
        runtime_roots=roots,
        actor=actor_n,
    )
    identity = built["identity"]
    adoption_record_id = built["adoption_record_id"]
    repair_identity_key = built["repair_identity_key"]
    claim_id = built["claim_id"]
    record_path = adoption_record_path(plan_dir, adoption_record_id)

    # ── Receipt destination guard (read-only; fail closed before ANY write) ─
    # T-0640 D1: the queue root resolves from ARNOLD_REPAIR_QUEUE_ROOT else
    # the marker-adjacent box-central queue (never project_dir — a per-epic
    # checkout queue is invisible to the box-central G14/watchdog paths).
    queue_root = repair_requests.resolve_aligned_repair_queue_root()
    receipt_final = _validate_receipt_destination(
        Path(receipt_path).expanduser() if receipt_path else None,
        plan_dir=plan_dir,
        protected_paths=[
            state_path,
            spec_path,
            repair_requests.requests_dir(queue_root),
            repair_requests.decisions_dir(queue_root),
        ],
    )

    # ── Chain transaction lock + occurrence-adoption lock; re-verify the
    #    mutable CAS inputs under the lock, then persist once ──────────────
    with _adoption_transaction_lock(chain_state_file):
        # The read-only guard pass above ran BEFORE the lock; the mutable
        # occurrence inputs (chain/plan state bytes, pause authority, failure
        # and cursor) are re-read and re-verified under the lock so a
        # concurrent mutation between guard and persist cannot slip through.
        _expect_file_sha(chain_state_file, expected_chain_state_sha256, "chain state")
        _expect_file_sha(state_path, expected_plan_state_sha256, "plan state")
        if not state_path.is_file():
            raise CliError("plan_state_unavailable", "plan state.json vanished")
        try:
            locked_plan_state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CliError("plan_state_unreadable", str(exc)) from exc
        if not isinstance(locked_plan_state, Mapping):
            raise CliError("plan_state_unreadable", "plan state is not an object")
        locked_latest_failure = locked_plan_state.get("latest_failure")
        if not isinstance(locked_latest_failure, Mapping):
            raise CliError(
                "ambiguous_failure",
                "plan latest_failure changed to a non-singular value under the lock",
            )
        locked_cursor = locked_plan_state.get("resume_cursor")
        if not isinstance(locked_cursor, Mapping):
            raise CliError("resume_cursor_missing", "resume cursor vanished under the lock")
        _expect_object_sha(
            locked_latest_failure, expected_latest_failure_sha256, "latest failure"
        )
        _expect_object_sha(locked_cursor, expected_resume_cursor_sha256, "resume cursor")
        if str(locked_plan_state.get("current_state") or "").strip() != _PAUSED_PLAN_STATE:
            raise CliError(
                "chain_not_paused",
                "plan pause changed under the lock",
            )
        locked_chain_state = chain_spec.load_chain_state(
            spec_path, verify_execution_binding=False
        )
        locked_pause = pause_record(locked_chain_state)
        if locked_pause is None:
            raise CliError("chain_not_paused", "chain pause authority vanished under the lock")
        _expect_object_sha(locked_pause, expected_pause_authority_sha256, "pause authority")

        # ── Persist the deterministic adoption authority/WBC record ───────
        record = {
            "schema": SCHEMA,
            "adoption_record_id": adoption_record_id,
            "identity": identity,
            "repair_identity_key": repair_identity_key,
            "claim_id": claim_id,
            "mutable": {
                "adopted_at": _utc_now(),
                "reason": reason_n,
                "receipt_path": str(receipt_final) if receipt_final is not None else "",
                "pid": os.getpid(),
                "hostname": _hostname(),
            },
        }
        existing_record = _load_adoption_record(plan_dir, adoption_record_id)
        if existing_record is not None:
            if (
                existing_record.get("adoption_record_id") != adoption_record_id
                or existing_record.get("identity") != identity
                or existing_record.get("repair_identity_key") != repair_identity_key
                or existing_record.get("claim_id") != claim_id
            ):
                raise CliError(
                    "adoption_record_mismatch",
                    f"persisted adoption record {adoption_record_id} disagrees "
                    "with the freshly verified adoption authority; refusing "
                    "instead of overwriting",
                )
            record = existing_record
        else:
            _write_adoption_record_durably(record_path, record)

        # ── Enqueue ONE deterministic request + ONE accepted decision ─────
        enqueued = repair_requests.enqueue_owner_adopted_repair_request(
            queue_root=queue_root,
            session=session_n,
            source=REPAIR_SOURCE,
            workspace=project_dir,
            run_kind="chain",
            marker_dir=plan_dir,
            target={
                "plan_dir": str(plan_dir),
                "plan_name": plan_name,
                "retry_strategy": expected_retry_strategy,
                "adoption_record_id": adoption_record_id,
            },
            problem_signature={
                "failure_kind": expected_failure_kind,
                "current_state": "blocked",
                "phase_or_step": expected_phase,
                "milestone_or_plan": plan_name,
                "gate_recommendation": "repair gate contract",
                "blocked_task_id": f"phase:{expected_phase}",
            },
            root_cause_hint=(
                f"owner adoption of identity-less blocked occurrence: "
                f"{expected_failure_code} at phase:{expected_phase}"
            ),
            repair_identity=identity,
        )
        request_record = enqueued.get("request")
        decision_record = enqueued.get("decision")
        if not isinstance(request_record, Mapping) or not isinstance(
            decision_record, Mapping
        ):
            raise CliError(
                "adoption_enqueue_failed",
                "owner-adoption enqueue did not return a request+decision pair",
            )
        request_id = str(request_record.get("request_id") or "").strip()
        decision_id = str(decision_record.get("decision_id") or "").strip()
        if not request_id or not decision_id:
            raise CliError(
                "adoption_enqueue_failed",
                "owner-adoption enqueue returned empty request/decision ids",
            )

    # ── Durable receipt (outside the identity, so outside the key) ────────
    receipt = {
        "schema": SCHEMA,
        "status": "adopted",
        "recorded_at": _utc_now(),
        "spec": str(spec_path),
        "project_dir": str(project_dir),
        "plan": plan_name,
        "plan_dir": str(plan_dir),
        "session": session_n,
        "actor": actor_n,
        "reason": reason_n,
        "adoption_record_id": adoption_record_id,
        "adoption_record_path": str(record_path),
        "repair_identity_key": repair_identity_key,
        "claim_id": claim_id,
        "request_id": request_id,
        "decision_id": decision_id,
        "identity": identity,
    }
    receipt_out = None
    if receipt_final is not None:
        _write_receipt_durably(receipt_final, receipt)
        receipt_out = str(receipt_final)

    return {
        "status": "adopted",
        "plan": plan_name,
        "plan_dir": str(plan_dir),
        "session": session_n,
        "identity_kind": IDENTITY_KIND,
        "adoption_record_id": adoption_record_id,
        "adoption_record_path": str(record_path),
        "repair_identity_key": repair_identity_key,
        "request_id": request_id,
        "decision_id": decision_id,
        "claim_id": claim_id,
        "receipt_path": receipt_out,
        "receipt": receipt,
    }


__all__ = [
    "ADOPTION_ATTEMPT_PREFIX",
    "ADOPTION_FENCE_TOKEN",
    "ADOPTION_NAMESPACE",
    "ADOPTION_RUN_PREFIX",
    "AUTHORITY_KIND",
    "AUTHORITY_OWNER",
    "AUTHORITY_SCOPE",
    "CAS_FIELDS",
    "CLAIM_PREFIX",
    "IDENTITY_KIND",
    "IDENTITY_SCHEMA_VERSION",
    "OCCURRENCE_FIELDS",
    "OPERATOR_ACTOR",
    "OWNER_ADOPTED_OCCURRENCE_CONTRACT",
    "REPAIR_SOURCE",
    "RUNTIME_ROOT_FIELDS",
    "SCHEMA",
    "adopt_occurrence",
    "adoption_record_path",
    "build_adoption_identity",
    "canonical_json",
    "owner_adoption_claim_id",
    "runtime_roots_payload",
]
