"""T-0101g: copied-state rehearsal of the full T-0101 canary transaction.

This test replays the ENTIRE T-0101 sequence on a tmp COPY of a mini chain
state (a progressed, blocked, UNBOUND chain + a durably pausable plan + a
repair-queue request/decision/occurrence tuple + a per-epic runtime manifest
+ a cloud-session marker) using the REAL commands/entry points:

  (a) pause        -> ``megaplan chain pause`` — the REAL CLI parser +
                      dispatch (durable pause authority)
  (b) migrate      -> ``megaplan chain execution-binding-migrate`` — the REAL
                      CLI parser + dispatch.  Runs on the paused OPTIONAL
                      legacy spec; the SAME identity-less r5 marker seeded
                      from the start is consumed unchanged under the
                      marker-SHA + relaunch-root guards; the OLD runtime is
                      independently reverified via its provenance receipt
  (c) marker       -> ``python -P -m arnold_pipelines.megaplan.cloud.
                      legacy_marker_runtime_migration`` — the REAL module CLI.
                      Binds the SAME unchanged identity-less r5 marker
                      (editable_source_head=None, editable_install_sync.
                      status=skipped, no source) to the verified legacy
                      runtime, writing the
                      STRONG ``runtime_binding`` form so the later marker
                      cutover (h) CAS-runs against the strong form.  The
                      migration's relaunch gate is hardcoded to the live-box
                      root layout (``/workspace/runtime-candidates/<slug>``,
                      regex in legacy_marker_runtime_migration.py), which
                      cannot be materialized on this macOS host; the rehearsal
                      follows the migration's own test suite in patching the
                      ``verify_external_runtime_identity`` seam (documented
                      at the call site) while driving everything else — the
                      CLI entry, every CAS guard, the marker write, and the
                      immutable evidence receipts — for real.
  (d) install      -> the FULL required-binding bundle committed by digest as
                      the T-0101h P/F two-commit construction: commit P is
                      the complete intended bundle (chain.yaml with the
                      required driver + all 7 final assets NORTHSTAR/briefs/
                      decision as they exist in the working tree), commit F
                      changes ONLY ``driver.intended_initiative_revision`` ->
                      P.  NO chain state is written here (the old test-only
                      ``save_chain_state`` bridge is gone); the verifier is
                      re-run from a CLEAN checkout of F and must be
                      ``ready=True``
  (e) rebind       -> ``megaplan chain rebind`` — the REAL CLI dispatch; the
                      ONLY operation that re-records the new spec hash
                      (persists via save_chain_state, re-records
                      metadata.chain_spec_sha256)
  (f) runtime      -> ``megaplan chain runtime-cutover`` — the REAL CLI
                      dispatch (runtime rebind + engine_root old->new in one
                      CAS transaction)
  (g) manifest     -> ``python -P -m arnold_pipelines.megaplan.cloud.
                      runtime_manifest cutover`` — the REAL CLI parser +
                      dispatch (CAS sha + generation, real .venv + wrapper
                      paths inside the receipted root)
  (h) marker       -> ``python -P -m arnold_pipelines.megaplan.cloud.
                      runtime_cutover`` — the REAL CLI parser + dispatch of
                      ``update_marker_runtime`` (marker runtime CAS cutover
                      against the STRONG post-migration binding)
  (i) occurrence   -> ``megaplan chain occurrence-join`` — the REAL CLI
                      dispatch (operator-only fenced claim)
  (j) resume       -> ``megaplan chain resume`` — the REAL CLI dispatch
                      (clears the pause authority, restores the exact prior
                      plan state)

Every write step is rehearsed with rollback injection:

  1. snapshot the whole copied project tree;
  2. run the step and verify every written file still CAS-verifies
     (state records the spec hash it guards, manifest/marker SHA-256 match the
     step's own receipts, cursors and pause authority survive, etc.);
  3. RESTORE the pre-step bytes (the rollback);
  4. re-run the step and verify it is idempotent/recoverable from the restored
     bytes;
  5. attempt the step with a wrong-CAS input (wrong sha / milestone / branch /
     occurrence) and assert it refuses with ZERO mutation.

AND the effect-boundary writes are rehearsed with REAL failure injection
(T-0101h finding 5 — the failure is injected AFTER internal writes, not by
restoring the tree):

  - migration evidence/marker write: ``tempfile.mkstemp`` inside
    ``legacy_marker_runtime_migration`` raises once — the marker is
    byte-unchanged, no stranded evidence exists, and the SAME module CLI
    re-run completes the migration;
  - manifest write: ``runtime_manifest._atomic_write`` raises once — the
    rollback receipt has already landed (written before the manifest write),
    the manifest file is byte-unchanged (no half-written manifest), and the
    SAME ``runtime_manifest cutover`` CLI command re-run completes the cutover;
  - marker write: the atomic marker write (``tempfile.mkstemp`` inside
    ``update_marker_runtime``, after every CAS guard passed) raises once — the
    marker is byte-unchanged and the re-run completes;
  - claim write: the WBC claim commit (``SqliteAttemptLedgerStore.
    append_started``) raises once AFTER the lease was acquired — the lease is
    rolled back (terminal release), no stranded claim remains, and the SAME
    ``chain occurrence-join`` CLI command re-run completes the join;
  - receipt write: the receipt emit (``os.replace``) raises once on a FIRST
    claim — the lease is rolled back (terminal release) while the WBC STARTED
    attempt is retained as the re-join anchor, no receipt file exists, and the
    SAME ``chain occurrence-join`` CLI command re-run regenerates the receipt
    (``already_claimed``).

Final state must be the T-0101 acceptance shape: chain bound to the NEW
runtime, engine_root == new root, manifest == new root, marker == new root,
claim held, resume cursor byte-equivalent, fresh progress possible, and the
six-way root equality (chain execution root == recorded engine_root ==
manifest runtime_root == marker runtime root == independently observed
import root == REPO_ROOT) with the manifest's venv/repair-bin paths real,
executable, and inside the root.

A quiesce precondition (watchdog/incident-ledger writers stopped before the
sequence) is asserted up front; the live quiesce itself is operator-side
(tasklist T-0101), so the rehearsal proves the precondition helper exists,
is callable, and that the copied tree carries no incident-ledger journal.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

from arnold.workflow.attempt_ledger_store import (
    AttemptEventType,
    AttemptLedgerError,
    SqliteAttemptLedgerStore,
)
from arnold_pipelines.megaplan.chain import spec as chain_spec
from arnold_pipelines.megaplan.chain.execution_binding import (
    active_execution_identity,
    binding_policy,
    execution_binding_report,
    verify_external_runtime_identity,
)
from arnold_pipelines.megaplan.chain.occurrence_join import (
    occurrence_adoption_claim_attempt_id,
    occurrence_adoption_join_lease_id,
    occurrence_claim_attempt_id,
    occurrence_join_lease_id,
)
from arnold_pipelines.megaplan.chain.operator_pause import (
    AUTHORITY_KEY,
    AUTHORITY_SCHEMA,
    _RUNNER_RESUMABLE_STATES,
    pause_record,
)
from arnold_pipelines.megaplan.chain.spec import (
    ChainState,
    load_chain_state,
    save_chain_state,
)
from arnold_pipelines.megaplan.cloud import (
    legacy_marker_runtime_migration as legacy_marker_module,
)
from arnold_pipelines.megaplan.cloud import repair_requests
from arnold_pipelines.megaplan.cloud import runtime_cutover as runtime_cutover_module
from arnold_pipelines.megaplan.cloud import runtime_manifest as runtime_manifest_module
from arnold_pipelines.megaplan.cloud.install_sync import (
    ensure_dependency_generation,
)
from arnold_pipelines.megaplan.cloud.runtime_cutover import (
    marker_runtime_identity,
    normalize_runtime_identity,
)
from arnold_pipelines.megaplan.cloud.runtime_manifest import (
    MANIFEST_SCHEMA_VERSION,
    RuntimeManifest,
    _verify_dependency_generation_binding,
    load_manifest,
    write_manifest,
)
from arnold_pipelines.megaplan.custody.lease_store import open_lease_store
from arnold_pipelines.megaplan.custody.phase_wbc import PHASE_WBC_LEDGER_FILENAME
from arnold_pipelines.megaplan.types import CliError

from tests.cloud.repair_identity_fixtures import repair_identity

REPO_ROOT = Path(__file__).resolve().parents[4]

SESSION = "canary-session"          # chain session + cloud-session marker name
REPAIR_SESSION = "canary-repair"    # repair-queue session (occurrence identity)
PLAN = "c1-plan"
BRANCH = "canary-work"
CLAIM_ID = "operator-claim-canary-0001"
# The mini initiative carries the same 7 final assets as the real
# megaplan-maintenance initiative: NORTHSTAR + five milestone briefs + the
# authority-ledger decision.
MILESTONES = ("c1", "c2", "c3", "c4", "c5")
ASSET_REL = (
    ".megaplan/initiatives/demo/decisions/authority-ledger-and-loop-boundaries.md"
)
#: The live-box legacy runtime root the marker migration's relaunch gate is
#: hardcoded to (``_RUNTIME_ROOT`` regex).  It cannot be materialized on this
#: macOS host (``/workspace`` requires root); the rehearsal mirrors the
#: migration's own fixture pattern instead (see the module docstring).
LEGACY_CANDIDATE = "/workspace/runtime-candidates/arnold-canary-legacy"


@pytest.fixture(autouse=True)
def _align_repair_queue_root(tmp_path: Path) -> Iterator[None]:
    """T-0640 D1: the real ``chain occurrence-join`` / ``occurrence-adopt``
    CLI paths resolve the queue root from ARNOLD_REPAIR_QUEUE_ROOT (else the
    marker-adjacent box-central queue — never project_dir).  Pin it to this
    test's tmp queue where the rehearsal enqueues.  Set directly on
    os.environ (restored in teardown) so monkeypatch.undo() cannot silently
    reset it."""
    prior = os.environ.get("ARNOLD_REPAIR_QUEUE_ROOT")
    os.environ["ARNOLD_REPAIR_QUEUE_ROOT"] = str(
        tmp_path / ".megaplan" / "repair-queue"
    )
    try:
        yield
    finally:
        if prior is None:
            os.environ.pop("ARNOLD_REPAIR_QUEUE_ROOT", None)
        else:
            os.environ["ARNOLD_REPAIR_QUEUE_ROOT"] = prior


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(value: dict) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _normalized(value: dict) -> dict:
    """Project an identity through the same content-addressed normalizer the
    marker-migration chain checks use."""
    return normalize_runtime_identity(value)


# ── offline runtime fixture (independent interpreter with a verifiable
#    runtime identity) — the LEGACY runtime the copied chain was launched under.
@pytest.fixture(scope="module")
def offline_rollback_runtime(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, Path | str]:
    root = tmp_path_factory.mktemp("offline-runtime-rollback")
    source_a = root / "runtime-a"
    venv_a = root / "venv-a"
    venv_b = root / "venv-b"
    venv_observer = root / "venv-observer"
    subprocess.run(
        ["git", "clone", "--shared", "--no-checkout", str(REPO_ROOT), str(source_a)],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "-C", str(source_a), "checkout", "--detach", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            sys.executable,
            "-m",
            "venv",
            "--copies",
            "--system-site-packages",
            str(venv_a),
        ],
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            "-m",
            "venv",
            "--copies",
            "--system-site-packages",
            str(venv_b),
        ],
        check=True,
    )
    python_a = venv_a / "bin" / "python3"
    python_b = venv_b / "bin" / "python3"
    for python, source in (
        (python_a, source_a),
        (python_b, REPO_ROOT),
    ):
        subprocess.run(
            [str(python), "-m", "pip", "install", "--no-deps", "-e", str(source)],
            check=True,
            capture_output=True,
            text=True,
        )
    # A byte-for-byte copy of the candidate-bound control environment gives
    # the independent observer a distinct executable path without creating a
    # third venv (which is not reliable on all supported Python builds).
    shutil.copytree(venv_b, venv_observer, symlinks=True)
    python_observer = venv_observer / "bin" / "python3"
    revision_a = _git(source_a, "rev-parse", "HEAD")
    receipt = root / "runtime-a-receipt.json"
    identity = root / "runtime-a-identity.json"
    provenance_program = (
        REPO_ROOT / "arnold_pipelines" / "megaplan" / "cloud" / "runtime_provenance.py"
    )
    result = subprocess.run(
        [
            str(python_a),
            "-P",
            str(provenance_program),
            "--expected-root",
            str(source_a),
            "--expected-revision",
            revision_a,
            "--receipt-out",
            str(receipt),
            "--identity-out",
            str(identity),
            "--emit-receipt",
        ],
        check=False,
        capture_output=True,
        text=True,
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
    )
    assert result.returncode == 0, result.stderr
    return {
        "root": root,
        "source_a": source_a,
        "python_a": python_a,
        "python_b": python_b,
        "python_observer": python_observer,
        "revision_a": revision_a,
        "receipt": receipt,
        "identity": identity,
    }


# ── copied-state fixture builders -------------------------------------------

def _pin_legacy_chain(tmp_path: Path) -> Path:
    """A mini git initiative whose chain spec is the OLD OPTIONAL policy.

    ``driver.execution_binding`` is ``optional`` (the box's pre-T-0101f state),
    no runtime-match enforcement, no binding assets, revision pinned to the
    committed initiative HEAD (a SECOND commit — the tree is CLEAN so the
    later P/F bundle commits are the only spec changes in history).
    """
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "tests@example.com")
    _git(tmp_path, "config", "user.name", "Tests")
    initiative = tmp_path / ".megaplan" / "initiatives" / "demo"
    briefs = initiative / "briefs"
    briefs.mkdir(parents=True, exist_ok=True)
    (initiative / "NORTHSTAR.md").write_text(
        "# Durable destination\n", encoding="utf-8"
    )
    milestones = []
    for label in MILESTONES:
        brief = briefs / f"{label}.md"
        brief.write_text(f"# {label}\n", encoding="utf-8")
        milestones.append(
            {
                "label": label,
                "idea": f".megaplan/initiatives/demo/briefs/{label}.md",
            }
        )
    payload = {
        "anchors": {"north_star": "NORTHSTAR.md"},
        "milestones": milestones,
        "driver": {
            "execution_binding": "optional",
            "initiative_path": ".megaplan/initiatives/demo",
            "intended_initiative_revision": "UNSET_REQUIRED_BEFORE_LAUNCH",
            "require_editable_runtime_match": False,
        },
    }
    spec_path = initiative / "chain.yaml"
    spec_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "legacy initiative revision")
    raw = yaml.safe_load(spec_path.read_text(encoding="utf-8"))
    raw["driver"]["intended_initiative_revision"] = _git(
        tmp_path, "rev-parse", "HEAD"
    )
    spec_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    _git(tmp_path, "add", ".megaplan/initiatives/demo/chain.yaml")
    _git(tmp_path, "commit", "-m", "legacy initiative revision pin")
    return spec_path


def _write_final_decision_asset(tmp_path: Path) -> Path:
    """The seventh final bundle asset (decision), with its final content, as
    it exists in the working tree at install time (committed inside P)."""
    decision = (
        tmp_path / ".megaplan" / "initiatives" / "demo" / "decisions"
    ) / "authority-ledger-and-loop-boundaries.md"
    decision.parent.mkdir(parents=True, exist_ok=True)
    decision.write_text(
        "# Authority ledger and loop boundaries\n\n"
        "The authority ledger is append-only; every loop boundary is fenced "
        "and operator-authorizable.  This is the T-0101f final decision "
        "asset, committed by digest in the required-binding bundle.\n",
        encoding="utf-8",
    )
    return decision


def _commit_binding_bundle(
    spec_path: Path,
    tmp_path: Path,
    *,
    assets: list[str],
) -> tuple[str, str]:
    """Commit the FULL required-binding bundle as commit P, then a pin-only
    commit F (the T-0101h finding-4 two-commit construction).

    P is the complete intended bundle: chain.yaml with the required driver
    (``execution_binding: required``, ``require_editable_runtime_match: true``,
    ``execution_binding_assets``) plus every final initiative asset as it
    exists in the working tree.  P's own pin may be any valid commit — it is
    masked in the verifier's comparable hash (a commit cannot contain its own
    SHA).  F changes ONLY ``driver.intended_initiative_revision`` -> P.

    NO chain state is written here (the T-0101h round-1 test-only
    ``save_chain_state`` bridge is deleted): the state-hash re-record happens
    exclusively through the real ``chain rebind`` CLI afterwards, which
    persists via ``save_chain_state`` and re-records
    ``metadata.chain_spec_sha256``.
    """
    legacy_head = _git(tmp_path, "rev-parse", "HEAD")
    raw = yaml.safe_load(spec_path.read_text(encoding="utf-8"))
    driver = raw.setdefault("driver", {})
    driver["execution_binding"] = "required"
    driver["require_editable_runtime_match"] = True
    driver["execution_binding_assets"] = [item.strip() for item in assets]
    driver["intended_initiative_revision"] = legacy_head
    spec_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    _git(tmp_path, "add", ".megaplan/initiatives/demo")
    _git(tmp_path, "commit", "-m", "install required-binding bundle snapshot (P)")
    snapshot = _git(tmp_path, "rev-parse", "HEAD")
    raw = yaml.safe_load(spec_path.read_text(encoding="utf-8"))
    raw["driver"]["intended_initiative_revision"] = snapshot
    spec_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    _git(tmp_path, "add", ".megaplan/initiatives/demo/chain.yaml")
    _git(tmp_path, "commit", "-m", "pin intended initiative revision to P (F)")
    final = _git(tmp_path, "rev-parse", "HEAD")
    return snapshot, final


def _verify_clean_checkout_of_f(
    tmp_path: Path, snapshot: str, final: str
) -> dict:
    """Run the binding verifier from a CLEAN checkout of F (T-0101h finding 4).

    A fresh ``git clone --shared`` at F — NOT the (already clean) rehearsal
    tree — proves the pinned bundle self-verifies: ``chain_spec_not_at_
    intended_revision`` and every ``asset_not_at_intended_revision`` must be
    gone and ``ready`` must be True.
    """
    clone_dir = tmp_path / "clean-f-checkout"
    shutil.rmtree(clone_dir, ignore_errors=True)
    subprocess.run(
        ["git", "clone", "--quiet", "--shared", "--no-checkout", str(tmp_path), str(clone_dir)],
        check=True,
        capture_output=True,
        text=True,
    )
    _git(clone_dir, "checkout", "--quiet", "--detach", final)
    assert _git(clone_dir, "rev-parse", "HEAD") == final
    clone_spec = clone_dir / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    assert clone_spec.is_file()
    identity = active_execution_identity(clone_spec)
    assert identity["ready"] is True, identity["errors"]
    revision = identity["revision_verification"]
    assert revision["ok"] is True, revision["errors"]
    assert revision["revision"] == snapshot
    assert "chain_spec_not_at_intended_revision" not in revision["errors"]
    asset_errors = [
        error
        for error in revision["errors"]
        if error.startswith("asset_not_at_intended_revision:")
    ]
    assert asset_errors == [], asset_errors
    return identity


def _masked_legacy_identity(
    old_identity: dict, candidate_root: str
) -> dict:
    """Mask the REAL verified legacy runtime identity onto the live-box root.

    The migration's relaunch gate resolves the command's
    ``/workspace/runtime-candidates/<slug>`` root (the live box layout) and
    demands it equal the verified legacy runtime root.  This host has no
    ``/workspace``, so the rehearsal replays the migration on the live-shaped
    identity: every path under the real offline root is re-rooted at the
    candidate literal, the real ``source_revision`` is preserved, and the
    content digest is recomputed through the same normalizer the migration's
    chain check uses.
    """
    old_root = str(Path(old_identity["import_root"]).resolve())

    def _mask(value: str) -> str:
        text = str(value)
        return text.replace(old_root, candidate_root) if text.startswith(old_root) else text

    masked = dict(old_identity)
    masked["import_root"] = candidate_root
    masked["editable_root"] = _mask(str(masked.get("editable_root") or ""))
    masked["editable_revision"] = str(
        masked.get("editable_revision") or masked.get("source_revision") or ""
    )
    direct_url = dict(masked.get("direct_url") or {})
    if "url" in direct_url:
        direct_url["url"] = _mask(str(direct_url["url"]))
    masked["direct_url"] = direct_url
    masked["pth"] = [
        {
            **dict(record),
            "path": _mask(str(record.get("path") or "")),
            "entries": [_mask(str(entry)) for entry in record.get("entries", [])],
        }
        for record in masked.get("pth") or []
        if isinstance(record, dict)
    ]
    masked["imports"] = {
        key: _mask(str(value))
        for key, value in (masked.get("imports") or {}).items()
    }
    masked["content_sha256"] = _normalized(masked)["content_sha256"]
    return masked


def _masked_chain_state_file(
    path: Path, spec_path: Path, masked_identity: dict
) -> Path:
    """A chain-state evidence file for the migration that mirrors the REAL
    paused chain state (same pause authority, plan, spec paths) with only the
    runtime binding re-rooted to the live-shaped masked identity — the
    migration's chain check requires the state's binding to equal the
    verified identity."""
    state_path = chain_spec._state_path_for(spec_path)
    raw = json.loads(state_path.read_text(encoding="utf-8"))
    binding = raw["metadata"]["execution_binding"]
    binding["runtime_binding"]["current_identity"] = dict(masked_identity)
    path.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _migration_fixture(
    root: Path,
    *,
    spec_path: Path,
    old_identity: dict,
    candidate_root: str,
    workspace: str,
    marker_path: Path,
    write_marker: bool = False,
) -> dict:
    """Write the evidence files the legacy marker migration consumes into
    *root*: masked runtime identity, provenance receipt, and the re-rooted
    chain-state evidence.  The TRUE identity-less marker (r5 shape:
    ``editable_source_head=None``, ``editable_install_sync.status=skipped``,
    no source) is NOT written here — the rehearsal seeds ONE unchanged copy at
    setup and the whole sequence consumes it.  ``write_marker=True``
    materializes a THROWAWAY identity-less marker (same shape, same relaunch
    format) for wrong-CAS probes OUTSIDE the rehearsal tree.

    The relaunch command names exactly one ``/workspace/runtime-candidates``-
    style root (the live-box layout).  Returns every CLI piece the migration
    needs (relaunch command + digest, masked identity, chain state, identity
    and receipt paths).
    """
    relaunch = (
        f"SRC={candidate_root}; PYTHONPATH={candidate_root} python -P -m "
        f"arnold_pipelines.megaplan chain start --spec "
        f"{spec_path.resolve(strict=False)}"
    )
    masked = _masked_legacy_identity(old_identity, candidate_root)
    if write_marker:
        marker = {
            "session": SESSION,
            "workspace": workspace,
            "remote_spec": str(spec_path.resolve(strict=False)),
            "run_kind": "chain",
            "should_run": False,
            "operator_pause": {"active": True, "plan": PLAN},
            "editable_source_branch": "editible-install",
            "editable_source_head": None,
            "editable_install_sync": {"status": "skipped", "reason": "disabled_by_flag"},
            "relaunch_command": relaunch,
        }
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        marker_path.write_text(json.dumps(marker, sort_keys=True) + "\n", encoding="utf-8")
    evidence = root / "migration-evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    identity_path = evidence / "runtime-identity.json"
    identity_path.write_text(
        json.dumps(masked, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    receipt_path = evidence / "runtime-provenance-receipt.json"
    receipt_path.write_text("{}\n", encoding="utf-8")
    chain_state_path = _masked_chain_state_file(
        evidence / "chain-state-masked.json", spec_path, masked
    )
    return {
        "marker_path": marker_path,
        "relaunch": relaunch,
        "relaunch_sha256": hashlib.sha256(relaunch.encode("utf-8")).hexdigest(),
        "masked_identity": masked,
        "chain_state_path": chain_state_path,
        "identity_path": identity_path,
        "receipt_path": receipt_path,
    }


def _migration_argv(
    fixture: dict, *, tmp_path: Path, spec_path: Path, **overrides: str
) -> list[str]:
    argv = [
        "--marker", str(fixture["marker_path"]),
        "--expect-marker-sha256", _sha256_file(fixture["marker_path"]),
        "--expect-relaunch-command-sha256", fixture["relaunch_sha256"],
        "--expect-legacy-runtime-root", LEGACY_CANDIDATE,
        "--expect-chain-runtime-sha256", fixture["masked_identity"]["content_sha256"],
        "--expect-session", SESSION,
        "--expect-workspace", str(tmp_path),
        "--expect-remote-spec", str(spec_path.resolve(strict=False)),
        "--expect-current-plan", PLAN,
        "--chain-state", str(fixture["chain_state_path"]),
        "--runtime-identity", str(fixture["identity_path"]),
        "--runtime-provenance-receipt", str(fixture["receipt_path"]),
        "--reason",
        "T-0101 rehearsal: bind the identity-less marker to the verified "
        "legacy runtime",
        "--actor", "operator",
    ]
    for flag, value in overrides.items():
        argv[argv.index(flag) + 1] = value
    return argv


def _repair_identity() -> dict[str, object]:
    return dict(
        repair_identity(
            session=REPAIR_SESSION,
            plan=PLAN,
            failure_kind="deterministic_phase_failure",
            phase="gate",
            task="phase:gate",
            environment=str(Path("/workspace") / SESSION),
        )
    )


def _plan_payload(
    identity: dict[str, object] | None = None,
    *,
    failure_recorded_at: str = "2026-08-12T00:00:00Z",
) -> dict[str, object]:
    """Plan-state payload for the copied-state rehearsal trees.

    The plan state is IDENTITY-LESS by construction (T-0101e'): the blocked
    occurrence being adopted carries no synthetic v1 repair identity
    anywhere (not in ``meta``, not in ``latest_failure.metadata``) — the
    old synthetic v1 seeding is removed.  The REQUEST-side identity (used by
    ``_enqueue_repair``) is a separate, explicitly persisted test-owned fact.
    """
    return {
        "schema_version": 1,
        "name": PLAN,
        "current_state": "blocked",
        "phase": "gate",
        "iteration": 1,
        "latest_failure": {
            "kind": "deterministic_phase_failure",
            "phase": "gate",
            "recorded_at": failure_recorded_at,
            "message": "blocked_no_lease: no current custody lease for the gate boundary",
            "metadata": {"blocked_no_lease": "gate"},
        },
        "resume_cursor": {
            "phase": "gate",
            "retry_strategy": "repair_phase_contract",
        },
        "meta": {"kept": True},
    }


def _write_plan_state(tmp_path: Path, payload: dict[str, object]) -> Path:
    plan_dir = tmp_path / ".megaplan" / "plans" / PLAN
    plan_dir.mkdir(parents=True, exist_ok=True)
    plan_path = plan_dir / "state.json"
    plan_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return plan_path


def _write_cloud_marker(
    tmp_path: Path,
    spec_path: Path,
    *,
    old_root: Path,
) -> Path:
    """Seed the EXACT paused identity-less legacy marker (r5 shape:
    ``editable_source_head=None``, ``editable_install_sync.status=skipped``,
    no source, no ``runtime_binding``).  The relaunch command names exactly
    one ``/workspace/runtime-candidates``-style root (the old runtime root).
    The whole migration sequence consumes ONE unchanged copy of this marker —
    nothing rewrites it between steps."""
    marker_dir = tmp_path / ".megaplan" / "cloud-sessions"
    marker_dir.mkdir(parents=True, exist_ok=True)
    marker_path = marker_dir / f"{SESSION}.json"
    marker_path.write_text(
        json.dumps(
            {
                "session": SESSION,
                "workspace": str(tmp_path),
                "remote_spec": str(spec_path.resolve(strict=False)),
                "run_kind": "chain",
                "should_run": False,
                "operator_pause": {"active": True, "plan": PLAN},
                "editable_source_branch": "editible-install",
                "editable_source_head": None,
                "editable_install_sync": {
                    "status": "skipped",
                    "reason": "disabled_by_flag",
                },
                "relaunch_command": (
                    f"SRC={old_root}; PYTHONPATH={old_root} python -P -m "
                    f"arnold_pipelines.megaplan chain start --spec "
                    f"{spec_path.resolve(strict=False)}"
                ),
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return marker_path


def _write_runtime_manifest(
    manifest_path: Path,
    *,
    epic_id: str,
    runtime_root: Path,
    expected_head: str,
) -> Path:
    """The pre-cutover per-epic manifest for the LEGACY runtime, in the exact
    staging layout (``{root}/.venv``, wrapper under the checkout,
    ``pyproject.toml`` lockfile, empty editable install path)."""
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest = RuntimeManifest.from_dict(
        {
            "runtime_id": "runtime-canary-1",
            "schema": MANIFEST_SCHEMA_VERSION,
            "generation": 1,
            "epic_id": epic_id,
            "state": "active",
            "owner": "operator",
            "base": {
                "ref": "refs/heads/main",
                "commit": expected_head,
                "editable_install_path": "",
                "venv_path": str(runtime_root / ".venv"),
            },
            "epic": {
                "branch": "canary-work",
                "worktree_path": str(runtime_root),
                "venv_path": str(runtime_root / ".venv"),
                "runtime_root": str(runtime_root),
                "expected_head": expected_head,
                "repair_bin": str(
                    runtime_root
                    / "arnold_pipelines"
                    / "megaplan"
                    / "cloud"
                    / "wrappers"
                    / "arnold-babysitter"
                ),
                "deps_lockfile": str(runtime_root / "pyproject.toml"),
            },
            "indirection": {
                "host_path": str(runtime_root),
                "container_path": "/workspace/demo",
                "mount_table": [],
                "execution_namespace": "demo-ns",
                "verified_head": expected_head,
                "last_verified_at": "2026-08-12T00:00:00+00:00",
                "attestation": {
                    "module_file": str(runtime_root / "arnold_pipelines" / "__init__.py"),
                    "module_digest": "0" * 64,
                    "mount_id": "0:0",
                },
            },
            "policy": {
                "policy_sha": "policy-1",
                "model_policy_sha": "model-1",
                "sync_policy": "push-on-promote",
            },
            "promotions": [],
            "timestamps": {
                "created": "2026-08-12T00:00:00+00:00",
                "updated": "2026-08-12T00:00:00+00:00",
                "closed": "",
            },
            "gc_policy": "closed-only",
            "commands": ["megaplan chain"],
        }
    )
    write_manifest(manifest, manifest_path)
    return manifest_path


def _enqueue_repair(tmp_path: Path, identity: dict[str, object]) -> dict[str, object]:
    queue_root = tmp_path / ".megaplan" / "repair-queue"
    plan_dir = tmp_path / ".megaplan" / "plans" / PLAN
    return repair_requests.enqueue_occurrence_bound_repair_request(
        queue_root=queue_root,
        session=REPAIR_SESSION,
        source="lifecycle_failure",
        workspace=tmp_path,
        run_kind="chain",
        marker_dir=plan_dir,
        target={
            "plan_dir": str(plan_dir),
            "plan_name": PLAN,
            "workspace_path": str(tmp_path),
            "retry_strategy": "repair_phase_contract",
        },
        problem_signature={
            "failure_kind": "deterministic_phase_failure",
            "current_state": "blocked",
            "phase_or_step": "gate",
            "milestone_or_plan": PLAN,
            "gate_recommendation": "repair gate contract",
            "blocked_task_id": "phase:gate",
        },
        root_cause_hint="blocked_no_lease: gate boundary lease unavailable",
        occurrence_identity=identity,
    )


def _emit_control_runtime_receipt(
    offline_rollback_runtime: dict[str, Path | str],
) -> dict[str, Path]:
    """Emit an independent provenance receipt for the CONTROL runtime.

    The NEW runtime of this rehearsal is the control runtime itself (the
    interpreter that will resume the chain); python_b (an independent venv
    whose editable install points at REPO_ROOT) receipts it, exactly like the
    fixture receipts the legacy runtime with python_a.
    """
    revision = _git(REPO_ROOT, "rev-parse", "HEAD")
    identity_path = Path(offline_rollback_runtime["root"]) / "runtime-control-identity.json"
    receipt_path = Path(offline_rollback_runtime["root"]) / "runtime-control-receipt.json"
    provenance_program = (
        REPO_ROOT / "arnold_pipelines" / "megaplan" / "cloud" / "runtime_provenance.py"
    )
    result = subprocess.run(
        [
            str(offline_rollback_runtime["python_b"]),
            "-P",
            str(provenance_program),
            "--expected-root",
            str(REPO_ROOT),
            "--expected-revision",
            revision,
            "--receipt-out",
            str(receipt_path),
            "--identity-out",
            str(identity_path),
            "--emit-receipt",
        ],
        check=False,
        capture_output=True,
        text=True,
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
    )
    assert result.returncode == 0, result.stderr
    return {"identity": identity_path, "receipt": receipt_path, "revision": revision}


def _build_control_dependency_generation(
    offline_rollback_runtime: dict[str, Path | str],
) -> tuple[dict[str, object], Path]:
    """Build and production-verify the candidate's immutable dependency generation."""
    proof = ensure_dependency_generation(
        REPO_ROOT,
        Path(offline_rollback_runtime["root"]) / "control-generations",
        python_executable=str(offline_rollback_runtime["python_b"]),
        build_strategy="pip",
    )
    _verify_dependency_generation_binding(proof, runtime_root=str(REPO_ROOT))
    interpreter = Path(str(proof["interpreter_path"])).resolve()
    generation = interpreter.parent.parent
    assert generation.name == str(proof["frozen_spec_sha256"])
    assert generation.is_relative_to(
        Path(offline_rollback_runtime["root"]).resolve()
    )
    return proof, generation


# ── rollback-injection harness ----------------------------------------------

def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _restore(root: Path, snap: dict[str, bytes]) -> None:
    for path in sorted(root.rglob("*")):
        if path.is_file() and str(path.relative_to(root)) not in snap:
            path.unlink()
    for rel, data in snap.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        # os.replace (not write_bytes) so read-only files like git loose
        # objects (0444) can be rolled back byte-for-byte.
        tmp = target.with_name(target.name + ".restore-tmp")
        tmp.write_bytes(data)
        os.replace(tmp, target)


def _snapshot_excluding_sqlite(root: Path) -> dict[str, bytes]:
    """Snapshot every file except SQLite databases and their WAL/SHM sidecars.

    Merely OPENING a WAL-mode SQLite database for reads can checkpoint the
    WAL into the main file, so byte-comparison is not a sound zero-mutation
    oracle for those files; the step semantics (no new claims/leases/receipts)
    are asserted separately where a refusal touches a ledger.
    """
    return {
        rel: data
        for rel, data in _snapshot(root).items()
        if not rel.endswith(".sqlite3")
        and not rel.endswith(".sqlite3-wal")
        and not rel.endswith(".sqlite3-shm")
    }


def _refuse_zero_mutation(tmp_path: Path, attempt) -> None:
    """Run a wrong-CAS attempt and prove ZERO mutation byte-for-byte."""
    pre = _snapshot_excluding_sqlite(tmp_path)
    attempt()
    assert _snapshot_excluding_sqlite(tmp_path) == pre, (
        "wrong-CAS input must refuse with zero mutation (every byte unchanged)"
    )


def _rehearse(
    tmp_path: Path,
    run,
    verify,
    refuse,
    *,
    refuse_before: bool = False,
):
    """Rollback-injection rehearsal of one write step.

    - ``run()`` executes the step and returns its result.
    - ``verify(result)`` asserts every written file still CAS-verifies.
    - ``refuse()`` attempts the step with wrong-CAS input; must raise CliError
      with zero mutation.
    - ``refuse_before=True`` when the refusal only makes sense on the pre-step
      state (e.g. pause refuses a plan that is already done).

    Returns the result of the post-rollback re-run (the state the next step
    consumes).
    """
    if refuse_before:
        refuse()
    pre = _snapshot(tmp_path)
    result = run()
    verify(result)
    _restore(tmp_path, pre)
    result = run()
    verify(result)
    if not refuse_before:
        refuse()
    return result


# ── quiesce precondition (T-0101h finding on watchdog/incident-ledger
#    writers; the live quiesce is operator-side) ─────────────────────────────

def assert_quiesce_precondition(root: Path) -> None:
    """Quiesce precondition for the T-0101 canary transaction.

    Live contract (tasklist T-0101): before the sequence the operator MUST
    disable the systemd watchdog restarter and stop every watchdog/chain/
    repair/incident-ledger writer (proved via a writer-FD census).  The
    rehearsal cannot stop live writers, so it simulates the precondition:
    this helper exists and is callable, and the copied tree itself carries no
    incident-ledger journal — no writer has appended to the rehearsal copy.
    """
    ledger = root / ".megaplan" / "incident-ledger"
    if ledger.exists():
        journal = [path for path in ledger.rglob("*") if path.is_file()]
        assert not journal, (
            "quiesce precondition failed: incident-ledger writers are not "
            f"stopped ({len(journal)} journal files present in the rehearsal tree)"
        )


# ── REAL CLI dispatch helpers (parser + dispatch, not raw functions) ──────

def _expect_ok(rc: int, payload: dict | None) -> dict:
    """Assert a CLI dispatch succeeded and return its stdout JSON payload."""
    assert rc == 0, f"CLI command failed: rc={rc} payload={payload!r}"
    assert payload is not None and payload.get("success") is not False, payload
    return payload


def _chain_cli(
    root: Path, argv: list[str], capsys: pytest.CaptureFixture[str]
) -> tuple[int, dict | None]:
    """Invoke the REAL ``megaplan chain`` CLI in-process: the top-level parser
    (``megaplan.cli.build_parser``) parses *argv* and ``run_chain_cli``
    dispatches — the exact parser + dispatch path ``python -P -m
    arnold_pipelines.megaplan chain ...`` takes, minus the subprocess hop.
    """
    from arnold_pipelines.megaplan.chain import run_chain_cli
    from arnold_pipelines.megaplan.cli import build_parser

    args = build_parser().parse_args(argv)
    rc = run_chain_cli(root, args)
    captured = capsys.readouterr()
    payload = json.loads(captured.out) if captured.out.strip() else None
    return rc, payload


def _manifest_cli(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> tuple[int, dict | None]:
    """Invoke the REAL ``runtime_manifest`` CLI in-process (its own argparse
    parser + dispatch, as ``python -P -m
    arnold_pipelines.megaplan.cloud.runtime_manifest cutover ...``).
    """
    rc = runtime_manifest_module.main(argv)
    captured = capsys.readouterr()
    payload = json.loads(captured.out) if captured.out.strip() else None
    return rc, payload


def _marker_cli(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> tuple[int, dict | None]:
    """Invoke the REAL ``runtime_cutover`` CLI in-process (``python -P -m
    arnold_pipelines.megaplan.cloud.runtime_cutover`` — the ordinary marker
    runtime cutover command).  Refusals raise CliError out of ``main``; the
    wrapper normalizes them to rc 2."""
    try:
        rc = runtime_cutover_module.main(argv)
    except CliError:
        rc = 2
    captured = capsys.readouterr()
    payload = json.loads(captured.out) if captured.out.strip() else None
    return rc, payload


def _migration_cli(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> tuple[int, dict | None]:
    """Invoke the REAL ``legacy_marker_runtime_migration`` module CLI
    (``python -P -m arnold_pipelines.megaplan.cloud.
    legacy_marker_runtime_migration``).  Refusals raise CliError out of
    ``main``; the wrapper normalizes them to rc 2 (the OSError write-failure
    injection still propagates, like the marker cutover)."""
    try:
        rc = legacy_marker_module.main(argv)
    except CliError:
        rc = 2
    captured = capsys.readouterr()
    payload = json.loads(captured.out) if captured.out.strip() else None
    return rc, payload


# ── effect-boundary failure injection ─────────────────────────────────────

def _boom(message: str):
    """Return a callable that always raises OSError (write-boundary probe)."""

    def _raise(*_args, **_kwargs):
        raise OSError(message)

    return _raise


class _FailingTempfile:
    """Stand-in for the ``tempfile`` module global inside a cloud module:
    ``mkstemp`` (the atomic write's entry point) raises OSError; every other
    attribute delegates to the real module.
    """

    def mkstemp(self, *_args, **_kwargs):
        raise OSError("injected marker write failure")

    def __getattr__(self, name):
        return getattr(tempfile, name)


class _FailingTempfileAfter:
    """Stand-in for the ``tempfile`` module global inside a cloud module:
    ``mkstemp`` succeeds for the first ``succeed`` calls (the prepared
    receipt, then the marker replacement's temp file) and raises OSError on
    the next one — the committed-receipt write boundary, i.e. AFTER
    ``os.replace(marker)``.  Every other attribute delegates to the real
    module.
    """

    def __init__(self, succeed: int):
        self._succeed = succeed
        self._calls = 0

    def mkstemp(self, *_args, **_kwargs):
        if self._calls < self._succeed:
            self._calls += 1
            return tempfile.mkstemp(*_args, **_kwargs)
        raise OSError("injected committed-receipt write failure")

    def __getattr__(self, name):
        return getattr(tempfile, name)


class _FailingReplaceOS:
    """Stand-in for the ``os`` module global inside the migration module:
    every attribute delegates to the real module EXCEPT ``replace``, which
    raises (the marker-replacement boundary, AFTER the prepared receipt)."""

    def __getattr__(self, name):
        if name == "replace":
            raise OSError("injected marker replace failure")
        return getattr(os, name)


class _FixedClock:
    """Stand-in for the ``time`` module global inside a cloud module:
    ``strftime`` returns a FIXED future stamp (simulating a DELAYED retry at
    a later wall-clock time); ``gmtime`` returns ``None``."""

    def __init__(self, stamp: str) -> None:
        self._stamp = stamp

    def strftime(self, _fmt: str, _when=None) -> str:
        return self._stamp

    def gmtime(self) -> None:
        return None


def _minimal_join_state(tmp_path: Path) -> dict[str, object]:
    """The copied-state surface the ``chain occurrence-join`` CLI consumes: a
    progressed, stopped-BLOCKED (unpaused) chain + plan state + one enqueued
    repair request/decision with a normalized occurrence identity.
    """
    spec_path = _pin_legacy_chain(tmp_path)
    _git(tmp_path, "checkout", "-b", BRANCH)
    chain_state = ChainState()
    chain_state.current_milestone_index = 0
    chain_state.current_plan_name = PLAN
    chain_state.last_state = "blocked"
    chain_state.chain_session = SESSION
    chain_state.completed = []
    save_chain_state(spec_path, chain_state)
    identity = _repair_identity()
    plan_path = _write_plan_state(tmp_path, _plan_payload(identity))
    queue = _enqueue_repair(tmp_path, identity)
    assert queue["status"] == "queued", queue
    return {
        "spec_path": spec_path,
        "plan_path": plan_path,
        "plan_dir": tmp_path / ".megaplan" / "plans" / PLAN,
        "queue": queue,
        "identity": identity,
    }


def _join_argv(tmp_path: Path, state: dict[str, object], receipt_path: Path) -> list[str]:
    """argv for ``megaplan chain occurrence-join`` against *state*."""
    queue = state["queue"]
    return [
        "chain",
        "occurrence-join",
        "--spec", str(state["spec_path"]),
        "--project-dir", str(tmp_path),
        "--session", REPAIR_SESSION,
        "--occurrence", queue["request"]["repair_identity_key"],
        "--request", queue["request"]["request_id"],
        "--decision", queue["decision"]["decision_id"],
        "--claim", CLAIM_ID,
        "--reason", "T-0101 rehearsal: operator exact-occurrence join",
        "--actor", "operator",
        "--receipt", str(receipt_path),
    ]


# ── the rehearsal -----------------------------------------------------------

def test_canary_rehearsal_full_sequence_with_rollback_injection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    offline_rollback_runtime: dict[str, Path | str],
) -> None:
    """The whole T-0101 sequence on copied state, rollback injected everywhere."""
    # ── copied state: progressed, blocked, UNBOUND chain ──────────────────
    spec_path = _pin_legacy_chain(tmp_path)
    _git(tmp_path, "checkout", "-b", BRANCH)
    chain_state = ChainState()
    chain_state.current_milestone_index = 0
    chain_state.current_plan_name = PLAN
    chain_state.last_state = "blocked"
    chain_state.chain_session = SESSION
    chain_state.completed = []
    save_chain_state(spec_path, chain_state)  # metadata stays unbound/unpaused

    identity = _repair_identity()
    plan_payload = _plan_payload(identity)
    plan_path = _write_plan_state(tmp_path, plan_payload)

    real_old_identity = json.loads(
        Path(offline_rollback_runtime["identity"]).read_text(encoding="utf-8")
    )
    real_old_identity_path = Path(offline_rollback_runtime["identity"])
    real_old_receipt_path = Path(offline_rollback_runtime["receipt"])
    # The whole sequence replays on the LIVE-SHAPED old runtime: the marker
    # relaunch gate resolves a /workspace/runtime-candidates-style root, so
    # the canonical "old runtime" is the REAL identity re-rooted at
    # LEGACY_CANDIDATE.  The REAL offline runtime still re-verifies first
    # inside the patched verifier seam (steps b and c).
    old_identity = _masked_legacy_identity(real_old_identity, LEGACY_CANDIDATE)
    old_root = Path(old_identity["import_root"]).resolve()
    old_revision = str(old_identity["source_revision"])
    # The masked identity migrate binds in step (b): written out so the REAL
    # CLI's --old-runtime-identity flag names the exact identity it binds.
    masked_identity_path = (
        tmp_path / "migration-evidence" / "runtime-identity-masked.json"
    )
    masked_identity_path.parent.mkdir(parents=True, exist_ok=True)
    masked_identity_path.write_text(
        json.dumps(old_identity, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    marker_path = _write_cloud_marker(tmp_path, spec_path, old_root=old_root)
    manifest_path = _write_runtime_manifest(
        tmp_path / "runtime-manifest.json",
        epic_id="demo",
        runtime_root=old_root,
        expected_head=old_revision,
    )
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["bootstrap_manifest_path"] = str(manifest_path)
    marker_path.write_text(json.dumps(marker, sort_keys=True) + "\n", encoding="utf-8")
    marker_sha_seeded = _sha256_file(marker_path)
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(manifest_path))
    queue = _enqueue_repair(tmp_path, identity)
    assert queue["status"] == "queued", queue

    # Quiesce precondition: watchdog/incident-ledger writers stopped before
    # the sequence (helper exists, is callable, and the copied tree carries
    # no incident-ledger journal; the live quiesce is operator-side).
    assert callable(assert_quiesce_precondition)
    assert_quiesce_precondition(tmp_path)

    # Independent receipt for the NEW (control) runtime, used by the manifest
    # CAS cutover (g).
    control = _emit_control_runtime_receipt(offline_rollback_runtime)
    control_revision = str(control["revision"])
    assert control_revision == _git(REPO_ROOT, "rev-parse", "HEAD")

    rollback_receipt_path = tmp_path / "manifest-cutover-rollback.json"
    plan_dir = tmp_path / ".megaplan" / "plans" / PLAN
    # occurrence-join receipts are constrained to the plan evidence root.
    receipt_path = plan_dir / "evidence" / "occurrence-join-receipt.json"

    # ── (a) pause via the REAL chain CLI under the old optional spec ──────
    def _pause_argv(reason: str) -> list[str]:
        return [
            "chain",
            "pause",
            "--spec", str(spec_path),
            "--project-dir", str(tmp_path),
            "--reason", reason,
            "--actor", "operator",
        ]

    def run_a():
        return _expect_ok(*_chain_cli(tmp_path, _pause_argv(
            "T-0101 rehearsal: pause before legacy migration"
        ), capsys))

    def verify_a(result):
        assert result["paused"] is True
        state = load_chain_state(spec_path, verify_execution_binding=False)
        authority = pause_record(state)
        assert authority is not None and authority.get("plan") == PLAN
        assert authority.get("previous_chain_last_state") == "blocked"
        assert authority.get("previous_plan_state") == "blocked"
        assert state.last_state == "paused"
        # The written chain state still CAS-verifies against the spec file.
        assert state.metadata["chain_spec_sha256"] == _sha256_file(spec_path)
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        assert plan["current_state"] == "paused"
        assert plan["meta"][AUTHORITY_KEY]["schema_version"] == AUTHORITY_SCHEMA
        assert plan["latest_failure"] == plan_payload["latest_failure"]
        assert plan["resume_cursor"] == plan_payload["resume_cursor"]

    def refuse_a():
        def attempt():
            plan_bytes = plan_path.read_bytes()
            payload = json.loads(plan_bytes)
            payload["current_state"] = "done"
            plan_path.write_text(json.dumps(payload), encoding="utf-8")
            try:
                rc, payload = _chain_cli(tmp_path, _pause_argv("probe"), capsys)
                assert rc == 1
                assert payload is not None and payload.get("success") is False
            finally:
                plan_path.write_bytes(plan_bytes)

        _refuse_zero_mutation(tmp_path, attempt)

    _rehearse(tmp_path, run_a, verify_a, refuse_a, refuse_before=True)

    # ── (b) execution-binding-migrate via the REAL CLI (old runtime) ──────
    # migrate RUNS on the paused OPTIONAL legacy spec — the old
    # "driver.execution_binding is not required" refusal is gone.  The marker
    # is the SAME identity-less r5 marker seeded at setup (no rewrite between
    # steps): migrate accepts it under the explicit marker-SHA + relaunch-root
    # guards — the strong runtime_binding is created by (c), not here.  The
    # REAL offline runtime is still independently reverified via its
    # provenance receipt by the same verifier the CLI uses; the identity
    # migrate binds is the LIVE-SHAPED masked one (relaunch gate is
    # /workspace-layout), written out at setup above.
    def _migrate_argv(expected_branch: str, reason: str) -> list[str]:
        return [
            "chain",
            "execution-binding-migrate",
            "--spec", str(spec_path),
            "--project-dir", str(tmp_path),
            "--old-runtime-identity",
            str(masked_identity_path),
            "--old-runtime-provenance-receipt",
            str(real_old_receipt_path),
            "--expected-current-milestone", "c1",
            "--expected-current-plan", PLAN,
            "--expected-branch", expected_branch,
            "--expect-marker-sha256", _sha256_file(marker_path),
            "--reason", reason,
            "--actor", "operator",
        ]

    def run_b():
        return _expect_ok(
            *_chain_cli(tmp_path, _migrate_argv(
                BRANCH,
                "T-0101 rehearsal: bind independently receipted legacy runtime",
            ), capsys)
        )

    def verify_b(result):
        assert result["old_runtime_root"] == str(old_root)
        assert result["engine_root"] == str(old_root)
        assert result["verification_mode"] == "external_interpreter_receipt"
        state = load_chain_state(spec_path, verify_execution_binding=False)
        binding = state.metadata["execution_binding"]
        assert binding["runtime_binding"]["current_identity"] == old_identity
        assert binding["launched_identity"]["runtime"] == old_identity
        assert binding["runtime_binding"]["rebind_events"] == []
        assert state.metadata["execution_environment"]["engine_root"] == str(old_root)
        # Every non-metadata field is preserved; pause survives.
        assert state.current_milestone_index == 0
        assert state.current_plan_name == PLAN
        assert state.last_state == "paused"
        assert pause_record(state) is not None
        # The written state still CAS-verifies against the spec it guards.
        assert state.metadata["chain_spec_sha256"] == _sha256_file(spec_path)
        # The spec is STILL the OLD OPTIONAL policy: migrate binds without
        # touching driver.execution_binding; the full required bundle lands
        # in step (d) and is adopted by the rebind in step (e).
        assert binding_policy(spec_path)["required"] is False
        # Plan / marker / manifest are untouched by the migration transaction;
        # the identity-less marker migrate consumed is byte-identical to the
        # seeded one (no weak→identity-less rewrite anywhere).
        assert json.loads(plan_path.read_text(encoding="utf-8"))["current_state"] == "paused"
        assert json.loads(marker_path.read_text(encoding="utf-8"))["session"] == SESSION
        assert _sha256_file(marker_path) == marker_sha_seeded
        assert marker_runtime_identity(
            json.loads(marker_path.read_text(encoding="utf-8"))
        ) is None
        assert load_manifest(manifest_path).epic["runtime_root"] == str(old_root)

    def refuse_b():
        def wrong_branch():
            def attempt():
                rc, payload = _chain_cli(
                    tmp_path, _migrate_argv("wrong-branch", "probe"), capsys
                )
                assert rc == 1
                assert payload is not None and payload.get("success") is False

            _refuse_zero_mutation(tmp_path, attempt)

        def spec_tamper():
            spec_bytes = spec_path.read_bytes()
            spec_path.write_bytes(spec_bytes + b"# tampered\n")
            try:
                def attempt():
                    rc, payload = _chain_cli(
                        tmp_path, _migrate_argv(BRANCH, "probe"), capsys
                    )
                    assert rc == 1
                    assert payload is not None and payload.get("success") is False

                _refuse_zero_mutation(tmp_path, attempt)
            finally:
                spec_path.write_bytes(spec_bytes)

        _refuse_zero_mutation(tmp_path, wrong_branch)
        _refuse_zero_mutation(tmp_path, spec_tamper)

    # The verifier patch is scoped to step (b) ONLY: later chain CLI actions
    # (rebind, runtime-cutover) must keep using the REAL verifier.  It runs
    # the REAL verifier on the REAL offline runtime first, then returns the
    # live-shaped masked identity migrate binds.
    execution_binding_module = sys.modules[
        "arnold_pipelines.megaplan.chain.execution_binding"
    ]
    real_migrate_verifier = execution_binding_module.verify_external_runtime_identity

    def _migrate_verifier(_identity_path: Path, _receipt_path: Path) -> dict:
        real_verified = verify_external_runtime_identity(
            real_old_identity_path, real_old_receipt_path
        )
        assert real_verified["import_root"] == real_old_identity["import_root"]
        assert real_verified["source_revision"] == real_old_identity["source_revision"]
        return dict(old_identity)

    monkeypatch.setattr(
        execution_binding_module,
        "verify_external_runtime_identity",
        _migrate_verifier,
    )
    try:
        _rehearse(tmp_path, run_b, verify_b, refuse_b)
    finally:
        execution_binding_module.verify_external_runtime_identity = (
            real_migrate_verifier
        )

    # ── (c) legacy_marker_runtime_migration via its REAL module CLI ───────
    # The SAME identity-less r5 marker from step (b) is consumed unchanged
    # (editable_source_head=None, editable_install_sync.status=skipped, no
    # source); the relaunch command names exactly one
    # /workspace/runtime-candidates-style root.  A candidate-shaped tmp dir
    # (with .venv + executable wrapper) mirrors the live layout; the
    # migration's root gate is hardcoded to the literal live-box root, which
    # cannot be materialized on macOS — so, exactly like the migration's own
    # test suite, the ``verify_external_runtime_identity`` seam is patched to
    # (1) run the REAL verifier against the REAL offline runtime first, then
    # (2) return the live-shaped masked identity.  Everything else — the CLI
    # entry, every CAS guard, the marker rewrite, the immutable evidence
    # receipts — runs for real.
    candidate_dir = tmp_path / "workspace" / "runtime-candidates" / "arnold-canary-legacy"
    (candidate_dir / ".venv").mkdir(parents=True, exist_ok=True)
    wrapper = candidate_dir / "arnold-babysitter"
    wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    wrapper.chmod(0o755)
    fixture = _migration_fixture(
        tmp_path,
        spec_path=spec_path,
        old_identity=old_identity,
        candidate_root=LEGACY_CANDIDATE,
        workspace=str(tmp_path),
        marker_path=marker_path,
    )
    # The marker is STILL the seeded identity-less one — no test-only rewrite
    # between (b) and (c): the sequence consumes ONE unchanged marker.
    assert marker_runtime_identity(
        json.loads(marker_path.read_text(encoding="utf-8"))
    ) is None
    assert _sha256_file(marker_path) == marker_sha_seeded

    real_offline_identity_path = Path(offline_rollback_runtime["identity"])
    real_offline_receipt_path = Path(offline_rollback_runtime["receipt"])
    masked_identity = fixture["masked_identity"]

    def _migration_verifier(_identity_path: Path, _receipt_path: Path) -> dict:
        # Real re-verification first: the offline runtime the rehearsal is
        # based on must still verify before the migration is allowed to bind.
        real_verified = verify_external_runtime_identity(
            real_offline_identity_path, real_offline_receipt_path
        )
        assert real_verified["import_root"] == real_old_identity["import_root"]
        assert real_verified["source_revision"] == real_old_identity["source_revision"]
        # Then return the live-shaped (masked) identity the migration binds.
        return dict(masked_identity)

    monkeypatch.setattr(
        legacy_marker_module, "verify_external_runtime_identity", _migration_verifier
    )

    def run_c():
        return _expect_ok(
            *_migration_cli(_migration_argv(fixture, tmp_path=tmp_path, spec_path=spec_path), capsys)
        )

    def verify_c(result):
        assert _sha256_file(marker_path) == result["marker_after_sha256"]
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        # The marker now carries the STRONG runtime_binding form built from
        # the verified legacy runtime (the later CAS cutover (h) runs against
        # this strong form — never the weak legacy fallback).
        binding = marker_runtime_identity(marker)
        assert binding is not None, "marker must be strong-bound after migration"
        assert binding["import_root"] == LEGACY_CANDIDATE
        assert binding["source_revision"] == old_revision
        stored = marker["runtime_binding"]["current_identity"]
        assert _normalized(stored) == _normalized(masked_identity)
        assert marker["editable_source_head"] == old_revision
        assert marker["editable_install_sync"]["status"] == "content-addressed-runtime"
        assert marker["editable_install_sync"]["runtime_sha256"] == binding["content_sha256"]
        assert marker["operator_pause"]["active"] is True
        assert marker["should_run"] is False
        assert marker["relaunch_command"] == fixture["relaunch"]
        # Immutable evidence receipts (prepared + committed) exist.
        evidence_root = marker_path.parent / "runtime-marker-migrations" / SESSION
        receipts = sorted(evidence_root.iterdir())
        assert receipts, "migration must write immutable evidence receipts"
        assert any(path.name.endswith(".prepared.json") for path in receipts)
        assert any(path.name.endswith(".committed.json") for path in receipts)
        # The chain/plan state and the manifest are untouched.
        state = load_chain_state(spec_path, verify_execution_binding=False)
        assert pause_record(state) is not None
        assert state.metadata["chain_spec_sha256"] == _sha256_file(spec_path)
        assert json.loads(plan_path.read_text(encoding="utf-8"))["current_state"] == "paused"
        assert load_manifest(manifest_path).epic["runtime_root"] == str(old_root)

    def refuse_c():
        # The REAL marker is now strong-bound and is the EXACT migration
        # after-image: a correct-CAS re-invocation is IDEMPOTENT (round-3 —
        # the identity-present refusal applies only when the marker DIFFERS
        # from the prepared after-image).  The one-time refusal is proven
        # against a FOREIGN strong-bound marker (digest matches no migration
        # receipt) with zero mutation.
        def one_time_real():
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
            assert marker_runtime_identity(marker) is not None
            original_argv = _migration_argv(
                fixture, tmp_path=tmp_path, spec_path=spec_path
            )
            # The ORIGINAL exact guards include the PRE-migration identity-less
            # before-image digest — never the strong after-image that now sits
            # on disk (that digest is a WRONG before-image guard under the
            # round-4 exact-CAS finalize).
            original_argv[
                original_argv.index("--expect-marker-sha256") + 1
            ] = marker_sha_seeded

            # Same strong-bound after-image with the ORIGINAL exact guards:
            # the idempotent finalize path succeeds with ZERO marker mutation
            # (and does not duplicate evidence).
            migrated_bytes = marker_path.read_bytes()
            rc, payload = _migration_cli(original_argv, capsys)
            assert rc == 0, (
                f"idempotent re-run must succeed: rc={rc} payload={payload!r}"
            )
            assert payload is not None and payload.get("success") is not False, payload
            assert marker_path.read_bytes() == migrated_bytes, (
                "idempotent re-run must not rewrite the marker"
            )

            # T-0101h round-4: finalization binds EVERY invocation guard to
            # the prepared record — an invocation that binds the CURRENT
            # (after-image) digest as the before-image guard is a WRONG guard
            # and must refuse with zero mutation.
            wrong_argv = _migration_argv(
                fixture, tmp_path=tmp_path, spec_path=spec_path
            )
            wrong_argv[
                wrong_argv.index("--expect-marker-sha256") + 1
            ] = _sha256_file(marker_path)
            rc, payload = _migration_cli(wrong_argv, capsys)
            assert rc == 2, (
                f"after-image as before-image guard must refuse: rc={rc} payload={payload!r}"
            )
            assert marker_path.read_bytes() == migrated_bytes, (
                "wrong-guard refusal must not rewrite the marker"
            )

            # A FOREIGN strong-bound marker (content digest matches NO
            # prepared/committed after-image) refuses with zero mutation.
            def foreign_attempt():
                migrated_bytes = marker_path.read_bytes()
                foreign = json.loads(marker_path.read_text(encoding="utf-8"))
                foreign["runtime_binding"]["current_identity"]["content_sha256"] = (
                    "f" * 64
                )
                foreign["editable_source_head"] = "f" * 40
                marker_path.write_text(
                    json.dumps(foreign, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                foreign_bytes = marker_path.read_bytes()
                try:
                    rc, payload = _migration_cli(original_argv, capsys)
                    assert rc == 2
                    assert payload is None or payload.get("success") is False
                    assert marker_path.read_bytes() == foreign_bytes
                finally:
                    marker_path.write_bytes(migrated_bytes)

            _refuse_zero_mutation(tmp_path, foreign_attempt)

        # Wrong-CAS probes against a THROWAWAY identity-less marker OUTSIDE
        # the rehearsal tree (so the real tree is provably untouched): wrong
        # relaunch digest, wrong marker digest, wrong chain runtime digest —
        # each refuses with the throwaway marker byte-unchanged and NO
        # evidence written.
        def wrong_cas_probes():
            probe = Path(tempfile.mkdtemp(prefix="canary-migration-probe-"))
            try:
                probe_fixture = _migration_fixture(
                    probe,
                    spec_path=spec_path,
                    old_identity=old_identity,
                    candidate_root=LEGACY_CANDIDATE,
                    workspace=str(tmp_path),
                    marker_path=probe / f"{SESSION}.json",
                    write_marker=True,
                )
                marker_before = probe_fixture["marker_path"].read_bytes()
                for flag in (
                    "--expect-relaunch-command-sha256",
                    "--expect-marker-sha256",
                    "--expect-chain-runtime-sha256",
                ):
                    argv = _migration_argv(
                        probe_fixture,
                        tmp_path=tmp_path,
                        spec_path=spec_path,
                        **{flag: "0" * 64},
                    )
                    rc, _payload = _migration_cli(argv, capsys)
                    assert rc == 2, f"{flag} must refuse"
                    assert probe_fixture["marker_path"].read_bytes() == marker_before
                    assert not (probe / "runtime-marker-migrations").exists()
            finally:
                shutil.rmtree(probe, ignore_errors=True)

        one_time_real()
        wrong_cas_probes()

    pre_c = _snapshot(tmp_path)
    _rehearse(tmp_path, run_c, verify_c, refuse_c)

    # Injected MIGRATION write failure FIRST (fresh identity-less state): the
    # evidence/marker write path dies (``tempfile.mkstemp`` raises OSError)
    # after every CAS guard passed.  The marker must be byte-unchanged, no
    # stranded evidence may exist, and the SAME module CLI re-run completes.
    _restore(tmp_path, pre_c)
    assert marker_runtime_identity(
        json.loads(marker_path.read_text(encoding="utf-8"))
    ) is None
    migration_before_sha = _sha256_file(marker_path)
    real_migration_tempfile = legacy_marker_module.tempfile
    monkeypatch.setattr(legacy_marker_module, "tempfile", _FailingTempfile())
    try:
        with pytest.raises(OSError):
            _migration_cli(
                _migration_argv(fixture, tmp_path=tmp_path, spec_path=spec_path),
                capsys,
            )
    finally:
        monkeypatch.setattr(legacy_marker_module, "tempfile", real_migration_tempfile)
    assert _sha256_file(marker_path) == migration_before_sha
    # No stranded evidence: the immutable prepared/committed receipts never
    # landed (the write boundary died before any evidence file was written).
    migration_evidence_root = marker_path.parent / "runtime-marker-migrations"
    stranded = (
        [path for path in migration_evidence_root.rglob("*") if path.is_file()]
        if migration_evidence_root.exists()
        else []
    )
    assert stranded == [], stranded
    rc, payload = _migration_cli(
        _migration_argv(fixture, tmp_path=tmp_path, spec_path=spec_path), capsys
    )
    assert rc == 0
    verify_c(payload)

    # Injected MIGRATION write failure in the MARKER-WRITE window (prepared
    # receipt landed, the marker replacement died): mkstemp succeeds for the
    # prepared receipt and raises on the marker's temp file — the marker is
    # byte-unchanged but the prepared receipt is stranded.  A DELAYED
    # identical retry (wall clock advanced to a fixed future stamp) must
    # REUSE the prepared receipt's exact after-image — never recompute
    # time-dependent bytes, which would collide with the immutable prepared
    # receipt — and complete the migration.
    _restore(tmp_path, pre_c)
    assert marker_runtime_identity(
        json.loads(marker_path.read_text(encoding="utf-8"))
    ) is None
    marker_write_argv = _migration_argv(
        fixture, tmp_path=tmp_path, spec_path=spec_path
    )
    real_migration_tempfile = legacy_marker_module.tempfile
    monkeypatch.setattr(legacy_marker_module, "tempfile", _FailingTempfileAfter(1))
    try:
        with pytest.raises(OSError):
            _migration_cli(marker_write_argv, capsys)
    finally:
        monkeypatch.setattr(legacy_marker_module, "tempfile", real_migration_tempfile)
    assert _sha256_file(marker_path) == migration_before_sha, (
        "the marker-write failure must leave the marker byte-unchanged"
    )
    assert marker_runtime_identity(
        json.loads(marker_path.read_text(encoding="utf-8"))
    ) is None
    marker_write_evidence_root = (
        marker_path.parent / "runtime-marker-migrations" / SESSION
    )
    marker_write_prepared = sorted(marker_write_evidence_root.glob("*.prepared.json"))
    marker_write_committed = sorted(
        marker_write_evidence_root.glob("*.committed.json")
    )
    assert len(marker_write_prepared) == 1 and marker_write_committed == [], (
        "the marker-write failure must strand exactly the prepared receipt"
    )
    marker_write_prepared_bytes = marker_write_prepared[0].read_bytes()

    # DELAYED retry: the wall clock has advanced — recomputing time-dependent
    # after-image bytes would change the marker digest and collide with the
    # immutable prepared receipt.  The retry reuses the prepared record.
    real_migration_time = legacy_marker_module.time
    monkeypatch.setattr(
        legacy_marker_module, "time", _FixedClock("2099-12-31T23:59:59Z")
    )
    try:
        rc, payload = _migration_cli(marker_write_argv, capsys)
    finally:
        monkeypatch.setattr(legacy_marker_module, "time", real_migration_time)
    assert rc == 0, f"delayed identical retry must recover: rc={rc} payload={payload!r}"
    assert payload is not None and payload.get("success") is not False, payload
    assert payload["marker_after_sha256"] == json.loads(
        marker_write_prepared_bytes.decode("utf-8")
    )["marker_after_sha256"]
    assert _sha256_file(marker_path) == payload["marker_after_sha256"]
    assert marker_write_prepared[0].read_bytes() == marker_write_prepared_bytes, (
        "the retry must reuse the stranded prepared receipt, not rewrite it"
    )
    assert len(sorted(marker_write_evidence_root.glob("*.committed.json"))) == 1
    verify_c(payload)

    # Injected MIGRATION write failure at ``os.replace`` (the marker
    # replacement boundary, AFTER the prepared receipt landed): same
    # recovery — the delayed identical retry reuses the prepared after-image.
    _restore(tmp_path, pre_c)
    assert marker_runtime_identity(
        json.loads(marker_path.read_text(encoding="utf-8"))
    ) is None
    replace_window_argv = _migration_argv(
        fixture, tmp_path=tmp_path, spec_path=spec_path
    )
    real_migration_os = legacy_marker_module.os
    monkeypatch.setattr(legacy_marker_module, "os", _FailingReplaceOS())
    try:
        with pytest.raises(OSError):
            _migration_cli(replace_window_argv, capsys)
    finally:
        monkeypatch.setattr(legacy_marker_module, "os", real_migration_os)
    assert _sha256_file(marker_path) == migration_before_sha
    assert marker_runtime_identity(
        json.loads(marker_path.read_text(encoding="utf-8"))
    ) is None
    replace_window_evidence_root = (
        marker_path.parent / "runtime-marker-migrations" / SESSION
    )
    replace_window_prepared = sorted(
        replace_window_evidence_root.glob("*.prepared.json")
    )
    assert len(replace_window_prepared) == 1
    assert list(replace_window_evidence_root.glob("*.committed.json")) == []
    monkeypatch.setattr(
        legacy_marker_module, "time", _FixedClock("2100-01-01T00:00:00Z")
    )
    try:
        rc, payload = _migration_cli(replace_window_argv, capsys)
    finally:
        monkeypatch.setattr(legacy_marker_module, "time", real_migration_time)
    assert rc == 0, f"delayed identical retry must recover: rc={rc} payload={payload!r}"
    assert payload is not None and payload.get("success") is not False, payload
    assert payload["marker_after_sha256"] == json.loads(
        replace_window_prepared[0].read_text(encoding="utf-8")
    )["marker_after_sha256"]
    assert _sha256_file(marker_path) == payload["marker_after_sha256"]
    assert len(sorted(replace_window_evidence_root.glob("*.committed.json"))) == 1
    verify_c(payload)

    # Injected MIGRATION write failure AFTER the marker replacement (the
    # committed-receipt boundary): mkstemp succeeds for the prepared receipt
    # and the marker replacement, then raises OSError on the committed
    # receipt.  The marker is strong-bound but NO committed receipt exists.
    # The IDENTICAL CLI invocation (same exact guards, including the ORIGINAL
    # before-image digest) must recognize the exact prepared after-image,
    # emit the missing committed receipt, and return success — the idempotent
    # finalize path — never refuse.
    _restore(tmp_path, pre_c)
    assert marker_runtime_identity(
        json.loads(marker_path.read_text(encoding="utf-8"))
    ) is None
    crash_argv = _migration_argv(fixture, tmp_path=tmp_path, spec_path=spec_path)
    real_migration_tempfile = legacy_marker_module.tempfile
    monkeypatch.setattr(legacy_marker_module, "tempfile", _FailingTempfileAfter(2))
    try:
        with pytest.raises(OSError):
            _migration_cli(crash_argv, capsys)
    finally:
        monkeypatch.setattr(legacy_marker_module, "tempfile", real_migration_tempfile)
    assert marker_runtime_identity(
        json.loads(marker_path.read_text(encoding="utf-8"))
    ) is not None, "marker replacement must have landed before the injected crash"
    crash_evidence_root = marker_path.parent / "runtime-marker-migrations" / SESSION
    crash_prepared = sorted(crash_evidence_root.glob("*.prepared.json"))
    crash_committed = sorted(crash_evidence_root.glob("*.committed.json"))
    assert len(crash_prepared) == 1 and crash_committed == [], (
        "step-3 crash must leave the prepared receipt but no committed receipt"
    )
    rc, payload = _migration_cli(crash_argv, capsys)
    assert rc == 0, f"identical re-invocation must recover: rc={rc} payload={payload!r}"
    assert payload is not None and payload.get("success") is not False, payload
    assert payload["marker_after_sha256"] == _sha256_file(marker_path)
    assert payload["migration_id"] == json.loads(
        crash_prepared[0].read_text(encoding="utf-8")
    )["migration_id"]
    crash_committed = sorted(crash_evidence_root.glob("*.committed.json"))
    assert len(crash_committed) == 1, (
        "the finalize path must emit the missing committed receipt"
    )
    assert payload["commit_path"] == str(crash_committed[0])
    verify_c(payload)

    # ── (d) install the full required-binding bundle (T-0101h P/F) ────────
    # Real git work only: edit chain.yaml driver fields, commit P (the
    # complete bundle), commit F (pin-only).  NO direct save_chain_state —
    # the state-hash re-record happens exclusively through the real
    # ``chain rebind`` CLI in step (e).
    def run_d():
        decision = _write_final_decision_asset(tmp_path)
        assert decision.is_file()
        snapshot, final = _commit_binding_bundle(
            spec_path, tmp_path, assets=[ASSET_REL]
        )
        # P/F two-commit construction: F changes ONLY the pin; the tree is
        # clean (no tracked modifications) and HEAD == F.
        assert _git(tmp_path, "rev-parse", "HEAD") == final
        diff_result = subprocess.run(
            ["git", "-C", str(tmp_path), "diff", "--exit-code", "--quiet"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert diff_result.returncode == 0, "install must leave the tree clean"
        raw = yaml.safe_load(spec_path.read_text(encoding="utf-8"))
        assert raw["driver"]["intended_initiative_revision"] == snapshot
        assert _git(tmp_path, "rev-parse", f"{final}^") == snapshot
        assert snapshot != final
        # The verifier must be ready=True from a CLEAN checkout of F with no
        # chain_spec_not_at_intended_revision and no asset drift.
        _verify_clean_checkout_of_f(tmp_path, snapshot, final)
        return {"snapshot": snapshot, "final": final}

    def verify_d(result):
        policy = binding_policy(spec_path)
        assert policy["required"] is True
        assert policy["require_editable_runtime_match"] is True
        assert policy["execution_binding_assets"] == [ASSET_REL]
        assert policy["intended_initiative_revision"] == result["snapshot"]
        state = load_chain_state(spec_path, verify_execution_binding=False)
        assert pause_record(state) is not None
        # The install NEVER wrote chain state: the recorded spec hash still
        # points at the OLD optional spec, and the launched bundle is the
        # pre-install one — the drift step (e) repairs.
        assert state.metadata["chain_spec_sha256"] != _sha256_file(spec_path)
        report = execution_binding_report(spec_path, state)
        assert report["status"] in {"drift", "reconcile_required"}
        assert "assets" in report["drift_fields"]

    def refuse_d():
        def sequence_tamper():
            spec_bytes = spec_path.read_bytes()
            raw = yaml.safe_load(spec_bytes.decode("utf-8"))
            raw["milestones"][0]["label"] = "c1-renamed"
            spec_path.write_text(
                yaml.safe_dump(raw, sort_keys=False), encoding="utf-8"
            )
            try:
                state = load_chain_state(spec_path, verify_execution_binding=False)
                previous = state.metadata["execution_binding"]["launched_identity"][
                    "bundle_sha256"
                ]

                def attempt():
                    # A sequence-changing install cannot sneak through the
                    # next CAS boundary: the CLI rebind refuses the
                    # uncommitted bundle drift.
                    rc, payload = _chain_cli(
                        tmp_path,
                        [
                            "chain",
                            "rebind",
                            "--spec", str(spec_path),
                            "--from-bundle-sha256", previous,
                            "--to-bundle-sha256", previous,
                            "--expected-current-milestone", "c1",
                            "--expected-current-plan", PLAN,
                            "--expected-next-milestone", "c2",
                            "--reason", "probe",
                            "--actor", "operator",
                        ],
                        capsys,
                    )
                    assert rc == 1
                    assert payload is not None and payload.get("success") is False

                _refuse_zero_mutation(tmp_path, attempt)
            finally:
                spec_path.write_bytes(spec_bytes)

        _refuse_zero_mutation(tmp_path, sequence_tamper)

    _rehearse(tmp_path, run_d, verify_d, refuse_d)

    # ── (e) chain rebind via the REAL CLI for the execution bundle ────────
    # The ONLY supported state-hash re-record: persists via save_chain_state
    # and re-records metadata.chain_spec_sha256 against the NEW spec.
    def run_e():
        state = load_chain_state(spec_path, verify_execution_binding=False)
        previous = state.metadata["execution_binding"]["launched_identity"][
            "bundle_sha256"
        ]
        active = active_execution_identity(spec_path)
        return _expect_ok(
            *_chain_cli(
                tmp_path,
                [
                    "chain",
                    "rebind",
                    "--spec", str(spec_path),
                    "--from-bundle-sha256", previous,
                    "--to-bundle-sha256", active["bundle_sha256"],
                    "--expected-current-milestone", "c1",
                    "--expected-current-plan", PLAN,
                    "--expected-next-milestone", "c2",
                    "--reason",
                    "T-0101 rehearsal: adopt the required-binding bundle",
                    "--actor", "operator",
                ],
                capsys,
            )
        )

    def verify_e(result):
        assert result["execution_binding"]["status"] == "match"
        assert result["event"]["to_bundle_sha256"] == active_execution_identity(
            spec_path
        )["bundle_sha256"]
        state = load_chain_state(spec_path, verify_execution_binding=False)
        assert (
            state.metadata["execution_binding"]["launched_identity"]["bundle_sha256"]
            == active_execution_identity(spec_path)["bundle_sha256"]
        )
        # The bundle-sha re-record: bundle_sha256 includes the pin, so after
        # F the recorded hash changes and the real rebind re-records it.
        assert (
            state.metadata["execution_binding"]["launched_identity"]["bundle_sha256"]
            == result["event"]["to_bundle_sha256"]
        )
        # The spec-hash re-record: the ONLY state write of the install window.
        assert state.metadata["chain_spec_sha256"] == _sha256_file(spec_path)
        # The runtime binding is untouched by the execution-bundle rebind:
        # still the OLD runtime, engine_root still old.
        assert (
            state.metadata["execution_binding"]["runtime_binding"]["current_identity"]
            == old_identity
        )
        assert state.metadata["execution_environment"]["engine_root"] == str(old_root)
        assert state.current_milestone_index == 0
        assert state.current_plan_name == PLAN
        assert pause_record(state) is not None

    def refuse_e():
        state = load_chain_state(spec_path, verify_execution_binding=False)
        previous = state.metadata["execution_binding"]["launched_identity"][
            "bundle_sha256"
        ]
        active = active_execution_identity(spec_path)

        def _rebind_argv(from_sha: str, next_milestone: str) -> list[str]:
            return [
                "chain",
                "rebind",
                "--spec", str(spec_path),
                "--from-bundle-sha256", from_sha,
                "--to-bundle-sha256", active["bundle_sha256"],
                "--expected-current-milestone", "c1",
                "--expected-current-plan", PLAN,
                "--expected-next-milestone", next_milestone,
                "--reason", "probe",
                "--actor", "operator",
            ]

        def wrong_previous():
            def attempt():
                rc, payload = _chain_cli(
                    tmp_path, _rebind_argv("0" * 64, "c2"), capsys
                )
                assert rc == 1
                assert payload is not None and payload.get("success") is False

            _refuse_zero_mutation(tmp_path, attempt)

        def wrong_next():
            def attempt():
                rc, payload = _chain_cli(
                    tmp_path, _rebind_argv(previous, "c3"), capsys
                )
                assert rc == 1
                assert payload is not None and payload.get("success") is False

            _refuse_zero_mutation(tmp_path, attempt)

        _refuse_zero_mutation(tmp_path, wrong_previous)
        _refuse_zero_mutation(tmp_path, wrong_next)

    _rehearse(tmp_path, run_e, verify_e, refuse_e)

    # ── (f) chain runtime-cutover via the REAL CLI: runtime rebind + ──────
    # engine_root old->new in one CAS transaction.
    def run_f():
        state = load_chain_state(spec_path, verify_execution_binding=False)
        previous_sha = state.metadata["execution_binding"]["runtime_binding"][
            "current_identity"
        ]["content_sha256"]
        report = execution_binding_report(spec_path, state)
        active_sha = report["runtime_binding"]["active"]["content_sha256"]
        return _expect_ok(
            *_chain_cli(
                tmp_path,
                [
                    "chain",
                    "runtime-cutover",
                    "--spec", str(spec_path),
                    "--project-dir", str(tmp_path),
                    "--from-runtime-sha256", previous_sha,
                    "--to-runtime-sha256", active_sha,
                    "--expected-current-milestone", "c1",
                    "--expected-current-plan", PLAN,
                    "--direction", "cutover",
                    "--reason",
                    "T-0101 rehearsal: chain runtime cutover to the control runtime",
                    "--actor", "operator",
                ],
                capsys,
            )
        )

    def verify_f(result):
        assert result["runtime_binding"]["status"] == "match"
        assert result["verification_mode"] == "active_control_runtime"
        transition = result["engine_root_transition"]
        assert transition["from_engine_root"] == str(old_root)
        assert Path(transition["to_engine_root"]).resolve() == REPO_ROOT
        state = load_chain_state(spec_path, verify_execution_binding=False)
        assert state.metadata["execution_environment"]["engine_root"] == str(
            REPO_ROOT
        )
        runtime = state.metadata["execution_binding"]["runtime_binding"][
            "current_identity"
        ]
        assert Path(runtime["import_root"]).resolve() == REPO_ROOT
        assert (
            runtime["content_sha256"]
            == result["runtime_binding"]["expected"]["content_sha256"]
        )
        assert state.current_milestone_index == 0
        assert state.current_plan_name == PLAN
        assert pause_record(state) is not None

    def refuse_f():
        def wrong_previous_sha():
            def attempt():
                rc, payload = _chain_cli(
                    tmp_path,
                    [
                        "chain",
                        "runtime-cutover",
                        "--spec", str(spec_path),
                        "--project-dir", str(tmp_path),
                        "--from-runtime-sha256", "f" * 64,
                        "--to-runtime-sha256", "e" * 64,
                        "--expected-current-milestone", "c1",
                        "--expected-current-plan", PLAN,
                        "--direction", "cutover",
                        "--reason", "probe",
                        "--actor", "operator",
                    ],
                    capsys,
                )
                assert rc == 1
                assert payload is not None and payload.get("success") is False

            _refuse_zero_mutation(tmp_path, attempt)

    _rehearse(tmp_path, run_f, verify_f, refuse_f)

    # ── (g) runtime_manifest CAS cutover via the REAL CLI ────────────────
    # The TO generation is immutable, content-addressed, and independently
    # verified against the candidate's frozen dependency spec.  Its venv is
    # intentionally outside the runtime root; only the repair wrapper must
    # resolve inside the receipted runtime root.
    control_generation, to_venv_path = _build_control_dependency_generation(
        offline_rollback_runtime
    )
    to_repair_bin = (
        REPO_ROOT / "arnold_pipelines" / "megaplan" / "cloud" / "wrappers"
    ) / "arnold-babysitter"
    assert to_venv_path.is_dir()
    assert to_repair_bin.is_file() and os.access(to_repair_bin, os.X_OK)

    def _manifest_argv() -> list[str]:
        manifest = load_manifest(manifest_path)
        return [
            "cutover",
            str(manifest_path),
            "--expect-manifest-sha256", _sha256_file(manifest_path),
            "--expect-generation", str(manifest.generation),
            "--from-runtime-root", str(old_root),
            "--from-expected-head", old_revision,
            "--to-runtime-root", str(REPO_ROOT),
            "--to-expected-head", control_revision,
            "--to-venv-path", str(to_venv_path),
            "--to-repair-bin", str(to_repair_bin),
            "--runtime-identity", str(control["identity"]),
            "--runtime-provenance-receipt", str(control["receipt"]),
            "--reason",
            "T-0101 rehearsal: manifest CAS cutover to the control runtime",
            "--actor", "operator",
            "--receipt-out", str(rollback_receipt_path),
            "--to-dependency-generation",
            json.dumps(control_generation, sort_keys=True),
        ]

    def run_g():
        return _expect_ok(*_manifest_cli(_manifest_argv(), capsys))

    def verify_g(result):
        assert result["generation_after"] == result["generation_before"] + 1
        # The written manifest file is byte-exactly the recorded after-image.
        assert _sha256_file(manifest_path) == result["manifest_after_sha256"]
        manifest = load_manifest(manifest_path)
        assert manifest.generation == result["generation_after"]
        assert manifest.epic["runtime_root"] == str(REPO_ROOT)
        assert manifest.epic["expected_head"] == control_revision
        assert manifest.epic["venv_path"] == str(to_venv_path)
        assert manifest.epic["repair_bin"] == str(to_repair_bin)
        assert manifest.indirection["verified_head"] == control_revision
        # Rollback receipt captures the pre-cutover manifest facts.
        receipt = json.loads(rollback_receipt_path.read_text(encoding="utf-8"))
        assert receipt["manifest_before_sha256"] == result["manifest_before_sha256"]
        assert receipt["from"]["runtime_root"] == str(old_root)
        assert receipt["to"]["runtime_root"] == str(REPO_ROOT)

    def refuse_g():
        def wrong_sha():
            argv = _manifest_argv()
            argv[argv.index("--expect-manifest-sha256") + 1] = "0" * 64

            def attempt():
                rc, _payload = _manifest_cli(argv, capsys)
                assert rc == 2

            _refuse_zero_mutation(tmp_path, attempt)

        def nonexistent_to_paths():
            argv = _manifest_argv()
            argv[argv.index("--to-venv-path") + 1] = str(
                tmp_path / "no-such-venv"
            )
            argv[argv.index("--to-repair-bin") + 1] = str(
                tmp_path / "no-such-repair-bin"
            )

            def attempt():
                rc, _payload = _manifest_cli(argv, capsys)
                assert rc == 2

            _refuse_zero_mutation(tmp_path, attempt)

        _refuse_zero_mutation(tmp_path, wrong_sha)
        _refuse_zero_mutation(tmp_path, nonexistent_to_paths)

    # Injected failure FIRST (fresh pre-cutover state): the atomic MANIFEST
    # WRITE dies AFTER the rollback receipt lands.  The receipt (written
    # before the manifest write) must exist, the manifest file must be
    # byte-unchanged (no half-written manifest), and the SAME CLI command
    # re-run must complete the cutover.
    pre_g = _snapshot(tmp_path)
    manifest_before_sha = _sha256_file(manifest_path)
    real_atomic_write = runtime_manifest_module._atomic_write
    monkeypatch.setattr(
        runtime_manifest_module, "_atomic_write", _boom("injected manifest write failure")
    )
    try:
        rc, _payload = _manifest_cli(_manifest_argv(), capsys)
    finally:
        monkeypatch.setattr(runtime_manifest_module, "_atomic_write", real_atomic_write)
    assert rc == 2
    receipt = json.loads(rollback_receipt_path.read_text(encoding="utf-8"))
    assert receipt["manifest_before_sha256"] == manifest_before_sha
    assert receipt["from"]["runtime_root"] == str(old_root)
    assert receipt["to"]["runtime_root"] == str(REPO_ROOT)
    assert receipt["reason"] == "T-0101 rehearsal: manifest CAS cutover to the control runtime"
    assert _sha256_file(manifest_path) == manifest_before_sha
    assert load_manifest(manifest_path).generation == 1
    # The SAME CLI command re-run completes the cutover.
    rc, payload = _manifest_cli(_manifest_argv(), capsys)
    assert rc == 0
    verify_g(payload)
    # Roll the cutover bytes back for the standard rollback rehearsal.
    _restore(tmp_path, pre_g)
    _rehearse(tmp_path, run_g, verify_g, refuse_g)

    # ── (h) marker runtime cutover via the REAL ``runtime_cutover`` CLI ──
    # The marker is STRONG-bound after (c); the CAS runs against the strong
    # form's digest — never the weak legacy fallback.
    control_identity_path = tmp_path / "marker-cutover-runtime-identity.json"
    relaunch_file = tmp_path / "marker-relaunch-command.txt"

    def _marker_argv() -> list[str]:
        marker_bytes = marker_path.read_bytes()
        marker = json.loads(marker_bytes)
        previous_runtime_sha = marker_runtime_identity(marker)["content_sha256"]
        state = load_chain_state(spec_path, verify_execution_binding=False)
        active_runtime = state.metadata["execution_binding"]["runtime_binding"][
            "current_identity"
        ]
        control_identity_path.write_text(
            json.dumps(active_runtime, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        relaunch = (
            f"PYTHONPATH={REPO_ROOT} python -P -m arnold_pipelines.megaplan "
            f"chain start --spec {spec_path.resolve(strict=False)} # {control_revision}"
        )
        relaunch_file.write_text(relaunch + "\n", encoding="utf-8")
        return [
            "--marker", str(marker_path),
            "--manifest", str(manifest_path),
            "--expect-marker-sha256", _sha256_file(marker_path),
            "--from-runtime-sha256", previous_runtime_sha,
            "--runtime-identity", str(control_identity_path),
            "--relaunch-command-file", str(relaunch_file),
            "--reason",
            "T-0101 rehearsal: marker runtime cutover to the control runtime",
            "--actor", "operator",
            "--direction", "cutover",
            "--source-branch", BRANCH,
        ]

    def run_h():
        return _expect_ok(*_marker_cli(_marker_argv(), capsys))

    def verify_h(result):
        assert _sha256_file(marker_path) == result["marker_after_sha256"]
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        assert marker["editable_source_head"] == control_revision
        assert marker["editable_source_branch"] == BRANCH
        assert marker["editable_install_sync"]["source"] == str(REPO_ROOT)
        assert marker["operator_pause"]["active"] is True
        binding = marker["runtime_binding"]
        assert Path(binding["current_identity"]["import_root"]).resolve() == REPO_ROOT
        assert binding["current_identity"]["source_revision"] == control_revision
        assert marker["relaunch_command"].endswith(f"# {control_revision}")

    def refuse_h():
        def wrong_marker_sha():
            argv = _marker_argv()
            argv[argv.index("--expect-marker-sha256") + 1] = "0" * 64

            def attempt():
                rc, _payload = _marker_cli(argv, capsys)
                assert rc == 2

            _refuse_zero_mutation(tmp_path, attempt)

        _refuse_zero_mutation(tmp_path, wrong_marker_sha)

    # Injected failure FIRST: the atomic MARKER WRITE dies at the effect
    # boundary — every CAS guard (marker sha, runtime sha, relaunch match) has
    # passed and ``tempfile.mkstemp`` fails before any byte lands.  The marker
    # file must be byte-unchanged (no half-written marker) and the re-run
    # completes.
    marker_before_sha = _sha256_file(marker_path)
    real_tempfile = runtime_cutover_module.tempfile
    monkeypatch.setattr(runtime_cutover_module, "tempfile", _FailingTempfile())
    try:
        with pytest.raises(OSError):
            _marker_cli(_marker_argv(), capsys)
    finally:
        monkeypatch.setattr(runtime_cutover_module, "tempfile", real_tempfile)
    assert _sha256_file(marker_path) == marker_before_sha
    _rehearse(tmp_path, run_h, verify_h, refuse_h)

    # ── (i) occurrence-join via the REAL CLI: operator-only exact- ────────
    # occurrence fenced claim.
    def _join_argv_full() -> list[str]:
        return [
            "chain",
            "occurrence-join",
            "--spec", str(spec_path),
            "--project-dir", str(tmp_path),
            "--session", REPAIR_SESSION,
            "--occurrence", queue["request"]["repair_identity_key"],
            "--request", queue["request"]["request_id"],
            "--decision", queue["decision"]["decision_id"],
            "--claim", CLAIM_ID,
            "--reason", "T-0101 rehearsal: operator exact-occurrence join",
            "--actor", "operator",
            "--receipt", str(receipt_path),
        ]

    def run_i():
        return _expect_ok(*_chain_cli(tmp_path, _join_argv_full(), capsys))

    def verify_i(result):
        assert result["status"] == "claimed"
        assert result["claim_id"] == CLAIM_ID
        assert result["occurrence"] == queue["request"]["repair_identity_key"]
        assert receipt_path.exists()
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        assert receipt["relation"]["request_id"] == queue["request"]["request_id"]
        assert receipt["relation"]["decision_request_id"] == queue["request"][
            "request_id"
        ]
        lease_id = occurrence_join_lease_id(CLAIM_ID)
        lease = open_lease_store(plan_dir / "custody" / "leases").current_lease(
            lease_id
        )
        assert lease is not None and not lease.is_expired
        assert (plan_dir / PHASE_WBC_LEDGER_FILENAME).exists()
        # The join never rewrites chain/plan/queue state.
        assert json.loads(plan_path.read_text(encoding="utf-8"))[
            "current_state"
        ] == "paused"
        assert (
            load_chain_state(spec_path, verify_execution_binding=False).last_state
            == "paused"
        )

    def refuse_i():
        def wrong_occurrence():
            probe_receipt = plan_dir / "evidence" / "probe-receipt.json"
            argv = _join_argv_full()
            argv[argv.index("--occurrence") + 1] = "f" * 64
            argv[argv.index("--claim") + 1] = "wrong-occurrence-claim"
            argv[argv.index("--receipt") + 1] = str(probe_receipt)

            def attempt():
                rc, payload = _chain_cli(tmp_path, argv, capsys)
                assert rc == 1
                assert payload is not None and payload.get("success") is False
                # No receipt may be emitted and the existing claim is
                # untouched: the refusal must not mint a claim/lease for the
                # wrong occurrence.
                assert not probe_receipt.exists()
                lease_id = occurrence_join_lease_id("wrong-occurrence-claim")
                assert open_lease_store(
                    plan_dir / "custody" / "leases"
                ).current_lease(lease_id) is None
                plan = json.loads(plan_path.read_text(encoding="utf-8"))
                assert plan["current_state"] == "paused"

            _refuse_zero_mutation(tmp_path, attempt)

    _rehearse(tmp_path, run_i, verify_i, refuse_i)

    # ── (j) resume via the REAL chain CLI with the pause authority ───────
    def run_j():
        return _expect_ok(
            *_chain_cli(
                tmp_path,
                [
                    "chain",
                    "resume",
                    "--spec", str(spec_path),
                    "--project-dir", str(tmp_path),
                    "--actor", "operator",
                ],
                capsys,
            )
        )

    def verify_j(result):
        assert result["changed"] is True
        assert result["paused"] is False
        assert result["plan"] == PLAN
        assert result["restored_plan_state"] == "blocked"
        # verify=True: the full binding (bundle + runtime) must be an exact
        # match for the chain to be resumable.
        state = load_chain_state(spec_path)
        assert pause_record(state) is None
        assert state.last_state == "blocked"
        resume_authority = state.metadata["operator_resume"]
        assert resume_authority["schema_version"] == AUTHORITY_SCHEMA
        assert resume_authority["plan"] == PLAN
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        assert plan["current_state"] == "blocked"
        # Resume cursor byte-equivalent: failure + cursor fields identical to
        # the pre-pause plan payload.
        assert plan["latest_failure"] == plan_payload["latest_failure"]
        assert plan["resume_cursor"] == plan_payload["resume_cursor"]
        assert "blocked" in _RUNNER_RESUMABLE_STATES  # fresh progress possible

    def refuse_j():
        def plan_not_paused():
            plan_bytes = plan_path.read_bytes()
            payload = json.loads(plan_bytes)
            payload["current_state"] = "blocked"
            plan_path.write_text(json.dumps(payload), encoding="utf-8")
            try:
                rc, cli_payload = _chain_cli(
                    tmp_path,
                    [
                        "chain",
                        "resume",
                        "--spec", str(spec_path),
                        "--project-dir", str(tmp_path),
                        "--actor", "operator",
                    ],
                    capsys,
                )
                assert rc == 1
                assert cli_payload is not None and cli_payload.get("success") is False
            finally:
                plan_path.write_bytes(plan_bytes)

        _refuse_zero_mutation(tmp_path, plan_not_paused)

    _rehearse(tmp_path, run_j, verify_j, refuse_j, refuse_before=True)

    # ── final acceptance: the T-0101 six-way root equality + claim ────────
    state = load_chain_state(spec_path)  # verify=True (bundle + runtime)
    runtime = state.metadata["execution_binding"]["runtime_binding"][
        "current_identity"
    ]
    chain_execution_root = Path(runtime["import_root"]).resolve()
    recorded_engine_root = Path(
        state.metadata["execution_environment"]["engine_root"]
    ).resolve()
    manifest = load_manifest(manifest_path)
    manifest_root = Path(manifest.epic["runtime_root"]).resolve()
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker_root = Path(
        marker["runtime_binding"]["current_identity"]["import_root"]
    ).resolve()
    # The independent leg is a GENUINE final observation: the candidate
    # .venv interpreter (safe-path) resolves the real import root — never a
    # re-read of self-written JSON.
    independent = subprocess.run(
        [
            str(offline_rollback_runtime["python_observer"]), "-P", "-c",
            "import pathlib, arnold_pipelines; "
            "print(pathlib.Path(arnold_pipelines.__file__).resolve().parents[1])",
        ],
        check=True,
        capture_output=True,
        text=True,
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
    )
    independent_root = Path(independent.stdout.strip()).resolve()
    assert independent_root == REPO_ROOT, independent.stdout
    assert (
        chain_execution_root
        == recorded_engine_root
        == manifest_root
        == marker_root
        == independent_root
        == REPO_ROOT
    ), "all six T-0101 roots must be equal and point at the new runtime"
    # The repair executable is runtime-root-bound; the dependency venv is an
    # immutable content-addressed generation, deliberately stored beside the
    # candidate runtime rather than inside its source tree.
    manifest_venv = Path(manifest.epic["venv_path"]).resolve()
    manifest_repair = Path(manifest.epic["repair_bin"]).resolve()
    assert manifest_venv.is_dir()
    assert manifest_repair.is_file() and os.access(manifest_repair, os.X_OK)
    assert manifest_venv == to_venv_path.resolve()
    assert manifest_venv.name == str(control_generation["frozen_spec_sha256"])
    assert manifest_repair.is_relative_to(REPO_ROOT)
    lease = open_lease_store(plan_dir / "custody" / "leases").current_lease(
        occurrence_join_lease_id(CLAIM_ID)
    )
    assert lease is not None and not lease.is_expired
    assert (plan_dir / PHASE_WBC_LEDGER_FILENAME).exists()
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    assert plan["current_state"] == "blocked"
    assert plan["latest_failure"] == plan_payload["latest_failure"]
    assert plan["resume_cursor"] == plan_payload["resume_cursor"]
    assert state.current_milestone_index == 0
    assert state.current_plan_name == PLAN


# ── failure-injection rehearsals at the occurrence-join effect boundaries ──

def test_canary_rehearsal_cli_claim_write_failure_injection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Injected failure: the WBC CLAIM commit dies after the lease was acquired.

    ``join_exact_occurrence`` acquires the custody lease, then commits the WBC
    claim attempt; injecting a failure into ``SqliteAttemptLedgerStore.
    append_started`` (the claim write, after the lease effect) must leave NO
    stranded claim — the just-acquired lease is rolled back (terminal release),
    no receipt exists — and re-running the SAME ``chain occurrence-join`` CLI
    command must complete the join.
    """
    state = _minimal_join_state(tmp_path)
    receipt_path = state["plan_dir"] / "evidence" / "occurrence-join-receipt.json"
    lease_store = open_lease_store(state["plan_dir"] / "custody" / "leases")

    real_append_started = SqliteAttemptLedgerStore.append_started

    def boom_append_started(self, *_args, **_kwargs):
        raise AttemptLedgerError("injected WBC claim commit failure")

    monkeypatch.setattr(SqliteAttemptLedgerStore, "append_started", boom_append_started)
    try:
        rc, payload = _chain_cli(
            tmp_path, _join_argv(tmp_path, state, receipt_path), capsys
        )
    finally:
        monkeypatch.setattr(
            SqliteAttemptLedgerStore, "append_started", real_append_started
        )

    assert rc == 1
    assert payload is not None and payload.get("error") == "claim_denied"
    # The just-acquired lease was rolled back: the last lifecycle event is a
    # terminal release (NOT merely is_expired — the terminal expiry is only
    # advanced 1s and can read False inside that window).
    history = lease_store.load_history(occurrence_join_lease_id(CLAIM_ID))
    assert history and history[-1].event_type == "release"
    # No receipt and no stranded claim (the WBC attempt has no STARTED event).
    assert not receipt_path.exists()
    wbc = SqliteAttemptLedgerStore(state["plan_dir"] / PHASE_WBC_LEDGER_FILENAME)
    attempt_id = occurrence_claim_attempt_id(state["plan_dir"], CLAIM_ID)
    assert wbc.read_events(attempt_id) == []
    assert wbc.has_terminal_event(attempt_id) is False

    # Re-running the SAME CLI command completes the join.
    rc, payload = _chain_cli(
        tmp_path, _join_argv(tmp_path, state, receipt_path), capsys
    )
    assert rc == 0
    assert payload is not None and payload["status"] == "claimed"
    assert receipt_path.exists()


def test_canary_rehearsal_cli_receipt_write_failure_injection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Injected failure: the RECEIPT emit dies after the claim + lease effects.

    The durable receipt is written last; a failure there on a FIRST claim
    (``os.replace`` raising OSError) must leave the occurrence recoverable:
    the lease is rolled back (terminal release), the WBC STARTED attempt is
    retained as the re-join anchor, and NO receipt file exists.  Re-running
    the SAME ``chain occurrence-join`` CLI command must regenerate the receipt
    (``already_claimed``) — the T-0101h round-2 cross-process-safe re-join.
    """
    state = _minimal_join_state(tmp_path)
    receipt_path = state["plan_dir"] / "evidence" / "occurrence-join-receipt.json"
    lease_store = open_lease_store(state["plan_dir"] / "custody" / "leases")

    real_replace = os.replace
    resolved_receipt = str(receipt_path.resolve())

    def boom_replace(src, dst, *_args, **_kwargs):
        if str(dst) == resolved_receipt:
            raise OSError("injected receipt write failure")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", boom_replace)
    try:
        rc, payload = _chain_cli(
            tmp_path, _join_argv(tmp_path, state, receipt_path), capsys
        )
    finally:
        monkeypatch.setattr(os, "replace", real_replace)

    assert rc == 1
    assert payload is not None and payload.get("error") == "receipt_write_failed"
    # First-claim rollback: the lease was released (terminal), no receipt file.
    history = lease_store.load_history(occurrence_join_lease_id(CLAIM_ID))
    assert history and history[-1].event_type == "release"
    assert not receipt_path.exists()
    # The WBC STARTED claim is retained as the re-join anchor (no terminal).
    wbc = SqliteAttemptLedgerStore(state["plan_dir"] / PHASE_WBC_LEDGER_FILENAME)
    attempt_id = occurrence_claim_attempt_id(state["plan_dir"], CLAIM_ID)
    started = wbc.read_events(attempt_id)
    assert len(started) == 1
    assert wbc.has_terminal_event(attempt_id) is False

    # Re-running the SAME CLI command regenerates the receipt.
    rc, payload = _chain_cli(
        tmp_path, _join_argv(tmp_path, state, receipt_path), capsys
    )
    assert rc == 0
    assert payload is not None and payload["status"] == "already_claimed"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["claim_id"] == CLAIM_ID
    assert receipt["relation"]["request_id"] == state["queue"]["request"][
        "request_id"
    ]
    assert receipt["relation"]["decision_request_id"] == state["queue"]["request"][
        "request_id"
    ]


# ── T-0101e' — identity-less copied-state adoption sequence ────────────────

def _rehearsal_adopt_argv(
    spec_path: Path,
    tmp_path: Path,
    *,
    plan_path: Path,
    plan_payload: dict,
    marker_path: Path,
    manifest_path: Path,
    control_identity: Path,
    control_receipt: Path,
    roots: dict,
    actor: str = "operator",
    receipt_name: str = "occurrence-adopt-receipt.json",
    failure_recorded_at: str = "2026-08-11T07:35:34Z",
) -> list[str]:
    """argv for ``megaplan chain occurrence-adopt`` against the rehearsed tree.

    Every expected sha is computed from a fresh reread with the SAME
    canonicalization the command uses, so the guard pass is byte-exact.
    """
    state = load_chain_state(spec_path, verify_execution_binding=False)
    pause = state.metadata.get("operator_pause")
    pause_sha = (
        "sha256:" + _canonical_sha256(pause)
        if pause is not None
        else "sha256:" + "0" * 64
    )
    plan_dir = tmp_path / ".megaplan" / "plans" / PLAN
    latest_failure = plan_payload["latest_failure"]
    resume_cursor = plan_payload["resume_cursor"]
    if failure_recorded_at != plan_payload["latest_failure"]["recorded_at"]:
        latest_failure = dict(latest_failure)
        latest_failure["recorded_at"] = failure_recorded_at
    return [
        "chain",
        "occurrence-adopt",
        "--spec", str(spec_path),
        "--project-dir", str(tmp_path),
        "--session", SESSION,
        "--expected-current-plan", PLAN,
        "--expected-phase", "gate",
        "--expected-failure-kind", "deterministic_phase_failure",
        "--expected-failure-code", "blocked_no_lease",
        "--expected-failure-recorded-at", failure_recorded_at,
        "--expected-resume-phase", "gate",
        "--expected-retry-strategy", "repair_phase_contract",
        "--expected-chain-state-sha256", "sha256:" + _sha256_file(
            chain_spec._state_path_for(spec_path)
        ),
        "--expected-plan-state-sha256", "sha256:" + _sha256_file(plan_path),
        "--expected-latest-failure-sha256", "sha256:" + _canonical_sha256(latest_failure),
        "--expected-resume-cursor-sha256", "sha256:" + _canonical_sha256(resume_cursor),
        "--expected-pause-authority-sha256", pause_sha,
        "--runtime-manifest", str(manifest_path),
        "--expected-runtime-manifest-sha256", "sha256:" + _sha256_file(manifest_path),
        "--marker", str(marker_path),
        "--expected-marker-sha256", "sha256:" + _sha256_file(marker_path),
        "--runtime-identity", str(control_identity),
        "--runtime-provenance-receipt", str(control_receipt),
        "--candidate-root", roots["candidate_root"],
        "--expected-runtime-roots-sha256", "sha256:" + _canonical_sha256(roots),
        "--reason", "T-0101 rehearsal: adopt the identity-less blocked occurrence",
        "--actor", actor,
        "--receipt", str(tmp_path / ".megaplan" / "plans" / PLAN / "evidence" / receipt_name),
    ]


def _copy_rehearsal_tree(
    src: Path, dst: Path, src_spec_path: Path
) -> Path:
    """Copy the rehearsed tree and rematerialize its chain state.

    The chain-state storage path is derived from the spec path, so the copy
    needs its own state file (the spec-path-keyed bytes are re-saved from the
    source state for the copy's spec path).
    """
    # The live rehearsal writes the source tree's incident-ledger journal as
    # part of normal chain control.  It is bound to the source chain/ledger
    # identity and cannot be replayed from a copied checkout; carrying it
    # into a probe makes the real ``save_chain_state`` gate reject the copy
    # with a ledger-id mismatch.  Probes intentionally exercise copied chain
    # state, not a cloned writer journal.
    shutil.copytree(
        src,
        dst,
        symlinks=True,
        ignore=shutil.ignore_patterns("incident-ledger", "repair-queue"),
    )
    new_spec = dst / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    state = load_chain_state(src_spec_path, verify_execution_binding=False)
    save_chain_state(new_spec, state)
    return new_spec


def test_canary_rehearsal_identityless_adoption_sequence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    offline_rollback_runtime: dict[str, Path | str],
) -> None:
    """Copied-state case that begins with repair_identity = null.

    Runs the full T-0101 sequence on identity-less state:

        pause → prior T-0101 cutovers → occurrence-adopt → enqueue/accept
        → occurrence-join → resume

    and exercises every T-0101e' property: three identical runs produce the
    same key/request/decision; one-bit changes to EVERY CAS digest refuse
    with zero mutation; different plan/timestamp/cursor/roots produce a
    different key; non-operator / missing pause / non-null existing identity
    / ambiguous failure / unequal roots refuse; crash injection after the
    adoption-authority / request writes converges on retry; two concurrent
    adopters yield one record/request/accepted decision; superseding the
    accepted decision blocks join; the join produces one real current
    lease/epoch with request→decision→claim→attempt equality; resume
    preserves the gate cursor byte-for-byte with fresh typed progress.
    """
    # ── copied state: progressed, blocked, UNBOUND chain, NO repair identity ─
    spec_path = _pin_legacy_chain(tmp_path)
    _git(tmp_path, "checkout", "-b", BRANCH)
    chain_state = ChainState()
    chain_state.current_milestone_index = 0
    chain_state.current_plan_name = PLAN
    chain_state.last_state = "blocked"
    chain_state.chain_session = SESSION
    chain_state.completed = []
    save_chain_state(spec_path, chain_state)  # metadata stays unbound/unpaused

    # The plan state is IDENTITY-LESS: no meta.repair_identity and no
    # latest_failure.metadata.repair_identity (the synthetic v1 seeding is
    # removed).  No repair request is enqueued at setup — the adoption
    # command creates request + accepted decision itself.
    plan_payload = _plan_payload(failure_recorded_at="2026-08-11T07:35:34Z")
    plan_path = _write_plan_state(tmp_path, plan_payload)

    real_old_identity = json.loads(
        Path(offline_rollback_runtime["identity"]).read_text(encoding="utf-8")
    )
    real_old_identity_path = Path(offline_rollback_runtime["identity"])
    real_old_receipt_path = Path(offline_rollback_runtime["receipt"])
    old_identity = _masked_legacy_identity(real_old_identity, LEGACY_CANDIDATE)
    old_root = Path(old_identity["import_root"]).resolve()
    old_revision = str(old_identity["source_revision"])
    masked_identity_path = (
        tmp_path / "migration-evidence" / "runtime-identity-masked.json"
    )
    masked_identity_path.parent.mkdir(parents=True, exist_ok=True)
    masked_identity_path.write_text(
        json.dumps(old_identity, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    marker_path = _write_cloud_marker(tmp_path, spec_path, old_root=old_root)
    manifest_path = _write_runtime_manifest(
        tmp_path / "runtime-manifest.json",
        epic_id="demo",
        runtime_root=old_root,
        expected_head=old_revision,
    )
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(manifest_path))
    assert_quiesce_precondition(tmp_path)
    control = _emit_control_runtime_receipt(offline_rollback_runtime)
    control_revision = str(control["revision"])
    assert control_revision == _git(REPO_ROOT, "rev-parse", "HEAD")
    plan_dir = tmp_path / ".megaplan" / "plans" / PLAN
    join_receipt_path = plan_dir / "evidence" / "occurrence-join-receipt.json"
    rollback_receipt_path = tmp_path / "manifest-cutover-rollback.json"

    # ── (a) pause via the REAL chain CLI ──────────────────────────────────
    def _pause_argv() -> list[str]:
        return [
            "chain",
            "pause",
            "--spec", str(spec_path),
            "--project-dir", str(tmp_path),
            "--reason", "T-0101e' rehearsal: pause the identity-less chain",
            "--actor", "operator",
        ]

    rc, payload = _chain_cli(tmp_path, _pause_argv(), capsys)
    assert rc == 0 and payload is not None and payload["paused"] is True, payload
    state = load_chain_state(spec_path, verify_execution_binding=False)
    assert pause_record(state) is not None and state.last_state == "paused"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    assert plan["current_state"] == "paused"
    assert plan["latest_failure"] == plan_payload["latest_failure"]
    assert plan["resume_cursor"] == plan_payload["resume_cursor"]

    # ── (b) execution-binding-migrate via the REAL CLI (old runtime) ──────
    execution_binding_module = sys.modules[
        "arnold_pipelines.megaplan.chain.execution_binding"
    ]
    real_migrate_verifier = execution_binding_module.verify_external_runtime_identity

    def _migrate_verifier(_identity_path: Path, _receipt_path: Path) -> dict:
        real_verified = verify_external_runtime_identity(
            real_old_identity_path, real_old_receipt_path
        )
        assert real_verified["import_root"] == real_old_identity["import_root"]
        return dict(old_identity)

    monkeypatch.setattr(
        execution_binding_module,
        "verify_external_runtime_identity",
        _migrate_verifier,
    )
    try:
        rc, payload = _chain_cli(
            tmp_path,
            [
                "chain",
                "execution-binding-migrate",
                "--spec", str(spec_path),
                "--project-dir", str(tmp_path),
                "--old-runtime-identity", str(masked_identity_path),
                "--old-runtime-provenance-receipt", str(real_old_receipt_path),
                "--expected-current-milestone", "c1",
                "--expected-current-plan", PLAN,
                "--expected-branch", BRANCH,
                "--expect-marker-sha256", _sha256_file(marker_path),
                "--reason", "T-0101e' rehearsal: bind legacy runtime",
                "--actor", "operator",
            ],
            capsys,
        )
    finally:
        execution_binding_module.verify_external_runtime_identity = (
            real_migrate_verifier
        )
    assert rc == 0 and payload is not None and payload["success"] is not False, payload
    assert payload["old_runtime_root"] == str(old_root)
    state = load_chain_state(spec_path, verify_execution_binding=False)
    assert pause_record(state) is not None

    # ── (c) legacy_marker_runtime_migration via its REAL module CLI ───────
    candidate_dir = tmp_path / "workspace" / "runtime-candidates" / "arnold-canary-legacy"
    (candidate_dir / ".venv").mkdir(parents=True, exist_ok=True)
    wrapper = candidate_dir / "arnold-babysitter"
    wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    wrapper.chmod(0o755)
    fixture = _migration_fixture(
        tmp_path,
        spec_path=spec_path,
        old_identity=old_identity,
        candidate_root=LEGACY_CANDIDATE,
        workspace=str(tmp_path),
        marker_path=marker_path,
    )
    masked_identity = fixture["masked_identity"]
    real_offline_identity_path = Path(offline_rollback_runtime["identity"])
    real_offline_receipt_path = Path(offline_rollback_runtime["receipt"])

    def _migration_verifier(_identity_path: Path, _receipt_path: Path) -> dict:
        real_verified = verify_external_runtime_identity(
            real_offline_identity_path, real_offline_receipt_path
        )
        assert real_verified["import_root"] == real_old_identity["import_root"]
        return dict(masked_identity)

    real_migration_verifier = legacy_marker_module.verify_external_runtime_identity
    monkeypatch.setattr(
        legacy_marker_module, "verify_external_runtime_identity", _migration_verifier
    )
    try:
        rc, payload = _migration_cli(
            _migration_argv(fixture, tmp_path=tmp_path, spec_path=spec_path), capsys
        )
    finally:
        legacy_marker_module.verify_external_runtime_identity = (
            real_migration_verifier
        )
    assert rc == 0, payload
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    assert marker["runtime_binding"]["current_identity"]["import_root"] == LEGACY_CANDIDATE
    assert marker["operator_pause"]["active"] is True

    # ── (d) install the full required-binding bundle (P/F) ────────────────
    decision = _write_final_decision_asset(tmp_path)
    assert decision.is_file()
    snapshot, final = _commit_binding_bundle(
        spec_path, tmp_path, assets=[ASSET_REL]
    )
    assert _git(tmp_path, "rev-parse", "HEAD") == final
    _verify_clean_checkout_of_f(tmp_path, snapshot, final)

    # ── (e) chain rebind via the REAL CLI ─────────────────────────────────
    state = load_chain_state(spec_path, verify_execution_binding=False)
    previous = state.metadata["execution_binding"]["launched_identity"]["bundle_sha256"]
    active = active_execution_identity(spec_path)
    rc, payload = _chain_cli(
        tmp_path,
        [
            "chain",
            "rebind",
            "--spec", str(spec_path),
            "--from-bundle-sha256", previous,
            "--to-bundle-sha256", active["bundle_sha256"],
            "--expected-current-milestone", "c1",
            "--expected-current-plan", PLAN,
            "--expected-next-milestone", "c2",
            "--reason", "T-0101e' rehearsal: adopt the required-binding bundle",
            "--actor", "operator",
        ],
        capsys,
    )
    assert rc == 0 and payload is not None and payload["success"] is not False, payload
    state = load_chain_state(spec_path, verify_execution_binding=False)
    assert state.metadata["chain_spec_sha256"] == _sha256_file(spec_path)
    assert pause_record(state) is not None

    # ── (f) chain runtime-cutover via the REAL CLI (old → control) ────────
    state = load_chain_state(spec_path, verify_execution_binding=False)
    previous_sha = state.metadata["execution_binding"]["runtime_binding"][
        "current_identity"
    ]["content_sha256"]
    report = execution_binding_report(spec_path, state)
    active_sha = report["runtime_binding"]["active"]["content_sha256"]
    rc, payload = _chain_cli(
        tmp_path,
        [
            "chain",
            "runtime-cutover",
            "--spec", str(spec_path),
            "--project-dir", str(tmp_path),
            "--from-runtime-sha256", previous_sha,
            "--to-runtime-sha256", active_sha,
            "--expected-current-milestone", "c1",
            "--expected-current-plan", PLAN,
            "--direction", "cutover",
            "--reason", "T-0101e' rehearsal: chain runtime cutover to control",
            "--actor", "operator",
        ],
        capsys,
    )
    assert rc == 0 and payload is not None and payload["success"] is not False, payload
    state = load_chain_state(spec_path, verify_execution_binding=False)
    assert state.metadata["execution_environment"]["engine_root"] == str(REPO_ROOT)
    assert pause_record(state) is not None

    # ── (g) runtime_manifest CAS cutover via the REAL CLI ─────────────────
    control_generation, to_venv_path = _build_control_dependency_generation(
        offline_rollback_runtime
    )
    # The pytest interpreter may belong to another checkout.  Use the
    # separate candidate-bound observer environment for the production
    # observer.  It is distinct from the offline receipt interpreter, so the
    # production identity verifier still proves independence.
    from arnold_pipelines.megaplan.chain import (
        occurrence_adopt as occurrence_adopt_module,
    )
    candidate_python = Path(offline_rollback_runtime["python_observer"]).resolve()
    host_python = occurrence_adopt_module.sys.executable
    monkeypatch.setattr(
        occurrence_adopt_module.sys, "executable", str(candidate_python)
    )
    assert (
        Path(occurrence_adopt_module._independent_import_root()).resolve()
        == REPO_ROOT
    )
    # Restore the host executable for the manifest's independent runtime
    # verifier; rebind it only around the later occurrence-adopt dispatch.
    monkeypatch.setattr(occurrence_adopt_module.sys, "executable", host_python)
    to_repair_bin = (
        REPO_ROOT / "arnold_pipelines" / "megaplan" / "cloud" / "wrappers"
    ) / "arnold-babysitter"
    assert to_venv_path.is_dir()
    assert to_repair_bin.is_file() and os.access(to_repair_bin, os.X_OK)
    manifest = load_manifest(manifest_path)
    rc, payload = _manifest_cli(
        [
            "cutover",
            str(manifest_path),
            "--expect-manifest-sha256", _sha256_file(manifest_path),
            "--expect-generation", str(manifest.generation),
            "--from-runtime-root", str(old_root),
            "--from-expected-head", old_revision,
            "--to-runtime-root", str(REPO_ROOT),
            "--to-expected-head", control_revision,
            "--to-venv-path", str(to_venv_path),
            "--to-repair-bin", str(to_repair_bin),
            "--runtime-identity", str(control["identity"]),
            "--runtime-provenance-receipt", str(control["receipt"]),
            "--reason", "T-0101e' rehearsal: manifest cutover to control",
            "--actor", "operator",
            "--receipt-out", str(rollback_receipt_path),
            "--to-dependency-generation",
            json.dumps(control_generation, sort_keys=True),
        ],
        capsys,
    )
    assert rc == 0, payload
    assert load_manifest(manifest_path).epic["runtime_root"] == str(REPO_ROOT)

    # ── (h) marker runtime cutover via the REAL CLI ───────────────────────
    control_identity_path = tmp_path / "marker-cutover-runtime-identity.json"
    relaunch_file = tmp_path / "marker-relaunch-command.txt"
    marker_bytes = marker_path.read_bytes()
    marker = json.loads(marker_bytes)
    previous_runtime_sha = marker_runtime_identity(marker)["content_sha256"]
    state = load_chain_state(spec_path, verify_execution_binding=False)
    active_runtime = state.metadata["execution_binding"]["runtime_binding"][
        "current_identity"
    ]
    control_identity_path.write_text(
        json.dumps(active_runtime, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    relaunch = (
        f"PYTHONPATH={REPO_ROOT} python -P -m arnold_pipelines.megaplan "
        f"chain start --spec {spec_path.resolve(strict=False)} # {control_revision}"
    )
    relaunch_file.write_text(relaunch + "\n", encoding="utf-8")
    rc, payload = _marker_cli(
        [
            "--marker", str(marker_path),
            "--manifest", str(manifest_path),
            "--expect-marker-sha256", _sha256_file(marker_path),
            "--from-runtime-sha256", previous_runtime_sha,
            "--runtime-identity", str(control_identity_path),
            "--relaunch-command-file", str(relaunch_file),
            "--reason", "T-0101e' rehearsal: marker cutover to control",
            "--actor", "operator",
            "--direction", "cutover",
            "--source-branch", BRANCH,
        ],
        capsys,
    )
    assert rc == 0, payload
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    assert marker["runtime_binding"]["current_identity"]["import_root"] == str(REPO_ROOT)

    # ── six-way runtime roots (all equal at the control runtime) ──────────
    state = load_chain_state(spec_path, verify_execution_binding=False)
    runtime = state.metadata["execution_binding"]["runtime_binding"]["current_identity"]
    chain_execution_root = str(Path(runtime["import_root"]).resolve())
    recorded_engine_root = str(
        Path(state.metadata["execution_environment"]["engine_root"]).resolve()
    )
    manifest_root = str(Path(load_manifest(manifest_path).epic["runtime_root"]).resolve())
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker_root = str(
        Path(marker["runtime_binding"]["current_identity"]["import_root"]).resolve()
    )
    independent = subprocess.run(
        [
            str(candidate_python), "-P", "-c",
            "import pathlib, arnold_pipelines; "
            "print(pathlib.Path(arnold_pipelines.__file__).resolve().parents[1])",
        ],
        check=True,
        capture_output=True,
        text=True,
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
    )
    independent_root = Path(independent.stdout.strip()).resolve()
    assert independent_root == REPO_ROOT, independent.stdout
    roots = {
        "chain_execution_root": chain_execution_root,
        "recorded_engine_root": recorded_engine_root,
        "manifest_runtime_root": manifest_root,
        "marker_runtime_root": marker_root,
        "independent_import_root": str(independent_root),
        "candidate_root": str(REPO_ROOT),
    }
    assert len({Path(value).resolve() for value in roots.values()}) == 1
    assert Path(chain_execution_root).resolve() == REPO_ROOT

    monkeypatch.setattr(
        occurrence_adopt_module.sys, "executable", str(candidate_python)
    )
    adopt_argv = _rehearsal_adopt_argv(
        spec_path,
        tmp_path,
        plan_path=plan_path,
        plan_payload=plan_payload,
        marker_path=marker_path,
        manifest_path=manifest_path,
        control_identity=Path(control["identity"]),
        control_receipt=Path(control["receipt"]),
        roots=roots,
    )

    # ── occurrence-adopt: crash injection first (fresh pre-adopt state) ───
    pre_adopt = _snapshot(tmp_path)
    real_enqueue = repair_requests.enqueue_owner_adopted_repair_request
    real_write_decision = repair_requests.write_decision

    def _crash_after_adoption_record():
        def boom_wrapper(*_args, **_kwargs):
            raise OSError("injected crash before enqueue")

        monkeypatch.setattr(
            repair_requests, "enqueue_owner_adopted_repair_request", boom_wrapper
        )
        try:
            with pytest.raises(OSError):
                _chain_cli(tmp_path, adopt_argv, capsys)
        finally:
            monkeypatch.setattr(
                repair_requests, "enqueue_owner_adopted_repair_request", real_enqueue
            )
        adoptions = list((plan_dir / "evidence" / "occurrence-adoptions").glob("*.json"))
        assert len(adoptions) == 1, "adoption record must persist before enqueue"
        rc, payload = _chain_cli(tmp_path, adopt_argv, capsys)
        assert rc == 0 and payload is not None and payload["status"] == "adopted", payload
        queue = tmp_path / ".megaplan" / "repair-queue"
        assert len(repair_requests.iter_repair_requests(queue)) == 1
        assert len(
            [
                record
                for record in repair_requests.iter_repair_decisions(queue)
                if record["decision"] == "accepted"
            ]
        ) == 1
        return payload

    def _crash_after_request_write():
        def boom_decision(*_args, **kwargs):
            if kwargs.get("decision") == "accepted":
                raise OSError("injected crash before accepted decision")
            return real_write_decision(*_args, **kwargs)

        monkeypatch.setattr(repair_requests, "write_decision", boom_decision)
        try:
            with pytest.raises(OSError):
                _chain_cli(tmp_path, adopt_argv, capsys)
        finally:
            monkeypatch.setattr(repair_requests, "write_decision", real_write_decision)
        queue = tmp_path / ".megaplan" / "repair-queue"
        assert len(repair_requests.iter_repair_requests(queue)) == 1
        assert repair_requests.iter_repair_decisions(queue) == []
        rc, payload = _chain_cli(tmp_path, adopt_argv, capsys)
        assert rc == 0 and payload is not None and payload["status"] == "adopted", payload
        assert len(repair_requests.iter_repair_requests(queue)) == 1
        accepted = [
            record
            for record in repair_requests.iter_repair_decisions(queue)
            if record["decision"] == "accepted"
        ]
        assert len(accepted) == 1
        return payload

    _restore(tmp_path, pre_adopt)
    crash_payload = _crash_after_adoption_record()
    _restore(tmp_path, pre_adopt)
    crash_payload_2 = _crash_after_request_write()
    # The adopted occurrence identity and the deterministic request are the
    # same across BOTH crash scenarios (the accepted decision's id embeds its
    # second-resolution created_at, so two separately-crashed scenarios may
    # record it at different wall-clock seconds — each converges to exactly
    # one accepted decision for the SAME request).
    assert crash_payload["repair_identity_key"] == crash_payload_2["repair_identity_key"]
    assert crash_payload["request_id"] == crash_payload_2["request_id"]
    assert crash_payload["claim_id"] == crash_payload_2["claim_id"]
    _restore(tmp_path, pre_adopt)

    # ── two concurrent adopters → one record/request/accepted decision ────
    outcomes: list[tuple[int, dict | None]] = []
    errors: list[BaseException] = []

    def adopter() -> None:
        try:
            rc, payload = _chain_cli(tmp_path, adopt_argv, capsys)
            outcomes.append((rc, payload))
        except BaseException as exc:  # noqa: BLE001 - captured for assertion
            errors.append(exc)

    threads = [threading.Thread(target=adopter), threading.Thread(target=adopter)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == [], errors
    assert [rc for rc, _ in outcomes] == [0, 0], outcomes
    first, second = outcomes[0][1], outcomes[1][1]
    assert first["repair_identity_key"] == second["repair_identity_key"]
    assert first["request_id"] == second["request_id"]
    assert first["decision_id"] == second["decision_id"]
    assert first["claim_id"] == second["claim_id"]
    queue = tmp_path / ".megaplan" / "repair-queue"
    assert len(repair_requests.iter_repair_requests(queue)) == 1
    assert len(
        [
            record
            for record in repair_requests.iter_repair_decisions(queue)
            if record["decision"] == "accepted"
        ]
    ) == 1
    adoptions = list((plan_dir / "evidence" / "occurrence-adoptions").glob("*.json"))
    assert len(adoptions) == 1
    canonical_key = first["repair_identity_key"]
    canonical_request = first["request_id"]
    canonical_decision = first["decision_id"]
    canonical_claim = first["claim_id"]

    # ── three identical runs (the two concurrent + one more) → same ids ───
    rc, payload = _chain_cli(tmp_path, adopt_argv, capsys)
    assert rc == 0 and payload is not None and payload["status"] == "adopted", payload
    assert payload["repair_identity_key"] == canonical_key
    assert payload["request_id"] == canonical_request
    assert payload["decision_id"] == canonical_decision
    assert payload["claim_id"] == canonical_claim
    assert len(repair_requests.iter_repair_requests(queue)) == 1
    assert len(
        [
            record
            for record in repair_requests.iter_repair_decisions(queue)
            if record["decision"] == "accepted"
        ]
    ) == 1
    assert len(list((plan_dir / "evidence" / "occurrence-adoptions").glob("*.json"))) == 1

    # ── one-bit changes to EVERY CAS digest refuse with zero mutation ─────
    pre = _snapshot_excluding_sqlite(tmp_path)
    for flag in (
        "--expected-chain-state-sha256",
        "--expected-plan-state-sha256",
        "--expected-latest-failure-sha256",
        "--expected-resume-cursor-sha256",
        "--expected-pause-authority-sha256",
        "--expected-runtime-manifest-sha256",
        "--expected-marker-sha256",
        "--expected-runtime-roots-sha256",
    ):
        argv = list(adopt_argv)
        index = argv.index(flag) + 1
        value = argv[index]
        flipped = "sha256:" + ("0" if value[7] != "0" else "1") + value[8:]
        argv[index] = flipped
        rc, payload = _chain_cli(tmp_path, argv, capsys)
        assert rc == 1, (flag, rc, payload)
        assert payload is not None and payload["success"] is False, (flag, payload)
        assert payload["error"] == "cas_mismatch", (flag, payload)
        assert _snapshot_excluding_sqlite(tmp_path) == pre, (
            f"{flag} refusal must be zero-mutation"
        )

    # ── non-operator and unequal-roots refusals (argv-only, zero mutation) ─
    argv = list(adopt_argv)
    argv[argv.index("--actor") + 1] = "not-operator"
    rc, payload = _chain_cli(tmp_path, argv, capsys)
    assert rc == 1 and payload is not None and payload["error"] == "actor_forbidden"
    assert _snapshot_excluding_sqlite(tmp_path) == pre
    argv = list(adopt_argv)
    argv[argv.index("--candidate-root") + 1] = "/elsewhere/root"
    rc, payload = _chain_cli(tmp_path, argv, capsys)
    assert rc == 1 and payload is not None and payload["error"] == "runtime_roots_unequal"
    assert _snapshot_excluding_sqlite(tmp_path) == pre

    # ── throwaway copies: missing pause / non-null identity / ambiguous
    #    failure refuse, and a different failure timestamp yields a DIFFERENT
    #    key (plan/timestamp/cursor/roots sensitivity) ─────────────────────
    copy_root = tmp_path / "adopt-probes"
    copy_root.mkdir(parents=True, exist_ok=True)
    canonical_queue_root = os.environ.get("ARNOLD_REPAIR_QUEUE_ROOT")
    assert canonical_queue_root
    # Probe copies are independent occurrences.  Keep their external,
    # box-central queue separate so a deliberately different timestamp does
    # not create a second request in the canonical occurrence's queue.
    monkeypatch.setenv(
        "ARNOLD_REPAIR_QUEUE_ROOT", str(copy_root / ".megaplan" / "repair-queue")
    )
    # Snapshot the rehearsed tree ONCE (before any probe copy exists, so the
    # copies cannot nest into themselves); every probe copies from this base.
    probe_base = tmp_path / "probe-base"
    probe_base_spec = _copy_rehearsal_tree(tmp_path, probe_base, spec_path)

    probe_root = copy_root / "missing-pause"
    probe_spec = _copy_rehearsal_tree(probe_base, probe_root, probe_base_spec)
    probe_state = load_chain_state(probe_spec, verify_execution_binding=False)
    probe_state.metadata.pop("operator_pause", None)
    save_chain_state(probe_spec, probe_state)
    probe_argv = _rehearsal_adopt_argv(
        probe_spec,
        probe_root,
        plan_path=probe_root / ".megaplan" / "plans" / PLAN / "state.json",
        plan_payload=plan_payload,
        marker_path=probe_root / ".megaplan" / "cloud-sessions" / f"{SESSION}.json",
        manifest_path=probe_root / "runtime-manifest.json",
        control_identity=Path(control["identity"]),
        control_receipt=Path(control["receipt"]),
        roots=roots,
    )
    rc, payload = _chain_cli(probe_root, probe_argv, capsys)
    assert rc == 1 and payload is not None and payload["error"] == "chain_not_paused", payload

    probe_root = copy_root / "non-null-identity"
    probe_spec = _copy_rehearsal_tree(probe_base, probe_root, probe_base_spec)
    probe_plan_path = probe_root / ".megaplan" / "plans" / PLAN / "state.json"
    probe_plan = json.loads(probe_plan_path.read_text(encoding="utf-8"))
    probe_plan["meta"]["repair_identity"] = _repair_identity()
    probe_plan_path.write_text(json.dumps(probe_plan, indent=2) + "\n", encoding="utf-8")
    probe_argv = _rehearsal_adopt_argv(
        probe_spec,
        probe_root,
        plan_path=probe_plan_path,
        plan_payload=plan_payload,
        marker_path=probe_root / ".megaplan" / "cloud-sessions" / f"{SESSION}.json",
        manifest_path=probe_root / "runtime-manifest.json",
        control_identity=Path(control["identity"]),
        control_receipt=Path(control["receipt"]),
        roots=roots,
    )
    rc, payload = _chain_cli(probe_root, probe_argv, capsys)
    assert rc == 1 and payload is not None, payload
    assert payload["error"] == "repair_identity_already_present", payload

    probe_root = copy_root / "ambiguous-failure"
    probe_spec = _copy_rehearsal_tree(probe_base, probe_root, probe_base_spec)
    probe_plan_path = probe_root / ".megaplan" / "plans" / PLAN / "state.json"
    probe_plan = json.loads(probe_plan_path.read_text(encoding="utf-8"))
    probe_plan["latest_failure"] = [probe_plan["latest_failure"]]
    probe_plan_path.write_text(json.dumps(probe_plan, indent=2) + "\n", encoding="utf-8")
    probe_argv = _rehearsal_adopt_argv(
        probe_spec,
        probe_root,
        plan_path=probe_plan_path,
        plan_payload=plan_payload,
        marker_path=probe_root / ".megaplan" / "cloud-sessions" / f"{SESSION}.json",
        manifest_path=probe_root / "runtime-manifest.json",
        control_identity=Path(control["identity"]),
        control_receipt=Path(control["receipt"]),
        roots=roots,
    )
    rc, payload = _chain_cli(probe_root, probe_argv, capsys)
    assert rc == 1 and payload is not None and payload["error"] == "ambiguous_failure", payload

    probe_root = copy_root / "different-timestamp"
    probe_spec = _copy_rehearsal_tree(probe_base, probe_root, probe_base_spec)
    probe_plan_path = probe_root / ".megaplan" / "plans" / PLAN / "state.json"
    probe_plan = json.loads(probe_plan_path.read_text(encoding="utf-8"))
    probe_plan["latest_failure"]["recorded_at"] = "2026-08-11T08:00:00Z"
    probe_plan_path.write_text(json.dumps(probe_plan, indent=2) + "\n", encoding="utf-8")
    probe_argv = _rehearsal_adopt_argv(
        probe_spec,
        probe_root,
        plan_path=probe_plan_path,
        plan_payload=probe_plan,
        marker_path=probe_root / ".megaplan" / "cloud-sessions" / f"{SESSION}.json",
        manifest_path=probe_root / "runtime-manifest.json",
        control_identity=Path(control["identity"]),
        control_receipt=Path(control["receipt"]),
        roots=roots,
        failure_recorded_at="2026-08-11T08:00:00Z",
    )
    rc, payload = _chain_cli(probe_root, probe_argv, capsys)
    assert rc == 0 and payload is not None and payload["status"] == "adopted", payload
    assert payload["repair_identity_key"] != canonical_key, (
        "a different failure timestamp must produce a different key"
    )
    assert payload["adoption_record_id"] != json.loads(
        adoptions[0].read_text(encoding="utf-8")
    )["adoption_record_id"]

    monkeypatch.setenv("ARNOLD_REPAIR_QUEUE_ROOT", canonical_queue_root)

    # ── superseding the accepted decision blocks join ─────────────────────
    supersede = repair_requests.write_decision(
        queue,
        request_id=canonical_request,
        decision="superseded",
        reason="superseded by a newer target",
        related_request_id="newer-target",
        created_at="2099-01-01T00:00:00Z",
    )
    join_argv = [
        "chain",
        "occurrence-join",
        "--spec", str(spec_path),
        "--project-dir", str(tmp_path),
        "--session", SESSION,
        "--occurrence", canonical_key,
        "--request", canonical_request,
        "--decision", canonical_decision,
        "--claim", canonical_claim,
        "--reason", "T-0101e' rehearsal: exact adopted-occurrence claim",
        "--actor", "operator",
        "--receipt", str(join_receipt_path),
    ]
    rc, payload = _chain_cli(tmp_path, join_argv, capsys)
    assert rc == 1 and payload is not None and payload["error"] == "decision_superseded", payload
    assert not join_receipt_path.exists()
    # Remove the superseding decision (immutable records; deleting restores
    # the accepted decision as latest) so the real join can proceed.
    supersede_path = Path(supersede["_path"])
    supersede_path.unlink()

    # ── occurrence-join via the REAL CLI: adopted-occurrence fenced claim ─
    rc, payload = _chain_cli(tmp_path, join_argv, capsys)
    assert rc == 0, payload
    assert payload is not None and payload["status"] == "claimed", payload
    assert payload["claim_id"] == canonical_claim
    assert payload["occurrence"] == canonical_key
    assert payload["request_id"] == canonical_request
    assert payload["decision_id"] == canonical_decision
    assert join_receipt_path.exists()
    receipt = json.loads(join_receipt_path.read_text(encoding="utf-8"))
    assert receipt["identity_kind"] == "owner_boundary_adoption"
    assert receipt["adoption"]["adoption_record_id"].startswith("sha256:")
    assert receipt["lease"]["lease_origin"] == "owner_boundary_adoption_claim"
    assert receipt["occurrence"]["fence_token"] == 1
    assert receipt["occurrence"]["f01_digest"].startswith("sha256:")
    assert receipt["relation"]["request_id"] == canonical_request
    assert receipt["relation"]["decision_request_id"] == canonical_request
    assert receipt["relation"]["claim_request_id"] == canonical_request
    assert receipt["relation"]["attempt_request_id"] == canonical_request
    assert receipt["relation"]["request_occurrence"] == canonical_key
    assert receipt["relation"]["claim_occurrence_id"] == canonical_key
    assert receipt["relation"]["attempt_occurrence_id"] == canonical_key
    assert receipt["relation"]["attempt_claim_id"] == canonical_claim
    assert receipt["relation"]["attempt_decision_id"] == canonical_decision
    # The new claim attempt + lease derive from BOTH the key and the claim id.
    assert payload["attempt_id"] == occurrence_adoption_claim_attempt_id(
        plan_dir, canonical_key, canonical_claim
    )
    assert payload["lease_id"] == occurrence_adoption_join_lease_id(
        canonical_key, canonical_claim
    )
    # ONE real current lease + custody epoch created AT JOIN TIME.
    lease = open_lease_store(plan_dir / "custody" / "leases").current_lease(
        payload["lease_id"]
    )
    assert lease is not None and not lease.is_expired
    assert int(lease.custody_epoch) >= 1
    assert str(lease.run_authority_grant_id) == canonical_request
    wbc = SqliteAttemptLedgerStore(plan_dir / PHASE_WBC_LEDGER_FILENAME)
    started = wbc.read_events(payload["attempt_id"])
    assert len(started) == 1
    assert started[0].event_type == AttemptEventType.STARTED
    assert wbc.has_terminal_event(payload["attempt_id"]) is False
    event_payload = started[0].payload
    assert event_payload["occurrence_id"] == canonical_key
    assert event_payload["occurrence_digest"] == receipt["occurrence"]["f01_digest"]
    assert event_payload["fence_token"] == 1
    assert event_payload["wbc_attempt_reference"].startswith("owner-adoption-attempt:")
    assert event_payload["coordinator_attempt_id"] == event_payload["wbc_attempt_reference"]
    assert event_payload["request_id"] == canonical_request
    assert event_payload["decision_id"] == canonical_decision
    assert event_payload["claim_id"] == canonical_claim
    assert event_payload["lease_id"] == payload["lease_id"]
    # The join never rewrites chain/plan/queue state.
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    assert plan["current_state"] == "paused"
    assert load_chain_state(spec_path, verify_execution_binding=False).last_state == "paused"
    assert len(repair_requests.iter_repair_requests(queue)) == 1
    # An identical re-join is idempotent.
    rc, payload = _chain_cli(tmp_path, join_argv, capsys)
    assert rc == 0 and payload is not None and payload["status"] == "already_claimed", payload

    # ── (j) resume via the REAL chain CLI ─────────────────────────────────
    rc, payload = _chain_cli(
        tmp_path,
        [
            "chain",
            "resume",
            "--spec", str(spec_path),
            "--project-dir", str(tmp_path),
            "--actor", "operator",
        ],
        capsys,
    )
    assert rc == 0 and payload is not None, payload
    assert payload["changed"] is True and payload["paused"] is False, payload
    assert payload["plan"] == PLAN and payload["restored_plan_state"] == "blocked"
    state = load_chain_state(spec_path)
    assert pause_record(state) is None
    assert state.last_state == "blocked"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    assert plan["current_state"] == "blocked"
    # Gate cursor byte-identical + fresh typed progress.
    assert plan["latest_failure"] == plan_payload["latest_failure"]
    assert plan["resume_cursor"] == plan_payload["resume_cursor"]
    assert "blocked" in _RUNNER_RESUMABLE_STATES
    # The adoption claim lease is still current after resume.
    lease = open_lease_store(plan_dir / "custody" / "leases").current_lease(
        occurrence_adoption_join_lease_id(canonical_key, canonical_claim)
    )
    assert lease is not None and not lease.is_expired
    # Final six-way root equality at the control runtime.
    chain_root = Path(
        state.metadata["execution_binding"]["runtime_binding"]["current_identity"][
            "import_root"
        ]
    ).resolve()
    engine_root = Path(state.metadata["execution_environment"]["engine_root"]).resolve()
    manifest_root = Path(load_manifest(manifest_path).epic["runtime_root"]).resolve()
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker_root = Path(
        marker["runtime_binding"]["current_identity"]["import_root"]
    ).resolve()
    assert (
        chain_root
        == engine_root
        == manifest_root
        == marker_root
        == independent_root
        == REPO_ROOT
    ), "all six T-0101 roots must be equal at the control runtime"
