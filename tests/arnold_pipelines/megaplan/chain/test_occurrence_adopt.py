"""T-0101e': unit coverage for ``chain occurrence-adopt`` (option-D design).

Covers the deterministic identity builder, the v2 envelope normalizer, the
narrow owner-adoption enqueue wrapper (idempotency, crash convergence,
byte-divergence refusal), the restricted-scope rejection of the adoption
identity by generic repair machinery, and the real CLI happy/refusal paths on
a mini copied tree bound to a real candidate editable runtime and independently
observed by a second interpreter.

The mini tree points every runtime root at the candidate worktree.  The
candidate identity and provenance receipt come from one fresh editable
interpreter; the independent import-root observation comes from another, so
the six-way root equality and independently verified identity guards run
without a fabricated verifier result or forced ``PYTHONPATH``.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

from arnold_pipelines.megaplan.chain import run_chain_cli
from arnold_pipelines.megaplan.chain.occurrence_adopt import (
    build_adoption_identity,
)
from arnold_pipelines.megaplan.chain.spec import (
    ChainState,
    load_chain_state,
    save_chain_state,
)
from arnold_pipelines.megaplan.cli import build_parser
from arnold_pipelines.megaplan.cloud import repair_requests
from arnold_pipelines.megaplan.cloud.runtime_manifest import (
    MANIFEST_SCHEMA_VERSION,
    RuntimeManifest,
    write_manifest,
)
from arnold_pipelines.megaplan.types import CliError

from tests.cloud.repair_identity_fixtures import repair_identity

REPO_ROOT = Path(__file__).resolve().parents[4]

SESSION = "adopt-test-session"
PLAN = "adopt-plan"
FAILURE_RECORDED_AT = "2026-08-11T07:35:34Z"


@pytest.fixture(autouse=True)
def _align_repair_queue_root(tmp_path: Path) -> Iterator[None]:
    """T-0640 D1: occurrence-adopt resolves the queue root from
    ARNOLD_REPAIR_QUEUE_ROOT (else the marker-adjacent box-central queue —
    never project_dir).  Pin it to the box-central-style tmp queue the CLI
    tests below assert against (the tree is the epic checkout and must NOT
    hijack the queue root).  Set directly on os.environ (restored in
    teardown) so monkeypatch.undo() cannot silently reset it."""
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


def _canonical_sha256(value: dict) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


# ── candidate-bound runtime + mini copied-tree builder ─────────────────────


def _build_candidate_runtime(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Build a real candidate-bound editable runtime and receipt.

    The pytest interpreter is installed outside this worktree on some hosts,
    so the candidate is observed by two fresh interpreters: ``producer``
    emits the identity/provenance receipt and ``observer`` supplies the
    independent import-root observation used by occurrence-adopt.  Both are
    installed editable from this worktree with ``PYTHONPATH`` removed.
    """
    root = tmp_path_factory.mktemp("adopt-runtime")
    venv_a = root / "venv-a"
    venv_b = root / "venv-b"
    for venv_path in (venv_a, venv_b):
        subprocess.run(
            [
                sys.executable,
                "-m",
                "venv",
                "--copies",
                "--system-site-packages",
                str(venv_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                str(venv_path / "bin" / "python"),
                "-m",
                "pip",
                "install",
                "--no-deps",
                "-e",
                str(REPO_ROOT),
            ],
            check=True,
            capture_output=True,
            text=True,
            env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        )

    producer = venv_a / "bin" / "python"
    observer = venv_b / "bin" / "python"
    revision = _git(REPO_ROOT, "rev-parse", "HEAD")
    identity_path = root / "runtime-identity.json"
    receipt_path = root / "runtime-receipt.json"
    provenance_program = (
        REPO_ROOT
        / "arnold_pipelines"
        / "megaplan"
        / "cloud"
        / "runtime_provenance.py"
    )
    result = subprocess.run(
        [
            str(producer),
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
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert identity["import_root"] == str(REPO_ROOT)
    assert identity["editable_root"] == str(REPO_ROOT)
    assert identity["source_revision"] == revision
    assert receipt["provenance"]["ok"] is True
    assert receipt["runtime_identity"] == identity
    assert receipt["interpreter"]["executable"] == str(producer.resolve())
    assert producer.resolve() != Path(sys.executable).resolve()

    observation = subprocess.run(
        [
            str(observer),
            "-P",
            "-c",
            (
                "import pathlib, arnold_pipelines; "
                "print(pathlib.Path(arnold_pipelines.__file__).resolve().parents[1])"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
    )
    assert observation.returncode == 0, observation.stderr
    assert Path(observation.stdout.strip()).resolve() == REPO_ROOT.resolve()
    assert observer.resolve() != producer.resolve()
    return {
        "root": REPO_ROOT,
        "venv": venv_a,
        "producer": producer,
        "observer": observer,
        "identity": identity,
        "receipt": receipt,
    }


def _build_tree(root: Path, runtime: dict) -> dict:
    """A mini chain + paused identity-less blocked plan + bound runtime.

    Every runtime root (chain binding, engine root, manifest runtime root,
    marker runtime root, candidate root) points at the real candidate
    checkout.  The independent import-root observation and provenance
    receipt are produced by separate candidate-bound interpreters.
    """
    runtime_root = Path(runtime["root"])
    runtime_identity = dict(runtime["identity"])
    runtime_receipt = dict(runtime["receipt"])
    runtime_venv = Path(runtime["venv"])
    _git(root, "init")
    _git(root, "config", "user.email", "tests@example.com")
    _git(root, "config", "user.name", "Tests")
    initiative = root / ".megaplan" / "initiatives" / "demo"
    briefs = initiative / "briefs"
    briefs.mkdir(parents=True, exist_ok=True)
    (initiative / "NORTHSTAR.md").write_text("# Durable destination\n", encoding="utf-8")
    for label in ("c1", "c2"):
        (briefs / f"{label}.md").write_text(f"# {label}\n", encoding="utf-8")
    spec_path = initiative / "chain.yaml"
    spec_path.write_text(
        yaml.safe_dump(
            {
                "anchors": {"north_star": "NORTHSTAR.md"},
                "milestones": [
                    {
                        "label": label,
                        "idea": f".megaplan/initiatives/demo/briefs/{label}.md",
                    }
                    for label in ("c1", "c2")
                ],
                "driver": {
                    "execution_binding": "required",
                    "intended_initiative_revision": "x",
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    _git(root, "add", ".")
    _git(root, "commit", "-m", "init")
    raw = yaml.safe_load(spec_path.read_text(encoding="utf-8"))
    raw["driver"]["intended_initiative_revision"] = _git(root, "rev-parse", "HEAD")
    spec_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "pin")
    _git(root, "checkout", "-b", "adopt-work")

    chain_state = ChainState()
    chain_state.current_milestone_index = 0
    chain_state.current_plan_name = PLAN
    chain_state.last_state = "paused"
    chain_state.chain_session = SESSION
    chain_state.completed = []
    chain_state.metadata["execution_binding"] = {
        "runtime_binding": {
            "current_identity": {
                **runtime_identity,
            }
        }
    }
    chain_state.metadata["execution_environment"] = {"engine_root": str(runtime_root)}
    chain_state.metadata["operator_pause"] = {
        "schema_version": "arnold.megaplan.operator-pause.v1",
        "active": True,
        "paused_at": "2026-08-12T00:00:00Z",
        "actor": "operator",
        "reason": "T-0101e' unit tree",
        "previous_chain_last_state": "blocked",
        "previous_plan_state": "blocked",
        "plan": PLAN,
    }
    save_chain_state(spec_path, chain_state)

    plan_dir = root / ".megaplan" / "plans" / PLAN
    plan_dir.mkdir(parents=True, exist_ok=True)
    plan_payload = {
        "schema_version": 1,
        "name": PLAN,
        "current_state": "paused",
        "phase": "gate",
        "iteration": 1,
        "latest_failure": {
            "kind": "deterministic_phase_failure",
            "phase": "gate",
            "recorded_at": FAILURE_RECORDED_AT,
            "message": (
                "blocked_no_lease: no current custody lease for the gate boundary"
            ),
            "metadata": {"blocked_no_lease": "gate"},
        },
        "resume_cursor": {"phase": "gate", "retry_strategy": "repair_phase_contract"},
        "meta": {"kept": True},
    }
    plan_path = plan_dir / "state.json"
    plan_path.write_text(json.dumps(plan_payload, indent=2) + "\n", encoding="utf-8")

    marker_dir = root / ".megaplan" / "cloud-sessions"
    marker_dir.mkdir(parents=True, exist_ok=True)
    marker_path = marker_dir / f"{SESSION}.json"
    marker_path.write_text(
        json.dumps(
            {
                "session": SESSION,
                "runtime_binding": {
                    "current_identity": {
                        **runtime_identity,
                    }
                },
                "editable_source_head": "x",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    manifest_path = root / "runtime-manifest.json"
    manifest = RuntimeManifest.from_dict(
        {
            "runtime_id": "adopt-runtime-1",
            "schema": MANIFEST_SCHEMA_VERSION,
            "generation": 1,
            "epic_id": "demo",
            "state": "active",
            "owner": "operator",
            "base": {
                "ref": "refs/heads/main",
                "commit": "0" * 40,
                "editable_install_path": "",
                "venv_path": str(runtime_venv),
            },
            "epic": {
                "branch": "adopt-work",
                "worktree_path": str(runtime_root),
                "venv_path": str(runtime_venv),
                "runtime_root": str(runtime_root),
                "expected_head": "0" * 40,
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
                "verified_head": "0" * 40,
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

    identity_path = root / "runtime-identity.json"
    identity_path.write_text(
        json.dumps(
            runtime_identity
        ),
        encoding="utf-8",
    )
    receipt_path = root / "runtime-receipt.json"
    receipt_path.write_text(
        json.dumps(runtime_receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    return {
        "root": root,
        "spec_path": spec_path,
        "plan_path": plan_path,
        "plan_dir": plan_dir,
        "marker_path": marker_path,
        "manifest_path": manifest_path,
        "identity_path": identity_path,
        "receipt_path": receipt_path,
        "runtime_root": runtime_root,
        "plan_payload": plan_payload,
    }


@pytest.fixture(scope="module")
def candidate_runtime(tmp_path_factory: pytest.TempPathFactory) -> dict:
    return _build_candidate_runtime(tmp_path_factory)


@pytest.fixture(scope="module")
def adopt_tree(
    tmp_path_factory: pytest.TempPathFactory, candidate_runtime: dict
) -> dict:
    """One module-scoped canonical tree; tests copy it per scenario."""
    return _build_tree(
        tmp_path_factory.mktemp("adopt-tree"),
        candidate_runtime,
    )


def _fresh_tree(base: Path, canonical: dict) -> dict:
    """Copy the canonical tree and rematerialize the chain state for the copy.

    The chain-state storage path is derived from the spec path, so a plain
    copytree would orphan the copied chain state; the state is re-saved for
    the copy's spec path.  Every other path (plan dir, marker, manifest) is
    name-keyed and copies intact.
    """
    root = base / "tree"
    shutil.copytree(canonical["root"], root, symlinks=True)
    spec_path = root / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    state = load_chain_state(canonical["spec_path"], verify_execution_binding=False)
    save_chain_state(spec_path, state)
    tree = dict(canonical)
    tree["root"] = root
    tree["spec_path"] = spec_path
    tree["plan_path"] = root / ".megaplan" / "plans" / PLAN / "state.json"
    tree["plan_dir"] = root / ".megaplan" / "plans" / PLAN
    tree["marker_path"] = root / ".megaplan" / "cloud-sessions" / f"{SESSION}.json"
    tree["manifest_path"] = root / "runtime-manifest.json"
    tree["identity_path"] = root / "runtime-identity.json"
    tree["receipt_path"] = root / "runtime-receipt.json"
    return tree


def _roots(runtime_root: Path | str) -> dict:
    runtime_root = str(runtime_root)
    return {
        "chain_execution_root": runtime_root,
        "recorded_engine_root": runtime_root,
        "manifest_runtime_root": runtime_root,
        "marker_runtime_root": runtime_root,
        "independent_import_root": runtime_root,
        "candidate_root": runtime_root,
    }


def _adopt_argv(
    tree: dict,
    *,
    actor: str = "operator",
    receipt_name: str = "adopt-receipt.json",
) -> list[str]:
    from arnold_pipelines.megaplan.chain.spec import _state_path_for

    state = load_chain_state(tree["spec_path"], verify_execution_binding=False)
    pause = state.metadata.get("operator_pause")
    pause_sha = (
        "sha256:" + _canonical_sha256(pause)
        if pause is not None
        else "sha256:" + "0" * 64
    )
    plan_payload = json.loads(tree["plan_path"].read_text(encoding="utf-8"))
    return [
        "chain",
        "occurrence-adopt",
        "--spec", str(tree["spec_path"]),
        "--project-dir", str(tree["root"]),
        "--session", SESSION,
        "--expected-current-plan", PLAN,
        "--expected-phase", "gate",
        "--expected-failure-kind", "deterministic_phase_failure",
        "--expected-failure-code", "blocked_no_lease",
        "--expected-failure-recorded-at", FAILURE_RECORDED_AT,
        "--expected-resume-phase", "gate",
        "--expected-retry-strategy", "repair_phase_contract",
        "--expected-chain-state-sha256", "sha256:" + _sha256_file(_state_path_for(tree["spec_path"])),
        "--expected-plan-state-sha256", "sha256:" + _sha256_file(tree["plan_path"]),
        "--expected-latest-failure-sha256", "sha256:" + _canonical_sha256(plan_payload["latest_failure"]),
        "--expected-resume-cursor-sha256", "sha256:" + _canonical_sha256(plan_payload["resume_cursor"]),
        "--expected-pause-authority-sha256", pause_sha,
        "--runtime-manifest", str(tree["manifest_path"]),
        "--expected-runtime-manifest-sha256", "sha256:" + _sha256_file(tree["manifest_path"]),
        "--marker", str(tree["marker_path"]),
        "--expected-marker-sha256", "sha256:" + _sha256_file(tree["marker_path"]),
        "--runtime-identity", str(tree["identity_path"]),
        "--runtime-provenance-receipt", str(tree["receipt_path"]),
        "--candidate-root", str(tree["runtime_root"]),
        "--expected-runtime-roots-sha256", "sha256:" + _canonical_sha256(_roots(tree["runtime_root"])),
        "--reason", "T-0101e' unit adoption",
        "--actor", actor,
        "--receipt", str(tree["plan_dir"] / "evidence" / receipt_name),
    ]


def _chain_cli(
    root: Path, argv: list[str], capsys: pytest.CaptureFixture[str]
) -> tuple[int, dict | None]:
    args = build_parser().parse_args(argv)
    rc = run_chain_cli(root, args)
    captured = capsys.readouterr()
    payload = json.loads(captured.out) if captured.out.strip() else None
    return rc, payload


@pytest.fixture
def candidate_runtime_observation(
    monkeypatch: pytest.MonkeyPatch, candidate_runtime: dict
) -> dict:
    """Select the candidate observer through the production runtime seam.

    The test runner may resolve the package from a different checkout.  Keep
    the production verifier untouched, and use the launch runtime's explicit
    ``ARNOLD_RUNTIME_PYTHON`` selector to make the real helper invoke the
    candidate-bound observer.  Assert its bytes are genuinely imported from
    the candidate root.
    """
    from arnold_pipelines.megaplan.chain import occurrence_adopt

    monkeypatch.setenv("ARNOLD_RUNTIME_PYTHON", str(candidate_runtime["observer"]))
    assert (
        Path(occurrence_adopt._independent_import_root()).resolve()
        == Path(candidate_runtime["root"]).resolve()
    )
    return candidate_runtime


def test_candidate_runtime_rejects_wrong_root_across_interpreters(
    tmp_path: Path, candidate_runtime: dict
) -> None:
    """A candidate interpreter must fail closed when asked to prove another root."""
    from arnold_pipelines.megaplan.chain.execution_binding import (
        verify_external_runtime_identity,
    )

    identity_path = tmp_path / "wrong-root-identity.json"
    receipt_path = tmp_path / "wrong-root-receipt.json"
    wrong_root = tmp_path / "not-the-candidate"
    revision = candidate_runtime["identity"]["source_revision"]
    provenance_program = (
        REPO_ROOT
        / "arnold_pipelines"
        / "megaplan"
        / "cloud"
        / "runtime_provenance.py"
    )
    result = subprocess.run(
        [
            str(candidate_runtime["producer"]),
            "-P",
            str(provenance_program),
            "--expected-root",
            str(wrong_root),
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
    assert result.returncode != 0
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["interpreter"]["executable"] == str(
        Path(candidate_runtime["producer"]).resolve()
    )
    assert "import_root_mismatch" in receipt["provenance"]["errors"]
    with pytest.raises(CliError) as excinfo:
        verify_external_runtime_identity(identity_path, receipt_path)
    assert excinfo.value.code == "chain_runtime_binding_drift"


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


# ── deterministic identity builder ─────────────────────────────────────────


def _builder_kwargs(**overrides: object) -> dict:
    kwargs: dict = {
        "session": "megaplan-maintenance",
        "plan_name": "m1-containment-and-truthful-20260811-0640",
        "phase": "gate",
        "failure_kind": "deterministic_phase_failure",
        "failure_code": "blocked_no_lease",
        "failure_recorded_at": FAILURE_RECORDED_AT,
        "resume_phase": "gate",
        "retry_strategy": "repair_phase_contract",
        "cas": {field: "sha256:" + "a" * 64 for field in repair_requests.OWNER_ADOPTION_CAS_FIELDS},
        "runtime_roots": {
            field: "/workspace/runtime-candidates/arnold-test"
            for field in repair_requests.OWNER_ADOPTION_ROOT_FIELDS
        },
    }
    kwargs.update(overrides)
    return kwargs


def test_build_adoption_identity_deterministic_and_schema() -> None:
    first = build_adoption_identity(**_builder_kwargs())
    second = build_adoption_identity(**_builder_kwargs())
    assert first == second
    envelope = first["identity"]
    assert envelope["schema_version"] == "megaplan-repair-identity-owner-adoption-v1"
    assert envelope["identity_kind"] == "owner_boundary_adoption"
    occurrence = envelope["occurrence"]
    assert occurrence["contract_type"] == "owner_adopted_blocked_occurrence"
    assert occurrence["plan_name"] == "m1-containment-and-truthful-20260811-0640"
    assert occurrence["failure_recorded_at"] == FAILURE_RECORDED_AT
    assert occurrence["subject_occurrence_digest"].startswith("sha256:")
    assert set(envelope["cas"]) == set(repair_requests.OWNER_ADOPTION_CAS_FIELDS)
    assert set(envelope["runtime_roots"]) == set(
        repair_requests.OWNER_ADOPTION_ROOT_FIELDS
    )
    authority = envelope["authority"]
    assert authority["kind"] == "operator_owner_boundary_adoption"
    assert authority["owner"] == "megaplan.chain"
    assert authority["scope"] == ["enqueue_exact_occurrence", "occurrence_join"]
    assert authority["historical_authority_status"] == "absent"
    assert authority["adoption_fence_token"] == 1
    # No fabricated historical v1 fields anywhere in the envelope.
    for forbidden in (
        "run_incarnation_id",
        "coordinator_attempt_id",
        "lease_id",
        "custody_epoch",
    ):
        assert forbidden not in envelope
    # Mutable labels stay outside the identity.
    for label in ("adopted_at", "reason", "receipt_path", "pid", "hostname"):
        assert label not in envelope
    # Authority references are deterministic and namespaced.
    assert first["adoption_record_id"].startswith("sha256:")
    assert first["adoption_run_id"].startswith("repair-adoption:")
    assert first["adoption_run_revision"] == first["adoption_record_id"]
    assert first["adoption_attempt_id"].startswith("owner-adoption-attempt:")
    assert authority["wbc_attempt_reference"] == authority["adoption_attempt_id"]
    assert first["claim_id"] == (
        "t0101-owner-adoption:" + first["repair_identity_key"][7:]
    )
    # Key parity with the queue-side normalizer.
    normalized = repair_requests.normalize_owner_adoption_identity(envelope)
    assert normalized is not None
    assert repair_requests.owner_adoption_identity_key(normalized) == first[
        "repair_identity_key"
    ]
    # The v1 machinery must NEVER normalize the adoption envelope.
    assert repair_requests.normalize_repair_identity(envelope) is None
    assert repair_requests.repair_identity_key(envelope) == ""


@pytest.mark.parametrize(
    ("override", "label"),
    [
        ({"plan_name": "other-plan"}, "plan"),
        ({"failure_recorded_at": "2026-08-12T00:00:00Z"}, "failure timestamp"),
        ({"resume_phase": "executed"}, "cursor"),
        (
            {
                "runtime_roots": {
                    field: "/elsewhere/root"
                    for field in repair_requests.OWNER_ADOPTION_ROOT_FIELDS
                }
            },
            "roots",
        ),
        ({"failure_kind": "human_gate"}, "failure kind"),
        ({"phase": "executed"}, "phase"),
    ],
)
def test_build_adoption_identity_sensitive_to_inputs(override: dict, label: str) -> None:
    baseline = build_adoption_identity(**_builder_kwargs())
    variant = build_adoption_identity(**_builder_kwargs(**override))
    assert variant["repair_identity_key"] != baseline["repair_identity_key"], label
    assert variant["adoption_record_id"] != baseline["adoption_record_id"], label


def test_build_adoption_identity_cas_one_bit_sensitive() -> None:
    baseline = build_adoption_identity(**_builder_kwargs())
    for field in repair_requests.OWNER_ADOPTION_CAS_FIELDS:
        cas = {
            key: value for key, value in baseline["identity"]["cas"].items()
        }
        value = cas[field]
        flipped = "sha256:" + ("0" if value[7] != "0" else "1") + value[8:]
        cas[field] = flipped
        variant = build_adoption_identity(**_builder_kwargs(cas=cas))
        assert variant["repair_identity_key"] != baseline["repair_identity_key"], field


# ── v2 envelope normalizer ─────────────────────────────────────────────────


def test_normalize_owner_adoption_identity_rejects_invalid() -> None:
    valid = build_adoption_identity(**_builder_kwargs())["identity"]

    tampered = dict(valid)
    tampered["occurrence"] = dict(valid["occurrence"])
    tampered["occurrence"]["contract_type"] = "repair_occurrence_key"
    assert repair_requests.normalize_owner_adoption_identity(tampered) is None

    tampered = dict(valid)
    tampered["cas"] = dict(valid["cas"])
    tampered["cas"]["plan_state_sha256"] = "sha256:zzz"
    assert repair_requests.normalize_owner_adoption_identity(tampered) is None

    tampered = dict(valid)
    tampered["authority"] = dict(valid["authority"])
    tampered["authority"]["scope"] = ["enqueue_exact_occurrence", "generic_dispatch"]
    assert repair_requests.normalize_owner_adoption_identity(tampered) is None

    tampered = dict(valid)
    tampered["authority"] = dict(valid["authority"])
    tampered["authority"]["adoption_fence_token"] = 7
    assert repair_requests.normalize_owner_adoption_identity(tampered) is None

    tampered = dict(valid)
    tampered["authority"] = dict(valid["authority"])
    tampered["authority"]["wbc_attempt_reference"] = "some-other-attempt"
    assert repair_requests.normalize_owner_adoption_identity(tampered) is None

    tampered = dict(valid)
    tampered["authority"] = dict(valid["authority"])
    tampered["authority"]["historical_authority_status"] = "present"
    assert repair_requests.normalize_owner_adoption_identity(tampered) is None

    for forbidden in ("run_incarnation_id", "coordinator_attempt_id", "lease_id", "custody_epoch"):
        tampered = dict(valid)
        tampered[forbidden] = "historical-value"
        assert repair_requests.normalize_owner_adoption_identity(tampered) is None

    assert repair_requests.normalize_owner_adoption_identity(None) is None
    assert repair_requests.normalize_owner_adoption_identity({}) is None


def test_plan_state_has_repair_identity() -> None:
    assert repair_requests.plan_state_has_repair_identity({"meta": {"kept": True}}) is False
    identity = repair_identity(
        session=SESSION, plan=PLAN, failure_kind="deterministic_phase_failure",
        phase="gate", task="phase:gate",
    )
    assert repair_requests.plan_state_has_repair_identity(
        {"meta": {"repair_identity": identity}}
    ) is True
    assert repair_requests.plan_state_has_repair_identity(
        {"repair_identity_key": "sha256:abc"}
    ) is True
    assert repair_requests.plan_state_has_repair_identity(
        {"current_target": {"current_refs": {"repair_identity": identity}}}
    ) is True


# ── owner-adoption enqueue wrapper ─────────────────────────────────────────


def _wrapper_args(tmp_path: Path) -> dict:
    queue_root = tmp_path / ".megaplan" / "repair-queue"
    built = build_adoption_identity(**_builder_kwargs())
    return {
        "queue_root": queue_root,
        "session": "megaplan-maintenance",
        "source": "owner_boundary_occurrence_adoption",
        "workspace": tmp_path,
        "run_kind": "chain",
        "marker_dir": tmp_path,
        "target": {
            "plan_dir": str(tmp_path),
            "plan_name": "m1-containment-and-truthful-20260811-0640",
            "retry_strategy": "repair_phase_contract",
            "adoption_record_id": built["adoption_record_id"],
        },
        "problem_signature": {
            "failure_kind": "deterministic_phase_failure",
            "current_state": "blocked",
            "phase_or_step": "gate",
            "milestone_or_plan": "m1-containment-and-truthful-20260811-0640",
            "gate_recommendation": "repair gate contract",
            "blocked_task_id": "phase:gate",
        },
        "root_cause_hint": "owner adoption of identity-less blocked occurrence",
        "repair_identity": built["identity"],
    }


def test_enqueue_owner_adopted_repair_request_idempotent(tmp_path: Path) -> None:
    args = _wrapper_args(tmp_path)
    first = repair_requests.enqueue_owner_adopted_repair_request(**args)
    assert first["status"] == "queued", first
    request_id = first["request"]["request_id"]
    decision_id = first["decision"]["decision_id"]
    assert first["decision"]["decision"] == "accepted"
    for _ in range(2):
        retry = repair_requests.enqueue_owner_adopted_repair_request(**args)
        assert retry["status"] == "already_accepted", retry
        assert retry["request"]["request_id"] == request_id
        assert retry["decision"]["decision_id"] == decision_id
    queue_root = args["queue_root"]
    assert len(repair_requests.iter_repair_requests(queue_root)) == 1
    accepted = [
        record
        for record in repair_requests.iter_repair_decisions(queue_root)
        if record["decision"] == "accepted"
    ]
    assert len(accepted) == 1, accepted
    # The request id is deterministic and bound to the adoption identity.
    assert request_id == repair_requests.request_id_for(
        session=args["session"],
        problem_signature=args["problem_signature"],
        root_cause_hint=args["root_cause_hint"],
        repair_identity=args["repair_identity"],
    )


def test_enqueue_owner_adopted_refuses_byte_divergent(tmp_path: Path) -> None:
    args = _wrapper_args(tmp_path)
    first = repair_requests.enqueue_owner_adopted_repair_request(**args)
    request_id = first["request"]["request_id"]
    request_path = repair_requests.requests_dir(args["queue_root"]) / f"{request_id}.json"
    tampered = json.loads(request_path.read_bytes())
    tampered["problem_signature"]["gate_recommendation"] = "tampered"
    request_path.write_text(
        json.dumps(tampered, indent=2) + "\n", encoding="utf-8"
    )
    tampered_bytes = request_path.read_bytes()
    with pytest.raises(CliError) as excinfo:
        repair_requests.enqueue_owner_adopted_repair_request(**args)
    assert excinfo.value.code == "adoption_request_mismatch"
    # The refusal is zero-mutation: the divergent file is untouched.
    assert request_path.read_bytes() == tampered_bytes


def test_enqueue_owner_adopted_crash_between_request_and_decision_converges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = _wrapper_args(tmp_path)
    real_write_decision = repair_requests.write_decision

    def boom_write_decision(*a, **kwargs):
        if kwargs.get("decision") == "accepted":
            raise OSError("injected crash before accepted decision")
        return real_write_decision(*a, **kwargs)

    monkeypatch.setattr(repair_requests, "write_decision", boom_write_decision)
    with pytest.raises(OSError):
        repair_requests.enqueue_owner_adopted_repair_request(**args)
    monkeypatch.setattr(repair_requests, "write_decision", real_write_decision)
    queue_root = args["queue_root"]
    requests = repair_requests.iter_repair_requests(queue_root)
    assert len(requests) == 1
    assert repair_requests.iter_repair_decisions(queue_root) == []
    request_id = requests[0]["request_id"]
    converged = repair_requests.enqueue_owner_adopted_repair_request(**args)
    assert converged["request"]["request_id"] == request_id
    assert converged["decision"]["decision"] == "accepted"
    accepted = [
        record
        for record in repair_requests.iter_repair_decisions(queue_root)
        if record["decision"] == "accepted"
    ]
    assert len(accepted) == 1, accepted


def test_generic_repair_machinery_rejects_adoption_scope(tmp_path: Path) -> None:
    """The restricted scope must hold: no generic enqueue/claim/dispatch/bind."""
    args = _wrapper_args(tmp_path)
    queue_root = args["queue_root"]
    identity = args["repair_identity"]
    signature = args["problem_signature"]

    generic = repair_requests.enqueue_repair_request(
        queue_root=queue_root,
        session=args["session"],
        source="lifecycle_failure",
        workspace=tmp_path,
        run_kind="chain",
        marker_dir=tmp_path,
        target={"plan_dir": str(tmp_path), "plan_name": "m1"},
        problem_signature=signature,
        root_cause_hint="hint",
        repair_identity=identity,
    )
    assert generic["status"] == "zero_authority_rejected", generic
    assert generic["evidence"]["identity_kind"] == "owner_boundary_adoption"

    bound = repair_requests.enqueue_occurrence_bound_repair_request(
        queue_root=queue_root,
        session=args["session"],
        source="lifecycle_failure",
        workspace=tmp_path,
        run_kind="chain",
        marker_dir=tmp_path,
        target={"plan_dir": str(tmp_path), "plan_name": "m1"},
        problem_signature=signature,
        root_cause_hint="hint",
        occurrence_identity=identity,
    )
    assert bound["status"] == "zero_authority_rejected", bound

    with pytest.raises(ValueError):
        repair_requests.write_dispatch_attempt(
            queue_root,
            request_id="x",
            blocker_id="phase:gate",
            actor="operator",
            repair_layer="chain",
            command="echo hi",
            child_pid=1,
            managed_run_id="run-1",
            managed_manifest_path="manifest.json",
            repair_identity=identity,
        )

    assert (
        repair_requests.bind_managed_run_to_active_claim(
            queue_root,
            blocker_id="phase:gate",
            request_id="x",
            managed_run_id="run-1",
            managed_manifest_path="manifest.json",
            expected_owner_pid=None,
            new_owner_pid=1,
            repair_identity=identity,
        )
        is False
    )


# ── real CLI happy/refusal paths on the mini copied tree ───────────────────


def test_cli_adopt_happy_path_and_idempotent_retry(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    adopt_tree: dict,
    candidate_runtime_observation: None,
) -> None:
    tree = _fresh_tree(tmp_path, adopt_tree)
    argv = _adopt_argv(tree)
    rc, payload = _chain_cli(tree["root"], argv, capsys)
    assert rc == 0, payload
    assert payload is not None and payload["status"] == "adopted", payload
    assert payload["identity_kind"] == "owner_boundary_adoption"
    assert payload["repair_identity_key"].startswith("sha256:")
    assert payload["claim_id"] == (
        "t0101-owner-adoption:" + payload["repair_identity_key"][7:]
    )
    assert payload["receipt_path"] == str(
        tree["plan_dir"] / "evidence" / "adopt-receipt.json"
    )
    # Exactly one adoption record, one request, one accepted decision.
    adoptions = list((tree["plan_dir"] / "evidence" / "occurrence-adoptions").glob("*.json"))
    assert len(adoptions) == 1
    record = json.loads(adoptions[0].read_text(encoding="utf-8"))
    assert record["adoption_record_id"] == payload["adoption_record_id"]
    assert record["repair_identity_key"] == payload["repair_identity_key"]
    assert record["claim_id"] == payload["claim_id"]
    assert record["mutable"]["reason"] == "T-0101e' unit adoption"
    # T-0640 D1: the request lands in the ALIGNED queue root (env-selected
    # box-central), never under the epic checkout tree.
    queue = tmp_path / ".megaplan" / "repair-queue"
    assert not (tree["root"] / ".megaplan" / "repair-queue").exists()
    assert len(repair_requests.iter_repair_requests(queue)) == 1
    accepted = [
        record
        for record in repair_requests.iter_repair_decisions(queue)
        if record["decision"] == "accepted"
    ]
    assert len(accepted) == 1

    # Exact retry: SAME key/request/decision, no new records.
    rc, retry = _chain_cli(tree["root"], argv, capsys)
    assert rc == 0, retry
    assert retry["repair_identity_key"] == payload["repair_identity_key"]
    assert retry["request_id"] == payload["request_id"]
    assert retry["decision_id"] == payload["decision_id"]
    assert retry["claim_id"] == payload["claim_id"]
    assert len(list((tree["plan_dir"] / "evidence" / "occurrence-adoptions").glob("*.json"))) == 1
    assert len(repair_requests.iter_repair_requests(queue)) == 1
    assert len(
        [
            record
            for record in repair_requests.iter_repair_decisions(queue)
            if record["decision"] == "accepted"
        ]
    ) == 1


@pytest.mark.parametrize(
    "flag",
    [
        "--expected-chain-state-sha256",
        "--expected-plan-state-sha256",
        "--expected-latest-failure-sha256",
        "--expected-resume-cursor-sha256",
        "--expected-pause-authority-sha256",
        "--expected-runtime-manifest-sha256",
        "--expected-marker-sha256",
        "--expected-runtime-roots-sha256",
    ],
)
def test_cli_adopt_refuses_one_bit_cas_flip_zero_mutation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    adopt_tree: dict,
    candidate_runtime_observation: None,
    flag: str,
) -> None:
    tree = _fresh_tree(tmp_path, adopt_tree)
    argv = _adopt_argv(tree)
    index = argv.index(flag) + 1
    value = argv[index]
    flipped = "sha256:" + ("0" if value[7] != "0" else "1") + value[8:]
    argv[index] = flipped
    pre = _snapshot(tree["root"])
    rc, payload = _chain_cli(tree["root"], argv, capsys)
    assert rc == 1, (rc, payload)
    assert payload is not None and payload["success"] is False, payload
    assert payload["error"] == "cas_mismatch", payload
    assert _snapshot(tree["root"]) == pre, f"{flag} refusal must be zero-mutation"


def test_cli_adopt_refuses_non_operator(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    adopt_tree: dict,
    candidate_runtime_observation: None,
) -> None:
    tree = _fresh_tree(tmp_path, adopt_tree)
    argv = _adopt_argv(tree, actor="not-operator")
    rc, payload = _chain_cli(tree["root"], argv, capsys)
    assert rc == 1 and payload is not None and payload["error"] == "actor_forbidden"


def test_cli_adopt_refuses_missing_pause(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    adopt_tree: dict,
    candidate_runtime_observation: None,
) -> None:
    tree = _fresh_tree(tmp_path, adopt_tree)
    state = load_chain_state(tree["spec_path"], verify_execution_binding=False)
    state.metadata.pop("operator_pause", None)
    save_chain_state(tree["spec_path"], state)
    argv = _adopt_argv(tree)
    from arnold_pipelines.megaplan.chain.spec import _state_path_for

    argv[argv.index("--expected-chain-state-sha256") + 1] = (
        "sha256:" + _sha256_file(_state_path_for(tree["spec_path"]))
    )
    rc, payload = _chain_cli(tree["root"], argv, capsys)
    assert rc == 1 and payload is not None and payload["error"] == "chain_not_paused"


def test_cli_adopt_refuses_non_null_existing_identity(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    adopt_tree: dict,
    candidate_runtime_observation: None,
) -> None:
    tree = _fresh_tree(tmp_path, adopt_tree)
    plan_payload = json.loads(tree["plan_path"].read_text(encoding="utf-8"))
    plan_payload["meta"]["repair_identity"] = repair_identity(
        session=SESSION,
        plan=PLAN,
        failure_kind="deterministic_phase_failure",
        phase="gate",
        task="phase:gate",
    )
    tree["plan_path"].write_text(json.dumps(plan_payload, indent=2) + "\n", encoding="utf-8")
    argv = _adopt_argv(tree)
    rc, payload = _chain_cli(tree["root"], argv, capsys)
    assert rc == 1 and payload is not None
    assert payload["error"] == "repair_identity_already_present", payload


def test_cli_adopt_refuses_ambiguous_failure(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    adopt_tree: dict,
    candidate_runtime_observation: None,
) -> None:
    tree = _fresh_tree(tmp_path, adopt_tree)
    plan_payload = json.loads(tree["plan_path"].read_text(encoding="utf-8"))
    plan_payload["latest_failure"] = [plan_payload["latest_failure"]]
    tree["plan_path"].write_text(json.dumps(plan_payload, indent=2) + "\n", encoding="utf-8")
    argv = _adopt_argv(tree)
    rc, payload = _chain_cli(tree["root"], argv, capsys)
    assert rc == 1 and payload is not None and payload["error"] == "ambiguous_failure"


def test_cli_adopt_refuses_unequal_roots(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    adopt_tree: dict,
    candidate_runtime_observation: None,
) -> None:
    tree = _fresh_tree(tmp_path, adopt_tree)
    argv = _adopt_argv(tree)
    argv[argv.index("--candidate-root") + 1] = "/elsewhere/root"
    rc, payload = _chain_cli(tree["root"], argv, capsys)
    assert rc == 1 and payload is not None and payload["error"] == "runtime_roots_unequal"


def test_cli_adopt_crash_after_record_and_after_request_converge(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    adopt_tree: dict,
    candidate_runtime_observation: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Crash injection after the adoption authority / request writes converges.

    The raw OSError propagates (the process dies); on retry the persisted
    adoption record + request are reused and exactly one accepted decision is
    recorded.
    """
    tree = _fresh_tree(tmp_path, adopt_tree)
    argv = _adopt_argv(tree)

    real_wrapper = repair_requests.enqueue_owner_adopted_repair_request

    def boom_wrapper(*a, **kwargs):
        raise OSError("injected crash before enqueue")

    monkeypatch.setattr(repair_requests, "enqueue_owner_adopted_repair_request", boom_wrapper)
    with pytest.raises(OSError):
        _chain_cli(tree["root"], argv, capsys)
    monkeypatch.setattr(
        repair_requests, "enqueue_owner_adopted_repair_request", real_wrapper
    )
    # The adoption record persisted BEFORE enqueue.
    adoptions = list((tree["plan_dir"] / "evidence" / "occurrence-adoptions").glob("*.json"))
    assert len(adoptions) == 1
    rc, payload = _chain_cli(tree["root"], argv, capsys)
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

    # Second scenario: crash after the request write, before the accepted
    # decision (fresh tree under its OWN aligned root).
    tree = _fresh_tree(tmp_path / "second", adopt_tree)
    argv = _adopt_argv(tree)
    second_queue = tmp_path / "second" / ".megaplan" / "repair-queue"
    monkeypatch.setenv("ARNOLD_REPAIR_QUEUE_ROOT", str(second_queue))
    real_write_decision = repair_requests.write_decision

    def boom_decision(*a, **kwargs):
        if kwargs.get("decision") == "accepted":
            raise OSError("injected crash before accepted decision")
        return real_write_decision(*a, **kwargs)

    monkeypatch.setattr(repair_requests, "write_decision", boom_decision)
    with pytest.raises(OSError):
        _chain_cli(tree["root"], argv, capsys)
    monkeypatch.setattr(repair_requests, "write_decision", real_write_decision)
    queue = second_queue
    assert len(repair_requests.iter_repair_requests(queue)) == 1
    assert repair_requests.iter_repair_decisions(queue) == []
    rc, payload = _chain_cli(tree["root"], argv, capsys)
    assert rc == 0 and payload is not None and payload["status"] == "adopted", payload
    assert len(repair_requests.iter_repair_requests(queue)) == 1
    assert len(
        [
            record
            for record in repair_requests.iter_repair_decisions(queue)
            if record["decision"] == "accepted"
        ]
    ) == 1


def test_cli_adopt_two_concurrent_adopters_one_record(
    tmp_path: Path,
    adopt_tree: dict,
    candidate_runtime_observation: None,
) -> None:
    import threading

    tree = _fresh_tree(tmp_path, adopt_tree)
    argv = _adopt_argv(tree)
    errors: list[BaseException] = []

    def adopter() -> None:
        # stdout is intentionally NOT captured (redirect_stdout is not
        # thread-safe); the CLI writes to the pytest capture and the outcome
        # is asserted from the durable files after both threads finish.
        try:
            run_chain_cli(tree["root"], build_parser().parse_args(argv))
        except BaseException as exc:  # noqa: BLE001 - captured for assertion
            errors.append(exc)

    threads = [threading.Thread(target=adopter), threading.Thread(target=adopter)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == [], errors
    # Exactly ONE adoption record whose identity is the ONLY request.
    adoptions = list((tree["plan_dir"] / "evidence" / "occurrence-adoptions").glob("*.json"))
    assert len(adoptions) == 1
    record = json.loads(adoptions[0].read_text(encoding="utf-8"))
    queue = tmp_path / ".megaplan" / "repair-queue"
    requests = repair_requests.iter_repair_requests(queue)
    assert len(requests) == 1
    assert requests[0]["repair_identity_key"] == record["repair_identity_key"]
    assert requests[0]["request_id"] == record.get("request_id") or requests[0]["request_id"]
    accepted = [
        record_decision
        for record_decision in repair_requests.iter_repair_decisions(queue)
        if record_decision["decision"] == "accepted"
    ]
    assert len(accepted) == 1
    assert accepted[0]["request_id"] == requests[0]["request_id"]
    # The claim id is deterministic from the single identity key.
    assert record["claim_id"] == (
        "t0101-owner-adoption:" + record["repair_identity_key"][7:]
    )


# ── T-0640 D1: aligned repair-queue root resolution ───────────────────────


def test_resolve_aligned_repair_queue_root_env_override_wins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ARNOLD_REPAIR_QUEUE_ROOT is authoritative for adopt/join."""
    target = tmp_path / "box" / ".megaplan" / "repair-queue"
    monkeypatch.setenv("ARNOLD_REPAIR_QUEUE_ROOT", str(target))
    monkeypatch.setenv("ARNOLD_REPAIR_MARKER_DIR", str(tmp_path / "elsewhere"))
    assert repair_requests.resolve_aligned_repair_queue_root() == target.resolve()


def test_resolve_aligned_repair_queue_root_defaults_to_box_central(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No env at all: the marker-adjacent box-central queue is the default."""
    monkeypatch.delenv("ARNOLD_REPAIR_QUEUE_ROOT", raising=False)
    monkeypatch.delenv("ARNOLD_REPAIR_MARKER_DIR", raising=False)
    resolved = repair_requests.resolve_aligned_repair_queue_root()
    assert resolved == Path("/workspace/.megaplan/repair-queue")
    # The default satisfies the structural central-queue contract.
    assert resolved.name == "repair-queue"
    assert resolved.parent.name == ".megaplan"


def test_resolve_aligned_repair_queue_root_never_epic_checkout_or_plans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An epic-checkout project_dir path never hijacks the default root."""
    epic = tmp_path / "megaplan-maintenance" / "Arnold"
    (epic / ".megaplan" / "plans").mkdir(parents=True)
    monkeypatch.delenv("ARNOLD_REPAIR_QUEUE_ROOT", raising=False)
    monkeypatch.delenv("ARNOLD_REPAIR_MARKER_DIR", raising=False)
    resolved = repair_requests.resolve_aligned_repair_queue_root()
    assert resolved != (epic / ".megaplan" / "repair-queue")
    assert resolved != (epic / ".megaplan" / "plans" / "repair-queue")
    assert resolved == Path("/workspace/.megaplan/repair-queue")
    # Anything under .megaplan/plans is structurally rejected regardless of
    # how it was derived.
    with pytest.raises(ValueError):
        repair_requests.validate_queue_root(epic / ".megaplan" / "plans" / "repair-queue")
