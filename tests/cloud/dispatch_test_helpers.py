from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import venv
from datetime import datetime, timezone
from pathlib import Path

from arnold_pipelines.megaplan.cloud.worker_dispatch import WorkerAdmissionRequest, _digest
from arnold_pipelines.megaplan.chain.spec import ChainState, save_chain_state
from arnold_pipelines.megaplan.cloud import runtime_attestation
from arnold_pipelines.megaplan.cloud.runtime_attestation import (
    ensure_runtime_launch_seed,
    validate_runtime_launch_seed,
)
from arnold_pipelines.megaplan.cloud.runtime_manifest import (
    MANIFEST_SCHEMA_VERSION,
    RuntimeManifest,
    bootstrap_manifest,
    load_manifest,
    manifest_bytes_sha256,
    write_manifest,
)
from arnold_pipelines.megaplan.cloud.runtime_provenance import (
    normalized_runtime_identity,
)
from arnold_pipelines.megaplan.fallback_chains import provider_family


_FIXTURE_SUPERVISOR_ROOT: Path | None = None
_FIXTURE_SUPERVISOR_KEY: str | None = None


def _fixture_supervisor_root(root: Path, revision: str) -> Path:
    """Return a small non-editable supervisor install for seed issuance.

    The production seed validator intentionally rejects the editable worker
    environment as a supervisor runtime.  Install the package once into a
    cached system-site-packages venv so the fixture exercises that same
    production boundary without mocking attestation or seed validation.
    """
    global _FIXTURE_SUPERVISOR_ROOT, _FIXTURE_SUPERVISOR_KEY
    key = hashlib.sha256(f"{root}\0{revision}".encode("utf-8")).hexdigest()[:20]
    if (
        _FIXTURE_SUPERVISOR_ROOT is not None
        and _FIXTURE_SUPERVISOR_KEY == key
        and (_FIXTURE_SUPERVISOR_ROOT / "bin" / "python").is_file()
    ):
        return _FIXTURE_SUPERVISOR_ROOT

    supervisor = Path(tempfile.gettempdir()) / f"arnold-worker-supervisor-{key}"
    installed_marker = supervisor / ".worker-fixture-installed"
    if not installed_marker.is_file():
        if not (supervisor / "bin" / "python").is_file():
            venv.EnvBuilder(system_site_packages=True, with_pip=True).create(supervisor)
        environment = dict(os.environ)
        for name in (
            "PYTHONPATH",
            "ARNOLD_RUNTIME_MANIFEST",
            "MEGAPLAN_RUNTIME_LAUNCH_SEED",
            "ARNOLD_BABYSITTER_MARKER_PATH",
            "ARNOLD_BABYSITTER_MANIFEST_IDENTITY",
        ):
            environment.pop(name, None)
        subprocess.run(
            [
                str(supervisor / "bin" / "python"),
                "-m",
                "pip",
                "install",
                "--no-deps",
                "--no-build-isolation",
                "--quiet",
                str(root),
            ],
            check=True,
            cwd=root,
            env=environment,
        )
        installed_marker.write_text("ok\n", encoding="utf-8")
    _FIXTURE_SUPERVISOR_ROOT = supervisor
    _FIXTURE_SUPERVISOR_KEY = key
    return supervisor


def _production_runtime_fixture(tmp_path: Path) -> tuple[str, str, Path, Path]:
    """Materialize and validate a complete production runtime binding.

    This deliberately goes through the production RuntimeManifest writer and
    ``ensure_runtime_launch_seed`` issuance path.  The returned identities are
    hashes of the exact bytes on disk, and validation runs before callers can
    mutate the manifest, marker, or seed.
    """
    root = Path(__file__).resolve().parents[2]
    tmp_path.mkdir(parents=True, exist_ok=True)

    # The worker preflight deliberately performs a real read-only credential
    # probe.  Keep that probe hermetic under the neutral ``env -i`` test
    # runner: provide the smallest supported Codex session and key-pool
    # stores beneath this test's temporary directory, never the developer's
    # HOME or real credentials.  ``scan_providers`` only needs a parseable
    # Codex auth store to establish the selected native route; the key-pool
    # file is included so the same fixture remains complete for provider
    # backed routes used by neighboring worker admission tests.
    fixture_home = tmp_path / "home"
    codex_home = fixture_home / ".codex"
    codex_home.mkdir(parents=True, exist_ok=True)
    (codex_home / "auth.json").write_text(
        json.dumps(
            {
                "auth_mode": "chatgpt",
                "tokens": {
                    "access_token": "fixture-access-token",
                    "refresh_token": "fixture-refresh-token",
                    "id_token": "fixture-id-token",
                },
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (codex_home / "config.toml").write_text(
        'preferred_auth_method = "chatgpt"\n', encoding="utf-8"
    )
    fixture_key_pool = tmp_path / "api_keys.json"
    fixture_key_pool.write_text(
        json.dumps([{"key": "fixture-zhipu-key"}]) + "\n", encoding="utf-8"
    )
    os.environ["HOME"] = str(fixture_home)
    os.environ["CODEX_HOME"] = str(codex_home)
    os.environ["MEGAPLAN_API_KEYS_PATH"] = str(fixture_key_pool)

    revision = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    branch = subprocess.check_output(
        ["git", "-C", str(root), "branch", "--show-current"], text=True
    ).strip()
    now = datetime.now(timezone.utc).isoformat()

    manifest_path = tmp_path / "runtime-manifest.json"
    manifest = RuntimeManifest(
        runtime_id=f"worker-fixture-{tmp_path.name}",
        schema=MANIFEST_SCHEMA_VERSION,
        generation=1,
        epic_id=f"worker-fixture-{tmp_path.name}",
        state="active",
        owner="tests",
        base={
            "ref": branch,
            "commit": revision,
            "editable_install_path": str(root),
            "venv_path": str(root / ".venv"),
        },
        epic={
            "branch": branch,
            "worktree_path": str(root),
            "venv_path": str(root / ".venv"),
            "runtime_root": str(root),
            "expected_head": revision,
            "repair_bin": str(root / "scripts"),
            "deps_lockfile": str(root / "uv.lock"),
        },
        indirection={
            "host_path": str(root),
            "container_path": str(root),
            "mount_table": [],
            "execution_namespace": "worker-fixture",
            "verified_head": revision,
            "last_verified_at": now,
            "attestation": {
                "module_file": str(root / "arnold_pipelines" / "__init__.py"),
                "module_digest": "fixture",
                "mount_id": "fixture",
            },
        },
        policy={
            "policy_sha": "worker-fixture",
            "model_policy_sha": "worker-fixture",
            "sync_policy": "test-only",
        },
        promotions=[],
        timestamps={"created": now, "updated": now, "closed": ""},
        gc_policy="closed-only",
        commands=[{"argv": ["megaplan", "chain"]}],
    )
    write_manifest(manifest, manifest_path)
    assert bootstrap_manifest(manifest_path).to_dict() == load_manifest(
        manifest_path
    ).to_dict()
    manifest_identity = manifest_bytes_sha256(manifest_path)

    provenance = runtime_attestation.runtime_provenance(
        expected_root=root, expected_revision=revision
    )
    if not provenance.get("ok"):
        raise AssertionError(f"fixture runtime provenance is not ready: {provenance}")
    runtime_identity = normalized_runtime_identity(provenance)

    # The seed validator checks the chain's persisted execution binding.  Use
    # a copied, isolated chain spec and persist that binding through the normal
    # ChainState writer so no repository control-plane state is touched.
    chain_spec_path = tmp_path / "chain.yaml"
    shutil.copy2(root / ".megaplan" / "collection" / "chain.yaml", chain_spec_path)
    save_chain_state(
        chain_spec_path,
        ChainState(
            metadata={
                "execution_binding": {
                    "runtime_binding": {"current_identity": runtime_identity}
                }
            }
        ),
        _record_projection=False,
    )

    marker_path = tmp_path / "session-marker.json"
    marker_payload = {
        "session": "worker-fixture",
        "workspace": str(tmp_path),
        "remote_spec": str(chain_spec_path),
        "identity_digest": "worker-fixture",
        "run_kind": "chain",
        "relaunch_command": (
            f"ARNOLD_RUNTIME_MANIFEST={manifest_path} "
            f"{root / '.venv' / 'bin' / 'python'} -m arnold_pipelines.megaplan chain"
        ),
        "editable_source_branch": branch,
        "editable_source_head": revision,
        "bootstrap_manifest_path": str(manifest_path),
        "manifest_sha256": manifest_identity,
        "manifest_identity": manifest_identity,
        "runtime_binding": {"current_identity": runtime_identity},
    }
    marker_path.write_text(json.dumps(marker_payload, sort_keys=True) + "\n", encoding="utf-8")

    hot_env_path = tmp_path / "runtime.env"
    hot_env_path.write_text(f"export MEGAPLAN_RUNTIME_SRC={root}\n", encoding="utf-8")

    supervisor_root = _fixture_supervisor_root(root, revision)
    probe_environment = dict(os.environ)
    for name in (
        "PYTHONPATH",
        "ARNOLD_RUNTIME_MANIFEST",
        "MEGAPLAN_RUNTIME_LAUNCH_SEED",
        "ARNOLD_BABYSITTER_MARKER_PATH",
        "ARNOLD_BABYSITTER_MANIFEST_IDENTITY",
    ):
        probe_environment.pop(name, None)
    probe = subprocess.run(
        [
            str(supervisor_root / "bin" / "python"),
            "-P",
            "-m",
            "arnold_pipelines.megaplan.cloud.runtime_attestation",
            "probe-supervisor",
            "--expected-source",
            str(root),
            "--expected-revision",
            revision,
            "--expected-runtime",
            str(supervisor_root),
            "--expected-fingerprint",
            "worker-fixture",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=probe_environment,
    )
    supervisor_vector = json.loads(probe.stdout)
    imports = {
        item["module"]: item["path"]
        for item in supervisor_vector["loaded_modules"]
    }
    supervisor_receipt_path = tmp_path / "supervisor-receipt.json"
    supervisor_receipt_path.write_text(
        json.dumps(
            {
                "fingerprint": "worker-fixture",
                "runtime": str(supervisor_root),
                "source": str(root),
                "source_revision": revision,
                "imports": {
                    "arnold": imports["arnold"],
                    "arnold_pipelines": imports["arnold_pipelines"],
                    "megaplan": imports["arnold_pipelines.megaplan"],
                },
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    seed_path = ensure_runtime_launch_seed(
        manifest_path=manifest_path,
        chain_spec_path=chain_spec_path,
        marker_path=marker_path,
        chain_runtime_identity=runtime_identity,
        seed_dir=tmp_path / "runtime-launch-seeds",
        supervisor_receipt_path=supervisor_receipt_path,
        hot_env_path=hot_env_path,
        expected_branch=branch,
    )
    seed_payload = json.loads(seed_path.read_text(encoding="utf-8"))
    validation = validate_runtime_launch_seed(seed_payload, component="worker")
    if validation.get("status") != "ready":
        raise AssertionError(f"fixture launch seed did not validate: {validation}")
    seed_identity = hashlib.sha256(seed_path.read_bytes()).hexdigest()
    marker_payload.update(
        {"seed_path": str(seed_path), "seed_identity": seed_identity}
    )
    marker_path.write_text(json.dumps(marker_payload, sort_keys=True) + "\n", encoding="utf-8")
    # The marker's extra seed receipt fields are telemetry; prove that the
    # complete post-issuance fixture still satisfies the production validator.
    post_marker_validation = validate_runtime_launch_seed(
        seed_payload, component="worker"
    )
    if post_marker_validation.get("status") != "ready":
        raise AssertionError(
            f"fixture launch seed drifted after marker receipt: {post_marker_validation}"
        )

    os.environ["ARNOLD_RUNTIME_MANIFEST"] = str(manifest_path)
    os.environ["ARNOLD_BABYSITTER_MARKER_PATH"] = str(marker_path)
    os.environ["ARNOLD_BABYSITTER_MANIFEST_IDENTITY"] = manifest_identity
    os.environ["MEGAPLAN_RUNTIME_LAUNCH_SEED"] = str(seed_path)
    return manifest_identity, seed_identity, manifest_path, marker_path


def native_proof(
    *,
    backend: str = "codex",
    provider: str = "codex",
    model: str = "gpt-5.5",
    route: str = "codex:gpt-5.5",
    observed_at: str = "2026-08-30T00:00:00+00:00",
) -> dict[str, object]:
    registry = {"constructor": "tests.native:constructor", "generation": "registry-v1", "models": [model]}
    content = {
        "backend": backend,
        "provider": provider,
        "normalized_model": model,
        "route": route,
        "capability_registry": registry,
        "registry_generation": "registry-v1",
        "proof": {"constructable": True, "registry": registry, "preparation": {"ok": True, "backend": backend, "provider": provider, "model": model, "route": route, "operation": "test constructor"}},
        "proof_generation": "proof-v1",
        # Keep test proofs aligned with the canonical upstream family
        # vocabulary used by worker admission (codex, claude, omp upstream,
        # ...); the legacy gpt alias is no longer accepted.
        "family": provider_family(route),
    }
    identity = _digest(content)
    return {
        **content,
        "kind": "native_backend",
        "identity": identity,
        "observed_at": observed_at,
        "digest": _digest({**content, "identity": identity, "observed_at": observed_at}),
    }


def request(tmp_path: Path, **changes: object) -> WorkerAdmissionRequest:
    manifest_identity, seed_identity, _manifest_path, _marker_path = (
        _production_runtime_fixture(tmp_path)
    )

    values: dict[str, object] = {
        "plan_id": "plan",
        "phase": "execute",
        "dispatch_family_id": "family",
        "logical_dispatch_id": "logical",
        "physical_door_id": "door",
        "configured_spec": "codex:gpt-5.5",
        "selected_spec": "codex:gpt-5.5",
        "source_revision": "a" * 40,
        "runtime_vector": {"runtime": "native"},
        "manifest_identity": manifest_identity,
        "seed_identity": seed_identity,
        "dependency_interpreter_identity": "/python",
        "prompt_or_phase_input_identity": "prompt",
        "configured_fallback_chain_identity": "",
        "authorized_route_identity": "codex:gpt-5.5",
        "projection_key": "projection",
        "production_intent": False,
        "ledger_root": tmp_path,
        "route_liveness_resolver": lambda *_: {
            "kind": "native_backend",
            "identity": "backend",
            "digest": "b" * 64,
            "backend": "codex",
            "provider": "codex",
            "normalized_model": "gpt-5.5",
            "capability_registry": "test-native-registry",
            "proof": "test-native-proof",
            "route": "codex:gpt-5.5",
            "observed_at": "2026-01-01T00:00:00+00:00",
            "family": provider_family("codex:gpt-5.5"),
        },
        "memory_headroom_reader": lambda _spec: {"ok": True, "available_bytes": 10},
        "source_runtime_validator": lambda _request: {
            "ok": True,
            "source_revision": "a" * 40,
            "runtime_vector": {"runtime": "native"},
            "manifest_identity": manifest_identity,
            "seed_identity": seed_identity,
            "dependency_interpreter_identity": "/python",
        },
    }
    values.update(changes)
    return WorkerAdmissionRequest(**values)
