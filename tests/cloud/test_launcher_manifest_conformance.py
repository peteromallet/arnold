"""P1 admission conformance: launchers resolve via the runtime manifest.

The per-runtime manifest is the ONLY post-bootstrap resolver.  A PRESENT
manifest must load and validate (corrupt / schema-mismatched manifests exit
78 with a typed ``manifest_invalid`` error before any dispatch).  A genuinely
ABSENT manifest is admitted ONLY by a valid, unexpired ``allow_manifestless``
permit in the ``.runtime_policy.json`` sidecar (``dirname(ARNOLD_RUNTIME_MANIFEST)
/.runtime_policy.json``, or the ``ARNOLD_RUNTIME_POLICY`` override); without a
permit the launcher fails closed with exit 78.  The legacy
``with_name(...)`` / env / SRC_DIR runtime-selection fallback chains are
REMOVED — env pins survive only as explicit operator/test overrides on top of
the manifest.  A drift-check unit exercises ``attest_runtime`` content
attestation.
"""

from __future__ import annotations

import hashlib
import json
import shlex
import subprocess
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WRAPPERS_DIR = REPO_ROOT / "arnold_pipelines" / "megaplan" / "cloud" / "wrappers"
WATCHDOG = WRAPPERS_DIR / "arnold-watchdog"
CHAIN = WRAPPERS_DIR / "arnold-chain"
RUNTIME_LIB = WRAPPERS_DIR / "arnold-supervisor-runtime-lib"
DEFAULT_MANIFEST_PATH = "/workspace/.megaplan/runtime-manifest.json"


def _base_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _write_allow_manifestless_policy(
    policy_path: Path,
    *,
    issued_at: str | None = None,
    expires_at: str | None = None,
    permits: list[dict[str, object]] | None = None,
) -> Path:
    """Write a ``.runtime_policy.json`` sidecar with one valid permit by default.

    The settled permit contract: ``kind="allow_manifestless"``, non-empty
    ``id``, ``issued_at``/``expires_at`` ISO8601 UTC with
    ``0 < expires_at - issued_at <= 24h`` and current-unexpired, plus
    ``actor``, ``reason``, ``evidence``, ``chain_digest``.  ``permits``
    overrides the whole list for multi-record / revoked / expired cases.
    """
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    if permits is not None:
        payload = {"permits": permits}
    else:
        now = datetime.now(timezone.utc)
        payload = {
            "permits": [
                {
                    "kind": "allow_manifestless",
                    "id": "permit-test-1",
                    "issued_at": issued_at or now.isoformat(),
                    "expires_at": expires_at or (now + timedelta(hours=1)).isoformat(),
                    "actor": "launcher-conformance-test",
                    "reason": "wave-2 test harness admission",
                    "evidence": ["test harness injects a valid permit"],
                    "chain_digest": hashlib.sha256(b"test-chain").hexdigest(),
                }
            ]
        }
    policy_path.write_text(json.dumps(payload), encoding="utf-8")
    return policy_path


def _schema_valid_manifest() -> dict[str, object]:
    """A manifest the canonical validator (bootstrap_manifest) accepts: schema
    ``"1"`` with every required top-level and nested key (G2 round 4 — the
    minimal ``{"epic": {"branch": ...}}`` shape only ever passed admission
    through the deleted raw-parse fallback)."""
    now = datetime.now(timezone.utc).isoformat()
    return {
        "runtime_id": "demo-runtime",
        "schema": "1",
        "generation": 1,
        "epic_id": "demo-epic",
        "state": "active",
        "owner": "test",
        "base": {
            "ref": "main",
            "commit": "0" * 40,
            "editable_install_path": "/workspace/.megaplan/editable",
            "venv_path": "/workspace/.megaplan/venv",
        },
        "epic": {
            "branch": "fixer/p1-wave2",
            "worktree_path": "/workspace/demo-epic-worktree",
            "venv_path": "/workspace/.megaplan/venv",
            "runtime_root": "/workspace/demo-epic-worktree",
            "expected_head": "0" * 40,
            "repair_bin": "/usr/local/bin/arnold-babysitter",
            "deps_lockfile": "requirements.lock",
        },
        "indirection": {
            "host_path": "/tmp/demo",
            "container_path": "/workspace/demo",
            "mount_table": [],
            "execution_namespace": "demo",
            "verified_head": "0" * 40,
            "last_verified_at": now,
            "attestation": {
                "module_file": "arnold_pipelines/megaplan/__init__.py",
                "module_digest": "0" * 64,
                "mount_id": "demo-mount",
            },
        },
        "policy": {
            "policy_sha": "0" * 64,
            "model_policy_sha": "0" * 64,
            "sync_policy": "manifest-only",
        },
        "promotions": [],
        "timestamps": {"created": now, "updated": now, "closed": None},
        "gc_policy": "keep",
        "commands": [],
    }


def test_launcher_sources_parse() -> None:
    """bash -n must succeed on the surviving launcher wrappers."""
    for wrapper in (WATCHDOG, WRAPPERS_DIR / "arnold-babysitter"):
        bash_n = subprocess.run(
            ["bash", "-n", str(wrapper)], capture_output=True, text=True
        )
        assert bash_n.returncode == 0, f"bash -n {wrapper.name} failed:\n{bash_n.stderr}"


def test_watchdog_fail_closed_manifest_gate_and_reactive_dispatch() -> None:
    """The watchdog gates through the lib authority and dispatches reactive.

    The shared lib's ``arnold_runtime_manifest_authority`` is the SOLE
    manifest resolver and is wired into the watchdog before any field read;
    the reactive dispatch seam names the mode explicitly.
    """
    text = WATCHDOG.read_text(encoding="utf-8")
    lib = RUNTIME_LIB.read_text(encoding="utf-8")
    # Gate: the lib defines the typed admission kernel with fail-closed paths.
    assert "arnold_runtime_manifest_authority()" in lib
    assert "manifest present without epic.branch; failing closed" in lib
    assert "runtime manifest absent without a valid allow_manifestless permit; failing closed" in lib
    assert "arnold_manifest_allow_manifestless()" in lib
    # The watchdog wires the gate BEFORE field reads.
    assert "arnold_runtime_manifest_authority watchdog" in text
    assert text.index("arnold_runtime_manifest_authority watchdog") < text.index(
        'MANIFEST_RUNTIME_ROOT="$(arnold_runtime_manifest_epic_field epic.runtime_root)"'
    )
    # Dispatch through the babysitter seam; the layered repair-bin resolution
    # was removed with the layered repair stack.
    assert "arnold-babysitter" in text
    assert "CLOUD_WATCHDOG_BABYSITTER_BIN" in text
    # Manifest runtime binding: PYTHONPATH/SRC_DIR follow the manifest runtime
    # root so the selected executable and imported code share one runtime.
    assert "REPAIR_DISPATCH_RUNTIME_SRC" in text
    assert 'REPAIR_DISPATCH_RUNTIME_SRC="$SRC_DIR"' in text
    assert 'REPAIR_DISPATCH_RUNTIME_SRC="$MANIFEST_RUNTIME_ROOT"' in text


def test_lib_manifest_authority_gate_blocks_and_admits(tmp_path: Path) -> None:
    """The shared lib admission kernel: present+valid passes, corrupt blocks,
    absent without permit blocks, absent with valid permit passes."""
    status_dir = tmp_path / "status"

    def run_gate(
        *,
        manifest_path: Path | None,
        policy_path: Path | None,
    ) -> subprocess.CompletedProcess[str]:
        script = f"""
source {str(RUNTIME_LIB)!r}
export MEGAPLAN_SUPERVISOR_STDLIB_PYTHON={shlex.quote(sys.executable)}
export ARNOLD_RUNTIME_MANIFEST={shlex.quote(str(manifest_path)) if manifest_path else ""}
export ARNOLD_RUNTIME_POLICY={shlex.quote(str(policy_path)) if policy_path else ""}
export MEGAPLAN_SUPERVISOR_STATUS_DIR={shlex.quote(str(status_dir))}
arnold_runtime_manifest_authority gate-test
echo "GATE_OK"
"""
        env = dict(os.environ)
        env["PATH"] = f"{Path(sys.executable).parent}:{env.get('PATH', '')}"
        return subprocess.run(
            ["bash", "-c", script],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )

    # 1) Absent manifest without a permit -> fail closed (78).
    blocked = run_gate(
        manifest_path=tmp_path / "no-such-manifest.json",
        policy_path=tmp_path / "no-such-policy.json",
    )
    assert blocked.returncode == 78
    assert "runtime manifest absent without a valid allow_manifestless permit" in blocked.stderr

    # 2) Absent manifest with a valid permit -> admit.
    policy = _write_allow_manifestless_policy(tmp_path / ".runtime_policy.json")
    admitted = run_gate(
        manifest_path=tmp_path / "no-such-manifest.json",
        policy_path=policy,
    )
    assert admitted.returncode == 0, admitted.stderr
    assert "GATE_OK" in admitted.stdout

    # 3) Present corrupt manifest -> fail closed (78) regardless of permit.
    #    The typed load-failure message proves the raw-parse fallback is gone
    #    (G2 round 4): an unreadable manifest is an admission failure, never
    #    a silent empty field read.
    corrupt = tmp_path / "corrupt-manifest.json"
    corrupt.write_text("{not valid json", encoding="utf-8")
    corrupt_blocked = run_gate(
        manifest_path=corrupt,
        policy_path=policy,
    )
    assert corrupt_blocked.returncode == 78
    assert (
        "present but failed to load (corrupt or schema-invalid)" in corrupt_blocked.stderr
    )

    # 4) Present valid manifest (schema-valid, epic.branch) -> admit.  The
    #    manifest must satisfy the canonical bootstrap_manifest validator —
    #    a minimal {"epic": {"branch": ...}} payload is schema-invalid and
    #    now fails closed (it only ever passed through the deleted fallback).
    valid = tmp_path / "valid-manifest.json"
    valid.write_text(
        json.dumps(_schema_valid_manifest()),
        encoding="utf-8",
    )
    valid_ok = run_gate(
        manifest_path=valid,
        policy_path=tmp_path / "no-such-policy.json",
    )
    assert valid_ok.returncode == 0, valid_ok.stderr
    assert "GATE_OK" in valid_ok.stdout

    # 5) DANGLING SYMLINK at the manifest path -> fail closed (78), even with
    #    a valid permit present.  G5 round-13 finding: the old ``[[ -f ]]``
    #    guard FOLLOWED the link to its missing target, reported false, and
    #    collapsed the PRESENT-but-unreadable entry into the manifestless
    #    permit check (which would admit).  Present must never degrade to
    #    absent — the typed dangling-symlink message proves the permit did
    #    not rescue the run.
    dangling_target = tmp_path / "vanished-target.json"
    dangling_link = tmp_path / "dangling-manifest.json"
    dangling_link.symlink_to(dangling_target)  # target never created
    dangling_blocked = run_gate(
        manifest_path=dangling_link,
        policy_path=policy,
    )
    assert dangling_blocked.returncode == 78
    assert "present but unreadable (dangling symlink)" in dangling_blocked.stderr
    assert "GATE_OK" not in dangling_blocked.stdout

    # 6) STAT-INACCESSIBLE manifest path (a parent component is a regular
    #    file -> ENOTDIR, the same OSError fail-closed class as EACCES) ->
    #    exit 78 even with a valid permit: absence is unprovable, so the
    #    entry must never fall through to the manifestless permit check.
    not_a_dir = tmp_path / "plain-file"
    not_a_dir.write_text("i am a file, not a directory", encoding="utf-8")
    enotdir_manifest = not_a_dir / "runtime-manifest.json"
    enotdir_blocked = run_gate(
        manifest_path=enotdir_manifest,
        policy_path=policy,
    )
    assert enotdir_blocked.returncode == 78
    assert "present but unreadable (stat/lstat failed)" in enotdir_blocked.stderr
    assert "GATE_OK" not in enotdir_blocked.stdout


def test_lib_authority_treats_compatibility_only_pointer_as_absent(
    tmp_path: Path,
) -> None:
    """G2 correction 1: a ``compatibility_only`` pointer is NON-AUTHORITATIVE.

    The lib admission gate treats it as ABSENT — the run falls through to the
    permit check (block without a valid permit), it is never "present without
    epic.branch", and the pointer's own contents never admit a run.
    """
    status_dir = tmp_path / "status"
    pointer = tmp_path / "runtime-manifest.json"
    pointer.write_text(
        json.dumps(
            {"compatibility_only": True, "epic": {"branch": "fixer/p1-wave2"}}
        ),
        encoding="utf-8",
    )

    def run_gate(policy_path: Path | None) -> subprocess.CompletedProcess[str]:
        script = f"""
source {str(RUNTIME_LIB)!r}
export MEGAPLAN_SUPERVISOR_STDLIB_PYTHON={shlex.quote(sys.executable)}
export ARNOLD_RUNTIME_MANIFEST={shlex.quote(str(pointer))}
export ARNOLD_RUNTIME_POLICY={shlex.quote(str(policy_path)) if policy_path else ""}
export MEGAPLAN_SUPERVISOR_STATUS_DIR={shlex.quote(str(status_dir))}
arnold_runtime_manifest_authority gate-test
echo "GATE_OK"
"""
        env = dict(os.environ)
        env["PATH"] = f"{Path(sys.executable).parent}:{env.get('PATH', '')}"
        return subprocess.run(
            ["bash", "-c", script],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )

    # No permit -> the compatibility_only pointer is treated as ABSENT -> the
    # absent-manifest fail-closed message, never the present-but-invalid one.
    blocked = run_gate(tmp_path / "no-such-policy.json")
    assert blocked.returncode == 78
    assert (
        "runtime manifest absent without a valid allow_manifestless permit"
        in blocked.stderr
    )
    assert "present without epic.branch" not in blocked.stderr

    # A valid unexpired permit admits the manifestless run (the pointer alone
    # never selects a runtime).
    policy = _write_allow_manifestless_policy(tmp_path / ".runtime_policy.json")
    admitted = run_gate(policy)
    assert admitted.returncode == 0, admitted.stderr
    assert "GATE_OK" in admitted.stdout


def _fake_runtime_manifest(tmp_path: Path, module_digest: str) -> dict:
    """A schema-shaped fake manifest with attestation fields (Phase 2 schema)."""

    tree = tmp_path / "runtime-tree"
    tree.mkdir(parents=True, exist_ok=True)
    module_file = tree / "arnold_pipelines" / "__init__.py"
    module_file.parent.mkdir(parents=True, exist_ok=True)
    module_file.write_text("# observed content\n", encoding="utf-8")
    return {
        "runtime_id": "drift-test-runtime",
        "schema": "1",
        "generation": 1,
        "epic_id": "drift-test-epic",
        "state": "active",
        "owner": "launcher-conformance-test",
        "base": {
            "ref": "refs/heads/base/editable-install",
            "commit": "0" * 40,
            "editable_install_path": str(tree),
            "venv_path": str(tree / "venv"),
        },
        "epic": {
            "branch": "fixer/drift-test",
            "worktree_path": str(tree),
            "venv_path": str(tree / "venv"),
            "runtime_root": str(tree),
            "expected_head": "0" * 40,
            "repair_bin": str(tree / "arnold_pipelines/megaplan/cloud/wrappers/arnold-babysitter"),
            "deps_lockfile": "deps_lockfile.txt",
        },
        "indirection": {
            "host_path": str(tree),
            "container_path": str(tree),
            "mount_table": [],
            "execution_namespace": "drift-test",
            "verified_head": "0" * 40,
            "last_verified_at": "2026-08-07T00:00:00Z",
            "attestation": {
                "module_file": str(module_file),
                "module_digest": module_digest,
                "mount_id": "drift-test-mount",
            },
        },
        "policy": {
            "policy_sha": "0" * 64,
            "model_policy_sha": "0" * 64,
            "sync_policy": {"enabled": False},
        },
        "promotions": [],
        "timestamps": {
            "created": "2026-08-07T00:00:00Z",
            "updated": "2026-08-07T00:00:00Z",
            "closed": None,
        },
        "gc_policy": "default",
        "commands": [],
    }


def test_attest_runtime_detects_tree_content_drift(tmp_path: Path) -> None:
    """attest_runtime must fail loudly when the tree content differs.

    A fake manifest points at a tmp tree whose content does not match the
    actually-observed module; the drift check must surface as
    declared_vs_observed_match False (never a silent pass).
    """
    pytest.importorskip("arnold_pipelines.megaplan.cloud.runtime_manifest")
    from arnold_pipelines.megaplan.cloud.runtime_manifest import (
        attest_runtime,
        bootstrap_manifest,
    )

    declared_digest = hashlib.sha256(b"declared-but-not-observed-content\n").hexdigest()
    manifest_path = tmp_path / "runtime-manifest.json"
    manifest_path.write_text(
        json.dumps(_fake_runtime_manifest(tmp_path, module_digest=declared_digest)),
        encoding="utf-8",
    )

    manifest = bootstrap_manifest(manifest_path)
    result = attest_runtime(manifest)

    assert isinstance(result, dict)
    assert result["declared_vs_observed_match"] is False
    # Contract keys all present.
    for key in ("module_file", "module_digest", "mount_id", "declared_vs_observed_match", "errors"):
        assert key in result


# ── T-0024: raw-but-fail-closed readers distinguish absent from invalid ──────


def test_arnold_chain_refuses_present_but_corrupt_manifest(tmp_path: Path) -> None:
    """arnold-chain pins the runtime manifest BEFORE any launch: a PRESENT
    but corrupt manifest must exit 24 with the typed binding-drift message —
    the corrupt file is never treated as absent/empty and never falls back to
    a fixed engine dir."""
    corrupt = tmp_path / "runtime-manifest.json"
    corrupt.write_text("{not valid json", encoding="utf-8")
    spec = tmp_path / "chain.yaml"
    spec.write_text("milestones: []\n", encoding="utf-8")
    env = {
        **_base_env(),
        "ARNOLD_RUNTIME_MANIFEST": str(corrupt),
        "MEGAPLAN_PROJECT_DIR": str(tmp_path),
    }
    proc = subprocess.run(
        [str(CHAIN), str(spec)],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 24, (proc.stdout, proc.stderr)
    assert "isolated_chain_runtime_binding_drift" in proc.stderr
    assert "manifest lacks epic.runtime_root" in proc.stderr


def test_current_target_resolver_fails_closed_on_present_but_invalid_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """current_target's manifest root reader distinguishes ABSENT from INVALID
    (T-0024): a genuinely missing manifest (env unset) degrades, but a
    PRESENT-but-corrupt manifest raises the typed ManifestError — the
    resolver never falls back to the workspace as the executed tree."""
    from arnold_pipelines.megaplan.cloud.current_target import (
        _manifest_runtime_root,
        _resolver_tree_path,
    )
    from arnold_pipelines.megaplan.cloud.runtime_manifest import (
        ManifestError,
        load_manifest,
    )

    monkeypatch.delenv("ARNOLD_RUNTIME_MANIFEST", raising=False)
    assert _manifest_runtime_root() is None

    # A genuinely missing pinned file is ABSENT -> still degrades.
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(tmp_path / "missing.json"))
    assert _manifest_runtime_root() is None
    workspace = tmp_path / "ws"
    workspace.mkdir()
    assert _resolver_tree_path(workspace, None) == workspace

    # A PRESENT-but-corrupt manifest is INVALID -> typed fail-closed, never
    # a workspace fallback.
    corrupt = tmp_path / "runtime-manifest.json"
    corrupt.write_text("{not valid json", encoding="utf-8")
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(corrupt))
    with pytest.raises(ManifestError, match="present but failed to load"):
        _manifest_runtime_root()
    with pytest.raises(ManifestError, match="present but failed to load"):
        _resolver_tree_path(workspace, None)

    # A canonically schema-valid manifest IS trusted (proves the corrupt
    # rejection is about invalidity, not about the env pin being ignored).
    # The fixture is a full schema "1" manifest that the canonical validator
    # (load_manifest / bootstrap_manifest) accepts — NEVER the schema-less
    # {"epic": {"runtime_root": ...}} shape, which is canonically invalid
    # and must not be blessed as a valid manifest.
    tree = tmp_path / "manifest-tree"
    tree.mkdir()
    manifest_payload = _schema_valid_manifest()
    manifest_payload["epic"]["runtime_root"] = str(tree)  # type: ignore[index]
    valid = tmp_path / "valid.json"
    valid.write_text(json.dumps(manifest_payload), encoding="utf-8")
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(valid))
    assert load_manifest(valid).epic["runtime_root"] == str(tree)
    assert _manifest_runtime_root() == tree
    assert _resolver_tree_path(workspace, None) == tree

    # The reader above is deliberately FIELD-PRESENCE-ONLY (T-0024): it
    # distinguishes ABSENT from INVALID-on-load (corrupt JSON, non-object,
    # missing runtime_root), NOT schema conformance — canonical schema
    # validation lives at launcher admission (exit 78 via bootstrap_manifest).
    # The schema-less {"epic": {"runtime_root": ...}} shape is canonically
    # REFUSED by the validator even though this reader still reads its
    # runtime_root field; the trusted fixture above therefore stays
    # schema-valid so this test never blesses the schema-less shape.
    schema_less = tmp_path / "schema-less.json"
    schema_less.write_text(
        json.dumps({"epic": {"runtime_root": str(tree)}}), encoding="utf-8"
    )
    with pytest.raises(ManifestError, match="missing required fields"):
        load_manifest(schema_less)
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(schema_less))
    assert _manifest_runtime_root() == tree
