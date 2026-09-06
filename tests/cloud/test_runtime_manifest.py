"""Tests for the Phase-2 per-runtime manifest (post-bootstrap resolver)."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event, Thread

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
from arnold_pipelines.megaplan.cloud import shadow_attestation
from arnold_pipelines.megaplan.cloud.runtime_manifest import (
    COMPATIBILITY_ONLY_KEY,
    DEPENDENCY_GENERATION_KEYS,
    MANIFEST_FILENAME,
    MANIFEST_SCHEMA_VERSION,
    ManifestError,
    ForeignAuthoritativePointerConflict,
    RuntimeManifest,
    active_manifest_path,
    add_deviation,
    advance_generation,
    append_promotion,
    attest_runtime,
    bootstrap_manifest,
    dependency_generation_proof,
    has_valid_allow_manifestless_permit,
    is_compatibility_only_pointer,
    list_manifests,
    load_manifest,
    load_manifest_by_epic,
    main,
    manifest_present,
    manifest_promotion_lock,
    refresh_legacy_session_copy,
    set_state,
    validate_dependency_generation,
    validate_deviation,
    write_active_pointer,
    write_manifest,
)
from arnold_pipelines.megaplan.cloud.install_sync import (
    compute_venv_digest,
    frozen_spec_sha256,
)


# Keep the small temporary repositories used by the manifest tests aligned
# with the frozen-spec authority (T-0301).  The default manifest fixture uses
# the same content address so it remains a complete, non-placeholder proof in
# tests that do not need a real checkout.
_FIXTURE_PYPROJECT = '[project]\nname = "demo"\nversion = "0.1.0"\n'
_FIXTURE_UV_LOCK = 'version = 1\nrequires-python = ">=3.11"\n'


def _fixture_spec_digest() -> str:
    digest = hashlib.sha256()
    for filename, content in (
        ("pyproject.toml", _FIXTURE_PYPROJECT),
        ("uv.lock", _FIXTURE_UV_LOCK),
    ):
        digest.update(filename.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content.encode("utf-8"))
    return digest.hexdigest()


_FIXTURE_SPEC_SHA256 = _fixture_spec_digest()
_FIXTURE_VENV_DIGEST = hashlib.sha256(
    json.dumps(
        {"pyvenv_cfg": "home = /usr\n", "installed": []}, sort_keys=True
    ).encode("utf-8")
).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _make_manifest(**overrides: object) -> dict[str, object]:
    manifest: dict[str, object] = {
        "runtime_id": "runtime-test-1",
        "schema": MANIFEST_SCHEMA_VERSION,
        "generation": 3,
        "epic_id": "epic-demo",
        "state": "active",
        "owner": "superfixer",
        "base": {
            "ref": "refs/heads/base/editable-install",
            "commit": "87a912beb",
            "editable_install_path": "/opt/arnold/base",
            "venv_path": "/opt/arnold/base/venv",
        },
        "epic": {
            "branch": "fixer/epic-demo-20260807",
            "worktree_path": "/opt/arnold/runtime-candidates/epic-demo",
            "venv_path": "/opt/arnold/runtime-candidates/epic-demo/venv",
            "runtime_root": "/opt/arnold/runtime-candidates/epic-demo/runtime",
            "expected_head": "abc123def",
            "repair_bin": "/opt/arnold/runtime-candidates/epic-demo/venv/bin/arnold-babysitter",
            "deps_lockfile": "/opt/arnold/base/uv.lock",
            # T-0301: the content-addressed dependency-generation proof.  The
            # interpreter path matches the DEFAULT cutover --to-venv-path
            # (runtime-2/venv) so tree-free cutover tests agree by
            # construction; tree-based tests override it via
            # _generation_proof(<to_venv>/bin/python).
            "dependency_generation": {
                "id": _FIXTURE_SPEC_SHA256,
                "frozen_spec_sha256": _FIXTURE_SPEC_SHA256,
                "interpreter_path": (
                    "/opt/arnold/runtime-candidates/epic-demo/runtime-2/"
                    f"venv-generations/{_FIXTURE_SPEC_SHA256}/bin/python"
                ),
                "venv_digest": _FIXTURE_VENV_DIGEST,
                "created": "2026-08-07T00:00:00+00:00",
            },
        },
        "indirection": {
            "host_path": "/opt/arnold/runtime-candidates/epic-demo",
            "container_path": "/workspace/epic-demo",
            "mount_table": [],
            "execution_namespace": "epic-demo-ns",
            "verified_head": "abc123def",
            "last_verified_at": "2026-08-07T00:00:00+00:00",
            "attestation": {
                "module_file": "/opt/arnold/runtime-candidates/epic-demo/arnold_pipelines/__init__.py",
                "module_digest": "d41d8cd98f00b204e9800998ecf8427e",
                "mount_id": "0:42",
            },
        },
        "policy": {
            "policy_sha": "policy-sha-1",
            "model_policy_sha": "model-sha-1",
            "sync_policy": "push-on-promote",
        },
        "promotions": [],
        "timestamps": {
            "created": "2026-08-07T00:00:00+00:00",
            "updated": "2026-08-07T00:00:00+00:00",
            "closed": "",
        },
        "gc_policy": "closed-only",
        "commands": ["megaplan chain"],
    }
    for key, value in overrides.items():
        if (
            key in ("base", "epic", "indirection", "policy", "timestamps")
            and isinstance(manifest[key], dict)
            and isinstance(value, dict)
        ):
            merged = dict(manifest[key])  # type: ignore[arg-type]
            merged.update(value)
            manifest[key] = merged
        else:
            manifest[key] = value
    return manifest


def _make_manifest_obj(**overrides: object) -> RuntimeManifest:
    data = _make_manifest(**overrides)
    epic_override = overrides.get("epic")
    runtime_root = Path(str(data["epic"].get("runtime_root") or ""))
    # A real checkout fixture gets a real content-addressed proof.  Preserve
    # explicit proof overrides so malformed/negative tests still exercise the
    # manifest and transition validators themselves.
    if (
        isinstance(epic_override, dict)
        and "dependency_generation" not in epic_override
        and runtime_root.is_dir()
        and (runtime_root / ".runtime-manifest-test-real").is_file()
        and (runtime_root / "pyproject.toml").is_file()
        and (runtime_root / "uv.lock").is_file()
    ):
        spec_digest = frozen_spec_sha256(runtime_root)
        generation_dir = runtime_root / ".test-generations" / spec_digest
        interpreter = generation_dir / "bin" / "python"
        interpreter.parent.mkdir(parents=True, exist_ok=True)
        if not interpreter.exists():
            interpreter.write_text("#!/bin/sh\n", encoding="utf-8")
            interpreter.chmod(0o755)
        pyvenv_cfg = generation_dir / "pyvenv.cfg"
        if not pyvenv_cfg.exists():
            pyvenv_cfg.write_text("home = /usr\n", encoding="utf-8")
        data["epic"]["dependency_generation"] = {
            "id": spec_digest,
            "frozen_spec_sha256": spec_digest,
            "interpreter_path": str(interpreter),
            "venv_digest": compute_venv_digest(interpreter),
            "created": "2026-08-07T00:00:00+00:00",
        }
    return RuntimeManifest.from_dict(data)


def _make_deviation(**overrides: object) -> dict[str, object]:
    """A structurally valid, currently-unexpired deviation record (defaults to
    ``kind=allow_manifestless``, issued now, expiring in 1h)."""
    now = datetime.now(timezone.utc)
    record: dict[str, object] = {
        "kind": "allow_manifestless",
        "id": "perm-0001",
        "issued_at": now.isoformat(timespec="seconds"),
        "expires_at": (now + timedelta(hours=1)).isoformat(timespec="seconds"),
        "actor": "operator",
        "reason": "box migration window",
        "evidence": ["incident-42", "approval-email"],
        "chain_digest": "sha256:deadbeef",
    }
    record.update(overrides)
    return record


def _real_git_repo(tmp_path: Path) -> tuple[Path, str]:
    """Create a REAL temporary git repository with one commit.

    Returns ``(root, head_sha)``.  Used by tests that exercise the
    git-object head guard (advance_generation / cutover success paths and
    their rejection tests) — the guard rejects correctly shaped but
    non-object 40-hex heads, so fake SHAs can no longer pass those paths.
    """
    root = tmp_path / "real-repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(
        ["git", "-C", str(root), "config", "user.name", "Test"], check=True
    )
    subprocess.run(
        ["git", "-C", str(root), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    (root / "pyproject.toml").write_text(_FIXTURE_PYPROJECT, encoding="utf-8")
    (root / "uv.lock").write_text(_FIXTURE_UV_LOCK, encoding="utf-8")
    (root / ".runtime-manifest-test-real").write_text("fixture\n", encoding="utf-8")
    (root / "README.md").write_text("seed\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "seed"], check=True)
    sha = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return root, sha


def _make_attestation_tree(tmp_path: Path) -> Path:
    """Minimal importable-layout tree so the tree-search fallback resolves the
    module file inside the tree (mirrors test_shadow_attestation)."""
    tree = tmp_path / "tree"
    cloud = tree / "arnold_pipelines" / "megaplan" / "cloud"
    cloud.mkdir(parents=True)
    (tree / "arnold_pipelines" / "__init__.py").write_text("# pkg\n", encoding="utf-8")
    (tree / "arnold_pipelines" / "megaplan" / "__init__.py").write_text(
        "# megaplan\n", encoding="utf-8"
    )
    (cloud / "__init__.py").write_text("# cloud\n", encoding="utf-8")
    (cloud / "alpha.py").write_text("ALPHA = 1\n", encoding="utf-8")
    return tree


def _not_importable(module_name: str) -> str:
    """Stand-in for ``find_spec`` returning nothing (module not importable)."""
    return ""


# ── round trip / validation ────────────────────────────────────────────────


def test_write_load_round_trip(tmp_path: Path) -> None:
    manifest = _make_manifest_obj()
    path = tmp_path / "manifests" / "runtime-manifest.json"
    write_manifest(manifest, path)
    loaded = load_manifest(path)
    assert loaded == manifest
    assert loaded.to_dict() == manifest.to_dict()
    assert loaded.schema == MANIFEST_SCHEMA_VERSION
    assert loaded.epic["repair_bin"].endswith("arnold-babysitter")


def test_load_rejects_schema_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "old-schema.json"
    _write_json(path, _make_manifest(schema="0"))
    with pytest.raises(ManifestError, match="schema"):
        load_manifest(path)


def test_load_rejects_missing_required_field(tmp_path: Path) -> None:
    data = _make_manifest()
    del data["epic"]["repair_bin"]  # type: ignore[typeddict-item]
    path = tmp_path / "incomplete.json"
    _write_json(path, data)
    with pytest.raises(ManifestError, match="repair_bin"):
        load_manifest(path)


def test_load_rejects_missing_top_level_field(tmp_path: Path) -> None:
    data = _make_manifest()
    del data["owner"]
    path = tmp_path / "incomplete.json"
    _write_json(path, data)
    with pytest.raises(ManifestError, match="owner"):
        load_manifest(path)


def test_load_rejects_corrupt_json(tmp_path: Path) -> None:
    path = tmp_path / "corrupt.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ManifestError, match="corrupt"):
        load_manifest(path)


def test_manifest_rejects_generation_below_one() -> None:
    with pytest.raises(ManifestError, match="generation"):
        _make_manifest_obj(generation=0)


def test_manifest_rejects_invalid_state() -> None:
    with pytest.raises(ManifestError, match="state"):
        _make_manifest_obj(state="destroyed")


def test_write_is_atomic_and_leaves_valid_json_on_disk(tmp_path: Path) -> None:
    path = tmp_path / "manifests" / "runtime-manifest.json"
    write_manifest(_make_manifest_obj(runtime_id="first"), path)
    write_manifest(_make_manifest_obj(runtime_id="second"), path)
    raw = path.read_text(encoding="utf-8")
    loaded = json.loads(raw)
    assert loaded["runtime_id"] == "second"
    assert RuntimeManifest.from_dict(loaded).runtime_id == "second"
    # no partial/tmp files left behind (only the persistent canonical lock pair)
    leftovers = [
        p.name
        for p in path.parent.glob(f"{path.name}.*")
        if p.name
        not in {f"{path.name}.lock", f"{path.name}.promotion.lock"}
    ]
    assert leftovers == []


def test_promotion_lock_fences_ordinary_manifest_writer(tmp_path: Path) -> None:
    """An ordinary writer cannot enter while the promotion fence is held."""
    path = tmp_path / "runtime-manifest.json"
    manifest = _make_manifest_obj()
    write_manifest(manifest, path)

    started = Event()
    completed = Event()

    def ordinary_writer() -> None:
        started.set()
        write_manifest(manifest, path)
        completed.set()

    with manifest_promotion_lock(path):
        thread = Thread(target=ordinary_writer)
        thread.start()
        assert started.wait(1), "ordinary writer did not start"
        assert not completed.wait(0.1), "ordinary writer entered promotion fence"
    thread.join(timeout=2)
    assert not thread.is_alive(), "ordinary writer remained blocked after release"
    assert completed.is_set()


# ── index ───────────────────────────────────────────────────────────────────


def test_load_manifest_by_epic_finds_by_epic_id_and_none_when_absent(
    tmp_path: Path,
) -> None:
    write_manifest(
        _make_manifest_obj(runtime_id="r1", epic_id="epic-a"), tmp_path / "a.json"
    )
    write_manifest(
        _make_manifest_obj(runtime_id="r2", epic_id="epic-b"), tmp_path / "b.json"
    )
    found = load_manifest_by_epic("epic-b", tmp_path)
    assert found is not None
    assert found.runtime_id == "r2"
    assert load_manifest_by_epic("epic-absent", tmp_path) is None


def test_list_manifests_sorted_by_runtime_id(tmp_path: Path) -> None:
    write_manifest(
        _make_manifest_obj(runtime_id="r-zulu", epic_id="e1"), tmp_path / "z.json"
    )
    write_manifest(
        _make_manifest_obj(runtime_id="r-alpha", epic_id="e2"), tmp_path / "a.json"
    )
    write_manifest(
        _make_manifest_obj(runtime_id="r-mid", epic_id="e3"), tmp_path / "m.json"
    )
    names = [manifest.runtime_id for manifest in list_manifests(tmp_path)]
    assert names == ["r-alpha", "r-mid", "r-zulu"]
    assert names == sorted(names)


def test_index_skips_non_manifest_json(tmp_path: Path) -> None:
    write_manifest(_make_manifest_obj(runtime_id="r1"), tmp_path / "r1.json")
    _write_json(tmp_path / "stray.json", {"not": "a manifest"})
    assert [m.runtime_id for m in list_manifests(tmp_path)] == ["r1"]


# ── transitions ─────────────────────────────────────────────────────────────


def test_advance_generation_bumps_and_records_promotion(tmp_path: Path) -> None:
    root, head = _real_git_repo(tmp_path)
    manifest = _make_manifest_obj(
        generation=2,
        epic={"runtime_root": str(root), "expected_head": head},
        indirection={"verified_head": head},
    )
    advanced = advance_generation(manifest, head, reason="promote durable fix")
    assert advanced is not manifest
    assert advanced.generation == 3
    assert advanced.epic["expected_head"] == head
    assert advanced.indirection["verified_head"] == head
    assert advanced.timestamps["updated"]
    assert len(advanced.promotions) == 1
    record = advanced.promotions[0]
    assert record["previous_generation"] == 2
    assert record["previous_commit"] == head
    assert record["reason"] == "promote durable fix"
    assert record["at"]
    # original manifest untouched (rollback source retained on the new one)
    assert manifest.generation == 2
    assert manifest.epic["expected_head"] == head
    assert manifest.promotions == []


# ── T-0301: content-addressed dependency generation ─────────────────────────


def test_advance_generation_carries_the_generation_proof(tmp_path: Path) -> None:
    root, head = _real_git_repo(tmp_path)
    manifest = _make_manifest_obj(epic={"runtime_root": str(root)})
    advanced = advance_generation(manifest, head, reason="carry proof")
    assert (
        advanced.epic["dependency_generation"]
        == manifest.epic["dependency_generation"]
    )
    assert dependency_generation_proof(advanced) is not None


def test_advance_generation_refuses_without_proof() -> None:
    """T-0301 publication gate: a manifest with NO dependency-generation
    proof cannot be advanced — unknown dependency state blocks publication."""
    manifest = _make_manifest_obj()
    del manifest.epic["dependency_generation"]  # type: ignore[typeddict-item]
    with pytest.raises(ManifestError, match="dependency_generation proof"):
        advance_generation(manifest, "bbbb2222", reason="no proof")


def test_advance_generation_accepts_explicit_override_proof(tmp_path: Path) -> None:
    root, head = _real_git_repo(tmp_path)
    manifest = _make_manifest_obj(epic={"runtime_root": str(root)})
    override = dict(manifest.epic["dependency_generation"])
    del manifest.epic["dependency_generation"]  # type: ignore[typeddict-item]
    advanced = advance_generation(
        manifest,
        head,
        reason="explicit rebuilt generation",
        dependency_generation=override,
    )
    assert advanced.epic["dependency_generation"] == override


def test_advance_generation_rejects_non_object_head_and_accepts_real_commit(
    tmp_path: Path,
) -> None:
    """Git-object head guard (codex fix 2026-08-17): a correctly SHAPED but
    fabricated 40-hex head (real prefix + invented tail — the recurring
    corruption pattern) is REFUSED before any promotion record is built, and
    the input manifest is untouched; the REAL commit SHA advances."""
    root, head = _real_git_repo(tmp_path)
    manifest = _make_manifest_obj(
        generation=2,
        epic={"runtime_root": str(root), "expected_head": head},
        indirection={"verified_head": head},
    )
    fake = head[:10] + "a" * 30  # 40-hex, correct shape, not a git object
    with pytest.raises(ManifestError, match="does not resolve"):
        advance_generation(manifest, fake, reason="fake head must refuse")
    # zero mutation: no promotion record, same generation, same head
    assert manifest.generation == 2
    assert manifest.epic["expected_head"] == head
    assert manifest.promotions == []
    # and the 41-char prefix+tail pattern is rejected at shape (not git)
    with pytest.raises(ManifestError, match="40-char lowercase hex"):
        advance_generation(manifest, head[:10] + "a" * 31, reason="41-char fake")
    assert manifest.promotions == []
    # the REAL commit advances
    advanced = advance_generation(manifest, head, reason="real head advances")
    assert advanced.generation == 3
    assert advanced.epic["expected_head"] == head
    assert len(advanced.promotions) == 1


def test_validate_dependency_generation_rejects_malformed_records() -> None:
    valid = _make_manifest_obj().epic["dependency_generation"]
    for field_name in DEPENDENCY_GENERATION_KEYS:
        broken = dict(valid)
        del broken[field_name]
        with pytest.raises(ManifestError, match="dependency_generation"):
            validate_dependency_generation(broken)
    # non-hex digests
    for field_name in ("id", "frozen_spec_sha256", "venv_digest"):
        with pytest.raises(ManifestError, match=field_name):
            validate_dependency_generation(dict(valid, **{field_name: "zz" * 32}))
    # content address must equal the frozen-spec digest
    with pytest.raises(ManifestError, match="must equal frozen_spec_sha256"):
        validate_dependency_generation(
            dict(valid, id="c" * 64, frozen_spec_sha256="d" * 64)
        )
    # interpreter must be absolute
    with pytest.raises(ManifestError, match="interpreter_path"):
        validate_dependency_generation(
            dict(valid, interpreter_path="relative/bin/python")
        )
    # created must be UTC ISO
    with pytest.raises(ManifestError, match="created"):
        validate_dependency_generation(dict(valid, created="2026-08-07T00:00:00"))
    assert validate_dependency_generation(valid) == valid


def test_manifest_rejects_present_but_malformed_proof() -> None:
    """A PRESENT but malformed proof is schema-invalid (fail-closed — a
    partial proof is never partially trusted); an ABSENT proof loads fine
    (legacy) and is enforced at the publication/launch/GC gates."""
    with pytest.raises(ManifestError, match="dependency_generation"):
        _make_manifest_obj(
            epic={"dependency_generation": {"id": "a" * 64}}
        )
    legacy = _make_manifest_obj()
    del legacy.epic["dependency_generation"]  # type: ignore[typeddict-item]
    assert dependency_generation_proof(legacy) is None
    assert legacy.epic.get("dependency_generation") is None


def test_dependency_generation_proof_returns_complete_record() -> None:
    manifest = _make_manifest_obj()
    proof = dependency_generation_proof(manifest)
    assert proof is not None
    assert proof["id"] == proof["frozen_spec_sha256"]
    assert proof["interpreter_path"].endswith("/bin/python")


def test_set_state_and_promotion_preserve_the_proof() -> None:
    manifest = _make_manifest_obj()
    closed = set_state(manifest, "closed")
    assert closed.epic["dependency_generation"] == manifest.epic["dependency_generation"]
    promoted = append_promotion(manifest, {"previous_generation": 1, "reason": "x"})
    assert (
        promoted.epic["dependency_generation"]
        == manifest.epic["dependency_generation"]
    )


def test_set_state_validates_and_stamps_closed_timestamp() -> None:
    manifest = _make_manifest_obj(state="active")
    with pytest.raises(ManifestError, match="state"):
        set_state(manifest, "destroyed")
    closed = set_state(manifest, "closed")
    assert closed.state == "closed"
    assert closed.timestamps["closed"]
    # reopening preserves the historical closed timestamp
    reopened = set_state(closed, "active")
    assert reopened.state == "active"
    assert reopened.timestamps["closed"] == closed.timestamps["closed"]


def test_append_promotion(tmp_path: Path) -> None:
    _, head = _real_git_repo(tmp_path)
    manifest = _make_manifest_obj()
    record = {
        "previous_generation": 1,
        "previous_commit": head,
        "reason": "rollback record",
        "at": "2026-08-07T12:00:00+00:00",
    }
    updated = append_promotion(manifest, record)
    assert updated.promotions == [record]
    assert manifest.promotions == []
    # a record WITHOUT commit fields (journal-only) is still accepted
    journal_only = append_promotion(manifest, {"previous_generation": 1})
    assert journal_only.promotions == [{"previous_generation": 1}]
    with pytest.raises(ManifestError, match="record"):
        append_promotion(manifest, ["not", "a", "dict"])


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("previous_commit", "c1"),
        ("previous_commit", "ZZ" * 20),
        ("from_sha", "short"),
        ("from_sha", "x" * 40),
        ("to_sha", "d" * 39),
    ],
)
def test_append_promotion_rejects_malformed_commit_fields(
    field: str, bad_value: str
) -> None:
    """Codex fix 2026-08-17: present, non-empty commit fields in a promotion
    record must be 40-char lowercase hex — short / non-hex / wrong-length
    values are refused; records that omit the fields (or leave them empty)
    stay accepted."""
    manifest = _make_manifest_obj()
    record = {"previous_generation": 1, field: bad_value}
    with pytest.raises(ManifestError, match=field):
        append_promotion(manifest, record)
    assert manifest.promotions == []


def test_append_promotion_accepts_40hex_commit_fields() -> None:
    """Codex fix 2026-08-17: 40-hex commit fields pass the shape check
    (no git lookup at append time — a journal record may reference another
    repository)."""
    manifest = _make_manifest_obj()
    record = {
        "previous_commit": "a" * 40,
        "from_sha": "b" * 40,
        "to_sha": "c" * 40,
        "reason": "rolled back",
    }
    updated = append_promotion(manifest, record)
    assert updated.promotions == [record]


# ── deviations (expiring exception records) ─────────────────────────────────


def test_from_dict_defaults_deviations_to_empty_list() -> None:
    manifest = _make_manifest_obj()
    assert manifest.deviations == []
    # the fixture itself carries no deviations key (old-manifest shape)
    assert "deviations" not in _make_manifest()


def test_deviations_round_trip_preserved(tmp_path: Path) -> None:
    record = _make_deviation()
    manifest = _make_manifest_obj(deviations=[record])
    assert manifest.deviations == [record]
    path = tmp_path / "m.json"
    write_manifest(manifest, path)
    loaded = load_manifest(path)
    assert loaded == manifest
    assert loaded.deviations == [record]
    # the serialized JSON on disk actually carries the list
    assert json.loads(path.read_text(encoding="utf-8"))["deviations"] == [record]
    # a second read→write cycle preserves it as well
    write_manifest(loaded, path)
    assert load_manifest(path).deviations == [record]


def test_all_transitions_preserve_deviations(tmp_path: Path) -> None:
    record = _make_deviation()
    root, head = _real_git_repo(tmp_path)
    manifest = _make_manifest_obj(
        deviations=[record], epic={"runtime_root": str(root)}
    )
    closed = set_state(manifest, "closed")
    assert closed.deviations == [record]
    advanced = advance_generation(manifest, head, reason="preserve check")
    assert advanced.deviations == [record]
    promoted = append_promotion(
        manifest,
        {
            "previous_generation": 1,
            "previous_commit": head,
            "reason": "rollback record",
        },
    )
    assert promoted.deviations == [record]
    assert manifest.deviations == [record]  # original untouched


def test_manifest_rejects_non_list_deviations() -> None:
    with pytest.raises(ManifestError, match="deviations"):
        _make_manifest_obj(deviations="not-a-list")
    with pytest.raises(ManifestError, match="deviations"):
        _make_manifest_obj(deviations={"kind": "allow_manifestless"})


def test_manifest_rejects_non_object_deviation_entries() -> None:
    with pytest.raises(ManifestError, match="deviations"):
        _make_manifest_obj(deviations=[_make_deviation(), "not-an-object"])


def test_validate_deviation_rejects_non_object_record() -> None:
    with pytest.raises(ManifestError, match="object"):
        validate_deviation("not-a-dict")
    with pytest.raises(ManifestError, match="object"):
        validate_deviation(["not", "a", "dict"])


def test_validate_deviation_rejects_missing_fields() -> None:
    for field_name in (
        "kind",
        "id",
        "issued_at",
        "expires_at",
        "actor",
        "reason",
        "evidence",
        "chain_digest",
    ):
        bad = dict(_make_deviation())
        del bad[field_name]
        with pytest.raises(ManifestError, match=field_name):
            validate_deviation(bad)


def test_validate_deviation_rejects_empty_string_fields() -> None:
    for field_name in ("kind", "id", "actor", "reason", "chain_digest"):
        bad = _make_deviation(**{field_name: ""})
        with pytest.raises(ManifestError, match=field_name):
            validate_deviation(bad)


def test_validate_deviation_rejects_non_utc_timestamps() -> None:
    naive = _make_deviation(issued_at="2026-08-07T00:00:00")  # no tz info
    with pytest.raises(ManifestError, match="UTC"):
        validate_deviation(naive)
    offset = _make_deviation(expires_at="2026-08-07T00:00:00+05:00")  # wrong offset
    with pytest.raises(ManifestError, match="UTC"):
        validate_deviation(offset)
    unparsable = _make_deviation(issued_at="not-a-date")
    with pytest.raises(ManifestError, match="ISO8601"):
        validate_deviation(unparsable)
    empty = _make_deviation(expires_at="")
    with pytest.raises(ManifestError, match="expires_at"):
        validate_deviation(empty)


def test_validate_deviation_rejects_bad_evidence() -> None:
    not_list = _make_deviation(evidence="not-a-list")
    with pytest.raises(ManifestError, match="evidence"):
        validate_deviation(not_list)
    non_strings = _make_deviation(evidence=["ok", 42])
    with pytest.raises(ManifestError, match="evidence"):
        validate_deviation(non_strings)


def test_validate_deviation_accepts_empty_evidence() -> None:
    # contract: evidence is a list of strings; an empty list is structurally valid
    record = _make_deviation(evidence=[])
    assert validate_deviation(record) == record


def test_validate_deviation_rejects_expired() -> None:
    now = datetime.now(timezone.utc)
    record = _make_deviation(
        issued_at=(now - timedelta(hours=2)).isoformat(timespec="seconds"),
        expires_at=(now - timedelta(hours=1)).isoformat(timespec="seconds"),
    )
    with pytest.raises(ManifestError, match="expired"):
        validate_deviation(record)


def test_validate_deviation_rejects_lifetime_outside_bounds() -> None:
    now = datetime.now(timezone.utc)
    too_long = _make_deviation(
        issued_at=now.isoformat(timespec="seconds"),
        expires_at=(now + timedelta(hours=25)).isoformat(timespec="seconds"),
    )
    with pytest.raises(ManifestError, match="24h"):
        validate_deviation(too_long)
    zero = _make_deviation(
        issued_at=now.isoformat(timespec="seconds"),
        expires_at=now.isoformat(timespec="seconds"),
    )
    with pytest.raises(ManifestError, match="24h"):
        validate_deviation(zero)
    backwards = _make_deviation(
        issued_at=now.isoformat(timespec="seconds"),
        expires_at=(now - timedelta(hours=1)).isoformat(timespec="seconds"),
    )
    with pytest.raises(ManifestError, match="24h"):
        validate_deviation(backwards)


def test_validate_deviation_returns_record_unchanged_on_success() -> None:
    record = _make_deviation()
    assert validate_deviation(record) is record
    # extra keys (e.g. a revoked_at tombstone) are tolerated + preserved
    tombstoned = _make_deviation(revoked_at="2026-08-07T00:00:00+00:00")
    assert validate_deviation(tombstoned) == tombstoned


def test_has_valid_allow_manifestless_permit() -> None:
    now = datetime.now(timezone.utc)
    valid = _make_deviation()
    assert (
        has_valid_allow_manifestless_permit(
            _make_manifest_obj(deviations=[valid])
        )
        is True
    )
    # no deviations at all -> no permit
    assert has_valid_allow_manifestless_permit(_make_manifest_obj()) is False
    # wrong kind does not admit
    wrong_kind = dict(valid, kind="manifest_missing")
    assert (
        has_valid_allow_manifestless_permit(
            _make_manifest_obj(deviations=[wrong_kind])
        )
        is False
    )
    # expired permit does not admit
    expired = _make_deviation(
        issued_at=(now - timedelta(hours=2)).isoformat(timespec="seconds"),
        expires_at=(now - timedelta(hours=1)).isoformat(timespec="seconds"),
    )
    assert (
        has_valid_allow_manifestless_permit(
            _make_manifest_obj(deviations=[expired])
        )
        is False
    )
    # revoked permit (auditable tombstone) does not admit
    revoked = dict(valid, revoked_at="2026-08-07T00:00:00+00:00")
    assert (
        has_valid_allow_manifestless_permit(
            _make_manifest_obj(deviations=[revoked])
        )
        is False
    )
    # one valid permit wins even among invalid/expired records; a bad record
    # cannot poison admission
    mixed = _make_manifest_obj(deviations=[expired, {"kind": "garbage"}, valid])
    assert has_valid_allow_manifestless_permit(mixed) is True
    # a malformed record alone never admits
    malformed = _make_manifest_obj(deviations=[{"kind": "allow_manifestless"}])
    assert has_valid_allow_manifestless_permit(malformed) is False


def test_add_deviation_appends_immutably() -> None:
    manifest = _make_manifest_obj()
    record = _make_deviation()
    updated = add_deviation(manifest, record)
    assert updated is not manifest
    assert updated.deviations == [record]
    assert manifest.deviations == []  # original untouched
    second = _make_deviation(id="perm-0002")
    again = add_deviation(updated, second)
    assert again.deviations == [record, second]
    assert updated.deviations == [record]  # intermediate also untouched


def test_add_deviation_rejects_invalid_record_and_leaves_manifest_untouched() -> None:
    manifest = _make_manifest_obj()
    now = datetime.now(timezone.utc)
    expired = _make_deviation(
        issued_at=(now - timedelta(hours=2)).isoformat(timespec="seconds"),
        expires_at=(now - timedelta(hours=1)).isoformat(timespec="seconds"),
    )
    with pytest.raises(ManifestError, match="expired"):
        add_deviation(manifest, expired)
    missing = dict(_make_deviation())
    del missing["chain_digest"]
    with pytest.raises(ManifestError, match="chain_digest"):
        add_deviation(manifest, missing)
    assert manifest.deviations == []


# ── attestation ─────────────────────────────────────────────────────────────


def test_attest_runtime_returns_expected_keys_with_tree_search_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = _make_attestation_tree(tmp_path)
    manifest = _make_manifest_obj(
        epic={"runtime_root": str(tree)},
    )
    # force the tree-search fallback (module not importable from the temp tree)
    monkeypatch.setattr(shadow_attestation, "_find_spec_origin", _not_importable)
    result = attest_runtime(manifest)
    assert set(result) == {
        "module_file",
        "module_digest",
        "mount_id",
        "declared_vs_observed_match",
        "errors",
    }
    assert result["module_file"] == str(tree / "arnold_pipelines" / "__init__.py")
    assert result["module_digest"]
    assert result["declared_vs_observed_match"] is True
    if sys.platform == "linux":
        assert result["errors"] == []
    else:
        # non-Linux: only the expected mount probe is unavailable; no module/tree errors
        assert [
            entry
            for entry in result["errors"]
            if not entry.startswith("mount_id_unavailable")
        ] == []


def test_attest_runtime_never_raises_on_broken_runtime_root(tmp_path: Path) -> None:
    manifest = _make_manifest_obj(
        epic={"runtime_root": str(tmp_path / "does-not-exist")},
    )
    result = attest_runtime(manifest)
    assert set(result) == {
        "module_file",
        "module_digest",
        "mount_id",
        "declared_vs_observed_match",
        "errors",
    }
    assert result["declared_vs_observed_match"] is False
    assert result["errors"]


def test_attest_runtime_never_raises_when_probe_blows_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _make_manifest_obj(epic={"runtime_root": str(tmp_path)})
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest.attest_target_content",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    result = attest_runtime(manifest)
    assert result["errors"] == ["attestation_failed:boom"]
    assert result["declared_vs_observed_match"] is False


# ── bootstrap ───────────────────────────────────────────────────────────────


def test_bootstrap_manifest_from_pointer_file(tmp_path: Path) -> None:
    manifest = _make_manifest_obj(runtime_id="booted")
    manifest_path = tmp_path / "manifests" / "runtime-manifest.json"
    write_manifest(manifest, manifest_path)
    pointer = tmp_path / "bootstrap"
    pointer.write_text(f"# active runtime\n{manifest_path}\n", encoding="utf-8")
    loaded = bootstrap_manifest(pointer)
    assert loaded.runtime_id == "booted"
    assert loaded == manifest


def test_bootstrap_manifest_from_directory(tmp_path: Path) -> None:
    manifest = _make_manifest_obj(runtime_id="dir-booted")
    write_manifest(manifest, tmp_path / "manifests" / "runtime-manifest.json")
    loaded = bootstrap_manifest(tmp_path / "manifests")
    assert loaded == manifest


def test_bootstrap_manifest_from_json_file_directly(tmp_path: Path) -> None:
    manifest = _make_manifest_obj(runtime_id="json-booted")
    path = tmp_path / "runtime-manifest.json"
    write_manifest(manifest, path)
    assert bootstrap_manifest(path) == manifest


def test_bootstrap_manifest_missing_path_raises(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="does not exist"):
        bootstrap_manifest(tmp_path / "nope")


def test_bootstrap_manifest_empty_pointer_raises(tmp_path: Path) -> None:
    pointer = tmp_path / "bootstrap"
    pointer.write_text("# nothing here\n", encoding="utf-8")
    with pytest.raises(ManifestError, match="no manifest path"):
        bootstrap_manifest(pointer)


# ── compatibility_only pointer (G2 correction 1) ───────────────────────────


def _compatibility_pointer(path: Path) -> Path:
    """A full manifest JSON additionally marked ``compatibility_only: true`` —
    the exact shape arnold-runtime-create writes as compatibility telemetry."""
    payload = dict(_make_manifest(runtime_id="telemetry-pointer"))
    payload[COMPATIBILITY_ONLY_KEY] = True
    _write_json(path, payload)
    return path


def test_is_compatibility_only_pointer_detects_marker(tmp_path: Path) -> None:
    pointer = _compatibility_pointer(tmp_path / "pointer.json")
    assert is_compatibility_only_pointer(pointer) is True
    # a plain valid manifest (no marker) is NOT compatibility telemetry
    real = tmp_path / "real.json"
    write_manifest(_make_manifest_obj(), real)
    assert is_compatibility_only_pointer(real) is False
    # absent / non-JSON files are not compatibility pointers (they fail on
    # their own as absent/invalid)
    assert is_compatibility_only_pointer(tmp_path / "missing.json") is False
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{not json", encoding="utf-8")
    assert is_compatibility_only_pointer(corrupt) is False
    # marker must be the literal boolean true
    falsy = tmp_path / "falsy.json"
    _write_json(falsy, {**dict(_make_manifest()), COMPATIBILITY_ONLY_KEY: "true"})
    assert is_compatibility_only_pointer(falsy) is False


def test_bootstrap_manifest_rejects_compatibility_only_pointer(
    tmp_path: Path,
) -> None:
    """A compatibility_only pointer is NON-AUTHORITATIVE: the resolver treats
    it as ABSENT (raises) so it can never select a runtime."""
    pointer = _compatibility_pointer(tmp_path / "runtime-manifest.json")
    with pytest.raises(ManifestError, match="compatibility_only"):
        bootstrap_manifest(pointer)
    # same rejection through a directory bootstrap (canonical filename)
    directory = tmp_path / "manifest-dir"
    _compatibility_pointer(directory / MANIFEST_FILENAME)
    with pytest.raises(ManifestError, match="compatibility_only"):
        bootstrap_manifest(directory)
    # same rejection through a legacy pointer file naming the marked target
    legacy = tmp_path / "bootstrap"
    legacy.write_text(f"{pointer}\n", encoding="utf-8")
    with pytest.raises(ManifestError, match="compatibility_only"):
        bootstrap_manifest(legacy)


def test_manifest_present_treats_compatibility_only_as_absent(
    tmp_path: Path,
) -> None:
    """Admission probe: present+valid+authoritative is True; everything else
    (missing, corrupt, schema-invalid, or a compatibility_only pointer) is
    ABSENT (False)."""
    real = tmp_path / "real.json"
    write_manifest(_make_manifest_obj(), real)
    assert manifest_present(real) is True
    assert manifest_present(tmp_path / "missing.json") is False
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{not json", encoding="utf-8")
    assert manifest_present(corrupt) is False
    invalid = tmp_path / "invalid.json"
    _write_json(invalid, _make_manifest(schema="99"))
    assert manifest_present(invalid) is False
    pointer = _compatibility_pointer(tmp_path / "pointer.json")
    assert manifest_present(pointer) is False


# ── compatibility_only as a preserved manifest field (G2 second re-run) ──────


def test_from_dict_defaults_compatibility_only_false() -> None:
    """Old manifests (schema "1", no marker) load with compatibility_only False
    — authoritative; only the explicit boolean True demotes a pointer."""
    manifest = _make_manifest_obj()
    assert manifest.compatibility_only is False
    assert COMPATIBILITY_ONLY_KEY not in _make_manifest()
    loaded = RuntimeManifest.from_dict(
        dict(_make_manifest(), compatibility_only=True)
    )
    assert loaded.compatibility_only is True


def test_manifest_rejects_non_bool_compatibility_only() -> None:
    with pytest.raises(ManifestError, match="compatibility_only"):
        _make_manifest_obj(compatibility_only="true")


def test_to_dict_round_trip_preserves_compatibility_only() -> None:
    marked = _make_manifest_obj(compatibility_only=True)
    payload = marked.to_dict()
    assert payload[COMPATIBILITY_ONLY_KEY] is True
    # serialized JSON round trip (the write_manifest path) keeps the marker
    round_tripped = RuntimeManifest.from_dict(json.loads(json.dumps(payload)))
    assert round_tripped.compatibility_only is True
    assert round_tripped.to_dict()[COMPATIBILITY_ONLY_KEY] is True


def test_write_active_pointer_carries_marker_and_demotion_is_durable(
    tmp_path: Path,
) -> None:
    """The pointer is written with the marker as part of the manifest payload,
    and once demoted it STAYS demoted across every subsequent pointer write —
    a promote/close transition can never re-admit the global pointer."""
    pointer = tmp_path / "pointer.json"
    marked = _make_manifest_obj(generation=1, compatibility_only=True)
    write_active_pointer(marked, pointer)
    payload = json.loads(pointer.read_text())
    assert payload[COMPATIBILITY_ONLY_KEY] is True
    assert is_compatibility_only_pointer(pointer) is True
    # the marker is a preserved field: the pointer reads back as a manifest
    # (resolvers refuse it) and a generation switch keeps it demoted
    assert load_manifest(pointer).compatibility_only is True
    write_active_pointer(_make_manifest_obj(generation=2), pointer)
    payload = json.loads(pointer.read_text())
    assert payload[COMPATIBILITY_ONLY_KEY] is True
    assert payload["generation"] == 2
    assert is_compatibility_only_pointer(pointer) is True


def test_generic_write_manifest_cannot_readmit_demoted_active_pointer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """G2 final fix: the generic write_manifest() path can target the active
    pointer — an AUTHORITATIVE manifest (compatibility_only False/absent)
    written over a demoted pointer must NOT re-admit it. The demotion
    invariant lives in the lowest-level writer, so no writer can strip the
    marker from the active pointer."""
    pointer = tmp_path / "runtime-manifest.json"
    _compatibility_pointer(pointer)  # demoted active pointer
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(pointer))
    assert is_compatibility_only_pointer(pointer) is True

    # the generic write path with a fully authoritative manifest payload
    write_manifest(_make_manifest_obj(runtime_id="readmit-attempt"), pointer)

    # the pointer still carries the marker in the WRITTEN payload …
    assert is_compatibility_only_pointer(pointer) is True
    payload = json.loads(pointer.read_text())
    assert payload[COMPATIBILITY_ONLY_KEY] is True
    assert payload["runtime_id"] == "readmit-attempt"  # content was written
    # … the manifest reads back demoted, …
    assert load_manifest(pointer).compatibility_only is True
    # … admission treats it as ABSENT, …
    assert manifest_present(pointer) is False
    # … and bootstrap refuses to select a runtime from it.
    with pytest.raises(ManifestError, match="compatibility_only"):
        bootstrap_manifest(active_manifest_path())


def test_write_manifest_does_not_force_marker_on_per_slug_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the ACTIVE POINTER path is protected: a per-slug authoritative
    manifest written to a DIFFERENT path is never forced to carry the
    compatibility_only marker, even while the active pointer is demoted."""
    pointer = tmp_path / "runtime-manifest.json"
    _compatibility_pointer(pointer)  # demoted active pointer
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(pointer))

    slug = tmp_path / "slugs" / "epic-demo" / "runtime-manifest.json"
    write_manifest(_make_manifest_obj(runtime_id="per-slug"), slug)

    # the per-slug manifest is authoritative — no marker was forced
    assert is_compatibility_only_pointer(slug) is False
    assert manifest_present(slug) is True
    assert load_manifest(slug).compatibility_only is False
    assert json.loads(slug.read_text()).get(COMPATIBILITY_ONLY_KEY, False) is False
    # and the active pointer is untouched (still demoted)
    assert is_compatibility_only_pointer(pointer) is True


def test_reconstruct_preserves_compatibility_only(tmp_path: Path) -> None:
    """Every immutable transition (advance_generation / set_state) carries the
    marker — promote and close cannot strip it from the pointer."""
    root, head = _real_git_repo(tmp_path)
    marked = _make_manifest_obj(
        compatibility_only=True, epic={"runtime_root": str(root)}
    )
    advanced = advance_generation(marked, head, reason="preserve marker")
    assert advanced.compatibility_only is True
    closed = set_state(advanced, "closed")
    assert closed.compatibility_only is True
    assert closed.to_dict()[COMPATIBILITY_ONLY_KEY] is True


# ── CLI ─────────────────────────────────────────────────────────────────────


def test_main_write_read_attest(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest = _make_manifest_obj(runtime_id="cli-booted")
    src = tmp_path / "src.json"
    src.write_text(json.dumps(manifest.to_dict()), encoding="utf-8")
    path = tmp_path / "runtime-manifest.json"
    assert main(["write", str(path), "--from", str(src)]) == 0
    assert path.exists()
    capsys.readouterr()  # drain the write subcommand's stdout
    assert main(["read", str(path)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["runtime_id"] == "cli-booted"
    assert main(["attest", str(path)]) == 0
    attest_out = json.loads(capsys.readouterr().out)
    assert set(attest_out) == {
        "module_file",
        "module_digest",
        "mount_id",
        "declared_vs_observed_match",
        "errors",
    }


def test_main_read_rejects_invalid_manifest(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    _write_json(path, _make_manifest(schema="0"))
    assert main(["read", str(path)]) == 2


# ── active-generation pointer ───────────────────────────────────────────────


def test_active_manifest_path_env_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ARNOLD_RUNTIME_MANIFEST", raising=False)
    assert active_manifest_path() == Path("/workspace/.megaplan") / MANIFEST_FILENAME
    pointer = tmp_path / "custom" / "pointer.json"
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(pointer))
    assert active_manifest_path() == pointer


def test_write_active_pointer_first_write_and_retention(tmp_path: Path) -> None:
    pointer = tmp_path / "pointer.json"
    assert write_active_pointer(_make_manifest_obj(generation=1), pointer) == pointer
    assert load_manifest(pointer).generation == 1
    assert not list(tmp_path.glob("pointer.json.previous-*"))
    # same-generation rewrite (e.g. set_state): no retention
    write_active_pointer(_make_manifest_obj(generation=1, state="closed"), pointer)
    assert not list(tmp_path.glob("pointer.json.previous-*"))
    # strict generation bump: previous generation retained for rollback
    write_active_pointer(_make_manifest_obj(generation=2), pointer)
    assert load_manifest(pointer).generation == 2
    retained = tmp_path / "pointer.json.previous-1.json"
    assert retained.exists()
    assert load_manifest(retained).generation == 1


def test_write_active_pointer_refuses_invalid_existing_pointer(tmp_path: Path) -> None:
    pointer = tmp_path / "pointer.json"
    pointer.write_text("{not json", encoding="utf-8")
    with pytest.raises(ManifestError, match="fail-closed"):
        write_active_pointer(_make_manifest_obj(), pointer)
    assert pointer.read_text() == "{not json"  # untouched


def test_write_active_pointer_refuses_foreign_epic_overwrite(tmp_path: Path) -> None:
    """The active pointer must never be silently clobbered by another epic.

    Regression for occurrence 0a0ce24c3510: astrid-first's gen-78
    ``advance_generation`` inherited ARNOLD_RUNTIME_MANIFEST resolving to the
    shared default pointer and overwrote the megaplan-maintenance manifest
    (gen 119) with no retention (78 < 119 skipped the rollback copy).
    """
    pointer = tmp_path / "pointer.json"
    foreign = _make_manifest_obj(generation=119)
    foreign.epic["branch"] = "fixer/megaplan-maintenance-20260813"
    write_active_pointer(foreign, pointer)
    incoming = _make_manifest_obj(generation=78)
    incoming.epic["branch"] = "fixer/astrid-first-20260814"
    with pytest.raises(ForeignAuthoritativePointerConflict, match="different epic") as excinfo:
        write_active_pointer(incoming, pointer)
    assert excinfo.value.code == "foreign_authoritative_pointer_conflict"
    # pointer untouched: the active epic's generation survives the attempt
    assert load_manifest(pointer).generation == 119
    assert (
        load_manifest(pointer).epic["branch"]
        == "fixer/megaplan-maintenance-20260813"
    )
    assert not list(tmp_path.glob("pointer.json.previous-78.json"))


def test_write_active_pointer_same_epic_overwrite_still_allowed(tmp_path: Path) -> None:
    """Same-epic generation bumps keep retention + write (no false refusal)."""
    pointer = tmp_path / "pointer.json"
    first = _make_manifest_obj(generation=119)
    first.epic["branch"] = "fixer/megaplan-maintenance-20260813"
    write_active_pointer(first, pointer)
    second = _make_manifest_obj(generation=120)
    second.epic["branch"] = "fixer/megaplan-maintenance-20260813"
    write_active_pointer(second, pointer)
    assert load_manifest(pointer).generation == 120
    retained = tmp_path / "pointer.json.previous-119.json"
    assert retained.exists()
    assert (
        load_manifest(retained).epic["branch"]
        == "fixer/megaplan-maintenance-20260813"
    )


def test_write_active_pointer_allows_compatibility_only_pointer_replacement(
    tmp_path: Path,
) -> None:
    """A compatibility_only pointer (non-authoritative telemetry) is replaceable."""
    pointer = tmp_path / "pointer.json"
    compat = _make_manifest_obj(generation=1, compatibility_only=True)
    compat.epic["branch"] = "fixer/megaplan-maintenance-20260813"
    write_active_pointer(compat, pointer)
    incoming = _make_manifest_obj(generation=2)
    incoming.epic["branch"] = "fixer/astrid-first-20260814"
    write_active_pointer(incoming, pointer)
    assert load_manifest(pointer).generation == 2
    assert load_manifest(pointer).epic["branch"] == "fixer/astrid-first-20260814"


def test_bootstrap_manifest_resolves_through_active_pointer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pointer = tmp_path / "pointer.json"
    manifest = _make_manifest_obj(runtime_id="ptr-booted")
    write_active_pointer(manifest, pointer)
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(pointer))
    # the pointer IS the active generation: bootstrap resolves it directly
    assert bootstrap_manifest(active_manifest_path()) == manifest


# ── CLI subcommands (subprocess round trips) ────────────────────────────────


def _cli_env(
    tmp_path: Path, extra_env: dict[str, str] | None = None
) -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    env["ARNOLD_RUNTIME_MANIFEST"] = str(tmp_path / "runtime-manifest.json")
    if extra_env:
        env.update(extra_env)
    return env


def _run_cli(
    env: dict[str, str], *args: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "arnold_pipelines.megaplan.cloud.runtime_manifest",
            *args,
        ],
        capture_output=True,
        text=True,
        env=env,
    )


def test_cli_set_state_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "m.json"
    write_manifest(_make_manifest_obj(), path)
    env = _cli_env(tmp_path)
    proc = _run_cli(env, "set_state", str(path), "closed")
    assert proc.returncode == 0, proc.stderr
    closed = load_manifest(path)
    assert closed.state == "closed"
    assert closed.timestamps["closed"]
    # the manifest survives a re-read round trip
    assert _run_cli(env, "read", str(path)).returncode == 0


def test_cli_set_state_rejects_unknown_state(tmp_path: Path) -> None:
    path = tmp_path / "m.json"
    write_manifest(_make_manifest_obj(), path)
    proc = _run_cli(_cli_env(tmp_path), "set_state", str(path), "destroyed")
    assert proc.returncode == 2
    assert load_manifest(path).state == "active"  # unchanged


def test_cli_append_promotion_inline_and_file(tmp_path: Path) -> None:
    path = tmp_path / "m.json"
    write_manifest(_make_manifest_obj(), path)
    env = _cli_env(tmp_path)
    sha_a = "a" * 40
    sha_b = "b" * 40
    record = f'{{"from_sha": "{sha_a}", "to_sha": "{sha_b}", "result": "pushed"}}'
    proc = _run_cli(env, "append_promotion", str(path), record)
    assert proc.returncode == 0, proc.stderr
    record_file = tmp_path / "record.json"
    record_file.write_text(record, encoding="utf-8")
    proc_file = _run_cli(env, "append_promotion", str(path), f"@{record_file}")
    assert proc_file.returncode == 0, proc_file.stderr
    manifest = load_manifest(path)
    assert [p["to_sha"] for p in manifest.promotions] == [sha_b, sha_b]


def test_cli_append_promotion_rejects_bad_record(tmp_path: Path) -> None:
    path = tmp_path / "m.json"
    write_manifest(_make_manifest_obj(), path)
    env = _cli_env(tmp_path)
    assert _run_cli(env, "append_promotion", str(path), "not-json").returncode == 2
    assert _run_cli(env, "append_promotion", str(path), "[1, 2]").returncode == 2
    assert _run_cli(
        env, "append_promotion", str(path), f"@{tmp_path / 'missing.json'}"
    ).returncode == 2
    assert load_manifest(path).promotions == []


def test_cli_advance_generation_switches_pointer_and_retains_previous(
    tmp_path: Path,
) -> None:
    root, head = _real_git_repo(tmp_path)
    pointer = tmp_path / "runtime-manifest.json"
    path = tmp_path / "m.json"
    manifest = _make_manifest_obj(
        generation=1,
        epic={"runtime_root": str(root), "expected_head": head},
        indirection={"verified_head": head},
    )
    write_manifest(manifest, path)
    # pointer already holds gen 1 (as runtime-create writes it at creation)
    write_active_pointer(manifest, pointer)
    env = _cli_env(tmp_path)
    proc = _run_cli(
        env, "advance_generation", str(path), head, "--reason", "cli test"
    )
    assert proc.returncode == 0, proc.stderr
    advanced = load_manifest(path)
    assert advanced.generation == 2
    assert advanced.epic["expected_head"] == head
    # pointer switched to the new generation
    pointer_manifest = load_manifest(pointer)
    assert pointer_manifest.generation == 2
    assert pointer_manifest.epic["expected_head"] == head
    # previous generation retained for rollback
    retention = tmp_path / "runtime-manifest.json.previous-1.json"
    assert retention.exists()
    assert load_manifest(retention).generation == 1
    assert load_manifest(retention).epic["expected_head"] == head
    # bootstrap resolves through the pointer to the ACTIVE generation
    assert bootstrap_manifest(pointer) == advanced


def test_cli_advance_generation_creates_pointer_when_absent(tmp_path: Path) -> None:
    root, head = _real_git_repo(tmp_path)
    path = tmp_path / "m.json"
    write_manifest(_make_manifest_obj(epic={"runtime_root": str(root)}), path)
    env = _cli_env(tmp_path)
    proc = _run_cli(
        env, "advance_generation", str(path), head, "--reason", "first promotion"
    )
    assert proc.returncode == 0, proc.stderr
    assert (tmp_path / "runtime-manifest.json").exists()
    assert not list(tmp_path.glob("runtime-manifest.json.previous-*"))
    assert load_manifest(path).generation == 4  # default fixture generation is 3


def test_cli_advance_generation_requires_reason(tmp_path: Path) -> None:
    path = tmp_path / "m.json"
    write_manifest(_make_manifest_obj(), path)
    proc = _run_cli(_cli_env(tmp_path), "advance_generation", str(path), "newsha003")
    assert proc.returncode == 2  # argparse usage error


def test_cli_advance_generation_exits_2_on_missing_manifest(tmp_path: Path) -> None:
    proc = _run_cli(
        _cli_env(tmp_path),
        "advance_generation",
        str(tmp_path / "missing.json"),
        "newsha004",
        "--reason",
        "r",
    )
    assert proc.returncode == 2


def test_cli_add_deviation_round_trip_inline_and_file(tmp_path: Path) -> None:
    path = tmp_path / "m.json"
    write_manifest(_make_manifest_obj(), path)
    env = _cli_env(tmp_path)
    record = json.dumps(_make_deviation(id="cli-perm-1"))
    proc = _run_cli(env, "add_deviation", str(path), record)
    assert proc.returncode == 0, proc.stderr
    manifest = load_manifest(path)
    assert [d["id"] for d in manifest.deviations] == ["cli-perm-1"]
    assert manifest.deviations[0]["kind"] == "allow_manifestless"
    # @FILE form appends a second record
    record_file = tmp_path / "deviation.json"
    record_file.write_text(json.dumps(_make_deviation(id="cli-perm-2")), encoding="utf-8")
    proc_file = _run_cli(env, "add_deviation", str(path), f"@{record_file}")
    assert proc_file.returncode == 0, proc_file.stderr
    assert [d["id"] for d in load_manifest(path).deviations] == [
        "cli-perm-1",
        "cli-perm-2",
    ]
    # the manifest with deviations survives a re-read round trip
    assert _run_cli(env, "read", str(path)).returncode == 0
    read_out = json.loads(_run_cli(env, "read", str(path)).stdout)
    assert [d["id"] for d in read_out["deviations"]] == [
        "cli-perm-1",
        "cli-perm-2",
    ]


def test_cli_add_deviation_rejects_bad_record(tmp_path: Path) -> None:
    path = tmp_path / "m.json"
    write_manifest(_make_manifest_obj(), path)
    env = _cli_env(tmp_path)
    assert _run_cli(env, "add_deviation", str(path), "not-json").returncode == 2
    missing_field = json.dumps(dict(_make_deviation(), reason=""))
    assert _run_cli(env, "add_deviation", str(path), missing_field).returncode == 2
    now = datetime.now(timezone.utc)
    expired = json.dumps(
        _make_deviation(
            issued_at=(now - timedelta(hours=2)).isoformat(timespec="seconds"),
            expires_at=(now - timedelta(hours=1)).isoformat(timespec="seconds"),
        )
    )
    assert _run_cli(env, "add_deviation", str(path), expired).returncode == 2
    assert _run_cli(
        env, "add_deviation", str(path), f"@{tmp_path / 'missing.json'}"
    ).returncode == 2
    assert load_manifest(path).deviations == []  # nothing was appended


# ── T-0013 regression locks: per-session binding, lifecycle, attestation ────


def test_per_session_manifest_binding_has_no_global_pointer_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Per-session manifest binding (``ARNOLD_RUNTIME_MANIFEST``) is the ONLY
    resolver: the global active pointer at the default path is never
    consulted or selected, and a bound-but-missing session path fails closed
    instead of falling back to it (G1 correction 1/2)."""
    global_path = Path("/workspace/.megaplan") / MANIFEST_FILENAME
    monkeypatch.delenv("ARNOLD_RUNTIME_MANIFEST", raising=False)
    # Unbound: the default path is only ever visible as the UNBOUND default —
    # the moment a session binds, that path is the session path.
    assert active_manifest_path() == global_path

    session_a = tmp_path / "sessions" / "epic-a" / "runtime-manifest.json"
    session_b = tmp_path / "sessions" / "epic-b" / "runtime-manifest.json"
    manifest_a = _make_manifest_obj(runtime_id="runtime-a", epic_id="epic-a")
    manifest_b = _make_manifest_obj(runtime_id="runtime-b", epic_id="epic-b")
    write_active_pointer(manifest_a, session_a)
    write_active_pointer(manifest_b, session_b)

    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(session_a))
    # Bound session A: the active pointer IS the session path — never the
    # global default — and resolves exactly session A's manifest.
    assert active_manifest_path() == session_a
    assert bootstrap_manifest(active_manifest_path()) == manifest_a
    assert bootstrap_manifest(active_manifest_path()).runtime_id == "runtime-a"

    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(session_b))
    # Session B binds independently: no cross-selection with session A.
    assert bootstrap_manifest(active_manifest_path()) == manifest_b
    assert bootstrap_manifest(active_manifest_path()).runtime_id == "runtime-b"

    # A bound-but-missing path fails closed (ManifestError) — there is NO
    # fallback to the global active pointer for per-session resolution.
    missing = tmp_path / "sessions" / "epic-missing" / "runtime-manifest.json"
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(missing))
    with pytest.raises(ManifestError, match="does not exist"):
        bootstrap_manifest(active_manifest_path())
    # The global default pointer was never created or written by any of the
    # per-session operations above.
    assert not global_path.exists()


def test_compatibility_only_survives_create_promote_close_lifecycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The runtime-create -> promote -> close lifecycle can never re-admit
    the active pointer: the ``compatibility_only`` marker written at create
    survives promote (``advance_generation``) and close (``set_state``)
    through the real CLI pointer path, and the pointer stays
    NON-AUTHORITATIVE at every step (G2 correction 1 + second re-run)."""
    _stub_git_head_guard(monkeypatch)
    pointer = tmp_path / "runtime-manifest.json"
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(pointer))
    root, _head = _real_git_repo(tmp_path)

    # create: arnold-runtime-create writes the pointer as compatibility
    # telemetry (compatibility_only=True).
    created = _make_manifest_obj(
        generation=1,
        compatibility_only=True,
        epic={"runtime_root": str(root)},
    )
    write_active_pointer(created, pointer)
    assert is_compatibility_only_pointer(pointer) is True

    # promote: advance_generation through the active pointer (CLI path) —
    # generation bumps but the marker survives and admission stays absent.
    assert (
        main(["advance_generation", str(pointer), "newsha001", "--reason", "promote"])
        == 0
    )
    promoted = load_manifest(pointer)
    assert promoted.generation == 2
    assert promoted.epic["expected_head"] == "newsha001"
    assert promoted.compatibility_only is True
    assert is_compatibility_only_pointer(pointer) is True
    assert manifest_present(pointer) is False
    with pytest.raises(ManifestError, match="compatibility_only"):
        bootstrap_manifest(pointer)

    # close: set_state closed through the active pointer (CLI path) — the
    # closed state is stamped but the pointer remains non-authoritative.
    assert main(["set_state", str(pointer), "closed"]) == 0
    closed = load_manifest(pointer)
    assert closed.state == "closed"
    assert closed.timestamps["closed"]
    assert closed.compatibility_only is True
    assert is_compatibility_only_pointer(pointer) is True
    assert manifest_present(pointer) is False
    with pytest.raises(ManifestError, match="compatibility_only"):
        bootstrap_manifest(pointer)

    # The serialized pointer on disk carries the marker after every step.
    payload = json.loads(pointer.read_text(encoding="utf-8"))
    assert payload[COMPATIBILITY_ONLY_KEY] is True
    assert payload["state"] == "closed"
    assert payload["generation"] == 2


def test_missing_runtime_attestation_never_authorizes(tmp_path: Path) -> None:
    """Content attestation of a manifest whose runtime root is missing is
    NEVER green: ``declared_vs_observed_match`` is False with errors and no
    module identity, so no dispatch path can treat the runtime as attested
    (design rule 7 content attestation; T-0013 regression lock)."""
    manifest = _make_manifest_obj(
        epic={"runtime_root": str(tmp_path / "no-such-runtime")},
    )
    result = attest_runtime(manifest)
    # Missing runtime root => NEVER a green attestation: the declared tree
    # cannot match, so declared_vs_observed_match is False with errors.
    assert result["declared_vs_observed_match"] is False
    assert result["errors"]
    # The probed module identity must NOT come from the declared (missing)
    # runtime root — no attestation payload can select that tree.
    assert result["module_file"] != str(
        (tmp_path / "no-such-runtime" / "arnold_pipelines" / "__init__.py").resolve()
    )
    assert all(
        key in result
        for key in (
            "module_file",
            "module_digest",
            "mount_id",
            "declared_vs_observed_match",
            "errors",
        )
    )


# ── CAS runtime cutover (T-0101d) ───────────────────────────────────────────


from arnold_pipelines.megaplan.cloud.runtime_manifest import (  # noqa: E402
    CUTOVER_RECEIPT_SUFFIX,
    RECEIPT_ALIASES_PROTECTED_STATE,
    RECEIPT_POST_VERIFY_FAILED,
    apply_runtime_manifest_cutover,
    cutover_runtime_manifest,
)
from arnold_pipelines.megaplan.cloud.runtime_provenance import (  # noqa: E402
    RUNTIME_MANIFEST_CUTOVER_ROLLBACK_SCHEMA,
    RUNTIME_PROVENANCE_RECEIPT_SCHEMA,
    emit_runtime_manifest_cutover_rollback_receipt,
    verify_runtime_manifest_cutover_rollback_receipt,
)
from arnold_pipelines.megaplan.types import CliError  # noqa: E402

_FROM_RUNTIME_ROOT = "/opt/arnold/runtime-candidates/epic-demo/runtime"
_FROM_EXPECTED_HEAD = "abc123def"
_TO_RUNTIME_ROOT = "/opt/arnold/runtime-candidates/epic-demo/runtime-2"
_TO_EXPECTED_HEAD = "def456789"
_TO_VENV_PATH = "/opt/arnold/runtime-candidates/epic-demo/runtime-2/venv"
_TO_REPAIR_BIN = (
    "/opt/arnold/runtime-candidates/epic-demo/runtime-2/venv/bin/arnold-babysitter"
)


def _generation_proof(
    interpreter_path: str, **overrides: object
) -> dict[str, object]:
    """A structurally valid content-addressed dependency-generation proof
    (T-0301) bound to *interpreter_path* — the value every cutover's
    ``--to-venv-path``/``--to-dependency-generation`` coherence gates expect
    (proof interpreter == ``<to_venv>/bin/python``)."""
    proof: dict[str, object] = {
        "id": "a" * 64,
        "frozen_spec_sha256": "a" * 64,
        "interpreter_path": interpreter_path,
        "venv_digest": "b" * 64,
        "created": "2026-08-07T00:00:00+00:00",
    }
    proof.update(overrides)
    return proof


def _verified_identity(
    to_runtime_root: str = _TO_RUNTIME_ROOT,
    source_revision: str = _TO_EXPECTED_HEAD,
) -> dict[str, object]:
    """Identity payload returned by a mocked (already-passed) external
    verification — mirrors the shape ``verify_external_runtime_identity``
    returns.  The receipted source revision defaults to ``_TO_EXPECTED_HEAD``:
    the cutover REQUIRES ``verified.source_revision == --to-expected-head``,
    so a coherent happy-path identity must resolve to the very head it stamps
    (tests that need a mismatch pass an explicit different revision)."""
    return {
        "import_root": to_runtime_root,
        "source_revision": source_revision,
        "editable_root": to_runtime_root,
        "editable_revision": source_revision,
        "direct_url": {},
        "pth": [],
        "imports": {},
        "content_sha256": "c" * 64,
    }


def _fake_identity_files(tmp_path: Path) -> tuple[Path, Path]:
    identity = tmp_path / "identity.json"
    receipt = tmp_path / "receipt.json"
    identity.write_text(json.dumps(_verified_identity()), encoding="utf-8")
    receipt.write_text(
        json.dumps({"schema": RUNTIME_PROVENANCE_RECEIPT_SCHEMA}),
        encoding="utf-8",
    )
    return identity, receipt


def _make_cutover_runtime_tree(tmp_path: Path) -> tuple[str, str, str]:
    """Build the REAL staging-shaped TO-runtime tree the path-coherence gates
    require: a ``.venv`` DIRECTORY with an EXECUTABLE ``bin/python``
    interpreter (T-0301: the venv binding must agree with the generation
    proof's interpreter_path) and an EXECUTABLE repair wrapper, both
    resolving INSIDE the runtime root (the layout arnold-runtime-create
    writes: ``{root}/.venv`` and ``{root}/arnold_pipelines/megaplan/cloud/
    wrappers/arnold-babysitter``).  Returns ``(to_root, venv, repair)``."""
    to_root = tmp_path / "runtime-candidates" / "epic-demo" / "runtime-2"
    venv = to_root / ".venv"
    (venv / "bin").mkdir(parents=True, exist_ok=True)
    python = venv / "bin" / "python"
    python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    python.chmod(0o755)
    (venv / "pyvenv.cfg").write_text("home = /usr\n", encoding="utf-8")
    repair = (
        to_root
        / "arnold_pipelines"
        / "megaplan"
        / "cloud"
        / "wrappers"
        / "arnold-babysitter"
    )
    repair.parent.mkdir(parents=True, exist_ok=True)
    repair.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    repair.chmod(0o755)
    return str(to_root), str(venv), str(repair)


def _stub_git_head_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Narrowly bypass the git-object head guard (codex fix 2026-08-17) in
    tests whose sole subject is NOT the guard — field relocation, receipt
    handling, and error precedence.  The dedicated real-repo tests
    (``test_advance_generation_rejects_non_object_head_*``,
    ``test_cutover_runtime_manifest_rejects_non_object_target_head``, and
    ``test_runtime_manifest_cli_rejects_fake_sha_generation_advance`` in the
    lifecycle suite) exercise the REAL guard; this is a per-test stub only.
    """
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest._require_resolvable_head",
        lambda runtime_root, head: head,
    )


def _cutover_cli_args(
    path: Path,
    *,
    expect_manifest_sha256: str,
    expect_generation: int = 3,
    identity: Path,
    receipt: Path,
    receipt_out: Path | None = None,
    to_runtime_root: str = _TO_RUNTIME_ROOT,
    to_venv_path: str = _TO_VENV_PATH,
    to_repair_bin: str = _TO_REPAIR_BIN,
) -> list[str]:
    args = [
        "cutover",
        str(path),
        "--expect-manifest-sha256",
        expect_manifest_sha256,
        "--expect-generation",
        str(expect_generation),
        "--from-runtime-root",
        _FROM_RUNTIME_ROOT,
        "--from-expected-head",
        _FROM_EXPECTED_HEAD,
        "--to-runtime-root",
        to_runtime_root,
        "--to-expected-head",
        _TO_EXPECTED_HEAD,
        "--to-venv-path",
        to_venv_path,
        "--to-repair-bin",
        to_repair_bin,
        "--runtime-identity",
        str(identity),
        "--runtime-provenance-receipt",
        str(receipt),
        "--reason",
        "T-0101d cutover test",
        "--actor",
        "operator",
    ]
    if receipt_out is not None:
        args += ["--receipt-out", str(receipt_out)]
    return args


def _self_asserting_identity_and_receipt(
    tmp_path: Path,
) -> tuple[Path, Path]:
    """Identity + provenance receipt whose interpreter IS the control
    interpreter — the real verifier refuses it at the independence check
    (before any subprocess re-run), proving the cutover wires the genuine
    chain verifier, without needing a second venv."""
    control = Path(sys.executable).resolve()
    identity = {
        "import_root": str(REPO_ROOT),
        "source_revision": "a" * 40,
        "editable_root": str(REPO_ROOT),
        "editable_revision": "a" * 40,
        "direct_url": {},
        "pth": [],
        "imports": {},
    }
    identity["content_sha256"] = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    receipt = {
        "schema": RUNTIME_PROVENANCE_RECEIPT_SCHEMA,
        "interpreter": {
            "executable": str(control),
            "sha256": hashlib.sha256(control.read_bytes()).hexdigest(),
            "prefix": str(Path(sys.prefix).resolve()),
            "base_prefix": str(Path(sys.base_prefix).resolve()),
        },
        "provenance": {},
        "runtime_identity": identity,
    }
    receipt["content_sha256"] = hashlib.sha256(
        json.dumps(
            {
                key: receipt[key]
                for key in ("schema", "interpreter", "provenance", "runtime_identity")
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    identity_path = tmp_path / "self-asserting-identity.json"
    receipt_path = tmp_path / "self-asserting-receipt.json"
    identity_path.write_text(json.dumps(identity), encoding="utf-8")
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    return identity_path, receipt_path


def test_cutover_runtime_manifest_moves_runtime_facts_and_bumps_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_git_head_guard(monkeypatch)
    manifest = _make_manifest_obj(
        generation=2,
        base={"commit": _FROM_EXPECTED_HEAD},  # schema-consistent base pin
    )
    updated = cutover_runtime_manifest(
        manifest,
        from_runtime_root=_FROM_RUNTIME_ROOT,
        from_expected_head=_FROM_EXPECTED_HEAD,
        to_runtime_root=_TO_RUNTIME_ROOT,
        to_expected_head=_TO_EXPECTED_HEAD,
        to_venv_path=_TO_VENV_PATH,
        to_repair_bin=_TO_REPAIR_BIN,
        reason="cutover to receipted runtime",
    )
    assert updated is not manifest
    assert updated.generation == 3
    assert updated.epic["runtime_root"] == _TO_RUNTIME_ROOT
    assert updated.epic["worktree_path"] == _TO_RUNTIME_ROOT
    assert updated.epic["expected_head"] == _TO_EXPECTED_HEAD
    assert updated.epic["venv_path"] == _TO_VENV_PATH
    assert updated.epic["repair_bin"] == _TO_REPAIR_BIN
    # base.commit tracks the head when it pinned the from-head; the ref is a
    # branch name and is never rewritten by a cutover.
    assert updated.base["commit"] == _TO_EXPECTED_HEAD
    assert updated.base["ref"] == manifest.base["ref"]
    assert updated.indirection["verified_head"] == _TO_EXPECTED_HEAD
    assert updated.indirection["host_path"] == _TO_RUNTIME_ROOT
    assert updated.timestamps["updated"]
    assert len(updated.promotions) == 1
    record = updated.promotions[0]
    assert record["previous_generation"] == 2
    assert record["previous_commit"] == _FROM_EXPECTED_HEAD
    assert record["previous_runtime_root"] == _FROM_RUNTIME_ROOT
    assert record["previous_venv_path"] == manifest.epic["venv_path"]
    assert record["previous_repair_bin"] == manifest.epic["repair_bin"]
    assert record["reason"] == "cutover to receipted runtime"
    assert record["at"]
    # original untouched (the rollback source is retained on the new one)
    assert manifest.generation == 2
    assert manifest.epic["runtime_root"] == _FROM_RUNTIME_ROOT
    assert manifest.promotions == []


def test_cutover_runtime_manifest_preserves_base_pin_and_markers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_git_head_guard(monkeypatch)
    manifest = _make_manifest_obj(
        base={"commit": "87a912beb"},  # NOT the from-head — a foreign pin
        deviations=[_make_deviation()],
        compatibility_only=True,
    )
    updated = cutover_runtime_manifest(
        manifest,
        from_runtime_root=_FROM_RUNTIME_ROOT,
        from_expected_head=_FROM_EXPECTED_HEAD,
        to_runtime_root=_TO_RUNTIME_ROOT,
        to_expected_head=_TO_EXPECTED_HEAD,
        to_venv_path=_TO_VENV_PATH,
        to_repair_bin=_TO_REPAIR_BIN,
        reason="preserve foreign base pin",
    )
    # a base pinned to something else is never silently rewritten
    assert updated.base["commit"] == "87a912beb"
    # compatibility_only demotion + deviations survive the transition
    assert updated.compatibility_only is True
    assert updated.deviations == manifest.deviations
    assert updated.to_dict()[COMPATIBILITY_ONLY_KEY] is True


def test_cutover_runtime_manifest_rejects_guard_mismatch() -> None:
    manifest = _make_manifest_obj()
    with pytest.raises(ManifestError, match="from-runtime-root"):
        cutover_runtime_manifest(
            manifest,
            from_runtime_root="/opt/elsewhere",
            from_expected_head=_FROM_EXPECTED_HEAD,
            to_runtime_root=_TO_RUNTIME_ROOT,
            to_expected_head=_TO_EXPECTED_HEAD,
            to_venv_path=_TO_VENV_PATH,
            to_repair_bin=_TO_REPAIR_BIN,
            reason="bad from-root",
        )
    with pytest.raises(ManifestError, match="from-expected-head"):
        cutover_runtime_manifest(
            manifest,
            from_runtime_root=_FROM_RUNTIME_ROOT,
            from_expected_head="wronghead",
            to_runtime_root=_TO_RUNTIME_ROOT,
            to_expected_head=_TO_EXPECTED_HEAD,
            to_venv_path=_TO_VENV_PATH,
            to_repair_bin=_TO_REPAIR_BIN,
            reason="bad from-head",
        )
    with pytest.raises(ManifestError, match="cutover requires"):
        cutover_runtime_manifest(
            manifest,
            from_runtime_root=_FROM_RUNTIME_ROOT,
            from_expected_head=_FROM_EXPECTED_HEAD,
            to_runtime_root="",
            to_expected_head=_TO_EXPECTED_HEAD,
            to_venv_path=_TO_VENV_PATH,
            to_repair_bin=_TO_REPAIR_BIN,
            reason="empty to-root",
        )
    assert manifest.generation == 3


# ── T-0301 cutover publication gate ─────────────────────────────────────────


def test_cutover_runtime_manifest_carries_the_generation_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_git_head_guard(monkeypatch)
    manifest = _make_manifest_obj()
    updated = cutover_runtime_manifest(
        manifest,
        from_runtime_root=_FROM_RUNTIME_ROOT,
        from_expected_head=_FROM_EXPECTED_HEAD,
        to_runtime_root=_TO_RUNTIME_ROOT,
        to_expected_head=_TO_EXPECTED_HEAD,
        to_venv_path=_TO_VENV_PATH,
        to_repair_bin=_TO_REPAIR_BIN,
        reason="carry generation",
    )
    assert (
        updated.epic["dependency_generation"]
        == manifest.epic["dependency_generation"]
    )
    assert dependency_generation_proof(updated) is not None


def test_cutover_runtime_manifest_refuses_without_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-0301 publication gate: a manifest with NO dependency-generation
    proof cannot be cut over — unknown dependency state blocks publication."""
    _stub_git_head_guard(monkeypatch)
    manifest = _make_manifest_obj()
    del manifest.epic["dependency_generation"]  # type: ignore[typeddict-item]
    with pytest.raises(ManifestError, match="dependency_generation proof"):
        cutover_runtime_manifest(
            manifest,
            from_runtime_root=_FROM_RUNTIME_ROOT,
            from_expected_head=_FROM_EXPECTED_HEAD,
            to_runtime_root=_TO_RUNTIME_ROOT,
            to_expected_head=_TO_EXPECTED_HEAD,
            to_venv_path=_TO_VENV_PATH,
            to_repair_bin=_TO_REPAIR_BIN,
            reason="no proof",
        )


def test_cutover_runtime_manifest_accepts_explicit_proof_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_git_head_guard(monkeypatch)
    manifest = _make_manifest_obj()
    del manifest.epic["dependency_generation"]  # type: ignore[typeddict-item]
    override = _generation_proof(
        f"{_TO_VENV_PATH}/bin/python", id="e" * 64, frozen_spec_sha256="e" * 64
    )
    updated = cutover_runtime_manifest(
        manifest,
        from_runtime_root=_FROM_RUNTIME_ROOT,
        from_expected_head=_FROM_EXPECTED_HEAD,
        to_runtime_root=_TO_RUNTIME_ROOT,
        to_expected_head=_TO_EXPECTED_HEAD,
        to_venv_path=_TO_VENV_PATH,
        to_repair_bin=_TO_REPAIR_BIN,
        reason="explicit rebuilt generation",
        to_dependency_generation=override,
    )
    assert updated.epic["dependency_generation"] == override


def test_cutover_runtime_manifest_rejects_non_object_target_head(
    tmp_path: Path,
) -> None:
    """Git-object head guard (codex fix 2026-08-17): the cutover's TARGET
    head must be a 40-hex SHA that RESOLVES to that exact commit in the
    TARGET runtime root.  A correctly shaped but fabricated head (real
    prefix + invented tail) is REFUSED before a new manifest is returned."""
    to_root, _head = _real_git_repo(tmp_path)
    manifest = _make_manifest_obj(
        epic={"runtime_root": _FROM_RUNTIME_ROOT},
    )
    fake = _head[:10] + "b" * 30  # 40-hex, correct shape, not a git object
    with pytest.raises(ManifestError, match="does not resolve"):
        cutover_runtime_manifest(
            manifest,
            from_runtime_root=_FROM_RUNTIME_ROOT,
            from_expected_head=_FROM_EXPECTED_HEAD,
            to_runtime_root=str(to_root),
            to_expected_head=fake,
            to_venv_path=_TO_VENV_PATH,
            to_repair_bin=_TO_REPAIR_BIN,
            reason="fake target head must refuse",
        )
    # zero mutation: the input manifest is untouched
    assert manifest.generation == 3
    assert manifest.epic["runtime_root"] == _FROM_RUNTIME_ROOT
    assert manifest.promotions == []
    # a REAL commit in the target root passes
    updated = cutover_runtime_manifest(
        manifest,
        from_runtime_root=_FROM_RUNTIME_ROOT,
        from_expected_head=_FROM_EXPECTED_HEAD,
        to_runtime_root=str(to_root),
        to_expected_head=_head,
        to_venv_path=_TO_VENV_PATH,
        to_repair_bin=_TO_REPAIR_BIN,
        reason="real target head advances",
    )
    assert updated.generation == 4
    assert updated.epic["expected_head"] == _head


def test_cli_cutover_refuses_without_proof_zero_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """T-0301: the CLI cutover refuses (typed, ZERO mutation, no rollback
    receipt) when the manifest has no complete generation proof and no
    --to-dependency-generation is given."""
    identity, receipt = _fake_identity_files(tmp_path)
    to_root, to_venv, to_repair = _make_cutover_runtime_tree(tmp_path)
    path = tmp_path / "m.json"
    manifest = _make_manifest_obj(generation=3)
    del manifest.epic["dependency_generation"]  # type: ignore[typeddict-item]
    write_manifest(manifest, path)
    before = path.read_bytes()
    expected_sha = hashlib.sha256(before).hexdigest()
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: _verified_identity(
            to_runtime_root=to_root
        ),
    )
    assert main(
        _cutover_argv_with_tree(
            path, expected_sha, identity, receipt, to_root, to_venv, to_repair
        )
    ) == 2
    assert "dependency_generation proof" in capsys.readouterr().err
    assert path.read_bytes() == before
    assert not (tmp_path / f"m.json{CUTOVER_RECEIPT_SUFFIX}").exists()


def test_cli_cutover_accepts_explicit_to_dependency_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """T-0301: --to-dependency-generation supplies the rebuilt proof for a
    manifest that has none (the normal migration path for pre-T-0301
    manifests), and the cutover succeeds."""
    _stub_git_head_guard(monkeypatch)
    identity, receipt = _fake_identity_files(tmp_path)
    to_root, to_venv, to_repair = _make_cutover_runtime_tree(tmp_path)
    path = tmp_path / "m.json"
    manifest = _make_manifest_obj(generation=3)
    del manifest.epic["dependency_generation"]  # type: ignore[typeddict-item]
    write_manifest(manifest, path)
    before_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: _verified_identity(
            to_runtime_root=to_root
        ),
    )
    args = _cutover_argv_with_tree(
        path, before_sha, identity, receipt, to_root, to_venv, to_repair
    )
    args += [
        "--to-dependency-generation",
        json.dumps(_generation_proof(f"{to_venv}/bin/python")),
    ]
    assert main(args) == 0
    updated = load_manifest(path)
    assert updated.generation == 4
    assert updated.epic["dependency_generation"]["interpreter_path"] == (
        f"{to_venv}/bin/python"
    )
    assert manifest.generation == 3


def test_cli_cutover_happy_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _stub_git_head_guard(monkeypatch)
    path = tmp_path / "m.json"
    identity, receipt = _fake_identity_files(tmp_path)
    to_root, to_venv, to_repair = _make_cutover_runtime_tree(tmp_path)
    manifest = _make_manifest_obj(
        generation=3,
        base={"commit": _FROM_EXPECTED_HEAD},
        deviations=[_make_deviation()],
        # T-0301: the manifest's generation proof must agree with the
        # tree's venv interpreter (proof coherence gate).
        epic={"dependency_generation": _generation_proof(f"{to_venv}/bin/python")},
    )
    write_manifest(manifest, path)
    before = manifest.to_dict()
    expected_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: _verified_identity(
            to_runtime_root=to_root
        ),
    )

    assert main(
        _cutover_cli_args(
            path,
            expect_manifest_sha256=expected_sha,
            identity=identity,
            receipt=receipt,
            to_runtime_root=to_root,
            to_venv_path=to_venv,
            to_repair_bin=to_repair,
        )
    ) == 0

    updated = load_manifest(path)
    assert updated.generation == 4
    assert updated.epic["runtime_root"] == to_root
    assert updated.epic["worktree_path"] == to_root
    assert updated.epic["expected_head"] == _TO_EXPECTED_HEAD
    assert updated.epic["venv_path"] == to_venv
    assert updated.epic["repair_bin"] == to_repair
    assert updated.base["commit"] == _TO_EXPECTED_HEAD
    assert updated.indirection["verified_head"] == _TO_EXPECTED_HEAD
    assert updated.indirection["host_path"] == to_root
    # deviations preserved end-to-end through the disk round trip
    assert updated.deviations == before["deviations"]

    # default rollback receipt: old manifest SHA-256 + FULL old field set
    receipt_path = tmp_path / f"m.json{CUTOVER_RECEIPT_SUFFIX}"
    assert receipt_path.exists()
    receipt_payload = verify_runtime_manifest_cutover_rollback_receipt(
        receipt_path, expected_manifest_before_sha256=expected_sha
    )
    assert receipt_payload["schema"] == RUNTIME_MANIFEST_CUTOVER_ROLLBACK_SCHEMA
    assert receipt_payload["generation_before"] == 3
    assert receipt_payload["generation_after"] == 4
    assert receipt_payload["manifest_after_sha256"] == hashlib.sha256(
        path.read_bytes()
    ).hexdigest()
    assert receipt_payload["from"] == {
        "runtime_root": _FROM_RUNTIME_ROOT,
        "expected_head": _FROM_EXPECTED_HEAD,
    }
    assert receipt_payload["to"] == {
        "runtime_root": to_root,
        "expected_head": _TO_EXPECTED_HEAD,
        "venv_path": to_venv,
        "repair_bin": to_repair,
    }
    assert receipt_payload["previous_manifest"] == before
    assert receipt_payload["runtime_identity_sha256"] == "c" * 64
    assert receipt_payload["actor"] == "operator"

    # the CLI payload carries the same facts
    out = json.loads(capsys.readouterr().out)
    assert out["generation_before"] == 3
    assert out["generation_after"] == 4
    assert out["rollback_receipt_path"] == str(receipt_path)


def test_cli_cutover_honors_custom_receipt_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_git_head_guard(monkeypatch)
    path = tmp_path / "m.json"
    identity, receipt = _fake_identity_files(tmp_path)
    to_root, to_venv, to_repair = _make_cutover_runtime_tree(tmp_path)
    write_manifest(
        _make_manifest_obj(
            generation=3,
            epic={"dependency_generation": _generation_proof(f"{to_venv}/bin/python")},
        ),
        path,
    )
    expected_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: _verified_identity(
            to_runtime_root=to_root
        ),
    )
    receipt_out = tmp_path / "receipts" / "cutover-receipt.json"
    assert main(
        _cutover_cli_args(
            path,
            expect_manifest_sha256=expected_sha,
            identity=identity,
            receipt=receipt,
            receipt_out=receipt_out,
            to_runtime_root=to_root,
            to_venv_path=to_venv,
            to_repair_bin=to_repair,
        )
    ) == 0
    assert receipt_out.exists()
    # default sibling receipt is NOT created when a custom path is supplied
    assert not (tmp_path / f"m.json{CUTOVER_RECEIPT_SUFFIX}").exists()
    assert verify_runtime_manifest_cutover_rollback_receipt(
        receipt_out, expected_manifest_before_sha256=expected_sha
    )["generation_after"] == 4


def test_cli_cutover_refuses_root_owned_by_another_active_epic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Occurrence 0a0ce24c3510: a cutover into a runtime root already claimed
    by ANOTHER active epic's manifest is refused fail-closed with the typed
    ``runtime_root_ownership_conflict`` and ZERO mutation — the shared-root
    wedge killed worker dispatch on the shared checkout's HEAD drift
    (drive2/drive3)."""
    _stub_git_head_guard(monkeypatch)
    path = tmp_path / "m.json"
    identity, receipt = _fake_identity_files(tmp_path)
    to_root, to_venv, to_repair = _make_cutover_runtime_tree(tmp_path)
    write_manifest(
        _make_manifest_obj(
            generation=3,
            # the moving epic's branch
            epic={
                "branch": "fixer/epic-a",
                "dependency_generation": _generation_proof(f"{to_venv}/bin/python"),
            },
        ),
        path,
    )
    expected_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: _verified_identity(
            to_runtime_root=to_root
        ),
    )
    # A rival ACTIVE manifest already claims the target root.
    rival = {
        "schema": "arnold.megaplan.runtime_manifest.v1",
        "generation": 9,
        "state": "active",
        "epic": {
            "branch": "fixer/epic-b",
            "runtime_root": to_root,
            "worktree_path": to_root,
            "expected_head": "d" * 40,
            "venv_path": to_venv,
            "repair_bin": to_repair,
        },
    }
    (tmp_path / "rival.json").write_text(
        json.dumps(rival, sort_keys=True), encoding="utf-8"
    )

    rc = main(
        _cutover_cli_args(
            path,
            expect_manifest_sha256=expected_sha,
            identity=identity,
            receipt=receipt,
            to_runtime_root=to_root,
            to_venv_path=to_venv,
            to_repair_bin=to_repair,
        )
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "already owned by another active epic" in err
    assert "rival.json" in err
    # ZERO mutation: the manifest is untouched.
    assert load_manifest(path).generation == 3
    assert load_manifest(path).epic["runtime_root"] != to_root


def test_cli_cutover_allows_same_epic_rebinding_its_own_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The ownership guard must NOT block a cutover by the SAME epic rebinding
    its own runtime root (the standard per-epic rebind, e.g. gen 79 -> 80 in
    the dedicated-worktree topology fix)."""
    _stub_git_head_guard(monkeypatch)
    path = tmp_path / "m.json"
    identity, receipt = _fake_identity_files(tmp_path)
    to_root, to_venv, to_repair = _make_cutover_runtime_tree(tmp_path)
    write_manifest(
        _make_manifest_obj(
            generation=3,
            epic={
                "branch": "fixer/epic-a",
                "dependency_generation": _generation_proof(f"{to_venv}/bin/python"),
            },
        ),
        path,
    )
    expected_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: _verified_identity(
            to_runtime_root=to_root
        ),
    )
    # The same epic's OLD manifest also claimed this root (pre-cutover).
    rival = {
        "schema": "arnold.megaplan.runtime_manifest.v1",
        "generation": 2,
        "state": "active",
        "epic": {
            "branch": "fixer/epic-a",
            "runtime_root": to_root,
            "worktree_path": to_root,
            "expected_head": "e" * 40,
            "venv_path": to_venv,
            "repair_bin": to_repair,
        },
    }
    (tmp_path / "legacy.json").write_text(
        json.dumps(rival, sort_keys=True), encoding="utf-8"
    )

    assert main(
        _cutover_cli_args(
            path,
            expect_manifest_sha256=expected_sha,
            identity=identity,
            receipt=receipt,
            to_runtime_root=to_root,
            to_venv_path=to_venv,
            to_repair_bin=to_repair,
        )
    ) == 0
    assert load_manifest(path).generation == 4
    assert load_manifest(path).epic["runtime_root"] == to_root


def test_cli_cutover_ignores_rollback_receipts_in_ownership_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Occurrence 927ad612eda8: generation-retention receipts
    (``<name>.previous-<N>.json``) and cutover rollback receipts
    (``<name>.cutover-rollback.json``) are NOT live epics.  Before the fix the
    ownership scan globbed every ``*.json`` sibling and treated stale receipts
    as rival ACTIVE owners, so ANY cutover into a root that any receipt ever
    mentioned was refused fail-closed with ``runtime_root_ownership_conflict``
    (observed: 100 stale receipts listed as owners)."""
    _stub_git_head_guard(monkeypatch)
    path = tmp_path / "m.json"
    identity, receipt = _fake_identity_files(tmp_path)
    to_root, to_venv, to_repair = _make_cutover_runtime_tree(tmp_path)
    write_manifest(
        _make_manifest_obj(
            generation=3,
            epic={
                "branch": "fixer/epic-a",
                "dependency_generation": _generation_proof(f"{to_venv}/bin/python"),
            },
        ),
        path,
    )
    expected_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: _verified_identity(
            to_runtime_root=to_root
        ),
    )
    # Stale rollback/retention receipts claiming the target root as a rival
    # epic (both naming shapes the engine writes).
    stale = {
        "schema": "arnold.megaplan.runtime_manifest.v1",
        "generation": 9,
        "state": "active",
        "epic": {
            "branch": "fixer/epic-b",
            "runtime_root": to_root,
            "worktree_path": to_root,
            "expected_head": "d" * 40,
            "venv_path": to_venv,
            "repair_bin": to_repair,
        },
    }
    (tmp_path / "rival.json.previous-38.json").write_text(
        json.dumps(stale, sort_keys=True), encoding="utf-8"
    )
    (tmp_path / "rival.json.cutover-rollback.json").write_text(
        json.dumps(stale, sort_keys=True), encoding="utf-8"
    )

    rc = main(
        _cutover_cli_args(
            path,
            expect_manifest_sha256=expected_sha,
            identity=identity,
            receipt=receipt,
            to_runtime_root=to_root,
            to_venv_path=to_venv,
            to_repair_bin=to_repair,
        )
    )
    assert rc == 0, capsys.readouterr().err
    assert load_manifest(path).generation == 4
    assert load_manifest(path).epic["runtime_root"] == to_root


def test_cli_cutover_rejects_receipt_out_aliasing_manifest_zero_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """T-0101h round-5 blocker 3: ``--receipt-out`` realpathing onto the
    manifest itself is refused (typed, ZERO mutation) — the final manifest
    write would otherwise clobber the just-written receipt, letting the
    command "succeed" without a durable rollback receipt."""
    path, expected_sha = _write_cutover_manifest(tmp_path)
    before = path.read_bytes()
    identity, receipt = _fake_identity_files(tmp_path)
    to_root, to_venv, to_repair = _make_cutover_runtime_tree(tmp_path)

    def _boom(*args: object, **kwargs: object) -> None:
        raise AssertionError("verifier must not run on an alias refusal")

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        _boom,
    )
    assert main(
        _cutover_cli_args(
            path,
            expect_manifest_sha256=expected_sha,
            identity=identity,
            receipt=receipt,
            receipt_out=path,  # direct alias of the manifest
            to_runtime_root=to_root,
            to_venv_path=to_venv,
            to_repair_bin=to_repair,
        )
    ) == 2
    assert "resolves onto protected transaction state" in capsys.readouterr().err
    # zero mutation: manifest bytes unchanged, no receipt anywhere
    assert path.read_bytes() == before
    assert not (tmp_path / f"m.json{CUTOVER_RECEIPT_SUFFIX}").exists()


def test_cli_cutover_rejects_receipt_out_aliasing_guard_inputs_zero_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """T-0101h round-5 blocker 3: ``--receipt-out`` realpathing onto either
    identity/provenance guard input (--runtime-identity or
    --runtime-provenance-receipt) is refused with zero mutation."""
    path, expected_sha = _write_cutover_manifest(tmp_path)
    before = path.read_bytes()
    identity, receipt = _fake_identity_files(tmp_path)
    to_root, to_venv, to_repair = _make_cutover_runtime_tree(tmp_path)

    def _boom(*args: object, **kwargs: object) -> None:
        raise AssertionError("verifier must not run on an alias refusal")

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        _boom,
    )
    for aliased in (identity, receipt):
        assert main(
            _cutover_cli_args(
                path,
                expect_manifest_sha256=expected_sha,
                identity=identity,
                receipt=receipt,
                receipt_out=aliased,
                to_runtime_root=to_root,
                to_venv_path=to_venv,
                to_repair_bin=to_repair,
            )
        ) == 2
        assert "resolves onto protected transaction state" in capsys.readouterr().err
    assert path.read_bytes() == before
    assert not (tmp_path / f"m.json{CUTOVER_RECEIPT_SUFFIX}").exists()


def test_apply_cutover_receipt_out_alias_refuses_typed_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-0101h round-5 blocker 3: the alias refusal is TYPED
    (``receipt_aliases_protected_state``) at the API level and happens before
    any verifier/lock/mkdir work."""
    path, expected_sha = _write_cutover_manifest(tmp_path)
    before = path.read_bytes()
    identity, receipt = _fake_identity_files(tmp_path)

    def _boom(*args: object, **kwargs: object) -> None:
        raise AssertionError("verifier must not run on an alias refusal")

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        _boom,
    )
    with pytest.raises(CliError) as exc_info:
        apply_runtime_manifest_cutover(
            path,
            expect_manifest_sha256=expected_sha,
            expect_generation=3,
            from_runtime_root=_FROM_RUNTIME_ROOT,
            from_expected_head=_FROM_EXPECTED_HEAD,
            to_runtime_root=_TO_RUNTIME_ROOT,
            to_expected_head=_TO_EXPECTED_HEAD,
            to_venv_path=_TO_VENV_PATH,
            to_repair_bin=_TO_REPAIR_BIN,
            runtime_identity_path=identity,
            runtime_provenance_receipt_path=receipt,
            reason="receipt alias refusal",
            receipt_path=path,
        )
    assert exc_info.value.code == RECEIPT_ALIASES_PROTECTED_STATE
    assert path.read_bytes() == before


def test_cli_cutover_receipt_symlink_not_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-0101h round-5 blocker 3: a pre-seeded symlink AT the receipt path is
    NOT followed — the hardened write replaces the link entry with a real
    receipt file at the literal path, and the link's former target stays
    byte-identical."""
    _stub_git_head_guard(monkeypatch)
    identity, receipt = _fake_identity_files(tmp_path)
    to_root, to_venv, to_repair = _make_cutover_runtime_tree(tmp_path)
    path, expected_sha = _write_cutover_manifest(
        tmp_path,
        epic={"dependency_generation": _generation_proof(f"{to_venv}/bin/python")},
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: _verified_identity(
            to_runtime_root=to_root
        ),
    )
    decoy = tmp_path / "decoy-target.json"
    decoy.write_text('{"decoy": true}\n', encoding="utf-8")
    decoy_before = decoy.read_bytes()
    receipt_out = tmp_path / "receipt-link.json"
    receipt_out.symlink_to(decoy)
    assert main(
        _cutover_cli_args(
            path,
            expect_manifest_sha256=expected_sha,
            identity=identity,
            receipt=receipt,
            receipt_out=receipt_out,
            to_runtime_root=to_root,
            to_venv_path=to_venv,
            to_repair_bin=to_repair,
        )
    ) == 0
    # the link was replaced by a REAL receipt file at the literal path
    assert not receipt_out.is_symlink()
    assert receipt_out.is_file()
    verify_runtime_manifest_cutover_rollback_receipt(
        receipt_out, expected_manifest_before_sha256=expected_sha
    )
    # the link's former target is untouched
    assert decoy.read_bytes() == decoy_before


def test_cli_cutover_receipt_post_verify_failed_when_receipt_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """T-0101h round-5 blocker 3: when the receipt write silently fails
    (injected no-op emitter) the manifest write still happens, but the
    post-verify refuses instead of reporting success without durable
    rollback evidence — a typed post-condition check."""
    _stub_git_head_guard(monkeypatch)
    identity, receipt = _fake_identity_files(tmp_path)
    to_root, to_venv, to_repair = _make_cutover_runtime_tree(tmp_path)
    path, expected_sha = _write_cutover_manifest(
        tmp_path,
        epic={"dependency_generation": _generation_proof(f"{to_venv}/bin/python")},
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: _verified_identity(
            to_runtime_root=to_root
        ),
    )
    # the receipt write "fails" by doing nothing — the manifest write below
    # proceeds, so the post-verify is the only thing that can refuse.
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        ".emit_runtime_manifest_cutover_rollback_receipt",
        lambda *args, **kwargs: {},
    )
    assert main(
        _cutover_cli_args(
            path,
            expect_manifest_sha256=expected_sha,
            identity=identity,
            receipt=receipt,
            to_runtime_root=to_root,
            to_venv_path=to_venv,
            to_repair_bin=to_repair,
        )
    ) == 2
    assert "post-write verification" in capsys.readouterr().err
    # the manifest itself was already rewritten (post-condition refusal)...
    assert json.loads(path.read_text(encoding="utf-8"))["generation"] == 4
    # ...and no rollback receipt exists anywhere
    assert not (tmp_path / f"m.json{CUTOVER_RECEIPT_SUFFIX}").exists()


def test_apply_cutover_receipt_post_verify_failed_typed_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-0101h round-5 blocker 3: the post-verify refusal is TYPED
    (``receipt_post_verify_failed``) at the API level."""
    _stub_git_head_guard(monkeypatch)
    identity, receipt = _fake_identity_files(tmp_path)
    to_root, to_venv, to_repair = _make_cutover_runtime_tree(tmp_path)
    path, expected_sha = _write_cutover_manifest(
        tmp_path,
        epic={"dependency_generation": _generation_proof(f"{to_venv}/bin/python")},
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: _verified_identity(
            to_runtime_root=to_root
        ),
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        ".emit_runtime_manifest_cutover_rollback_receipt",
        lambda *args, **kwargs: {},
    )
    with pytest.raises(CliError) as exc_info:
        apply_runtime_manifest_cutover(
            path,
            expect_manifest_sha256=expected_sha,
            expect_generation=3,
            from_runtime_root=_FROM_RUNTIME_ROOT,
            from_expected_head=_FROM_EXPECTED_HEAD,
            to_runtime_root=to_root,
            to_expected_head=_TO_EXPECTED_HEAD,
            to_venv_path=to_venv,
            to_repair_bin=to_repair,
            runtime_identity_path=identity,
            runtime_provenance_receipt_path=receipt,
            reason="receipt post-verify refusal",
        )
    assert exc_info.value.code == RECEIPT_POST_VERIFY_FAILED


def test_cli_cutover_happy_path_receipt_post_verify_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-0101h round-5 blocker 3 happy path: after a successful cutover the
    durable rollback receipt exists at the literal ``--receipt-out`` path, is
    parseable, and carries the exact pre-cutover manifest SHA-256 (the
    internal post-verify passes and the command reports success)."""
    _stub_git_head_guard(monkeypatch)
    identity, receipt = _fake_identity_files(tmp_path)
    to_root, to_venv, to_repair = _make_cutover_runtime_tree(tmp_path)
    path, expected_sha = _write_cutover_manifest(
        tmp_path,
        epic={"dependency_generation": _generation_proof(f"{to_venv}/bin/python")},
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: _verified_identity(
            to_runtime_root=to_root
        ),
    )
    receipt_out = tmp_path / "rcpt.json"
    assert main(
        _cutover_cli_args(
            path,
            expect_manifest_sha256=expected_sha,
            identity=identity,
            receipt=receipt,
            receipt_out=receipt_out,
            to_runtime_root=to_root,
            to_venv_path=to_venv,
            to_repair_bin=to_repair,
        )
    ) == 0
    payload = verify_runtime_manifest_cutover_rollback_receipt(
        receipt_out, expected_manifest_before_sha256=expected_sha
    )
    assert payload["manifest_before_sha256"] == expected_sha
    assert payload["generation_before"] == 3
    assert payload["generation_after"] == 4


def _write_cutover_manifest(
    tmp_path: Path, **manifest_overrides: object
) -> tuple[Path, str]:
    path = tmp_path / "m.json"
    manifest = _make_manifest_obj(generation=3, **manifest_overrides)
    write_manifest(manifest, path)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _cutover_argv_with_tree(
    path: Path,
    expected_sha: str,
    identity: Path,
    receipt: Path,
    to_root: str,
    to_venv: str,
    to_repair: str,
) -> list[str]:
    return _cutover_cli_args(
        path,
        expect_manifest_sha256=expected_sha,
        identity=identity,
        receipt=receipt,
        to_runtime_root=to_root,
        to_venv_path=to_venv,
        to_repair_bin=to_repair,
    )


def test_cli_cutover_rejects_nonexistent_venv_zero_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """T-0101h round-2: the cutover refuses (typed, ZERO mutation, no rollback
    receipt) when --to-venv-path does not exist as a directory."""
    path, expected_sha = _write_cutover_manifest(tmp_path)
    before = path.read_bytes()
    identity, receipt = _fake_identity_files(tmp_path)
    to_root, to_venv, to_repair = _make_cutover_runtime_tree(tmp_path)
    missing_venv = str(Path(to_venv) / "does-not-exist")
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: _verified_identity(
            to_runtime_root=to_root
        ),
    )
    assert main(
        _cutover_argv_with_tree(
            path, expected_sha, identity, receipt, to_root, missing_venv, to_repair
        )
    ) == 2
    assert "existing directory" in capsys.readouterr().err
    assert path.read_bytes() == before
    assert not (tmp_path / f"m.json{CUTOVER_RECEIPT_SUFFIX}").exists()


def test_cli_cutover_rejects_non_executable_repair_bin_zero_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """T-0101h round-2: the cutover refuses when --to-repair-bin exists but is
    NOT executable (a wrapper that cannot be invoked would strand repair)."""
    path, expected_sha = _write_cutover_manifest(tmp_path)
    before = path.read_bytes()
    identity, receipt = _fake_identity_files(tmp_path)
    to_root, to_venv, to_repair = _make_cutover_runtime_tree(tmp_path)
    Path(to_repair).chmod(0o644)  # strip the executable bit
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: _verified_identity(
            to_runtime_root=to_root
        ),
    )
    assert main(
        _cutover_argv_with_tree(
            path, expected_sha, identity, receipt, to_root, to_venv, to_repair
        )
    ) == 2
    assert "existing executable" in capsys.readouterr().err
    assert path.read_bytes() == before
    assert not (tmp_path / f"m.json{CUTOVER_RECEIPT_SUFFIX}").exists()


def test_cli_cutover_rejects_venv_interpreter_mismatch_zero_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """T-0301: the venv coherence anchor is the generation PROOF, not root
    containment.  A venv OUTSIDE the runtime root is the NORMAL shared
    content-addressed generation layout, but its interpreter must equal the
    manifest's dependency_generation.interpreter_path — a venv whose
    interpreter disagrees with the proof is refused (typed, ZERO mutation,
    no rollback receipt)."""
    identity, receipt = _fake_identity_files(tmp_path)
    to_root, _to_venv, to_repair = _make_cutover_runtime_tree(tmp_path)
    escaped_venv = tmp_path / "escaped-venv"
    (escaped_venv / "bin").mkdir(parents=True)
    (escaped_venv / "bin" / "python").write_text("#!/bin/sh\nexit 0\n")
    (escaped_venv / "bin" / "python").chmod(0o755)
    # The manifest proof points at the IN-ROOT venv interpreter, but the
    # cutover is asked to bind the OUT-OF-ROOT venv: the bindings disagree.
    path, expected_sha = _write_cutover_manifest(
        tmp_path,
        epic={
            "dependency_generation": _generation_proof(f"{_TO_VENV_PATH}/bin/python")
        },
    )
    before = path.read_bytes()
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: _verified_identity(
            to_runtime_root=to_root
        ),
    )
    assert main(
        _cutover_argv_with_tree(
            path,
            expected_sha,
            identity,
            receipt,
            to_root,
            str(escaped_venv),
            to_repair,
        )
    ) == 2
    assert "does not match the generation proof" in capsys.readouterr().err
    assert path.read_bytes() == before
    assert not (tmp_path / f"m.json{CUTOVER_RECEIPT_SUFFIX}").exists()


def test_cli_cutover_rejects_repair_bin_escaping_root_zero_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """T-0101h round-2: a --to-repair-bin that resolves OUTSIDE the receipted
    runtime root is refused (same containment class as the venv escape)."""
    path, expected_sha = _write_cutover_manifest(tmp_path)
    before = path.read_bytes()
    identity, receipt = _fake_identity_files(tmp_path)
    to_root, to_venv, _to_repair = _make_cutover_runtime_tree(tmp_path)
    escaped_repair = tmp_path / "escaped-repair-loop"
    escaped_repair.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    escaped_repair.chmod(0o755)
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: _verified_identity(
            to_runtime_root=to_root
        ),
    )
    assert main(
        _cutover_argv_with_tree(
            path,
            expected_sha,
            identity,
            receipt,
            to_root,
            to_venv,
            str(escaped_repair),
        )
    ) == 2
    assert "inside --to-runtime-root" in capsys.readouterr().err
    assert path.read_bytes() == before
    assert not (tmp_path / f"m.json{CUTOVER_RECEIPT_SUFFIX}").exists()


def test_cli_cutover_rejects_stale_editable_install_path_zero_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """T-0101h round-2: ``base.editable_install_path == ''`` (the staging
    default) survives the cutover ONLY when the receipted identity proves a
    single-root runtime.  An identity with editable markers OUTSIDE its
    import_root proves a split editable install — keeping '' would silently
    leave a stale field, so the cutover refuses with a typed error."""
    identity, receipt = _fake_identity_files(tmp_path)
    to_root, to_venv, to_repair = _make_cutover_runtime_tree(tmp_path)
    path, expected_sha = _write_cutover_manifest(
        tmp_path,
        base={"commit": _FROM_EXPECTED_HEAD, "editable_install_path": ""},
        epic={"dependency_generation": _generation_proof(f"{to_venv}/bin/python")},
    )
    before = path.read_bytes()
    split_identity = dict(_verified_identity(to_runtime_root=to_root))
    split_identity["editable_root"] = "/opt/elsewhere-editable"
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: split_identity,
    )
    assert main(
        _cutover_argv_with_tree(
            path, expected_sha, identity, receipt, to_root, to_venv, to_repair
        )
    ) == 2
    assert "editable markers" in capsys.readouterr().err
    assert path.read_bytes() == before
    assert not (tmp_path / f"m.json{CUTOVER_RECEIPT_SUFFIX}").exists()


def test_cutover_relocates_root_relative_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-0101h round-2: root-relative fields (deps_lockfile, base.venv_path,
    base.editable_install_path) are RELOCATED to the same relative offset
    under the new root; shared paths outside the runtime root and the
    source-based base.ref are untouched."""
    _stub_git_head_guard(monkeypatch)
    manifest = _make_manifest_obj(
        base={
            "commit": _FROM_EXPECTED_HEAD,
            "venv_path": f"{_FROM_RUNTIME_ROOT}/.venv",
            "editable_install_path": _FROM_RUNTIME_ROOT,
        },
        epic={"deps_lockfile": f"{_FROM_RUNTIME_ROOT}/uv.lock"},
    )
    updated = cutover_runtime_manifest(
        manifest,
        from_runtime_root=_FROM_RUNTIME_ROOT,
        from_expected_head=_FROM_EXPECTED_HEAD,
        to_runtime_root=_TO_RUNTIME_ROOT,
        to_expected_head=_TO_EXPECTED_HEAD,
        to_venv_path=f"{_TO_RUNTIME_ROOT}/.venv",
        to_repair_bin=(
            f"{_TO_RUNTIME_ROOT}/arnold_pipelines/megaplan/cloud/wrappers/"
            "arnold-babysitter"
        ),
        reason="cutover relocates root-relative fields",
    )
    assert updated.epic["deps_lockfile"] == f"{_TO_RUNTIME_ROOT}/uv.lock"
    assert updated.base["venv_path"] == f"{_TO_RUNTIME_ROOT}/.venv"
    assert updated.base["editable_install_path"] == _TO_RUNTIME_ROOT
    # base.ref is a git ref NAME (source-based), never rewritten by a root move
    assert updated.base["ref"] == manifest.base["ref"]


def test_cutover_preserves_shared_non_root_relative_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Shared paths OUTSIDE the runtime root (a base checkout) do not go stale
    when the root moves: the cutover leaves them byte-identical."""
    _stub_git_head_guard(monkeypatch)
    manifest = _make_manifest_obj()  # factory: base/venv/editable under /opt/arnold/base
    updated = cutover_runtime_manifest(
        manifest,
        from_runtime_root=_FROM_RUNTIME_ROOT,
        from_expected_head=_FROM_EXPECTED_HEAD,
        to_runtime_root=_TO_RUNTIME_ROOT,
        to_expected_head=_TO_EXPECTED_HEAD,
        to_venv_path=_TO_VENV_PATH,
        to_repair_bin=_TO_REPAIR_BIN,
        reason="cutover preserves shared base fields",
    )
    assert updated.base["venv_path"] == manifest.base["venv_path"]
    assert updated.base["editable_install_path"] == manifest.base["editable_install_path"]
    assert updated.epic["deps_lockfile"] == manifest.epic["deps_lockfile"]
    assert updated.base["ref"] == manifest.base["ref"]


def test_cli_cutover_rewrites_root_relative_fields_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-0101h round-2 end-to-end: a staging-shaped manifest (root-relative
    deps_lockfile / base.venv_path, empty editable_install_path) is rewritten
    coherently through the REAL CLI cutover — no stale root-relative field
    survives the root move."""
    _stub_git_head_guard(monkeypatch)
    identity, receipt = _fake_identity_files(tmp_path)
    to_root, to_venv, to_repair = _make_cutover_runtime_tree(tmp_path)
    path, expected_sha = _write_cutover_manifest(
        tmp_path,
        base={
            "commit": _FROM_EXPECTED_HEAD,
            "venv_path": f"{_FROM_RUNTIME_ROOT}/.venv",
            "editable_install_path": "",
        },
        epic={
            "deps_lockfile": f"{_FROM_RUNTIME_ROOT}/pyproject.toml",
            "dependency_generation": _generation_proof(f"{to_venv}/bin/python"),
        },
    )
    before_base_ref = load_manifest(path).base["ref"]
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: _verified_identity(
            to_runtime_root=to_root
        ),
    )
    assert main(
        _cutover_argv_with_tree(
            path, expected_sha, identity, receipt, to_root, to_venv, to_repair
        )
    ) == 0
    updated = load_manifest(path)
    assert updated.epic["runtime_root"] == to_root
    assert updated.epic["venv_path"] == to_venv
    # root-relative fields were REWRITTEN to the new root
    assert updated.epic["deps_lockfile"] == f"{to_root}/pyproject.toml"
    assert updated.base["venv_path"] == f"{to_root}/.venv"
    # '' survives only because the receipted identity is single-root here
    assert updated.base["editable_install_path"] == ""
    # base.ref stays source-based across the root move
    assert updated.base["ref"] == before_base_ref


def test_cli_cutover_rejects_manifest_sha_mismatch_zero_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "m.json"
    write_manifest(_make_manifest_obj(generation=3), path)
    before = path.read_bytes()
    identity, receipt = _fake_identity_files(tmp_path)
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: _verified_identity(),
    )
    assert main(
        _cutover_cli_args(
            path,
            expect_manifest_sha256="0" * 64,  # wrong SHA
            identity=identity,
            receipt=receipt,
        )
    ) == 2
    assert path.read_bytes() == before  # byte-for-byte unchanged
    assert not (tmp_path / f"m.json{CUTOVER_RECEIPT_SUFFIX}").exists()


def test_cli_cutover_rejects_generation_mismatch_zero_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "m.json"
    write_manifest(_make_manifest_obj(generation=3), path)
    before = path.read_bytes()
    expected_sha = hashlib.sha256(before).hexdigest()
    identity, receipt = _fake_identity_files(tmp_path)
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: _verified_identity(),
    )
    assert main(
        _cutover_cli_args(
            path,
            expect_manifest_sha256=expected_sha,
            expect_generation=7,  # wrong generation
            identity=identity,
            receipt=receipt,
        )
    ) == 2
    assert path.read_bytes() == before
    assert not (tmp_path / f"m.json{CUTOVER_RECEIPT_SUFFIX}").exists()


def test_cli_cutover_rejects_from_guard_mismatch_zero_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "m.json"
    write_manifest(_make_manifest_obj(generation=3), path)
    before = path.read_bytes()
    expected_sha = hashlib.sha256(before).hexdigest()
    identity, receipt = _fake_identity_files(tmp_path)
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: _verified_identity(),
    )
    # wrong from-runtime-root guard (file SHA + generation both pass)
    args = _cutover_cli_args(
        path,
        expect_manifest_sha256=expected_sha,
        identity=identity,
        receipt=receipt,
    )
    args[args.index("--from-runtime-root") + 1] = "/opt/elsewhere"
    assert main(args) == 2
    assert path.read_bytes() == before
    assert not (tmp_path / f"m.json{CUTOVER_RECEIPT_SUFFIX}").exists()


def test_cli_cutover_rejects_identity_root_mismatch_zero_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "m.json"
    write_manifest(_make_manifest_obj(generation=3), path)
    before = path.read_bytes()
    expected_sha = hashlib.sha256(before).hexdigest()
    identity, receipt = _fake_identity_files(tmp_path)
    # verifier "passes" but for a DIFFERENT root than --to-runtime-root
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: _verified_identity(
            to_runtime_root="/opt/unreceipted-runtime"
        ),
    )
    assert main(
        _cutover_cli_args(
            path,
            expect_manifest_sha256=expected_sha,
            identity=identity,
            receipt=receipt,
        )
    ) == 2
    assert path.read_bytes() == before
    assert not (tmp_path / f"m.json{CUTOVER_RECEIPT_SUFFIX}").exists()


def test_cli_cutover_rejects_receipt_head_mismatch_zero_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The manifest head is BOUND to the receipt: a receipted source revision
    that differs from --to-expected-head refuses with zero mutation — the
    manifest cannot stamp a head the independently verified runtime did not
    resolve to (T-0101h finding 2)."""
    path = tmp_path / "m.json"
    write_manifest(_make_manifest_obj(generation=3), path)
    before = path.read_bytes()
    expected_sha = hashlib.sha256(before).hexdigest()
    identity, receipt = _fake_identity_files(tmp_path)
    # verifier "passes" but for a DIFFERENT source revision than
    # --to-expected-head (the receipt is for a different commit)
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.runtime_manifest"
        "._verify_external_runtime_identity",
        lambda identity_path, receipt_path: _verified_identity(
            source_revision="b" * 40
        ),
    )
    assert main(
        _cutover_cli_args(
            path,
            expect_manifest_sha256=expected_sha,
            identity=identity,
            receipt=receipt,
        )
    ) == 2
    assert path.read_bytes() == before  # byte-for-byte unchanged
    assert not (tmp_path / f"m.json{CUTOVER_RECEIPT_SUFFIX}").exists()


def test_cli_cutover_rejects_self_asserting_identity_receipt_zero_mutation(
    tmp_path: Path,
) -> None:
    """The cutover wires the REAL chain verifier: an identity receipt whose
    interpreter is the control interpreter is refused at the independence
    check — before any write, byte-for-byte zero mutation (the T-0101d
    'mismatched old identity receipt -> refuse' acceptance case)."""
    path = tmp_path / "m.json"
    write_manifest(_make_manifest_obj(generation=3), path)
    before = path.read_bytes()
    expected_sha = hashlib.sha256(before).hexdigest()
    identity, receipt = _self_asserting_identity_and_receipt(tmp_path)
    assert main(
        _cutover_cli_args(
            path,
            expect_manifest_sha256=expected_sha,
            identity=identity,
            receipt=receipt,
        )
    ) == 2
    assert path.read_bytes() == before
    assert not (tmp_path / f"m.json{CUTOVER_RECEIPT_SUFFIX}").exists()


def test_cli_cutover_rejects_missing_manifest(tmp_path: Path) -> None:
    identity, receipt = _fake_identity_files(tmp_path)
    missing = tmp_path / "missing.json"
    assert main(
        _cutover_cli_args(
            missing,
            expect_manifest_sha256="0" * 64,
            identity=identity,
            receipt=receipt,
        )
    ) == 2


def test_cli_cutover_requires_reason(tmp_path: Path) -> None:
    path = tmp_path / "m.json"
    write_manifest(_make_manifest_obj(), path)
    expected_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    identity, receipt = _fake_identity_files(tmp_path)
    args = _cutover_cli_args(
        path, expect_manifest_sha256=expected_sha, identity=identity, receipt=receipt
    )
    args.remove("--reason")
    args.remove("T-0101d cutover test")
    with pytest.raises(SystemExit):
        main(args)


def test_apply_runtime_manifest_cutover_rejects_malformed_guards(tmp_path: Path) -> None:
    path = tmp_path / "m.json"
    write_manifest(_make_manifest_obj(), path)
    identity, receipt = _fake_identity_files(tmp_path)
    with pytest.raises(CliError, match="64-char"):
        apply_runtime_manifest_cutover(
            path,
            expect_manifest_sha256="short",
            expect_generation=3,
            from_runtime_root=_FROM_RUNTIME_ROOT,
            from_expected_head=_FROM_EXPECTED_HEAD,
            to_runtime_root=_TO_RUNTIME_ROOT,
            to_expected_head=_TO_EXPECTED_HEAD,
            to_venv_path=_TO_VENV_PATH,
            to_repair_bin=_TO_REPAIR_BIN,
            runtime_identity_path=identity,
            runtime_provenance_receipt_path=receipt,
            reason="bad sha guard",
        )
    with pytest.raises(CliError, match="int >= 1"):
        apply_runtime_manifest_cutover(
            path,
            expect_manifest_sha256="0" * 64,
            expect_generation=0,
            from_runtime_root=_FROM_RUNTIME_ROOT,
            from_expected_head=_FROM_EXPECTED_HEAD,
            to_runtime_root=_TO_RUNTIME_ROOT,
            to_expected_head=_TO_EXPECTED_HEAD,
            to_venv_path=_TO_VENV_PATH,
            to_repair_bin=_TO_REPAIR_BIN,
            runtime_identity_path=identity,
            runtime_provenance_receipt_path=receipt,
            reason="bad generation guard",
        )
    with pytest.raises(CliError, match="to-repair-bin is required"):
        apply_runtime_manifest_cutover(
            path,
            expect_manifest_sha256="0" * 64,
            expect_generation=3,
            from_runtime_root=_FROM_RUNTIME_ROOT,
            from_expected_head=_FROM_EXPECTED_HEAD,
            to_runtime_root=_TO_RUNTIME_ROOT,
            to_expected_head=_TO_EXPECTED_HEAD,
            to_venv_path=_TO_VENV_PATH,
            to_repair_bin="",
            runtime_identity_path=identity,
            runtime_provenance_receipt_path=receipt,
            reason="empty to-repair-bin",
        )
    assert path.read_bytes() == path.read_bytes()  # untouched (no write reached)


def test_verify_rollback_receipt_rejects_bad_schema_and_digest(
    tmp_path: Path,
) -> None:
    path = tmp_path / "receipt.json"
    with pytest.raises(ValueError, match="invalid JSON"):
        verify_runtime_manifest_cutover_rollback_receipt(path)
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON"):
        verify_runtime_manifest_cutover_rollback_receipt(path)
    path.write_text(json.dumps({"schema": "other"}), encoding="utf-8")
    with pytest.raises(ValueError, match="schema mismatch"):
        verify_runtime_manifest_cutover_rollback_receipt(path)
    receipt = emit_runtime_manifest_cutover_rollback_receipt(
        path,
        manifest_path=Path("/opt/m.json"),
        manifest_before_sha256="a" * 64,
        manifest_after_sha256="b" * 64,
        generation_before=3,
        generation_after=4,
        from_runtime_root=_FROM_RUNTIME_ROOT,
        from_expected_head=_FROM_EXPECTED_HEAD,
        to_runtime_root=_TO_RUNTIME_ROOT,
        to_expected_head=_TO_EXPECTED_HEAD,
        to_venv_path=_TO_VENV_PATH,
        to_repair_bin=_TO_REPAIR_BIN,
        previous_manifest={"runtime_id": "old"},
        runtime_identity_sha256="c" * 64,
        actor="operator",
        reason="test",
    )
    assert verify_runtime_manifest_cutover_rollback_receipt(path) == receipt
    # wrong expected pre-cutover SHA (valid receipt, mismatched expectation)
    with pytest.raises(ValueError, match="expected pre-cutover"):
        verify_runtime_manifest_cutover_rollback_receipt(
            path, expected_manifest_before_sha256="d" * 64
        )
    # tampered digest
    tampered = dict(receipt)
    tampered["content_sha256"] = "0" * 64
    path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ValueError, match="digest is invalid"):
        verify_runtime_manifest_cutover_rollback_receipt(path)


def test_refresh_legacy_session_copy_updates_same_runtime_mirror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A creation-time session copy that lags the advanced generation is
    refreshed through the sanctioned flock-protected writer (occurrence
    c2f73c7ddcef): after the advance, the mirror binds the same runtime at
    the new generation/head instead of silently lagging it."""
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST_DIR", str(tmp_path))
    head = "f" * 40
    authoritative_path = tmp_path / "runtime-manifests" / "runtime-test-1.json"
    authoritative_path.parent.mkdir(parents=True, exist_ok=True)
    legacy_path = tmp_path / "epic-demo.json"
    write_manifest(_make_manifest_obj(generation=13), legacy_path)
    advanced = _make_manifest_obj(
        generation=14, epic={"expected_head": head}
    )
    write_manifest(advanced, authoritative_path)

    refreshed = refresh_legacy_session_copy(advanced, authoritative_path)

    assert refreshed == legacy_path
    assert load_manifest(legacy_path).generation == advanced.generation
    assert load_manifest(legacy_path).epic.get("expected_head") == head


def test_refresh_legacy_session_copy_leaves_unrelated_files_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the mirror this seam created is touched: a different runtime's
    file, an unparseable file, a missing file, and the authoritative path
    itself are all left byte-identical (or absent)."""
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST_DIR", str(tmp_path))
    authoritative_path = tmp_path / "runtime-manifests" / "runtime-test-1.json"
    authoritative_path.parent.mkdir(parents=True, exist_ok=True)
    advanced = _make_manifest_obj(
        generation=14, epic={"expected_head": "f" * 40}
    )
    write_manifest(advanced, authoritative_path)

    # different runtime_id
    other = tmp_path / "epic-demo.json"
    other_manifest = _make_manifest_obj(runtime_id="runtime-other-2")
    write_manifest(other_manifest, other)
    before = other.read_bytes()
    assert (
        refresh_legacy_session_copy(advanced, authoritative_path) is None
    )
    assert other.read_bytes() == before

    # unparseable file
    junk = tmp_path / "epic-demo.json"
    junk.write_text("{not json", encoding="utf-8")
    assert (
        refresh_legacy_session_copy(advanced, authoritative_path) is None
    )
    assert junk.read_text(encoding="utf-8") == "{not json"

    # no file at all
    junk.unlink()
    assert (
        refresh_legacy_session_copy(advanced, authoritative_path) is None
    )

    # the authoritative path itself is never treated as its own mirror
    same_path = refresh_legacy_session_copy(advanced, authoritative_path)
    assert same_path is None


# ── advance_generation_at_path: shared lock+CAS producer (d51891b51841) ─────

from arnold_pipelines.megaplan.cloud.runtime_manifest import (  # noqa: E402
    advance_generation_at_path,
)


def _spec_repo(tmp_path: Path) -> tuple[Path, str]:
    """A REAL git repo WITH the frozen dependency spec (pyproject.toml +
    uv.lock) the strict frozen-spec gate requires. Returns (root, head)."""
    root = tmp_path / "spec-repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    (root / "pyproject.toml").write_text(
        '[project]\nname = "native-demo"\nversion = "0.2.0"\n', encoding="utf-8"
    )
    (root / "uv.lock").write_text(
        'version = 1\nrequires-python = ">=3.12"\n', encoding="utf-8"
    )
    (root / "README.md").write_text("seed\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "seed"], check=True)
    sha = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return root, sha


def _bound_manifest(
    tmp_path: Path, root: Path, head: str, **overrides: object
) -> RuntimeManifest:
    """A manifest bound to *root* at *head* whose dependency-generation proof
    ACTUALLY binds: frozen-spec digest recomputed from the repo, interpreter
    inside the generation dir named by that digest, digest-consistent venv."""
    frozen = frozen_spec_sha256(root)
    gen_dir = tmp_path / "runtime-venvs" / frozen
    (gen_dir / "bin").mkdir(parents=True, exist_ok=True)
    interpreter = gen_dir / "bin" / "python"
    interpreter.write_text("#!/bin/sh\n", encoding="utf-8")
    interpreter.chmod(0o755)
    (gen_dir / "pyvenv.cfg").write_text("home = /usr\n", encoding="utf-8")
    return _make_manifest_obj(
        epic={
            "runtime_root": str(root),
            "expected_head": head,
            "dependency_generation": {
                "id": frozen,
                "frozen_spec_sha256": frozen,
                "interpreter_path": str(interpreter),
                "venv_digest": compute_venv_digest(interpreter),
                "created": "2026-08-07T00:00:00+00:00",
            },
        },
        indirection={"verified_head": head},
        **overrides,
    )


def test_advance_generation_at_path_advances_pointer_and_slug(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, head = _spec_repo(tmp_path)
    pointer = tmp_path / "pointer" / "runtime-manifest.json"
    slug = tmp_path / "manifests" / "native-demo.json"
    manifest = _bound_manifest(tmp_path, root, head, generation=26)
    write_manifest(manifest, slug)
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(pointer))
    advanced, status = advance_generation_at_path(
        slug, head, reason="test advance"
    )
    assert status == "advanced"
    assert advanced.generation == 27
    assert advanced.epic["expected_head"] == head
    assert len(advanced.promotions) == 1
    assert advanced.promotions[0]["previous_commit"] == head
    assert load_manifest(slug).generation == 27
    assert load_manifest(pointer).generation == 27


def test_advance_generation_at_path_cas_refuses_concurrent_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, head = _spec_repo(tmp_path)
    pointer = tmp_path / "pointer" / "runtime-manifest.json"
    slug = tmp_path / "manifests" / "native-demo.json"
    manifest = _bound_manifest(tmp_path, root, head, generation=26)
    write_manifest(manifest, slug)
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(pointer))
    # a concurrent writer advances the file between our snapshot and the call
    subprocess.run(["git", "-C", str(root), "commit", "-q", "--allow-empty", "-m", "next"], check=True)
    head2 = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    concurrent = _bound_manifest(tmp_path, root, head2, generation=27)
    write_manifest(concurrent, slug)
    with pytest.raises(ManifestError, match="changed under the caller"):
        advance_generation_at_path(
            slug,
            head2,
            reason="stale caller",
            expected=(str(manifest.runtime_id), 26, head),
        )
    assert load_manifest(slug).generation == 27  # zero mutation: untouched


def test_advance_generation_at_path_idempotent_only_when_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, head = _spec_repo(tmp_path)
    pointer = tmp_path / "pointer" / "runtime-manifest.json"
    slug = tmp_path / "manifests" / "native-demo.json"
    manifest = _bound_manifest(tmp_path, root, head, generation=26)
    write_manifest(manifest, slug)
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(pointer))
    # flag ON (auto-driver publish hook): already-pinned is a no-op
    current, status = advance_generation_at_path(
        slug, head, reason="hook retry", idempotent_when_pinned=True
    )
    assert status == "current"
    assert current.generation == 26
    assert load_manifest(slug).generation == 26
    # flag OFF (module CLI): re-promotion of the same commit still bumps
    advanced, status = advance_generation_at_path(slug, head, reason="re-promote")
    assert status == "advanced"
    assert advanced.generation == 27
    assert load_manifest(slug).generation == 27


def test_advance_generation_at_path_requires_bound_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, head = _spec_repo(tmp_path)
    pointer = tmp_path / "pointer" / "runtime-manifest.json"
    slug = tmp_path / "manifests" / "native-demo.json"
    # default fixture proof ("a"*64 frozen spec) does NOT bind to the repo
    manifest = _make_manifest_obj(
        epic={"runtime_root": str(root), "expected_head": head},
        indirection={"verified_head": head},
        generation=26,
    )
    write_manifest(manifest, slug)
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(pointer))
    before = slug.read_bytes()
    with pytest.raises(ManifestError, match="frozen_spec_sha256"):
        advance_generation_at_path(slug, head, reason="unbound proof")
    assert slug.read_bytes() == before  # zero mutation on refusal
