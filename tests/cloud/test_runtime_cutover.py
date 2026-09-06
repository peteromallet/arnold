from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from arnold_pipelines.megaplan.chain.execution_binding import (
    cutover_runtime_identity,
)
from arnold_pipelines.megaplan.cloud import runtime_cutover
from arnold_pipelines.megaplan.cloud import legacy_marker_runtime_migration
from arnold_pipelines.megaplan.cloud.legacy_marker_runtime_migration import (
    migrate_legacy_marker_runtime,
)
from arnold_pipelines.megaplan.cloud.runtime_cutover import (
    marker_runtime_identity,
    normalize_runtime_identity,
    update_marker_runtime,
)
from arnold_pipelines.megaplan.types import CliError


def _write_marker(path: Path) -> dict:
    manifest_path = path.with_name("runtime-manifest.json")
    manifest_path.write_bytes(b'{"schema":"1","generation":1}\n')
    marker = {
        "session": "custody",
        "workspace": "/workspace/project",
        "remote_spec": "/workspace/project/chain.yaml",
        "editable_source_head": "a" * 40,
        "editable_source_branch": "legacy",
        "editable_install_sync": {
            "status": "private-venv-editable",
            "source": "/workspace/runtime-a",
        },
        "engine_ref_check": {"status": "stale"},
        "launch_command": "old launch",
        "relaunch_command": "old relaunch",
        "bootstrap_manifest_path": str(manifest_path),
    }
    path.write_text(json.dumps(marker, sort_keys=True) + "\n", encoding="utf-8")
    return marker


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _runtime_b() -> dict:
    return normalize_runtime_identity(
        {
            "import_root": "/workspace/runtime-b",
            "source_revision": "b" * 40,
            "editable_root": "/workspace/runtime-b",
            "editable_revision": "b" * 40,
            "direct_url": {
                "dir_info": {"editable": True},
                "url": "file:///workspace/runtime-b",
            },
            "pth": [
                {
                    "path": "/venv/site-packages/_editable_impl_arnold.pth",
                    "entries": ["/workspace/runtime-b"],
                    "readable": True,
                }
            ],
            "imports": {
                "arnold": "/workspace/runtime-b/arnold/__init__.py",
                "arnold_pipelines": "/workspace/runtime-b/arnold_pipelines/__init__.py",
                "megaplan": "/workspace/runtime-b/arnold_pipelines/megaplan/__init__.py",
            },
        }
    )


def _runtime_b_relaunch() -> str:
    return f"exec /workspace/runtime-b/bin/chain # {'b' * 40}"


def _legacy_runtime() -> dict:
    root = "/workspace/runtime-candidates/arnold-18b279f5ef-live"
    return normalize_runtime_identity(
        {
            "import_root": root,
            "source_revision": "1" * 40,
            "editable_root": root,
            "editable_revision": "1" * 40,
            "direct_url": {
                "dir_info": {"editable": True},
                "url": f"file://{root}",
            },
            "pth": [
                {
                    "path": "/venv/site-packages/_editable_impl_arnold.pth",
                    "entries": [root],
                    "readable": True,
                }
            ],
            "imports": {
                "arnold": f"{root}/arnold/__init__.py",
                "arnold_pipelines": f"{root}/arnold_pipelines/__init__.py",
                "megaplan": f"{root}/arnold_pipelines/megaplan/__init__.py",
            },
        }
    )


def _legacy_migration_fixture(tmp_path: Path) -> dict:
    session = "critique-ledger-r5"
    workspace = "/workspace/critique-ledger-r5/Arnold"
    remote_spec = f"{workspace}/.megaplan/initiatives/critique-ledger/chain.yaml"
    plan = "cl2-wbc-backed-ledger"
    runtime = _legacy_runtime()
    relaunch = (
        f"SRC={runtime['import_root']}; "
        f"PYTHONPATH={runtime['import_root']} python -P -m "
        f"arnold_pipelines.megaplan chain start --spec {remote_spec}"
    )
    marker_path = tmp_path / f"{session}.json"
    marker_path.write_text(
        json.dumps(
            {
                "session": session,
                "workspace": workspace,
                "remote_spec": remote_spec,
                "run_kind": "chain",
                "should_run": False,
                "operator_pause": {"active": True, "plan": plan},
                "editable_source_branch": "editible-install",
                "editable_source_head": None,
                "editable_install_sync": {
                    "status": "skipped",
                    "reason": "disabled_by_flag",
                },
                "relaunch_command": relaunch,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    chain_state_path = tmp_path / "chain-state.json"
    chain_state_path.write_text(
        json.dumps(
            {
                "current_plan_name": plan,
                "last_state": "paused",
                "metadata": {
                    "operator_pause": {"active": True, "plan": plan},
                    "chain_spec_path": remote_spec,
                    "execution_binding": {
                        "launched_identity": {"spec_path": remote_spec},
                        "runtime_binding": {"current_identity": runtime},
                    },
                },
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    identity_path = tmp_path / "runtime-identity.json"
    identity_path.write_text(json.dumps(runtime), encoding="utf-8")
    receipt_path = tmp_path / "runtime-receipt.json"
    receipt_path.write_text("{}\n", encoding="utf-8")
    return {
        "session": session,
        "workspace": workspace,
        "remote_spec": remote_spec,
        "plan": plan,
        "runtime": runtime,
        "relaunch": relaunch,
        "marker_path": marker_path,
        "chain_state_path": chain_state_path,
        "identity_path": identity_path,
        "receipt_path": receipt_path,
    }


def _migrate_legacy(fixture: dict, **overrides):
    marker_path = fixture["marker_path"]
    args = {
        "expected_marker_sha256": _sha(marker_path),
        "expected_relaunch_command_sha256": hashlib.sha256(
            fixture["relaunch"].encode("utf-8")
        ).hexdigest(),
        "expected_legacy_runtime_root": fixture["runtime"]["import_root"],
        "expected_chain_runtime_sha256": fixture["runtime"]["content_sha256"],
        "expected_session": fixture["session"],
        "expected_workspace": fixture["workspace"],
        "expected_remote_spec": fixture["remote_spec"],
        "expected_current_plan": fixture["plan"],
        "chain_state_path": fixture["chain_state_path"],
        "runtime_identity_path": fixture["identity_path"],
        "runtime_provenance_receipt_path": fixture["receipt_path"],
        "reason": "bind exact legacy runtime before cutover",
        "actor": "test-operator",
    }
    args.update(overrides)
    return migrate_legacy_marker_runtime(marker_path, **args)


def test_marker_runtime_update_is_cas_guarded_and_clears_obsolete_fields(
    tmp_path: Path,
) -> None:
    marker_path = tmp_path / "custody.json"
    marker = _write_marker(marker_path)
    previous = marker_runtime_identity(marker)
    assert previous is not None

    result = update_marker_runtime(
        marker_path,
        expected_marker_sha256=_sha(marker_path),
        expected_previous_runtime_sha256=previous["content_sha256"],
        active_runtime_identity=_runtime_b(),
        relaunch_command=_runtime_b_relaunch(),
        source_branch="archive/runtime-b",
        reason="verified runtime cutover",
    )

    updated = json.loads(marker_path.read_text())
    assert updated["editable_source_head"] == "b" * 40
    assert updated["runtime_binding"]["current_identity"]["content_sha256"] == _runtime_b()[
        "content_sha256"
    ]
    assert updated["runtime_binding"]["rebind_events"][0]["direction"] == "cutover"
    assert "engine_ref_check" not in updated
    assert "launch_command" not in updated
    assert result["marker_after_sha256"] == _sha(marker_path)

    with pytest.raises(CliError, match="marker changed"):
        update_marker_runtime(
            marker_path,
            expected_marker_sha256=result["marker_before_sha256"],
            expected_previous_runtime_sha256=previous["content_sha256"],
            active_runtime_identity=_runtime_b(),
            relaunch_command=_runtime_b_relaunch(),
            reason="stale writer",
        )


def test_marker_runtime_cutover_atomically_rebinds_manifest_identity(
    tmp_path: Path,
) -> None:
    marker_path = tmp_path / "custody.json"
    marker = _write_marker(marker_path)
    previous = marker_runtime_identity(marker)
    assert previous is not None
    manifest_path = tmp_path / "runtime-manifest.json"
    manifest_path.write_bytes(b'{"schema":"1","generation":1}\n')

    update_marker_runtime(
        marker_path,
        expected_marker_sha256=_sha(marker_path),
        expected_previous_runtime_sha256=previous["content_sha256"],
        active_runtime_identity=_runtime_b(),
        relaunch_command=_runtime_b_relaunch(),
        reason="manifest-bound runtime cutover",
        manifest_path=manifest_path,
    )
    updated = json.loads(marker_path.read_text())
    expected = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert updated["manifest_identity"] == expected
    assert updated["manifest_sha256"] == expected


def test_runtime_cutover_cli_binds_manifest_and_refuses_bad_authority_without_mutation(
    tmp_path: Path,
) -> None:
    marker_path = tmp_path / "custody.json"
    marker = _write_marker(marker_path)
    previous = marker_runtime_identity(marker)
    assert previous is not None
    identity_path = tmp_path / "runtime-identity.json"
    identity_path.write_text(json.dumps(_runtime_b()), encoding="utf-8")
    command_path = tmp_path / "relaunch.txt"
    command_path.write_text(_runtime_b_relaunch(), encoding="utf-8")
    manifest_path = Path(str(marker["bootstrap_manifest_path"]))

    argv = [
        "--marker", str(marker_path),
        "--manifest", str(manifest_path),
        "--expect-marker-sha256", _sha(marker_path),
        "--from-runtime-sha256", previous["content_sha256"],
        "--runtime-identity", str(identity_path),
        "--relaunch-command-file", str(command_path),
        "--reason", "cli manifest-bound cutover",
    ]
    assert runtime_cutover.main(argv) == 0
    updated = json.loads(marker_path.read_text())
    expected = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert updated["manifest_identity"] == expected
    assert updated["manifest_sha256"] == expected

    for mutation in ("tamper", "missing", "mismatch"):
        before = marker_path.read_bytes()
        if mutation == "tamper":
            manifest_path.write_bytes(b'{"schema":"1","generation":2}\n')
            selected = manifest_path
        elif mutation == "missing":
            selected = tmp_path / "missing-runtime-manifest.json"
        else:
            selected = tmp_path / "other-runtime-manifest.json"
            selected.write_bytes(b'{"schema":"1","generation":1}\n')
        bad_argv = [*argv]
        bad_argv[bad_argv.index("--manifest") + 1] = str(selected)
        bad_argv[bad_argv.index("--expect-marker-sha256") + 1] = _sha(marker_path)
        with pytest.raises(CliError):
            runtime_cutover.main(bad_argv)
        assert marker_path.read_bytes() == before


def test_marker_runtime_update_failure_before_replace_leaves_original(
    tmp_path: Path,
    monkeypatch,
) -> None:
    marker_path = tmp_path / "custody.json"
    marker = _write_marker(marker_path)
    before = marker_path.read_bytes()
    previous = marker_runtime_identity(marker)
    assert previous is not None
    monkeypatch.setattr(
        runtime_cutover.os,
        "replace",
        lambda *_args: (_ for _ in ()).throw(OSError("injected replace failure")),
    )

    with pytest.raises(OSError, match="injected"):
        update_marker_runtime(
            marker_path,
            expected_marker_sha256=_sha(marker_path),
            expected_previous_runtime_sha256=previous["content_sha256"],
            active_runtime_identity=_runtime_b(),
            relaunch_command=_runtime_b_relaunch(),
            reason="failure injection",
        )

    assert marker_path.read_bytes() == before
    assert [
        path.name for path in tmp_path.glob("custody.json.*")
    ] == ["custody.json.runtime-cutover.lock"]


def test_marker_runtime_update_rejects_mismatched_relaunch_before_mutation(
    tmp_path: Path,
) -> None:
    marker_path = tmp_path / "custody.json"
    marker = _write_marker(marker_path)
    before = marker_path.read_bytes()
    previous = marker_runtime_identity(marker)
    assert previous is not None

    with pytest.raises(CliError, match="does not bind"):
        update_marker_runtime(
            marker_path,
            expected_marker_sha256=_sha(marker_path),
            expected_previous_runtime_sha256=previous["content_sha256"],
            active_runtime_identity=_runtime_b(),
            relaunch_command=f"exec /workspace/runtime-a/bin/chain # {'a' * 40}",
            reason="must reject split custody",
        )

    assert marker_path.read_bytes() == before


def _composition_chain_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, SimpleNamespace, dict, dict]:
    """Synthetic post-T-0101b chain state: bound old runtime, initialized
    engine_root, drifted successor runtime — no git repo required."""
    import arnold_pipelines.megaplan.chain.execution_binding as eb

    spec_path = tmp_path / "chain.yaml"
    old_root = "/workspace/runtime-a"
    old_runtime = normalize_runtime_identity(
        {
            "import_root": old_root,
            "source_revision": "a" * 40,
            "editable_root": old_root,
            "editable_revision": "a" * 40,
            "direct_url": {
                "dir_info": {"editable": True},
                "url": f"file://{old_root}",
            },
            "pth": [
                {
                    "path": "/venv/site-packages/_editable_impl_arnold.pth",
                    "entries": [old_root],
                    "readable": True,
                }
            ],
            "imports": {
                "arnold": f"{old_root}/arnold/__init__.py",
                "arnold_pipelines": f"{old_root}/arnold_pipelines/__init__.py",
                "megaplan": f"{old_root}/arnold_pipelines/megaplan/__init__.py",
            },
        }
    )
    new_runtime = _runtime_b()
    launched = {
        "schema": "arnold.megaplan.chain_execution_binding.v1",
        "spec_path": str(spec_path),
        "chain_spec_sha256": "a" * 64,
        "bundle_sha256": "b" * 64,
        "milestone_sequence": [
            {"index": 0, "label": "c1"},
            {"index": 1, "label": "c2"},
        ],
        "assets": [],
        "intended_initiative_revision": "a" * 40,
        "initiative_path": "initiative",
        "runtime": old_runtime,
        "revision_verification": {"ok": True},
        "ready": True,
        "errors": [],
    }
    state = SimpleNamespace(
        metadata={
            "execution_binding": {
                "schema": "arnold.megaplan.chain_execution_binding.v1",
                "launched_identity": launched,
                "runtime_binding": {
                    "schema": "arnold.megaplan.chain_runtime_binding.v1",
                    "current_identity": old_runtime,
                    "rebind_events": [],
                },
            },
            "execution_environment": {"engine_root": old_root},
        },
        current_milestone_index=0,
        current_plan_name="c1-plan",
        last_state="paused",
        completed=[],
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.chain.execution_binding.binding_policy",
        lambda _path: {
            "required": True,
            "mode": "required",
            "intended_initiative_revision": "a" * 40,
            "initiative_path": "initiative",
            "execution_binding_assets": [],
            "require_editable_runtime_match": True,
        },
    )
    active = json.loads(json.dumps(launched))
    active["runtime"] = new_runtime
    active["ready"] = True
    active["errors"] = []
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.chain.execution_binding.active_execution_identity",
        lambda _path: active,
    )
    return spec_path, state, old_runtime, new_runtime


def test_chain_runtime_cutover_composes_with_marker_runtime_update(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-0101c composition: after ``chain runtime-cutover`` moves the chain's
    engine_root, the marker-side ``update_marker_runtime`` accepts the SAME
    new identity with a relaunch command binding the new root — the chain's
    new runtime binding and the marker's runtime binding converge."""
    spec_path, state, old_runtime, new_runtime = _composition_chain_state(
        tmp_path, monkeypatch
    )

    cutover = cutover_runtime_identity(
        spec_path,
        state,
        expected_previous_runtime_sha256=old_runtime["content_sha256"],
        expected_active_runtime_sha256=new_runtime["content_sha256"],
        expected_current_milestone="c1",
        expected_current_plan="c1-plan",
        reason="chain cutover then marker sync",
    )
    assert cutover["runtime_binding"]["status"] == "match"
    assert state.metadata["execution_environment"]["engine_root"] == str(
        Path(new_runtime["import_root"]).resolve()
    )
    chain_new_identity = state.metadata["execution_binding"]["runtime_binding"][
        "current_identity"
    ]
    assert chain_new_identity["content_sha256"] == new_runtime["content_sha256"]

    marker_path = tmp_path / "custody.json"
    manifest_path = tmp_path / "runtime-manifest.json"
    manifest_path.write_bytes(b'{"schema":"1","generation":1}\n')
    marker_path.write_text(
        json.dumps(
            {
                "session": "custody",
                "workspace": "/workspace/project",
                "remote_spec": "/workspace/project/chain.yaml",
                "runtime_binding": {
                    "schema": "arnold.megaplan.marker_runtime_binding.v1",
                    "current_identity": old_runtime,
                    "rebind_events": [],
                },
                "editable_source_head": "a" * 40,
                "editable_source_branch": "legacy",
                "editable_install_sync": {
                    "status": "content-addressed-runtime",
                    "source": old_runtime["import_root"],
                    "runtime_sha256": old_runtime["content_sha256"],
                },
                    "relaunch_command": "old relaunch",
                    "bootstrap_manifest_path": str(manifest_path),
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    marker_result = update_marker_runtime(
        marker_path,
        expected_marker_sha256=_sha(marker_path),
        expected_previous_runtime_sha256=old_runtime["content_sha256"],
        active_runtime_identity=chain_new_identity,
        relaunch_command=_runtime_b_relaunch(),
        reason="marker follows chain cutover",
        manifest_path=manifest_path,
    )
    assert (
        marker_result["runtime_binding"]["current_identity"]["content_sha256"]
        == new_runtime["content_sha256"]
    )
    assert marker_result["event"]["from_runtime_sha256"] == cutover["event"][
        "from_runtime_sha256"
    ]
    assert marker_result["event"]["to_runtime_sha256"] == cutover["event"][
        "to_runtime_sha256"
    ]
    updated_marker = json.loads(marker_path.read_text(encoding="utf-8"))
    assert (
        updated_marker["runtime_binding"]["current_identity"]["content_sha256"]
        == new_runtime["content_sha256"]
    )


def test_legacy_marker_migration_binds_exact_chain_runtime_and_immutable_evidence(
    tmp_path: Path, monkeypatch
) -> None:
    fixture = _legacy_migration_fixture(tmp_path)
    verifier_calls: list[tuple[Path, Path]] = []

    def verifier(identity_path: Path, receipt_path: Path) -> dict:
        verifier_calls.append((identity_path, receipt_path))
        return fixture["runtime"]

    monkeypatch.setattr(
        legacy_marker_runtime_migration, "verify_external_runtime_identity", verifier
    )

    result = _migrate_legacy(fixture)

    assert verifier_calls == [
        (fixture["identity_path"].resolve(), fixture["receipt_path"].resolve())
    ]
    marker = json.loads(fixture["marker_path"].read_text(encoding="utf-8"))
    assert marker_runtime_identity(marker) == fixture["runtime"]
    assert marker["should_run"] is False
    assert marker["operator_pause"]["active"] is True
    assert marker["relaunch_command"] == fixture["relaunch"]
    assert marker["run_id"] == result["run_id"]
    assert marker["run_id"]
    assert result["marker_after_sha256"] == _sha(fixture["marker_path"])
    receipt_path = Path(result["receipt_path"])
    commit_path = Path(result["commit_path"])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    commit = json.loads(commit_path.read_text(encoding="utf-8"))
    assert receipt["run_id"] == result["run_id"]
    assert receipt["marker_before_sha256"] == result["marker_before_sha256"]
    assert receipt["marker_after_sha256"] == result["marker_after_sha256"]
    assert commit["receipt_sha256"] == _sha(receipt_path)

    with pytest.raises(FileExistsError):
        receipt_path.open("x").close()
    with pytest.raises(FileExistsError):
        commit_path.open("x").close()


def test_legacy_marker_migration_output_is_strong_runtime_binding(
    tmp_path: Path, monkeypatch
) -> None:
    """T-0101h round-2: the migration must leave the marker in the STRONG
    runtime_binding form (content-addressable current_identity built from the
    independently-verified OLD runtime receipt: content_sha256, import_root ==
    old runtime root, source_revision == old expected head) so a subsequent
    update_marker_runtime CAS runs against the strong form — never the weak
    legacy fallback."""
    fixture = _legacy_migration_fixture(tmp_path)
    monkeypatch.setattr(
        legacy_marker_runtime_migration,
        "verify_external_runtime_identity",
        lambda *_args: fixture["runtime"],
    )
    result = _migrate_legacy(fixture)

    marker = json.loads(fixture["marker_path"].read_text(encoding="utf-8"))
    binding = marker["runtime_binding"]
    assert binding["schema"] == "arnold.megaplan.marker_runtime_binding.v1"
    current = binding["current_identity"]
    # strong content-addressed form: digest, root, and revision all come
    # from the OLD verified runtime (source_revision == old expected head,
    # import_root == old runtime root).
    assert current["content_sha256"] == fixture["runtime"]["content_sha256"]
    assert current["import_root"] == fixture["runtime"]["import_root"]
    assert current["source_revision"] == fixture["runtime"]["source_revision"]
    # the strong binding is what marker_runtime_identity resolves now
    assert marker_runtime_identity(marker) == fixture["runtime"]
    assert marker["editable_install_sync"]["status"] == "content-addressed-runtime"
    assert (
        marker["editable_install_sync"]["source"] == fixture["runtime"]["import_root"]
    )
    assert marker["editable_install_sync"]["runtime_sha256"] == fixture["runtime"][
        "content_sha256"
    ]
    assert marker["editable_source_head"] == fixture["runtime"]["source_revision"]
    # evidence binds the migrated marker to the strong form too
    receipt = json.loads(Path(result["receipt_path"]).read_text(encoding="utf-8"))
    assert receipt["runtime_root"] == fixture["runtime"]["import_root"]
    assert receipt["runtime_revision"] == fixture["runtime"]["source_revision"]


def test_legacy_marker_migration_refuses_marker_with_legacy_editable_fields(
    tmp_path: Path, monkeypatch
) -> None:
    """One-time migration, identity-less markers ONLY: a marker carrying the
    weak legacy editable form (editable_source_head + editable_install_sync.
    source) already resolves a runtime identity, so the migration must refuse
    it with zero mutation — such a marker routes through ordinary cutover
    (or a prior migration round) instead."""
    fixture = _legacy_migration_fixture(tmp_path)
    monkeypatch.setattr(
        legacy_marker_runtime_migration,
        "verify_external_runtime_identity",
        lambda *_args: fixture["runtime"],
    )
    marker = json.loads(fixture["marker_path"].read_text(encoding="utf-8"))
    marker["editable_source_head"] = fixture["runtime"]["source_revision"]
    marker["editable_install_sync"] = {
        "status": "private-venv-editable",
        "source": fixture["runtime"]["import_root"],
    }
    fixture["marker_path"].write_text(json.dumps(marker), encoding="utf-8")
    # sanity: this marker IS identity-resolvable through the weak fallback
    assert marker_runtime_identity(marker) is not None
    before = fixture["marker_path"].read_bytes()

    with pytest.raises(CliError, match="already has a runtime identity"):
        _migrate_legacy(fixture)

    assert fixture["marker_path"].read_bytes() == before


def test_post_migration_update_marker_runtime_cas_succeeds_on_strong_form(
    tmp_path: Path, monkeypatch
) -> None:
    """T-0101h round-2 wiring: after legacy_marker_runtime_migration binds the
    marker to the OLD runtime via the strong runtime_binding form, an ordinary
    update_marker_runtime cutover CASes against that strong form and succeeds —
    the rehearsal's step (g) must run against this fully bound marker."""
    fixture = _legacy_migration_fixture(tmp_path)
    monkeypatch.setattr(
        legacy_marker_runtime_migration,
        "verify_external_runtime_identity",
        lambda *_args: fixture["runtime"],
    )
    _migrate_legacy(fixture)
    migrated = json.loads(fixture["marker_path"].read_text(encoding="utf-8"))
    previous = marker_runtime_identity(migrated)
    # the CAS guard is the STRONG form's digest, not a synthesized fallback
    assert previous == fixture["runtime"]
    assert previous["content_sha256"] == fixture["runtime"]["content_sha256"]

    new_runtime = _runtime_b()
    manifest_path = tmp_path / "runtime-manifest.json"
    manifest_path.write_bytes(b'{"schema":"1","generation":1}\n')
    migrated["bootstrap_manifest_path"] = str(manifest_path)
    fixture["marker_path"].write_text(
        json.dumps(migrated, sort_keys=True) + "\n", encoding="utf-8"
    )
    result = update_marker_runtime(
        fixture["marker_path"],
        expected_marker_sha256=_sha(fixture["marker_path"]),
        expected_previous_runtime_sha256=previous["content_sha256"],
        active_runtime_identity=new_runtime,
        relaunch_command=_runtime_b_relaunch(),
        reason="post-migration marker cutover to the verified successor runtime",
        manifest_path=manifest_path,
    )
    assert result["event"]["from_runtime_sha256"] == previous["content_sha256"]
    assert result["event"]["to_runtime_sha256"] == new_runtime["content_sha256"]
    updated = json.loads(fixture["marker_path"].read_text(encoding="utf-8"))
    assert (
        updated["runtime_binding"]["current_identity"]["content_sha256"]
        == new_runtime["content_sha256"]
    )
    assert updated["runtime_binding"]["rebind_events"][0]["direction"] == "cutover"
    # the CAS event chain records the migration origin: the first rebind
    # event's from-digest IS the strong-form old runtime the migration bound
    assert (
        updated["runtime_binding"]["rebind_events"][0]["from_runtime_sha256"]
        == fixture["runtime"]["content_sha256"]
    )
    assert result["marker_after_sha256"] == _sha(fixture["marker_path"])


def test_legacy_marker_migration_retry_after_committed_receipt_crash_finalizes(
    tmp_path: Path, monkeypatch
) -> None:
    """T-0101h round-3: the migration writes prepared receipt → marker
    replacement → committed receipt.  If it dies between the marker
    replacement and the committed receipt, the marker is strong-bound but
    uncommitted.  Re-invoking with the ORIGINAL exact guards must recognize
    the prepared after-image, emit the missing committed receipt, and return
    success (idempotent finalize) — never refuse."""
    fixture = _legacy_migration_fixture(tmp_path)
    monkeypatch.setattr(
        legacy_marker_runtime_migration,
        "verify_external_runtime_identity",
        lambda *_args: fixture["runtime"],
    )
    before_sha = _sha(fixture["marker_path"])
    real_write_immutable = legacy_marker_runtime_migration._write_immutable

    def _crash_at_commit(path: Path, value: dict) -> None:
        if path.name.endswith(".committed.json"):
            raise OSError("injected committed-receipt write failure")
        real_write_immutable(path, value)

    monkeypatch.setattr(
        legacy_marker_runtime_migration, "_write_immutable", _crash_at_commit
    )
    with pytest.raises(OSError, match="committed-receipt"):
        _migrate_legacy(fixture)
    # Step 3 crashed: marker strong-bound, prepared receipt present,
    # committed receipt absent.
    marker = json.loads(fixture["marker_path"].read_text(encoding="utf-8"))
    assert marker_runtime_identity(marker) == fixture["runtime"]
    evidence_root = (
        fixture["marker_path"].parent
        / "runtime-marker-migrations"
        / fixture["session"]
    )
    prepared_paths = sorted(evidence_root.glob("*.prepared.json"))
    committed_paths = sorted(evidence_root.glob("*.committed.json"))
    assert len(prepared_paths) == 1
    assert committed_paths == []
    prepared = json.loads(prepared_paths[0].read_text(encoding="utf-8"))
    assert prepared["marker_after_sha256"] == _sha(fixture["marker_path"])

    # Identical invocation (same original before-image guards) recovers.
    monkeypatch.setattr(
        legacy_marker_runtime_migration, "_write_immutable", real_write_immutable
    )
    result = _migrate_legacy(fixture, expected_marker_sha256=before_sha)
    assert result["marker_before_sha256"] == before_sha
    assert result["marker_after_sha256"] == _sha(fixture["marker_path"])
    assert result["run_id"] == prepared["run_id"]
    assert result["migration_id"] == prepared["migration_id"]
    assert result["runtime_sha256"] == prepared["runtime_sha256"]
    committed_paths = sorted(evidence_root.glob("*.committed.json"))
    assert len(committed_paths) == 1
    commit = json.loads(committed_paths[0].read_text(encoding="utf-8"))
    assert commit["migration_id"] == prepared["migration_id"]
    assert commit["marker_after_sha256"] == prepared["marker_after_sha256"]
    assert commit["receipt_sha256"] == _sha(prepared_paths[0])
    assert Path(result["receipt_path"]) == prepared_paths[0]
    assert Path(result["commit_path"]) == committed_paths[0]
    # Re-running again is still idempotent: no evidence collision.
    again = _migrate_legacy(fixture, expected_marker_sha256=before_sha)
    assert again["migration_id"] == prepared["migration_id"]
    assert len(sorted(evidence_root.glob("*.committed.json"))) == 1


class _MarkerWriteFailingTempfile:
    """Stand-in for the ``tempfile`` module global inside the migration
    module: ``mkstemp`` succeeds ONCE (the prepared receipt) and raises on
    the next call — the MARKER replacement's temp file, BEFORE
    ``os.replace``.  Every other attribute delegates to the real module."""

    def __init__(self) -> None:
        self._calls = 0

    def mkstemp(self, *_args, **_kwargs):
        if self._calls == 0:
            self._calls += 1
            return tempfile.mkstemp(*_args, **_kwargs)
        raise OSError("injected marker tempfile failure")

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
    """Stand-in for the ``time`` module global inside the migration module:
    ``strftime`` returns a FIXED stamp (simulating a retry at a later
    wall-clock time); ``gmtime`` returns ``None``."""

    def __init__(self, stamp: str) -> None:
        self._stamp = stamp

    def strftime(self, _fmt: str, _when: Any = None) -> str:
        return self._stamp

    def gmtime(self) -> None:
        return None


class _FsyncOrderSpyOS:
    """Stand-in for the ``os`` module global inside the migration module:
    records every ``fsync`` (labelled with the path the descriptor was
    opened on, or ``fd:N`` for descriptors obtained via
    ``tempfile.mkstemp``), ``replace``, and ``link`` so a test can assert
    the crash-durability ordering: prepared-directory fsync → marker
    replacement + marker-directory fsync → committed-directory fsync.
    Every other attribute delegates to the real module."""

    def __init__(self) -> None:
        self.events: list[tuple[str, ...]] = []
        self._fd_paths: dict[int, str] = {}

    def open(self, path, flags, mode=0o777, **kwargs):
        descriptor = os.open(path, flags, mode, **kwargs)
        self._fd_paths[descriptor] = str(path)
        return descriptor

    def close(self, descriptor):
        self._fd_paths.pop(descriptor, None)
        os.close(descriptor)

    def fsync(self, descriptor):
        self.events.append(
            ("fsync", self._fd_paths.get(descriptor, f"fd:{descriptor}"))
        )
        os.fsync(descriptor)

    def replace(self, source, destination, **kwargs):
        self.events.append(("replace", str(source), str(destination)))
        os.replace(source, destination, **kwargs)

    def link(self, source, destination, **kwargs):
        self.events.append(("link", str(source), str(destination)))
        os.link(source, destination, **kwargs)

    def __getattr__(self, name):
        return getattr(os, name)


@pytest.mark.parametrize("failure", ["tempfile", "replace"])
def test_legacy_marker_migration_retry_after_marker_write_failure_reuses_prepared_after_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    """T-0101h round-4 blocker 1: the prepared receipt is committed BEFORE
    the marker replacement.  If the marker write dies — the marker's
    tempfile, or the ``os.replace`` itself — a DELAYED identical retry must
    REUSE the stranded prepared receipt's EXACT after-image (its
    ``prepared_at``), never recompute time-dependent bytes: recomputing at a
    later wall-clock time would change the after-image, collide with the
    immutable prepared receipt, and permanently wedge the retry."""
    fixture = _legacy_migration_fixture(tmp_path)
    monkeypatch.setattr(
        legacy_marker_runtime_migration,
        "verify_external_runtime_identity",
        lambda *_args: fixture["runtime"],
    )
    before_sha = _sha(fixture["marker_path"])
    if failure == "tempfile":
        real_tempfile = legacy_marker_runtime_migration.tempfile
        monkeypatch.setattr(
            legacy_marker_runtime_migration,
            "tempfile",
            _MarkerWriteFailingTempfile(),
        )
        try:
            with pytest.raises(OSError, match="injected marker tempfile failure"):
                _migrate_legacy(fixture)
        finally:
            monkeypatch.setattr(
                legacy_marker_runtime_migration, "tempfile", real_tempfile
            )
    else:
        real_os = legacy_marker_runtime_migration.os
        monkeypatch.setattr(legacy_marker_runtime_migration, "os", _FailingReplaceOS())
        try:
            with pytest.raises(OSError, match="injected marker replace failure"):
                _migrate_legacy(fixture)
        finally:
            monkeypatch.setattr(legacy_marker_runtime_migration, "os", real_os)
    # The marker is byte-unchanged, but the prepared receipt IS stranded.
    assert _sha(fixture["marker_path"]) == before_sha
    assert marker_runtime_identity(
        json.loads(fixture["marker_path"].read_text(encoding="utf-8"))
    ) is None
    evidence_root = (
        fixture["marker_path"].parent
        / "runtime-marker-migrations"
        / fixture["session"]
    )
    prepared_paths = sorted(evidence_root.glob("*.prepared.json"))
    committed_paths = sorted(evidence_root.glob("*.committed.json"))
    assert len(prepared_paths) == 1
    assert committed_paths == []
    prepared = json.loads(prepared_paths[0].read_text(encoding="utf-8"))
    prepared_bytes = prepared_paths[0].read_bytes()

    # DELAYED retry: the wall clock has advanced to a fixed FUTURE stamp —
    # recomputing time-dependent bytes would change the after-image and
    # collide with the immutable prepared receipt.  The retry must reuse the
    # prepared record instead and complete the migration.
    monkeypatch.setattr(
        legacy_marker_runtime_migration,
        "time",
        _FixedClock("2099-12-31T23:59:59Z"),
    )
    result = _migrate_legacy(fixture)
    assert result["marker_before_sha256"] == before_sha
    assert result["marker_after_sha256"] == prepared["marker_after_sha256"]
    assert result["migration_id"] == prepared["migration_id"]
    assert result["run_id"] == prepared["run_id"]
    assert result["runtime_sha256"] == prepared["runtime_sha256"]
    assert _sha(fixture["marker_path"]) == prepared["marker_after_sha256"]
    assert prepared_paths[0].read_bytes() == prepared_bytes, (
        "the retry must reuse the stranded prepared receipt, not rewrite it"
    )
    committed_paths = sorted(evidence_root.glob("*.committed.json"))
    assert len(committed_paths) == 1
    commit = json.loads(committed_paths[0].read_text(encoding="utf-8"))
    assert commit["migration_id"] == prepared["migration_id"]
    assert commit["marker_after_sha256"] == prepared["marker_after_sha256"]
    assert commit["receipt_sha256"] == _sha(prepared_paths[0])
    # The reused after-image kept the ORIGINAL prepared timestamp — the
    # delayed future wall-clock never leaked into the marker bytes.
    marker = json.loads(fixture["marker_path"].read_text(encoding="utf-8"))
    assert marker["runtime_binding"]["last_rebound_at"] == prepared["prepared_at"]
    assert marker["updated_at"] == prepared["prepared_at"]
    assert marker["run_id"] == prepared["run_id"]


@pytest.mark.parametrize(
    "tamper",
    [
        "expected_marker_sha256",
        "expected_relaunch_command_sha256",
        "chain_state",
        "runtime_identity",
        "runtime_receipt",
    ],
)
def test_legacy_marker_migration_refuses_wrong_guard_against_prepared_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tamper: str
) -> None:
    """T-0101h round-4 blocker 2: receipt finalization must bind EVERY
    invocation guard + evidence digest to the prepared record.  A step-3
    crash leaves a strong-bound marker + prepared receipt (no committed
    receipt); re-invoking with ANY ONE wrong guard must refuse with ZERO
    marker or evidence mutation — the finalize path must NOT accept on
    session/path/after-image alone."""
    fixture = _legacy_migration_fixture(tmp_path)
    monkeypatch.setattr(
        legacy_marker_runtime_migration,
        "verify_external_runtime_identity",
        lambda *_args: fixture["runtime"],
    )
    before_sha = _sha(fixture["marker_path"])
    real_write_immutable = legacy_marker_runtime_migration._write_immutable

    def _crash_at_commit(path: Path, value: dict) -> None:
        if path.name.endswith(".committed.json"):
            raise OSError("injected committed-receipt write failure")
        real_write_immutable(path, value)

    monkeypatch.setattr(
        legacy_marker_runtime_migration, "_write_immutable", _crash_at_commit
    )
    with pytest.raises(OSError, match="committed-receipt"):
        _migrate_legacy(fixture)
    monkeypatch.setattr(
        legacy_marker_runtime_migration, "_write_immutable", real_write_immutable
    )
    evidence_root = (
        fixture["marker_path"].parent
        / "runtime-marker-migrations"
        / fixture["session"]
    )
    prepared_paths = sorted(evidence_root.glob("*.prepared.json"))
    assert len(prepared_paths) == 1
    assert list(evidence_root.glob("*.committed.json")) == []
    marker_before_probe = fixture["marker_path"].read_bytes()
    evidence_before = {
        str(path): path.read_bytes()
        for path in sorted(evidence_root.rglob("*"))
        if path.is_file()
    }

    overrides: dict[str, str] = {"expected_marker_sha256": before_sha}
    if tamper == "expected_marker_sha256":
        overrides["expected_marker_sha256"] = "0" * 64
    elif tamper == "expected_relaunch_command_sha256":
        overrides["expected_relaunch_command_sha256"] = "0" * 64
    elif tamper == "chain_state":
        state = json.loads(fixture["chain_state_path"].read_text(encoding="utf-8"))
        state["metadata"]["probe"] = "tampered"
        fixture["chain_state_path"].write_text(json.dumps(state), encoding="utf-8")
    elif tamper == "runtime_identity":
        identity = json.loads(fixture["identity_path"].read_text(encoding="utf-8"))
        identity["probe"] = "tampered"
        fixture["identity_path"].write_text(json.dumps(identity), encoding="utf-8")
    else:
        fixture["receipt_path"].write_text('{"probe": "tampered"}\n', encoding="utf-8")

    with pytest.raises(CliError, match="refusing foreign mutation"):
        _migrate_legacy(fixture, **overrides)

    assert fixture["marker_path"].read_bytes() == marker_before_probe
    assert {
        str(path): path.read_bytes()
        for path in sorted(evidence_root.rglob("*"))
        if path.is_file()
    } == evidence_before


def test_legacy_marker_migration_refuses_wrong_guard_when_committed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-0101h round-4 blocker 2: once the migration is FULLY committed, a
    re-invocation with any wrong guard must still refuse with ZERO mutation —
    the committed receipt binds every guard digest, so already-committed
    idempotency cannot be tricked by a stale or wrong-guard invocation."""
    fixture = _legacy_migration_fixture(tmp_path)
    monkeypatch.setattr(
        legacy_marker_runtime_migration,
        "verify_external_runtime_identity",
        lambda *_args: fixture["runtime"],
    )
    before_sha = _sha(fixture["marker_path"])
    first = _migrate_legacy(fixture)
    evidence_root = (
        fixture["marker_path"].parent
        / "runtime-marker-migrations"
        / fixture["session"]
    )
    marker_before_probe = fixture["marker_path"].read_bytes()
    chain_state_bytes = fixture["chain_state_path"].read_bytes()
    evidence_before = {
        str(path): path.read_bytes()
        for path in sorted(evidence_root.rglob("*"))
        if path.is_file()
    }

    # Wrong chain-state evidence digest against the committed marker.
    state = json.loads(fixture["chain_state_path"].read_text(encoding="utf-8"))
    state["metadata"]["probe"] = "tampered"
    fixture["chain_state_path"].write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(CliError, match="refusing foreign mutation"):
        _migrate_legacy(fixture, expected_marker_sha256=before_sha)
    assert fixture["marker_path"].read_bytes() == marker_before_probe
    assert {
        str(path): path.read_bytes()
        for path in sorted(evidence_root.rglob("*"))
        if path.is_file()
    } == evidence_before

    # The after-image digest is NOT the before-image guard: an invocation
    # binding the CURRENT strong marker digest must refuse too.
    with pytest.raises(CliError, match="already has a runtime identity"):
        _migrate_legacy(fixture)
    assert fixture["marker_path"].read_bytes() == marker_before_probe
    assert {
        str(path): path.read_bytes()
        for path in sorted(evidence_root.rglob("*"))
        if path.is_file()
    } == evidence_before

    # Even with the prepared receipt deleted, the committed record alone
    # carries the guard digests and refuses wrong guards...
    prepared_paths = sorted(evidence_root.glob("*.prepared.json"))
    assert len(prepared_paths) == 1
    prepared_paths[0].unlink()
    state = json.loads(fixture["chain_state_path"].read_text(encoding="utf-8"))
    state["metadata"]["probe"] = "tampered-again"
    fixture["chain_state_path"].write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(CliError, match="refusing foreign mutation"):
        _migrate_legacy(fixture, expected_marker_sha256=before_sha)
    assert fixture["marker_path"].read_bytes() == marker_before_probe
    # ...while the CORRECT guards still succeed (committed-only idempotency):
    # restore the EXACT original chain-state bytes so every evidence digest
    # matches the committed record again.
    fixture["chain_state_path"].write_bytes(chain_state_bytes)
    rerun = _migrate_legacy(fixture, expected_marker_sha256=before_sha)
    assert rerun["migration_id"] == first["migration_id"]
    assert rerun["marker_after_sha256"] == first["marker_after_sha256"]


def test_legacy_marker_migration_rerun_on_committed_marker_is_idempotent(
    tmp_path: Path, monkeypatch
) -> None:
    """Once the migration fully commits, a re-invocation with the ORIGINAL
    exact guards is idempotent: the strong-bound marker matches the
    committed after-image and the run returns success without rewriting the
    marker — even with the prepared receipt deleted, the committed receipt
    alone recognizes the marker."""
    fixture = _legacy_migration_fixture(tmp_path)
    monkeypatch.setattr(
        legacy_marker_runtime_migration,
        "verify_external_runtime_identity",
        lambda *_args: fixture["runtime"],
    )
    before_sha = _sha(fixture["marker_path"])
    first = _migrate_legacy(fixture)
    evidence_root = (
        fixture["marker_path"].parent
        / "runtime-marker-migrations"
        / fixture["session"]
    )
    prepared_paths = sorted(evidence_root.glob("*.prepared.json"))
    committed_paths = sorted(evidence_root.glob("*.committed.json"))
    assert len(prepared_paths) == 1 and len(committed_paths) == 1
    prepared_bytes = prepared_paths[0].read_bytes()
    committed_bytes = committed_paths[0].read_bytes()
    marker_after_retry = fixture["marker_path"].read_bytes()

    # Same exact guards, marker already strong-bound: success, no rewrite.
    rerun = _migrate_legacy(fixture, expected_marker_sha256=before_sha)
    assert rerun["marker_after_sha256"] == first["marker_after_sha256"]
    assert rerun["migration_id"] == first["migration_id"]
    assert rerun["marker_before_sha256"] == before_sha
    assert fixture["marker_path"].read_bytes() == marker_after_retry
    assert prepared_paths[0].read_bytes() == prepared_bytes
    assert committed_paths[0].read_bytes() == committed_bytes

    # Even without the prepared receipt, the committed receipt alone
    # recognizes the marker (already-committed idempotency).
    prepared_paths[0].unlink()
    rerun = _migrate_legacy(fixture, expected_marker_sha256=before_sha)
    assert rerun["migration_id"] == first["migration_id"]
    assert rerun["marker_after_sha256"] == first["marker_after_sha256"]
    assert rerun["marker_before_sha256"] == before_sha
    assert Path(rerun["commit_path"]).is_file()
    assert fixture["marker_path"].read_bytes() == marker_after_retry


def test_legacy_marker_migration_refuses_foreign_strong_bound_marker(
    tmp_path: Path, monkeypatch
) -> None:
    """A strong-bound marker that matches NEITHER a prepared NOR a committed
    migration after-image is a foreign mutation: the one-time migration must
    refuse it with zero writes — the idempotent finalize path must NOT treat
    it as this migration's after-image."""
    fixture = _legacy_migration_fixture(tmp_path)
    monkeypatch.setattr(
        legacy_marker_runtime_migration,
        "verify_external_runtime_identity",
        lambda *_args: fixture["runtime"],
    )
    original_before_sha = _sha(fixture["marker_path"])
    _migrate_legacy(fixture)  # full success: prepared + committed + strong marker
    marker = json.loads(fixture["marker_path"].read_text(encoding="utf-8"))
    # Foreign mutation: same strong-bound shape but a DIFFERENT digest — no
    # prepared/committed receipt carries this after-image.
    marker["runtime_binding"]["current_identity"]["content_sha256"] = "f" * 64
    marker["editable_source_head"] = "f" * 40
    fixture["marker_path"].write_text(
        json.dumps(marker, sort_keys=True) + "\n", encoding="utf-8"
    )
    before = fixture["marker_path"].read_bytes()
    evidence_root = (
        fixture["marker_path"].parent
        / "runtime-marker-migrations"
        / fixture["session"]
    )
    evidence_before = {
        str(path): path.read_bytes()
        for path in sorted(evidence_root.rglob("*"))
        if path.is_file()
    }

    with pytest.raises(CliError, match="refusing foreign mutation"):
        _migrate_legacy(fixture, expected_marker_sha256=original_before_sha)

    assert fixture["marker_path"].read_bytes() == before
    assert {
        str(path): path.read_bytes()
        for path in sorted(evidence_root.rglob("*"))
        if path.is_file()
    } == evidence_before


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        ("marker_sha", "changed before migration"),
        ("relaunch_sha", "relaunch command hash"),
        ("runtime_root", "verified runtime identity"),
        ("session", "identity fields changed"),
        ("chain_plan", "current plan guard"),
        ("chain_pause", "durably paused chain"),
        ("chain_spec_missing", "canonical chain and launched execution bindings"),
        ("chain_spec_conflict", "canonical chain and launched execution bindings"),
        ("launch_spec_missing", "canonical chain and launched execution bindings"),
        ("launch_spec_conflict", "canonical chain and launched execution bindings"),
        ("marker_pause", "marker-side operator-pause"),
        ("should_run", "should_run=false"),
        ("chain_runtime", "chain runtime digest"),
        ("partial_binding", "already has a runtime identity"),
    ],
)
def test_legacy_marker_migration_rejects_stale_or_ambiguous_custody(
    tmp_path: Path, monkeypatch, mutation: str, error: str
) -> None:
    fixture = _legacy_migration_fixture(tmp_path)
    monkeypatch.setattr(
        legacy_marker_runtime_migration,
        "verify_external_runtime_identity",
        lambda *_args: fixture["runtime"],
    )
    overrides = {}
    if mutation == "marker_sha":
        overrides["expected_marker_sha256"] = "f" * 64
    elif mutation == "relaunch_sha":
        overrides["expected_relaunch_command_sha256"] = "f" * 64
    elif mutation == "runtime_root":
        overrides["expected_legacy_runtime_root"] = (
            "/workspace/runtime-candidates/arnold-other"
        )
    elif mutation == "session":
        overrides["expected_session"] = "another-session"
    elif mutation in {
        "chain_plan",
        "chain_pause",
        "chain_spec_missing",
        "chain_spec_conflict",
        "launch_spec_missing",
        "launch_spec_conflict",
        "chain_runtime",
    }:
        state = json.loads(fixture["chain_state_path"].read_text(encoding="utf-8"))
        if mutation == "chain_plan":
            state["current_plan_name"] = "another-plan"
        elif mutation == "chain_pause":
            state["last_state"] = "gated"
        elif mutation == "chain_spec_missing":
            state["metadata"].pop("chain_spec_path")
        elif mutation == "chain_spec_conflict":
            state["metadata"]["chain_spec_path"] = "/workspace/other/chain.yaml"
        elif mutation == "launch_spec_missing":
            state["metadata"]["execution_binding"]["launched_identity"].pop(
                "spec_path"
            )
        elif mutation == "launch_spec_conflict":
            state["metadata"]["execution_binding"]["launched_identity"][
                "spec_path"
            ] = "/workspace/other/chain.yaml"
        else:
            state["metadata"]["execution_binding"]["runtime_binding"][
                "current_identity"
            ]["content_sha256"] = "e" * 64
        fixture["chain_state_path"].write_text(json.dumps(state), encoding="utf-8")
    else:
        marker = json.loads(fixture["marker_path"].read_text(encoding="utf-8"))
        if mutation == "marker_pause":
            marker["operator_pause"] = None
        elif mutation == "should_run":
            marker["should_run"] = True
        elif mutation == "partial_binding":
            marker["runtime_binding"] = {"current_identity": fixture["runtime"]}
        fixture["marker_path"].write_text(json.dumps(marker), encoding="utf-8")

    with pytest.raises(CliError, match=error):
        _migrate_legacy(fixture, **overrides)


def test_legacy_marker_migration_rejects_external_receipt_identity_mismatch(
    tmp_path: Path, monkeypatch
) -> None:
    fixture = _legacy_migration_fixture(tmp_path)
    monkeypatch.setattr(
        legacy_marker_runtime_migration,
        "verify_external_runtime_identity",
        lambda *_args: _runtime_b(),
    )

    with pytest.raises(CliError, match="verified runtime identity"):
        _migrate_legacy(fixture)


def test_legacy_marker_migration_fsyncs_directories_in_crash_durable_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-0101h round-6: crash-durable fsync ordering.  The migration must
    fsync the prepared receipt's directory BEFORE replacing the marker,
    fsync the marker's directory IMMEDIATELY after the replacement, and
    fsync the evidence directory again after the committed receipt is
    linked — otherwise a host/power crash can leave the strong marker
    durable while both receipt directory entries vanish, deadlocking the
    retry at the refuse path (strong marker, no recoverable receipt)."""
    fixture = _legacy_migration_fixture(tmp_path)
    monkeypatch.setattr(
        legacy_marker_runtime_migration,
        "verify_external_runtime_identity",
        lambda *_args: fixture["runtime"],
    )
    spy = _FsyncOrderSpyOS()
    monkeypatch.setattr(legacy_marker_runtime_migration, "os", spy)

    _migrate_legacy(fixture)

    evidence_dir = str(
        (
            fixture["marker_path"].parent
            / "runtime-marker-migrations"
            / fixture["session"]
        ).resolve()
    )
    marker_dir = str(fixture["marker_path"].parent.resolve())
    events = spy.events

    # The prepared receipt is created (link) and its directory fsynced
    # BEFORE the marker replacement.
    first_evidence_sync = next(
        i
        for i, event in enumerate(events)
        if event[0] == "fsync" and event[1] == evidence_dir
    )
    replace_index = next(
        i for i, event in enumerate(events) if event[0] == "replace"
    )
    assert first_evidence_sync < replace_index

    # The marker directory is fsynced IMMEDIATELY after the replacement —
    # nothing may slip between them.
    assert events[replace_index + 1] == ("fsync", marker_dir)

    # The committed receipt is created AFTER the marker-dir fsync, and its
    # evidence-directory fsync directly follows the link.
    committed_link_index = next(
        i
        for i, event in enumerate(events)
        if event[0] == "link" and event[2].endswith(".committed.json")
    )
    assert committed_link_index > replace_index
    assert events[committed_link_index + 1] == ("fsync", evidence_dir)


def test_legacy_marker_migration_rebuilds_prepared_receipt_after_directory_entry_loss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-0101h round-6: filesystem-crash durability.  If a host crash loses
    the prepared receipt's directory entry after it was created but BEFORE
    the marker replacement (the marker is still identity-less), a retry with
    the original exact guards must REBUILD the prepared receipt durably
    (fresh record whose evidence-directory fsync precedes the marker
    replacement) and complete the migration — never wedge."""
    fixture = _legacy_migration_fixture(tmp_path)
    monkeypatch.setattr(
        legacy_marker_runtime_migration,
        "verify_external_runtime_identity",
        lambda *_args: fixture["runtime"],
    )
    before_sha = _sha(fixture["marker_path"])
    real_os = legacy_marker_runtime_migration.os
    monkeypatch.setattr(legacy_marker_runtime_migration, "os", _FailingReplaceOS())
    try:
        with pytest.raises(OSError, match="injected marker replace failure"):
            _migrate_legacy(fixture)
    finally:
        monkeypatch.setattr(legacy_marker_runtime_migration, "os", real_os)

    evidence_root = (
        fixture["marker_path"].parent
        / "runtime-marker-migrations"
        / fixture["session"]
    )
    prepared_paths = sorted(evidence_root.glob("*.prepared.json"))
    assert len(prepared_paths) == 1
    # The prepared receipt's directory entry is lost in the crash; the
    # marker itself was never replaced.
    prepared_paths[0].unlink()
    assert _sha(fixture["marker_path"]) == before_sha

    # Delayed retry with the ORIGINAL exact guards: rebuild the prepared
    # receipt durably and finish the migration.
    spy = _FsyncOrderSpyOS()
    monkeypatch.setattr(legacy_marker_runtime_migration, "os", spy)
    result = _migrate_legacy(fixture, expected_marker_sha256=before_sha)

    assert result["marker_before_sha256"] == before_sha
    assert result["marker_after_sha256"] == _sha(fixture["marker_path"])
    prepared_paths = sorted(evidence_root.glob("*.prepared.json"))
    committed_paths = sorted(evidence_root.glob("*.committed.json"))
    assert len(prepared_paths) == 1
    assert len(committed_paths) == 1
    rebuilt = json.loads(prepared_paths[0].read_text(encoding="utf-8"))
    assert rebuilt["marker_before_sha256"] == before_sha
    assert rebuilt["marker_after_sha256"] == result["marker_after_sha256"]
    marker = json.loads(fixture["marker_path"].read_text(encoding="utf-8"))
    assert marker_runtime_identity(marker) == fixture["runtime"]

    # The REBUILT prepared receipt is crash-durable: its evidence-directory
    # fsync precedes the marker replacement.
    events = spy.events
    evidence_dir = str(evidence_root.resolve())
    first_evidence_sync = next(
        i
        for i, event in enumerate(events)
        if event[0] == "fsync" and event[1] == evidence_dir
    )
    replace_index = next(
        i for i, event in enumerate(events) if event[0] == "replace"
    )
    assert first_evidence_sync < replace_index
