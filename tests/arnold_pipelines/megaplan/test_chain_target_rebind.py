from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Mapping

import pytest

from arnold_pipelines.megaplan.chain import spec as chain_spec
from arnold_pipelines.megaplan.chain.operator_pause import (
    AUTHORITY_SCHEMA,
    resume_chain,
)
from arnold_pipelines.megaplan.chain.target_rebind import (
    PROJECT_SOURCE_REBIND_ERROR,
    _restore_git,
    assert_chain_project_source_binding,
    assert_plan_project_source_binding,
    publish_bound_project_source_branch,
    sha256_path,
    target_rebind,
)
from arnold_pipelines.megaplan.chain.execution_binding import active_execution_identity
from arnold_pipelines.megaplan.chain.execution_binding import rebind_runtime_identity
from arnold_pipelines.megaplan.cloud.runtime_cutover import (
    marker_runtime_identity,
    normalize_runtime_identity,
    update_marker_runtime,
)
from arnold_pipelines.megaplan.cloud.runtime_manifest import (
    RuntimeManifest,
    manifest_bytes_sha256,
    write_manifest,
)
from arnold_pipelines.megaplan.chain.seed_rematerialize import (
    SEED_MANIFEST_SCHEMA,
    SEED_REMATERIALIZE_ERROR,
    seed_rematerialize,
)
from arnold_pipelines.megaplan.cli import build_parser
from arnold_pipelines.megaplan.auto import DriverOutcome
from arnold_pipelines.megaplan.runtime.execution_environment import (
    preflight_mutating_phase,
)
from arnold_pipelines.megaplan.types import CliError

PLAN_NAME = "m10-plan"
MILESTONE = "m10-safe-retry-recovery-and-effects"
M9_BRANCH = "megaplan/m9"
M10_BRANCH = "megaplan/custody/m10"
M9_REF = f"refs/heads/{M9_BRANCH}"
CONVERGENCE_REF = "refs/heads/integrate/convergence"


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", *args],
        cwd=root,
        text=True,
        stderr=subprocess.STDOUT,
    ).strip()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _fixture(tmp_path: Path) -> dict[str, Any]:
    root = tmp_path / "custody-session"
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", str(origin)], check=True, capture_output=True)
    root.mkdir()
    subprocess.run(
        ["git", "init", "--initial-branch", M9_BRANCH],
        cwd=root,
        check=True,
        capture_output=True,
    )
    _git(root, "config", "user.name", "Target Rebind Test")
    _git(root, "config", "user.email", "target-rebind@example.invalid")
    _git(root, "remote", "add", "origin", str(origin))
    (root / ".gitignore").write_text(".megaplan/\n", encoding="utf-8")
    (root / "source.txt").write_text("m9\n", encoding="utf-8")
    _git(root, "add", ".gitignore", "source.txt")
    _git(root, "commit", "-m", "m9 source")
    source_sha = _git(root, "rev-parse", "HEAD")
    _git(root, "push", "-u", "origin", M9_BRANCH)

    _git(root, "switch", "-c", "integrate/convergence")
    (root / "source.txt").write_text("m9\nconvergence\n", encoding="utf-8")
    _git(root, "add", "source.txt")
    _git(root, "commit", "-m", "convergence source")
    target_sha = _git(root, "rev-parse", "HEAD")
    _git(root, "push", "-u", "origin", "integrate/convergence")
    _git(root, "switch", M9_BRANCH)

    spec_path = root / ".megaplan" / "initiatives" / "custody" / "chain.yaml"
    spec_path.parent.mkdir(parents=True)
    spec_path.write_text(
        "\n".join(
            [
                "base_branch: main",
                "milestones:",
                f"- label: {MILESTONE}",
                "  idea: .megaplan/initiatives/custody/brief.md",
                f"  branch: {M10_BRANCH}",
                "anchors:",
                "  north_star: NORTHSTAR.md",
                "driver:",
                "  require_anchor: true",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (spec_path.parent / "brief.md").write_text("M10 brief\n", encoding="utf-8")
    (spec_path.parent / "NORTHSTAR.md").write_text("# North Star\n\nSafe custody.\n", encoding="utf-8")
    (spec_path.parent / "decisions.md").write_text(
        "\n".join(
            [
                "## Settled Decisions",
                "",
                "- **SD-001** — Keep all prior evidence in a content-addressed archive. "
                "_load_bearing: true_",
                "  rationale: Rollback and audit must remain possible.",
                "",
            ]
        ),
        encoding="utf-8",
    )

    chain = chain_spec.ChainState(
        current_milestone_index=0,
        current_plan_name=PLAN_NAME,
        last_state="paused",
        target_base_ref="launch-base-must-not-change",
        metadata={
            "operator_pause": {
                "schema_version": AUTHORITY_SCHEMA,
                "active": True,
                "paused_at": "2026-07-23T00:00:00Z",
                "actor": "test",
                "reason": "source cutover",
                "previous_chain_last_state": "blocked",
                "previous_plan_state": "blocked",
                "plan": PLAN_NAME,
            },
            "execution_environment": {
                "target_head": source_sha,
                "target_base": "base-observation",
                "target_base_ref": "main",
            },
        },
    )
    chain_spec.save_chain_state(spec_path, chain, _record_projection=False)
    state_path = chain_spec._state_path_for(spec_path)

    plan_dir = root / ".megaplan" / "plans" / PLAN_NAME
    plan_dir.mkdir(parents=True)
    plan_path = plan_dir / "state.json"
    plan = {
        "schema_version": 1,
        "name": PLAN_NAME,
        "current_state": "paused",
        "config": {
            "project_dir": str(root),
            "base_branch": M9_BRANCH,
        },
        "active_step": None,
        "iteration": 6,
        "history": [
            {"step": "init", "result": "success"},
            {"step": "prep", "result": "success"},
            {"step": "plan", "result": "success"},
            {"step": "critique", "result": "success"},
            {"step": "gate", "result": "error"},
        ],
        "latest_failure": {"kind": "deterministic_phase_failure", "phase": "gate"},
        "resume_cursor": {"phase": "gate", "retry_strategy": "repair_phase_contract"},
        "last_gate": {},
        "meta": {
            "operator_pause": {
                "schema_version": AUTHORITY_SCHEMA,
                "paused_at": "2026-07-23T00:00:00Z",
                "reason": "source cutover",
                "previous_current_state": "blocked",
                "previous_chain_last_state": "blocked",
            },
            "chain_policy": {
                "milestone_label": MILESTONE,
                "milestone_base_sha": source_sha,
            },
            "execution_environment": {
                "target_head": source_sha,
                "target_base": "base-observation",
                "target_base_ref": "main",
            },
            "gate_artifact_recovery": {"stale": True},
        },
    }
    _write_json(plan_path, plan)
    (plan_dir / "phase_result.json").write_text('{"stale": true}\n', encoding="utf-8")
    return {
        "root": root,
        "spec": spec_path,
        "state_path": state_path,
        "plan_dir": plan_dir,
        "plan_path": plan_path,
        "source": source_sha,
        "target": target_sha,
    }


def _guards(fixture: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "direction": "cutover",
        "expected_session_id": fixture["root"].name,
        "expected_current_milestone": MILESTONE,
        "expected_current_plan": PLAN_NAME,
        "from_branch": M9_BRANCH,
        "from_head": fixture["source"],
        "from_milestone_base": fixture["source"],
        "from_ref": M9_REF,
        "to_branch": M10_BRANCH,
        "to_head": fixture["target"],
        "to_ref": CONVERGENCE_REF,
        "expected_spec_sha256": sha256_path(fixture["spec"]),
        "expected_chain_state_sha256": sha256_path(fixture["state_path"]),
        "expected_plan_state_sha256": sha256_path(fixture["plan_path"]),
        "reason": "activate convergence source",
        "actor": "test",
    }
    values.update(overrides)
    return values


def _cutover(fixture: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    return target_rebind(
        fixture["spec"],
        fixture["root"],
        **_guards(fixture, **overrides),
    )


def _seed_manifest(fixture: dict[str, Any]) -> Path:
    root = fixture["root"]
    spec = fixture["spec"]
    active = active_execution_identity(spec)
    paths = [
        ("chain_spec", spec),
        ("milestone_brief", spec.parent / "brief.md"),
        ("north_star", spec.parent / "NORTHSTAR.md"),
        ("decision", spec.parent / "decisions.md"),
    ]
    chain = _load_json(fixture["state_path"])
    launched = (
        chain.get("metadata", {}).get("execution_binding", {}).get("launched_identity", {})
    )
    manifest = {
        "schema": SEED_MANIFEST_SCHEMA,
        "session_id": root.name,
        "milestone": MILESTONE,
        "plan": PLAN_NAME,
        "target": {"branch": M10_BRANCH, "head": fixture["target"]},
        "previous_bundle_sha256": str(launched.get("bundle_sha256") or ""),
        "active_bundle_sha256": active["bundle_sha256"],
        "assets": [
            {
                "kind": kind,
                "path": path.relative_to(root).as_posix(),
                "sha256": sha256_path(path),
            }
            for kind, path in paths
        ],
    }
    path = fixture["root"].parent / "m10-seed-manifest.json"
    _write_json(path, manifest)
    return path


def _rematerialize(fixture: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    manifest_path = overrides.get("seed_manifest_path") or _seed_manifest(fixture)
    values: dict[str, Any] = {
        "expected_session_id": fixture["root"].name,
        "expected_current_milestone": MILESTONE,
        "expected_current_plan": PLAN_NAME,
        "expected_branch": M10_BRANCH,
        "expected_head": fixture["target"],
        "expected_spec_sha256": sha256_path(fixture["spec"]),
        "expected_chain_state_sha256": sha256_path(fixture["state_path"]),
        "expected_plan_state_sha256": sha256_path(fixture["plan_path"]),
        "seed_manifest_path": manifest_path,
        "expected_seed_manifest_sha256": sha256_path(manifest_path),
        "reason": "adopt latest M10 inputs",
        "actor": "test",
    }
    values.update(overrides)
    return seed_rematerialize(
        fixture["spec"],
        fixture["root"],
        **values,
    )


def _target_rollback(
    fixture: dict[str, Any],
    **overrides: Any,
) -> dict[str, Any]:
    return target_rebind(
        fixture["spec"],
        fixture["root"],
        **_guards(
            fixture,
            direction="rollback",
            from_branch=M10_BRANCH,
            from_head=fixture["target"],
            from_milestone_base=fixture["target"],
            from_ref=CONVERGENCE_REF,
            to_branch=M9_BRANCH,
            to_head=fixture["source"],
            to_ref=M9_REF,
            **overrides,
        ),
    )


def _runtime_fixture(fixture: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], Path]:
    spec_text = fixture["spec"].read_text(encoding="utf-8")
    fixture["spec"].write_text(
        spec_text.replace(
            "driver:\n",
            "driver:\n  execution_binding: required\n"
            "  require_editable_runtime_match: true\n"
            "  initiative_path: .megaplan/initiatives/custody\n"
            f"  intended_initiative_revision: {'0' * 40}\n",
        ),
        encoding="utf-8",
    )
    _git(
        fixture["root"],
        "add",
        "--force",
        ".megaplan/initiatives/custody/chain.yaml",
        ".megaplan/initiatives/custody/brief.md",
        ".megaplan/initiatives/custody/NORTHSTAR.md",
        ".megaplan/initiatives/custody/decisions.md",
    )
    _git(fixture["root"], "commit", "-m", "bind custody initiative")
    initiative_revision = _git(fixture["root"], "rev-parse", "HEAD")
    fixture["spec"].write_text(
        fixture["spec"].read_text(encoding="utf-8").replace(
            "0" * 40,
            initiative_revision,
        ),
        encoding="utf-8",
    )
    _git(fixture["root"], "add", "--force", ".megaplan/initiatives/custody/chain.yaml")
    _git(fixture["root"], "commit", "-m", "pin custody initiative revision")
    fixture["source"] = _git(fixture["root"], "rev-parse", "HEAD")
    _git(fixture["root"], "push", "--force", "origin", M9_BRANCH)
    _git(fixture["root"], "switch", "integrate/convergence")
    _git(fixture["root"], "merge", "--no-edit", M9_BRANCH)
    fixture["target"] = _git(fixture["root"], "rev-parse", "HEAD")
    _git(fixture["root"], "push", "--force", "origin", "integrate/convergence")
    _git(fixture["root"], "switch", M9_BRANCH)
    plan = _load_json(fixture["plan_path"])
    plan["meta"]["chain_policy"]["milestone_base_sha"] = fixture["source"]
    plan["meta"]["execution_environment"]["target_head"] = fixture["source"]
    _write_json(fixture["plan_path"], plan)
    chain = _load_json(fixture["state_path"])
    chain["metadata"]["execution_environment"]["target_head"] = fixture["source"]
    _write_json(fixture["state_path"], chain)
    active = active_execution_identity(fixture["spec"])
    runtime_a = dict(active["runtime"])
    runtime_b = normalize_runtime_identity(
        {
            **runtime_a,
            "import_root": "/runtime/B",
            "source_revision": "b" * 40,
            "editable_root": "/runtime/B",
            "editable_revision": "b" * 40,
            "direct_url": {
                "url": "file:///runtime/B",
                "dir_info": {"editable": True},
            },
            "pth": [{"path": "/runtime/B/site/arnold.pth", "entries": ["/runtime/B"]}],
            "imports": {
                key: str(value).replace(
                    str(runtime_a.get("import_root") or ""),
                    "/runtime/B",
                )
                for key, value in (runtime_a.get("imports") or {}).items()
            },
        }
    )
    chain = _load_json(fixture["state_path"])
    chain["metadata"]["execution_binding"] = {
        "schema": "arnold.megaplan.chain_execution_binding.v1",
        "launched_identity": active,
        "runtime_binding": {
            "schema": "arnold.megaplan.chain_runtime_binding.v1",
            "current_identity": runtime_a,
            "rebind_events": [],
        },
    }
    _write_json(fixture["state_path"], chain)
    marker = fixture["root"] / ".megaplan" / "cloud-session.json"
    _write_json(
        marker,
        {
            "runtime_binding": {
                "schema": "arnold.megaplan.marker_runtime_binding.v1",
                "current_identity": runtime_a,
                "rebind_events": [],
            }
        },
    )
    return runtime_a, runtime_b, marker


def _runtime_rebind(
    fixture: dict[str, Any],
    *,
    source: Mapping[str, Any],
    target: Mapping[str, Any],
    direction: str,
) -> dict[str, Any]:
    state = chain_spec.load_chain_state(
        fixture["spec"],
        verify_execution_binding=False,
    )
    result = rebind_runtime_identity(
        fixture["spec"],
        state,
        expected_previous_runtime_sha256=str(source["content_sha256"]),
        expected_active_runtime_sha256=str(target["content_sha256"]),
        expected_current_milestone=MILESTONE,
        expected_current_plan=PLAN_NAME,
        reason=f"{direction} integrated runtime",
        actor="test",
        direction=direction,
        verified_external_runtime_identity=target,
    )
    _write_json(fixture["state_path"], state.to_dict())
    return result


def _marker_rebind(
    marker: Path,
    *,
    source: Mapping[str, Any],
    target: Mapping[str, Any],
    direction: str,
    manifest_path: Path,
) -> dict[str, Any]:
    return update_marker_runtime(
        marker,
        expected_marker_sha256=sha256_path(marker),
        expected_previous_runtime_sha256=str(source["content_sha256"]),
        active_runtime_identity=target,
        relaunch_command=(
            f"{target['import_root']} {target['source_revision']} "
            "control interpreter resumes only after final seed"
        ),
        reason=f"{direction} integrated marker",
        actor="test",
        direction=direction,
        manifest_path=manifest_path,
    )


def _runtime_manifest(fixture: dict[str, Any]) -> Path:
    """Create the authoritative, schema-valid manifest for marker cutovers."""

    runtime_root = fixture["root"] / ".runtime"
    revision = fixture["source"]
    payload = {
        "runtime_id": "target-rebind-runtime",
        "schema": "1",
        "generation": 1,
        "epic_id": "target-rebind-epic",
        "state": "active",
        "owner": "test",
        "base": {
            "ref": M9_REF,
            "commit": revision,
            "editable_install_path": str(runtime_root / "base"),
            "venv_path": str(runtime_root / "base" / "venv"),
        },
        "epic": {
            "branch": M9_BRANCH,
            "worktree_path": str(runtime_root),
            "venv_path": str(runtime_root / "venv"),
            "runtime_root": str(runtime_root),
            "expected_head": revision,
            "repair_bin": str(runtime_root / "venv" / "bin" / "arnold-babysitter"),
            "deps_lockfile": str(runtime_root / "uv.lock"),
        },
        "indirection": {
            "host_path": str(runtime_root),
            "container_path": str(runtime_root),
            "mount_table": [],
            "execution_namespace": "target-rebind",
            "verified_head": revision,
            "last_verified_at": "2026-09-06T00:00:00Z",
            "attestation": {
                "module_file": str(runtime_root / "arnold_pipelines" / "__init__.py"),
                "module_digest": "0" * 64,
                "mount_id": "0:0",
            },
        },
        "policy": {
            "policy_sha": "0" * 64,
            "model_policy_sha": "0" * 64,
            "sync_policy": "disabled",
        },
        "promotions": [],
        "timestamps": {
            "created": "2026-09-06T00:00:00Z",
            "updated": "2026-09-06T00:00:00Z",
            "closed": "",
        },
        "gc_policy": "closed-only",
        "commands": [],
    }
    path = fixture["root"].parent / "target-rebind-runtime-manifest.json"
    write_manifest(RuntimeManifest.from_dict(payload), path)
    return path


def _assert_marker_manifest(marker: Path, manifest_path: Path) -> None:
    payload = _load_json(marker)
    expected = manifest_bytes_sha256(manifest_path)
    assert payload["manifest_identity"] == expected
    assert payload["manifest_sha256"] == expected


def _seed_rollback(
    fixture: dict[str, Any],
    cutover: dict[str, Any],
    manifest_path: Path,
    **overrides: Any,
) -> dict[str, Any]:
    values: dict[str, Any] = {
        "expected_session_id": fixture["root"].name,
        "expected_current_milestone": MILESTONE,
        "expected_current_plan": PLAN_NAME,
        "expected_branch": M9_BRANCH,
        "expected_head": fixture["source"],
        "expected_spec_sha256": sha256_path(fixture["spec"]),
        "expected_chain_state_sha256": sha256_path(fixture["state_path"]),
        "expected_plan_state_sha256": sha256_path(fixture["plan_path"]),
        "seed_manifest_path": manifest_path,
        "expected_seed_manifest_sha256": sha256_path(manifest_path),
        "direction": "rollback",
        "expected_cutover_event_sha256": cutover["event"]["content_sha256"],
        "expected_archive_manifest_sha256": cutover["event"][
            "archive_manifest_sha256"
        ],
        "reason": "restore predecessor M10 seed",
        "actor": "test",
    }
    values.update(overrides)
    return seed_rematerialize(fixture["spec"], fixture["root"], **values)


def test_cutover_switches_configured_branch_and_rebinds_both_states(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)

    result = _cutover(fixture)

    assert result["branch"] == M10_BRANCH
    assert _git(fixture["root"], "branch", "--show-current") == M10_BRANCH
    assert _git(fixture["root"], "rev-parse", "HEAD") == fixture["target"]
    assert _git(fixture["root"], "rev-parse", M9_BRANCH) == fixture["source"]
    plan = _load_json(fixture["plan_path"])
    chain = _load_json(fixture["state_path"])
    binding = plan["meta"]["project_source_binding"]
    assert chain["metadata"]["project_source_binding"] == binding
    assert binding["current"]["head"] == fixture["target"]
    assert binding["original"]["head"] == fixture["source"]
    assert binding["rebind_events"][0]["direction"] == "cutover"
    assert plan["meta"]["chain_policy"]["milestone_base_sha"] == fixture["target"]
    assert plan["meta"]["execution_environment"]["target_head"] == fixture["target"]
    assert chain["metadata"]["execution_environment"]["target_head"] == fixture["target"]
    assert chain["target_base_ref"] == "launch-base-must-not-change"
    assert plan["current_state"] == "paused"
    assert plan["meta"]["operator_pause"]["previous_current_state"] == "planned"
    assert chain["metadata"]["operator_pause"]["previous_plan_state"] == "planned"
    assert chain["metadata"]["operator_pause"]["previous_chain_last_state"] == "planned"
    assert plan["resume_cursor"] == {
        "phase": "critique",
        "retry_strategy": "fresh_critique_after_project_source_rebind",
        "project_source_rebind_sha256": binding["rebind_events"][0][
            "content_sha256"
        ],
    }
    assert "latest_failure" not in plan
    assert "gate_artifact_recovery" not in plan["meta"]
    assert not (fixture["plan_dir"] / "phase_result.json").exists()
    invalidated = binding["rebind_events"][0]["invalidated_artifacts"]
    assert invalidated[0]["artifact"] == "phase_result.json"
    assert (fixture["plan_dir"].parent / invalidated[0]["archive_path"]).exists()

    state = chain_spec.load_chain_state(fixture["spec"], verify_execution_binding=False)
    assert_chain_project_source_binding(
        fixture["root"],
        state,
        plan_name=PLAN_NAME,
        operation="test completion",
    )


@pytest.mark.parametrize(
    "stage",
    ["after_git_switch", "after_plan_write", "after_chain_write"],
)
def test_failure_injection_restores_git_and_both_state_files(
    tmp_path: Path,
    stage: str,
) -> None:
    fixture = _fixture(tmp_path)
    original_plan = fixture["plan_path"].read_bytes()
    original_chain = fixture["state_path"].read_bytes()

    def fail(current: str) -> None:
        if current == stage:
            raise RuntimeError(f"injected at {stage}")

    with pytest.raises(RuntimeError, match="injected"):
        _cutover(fixture, failure_injector=fail)

    assert fixture["plan_path"].read_bytes() == original_plan
    assert fixture["state_path"].read_bytes() == original_chain
    assert _git(fixture["root"], "branch", "--show-current") == M9_BRANCH
    assert _git(fixture["root"], "rev-parse", "HEAD") == fixture["source"]
    assert (
        subprocess.run(
            ["git", "show-ref", "--verify", "--quiet", f"refs/heads/{M10_BRANCH}"],
            cwd=fixture["root"],
            check=False,
        ).returncode
        == 1
    )
    assert (fixture["plan_dir"] / "phase_result.json").exists()


def _restore_git_fixture(tmp_path: Path) -> dict[str, Any]:
    root = tmp_path / "restore-repo"
    origin = tmp_path / "origin-restore.git"
    subprocess.run(["git", "init", "--bare", str(origin)], check=True, capture_output=True)
    root.mkdir()
    subprocess.run(
        ["git", "init", "--initial-branch", M9_BRANCH],
        cwd=root,
        check=True,
        capture_output=True,
    )
    _git(root, "config", "user.name", "Restore Test")
    _git(root, "config", "user.email", "restore@example.invalid")
    _git(root, "remote", "add", "origin", str(origin))
    (root / "source.txt").write_text("m9\n", encoding="utf-8")
    _git(root, "add", "source.txt")
    _git(root, "commit", "-m", "m9 source")
    source_sha = _git(root, "rev-parse", "HEAD")
    _git(root, "branch", "stray-rollback-branch")
    return {"root": root, "source": source_sha}


def _sandbox_census_stores(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Point the reference census at sandboxed (initially absent) stores."""
    monkeypatch.setenv("ARNOLD_BASE_DIR", "")
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST_DIR", str(tmp_path / "ref-manifests"))
    monkeypatch.setenv("ARNOLD_REFERENCE_CHAIN_STORE", str(tmp_path / "ref-chains"))
    monkeypatch.setenv("ARNOLD_REFERENCE_MARKER_STORE", str(tmp_path / "ref-markers"))
    monkeypatch.setenv(
        "ARNOLD_REFERENCE_SCHEDULE_STORES", str(tmp_path / "ref-schedules")
    )
    monkeypatch.setenv(
        "ARNOLD_REFERENCE_REPAIR_QUEUE", str(tmp_path / "ref-repair-queue")
    )
    monkeypatch.setenv("ARNOLD_REFERENCE_LEASE_STORE", str(tmp_path / "ref-leases"))


def test_restore_git_refuses_created_branch_delete_on_referenced_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rollback must never delete the branch it created while a runtime store
    still references the project root (census REFERENCED hard-skip: the
    rollback branch delete is refused and the branch survives)."""
    fixture = _restore_git_fixture(tmp_path)
    _sandbox_census_stores(monkeypatch, tmp_path)
    store = tmp_path / "ref-chains"
    store.mkdir(parents=True)
    (store / "chain-ref.json").write_text(
        json.dumps(
            {
                "metadata": {
                    "execution_environment": {"engine_root": str(fixture["root"])}
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(CliError, match="reference census REFERENCED"):
        _restore_git(
            fixture["root"],
            branch=M9_BRANCH,
            head=fixture["source"],
            created_branch="stray-rollback-branch",
        )
    assert _git(fixture["root"], "rev-parse", "stray-rollback-branch")


def test_restore_git_blocks_created_branch_delete_on_unknown_census(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A corrupt reference store makes the census UNKNOWN and BLOCKS the
    rollback branch delete (fail-closed: delete-on-unknown never happens)."""
    fixture = _restore_git_fixture(tmp_path)
    _sandbox_census_stores(monkeypatch, tmp_path)
    store = tmp_path / "ref-chains"
    store.mkdir(parents=True)
    (store / "corrupt.json").write_text(
        '{"metadata": {"execution_environment": ', encoding="utf-8"
    )

    with pytest.raises(CliError, match="reference census UNKNOWN"):
        _restore_git(
            fixture["root"],
            branch=M9_BRANCH,
            head=fixture["source"],
            created_branch="stray-rollback-branch",
        )
    assert _git(fixture["root"], "rev-parse", "stray-rollback-branch")


def test_restore_git_deletes_created_branch_on_clear_census(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A CLEAR reference census keeps the route authority: the rollback
    deletes the created branch exactly as before."""
    fixture = _restore_git_fixture(tmp_path)
    _sandbox_census_stores(monkeypatch, tmp_path)

    _restore_git(
        fixture["root"],
        branch=M9_BRANCH,
        head=fixture["source"],
        created_branch="stray-rollback-branch",
    )
    assert (
        subprocess.run(
            ["git", "show-ref", "--verify", "--quiet", "refs/heads/stray-rollback-branch"],
            cwd=fixture["root"],
            check=False,
        ).returncode
        == 1
    )


def test_rollback_is_exact_inverse_before_execute(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _cutover(fixture)

    result = target_rebind(
        fixture["spec"],
        fixture["root"],
        **_guards(
            fixture,
            direction="rollback",
            from_branch=M10_BRANCH,
            from_head=fixture["target"],
            from_milestone_base=fixture["target"],
            from_ref=CONVERGENCE_REF,
            to_branch=M9_BRANCH,
            to_head=fixture["source"],
            to_ref=M9_REF,
        ),
    )

    assert result["direction"] == "rollback"
    assert _git(fixture["root"], "branch", "--show-current") == M9_BRANCH
    assert _git(fixture["root"], "rev-parse", "HEAD") == fixture["source"]
    plan = _load_json(fixture["plan_path"])
    binding = plan["meta"]["project_source_binding"]
    assert binding["current"]["branch"] == M9_BRANCH
    assert binding["current"]["head"] == fixture["source"]
    assert [event["direction"] for event in binding["rebind_events"]] == [
        "cutover",
        "rollback",
    ]
    assert plan["meta"]["chain_policy"]["milestone_base_sha"] == fixture["source"]


def test_cutover_can_repeat_after_exact_pre_execute_rollback(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _cutover(fixture)
    target_rebind(
        fixture["spec"],
        fixture["root"],
        **_guards(
            fixture,
            direction="rollback",
            from_branch=M10_BRANCH,
            from_head=fixture["target"],
            from_milestone_base=fixture["target"],
            from_ref=CONVERGENCE_REF,
            to_branch=M9_BRANCH,
            to_head=fixture["source"],
            to_ref=M9_REF,
        ),
    )

    result = _cutover(fixture)

    assert result["branch"] == M10_BRANCH
    binding = _load_json(fixture["plan_path"])["meta"]["project_source_binding"]
    assert [event["direction"] for event in binding["rebind_events"]] == [
        "cutover",
        "rollback",
        "cutover",
    ]


def test_rollback_refuses_after_execute_history(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _cutover(fixture)
    plan = _load_json(fixture["plan_path"])
    plan["history"].append({"step": "execute", "result": "success"})
    _write_json(fixture["plan_path"], plan)

    with pytest.raises(CliError, match="already has execute history"):
        target_rebind(
            fixture["spec"],
            fixture["root"],
            **_guards(
                fixture,
                direction="rollback",
                from_branch=M10_BRANCH,
                from_head=fixture["target"],
                from_milestone_base=fixture["target"],
                from_ref=CONVERGENCE_REF,
                to_branch=M9_BRANCH,
                to_head=fixture["source"],
                to_ref=M9_REF,
            ),
        )


def test_cutover_refuses_stale_state_cas(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    with pytest.raises(CliError, match="chain-state SHA-256 changed"):
        _cutover(fixture, expected_chain_state_sha256="0" * 64)


def test_cutover_refuses_dirty_worktree(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    (fixture["root"] / "untracked.txt").write_text("dirty\n", encoding="utf-8")

    with pytest.raises(CliError, match="worktree is dirty"):
        _cutover(fixture)


def test_cutover_refuses_missing_pause_authority(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    chain = _load_json(fixture["state_path"])
    chain["metadata"].pop("operator_pause")
    _write_json(fixture["state_path"], chain)

    with pytest.raises(CliError, match="requires matching durable"):
        _cutover(fixture)


@pytest.mark.parametrize(
    ("artifact", "active_step", "message"),
    [
        ("execution.json", None, "already has execution/finalize/review artifacts"),
        (None, {"phase": "gate", "run_id": "live"}, "plan has an active step"),
    ],
)
def test_cutover_refuses_active_or_executed_plan(
    tmp_path: Path,
    artifact: str | None,
    active_step: dict[str, str] | None,
    message: str,
) -> None:
    fixture = _fixture(tmp_path)
    if artifact is not None:
        (fixture["plan_dir"] / artifact).write_text("{}\n", encoding="utf-8")
    if active_step is not None:
        plan = _load_json(fixture["plan_path"])
        plan["active_step"] = active_step
        _write_json(fixture["plan_path"], plan)

    with pytest.raises(CliError, match=message):
        _cutover(fixture)


def test_cutover_refuses_target_sha_not_advertised_by_exact_ref(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)

    with pytest.raises(CliError, match="advertised target"):
        _cutover(fixture, to_head=fixture["source"])


def test_cutover_refuses_non_fast_forward_target(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    root = fixture["root"]
    tree = _git(root, "rev-parse", f"{fixture['target']}^{{tree}}")
    unrelated = subprocess.check_output(
        ["git", "commit-tree", tree],
        cwd=root,
        input="unrelated target\n",
        text=True,
    ).strip()
    _git(root, "push", "origin", f"{unrelated}:{CONVERGENCE_REF}", "--force")

    with pytest.raises(CliError, match="strict fast-forward"):
        _cutover(fixture, to_head=unrelated)


def test_cutover_accepts_exact_changed_target_chain_spec(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    root = fixture["root"]
    seed_paths = [
        fixture["spec"],
        fixture["spec"].parent / "brief.md",
        fixture["spec"].parent / "NORTHSTAR.md",
        fixture["spec"].parent / "decisions.md",
    ]
    old_bytes = {path: path.read_bytes() for path in seed_paths}
    old_spec_sha = sha256_path(fixture["spec"])
    _git(root, "switch", "integrate/convergence")
    fixture["spec"].write_text(
        fixture["spec"].read_text(encoding="utf-8") + "# C01-C20 amendment\n",
        encoding="utf-8",
    )
    _git(root, "add", "--force", *(str(path.relative_to(root)) for path in seed_paths))
    _git(root, "commit", "-m", "amend M10 load-bearing inputs")
    amended_target = _git(root, "rev-parse", "HEAD")
    amended_spec_sha = sha256_path(fixture["spec"])
    _git(root, "push", "origin", f"HEAD:{CONVERGENCE_REF}")
    _git(root, "switch", M9_BRANCH)
    for path, payload in old_bytes.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    fixture["target"] = amended_target

    result = _cutover(
        fixture,
        expected_spec_sha256=old_spec_sha,
        expected_target_spec_sha256=amended_spec_sha,
    )

    assert result["head"] == amended_target
    assert sha256_path(fixture["spec"]) == amended_spec_sha
    assert result["event"]["target_spec_sha256"] == amended_spec_sha
    rematerialized = _rematerialize(fixture)
    assert rematerialized["next_state_after_resume"] == "initialized"
    seed_event = _load_json(fixture["plan_path"])["meta"]["seed_source_binding"][
        "events"
    ][-1]
    chain_asset = next(
        item for item in seed_event["verified_assets"] if item["kind"] == "chain_spec"
    )
    assert chain_asset["sha256"] == amended_spec_sha


def test_bound_source_guard_allows_descendants_but_rejects_wrong_branch(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    _cutover(fixture)
    (fixture["root"] / "m10.txt").write_text("m10 work\n", encoding="utf-8")
    _git(fixture["root"], "add", "m10.txt")
    _git(fixture["root"], "commit", "-m", "m10 work")
    plan = _load_json(fixture["plan_path"])
    assert_plan_project_source_binding(
        fixture["root"],
        plan,
        operation="execute preflight",
    )

    _git(fixture["root"], "switch", M9_BRANCH)
    with pytest.raises(CliError, match="does not preserve the bound project source"):
        assert_plan_project_source_binding(
            fixture["root"],
            plan,
            operation="execute preflight",
        )


def test_bound_source_guard_rejects_same_branch_without_bound_ancestor(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    _cutover(fixture)
    root = fixture["root"]
    tree = _git(root, "rev-parse", f"{fixture['source']}^{{tree}}")
    unrelated = subprocess.check_output(
        ["git", "commit-tree", tree],
        cwd=root,
        input="unrelated m10 rewrite\n",
        text=True,
    ).strip()
    _git(root, "reset", "--hard", unrelated)
    plan = _load_json(fixture["plan_path"])

    with pytest.raises(CliError, match="does not preserve the bound project source"):
        assert_plan_project_source_binding(
            root,
            plan,
            operation="milestone completion",
        )


def test_mutating_phase_preflight_enforces_bound_source(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _cutover(fixture)
    plan = _load_json(fixture["plan_path"])

    env = preflight_mutating_phase(
        root=fixture["root"],
        state=plan,
        phase="execute",
        engine_root=fixture["root"],
    )
    assert env.target_head == fixture["target"]

    _git(fixture["root"], "switch", M9_BRANCH)
    with pytest.raises(CliError, match="does not preserve the bound project source"):
        preflight_mutating_phase(
            root=fixture["root"],
            state=plan,
            phase="execute",
            engine_root=fixture["root"],
        )


def test_bound_publication_creates_remote_from_current_branch_not_chain_base(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    _cutover(fixture)
    (fixture["root"] / "m10.txt").write_text("completed M10 work\n", encoding="utf-8")
    _git(fixture["root"], "add", "m10.txt")
    _git(fixture["root"], "commit", "-m", "complete M10")
    final_head = _git(fixture["root"], "rev-parse", "HEAD")
    state = chain_spec.load_chain_state(
        fixture["spec"],
        verify_execution_binding=False,
    )

    published = publish_bound_project_source_branch(
        fixture["root"],
        state,
        plan_name=PLAN_NAME,
        milestone_branch=M10_BRANCH,
    )

    assert published == final_head
    assert (
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", fixture["target"], published],
            cwd=fixture["root"],
            check=False,
        ).returncode
        == 0
    )
    assert _git(
        fixture["root"],
        "ls-remote",
        "--heads",
        "origin",
        f"refs/heads/{M10_BRANCH}",
    ).split()[0] == final_head


def test_bound_publication_refuses_remote_branch_that_drops_bound_source(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    _git(
        fixture["root"],
        "push",
        "origin",
        f"{fixture['source']}:refs/heads/{M10_BRANCH}",
    )
    _cutover(fixture)
    state = chain_spec.load_chain_state(
        fixture["spec"],
        verify_execution_binding=False,
    )

    with pytest.raises(CliError, match="drops bound source"):
        publish_bound_project_source_branch(
            fixture["root"],
            state,
            plan_name=PLAN_NAME,
            milestone_branch=M10_BRANCH,
        )
    assert _git(
        fixture["root"],
        "ls-remote",
        "--heads",
        "origin",
        f"refs/heads/{M10_BRANCH}",
    ).split()[0] == fixture["source"]


def test_no_push_resume_keeps_exact_bound_branch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    _cutover(fixture)
    resume_chain(
        fixture["spec"],
        fixture["root"],
        actor="test",
        verify_execution_binding=False,
    )
    observed: dict[str, str] = {}

    def fake_drive(
        root: Path,
        _spec_path: Path,
        plan: str,
        _spec: Any,
        *,
        on_phase_complete: Any,
        writer: Any,
    ) -> DriverOutcome:
        del on_phase_complete, writer
        observed["branch"] = _git(root, "branch", "--show-current")
        observed["head"] = _git(root, "rev-parse", "HEAD")
        return DriverOutcome(
            status="blocked",
            plan=plan,
            final_state="blocked",
            iterations=1,
            reason="test stop",
        )

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.chain._drive_plan_with_blocked_execute_recovery",
        fake_drive,
    )
    from arnold_pipelines.megaplan.chain import run_chain

    result = run_chain(
        fixture["spec"],
        fixture["root"],
        no_push=True,
        no_git_refresh=True,
        one=True,
        writer=lambda _message: None,
    )

    assert observed == {"branch": M10_BRANCH, "head": fixture["target"]}
    assert result["status"] == "stopped"


def test_target_rebind_cli_exposes_all_cas_guards() -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            "chain",
            "target-rebind",
            "--spec",
            "chain.yaml",
            "--project-dir",
            "/workspace/session",
            "--expected-session-id",
            "session",
            "--expected-current-milestone",
            MILESTONE,
            "--expected-current-plan",
            PLAN_NAME,
            "--from-branch",
            M9_BRANCH,
            "--from-head",
            "a" * 40,
            "--from-milestone-base",
            "a" * 40,
            "--from-ref",
            M9_REF,
            "--to-branch",
            M10_BRANCH,
            "--to-head",
            "b" * 40,
            "--to-ref",
            CONVERGENCE_REF,
            "--expected-spec-sha256",
            "1" * 64,
            "--expected-chain-state-sha256",
            "2" * 64,
            "--expected-plan-state-sha256",
            "3" * 64,
            "--reason",
            "cut over",
        ]
    )

    assert args.chain_action == "target-rebind"
    assert args.from_milestone_base == "a" * 40
    assert args.expected_plan_state_sha256 == "3" * 64
    assert PROJECT_SOURCE_REBIND_ERROR == "project_source_rebind_refused"


def test_seed_rematerialize_archives_old_epoch_and_replans_same_milestone(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    _cutover(fixture)
    old_plan = _load_json(fixture["plan_path"])
    old_plan["history"].append({"step": "finalize", "result": "success"})
    _write_json(fixture["plan_path"], old_plan)
    (fixture["plan_dir"] / "finalize.json").write_text(
        '{"stale": true}\n',
        encoding="utf-8",
    )

    result = _rematerialize(fixture)

    plan = _load_json(fixture["plan_path"])
    chain = _load_json(fixture["state_path"])
    assert plan["current_state"] == "paused"
    assert plan["iteration"] == 0
    assert plan["plan_versions"] == []
    assert [entry["step"] for entry in plan["history"]] == ["init"]
    assert plan["idea"] == "M10 brief"
    assert plan["meta"]["operator_pause"]["previous_current_state"] == "initialized"
    assert chain["metadata"]["operator_pause"]["previous_plan_state"] == "initialized"
    assert chain["current_milestone_index"] == 0
    assert chain["current_plan_name"] == PLAN_NAME
    assert plan["meta"]["seed_source_binding"] == chain["metadata"]["seed_source_binding"]
    assert plan["meta"]["seed_source_binding"]["current_manifest_sha256"]
    assert plan["meta"]["canonical_source_binding"]["bound"]["file_sha256"] == sha256_path(
        fixture["spec"].parent / "brief.md"
    )
    assert (fixture["plan_dir"] / "anchors" / "north_star" / "epic.md").is_file()
    assert plan["meta"]["imported_decisions"]
    archive = fixture["plan_dir"].parent / result["archive_path"]
    archived_state = _load_json(archive / "state.json")
    assert archived_state["iteration"] == 6
    assert archived_state["history"][-1]["step"] == "finalize"
    assert (archive / "finalize.json").is_file()
    assert not (fixture["plan_dir"] / "finalize.json").exists()
    assert result["next_state_after_resume"] == "initialized"
    resume_chain(
        fixture["spec"],
        fixture["root"],
        actor="test",
        verify_execution_binding=False,
    )
    assert _load_json(fixture["plan_path"])["current_state"] == "initialized"
    assert _load_json(fixture["state_path"])["last_state"] == "initialized"


@pytest.mark.parametrize(
    "stage",
    ["after_archive", "after_plan_write", "after_chain_write"],
)
def test_seed_rematerialize_failure_compensates_exact_plan_and_chain(
    tmp_path: Path,
    stage: str,
) -> None:
    fixture = _fixture(tmp_path)
    _cutover(fixture)
    (fixture["plan_dir"] / "finalize.json").write_text(
        '{"stale": true}\n',
        encoding="utf-8",
    )
    original_plan = fixture["plan_path"].read_bytes()
    original_chain = fixture["state_path"].read_bytes()

    def fail(current: str) -> None:
        if current == stage:
            raise RuntimeError(f"injected at {stage}")

    with pytest.raises(RuntimeError, match="injected"):
        _rematerialize(fixture, failure_injector=fail)

    assert fixture["plan_path"].read_bytes() == original_plan
    assert fixture["state_path"].read_bytes() == original_chain
    assert (fixture["plan_dir"] / "finalize.json").read_text(encoding="utf-8") == (
        '{"stale": true}\n'
    )
    archive_root = fixture["plan_dir"].parent / ".seed-rematerialize-archive"
    assert not archive_root.exists() or not any(archive_root.rglob("state.json"))


def test_seed_rematerialize_refuses_stale_load_bearing_asset(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _cutover(fixture)
    manifest_path = _seed_manifest(fixture)
    (fixture["spec"].parent / "decisions.md").write_text(
        "changed without manifest adoption\n",
        encoding="utf-8",
    )

    with pytest.raises(CliError, match="seed manifest asset changed"):
        _rematerialize(
            fixture,
            seed_manifest_path=manifest_path,
            expected_seed_manifest_sha256=sha256_path(manifest_path),
        )


def test_seed_rematerialize_refuses_after_execute(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _cutover(fixture)
    plan = _load_json(fixture["plan_path"])
    plan["history"].append({"step": "execute", "result": "success"})
    _write_json(fixture["plan_path"], plan)

    with pytest.raises(CliError, match="forbidden after execute history"):
        _rematerialize(fixture)


def test_seed_cutover_rollback_recutover_restores_predecessor_epoch(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    _cutover(fixture)
    predecessor = _load_json(fixture["plan_path"])
    (fixture["plan_dir"] / "plan_v7.md").write_text(
        "# Superseded plan\n",
        encoding="utf-8",
    )
    manifest_path = _seed_manifest(fixture)
    seed_cutover = _rematerialize(
        fixture,
        seed_manifest_path=manifest_path,
        expected_seed_manifest_sha256=sha256_path(manifest_path),
    )
    _target_rollback(fixture)

    rolled_back = _seed_rollback(fixture, seed_cutover, manifest_path)

    restored = _load_json(fixture["plan_path"])
    assert rolled_back["direction"] == "rollback"
    assert restored["iteration"] == predecessor["iteration"]
    assert restored["history"] == predecessor["history"]
    assert (fixture["plan_dir"] / "plan_v7.md").read_text(encoding="utf-8") == (
        "# Superseded plan\n"
    )
    events = restored["meta"]["seed_source_binding"]["events"]
    assert [event["direction"] for event in events] == ["cutover", "rollback"]

    _cutover(fixture)
    second_manifest = _seed_manifest(fixture)
    second_cutover = _rematerialize(
        fixture,
        seed_manifest_path=second_manifest,
        expected_seed_manifest_sha256=sha256_path(second_manifest),
    )
    events = _load_json(fixture["plan_path"])["meta"]["seed_source_binding"]["events"]
    assert [event["direction"] for event in events] == [
        "cutover",
        "rollback",
        "cutover",
    ]
    assert second_cutover["event"]["content_sha256"] != seed_cutover["event"][
        "content_sha256"
    ]


def test_full_runtime_marker_target_seed_a_b_a_b_keeps_all_receipts(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    runtime_a, runtime_b, marker = _runtime_fixture(fixture)
    runtime_manifest_path = _runtime_manifest(fixture)

    # Bootstrap order is load-bearing: the external runtime and marker move
    # before target/seeds, and the still-new B interpreter supplies the
    # independently verified identity while the project is later back on A.
    _runtime_rebind(
        fixture,
        source=runtime_a,
        target=runtime_b,
        direction="cutover",
    )
    _marker_rebind(
        marker,
        source=runtime_a,
        target=runtime_b,
        direction="cutover",
        manifest_path=runtime_manifest_path,
    )
    _assert_marker_manifest(marker, runtime_manifest_path)
    _cutover(fixture, verified_external_runtime_identity=runtime_b)
    manifest_path = _seed_manifest(fixture)
    first_seed = _rematerialize(
        fixture,
        seed_manifest_path=manifest_path,
        expected_seed_manifest_sha256=sha256_path(manifest_path),
        verified_external_runtime_identity=runtime_b,
    )
    chain = _load_json(fixture["state_path"])
    assert (
        chain["metadata"]["execution_binding"]["runtime_binding"]["current_identity"]
        == marker_runtime_identity(_load_json(marker))
        == runtime_b
    )

    _runtime_rebind(
        fixture,
        source=runtime_b,
        target=runtime_a,
        direction="rollback",
    )
    _marker_rebind(
        marker,
        source=runtime_b,
        target=runtime_a,
        direction="rollback",
        manifest_path=runtime_manifest_path,
    )
    _assert_marker_manifest(marker, runtime_manifest_path)
    _target_rollback(
        fixture,
        verified_external_runtime_identity=runtime_a,
    )
    _seed_rollback(fixture, first_seed, manifest_path)

    assert _git(fixture["root"], "branch", "--show-current") == M9_BRANCH
    assert _git(fixture["root"], "rev-parse", "HEAD") == fixture["source"]
    chain = _load_json(fixture["state_path"])
    runtime_binding = chain["metadata"]["execution_binding"]["runtime_binding"]
    assert runtime_binding["current_identity"] == runtime_a
    assert [event["direction"] for event in runtime_binding["rebind_events"]] == [
        "cutover",
        "rollback",
    ]
    assert marker_runtime_identity(_load_json(marker)) == runtime_a

    _runtime_rebind(
        fixture,
        source=runtime_a,
        target=runtime_b,
        direction="cutover",
    )
    _marker_rebind(
        marker,
        source=runtime_a,
        target=runtime_b,
        direction="cutover",
        manifest_path=runtime_manifest_path,
    )
    _assert_marker_manifest(marker, runtime_manifest_path)
    _cutover(fixture, verified_external_runtime_identity=runtime_b)
    second_manifest = _seed_manifest(fixture)
    _rematerialize(
        fixture,
        seed_manifest_path=second_manifest,
        expected_seed_manifest_sha256=sha256_path(second_manifest),
        verified_external_runtime_identity=runtime_b,
    )

    assert _git(fixture["root"], "branch", "--show-current") == M10_BRANCH
    assert _git(fixture["root"], "rev-parse", "HEAD") == fixture["target"]
    plan = _load_json(fixture["plan_path"])
    chain = _load_json(fixture["state_path"])
    assert [event["direction"] for event in plan["meta"]["project_source_binding"]["rebind_events"]] == [
        "cutover",
        "rollback",
        "cutover",
    ]
    assert [event["direction"] for event in plan["meta"]["seed_source_binding"]["events"]] == [
        "cutover",
        "rollback",
        "cutover",
    ]
    assert [
        event["direction"]
        for event in chain["metadata"]["execution_binding"]["runtime_binding"][
            "rebind_events"
        ]
    ] == ["cutover", "rollback", "cutover"]
    assert [
        event["direction"]
        for event in _load_json(marker)["runtime_binding"]["rebind_events"]
    ] == ["cutover", "rollback", "cutover"]
    assert (
        chain["metadata"]["execution_binding"]["runtime_binding"]["current_identity"]
        == marker_runtime_identity(_load_json(marker))
        == runtime_b
    )
    _assert_marker_manifest(marker, runtime_manifest_path)


def test_target_rollback_can_escape_pre_seed_binding_drift(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    runtime_a, runtime_b, _marker = _runtime_fixture(fixture)
    _runtime_rebind(
        fixture,
        source=runtime_a,
        target=runtime_b,
        direction="cutover",
    )
    _cutover(fixture, verified_external_runtime_identity=runtime_b)

    result = _target_rollback(
        fixture,
        verified_external_runtime_identity=runtime_b,
    )

    assert result["direction"] == "rollback"
    assert _git(fixture["root"], "branch", "--show-current") == M9_BRANCH
    assert _git(fixture["root"], "rev-parse", "HEAD") == fixture["source"]


def test_seed_rollback_refuses_stale_cutover_guard(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _cutover(fixture)
    manifest_path = _seed_manifest(fixture)
    seed_cutover = _rematerialize(
        fixture,
        seed_manifest_path=manifest_path,
        expected_seed_manifest_sha256=sha256_path(manifest_path),
    )
    _target_rollback(fixture)

    with pytest.raises(CliError, match="active seed cutover"):
        _seed_rollback(
            fixture,
            seed_cutover,
            manifest_path,
            expected_cutover_event_sha256="0" * 64,
        )


def test_seed_rollback_refuses_forged_archive(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _cutover(fixture)
    manifest_path = _seed_manifest(fixture)
    seed_cutover = _rematerialize(
        fixture,
        seed_manifest_path=manifest_path,
        expected_seed_manifest_sha256=sha256_path(manifest_path),
    )
    _target_rollback(fixture)
    archive = fixture["plan_dir"].parent / seed_cutover["archive_path"]
    (archive / "state.json").write_text('{"forged": true}\n', encoding="utf-8")

    with pytest.raises(CliError, match="missing or forged"):
        _seed_rollback(fixture, seed_cutover, manifest_path)


def test_seed_rollback_refuses_new_planning_evidence(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _cutover(fixture)
    manifest_path = _seed_manifest(fixture)
    seed_cutover = _rematerialize(
        fixture,
        seed_manifest_path=manifest_path,
        expected_seed_manifest_sha256=sha256_path(manifest_path),
    )
    _target_rollback(fixture)
    plan = _load_json(fixture["plan_path"])
    plan["history"].append({"step": "plan", "result": "success"})
    _write_json(fixture["plan_path"], plan)

    with pytest.raises(CliError, match="unavailable after new planning"):
        _seed_rollback(fixture, seed_cutover, manifest_path)


@pytest.mark.parametrize(
    "stage",
    [
        "after_archive_restore",
        "after_rollback_plan_write",
        "after_rollback_chain_write",
    ],
)
def test_seed_rollback_failure_restores_rematerialized_epoch(
    tmp_path: Path,
    stage: str,
) -> None:
    fixture = _fixture(tmp_path)
    _cutover(fixture)
    manifest_path = _seed_manifest(fixture)
    seed_cutover = _rematerialize(
        fixture,
        seed_manifest_path=manifest_path,
        expected_seed_manifest_sha256=sha256_path(manifest_path),
    )
    _target_rollback(fixture)
    original_plan = fixture["plan_path"].read_bytes()
    original_chain = fixture["state_path"].read_bytes()
    original_idea = (fixture["plan_dir"] / "idea_snapshot.md").read_bytes()

    def fail(current: str) -> None:
        if current == stage:
            raise RuntimeError(f"injected at {stage}")

    with pytest.raises(RuntimeError, match="injected"):
        _seed_rollback(
            fixture,
            seed_cutover,
            manifest_path,
            failure_injector=fail,
        )

    assert fixture["plan_path"].read_bytes() == original_plan
    assert fixture["state_path"].read_bytes() == original_chain
    assert (fixture["plan_dir"] / "idea_snapshot.md").read_bytes() == original_idea


def test_seed_rematerialize_cli_exposes_manifest_and_state_cas_guards() -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            "chain",
            "seed-rematerialize",
            "--spec",
            "chain.yaml",
            "--project-dir",
            "/workspace/session",
            "--expected-session-id",
            "session",
            "--expected-current-milestone",
            MILESTONE,
            "--expected-current-plan",
            PLAN_NAME,
            "--expected-branch",
            M10_BRANCH,
            "--expected-head",
            "a" * 40,
            "--expected-spec-sha256",
            "1" * 64,
            "--expected-chain-state-sha256",
            "2" * 64,
            "--expected-plan-state-sha256",
            "3" * 64,
            "--seed-manifest",
            "m10-seed.json",
            "--expected-seed-manifest-sha256",
            "4" * 64,
            "--reason",
            "rematerialize",
        ]
    )

    assert args.chain_action == "seed-rematerialize"
    assert args.direction == "cutover"
    assert args.expected_seed_manifest_sha256 == "4" * 64
    assert SEED_REMATERIALIZE_ERROR == "seed_rematerialize_refused"
