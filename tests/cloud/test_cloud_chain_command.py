from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tarfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from agentbox.config import AgentBoxConfig
from agentbox.tmux import SessionStatus
from arnold_pipelines.megaplan import chain as chain_module
from arnold_pipelines.megaplan.cloud.cli import (
    _atomic_marker_write_command,
    _bootstrap_launch_command,
    _chain_anchor_uploads,
    _chain_launch_verification_command,
    _chain_project_root,
    _chain_runtime_policy_upload,
    _chain_runtime_probe_and_create_command,
    _chain_runtime_provenance_payload,
    _chain_runtime_marker_binding,
    _chain_command_with_runtime_binding,
    ChainLaunchContext,
    _chain_start_command,
    _cloud_launch_credentials_observation,
    _epic_chain_start_command,
    _manifest_runtime_activate_command,
    _parse_chain_runtime_binding,
    _plan_auto_command,
    _refresh_then_chain_start_command,
    _refresh_then_epic_chain_start_command,
    _cloud_chains_command,
    _cloud_session_plan_state,
    _derive_chain_launch_context,
    _derive_epic_chain_launch_context,
    _durable_megaplan_uploads,
    _derive_bootstrap_session_name,
    _latest_failure_from_plan_status,
    _launch_boundary_prefix,
    _materialize_canonical_epic_input,
    _normalized_chain_upload_spec,
    _phase_model_by_label_from_preflight,
    _filter_cloud_sessions_since,
    _parse_cloud_status_since,
    _provider_for_action,
    _remote_chain_upload_path,
    _remote_chain_workspace_path,
    _resolve_resume_workspace,
    _run_cloud_chains,
    _run_chain_wrapper,
    _run_epic_chain_wrapper,
    _run_preflight,
    _run_sync_megaplan,
    _run_launch_epic_wrapper,
    _run_bootstrap_wrapper,
    _status_should_use_chain,
    _tmux_chain_launch_command,
    _tmux_chain_stop_for_fresh_command,
    _validate_chain_spec_location,
    _verify_configured_megaplan_ref_advertised,
    build_cloud_parser,
    cloud_chain_status_payload,
    run_cloud_cli,
)
from arnold_pipelines.megaplan.fallback_chains import encode_phase_model_value
from arnold_pipelines.megaplan.cloud.preflight import resolve_cloud_chain_runtime_dependencies
from arnold_pipelines.megaplan.cloud.spec import (
    ChainSubSpec,
    CloudSpec,
    CodexSpec,
    MegaplanSpec,
    RepoSpec,
    ResourcesSpec,
    SshSpec,
)
from arnold_pipelines.megaplan.profiles import (
    CONTINUATION_RUNTIME_MODEL_SPEC,
    CONTINUATION_RUNTIME_PROFILE,
    VALID_PHASE_KEYS,
)
from arnold_pipelines.megaplan.types import CliError


def test_on_box_chain_uses_direct_agentbox_transport() -> None:
    from arnold_pipelines.megaplan.cloud.providers.on_box import OnBoxProvider

    provider = _provider_for_action(
        _cloud_spec(),
        argparse.Namespace(cloud_action="chain", on_box=True, session=None),
    )

    assert isinstance(provider, OnBoxProvider)


def test_fresh_chain_stop_is_identity_guarded_before_reset() -> None:
    command = _tmux_chain_stop_for_fresh_command(
        session_name="demo-chain",
        marker_path="/workspace/.megaplan/cloud-sessions/demo-chain.json",
        identity_digest="digest-123",
    )

    assert "tmux has-session -t demo-chain" in command
    assert "arnold_pipelines.megaplan.cloud.operator_control tmux-stop" in command
    assert "--marker /workspace/.megaplan/cloud-sessions/demo-chain.json" in command
    assert "grep -F digest-123" not in command
    assert "tmux kill-session -t demo-chain" not in command
    assert "refusing fresh reset" in command
    assert "exit 17" in command


def test_supervisor_resume_routes_through_operator_transaction_authority() -> None:
    from arnold_pipelines.megaplan.cloud.supervise import _canonical_resume_command

    command = _canonical_resume_command(
        "/workspace", "/workspace/chain.yaml", session_name="demo-chain"
    )

    assert "arnold_pipelines.megaplan.cloud.operator_control" in command
    assert " resume " in f" {command} "
    assert "tmux new-session" not in command


def test_cloud_capacity_observation_fails_closed_without_remote_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arnold_pipelines.megaplan.cloud import cli as cloud_cli

    monkeypatch.setattr(
        cloud_cli,
        "read_only_capacity_observation",
        lambda *args, **kwargs: {"status": "unknown"},
    )
    observed = cloud_cli._cloud_launch_capacity_observation(
        SimpleNamespace(), tmp_path
    )

    assert observed["status"] == "unknown"
    assert observed["disk"] == "unknown"
    assert observed["inode"] == "unknown"
    assert observed["output"] == "unknown"


def _cloud_spec() -> CloudSpec:
    return CloudSpec(
        provider="ssh",
        repo=RepoSpec(url="https://github.com/example/app.git", branch="main"),
        agents={"default": "codex"},
        codex=CodexSpec(),
        mode="idle",
        megaplan=MegaplanSpec(runtime_python="/workspace/runtime-venvs/test/bin/python"),
        resources=ResourcesSpec(),
        secrets=[],
        ssh=SshSpec(host="testhost"),
    )


def _attach_real_fresh_child_admission(
    project: Path,
    spec_path: Path,
    *,
    source_revision: str = "main",
    chain_identity: str = "cloud-test-child",
) -> None:
    """Opt the canonical fixture into the real RA/WBC/Custody boundary."""
    owners = project / ".test-fresh-child-owners"
    owners.mkdir(parents=True, exist_ok=True)
    raw = yaml.safe_load(spec_path.read_text(encoding="utf-8")) or {}
    raw["fresh_child_admission"] = {
        "enabled": True,
        "authority_journal_path": ".test-fresh-child-owners/authority.sqlite",
        "wbc_ledger_path": ".test-fresh-child-owners/wbc.sqlite",
        "custody_lease_dir": ".test-fresh-child-owners/leases",
        "approval_receipt": "sha256:" + "a" * 64,
        "approval_actor": "cloud-test-operator",
        "parent_occurrence_digest": "sha256:" + "b" * 64,
        "blocker_or_phase_result_hash": "sha256:" + "c" * 64,
        "normalized_failure_kind": "blocked",
        "chain_identity": chain_identity,
        "source_revision": source_revision,
        "run_revision": source_revision,
        "environment": "cloud",
        "session": "megaplan",
        "chain": "chain",
        "phase": "launch",
        "task": "launch",
    }
    spec_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")


def _running_container_observation() -> dict[str, object]:
    return {
        "status": "available",
        "lifecycle": "running",
        "collector": {"status": "available", "reason": None},
    }


def _go_prelaunch_capacity() -> dict[str, object]:
    return {
        "status": "go",
        "verdict": "GO",
        "checks": {
            "byte_floor": True,
            "inode_floor": True,
            "reserve_fsync": True,
            "sqlite_wal": True,
            "receipt_atomic_fsync": True,
            "cleanup": True,
        },
    }


def test_cloud_credentials_observation_is_route_aware_and_secret_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("C2_CONFIGURED_SECRET", "value-not-emitted")
    configured = replace(_cloud_spec(), secrets=["C2_CONFIGURED_SECRET"])
    missing_probe = _cloud_launch_credentials_observation(configured, SimpleNamespace())
    assert missing_probe["status"] == "unknown"
    assert missing_probe["reason"] == "remote_credential_probe_unavailable"
    assert "value-not-emitted" not in json.dumps(missing_probe)

    credentialless = _cloud_launch_credentials_observation(_cloud_spec(), SimpleNamespace())
    assert credentialless == {
        "status": "not_applicable",
        "identity": "credentialless_local",
        "transport": "ssh",
        "required": [],
    }


def _cloud_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    build_cloud_parser(subparsers)
    return parser


def test_cloud_status_and_chains_accept_compact_since_flags() -> None:
    status_args = _cloud_parser().parse_args(["cloud", "status", "--all", "--compact", "--since", "12h"])
    chains_args = _cloud_parser().parse_args(["cloud", "chains", "--compact", "--since", "12h"])

    assert status_args.cloud_action == "status"
    assert status_args.all is True
    assert status_args.compact is True
    assert status_args.since == "12h"
    assert chains_args.cloud_action == "chains"
    assert chains_args.compact is True
    assert chains_args.since == "12h"


def test_sync_megaplan_accepts_on_box_provider() -> None:
    from arnold_pipelines.megaplan.cloud.providers.on_box import OnBoxProvider

    args = _cloud_parser().parse_args(
        ["cloud", "sync-megaplan", "initiative/chain.yaml", "--on-box"]
    )

    assert args.cloud_action == "sync-megaplan"
    assert args.on_box is True
    assert isinstance(_provider_for_action(_cloud_spec(), args), OnBoxProvider)


def test_cloud_exec_accepts_on_box_provider() -> None:
    from arnold_pipelines.megaplan.cloud.providers.on_box import OnBoxProvider

    args = _cloud_parser().parse_args(
        ["cloud", "exec", "printf on-box", "--on-box"]
    )

    assert args.cloud_action == "exec"
    assert args.on_box is True
    assert isinstance(_provider_for_action(_cloud_spec(), args), OnBoxProvider)


def test_cloud_supervise_accepts_on_box_provider() -> None:
    from arnold_pipelines.megaplan.cloud.providers.on_box import OnBoxProvider

    args = _cloud_parser().parse_args(
        [
            "cloud",
            "supervise",
            "--chain",
            "--remote-spec",
            "initiative/chain.yaml",
            "--on-box",
        ]
    )

    assert args.cloud_action == "supervise"
    assert args.chain is True
    assert args.remote_spec == "initiative/chain.yaml"
    assert args.on_box is True
    assert isinstance(_provider_for_action(_cloud_spec(), args), OnBoxProvider)


def test_on_box_refused_for_action_outside_allowlist() -> None:
    """G7 negative: --on-box is allowlisted per action — an action outside
    the allowlist (status) refuses with the updated message listing
    supervise, while exec stays allowed.
    """
    from arnold_pipelines.megaplan.cloud.providers.on_box import OnBoxProvider

    with pytest.raises(
        CliError,
        match=(
            "--on-box is supported only for cloud chain, exec, launch-epic, "
            "sync-megaplan, and supervise"
        ),
    ):
        _provider_for_action(
            _cloud_spec(),
            argparse.Namespace(cloud_action="status", on_box=True, session=None),
        )

    assert isinstance(
        _provider_for_action(
            _cloud_spec(),
            argparse.Namespace(cloud_action="exec", on_box=True, session=None),
        ),
        OnBoxProvider,
    )


def test_cloud_chain_accepts_prepare_only() -> None:
    args = _cloud_parser().parse_args(
        ["cloud", "chain", "initiative/chain.yaml", "--prepare-only"]
    )

    assert args.cloud_action == "chain"
    assert args.prepare_only is True
    epic_args = _cloud_parser().parse_args(
        ["cloud", "launch-epic", "initiative", "--prepare-only"]
    )
    assert epic_args.prepare_only is True


def test_chain_start_command_sources_cloud_hot_env_before_launch() -> None:
    command = _chain_start_command(
        "/workspace/project/.megaplan/initiatives/demo/chain.yaml",
        project_dir="/workspace/project",
        engine_dir="/workspace/arnold",
    )

    pin_at = command.index(
        'PINNED_RUNTIME_MANIFEST="${ARNOLD_RUNTIME_MANIFEST:-}"'
    )
    hot_env_at = command.index(
        "if [ -f /workspace/.cloud-hot-env ]; then set -a; . /workspace/.cloud-hot-env; set +a; fi;"
    )
    assert pin_at < hot_env_at
    assert (
        'if [ -n "$PINNED_RUNTIME_MANIFEST" ]; then '
        'export ARNOLD_RUNTIME_MANIFEST="$PINNED_RUNTIME_MANIFEST"; fi;'
    ) in command
    # G6 round-2 finding 2: the ENGINE_DIR read is CANONICAL-schema gated —
    # the emitted reader requires schema "1" plus the manifest's required key
    # sets, so a present-but-schema-invalid manifest fails closed.
    assert (
        'ENGINE_DIR="$(env -u PYTHONHOME PYTHONSAFEPATH=1 python -P -c '
        "'import json,sys; d=json.load(open(sys.argv[1]));"
    ) in command
    assert 'd.get("schema")=="1"' in command
    assert "all(k in d for k in R)" in command
    assert "all(k in e for k in E)" in command
    # T-0011: the ENGINE_DIR fallback is gone — the manifest pin is mandatory
    # and fails closed on a missing/unreadable manifest, empty runtime_root or
    # expected_head, or a failed runtime_provenance check.
    assert 'if [ -z "$ENGINE_DIR" ]; then ENGINE_DIR=' not in command
    assert "isolated_chain_runtime_binding_drift: missing runtime manifest pin" in command
    assert "isolated_chain_runtime_binding_drift: runtime manifest unreadable" in command
    assert "isolated_chain_runtime_binding_drift: manifest lacks runtime_root" in command
    assert "isolated_chain_runtime_binding_drift: manifest lacks runtime identity" in command
    assert '--expected-root "$ENGINE_DIR"' in command
    assert '--expected-revision "$_EXPECTED_REVISION"' in command
    # G5 round-2 finding 1: the pin existence/readability checks run BEFORE
    # the manifest JSON-reader subprocess — on a missing or unreadable pin
    # the gate exits 24 with ZERO subprocess starts.
    assert command.index(
        'if [ -z "$PINNED_RUNTIME_MANIFEST" ]; then'
    ) < command.index(
        'ENGINE_DIR="$(env -u PYTHONHOME PYTHONSAFEPATH=1 python -P -c'
    )
    assert command.index(
        'if [ ! -r "$PINNED_RUNTIME_MANIFEST" ]; then'
    ) < command.index(
        'ENGINE_DIR="$(env -u PYTHONHOME PYTHONSAFEPATH=1 python -P -c'
    )
    # G5 round-6 finding 2: the emitted cd is the manifest-bound accepted
    # root ($ENGINE_DIR) — never project_dir (the workspace) and never the
    # launch-time engine_dir guess.
    assert (
        'cd "$ENGINE_DIR" && env -u PYTHONHOME PYTHONSAFEPATH=1 '
        'PYTHONPATH="$ENGINE_DIR"' in command
    )
    assert 'cd /workspace/project' not in command
    assert "MEGAPLAN_LAUNCH_RUNTIME_SRC" not in command
    assert "MEGAPLAN_RUNTIME_SRC" not in command
    # T-0301: the launch runs under the generation interpreter
    # (manifest-bound, worktree-first PYTHONPATH) — never ambient python.
    assert (
        'MEGAPLAN_TRUSTED_CONTAINER=1 "$GEN_INTERPRETER" -P -m '
        "arnold_pipelines.megaplan chain start"
    ) in command
    assert "python -P -m arnold_pipelines.megaplan chain start" not in command


def test_chain_start_command_installs_session_scoped_git_boundary() -> None:
    command = _chain_start_command(
        "/workspace/project/.megaplan/initiatives/demo/chain.yaml",
        project_dir="/workspace/project",
        engine_dir="/workspace/runtime-candidates/demo",
        repair_session="native-build-forward-c2-780129da-20260903-r5",
    )
    assert "arnold-launch-boundary" in command
    assert "arnold_materialize_launch_boundary" in command
    assert command.index(". \"$ARNOLD_LAUNCH_BOUNDARY\"") < command.index(
        "arnold_materialize_launch_boundary"
    )
    assert "on_box_git_auth_unavailable" not in command
    assert "native-build-forward-c2-780129da-20260903-r5" in command


def test_shared_launch_boundary_reasserts_hostile_hot_env() -> None:
    boundary = Path(__file__).resolve().parents[2] / (
        "arnold_pipelines/megaplan/cloud/wrappers/arnold-launch-boundary"
    )
    script = f"""
set -euo pipefail
source {shlex.quote(str(boundary))}
export ARNOLD_CHAIN_GIT_HELPER=/hostile/helper
export HOME=/hostile/home
export GIT_CONFIG_GLOBAL=/hostile/config
export PYTHONPATH=/hostile/python
export ARNOLD_BABYSITTER_MODEL=omp:deepseek/deepseek-v4-flash
export ARNOLD_BABYSITTER_ROUTING=codex
    export ARNOLD_BABYSITTER_CHAIN_PROFILE=all-muse-spark-openrouter
    export ARNOLD_BABYSITTER_CLOSED_PROFILE=all-muse-spark-openrouter
    arnold_materialize_launch_boundary native-build-forward-c2-780129da-20260903-r5 /tmp /tmp
printf '%s\\n' "$ARNOLD_CHAIN_GIT_HELPER" "$HOME" "$GIT_CONFIG_GLOBAL" "$PYTHONPATH" "$ARNOLD_BABYSITTER_MODEL" "$ARNOLD_BABYSITTER_OMP_MODEL" "$ARNOLD_BABYSITTER_ROUTING"
"""
    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, check=True
    )
    assert result.stdout.splitlines() == [
        "/workspace/.creds/git-credentials",
        "/hostile/home",
        "/hostile/config",
        "/tmp",  # runtime boundary pins imports
        "omp:openrouter/meta/muse-spark-1.3-contributor:high",
        "omp:openrouter/meta/muse-spark-1.3-contributor:high",
        "omp",
    ]
    assert "secret" not in result.stdout + result.stderr


def test_shared_launch_boundary_accepts_successor_profile() -> None:
    boundary = Path(__file__).resolve().parents[2] / (
        "arnold_pipelines/megaplan/cloud/wrappers/arnold-launch-boundary"
    )
    result = subprocess.run(
        [
            "bash",
            "-c",
            f"source {shlex.quote(str(boundary))}; "
            "export ARNOLD_BABYSITTER_CHAIN_PROFILE=all-muse-spark-1-3-contributor; "
            "export ARNOLD_BABYSITTER_CLOSED_PROFILE=all-muse-spark-1-3-contributor; "
            "arnold_materialize_launch_boundary successor /tmp /tmp",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "closed_profile_route_mismatch" not in result.stderr


def test_chain_controller_delegates_to_canonical_engine() -> None:
    from arnold_pipelines.megaplan.cloud import chain_drive

    cli_command = _chain_start_command(
        "/workspace/project/chain.yaml",
        project_dir="/workspace/project",
        engine_dir="/workspace/runtime-candidates/demo",
        repair_session="native-build-forward-c2-780129da-20260903-r5",
    )
    drive_command = chain_drive.launch_engine_command("encoded-request")
    wrappers = Path(__file__).resolve().parents[2] / "arnold_pipelines/megaplan/cloud/wrappers"
    chain_source = (wrappers / "arnold-chain").read_text(encoding="utf-8")
    watchdog_source = (wrappers / "arnold-watchdog").read_text(encoding="utf-8")
    assert "arnold_materialize_launch_boundary" in cli_command
    assert "chain_drive" in drive_command
    assert "arnold_materialize_launch_boundary" in chain_source
    assert "arnold_materialize_launch_boundary" in watchdog_source
    for source in (cli_command, chain_source, watchdog_source):
        if "cloud-hot-env" in source:
            assert source.index("cloud-hot-env") < source.index(
                "arnold_materialize_launch_boundary"
            )
        assert "if arnold_materialize_launch_boundary" in source


def test_boundary_failure_preserves_rc_and_never_dispatches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = tmp_path / "arnold-launch-boundary"
    boundary.write_text(
        "arnold_materialize_launch_boundary() { return 78; }\n",
        encoding="utf-8",
    )
    boundary.chmod(0o755)

    import arnold_pipelines.megaplan.cloud.cli as cli_module

    monkeypatch.setattr(cli_module, "_LAUNCH_BOUNDARY_PATH", str(boundary))
    cli_prefix = _launch_boundary_prefix(
        session="native-build-forward-c2-780129da-20260903-r5",
        engine_var=shlex.quote(str(tmp_path)),
    )
    cli_result = subprocess.run(
        ["bash", "-c", cli_prefix + "echo SENTINEL"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cli_result.returncode == 78
    assert "SENTINEL" not in cli_result.stdout

    from arnold_pipelines.megaplan.cloud import chain_drive

    drive_command = chain_drive.launch_engine_command("encoded-request")
    assert "arnold_pipelines.megaplan.cloud.chain_drive" in drive_command


def test_closed_profile_route_uses_authoritative_profile_not_session_generation() -> None:
    from arnold_pipelines.megaplan.cloud.cli import _validate_continuation_muse_routes

    good = {
        "milestones": [
            {
                "label": "c2",
                "profile": "all-muse-spark-openrouter",
                "resolved_phase_chains": {
                    "plan": [
                        "omp:openrouter/meta/muse-spark-1.3-contributor"
                    ]
                },
            }
        ]
    }
    assert _validate_continuation_muse_routes(
        good, session="native-build-forward-c2-780129da-20260903-r5"
    ) == {
        "status": "ok",
        "model": "omp:openrouter/meta/muse-spark-1.3-contributor",
        "profile": "all-muse-spark-openrouter",
        "thinking": "high",
        "fallback": False,
    }
    bad = {
        "milestones": [
            {
                "label": "c2",
                "profile": "all-muse-spark-openrouter",
                "resolved_phase_chains": {
                    "plan": ["omp:deepseek/deepseek-v4-flash", "codex"]
                },
            }
        ]
    }
    with pytest.raises(CliError) as caught:
        _validate_continuation_muse_routes(
            bad, session="native-build-forward-c2-future-r99"
        )
    assert caught.value.code == "closed_profile_route_mismatch"


def test_successor_closed_profile_route_requires_canonical_role_closure() -> None:
    from arnold_pipelines.megaplan.cloud.cli import _validate_continuation_muse_routes

    roles = {
        role: {"spec": CONTINUATION_RUNTIME_MODEL_SPEC, "effort": "high"}
        for role in (
            "phase",
            "tiebreaker_researcher",
            "tiebreaker_challenger",
            "oracle",
            "researcher",
            "fixer",
            "babysitter",
        )
    }
    summary = {
        "milestones": [
            {
                "label": "successor-c2",
                "profile": CONTINUATION_RUNTIME_PROFILE,
                "resolved_phase_chains": {
                    "plan": [CONTINUATION_RUNTIME_MODEL_SPEC],
                    "tiebreaker_researcher": [CONTINUATION_RUNTIME_MODEL_SPEC],
                },
            }
        ],
        "runtime_model_binding": {
            "profile": CONTINUATION_RUNTIME_PROFILE,
            "spec": CONTINUATION_RUNTIME_MODEL_SPEC,
            "backend": "omp",
            "provider": "openrouter",
            "model": "meta/muse-spark-1.3-contributor",
            "effort": "high",
            "roles": roles,
        },
    }
    assert _validate_continuation_muse_routes(summary) == {
        "status": "ok",
        "model": CONTINUATION_RUNTIME_MODEL_SPEC,
        "profile": CONTINUATION_RUNTIME_PROFILE,
        "thinking": "high",
        "fallback": False,
    }
    alias = copy.deepcopy(summary)
    alias["milestones"][0]["profile"] = "successor-muse-alias"
    with pytest.raises(CliError, match="supported Muse profile"):
        _validate_continuation_muse_routes(alias)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda summary: summary["milestones"][0]["resolved_phase_chains"].update(
            {"plan": [CONTINUATION_RUNTIME_MODEL_SPEC, "codex"]}
        ),
        lambda summary: summary["runtime_model_binding"]["roles"]["fixer"].update(
            {"spec": "omp:deepseek/deepseek-v4-flash", "effort": "high"}
        ),
        lambda summary: summary["runtime_model_binding"]["roles"]["oracle"].update(
            {"spec": CONTINUATION_RUNTIME_MODEL_SPEC, "effort": "low"}
        ),
        lambda summary: summary["runtime_model_binding"].update(
            {"provider": "deepseek"}
        ),
        lambda summary: summary["runtime_model_binding"]["roles"].pop("babysitter"),
    ],
)
def test_successor_closed_profile_route_fails_closed_on_route_or_role_drift(mutation) -> None:
    from arnold_pipelines.megaplan.cloud.cli import _validate_continuation_muse_routes

    roles = {
        role: {"spec": CONTINUATION_RUNTIME_MODEL_SPEC, "effort": "high"}
        for role in (
            "phase",
            "tiebreaker_researcher",
            "tiebreaker_challenger",
            "oracle",
            "researcher",
            "fixer",
            "babysitter",
        )
    }
    summary = {
        "milestones": [
            {
                "label": "successor-c2",
                "profile": CONTINUATION_RUNTIME_PROFILE,
                "resolved_phase_chains": {"plan": [CONTINUATION_RUNTIME_MODEL_SPEC]},
            }
        ],
        "runtime_model_binding": {
            "profile": CONTINUATION_RUNTIME_PROFILE,
            "spec": CONTINUATION_RUNTIME_MODEL_SPEC,
            "backend": "omp",
            "provider": "openrouter",
            "model": "meta/muse-spark-1.3-contributor",
            "effort": "high",
            "roles": roles,
        },
    }
    mutation(summary)
    with pytest.raises(CliError, match="no fallback"):
        _validate_continuation_muse_routes(summary)


def test_successor_closed_profile_route_rejects_mixed_profiles() -> None:
    from arnold_pipelines.megaplan.cloud.cli import _validate_continuation_muse_routes

    summary = {
        "milestones": [
            {
                "label": "successor-c2",
                "profile": CONTINUATION_RUNTIME_PROFILE,
                "resolved_phase_chains": {"plan": [CONTINUATION_RUNTIME_MODEL_SPEC]},
            },
            {
                "label": "legacy-c2",
                "profile": "all-muse-spark-openrouter",
                "resolved_phase_chains": {
                    "plan": ["omp:openrouter/meta/muse-spark-1.3-contributor"]
                },
            },
        ],
    }
    with pytest.raises(CliError, match="every chain milestone"):
        _validate_continuation_muse_routes(summary)


def test_successor_cloud_preflight_runs_exact_muse_probe(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "successor"
    spec_dir = project / ".megaplan" / "initiatives" / "successor"
    (spec_dir / "briefs").mkdir(parents=True)
    (project / ".megaplan").mkdir(exist_ok=True)
    (project / ".megaplan" / "profiles.toml").write_text(
        f"[profiles.{CONTINUATION_RUNTIME_PROFILE}]\n"
        + "\n".join(
            f"{phase} = \"{CONTINUATION_RUNTIME_MODEL_SPEC}\""
            for phase in (
                "plan",
                "prep",
                "critique",
                "critique_evaluator",
                "revise",
                "gate",
                "finalize",
                "execute",
                "feedback",
                "loop_plan",
                "loop_execute",
                "review",
                "tiebreaker_researcher",
                "tiebreaker_challenger",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    (spec_dir / "NORTHSTAR.md").write_text(
        "successor " + "launch contract " * 30,
        encoding="utf-8",
    )
    (spec_dir / "briefs" / "m1.md").write_text("successor idea\n", encoding="utf-8")
    spec_path = spec_dir / "chain.yaml"
    spec_path.write_text(
        "anchors:\n"
        "  north_star: NORTHSTAR.md\n"
        "milestones:\n"
        "  - label: successor-c2\n"
        "    idea: .megaplan/initiatives/successor/briefs/m1.md\n"
        f"    profile: {CONTINUATION_RUNTIME_PROFILE}\n",
        encoding="utf-8",
    )
    probes: list[tuple[object, bool]] = []

    def fake_probe(provider=None, *, local=False):
        probes.append((provider, local))
        return {
            "status": "ok",
            "provider": "openrouter",
            "model": "meta/muse-spark-1.3-contributor",
            "thinking": "high",
            "fallback": False,
        }

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.cli._omp_openrouter_capability_check",
        fake_probe,
    )
    rc = _run_preflight(
        project,
        argparse.Namespace(
            spec=str(spec_path),
            skip_remote=True,
            allow_loose_chain_spec=False,
        ),
        _cloud_spec(),
        SimpleNamespace(),
    )
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0, payload
    assert len(probes) == 1
    _provider, local = probes[0]
    assert local is True
    assert payload["closed_route"]["status"] == "ok"
    assert payload["closed_route"]["model"] == CONTINUATION_RUNTIME_MODEL_SPEC
    assert payload["closed_route"]["profile"] == CONTINUATION_RUNTIME_PROFILE
    assert payload["closed_route"]["thinking"] == "high"
    assert payload["closed_route"]["fallback"] is False


def test_tmux_chain_projects_closed_profile_into_watchdog_environment() -> None:
    command = _tmux_chain_launch_command(
        "/workspace/project",
        "/workspace/project/chain.yaml",
        session_name="native-build-forward-c2-future-generation-r99",
        marker_payload={
            "session": "native-build-forward-c2-future-generation-r99",
            "babysitter_chain_profile": "all-muse-spark-openrouter",
            "babysitter_closed_profile": "all-muse-spark-openrouter",
        },
    )
    assert "ARNOLD_BABYSITTER_CHAIN_PROFILE=all-muse-spark-openrouter" in command
    assert "ARNOLD_BABYSITTER_CLOSED_PROFILE=all-muse-spark-openrouter" in command
    assert "bb000694" not in command


def test_r4_omp_capability_probe_returns_sanitized_evidence() -> None:
    from arnold_pipelines.megaplan.cloud.cli import _omp_openrouter_capability_check

    class Provider:
        def ssh_exec(self, command):
            assert "openrouter/meta/muse-spark-1.3-contributor" in command
            assert "--thinking high" in command
            assert "--no-tools --no-session" in command
            assert "fallback" not in command
            return subprocess.CompletedProcess([], 0, "ARNOLD_MUSE_PREFLIGHT_OK\n", "")

    result = _omp_openrouter_capability_check(Provider())
    assert result["status"] == "ok"
    assert result["provider"] == "openrouter"
    assert result["model"] == "meta/muse-spark-1.3-contributor"
    assert result["thinking"] == "high"
    assert result["fallback"] is False
    assert "OPENROUTER_API_KEY" not in result


def test_r4_omp_capability_probe_rejects_marker_embedded_in_garbage() -> None:
    from arnold_pipelines.megaplan.cloud.cli import _omp_openrouter_capability_check

    class Provider:
        def ssh_exec(self, command):
            return subprocess.CompletedProcess(
                [], 0, "prefix ARNOLD_MUSE_PREFLIGHT_OK suffix\n", ""
            )

    result = _omp_openrouter_capability_check(Provider())
    assert result["status"] == "probe_failed"
    assert result["reason"] == "omp_probe_response_mismatch"


def test_r4_omp_capability_probe_auth_failure_is_typed_and_redacted() -> None:
    from arnold_pipelines.megaplan.cloud.cli import _omp_openrouter_capability_check

    class Provider:
        def ssh_exec(self, command):
            return subprocess.CompletedProcess(
                [], 1, "", "unauthorized: secret-token-must-not-escape"
            )

    result = _omp_openrouter_capability_check(Provider())
    assert result["status"] == "authentication_failed"
    assert result["reason"] == "omp_authentication_failed"
    assert "secret-token" not in repr(result)
    assert "OPENROUTER_API_KEY" not in repr(result)


def test_r4_omp_capability_probe_resolution_failure_is_typed() -> None:
    from arnold_pipelines.megaplan.cloud.cli import _omp_openrouter_capability_check

    class Provider:
        def ssh_exec(self, command):
            return subprocess.CompletedProcess([], 1, "", "model not found")

    result = _omp_openrouter_capability_check(Provider())
    assert result["status"] == "resolution_failed"
    assert result["reason"] == "omp_model_resolution_failed"


def test_r4_omp_store_probe_does_not_require_or_copy_env_key(monkeypatch) -> None:
    from arnold_pipelines.megaplan.cloud.cli import _omp_openrouter_capability_check

    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, "ARNOLD_MUSE_PREFLIGHT_OK\n", "")

    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli.subprocess.run", fake_run)
    result = _omp_openrouter_capability_check(local=True)
    assert result["status"] == "ok"
    argv, kwargs = calls[0]
    assert argv[argv.index("--model") + 1] == "openrouter/meta/muse-spark-1.3-contributor"
    assert argv[argv.index("--thinking") + 1] == "high"
    assert "OPENROUTER_API_KEY" not in repr(argv)
    assert "sk-secret" not in repr(result)


def test_r4_omp_probe_does_not_copy_a_different_env_store_key(monkeypatch) -> None:
    from arnold_pipelines.megaplan.cloud.cli import _omp_openrouter_capability_check

    secret = "env-key-from-a-different-store"
    monkeypatch.setenv("OPENROUTER_API_KEY", secret)
    calls = []

    class Provider:
        def ssh_exec(self, command):
            calls.append(command)
            return subprocess.CompletedProcess(
                [], 0, "ARNOLD_MUSE_PREFLIGHT_OK\n", ""
            )

    result = _omp_openrouter_capability_check(Provider())
    assert result["status"] == "ok"
    assert calls and secret not in calls[0]
    assert secret not in repr(result)


def test_chain_start_command_cd_is_manifest_accepted_root_not_project_or_engine() -> None:
    """G5 round-6 finding 2: the emitted cd is ALWAYS the manifest-bound
    accepted root.  project_dir (the chain workspace) and the launch-time
    engine_dir guess (e.g. the shared /workspace/arnold) must never reach
    the cd, even when both differ from the accepted root."""
    command = _chain_start_command(
        "/workspace/project/.megaplan/initiatives/demo/chain.yaml",
        project_dir="/workspace/project",
        engine_dir="/workspace/arnold",
    )
    assert 'cd "$ENGINE_DIR"' in command
    assert 'cd /workspace/project' not in command
    assert 'cd /workspace/arnold' not in command
    assert 'PYTHONPATH="$ENGINE_DIR:${PYTHONPATH:-}"' not in command


def test_epic_chain_start_command_pins_manifest_before_hot_env_and_fails_closed() -> None:
    command = _epic_chain_start_command(
        "/workspace/app/epic-chain.yaml",
        workspace="/workspace/app",
        log_relative=".megaplan/epic.log",
    )

    pin_at = command.index(
        'PINNED_RUNTIME_MANIFEST="${ARNOLD_RUNTIME_MANIFEST:-}"'
    )
    hot_env_at = command.index(
        "if [ -f /workspace/.cloud-hot-env ]; then set -a; . /workspace/.cloud-hot-env; set +a; fi;"
    )
    assert pin_at < hot_env_at
    assert (
        'if [ -n "$PINNED_RUNTIME_MANIFEST" ]; then '
        'export ARNOLD_RUNTIME_MANIFEST="$PINNED_RUNTIME_MANIFEST"; fi;'
    ) in command
    # G6 round-2 finding 2: the ENGINE_DIR read is CANONICAL-schema gated —
    # the emitted reader requires schema "1" plus the manifest's required key
    # sets, so a present-but-schema-invalid manifest fails closed.
    assert (
        'ENGINE_DIR="$(env -u PYTHONHOME PYTHONSAFEPATH=1 python -P -c '
        "'import json,sys; d=json.load(open(sys.argv[1]));"
    ) in command
    assert 'd.get("schema")=="1"' in command
    assert "all(k in d for k in R)" in command
    assert "all(k in e for k in E)" in command
    # G2 round 2: the epic-chain parent launch has NO fixed engine dir — the
    # per-session manifest pin is mandatory and fails closed (exit 24) on a
    # missing/unreadable manifest, empty runtime_root or expected_head, or a
    # failed runtime_provenance check.
    assert 'if [ -z "$ENGINE_DIR" ]; then ENGINE_DIR=' not in command
    assert "isolated_chain_runtime_binding_drift: missing runtime manifest pin" in command
    assert "isolated_chain_runtime_binding_drift: runtime manifest unreadable" in command
    assert "isolated_chain_runtime_binding_drift: manifest lacks runtime_root" in command
    assert "isolated_chain_runtime_binding_drift: manifest lacks runtime identity" in command
    assert "isolated_chain_runtime_binding_drift: active imports disagree with manifest-bound runtime" in command
    assert '--expected-root "$ENGINE_DIR"' in command
    assert '--expected-revision "$_EXPECTED_REVISION"' in command
    assert (
        'cd "$ENGINE_DIR" && env -u PYTHONHOME PYTHONSAFEPATH=1 '
        'PYTHONPATH="$ENGINE_DIR"' in command
    )
    assert 'cd /workspace/app' not in command
    # PYTHONPATH carries ONLY the manifest-bound engine root: no fixed-path
    # literal and no merge with any inherited PYTHONPATH.
    assert 'PYTHONPATH="$ENGINE_DIR:${PYTHONPATH:-}"' not in command
    assert "/workspace/arnold" not in command
    assert "MEGAPLAN_LAUNCH_RUNTIME_SRC" not in command
    assert "MEGAPLAN_RUNTIME_SRC" not in command
    assert "manifest lacks dependency generation interpreter" in command
    assert "dependency generation interpreter not executable" in command
    assert (
        'MEGAPLAN_TRUSTED_CONTAINER=1 "$GEN_INTERPRETER" -P -m '
        "arnold_pipelines.megaplan epic-chain start"
    ) in command
    assert "python -P -m arnold_pipelines.megaplan epic-chain start" not in command


def test_refresh_then_epic_chain_start_command_has_no_spec_engine_or_fixed_fallback() -> None:
    # The refresh wrapper delegates straight to the manifest-pinned launch:
    # the spec's megaplan.src_path is NOT consulted and there is no fixed
    # engine dir fallback (G2 round 2).
    command = _refresh_then_epic_chain_start_command(
        "/workspace/app/epic-chain.yaml",
        workspace="/workspace/app",
        log_relative=".megaplan/epic.log",
    )

    assert 'PINNED_RUNTIME_MANIFEST="${ARNOLD_RUNTIME_MANIFEST:-}"' in command
    assert "isolated_chain_runtime_binding_drift: missing runtime manifest pin" in command
    assert "runtime_provenance --expected-root" in command
    assert 'PYTHONPATH="$ENGINE_DIR"' in command
    assert "/workspace/arnold" not in command
    assert "/workspace/some-src" not in command
    assert "megaplan-refresh" not in command
    assert "pip install -e" not in command
    assert "MEGAPLAN_LAUNCH_RUNTIME_SRC" not in command
    assert "MEGAPLAN_RUNTIME_SRC" not in command
    assert (
        'MEGAPLAN_TRUSTED_CONTAINER=1 "$GEN_INTERPRETER" -P -m '
        "arnold_pipelines.megaplan epic-chain start"
    ) in command


def test_managed_chain_start_exports_canonical_repair_route() -> None:
    command = _chain_start_command(
        "/workspace/project/.megaplan/initiatives/demo/chain.yaml",
        project_dir="/workspace/project",
        engine_dir="/workspace/arnold",
        repair_session="demo-chain",
        repair_run_kind="chain",
        repair_marker_dir="/workspace/.megaplan/cloud-sessions",
    )

    assert "ARNOLD_REPAIR_QUEUE_ROOT" in command
    assert "ARNOLD_REPAIR_MARKER_DIR=/workspace/.megaplan/cloud-sessions" in command
    assert "ARNOLD_REPAIR_SESSION=demo-chain" in command
    assert "ARNOLD_CHAIN_SESSION=demo-chain" in command
    assert "ARNOLD_REPAIR_RUN_KIND=chain" in command


def test_managed_chain_start_exports_operation_marker_root() -> None:
    """The marker writer and chain launch-seed reader share one root."""
    marker_dir = "/workspace/operation-clean1/.megaplan/cloud-sessions"
    command = _chain_start_command(
        "/workspace/operation-clean1/chain.yaml",
        project_dir="/workspace/operation-clean1",
        engine_dir="/workspace/operation-clean1/runtime",
        repair_session="operation-clean1",
        repair_marker_dir=marker_dir,
    )

    assert f"export ARNOLD_CHAIN_SESSION_MARKER_DIR={marker_dir}" in command


def test_tmux_chain_launch_default_marker_records_run_kind() -> None:
    command = _tmux_chain_launch_command(
        "/workspace/project",
        "/workspace/project/.megaplan/initiatives/demo/chain.yaml",
        session_name="demo-chain",
        identity_digest="abc123",
    )

    marker_json = re.search(r"payload = json.loads\('([^']+)'\)", command)

    assert marker_json is not None
    marker = json.loads(marker_json.group(1))
    assert marker["run_kind"] == "chain"
    assert marker["notification_context"]["audience"] == "test_only"
    assert marker["notification_context"]["reason"] == "pytest_environment"


def test_atomic_marker_writer_can_be_followed_by_shell_operator(tmp_path: Path) -> None:
    marker = tmp_path / "markers" / "demo.json"
    manifest = tmp_path / "runtime-manifest.json"
    manifest.write_bytes(b"launch-created-successor-manifest\n")
    command = _atomic_marker_write_command(
        str(marker),
        {
            "session": "demo",
            "run_kind": "chain",
            "bootstrap_manifest_path": str(manifest),
        },
    )

    result = subprocess.run(
        ["bash", "-lc", f"{command}; test -s {marker}"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(marker.read_text())
    # Marker metadata is observational only; canonical admission/acceptance
    # lives in OperationRun and enriches the projection with custody facts.
    assert payload["run_kind"] == "chain"
    assert payload["session"] == "demo"
    expected_manifest_identity = hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert payload["manifest_sha256"] == expected_manifest_identity
    assert payload["manifest_identity"] == expected_manifest_identity
    assert payload["content_digest"]


def test_atomic_marker_writer_rejects_foreign_identity(tmp_path: Path) -> None:
    marker = tmp_path / "markers" / "demo.json"
    marker.parent.mkdir(parents=True)
    original = {
        "session": "demo",
        "run_kind": "chain",
        "operation_id": "old-operation",
        "request_id": "old-request",
        "envelope_digest": "old-envelope",
    }
    marker.write_text(json.dumps(original), encoding="utf-8")
    command = _atomic_marker_write_command(
        str(marker),
        {
            **original,
            "operation_id": "new-operation",
            "request_id": "new-request",
            "envelope_digest": "new-envelope",
        },
    )

    result = subprocess.run(
        ["bash", "-lc", command], capture_output=True, text=True, check=False
    )

    assert result.returncode != 0
    assert json.loads(marker.read_text(encoding="utf-8")) == original


def test_atomic_marker_writer_rejects_incomplete_foreign_custody(tmp_path: Path) -> None:
    marker = tmp_path / "markers" / "demo.json"
    marker.parent.mkdir(parents=True)
    marker.write_text(
        json.dumps(
            {
                "recovery_command": "foreign-recovery",
                "supervisor_start_identity": "foreign-supervisor",
            }
        ),
        encoding="utf-8",
    )
    command = _atomic_marker_write_command(
        str(marker),
        {
            "session": "demo",
            "run_kind": "chain",
            "operation_id": "new-operation",
            "request_id": "new-request",
            "envelope_digest": "new-envelope",
        },
    )

    result = subprocess.run(
        ["bash", "-lc", command], capture_output=True, text=True, check=False
    )

    assert result.returncode != 0
    assert "foreign/incomplete occupant" in result.stderr
    assert json.loads(marker.read_text(encoding="utf-8"))["recovery_command"] == "foreign-recovery"


def test_atomic_marker_writer_replaces_matching_occupant_without_unknown_fields(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "markers" / "demo.json"
    marker.parent.mkdir(parents=True)
    original = {
        "session": "demo",
        "run_kind": "chain",
        "operation_id": "op",
        "request_id": "req",
        "envelope_digest": "env",
        "foreign_unknown": "must-not-merge",
    }
    marker.write_text(json.dumps(original), encoding="utf-8")
    command = _atomic_marker_write_command(
        str(marker),
        {
            "session": "demo",
            "run_kind": "chain",
            "operation_id": "op",
            "request_id": "req",
            "envelope_digest": "env",
            "progress_identity": "new",
        },
    )

    result = subprocess.run(
        ["bash", "-lc", command], capture_output=True, text=True, check=False
    )

    assert result.returncode == 0, result.stderr
    updated = json.loads(marker.read_text(encoding="utf-8"))
    assert updated["progress_identity"] == "new"
    assert "foreign_unknown" not in updated


def test_bound_chain_marker_carries_deterministic_relaunch_command(tmp_path: Path) -> None:
    ctx = ChainLaunchContext(
        identity="demo",
        slug="demo",
        digest="d" * 64,
        workspace="/workspace/demo",
        remote_spec_path="/workspace/demo/chain.yaml",
        session_name="demo-chain",
        log_relative=".megaplan/cloud-chain.log",
        log_path="/workspace/demo/.megaplan/cloud-chain.log",
        state_path="/workspace/demo/.megaplan/state.json",
        marker_path=str(tmp_path / "demo.json"),
    )
    binding = {
        "manifest_path": "/workspace/.megaplan/demo.json",
        "manifest_sha256": "a" * 64,
        "manifest_identity": "a" * 64,
        "runtime_id": "runtime-demo",
        "runtime_source": "/workspace/runtime-demo",
        "runtime_src": "/workspace/runtime-demo",
        "runtime_revision": "b" * 40,
        "runtime_identity": {"import_root": "/workspace/runtime-demo", "source_revision": "b" * 40},
        "runtime_identity_raw": {},
    }
    command = _chain_command_with_runtime_binding(
        "env MEGAPLAN_BOUND_RUNTIME_REVISION=bbbb chain start",
        launch_ctx=ctx,
        binding=binding,
        operation_id="op",
        request_id="req",
    )

    marker_match = re.search(r"payload = json.loads\('([^']+)'\)", command)
    assert marker_match is not None
    payload = json.loads(marker_match.group(1))
    assert payload["relaunch_command"] == "env MEGAPLAN_BOUND_RUNTIME_REVISION=bbbb chain start"


def test_tmux_chain_launch_command_is_valid_shell() -> None:
    command = _tmux_chain_launch_command(
        "/workspace/project",
        "/workspace/project/.megaplan/initiatives/demo/chain.yaml",
        session_name="demo-chain",
        identity_digest="abc123",
    )

    result = subprocess.run(
        ["bash", "-n"],
        input=command,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_tmux_chain_launch_never_refreshes_remote_git() -> None:
    spec = replace(
        _cloud_spec(),
        megaplan=MegaplanSpec(
            ref="local-runtime",
            src_path="/workspace/local-runtime",
        ),
    )

    command = _tmux_chain_launch_command(
        "/workspace/project",
        "/workspace/project/.megaplan/initiatives/demo/chain.yaml",
        spec=spec,
    )

    # The editable-install refresh machinery is deleted (P4): no git mutation
    # and no refresh-verified runtime receipt in the launch path.
    assert "git push" not in command
    assert "git fetch" not in command
    assert "git pull" not in command
    assert 'BRANCH="$(git -C "$SRC" branch --show-current)"' not in command
    assert "megaplan-refresh" not in command
    assert "pip install -e" not in command
    # T-0011: the manifest pin + runtime_provenance gate is mandatory for
    # every production chain start (no fixed-path fallback), even with a
    # non-isolated spec.
    assert "runtime_provenance --expected-root" in command
    assert 'PINNED_RUNTIME_MANIFEST="${ARNOLD_RUNTIME_MANIFEST:-}"' in command
    assert "MEGAPLAN_LAUNCH_RUNTIME_SRC" not in command
    assert "MEGAPLAN_RUNTIME_SRC" not in command


def _runtime_probe_shim(tmp_path: Path, *, provenance_exit: int = 0) -> Path:
    shim = tmp_path / "bin" / "python"
    shim.parent.mkdir(parents=True)
    shim.write_text(
        "#!/bin/sh\n"
        "case \"$*\" in\n"
        "  *json.load*)\n"
        "    printf '%s|%s|%s|%s|%s\\n' \"$PYTHONPATH\" \"$ARNOLD_RUNTIME_MANIFEST\" "
        "\"${HOT_ENV_SOURCED-unset}\" \"${PYTHONHOME-unset}\" \"$*\" >> \"$RUNTIME_CAPTURE\"\n"
        "    exec \"$REAL_PYTHON\" \"$@\" ;;\n"
        "  *arnold_pipelines.megaplan.cloud.runtime_provenance*)\n"
        "    printf '%s|%s|%s|%s|%s\\n' \"$PYTHONPATH\" \"$ARNOLD_RUNTIME_MANIFEST\" "
        "\"${HOT_ENV_SOURCED-unset}\" \"${PYTHONHOME-unset}\" \"$*\" >> \"$RUNTIME_CAPTURE\"\n"
        "    if [ \"$HOT_ENV_SOURCED\" = 1 ] && [ -z \"$ZHIPU_API_KEY\" ]; then exit 3; fi\n"
        f"    exit {provenance_exit} ;;\n"
        "  *\"arnold_pipelines.megaplan chain start\"*)\n"
        "    printf '%s|%s|%s|%s|%s\\n' \"$PYTHONPATH\" \"$ARNOLD_RUNTIME_MANIFEST\" "
        "\"${HOT_ENV_SOURCED-unset}\" \"${PYTHONHOME-unset}\" \"$*\" >> \"$RUNTIME_CAPTURE\"\n"
        "    if [ \"$HOT_ENV_SOURCED\" = 1 ] && [ -z \"$ZHIPU_API_KEY\" ]; then exit 3; fi\n"
        "    exit 0 ;;\n"
        "  *\"arnold_pipelines.megaplan epic-chain start\"*)\n"
        "    printf '%s|%s|%s|%s|%s\\n' \"$PYTHONPATH\" \"$ARNOLD_RUNTIME_MANIFEST\" "
        "\"${HOT_ENV_SOURCED-unset}\" \"${PYTHONHOME-unset}\" \"$*\" >> \"$RUNTIME_CAPTURE\"\n"
        "    exit 0 ;;\n"
        "  *\"arnold_pipelines.megaplan auto\"*)\n"
        "    printf '%s|%s|%s|%s|%s\\n' \"$PYTHONPATH\" \"$ARNOLD_RUNTIME_MANIFEST\" "
        "\"${HOT_ENV_SOURCED-unset}\" \"${PYTHONHOME-unset}\" \"$*\" >> \"$RUNTIME_CAPTURE\"\n"
        "    exit 0 ;;\n"
        "  *\"arnold_pipelines.megaplan init\"*)\n"
        "    printf '%s|%s|%s|%s|%s\\n' \"$PYTHONPATH\" \"$ARNOLD_RUNTIME_MANIFEST\" "
        "\"${HOT_ENV_SOURCED-unset}\" \"${PYTHONHOME-unset}\" \"$*\" >> \"$RUNTIME_CAPTURE\"\n"
        "    exit 0 ;;\n"
        "esac\n"
        "exec \"$REAL_PYTHON\" \"$@\"\n",
        encoding="utf-8",
    )
    shim.chmod(0o755)
    return shim


def _canonical_manifest_payload(
    runtime_root: str,
    *,
    expected_head: str,
    interpreter_path: str = "/opt/arnold/runtime-venvs/generation/bin/python",
) -> dict[str, object]:
    """Canonical schema-"1" runtime-manifest payload (G6 round-2 finding 2).

    Must pass :func:`load_manifest` (trusted-case fixtures must be genuinely
    schema-valid) and must satisfy the shell pin-gate's canonical required
    key sets (``TOP_LEVEL_REQUIRED`` / ``EPIC_REQUIRED``), which the
    schema-gated pinned-manifest reads now enforce.

    T-0301: carries a complete ``dependency_generation`` proof; launch tests
    that RUN the emitted command point ``interpreter_path`` at their probe
    shim so the gate's executable check passes and the provenance/launch run
    through the shim.
    """
    return {
        "runtime_id": "pincheck-runtime-1",
        "schema": "1",
        "generation": 1,
        "epic_id": "pincheck-epic",
        "state": "active",
        "owner": "test",
        "base": {
            "ref": "refs/heads/main",
            "commit": expected_head or "0" * 40,
            "editable_install_path": f"{runtime_root}/base",
            "venv_path": f"{runtime_root}/base/venv",
        },
        "epic": {
            "branch": "main",
            "worktree_path": runtime_root,
            "venv_path": f"{runtime_root}/venv",
            "runtime_root": runtime_root,
            "expected_head": expected_head,
            "repair_bin": f"{runtime_root}/venv/bin/arnold-babysitter",
            "deps_lockfile": f"{runtime_root}/uv.lock",
            "dependency_generation": {
                "id": "a" * 64,
                "frozen_spec_sha256": "a" * 64,
                "interpreter_path": interpreter_path,
                "venv_digest": "b" * 64,
                "created": "2026-08-12T00:00:00Z",
            },
        },
        "indirection": {
            "host_path": runtime_root,
            "container_path": "/workspace/pincheck",
            "mount_table": [],
            "execution_namespace": "pincheck-ns",
            "verified_head": expected_head or "0" * 40,
            "last_verified_at": "2026-08-12T00:00:00Z",
            "attestation": {
                "module_file": f"{runtime_root}/arnold_pipelines/__init__.py",
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
            "created": "2026-08-12T00:00:00Z",
            "updated": "2026-08-12T00:00:00Z",
            "closed": "",
        },
        "gc_policy": "closed-only",
        "commands": [],
    }


def _write_runtime_manifest(
    path: Path, *, runtime_root: Path, revision: str, interpreter_path: str | None = None
) -> Path:
    """Write a canonically schema-valid runtime manifest (G6 round-2 finding 2).

    The pinned-manifest reads are schema-gated, so trusted-case fixtures must
    be real canonical manifests (schema "1" + required key sets), not the old
    schema-less ``{"epic": ...}`` shape.
    """
    from arnold_pipelines.megaplan.cloud.runtime_manifest import (
        RuntimeManifest,
        write_manifest,
    )

    payload = _canonical_manifest_payload(str(runtime_root), expected_head=revision)
    if interpreter_path is not None:
        payload["epic"]["dependency_generation"]["interpreter_path"] = (  # type: ignore[index]
            interpreter_path
        )
    write_manifest(RuntimeManifest.from_dict(payload), path)
    return path


def test_chain_launch_keeps_manifest_pin_across_poisoned_hot_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from arnold_pipelines.megaplan.cloud import cli as cloud_cli

    accepted = tmp_path / "accepted-runtime"
    stale = tmp_path / "stale-runtime"
    accepted.mkdir()
    stale.mkdir()
    revision = "a" * 40
    shim = _runtime_probe_shim(tmp_path)
    accepted_manifest = _write_runtime_manifest(
        tmp_path / "accepted-manifest.json",
        runtime_root=accepted,
        revision=revision,
        # T-0301: the generation interpreter IS the shim so the gate's
        # executable check passes and provenance/launch run through it.
        interpreter_path=str(shim),
    )
    stale_manifest = tmp_path / "stale-manifest.json"
    hot_env = tmp_path / "cloud-hot-env"
    hot_env.write_text(
        "\n".join(
            [
                f"export ARNOLD_RUNTIME_MANIFEST={stale_manifest}",
                f"export PYTHONPATH={stale}",
                f"export PYTHONHOME={stale}",
                "export HOT_ENV_SOURCED=1",
                "export ZHIPU_API_KEY=sentinel",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(cloud_cli, "_CLOUD_HOT_ENV_PATH", str(hot_env))
    capture = tmp_path / "capture.txt"
    # The manifest pin is mandatory regardless of isolated_chain_runner
    # (T-0011); the /fallback/runtime engine_dir must never reach PYTHONPATH.
    command = cloud_cli._chain_start_command(
        str(tmp_path / "chain.yaml"),
        project_dir=str(tmp_path),
        engine_dir="/fallback/runtime",
        log_relative="chain.log",
    )

    result = subprocess.run(
        ["bash", "-c", command],
        capture_output=True,
        text=True,
        check=False,
        env={
            **os.environ,
            "PATH": f"{shim.parent}{os.pathsep}{os.environ['PATH']}",
            "RUNTIME_CAPTURE": str(capture),
            "REAL_PYTHON": sys.executable,
            "ARNOLD_RUNTIME_MANIFEST": str(accepted_manifest),
            # G5 round-6 finding 2: an ambient shared-root PYTHONPATH must
            # not leak into the launch — only the manifest-bound accepted
            # root may reach the python processes.
            "PYTHONPATH": "/workspace/arnold",
        },
    )

    assert result.returncode == 0, result.stderr
    observations = capture.read_text(encoding="utf-8").splitlines()
    # Three manifest JSON-reader subprocesses (runtime_root + expected_head
    # + the T-0301 generation-interpreter read) run inside the pin gate;
    # provenance + chain start follow.
    assert len(observations) == 5, observations
    json_reads = [o for o in observations if "json.load(open(sys.argv[1]))" in o]
    assert len(json_reads) == 3, observations
    main = [o for o in observations if "json.load(open(sys.argv[1]))" not in o]
    assert len(main) == 2, observations
    for observation in main:
        (
            pythonpath,
            manifest,
            hot_env_sourced,
            pythonhome,
            _args,
        ) = observation.split("|", 4)
        assert pythonpath == str(accepted)
        assert manifest == str(accepted_manifest)
        assert hot_env_sourced == "1"
        assert pythonhome == "unset"
    for observation in json_reads:
        (
            _pythonpath,
            manifest,
            hot_env_sourced,
            pythonhome,
            _args,
        ) = observation.split("|", 4)
        assert manifest == str(accepted_manifest)
        assert hot_env_sourced == "1"
        assert pythonhome == "unset"
    assert "runtime_provenance" in main[0]
    assert f"--expected-revision {revision}" in main[0]
    assert "chain start" in main[1]


def test_chain_launch_fails_closed_before_chain_on_runtime_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from arnold_pipelines.megaplan.cloud import cli as cloud_cli

    hot_env = tmp_path / "cloud-hot-env"
    hot_env.write_text(
        "export ARNOLD_RUNTIME_MANIFEST=/stale/manifest.json\n", encoding="utf-8"
    )
    monkeypatch.setattr(cloud_cli, "_CLOUD_HOT_ENV_PATH", str(hot_env))
    shim = _runtime_probe_shim(tmp_path, provenance_exit=2)
    capture = tmp_path / "capture.txt"
    accepted = tmp_path / "accepted-runtime"
    accepted.mkdir()
    accepted_manifest = _write_runtime_manifest(
        tmp_path / "accepted-manifest.json",
        runtime_root=accepted,
        revision="a" * 40,
        interpreter_path=str(shim),
    )
    command = cloud_cli._chain_start_command(
        str(tmp_path / "chain.yaml"),
        project_dir=str(tmp_path),
        engine_dir="/fallback/runtime",
        log_relative="chain.log",
    )

    result = subprocess.run(
        ["bash", "-c", command],
        capture_output=True,
        text=True,
        check=False,
        env={
            **os.environ,
            "PATH": f"{shim.parent}{os.pathsep}{os.environ['PATH']}",
            "RUNTIME_CAPTURE": str(capture),
            "REAL_PYTHON": sys.executable,
            "ARNOLD_RUNTIME_MANIFEST": str(accepted_manifest),
        },
    )

    assert result.returncode == 24
    observations = capture.read_text(encoding="utf-8").splitlines()
    # The three manifest JSON-reader subprocesses (runtime_root +
    # expected_head + the T-0301 generation-interpreter read) ran inside the
    # pin gate; provenance is the only main-step invocation (chain start
    # never ran).
    assert len(observations) == 4, observations
    json_reads = [o for o in observations if "json.load(open(sys.argv[1]))" in o]
    assert len(json_reads) == 3, observations
    main = [o for o in observations if "json.load(open(sys.argv[1]))" not in o]
    assert len(main) == 1, observations
    assert "runtime_provenance" in main[0]
    assert "chain start" not in main[0]
    assert "isolated_chain_runtime_binding_drift" in (
        tmp_path / "chain.log"
    ).read_text(encoding="utf-8")


def test_chain_launch_schema_invalid_manifest_fails_closed_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """G6 round-2 finding 2: a PRESENT-but-schema-invalid manifest at the pin
    (the runtime pin fields present, but no canonical schema — no schema
    version, no top-level required keys) must fail closed: exit 24 and no
    chain start, instead of deriving an ENGINE_DIR from it."""
    from arnold_pipelines.megaplan.cloud import cli as cloud_cli

    hot_env = tmp_path / "cloud-hot-env"
    hot_env.write_text(
        "export ARNOLD_RUNTIME_MANIFEST=/stale/manifest.json\n", encoding="utf-8"
    )
    monkeypatch.setattr(cloud_cli, "_CLOUD_HOT_ENV_PATH", str(hot_env))
    shim = _runtime_probe_shim(tmp_path)
    capture = tmp_path / "capture.txt"
    schema_invalid = tmp_path / "schema-invalid-manifest.json"
    schema_invalid.write_text(
        json.dumps(
            {
                "epic": {
                    "runtime_root": str(tmp_path / "accepted-runtime"),
                    "expected_head": "a" * 40,
                }
            }
        ),
        encoding="utf-8",
    )
    command = cloud_cli._chain_start_command(
        str(tmp_path / "chain.yaml"),
        project_dir=str(tmp_path),
        engine_dir="/fallback/runtime",
        log_relative="chain.log",
    )

    result = subprocess.run(
        ["bash", "-c", command],
        capture_output=True,
        text=True,
        check=False,
        env={
            **os.environ,
            "PATH": f"{shim.parent}{os.pathsep}{os.environ['PATH']}",
            "RUNTIME_CAPTURE": str(capture),
            "REAL_PYTHON": sys.executable,
            "ARNOLD_RUNTIME_MANIFEST": str(schema_invalid),
        },
    )

    assert result.returncode == 24, result.stderr
    observations = capture.read_text(encoding="utf-8").splitlines()
    # The canonical-gated runtime_root read ran and yielded nothing, so the
    # gate exited 24 immediately — the expected_head read, provenance, and
    # chain start never ran.
    assert len(observations) == 1, observations
    json_reads = [o for o in observations if "json.load(open(sys.argv[1]))" in o]
    assert len(json_reads) == 1, observations
    assert "chain start" not in capture.read_text(encoding="utf-8")
    log_text = (tmp_path / "chain.log").read_text(encoding="utf-8")
    assert "isolated_chain_runtime_binding_drift" in log_text
    assert "manifest lacks runtime_root" in log_text


def _epic_chain_launch_command(
    workspace: Path,
    *,
    log_relative: str = ".megaplan/epic.log",
) -> str:
    return _epic_chain_start_command(
        "/workspace/app/epic-chain.yaml",
        workspace=str(workspace),
        log_relative=log_relative,
    )


def test_epic_chain_launch_bound_manifest_uses_only_manifest_root_on_pythonpath(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from arnold_pipelines.megaplan.cloud import cli as cloud_cli

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".megaplan").mkdir()
    stale = tmp_path / "stale-runtime"
    accepted = tmp_path / "accepted-runtime"
    stale.mkdir()
    accepted.mkdir()
    shim = _runtime_probe_shim(tmp_path)
    accepted_manifest = _write_runtime_manifest(
        tmp_path / "accepted-manifest.json",
        runtime_root=accepted,
        revision="a" * 40,
        interpreter_path=str(shim),
    )
    stale_manifest = tmp_path / "stale-manifest.json"
    hot_env = tmp_path / "cloud-hot-env"
    hot_env.write_text(
        "\n".join(
            [
                f"export ARNOLD_RUNTIME_MANIFEST={stale_manifest}",
                f"export PYTHONPATH={stale}",
                f"export PYTHONHOME={stale}",
                "export HOT_ENV_SOURCED=1",
                "export ZHIPU_API_KEY=sentinel",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(cloud_cli, "_CLOUD_HOT_ENV_PATH", str(hot_env))
    capture = tmp_path / "capture.txt"

    command = _epic_chain_launch_command(workspace)
    result = subprocess.run(
        ["bash", "-c", command],
        capture_output=True,
        text=True,
        check=False,
        env={
            **os.environ,
            "PATH": f"{shim.parent}{os.pathsep}{os.environ['PATH']}",
            "RUNTIME_CAPTURE": str(capture),
            "REAL_PYTHON": sys.executable,
            "ARNOLD_RUNTIME_MANIFEST": str(accepted_manifest),
            # G5 round-6 finding 2: an ambient shared-root PYTHONPATH must
            # not leak into the launch — only the manifest-bound accepted
            # root may reach the python processes.
            "PYTHONPATH": "/workspace/arnold",
        },
    )

    assert result.returncode == 0, result.stderr
    observations = capture.read_text(encoding="utf-8").splitlines()
    # Three manifest JSON-reader subprocesses (runtime_root + expected_head
    # + the T-0301 generation-interpreter read) run inside the pin gate;
    # provenance + epic-chain start follow.
    assert len(observations) == 5, observations
    json_reads = [o for o in observations if "json.load(open(sys.argv[1]))" in o]
    assert len(json_reads) == 3, observations
    main = [o for o in observations if "json.load(open(sys.argv[1]))" not in o]
    assert len(main) == 2, observations
    for observation in main:
        (
            pythonpath,
            manifest,
            hot_env_sourced,
            pythonhome,
            _args,
        ) = observation.split("|", 4)
        assert pythonpath == str(accepted)
        assert manifest == str(accepted_manifest)
        assert hot_env_sourced == "1"
        assert pythonhome == "unset"
    for observation in json_reads:
        (
            _pythonpath,
            manifest,
            hot_env_sourced,
            pythonhome,
            _args,
        ) = observation.split("|", 4)
        assert manifest == str(accepted_manifest)
        assert hot_env_sourced == "1"
        assert pythonhome == "unset"
    assert "runtime_provenance" in main[0]
    assert "epic-chain start" in main[1]
    assert "/workspace/arnold" not in capture.read_text(encoding="utf-8")


def test_epic_chain_launch_unbound_manifest_fails_closed_before_launch(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".megaplan").mkdir()
    shim = _runtime_probe_shim(tmp_path)
    capture = tmp_path / "capture.txt"

    command = _epic_chain_launch_command(workspace)
    result = subprocess.run(
        ["bash", "-c", command],
        capture_output=True,
        text=True,
        check=False,
        env={
            **os.environ,
            "PATH": f"{shim.parent}{os.pathsep}{os.environ['PATH']}",
            "RUNTIME_CAPTURE": str(capture),
            "REAL_PYTHON": sys.executable,
        },
    )

    assert result.returncode == 24
    # No provenance probe and no launch boundary were reached.
    capture_text = capture.read_text(encoding="utf-8") if capture.exists() else ""
    assert capture_text == ""
    log_text = (workspace / ".megaplan" / "epic.log").read_text(encoding="utf-8")
    assert "isolated_chain_runtime_binding_drift: missing runtime manifest pin" in log_text


@pytest.mark.parametrize(
    ("case", "manifest", "provenance_rc", "expect"),
    [
        (
            "missing-file",
            "/nonexistent/runtime-manifest.json",
            0,
            "runtime manifest unreadable",
        ),
        (
            "empty-epic",
            {"epic": {}},
            0,
            "manifest lacks runtime_root",
        ),
        (
            "no-expected-head",
            _canonical_manifest_payload("/some/root", expected_head=""),
            0,
            "manifest lacks runtime identity",
        ),
        (
            "schema-invalid",
            {"epic": {"runtime_root": "/some/root", "expected_head": "a" * 40}},
            0,
            "manifest lacks runtime_root",
        ),
        (
            "unsupported-schema",
            {
                "schema": "2",
                "epic": {"runtime_root": "/some/root", "expected_head": "a" * 40},
            },
            0,
            "manifest lacks runtime_root",
        ),
        (
            "provenance-mismatch",
            "valid",
            23,
            "active imports disagree with manifest-bound runtime",
        ),
    ],
)
def test_epic_chain_launch_invalid_manifest_fails_closed_before_launch(
    tmp_path: Path,
    case: str,
    manifest: object,
    provenance_rc: int,
    expect: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".megaplan").mkdir()
    shim = _runtime_probe_shim(tmp_path, provenance_exit=provenance_rc)
    capture = tmp_path / "capture.txt"
    env = {
        **os.environ,
        "PATH": f"{shim.parent}{os.pathsep}{os.environ['PATH']}",
        "RUNTIME_CAPTURE": str(capture),
        "REAL_PYTHON": sys.executable,
    }
    manifest_path = tmp_path / "runtime-manifest.json"
    if manifest == "valid":
        manifest_path = _write_runtime_manifest(
            manifest_path,
            runtime_root=tmp_path / "accepted-runtime",
            revision="a" * 40,
            interpreter_path=str(shim),
        )
        env["ARNOLD_RUNTIME_MANIFEST"] = str(manifest_path)
    elif isinstance(manifest, dict):
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        env["ARNOLD_RUNTIME_MANIFEST"] = str(manifest_path)
    else:
        env["ARNOLD_RUNTIME_MANIFEST"] = str(manifest)

    result = subprocess.run(
        ["bash", "-c", _epic_chain_launch_command(workspace)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )

    assert result.returncode == 24, (case, result.stdout, result.stderr)
    log_text = (workspace / ".megaplan" / "epic.log").read_text(encoding="utf-8")
    assert "isolated_chain_runtime_binding_drift" in log_text, case
    assert expect in log_text, case
    # No launch boundary was reached for any rejection.
    capture_text = capture.read_text(encoding="utf-8") if capture.exists() else ""
    assert "epic-chain start" not in capture_text, case


def _plan_auto_launch_command(
    workspace: Path, *, log_relative: str = ".megaplan/plan.log"
) -> str:
    return _plan_auto_command(
        "demo-plan",
        workspace=str(workspace),
        log_relative=log_relative,
    )


def test_plan_auto_launch_bound_manifest_uses_only_manifest_root_on_pythonpath(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from arnold_pipelines.megaplan.cloud import cli as cloud_cli

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".megaplan").mkdir()
    stale = tmp_path / "stale-runtime"
    accepted = tmp_path / "accepted-runtime"
    stale.mkdir()
    accepted.mkdir()
    shim = _runtime_probe_shim(tmp_path)
    accepted_manifest = _write_runtime_manifest(
        tmp_path / "accepted-manifest.json",
        runtime_root=accepted,
        revision="a" * 40,
        interpreter_path=str(shim),
    )
    stale_manifest = tmp_path / "stale-manifest.json"
    hot_env = tmp_path / "cloud-hot-env"
    hot_env.write_text(
        "\n".join(
            [
                f"export ARNOLD_RUNTIME_MANIFEST={stale_manifest}",
                f"export PYTHONPATH={stale}",
                f"export PYTHONHOME={stale}",
                "export HOT_ENV_SOURCED=1",
                "export ZHIPU_API_KEY=sentinel",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(cloud_cli, "_CLOUD_HOT_ENV_PATH", str(hot_env))
    capture = tmp_path / "capture.txt"

    command = _plan_auto_launch_command(workspace)
    result = subprocess.run(
        ["bash", "-c", command],
        capture_output=True,
        text=True,
        check=False,
        env={
            **os.environ,
            "PATH": f"{shim.parent}{os.pathsep}{os.environ['PATH']}",
            "RUNTIME_CAPTURE": str(capture),
            "REAL_PYTHON": sys.executable,
            "ARNOLD_RUNTIME_MANIFEST": str(accepted_manifest),
            # G5 round-6 finding 2: an ambient shared-root PYTHONPATH must
            # not leak into the launch — only the manifest-bound accepted
            # root may reach the python processes.
            "PYTHONPATH": "/workspace/arnold",
        },
    )

    assert result.returncode == 0, result.stderr
    observations = capture.read_text(encoding="utf-8").splitlines()
    # Three manifest JSON-reader subprocesses (runtime_root + expected_head
    # + the T-0301 generation-interpreter read) run inside the pin gate;
    # provenance + auto follow.
    assert len(observations) == 5, observations
    json_reads = [o for o in observations if "json.load(open(sys.argv[1]))" in o]
    assert len(json_reads) == 3, observations
    main = [o for o in observations if "json.load(open(sys.argv[1]))" not in o]
    assert len(main) == 2, observations
    for observation in main:
        (
            pythonpath,
            manifest,
            hot_env_sourced,
            pythonhome,
            _args,
        ) = observation.split("|", 4)
        assert pythonpath == str(accepted)
        assert manifest == str(accepted_manifest)
        assert hot_env_sourced == "1"
        assert pythonhome == "unset"
    for observation in json_reads:
        (
            _pythonpath,
            manifest,
            hot_env_sourced,
            pythonhome,
            _args,
        ) = observation.split("|", 4)
        assert manifest == str(accepted_manifest)
        assert hot_env_sourced == "1"
        assert pythonhome == "unset"
    assert "runtime_provenance" in main[0]
    assert "arnold_pipelines.megaplan auto" in main[1]
    assert "/workspace/arnold" not in capture.read_text(encoding="utf-8")
    assert "/workspace/arnold" not in command


def test_plan_auto_launch_unbound_manifest_fails_closed_before_launch(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".megaplan").mkdir()
    shim = _runtime_probe_shim(tmp_path)
    capture = tmp_path / "capture.txt"

    command = _plan_auto_launch_command(workspace)
    result = subprocess.run(
        ["bash", "-c", command],
        capture_output=True,
        text=True,
        check=False,
        env={
            **os.environ,
            "PATH": f"{shim.parent}{os.pathsep}{os.environ['PATH']}",
            "RUNTIME_CAPTURE": str(capture),
            "REAL_PYTHON": sys.executable,
        },
    )

    assert result.returncode == 24
    # No provenance probe and no launch boundary were reached.
    capture_text = capture.read_text(encoding="utf-8") if capture.exists() else ""
    assert capture_text == ""
    log_text = (workspace / ".megaplan" / "plan.log").read_text(encoding="utf-8")
    assert "isolated_chain_runtime_binding_drift: missing runtime manifest pin" in log_text


@pytest.mark.parametrize(
    ("case", "manifest", "provenance_rc", "expect"),
    [
        (
            "missing-file",
            "/nonexistent/runtime-manifest.json",
            0,
            "runtime manifest unreadable",
        ),
        (
            "empty-epic",
            {"epic": {}},
            0,
            "manifest lacks runtime_root",
        ),
        (
            "no-expected-head",
            _canonical_manifest_payload("/some/root", expected_head=""),
            0,
            "manifest lacks runtime identity",
        ),
        (
            "schema-invalid",
            {"epic": {"runtime_root": "/some/root", "expected_head": "a" * 40}},
            0,
            "manifest lacks runtime_root",
        ),
        (
            "unsupported-schema",
            {
                "schema": "2",
                "epic": {"runtime_root": "/some/root", "expected_head": "a" * 40},
            },
            0,
            "manifest lacks runtime_root",
        ),
        (
            "provenance-mismatch",
            "valid",
            23,
            "active imports disagree with manifest-bound runtime",
        ),
    ],
)
def test_plan_auto_launch_invalid_manifest_fails_closed_before_launch(
    tmp_path: Path,
    case: str,
    manifest: object,
    provenance_rc: int,
    expect: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".megaplan").mkdir()
    shim = _runtime_probe_shim(tmp_path, provenance_exit=provenance_rc)
    capture = tmp_path / "capture.txt"
    env = {
        **os.environ,
        "PATH": f"{shim.parent}{os.pathsep}{os.environ['PATH']}",
        "RUNTIME_CAPTURE": str(capture),
        "REAL_PYTHON": sys.executable,
    }
    manifest_path = tmp_path / "runtime-manifest.json"
    if manifest == "valid":
        manifest_path = _write_runtime_manifest(
            manifest_path,
            runtime_root=tmp_path / "accepted-runtime",
            revision="a" * 40,
            interpreter_path=str(shim),
        )
        env["ARNOLD_RUNTIME_MANIFEST"] = str(manifest_path)
    elif isinstance(manifest, dict):
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        env["ARNOLD_RUNTIME_MANIFEST"] = str(manifest_path)
    else:
        env["ARNOLD_RUNTIME_MANIFEST"] = str(manifest)

    result = subprocess.run(
        ["bash", "-c", _plan_auto_launch_command(workspace)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )

    assert result.returncode == 24, (case, result.stdout, result.stderr)
    log_text = (workspace / ".megaplan" / "plan.log").read_text(encoding="utf-8")
    assert "isolated_chain_runtime_binding_drift" in log_text, case
    assert expect in log_text, case
    # No launch boundary was reached for any rejection.
    capture_text = capture.read_text(encoding="utf-8") if capture.exists() else ""
    assert "arnold_pipelines.megaplan auto" not in capture_text, case


def test_bootstrap_launch_unbound_manifest_fails_closed_before_init(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from arnold_pipelines.megaplan.cloud import cli as cloud_cli

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".megaplan").mkdir()
    marker_dir = tmp_path / "markers"
    monkeypatch.setattr(cloud_cli, "_CHAIN_SESSION_MARKER_DIR", str(marker_dir))
    shim = _runtime_probe_shim(tmp_path)
    capture = tmp_path / "capture.txt"
    # Spy on mkdir: record every invocation, then pass through to the real
    # binary so the assertion below can prove ZERO dir creation.
    mkdir_capture = tmp_path / "mkdir-capture.txt"
    mkdir_spy = tmp_path / "bin" / "mkdir"
    mkdir_spy.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$*" >> {shlex.quote(str(mkdir_capture))}\n'
        'exec /bin/mkdir "$@"\n',
        encoding="utf-8",
    )
    mkdir_spy.chmod(0o755)

    command = cloud_cli._bootstrap_launch_command(
        workspace=str(workspace),
        remote_idea_path=str(workspace / "idea.txt"),
        plan_name="demo-plan",
        robustness="standard",
        session_name="plan-session",
    )
    result = subprocess.run(
        ["bash", "-c", command],
        capture_output=True,
        text=True,
        check=False,
        env={
            **os.environ,
            "PATH": f"{shim.parent}{os.pathsep}{os.environ['PATH']}",
            "RUNTIME_CAPTURE": str(capture),
            "REAL_PYTHON": sys.executable,
        },
    )

    assert result.returncode == 24, result.stderr
    # G5 round-2 finding 1: the pin gate runs BEFORE the marker write and the
    # init launch — the shim records ZERO python invocations (the manifest
    # JSON-reader subprocess never starts) and the session marker is NOT
    # written.
    capture_text = capture.read_text(encoding="utf-8") if capture.exists() else ""
    assert capture_text == "", capture_text.splitlines()
    assert "json.load(open(sys.argv[1]))" not in capture_text
    assert "arnold_pipelines.megaplan init" not in capture_text
    marker_path = marker_dir / "plan-session.json"
    assert not marker_path.exists(), "session marker written before the pin gate"
    # G5 round-6 finding 1a: the pin gate is the FIRST side-effecting
    # statement — the missing pin exits 24 with ZERO mkdir/dir-creation, so
    # neither the marker dir nor the cloud-logs dir is ever created and the
    # drift message falls back to stderr (no log dir exists to write to).
    assert not mkdir_capture.exists(), mkdir_capture.read_text(encoding="utf-8")
    assert not marker_dir.exists()
    assert not (workspace / ".megaplan" / "cloud-logs").exists()
    assert "isolated_chain_runtime_binding_drift: missing runtime manifest pin" in (
        result.stderr
    )


def test_bootstrap_launch_bound_manifest_reaches_init_with_manifest_root_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from arnold_pipelines.megaplan.cloud import cli as cloud_cli

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".megaplan").mkdir()
    marker_dir = tmp_path / "markers"
    monkeypatch.setattr(cloud_cli, "_CHAIN_SESSION_MARKER_DIR", str(marker_dir))
    accepted = tmp_path / "accepted-runtime"
    accepted.mkdir()
    shim = _runtime_probe_shim(tmp_path)
    accepted_manifest = _write_runtime_manifest(
        tmp_path / "accepted-manifest.json",
        runtime_root=accepted,
        revision="a" * 40,
        interpreter_path=str(shim),
    )
    capture = tmp_path / "capture.txt"

    command = cloud_cli._bootstrap_launch_command(
        workspace=str(workspace),
        remote_idea_path=str(workspace / "idea.txt"),
        plan_name="demo-plan",
        robustness="standard",
        session_name="plan-session",
    )
    result = subprocess.run(
        ["bash", "-c", command],
        capture_output=True,
        text=True,
        check=False,
        env={
            **os.environ,
            "PATH": f"{shim.parent}{os.pathsep}{os.environ['PATH']}",
            "RUNTIME_CAPTURE": str(capture),
            "REAL_PYTHON": sys.executable,
            "ARNOLD_RUNTIME_MANIFEST": str(accepted_manifest),
        },
    )

    assert result.returncode == 0, result.stderr
    observations = capture.read_text(encoding="utf-8").splitlines()
    # Three manifest JSON-reader subprocesses (runtime_root + expected_head
    # + the T-0301 generation-interpreter read) run inside the pin gate,
    # then runtime_provenance, then init.
    assert len(observations) == 5, observations
    json_reads = [o for o in observations if "json.load(open(sys.argv[1]))" in o]
    assert len(json_reads) == 3, observations
    provenance = [o for o in observations if "runtime_provenance" in o]
    init = [o for o in observations if "arnold_pipelines.megaplan init" in o]
    assert len(provenance) == 1 and len(init) == 1, observations
    for observation in observations:
        pythonpath, manifest, _hot, _home, args = observation.split("|", 4)
        assert manifest == str(accepted_manifest)
        if "json.load(open(sys.argv[1]))" not in args:
            assert pythonpath == str(accepted)
    assert "runtime_provenance" in provenance[0]
    assert "arnold_pipelines.megaplan init" in init[0]
    assert "/workspace/arnold" not in capture.read_text(encoding="utf-8")
    assert "/workspace/arnold" not in command
    # G5 round-6 finding 1a: with a valid pin the gate passes first, THEN
    # the mkdir runs — the marker dir and the cloud-logs dir are created and
    # the marker is written (the command proceeds).
    assert marker_dir.is_dir()
    assert (workspace / ".megaplan" / "cloud-logs").is_dir()
    assert (marker_dir / "plan-session.json").is_file()


def test_chain_spec_enables_post_hot_env_runtime_gate_regardless_of_isolated_runner() -> None:
    # T-0011: the runtime pin is mandatory for EVERY production chain start;
    # isolated_chain_runner no longer toggles it.
    for spec in (
        replace(_cloud_spec(), isolated_chain_runner=True),
        _cloud_spec(),
    ):
        command = _tmux_chain_launch_command(
            "/workspace/project",
            "/workspace/project/.megaplan/initiatives/demo/chain.yaml",
            spec=spec,
        )

        assert "isolated_chain_runtime_binding_drift" in command
        assert "--expected-root" in command
        assert "--expected-revision" in command
        assert ". /workspace/.cloud-hot-env" in command


# ── P1 producer routing: per-epic runtime creation + manifest binding ────────


def _runtime_binding(**overrides: Any) -> dict[str, Any]:
    binding = {
        "manifest_path": "/workspace/.megaplan/demo-abc123.json",
        "manifest_sha256": "c" * 64,
        "manifest_identity": "c" * 64,
        "runtime_src": "/workspace/runtime-candidates/demo-abc123",
        "runtime_source": "/workspace/runtime-candidates/demo-abc123",
        "runtime_revision": "a" * 40,
        "runtime_id": "demo-abc123-20260810",
        "slug": "demo-abc123",
        "created": True,
        "policy_path": None,
        "runtime_identity": {
            "import_root": "/workspace/runtime-candidates/demo-abc123",
            "source_revision": "a" * 40,
            "editable_root": "",
            "editable_revision": "",
            "direct_url": {},
            "pth": [],
            "imports": {},
            "content_sha256": "b" * 64,
        },
        "runtime_identity_raw": {
            "runtime_id": "demo-abc123-20260810",
            "epic_id": "demo-abc123",
            "runtime_source": "/workspace/runtime-candidates/demo-abc123",
            "runtime_revision": "a" * 40,
        },
    }
    binding.update(overrides)
    return binding


def test_chain_runtime_probe_and_create_command_embeds_create_and_policy() -> None:
    command = _chain_runtime_probe_and_create_command(
        slug="demo-abc123",
        manifest_path="/workspace/.megaplan/demo-abc123.json",
        runtime_src="/workspace/runtime-candidates/demo-abc123",
        manifest_dir="/workspace/.megaplan",
        base_repo="/workspace/arnold",
        base_ref="editible-install",
        policy_path="/workspace/chain/.megaplan/plans/.chains/demo.runtime_policy.json",
    )
    # absent manifest → arnold-runtime-create ON THE BOX with the policy env
    assert "arnold-runtime-create" in command
    assert "export ARNOLD_RUNTIME_POLICY=/workspace/chain/.megaplan/plans/.chains/demo.runtime_policy.json" in command
    assert "export ARNOLD_BASE_REPO=/workspace/arnold" in command
    assert 'if [ -f "$MANIFEST" ]; then' in command
    assert '"epic_id": payload.get("epic_id", "")' in command
    # the launched chain binds THIS manifest (per-session, no global pointer)
    assert "/workspace/.megaplan/demo-abc123.json" in command


def test_chain_runtime_probe_command_binds_operation_roots() -> None:
    command = _chain_runtime_probe_and_create_command(
        slug="demo-clean1",
        manifest_path="/workspace/demo-clean1/.megaplan/demo-clean1.json",
        runtime_src="/workspace/demo-clean1/runtime-candidates/demo-clean1",
        manifest_dir="/workspace/demo-clean1/.megaplan",
        base_repo="/workspace/demo-clean1/Arnold",
        base_ref="main",
        policy_path=None,
        marker_path="/workspace/demo-clean1/.megaplan/cloud-sessions/demo-clean1.json",
        base_dir="/workspace/demo-clean1",
    )
    assert "export ARNOLD_BASE_DIR=/workspace/demo-clean1" in command
    assert "export ARNOLD_RUNTIME_MANIFEST_DIR=/workspace/demo-clean1/.megaplan" in command
    assert "export ARNOLD_CHAIN_SESSION_MARKER_DIR=/workspace/demo-clean1/.megaplan/cloud-sessions" in command


def test_chain_launch_env_propagates_operation_roots() -> None:
    command = _refresh_then_chain_start_command(
        "/workspace/demo-clean1/Arnold/.megaplan/plans/.chains/demo.yaml",
        project_dir="/workspace/demo-clean1/Arnold",
        spec=SimpleNamespace(megaplan=SimpleNamespace(src_path="/workspace/demo-clean1/Arnold")),
        repair_session="demo-clean1",
        repair_marker_dir="/workspace/demo-clean1/.megaplan/cloud-sessions",
    )
    assert "export ARNOLD_BASE_DIR=/workspace/demo-clean1" in command
    assert "export ARNOLD_RUNTIME_MANIFEST_DIR=/workspace/demo-clean1/.megaplan" in command


def test_fresh_continuation_cloud_spec_uses_unique_workspace_root() -> None:
    from arnold_pipelines.megaplan.cloud.spec import load_spec

    path = (
        Path(__file__).parents[2]
        / ".megaplan/initiatives/native-build-forward-main-continuation-20260904/cloud.yaml"
    )
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    spec = load_spec(path)
    assert spec.ssh is not None
    # The checked-in continuation spec is authoritative for both the host
    # mount and the candidate-bound project root.  Keep this assertion tied
    # to that contract rather than baking in a superseded run's path.
    assert spec.ssh.workspace_dir == raw["ssh"]["workspace_dir"]
    assert spec.repo.workspace == raw["repo"]["workspace"]
    assert spec.repo.workspace != spec.megaplan.src_path
    assert spec.repo.workspace.startswith("/workspace/")
    assert spec.ssh.workspace_dir.rstrip("/").endswith(spec.ssh.container)
    assert spec.resources.volume is None


def test_chain_runtime_probe_uses_reviewed_source_wrapper_over_stale_installed_bin(
    tmp_path: Path,
) -> None:
    """A stale image wrapper must not get a chance to import an old runtime."""
    source = tmp_path / "reviewed-source"
    source.mkdir()
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "branch", "-M", "main"], check=True)
    package = source / "arnold_pipelines"
    package.mkdir()
    (package / "__init__.py").write_text("__version__ = 'reviewed'\n")
    wrapper = (
        source / "arnold_pipelines" / "megaplan" / "cloud" / "wrappers"
        / "arnold-runtime-create"
    )
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text(
        "#!/bin/sh\n"
        "printf source-wrapper > \"$SOURCE_MARKER\"\n"
        "cat > \"$ARNOLD_RUNTIME_MANIFEST_DIR/$1.json\" <<'JSON'\n"
        '{"runtime_id":"demo-1","schema":"1","generation":1,'
        '"epic_id":"demo","state":"active","owner":"test",'
        '"base":{},"epic":{"branch":"fixer/demo","worktree_path":"/tmp/runtime",'
        '"venv_path":"/tmp","runtime_root":"/tmp/runtime",'
        '"expected_head":"0000000000000000000000000000000000000000",'
        '"repair_bin":"/tmp/repair","deps_lockfile":"/tmp/uv.lock"},'
        '"indirection":{},"policy":{},"promotions":[],"timestamps":{},'
        '"gc_policy":{},"commands":[]}\n'
        "JSON\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(
        [
            "git", "-C", str(source), "-c", "user.name=test",
            "-c", "user.email=test@example.invalid", "commit", "-qm",
            "reviewed source",
        ],
        check=True,
    )
    stale_bin = tmp_path / "stale-bin"
    stale_bin.mkdir()
    stale_marker = tmp_path / "stale-wrapper-used"
    (stale_bin / "arnold-runtime-create").write_text(
        f"#!/bin/sh\nprintf stale > {shlex.quote(str(stale_marker))}\nexit 99\n",
        encoding="utf-8",
    )
    (stale_bin / "arnold-runtime-create").chmod(0o755)
    source_marker = tmp_path / "source-wrapper-used"
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir()
    manifest = manifest_dir / "demo.json"
    command = _chain_runtime_probe_and_create_command(
        slug="demo", manifest_path=str(manifest), runtime_src="/tmp/runtime",
        manifest_dir=str(manifest_dir), base_repo=str(source), base_ref="main",
        policy_path=None, runtime_python=sys.executable,
    )
    assert 'CREATE_BIN="$CREATE_SOURCE/arnold_pipelines/megaplan/cloud/wrappers/arnold-runtime-create"' in command
    assert "/usr/local/bin/arnold-runtime-create" not in command
    assert "command -v python3" not in command
    result = subprocess.run(
        ["bash", "-c", command], capture_output=True, text=True,
        env={
            **os.environ,
            "PATH": f"{stale_bin}:{os.environ['PATH']}",
            "SOURCE_MARKER": str(source_marker),
            "PYTHONPATH": str(tmp_path / "missing-ambient-python"),
        },
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert source_marker.read_text() == "source-wrapper"
    assert not stale_marker.exists()
    assert json.loads(result.stdout)["epic_id"] == "demo"


    def run_probe(python: str | None) -> subprocess.CompletedProcess[str]:
        probe = _chain_runtime_probe_and_create_command(
            slug="demo", manifest_path=str(manifest), runtime_src="/tmp/runtime",
            manifest_dir=str(manifest_dir), base_repo=str(source), base_ref="main",
            policy_path=None, runtime_python=python,
        )
        return subprocess.run(
            ["bash", "-c", probe], capture_output=True, text=True,
            env={
                **os.environ,
                "PATH": f"{stale_bin}:{os.environ['PATH']}",
                "SOURCE_MARKER": str(source_marker),
                "PYTHONPATH": str(tmp_path / "missing-ambient-python"),
            },
            check=False,
        )

    for dirty_path, staged in (
        (source / "arnold_pipelines" / "dirty.py", False),
        (source / "arnold_pipelines" / "dirty.py", True),
        (source / "untracked.txt", False),
    ):
        dirty_path.write_text("dirty\n", encoding="utf-8")
        if staged:
            subprocess.run(["git", "-C", str(source), "add", str(dirty_path)], check=True)
        dirty_result = run_probe(sys.executable)
        assert dirty_result.returncode == 78
        assert "chain_runtime_source_dirty" in dirty_result.stderr
        subprocess.run(["git", "-C", str(source), "reset", "--hard", "-q"], check=True)
        subprocess.run(["git", "-C", str(source), "clean", "-fdq"], check=True)

    for missing_python in (None, str(tmp_path / "missing-python")):
        interpreter_result = run_probe(missing_python)
        assert interpreter_result.returncode == 78
        assert "chain_runtime_wrapper_interpreter_unavailable" in interpreter_result.stderr


def test_chain_runtime_probe_pins_canonical_origin_and_partial_recovery_guards() -> None:
    command = _chain_runtime_probe_and_create_command(
        slug="demo-abc123",
        manifest_path="/workspace/.megaplan/demo-abc123.json",
        runtime_src="/workspace/runtime-candidates/demo-abc123",
        manifest_dir="/workspace/.megaplan",
        base_repo="/workspace/arnold",
        base_ref="main",
        policy_path=None,
        canonical_origin_url="https://github.com/example/Arnold.git",
        chain_state_path="/workspace/chain/.megaplan/plans/.chains/demo.json",
        marker_path="/workspace/.megaplan/cloud-sessions/demo.json",
        session_name="demo",
    )
    assert "export ARNOLD_CANONICAL_ORIGIN_URL=https://github.com/example/Arnold.git" in command
    assert "chain runtime recovery refused" in command
    assert '"${CHAIN_STATE:-}"' in command
    assert "liveness-lease.json" in command
    # Existing partial runtimes go through the same guarded create wrapper;
    # the wrapper's idempotent path verifies instead of recreating them.
    assert command.count('"$CREATE_BIN" "$SLUG" "$BASE_REF"') == 2


def test_chain_runtime_probe_and_create_command_omits_policy_without_sidecar() -> None:
    command = _chain_runtime_probe_and_create_command(
        slug="demo-abc123",
        manifest_path="/workspace/.megaplan/demo-abc123.json",
        runtime_src="/workspace/runtime-candidates/demo-abc123",
        manifest_dir="/workspace/.megaplan",
        base_repo="/workspace/arnold",
        base_ref="editible-install",
        policy_path=None,
    )
    assert "ARNOLD_RUNTIME_POLICY" not in command


def test_chain_runtime_policy_upload_ships_existing_sidecar(tmp_path: Path) -> None:
    from arnold_pipelines.megaplan.chain.spec import _runtime_policy_path_for

    project = tmp_path / "app"
    spec_dir = project / ".megaplan" / "initiatives" / "demo"
    spec_dir.mkdir(parents=True)
    spec_path = spec_dir / "chain.yaml"
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    sidecar = _runtime_policy_path_for(spec_path)
    sidecar.parent.mkdir(parents=True)
    sidecar.write_text(
        json.dumps({"permits": [{"kind": "allow_manifestless", "id": "perm-1"}]}),
        encoding="utf-8",
    )

    uploads: list[tuple[Path, str]] = []

    class CaptureProvider:
        def upload_file(self, src: Path, dest: str) -> None:
            uploads.append((src, dest))

    remote = _chain_runtime_policy_upload(
        spec_path,
        workspace="/workspace/demo/app",
        provider=CaptureProvider(),
    )

    # the sidecar travels to the box so arnold-runtime-create can stamp an
    # allow_manifestless permit into the created manifest (P1 producer routing)
    assert remote == f"/workspace/demo/app/.megaplan/plans/.chains/{sidecar.name}"
    assert uploads == [(sidecar, remote)]


def test_chain_runtime_policy_upload_skips_without_sidecar(tmp_path: Path) -> None:
    spec_dir = tmp_path / ".megaplan" / "initiatives" / "demo"
    spec_dir.mkdir(parents=True)
    spec_path = spec_dir / "chain.yaml"
    spec_path.write_text("milestones: []\n", encoding="utf-8")

    uploads: list[tuple[Path, str]] = []

    class CaptureProvider:
        def upload_file(self, src: Path, dest: str) -> None:
            uploads.append((src, dest))

    remote = _chain_runtime_policy_upload(
        spec_path,
        workspace="/workspace/demo/app",
        provider=CaptureProvider(),
    )

    assert remote is None
    assert uploads == []


def test_manifest_runtime_activate_command_exports_binding_env() -> None:
    command = _manifest_runtime_activate_command(_runtime_binding())
    # the launch env is bound to the created runtime's manifest path only
    # (G1: no global-pointer fallback; G4: no SRC selector transport)
    assert 'export ARNOLD_RUNTIME_MANIFEST="$MANIFEST"' in command
    assert "MEGAPLAN_LAUNCH_RUNTIME_SRC" not in command
    assert "MEGAPLAN_LAUNCH_RUNTIME_REVISION" not in command
    assert "MEGAPLAN_RUNTIME_SRC" not in command
    assert "/workspace/runtime-candidates/demo-abc123" in command
    # fail closed when the bound runtime disappeared
    assert "exit 23" in command
    assert "manifest-bound runtime worktree missing" in command


def test_refresh_then_chain_start_command_uses_activate_when_bound() -> None:
    command = _refresh_then_chain_start_command(
        "/workspace/chain/.megaplan/initiatives/demo/chain.yaml",
        spec=_cloud_spec(),
        project_dir="/workspace/chain",
        log_relative=".megaplan/cloud-chain.log",
        runtime_binding=_runtime_binding(),
    )
    # manifest-bound runtime: the editable-install refresh is skipped
    assert "activating manifest-bound runtime" in command
    assert (
        'MEGAPLAN_TRUSTED_CONTAINER=1 "$GEN_INTERPRETER" -P -m '
        "arnold_pipelines.megaplan chain start"
    ) in command
    assert "megaplan-refresh" not in command
    assert "pip install -e" not in command
    assert 'export ARNOLD_RUNTIME_MANIFEST="$MANIFEST"' in command


def test_parse_chain_runtime_binding_accepts_binding_record() -> None:
    payload = {
        "present": True,
        "created": 1,
        "epic_id": "demo-abc123",
        "runtime_id": "demo-abc123-20260810",
        "runtime_src": "/workspace/runtime-candidates/demo-abc123",
        "runtime_source": "/workspace/runtime-candidates/demo-abc123",
        "runtime_revision": "a" * 40,
        "manifest_path": "/workspace/.megaplan/demo-abc123.json",
        "manifest_sha256": "c" * 64,
        "manifest_identity": "c" * 64,
        "runtime_identity": {
            "import_root": "/workspace/runtime-candidates/demo-abc123",
            "source_revision": "a" * 40,
            "editable_root": "",
            "editable_revision": "",
            "direct_url": {},
            "pth": [],
            "imports": {},
            "content_sha256": "b" * 64,
        },
        "runtime_identity_raw": {
            "runtime_id": "demo-abc123-20260810",
            "epic_id": "demo-abc123",
            "runtime_source": "/workspace/runtime-candidates/demo-abc123",
            "runtime_revision": "a" * 40,
        },
    }
    result = subprocess.CompletedProcess([], 0, json.dumps(payload) + "\n", "")
    binding = _parse_chain_runtime_binding(
        result,
        slug="demo-abc123",
    )
    assert binding["runtime_revision"] == "a" * 40
    assert binding["runtime_src"] == "/workspace/runtime-candidates/demo-abc123"
    assert binding["created"] is True
    assert binding["runtime_identity"]["source_revision"] == "a" * 40


def test_parse_chain_runtime_binding_rejects_unreadable_output() -> None:
    result = subprocess.CompletedProcess([], 0, "", "")
    with pytest.raises(CliError) as excinfo:
        _parse_chain_runtime_binding(
            result,
            slug="demo-abc123",
        )
    assert excinfo.value.code == "chain_runtime_probe_unreadable"


def test_parse_chain_runtime_binding_rejects_epic_mismatch() -> None:
    payload = {
        "present": True,
        "epic_id": "other-epic",
        "runtime_revision": "a" * 40,
    }
    result = subprocess.CompletedProcess([], 0, json.dumps(payload) + "\n", "")
    with pytest.raises(CliError) as excinfo:
        _parse_chain_runtime_binding(
            result,
            slug="demo-abc123",
        )
    assert excinfo.value.code == "chain_runtime_epic_mismatch"


def test_parse_chain_runtime_binding_rejects_missing_runtime_src() -> None:
    """G6 round-9 finding 2: a binding record without ``runtime_src`` fails
    closed (typed ``chain_runtime_manifest_incomplete``) — there is NO
    default runtime source fallback. Only the manifest's own
    ``epic.runtime_root`` is ever used."""
    payload = {
        "present": True,
        "created": 1,
        "epic_id": "demo-abc123",
        "runtime_id": "demo-abc123-20260810",
        # runtime_src deliberately absent
        "runtime_revision": "a" * 40,
    }
    result = subprocess.CompletedProcess([], 0, json.dumps(payload) + "\n", "")
    with pytest.raises(CliError) as excinfo:
        _parse_chain_runtime_binding(
            result,
            slug="demo-abc123",
        )
    assert excinfo.value.code == "chain_runtime_manifest_incomplete"
    assert "no epic.runtime_root" in excinfo.value.message


def test_parse_chain_runtime_binding_rejects_empty_runtime_src() -> None:
    """An empty-string ``runtime_src`` is the same fail-closed state as an
    absent one — never a silent default."""
    payload = {
        "present": True,
        "epic_id": "demo-abc123",
        "runtime_src": "",
        "runtime_revision": "a" * 40,
    }
    result = subprocess.CompletedProcess([], 0, json.dumps(payload) + "\n", "")
    with pytest.raises(CliError) as excinfo:
        _parse_chain_runtime_binding(
            result,
            slug="demo-abc123",
        )
    assert excinfo.value.code == "chain_runtime_manifest_incomplete"
    assert "no epic.runtime_root" in excinfo.value.message


def _run_binding_reader(
    manifest_path: Path, *, created: int = 0
) -> subprocess.CompletedProcess[str]:
    from arnold_pipelines.megaplan.cloud import cli as cloud_cli

    return subprocess.run(
        [sys.executable, "-", str(manifest_path), str(created)],
        input=cloud_cli._RUNTIME_MANIFEST_BINDING_READER,
        capture_output=True,
        text=True,
        check=False,
    )


def test_runtime_binding_reader_emits_binding_for_canonical_manifest(
    tmp_path: Path,
) -> None:
    """The box-side probe reader prints a binding record ONLY for a
    canonically schema-valid per-epic manifest (schema "1" + required key
    sets), and the record's ``runtime_src`` is the manifest's own
    ``epic.runtime_root``."""
    runtime_root = tmp_path / "accepted-runtime"
    runtime_root.mkdir()
    manifest = _write_runtime_manifest(
        tmp_path / "manifest.json",
        runtime_root=runtime_root,
        revision="a" * 40,
    )

    result = _run_binding_reader(manifest)

    assert result.returncode == 0, result.stderr
    binding = json.loads(result.stdout)
    assert binding["present"] is True
    assert binding["runtime_src"] == str(runtime_root)
    assert binding["runtime_revision"] == "a" * 40
    assert binding["runtime_identity"]["import_root"] == str(runtime_root)
    assert binding["runtime_identity"]["source_revision"] == "a" * 40
    assert len(binding["runtime_identity"]["content_sha256"]) == 64


@pytest.mark.parametrize(
    ("case", "payload"),
    [
        (
            "schema-less-raw-fields",
            {
                "epic_id": "pincheck-epic",
                "epic": {
                    "runtime_root": "/workspace/runtime-candidates/demo",
                    "expected_head": "a" * 40,
                },
            },
        ),
        (
            "wrong-schema-version",
            dict(
                _canonical_manifest_payload(
                    "/workspace/runtime-candidates/demo", expected_head="a" * 40
                ),
                schema="2",
            ),
        ),
        (
            "missing-top-level-required",
            {
                key: value
                for key, value in _canonical_manifest_payload(
                    "/workspace/runtime-candidates/demo", expected_head="a" * 40
                ).items()
                if key != "state"
            },
        ),
        (
            "missing-epic-required",
            dict(
                _canonical_manifest_payload(
                    "/workspace/runtime-candidates/demo", expected_head="a" * 40
                ),
                epic={
                    "runtime_root": "/workspace/runtime-candidates/demo",
                    "expected_head": "a" * 40,
                },
            ),
        ),
    ],
)
def test_runtime_binding_reader_rejects_schema_invalid_manifest_fail_closed(
    tmp_path: Path, case: str, payload: dict[str, object]
) -> None:
    """G6 round-9 finding 2: a PRESENT-but-schema-invalid per-epic manifest
    at the box-side probe read must fail closed — non-zero exit and NO raw
    fields on stdout (no binding record), so the calling ``set -e`` probe
    aborts and the launch fails loudly instead of using raw fields."""
    manifest = tmp_path / f"{case}.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    result = _run_binding_reader(manifest)

    assert result.returncode != 0, case
    assert result.stdout.strip() == "", case
    assert "schema-invalid" in result.stderr, case


def test_chain_runtime_probe_and_create_command_reader_is_schema_gated() -> None:
    """The probe/create command's embedded binding reader must carry the
    canonical schema gate (generated from runtime_manifest's own constants),
    so a present-but-schema-invalid manifest on the box can never yield raw
    fields."""
    command = _chain_runtime_probe_and_create_command(
        slug="demo-abc123",
        manifest_path="/workspace/.megaplan/demo-abc123.json",
        runtime_src="/workspace/runtime-candidates/demo-abc123",
        manifest_dir="/workspace/.megaplan",
        base_repo="/workspace/arnold",
        base_ref="editible-install",
        policy_path=None,
    )
    assert 'd.get("schema")' in command
    assert "TOP_LEVEL_REQUIRED" in command
    assert "EPIC_REQUIRED" in command
    assert "MANIFEST_SCHEMA_VERSION" in command
    assert "refusing to read raw fields" in command
    assert "sys.exit(24)" in command


def test_chain_runtime_provenance_payload_records_bound_manifest() -> None:
    payload = _chain_runtime_provenance_payload(
        _runtime_binding(created=True, policy_path="/workspace/chain/.megaplan/plans/.chains/demo.runtime_policy.json"),
        policy_path="/workspace/chain/.megaplan/plans/.chains/demo.runtime_policy.json",
    )
    # launch provenance: the session marker records the exact manifest path
    # this launch is bound to (G1 per-session binding)
    assert payload["binding"] == "manifest_bound"
    assert payload["path"] == "/workspace/.megaplan/demo-abc123.json"
    assert payload["runtime_src"] == "/workspace/runtime-candidates/demo-abc123"
    assert payload["expected_head"] == "a" * 40
    assert payload["created_by_launch"] is True
    assert payload["policy_path"].endswith("demo.runtime_policy.json")


def test_chain_runtime_marker_binding_publishes_canonical_identity() -> None:
    marker_binding = _chain_runtime_marker_binding(_runtime_binding())
    assert marker_binding["schema"] == "arnold.megaplan.marker_runtime_binding.v1"
    assert marker_binding["current_identity"]["import_root"] == (
        "/workspace/runtime-candidates/demo-abc123"
    )
    assert marker_binding["current_identity"]["source_revision"] == "a" * 40


def test_chain_runtime_marker_binding_rejects_missing_identity() -> None:
    with pytest.raises(CliError, match="canonical runtime identity"):
        _chain_runtime_marker_binding(_runtime_binding(runtime_identity=None))


def test_preflight_phase_model_materialization_preserves_profile_tier_routing() -> None:
    result = _phase_model_by_label_from_preflight(
        {
            "milestones": [
                {
                    "label": "m1",
                    "profile": "premium",
                    "explicit_phase_model": [],
                    "resolved_phase_map": {
                        "execute": "codex:gpt-5.4",
                        "plan": "codex:high",
                    },
                }
            ]
        }
    )

    assert result == {}


def test_preflight_phase_model_materialization_keeps_explicit_profile_pins() -> None:
    result = _phase_model_by_label_from_preflight(
        {
            "milestones": [
                {
                    "label": "m1",
                    "profile": "premium",
                    "explicit_phase_model": ["prep=omp:deepseek/deepseek-v4-pro"],
                    "resolved_phase_map": {
                        "execute": "codex:gpt-5.4",
                        "prep": "omp:deepseek/deepseek-v4-pro",
                    },
                }
            ]
        }
    )

    assert result == {"m1": ["prep=omp:deepseek/deepseek-v4-pro"]}


def test_preflight_phase_model_materialization_keeps_cloud_default_without_profile() -> None:
    result = _phase_model_by_label_from_preflight(
        {
            "milestones": [
                {
                    "label": "m1",
                    "profile": None,
                    "explicit_phase_model": [],
                    "resolved_phase_map": {
                        "execute": "codex:medium",
                        "plan": "codex:high",
                    },
                }
            ]
        }
    )

    assert result == {"m1": ["execute=codex:medium", "plan=codex:high"]}


def test_preflight_phase_model_materialization_preserves_explicit_encoded_chain_without_profile() -> None:
    encoded_execute = encode_phase_model_value(
        "execute",
        ["codex:gpt-5.4", "claude:sonnet"],
    )

    result = _phase_model_by_label_from_preflight(
        {
            "milestones": [
                {
                    "label": "m1",
                    "profile": None,
                    "explicit_phase_model": [encoded_execute],
                    "resolved_phase_chains": {
                        "plan": ["codex:high"],
                        "execute": ["codex:gpt-5.4", "claude:sonnet"],
                    },
                    "resolved_phase_map": {
                        "plan": "codex:high",
                        "execute": "codex:gpt-5.4",
                    },
                }
            ]
        }
    )

    assert result == {"m1": [encoded_execute, "plan=codex:high"]}


def test_launch_epic_rejects_missing_north_star(tmp_path: Path) -> None:
    app = tmp_path / "app"
    brief_dir = app / ".megaplan" / "initiatives" / "demo"
    brief_dir.mkdir(parents=True)
    subprocess.run(["git", "init"], cwd=app, check=True, capture_output=True, text=True)
    (brief_dir / "m1.md").write_text("M1\n", encoding="utf-8")

    with pytest.raises(Exception) as excinfo:
        _materialize_canonical_epic_input(
            root=tmp_path,
            spec=_cloud_spec(),
            spec_or_dir=str(brief_dir),
        )

    assert getattr(excinfo.value, "code", "") == "missing_north_star"
    assert "NORTHSTAR.md" in getattr(excinfo.value, "message", str(excinfo.value))


def test_launch_epic_rejects_noncanonical_before_materialization_or_filesystem_delta(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = tmp_path / "app"
    brief_dir = app / ".megaplan" / "initiatives" / "incoming"
    brief_dir.mkdir(parents=True)
    subprocess.run(["git", "init"], cwd=app, check=True, capture_output=True, text=True)
    (brief_dir / "NORTHSTAR.md").write_text("North star\n", encoding="utf-8")
    (brief_dir / "m1.md").write_text("M1\n", encoding="utf-8")
    before = sorted(
        (path.relative_to(tmp_path), path.read_bytes())
        for path in tmp_path.rglob("*")
        if path.is_file()
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.cli._materialize_canonical_epic_input",
        lambda **_kwargs: pytest.fail("rejected launch must not materialize input"),
    )

    with pytest.raises(CliError) as excinfo:
        _run_launch_epic_wrapper(
            tmp_path,
            argparse.Namespace(
                spec_or_dir=str(brief_dir),
                slug=None,
                fresh=False,
                no_git_refresh=True,
                cloud_yaml=str(app / "cloud.yaml"),
                prepare_only=False,
            ),
            _cloud_spec(),
            SimpleNamespace(),
        )

    assert excinfo.value.code == "chain_spec_not_canonical"
    after = sorted(
        (path.relative_to(tmp_path), path.read_bytes())
        for path in tmp_path.rglob("*")
        if path.is_file()
    )
    assert after == before


def test_chain_rejects_noncanonical_before_materialization_or_filesystem_delta(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = tmp_path / "app"
    brief_dir = app / ".megaplan" / "initiatives" / "incoming"
    brief_dir.mkdir(parents=True)
    subprocess.run(["git", "init"], cwd=app, check=True, capture_output=True, text=True)
    (brief_dir / "NORTHSTAR.md").write_text("North star\n", encoding="utf-8")
    (brief_dir / "m1.md").write_text("M1\n", encoding="utf-8")
    before = sorted(
        (path.relative_to(tmp_path), path.read_bytes())
        for path in tmp_path.rglob("*")
        if path.is_file()
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.cli._materialize_canonical_epic_input",
        lambda **_kwargs: pytest.fail("rejected launch must not materialize input"),
    )

    with pytest.raises(CliError) as excinfo:
        _run_chain_wrapper(
            tmp_path,
            argparse.Namespace(
                spec=str(brief_dir),
                idea_dir=None,
                prepare_only=False,
                allow_loose_chain_spec=False,
            ),
            _cloud_spec(),
            SimpleNamespace(),
        )

    assert excinfo.value.code == "chain_spec_not_canonical"
    after = sorted(
        (path.relative_to(tmp_path), path.read_bytes())
        for path in tmp_path.rglob("*")
        if path.is_file()
    )
    assert after == before


def test_public_cloud_chain_rejects_noncanonical_before_deploy_cache_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home = tmp_path / "isolated-home"
    monkeypatch.setenv("HOME", str(home))
    project = tmp_path / "project"
    project.mkdir()
    loose = project / "incoming-chain.yaml"
    loose.write_text(
        "milestones:\n  - label: m1\n    idea: idea.md\n",
        encoding="utf-8",
    )
    before = {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.cli._load_cloud_spec",
        lambda *_args: _cloud_spec(),
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.cli._provider_for_action",
        lambda *_args: SimpleNamespace(),
    )

    args = _cloud_parser().parse_args(
        ["cloud", "chain", str(loose), "--cloud-yaml", str(project / "cloud.yaml")]
    )
    rc = run_cloud_cli(project, args)
    captured = capsys.readouterr()
    output = captured.out + captured.err

    assert rc == 1
    assert "chain_spec_not_canonical" in output
    assert not home.exists()
    assert {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()} == before


def test_public_cloud_launch_epic_rejects_noncanonical_before_deploy_cache_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home = tmp_path / "isolated-home"
    monkeypatch.setenv("HOME", str(home))
    project = tmp_path / "project"
    loose = project / "incoming-epic"
    loose.mkdir(parents=True)
    (loose / "NORTHSTAR.md").write_text("North star\n", encoding="utf-8")
    (loose / "m1.md").write_text("M1\n", encoding="utf-8")
    before = {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.cli._load_cloud_spec",
        lambda *_args: _cloud_spec(),
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.cli._provider_for_action",
        lambda *_args: SimpleNamespace(),
    )

    args = _cloud_parser().parse_args(
        ["cloud", "launch-epic", str(loose), "--cloud-yaml", str(project / "cloud.yaml")]
    )
    rc = run_cloud_cli(project, args)
    captured = capsys.readouterr()
    output = captured.out + captured.err

    assert rc == 1
    assert "chain_spec_not_canonical" in output
    assert not home.exists()
    assert {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()} == before


def test_launch_epic_materializes_canonical_layout_from_brief_dir(tmp_path: Path) -> None:
    app = tmp_path / "app"
    brief_dir = app / "incoming" / "research-plan-execute-epic"
    brief_dir.mkdir(parents=True)
    subprocess.run(["git", "init"], cwd=app, check=True, capture_output=True, text=True)
    (brief_dir / "NORTHSTAR.md").write_text("North star\n", encoding="utf-8")
    (brief_dir / "m1-contracts.md").write_text("M1\n", encoding="utf-8")
    (brief_dir / "m2-routing.md").write_text("M2\n", encoding="utf-8")

    materialized = _materialize_canonical_epic_input(
        root=tmp_path,
        spec=_cloud_spec(),
        spec_or_dir=str(brief_dir),
    )

    assert materialized.generated_chain is True
    assert materialized.slug == "research-plan-execute-epic"
    assert materialized.spec_path == app / ".megaplan" / "initiatives" / "research-plan-execute-epic" / "chain.yaml"
    raw = yaml.safe_load(materialized.spec_path.read_text(encoding="utf-8"))
    assert raw["anchors"] == {"north_star": "NORTHSTAR.md"}
    assert raw["milestones"][0]["idea"] == ".megaplan/initiatives/research-plan-execute-epic/briefs/m1-contracts.md"
    assert (materialized.brief_dir / "NORTHSTAR.md").is_file()
    assert (materialized.brief_dir / "briefs" / "m2-routing.md").is_file()
    assert str(materialized.spec_path) in materialized.created_files


def test_canonical_launch_reuses_reviewed_bytes_without_mutating_source(tmp_path: Path) -> None:
    app = tmp_path / "app"
    initiative = app / ".megaplan" / "initiatives" / "demo"
    briefs = initiative / "briefs"
    briefs.mkdir(parents=True)
    subprocess.run(["git", "init"], cwd=app, check=True, capture_output=True, text=True)
    (initiative / "NORTHSTAR.md").write_text("North star\n", encoding="utf-8")
    (briefs / "m1.md").write_text("M1\n", encoding="utf-8")
    raw = {
        "base_branch": "main",
        "anchors": {"north_star": "NORTHSTAR.md"},
        "milestones": [{
            "label": "m1",
            "idea": ".megaplan/initiatives/demo/briefs/m1.md",
            "branch": "epic/demo/m1",
            "profile": "all-muse-spark-openrouter",
        }],
    }
    spec_path = initiative / "chain.yaml"
    spec_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    before = spec_path.read_bytes()

    materialized = _materialize_canonical_epic_input(
        root=tmp_path,
        spec=_cloud_spec(),
        spec_or_dir=str(spec_path),
    )

    assert materialized.spec_path == spec_path
    assert materialized.copied_files == []
    assert spec_path.read_bytes() == before
    assert not list(app.glob(".megaplan/initiatives/demo/chain.yaml.*"))


def test_noncanonical_reviewed_source_fails_before_any_write(tmp_path: Path) -> None:
    app = tmp_path / "app"
    initiative = app / ".megaplan" / "initiatives" / "demo"
    briefs = initiative / "briefs"
    briefs.mkdir(parents=True)
    subprocess.run(["git", "init"], cwd=app, check=True, capture_output=True, text=True)
    (initiative / "NORTHSTAR.md").write_text("North star\n", encoding="utf-8")
    (briefs / "m1.md").write_text("M1\n", encoding="utf-8")
    spec_path = initiative / "chain.yaml"
    spec_path.write_text(
        "base_branch: main\n"
        "anchors:\n  north_star: NORTHSTAR.md\n"
        "milestones:\n"
        "- label: m1\n"
        "  idea: .megaplan/initiatives/demo/briefs/m1.md\n"
        "  branch: epic/demo/m1\n"
        "  profile: all-muse-spark-openrouter\n"
        "driver:\n"
        "  execution_binding_assets:\n"
        "    - arnold_pipelines/megaplan/profiles/all-muse-spark-openrouter.toml\n",
        encoding="utf-8",
    )
    before = spec_path.read_bytes()

    with pytest.raises(CliError) as excinfo:
        _materialize_canonical_epic_input(
            root=tmp_path,
            spec=_cloud_spec(),
            spec_or_dir=str(spec_path),
        )

    assert excinfo.value.code == "chain_spec_not_canonical"
    assert spec_path.read_bytes() == before
    assert not (initiative / "reconcile.md").exists()


class _LaunchEpicProvider:
    def __init__(self) -> None:
        self.uploads: list[tuple[Path, str]] = []
        self.remote_files: set[str] = set()
        self.markers: dict[str, dict] = {}
        self.runtime_probe_calls = 0
        self.fresh_child_authority_context = None

    def bind_authority_context(self, context) -> None:
        assert callable(getattr(context, "read", None))
        self.fresh_child_authority_context = context

    def upload_file(self, src: Path, dest: str) -> None:
        self.uploads.append((src, dest))
        self.remote_files.add(dest)

    def invoke_launch_engine(self, request: dict) -> dict:
        self.launch_request = request
        return {
            "schema": "arnold.megaplan.cloud_launch_response.v1",
            "result": "ACCEPTED",
            "reason": "accepted",
        }

    def ssh_exec(self, command: str) -> subprocess.CompletedProcess[str]:
        if "MEGAPLAN_RESET" in command:
            return subprocess.CompletedProcess([], 0, "", "")
        if "MEGAPLAN_PRELAUNCH_MARKER_GUARD" in command:
            return subprocess.CompletedProcess(
                [],
                0,
                json.dumps(
                    {
                        "session_alive": False,
                        "marker_present": False,
                        "identity_matches": False,
                        "marker_read_error": "",
                    }
                )
                + "\n",
                "",
            )
        if "MEGAPLAN_WATCHDOG_TRACKING" in command:
            marker = re.search(r"marker_path = pathlib\.Path\('([^']+)'\)", command).group(1)
            workspace = re.search(r"workspace = pathlib\.Path\('([^']+)'\)", command).group(1)
            remote_spec = re.search(r"remote_spec = pathlib\.Path\('([^']+)'\)", command).group(1)
            payload = self.markers.get(marker, {})
            errors = []
            if not payload:
                errors.append("marker missing")
            if remote_spec not in self.remote_files:
                errors.append("remote_spec missing")
            if payload.get("workspace") != workspace:
                errors.append("workspace mismatch")
            if payload.get("remote_spec") != remote_spec:
                errors.append("remote_spec mismatch")
            result = {
                "tracked": not errors,
                "errors": errors,
                "marker_path": marker,
                "workspace": workspace,
                "remote_spec": remote_spec,
                "session": payload.get("session"),
            }
            return subprocess.CompletedProcess([], 0 if result["tracked"] else 1, json.dumps(result) + "\n", "")
        if "MEGAPLAN_VERIFY" in command:
            result = {
                "session_alive": True,
                "advanced_past_init": True,
                "chain_log": "/workspace/log",
                "state_present": True,
                "plan_dirs": ["m1"],
            }
            return subprocess.CompletedProcess([], 0, json.dumps(result) + "\n", "")
        if "ARNOLD_RUNTIME_MANIFEST_DIR" in command:
            # P1 producer routing: the per-epic runtime probe/create command
            # must return one JSON binding record (see
            # _RUNTIME_MANIFEST_BINDING_READER). The test fakes a manifest
            # already present on the box.
            self.runtime_probe_calls += 1
            slug_match = re.search(r"SLUG='([^']+)'", command)
            slug = slug_match.group(1) if slug_match else "demo"
            binding = {
                "present": True,
                "created": 0,
                "epic_id": slug,
                "runtime_id": f"runtime-{slug}",
                "runtime_src": f"/workspace/runtime-candidates/{slug}",
                "runtime_source": f"/workspace/runtime-candidates/{slug}",
                "runtime_revision": "a" * 40,
                "manifest_path": f"/workspace/.megaplan/{slug}.json",
                "manifest_sha256": "c" * 64,
                "manifest_identity": "c" * 64,
                "runtime_identity": {
                    "import_root": f"/workspace/runtime-candidates/{slug}",
                    "source_revision": "a" * 40,
                    "editable_root": "",
                    "editable_revision": "",
                    "direct_url": {},
                    "pth": [],
                    "imports": {
                        "arnold": f"/workspace/runtime-candidates/{slug}/arnold/__init__.py",
                        "arnold_pipelines": f"/workspace/runtime-candidates/{slug}/arnold_pipelines/__init__.py",
                        "megaplan": f"/workspace/runtime-candidates/{slug}/arnold_pipelines/megaplan/__init__.py",
                    },
                    "content_sha256": "b" * 64,
                },
                "runtime_identity_raw": {
                    "runtime_id": f"runtime-{slug}",
                    "epic_id": slug,
                    "runtime_source": f"/workspace/runtime-candidates/{slug}",
                    "runtime_revision": "a" * 40,
                },
            }
            return subprocess.CompletedProcess([], 0, json.dumps(binding, sort_keys=True) + "\n", "")
        if "tmux new-session" in command or "session already running for this chain" in command:
            marker_path, marker_payload = _parse_marker_write(command)
            self.markers[marker_path] = marker_payload
            return subprocess.CompletedProcess([], 0, "started session\n", "")
        return subprocess.CompletedProcess([], 0, "", "")


def shlex_split_one(value: str) -> str:
    import shlex

    parsed = shlex.split(value)
    assert len(parsed) == 1
    return parsed[0]


def _parse_marker_write(command: str) -> tuple[str, dict]:
    marker_match = re.search(
        r"path = pathlib\.Path\((?P<path>'(?:\\'|[^'])*')\)\s+payload = json\.loads\((?P<payload>'(?:\\'|[^'])*')\)",
        command,
        re.DOTALL,
    )
    assert marker_match, command
    return ast.literal_eval(marker_match.group("path")), json.loads(ast.literal_eval(marker_match.group("payload")))


def test_launch_epic_end_to_end_uploads_canonical_spec_and_tracks_watchdog(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = tmp_path / "app"
    brief_dir = app / ".megaplan" / "initiatives" / "demo"
    brief_dir.mkdir(parents=True)
    subprocess.run(["git", "init"], cwd=app, check=True, capture_output=True, text=True)
    (brief_dir / "NORTHSTAR.md").write_text("North star\n", encoding="utf-8")
    (brief_dir / "m1.md").write_text("M1\n", encoding="utf-8")

    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli._ensure_repo_checkout", lambda *_a, **_k: None)
    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli._run_remote_dependency_check", lambda *_a, **_k: [])
    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli.seed_codex_oauth", lambda *_a, **_k: {"status": "skipped"})
    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli._remote_repo_head", lambda *_a, **_k: {"branch": "main", "head": "abc123"})
    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli._relay_output", lambda *_a, **_k: None)
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")

    provider = _LaunchEpicProvider()
    prepare_args = argparse.Namespace(
        spec_or_dir=str(brief_dir),
        slug=None,
        fresh=True,
        no_git_refresh=True,
        cloud_yaml=str(app / "cloud.yaml"),
        prepare_only=True,
    )
    assert _run_launch_epic_wrapper(tmp_path, prepare_args, _cloud_spec(), provider) == 0
    canonical_spec = app / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    assert canonical_spec.is_file()
    _attach_real_fresh_child_admission(app, canonical_spec)
    rc = _run_launch_epic_wrapper(
        tmp_path,
        argparse.Namespace(
            spec_or_dir=str(canonical_spec),
            slug=None,
            fresh=True,
            no_git_refresh=True,
            cloud_yaml=str(app / "cloud.yaml"),
            prepare_only=False,
        ),
        _cloud_spec(),
        provider,
    )

    assert rc == 0
    uploaded_remote_paths = {remote for _local, remote in provider.uploads}
    remote_spec = next(path for path in uploaded_remote_paths if path.endswith("/.megaplan/initiatives/demo/chain.yaml"))
    assert "/workspace/demo-" in remote_spec
    assert not provider.markers
    assert provider.launch_request["session"]
    assert provider.launch_request["envelope"]["launch_spec"]["operation_type"] == "megaplan_chain"
    assert provider.launch_request["envelope"]["launch_spec"]["expected_session_name"] == provider.launch_request["session"]
    binding = provider.launch_request["envelope"]["launch_spec"]["metadata"]["runtime_binding"]
    assert provider.runtime_probe_calls == 1
    assert binding["manifest_path"].startswith("/workspace/.megaplan/")
    assert len(binding["manifest_sha256"]) == 64
    assert binding["manifest_identity"] == binding["manifest_sha256"]
    assert binding["runtime_source"] == f"/workspace/runtime-candidates/demo"
    assert remote_spec in provider.remote_files


def test_composed_cli_on_box_chain_drive_dispatches_once_with_seed_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise the real CLI request through OnBox into chain_drive.

    Muse role/policy closure is already exhaustively pinned by
    ``test_continuation_runtime_binding.py``; this composition test focuses
    on carrying that launch's runtime seed through the direct dispatch path.
    """
    from arnold_pipelines.megaplan.cloud import chain_drive
    from arnold_pipelines.megaplan.cloud.providers.on_box import OnBoxProvider

    app = tmp_path / "app"
    brief_dir = app / ".megaplan" / "initiatives" / "demo"
    brief_dir.mkdir(parents=True)
    subprocess.run(["git", "init"], cwd=app, check=True, capture_output=True, text=True)
    (brief_dir / "NORTHSTAR.md").write_text("North star\n", encoding="utf-8")
    (brief_dir / "m1.md").write_text("M1\n", encoding="utf-8")
    (app / ".megaplan" / "profiles.toml").write_text(
        "[profiles.{}]\n".format(CONTINUATION_RUNTIME_PROFILE)
        + "".join(
            f'{phase} = "{CONTINUATION_RUNTIME_MODEL_SPEC}"\n'
            for phase in VALID_PHASE_KEYS
        ),
        encoding="utf-8",
    )
    materialized = _materialize_canonical_epic_input(
        root=tmp_path, spec=_cloud_spec(), spec_or_dir=str(brief_dir)
    )
    canonical = yaml.safe_load(materialized.spec_path.read_text(encoding="utf-8"))
    for milestone in canonical["milestones"]:
        milestone["profile"] = CONTINUATION_RUNTIME_PROFILE
    materialized.spec_path.write_text(
        yaml.safe_dump(canonical, sort_keys=False), encoding="utf-8"
    )
    _attach_real_fresh_child_admission(
        materialized.project_root,
        materialized.spec_path,
        chain_identity="cloud-composed-child",
    )

    runtime_root = (tmp_path / "runtime-candidate").resolve()
    runtime_root.mkdir()
    interpreter = tmp_path / "runtime-venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_text("#!/bin/sh\n", encoding="utf-8")
    interpreter.chmod(0o755)
    manifest_path = (tmp_path / "runtime-manifest.json").resolve()
    runtime_revision = "a" * 40
    manifest_payload = {
        "schema": "1",
        "runtime_id": "runtime-demo",
        "generation": 1,
        "epic_id": "demo",
        "state": "active",
        "owner": "test",
        "base": {"ref": "main", "commit": runtime_revision, "editable_install_path": "", "venv_path": ""},
        "epic": {
            "branch": "epic/demo",
            "worktree_path": str(runtime_root),
            "venv_path": "",
            "runtime_root": str(runtime_root),
            "expected_head": runtime_revision,
            "repair_bin": "",
            "deps_lockfile": "",
            "dependency_generation": {
                "id": "b" * 64,
                "frozen_spec_sha256": "b" * 64,
                "interpreter_path": str(interpreter),
                "venv_digest": "c" * 64,
                "created": "2026-01-01T00:00:00+00:00",
            },
        },
        "indirection": {
            "host_path": "", "container_path": "", "mount_table": [],
            "execution_namespace": "", "verified_head": "", "last_verified_at": "",
            "attestation": {"module_file": "", "module_digest": "", "mount_id": ""},
        },
        "policy": {"policy_sha": "", "model_policy_sha": "", "sync_policy": ""},
        "promotions": [],
        "timestamps": {"created": "", "updated": "", "closed": ""},
        "gc_policy": "",
        "commands": [],
    }
    manifest_path.write_text(json.dumps(manifest_payload), encoding="utf-8")
    manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    runtime_identity = chain_drive._canonical_runtime_identity(str(runtime_root), runtime_revision)
    raw_identity = {
        "runtime_id": "runtime-demo",
        "epic_id": "demo",
        "runtime_source": str(runtime_root),
        "runtime_revision": runtime_revision,
    }

    class ComposedProvider(_LaunchEpicProvider):
        def ssh_exec(self, command: str) -> subprocess.CompletedProcess[str]:
            result = super().ssh_exec(command)
            if "ARNOLD_RUNTIME_MANIFEST_DIR" not in command:
                return result
            payload = json.loads(result.stdout)
            payload.update(
                {
                    "runtime_id": "runtime-demo",
                    "runtime_src": str(runtime_root),
                    "runtime_source": str(runtime_root),
                    "runtime_revision": runtime_revision,
                    "manifest_path": str(manifest_path),
                    "manifest_sha256": manifest_sha,
                    "manifest_identity": manifest_sha,
                    "runtime_identity": runtime_identity,
                    "runtime_identity_raw": raw_identity,
                    "dependency_generation": manifest_payload["epic"]["dependency_generation"],
                }
            )
            return subprocess.CompletedProcess([], 0, json.dumps(payload) + "\n", "")

        def invoke_launch_engine(self, request: dict) -> dict:
            self.launch_request = request
            return OnBoxProvider.invoke_launch_engine(object.__new__(OnBoxProvider), request)

    provider = ComposedProvider()
    config = AgentBoxConfig(
        workspace_root=tmp_path,
        ops_store_root=tmp_path / "ops",
        runs_root=tmp_path / "runs",
        locks_root=tmp_path / "locks",
    )
    dispatches: list[list[str]] = []
    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli._ensure_repo_checkout", lambda *_a, **_k: None)
    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli._chain_runtime_manifest_dir", lambda: str(tmp_path))
    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli._chain_runtime_manifest_path", lambda _slug: str(manifest_path))
    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli._chain_runtime_worktree_path", lambda _slug: str(runtime_root))
    monkeypatch.setattr(chain_drive, "load_agentbox_config", lambda: config)
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", "/ambient/contradictory.json")
    monkeypatch.setattr(chain_drive, "run_tmux", lambda argv: dispatches.append(list(argv)))
    # This composition test uses a synthetic remote runtime fixture; the
    # dedicated launch-door tests cover the real live provenance probe.
    monkeypatch.setattr(chain_drive, "_validate_live_runtime", lambda binding: None)
    monkeypatch.setattr(chain_drive, "_probe_live_collision", lambda session: None)

    def observe(session: str, expected_identity=None) -> SessionStatus:
        assert expected_identity is not None
        return SessionStatus(
            session,
            "running",
            True,
            operation_id=expected_identity["ARNOLD_LAUNCH_OPERATION_ID"],
            request_id=expected_identity["ARNOLD_LAUNCH_REQUEST_ID"],
            envelope_digest=expected_identity["ARNOLD_LAUNCH_ENVELOPE_DIGEST"],
            process_session_identity=expected_identity["ARNOLD_LAUNCH_PROCESS_IDENTITY"],
            identity_available=True,
        )

    monkeypatch.setattr(chain_drive, "inspect_session", observe)
    assert _run_chain_wrapper(
        tmp_path,
        argparse.Namespace(
            spec=str(materialized.spec_path),
            idea_dir=str(materialized.project_root),
            prepare_only=False,
            allow_loose_chain_spec=False,
            _canonicalized_epic=True,
            _generated_canonical_files=[],
            one=False,
            no_git_refresh=True,
        ),
        _cloud_spec(),
        provider,
    ) == 0

    assert len(dispatches) == 1
    argv = dispatches[0]
    assert argv.count(f"ARNOLD_RUNTIME_MANIFEST={manifest_path}") == 1
    marker_path, marker = _parse_marker_write(argv[-1])
    assert marker_path
    marker_binding = marker["runtime_binding"]
    assert marker["bootstrap_manifest_path"] == str(manifest_path)
    assert marker["manifest_sha256"] == manifest_sha
    assert marker["manifest_identity"] == manifest_sha
    assert marker_binding["manifest_identity"] == manifest_sha
    assert marker_binding["manifest_sha256"] == manifest_sha
    assert marker_binding["current_identity"] == runtime_identity
    assert marker_binding["raw_identity"] == raw_identity
    assert marker_binding["seed_identity"] == manifest_sha
    assert marker["progress_artifact"] == str(
        Path(provider.launch_request["envelope"]["launch_spec"]["cwd"])
        / ".megaplan"
        / f"cloud-chain-{provider.launch_request['session']}.log"
    )
    marker_policy = marker_binding["model_policy"]
    assert marker_policy["route"] == "omp:openrouter/meta/muse-spark-1.3-contributor:high"
    assert marker_policy["fallback"] is False
    assert set(marker_policy["roles"]) == {
        "babysitter", "fixer", "controller", "researcher", "oracle", "superfixer"
    }
    assert set(marker_policy["roles"].values()) == {
        "omp:openrouter/meta/muse-spark-1.3-contributor:high"
    }
    envelope_binding = provider.launch_request["envelope"]["launch_spec"]["metadata"]["runtime_binding"]
    assert envelope_binding["manifest_path"] == str(manifest_path)
    assert envelope_binding["manifest_identity"] == manifest_sha
    attestation = provider.launch_request["envelope"]["launch_spec"]["metadata"]["launch_attestation"]
    assert attestation["seed_identity"] == manifest_sha
    assert attestation["manifest_identity"] == manifest_sha


def test_remote_chain_upload_path_anchors_relative_initiatives_to_workspace() -> None:
    path = _remote_chain_upload_path(
        ".megaplan/initiatives/god-file-splits/briefs/m1.md",
        source_workspace="/workspace",
        target_workspace="/workspace/vibecomfy-god-file-splits",
    )

    assert path == "/workspace/vibecomfy-god-file-splits/.megaplan/initiatives/god-file-splits/briefs/m1.md"


def test_remote_chain_workspace_path_preserves_spec_relative_path() -> None:
    path = _remote_chain_workspace_path(
        Path("/workspace/.megaplan/initiatives/god-file-splits/chain.yaml"),
        local_root=Path("/workspace"),
        target_workspace="/workspace/vibecomfy-god-file-splits",
    )

    assert path == "/workspace/vibecomfy-god-file-splits/.megaplan/initiatives/god-file-splits/chain.yaml"


def test_bootstrap_launch_command_writes_plan_marker_and_relaunch_command() -> None:
    command = _bootstrap_launch_command(
        workspace="/workspace/vibecomfy-per-workflow-window-chat-20260628",
        remote_idea_path="/workspace/vibecomfy-per-workflow-window-chat-20260628/idea.txt",
        plan_name="per-workflow-window-chat-cloud-20260628",
        robustness="full",
        session_name="vibecomfy-per-workflow-window-chat",
    )

    assert "/workspace/.megaplan/cloud-sessions/vibecomfy-per-workflow-window-chat.json" in command
    assert '"run_kind": "plan"' in command
    assert '"plan_name": "per-workflow-window-chat-cloud-20260628"' in command
    # T-0301: auto/init launch under the generation interpreter.  The
    # relaunch command embedded in the marker payload is JSON-escaped twice
    # (heredoc + json.dumps), so its quotes appear as \\" inside the emitted
    # command.
    assert (
        '\\\\"$GEN_INTERPRETER\\\\" -P -m arnold_pipelines.megaplan auto '
        "--plan per-workflow-window-chat-cloud-20260628"
    ) in command
    assert (
        '"$GEN_INTERPRETER" -P -m arnold_pipelines.megaplan init --project-dir '
        "/workspace/vibecomfy-per-workflow-window-chat-20260628"
    ) in command
    assert "--name per-workflow-window-chat-cloud-20260628" in command
    # T-0021: bootstrap is manifest-bound with no megaplan.src_path read and
    # no /workspace/arnold fallback; the pin must be enforced before init.
    assert "isolated_chain_runtime_binding_drift" in command
    assert 'PYTHONPATH="$ENGINE_DIR"' in command
    assert 'PYTHONPATH="/workspace/arnold' not in command
    assert "PYTHONPATH=/workspace/arnold" not in command
    assert command.index("isolated_chain_runtime_binding_drift") < command.index(
        "arnold_pipelines.megaplan init"
    )
    # G5 round-2 finding 1: the pin gate runs BEFORE the session-marker write
    # — a missing/unreadable pin exits 24 with zero marker side effects.
    assert command.index("isolated_chain_runtime_binding_drift") < command.index(
        '"relaunch_command"'
    )
    # G5 round-6 finding 1a: the pin gate is the FIRST side-effecting
    # statement — the mkdir -p for the marker dir + cloud-logs runs only
    # after the missing/unreadable pin checks, so a missing pin exits 24
    # with ZERO dir-creation side effects.
    assert command.index(
        'if [ -z "$PINNED_RUNTIME_MANIFEST" ]; then'
    ) < command.index("mkdir -p")
    assert command.index(
        'if [ ! -r "$PINNED_RUNTIME_MANIFEST" ]; then'
    ) < command.index("mkdir -p")
    # The relaunch command embedded in the marker carries the same pin gate.
    assert "relaunch_command" in command
    # The embedded relaunch (the whole launch shell command, JSON-escaped in
    # the marker payload) carries the same canonical-gated pin.
    relaunch_embedded = command.split("relaunch_command", 1)[1]
    assert "isolated_chain_runtime_binding_drift" in relaunch_embedded
    # JSON-escaped in the marker payload, so assert the engine pin fragments.
    assert "ENGINE_DIR" in relaunch_embedded
    assert "arnold_pipelines.megaplan auto" in relaunch_embedded


def test_run_bootstrap_wrapper_writes_marker_using_repo_named_session(tmp_path: Path, monkeypatch) -> None:
    idea_file = tmp_path / "idea.txt"
    idea_file.write_text("Per workflow window chat", encoding="utf-8")
    commands: list[str] = []
    uploads: list[tuple[Path, str]] = []
    archive_names: list[str] = []

    class CaptureProvider:
        def upload_file(self, src: Path, dest: str) -> None:
            uploads.append((src, dest))

        def upload_archive(self, src: Path, dest_dir: str) -> None:
            uploads.append((src, dest_dir))
            with tarfile.open(src, "r:gz") as tar:
                archive_names.extend(sorted(tar.getnames()))

        def ssh_exec(self, command: str) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            return subprocess.CompletedProcess(args=["ssh"], returncode=0, stdout="", stderr="")

    spec = SimpleNamespace(
        repo=SimpleNamespace(
            url="https://github.com/example/vibecomfy-per-workflow-window-chat.git",
            workspace="/workspace/vibecomfy-per-workflow-window-chat-20260628",
        ),
        megaplan=SimpleNamespace(src_path="/workspace/arnold"),
        secrets=[],
    )
    args = argparse.Namespace(
        idea_file=str(idea_file),
        plan_name="per-workflow-window-chat-cloud-20260628",
        robustness="full",
    )
    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli._ensure_repo_checkout", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli._relay_output", lambda *_args, **_kwargs: None)

    assert _derive_bootstrap_session_name(spec) == "vibecomfy-per-workflow-window-chat"
    assert _run_bootstrap_wrapper(args, spec, CaptureProvider()) == 0
    assert uploads == [(idea_file.resolve(), "/workspace/vibecomfy-per-workflow-window-chat-20260628/idea.txt")]
    assert len(commands) == 1
    assert "/workspace/.megaplan/cloud-sessions/vibecomfy-per-workflow-window-chat.json" in commands[0]


def test_chain_anchor_uploads_follow_chain_spec_directory(tmp_path: Path) -> None:
    spec_dir = tmp_path / ".megaplan" / "initiatives" / "demo"
    spec_dir.mkdir(parents=True)
    (spec_dir / "NORTHSTAR.md").write_text("north star\n", encoding="utf-8")
    (spec_dir / "m1-northstar.md").write_text("milestone star\n", encoding="utf-8")
    (spec_dir / "idea.md").write_text("idea\n", encoding="utf-8")
    spec_path = spec_dir / "chain.yaml"
    spec_path.write_text(
        "anchors:\n"
        "  north_star: NORTHSTAR.md\n"
        "milestones:\n"
        "  - label: m1\n"
        "    idea: idea.md\n"
        "    anchors:\n"
        "      north_star: m1-northstar.md\n",
        encoding="utf-8",
    )

    chain_spec = chain_module.load_spec(spec_path)
    uploads = _chain_anchor_uploads(
        spec_path,
        "/workspace/chain-123/app/.megaplan/initiatives/demo/chain.yaml",
        chain_spec,
    )

    assert uploads == [
        (spec_dir / "NORTHSTAR.md", "/workspace/chain-123/app/.megaplan/initiatives/demo/NORTHSTAR.md"),
        (spec_dir / "m1-northstar.md", "/workspace/chain-123/app/.megaplan/initiatives/demo/m1-northstar.md"),
    ]


def test_normalized_chain_upload_spec_materializes_preflight_phase_map(tmp_path: Path) -> None:
    spec_path = tmp_path / "chain.yaml"
    spec_path.write_text(
        "milestones:\n"
        "  - label: m1\n"
        "    idea: .megaplan/initiatives/demo/briefs/m1.md\n",
        encoding="utf-8",
    )
    preflight = {
        "milestones": [
            {
                "label": "m1",
                "resolved_phase_map": {
                    "plan": "codex",
                    "revise": "codex",
                    "execute": "codex",
                },
            }
        ]
    }

    upload_path = _normalized_chain_upload_spec(
        spec_path,
        base_branch="main",
        source_workspace="/workspace/app",
        target_workspace="/workspace/chain-123/app",
        phase_model_by_label=_phase_model_by_label_from_preflight(preflight),
    )
    try:
        normalized = yaml.safe_load(upload_path.read_text(encoding="utf-8"))
    finally:
        upload_path.unlink(missing_ok=True)

    milestone = normalized["milestones"][0]
    assert milestone["idea"] == ".megaplan/initiatives/demo/briefs/m1.md"
    assert milestone["phase_model"] == [
        "plan=codex",
        "revise=codex",
        "execute=codex",
    ]


def test_cloud_preflight_expands_vendor_depth_like_init() -> None:
    chain_spec = chain_module.ChainSpec.from_dict(
        {
            "milestones": [
                {
                    "label": "m1",
                    "idea": "idea.md",
                    "profile": "partnered-codex",
                    "vendor": "codex",
                    "depth": "high",
                }
            ]
        }
    )

    summary = resolve_cloud_chain_runtime_dependencies(
        chain_spec,
        project_dir=None,
        cloud_default_agent="codex",
    )

    phase_map = summary["milestones"][0]["resolved_phase_map"]
    assert phase_map["plan"] == "codex:gpt-5.6-sol:high"
    assert phase_map["revise"] == "codex:gpt-5.6-luna:high"
    assert phase_map["execute"] == "codex:gpt-5.6-sol:medium"


def test_cloud_preflight_reports_dependencies_for_every_spec_in_each_chain() -> None:
    chain_spec = chain_module.ChainSpec.from_dict(
        {
            "milestones": [
                {
                    "label": "m1",
                    "idea": "idea.md",
                    "phase_model": [
                        encode_phase_model_value("plan", ["codex:high", "claude:sonnet"]),
                        encode_phase_model_value("prep", ["omp:deepseek/deepseek-v4-pro", "codex"]),
                    ],
                }
            ]
        }
    )

    summary = resolve_cloud_chain_runtime_dependencies(
        chain_spec,
        project_dir=None,
        cloud_default_agent="codex",
    )

    milestone = summary["milestones"][0]
    assert milestone["resolved_phase_map"]["plan"] == "codex:high"
    assert milestone["resolved_phase_chains"]["plan"] == ["codex:high", "claude:sonnet"]
    assert sorted(summary["required_agents"]) == ["claude", "codex", "omp"]
    assert "codex" in summary["runtime_commands"]
    assert "claude" in summary["runtime_commands"]
    assert "DEEPSEEK_API_KEY" in summary["env_hints"]


def test_chain_project_root_uses_spec_git_repo_not_caller_root(tmp_path: Path) -> None:
    app_root = tmp_path / "app"
    caller_root = tmp_path / "arnold"
    spec_dir = app_root / "docs" / "chains" / "demo"
    spec_dir.mkdir(parents=True)
    caller_root.mkdir()
    subprocess.run(["git", "init"], cwd=app_root, check=True, capture_output=True, text=True)
    spec_path = spec_dir / "chain.yaml"
    spec_path.write_text("milestones: []\n", encoding="utf-8")

    assert _chain_project_root(spec_path, caller_root) == app_root.resolve()


def test_cloud_chain_spec_location_requires_durable_initiatives_tree(tmp_path: Path) -> None:
    project = tmp_path / "app"
    valid = project / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    loose = project / "chain.yaml"
    valid.parent.mkdir(parents=True)
    valid.write_text("milestones: []\n", encoding="utf-8")
    loose.write_text("milestones: []\n", encoding="utf-8")

    _validate_chain_spec_location(valid, project)
    with pytest.raises(CliError) as excinfo:
        _validate_chain_spec_location(loose, project)

    assert excinfo.value.code == "chain_spec_layout_violation"


def test_durable_megaplan_uploads_exclude_runtime_state(tmp_path: Path) -> None:
    project = tmp_path / "app"
    (project / ".megaplan" / "initiatives" / "demo").mkdir(parents=True)
    (project / ".megaplan" / "tickets").mkdir(parents=True)
    (project / ".megaplan" / "ideas").mkdir(parents=True)
    (project / ".megaplan" / "plans" / "run").mkdir(parents=True)
    (project / ".megaplan" / "initiatives" / "demo" / "chain.yaml").write_text("milestones: []\n", encoding="utf-8")
    (project / ".megaplan" / "tickets" / "T.md").write_text("ticket\n", encoding="utf-8")
    (project / ".megaplan" / "ideas" / "idea.md").write_text("idea\n", encoding="utf-8")
    (project / ".megaplan" / "ideas" / "._idea.md").write_text("appledouble\n", encoding="utf-8")
    (project / ".megaplan" / "tickets" / "._T.md").write_text("appledouble\n", encoding="utf-8")
    (project / ".megaplan" / "initiatives" / "demo" / ".DS_Store").write_text("finder\n", encoding="utf-8")
    (project / ".megaplan" / "plans" / "run" / "state.json").write_text("{}\n", encoding="utf-8")

    uploads = _durable_megaplan_uploads(project, "/workspace/demo/app")
    remotes = [remote for _local, remote in uploads]

    assert "/workspace/demo/app/.megaplan/initiatives/demo/chain.yaml" in remotes
    assert "/workspace/demo/app/.megaplan/tickets/T.md" in remotes
    assert "/workspace/demo/app/.megaplan/ideas/idea.md" in remotes
    assert all("/.megaplan/plans/" not in remote for remote in remotes)
    assert all("/._" not in remote for remote in remotes)
    assert all(not remote.endswith(".DS_Store") for remote in remotes)


def test_cloud_preflight_reports_remote_imports_profile_warning_and_expected_spec(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "app"
    spec_dir = project / ".megaplan" / "initiatives" / "demo"
    spec_dir.mkdir(parents=True)
    subprocess.run(["git", "init"], cwd=project, check=True, capture_output=True, text=True)
    (spec_dir / "NORTHSTAR.md").write_text("north star\n", encoding="utf-8")
    (spec_dir / "briefs").mkdir()
    (spec_dir / "briefs" / "m1.md").write_text("idea\n", encoding="utf-8")
    spec_path = spec_dir / "chain.yaml"
    spec_path.write_text(
        "anchors:\n"
        "  north_star: NORTHSTAR.md\n"
        "milestones:\n"
        "  - label: m1\n"
        "    idea: .megaplan/initiatives/demo/briefs/m1.md\n"
        "    phase_model:\n"
        "      - plan=claude\n"
        "      - revise=codex\n"
        "      - execute=codex\n",
        encoding="utf-8",
    )
    commands: list[str] = []

    class PreflightProvider:
        def observe_container(self):
            return _running_container_observation()

        def observe_prelaunch_capacity(self):
            return _go_prelaunch_capacity()

        def ssh_exec(self, command: str) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            if "MEGAPLAN_IMPORT_CHECK" in command:
                payload = {
                    "checks": {
                        "arnold_pipelines.megaplan": True,
                        "arnold_pipelines.megaplan.cli": True,
                        "arnold.pipelines.megaplan": False,
                    },
                    "errors": [],
                }
                return subprocess.CompletedProcess([], 0, json.dumps(payload) + "\n", "")
            return subprocess.CompletedProcess([], 0, "\n", "")

    rc = _run_preflight(
        project,
        argparse.Namespace(
            spec=str(spec_path),
            skip_remote=False,
            allow_loose_chain_spec=False,
        ),
        _cloud_spec(),
        PreflightProvider(),
    )

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["success"] is True
    assert payload["canonical_layout"] is True
    assert payload["remote"]["expected_remote_spec"].endswith("/.megaplan/initiatives/demo/chain.yaml")
    assert payload["remote"]["import_check"]["status"] == "ok"
    assert payload["remote"]["host_predeploy_verdict"] == "GO"
    assert payload["remote"]["collector_launch_verdict"] == "GO"
    assert any("Codex-only cloud workers should use profile partnered-codex" in warning for warning in payload["warnings"])
    assert any("MEGAPLAN_IMPORT_CHECK" in command for command in commands)


def test_cloud_preflight_fails_on_stale_remote_import(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "app"
    spec_dir = project / ".megaplan" / "initiatives" / "demo"
    spec_dir.mkdir(parents=True)
    subprocess.run(["git", "init"], cwd=project, check=True, capture_output=True, text=True)
    (spec_dir / "NORTHSTAR.md").write_text("north star\n", encoding="utf-8")
    (spec_dir / "briefs").mkdir()
    (spec_dir / "briefs" / "m1.md").write_text("idea\n", encoding="utf-8")
    spec_path = spec_dir / "chain.yaml"
    spec_path.write_text(
        "anchors:\n"
        "  north_star: NORTHSTAR.md\n"
        "milestones:\n"
        "  - label: m1\n"
        "    idea: .megaplan/initiatives/demo/briefs/m1.md\n",
        encoding="utf-8",
    )

    class StaleProvider:
        def observe_container(self):
            return _running_container_observation()

        def observe_prelaunch_capacity(self):
            return _go_prelaunch_capacity()

        def ssh_exec(self, command: str) -> subprocess.CompletedProcess[str]:
            if "MEGAPLAN_IMPORT_CHECK" in command:
                payload = {
                    "checks": {
                        "arnold_pipelines.megaplan": False,
                        "arnold_pipelines.megaplan.cli": False,
                        "arnold.pipelines.megaplan": True,
                    },
                    "errors": ["missing modern arnold_pipelines.megaplan import"],
                }
                return subprocess.CompletedProcess([], 1, json.dumps(payload) + "\n", "")
            return subprocess.CompletedProcess([], 0, "\n", "")

    rc = _run_preflight(
        project,
        argparse.Namespace(
            spec=str(spec_path),
            skip_remote=False,
            allow_loose_chain_spec=False,
        ),
        _cloud_spec(),
        StaleProvider(),
    )

    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["success"] is False
    assert "missing modern arnold_pipelines.megaplan import" in payload["errors"]


def test_cloud_preflight_reports_engine_ref_check_when_remote_checks_run(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "app"
    spec_dir = project / ".megaplan" / "initiatives" / "demo"
    spec_dir.mkdir(parents=True)
    subprocess.run(["git", "init"], cwd=project, check=True, capture_output=True, text=True)
    (spec_dir / "NORTHSTAR.md").write_text("north star\n", encoding="utf-8")
    (spec_dir / "briefs").mkdir()
    (spec_dir / "briefs" / "m1.md").write_text("idea\n", encoding="utf-8")
    spec_path = spec_dir / "chain.yaml"
    spec_path.write_text(
        "anchors:\n"
        "  north_star: NORTHSTAR.md\n"
        "milestones:\n"
        "  - label: m1\n"
        "    idea: .megaplan/initiatives/demo/briefs/m1.md\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.cli._verify_configured_megaplan_ref_advertised",
        lambda *_a, **_k: {
            "status": "ok",
            "repo": "https://github.com/example/arnold.git",
            "requested_ref": "editible-install",
            "advertised_ref": "refs/heads/editible-install",
            "commit": "abc123",
            "ref_kind": "branch",
        },
    )

    class PreflightProvider:
        def observe_container(self):
            return _running_container_observation()

        def observe_prelaunch_capacity(self):
            return _go_prelaunch_capacity()

        def ssh_exec(self, command: str) -> subprocess.CompletedProcess[str]:
            if "MEGAPLAN_IMPORT_CHECK" in command:
                payload = {
                    "checks": {
                        "arnold_pipelines.megaplan": True,
                        "arnold_pipelines.megaplan.cli": True,
                        "arnold.pipelines.megaplan": False,
                    },
                    "errors": [],
                }
                return subprocess.CompletedProcess([], 0, json.dumps(payload) + "\n", "")
            return subprocess.CompletedProcess([], 0, "\n", "")

    rc = _run_preflight(
        project,
        argparse.Namespace(
            spec=str(spec_path),
            skip_remote=False,
            allow_loose_chain_spec=False,
            cloud_yaml=str(project / "cloud.yaml"),
        ),
        replace(
            _cloud_spec(),
            megaplan=MegaplanSpec(repo="https://github.com/example/arnold.git", ref="editible-install"),
        ),
        PreflightProvider(),
    )

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["remote"]["engine_ref_check"]["advertised_ref"] == "refs/heads/editible-install"


def test_verify_configured_megaplan_ref_accepts_full_ref(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.cli._ls_remote_refs",
        lambda repo, refs: subprocess.CompletedProcess(
            [],
            0,
            "abc123\trefs/heads/editible-install\n",
            "",
        ),
    )

    result = _verify_configured_megaplan_ref_advertised(
        replace(
            _cloud_spec(),
            megaplan=MegaplanSpec(repo="https://github.com/example/arnold.git", ref="refs/heads/editible-install"),
        )
    )

    assert result["status"] == "ok"
    assert result["advertised_ref"] == "refs/heads/editible-install"
    assert result["ref_kind"] == "full_ref"


def test_verify_configured_megaplan_ref_accepts_fetchable_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    commit = "a" * 40
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.cli._probe_remote_commit",
        lambda repo, requested: subprocess.CompletedProcess([], 0, "", ""),
    )

    result = _verify_configured_megaplan_ref_advertised(
        replace(
            _cloud_spec(),
            megaplan=MegaplanSpec(repo="https://github.com/example/arnold.git", ref=commit),
        )
    )

    assert result == {
        "status": "ok",
        "repo": "https://github.com/example/arnold.git",
        "requested_ref": commit,
        "commit": commit,
        "ref_kind": "commit",
        "verification": "fetch",
    }


def test_fresh_launch_git_probes_use_the_path_only_on_box_helper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Engine ref probes share the authenticated on-box Git environment."""
    from arnold_pipelines.megaplan.cloud.auth import on_box_git_credential_env
    from arnold_pipelines.megaplan.cloud.cli import _git_ref_probe_env

    helper = tmp_path / "git-credentials"
    secret = "ghp_probe_secret_must_not_escape"
    helper.write_text(f"https://x-access-token:{secret}@github.com\n", encoding="utf-8")
    monkeypatch.setenv("ARNOLD_ON_BOX_GIT_CREDENTIAL_FILE", str(helper))
    monkeypatch.setenv("GITHUB_TOKEN", "ambient-token-must-not-be-forwarded")

    env = _git_ref_probe_env("https://github.com/peteromallet/Arnold.git")
    expected = on_box_git_credential_env(env=dict(os.environ), required=True)
    assert env == expected
    assert env["GIT_CONFIG_VALUE_0"] == f"store --file={helper}"
    assert secret not in repr(env)
    assert "ambient-token-must-not-be-forwarded" not in repr(env)


def test_fresh_launch_git_probe_reports_missing_explicit_helper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arnold_pipelines.megaplan.cloud.cli import _git_ref_probe_env

    monkeypatch.setenv(
        "ARNOLD_ON_BOX_GIT_CREDENTIAL_FILE", str(tmp_path / "missing-credentials")
    )
    with pytest.raises(CliError) as caught:
        _git_ref_probe_env("https://github.com/peteromallet/Arnold.git")
    assert caught.value.code == "on_box_git_auth_unavailable"


def test_fresh_bootstrap_git_probe_sequence_propagates_helper_to_each_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both advertised-ref and commit-fetch probes use the same helper path."""
    from arnold_pipelines.megaplan.cloud import cli as cloud_cli

    helper = tmp_path / "git-credentials"
    helper.write_text("https://x-access-token:fixture-secret@github.com\n", encoding="utf-8")
    monkeypatch.setenv("ARNOLD_ON_BOX_GIT_CREDENTIAL_FILE", str(helper))
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(argv, **kwargs):
        calls.append((list(argv), dict(kwargs)))
        if argv[:2] == ["git", "ls-remote"]:
            return subprocess.CompletedProcess(argv, 0, "abc\trefs/heads/main\n", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(cloud_cli.subprocess, "run", fake_run)
    cloud_cli._ls_remote_refs("https://github.com/example/app.git", ["refs/heads/main"])
    cloud_cli._probe_remote_commit("https://github.com/example/app.git", "a" * 40)

    git_transports = [
        (argv, kwargs)
        for argv, kwargs in calls
        if argv[:2] == ["git", "ls-remote"] or argv[:2] == ["git", "-C"] and "fetch" in argv
    ]
    assert len(git_transports) == 2
    for _argv, kwargs in git_transports:
        env = kwargs["env"]
        assert isinstance(env, dict)
        assert env["GIT_CONFIG_VALUE_0"] == f"store --file={helper}"
        assert "fixture-secret" not in repr(env)


def test_verify_configured_megaplan_ref_rejects_unfetchable_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    commit = "b" * 40
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.cli._probe_remote_commit",
        lambda repo, requested: subprocess.CompletedProcess([], 128, "", "fatal: not our ref"),
    )

    with pytest.raises(CliError) as excinfo:
        _verify_configured_megaplan_ref_advertised(
            replace(
                _cloud_spec(),
                megaplan=MegaplanSpec(repo="https://github.com/example/arnold.git", ref=commit),
            )
        )

    assert excinfo.value.code == "engine_commit_unfetchable"
    assert excinfo.value.extra["engine_ref_check"]["reason"] == "raw_sha_unfetchable"


def test_verify_configured_megaplan_ref_rejects_ambiguous_short_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.cli._ls_remote_refs",
        lambda repo, refs: subprocess.CompletedProcess(
            [],
            0,
            "abc123\trefs/heads/editible-install\n"
            "def456\trefs/tags/editible-install\n",
            "",
        ),
    )

    spec = replace(
        _cloud_spec(),
        megaplan=MegaplanSpec(repo="https://github.com/example/arnold.git", ref="editible-install")
    )
    with pytest.raises(CliError) as excinfo:
        _verify_configured_megaplan_ref_advertised(spec)

    assert excinfo.value.code == "engine_ref_ambiguous"


class _EpicAuthorityContextAdapter:
    """Keep the epic wrapper's legacy target shape on the real context."""

    def __init__(self, context) -> None:
        self._context = context
        self.receipt = context.receipt

    def read(self, *, capability, target_binding, expected=None):
        target = dict(target_binding)
        child_selector = self.receipt.request.child_selector
        target.setdefault("request", child_selector["request_id"])
        if capability == "repository_prepare":
            target.update(boundary="controller", operation="repository_prepare")
        elif capability == "file_upload":
            target.update(boundary="controller", operation="file_upload")
        elif capability == "ssh_engine_invocation":
            target.update(
                boundary="engine",
                operation=target.get("operation") or child_selector["operation_id"],
            )
        return self._context.read(
            capability=capability,
            target_binding=target,
            expected=expected,
        )


class _RefFailureProvider:
    def __init__(self) -> None:
        self.uploads: list[tuple[Path, str]] = []
        self.markers: dict[str, dict] = {}
        self.fresh_child_authority_context = None

    def bind_authority_context(self, context) -> None:
        assert callable(getattr(context, "read", None))
        self.fresh_child_authority_context = _EpicAuthorityContextAdapter(context)

    def upload_file(self, src: Path, dest: str) -> None:
        self.uploads.append((src, dest))

    def ssh_exec(self, command: str) -> subprocess.CompletedProcess[str]:
        if "MEGAPLAN_MARKER_WRITE" in command:
            marker_path, marker_payload = _parse_marker_write(command)
            self.markers[marker_path] = marker_payload
            return subprocess.CompletedProcess([], 0, "", "")
        if "MEGAPLAN_PRELAUNCH_MARKER_GUARD" in command:
            return subprocess.CompletedProcess(
                [],
                0,
                json.dumps(
                    {
                        "session_alive": False,
                        "marker_present": False,
                        "identity_matches": False,
                        "marker_read_error": "",
                    }
                )
                + "\n",
                "",
            )
        raise AssertionError(command)


def test_cloud_chain_persists_failed_launch_outcome_when_engine_ref_is_not_advertised(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "app"
    spec_dir = project / ".megaplan" / "initiatives" / "demo"
    spec_dir.mkdir(parents=True)
    subprocess.run(["git", "init"], cwd=project, check=True, capture_output=True, text=True)
    (spec_dir / "NORTHSTAR.md").write_text("north star\n", encoding="utf-8")
    (spec_dir / "briefs").mkdir()
    (spec_dir / "briefs" / "m1.md").write_text("idea\n", encoding="utf-8")
    spec_path = spec_dir / "chain.yaml"
    spec_path.write_text(
        "anchors:\n"
        "  north_star: NORTHSTAR.md\n"
        "milestones:\n"
        "  - label: m1\n"
        "    idea: .megaplan/initiatives/demo/briefs/m1.md\n",
        encoding="utf-8",
    )
    _attach_real_fresh_child_admission(
        project,
        spec_path,
        source_revision="editible-install",
        chain_identity="cloud-ref-chain",
    )

    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli._ensure_repo_checkout", lambda *_a, **_k: None)
    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli._run_remote_dependency_check", lambda *_a, **_k: [])
    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli.seed_codex_oauth", lambda *_a, **_k: {"status": "skipped"})
    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli._remote_repo_head", lambda *_a, **_k: {"branch": "main", "head": "abc123"})
    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli._relay_output", lambda *_a, **_k: None)
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.cli._verify_configured_megaplan_ref_advertised",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CliError(
                "engine_ref_not_advertised",
                "Configured cloud megaplan.ref 'editible-install' is not advertised by https://github.com/example/arnold.git.",
                extra={
                    "engine_ref_check": {
                        "status": "failed",
                        "repo": "https://github.com/example/arnold.git",
                        "requested_ref": "editible-install",
                    }
                },
            )
        ),
    )

    provider = _RefFailureProvider()
    cloud_spec = replace(
        _cloud_spec(),
        megaplan=MegaplanSpec(repo="https://github.com/example/arnold.git", ref="editible-install")
    )
    with pytest.raises(CliError) as excinfo:
        _run_chain_wrapper(
            project,
            argparse.Namespace(
                spec=str(spec_path),
                idea_dir=None,
                fresh=False,
                no_git_refresh=False,
                allow_loose_chain_spec=False,
                allow_template_placeholders=False,
                allow_human_gates=False,
                cloud_yaml=str(project / "cloud.yaml"),
                _canonicalized_epic=True,
                _generated_canonical_files=[],
            ),
            cloud_spec,
            provider,
        )

    assert excinfo.value.code == "engine_ref_not_advertised"
    assert not provider.markers


def test_cloud_epic_chain_persists_failed_launch_outcome_when_engine_ref_is_not_advertised(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "app"
    child_dir = project / ".megaplan" / "initiatives" / "child"
    parent_dir = project / ".megaplan" / "initiatives" / "demo"
    child_dir.mkdir(parents=True)
    parent_dir.mkdir(parents=True)
    subprocess.run(["git", "init"], cwd=project, check=True, capture_output=True, text=True)
    (child_dir / "NORTHSTAR.md").write_text("child north star\n", encoding="utf-8")
    (child_dir / "briefs").mkdir()
    (child_dir / "briefs" / "m1.md").write_text("idea\n", encoding="utf-8")
    child_spec = child_dir / "chain.yaml"
    child_spec.write_text(
        "anchors:\n"
        "  north_star: NORTHSTAR.md\n"
        "milestones:\n"
        "  - label: m1\n"
        "    idea: .megaplan/initiatives/child/briefs/m1.md\n",
        encoding="utf-8",
    )
    _attach_real_fresh_child_admission(
        project,
        child_spec,
        source_revision="editible-install",
        chain_identity="cloud-ref-epic-child",
    )
    (parent_dir / "NORTHSTAR.md").write_text("parent north star\n", encoding="utf-8")
    epic_spec = parent_dir / "epic-chain.yaml"
    epic_spec.write_text(
        "base_branch: main\n"
        "anchors:\n"
        "  north_star: NORTHSTAR.md\n"
        "epics:\n"
        "  - id: child\n"
        "    spec: ../child/chain.yaml\n"
        "on_failure:\n"
        "  abort: stop_epic_chain\n",
        encoding="utf-8",
    )

    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli._ensure_repo_checkout", lambda *_a, **_k: None)
    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli.seed_codex_oauth", lambda *_a, **_k: {"status": "skipped"})
    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli._relay_output", lambda *_a, **_k: None)
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.cli._verify_configured_megaplan_ref_advertised",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CliError(
                "engine_ref_not_advertised",
                "Configured cloud megaplan.ref 'editible-install' is not advertised by https://github.com/example/arnold.git.",
                extra={
                    "engine_ref_check": {
                        "status": "failed",
                        "repo": "https://github.com/example/arnold.git",
                        "requested_ref": "editible-install",
                    }
                },
            )
        ),
    )

    class EpicRefFailureProvider(_RefFailureProvider):
        def upload_archive(self, src: Path, dest: str) -> None:
            self.uploads.append((src, dest))

        def ssh_exec(self, command: str) -> subprocess.CompletedProcess[str]:
            if command.startswith("rm -rf "):
                return subprocess.CompletedProcess([], 0, "", "")
            return super().ssh_exec(command)

    provider = EpicRefFailureProvider()
    cloud_spec = replace(
        _cloud_spec(),
        megaplan=MegaplanSpec(repo="https://github.com/example/arnold.git", ref="editible-install"),
    )
    from arnold_pipelines.megaplan.chain import epic_chain as epic_chain_module
    from arnold_pipelines.megaplan.chain.fresh_child_launch import provision_fresh_child_authority

    loaded_epic = epic_chain_module.load_epic_chain_spec(epic_spec)
    loaded_child = chain_module.load_spec(child_spec)
    launch_ctx = _derive_epic_chain_launch_context(
        root=project,
        spec=cloud_spec,
        local_spec_path=epic_spec,
        epic_chain_spec=loaded_epic,
    )
    authority_target = {
        "provider": str(cloud_spec.provider),
        "workspace": launch_ctx.workspace,
        "session": launch_ctx.session_name,
        "source_revision": str(cloud_spec.megaplan.ref),
        "chain_spec": str(epic_spec.resolve()),
        "boundary": "controller",
        "operation": "repository_prepare",
    }
    provision_fresh_child_authority(
        root=project,
        spec_path=child_spec,
        spec=loaded_child.fresh_child_admission,
        launch_context=authority_target,
        provider=provider,
        operation_id=f"cloud-epic-chain:{launch_ctx.identity}",
        request_id=f"cloud-epic-chain-request:{launch_ctx.digest}",
        upload_destinations=(launch_ctx.workspace, launch_ctx.remote_spec_path),
    )
    with pytest.raises(CliError) as excinfo:
        _run_epic_chain_wrapper(
            project,
            argparse.Namespace(
                spec=str(epic_spec),
                fresh=False,
                one=False,
                cloud_yaml=str(project / "cloud.yaml"),
            ),
            cloud_spec,
            provider,
        )

    assert excinfo.value.code == "engine_ref_not_advertised"
    assert not provider.markers


def test_sync_megaplan_uses_derived_chain_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = tmp_path / "app"
    spec_dir = project / ".megaplan" / "initiatives" / "demo"
    spec_dir.mkdir(parents=True)
    spec_path = spec_dir / "chain.yaml"
    idea_path = spec_dir / "briefs" / "m1.md"
    idea_path.parent.mkdir()
    spec_path.write_text(
        "milestones:\n"
        "  - label: m1\n"
        "    idea: .megaplan/initiatives/demo/briefs/m1.md\n",
        encoding="utf-8",
    )
    idea_path.write_text("idea\n", encoding="utf-8")
    (project / ".megaplan" / "tickets").mkdir()
    (project / ".megaplan" / "tickets" / "ticket.md").write_text("ticket\n", encoding="utf-8")

    subprocess.run(["git", "init"], cwd=project, check=True, capture_output=True, text=True)
    chain_spec = chain_module.load_spec(spec_path)
    cloud_spec = CloudSpec(
        provider="ssh",
        repo=RepoSpec(url="https://github.com/example/app.git"),
        agents={"default": "codex"},
        codex=CodexSpec(),
        mode="idle",
        megaplan=MegaplanSpec(),
        resources=ResourcesSpec(),
        secrets=[],
        ssh=SshSpec(host="testhost"),
    )
    expected = _derive_chain_launch_context(
        root=project,
        spec=cloud_spec,
        local_spec_path=spec_path,
        chain_spec=chain_spec,
    )
    commands: list[str] = []
    uploads: list[tuple[Path, str]] = []
    archive_names: list[str] = []

    class CaptureProvider:
        def ssh_exec(self, command: str) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            return subprocess.CompletedProcess([], 0, "", "")

        def upload_file(self, src: Path, dest: str) -> None:
            uploads.append((src, dest))

        def upload_archive(self, src: Path, dest_dir: str) -> None:
            uploads.append((src, dest_dir))
            with tarfile.open(src, "r:gz") as tar:
                archive_names.extend(sorted(tar.getnames()))

    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli._ensure_repo_checkout", lambda *_args, **_kwargs: None)

    result = _run_sync_megaplan(
        project,
        argparse.Namespace(
            spec=str(spec_path),
            workspace=None,
            clean=True,
            allow_loose_chain_spec=False,
        ),
        cloud_spec,
        CaptureProvider(),
    )

    assert result == 0
    assert commands and "rm -rf" in commands[0]
    assert uploads and uploads[0][1] == expected.workspace
    assert ".megaplan/initiatives/demo/chain.yaml" in archive_names
    assert ".megaplan/tickets/ticket.md" in archive_names


def test_status_auto_uses_chain_for_chain_mode() -> None:
    spec = CloudSpec(
        provider="ssh",
        repo=RepoSpec(url="https://github.com/example/app.git", workspace="/workspace/app"),
        agents={"default": "codex"},
        codex=CodexSpec(),
        mode="chain",
        chain=ChainSubSpec(spec="/workspace/app/chain.yaml"),
        megaplan=MegaplanSpec(),
        resources=ResourcesSpec(),
        secrets=[],
        ssh=SshSpec(host="testhost"),
    )

    assert _status_should_use_chain(Path("/repo"), argparse.Namespace(chain=False, remote_spec=None, cloud_yaml=None), spec)


def test_status_auto_uses_chain_for_remote_spec_override() -> None:
    spec = CloudSpec(
        provider="ssh",
        repo=RepoSpec(url="https://github.com/example/app.git", workspace="/workspace/app"),
        agents={"default": "codex"},
        codex=CodexSpec(),
        mode="idle",
        megaplan=MegaplanSpec(),
        resources=ResourcesSpec(),
        secrets=[],
        ssh=SshSpec(host="testhost"),
    )

    assert _status_should_use_chain(
        Path("/repo"),
        argparse.Namespace(chain=False, remote_spec="/workspace/app/chain.yaml", cloud_yaml=None),
        spec,
    )


class _ResumeProvider:
    def __init__(self, chain_state: dict) -> None:
        self.chain_state = chain_state

    def read_remote_file(self, _path: str) -> str:
        return json.dumps(self.chain_state)

    def ssh_exec(self, _command: str) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], 1, "", "")


def test_cloud_resume_uses_chain_marker_workspace(monkeypatch: pytest.MonkeyPatch) -> None:
    spec = CloudSpec(
        provider="ssh",
        repo=RepoSpec(url="https://github.com/example/app.git", workspace="/workspace/app"),
        agents={"default": "codex"},
        codex=CodexSpec(),
        mode="idle",
        megaplan=MegaplanSpec(),
        resources=ResourcesSpec(),
        secrets=[],
        ssh=SshSpec(host="testhost"),
    )
    marker = {
        "workspace": "/workspace/chain-51d959cf/vibecomfy",
        "remote_spec": "/workspace/chain-51d959cf/vibecomfy/.megaplan/initiatives/demo/chain.yaml",
    }
    chain_state = chain_module.ChainState(
        current_plan_name="milestone-demo",
        resolved_workspace="/workspace/chain-51d959cf/vibecomfy",
    ).to_dict()

    monkeypatch.setattr("arnold_pipelines.megaplan.cloud.cli._load_marker", lambda *_args: marker)

    workspace = _resolve_resume_workspace(
        Path("/repo"),
        argparse.Namespace(plan="milestone-demo"),
        spec,
        _ResumeProvider(chain_state),
    )

    assert workspace == "/workspace/chain-51d959cf/vibecomfy"


def test_latest_failure_summary_bubbles_plan_state_message() -> None:
    summary = _latest_failure_from_plan_status(
        {
            "status": "stalled",
            "latest_failure": {
                "kind": "agent_deps_missing",
                "phase": "plan",
                "message": "Claude routes through Shannon, but bun is missing",
                "metadata": {"ignored": True},
            },
        }
    )

    assert summary == {
        "kind": "agent_deps_missing",
        "phase": "plan",
        "message": "Claude routes through Shannon, but bun is missing",
        "raw": {
            "kind": "agent_deps_missing",
            "phase": "plan",
            "message": "Claude routes through Shannon, but bun is missing",
            "metadata": {"ignored": True},
        },
    }


class _StatusProvider:
    def __init__(
        self,
        *,
        remote_spec: str,
        chain_yaml: str,
        chain_state: dict,
        plan_status: dict,
        runner_probe: str = "dead\n",
    ) -> None:
        self.remote_spec = remote_spec
        self.state_path = str(chain_module._state_path_for(Path(remote_spec)))
        self.chain_yaml = chain_yaml
        self.chain_state = chain_state
        self.plan_status = plan_status
        self.runner_probe = runner_probe

    def read_remote_file(self, path: str) -> str:
        if path == self.remote_spec:
            return self.chain_yaml
        if path == self.state_path:
            return json.dumps(self.chain_state)
        raise OSError(f"unexpected remote file: {path}")

    def status_payload(self, *, plan: str | None, workspace: str) -> dict:
        assert plan == "milestone-demo"
        assert workspace == "/workspace/chain-51d959cf/vibecomfy"
        return dict(self.plan_status)

    def ssh_exec(self, command: str) -> subprocess.CompletedProcess[str]:
        if "tmux has-session" in command:
            return subprocess.CompletedProcess([], 0, self.runner_probe, "")
        if command.startswith("stat "):
            return subprocess.CompletedProcess([], 0, "unavailable\n", "")
        if "verify-human" in command:
            return subprocess.CompletedProcess([], 0, "{}", "")
        return subprocess.CompletedProcess([], 1, "", "unexpected command")


def test_cloud_chain_status_payload_exposes_plan_latest_failure() -> None:
    remote_spec = "/workspace/chain-51d959cf/vibecomfy/.megaplan/initiatives/demo/chain.yaml"
    chain_yaml = (
        "milestones:\n"
        "  - label: m1\n"
        "    idea: idea.md\n"
    )
    chain_state = chain_module.ChainState(
        current_milestone_index=0,
        current_plan_name="milestone-demo",
        last_state="prepped",
        resolved_workspace="/workspace/chain-51d959cf/vibecomfy",
        chain_session="megaplan-chain-demo",
    ).to_dict()
    plan_status = {
        "status": "stalled",
        "latest_failure": {
            "kind": "agent_deps_missing",
            "message": "Claude routes through Shannon, but bun is missing",
            "phase": "plan",
        },
    }
    spec = CloudSpec(
        provider="ssh",
        repo=RepoSpec(url="https://github.com/example/app.git", workspace="/workspace/app"),
        agents={"default": "codex"},
        codex=CodexSpec(),
        mode="idle",
        megaplan=MegaplanSpec(),
        resources=ResourcesSpec(),
        secrets=[],
        ssh=SshSpec(host="testhost"),
    )

    payload = cloud_chain_status_payload(
        Path("/repo"),
        argparse.Namespace(remote_spec=remote_spec, cloud_yaml=None),
        spec,
        _StatusProvider(
            remote_spec=remote_spec,
            chain_yaml=chain_yaml,
            chain_state=chain_state,
            plan_status=plan_status,
        ),
    )

    assert payload["latest_failure"]["message"] == "Claude routes through Shannon, but bun is missing"
    assert payload["plan_status"] == plan_status


def test_cloud_resume_uses_resume_command_for_failed_plan(monkeypatch, tmp_path: Path) -> None:
    commands: list[str] = []

    class Provider:
        def status_payload(self, *, plan: str | None, workspace: str) -> dict:
            assert plan == "milestone-demo"
            assert workspace == "/workspace/chain-51d959cf/vibecomfy"
            return {
                "state": "failed",
                "next_step": "review",
                "valid_next": ["review"],
            }

        def ssh_exec(self, command: str) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.cli._load_cloud_spec",
        lambda root, args: _cloud_spec(),
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.cli._provider_for_action",
        lambda spec, args: Provider(),
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.cli._resolve_resume_workspace",
        lambda root, args, spec, provider: "/workspace/chain-51d959cf/vibecomfy",
    )

    args = _cloud_parser().parse_args(["cloud", "resume", "--plan", "milestone-demo"])

    rc = run_cloud_cli(tmp_path, args)

    assert rc == 0
    assert commands == [
        "if [ -f /workspace/.cloud-hot-env ]; then set -a; . /workspace/.cloud-hot-env; set +a; fi; cd /workspace/chain-51d959cf/vibecomfy && /workspace/runtime-venvs/test/bin/python -P -m arnold_pipelines.megaplan resume --plan milestone-demo"
    ]


def test_cloud_chain_status_payload_keeps_live_process_diagnostic_only() -> None:
    remote_spec = "/workspace/chain-51d959cf/vibecomfy/.megaplan/initiatives/demo/chain.yaml"
    chain_yaml = (
        "milestones:\n"
        "  - label: m1\n"
        "    idea: idea.md\n"
    )
    chain_state = chain_module.ChainState(
        current_milestone_index=0,
        current_plan_name="milestone-demo",
        last_state="prepped",
        resolved_workspace="/workspace/chain-51d959cf/vibecomfy",
        chain_session="megaplan-chain-demo",
    ).to_dict()
    spec = CloudSpec(
        provider="ssh",
        repo=RepoSpec(url="https://github.com/example/app.git", workspace="/workspace/app"),
        agents={"default": "codex"},
        codex=CodexSpec(),
        mode="idle",
        megaplan=MegaplanSpec(),
        resources=ResourcesSpec(),
        secrets=[],
        ssh=SshSpec(host="testhost"),
    )

    payload = cloud_chain_status_payload(
        Path("/repo"),
        argparse.Namespace(remote_spec=remote_spec, cloud_yaml=None),
        spec,
        _StatusProvider(
            remote_spec=remote_spec,
            chain_yaml=chain_yaml,
            chain_state=chain_state,
            plan_status={"status": "running"},
            runner_probe="process_alive\n",
        ),
    )

    assert payload["runner"]["status"] == "unknown"
    assert payload["runner"]["authority"] == "canonical_current_target"
    assert payload["runner"]["diagnostic_tmux_status"] == "missing"
    assert payload["runner"]["diagnostic_process_status"] == "alive"
    assert payload["runner"]["mutation_permitted"] is False
    assert payload["effective_status"] == "running"


def test_cloud_chains_command_lists_marker_only_live_process_sessions() -> None:
    script = _cloud_chains_command()

    assert "marker_dir.glob(\"*.json\")" in script
    assert "process_status" in script
    assert "tmux_status" in script
    assert '" chain start" in line' in script
    assert '" epic-chain start" in line' in script
    assert "def _effective_session_status(payload):" in script
    assert "return \"running\"" in script


def test_cloud_chains_command_prefers_live_runner_over_stale_done_plan_pointer() -> None:
    script = _cloud_chains_command()

    status_fn = script[script.index("def _effective_session_status(payload):") :]
    live_runner_check = 'payload.get("tmux_status") == "alive" or payload.get("process_status") == "alive"'
    stale_done_check = 'if current_state == "done":'

    assert status_fn.index(live_runner_check) < status_fn.index(stale_done_check)


def test_cloud_chains_command_lists_all_canonical_markers_not_only_default_prefix() -> None:
    script = _cloud_chains_command()

    assert "name.startswith" not in script
    assert "sessions_by_name.setdefault(name, _payload_for(name))" in script
    assert "untracked_tmux_sessions" in script


def test_cloud_chains_command_derives_display_name_from_initiative_path() -> None:
    script = _cloud_chains_command()

    assert "def _display_name(payload):" in script
    assert '{"initiatives", "briefs"}' in script
    assert '"display_name"' in script


def test_cloud_chains_command_includes_should_run_and_watchdog_repair_state() -> None:
    script = _cloud_chains_command()

    assert "def _load_watchdog_sessions():" in script
    assert "watchdog_by_session" in script
    assert '"watchdog_evidence"' in script
    assert '"watchdog_repairing"' in script
    assert '"should_be_running"' in script
    assert "def _should_be_running(payload):" in script
    assert 'if payload.get("should_run") is False:' in script
    assert (
        'isinstance(operator_pause, dict) and operator_pause.get("active") is True'
        in script
    )
    assert "should_be_running_count" in script
    assert "watchdog_repairing_count" in script


def test_cloud_chains_command_explains_policy_and_user_action_blocks() -> None:
    script = _cloud_chains_command()

    assert "def _policy_evidence(remote_spec):" in script
    assert '"merge_policy"' in script
    assert '"driver_auto_approve"' in script
    assert "def _operator_status(payload):" in script
    assert "blocked_prep_clarification" in script
    assert "clarification_question_count" in script
    assert '"operator_summary"' in script
    assert '"next_action"' in script
    assert "human_gate_misconfigured" in script
    assert "not payload.get(\"allow_human_gates\")" in script


# ── T11: sidecar classification & evidence field tests ──────────────────


def test_cloud_chains_command_uses_canonical_session_marker_filter() -> None:
    """The generated script must import and call ``is_canonical_session_marker_path``
    to exclude canonical sidecar JSONs from session listing."""
    script = _cloud_chains_command()

    assert "from arnold_pipelines.megaplan.cloud.session_markers import is_canonical_session_marker_path" in script
    assert "is_canonical_session_marker_path(marker)" in script


def test_cloud_chains_command_emits_latest_plan_state_evidence() -> None:
    script = _cloud_chains_command()

    assert "def _latest_plan_state_evidence(workspace):" in script
    assert '"latest_plan_state"' in script
    assert '"active_phase"' in script
    assert '".megaplan" / "plans"' in script
    assert 'plans_dir.glob("*/state.json")' in script


def test_cloud_chains_command_emits_event_activity_evidence() -> None:
    script = _cloud_chains_command()

    assert "def _event_activity_evidence(workspace, plan_name):" in script
    assert '"event_activity_evidence"' in script
    assert '"event_activity_status"' in script
    assert 'plans" / plan_name / "events.ndjson"' in script
    assert 'plan_name = latest_plan_state.get("plan")' in script


def test_cloud_chains_command_emits_separate_evidence_fields() -> None:
    """Every session row must emit distinct ``marker_evidence``, ``tmux_evidence``,
    ``process_evidence``, ``chain_health_evidence``, and ``active_step_evidence`` fields."""
    script = _cloud_chains_command()

    assert '"marker_evidence"' in script
    assert '"tmux_evidence"' in script
    assert '"process_evidence"' in script
    assert '"chain_health_evidence"' in script
    assert '"active_step_evidence"' in script
    # Status convenience mirrors
    assert '"marker_status"' in script
    assert '"tmux_status"' in script
    assert '"process_status"' in script
    assert '"chain_health_status"' in script
    assert '"active_step_status"' in script


def test_cloud_status_since_parser_accepts_duration() -> None:
    now = _parse_cloud_status_since("2026-07-04T12:00:00Z")
    assert now is not None

    cutoff = _parse_cloud_status_since("12h", now=now)

    assert cutoff is not None
    assert cutoff.isoformat() == "2026-07-04T00:00:00+00:00"


def test_cloud_status_since_filter_uses_real_plan_state_not_watchdog_mtime() -> None:
    payload = {
        "sessions": [
            {
                "session": "old-but-reobserved",
                "status": "complete",
                "watchdog_repairing": False,
                "should_be_running": False,
                "watchdog_evidence": {"updated_at": "2026-07-04T08:00:00Z"},
                "latest_plan_state": {
                    "status": "present",
                    "updated_at": "2026-07-03T08:00:00Z",
                    "plan": "old-plan",
                    "state": "done",
                },
                "operator_status": {"status": "complete"},
            },
            {
                "session": "recent",
                "status": "complete",
                "watchdog_repairing": False,
                "should_be_running": False,
                "latest_plan_state": {
                    "status": "present",
                    "updated_at": "2026-07-04T04:00:00Z",
                    "plan": "recent-plan",
                    "state": "done",
                },
                "operator_status": {"status": "complete"},
            },
        ]
    }
    since = _parse_cloud_status_since("2026-07-04T00:00:00Z")

    _filter_cloud_sessions_since(payload, since)

    assert [item["session"] for item in payload["sessions"]] == ["recent"]
    assert payload["unfiltered_session_count"] == 2
    assert payload["summary"] == {"complete": 1}


def test_cloud_status_since_filter_prefers_event_activity_over_stale_state() -> None:
    payload = {
        "sessions": [
            {
                "session": "active-prep",
                "status": "running",
                "watchdog_repairing": False,
                "should_be_running": True,
                "latest_plan_state": {
                    "status": "present",
                    "updated_at": "2026-07-03T08:00:00Z",
                    "plan": "active-plan",
                    "state": "initialized",
                },
                "event_activity_evidence": {
                    "status": "present",
                    "updated_at": "2026-07-04T04:00:00Z",
                    "phase": "prep-research",
                    "kind": "llm_token_heartbeat",
                },
                "operator_status": {"status": "running_phase"},
            }
        ]
    }
    since = _parse_cloud_status_since("2026-07-04T00:00:00Z")

    _filter_cloud_sessions_since(payload, since)

    assert [item["session"] for item in payload["sessions"]] == ["active-prep"]
    assert payload["sessions"][0]["real_activity_at"] == "2026-07-04T04:00:00Z"


def test_cloud_session_plan_state_prefers_event_phase_over_initialized_state() -> None:
    assert (
        _cloud_session_plan_state(
            {
                "latest_plan_state": {"status": "present", "state": "initialized"},
                "event_activity_evidence": {
                    "status": "present",
                    "phase": "prep-research",
                    "kind": "llm_token_heartbeat",
                },
            }
        )
        == "prep-research"
    )


def test_cloud_session_plan_state_uses_latest_state_active_phase_fallback() -> None:
    assert (
        _cloud_session_plan_state(
            {
                "latest_plan_state": {
                    "status": "present",
                    "state": "initialized",
                    "active_phase": "prep-distill",
                },
                "event_activity_evidence": {"status": "missing"},
                "active_step_evidence": {"status": "missing"},
            }
        )
        == "prep-distill"
    )


def test_cloud_chains_command_treats_initialized_as_known_nonterminal_state() -> None:
    script = _cloud_chains_command()

    assert '{"initialized", "prepped", "planned", "gated", "finalized", "executed", "reviewed", "stopped"}' in script
    assert '"initialized",\n            "prepped",' in script


class _CloudChainsProvider:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def ssh_exec(self, command: str) -> subprocess.CompletedProcess[str]:
        assert "_latest_plan_state_evidence" in command
        return subprocess.CompletedProcess([], 0, json.dumps(self.payload) + "\n", "")


def test_cloud_status_all_compact_since_filters_payload_and_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    payload = {
        "success": True,
        "sessions": [
            {
                "session": "old",
                "display_name": "old",
                "status": "complete",
                "watchdog_repairing": False,
                "should_be_running": False,
                "workspace": "/workspace/old",
                "latest_plan_state": {
                    "status": "present",
                    "updated_at": "2026-07-03T08:00:00Z",
                    "plan": "old-plan",
                    "state": "done",
                },
                "operator_status": {"status": "complete"},
            },
            {
                "session": "running",
                "display_name": "running",
                "status": "running",
                "watchdog_repairing": True,
                "should_be_running": True,
                "workspace": "/workspace/running",
                "latest_plan_state": {
                    "status": "present",
                    "updated_at": "2026-07-04T04:00:00Z",
                    "plan": "active-plan",
                    "state": "initialized",
                },
                "event_activity_evidence": {
                    "status": "present",
                    "updated_at": "2026-07-04T04:05:00Z",
                    "phase": "prep-research",
                    "kind": "llm_token_heartbeat",
                },
                "operator_status": {"status": "running_repairing"},
            },
        ],
    }
    spec = CloudSpec(
        provider="ssh",
        repo=RepoSpec(url="https://github.com/example/app.git", workspace="/workspace/app"),
        agents={"default": "codex"},
        codex=CodexSpec(),
        mode="idle",
        megaplan=MegaplanSpec(),
        resources=ResourcesSpec(),
        secrets=[],
        ssh=SshSpec(host="testhost"),
    )
    args = argparse.Namespace(since="2026-07-04T00:00:00Z", compact=True)

    assert _run_cloud_chains(spec, _CloudChainsProvider(payload), args=args) == 0

    captured = capsys.readouterr()
    assert "cloud sessions: 1 since=2026-07-04T00:00:00Z filtered_from=2" in captured.err
    assert "session=running" in captured.err
    assert "activity_state=prep-research" in captured.err
    assert "session=old" not in captured.err
    emitted = json.loads(captured.out)
    assert [item["session"] for item in emitted["sessions"]] == ["running"]
    assert emitted["should_be_running_count"] == 1


def test_cloud_chains_command_marker_only_sessions_have_process_dead_tmux_missing() -> None:
    """When only a marker exists (no tmux, no process), the row must show
    tmux=missing and process=dead (or unknown), not omit the fields."""
    script = _cloud_chains_command()

    # tmux_evidence defaults to missing when session not in tmux_names
    assert '"tmux_evidence": {"status": "alive" if name in tmux_names else "missing"}' in script
    # process_evidence calls _process_status which returns alive/dead/unknown
    assert "def _process_status(remote_spec, workspace=\"\", plan_name=\"\"):" in script
    assert '"process_evidence"' in script


def test_cloud_chain_status_payload_exposes_separate_evidence_fields() -> None:
    """``cloud_chain_status_payload`` must return separate marker_evidence,
    tmux_evidence, process_evidence, and active_step_evidence keys."""
    remote_spec = "/workspace/chain-51d959cf/vibecomfy/.megaplan/initiatives/demo/chain.yaml"
    chain_yaml = "milestones:\n  - label: m1\n    idea: idea.md\n"
    chain_state = chain_module.ChainState(
        current_milestone_index=0,
        current_plan_name="milestone-demo",
        last_state="prepped",
        resolved_workspace="/workspace/chain-51d959cf/vibecomfy",
        chain_session="megaplan-chain-demo",
    ).to_dict()
    spec = CloudSpec(
        provider="ssh",
        repo=RepoSpec(url="https://github.com/example/app.git", workspace="/workspace/app"),
        agents={"default": "codex"},
        codex=CodexSpec(),
        mode="idle",
        megaplan=MegaplanSpec(),
        resources=ResourcesSpec(),
        secrets={},
        ssh=SshSpec(host="testhost"),
    )

    payload = cloud_chain_status_payload(
        Path("/repo"),
        argparse.Namespace(remote_spec=remote_spec, cloud_yaml=None),
        spec,
        _StatusProvider(
            remote_spec=remote_spec,
            chain_yaml=chain_yaml,
            chain_state=chain_state,
            plan_status={"status": "running"},
            runner_probe="dead\n",
        ),
    )

    assert "marker_evidence" in payload
    assert "tmux_evidence" in payload
    assert "process_evidence" in payload
    assert "active_step_evidence" in payload
    # marker_evidence structure
    assert isinstance(payload["marker_evidence"], dict)
    assert "status" in payload["marker_evidence"]
    # tmux_evidence structure
    assert isinstance(payload["tmux_evidence"], dict)
    assert "status" in payload["tmux_evidence"]
    # process_evidence structure
    assert isinstance(payload["process_evidence"], dict)
    assert "status" in payload["process_evidence"]
    # active_step_evidence structure
    assert isinstance(payload["active_step_evidence"], dict)
    assert "status" in payload["active_step_evidence"]


def test_cloud_chain_status_payload_tmux_alive_sets_tmux_evidence_and_process_unknown() -> None:
    """When tmux is alive, ``tmux_evidence`` is *alive* while ``process_evidence``
    is *unknown* (not dead, not alive)."""
    remote_spec = "/workspace/chain-51d959cf/vibecomfy/.megaplan/initiatives/demo/chain.yaml"
    chain_yaml = "milestones:\n  - label: m1\n    idea: idea.md\n"
    chain_state = chain_module.ChainState(
        current_milestone_index=0,
        current_plan_name="milestone-demo",
        last_state="prepped",
        resolved_workspace="/workspace/chain-51d959cf/vibecomfy",
        chain_session="megaplan-chain-demo",
    ).to_dict()
    spec = CloudSpec(
        provider="ssh",
        repo=RepoSpec(url="https://github.com/example/app.git", workspace="/workspace/app"),
        agents={"default": "codex"},
        codex=CodexSpec(),
        mode="idle",
        megaplan=MegaplanSpec(),
        resources=ResourcesSpec(),
        secrets={},
        ssh=SshSpec(host="testhost"),
    )

    payload = cloud_chain_status_payload(
        Path("/repo"),
        argparse.Namespace(remote_spec=remote_spec, cloud_yaml=None),
        spec,
        _StatusProvider(
            remote_spec=remote_spec,
            chain_yaml=chain_yaml,
            chain_state=chain_state,
            plan_status={"status": "running"},
            runner_probe="tmux_alive\n",
        ),
    )

    assert payload["tmux_evidence"]["status"] == "alive"
    assert payload["process_evidence"]["status"] == "unknown"
    assert payload["runner"]["diagnostic_tmux_status"] == "alive"
    assert payload["runner"]["diagnostic_process_status"] == "unknown"
    assert payload["runner"]["status"] == "unknown"


def test_cloud_chain_status_payload_active_step_from_plan_status() -> None:
    """``active_step_evidence`` must reflect the active step from plan status
    when available."""
    remote_spec = "/workspace/chain-51d959cf/vibecomfy/.megaplan/initiatives/demo/chain.yaml"
    chain_yaml = "milestones:\n  - label: m1\n    idea: idea.md\n"
    chain_state = chain_module.ChainState(
        current_milestone_index=0,
        current_plan_name="milestone-demo",
        last_state="prepped",
        resolved_workspace="/workspace/chain-51d959cf/vibecomfy",
        chain_session="megaplan-chain-demo",
    ).to_dict()
    spec = CloudSpec(
        provider="ssh",
        repo=RepoSpec(url="https://github.com/example/app.git", workspace="/workspace/app"),
        agents={"default": "codex"},
        codex=CodexSpec(),
        mode="idle",
        megaplan=MegaplanSpec(),
        resources=ResourcesSpec(),
        secrets={},
        ssh=SshSpec(host="testhost"),
    )

    payload = cloud_chain_status_payload(
        Path("/repo"),
        argparse.Namespace(remote_spec=remote_spec, cloud_yaml=None),
        spec,
        _StatusProvider(
            remote_spec=remote_spec,
            chain_yaml=chain_yaml,
            chain_state=chain_state,
            plan_status={
                "status": "running",
                "active_step": {
                    "phase": "execute",
                    "name": "run_tests",
                    "attempt": 2,
                    "worker_pid": 4242,
                },
            },
            runner_probe="dead\n",
        ),
    )

    assert payload["active_step_evidence"]["status"] == "present"
    assert payload["active_step_evidence"]["phase"] == "execute"
    assert payload["active_step_evidence"]["name"] == "run_tests"
    assert payload["active_step_evidence"]["attempt"] == 2
    assert payload["active_step_evidence"]["worker_pid"] == 4242


def test_cloud_chain_status_payload_active_step_absent_when_missing() -> None:
    """``active_step_evidence.status`` is *absent* when plan status has no active step."""
    remote_spec = "/workspace/chain-51d959cf/vibecomfy/.megaplan/initiatives/demo/chain.yaml"
    chain_yaml = "milestones:\n  - label: m1\n    idea: idea.md\n"
    chain_state = chain_module.ChainState(
        current_milestone_index=0,
        current_plan_name="milestone-demo",
        last_state="prepped",
        resolved_workspace="/workspace/chain-51d959cf/vibecomfy",
        chain_session="megaplan-chain-demo",
    ).to_dict()
    spec = CloudSpec(
        provider="ssh",
        repo=RepoSpec(url="https://github.com/example/app.git", workspace="/workspace/app"),
        agents={"default": "codex"},
        codex=CodexSpec(),
        mode="idle",
        megaplan=MegaplanSpec(),
        resources=ResourcesSpec(),
        secrets={},
        ssh=SshSpec(host="testhost"),
    )

    payload = cloud_chain_status_payload(
        Path("/repo"),
        argparse.Namespace(remote_spec=remote_spec, cloud_yaml=None),
        spec,
        _StatusProvider(
            remote_spec=remote_spec,
            chain_yaml=chain_yaml,
            chain_state=chain_state,
            plan_status={"status": "running"},
            runner_probe="dead\n",
        ),
    )

    assert payload["active_step_evidence"]["status"] == "absent"
