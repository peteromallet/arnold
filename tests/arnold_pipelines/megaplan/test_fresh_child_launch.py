from __future__ import annotations

import argparse
from contextlib import nullcontext
import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

from arnold_pipelines.megaplan.chain.spec import ChainSpec
from arnold_pipelines.megaplan.types import CliError


def _base(enabled: bool = True) -> dict[str, object]:
    return {
        "milestones": [{"label": "plan", "idea": "make progress"}],
        "fresh_child_admission": {
            "enabled": enabled,
            "authority_journal_path": ".megaplan/authority/journal.sqlite",
            "wbc_ledger_path": ".megaplan/wbc/attempts.sqlite",
            "custody_lease_dir": ".megaplan/custody/leases",
            "approval_receipt": "operator-approved-independent-child:v1",
            "approval_actor": "operator",
            "parent_occurrence_digest": "sha256:parent",
            "blocker_or_phase_result_hash": "sha256:blocker",
            "normalized_failure_kind": "stalled",
            "chain_identity": "critique-ledger-accountability-v3-r7",
            "source_revision": "r7-source",
        },
    }


def test_legacy_chain_specs_have_no_fresh_child_admission() -> None:
    spec = ChainSpec.from_dict({"milestones": []})
    assert spec.fresh_child_admission is None


def test_fresh_child_admission_parses_strict_owner_and_lineage_bindings() -> None:
    spec = ChainSpec.from_dict(_base())
    admission = spec.fresh_child_admission
    assert admission is not None and admission.enabled
    assert admission.chain_identity == "critique-ledger-accountability-v3-r7"
    assert admission.authority_journal_path == ".megaplan/authority/journal.sqlite"


def test_enabled_fresh_child_admission_requires_source_revision() -> None:
    raw = _base()
    config = raw["fresh_child_admission"]
    assert isinstance(config, dict)
    config.pop("source_revision")
    with pytest.raises(CliError, match="source_revision"):
        ChainSpec.from_dict(raw)


def test_fresh_child_admission_rejects_unknown_keys() -> None:
    raw = _base()
    config = raw["fresh_child_admission"]
    assert isinstance(config, dict)
    config["projection_path"] = ".megaplan/status.json"
    with pytest.raises(CliError, match="projection_path"):
        ChainSpec.from_dict(raw)


def test_owned_path_rejects_escape_and_symlink(tmp_path: Path) -> None:
    from arnold_pipelines.megaplan.chain.fresh_child_launch import (
        FreshChildLaunchError,
        _resolve_owned_path,
    )

    with pytest.raises(FreshChildLaunchError, match="below the child workspace"):
        _resolve_owned_path(tmp_path, "../outside.sqlite", "owner")

    external = tmp_path.parent / "external-owner-dir"
    external.mkdir(exist_ok=True)
    link = tmp_path / "link"
    link.symlink_to(external, target_is_directory=True)
    with pytest.raises(FreshChildLaunchError, match="child workspace|symlink"):
        _resolve_owned_path(tmp_path, "link/journal.sqlite", "owner")


def test_supervisor_persists_cursor_before_fresh_child_owner_admission() -> None:
    """Guard the crash window that would mint a second plan/child on replay."""

    from arnold_pipelines.megaplan.supervisor import chain_runner

    source = inspect.getsource(chain_runner.run_chain)
    assert "_admit_fresh_child_for_plan" not in source
    save = source.index("chain_spec.save_chain_state(spec_path, chain_state)")
    ensure = source.index("_ensure_fresh_child_for_plan", save)
    drive = source.index("driver.drive", ensure)
    assert save < ensure < drive


def test_production_on_box_factory_binds_real_owners_and_closed_targets(
    tmp_path: Path,
) -> None:
    """The actual ``--on-box`` factory reaches the real owner boundary."""
    from arnold_pipelines.megaplan.chain.fresh_child_launch import (
        provision_fresh_child_authority,
    )
    from arnold_pipelines.megaplan.chain.spec import FreshChildAdmissionSpec
    from arnold_pipelines.megaplan.cloud.cli import _provider_for_action
    from arnold_pipelines.megaplan.cloud.spec import (
        CloudSpec,
        CodexSpec,
        MegaplanSpec,
        RepoSpec,
        ResourcesSpec,
        SshSpec,
    )
    from arnold_pipelines.run_authority.journal import RunAuthorityJournal

    owners = tmp_path / "owners"
    owners.mkdir()
    chain_path = tmp_path / "chain.yaml"
    chain_path.write_text("milestones: []\n", encoding="utf-8")
    admission = FreshChildAdmissionSpec(
        enabled=True,
        authority_journal_path="owners/authority.sqlite",
        wbc_ledger_path="owners/wbc.sqlite",
        custody_lease_dir="owners/leases",
        approval_receipt="sha256:" + "a" * 64,
        approval_actor="operator",
        parent_occurrence_digest="sha256:" + "b" * 64,
        blocker_or_phase_result_hash="sha256:" + "c" * 64,
        normalized_failure_kind="blocked",
        chain_identity="production-fixture",
        source_revision="source-fixture",
        session="fixture-session",
        chain="fixture-chain",
        phase="launch",
        task="launch",
    )
    cloud = CloudSpec(
        provider="ssh",
        repo=RepoSpec(url="https://github.com/example/app.git", workspace="/workspace/app"),
        agents={"default": "codex"},
        codex=CodexSpec(),
        mode="idle",
        megaplan=MegaplanSpec(),
        resources=ResourcesSpec(),
        secrets=[],
        ssh=SshSpec(host="fixture-host", container="fixture-container"),
    )
    provider = _provider_for_action(
        cloud,
        SimpleNamespace(on_box=True, cloud_action="chain", session=None),
    )
    from arnold_pipelines.megaplan.cloud.providers.on_box import OnBoxProvider
    assert isinstance(provider, OnBoxProvider)
    common = {
        "provider": "ssh",
        "workspace": "/workspace/app",
        "session": "fixture-session",
        "source_revision": "source-fixture",
        "boundary": "controller",
        "chain_spec": str(chain_path),
        "operation": "repository_prepare",
        "request": "cloud-chain-request:fixture",
        "provider_host": "fixture-host",
        "provider_container": "fixture-container",
    }
    context, receipt, _authority = provision_fresh_child_authority(
        root=tmp_path,
        spec_path=chain_path,
        spec=admission,
        launch_context=common,
        provider=provider,
        operation_id="cloud-chain:fixture",
        request_id="cloud-chain-request:fixture",
        upload_destinations=("/workspace/app/idea.md",),
    )
    assert provider.fresh_child_authority_context is context
    assert receipt.authority.grant.capabilities == (
        "file_upload",
        "launch_dispatch",
        "repository_prepare",
        "ssh_engine_invocation",
    )
    assert context.wbc.store._db_path == owners / "wbc.sqlite"
    journal = RunAuthorityJournal(owners / "authority.sqlite")
    assert journal.read_view(receipt.request.run_id, receipt.request.run_revision).cursor == 8

    upload = {**common, "operation": "file_upload", "destination": "/workspace/app/idea.md"}
    assert context.read(capability="file_upload", target_binding=upload)["capability"] == "file_upload"
    with pytest.raises(Exception, match="target is not an admitted action descriptor"):
        context.read(
            capability="file_upload",
            target_binding={**upload, "destination": "/workspace/app/wrong.md"},
        )
    dispatch = {
        **common,
        "operation": "cloud-chain:fixture",
        "boundary": "dispatch",
    }
    assert context.read(capability="launch_dispatch", target_binding=dispatch)["capability"] == "launch_dispatch"
    with pytest.raises(Exception, match="target is not an admitted action descriptor"):
        context.read(
            capability="launch_dispatch",
            target_binding={**dispatch, "operation": "cloud-chain:wrong"},
        )
    with pytest.raises(Exception, match="capability is not in the admitted grant"):
        context.read(capability="not-admitted", target_binding=dispatch)

    provision_fresh_child_authority(
        root=tmp_path,
        spec_path=chain_path,
        spec=admission,
        launch_context=common,
        provider=provider,
        operation_id="cloud-chain:fixture",
        request_id="cloud-chain-request:fixture",
        upload_destinations=("/workspace/app/idea.md",),
    )
    assert journal.read_view(receipt.request.run_id, receipt.request.run_revision).cursor == 8


@pytest.mark.parametrize("expire_before_engine", [False, True], ids=["accept-and-replay", "revoked"])
def test_launch_epic_on_box_cli_rereads_real_owners_before_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    expire_before_engine: bool,
) -> None:
    """The exact on-box CLI route keeps admission and the engine owner reread real."""
    import hashlib
    import json

    from agentbox.config import AgentBoxConfig
    from agentbox.tmux import SessionStatus
    from arnold_pipelines.megaplan.cloud import chain_drive, cli as cloud_cli
    from arnold_pipelines.megaplan.cloud.providers.on_box import OnBoxProvider
    import yaml

    revision = "d" * 40
    project = tmp_path / "project"
    initiative = project / ".megaplan" / "initiatives" / "input-fixture"
    briefs = initiative / "briefs"
    briefs.mkdir(parents=True)
    (initiative / "NORTHSTAR.md").write_text("north star\n", encoding="utf-8")
    (briefs / "m1.md").write_text("make one bounded test\n", encoding="utf-8")
    source_chain = initiative / "chain.yaml"
    source_chain.write_text(
        yaml.safe_dump(
            {
                "anchors": {"north_star": "NORTHSTAR.md"},
                "milestones": [
                    {
                        "label": "m1",
                        "idea": ".megaplan/initiatives/input-fixture/briefs/m1.md",
                    }
                ],
                "fresh_child_admission": {
                    "enabled": True,
                    "authority_journal_path": "owners/authority.sqlite",
                    "wbc_ledger_path": "owners/wbc.sqlite",
                    "custody_lease_dir": "owners/leases",
                    "approval_receipt": "sha256:771e41594e39d2328637b75abd90acb4c8b19966862f29db3a55cfc4d97f585a",
                    "approval_actor": "operator",
                    "parent_occurrence_digest": "sha256:" + "b" * 64,
                    "blocker_or_phase_result_hash": "sha256:" + "c" * 64,
                    "normalized_failure_kind": "blocked",
                    "chain_identity": "on-box-cli-fixture",
                    "source_revision": revision,
                    "run_revision": revision,
                    "session": "fixture-session",
                    "chain": "fixture-chain",
                    "phase": "launch",
                    "task": "launch",
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    cloud_yaml = project / "cloud.yaml"
    cloud_yaml.write_text(
        f"""provider: ssh
repo:
  url: https://github.com/example/app.git
  branch: main
  workspace: /workspace/on-box-fixture
megaplan:
  ref: {revision}
  src_path: /workspace/arnold
  runtime_python: /usr/bin/python3
ssh:
  host: fixture-host
  container: fixture-container
chain_session: fixture-session
""",
        encoding="utf-8",
    )
    slug = "on-box-cli-fixture-unique"

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    cloud_cli.build_cloud_parser(subparsers)
    args = parser.parse_args(
        [
            "cloud",
            "launch-epic",
            str(source_chain),
            "--on-box",
            "--slug",
            slug,
            "--no-git-refresh",
            "--cloud-yaml",
            str(cloud_yaml),
        ]
    )
    assert args.on_box is True
    assert args.cloud_action == "launch-epic"

    runtime_root = (tmp_path / "runtime").resolve()
    runtime_root.mkdir()
    interpreter = (tmp_path / "runtime-venv" / "bin" / "python").resolve()
    interpreter.parent.mkdir(parents=True)
    interpreter.write_text("#!/bin/sh\n", encoding="utf-8")
    interpreter.chmod(0o755)
    manifest_path = (tmp_path / "runtime-manifest.json").resolve()
    dependency_generation = {
        "id": "e" * 64,
        "frozen_spec_sha256": "e" * 64,
        "interpreter_path": str(interpreter),
        "venv_digest": "f" * 64,
        "created": "2026-01-01T00:00:00+00:00",
    }
    manifest_path.write_text(
        json.dumps(
            {
                "schema": "1",
                "runtime_id": "runtime-on-box-fixture",
                "generation": 1,
                "epic_id": "on-box-cli-fixture",
                "state": "active",
                "owner": "test",
                "base": {
                    "ref": revision,
                    "commit": revision,
                    "editable_install_path": "",
                    "venv_path": "",
                },
                "epic": {
                    "branch": "epic/on-box-cli-fixture",
                    "worktree_path": str(runtime_root),
                    "venv_path": "",
                    "runtime_root": str(runtime_root),
                    "expected_head": revision,
                    "repair_bin": "",
                    "deps_lockfile": "",
                    "dependency_generation": dependency_generation,
                },
                "indirection": {
                    "host_path": "",
                    "container_path": "",
                    "mount_table": [],
                    "execution_namespace": "",
                    "verified_head": "",
                    "last_verified_at": "",
                    "attestation": {"module_file": "", "module_digest": "", "mount_id": ""},
                },
                "policy": {"policy_sha": "", "model_policy_sha": "", "sync_policy": ""},
                "promotions": [],
                "timestamps": {"created": "", "updated": "", "closed": ""},
                "gc_policy": "",
                "commands": [],
            }
        ),
        encoding="utf-8",
    )
    manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    runtime_identity = chain_drive._canonical_runtime_identity(str(runtime_root), revision)
    runtime_binding = {
        "manifest_path": str(manifest_path),
        "runtime_src": str(runtime_root),
        "runtime_source": str(runtime_root),
        "runtime_revision": revision,
        "runtime_id": "runtime-on-box-fixture",
        "runtime_identity": runtime_identity,
        "runtime_identity_raw": {
            "runtime_id": "runtime-on-box-fixture",
            "epic_id": "on-box-cli-fixture",
            "runtime_source": str(runtime_root),
            "runtime_revision": revision,
        },
        "dependency_generation": dependency_generation,
        "manifest_sha256": manifest_sha,
        "manifest_identity": manifest_sha,
    }

    selected_providers: list[OnBoxProvider] = []
    original_provider_for_action = cloud_cli._provider_for_action

    def _capture_provider(spec, parsed_args):
        provider = original_provider_for_action(spec, parsed_args)
        selected_providers.append(provider)
        return provider

    monkeypatch.setattr(cloud_cli, "_provider_for_action", _capture_provider)
    monkeypatch.setattr(cloud_cli, "_materialized_deploy_dir", lambda _spec: nullcontext())
    monkeypatch.setattr(cloud_cli, "_ensure_repo_checkout", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cloud_cli, "_ensure_chain_runtime_binding", lambda **_kwargs: runtime_binding)
    monkeypatch.setattr(
        cloud_cli,
        "_cloud_launch_collision_observation",
        lambda _provider, launch_ctx: {
            "status": "none",
            "namespace": launch_ctx.session_name,
            "evidence": {
                "verified": True,
                "exists": False,
                "session": launch_ctx.session_name,
            },
        },
    )
    monkeypatch.setattr(
        cloud_cli,
        "_cloud_launch_capacity_observation",
        lambda *_args: {"status": "available", "disk": 1, "inode": 1, "output": 0, "temp": 1},
    )
    monkeypatch.setattr(
        cloud_cli,
        "_cloud_launch_network_observation",
        lambda *_args: {"status": "available", "transport": "local"},
    )
    monkeypatch.setattr(
        cloud_cli,
        "_cloud_launch_credentials_observation",
        lambda *_args: {"status": "present", "identity": "fixture", "transport": "on-box"},
    )
    effects: list[tuple[str, object]] = []
    monkeypatch.setattr(
        OnBoxProvider,
        "upload_file",
        lambda self, source, dest: effects.append(("file", dest)),
    )

    config = AgentBoxConfig(
        workspace_root=tmp_path,
        ops_store_root=tmp_path / "ops",
        runs_root=tmp_path / "runs",
        locks_root=tmp_path / "locks",
    )
    dispatches: list[list[str]] = []
    monkeypatch.setattr(chain_drive, "load_agentbox_config", lambda: config)
    monkeypatch.setattr(chain_drive, "_validate_live_runtime", lambda _binding: None)
    monkeypatch.setattr(chain_drive, "_probe_live_collision", lambda _session: None)
    monkeypatch.setattr(chain_drive, "run_tmux", lambda argv: dispatches.append(list(argv)))

    def _observe(session: str, expected_identity=None) -> SessionStatus:
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

    monkeypatch.setattr(chain_drive, "inspect_session", _observe)

    if expire_before_engine:
        original_invoke = OnBoxProvider.invoke_launch_engine

        def _expire_then_invoke(self, request):
            context = self.fresh_child_authority_context
            assert context is not None
            context.custody.store.expire(
                lease_id=context.receipt.custody.lease_id,
                idempotency_key="test-revoke-before-engine",
            )
            return original_invoke(self, request)

        monkeypatch.setattr(OnBoxProvider, "invoke_launch_engine", _expire_then_invoke)

    first_rc = cloud_cli.run_cloud_cli(project, args)
    assert selected_providers
    assert isinstance(selected_providers[0], OnBoxProvider)
    assert selected_providers[0].fresh_child_authority_context is not None
    assert effects and any(kind == "file" for kind, _destination in effects)
    output = capsys.readouterr().out

    if expire_before_engine:
        assert first_rc == 1
        assert '"reason": "G5A_REMOTE_BLOCKED"' in output
        assert dispatches == []
        return

    assert first_rc == 0
    assert '"result": "ACCEPTED"' in output
    assert len(dispatches) == 1

    # An exact CLI replay re-opens the same admitted owners and durable launch
    # envelope, but the authoritative operation store prevents redispatch.
    assert cloud_cli.run_cloud_cli(project, args) == 0
    replay_output = capsys.readouterr().out
    assert '"reason": "replay"' in replay_output
    assert len(dispatches) == 1
