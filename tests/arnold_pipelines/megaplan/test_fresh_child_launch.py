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
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
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
    from arnold_pipelines.megaplan.cloud import chain_drive

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

    engine_calls: list[dict[str, object]] = []

    def _engine(request: dict[str, object]) -> dict[str, object]:
        engine_calls.append(request)
        return {
            "schema": "arnold.megaplan.cloud_launch_response.v1",
            "result": "UNKNOWN",
            "reason": "fixture_gate_only",
            "invoked": True,
        }

    monkeypatch.setattr(chain_drive, "execute_authoritative_launch", _engine)
    response = provider.invoke_launch_engine({"authority": context.read(
        capability="launch_dispatch", target_binding=dispatch,
    )})
    assert response["result"] == "UNKNOWN"
    assert len(engine_calls) == 1

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


def test_launch_epic_on_box_cli_uses_bound_authority_before_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The normal ``launch-epic --on-box`` route selects and binds on-box authority."""
    from arnold.runtime.durable_ops import LaunchEnvelope
    from arnold_pipelines.megaplan.cloud import chain_drive, cli as cloud_cli
    from arnold_pipelines.megaplan.cloud.providers.on_box import OnBoxProvider
    import yaml

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
                    "source_revision": "source-fixture",
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
        """provider: ssh\nrepo:\n  url: https://github.com/example/app.git\n  branch: main\n  workspace: /workspace/on-box-fixture\nmegaplan:\n  ref: source-fixture\n  src_path: /workspace/arnold\n  runtime_python: /usr/bin/python3\nssh:\n  host: fixture-host\n  container: fixture-container\nchain_session: fixture-session\n""",
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

    selected_providers: list[OnBoxProvider] = []
    original_provider_for_action = cloud_cli._provider_for_action

    def _capture_provider(spec, parsed_args):
        provider = original_provider_for_action(spec, parsed_args)
        selected_providers.append(provider)
        return provider

    monkeypatch.setattr(cloud_cli, "_provider_for_action", _capture_provider)
    monkeypatch.setattr(cloud_cli, "_materialized_deploy_dir", lambda _spec: nullcontext())
    monkeypatch.setattr(cloud_cli, "_ensure_repo_checkout", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        cloud_cli,
        "_ensure_chain_runtime_binding",
        lambda **_kwargs: {
            "manifest_path": "/workspace/on-box-fixture/runtime.json",
            "runtime_src": "/workspace/on-box-fixture/runtime",
            "runtime_source": "/workspace/on-box-fixture/runtime",
            "runtime_revision": "source-fixture",
            "runtime_id": "fixture-runtime",
            "runtime_identity": {"runtime_id": "fixture-runtime"},
            "runtime_identity_raw": {"runtime_id": "fixture-runtime"},
            "dependency_generation": {},
            "manifest_sha256": "a" * 64,
            "manifest_identity": "a" * 64,
        },
    )
    monkeypatch.setattr(cloud_cli, "_cloud_launch_collision_observation", lambda *_args: {"status": "clear"})
    monkeypatch.setattr(
        cloud_cli,
        "_cloud_launch_capacity_observation",
        lambda *_args: {
            "status": "available",
            "disk": 1,
            "inode": 1,
            "output": 0,
            "temp": 1,
        },
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
    monkeypatch.setattr(OnBoxProvider, "upload_archive", lambda self, archive, dest: effects.append(("archive", dest)))
    monkeypatch.setattr(OnBoxProvider, "upload_file", lambda self, source, dest: effects.append(("file", dest)))
    engine_calls: list[dict[str, object]] = []

    def _accepted_engine(request: dict[str, object]) -> dict[str, object]:
        engine_calls.append(request)
        envelope = LaunchEnvelope.from_json(request["envelope"])
        return {
            "schema": "arnold.megaplan.cloud_launch_response.v1",
            "result": "ACCEPTED",
            "reason": "accepted",
            "invoked": True,
            "operation_id": envelope.operation_id,
            "request_id": envelope.request_id,
            "envelope_digest": envelope.digest,
        }

    monkeypatch.setattr(chain_drive, "execute_authoritative_launch", _accepted_engine)
    assert cloud_cli.run_cloud_cli(project, args) == 0
    assert len(selected_providers) == 1
    provider = selected_providers[0]
    assert isinstance(provider, OnBoxProvider)
    assert provider.fresh_child_authority_context is not None
    assert effects and any(kind == "file" for kind, _destination in effects)
    assert len(engine_calls) == 1
    output = capsys.readouterr().out
    assert '"result": "ACCEPTED"' in output
