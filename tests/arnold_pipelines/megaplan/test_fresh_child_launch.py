from __future__ import annotations

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


def test_production_ssh_factory_binds_real_owners_and_closed_targets(tmp_path: Path) -> None:
    """The supported factory reaches the real RA/WBC/Custody boundary."""
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
        SimpleNamespace(on_box=False, cloud_action="chain", session=None),
    )
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
    assert provider._ssh_effect_adapter._protocol._store._db_path == owners / "wbc.sqlite"
    journal = RunAuthorityJournal(owners / "authority.sqlite")
    assert journal.read_view(receipt.request.run_id, receipt.request.run_revision).cursor == 8

    upload = {**common, "operation": "file_upload", "destination": "/workspace/app/idea.md"}
    assert context.read(capability="file_upload", target_binding=upload)["capability"] == "file_upload"
    with pytest.raises(Exception, match="target is not an admitted action descriptor"):
        context.read(
            capability="file_upload",
            target_binding={**upload, "destination": "/workspace/app/wrong.md"},
        )
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
