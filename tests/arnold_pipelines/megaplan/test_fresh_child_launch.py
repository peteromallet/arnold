from __future__ import annotations

import argparse
from contextlib import contextmanager, nullcontext
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
    owners.mkdir(mode=0o700)
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


def _admit_worker_child(root: Path):
    import json

    from arnold_pipelines.megaplan.chain import _ensure_fresh_child_for_plan
    from arnold_pipelines.megaplan.chain.spec import (
        ChainSpec,
        ChainState,
        FreshChildAdmissionSpec,
        MilestoneSpec,
    )

    root.mkdir(parents=True, exist_ok=True)
    plan_dir = root / ".megaplan" / "plans" / "child-plan"
    plan_dir.mkdir(parents=True)
    (plan_dir / "state.json").write_text(
        '{"name":"child-plan","current_state":"initialized"}', encoding="utf-8"
    )
    (plan_dir / "idea_snapshot.md").write_text("bounded child\n", encoding="utf-8")
    spec_path = root / "chain.yaml"
    spec_path.write_text("milestones: []\n", encoding="utf-8")
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
        chain_identity="worker-child-fixture",
        source_revision="source-revision",
        run_revision="source-revision",
    )
    milestone = MilestoneSpec(label="m1", idea="bounded child")
    chain = ChainSpec(milestones=[milestone], fresh_child_admission=admission)
    chain_state = ChainState(current_milestone_index=0, current_plan_name="child-plan")
    pointer = _ensure_fresh_child_for_plan(
        root=root,
        spec_path=spec_path,
        spec=chain,
        state=chain_state,
        milestone=milestone,
        milestone_index=0,
        plan_name="child-plan",
    )
    assert pointer is not None
    projected = json.loads(
        (plan_dir / "state.json").read_text(encoding="utf-8")
    )["meta"]["fresh_child_admission"]
    assert projected == pointer
    return plan_dir, pointer


def _worker_dispatch_for_phase(plan_dir: Path, pointer, phase: str, invocation: str):
    from arnold_pipelines.megaplan.chain.fresh_child_launch import phase_wbc_handoff
    from arnold_pipelines.megaplan.custody.worker_dispatch_wbc import (
        build_worker_dispatch_spec,
    )

    state = {
        "name": "child-plan",
        "iteration": 1,
        "config": {"project_dir": str(plan_dir.parent.parent.parent)},
        "meta": {"current_invocation_id": invocation},
        "active_step": {
            "run_id": invocation,
            "_phase_wbc": phase_wbc_handoff(
                pointer,
                plan_dir=plan_dir,
                step=phase,
                invocation_id=invocation,
            ),
        },
    }
    dispatch = build_worker_dispatch_spec(
        plan_dir=plan_dir,
        state=state,
        step=phase,
        agent="codex",
        selected_spec="codex:gpt-fixture",
        route_kind="direct",
    )
    assert dispatch is not None
    return dispatch


def test_canonical_production_handler_projects_child_into_real_dispatch_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from arnold_pipelines.megaplan.handlers import shared
    from arnold_pipelines.megaplan.workers._impl import WorkerResult

    plan_dir, pointer = _admit_worker_child(tmp_path / "handler-production")
    provider_calls: list[str] = []
    captured: dict[str, object] = {}

    @contextmanager
    def guard(_plan_dir: Path):
        yield

    def set_active(current, *args, **kwargs):
        del args, kwargs
        current["active_step"] = {"phase": "plan", "run_id": "handler-run"}
        return "handler-run"

    def run_worker(*args, **kwargs):
        del args
        dispatch = kwargs["wbc_dispatch"]
        captured["dispatch"] = dispatch
        dispatch.run(
            lambda _start: provider_calls.append("plan") or {"success": True}
        )
        return (
            WorkerResult(
                payload={"success": True},
                raw_output="ok",
                duration_ms=1,
                cost_usd=0.0,
                session_id="handler-session",
                worker_channel="external-test-stub",
            ),
            "codex",
            "fresh",
            False,
        )

    monkeypatch.setattr(shared, "apply_profile_expansion", lambda *a, **k: None)
    monkeypatch.setattr(shared, "set_active_step", set_active)
    monkeypatch.setattr(shared, "save_state_merge_meta", lambda *a, **k: None)
    monkeypatch.setattr(shared, "phase_result_guard", guard)
    monkeypatch.setattr(shared.worker_module, "run_step_with_worker", run_worker)
    state = {
        "name": "child-plan",
        "iteration": 1,
        "config": {"project_dir": str(plan_dir.parent.parent.parent)},
        "meta": {
            "current_invocation_id": "handler-invocation",
            "fresh_child_admission": pointer,
        },
    }
    worker, agent, mode, refreshed = shared._run_worker(
        "plan",
        state,
        plan_dir,
        argparse.Namespace(production_intent=True, phase_model=[]),
        root=plan_dir.parent.parent.parent,
        resolved=("codex", "fresh", False, "gpt-fixture"),
    )

    assert captured["dispatch"] is not None
    assert provider_calls == ["plan"]
    assert state["active_step"]["_phase_wbc"]["projected_from_fresh_child"] is True
    assert (worker.payload, agent, mode, refreshed) == (
        {"success": True},
        "codex",
        "fresh",
        False,
    )


def test_canonical_child_runs_two_common_wbc_phases_then_terminal_cas_once(
    tmp_path: Path,
) -> None:
    """The production admission→adapter path retains one child identity."""
    from arnold.workflow.execution_attempt_ledger import AttemptEventType
    from arnold_pipelines.megaplan.chain.fresh_child_launch import (
        FreshChildLaunchError,
        _close_loaded_context,
        _load_admitted_child,
        phase_wbc_handoff,
        terminalize_fresh_child,
    )

    plan_dir, pointer = _admit_worker_child(tmp_path / "multi-phase")
    provider_calls: list[str] = []
    attempts = []
    source_versions = []
    target_descriptors = []
    for phase in ("plan", "critique"):
        dispatch = _worker_dispatch_for_phase(
            plan_dir, pointer, phase, f"invocation-{phase}"
        )
        attempts.append(dispatch.attempt_id)
        source_versions.append(
            dispatch.start_event.payload["fresh_child_run_revision"]
        )
        target_descriptors.append(
            dispatch.start_event.payload["fresh_child_target_descriptor_digest"]
        )
        result = dispatch.run(
            lambda _start, phase=phase: provider_calls.append(phase)
            or {"success": True}
        )
        assert result.terminal.append_result.event.event_type is AttemptEventType.COMPLETED

    assert provider_calls == ["plan", "critique"]
    assert len(set(attempts)) == 2
    assert source_versions == ["source-revision", "source-revision"]
    assert len(set(target_descriptors)) == 1
    context, _ = _load_admitted_child(pointer, plan_dir=plan_dir)
    reservation = context.wbc.read_reservation(
        context.receipt.identity.wbc_attempt_id, context.receipt.identity.glek
    )
    assert reservation is not None
    assert reservation.reservation.reservation_count == 1
    _close_loaded_context(context)

    payload = {
        "schema": "arnold.megaplan.fresh_child_terminal.v1",
        "milestone_label": "m1",
        "milestone_index": 0,
        "plan_name": "child-plan",
        "outcome_status": "done",
    }
    first = terminalize_fresh_child(
        pointer, plan_dir=plan_dir, outcome_kind="COMPLETED", outcome_payload=payload
    )
    replay = terminalize_fresh_child(
        pointer, plan_dir=plan_dir, outcome_kind="COMPLETED", outcome_payload=payload
    )
    assert first["is_duplicate"] is False
    assert replay["is_duplicate"] is True
    context, _ = _load_admitted_child(pointer, plan_dir=plan_dir)
    assert context.wbc.store.get_global_effect_outcome(
        context.receipt.identity.wbc_attempt_id, context.receipt.identity.glek
    ) is not None
    replay_reservation = context.wbc.read_reservation(
        context.receipt.identity.wbc_attempt_id, context.receipt.identity.glek
    )
    assert replay_reservation is not None
    assert replay_reservation.reservation.reservation_count == 1
    assert context.journal.read_view(
        context.receipt.identity.run_id, context.receipt.identity.run_revision
    ).cursor == 8
    _close_loaded_context(context)
    with pytest.raises(FreshChildLaunchError, match="terminal or ineligible"):
        phase_wbc_handoff(pointer, plan_dir=plan_dir, step="review")
    assert provider_calls == ["plan", "critique"]


def test_fresh_child_expiry_blocks_provider_and_records_local_failure(
    tmp_path: Path,
) -> None:
    from arnold.workflow.execution_attempt_ledger import AttemptEventType
    from arnold_pipelines.megaplan.chain.fresh_child_launch import (
        FreshChildLaunchError,
        _close_loaded_context,
        _load_admitted_child,
    )

    plan_dir, pointer = _admit_worker_child(tmp_path / "expired-before")
    dispatch = _worker_dispatch_for_phase(plan_dir, pointer, "plan", "inv-before")
    context, _ = _load_admitted_child(pointer, plan_dir=plan_dir)
    context.custody.store.expire(
        lease_id=context.receipt.custody.lease_id,
        idempotency_key="expire-before-provider",
    )
    _close_loaded_context(context)
    provider_calls: list[bool] = []
    with pytest.raises(FreshChildLaunchError, match="expired|custody_ref"):
        dispatch.run(lambda _start: provider_calls.append(True))
    assert provider_calls == []
    event_types = [
        event.event_type
        for event in dispatch.facade._ledger_store.read_events(dispatch.attempt_id)
    ]
    assert event_types == [
        AttemptEventType.STARTED,
        AttemptEventType.FAILED,
    ]


def test_fresh_child_authority_loss_after_provider_never_records_success(
    tmp_path: Path,
) -> None:
    from arnold.workflow.execution_attempt_ledger import AttemptEventType
    from arnold_pipelines.megaplan.chain.fresh_child_launch import (
        _close_loaded_context,
        _load_admitted_child,
    )
    from arnold_pipelines.megaplan.custody.common_worker_dispatch import (
        PostLaunchIndeterminateError,
    )

    plan_dir, pointer = _admit_worker_child(tmp_path / "expired-after")
    dispatch = _worker_dispatch_for_phase(plan_dir, pointer, "plan", "inv-after")
    context, _ = _load_admitted_child(pointer, plan_dir=plan_dir)
    provider_calls: list[bool] = []

    def external_stub(_start):
        provider_calls.append(True)
        context.custody.store.expire(
            lease_id=context.receipt.custody.lease_id,
            idempotency_key="expire-after-provider",
        )
        _close_loaded_context(context)
        return {"success": True}

    with pytest.raises(PostLaunchIndeterminateError, match="authority changed"):
        dispatch.run(external_stub)
    assert provider_calls == [True]
    event_types = [
        event.event_type
        for event in dispatch.facade._ledger_store.read_events(dispatch.attempt_id)
    ]
    assert event_types == [
        AttemptEventType.STARTED,
        AttemptEventType.FAILED,
    ]


def test_fresh_child_tamper_missing_store_and_wrong_scope_fail_closed(
    tmp_path: Path,
) -> None:
    import json

    from arnold_pipelines.megaplan.chain.fresh_child_launch import (
        FreshChildLaunchError,
        _load_admitted_child,
        phase_wbc_handoff,
    )

    tamper_dir, tamper_pointer = _admit_worker_child(tmp_path / "tamper")
    receipt_path = Path(tamper_pointer["receipt_path"])
    raw = json.loads(receipt_path.read_text(encoding="utf-8"))
    raw["request"]["source_revision"] = "tampered"
    receipt_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(FreshChildLaunchError, match="digest drift"):
        phase_wbc_handoff(tamper_pointer, plan_dir=tamper_dir, step="plan")

    missing_dir, missing_pointer = _admit_worker_child(tmp_path / "missing")
    missing_payload = json.loads(
        Path(missing_pointer["receipt_path"]).read_text(encoding="utf-8")
    )
    missing_wbc = Path(missing_payload["owner_paths"]["wbc_ledger"])
    missing_wbc.unlink()
    with pytest.raises(FreshChildLaunchError, match="WBC ledger is unavailable"):
        phase_wbc_handoff(missing_pointer, plan_dir=missing_dir, step="plan")
    assert not missing_wbc.exists()

    scope_dir, scope_pointer = _admit_worker_child(tmp_path / "scope")
    context, _ = _load_admitted_child(scope_pointer, plan_dir=scope_dir)
    with pytest.raises(Exception, match="target is not an admitted action descriptor"):
        context.read(
            capability="execute",
            target_binding={
                "boundary": "child_worker_dispatch",
                "workspace": str(tmp_path / "wrong-workspace"),
            },
        )


def test_fresh_child_rejects_receipt_and_owner_symlink_substitution(
    tmp_path: Path,
) -> None:
    import json

    from arnold_pipelines.megaplan.chain.fresh_child_launch import (
        FreshChildLaunchError,
        phase_wbc_handoff,
    )

    receipt_dir, receipt_pointer = _admit_worker_child(tmp_path / "receipt-link")
    receipt = Path(receipt_pointer["receipt_path"])
    receipt_real = receipt.with_suffix(".held.json")
    receipt.rename(receipt_real)
    receipt.symlink_to(receipt_real)
    with pytest.raises(FreshChildLaunchError, match="receipt is unavailable or unsafe"):
        phase_wbc_handoff(receipt_pointer, plan_dir=receipt_dir, step="plan")

    owner_dir, owner_pointer = _admit_worker_child(tmp_path / "owner-link")
    owner_payload = json.loads(
        Path(owner_pointer["receipt_path"]).read_text(encoding="utf-8")
    )
    ledger = Path(owner_payload["owner_paths"]["wbc_ledger"])
    ledger_real = ledger.with_suffix(".held.sqlite")
    ledger.rename(ledger_real)
    ledger.symlink_to(ledger_real)
    with pytest.raises(FreshChildLaunchError, match="WBC ledger.*symlink|WBC ledger.*unsafe"):
        phase_wbc_handoff(owner_pointer, plan_dir=owner_dir, step="plan")

    permission_dir, permission_pointer = _admit_worker_child(
        tmp_path / "owner-permission"
    )
    permission_payload = json.loads(
        Path(permission_pointer["receipt_path"]).read_text(encoding="utf-8")
    )
    authority_parent = Path(
        permission_payload["owner_paths"]["authority_journal"]
    ).parent
    authority_parent.chmod(0o755)
    with pytest.raises(FreshChildLaunchError, match="private directory"):
        phase_wbc_handoff(permission_pointer, plan_dir=permission_dir, step="plan")

    sidecar_dir, sidecar_pointer = _admit_worker_child(tmp_path / "sidecar-link")
    sidecar_payload = json.loads(
        Path(sidecar_pointer["receipt_path"]).read_text(encoding="utf-8")
    )
    sidecar = Path(sidecar_payload["owner_paths"]["wbc_ledger"] + "-wal")
    sidecar_target = tmp_path / "foreign-wal"
    sidecar_target.write_bytes(b"not a canonical WAL")
    if sidecar.exists():
        sidecar.rename(sidecar.with_suffix(".held-wal"))
    sidecar.symlink_to(sidecar_target)
    with pytest.raises(FreshChildLaunchError, match="WBC ledger sidecar is unsafe"):
        phase_wbc_handoff(sidecar_pointer, plan_dir=sidecar_dir, step="plan")


def test_fresh_child_rejects_sqlite_aba_replacement_and_leaks_no_owner_fds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json
    import os
    import shutil

    from arnold_pipelines.megaplan.chain import fresh_child_launch as launch

    plan_dir, pointer = _admit_worker_child(tmp_path / "sqlite-aba")
    payload = json.loads(Path(pointer["receipt_path"]).read_text(encoding="utf-8"))
    authority = Path(payload["owner_paths"]["authority_journal"])
    wbc = Path(payload["owner_paths"]["wbc_ledger"])
    identities = {
        (os.stat(authority).st_dev, os.stat(authority).st_ino),
        (os.stat(wbc).st_dev, os.stat(wbc).st_ino),
    }

    def matching_owner_fds() -> int:
        return sum(
            identity in identities for identity in launch._open_fd_identities().values()
        )

    before = matching_owner_fds()
    for _ in range(4):
        launch.read_fresh_child_authority(pointer, plan_dir=plan_dir)
    assert matching_owner_fds() == before

    saved = authority.with_suffix(".original.sqlite")
    replacement = authority.with_suffix(".replacement.sqlite")
    attached = authority.with_suffix(".attached.sqlite")
    shutil.copyfile(authority, replacement)
    original_connect = launch.sqlite3.connect
    raced = False

    def racing_connect(database, *args, **kwargs):
        nonlocal raced
        if not raced and str(database).startswith(authority.as_uri()):
            raced = True
            authority.rename(saved)
            replacement.rename(authority)
            connection = original_connect(database, *args, **kwargs)
            authority.rename(attached)
            saved.rename(authority)
            return connection
        return original_connect(database, *args, **kwargs)

    monkeypatch.setattr(launch.sqlite3, "connect", racing_connect)
    provider_calls: list[bool] = []
    with pytest.raises(launch.FreshChildLaunchError, match="descriptor-verified"):
        launch.phase_wbc_handoff(pointer, plan_dir=plan_dir, step="plan")
    assert raced
    assert provider_calls == []
    assert (os.stat(authority).st_dev, os.stat(authority).st_ino) in identities


@pytest.mark.parametrize(
    ("outcome_kind", "outcome_status"),
    [
        ("COMPLETED", "done"),
        ("FAILED", "failed"),
        ("BLOCKED", "authority_divergence"),
        ("BLOCKED", "milestone_validation_blocked"),
    ],
)
def test_chain_child_terminal_helper_accepts_one_truthful_outcome(
    tmp_path: Path, outcome_kind: str, outcome_status: str
) -> None:
    from arnold_pipelines.megaplan.chain import _terminalize_fresh_child_for_plan
    from arnold_pipelines.megaplan.chain.fresh_child_launch import (
        _close_loaded_context,
        _load_admitted_child,
    )
    from arnold_pipelines.megaplan.chain.spec import ChainState, MilestoneSpec

    plan_dir, pointer = _admit_worker_child(tmp_path / outcome_kind.lower())
    milestone = MilestoneSpec(label="m1", idea="bounded child")
    state = ChainState(
        current_milestone_index=0,
        current_plan_name="child-plan",
        metadata={"fresh_child_admissions": {"m1": pointer}},
    )
    call = lambda: _terminalize_fresh_child_for_plan(
        root=plan_dir.parent.parent.parent,
        state=state,
        milestone=milestone,
        milestone_index=0,
        plan_name="child-plan",
        outcome_kind=outcome_kind,
        outcome_status=outcome_status,
    )
    call()
    call()
    context, _ = _load_admitted_child(pointer, plan_dir=plan_dir)
    accepted = context.wbc.store.get_global_effect_outcome(
        context.receipt.identity.wbc_attempt_id, context.receipt.identity.glek
    )
    assert accepted is not None
    assert accepted.outcome_kind == outcome_kind
    assert accepted.outcome_payload["outcome_status"] == outcome_status
    _close_loaded_context(context)
