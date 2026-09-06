from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import yaml

from arnold.workflow.effect_protocol import EffectProtocol

from arnold_pipelines.megaplan.chain.spec import ChainState, save_chain_state
from arnold_pipelines.megaplan.cloud.providers.local import LocalProvider
from arnold_pipelines.megaplan.cloud.providers.on_box import OnBoxProvider
from arnold_pipelines.megaplan.cloud.providers.ssh import SshProvider
from arnold_pipelines.megaplan.cloud.template import render_ensure_repo_command
from arnold_pipelines.megaplan.types import CliError
from arnold_pipelines.megaplan.cloud.spec import (
    CloudSpec,
    CodexSpec,
    LocalSpec,
    MegaplanSpec,
    RepoSpec,
    ResourcesSpec,
    SshSpec,
)
from arnold_pipelines.megaplan.cloud.ssh_effect_adapter import SshEffectAdapter
from arnold_pipelines.megaplan.cloud.supervise import cloud_supervise_tick
from arnold_pipelines.megaplan.cloud.wrapper_acceptance_gate import check_wrapper_acceptance_gate
from arnold_pipelines.megaplan.custody.action_validator import GateResult
from arnold_pipelines.megaplan.custody.process_adapter_wbc import process_adapter_wbc_dir


def _authorized_effect_adapter() -> SshEffectAdapter:
    """Real adapter with an explicit authorized gate so the action-off
    ssh_exec transport runs through the Step 13F gate in tests."""
    protocol = MagicMock(spec=EffectProtocol)
    reservation = MagicMock()
    reservation.global_logical_effect_key = "glek-ssh-exec-test"
    protocol.reserve_and_start.return_value = reservation
    return SshEffectAdapter(
        protocol,
        action_gate_check=lambda _boundary, _target_key: GateResult.AUTHORIZED,
        production_enabled=False,
    )


def _records(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _cloud_spec(tmp_path: Path, *, provider: str) -> CloudSpec:
    return CloudSpec(
        provider=provider,
        repo=RepoSpec(
            url="https://github.com/example/app.git",
            workspace=str((tmp_path / "workspace").resolve()),
            workspace_explicit=True,
        ),
        agents={"default": "codex"},
        codex=CodexSpec(),
        mode="idle",
        megaplan=MegaplanSpec(),
        resources=ResourcesSpec(),
        secrets=[],
        local=LocalSpec(),
        ssh=SshSpec(host="example.test"),
    )


def test_local_provider_ssh_exec_records_process_adapter_wbc(
    tmp_path: Path,
    monkeypatch,
) -> None:
    class TestLocalProvider(LocalProvider):
        def _deploy_dir(self) -> Path:
            path = tmp_path / "deploy"
            path.mkdir(parents=True, exist_ok=True)
            return path

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.local.shutil.which",
        lambda _name: "docker",
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.local.subprocess.run",
        lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, "ok\n", ""),
    )

    provider = TestLocalProvider(_cloud_spec(tmp_path, provider="local"))
    provider.ssh_exec("echo ok")

    sidecar = process_adapter_wbc_dir(
        tmp_path / "deploy",
        producer_family="cloud_provider_adapter",
        adapter_name="TestLocalProvider",
    )
    records = _records(sidecar / "events.ndjson")

    assert [record["payload"]["boundary_event"] for record in records] == ["started", "terminal"]
    assert records[0]["payload"]["surface"] == "ssh_exec"
    assert records[-1]["payload"]["indeterminate_hooks"] == {
        "signal": "reserved_for_m10_hardening",
        "crash": "reserved_for_m10_hardening",
    }


def test_on_box_provider_records_process_adapter_wbc(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = tmp_path / "workspace"
    control_root = tmp_path / "control-plane"
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.on_box._ON_BOX_CONTROL_ROOT",
        control_root,
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.on_box.subprocess.run",
        lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, "ok\n", ""),
    )

    provider = OnBoxProvider(_cloud_spec(tmp_path, provider="ssh"))
    assert not workspace.exists()
    provider.ssh_exec("echo ok")
    assert not workspace.exists()

    sidecar = process_adapter_wbc_dir(
        provider._process_adapter_evidence_root(),
        producer_family="cloud_provider_adapter",
        adapter_name="OnBoxProvider",
    )
    records = _records(sidecar / "events.ndjson")

    assert [record["payload"]["boundary_event"] for record in records] == ["started", "terminal"]
    assert records[-1]["payload"]["status"] == "completed"


def test_on_box_manifest_probe_preserves_json_stdout_without_git_classification(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A compound manifest probe must not lose its binding JSON.

    The probe contains Git identity checks, but no authenticated Git
    operation. An unreachable ``else`` branch must not classify the whole
    command as Git and suppress its stdout at the credential boundary.
    """
    from arnold_pipelines.megaplan.cloud.cli import _chain_runtime_probe_and_create_command
    from arnold_pipelines.megaplan.cloud.runtime_manifest import (
        EPIC_REQUIRED,
        TOP_LEVEL_REQUIRED,
    )

    control_root = tmp_path / "control-plane"
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.on_box._ON_BOX_CONTROL_ROOT",
        control_root,
    )

    source = tmp_path / "source"
    subprocess.run(["git", "init", "-q", "-b", "main", str(source)], check=True)
    wrapper = source / "arnold_pipelines/megaplan/cloud/wrappers/arnold-runtime-create"
    wrapper.parent.mkdir(parents=True)
    (source / "arnold_pipelines/__init__.py").write_text("\n", encoding="utf-8")
    # The reviewed runtime-create wrapper validates the complete operational
    # wrapper set before emitting a manifest.  Keep this clean fixture
    # faithful to that provenance contract instead of testing against a
    # deliberately incomplete checkout.
    for name in (
        "arnold-runtime-create",
        "arnold-supervisor-runtime",
        "arnold-supervise",
        "arnold-chain",
        "arnold-run",
        "arnold-launch-boundary",
    ):
        path = wrapper.parent / name
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)
    # The source-bound probe imports this checkout before checking its dirty
    # state. Ignore interpreter bytecode so that the clean provenance check is
    # about source files, not an incidental import cache.
    (source / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(
        [
            "git", "-C", str(source), "-c", "user.name=Test",
            "-c", "user.email=test@example.com", "commit", "-qm", "seed",
        ],
        check=True,
    )
    head = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir()
    manifest = manifest_dir / "demo.json"
    payload = {key: {} for key in TOP_LEVEL_REQUIRED}
    payload.update(
        schema="1", generation=1, epic_id="demo", state="active",
        owner="test", runtime_id="demo-runtime",
    )
    payload["base"] = {
        "ref": "main", "commit": head, "editable_install_path": "",
        "venv_path": str(tmp_path / "venv"),
    }
    payload["epic"] = {
        key: {
            "branch": "fixer/demo", "worktree_path": str(tmp_path / "runtime"),
            "venv_path": str(tmp_path / "venv"), "runtime_root": str(tmp_path / "runtime"),
            "expected_head": head, "repair_bin": str(tmp_path / "repair"),
            "deps_lockfile": str(tmp_path / "uv.lock"),
        }[key]
        for key in EPIC_REQUIRED
    }
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    command = _chain_runtime_probe_and_create_command(
        slug="demo", manifest_path=str(manifest), runtime_src=str(tmp_path / "runtime"),
        manifest_dir=str(manifest_dir), base_repo=str(source), base_ref="main",
        policy_path=None, runtime_python=sys.executable,
    )
    assert 'git -C "$BASE_REPO" fetch' not in command

    result = OnBoxProvider(_cloud_spec(tmp_path, provider="ssh")).ssh_exec(command)

    assert result.returncode == 0
    binding = json.loads(result.stdout)
    runtime_identity = binding.pop("runtime_identity")
    assert binding == {
        "created": 0, "epic_id": "demo", "present": True,
        "runtime_id": "demo-runtime", "runtime_revision": head,
        "runtime_src": str(tmp_path / "runtime"),
    }
    assert runtime_identity == {
        "content_sha256": runtime_identity["content_sha256"],
        "direct_url": {},
        "editable_revision": "",
        "editable_root": "",
        "import_root": str(tmp_path / "runtime"),
        "imports": {
            "arnold": str(tmp_path / "runtime" / "arnold/__init__.py"),
            "arnold_pipelines": str(tmp_path / "runtime" / "arnold_pipelines/__init__.py"),
            "megaplan": str(tmp_path / "runtime" / "arnold_pipelines/megaplan/__init__.py"),
        },
        "pth": [],
        "source_revision": head,
    }
    assert len(runtime_identity["content_sha256"]) == 64


def test_on_box_compound_wrapper_inherits_path_only_git_helper_and_json_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Internal Git in a wrapper receives auth without hiding wrapper JSON."""

    control_root = tmp_path / "control-plane"
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.on_box._ON_BOX_CONTROL_ROOT",
        control_root,
    )
    credential_file = tmp_path / "git-credentials"
    secret = "ghp_internal_wrapper_secret_never_logged"
    credential_file.write_text(
        f"https://x-access-token:{secret}@github.com\n", encoding="utf-8"
    )
    monkeypatch.setenv("ARNOLD_ON_BOX_GIT_CREDENTIAL_FILE", str(credential_file))
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(argv, **kwargs):
        calls.append((list(argv), dict(kwargs)))
        return subprocess.CompletedProcess(
            argv,
            0,
            '{"internal_push": "authorized", "note": "git push / git ls-remote"}\n',
            "",
        )

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.on_box.subprocess.run", fake_run
    )
    provider = OnBoxProvider(_cloud_spec(tmp_path, provider="ssh"))
    # Git words in JSON, a heredoc, and a comment must not classify this
    # compound wrapper as a direct Git authentication operation.
    command = """cat <<'JSON'
{"internal_push":"authorized","note":"git push / git ls-remote"}
JSON
# git push origin main
"""

    result = provider.ssh_exec(command)

    assert result.returncode == 0
    assert json.loads(result.stdout) == {
        "internal_push": "authorized",
        "note": "git push / git ls-remote",
    }
    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert secret not in repr(argv)
    env = kwargs["env"]
    assert isinstance(env, dict)
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert env["GIT_CONFIG_VALUE_0"] == f"store --file={credential_file}"
    assert secret not in repr(env)
    journal = (
        process_adapter_wbc_dir(
            provider._process_adapter_evidence_root(),
            producer_family="cloud_provider_adapter",
            adapter_name="OnBoxProvider",
        )
        / "events.ndjson"
    ).read_text(encoding="utf-8")
    assert secret not in journal


def test_on_box_checkout_clones_after_external_wbc_evidence(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """The first on-box receipt must not precreate the clone destination."""
    from arnold_pipelines.megaplan.cloud.cli import _ensure_repo_checkout

    control_root = tmp_path / "control-plane"
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.on_box._ON_BOX_CONTROL_ROOT",
        control_root,
    )
    source = tmp_path / "source"
    subprocess.run(["git", "init", "--bare", str(source)], check=True, capture_output=True)
    seed = tmp_path / "seed"
    subprocess.run(["git", "init", "-b", "main", str(seed)], check=True, capture_output=True)
    (seed / "README").write_text("seed\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(seed), "add", "README"], check=True)
    subprocess.run(
        ["git", "-C", str(seed), "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "seed"],
        check=True,
        capture_output=True,
    )
    subprocess.run(["git", "-C", str(seed), "remote", "add", "origin", str(source)], check=True)
    subprocess.run(["git", "-C", str(seed), "push", "origin", "main"], check=True, capture_output=True)

    workspace = tmp_path / "workspace"
    spec = _cloud_spec(tmp_path, provider="ssh")
    spec = replace(spec, repo=replace(spec.repo, url=str(source), workspace=str(workspace)))
    provider = OnBoxProvider(spec)
    provider.ssh_exec("echo before-clone")
    assert not workspace.exists()
    _ensure_repo_checkout(spec, provider, relay=False)
    assert (workspace / ".git").is_dir()
    assert (workspace / "README").read_text(encoding="utf-8") == "seed\n"


def test_on_box_github_checkout_uses_file_helper_without_secret_in_argv_or_wbc(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """On-box Git receives only the durable helper path, never its contents."""
    from arnold_pipelines.megaplan.cloud.cli import _ensure_repo_checkout

    control_root = tmp_path / "control-plane"
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.on_box._ON_BOX_CONTROL_ROOT",
        control_root,
    )
    credential_file = tmp_path / "git-credentials"
    secret = "ghp_super_secret_value_1234567890"
    credential_file.write_text(
        f"https://x-access-token:{secret}@github.com\n", encoding="utf-8"
    )
    monkeypatch.setenv("ARNOLD_ON_BOX_GIT_CREDENTIAL_FILE", str(credential_file))
    spec = replace(
        _cloud_spec(tmp_path, provider="ssh"),
        repo=replace(
            _cloud_spec(tmp_path, provider="ssh").repo,
            url=f"https://user:{secret}@github.com:443/example/app.git",
        ),
    )
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(argv, **kwargs):
        calls.append((list(argv), dict(kwargs)))
        return subprocess.CompletedProcess(argv, 0, "ok\n", "")

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.on_box.subprocess.run", fake_run
    )
    provider = OnBoxProvider(spec)
    auth_calls: list[str] = []
    original_git_auth_exec = provider.git_auth_exec

    def recording_git_auth_exec(command: str):
        auth_calls.append(command)
        return original_git_auth_exec(command)

    monkeypatch.setattr(provider, "git_auth_exec", recording_git_auth_exec)
    _ensure_repo_checkout(spec, provider, relay=False)

    argv, kwargs = calls[0]
    assert len(auth_calls) == 1
    assert secret not in auth_calls[0]
    assert secret not in " ".join(argv)
    assert secret not in render_ensure_repo_command(spec.repo)
    assert "github.com:443/example/app.git" in " ".join(argv)
    env = kwargs["env"]
    assert isinstance(env, dict)
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert env["GIT_CONFIG_VALUE_0"] == f"store --file={credential_file}"
    assert all(secret not in str(value) for value in env.values())
    journal = (
        process_adapter_wbc_dir(
            provider._process_adapter_evidence_root(),
            producer_family="cloud_provider_adapter",
            adapter_name="OnBoxProvider",
        )
        / "events.ndjson"
    ).read_text()
    assert secret not in journal


def test_on_box_github_checkout_missing_helper_is_typed_and_does_not_spawn(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """An authenticated on-box Git operation fails closed before transport."""
    from arnold_pipelines.megaplan.cloud.cli import _ensure_repo_checkout

    control_root = tmp_path / "control-plane"
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.on_box._ON_BOX_CONTROL_ROOT",
        control_root,
    )
    missing = tmp_path / "missing-git-credentials"
    monkeypatch.setenv("ARNOLD_ON_BOX_GIT_CREDENTIAL_FILE", str(missing))
    spec = _cloud_spec(tmp_path, provider="ssh")
    spawned = False

    def fail_run(*_args, **_kwargs):
        nonlocal spawned
        spawned = True
        raise AssertionError("Git transport must not start without helper")

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.on_box.subprocess.run", fail_run
    )
    with pytest.raises(CliError) as caught:
        _ensure_repo_checkout(spec, OnBoxProvider(spec), relay=False)
    assert caught.value.code == "on_box_git_auth_unavailable"
    assert "missing-git-credentials" not in caught.value.message
    assert not spawned


@pytest.mark.parametrize("command", ["git push origin main", "git ls-remote origin main"])
def test_on_box_git_auth_failure_is_typed_and_redacted(
    tmp_path: Path,
    monkeypatch,
    command: str,
) -> None:
    helper = tmp_path / "git-credentials"
    secret = "ghp_auth_failure_secret_1234567890"
    helper.write_text(f"https://x-access-token:{secret}@github.com\n", encoding="utf-8")
    monkeypatch.setenv("ARNOLD_ON_BOX_GIT_CREDENTIAL_FILE", str(helper))
    control_root = tmp_path / "control-plane"
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.on_box._ON_BOX_CONTROL_ROOT",
        control_root,
    )

    def auth_failure(argv, **kwargs):
        return subprocess.CompletedProcess(
            argv, 128, "", f"fatal: Authentication failed for {secret}\n"
        )

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.on_box.subprocess.run", auth_failure
    )
    provider = OnBoxProvider(_cloud_spec(tmp_path, provider="ssh"))
    with pytest.raises(CliError) as caught:
        provider.git_auth_exec(command)
    assert caught.value.code == "on_box_git_auth_failed"
    assert secret not in str(caught.value)
    journal = (
        process_adapter_wbc_dir(
            provider._process_adapter_evidence_root(),
            producer_family="cloud_provider_adapter",
            adapter_name="OnBoxProvider",
        )
        / "events.ndjson"
    )
    assert secret not in journal.read_text(encoding="utf-8")


@pytest.mark.parametrize("command", ["git push origin main", "git ls-remote origin main"])
def test_on_box_direct_git_auth_output_is_redacted_by_explicit_call_site(
    tmp_path: Path,
    monkeypatch,
    command: str,
) -> None:
    """Direct Git callers opt into redaction; shell wrappers do not."""

    helper = tmp_path / "git-credentials"
    helper.write_text(
        "https://x-access-token:helper-secret@example.test\n", encoding="utf-8"
    )
    monkeypatch.setenv("ARNOLD_ON_BOX_GIT_CREDENTIAL_FILE", str(helper))
    control_root = tmp_path / "control-plane"
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.on_box._ON_BOX_CONTROL_ROOT",
        control_root,
    )
    calls: list[tuple[list[str], dict[str, object]]] = []
    leaked_output = "remote https://x-access-token:secret-in-output@example.test\n"

    def successful_git(argv, **kwargs):
        calls.append((list(argv), dict(kwargs)))
        return subprocess.CompletedProcess(argv, 0, leaked_output, leaked_output)

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.on_box.subprocess.run",
        successful_git,
    )
    result = OnBoxProvider(_cloud_spec(tmp_path, provider="ssh")).git_auth_exec(command)

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""
    assert len(calls) == 1
    assert "secret-in-output" not in repr(calls[0])


def test_ssh_provider_ssh_exec_records_process_adapter_wbc(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.shutil.which",
        lambda name: name,
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.tempfile.gettempdir",
        lambda: str(tmp_path),
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.subprocess.run",
        lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, "ok\n", ""),
    )

    provider = SshProvider(
        _cloud_spec(tmp_path, provider="ssh"),
        ssh_effect_adapter=_authorized_effect_adapter(),
    )
    provider.ssh_exec("pwd")

    sidecar = process_adapter_wbc_dir(
        tmp_path / "arnold-process-adapter-wbc" / "ssh",
        producer_family="cloud_provider_adapter",
        adapter_name="SshProvider",
    )
    records = _records(sidecar / "events.ndjson")

    assert [record["payload"]["boundary_event"] for record in records] == ["started", "terminal"]
    assert records[0]["payload"]["surface"] == "ssh_exec"


def test_wrapper_acceptance_gate_records_closed_process_adapter_wbc(tmp_path: Path) -> None:
    spec_path = tmp_path / "chain.yaml"
    spec_path.write_text(
        yaml.safe_dump(
            {
                "milestones": [{"label": "M5A", "idea": "m5a.md"}],
                "successors": [
                    {
                        "chain_spec_path": "next/chain.yaml",
                        "label": "M6",
                        "require_accepted_transaction": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    state = ChainState(
        current_milestone_index=0,
        completion_contract_mode="enforce",
        completed=[
            {
                "label": "M5A",
                "plan": "m5a-plan",
                "milestone_index": 0,
                "transaction_id": "tx-001",
                "snapshot_hash": "sha256:test",
                "source_commit_ref": "a" * 40,
                "runtime_identity": "ci-main",
                "acceptance_receipt": {
                    "transaction_id": "tx-001",
                    "snapshot_hash": "sha256:test",
                    "milestone_label": "M5A",
                    "milestone_index": 0,
                    "plan_name": "m5a-plan",
                },
            }
        ],
    )
    save_chain_state(spec_path, state)

    result = check_wrapper_acceptance_gate(
        str(spec_path),
        workspace=str(tmp_path),
        caller_kind="watchdog",
    )

    sidecar = process_adapter_wbc_dir(
        tmp_path,
        producer_family="cloud_wrapper_adapter",
        adapter_name="wrapper_acceptance_gate",
    )
    records = _records(sidecar / "events.ndjson")

    assert result["gate_open"] is False
    assert records[-1]["payload"]["status"] == "gate_closed"
    assert records[-1]["payload"]["outcome"] == "blocked"


def test_cloud_supervise_tick_records_process_adapter_wbc(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.cli.cloud_chain_status_payload",
        lambda *_args, **_kwargs: {
            "effective_status": "running",
            "runner": {"status": "running"},
            "sync": {},
            "pr": {},
            "logs": {},
            "provider_consistency": {},
            "chain_state": {},
        },
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.cli._resolve_remote_chain_spec",
        lambda *_args, **_kwargs: "/workspace/app/chain.yaml",
    )

    report = cloud_supervise_tick(
        tmp_path,
        argparse.Namespace(session="demo"),
        SimpleNamespace(provider="ssh", repo=SimpleNamespace(workspace="/workspace/app")),
        SimpleNamespace(),
    )

    sidecar = process_adapter_wbc_dir(
        tmp_path,
        producer_family="cloud_supervision_adapter",
        adapter_name="cloud_supervise_tick",
    )
    records = _records(sidecar / "events.ndjson")

    assert report["next_action"] == "noop"
    assert records[-1]["payload"]["status"] == "running"
    assert records[-1]["payload"]["outcome"] == "succeeded"
