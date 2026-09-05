from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentbox.config import AgentBoxConfig
from agentbox.credentials.backend import (
    CredentialBackendError,
    list_credentials,
    push_credential,
    push_guide,
    run_credential_tests,
)
from agentbox.operations import create_agentbox_operation
from agentbox.run_dirs import ensure_run_dir
from arnold_pipelines.megaplan.agentbox_adapter import (
    MEGAPLAN_CHAIN_OPERATION_TYPE,
    MegaplanChainHandler,
    MegaplanChainLaunchError,
)


def test_list_credentials_shows_status_without_values(tmp_path: Path) -> None:
    config = AgentBoxConfig(workspace_root=tmp_path / "workspace")
    env = {"GITHUB_TOKEN": "ghp_1234567890abcdef1234567890abcdef123456"}

    records = list_credentials(config, environ=env)

    github = next(record for record in records if record.name == "GITHUB_TOKEN")
    assert github.present is True
    assert github.provider == "github"
    assert github.pushed is False
    # No record should expose the actual token value.
    for record in records:
        assert record.name in env or not record.present


def test_push_credential_copies_value_and_records_metadata(tmp_path: Path) -> None:
    config = AgentBoxConfig(workspace_root=tmp_path / "workspace")
    env = {"GITHUB_TOKEN": "ghp_1234567890abcdef1234567890abcdef123456"}

    record = push_credential(config, "GITHUB_TOKEN", environ=env)

    assert record.pushed is True
    value_path = Path(config.credentials_root) / "GITHUB_TOKEN"
    assert value_path.read_text(encoding="utf-8") == env["GITHUB_TOKEN"]
    # Value file should be readable only by the owner.
    assert oct(value_path.stat().st_mode)[-3:] == "600"

    meta_path = Path(config.credentials_root) / "GITHUB_TOKEN.meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["name"] == "GITHUB_TOKEN"
    assert meta["source"] == "$GITHUB_TOKEN"
    assert meta["destination"] == str(value_path)
    assert "ghp_" not in json.dumps(meta)
    assert meta["audit"][-1]["event"] == "pushed"


def test_push_credential_rejects_missing_env_value(tmp_path: Path) -> None:
    config = AgentBoxConfig(workspace_root=tmp_path / "workspace")
    with pytest.raises(CredentialBackendError):
        push_credential(config, "GITHUB_TOKEN", environ={})


def test_push_guide_lists_missing_credentials(tmp_path: Path) -> None:
    config = AgentBoxConfig(workspace_root=tmp_path / "workspace")
    env = {"GITHUB_TOKEN": "ghp_1234567890abcdef1234567890abcdef123456"}

    guide = push_guide(config, environ=env)

    assert all(entry["name"] != "GITHUB_TOKEN" for entry in guide)
    openai = next((entry for entry in guide if entry["name"] == "OPENAI_API_KEY"), None)
    assert openai is not None
    assert "agentbox creds push OPENAI_API_KEY" in openai["setup"]


def test_test_credentials_passes_and_fails_with_fake_checkers(tmp_path: Path) -> None:
    config = AgentBoxConfig(workspace_root=tmp_path / "workspace")
    env = {
        "GITHUB_TOKEN": "ghp_1234567890abcdef1234567890abcdef123456",
        "OPENAI_API_KEY": "too-short",
    }

    fake_checkers = {
        "github": lambda name, value: (True, "github ok"),
        "openai": lambda name, value: (False, "openai bad"),
    }

    results = run_credential_tests(config, environ=env, checkers=fake_checkers)

    by_name = {result["name"]: result for result in results}
    assert by_name["GITHUB_TOKEN"]["ok"] is True
    assert by_name["GITHUB_TOKEN"]["status"] == "passed"
    assert by_name["OPENAI_API_KEY"]["ok"] is False
    assert by_name["OPENAI_API_KEY"]["status"] == "failed"

    meta_path = Path(config.credentials_root) / "GITHUB_TOKEN.meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["test_status"] == "passed"
    assert meta["last_tested"] is not None
    assert meta["test_message"] == "github ok"
    assert "ghp_" not in json.dumps(meta)
    assert meta["audit"][-1]["event"] == "tested"


def test_missing_required_credentials_block_chain_launch_and_return_fix_command(
    tmp_path: Path,
    monkeypatch,
) -> None:
    agentbox_config = AgentBoxConfig(workspace_root=tmp_path / "agentbox")
    operation_id = "chain-creds-1"
    project_root = tmp_path / "repo"
    project_root.mkdir()
    idea_file = project_root / "idea.md"
    idea_file.write_text("# idea", encoding="utf-8")
    spec_path = project_root / "chain.yaml"
    spec_path.write_text(
        "milestones:\n"
        "  - label: m1\n"
        f"    idea: {idea_file.name}\n",
        encoding="utf-8",
    )
    (project_root / "credentials.yaml").write_text(
        "credentials:\n"
        "  - name: GITHUB_TOKEN\n"
        "    provider: github\n"
        "    required: true\n",
        encoding="utf-8",
    )

    create_agentbox_operation(
        agentbox_config,
        operation_id,
        operation_type=MEGAPLAN_CHAIN_OPERATION_TYPE,
        command=["echo", "chain"],
    )
    run_paths = ensure_run_dir(agentbox_config, operation_id)
    credentials_root = Path(agentbox_config.credentials_root)
    assert not credentials_root.exists()

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.agentbox_adapter._record_for",
        lambda config, name, environ=None: SimpleNamespace(
            name=name,
            provider="github",
            present=False,
            pushed=False,
            test_status="untested",
        ),
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.agentbox_adapter.get_repo",
        lambda _config, _name: SimpleNamespace(path=project_root),
    )

    handler = MegaplanChainHandler()
    with pytest.raises(MegaplanChainLaunchError) as exc_info:
        handler.launch(
            agentbox_config,
            operation_id,
            repo_name="owner/repo",
            spec_path=spec_path,
        )

    exc = exc_info.value
    assert exc.kind == "credential_preflight_failed"
    assert "GITHUB_TOKEN" in str(exc)
    assert exc.diagnostics["fix_commands"] == ["agentbox creds push GITHUB_TOKEN"]
    assert exc.diagnostics["phase"] == "credential_preflight"
    assert not credentials_root.exists()
