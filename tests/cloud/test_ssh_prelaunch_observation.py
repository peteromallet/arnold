from __future__ import annotations

import argparse
import json
import shlex
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from arnold.workflow.effect_protocol import EffectProtocol

from arnold_pipelines.megaplan.cloud import cli as cloud_cli
from arnold_pipelines.megaplan.cloud.providers.ssh import SshProvider
from arnold_pipelines.megaplan.cloud.providers.ssh_preflight import (
    classify_container_inspect,
    container_inspect_command,
    parse_workspace_prelaunch_result,
    validate_container_name,
    validate_workspace_dir,
    workspace_prelaunch_command,
)
from arnold_pipelines.megaplan.cloud.spec import (
    CloudSpec,
    CodexSpec,
    MegaplanSpec,
    RepoSpec,
    ResourcesSpec,
    SshSpec,
    load_spec,
)
from arnold_pipelines.megaplan.cloud.ssh_effect_adapter import SshEffectAdapter
from arnold_pipelines.megaplan.custody.action_validator import GateResult
from arnold_pipelines.megaplan.types import CliError


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


def _spec(
    *,
    workspace_dir: str = "/opt/megaplan-cloud/workspace",
    container: str = "megaplan-cloud-agent",
    resources: ResourcesSpec | None = None,
    host: str = "example.invalid",
    user: str | None = None,
    port: int = 22,
    identity_file: str | None = None,
) -> CloudSpec:
    return CloudSpec(
        provider="ssh",
        repo=RepoSpec(url="https://example.invalid/repo.git"),
        agents={"default": "codex"},
        codex=CodexSpec(),
        mode="idle",
        megaplan=MegaplanSpec(),
        resources=resources or ResourcesSpec(),
        secrets=["OPENAI_API_KEY"],
        ssh=SshSpec(
            host=host,
            user=user,
            port=port,
            identity_file=identity_file,
            workspace_dir=workspace_dir,
            container=container,
        ),
    )


def _inspect_output(
    *,
    lifecycle: str = "running",
    workspace_source: str = "/opt/megaplan-cloud/workspace",
) -> str:
    state = {
        "Status": lifecycle,
        "Running": lifecycle in {"running", "paused", "restarting"},
        "Paused": lifecycle == "paused",
        "Restarting": lifecycle == "restarting",
        "OOMKilled": False,
        "ExitCode": 0 if lifecycle == "running" else 137,
        "Error": "",
        "StartedAt": "2026-08-02T00:00:00Z",
        "FinishedAt": "2026-08-02T00:01:00Z",
    }
    mounts = [
        {
            "Type": "bind",
            "Source": workspace_source,
            "Destination": "/workspace",
            "RW": True,
        }
    ]
    return (
        "\n".join(
            json.dumps(item)
            for item in (
                state,
                0,
                "container-id",
                "sha256:image",
                "megaplan-cloud-agent",
                mounts,
            )
        )
        + "\n"
    )


def _parse_capacity(
    *,
    returncode: int,
    stdout: str,
    stderr: str = "",
    workspace: str,
    min_free_bytes: int,
    min_free_inodes: int,
    receipt_reserve_bytes: int,
) -> dict[str, object]:
    return parse_workspace_prelaunch_result(
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        expected_workspace=workspace,
        min_free_bytes=min_free_bytes,
        min_free_inodes=min_free_inodes,
        receipt_reserve_bytes=receipt_reserve_bytes,
    )


def _capacity_payload(
    *,
    workspace: str = "/opt/megaplan-cloud/workspace",
    min_free_bytes: int = 0,
    min_free_inodes: int = 0,
    receipt_reserve_bytes: int = 0,
) -> dict[str, object]:
    return {
        "schema": "arnold.cloud.ssh_workspace_prelaunch.v2",
        "workspace": workspace,
        "thresholds": {
            "min_free_bytes": min_free_bytes,
            "min_free_inodes": min_free_inodes,
            "receipt_reserve_bytes": receipt_reserve_bytes,
        },
        "status": "go",
        "verdict": "GO",
        "checks": {
            "byte_floor": True,
            "inode_floor": True,
            "workspace_identity": True,
            "temp_volume": True,
            "output_bound": True,
        },
        "errors": [],
        "mount": {
            "st_dev": 1,
            "device_major": 0,
            "device_minor": 1,
            "inode": 2,
        },
        "temp_mount": {
            "st_dev": 1,
            "device_major": 0,
            "device_minor": 1,
            "inode": 3,
        },
        "capacity": {
            "free_bytes": min_free_bytes + receipt_reserve_bytes + 1,
            "free_inodes": min_free_inodes + 1,
            "temp_free_bytes": receipt_reserve_bytes + 1,
            "temp_free_inodes": 2,
        },
    }


def test_run_preserves_redacted_stderr_stdout_and_returncode_without_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "sk-this-is-a-sensitive-token"
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    monkeypatch.setenv("ARNOLD_REDACTION_ENABLED", "0")
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.shutil.which", lambda name: name
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.tempfile.gettempdir",
        lambda: str(tmp_path),
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.subprocess.run",
        lambda argv, **kwargs: subprocess.CompletedProcess(
            argv,
            23,
            f"stdout token={secret}",
            f"stderr Authorization: Bearer {secret}",
        ),
    )
    provider = SshProvider(_spec(), ssh_effect_adapter=_authorized_effect_adapter())

    with pytest.raises(CliError) as caught:
        provider.ssh_exec(f"tool --api-key={secret}")

    message = caught.value.message
    assert "returncode=23" in message
    assert "stderr:" in message and "stdout:" in message
    assert "***REDACTED***" in message
    assert secret not in message
    assert "tool --api-key" not in message
    evidence = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / "arnold-process-adapter-wbc" / "ssh").rglob("*.ndjson")
    )
    assert secret not in evidence
    assert "stdout" in evidence and "stderr" in evidence


def test_run_preserves_stdout_only_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.shutil.which", lambda name: name
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.tempfile.gettempdir",
        lambda: str(tmp_path),
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.subprocess.run",
        lambda argv, **kwargs: subprocess.CompletedProcess(
            argv, 1, "Error response from daemon: container is not running", ""
        ),
    )

    with pytest.raises(CliError) as caught:
        SshProvider(
            _spec(), ssh_effect_adapter=_authorized_effect_adapter()
        ).ssh_exec("stat /workspace")

    assert "returncode=1" in caught.value.message
    assert "stdout: Error response from daemon" in caught.value.message
    assert "stderr:" not in caught.value.message


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ("running", "running"),
        ("exited", "stopped"),
        ("dead", "stopped"),
        ("paused", "paused"),
        ("restarting", "restarting"),
    ],
)
def test_container_lifecycle_parsing(state: str, expected: str) -> None:
    result = classify_container_inspect(
        returncode=0,
        stdout=_inspect_output(lifecycle=state),
        stderr="",
        expected_container="megaplan-cloud-agent",
    )

    assert result["lifecycle"] == expected
    assert result["workspace_bind"]["source"] == "/opt/megaplan-cloud/workspace"
    expected_collector = "available" if expected == "running" else "unavailable"
    assert result["collector"]["status"] == expected_collector


def test_container_missing_is_typed_without_guessing_other_transport_errors() -> None:
    missing = classify_container_inspect(
        returncode=1,
        stdout="Error: No such container: megaplan-cloud-agent",
        stderr="",
        expected_container="megaplan-cloud-agent",
    )
    transport = classify_container_inspect(
        returncode=255,
        stdout="",
        stderr="ssh: Could not resolve hostname container-not-found.example",
        expected_container="megaplan-cloud-agent",
    )

    assert missing["lifecycle"] == "missing"
    assert transport["lifecycle"] == "unknown"


@pytest.mark.parametrize(
    ("returncode", "stdout", "stderr"),
    [
        (
            255,
            "Error: No such container: megaplan-cloud-agent",
            "ssh transport failed",
        ),
        (
            255,
            "",
            "banner: No such container: megaplan-cloud-agent",
        ),
        (
            1,
            "Error: No such container: megaplan-cloud-agent",
            "host banner",
        ),
        (1, "Error: No such container: a-different-container", ""),
    ],
)
def test_transport_or_mixed_diagnostics_never_become_container_missing(
    returncode: int, stdout: str, stderr: str
) -> None:
    payload = classify_container_inspect(
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        expected_container="megaplan-cloud-agent",
    )

    assert payload["status"] == "unknown"
    assert payload["lifecycle"] == "unknown"


def test_malformed_successful_container_state_is_unknown_not_stopped() -> None:
    stdout = (
        "\n".join(
            json.dumps(item)
            for item in ({}, 0, "container-id", "sha256:image", "image", [])
        )
        + "\n"
    )

    payload = classify_container_inspect(
        returncode=0,
        stdout=stdout,
        stderr="",
        expected_container="megaplan-cloud-agent",
    )

    assert payload["lifecycle"] == "unknown"
    assert payload["collector"]["status"] == "unavailable"


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("state", "Status", 1),
        ("state", "Running", "false"),
        ("state", "Paused", 0),
        ("state", "Restarting", "false"),
        ("state", "OOMKilled", "false"),
        ("state", "ExitCode", True),
        ("state", "ExitCode", "zero"),
        ("state", "Error", []),
        ("mount", "RW", "false"),
        ("mount", "Type", 1),
        ("mount", "Source", None),
        ("mount", "Destination", []),
    ],
)
def test_inspect_fields_require_exact_json_types(
    section: str, field: str, value: object
) -> None:
    parts = [json.loads(line) for line in _inspect_output().splitlines()]
    target = parts[0] if section == "state" else parts[5][0]
    target[field] = value
    payload = classify_container_inspect(
        returncode=0,
        stdout="\n".join(json.dumps(item) for item in parts) + "\n",
        stderr="",
        expected_container="megaplan-cloud-agent",
    )

    assert payload["status"] == "unknown"
    assert payload["lifecycle"] == "unknown"
    assert payload["collector"]["status"] == "unavailable"


@pytest.mark.parametrize(
    ("index", "value"), [(1, None), (2, 42), (3, ""), (1, "   ")]
)
def test_inspect_identity_fields_require_nonempty_strings(
    index: int, value: object
) -> None:
    parts = [json.loads(line) for line in _inspect_output().splitlines()]
    parts[index] = value
    payload = classify_container_inspect(
        returncode=0,
        stdout="\n".join(json.dumps(item) for item in parts) + "\n",
        stderr="",
        expected_container="megaplan-cloud-agent",
    )

    assert payload["lifecycle"] == "unknown"


def test_inspect_duplicate_state_fields_are_unknown() -> None:
    lines = _inspect_output().splitlines()
    lines[0] = lines[0].replace('"Running": true', '"Running": false, "Running": true')

    payload = classify_container_inspect(
        returncode=0,
        stdout="\n".join(lines) + "\n",
        stderr="",
        expected_container="megaplan-cloud-agent",
    )

    assert payload["lifecycle"] == "unknown"


@pytest.mark.parametrize(
    ("state_updates"),
    [
        {"Status": "running", "Running": False},
        {"Status": "exited", "Running": True},
        {"Status": "running", "Paused": True},
        {"Status": "restarting", "Paused": True, "Restarting": True},
    ],
)
def test_contradictory_container_state_is_unknown(
    state_updates: dict[str, object],
) -> None:
    parts = [json.loads(line) for line in _inspect_output().splitlines()]
    parts[0].update(state_updates)
    payload = classify_container_inspect(
        returncode=0,
        stdout="\n".join(json.dumps(item) for item in parts) + "\n",
        stderr="",
        expected_container="megaplan-cloud-agent",
    )

    assert payload["lifecycle"] == "unknown"


@pytest.mark.parametrize(
    "value",
    ["bad;docker rm -f victim", "bad name", "../container", "name\nother"],
)
def test_container_identifier_rejects_shell_injection(value: str) -> None:
    with pytest.raises(CliError):
        validate_container_name(value)
    with pytest.raises(CliError):
        container_inspect_command(value)


@pytest.mark.parametrize(
    "value",
    ["/", "relative/path", "/opt/work/../victim", "/opt/work\nrm -rf /", "/opt//work"],
)
def test_workspace_path_rejects_unsafe_or_ambiguous_targets(value: str) -> None:
    with pytest.raises(CliError):
        validate_workspace_dir(value)
    with pytest.raises(CliError):
        workspace_prelaunch_command(
            value,
            min_free_bytes=0,
            min_free_inodes=0,
            receipt_reserve_bytes=0,
        )


def test_actual_workspace_probe_fsyncs_wal_receipt_and_cleans_up(
    tmp_path: Path,
) -> None:
    command = workspace_prelaunch_command(
        str(tmp_path),
        min_free_bytes=0,
        min_free_inodes=0,
        receipt_reserve_bytes=4096,
    )

    result = subprocess.run(
        shlex.split(command), text=True, capture_output=True, check=False
    )
    payload = _parse_capacity(
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        workspace=str(tmp_path),
        min_free_bytes=0,
        min_free_inodes=0,
        receipt_reserve_bytes=4096,
    )

    assert payload["verdict"] == "GO", payload
    assert payload["checks"] == {
        "byte_floor": True,
        "inode_floor": True,
        "output_bound": True,
        "temp_volume": True,
        "workspace_identity": True,
    }
    assert list(tmp_path.glob(".arnold-prelaunch-*")) == []


def test_actual_workspace_probe_capacity_shortfall_is_no_go_and_cleans_up(
    tmp_path: Path,
) -> None:
    command = workspace_prelaunch_command(
        str(tmp_path),
        min_free_bytes=2**63,
        min_free_inodes=0,
        receipt_reserve_bytes=4096,
    )

    result = subprocess.run(
        shlex.split(command), text=True, capture_output=True, check=False
    )
    payload = _parse_capacity(
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        workspace=str(tmp_path),
        min_free_bytes=2**63,
        min_free_inodes=0,
        receipt_reserve_bytes=4096,
    )

    assert result.returncode == 3
    assert payload["verdict"] == "NO-GO"
    assert "prelaunch_free_bytes_below_reserve" in payload["errors"]
    assert list(tmp_path.glob(".arnold-prelaunch-*")) == []


@pytest.mark.parametrize(
    "error",
    [
        "prelaunch_free_inodes_below_reserve",
        "prelaunch_temp_volume_below_reserve",
        "capacity_observation_unproven",
    ],
)
def test_capacity_and_durability_failures_remain_typed_no_go(error: str) -> None:
    raw = json.dumps(
        {
                "schema": "arnold.cloud.ssh_workspace_prelaunch.v2",
            "workspace": "/opt/megaplan-cloud/workspace",
            "thresholds": {
                "min_free_bytes": 0,
                "min_free_inodes": 0,
                "receipt_reserve_bytes": 0,
            },
            "status": "no-go",
            "verdict": "NO-GO",
                "checks": {
                    "byte_floor": True,
                    "inode_floor": error != "prelaunch_free_inodes_below_reserve",
                    "workspace_identity": True,
                    "temp_volume": error != "prelaunch_temp_volume_below_reserve",
                    "output_bound": error != "capacity_observation_unproven",
                },
            "errors": [error],
            "mount": {
                "st_dev": 1,
                "device_major": 0,
                "device_minor": 1,
                "inode": 2,
            },
                "temp_mount": {
                    "st_dev": 1,
                    "device_major": 0,
                    "device_minor": 1,
                    "inode": 3,
                },
                "capacity": {
                    "free_bytes": 3,
                    "free_inodes": 4,
                    "temp_free_bytes": 3,
                    "temp_free_inodes": 4,
                },
        }
    )

    payload = _parse_capacity(
        returncode=3,
        stdout=raw,
        workspace="/opt/megaplan-cloud/workspace",
        min_free_bytes=0,
        min_free_inodes=0,
        receipt_reserve_bytes=0,
    )

    assert payload["status"] == "no-go"
    assert payload["verdict"] == "NO-GO"
    assert payload["errors"] == [error]


def test_unparseable_capacity_observation_is_unknown_no_go() -> None:
    payload = _parse_capacity(
        returncode=255,
        stdout="not-json",
        stderr="transport failed",
        workspace="/opt/megaplan-cloud/workspace",
        min_free_bytes=0,
        min_free_inodes=0,
        receipt_reserve_bytes=0,
    )

    assert payload["status"] == "unknown"
    assert payload["verdict"] == "NO-GO"
    assert payload["returncode"] == 255


@pytest.mark.parametrize(
    "case",
    [
        "wrong_schema",
        "missing_schema",
        "unknown_field",
        "wrong_workspace",
        "wrong_threshold",
        "string_capacity",
        "boolean_capacity",
        "malformed_mount",
        "false_check",
        "missing_check",
        "nonempty_errors",
        "insufficient_reported_capacity",
    ],
)
def test_malformed_or_contradictory_capacity_go_is_unknown_no_go(case: str) -> None:
    payload = _capacity_payload()
    expected_min_free_bytes = 0
    if case == "wrong_schema":
        payload["schema"] = "wrong"
    elif case == "missing_schema":
        del payload["schema"]
    elif case == "unknown_field":
        payload["extra"] = "not-allowlisted"
    elif case == "wrong_workspace":
        payload["workspace"] = "/wrong/workspace"
    elif case == "wrong_threshold":
        payload["thresholds"]["min_free_bytes"] = 1
    elif case == "string_capacity":
        payload["capacity"]["free_bytes"] = "1"
    elif case == "boolean_capacity":
        payload["capacity"]["free_inodes"] = True
    elif case == "malformed_mount":
        payload["mount"]["st_dev"] = "1"
    elif case == "false_check":
        payload["checks"]["output_bound"] = False
    elif case == "missing_check":
        del payload["checks"]["output_bound"]
    elif case == "nonempty_errors":
        payload["errors"] = ["failed"]
    elif case == "insufficient_reported_capacity":
        expected_min_free_bytes = 1
        payload["thresholds"]["min_free_bytes"] = 1
        payload["capacity"]["free_bytes"] = 0

    result = _parse_capacity(
        returncode=0,
        stdout=json.dumps(payload),
        workspace="/opt/megaplan-cloud/workspace",
        min_free_bytes=expected_min_free_bytes,
        min_free_inodes=0,
        receipt_reserve_bytes=0,
    )

    assert result["status"] == "unknown"
    assert result["verdict"] == "NO-GO"


def test_capacity_duplicate_json_fields_are_unknown_no_go() -> None:
    raw = json.dumps(_capacity_payload())
    raw = raw.replace('"schema":', '"schema":"decoy","schema":', 1)

    payload = _parse_capacity(
        returncode=0,
        stdout=raw,
        workspace="/opt/megaplan-cloud/workspace",
        min_free_bytes=0,
        min_free_inodes=0,
        receipt_reserve_bytes=0,
    )

    assert payload["status"] == "unknown"
    assert payload["verdict"] == "NO-GO"


@pytest.mark.parametrize(
    ("returncode", "stderr"), [(3, ""), (255, "transport failed"), (0, "warning")]
)
def test_capacity_go_cannot_contradict_process_evidence(
    returncode: int, stderr: str
) -> None:
    payload = _parse_capacity(
        returncode=returncode,
        stdout=json.dumps(_capacity_payload()),
        stderr=stderr,
        workspace="/opt/megaplan-cloud/workspace",
        min_free_bytes=0,
        min_free_inodes=0,
        receipt_reserve_bytes=0,
    )

    assert payload["status"] == "unknown"
    assert payload["verdict"] == "NO-GO"


def test_provider_rejects_wrong_workspace_bind_without_capacity_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.shutil.which", lambda name: name
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.tempfile.gettempdir",
        lambda: str(tmp_path),
    )

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(
            argv, 0, _inspect_output(workspace_source="/wrong/workspace"), ""
        )

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.subprocess.run", fake_run
    )

    payload = SshProvider(_spec()).observe_prelaunch_capacity()

    assert payload["verdict"] == "NO-GO"
    assert payload["errors"] == ["configured_workspace_bind_mismatch"]
    assert len(calls) == 1
    assert "docker inspect" in calls[0][-1]
    assert "python3" not in calls[0][-1]


def test_provider_capacity_observation_uses_only_fixed_inspect_and_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.shutil.which", lambda name: name
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.tempfile.gettempdir",
        lambda: str(tmp_path),
    )
    capacity = {
        "schema": "arnold.cloud.ssh_workspace_prelaunch.v2",
        "workspace": "/opt/megaplan-cloud/workspace",
        "thresholds": {
            "min_free_bytes": 1_073_741_824,
            "min_free_inodes": 10_000,
            "receipt_reserve_bytes": 1_048_576,
        },
        "status": "go",
        "verdict": "GO",
        "checks": {
            "byte_floor": True,
            "inode_floor": True,
            "workspace_identity": True,
            "temp_volume": True,
            "output_bound": True,
        },
        "errors": [],
        "mount": {
            "st_dev": 1,
            "device_major": 0,
            "device_minor": 1,
            "inode": 2,
        },
        "temp_mount": {
            "st_dev": 1,
            "device_major": 0,
            "device_minor": 1,
            "inode": 3,
        },
        "capacity": {
            "free_bytes": 2_147_483_648,
            "free_inodes": 20_000,
            "temp_free_bytes": 2_147_483_648,
            "temp_free_inodes": 20_000,
        },
    }

    def fake_run(argv, **kwargs):
        command = argv[-1]
        calls.append(command)
        if command.startswith("docker inspect"):
            return subprocess.CompletedProcess(argv, 0, _inspect_output(), "")
        assert command.startswith("python3 -c ")
        return subprocess.CompletedProcess(argv, 0, json.dumps(capacity) + "\n", "")

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.subprocess.run", fake_run
    )

    payload = SshProvider(_spec()).observe_prelaunch_capacity()

    assert payload["verdict"] == "GO"
    assert len(calls) == 2
    assert all("docker exec" not in command for command in calls)
    assert calls[0].startswith("docker inspect --type container")
    assert calls[1].startswith("python3 -c ")


def test_stopped_exact_container_can_have_host_capacity_go_without_collector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.shutil.which", lambda name: name
    )
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.tempfile.gettempdir",
        lambda: str(tmp_path),
    )
    capacity = _capacity_payload(
        min_free_bytes=1_073_741_824,
        min_free_inodes=10_000,
        receipt_reserve_bytes=1_048_576,
    )

    def fake_run(argv, **kwargs):
        if argv[-1].startswith("docker inspect"):
            return subprocess.CompletedProcess(
                argv, 0, _inspect_output(lifecycle="exited"), ""
            )
        return subprocess.CompletedProcess(argv, 0, json.dumps(capacity), "")

    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.subprocess.run", fake_run
    )

    payload = SshProvider(_spec()).observe_prelaunch_capacity()

    assert payload["verdict"] == "GO"
    assert payload["container"]["lifecycle"] == "stopped"
    assert payload["container"]["collector"]["status"] == "unavailable"


def test_provider_host_observation_rejects_non_allowlisted_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.shutil.which", lambda name: name
    )

    with pytest.raises(CliError, match="not allowlisted"):
        SshProvider(_spec())._host_observation("arbitrary-command")


@pytest.mark.parametrize(
    "host",
    [
        "-oProxyCommand=touch-decoy",
        " root@example.invalid",
        "root@example.invalid",
        "example.invalid\n-oProxyCommand=decoy",
        "example.invalid;decoy",
    ],
)
def test_provider_rejects_option_shaped_or_injected_ssh_hosts(
    host: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.shutil.which", lambda name: name
    )

    with pytest.raises(CliError, match="ssh.host"):
        SshProvider(_spec(host=host))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("user", "-oProxyCommand"),
        ("user", "root user"),
        ("user", "root\n-oProxyCommand"),
        ("port", True),
        ("port", 65536),
        ("identity_file", "-oProxyCommand=decoy"),
        ("identity_file", "/tmp/key\n-oProxyCommand=decoy"),
    ],
)
def test_provider_rejects_unsafe_ssh_transport_values(
    field: str, value: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.shutil.which", lambda name: name
    )

    with pytest.raises(CliError):
        SshProvider(_spec(**{field: value}))


def test_ssh_argv_terminates_options_before_validated_destination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "arnold_pipelines.megaplan.cloud.providers.ssh.shutil.which", lambda name: name
    )
    provider = SshProvider(
        _spec(
            host="[2001:db8::1]",
            user="deploy-user",
            port=2222,
            identity_file="/keys/deploy key",
        )
    )

    assert provider._ssh_destination_argv() == [
        "ssh",
        "-p",
        "2222",
        "-i",
        "/keys/deploy key",
        "--",
        "deploy-user@[2001:db8::1]",
    ]


def test_spec_loads_configured_prelaunch_reserves_and_rejects_negative(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cloud.yaml"
    path.write_text(
        "provider: ssh\n"
        "repo:\n  url: https://example.invalid/repo.git\n"
        "resources:\n"
        "  prelaunch_min_free_bytes: 1234\n"
        "  prelaunch_min_free_inodes: 56\n"
        "  prelaunch_receipt_reserve_bytes: 789\n"
        "ssh:\n  host: example.invalid\n",
        encoding="utf-8",
    )

    spec = load_spec(path)

    assert spec.resources.prelaunch_min_free_bytes == 1234
    assert spec.resources.prelaunch_min_free_inodes == 56
    assert spec.resources.prelaunch_receipt_reserve_bytes == 789
    path.write_text(
        path.read_text(encoding="utf-8").replace("1234", "-1"), encoding="utf-8"
    )
    with pytest.raises(CliError, match="non-negative integer"):
        load_spec(path)


def test_status_short_circuits_before_docker_exec_when_container_stopped() -> None:
    class Provider:
        def observe_container(self):
            return {
                "status": "available",
                "lifecycle": "stopped",
                "collector": {"status": "unavailable", "reason": "container_stopped"},
            }

        def status_payload(self, **kwargs):
            raise AssertionError("docker exec collector must not run")

    with pytest.raises(CliError) as caught:
        cloud_cli.cloud_status_payload(
            argparse.Namespace(plan=None), _spec(), Provider()
        )

    assert caught.value.code == "provider_collector_unavailable"
    assert caught.value.extra["container_observation"]["lifecycle"] == "stopped"


def test_status_all_short_circuits_before_snapshot_or_legacy_exec(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("MEGAPLAN_TRUSTED_CONTAINER", raising=False)

    class Provider:
        def observe_container(self):
            return {
                "status": "available",
                "lifecycle": "paused",
                "collector": {"status": "unavailable", "reason": "container_paused"},
            }

        def read_remote_file(self, path):
            raise AssertionError(f"snapshot read must not run: {path}")

        def ssh_exec(self, command):
            raise AssertionError(f"legacy docker exec must not run: {command}")

    rc = cloud_cli._run_status_all(
        _spec(), Provider(), args=argparse.Namespace(all=True, compact=True, since=None)
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert payload["container_observation"]["lifecycle"] == "paused"
    assert payload["collector"] == {
        "status": "unavailable",
        "reason": "container_paused",
    }


def test_chain_status_short_circuits_before_remote_file_reads() -> None:
    class Provider:
        def observe_container(self):
            return {
                "status": "available",
                "lifecycle": "missing",
                "collector": {"status": "unavailable", "reason": "container_missing"},
            }

        def read_remote_file(self, path):
            raise AssertionError(f"remote file read must not run: {path}")

    with pytest.raises(CliError) as caught:
        cloud_cli.cloud_chain_status_payload(
            Path("/repo"),
            argparse.Namespace(
                remote_spec="/workspace/initiative/chain.yaml", cloud_yaml=None
            ),
            _spec(),
            Provider(),
        )

    assert caught.value.code == "provider_collector_unavailable"
    assert caught.value.extra["container_observation"]["lifecycle"] == "missing"


def test_preflight_nonrunning_exposes_no_go_and_never_uses_ssh_exec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    project = tmp_path / "app"
    initiative = project / ".megaplan" / "initiatives" / "demo"
    (initiative / "briefs").mkdir(parents=True)
    subprocess.run(
        ["git", "init"], cwd=project, check=True, capture_output=True, text=True
    )
    (initiative / "NORTHSTAR.md").write_text("north star\n", encoding="utf-8")
    (initiative / "briefs" / "m1.md").write_text("idea\n", encoding="utf-8")
    spec_path = initiative / "chain.yaml"
    spec_path.write_text(
        "anchors:\n  north_star: NORTHSTAR.md\nmilestones:\n  - label: m1\n    idea: .megaplan/initiatives/demo/briefs/m1.md\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        cloud_cli,
        "_verify_configured_megaplan_ref_advertised",
        lambda _spec: {"status": "skipped"},
    )

    class Provider:
        def observe_container(self):
            return {
                "status": "available",
                "lifecycle": "stopped",
                "collector": {"status": "unavailable", "reason": "container_stopped"},
            }

        def observe_prelaunch_capacity(self):
            return {
                "status": "go",
                "verdict": "GO",
                "checks": {"cleanup": True},
            }

        def ssh_exec(self, command):
            raise AssertionError(f"docker exec must not run: {command}")

    rc = cloud_cli._run_preflight(
        project,
        argparse.Namespace(
            spec=str(spec_path),
            skip_remote=False,
            allow_loose_chain_spec=False,
        ),
        _spec(),
        Provider(),
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert payload["remote"]["container_observation"]["lifecycle"] == "stopped"
    assert payload["remote"]["host_predeploy_verdict"] == "GO"
    assert payload["remote"]["collector_launch_verdict"] == "NO-GO"
    assert payload["remote"]["import_check"]["status"] == "unavailable"
    assert any(
        "remote exec collector unavailable" in item for item in payload["errors"]
    )
