from __future__ import annotations

import subprocess

from arnold_pipelines.megaplan.cloud.providers import ssh as ssh_module
from arnold_pipelines.megaplan.cloud.providers.ssh_preflight import workspace_prelaunch_command


def test_workspace_prelaunch_command_contains_only_read_observations() -> None:
    command = workspace_prelaunch_command(
        "/opt/megaplan-cloud/workspace",
        min_free_bytes=1,
        min_free_inodes=2,
        receipt_reserve_bytes=3,
    )

    assert "statvfs" in command
    assert "lstat" in command
    assert "sqlite" not in command.lower()
    assert "fsync" not in command.lower()
    assert "mkdtemp" not in command.lower()
    assert "os.write" not in command.lower()
    assert "os.replace" not in command.lower()


def test_host_observation_does_not_reserve_process_adapter_wbc(monkeypatch) -> None:
    class FakeProvider:
        _ssh = type("Ssh", (), {"workspace_dir": "/opt/megaplan-cloud/workspace", "container": "agent"})()

        def _ssh_destination_argv(self):
            return ["ssh", "--", "example.invalid"]

        def _begin_process_adapter_attempt(self, **_kwargs):
            raise AssertionError("observation must not start a WBC attempt")

    fake = FakeProvider()
    monkeypatch.setattr(
        ssh_module.subprocess,
        "run",
        lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, "", ""),
    )
    # Exercise the implementation body without constructing a provider whose
    # spec would require local SSH binaries.
    result = ssh_module.SshProvider._host_observation(fake, "container")
    assert isinstance(result, subprocess.CompletedProcess)
