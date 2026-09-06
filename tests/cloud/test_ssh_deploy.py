"""Tests for SshProvider.deploy() persistent mounts."""

from __future__ import annotations

import json
import shlex
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from arnold.workflow.effect_protocol import EffectProtocol

from arnold_pipelines.megaplan.cloud.spec import (
    CloudSpec,
    RepoSpec,
    CodexSpec,
    MegaplanSpec,
    ResourcesSpec,
    SshSpec,
)
from arnold_pipelines.megaplan.cloud.ssh_effect_adapter import SshEffectAdapter
from arnold_pipelines.megaplan.custody.action_validator import GateResult
from arnold_pipelines.megaplan.types import CliError


def _authorized_effect_adapter() -> SshEffectAdapter:
    """Real adapter with an explicit authorized gate and a bypassed stale
    fence, so deploy command capture runs through the actual WBC route."""
    protocol = MagicMock(spec=EffectProtocol)
    reservation = MagicMock()
    reservation.global_logical_effect_key = "glek-deploy-test"
    protocol.reserve_and_start.return_value = reservation

    class FenceBypassAdapter(SshEffectAdapter):
        def _check_stale_fence(self, target, fence_token):
            return True

    return FenceBypassAdapter(
        protocol,
        action_gate_check=lambda _boundary, _target_key: GateResult.AUTHORIZED,
        production_enabled=False,
    )


def _minimal_cloud_spec(**ssh_overrides) -> CloudSpec:
    """Build a minimal valid CloudSpec with provider=ssh."""
    ssh = SshSpec(
        host="testhost",
        **ssh_overrides,
    )
    return CloudSpec(
        provider="ssh",
        repo=RepoSpec(url="https://github.com/example/app.git"),
        agents={"default": "codex"},
        codex=CodexSpec(),
        mode="idle",
        megaplan=MegaplanSpec(),
        resources=ResourcesSpec(),
        secrets=[],
        ssh=ssh,
    )


class TestSshDeployPersistentMounts:
    """SshProvider.deploy() must create remote dirs and run Docker with
    persistent workspace + cache mounts, without requiring real SSH/Docker."""

    def _build_deploy_command(self, spec: CloudSpec) -> str:
        """Reconstruct the exact deploy remote command that SshProvider would
        send, by calling _remote_run with a mock that captures the command."""
        from arnold_pipelines.megaplan.cloud.providers.ssh import SshProvider

        captured_commands: list[str] = []

        class CaptureSshProvider(SshProvider):
            def _remote_run(self, command, *, capture_output=True, input=None):
                captured_commands.append(command)
                # Return a mock completed process
                from subprocess import CompletedProcess
                return CompletedProcess(args=[], returncode=0, stdout="", stderr="")

            def _run(self, argv, *, capture_output=True, input=None):
                # For the docker rm/run calls
                captured_commands.append(" ".join(argv))
                from subprocess import CompletedProcess
                return CompletedProcess(args=[], returncode=0, stdout="", stderr="")

            def _sync_deploy_dir(self, deploy_dir):
                pass  # skip for this test

        provider = CaptureSshProvider(
            spec,
            ssh_effect_adapter=_authorized_effect_adapter(),
        )
        provider.deploy(Path("/tmp/fake"), secrets={"OPENAI_API_KEY": "sk-test"})
        # Return the concatenated commands for assertion
        return "\n".join(captured_commands)

    def test_deploy_creates_workspace_and_cache_dirs(self) -> None:
        """deploy() must mkdir -p the workspace_dir and cache subdirs."""
        spec = _minimal_cloud_spec()
        commands = self._build_deploy_command(spec)

        # Should create workspace_dir
        assert shlex.quote(spec.ssh.workspace_dir) in commands
        # Should create cache_dir/pip
        assert shlex.quote(f"{spec.ssh.cache_dir}/pip") in commands
        # Should create cache_dir/npm
        assert shlex.quote(f"{spec.ssh.cache_dir}/npm") in commands

    def test_deploy_creates_remote_dir(self) -> None:
        """deploy() must mkdir -p the remote_dir."""
        spec = _minimal_cloud_spec()
        commands = self._build_deploy_command(spec)
        assert shlex.quote(spec.ssh.remote_dir) in commands

    def test_deploy_mounts_workspace_volume(self) -> None:
        """Docker run must include -v <workspace_dir>:/workspace."""
        spec = _minimal_cloud_spec()
        commands = self._build_deploy_command(spec)
        workspace_mount = f"-v {shlex.quote(spec.ssh.workspace_dir)}:/workspace"
        assert workspace_mount in commands, (
            f"Expected workspace mount not found in:\n{commands}"
        )

    def test_deploy_mounts_pip_cache(self) -> None:
        """Docker run must include -v <cache_dir>/pip:/root/.cache/pip."""
        spec = _minimal_cloud_spec()
        commands = self._build_deploy_command(spec)
        pip_mount = (
            f"-v {shlex.quote(f'{spec.ssh.cache_dir}/pip')}:/root/.cache/pip"
        )
        assert pip_mount in commands, (
            f"Expected pip cache mount not found in:\n{commands}"
        )

    def test_deploy_mounts_npm_cache(self) -> None:
        """Docker run must include -v <cache_dir>/npm:/root/.npm."""
        spec = _minimal_cloud_spec()
        commands = self._build_deploy_command(spec)
        npm_mount = (
            f"-v {shlex.quote(f'{spec.ssh.cache_dir}/npm')}:/root/.npm"
        )
        assert npm_mount in commands, (
            f"Expected npm cache mount not found in:\n{commands}"
        )

    def test_deploy_uses_custom_paths(self) -> None:
        """When workspace_dir/cache_dir are overridden, deploy uses them."""
        spec = _minimal_cloud_spec(
            workspace_dir="/data/ws",
            cache_dir="/data/cache",
            remote_dir="/data/deploy",
        )
        commands = self._build_deploy_command(spec)
        assert "/data/ws" in commands
        assert "/data/cache/pip" in commands
        assert "/data/cache/npm" in commands
        assert "/data/deploy" in commands

    def test_deploy_includes_restart_policy(self) -> None:
        """Docker run must include --restart unless-stopped."""
        spec = _minimal_cloud_spec()
        commands = self._build_deploy_command(spec)
        assert "--restart unless-stopped" in commands

    def test_deploy_binds_container_port(self) -> None:
        """Docker run must publish the resources.port."""
        spec = _minimal_cloud_spec()
        commands = self._build_deploy_command(spec)
        port = spec.resources.port
        assert f"-p {port}:{port}" in commands


class TestSshProviderMissingEffectAdapter:
    """A missing ssh_effect_adapter is a typed denial (ssh.py:2800-2803):

    no gate/adapter may fall back to direct SSH, upload, deploy, or
    remote-command execution — blocked cases make zero transport calls.
    """

    def _capture_provider(self, spec: CloudSpec):
        from arnold_pipelines.megaplan.cloud.providers.ssh import SshProvider

        captured_commands: list[str] = []

        class CaptureSshProvider(SshProvider):
            def _remote_run(self, command, *, capture_output=True, input=None):
                captured_commands.append(command)
                from subprocess import CompletedProcess
                return CompletedProcess(args=[], returncode=0, stdout="", stderr="")

            def _run(self, argv, *, capture_output=True, input=None):
                captured_commands.append(" ".join(argv))
                from subprocess import CompletedProcess
                return CompletedProcess(args=[], returncode=0, stdout="", stderr="")

            def _sync_deploy_dir(self, deploy_dir):
                pass

        provider = CaptureSshProvider(spec)
        return provider, captured_commands

    def test_deploy_without_adapter_is_typed_denial_with_zero_transport(self) -> None:
        """deploy() with _ssh_effect_adapter None raises a typed denial."""
        provider, captured_commands = self._capture_provider(_minimal_cloud_spec())

        with pytest.raises(CliError) as caught:
            provider.deploy(Path("/tmp/fake"), secrets={"OPENAI_API_KEY": "sk-test"})

        assert caught.value.code == "ssh_effect_adapter_unavailable"
        assert "no ssh_effect_adapter installed" in caught.value.message
        assert captured_commands == []

    def test_build_without_adapter_is_typed_denial_with_zero_transport(self) -> None:
        """build() with _ssh_effect_adapter None raises a typed denial."""
        provider, captured_commands = self._capture_provider(_minimal_cloud_spec())

        with pytest.raises(CliError) as caught:
            provider.build(Path("/tmp/fake"))

        assert caught.value.code == "ssh_effect_adapter_unavailable"
        assert captured_commands == []

    def test_destroy_without_adapter_is_typed_denial_with_zero_transport(self) -> None:
        """destroy() with _ssh_effect_adapter None raises a typed denial."""
        provider, captured_commands = self._capture_provider(_minimal_cloud_spec())

        with pytest.raises(CliError) as caught:
            provider.destroy()

        assert caught.value.code == "ssh_effect_adapter_unavailable"
        assert captured_commands == []

    def test_route_through_wbc_without_adapter_is_typed_denial(self) -> None:
        """The 2800-2803 branch itself denies and never invokes apply_fn."""
        from arnold_pipelines.megaplan.cloud.providers.ssh import SshProvider

        apply_calls: list[dict] = []
        provider = SshProvider(_minimal_cloud_spec())

        with pytest.raises(CliError, match="no ssh_effect_adapter installed"):
            provider._maybe_route_through_wbc(
                "deploy",
                {"deploy_dir": "/tmp/fake"},
                lambda payload: apply_calls.append(payload),
            )

        assert apply_calls == []


class TestSshProviderGatedDirectTransport:
    """Step 13F (T-0018): ssh_exec/upload/down are action-off and gate-only.

    Direct transport must route through the adapter gate: a missing adapter
    or a non-AUTHORIZED gate verdict is a typed denial with zero transport
    calls, while observation-only paths (prelaunch/capacity/status) keep
    working without any adapter.
    """

    def _capture_provider(self, spec: CloudSpec, adapter=None):
        from arnold_pipelines.megaplan.cloud.providers.ssh import SshProvider

        captured_commands: list[str] = []

        class CaptureSshProvider(SshProvider):
            def _remote_run(self, command, *, capture_output=True, input=None, surface=None):
                del capture_output, input, surface
                captured_commands.append(command)
                return subprocess.CompletedProcess(
                    args=[], returncode=0, stdout='{"ok": true}\n', stderr=""
                )

            def _run(self, argv, *, capture_output=True, input=None, surface=None):
                del capture_output, input, surface
                captured_commands.append(" ".join(argv))
                return subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="", stderr=""
                )

            def _sync_deploy_dir(self, deploy_dir):
                pass

        return CaptureSshProvider(spec, ssh_effect_adapter=adapter), captured_commands

    def _shadow_adapter(self) -> SshEffectAdapter:
        return SshEffectAdapter(
            MagicMock(spec=EffectProtocol),
            action_gate_check=lambda _boundary, _target_key: GateResult.SHADOW_PASS,
            production_enabled=False,
        )

    def _assert_denied(
        self, adapter, operation, *, code: str, message_part: str
    ) -> None:
        provider, captured = self._capture_provider(
            _minimal_cloud_spec(), adapter=adapter
        )
        with pytest.raises(CliError) as caught:
            operation(provider)
        assert caught.value.code == code
        assert message_part in caught.value.message
        assert captured == []

    # ── missing adapter: typed denial, zero transport ──

    def test_ssh_exec_without_adapter_is_typed_denial_with_zero_transport(self) -> None:
        self._assert_denied(
            None,
            lambda p: p.ssh_exec("echo hi"),
            code="ssh_effect_adapter_unavailable",
            message_part="no ssh_effect_adapter installed",
        )

    def test_upload_file_without_adapter_is_typed_denial_with_zero_transport(self) -> None:
        self._assert_denied(
            None,
            lambda p: p.upload_file(Path("/tmp/fake"), "/remote/f"),
            code="ssh_effect_adapter_unavailable",
            message_part="no ssh_effect_adapter installed",
        )

    def test_upload_archive_without_adapter_is_typed_denial_with_zero_transport(self) -> None:
        self._assert_denied(
            None,
            lambda p: p.upload_archive(Path("/tmp/fake.tar.gz"), "/remote"),
            code="ssh_effect_adapter_unavailable",
            message_part="no ssh_effect_adapter installed",
        )

    def test_down_without_adapter_is_typed_denial_with_zero_transport(self) -> None:
        self._assert_denied(
            None,
            lambda p: p.down(),
            code="ssh_effect_adapter_unavailable",
            message_part="no ssh_effect_adapter installed",
        )

    # ── non-AUTHORIZED gate: typed denial, zero transport ──

    def test_direct_transport_denied_on_non_authorized_gate(self) -> None:
        shadow = self._shadow_adapter()
        for operation in (
            lambda p: p.ssh_exec("echo hi"),
            lambda p: p.upload_file(Path("/tmp/fake"), "/remote/f"),
            lambda p: p.upload_archive(Path("/tmp/fake.tar.gz"), "/remote"),
            lambda p: p.down(),
        ):
            self._assert_denied(
                shadow,
                operation,
                code="provider_failed",
                message_part="Action gate blocked",
            )

    def test_direct_transport_runs_on_production_adapter_when_authorized(
        self,
    ) -> None:
        production = SshEffectAdapter(
            MagicMock(spec=EffectProtocol),
            action_gate_check=lambda _boundary, _target_key: GateResult.AUTHORIZED,
            production_enabled=True,
        )
        provider, captured = self._capture_provider(
            _minimal_cloud_spec(), adapter=production
        )
        result = provider.ssh_exec("echo hi")
        assert result.returncode == 0
        assert captured == ["docker exec megaplan-cloud-agent bash -lc 'echo hi'"]

    # ── authorized gate: transport runs ──

    def test_ssh_exec_runs_through_authorized_gate(self) -> None:
        provider, captured = self._capture_provider(
            _minimal_cloud_spec(), adapter=_authorized_effect_adapter()
        )
        result = provider.ssh_exec("echo hi")
        assert result.returncode == 0
        assert captured == ["docker exec megaplan-cloud-agent bash -lc 'echo hi'"]

    def test_down_runs_through_authorized_gate(self) -> None:
        provider, captured = self._capture_provider(
            _minimal_cloud_spec(), adapter=_authorized_effect_adapter()
        )
        assert provider.down() == 0
        assert captured == ["docker stop megaplan-cloud-agent"]

    # ── production construction: install the canonical gated adapter ──

    def test_production_factory_installs_canonical_adapter_and_gate(self) -> None:
        from arnold_pipelines.megaplan.cloud.providers.base import get_provider
        from arnold_pipelines.megaplan.cloud.providers.ssh import SshProvider
        from arnold_pipelines.megaplan.cloud.ssh_effect_adapter import (
            SshEffectAdapter,
            SshEffectShard,
            SshTarget,
        )

        # The real cloud provider factory must be usable by preflight, while
        # retaining the production action-off gate.  It must never construct
        # the provider with the raw-transport/None adapter path.
        provider = get_provider("ssh", _minimal_cloud_spec())
        assert isinstance(provider, SshProvider)
        assert isinstance(provider._ssh_effect_adapter, SshEffectAdapter)
        assert provider._ssh_effect_adapter._production_enabled is True
        assert provider._ssh_effect_adapter._protocol is not None
        target = SshTarget(
            shard=SshEffectShard.DEPLOY,
            host="testhost",
            container="megaplan-cloud-agent",
        )
        assert provider._ssh_effect_adapter._gate(target) is GateResult.BLOCKED_MISSING_GRANT

    def test_production_factory_never_allows_raw_ssh_dispatch(self) -> None:
        from arnold_pipelines.megaplan.cloud.providers.base import get_provider

        provider = get_provider("ssh", _minimal_cloud_spec())
        with pytest.raises(CliError) as caught:
            provider._gate_action_off_transport(
                "down",
                lambda: pytest.fail("raw SSH dispatch bypassed gate"),
            )
        assert caught.value.code == "provider_failed"
        assert "Action gate blocked" in caught.value.message

    def test_continuation_cloud_yaml_preflight_uses_gated_factory(self) -> None:
        """The real SSH cloud.yaml follows the preflight provider path."""
        from arnold_pipelines.megaplan.cloud.cli import _provider_for_action
        from arnold_pipelines.megaplan.cloud.spec import load_spec
        from arnold_pipelines.megaplan.cloud.ssh_effect_adapter import (
            SshEffectAdapter,
        )

        cloud_yaml = (
            Path(__file__).parents[2]
            / ".megaplan/initiatives/native-build-forward-continuation-20260902-r4/cloud.yaml"
        )
        spec = load_spec(cloud_yaml)
        provider = _provider_for_action(
            spec,
            SimpleNamespace(on_box=False, cloud_action=None, session=None),
        )
        assert isinstance(provider._ssh_effect_adapter, SshEffectAdapter)
        assert provider._ssh_effect_adapter._production_enabled is True

    # ── observation paths unaffected ──

    def test_observation_paths_unaffected_without_adapter(self) -> None:
        provider, captured = self._capture_provider(_minimal_cloud_spec())

        # status read works without an adapter
        payload = provider.status_payload(
            plan=None, workspace="/opt/megaplan-cloud/workspace"
        )
        assert payload["ok"] is True

        # prelaunch capacity works without an adapter
        provider.observe_container = lambda: {
            "status": "available",
            "lifecycle": "running",
            "workspace_bind": {"status": "missing"},
        }
        prelaunch = provider.observe_prelaunch_capacity()
        assert prelaunch["verdict"] == "NO-GO"

        # capacity inventory works without an adapter
        inventory = {
            "schema": "arnold.cloud.ssh_capacity_inventory.v1",
            "workspace": "/opt/megaplan-cloud/workspace",
            "filesystem": {"free_bytes": 1, "free_inodes": 20, "block_size": 4096},
            "mount": {
                "st_dev": 1,
                "device_major": 0,
                "device_minor": 1,
                "inode": 2,
            },
            "scopes": [
                {"path": path, "status": "available", "size_bytes": 1}
                for path in (
                    "/opt/megaplan-cloud/workspace",
                    "/opt/megaplan-cloud/deploy",
                    "/opt/megaplan-cloud/cache",
                )
            ],
            "docker_disk_usage": [],
            "errors": [],
            "status": "available",
            "returncode": 0,
        }
        provider._host_observation = lambda operation: subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(inventory) + "\n", stderr=""
        )
        capacity = provider.observe_capacity_inventory()
        assert isinstance(capacity, dict)

        # The only transport is the status read itself (ungated observation);
        # no gated mutation command (docker stop/upload/exec-mutation) ran.
        assert len(captured) == 1
        assert "docker exec" in captured[0]
        assert "megaplan status" in captured[0]

    def test_observation_transports_ungated_without_adapter(self) -> None:
        """T-0018: read_remote_file/logs are observation-only and attach is
        interactive transport — all three keep working without an effect
        adapter (classified in source, never gated, never mutating)."""
        provider, captured = self._capture_provider(_minimal_cloud_spec())

        # read_remote_file: read-only remote inspection (cat), ungated
        content = provider.read_remote_file("/opt/megaplan-cloud/state.json")
        assert content == '{"ok": true}\n'
        assert "cat" in captured[0]

        # logs (non-follow): read-only docker logs stream, ungated
        assert provider.logs(follow=False) == 0
        assert "docker logs" in captured[1]

        # attach: interactive PTY transport (tmux client attach), ungated
        assert provider.attach() == 0
        assert "tmux attach" in captured[2]

        # status_payload: documented observation-only read, ungated
        captured.clear()
        payload = provider.status_payload(
            plan=None, workspace="/opt/megaplan-cloud/workspace"
        )
        assert payload["ok"] is True
        assert "megaplan status" in captured[0]

    def test_observation_classification_documented(self) -> None:
        """T-0018: read_remote_file/logs are explicitly documented in source
        as observation-only transports and attach as interactive transport —
        an explicit classification, never a silent ungated bypass."""
        import inspect

        from arnold_pipelines.megaplan.cloud.providers.ssh import SshProvider

        assert "Observation-only transport" in inspect.getsource(
            SshProvider.read_remote_file
        )
        assert "Observation-only transport" in inspect.getsource(
            SshProvider.logs
        )
        assert "Interactive transport" in inspect.getsource(SshProvider.attach)
        assert "Observation-only path" in inspect.getsource(
            SshProvider.status_payload
        )


def test_entrypoint_starts_discord_resident_from_shared_secret_env() -> None:
    from arnold_pipelines.megaplan.cloud.template import render_entrypoint

    entrypoint = render_entrypoint(_minimal_cloud_spec())

    assert "/workspace/.secrets/megaplan-resident-discord.env" in entrypoint
    assert "tmux has-session -t megaplan-resident-discord" in entrypoint
    assert "MEGAPLAN_RESIDENT_STORE_ROOT" in entrypoint
    assert "--store-root" in entrypoint
    assert "MEGAPLAN_RUNTIME_PYTHON" in entrypoint
    assert 'exec \\"\\$runtime_python\\" -P -m arnold_pipelines.megaplan resident discord' in entrypoint
    assert "MEGAPLAN_RESIDENT_DISCORD_BOT_ROLE" in entrypoint
    assert "MEGAPLAN_RESIDENT_MODE:-production" in entrypoint
    assert "/workspace/.megaplan/resident-runtime.env" in entrypoint
    assert entrypoint.index("/workspace/.cloud-hot-env") < entrypoint.index(
        "/workspace/.megaplan/resident-runtime.env"
    )
    assert "tmux new-session -d -s megaplan-resident-discord -c /workspace" in entrypoint
    assert "runtime_src=/workspace/arnold" not in entrypoint
    assert "MEGAPLAN_RUNTIME_SRC" not in entrypoint
    assert r'cd \"\$runtime_src\"' in entrypoint


def test_entrypoint_boot_supervisors_use_manifest_pinned_runtime() -> None:
    from arnold_pipelines.megaplan.cloud.template import render_entrypoint

    entrypoint = render_entrypoint(_minimal_cloud_spec())

    # Heartbeat, watchdog, and resident all resolve runtime_src from the
    # per-session manifest (ARNOLD_RUNTIME_MANIFEST -> epic.runtime_root):
    # no shared-root literal and no env-selector read (G5).  An unbound pin
    # skips the supervisor sessions instead of launching from /workspace/arnold.
    assert entrypoint.count("runtime_src=/workspace/arnold") == 0
    assert entrypoint.count("arnold_runtime_manifest_epic_field epic.runtime_root") == 1
    assert entrypoint.count("ENTRYPOINT_RUNTIME_ROOT") >= 4
    assert entrypoint.count(r'cd \"\$runtime_src\"') == 3
    assert r"MEGAPLAN_RUNTIME_SRC:-\${CLOUD_WATCHDOG_ARNOLD_SRC" not in entrypoint
    assert "MEGAPLAN_RUNTIME_SRC" not in entrypoint
    assert "CLOUD_WATCHDOG_ARNOLD_SRC" not in entrypoint
    assert (
        r'exec \"\$runtime_src/arnold_pipelines/megaplan/cloud/wrappers/'
        r'arnold-heartbeat\"'
    ) in entrypoint
    assert (
        r'exec \"\$runtime_src/arnold_pipelines/megaplan/cloud/wrappers/'
        r'arnold-watchdog\"'
    ) in entrypoint
    assert (
        "/workspace/arnold/arnold_pipelines/megaplan/cloud/wrappers/"
        "arnold-heartbeat"
    ) not in entrypoint
    assert (
        "/workspace/arnold/arnold_pipelines/megaplan/cloud/wrappers/"
        "arnold-watchdog"
    ) not in entrypoint
    assert "tmux new-session -d -s megaplan-resident-discord -c /workspace/arnold" not in entrypoint


def test_entrypoint_runtime_selector_quoting_is_valid_bash() -> None:
    import subprocess

    from arnold_pipelines.megaplan.cloud.template import render_entrypoint

    entrypoint = render_entrypoint(_minimal_cloud_spec())
    syntax = subprocess.run(
        ["bash", "-n"],
        input=entrypoint,
        capture_output=True,
        text=True,
        check=False,
    )

    assert syntax.returncode == 0, syntax.stderr


def test_cloud_image_installs_pinned_railway_cli() -> None:
    dockerfile = (
        Path(__file__).parents[2]
        / "arnold_pipelines/megaplan/cloud/templates/Dockerfile"
    ).read_text()

    assert "@railway/cli@4.12.0" in dockerfile
    assert "ln -sf /opt/zero-recovery-node/bin/railway /usr/local/bin/railway" in dockerfile
    assert "railway --version" in dockerfile


def test_cloud_image_keeps_default_python_and_bakes_generation_interpreter() -> None:
    dockerfile = (
        Path(__file__).parents[2]
        / "arnold_pipelines/megaplan/cloud/templates/Dockerfile"
    ).read_text()

    assert "/root/.pyenv/bin/pyenv install 3.11.11" in dockerfile
    assert "PYTHON_CONFIGURE_OPTS=--enable-shared /root/.pyenv/bin/pyenv install 3.13.6" in dockerfile
    assert "/root/.pyenv/versions/3.13.6/lib/libpython3.13.so.1.0" in dockerfile
    assert "/root/.pyenv/versions/3.13.6/bin/python -c" in dockerfile
    assert "LD_LIBRARY_PATH=/root/.pyenv/versions/3.13.6/lib:/root/.pyenv/versions/3.11.11/lib" in dockerfile


def test_cloud_image_installs_account_management_before_finite_uid_creation() -> None:
    dockerfile = (
        Path(__file__).parents[2]
        / "arnold_pipelines/megaplan/cloud/templates/Dockerfile"
    ).read_text()

    package_install = dockerfile.index("apt-get install -y --no-install-recommends")
    passwd_package = dockerfile.index("      passwd \\")
    finite_group = dockerfile.index("/usr/sbin/groupadd --gid 65532 finite-model")
    finite_user = dockerfile.index("/usr/sbin/useradd --uid 65532 --gid 65532")

    assert package_install < passwd_package < finite_group < finite_user
    assert "RUN groupadd " not in dockerfile
    assert "&& useradd " not in dockerfile


def test_cloud_image_bakes_source_runtime_floor_without_pypi_name_collision() -> None:
    dockerfile = (
        Path(__file__).parents[2]
        / "arnold_pipelines/megaplan/cloud/templates/Dockerfile"
    ).read_text()

    assert 'ARG MEGAPLAN_INSTALL_SPEC=""' in dockerfile
    for requirement in (
        '"PyYAML>=6.0"',
        '"pydantic>=2.0"',
        '"python-ulid>=3.0"',
        '"psutil>=5.9"',
        '"httpx>=0.27"',
        '"discord.py>=2.6,<3"',
    ):
        assert requirement in dockerfile
    assert "import discord, httpx, psutil, pydantic, ulid, yaml" in dockerfile
    assert 'ARG MEGAPLAN_INSTALL_SPEC="arnold[agent]"' not in dockerfile


def test_entrypoint_persists_railway_auth_without_rendered_secret() -> None:
    import subprocess

    from arnold_pipelines.megaplan.cloud.template import render_entrypoint

    entrypoint = render_entrypoint(_minimal_cloud_spec())

    assert "RAILWAY_CREDS_DIR=/workspace/.creds/railway" in entrypoint
    assert 'ln -s "$RAILWAY_CREDS_DIR" /root/.railway' in entrypoint
    assert "/workspace/.creds/railway-config.json" in entrypoint
    assert '[[ ! -s "$RAILWAY_CREDS_DIR/config.json" ]]' in entrypoint
    assert "railway login" not in entrypoint
    assert "RAILWAY_TOKEN=" not in entrypoint
    assert "RAILWAY_API_TOKEN=" not in entrypoint
    syntax = subprocess.run(
        ["bash", "-n"],
        input=entrypoint,
        capture_output=True,
        text=True,
        check=False,
    )
    assert syntax.returncode == 0, syntax.stderr


def test_resident_self_heal_starts_the_production_bot_boundary() -> None:
    ensure_script = (
        Path(__file__).parents[2]
        / "arnold_pipelines/megaplan/cloud/systemd/ensure-megaplan-resident"
    ).read_text()

    assert "MEGAPLAN_RESIDENT_DISCORD_BOT_ROLE" in ensure_script
    assert "MEGAPLAN_RESIDENT_MODE:-production" in ensure_script
    assert "MEGAPLAN_RESIDENT_STORE_ROOT" in ensure_script
    assert "MEGAPLAN_RUNTIME_PYTHON" in ensure_script
    assert 'exec \\"\\$runtime_python\\" -P -m arnold_pipelines.megaplan resident discord' in ensure_script
    assert '"$runtime_python" -P -m arnold_pipelines.megaplan resident health' in ensure_script
    assert "--store-root" in ensure_script
    assert "/workspace/.megaplan/resident-runtime.env" in ensure_script
    assert ensure_script.index("/workspace/.cloud-hot-env") < ensure_script.index(
        "/workspace/.megaplan/resident-runtime.env"
    )
    assert 'readlink -f "/proc/$pane_pid/exe"' in ensure_script
    assert 'grep -F -- "PYTHONPATH=$runtime_src:"' in ensure_script
    assert '"MEGAPLAN_RUNTIME_PYTHON=$runtime_python"' in ensure_script
    assert "MEGAPLAN_RUNTIME_SRC" not in ensure_script
