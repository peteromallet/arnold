"""Abstract base classes for cloud providers.

Sprint 2 will add `init_plan(...)`-style workflows and more providers. Provider
implementations should stay stateless beyond local CLI discovery and credential
resolution so the CLI can instantiate them on demand.
"""

from __future__ import annotations

import abc
import json
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from arnold_pipelines.megaplan.custody.process_adapter_wbc import (
    ProcessAdapterWbcAttempt,
    begin_process_adapter_attempt,
)
from arnold_pipelines.megaplan.cloud.spec import CloudSpec
from arnold_pipelines.megaplan.types import CliError


def megaplan_runtime_invocation(spec: CloudSpec) -> str:
    """Return the hermetic remote Megaplan interpreter invocation.

    Cloud control-plane commands must not resolve the legacy ``arnold`` console
    script through PATH.  A cloud spec therefore has to name the absolute
    runtime interpreter that owns the Megaplan module.  Missing identity is a
    configuration error, never permission to fall back to a mutable command.
    """
    runtime_python = getattr(spec.megaplan, "runtime_python", None)
    if not isinstance(runtime_python, str) or not runtime_python.strip():
        raise CliError(
            "runtime_identity_missing",
            "cloud.megaplan.runtime_python must name the absolute pinned Megaplan interpreter",
        )
    return f"{shlex.quote(runtime_python)} -P -m arnold_pipelines.megaplan"


def parse_launch_engine_response(raw: str, *, invoked: bool = True) -> dict[str, Any]:
    """Parse one strict typed response line from the co-located engine."""
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    try:
        payload = json.loads(lines[-1] if lines else "{}")
    except json.JSONDecodeError:
        return {
            "schema": "arnold.megaplan.cloud_launch_response.v1",
            "result": "UNKNOWN",
            "reason": "malformed_engine_response",
            "invoked": invoked,
        }
    if not isinstance(payload, dict) or payload.get("schema") != "arnold.megaplan.cloud_launch_response.v1":
        return {
            "schema": "arnold.megaplan.cloud_launch_response.v1",
            "result": "UNKNOWN",
            "reason": "malformed_engine_response",
            "invoked": invoked,
        }
    payload["invoked"] = invoked
    return payload


@dataclass
class DeployStepReport:
    name: str
    status: str
    detail: str = ""
    stdout: str = ""
    stderr: str = ""
    log_ref: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DeployReport:
    success: bool
    provider: str
    service: str | None
    deploy_dir: str
    steps: list[DeployStepReport] = field(default_factory=list)
    image_rebuild: str = "unknown"
    image_ref: str | None = None
    no_op: bool = False
    vars_updated: int = 0
    logs: dict[str, Any] = field(default_factory=dict)
    verdict: str = ""
    warnings: list[str] = field(default_factory=list)
    exit_code: int = 0


def _missing_cli_error(binary: str, install_url: str) -> None:
    raise CliError(
        "provider_unavailable",
        f"Missing required CLI '{binary}'. Install: {install_url}",
    )


def _logs_follow(
    argv: list[str],
    *,
    cwd: Path | None = None,
    secret_names: list[str] | tuple[str, ...] = (),
    env: dict[str, str] | None = None,
) -> int:
    from arnold_pipelines.megaplan.cloud.redact import stream_redact

    try:
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except FileNotFoundError as exc:
        raise CliError("provider_failed", str(exc)) from exc

    for chunk in stream_redact(proc, secret_names, env=env):
        sys.stdout.write(chunk)

    returncode = proc.wait()
    if returncode != 0:
        raise CliError("provider_failed", f"Command failed: {' '.join(argv)}")
    return 0


def _write_redacted_output(
    result: subprocess.CompletedProcess[str],
    *,
    secret_names: list[str] | tuple[str, ...] = (),
    env: dict[str, str] | None = None,
) -> None:
    from arnold_pipelines.megaplan.cloud.redact import redact

    if getattr(result, "stdout", ""):
        sys.stdout.write(redact(result.stdout, secret_names, env=env))
    if getattr(result, "stderr", ""):
        sys.stderr.write(redact(result.stderr, secret_names, env=env))


class Provider(abc.ABC):
    supports_session = False

    def authoritative_store_root(self) -> str | None:
        """Configured store path as seen by the engine process, if known."""
        return None

    def _process_adapter_evidence_root(self) -> Path:
        return Path(tempfile.gettempdir()) / "arnold-process-adapter-wbc"

    def _begin_process_adapter_attempt(
        self,
        *,
        surface: str,
        start_details: dict[str, Any] | None = None,
        adapter_name: str | None = None,
    ) -> ProcessAdapterWbcAttempt:
        return begin_process_adapter_attempt(
            self._process_adapter_evidence_root(),
            producer_family="cloud_provider_adapter",
            adapter_name=adapter_name or type(self).__name__,
            surface=surface,
            start_details=start_details,
        )

    @abc.abstractmethod
    def build(self, deploy_dir: Path) -> int:
        raise NotImplementedError

    @abc.abstractmethod
    def deploy(self, deploy_dir: Path, *, secrets: dict[str, str]) -> int | DeployReport:
        raise NotImplementedError

    @abc.abstractmethod
    def ssh_exec(self, command: str) -> subprocess.CompletedProcess:
        raise NotImplementedError

    def git_auth_exec(self, command: str) -> subprocess.CompletedProcess:
        """Run a Git command whose output may contain authentication data.

        Providers may override this boundary to require their path-only Git
        credential setup and redact the command's output.  Keeping it a
        separate call-site operation is deliberate: arbitrary shell wrappers
        passed to ``ssh_exec`` must never be classified by searching their
        source text for words such as ``git push``.
        """
        return self.ssh_exec(command)

    def invoke_launch_engine(self, request: dict[str, Any]) -> dict[str, Any]:
        """Invoke the co-located authoritative launch engine.

        Providers may override the transport details, but the response is
        always the engine's typed JSON result.  A transport failure is
        explicitly ``UNKNOWN`` and is never retried by this boundary.
        """
        from arnold_pipelines.megaplan.cloud.chain_drive import (
            encode_launch_request,
            launch_engine_command,
        )

        command = launch_engine_command(encode_launch_request(request))
        try:
            result = self.ssh_exec(command)
        except Exception as exc:
            return {
                "schema": "arnold.megaplan.cloud_launch_response.v1",
                "result": "UNKNOWN",
                "reason": "transport_unavailable",
                "invoked": False,
                "detail": f"{type(exc).__name__}: {exc}",
            }
        return parse_launch_engine_response(result.stdout or "", invoked=True)

    @abc.abstractmethod
    def upload_file(self, src: Path, dest: str) -> None:
        raise CliError("not_implemented", "This provider does not support file upload")

    def upload_archive(self, src: Path, dest_dir: str) -> None:
        raise CliError("not_implemented", "This provider does not support archive upload")

    @abc.abstractmethod
    def read_remote_file(self, path: str) -> str:
        raise CliError("not_implemented", "This provider does not support remote file reads")

    @abc.abstractmethod
    def attach(self) -> int:
        """Attach to the remote tmux session.

        Interactive attach is intentionally not redacted line-by-line; unlike
        `logs -f`, the attached PTY is a raw interactive stream.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def logs(self, *, follow: bool = True) -> int:
        raise NotImplementedError

    @abc.abstractmethod
    def status_payload(
        self,
        *,
        plan: str | None,
        workspace: str,
        session: str | None = None,
    ) -> dict:
        raise NotImplementedError

    @abc.abstractmethod
    def down(self) -> int:
        raise NotImplementedError

    @abc.abstractmethod
    def destroy(self, *, volume: str | None = None) -> int:
        raise NotImplementedError


ProviderFactory = Callable[[CloudSpec], Provider]


def _local_provider(spec: CloudSpec) -> Provider:
    from arnold_pipelines.megaplan.cloud.providers.local import LocalProvider

    return LocalProvider(spec)


def _ssh_provider(spec: CloudSpec) -> Provider:
    from arnold_pipelines.megaplan.cloud.providers.ssh import SshProvider
    from arnold_pipelines.megaplan.cloud.ssh_effect_adapter import (
        current_ssh_gate_check,
        open_ssh_effect_adapter,
    )

    # Production construction installs the effect protocol and a gate that
    # reads the provider's bound FreshChildAuthorityContext for every effect.
    # The provider is created first so the gate cannot accidentally capture a
    # synthetic operation/request projection.
    from arnold.workflow.attempt_ledger_store import SqliteAttemptLedgerStore
    from arnold.workflow.effect_protocol import EffectProtocol
    from arnold.workflow.ledger_outbox import SqliteLedgerOutbox

    store = SqliteAttemptLedgerStore(":memory:")
    protocol = EffectProtocol(store, SqliteLedgerOutbox(store))
    provider_holder: dict[str, Any] = {}
    adapter = open_ssh_effect_adapter(
        protocol,
        action_gate_check=current_ssh_gate_check(
            lambda: getattr(provider_holder.get("provider"), "fresh_child_authority_context", None)
        ),
        production_enabled=True,
    )
    provider = SshProvider(spec, ssh_effect_adapter=adapter)
    provider_holder["provider"] = provider
    return provider


_PROVIDER_FACTORIES: dict[str, ProviderFactory] = {
    "local": _local_provider,
    "ssh": _ssh_provider,
}


def get_provider(name: str, spec: CloudSpec) -> Provider:
    provider_factory = _PROVIDER_FACTORIES.get(name)
    if provider_factory is None:
        raise CliError("invalid_spec", f"Unknown cloud provider '{name}'")
    return provider_factory(spec)
