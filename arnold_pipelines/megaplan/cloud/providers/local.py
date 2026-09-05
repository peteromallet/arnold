from __future__ import annotations

import base64
import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path

from arnold_pipelines.megaplan.cloud.spec import CloudSpec, LocalSpec
from arnold_pipelines.megaplan.types import CliError

from .base import (
    Provider,
    _logs_follow,
    _missing_cli_error,
    _write_redacted_output,
    parse_launch_engine_response,
)


INSTALL_LINK = "Install: https://docs.docker.com/get-docker/"


class LocalProvider(Provider):
    def __init__(self, spec: CloudSpec) -> None:
        self._spec = spec
        self._local = spec.local or LocalSpec()
        self._binary = shutil.which("docker")
        if self._binary is None:
            _missing_cli_error("docker", INSTALL_LINK.removeprefix("Install: "))

    def authoritative_store_root(self) -> str:
        return "/workspace/ops"

    def _deploy_dir(self) -> Path:
        from arnold_pipelines.megaplan.cloud.cli import _persistent_deploy_dir

        return _persistent_deploy_dir(self._spec)

    def _workspace_dir(self) -> Path:
        path = self._deploy_dir() / self._local.workdir
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _compose_file(self) -> Path:
        return self._deploy_dir() / "docker-compose.yaml"

    def _compose_argv(self, *args: str) -> list[str]:
        return [
            self._binary or "docker",
            "compose",
            "-p",
            self._local.compose_project,
            "-f",
            str(self._compose_file()),
            *args,
        ]

    def _process_adapter_evidence_root(self) -> Path:
        return self._deploy_dir()

    def _run(
        self,
        argv: list[str],
        *,
        capture_output: bool = True,
        input: str | None = None,
        surface: str = "shell_command",
    ) -> subprocess.CompletedProcess[str]:
        attempt = self._begin_process_adapter_attempt(
            surface=surface,
            start_details={
                "argv": list(argv),
                "capture_output": capture_output,
                "input_supplied": input is not None,
            },
        )
        deploy_dir = self._deploy_dir()
        try:
            kwargs: dict[str, object] = {
                "cwd": deploy_dir,
                "capture_output": capture_output,
                "text": True,
                "check": False,
            }
            if input is not None:
                kwargs["input"] = input
            result = subprocess.run(argv, **kwargs)
        except FileNotFoundError as exc:
            attempt.terminal(
                status="failed",
                outcome="blocked",
                details={"error_type": type(exc).__name__, "message": str(exc)},
            )
            raise CliError("provider_failed", str(exc)) from exc
        if result.returncode != 0 and _is_missing_compose_subcommand(argv, result):
            compose_binary = shutil.which("docker-compose")
            if compose_binary is not None:
                fallback_argv = [compose_binary, *argv[2:]]
                attempt.effect(
                    "compose_fallback",
                    details={"fallback_argv": fallback_argv},
                )
                try:
                    result = subprocess.run(fallback_argv, **kwargs)
                except FileNotFoundError as exc:
                    attempt.terminal(
                        status="failed",
                        outcome="blocked",
                        details={"error_type": type(exc).__name__, "message": str(exc)},
                    )
                    raise CliError("provider_failed", str(exc)) from exc
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            attempt.terminal(
                status="failed",
                outcome="indeterminate",
                details={
                    "returncode": result.returncode,
                    "stderr": stderr,
                    "stdout": (result.stdout or "").strip(),
                },
            )
            raise CliError("provider_failed", stderr or f"Command failed: {' '.join(argv)}")
        attempt.terminal(
            status="completed",
            outcome="succeeded",
            details={"returncode": result.returncode},
        )
        return result

    def build(self, deploy_dir: Path) -> int:
        del deploy_dir
        self._run(self._compose_argv("build"), surface="build")
        return 0

    def deploy(self, deploy_dir: Path, *, secrets: dict[str, str]) -> int:
        del deploy_dir
        env_lines = [f"PORT={self._spec.resources.port}"]
        env_lines.extend(f"{name}={value}" for name, value in secrets.items())
        (self._deploy_dir() / ".env").write_text("\n".join(env_lines) + "\n", encoding="utf-8")
        self._run(self._compose_argv("up", "-d"), surface="deploy")
        return 0

    def ssh_exec(self, command: str) -> subprocess.CompletedProcess[str]:
        return self._run(
            self._compose_argv("exec", "-T", "agent", "bash", "-lc", command),
            surface="ssh_exec",
        )

    def invoke_launch_engine(self, request: dict[str, object]) -> dict[str, object]:
        """Run the engine inside the agent container beside its store."""
        from arnold_pipelines.megaplan.cloud.chain_drive import (
            encode_launch_request,
            launch_engine_command,
        )
        try:
            result = self._run(
                self._compose_argv(
                    "exec", "-T", "agent", "bash", "-lc",
                    launch_engine_command(encode_launch_request(request)),
                ),
                surface="launch_engine",
            )
        except Exception as exc:
            return {
                "schema": "arnold.megaplan.cloud_launch_response.v1",
                "result": "UNKNOWN",
                "reason": "transport_unavailable",
                "invoked": False,
                "detail": f"{type(exc).__name__}: {exc}",
            }
        return parse_launch_engine_response(result.stdout or "", invoked=True)

    def upload_file(self, src: Path, dest: str) -> None:
        payload = base64.b64encode(src.read_bytes()).decode("ascii")
        inner = f"mkdir -p {shlex.quote(Path(dest).parent.as_posix())} && base64 -d > {shlex.quote(dest)}"
        self._run(
            self._compose_argv("exec", "-T", "agent", "bash", "-lc", inner),
            input=payload,
            surface="upload_file",
        )

    def upload_archive(self, src: Path, dest_dir: str) -> None:
        payload = base64.b64encode(src.read_bytes()).decode("ascii")
        inner = f"mkdir -p {shlex.quote(dest_dir)} && base64 -d | tar -xzf - -C {shlex.quote(dest_dir)}"
        self._run(
            self._compose_argv("exec", "-T", "agent", "bash", "-lc", inner),
            input=payload,
            surface="upload_archive",
        )

    def read_remote_file(self, path: str) -> str:
        result = self._run(
            self._compose_argv("exec", "-T", "agent", "cat", path),
            surface="read_remote_file",
        )
        return result.stdout

    def attach(self) -> int:
        self._run(
            self._compose_argv("exec", "agent", "tmux", "attach", "-t", "agent"),
            capture_output=False,
            surface="attach",
        )
        return 0

    def logs(self, *, follow: bool = True) -> int:
        argv = self._compose_argv("logs")
        if follow:
            argv.append("-f")
            argv.append("agent")
            return _logs_follow(argv, cwd=self._deploy_dir(), secret_names=self._spec.secrets, env=os.environ)
        argv.extend(["--tail", "200", "agent"])
        result = self._run(argv, surface="logs")
        _write_redacted_output(result, secret_names=self._spec.secrets, env=os.environ)
        return 0

    def status_payload(
        self,
        *,
        plan: str | None,
        workspace: str,
        session: str | None = None,
    ) -> dict:
        from arnold_pipelines.megaplan.cloud.providers.ssh import (
            _megaplan_status_module_command,
        )

        command = _megaplan_status_module_command(
            workspace=workspace,
            plan=plan,
            runtime_root=self._spec.megaplan.src_path,
            runtime_revision=None,
            session=session,
        )
        result = self.ssh_exec(command)
        payload = json.loads(result.stdout)
        if not isinstance(payload, dict):
            raise CliError("provider_failed", "Megaplan status did not return a JSON object")
        return payload

    def down(self) -> int:
        self._run(self._compose_argv("stop"), surface="down")
        return 0

    def destroy(self, *, volume: str | None = None) -> int:
        del volume
        self._run(
            self._compose_argv("down", "--volumes", "--remove-orphans"),
            surface="destroy",
        )
        return 0


def _is_missing_compose_subcommand(
    argv: list[str],
    result: subprocess.CompletedProcess[str],
) -> bool:
    if len(argv) < 2 or argv[1] != "compose":
        return False
    output = f"{result.stderr or ''}\n{result.stdout or ''}".lower()
    return "unknown shorthand flag" in output or "docker: 'compose' is not a docker command" in output
