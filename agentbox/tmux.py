"""Tmux process-session helpers for AgentBox host runs."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from arnold.runtime.durable_ops import (
    ResourceType,
    TypedResource,
    TypedResourceAlreadyExists,
)

from agentbox.config import AgentBoxConfig
from agentbox.operations import open_operation_store
from agentbox.run_dirs import RunDirPaths


TMUX_BIN = "tmux"
TMUX_COMMAND_INLINE_LIMIT = 8192
COMMAND_FILE_INTERPRETER = "/bin/bash"
_COMMAND_FILE_TEST_HOOK: Any = None


class TmuxError(RuntimeError):
    """Raised for tmux command failures that are not structured statuses."""

    def __init__(self, detail: str, *, returncode: int | None = None) -> None:
        super().__init__(detail)
        self.returncode = returncode


@dataclass(frozen=True)
class TmuxResult:
    """Completed tmux invocation details."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class CommandFileBinding:
    """Descriptor-verifiable identity for one durable command file."""

    path: Path
    durable_root: Path
    components: tuple[str, ...]
    filename: str
    digest: str


@dataclass(frozen=True)
class SessionStatus:
    """Structured process-session status."""

    session_name: str
    state: str
    exists: bool
    detail: str | None = None
    operation_id: str | None = None
    request_id: str | None = None
    envelope_digest: str | None = None
    process_session_identity: str | None = None
    identity_available: bool = False


def session_name(operation_id: str) -> str:
    """Return a deterministic tmux-safe session name for an operation."""

    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "-", operation_id).strip("-")
    if not normalized:
        normalized = "operation"
    return f"agentbox-{normalized}"[:80]


def new_session_argv(
    name: str,
    command: Sequence[str] | str,
    *,
    cwd: Path | str | None = None,
    stdout_path: Path | str | None = None,
    stderr_path: Path | str | None = None,
    environment: Mapping[str, str] | None = None,
) -> list[str]:
    """Build argv for a detached tmux session."""

    argv = [TMUX_BIN, "new-session", "-d", "-s", name]
    if cwd is not None:
        argv.extend(["-c", str(cwd)])
    for key, value in sorted((environment or {}).items()):
        argv.extend(["-e", f"{key}={value}"])
    argv.append(_command_for_shell(command, stdout_path=stdout_path, stderr_path=stderr_path))
    return argv


def command_file_session_argv(
    name: str,
    command_file: CommandFileBinding,
    *,
    cwd: Path | str | None = None,
    stdout_path: Path | str | None = None,
    stderr_path: Path | str | None = None,
    environment: Mapping[str, str] | None = None,
) -> list[str]:
    """Build a short fixed-form argv that executes an already-bound command file."""

    if not os.path.isfile(COMMAND_FILE_INTERPRETER) or not os.access(
        COMMAND_FILE_INTERPRETER, os.X_OK
    ):
        raise TmuxError("required command interpreter is unavailable")

    verifier = (
        "import hashlib,os,stat,sys,tempfile;"
        "root,*parts,digest=sys.argv[1:];"
        "flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW;"
        "fd=os.open(root,flags);"
        "check=lambda s,d: (stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and not(stat.S_IMODE(s.st_mode)&0o077)) or (_ for _ in()).throw(PermissionError('unsafe command directory'));"
        "rootcheck=lambda s: (stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and not(stat.S_IMODE(s.st_mode)&0o022)) or (_ for _ in()).throw(PermissionError('unsafe command root'));"
        "rootcheck(os.fstat(fd));"
        "exec(\"for part in parts[:-1]:\\n n=os.open(part,flags,dir_fd=fd)\\n check(os.fstat(n),n)\\n os.close(fd)\\n fd=n\");"
        "script=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd);"
        "s=os.fstat(script);"
        "(stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==0o600) or (_ for _ in()).throw(PermissionError('unsafe command file'));"
        "data=b'';"
        "exec(\"while True:\\n b=os.read(script,1048576)\\n if not b: break\\n data+=b\");"
        "hashlib.sha256(data).hexdigest()==digest or (_ for _ in()).throw(ValueError('command digest mismatch'));"
        "safe=tempfile.TemporaryFile();safe.write(data);safe.flush();safe.seek(0);"
        "script=safe.fileno();os.set_inheritable(script,True);"
        "os.execv('/bin/bash',['/bin/bash',f'/dev/fd/{script}'])"
    )
    command = " ".join(
        _shell_quote(value)
        for value in (
            sys.executable,
            "-c",
            verifier,
            str(command_file.durable_root),
            *command_file.components,
            command_file.filename,
            command_file.digest,
        )
    )
    return new_session_argv(
        name,
        f"exec {command}",
        cwd=cwd,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        environment=environment,
    )


def materialize_command_file(
    command: str,
    *,
    durable_root: Path | str,
    operation_id: str,
    request_id: str,
    envelope_digest: str,
) -> CommandFileBinding:
    """Atomically bind command bytes to one admitted launch identity.

    The caller must invoke this only after canonical launch admission. Existing
    equal bytes are reused for idempotent re-entry; every other occupancy is a
    hard failure.
    """

    if not isinstance(command, str):
        raise TypeError("command must be a string")
    identities = (
        ("operation", operation_id),
        ("request", request_id),
        ("envelope", envelope_digest),
    )
    if any(not isinstance(value, str) or not value for _, value in identities):
        raise ValueError("command-file identity must be a non-empty string")
    payload = command.encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    root = Path(durable_root).absolute()
    relative_components = (
        "command-files",
        *(_identity_component(label, value) for label, value in identities),
    )
    directory = root.joinpath(*relative_components)
    target = directory / f"command-{digest}.sh"
    if target.parent != directory or target.is_absolute() is False:
        raise ValueError("command-file path escaped durable root")
    os.makedirs(root, mode=0o700, exist_ok=True)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent_fd = os.open(root, flags)
    try:
        _verify_trusted_root_fd(parent_fd)
        for component in relative_components:
            try:
                child_fd = os.open(component, flags, dir_fd=parent_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o700, dir_fd=parent_fd)
                except FileExistsError:
                    pass
                try:
                    child_fd = os.open(component, flags, dir_fd=parent_fd)
                except OSError as exc:
                    raise ValueError("command-file ancestor is not a directory") from exc
            except OSError as exc:
                raise ValueError("command-file ancestor is not a directory") from exc
            try:
                _verify_private_directory_fd(child_fd)
            except Exception:
                os.close(child_fd)
                raise
            os.close(parent_fd)
            parent_fd = child_fd
            _command_file_test_hook("directory_opened", component, parent_fd)

        filename = target.name
        try:
            final_fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        except FileNotFoundError:
            temporary = f".{filename}.{os.getpid()}.{os.urandom(6).hex()}.tmp"
            temporary_fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
            try:
                offset = 0
                while offset < len(payload):
                    offset += os.write(temporary_fd, payload[offset:])
                os.fsync(temporary_fd)
            finally:
                os.close(temporary_fd)
            try:
                os.link(
                    temporary,
                    filename,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                pass
            finally:
                os.unlink(temporary, dir_fd=parent_fd)
            try:
                final_fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
            except OSError as exc:
                raise ValueError("command-file occupant is not a private regular file") from exc
        except OSError as exc:
            raise ValueError("command-file occupant is not a private regular file") from exc
        try:
            _verify_command_file_fd(final_fd, payload)
            _command_file_test_hook("final_verified", filename, final_fd)
        finally:
            os.close(final_fd)
        os.fsync(parent_fd)
        return CommandFileBinding(
            path=target,
            durable_root=root,
            components=relative_components,
            filename=filename,
            digest=digest,
        )
    finally:
        os.close(parent_fd)


def _verify_private_directory_fd(fd: int) -> None:
    info = os.fstat(fd)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise ValueError("command-file ancestor is not an owner-private directory")


def _verify_trusted_root_fd(fd: int) -> None:
    info = os.fstat(fd)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise ValueError("command-file durable root is not a trusted directory")


def _identity_component(label: str, value: str) -> str:
    """Return a bounded filesystem component binding the exact UTF-8 identity."""

    return f"{label}-{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _verify_command_file_fd(fd: int, payload: bytes) -> None:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("command-file occupant is not a private regular file")
    if info.st_uid != os.geteuid():
        raise ValueError("command-file owner differs")
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        chunks.append(chunk)
    if b"".join(chunks) != payload:
        raise ValueError("command-file occupant bytes differ")


def _command_file_test_hook(stage: str, component: str, fd: int) -> None:
    if _COMMAND_FILE_TEST_HOOK is not None:
        _COMMAND_FILE_TEST_HOOK(stage, component, fd)


def has_session_argv(name: str) -> list[str]:
    return [TMUX_BIN, "has-session", "-t", name]


def show_environment_argv(name: str) -> list[str]:
    return [TMUX_BIN, "show-environment", "-t", name]


def capture_pane_argv(name: str, *, lines: int = 200) -> list[str]:
    return [TMUX_BIN, "capture-pane", "-p", "-t", name, "-S", f"-{lines}"]


def attach_argv(name: str) -> list[str]:
    return [TMUX_BIN, "attach-session", "-t", name]


def stop_argv(name: str) -> list[str]:
    return [TMUX_BIN, "send-keys", "-t", name, "C-c"]


def send_keys_argv(name: str, keys: Sequence[str]) -> list[str]:
    return [TMUX_BIN, "send-keys", "-t", name, *keys]


def run_tmux(argv: Sequence[str], *, check: bool = True) -> TmuxResult:
    """Run a tmux argv-list command with captured output."""

    completed = subprocess.run(
        list(argv),
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    result = TmuxResult(
        argv=tuple(argv),
        returncode=completed.returncode,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
    )
    if check and result.returncode != 0:
        raise TmuxError(
            result.stderr or result.stdout or f"tmux exited {result.returncode}",
            returncode=result.returncode,
        )
    return result


def start_session(
    operation_id: str,
    command: Sequence[str] | str,
    *,
    cwd: Path | str | None = None,
    run_paths: RunDirPaths | None = None,
    identity: Mapping[str, str] | None = None,
) -> str:
    """Start a detached tmux session and return its deterministic name."""

    name = session_name(operation_id)
    run_tmux(
        new_session_argv(
            name,
            command,
            cwd=cwd,
            stdout_path=run_paths.stdout_path if run_paths else None,
            stderr_path=run_paths.stderr_path if run_paths else None,
            environment=identity,
        )
    )
    return name


def inspect_session(name: str, *, expected_identity: Mapping[str, str] | None = None) -> SessionStatus:
    """Return live state and exact tmux-provided launch identity.

    The tmux server environment is the query surface.  No marker, receipt, or
    sidecar file is consulted; missing or mismatched identity is unavailable.
    """

    result = run_tmux(has_session_argv(name), check=False)
    if result.returncode == 0 and expected_identity is None:
        return SessionStatus(session_name=name, state="running", exists=True)
    if result.returncode == 0:
        env_result = run_tmux(show_environment_argv(name), check=False)
        if env_result.returncode != 0:
            return SessionStatus(
                session_name=name,
                state="unavailable",
                exists=True,
                detail=env_result.stderr or env_result.stdout or "tmux identity query failed",
            )
        values: dict[str, str] = {}
        for line in env_result.stdout.splitlines():
            if "=" in line and not line.startswith("-"):
                key, value = line.split("=", 1)
                values[key] = value
        identity = {
            "operation_id": values.get("ARNOLD_LAUNCH_OPERATION_ID"),
            "request_id": values.get("ARNOLD_LAUNCH_REQUEST_ID"),
            "envelope_digest": values.get("ARNOLD_LAUNCH_ENVELOPE_DIGEST"),
            "process_session_identity": values.get("ARNOLD_LAUNCH_PROCESS_IDENTITY"),
        }
        available = all(isinstance(value, str) and value for value in identity.values())
        expected_keys = {
            "operation_id": "ARNOLD_LAUNCH_OPERATION_ID",
            "request_id": "ARNOLD_LAUNCH_REQUEST_ID",
            "envelope_digest": "ARNOLD_LAUNCH_ENVELOPE_DIGEST",
            "process_session_identity": "ARNOLD_LAUNCH_PROCESS_IDENTITY",
        }
        matches = available and all(
            values.get(expected_keys.get(key, key)) == value
            for key, value in (expected_identity or {}).items()
        )
        return SessionStatus(
            session_name=name,
            state="running" if matches else "unavailable",
            exists=True,
            detail=None if matches else "exact launch identity unavailable or mismatched",
            operation_id=identity["operation_id"],
            request_id=identity["request_id"],
            envelope_digest=identity["envelope_digest"],
            process_session_identity=identity["process_session_identity"],
            identity_available=bool(matches),
        )
    detail = result.stderr or result.stdout or None
    if detail and "no server running" in detail.lower():
        return SessionStatus(session_name=name, state="dead", exists=False, detail=detail)
    return SessionStatus(session_name=name, state="missing", exists=False, detail=detail)


def capture_pane(name: str, *, lines: int = 200) -> str:
    """Capture a tmux pane when it exists; raise for missing/dead sessions."""

    status = inspect_session(name)
    if not status.exists:
        raise TmuxError(status.detail or f"session {name!r} is {status.state}")
    return run_tmux(capture_pane_argv(name, lines=lines)).stdout


def stop_session(name: str) -> SessionStatus:
    """Send Ctrl-C to a session if it exists, otherwise return its status."""

    status = inspect_session(name)
    if not status.exists:
        return status
    run_tmux(stop_argv(name))
    return inspect_session(name)


def record_process_session_resource(
    config: AgentBoxConfig,
    operation_id: str,
    *,
    name: str,
    status: SessionStatus,
    details: Mapping[str, Any] | None = None,
    resource_id: str | None = None,
) -> TypedResource:
    """Record a PROCESS_SESSION durable resource for the tmux session."""

    resource = TypedResource(
        id=resource_id or f"{operation_id}:process-session",
        operation_id=operation_id,
        resource_type=ResourceType.PROCESS_SESSION,
        name=name,
        details={
            "provider": "tmux",
            "session_name": name,
            "state": status.state,
            "exists": status.exists,
            **dict(details or {}),
        },
    )
    store = open_operation_store(config)
    try:
        return store.create_typed_resource(resource)
    except TypedResourceAlreadyExists:
        for existing in store.list_typed_resources(operation_id):
            if existing.id == resource.id:
                return existing
        raise


def _command_for_shell(
    command: Sequence[str] | str,
    *,
    stdout_path: Path | str | None,
    stderr_path: Path | str | None,
) -> str:
    if isinstance(command, str):
        rendered = command
    else:
        rendered = " ".join(_shell_quote(part) for part in command)
    if stdout_path is not None:
        rendered += f" >> {_shell_quote(str(stdout_path))}"
    if stderr_path is not None:
        rendered += f" 2>> {_shell_quote(str(stderr_path))}"
    return rendered


def _shell_quote(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_@%+=:,./-]+", value):
        return value
    return "'" + value.replace("'", "'\\''") + "'"


__all__ = [
    "CommandFileBinding",
    "SessionStatus",
    "TmuxError",
    "TmuxResult",
    "attach_argv",
    "capture_pane",
    "capture_pane_argv",
    "command_file_session_argv",
    "has_session_argv",
    "inspect_session",
    "materialize_command_file",
    "new_session_argv",
    "record_process_session_resource",
    "run_tmux",
    "show_environment_argv",
    "send_keys_argv",
    "session_name",
    "start_session",
    "stop_argv",
    "stop_session",
]
