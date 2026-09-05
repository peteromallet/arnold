from __future__ import annotations

import base64
import hashlib
import inspect
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

from arnold_pipelines.megaplan.cloud.spec import (
    CloudSpec,
    SshSpec,
    validate_ssh_host,
    validate_ssh_identity_file,
    validate_ssh_port,
    validate_ssh_user,
)
from arnold_pipelines.megaplan.types import CliError

from .base import (
    Provider,
    _logs_follow,
    _missing_cli_error,
    _write_redacted_output,
    parse_launch_engine_response,
)
from .ssh_preflight import (
    capacity_inventory_command,
    classify_container_inspect,
    container_inspect_command,
    parse_capacity_inventory_result,
    parse_workspace_prelaunch_result,
    validate_workspace_dir,
    workspace_prelaunch_command,
    validate_container_name,
)
from .resident_recovery import (
    parse_resident_down_receipt,
    parse_resident_reconcile_adoption_receipt,
    parse_resident_reconcile_down_receipt,
    parse_resident_recovery_receipt,
    resident_custody_host_root,
    resident_down_command,
    resident_only_container_name,
    resident_receipt_sha256,
    resident_reconcile_adoption_command,
    resident_recover_command,
)
from .zero_recovery import (
    bootstrap_reclaim_command,
    build_bootstrap_reclaim_transaction,
    build_predeploy_transaction,
    fence_command,
    parse_bootstrap_reclaim_receipt,
    parse_fence_receipt,
    validate_bootstrap_reclaim_transaction,
    validate_predeploy_transaction,
)
from ..hot_env import HotEnvError, hot_env_install_command, render_hot_env, validate_hot_env_mapping

LOGGER = logging.getLogger(__name__)

INSTALL_LINK = "Install: https://www.openssh.com/"
_CLOUD_SESSION_MARKER_DIR = "/workspace/.megaplan/cloud-sessions"
_FULL_GIT_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")


def _status_runtime_binding_from_marker(
    marker: Mapping[str, Any],
) -> tuple[str, str, str] | None:
    """Return the exact runtime root/revision selected by a session marker.

    Runtime cutovers publish ``runtime_binding.current_identity``.  Older
    markers carry the same root/revision split across the editable-install
    fields.  A partially present binding is corruption, not permission to
    silently select some other installed Arnold/Megaplan copy.
    """

    runtime_binding = marker.get("runtime_binding")
    if isinstance(runtime_binding, Mapping):
        identity = runtime_binding.get("current_identity")
        if not isinstance(identity, Mapping):
            raise CliError(
                "status_runtime_binding_invalid",
                "session runtime_binding has no current_identity",
            )
        root = str(identity.get("import_root") or "").strip()
        revision = str(identity.get("source_revision") or "").strip().lower()
        source = "runtime_binding"
    else:
        sync = marker.get("editable_install_sync")
        sync = sync if isinstance(sync, Mapping) else {}
        root = str(sync.get("source") or "").strip()
        revision = str(marker.get("editable_source_head") or "").strip().lower()
        source = "editable_install_sync"

    if not root and not revision:
        return None
    if not PurePosixPath(root).is_absolute() or not _FULL_GIT_SHA_RE.fullmatch(revision):
        raise CliError(
            "status_runtime_binding_invalid",
            "session runtime binding must contain an absolute import root and full source revision",
        )
    return root, revision, source


def _megaplan_status_module_command(
    *,
    workspace: str,
    plan: str | None,
    runtime_root: str,
    runtime_revision: str | None,
    session: str | None,
    marker_dir: str = _CLOUD_SESSION_MARKER_DIR,
) -> str:
    """Build the only SSH plan-status route.

    The command never resolves a console script from ``PATH``.  It first
    attests imports against the chosen source root/revision, then invokes the
    Megaplan module with safe-path isolation.  This prevents the native Arnold
    CLI named ``arnold`` from ever being selected by cloud plan status.
    """

    root = str(runtime_root or "").strip()
    if not PurePosixPath(root).is_absolute():
        raise CliError(
            "status_runtime_binding_invalid",
            "status runtime root must be an absolute path",
        )
    revision = str(runtime_revision or "").strip().lower()
    if revision and not _FULL_GIT_SHA_RE.fullmatch(revision):
        raise CliError(
            "status_runtime_binding_invalid",
            "status runtime revision must be a full Git SHA",
        )

    root_q = shlex.quote(root)
    workspace_q = shlex.quote(workspace)
    revision_assignment = (
        f"STATUS_RUNTIME_REVISION={shlex.quote(revision)}"
        if revision
        else f"STATUS_RUNTIME_REVISION=$(git -C {root_q} rev-parse HEAD)"
    )
    runtime_prefix = (
        "env -u PYTHONHOME PYTHONSAFEPATH=1 "
        f"PYTHONPATH={root_q} python -P -m"
    )
    status_argv = [
        "arnold_pipelines.megaplan",
        "status",
        "--project-dir",
        workspace,
    ]
    if plan is not None:
        status_argv.extend(["--plan", plan])
    if session:
        status_argv.extend(
            ["--cloud-session", session, "--cloud-marker-dir", marker_dir]
        )
    return (
        "set -e; "
        f"cd {workspace_q}; "
        f"{revision_assignment}; "
        f"{runtime_prefix} arnold_pipelines.megaplan.cloud.runtime_provenance "
        f"--expected-root {root_q} --expected-revision \"$STATUS_RUNTIME_REVISION\" "
        ">/dev/null; "
        f"{runtime_prefix} {shlex.join(status_argv)}"
    )

_ZERO_RECOVERY_CANARY_RUNTIME_FORMAT = (
    "{{json .State}}\n{{json .Config.Env}}\n{{json .Config.Cmd}}\n"
    "{{json .HostConfig.RestartPolicy}}\n{{json .HostConfig.Init}}\n{{json .Mounts}}\n"
    "{{json .HostConfig.CapDrop}}\n{{json .HostConfig.CapAdd}}\n"
    "{{json .HostConfig.SecurityOpt}}\n{{json .HostConfig.IpcMode}}\n"
    "{{json .HostConfig.Tmpfs}}\n{{json .HostConfig.PidsLimit}}\n"
    "{{json .HostConfig.Memory}}\n{{json .HostConfig.MemorySwap}}\n"
    "{{json .HostConfig.PortBindings}}"
)

_ISOLATED_CHAIN_RUNNER_ENTRYPOINT = "/root/.pyenv/versions/3.11.11/bin/python3"
_ISOLATED_CHAIN_RUNNER_HEALTH_CODE = """import http.server
import os
import socketserver

if os.environ.get("MEGAPLAN_ISOLATED_CHAIN_RUNNER") != "1":
    raise SystemExit(64)
port = int(os.environ.get("PORT", "8080"))

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"OK - megaplan isolated chain runner alive\\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass

with socketserver.ThreadingTCPServer(("0.0.0.0", port), Handler) as httpd:
    httpd.serve_forever()
"""
_ISOLATED_CHAIN_RUNNER_COMMAND = (
    "-I",
    "-S",
    "-c",
    _ISOLATED_CHAIN_RUNNER_HEALTH_CODE,
)
_ISOLATED_CHAIN_RUNNER_FORBIDDEN_ENV_NAMES = frozenset(
    {
        "BASH_ENV",
        "ENV",
        "GCONV_PATH",
        "HOSTALIASES",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "LOCPATH",
        "NLSPATH",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
    }
)


def _strict_env_mapping(raw: object) -> dict[str, str] | None:
    if not isinstance(raw, list):
        return None
    result: dict[str, str] = {}
    for item in raw:
        if not isinstance(item, str) or "=" not in item:
            return None
        name, value = item.split("=", 1)
        if not name or name in result:
            return None
        result[name] = value
    return result


def _isolated_env_name_is_forbidden(name: str) -> bool:
    return (
        name in _ISOLATED_CHAIN_RUNNER_FORBIDDEN_ENV_NAMES
        or name.startswith("BASH_FUNC_")
        or name.startswith("LD_")
        or name.startswith("PYTHON")
    )
_ISOLATED_CHAIN_RUNNER_RUNTIME_FORMAT = (
    "{{json .State}}\n{{json .Config.Env}}\n{{json .Config.Entrypoint}}\n"
    "{{json .Config.Cmd}}\n{{json .Image}}\n{{json .Config.Image}}\n"
    "{{json .HostConfig.RestartPolicy}}\n{{json .Mounts}}\n{{json .Id}}\n"
    "{{json .HostConfig.Privileged}}\n{{json .HostConfig.Devices}}\n"
    "{{json .HostConfig.DeviceRequests}}\n{{json .HostConfig.CapDrop}}\n"
    "{{json .HostConfig.CapAdd}}\n{{json .HostConfig.SecurityOpt}}\n"
    "{{json .HostConfig.NetworkMode}}\n{{json .HostConfig.PidMode}}\n"
    "{{json .HostConfig.IpcMode}}\n{{json .HostConfig.Init}}\n"
    "{{json .HostConfig.PidsLimit}}\n{{json .HostConfig.Memory}}\n"
    "{{json .HostConfig.MemorySwap}}\n{{json .HostConfig.PortBindings}}\n"
    "{{json .Config.Healthcheck}}"
)
_DOCKER_IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ISOLATED_CHAIN_RUNNER_CAP_ADD = (
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "KILL",
    "SETGID",
    "SETUID",
)
_ISOLATED_CHAIN_RUNNER_MEMORY_BYTES = 8 * 1024 * 1024 * 1024
_ISOLATED_CHAIN_RUNNER_PIDS_LIMIT = 1024


def _isolated_chain_runner_runtime_command(container: str) -> str:
    return shlex.join(
        [
            "docker",
            "inspect",
            "--type=container",
            "--format",
            _ISOLATED_CHAIN_RUNNER_RUNTIME_FORMAT,
            validate_container_name(container),
        ]
    )


def _normalized_docker_cap_add(value: object) -> object:
    """Normalize Docker's daemon-dependent CAP_ display prefix."""
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        return value
    return [item.removeprefix("CAP_") for item in value]


_ZERO_RECOVERY_WORKSPACE_PREP_SCRIPT = r"""
import hashlib, json, os, stat, sys

parent, child = sys.argv[1:3]
parent_realpath = os.path.realpath(parent)
if parent_realpath != parent:
    raise RuntimeError("isolated_workspace_parent_not_canonical")
parent_stat = os.lstat(parent)
if not stat.S_ISDIR(parent_stat.st_mode) or stat.S_ISLNK(parent_stat.st_mode):
    raise RuntimeError("isolated_workspace_parent_invalid")
name = os.path.basename(child)
if not name or os.path.dirname(child) != parent or os.path.join(parent, name) != child:
    raise RuntimeError("isolated_workspace_not_direct_child")
parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    os.mkdir(name, 0o700, dir_fd=parent_fd)
    child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        initial_stat = os.fstat(child_fd)
        if (
            not stat.S_ISDIR(initial_stat.st_mode)
            or stat.S_IMODE(initial_stat.st_mode) != 0o700
            or initial_stat.st_uid != 0
            or initial_stat.st_gid != 0
            or os.listdir(child_fd)
        ):
            raise RuntimeError("isolated_workspace_initial_custody_invalid")
        os.fchown(child_fd, 0, 65532)
        os.fchmod(child_fd, 0o750)
        child_stat = os.fstat(child_fd)
        if (
            not stat.S_ISDIR(child_stat.st_mode)
            or stat.S_IMODE(child_stat.st_mode) != 0o750
            or child_stat.st_uid != 0
            or child_stat.st_gid != 65532
            or child_stat.st_dev != initial_stat.st_dev
            or child_stat.st_ino != initial_stat.st_ino
        ):
            raise RuntimeError("isolated_workspace_mode_invalid")
        if os.listdir(child_fd):
            raise RuntimeError("isolated_workspace_not_empty")
        child_realpath = os.path.realpath(child)
        if child_realpath != child:
            raise RuntimeError("isolated_workspace_child_not_canonical")
        os.fsync(child_fd)
    finally:
        os.close(child_fd)
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
initial_custody = {
    "mode": "0700", "uid": 0, "gid": 0,
    "st_dev": initial_stat.st_dev, "st_ino": initial_stat.st_ino,
    "empty": True,
}
runtime_access = {
    "mode": "0750", "uid": 0, "gid": 65532,
    "st_dev": child_stat.st_dev, "st_ino": child_stat.st_ino,
}
transition = {"initial_custody": initial_custody, "runtime_access": runtime_access}
print(json.dumps({
    "schema": "arnold.cloud.zero_recovery_isolated_workspace.v1",
    "status": "created",
    "parent": parent,
    "parent_realpath": parent_realpath,
    "bind_source": child,
    "bind_source_realpath": child_realpath,
    "bind_destination": "/workspace",
    "initial_custody": initial_custody,
    "runtime_access": runtime_access,
    "transition_digest": hashlib.sha256(json.dumps(
        transition, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest(),
    "created_empty": True,
    "never_reused": True,
}, sort_keys=True, separators=(",", ":")))
""".strip()

_ZERO_RECOVERY_WORKSPACE_RESEAL_SCRIPT = r"""
import hashlib, json, os, stat, sys

child, expected_dev, expected_ino, access_digest = sys.argv[1:5]
expected_dev, expected_ino = int(expected_dev), int(expected_ino)
if os.path.realpath(child) != child:
    raise RuntimeError("terminal_workspace_not_canonical")
fd = os.open(child, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    before = os.fstat(fd)
    if (
        not stat.S_ISDIR(before.st_mode)
        or before.st_dev != expected_dev
        or before.st_ino != expected_ino
        or before.st_uid != 0
        or before.st_gid not in {0, 65532}
        or stat.S_IMODE(before.st_mode) not in {0o700, 0o750}
    ):
        raise RuntimeError("terminal_workspace_identity_mismatch")
    os.fchown(fd, 0, 0)
    os.fchmod(fd, 0o700)
    os.fsync(fd)
    after = os.fstat(fd)
finally:
    os.close(fd)
if (
    after.st_dev != expected_dev or after.st_ino != expected_ino
    or after.st_uid != 0 or after.st_gid != 0
    or stat.S_IMODE(after.st_mode) != 0o700
):
    raise RuntimeError("terminal_workspace_reseal_failed")
transition = {
    "before": {
        "st_dev": before.st_dev, "st_ino": before.st_ino,
        "uid": before.st_uid, "gid": before.st_gid,
        "mode": f"{stat.S_IMODE(before.st_mode):04o}",
    },
    "after": {
        "st_dev": after.st_dev, "st_ino": after.st_ino,
        "uid": after.st_uid, "gid": after.st_gid,
        "mode": f"{stat.S_IMODE(after.st_mode):04o}",
    },
}
print(json.dumps({
    "schema": "arnold.cloud.zero_recovery_terminal_workspace.v1",
    "status": "sealed",
    "path": child,
    "access_transition_digest": access_digest,
    "transition": transition,
    "transition_digest": hashlib.sha256(json.dumps(
        transition, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest(),
}, sort_keys=True, separators=(",", ":")))
""".strip()

_ZERO_RECOVERY_OAUTH_INSTALL_SCRIPT = r"""
import json, os, stat, sys

def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate auth field")
        result[key] = value
    return result

def safe_child_dir(base, name):
    base_stat = os.lstat(base)
    if not stat.S_ISDIR(base_stat.st_mode) or stat.S_ISLNK(base_stat.st_mode):
        raise RuntimeError("unsafe credential base directory")
    try:
        os.mkdir(os.path.join(base, name), 0o700)
    except FileExistsError:
        pass
    child = os.path.join(base, name)
    child_stat = os.lstat(child)
    if not stat.S_ISDIR(child_stat.st_mode) or stat.S_ISLNK(child_stat.st_mode):
        raise RuntimeError("unsafe credential directory")
    os.chmod(child, 0o700, follow_symlinks=False)
    return child

def atomic_install(parent, name, data):
    directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = "." + name + ".zero-recovery-new"
    try:
        try:
            existing = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise RuntimeError("credential destination is not a regular file")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        temporary_fd = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        try:
            view = memoryview(data)
            while view:
                written = os.write(temporary_fd, view)
                view = view[written:]
            os.fchmod(temporary_fd, 0o600)
            os.fsync(temporary_fd)
        finally:
            os.close(temporary_fd)
        os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
        installed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(installed.st_mode) or stat.S_IMODE(installed.st_mode) != 0o600:
            raise RuntimeError("credential installation verification failed")
    finally:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.close(directory_fd)

raw = sys.stdin.buffer.read()
auth = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
if not isinstance(auth, dict) or auth.get("auth_mode") != "chatgpt":
    raise RuntimeError("ChatGPT OAuth object required")
root_codex = safe_child_dir("/root", ".codex")
atomic_install(root_codex, "auth.json", raw)
config = b'preferred_auth_method = "chatgpt"\nforced_login_method = "chatgpt"\nmodel = "gpt-5.6-sol"\nmodel_reasoning_effort = "high"\napproval_policy = "never"\nsandbox_mode = "danger-full-access"\n'
atomic_install(root_codex, "config.toml", config)
""".strip()

_ISOLATED_GIT_CREDENTIAL_INSTALL_SCRIPT = r"""
import json, os, stat, sys, urllib.parse

home = sys.argv[1]
if home != "/root":
    raise RuntimeError("isolated git credential home rejected")
token = sys.stdin.buffer.read()
if (
    not token
    or len(token) > 4096
    or any(byte < 0x21 or byte > 0x7e for byte in token)
):
    raise RuntimeError("isolated git credential token rejected")

def require_directory(path, mode):
    try:
        current = os.lstat(path)
    except FileNotFoundError:
        os.mkdir(path, mode)
        current = os.lstat(path)
    if not stat.S_ISDIR(current.st_mode) or stat.S_ISLNK(current.st_mode):
        raise RuntimeError("isolated git credential directory rejected")
    if current.st_uid != 0 or current.st_gid != 0:
        raise RuntimeError("isolated git credential directory custody rejected")
    os.chmod(path, mode, follow_symlinks=False)

def atomic_replace(parent, name, data):
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = "." + name + ".isolated-new"
    try:
        try:
            existing = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and (
            not stat.S_ISREG(existing.st_mode)
            or existing.st_uid != 0
            or existing.st_gid != 0
        ):
            raise RuntimeError("isolated git credential destination rejected")
        try:
            stale = os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            stale = None
        if stale is not None:
            if (
                not stat.S_ISREG(stale.st_mode)
                or stale.st_uid != 0
                or stale.st_gid != 0
            ):
                raise RuntimeError("isolated git credential temporary rejected")
            os.unlink(temporary, dir_fd=parent_fd)
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
        installed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(installed.st_mode)
            or stat.S_IMODE(installed.st_mode) != 0o600
            or installed.st_uid != 0
            or installed.st_gid != 0
        ):
            raise RuntimeError("isolated git credential install verification failed")
    finally:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)

config_root = os.path.join(home, ".config")
credential_root = os.path.join(config_root, "megaplan")
gh_root = os.path.join(config_root, "gh")
require_directory(config_root, 0o700)
require_directory(credential_root, 0o700)
require_directory(gh_root, 0o700)
gh_hosts = os.path.join(gh_root, "hosts.yml")
try:
    prior_gh = os.lstat(gh_hosts)
except FileNotFoundError:
    prior_gh = None
if prior_gh is not None:
    if (
        not stat.S_ISREG(prior_gh.st_mode)
        or prior_gh.st_uid != 0
        or prior_gh.st_gid != 0
    ):
        raise RuntimeError("isolated gh credential destination rejected")
    os.unlink(gh_hosts)
credential_path = os.path.join(credential_root, "git-credentials")
encoded = urllib.parse.quote_from_bytes(token, safe="")
credential = ("https://x-access-token:" + encoded + "@github.com\n").encode("ascii")
git_config = (
    "[credential]\n"
    "\thelper = store --file " + credential_path + "\n"
    "\tuseHttpPath = false\n"
    "[user]\n"
    "\tname = Arnold Megaplan\n"
    "\temail = megaplan@arnold.invalid\n"
).encode("utf-8")
atomic_replace(credential_root, "git-credentials", credential)
atomic_replace(home, ".gitconfig", git_config)
print(json.dumps({
    "schema": "arnold.cloud.isolated_chain_runner_git_auth.v1",
    "status": "seeded",
    "credential_file_mode": "0600",
    "config_file_mode": "0600",
    "credential_scope": "github.com",
    "credential_helper": "store",
    "user_name": "Arnold Megaplan",
    "user_email": "megaplan@arnold.invalid",
}, sort_keys=True, separators=(",", ":")))
""".strip()

_ISOLATED_GH_AUTH_ATTEST_SCRIPT = r"""
import json, os, stat

def require_root_file(path):
    current = os.lstat(path)
    if (
        not stat.S_ISREG(current.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or current.st_uid != 0
        or current.st_gid != 0
        or stat.S_IMODE(current.st_mode) != 0o600
    ):
        raise RuntimeError("isolated auth file custody rejected")

hosts = "/root/.config/gh/hosts.yml"
git_config = "/root/.gitconfig"
credential = "/root/.config/megaplan/git-credentials"
require_root_file(hosts)
require_root_file(git_config)
require_root_file(credential)
expected_config = (
    "[credential]\n"
    "\thelper = store --file /root/.config/megaplan/git-credentials\n"
    "\tuseHttpPath = false\n"
    "[user]\n"
    "\tname = Arnold Megaplan\n"
    "\temail = megaplan@arnold.invalid\n"
)
with open(git_config, "r", encoding="utf-8") as stream:
    if stream.read() != expected_config:
        raise RuntimeError("isolated git config identity or helper changed")
print(json.dumps({
    "schema": "arnold.cloud.isolated_chain_runner_gh_auth.v1",
    "status": "authenticated",
    "hostname": "github.com",
    "config_file_mode": "0600",
}, sort_keys=True, separators=(",", ":")))
""".strip()


def _zero_recovery_canary_runtime_command(container: str) -> str:
    """Build the exact fixed inspect argv; ``container`` is never positional."""
    return shlex.join(
        [
            "docker",
            "inspect",
            "--type=container",
            "--format",
            _ZERO_RECOVERY_CANARY_RUNTIME_FORMAT,
            validate_container_name(container),
        ]
    )


def _require_advertised_branch_commit(
    *, stdout: str, branch: str, source_commit: str
) -> None:
    lines = [line for line in stdout.splitlines() if line.strip()]
    expected = f"{source_commit}\trefs/heads/{branch}"
    if lines != [expected]:
        raise CliError(
            "zero_recovery_canary_branch_moved",
            "advertised branch tip does not equal the admitted launch commit",
        )


class SshProvider(Provider):
    def __init__(
        self,
        spec: CloudSpec,
        *,
        ssh_effect_adapter: Any | None = None,
    ) -> None:
        self._spec = spec
        self._ssh = spec.ssh or SshSpec(host="localhost")
        self._validated_host = validate_ssh_host(self._ssh.host)
        self._validated_user = validate_ssh_user(self._ssh.user)
        self._validated_port = validate_ssh_port(self._ssh.port)
        self._validated_identity_file = validate_ssh_identity_file(
            self._ssh.identity_file
        )
        self._ssh_binary = shutil.which("ssh")
        self._scp_binary = shutil.which("scp")
        self._rsync_binary = shutil.which("rsync")
        self._ssh_effect_adapter = ssh_effect_adapter
        self._consumed_zero_recovery_transactions: set[str] = set()
        if self._ssh_binary is None:
            _missing_cli_error("ssh", INSTALL_LINK.removeprefix("Install: "))
        if self._scp_binary is None and self._rsync_binary is None:
            _missing_cli_error("scp/rsync", INSTALL_LINK.removeprefix("Install: "))

    def authoritative_store_root(self) -> str:
        return "/workspace/ops"

    def _target(self) -> str:
        if self._validated_user:
            return f"{self._validated_user}@{self._validated_host}"
        return self._validated_host

    def _ssh_transport_argv(self) -> list[str]:
        argv = [self._ssh_binary or "ssh", "-p", str(self._validated_port)]
        if self._validated_identity_file:
            argv.extend(["-i", self._validated_identity_file])
        return argv

    def _ssh_destination_argv(self) -> list[str]:
        return [*self._ssh_transport_argv(), "--", self._target()]

    def _process_adapter_evidence_root(self) -> Path:
        return Path(tempfile.gettempdir()) / "arnold-process-adapter-wbc" / "ssh"

    def _run(
        self,
        argv: list[str],
        *,
        capture_output: bool = True,
        input: str | None = None,
        surface: str = "shell_command",
        raise_on_failure: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        attempt = self._begin_process_adapter_attempt(
            surface=surface,
            start_details={
                "executable": Path(argv[0]).name if argv else "",
                "argument_count": len(argv),
                "capture_output": capture_output,
                "input_supplied": input is not None,
            },
        )
        try:
            kwargs: dict[str, object] = {
                "capture_output": capture_output,
                "text": True,
                "check": False,
            }
            if input is not None:
                kwargs["input"] = input
            result = subprocess.run(argv, **kwargs)
        except FileNotFoundError as exc:
            message = self._redact_failure_text(str(exc))
            attempt.terminal(
                status="failed",
                outcome="blocked",
                details={"error_type": type(exc).__name__, "message": message},
            )
            raise CliError("provider_failed", message) from exc
        if result.returncode != 0:
            stderr = self._redact_failure_text((result.stderr or "").strip())
            stdout = self._redact_failure_text((result.stdout or "").strip())
            attempt.terminal(
                status="failed",
                outcome="indeterminate",
                details={
                    "returncode": result.returncode,
                    "stderr": stderr,
                    "stdout": stdout,
                },
            )
            if raise_on_failure:
                details = [
                    f"provider command failed (surface={surface}, returncode={result.returncode})"
                ]
                if stderr:
                    details.append(f"stderr: {stderr}")
                if stdout:
                    details.append(f"stdout: {stdout}")
                if not stderr and not stdout:
                    details.append("stderr: <empty>; stdout: <empty>")
                raise CliError("provider_failed", "; ".join(details))
            return result
        attempt.terminal(
            status="completed",
            outcome="succeeded",
            details={"returncode": result.returncode},
        )
        return result

    def _redact_failure_text(self, value: str) -> str:
        from arnold_pipelines.megaplan.cloud.redact import redact

        failure_env = dict(os.environ)
        # Provider failures and their WBC evidence must never become a secret
        # exfiltration surface, even when ordinary output redaction is disabled.
        failure_env["ARNOLD_REDACTION_ENABLED"] = "1"
        redacted = redact(value, self._spec.secrets, env=failure_env)
        for secret in getattr(self, "_ephemeral_redaction_values", ()):
            if secret:
                redacted = redacted.replace(secret, "[REDACTED]")
        return redacted

    def _remote_run_secret_input(
        self, command: str, *, secret: str, surface: str
    ) -> subprocess.CompletedProcess[str]:
        previous = getattr(self, "_ephemeral_redaction_values", ())
        self._ephemeral_redaction_values = (*previous, secret)
        try:
            return self._remote_run_compatible(
                command,
                input=secret,
                surface=surface,
            )
        finally:
            self._ephemeral_redaction_values = previous

    def _remote_run(
        self,
        command: str,
        *,
        capture_output: bool = True,
        input: str | None = None,
        surface: str = "remote_command",
        raise_on_failure: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return self._run(
            [*self._ssh_destination_argv(), command],
            capture_output=capture_output,
            input=input,
            surface=surface,
            raise_on_failure=raise_on_failure,
        )

    def _host_observation(self, operation: str) -> subprocess.CompletedProcess[str]:
        """Run one of the fixed host observations without WBC allocation.

        Observation transport is deliberately outside ``_run``: that method
        reserves and appends a process-adapter WBC attempt, which is valid for
        effects but would make a preflight mutate custody before admission.
        """
        if operation == "container":
            command = container_inspect_command(self._ssh.container)
            surface = "observe_container"
        elif operation == "predecessor-container":
            predecessor = self._spec.zero_recovery_predecessor_container
            if not predecessor:
                raise CliError(
                    "invalid_provider_observation",
                    "predecessor observation requires a zero-recovery predecessor",
                )
            command = container_inspect_command(predecessor)
            surface = "observe_predecessor_container"
        elif operation == "prelaunch-capacity":
            command = workspace_prelaunch_command(
                validate_workspace_dir(self._ssh.workspace_dir),
                min_free_bytes=self._spec.resources.prelaunch_min_free_bytes,
                min_free_inodes=self._spec.resources.prelaunch_min_free_inodes,
                receipt_reserve_bytes=self._spec.resources.prelaunch_receipt_reserve_bytes,
            )
            surface = "observe_prelaunch_capacity"
        elif operation == "capacity-inventory":
            command = capacity_inventory_command(
                workspace_dir=self._ssh.workspace_dir,
                remote_dir=self._ssh.remote_dir,
                cache_dir=self._ssh.cache_dir,
            )
            surface = "observe_capacity_inventory"
        else:
            raise CliError(
                "invalid_provider_observation",
                "SSH host observation is not allowlisted",
            )
        argv = [*self._ssh_destination_argv(), command]
        try:
            return subprocess.run(
                argv,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError as exc:
            return subprocess.CompletedProcess(
                argv,
                255,
                "",
                f"observation transport unavailable: {type(exc).__name__}",
            )

    def observe_container(self) -> dict[str, Any]:
        result = self._host_observation("container")
        return classify_container_inspect(
            returncode=result.returncode,
            stdout=self._redact_failure_text(result.stdout or ""),
            stderr=self._redact_failure_text(result.stderr or ""),
            expected_container=self._ssh.container,
        )

    def _resolve_isolated_chain_runner_image_id(self) -> str:
        configured = self._spec.isolated_chain_runner_image_id
        if configured is None or not _DOCKER_IMAGE_ID_RE.fullmatch(configured):
            raise CliError(
                "isolated_chain_runner_image_pin_required",
                "isolated chain-runner requires an exact configured sha256 image ID",
            )
        result = self._remote_run_compatible(
            shlex.join(
                [
                    "docker",
                    "image",
                    "inspect",
                    "--format",
                    "{{json .Id}}",
                    configured,
                ]
            ),
            surface="isolated_chain_runner_image_resolve",
        )
        try:
            image_id = json.loads((result.stdout or "").strip())
        except json.JSONDecodeError as exc:
            raise CliError(
                "isolated_chain_runner_image_unknown",
                "isolated chain-runner image identity was not strict JSON",
            ) from exc
        if result.returncode != 0 or image_id != configured:
            raise CliError(
                "isolated_chain_runner_image_unknown",
                "isolated chain-runner image identity was unavailable or malformed",
            )
        env_result = self._remote_run_compatible(
            shlex.join(
                [
                    "docker",
                    "image",
                    "inspect",
                    "--format",
                    "{{json .Config.Env}}",
                    image_id,
                ]
            ),
            surface="isolated_chain_runner_image_env_observe",
        )
        try:
            raw_env = json.loads((env_result.stdout or "").strip())
        except json.JSONDecodeError as exc:
            raise CliError(
                "isolated_chain_runner_image_env_unknown",
                "isolated chain-runner immutable image environment was not strict JSON",
            ) from exc
        image_env = _strict_env_mapping(raw_env)
        if (
            env_result.returncode != 0
            or image_env is None
            or "PORT" in image_env
            or "MEGAPLAN_ISOLATED_CHAIN_RUNNER" in image_env
            or any(_isolated_env_name_is_forbidden(name) for name in image_env)
        ):
            raise CliError(
                "isolated_chain_runner_image_env_rejected",
                "isolated chain-runner immutable image environment was unsafe or malformed",
            )
        self._isolated_chain_runner_image_env = image_env
        return image_id

    def _observe_isolated_chain_runner_runtime(
        self,
        *,
        expected_image_id: str,
        target: str,
        expected_container_id: str | None = None,
        expected_lifecycle: str = "running",
    ) -> dict[str, Any]:
        if expected_lifecycle not in {"running", "stopped"}:
            raise CliError(
                "isolated_chain_runner_runtime_unknown",
                "isolated chain-runner lifecycle expectation was invalid",
            )
        result = self._remote_run_compatible(
            _isolated_chain_runner_runtime_command(target),
            surface="isolated_chain_runner_runtime_observe",
        )
        try:
            lines = (result.stdout or "").splitlines()
            if len(lines) != 24:
                raise ValueError("expected twenty-four docker inspect fields")
            (
                state,
                env,
                entrypoint,
                command,
                image_id,
                image_ref,
                restart_policy,
                mounts,
                container_id,
                privileged,
                devices,
                device_requests,
                cap_drop,
                cap_add,
                security_opt,
                network_mode,
                pid_mode,
                ipc_mode,
                init,
                pids_limit,
                memory,
                memory_swap,
                port_bindings,
                healthcheck,
            ) = (json.loads(line) for line in lines)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise CliError(
                "isolated_chain_runner_runtime_unknown",
                "isolated chain-runner runtime evidence was malformed",
            ) from exc

        observed_env = _strict_env_mapping(env)
        image_env = getattr(self, "_isolated_chain_runner_image_env", None)
        expected_env = (
            {
                **image_env,
                "PORT": str(self._spec.resources.port),
                "MEGAPLAN_ISOLATED_CHAIN_RUNNER": "1",
            }
            if isinstance(image_env, dict)
            else None
        )
        expected_mounts = {
            (
                "bind",
                self._ssh.workspace_dir,
                "/workspace",
                True,
            ),
            (
                "bind",
                f"{self._ssh.cache_dir}/pip",
                "/root/.cache/pip",
                True,
            ),
            (
                "bind",
                f"{self._ssh.cache_dir}/npm",
                "/root/.npm",
                True,
            ),
        }
        observed_mounts = (
            {
                (
                    item.get("Type"),
                    item.get("Source"),
                    item.get("Destination"),
                    item.get("RW"),
                )
                for item in mounts
                if isinstance(item, Mapping)
            }
            if isinstance(mounts, list)
            else set()
        )
        state_status = state.get("Status") if isinstance(state, Mapping) else None
        state_running = state.get("Running") if isinstance(state, Mapping) else None
        state_paused = state.get("Paused") if isinstance(state, Mapping) else None
        state_restarting = (
            state.get("Restarting") if isinstance(state, Mapping) else None
        )
        state_status_valid = (
            state_status == "running"
            if expected_lifecycle == "running"
            else state_status in {"created", "exited", "dead"}
        )
        valid = (
            result.returncode == 0
            and isinstance(state, Mapping)
            and state_status_valid
            and state_running is (expected_lifecycle == "running")
            and state_paused is False
            and state_restarting is False
            and observed_env is not None
            and expected_env is not None
            and observed_env == expected_env
            and not any(
                _isolated_env_name_is_forbidden(name) for name in observed_env
            )
            and entrypoint == [_ISOLATED_CHAIN_RUNNER_ENTRYPOINT]
            and command == list(_ISOLATED_CHAIN_RUNNER_COMMAND)
            and image_id == expected_image_id
            and image_ref == expected_image_id
            and restart_policy == {"Name": "unless-stopped", "MaximumRetryCount": 0}
            and privileged is False
            and devices == []
            and device_requests in (None, [])
            and _normalized_docker_cap_add(cap_drop) == ["ALL"]
            and _normalized_docker_cap_add(cap_add)
            == list(_ISOLATED_CHAIN_RUNNER_CAP_ADD)
            and security_opt == ["no-new-privileges:true"]
            and network_mode == "bridge"
            and pid_mode == ""
            and ipc_mode == "private"
            and init is True
            and pids_limit == _ISOLATED_CHAIN_RUNNER_PIDS_LIMIT
            and memory == _ISOLATED_CHAIN_RUNNER_MEMORY_BYTES
            and memory_swap == _ISOLATED_CHAIN_RUNNER_MEMORY_BYTES
            and port_bindings
            == {
                f"{self._spec.resources.port}/tcp": [
                    {"HostIp": "", "HostPort": str(self._spec.resources.port)}
                ]
            }
            and healthcheck == {"Test": ["NONE"]}
            and isinstance(mounts, list)
            and len(mounts) == len(expected_mounts)
            and len(observed_mounts) == len(mounts)
            and observed_mounts == expected_mounts
            and isinstance(container_id, str)
            and bool(re.fullmatch(r"[0-9a-f]{64}", container_id))
            and (
                expected_container_id is None
                or container_id == expected_container_id
            )
        )
        if not valid:
            raise CliError(
                "isolated_chain_runner_runtime_mismatch",
                "isolated chain-runner image, command, marker, lifecycle, or workspace binding mismatched",
            )
        observation = {
            "schema": "arnold.cloud.isolated_chain_runner_runtime.v1",
            "status": "available",
            "lifecycle": expected_lifecycle,
            "container": self._ssh.container,
            "container_id": container_id,
            "image_id": image_id,
            "image_ref": image_ref,
            "entrypoint": entrypoint,
            "command": command,
            "mounts": [
                {
                    "type": mount_type,
                    "source": source,
                    "destination": destination,
                    "rw": rw,
                }
                for mount_type, source, destination, rw in sorted(expected_mounts)
            ],
            "restart_policy": restart_policy,
            "host_config": {
                "privileged": privileged,
                "devices": devices,
                "device_requests": device_requests,
                "cap_drop": _normalized_docker_cap_add(cap_drop),
                "cap_add": _normalized_docker_cap_add(cap_add),
                "security_opt": security_opt,
                "network_mode": network_mode,
                "pid_mode": pid_mode,
                "ipc_mode": ipc_mode,
                "init": init,
                "pids_limit": pids_limit,
                "memory": memory,
                "memory_swap": memory_swap,
                "port_bindings": port_bindings,
                "healthcheck": healthcheck,
            },
        }
        self._isolated_chain_runner_deploy_observation = observation
        self._isolated_chain_runner_container_id = container_id
        return observation

    def attest_isolated_chain_runner_runtime(self) -> dict[str, Any]:
        if not self._spec.isolated_chain_runner:
            raise CliError(
                "isolated_chain_runner_attestation_unavailable",
                "isolated chain-runner profile is required",
            )
        expected_image_id = self._resolve_isolated_chain_runner_image_id()
        first = self.observe_container()
        container_id = first.get("container_id")
        if (
            first.get("status") != "available"
            or first.get("lifecycle") != "running"
            or not isinstance(container_id, str)
            or not re.fullmatch(r"[0-9a-f]{64}", container_id)
        ):
            raise CliError(
                "isolated_chain_runner_not_deployed",
                "exact isolated chain-runner deployment is not running",
            )
        observation = self._observe_isolated_chain_runner_runtime(
            expected_image_id=expected_image_id,
            target=container_id,
            expected_container_id=container_id,
        )
        second = self.observe_container()
        if (
            second.get("status") != "available"
            or second.get("lifecycle") != "running"
            or second.get("container_id") != container_id
        ):
            self._isolated_chain_runner_container_id = None
            raise CliError(
                "isolated_chain_runner_name_replaced",
                "isolated chain-runner name changed during runtime attestation",
            )
        return observation

    def _attest_isolated_chain_runner_stopped_runtime(
        self,
        *,
        expected_image_id: str,
    ) -> dict[str, Any]:
        """Prove an exited target is the exact isolated runtime before starting it.

        A stopped container is recoverable only when its immutable image,
        command, environment, capabilities, and workspace/cache mounts still
        match the pinned isolated profile.  The observation is repeated by
        name after the inspect so a replacement cannot be mistaken for the
        container that was admitted.  No ``rm``/``run`` path is used here;
        the existing container and its persistent workspace are preserved.
        """

        first = self.observe_container()
        container_id = first.get("container_id")
        if (
            first.get("status") != "available"
            or first.get("lifecycle") != "stopped"
            or not isinstance(container_id, str)
            or not re.fullmatch(r"[0-9a-f]{64}", container_id)
        ):
            raise CliError(
                "isolated_chain_runner_stopped_runtime_unknown",
                "stopped isolated chain-runner identity was unavailable",
            )
        observation = self._observe_isolated_chain_runner_runtime(
            expected_image_id=expected_image_id,
            target=container_id,
            expected_container_id=container_id,
            expected_lifecycle="stopped",
        )
        second = self.observe_container()
        if (
            second.get("status") != "available"
            or second.get("lifecycle") != "stopped"
            or second.get("container_id") != container_id
        ):
            raise CliError(
                "isolated_chain_runner_name_replaced",
                "isolated chain-runner name changed during stopped-runtime attestation",
            )
        return observation

    def seed_isolated_chain_runner_git_credentials(
        self, token: str
    ) -> dict[str, str]:
        """Install GitHub push auth in the exact attested isolated container.

        The token crosses both the local SSH boundary and the Docker exec
        boundary only on stdin.  The fixed installer emits no output and
        atomically replaces root-custodied credential/config files.
        """
        if not self._spec.isolated_chain_runner:
            raise CliError(
                "isolated_chain_runner_git_auth_invalid",
                "isolated chain-runner profile is required for Git auth seeding",
            )
        encoded = token.encode("utf-8")
        if (
            not token
            or len(encoded) > 4096
            or any(byte < 0x21 or byte > 0x7E for byte in encoded)
        ):
            raise CliError(
                "isolated_chain_runner_git_auth_invalid",
                "local GitHub auth token was empty or malformed",
            )
        before = self.attest_isolated_chain_runner_runtime()
        container_id = before["container_id"]
        command = shlex.join(
            [
                "docker",
                "exec",
                "-i",
                container_id,
                _ISOLATED_CHAIN_RUNNER_ENTRYPOINT,
                "-I",
                "-S",
                "-c",
                _ISOLATED_GIT_CREDENTIAL_INSTALL_SCRIPT,
                "/root",
            ]
        )
        install = self._remote_run_secret_input(
            command,
            secret=token,
            surface="isolated_chain_runner_git_auth_seed",
        )
        expected_receipt = {
            "schema": "arnold.cloud.isolated_chain_runner_git_auth.v1",
            "status": "seeded",
            "credential_file_mode": "0600",
            "config_file_mode": "0600",
            "credential_scope": "github.com",
            "credential_helper": "store",
            "user_name": "Arnold Megaplan",
            "user_email": "megaplan@arnold.invalid",
        }
        try:
            install_receipt = json.loads((install.stdout or "").strip())
        except json.JSONDecodeError as exc:
            raise CliError(
                "isolated_chain_runner_git_auth_failed",
                "isolated Git credential receipt was malformed",
            ) from exc
        if install_receipt != expected_receipt:
            raise CliError(
                "isolated_chain_runner_git_auth_failed",
                "isolated Git credential modes, helper, or identity were not attested",
            )
        self._remote_run_secret_input(
            shlex.join(
                [
                    "docker",
                    "exec",
                    "-i",
                    container_id,
                    "gh",
                    "auth",
                    "login",
                    "--hostname",
                    "github.com",
                    "--git-protocol",
                    "https",
                    "--with-token",
                    "--insecure-storage",
                ]
            ),
            secret=token,
            surface="isolated_chain_runner_gh_auth_seed",
        )
        self._remote_run_compatible(
            shlex.join(
                [
                    "docker",
                    "exec",
                    container_id,
                    "gh",
                    "auth",
                    "status",
                    "--hostname",
                    "github.com",
                ]
            ),
            surface="isolated_chain_runner_gh_auth_status",
        )
        gh_attestation_result = self._remote_run_compatible(
            shlex.join(
                [
                    "docker",
                    "exec",
                    container_id,
                    _ISOLATED_CHAIN_RUNNER_ENTRYPOINT,
                    "-I",
                    "-S",
                    "-c",
                    _ISOLATED_GH_AUTH_ATTEST_SCRIPT,
                ]
            ),
            surface="isolated_chain_runner_gh_auth_attest",
        )
        expected_gh_attestation = {
            "schema": "arnold.cloud.isolated_chain_runner_gh_auth.v1",
            "status": "authenticated",
            "hostname": "github.com",
            "config_file_mode": "0600",
        }
        try:
            gh_attestation = json.loads(
                (gh_attestation_result.stdout or "").strip()
            )
        except json.JSONDecodeError as exc:
            raise CliError(
                "isolated_chain_runner_git_auth_failed",
                "isolated gh auth receipt was malformed",
            ) from exc
        if gh_attestation != expected_gh_attestation:
            raise CliError(
                "isolated_chain_runner_git_auth_failed",
                "isolated gh auth status or root custody was not attested",
            )
        after = self.attest_isolated_chain_runner_runtime()
        if after.get("container_id") != container_id:
            raise CliError(
                "isolated_chain_runner_name_replaced",
                "isolated chain-runner changed during Git auth seeding",
            )
        return {
            **expected_receipt,
            "gh_auth_status": "authenticated",
            "gh_config_file_mode": "0600",
            "container_id": container_id,
        }

    def observe_zero_recovery_predecessor(self) -> dict[str, Any]:
        predecessor = self._spec.zero_recovery_predecessor_container
        if not predecessor:
            raise CliError(
                "zero_recovery_predeploy_invalid", "zero-recovery predecessor missing"
            )
        result = self._host_observation("predecessor-container")
        return classify_container_inspect(
            returncode=result.returncode,
            stdout=self._redact_failure_text(result.stdout or ""),
            stderr=self._redact_failure_text(result.stderr or ""),
            expected_container=predecessor,
        )

    def observe_zero_recovery_predecessor_capacity(self) -> dict[str, Any]:
        workspace = validate_workspace_dir(self._ssh.workspace_dir)
        container = self.observe_zero_recovery_predecessor()
        mount = container.get("workspace_bind")
        if not isinstance(mount, dict) or (
            mount.get("status") != "present"
            or mount.get("type") != "bind"
            or mount.get("source") != workspace
            or mount.get("rw") is not True
        ):
            return {
                "schema": "arnold.cloud.ssh_workspace_prelaunch.v1",
                "status": "no-go",
                "verdict": "NO-GO",
                "workspace": workspace,
                "errors": ["configured_workspace_bind_mismatch"],
                "container": container,
            }
        result = self._host_observation("prelaunch-capacity")
        payload = parse_workspace_prelaunch_result(
            returncode=result.returncode,
            stdout=self._redact_failure_text(result.stdout or ""),
            stderr=self._redact_failure_text(result.stderr or ""),
            expected_workspace=workspace,
            min_free_bytes=self._spec.resources.prelaunch_min_free_bytes,
            min_free_inodes=self._spec.resources.prelaunch_min_free_inodes,
            receipt_reserve_bytes=self._spec.resources.prelaunch_receipt_reserve_bytes,
        )
        payload["container"] = container
        return payload

    def observe_prelaunch_capacity(self) -> dict[str, Any]:
        """Probe only the configured host bind; no arbitrary host path is accepted."""
        workspace = validate_workspace_dir(self._ssh.workspace_dir)
        container = self.observe_container()
        mount = container.get("workspace_bind")
        if not isinstance(mount, dict) or (
            mount.get("status") != "present"
            or mount.get("type") != "bind"
            or mount.get("source") != workspace
            or mount.get("rw") is not True
        ):
            return {
                "schema": "arnold.cloud.ssh_workspace_prelaunch.v1",
                "status": "no-go",
                "verdict": "NO-GO",
                "workspace": workspace,
                "errors": ["configured_workspace_bind_mismatch"],
                "container": container,
            }
        result = self._host_observation("prelaunch-capacity")
        payload = parse_workspace_prelaunch_result(
            returncode=result.returncode,
            stdout=self._redact_failure_text(result.stdout or ""),
            stderr=self._redact_failure_text(result.stderr or ""),
            expected_workspace=workspace,
            min_free_bytes=self._spec.resources.prelaunch_min_free_bytes,
            min_free_inodes=self._spec.resources.prelaunch_min_free_inodes,
            receipt_reserve_bytes=self._spec.resources.prelaunch_receipt_reserve_bytes,
        )
        payload["container"] = container
        expected_mount = container.get("workspace_bind", {}).get("source")
        if payload.get("workspace") != workspace or expected_mount != workspace:
            payload["status"] = "no-go"
            payload["verdict"] = "NO-GO"
            payload.setdefault("errors", []).append("observed_workspace_mount_mismatch")
        return payload

    def observe_capacity_inventory(self) -> dict[str, Any]:
        """Return a fixed read-only inventory; this method never reclaims data."""
        paths = [self._ssh.workspace_dir, self._ssh.remote_dir, self._ssh.cache_dir]
        result = self._host_observation("capacity-inventory")
        return parse_capacity_inventory_result(
            returncode=result.returncode,
            stdout=self._redact_failure_text(result.stdout or ""),
            stderr=self._redact_failure_text(result.stderr or ""),
            expected_paths=paths,
        )

    def _resident_recovery_source_container(self) -> str:
        """Return the only source container admitted by the loaded profile."""
        return validate_container_name(
            self._spec.zero_recovery_predecessor_container or self._ssh.container
        )

    def _observe_resident_recovery_source(self) -> dict[str, Any]:
        source = self._resident_recovery_source_container()
        if source == self._ssh.container:
            return self.observe_container()
        return self.observe_zero_recovery_predecessor()

    def _observe_resident_recovery_capacity(self) -> dict[str, Any]:
        if self._spec.zero_recovery_predecessor_container:
            return self.observe_zero_recovery_predecessor_capacity()
        return self.observe_prelaunch_capacity()

    def _require_resident_recovery_source(
        self,
        *,
        expected_source_container_id: str,
        expected_source_image_id: str,
    ) -> dict[str, Any]:
        observation = self._observe_resident_recovery_source()
        expected_mount = {
            "status": "present",
            "type": "bind",
            "source": validate_workspace_dir(self._ssh.workspace_dir),
            "destination": "/workspace",
            "rw": True,
        }
        if (
            observation.get("status") != "available"
            or observation.get("lifecycle") != "stopped"
            or observation.get("container_id") != expected_source_container_id
            or observation.get("image_id") != expected_source_image_id
            or observation.get("workspace_bind") != expected_mount
        ):
            raise CliError(
                "resident_recovery_source_mismatch",
                "preserved source container failed stopped identity/image/workspace compare-and-swap",
            )
        return observation

    def resident_recover(
        self,
        *,
        outage_epoch: str,
        expected_source_container_id: str,
        expected_source_image_id: str,
        expected_resident_image_id: str,
        expected_runtime_path: str,
        expected_runtime_commit: str,
        expected_runtime_tree: str,
        expected_runtime_python_path: str,
        expected_runtime_python_sha256: str,
        health_timeout_seconds: int = 45,
    ) -> dict[str, Any]:
        """Start one finite, listener-only Discord resident transaction."""
        self._require_resident_recovery_source(
            expected_source_container_id=expected_source_container_id,
            expected_source_image_id=expected_source_image_id,
        )
        capacity = self._observe_resident_recovery_capacity()
        if capacity.get("status") != "go" or capacity.get("verdict") != "GO":
            raise CliError(
                "resident_recovery_capacity_no_go",
                "workspace capacity did not meet the configured byte/inode/receipt floors",
            )
        command, script = resident_recover_command(
            source_container=self._resident_recovery_source_container(),
            expected_source_container_id=expected_source_container_id,
            expected_source_image_id=expected_source_image_id,
            expected_resident_image_id=expected_resident_image_id,
            expected_runtime_path=expected_runtime_path,
            expected_runtime_commit=expected_runtime_commit,
            expected_runtime_tree=expected_runtime_tree,
            expected_runtime_python_path=expected_runtime_python_path,
            expected_runtime_python_sha256=expected_runtime_python_sha256,
            workspace=self._ssh.workspace_dir,
            outage_epoch=outage_epoch,
            min_free_bytes=self._spec.resources.prelaunch_min_free_bytes,
            min_free_inodes=self._spec.resources.prelaunch_min_free_inodes,
            receipt_reserve_bytes=self._spec.resources.prelaunch_receipt_reserve_bytes,
            health_timeout_seconds=health_timeout_seconds,
        )
        result = self._remote_run_compatible(
            command,
            input=script,
            surface="resident_only_recover",
        )
        payload = parse_resident_recovery_receipt(result.stdout or "")
        start = payload["start_receipt"]
        health = payload["health_receipt"]
        fence = payload["source_fence_receipt"]
        expected_resident = resident_only_container_name(
            self._resident_recovery_source_container()
        )
        receipt_prefix = (
            f"{resident_custody_host_root(expected_source_container_id)}/"
            f"{outage_epoch}/transaction"
        )
        if (
            payload.get("outage_epoch") != outage_epoch
            or fence.get("outage_epoch") != outage_epoch
            or fence.get("source_container_id") != expected_source_container_id
            or fence.get("source_image_id") != expected_source_image_id
            or fence.get("workspace") != self._ssh.workspace_dir
            or start.get("source_container_id") != expected_source_container_id
            or start.get("source_image_id") != expected_source_image_id
            or start.get("resident_image_id") != expected_resident_image_id
            or start.get("workspace") != self._ssh.workspace_dir
            or start.get("resident_container") != expected_resident
            or health.get("outage_epoch") != outage_epoch
            or health.get("resident_container") != expected_resident
            or health.get("resident_container_id")
            != start.get("resident_container_id")
            or payload.get("receipt_paths")
            != {
                "fence_intent": receipt_prefix + ".fence.intent.json",
                "fence": receipt_prefix + ".fence.json",
                "intent": receipt_prefix + ".intent.json",
                "seed": (
                    f"{resident_custody_host_root(expected_source_container_id)}/"
                    f"{outage_epoch}/seed/launch-seed.json"
                ),
                "start": receipt_prefix + ".start.json",
                "health": receipt_prefix + ".health.json",
            }
        ):
            raise CliError(
                "resident_recovery_unknown",
                "resident recovery receipt did not match the admitted transaction",
            )
        return payload

    def resident_down(
        self,
        *,
        outage_epoch: str,
        expected_source_container_id: str,
        expected_source_image_id: str,
        expected_resident_image_id: str,
        expected_resident_container_id: str,
    ) -> dict[str, Any]:
        """Stop/remove only the resident identity minted for one outage epoch."""
        command, script = resident_down_command(
            source_container=self._resident_recovery_source_container(),
            expected_source_container_id=expected_source_container_id,
            expected_source_image_id=expected_source_image_id,
            expected_resident_image_id=expected_resident_image_id,
            expected_resident_container_id=expected_resident_container_id,
            workspace=self._ssh.workspace_dir,
            outage_epoch=outage_epoch,
        )
        result = self._remote_run_compatible(
            command,
            input=script,
            surface="resident_only_down",
        )
        payload = parse_resident_down_receipt(result.stdout or "")
        if (
            payload.get("outage_epoch") != outage_epoch
            or payload.get("resident_container")
            != resident_only_container_name(self._resident_recovery_source_container())
            or payload.get("resident_container_id")
            != expected_resident_container_id
            or payload.get("source_fence_rollback", {}).get(
                "source_container_id"
            )
            != expected_source_container_id
        ):
            raise CliError(
                "resident_down_unknown",
                "resident down receipt did not match the admitted transaction",
            )
        return payload

    def resident_reconcile_down(
        self,
        *,
        outage_epoch: str,
        expected_source_container_id: str,
        expected_source_image_id: str,
        expected_resident_image_id: str,
        expected_resident_container_id: str,
        expected_resident_command_sha256: str,
        expected_resident_env_sha256: str,
        expected_recovery_seed_host_dir: str,
        expected_recovery_seed_sha256: str,
        expected_runtime_path: str,
        expected_runtime_commit: str,
        expected_runtime_tree: str,
        expected_runtime_content_sha256: str,
        expected_runtime_python_path: str,
        expected_runtime_python_sha256: str,
        expected_workspace_device: int,
        expected_workspace_inode: int,
    ) -> dict[str, Any]:
        """Adopt and remove one exact live resident lacking launch receipts."""

        self._require_resident_recovery_source(
            expected_source_container_id=expected_source_container_id,
            expected_source_image_id=expected_source_image_id,
        )
        source_container = self._resident_recovery_source_container()
        command, script = resident_reconcile_adoption_command(
            source_container=source_container,
            expected_source_container_id=expected_source_container_id,
            expected_source_image_id=expected_source_image_id,
            expected_resident_image_id=expected_resident_image_id,
            expected_resident_container_id=expected_resident_container_id,
            expected_resident_command_sha256=expected_resident_command_sha256,
            expected_resident_env_sha256=expected_resident_env_sha256,
            expected_recovery_seed_host_dir=expected_recovery_seed_host_dir,
            expected_recovery_seed_sha256=expected_recovery_seed_sha256,
            expected_runtime_path=expected_runtime_path,
            expected_runtime_commit=expected_runtime_commit,
            expected_runtime_tree=expected_runtime_tree,
            expected_runtime_content_sha256=expected_runtime_content_sha256,
            expected_runtime_python_path=expected_runtime_python_path,
            expected_runtime_python_sha256=expected_runtime_python_sha256,
            expected_workspace_device=expected_workspace_device,
            expected_workspace_inode=expected_workspace_inode,
            workspace=self._ssh.workspace_dir,
            outage_epoch=outage_epoch,
        )
        result = self._remote_run_compatible(
            command,
            input=script,
            surface="resident_only_reconcile_adopt",
        )
        adoption = parse_resident_reconcile_adoption_receipt(result.stdout or "")
        expected_resident = resident_only_container_name(source_container)
        if (
            adoption.get("outage_epoch") != outage_epoch
            or adoption.get("source_container_id") != expected_source_container_id
            or adoption.get("source_image_id") != expected_source_image_id
            or adoption.get("resident_container") != expected_resident
            or adoption.get("resident_container_id")
            != expected_resident_container_id
            or adoption.get("resident_image_id") != expected_resident_image_id
            or adoption.get("workspace") != self._ssh.workspace_dir
        ):
            raise CliError(
                "resident_reconcile_unknown",
                "resident adoption receipt did not match the admitted transaction",
            )
        adoption_sha = resident_receipt_sha256(adoption)
        command, script = resident_down_command(
            source_container=source_container,
            expected_source_container_id=expected_source_container_id,
            expected_source_image_id=expected_source_image_id,
            expected_resident_image_id=expected_resident_image_id,
            expected_resident_container_id=expected_resident_container_id,
            workspace=self._ssh.workspace_dir,
            outage_epoch=outage_epoch,
            expected_reconcile_adoption_sha256=adoption_sha,
        )
        result = self._remote_run_compatible(
            command,
            input=script,
            surface="resident_only_reconcile_down",
        )
        down = parse_resident_reconcile_down_receipt(result.stdout or "")
        if (
            down.get("outage_epoch") != outage_epoch
            or down.get("resident_container") != expected_resident
            or down.get("resident_container_id") != expected_resident_container_id
            or down.get("reconcile_adoption_sha256") != adoption_sha
            or down.get("source_fence_rollback", {}).get("source_container_id")
            != expected_source_container_id
        ):
            raise CliError(
                "resident_reconcile_unknown",
                "resident reconcile-down receipt did not match the admitted transaction",
            )
        return {
            "schema": "arnold.cloud.resident_only_reconcile_transaction.v1",
            "status": "down",
            "adoption_receipt": adoption,
            "down_receipt": down,
        }

    def _zero_recovery_isolated_workspace(self) -> str:
        configured = self._spec.zero_recovery_workspace_dir
        if not self._spec.zero_recovery_canary or configured is None:
            raise CliError(
                "zero_recovery_canary_invalid",
                "isolated zero-recovery workspace is not configured",
            )
        workspace = validate_workspace_dir(configured)
        parent = PurePosixPath(validate_workspace_dir(self._ssh.workspace_dir))
        if PurePosixPath(workspace).parent != parent:
            raise CliError(
                "zero_recovery_canary_invalid",
                "isolated workspace is not an exact child of the preserved workspace",
            )
        return workspace

    def _prepare_zero_recovery_isolated_workspace(self) -> dict[str, Any]:
        parent = validate_workspace_dir(self._ssh.workspace_dir)
        child = self._zero_recovery_isolated_workspace()
        result = self._remote_run_compatible(
            shlex.join(
                ["python3", "-c", _ZERO_RECOVERY_WORKSPACE_PREP_SCRIPT, parent, child]
            ),
            surface="zero_recovery_isolated_workspace_create",
        )
        lines = [line for line in (result.stdout or "").splitlines() if line.strip()]
        try:
            payload = json.loads(lines[0]) if len(lines) == 1 else None
        except json.JSONDecodeError as exc:
            raise CliError(
                "zero_recovery_workspace_unknown",
                "isolated workspace receipt was malformed",
            ) from exc
        expected = {
            "schema": "arnold.cloud.zero_recovery_isolated_workspace.v1",
            "status": "created",
            "parent": parent,
            "parent_realpath": parent,
            "bind_source": child,
            "bind_source_realpath": child,
            "bind_destination": "/workspace",
            "created_empty": True,
            "never_reused": True,
        }
        initial = payload.get("initial_custody") if isinstance(payload, dict) else None
        runtime_access = payload.get("runtime_access") if isinstance(payload, dict) else None
        if (
            not isinstance(payload, dict)
            or {key: payload.get(key) for key in expected} != expected
            or set(payload)
            != {*expected, "initial_custody", "runtime_access", "transition_digest"}
            or not isinstance(initial, dict)
            or set(initial) != {"mode", "uid", "gid", "st_dev", "st_ino", "empty"}
            or initial.get("mode") != "0700"
            or initial.get("uid") != 0
            or initial.get("gid") != 0
            or initial.get("empty") is not True
            or not isinstance(runtime_access, dict)
            or set(runtime_access) != {"mode", "uid", "gid", "st_dev", "st_ino"}
            or runtime_access.get("mode") != "0750"
            or runtime_access.get("uid") != 0
            or runtime_access.get("gid") != 65532
            or type(initial.get("st_dev")) is not int
            or type(initial.get("st_ino")) is not int
            or initial["st_ino"] <= 0
            or runtime_access.get("st_dev") != initial.get("st_dev")
            or runtime_access.get("st_ino") != initial.get("st_ino")
            or payload.get("transition_digest")
            != hashlib.sha256(
                json.dumps(
                    {"initial_custody": initial, "runtime_access": runtime_access},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
        ):
            raise CliError(
                "zero_recovery_workspace_unknown",
                "isolated workspace receipt did not bind the exact target",
            )
        self._zero_recovery_workspace_creation_receipt = payload
        return payload

    def _zero_recovery_target(self) -> dict[str, Any]:
        return {
            "host": self._validated_host,
            "user": self._validated_user,
            "port": self._validated_port,
            "container": self._spec.zero_recovery_predecessor_container,
            "canary_container": self._ssh.container,
            "workspace": validate_workspace_dir(self._ssh.workspace_dir),
            "canary_workspace": self._zero_recovery_isolated_workspace(),
            "container_workspace": "/workspace",
            "capacity_scopes": [
                validate_workspace_dir(self._ssh.workspace_dir),
                validate_workspace_dir(self._ssh.remote_dir),
                validate_workspace_dir(self._ssh.cache_dir),
            ],
            "capacity_floor_bytes": (
                self._spec.resources.prelaunch_min_free_bytes
                + self._spec.resources.prelaunch_receipt_reserve_bytes
            ),
        }

    def prepare_zero_recovery_predeploy_transaction(self) -> dict[str, Any]:
        if not self._spec.zero_recovery_canary:
            raise CliError(
                "zero_recovery_predeploy_invalid",
                "predeploy transactions are only available for zero-recovery canaries",
            )
        outer = self.observe_zero_recovery_predecessor()
        capacity = self.observe_zero_recovery_predecessor_capacity()
        return build_predeploy_transaction(
            outer=outer,
            capacity=capacity,
            target=self._zero_recovery_target(),
        )

    def prepare_zero_recovery_bootstrap_reclaim(self) -> dict[str, Any]:
        """Prepare a dry-run-only, expiring bootstrap containment proposal."""
        if not self._spec.zero_recovery_canary:
            raise CliError(
                "zero_recovery_bootstrap_invalid",
                "bootstrap reclaim is only available for a zero-recovery canary",
            )
        outer = self.observe_zero_recovery_predecessor()
        prelaunch = self.observe_zero_recovery_predecessor_capacity()
        inventory = self.observe_capacity_inventory()
        return build_bootstrap_reclaim_transaction(
            outer=outer,
            prelaunch=prelaunch,
            inventory=inventory,
            target=self._zero_recovery_target(),
        )

    def apply_zero_recovery_bootstrap_reclaim(
        self, proposal: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Apply the one fixed stop/fence/dangling-build-cache bootstrap."""
        if not self._spec.zero_recovery_canary:
            raise CliError(
                "zero_recovery_bootstrap_invalid",
                "bootstrap reclaim is only available for a zero-recovery canary",
            )
        # These are the final client-side checks. The fixed remote script repeats
        # identity/inventory checks before its first containment mutation.
        outer = self.observe_zero_recovery_predecessor()
        prelaunch = self.observe_zero_recovery_predecessor_capacity()
        inventory = self.observe_capacity_inventory()
        transaction = validate_bootstrap_reclaim_transaction(
            proposal,
            target=self._zero_recovery_target(),
            outer=outer,
            prelaunch=prelaunch,
            inventory=inventory,
        )
        result = self._remote_run_compatible(
            bootstrap_reclaim_command(transaction),
            surface="zero_recovery_bootstrap_fence_reclaim",
        )
        return parse_bootstrap_reclaim_receipt(
            stdout=result.stdout or "",
            transaction_id=transaction["transaction_id"],
            transaction_digest=transaction["transaction_digest"],
            proposal_inventory_digest=hashlib.sha256(
                json.dumps(
                    transaction["capacity_inventory"],
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
        )

    def seed_zero_recovery_codex_oauth(self, auth_json: str) -> None:
        """Seed only Codex OAuth through one fixed container command."""
        if not self._spec.zero_recovery_canary or self._spec.megaplan.codex_auth != "chatgpt":
            raise CliError("zero_recovery_auth_invalid", "Codex ChatGPT OAuth required")
        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate auth field")
                result[key] = value
            return result

        try:
            payload = json.loads(auth_json, object_pairs_hook=reject_duplicates)
        except (json.JSONDecodeError, ValueError) as exc:
            raise CliError("zero_recovery_auth_invalid", "Codex auth was invalid JSON") from exc
        if not isinstance(payload, dict) or payload.get("auth_mode") != "chatgpt":
            raise CliError("zero_recovery_auth_invalid", "Codex ChatGPT OAuth object required")
        self._remote_run_compatible(
            shlex.join(
                [
                    "docker",
                    "exec",
                    "-i",
                    self._ssh.container,
                    "python3",
                    "-c",
                    _ZERO_RECOVERY_OAUTH_INSTALL_SCRIPT,
                ]
            ),
            input=auth_json,
            surface="zero_recovery_codex_oauth_seed",
        )

    def _observe_zero_recovery_canary_runtime(
        self, *, expected_running: bool = True
    ) -> dict[str, Any]:
        command = _zero_recovery_canary_runtime_command(self._ssh.container)
        result = self._remote_run_compatible(
            command, surface="observe_zero_recovery_canary_runtime"
        )
        lines = (result.stdout or "").splitlines()
        try:
            (
                state, env, cmd, restart, init, mounts, cap_drop, cap_add,
                security_opt, ipc_mode, tmpfs, pids_limit, memory_limit,
                memory_swap, port_bindings,
            ) = [json.loads(line) for line in lines]
        except (ValueError, json.JSONDecodeError) as exc:
            raise CliError(
                "zero_recovery_canary_unknown", "canary runtime evidence malformed"
            ) from exc
        if (
            len(lines) != 15
            or not isinstance(state, dict)
            or state.get("Running") is not expected_running
            or not isinstance(env, list)
            or "MEGAPLAN_ZERO_RECOVERY_CANARY=1" not in env
            or cmd != ["/usr/local/bin/entrypoint.sh"]
            or restart != {"Name": "no", "MaximumRetryCount": 0}
            or init is not True
            or not isinstance(mounts, list)
            or any(not isinstance(item, dict) for item in mounts)
            or len([item for item in mounts if item.get("Type") == "bind"]) != 1
            or any(
                not isinstance(item, dict)
                or item.get("Type") not in {"bind", "tmpfs"}
                or (
                    item.get("Type") == "tmpfs"
                    and item.get("Destination") != "/run/megaplan-zero-recovery"
                )
                for item in mounts
            )
            or not isinstance(
                next((item for item in mounts if item.get("Type") == "bind"), None),
                dict,
            )
            or {
                "Type": next(item for item in mounts if item.get("Type") == "bind").get("Type"),
                "Source": next(item for item in mounts if item.get("Type") == "bind").get("Source"),
                "Destination": next(item for item in mounts if item.get("Type") == "bind").get("Destination"),
                "RW": next(item for item in mounts if item.get("Type") == "bind").get("RW"),
                "Propagation": next(item for item in mounts if item.get("Type") == "bind").get("Propagation"),
            }
            != {
                "Type": "bind",
                "Source": self._zero_recovery_isolated_workspace(),
                "Destination": "/workspace",
                "RW": True,
                "Propagation": "rprivate",
            }
            or cap_drop != ["ALL"]
            or _normalized_docker_cap_add(cap_add)
            != ["CHOWN", "DAC_READ_SEARCH", "KILL", "SETGID", "SETPCAP", "SETUID"]
            or security_opt != ["no-new-privileges:true"]
            or ipc_mode != "none"
            or tmpfs
            != {"/run/megaplan-zero-recovery": "rw,noexec,nosuid,nodev,size=256m,mode=0711"}
            or pids_limit != 256
            or memory_limit != 4_294_967_296
            or memory_swap != 4_294_967_296
            or port_bindings not in ({}, None)
        ):
            raise CliError(
                "zero_recovery_canary_unknown",
                "canary runtime flag, entrypoint, lifecycle, or restart policy mismatch",
            )
        bind_mount = next(item for item in mounts if item.get("Type") == "bind")
        normalized_mounts = [
            {
                "type": "bind", "source": bind_mount["Source"],
                "destination": bind_mount["Destination"], "rw": bind_mount["RW"],
                "propagation": bind_mount["Propagation"],
            },
            {
                "type": "tmpfs", "source": None,
                "destination": "/run/megaplan-zero-recovery", "rw": True,
                "options": "rw,noexec,nosuid,nodev,size=256m,mode=0711",
            },
        ]
        return {
            "state": state,
            "env": env,
            "cmd": cmd,
            "restart_policy": restart,
            "init": True,
            "workspace_bind": {
                "type": "bind",
                "source": bind_mount["Source"],
                "destination": bind_mount["Destination"],
                "rw": bind_mount["RW"],
                "propagation": bind_mount["Propagation"],
            },
            "host_bind_count": 1,
            "mount_inventory_sha256": hashlib.sha256(
                json.dumps(normalized_mounts, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "runtime_tmpfs": tmpfs,
            "cap_drop": cap_drop,
            "cap_add": _normalized_docker_cap_add(cap_add),
            "security_opt": security_opt,
            "ipc_mode": ipc_mode,
            "pids_limit": pids_limit,
            "memory_limit": memory_limit,
            "memory_swap": memory_swap,
            "port_bindings": {},
        }

    def run_zero_recovery_canary(
        self,
        *,
        source_commit: str,
        source_tree: str,
        manifest_sha256: Mapping[str, str],
    ) -> int:
        """Invoke only the tracked finite runner in one exact fresh checkout."""
        if not self._spec.zero_recovery_canary:
            raise CliError("zero_recovery_canary_unavailable", "zero profile required")
        self._observe_zero_recovery_canary_runtime()
        if (
            len(source_commit) != 40
            or any(character not in "0123456789abcdef" for character in source_commit)
            or len(source_tree) != 40
            or any(character not in "0123456789abcdef" for character in source_tree)
        ):
            raise CliError(
                "zero_recovery_canary_invalid",
                "zero canary repo.branch must be an exact lowercase source commit",
            )
        expected_manifest_paths = {
            ".megaplan/initiatives/critique-ledger-safe-v3-canary/canary.yaml",
            ".megaplan/initiatives/critique-ledger-safe-v3-canary/cloud.yaml",
            ".megaplan/initiatives/critique-ledger-safe-v3-canary/proof-map.json",
            ".megaplan/initiatives/critique-ledger-safe-v3-canary/traceability.json",
        }
        if (
            set(manifest_sha256) != expected_manifest_paths
            or any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in manifest_sha256.values())
        ):
            raise CliError(
                "zero_recovery_canary_invalid", "manifest hash admission is incomplete"
            )
        workspace = PurePosixPath(self._spec.repo.workspace)
        if not workspace.is_absolute() or workspace == PurePosixPath("/"):
            raise CliError("zero_recovery_canary_invalid", "invalid canary workspace")
        runner = workspace / ".megaplan/initiatives/critique-ledger-safe-v3-canary/run_canary.py"
        advertised = self._remote_run_compatible(
            shlex.join(
                [
                    "docker",
                    "exec",
                    self._ssh.container,
                    "git",
                    "ls-remote",
                    "--exit-code",
                    "--heads",
                    "--",
                    self._spec.repo.url,
                    self._spec.repo.branch,
                ]
            ),
            surface="zero_recovery_canary_branch_admission",
        )
        _require_advertised_branch_commit(
            stdout=advertised.stdout or "",
            branch=self._spec.repo.branch,
            source_commit=source_commit,
        )
        remote_branch_ref = f"refs/remotes/origin/{self._spec.repo.branch}"
        manifest_hashes_b64 = base64.b64encode(
            json.dumps(
                dict(manifest_sha256), sort_keys=True, separators=(",", ":")
            ).encode()
        ).decode("ascii")
        inner = " && ".join(
            [
                "trap 'kill -TERM 1' EXIT",
                f"test ! -e {shlex.quote(str(workspace))}",
                f"git clone --single-branch --branch {shlex.quote(self._spec.repo.branch)} --no-checkout -- {shlex.quote(self._spec.repo.url)} {shlex.quote(str(workspace))}",
                f"test \"$(git -C {shlex.quote(str(workspace))} rev-parse {shlex.quote(remote_branch_ref)})\" = {source_commit}",
                f"git -C {shlex.quote(str(workspace))} checkout --detach {source_commit}",
                f"test \"$(git -C {shlex.quote(str(workspace))} rev-parse HEAD)\" = {source_commit}",
                f"test \"$(git -C {shlex.quote(str(workspace))} rev-parse HEAD^{{tree}})\" = {source_tree}",
                f"cd {shlex.quote(str(workspace))}",
                f"MEGAPLAN_ZERO_RECOVERY_CANARY=1 ZERO_RECOVERY_SOURCE_COMMIT={source_commit} ZERO_RECOVERY_SOURCE_TREE={source_tree} ZERO_RECOVERY_MANIFEST_SHA256_B64={manifest_hashes_b64} PYTHONDONTWRITEBYTECODE=1 PYTHONPATH={shlex.quote(str(workspace))} python3 -P {shlex.quote(str(runner))}",
            ]
        )
        self._remote_run_compatible(
            shlex.join(
                [
                    "docker",
                    "exec",
                    self._ssh.container,
                    "bash",
                    "-lc",
                    inner,
                ]
            ),
            capture_output=False,
            surface="zero_recovery_finite_canary_run",
        )
        return 0

    def _zero_recovery_workspace_creation_from_runtime(
        self, runtime_observation: Mapping[str, Any]
    ) -> dict[str, Any]:
        env = runtime_observation.get("env")
        if not isinstance(env, list):
            raise CliError(
                "zero_recovery_workspace_unknown", "runtime environment was unavailable"
            )
        values: dict[str, str] = {}
        for key in (
            "ZERO_RECOVERY_WORKSPACE_DEV",
            "ZERO_RECOVERY_WORKSPACE_INO",
            "ZERO_RECOVERY_WORKSPACE_TRANSITION_DIGEST",
        ):
            matches = [item.split("=", 1)[1] for item in env if isinstance(item, str) and item.startswith(key + "=")]
            if len(matches) != 1:
                raise CliError(
                    "zero_recovery_workspace_unknown",
                    "runtime workspace identity was missing or duplicated",
                )
            values[key] = matches[0]
        try:
            st_dev = int(values["ZERO_RECOVERY_WORKSPACE_DEV"])
            st_ino = int(values["ZERO_RECOVERY_WORKSPACE_INO"])
        except ValueError as exc:
            raise CliError(
                "zero_recovery_workspace_unknown",
                "runtime workspace identity was not numeric",
            ) from exc
        if st_dev < 0 or st_ino <= 0:
            raise CliError(
                "zero_recovery_workspace_unknown",
                "runtime workspace identity was outside the admitted range",
            )
        initial = {
            "mode": "0700", "uid": 0, "gid": 0,
            "st_dev": st_dev, "st_ino": st_ino, "empty": True,
        }
        runtime_access = {
            "mode": "0750", "uid": 0, "gid": 65532,
            "st_dev": st_dev, "st_ino": st_ino,
        }
        transition_digest = hashlib.sha256(
            json.dumps(
                {"initial_custody": initial, "runtime_access": runtime_access},
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        if transition_digest != values["ZERO_RECOVERY_WORKSPACE_TRANSITION_DIGEST"]:
            raise CliError(
                "zero_recovery_workspace_unknown",
                "runtime workspace transition binding did not match",
            )
        child = self._zero_recovery_isolated_workspace()
        parent = validate_workspace_dir(self._ssh.workspace_dir)
        receipt = {
            "schema": "arnold.cloud.zero_recovery_isolated_workspace.v1",
            "status": "created",
            "parent": parent,
            "parent_realpath": parent,
            "bind_source": child,
            "bind_source_realpath": child,
            "bind_destination": "/workspace",
            "initial_custody": initial,
            "runtime_access": runtime_access,
            "transition_digest": transition_digest,
            "created_empty": True,
            "never_reused": True,
        }
        self._zero_recovery_workspace_creation_receipt = receipt
        return receipt

    def _reseal_zero_recovery_workspace(
        self, runtime_observation: Mapping[str, Any]
    ) -> dict[str, Any]:
        creation = self._zero_recovery_workspace_creation_from_runtime(
            runtime_observation
        )
        runtime_access = creation["runtime_access"]
        child = self._zero_recovery_isolated_workspace()
        result = self._remote_run_compatible(
            shlex.join(
                [
                    "python3", "-c", _ZERO_RECOVERY_WORKSPACE_RESEAL_SCRIPT,
                    child,
                    str(runtime_access["st_dev"]),
                    str(runtime_access["st_ino"]),
                    creation["transition_digest"],
                ]
            ),
            surface="zero_recovery_terminal_workspace_reseal",
        )
        lines = [line for line in (result.stdout or "").splitlines() if line.strip()]
        try:
            payload = json.loads(lines[0]) if len(lines) == 1 else None
        except json.JSONDecodeError as exc:
            raise CliError(
                "zero_recovery_workspace_unknown", "terminal workspace receipt malformed"
            ) from exc
        transition = payload.get("transition") if isinstance(payload, dict) else None
        before = transition.get("before") if isinstance(transition, dict) else None
        after = transition.get("after") if isinstance(transition, dict) else None
        if (
            not isinstance(payload, dict)
            or set(payload)
            != {"schema", "status", "path", "access_transition_digest", "transition", "transition_digest"}
            or payload.get("schema")
            != "arnold.cloud.zero_recovery_terminal_workspace.v1"
            or payload.get("status") != "sealed"
            or payload.get("path") != child
            or payload.get("access_transition_digest")
            != creation["transition_digest"]
            or not isinstance(before, dict)
            or not isinstance(after, dict)
            or before.get("st_dev") != runtime_access["st_dev"]
            or before.get("st_ino") != runtime_access["st_ino"]
            or after
            != {
                "st_dev": runtime_access["st_dev"],
                "st_ino": runtime_access["st_ino"],
                "uid": 0,
                "gid": 0,
                "mode": "0700",
            }
            or payload.get("transition_digest")
            != hashlib.sha256(
                json.dumps(transition, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        ):
            raise CliError(
                "zero_recovery_workspace_unknown",
                "terminal workspace receipt did not prove same-inode root custody",
            )
        self._zero_recovery_terminal_workspace_receipt = payload
        return payload

    def execute_zero_recovery_canary(
        self,
        auth_json: str,
        *,
        source_commit: str,
        source_tree: str,
        manifest_sha256: Mapping[str, str],
    ) -> int:
        """Terminal-safe orchestration from first credential mutation onward."""
        terminal_error: BaseException | None = None
        cleanup_errors: list[str] = []
        result = 1
        try:
            self._observe_zero_recovery_canary_runtime()
            self.seed_zero_recovery_codex_oauth(auth_json)
            result = self.run_zero_recovery_canary(
                source_commit=source_commit,
                source_tree=source_tree,
                manifest_sha256=manifest_sha256,
            )
        except BaseException as exc:
            terminal_error = exc
        finally:
            # Do not observe first: observation itself may fail.  The exact admitted
            # canary is stopped once on every path after credential mutation.
            try:
                self._remote_run_compatible(
                    shlex.join(["docker", "stop", self._ssh.container]),
                    surface="zero_recovery_finite_canary_terminal_stop",
                )
            except BaseException as exc:
                cleanup_errors.append(f"stop: {type(exc).__name__}")
            try:
                observation = self.observe_container()
                if (
                    observation.get("status") != "available"
                    or observation.get("container") != self._ssh.container
                    or observation.get("lifecycle") != "stopped"
                ):
                    cleanup_errors.append("observation did not prove exact stopped target")
                else:
                    stopped_runtime = self._observe_zero_recovery_canary_runtime(
                        expected_running=False
                    )
                    self._reseal_zero_recovery_workspace(stopped_runtime)
            except BaseException as exc:
                cleanup_errors.append(f"observation: {type(exc).__name__}")
        if cleanup_errors:
            primary = f"; primary={type(terminal_error).__name__}" if terminal_error else ""
            raise CliError(
                "zero_recovery_canary_stop_unknown",
                "terminal reconciliation failed" + primary + "; cleanup=" + ", ".join(cleanup_errors),
            ) from terminal_error
        if terminal_error is not None:
            raise terminal_error
        return result

    def _reconcile_zero_recovery_canary_stop(self) -> tuple[dict[str, Any], bool]:
        stop_error: BaseException | None = None
        try:
            self._remote_run_compatible(
                shlex.join(["docker", "stop", self._ssh.container]),
                surface="zero_recovery_finite_canary_reconcile_stop",
            )
        except BaseException as exc:
            stop_error = exc
        try:
            observation = self.observe_container()
        except BaseException as exc:
            stop_detail = f"; stop={type(stop_error).__name__}" if stop_error else ""
            raise CliError(
                "zero_recovery_canary_stop_unknown",
                f"blind stop was followed by an observation failure{stop_detail}",
            ) from exc
        if (
            observation.get("status") != "available"
            or observation.get("container") != self._ssh.container
            or observation.get("lifecycle") != "stopped"
        ):
            raise CliError(
                "zero_recovery_canary_stop_unknown",
                "status reconciliation did not prove the exact stopped canary",
            )
        stopped_runtime = self._observe_zero_recovery_canary_runtime(
            expected_running=False
        )
        self._reseal_zero_recovery_workspace(stopped_runtime)
        # An already-stopped target may make docker stop nonzero; the exact final
        # stopped observation is authoritative and safe to accept.
        return observation, True

    def zero_recovery_canary_status(
        self, *, source_commit: str, source_tree: str
    ) -> dict[str, Any]:
        """Read one fixed host-side receipt directory; never container-exec."""
        repo_workspace = PurePosixPath(self._spec.repo.workspace)
        workspace_root = PurePosixPath("/workspace")
        try:
            relative = repo_workspace.relative_to(workspace_root)
        except ValueError as exc:
            raise CliError(
                "zero_recovery_canary_invalid",
                "canary repo workspace must be below /workspace",
            ) from exc
        host_receipts = (
            PurePosixPath(self._zero_recovery_isolated_workspace())
            / relative
            / ".megaplan/initiatives/critique-ledger-safe-v3-canary/receipts"
        )
        script = (
            "import base64,hashlib,json,pathlib,sys; root=pathlib.Path(sys.argv[1]); "
            "files=sorted(root.glob('*.run-receipt.json')) if root.is_dir() else []; "
            "raw=files[0].read_bytes() if len(files)==1 else None; "
            "payload={'schema':'arnold.cloud.zero_recovery_canary_status.v1','receipt_b64':base64.b64encode(raw).decode('ascii') if raw is not None else None,'receipt_sha256':hashlib.sha256(raw).hexdigest() if raw is not None else None,'receipt_count':len(files)}; "
            "print(json.dumps(payload,sort_keys=True))"
        )
        payload: dict[str, Any] = {
            "schema": "arnold.cloud.zero_recovery_canary_status.v1",
            "status": "unknown",
            "receipt": None,
            "receipt_sha256": None,
            "receipt_count": 0,
        }
        try:
            result = self._remote_run_compatible(
                shlex.join(["python3", "-c", script, str(host_receipts)]),
                surface="zero_recovery_canary_status",
            )
            def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
                decoded: dict[str, Any] = {}
                for key, value in pairs:
                    if key in decoded:
                        raise ValueError("duplicate JSON field")
                    decoded[key] = value
                return decoded

            envelope = json.loads(
                result.stdout or "", object_pairs_hook=reject_duplicates
            )
            if (
                not isinstance(envelope, dict)
                or set(envelope)
                != {"schema", "receipt_b64", "receipt_sha256", "receipt_count"}
                or envelope.get("schema")
                != "arnold.cloud.zero_recovery_canary_status.v1"
                or type(envelope.get("receipt_count")) is not int
            ):
                raise ValueError("status envelope schema mismatch")
            payload["receipt_count"] = envelope["receipt_count"]
            if envelope["receipt_count"] == 1:
                raw = base64.b64decode(envelope["receipt_b64"], validate=True)
                digest = hashlib.sha256(raw).hexdigest()
                if digest != envelope["receipt_sha256"]:
                    raise ValueError("receipt transport digest mismatch")
                receipt = json.loads(
                    raw.decode("utf-8"), object_pairs_hook=reject_duplicates
                )
                unsigned = dict(receipt) if isinstance(receipt, dict) else {}
                receipt_digest = unsigned.pop("receipt_digest", None)
                receipt_schema = receipt.get("schema") if isinstance(receipt, dict) else None
                legacy_v2 = (
                    receipt_schema
                    == "arnold.megaplan.finite_canary_run_receipt.v2"
                )
                required_receipt_fields = {
                    "schema", "status", "canary_id", "plan_name", "phases",
                    "phase_results", "terminal_state", "product_outcome",
                    "gate_attempts", "failure", "started_at",
                    "completed_at", "source_commit", "source_tree",
                    "canary_spec_sha256", "launch_manifest_sha256", "state_sha256", "gate_sha256",
                    "dispatch_ledger_sha256", "dispatches", "import_root",
                    "dispatch_integrity", "phase_commands", "phase_receipt_sha256",
                    "phase_receipts_manifest_sha256", "repository_integrity",
                    "privilege_receipt_sha256",
                    "privilege_receipts_manifest_sha256",
                    "receipt_digest",
                }
                if legacy_v2:
                    required_receipt_fields -= {"product_outcome", "gate_attempts"}
                direct_phases = ["init", "plan", "critique", "gate", "finalize"]
                v3_allowed_phases = [
                    ["init", "plan", "critique", "gate"][:length]
                    for length in range(5)
                ] + [
                    direct_phases,
                    ["init", "plan", "critique", "gate", "revise"],
                    ["init", "plan", "critique", "gate", "revise", "critique"],
                    ["init", "plan", "critique", "gate", "revise", "critique", "gate"],
                    ["init", "plan", "critique", "gate", "revise", "critique", "gate", "finalize"],
                ]
                if (
                    not isinstance(receipt, dict)
                    or set(receipt) != required_receipt_fields
                    or receipt_schema not in {
                        "arnold.megaplan.finite_canary_run_receipt.v2",
                        "arnold.megaplan.finite_canary_run_receipt.v3",
                    }
                    or receipt.get("status") not in {"passed", "failed"}
                    or receipt.get("canary_id") != "critique-ledger-safe-v3-canary"
                    or receipt.get("plan_name")
                    != "critique-ledger-cl2-planning-canary"
                    or receipt.get("source_commit") != source_commit
                    or receipt.get("source_tree") != source_tree
                    or receipt.get("terminal_state") not in (
                        {"finalized", "failed"}
                        if legacy_v2
                        else {
                            "finalized",
                            "product_gate_not_proceed",
                            "product_revise_blocked",
                            "failed",
                        }
                    )
                    or (
                        receipt.get("status") == "failed"
                        and receipt.get("terminal_state") != "failed"
                    )
                    or (
                        receipt.get("status") == "passed"
                        and receipt.get("terminal_state") == "failed"
                    )
                    or receipt.get("dispatch_integrity")
                    not in {"not_started", "partial", "complete", "unreadable"}
                    or (
                        receipt.get("status") == "passed"
                        and receipt.get("dispatch_integrity") != "complete"
                    )
                    or not isinstance(receipt.get("phase_results"), list)
                    or len(receipt.get("phase_results")) > 8
                    or [item.get("phase") for item in receipt.get("phase_results") if isinstance(item, dict)]
                    != (
                        direct_phases[: len(receipt.get("phase_results"))]
                        if legacy_v2
                        else receipt.get("phases")
                    )
                    or (
                        legacy_v2
                        and receipt.get("phases") != direct_phases
                    )
                    or (
                        not legacy_v2
                        and receipt.get("phases") not in v3_allowed_phases
                    )
                    or (
                        not legacy_v2
                        and (
                            not isinstance(receipt.get("gate_attempts"), list)
                            or len(receipt.get("gate_attempts")) > 2
                        )
                    )
                    or (
                        not legacy_v2
                        and
                        receipt.get("terminal_state") == "finalized"
                        and (
                            not isinstance(receipt.get("product_outcome"), dict)
                            or receipt["product_outcome"].get("kind")
                            != "proceed_finalized"
                            or not receipt.get("phases")
                            or receipt["phases"][-1] != "finalize"
                            or not receipt.get("gate_attempts")
                            or receipt["gate_attempts"][-1].get("recommendation")
                            != "PROCEED"
                        )
                    )
                    or (
                        not legacy_v2
                        and
                        receipt.get("terminal_state")
                        == "product_gate_not_proceed"
                        and (
                            not isinstance(receipt.get("product_outcome"), dict)
                            or receipt["product_outcome"].get("kind")
                            != "product_gate_not_proceed"
                            or not receipt.get("phases")
                            or receipt["phases"][-1] != "gate"
                            or not receipt.get("gate_attempts")
                            or receipt["gate_attempts"][-1].get("recommendation")
                            == "PROCEED"
                        )
                    )
                    or (
                        not legacy_v2
                        and receipt.get("terminal_state")
                        == "product_revise_blocked"
                        and (
                            not isinstance(receipt.get("product_outcome"), dict)
                            or receipt["product_outcome"].get("kind")
                            != "product_revise_blocked"
                            or set(receipt["product_outcome"])
                            != {
                                "kind",
                                "reason_code",
                                "action_ids",
                                "revise_dispatch_started",
                                "gate_attempt",
                            }
                            or receipt["product_outcome"].get("reason_code")
                            not in {
                                "north_star_revise_human_halt",
                                "north_star_revise_unresolved_blocking",
                            }
                            or not isinstance(
                                receipt["product_outcome"].get("action_ids"), list
                            )
                            or not receipt["product_outcome"].get("action_ids")
                            or any(
                                not isinstance(action_id, str) or not action_id
                                for action_id in receipt["product_outcome"]["action_ids"]
                            )
                            or len(set(receipt["product_outcome"]["action_ids"]))
                            != len(receipt["product_outcome"]["action_ids"])
                            or not receipt.get("phases")
                            or receipt["phases"][-1] != "revise"
                            or not receipt.get("gate_attempts")
                            or receipt["gate_attempts"][-1].get("recommendation")
                            != "ITERATE"
                            or receipt.get("failure") is not None
                            or not receipt.get("phase_results")
                            or receipt["phase_results"][-1].get("returncode") != 1
                            or (
                                receipt["product_outcome"]["reason_code"]
                                == "north_star_revise_human_halt"
                                and (
                                    receipt["product_outcome"].get(
                                        "revise_dispatch_started"
                                    )
                                    is not False
                                    or receipt["phase_results"][-1].get(
                                        "dispatch_ordinal"
                                    )
                                    is not None
                                )
                            )
                            or (
                                receipt["product_outcome"]["reason_code"]
                                == "north_star_revise_unresolved_blocking"
                                and (
                                    receipt["product_outcome"].get(
                                        "revise_dispatch_started"
                                    )
                                    is not True
                                    or type(
                                        receipt["phase_results"][-1].get(
                                            "dispatch_ordinal"
                                        )
                                    )
                                    is not int
                                    or receipt["phase_results"][-1].get(
                                        "dispatch_ordinal"
                                    )
                                    != 4
                                )
                            )
                        )
                    )
                    or not isinstance(receipt_digest, str)
                    or hashlib.sha256(
                        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest()
                    != receipt_digest
                ):
                    raise ValueError("receipt schema, source, phases, or digest mismatch")
                payload.update(
                    status="available",
                    receipt=receipt,
                    receipt_sha256=digest,
                )
        except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            payload["validation_error"] = type(exc).__name__
        finally:
            observation = self.observe_container()
            if observation.get("lifecycle") == "running":
                # Status is an observation surface while the finite runner is
                # active.  Its execution owner performs the terminal stop and
                # workspace reseal.  A poll must never become a cancellation.
                reconciled_stop = False
                payload["status"] = "in_progress"
            else:
                observation, reconciled_stop = (
                    self._reconcile_zero_recovery_canary_stop()
                )
        payload["container_observation"] = observation
        payload["reconciled_stop"] = reconciled_stop
        payload["terminal_workspace"] = getattr(
            self, "_zero_recovery_terminal_workspace_receipt", None
        )
        payload["workspace_creation"] = getattr(
            self, "_zero_recovery_workspace_creation_receipt", None
        )
        return payload

    def _remote_run_compatible(
        self,
        command: str,
        *,
        capture_output: bool = True,
        input: str | None = None,
        surface: str,
    ) -> subprocess.CompletedProcess[str]:
        """Preserve provenance while supporting predecessor provider overrides."""
        parameters = inspect.signature(self._remote_run).parameters
        if "surface" in parameters:
            return self._remote_run(
                command,
                capture_output=capture_output,
                input=input,
                surface=surface,
            )
        return self._remote_run(
            command,
            capture_output=capture_output,
            input=input,
        )

    def _sync_deploy_dir(self, deploy_dir: Path) -> None:
        remote_dir = shlex.quote(self._ssh.remote_dir)
        if self._rsync_binary is not None:
            self._remote_run(f"mkdir -p {remote_dir}", surface="sync_prepare")
            self._run(
                [
                    self._rsync_binary,
                    "-az",
                    "-e",
                    shlex.join([*self._ssh_transport_argv(), "--"]),
                    f"{deploy_dir}/",
                    f"{self._target()}:{remote_dir}/",
                ],
                surface="sync_rsync",
            )
            return
        sys.stderr.write("WARN: rsync unavailable; falling back to scp -r\n")
        self._remote_run(
            f"rm -rf {remote_dir} && mkdir -p {remote_dir}",
            surface="sync_prepare",
        )
        self._run(
            [
                self._scp_binary or "scp",
                "-r",
                "-P",
                str(self._validated_port),
                *(
                    ["-i", self._validated_identity_file]
                    if self._validated_identity_file
                    else []
                ),
                "--",
                f"{deploy_dir}/.",
                f"{self._target()}:{remote_dir}",
            ],
            surface="sync_scp",
        )

    # ── Step 13F: WBC routing integration ─────────────────────────────────

    def _maybe_route_through_wbc(
        self,
        shard: str,
        intent_payload: dict[str, Any],
        apply_fn: Any,
    ) -> int:
        """Route an SSH mutation through the WBC adapter.

        Step 13F: build/deploy/destroy always route through the WBC protocol.
        A missing adapter is a typed denial — SSH mutations are action-off in
        M10 and must never fall back to direct transport execution.  Returns 0
        on success, raises on failure (matching existing SshProvider semantics).
        """
        adapter = self._ssh_effect_adapter
        if adapter is None:
            raise CliError(
                "ssh_effect_adapter_unavailable",
                f"SSH {shard} effect denied: no ssh_effect_adapter installed; "
                "SSH mutations are action-off",
            )

        from arnold_pipelines.megaplan.cloud.ssh_effect_adapter import (
            SshEffectShard,
            SshTarget,
        )

        target = SshTarget(
            shard=SshEffectShard(shard),
            host=self._ssh.host,
            container=self._ssh.container,
            operation=shard,
        )

        outcome = adapter.route(
            target=target,
            intent_payload=intent_payload,
            apply_fn=lambda _: apply_fn(intent_payload),
        )

        if not outcome.ok:
            raise CliError(
                "provider_failed",
                outcome.error or f"WBC gate blocked SSH {shard}",
            )
        return 0

    def _gate_action_off_transport(
        self,
        shard: str,
        transport: Callable[[], Any],
    ) -> Any:
        """Gate-only dispatch for action-off SSH operations.

        ssh_exec / upload_file / upload_archive / down are action-off in M10:
        they are not routed through the WBC protocol, but they must never run
        ungated.  A missing adapter is a typed denial; a non-AUTHORIZED gate
        verdict (or a production adapter) denies before any transport call.
        """
        adapter = self._ssh_effect_adapter
        if adapter is None:
            raise CliError(
                "ssh_effect_adapter_unavailable",
                f"SSH {shard} effect denied: no ssh_effect_adapter installed; "
                "SSH mutations are action-off",
            )

        from arnold_pipelines.megaplan.cloud.ssh_effect_adapter import (
            SshEffectShard,
            SshTarget,
        )

        target = SshTarget(
            shard=SshEffectShard(shard),
            host=self._ssh.host,
            container=self._ssh.container,
            operation=shard,
        )

        outcome = adapter.gate_dispatch(target)
        if not outcome.ok:
            raise CliError(
                "provider_failed",
                outcome.error or f"WBC gate blocked SSH {shard}",
            )
        return transport()

    def build(self, deploy_dir: Path) -> int:
        # Step 13F: every SSH mutation routes through the WBC effect adapter;
        # a missing adapter is a typed denial, never a direct-transport fallback.
        return self._maybe_route_through_wbc(
            "build",
            {"deploy_dir": str(deploy_dir), "container": self._ssh.container},
            lambda _: self._build_direct(deploy_dir),
        )

    def _build_direct(self, deploy_dir: Path) -> int:
        self._sync_deploy_dir(deploy_dir)
        self._remote_run(
            f"docker build -t {shlex.quote(self._ssh.container)} {shlex.quote(self._ssh.remote_dir)}",
            surface="build",
        )
        return 0

    def _provision_cloud_hot_env(
        self, secrets: Mapping[str, str], *, newly_started: bool
    ) -> None:
        """Install the credentials-only hot env in the running container.

        The file lives on the persistent ``/workspace`` mount and is consumed
        by session/recovery launches.  Install it after the target container
        is running so the command verifies the exact mounted destination; an
        install or verification failure raises before deploy can report ready.
        """

        try:
            payload = render_hot_env(validate_hot_env_mapping(secrets))
        except HotEnvError as exc:
            raise CliError("cloud_hot_env_rejected", str(exc)) from exc
        try:
            result = self._remote_run_secret_input(
                hot_env_install_command(container=self._ssh.container),
                secret=payload,
                surface="deploy_cloud_hot_env",
            )
            if result.returncode != 0:
                raise CliError(
                    "cloud_hot_env_verification_failed",
                    "container .cloud-hot-env installation or verification failed",
                )
        except Exception:
            if newly_started:
                try:
                    # Preserve the failed container for evidence; only stop it
                    # so no chain can observe a container with unverified hot
                    # credentials.  In particular, do not use docker rm here.
                    self._remote_run_compatible(
                        f"docker stop {shlex.quote(self._ssh.container)}",
                        surface="deploy_cloud_hot_env_fail_closed_stop",
                    )
                except Exception as stop_exc:
                    raise CliError(
                        "cloud_hot_env_fail_closed",
                        "hot-env installation failed and target container could not be stopped",
                    ) from stop_exc
            raise

    def deploy(
        self,
        deploy_dir: Path,
        *,
        secrets: dict[str, str],
        predeploy_transaction: Mapping[str, Any] | None = None,
    ) -> int:
        try:
            validate_hot_env_mapping(secrets)
        except HotEnvError as exc:
            # Reject malformed/non-credential names before reserving the WBC
            # effect or making any SSH mutation.
            raise CliError("cloud_hot_env_rejected", str(exc)) from exc
        # Step 13F: every SSH mutation routes through the WBC effect adapter;
        # a missing adapter is a typed denial, never a direct-transport fallback.
        return self._maybe_route_through_wbc(
            "deploy",
            {
                "deploy_dir": str(deploy_dir),
                "container": self._ssh.container,
                "port": self._spec.resources.port,
            },
            lambda _: self._deploy_direct(
                deploy_dir,
                secrets=secrets,
                predeploy_transaction=predeploy_transaction,
            ),
        )

    def _deploy_direct(
        self,
        deploy_dir: Path,
        *,
        secrets: dict[str, str],
        predeploy_transaction: Mapping[str, Any] | None = None,
    ) -> int:
        del deploy_dir
        transaction: dict[str, Any] | None = None
        launch_container = True
        isolated_image_id: str | None = None
        if self._spec.isolated_chain_runner and (self._spec.secrets or secrets):
            raise CliError(
                "isolated_chain_runner_secrets_denied",
                "isolated chain-runner deploy requires an empty startup secret environment",
            )
        # Validate before the first host/container mutation.  The same policy
        # is used by scripts/cloud_hot_upload.py, so selectors/model/sync
        # overrides can never enter either the Docker env file or hot env.
        try:
            validated_hot_env = validate_hot_env_mapping(secrets)
        except HotEnvError as exc:
            raise CliError("cloud_hot_env_rejected", str(exc)) from exc
        if self._spec.zero_recovery_canary:
            if predeploy_transaction is None:
                raise CliError(
                    "zero_recovery_predeploy_required",
                    "zero-recovery deploy requires a fresh predeploy transaction",
                )
            final_outer = self.observe_zero_recovery_predecessor()
            final_capacity = self.observe_zero_recovery_predecessor_capacity()
            transaction = validate_predeploy_transaction(
                predeploy_transaction,
                target=self._zero_recovery_target(),
                outer=final_outer,
                capacity=final_capacity,
            )
            transaction_id = transaction["transaction_id"]
            if transaction_id in self._consumed_zero_recovery_transactions:
                raise CliError(
                    "zero_recovery_predeploy_replayed",
                    "zero-recovery predeploy transaction was already consumed",
                )
            # Consume before the first mutation. A later ambiguous failure may
            # be reconciled, but this provider instance never redispatches it.
            self._consumed_zero_recovery_transactions.add(transaction_id)
            apply_fence = self._remote_run_compatible(
                fence_command(
                    self._ssh.workspace_dir,
                    action="apply",
                    transaction_id=transaction_id,
                    transaction_digest=transaction["transaction_digest"],
                ),
                surface="zero_recovery_fence_apply",
            )
            parse_fence_receipt(
                stdout=apply_fence.stdout or "",
                transaction_id=transaction_id,
                transaction_digest=transaction["transaction_digest"],
                stage="apply",
            )
            canary_observation = self.observe_container()
            if canary_observation.get("lifecycle") == "missing":
                launch_container = True
            elif (
                canary_observation.get("status") == "available"
                and canary_observation.get("lifecycle") == "running"
                and canary_observation.get("image_ref") == self._ssh.container
                and canary_observation.get("workspace_bind")
                == {
                    "status": "present",
                    "type": "bind",
                    "source": self._zero_recovery_isolated_workspace(),
                    "destination": "/workspace",
                    "rw": True,
                }
            ):
                self._observe_zero_recovery_canary_runtime()
                launch_container = False
            else:
                raise CliError(
                    "zero_recovery_canary_collision",
                    "canary target name exists with an unknown or mismatched identity",
                )
        if self._spec.isolated_chain_runner:
            isolated_image_id = self._resolve_isolated_chain_runner_image_id()
            existing = self.observe_container()
            if existing.get("lifecycle") == "missing":
                launch_container = True
            elif (
                existing.get("status") == "available"
                and existing.get("lifecycle") == "running"
            ):
                self.attest_isolated_chain_runner_runtime()
                launch_container = False
            elif (
                existing.get("status") == "available"
                and existing.get("lifecycle") == "stopped"
            ):
                # Recover an exact exited container in place.  The stopped
                # runtime attestation proves the pinned image/config and the
                # persistent workspace bind before Docker is allowed to start
                # it; using the immutable ID avoids a name-reuse race.
                stopped_observation = self._attest_isolated_chain_runner_stopped_runtime(
                    expected_image_id=isolated_image_id,
                )
                stopped_container_id = stopped_observation["container_id"]
                self._remote_run_compatible(
                    f"docker start {shlex.quote(stopped_container_id)}",
                    surface="deploy_recover_stopped",
                )
                self.attest_isolated_chain_runner_runtime()
                launch_container = False
            else:
                raise CliError(
                    "isolated_chain_runner_collision",
                    "isolated chain-runner target exists without an exact running attestation",
                )
        env_path = f"{self._ssh.remote_dir}/.env"
        env_lines = [f"PORT={self._spec.resources.port}"]
        if self._spec.zero_recovery_canary:
            env_lines.append("MEGAPLAN_ZERO_RECOVERY_CANARY=1")
        env_lines.extend(f"{name}={value}" for name, value in secrets.items())
        workspace_receipt: dict[str, Any] | None = None
        if launch_container:
            if self._spec.zero_recovery_canary:
                self._remote_run_compatible(
                    f"mkdir -p {shlex.quote(self._ssh.remote_dir)}",
                    surface="deploy_prepare",
                )
                workspace_receipt = self._prepare_zero_recovery_isolated_workspace()
                runtime_access = workspace_receipt["runtime_access"]
                env_lines.extend(
                    [
                        f"ZERO_RECOVERY_WORKSPACE_DEV={runtime_access['st_dev']}",
                        f"ZERO_RECOVERY_WORKSPACE_INO={runtime_access['st_ino']}",
                        "ZERO_RECOVERY_WORKSPACE_TRANSITION_DIGEST="
                        f"{workspace_receipt['transition_digest']}",
                    ]
                )
            else:
                self._remote_run_compatible(
                    "mkdir -p "
                    f"{shlex.quote(self._ssh.remote_dir)} "
                    f"{shlex.quote(self._ssh.workspace_dir)} "
                    f"{shlex.quote(f'{self._ssh.cache_dir}/pip')} "
                    f"{shlex.quote(f'{self._ssh.cache_dir}/npm')}",
                    surface="deploy_prepare",
                )
            if not self._spec.isolated_chain_runner:
                self._remote_run_compatible(
                    f"cat > {shlex.quote(env_path)}",
                    input="\n".join(env_lines) + "\n",
                    surface="deploy_env",
                )
        if not self._spec.zero_recovery_canary and (
            not self._spec.isolated_chain_runner
        ):
            self._remote_run_compatible(
                f"docker rm -f {shlex.quote(self._ssh.container)} >/dev/null 2>&1 || true",
                surface="deploy_remove_existing",
            )
        if launch_container:
            workspace_mount = (
                self._zero_recovery_isolated_workspace()
                if self._spec.zero_recovery_canary
                else self._ssh.workspace_dir
            )
            cache_mounts = (
                []
                if self._spec.zero_recovery_canary
                else [
                    f"-v {shlex.quote(f'{self._ssh.cache_dir}/pip')}:/root/.cache/pip",
                    f"-v {shlex.quote(f'{self._ssh.cache_dir}/npm')}:/root/.npm",
                ]
            )
            self._remote_run_compatible(
                " ".join(
                [
                    "docker run -d",
                    f"--name {shlex.quote(self._ssh.container)}",
                    "--restart no"
                    if self._spec.zero_recovery_canary
                    else "--restart unless-stopped",
                    *(["--init"] if self._spec.zero_recovery_canary else []),
                    *(
                        ["-e MEGAPLAN_ZERO_RECOVERY_CANARY=1"]
                        if self._spec.zero_recovery_canary
                        else []
                    ),
                    *(
                        [
                            f"-e PORT={self._spec.resources.port}",
                            "-e MEGAPLAN_ISOLATED_CHAIN_RUNNER=1",
                        ]
                        if self._spec.isolated_chain_runner
                        else []
                    ),
                    *(
                        [
                            "--entrypoint",
                            shlex.quote(_ISOLATED_CHAIN_RUNNER_ENTRYPOINT),
                            "--no-healthcheck",
                            "--init",
                            "--cap-drop ALL",
                            *(
                                f"--cap-add {capability}"
                                for capability in _ISOLATED_CHAIN_RUNNER_CAP_ADD
                            ),
                            "--security-opt no-new-privileges:true",
                            "--network bridge",
                            "--ipc private",
                            f"--pids-limit {_ISOLATED_CHAIN_RUNNER_PIDS_LIMIT}",
                            "--memory 8g",
                            "--memory-swap 8g",
                        ]
                        if self._spec.isolated_chain_runner
                        else []
                    ),
                    *(
                        [
                            "--cap-drop ALL",
                            "--cap-add CHOWN",
                            "--cap-add DAC_READ_SEARCH",
                            "--cap-add KILL",
                            "--cap-add SETGID",
                            "--cap-add SETPCAP",
                            "--cap-add SETUID",
                            "--security-opt no-new-privileges:true",
                            "--ipc none",
                            "--pids-limit 256",
                            "--memory 4g",
                            "--memory-swap 4g",
                            "--tmpfs /run/megaplan-zero-recovery:rw,noexec,nosuid,nodev,size=256m,mode=0711",
                        ]
                        if self._spec.zero_recovery_canary
                        else []
                    ),
                    *(
                        []
                        if self._spec.isolated_chain_runner
                        else [f"--env-file {shlex.quote(env_path)}"]
                    ),
                    *(
                        []
                        if self._spec.zero_recovery_canary
                        else [f"-p {self._spec.resources.port}:{self._spec.resources.port}"]
                    ),
                    f"-v {shlex.quote(workspace_mount)}:/workspace",
                    *cache_mounts,
                    shlex.quote(isolated_image_id or self._ssh.container),
                    *(
                        [shlex.quote(item) for item in _ISOLATED_CHAIN_RUNNER_COMMAND]
                        if self._spec.isolated_chain_runner
                        else []
                    ),
                ]
                ),
                surface="deploy_run",
            )
            if self._spec.zero_recovery_canary:
                self._observe_zero_recovery_canary_runtime()
            if self._spec.isolated_chain_runner:
                if isolated_image_id is None:  # pragma: no cover - defensive invariant
                    raise CliError(
                        "isolated_chain_runner_image_unknown",
                        "isolated chain-runner image identity was not resolved",
                    )
                self.attest_isolated_chain_runner_runtime()
        if not self._spec.zero_recovery_canary and not self._spec.isolated_chain_runner:
            self._provision_cloud_hot_env(
                validated_hot_env,
                newly_started=launch_container,
            )
        if transaction is not None:
            verify_fence = self._remote_run_compatible(
                fence_command(
                    self._ssh.workspace_dir,
                    action="verify",
                    transaction_id=transaction["transaction_id"],
                    transaction_digest=transaction["transaction_digest"],
                ),
                surface="zero_recovery_fence_verify",
            )
            parse_fence_receipt(
                stdout=verify_fence.stdout or "",
                transaction_id=transaction["transaction_id"],
                transaction_digest=transaction["transaction_digest"],
                stage="verify",
            )
        return 0

    def _container_io_target(self) -> str:
        if not self._spec.isolated_chain_runner:
            return self._ssh.container
        container_id = getattr(self, "_isolated_chain_runner_container_id", None)
        if not isinstance(container_id, str) or not re.fullmatch(
            r"[0-9a-f]{64}", container_id
        ):
            raise CliError(
                "isolated_chain_runner_attestation_required",
                "isolated container I/O requires a fresh exact runtime attestation",
            )
        return container_id

    def ssh_exec(self, command: str) -> subprocess.CompletedProcess[str]:
        # Step 13F: ssh_exec is action-off — every dispatch routes through the
        # adapter gate; a missing adapter or non-AUTHORIZED verdict is a typed
        # denial with zero transport calls.
        target = self._container_io_target()
        return self._gate_action_off_transport(
            "ssh_exec",
            lambda: self._remote_run(
                f"docker exec {shlex.quote(target)} bash -lc {shlex.quote(command)}",
                surface="ssh_exec",
            ),
        )

    def invoke_launch_engine(self, request: dict[str, Any]) -> dict[str, Any]:
        """Invoke the engine inside the attested remote container.

        The controller never opens the remote operation store.  The command
        runs in the container that owns ``AgentBoxConfig.ops_store_root`` and
        returns the engine's typed response unchanged; transport loss is
        surfaced as ``UNKNOWN`` without a retry.
        """
        from arnold_pipelines.megaplan.cloud.chain_drive import (
            encode_launch_request,
            launch_engine_command,
        )

        try:
            result = self.ssh_exec(launch_engine_command(encode_launch_request(request)))
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
        # Step 13F: upload_file is action-off — gate before any transport or
        # local file IO.
        target = self._container_io_target()
        parent = Path(dest).parent.as_posix()
        inner = f"mkdir -p {shlex.quote(parent)} && base64 -d > {shlex.quote(dest)}"

        def _transport() -> None:
            payload = base64.b64encode(src.read_bytes()).decode("ascii")
            self._remote_run(
                f"docker exec -i {shlex.quote(target)} bash -lc {shlex.quote(inner)}",
                input=payload,
                surface="upload_file",
            )

        self._gate_action_off_transport("upload_file", _transport)

    def upload_archive(self, src: Path, dest_dir: str) -> None:
        # Step 13F: upload_archive is action-off — gate before any transport
        # or local file IO.
        target = self._container_io_target()
        inner = f"mkdir -p {shlex.quote(dest_dir)} && base64 -d | tar -xzf - -C {shlex.quote(dest_dir)}"

        def _transport() -> None:
            payload = base64.b64encode(src.read_bytes()).decode("ascii")
            self._remote_run(
                f"docker exec -i {shlex.quote(target)} bash -lc {shlex.quote(inner)}",
                input=payload,
                surface="upload_archive",
            )

        self._gate_action_off_transport("upload_archive", _transport)

    def read_remote_file(self, path: str) -> str:
        # Observation-only transport (Step 13F): `cat` of a remote file is a
        # read-only inspection and is intentionally ungated — it must keep
        # working without an effect adapter, exactly like the status read.
        # It never mutates the remote.
        target = self._container_io_target()
        result = self._remote_run(
            f"docker exec {shlex.quote(target)} bash -lc {shlex.quote(f'cat {shlex.quote(path)}')}",
            surface="read_remote_file",
        )
        return result.stdout

    def attach(self) -> int:
        # Interactive transport (Step 13F): attach opens a raw PTY stream to
        # the live tmux session — NOT observation-only and NOT a programmatic
        # mutation API.  The attach command itself is non-mutating (a tmux
        # client attach); all subsequent input is human-driven at an
        # interactive TTY, so it is intentionally ungated like the
        # observation transports.
        target = self._container_io_target()
        self._remote_run(
            f"docker exec -it {shlex.quote(target)} tmux attach -t agent",
            capture_output=False,
            surface="attach",
        )
        return 0

    def logs(self, *, follow: bool = True) -> int:
        # Observation-only transport (Step 13F): `docker logs` is a read-only
        # stream and is intentionally ungated — it must keep working without
        # an effect adapter.  It never mutates the remote.
        target = self._container_io_target()
        argv = f"docker logs {'-f ' if follow else '--tail 200 '}{shlex.quote(target)}"
        if follow:
            return _logs_follow(
                [*self._ssh_destination_argv(), argv.strip()],
                secret_names=self._spec.secrets,
                env=os.environ,
            )
        result = self._remote_run(argv.strip(), surface="logs")
        _write_redacted_output(result, secret_names=self._spec.secrets, env=os.environ)
        return 0

    def status_payload(
        self,
        *,
        plan: str | None,
        workspace: str,
        session: str | None = None,
    ) -> dict:
        runtime_root = self._spec.megaplan.src_path
        runtime_revision: str | None = None
        runtime_source = "configured_megaplan_source"
        if session:
            marker_path = str(
                PurePosixPath(_CLOUD_SESSION_MARKER_DIR) / f"{session}.json"
            )
            try:
                marker = json.loads(self.read_remote_file(marker_path))
            except (CliError, OSError, json.JSONDecodeError) as exc:
                raise CliError(
                    "status_runtime_binding_unavailable",
                    "cannot read the selected session runtime binding",
                ) from exc
            if not isinstance(marker, Mapping):
                raise CliError(
                    "status_runtime_binding_invalid",
                    "session marker must be a JSON object",
                )
            selected = _status_runtime_binding_from_marker(marker)
            if selected is None:
                raise CliError(
                    "status_runtime_binding_unavailable",
                    "session marker does not identify its selected runtime",
                )
            runtime_root, runtime_revision, runtime_source = selected

        command = _megaplan_status_module_command(
            workspace=workspace,
            plan=plan,
            runtime_root=runtime_root,
            runtime_revision=runtime_revision,
            session=session,
        )
        # Observation-only path: status reads must keep working without an
        # effect adapter, so they use the ungated observation transport
        # instead of the action-off ssh_exec gate (Step 13F).
        target = self._container_io_target()
        result = self._remote_run(
            f"docker exec {shlex.quote(target)} bash -lc {shlex.quote(command)}",
            surface="status_observation",
        )
        payload = json.loads(result.stdout)
        if not isinstance(payload, dict):
            raise CliError("provider_failed", "Megaplan status did not return a JSON object")
        payload["status_runtime"] = {
            "route": "python -P -m arnold_pipelines.megaplan status",
            "root": runtime_root,
            "revision": runtime_revision or "attested_at_read",
            "source": runtime_source,
        }
        return payload

    def down(self) -> int:
        # Step 13F: down is action-off — gate before any transport.
        self._gate_action_off_transport(
            "down",
            lambda: self._remote_run(
                f"docker stop {shlex.quote(self._ssh.container)}", surface="down"
            ),
        )
        return 0

    def destroy(self, *, volume: str | None = None) -> int:
        # Step 13F: every SSH mutation routes through the WBC effect adapter;
        # a missing adapter is a typed denial, never a direct-transport fallback.
        return self._maybe_route_through_wbc(
            "destroy",
            {"container": self._ssh.container, "remote_dir": self._ssh.remote_dir},
            lambda _: self._destroy_direct(volume=volume),
        )

    def _destroy_direct(self, *, volume: str | None = None) -> int:
        del volume
        self._remote_run(
            f"docker rm -f {shlex.quote(self._ssh.container)} >/dev/null 2>&1 || true && rm -rf {shlex.quote(self._ssh.remote_dir)}",
            surface="destroy",
        )
        return 0
