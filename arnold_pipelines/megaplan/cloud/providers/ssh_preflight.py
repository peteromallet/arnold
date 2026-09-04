"""Fixed, read-only host observations used before SSH cloud launch.

The public builders accept only the configured container/workspace and numeric
reserve floors.  They intentionally do not expose an arbitrary host command.
"""

from __future__ import annotations

import json
import posixpath
import re
import shlex
from pathlib import PurePosixPath
from typing import Any, Mapping

from arnold_pipelines.megaplan.types import CliError


_CONTAINER_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_CONTAINER_OBSERVATION_SCHEMA = "arnold.cloud.ssh_container_observation.v1"
_WORKSPACE_PRELAUNCH_SCHEMA = "arnold.cloud.ssh_workspace_prelaunch.v2"
_CAPACITY_INVENTORY_SCHEMA = "arnold.cloud.ssh_capacity_inventory.v1"
_REQUIRED_CAPACITY_CHECKS = {
    "byte_floor",
    "inode_floor",
    "workspace_identity",
    "temp_volume",
    "output_bound",
}
_CAPACITY_TOP_LEVEL_FIELDS = {
    "schema",
    "workspace",
    "thresholds",
    "checks",
    "errors",
    "mount",
    "temp_mount",
    "capacity",
    "status",
    "verdict",
}


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = item
    return result


def _strict_json_value(value: str) -> Any:
    return json.loads(value, object_pairs_hook=_reject_duplicate_keys)


def validate_container_name(value: str) -> str:
    if not isinstance(value, str) or not _CONTAINER_NAME_RE.fullmatch(value):
        raise CliError(
            "invalid_provider_observation_target",
            "configured SSH container name is not a safe Docker identifier",
        )
    return value


def validate_workspace_dir(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or "\n" in value
        or "\r" in value
    ):
        raise CliError(
            "invalid_provider_observation_target",
            "configured SSH workspace directory is not a safe absolute path",
        )
    path = PurePosixPath(value)
    normalized = posixpath.normpath(value)
    if (
        not path.is_absolute()
        or normalized != value
        or value == "/"
        or ".." in path.parts
    ):
        raise CliError(
            "invalid_provider_observation_target",
            "configured SSH workspace directory must be normalized, absolute, and non-root",
        )
    return value


def container_inspect_command(container: str) -> str:
    name = validate_container_name(container)
    return shlex.join(
        [
            "docker",
            "inspect",
            "--type",
            "container",
            "--format",
            "{{json .State}}\n{{json .RestartCount}}\n{{json .Id}}\n{{json .Image}}\n{{json .Config.Image}}\n{{json .Mounts}}",
            name,
        ]
    )


def classify_container_inspect(
    *,
    returncode: int,
    stdout: str,
    stderr: str,
    expected_container: str,
) -> dict[str, Any]:
    """Classify fixed ``docker inspect`` output without guessing transport errors."""
    name = validate_container_name(expected_container)
    diagnostic_parts = [part for part in (stderr.strip(), stdout.strip()) if part]
    diagnostic = "\n".join(diagnostic_parts)
    if returncode != 0:
        # OpenSSH reserves 255 for transport/setup failures.  Never promote text
        # from that channel (including a hostile banner) into remote Docker truth.
        missing_pattern = re.compile(
            rf"(?:Error response from daemon: )?(?:Error: )?"
            rf"No such (?:container|object): {re.escape(name)}\.?",
            re.IGNORECASE,
        )
        lifecycle = "unknown"
        if (
            returncode == 1
            and len(diagnostic_parts) == 1
            and missing_pattern.fullmatch(diagnostic_parts[0])
        ):
            lifecycle = "missing"
        return {
            "schema": _CONTAINER_OBSERVATION_SCHEMA,
            "status": "available" if lifecycle == "missing" else "unknown",
            "lifecycle": lifecycle,
            "container": name,
            "returncode": returncode,
            "diagnostic": diagnostic,
            "collector": {
                "status": "unavailable",
                "reason": "container_missing"
                if lifecycle == "missing"
                else "container_state_unknown",
            },
        }

    try:
        lines = stdout.splitlines()
        if len(lines) != 6:
            raise ValueError("expected six docker inspect fields")
        state, restart_count, container_id, image_id, image_ref, mounts = (
            _strict_json_value(line) for line in lines
        )
        payload = {
            "State": state,
            "RestartCount": restart_count,
            "Id": container_id,
            "Image": image_id,
            "Config": {"Image": image_ref},
            "Mounts": mounts,
        }
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "schema": _CONTAINER_OBSERVATION_SCHEMA,
            "status": "unknown",
            "lifecycle": "unknown",
            "container": name,
            "returncode": returncode,
            "diagnostic": f"docker inspect output was not JSON: {exc}",
            "collector": {"status": "unavailable", "reason": "container_state_unknown"},
        }
    if not isinstance(payload, Mapping):
        return {
            "schema": _CONTAINER_OBSERVATION_SCHEMA,
            "status": "unknown",
            "lifecycle": "unknown",
            "container": name,
            "returncode": returncode,
            "diagnostic": "docker inspect output was not an object",
            "collector": {"status": "unavailable", "reason": "container_state_unknown"},
        }

    state = payload.get("State")
    container_id = payload.get("Id")
    image_id = payload.get("Image")
    config = payload.get("Config")
    image_ref = config.get("Image") if isinstance(config, Mapping) else None
    mounts = payload.get("Mounts")
    required_state_types = (
        isinstance(state, Mapping)
        and isinstance(state.get("Status"), str)
        and bool(state.get("Status"))
        and type(state.get("Running")) is bool
        and type(state.get("Paused")) is bool
        and type(state.get("Restarting")) is bool
        and type(state.get("OOMKilled")) is bool
        and type(state.get("ExitCode")) is int
        and state.get("ExitCode") >= 0
        and isinstance(state.get("Error"), str)
        and isinstance(state.get("StartedAt"), str)
        and bool(state.get("StartedAt"))
        and isinstance(state.get("FinishedAt"), str)
        and bool(state.get("FinishedAt"))
        and type(payload.get("RestartCount")) is int
        and payload.get("RestartCount") >= 0
    )
    identity_types = (
        isinstance(container_id, str)
        and bool(container_id.strip())
        and isinstance(image_id, str)
        and bool(image_id.strip())
        and isinstance(image_ref, str)
        and bool(image_ref.strip())
        and isinstance(mounts, list)
    )
    mounts_typed = identity_types and all(
        isinstance(item, Mapping)
        and isinstance(item.get("Type"), str)
        and bool(item.get("Type").strip())
        and isinstance(item.get("Source"), str)
        and bool(item.get("Source").strip())
        and isinstance(item.get("Destination"), str)
        and bool(item.get("Destination").strip())
        and type(item.get("RW")) is bool
        for item in mounts
    )
    if not required_state_types or not identity_types or not mounts_typed:
        return {
            "schema": _CONTAINER_OBSERVATION_SCHEMA,
            "status": "unknown",
            "lifecycle": "unknown",
            "container": name,
            "returncode": returncode,
            "diagnostic": "docker inspect output failed strict schema validation",
            "collector": {"status": "unavailable", "reason": "container_state_unknown"},
        }

    raw_status = state["Status"]
    running = state["Running"]
    paused = state["Paused"]
    restarting = state["Restarting"]
    if raw_status == "paused" and running and paused and not restarting:
        lifecycle = "paused"
    elif raw_status == "restarting" and running and restarting and not paused:
        lifecycle = "restarting"
    elif raw_status == "running" and running and not paused and not restarting:
        lifecycle = "running"
    elif (
        raw_status in {"created", "exited", "dead", "removing"}
        and not running
        and not paused
        and not restarting
    ):
        lifecycle = "stopped"
    else:
        lifecycle = "unknown"

    workspace_mounts = [
        item
        for item in mounts
        if isinstance(item, Mapping) and item.get("Destination") == "/workspace"
    ]
    if len(workspace_mounts) == 1:
        mount = workspace_mounts[0]
        workspace_bind = {
            "status": "present",
            "type": mount.get("Type"),
            "source": mount.get("Source"),
            "destination": "/workspace",
            "rw": mount.get("RW"),
        }
    else:
        workspace_bind = {
            "status": "missing" if not workspace_mounts else "invalid",
            "count": len(workspace_mounts),
            "destination": "/workspace",
        }

    observation = {
        "schema": _CONTAINER_OBSERVATION_SCHEMA,
        "status": "available" if lifecycle != "unknown" else "unknown",
        "lifecycle": lifecycle,
        "container_state": raw_status,
        "container": name,
        "container_id": container_id,
        "returncode": returncode,
        "exit_code": state.get("ExitCode"),
        "oom_killed": state.get("OOMKilled"),
        "error": state.get("Error"),
        "started_at": state.get("StartedAt"),
        "finished_at": state.get("FinishedAt"),
        "restart_count": payload.get("RestartCount"),
        "image_id": image_id,
        "image_ref": image_ref,
        "workspace_bind": workspace_bind,
        "collector": {
            "status": "available" if lifecycle == "running" else "unavailable",
            "reason": None if lifecycle == "running" else f"container_{lifecycle}",
        },
    }
    return observation


_CAPACITY_PROBE_SCRIPT = r"""
import json
import os
import stat
import sys

workspace = sys.argv[1]
min_free_bytes = int(sys.argv[2])
min_free_inodes = int(sys.argv[3])
output_bound_bytes = int(sys.argv[4])
temp_volume = sys.argv[5]
result = {
    "schema": "arnold.cloud.ssh_workspace_prelaunch.v2",
    "workspace": workspace,
    "thresholds": {
        "min_free_bytes": min_free_bytes,
        "min_free_inodes": min_free_inodes,
        "receipt_reserve_bytes": output_bound_bytes,
    },
    "checks": {},
    "errors": [],
}

def identity(path):
    item = os.lstat(path)
    return {
        "st_dev": item.st_dev,
        "device_major": os.major(item.st_dev),
        "device_minor": os.minor(item.st_dev),
        "inode": item.st_ino,
    }

try:
    workspace_stat = os.lstat(workspace)
    temp_stat = os.stat(temp_volume)
    if (
        not stat.S_ISDIR(workspace_stat.st_mode)
        or stat.S_ISLNK(workspace_stat.st_mode)
        or not stat.S_ISDIR(temp_stat.st_mode)
    ):
        raise RuntimeError("configured capacity path is not a real directory")
    workspace_vfs = os.statvfs(workspace)
    temp_vfs = os.statvfs(temp_volume)
    free_bytes = workspace_vfs.f_bavail * workspace_vfs.f_frsize
    free_inodes = workspace_vfs.f_favail
    temp_free_bytes = temp_vfs.f_bavail * temp_vfs.f_frsize
    temp_free_inodes = temp_vfs.f_favail
    result["mount"] = identity(workspace_stat and workspace)
    result["temp_mount"] = identity(temp_volume)
    result["capacity"] = {
        "free_bytes": free_bytes,
        "free_inodes": free_inodes,
        "temp_free_bytes": temp_free_bytes,
        "temp_free_inodes": temp_free_inodes,
    }
    result["checks"]["byte_floor"] = free_bytes >= min_free_bytes + output_bound_bytes
    result["checks"]["inode_floor"] = free_inodes >= min_free_inodes
    result["checks"]["workspace_identity"] = True
    result["checks"]["temp_volume"] = temp_free_bytes >= output_bound_bytes and temp_free_inodes > 0
    result["checks"]["output_bound"] = free_bytes >= output_bound_bytes
    if not result["checks"]["byte_floor"]:
        result["errors"].append("prelaunch_free_bytes_below_reserve")
    if not result["checks"]["inode_floor"]:
        result["errors"].append("prelaunch_free_inodes_below_reserve")
    if not result["checks"]["temp_volume"]:
        result["errors"].append("prelaunch_temp_volume_below_reserve")
except (OSError, RuntimeError, ValueError) as exc:
    result["errors"].append(str(exc) or type(exc).__name__)

required_checks = ("byte_floor", "inode_floor", "workspace_identity", "temp_volume", "output_bound")
result["status"] = "go" if not result["errors"] and all(result["checks"].get(key) is True for key in required_checks) else "no-go"
result["verdict"] = "GO" if result["status"] == "go" else "NO-GO"
print(json.dumps(result, sort_keys=True))
raise SystemExit(0 if result["status"] == "go" else 3)
""".strip()


def workspace_prelaunch_command(
    workspace_dir: str,
    *,
    min_free_bytes: int,
    min_free_inodes: int,
    receipt_reserve_bytes: int,
    temp_volume: str = "/tmp",
) -> str:
    workspace = validate_workspace_dir(workspace_dir)
    values = (min_free_bytes, min_free_inodes, receipt_reserve_bytes)
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in values
    ):
        raise CliError(
            "invalid_provider_observation_target",
            "prelaunch capacity thresholds must be non-negative integers",
        )
    return shlex.join(
        [
            "python3",
            "-c",
            _CAPACITY_PROBE_SCRIPT,
            workspace,
            str(min_free_bytes),
            str(min_free_inodes),
            str(receipt_reserve_bytes),
            validate_workspace_dir(temp_volume),
        ]
    )


_CAPACITY_INVENTORY_SCRIPT = r"""
import json
import os
import stat
import subprocess
import sys

workspace = sys.argv[1]
scopes = sys.argv[1:4]
result = {
    "schema": "arnold.cloud.ssh_capacity_inventory.v1",
    "workspace": workspace,
    "filesystem": {},
    "mount": {},
    "scopes": [],
    "docker_disk_usage": [],
    "errors": [],
}
try:
    values = os.statvfs(workspace)
    workspace_stat = os.stat(workspace, follow_symlinks=False)
    result["filesystem"] = {
        "free_bytes": values.f_bavail * values.f_frsize,
        "free_inodes": values.f_favail,
        "block_size": values.f_frsize,
    }
    result["mount"] = {
        "st_dev": workspace_stat.st_dev,
        "device_major": os.major(workspace_stat.st_dev),
        "device_minor": os.minor(workspace_stat.st_dev),
        "inode": workspace_stat.st_ino,
    }
    best = None
    with open("/proc/self/mountinfo", "r", encoding="utf-8") as handle:
        for line in handle:
            fields = line.rstrip("\n").split()
            if "-" not in fields or len(fields) < 10:
                continue
            dash = fields.index("-")
            mount_point = fields[4].replace("\\040", " ")
            if workspace == mount_point or workspace.startswith(mount_point.rstrip("/") + "/"):
                if best is None or len(mount_point) > len(best[0]):
                    best = (mount_point, fields[dash + 1], fields[dash + 2])
    if best is None:
        raise RuntimeError("workspace_mount_identity_unknown")
    result["mount"].update({"mount_point": best[0], "filesystem": best[1], "mount_source": best[2]})
except OSError as exc:
    result["errors"].append("workspace_statvfs_failed:" + str(exc))

for path in scopes:
    item = {"path": path}
    try:
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeError("scope_is_symlink")
        if not stat.S_ISDIR(info.st_mode):
            raise RuntimeError("scope_is_not_directory")
        usage = subprocess.run(
            ["du", "-sb", "--one-file-system", "--", path],
            text=True, capture_output=True, check=False,
        )
        fields = usage.stdout.split()
        if (
            usage.returncode != 0
            or len(fields) != 2
            or not fields[0].isdigit()
            or fields[1] != path
        ):
            raise RuntimeError("scope_du_unknown")
        item.update({"status": "available", "size_bytes": int(fields[0])})
    except FileNotFoundError:
        item.update({"status": "absent", "size_bytes": 0})
    except Exception as exc:
        item.update({"status": "unknown", "size_bytes": None})
        result["errors"].append(path + ":" + str(exc))
    result["scopes"].append(item)

docker = subprocess.run(
    ["docker", "system", "df", "--format", "{{json .}}"],
    text=True, capture_output=True, check=False,
)
if docker.returncode != 0:
    result["errors"].append("docker_disk_usage_unknown:" + docker.stderr.strip())
else:
    try:
        for line in docker.stdout.splitlines():
            if line.strip():
                row = json.loads(line)
                if (
                    not isinstance(row, dict)
                    or set(row) != {"Type", "TotalCount", "Active", "Size", "Reclaimable"}
                    or row.get("Type") not in {"Images", "Containers", "Local Volumes", "Build Cache"}
                    or any(not isinstance(value, str) or not value for value in row.values())
                ):
                    raise RuntimeError("docker_disk_usage_row_malformed")
                result["docker_disk_usage"].append(row)
    except Exception as exc:
        result["errors"].append("docker_disk_usage_malformed:" + str(exc))

observed_types = [row.get("Type") for row in result["docker_disk_usage"]]
if observed_types != ["Images", "Containers", "Local Volumes", "Build Cache"]:
    result["errors"].append("docker_disk_usage_rows_inexact")
result["status"] = "available" if not result["errors"] else "unknown"
print(json.dumps(result, sort_keys=True))
raise SystemExit(0 if result["status"] == "available" else 3)
""".strip()


def capacity_inventory_command(
    *, workspace_dir: str, remote_dir: str, cache_dir: str
) -> str:
    paths = [
        validate_workspace_dir(workspace_dir),
        validate_workspace_dir(remote_dir),
        validate_workspace_dir(cache_dir),
    ]
    base = PurePosixPath("/opt/megaplan-cloud")
    if any(base not in (PurePosixPath(path), *PurePosixPath(path).parents) for path in paths):
        raise CliError(
            "invalid_provider_observation_target",
            "capacity inventory is restricted to exact /opt/megaplan-cloud scopes",
        )
    return shlex.join(["python3", "-c", _CAPACITY_INVENTORY_SCRIPT, *paths])


def parse_capacity_inventory_result(
    *, returncode: int, stdout: str, stderr: str, expected_paths: list[str]
) -> dict[str, Any]:
    lines = [line for line in stdout.splitlines() if line.strip()]
    try:
        payload = _strict_json_object(lines[0]) if len(lines) == 1 else None
    except (TypeError, ValueError, json.JSONDecodeError):
        payload = None
    required = {
        "schema",
        "workspace",
        "filesystem",
        "mount",
        "scopes",
        "docker_disk_usage",
        "errors",
        "status",
    }
    scopes = payload.get("scopes") if isinstance(payload, dict) else None
    filesystem = payload.get("filesystem") if isinstance(payload, dict) else None
    valid = (
        isinstance(payload, dict)
        and set(payload) == required
        and payload.get("schema") == _CAPACITY_INVENTORY_SCHEMA
        and payload.get("workspace") == expected_paths[0]
        and payload.get("status") == "available"
        and payload.get("errors") == []
        and returncode == 0
        and not stderr.strip()
        and isinstance(filesystem, dict)
        and set(filesystem) == {"free_bytes", "free_inodes", "block_size"}
        and all(_nonnegative_integer(value) for value in filesystem.values())
        and _valid_mount_identity(payload.get("mount"))
        and isinstance(scopes, list)
        and [item.get("path") for item in scopes if isinstance(item, dict)]
        == expected_paths
        and all(
            isinstance(item, dict)
            and set(item) == {"path", "status", "size_bytes"}
            and item.get("status") in {"available", "absent"}
            and _nonnegative_integer(item.get("size_bytes"))
            for item in scopes
        )
        and isinstance(payload.get("docker_disk_usage"), list)
        and [item.get("Type") for item in payload.get("docker_disk_usage")]
        == ["Images", "Containers", "Local Volumes", "Build Cache"]
        and all(
            isinstance(item, dict)
            and set(item) == {"Type", "TotalCount", "Active", "Size", "Reclaimable"}
            and all(isinstance(value, str) and bool(value) for value in item.values())
            for item in payload.get("docker_disk_usage")
        )
    )
    if valid:
        payload["returncode"] = returncode
        return payload
    return {
        "schema": _CAPACITY_INVENTORY_SCHEMA,
        "status": "unknown",
        "returncode": returncode,
        "errors": ["capacity inventory evidence was incomplete or malformed"],
        "diagnostic": "\n".join(
            part for part in (stderr.strip(), stdout.strip()) if part
        ),
    }


def _unknown_workspace_prelaunch(
    *, returncode: int, stdout: str, stderr: str, reason: str
) -> dict[str, Any]:
    diagnostic = "\n".join(part for part in (stderr.strip(), stdout.strip()) if part)
    return {
        "schema": _WORKSPACE_PRELAUNCH_SCHEMA,
        "status": "unknown",
        "verdict": "NO-GO",
        "returncode": returncode,
        "errors": [reason],
        "diagnostic": diagnostic,
    }


def _strict_json_object(value: str) -> dict[str, Any]:
    payload = _strict_json_value(value)
    if not isinstance(payload, dict):
        raise ValueError("workspace prelaunch output was not an object")
    return payload


def _nonnegative_integer(value: Any) -> bool:
    return type(value) is int and value >= 0


def _valid_mount_identity(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    required = {"st_dev", "device_major", "device_minor", "inode"}
    optional = {"mount_point", "filesystem", "mount_source"}
    if not required.issubset(value) or not set(value).issubset(required | optional):
        return False
    if not all(_nonnegative_integer(value[key]) for key in required):
        return False
    return all(
        isinstance(value[key], str) and bool(value[key])
        for key in optional & set(value)
    )


def _valid_capacity(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"free_bytes", "free_inodes", "temp_free_bytes", "temp_free_inodes"}
        and _nonnegative_integer(value.get("free_bytes"))
        and _nonnegative_integer(value.get("free_inodes"))
        and _nonnegative_integer(value.get("temp_free_bytes"))
        and _nonnegative_integer(value.get("temp_free_inodes"))
    )


def _valid_thresholds(
    value: Any,
    *,
    min_free_bytes: int,
    min_free_inodes: int,
    receipt_reserve_bytes: int,
) -> bool:
    expected = {
        "min_free_bytes": min_free_bytes,
        "min_free_inodes": min_free_inodes,
        "receipt_reserve_bytes": receipt_reserve_bytes,
    }
    return (
        isinstance(value, dict)
        and set(value) == set(expected)
        and all(_nonnegative_integer(item) for item in value.values())
        and value == expected
    )


def _valid_checks(value: Any, *, complete: bool) -> bool:
    if not isinstance(value, dict) or not set(value).issubset(_REQUIRED_CAPACITY_CHECKS):
        return False
    if not all(type(item) is bool for item in value.values()):
        return False
    return not complete or (
        set(value) == _REQUIRED_CAPACITY_CHECKS and all(value.values())
    )


def parse_workspace_prelaunch_result(
    *,
    returncode: int,
    stdout: str,
    stderr: str,
    expected_workspace: str,
    min_free_bytes: int,
    min_free_inodes: int,
    receipt_reserve_bytes: int,
) -> dict[str, Any]:
    """Parse the fixed capacity probe, promoting only an exact GO schema."""
    workspace = validate_workspace_dir(expected_workspace)
    expected_thresholds = (min_free_bytes, min_free_inodes, receipt_reserve_bytes)
    if any(not _nonnegative_integer(value) for value in expected_thresholds):
        raise CliError(
            "invalid_provider_observation_target",
            "prelaunch capacity thresholds must be non-negative integers",
        )
    lines = [line for line in stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        return _unknown_workspace_prelaunch(
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            reason="workspace prelaunch output did not contain exactly one JSON object",
        )
    try:
        payload = _strict_json_object(lines[0])
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        return _unknown_workspace_prelaunch(
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            reason=f"workspace prelaunch output failed strict JSON parsing: {exc}",
        )

    def invalid(reason: str) -> dict[str, Any]:
        return _unknown_workspace_prelaunch(
            returncode=returncode, stdout=stdout, stderr=stderr, reason=reason
        )

    if not set(payload).issubset(_CAPACITY_TOP_LEVEL_FIELDS):
        return invalid("workspace prelaunch output contained unknown fields")
    if payload.get("schema") != _WORKSPACE_PRELAUNCH_SCHEMA:
        return invalid("workspace prelaunch schema was missing or incorrect")
    if payload.get("workspace") != workspace:
        return invalid("workspace prelaunch target did not match configuration")
    if not _valid_thresholds(
        payload.get("thresholds"),
        min_free_bytes=min_free_bytes,
        min_free_inodes=min_free_inodes,
        receipt_reserve_bytes=receipt_reserve_bytes,
    ):
        return invalid("workspace prelaunch thresholds were malformed or mismatched")
    errors = payload.get("errors")
    if not isinstance(errors, list) or not all(
        isinstance(item, str) and bool(item) for item in errors
    ):
        return invalid("workspace prelaunch errors were malformed")
    if not _valid_checks(payload.get("checks"), complete=False):
        return invalid("workspace prelaunch checks were malformed")
    if not _valid_mount_identity(payload.get("mount")) or not _valid_mount_identity(payload.get("temp_mount")):
        return invalid("workspace prelaunch mount identity was malformed")
    if not _valid_capacity(payload.get("capacity")):
        return invalid("workspace prelaunch capacity was malformed")

    is_go = payload.get("status") == "go" and payload.get("verdict") == "GO"
    if is_go:
        if set(payload) != _CAPACITY_TOP_LEVEL_FIELDS:
            return invalid("workspace prelaunch GO output did not match the exact schema")
        if returncode != 0 or stderr.strip() or errors:
            return invalid("workspace prelaunch GO contradicted process or error evidence")
        if not _valid_checks(payload.get("checks"), complete=True):
            return invalid("workspace prelaunch GO did not prove every required check")
        capacity = payload["capacity"]
        if (
            capacity["free_bytes"] < min_free_bytes + receipt_reserve_bytes
            or capacity["free_inodes"] < min_free_inodes
        ):
            return invalid("workspace prelaunch GO contradicted reported capacity")
        payload["returncode"] = returncode
        return payload

    if payload.get("status") != "no-go" or payload.get("verdict") != "NO-GO":
        return invalid("workspace prelaunch status and verdict were contradictory")
    if returncode == 0 or not errors:
        return invalid("workspace prelaunch NO-GO contradicted process or error evidence")
    payload["returncode"] = returncode
    if stderr.strip():
        payload["diagnostic"] = stderr.strip()
    return payload


__all__ = [
    "capacity_inventory_command",
    "classify_container_inspect",
    "container_inspect_command",
    "parse_workspace_prelaunch_result",
    "parse_capacity_inventory_result",
    "validate_container_name",
    "validate_workspace_dir",
    "workspace_prelaunch_command",
]
