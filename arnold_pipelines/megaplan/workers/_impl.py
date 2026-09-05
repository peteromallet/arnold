"""Worker orchestration: running Claude and Codex steps."""

from __future__ import annotations

import argparse
import base64
import hashlib
import inspect
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import uuid
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Literal, Mapping

from arnold_pipelines.megaplan.audits.robustness import build_empty_template
from arnold_pipelines.megaplan.forms.provocations import select_active_checks
from arnold_pipelines.megaplan.fallback_chains import (
    classify_retryability,
    configured_fallback_chain_for_phase,
    decode_phase_model_value,
    fallback_observability_fields,
    is_same_family_operational_classification,
    provider_family,
)
from arnold_pipelines.megaplan.profiles import DEFAULT_AGENT_ROUTING, effective_premium_vendor
from arnold_pipelines.megaplan.schemas import (
    SCHEMAS,
    EpicEvent,
    get_execution_schema_key,
    strict_schema,
)
from arnold_pipelines.megaplan.provider_response import (
    CompiledResponseContract,
    ResponseEnforcement,
    compile_response_contract,
    persist_response_enforcement_attestation,
)
from arnold_pipelines.megaplan.orchestration.progress import strip_progress_env
from arnold_pipelines.megaplan.observability.routing_ledger import (
    format_selected_spec,
    normalize_routing_phase,
    record_step_routing,
)
from arnold_pipelines.megaplan.types import (
    AgentMode,
    CliError,
    MOCK_ENV_VAR,
    PlanState,
    SessionInfo,
    format_agent_spec,
    is_premium_placeholder_agent,
    parse_agent_spec,
    resolved_default_model_for_agent,
    resolve_premium_placeholder_spec,
)
from arnold_pipelines.megaplan._core import (
    apply_session_update,
    atomic_write_json,
    configured_robustness,
    creative_form_id,
    detect_available_agents,
    phase_timeout_seconds,
    get_effective,
    json_dump,
    latest_plan_meta_path,
    load_config,
    now_utc,
    read_json,
    schemas_root,
    touch_active_step,
)
from arnold_pipelines.megaplan._core.state import write_plan_state
from arnold_pipelines.megaplan._core.io import framed_json_record_bytes
from arnold_pipelines.megaplan.prompts import (
    _resolve_prompt_root,
    create_codex_prompt,
)
from arnold.execution.step_invocation import StepInvocation
from arnold_pipelines.megaplan.model_seam import (
    DEFAULT_LOCAL_STRICT_ARTIFACT_MAX_BYTES,
    LOCAL_STRICT_ARTIFACT_RECEIPT_SCHEMA,
    ModelBudgetError,
    ModelTier,
    ModelStructuralAuditError,
    audit_step_payload,
    capture_step_output,
    local_strict_repair_input,
    render_prompt_for_dispatch,
    render_step_message,
    schema_audits_step_payload,
)
from arnold_pipelines.megaplan.runtime.process import TmuxSession, spawn
from arnold_pipelines.megaplan.runtime.engine_isolation import engine_write_barrier
from arnold_pipelines.megaplan.runtime.execution_environment import resolve_execution_environment
from arnold_pipelines.megaplan.runtime.execution_environment import (
    ExecutionEnvironment,
    classify_path_overlap,
    isolation_cli_error,
)
from arnold_pipelines.megaplan.watchdog.worker_identity import (
    current_boot_identity,
    read_process_start_identity,
)

if TYPE_CHECKING:
    from arnold_pipelines.megaplan.custody.common_worker_dispatch import CommonWorkerDispatchSpec

from arnold_pipelines.megaplan.workers._mock_payloads import _EXECUTE_STEPS, _build_mock_payload

_CROSS_CALL_PERSISTENT_STEPS = _EXECUTE_STEPS
_CODEX_WORKER_CHANNEL = "codex_cli"
_WORKER_IDENTITY_METADATA_KEY = "worker_identity"
_LOCAL_STRICT_ARTIFACT_DIRNAME = "local-strict-artifacts"
_MUTATING_WORKER_STEPS = {"execute", "revise", "loop_execute"}
_ZERO_RECOVERY_MODEL_PHASES = frozenset(
    {"plan", "critique", "gate", "revise", "finalize"}
)
_ZERO_RECOVERY_MODEL_UID = 65532
_ZERO_RECOVERY_MODEL_GID = 65532
_ZERO_RECOVERY_RUNTIME_ROOT = Path("/run/megaplan-zero-recovery")
_ZERO_RECOVERY_MODEL_PATH = "/opt/zero-recovery-node/bin:/usr/local/bin:/usr/bin:/bin"
_ZERO_RECOVERY_SCHEMA_PATHS = tuple(
    f".megaplan/schemas/{filename}" for filename in sorted(SCHEMAS)
)
_WORKER_DISPATCH_BINDING: ContextVar[dict[str, Any] | None] = ContextVar(
    "megaplan_worker_dispatch_binding", default=None
)
_LOCAL_SPAWN_CONTROL: ContextVar[Any | None] = ContextVar(
    "megaplan_local_spawn_control", default=None
)
_ZERO_RECOVERY_ENGINE_RUNTIME_PATHS = (
    ".megaplan/.state-locks/critique-ledger-cl2-planning-canary.lock",
    ".megaplan/epics/critique-ledger-cl2-planning-canary/events.jsonl",
)
_ZERO_RECOVERY_EPIC_JOURNAL_DIR = (
    ".megaplan/epics/critique-ledger-cl2-planning-canary/_journal"
)
_ZERO_RECOVERY_EMPTY_RUNTIME_DIRS = {
    _ZERO_RECOVERY_EPIC_JOURNAL_DIR,
    ".megaplan/blobs",
    # run_command creates its stdin tempfile here and unlinks the file on every
    # terminal path. The trusted empty directory may persist; any surviving
    # child is still rejected by the direct-source manifest walk.
    ".megaplan/worker_tmp",
}


def _zero_recovery_global_scratch_observation() -> dict[str, str]:
    """Prove global scratch is inaccessible; IPC-none may omit /dev/shm."""
    observation: dict[str, str] = {}
    for global_tmp in (Path("/tmp"), Path("/var/tmp"), Path("/dev/shm")):
        try:
            global_tmp_stat = os.lstat(global_tmp)
        except FileNotFoundError:
            if global_tmp == Path("/dev/shm"):
                observation[str(global_tmp)] = "absent_ipc_none"
                continue
            raise CliError(
                "zero_recovery_privilege_boundary_invalid",
                f"required global scratch path is absent: {global_tmp}",
            )
        if (
            not stat.S_ISDIR(global_tmp_stat.st_mode)
            or stat.S_ISLNK(global_tmp_stat.st_mode)
            or global_tmp_stat.st_uid != 0
            or global_tmp_stat.st_mode & 0o022
        ):
            raise CliError(
                "zero_recovery_privilege_boundary_invalid",
                f"global scratch is writable by the finite-model UID: {global_tmp}",
            )
        observation[str(global_tmp)] = "root_nonwritable"
    return observation


def _zero_recovery_copy_private_file(source: Path, destination: Path) -> None:
    source_stat = os.lstat(source)
    if (
        not stat.S_ISREG(source_stat.st_mode)
        or source_stat.st_nlink != 1
        or source_stat.st_uid != 0
        or source_stat.st_mode & 0o022
    ):
        raise CliError(
            "zero_recovery_privilege_boundary_invalid",
            f"canonical model input is not root-owned immutable data: {source}",
        )
    data = source.read_bytes()
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fchmod(fd, 0o600)
        os.fchown(fd, _ZERO_RECOVERY_MODEL_UID, _ZERO_RECOVERY_MODEL_GID)
        os.fsync(fd)
    finally:
        os.close(fd)


def _prepare_zero_recovery_schema_input(
    schema_file: Path,
) -> dict[str, Any] | None:
    if os.getenv("MEGAPLAN_ZERO_RECOVERY_CANARY") != "1":
        return None
    if os.geteuid() != 0:
        raise CliError(
            "zero_recovery_privilege_boundary_invalid",
            "finite canary schema grant requires the trusted root harness",
        )
    schema_stat = os.lstat(schema_file)
    if (
        not stat.S_ISREG(schema_stat.st_mode)
        or schema_stat.st_nlink != 1
        or schema_stat.st_uid != 0
        or schema_stat.st_gid != 0
        or schema_stat.st_mode & 0o022
    ):
        raise CliError(
            "zero_recovery_privilege_boundary_invalid",
            "finite canary schema is not root-owned immutable data",
        )
    fd = os.open(schema_file, os.O_RDONLY | os.O_NOFOLLOW)
    grant_attempted = False
    try:
        opened = os.fstat(fd)
        if (
            (opened.st_dev, opened.st_ino)
            != (schema_stat.st_dev, schema_stat.st_ino)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != 0
            or opened.st_gid != 0
        ):
            raise CliError(
                "zero_recovery_privilege_boundary_invalid",
                "finite canary schema identity raced before read-only grant",
            )
        digest = hashlib.sha256()
        while chunk := os.read(fd, 1024 * 1024):
            digest.update(chunk)
        grant_attempted = True
        os.fchmod(fd, 0o644)
        granted = os.fstat(fd)
        if (
            (granted.st_dev, granted.st_ino)
            != (schema_stat.st_dev, schema_stat.st_ino)
            or not stat.S_ISREG(granted.st_mode)
            or granted.st_nlink != 1
            or granted.st_uid != 0
            or granted.st_gid != 0
            or stat.S_IMODE(granted.st_mode) != 0o644
        ):
            raise CliError(
                "zero_recovery_privilege_boundary_invalid",
                "finite canary schema read-only grant did not seal exact identity",
            )
    except BaseException:
        if grant_attempted:
            try:
                os.fchmod(fd, stat.S_IMODE(schema_stat.st_mode))
            except OSError:
                pass
        raise
    finally:
        os.close(fd)
    return {
        "path": schema_file,
        "st_dev": schema_stat.st_dev,
        "st_ino": schema_stat.st_ino,
        "mode": stat.S_IMODE(schema_stat.st_mode),
        "sha256": digest.hexdigest(),
    }


def _restore_zero_recovery_schema_input(
    grant: dict[str, Any] | None,
) -> None:
    if grant is None:
        return
    schema_file = grant["path"]
    observed = os.lstat(schema_file)
    fd = os.open(schema_file, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        current_mode = stat.S_IMODE(opened.st_mode)
        if (
            (observed.st_dev, observed.st_ino)
            != (grant["st_dev"], grant["st_ino"])
            or (opened.st_dev, opened.st_ino)
            != (grant["st_dev"], grant["st_ino"])
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != 0
            or opened.st_gid != 0
            or current_mode not in {0o644, grant["mode"]}
        ):
            raise CliError(
                "zero_recovery_privilege_boundary_invalid",
                "finite canary schema changed before read-only grant revocation",
            )
        digest = hashlib.sha256()
        while chunk := os.read(fd, 1024 * 1024):
            digest.update(chunk)
        if digest.hexdigest() != grant["sha256"]:
            raise CliError(
                "zero_recovery_privilege_boundary_invalid",
                "finite canary schema content changed before grant revocation",
            )
        if current_mode == grant["mode"]:
            return
        os.fchmod(fd, grant["mode"])
        restored = os.fstat(fd)
        if (
            (restored.st_dev, restored.st_ino)
            != (grant["st_dev"], grant["st_ino"])
            or stat.S_IMODE(restored.st_mode) != grant["mode"]
            or restored.st_uid != 0
            or restored.st_gid != 0
            or restored.st_nlink != 1
        ):
            raise CliError(
                "zero_recovery_privilege_boundary_invalid",
                "finite canary schema grant revocation did not reseal identity",
            )
    finally:
        os.close(fd)


def _prepare_zero_recovery_model_runtime(
    *,
    step: str,
    plan_dir: Path,
    output_path: Path,
    plan_iteration: int,
    dispatch_ordinal: int,
) -> dict[str, Any] | None:
    if os.getenv("MEGAPLAN_ZERO_RECOVERY_CANARY") != "1":
        return None
    if os.geteuid() != 0:
        raise CliError(
            "zero_recovery_privilege_boundary_invalid",
            "finite canary trusted harness must run as root",
        )
    preexisting = subprocess.run(
        ["/usr/bin/pgrep", "-u", str(_ZERO_RECOVERY_MODEL_UID)],
        env={"PATH": "/usr/bin:/bin"}, capture_output=True, check=False,
    )
    if preexisting.returncode != 1:
        raise CliError(
            "zero_recovery_privilege_boundary_invalid",
            "finite-model UID was not process-empty before dispatch",
        )
    global_scratch = _zero_recovery_global_scratch_observation()
    plan_stat = os.lstat(plan_dir)
    if (
        not stat.S_ISDIR(plan_stat.st_mode)
        or stat.S_ISLNK(plan_stat.st_mode)
        or plan_stat.st_uid != 0
        or plan_stat.st_mode & 0o022
    ):
        raise CliError(
            "zero_recovery_privilege_boundary_invalid",
            "plan output parent must be a root-owned non-writable directory",
        )
    runtime_root_stat = os.lstat(_ZERO_RECOVERY_RUNTIME_ROOT)
    if (
        not stat.S_ISDIR(runtime_root_stat.st_mode)
        or stat.S_ISLNK(runtime_root_stat.st_mode)
        or runtime_root_stat.st_uid != 0
        or stat.S_IMODE(runtime_root_stat.st_mode) != 0o711
    ):
        raise CliError(
            "zero_recovery_privilege_boundary_invalid",
            "finite model runtime root is not the admitted root-owned 0711 directory",
        )
    runtime = _ZERO_RECOVERY_RUNTIME_ROOT / (
        f"{dispatch_ordinal:02d}-{step}-i{plan_iteration}-{uuid.uuid4().hex}"
    )
    output_created = False
    try:
        os.mkdir(runtime, 0o700)
        home = runtime / "home"
        codex_home = home / ".codex"
        tmp = runtime / "tmp"
        for directory in (
            home,
            codex_home,
            tmp,
            runtime / "xdg-cache",
            runtime / "xdg-config",
        ):
            os.mkdir(directory, 0o700)
        canonical_codex = Path("/root/.codex")
        _zero_recovery_copy_private_file(
            canonical_codex / "auth.json", codex_home / "auth.json"
        )
        _zero_recovery_copy_private_file(
            canonical_codex / "config.toml", codex_home / "config.toml"
        )
        output_fd = os.open(
            output_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        output_created = True
        try:
            os.fchmod(output_fd, 0o600)
            os.fchown(output_fd, _ZERO_RECOVERY_MODEL_UID, _ZERO_RECOVERY_MODEL_GID)
            os.fsync(output_fd)
            output_stat = os.fstat(output_fd)
        finally:
            os.close(output_fd)
        # The trusted root process deliberately lacks DAC_OVERRIDE. Construct
        # and seed the complete tree before transferring its directories to
        # the finite model UID; chowning `home` first would make `.codex`
        # uncreatable under the admitted capability set.
        for directory in (
            codex_home,
            home,
            tmp,
            runtime / "xdg-cache",
            runtime / "xdg-config",
        ):
            os.chown(directory, _ZERO_RECOVERY_MODEL_UID, _ZERO_RECOVERY_MODEL_GID)
        os.chown(runtime, _ZERO_RECOVERY_MODEL_UID, _ZERO_RECOVERY_MODEL_GID)
        probe_env = _zero_recovery_model_env(
            {
                "runtime": runtime,
                "home": home,
                "codex_home": codex_home,
                "tmp": tmp,
            },
            turn_id=f"privilege_probe_{step}",
        )
        probe = subprocess.run(
            _zero_recovery_model_command(["/bin/cat", "/proc/self/status"]),
            cwd=plan_dir,
            env=probe_env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        status_fields: dict[str, str] = {}
        for line in probe.stdout.splitlines():
            key, separator, value = line.partition(":")
            if separator:
                status_fields[key] = value.strip()
        privilege_observation = {
            key: status_fields.get(key)
            for key in (
                "Uid", "Gid", "Groups", "NoNewPrivs", "CapInh", "CapPrm",
                "CapEff", "CapBnd", "CapAmb",
            )
        }
        zero_cap = "0000000000000000"
        if (
            probe.returncode != 0
            or privilege_observation["Uid"] != "65532\t65532\t65532\t65532"
            or privilege_observation["Gid"] != "65532\t65532\t65532\t65532"
            or privilege_observation["Groups"] not in {"", None}
            or privilege_observation["NoNewPrivs"] != "1"
            or any(
                privilege_observation[key] != zero_cap
                for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
            )
        ):
            raise CliError(
                "zero_recovery_privilege_boundary_invalid",
                "finite-model setpriv probe did not prove zero capabilities and NNP",
            )
        post_probe = subprocess.run(
            ["/usr/bin/pgrep", "-u", str(_ZERO_RECOVERY_MODEL_UID)],
            env={"PATH": "/usr/bin:/bin"}, capture_output=True, check=False,
        )
        if post_probe.returncode != 1:
            raise CliError(
                "zero_recovery_privilege_boundary_invalid",
                "finite-model privilege probe left a process",
            )
        return {
            "step": step,
            "plan_iteration": plan_iteration,
            "dispatch_ordinal": dispatch_ordinal,
            "runtime": runtime,
            "home": home,
            "codex_home": codex_home,
            "tmp": tmp,
            "output_dev": output_stat.st_dev,
            "output_ino": output_stat.st_ino,
            "privilege_observation": privilege_observation,
            "global_scratch": global_scratch,
        }
    except BaseException:
        if output_created:
            try:
                os.chown(output_path, 0, 0, follow_symlinks=False)
                os.chmod(output_path, 0o600, follow_symlinks=False)
            except OSError:
                pass
        if runtime.exists():
            try:
                _reclaim_zero_recovery_tree(runtime)
            except BaseException:
                pass
        raise


def _reclaim_zero_recovery_tree(path: Path) -> None:
    current = os.lstat(path)
    if stat.S_ISLNK(current.st_mode):
        # Ephemeral Codex arg0 wrappers are symlinks inside the isolated
        # runtime.  The finite-model UID is process-empty before reclaim, so
        # remove the link itself without following or touching its target.
        path.unlink()
        return
    if (
        not stat.S_ISDIR(current.st_mode)
        and not stat.S_ISREG(current.st_mode)
        and not stat.S_ISSOCK(current.st_mode)
    ):
        raise CliError(
            "zero_recovery_privilege_boundary_invalid",
            "model runtime contains a forbidden filesystem object: "
            f"{path} mode={stat.S_IFMT(current.st_mode):#o}",
        )
    if stat.S_ISREG(current.st_mode) and current.st_nlink != 1:
        raise CliError(
            "zero_recovery_privilege_boundary_invalid",
            f"model runtime contains a hard-linked file: {path}",
        )
    if stat.S_ISDIR(current.st_mode):
        # The trusted harness has CHOWN but deliberately lacks DAC_OVERRIDE.
        # After UID process emptiness is proven, take ownership of the
        # directory before recursing so an ephemeral symlink entry can be
        # unlinked from its formerly model-owned 0700 parent.
        os.chown(path, 0, 0, follow_symlinks=False)
        os.chmod(path, 0o700, follow_symlinks=False)
        with os.scandir(path) as entries:
            children = [Path(entry.path) for entry in entries]
        for child in children:
            _reclaim_zero_recovery_tree(child)
    else:
        os.chown(path, 0, 0, follow_symlinks=False)
        os.chmod(path, 0o600, follow_symlinks=False)


def _zero_recovery_runtime_usage(path: Path) -> tuple[int, int]:
    files = 0
    total_bytes = 0

    def visit(candidate: Path) -> None:
        nonlocal files, total_bytes
        item_stat = os.lstat(candidate)
        if stat.S_ISDIR(item_stat.st_mode) and not stat.S_ISLNK(item_stat.st_mode):
            with os.scandir(candidate) as entries:
                children = [Path(entry.path) for entry in entries]
            for child in children:
                visit(child)
            return
        if stat.S_ISSOCK(item_stat.st_mode):
            # Codex creates an AF_UNIX IPC endpoint under its isolated
            # CODEX_HOME.  Once every finite-model UID process is dead, the
            # filesystem socket has no listener and is an inert, bounded
            # runtime object.  Count it without opening or following it; the
            # subsequent reclaim seals its ownership and mode.
            files += 1
            return
        if stat.S_ISLNK(item_stat.st_mode):
            # Account for the link itself and its bounded target text without
            # resolving it.  Reclaim later unlinks this ephemeral runtime-only
            # object after process emptiness has been established.
            files += 1
            total_bytes += len(os.fsencode(os.readlink(candidate)))
            return
        if not stat.S_ISREG(item_stat.st_mode) or item_stat.st_nlink != 1:
            raise CliError(
                "zero_recovery_privilege_boundary_invalid",
                "finite-model runtime contains a forbidden or linked object: "
                f"{candidate} mode={stat.S_IFMT(item_stat.st_mode):#o} "
                f"nlink={item_stat.st_nlink}",
            )
        files += 1
        total_bytes += item_stat.st_size

    visit(path)
    return files, total_bytes


def _write_zero_recovery_privilege_receipt(
    runtime: dict[str, Any], *, output_path: Path, runtime_files: int, runtime_bytes: int
) -> None:
    output_stat = os.lstat(output_path)
    output_digest = hashlib.sha256(output_path.read_bytes()).hexdigest()
    runtime_stat = os.lstat(runtime["runtime"])
    payload: dict[str, Any] = {
        "schema": "arnold.megaplan.zero_recovery_privilege_receipt.v2",
        "status": "sealed",
        "phase": runtime["step"],
        "plan_iteration": runtime["plan_iteration"],
        "dispatch_ordinal": runtime["dispatch_ordinal"],
        "model_uid": _ZERO_RECOVERY_MODEL_UID,
        "model_gid": _ZERO_RECOVERY_MODEL_GID,
        "uid_processes_before": 0,
        "uid_processes_after": 0,
        "privilege_observation": runtime["privilege_observation"],
        "command_prefix": _zero_recovery_model_command([]),
        "environment_keys": sorted(
            _zero_recovery_model_env(runtime, turn_id="receipt").keys()
        ),
        "writable_roots": [output_path.name, str(runtime["runtime"])],
        "global_scratch": runtime["global_scratch"],
        "limits": {
            "nproc": 64,
            "fsize_bytes": 67_108_864,
            "runtime_max_files": 4096,
            "runtime_max_bytes": 134_217_728,
            "output_max_bytes": 16_777_216,
        },
        "output": {
            "path": output_path.name,
            "st_dev": output_stat.st_dev,
            "st_ino": output_stat.st_ino,
            "size": output_stat.st_size,
            "sha256": output_digest,
            "sealed_uid": output_stat.st_uid,
            "sealed_gid": output_stat.st_gid,
            "mode": f"{stat.S_IMODE(output_stat.st_mode):04o}",
            "nlink": output_stat.st_nlink,
        },
        "runtime": {
            "path": str(runtime["runtime"]),
            "st_dev": runtime_stat.st_dev,
            "st_ino": runtime_stat.st_ino,
            "files": runtime_files,
            "bytes": runtime_bytes,
            "sealed_uid": runtime_stat.st_uid,
            "sealed_gid": runtime_stat.st_gid,
            "mode": f"{stat.S_IMODE(runtime_stat.st_mode):04o}",
        },
        "recorded_at": now_utc(),
    }
    payload["receipt_digest"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    receipt_path = output_path.parent / output_path.name.replace(
        "-worker-output.json", "-privilege-receipt.json"
    )
    fd = os.open(
        receipt_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    runtime["privilege_receipt_path"] = receipt_path
    runtime["privilege_receipt_sha256"] = hashlib.sha256(
        receipt_path.read_bytes()
    ).hexdigest()


def _quiesce_zero_recovery_model_uid() -> None:
    process_env = {"PATH": "/usr/bin:/bin"}
    deadline = time.monotonic() + 5.0
    consecutive_empty = 0
    last_processes: list[dict[str, str]] = []
    # Real Codex may terminate a process tree in waves. Re-issue KILL while the
    # container's init reaps exited descendants; a one-shot kill plus 200 ms
    # can mistake a transient orphan/zombie for a live mutation-capable owner.
    while True:
        observed = subprocess.run(
            [
                "/usr/bin/ps", "--no-headers", "-o", "pid=,ppid=,stat=,lstart=",
                "-u", str(_ZERO_RECOVERY_MODEL_UID),
            ],
            env=process_env, capture_output=True, check=False, text=True,
        )
        if observed.returncode not in {0, 1}:
            raise CliError(
                "zero_recovery_privilege_boundary_invalid",
                "could not observe finite-model UID process states",
            )
        last_processes = []
        for line in (observed.stdout or "").splitlines():
            fields = line.strip().split(None, 3)
            if len(fields) != 4 or not fields[0].isdigit() or not fields[1].isdigit():
                raise CliError(
                    "zero_recovery_privilege_boundary_invalid",
                    "finite-model UID process census was malformed",
                )
            last_processes.append(
                {
                    "pid": fields[0],
                    "ppid": fields[1],
                    "stat": fields[2],
                    "started": fields[3],
                }
            )
        if not last_processes:
            consecutive_empty += 1
            if consecutive_empty == 2:
                return
        else:
            consecutive_empty = 0
            live_pids = [
                item["pid"]
                for item in last_processes
                if not item["stat"].startswith("Z")
            ]
            if live_pids:
                # Races with a process exiting are harmless: the following
                # census, not kill(2)'s return code, is authoritative.
                subprocess.run(
                    ["/bin/kill", "-KILL", *live_pids],
                    env=process_env, capture_output=True, check=False,
                )
        if time.monotonic() >= deadline:
            kind = (
                "unreaped zombies"
                if last_processes
                and all(item["stat"].startswith("Z") for item in last_processes)
                else "surviving processes"
            )
            detail = ", ".join(
                "pid={pid} ppid={ppid} stat={stat} started={started}".format(**item)
                for item in last_processes[:8]
            )
            raise CliError(
                "zero_recovery_privilege_boundary_invalid",
                f"finite-model UID retained {kind} after bounded kill/reap: {detail}",
            )
        time.sleep(0.05)


def _finish_zero_recovery_model_runtime(
    runtime: dict[str, Any] | None,
    *,
    output_path: Path,
    on_process_empty: Callable[[], None] | None = None,
) -> None:
    if runtime is None:
        return
    _quiesce_zero_recovery_model_uid()
    if on_process_empty is not None:
        on_process_empty()
    output_stat = os.lstat(output_path)
    if (
        not stat.S_ISREG(output_stat.st_mode)
        or output_stat.st_nlink != 1
        or output_stat.st_dev != runtime["output_dev"]
        or output_stat.st_ino != runtime["output_ino"]
        or output_stat.st_uid != _ZERO_RECOVERY_MODEL_UID
        or output_stat.st_gid != _ZERO_RECOVERY_MODEL_GID
    ):
        raise CliError(
            "zero_recovery_privilege_boundary_invalid",
            "finite model replaced or aliased its exact precreated output",
        )
    if output_stat.st_size > 16_777_216:
        raise CliError(
            "zero_recovery_privilege_boundary_invalid",
            "finite model output exceeded the admitted size bound",
        )
    runtime_files, runtime_bytes = _zero_recovery_runtime_usage(runtime["runtime"])
    if runtime_files > 4096 or runtime_bytes > 134_217_728:
        raise CliError(
            "zero_recovery_privilege_boundary_invalid",
            "finite model runtime exceeded admitted file or byte bounds",
        )
    os.chown(output_path, 0, 0, follow_symlinks=False)
    os.chmod(output_path, 0o600, follow_symlinks=False)
    _reclaim_zero_recovery_tree(runtime["runtime"])
    _write_zero_recovery_privilege_receipt(
        runtime,
        output_path=output_path,
        runtime_files=runtime_files,
        runtime_bytes=runtime_bytes,
    )


def _zero_recovery_model_command(command: list[str]) -> list[str]:
    return [
        "/usr/bin/setpriv",
        f"--reuid={_ZERO_RECOVERY_MODEL_UID}",
        f"--regid={_ZERO_RECOVERY_MODEL_GID}",
        "--clear-groups",
        "--no-new-privs",
        "--bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--",
        "/usr/bin/prlimit",
        "--nproc=64",
        "--fsize=67108864",
        "--core=0",
        "--",
        *command,
    ]


def _zero_recovery_model_env(
    runtime: dict[str, Any], *, turn_id: str
) -> dict[str, str]:
    return {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HOME": str(runtime["home"]),
            "CODEX_HOME": str(runtime["codex_home"]),
            "TMPDIR": str(runtime["tmp"]),
            "XDG_CACHE_HOME": str(runtime["runtime"] / "xdg-cache"),
            "XDG_CONFIG_HOME": str(runtime["runtime"] / "xdg-config"),
            "PATH": _ZERO_RECOVERY_MODEL_PATH,
            "USER": "finite-model",
            "LOGNAME": "finite-model",
            "MEGAPLAN_TURN_ID": turn_id,
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
        }


def _zero_recovery_file_record(path: Path, *, trusted_uid: int) -> dict[str, Any]:
    item_stat = os.lstat(path)
    if item_stat.st_uid != trusted_uid or (
        not stat.S_ISLNK(item_stat.st_mode) and item_stat.st_mode & 0o022
    ):
        raise CliError(
            "zero_recovery_worker_mutation_denied",
            f"source object is not trusted-owner non-writable: {path}",
        )
    if stat.S_ISLNK(item_stat.st_mode):
        target = os.readlink(path)
        return {
            "kind": "symlink", "mode": stat.S_IMODE(item_stat.st_mode),
            "uid": item_stat.st_uid, "gid": item_stat.st_gid,
            "sha256": hashlib.sha256(target.encode()).hexdigest(),
        }
    if not stat.S_ISREG(item_stat.st_mode) or item_stat.st_nlink != 1:
        raise CliError(
            "zero_recovery_worker_mutation_denied",
            f"source object is not a single-link regular file: {path}",
        )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (item_stat.st_dev, item_stat.st_ino):
            raise CliError(
                "zero_recovery_worker_mutation_denied", "source inode raced"
            )
        digest = hashlib.sha256()
        while chunk := os.read(fd, 1024 * 1024):
            digest.update(chunk)
    finally:
        os.close(fd)
    return {
        "kind": "file", "mode": stat.S_IMODE(item_stat.st_mode),
        "uid": item_stat.st_uid, "gid": item_stat.st_gid,
        "sha256": digest.hexdigest(),
    }


def _zero_recovery_runtime_file_identity(
    path: Path, *, trusted_uid: int
) -> tuple[dict[str, Any], bytes]:
    try:
        observed = os.lstat(path)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise CliError(
            "zero_recovery_worker_mutation_denied",
            "canary engine runtime file identity is invalid",
        ) from exc
    try:
        identity = os.fstat(fd)
        if (
            not stat.S_ISREG(observed.st_mode)
            or not stat.S_ISREG(identity.st_mode)
            or (identity.st_dev, identity.st_ino)
            != (observed.st_dev, observed.st_ino)
            or identity.st_nlink != 1
            or identity.st_uid != trusted_uid
            or identity.st_mode & 0o022
            or stat.S_IMODE(identity.st_mode) != 0o644
        ):
            raise CliError(
                "zero_recovery_worker_mutation_denied",
                "canary engine runtime file identity is invalid",
            )
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read()
        after_read = os.fstat(fd)
        if (
            (after_read.st_dev, after_read.st_ino, after_read.st_size)
            != (identity.st_dev, identity.st_ino, identity.st_size)
            or len(raw) != identity.st_size
        ):
            raise CliError(
                "zero_recovery_worker_mutation_denied",
                "canary engine runtime file raced",
            )
    finally:
        os.close(fd)
    return {
        "path": path.as_posix(),
        "st_dev": identity.st_dev,
        "st_ino": identity.st_ino,
        "size": identity.st_size,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }, raw


def _zero_recovery_observe_engine_runtime(
    root: Path, *, trusted_uid: int
) -> dict[str, Any]:
    lock_path = root / _ZERO_RECOVERY_ENGINE_RUNTIME_PATHS[0]
    event_path = root / _ZERO_RECOVERY_ENGINE_RUNTIME_PATHS[1]
    lock = None
    try:
        os.lstat(lock_path)
        lock_present = True
    except FileNotFoundError:
        lock_present = False
    if lock_present:
        lock, lock_raw = _zero_recovery_runtime_file_identity(
            lock_path, trusted_uid=trusted_uid
        )
        lock["path"] = _ZERO_RECOVERY_ENGINE_RUNTIME_PATHS[0]
        if lock_raw != b"":
            raise CliError(
                "zero_recovery_worker_mutation_denied",
                "canary state lock is not empty",
            )
    events = None
    try:
        os.lstat(event_path)
        events_present = True
    except FileNotFoundError:
        events_present = False
    if not events_present:
        return {"lock": lock, "events": events}
    journal_dir = root / _ZERO_RECOVERY_EPIC_JOURNAL_DIR
    if not journal_dir.is_dir() or any(journal_dir.iterdir()):
        raise CliError(
            "zero_recovery_worker_mutation_denied",
            "canary epic transaction journal is not empty at checkpoint",
        )
    events, raw = _zero_recovery_runtime_file_identity(
        event_path, trusted_uid=trusted_uid
    )
    events["path"] = _ZERO_RECOVERY_ENGINE_RUNTIME_PATHS[1]
    flattened: list[dict[str, Any]] = []
    offset = 0
    while offset < len(raw):
        frame_start = offset
        if len(raw) - offset < 5:
            break
        payload_size = int.from_bytes(raw[offset : offset + 4], "big")
        offset += 4
        if payload_size > 1024 * 1024 or len(raw) - offset < payload_size + 1:
            break
        payload = raw[offset : offset + payload_size]
        offset += payload_size
        if raw[offset : offset + 1] != b"\n":
            break
        offset += 1
        try:
            record = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            break
        if (
            not isinstance(record, dict)
            or framed_json_record_bytes(record) != raw[frame_start:offset]
        ):
            break
        flattened.append(record)
    if not flattened or offset != len(raw) or len(flattened) % 3:
        raise CliError(
            "zero_recovery_worker_mutation_denied",
            "canary epic event journal is noncanonical",
        )
    sequences: list[int] = []
    transaction_ids: set[str] = set()
    for record_index in range(0, len(flattened), 3):
        records = flattened[record_index : record_index + 3]
        transaction_id = records[0].get("tx_id")
        if (
            not isinstance(transaction_id, str)
            or re.fullmatch(r"tx_[0-9a-f]{12}", transaction_id) is None
            or transaction_id in transaction_ids
            or records[0]
            != {"event_type": "_tx_begin", "tx_id": transaction_id}
            or records[-1]
            != {"event_type": "_tx_commit", "tx_id": transaction_id}
        ):
            raise CliError(
                "zero_recovery_worker_mutation_denied",
                "canary epic event transaction markers are invalid",
            )
        transaction_ids.add(transaction_id)
        for raw_event in records[1:-1]:
            event = dict(raw_event)
            if event.pop("tx_id", None) != transaction_id:
                raise CliError(
                    "zero_recovery_worker_mutation_denied",
                    "canary epic event transaction binding is invalid",
                )
            try:
                parsed = EpicEvent.model_validate(event)
            except Exception as exc:
                raise CliError(
                    "zero_recovery_worker_mutation_denied",
                    "canary epic event record is invalid",
                ) from exc
            if (
                set(event) != set(EpicEvent.model_fields)
                or parsed.epic_id != "critique-ledger-cl2-planning-canary"
                or parsed.event_type != "state_change"
                or re.fullmatch(r"evt_[0-9a-f]{12}", parsed.id) is None
                or re.fullmatch(r"[0-9a-f]{16}", parsed.transaction_id) is None
                or not isinstance(parsed.post_state, dict)
                or set(parsed.post_state) != {"event"}
                or not isinstance(parsed.post_state.get("event"), dict)
                or type(parsed.post_state["event"].get("seq")) is not int
            ):
                raise CliError(
                    "zero_recovery_worker_mutation_denied",
                    "canary epic event record escaped the admitted plan",
                )
            sequences.append(parsed.post_state["event"]["seq"])
    if sequences != list(range(len(sequences))):
        raise CliError(
            "zero_recovery_worker_mutation_denied",
            "canary epic event sequence is not contiguous",
        )
    events.update({
        "transaction_count": len(transaction_ids),
        "last_seq": sequences[-1],
        "_raw": raw,
    })
    return {"lock": lock, "events": events}


def _zero_recovery_validate_engine_runtime_transition(
    before: dict[str, Any], after: dict[str, Any]
) -> None:
    before_lock = before.get("lock")
    after_lock = after.get("lock")
    before_events = before.get("events")
    after_events = after.get("events")
    if before_lock is not None and (
        after_lock is None
        or (after_lock["st_dev"], after_lock["st_ino"])
        != (before_lock["st_dev"], before_lock["st_ino"])
    ):
        raise CliError(
            "zero_recovery_worker_mutation_denied",
            "canary state lock identity changed",
        )
    if before_events is None:
        return
    if (
        after_events is None
        or (after_events["st_dev"], after_events["st_ino"])
        != (before_events["st_dev"], before_events["st_ino"])
        or after_events["size"] < before_events["size"]
        or after_events["transaction_count"] < before_events["transaction_count"]
        or after_events["last_seq"] < before_events["last_seq"]
        or not after_events["_raw"].startswith(before_events["_raw"])
    ):
        raise CliError(
            "zero_recovery_worker_mutation_denied",
            "canary epic event journal is not append-only",
        )


def _zero_recovery_git_metadata(root: Path, *, trusted_uid: int) -> dict[str, Any]:
    git_dir = root / ".git"
    git_stat = os.lstat(git_dir)
    if (
        not stat.S_ISDIR(git_stat.st_mode)
        or stat.S_ISLNK(git_stat.st_mode)
        or git_stat.st_uid != trusted_uid
        or git_stat.st_mode & 0o022
    ):
        raise CliError(
            "zero_recovery_worker_mutation_denied", ".git custody is unsafe"
        )
    records: dict[str, Any] = {}

    def visit(path: Path, relative: str) -> None:
        item_stat = os.lstat(path)
        if item_stat.st_uid != trusted_uid or item_stat.st_mode & 0o022:
            raise CliError(
                "zero_recovery_worker_mutation_denied",
                f"Git control metadata is writable: .git/{relative}",
            )
        if stat.S_ISDIR(item_stat.st_mode):
            records[relative] = {
                "kind": "dir", "mode": stat.S_IMODE(item_stat.st_mode),
                "uid": item_stat.st_uid, "gid": item_stat.st_gid,
            }
            with os.scandir(path) as entries:
                children = sorted(entries, key=lambda entry: entry.name)
            for entry in children:
                visit(Path(entry.path), f"{relative}/{entry.name}" if relative else entry.name)
            return
        records[relative] = _zero_recovery_file_record(
            path, trusted_uid=trusted_uid
        )

    for name in (
        "HEAD", "config", "config.worktree", "index", "packed-refs",
        "refs", "hooks", "info", "shallow", "commondir", "gitdir", "modules",
    ):
        candidate = git_dir / name
        try:
            os.lstat(candidate)
        except FileNotFoundError:
            continue
        visit(candidate, name)
    return records


def _zero_recovery_direct_source_manifest(
    root: Path,
    plan_dir: Path,
    *,
    tracked_index: list[dict[str, str]],
    head: str,
    tree: str,
) -> dict[str, Any]:
    trusted_uid = os.geteuid()
    root_stat = os.lstat(root)
    if (
        not stat.S_ISDIR(root_stat.st_mode)
        or stat.S_ISLNK(root_stat.st_mode)
        or root_stat.st_uid != trusted_uid
        or root_stat.st_mode & 0o022
    ):
        raise CliError(
            "zero_recovery_worker_mutation_denied", "checkout root custody is unsafe"
        )
    tracked_paths = {entry["path"] for entry in tracked_index}
    tracked_parents = {
        parent.as_posix()
        for value in tracked_paths
        for parent in Path(value).parents
        if parent.as_posix() != "."
    }
    plan_relative = plan_dir.absolute().relative_to(root.absolute()).as_posix()
    mutable_allowed = (
        plan_relative,
        ".megaplan/initiatives/critique-ledger-safe-v3-canary/receipts",
    )
    schema_paths = set(_ZERO_RECOVERY_SCHEMA_PATHS)
    engine_runtime_paths = set(_ZERO_RECOVERY_ENGINE_RUNTIME_PATHS)
    allowed_ancestors = {
        parent.as_posix()
        for value in (
            *mutable_allowed,
            *_ZERO_RECOVERY_SCHEMA_PATHS,
            *_ZERO_RECOVERY_ENGINE_RUNTIME_PATHS,
            _ZERO_RECOVERY_EPIC_JOURNAL_DIR,
        )
        for parent in Path(value).parents
        if parent.as_posix() != "."
    }
    tracked: dict[str, Any] = {}
    for entry in tracked_index:
        relative = entry["path"]
        tracked[relative] = _zero_recovery_file_record(
            root / relative, trusted_uid=trusted_uid
        )
        tracked[relative]["git_mode"] = entry["git_mode"]
        tracked[relative]["git_object"] = entry["git_object"]
    runtime_delta: list[dict[str, Any]] = []

    def visit(directory: Path, prefix: str = "") -> None:
        directory_stat = os.lstat(directory)
        if (
            not stat.S_ISDIR(directory_stat.st_mode)
            or stat.S_ISLNK(directory_stat.st_mode)
            or directory_stat.st_uid != trusted_uid
            or directory_stat.st_mode & 0o022
        ):
            raise CliError(
                "zero_recovery_worker_mutation_denied",
                f"source directory custody is unsafe: {prefix or '.'}",
            )
        with os.scandir(directory) as entries:
            children = sorted(entries, key=lambda entry: entry.name)
        for child in children:
            relative = f"{prefix}/{child.name}" if prefix else child.name
            if relative == ".git":
                continue
            item_stat = os.lstat(child.path)
            if stat.S_ISDIR(item_stat.st_mode) and not stat.S_ISLNK(item_stat.st_mode):
                if (
                    relative not in tracked_parents
                    and relative not in allowed_ancestors
                    and relative not in _ZERO_RECOVERY_EMPTY_RUNTIME_DIRS
                    and not any(
                        relative == root_value or relative.startswith(root_value + "/")
                        for root_value in mutable_allowed
                    )
                ):
                    raise CliError(
                        "zero_recovery_worker_mutation_denied",
                        f"forbidden untracked directory: {relative}",
                    )
                visit(Path(child.path), relative)
                continue
            if relative in tracked_paths:
                continue
            if (
                relative not in schema_paths
                and relative not in engine_runtime_paths
                and not any(
                relative == root_value or relative.startswith(root_value + "/")
                for root_value in mutable_allowed
                )
            ):
                raise CliError(
                    "zero_recovery_worker_mutation_denied",
                    f"forbidden untracked path: {relative}",
                )
            record = _zero_recovery_file_record(
                Path(child.path), trusted_uid=trusted_uid
            )
            runtime_delta.append({"path": relative, **record})

    visit(root)
    schema_runtime = [
        item for item in runtime_delta if item["path"] in schema_paths
    ]
    if (
        [item["path"] for item in schema_runtime]
        != list(_ZERO_RECOVERY_SCHEMA_PATHS)
        or any(item["kind"] != "file" for item in schema_runtime)
    ):
        raise CliError(
            "zero_recovery_worker_mutation_denied",
            "canonical runtime schema set is incomplete",
        )
    engine_runtime = _zero_recovery_observe_engine_runtime(
        root, trusted_uid=trusted_uid
    )
    git_metadata = _zero_recovery_git_metadata(root, trusted_uid=trusted_uid)
    return {
        "head": head,
        "tree": tree,
        "tracked_index": tracked_index,
        "tracked": tracked,
        "git_metadata": git_metadata,
        "runtime_delta": runtime_delta,
        "schema_runtime": schema_runtime,
        "engine_runtime": engine_runtime,
    }


def _zero_recovery_source_identity(
    root: Path, plan_dir: Path
) -> dict[str, Any] | None:
    if os.getenv("MEGAPLAN_ZERO_RECOVERY_CANARY") != "1":
        return None
    git_env = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }

    def output(argv: list[str]) -> str:
        result = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", *argv],
            cwd=root, env=git_env, capture_output=True, text=True, check=True
        )
        return result.stdout.strip()

    head = output(["rev-parse", "HEAD"])
    tree = output(["rev-parse", "HEAD^{tree}"])
    for argv in (
        ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "diff", "--quiet", "HEAD", "--"],
        ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "diff", "--cached", "--quiet", "HEAD", "--"],
    ):
        if subprocess.run(argv, cwd=root, env=git_env, check=False).returncode != 0:
            raise CliError(
                "zero_recovery_worker_mutation_denied",
                "model altered tracked source or index state",
            )
    staged = subprocess.run(
        [
            "git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
            "ls-files", "--stage", "-z",
        ],
        cwd=root, env=git_env, capture_output=True, check=True,
    ).stdout
    tracked_index: list[dict[str, str]] = []
    for raw_entry in staged.split(b"\0"):
        if not raw_entry:
            continue
        metadata, raw_path = raw_entry.split(b"\t", 1)
        git_mode, git_object, stage = metadata.decode("ascii").split(" ")
        relative = raw_path.decode("utf-8", errors="strict")
        if stage != "0" or Path(relative).as_posix() != relative or ".." in Path(relative).parts:
            raise CliError(
                "zero_recovery_worker_mutation_denied", "invalid tracked index entry"
            )
        tracked_index.append(
            {"path": relative, "git_mode": git_mode, "git_object": git_object}
        )
    return _zero_recovery_direct_source_manifest(
        root, plan_dir, tracked_index=tracked_index, head=head, tree=tree
    )


def _assert_zero_recovery_source_unchanged(
    root: Path, plan_dir: Path, before: dict[str, Any] | None
) -> dict[str, Any] | None:
    if before is None:
        return
    after = _zero_recovery_direct_source_manifest(
        root,
        plan_dir,
        tracked_index=before["tracked_index"],
        head=before["head"],
        tree=before["tree"],
    )
    changed: list[str] = []
    if after["tracked"] != before["tracked"]:
        changed.append("tracked_source")
    if after["git_metadata"] != before["git_metadata"]:
        changed.append("git_control_metadata")
    if after["schema_runtime"] != before["schema_runtime"]:
        before_schemas = {
            item["path"]: (item["mode"], item["sha256"])
            for item in before["schema_runtime"]
        }
        after_schemas = {
            item["path"]: (item["mode"], item["sha256"])
            for item in after["schema_runtime"]
        }
        schema_changes = sorted(
            path
            for path in set(before_schemas) | set(after_schemas)
            if before_schemas.get(path) != after_schemas.get(path)
        )
        schema_evidence = []
        for path in schema_changes[:8]:
            prior = before_schemas.get(path)
            current = after_schemas.get(path)
            prior_text = (
                "absent"
                if prior is None
                else f"{prior[0]:04o}:{prior[1][:12]}"
            )
            current_text = (
                "absent"
                if current is None
                else f"{current[0]:04o}:{current[1][:12]}"
            )
            schema_evidence.append(f"{path}({prior_text}->{current_text})")
        changed.append("runtime_schema:" + ",".join(schema_evidence))
    if changed:
        raise CliError(
            "zero_recovery_worker_mutation_denied",
            "model changed admitted source identity: " + " | ".join(changed),
        )
    _zero_recovery_validate_engine_runtime_transition(
        before["engine_runtime"], after["engine_runtime"]
    )
    return after


def _zero_recovery_plan_snapshot(
    root: Path,
    plan_dir: Path,
    *,
    output_path: Path,
) -> dict[str, str] | None:
    """Hash every plan artifact the finite-model process is forbidden to alter."""
    if os.getenv("MEGAPLAN_ZERO_RECOVERY_CANARY") != "1":
        return None
    plan_root = plan_dir.resolve()
    output = output_path.absolute()
    privilege_receipt = (
        output.parent
        / output.name.replace("-worker-output.json", "-privilege-receipt.json")
    )
    if plan_dir.absolute() != plan_root or output.parent != plan_root:
        raise CliError(
            "zero_recovery_worker_output_invalid",
            "finite canary worker output parent must be the exact plan directory",
        )
    snapshot: dict[str, str] = {}
    receipt_dir = (
        root
        / ".megaplan/initiatives/critique-ledger-safe-v3-canary/receipts"
    )
    trusted_uid = os.geteuid()
    for prefix, boundary in (("plan", plan_dir), ("receipts", receipt_dir)):
        boundary_stat = os.lstat(boundary)
        if (
            not stat.S_ISDIR(boundary_stat.st_mode)
            or stat.S_ISLNK(boundary_stat.st_mode)
            or boundary_stat.st_uid != trusted_uid
            or boundary_stat.st_mode & 0o022
        ):
            raise CliError(
                "zero_recovery_worker_mutation_denied",
                f"{prefix} boundary is not trusted-owner non-writable",
            )
        for candidate in boundary.rglob("*"):
            candidate_stat = os.lstat(candidate)
            if (
                candidate_stat.st_uid != trusted_uid
                or (
                    not stat.S_ISLNK(candidate_stat.st_mode)
                    and candidate_stat.st_mode & 0o022
                )
            ):
                raise CliError(
                    "zero_recovery_worker_mutation_denied",
                    f"{prefix} artifact permissions are unsafe: {candidate.name}",
                )
            if stat.S_ISDIR(candidate_stat.st_mode) and not stat.S_ISLNK(candidate_stat.st_mode):
                continue
            if prefix == "plan" and candidate.absolute() in {output, privilege_receipt}:
                continue
            relative = candidate.relative_to(boundary).as_posix()
            if stat.S_ISLNK(candidate_stat.st_mode):
                data = os.readlink(candidate).encode()
            elif stat.S_ISREG(candidate_stat.st_mode) and candidate_stat.st_nlink == 1:
                data = candidate.read_bytes()
            else:
                raise CliError(
                    "zero_recovery_worker_mutation_denied",
                    f"unsupported {prefix} artifact at worker boundary: {relative}",
                )
            snapshot[f"{prefix}/{relative}"] = hashlib.sha256(data).hexdigest()
    return snapshot


def _assert_zero_recovery_plan_unchanged(
    root: Path,
    plan_dir: Path,
    *,
    output_path: Path,
    before: dict[str, str] | None,
) -> None:
    if before is None:
        return
    try:
        output_stat = os.lstat(output_path)
    except FileNotFoundError:
        output_stat = None
    if output_stat is not None and (
        not stat.S_ISREG(output_stat.st_mode) or output_stat.st_nlink != 1
    ):
        raise CliError(
            "zero_recovery_worker_mutation_denied",
            "model output path is not a single-link no-follow regular file",
        )
    after = _zero_recovery_plan_snapshot(
        root, plan_dir, output_path=output_path
    )
    if after != before:
        changed = sorted(set(before) ^ set(after or {}))
        for path in sorted(set(before) & set(after or {})):
            if before[path] != (after or {})[path]:
                changed.append(path)
        raise CliError(
            "zero_recovery_worker_mutation_denied",
            "model altered forbidden plan artifacts: " + ", ".join(changed[:8]),
        )


def _verify_zero_recovery_worker_boundaries(
    *,
    root: Path,
    plan_dir: Path,
    output_path: Path,
    runtime: dict[str, Any] | None,
    schema_grant: dict[str, Any] | None,
    source_before: dict[str, Any] | None,
    plan_before: dict[str, str] | None,
) -> None:
    errors: list[str] = []
    try:
        _finish_zero_recovery_model_runtime(
            runtime,
            output_path=output_path,
            on_process_empty=lambda: _restore_zero_recovery_schema_input(
                schema_grant
            ),
        )
    except BaseException as exc:
        errors.append(f"{type(exc).__name__}:{str(exc)}")
    for check in (
        lambda: _assert_zero_recovery_source_unchanged(root, plan_dir, source_before),
        lambda: _assert_zero_recovery_plan_unchanged(
            root, plan_dir, output_path=output_path, before=plan_before
        ),
    ):
        try:
            check()
        except BaseException as exc:
            errors.append(f"{type(exc).__name__}:{str(exc)}")
    if errors:
        raise CliError(
            "zero_recovery_worker_mutation_denied",
            "finite model boundary failed: " + " | ".join(errors),
        )


def _record_zero_recovery_dispatch(
    plan_dir: Path,
    *,
    step: str,
    agent: str,
    model: str | None,
    effort: str | None,
    plan_iteration: int,
) -> dict[str, Any] | None:
    """Append the sole permitted model dispatch before crossing its boundary."""
    if os.getenv("MEGAPLAN_ZERO_RECOVERY_CANARY") != "1":
        return None
    if step not in _ZERO_RECOVERY_MODEL_PHASES:
        raise CliError(
            "zero_recovery_dispatch_denied",
            f"model dispatch is not permitted for zero-recovery step {step!r}",
        )
    if os.getenv("MEGAPLAN_USE_AGENT_DISPATCHER") == "1":
        raise CliError(
            "zero_recovery_dispatch_denied",
            "adaptive agent dispatcher is forbidden for the finite canary",
        )
    if agent != "codex" or model != "gpt-5.6-sol" or effort != "high":
        raise CliError(
            "zero_recovery_dispatch_denied",
            "finite canary dispatch did not match the admitted Codex model pin",
        )
    if plan_iteration < 1:
        raise CliError(
            "zero_recovery_dispatch_denied",
            "finite canary dispatch requires a positive trusted plan iteration",
        )
    ledger_path = plan_dir / "zero_recovery_dispatch_ledger.ndjson"
    prior_records: list[dict[str, Any]] = []
    if ledger_path.is_file():
        try:
            prior_records = [
                json.loads(line)
                for line in ledger_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CliError(
                "zero_recovery_dispatch_denied",
                "finite canary dispatch ledger is unreadable",
            ) from exc
    if len(prior_records) % 2 != 0 or any(
        prior_records[index].get("event") != "start"
        or prior_records[index + 1].get("event") != "terminal"
        or prior_records[index].get("dispatch_id")
        != prior_records[index + 1].get("dispatch_id")
        for index in range(0, len(prior_records), 2)
    ):
        raise CliError(
            "zero_recovery_dispatch_denied",
            "finite canary dispatch ledger has an unterminated or unordered pair",
        )
    if any(
        record.get("event") == "start"
        and record.get("phase") == step
        and record.get("plan_iteration") == plan_iteration
        for record in prior_records
    ):
        raise CliError(
            "zero_recovery_redispatch_denied",
            f"a second {step} dispatch for plan iteration {plan_iteration} "
            "was rejected before provider invocation",
        )
    dispatch_ordinal = len(prior_records) // 2 + 1
    artifact_stem = (
        f".zero-recovery-{dispatch_ordinal:02d}-{step}-i{plan_iteration}"
    )
    lock_path = plan_dir / f"{artifact_stem}-dispatch.lock"
    try:
        lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise CliError(
            "zero_recovery_redispatch_denied",
            f"a second {step} dispatch was rejected before provider invocation",
        ) from exc
    with os.fdopen(lock_fd, "w", encoding="utf-8") as lock:
        lock.write("single-dispatch\n")
        lock.flush()
        os.fsync(lock.fileno())
    record: dict[str, Any] = {
        "schema": "arnold.megaplan.zero_recovery_dispatch.v2",
        "event": "start",
        "dispatch_id": uuid.uuid4().hex,
        "phase": step,
        "selected_agent": agent,
        "selected_model": model,
        "selected_effort": effort,
        "model_cli_argv": ["-c", "model='gpt-5.6-sol'"],
        "attempt": 1,
        "plan_iteration": plan_iteration,
        "dispatch_ordinal": dispatch_ordinal,
        "retry": False,
        "fallback": False,
        "json_repair": False,
        "adaptive_routing": False,
        "recorded_at": now_utc(),
    }
    ledger_fd = os.open(ledger_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(ledger_fd, "a", encoding="utf-8") as ledger:
        ledger.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        ledger.flush()
        os.fsync(ledger.fileno())
    return record


def _record_zero_recovery_dispatch_terminal(
    plan_dir: Path,
    *,
    start: dict[str, Any] | None,
    worker: WorkerResult,
) -> None:
    if start is None:
        return
    actual_model = getattr(worker, "model_actual", None)
    model_evidence = getattr(worker, "model_evidence", None)
    privilege_receipt_path = getattr(worker, "privilege_receipt_path", None)
    privilege_receipt_sha256 = getattr(worker, "privilege_receipt_sha256", None)
    rollout_path = getattr(worker, "rollout_path", None)
    rollout_sha256 = getattr(worker, "rollout_sha256", None)
    if (
        actual_model != start["selected_model"]
        or model_evidence != "codex_cli_turn_context"
        or not isinstance(privilege_receipt_path, str)
        or not isinstance(privilege_receipt_sha256, str)
        or not isinstance(rollout_path, str)
        or not isinstance(rollout_sha256, str)
    ):
        raise CliError(
            "zero_recovery_dispatch_denied",
            "sealed Codex CLI evidence did not match the admitted model boundary",
        )
    record = {
        "schema": "arnold.megaplan.zero_recovery_dispatch.v2",
        "event": "terminal",
        "dispatch_id": start["dispatch_id"],
        "phase": start["phase"],
        "actual_agent": start["selected_agent"],
        "actual_model": actual_model,
        "model_evidence": model_evidence,
        "privilege_receipt_path": privilege_receipt_path,
        "privilege_receipt_sha256": privilege_receipt_sha256,
        "rollout_path": rollout_path,
        "rollout_sha256": rollout_sha256,
        "actual_effort": start["selected_effort"],
        "attempt": start["attempt"],
        "plan_iteration": start["plan_iteration"],
        "dispatch_ordinal": start["dispatch_ordinal"],
        "retry": False,
        "fallback": False,
        "json_repair": False,
        "adaptive_routing": False,
        "result": "returned",
        "recorded_at": now_utc(),
    }
    ledger_fd = os.open(
        plan_dir / "zero_recovery_dispatch_ledger.ndjson",
        os.O_WRONLY | os.O_CREAT | os.O_APPEND,
        0o600,
    )
    with os.fdopen(ledger_fd, "a", encoding="utf-8") as ledger:
        ledger.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        ledger.flush()
        os.fsync(ledger.fileno())


def _active_zero_recovery_dispatch(
    plan_dir: Path, *, step: str
) -> dict[str, Any] | None:
    """Return the trusted unpaired start that owns this worker artifact set."""
    if os.getenv("MEGAPLAN_ZERO_RECOVERY_CANARY") != "1":
        return None
    ledger_path = plan_dir / "zero_recovery_dispatch_ledger.ndjson"
    try:
        records = [
            json.loads(line)
            for line in ledger_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CliError(
            "zero_recovery_dispatch_denied",
            "finite canary active dispatch ledger is unreadable",
        ) from exc
    active = records[-1] if records else None
    expected_ordinal = (len(records) + 1) // 2
    if (
        len(records) % 2 != 1
        or not isinstance(active, dict)
        or active.get("event") != "start"
        or active.get("phase") != step
        or active.get("dispatch_ordinal") != expected_ordinal
        or not isinstance(active.get("plan_iteration"), int)
        or active["plan_iteration"] < 1
    ):
        raise CliError(
            "zero_recovery_dispatch_denied",
            "finite canary worker has no matching trusted active dispatch",
        )
    return active

# Shared mapping from step name to schema filename, used by both
# run_claude_step and run_codex_step.
# Built from the authoritative StepContract registry.
from arnold_pipelines.megaplan.step_contracts import (
    build_capture_schema_keys_by_step,
    build_step_schema_filenames,
)

STEP_SCHEMA_FILENAMES: dict[str, str] = build_step_schema_filenames()
STEP_CAPTURE_SCHEMA_FILENAMES: dict[str, str] = build_capture_schema_keys_by_step()

# Derive required keys per step from SCHEMAS so they aren't duplicated.
_STEP_REQUIRED_KEYS: dict[str, list[str]] = {
    step: SCHEMAS.get(
        filename
        if step == "execute"
        else STEP_CAPTURE_SCHEMA_FILENAMES.get(step, filename),
        {},
    ).get("required", [])
    for step, filename in STEP_SCHEMA_FILENAMES.items()
}
_RETIRED_VALIDATE_PAYLOAD_STEPS = frozenset({
    "finalize", "critique", "review", "gate",
    "plan", "prep", "prep-triage", "prep-research", "prep-distill",
    "feedback", "critique_evaluator", "revise",
    "loop_plan", "loop_execute", "tiebreaker_researcher", "tiebreaker_challenger",
    "execute",
})


def _project_local_tmp_dir(base: Path) -> Path:
    """Return a writable temp directory inside the project tree.

    Codex's read-only sandbox is scoped to the repo root, so prompt and output
    temp files passed via ``@/path`` must live under ``base`` (typically the
    project root or the plan directory) rather than the system temp directory.
    """
    tmp = base / ".megaplan" / "worker_tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    return tmp


def _normalize_stdin_text(stdin_text: str | None) -> str | None:
    """Read prompt-file contents when a worker is handed a file path.

    The codex path accepts prompt text via stdin. Some callers hand that seam a
    temp-file path containing the real prompt; if the path string reaches the
    model verbatim, the worker sees only a filename. When *stdin_text* names an
    existing file, read and return its contents instead.
    """
    if stdin_text is None:
        return None
    candidate = stdin_text.strip()
    if not candidate or "\n" in candidate or "\r" in candidate:
        return stdin_text
    try:
        path = Path(candidate).expanduser()
    except (TypeError, ValueError):
        return stdin_text
    if not path.is_file():
        return stdin_text
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return stdin_text


@dataclass
class CommandResult:
    command: list[str]
    cwd: Path
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int
    worker_identity: dict[str, Any] | None = None


@dataclass
class SpawnCleanupHold:
    """Process-local handoff for a child whose admission could not certify it.

    Registration happens after ``Popen`` because the child PID and start
    identity are needed for the certificate.  If that certification fails,
    the child cannot be signaled by this layer: it has no admitted authority.
    Keep the handle and immutable identity in a typed, bounded reconciliation
    object instead of abandoning it or attempting a raw kill.
    """

    process: Any = field(repr=False)
    pid: int
    process_start_identity: str | None
    admission_error: str
    execution_context: dict[str, Any] | None
    worker_identity: dict[str, Any] | None = None
    spawn_event_id: str | None = None
    dispatch_outcome: dict[str, Any] | None = None
    reconciliation_route: str = "worker-dispatch.spawn-registration-reconcile.v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": "cleanup_hold",
            "pid": self.pid,
            "process_start_identity": self.process_start_identity,
            "admission_error": self.admission_error,
            "execution_context": self.execution_context,
            "worker_identity": self.worker_identity,
            "spawn_event_id": self.spawn_event_id,
            "dispatch_outcome": self.dispatch_outcome,
            "reconciliation_route": self.reconciliation_route,
        }

    def reconcile(self, *, timeout_s: float = 0.0) -> dict[str, Any]:
        """Poll/reap with a small bounded wait; never signal the child."""
        try:
            bounded = min(max(float(timeout_s), 0.0), 5.0)
        except (TypeError, ValueError):
            bounded = 0.0
        returncode = self.process.poll()
        if returncode is None and bounded:
            try:
                returncode = self.process.wait(timeout=bounded)
            except (subprocess.TimeoutExpired, TimeoutError):
                returncode = self.process.poll()
        state = "reaped" if returncode is not None else "live"
        return {
            "state": state,
            "pid": self.pid,
            "returncode": returncode,
            "process_start_identity": self.process_start_identity,
            "reconciliation_route": self.reconciliation_route,
        }


class SpawnRegistrationError(CliError):
    """Typed unresolved custody error for failed post-spawn admission."""

    def __init__(
        self,
        cause: BaseException,
        *,
        cleanup_hold: SpawnCleanupHold,
        cleanup_result: Mapping[str, Any],
    ) -> None:
        self.cause = cause
        self.cleanup_hold = cleanup_hold
        self.cleanup_result = dict(cleanup_result)
        self.dispatch_outcome = cleanup_hold.dispatch_outcome
        super().__init__(
            "worker_spawn_unresolved",
            "spawned worker admission failed; child handed off for bounded reconciliation",
            extra={
                "spawn_cleanup_hold": cleanup_hold.to_dict(),
                "dispatch_outcome": cleanup_hold.dispatch_outcome,
                "cleanup_result": dict(cleanup_result),
                "admission_error_type": type(cause).__name__,
                "admission_error": str(cause),
            },
        )

ProgressLivenessState = Literal["progressing", "alive_only", "stalled", "unknown"]
# Inter-event idle bound for the shannon worker (Claude via the shannon CLI).
#
# HISTORY (2026-05-24): shannon was launched with ``--output-format=json``, a
# FULLY BUFFERED format — shannon accumulated the whole turn (init + per-turn
# assistant/result) and wrote ONE ``JSON.stringify([...])`` array to stdout only
# at turn end. With no incremental stdout, the watchdog below (which resets
# ``last_output`` only on real stdout/stderr chunks, _impl.py:420) degenerated
# into a coarse total-turn DURATION cap: it effectively timed turn-start →
# turn-end. A legitimately long single Opus turn that ran silent past this bound
# was killed as a false ``worker_stall``.
#
# FIX (2026-05-28): shannon is now launched with ``--output-format=stream-json``
# (megaplan/workers/shannon.py), which emits one JSON event per line (NDJSON) AS
# work happens — ``system/init`` after session discovery, optional ``hook_*``
# rows, per-turn ``assistant`` + ``result``, and a trailing ``shannon_session``
# metadata row on cleanup. Each line flushes to stdout, so the watchdog resets
# ``last_output`` on real progress and this value once again behaves as a TRUE
# inter-event idle bound rather than a duration cap. A long legit turn keeps the
# timer reset via incremental events; only a genuinely hung turn (no event for
# the whole window) trips it.
#
# CAVEAT: the bound is only as fine-grained as shannon's event cadence. The
# heaviest gap is WITHIN a single ``waitForAssistantReply`` — shannon polls
# Claude's transcript .jsonl, which is written one row per COMPLETED content
# block, so a single very long thinking/answer block still emits no event until
# it finishes. Real transcripts show within-block gaps up to ~363s.
#
# TIGHTENED (2026-05-29): the shannon ``liveness_probe`` now treats Claude's
# transcript .jsonl mtime as the trusted progress signal (it advances as content
# blocks/tool events flush, INCLUDING mid-turn — finer-grained than the NDJSON
# events on stdout), and NO LONGER counts tmux pane churn as progress. Because a
# healthy slow turn keeps the idle clock reset via that transcript-mtime probe,
# the raw inter-event bound no longer needs ~2.5x headroom over the worst-case
# within-block gap. A WEDGED Claude (stalled SSE — sockets ESTABLISHED, 0% CPU)
# repaints its pane but writes NO transcript, so the probe correctly reads it as
# idle; lowering the bound from 900s to 300s makes such a wedge fail fast
# (~5 min) and retry instead of burning ~15 min per turn. 300s still sits below
# the 363s observed within-block gap only when the transcript is genuinely
# static for that long, which the probe distinguishes from a hang. Override via
# SHANNON_STREAM_READ_TIMEOUT.
DEFAULT_WORKER_STREAM_IDLE_TIMEOUT_SECONDS = 300.0

# Guaranteed backstop for the liveness-probe rescue path (_impl.py run_command).
#
# THREE-CHANNEL LIVENESS MODEL (2026-06-10). The shannon ``liveness_probe`` no
# longer treats "silence == death". Silence is ambiguous: a healthy turn is
# legitimately silent while (a) running a long synchronous tool call (a 10-20 min
# ``pytest``) — Claude emits nothing and the transcript does not grow; or (b)
# thinking server-side for minutes — no tokens surfaced yet. A genuine wedge
# (stalled SSE: sockets ESTABLISHED, 0% CPU, receiving nothing) ALSO looks
# silent. Conflating these false-killed healthy turns. The probe now samples
# THREE independent channels and treats the turn as ALIVE if ANY advanced since
# the last sample, WEDGED only if ALL THREE are flat continuously for the idle
# window K (``SHANNON_STREAM_READ_TIMEOUT``, default 300s):
#   1. transcript .jsonl mtime/size advanced  (catches normal token streaming);
#   2. process-subtree CPU-time advanced       (catches the silent tool call);
#   3. API socket recv-bytes advanced          (catches the silent thinking).
# See ``build_three_channel_liveness_probe`` below and
# ``shannon._make_shannon_liveness_probe`` for the concrete samplers. Silence on
# its own NEVER kills; only all-three-flat-for-K does.
#
# Two distinct backstops still exist BELOW the three channels:
#
# ``DEFAULT_PROBE_RESCUE_CAP_SECONDS`` / ``SHANNON_PROBE_RESCUE_CAP_SECONDS`` —
# caps how long a turn that has produced ZERO real stdout/stderr may be kept
# alive by probe rescues alone, INDEPENDENT of the probe, in case the probe's
# signals are all unreadable (e.g. it globs the wrong project dir, or ps/nettop
# are missing). NDJSON events from a healthy shannon turn reset the real-output
# clock, so this only fires on a genuinely stdout-silent turn. It is RESET by
# real output, so it is NOT an absolute cap — see the next one.
DEFAULT_PROBE_RESCUE_CAP_SECONDS = 600.0

# Hard absolute per-turn backstop. This is intentionally much larger than the
# idle/probe rescue caps: it only bounds a genuinely runaway turn that keeps at
# least one liveness channel hot forever.
DEFAULT_TURN_HARD_CAP_SECONDS = 5400.0

DEFAULT_CODEX_EXECUTOR_SESSION_HEADROOM_TOKENS = 1_000_000
CODEX_EXECUTOR_SESSION_HEADROOM_ENV = "MEGAPLAN_CODEX_EXECUTOR_SESSION_HEADROOM_TOKENS"


def _worker_stream_idle_timeout_seconds() -> float:
    """Inter-event idle bound (seconds) for the shannon worker.

    With shannon on ``--output-format=stream-json`` (see the constant comment
    above) this is a genuine inter-event idle bound: incremental NDJSON events
    reset the watchdog, so it only trips when shannon emits NO event for the
    whole window (a hung turn or a >window within-block gap). Configurable via
    ``SHANNON_STREAM_READ_TIMEOUT``. Defaults to 5 min — the transcript-mtime
    liveness probe keeps a healthy slow turn's idle clock reset mid-turn, so a
    wedged turn (no transcript growth) fails fast and retries instead of burning
    the old 15 min window. Clamped to a sane floor.
    """
    try:
        value = float(os.getenv(
            "SHANNON_STREAM_READ_TIMEOUT",
            DEFAULT_WORKER_STREAM_IDLE_TIMEOUT_SECONDS,
        ))
    except (TypeError, ValueError):
        value = DEFAULT_WORKER_STREAM_IDLE_TIMEOUT_SECONDS
    # Never allow a sub-30s idle bound that could abort a healthy slow tool turn.
    return max(value, 30.0)


def _probe_rescue_cap_seconds() -> float:
    """Max wall-clock seconds a stdout-silent turn may be kept alive by probe
    rescues alone (see ``DEFAULT_PROBE_RESCUE_CAP_SECONDS``).

    Configurable via ``SHANNON_PROBE_RESCUE_CAP_SECONDS``. Clamped to a generous
    floor so it can never undercut a legitimately long probe-rescued turn (or the
    short silent workers the idle-timeout tests rely on) — its sole job is to kill
    a pathological wedge whose probe signal is unreadable, not to second-guess a
    working probe.
    """
    try:
        value = float(os.getenv(
            "SHANNON_PROBE_RESCUE_CAP_SECONDS",
            DEFAULT_PROBE_RESCUE_CAP_SECONDS,
        ))
    except (TypeError, ValueError):
        value = DEFAULT_PROBE_RESCUE_CAP_SECONDS
    return max(value, 120.0)


def _turn_hard_cap_seconds() -> float:
    """Hard ABSOLUTE per-turn wall-clock cap (see ``DEFAULT_TURN_HARD_CAP_SECONDS``).

    INDEPENDENT of the three-channel probe and the rescue cap; never reset by any
    signal. Stops an INFINITE run (e.g. a ``pytest`` stuck in an infinite loop
    keeping the CPU channel hot forever) even when the channels correctly report
    the turn as "alive". Configurable via ``SHANNON_TURN_HARD_CAP_SECONDS``.
    Clamped to a generous floor so it can never undercut a legitimately long
    test-plus-thinking turn — its sole job is to bound a genuine runaway.
    """
    try:
        value = float(os.getenv(
            "SHANNON_TURN_HARD_CAP_SECONDS",
            DEFAULT_TURN_HARD_CAP_SECONDS,
        ))
    except (TypeError, ValueError):
        value = DEFAULT_TURN_HARD_CAP_SECONDS
    # Floor: comfortably above the test_baseline_timeout default (3600s) so a
    # legitimate large test run plus thinking is never cut short.
    return max(value, 3600.0)


def build_three_channel_liveness_probe(
    *,
    transcript_sample: Callable[[], float | int | None],
    cpu_sample: Callable[[], float | int | None],
    socket_sample: Callable[[], float | int | None],
) -> Callable[[], bool]:
    """Compose three independent activity samplers into one liveness probe.

    This is the COMBINING / DECISION half of the three-channel liveness model —
    deliberately separated from the concrete samplers so it is unit-testable
    WITHOUT a live ``claude`` process, live sockets, or ``ps``/``nettop``. Each
    sampler returns a monotone-comparable token (a counter / mtime / byte total)
    or ``None`` when that channel is unreadable RIGHT NOW.

    Returned probe semantics (matches ``run_command``'s ``liveness_probe``
    contract: ``True`` == "alive, reset the idle clock", ``False`` == "wedged,
    proceed to kill"):

    * First call primes the baselines and returns ``True`` (no comparison yet).
    * On each later call a channel is "active" iff its token is readable now AND
      STRICTLY GREATER than its last readable value. The turn is ALIVE if ANY of
      the three channels is active.
    * The turn is WEDGED (``False``) only when ALL THREE channels are FLAT — i.e.
      every readable channel's token is unchanged. Because ``run_command`` only
      consults the probe after the idle window K has elapsed with no real output,
      a ``False`` here means all three were flat continuously across K → kill.
    * GRACEFUL DEGRADATION: a channel that returns ``None`` (tool unavailable,
      e.g. ``nettop`` missing, or no transcript yet) is "unknown", NOT "flat". A
      sample that raises is also treated as unknown. If EVERY channel is unknown
      we cannot prove a wedge, so we return ``True`` (defer to the rescue cap /
      hard cap / wall-clock ``timeout``) — a missing tool can never cause a false
      kill. Once a channel becomes readable its baseline is (re)established so the
      first readable sample is not mistaken for "advanced".
    """
    last: dict[str, float] = {}
    primed = [False]

    def _sample(name: str, fn: Callable[[], float | int | None]) -> float | None:
        try:
            value = fn()
        except Exception:
            return None
        if value is None:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _probe() -> bool:
        samples = {
            "transcript": _sample("transcript", transcript_sample),
            "cpu": _sample("cpu", cpu_sample),
            "socket": _sample("socket", socket_sample),
        }

        if not primed[0]:
            for name, value in samples.items():
                if value is not None:
                    last[name] = value
            primed[0] = True
            return True

        any_active = False
        any_readable = False
        for name, value in samples.items():
            if value is None:
                # Unknown right now — neither active nor flat. Do not update the
                # baseline so a transient read failure can't swallow real growth.
                continue
            any_readable = True
            prev = last.get(name)
            if prev is None:
                # Channel just became readable; establish its baseline. Not
                # counted as activity (no prior value to advance from).
                last[name] = value
                continue
            if value > prev:
                any_active = True
            # Advance the high-water mark monotonically (never regress on a
            # transient lower read, e.g. a transcript rotation).
            if value > prev:
                last[name] = value

        if any_active:
            return True
        if not any_readable:
            # No channel could be read at all — cannot prove a wedge. Stay
            # conservative; the rescue cap / hard cap / wall-clock timeout bound
            # a genuinely dead turn so this never hangs forever.
            return True
        # At least one channel readable and ALL readable channels flat → wedged.
        return False

    return _probe


def _ps_children(pid: str) -> list[str]:
    """Return the direct child PIDs of *pid* via ``ps`` (portable; macOS+Linux)."""
    try:
        result = subprocess.run(
            ["ps", "-o", "pid=,ppid="],
            check=False,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, OSError):
        return []
    if result.returncode != 0:
        return []
    children: list[str] = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        child, parent = parts
        if parent == pid:
            children.append(child)
    return children


def _process_tree_pids(roots: list[str], *, max_pids: int = 256) -> list[str]:
    """BFS the process subtree rooted at each pid in *roots* (descendants too)."""
    seen: list[str] = []
    seen_set: set[str] = set()
    frontier = [pid for pid in roots if pid]
    while frontier and len(seen) < max_pids:
        pid = frontier.pop()
        if pid in seen_set:
            continue
        seen_set.add(pid)
        seen.append(pid)
        frontier.extend(_ps_children(pid))
    return seen


def _cputime_to_seconds(raw: str) -> float | None:
    """Parse a ``ps`` ``cputime`` field (``[[DD-]HH:]MM:SS[.ss]``) to seconds."""
    raw = raw.strip()
    if not raw or raw == "-":
        return None
    days = 0
    if "-" in raw:
        day_str, _, raw = raw.partition("-")
        try:
            days = int(day_str)
        except ValueError:
            days = 0
    parts = raw.split(":")
    try:
        nums = [float(part) for part in parts]
    except ValueError:
        return None
    seconds = 0.0
    for value in nums:
        seconds = seconds * 60 + value
    return seconds + days * 86400.0


def _subtree_cputime_sample(roots: list[str]) -> float | None:
    """Return cumulative CPU time (seconds) consumed by the subtree of *roots*."""
    pids = _process_tree_pids(roots)
    if not pids:
        return None
    try:
        result = subprocess.run(
            ["ps", "-o", "pid=,cputime="],
            check=False,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, OSError):
        return None
    if result.returncode != 0:
        return None
    pid_set = set(pids)
    total = 0.0
    saw_any = False
    for line in result.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        pid, cputime = parts
        if pid not in pid_set:
            continue
        seconds = _cputime_to_seconds(cputime)
        if seconds is None:
            continue
        saw_any = True
        total += seconds
    return total if saw_any else None


def _path_progress_signal(path: Path | None) -> tuple[int, int] | None:
    """Return a monotone-comparable progress signal for *path* when readable."""
    if path is None:
        return None
    try:
        stat = path.stat()
    except OSError:
        return None
    return (max(int(stat.st_mtime_ns), 0), int(stat.st_size))


@dataclass
class CodexProgressLiveness:
    """Progress classifier for Codex turns that go silent during tool work.

    Execute turns often enter a long foreground tool call (`pytest`, build,
    shell script) after Codex has already emitted the JSON trace row that
    started the tool. During that window the Codex parent process can remain
    stdout-silent for many minutes even though the subprocess tree is actively
    working. Without a secondary progress signal the idle-output watchdog turns
    into a false total-turn cap.

    We treat the turn as `progressing` when any of these cheap local signals
    advances since the last probe:

    - the structured output file grows;
    - the Codex rollout JSONL grows (after `thread.started` reveals the session);
    - the Codex subprocess tree accumulates CPU time.

    A live child with readable but flat signals is only `alive_only` so
    `run_command` applies its grace cap. A dead child is `stalled`.
    """

    output_path: Path
    # Review is read-only and normally short.  Unlike execute, a review must
    # not let a spinning Codex/node process masquerade as useful work forever:
    # its JSON trace/rollout/output file are the authoritative evidence that
    # the model is actually advancing.  Execute keeps CPU sampling because a
    # legitimate long-running tool can be stdout-silent for minutes.
    include_cpu_signal: bool = True

    session_id: str | None = None
    _stdout_buffer: str = ""
    _child_pid: str | None = None
    _child_alive: Callable[[], bool] | None = None
    _last_output_signal: tuple[int, int] | None = None
    _last_rollout_signal: tuple[int, int] | None = None
    _last_cpu_signal: float | None = None

    def bind_process(self, process: Any) -> Callable[[], ProgressLivenessState]:
        try:
            pid = getattr(process, "pid", None)
        except Exception:
            pid = None
        self._child_pid = str(pid) if pid is not None else None
        self._child_alive = lambda: process.poll() is None
        return self.probe

    def activity_guard(self, kind: str, text: str) -> None:
        """Observe stdout JSONL so the probe can discover the Codex session id."""
        if kind != "stdout" or not text:
            return
        self._stdout_buffer += text
        lines = self._stdout_buffer.splitlines(keepends=True)
        if lines and not lines[-1].endswith(("\n", "\r")):
            self._stdout_buffer = lines.pop()
        else:
            self._stdout_buffer = ""
        for line in lines:
            stripped = line.strip()
            if not stripped.startswith("{"):
                continue
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and payload.get("thread_id"):
                self.session_id = str(payload["thread_id"])

    def _sample_rollout_signal(self) -> tuple[int, int] | None:
        if not self.session_id:
            return None
        return _path_progress_signal(_codex_session_jsonl_path(self.session_id))

    def _sample_cpu_signal(self) -> float | None:
        if not self._child_pid:
            return None
        return _subtree_cputime_sample([self._child_pid])

    def _observe(
        self,
        current: Any | None,
        attr_name: str,
    ) -> tuple[bool, bool]:
        if current is None:
            return False, False
        previous = getattr(self, attr_name)
        if previous is None:
            setattr(self, attr_name, current)
            return True, False
        if current > previous:
            setattr(self, attr_name, current)
            return True, True
        return True, False

    def probe(self) -> ProgressLivenessState:
        readable = False
        progressing = False

        signals: list[tuple[Any | None, str]] = [
            (_path_progress_signal(self.output_path), "_last_output_signal"),
            (self._sample_rollout_signal(), "_last_rollout_signal"),
        ]
        if self.include_cpu_signal:
            signals.append((self._sample_cpu_signal(), "_last_cpu_signal"))
        for current, attr_name in signals:
            signal_readable, signal_progressing = self._observe(current, attr_name)
            readable = readable or signal_readable
            progressing = progressing or signal_progressing

        if progressing:
            return "progressing"

        if self._child_alive is not None:
            try:
                if not bool(self._child_alive()):
                    return "stalled"
            except Exception:
                return "unknown"

        if readable:
            return "alive_only"
        return "unknown"


def _codex_executor_session_headroom_tokens() -> int:
    raw = os.getenv(CODEX_EXECUTOR_SESSION_HEADROOM_ENV)
    if raw is None:
        return DEFAULT_CODEX_EXECUTOR_SESSION_HEADROOM_TOKENS
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_CODEX_EXECUTOR_SESSION_HEADROOM_TOKENS
    return max(value, 0)


def _codex_total_tokens_from_session(session: dict[str, Any]) -> int | None:
    usage = session.get("last_total_tokens")
    if not isinstance(usage, dict):
        return None
    total = usage.get("total_tokens")
    if total is None:
        total = sum(
            int(usage.get(key, 0) or 0)
            for key in (
                "input_tokens",
                "output_tokens",
                "reasoning_output_tokens",
            )
        )
    try:
        return int(total)
    except (TypeError, ValueError):
        return None


@dataclass
class WorkerResult:
    payload: dict[str, Any]
    raw_output: str
    duration_ms: int
    cost_usd: float
    session_id: str | None = None
    trace_output: str | None = None
    rendered_prompt: str | None = None
    model_actual: str | None = None
    model_evidence: str | None = None
    privilege_receipt_path: str | None = None
    privilege_receipt_sha256: str | None = None
    rollout_path: str | None = None
    rollout_sha256: str | None = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    # ``unpriced`` means usage was observed but no canonical model rate exists;
    # cost_usd remains 0.0 for backward-compatible numeric aggregation.
    cost_pricing: str | None = None
    # Populated by the Shannon worker so the receipt records the rolled
    # session plan (kind, session_id, voice, pre-turn kinds + pre_sleep_s).
    # ``None`` for non-Shannon workers.
    shannon_plan: dict[str, Any] | None = None
    rate_limit: dict[str, Any] | None = None
    worker_channel: str | None = None
    auth_channel: str | None = None
    auth_metadata: dict[str, Any] | None = None
    # Identity captured by the actual worker/process seam.  Keep optional for
    # legacy callers that only returned a payload.
    worker_identity: dict[str, Any] | None = None
    configured_specs: tuple[str, ...] = ()
    attempt_index: int = 0
    attempted_specs: tuple[str, ...] = ()
    failed_attempt_reasons: tuple[str, ...] = ()
    fallback_trigger: str | None = None
    response_enforcement_attestation: dict[str, Any] | None = None

    @classmethod
    def from_agent_result(cls, agent_result: Any) -> WorkerResult:
        """Project a runtime ``AgentResult`` into the worker compatibility type."""
        metadata = getattr(agent_result, "metadata", {}) or {}
        raw_auth_metadata = metadata.get("auth_metadata")
        auth_metadata = (
            dict(raw_auth_metadata) if isinstance(raw_auth_metadata, dict) else raw_auth_metadata
        )
        identity_candidates: list[dict[str, Any]] = []

        def collect_identity(candidate: Any, source: str) -> None:
            if candidate is None:
                return
            if not isinstance(candidate, dict):
                raise ValueError(f"{source} worker_identity must be an object")
            if (
                not isinstance(candidate.get("host"), str)
                or not candidate.get("host")
                or isinstance(candidate.get("pid"), bool)
                or not isinstance(candidate.get("pid"), int)
                or candidate["pid"] <= 0
                or not isinstance(candidate.get("boot_id"), str)
                or not candidate.get("boot_id")
            ):
                raise ValueError(f"{source} worker_identity is malformed")
            identity_candidates.append(dict(candidate))

        collect_identity(metadata.get(_WORKER_IDENTITY_METADATA_KEY), "metadata")
        if isinstance(auth_metadata, dict):
            collect_identity(auth_metadata.get(_WORKER_IDENTITY_METADATA_KEY), "auth_metadata")
            raw_outcome = auth_metadata.get("dispatch_outcome")
            if isinstance(raw_outcome, dict):
                collect_identity(raw_outcome.get("worker_identity"), "dispatch_outcome")
        if identity_candidates and any(item != identity_candidates[0] for item in identity_candidates[1:]):
            raise ValueError("worker identity conflicts across AgentResult metadata")
        worker_identity = identity_candidates[0] if identity_candidates else None
        rate_limit = getattr(agent_result, "rate_limit", None)
        if rate_limit is None:
            rate_limit = metadata.get("rate_limit")
            if not isinstance(rate_limit, dict):
                rate_limit = None
        return cls(
            payload=agent_result.payload,
            raw_output=agent_result.raw_output,
            duration_ms=agent_result.duration_ms,
            cost_usd=agent_result.cost_usd,
            session_id=agent_result.session_id,
            trace_output=agent_result.trace_output,
            rendered_prompt=agent_result.rendered_prompt,
            model_actual=agent_result.model_actual,
            model_evidence=metadata.get("model_evidence"),
            prompt_tokens=agent_result.prompt_tokens,
            completion_tokens=agent_result.completion_tokens,
            total_tokens=agent_result.total_tokens,
            cost_pricing=metadata.get("cost_pricing"),
            shannon_plan=agent_result.shannon_plan,
            rate_limit=rate_limit,
            worker_channel=metadata.get("worker_channel"),
            auth_channel=metadata.get("auth_channel"),
            auth_metadata=auth_metadata,
            worker_identity=worker_identity,
            configured_specs=tuple(metadata.get("configured_specs", ())),
            attempt_index=int(metadata.get("attempt_index", 0) or 0),
            attempted_specs=tuple(metadata.get("attempted_specs", ())),
            failed_attempt_reasons=tuple(metadata.get("failed_attempt_reasons", ())),
            fallback_trigger=metadata.get("fallback_trigger"),
            response_enforcement_attestation=metadata.get(
                "response_enforcement_attestation"
            ),
        )

    def to_agent_result(self) -> Any:
        """Project the worker compatibility type into the runtime ``AgentResult``."""
        from arnold_pipelines.megaplan.agent_runtime import AgentResult

        # Keep the identity in the authenticated metadata envelope as well as
        # the top-level metadata.  The latter is the compatibility carrier for
        # old consumers; the former lets custody-aware consumers validate it
        # without depending on a payload field.  ``setdefault`` deliberately
        # leaves a conflicting embedded value visible to ``from_agent_result``.
        auth_metadata = self.auth_metadata
        if self.worker_identity is not None:
            auth_metadata = dict(auth_metadata or {})
            auth_metadata.setdefault(_WORKER_IDENTITY_METADATA_KEY, self.worker_identity)
        metadata = {
            key: value
            for key, value in {
                "rate_limit": self.rate_limit,
                "worker_channel": self.worker_channel,
                "auth_channel": self.auth_channel,
                "auth_metadata": auth_metadata,
                # Reserved top-level metadata preserves this identity across
                # the AgentResult projection; older results simply omit it.
                _WORKER_IDENTITY_METADATA_KEY: self.worker_identity,
                "cost_pricing": self.cost_pricing,
                "model_evidence": self.model_evidence,
                "configured_specs": list(self.configured_specs),
                "attempt_index": self.attempt_index,
                "attempted_specs": list(self.attempted_specs),
                "failed_attempt_reasons": list(self.failed_attempt_reasons),
                "fallback_trigger": self.fallback_trigger,
                "response_enforcement_attestation": self.response_enforcement_attestation,
            }.items()
            if value is not None
        }
        return AgentResult(
            payload=self.payload,
            raw_output=self.raw_output,
            duration_ms=self.duration_ms,
            cost_usd=self.cost_usd,
            session_id=self.session_id,
            trace_output=self.trace_output,
            rendered_prompt=self.rendered_prompt,
            model_actual=self.model_actual,
            prompt_tokens=self.prompt_tokens,
            completion_tokens=self.completion_tokens,
            total_tokens=self.total_tokens,
            shannon_plan=self.shannon_plan,
            rate_limit=self.rate_limit,
            metadata=metadata,
        )


# ---------------------------------------------------------------------------
# Worker working directory resolution (git-worktree isolation)
#
# When megaplan is invoked from a git worktree, the plan's stored project_dir
# may point at a *different* checkout (usually the main repo). To avoid
# subprocess workers writing source code into the wrong working tree, resolve
# the "working directory" at CLI entry (CWD, or an explicit --work-dir
# override) and pass *that* through to the worker's --add-dir / -C flags.
#
# Plan state files (.megaplan/plans/...) still live under project_dir; only
# the source-code working tree tracked by the subprocess changes.
# ---------------------------------------------------------------------------

_WORK_DIR_OVERRIDE: ContextVar[Path | None] = ContextVar(
    "megaplan_work_dir_override", default=None
)
_WORK_DIR_WARNED: set[Path] = set()
_WORK_DIR_WARNED_LOCK = threading.Lock()


def set_work_dir_override(path: Path | str | None) -> None:
    """Set an explicit working directory for subprocess workers.

    Typically called once from the CLI entry point with either an explicit
    --work-dir value or ``Path.cwd()``. Pass ``None`` to clear the override
    (primarily useful in tests).

    Sets the ContextVar for the current context.
    """
    _WORK_DIR_OVERRIDE.set(Path(path) if path is not None else None)


def resolve_work_dir(state: PlanState) -> Path:
    """Return the source-code working directory for worker subprocesses.

    Precedence:
    1. Explicit override set via :func:`set_work_dir_override` (e.g. from the
       CLI ``--work-dir`` flag).
    2. The plan's stored ``project_dir`` (persisted at ``megaplan init``).
    Missing or stale ``project_dir`` fails closed unless an explicit override
    was supplied.

    If the resolved path differs from the plan's stored ``project_dir``, a
    one-time informational line is printed so operators notice worktree
    divergence. (Callers that want a visually-loud operator warning should
    invoke :func:`warn_if_work_dir_differs_from_project_dir` from the phase
    entry point — this function keeps the log terse because it fires on every
    worker invocation.)
    """
    override = _WORK_DIR_OVERRIDE.get()
    if override is not None:
        resolved_override = Path(override).expanduser().resolve()
        if not resolved_override.is_dir():
            raise CliError(
                "invalid_work_dir",
                f"worker work-dir override does not exist or is not a directory: {resolved_override}",
            )
        return resolved_override
    try:
        raw_project_dir = state["config"]["project_dir"]
    except Exception as exc:
        raise CliError(
            "missing_project_dir",
            "plan state is missing config.project_dir; refusing to use process cwd for worker execution",
        ) from exc
    project_dir = Path(str(raw_project_dir)).expanduser().resolve()
    if not project_dir.is_dir():
        raise CliError(
            "stale_project_dir",
            f"plan config.project_dir does not exist or is not a directory: {project_dir}",
        )
    work_dir = project_dir
    resolved_work = work_dir.resolve()
    if project_dir is not None and resolved_work != project_dir:
        with _WORK_DIR_WARNED_LOCK:
            if resolved_work not in _WORK_DIR_WARNED:
                _WORK_DIR_WARNED.add(resolved_work)
                print(
                    f"[megaplan] Using plan's project_dir ({project_dir}) for "
                    f"subprocess --add-dir. Override with --work-dir if needed.",
                    flush=True,
                )
    return resolved_work


def _guard_mutating_worker_launch(step: str, state: PlanState, root: Path) -> None:
    if step not in _MUTATING_WORKER_STEPS:
        return
    env = resolve_execution_environment(root=root, state=state)
    proof = engine_write_barrier(env, step)
    _record_engine_verification(
        state,
        step=step,
        timing="before_worker",
        env=env,
        proof=(
            proof
            if isinstance(proof, dict)
            else proof.to_dict()
            if hasattr(proof, "to_dict")
            else {"provider": type(proof).__name__}
        ),
    )


def _record_engine_verification(
    state: PlanState,
    *,
    step: str,
    timing: str,
    env: ExecutionEnvironment,
    proof: dict[str, Any] | None = None,
) -> dict[str, Any]:
    meta = state.setdefault("meta", {})
    if not isinstance(meta, dict):
        meta = {}
        state["meta"] = meta
    verifications = meta.setdefault("engine_isolation_verifications", [])
    if not isinstance(verifications, list):
        verifications = []
        meta["engine_isolation_verifications"] = verifications
    record: dict[str, Any] = {
        "phase": step,
        "timing": timing,
        "engine_root": str(env.engine_root),
    }
    if proof is not None:
        record["proof"] = proof
    verifications.append(record)
    return record


def _verify_engine_after_mutating_worker(
    step: str,
    state: PlanState,
    root: Path,
    before_env: ExecutionEnvironment,
) -> None:
    del before_env
    if step not in _MUTATING_WORKER_STEPS:
        return
    after_env = resolve_execution_environment(root=root, state=state)
    _record_engine_verification(
        state,
        step=step,
        timing="after_worker",
        env=after_env,
    )


def warn_if_work_dir_differs_from_project_dir(state: PlanState) -> None:
    """Emit a visible WARNING if the resolved work_dir is narrower than the
    plan's stored ``project_dir``.

    Intended to be called at the top of any phase that spawns sandboxed
    subprocess workers (execute, review, etc.). The warning alerts the
    operator that codex will be sandboxed to a subset of the project tree,
    which silently breaks writes to sibling subrepos.
    """
    try:
        project_dir = Path(state["config"]["project_dir"]).resolve()
    except Exception:
        return
    work_dir = resolve_work_dir(state)
    try:
        resolved_work = work_dir.resolve()
    except Exception:
        resolved_work = work_dir
    if resolved_work == project_dir:
        return
    try:
        cwd = Path.cwd().resolve()
    except Exception:
        cwd = Path.cwd()
    # ANSI bold yellow + warning emoji for visual distinction. Printed to
    # stderr so it is not swallowed by output redirection of the primary
    # response payload.
    prefix = "\033[1;33m" if sys.stderr.isatty() else ""
    suffix = "\033[0m" if sys.stderr.isatty() else ""
    message = (
        f"{prefix}⚠️  WARNING: codex will be sandboxed to {resolved_work}, "
        f"but the plan's project_dir is {project_dir}. File writes outside "
        f"{resolved_work} will fail. Pass --work-dir {project_dir} or cd to "
        f"{project_dir} to match the plan.{suffix}"
    )
    # CWD context helps the operator see *why* work_dir ended up narrower.
    if cwd != project_dir and cwd != resolved_work:
        message += f"\n[megaplan] (current shell cwd: {cwd})"
    print(message, file=sys.stderr, flush=True)





def _spawn_registration_for_process(process: Any) -> dict[str, Any]:
    """Build the exact child registration envelope at spawn time."""
    pid = int(process.pid)
    import platform
    host = platform.node()
    boot_id = current_boot_identity() or ""
    process_start = read_process_start_identity(pid) or ""
    if not host or pid <= 0 or not boot_id or not process_start:
        raise RuntimeError("spawned child identity is incomplete")
    now = datetime.now(timezone.utc).isoformat()
    return {
        "worker_identity": {
            "host": host, "pid": pid, "boot_id": boot_id,
            "process_start_identity": process_start,
        },
        "started_at": now,
        "supervisor_identity": {
            "host": host, "pid": os.getpid(), "boot_id": boot_id,
            "process_start_identity": read_process_start_identity(os.getpid()) or "",
        },
        "container_identity": (
            os.environ.get("CONTAINER_ID") or os.environ.get("ARNOLD_CONTAINER_ID")
            or os.environ.get("HOSTNAME") or ""
        ),
        "incarnation_identity": (
            os.environ.get("ARNOLD_RUNTIME_INCARNATION")
            or os.environ.get("ARNOLD_SUPERVISOR_INCARNATION") or ""
        ),
    }


def _spawn_execution_context_snapshot(callback: Any) -> dict[str, Any] | None:
    """Extract only already-bound context for an admission-failure handoff."""
    current = callback
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        context = getattr(current, "context", None)
        if context is not None:
            try:
                value = context.to_dict() if hasattr(context, "to_dict") else dict(context)
            except (TypeError, ValueError):
                value = None
            if isinstance(value, Mapping):
                return dict(value)
        current = getattr(current, "delegate", None)
    binding = _WORKER_DISPATCH_BINDING.get() or {}
    value = binding.get("execution_context") or binding.get("context")
    if value is not None:
        try:
            value = value.to_dict() if hasattr(value, "to_dict") else dict(value)
        except (TypeError, ValueError):
            value = None
        if isinstance(value, Mapping):
            return dict(value)
    return None


def _spawn_unresolved_outcome_snapshot(
    context: dict[str, Any] | None,
    *,
    worker_identity: dict[str, Any] | None,
    started_at: str | None,
    finished_at: str | None,
    reconciliation_event_id: str | None,
) -> dict[str, Any] | None:
    """Build the lossless unresolved-launch transport when context is bound."""
    context = context if isinstance(context, Mapping) else {}
    # Unbound legacy callbacks have no receipt to copy.  Keep the unresolved
    # transport typed and explicit rather than dropping it or inventing an
    # accepted outcome; the process identity and reconciliation event remain
    # authoritative for the eventual handoff.
    admission_receipt_id = context.get("admission_receipt_id") or None
    semantic_fingerprint = context.get("semantic_dispatch_fingerprint") or None
    if admission_receipt_id and not semantic_fingerprint:
        admission_receipt_id = None
    from arnold_pipelines.megaplan.orchestration.phase_result import DispatchOutcome
    observed_at = datetime.now(timezone.utc).isoformat()

    return DispatchOutcome(
        kind="unresolved_launch",
        launch_state="ambiguous",
        plan_id=str(context.get("plan_id") or "unknown"),
        phase=str(context.get("phase") or "unknown"),
        dispatch_family_id=str(context.get("dispatch_family_id") or "unknown"),
        logical_dispatch_id=str(context.get("logical_dispatch_id") or "unresolved-launch"),
        admission_receipt_id=(str(admission_receipt_id) if admission_receipt_id else None),
        semantic_dispatch_fingerprint=(str(semantic_fingerprint) if semantic_fingerprint else None),
        selected_spec=str(context.get("selected_spec") or "unknown"),
        worker_identity=worker_identity,
        started_at=started_at or observed_at,
        finished_at=finished_at or observed_at,
        reconciliation_event_id=reconciliation_event_id,
    ).to_dict()


def _canonical_spawn_cleanup_handoff_id(value: Any) -> str | None:
    """Extract only an explicitly typed, persisted cleanup-handoff identity."""
    if isinstance(value, Mapping):
        event_type = value.get("event_type")
        if event_type == "spawn_cleanup_handoff":
            reference = value.get("handoff_id") or value.get("event_id")
            if isinstance(reference, str) and reference:
                return reference
        if value.get("state") == "cleanup_hold":
            reference = value.get("handoff_id")
            if isinstance(reference, str) and reference:
                return reference
        for key in ("handoff", "payload", "event"):
            reference = _canonical_spawn_cleanup_handoff_id(value.get(key))
            if reference is not None:
                return reference
    return None


def _handoff_spawn_cleanup(callback: Any, hold: SpawnCleanupHold) -> Any:
    """Offer custody using the bound authority's hold/process API."""
    current = callback
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        handoff = getattr(current, "handoff_spawn_cleanup", None)
        if callable(handoff):
            # Production WBCs receive the parent-owned Popen handle and, when
            # supported, the complete hold metadata.  Older test/development
            # callbacks accepted the hold as their sole positional argument;
            # retain that compatibility without confusing their return value
            # for a durable ledger identity.
            try:
                # Generic WBC wrappers expose a ``process`` parameter while
                # forwarding to a legacy delegate whose parameter is named
                # ``hold``.  Inspect the actual target when available so the
                # wrapper receives the same shape it will forward.
                target = getattr(current, "handoff_impl", None)
                if not callable(target):
                    delegate = getattr(current, "delegate", None)
                    target = getattr(delegate, "handoff_spawn_cleanup", None)
                target = target if callable(target) else handoff
                parameters = inspect.signature(target).parameters
            except (TypeError, ValueError):
                parameters = {}
            if "process" in parameters:
                if "hold" in parameters:
                    return handoff(hold.process, hold=hold)
                return handoff(hold.process)
            if "hold" in parameters:
                return handoff(hold)
            return handoff(hold)
        current = getattr(current, "delegate", None)
    return None


def run_command(
    command: list[str],
    *,
    cwd: Path,
    stdin_text: str | None = None,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
    activity_callback: Callable[[str, str], None] | None = None,
    activity_guard: Callable[[str, str], None] | None = None,
    idle_timeout: float | None = None,
    pre_first_byte_timeout: float | None = None,
    liveness_probe: Callable[[], bool] | None = None,
    progress_liveness_probe: Callable[[], ProgressLivenessState] | None = None,
    progress_liveness_factory: Callable[[Any], Callable[[], ProgressLivenessState] | None]
    | None = None,
    progress_liveness_grace_timeout: float | None = None,
    tmux_session: TmuxSession | None = None,
    spawn_registration_callback: Callable[[Mapping[str, Any]], Any] | None = None,
    # Friendly alias for callers that describe the hook as an on-spawn
    # callback.  Both names are process-local and have identical semantics.
    on_spawn: Callable[[Mapping[str, Any]], Any] | None = None,
) -> CommandResult:
    stdin_text = _normalize_stdin_text(stdin_text)
    spawned_registration: dict[str, Any] | None = None
    # Codex CLI (v0.137+) interprets a trailing "-" as "read the prompt from
    # stdin".  Older versions wedged on piped stdin, so the code previously wrote
    # the prompt to a temp file and passed "@/path/to/file".  Modern Codex treats
    # "@file" as a reference/attachment rather than the prompt itself, causing the
    # worker to hang waiting for instructions.  We now write the prompt to a temp
    # file and feed that file as stdin while keeping the trailing "-".
    stdin_path: Path | None = None
    if stdin_text is not None and command and command[-1] == "-":
        stdin_handle = tempfile.NamedTemporaryFile(
            "w+", encoding="utf-8", delete=False, dir=str(_project_local_tmp_dir(cwd))
        )
        stdin_handle.write(stdin_text)
        stdin_handle.flush()
        stdin_handle.close()
        stdin_path = Path(stdin_handle.name)
        # Keep the trailing "-" so codex reads the prompt from stdin.

    try:
        started = time.monotonic()
        timeout = timeout or get_effective("execution", "worker_timeout_seconds")
        if (
            activity_callback is None
            and activity_guard is None
            and spawn_registration_callback is None
            and on_spawn is None
        ):
            stdin_file: Any | None = None
            try:
                if stdin_path is not None:
                    stdin_file = open(stdin_path, "rb")
                process = subprocess.run(
                    command,
                    stdin=stdin_file if stdin_file is not None else subprocess.DEVNULL,
                    text=True,
                    cwd=str(cwd),
                    capture_output=True,
                    timeout=timeout,
                    env=env,
                )
            except subprocess.TimeoutExpired as exc:
                def _coerce_timeout_output(value: str | bytes | None) -> str:
                    if value is None:
                        return ""
                    if isinstance(value, bytes):
                        return value.decode("utf-8", errors="replace")
                    return value

                raise CliError(
                    "worker_timeout",
                    f"Command timed out after {timeout}s: {' '.join(command[:3])}...",
                    extra={
                        "raw_output": _coerce_timeout_output(exc.output)
                        + _coerce_timeout_output(exc.stderr)
                    },
                ) from exc
            except FileNotFoundError as exc:
                raise CliError(
                    "agent_not_found",
                    f"Command not found: {command[0]}",
                ) from exc
            finally:
                if stdin_file is not None:
                    stdin_file.close()
                if stdin_path is not None:
                    stdin_path.unlink(missing_ok=True)
            return CommandResult(
                command=command,
                cwd=cwd,
                returncode=process.returncode,
                stdout=process.stdout or "",
                stderr=process.stderr or "",
                duration_ms=int((time.monotonic() - started) * 1000),
            )

        stdin_file = None
        try:
            if stdin_path is not None:
                # Reuse the single sealed prompt file created above. Creating a
                # second file here leaked the first on every streaming call.
                stdin_file = open(stdin_path, "rb")

            process = spawn(
                command,
                cwd=str(cwd),
                stdin=stdin_file if stdin_file is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            callback = spawn_registration_callback or on_spawn
            local_control_token = _LOCAL_SPAWN_CONTROL.set(callback)
            if callback is not None:
                try:
                    spawned_registration = _spawn_registration_for_process(process)
                    registrar = getattr(callback, "register", None)
                    if callable(registrar):
                        registrar(spawned_registration)
                    elif callable(callback):
                        # Legacy callbacks remain accepted for development and
                        # replay compatibility.  They do not provide a
                        # production signal authority; native timeout paths
                        # consequently fail closed when no ``signal_ladder``
                        # method is present.
                        callback(spawned_registration)
                    else:
                        raise RuntimeError("spawn control is not callable")
                except BaseException as admission_error:
                    # Registration happens after Popen, so an admission or
                    # certification failure must not drop a live child with a
                    # bare re-raise.  Build the handoff first.  Registration
                    # did not complete, so there is no valid admitted
                    # authority at this boundary and no native ladder may be
                    # attempted here.
                    authority_result: dict[str, Any] = {
                        "attempted": False,
                        "handled": False,
                        "reason": "registration_failed_before_admission_completion",
                    }
                    registration = spawned_registration or {}
                    worker_identity = registration.get("worker_identity")
                    if not isinstance(worker_identity, Mapping):
                        worker_identity = None
                    else:
                        worker_identity = dict(worker_identity)
                    context_snapshot = _spawn_execution_context_snapshot(callback)
                    canonical_registration = json.dumps(
                        registration, sort_keys=True, separators=(",", ":"), default=str
                    )
                    spawn_event_id = hashlib.sha256(
                        ("spawn-registration:" + canonical_registration).encode("utf-8")
                    ).hexdigest()
                    hold = SpawnCleanupHold(
                        process=process,
                        pid=int(process.pid),
                        process_start_identity=(
                            str(worker_identity.get("process_start_identity"))
                            if worker_identity and worker_identity.get("process_start_identity")
                            else None
                        ),
                        admission_error=str(admission_error),
                        execution_context=context_snapshot,
                        worker_identity=worker_identity,
                        spawn_event_id=spawn_event_id,
                    )
                    hold.dispatch_outcome = _spawn_unresolved_outcome_snapshot(
                        context_snapshot,
                        worker_identity=worker_identity,
                        started_at=(
                            str(registration.get("started_at"))
                            if registration.get("started_at")
                            else None
                        ),
                        finished_at=None,
                        reconciliation_event_id=spawn_event_id,
                    )
                    handoff_result = None
                    try:
                        # A production WBC may implement this optional method
                        # to persist a cleanup-hold event and own the handle.
                        # No signal primitive is used by this handoff.
                        handoff_result = _handoff_spawn_cleanup(callback, hold)
                    except BaseException as handoff_error:
                        handoff_result = {
                            "state": "unresolved",
                            "error": str(handoff_error),
                        }
                    authority_result["handoff"] = handoff_result
                    canonical_handoff_id = _canonical_spawn_cleanup_handoff_id(handoff_result)
                    # The synthetic registration hash is useful for local
                    # diagnostics only.  It must never masquerade as a
                    # durable reconciliation reference.  A production WBC
                    # return is authoritative only when it carries an
                    # explicitly typed cleanup-handoff event identity.
                    hold.dispatch_outcome = _spawn_unresolved_outcome_snapshot(
                        context_snapshot,
                        worker_identity=worker_identity,
                        started_at=(
                            str(registration.get("started_at"))
                            if registration.get("started_at")
                            else None
                        ),
                        finished_at=None,
                        reconciliation_event_id=canonical_handoff_id,
                    )
                    authority_result["handoff_event_id"] = canonical_handoff_id
                    authority_result["handoff_required"] = bool(
                        getattr(callback, "production", False)
                    )
                    authority_result["handoff_supported"] = handoff_result is not None
                    authority_result["reconciliation"] = hold.reconcile(timeout_s=0.0)
                    raise SpawnRegistrationError(
                        admission_error,
                        cleanup_hold=hold,
                        cleanup_result=authority_result,
                    ) from admission_error
            if progress_liveness_probe is None and progress_liveness_factory is not None:
                try:
                    progress_liveness_probe = progress_liveness_factory(process)
                except Exception:
                    progress_liveness_probe = None
            stdout_parts: list[bytes] = []
            stderr_parts: list[bytes] = []

            # Idle-output watchdog state. Updated ONLY on real stdout/stderr chunks
            # (never by the liveness heartbeat) so a stalled-but-alive subprocess is
            # detected while a healthy, actively-streaming call keeps resetting it.
            # ``last_output`` is a single-element list so the reader closures can
            # mutate it without a nonlocal declaration.
            last_output = [time.monotonic()]
            # Pre-first-byte watchdog state: distinct from idle_timeout. Set True
            # the moment any real stdout/stderr chunk arrives. The liveness
            # heartbeat does NOT flip this — that's the entire point: a wedged
            # codex subprocess produces zero output but keeps the heartbeat
            # ticking, which masks the stall. See diagnostic
            # /tmp/codex_wedge_diagnostic.md.
            first_byte_seen = [False]
            # Backstop tracker for the liveness-probe rescue path below. Unlike
            # ``last_output`` (which the probe resets when it believes the worker
            # is progressing), this is reset ONLY by real stdout/stderr bytes and
            # is NEVER touched by the probe. It bounds how long a stdout-SILENT
            # turn may be kept alive by probe rescues alone, so a wedge whose
            # transcript signal is unreadable for any reason (slug drift, probe
            # bug, exception) still dies within a hard multiple of the idle bound
            # instead of running to the 2h wall-clock ``timeout``.
            last_real_output = [time.monotonic()]
            last_progress_signal = [last_real_output[0]]
            guard_triggered = threading.Event()
            guard_error: list[CliError] = []

            def _reader(stream: Any, parts: list[bytes], kind: str) -> None:
                if stream is None:
                    return
                # Use read1() so we deliver bytes as soon as the OS makes them
                # available (one underlying read) rather than blocking until a full
                # 4096-byte buffer fills. The plain read(4096) would not return until
                # the pipe accumulated 4096 bytes OR closed, so a worker streaming
                # small frames (e.g. shannon JSON deltas) would surface NO activity
                # mid-stream — both starving the liveness/activity callback and
                # hiding genuine progress from the idle-output watchdog below.
                # read1() falls back to read() for any stream lacking it.
                reader = getattr(stream, "read1", None) or stream.read
                while True:
                    chunk = reader(4096)
                    if not chunk:
                        break
                    last_output[0] = time.monotonic()
                    last_real_output[0] = time.monotonic()
                    last_progress_signal[0] = time.monotonic()
                    first_byte_seen[0] = True
                    parts.append(chunk)
                    text = chunk.decode("utf-8", errors="replace")
                    if activity_guard is not None:
                        try:
                            activity_guard(kind, text)
                        except CliError as exc:
                            guard_error.append(exc)
                            guard_triggered.set()
                            return
                        except Exception as exc:
                            guard_error.append(
                                CliError(
                                    "activity_guard_error",
                                    f"Worker activity guard failed: {exc}",
                                )
                            )
                            guard_triggered.set()
                            return
                    if activity_callback is not None:
                        activity_callback(kind, text)

            threads = [
                threading.Thread(target=_reader, args=(process.stdout, stdout_parts, "stdout"), daemon=True),
                threading.Thread(target=_reader, args=(process.stderr, stderr_parts, "stderr"), daemon=True),
            ]
            # Liveness heartbeat: some subprocess workers (notably ``codex exec``)
            # can run a single long task while emitting nothing on stdout/stderr for
            # many minutes — a tool turn or a stalled-then-resuming network call.
            # The reader-driven ``activity_callback`` only fires on output, so a
            # provably-alive worker would otherwise look idle and trip the outer
            # `megaplan auto` idle-timeout, killing the whole phase. Emit a periodic
            # liveness signal while the process is alive so that watchdog sees a
            # heartbeat. The callback is rate-limited and routes to
            # ``touch_active_step`` (bumping state.json mtime, which the auto driver
            # recognizes as activity); this is a no-op for any worker whose
            # activity_callback is None.
            heartbeat_stop = threading.Event()

            def _heartbeat() -> None:
                while not heartbeat_stop.wait(5.0):
                    if process.poll() is not None:
                        return
                    if activity_callback is None:
                        continue
                    try:
                        activity_callback("liveness", "worker subprocess alive")
                    except Exception:
                        pass

            threads.append(threading.Thread(target=_heartbeat, daemon=True))
            for thread in threads:
                thread.start()

            def _coerce_timeout_output(parts: list[bytes]) -> str:
                return b"".join(parts).decode("utf-8", errors="replace")

            def _combined_raw_output() -> str:
                return _coerce_timeout_output(stdout_parts) + _coerce_timeout_output(stderr_parts)

            def _raise_guard_error() -> None:
                error = guard_error[0] if guard_error else CliError(
                    "activity_guard_error",
                    "Worker activity guard stopped the subprocess.",
                )
                raw = _combined_raw_output()
                if raw:
                    existing = str(error.extra.get("raw_output", ""))
                    error.extra["raw_output"] = existing + raw if existing else raw
                raise error

            # When the caller opts in to the idle-output watchdog (e.g. the shannon
            # worker) OR the pre-first-byte watchdog (e.g. the codex worker), poll
            # process.wait() in short slices so we can also enforce those bounds
            # between slices. When both timeouts are None (no watchdog opt-in),
            # this collapses to the original single process.wait(timeout=timeout)
            # — no behavioral change for those callers.
            first_byte_deadline = (
                started + pre_first_byte_timeout
                if pre_first_byte_timeout is not None
                else None
            )
            if (
                idle_timeout is not None
                or first_byte_deadline is not None
                or activity_guard is not None
                or progress_liveness_probe is not None
            ):
                deadline = started + timeout
                # Hard ABSOLUTE per-turn cap (three-channel liveness backstop).
                # Independent of the probe and never reset by any signal: it
                # bounds an INFINITE run that keeps a liveness channel hot forever
                # (e.g. a pytest stuck in an infinite loop spinning CPU). Only
                # armed on the shannon liveness path (a probe was supplied); other
                # callers keep their exact prior behaviour. Clamped at/below the
                # wall-clock ``timeout`` so it can only ever tighten, never loosen.
                hard_cap_deadline = (
                    started + min(_turn_hard_cap_seconds(), float(timeout))
                    if liveness_probe is not None
                    else None
                )
                try:
                    while True:
                        if guard_triggered.is_set():
                            _native_signal_ladder(process, cause_kind="stall")
                            heartbeat_stop.set()
                            for thread in threads:
                                thread.join(timeout=1)
                            _raise_guard_error()
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise subprocess.TimeoutExpired(command, timeout)
                        # Poll on short slices so watchdogs and guard failures
                        # fire promptly while reader threads keep collecting output.
                        wait_slice = min(0.1 if activity_guard is not None else 1.0, remaining)
                        try:
                            returncode = process.wait(timeout=wait_slice)
                            break
                        except subprocess.TimeoutExpired:
                            # Hard absolute cap first: fires regardless of probe
                            # channels or real output. A runaway that keeps a
                            # channel hot forever (infinite-loop pytest, a forever
                            # pinging socket) is killed here even though the probe
                            # would correctly call it "alive".
                            if (
                                hard_cap_deadline is not None
                                and time.monotonic() > hard_cap_deadline
                            ):
                                _native_signal_ladder(process, cause_kind="timeout")
                                returncode = process.poll() if process.poll() is not None else -1
                                heartbeat_stop.set()
                                for thread in threads:
                                    thread.join(timeout=1)
                                cap = min(_turn_hard_cap_seconds(), float(timeout))
                                raise CliError(
                                    "worker_timeout",
                                    (
                                        f"Worker exceeded the hard per-turn cap "
                                        f"({cap:.0f}s; SHANNON_TURN_HARD_CAP_SECONDS); "
                                        f"runaway turn killed: {' '.join(command[:3])}..."
                                    ),
                                    extra={
                                        "raw_output": _coerce_timeout_output(stdout_parts)
                                        + _coerce_timeout_output(stderr_parts)
                                    },
                                )
                            # Still running: check the pre-first-byte bound first.
                            # Only real stdout/stderr flips first_byte_seen; the
                            # heartbeat explicitly does not, so a wedged subprocess
                            # that produces zero bytes will trip this even while
                            # heartbeats keep ``state.json`` mtime fresh.
                            if (
                                first_byte_deadline is not None
                                and not first_byte_seen[0]
                                and time.monotonic() > first_byte_deadline
                            ):
                                _native_signal_ladder(process, cause_kind="stall")
                                returncode = process.poll() if process.poll() is not None else -1
                                heartbeat_stop.set()
                                for thread in threads:
                                    thread.join(timeout=1)
                                raise CliError(
                                    "codex_pre_first_byte_stall",
                                    (
                                        f"Worker produced no output before pre-first-byte "
                                        f"deadline ({pre_first_byte_timeout:.0f}s); "
                                        f"likely codex wedge at startup: "
                                        f"{' '.join(command[:3])}..."
                                    ),
                                    extra={
                                        "raw_output": _coerce_timeout_output(stdout_parts)
                                        + _coerce_timeout_output(stderr_parts)
                                    },
                                )
                            # Then the idle-output bound. Only real stdout/stderr
                            # resets last_output; the heartbeat does not.
                            if (
                                idle_timeout is not None
                                and time.monotonic() - last_output[0] > idle_timeout
                            ):
                                # Buffered-mode rescue: some workers (notably the
                                # shannon path, which drives Claude in a tmux pane
                                # under ``--output-format=json``) emit NOTHING on
                                # stdout/stderr for the entire turn — the CLI
                                # buffers its whole result. For those, an idle bound
                                # on stdout bytes alone degenerates into a hard
                                # total-turn wall-clock cap and KILLS healthy,
                                # actively-progressing turns (the original
                                # ``worker_stall`` with empty ``raw_output`` at
                                # exactly the idle bound). When a ``liveness_probe``
                                # is supplied, consult a REAL liveness signal (tmux
                                # pane content advancing, transcript .jsonl mtime
                                # moving) before killing: if the worker is alive and
                                # making progress, treat that as activity — reset the
                                # idle clock and keep waiting. Only a worker that is
                                # BOTH stdout-silent AND not progressing is killed,
                                # which still catches a genuinely hung/dead turn. The
                                # wall-clock ``timeout`` (worker_timeout_seconds)
                                # remains the hard upper bound.
                                if progress_liveness_probe is not None:
                                    try:
                                        liveness_state = progress_liveness_probe()
                                    except Exception:
                                        liveness_state = "unknown"
                                    if liveness_state == "progressing":
                                        if activity_callback is not None:
                                            try:
                                                activity_callback(
                                                    "liveness",
                                                    "worker progressing (probe); idle clock reset",
                                                )
                                            except Exception:
                                                pass
                                        now = time.monotonic()
                                        last_output[0] = now
                                        last_progress_signal[0] = now
                                        continue
                                    if liveness_state in {"alive_only", "unknown"}:
                                        grace = (
                                            progress_liveness_grace_timeout
                                            if progress_liveness_grace_timeout is not None
                                            else _probe_rescue_cap_seconds()
                                        )
                                        if time.monotonic() - last_progress_signal[0] <= grace:
                                            if activity_callback is not None:
                                                try:
                                                    activity_callback(
                                                        "liveness",
                                                        f"worker {liveness_state} (probe); "
                                                        "idle clock reset within grace",
                                                    )
                                                except Exception:
                                                    pass
                                            last_output[0] = time.monotonic()
                                            continue
                                    # "stalled" or expired alive_only/unknown
                                    # grace falls through to the centralized
                                    # worker_stall kill path below.
                                elif liveness_probe is not None:
                                    # Hard backstop: cap how long a stdout-SILENT
                                    # turn may be rescued by the probe alone. The
                                    # probe's "progress" signal (transcript mtime)
                                    # can be wrong — e.g. it globs the wrong
                                    # project dir and falls into its no-signal
                                    # branch that returns True forever — which is
                                    # exactly the failure that let a wedge keep its
                                    # idle clock reset past the bound. Once REAL
                                    # output (the only probe-independent signal) has
                                    # been absent longer than the rescue cap, stop
                                    # trusting the probe and kill. NDJSON events
                                    # from a healthy turn reset last_real_output, so
                                    # this never threatens a turn that is actually
                                    # emitting; the (now slug-correct) probe is the
                                    # primary path and kills a wedge at ~the idle
                                    # bound, so this only bites when the probe
                                    # signal is unreadable.
                                    probe_rescue_cap = _probe_rescue_cap_seconds()
                                    if (
                                        time.monotonic() - last_real_output[0]
                                        > probe_rescue_cap
                                    ):
                                        alive_and_progressing = False
                                    else:
                                        try:
                                            alive_and_progressing = bool(liveness_probe())
                                        except Exception:
                                            # A probe failure must never kill a
                                            # worker outright; fall back to the
                                            # conservative "treat as progress"
                                            # stance so a live turn is never
                                            # collateral. A truly dead turn is still
                                            # bounded by the probe_rescue_cap above
                                            # and the wall-clock timeout.
                                            alive_and_progressing = True
                                    if alive_and_progressing:
                                        if activity_callback is not None:
                                            try:
                                                activity_callback(
                                                    "liveness",
                                                    "buffered worker progressing "
                                                    "(probe); idle clock reset",
                                                )
                                            except Exception:
                                                pass
                                        last_output[0] = time.monotonic()
                                        continue
                                _native_signal_ladder(process, cause_kind="stall")
                                returncode = process.poll() if process.poll() is not None else -1
                                heartbeat_stop.set()
                                for thread in threads:
                                    thread.join(timeout=1)
                                raise CliError(
                                    "worker_stall",
                                    (
                                        f"Worker produced no output for {idle_timeout:.0f}s "
                                        f"(stalled stream): {' '.join(command[:3])}..."
                                    ),
                                    extra={
                                        "raw_output": _coerce_timeout_output(stdout_parts)
                                        + _coerce_timeout_output(stderr_parts)
                                    },
                                )
                            continue
                except subprocess.TimeoutExpired as exc:
                    _native_signal_ladder(process, cause_kind="timeout")
                    returncode = process.poll() if process.poll() is not None else -1
                    heartbeat_stop.set()
                    for thread in threads:
                        thread.join(timeout=1)
                    raise CliError(
                        "worker_timeout",
                        f"Command timed out after {timeout}s: {' '.join(command[:3])}...",
                        extra={"raw_output": _coerce_timeout_output(stdout_parts) + _coerce_timeout_output(stderr_parts)},
                    ) from exc
            else:
                try:
                    returncode = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired as exc:
                    _native_signal_ladder(process, cause_kind="timeout")
                    returncode = process.poll() if process.poll() is not None else -1
                    heartbeat_stop.set()
                    for thread in threads:
                        thread.join(timeout=1)
                    raise CliError(
                        "worker_timeout",
                        f"Command timed out after {timeout}s: {' '.join(command[:3])}...",
                        extra={"raw_output": _coerce_timeout_output(stdout_parts) + _coerce_timeout_output(stderr_parts)},
                    ) from exc
            if guard_triggered.is_set():
                _native_signal_ladder(process, cause_kind="stall")
                heartbeat_stop.set()
                for thread in threads:
                    thread.join(timeout=1)
                _raise_guard_error()
            heartbeat_stop.set()
            for thread in threads:
                thread.join(timeout=1)
        except FileNotFoundError as exc:
            raise CliError(
                "agent_not_found",
                f"Command not found: {command[0]}",
            ) from exc
        return CommandResult(
            command=command,
            cwd=cwd,
            returncode=returncode,
            stdout=b"".join(stdout_parts).decode("utf-8", errors="replace"),
            stderr=b"".join(stderr_parts).decode("utf-8", errors="replace"),
            duration_ms=int((time.monotonic() - started) * 1000),
            worker_identity=(
                dict(spawned_registration["worker_identity"])
                if spawned_registration is not None
                else None
            ),
        )
    finally:
        # Guard against UnboundLocalError when an early exception prevents
        # the stdin temp-file variables from being bound.
        stdin_file_local = locals().get("stdin_file")
        if stdin_file_local is not None:
            try:
                stdin_file_local.close()
            except Exception:
                pass
        stdin_path_local = locals().get("stdin_path")
        if stdin_path_local is not None:
            try:
                stdin_path_local.unlink(missing_ok=True)
            except Exception:
                pass
        if tmux_session:
            tmux_session.teardown()
        token = locals().get("local_control_token")
        if token is not None:
            _LOCAL_SPAWN_CONTROL.reset(token)


def _activity_callback_for_state(state: PlanState, plan_dir: Path) -> Callable[[str, str], None] | None:
    active_step = state.get("active_step")
    if not isinstance(active_step, dict):
        return None
    run_id = active_step.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        return None
    last_touch = 0.0

    def _callback(kind: str, detail: str) -> None:
        nonlocal last_touch
        now = time.monotonic()
        if now - last_touch < 2.0:
            return
        last_touch = now
        touch_active_step(plan_dir, run_id=run_id, kind=kind, detail=detail.strip())

    return _callback


def _spawn_registration_callback_from_binding() -> Callable[[Mapping[str, Any]], Any] | None:
    callback = (_WORKER_DISPATCH_BINDING.get() or {}).get("spawn_registration_callback")
    return callback if callable(callback) else None


def _native_signal_ladder(process: Any, *, cause_kind: str) -> bool:
    """Request the durable worker ladder; absent proof means no signal.

    Native workers must not call ``kill``/``kill_group`` directly.  The
    process-local callback is installed only by an admitted WBC dispatch and
    may itself decline when accepted identity/confirmation proof is absent.
    """
    # Native timeout/guard branches may only emit canonical CauseKind values;
    # keep this last door fail-closed for any legacy or future caller that
    # supplies an untyped label.
    if cause_kind not in {"timeout", "stall", "idle", "wedge", "cgroup_oom"}:
        return False
    callback = _spawn_registration_callback_from_binding() or _LOCAL_SPAWN_CONTROL.get()
    # Native supervision already owns an explicit timeout/guard decision.  A
    # two-scan progress proof cannot be manufactured inside this low-level
    # callback, so use the same controlled launch's explicitly-authorized
    # timeout teardown.  It records TERM/KILL before each physical callback
    # and appends the terminal only after observing the child dead.
    immediate = getattr(callback, "immediate_timeout", None) if callback is not None else None
    if not callable(immediate) and callback is not None:
        # Production WBC callbacks bind ControlledFinalLaunch through the
        # SpawnedChildControl.signal_impl callable.  Resolve that same
        # authority without introducing a second callback/persistence door.
        owner = getattr(getattr(callback, "signal_impl", None), "__self__", None)
        immediate = getattr(owner, "immediate_timeout", None)
    if callable(immediate) and cause_kind in {"timeout", "stall"}:
        result = immediate(process, timeout_source=f"native-{cause_kind}")
        return bool(
            isinstance(result, Mapping)
            and result.get("state") in {"killed", "already_dead"}
        )
    ladder = getattr(callback, "signal_ladder", None) if callback is not None else None
    if not callable(ladder):
        return False
    result = ladder(process, cause_kind=cause_kind)
    # Do not treat a structured ``confirmation_pending``/``unresolved``
    # result as truthy merely because it is a non-empty object.  Native
    # callers use this boolean as the physical-teardown acknowledgement.
    # Only terminal states count as handled; every pending/refused result is a
    # hard failure at this boundary and cannot silently fall through.
    if isinstance(result, Mapping):
        return result.get("state") in {"killed", "already_dead"}
    return getattr(result, "state", None) in {"killed", "already_dead"}


_CODEX_ERROR_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern_substring, error_code, human_message)
    # Keep transport failures ahead of generic HTTP/status matches so
    # thread IDs or unrelated numbers do not get misclassified as 429s.
    ("failed to lookup address information", "connection_error", "Codex could not resolve the backend host"),
    ("failed to connect to websocket", "connection_error", "Codex could not connect to the realtime backend"),
    # Durable billing exhaustion must be recognized BEFORE the generic transport
    # row below: codex surfaces "no credits remaining" wrapped inside
    # "stream disconnected before completion", and the first-match-wins table
    # would otherwise swallow the billing signal as a transient connection
    # drop (astrid-first m6 finalize, occurrence fc98376b2f10). quota_exceeded
    # also routes to _codex_hard_quota_guidance() instead of "re-run once".
    ("no credits remaining", "quota_exceeded", "Codex quota exceeded"),
    ("stream disconnected before completion", "connection_error", "Codex connection dropped before completion"),
    ("error sending request for url", "connection_error", "Codex could not send the backend request"),
    ("nodename nor servname provided", "connection_error", "Codex could not resolve the backend host"),
    ("connection error", "connection_error", "Codex could not connect to the API"),
    ("connection refused", "connection_error", "Codex could not connect to the API"),
    ("usage limit", "quota_exceeded", "Codex usage limit reached"),
    ("try again at", "quota_exceeded", "Codex usage limit reached"),
    ("rate limit", "rate_limit", "Codex hit a rate limit"),
    ("rate_limit", "rate_limit", "Codex hit a rate limit"),
    ("quota", "quota_exceeded", "Codex quota exceeded"),
    ("context length", "context_overflow", "Prompt exceeded Codex context length"),
    ("context_length", "context_overflow", "Prompt exceeded Codex context length"),
    ("maximum context", "context_overflow", "Prompt exceeded Codex context length"),
    ("too many tokens", "context_overflow", "Prompt exceeded Codex context length"),
    ("timed out", "worker_timeout", "Codex request timed out"),
    ("timeout", "worker_timeout", "Codex request timed out"),
    ("invalid_json_schema", "schema_error", "Codex request rejected: invalid JSON schema"),
    ("invalid_request_error", "schema_error", "Codex request rejected: invalid request"),
    ("internal server error", "api_error", "Codex API returned an internal error"),
    ("model not found", "model_error", "Codex model not found or unavailable"),
    ("permission denied", "permission_error", "Codex permission denied"),
    ("authentication", "auth_error", "Codex authentication failed"),
    ("unauthorized", "auth_error", "Codex authentication failed"),
]


def _codex_retry_guidance(step: str | None = None) -> str:
    if step in _EXECUTE_STEPS:
        return (
            "Re-run the same execute step on Codex once before changing agent; "
            "preserve the existing session path unless a fresh retry is explicitly needed."
        )
    return "Re-run the same step on Codex once before changing agent."


def _codex_hard_quota_guidance() -> str:
    """Give bounded recovery guidance for capacity that cannot recover now."""
    return (
        "Do not retry immediately. Restore Codex credits/capacity or wait until the "
        "provider-stated reset, then re-run the same step on Codex exactly once."
    )


def _diagnose_codex_failure(raw: str, returncode: int) -> tuple[str, str]:
    """Parse Codex stderr/stdout for known error patterns. Returns (error_code, message)."""
    lower = raw.lower()
    for pattern, code, message in _CODEX_ERROR_PATTERNS:
        if pattern in lower:
            guidance = (
                _codex_hard_quota_guidance()
                if code == "quota_exceeded"
                else _codex_retry_guidance()
            )
            return code, f"{message}. {guidance}"
    if re.search(r"\bhttp\s*429\b", lower) or re.search(r"\b429\b", lower):
        return "rate_limit", f"Codex hit a rate limit (HTTP 429). {_codex_retry_guidance()}"
    if re.search(r"\bhttp\s*400\b", lower) or re.search(r"\b400\b", lower):
        return "schema_error", f"Codex API rejected request (HTTP 400). {_codex_retry_guidance()}"
    if re.search(r"\bhttp\s*500\b", lower) or re.search(r"\b500\b", lower):
        return "api_error", f"Codex API returned an internal error (HTTP 500). {_codex_retry_guidance()}"
    if re.search(r"\bhttp\s*502\b", lower) or re.search(r"\b502\b", lower):
        return "api_error", f"Codex API returned a gateway error (HTTP 502). {_codex_retry_guidance()}"
    if re.search(r"\bhttp\s*503\b", lower) or re.search(r"\b503\b", lower):
        return "api_error", f"Codex API service unavailable (HTTP 503). {_codex_retry_guidance()}"
    return "worker_error", (
        f"Codex step failed with exit code {returncode} (no recognized error pattern in output). "
        + _codex_retry_guidance()
    )


def _codex_timeout_for_step(step: str) -> int:
    configured_timeout = int(get_effective("execution", "worker_timeout_seconds"))
    return phase_timeout_seconds(step, configured_timeout_seconds=configured_timeout)


def _codex_exec_mode_flags(step: str) -> list[str]:
    if _trusted_container():
        return []
    # All non-execute phases (plan, prep, critique, revise, gate, finalize,
    # review) need to write template artifacts (plan markdown, metadata JSON,
    # critique/review JSON, finalize.json). Without an explicit sandbox codex
    # defaults to on-request approval, which fails silently when stdin is the
    # prompt (no tty). Default everything to workspace-write sandbox mode so
    # codex auto-approves writes within configured writable_roots.
    return ["--sandbox", "workspace-write"]


_ROLLOUT_MISSING_PATTERNS = (
    "no rollout found for thread id",
    "thread/resume failed",
)


# Patterns that indicate the worker's *session history* has absorbed an
# obsolete environmental failure (e.g. from an earlier invocation before the
# container was configured for trusted-mode). On a later invocation the model
# reads this history, believes the environment is still broken, and returns
# "blocked" without attempting commands — causing infinite retry loops.
# Detecting these in the raw output and invalidating the session forces a
# fresh start so the belief can't survive.
_POISONED_SESSION_PATTERNS: tuple[tuple[str, ...], ...] = (
    # Single-substring match (any one of these is enough).
    ("bwrap: creating new namespace failed",),
    # Multi-substring match (all substrings must be present).
    ("permission denied", "cannot start sandbox"),
    ("repository command execution", "unavailable", "sandbox"),
    ("permissions profile", "does not define any recognized filesystem entries"),
)


def _is_rollout_missing(raw: str) -> bool:
    """Detect Codex's signal that a session/thread id has no rollout.

    Happens when: container was restarted between phases and codex's session
    store (usually ``$HOME/.codex/sessions``) was wiped, but megaplan's plan
    state still has the session id and tries to ``codex exec resume <id>``.

    Match is case-insensitive on known substrings so minor wording changes
    upstream don't break recovery. Fall back to failing loudly if Codex
    introduces a new error string — false positives here would mask real
    session crashes.
    """
    if not raw:
        return False
    lowered = raw.lower()
    return any(pat in lowered for pat in _ROLLOUT_MISSING_PATTERNS)


def _is_poisoned_environmental_failure(raw: str) -> bool:
    """Detect obsolete sandbox/environment failure beliefs in worker output.

    Returns True when the raw output contains known-stale environment errors
    that a persistent session may have absorbed from a prior invocation
    (before trusted-container mode was enabled). See the comment on
    ``_POISONED_SESSION_PATTERNS`` above for motivation.

    The check is intentionally conservative: every pattern is a conjunction
    of substrings all of which must be present (case-insensitive). A single
    sandbox error combined with a generic "Permission denied" elsewhere in a
    long trace should not trigger unless the full phrase appears.
    """
    if not raw:
        return False
    lowered = raw.lower()
    for group in _POISONED_SESSION_PATTERNS:
        if all(sub in lowered for sub in group):
            return True
    return False


def _is_session_too_large_for_compact(raw: str) -> bool:
    """Detect a Codex session that has grown too large to remote-compact.

    Codex auto-triggers OpenAI's remote-compaction API when the session
    approaches the model's context window. If that compaction call hits a
    rate limit and exhausts its retry budget, codex emits a
    ``remote compact task ... 429 Too Many Requests`` error and exits
    non-zero. ``codex exec resume <session-id>`` will keep replaying the
    same oversized session and hit the same wall — invalidating the
    session and retrying with ``--fresh`` is the only escape.
    """
    if not raw:
        return False
    lowered = raw.lower()
    return "remote compact task" in lowered and "429" in lowered


# System directories that should never be auto-promoted to a writable
# sandbox root. Used by :func:`_auto_writable_roots`. The check below
# matches the resolved path against these roots exactly *and* against
# direct children (e.g. /usr) — we never want to widen the sandbox to
# anything that broad even if the user happens to have project_dir at
# /usr/local/foo.
_AUTO_ROOT_FORBIDDEN: tuple[Path, ...] = (
    Path("/"),
    Path("/usr"),
    Path("/etc"),
    Path("/var"),
    Path("/private"),
    Path("/System"),
    Path("/Library"),
    Path("/bin"),
    Path("/sbin"),
    Path("/opt"),
    Path("/tmp"),
    Path.home(),
)


def _is_safe_auto_root(candidate: Path) -> bool:
    """Return True iff *candidate* is safe to auto-promote to a writable root.

    Excludes (a) system directories, (b) the user's home directory itself
    (granting write to ~ would defeat the sandbox), and (c) any path
    shallower than two levels below root (e.g. ``/Users``, ``/home``).
    """
    try:
        resolved = candidate.resolve()
    except Exception:
        return False
    # Reject filesystem root and very shallow paths.
    if len(resolved.parts) < 3:
        return False
    for forbidden in _AUTO_ROOT_FORBIDDEN:
        try:
            forbidden_resolved = forbidden.resolve()
        except Exception:
            continue
        if resolved == forbidden_resolved:
            return False
    return True


def _auto_writable_roots(work_dir: Path) -> list[str]:
    """Auto-detect additional writable roots that surround *work_dir*.

    Strategy: walk up from *work_dir* looking for a workspace marker — the
    nearest ancestor containing a ``.git`` directory or a sibling
    ``.megaplan/`` directory. If that ancestor is a strict parent of
    *work_dir* and passes :func:`_is_safe_auto_root`, return it as an
    additional writable root.

    This handles the common monorepo / multi-package workspace case where
    ``project_dir`` is a subdirectory (e.g. ``tools/``) but legitimate plan
    output writes to sibling directories (``effects/``, ``themes/``,
    ``animations/``). Without this, codex's ``workspace-write`` sandbox
    blocks those writes with ``sandbox denied creating '../foo' outside the
    writable root``.

    Disable with ``MEGAPLAN_NARROW_SANDBOX=1`` (e.g. for CI runs of
    untrusted plans where the narrow default is the safer choice).
    """
    if os.environ.get("MEGAPLAN_NARROW_SANDBOX", "").strip().lower() in {
        "1", "true", "yes", "on",
    }:
        return []
    try:
        start = Path(work_dir).resolve()
    except Exception:
        return []
    current = start.parent
    seen_root: Path | None = None
    while True:
        if seen_root is None:
            if (current / ".git").exists() or (current / ".megaplan").is_dir():
                seen_root = current
                break
        parent = current.parent
        if parent == current:
            break
        current = parent
    if seen_root is None or seen_root == start:
        return []
    if not _is_safe_auto_root(seen_root):
        return []
    return [str(seen_root)]


def _trusted_container() -> bool:
    """Return True when MEGAPLAN_TRUSTED_CONTAINER is set to a truthy value.

    In a locked-down container (Docker/Railway/Kubernetes without
    user-namespace capabilities), bubblewrap's default sandbox fails with
    ``bwrap: Creating new namespace failed: Permission denied`` because
    ``kernel.unprivileged_userns_clone`` is not settable by an unprivileged
    user. Per the official guidance at
    https://docs.docker.com/ai/sandboxes/agents/codex/ the operator is
    expected to rely on container-level isolation and bypass the Codex
    sandbox entirely. Setting ``MEGAPLAN_TRUSTED_CONTAINER=1`` on the
    worker environment activates that path.
    """
    return os.environ.get("MEGAPLAN_TRUSTED_CONTAINER", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _codex_writable_roots(
    work_dir: Path | str,
    state: PlanState,
    env: ExecutionEnvironment,
    *,
    phase: str | None = None,
) -> list[str]:
    """Return Codex writable roots after engine root filtering.

    The target work dir is always present. Auto/configured extra roots are
    accepted only when they are disjoint from the engine root.
    """

    roots: list[tuple[Path, str]] = [(Path(work_dir).resolve(), "target_work_dir")]
    roots.extend((Path(root).resolve(), "auto") for root in _auto_writable_roots(Path(work_dir)))
    try:
        raw_extra = state.get("config", {}).get("extra_writable_roots", []) or []
        if isinstance(raw_extra, list):
            for root in raw_extra:
                if not isinstance(root, str):
                    continue
                path = Path(root)
                roots.append(
                    (
                        (Path(work_dir) / path).resolve() if not path.is_absolute() else path.resolve(),
                        "configured",
                    )
                )
    except Exception:
        pass

    seen: set[str] = set()
    filtered: list[str] = []
    trusted = _trusted_container()
    for root, source in roots:
        root_str = str(root)
        if root_str in seen:
            continue
        seen.add(root_str)
        overlap = classify_path_overlap(root, env.engine_root)
        if overlap != "disjoint" and not trusted:
            if _is_self_hosted_engine_target_root(root, source, state, env):
                filtered.append(root_str)
                continue
            if source == "auto" and not (root / ".git").exists():
                continue
            raise isolation_cli_error(
                "codex_writable_root_overlaps_engine",
                "Codex writable root overlaps the engine root; refusing engine-writable sandbox",
                env=env,
                extra={
                    "writable_root": root_str,
                    "writable_root_source": source,
                    "overlap": overlap,
                },
            )
        filtered.append(root_str)
    work_str = str(Path(work_dir).resolve())
    if work_str not in filtered:
        filtered.insert(0, work_str)
    return filtered


def _is_self_hosted_engine_target_root(
    root: Path,
    source: str,
    state: PlanState,
    env: ExecutionEnvironment,
) -> bool:
    """Allow only intentional self-hosted engine development writes.

    A normal target project must not receive writable access to a separate
    Megaplan engine checkout.  When the target, work, and engine roots are the
    same repository, however, the plan is explicitly operating on Megaplan
    itself; refusing the target root would make editable engine work
    impossible.  Keep the exception exact so parent/auto/configured roots that
    merely contain the engine stay blocked.
    """

    if source != "target_work_dir":
        return False
    configured_mode = ""
    try:
        configured_mode = str(
            state.get("config", {}).get("engine_isolation_mode", "")
            or state.get("config", {}).get("engine_isolation_provider", "")
        ).strip()
    except Exception:
        configured_mode = ""
    provider = (
        os.environ.get("MEGAPLAN_ENGINE_ISOLATION_PROVIDER", "")
        or os.environ.get("MEGPLAN_ENGINE_ISOLATION_PROVIDER", "")
        or configured_mode
    ).strip()
    if provider != "self_hosted_editable":
        return False
    return (
        root == env.engine_root
        and root == env.target_root
        and root == env.work_dir
    )


def _codex_sandbox_fingerprint(work_dir: Path | str, state: PlanState, env: ExecutionEnvironment) -> str:
    """Return a stable hash of the sandbox-affecting inputs for codex.

    Captures every input that would change codex's effective sandbox
    between invocations:

    - ``MEGAPLAN_TRUSTED_CONTAINER`` (toggles ``--dangerously-bypass-...``)
    - ``work_dir`` (appears in ``-C`` and in
      ``sandbox_workspace_write.writable_roots``)

    The hash is stored on each session entry when it is created; at resume
    time we refuse to reuse a session whose fingerprint no longer matches.
    This prevents the silent drift where an operator sets
    ``MEGAPLAN_TRUSTED_CONTAINER=1`` *after* a session was created and
    codex keeps using the locked-in (broken) sandbox forever.
    """
    payload = {
        "trusted_container": _trusted_container(),
        "work_dir": str(Path(work_dir).resolve()),
        "writable_roots": [] if _trusted_container() else _codex_writable_roots(work_dir, state, env),
        "engine_root": str(env.engine_root),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()[:16]


def _worker_isolated_env_vars() -> list[str]:
    """Return the list of env var names to per-worker filesystem-isolate.

    Driven by the config key ``execution.worker_isolated_env_vars`` (a list
    of env var names). Opt-in: an empty / unset list means no isolation and
    the worker env is built exactly as before. This is intentionally general
    — megaplan core knows nothing about any specific project's var names.

    A project whose CLI honours a "home"-style env var (e.g. Astrid's
    ``ASTRID_HOME`` / ``ASTRID_PROJECTS_ROOT``) can list those vars so each
    concurrent worker gets an isolated, throwaway state directory instead of
    sharing one global per-user dir — which otherwise lets one worker's stray
    session/state files spuriously fail another worker's test suite.
    """
    try:
        raw = get_effective("execution", "worker_isolated_env_vars")
    except KeyError:
        return []
    if not isinstance(raw, (list, tuple)):
        return []
    out: list[str] = []
    for name in raw:
        if isinstance(name, str) and name.strip():
            out.append(name.strip())
    return out


def _apply_worker_state_isolation(env: dict[str, str]) -> dict[str, str]:
    """Redirect configured env vars to fresh per-worker temp directories.

    For each var name in ``execution.worker_isolated_env_vars`` we mint a
    unique directory under the OS temp dir and point the var at it, mutating
    *env* in place. This isolates per-user filesystem state across concurrent
    workers. Directories are NOT eagerly deleted (a worker may spawn child
    processes that outlive this call); they are uniquely named under the
    system temp dir and left for the OS tmp reaper, which bounds leakage.

    No-ops when the config list is empty, so the existing env is untouched.
    Existing keys are overwritten only for the listed vars; every other key
    (API keys, codex/omp/claude paths, MEGAPLAN_* ids) is preserved.
    """
    names = _worker_isolated_env_vars()
    if not names:
        return env
    base = Path(tempfile.gettempdir()) / "megaplan-worker-isolation"
    token = uuid.uuid4().hex[:12]
    for name in names:
        worker_dir = base / token / name
        try:
            worker_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            # If we cannot create the dir, leave the var as-is rather than
            # pointing the worker at a path that does not exist.
            continue
        env[name] = str(worker_dir)
    return env


# Canonical codex OAuth seeds, freshest-first. Mirrors cloud/auth.py OAUTH_SEEDS:
# the persistent volume copy (/workspace/.creds) is written on every deploy and
# the root copy is re-seeded by the entrypoint on boot.
_CODEX_AUTH_SEED_PATHS = (
    Path("/workspace/.creds/codex-auth.json"),
    Path("/root/.codex/auth.json"),
)
# Fallback freshness bound when the JWT access token carries no decodable exp.
_CODEX_AUTH_FALLBACK_MAX_AGE = 30 * 24 * 60 * 60
# Skew so a token that expires within 5 minutes is treated as stale.
_CODEX_AUTH_EXPIRY_SKEW = 5 * 60


def _seed_codex_auth_into_env(env: dict[str, str]) -> None:
    """Best-effort repair of the auth file used by the final Codex child env.

    The normal dispatch path inherits ``CODEX_HOME`` unchanged (the orchestrator
    unit exports ``CODEX_HOME=/workspace/.codex``), so a stale ``auth.json`` there
    makes every Codex child fail with 401 on the realtime backend. This helper
    validates the file the child will actually read and, when it is missing or its
    credential is expired, atomically replaces it with a canonical seed that
    independently passes the same validation.

    Best-effort contract: never raises, never prints tokens, never touches
    ``config.toml``, and leaves the child environment/files unchanged when no
    valid seed exists (a genuinely external credential gate must still surface
    truthfully as the original connection error).
    """
    now = time.time()

    def warn(reason: str) -> None:
        print(f"[megaplan] Codex auth self-heal skipped: {reason}", file=sys.stderr)

    def read_valid(path: Path) -> bytes | None:
        fd = -1
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            opened = os.fstat(fd)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) & 0o077
            ):
                return None
            raw = os.read(fd, 1_048_577)
            if not raw or len(raw) > 1_048_576:
                return None
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                return None
            if payload.get("auth_mode") == "apikey":
                key = payload.get("OPENAI_API_KEY")
                return raw if isinstance(key, str) and key.strip() else None
            tokens = payload.get("tokens")
            tokens = tokens if isinstance(tokens, dict) else {}
            access_token = tokens.get("access_token")
            if not isinstance(access_token, str) or not access_token.strip():
                return None
            exp: int | float | None = None
            try:
                part = access_token.split(".")[1]
                part += "=" * (-len(part) % 4)
                claims = json.loads(base64.urlsafe_b64decode(part))
                candidate = claims.get("exp") if isinstance(claims, dict) else None
                if isinstance(candidate, (int, float)) and not isinstance(candidate, bool):
                    exp = candidate
            except (IndexError, ValueError, TypeError, json.JSONDecodeError):
                pass
            if exp is not None:
                return raw if float(exp) > now + _CODEX_AUTH_EXPIRY_SKEW else None
            refreshed = payload.get("last_refresh")
            if not isinstance(refreshed, str):
                return None
            stamp = datetime.fromisoformat(refreshed.replace("Z", "+00:00"))
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            age = now - stamp.timestamp()
            return raw if -_CODEX_AUTH_EXPIRY_SKEW <= age <= _CODEX_AUTH_FALLBACK_MAX_AGE else None
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
            return None
        finally:
            if fd >= 0:
                os.close(fd)

    try:
        home = Path(env.get("CODEX_HOME") or Path(env.get("HOME") or Path.home()) / ".codex")
        home_stat = os.lstat(home)
        if (
            not stat.S_ISDIR(home_stat.st_mode)
            or stat.S_ISLNK(home_stat.st_mode)
            or home_stat.st_uid not in {0, os.geteuid()}
            or home_stat.st_mode & 0o022
        ):
            warn("unsafe CODEX_HOME")
            return
        target = home / "auth.json"
        if read_valid(target) is not None:
            return
        try:
            target_stat = os.lstat(target)
            if not stat.S_ISREG(target_stat.st_mode) or target_stat.st_nlink != 1:
                warn("unsafe existing auth.json")
                return
        except FileNotFoundError:
            pass
        seed = next((data for path in _CODEX_AUTH_SEED_PATHS if (data := read_valid(path)) is not None), None)
        if seed is None:
            warn("no valid canonical seed")
            return
        temporary = home / f".auth.json.tmp.{os.getpid()}.{uuid.uuid4().hex}"
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            view = memoryview(seed)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short Codex auth write")
                view = view[written:]
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, target)
    except Exception as exc:
        warn(type(exc).__name__)
        try:
            temporary.unlink(missing_ok=True)
        except (NameError, OSError):
            pass


def _codex_child_env(
    turn_id: str | None = None,
    actor_id: str | None = None,
) -> dict[str, str]:
    env = strip_progress_env(os.environ.copy())
    # Nested Codex workers should not inherit the parent Codex session state.
    # Those variables can cause the child to attach to the outer thread/CI
    # context instead of behaving like an isolated worker invocation.
    env.pop("CODEX_THREAD_ID", None)
    env.pop("CODEX_CI", None)
    if turn_id is not None:
        env["MEGAPLAN_TURN_ID"] = turn_id
    if actor_id is not None:
        env["MEGAPLAN_ACTOR_ID"] = actor_id
    _apply_worker_state_isolation(env)
    # Seed AFTER worker-state isolation so the final CODEX_HOME the child will
    # read (possibly redirected to a per-worker temp dir) carries valid auth.
    _seed_codex_auth_into_env(env)
    return env


def _external_worker_env(
    turn_id: str | None = None,
    actor_id: str | None = None,
) -> dict[str, str]:
    env = strip_progress_env(os.environ.copy())
    if turn_id is not None:
        env["MEGAPLAN_TURN_ID"] = turn_id
    if actor_id is not None:
        env["MEGAPLAN_ACTOR_ID"] = actor_id
    _apply_worker_state_isolation(env)
    return env


def _merge_partial_output(raw_output: str, output_path: Path) -> str:
    merged = raw_output or ""
    try:
        partial = output_path.read_text(encoding="utf-8").strip()
    except (FileNotFoundError, OSError, UnicodeDecodeError):
        partial = ""
    if partial and partial not in merged:
        if merged and not merged.endswith("\n"):
            merged += "\n"
        merged += "[partial_output_file]\n" + partial
    return merged


def _codex_session_jsonl_path(
    session_id: str, *, codex_home: Path | None = None
) -> Path | None:
    """Locate the rollout JSONL for a given codex session_id.

    Codex stores rollouts at
    ``$CODEX_HOME/sessions/<YYYY>/<MM>/<DD>/rollout-<timestamp>-<session-id>.jsonl``.
    The directory date may not match the call date if a session was created
    earlier and resumed. We glob across all date dirs and return the most
    recently modified match (or ``None`` if none).
    """
    if not session_id:
        return None
    resolved_codex_home = codex_home or Path(
        os.getenv("CODEX_HOME", "").strip() or str(Path.home() / ".codex")
    ).expanduser()
    sessions_root = resolved_codex_home / "sessions"
    if not sessions_root.is_dir():
        return None
    try:
        matches = list(sessions_root.glob(f"*/*/*/rollout-*-{session_id}.jsonl"))
    except OSError:
        return None
    if not matches:
        return None
    try:
        matches.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        pass
    return matches[0]


def _read_codex_total_token_usage(jsonl_path: Path) -> dict[str, Any] | None:
    """Read a codex rollout JSONL and return the latest ``total_token_usage``.

    Scans for ``event_msg`` events of type ``token_count`` and returns the
    ``info.total_token_usage`` blob from the last one with non-null ``info``.
    Returns ``None`` if no usable event is found or the file is unreadable.
    Tolerates malformed/non-JSON lines.
    """
    try:
        text = jsonl_path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError, UnicodeDecodeError):
        return None
    last_usage: dict[str, Any] | None = None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(obj, dict) or obj.get("type") != "event_msg":
            continue
        payload = obj.get("payload")
        if not isinstance(payload, dict) or payload.get("type") != "token_count":
            continue
        info = payload.get("info")
        if not isinstance(info, dict):
            continue
        usage = info.get("total_token_usage")
        if isinstance(usage, dict):
            last_usage = usage
    return last_usage


def _read_codex_observed_model(jsonl_path: Path) -> str | None:
    """Return the latest model genuinely recorded by the Codex rollout."""
    try:
        lines = jsonl_path.read_text(encoding="utf-8").splitlines()
    except (FileNotFoundError, OSError, UnicodeDecodeError):
        return None
    observed: str | None = None
    for line in lines:
        try:
            item = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(item, dict):
            continue
        payload = item.get("payload")
        candidate: Any = None
        if item.get("type") == "turn_context" and isinstance(payload, dict):
            candidate = payload.get("model")
        elif (
            item.get("type") == "event_msg"
            and isinstance(payload, dict)
            and payload.get("type") == "thread_settings_applied"
            and isinstance(payload.get("thread_settings"), dict)
        ):
            candidate = payload["thread_settings"].get("model")
        if isinstance(candidate, str) and candidate.strip():
            observed = candidate.strip()
    return observed


def _read_codex_default_model() -> str | None:
    """Best-effort read of the codex CLI default model from ``config.toml``.

    Returns ``None`` if the config is missing or the model field is absent;
    callers should fall back to :data:`codex_pricing.DEFAULT_MODEL` in that
    case. We do a permissive line-based parse to avoid taking a hard
    dependency on a TOML library just for one key.
    """
    codex_home_str = os.getenv("CODEX_HOME", "").strip() or str(Path.home() / ".codex")
    config_path = Path(codex_home_str).expanduser() / "config.toml"
    try:
        text = config_path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError, UnicodeDecodeError):
        return None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Stop at first table header so we only read top-level model =
        if stripped.startswith("["):
            break
        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        if key.strip() == "model":
            value = value.strip().split("#", 1)[0].strip()
            return value.strip().strip('"').strip("'") or None
    return None


def _codex_step_cost(
    session_id: str | None,
    session_entry: dict[str, Any],
    requested_model: str | None = None,
    *,
    codex_home: Path | None = None,
) -> tuple[float, int, int, str | None, dict[str, Any] | None]:
    """Compute incremental cost (USD) and token deltas for one codex step.

    Looks up the rollout JSONL for ``session_id``, reads the cumulative
    ``total_token_usage``, and subtracts the ``last_total_tokens`` snapshot
    stored on ``session_entry`` (mutated in place to record the new totals).

    Returns ``(cost_usd, prompt_tokens_delta, completion_tokens_delta,
    model, current_total_usage)``. Unknown model rates produce numeric 0.0 for
    existing aggregation code; the caller records the explicit ``unpriced``
    status on the worker result. Missing usage never raises.
    """
    from arnold_pipelines.megaplan.pricing.codex import cost_from_codex_usage_dict

    if not session_id:
        # A requested CLI model is not provider evidence.  In particular, zero
        # recovery must fail closed when no rollout/session can attest it.
        return 0.0, 0, 0, None, None
    path = _codex_session_jsonl_path(session_id, codex_home=codex_home)
    if path is None:
        return 0.0, 0, 0, None, None
    observed_model = _read_codex_observed_model(path)
    current = _read_codex_total_token_usage(path)
    if current is None:
        return 0.0, 0, 0, observed_model, None
    prev = session_entry.get("last_total_tokens") if isinstance(session_entry, dict) else None
    if not isinstance(prev, dict):
        prev = {}

    def _delta(key: str) -> int:
        try:
            cur = int(current.get(key, 0) or 0)
            old = int(prev.get(key, 0) or 0)
        except (TypeError, ValueError):
            return 0
        return max(cur - old, 0)

    delta_usage = {
        "input_tokens": _delta("input_tokens"),
        "cached_input_tokens": _delta("cached_input_tokens"),
        "output_tokens": _delta("output_tokens"),
        "reasoning_output_tokens": _delta("reasoning_output_tokens"),
    }
    pricing_model = observed_model or requested_model or _read_codex_default_model()
    priced_cost = cost_from_codex_usage_dict(delta_usage, pricing_model)
    cost = priced_cost if priced_cost is not None else 0.0
    prompt_tokens = delta_usage["input_tokens"]  # already includes cached
    completion_tokens = (
        delta_usage["output_tokens"] + delta_usage["reasoning_output_tokens"]
    )
    return cost, prompt_tokens, completion_tokens, observed_model, current


def _emit_codex_execute_llm_start(
    plan_dir: Path,
    *,
    model: str | None,
    prompt: str,
    json_trace: bool,
) -> str:
    call_transaction_id = uuid.uuid4().hex
    try:
        from arnold_pipelines.megaplan.observability.events import EventKind, emit

        prompt_hash = (
            hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]
            if prompt
            else None
        )
        emit(
            EventKind.LLM_CALL_START,
            plan_dir=plan_dir,
            phase="execute",
            payload={
                "provider": "codex",
                "model": model,
                "prompt_hash": prompt_hash,
                "streaming": bool(json_trace),
                "request_id": None,
                "call_transaction_id": call_transaction_id,
            },
        )
    except Exception:
        pass
    return call_transaction_id


def _emit_codex_execute_llm_end(
    plan_dir: Path,
    *,
    request_id: str | None,
    model: str | None,
    tokens_in: int,
    tokens_out: int,
    call_transaction_id: str | None = None,
) -> None:
    try:
        from arnold_pipelines.megaplan.observability.events import EventKind, emit

        emit(
            EventKind.LLM_CALL_END,
            plan_dir=plan_dir,
            phase="execute",
            payload={
                "tokens_in": tokens_in,
                "tokens_out": tokens_out,
                "request_id": request_id,
                "model": model,
                "call_transaction_id": call_transaction_id,
            },
        )
    except Exception:
        pass


def _emit_codex_execute_cost_recorded(
    plan_dir: Path,
    *,
    request_id: str | None,
    model: str | None,
    cost_usd: float,
) -> None:
    try:
        from arnold_pipelines.megaplan.observability.events import EventKind, emit

        emit(
            EventKind.COST_RECORDED,
            plan_dir=plan_dir,
            phase="execute",
            payload={
                "request_id": request_id,
                "cost_usd": float(cost_usd),
                "provider": "codex",
                "model": model,
            },
        )
    except Exception:
        pass


def extract_session_id(raw: str) -> str | None:
    # Try structured JSONL first (codex --json emits {"type":"thread.started","thread_id":"..."})
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict) and obj.get("thread_id"):
                return str(obj["thread_id"])
        except (json.JSONDecodeError, ValueError):
            continue
    # Fallback: unstructured text pattern
    match = re.search(r"\bsession[_ ]id[: ]+([0-9a-fA-F-]{8,})", raw)
    return match.group(1) if match else None


def _extract_claude_usage(envelope: dict[str, Any] | None) -> tuple[int, int]:
    """Return ``(prompt_tokens, completion_tokens)`` from a Claude envelope.

    The Claude CLI emits a ``usage`` dict like::

        {
            "input_tokens": 123,
            "cache_read_input_tokens": 456,
            "cache_creation_input_tokens": 78,
            "output_tokens": 90,
        }

    Cached and uncached input are summed into ``prompt_tokens``. Missing or
    non-numeric fields default to ``0``. Returns ``(0, 0)`` if ``envelope``
    is missing or lacks a ``usage`` dict.
    """
    if not isinstance(envelope, dict):
        return 0, 0
    usage = envelope.get("usage")
    if not isinstance(usage, dict):
        return 0, 0

    def _safe_int(value: Any) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    prompt_tokens = (
        _safe_int(usage.get("input_tokens"))
        + _safe_int(usage.get("cache_read_input_tokens"))
        + _safe_int(usage.get("cache_creation_input_tokens"))
    )
    completion_tokens = _safe_int(usage.get("output_tokens"))
    return prompt_tokens, completion_tokens


def parse_claude_envelope(raw: str) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        envelope = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CliError("parse_error", f"Claude output was not valid JSON: {exc}", extra={"raw_output": raw}) from exc
    if isinstance(envelope, dict) and envelope.get("is_error"):
        message = envelope.get("result") or envelope.get("message") or "Claude returned an error"
        lower = str(message).lower()
        error_code = "worker_error"
        if any(pattern in lower for pattern in ("not logged in", "/login", "unauthorized", "authentication")):
            error_code = "auth_error"
        raise CliError(error_code, f"Claude step failed: {message}", extra={"raw_output": raw})
    # When using --json-schema, structured output lives in "structured_output"
    # rather than "result" (which may be empty).
    payload: Any = envelope
    if isinstance(envelope, dict):
        if "structured_output" in envelope and isinstance(envelope["structured_output"], dict):
            payload = envelope["structured_output"]
        elif "result" in envelope:
            payload = envelope["result"]
    if isinstance(payload, str):
        if not payload.strip():
            raise CliError("parse_error", "Claude returned empty result (check structured_output field)", extra={"raw_output": raw})
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise CliError("parse_error", f"Claude result payload was not valid JSON: {exc}", extra={"raw_output": raw}) from exc
    if not isinstance(payload, dict):
        raise CliError("parse_error", "Claude result payload was not an object", extra={"raw_output": raw})
    return envelope, payload


# DeepSeek and Kimi sometimes emit tool markup using ASCII XML tags and
# sometimes using DSML-style tags such as ``<｜DSML｜invoke name="write_file">``.
# Detect both forms so the recovery path can extract the payload instead of
# failing the whole worker turn.
_DSML_PREFIX = "\uff5cDSML\uff5c"
_DEEPSEEK_TOOL_TAG_RE = re.compile(
    rf"<(?P<name>(?:\{_DSML_PREFIX})?(?:read_file|file_read|read|search_files|file_search|search|"
    rf"web_extract|fetch_url|web_search|write_file|file_write|write|edit_file|"
    rf"patch|apply_patch|delete_file|run_command|bash|terminal|invoke|tool_call|"
    rf"tool_calls|tool_result))\b(?P<attrs>[^<>]*)>",
    re.IGNORECASE,
)
_DEEPSEEK_INVOKE_NAME_RE = re.compile(
    r"\bname=[\"'](?P<name>[^\"']+)[\"']",
    re.IGNORECASE,
)
_DEEPSEEK_MUTATING_TOOL_NAMES = frozenset(
    {
        "write_file",
        "file_write",
        "write",
        "edit_file",
        "patch",
        "apply_patch",
        "delete_file",
        "run_command",
        "bash",
        "terminal",
    }
)


def _deepseek_tool_markup_names(raw: str) -> set[str]:
    """Return tool-like XML tag names emitted in assistant text."""
    names: set[str] = set()
    if not raw or "<" not in raw:
        return names
    for match in _DEEPSEEK_TOOL_TAG_RE.finditer(raw):
        name = match.group("name")
        if name.startswith(_DSML_PREFIX):
            name = name[len(_DSML_PREFIX):]
        name = name.lower()
        if name == "invoke":
            invoked = _DEEPSEEK_INVOKE_NAME_RE.search(match.group("attrs") or "")
            if invoked:
                names.add(invoked.group("name").strip().lower())
            else:
                names.add(name)
            continue
        names.add(name)
    return names


def _looks_like_deepseek_tool_markup(raw: str) -> bool:
    return bool(_deepseek_tool_markup_names(raw))


def _contains_mutating_deepseek_tool_markup(raw: str) -> bool:
    return bool(_deepseek_tool_markup_names(raw).intersection(_DEEPSEEK_MUTATING_TOOL_NAMES))


def _critique_repair_context(
    *,
    check_id: str | None = None,
    question: str | None = None,
) -> str:
    bits: list[str] = []
    if check_id:
        bits.append(f"check {check_id!r}")
    if question:
        cleaned = " ".join(str(question).split())
        if cleaned:
            bits.append(f"question {cleaned[:180]!r}")
    return f" ({'; '.join(bits)})" if bits else ""


def _extract_json_candidates_from_raw(raw: str) -> list[dict[str, Any]]:
    """Extract plausible JSON payload objects from raw agent output."""
    # Some models (DeepSeek/Kimi) answer with write-style tool markup containing
    # the JSON payload. Recover that first so downstream extraction sees JSON.
    from arnold_pipelines.megaplan.workers._payload import (
        _deescape_double_encoded_json,
        _extract_json_from_mutating_tool_markup,
    )

    recovered = _extract_json_from_mutating_tool_markup(raw)
    if recovered is not None:
        raw = recovered
    deescaped = _deescape_double_encoded_json(raw)
    if deescaped is not None:
        raw = deescaped

    # GLM on the coding endpoint sometimes double-encodes the JSON payload
    # (backslash-escaped interior quotes). De-escape one layer so the strategies
    # below can see the real object.
    try:
        from arnold_pipelines.megaplan.workers._payload import _deescape_double_encoded_json

        deescaped = _deescape_double_encoded_json(raw)
        if deescaped is not None:
            raw = deescaped
    except Exception:
        pass

    def _iter_nested_json_dicts(value: Any) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        if isinstance(value, dict):
            candidates.append(value)
            prioritized_keys = (
                "structured_output",
                "result",
                "payload",
                "text",
                "message",
            )
            for key in prioritized_keys:
                if key not in value:
                    continue
                nested = value.get(key)
                candidates.extend(_iter_nested_json_dicts(nested))
            for nested in value.values():
                candidates.extend(_iter_nested_json_dicts(nested))
            return candidates
        if isinstance(value, list):
            for item in value:
                candidates.extend(_iter_nested_json_dicts(item))
            return candidates
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("{") or text.startswith("["):
                try:
                    parsed = json.loads(text)
                except json.JSONDecodeError:
                    return []
                return _iter_nested_json_dicts(parsed)
            # Prose-wrapped JSON inside a string field — scan for embedded
            # JSON objects (e.g. assistant message text that prefaces the
            # structured output with a sentence or two). Mirrors strategy 3
            # below but scoped to the string content.
            embedded: list[dict[str, Any]] = []
            decoder = json.JSONDecoder()
            cursor = 0
            while True:
                brace = text.find("{", cursor)
                if brace < 0:
                    break
                try:
                    parsed, _end = decoder.raw_decode(text[brace:])
                except json.JSONDecodeError:
                    cursor = brace + 1
                    continue
                embedded.extend(_iter_nested_json_dicts(parsed))
                cursor = brace + 1
            return embedded
        return []

    candidates: list[dict[str, Any]] = []

    # Strategy 1: look for ```json ... ``` fenced blocks
    fenced = re.findall(r"```json\s*\n(.*?)```", raw, re.DOTALL)
    for block in fenced:
        try:
            obj = json.loads(block.strip())
            candidates.extend(_iter_nested_json_dicts(obj))
        except json.JSONDecodeError:
            continue
    # Strategy 2: parse JSONL/event-stream lines and inspect nested message fields.
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        candidates.extend(_iter_nested_json_dicts(obj))
    # Strategy 3: scan for the first decodable JSON object, even when
    # additional logs/traces are appended after it.
    decoder = json.JSONDecoder()
    search_start = 0
    while True:
        brace_start = raw.find("{", search_start)
        if brace_start < 0:
            break
        try:
            obj, _end = decoder.raw_decode(raw[brace_start:])
        except json.JSONDecodeError:
            search_start = brace_start + 1
            continue
        candidates.extend(_iter_nested_json_dicts(obj))
        search_start = brace_start + 1
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for candidate in candidates:
        try:
            marker = json_dump(candidate)
        except Exception:
            marker = repr(candidate)
        if marker in seen:
            continue
        seen.add(marker)
        deduped.append(candidate)
    return deduped


def _extract_json_from_raw(raw: str) -> dict[str, Any] | None:
    """Return the first plausible JSON object extracted from raw agent output."""
    candidates = _extract_json_candidates_from_raw(raw)
    if candidates:
        return candidates[0]
    return None


def _looks_like_plan_markdown(text: str) -> bool:
    stripped = text.lstrip()
    if not stripped:
        return False
    if stripped.startswith("# "):
        return True
    if "## Overview" in text:
        return True
    return bool(re.search(r"(?m)^#{2,3}\s+Step\s+\d+:\s+.+$", text))


def _extract_plan_capture_input(raw_text: str) -> str | dict[str, Any]:
    candidate = _extract_json_from_raw(raw_text)
    if isinstance(candidate, dict):
        if isinstance(candidate.get("plan"), str):
            return candidate
        if isinstance(candidate.get("steps"), list):
            return candidate
        if isinstance(candidate.get("title"), str) and isinstance(candidate.get("overview"), str):
            return candidate
    if _looks_like_plan_markdown(raw_text):
        from arnold_pipelines.megaplan.model_seam import coerce_plan_markdown_payload

        return coerce_plan_markdown_payload(raw_text)
    return raw_text


def _json_decode_error_for_raw(raw: str) -> json.JSONDecodeError | None:
    """Return a representative JSON decode error for malformed model output."""
    from arnold_pipelines.megaplan.workers._payload import _deescape_double_encoded_json

    text = raw.strip()
    if not text:
        return None
    deescaped = _deescape_double_encoded_json(text)
    if deescaped is not None:
        try:
            json.loads(deescaped)
            return None
        except json.JSONDecodeError:
            pass
    candidates = [text]
    fenced = re.findall(r"```json\s*\n(.*?)```", raw, re.DOTALL)
    candidates.extend(block.strip() for block in fenced if block.strip())
    brace = raw.find("{")
    if brace >= 0:
        candidates.append(raw[brace:].strip())
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            candidates.append(stripped)
    # GLM coding-endpoint double-encoded JSON: if the de-escaped form parses
    # cleanly, the output is not malformed, so do not report a decode error.
    try:
        from arnold_pipelines.megaplan.workers._payload import _deescape_double_encoded_json

        deescaped = _deescape_double_encoded_json(raw)
        if deescaped is not None:
            try:
                json.loads(deescaped)
                return None
            except json.JSONDecodeError:
                candidates.insert(0, deescaped)
    except Exception:
        pass
    for candidate in candidates:
        try:
            json.loads(candidate)
        except json.JSONDecodeError as exc:
            return exc
        except (TypeError, ValueError):
            continue
    return None


def _codex_repair_input(
    raw_transport: str,
    canonical_output: str,
) -> tuple[str, json.JSONDecodeError | None]:
    """Select and diagnose the same Codex response source used by capture.

    With ``--json`` the transport is JSONL and therefore is not itself one
    model response.  The ``-o`` file is canonical whenever it is non-empty.
    """

    # JSONL is evidence about the invocation, not a substitute response.  In
    # particular, feeding it to semantic repair gives the model a truncated
    # event stream instead of the object that failed the contract.
    repair_raw = canonical_output
    return repair_raw, _json_decode_error_for_raw(repair_raw)


def _codex_terminal_message_candidates(raw_transport: str) -> list[str]:
    """Extract only terminal assistant-message bodies from Codex JSONL.

    Tool results and event payloads can themselves contain arbitrary JSON.
    Broad recursive candidate recovery therefore cannot establish which text
    Codex selected as its final response.  This recognises only the documented
    assistant-message event shapes and leaves an absent event as explicitly
    unavailable evidence.
    """

    candidates: list[str] = []
    for line in raw_transport.splitlines():
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(event, dict):
            continue
        event_type = event.get("type")
        item = event.get("item")
        if event_type == "item.completed" and isinstance(item, dict):
            if item.get("type") == "agent_message" and isinstance(item.get("text"), str):
                candidates.append(item["text"])
            continue
        if event_type == "agent_message" and isinstance(event.get("text"), str):
            candidates.append(event["text"])
            continue
        if event_type in {"message.completed", "response.output_text.done"}:
            text_value = event.get("text") or event.get("output_text")
            if isinstance(text_value, str):
                candidates.append(text_value)
    return candidates


def _select_codex_terminal_output(raw_transport: str, output_raw: str) -> str:
    """Select the exact ``-o`` response and cross-check JSONL when possible."""

    if not output_raw.strip():
        raise ModelStructuralAuditError(
            "Codex selected terminal output file is empty; JSONL transport is not a response fallback"
        )
    selected = output_raw.strip()
    # Tool-using Codex turns legitimately emit intermediate agent_message
    # items before commands.  The CLI's ``-o/--output-last-message`` contract
    # selects the last assistant message, so cross-check that ordered terminal
    # value rather than treating earlier progress messages as ambiguity.
    candidates = [
        candidate.strip()
        for candidate in _codex_terminal_message_candidates(raw_transport)
        if candidate.strip()
    ]
    if candidates and candidates[-1] != selected:
        raise ModelStructuralAuditError(
            "Codex selected terminal output does not equal the last JSONL assistant message"
        )
    return output_raw


def _new_response_occurrence(
    state: PlanState,
    plan_dir: Path,
    *,
    step: str,
) -> dict[str, Any]:
    """Mint an occurrence identity bound to plan, invocation, phase and WBC."""

    binding = _WORKER_DISPATCH_BINDING.get() or {}
    active = state.get("active_step")
    meta = state.get("meta")
    invocation_id = None
    # The phase and worker WBC identities are minted from the canonical
    # invocation stored in state.meta.  ``active_step.run_id`` is only the
    # process-liveness fence and must not be mislabeled as that invocation.
    if isinstance(meta, dict):
        invocation_id = meta.get("current_invocation_id")
    if not invocation_id and isinstance(active, dict):
        orphan_fence = active.get("orphan_fence")
        if isinstance(orphan_fence, dict):
            invocation_id = orphan_fence.get("invocation_id")
        invocation_id = invocation_id or active.get("invocation_id") or active.get("run_id")
    material = {
        "plan_name": str(state.get("name") or plan_dir.name),
        "plan_dir": str(plan_dir.resolve()),
        "phase": step,
        "plan_iteration": int(state.get("iteration") or 0),
        "invocation_id": str(invocation_id or "unavailable"),
        "phase_wbc_attempt_id": str(
            binding.get("phase_wbc_attempt_id") or "unavailable"
        ),
        "worker_wbc_attempt_id": str(
            binding.get("worker_wbc_attempt_id") or "unavailable"
        ),
        "nonce": uuid.uuid4().hex,
    }
    material["occurrence_id"] = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return material


def _response_output_path(
    plan_dir: Path,
    *,
    step: str,
    occurrence_id: str,
    repair_ordinal: int,
) -> Path:
    """Return a fresh per-occurrence ``-o`` path; primary and repair never alias."""

    safe_step = re.sub(r"[^a-zA-Z0-9_.-]", "-", step).strip(".-") or "step"
    path = _project_local_tmp_dir(plan_dir) / (
        f"response-{safe_step}-{occurrence_id}-r{repair_ordinal}.json"
    )
    if path.exists() or path.is_symlink():
        raise CliError(
            "local_response_contract",
            "fresh per-occurrence Codex response output unexpectedly already exists",
        )
    return path


def _write_response_evidence_blob(path: Path, data: bytes) -> None:
    """Create one immutable content-addressed evidence blob."""

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        if path.read_bytes() != data:
            raise CliError(
                "local_response_contract",
                "content-addressed Codex response evidence digest collision",
            )
        return
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _persist_codex_response_evidence(
    plan_dir: Path,
    *,
    occurrence: dict[str, Any],
    repair_ordinal: int,
    raw_transport: str,
    terminal_output: str,
    output_path: Path,
    model: str | None,
    selection_error: Exception | None,
) -> dict[str, Any]:
    """Persist hash-addressed transport, terminal output and selection receipt."""

    evidence_root = plan_dir / ".megaplan" / "model-response-evidence"
    objects = evidence_root / "objects"

    def _blob(value: str, suffix: str) -> dict[str, Any] | None:
        data = value.encode("utf-8")
        if not data:
            return None
        digest = hashlib.sha256(data).hexdigest()
        blob_path = objects / f"{digest}.{suffix}"
        _write_response_evidence_blob(blob_path, data)
        return {
            "sha256": f"sha256:{digest}",
            "bytes": len(data),
            "path": str(blob_path.relative_to(plan_dir)),
        }

    transport = _blob(raw_transport, "jsonl")
    selected = _blob(terminal_output, "json")
    receipt = {
        "schema": "arnold.megaplan.codex-response-evidence.v1",
        "occurrence": dict(occurrence),
        "repair_ordinal": repair_ordinal,
        "phase": occurrence["phase"],
        "plan_name": occurrence["plan_name"],
        "invocation_id": occurrence["invocation_id"],
        "phase_wbc_attempt_id": occurrence["phase_wbc_attempt_id"],
        "worker_wbc_attempt_id": occurrence["worker_wbc_attempt_id"],
        "model": model,
        "output_path": str(output_path),
        "transport": transport,
        "selected_terminal_output": selected,
        "selection_status": "accepted" if selection_error is None else "rejected",
        "selection_error": str(selection_error) if selection_error is not None else None,
    }
    receipt_path = (
        evidence_root
        / "occurrences"
        / occurrence["occurrence_id"]
        / f"repair-{repair_ordinal}.json"
    )
    if receipt_path.exists() or receipt_path.is_symlink():
        raise CliError(
            "local_response_contract",
            "Codex response evidence receipt already exists for this occurrence ordinal",
        )
    atomic_write_json(receipt_path, receipt)
    return {
        "receipt_path": str(receipt_path.relative_to(plan_dir)),
        "receipt_sha256": "sha256:"
        + hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        **receipt,
    }


def _build_response_contract_repair_prompt(
    *,
    step: str,
    schema: dict[str, Any],
    failure_reason: str,
    selected_output: str,
) -> str:
    """Build one semantic repair from the full selected object and schema."""

    return (
        "Your previous selected response failed the canonical local response contract.\n"
        f"Phase: {step}\n"
        f"Structural audit: {failure_reason}\n\n"
        "Return ONLY one corrected JSON object. Do not use Markdown, prose, NDJSON, "
        "or an event stream. Preserve all valid content while fixing the exact contract "
        "violations.\n\nCanonical JSON Schema (complete):\n"
        + json.dumps(schema, sort_keys=True, ensure_ascii=False)
        + "\n\nSelected response to repair (complete):\n"
        + selected_output
    )


def _build_json_repair_prompt(error: json.JSONDecodeError, raw: str) -> str:
    prompt = (
        f"Your previous output was not valid JSON (error at line {error.lineno} "
        f"col {error.colno}). Re-emit ONLY a single JSON object matching the "
        "required schema. Escape every backslash as `\\\\` (e.g. write a regex "
        "as `clarify\\\\s*\\\\(`). No prose, no code fences."
    )
    raw = raw.strip()
    if raw:
        prompt += "\n\nPrevious output to repair:\n" + raw[-20000:]
    return prompt


def _recover_payload_from_candidates(
    step: str,
    candidates: list[dict[str, Any]],
    *,
    raw: str,
    validate: bool,
) -> dict[str, Any] | None:
    validation_errors: list[str] = []
    for candidate in candidates:
        if not validate:
            return dict(candidate)
        payload = _normalize_step_payload_for_audit(step, dict(candidate))
        try:
            audit_step_payload(step, payload)
        except ModelStructuralAuditError as error:
            if _looks_like_step_payload(step, payload):
                validation_errors.append(error.details)
            continue
        return payload
    if validation_errors:
        unique_errors = list(dict.fromkeys(validation_errors))
        raise CliError(
            "parse_error",
            f"Repaired JSON object for {step} failed validation: "
            + " | ".join(unique_errors),
            extra={"raw_output": raw, "model_output_parse_error": True},
        )
    return None


def _repair_worker_json_once(
    step: str,
    raw: str,
    repair_call: Callable[[str], str],
    *,
    parse_error: json.JSONDecodeError | None = None,
    validate: bool = True,
    output_path: Path | None = None,
    template_unchanged: bool = False,
    check_id: str | None = None,
    question: str | None = None,
) -> tuple[dict[str, Any], str] | None:
    error = parse_error or _json_decode_error_for_raw(raw)
    if error is None:
        return None
    repaired_raw = repair_call(_build_json_repair_prompt(error, raw))
    repaired_candidates = _extract_json_candidates_from_raw(repaired_raw)
    if (
        step == "critique"
        and _looks_like_deepseek_tool_markup(repaired_raw)
        and repaired_candidates
        and not any(_looks_like_step_payload(step, candidate) for candidate in repaired_candidates)
    ):
        context = _critique_repair_context(check_id=check_id, question=question)
        raise CliError(
            "parse_error",
            "Repair retry for critique did not return a critique JSON object"
            f"{context}: model emitted unsupported tool-call markup; critique template unchanged",
            extra={
                "raw_output": repaired_raw,
                "model_output_parse_error": True,
                "unsupported_tool_call_markup": True,
                "critique_template_unchanged": True,
                **({"check_id": check_id} if check_id else {}),
                **({"question": question} if question else {}),
            },
        )
    payload = _recover_payload_from_candidates(
        step,
        repaired_candidates,
        raw=repaired_raw,
        validate=validate,
    )
    if payload is None:
        repaired_error = _json_decode_error_for_raw(repaired_raw)
        location = (
            f" at line {repaired_error.lineno} col {repaired_error.colno}"
            if repaired_error is not None
            else ""
        )
        if step == "critique" and (
            _looks_like_deepseek_tool_markup(raw)
            or _looks_like_deepseek_tool_markup(repaired_raw)
            or template_unchanged
        ):
            context = _critique_repair_context(check_id=check_id, question=question)
            template_detail = (
                f"; critique template unchanged at {output_path.name}"
                if template_unchanged and output_path is not None
                else "; critique template unchanged"
                if template_unchanged
                else ""
            )
            mutating_detail = (
                "; unsupported write operation rejected"
                if _contains_mutating_deepseek_tool_markup(raw)
                or _contains_mutating_deepseek_tool_markup(repaired_raw)
                else ""
            )
            raise CliError(
                "parse_error",
                "Repair retry for critique did not return valid JSON"
                f"{location}{context}: model emitted unsupported tool-call markup"
                f"{template_detail}{mutating_detail}",
                extra={
                    "raw_output": repaired_raw,
                    "model_output_parse_error": True,
                    "unsupported_tool_call_markup": True,
                    "critique_template_unchanged": template_unchanged,
                    **({"check_id": check_id} if check_id else {}),
                    **({"question": question} if question else {}),
                },
            )
        raise CliError(
            "parse_error",
            f"Repair retry for {step} did not return valid JSON{location}",
            extra={"raw_output": repaired_raw, "model_output_parse_error": True},
        )
    return payload, repaired_raw


def _looks_like_step_payload(step: str, payload: dict[str, Any]) -> bool:
    required = set(_STEP_REQUIRED_KEYS.get(step, []))
    if required.intersection(payload):
        return True
    if step == "execute" and {"task_updates", "sense_check_acknowledgments"}.intersection(payload):
        return True
    return False


def parse_json_file(path: Path) -> dict[str, Any]:
    try:
        payload = read_json(path)
    except FileNotFoundError as exc:
        raise CliError("parse_error", f"Output file {path.name} was not created") from exc
    except json.JSONDecodeError as exc:
        raise CliError("parse_error", f"Output file {path.name} was not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise CliError("parse_error", f"Output file {path.name} did not contain a JSON object")
    return payload


def _normalize_step_payload_for_audit(step: str, payload: dict[str, Any]) -> dict[str, Any]:
    if step != "critique":
        return payload
    checks = payload.get("checks")
    if not isinstance(checks, list):
        return payload
    changed = False
    clean_checks: list[Any] = []
    for check in checks:
        if not isinstance(check, dict):
            clean_checks.append(check)
            continue
        findings = check.get("findings")
        if not isinstance(findings, list):
            clean_checks.append(check)
            continue
        clean_findings: list[Any] = []
        check_changed = False
        for finding in findings:
            if not isinstance(finding, dict):
                clean_findings.append(finding)
                continue
            extra_keys = set(finding) - {"detail", "flagged"}
            if extra_keys:
                finding = {k: v for k, v in finding.items() if k in {"detail", "flagged"}}
                check_changed = True
            clean_findings.append(finding)
        if check_changed:
            check = dict(check)
            check["findings"] = clean_findings
            changed = True
        clean_checks.append(check)
    if not changed:
        return payload
    clean_payload = dict(payload)
    clean_payload["checks"] = clean_checks
    return clean_payload


def _mock_result(
    payload: dict[str, Any],
    *,
    trace_output: str | None = None,
) -> WorkerResult:
    return WorkerResult(
        payload=payload,
        raw_output=json_dump(payload),
        duration_ms=10,
        cost_usd=0.0,
        session_id=str(uuid.uuid4()),
        trace_output=trace_output,
    )


# Steps the mock worker supports, in declaration order. The trace stub
# only fires for the two execute-shaped steps; everything else gets an
# empty trace. Update both sets to add a new step.
_MOCK_SUPPORTED_STEPS: tuple[str, ...] = (
    "plan", "prep", "prep-triage", "prep-research", "prep-distill", "loop_plan",
    "critique_evaluator", "critique", "revise", "gate", "finalize",
    "execute", "loop_execute", "review",
)
_MOCK_TRACE_OUTPUTS: dict[str, str] = {
    "execute": '{"event":"mock-execute"}\n',
    "loop_execute": '{"event":"mock-loop-execute"}\n',
}


def _mock_step(
    step: str,
    state: PlanState,
    plan_dir: Path,
    *,
    prompt_override: str | None = None,
) -> WorkerResult:
    """Build the canonical mock WorkerResult for ``step``.

    ``step == "execute"`` writes the IMPLEMENTED_BY_MEGAPLAN.txt sentinel
    into the project directory — the only side effect any of the mock
    handlers performed. Execute-shaped steps thread ``prompt_override``
    through; the rest ignore it.
    """
    if step not in _MOCK_SUPPORTED_STEPS:
        raise CliError("unsupported_step", f"Mock worker does not support '{step}'")
    if step == "execute":
        target = Path(state["config"]["project_dir"]) / "IMPLEMENTED_BY_MEGAPLAN.txt"
        target.write_text("mock execution completed\n", encoding="utf-8")
    if step in _EXECUTE_STEPS:
        payload = _build_mock_payload(step, state, plan_dir, prompt_override=prompt_override)
    else:
        payload = _build_mock_payload(step, state, plan_dir)
    return _mock_result(payload, trace_output=_MOCK_TRACE_OUTPUTS.get(step))


def _check_mock_safe() -> None:
    """Raise if MOCK_WORKERS is set but the process is not running under pytest.

    A stale ``MEGAPLAN_MOCK_WORKERS=1`` env var in a production context would
    silently produce synthetic output trusted as real.  This guard ensures the
    mock shortcut only engages inside a test run.
    """
    if "PYTEST_CURRENT_TEST" not in os.environ:
        raise CliError(
            "mock_worker_blocked",
            "MEGAPLAN_MOCK_WORKERS is set but the process is not running "
            "under pytest. Refusing to produce synthetic output in a "
            "non-test context. Unset MEGAPLAN_MOCK_WORKERS to run real "
            "workers.",
        )


def mock_worker_output(
    step: str,
    state: PlanState,
    plan_dir: Path,
    *,
    prompt_override: str | None = None,
    prompt_kwargs: dict[str, Any] | None = None,
) -> WorkerResult:
    del prompt_kwargs
    result = _mock_step(step, state, plan_dir, prompt_override=prompt_override)
    try:
        root = _resolve_prompt_root(plan_dir, None)
        schema_path = schemas_root(root) / STEP_SCHEMA_FILENAMES[step]
        schema = read_json(schema_path) if schema_path.exists() else None
        side_effect_paths = (
            plan_dir / "critique_output.json",
            plan_dir / "review_output.json",
        )
        preexisting_paths = {path for path in side_effect_paths if path.exists()}
        result.rendered_prompt = render_prompt_for_dispatch(
            "omp",
            step,
            state,
            plan_dir,
            root=root,
            schema=schema,
            prompt_override=prompt_override,
        ).prompt
        for path in side_effect_paths:
            if path.exists() and path not in preexisting_paths:
                path.unlink()
    except Exception:
        result.rendered_prompt = prompt_override
    return result


def _normalize_shannon_session_channel(worker_channel: str | None) -> str | None:
    if worker_channel in {None, ""}:
        return None
    normalized = str(worker_channel).strip().lower().replace("-", "_")
    if normalized in {"shannon_stream", "stream", "stream_json", "native_stream"}:
        return "stream_json"
    if normalized in {"shannon", "tmux", "interactive_tmux"}:
        return "tmux"
    return normalized


def _shannon_session_identity_suffix(
    *,
    worker_channel: str | None,
    auth_channel: str | None,
    auth_metadata: dict[str, Any] | None,
) -> str | None:
    channel = _normalize_shannon_session_channel(worker_channel)
    if channel is None:
        return None
    metadata = auth_metadata if isinstance(auth_metadata, dict) else {}
    auth = str(auth_channel or metadata.get("auth_channel") or "subscription")
    auth = auth.strip().lower().replace("-", "_")
    if auth in {"", "oauth"}:
        auth = "subscription"

    # Historical Shannon session keys were tmux/subscription keys. Keep that
    # exact spelling as the compatibility/migration path; all other Shannon
    # channel identities get an explicit suffix so stream/tmux cannot cross-resume.
    if channel == "tmux" and auth == "subscription":
        return None

    parts = [channel, auth]
    if auth == "api_key":
        dry_run = bool(metadata.get("dry_run"))
        source = metadata.get("api_key_source")
        parts.append("dry_run" if dry_run else "live")
        if source:
            digest = hashlib.sha256(str(source).encode("utf-8")).hexdigest()[:8]
            parts.append(digest)
    return "_".join(parts)


def session_key_for(
    step: str,
    agent: str,
    model: str | None = None,
    *,
    worker_channel: str | None = None,
    auth_channel: str | None = None,
    auth_metadata: dict[str, Any] | None = None,
) -> str:
    if step in {"plan", "revise"}:
        key = f"{agent}_planner"
    elif step == "critique":
        key = f"{agent}_critic"
    elif step == "gate":
        key = f"{agent}_gatekeeper"
    elif step == "finalize":
        key = f"{agent}_finalizer"
    elif step == "execute":
        key = f"{agent}_executor"
    elif step == "review":
        key = f"{agent}_reviewer"
    else:
        key = f"{agent}_{step}"
    if agent in {"shannon", "claude"}:
        channel_suffix = _shannon_session_identity_suffix(
            worker_channel=worker_channel,
            auth_channel=auth_channel,
            auth_metadata=auth_metadata,
        )
        if channel_suffix:
            key += f"_{channel_suffix}"
    if model:
        key += f"_{hashlib.sha256(model.encode()).hexdigest()[:8]}"
    return key


def update_session_state(
    step: str,
    agent: str,
    session_id: str | None,
    *,
    mode: str,
    refreshed: bool,
    model: str | None = None,
    existing_sessions: dict[str, Any] | None = None,
    worker_channel: str | None = None,
    auth_channel: str | None = None,
    auth_metadata: dict[str, Any] | None = None,
) -> tuple[str, SessionInfo] | None:
    """Build a session entry for the given step.

    Returns ``(key, entry)`` so the caller can store it on the state dict,
    or ``None`` when there is no session_id to record.
    """
    if not session_id:
        return None
    key = session_key_for(
        step,
        agent,
        model=model,
        worker_channel=worker_channel,
        auth_channel=auth_channel,
        auth_metadata=auth_metadata,
    )
    if existing_sessions is None:
        existing_sessions = {}
    entry = {
        "id": session_id,
        "mode": mode,
        "created_at": existing_sessions.get(key, {}).get("created_at", now_utc()),
        "last_used_at": now_utc(),
        "refreshed": refreshed,
    }
    if worker_channel is not None:
        entry["worker_channel"] = _normalize_shannon_session_channel(worker_channel) or worker_channel
    if auth_channel is not None:
        entry["auth_channel"] = str(auth_channel).strip().lower().replace("-", "_")
    if auth_metadata is not None:
        entry["auth_metadata"] = dict(auth_metadata)
    existing_entry = existing_sessions.get(key, {})
    if (
        isinstance(existing_entry, dict)
        and existing_entry.get("id") == session_id
        and isinstance(existing_entry.get("last_total_tokens"), dict)
    ):
        entry["last_total_tokens"] = dict(existing_entry["last_total_tokens"])
    return key, entry


_VALID_CLAUDE_EFFORTS = {"low", "medium", "high", "xhigh", "max"}
_VALID_CODEX_EFFORTS = ("minimal", "low", "medium", "high", "xhigh", "max")


def _normalize_codex_effort(effort: str | None) -> str | None:
    """Preserve an explicitly requested Codex effort without silent clamping."""

    return effort


def _codex_effort_flag(effort: str | None) -> list[str]:
    """Build the exact Codex CLI effort flag, preserving xhigh/max."""

    effort = _normalize_codex_effort(effort)
    if effort is None:
        return []
    if effort not in _VALID_CODEX_EFFORTS:
        raise CliError("invalid_args", f"Unsupported codex effort level: {effort}")
    return ["-c", f"model_reasoning_effort={effort}"]


def _codex_model_flag(model: str | None) -> list[str]:
    """Build the ``-c model='...'`` codex flag, validating *model* first.

    Last-line-of-defense gate at the dispatch site: an upstream mis-parse
    (e.g. the historical ``codex:claude:sonnet`` bug, which yielded
    ``model='claude'``) must never be passed verbatim to the codex CLI as
    ``-c model='claude'``. ``parse_agent_spec`` now rejects such specs at the
    chokepoint, but this guard ensures the invariant holds even for callers
    that build a model string by another path. Returns an empty list when
    *model* is ``None`` (codex uses its configured default).
    """
    if model is None:
        return []
    from arnold_pipelines.megaplan.types import _is_codex_model_name

    if not _is_codex_model_name(model):
        raise CliError(
            "invalid_codex_model",
            f"Refusing to launch codex with model={model!r}: not a recognised "
            f"codex/GPT-5.x model. This usually means a malformed agent spec "
            f"(e.g. 'codex:claude:sonnet') reached dispatch. Fix the phase_model "
            f"pin (e.g. via `megaplan override set-model` / `set-vendor`).",
        )
    return ["-c", f"model='{model}'"]


def _run_claude_step_uncapped(
    step: str,
    state: PlanState,
    plan_dir: Path,
    *,
    root: Path,
    fresh: bool,
    prompt_override: str | None = None,
    prompt_kwargs: dict[str, Any] | None = None,
    effort: str | None = None,
    model: str | None = None,
    output_path: Path | None = None,
) -> WorkerResult:
    """Compatibility wrapper: the public ``claude`` route runs via the native
    ``claude --print`` worker (workers/claude.py)."""
    if effort is not None and effort not in _VALID_CLAUDE_EFFORTS:
        raise CliError("invalid_args", f"Unsupported claude effort level: {effort}")
    from arnold_pipelines.megaplan.workers.claude import (
        run_claude_step as _run_claude_native,
    )

    return _run_claude_native(
        step,
        state,
        plan_dir,
        root=root,
        fresh=fresh,
        prompt_override=prompt_override,
        prompt_kwargs=prompt_kwargs,
        effort=effort,
        model=model,
        read_only=False,
        output_path=output_path,
    )


def run_claude_step(
    step: str,
    state: PlanState,
    plan_dir: Path,
    *,
    root: Path,
    fresh: bool,
    prompt_override: str | None = None,
    prompt_kwargs: dict[str, Any] | None = None,
    effort: str | None = None,
    model: str | None = None,
    output_path: Path | None = None,
) -> WorkerResult:
    return _run_claude_step_uncapped(
        step,
        state,
        plan_dir,
        root=root,
        fresh=fresh,
        prompt_override=prompt_override,
        prompt_kwargs=prompt_kwargs,
        effort=effort,
        model=model,
        output_path=output_path,
    )


def _prepare_codex_response_contract(
    *,
    schema: dict[str, Any],
    plan_dir: Path,
    step: str,
    model: str | None,
    provider_schema_available: bool,
) -> tuple[CompiledResponseContract, Path | None]:
    """Compile, persist, and expose one Codex response-enforcement decision."""

    contract = compile_response_contract(
        schema,
        provider="codex",
        model=model,
        phase=step,
        provider_schema_available=provider_schema_available,
    )
    persist_response_enforcement_attestation(plan_dir, contract.attestation)
    transport_path: Path | None = None
    if contract.transport_schema is not None:
        transport_path = _project_local_tmp_dir(plan_dir) / (
            f"response-schema-{step}-{contract.attestation.transport_schema_hash}.json"
        )
        atomic_write_json(transport_path, contract.transport_schema)
    print(
        "[megaplan] response enforcement "
        f"phase={step} mode={contract.attestation.response_enforcement} "
        f"reason={contract.attestation.enforcement_reason}",
        flush=True,
    )
    return contract, transport_path


def _codex_response_schema_args(transport_schema_file: Path | None) -> list[str]:
    """Return Codex response arguments for the selected enforcement mode."""

    if transport_schema_file is None:
        return ["-"]
    return ["--output-schema", str(transport_schema_file), "-"]


def _is_codex_provider_schema_rejection(raw: str) -> bool:
    """Recognize a backend rejection of the submitted response schema."""

    lowered = raw.lower()
    return bool(
        "invalid_json_schema" in lowered
        or (
            ("output schema" in lowered or "response_format" in lowered)
            and (
                "invalid schema" in lowered
                or "http 400" in lowered
                or "invalid_request_error" in lowered
            )
        )
    )


def _codex_provider_contract_error(
    contract: CompiledResponseContract,
    raw: str,
) -> CliError:
    """Return the typed, stable failure for a rejected compiled schema."""

    attestation = contract.attestation
    material = {
        "compiler_version": attestation.compiler_version,
        "provider": attestation.provider,
        "model": attestation.model,
        "phase": attestation.phase,
        "canonical_schema_hash": attestation.canonical_schema_hash,
        "transport_schema_hash": attestation.transport_schema_hash,
        "failure_class": "provider_schema_rejected",
    }
    fingerprint = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    message = (
        "Codex rejected the compiled response schema before model execution; "
        "an identical request is non-retryable"
    )
    return CliError(
        "provider_contract",
        message,
        extra={
            "raw_output": raw,
            "_external_error": {
                "provider": "codex",
                "error_kind": "provider_contract",
                "message": message,
                "error_layer": "schema_error",
                "deterministic": True,
                "nonretryable": True,
                "failure_fingerprint": fingerprint,
            },
            "response_enforcement_attestation": attestation.to_json(),
        },
    )


def _prepare_local_strict_artifact_handoff(
    plan_dir: Path,
    *,
    step: str,
) -> dict[str, Any]:
    """Mint one non-reusable candidate path for a local-strict invocation."""

    root = (_project_local_tmp_dir(plan_dir) / _LOCAL_STRICT_ARTIFACT_DIRNAME).absolute()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root_stat = os.lstat(root)
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        raise CliError(
            "local_response_contract",
            "local-strict artifact handoff root is not a real directory",
        )
    root = root.resolve(strict=True)
    safe_step = re.sub(r"[^a-zA-Z0-9_.-]", "-", step).strip(".-") or "step"
    candidate = root / f"{safe_step}-{uuid.uuid4().hex}.candidate.json"
    if candidate.exists() or candidate.is_symlink():
        raise CliError(
            "local_response_contract",
            "fresh local-strict artifact candidate unexpectedly already exists",
        )
    return {
        "schema": LOCAL_STRICT_ARTIFACT_RECEIPT_SCHEMA,
        "root": str(root),
        "candidate_path": str(candidate),
        "max_bytes": DEFAULT_LOCAL_STRICT_ARTIFACT_MAX_BYTES,
    }


def _preflight_trusted_container_artifact_handoff(handoff: dict[str, Any]) -> None:
    """Prove the trusted-container handoff supports atomic non-empty publish.

    The environment flag remains an explicit operator assertion; this check
    neither infers nor enables trust.  Once asserted, we fail before model
    dispatch unless the exact handoff filesystem can create, fsync, rename,
    read and remove a non-empty regular file without traversing symlinks.
    """

    if not _trusted_container():
        raise CliError(
            "local_response_contract",
            "trusted-container artifact handoff preflight requires explicit MEGAPLAN_TRUSTED_CONTAINER",
        )
    root = Path(str(handoff.get("root") or ""))
    candidate = Path(str(handoff.get("candidate_path") or ""))
    if not root.is_absolute() or candidate.parent != root:
        raise CliError(
            "local_response_contract",
            "trusted-container artifact handoff preflight received an invalid path binding",
        )
    probe_target = root / f".handoff-canary-{uuid.uuid4().hex}.json"
    probe_tmp = root / f".{probe_target.name}.tmp-{uuid.uuid4().hex}"
    payload = b'{"handoff":"atomic-nonempty"}\n'
    try:
        fd = os.open(probe_tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(probe_tmp, probe_target)
        observed = os.lstat(probe_target)
        if (
            not stat.S_ISREG(observed.st_mode)
            or stat.S_ISLNK(observed.st_mode)
            or observed.st_nlink != 1
            or observed.st_size != len(payload)
            or probe_target.read_bytes() != payload
        ):
            raise OSError("atomic handoff canary did not round-trip exactly")
    except OSError as error:
        raise CliError(
            "local_response_contract",
            "trusted-container filesystem cannot provide an atomic non-empty artifact handoff",
            extra={"handoff_root": str(root), "pre_dispatch": True},
        ) from error
    finally:
        for path in (probe_tmp, probe_target):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass


def _local_response_contract_error(
    *,
    step: str,
    schema: dict[str, Any],
    reason: str,
    raw: str,
    attempts: int = 2,
    occurrence: dict[str, Any] | None = None,
    evidence: dict[str, Any] | None = None,
) -> CliError:
    """Return the terminal receipt after this occurrence used its one repair."""

    from arnold_pipelines.megaplan.provider_response import schema_sha256

    occurrence_material = {
        "phase": step,
        "canonical_schema_hash": schema_sha256(schema),
        "failure_class": "local_response_contract",
    }
    occurrence_id = str(
        (occurrence or {}).get("occurrence_id")
        or hashlib.sha256(
            json.dumps(
                {**occurrence_material, "nonce": uuid.uuid4().hex},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    )
    material = {
        **occurrence_material,
        "reason": reason,
    }
    fingerprint = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if attempts <= 1:
        message = (
            f"Codex {step} output failed the local response custody contract; "
            "semantic repair is forbidden because no unambiguous selected response exists"
        )
    else:
        message = (
            f"Codex {step} output failed the local response contract after the "
            "single occurrence-scoped repair; repeating the unchanged phase is forbidden"
        )
    return CliError(
        "local_response_contract",
        message,
        extra={
            "raw_output": raw,
            "local_response_contract": {
                "attempts": attempts,
                "repairs": max(0, attempts - 1),
                "max_attempts": 2,
                "exhausted": True,
                "occurrence_id": occurrence_id,
                "failure_fingerprint": fingerprint,
                "occurrence": dict(occurrence or {}),
                "evidence_receipt": (
                    evidence.get("receipt_path") if isinstance(evidence, dict) else None
                ),
            },
            "_external_error": {
                "provider": "codex",
                "error_kind": "local_response_contract",
                "message": message,
                "error_layer": "model_output",
                "deterministic": True,
                "nonretryable": True,
                "failure_fingerprint": fingerprint,
            },
        },
    )


def _run_codex_step_uncapped(
    step: str,
    state: PlanState,
    plan_dir: Path,
    *,
    root: Path,
    persistent: bool,
    fresh: bool = False,
    json_trace: bool = False,
    prompt_override: str | None = None,
    prompt_kwargs: dict[str, Any] | None = None,
    effort: str | None = None,
    model: str | None = None,
    read_only: bool = False,
    output_path: Path | None = None,
    repair_attempted: bool = False,
    free_text: bool = False,
    response_occurrence: dict[str, Any] | None = None,
) -> WorkerResult:
    if read_only and step not in {"prep-triage", "prep-distill", "critique", "review"}:
        raise CliError(
            "unsupported_step",
            f"Codex read-only runner does not support '{step}'",
        )
    effort = _normalize_codex_effort(effort)
    if effort is not None and effort not in _VALID_CODEX_EFFORTS:
        raise CliError("invalid_args", f"Unsupported codex effort level: {effort}")
    fresh = fresh or step not in _CROSS_CALL_PERSISTENT_STEPS
    if step == "execute" and os.getenv("MEGAPLAN_CODEX_EXECUTE_PERSIST_SESSION") != "1":
        fresh = True
    if os.getenv(MOCK_ENV_VAR) == "1":
        _check_mock_safe()
        return mock_worker_output(step, state, plan_dir, prompt_override=prompt_override, prompt_kwargs=prompt_kwargs)
    response_occurrence = response_occurrence or _new_response_occurrence(
        state, plan_dir, step=step
    )
    repair_ordinal = 1 if repair_attempted else 0
    work_dir = resolve_work_dir(state)
    execution_env = resolve_execution_environment(root=root, state=state)
    sandbox_fingerprint = (
        "read-only"
        if read_only
        else _codex_sandbox_fingerprint(work_dir, state, execution_env)
    )
    if not read_only:
        _guard_mutating_worker_launch(step, state, root)
    plan_mode = state["config"].get("mode", "code")
    codex_schema_name = (
        get_execution_schema_key(plan_mode, form=creative_form_id(state))
        if step == "execute"
        else STEP_SCHEMA_FILENAMES[step]
    )
    schema_file = schemas_root(root) / codex_schema_name
    session_key = session_key_for(step, "codex", model=model)
    session = state["sessions"].get(session_key, {})
    if persistent and step == "execute" and session.get("id") and not fresh:
        prior_fingerprint = session.get("sandbox_fingerprint")
        if prior_fingerprint and prior_fingerprint != sandbox_fingerprint:
            print(
                f"[megaplan] Codex executor session {session['id']} sandbox "
                "fingerprint changed; starting execute with a fresh session",
                flush=True,
            )
            state["sessions"].pop(session_key, None)
            session = {}
            fresh = True
    if fresh and persistent and step == "execute" and session.get("id"):
        print(
            f"[megaplan] Fresh codex execute requested; invalidating prior "
            f"{session_key} session {session['id']}",
            flush=True,
        )
        state["sessions"].pop(session_key, None)
        session = {}
    if persistent and step == "execute" and session.get("id") and not fresh:
        threshold = _codex_executor_session_headroom_tokens()
        total_tokens = _codex_total_tokens_from_session(session)
        if total_tokens is not None and total_tokens >= threshold:
            print(
                f"[megaplan] Codex executor session {session['id']} has "
                f"{total_tokens:,} total tokens, exceeding headroom threshold "
                f"{threshold:,}; starting execute with a fresh session",
                flush=True,
            )
            state["sessions"].pop(session_key, None)
            session = {}
            fresh = True
    active_dispatch: dict[str, Any] | None = None
    if os.getenv("MEGAPLAN_ZERO_RECOVERY_CANARY") == "1":
        active_dispatch = _active_zero_recovery_dispatch(plan_dir, step=step)
        assert active_dispatch is not None
        artifact_stem = (
            f".zero-recovery-{active_dispatch['dispatch_ordinal']:02d}-{step}"
            f"-i{active_dispatch['plan_iteration']}"
        )
        fixed_output = plan_dir / f"{artifact_stem}-worker-output.json"
        if output_path is not None and Path(output_path).absolute() != fixed_output.absolute():
            raise CliError(
                "zero_recovery_worker_output_invalid",
                "finite canary requires the fixed per-phase worker output",
            )
        output_path = fixed_output
        if output_path.exists() or output_path.is_symlink():
            raise CliError(
                "zero_recovery_worker_output_invalid",
                "finite canary worker output already exists",
            )
    elif output_path is None:
        output_path = _response_output_path(
            plan_dir,
            step=step,
            occurrence_id=response_occurrence["occurrence_id"],
            repair_ordinal=repair_ordinal,
        )
    else:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.is_symlink():
            raise CliError(
                "local_response_contract",
                "Codex response output path must not be a symlink",
            )
        if output_path.exists() and output_path.stat().st_size > 0:
            raise CliError(
                "local_response_contract",
                "Codex response output path already contains evidence; overwriting it is forbidden",
            )
    seam_tier = (
        ModelTier.NON_ENFORCED
        if persistent and session.get("id") and not fresh and not read_only
        else ModelTier.ENFORCED
    )
    persisted_schema = read_json(schema_file)
    capture_schema_name = (
        codex_schema_name
        if step == "execute"
        else STEP_CAPTURE_SCHEMA_FILENAMES.get(step, codex_schema_name)
    )
    capture_schema = SCHEMAS.get(capture_schema_name, persisted_schema)
    # Preserve the consumer's semantic required/optional contract.  Gate is
    # the one established exception: every gate reader already treats its
    # OpenAI-strict projection as canonical (see model_seam audit handling).
    # Provider compatibility must never be obtained by silently promoting
    # optional fields before this compiler sees them.
    schema = (
        strict_schema(deepcopy(capture_schema))
        if step == "gate"
        else deepcopy(capture_schema)
    )
    response_contract: CompiledResponseContract | None = None
    transport_schema_file: Path | None = None
    if not free_text:
        response_contract, transport_schema_file = _prepare_codex_response_contract(
            schema=schema,
            plan_dir=plan_dir,
            step=step,
            model=model,
            provider_schema_available=not (
                persistent and session.get("id") and not fresh and not read_only
            ),
        )
    response_attestation = (
        response_contract.attestation.to_json()
        if response_contract is not None
        else None
    )
    local_strict_handoff: dict[str, Any] | None = None
    if (
        response_contract is not None
        and response_contract.attestation.response_enforcement
        == ResponseEnforcement.LOCAL_STRICT_JSON.value
        and os.getenv("MEGAPLAN_ZERO_RECOVERY_CANARY") != "1"
        and _trusted_container()
    ):
        local_strict_handoff = _prepare_local_strict_artifact_handoff(
            plan_dir,
            step=step,
        )
        _preflight_trusted_container_artifact_handoff(local_strict_handoff)
    rendered_prompt = render_prompt_for_dispatch(
        "codex",
        step,
        state,
        plan_dir,
        root=root,
        model=model,
        normalized_model=model,
        tier=seam_tier,
        schema=schema,
        prompt_override=prompt_override,
        **(prompt_kwargs or {}),
    )
    prompt = _normalize_stdin_text(rendered_prompt.prompt) or ""
    if (
        response_contract is not None
        and response_contract.attestation.response_enforcement
        == ResponseEnforcement.LOCAL_STRICT_JSON.value
    ):
        prompt += (
            "\n\nResponse enforcement: return exactly one JSON object matching "
            "the supplied canonical schema. Do not use Markdown fences or prose."
        )
        if local_strict_handoff is not None:
            candidate_path = local_strict_handoff["candidate_path"]
            candidate_path_json = json.dumps(candidate_path, ensure_ascii=True)
            prompt += (
                " If the complete object is too large for the final response, use the "
                "authorized artifact handoff instead: write the complete canonical JSON "
                f"to exactly {candidate_path!r} via a temporary sibling file followed by "
                "an atomic rename. Do not write finalize_output.json or any other scratch "
                "or canonical artifact. Then return only this exact receipt shape: "
                f"{{\"schema\":\"{LOCAL_STRICT_ARTIFACT_RECEIPT_SCHEMA}\","
                f"\"path\":{candidate_path_json},\"sha256\":\"<64 lowercase hex>\","
                "\"bytes\":<exact byte count>}. The receipt path is fixed and may not "
                "be substituted."
            )
    timeout_seconds = _codex_timeout_for_step("prep" if read_only else step)

    if read_only:
        command = [
            "codex",
            "exec",
            "--skip-git-repo-check",
            "--ephemeral",
            "-o",
            str(output_path),
        ]
        if _trusted_container():
            # Trusted containers are the outer sandbox. On hosts without
            # unprivileged user namespaces, Codex's read-only bubblewrap
            # sandbox fails before the worker can inspect local files.
            command.append("--dangerously-bypass-approvals-and-sandbox")
        else:
            command.extend([
                "-c",
                "sandbox_mode='read-only'",
            ])
        command.extend(_codex_model_flag(model))
        command.extend(_codex_effort_flag(effort))
        if json_trace:
            command.append("--json")
        if free_text:
            command.append("-")
        else:
            command.extend(_codex_response_schema_args(transport_schema_file))
    elif persistent and session.get("id") and not fresh:
        # codex exec resume does not support --output-schema; capture_step_output
        # handles the output file validation after parsing instead. It also
        # does not accept --add-dir; resumed sessions keep the workspace that
        # was granted when the session was created.
        command = ["codex", "exec", "resume"]
        if _trusted_container():
            command.append("--dangerously-bypass-approvals-and-sandbox")
        command.extend(_codex_model_flag(model))
        command.extend(_codex_effort_flag(effort))
        command.extend(_codex_exec_mode_flags(step))
        # Cap tool-result output per message at 50k chars (defense-in-depth;
        # codex interprets this as tokens — 50k tokens ≈ 200k chars, generous
        # but bounded).  The hardcoded 10 KiB default is too small for test
        # output; 50k tokens is per-message only, no cross-message elision.
        command.extend(["-c", "tool_output_token_limit=50000"])
        if json_trace:
            command.append("--json")
        command.extend([
            "--skip-git-repo-check",
            "-o", str(output_path),
            str(session["id"]), "-",
        ])
    else:
        command = [
            "codex",
            "exec",
            "--skip-git-repo-check",
            "-C",
            str(work_dir),
            "--add-dir",
            str(plan_dir),
        ]
        if _trusted_container():
            # In a trusted container the surrounding runtime is the sandbox.
            # Skip the workspace-write sandbox (which requires user namespaces
            # that most container runtimes don't grant) and let Codex run
            # without Codex's nested sandbox. The dedicated nonroot process and
            # outer container boundaries still constrain writes.
            command.append("--dangerously-bypass-approvals-and-sandbox")
        else:
            # Allow projects to declare extra writable roots via state.config.
            # Useful when the project_dir is a subdirectory of a multi-package
            # workspace and tasks legitimately create files in sibling dirs
            # (e.g. tools/ as project_dir but plan creates animations/ at the
            # workspace root). Roots are passed verbatim to codex; relative
            # paths are resolved against work_dir.
            roots = _codex_writable_roots(work_dir, state, execution_env, phase=step)
            roots_literal = ", ".join(f"\"{r}\"" for r in roots)
            command.extend([
                "-c",
                f"sandbox_workspace_write.writable_roots=[{roots_literal}]",
            ])
        command.extend([
            "-o",
            str(output_path),
        ])
        command.extend(_codex_model_flag(model))
        command.extend(_codex_effort_flag(effort))
        if not persistent:
            command.append("--ephemeral")
        command.extend(_codex_exec_mode_flags(step))
        # Cap tool-result output per message at 50k chars (defense-in-depth;
        # codex interprets this as tokens — 50k tokens ≈ 200k chars, generous
        # but bounded).  The hardcoded 10 KiB default is too small for test
        # output; 50k tokens is per-message only, no cross-message elision.
        command.extend(["-c", "tool_output_token_limit=50000"])
        if json_trace:
            command.append("--json")
        command.extend(_codex_response_schema_args(transport_schema_file))

    capture_failure: Exception | None = None
    try:
        # Pre-first-byte timeout: codex CLI can hang at startup (auth handshake,
        # default-endpoint connect, etc.) producing zero bytes while megaplan's
        # liveness heartbeat keeps the auto driver thinking everything is fine.
        # Bound the no-output startup phase to ~3min so wedges surface as a
        # retryable ``codex_pre_first_byte_stall`` instead of consuming the full
        # phase wall-clock. Env override:
        # MEGAPLAN_CODEX_PRE_FIRST_BYTE_TIMEOUT_S (default 180).
        try:
            pre_first_byte_s = float(
                os.getenv("MEGAPLAN_CODEX_PRE_FIRST_BYTE_TIMEOUT_S", "180")
            )
        except (TypeError, ValueError):
            pre_first_byte_s = 180.0
        try:
            codex_idle_s = float(os.getenv("MEGAPLAN_CODEX_IDLE_TIMEOUT_S", "600"))
        except (TypeError, ValueError):
            codex_idle_s = 600.0
        execute_call_transaction_id: str | None = None
        if step == "execute":
            execute_call_transaction_id = _emit_codex_execute_llm_start(
                plan_dir,
                model=model,
                prompt=prompt,
                json_trace=json_trace,
            )
        # Non-execute phases have no long mutating tool turn to protect.  They
        # must show a structured Codex event, rollout token, or output artifact
        # to extend their idle window; a live-but-silent node process is a
        # transport/CLI wedge, not progress.  Execute deliberately retains
        # CPU-based liveness because pytest/build subprocesses can be
        # legitimately quiet for minutes.
        strict_structured_liveness = step not in _EXECUTE_STEPS
        liveness = CodexProgressLiveness(
            output_path=output_path,
            include_cpu_signal=not strict_structured_liveness,
        )
        worker_plan_before = _zero_recovery_plan_snapshot(
            root, plan_dir, output_path=output_path
        )
        worker_source_before = _zero_recovery_source_identity(root, plan_dir)
        schema_grant = None
        try:
            schema_grant = _prepare_zero_recovery_schema_input(schema_file)
            model_runtime = _prepare_zero_recovery_model_runtime(
                step=step,
                plan_dir=plan_dir,
                output_path=output_path,
                plan_iteration=(
                    active_dispatch["plan_iteration"]
                    if active_dispatch is not None
                    else 0
                ),
                dispatch_ordinal=(
                    active_dispatch["dispatch_ordinal"]
                    if active_dispatch is not None
                    else 0
                ),
            )
            try:
                child_env = _codex_child_env(turn_id=f'plan_worker_{state["name"]}')
                if model_runtime is not None:
                    child_env = _zero_recovery_model_env(
                        model_runtime, turn_id=f'plan_worker_{state["name"]}'
                    )
                    command = _zero_recovery_model_command(command)
                result = run_command(
                    command,
                    cwd=work_dir,
                    stdin_text=prompt,
                    env=child_env,
                    timeout=timeout_seconds,
                    activity_callback=(
                        None
                        if os.getenv("MEGAPLAN_ZERO_RECOVERY_CANARY") == "1"
                        else _activity_callback_for_state(state, plan_dir)
                    ),
                    activity_guard=liveness.activity_guard,
                    pre_first_byte_timeout=(
                        pre_first_byte_s if pre_first_byte_s > 0 else None
                    ),
                    idle_timeout=codex_idle_s if codex_idle_s > 0 else None,
                    progress_liveness_factory=liveness.bind_process,
                    # Structured non-execute liveness has no grace: a process that is
                    # merely alive but has no token/event/artifact evidence must
                    # surface as a retryable worker_stall at the configured bounded
                    # idle timeout.
                    progress_liveness_grace_timeout=(
                        0.0
                        if strict_structured_liveness
                        else (codex_idle_s if codex_idle_s > 0 else None)
                    ),
                    spawn_registration_callback=_spawn_registration_callback_from_binding(),
                )
            finally:
                _verify_zero_recovery_worker_boundaries(
                    root=root,
                    plan_dir=plan_dir,
                    output_path=output_path,
                    runtime=model_runtime,
                    schema_grant=schema_grant,
                    source_before=worker_source_before,
                    plan_before=worker_plan_before,
                )
        finally:
            if schema_grant is not None:
                _quiesce_zero_recovery_model_uid()
                _restore_zero_recovery_schema_input(schema_grant)
        if not read_only:
            _verify_engine_after_mutating_worker(step, state, root, execution_env)
    except CliError as error:
        transport_raw = str(error.extra.get("raw_output", ""))
        try:
            terminal_raw = output_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            terminal_raw = ""
        try:
            _select_codex_terminal_output(transport_raw, terminal_raw)
            timeout_selection_error: Exception | None = None
        except ModelStructuralAuditError as selection_error:
            timeout_selection_error = selection_error
        timeout_response_evidence = _persist_codex_response_evidence(
            plan_dir,
            occurrence=response_occurrence,
            repair_ordinal=repair_ordinal,
            raw_transport=transport_raw,
            terminal_output=terminal_raw,
            output_path=output_path,
            model=model,
            selection_error=timeout_selection_error,
        )
        error.extra["raw_output"] = transport_raw
        error.extra["response_evidence"] = timeout_response_evidence
        # Recover from a lost session: container restarted since the session was
        # created, codex's rollout store is gone, but megaplan still has the id.
        # Clear the stale session and retry once with fresh=True.
        if os.getenv("MEGAPLAN_ZERO_RECOVERY_CANARY") != "1" and not fresh and persistent and session.get("id") and _is_rollout_missing(
            str(error.extra.get("raw_output", ""))
        ):
            print(
                f"[megaplan] Codex session {session['id']} has no rollout "
                f"(container restart or session wipe); retrying {step} with a fresh session",
                flush=True,
            )
            # Drop the stale session id so later phases don't also try to resume it.
            state["sessions"].pop(session_key, None)
            return run_codex_step(
                step,
                state,
                plan_dir,
                root=root,
                persistent=persistent,
                fresh=True,
                json_trace=json_trace,
                prompt_override=prompt_override,
                prompt_kwargs=prompt_kwargs,
                effort=effort,
                model=model,
                read_only=read_only,
            )
        # Recover from a poisoned session: the history carries an obsolete
        # "sandbox is broken" belief from a pre-trusted-container run. Only
        # act when we're in trusted-container mode (so we know the belief is
        # stale) and we were resuming a session (fresh sessions can't carry
        # the poisoned history). See _is_poisoned_environmental_failure.
        if (
            os.getenv("MEGAPLAN_ZERO_RECOVERY_CANARY") != "1"
            and
            not fresh
            and persistent
            and session.get("id")
            and _trusted_container()
            and _is_poisoned_environmental_failure(
                str(error.extra.get("raw_output", ""))
            )
        ):
            print(
                "[megaplan] Detected poisoned session (obsolete sandbox failure belief); "
                "invalidating session and retrying with --fresh",
                flush=True,
            )
            state["sessions"].pop(session_key, None)
            return run_codex_step(
                step,
                state,
                plan_dir,
                root=root,
                persistent=persistent,
                fresh=True,
                json_trace=json_trace,
                prompt_override=prompt_override,
                prompt_kwargs=prompt_kwargs,
                effort=effort,
                model=model,
                read_only=read_only,
            )
        # Recover from a session that grew too large to remote-compact:
        # OpenAI 429s the compaction call, codex gives up and exits. Same
        # session id will keep failing — start fresh.
        if (
            os.getenv("MEGAPLAN_ZERO_RECOVERY_CANARY") != "1"
            and
            not fresh
            and persistent
            and session.get("id")
            and _is_session_too_large_for_compact(
                str(error.extra.get("raw_output", ""))
            )
        ):
            print(
                "[megaplan] Detected oversized codex session (remote compact 429); "
                "invalidating session and retrying with --fresh",
                flush=True,
            )
            state["sessions"].pop(session_key, None)
            return run_codex_step(
                step,
                state,
                plan_dir,
                root=root,
                persistent=persistent,
                fresh=True,
                json_trace=json_trace,
                prompt_override=prompt_override,
                prompt_kwargs=prompt_kwargs,
                effort=effort,
                model=model,
                read_only=read_only,
            )
        if error.code in {"worker_timeout", "worker_stall"}:
            timeout_session_id = session.get("id") if persistent else None
            if timeout_session_id is None:
                timeout_session_id = extract_session_id(error.extra.get("raw_output", ""))
            if timeout_session_id is not None:
                error.extra["session_id"] = timeout_session_id
            diagnosed_code, diagnosed_message = _diagnose_codex_failure(
                str(error.extra.get("raw_output", "")),
                124,
            )
            if diagnosed_code == "connection_error":
                raise CliError(
                    diagnosed_code,
                    diagnosed_message,
                    extra=error.extra,
                    valid_next=error.valid_next,
                    exit_code=error.exit_code,
                ) from error
            raise CliError(
                error.code,
                (
                    (
                        f"Codex {step} worker became silent before producing structured output. "
                        if error.code == "worker_stall"
                        else f"Codex {step} step timed out after {timeout_seconds}s before producing structured output. "
                    )
                    + _codex_retry_guidance(step)
                ),
                extra=error.extra,
                valid_next=error.valid_next,
                exit_code=error.exit_code,
            ) from error
        raise
    raw = result.stdout + result.stderr
    try:
        output_raw = output_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        output_raw = ""
    try:
        selected_output = _select_codex_terminal_output(raw, output_raw)
        selection_error = None
    except ModelStructuralAuditError as error:
        selected_output = ""
        selection_error = error
    response_evidence = _persist_codex_response_evidence(
        plan_dir,
        occurrence=response_occurrence,
        repair_ordinal=repair_ordinal,
        raw_transport=raw,
        terminal_output=output_raw,
        output_path=output_path,
        model=model,
        selection_error=selection_error,
    )
    # Same rollout-missing recovery for the non-exception path (non-zero exit
    # without CliError being raised). See _is_rollout_missing for context.
    if (
        os.getenv("MEGAPLAN_ZERO_RECOVERY_CANARY") != "1"
        and
        not fresh
        and persistent
        and session.get("id")
        and result.returncode != 0
        and _is_rollout_missing(raw)
    ):
        print(
            f"[megaplan] Codex session {session['id']} has no rollout "
            f"(container restart or session wipe); retrying {step} with a fresh session",
            flush=True,
        )
        state["sessions"].pop(session_key, None)
        return run_codex_step(
            step,
            state,
            plan_dir,
            root=root,
            persistent=persistent,
            fresh=True,
            json_trace=json_trace,
            prompt_override=prompt_override,
            prompt_kwargs=prompt_kwargs,
            effort=effort,
            model=model,
            read_only=read_only,
        )
    # Poisoned-session recovery on non-exception path: the worker exited 0 or
    # non-zero but produced output that still echoes an obsolete sandbox
    # failure belief. Same guard conditions as the CliError branch above.
    if (
        os.getenv("MEGAPLAN_ZERO_RECOVERY_CANARY") != "1"
        and
        not fresh
        and persistent
        and session.get("id")
        and _trusted_container()
        and _is_poisoned_environmental_failure(raw)
    ):
        print(
            "[megaplan] Detected poisoned session (obsolete sandbox failure belief); "
            "invalidating session and retrying with --fresh",
            flush=True,
        )
        state["sessions"].pop(session_key, None)
        return run_codex_step(
            step,
            state,
            plan_dir,
            root=root,
            persistent=persistent,
            fresh=True,
            json_trace=json_trace,
            prompt_override=prompt_override,
            prompt_kwargs=prompt_kwargs,
            effort=effort,
            model=model,
            read_only=read_only,
        )
    # Oversized-session recovery on non-exception path. See the matching
    # branch in the CliError handler above for context.
    if (
        os.getenv("MEGAPLAN_ZERO_RECOVERY_CANARY") != "1"
        and
        not fresh
        and persistent
        and session.get("id")
        and result.returncode != 0
        and _is_session_too_large_for_compact(raw)
    ):
        print(
            "[megaplan] Detected oversized codex session (remote compact 429); "
            "invalidating session and retrying with --fresh",
            flush=True,
        )
        state["sessions"].pop(session_key, None)
        return run_codex_step(
            step,
            state,
            plan_dir,
            root=root,
            persistent=persistent,
            fresh=True,
            json_trace=json_trace,
            prompt_override=prompt_override,
            prompt_kwargs=prompt_kwargs,
            effort=effort,
            model=model,
            read_only=read_only,
        )
    if (
        result.returncode != 0
        and response_contract is not None
        and response_contract.transport_schema is not None
        and _is_codex_provider_schema_rejection(raw)
    ):
        contract_error = _codex_provider_contract_error(response_contract, raw)
        contract_error.extra["response_evidence"] = response_evidence
        raise contract_error
    if result.returncode != 0 and (not output_path.exists() or not output_path.read_text(encoding="utf-8").strip()):
        error_code, error_message = _diagnose_codex_failure(raw, result.returncode)
        raise CliError(
            error_code,
            error_message,
            extra={"raw_output": raw, "response_evidence": response_evidence},
        )
    if result.returncode != 0:
        error_code, error_message = _diagnose_codex_failure(raw, result.returncode)
        raise CliError(
            error_code,
            error_message,
            extra={"raw_output": raw, "response_evidence": response_evidence},
        )
    if free_text:
        if selection_error is not None:
            raise CliError(
                "local_response_contract",
                str(selection_error),
                extra={"response_evidence": response_evidence, "raw_output": raw},
            ) from selection_error
        text = selected_output
        payload: dict[str, Any] = {}
        if step == "plan":
            extracted = _extract_plan_capture_input(text)
            if isinstance(extracted, dict):
                payload = extracted
        return WorkerResult(
            payload=payload,
            raw_output=text,
            duration_ms=result.duration_ms,
            cost_usd=0.0,
            session_id=extract_session_id(raw),
            trace_output=raw if json_trace else None,
            rendered_prompt=prompt,
            worker_channel=_CODEX_WORKER_CHANNEL,
            worker_identity=result.worker_identity,
        )
    if selection_error is not None:
        raise _local_response_contract_error(
            step=step,
            schema=schema,
            reason=str(selection_error),
            raw=output_raw,
            attempts=1,
            occurrence=response_occurrence,
            evidence=response_evidence,
        ) from selection_error
    capture_input: str | dict[str, Any] = selected_output
    plan_text = selected_output
    if step == "plan":
        capture_input = _extract_plan_capture_input(plan_text)
    try:
        capture_invocation = StepInvocation(
            kind="model",
            metadata={
                "tier": seam_tier.value,
                "worker": "codex",
                "model": model,
                "normalized_model": model,
                "validation_step": step,
                "compatibility_validation_step": step,
                "schema": schema,
                "capture_schema": capture_schema,
                "response_enforcement_attestation": response_attestation,
                "capture_recovery": {
                    "step": step,
                    "plan_dir": str(plan_dir),
                    "output_path": str(output_path),
                    "prefer_output_file": True,
                    **(
                        {"artifact_handoff": local_strict_handoff}
                        if local_strict_handoff is not None
                        else {}
                    ),
                },
            },
        )
        capture_outcome = capture_step_output(
            capture_invocation,
            capture_input,
        )
        payload = _normalize_step_payload_for_audit(
            step,
            dict(capture_outcome.legacy_payload),
        )
    except json.JSONDecodeError as error:
        capture_failure = error
        payload = None
    except ModelStructuralAuditError as error:
        capture_failure = error
        payload = None
    if payload is None:
        try:
            output_raw = output_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            output_raw = ""
        repair_selected = local_strict_repair_input(capture_invocation, output_raw)
        repair_raw, _parse_error = _codex_repair_input(raw, repair_selected)
        failure_reason = (
            str(capture_failure)
            if capture_failure is not None
            else "model output was not valid canonical JSON"
        )
        if not repair_attempted and os.getenv("MEGAPLAN_ZERO_RECOVERY_CANARY") != "1":
            repair_prompt = _build_response_contract_repair_prompt(
                step=step,
                schema=schema,
                failure_reason=failure_reason,
                selected_output=repair_raw,
            )
            # _pre_dispatch_budget_check sentinel: budget guard for dispatch
            try:
                render_step_message(StepInvocation(kind="model", metadata={
                    "prompt": repair_prompt,
                    "model": model,
                    "normalized_model": model,
                    "validation_step": step,
                    "tier": (seam_tier.value if isinstance(seam_tier, ModelTier) else ModelTier.NON_ENFORCED.value),
                    "worker": "codex",
                }))
            except ModelBudgetError:
                raise
            repair_output_path = _response_output_path(
                plan_dir,
                step=step,
                occurrence_id=response_occurrence["occurrence_id"],
                repair_ordinal=repair_ordinal + 1,
            )
            return run_codex_step(
                step,
                state,
                plan_dir,
                root=root,
                persistent=persistent,
                fresh=True,
                json_trace=json_trace,
                prompt_override=repair_prompt,
                prompt_kwargs=prompt_kwargs,
                effort=effort,
                model=model,
                read_only=read_only,
                output_path=repair_output_path,
                repair_attempted=True,
                response_occurrence=response_occurrence,
            )
        raise _local_response_contract_error(
            step=step,
            schema=schema,
            reason=failure_reason,
            raw=repair_raw,
            attempts=2 if repair_attempted else 1,
            occurrence=response_occurrence,
            evidence=response_evidence,
        ) from capture_failure
    raw_session_id = extract_session_id(raw)
    session_id = session.get("id") if persistent and not fresh else None
    if persistent and not session_id:
        session_id = raw_session_id or session.get("id")
        if not session_id:
            raise CliError(
                "worker_error",
                f"Could not determine Codex session id for persistent {step} step",
                extra={"raw_output": raw},
            )
    trace_output = raw if json_trace else None
    # Capture real codex token usage / USD cost from the rollout JSONL.
    # session_id may be None for ephemeral runs; in that case try to recover
    # the auto-assigned id from the run output so we can still bill the step.
    cost_session_id = raw_session_id if fresh else (session_id or raw_session_id)
    session_entry = {}
    if isinstance(state.get("sessions"), dict):
        candidate_entry = state["sessions"].get(session_key, {})
        if isinstance(candidate_entry, dict) and candidate_entry.get("id") == cost_session_id:
            session_entry = candidate_entry
    cost_usd, prompt_tokens, completion_tokens, model_actual, current_totals = _codex_step_cost(
        cost_session_id,
        session_entry,
        model,
        codex_home=(model_runtime["codex_home"] if model_runtime is not None else None),
    )
    if os.getenv("MEGAPLAN_ZERO_RECOVERY_CANARY") == "1" and model_actual is None:
        raise CliError(
            "zero_recovery_model_evidence_missing",
            "Codex rollout did not provide a CLI turn-context model record",
        )
    observed_model = model_actual or model
    from arnold_pipelines.megaplan.pricing.codex import is_model_priced

    cost_pricing = (
        "unavailable"
        if current_totals is None
        else "priced"
        if is_model_priced(observed_model)
        else "unpriced"
    )
    if step == "execute":
        _emit_codex_execute_llm_end(
            plan_dir,
            request_id=cost_session_id,
            model=observed_model,
            tokens_in=prompt_tokens,
            tokens_out=completion_tokens,
            call_transaction_id=execute_call_transaction_id,
        )
        if current_totals is not None and cost_pricing == "priced":
            _emit_codex_execute_cost_recorded(
                plan_dir,
                request_id=cost_session_id,
                model=observed_model,
                cost_usd=cost_usd,
            )
    should_record_session = persistent and not (
        step == "execute" and os.getenv("MEGAPLAN_CODEX_EXECUTE_PERSIST_SESSION") != "1"
    )
    if should_record_session and isinstance(state.get("sessions"), dict):
        entry = state["sessions"].setdefault(session_key, {})
        if isinstance(entry, dict):
            if session_id:
                entry["id"] = session_id
            entry["sandbox_fingerprint"] = sandbox_fingerprint
    if current_totals is not None:
        # Persist the running totals so the next step in the same session
        # only bills its own delta. We mutate the existing session entry
        # when present; otherwise stash a minimal record under session_key.
        if isinstance(state.get("sessions"), dict):
            entry = state["sessions"].setdefault(session_key, {})
            if isinstance(entry, dict):
                if cost_session_id:
                    entry["id"] = cost_session_id
                entry["sandbox_fingerprint"] = sandbox_fingerprint
                entry["last_total_tokens"] = dict(current_totals)
    if cost_usd == 0.0 and cost_session_id and current_totals is None:
        # Don't crash; just leave a breadcrumb so operators can investigate
        # missing rollouts (codex stored elsewhere, permission issue, etc.).
        print(
            f"[megaplan] Could not locate codex rollout for session "
            f"{cost_session_id}; step cost will be recorded as $0.00",
            flush=True,
        )
    elif cost_pricing == "unpriced":
        print(
            f"[megaplan] No canonical pricing for Codex model {observed_model!r}; "
            "step cost is explicitly unpriced (numeric compatibility value $0.00)",
            flush=True,
        )
    privilege_receipt_path: str | None = None
    privilege_receipt_sha256: str | None = None
    rollout_relative: str | None = None
    rollout_sha256: str | None = None
    if model_runtime is not None:
        privilege_path = model_runtime.get("privilege_receipt_path")
        privilege_digest = model_runtime.get("privilege_receipt_sha256")
        rollout = _codex_session_jsonl_path(
            cost_session_id or "", codex_home=model_runtime["codex_home"]
        )
        if (
            not isinstance(privilege_path, Path)
            or not isinstance(privilege_digest, str)
            or rollout is None
        ):
            raise CliError(
                "zero_recovery_model_evidence_missing",
                "sealed privilege or Codex CLI rollout evidence is missing",
            )
        try:
            rollout_relative = rollout.relative_to(model_runtime["codex_home"]).as_posix()
        except ValueError as exc:
            raise CliError(
                "zero_recovery_model_evidence_missing",
                "Codex CLI rollout escaped the sealed phase home",
            ) from exc
        rollout_stat = os.lstat(rollout)
        if (
            not stat.S_ISREG(rollout_stat.st_mode)
            or rollout_stat.st_nlink != 1
            or rollout_stat.st_uid != 0
            or rollout_stat.st_mode & 0o022
        ):
            raise CliError(
                "zero_recovery_model_evidence_missing",
                "Codex CLI rollout was not sealed root-owned evidence",
            )
        privilege_receipt_path = privilege_path.name
        privilege_receipt_sha256 = privilege_digest
        rollout_sha256 = hashlib.sha256(rollout.read_bytes()).hexdigest()
    return WorkerResult(
        payload=payload,
        raw_output=selected_output,
        duration_ms=result.duration_ms,
        cost_usd=cost_usd,
        session_id=session_id,
        trace_output=trace_output,
        rendered_prompt=prompt,
        model_actual=observed_model,
        model_evidence=("codex_cli_turn_context" if model_actual is not None else "requested_cli_arg"),
        privilege_receipt_path=privilege_receipt_path,
        privilege_receipt_sha256=privilege_receipt_sha256,
        rollout_path=rollout_relative,
        rollout_sha256=rollout_sha256,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=prompt_tokens + completion_tokens,
        cost_pricing=cost_pricing,
        worker_channel=_CODEX_WORKER_CHANNEL,
        worker_identity=result.worker_identity,
        response_enforcement_attestation=response_attestation,
    )


def run_codex_step(
    step: str,
    state: PlanState,
    plan_dir: Path,
    *,
    root: Path,
    persistent: bool,
    fresh: bool = False,
    json_trace: bool = False,
    prompt_override: str | None = None,
    prompt_kwargs: dict[str, Any] | None = None,
    effort: str | None = None,
    model: str | None = None,
    read_only: bool = False,
    output_path: Path | None = None,
    free_text: bool = False,
    repair_attempted: bool = False,
    response_occurrence: dict[str, Any] | None = None,
) -> WorkerResult:
    # Non-execute supervision relies on stream-json to observe rollout/token
    # cadence.  Enforce it here as well as at dispatcher call sites so direct
    # handler callers cannot silently disable the watchdog's evidence channel.
    json_trace = json_trace or step not in _EXECUTE_STEPS
    return _run_codex_step_uncapped(
        step,
        state,
        plan_dir,
        root=root,
        persistent=persistent,
        fresh=fresh,
        json_trace=json_trace,
        prompt_override=prompt_override,
        prompt_kwargs=prompt_kwargs,
        effort=effort,
        model=model,
        read_only=read_only,
        output_path=output_path,
        free_text=free_text,
        repair_attempted=repair_attempted,
        response_occurrence=response_occurrence,
    )


def run_codex_prep_step(
    step: str,
    state: PlanState,
    plan_dir: Path,
    *,
    root: Path,
    prompt_override: str | None = None,
    prompt_kwargs: dict[str, Any] | None = None,
    effort: str | None = None,
    model: str | None = None,
) -> WorkerResult:
    """Run prep triage/distill through Codex without writable grants."""

    if step not in {"prep-triage", "prep-distill"}:
        raise CliError("unsupported_step", f"Codex prep runner does not support '{step}'")
    effort = _normalize_codex_effort(effort)
    if effort is not None and effort not in _VALID_CODEX_EFFORTS:
        raise CliError("invalid_args", f"Unsupported codex effort level: {effort}")
    if os.getenv(MOCK_ENV_VAR) == "1":
        _check_mock_safe()
        return mock_worker_output(
            step,
            state,
            plan_dir,
            prompt_override=prompt_override,
            prompt_kwargs=prompt_kwargs,
        )

    out_handle = tempfile.NamedTemporaryFile(
        "w+", encoding="utf-8", delete=False, dir=str(_project_local_tmp_dir(plan_dir))
    )
    out_handle.close()
    output_path = Path(out_handle.name)
    schema_file = schemas_root(root) / STEP_SCHEMA_FILENAMES[step]
    persisted_schema = read_json(schema_file)
    capture_schema = SCHEMAS.get(STEP_SCHEMA_FILENAMES[step], persisted_schema)
    schema = (
        strict_schema(deepcopy(capture_schema))
        if step == "gate"
        else deepcopy(capture_schema)
    )
    response_contract, transport_schema_file = _prepare_codex_response_contract(
        schema=schema,
        plan_dir=plan_dir,
        step=step,
        model=model,
        provider_schema_available=True,
    )
    response_attestation = response_contract.attestation.to_json()
    rendered_prompt = render_prompt_for_dispatch(
        "codex",
        step,
        state,
        plan_dir,
        root=root,
        model=model,
        normalized_model=model,
        tier=ModelTier.ENFORCED,
        schema=schema,
        prompt_override=prompt_override,
        **(prompt_kwargs or {}),
    )
    prompt = rendered_prompt.prompt
    if (
        response_contract.attestation.response_enforcement
        == ResponseEnforcement.LOCAL_STRICT_JSON.value
    ):
        prompt += (
            "\n\nResponse enforcement: return exactly one JSON object matching "
            "the supplied canonical schema. Do not use Markdown fences or prose."
        )
    command = [
        "codex",
        "exec",
        "--skip-git-repo-check",
        "--ephemeral",
        "-o",
        str(output_path),
    ]
    if _trusted_container():
        command.append("--dangerously-bypass-approvals-and-sandbox")
    else:
        command.extend([
            "-c",
            "sandbox_mode='read-only'",
        ])
    command.extend(_codex_model_flag(model))
    command.extend(_codex_effort_flag(effort))
    command.extend(_codex_response_schema_args(transport_schema_file))

    result = run_command(
        command,
        cwd=resolve_work_dir(state),
        stdin_text=prompt,
        env=_codex_child_env(turn_id=f'prep_worker_{state["name"]}'),
        timeout=_codex_timeout_for_step("prep"),
        activity_callback=_activity_callback_for_state(state, plan_dir),
        spawn_registration_callback=_spawn_registration_callback_from_binding(),
    )
    raw = result.stdout + result.stderr
    if (
        result.returncode != 0
        and response_contract.transport_schema is not None
        and _is_codex_provider_schema_rejection(raw)
    ):
        raise _codex_provider_contract_error(response_contract, raw)
    if result.returncode != 0 and (
        not output_path.exists() or not output_path.read_text(encoding="utf-8").strip()
    ):
        error_code, error_message = _diagnose_codex_failure(raw, result.returncode)
        raise CliError(error_code, error_message, extra={"raw_output": raw})
    try:
        capture_outcome = capture_step_output(
            StepInvocation(
                kind="model",
                metadata={
                    "tier": ModelTier.ENFORCED.value,
                    "worker": "codex",
                    "model": model,
                    "normalized_model": model,
                    "validation_step": step,
                    "compatibility_validation_step": step,
                    "schema": schema,
                    "capture_schema": capture_schema,
                    "response_enforcement_attestation": response_attestation,
                    "capture_recovery": {
                        "step": step,
                        "plan_dir": str(plan_dir),
                        "output_path": str(output_path),
                        "prefer_output_file": True,
                    },
                },
            ),
            raw,
        )
        payload = _normalize_step_payload_for_audit(
            step,
            dict(capture_outcome.legacy_payload),
        )
    except json.JSONDecodeError:
        payload = None
    except ModelStructuralAuditError as error:
        raise CliError("parse_error", str(error), extra={"raw_output": raw}) from error
    if payload is None:
        raise CliError(
            "parse_error",
            f"Output file {output_path.name} was not valid JSON and no fallback found",
            extra={"raw_output": raw},
        )
    return WorkerResult(
        payload=payload,
        raw_output=raw,
        duration_ms=result.duration_ms,
        cost_usd=0.0,
        session_id=extract_session_id(raw),
        rendered_prompt=prompt,
        model_actual=model,
        worker_channel=_CODEX_WORKER_CHANNEL,
        response_enforcement_attestation=response_attestation,
    )


def _is_agent_available(agent: str) -> bool:
    """Check if an agent is available (CLI binary or omp_rpc/omp)."""
    if agent in {"claude", "shannon"}:
        # shannon is a deprecated alias for claude: both run the native
        # `claude --print` worker (legacy tmux shannon machinery removed).
        return bool(shutil.which("claude"))
    if agent == "omp":
        # The omp worker launches a ``bun ... --mode rpc`` child through the
        # pinned omp_rpc client.  It is available when the omp executable is
        # on PATH or the omp_rpc package can be imported (custom-command
        # deployments); the worker fails closed at launch otherwise.
        try:
            import omp_rpc  # noqa: F401
        except ImportError:
            return bool(shutil.which("omp"))
        return True
    return bool(shutil.which(agent))


def _agent_requested_explicitly(step: str, args: argparse.Namespace) -> bool:
    if getattr(args, "agent", None):
        return True
    for phase_model in getattr(args, "phase_model", None) or []:
        if "=" not in phase_model:
            continue
        phase_step, _phase_spec = phase_model.split("=", 1)
        if phase_step == step:
            return True
    return False


def _runtime_fallback_candidates(current_agent: str) -> list[str]:
    return [agent for agent in detect_available_agents() if agent != current_agent]


_VENDOR_AWARE_DEFAULT_STEPS = frozenset({"critique_evaluator", "feedback"})


def _effective_premium_vendor(args: argparse.Namespace) -> str | None:
    vendor = getattr(args, "_effective_vendor", None) or getattr(args, "vendor", None)
    return vendor if vendor in {"claude", "codex"} else None


def _vendor_adjusted_default_spec(step: str, spec: str, args: argparse.Namespace) -> str:
    vendor = _effective_premium_vendor(args)
    if step not in _VENDOR_AWARE_DEFAULT_STEPS or vendor is None:
        return spec
    parsed = parse_agent_spec(spec)
    if parsed.agent not in {"claude", "codex"} or parsed.agent == vendor:
        return spec
    if parsed.model is None and parsed.effort is None:
        return vendor
    if parsed.model is None and parsed.effort is not None:
        return f"{vendor}:{parsed.effort}"
    return spec


def resolve_agent_mode(step: str, args: argparse.Namespace, *, home: Path | None = None) -> AgentMode:
    """Returns an :class:`AgentMode` with agent, mode, refreshed, model, effort, resolved_model.

    Both agents default to persistent sessions.  Use --fresh to start a new
    persistent session (break continuity) or --ephemeral for a truly one-off
    call with no session saved.

    The model is extracted from compound agent specs (e.g. 'omp:openai/gpt-5')
    or from --phase-model CLI flags.  For bare ``claude`` /
    ``codex`` specs (no explicit model), the pinned default model is resolved
    and stored in ``resolved_model``.
    """
    model: str | None = None
    effort: str | None = None

    explicit_agent_spec = getattr(args, "agent", None)
    explicit_agent_override = bool(explicit_agent_spec)
    live_phase_model_steps = getattr(args, "_live_phase_model_steps", None)
    live_phase_model_steps_known = live_phase_model_steps is not None
    if live_phase_model_steps is None:
        live_phase_model_steps = {
            pm.split("=", 1)[0]
            for pm in (getattr(args, "phase_model", None) or [])
            if "=" in pm
        }

    # Check --phase-model overrides first when they came from the current CLI.
    # Persisted phase_model entries are merged into args by profile expansion,
    # but an explicit recovery flag like `execute --agent codex` must be able
    # to override those stale persisted routes. If callers have not supplied
    # provenance, preserve the historical phase_model-first behavior.
    phase_models = getattr(args, "phase_model", None) or []
    phase_model_matches = (
        not explicit_agent_override
        or not live_phase_model_steps_known
        or step in live_phase_model_steps
    )
    if phase_model_matches:
        for pm in phase_models:
            if "=" in pm:
                pm_step, chain = decode_phase_model_value(pm)
                if pm_step == step:
                    pm_parsed = parse_agent_spec(chain.selected())
                    agent = pm_parsed.agent
                    model = pm_parsed.model
                    effort = pm_parsed.effort
                    break
        else:
            phase_model_matches = False

    if not phase_model_matches:
        # Check explicit --agent flag
        explicit = explicit_agent_spec
        if explicit:
            explicit_parsed = parse_agent_spec(explicit)
            agent = explicit_parsed.agent
            model = explicit_parsed.model
            effort = explicit_parsed.effort
        else:
            # Fall back to config / defaults
            config = load_config(home)
            configured_spec = config.get("agents", {}).get(step)
            spec = configured_spec or DEFAULT_AGENT_ROUTING[step]
            spec = _vendor_adjusted_default_spec(step, spec, args)
            if is_premium_placeholder_agent(parse_agent_spec(spec).agent):
                vendor = effective_premium_vendor(args, config)
                spec = format_agent_spec(resolve_premium_placeholder_spec(spec, vendor))
            spec_parsed = parse_agent_spec(spec)
            agent = spec_parsed.agent
            model = spec_parsed.model
            effort = spec_parsed.effort

    if is_premium_placeholder_agent(agent):
        raise CliError(
            "invalid_agent_spec",
            f"Unresolved premium placeholder reached worker dispatch for step {step!r}. "
            "Resolve it to 'claude' or 'codex' before dispatch.",
        )

    # Validate agent availability
    # MEGAPLAN_MOCK_WORKERS=1 bypasses availability for explicit Shannon
    if os.environ.get("MEGAPLAN_MOCK_WORKERS") == "1" and agent == "shannon":
        pass  # Skip availability check; worker handles mock mode
    elif not _is_agent_available(agent):
        is_explicit = _agent_requested_explicitly(step, args)
        if is_explicit:
            if agent == "shannon":
                from arnold_pipelines.megaplan._core.io import shannon_missing_deps
                missing = shannon_missing_deps()
                raise CliError(
                    "agent_deps_missing",
                    f"Shannon requires: {', '.join(missing)}. "
                    "Install bun (https://bun.sh) and ensure the vendored fork at megaplan/vendor/shannon/index.ts is present.",
                )
            if agent == "claude":
                from arnold_pipelines.megaplan._core.io import shannon_missing_deps
                missing = shannon_missing_deps()
                raise CliError(
                    "agent_deps_missing",
                    f"Claude routes through Shannon and requires: {', '.join(missing)}. "
                    "Install bun (https://bun.sh) and ensure the vendored fork at megaplan/vendor/shannon/index.ts is present.",
                )
            raise CliError("agent_not_found", f"Agent '{agent}' not found on PATH")
        # Try fallback
        available = detect_available_agents()
        if not available:
            raise CliError(
                "agent_not_found",
                "No supported agents found. Install claude or codex, or install the omp CLI (omp_rpc) for omp-spec models.",
            )
        fallback = available[0]
        args._agent_fallback = {
            "requested": agent,
            "resolved": fallback,
            "reason": f"{agent} not available",
        }
        agent = fallback
        model = None  # Reset model when falling back
        effort = None

    ephemeral = getattr(args, "ephemeral", False)
    fresh = getattr(args, "fresh", False)
    persist = getattr(args, "persist", False)
    conflicting = sum([fresh, persist, ephemeral])
    if conflicting > 1:
        raise CliError("invalid_args", "Cannot combine --fresh, --persist, and --ephemeral")
    # Resolve default model for bare premium agent specs.
    resolved_model: str | None = model
    if resolved_model is None and agent in ("claude", "codex"):
        resolved_model = resolved_default_model_for_agent(agent)

    if ephemeral:
        return AgentMode(
            agent=agent,
            mode="ephemeral",
            refreshed=True,
            model=model,
            effort=effort,
            resolved_model=resolved_model,
        )
    refreshed = fresh
    # Review with Claude: default to fresh to avoid self-bias (principle #5)
    if step == "review" and agent == "claude":
        if persist and not getattr(args, "confirm_self_review", False):
            raise CliError("invalid_args", "Claude review requires --confirm-self-review when using --persist")
        if not persist:
            refreshed = True
    return AgentMode(
        agent=agent,
        mode="persistent",
        refreshed=refreshed,
        model=model,
        effort=effort,
        resolved_model=resolved_model,
    )


# ---------------------------------------------------------------------------
# ArnoldDispatcher helper closures (flag-ON path, Step 5b)
#
# These functions are injected as per-call closure adapters inside the
# MEGAPLAN_USE_AGENT_DISPATCHER=1 branch of run_step_with_worker.  They
# replicate the inner one-shot retry semantics from the flag-OFF codex and
# shannon branches so CliError propagates unchanged to the outer
# auth/connection fallback loop.
# ---------------------------------------------------------------------------


def _omp_to_agent_result(
    req: Any,
    *,
    step: str,
    state: PlanState,
    plan_dir: Path,
    root: Path,
    worker_options: dict[str, Any] | None,
    prompt_override: str | None,
    prompt_kwargs: dict[str, Any] | None,
    output_path: Path | None,
    effective_refreshed: bool,
    wbc_dispatch: CommonWorkerDispatchSpec | None = None,
) -> Any:
    """Call run_omp_step and project WorkerResult → AgentResult (flag-on path)."""
    from arnold_pipelines.megaplan.workers.omp import run_omp_step

    mode = req.mode
    resolved_model = req.resolved_model
    effort = req.effort
    read_only = req.read_only
    if os.getenv(MOCK_ENV_VAR) != "1":
        assert resolved_model is not None and resolved_model != "", (
            "run_step_with_worker about to invoke run_omp_step via "
            "ArnoldDispatcher with empty resolved_model. "
            "AgentMode.resolved_model should hold e.g. "
            "'omp:deepseek/deepseek-v4-pro'."
        )
    _w = _coerce_omp_dispatch_result(run_omp_step(
        step,
        state,
        plan_dir,
        root=root,
        fresh=effective_refreshed,
        model=resolved_model,
        effort=effort,
        prompt_override=prompt_override,
        prompt_kwargs=prompt_kwargs,
        read_only=read_only,
        output_path=output_path,
        worker_options=worker_options,
        wbc_dispatch=wbc_dispatch,
    ))
    return _w.to_agent_result()


def _coerce_omp_dispatch_result(value: Any) -> WorkerResult:
    """Keep typed OMP terminals on the historical WorkerResult seam.

    ``run_omp_step`` owns admission and may return a canonical
    :class:`DispatchOutcome` for an accepted terminal.  The surrounding
    worker loop still performs fallback classification against ``payload``
    and the dispatcher adapter still projects to ``AgentResult``; both need a
    compatibility worker carrying the lossless outcome envelope instead of
    attempting ``DispatchOutcome.to_agent_result()`` or ``.payload``.
    """
    from arnold_pipelines.megaplan.orchestration.phase_result import DispatchOutcome

    if not isinstance(value, DispatchOutcome):
        if not isinstance(value, WorkerResult):
            raise CliError(
                "internal_error",
                "canonical OMP dispatch returned an invalid worker result",
            )
        return value
    if value.kind == "unresolved_launch":
        raise CliError(
            "scheduling_condition",
            "canonical OMP launch remains unresolved",
            extra={"reason": "unresolved_launch", "dispatch_outcome": value.to_dict()},
        )
    if value.kind == "no_launch":
        raise CliError(
            "internal_error",
            "canonical OMP dispatch completed without a worker launch",
            extra=value.to_dict(),
        )
    payload: dict[str, Any] = {}
    if isinstance(value.success_payload, dict):
        payload.update(value.success_payload)
    if value.kind != "success":
        payload.setdefault("success", False)
        if value.terminal_failure is not None:
            payload.setdefault("terminal_failure", dict(value.terminal_failure))
        if value.provider_evidence is not None:
            payload.setdefault("provider_evidence", dict(value.provider_evidence))
        if value.disposition_id is not None:
            payload.setdefault("disposition_id", value.disposition_id)
    return WorkerResult(
        payload=payload,
        raw_output="",
        duration_ms=0,
        cost_usd=0.0,
        worker_identity=dict(value.worker_identity or {}),
        auth_metadata={"dispatch_outcome": value.to_dict()},
    )


def _codex_to_agent_result(
    req: Any,
    *,
    step: str,
    state: PlanState,
    plan_dir: Path,
    root: Path,
    args: argparse.Namespace,
    worker_options: dict[str, Any] | None,
    prompt_override: str | None,
    prompt_kwargs: dict[str, Any] | None,
    output_path: Path | None,
    effective_refreshed: bool,
) -> Any:
    """Call run_codex_step and project WorkerResult → AgentResult."""
    mode = req.mode
    resolved_model = req.resolved_model
    effort = req.effort
    read_only = req.read_only
    if os.getenv(MOCK_ENV_VAR) != "1":
        assert resolved_model is not None and resolved_model != "", (
            "run_step_with_worker about to invoke run_codex_step via "
            "ArnoldDispatcher with empty resolved_model. "
            "AgentMode.resolved_model should hold e.g. 'gpt-5.5'. "
            "See /tmp/codex_wedge_diagnostic.md."
        )
    attempted_retry = False
    eff_fresh = effective_refreshed
    while True:
        try:
            _w = run_codex_step(
                step,
                state,
                plan_dir,
                root=root,
                persistent=(mode == "persistent"),
                fresh=eff_fresh,
                # Every non-execute phase needs stream-json too: it supplies
                # the token/tool evidence used to distinguish a live phase
                # from a silent transport wedge.  The final schema payload
                # still comes from the output file.
                json_trace=True,
                prompt_override=prompt_override,
                prompt_kwargs=prompt_kwargs,
                effort=effort,
                model=resolved_model,
                read_only=read_only,
                output_path=output_path,
            )
            return _w.to_agent_result()
        except CliError as error:
            session_id = error.extra.get("session_id")
            if (
                attempted_retry
                or step in _EXECUTE_STEPS
                or error.code
                not in {
                    "worker_timeout",
                    "worker_stall",
                    "connection_error",
                    "codex_pre_first_byte_stall",
                    "worker_error",
                }
            ):
                raise
            attempted_retry = True
            if mode == "persistent" and isinstance(session_id, str) and session_id:
                apply_session_update(
                    state,
                    step,
                    req.agent,
                    session_id,
                    mode=mode,
                    refreshed=eff_fresh,
                    model=resolved_model,
                )
                eff_fresh = step not in _CROSS_CALL_PERSISTENT_STEPS
            continue


def _shannon_to_agent_result(
    req: Any,
    *,
    step: str,
    state: PlanState,
    plan_dir: Path,
    root: Path,
    args: argparse.Namespace,
    worker_options: dict[str, Any] | None,
    prompt_override: str | None,
    prompt_kwargs: dict[str, Any] | None,
    output_path: Path | None,
    effective_refreshed: bool,
) -> Any:
    """Call run_claude_step and project WorkerResult → AgentResult.

    ``shannon`` is a deprecated alias for ``claude`` — both run the native
    ``claude --print`` worker (legacy tmux shannon machinery was removed).
    """
    from arnold_pipelines.megaplan.workers.claude import run_claude_step

    mode = req.mode
    resolved_model = req.resolved_model
    effort = req.effort
    read_only = req.read_only
    _w = run_claude_step(
        step,
        state,
        plan_dir,
        root=root,
        fresh=effective_refreshed,
        model=resolved_model,
        effort=effort,
        prompt_override=prompt_override,
        prompt_kwargs=prompt_kwargs,
        read_only=read_only,
        output_path=output_path,
    )
    return _w.to_agent_result()


def _selected_step_spec(agent: str, model: str | None, effort: str | None) -> str:
    return format_selected_spec(agent, model, effort) or agent


def _initial_fallback_metadata(
    step: str,
    args: argparse.Namespace,
    *,
    agent: str,
    model: str | None,
    effort: str | None,
    configured_specs: tuple[str, ...] | list[str] | str | None = None,
) -> dict[str, Any]:
    if configured_specs is not None:
        ledger_fields = fallback_observability_fields(configured_specs)
        normalized_specs = tuple(ledger_fields["configured_specs"])
    else:
        configured = configured_fallback_chain_for_phase(getattr(args, "phase_model", None), step)
        normalized_specs = configured.specs if configured is not None else (_selected_step_spec(agent, model, effort),)
    return {
        "configured_specs": normalized_specs,
        "attempt_index": 0,
        "attempted_specs": (normalized_specs[0],),
        "failed_attempt_reasons": (),
        "fallback_trigger": None,
    }


def _assign_worker_fallback_metadata(worker: WorkerResult, metadata: dict[str, Any]) -> None:
    worker.configured_specs = tuple(metadata["configured_specs"])
    worker.attempt_index = int(metadata["attempt_index"])
    worker.attempted_specs = tuple(metadata["attempted_specs"])
    worker.failed_attempt_reasons = tuple(metadata["failed_attempt_reasons"])
    worker.fallback_trigger = metadata["fallback_trigger"]


_CONFIGURED_SPEC_FALLBACK_CLASSES = frozenset(
    {
        "availability",
        "infrastructure",
    }
)


def _configured_spec_failure_class(error: CliError) -> str:
    external = error.extra.get("_external_error")
    if external is not None:
        return classify_retryability(external)
    return classify_retryability(
        {
            "code": error.code,
            "message": str(error),
            "status_code": error.extra.get("status_code"),
            "retryable": error.extra.get("retryable"),
        }
    )


def _agent_mode_from_configured_spec(
    spec: str,
    *,
    mode: str,
    refreshed: bool,
) -> AgentMode:
    parsed = parse_agent_spec(spec)
    resolved_model = parsed.model
    if parsed.agent in ("claude", "codex") and not resolved_model:
        resolved_model = resolved_default_model_for_agent(parsed.agent)
    return AgentMode(
        agent=parsed.agent,
        mode=mode,
        refreshed=refreshed,
        model=parsed.model,
        effort=parsed.effort,
        resolved_model=resolved_model,
    )


def _configured_spec_worker_failure_class(worker: WorkerResult) -> str | None:
    payload = worker.payload
    if not isinstance(payload, dict) or payload.get("success") is not False:
        return None
    details = payload.get("details")
    external = details.get("_external_error") if isinstance(details, dict) else None
    if external is not None:
        return classify_retryability(external)
    return classify_retryability(
        {
            "code": payload.get("error"),
            "message": payload.get("message"),
        }
    )


def _configured_spec_pre_tool(error: CliError) -> bool:
    """Return whether the failure carries a literal pre-tool attestation."""
    return error.extra.get("_pre_tool_attested") is True


def _configured_spec_worker_pre_tool(worker: WorkerResult) -> bool:
    """Return whether a failed worker payload carries a literal pre-tool attestation."""
    payload = worker.payload
    if not isinstance(payload, dict) or payload.get("success") is not False:
        return False
    details = payload.get("details")
    if not isinstance(details, dict):
        return False
    return details.get("_pre_tool_attested") is True


def _advance_configured_spec_fallback(
    fallback_metadata: dict[str, Any],
    failure_class: str | None,
    *,
    mode: str,
    step: str,
    read_only: bool,
    pre_tool: bool = False,
) -> tuple[AgentMode, dict[str, Any]] | None:
    # Never redispatch after a worker may have mutated the checkout. This is
    # stricter than the provider/model relationship and keeps mid-write
    # failures fail-closed for both explicit and profile-provided chains.
    # A launch-time (pre-tool) operational provider failure on a non-execute
    # phase may advance: no worker tool ran in THIS attempt, so nothing in the
    # checkout can have been mutated by it.  Auth, quota, rate-limit,
    # unsupported-model, and context failures stay on their typed ordinary
    # error path; they never authorize a target here.
    if step in _EXECUTE_STEPS:
        return None
    if not read_only and pre_tool is not True:
        return None
    if failure_class not in _CONFIGURED_SPEC_FALLBACK_CLASSES:
        return None
    configured_specs = tuple(fallback_metadata["configured_specs"])
    attempt_index = int(fallback_metadata["attempt_index"])
    next_index = attempt_index + 1
    if next_index >= len(configured_specs):
        return None
    next_spec = configured_specs[next_index]
    current_spec = configured_specs[attempt_index]
    if provider_family(next_spec) == provider_family(current_spec):
        if not is_same_family_operational_classification(failure_class):  # type: ignore[arg-type]
            return None
    next_mode = _agent_mode_from_configured_spec(
        next_spec,
        mode=mode,
        refreshed=True,
    )
    next_metadata = {
        "configured_specs": configured_specs,
        "attempt_index": next_index,
        "attempted_specs": (
            *fallback_metadata["attempted_specs"],
            next_spec,
        ),
        "failed_attempt_reasons": (
            *fallback_metadata["failed_attempt_reasons"],
            failure_class,
        ),
        "fallback_trigger": failure_class,
    }
    return next_mode, next_metadata


def _patch_active_step_fallback_metadata(
    plan_dir: Path,
    state: PlanState,
    metadata: dict[str, Any],
    *,
    agent: str,
    mode: str,
    model: str | None,
) -> None:
    active = state.get("active_step")
    run_id = active.get("run_id") if isinstance(active, dict) else None
    if not isinstance(run_id, str) or not run_id:
        return
    fields = fallback_observability_fields(
        metadata["configured_specs"],
        attempt_index=int(metadata["attempt_index"]),
        attempted_specs=metadata["attempted_specs"],
        failed_attempt_reasons=metadata["failed_attempt_reasons"],
        fallback_trigger=metadata["fallback_trigger"],
    )

    def _mutate(current: dict[str, Any]) -> bool:
        current_active = current.get("active_step")
        if not isinstance(current_active, dict) or current_active.get("run_id") != run_id:
            return False
        current_active["agent"] = agent
        current_active["mode"] = mode
        if model:
            current_active["model"] = model
        current_active.update(fields)
        current_active["last_activity_at"] = now_utc()
        current_active["last_activity_kind"] = "fallback"
        current_active["last_activity_detail"] = f"advanced to {fields['selected_spec']}"
        return True

    try:
        write_plan_state(plan_dir, mode="patch-many", mutation=_mutate)
    except Exception:
        return


def _native_construction_proof(
    backend: str, provider: str, model: str, route: str,
) -> dict[str, Any]:
    """Delegate proof production to the backend-owned catalog seam.

    This helper intentionally contains no model-name predicate or registry of
    its own.  The cloud admission seam performs exact catalog membership and
    derives all proof identities from the observed backend response.
    """
    from arnold_pipelines.megaplan.cloud.worker_dispatch import _default_native_liveness
    proof = _default_native_liveness(backend, model)
    if proof.get("route") != route:
        raise CliError("route_liveness_invalid", "native catalog selected a different route")
    return dict(proof)

def _production_worker_dispatch(
    step: str,
    state: PlanState,
    plan_dir: Path,
    args: argparse.Namespace,
    *,
    root: Path,
    resolved: tuple[str, str, bool, str | None] | AgentMode | None,
    prompt_override: str | None,
    prompt_kwargs: dict[str, Any] | None,
    read_only: bool,
    output_path: Path | None,
    worker_options: dict[str, Any] | None,
    wbc_dispatch: CommonWorkerDispatchSpec | None = None,
) -> Any:
    if wbc_dispatch is None:
        raise CliError(
            "wbc_dispatch_required",
            "production native dispatch requires the canonical WBC adapter",
        )
    from arnold_pipelines.megaplan.cloud.runtime_attestation import (
        configured_seed_path,
        require_production_worker_dispatch_runtime,
    )
    from arnold_pipelines.megaplan.cloud.runtime_provenance import runtime_provenance
    from arnold_pipelines.megaplan.cloud.worker_dispatch import (
        AdmissionRefusal,
        LaunchResult,
        SchedulingCondition,
        WorkerAdmissionRequest,
        dispatch_with_admission,
        production_provider_probe_executor,
    )
    from arnold_pipelines.megaplan.orchestration.phase_result import DispatchOutcome

    am = resolved or resolve_agent_mode(step, args)
    agent = am.agent if isinstance(am, AgentMode) else am[0]
    mode = am.mode if isinstance(am, AgentMode) else am[1]
    model = am.resolved_model if isinstance(am, AgentMode) else am[3]
    effort = am.effort if isinstance(am, AgentMode) else None
    selected_spec = format_selected_spec(agent, model, effort) or agent
    provenance = runtime_provenance()
    seed_path = configured_seed_path()
    manifest_path = os.environ.get("ARNOLD_RUNTIME_MANIFEST", "")
    seed_identity = hashlib.sha256(seed_path.read_bytes()).hexdigest() if seed_path and seed_path.is_file() else ""
    manifest_identity = hashlib.sha256(Path(manifest_path).read_bytes()).hexdigest() if manifest_path and Path(manifest_path).is_file() else ""
    logical_id = str((state.get("meta") or {}).get("current_invocation_id") or uuid.uuid4())
    options = worker_options or {}
    fallback_meta = _initial_fallback_metadata(
        step, args, agent=agent, model=model, effort=effort,
        configured_specs=options.get("configured_fallback_specs"),
    )
    configured_specs = tuple(fallback_meta["configured_specs"])
    request = WorkerAdmissionRequest(
        plan_id=str((state.get("meta") or {}).get("plan_id") or state.get("plan_id") or plan_dir.name),
        phase=step,
        dispatch_family_id=str(options.get("dispatch_family_id") or logical_id),
        logical_dispatch_id=logical_id,
        physical_door_id="workers._impl.run_step_with_worker",
        configured_spec=selected_spec,
        selected_spec=selected_spec,
        source_revision=str(provenance.get("source_revision") or ""),
        runtime_vector=provenance,
        manifest_identity=manifest_identity,
        seed_identity=seed_identity,
        dependency_interpreter_identity=str(Path(sys.executable).resolve()),
        prompt_or_phase_input_identity=str(options.get("prompt_or_phase_input_identity") or _digest_prompt_identity(prompt_override, prompt_kwargs, step)),
        configured_fallback_chain_identity=str(options.get("configured_fallback_chain_identity") or ""),
        configured_fallback_specs=configured_specs,
        authorized_route_identity=selected_spec,
        projection_key=str(options.get("projection_key") or f"{plan_dir.name}:{step}"),
        timeout_budget_s=float(options.get("timeout_budget_s") or 3600.0),
        production_intent=True,
        ledger_root=root,
        operation_store_root=Path(root) / "ops",
        admission_attempt=int(options.get("admission_attempt") or 1),
        # Production route liveness is backend-owned; caller options cannot
        # inject a substitute attestation.
    )

    transport_result: Any = None

    def launch(context: Any) -> Any:
        nonlocal transport_result
        admitted = getattr(context, "selected_spec", None) or selected_spec
        parse_agent_spec(admitted)
        child_am = (
            am
            if admitted == selected_spec
            else _agent_mode_from_configured_spec(admitted, mode=mode, refreshed=True)
        )
        if wbc_dispatch is not None:
            def _bound_dispatch(_start: Any) -> Any:
                token = _WORKER_DISPATCH_BINDING.set(
                    {
                        # The production WBC supplies a start result.  A
                        # compatibility adapter may invoke the admitted
                        # closure with no start payload; that remains the
                        # same already-owned attempt and simply has no
                        # child-certification callback.
                        "spawn_registration_callback": getattr(
                            _start, "spawn_registration_callback", None
                        )
                    }
                )
                try:
                    return _run_step_with_worker_legacy(
                        step, state, plan_dir, args, root=root, resolved=child_am,
                        prompt_override=prompt_override, prompt_kwargs=prompt_kwargs,
                        read_only=read_only, output_path=output_path,
                        worker_options=worker_options, record_routing=True,
                    )
                finally:
                    _WORKER_DISPATCH_BINDING.reset(token)
            # Older, test-owned WBC adapters expose the pre-context
            # ``run(dispatch)`` contract.  Select the call shape from the
            # adapter signature so a compatibility path cannot retry a
            # partially executed admission.
            run = wbc_dispatch.run
            try:
                accepts_context = "context" in inspect.signature(run).parameters
            except (TypeError, ValueError):
                accepts_context = True
            dispatch_result = (
                run(_bound_dispatch, context=context)
                if accepts_context
                else run(_bound_dispatch)
            )
            result = dispatch_result.worker_result
            transport_result = result
            worker = result[0] if isinstance(result, tuple) and len(result) == 4 else result
            identity = dict(getattr(worker, "worker_identity", None) or {})
            if not identity.get("process_start_identity"):
                pid = identity.get("pid")
                if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0:
                    try:
                        from arnold_pipelines.megaplan.watchdog.worker_identity import read_process_start_identity
                        start = read_process_start_identity(pid)
                    except Exception:
                        start = None
                    if isinstance(start, str) and start:
                        identity["process_start_identity"] = start
                if hasattr(worker, "worker_identity"):
                    worker.worker_identity = identity
            return LaunchResult(True, result, worker_identity=identity or getattr(worker, "worker_identity", None))
        return _run_step_with_worker_legacy(
            step, state, plan_dir, args, root=root, resolved=child_am,
            prompt_override=prompt_override, prompt_kwargs=prompt_kwargs,
            read_only=read_only, output_path=output_path,
            worker_options=worker_options, record_routing=True,
        )

    # Ask the admission seam for the canonical typed terminal.  The native
    # worker API still has a legacy tuple contract, so terminal outcomes are
    # projected back into that shape below after the ledger assigns the final
    # terminal event id.
    probe_executor = production_provider_probe_executor()
    outcome = dispatch_with_admission(
        request, launch, gate=require_production_worker_dispatch_runtime, return_worker=False,
        probe_executor=probe_executor, child_launch=launch,
    )
    if isinstance(outcome, AdmissionRefusal):
        raise CliError(outcome.code, outcome.reason, extra=outcome.to_dict())
    if isinstance(outcome, SchedulingCondition):
        raise CliError("scheduling_condition", outcome.reason, extra=outcome.to_dict())
    if isinstance(outcome, DispatchOutcome):
        if outcome.kind == "unresolved_launch":
            raise CliError(
                "scheduling_condition",
                "canonical native launch remains unresolved",
                extra={"reason": "unresolved_launch", "dispatch_outcome": outcome.to_dict()},
            )
        if outcome.kind == "no_launch":
            raise CliError(
                "internal_error",
                "canonical native dispatch completed without a worker launch",
                extra=outcome.to_dict(),
            )

        raw = transport_result
        if isinstance(raw, LaunchResult):
            raw = raw.value
        if isinstance(raw, tuple) and len(raw) == 4:
            transport_worker = raw[0]
            legacy_tail = raw[1:]
        else:
            transport_worker = raw
            legacy_tail = (agent, mode, bool(am.refreshed if isinstance(am, AgentMode) else am[2]))

        # A typed terminal can originate from an exception and therefore have
        # no ordinary WorkerResult transport.  Synthesize the compatibility
        # element in that case; all canonical identity/context remains in the
        # dispatch_outcome envelope, never inferred from a payload.
        if not isinstance(transport_worker, WorkerResult):
            payload: dict[str, Any] = {}
            if isinstance(outcome.success_payload, dict):
                payload.update(outcome.success_payload)
            if outcome.kind != "success":
                payload.setdefault("success", False)
                if outcome.terminal_failure is not None:
                    payload.setdefault("terminal_failure", dict(outcome.terminal_failure))
                if outcome.provider_evidence is not None:
                    payload.setdefault("provider_evidence", dict(outcome.provider_evidence))
                if outcome.disposition_id is not None:
                    payload.setdefault("disposition_id", outcome.disposition_id)
            transport_worker = WorkerResult(
                payload=payload,
                raw_output="",
                duration_ms=0,
                cost_usd=0.0,
            )

        metadata = dict(transport_worker.auth_metadata or {})
        metadata["dispatch_outcome"] = outcome.to_dict()
        transport_worker.auth_metadata = metadata
        # The typed outcome is authoritative.  This also repairs legacy
        # transports that omitted identity while preventing a second identity
        # from being invented at the handler boundary.
        transport_worker.worker_identity = dict(outcome.worker_identity)
        return (transport_worker, *legacy_tail)
    if not isinstance(outcome, tuple) or len(outcome) != 4:
        raise CliError("internal_error", "canonical worker dispatch returned an invalid worker result")
    return outcome


def _digest_prompt_identity(prompt_override: str | None, prompt_kwargs: dict[str, Any] | None, step: str) -> str:
    return hashlib.sha256(json.dumps({"step": step, "prompt": prompt_override, "kwargs": prompt_kwargs or {}}, sort_keys=True, default=str).encode()).hexdigest()


def run_step_with_worker(
    step: str,
    state: PlanState,
    plan_dir: Path,
    args: argparse.Namespace,
    *,
    root: Path,
    resolved: tuple[str, str, bool, str | None] | AgentMode | None = None,
    prompt_override: str | None = None,
    prompt_kwargs: dict[str, Any] | None = None,
    read_only: bool = False,
    output_path: Path | None = None,
    worker_options: dict[str, Any] | None = None,
    record_routing: bool = True,
    ledger_phase: str | None = None,
    ledger_step_label: str | None = None,
    ledger_selected_spec: str | None = None,
    ledger_tier: int | None = None,
    ledger_complexity: int | None = None,
    ledger_tier_routing_active: bool = False,
    ledger_configured_specs: tuple[str, ...] | list[str] | str | None = None,
    ledger_attempt_index: int | None = None,
    ledger_attempted_specs: tuple[str, ...] | list[str] | str | None = None,
    ledger_failed_attempt_reasons: tuple[str, ...] | list[str] | None = None,
    ledger_fallback_trigger: str | None = None,
    wbc_dispatch: CommonWorkerDispatchSpec | None = None,
) -> tuple[WorkerResult, str, str, bool]:
    dispatcher_enabled = os.getenv("MEGAPLAN_USE_AGENT_DISPATCHER") == "1"
    am = resolved or resolve_agent_mode(step, args)
    agent_name = am.agent if isinstance(am, AgentMode) else am[0]
    has_runtime_binding = bool(
        os.environ.get("ARNOLD_RUNTIME_MANIFEST")
        or os.environ.get("MEGAPLAN_RUNTIME_LAUNCH_SEED")
    )
    production_intent = bool(
        has_runtime_binding
        or (worker_options or {}).get("production_intent")
    )
    # Dispatcher-on is itself the higher-level native route.  When a caller
    # supplies only the OMP production option (without a process-wide runtime
    # binding), keep that route inside ArnoldDispatcher so its AgentResult
    # projection is exercised; the OMP door still performs its own admission
    # from worker_options.
    if dispatcher_enabled and not has_runtime_binding:
        production_intent = False
    if production_intent:
        if agent_name != "omp":
            return _production_worker_dispatch(
                step, state, plan_dir, args, root=root, resolved=am,
                prompt_override=prompt_override, prompt_kwargs=prompt_kwargs,
                read_only=read_only, output_path=output_path,
                worker_options=worker_options, wbc_dispatch=wbc_dispatch,
            )
        # OMP owns its physical admission door.  The outer worker entry only
        # delegates; it must never wrap this route in a second gate (or allow
        # a supplied WBC dispatcher to start before OMP admission).
        return _run_step_with_worker_legacy(
            step, state, plan_dir, args, root=root, resolved=am,
            prompt_override=prompt_override, prompt_kwargs=prompt_kwargs,
            read_only=read_only, output_path=output_path,
            worker_options=worker_options, wbc_dispatch=wbc_dispatch,
            record_routing=record_routing,
        )
    if dispatcher_enabled and agent_name == "omp" and wbc_dispatch is not None:
        # The OMP adapter owns the physical admission door.  In dispatcher-on
        # mode the common WBC supplied by the caller must be handed to that
        # door directly; wrapping the whole dispatcher call in the same WBC
        # would recursively re-enter the adapter and lose its identity.
        return _run_step_with_worker_legacy(
            step,
            state,
            plan_dir,
            args,
            root=root,
            resolved=resolved,
            prompt_override=prompt_override,
            prompt_kwargs=prompt_kwargs,
            read_only=read_only,
            worker_options=worker_options,
            record_routing=record_routing,
            wbc_dispatch=wbc_dispatch,
        )
    if wbc_dispatch is None:
        return _run_step_with_worker_legacy(
            step,
            state,
            plan_dir,
            args,
            root=root,
            resolved=resolved,
            prompt_override=prompt_override,
            prompt_kwargs=prompt_kwargs,
            read_only=read_only,
            output_path=output_path,
            worker_options=worker_options,
            record_routing=record_routing,
            ledger_phase=ledger_phase,
            ledger_step_label=ledger_step_label,
            ledger_selected_spec=ledger_selected_spec,
            ledger_tier=ledger_tier,
            ledger_complexity=ledger_complexity,
            ledger_tier_routing_active=ledger_tier_routing_active,
            ledger_configured_specs=ledger_configured_specs,
            ledger_attempt_index=ledger_attempt_index,
            ledger_attempted_specs=ledger_attempted_specs,
            ledger_failed_attempt_reasons=ledger_failed_attempt_reasons,
            ledger_fallback_trigger=ledger_fallback_trigger,
        )

    def _dispatch_with_binding(_start: Any) -> tuple[WorkerResult, str, str, bool]:
        artifacts_metadata = (
            dict(wbc_dispatch.artifacts.metadata)
            if wbc_dispatch.artifacts is not None
            else {}
        )
        token = _WORKER_DISPATCH_BINDING.set(
            {
                "worker_wbc_attempt_id": wbc_dispatch.attempt_id,
                "phase_wbc_attempt_id": artifacts_metadata.get("phase_attempt_id"),
                "phase_step": artifacts_metadata.get("phase_step") or step,
                "spawn_registration_callback": _start.spawn_registration_callback,
            }
        )
        try:
            return _run_step_with_worker_legacy(
                step,
                state,
                plan_dir,
                args,
                root=root,
                resolved=resolved,
                prompt_override=prompt_override,
                prompt_kwargs=prompt_kwargs,
                read_only=read_only,
                output_path=output_path,
                worker_options=worker_options,
                record_routing=record_routing,
                ledger_phase=ledger_phase,
                ledger_step_label=ledger_step_label,
                ledger_selected_spec=ledger_selected_spec,
                ledger_tier=ledger_tier,
                ledger_complexity=ledger_complexity,
                ledger_tier_routing_active=ledger_tier_routing_active,
                ledger_configured_specs=ledger_configured_specs,
                ledger_attempt_index=ledger_attempt_index,
                ledger_attempted_specs=ledger_attempted_specs,
                ledger_failed_attempt_reasons=ledger_failed_attempt_reasons,
                ledger_fallback_trigger=ledger_fallback_trigger,
            )
        finally:
            _WORKER_DISPATCH_BINDING.reset(token)

    dispatch_result = wbc_dispatch.run(_dispatch_with_binding)
    worker, agent, mode, refreshed = dispatch_result.worker_result
    metadata = dict(worker.auth_metadata) if isinstance(worker.auth_metadata, dict) else {}
    metadata["wbc_dispatch"] = {
        "attempt_id": dispatch_result.start.attempt_id,
        "writer_id": dispatch_result.diagnostics["writer_id"],
        "surface_name": dispatch_result.diagnostics["surface_name"],
        "expected_source_version": wbc_dispatch.expected_source_version,
        "start_source_lookup_key": wbc_dispatch.start_source_lookup_key,
        "terminal_source_lookup_key": wbc_dispatch.success_source_lookup_key,
        "start_event_sequence": (
            dispatch_result.start.append_result.event.sequence
            if dispatch_result.start.append_result is not None
            else None
        ),
        "terminal_event_sequence": (
            dispatch_result.terminal.append_result.event.sequence
            if dispatch_result.terminal.append_result is not None
            else None
        ),
        "promotion_mode": dispatch_result.terminal.promotion_mode.value,
        "route_kind": (
            dispatch_result.terminal.artifacts.metadata.get("route_kind")
            if dispatch_result.terminal.artifacts is not None
            else None
        ),
        "selected_spec": (
            dispatch_result.terminal.artifacts.metadata.get("selected_spec")
            if dispatch_result.terminal.artifacts is not None
            else None
        ),
        "attempt_index": (
            dispatch_result.terminal.artifacts.metadata.get("attempt_index")
            if dispatch_result.terminal.artifacts is not None
            else None
        ),
        "configured_specs": (
            list(dispatch_result.terminal.artifacts.metadata.get("configured_specs", ()))
            if dispatch_result.terminal.artifacts is not None
            else None
        ),
        "attempted_specs": (
            list(dispatch_result.terminal.artifacts.metadata.get("attempted_specs", ()))
            if dispatch_result.terminal.artifacts is not None
            else None
        ),
        "failed_attempt_reasons": (
            list(dispatch_result.terminal.artifacts.metadata.get("failed_attempt_reasons", ()))
            if dispatch_result.terminal.artifacts is not None
            else None
        ),
        "fallback_trigger": (
            dispatch_result.terminal.artifacts.metadata.get("fallback_trigger")
            if dispatch_result.terminal.artifacts is not None
            else None
        ),
        "worker_channel": worker.worker_channel,
        "auth_channel": worker.auth_channel,
    }
    worker.auth_metadata = metadata
    return worker, agent, mode, refreshed


def _run_step_with_worker_legacy(
    step: str,
    state: PlanState,
    plan_dir: Path,
    args: argparse.Namespace,
    *,
    root: Path,
    resolved: tuple[str, str, bool, str | None] | AgentMode | None = None,
    prompt_override: str | None = None,
    prompt_kwargs: dict[str, Any] | None = None,
    read_only: bool = False,
    output_path: Path | None = None,
    worker_options: dict[str, Any] | None = None,
    record_routing: bool = True,
    ledger_phase: str | None = None,
    ledger_step_label: str | None = None,
    ledger_selected_spec: str | None = None,
    ledger_tier: int | None = None,
    ledger_complexity: int | None = None,
    ledger_tier_routing_active: bool = False,
    ledger_configured_specs: tuple[str, ...] | list[str] | str | None = None,
    ledger_attempt_index: int | None = None,
    ledger_attempted_specs: tuple[str, ...] | list[str] | str | None = None,
    ledger_failed_attempt_reasons: tuple[str, ...] | list[str] | None = None,
    ledger_fallback_trigger: str | None = None,
    wbc_dispatch: CommonWorkerDispatchSpec | None = None,
) -> tuple[WorkerResult, str, str, bool]:
    from arnold_pipelines.megaplan.profiles import validate_continuation_agent_override

    project_dir_raw = (state.get("config") or {}).get("project_dir")
    validate_continuation_agent_override(
        Path(project_dir_raw) if isinstance(project_dir_raw, str) else None,
        args,
        step,
    )
    am = resolved or resolve_agent_mode(step, args)
    agent = am.agent if isinstance(am, AgentMode) else am[0]
    mode = am.mode if isinstance(am, AgentMode) else am[1]
    refreshed = am.refreshed if isinstance(am, AgentMode) else am[2]
    model = am.model if isinstance(am, AgentMode) else am[3]
    effort = am.effort if isinstance(am, AgentMode) else None
    resolved_model = am.resolved_model if isinstance(am, AgentMode) else am[3]
    # Backstop: legacy callers (tests, older sites) still pass a 4-tuple
    # ``resolved=`` which drops ``resolved_model``. If we ended up with a
    # codex/claude agent but no resolved_model, auto-apply the pinned default
    # here so downstream dispatch is never invoked with model=None. The
    # diagnostic in /tmp/codex_wedge_diagnostic.md shows that this was the
    # silent path leading to the wedge.
    if resolved_model is None and agent in ("claude", "codex"):
        resolved_model = resolved_default_model_for_agent(agent)
    # Cross-call persistence is only valid for execute-shaped phases. Every
    # other phase receives all needed context in its prompt, so resuming prior
    # planner/critic/reviewer sessions risks cache-replay no-ops.
    effective_refreshed = refreshed or step not in _CROSS_CALL_PERSISTENT_STEPS
    explicit_agent = _agent_requested_explicitly(step, args)
    attempted_agents: set[str] = set()
    if ledger_configured_specs is not None:
        ledger_fields = fallback_observability_fields(
            ledger_configured_specs,
            attempt_index=int(ledger_attempt_index or 0),
            attempted_specs=ledger_attempted_specs,
            failed_attempt_reasons=ledger_failed_attempt_reasons,
            fallback_trigger=ledger_fallback_trigger,
        )
        fallback_metadata = {
            "configured_specs": tuple(ledger_fields["configured_specs"]),
            "attempt_index": ledger_fields["selected_spec_index"],
            "attempted_specs": tuple(ledger_fields["attempted_specs"]),
            "failed_attempt_reasons": tuple(ledger_fields["failed_attempt_reasons"]),
            "fallback_trigger": ledger_fields["fallback_trigger"],
        }
        # The ledger fields are supplied for every explicit route, including
        # a scalar chain.  Presence—not chain length—is what suppresses the
        # ambient provider fallback below.
        configured_fallback_present = True
    else:
        configured = configured_fallback_chain_for_phase(getattr(args, "phase_model", None), step)
        fallback_metadata = _initial_fallback_metadata(
            step,
            args,
            agent=agent,
            model=model,
            effort=effort,
        )
        configured_fallback_present = configured is not None
    _zero_recovery_plan_iteration = int(state.get("iteration", 0) or 0)
    if step in {"plan", "revise"}:
        _zero_recovery_plan_iteration += 1
    _zero_recovery_dispatch_start = _record_zero_recovery_dispatch(
        plan_dir,
        step=step,
        agent=agent,
        model=resolved_model,
        effort=effort,
        plan_iteration=_zero_recovery_plan_iteration,
    )
    while True:
        attempted_agents.add(agent)
        try:
            if os.getenv("MEGAPLAN_USE_AGENT_DISPATCHER") != "1":
                if agent in ("claude", "shannon"):
                    # shannon is a deprecated alias for claude: both run the
                    # native ``claude --print`` worker (legacy tmux shannon
                    # machinery removed). The outer auth/connection fallback
                    # loop handles retries.
                    from arnold_pipelines.megaplan.workers.claude import run_claude_step

                    worker = run_claude_step(
                        step,
                        state,
                        plan_dir,
                        root=root,
                        fresh=effective_refreshed,
                        model=resolved_model,
                        effort=effort,
                        prompt_override=prompt_override,
                        prompt_kwargs=prompt_kwargs,
                        read_only=read_only,
                        output_path=output_path,
                    )
                elif agent == "omp":
                    # omp is a first-class direct worker: a fresh stateless
                    # RPC session per attempt.  The spec's ``omp:provider/model``
                    # carries the model, so an empty resolved_model is a caller
                    # bug — fail loud instead of reaching the codex assertion.
                    if os.getenv(MOCK_ENV_VAR) != "1":
                        assert resolved_model is not None and resolved_model != "", (
                            "run_step_with_worker about to invoke run_omp_step "
                            "with empty resolved_model. AgentMode.resolved_model "
                            "should hold e.g. 'omp:deepseek/deepseek-v4-pro'."
                        )
                    from arnold_pipelines.megaplan.workers.omp import run_omp_step

                    worker = _coerce_omp_dispatch_result(run_omp_step(
                        step,
                        state,
                        plan_dir,
                        root=root,
                        fresh=effective_refreshed,
                        model=resolved_model,
                        effort=effort,
                        prompt_override=prompt_override,
                        prompt_kwargs=prompt_kwargs,
                        read_only=read_only,
                        output_path=output_path,
                        worker_options=worker_options,
                        wbc_dispatch=wbc_dispatch,
                    ))
                else:
                    # Defensive guard: codex must receive an explicit model. The
                    # diagnostic in /tmp/codex_wedge_diagnostic.md shows that when
                    # ``resolved_model`` silently becomes ``None`` (e.g. via a
                    # 4-tuple ``resolved=`` that drops the AgentMode's
                    # ``resolved_model`` field), the codex CLI launches with no
                    # ``-c model=...`` and hangs at startup. Fail loud instead.
                    if os.getenv(MOCK_ENV_VAR) != "1":
                        assert resolved_model is not None and resolved_model != "", (
                            "run_step_with_worker about to invoke run_codex_step "
                            "with empty resolved_model. AgentMode.resolved_model "
                            "should hold e.g. 'gpt-5.5'. Upstream callers using a "
                            "4-tuple ``resolved=`` drop this field — pass the "
                            "AgentMode instance instead. See "
                            "/tmp/codex_wedge_diagnostic.md."
                        )
                    attempted_retry = False
                    while True:
                        try:
                            worker = run_codex_step(
                                step,
                                state,
                                plan_dir,
                                root=root,
                                persistent=(mode == "persistent"),
                                fresh=effective_refreshed,
                                json_trace=True,
                                prompt_override=prompt_override,
                                prompt_kwargs=prompt_kwargs,
                                effort=effort,
                                model=resolved_model,
                                read_only=read_only,
                                output_path=output_path,
                            )
                            break
                        except CliError as error:
                            session_id = error.extra.get("session_id")
                            if (
                                attempted_retry
                                or os.getenv("MEGAPLAN_ZERO_RECOVERY_CANARY") == "1"
                                or step in _EXECUTE_STEPS
                                or error.code
                                not in {
                                    "worker_timeout",
                                    "worker_stall",
                                    "connection_error",
                                    "codex_pre_first_byte_stall",
                                    "worker_error",
                                }
                            ):
                                raise
                            attempted_retry = True
                            if mode == "persistent" and isinstance(session_id, str) and session_id:
                                apply_session_update(
                                    state,
                                    step,
                                    agent,
                                    session_id,
                                    mode=mode,
                                    refreshed=effective_refreshed,
                                    model=resolved_model,
                                )
                                effective_refreshed = step not in _CROSS_CALL_PERSISTENT_STEPS
                            continue
            else:
                # Flag-ON path: route all agents through ArnoldDispatcher via
                # per-call closure registrations.  The outer auth/connection
                # fallback (except CliError below) still wraps everything; the
                # inner per-backend one-shot retry lives inside the closures.
                from arnold.agent import ArnoldDispatcher
                from arnold.agent.contracts import AgentRequest as _AgentRequest
                _dispatcher = ArnoldDispatcher()
                _omp_closure = lambda req: _omp_to_agent_result(
                    req,
                    step=step,
                    state=state,
                    plan_dir=plan_dir,
                    root=root,
                    worker_options=worker_options,
                    prompt_override=prompt_override,
                    prompt_kwargs=prompt_kwargs,
                    output_path=output_path,
                    effective_refreshed=effective_refreshed,
                    wbc_dispatch=wbc_dispatch,
                )
                # All omp-spec agents route through the omp adapter.
                _dispatcher.register("omp", _omp_closure)
                _dispatcher.register(
                    "codex",
                    lambda req: _codex_to_agent_result(
                        req,
                        step=step,
                        state=state,
                        plan_dir=plan_dir,
                        root=root,
                        args=args,
                        worker_options=worker_options,
                        prompt_override=prompt_override,
                        prompt_kwargs=prompt_kwargs,
                        output_path=output_path,
                        effective_refreshed=effective_refreshed,
                    ),
                )
                _claude_closure = lambda req: _shannon_to_agent_result(
                    req,
                    step=step,
                    state=state,
                    plan_dir=plan_dir,
                    root=root,
                    args=args,
                    worker_options=worker_options,
                    prompt_override=prompt_override,
                    prompt_kwargs=prompt_kwargs,
                    output_path=output_path,
                    effective_refreshed=effective_refreshed,
                )
                # shannon is a deprecated alias for claude — both route to the
                # native claude --print worker.
                _dispatcher.register("claude", _claude_closure)
                _dispatcher.register("shannon", _claude_closure)
                _prompt = None
                _request = _AgentRequest(
                    agent=agent,
                    mode=mode,
                    model=model,
                    resolved_model=resolved_model,
                    effort=effort,
                    read_only=read_only,
                    prompt=_prompt,
                    system_prompt=None,
                    metadata={
                        "step": step,
                        "plan_dir": str(plan_dir),
                        **(worker_options or {}),
                    },
                )
                worker = WorkerResult.from_agent_result(_dispatcher.dispatch(_request))
            _record_zero_recovery_dispatch_terminal(
                plan_dir,
                start=_zero_recovery_dispatch_start,
                worker=worker,
            )
            fallback_attempt = _advance_configured_spec_fallback(
                fallback_metadata,
                _configured_spec_worker_failure_class(worker),
                mode=mode,
                step=step,
                read_only=read_only,
                pre_tool=_configured_spec_worker_pre_tool(worker),
            )
            if fallback_attempt is not None:
                if os.getenv("MEGAPLAN_ZERO_RECOVERY_CANARY") == "1":
                    raise CliError(
                        "zero_recovery_fallback_denied",
                        "configured model fallback is forbidden after canary dispatch",
                    )
                next_mode, fallback_metadata = fallback_attempt
                agent = next_mode.agent
                mode = next_mode.mode
                refreshed = next_mode.refreshed
                model = next_mode.model
                effort = next_mode.effort
                resolved_model = next_mode.resolved_model
                effective_refreshed = True
                _patch_active_step_fallback_metadata(
                    plan_dir,
                    state,
                    fallback_metadata,
                    agent=agent,
                    mode=mode,
                    model=model,
                )
                continue
            _assign_worker_fallback_metadata(worker, fallback_metadata)
            if record_routing and (step != "execute" or ledger_step_label is not None):
                actual_model = getattr(worker, "model_actual", None)
                if actual_model is None and agent == "codex":
                    actual_model = resolved_model
                record_step_routing(
                    plan_dir,
                    phase=ledger_phase or normalize_routing_phase(step),
                    step_label=ledger_step_label or step,
                    agent=agent,
                    selected_spec=ledger_selected_spec
                    or format_selected_spec(agent, model, effort),
                    resolved_model=resolved_model,
                    actual_model=actual_model,
                    tier=ledger_tier,
                    complexity=ledger_complexity,
                    tier_routing_active=ledger_tier_routing_active,
                    configured_specs=worker.configured_specs,
                    attempt_index=worker.attempt_index,
                    attempted_specs=worker.attempted_specs,
                    failed_attempt_reasons=worker.failed_attempt_reasons,
                    fallback_trigger=worker.fallback_trigger,
            )
            return worker, agent, mode, effective_refreshed
        except CliError as error:
            fallback_attempt = _advance_configured_spec_fallback(
                fallback_metadata,
                _configured_spec_failure_class(error),
                mode=mode,
                step=step,
                read_only=read_only,
                pre_tool=_configured_spec_pre_tool(error),
            )
            if fallback_attempt is not None:
                if os.getenv("MEGAPLAN_ZERO_RECOVERY_CANARY") == "1":
                    raise CliError(
                        "zero_recovery_fallback_denied",
                        "configured model fallback is forbidden after canary dispatch failure",
                    ) from error
                next_mode, fallback_metadata = fallback_attempt
                agent = next_mode.agent
                mode = next_mode.mode
                refreshed = next_mode.refreshed
                model = next_mode.model
                effort = next_mode.effort
                resolved_model = next_mode.resolved_model
                effective_refreshed = True
                _patch_active_step_fallback_metadata(
                    plan_dir,
                    state,
                    fallback_metadata,
                    agent=agent,
                    mode=mode,
                    model=model,
                )
                continue
            suppress_ambient_fallback = bool(
                (worker_options or {}).get("_suppress_ambient_agent_fallback")
            )
            if (
                os.getenv("MEGAPLAN_ZERO_RECOVERY_CANARY") == "1"
                or
                explicit_agent
                or configured_fallback_present
                or suppress_ambient_fallback
                or error.code not in {"auth_error", "connection_error"}
            ):
                raise
            fallback_candidates = [
                candidate
                for candidate in _runtime_fallback_candidates(agent)
                if candidate not in attempted_agents
            ]
            if not fallback_candidates:
                raise
            fallback_agent = fallback_candidates[0]
            args._agent_fallback = {
                "requested": agent,
                "resolved": fallback_agent,
                "reason": f"{agent} runtime unhealthy: {error.code}",
            }
            failed_spec = _selected_step_spec(agent, model, effort)
            agent = fallback_agent
            model = None
            effort = None
            # Re-resolve the default model for the new agent so codex/claude
            # fallback paths still get an explicit ``-c model=...`` and don't
            # hang on the CLI default. The original ``resolved_model`` belonged
            # to the previously-tried agent and is no longer valid here.
            resolved_model = (
                resolved_default_model_for_agent(fallback_agent)
                if fallback_agent in ("claude", "codex")
                else None
            )
            selected_fallback_spec = _selected_step_spec(agent, model, effort)
            configured_specs = list(fallback_metadata["configured_specs"])
            if failed_spec not in configured_specs:
                configured_specs.append(failed_spec)
            if selected_fallback_spec not in configured_specs:
                configured_specs.append(selected_fallback_spec)
            fallback_metadata = {
                "configured_specs": tuple(configured_specs),
                "attempt_index": configured_specs.index(selected_fallback_spec),
                "attempted_specs": (
                    *fallback_metadata["attempted_specs"],
                    selected_fallback_spec,
                ),
                "failed_attempt_reasons": (
                    *fallback_metadata["failed_attempt_reasons"],
                    error.code,
                ),
                "fallback_trigger": error.code,
            }
            effective_refreshed = True
