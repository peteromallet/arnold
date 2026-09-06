"""Container-neutral runner liveness leases.

The Discord resident and an isolated chain runner intentionally live in
different PID/tmux namespaces.  A PID miss in the resident is therefore not a
death observation.  The runner publishes this short-lived, identity-bound
lease into the shared workspace; observers validate it without probing the
foreign namespace.

The lease is a liveness fact only.  It grants no repair, relaunch, completion,
or notification authority.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping


SCHEMA = "arnold.megaplan.runner_liveness_lease.v2"
FENCE_SCHEMA = "arnold.megaplan.runner_liveness_fence.v1"
DEFAULT_MARKER_DIR = Path("/workspace/.megaplan/cloud-sessions")
DEFAULT_INTERVAL_S = 5.0
DEFAULT_TTL_S = 20.0
MAX_LEASE_SPAN_S = 120.0
MAX_FUTURE_SKEW_S = 5.0
OWNER_PID_ENV = "ARNOLD_LIVENESS_OWNER_PID"
OWNER_START_ENV = "ARNOLD_LIVENESS_OWNER_PROCESS_START"

_ACTIVE_PUBLISHERS: dict[tuple[int, str], "LivenessLeasePublisher"] = {}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _canonical(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(payload: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload)).hexdigest()


def marker_binding(marker: Mapping[str, Any]) -> str:
    """Digest only immutable launch identity, not mutable status projections."""
    return _digest(
        {
            "session": str(marker.get("session") or ""),
            "workspace": str(marker.get("workspace") or ""),
            "remote_spec": str(marker.get("remote_spec") or ""),
            "run_kind": str(marker.get("run_kind") or ""),
            "identity_digest": str(marker.get("identity_digest") or ""),
            "started_at": str(marker.get("started_at") or ""),
            "run_id": str(marker.get("run_id") or ""),
            "attempt_id": str(marker.get("attempt_id") or ""),
            "incarnation_id": str(marker.get("incarnation_id") or ""),
            "pid": marker.get("pid"),
            # The manifest identity is part of the immutable launch binding;
            # a lease for a marker whose manifest bytes changed is not a lease
            # for the same managed run.
            "manifest_identity": str(marker.get("manifest_identity") or ""),
            "pid_namespace_id": str(marker.get("pid_namespace_id") or ""),
            "process_start_identity": str(marker.get("process_start_identity") or ""),
        }
    )


def lease_path(session: str, *, marker_dir: Path = DEFAULT_MARKER_DIR) -> Path:
    return marker_dir / f"{session}.liveness-lease.json"


def fence_path(session: str, *, marker_dir: Path = DEFAULT_MARKER_DIR) -> Path:
    return marker_dir / f"{session}.liveness-fence.json"


def publisher_lock_path(session: str, *, marker_dir: Path = DEFAULT_MARKER_DIR) -> Path:
    return marker_dir / f"{session}.liveness-publisher.lock"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return dict(value) if isinstance(value, Mapping) else {}


def _proc_start_identity(pid: int) -> str | None:
    try:
        # Field 22 is starttime.  Parse after the final ')' because comm may
        # itself contain spaces or parentheses.
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        tail = raw.rsplit(")", 1)[1].strip().split()
        start_ticks = tail[19]
        boot_id = (
            Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
        )
        return f"{boot_id}:{start_ticks}"
    except (OSError, IndexError):
        # macOS and other non-/proc test hosts: bind to the kernel-reported
        # process start string.  Production Linux always uses boot-id+ticks.
        try:
            os.kill(pid, 0)
            proc = subprocess.run(
                ["ps", "-o", "lstart=", "-p", str(pid)],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
            )
            started = proc.stdout.strip()
            if proc.returncode == 0 and started:
                host = socket.gethostname()
                return f"portable-{hashlib.sha256(host.encode()).hexdigest()[:16]}:{started}"
        except (OSError, subprocess.SubprocessError):
            pass
        return None


def _process_is_runnable(pid: int) -> bool:
    """False for dead/zombie or externally stopped processes.

    An embedded publisher freezes with its owner automatically.  This explicit
    state check also keeps the standalone migration sidecar from renewing a
    lease for a SIGSTOP-paused target.
    """
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        state = raw.rsplit(")", 1)[1].strip().split()[0]
        return state not in {"T", "t", "Z", "X", "x"}
    except (OSError, IndexError):
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True


def _namespace_id(kind: str, pid: int | str = "self") -> str:
    try:
        return os.readlink(f"/proc/{pid}/ns/{kind}")
    except OSError:
        return "unknown"


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _refresh_authority_marker(payload: dict[str, Any]) -> dict[str, Any]:
    """Add the runtime-local bindings required by the signal authority."""
    workspace = Path(str(payload.get("workspace") or "")).expanduser()
    provenance = payload.get("runtime_manifest")
    provenance_path = provenance.get("path") if isinstance(provenance, Mapping) else None
    manifest = Path(str(provenance_path)).expanduser() if provenance_path else workspace / ".megaplan" / "runtime-manifest.json"
    progress = workspace / ".megaplan" / "cloud-logs" / f"{payload.get('session', 'session')}.log"
    payload.setdefault("bootstrap_manifest_path", str(manifest))
    payload.setdefault("progress_artifact", str(progress))
    payload.setdefault("progress_identity", f"run:{payload.get('run_id', '')}")
    payload.setdefault("supervisor_pid", os.getpid())
    payload.setdefault("supervisor_process_start_identity", _proc_start_identity(int(payload["supervisor_pid"])))
    try:
        payload.setdefault("boot_identity", Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip())
    except OSError:
        payload.setdefault("boot_identity", "unknown-boot")
    payload.setdefault("container_identity", os.environ.get("ARNOLD_CONTAINER_IDENTITY") or socket.gethostname())
    if manifest.is_file():
        from arnold_pipelines.megaplan.cloud.runtime_manifest import (
            manifest_bytes_sha256,
        )

        manifest_identity = manifest_bytes_sha256(manifest)
        payload["manifest_sha256"] = manifest_identity
        payload["manifest_identity"] = manifest_identity
    else:
        # Never retain a previous marker identity when the pinned manifest is
        # gone; admission will fail closed on the missing binding.
        payload.pop("manifest_sha256", None)
        payload.pop("manifest_identity", None)
    if progress.is_file():
        payload["progress_content_digest"] = hashlib.sha256(progress.read_bytes()).hexdigest()
    tmux_keys = {
        "tmux_socket", "tmux_socket_fingerprint", "tmux_server_pid",
        "tmux_server_process_start_identity", "tmux_session_id",
        "tmux_owned_pane_id", "tmux_owned_pane_pid",
        "tmux_owned_pane_process_start_identity", "tmux_owned_pane_command",
        "tmux_all_panes_digest",
    }
    # Re-derive every tmux field on every refresh.  A failed query must erase
    # the previous binding; retaining it would turn a replaced/ambiguous
    # server or pane into stale authority.
    prior_tmux = {key: payload[key] for key in tmux_keys if key in payload}
    refreshed_tmux = tmux_authority_bindings({**payload, **prior_tmux})
    for key in tmux_keys:
        payload.pop(key, None)
    payload.update(refreshed_tmux)
    unsigned = dict(payload)
    unsigned.pop("content_digest", None)
    unsigned.pop("marker_sha256", None)
    payload["content_digest"] = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
    return payload


def tmux_authority_bindings(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return bindings only when one exact session and owned pane revalidate."""
    session = str(payload.get("session") or "").strip()
    if not session:
        return {}
    owner_pid = payload.get("pid") or payload.get("victim_pid") or os.getpid()
    try:
        owner_pid = int(owner_pid)
    except (TypeError, ValueError):
        return {}
    bound_socket = str(payload.get("tmux_socket") or "").strip()
    env_socket = bound_socket or os.environ.get("TMUX", "").split(",", 1)[0].strip()

    def query(args: list[str]) -> str | None:
        try:
            result = subprocess.run(["tmux", *args], check=False, capture_output=True, text=True, timeout=2)
        except (OSError, subprocess.SubprocessError):
            return None
        return result.stdout.strip() if result.returncode == 0 else None

    # ``=name`` is useful for pane/window targets but macOS tmux leaves
    # session_id/session_name empty for that form.  Query the exact session
    # name and bind the returned name below; all subsequent pane queries still
    # use the explicit socket and exact session target.
    first_args = ["-S", env_socket, "display-message", "-p", "-t", session, "#{socket_path}\t#{pid}\t#{session_id}\t#{session_name}"] if env_socket else ["display-message", "-p", "-t", session, "#{socket_path}\t#{pid}\t#{session_id}\t#{session_name}"]
    first = query(first_args)
    if not first:
        return {}
    parts = first.split("\t")
    if len(parts) != 4 or parts[3] != session or not parts[0] or not parts[1].isdigit() or not parts[2]:
        return {}
    socket_path, server_pid, session_id, session_name = parts
    try:
        socket_fingerprint = f"{os.stat(socket_path).st_dev}:{os.stat(socket_path).st_ino}"
        server_start = _proc_start_identity(int(server_pid))
    except (OSError, ValueError):
        return {}
    if not server_start:
        return {}
    rows = query(["-S", socket_path, "list-panes", "-t", f"={session}", "-F", "#{pane_id}\t#{pane_pid}\t#{pane_current_command}"])
    if not rows:
        return {}
    panes: list[tuple[str, int, str, str]] = []
    for line in rows.splitlines():
        fields = line.split("\t", 2)
        if len(fields) != 3 or not fields[0].startswith("%") or not fields[1].isdigit():
            return {}
        pane_id, pane_pid, command = fields
        start = _proc_start_identity(int(pane_pid))
        if not start:
            return {}
        panes.append((pane_id, int(pane_pid), start, command))
    owned = [pane for pane in panes if pane[1] == owner_pid]
    if len(owned) != 1:
        return {}
    encoded = "\n".join(f"{pane_id}|{pid}|{start}|{hashlib.sha256(command.encode()).hexdigest()}" for pane_id, pid, start, command in panes).encode()
    pane_id, pane_pid, pane_start, command = owned[0]
    return {
        "tmux_socket": socket_path,
        "tmux_socket_fingerprint": socket_fingerprint,
        "tmux_server_pid": int(server_pid),
        "tmux_server_process_start_identity": server_start,
        "tmux_session_id": session_id,
        "tmux_owned_pane_id": pane_id,
        "tmux_owned_pane_pid": pane_pid,
        "tmux_owned_pane_process_start_identity": pane_start,
        "tmux_owned_pane_command": command,
        "tmux_all_panes_digest": hashlib.sha256(encoded).hexdigest(),
    }


# Private compatibility alias for callers that were written while the
# producer helper was being introduced.  New authority consumers use the
# public name above.
_tmux_authority_bindings = tmux_authority_bindings


def _allocate_runner_fence(session: str, marker_dir: Path) -> int:
    """Durably advance the single-writer generation for one runner session."""

    marker_dir.mkdir(parents=True, exist_ok=True)
    lock_path = marker_dir / f".{session}.liveness-fence.lock"
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        current = _read_json(fence_path(session, marker_dir=marker_dir))
        try:
            previous = int(current.get("runner_fence", 0))
        except (TypeError, ValueError):
            previous = 0
        runner_fence = max(0, previous) + 1
        _atomic_json(
            fence_path(session, marker_dir=marker_dir),
            {
                "schema": FENCE_SCHEMA,
                "session": session,
                "runner_fence": runner_fence,
            },
        )
        return runner_fence


def prepare_managed_run_marker(
    session: str,
    *,
    marker_dir: Path,
    workspace: str | Path,
    remote_spec: str | Path,
    run_kind: str,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Create one launch identity before a managed process can start."""

    session = str(session or "").strip()
    run_kind = str(run_kind or "").strip()
    if not session or not run_kind:
        raise ValueError("managed marker requires session and run_kind")
    payload = {
        "session": session,
        "workspace": str(Path(workspace).resolve(strict=False)),
        "remote_spec": str(Path(remote_spec).resolve(strict=False)),
        "run_kind": run_kind,
        "run_id": str(run_id or uuid.uuid4()),
        "started_at": _iso(_utcnow()),
    }
    _refresh_authority_marker(payload)
    _atomic_json(Path(marker_dir) / f"{session}.json", payload)
    return payload


class LivenessLeasePublisher:
    """Renew a lease while one exact local process incarnation remains alive."""

    def __init__(
        self,
        session: str,
        *,
        marker_dir: Path = DEFAULT_MARKER_DIR,
        target_pid: int | None = None,
        interval_s: float = DEFAULT_INTERVAL_S,
        ttl_s: float = DEFAULT_TTL_S,
    ) -> None:
        self.session = session
        self.marker_dir = Path(marker_dir)
        self.target_pid = int(target_pid or os.getpid())
        self.interval_s = max(0.2, float(interval_s))
        self.ttl_s = min(MAX_LEASE_SPAN_S, max(self.interval_s * 2, float(ttl_s)))
        self.target_start_identity = _proc_start_identity(self.target_pid)
        if self.target_start_identity is None:
            raise RuntimeError(
                f"target process {self.target_pid} is not locally observable"
        )
        self.lease_id = str(uuid.uuid4())
        self.attempt_id = str(uuid.uuid4())
        self.incarnation_id = str(uuid.uuid4())
        self.runner_fence = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sequence = 0
        self._lock_handle: Any | None = None
        self._marker_snapshot: dict[str, Any] | None = None
        self._marker_binding = ""
        self._closed = False

    @property
    def path(self) -> Path:
        return lease_path(self.session, marker_dir=self.marker_dir)

    @property
    def lock_path(self) -> Path:
        return publisher_lock_path(self.session, marker_dir=self.marker_dir)

    def _acquire_owner_fence(self) -> None:
        if self._lock_handle is not None:
            return
        self.marker_dir.mkdir(parents=True, exist_ok=True)
        handle = self.lock_path.open("a+b")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            handle.close()
            raise RuntimeError(
                f"another liveness publisher owns session {self.session}"
            ) from exc
        self._lock_handle = handle
        # Advance the durable generation only after this publisher has won the
        # single-owner flock. A losing constructor must not fence the live
        # owner merely by attempting to start.
        self.runner_fence = _allocate_runner_fence(self.session, self.marker_dir)

    def _claim_marker(self) -> None:
        if self._marker_snapshot is not None:
            return
        marker_path = self.marker_dir / f"{self.session}.json"
        marker = _read_json(marker_path)
        if str(marker.get("session") or "") != self.session:
            raise RuntimeError(f"canonical session marker missing for {self.session}")
        required = {
            "workspace": marker.get("workspace"),
            "run_kind": marker.get("run_kind"),
            "run_id": marker.get("run_id"),
        }
        missing = [
            key for key, value in required.items() if not str(value or "").strip()
        ]
        if missing:
            raise RuntimeError(
                "canonical session marker lacks managed launch identity: "
                + ", ".join(missing)
            )
        marker.update(
            {
                "attempt_id": self.attempt_id,
                "incarnation_id": self.incarnation_id,
                "pid": self.target_pid,
                "pid_namespace_id": _namespace_id("pid", self.target_pid),
                "process_start_identity": self.target_start_identity,
                "liveness_claimed_at": _iso(_utcnow()),
            }
        )
        _refresh_authority_marker(marker)
        _atomic_json(marker_path, marker)
        self._marker_snapshot = marker
        self._marker_binding = marker_binding(marker)

    def _ensure_owner(self) -> None:
        self._acquire_owner_fence()
        self._claim_marker()

    def _target_matches(self) -> bool:
        return (
            _proc_start_identity(self.target_pid) == self.target_start_identity
            and _process_is_runnable(self.target_pid)
            and bool(self._marker_binding)
            and marker_binding(_read_json(self.marker_dir / f"{self.session}.json"))
            == self._marker_binding
        )

    def _payload(self, *, live: bool) -> dict[str, Any]:
        self._ensure_owner()
        marker = self._marker_snapshot or {}
        if (
            marker_binding(_read_json(self.marker_dir / f"{self.session}.json"))
            != self._marker_binding
        ):
            raise RuntimeError("canonical session marker changed after publisher claim")
        now = _utcnow()
        expires = now + timedelta(seconds=self.ttl_s) if live else now
        self._sequence += 1
        payload: dict[str, Any] = {
            "schema": SCHEMA,
            "session": self.session,
            "marker_binding": self._marker_binding,
            "workspace": str(marker.get("workspace") or ""),
            "remote_spec": str(marker.get("remote_spec") or ""),
            "run_kind": str(marker.get("run_kind") or ""),
            "run_id": str(marker.get("run_id") or ""),
            "attempt_id": self.attempt_id,
            "incarnation_id": self.incarnation_id,
            "lease_id": self.lease_id,
            "runner_fence": self.runner_fence,
            "sequence": self._sequence,
            "status": "live" if live else "stopped",
            "generated_at": _iso(now),
            "expires_at": _iso(expires),
            "runner_container_id": socket.gethostname(),
            "pid_namespace_id": _namespace_id("pid"),
            "time_namespace_id": _namespace_id("time"),
            "host_boot_id": self.target_start_identity.split(":", 1)[0],
            "target_pid": self.target_pid,
            "target_process_start_identity": self.target_start_identity,
            "publisher_pid": os.getpid(),
            "publisher_process_start_identity": _proc_start_identity(os.getpid()),
            "authority": "runner-owned-liveness-only",
        }
        payload["record_digest"] = _digest(payload)
        return payload

    def publish_once(self, *, live: bool = True) -> None:
        if self._closed:
            raise RuntimeError("closed liveness publisher cannot be resurrected")
        self._ensure_owner()
        if live and not self._target_matches():
            raise RuntimeError("bound target process incarnation is no longer live")
        _atomic_json(self.path, self._payload(live=live))

    def _run(self) -> None:
        while not self._stop.is_set() and self._target_matches():
            try:
                self.publish_once()
            except Exception:
                # A transient write failure must not kill the runner.  The old
                # lease expires and observers degrade to unknown.
                pass
            self._stop.wait(self.interval_s)

    def start(self) -> "LivenessLeasePublisher":
        self.publish_once()
        self._thread = threading.Thread(
            target=self._run,
            name=f"megaplan-liveness-{self.session}",
            daemon=True,
        )
        self._thread.start()
        return self

    def close(self) -> None:
        if self._closed:
            return
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self.interval_s + 0.5))
        # Terminalize only our own lease generation.
        current = _read_json(self.path)
        if current.get("lease_id") == self.lease_id:
            try:
                self.publish_once(live=False)
            except Exception:
                pass
        if self._lock_handle is not None:
            try:
                fcntl.flock(self._lock_handle.fileno(), fcntl.LOCK_UN)
            finally:
                self._lock_handle.close()
                self._lock_handle = None
        self._closed = True


def observe_liveness_lease(
    marker: Mapping[str, Any],
    *,
    marker_dir: Path = DEFAULT_MARKER_DIR,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate the current runner lease; never convert invalidity into death."""
    session = str(marker.get("session") or "")
    path = lease_path(session, marker_dir=Path(marker_dir))
    raw = _read_json(path)
    base = {
        "state": "unknown",
        "live": False,
        "path": str(path),
        "reason": "lease absent",
    }
    if not raw:
        return base
    if raw.get("schema") != SCHEMA:
        return {**base, "state": "degraded", "reason": "unsupported lease schema"}
    required_identity = (
        "run_kind",
        "run_id",
        "attempt_id",
        "incarnation_id",
        "pid_namespace_id",
        "target_process_start_identity",
    )
    if any(not str(raw.get(key) or "").strip() for key in required_identity):
        return {**base, "state": "degraded", "reason": "lease identity incomplete"}
    if not isinstance(raw.get("target_pid"), int) or isinstance(
        raw.get("target_pid"), bool
    ):
        return {**base, "state": "degraded", "reason": "lease target PID invalid"}
    supplied_digest = raw.get("record_digest")
    unsigned = dict(raw)
    unsigned.pop("record_digest", None)
    if supplied_digest != _digest(unsigned):
        return {**base, "state": "degraded", "reason": "lease digest mismatch"}
    if raw.get("session") != session or raw.get("marker_binding") != marker_binding(
        marker
    ):
        return {**base, "state": "degraded", "reason": "lease launch identity mismatch"}
    identity = {
        "lease_id": raw.get("lease_id"),
        "runner_container_id": raw.get("runner_container_id"),
        "pid_namespace_id": raw.get("pid_namespace_id"),
        "target_process_start_identity": raw.get("target_process_start_identity"),
        "marker_binding": raw.get("marker_binding"),
        "expires_at": raw.get("expires_at"),
        "runner_fence": raw.get("runner_fence"),
    }
    fence = _read_json(fence_path(session, marker_dir=Path(marker_dir)))
    try:
        if fence.get("schema") != FENCE_SCHEMA or fence.get("session") != session:
            raise ValueError("fence identity mismatch")
        current_fence = int(fence.get("runner_fence"))
        lease_fence = int(raw.get("runner_fence"))
    except (TypeError, ValueError):
        return {**base, **identity, "state": "degraded", "reason": "runner fence invalid"}
    if current_fence != lease_fence:
        return {
            **base,
            **identity,
            "state": "fenced",
            "reason": "runner lease belongs to a replaced fence generation",
            "current_runner_fence": current_fence,
        }
    generated = _parse_iso(raw.get("generated_at"))
    expires = _parse_iso(raw.get("expires_at"))
    if generated is None or expires is None:
        return {**base, "state": "degraded", "reason": "lease timestamp invalid"}
    observed = now or _utcnow()
    if generated > observed + timedelta(seconds=MAX_FUTURE_SKEW_S):
        return {**base, "state": "degraded", "reason": "lease generated in future"}
    if expires > generated + timedelta(seconds=MAX_LEASE_SPAN_S):
        return {**base, "state": "degraded", "reason": "lease span exceeds bound"}
    if raw.get("status") != "live" or expires <= observed:
        return {
            **base,
            **identity,
            "state": "expired",
            "reason": "runner lease expired or stopped",
        }
    return {
        "state": "live",
        "live": True,
        "path": str(path),
        "reason": "fresh identity-bound runner lease",
        **identity,
        "target_pid": raw.get("target_pid"),
        "run_kind": raw.get("run_kind"),
        "run_id": raw.get("run_id"),
        "attempt_id": raw.get("attempt_id"),
        "incarnation_id": raw.get("incarnation_id"),
        "sequence": raw.get("sequence"),
    }


def resolve_managed_session() -> str:
    """Resolve the session identity this process may publish liveness for.

    ROOT FIX (grok consult 2026-08-17, DeepSeek swarm evidence): session
    identity was split across two env vars with different semantics -
    ARNOLD_REPAIR_SESSION (box-global, set once at provisioning) vs
    ARNOLD_BABYSITTER_SESSION (per-dispatch, correct). The liveness layer
    read only the box-global one, so an astrid babysitter spawned by the
    mega watchdog's env inherited ARNOLD_REPAIR_SESSION=megaplan-maintenance
    and hijacked the MEGA lock/marker/lease (flock on mega lock, overwrote
    mega marker, persisted runner_lease.session=megaplan-maintenance into
    the astrid plan state, recursive superfixer collisions).

    Rules:
    - If ARNOLD_BABYSITTER_SESSION is set (per-dispatch, authoritative),
      it wins.
    - If ARNOLD_REPAIR_SESSION is set and differs from the babysitter
      session, the process is a FOREIGN identity leak: refuse to publish
      (return "") so it cannot hijack another session's lock/marker/lease.
    - Otherwise fall back to ARNOLD_REPAIR_SESSION (standalone runner).
    """
    babysitter = str(os.environ.get("ARNOLD_BABYSITTER_SESSION") or "").strip()
    repair = str(os.environ.get("ARNOLD_REPAIR_SESSION") or "").strip()
    if babysitter and repair and babysitter != repair:
        # Foreign identity leak: a per-dispatch babysitter session is present
        # and disagrees with the inherited box-global repair session. Never
        # publish under either - publishing under repair would hijack another
        # session; publishing under babysitter while the env claims repair
        # leaves the stale repair lease lying about liveness.
        return ""
    if babysitter:
        return babysitter
    return repair


def start_from_environment() -> LivenessLeasePublisher | None:
    session = resolve_managed_session()
    if not session:
        return None
    marker_dir = Path(
        os.environ.get("ARNOLD_REPAIR_MARKER_DIR") or str(DEFAULT_MARKER_DIR)
    )
    current_pid = os.getpid()
    current_start = _proc_start_identity(current_pid) or ""
    active = _ACTIVE_PUBLISHERS.get((current_pid, session))
    if active is not None:
        return active

    inherited_pid = 0
    try:
        inherited_pid = int(os.environ.get(OWNER_PID_ENV) or 0)
    except ValueError:
        inherited_pid = 0
    inherited_start = str(os.environ.get(OWNER_START_ENV) or "")
    if inherited_pid and inherited_pid != current_pid:
        if (
            inherited_start
            and _proc_start_identity(inherited_pid) == inherited_start
            and _process_is_runnable(inherited_pid)
        ):
            # A child process inherited the managed-run environment. The
            # exact parent incarnation remains the sole publisher.
            return None
    previous_pid = os.environ.get(OWNER_PID_ENV)
    previous_start = os.environ.get(OWNER_START_ENV)
    os.environ[OWNER_PID_ENV] = str(current_pid)
    os.environ[OWNER_START_ENV] = current_start
    publisher: LivenessLeasePublisher | None = None
    try:
        publisher = LivenessLeasePublisher(session, marker_dir=marker_dir)
        publisher.start()
    except Exception:
        if publisher is not None:
            publisher.close()
        if previous_pid is None:
            os.environ.pop(OWNER_PID_ENV, None)
        else:
            os.environ[OWNER_PID_ENV] = previous_pid
        if previous_start is None:
            os.environ.pop(OWNER_START_ENV, None)
        else:
            os.environ[OWNER_START_ENV] = previous_start
        return None
    publisher._previous_owner_env = (previous_pid, previous_start)
    _ACTIVE_PUBLISHERS[(current_pid, session)] = publisher
    return publisher


@contextlib.contextmanager
def managed_runner_lifecycle():
    """Publish exactly once for one managed CLI process and all its children."""

    session = resolve_managed_session()
    existing = _ACTIVE_PUBLISHERS.get((os.getpid(), session)) if session else None
    publisher = start_from_environment()
    owns_lifecycle = publisher is not None and publisher is not existing
    try:
        yield publisher
    finally:
        if owns_lifecycle and publisher is not None:
            publisher.close()
            _ACTIVE_PUBLISHERS.pop((os.getpid(), session), None)
            previous_pid, previous_start = getattr(
                publisher, "_previous_owner_env", (None, None)
            )
            if previous_pid is None:
                os.environ.pop(OWNER_PID_ENV, None)
            else:
                os.environ[OWNER_PID_ENV] = previous_pid
            if previous_start is None:
                os.environ.pop(OWNER_START_ENV, None)
            else:
                os.environ[OWNER_START_ENV] = previous_start


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Publish a runner-owned liveness lease"
    )
    parser.add_argument("publish", nargs="?")
    parser.add_argument("--session", required=True)
    parser.add_argument("--marker-dir", type=Path, default=DEFAULT_MARKER_DIR)
    parser.add_argument("--target-pid", type=int, default=os.getppid())
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL_S)
    parser.add_argument("--ttl", type=float, default=DEFAULT_TTL_S)
    args = parser.parse_args(argv)
    publisher = LivenessLeasePublisher(
        args.session,
        marker_dir=args.marker_dir,
        target_pid=args.target_pid,
        interval_s=args.interval,
        ttl_s=args.ttl,
    )
    try:
        publisher.start()
        while publisher._target_matches():
            time.sleep(min(1.0, publisher.interval_s))
    finally:
        publisher.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
