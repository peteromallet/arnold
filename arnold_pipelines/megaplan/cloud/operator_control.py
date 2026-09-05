"""Bounded local/on-box session control for durable operator pause."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from arnold_pipelines.megaplan.chain.operator_pause import (
    pause_chain,
    reconcile_quiesced_plan_pause,
    resume_chain,
)
from arnold_pipelines.megaplan.cloud.relaunch_resolution import marker_relaunch_command
from arnold_pipelines.megaplan.cloud.liveness_lease import tmux_authority_bindings
from arnold_pipelines.megaplan.incident.disposition import SignalDispositionError, signal_non_worker
from arnold_pipelines.megaplan.incident.ledger import IncidentLedger
from arnold_pipelines.megaplan.incident.schema import NonWorkerSignalDisposition


RESUME_HOLD_KEY = "operator_resume_hold"
RESUME_HOLD_SCHEMA = "arnold.megaplan.operator-resume-hold.v1"
_POST_LAUNCH_GRACE_SECONDS = 0.25
_TMUX_BINDING_KEYS = (
    "tmux_socket", "tmux_socket_fingerprint", "tmux_server_pid",
    "tmux_server_process_start_identity", "tmux_session_id",
    "tmux_owned_pane_id", "tmux_owned_pane_pid",
    "tmux_owned_pane_process_start_identity", "tmux_owned_pane_command",
    "tmux_all_panes_digest",
)


def _pid_start_identity(pid: int) -> str | None:
    """Return a positive process-incarnation token on Linux or macOS."""
    try:
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()
        if len(fields) > 21 and fields[21]:
            return fields[21]
    except (OSError, IndexError):
        pass
    try:
        result = subprocess.run(
            ["ps", "-o", "lstart=", "-p", str(pid)],
            capture_output=True,
            text=True,
            check=False,
            timeout=2,
        )
    except (OSError, TypeError, AttributeError, subprocess.TimeoutExpired):
        return None
    started = result.stdout.strip()
    if result.returncode != 0 or not started:
        return None
    return "ps-lstart:" + hashlib.sha256(started.encode("utf-8")).hexdigest()


def _resume_hold(
    *,
    spec: Path,
    workspace: Path,
    session: str,
    resume_authority: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": RESUME_HOLD_SCHEMA,
        "active": True,
        "session": session,
        "spec": str(spec.resolve(strict=False)),
        "workspace": str(workspace.resolve(strict=False)),
        "resume_authority": resume_authority,
    }


def _runner_survives_launch(session: str) -> bool:
    probe = ["tmux", "has-session", "-t", session]
    if subprocess.run(probe, check=False).returncode != 0:
        return False
    time.sleep(_POST_LAUNCH_GRACE_SECONDS)
    return subprocess.run(probe, check=False).returncode == 0


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError:
        return False
    return True


def _owned_pidfile_snapshot(
    path: Path,
    *,
    session: str,
    expected_pid: int | None = None,
    expected_group: int | None = None,
    expected_start: str | None = None,
) -> tuple[int, int, str, str]:
    """Read and fence one operator-owned pidfile incarnation.

    This is deliberately a complete snapshot: callers must re-run it as the
    final ledger-locked preflight, immediately before invoking the signal
    primitive.  A pidfile by itself is never an authority for a signal.
    """
    try:
        pid = int(path.read_text(encoding="utf-8").strip())
        cmdline = (
            Path(f"/proc/{pid}/cmdline")
            .read_bytes()
            .replace(b"\0", b" ")
            .decode(errors="replace")
        )
    except (OSError, ValueError) as exc:
        raise SignalDispositionError("owned pidfile or process command line is unavailable") from exc
    if expected_pid is not None and pid != expected_pid:
        raise SignalDispositionError("owned pidfile PID changed before teardown")
    if session not in cmdline or not any(
        token in cmdline for token in ("arnold-babysitter",)
    ):
        raise SignalDispositionError("pidfile target is not the owned operator runner")
    try:
        group = os.getpgid(pid)
    except (OSError, ProcessLookupError) as exc:
        raise SignalDispositionError("owned runner process group is unavailable") from exc
    if expected_group is not None and group != expected_group:
        raise SignalDispositionError("owned runner process group changed before teardown")
    start_identity = _pid_start_identity(pid)
    if not start_identity:
        raise SignalDispositionError("owned runner process identity is unavailable")
    if expected_start is not None and start_identity != expected_start:
        raise SignalDispositionError("owned runner process incarnation changed before teardown")
    return pid, group, start_identity, cmdline


def _stop_owned_pidfile(
    path: Path,
    *,
    session: str,
    workspace: Path,
    marker_path: Path,
) -> bool:
    """Stop a marker-bound operator runner through the non-worker ledger door."""
    workspace = workspace.expanduser().resolve(strict=False)
    path = path.expanduser().resolve(strict=False)
    marker_path = marker_path.expanduser().resolve(strict=False)
    if not _path_is_within(path, workspace) or not marker_path.is_absolute():
        return False
    try:
        marker, marker_sha256 = _load_marker(marker_path)
    except RuntimeError:
        return False
    marker_workspace = marker.get("workspace")
    if marker.get("session") != session or not isinstance(marker_workspace, str):
        return False
    try:
        if Path(marker_workspace).expanduser().resolve(strict=False) != workspace:
            return False
    except (OSError, RuntimeError):
        return False
    marker_ledger_root = marker.get("ledger_root") or marker.get("incident_ledger_root")
    if marker_ledger_root is not None:
        try:
            expected_ledger_root = workspace / ".megaplan" / "incident-ledger"
            if Path(str(marker_ledger_root)).expanduser().resolve(strict=False) != expected_ledger_root.resolve(strict=False):
                return False
        except (OSError, RuntimeError):
            return False
    try:
        pid, group, start_identity, cmdline = _owned_pidfile_snapshot(path, session=session)
        ledger = IncidentLedger(workspace)
        disposition = NonWorkerSignalDisposition(
            disposition_id=hashlib.sha256(
                f"operator-lifecycle\0{session}\0{group}\0term".encode()
            ).hexdigest(),
            subject="non_worker_lifecycle",
            lifecycle_identity=f"operator-session:{session}",
            killer_identity=f"operator:{os.getpid()}",
            cause_kind="lifecycle_shutdown",
            signal="SIGTERM",
            victim_pid_or_group=str(group),
            victim_process_start_identity=start_identity,
            observed_at=datetime.now(timezone.utc).isoformat(),
            evidence={"pidfile": str(path), "session": session, "cmdline": cmdline},
        )

        def preflight(_records: list[dict[str, Any]]) -> None:
            try:
                current_marker, current_sha256 = _load_marker(marker_path)
            except RuntimeError as exc:
                raise SignalDispositionError("operator marker disappeared before teardown") from exc
            if current_sha256 != marker_sha256 or current_marker != marker:
                raise SignalDispositionError("operator marker changed before teardown")
            _owned_pidfile_snapshot(
                path,
                session=session,
                expected_pid=pid,
                expected_group=group,
                expected_start=start_identity,
            )

        signal_non_worker(
            ledger,
            disposition,
            signal_fn=lambda: os.killpg(group, signal.SIGTERM),
            preflight=preflight,
        )
    except (ProcessLookupError, PermissionError, OSError, ValueError, SignalDispositionError):
        return False
    return True


def _validated_tmux_binding(marker: dict[str, Any], *, session: str) -> dict[str, Any] | None:
    """Return the marker's tmux binding only after a fresh exact re-query."""
    if marker.get("session") != session:
        return None
    if any(key not in marker for key in _TMUX_BINDING_KEYS):
        return None
    expected = {key: marker[key] for key in _TMUX_BINDING_KEYS}
    try:
        fresh = tmux_authority_bindings({**marker, "session": session})
    except Exception:
        return None
    return expected if fresh == expected else None


def _stop_tmux_session(
    marker: dict[str, Any], *, session: str, marker_path: Path, workspace: Path,
    expected_identity_digest: str | None = None,
    expected_remote_spec: str | None = None,
) -> bool:
    """Durably acknowledge an exact, marker-owned tmux session teardown."""
    if expected_identity_digest is not None and marker.get("identity_digest") != expected_identity_digest:
        return False
    if expected_remote_spec is not None and marker.get("remote_spec") != expected_remote_spec:
        return False
    binding = _validated_tmux_binding(marker, session=session)
    if binding is None:
        return False
    ledger = IncidentLedger(workspace)
    disposition_id = hashlib.sha256(
        json.dumps(
            ["operator-tmux", session, binding, "SIGTERM"],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    disposition = NonWorkerSignalDisposition(
        disposition_id=disposition_id,
        subject="non_worker_lifecycle",
        lifecycle_identity=f"operator-tmux:{session}:{binding['tmux_session_id']}",
        killer_identity=f"operator:{os.getpid()}",
        cause_kind="lifecycle_shutdown",
        signal="SIGTERM",
        victim_pid_or_group=str(binding["tmux_session_id"]),
        victim_process_start_identity=str(binding["tmux_server_process_start_identity"]),
        observed_at=datetime.now(timezone.utc).isoformat(),
        evidence={"marker_path": str(marker_path), "tmux": binding},
    )

    def preflight(_records: list[dict[str, Any]]) -> None:
        try:
            current_marker, _current_sha = _load_marker(marker_path)
        except RuntimeError as exc:
            raise SignalDispositionError("tmux marker disappeared before teardown") from exc
        if current_marker != marker or _validated_tmux_binding(current_marker, session=session) != binding:
            raise SignalDispositionError("tmux session or owned pane changed before teardown")

    def invoke() -> None:
        result = subprocess.run(
            [
                "tmux", "-S", str(binding["tmux_socket"]), "kill-session",
                "-t", f"={binding['tmux_session_id']}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise SignalDispositionError(
                f"tmux teardown failed with status {result.returncode}"
            )

    try:
        signal_non_worker(ledger, disposition, signal_fn=invoke, preflight=preflight)
    except (OSError, ValueError, SignalDispositionError):
        return False
    return True


def pause_session(
    *,
    spec: Path,
    workspace: Path,
    session: str,
    marker_path: Path,
    reason: str,
    actor: str,
) -> dict[str, Any]:
    marker, marker_sha256 = _load_marker(marker_path)
    result = pause_chain(spec, workspace, reason=reason, actor=actor)
    stopped = _stop_tmux_session(
        marker, session=session, marker_path=marker_path, workspace=workspace
    )
    marker_dir = marker_path.parent
    repair_stopped = any(
        _stop_owned_pidfile(
            path,
            session=session,
            workspace=workspace,
            marker_path=marker_path,
        )
        for path in (
            marker_dir / f"{session}.repair-loop.pid",
            marker_dir / f"{session}.meta-repair.pid",
        )
    )
    # tmux can return from kill-session while the terminated runner is
    # flushing its final in-memory state.  Give that bounded flush a chance to
    # land, then converge only the dead-owned writer race.  Arbitrary plan
    # changes remain fail-closed in reconcile_quiesced_plan_pause().
    time.sleep(_POST_LAUNCH_GRACE_SECONDS)
    plan_reconciled = reconcile_quiesced_plan_pause(
        spec,
        workspace,
        session=session,
        authority=result["authority"],
    )
    # Re-read under the marker cutover lock only for operator pause state.  A
    # marker is not launch authority; OperationRun owns launch admission and
    # accepted identity, so pausing never creates or cancels a launch
    # reservation projection.
    with marker_runtime_cutover_lock(marker_path):
        current_marker, current_sha256 = _load_marker(marker_path)
        current_marker["operator_pause"] = result["authority"]
        current_marker["should_run"] = False
        _write_marker_locked(marker_path, current_marker, expected_sha256=current_sha256)
    return {
        **result,
        "session": session,
        "runner_stopped": stopped,
        "repair_stopped": repair_stopped,
        "plan_reconciled": plan_reconciled,
    }


def resume_session(
    *,
    spec: Path,
    workspace: Path,
    session: str,
    marker_path: Path,
    actor: str,
    no_push: bool = False,
    start_runner: bool = True,
) -> dict[str, Any]:
    marker, marker_sha256 = _load_marker(marker_path)
    relaunch: str | None = None
    if start_runner:
        relaunch = marker_relaunch_command(marker)
        if not relaunch:
            raise RuntimeError("session marker relaunch command is stale or unavailable")
        if (
            subprocess.run(["tmux", "has-session", "-t", session], check=False).returncode
            == 0
        ):
            raise RuntimeError("session already has a live runner")
    hold = marker.get(RESUME_HOLD_KEY)
    hold = hold if isinstance(hold, dict) else None
    if hold is not None:
        if (
            hold.get("schema_version") != RESUME_HOLD_SCHEMA
            or hold.get("active") is not True
            or hold.get("session") != session
            or hold.get("spec") != str(spec.resolve(strict=False))
            or hold.get("workspace") != str(workspace.resolve(strict=False))
            or not isinstance(hold.get("resume_authority"), dict)
        ):
            raise RuntimeError("operator resume hold is invalid or targets another session")
        result = resume_chain(
            spec,
            workspace,
            actor=actor,
            verify_execution_binding=start_runner,
            expected_resume_authority=hold["resume_authority"],
        )
    elif marker.get("should_run") is False and not isinstance(marker.get("operator_pause"), dict):
        # Compatibility for authority-cleared holds created before the typed
        # marker receipt existed.  Require the complete canonical marker
        # identity; arbitrary marker-only stops remain fail-closed.
        marker_session = marker.get("chain_session") or marker.get("session")
        if (
            marker_session != session
            or marker.get("remote_spec") != str(spec.resolve(strict=False))
            or marker.get("workspace") != str(workspace.resolve(strict=False))
            or marker.get("retired") is True
            or marker.get("superseded") is True
        ):
            raise RuntimeError("legacy authority-cleared hold lacks exact session custody")
        result = resume_chain(
            spec,
            workspace,
            actor=actor,
            verify_execution_binding=start_runner,
            allow_legacy_authority_cleared_hold=True,
        )
    else:
        result = resume_chain(
            spec,
            workspace,
            actor=actor,
            verify_execution_binding=start_runner,
        )
    if not start_runner:
        marker.pop("operator_pause", None)
        marker["should_run"] = False
        marker[RESUME_HOLD_KEY] = _resume_hold(
            spec=spec,
            workspace=workspace,
            session=session,
            resume_authority=result["resume_authority"],
        )
        _write_marker(marker_path, marker, expected_sha256=marker_sha256)
        return {
            **result,
            "session": session,
            "runner_started": False,
            "no_push": no_push,
            "authority_only": True,
        }
    assert relaunch is not None
    queue_root = Path(
        os.environ.get("ARNOLD_REPAIR_QUEUE_ROOT")
        or marker_path.parent.parent / "repair-queue"
    )
    managed_env = {
        "ARNOLD_REPAIR_QUEUE_ROOT": str(queue_root),
        "ARNOLD_REPAIR_MARKER_DIR": str(marker_path.parent),
        "ARNOLD_REPAIR_SESSION": session,
        "ARNOLD_REPAIR_RUN_KIND": str(marker.get("run_kind") or "chain"),
    }
    if no_push:
        # A no-push chain resume deliberately stays on the current milestone
        # checkout. In chain.run_chain this disables PR branch preparation,
        # whose cleanup step otherwise resets tracked and untracked WIP before
        # checking out the remote milestone branch.
        managed_env["MEGAPLAN_CHAIN_NO_PUSH"] = "1"
    tmux_command = ["tmux", "new-session", "-d", "-s", session, "-c", str(workspace)]
    for key, value in managed_env.items():
        tmux_command.extend(["-e", f"{key}={value}"])
    tmux_command.append(relaunch)
    # Publish the final launch-authorizing marker before dispatch.  Runtime
    # attestation binds the marker's stable launch identity, while this CAS
    # prevents a concurrent pause/rebind from being overwritten.
    marker.pop("operator_pause", None)
    marker.pop(RESUME_HOLD_KEY, None)
    marker["should_run"] = True
    launched_marker_sha256 = _write_marker(
        marker_path,
        marker,
        expected_sha256=marker_sha256,
    )
    try:
        subprocess.run(tmux_command, check=True)
        alive = _runner_survives_launch(session)
        if not alive:
            raise RuntimeError("session runner exited before post-launch liveness confirmation")
    except Exception:
        # Restore a resumable stopped marker.  CAS prevents this failure path
        # from overwriting a concurrent pause, rebind, or successful relaunch.
        stopped, stopped_sha256 = _load_marker(marker_path)
        if stopped_sha256 != launched_marker_sha256:
            raise RuntimeError(
                "session marker changed concurrently after launch dispatch; "
                "refusing to restore stale stop authority"
            )
        stopped["should_run"] = False
        stopped[RESUME_HOLD_KEY] = _resume_hold(
            spec=spec,
            workspace=workspace,
            session=session,
            resume_authority=result["resume_authority"],
        )
        _write_marker(marker_path, stopped, expected_sha256=stopped_sha256)
        raise
    return {
        **result,
        "session": session,
        "runner_started": True,
        "no_push": no_push,
    }


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load_marker(path: Path) -> tuple[dict[str, Any], str]:
    try:
        encoded = path.read_bytes()
        value = json.loads(encoded)
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"session marker is unreadable or invalid: {path}") from exc
    if not isinstance(value, dict):
        raise RuntimeError("session marker must be a JSON object")
    return value, _sha256(encoded)


def _write_marker(
    path: Path,
    value: dict[str, Any],
    *,
    expected_sha256: str,
) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    with marker_runtime_cutover_lock(path):
        return _write_marker_locked(path, value, expected_sha256=expected_sha256)


@contextmanager
def marker_runtime_cutover_lock(
    path: Path,
    *,
    blocking: bool = True,
    timeout_s: float | None = None,
):
    """Hold the canonical lock for all marker read/CAS cutover operations.

    Babysitter admission and operator pause share this exact lock.  The
    non-blocking form is intentionally exposed so an automatic dispatch can
    report a typed suppression instead of waiting behind an operator action.
    A caller with an already-claimed reservation may use bounded blocking to
    let an in-flight pause finish before validating that claim.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".runtime-cutover.lock")
    with lock_path.open("a+", encoding="utf-8") as lock:
        if timeout_s is not None:
            if not blocking or isinstance(timeout_s, bool) or timeout_s < 0:
                raise ValueError("lock timeout requires blocking=True and a non-negative number")
            deadline = time.monotonic() + float(timeout_s)
        else:
            deadline = None
        flags = fcntl.LOCK_EX
        if not blocking or deadline is not None:
            flags |= fcntl.LOCK_NB
        while True:
            try:
                fcntl.flock(lock.fileno(), flags)
                break
            except BlockingIOError:
                if not blocking:
                    raise
                if deadline is None:
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        f"timed out acquiring marker runtime-cutover lock: {lock_path}"
                    )
                # flock has no portable timed-blocking form.  Sleeping keeps
                # the bounded retry from spinning while pause reaches its CAS.
                time.sleep(min(0.05, remaining))
        try:
            yield lock
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _write_marker_locked(
    path: Path,
    value: dict[str, Any],
    *,
    expected_sha256: str,
) -> str:
    """Write a marker while ``marker_runtime_cutover_lock`` is held."""
    try:
        current = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"session marker disappeared during update: {path}") from exc
    observed_sha256 = _sha256(current)
    if observed_sha256 != expected_sha256:
        raise RuntimeError(
            "session marker changed concurrently: "
            f"expected {expected_sha256}, observed {observed_sha256}"
        )
    if "content_digest" in value or "marker_sha256" in value:
        unsigned = dict(value)
        unsigned.pop("content_digest", None)
        unsigned.pop("marker_sha256", None)
        value = dict(value)
        value["content_digest"] = _sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return _sha256(encoded)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("pause", "resume", "tmux-stop"))
    parser.add_argument("--spec", required=True)
    parser.add_argument("--workspace")
    parser.add_argument("--session", required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--identity-digest")
    parser.add_argument("--remote-spec")
    parser.add_argument("--reason", default="operator requested pause")
    parser.add_argument("--actor", default="operator")
    parser.add_argument(
        "--no-push",
        action="store_true",
        help=(
            "resume with MEGAPLAN_CHAIN_NO_PUSH=1 so an existing dirty "
            "milestone checkout is not reset for PR branch preparation"
        ),
    )
    parser.add_argument(
        "--no-start",
        action="store_true",
        help="clear durable pause authority without starting the chain runner",
    )
    args = parser.parse_args(argv)
    if args.action == "tmux-stop":
        marker_path = Path(args.marker)
        marker, _marker_sha256 = _load_marker(marker_path)
        marker_workspace = marker.get("workspace") or args.workspace
        if not isinstance(marker_workspace, str) or not marker_workspace:
            print("tmux authority rejected: marker workspace is missing", file=sys.stderr)
            return 78
        stopped = _stop_tmux_session(
            marker,
            session=args.session,
            marker_path=marker_path,
            workspace=Path(marker_workspace),
            expected_identity_digest=args.identity_digest,
            expected_remote_spec=args.remote_spec,
        )
        if stopped:
            print(json.dumps({"success": True, "runner_stopped": True}, sort_keys=True))
            return 0
        print("tmux authority rejected or teardown failed", file=sys.stderr)
        return 78
    if not args.workspace:
        parser.error("--workspace is required for pause/resume")
    common = {
        "spec": Path(args.spec),
        "workspace": Path(args.workspace),
        "session": args.session,
        "marker_path": Path(args.marker),
        "actor": args.actor,
    }
    payload = (
        pause_session(**common, reason=args.reason)
        if args.action == "pause"
        else resume_session(
            **common,
            no_push=args.no_push,
            start_runner=not args.no_start,
        )
    )
    print(json.dumps({"success": True, **payload}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
