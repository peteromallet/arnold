from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from arnold_pipelines.megaplan.cloud.runtime_manifest import MANIFEST_SCHEMA_VERSION, RuntimeManifest, write_manifest
from arnold_pipelines.megaplan.cloud import cli as cloud_cli
from arnold_pipelines.megaplan.cloud import liveness_lease
from arnold_pipelines.megaplan.cloud.worker_dispatch import WorkerExecutionContextRef
from arnold_pipelines.megaplan.incident.authority import (
    SignalAuthorityError,
    resolve_signal_authority,
    revalidate_signal_payload,
)
from arnold_pipelines.megaplan.incident.ledger import IncidentLedger
from arnold_pipelines.megaplan.incident.schema import NonWorkerSignalDisposition
from arnold_pipelines.megaplan.watchdog.worker_identity import current_boot_identity, read_process_start_identity


def _manifest(path: Path, workspace: Path) -> Path:
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)
    (workspace / "seed").write_text("authority\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(workspace), "add", "seed"], check=True)
    subprocess.run(["git", "-C", str(workspace), "-c", "user.email=test@example.invalid", "-c", "user.name=pytest", "commit", "-qm", "seed"], check=True)
    head = subprocess.check_output(["git", "-C", str(workspace), "rev-parse", "HEAD"], text=True).strip()
    manifest = RuntimeManifest.from_dict({
        "runtime_id": "runtime-authority-1", "schema": MANIFEST_SCHEMA_VERSION,
        "generation": 7, "epic_id": "epic-authority", "state": "active", "owner": "pytest",
        "base": {"ref": "refs/heads/main", "commit": head, "editable_install_path": str(workspace), "venv_path": str(workspace / "venv")},
        "epic": {"branch": "authority", "worktree_path": str(workspace), "venv_path": str(workspace / "venv"), "runtime_root": str(workspace), "expected_head": head, "repair_bin": str(workspace / "bin"), "deps_lockfile": str(workspace / "uv.lock")},
        "indirection": {"host_path": str(workspace), "container_path": str(workspace), "mount_table": [], "execution_namespace": "pytest", "verified_head": head, "last_verified_at": "2026-08-31T00:00:00+00:00", "attestation": {"module_file": str(workspace / "module.py"), "module_digest": "b" * 64, "mount_id": "pytest"}},
        "policy": {"policy_sha": "policy", "model_policy_sha": "model", "sync_policy": "sync"},
        "promotions": [], "timestamps": {"created": "2026-08-31T00:00:00+00:00", "updated": "2026-08-31T00:00:00+00:00", "closed": ""},
        "gc_policy": "closed-only", "commands": ["pytest"],
    })
    write_manifest(manifest, path)
    return path


def _marker(marker_path: Path, *, session: str, workspace: Path, manifest: Path, pid: int, start: str, progress: Path, **extra: object) -> None:
    payload: dict[str, object] = {
        "session": session, "workspace": str(workspace), "run_id": f"run-{session}",
        "bootstrap_manifest_path": str(manifest),
        "runtime_id": "runtime-authority-1", "generation": 7,
        "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "progress_artifact": str(progress), "progress_content_digest": hashlib.sha256(progress.read_bytes()).hexdigest(), "progress_identity": f"progress-{session}",
        "supervisor_pid": os.getpid(), "supervisor_process_start_identity": read_process_start_identity(os.getpid()),
        "boot_identity": current_boot_identity(), "container_identity": os.environ.get("ARNOLD_CONTAINER_IDENTITY") or __import__("socket").gethostname(),
        "victim_pid": pid, "victim_process_start_identity": start,
        **extra,
    }
    unsigned = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    payload["content_digest"] = hashlib.sha256(unsigned.encode()).hexdigest()
    marker_path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")


@pytest.fixture
def authority_fixture(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".megaplan" / "incident-ledger").mkdir(parents=True)
    progress = workspace / "progress.json"
    progress.write_text("{}\n", encoding="utf-8")
    manifest = _manifest(workspace / ".megaplan" / "bootstrap.json", workspace)
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    victim = subprocess.Popen(["/bin/sleep", "30"])
    session = "session-a"
    marker_path = marker_dir / f"{session}.json"
    _marker(marker_path, session=session, workspace=workspace, manifest=manifest, pid=victim.pid, start=read_process_start_identity(victim.pid), progress=progress)
    try:
        yield workspace, marker_dir, manifest, progress, victim, session, marker_path
    finally:
        if victim.poll() is None:
            victim.kill()
            victim.wait(timeout=3)


def test_resolver_binds_explicit_marker_manifest_and_derives_identities(authority_fixture):
    workspace, marker_dir, manifest, progress, victim, session, marker_path = authority_fixture
    context = resolve_signal_authority(site_id="watchdog", session=session, marker_path=marker_path, target_kind="non_worker", victim_pid=victim.pid, victim_process_start_identity=read_process_start_identity(victim.pid), marker_dir=marker_dir)
    assert context.ledger_root == str(workspace)
    assert context.runtime_id == "runtime-authority-1"
    assert context.lifecycle_identity
    assert context.relevant_progress_identity.endswith(hashlib.sha256(progress.read_bytes()).hexdigest())
    assert context.validate_target_start()


def test_arbitrary_marker_and_ambient_environment_are_not_authority(authority_fixture, monkeypatch):
    workspace, marker_dir, manifest, progress, victim, session, marker_path = authority_fixture
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(marker_dir / "arbitrary.json"))
    with pytest.raises(SignalAuthorityError):
        resolve_signal_authority(site_id="watchdog", session=session, marker_path=workspace / "arbitrary.json", target_kind="non_worker", victim_pid=victim.pid, marker_dir=marker_dir)
    context = resolve_signal_authority(site_id="watchdog", session=session, marker_path=marker_path, target_kind="non_worker", victim_pid=victim.pid, marker_dir=marker_dir)
    assert context.manifest_path == str(manifest)


def test_marker_replacement_and_pid_reuse_are_rejected(authority_fixture):
    workspace, marker_dir, manifest, progress, victim, session, marker_path = authority_fixture
    start = read_process_start_identity(victim.pid)
    context = resolve_signal_authority(site_id="watchdog", session=session, marker_path=marker_path, target_kind="non_worker", victim_pid=victim.pid, victim_process_start_identity=start, marker_dir=marker_dir)
    payload = context.to_dict()
    payload["marker_dir"] = str(marker_dir)
    victim.terminate(); victim.wait(timeout=3)
    with pytest.raises(SignalAuthorityError):
        revalidate_signal_payload(payload, marker_dir=marker_dir, ledger_root=workspace)
    # A replacement marker with a valid self-digest still cannot satisfy the
    # old derived lifecycle identity in the CLI envelope.
    _marker(marker_path, session=session, workspace=workspace, manifest=manifest, pid=os.getpid(), start=read_process_start_identity(os.getpid()), progress=progress, run_id="replacement")
    with pytest.raises(SignalAuthorityError):
        revalidate_signal_payload(payload, marker_dir=marker_dir, ledger_root=workspace)


def test_worker_requires_unique_reservation_and_exact_physical_door(authority_fixture):
    workspace, marker_dir, manifest, progress, victim, session, marker_path = authority_fixture
    ledger = IncidentLedger(workspace)
    fingerprint = "f" * 64
    reservation = ledger.reserve(plan_id="p", phase="execute", projection_key="x", semantic_dispatch_fingerprint=fingerprint, logical_dispatch_id="l", dispatch_family_id="family", physical_door_id="door-a", selected_spec="codex")
    ref = WorkerExecutionContextRef(ledger_root=str(workspace), plan_id="p", phase="execute", dispatch_family_id="family", logical_dispatch_id="l", admission_receipt_id=reservation["payload"]["admission_receipt_id"], semantic_dispatch_fingerprint=fingerprint, selected_spec="codex", physical_door_id="door-b")
    raw = json.loads(marker_path.read_text(encoding="utf-8")); raw["worker_context"] = ref.to_dict(); raw.pop("content_digest"); raw["content_digest"] = hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest(); marker_path.write_text(json.dumps(raw, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    with pytest.raises(SignalAuthorityError, match="reservation"):
        resolve_signal_authority(site_id="worker", session=session, marker_path=marker_path, target_kind="worker", victim_pid=victim.pid, marker_dir=marker_dir)


def test_per_target_contexts_have_distinct_lifecycle(authority_fixture):
    workspace, marker_dir, manifest, progress, victim, session, marker_path = authority_fixture
    context_a = resolve_signal_authority(site_id="watchdog-a", session=session, marker_path=marker_path, target_kind="non_worker", victim_pid=victim.pid, marker_dir=marker_dir)
    context_b = resolve_signal_authority(site_id="watchdog-b", session=session, marker_path=marker_path, target_kind="non_worker", victim_pid=victim.pid, marker_dir=marker_dir)
    assert context_a.lifecycle_identity != context_b.lifecycle_identity


def test_signal_cli_reloads_explicit_authority_under_ledger_lock(authority_fixture):
    workspace, marker_dir, manifest, progress, victim, session, marker_path = authority_fixture
    context = resolve_signal_authority(site_id="watchdog", session=session, marker_path=marker_path, target_kind="non_worker", victim_pid=victim.pid, marker_dir=marker_dir)
    payload = {
        **context.to_dict(), "marker_dir": str(marker_dir), "killer_identity": "pytest",
        "signal": "SIGTERM", "ladder_stage": "term", "scan_interval_s": 0.05,
        "require_confirmation": True, "evidence": {"reason": "authority-test"},
    }
    assert payload["bootstrap_manifest_path"] == str(manifest)
    result = subprocess.run(
        [sys.executable, "-m", "arnold_pipelines.megaplan.incident.disposition", "signal-non-worker", "--ledger-root", str(workspace), "--marker-dir", str(marker_dir), "--json-stdin"],
        input=json.dumps(payload), text=True, capture_output=True,
        cwd=Path(__file__).resolve().parents[3], env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[3])}, check=False,
    )
    assert result.returncode == 75, result.stderr
    assert victim.poll() is None


def test_dead_replay_without_signal_claim_is_held(authority_fixture):
    workspace, marker_dir, manifest, progress, victim, session, marker_path = authority_fixture
    context = resolve_signal_authority(site_id="watchdog", session=session, marker_path=marker_path, target_kind="non_worker", victim_pid=victim.pid, marker_dir=marker_dir)
    from arnold_pipelines.megaplan.incident import disposition as disposition_module
    signal_name = "SIGTERM"
    disposition_id = disposition_module._digest({
        "schema_version": 1, "site_id": context.site_id,
        "lifecycle_identity": context.lifecycle_identity, "victim_pid": victim.pid,
        "victim_process_start_identity": context.victim_process_start_identity,
        "signal": signal_name, "ladder_stage": "term",
    })
    IncidentLedger(workspace).append_disposition(NonWorkerSignalDisposition(
        disposition_id=disposition_id, subject="non_worker_lifecycle",
        lifecycle_identity=context.lifecycle_identity, killer_identity="pytest",
        cause_kind="lifecycle_shutdown", signal=signal_name,
        victim_pid_or_group=str(victim.pid), victim_process_start_identity=context.victim_process_start_identity,
        observed_at="2026-08-31T00:00:00+00:00", evidence={}, confirmation_event_id=None,
    ))
    victim.terminate(); victim.wait(timeout=3)
    payload = {
        **context.to_dict(), "marker_dir": str(marker_dir), "killer_identity": "pytest",
        "signal": signal_name, "ladder_stage": "term", "scan_interval_s": 0.05,
        "require_confirmation": True,
    }
    result = subprocess.run(
        [sys.executable, "-m", "arnold_pipelines.megaplan.incident.disposition", "signal-non-worker", "--ledger-root", str(workspace), "--marker-dir", str(marker_dir), "--json-stdin"],
        input=json.dumps(payload), text=True, capture_output=True,
        cwd=Path(__file__).resolve().parents[3], env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[3])}, check=False,
    )
    assert result.returncode == 5
    assert "authority rejected" in result.stderr


def test_real_chain_marker_producer_round_trips_through_authority(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".megaplan" / "incident-ledger").mkdir(parents=True)
    manifest = _manifest(workspace / ".megaplan" / "runtime-manifest.json", workspace)
    log = workspace / ".megaplan" / "cloud-logs" / "plan.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text("chain starting\n", encoding="utf-8")
    victim = subprocess.Popen(["/bin/sleep", "30"])
    marker_dir = tmp_path / "markers"
    marker_path = marker_dir / "chain-session.json"
    try:
        payload = cloud_cli._bootstrap_marker_payload(
            session_name="chain-session", workspace=str(workspace), remote_spec="/workspace/plan.yaml",
            plan_name="plan", relaunch_command="arnold chain start",
        )
        result = subprocess.run(
            ["bash", "-c", cloud_cli._atomic_marker_write_command(str(marker_path), payload)],
            env={**os.environ, "MEGAPLAN_SUPERVISOR_PID": str(os.getpid())},
            capture_output=True, text=True, check=False,
        )
        assert result.returncode == 0, result.stderr
        context = resolve_signal_authority(
            site_id="chain", session="chain-session", marker_path=marker_path,
            target_kind="non_worker", victim_pid=victim.pid,
            victim_process_start_identity=read_process_start_identity(victim.pid), marker_dir=marker_dir,
        )
        assert context.manifest_path == str(manifest)
        assert context.relevant_progress_identity.endswith(hashlib.sha256(log.read_bytes()).hexdigest())
    finally:
        if victim.poll() is None:
            victim.kill(); victim.wait(timeout=3)


def test_liveness_refresh_uses_explicit_marker_manifest_and_progress(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    manifest = _manifest(tmp_path / "pinned" / "runtime.json", workspace)
    progress = tmp_path / "chain.log"
    progress.write_text("chain progress\n", encoding="utf-8")
    marker = {
        "session": "chain-session",
        "workspace": str(workspace),
        "run_id": "launch:chain",
        "runtime_manifest": {"path": str(workspace / ".megaplan" / "runtime-manifest.json")},
        "bootstrap_manifest_path": str(manifest),
        "progress_artifact": str(progress),
        "progress_identity": "chain:projected-progress",
        "manifest_sha256": "stale",
        "manifest_identity": "stale",
    }

    liveness_lease._refresh_authority_marker(marker)

    expected = hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert marker["bootstrap_manifest_path"] == str(manifest)
    assert marker["manifest_sha256"] == expected
    assert marker["manifest_identity"] == expected
    assert marker["progress_artifact"] == str(progress)
    assert marker["progress_identity"] == "chain:projected-progress"
    assert marker["progress_content_digest"] == hashlib.sha256(progress.read_bytes()).hexdigest()


@pytest.mark.skipif(__import__("shutil").which("tmux") is None, reason="tmux unavailable")
def test_real_tmux_marker_binding_round_trips_and_replacement_is_rejected(tmp_path: Path, monkeypatch):
    """The producer's explicit socket/session/pane proof is runtime-validated."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".megaplan" / "incident-ledger").mkdir(parents=True)
    manifest = _manifest(workspace / ".megaplan" / "runtime-manifest.json", workspace)
    progress = workspace / "progress.json"
    progress.write_text("tmux\n", encoding="utf-8")
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    # macOS tmux has a short Unix-socket path limit; keep the test socket in
    # /tmp while all authority artifacts remain in pytest's isolated tree.
    socket_path = Path("/tmp") / f"arnold-nbf-tmux-{os.getpid()}.sock"
    session = "authority-tmux"
    socket_path.unlink(missing_ok=True)
    subprocess.run(["tmux", "-S", str(socket_path), "new-session", "-d", "-s", session, "/bin/sleep 3"], check=True)
    try:
        pane_pid = int(subprocess.check_output(["tmux", "-S", str(socket_path), "list-panes", "-t", f"={session}", "-F", "#{pane_pid}"], text=True).strip())
        marker = {
            "session": session, "workspace": str(workspace), "run_id": "run-tmux",
            "bootstrap_manifest_path": str(manifest), "runtime_id": "runtime-authority-1", "generation": 7,
            "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
            "progress_artifact": str(progress), "progress_content_digest": hashlib.sha256(progress.read_bytes()).hexdigest(), "progress_identity": "progress-tmux",
            "supervisor_pid": os.getpid(), "supervisor_process_start_identity": read_process_start_identity(os.getpid()),
            "boot_identity": current_boot_identity(), "container_identity": os.environ.get("ARNOLD_CONTAINER_IDENTITY") or __import__("socket").gethostname(),
            "victim_pid": pane_pid, "victim_process_start_identity": read_process_start_identity(pane_pid),
        }
        monkeypatch.setenv("TMUX", f"{socket_path},0,0")
        liveness_lease._refresh_authority_marker(marker)
        assert marker["tmux_socket"] == str(socket_path)
        assert marker["tmux_owned_pane_pid"] == pane_pid
        marker_path = marker_dir / f"{session}.json"
        marker_path.write_text(json.dumps(marker, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        context = resolve_signal_authority(site_id="tmux", session=session, marker_path=marker_path, target_kind="non_worker", victim_pid=pane_pid, marker_dir=marker_dir, victim_process_start_identity=marker["victim_process_start_identity"])
        assert context.to_dict()["tmux_owned_pane_pid"] == pane_pid

        subprocess.run(["tmux", "-S", str(socket_path), "kill-server"], check=False)
        subprocess.run(["tmux", "-S", str(socket_path), "new-session", "-d", "-s", session, "/bin/sleep 3"], check=True)
        with pytest.raises(SignalAuthorityError, match="tmux|victim process"):
            resolve_signal_authority(site_id="tmux", session=session, marker_path=marker_path, target_kind="non_worker", victim_pid=pane_pid, marker_dir=marker_dir, victim_process_start_identity=marker["victim_process_start_identity"])
    finally:
        subprocess.run(["tmux", "-S", str(socket_path), "kill-server"], check=False)


def test_locked_final_revalidation_blocks_marker_replacement_before_signal(authority_fixture):
    workspace, marker_dir, manifest, progress, victim, session, marker_path = authority_fixture
    context = resolve_signal_authority(site_id="watchdog", session=session, marker_path=marker_path, target_kind="non_worker", victim_pid=victim.pid, marker_dir=marker_dir)
    import arnold_pipelines.megaplan.incident.disposition as disposition_module
    signal_name = "SIGTERM"
    disposition_id = disposition_module._digest({"schema_version": 1, "site_id": context.site_id, "lifecycle_identity": context.lifecycle_identity, "victim_pid": victim.pid, "victim_process_start_identity": context.victim_process_start_identity, "signal": signal_name, "ladder_stage": "term"})
    disposition = NonWorkerSignalDisposition(
        disposition_id=disposition_id, subject="non_worker_lifecycle", lifecycle_identity=context.lifecycle_identity,
        killer_identity="pytest", cause_kind="lifecycle_shutdown", signal=signal_name,
        victim_pid_or_group=str(victim.pid), victim_process_start_identity=context.victim_process_start_identity,
        observed_at="2026-08-31T00:00:00+00:00", evidence={}, confirmation_event_id=None,
    )
    payload = {**context.to_dict(), "marker_dir": str(marker_dir), "signal": signal_name}
    delivered = []

    def preflight(_records):
        raw = json.loads(marker_path.read_text(encoding="utf-8"))
        raw["run_id"] = "replacement"
        marker_path.write_text(json.dumps(raw, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        revalidate_signal_payload(payload, marker_dir=marker_dir, ledger_root=workspace)

    with pytest.raises(SignalAuthorityError):
        IncidentLedger(workspace).record_claim_signal_locked(
            disposition, signal=signal_name, signal_fn=lambda: delivered.append(True), preflight=preflight,
        )
    assert delivered == []
    assert not any((event.get("payload") or {}).get("event_type") == "non_worker_signal_disposition" for event in IncidentLedger(workspace).read_nbf_events())
