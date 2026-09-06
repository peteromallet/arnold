"""Regression tests for cloud watchdog wrapper invariants."""

from __future__ import annotations

import datetime as dt
import errno
import hashlib
import importlib.util
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from arnold_pipelines.megaplan.cloud import repair_lock, repair_requests
from arnold_pipelines.megaplan.cloud.fixer_prompt_policy import (
    PROCESS_CUSTODY_FAIL_CLOSED_POLICY,
)
from arnold_pipelines.megaplan.cloud.liveness_lease import LivenessLeasePublisher
from arnold_pipelines.megaplan.cloud.redact import REDACTION
from tests.cloud.repair_identity_fixtures import (
    identity_for_signature,
    repair_identity,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
WRAPPER_DIR = REPO_ROOT / "arnold_pipelines" / "megaplan" / "cloud" / "wrappers"
SYSTEMD_DIR = REPO_ROOT / "arnold_pipelines" / "megaplan" / "cloud" / "systemd"
WATCHDOG_TEST_MANIFEST_DIR = (
    REPO_ROOT / "tests" / "cloud" / "fixtures" / "watchdog-runtime-manifests"
)


def _enqueue_claimable_request(
    marker_dir: Path,
    *,
    session: str,
    signature: dict[str, object] | None = None,
    identity: dict[str, object] | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    signature = signature or {
        "failure_kind": "blocked_recovery_not_resolved",
        "current_state": "blocked",
        "phase_or_step": "execute",
        "milestone_or_plan": "m3",
        "gate_recommendation": "",
        "blocked_task_id": "T1",
    }
    identity = identity or identity_for_signature(
        session=session,
        signature=signature,
    )
    queued = repair_requests.enqueue_repair_request(
        queue_root=repair_requests.repair_queue_dir(marker_dir),
        session=session,
        source="watchdog_fixture",
        problem_signature=signature,
        repair_identity=identity,
    )
    assert queued["status"] == "queued"
    return queued, identity


def _write_live_session_marker(
    marker_dir: Path,
    session: str,
    workspace: Path,
    remote_spec: str,
    **extra: object,
) -> Path:
    # This helper represents a managed, live launch.  Keep its fixture
    # identity aligned with the production lease contract; tests that need an
    # unbound/legacy marker write that marker directly.
    extra.setdefault("run_id", f"run-{session}")
    marker_path = marker_dir / f"{session}.json"
    marker_path.write_text(
        json.dumps(
            {
                "session": session,
                "workspace": str(workspace),
                "remote_spec": remote_spec,
                **extra,
            }
        ),
        encoding="utf-8",
    )
    LivenessLeasePublisher(
        session,
        marker_dir=marker_dir,
        target_pid=os.getpid(),
        ttl_s=120,
    ).publish_once()
    return marker_path


@pytest.fixture(autouse=True)
def _isolate_resident_delegation_envelope(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin wrapper dependencies and isolate delegation provenance."""

    monkeypatch.delenv("ARNOLD_RESIDENT_DELEGATION_CONTEXT", raising=False)
    monkeypatch.setenv("MEGAPLAN_SUPERVISOR_PYTHON", sys.executable)
    monkeypatch.setenv(
        "PATH",
        f"{Path(sys.executable).parent}:{os.environ.get('PATH', '')}",
    )


def _wrapper(name: str) -> str:
    return (WRAPPER_DIR / name).read_text(encoding="utf-8")


def _systemd_file(name: str) -> str:
    return (SYSTEMD_DIR / name).read_text(encoding="utf-8")


def _discover_wrapper() -> str:
    return _wrapper("arnold-cloud-discover")


def test_auditor_classifies_meta_trigger_rejection_as_current_failure(
    tmp_path: Path,
) -> None:
    text = _wrapper("arnold-progress-auditor")
    start = text.index("def _meta_run_failure_code(path):")
    end = text.index("\ndef _text_has_meta_launch_failure(", start)
    namespace: dict[str, object] = {}
    exec("import re\n" + text[start:end], namespace)
    failure_code = namespace["_meta_run_failure_code"]
    assert callable(failure_code)
    log = tmp_path / "meta.log"
    log.write_text(
        "[meta-repair 2026-07-16T00:44:11+00:00] "
        "no meta-repair trigger matched; exiting\n",
        encoding="utf-8",
    )

    assert failure_code(log) == "meta_repair_trigger_rejected"
    assert '"trigger_rejected": bool(current_episode and trigger_rejected)' in text
    assert 'or meta.get("trigger_rejection_count")' in text


def test_progress_auditor_review_uses_bounded_pointer_and_typed_response() -> None:
    text = _wrapper("arnold-progress-auditor")

    assert "bounded_audit_review_pointer" in text
    assert 'cat "$review_evidence"' in text
    assert 'cat "$gather_file"' not in text
    assert "AUDIT_REVIEW_EVIDENCE_MAX_BYTES=65536" in text
    assert "AUDIT_REVIEW_BRIEF_MAX_BYTES=131072" in text
    assert '--output-last-message "$model_resp_path"' in text
    assert "normalize_audit_review_response" in text
    assert 'data["hypothesis"] = text[:2000]' in text


def test_progress_auditor_completion_evidence_records_approval_corrective_path() -> None:
    text = _wrapper("arnold-progress-auditor")

    assert 'escalation.get("decision") == "approval_required"' in text
    assert 'corrective_path.get("action") == "await_human_pr_merge"' in text
    assert 'corrective_path.get("repair_dispatch_permitted") is False' in text
    assert '"recommendation": "auditor_escalate_to_human"' in text
    assert 'aggregate_next_event = "human_approval.pr_merge"' in text


def test_relaunch_scripts_preserve_managed_repair_route_context() -> None:
    watchdog = _wrapper("arnold-watchdog")
    assert "export ARNOLD_REPAIR_QUEUE_ROOT=" in watchdog
    assert "export ARNOLD_REPAIR_MARKER_DIR=" in watchdog
    assert "export ARNOLD_REPAIR_SESSION=" in watchdog
    assert "export ARNOLD_REPAIR_RUN_KIND=" in watchdog
    assert 'REPAIR_DISPATCH_RUNTIME_SRC="$SRC_DIR"' in watchdog


def test_superfixer_wrappers_prefer_manifest_runtime_root() -> None:
    """P4: runtime sources resolve from the manifest epic.runtime_root with a
    fixed /workspace/arnold fallback — no env-selector fallback chains remain.
    """
    watchdog = _wrapper("arnold-watchdog")
    auditor = _wrapper("arnold-progress-auditor")

    assert 'SRC_DIR="${MANIFEST_RUNTIME_ROOT:-/workspace/arnold}"' in watchdog
    assert 'if declare -F arnold_runtime_manifest_epic_field >/dev/null 2>&1; then' in auditor
    assert 'AUDITOR_SOURCE_ROOT="$(arnold_runtime_manifest_epic_field epic.runtime_root 2>/dev/null)"' in auditor
    assert 'if [[ "$AUDITOR_MANIFEST_FIELD_RC" -ne 0 ]]; then' in auditor
    assert 'arnold-progress-auditor: runtime manifest present but invalid; failing closed' in auditor
    assert 'AUDITOR_SOURCE_ROOT="${AUDITOR_SOURCE_ROOT:-/workspace/arnold}"' in auditor
    # G4 correction 3: legacy selector reads were deleted with P4 — prove
    # none of the deleted fallback names appear in any fixer wrapper.
    for text in (watchdog, auditor):
        assert "MEGAPLAN_RUNTIME_SRC" not in text
        assert "CLOUD_WATCHDOG_ARNOLD_SRC" not in text
        assert "MEGAPLAN_META_ARNOLD_SRC" not in text
        assert "MEGAPLAN_AUDIT_ARNOLD_SRC" not in text


def test_supervisor_runtime_lib_exposes_manifest_epic_field_helper() -> None:
    text = _wrapper("arnold-supervisor-runtime-lib")
    assert "arnold_runtime_manifest_path()" in text
    assert "arnold_runtime_manifest_epic_field()" in text
    assert "${ARNOLD_RUNTIME_MANIFEST:-/workspace/.megaplan/runtime-manifest.json}" in text


def test_runtime_create_holds_single_writer_creation_lock() -> None:
    """Concurrent runtime creations must not race the active pointer."""
    text = _wrapper("arnold-runtime-create")
    assert ".runtime-create.lock" in text
    assert "flock -n 9" in text
    assert "refusing concurrent create" in text


@pytest.mark.parametrize(
    ("wrapper_name", "prefix"),
    [
        ("arnold-watchdog", "ARNOLD_WATCHDOG"),
        ("arnold-progress-auditor", "ARNOLD_PROGRESS_AUDITOR"),
    ],
)
def test_long_running_superfixer_wrappers_pin_syntax_checked_source_snapshot(
    wrapper_name: str, prefix: str
) -> None:
    text = _wrapper(wrapper_name)

    assert f'{prefix}_ORIGIN="$' in text
    assert f'${{{prefix}_SNAPSHOT_ACTIVE:-0}}' in text
    assert "mktemp" in text
    assert "bash -n" in text
    assert f"export {prefix}_SNAPSHOT_ACTIVE=1" in text
    if wrapper_name == "arnold-progress-auditor":
        assert f'{prefix}_SNAPSHOT_PATH="$progress_auditor_current"' in text
    else:
        assert f'{prefix}_SNAPSHOT_PATH="${{BASH_SOURCE[0]:-$0}}"' in text
    if wrapper_name == "arnold-watchdog":
        # Watchdog execs the checked snapshot immediately, then derives the
        # cleanup path from BASH_SOURCE inside that immutable child.
        assert 'exec bash "$watchdog_snapshot" "$@"' in text
        assert f'export {prefix}_SNAPSHOT_PATH="$' not in text
    else:
        # The other wrappers carry the snapshot path through their re-exec
        # envelope and verify that the child really runs from that path.
        assert f'"${{{prefix}_SNAPSHOT_PATH:-}}"' in text
        assert f'export {prefix}_SNAPSHOT_PATH="$' in text
    if wrapper_name == "arnold-progress-auditor":
        assert f'register_progress_auditor_cleanup "${prefix}_SNAPSHOT_PATH"' in text
        assert "trap 'cleanup_progress_auditor' EXIT" in text
    else:
        assert f'rm -f -- "${prefix}_SNAPSHOT_PATH"' in text
    assert 'trap \'rm -f -- "${BASH_SOURCE[0]:-$0}"\' EXIT' not in text


def _extract_wrapper_function(name: str) -> str:
    text = _wrapper("arnold-watchdog")
    start = text.index(f"{name}() {{")
    # ``launch_chain_tick`` contains nested shell functions and embedded
    # Python programs.  The first ``\n}\n`` is therefore an inner function
    # boundary, not the end of the extracted wrapper.  Keep isolated shell
    # contract tests bound to the real top-level function boundary.
    if name == "launch_chain_tick":
        end = text.index("\nscan_once_unlocked() {", start)
        return text[start:end]
    end = text.index("\n}\n", start) + 3
    return text[start:end]


def _extract_watchdog_embedded_program(function_name: str, marker: str) -> str:
    text = _wrapper("arnold-watchdog")
    start = text.index(f"{function_name}() {{")
    py_start = text.index(marker, start)
    py_start = text.index("\n", py_start) + 1
    py_end = text.index("\nPY\n", py_start)
    return text[py_start:py_end]


def test_watchdog_report_enospc_preserves_last_complete_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report_path = tmp_path / "watchdog-report.json"
    prior = {"timestamp_utc": "2026-08-03T00:00:00+00:00", "items": [{"status": "alive"}]}
    report_path.write_text(json.dumps(prior) + "\n", encoding="utf-8")
    items_path = tmp_path / "items.jsonl"
    items_path.write_text(json.dumps({"session": "demo", "status": "alive"}) + "\n", encoding="utf-8")
    program = _extract_watchdog_embedded_program(
        "emit_report",
        '<<\'PY\' > "$report_tmp"',
    )
    real_mkstemp = tempfile.mkstemp

    def fail_same_directory(*args, **kwargs):
        if Path(kwargs.get("dir") or "").resolve() == tmp_path.resolve():
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_mkstemp(*args, **kwargs)

    monkeypatch.setattr(tempfile, "mkstemp", fail_same_directory)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "emit-report",
            str(items_path),
            "1",
            str(report_path),
            "",
            "1",
            "0",
        ],
    )

    with pytest.raises(OSError, match="No space left on device"):
        exec(program, {})

    assert json.loads(report_path.read_text(encoding="utf-8")) == prior
    assert not list(tmp_path.glob(".watchdog-report.json.*.tmp"))


def test_watchdog_report_atomic_swap_never_exposes_partial_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report_path = tmp_path / "watchdog-report.json"
    prior = {"timestamp_utc": "2026-08-03T00:00:00+00:00", "items": [{"status": "alive"}]}
    report_path.write_text(json.dumps(prior) + "\n", encoding="utf-8")
    items_path = tmp_path / "items.jsonl"
    items_path.write_text(json.dumps({"session": "demo", "status": "complete"}) + "\n", encoding="utf-8")
    program = _extract_watchdog_embedded_program(
        "emit_report",
        '<<\'PY\' > "$report_tmp"',
    )
    replace_reached = threading.Event()
    allow_replace = threading.Event()
    real_replace = os.replace

    def blocked_replace(source, target):
        if Path(target) == report_path:
            replace_reached.set()
            assert allow_replace.wait(timeout=5)
        return real_replace(source, target)

    monkeypatch.setattr(os, "replace", blocked_replace)
    monkeypatch.setattr(
        sys,
        "argv",
        ["emit-report", str(items_path), "1", str(report_path), "", "1", "0"],
    )
    error: list[BaseException] = []

    def publish() -> None:
        try:
            exec(program, {})
        except BaseException as exc:  # pragma: no cover - asserted below
            error.append(exc)

    thread = threading.Thread(target=publish)
    thread.start()
    assert replace_reached.wait(timeout=5)
    for _ in range(100):
        assert json.loads(report_path.read_text(encoding="utf-8")) == prior
    allow_replace.set()
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert not error
    published = json.loads(report_path.read_text(encoding="utf-8"))
    assert published["items"] == [{"session": "demo", "status": "complete"}]
    assert not list(tmp_path.glob(".watchdog-report.json.*.tmp"))


def _extract_auditor_function(name: str) -> str:
    text = _wrapper("arnold-progress-auditor")
    start = text.index(f"{name}() {{")
    end = text.index("\n}\n", start) + 3
    return text[start:end]


def _extract_wrapper_function_until(name: str, next_name: str) -> str:
    text = _wrapper("arnold-watchdog")
    start = text.index(f"{name}() {{")
    end = text.index(f"\n{next_name}() {{", start)
    return text[start:end]


def _extract_relaunch_functions(wrapper_kind: str) -> list[str]:
    """Extract the resolver with its complete wrapper-specific dependency closure."""
    extract = _extract_wrapper_function
    names = [
        "chain_engine_root_preflight",
        "default_plan_relaunch_command",
        "resume_plan_relaunch_command",
        "chain_resume_plan_relaunch_command_if_needed",
        "stale_marker_relaunch_command",
        "default_chain_relaunch_command",
    ]
    if wrapper_kind == "repair":
        names.append("_repair_loop_acceptance_gate")
    names.append("resolve_relaunch_command")
    return [extract(name) for name in names]


def _extract_reap_program() -> str:
    text = _wrapper("arnold-watchdog")
    start = text.index("reap_stale_repair_candidates() {")
    marker = "python3 - \"$REAP_AGE_SECS\" \"$REAP_ORPHAN_AGE_SECS\" <<'PY'"
    py_start = text.index(marker, start)
    py_start = text.index("\n", py_start) + 1
    py_end = text.index("\nPY\n", py_start)
    return text[py_start:py_end]


def _load_reap_module(tmp_path: Path):
    mod_path = tmp_path / "_reap_prog.py"
    mod_path.write_text(_extract_reap_program(), encoding="utf-8")
    spec = importlib.util.spec_from_file_location("_reap_prog", mod_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _extract_repair_stall_program() -> str:
    text = _wrapper("arnold-watchdog")
    start = text.index("reap_stalled_repair_candidates() {")
    marker = None
    for candidate in (
        "python3 - \"$MARKER_DIR\" \"$REPAIR_OPERATOR_ROOT\" "
        "\"$REAP_STALL_GRACE_SECS\" \"$REAP_STALL_IDLE_SECS\" "
        "\"$REAP_AGE_SECS\" <<'PY'",
        "python3 - \"$MARKER_DIR\" \"$KIMI_OPERATOR_ROOT\" "
        "\"$REAP_STALL_GRACE_SECS\" \"$REAP_STALL_IDLE_SECS\" "
        "\"$REAP_AGE_SECS\" <<'PY'",
    ):
        if candidate in text[start:]:
            marker = candidate
            break
    assert marker is not None
    py_start = text.index(marker, start)
    py_start = text.index("\n", py_start) + 1
    py_end = text.index("\nPY\n", py_start)
    return text[py_start:py_end]


def _run_repair_stall(
    tmp_path: Path,
    ps_rows: str,
    marker_dir: Path,
    operator_root: Path,
    grace_secs: int = 900,
    idle_secs: int = 600,
    reap_age_secs: int = 7200,
) -> list[str]:
    program = _extract_repair_stall_program()
    prog_path = tmp_path / "_repair_stall_prog.py"
    prog_path.write_text(program, encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(prog_path),
            str(marker_dir),
            str(operator_root),
            str(grace_secs),
            str(idle_secs),
            str(reap_age_secs),
        ],
        input=ps_rows,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return [line for line in result.stdout.strip().splitlines() if line]


def _run_embedded_python(program: str, *args: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as tmpdir:
        prog_path = Path(tmpdir) / "_embedded.py"
        prog_path.write_text(program, encoding="utf-8")
        env = dict(os.environ)
        # Embedded wrapper fixtures must not inherit the resident process's
        # immutable Discord delegation envelope unless a test supplies one.
        env.pop("ARNOLD_RESIDENT_DELEGATION_CONTEXT", None)
        env["PYTHONPATH"] = f"{REPO_ROOT}:{env.get('PYTHONPATH', '')}"
        return subprocess.run(
            [sys.executable, str(prog_path), *args],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )


def _run_write_needs_human_marker(
    data_path: Path,
    out_path: Path,
    *,
    discord_status: str = "delivered",
) -> subprocess.CompletedProcess[str]:
    """Persist a needs-human marker via the surviving Python writer
    (``human_blockers.write_needs_human_marker_payload``), which the watchdog
    imports.  The shell-level writer was removed with the layered repair
    stack."""
    from arnold_pipelines.megaplan.cloud.human_blockers import (
        write_needs_human_marker_payload,
    )

    repair_payload = json.loads(data_path.read_text(encoding="utf-8"))
    marker = write_needs_human_marker_payload(
        out_path,
        repair_payload,
        repair_data_path=data_path,
        discord_status=discord_status,
    )
    return subprocess.CompletedProcess(
        args=["write_needs_human_marker_payload", str(data_path), str(out_path)],
        returncode=0,
        stdout=json.dumps(marker, sort_keys=True),
        stderr="",
    )


def _run_watchdog_shell(
    script: str,
    *,
    path_prefix: Path | None = None,
    allow_notification_delivery: bool = False,
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    # Watchdog tests execute extracted production shell functions.  Never let
    # ambient credentials grant those functions outbound notification
    # authority; delivery tests must inject an explicit local stub instead.
    for name in (
        "DISCORD_BOT_TOKEN",
        "DISCORD_DM_USER_ID",
        "DISCORD_WEBHOOK_URL",
        "REPORT_WEBHOOK",
        "SLACK_WEBHOOK_URL",
        "PYTEST_CURRENT_TEST",
    ):
        env.pop(name, None)
    env["DISCORD_DM_BIN"] = "/bin/false"
    # Keep notification safety deterministic even when pytest uses an
    # isolated basetemp outside the historical ``pytest-of-*`` path.
    env["MEGAPLAN_TEST_EXECUTION"] = "1"
    if allow_notification_delivery:
        # These fixtures inject local diagnostic/Discord stand-ins and assert
        # the durable notification path.  Keep the default harness fail-safe;
        # delivery must be opted into explicitly by such a fixture.
        env.pop("MEGAPLAN_TEST_EXECUTION", None)
        env.pop("ARNOLD_TEST_EXECUTION", None)
    env["MEGAPLAN_SUPERVISOR_PYTHON"] = sys.executable
    env["MEGAPLAN_BABYSITTER_PYTHON"] = sys.executable
    # Extracted relaunch functions use the identity-scoped runtime manifest
    # contract. Keep committed fixture payloads historical and copy them into
    # a per-run manifest directory rooted at this checked-out candidate. This
    # avoids baking a machine-specific checkout path into the repository.
    manifest_dir = tempfile.TemporaryDirectory(prefix="watchdog-runtime-manifests-")
    manifest_root = Path(manifest_dir.name)
    for fixture_path in WATCHDOG_TEST_MANIFEST_DIR.glob("*.json"):
        payload = json.loads(fixture_path.read_text(encoding="utf-8"))
        payload.setdefault("epic", {})["runtime_root"] = str(REPO_ROOT)
        (manifest_root / fixture_path.name).write_text(
            json.dumps(payload), encoding="utf-8"
        )
    env["ARNOLD_RUNTIME_MANIFEST_DIR"] = str(manifest_root)
    # The runtime library invokes the pinned interpreter with ``-P``.  Keep
    # the extracted-wrapper harness bound to this checkout explicitly rather
    # than relying on pytest's ambient import path.
    env["PYTHONPATH"] = f"{REPO_ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}"
    env["PATH"] = f"{Path(sys.executable).parent}:{env.get('PATH', '')}"
    if path_prefix is not None:
        env["PATH"] = f"{path_prefix}:{env.get('PATH', '')}"
    # Extracted-function fixtures do not include the full wrapper dependency
    # closure.  Supply inert defaults for observer-only helpers; individual
    # tests may define stronger spies/stubs later in their script and thereby
    # override these definitions.  These defaults never exist in production.
    harness_stubs = r'''
authority_gap_continue() { :; }
repair_goal_watchdog_status() { return 0; }
# No extracted fixture owns a current needs-human sidecar unless it defines
# one explicitly; return non-zero so the production fall-through remains
# reachable in ordinary wrapper tests.
emit_current_needs_human_sidecar() { return 1; }
environment_gone_check() { return 1; }
arnold_supervisor_tmux_session_exists() { return 1; }
arnold_supervisor_tmux_session_socket() { printf '%s\n' "${ARNOLD_TEST_TMUX_SOCKET:-/tmp/arnold-test.sock}"; }
emit_custody_structured_facts() { :; }
repair_needs_human_path() { return 1; }
emit_watchdog_incident_bridge_event() { :; }
relaunch_materializer_authority_gate() {
  printf '%s\n' '{"family":"direct_module.auto","is_non_authoritative_family":true,"is_repair_authority":false,"can_become_accepted_repair_on_success":false,"accepted_repair_requires_canonical_delegation":true,"canonical_delegation_path":"simple_fixer.singleton_claim.exact_f01_tuple","forbidden_sources_present":[]}'
}
'''
    try:
        return subprocess.run(
            ["bash", "-c", harness_stubs + "\n" + script],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
    finally:
        manifest_dir.cleanup()


def _assert_manifest_bound_chain_relaunch(command: str, runtime_root: Path) -> None:
    """Assert chain relaunches delegate runtime binding to the launch boundary.

    Chain commands intentionally do not synthesize a direct ``PYTHONPATH``
    assignment. The boundary receives the preflight-accepted candidate root
    and owns the runtime environment materialization.
    """
    assert "arnold_materialize_launch_boundary" in command
    boundary_lines = [
        line
        for line in command.splitlines()
        if "arnold_materialize_launch_boundary " in line
    ]
    assert boundary_lines, command
    assert str(runtime_root) in boundary_lines[0], command
    assert "PYTHONPATH=" not in command


def test_watchdog_maps_suppressed_babysitter_to_typed_report_without_schedule(
    tmp_path: Path,
) -> None:
    """The outer watchdog preserves the inner no-launch authority result.

    Exercise the real outer launcher in a subprocess with a child stub that
    writes the canonical inner suppression receipt.  The outer receipt must
    retain the typed authority evidence and must not acquire launch/schedule
    ownership fields.
    """
    paths = _prepare_watchdog_superfixer_fixture(tmp_path)
    child = tmp_path / "suppressed-babysitter.sh"
    child.write_text(
        "#!/usr/bin/env bash\n"
        "run_root=\n"
        "session=\n"
        "while [[ $# -gt 0 ]]; do\n"
        "  case \"$1\" in\n"
        "    --run-root) run_root=\"$2\"; shift 2 ;;\n"
        "    --session) session=\"$2\"; shift 2 ;;\n"
        "    *) shift ;;\n"
        "  esac\n"
        "done\n"
        "mkdir -p \"$run_root\"\n"
        "printf '%s\\n' '{\"schema\":\"arnold.babysitter.launch_receipt.v1\",\"status\":\"suppressed\",\"dispatch_outcome\":{\"kind\":\"no_launch\",\"status\":\"suppressed\",\"reason\":\"canonical_pause\",\"authority_identity\":{\"chain_id\":\"chain\",\"plan_name\":\"plan\",\"marker_identity\":\"marker-identity\"}}}' > \"$run_root/$session.babysitter-launch-receipt.json\"\n"
        "exit 0\n",
        encoding="utf-8",
    )
    child.chmod(child.stat().st_mode | stat.S_IXUSR)
    script = "\n\n".join(
        [
            _extract_wrapper_function("babysitter_policy_dispatch"),
            _extract_wrapper_function("launch_status_trigger_babysitter"),
            "babysitter_effective_mode() { printf 'superfixer\\t'; }",
            "babysitter_occurrence_digest() { printf 'digest'; }",
            "babysitter_running_for_occurrence() { return 1; }",
            "babysitter_after_elapsed() { return 0; }",
            "babysitter_parked_chain_stall() { return 1; }",
            "log() { :; }",
            "report_item() { printf '%s\\n' \"$4\"; }",
            f"MARKER_DIR={str(paths['marker_dir'])!r}",
            f"REPAIR_DATA_DIR={str(paths['repair_data_dir'])!r}",
            f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            "export CLOUD_WATCHDOG_BABYSITTER_BIN=" + shlex.quote(str(child)),
            "export ARNOLD_BABYSITTER_LAUNCH_GRACE_SECS=2",
            (
                "babysitter_policy_dispatch "
                f"{shlex.quote(paths['session'])} {shlex.quote(str(paths['workspace']))} "
                f"{shlex.quote(str(paths['spec_path']))} plan {shlex.quote(paths['plan_name'])} "
                f"{shlex.quote(str(tmp_path / 'report.tsv'))} reason"
            ),
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "babysitter_suppressed"
    receipt_path = paths["repair_data_dir"] / f"{paths['session']}.babysitter-receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["schema"] == "arnold.superfixer.watchdog_dispatch_receipt.v1"
    assert receipt["status"] == "suppressed"
    assert receipt["suppression_reason"] == "automatic babysitter admission authority"
    assert receipt["dispatch_outcome"] == {
        "kind": "no_launch",
        "status": "suppressed",
        "reason": "canonical_pause",
        "authority_identity": {
            "chain_id": "chain",
            "plan_name": "plan",
            "marker_identity": "marker-identity",
        },
    }
    assert "babysitter_pid" not in receipt
    assert "managed_run_id" not in receipt
    assert "scheduled_receipt" not in receipt
    assert not list(paths["repair_data_dir"].glob("*scheduled*receipt*"))


@pytest.mark.parametrize(
    ("marker_fields", "expected_rc", "expect_child"),
    [
        (
            {
                "babysitter_chain_profile": "all-muse-spark-openrouter",
                "babysitter_closed_profile": "all-muse-spark-openrouter",
            },
            0,
            True,
        ),
        ({"babysitter_chain_profile": "all-muse-spark-openrouter"}, 1, False),
        ({"babysitter_closed_profile": "all-muse-spark-openrouter"}, 1, False),
        (
            {
                "babysitter_chain_profile": "partnered-5",
                "babysitter_closed_profile": "all-muse-spark-openrouter",
            },
            1,
            False,
        ),
    ],
)
def test_watchdog_marker_binds_closed_fixer_before_child_spawn(
    tmp_path: Path,
    marker_fields: dict[str, str],
    expected_rc: int,
    expect_child: bool,
) -> None:
    """The scan/restart launch reads the exact marker before spawning."""
    paths = _prepare_watchdog_superfixer_fixture(tmp_path)
    marker_path = paths["marker_dir"] / f"{paths['session']}.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker.update(marker_fields)
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    child = tmp_path / "babysitter-stub.sh"
    record = tmp_path / "child-env.txt"
    child.write_text(
        "#!/usr/bin/env bash\n"
        "printf '%s|%s|%s|%s\\n' "
        "\"$ARNOLD_BABYSITTER_CHAIN_PROFILE\" "
        "\"$ARNOLD_BABYSITTER_CLOSED_PROFILE\" "
        "\"$ARNOLD_BABYSITTER_MODEL\" "
        "\"$ARNOLD_BABYSITTER_ROUTING\" "
        f"> {shlex.quote(str(record))}\n",
        encoding="utf-8",
    )
    child.chmod(0o755)
    script = "\n\n".join(
        [
            _extract_wrapper_function("launch_status_trigger_babysitter"),
            f"MARKER_DIR={str(paths['marker_dir'])!r}",
            f"REPAIR_DATA_DIR={str(paths['repair_data_dir'])!r}",
            f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            "export CLOUD_WATCHDOG_BABYSITTER_BIN=" + shlex.quote(str(child)),
            "launch_status_trigger_babysitter "
            f"{shlex.quote(paths['session'])} {shlex.quote(str(paths['workspace']))} "
            f"{shlex.quote(str(paths['spec_path']))} plan {shlex.quote(paths['plan_name'])} "
            f"{shlex.quote(str(tmp_path / 'report.tsv'))} reason digest",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == expected_rc, result.stderr
    if expect_child:
        assert record.read_text(encoding="utf-8").strip() == (
            "all-muse-spark-openrouter|all-muse-spark-openrouter|"
            "omp:openrouter/meta/muse-spark-1.3-contributor:high|omp"
        )
    else:
        assert not record.exists()


def test_run_watchdog_shell_strips_ambient_notification_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "DISCORD_BOT_TOKEN",
        "DISCORD_DM_USER_ID",
        "DISCORD_WEBHOOK_URL",
        "REPORT_WEBHOOK",
        "SLACK_WEBHOOK_URL",
    ):
        monkeypatch.setenv(name, "live-secret")
    monkeypatch.setenv("DISCORD_DM_BIN", "/bin/true")

    result = _run_watchdog_shell(
        """
for name in DISCORD_BOT_TOKEN DISCORD_DM_USER_ID DISCORD_WEBHOOK_URL REPORT_WEBHOOK SLACK_WEBHOOK_URL; do
  [[ -z "${!name:-}" ]] || exit 20
done
[[ "$DISCORD_DM_BIN" == /bin/false ]] || exit 21
"""
    )

    assert result.returncode == 0, result.stderr


def _read_incident_event_payloads(root: Path) -> list[dict[str, object]]:
    events_path = root / ".megaplan" / "incident-ledger" / "events.jsonl"
    if not events_path.exists():
        return []
    payloads: list[dict[str, object]] = []
    for line in events_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        payloads.append(json.loads(stripped)["payload"])
    return payloads


def _run_discover(
    tmp_path: Path,
    *,
    marker_dir: Path,
    src_dir: Path | None = None,
    manifest_root: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PATH"] = f"{tmp_path}:{env.get('PATH', '')}"
    env.setdefault("MEGAPLAN_DISCOVER_WORKSPACE_ROOT", str(tmp_path / "workspace-root"))
    # G5 round-5 finding 1: the wrapper resolves the executed root from
    # ARNOLD_RUNTIME_MANIFEST unconditionally (--src-dir is observation-only),
    # so the harness always pins a manifest whose epic.runtime_root matches
    # the runtime.  PYTHONPATH exposes the package to the wrapper's python3
    # subprocesses (manifest resolution + plan binding lookup).
    runtime_root = manifest_root or REPO_ROOT
    manifest = _make_authoritative_manifest()
    manifest["epic"]["runtime_root"] = str(runtime_root)
    manifest_path = tmp_path / "runtime-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    env["ARNOLD_RUNTIME_MANIFEST"] = str(manifest_path)
    env["PYTHONPATH"] = f"{REPO_ROOT}:{env.get('PYTHONPATH', '')}"
    return subprocess.run(
        [
            "bash",
            str(WRAPPER_DIR / "arnold-cloud-discover"),
            "tmux-unmarked",
            "--marker-dir",
            str(marker_dir),
            "--src-dir",
            str(src_dir or REPO_ROOT),
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def test_watchdog_defaults_runtime_and_sync_branch_to_manifest() -> None:
    text = _wrapper("arnold-watchdog")

    assert 'SRC_DIR="${MANIFEST_RUNTIME_ROOT:-/workspace/arnold}"' in text
    assert 'SYNC_BRANCH="${MANIFEST_EPIC_BRANCH:-}"' in text
    # The layered repair-trigger bin resolution was removed with the layered
    # stack; the babysitter dispatch runtime source binds to the manifest
    # runtime_root with the SRC_DIR fallback.
    assert 'REPAIR_DISPATCH_RUNTIME_SRC="$SRC_DIR"' in text
    assert 'REPAIR_DISPATCH_RUNTIME_SRC="$MANIFEST_RUNTIME_ROOT"' in text
    assert "arnold-repair-trigger" not in text
    # G4 correction 3: no env-selector fallbacks remain in the watchdog.
    assert "MEGAPLAN_RUNTIME_SRC" not in text
    assert "CLOUD_WATCHDOG_ARNOLD_SRC" not in text
    assert "CLOUD_WATCHDOG_SYNC_BRANCH" not in text
    assert "workflow-manifest-runtime" not in text


def test_watchdog_allows_scoped_invocations_to_bypass_shared_hot_env() -> None:
    text = _wrapper("arnold-watchdog")

    assert (
        'WATCHDOG_HOT_ENV="${ARNOLD_CLOUD_HOT_ENV:-/workspace/.cloud-hot-env}"'
        in text
    )
    assert 'if [[ -f "$WATCHDOG_HOT_ENV" ]]; then' in text
    assert '. "$WATCHDOG_HOT_ENV"' in text


def test_watchdog_sync_does_not_broadly_commit_source_drift() -> None:
    text = _wrapper("arnold-watchdog")
    start = text.index("sync_editable_source_branch() {")
    end = text.index("\n\ncodex_repair_editable_install() {", start)
    sync_body = text[start:end]

    assert "git add -A -- arnold_pipelines/megaplan/skills" in sync_body
    assert "source checkout has non-sync drift; not auto-committing" in sync_body
    assert "git add -A &&" not in sync_body


def test_host_watchdog_ensure_starts_shell_wrapped_watchdog_and_verifies_liveness() -> None:
    text = _systemd_file("ensure-megaplan-watchdog")

    launch_lines = [
        line for line in text.splitlines()
        if "docker exec -d" in line and "nohup" in line
    ]
    assert launch_lines, text
    launch = "\n".join(launch_lines)
    assert "/tmp/launch-watchdog.sh" not in launch
    assert "/tmp/launch-watchdog-astrid.sh" not in launch
    assert "ARNOLD_REPAIR_SESSION=megaplan-maintenance" not in launch
    assert "ARNOLD_WATCHDOG_OBSERVER=1" in launch
    assert "unset ARNOLD_RUNTIME_MANIFEST ARNOLD_REPAIR_SESSION" in launch
    assert "WATCHDOG_WRAPPER" in launch
    # Health check must not match its own pgrep argv.
    assert "pgrep -f arnold-watchdog" not in text
    assert "bash /tmp/arnold-watchdog[.]" in text
    assert "watchdog_restart_failed_not_alive" in text
    assert "tmux new-session -d -s watchdog" not in text
    assert "tmux has-session -t watchdog" not in text
    assert "runtime_src=/workspace/arnold" not in text
    assert "MEGAPLAN_RUNTIME_SRC" not in text
    assert "CLOUD_WATCHDOG_ARNOLD_SRC" not in text


def test_host_resident_ensure_starts_from_pinned_runtime_source() -> None:
    text = _systemd_file("ensure-megaplan-resident")

    assert 'tmux -S "$socket" new-session -d -s megaplan-resident-discord -c /workspace' in text
    assert (
        'runtime_src="$(arnold_runtime_manifest_epic_field epic.runtime_root'
        in text
    )
    assert 'PYTHONPATH="$runtime_src:${PYTHONPATH:-}"' in text
    assert r'cd \"\$runtime_src\"' in text
    # G4: the resident ensure script pins runtime_src to the manifest
    # epic.runtime_root; no env-selector fallback chain remains.
    assert "runtime_src=/workspace/arnold" not in text
    assert r"\${MEGAPLAN_RUNTIME_SRC:-" not in text
    assert "CLOUD_WATCHDOG_ARNOLD_SRC" not in text
    assert (
        "tmux new-session -d -s megaplan-resident-discord "
        "-c /workspace/arnold"
    ) not in text


def test_watchdog_flags_incomplete_markers_instead_of_dispatching_without_custody() -> None:
    text = _wrapper("arnold-watchdog")

    assert 'report_item "$report_items" "" "flag" "setup_invalid" "missing session: $marker"' in text
    assert 'report_item "$report_items" "$session" "flag" "workspace_missing" "missing workspace: $marker"' in text
    assert 'report_item "$report_items" "$session" "flag" "setup_invalid" "missing remote_spec: $marker" "$workspace"' in text
    # The tick never dispatches from a flag path; the babysitter is the only
    # dispatch and it reports typed statuses.
    assert "babysitter_scheduled" in text
    assert "babysitter_launch_failed" in text
    assert '"skip" "spec_missing"' not in text
    assert '"skip" "workspace_missing"' not in text


def test_watchdog_liveness_is_scoped_to_marked_chain_spec() -> None:
    text = _wrapper("arnold-watchdog")

    assert 'local remote_spec="$3"' in text
    assert "ps -eww -o args=" in text
    assert 'grep -Fq -- "$remote_spec"' in text
    assert 'health="$(session_health_status "$session" "$workspace" "$remote_spec" "$run_kind" "$plan_name")"' in text



def test_watchdog_terminal_plan_does_not_complete_chain_when_health_says_incomplete(
    tmp_path: Path,
) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text(
        "milestones:\n"
        "  - label: m1\n"
        "  - label: m2\n",
        encoding="utf-8",
    )
    _write_chain_state(
        workspace / ".megaplan" / "plans" / ".chains" / "chain-demo.json",
        {
            "current_plan_name": "demo-plan",
            "current_milestone_index": 1,
            "last_state": "authority_divergence",
            "completed": [{"label": "m1", "status": "done"}],
        },
    )
    _write_plan(
        workspace / ".megaplan" / "plans" / "demo-plan",
        {"name": "demo-plan", "current_state": "done"},
    )
    (marker_dir / "demo-session.chain-health.progress.json").write_text(
        json.dumps(
            {
                "chain_complete": False,
                "completed_count": 1,
                "milestone_count": 2,
                "pr_number": 90,
                "pr_state": "open",
            }
        ),
        encoding="utf-8",
    )
    current_target = {
        "plan_state": {"current_state": "done"},
        "stale_evidence": [{"kind": "stale_chain_state_after_terminal_plan"}],
    }
    script = "\n\n".join(
        [
            _extract_wrapper_function("session_terminal_status"),
            f"MARKER_DIR={str(marker_dir)!r}",
            f"session_terminal_status demo-session {str(workspace)!r} {str(spec_path)!r} chain {shlex.quote(json.dumps(current_target))} {str(marker_dir)!r}",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ""

def test_watchdog_checks_plan_phase_health_even_when_session_alive() -> None:
    text = _wrapper("arnold-watchdog")

    assert "plan_phase_health_status()" in text
    assert 'phase_health="$(plan_phase_health_status "$workspace" "$run_kind" "$plan_name")"' in text
    assert 'if failure_kind != "phase_failed":' in text
    assert "success_after_failure" in text
    assert 'f"recorded={recorded_at or' in text
    assert 'session alive but plan unhealthy' in text
    assert 'babysitter_policy_dispatch "$session" "$workspace" "$remote_spec" "$run_kind" "$plan_name" "$report_items"' in text


def test_watchdog_plan_status_exports_stale_active_step_pid(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    plan_dir = workspace / ".megaplan" / "plans" / "demo-plan"
    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    initiative_dir = workspace / ".megaplan" / "initiatives" / "demo"
    plan_dir.mkdir(parents=True)
    chain_dir.mkdir(parents=True)
    initiative_dir.mkdir(parents=True)
    spec_path = initiative_dir / "chain.yaml"
    spec_path.write_text("milestones:\n  - label: m1\n", encoding="utf-8")
    digest = hashlib.sha1(str(spec_path.resolve()).encode("utf-8")).hexdigest()[:12]
    (chain_dir / f"chain-{digest}.json").write_text(
        json.dumps(
            {
                "current_plan_name": "demo-plan",
                "current_milestone_index": 0,
                "last_state": "initialized",
                "completed": [],
            }
        ),
        encoding="utf-8",
    )
    (plan_dir / "state.json").write_text(
        json.dumps(
            {
                "name": "demo-plan",
                "current_state": "initialized",
                "active_step": {
                    "phase": "prep",
                    "worker_pid": 99999999,
                    "attempt": 1,
                },
            }
        ),
        encoding="utf-8",
    )

    script = "\n\n".join(
        [
            _extract_wrapper_function("plan_attention_status_env"),
            f"plan_attention_status_env {str(workspace)!r} {str(spec_path)!r} chain ''",
        ]
    )

    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    lines = result.stdout.strip().splitlines()
    assert "PLAN_STATUS_ACTIVE_STEP_PRESENT=1" in lines
    assert "PLAN_STATUS_ACTIVE_STEP_PHASE=prep" in lines
    assert "PLAN_STATUS_ACTIVE_STEP_WORKER_PID=99999999" in lines
    assert "PLAN_STATUS_ACTIVE_STEP_PID_ALIVE=0" in lines


def test_watchdog_routes_dead_active_step_to_repair_dispatch() -> None:
    text = _wrapper("arnold-watchdog")

    assert 'PLAN_STATUS_ACTIVE_STEP_PRESENT=0' in text
    assert 'PLAN_STATUS_ACTIVE_STEP_PID_ALIVE=' in text
    assert 'stale_active_step: plan=${PLAN_STATUS_PLAN_NAME:-unknown}' in text
    assert (
        'babysitter_policy_dispatch "$session" "$workspace" "$remote_spec" "$run_kind" '
        '"$plan_name" "$report_items"'
    ) in text
    assert '"stale active step: $stale_active_summary"' in text


def _run_parked_stall(workspace: Path, spec_path: Path, plan_name: str = "") -> int:
    program = _extract_watchdog_embedded_program(
        "babysitter_parked_chain_stall",
        "<<'PY'",
    )
    result = _run_embedded_python(
        program, "demo-session", str(workspace), str(spec_path), plan_name
    )
    return result.returncode


def _write_parked_plan(
    tmp_path: Path,
    *,
    current_state: str,
    active_step: dict | None,
) -> tuple[Path, Path]:
    workspace = tmp_path / "ws"
    plan_dir = workspace / ".megaplan" / "plans" / "demo-plan"
    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    initiative_dir = workspace / ".megaplan" / "initiatives" / "demo"
    plan_dir.mkdir(parents=True)
    chain_dir.mkdir(parents=True)
    initiative_dir.mkdir(parents=True)
    spec_path = initiative_dir / "chain.yaml"
    spec_path.write_text("- label: m1\n- label: m2\n", encoding="utf-8")
    digest = hashlib.sha1(str(spec_path.resolve()).encode("utf-8")).hexdigest()[:12]
    (chain_dir / f"chain-{digest}.json").write_text(
        json.dumps(
            {
                "current_plan_name": "demo-plan",
                "current_milestone_index": 0,
                "last_state": current_state,
                "completed": [],
            }
        ),
        encoding="utf-8",
    )
    state: dict[str, object] = {
        "name": "demo-plan",
        "current_state": current_state,
    }
    if active_step is not None:
        state["active_step"] = active_step
    (plan_dir / "state.json").write_text(json.dumps(state), encoding="utf-8")
    return workspace, spec_path


def test_parked_stall_treats_dead_pid_as_parked(tmp_path: Path) -> None:
    """A leftover active_step.phase with a dead pid is parked, not live."""
    workspace, spec = _write_parked_plan(
        tmp_path,
        current_state="critiqued",
        active_step={"phase": "revise", "worker_pid": 99999999, "attempt": 1},
    )
    assert _run_parked_stall(workspace, spec, "demo-plan") == 0


def test_parked_stall_treats_live_pid_as_not_parked(tmp_path: Path) -> None:
    workspace, spec = _write_parked_plan(
        tmp_path,
        current_state="critiqued",
        active_step={"phase": "revise", "worker_pid": os.getpid(), "attempt": 1},
    )
    assert _run_parked_stall(workspace, spec, "demo-plan") == 1


def test_parked_stall_phase_without_pid_is_parked(tmp_path: Path) -> None:
    workspace, spec = _write_parked_plan(
        tmp_path,
        current_state="critiqued",
        active_step={"phase": "revise"},
    )
    assert _run_parked_stall(workspace, spec, "demo-plan") == 0


def test_watchdog_observer_mode_skips_per_epic_manifest_pin() -> None:
    text = _wrapper("arnold-watchdog")
    assert "ARNOLD_WATCHDOG_OBSERVER" in text
    assert "Observer mode is a caller contract" in text
    assert "MUST NOT bind a" in text
    assert "_session_engine_root" in text
    assert 'child_env.pop("ARNOLD_RUNTIME_MANIFEST", None)' in text
    assert 'child_env["SRC_DIR"] = str(engine_root)' in text


def test_watchdog_reaper_is_wired_into_scan_and_report_summary() -> None:
    text = _wrapper("arnold-watchdog")

    assert 'REAP_AGE_SECS="${CLOUD_WATCHDOG_REAP_AGE_SECS:-7200}"' in text
    assert 'REAP_ORPHAN_AGE_SECS="${CLOUD_WATCHDOG_REAP_ORPHAN_AGE_SECS:-3900}"' in text
    assert 'REAP_STALL_GRACE_SECS="${CLOUD_WATCHDOG_REAP_STALL_GRACE_SECS:-1800}"' in text
    assert 'REAP_STALL_IDLE_SECS="${CLOUD_WATCHDOG_REAP_STALL_IDLE_SECS:-1800}"' in text
    assert 'KIMI_OPERATOR_ROOT="${KIMI_GOAL_OPERATOR_ROOT:-/workspace/kimi-goal-operator}"' in text
    assert "reap_stale_repairs()" in text
    assert "reap_stalled_repair_candidates()" in text
    assert 'reap_stale_repairs "$report_items"' in text
    assert '"reaped_repairs": len(reaped)' in text
    assert 'report_item "$report_items" "${session:-}" "reap" "reaped"' in text


def test_watchdog_reap_decision_helper_reaps_only_stale_cloud_repairs(tmp_path: Path) -> None:
    module = _load_reap_module(tmp_path)

    over_age = module.decide_reap(
        {
            "pid": 4100,
            "ppid": 4000,
            "pgid": 4100,
            "etimes": 7201,
            "args": (
                "codex exec --sandbox danger-full-access "
                "'You are the watchdog repair-loop dev-fix agent for a stopped Arnold cloud session. "
                "Context: Session: demo-session Workspace: /tmp/ws'"
            ),
        },
        7200,
        3900,
    )
    assert over_age["reap"] is True
    assert over_age["rule"] == "age_backstop"
    assert over_age["session"] == "demo-session"

    orphaned = module.decide_reap(
        {
            "pid": 5100,
            "ppid": 1,
            "pgid": 5000,
            "etimes": 3901,
            "args": (
                "python3 -m arnold.agent.run_agent "
                "--query='The user's invariant is: workflows on this Hetzner worker should never pause unexpectedly. "
                "Current Incident: Session: orphan-session Workspace: /tmp/ws'"
            ),
        },
        7200,
        3900,
    )
    assert orphaned["reap"] is True
    assert orphaned["rule"] == "orphan_fast_path"
    assert orphaned["session"] == "orphan-session"

    under_age = module.decide_reap(
        {
            "pid": 6100,
            "ppid": 6000,
            "pgid": 6000,
            "etimes": 600,
            "args": (
                "codex exec --sandbox danger-full-access "
                "'You are the watchdog repair-loop dev-fix agent for a stopped Arnold cloud session. "
                "Context: Session: fresh-session Workspace: /tmp/ws'"
            ),
        },
        7200,
        3900,
    )
    assert under_age["reap"] is False
    assert under_age["reason"] == "under_age"

    watchdog = module.decide_reap(
        {
            "pid": 7100,
            "ppid": 1,
            "pgid": 7100,
            "etimes": 9000,
            "args": "bash /usr/local/bin/arnold-watchdog --once",
        },
        7200,
        3900,
    )
    assert watchdog["reap"] is False
    assert watchdog["reason"] == "non_target"

    auditor = module.decide_reap(
        {
            "pid": 7200,
            "ppid": 1,
            "pgid": 7200,
            "etimes": 9000,
            "args": "bash /usr/local/bin/arnold-progress-auditor --once",
        },
        7200,
        3900,
    )
    assert auditor["reap"] is False
    assert auditor["reason"] == "non_target"

    non_arnold = module.decide_reap(
        {
            "pid": 7300,
            "ppid": 1,
            "pgid": 7300,
            "etimes": 99999,
            "args": "python3 -m http.server 8080",
        },
        7200,
        3900,
    )
    assert non_arnold["reap"] is False
    assert non_arnold["reason"] == "non_target"


def test_watchdog_progress_reap_decision_uses_log_idle_and_fails_safe(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    operator_root = tmp_path / "kimi-goal-operator"
    marker_dir.mkdir()
    operator_root.mkdir()
    now = time.time()

    stale_dir = operator_root / "20260628T000000Z-demo-session"
    stale_dir.mkdir()
    stale_operator = stale_dir / "operator.log"
    stale_codex = stale_dir / "codex-repair.log"
    stale_operator.write_text("operator\n", encoding="utf-8")
    stale_codex.write_text("codex\n", encoding="utf-8")
    stale_ts = now - 901
    os.utime(stale_operator, (stale_ts, stale_ts))
    os.utime(stale_codex, (stale_ts, stale_ts))
    os.utime(stale_dir, (stale_ts, stale_ts))

    stale_rows = (
        "4100 4000 4100 1800 "
        "codex exec --sandbox danger-full-access "
        "'You are the watchdog repair-loop dev-fix agent for a stopped Arnold cloud session. "
        "Context: Session: demo-session Workspace: /tmp/ws'\n"
    )
    stale_out = _run_repair_stall(tmp_path, stale_rows, marker_dir, operator_root)
    assert len(stale_out) == 1
    stale_fields = stale_out[0].split("\t")
    assert stale_fields[0] == "4100"
    assert stale_fields[6] == "stalled"
    assert stale_fields[7].startswith("stall_idle_")
    assert stale_fields[8] == str(stale_dir)
    assert int(stale_fields[9]) >= 600
    snapshot = marker_dir / "demo-session.reap-progress.json"
    snap_payload = json.loads(snapshot.read_text(encoding="utf-8"))
    assert snap_payload["operator_dir"] == str(stale_dir)
    assert "last_advance_ts" in snap_payload

    active_dir = operator_root / "20260628T000500Z-active-session"
    active_dir.mkdir()
    active_operator = active_dir / "operator.log"
    active_operator.write_text("still making progress\n", encoding="utf-8")
    active_ts = now - 30
    os.utime(active_operator, (active_ts, active_ts))
    os.utime(active_dir, (active_ts, active_ts))
    active_rows = (
        "5100 5000 5100 1800 "
        "codex exec --sandbox danger-full-access "
        "'You are the watchdog repair-loop dev-fix agent for a stopped Arnold cloud session. "
        "Context: Session: active-session Workspace: /tmp/ws'\n"
    )
    assert _run_repair_stall(tmp_path, active_rows, marker_dir, operator_root) == []
    active_snapshot = marker_dir / "active-session.reap-progress.json"
    assert active_snapshot.exists()

    unmappable_rows = (
        "6100 6000 6100 1800 "
        "codex exec --sandbox danger-full-access "
        "'You are the watchdog repair-loop dev-fix agent for a stopped Arnold cloud session. "
        "Context: Session: missing-session Workspace: /tmp/ws'\n"
    )
    assert _run_repair_stall(tmp_path, unmappable_rows, marker_dir, operator_root) == []
    assert not (marker_dir / "missing-session.reap-progress.json").exists()


def test_watchdog_kimi_operator_dedupe_does_not_match_its_own_grep() -> None:
    text = _wrapper("arnold-watchdog")

    # The layered repair-loop / kimi-goal-operator process scans were removed
    # with the layered stack; kimi_operator_running is now pgid-marker based.
    assert 'printf \'%s/%s.kimi-pgid\' "$MARKER_DIR" "$1"' in text
    assert 'kill -0 -- "-$pgid"' in text
    assert "repair_loop_pid_matches_session()" not in text
    assert "arnold-repair-loop" not in text
    # The kimi-goal-operator PROCESS SCANNING is gone (only the path variable
    # remains for the reaper operator root).
    assert 'os.path.basename(args[idx]) == "arnold-kimi-goal-operator"' not in text
    assert 'grep -F "[a]rnold-kimi-goal-operator $session "' not in text


def test_watchdog_kimi_operator_running_falls_back_to_pgid_pidfile_and_clear_removes_it(
    tmp_path: Path,
) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    session = "demo-session"
    pgid_path = marker_dir / f"{session}.kimi-pgid"
    marker_path = marker_dir / f"{session}.kimi-dispatch"
    pgid_path.write_text("4242\n", encoding="utf-8")
    marker_path.write_text("2026-06-28T00:00:00Z\n", encoding="utf-8")

    script = "\n\n".join(
        [
            _extract_wrapper_function("kimi_dispatch_marker_path"),
            _extract_wrapper_function("kimi_pgid_path"),
            _extract_wrapper_function("kimi_dispatch_marker_clear"),
            _extract_wrapper_function("kimi_operator_running"),
            f"""
MARKER_DIR={str(marker_dir)!r}
pgrep() {{
  return 1
}}
kill() {{
  if [[ "$#" -eq 3 && "$1" == "-0" && "$2" == "--" && "$3" == "-4242" ]]; then
    return 0
  fi
  return 1
}}
ps() {{
  cat <<'EOF'
 4242 python3 -m arnold.agent.run_agent --goal repair
EOF
}}
if kimi_operator_running {session!r}; then
  echo running
else
  echo stopped
fi
kimi_dispatch_marker_clear {session!r}
if [[ ! -e {str(pgid_path)!r} && ! -e {str(marker_path)!r} ]]; then
  echo cleared
fi
""".strip(),
        ]
    )
    result = subprocess.run(
        ["bash", "-lc", script],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines() == ["running", "cleared"]


@pytest.mark.parametrize(
    ("case_name", "script_body", "expected_outcome"),
    [
        (
            "stale",
            """
session_health_status() { echo stale; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
chain_health_status() {
  CHAIN_HEALTH_STATUS=ok
  CHAIN_HEALTH_SUMMARY=
  CHAIN_HEALTH_ARTIFACT_PATH=
  CHAIN_HEALTH_LOG_MESSAGE=
}
repair_unhealthy_session() { return 0; }
dispatch_kimi_repair() { REPAIR_DISPATCH_RESULT=dispatched; return 0; }
mechanical_relaunch_attempted_previously() { return 1; }
kimi_dispatch_failed_previously() { return 1; }
kimi_dispatch_marker_set() { :; }
kimi_dispatch_marker_clear() { :; }
""",
            "stale",
        ),
        (
            "stopped",
            """
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
chain_health_status() {
  CHAIN_HEALTH_STATUS=ok
  CHAIN_HEALTH_SUMMARY=
  CHAIN_HEALTH_ARTIFACT_PATH=
  CHAIN_HEALTH_LOG_MESSAGE=
}
dispatch_kimi_repair() { REPAIR_DISPATCH_RESULT=dispatched; return 0; }
mechanical_relaunch_attempted_previously() { return 0; }
kimi_dispatch_failed_previously() { return 1; }
kimi_dispatch_marker_set() { :; }
kimi_dispatch_marker_clear() { :; }
""",
            "stopped",
        ),
        (
            "unhealthy",
            """
session_health_status() { echo alive; }
plan_phase_health_status() { echo unhealthy_plan; }
plan_progress_stall_status() { echo ok; }
chain_health_status() {
  CHAIN_HEALTH_STATUS=ok
  CHAIN_HEALTH_SUMMARY=
  CHAIN_HEALTH_ARTIFACT_PATH=
  CHAIN_HEALTH_LOG_MESSAGE=
}
dispatch_kimi_repair() { REPAIR_DISPATCH_RESULT=dispatched; return 0; }
""",
            "unhealthy",
        ),
        (
            "progress_stall",
            """
session_health_status() { echo alive; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo progress_stall:demo-plan iteration=9; }
chain_health_status() {
  CHAIN_HEALTH_STATUS=ok
  CHAIN_HEALTH_SUMMARY=
  CHAIN_HEALTH_ARTIFACT_PATH=
  CHAIN_HEALTH_LOG_MESSAGE=
}
repair_unintended_stop() { return 0; }
dispatch_kimi_repair() { REPAIR_DISPATCH_RESULT=dispatched; return 0; }
""",
            "progress_stall",
        ),
        (
            "chain_health_failure",
            """
session_health_status() { echo dead; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
chain_health_status() {
  CHAIN_HEALTH_STATUS=chain_large_file_push_rejection
  CHAIN_HEALTH_SUMMARY=chain cycle detected
  CHAIN_HEALTH_ARTIFACT_PATH=/tmp/chain-health.json
  CHAIN_HEALTH_LOG_MESSAGE=
}
dispatch_kimi_repair() { REPAIR_DISPATCH_RESULT=dispatched; return 0; }
""",
            "chain_health_failure",
        ),
        (
            "state_mismatch",
            """
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
chain_health_status() {
  CHAIN_HEALTH_STATUS=ok
  CHAIN_HEALTH_SUMMARY=
  CHAIN_HEALTH_ARTIFACT_PATH=
  CHAIN_HEALTH_LOG_MESSAGE=
}
plan_attention_status_env() {
  cat <<'EOF'
PLAN_STATUS_STATE_MISMATCH=1
PLAN_STATUS_STATE_MISMATCH_SUMMARY='plan/chain mismatch detected'
EOF
}
dispatch_kimi_repair() { REPAIR_DISPATCH_RESULT=dispatched; return 0; }
""",
            "state_mismatch",
        ),
    ],
)
def test_launch_chain_tick_emits_incident_detection_outcomes(
    tmp_path: Path,
    case_name: str,
    script_body: str,
    expected_outcome: str,
) -> None:
    marker_dir = tmp_path / f"markers-{case_name}"
    marker_dir.mkdir()
    repair_dir = marker_dir / "repair-data"
    repair_dir.mkdir()
    workspace = tmp_path / f"workspace-{case_name}"
    workspace.mkdir()
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    (repair_dir / "demo-session.repair-data.json").write_text(
        json.dumps({"incident_id": f"inc-{case_name}"}),
        encoding="utf-8",
    )
    report_path = tmp_path / f"report-{case_name}.tsv"
    log_path = tmp_path / f"watchdog-{case_name}.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("emit_watchdog_incident_bridge_event"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(repair_dir)!r}",
            f"LOG={str(log_path)!r}",
            f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            """
report_item() { :; }
log() { printf '%s\n' "$*" >> "$LOG"; }
session_terminal_status() { return 0; }
resolve_existing_remote_spec() { printf '%s\n' "$3"; }
repair_needs_human_path() { printf '%s\n' "$REPAIR_DATA_DIR/$1.needs-human.json"; }
repair_needs_human_matches_current_plan() { return 1; }
workspace_has_other_alive_session() { return 1; }
notify_needs_human() { return 0; }
resolve_relaunch_command() { echo RELAUNCH; }
repair_loop_busy_state() { echo none; }
babysitter_effective_mode() { printf 'superfixer\\t\\n'; }
babysitter_occurrence_digest() { echo a9c062b1cfe5; }
babysitter_running_for_occurrence() { return 1; }
babysitter_after_elapsed() { return 0; }
launch_status_trigger_babysitter() { echo BABYSITTER >&2; return 0; }
babysitter_policy_dispatch() {
  launch_status_trigger_babysitter "$@"
  report_item "$6" "$1" "repair" "babysitter_scheduled" "single-flash babysitter dispatched: $7" "$2" "$3"
}
plan_attention_status_env() { return 0; }
plan_terminal_status() { echo none; }
ensure_install_or_repair() { return 0; }
tmux() { return 1; }
""".strip(),
            script_body.strip(),
            (
                f"launch_chain_tick demo-session {str(workspace)!r} "
                f"{str(spec_path)!r} {str(report_path)!r} chain '' ''"
            ),
        ]
    )

    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    payloads = _read_incident_event_payloads(workspace)
    assert payloads[0]["type"] == "detection"
    assert payloads[0]["outcome"] == expected_outcome


def test_watchdog_complete_teardown_collects_setsid_descendant_pgids(tmp_path: Path) -> None:
    ps_path = tmp_path / "ps"
    ps_path.write_text(
        "#!/usr/bin/env bash\n"
        "cat <<'EOF'\n"
        "100 1 100\n"
        "101 100 100\n"
        "102 101 102\n"
        "103 102 102\n"
        "EOF\n",
        encoding="utf-8",
    )
    ps_path.chmod(ps_path.stat().st_mode | stat.S_IXUSR)

    script = "\n\n".join(
        [
            _extract_wrapper_function("repair_tree_pgids"),
            """
PATH=%s:$PATH
repair_tree_pgids 100 100
""".strip() % str(tmp_path),
        ]
    )
    result = subprocess.run(
        ["bash", "-lc", script],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().split() == ["100", "102"]


def test_watchdog_treats_supervisor_retry_before_process_liveness_as_unhealthy() -> None:
    text = _extract_wrapper_function("session_health_status")

    pane_check = 'tmux -S "$capture_socket" capture-pane'
    retry_check = "retrying_failure"
    process_check = 'if chain_process_is_alive "$remote_spec"; then'

    assert text.index(pane_check) < text.index(process_check)
    assert text.index(retry_check) < text.index(process_check)
    assert '"error": "invalid_spec"' in text


def test_watchdog_skips_relaunch_while_review_pr_is_still_open() -> None:
    text = _wrapper("arnold-watchdog")

    assert "chain_wait_status()" in text
    assert 'wait_status="$(chain_wait_status "$workspace" "$remote_spec")"' in text
    assert 'if [[ "$health" == "awaiting_pr_merge" ]]; then' in text
    assert "reconcile_awaiting_pr_merge" in text
    assert 'report_item "$report_items" "$session" "observe" "awaiting_pr_merge"' in text
    assert 'if not automatic_progression:' in text
    assert 'emit("review_policy", policy_reason)' in text
    assert '["gh", "pr", "view", str(pr_number), "--json", "state"]' in text
    assert '["gh", "pr", "merge", str(pr_number), *flags]' in text


def test_watchdog_stopped_tmux_reports_awaiting_pr_merge_from_chain_state(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    chain_dir.mkdir(parents=True)
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True)
    spec_path.write_text("merge_policy: review\n", encoding="utf-8")
    (chain_dir / "demo-chain.json").write_text(
        json.dumps({"last_state": "awaiting_pr_merge"}),
        encoding="utf-8",
    )

    script = "\n\n".join(
        [
            _extract_wrapper_function("chain_wait_status"),
            _extract_wrapper_function("session_health_status"),
            """
matching_runner_process_alive() { return 1; }
tmux() {
  if [[ "$1" == "has-session" ]]; then
    return 1
  fi
  return 0
}
""".strip(),
            f"session_health_status demo-session {str(workspace)!r} {str(spec_path)!r} chain ''",
        ]
    )
    result = _run_watchdog_shell(script)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "awaiting_pr_merge"


def test_watchdog_stopped_tmux_prefers_live_chain_process_over_wait_state(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    chain_dir.mkdir(parents=True)
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True)
    spec_path.write_text("merge_policy: review\n", encoding="utf-8")
    (chain_dir / "demo-chain.json").write_text(
        json.dumps({"last_state": "awaiting_human_verify"}),
        encoding="utf-8",
    )

    script = "\n\n".join(
        [
            _extract_wrapper_function("chain_wait_status"),
            _extract_wrapper_function("session_health_status"),
            f"""
matching_runner_process_alive() {{ return 0; }}
tmux() {{
  if [[ "$1" == "has-session" ]]; then
    return 1
  fi
  return 0
}}
ps() {{
  printf '%s\\n' 'python3 -P -m arnold_pipelines.megaplan chain start --spec {str(spec_path)} --project-dir {str(workspace)}'
}}
""".strip(),
            f"session_health_status demo-session {str(workspace)!r} {str(spec_path)!r} chain ''",
        ]
    )
    result = _run_watchdog_shell(script)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "alive"


def test_watchdog_terminal_status_accepts_label_only_completed_chain(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    chain_dir.mkdir(parents=True)
    spec_path = workspace / ".megaplan" / "briefs" / "python-shaped-workflow-authoring" / "chain.yaml"
    spec_path.parent.mkdir(parents=True)
    spec_path.write_text(
        "\n".join(
            [
                "merge_policy: review",
                "milestones:",
                "  - label: m1",
                "  - label: m2",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    _write_chain_state(
        chain_dir / "chain-demo.json",
        {
            "last_state": "done",
            "current_milestone_index": 2,
            "current_plan_name": "",
            "completed": [{"label": "m1"}, {"label": "m2"}],
            "pr_number": 128,
            "pr_state": "merged",
        },
    )
    repair_dir = tmp_path / "repair-data"
    repair_dir.mkdir()

    script = "\n\n".join(
        [
            _extract_wrapper_function("session_terminal_status"),
            f"MARKER_DIR={str(tmp_path / 'markers')!r}",
            f"REPAIR_DATA_DIR={str(repair_dir)!r}",
            f"session_terminal_status demo-session {str(workspace)!r} {str(spec_path)!r} chain",
        ]
    )
    result = _run_watchdog_shell(script)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "complete\tchain complete"


def test_watchdog_terminal_status_reads_spec_local_chain_state(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    spec_path = workspace / ".megaplan" / "briefs" / "god-file-splits" / "chain.yaml"
    chain_dir = spec_path.parent / ".megaplan" / "plans" / ".chains"
    chain_dir.mkdir(parents=True)
    spec_path.write_text(
        "\n".join(
            [
                "milestones:",
                "  - label: split-comfy-nodes-agent-edit",
                "  - label: split-porting-emitter-py-god",
                "  - label: split-porting-edit-apply-py",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    _write_chain_state(
        chain_dir / "chain-demo.json",
        {
            "last_state": "done",
            "current_milestone_index": 3,
            "current_plan_name": "",
            "completed": [
                {"label": "split-comfy-nodes-agent-edit"},
                {"label": "split-porting-emitter-py-god"},
                {"label": "split-porting-edit-apply-py"},
            ],
            "events": [{"msg": "all milestones complete"}],
        },
    )
    repair_dir = tmp_path / "repair-data"
    repair_dir.mkdir()

    script = "\n\n".join(
        [
            _extract_wrapper_function("session_terminal_status"),
            f"MARKER_DIR={str(tmp_path / 'markers')!r}",
            f"REPAIR_DATA_DIR={str(repair_dir)!r}",
            f"session_terminal_status demo-session {str(workspace)!r} {str(spec_path)!r} chain",
        ]
    )
    result = _run_watchdog_shell(script)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "complete\tchain complete"


def test_watchdog_auto_merge_policy_attempts_pr_merge_before_waiting(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "ws"
    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    chain_dir.mkdir(parents=True)
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True)
    spec_path.write_text("merge_policy: auto\n", encoding="utf-8")
    (chain_dir / "demo-chain.json").write_text(
        json.dumps({"last_state": "awaiting_pr_merge", "pr_number": 42}),
        encoding="utf-8",
    )

    gh_log = tmp_path / "gh.log"
    merged_flag = tmp_path / "merged"
    gh_path = tmp_path / "gh"
    gh_path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env bash",
                f"printf '%s\\n' \"$*\" >> {str(gh_log)!r}",
                "if [[ \"$1 $2 $3\" == \"pr view 42\" ]]; then",
                f"  if [[ -f {str(merged_flag)!r} ]]; then",
                "    printf '%s\\n' '{\"state\":\"MERGED\"}'",
                "  else",
                "    printf '%s\\n' '{\"state\":\"OPEN\"}'",
                "  fi",
                "  exit 0",
                "fi",
                "if [[ \"$1 $2 $3\" == \"pr ready 42\" ]]; then",
                "  exit 0",
                "fi",
                "if [[ \"$1 $2 $3\" == \"pr merge 42\" ]]; then",
                f"  touch {str(merged_flag)!r}",
                "  exit 0",
                "fi",
                "exit 1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    gh_path.chmod(gh_path.stat().st_mode | stat.S_IXUSR)

    script = "\n\n".join(
        [
            _extract_wrapper_function("chain_wait_status"),
            f"chain_wait_status {str(workspace)!r} {str(spec_path)!r}",
        ]
    )
    result = _run_watchdog_shell(script, path_prefix=tmp_path)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "none"
    gh_calls = gh_log.read_text(encoding="utf-8").splitlines()
    assert "pr ready 42" in gh_calls
    assert "pr merge 42 --auto --squash --delete-branch" in gh_calls


def test_watchdog_auto_merge_gates_delete_branch_on_reference_census(
    tmp_path: Path,
) -> None:
    """G6 finding 4: the watchdog's gh-merge path must not delete the PR head
    branch without reference-census proof for the branch's runtime root.

    REFERENCED / UNKNOWN drop --delete-branch — the non-destructive merge
    still proceeds, but the deletion is refused with a writer note.  CLEAR
    keeps the existing route authority (merge + --delete-branch).
    """
    workspace = tmp_path / "ws"
    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    chain_dir.mkdir(parents=True)
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True)
    spec_path.write_text("merge_policy: auto\n", encoding="utf-8")
    (chain_dir / "demo-chain.json").write_text(
        json.dumps({"last_state": "awaiting_pr_merge", "pr_number": 42}),
        encoding="utf-8",
    )

    def run_scenario(
        scenario: str, store_dir: Path, log_path: Path
    ) -> list[str]:
        gh_bin = tmp_path / f"bin-{scenario}"
        gh_bin.mkdir()
        gh_log = gh_bin / "gh.log"
        merged_flag = gh_bin / "merged"
        gh_path = gh_bin / "gh"
        gh_path.write_text(
            "\n".join(
                [
                    "#!/usr/bin/env bash",
                    f"printf '%s\\n' \"$*\" >> {str(gh_log)!r}",
                    "if [[ \"$1 $2 $3\" == \"pr view 42\" ]]; then",
                    f"  if [[ -f {str(merged_flag)!r} ]]; then",
                    "    printf '%s\\n' '{\"state\":\"MERGED\"}'",
                    "  else",
                    "    printf '%s\\n' '{\"state\":\"OPEN\"}'",
                    "  fi",
                    "  exit 0",
                    "fi",
                    "if [[ \"$1 $2 $3\" == \"pr ready 42\" ]]; then",
                    "  exit 0",
                    "fi",
                    "if [[ \"$1 $2 $3\" == \"pr merge 42\" ]]; then",
                    f"  touch {str(merged_flag)!r}",
                    "  exit 0",
                    "fi",
                    "exit 1",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        gh_path.chmod(gh_path.stat().st_mode | stat.S_IXUSR)

        if scenario == "referenced":
            store_dir.mkdir(parents=True)
            (store_dir / "chain-ref.json").write_text(
                json.dumps(
                    {
                        "metadata": {
                            "execution_environment": {"engine_root": str(workspace)}
                        }
                    }
                ),
                encoding="utf-8",
            )
        elif scenario == "unknown":
            store_dir.mkdir(parents=True)
            (store_dir / "corrupt.json").write_text(
                '{"metadata": {"execution_environment": ', encoding="utf-8"
            )

        script = "\n\n".join(
            [
                "\n".join(
                    [
                        "export ARNOLD_BASE_DIR=''",
                        f"export ARNOLD_RUNTIME_MANIFEST_DIR={str(tmp_path / f'ref-manifests-{scenario}')!r}",
                        f"export ARNOLD_REFERENCE_CHAIN_STORE={str(store_dir)!r}",
                        f"export ARNOLD_REFERENCE_MARKER_STORE={str(tmp_path / f'ref-markers-{scenario}')!r}",
                        f"export ARNOLD_REFERENCE_SCHEDULE_STORES={str(tmp_path / f'ref-schedules-{scenario}')!r}",
                        f"export ARNOLD_REFERENCE_REPAIR_QUEUE={str(tmp_path / f'ref-repair-queue-{scenario}')!r}",
                        f"export ARNOLD_REFERENCE_LEASE_STORE={str(tmp_path / f'ref-leases-{scenario}')!r}",
                        f"export CLOUD_WATCHDOG_LOG={str(log_path)!r}",
                        f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}",
                    ]
                ),
                _extract_wrapper_function("chain_wait_status"),
                f"chain_wait_status {str(workspace)!r} {str(spec_path)!r}",
            ]
        )
        result = _run_watchdog_shell(script, path_prefix=gh_bin)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "none"
        return gh_log.read_text(encoding="utf-8").splitlines()

    # REFERENCED: merge proceeds, --delete-branch refused with a writer note.
    log_ref = tmp_path / "watchdog-referenced.log"
    gh_calls = run_scenario(
        "referenced", tmp_path / "ref-chains-referenced", log_ref
    )
    assert "pr merge 42 --auto --squash" in gh_calls
    assert not any("--delete-branch" in call for call in gh_calls)
    note = log_ref.read_text(encoding="utf-8")
    assert "reference census REFERENCED" in note
    assert "refusing --delete-branch" in note

    # UNKNOWN (corrupt store): fail-closed, --delete-branch refused too.
    log_unknown = tmp_path / "watchdog-unknown.log"
    gh_calls = run_scenario("unknown", tmp_path / "ref-chains-unknown", log_unknown)
    assert "pr merge 42 --auto --squash" in gh_calls
    assert not any("--delete-branch" in call for call in gh_calls)
    assert "reference census UNKNOWN" in log_unknown.read_text(encoding="utf-8")

    # CLEAR (absent store): existing route authority keeps --delete-branch.
    log_clear = tmp_path / "watchdog-clear.log"
    gh_calls = run_scenario("clear", tmp_path / "ref-chains-clear", log_clear)
    assert "pr merge 42 --auto --squash --delete-branch" in gh_calls


def test_watchdog_finalized_plan_never_authorizes_pr_merge(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    chain_dir.mkdir(parents=True)
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True)
    spec_path.write_text("merge_policy: auto\n", encoding="utf-8")
    (chain_dir / "demo-chain.json").write_text(
        json.dumps(
            {
                "last_state": "finalized",
                "current_plan_name": "demo-plan",
                "pr_number": 42,
            }
        ),
        encoding="utf-8",
    )
    gh_log = tmp_path / "gh.log"
    gh_path = tmp_path / "gh"
    gh_path.write_text(
        "#!/usr/bin/env bash\n"
        f"printf '%s\\n' \"$*\" >> {str(gh_log)!r}\n"
        "exit 1\n",
        encoding="utf-8",
    )
    gh_path.chmod(gh_path.stat().st_mode | stat.S_IXUSR)

    script = "\n\n".join(
        [
            _extract_wrapper_function("chain_wait_status"),
            f"chain_wait_status {str(workspace)!r} {str(spec_path)!r}",
        ]
    )
    result = _run_watchdog_shell(script, path_prefix=tmp_path)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "none"
    assert not gh_log.exists()


def test_watchdog_auto_policy_merged_pr_fetches_origin_but_unknown_liveness_fences_relaunch(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    marker_dir = tmp_path / "markers"
    repair_dir = tmp_path / "repair-data"
    marker_dir.mkdir()
    repair_dir.mkdir()
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True)
    spec_path.write_text("merge_policy: auto\n", encoding="utf-8")
    chain_path = workspace / ".megaplan" / "plans" / ".chains" / "demo-chain.json"
    _write_chain_state(
        chain_path,
        {"last_state": "awaiting_pr_merge", "pr_number": 42, "pr_state": "open"},
    )
    report_path = tmp_path / "report.tsv"
    call_log = tmp_path / "calls.log"
    gh_path = tmp_path / "gh"
    gh_path.write_text(
        "#!/usr/bin/env bash\n"
        f"printf 'gh %s\\n' \"$*\" >> {str(call_log)!r}\n"
        "if [[ \"$1 $2 $3\" == \"pr view 42\" ]]; then\n"
        "  printf '%s\\n' '{\"state\":\"MERGED\",\"mergeCommit\":{\"oid\":\"abc123\"}}'\n"
        "  exit 0\n"
        "fi\n"
        "exit 1\n",
        encoding="utf-8",
    )
    gh_path.chmod(gh_path.stat().st_mode | stat.S_IXUSR)
    git_path = tmp_path / "git"
    git_path.write_text(
        "#!/usr/bin/env bash\n"
        f"printf 'git %s\\n' \"$*\" >> {str(call_log)!r}\n"
        "exit 0\n",
        encoding="utf-8",
    )
    git_path.chmod(git_path.stat().st_mode | stat.S_IXUSR)

    script = "\n\n".join(
        [
            _extract_wrapper_function("json_field"),
            _extract_wrapper_function("safe_name"),
            _extract_wrapper_function("reconcile_awaiting_pr_merge"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(repair_dir)!r}",
            """
log() { printf '%s\n' "$*" >> "$CALL_LOG"; }
report_item() { printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"; }
session_health_status() { echo awaiting_pr_merge; }
chain_health_status() { CHAIN_HEALTH_STATUS=ok; }
plan_terminal_status() { echo none; }
plan_attention_status_env() { :; }
repair_needs_human_path() { printf '%s/%s.needs-human.json\n' "$REPAIR_DATA_DIR" "$1"; }
workspace_has_other_alive_session() { return 1; }
repair_loop_busy_state() { echo none; }
mechanical_relaunch_attempted_previously() { return 1; }
kimi_dispatch_failed_previously() { return 1; }
kimi_dispatch_marker_set() { :; }
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH; }
tmux() { printf 'tmux %s\n' "$*" >> "$CALL_LOG"; return 0; }
mktemp() { printf '%s\n' "$LAUNCH_SCRIPT"; }
chmod() { :; }
""".strip(),
            f"CALL_LOG={str(call_log)!r}",
            f"LAUNCH_SCRIPT={str(tmp_path / 'launch.sh')!r}",
            f"launch_chain_tick demo-session {str(workspace)!r} {str(spec_path)!r} {str(report_path)!r} chain '' ''",
        ]
    )

    result = _run_watchdog_shell(script, path_prefix=tmp_path)
    assert result.returncode == 0, result.stderr
    calls = call_log.read_text(encoding="utf-8")
    assert "gh pr view 42 --json state,mergeCommit" in calls
    assert "git fetch origin --prune" in calls
    assert "git cat-file -e abc123^{commit}" in calls
    assert "session awaiting PR merge reconciled merged; falling through to relaunch" in calls
    assert "tmux new-session -d -s demo-session" not in calls
    assert "\tobserve\tliveness_unknown\t" in report_path.read_text(encoding="utf-8")


def test_watchdog_auto_policy_open_pr_queues_evidence_and_preserves_wait(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ARNOLD_REPAIR_REQUEST_QUEUE", "1")
    workspace = tmp_path / "ws"
    workspace.mkdir()
    marker_dir = tmp_path / "markers"
    repair_dir = tmp_path / "repair-data"
    marker_dir.mkdir()
    repair_dir.mkdir()
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True)
    spec_path.write_text("merge_policy: auto\n", encoding="utf-8")
    _write_live_session_marker(
        marker_dir,
        "demo-session",
        workspace,
        str(spec_path),
        run_kind="chain",
    )
    chain_path = workspace / ".megaplan" / "plans" / ".chains" / "demo-chain.json"
    _write_chain_state(
        chain_path,
        {"last_state": "awaiting_pr_merge", "pr_number": 43, "pr_state": "open"},
    )
    report_path = tmp_path / "report.tsv"
    call_log = tmp_path / "calls.log"
    gh_path = tmp_path / "gh"
    gh_path.write_text(
        "#!/usr/bin/env bash\n"
        f"printf 'gh %s\\n' \"$*\" >> {str(call_log)!r}\n"
        "if [[ \"$1 $2 $3\" == \"pr view 43\" ]]; then\n"
        "  printf '%s\\n' '{\"state\":\"OPEN\"}'\n"
        "  exit 0\n"
        "fi\n"
        "exit 1\n",
        encoding="utf-8",
    )
    gh_path.chmod(gh_path.stat().st_mode | stat.S_IXUSR)

    script = "\n\n".join(
        [
            _extract_wrapper_function("reconcile_awaiting_pr_merge"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(repair_dir)!r}",
            """
log() { printf '%s\n' "$*" >> "$CALL_LOG"; }
report_item() { printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"; }
session_health_status() { echo awaiting_pr_merge; }
chain_health_status() { CHAIN_HEALTH_STATUS=ok; }
repair_needs_human_path() { printf '%s/%s.needs-human.json\n' "$REPAIR_DATA_DIR" "$1"; }
notify_needs_human() {
  report_item "$1" "$2" "notify" "human_gate_notification_queued" "$7" "$3" "$4"
}
tmux() { printf 'TMUX %s\n' "$*" >> "$CALL_LOG"; return 0; }
""".strip(),
            f"CALL_LOG={str(call_log)!r}",
            f"launch_chain_tick demo-session {str(workspace)!r} {str(spec_path)!r} {str(report_path)!r} chain '' ''",
        ]
    )

    result = _run_watchdog_shell(script, path_prefix=tmp_path)
    assert result.returncode == 0, result.stderr
    calls = call_log.read_text(encoding="utf-8")
    assert "gh pr view 43 --json state,mergeCommit" in calls
    assert "session awaiting PR merge: demo-session detail=PR #43 state=open evidence=read_only" in calls
    assert "TMUX" not in calls
    report = report_path.read_text(encoding="utf-8")
    assert "\tnotify\thuman_gate_notification_queued\tawaiting_human halt; state=awaiting_pr_merge;" in report
    queued = list((tmp_path / ".megaplan" / "repair-queue" / "requests").glob("*.json"))
    assert queued == []
    chain_payload = json.loads(chain_path.read_text(encoding="utf-8"))
    assert chain_payload["metadata"]["watchdog_pr_merge_reconciliation"]["pr_number"] == 43


def test_watchdog_queue_writers_use_explicit_central_queue_root() -> None:
    text = _wrapper("arnold-watchdog")

    # The shell-level queue-root assignment moved into the Python queue
    # writer; the relaunch envelope still binds the explicit central queue
    # root for the babysitter child.
    assert 'repair_queue_root="${ARNOLD_REPAIR_QUEUE_ROOT:-${repair_marker_dir%/*}/repair-queue}"' in text
    assert "export ARNOLD_REPAIR_QUEUE_ROOT=%q" in text
    # The PR-merge wait path is read-only: it never enqueues a repair request
    # or mints a repair identity.
    assert "def enqueue_wait_evidence" in text
    assert 'return "read_only"' in text
    assert "occurrence_identity=None" not in text


def test_watchdog_relaunch_runs_editable_install_code_against_active_workspace() -> None:
    text = _wrapper("arnold-watchdog")

    assert "if [[ -f /workspace/.cloud-hot-env ]]; then set -a; . /workspace/.cloud-hot-env; set +a; fi;" in text
    assert "resolve_relaunch_command()" in text
    assert "default_plan_relaunch_command()" in text
    assert "python3 -P -m arnold_pipelines.megaplan chain start" in text
    assert "python3 -P -m arnold_pipelines.megaplan auto --plan" in text
    assert '"$session" "$workspace" "$remote_spec" "$run_kind" "$plan_name" "$relaunch_command"' in text
    assert "--project-dir %q --one" not in text
    assert 'tmux -S "$tmux_socket" kill-session -t "=$tmux_session_id"' in text
    assert 'sleep 0.2' in text
    assert "relaunch raced with existing tmux session" in text
    assert "session exists after relaunch race" in text
    assert "export ARNOLD_SUPERVISE_SESSION=" in text
    assert "export ARNOLD_SUPERVISE_WORKSPACE=" in text
    assert "export ARNOLD_SUPERVISE_REMOTE_SPEC=" in text
    assert "export ARNOLD_SUPERVISE_RUN_KIND=" in text
    assert "printf -v quoted_command_shell '%q' \"$quoted_command\"" in text
    assert 'bash -lc $quoted_command_shell' in text
    assert 'bash -lc "$quoted_command"' not in text


def test_watchdog_relaunch_requires_substantive_health_before_reporting_restart() -> None:
    text = _wrapper("arnold-watchdog")

    assert "verify_relaunch_health()" in text
    assert 'verified_health="$(verify_relaunch_health ' in text
    assert '"restart_failed" "tmux relaunch did not produce a healthy runner' in text
    assert 'dispatch_kimi_repair "$session" "$workspace" "$remote_spec"' not in text


def test_l1_l2_l3_prompts_preserve_profile_and_reject_cursorless_success() -> None:
    """The surviving fixer prompt contract: profile preservation is enforced
    and cursorless success is rejected.  The L1 repair-loop and L2 meta-repair
    prompt tiers were removed with the layered stack; the L3 progress-auditor
    prompt is the surviving carrier of this contract."""
    auditor = _wrapper("arnold-progress-auditor")

    assert "Missing profile preservation is a repair-system" in auditor
    assert "completed-repair-without-cursor-advance" in auditor


def test_cloud_discover_relaunch_materializers_are_non_authoritative(
    tmp_path: Path,
) -> None:
    """Step 52: every relaunch command arnold-cloud-discover emits is a
    non-authoritative relaunch materializer.  A successful relaunch (rc=0)
    cannot become accepted repair outside canonical simple_fixer delegation;
    authority is never derived from a label, liveness signal, WBC receipt, or
    rebuildable projection (SC19)."""
    text = _wrapper("arnold-cloud-discover")
    assert "_relaunch_materializer_authority_gate" in text
    assert "forbidden_sources_present" in text
    # Extract the embedded Python program.
    py_start = text.index("<<'PY'\n") + len("<<'PY'\n")
    py_end = text.index("\nPY\n", py_start)
    program = text[py_start:py_end]
    # The relaunch generators re-read the per-epic runtime manifest as the
    # admission pin (G5/T-0022); give the harness a valid one whose
    # epic.runtime_root is the live import root, and bind the chain spec the
    # chain generator preflights.
    manifest_path = _write_runtime_manifest(tmp_path, runtime_root=REPO_ROOT)
    _bound_chain_state(Path("/tmp/ws"), "origin/main", REPO_ROOT)
    # Build a harness that mocks subprocess, exec's the program to define the
    # relaunch generators and the gate, then classifies each command.
    harness_lines = [
        "import io, json, subprocess, sys, types",
        "sys.argv = ['_cloud_discover', "
        + repr(str(tmp_path))
        + ", "
        + repr(str(REPO_ROOT))
        + "]",
        "import os",
        "os.environ['ARNOLD_RUNTIME_MANIFEST'] = "
        + repr(str(manifest_path)),
        "_fake = types.SimpleNamespace("
        "returncode=0, stdout='', stderr='', pid=0, args=[])",
        "subprocess.run = lambda *a, **k: _fake",
        "ns = {'os': os}",
        "_saved = sys.stdout",
        "sys.stdout = io.StringIO()",
        "try:",
        "    exec(compile("
        + repr(program)
        + ", 'cloud-discover', 'exec'), ns)",
        "except SystemExit:",
        "    pass",
        "sys.stdout = _saved",
        "_plan = ns['_plan_relaunch_command']('demo-plan', '/tmp/ws', 'demo')",
        "_chain = ns['_chain_relaunch_command']('origin/main', '/tmp/ws', 'demo')",
        "_gate = ns['_relaunch_materializer_authority_gate']",
        "_proofs = [",
        "    {'label': 'plan', 'cmd': _plan, 'gate': _gate(_plan)},",
        "    {'label': 'chain', 'cmd': _chain, 'gate': _gate(_chain)},",
        "]",
        "print(json.dumps(_proofs))",
    ]
    result = _run_embedded_python("\n".join(harness_lines))
    assert result.returncode == 0, result.stderr
    proofs = json.loads(result.stdout.strip())
    assert len(proofs) == 2
    for proof in proofs:
        g = proof["gate"]
        assert g["family"] != "", g
        assert g["is_non_authoritative_family"] is True, g
        assert g["is_repair_authority"] is False, g
        assert g["can_become_accepted_repair_on_success"] is False, g
        assert g["accepted_repair_requires_canonical_delegation"] is True, g
        assert (
            g["canonical_delegation_path"]
            == "simple_fixer.singleton_claim.exact_f01_tuple"
        ), g
        assert g["forbidden_sources_present"] == [], g


def test_watchdog_relaunch_materializers_are_non_authoritative() -> None:
    """Step 53: every relaunch command and arnold-supervise bash -lc script
    produced by arnold-watchdog is a non-authoritative relaunch materializer.
    A successful relaunch (rc=0) cannot become accepted repair outside
    canonical simple_fixer delegation; authority is never derived from a label,
    liveness signal, WBC receipt, or rebuildable projection (SC19)."""
    text = _wrapper("arnold-watchdog")
    assert "relaunch_materializer_authority_gate() {" in text
    assert 'relaunch_materializer_authority_gate "$quoted_command"' in text
    # The preflight re-reads the recorded engine root for the chain command;
    # bind /tmp/ws/origin/main to the live import root so the pin check and
    # the recorded-root check both pass.
    _bound_chain_state(Path("/tmp/ws"), "origin/main", REPO_ROOT)
    functions = "\n\n".join(_extract_relaunch_functions("watchdog"))
    gate = _extract_wrapper_function("relaunch_materializer_authority_gate")
    bash_lines = [
        'PLAN_AUTO="$(default_plan_relaunch_command "demo-plan" "/tmp/ws" "demo-plan")"',
        'PLAN_RESUME="$(resume_plan_relaunch_command "demo-plan" "/tmp/ws" "demo-plan")"',
        'CHAIN_START="$(default_chain_relaunch_command "demo-sess" "/tmp/ws" "origin/main")"',
        '_quoted="$(printf \'%q\' "$PLAN_AUTO")"',
        'SUPERVISE_WRAPPER="exec arnold-supervise \\"watchdog\\" bash -lc $_quoted"',
        '_G1="$(relaunch_materializer_authority_gate "$PLAN_AUTO")"',
        '_G2="$(relaunch_materializer_authority_gate "$PLAN_RESUME")"',
        '_G3="$(relaunch_materializer_authority_gate "$CHAIN_START")"',
        '_G4="$(relaunch_materializer_authority_gate "$SUPERVISE_WRAPPER")"',
        "python3 - \"$_G1\" \"$_G2\" \"$_G3\" \"$_G4\" <<'EMIT_PY'",
        "import json, sys",
        'labels = ["default_plan_relaunch", "resume_plan_relaunch", "default_chain_relaunch", "arnold_supervise_bash_lc"]',
        "proofs = []",
        "for label, raw in zip(labels, sys.argv[1:]):",
        "    gate = json.loads(raw)",
        '    gate["_generator"] = label',
        "    proofs.append(gate)",
        "print(json.dumps(proofs))",
        "EMIT_PY",
    ]
    script = "\n\n".join(
        [
            functions,
            gate,
            "SRC_DIR=" + repr(str(REPO_ROOT)),
            "MANIFEST_RUNTIME_ROOT=" + repr(str(REPO_ROOT)),
            "LIVE_IMPORT_ROOT=" + repr(str(REPO_ROOT)),
            "SYNC_BRANCH=editable-install",
            "\n".join(bash_lines),
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    proofs = json.loads(result.stdout.strip())
    assert len(proofs) == 4
    for proof in proofs:
        assert proof["family"] != "", proof
        assert proof["is_non_authoritative_family"] is True, proof
        assert proof["is_repair_authority"] is False, proof
        assert proof["can_become_accepted_repair_on_success"] is False, proof
        assert proof["accepted_repair_requires_canonical_delegation"] is True, proof
        assert (
            proof["canonical_delegation_path"]
            == "simple_fixer.singleton_claim.exact_f01_tuple"
        ), proof
        assert proof["forbidden_sources_present"] == [], proof


def _bound_chain_state(workspace: Path, spec_path: str, engine_root: Path) -> Path:
    """Write a runtime-bound chain state record at the canonical ``.chains``
    path (digest over the resolved spec path), mirroring the wrapper-side
    ``chain_engine_root_preflight`` state lookup."""
    spec = Path(spec_path)
    if not spec.is_absolute():
        spec = Path(workspace) / spec
    spec = spec.resolve()
    digest = hashlib.sha1(str(spec).encode("utf-8")).hexdigest()[:12]
    state = {
        "current_plan_name": "",
        "last_state": "blocked",
        "metadata": {"execution_environment": {"engine_root": str(engine_root)}},
    }
    path = workspace / ".megaplan" / "plans" / ".chains" / f"chain-{digest}.json"
    _write_chain_state(path, state)
    return path


def test_cloud_discover_plan_relaunch_binds_only_accepted_root_on_pythonpath(
    tmp_path: Path,
) -> None:
    """G5 round-7 finding 2: the arnold-cloud-discover ``_plan_relaunch_command``
    puts the preflight-accepted manifest root on PYTHONPATH ONLY — no
    ``:${PYTHONPATH:-}`` merge, so an ambient shared-root PYTHONPATH cannot
    leak into the launched python process."""
    text = _wrapper("arnold-cloud-discover")
    py_start = text.index("<<'PY'\n") + len("<<'PY'\n")
    py_end = text.index("\nPY\n", py_start)
    program = text[py_start:py_end]
    # The plan preflight reads the per-epic runtime manifest as its admission
    # pin; give the harness a valid one whose epic.runtime_root is the live
    # import root of the running python (G5 round-17 finding 1a: a standalone
    # plan never accepts a manifest root that differs from the live import
    # root), and bind the chain spec the chain generator preflights.  The
    # --src-dir hint stays observation-only.
    runtime_root = REPO_ROOT
    src_hint = tmp_path / "src-hint"
    manifest_path = _write_runtime_manifest(tmp_path, runtime_root=runtime_root)
    _bound_chain_state(Path("/tmp/ws"), "origin/main", runtime_root)
    harness_lines = [
        "import json, subprocess, sys, types",
        "sys.argv = ['_cloud_discover', "
        + repr(str(tmp_path))
        + ", "
        + repr(str(src_hint))
        + "]",
        "import os",
        "os.environ['ARNOLD_RUNTIME_MANIFEST'] = "
        + repr(str(manifest_path)),
        "_fake = types.SimpleNamespace("
        "returncode=0, stdout='', stderr='', pid=0, args=[])",
        "subprocess.run = lambda *a, **k: _fake",
        "ns = {'os': os}",
        "exec(compile("
        + repr(program)
        + ", 'cloud-discover', 'exec'), ns)",
        "_plan = ns['_plan_relaunch_command']('demo-plan', '/tmp/ws', 'demo')",
        "print(json.dumps({'plan': _plan}))",
    ]
    result = _run_embedded_python("\n".join(harness_lines))
    assert result.returncode == 0, result.stderr
    plan_cmd = json.loads(result.stdout.strip())["plan"]
    assert ":${PYTHONPATH:-}" not in plan_cmd
    assert f"PYTHONPATH={runtime_root}" in plan_cmd
    # The accepted root is the ONLY PYTHONPATH entry: no colon-joined merge
    # with any inherited value.
    assert f"PYTHONPATH={runtime_root}:" not in plan_cmd
    # The executed root is never the observation-only --src-dir.
    assert f"PYTHONPATH={src_hint}" not in plan_cmd


def test_cloud_discover_standalone_plan_manifest_live_drift_fails_closed(
    tmp_path: Path,
) -> None:
    """G5 (round-17 finding 1a): a STANDALONE plan (no bound chain) whose
    manifest epic.runtime_root differs from the ACTUAL live import root of
    the running python fails closed (typed drift, exit 24) — the manifest
    root is never returned unchecked."""
    text = _wrapper("arnold-cloud-discover")
    py_start = text.index("<<'PY'\n") + len("<<'PY'\n")
    py_end = text.index("\nPY\n", py_start)
    program = text[py_start:py_end]
    drifted_root = tmp_path / "drifted-runtime"
    manifest_path = _write_runtime_manifest(tmp_path, runtime_root=drifted_root)
    workspace = tmp_path / "ws"
    harness_lines = [
        "import subprocess, sys, types",
        "sys.argv = ['_cloud_discover', "
        + repr(str(tmp_path))
        + ", "
        + repr(str(drifted_root))
        + "]",
        "import os",
        "os.environ['ARNOLD_RUNTIME_MANIFEST'] = "
        + repr(str(manifest_path)),
        "_fake = types.SimpleNamespace("
        "returncode=0, stdout='', stderr='', pid=0, args=[])",
        "subprocess.run = lambda *a, **k: _fake",
        "ns = {'os': os}",
        "exec(compile("
        + repr(program)
        + ", 'cloud-discover', 'exec'), ns)",
        "ns['_plan_relaunch_command']('demo-plan', "
        + repr(str(workspace))
        + ", 'demo')",
    ]
    result = _run_embedded_python("\n".join(harness_lines))
    assert result.returncode == 24, result.stderr
    assert "chain_runtime_binding_drift" in result.stderr, result.stderr
    assert (
        f"engine root mismatch: manifest={drifted_root.resolve()} "
        f"live={REPO_ROOT.resolve()}"
    ) in result.stderr, result.stderr


def test_cloud_discover_bound_chain_live_comparison_precedes_state_read(
    tmp_path: Path,
) -> None:
    """G5 (round-17 finding 1b): the bound-chain live-root comparison runs
    BEFORE the chain-state read — a live import root that disagrees with the
    manifest pin drifts on the manifest/live arm with ZERO chain-state reads
    (the missing state file is never even touched)."""
    text = _wrapper("arnold-cloud-discover")
    py_start = text.index("<<'PY'\n") + len("<<'PY'\n")
    py_end = text.index("\nPY\n", py_start)
    program = text[py_start:py_end]
    drifted_root = tmp_path / "drifted-runtime"
    manifest_path = _write_runtime_manifest(tmp_path, runtime_root=drifted_root)
    workspace = tmp_path / "ws"
    harness_lines = [
        "import subprocess, sys, types",
        "sys.argv = ['_cloud_discover', "
        + repr(str(tmp_path))
        + ", "
        + repr(str(drifted_root))
        + "]",
        "import os",
        "os.environ['ARNOLD_RUNTIME_MANIFEST'] = "
        + repr(str(manifest_path)),
        "_fake = types.SimpleNamespace("
        "returncode=0, stdout='', stderr='', pid=0, args=[])",
        "subprocess.run = lambda *a, **k: _fake",
        "ns = {'os': os}",
        "exec(compile("
        + repr(program)
        + ", 'cloud-discover', 'exec'), ns)",
        "ns['_chain_relaunch_command']('origin/main', "
        + repr(str(workspace))
        + ", 'demo')",
    ]
    result = _run_embedded_python("\n".join(harness_lines))
    assert result.returncode == 24, result.stderr
    assert "chain_runtime_binding_drift" in result.stderr, result.stderr
    assert (
        f"engine root mismatch: manifest={drifted_root.resolve()} "
        f"live={REPO_ROOT.resolve()}"
    ) in result.stderr, result.stderr
    # The drift is on the live arm, NOT a chain-state failure: the state
    # read never ran.
    assert "chain state" not in result.stderr, result.stderr


@pytest.mark.parametrize("wrapper_kind", ["watchdog"])
def test_watchdog_relaunch_commands_bind_only_accepted_root_on_pythonpath(
    tmp_path: Path,
    wrapper_kind: str,
) -> None:
    """G5 round-6 finding 2 (watchdog) / round-7 finding 2 (repair-loop): every
    generated relaunch command uses PYTHONPATH=<accepted root> ONLY.  The
    inherited ``:${PYTHONPATH:-}`` append is gone, so an ambient shared-root
    PYTHONPATH cannot leak into the launched python process."""
    functions = "\n\n".join(_extract_relaunch_functions(wrapper_kind))
    ws = tmp_path / "ws"
    ws.mkdir()
    # G5 (round-17 finding 1c): the watchdog preflight compares against the
    # real import root, so the watchdog half pins the manifest/recorded root
    # to the live import root itself (REPO_ROOT); the repair half keeps its
    # own tmp runtime.
    runtime_root = (
        REPO_ROOT
        if wrapper_kind == "watchdog"
        else (tmp_path / "runtime")
    )
    if wrapper_kind == "repair":
        _init_git_repo(runtime_root)
    _bound_chain_state(ws, "origin/main", runtime_root)
    outputs = {
        "default_plan_relaunch": tmp_path / "plan-auto.sh",
        "resume_plan_relaunch": tmp_path / "plan-resume.sh",
        "default_chain_relaunch": tmp_path / "chain-start.sh",
    }
    script = "\n\n".join(
        [
            functions,
            "SRC_DIR=" + repr(str(runtime_root)),
            *(
                [f"ARNOLD_SRC={str(runtime_root)!r}"]
                if wrapper_kind == "repair"
                else []
            ),
            "MANIFEST_RUNTIME_ROOT=" + repr(str(runtime_root)),
            "LIVE_IMPORT_ROOT=" + repr(str(runtime_root)),
            "PYTHONPATH=" + repr(str(REPO_ROOT)),
            "SYNC_BRANCH=editable-install",
            (
                    f'default_plan_relaunch_command "demo-plan" {str(ws)!r} "demo-plan" '
                f"> {shlex.quote(str(outputs['default_plan_relaunch']))} || exit $?"
            ),
            (
                    f'resume_plan_relaunch_command "demo-plan" {str(ws)!r} "demo-plan" '
                f"> {shlex.quote(str(outputs['resume_plan_relaunch']))} || exit $?"
            ),
            (
                f'default_chain_relaunch_command "demo-sess" {str(ws)!r} "origin/main" '
                f"> {shlex.quote(str(outputs['default_chain_relaunch']))} || exit $?"
            ),
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    for label, path in outputs.items():
        generated = path.read_text(encoding="utf-8")
        assert ":${PYTHONPATH:-}" not in generated, label
        if label == "default_chain_relaunch":
            _assert_manifest_bound_chain_relaunch(generated, runtime_root)
        else:
            assert f"PYTHONPATH={runtime_root}" in generated, label
            # The accepted root is the ONLY PYTHONPATH entry: no colon-joined
            # merge with any inherited value.
            assert f"PYTHONPATH={runtime_root}:" not in generated, label


@pytest.mark.parametrize("wrapper_kind", ["watchdog"])
def test_watchdog_relaunch_launch_ignores_poisoned_shared_root_pythonpath(
    tmp_path: Path,
    wrapper_kind: str,
) -> None:
    """G5 round-6 finding 2 (watchdog) / round-7 finding 2 (repair-loop):
    executing a generated relaunch command with a poisoned shared-root
    PYTHONPATH still launches python with ONLY the accepted root on
    PYTHONPATH — the generated assignment never merges the inherited value."""
    functions = "\n\n".join(_extract_relaunch_functions(wrapper_kind))
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / ".megaplan" / "cloud-logs").mkdir(parents=True, exist_ok=True)
    # G5 (round-17 finding 1c): the watchdog preflight compares against the
    # real import root, so the watchdog half pins the manifest/recorded root
    # to the live import root itself (REPO_ROOT); the repair half keeps its
    # own tmp runtime.
    runtime_root = (
        REPO_ROOT
        if wrapper_kind == "watchdog"
        else (tmp_path / "runtime")
    )
    if wrapper_kind == "repair":
        _init_git_repo(runtime_root)
    _bound_chain_state(ws, "origin/main", runtime_root)
    plan_out = tmp_path / "plan-auto.sh"
    script = "\n\n".join(
        [
            functions,
            "SRC_DIR=" + repr(str(runtime_root)),
            *(
                [f"ARNOLD_SRC={str(runtime_root)!r}"]
                if wrapper_kind == "repair"
                else []
            ),
            "MANIFEST_RUNTIME_ROOT=" + repr(str(runtime_root)),
            "LIVE_IMPORT_ROOT=" + repr(str(runtime_root)),
            "PYTHONPATH=" + repr(str(REPO_ROOT)),
            "SYNC_BRANCH=editable-install",
            (
                    f'default_plan_relaunch_command "demo-plan" {str(ws)!r} "demo-plan" '
                f"> {shlex.quote(str(plan_out))} || exit $?"
            ),
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    relaunch = plan_out.read_text(encoding="utf-8")
    assert ":${PYTHONPATH:-}" not in relaunch

    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    capture = tmp_path / "capture.txt"
    shim = shim_dir / "python3"
    shim.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$PYTHONPATH" >> {shlex.quote(str(capture))}\n'
        "exit 0\n",
        encoding="utf-8",
    )
    shim.chmod(0o755)
    launched = subprocess.run(
        ["bash", "-c", relaunch],
        capture_output=True,
        text=True,
        check=False,
        env={
            **os.environ,
            "PATH": f"{shim_dir}:{os.environ['PATH']}",
            "PYTHONPATH": "/workspace/arnold",
        },
    )
    assert launched.returncode == 0, launched.stderr
    recorded = capture.read_text(encoding="utf-8").splitlines()
    assert recorded, "no python launch was observed"
    assert recorded == [str(runtime_root)] * len(recorded)


# ── Step 55-58: child-agent launch authority gates ─────────────────────────

# Watchdog child-agent launches (repair-loop, meta-repair, managed-agent, and
# Kimi families) may NEVER become accepted repair outside canonical
# simple_fixer delegation.  Authority is never derived from a label, a
# liveness signal, a WBC receipt, or a rebuildable projection (SC38).

_CHILD_AGENT_GATE_FORBIDDEN_VARS = (
    "ARNOLD_REPAIR_AUTHORITY_LABEL",
    "ARNOLD_REPAIR_LIVENESS_RECEIPT",
    "ARNOLD_REPAIR_WBC_RECEIPT",
    "ARNOLD_REPAIR_REBUILDABLE_PROJECTION",
)

_VALID_F01_OCCURRENCE = {
    "environment": "cloud",
    "session": "demo-session",
    "chain": "origin/main",
    "plan_revision": "rev-1",
    "phase": "build",
    "task": "T38",
    "attempt": "1",
    "normalized_failure_kind": "test_failure",
    "blocker_or_phase_result_hash": "phase-result-hash-1",
    "fence": "fence-1",
}


def _run_child_agent_gate(
    env_overrides: dict[str, str] | None = None,
    *,
    caller_kind: str = "live_watchdog",
    caller_id: str = "arnold-watchdog",
) -> dict[str, object]:
    """Extract and execute the watchdog child-agent launch authority gate.

    The gate classifies a watchdog child-agent launch (repair-loop, meta-repair,
    managed-agent, or Kimi family) and emits JSON with an ``outcome`` key in
    ``{zero_authority_rejected, delegated, no_authority_claim}``.
    """
    func = _extract_wrapper_function("child_agent_launch_authority_or_reject")
    unset_lines = "\n".join(
        ["unset ARNOLD_REPAIR_F01_OCCURRENCE"]
        + [f"unset {name}" for name in _CHILD_AGENT_GATE_FORBIDDEN_VARS]
    )
    export_lines = "\n".join(
        f"export {name}={shlex.quote(value)}"
        for name, value in (env_overrides or {}).items()
    )
    script = "\n".join(
        [
            func,
            "WRAPPER_REPO_ROOT=" + shlex.quote(str(REPO_ROOT)),
            unset_lines,
            export_lines,
            f"child_agent_launch_authority_or_reject {caller_kind} {caller_id}",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip())


def _assert_child_agent_launch_never_authorizes_forbidden_sources() -> None:
    """Shared SC38 behavioural proof: a forbidden authority source (label,
    liveness signal, WBC receipt, or rebuildable projection) may NEVER produce
    a delegated child-agent launch.  Only an exact, complete F01 occurrence
    tuple can delegate, and even then with no child-agent fan-out."""
    canonical = "simple_fixer.singleton_claim.exact_f01_tuple"

    # Each forbidden source alone rejects with zero authority and no fan-out.
    for name in _CHILD_AGENT_GATE_FORBIDDEN_VARS:
        gate = _run_child_agent_gate({name: "forbidden-source-value"})
        assert gate["outcome"] == "zero_authority_rejected", (name, gate)
        assert gate["delegated"] is False, (name, gate)
        assert gate["child_agent_fanout"] is False, (name, gate)
        assert gate["canonical_delegation_path"] == canonical, (name, gate)

    # A forbidden source combined with a valid F01 tuple still rejects — the
    # forbidden authority source wins over any rebuildable projection.
    gate = _run_child_agent_gate(
        {
            "ARNOLD_REPAIR_LIVENESS_RECEIPT": "liveness-receipt",
            "ARNOLD_REPAIR_F01_OCCURRENCE": json.dumps(_VALID_F01_OCCURRENCE),
        }
    )
    assert gate["outcome"] == "zero_authority_rejected", gate
    assert gate["delegated"] is False, gate

    # A partial F01 tuple (a rebuildable projection) cannot delegate.
    gate = _run_child_agent_gate(
        {"ARNOLD_REPAIR_F01_OCCURRENCE": json.dumps({"environment": "cloud", "session": ""})}
    )
    assert gate["outcome"] == "zero_authority_rejected", gate
    assert gate["delegated"] is False, gate

    # With no authority claim at all the launch is a typed no-claim (neither
    # delegated nor fan-out), never silently authorized.
    gate = _run_child_agent_gate()
    assert gate["outcome"] == "no_authority_claim", gate
    assert gate["delegated"] is False, gate
    assert gate["child_agent_fanout"] is False, gate
    assert gate["canonical_delegation_path"] == canonical, gate

    # Only an exact, complete F01 occurrence tuple delegates, through the
    # canonical singleton-claim path, with no child-agent fan-out.
    gate = _run_child_agent_gate(
        {"ARNOLD_REPAIR_F01_OCCURRENCE": json.dumps(_VALID_F01_OCCURRENCE)}
    )
    assert gate["outcome"] == "delegated", gate
    assert gate["delegated"] is True, gate
    assert gate["child_agent_fanout"] is False, gate
    assert gate["canonical_delegation_path"] == canonical, gate
    assert isinstance(gate.get("occurrence_fingerprint"), str)
    assert gate["occurrence_fingerprint"], gate


def test_watchdog_managed_agent_launch_rejected_or_delegated() -> None:
    """Step 57: the watchdog managed-agent launch (Codex editable-install
    repair) may NEVER become accepted repair outside canonical simple_fixer
    delegation.  Authority is never derived from a label, liveness signal, WBC
    receipt, or rebuildable projection (SC38)."""
    text = _wrapper("arnold-watchdog")
    assert "Step 57: managed-agent launches may NEVER become accepted" in text
    assert "T57-MANAGED-AGENT-FANOUT-01" in text
    assert (
        '"$(child_agent_launch_authority_or_reject live_watchdog arnold-watchdog)"'
        in text
    )
    _assert_child_agent_launch_never_authorizes_forbidden_sources()


def test_verify_relaunch_health_rejects_tmux_only_false_success() -> None:
    script = "\n\n".join(
        [
            _extract_wrapper_function("verify_relaunch_health"),
            """
checks=0
session_health_status() {
  checks=$((checks + 1))
  printf '%s\n' stopped
}
sleep() { :; }
verify_relaunch_health demo /workspace/demo /workspace/demo/chain.yaml chain '' 2
""".strip(),
        ]
    )

    result = _run_watchdog_shell(script)

    assert result.returncode == 1
    assert result.stdout.strip() == "stopped"


def test_verify_relaunch_health_fails_fast_on_launch_log_failure() -> None:
    script = "\n\n".join(
        [
            _extract_wrapper_function("verify_relaunch_health"),
            """
session_health_status() { printf '%s\n' chain_log_failure; }
sleep() { printf '%s\n' unexpected-sleep >&2; }
verify_relaunch_health demo /workspace/demo /workspace/demo/chain.yaml chain '' 15
""".strip(),
        ]
    )

    result = _run_watchdog_shell(script)

    assert result.returncode == 1
    assert result.stdout.strip() == "chain_log_failure"
    assert "unexpected-sleep" not in result.stderr


def test_supervise_exhaustion_queues_repair_request() -> None:
    text = _wrapper("arnold-supervise")
    helper = (REPO_ROOT / "arnold_pipelines/megaplan/cloud/supervise.py").read_text(
        encoding="utf-8"
    )

    assert "queue_repair_request()" in text
    assert "enqueue_supervisor_repair_request" in text
def test_supervise_exhaustion_queues_repair_request() -> None:
    text = _wrapper("arnold-supervise")
    assert "queue_repair_request" in text
    assert "exit_with_repair_request" in text
    assert "SUPERVISE_SESSION" in text
    assert "SUPERVISE_WORKSPACE" in text
    assert "SUPERVISE_REMOTE_SPEC" in text


def test_watchdog_reports_markerless_bootstrap_tmux_without_adopting_it(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    workspace_root = tmp_path / "workspace-root"
    workspace = workspace_root / "test-watchdog-vibecomfy-per-workflow-window-chat-20260628"
    (workspace / ".megaplan" / "plans" / "per-workflow-window-chat-cloud-20260628").mkdir(parents=True, exist_ok=True)

    tmux_path = tmp_path / "tmux"
    tmux_path.write_text(
        "#!/usr/bin/env bash\n"
        "cat <<'EOF'\n"
        f"vibecomfy-per-workflow-window-chat\t4000\t{workspace}\t"
        "cd "
        f"{workspace}"
        " && MEGAPLAN_TRUSTED_CONTAINER=1 python3 -m arnold_pipelines.megaplan init "
        "--project-dir . --idea-file .megaplan/initiatives/per-workflow-window-chat/briefs/per-workflow-window-chat.md "
        "--name per-workflow-window-chat-cloud-20260628 --auto-start\n"
        "EOF\n",
        encoding="utf-8",
    )
    tmux_path.chmod(tmux_path.stat().st_mode | stat.S_IXUSR)

    ps_path = tmp_path / "ps"
    ps_path.write_text(
        "#!/usr/bin/env bash\n"
        "cat <<'EOF'\n"
        "4000 1 bash -lc bootstrap\n"
        "4001 4000 /root/.pyenv/versions/3.11.11/bin/python3 -m arnold_pipelines.megaplan init "
        "--project-dir . --idea-file .megaplan/initiatives/per-workflow-window-chat/briefs/per-workflow-window-chat.md "
        "--name per-workflow-window-chat-cloud-20260628 --auto-start\n"
        "4002 4001 /root/.pyenv/versions/3.11.11/bin/python3 -m arnold_pipelines.megaplan critique "
        "--plan per-workflow-window-chat-cloud-20260628\n"
        "EOF\n",
        encoding="utf-8",
    )
    ps_path.chmod(ps_path.stat().st_mode | stat.S_IXUSR)

    manifest_path = tmp_path / "runtime-manifest.json"
    manifest = _make_authoritative_manifest()
    manifest["epic"]["runtime_root"] = str(REPO_ROOT)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    script = "\n\n".join(
        [
            _extract_wrapper_function("adopt_unmarked_tmux_sessions"),
            f"MARKER_DIR={str(marker_dir)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            f"DISCOVER_BIN={str(WRAPPER_DIR / 'arnold-cloud-discover')!r}",
            f"export MEGAPLAN_DISCOVER_WORKSPACE_ROOT={str(workspace_root)!r}",
            f"export ARNOLD_RUNTIME_MANIFEST={str(manifest_path)!r}",
            "adopt_unmarked_tmux_sessions",
        ]
    )
    result = _run_watchdog_shell(script, path_prefix=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "vibecomfy-per-workflow-window-chat" in result.stdout

    marker_path = marker_dir / "vibecomfy-per-workflow-window-chat.json"
    assert not marker_path.exists()


def test_watchdog_does_not_adopt_non_arnold_tmux_sessions(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    workspace_root = tmp_path / "workspace-root"
    workspace = workspace_root / "test-watchdog-random-workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    tmux_path = tmp_path / "tmux"
    tmux_path.write_text(
        "#!/usr/bin/env bash\n"
        "cat <<'EOF'\n"
        f"scratch\t5000\t{workspace}\tbash -lc 'python3 -m http.server 8080'\n"
        "EOF\n",
        encoding="utf-8",
    )
    tmux_path.chmod(tmux_path.stat().st_mode | stat.S_IXUSR)

    ps_path = tmp_path / "ps"
    ps_path.write_text(
        "#!/usr/bin/env bash\n"
        "cat <<'EOF'\n"
        "5000 1 bash -lc python3 -m http.server 8080\n"
        "5001 5000 python3 -m http.server 8080\n"
        "EOF\n",
        encoding="utf-8",
    )
    ps_path.chmod(ps_path.stat().st_mode | stat.S_IXUSR)

    script = "\n\n".join(
        [
            _extract_wrapper_function("adopt_unmarked_tmux_sessions"),
            f"MARKER_DIR={str(marker_dir)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            f"DISCOVER_BIN={str(WRAPPER_DIR / 'arnold-cloud-discover')!r}",
            f"export MEGAPLAN_DISCOVER_WORKSPACE_ROOT={str(workspace_root)!r}",
            "adopt_unmarked_tmux_sessions",
        ]
    )
    result = _run_watchdog_shell(script, path_prefix=tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ""
    assert not marker_dir.exists()


def test_shared_cloud_discover_finds_markerless_arnold_tmux_session_and_skips_supervisors(
    tmp_path: Path,
) -> None:
    marker_dir = tmp_path / "markers"
    workspace_root = tmp_path / "workspace-root"
    workspace = workspace_root / "test-shared-discover-vibecomfy"
    (workspace / ".megaplan" / "plans" / "shared-discover-plan").mkdir(parents=True, exist_ok=True)

    tmux_path = tmp_path / "tmux"
    tmux_path.write_text(
        "#!/usr/bin/env bash\n"
        "cat <<'EOF'\n"
        f"vibecomfy-shared-discover\t4000\t{workspace}\t"
        "cd "
        f"{workspace}"
        " && python3 -m arnold_pipelines.megaplan init --project-dir . "
        "--idea-file .megaplan/initiatives/shared/briefs/shared.md --name shared-discover-plan --auto-start\n"
        f"watchdog-demo\t5000\t{workspace}\tbash -lc '/usr/local/bin/arnold-watchdog --once'\n"
        f"kimi-helper\t6000\t{workspace}\tbash -lc '/usr/local/bin/arnold-kimi-goal-operator demo'\n"
        "EOF\n",
        encoding="utf-8",
    )
    tmux_path.chmod(tmux_path.stat().st_mode | stat.S_IXUSR)

    ps_path = tmp_path / "ps"
    ps_path.write_text(
        "#!/usr/bin/env bash\n"
        "cat <<'EOF'\n"
        "4000 1 bash -lc bootstrap\n"
        "4001 4000 python3 -m arnold_pipelines.megaplan init --project-dir . "
        "--idea-file .megaplan/initiatives/shared/briefs/shared.md --name shared-discover-plan --auto-start\n"
        "5000 1 bash -lc /usr/local/bin/arnold-watchdog --once\n"
        "6000 1 bash -lc /usr/local/bin/arnold-kimi-goal-operator demo\n"
        "EOF\n",
        encoding="utf-8",
    )
    ps_path.chmod(ps_path.stat().st_mode | stat.S_IXUSR)

    result = _run_discover(tmp_path, marker_dir=marker_dir)
    assert result.returncode == 0, result.stderr
    lines = [line for line in result.stdout.strip().splitlines() if line]
    assert len(lines) == 1
    fields = lines[0].split("\t")
    assert fields[0] == "vibecomfy-shared-discover"
    assert fields[1] == str(workspace)
    assert fields[2] == ".megaplan/initiatives/shared/briefs/shared.md"
    assert fields[3] == "plan"
    assert fields[4] == "shared-discover-plan"
    assert "python3 -P -m arnold_pipelines.megaplan auto --plan shared-discover-plan" in fields[5]


def test_watchdog_plan_markers_relaunch_with_auto_not_chain_start(tmp_path: Path) -> None:
    script = "\n\n".join(
        [
            *_extract_relaunch_functions("watchdog"),
            f"SRC_DIR={str(REPO_ROOT)!r}",
            f"MANIFEST_RUNTIME_ROOT={str(REPO_ROOT)!r}",
            "LIVE_IMPORT_ROOT=" + repr(str(REPO_ROOT)),
            "SYNC_BRANCH=editible-install",
            "resolve_relaunch_command demo-session /tmp/workspace /tmp/not-a-chain.yaml plan demo-plan ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert "python3 -P -m arnold_pipelines.megaplan auto --plan demo-plan" in result.stdout
    assert "chain start" not in result.stdout


def test_watchdog_stale_marker_relaunch_command_regenerates_clean_runtime_chain_command(
    tmp_path: Path,
) -> None:
    stale_command = (
        "{ set -e\n"
        "if [ -n \"$(git -C \"$SRC\" status --porcelain --untracked-files=no)\" ]; then\n"
        "  echo \"[megaplan-refresh] refusing editable install refresh: tracked changes in source checkout at $SRC\"\n"
        "  exit 19\n"
        "fi\n"
        "} >> .megaplan/cloud-chain-progress-auditor-stage-metrics.log 2>&1 && "
        "cd /workspace/progress-auditor-stage-metrics/Arnold && "
        "PYTHONPATH=/workspace/arnold:${PYTHONPATH:-} python -P -m arnold_pipelines.megaplan chain start"
    )
    workspace = tmp_path / "Arnold"
    spec = workspace / ".megaplan" / "initiatives" / "progress-auditor-stage-metrics" / "chain.yaml"
    # G5 (round-17 finding 1c): the preflight compares against the real
    # import root, so the manifest pin and recorded engine root must be the
    # live import root itself.
    runtime_root = REPO_ROOT
    _write_runtime_bound_chain_state(workspace, spec, runtime_root)
    script = "\n\n".join(
        [
            *_extract_relaunch_functions("watchdog"),
            f"SRC_DIR={str(runtime_root)!r}",
            f"MANIFEST_RUNTIME_ROOT={str(runtime_root)!r}",
            f"LIVE_IMPORT_ROOT={str(runtime_root)!r}",
            "PYTHONPATH=" + repr(str(REPO_ROOT)),
            "SYNC_BRANCH=editible-install",
            (
                f"resolve_relaunch_command progress-auditor-stage-metrics {str(workspace)!r} "
                f"{str(spec)!r} chain '' {shlex.quote(stale_command)}"
            ),
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    # P4: the editable-install refresh machinery is deleted; a stale refresh-era
    # marker regenerates the manifest-runtime chain start (no source checkout
    # mutation, no env-selector re-resolution).  T-0022: the regenerated
    # command passes ONLY the preflight-accepted engine root to the launch
    # boundary, which owns runtime environment materialization.
    assert "python3 -P -m arnold_pipelines.megaplan chain start" in result.stdout
    assert "chain start --spec" in result.stdout
    _assert_manifest_bound_chain_relaunch(result.stdout, runtime_root)
    assert "MEGAPLAN_RUNTIME_SRC" not in result.stdout
    assert "editable-engine" not in result.stdout
    assert "refusing editable install refresh: tracked changes in source checkout" not in result.stdout
    assert "source checkout dirty" not in result.stdout


def test_watchdog_nonstale_marker_relaunch_command_is_preserved() -> None:
    workspace = Path("/tmp/workspace")
    runtime_root = REPO_ROOT
    _write_runtime_bound_chain_state(workspace, "/tmp/chain.yaml", runtime_root)
    script = "\n\n".join(
        [
            *_extract_relaunch_functions("watchdog"),
            f"SRC_DIR={str(runtime_root)!r}",
            f"MANIFEST_RUNTIME_ROOT={str(runtime_root)!r}",
            "LIVE_IMPORT_ROOT=" + repr(str(runtime_root)),
            "SYNC_BRANCH=editible-install",
            "resolve_relaunch_command demo-session /tmp/workspace /tmp/chain.yaml chain '' 'echo marker-command'",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "echo marker-command"


@pytest.mark.parametrize("wrapper_kind", ["watchdog"])
def test_chain_resume_authority_outranks_marker_command_and_discovers_plan(
    tmp_path: Path,
    wrapper_kind: str,
) -> None:
    workspace = tmp_path / "workspace"
    spec_path = workspace / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    spec_path.parent.mkdir(parents=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    plan_name = "resume-required-plan"
    plan_dir = workspace / ".megaplan" / "plans" / plan_name
    plan_dir.mkdir(parents=True)
    (plan_dir / "state.json").write_text(
        json.dumps(
            {
                "current_state": "blocked",
                "resume_cursor": {
                    "phase": "plan",
                    "retry_strategy": "check_provider_and_retry",
                },
                "latest_failure": {
                    "kind": "external_error_resume_required",
                    "phase": "recover-blocked",
                },
            }
        ),
        encoding="utf-8",
    )
    _write_runtime_bound_chain_state(
        workspace,
        spec_path,
        REPO_ROOT,
        plan_name=plan_name,
    )

    source_var = "SRC_DIR" if wrapper_kind == "watchdog" else "ARNOLD_SRC"
    script = "\n\n".join(
        [
            *_extract_relaunch_functions(wrapper_kind),
            f"{source_var}={str(REPO_ROOT)!r}",
            f"MANIFEST_RUNTIME_ROOT={str(REPO_ROOT)!r}",
            f"LIVE_IMPORT_ROOT={str(REPO_ROOT)!r}",
            "SYNC_BRANCH=editible-install",
            (
                f"resolve_relaunch_command demo-session {str(workspace)!r} "
                f"{str(spec_path)!r} chain '' 'echo marker-chain-start'"
            ),
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert f"megaplan resume --plan {plan_name}" in result.stdout
    assert "marker-chain-start" not in result.stdout


@pytest.mark.parametrize("wrapper_kind", ["watchdog"])
def test_persisted_push_capable_marker_command_is_always_regenerated(
    tmp_path: Path,
    wrapper_kind: str,
) -> None:
    stale_command = (
        "echo '[megaplan-refresh] refusing editable install refresh:'; "
        "echo 'source checkout dirty; using clean runtime mirror'; "
        "echo 'source checkout has local commits not contained in origin/$REF; attempting push'; "
        "git -C \"$SRC\" push origin \"$REF\"; "
        "git -C \"$MEGAPLAN_RUNTIME_SRC\" merge-base --is-ancestor HEAD \"origin/$REF\""
    )
    workspace = tmp_path / "workspace"
    spec = workspace / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    # G5 (round-17 finding 1c): the watchdog preflight compares against the
    # real import root, so the watchdog half pins the manifest/recorded root
    # to the live import root itself (REPO_ROOT); the repair half keeps its
    # own tmp runtime.
    runtime_root = (
        REPO_ROOT
        if wrapper_kind == "watchdog"
        else _relaunch_runtime_root(tmp_path)
    )
    _write_runtime_bound_chain_state(workspace, spec, runtime_root)
    extract = _extract_wrapper_function
    source_var = "SRC_DIR" if wrapper_kind == "watchdog" else "ARNOLD_SRC"
    script = "\n\n".join(
        [
            extract("chain_engine_root_preflight"),
            extract("default_plan_relaunch_command"),
            extract("resume_plan_relaunch_command"),
            extract("chain_resume_plan_relaunch_command_if_needed"),
            extract("stale_marker_relaunch_command"),
            extract("default_chain_relaunch_command"),
            extract("resolve_relaunch_command"),
            f"{source_var}={str(runtime_root)!r}",
            f"MANIFEST_RUNTIME_ROOT={str(runtime_root)!r}",
            f"LIVE_IMPORT_ROOT={str(runtime_root)!r}",
            "PYTHONPATH=" + repr(str(REPO_ROOT)),
            *(
                [f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}"]
                if wrapper_kind == "repair"
                else []
            ),
            "SYNC_BRANCH=editible-install",
            (
                f"resolve_relaunch_command demo-session {str(workspace)!r} "
                f"{str(spec)!r} chain '' {shlex.quote(stale_command)}"
            ),
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    # P4: a push-capable (refresh-era) marker is regenerated as the
    # manifest-runtime chain start; the stale selector/refresh machinery is
    # gone from the emitted command.  T-0022: only the preflight-accepted
    # engine root is passed to the launch boundary, which owns runtime
    # environment materialization.
    assert "python3 -P -m arnold_pipelines.megaplan chain start" in result.stdout
    assert "chain start --spec" in result.stdout
    _assert_manifest_bound_chain_relaunch(result.stdout, runtime_root)
    assert "MEGAPLAN_RUNTIME_SRC" not in result.stdout
    assert "source checkout dirty" not in result.stdout
    assert "attempting push" not in result.stdout
    assert 'git -C "$SRC" push origin' not in result.stdout


@pytest.mark.parametrize("wrapper_kind", ["watchdog"])
def test_persisted_install_capable_marker_command_is_always_regenerated(
    tmp_path: Path,
    wrapper_kind: str,
) -> None:
    persisted_command = (
        "pip install -e /tmp/unbound-runtime && "
        "touch /tmp/unbound-runtime-was-selected"
    )
    workspace = tmp_path / "workspace"
    spec = workspace / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    # G5 (round-17 finding 1c): the watchdog preflight compares against the
    # real import root, so the watchdog half pins the manifest/recorded root
    # to the live import root itself (REPO_ROOT); the repair half keeps its
    # own tmp runtime.
    runtime_root = (
        REPO_ROOT
        if wrapper_kind == "watchdog"
        else _relaunch_runtime_root(tmp_path)
    )
    _write_runtime_bound_chain_state(workspace, spec, runtime_root)
    extract = _extract_wrapper_function
    source_var = "SRC_DIR" if wrapper_kind == "watchdog" else "ARNOLD_SRC"
    script = "\n\n".join(
        [
            extract("chain_engine_root_preflight"),
            extract("default_plan_relaunch_command"),
            extract("resume_plan_relaunch_command"),
            extract("chain_resume_plan_relaunch_command_if_needed"),
            extract("stale_marker_relaunch_command"),
            extract("default_chain_relaunch_command"),
            extract("resolve_relaunch_command"),
            f"{source_var}={str(runtime_root)!r}",
            f"MANIFEST_RUNTIME_ROOT={str(runtime_root)!r}",
            f"LIVE_IMPORT_ROOT={str(runtime_root)!r}",
            "PYTHONPATH=" + repr(str(REPO_ROOT)),
            *(
                [f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}"]
                if wrapper_kind == "repair"
                else []
            ),
            "SYNC_BRANCH=editible-install",
            (
                f"resolve_relaunch_command demo-session {str(workspace)!r} "
                f"{str(spec)!r} chain '' {shlex.quote(persisted_command)}"
            ),
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert "python3 -P -m arnold_pipelines.megaplan chain start" in result.stdout
    _assert_manifest_bound_chain_relaunch(result.stdout, runtime_root)
    assert "/tmp/unbound-runtime" not in result.stdout


@pytest.mark.parametrize("wrapper_kind", ["watchdog"])
@pytest.mark.parametrize(
    "persisted_command",
    (
        "/workspace/arnold/bin/python -P -m arnold_pipelines.megaplan chain start --spec chain.yaml",
        "env ARNOLD_SRC=/workspace/arnold /workspace/arnold/bin/python -P -m arnold_pipelines.megaplan chain start",
    ),
)
def test_persisted_shared_root_invocation_marker_is_regenerated(
    tmp_path: Path,
    wrapper_kind: str,
    persisted_command: str,
) -> None:
    """G5 round-10 finding 2: both relaunch wrappers reject a persisted
    command that invokes a python/binary under the shared /workspace/arnold
    checkout (bare or env-prefixed) and regenerate the clean manifest-runtime
    chain start from the preflight-accepted root.
    """
    workspace = tmp_path / "workspace"
    spec = workspace / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    # G5 (round-17 finding 1c): the watchdog preflight compares against the
    # real import root, so the watchdog half pins the manifest/recorded root
    # to the live import root itself (REPO_ROOT); the repair half keeps its
    # own tmp runtime.
    runtime_root = (
        REPO_ROOT
        if wrapper_kind == "watchdog"
        else _relaunch_runtime_root(tmp_path)
    )
    _write_runtime_bound_chain_state(workspace, spec, runtime_root)
    extract = _extract_wrapper_function
    source_var = "SRC_DIR" if wrapper_kind == "watchdog" else "ARNOLD_SRC"
    script = "\n\n".join(
        [
            extract("chain_engine_root_preflight"),
            extract("default_plan_relaunch_command"),
            extract("resume_plan_relaunch_command"),
            extract("chain_resume_plan_relaunch_command_if_needed"),
            extract("stale_marker_relaunch_command"),
            extract("default_chain_relaunch_command"),
            extract("resolve_relaunch_command"),
            f"{source_var}={str(runtime_root)!r}",
            f"MANIFEST_RUNTIME_ROOT={str(runtime_root)!r}",
            f"LIVE_IMPORT_ROOT={str(runtime_root)!r}",
            "PYTHONPATH=" + repr(str(REPO_ROOT)),
            *(
                [f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}"]
                if wrapper_kind == "repair"
                else []
            ),
            "SYNC_BRANCH=editible-install",
            (
                f"resolve_relaunch_command demo-session {str(workspace)!r} "
                f"{str(spec)!r} chain '' {shlex.quote(persisted_command)}"
            ),
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    # The shared-root invocation is never returned verbatim; the accepted
    # The regenerated command delegates the accepted manifest root to the
    # launch boundary; it never returns the shared-root invocation.
    assert "python3 -P -m arnold_pipelines.megaplan chain start" in result.stdout
    assert "chain start --spec" in result.stdout
    _assert_manifest_bound_chain_relaunch(result.stdout, runtime_root)
    assert "/workspace/arnold" not in result.stdout


@pytest.mark.parametrize("wrapper_kind", ["watchdog"])
def test_persisted_per_epic_invocation_marker_is_preserved(
    tmp_path: Path,
    wrapper_kind: str,
) -> None:
    """G5 round-14 finding 1: a persisted command invoking a python from the
    ACCEPTED manifest root (a per-epic runtime) stays admissible and is
    returned unchanged by both relaunch wrappers.  (Rounds 10/11 admitted
    ANY per-epic path; round 14 tightened admission to the accepted root —
    a different per-epic runtime is regenerated, see
    test_persisted_foreign_per_epic_marker_command_is_regenerated.)
    """
    workspace = tmp_path / "workspace"
    spec = workspace / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    # G5 (round-17 finding 1c): the watchdog preflight compares against the
    # real import root, so the watchdog half pins the manifest/recorded root
    # to the live import root itself (REPO_ROOT); the repair half keeps its
    # own tmp runtime.
    runtime_root = (
        REPO_ROOT
        if wrapper_kind == "watchdog"
        else _relaunch_runtime_root(tmp_path)
    )
    _write_runtime_bound_chain_state(workspace, spec, runtime_root)
    persisted_command = (
        f"{runtime_root}/bin/python -P -m "
        "arnold_pipelines.megaplan chain start --spec chain.yaml"
    )
    extract = _extract_wrapper_function
    source_var = "SRC_DIR" if wrapper_kind == "watchdog" else "ARNOLD_SRC"
    script = "\n\n".join(
        [
            extract("chain_engine_root_preflight"),
            extract("default_plan_relaunch_command"),
            extract("resume_plan_relaunch_command"),
            extract("chain_resume_plan_relaunch_command_if_needed"),
            extract("stale_marker_relaunch_command"),
            extract("default_chain_relaunch_command"),
            extract("resolve_relaunch_command"),
            f"{source_var}={str(runtime_root)!r}",
            f"MANIFEST_RUNTIME_ROOT={str(runtime_root)!r}",
            f"LIVE_IMPORT_ROOT={str(runtime_root)!r}",
            "PYTHONPATH=" + repr(str(REPO_ROOT)),
            *(
                [f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}"]
                if wrapper_kind == "repair"
                else []
            ),
            "SYNC_BRANCH=editible-install",
            (
                f"resolve_relaunch_command demo-session {str(workspace)!r} "
                f"{str(spec)!r} chain '' {shlex.quote(persisted_command)}"
            ),
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert result.stdout == persisted_command


@pytest.mark.parametrize("wrapper_kind", ["watchdog"])
@pytest.mark.parametrize(
    "persisted_command",
    (
        "MEGAPLAN_RUNTIME_SRC=${MEGAPLAN_RUNTIME_SRC:-/workspace/arnold} "
        "python -P -m arnold_pipelines.megaplan chain start --spec chain.yaml",
        "cd ${MEGAPLAN_RUNTIME_SRC:=/workspace/arnold} && "
        "python -P -m arnold_pipelines.megaplan chain start --spec chain.yaml",
        "${MEGAPLAN_RUNTIME_SRC:+/workspace/arnold}/bin/python -P -m "
        "arnold_pipelines.megaplan chain start --spec chain.yaml",
    ),
)
def test_persisted_shared_root_param_expansion_marker_is_regenerated(
    tmp_path: Path,
    wrapper_kind: str,
    persisted_command: str,
) -> None:
    """G5 round-11 finding 2: both relaunch wrappers reject a persisted
    command that carries the shared /workspace/arnold root inside a shell
    parameter-expansion default/alternate (${VAR:-...}, ${VAR:=...},
    ${VAR:+...}) and regenerate the clean manifest-runtime chain start from
    the preflight-accepted root.
    """
    workspace = tmp_path / "workspace"
    spec = workspace / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    # G5 (round-17 finding 1c): the watchdog preflight compares against the
    # real import root, so the watchdog half pins the manifest/recorded root
    # to the live import root itself (REPO_ROOT); the repair half keeps its
    # own tmp runtime.
    runtime_root = (
        REPO_ROOT
        if wrapper_kind == "watchdog"
        else _relaunch_runtime_root(tmp_path)
    )
    _write_runtime_bound_chain_state(workspace, spec, runtime_root)
    extract = _extract_wrapper_function
    source_var = "SRC_DIR" if wrapper_kind == "watchdog" else "ARNOLD_SRC"
    script = "\n\n".join(
        [
            extract("chain_engine_root_preflight"),
            extract("default_plan_relaunch_command"),
            extract("resume_plan_relaunch_command"),
            extract("chain_resume_plan_relaunch_command_if_needed"),
            extract("stale_marker_relaunch_command"),
            extract("default_chain_relaunch_command"),
            extract("resolve_relaunch_command"),
            f"{source_var}={str(runtime_root)!r}",
            f"MANIFEST_RUNTIME_ROOT={str(runtime_root)!r}",
            f"LIVE_IMPORT_ROOT={str(runtime_root)!r}",
            "PYTHONPATH=" + repr(str(REPO_ROOT)),
            *(
                [f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}"]
                if wrapper_kind == "repair"
                else []
            ),
            "SYNC_BRANCH=editible-install",
            (
                f"resolve_relaunch_command demo-session {str(workspace)!r} "
                f"{str(spec)!r} chain '' {shlex.quote(persisted_command)}"
            ),
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    # The param-expansion shared root is never returned verbatim; the
    # The regenerated command delegates the accepted manifest root to the
    # launch boundary; it never returns the shared-root parameter expansion.
    assert "python3 -P -m arnold_pipelines.megaplan chain start" in result.stdout
    assert "chain start --spec" in result.stdout
    _assert_manifest_bound_chain_relaunch(result.stdout, runtime_root)
    assert "/workspace/arnold" not in result.stdout


@pytest.mark.parametrize("wrapper_kind", ["watchdog"])
def test_persisted_per_epic_param_expansion_marker_is_preserved(
    tmp_path: Path,
    wrapper_kind: str,
) -> None:
    """G5 round-14 finding 1: the ACCEPTED manifest root inside a parameter
    expansion is a legitimate per-epic runtime — a persisted command naming
    it stays admissible and is returned unchanged by both relaunch
    wrappers.  (Rounds 10/11 admitted ANY per-epic path; round 14 tightened
    admission to the accepted root.)
    """
    workspace = tmp_path / "workspace"
    spec = workspace / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    # G5 (round-17 finding 1c): the watchdog preflight compares against the
    # real import root, so the watchdog half pins the manifest/recorded root
    # to the live import root itself (REPO_ROOT); the repair half keeps its
    # own tmp runtime.
    runtime_root = (
        REPO_ROOT
        if wrapper_kind == "watchdog"
        else _relaunch_runtime_root(tmp_path)
    )
    _write_runtime_bound_chain_state(workspace, spec, runtime_root)
    persisted_command = (
        f"CHAIN_RUNTIME=${{CHAIN_RUNTIME:-{runtime_root}}} "
        "python -P -m arnold_pipelines.megaplan chain start --spec chain.yaml"
    )
    extract = _extract_wrapper_function
    source_var = "SRC_DIR" if wrapper_kind == "watchdog" else "ARNOLD_SRC"
    script = "\n\n".join(
        [
            extract("chain_engine_root_preflight"),
            extract("default_plan_relaunch_command"),
            extract("resume_plan_relaunch_command"),
            extract("chain_resume_plan_relaunch_command_if_needed"),
            extract("stale_marker_relaunch_command"),
            extract("default_chain_relaunch_command"),
            extract("resolve_relaunch_command"),
            f"{source_var}={str(runtime_root)!r}",
            f"MANIFEST_RUNTIME_ROOT={str(runtime_root)!r}",
            f"LIVE_IMPORT_ROOT={str(runtime_root)!r}",
            "PYTHONPATH=" + repr(str(REPO_ROOT)),
            *(
                [f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}"]
                if wrapper_kind == "repair"
                else []
            ),
            "SYNC_BRANCH=editible-install",
            (
                f"resolve_relaunch_command demo-session {str(workspace)!r} "
                f"{str(spec)!r} chain '' {shlex.quote(persisted_command)}"
            ),
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert result.stdout == persisted_command


@pytest.mark.parametrize("wrapper_kind", ["watchdog"])
@pytest.mark.parametrize(
    "persisted_command",
    (
        "PYTHONPATH=/workspace/runtime-candidates/arnold-old:${PYTHONPATH:-} "
        "python -P -m arnold_pipelines.megaplan chain start --spec chain.yaml",
        "cd /workspace/runtime-candidates/arnold-old && "
        "python -P -m arnold_pipelines.megaplan chain start --spec chain.yaml",
        "/workspace/runtime-candidates/arnold-old/bin/python -P -m "
        "arnold_pipelines.megaplan chain start --spec chain.yaml",
    ),
)
def test_persisted_foreign_per_epic_marker_command_is_regenerated(
    tmp_path: Path,
    wrapper_kind: str,
    persisted_command: str,
) -> None:
    """G5 round-14 finding 1: a persisted command referencing a per-epic
    runtime path OTHER than the accepted manifest root (here arnold-old
    while the accepted root is the tmp runtime) is never returned verbatim
    — both relaunch wrappers regenerate the clean manifest-runtime chain
    start from the preflight-accepted root.
    """
    workspace = tmp_path / "workspace"
    spec = workspace / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    # G5 (round-17 finding 1c): the watchdog preflight compares against the
    # real import root, so the watchdog half pins the manifest/recorded root
    # to the live import root itself (REPO_ROOT); the repair half keeps its
    # own tmp runtime.
    runtime_root = (
        REPO_ROOT
        if wrapper_kind == "watchdog"
        else _relaunch_runtime_root(tmp_path)
    )
    _write_runtime_bound_chain_state(workspace, spec, runtime_root)
    extract = _extract_wrapper_function
    source_var = "SRC_DIR" if wrapper_kind == "watchdog" else "ARNOLD_SRC"
    script = "\n\n".join(
        [
            extract("chain_engine_root_preflight"),
            extract("default_plan_relaunch_command"),
            extract("resume_plan_relaunch_command"),
            extract("chain_resume_plan_relaunch_command_if_needed"),
            extract("stale_marker_relaunch_command"),
            extract("default_chain_relaunch_command"),
            extract("resolve_relaunch_command"),
            f"{source_var}={str(runtime_root)!r}",
            f"MANIFEST_RUNTIME_ROOT={str(runtime_root)!r}",
            f"LIVE_IMPORT_ROOT={str(runtime_root)!r}",
            "PYTHONPATH=" + repr(str(REPO_ROOT)),
            *(
                [f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}"]
                if wrapper_kind == "repair"
                else []
            ),
            "SYNC_BRANCH=editible-install",
            (
                f"resolve_relaunch_command demo-session {str(workspace)!r} "
                f"{str(spec)!r} chain '' {shlex.quote(persisted_command)}"
            ),
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    # The foreign per-epic runtime is never returned verbatim; the accepted
    # The regenerated command delegates the accepted manifest root to the
    # launch boundary; it never returns the foreign runtime command.
    assert "python3 -P -m arnold_pipelines.megaplan chain start" in result.stdout
    assert "chain start --spec" in result.stdout
    _assert_manifest_bound_chain_relaunch(result.stdout, runtime_root)
    assert "/workspace/runtime-candidates/arnold-old" not in result.stdout


@pytest.mark.parametrize("wrapper_kind", ["watchdog"])
@pytest.mark.parametrize(
    "persisted_command_fmt",
    (
        "cd {root} && python -P -m arnold_pipelines.megaplan chain start --spec chain.yaml",
        "PYTHONPATH={root}:${{PYTHONPATH:-}} python -P -m arnold_pipelines.megaplan chain start --spec chain.yaml",
        "{root}/bin/python -P -m arnold_pipelines.megaplan chain start --spec chain.yaml",
    ),
)
def test_persisted_accepted_root_marker_command_is_preserved(
    tmp_path: Path,
    wrapper_kind: str,
    persisted_command_fmt: str,
) -> None:
    """G5 round-14 finding 1: a persisted command whose runtime-path
    references are the ACCEPTED manifest root stays admissible and is
    returned unchanged by both relaunch wrappers.
    """
    workspace = tmp_path / "workspace"
    spec = workspace / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    # G5 (round-17 finding 1c): the watchdog preflight compares against the
    # real import root, so the watchdog half pins the manifest/recorded root
    # to the live import root itself (REPO_ROOT); the repair half keeps its
    # own tmp runtime.
    runtime_root = (
        REPO_ROOT
        if wrapper_kind == "watchdog"
        else _relaunch_runtime_root(tmp_path)
    )
    _write_runtime_bound_chain_state(workspace, spec, runtime_root)
    persisted_command = persisted_command_fmt.format(root=runtime_root)
    extract = _extract_wrapper_function
    source_var = "SRC_DIR" if wrapper_kind == "watchdog" else "ARNOLD_SRC"
    script = "\n\n".join(
        [
            extract("chain_engine_root_preflight"),
            extract("default_plan_relaunch_command"),
            extract("resume_plan_relaunch_command"),
            extract("chain_resume_plan_relaunch_command_if_needed"),
            extract("stale_marker_relaunch_command"),
            extract("default_chain_relaunch_command"),
            extract("resolve_relaunch_command"),
            f"{source_var}={str(runtime_root)!r}",
            f"MANIFEST_RUNTIME_ROOT={str(runtime_root)!r}",
            f"LIVE_IMPORT_ROOT={str(runtime_root)!r}",
            "PYTHONPATH=" + repr(str(REPO_ROOT)),
            *(
                [f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}"]
                if wrapper_kind == "repair"
                else []
            ),
            "SYNC_BRANCH=editible-install",
            (
                f"resolve_relaunch_command demo-session {str(workspace)!r} "
                f"{str(spec)!r} chain '' {shlex.quote(persisted_command)}"
            ),
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert result.stdout == persisted_command


def test_watchdog_chain_relaunch_prefers_plan_resume_for_external_resume_required(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    plan_dir = workspace / ".megaplan" / "plans" / "demo-plan"
    plan_dir.mkdir(parents=True)
    (workspace / ".megaplan" / "cloud-logs").mkdir(parents=True)
    (plan_dir / "state.json").write_text(
        json.dumps(
            {
                "current_state": "blocked",
                "resume_cursor": {"phase": "plan", "retry_strategy": "check_provider_and_retry"},
                "latest_failure": {
                    "kind": "external_error_resume_required",
                    "phase": "recover-blocked",
                },
            }
        ),
        encoding="utf-8",
    )
    _write_runtime_bound_chain_state(workspace, "/tmp/chain.yaml", REPO_ROOT)
    script = "\n\n".join(
        [
            *_extract_relaunch_functions("watchdog"),
            f"SRC_DIR={str(REPO_ROOT)!r}",
            f"MANIFEST_RUNTIME_ROOT={str(REPO_ROOT)!r}",
            "LIVE_IMPORT_ROOT=" + repr(str(REPO_ROOT)),
            "SYNC_BRANCH=editible-install",
            (
                f"resolve_relaunch_command demo-session {shlex.quote(str(workspace))} "
                f"/tmp/chain.yaml chain demo-plan ''"
            ),
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert "python3 -P -m arnold_pipelines.megaplan resume --plan demo-plan" in result.stdout
    assert "chain start" not in result.stdout


def test_watchdog_done_plan_reports_complete_without_repair_or_relaunch(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    plan_name = "demo-plan"
    _write_plan(
        workspace / ".megaplan" / "plans" / plan_name,
        {"iteration": 1, "current_state": "done", "active_step": None},
        events_body="{}\n",
    )

    marker_path = marker_dir / "demo-session.json"
    marker_path.write_text("marker\n", encoding="utf-8")
    progress_path = marker_dir / f"{plan_name}.progress.json"
    progress_path.write_text("{}\n", encoding="utf-8")
    report_path = tmp_path / "report.tsv"

    script = "\n\n".join(
        [
            _extract_wrapper_function("kimi_dispatch_marker_path"),
            _extract_wrapper_function("kimi_pgid_path"),
            _extract_wrapper_function("session_marker_path"),
            _extract_wrapper_function("kimi_dispatch_marker_clear"),
            _extract_wrapper_function("clear_session_tracking_artifacts"),
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function("plan_terminal_status"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { :; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
kimi_operator_running() { return 1; }
kimi_dispatch_marker_set() { :; }
mechanical_relaunch_attempted_previously() { return 1; }
kimi_dispatch_failed_previously() { return 1; }
dispatch_kimi_repair() { echo DISPATCH >&2; return 0; }
repair_unhealthy_session() { echo REPAIR >&2; return 0; }
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH; }
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
plan_attention_status_env() {
  cat <<'EOF'
PLAN_STATUS_FOUND='1'
PLAN_STATUS_PLAN_NAME='demo-plan'
PLAN_STATUS_CURRENT_STATE=''
PLAN_STATUS_RETRY_STRATEGY=''
PLAN_STATUS_FAILURE_KIND=''
PLAN_STATUS_FAILURE_MESSAGE=''
PLAN_STATUS_FAILURE_PHASE=''
PLAN_STATUS_FAILURE_RECORDED_AT=''
PLAN_STATUS_TIERS_TRIED=''
PLAN_STATUS_PUSHED_COMMITS=''
PLAN_STATUS_MANUAL_REVIEW='0'
EOF
}
""".strip(),
            f"launch_chain_tick demo-session {str(workspace)!r} .megaplan/initiatives/demo/briefs/demo.md {str(report_path)!r} chain {plan_name!r} ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert marker_path.exists()
    assert progress_path.exists()
    report = report_path.read_text(encoding="utf-8")
    assert "\tobserve\tcomplete\tplan complete\t" in report
    assert "BABYSITTER" not in result.stderr
    assert "REPAIR" not in result.stderr
    assert "TMUX" not in result.stderr


def test_watchdog_done_plan_without_marker_plan_name_uses_newest_plan_dir(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    older_plan = workspace / ".megaplan" / "plans" / "older-plan"
    newer_plan = workspace / ".megaplan" / "plans" / "newer-plan"
    _write_plan(older_plan, {"iteration": 1, "current_state": "planning", "active_step": None})
    _write_plan(newer_plan, {"iteration": 1, "current_state": "done", "active_step": None})
    old_ts = time.time() - 60
    new_ts = time.time()
    os.utime(older_plan / "state.json", (old_ts, old_ts))
    os.utime(newer_plan / "state.json", (new_ts, new_ts))
    report_path = tmp_path / "report.tsv"

    script = "\n\n".join(
        [
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function("plan_terminal_status"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { :; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
kimi_operator_running() { return 1; }
kimi_dispatch_marker_set() { :; }
mechanical_relaunch_attempted_previously() { return 1; }
kimi_dispatch_failed_previously() { return 1; }
dispatch_kimi_repair() { echo DISPATCH >&2; return 0; }
repair_unhealthy_session() { echo REPAIR >&2; return 0; }
ensure_install_or_repair() { return 0; }
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
plan_attention_status_env() {
  cat <<'EOF'
PLAN_STATUS_FOUND='1'
PLAN_STATUS_PLAN_NAME='newer-plan'
PLAN_STATUS_CURRENT_STATE=''
PLAN_STATUS_RETRY_STRATEGY=''
PLAN_STATUS_FAILURE_KIND=''
PLAN_STATUS_FAILURE_MESSAGE=''
PLAN_STATUS_FAILURE_PHASE=''
PLAN_STATUS_FAILURE_RECORDED_AT=''
PLAN_STATUS_TIERS_TRIED=''
PLAN_STATUS_PUSHED_COMMITS=''
PLAN_STATUS_MANUAL_REVIEW='0'
EOF
}
""".strip(),
            f"launch_chain_tick demo-session {str(workspace)!r} .megaplan/initiatives/demo/briefs/demo.md {str(report_path)!r} plan '' ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\tobserve\tcomplete\tplan complete\t" in report
    assert "spec_missing" not in report
    assert "BABYSITTER" not in result.stderr
    assert "REPAIR" not in result.stderr
    assert "TMUX" not in result.stderr


def test_watchdog_manual_review_plan_state_reports_needs_human_not_complete(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    plan_name = "demo-plan"
    _write_live_session_marker(
        marker_dir,
        "demo-session",
        workspace,
        ".megaplan/initiatives/demo/briefs/demo.md",
        run_kind="plan",
        plan_name=plan_name,
    )
    _write_plan(
        workspace / ".megaplan" / "plans" / plan_name,
        {
            "iteration": 3,
            "current_state": "manual_review",
            "resume_cursor": {"retry_strategy": "manual_review"},
            "latest_failure": {"kind": "iteration_cap", "message": "review required"},
        },
        events_body="{}\n",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            _extract_wrapper_function("plan_terminal_status"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"LOG={str(log_path)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() { echo stopped; }
session_terminal_status() { return 0; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
kimi_operator_running() { return 1; }
resolve_existing_remote_spec() { printf '%s\n' "$3"; }
dispatch_kimi_repair() { echo DISPATCH >&2; return 0; }
repair_unhealthy_session() { echo REPAIR >&2; return 0; }
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH >&2; return 1; }
notify_needs_human() {
  report_item "$1" "$2" "observe" "needs_human" "$7" "$3" "$4"
  log "needs-human notification fixture"
}
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
""".strip(),
            f"launch_chain_tick demo-session {str(workspace)!r} .megaplan/initiatives/demo/briefs/demo.md {str(report_path)!r} plan {plan_name!r} ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\tobserve\tneeds_human\tmanual_review halt;" in report
    assert "\tobserve\tcomplete\t" not in report
    assert "BABYSITTER" not in result.stderr
    assert "REPAIR" not in result.stderr
    assert "RELAUNCH" not in result.stderr
    assert "TMUX" not in result.stderr
    assert "needs-human webhook unset" not in log_path.read_text(encoding="utf-8")


def test_watchdog_blocked_recovery_manual_review_dispatches_repair_before_needs_human(
    tmp_path: Path,
) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    plan_name = "demo-plan"
    _write_live_session_marker(
        marker_dir,
        "demo-session",
        workspace,
        ".megaplan/initiatives/demo/briefs/demo.md",
        run_kind="plan",
        plan_name=plan_name,
    )
    _write_plan(
        workspace / ".megaplan" / "plans" / plan_name,
        {
            "iteration": 10,
            "current_state": "blocked",
            "resume_cursor": {"phase": "review", "retry_strategy": "manual_review"},
            "latest_failure": {
                "kind": "blocked_recovery_not_resolved",
                "message": "recover-blocked requires every current blocker to be explicitly resolved as non-terminal",
                "phase": "recover-blocked",
            },
        },
        events_body="{}\n",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            _extract_wrapper_function("plan_terminal_status"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"LOG={str(log_path)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
babysitter_effective_mode() { printf 'superfixer\t\n'; }
babysitter_occurrence_digest() { echo a9c062b1cfe5; }
babysitter_running_for_occurrence() { return 1; }
babysitter_after_elapsed() { return 0; }
launch_status_trigger_babysitter() { echo BABYSITTER >&2; return 0; }
babysitter_policy_dispatch() {
  launch_status_trigger_babysitter "$@"
  report_item "$6" "$1" "repair" "babysitter_scheduled" "single-flash babysitter dispatched: $7" "$2" "$3"
}
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH >&2; return 1; }
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
""".strip(),
            f"launch_chain_tick demo-session {str(workspace)!r} .megaplan/initiatives/demo/briefs/demo.md {str(report_path)!r} plan {plan_name!r} ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\trepair\tbabysitter_scheduled\t" in report
    assert "\tobserve\tneeds_human\t" not in report
    assert "BABYSITTER" in result.stderr
    assert "REPAIR" not in result.stderr
    assert "RELAUNCH" not in result.stderr
    assert "TMUX" not in result.stderr
    assert "needs-human webhook unset" not in log_path.read_text(encoding="utf-8")


def test_watchdog_auto_stall_manual_review_dispatches_repair_before_needs_human(
    tmp_path: Path,
) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    plan_name = "demo-plan"
    _write_live_session_marker(
        marker_dir,
        "demo-session",
        workspace,
        ".megaplan/initiatives/demo/briefs/demo.md",
        run_kind="plan",
        plan_name=plan_name,
    )
    _write_plan(
        workspace / ".megaplan" / "plans" / plan_name,
        {
            "iteration": 6,
            "current_state": "critiqued",
            "resume_cursor": {"retry_strategy": "manual_review"},
            "latest_failure": {
                "kind": "stalled",
                "message": "stalled at 'critiqued' for 5 iterations",
                "metadata": {"manual_review_origin": "auto_stall"},
            },
        },
        events_body="{}\n",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            _extract_wrapper_function("repair_needs_human_path"),
            _extract_wrapper_function("plan_terminal_status"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"LOG={str(log_path)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
babysitter_effective_mode() { printf 'superfixer\t\n'; }
babysitter_occurrence_digest() { echo a9c062b1cfe5; }
babysitter_running_for_occurrence() { return 1; }
babysitter_after_elapsed() { return 0; }
launch_status_trigger_babysitter() { echo BABYSITTER >&2; return 0; }
babysitter_policy_dispatch() {
  launch_status_trigger_babysitter "$@"
  report_item "$6" "$1" "repair" "babysitter_scheduled" "single-flash babysitter dispatched: $7" "$2" "$3"
}
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH >&2; return 1; }
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
""".strip(),
            f"launch_chain_tick demo-session {str(workspace)!r} .megaplan/initiatives/demo/briefs/demo.md {str(report_path)!r} plan {plan_name!r} ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\trepair\tbabysitter_scheduled\t" in report
    assert "\tobserve\tneeds_human\t" not in report
    assert "BABYSITTER" in result.stderr
    assert "REPAIR" not in result.stderr
    assert "RELAUNCH" not in result.stderr
    assert "TMUX" not in result.stderr
    assert "needs-human webhook unset" not in log_path.read_text(encoding="utf-8")


def test_watchdog_legacy_stalled_manual_review_dispatches_repair_before_needs_human(
    tmp_path: Path,
) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    plan_name = "demo-plan"
    _write_live_session_marker(
        marker_dir,
        "demo-session",
        workspace,
        ".megaplan/initiatives/demo/briefs/demo.md",
        run_kind="plan",
        plan_name=plan_name,
    )
    _write_plan(
        workspace / ".megaplan" / "plans" / plan_name,
        {
            "iteration": 9,
            "current_state": "critiqued",
            "resume_cursor": {"phase": "override add-note", "retry_strategy": "manual_review"},
            "latest_failure": {
                "kind": "stalled",
                "message": "stalled at 'critiqued' for 5 iterations",
                "phase": "override add-note",
                "metadata": {"stall_count": 5, "iteration": 9},
            },
        },
        events_body="{}\n",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            _extract_wrapper_function("repair_needs_human_path"),
            _extract_wrapper_function("plan_terminal_status"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"LOG={str(log_path)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
babysitter_effective_mode() { printf 'superfixer\t\n'; }
babysitter_occurrence_digest() { echo a9c062b1cfe5; }
babysitter_running_for_occurrence() { return 1; }
babysitter_after_elapsed() { return 0; }
launch_status_trigger_babysitter() { echo BABYSITTER >&2; return 0; }
babysitter_policy_dispatch() {
  launch_status_trigger_babysitter "$@"
  report_item "$6" "$1" "repair" "babysitter_scheduled" "single-flash babysitter dispatched: $7" "$2" "$3"
}
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH >&2; return 1; }
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
""".strip(),
            f"launch_chain_tick demo-session {str(workspace)!r} .megaplan/initiatives/demo/briefs/demo.md {str(report_path)!r} plan {plan_name!r} ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\trepair\tbabysitter_scheduled\t" in report
    assert "\tobserve\tneeds_human\t" not in report
    assert "BABYSITTER" in result.stderr
    assert "REPAIR" not in result.stderr
    assert "RELAUNCH" not in result.stderr
    assert "TMUX" not in result.stderr


def test_watchdog_awaiting_human_plan_state_routes_to_notification_not_repair(
    tmp_path: Path,
) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    plan_name = "demo-plan"
    _write_live_session_marker(
        marker_dir,
        "demo-session",
        workspace,
        ".megaplan/initiatives/demo/briefs/demo.md",
        run_kind="plan",
        plan_name=plan_name,
    )
    _write_plan(
        workspace / ".megaplan" / "plans" / plan_name,
        {
            "iteration": 3,
            "current_state": "awaiting_human",
            "latest_failure": {
                "kind": "blocked_by_prereq",
                "message": "execute reported blocked tasks awaiting user action: T1",
            },
        },
        events_body="{}\n",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            _extract_wrapper_function("repair_needs_human_path"),
            _extract_wrapper_function("plan_terminal_status"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"LOG={str(log_path)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
babysitter_effective_mode() { printf 'superfixer\t\n'; }
babysitter_occurrence_digest() { echo a9c062b1cfe5; }
babysitter_running_for_occurrence() { return 1; }
babysitter_after_elapsed() { return 0; }
launch_status_trigger_babysitter() { echo BABYSITTER >&2; return 0; }
babysitter_policy_dispatch() {
  launch_status_trigger_babysitter "$@"
  report_item "$6" "$1" "repair" "babysitter_scheduled" "single-flash babysitter dispatched: $7" "$2" "$3"
}
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH >&2; return 1; }
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
""".strip(),
            f"launch_chain_tick demo-session {str(workspace)!r} .megaplan/initiatives/demo/briefs/demo.md {str(report_path)!r} plan {plan_name!r} ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\trepair\trepair_dispatched\t" not in report
    assert "\tnotify\ttest_notification_suppressed\t" in report
    assert "\tobserve\tcomplete\t" not in report
    assert "BABYSITTER" not in result.stderr
    assert "REPAIR" not in result.stderr
    assert "RELAUNCH" not in result.stderr
    assert "TMUX" not in result.stderr
    assert "needs-human webhook unset" not in log_path.read_text(encoding="utf-8")


def test_watchdog_awaiting_human_verify_prep_routes_to_notification_not_repair(
    tmp_path: Path,
) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    plan_name = "demo-plan"
    _write_live_session_marker(
        marker_dir,
        "demo-session",
        workspace,
        ".megaplan/initiatives/demo/briefs/demo.md",
        run_kind="plan",
        plan_name=plan_name,
    )
    _write_plan(
        workspace / ".megaplan" / "plans" / plan_name,
        {
            "iteration": 3,
            "current_state": "awaiting_human_verify",
            "clarification": {
                "source": "prep",
                "questions": ["Which schema is authoritative?", "Which artifact should be backfilled?"],
            },
        },
        events_body="{}\n",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            _extract_wrapper_function("repair_needs_human_path"),
            _extract_wrapper_function("plan_terminal_status"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"LOG={str(log_path)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() { echo alive; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
babysitter_effective_mode() { printf 'superfixer\t\n'; }
babysitter_occurrence_digest() { echo a9c062b1cfe5; }
babysitter_running_for_occurrence() { return 1; }
babysitter_after_elapsed() { return 0; }
launch_status_trigger_babysitter() { echo BABYSITTER >&2; return 0; }
babysitter_policy_dispatch() {
  launch_status_trigger_babysitter "$@"
  report_item "$6" "$1" "repair" "babysitter_scheduled" "single-flash babysitter dispatched: $7" "$2" "$3"
}
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH >&2; return 1; }
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
""".strip(),
            f"launch_chain_tick demo-session {str(workspace)!r} .megaplan/initiatives/demo/briefs/demo.md {str(report_path)!r} plan {plan_name!r} ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\trepair\trepair_dispatched\t" not in report
    assert "\tnotify\ttest_notification_suppressed\t" in report
    assert "BABYSITTER" not in result.stderr
    assert "REPAIR" not in result.stderr
    assert "RELAUNCH" not in result.stderr
    assert "needs-human webhook unset" not in log_path.read_text(encoding="utf-8")


def test_watchdog_nonterminal_plan_state_mechanically_relaunches_before_kimi(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    plan_name = "demo-plan"
    _write_live_session_marker(
        marker_dir,
        "demo-session",
        workspace,
        ".megaplan/initiatives/demo/briefs/demo.md",
        run_kind="plan",
        plan_name=plan_name,
    )
    _write_plan(
        workspace / ".megaplan" / "plans" / plan_name,
        {"iteration": 1, "current_state": "planning", "active_step": None},
        events_body="{}\n",
    )
    report_path = tmp_path / "report.tsv"

    script = "\n\n".join(
        [
            _extract_wrapper_function("kimi_dispatch_marker_path"),
            _extract_wrapper_function("kimi_pgid_path"),
            _extract_wrapper_function("kimi_dispatch_marker_set"),
            _extract_wrapper_function("mechanical_relaunch_attempted_previously"),
            _extract_wrapper_function("kimi_dispatch_failed_previously"),
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function("plan_terminal_status"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { :; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
kimi_operator_running() { return 1; }
dispatch_kimi_repair() { echo DISPATCH >&2; return 0; }
repair_unhealthy_session() { echo REPAIR >&2; return 0; }
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH; }
safe_name() { printf '%s\n' "$1"; }
tmux() {
  if [[ "$1" == "has-session" || "$3" == "has-session" ]]; then
    return 1
  fi
  if [[ "$1" == "new-session" || "$3" == "new-session" ]]; then
    echo TMUX_NEW >&2
    return 0
  fi
  echo "TMUX_$1" >&2
  return 0
}
""".strip(),
            f"launch_chain_tick demo-session {str(workspace)!r} .megaplan/initiatives/demo/briefs/demo.md {str(report_path)!r} plan {plan_name!r} ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\trestart\trestarted\tstopped session relaunched\t" in report
    assert "\tobserve\tcomplete\t" not in report
    assert "BABYSITTER" not in result.stderr
    assert "REPAIR" not in result.stderr
    assert "TMUX_NEW" in result.stderr
    mechanical_marker = (marker_dir / "demo-session.kimi-dispatch").read_text().rstrip("\n").split("\t")
    assert mechanical_marker[:2] == [
        "arnold-dispatch-marker-v2",
        "deterministic_relaunch",
    ]
    assert mechanical_marker[3:] == ["", ""]


def _build_direct_relaunch_tick_script(
    paths: dict[str, Path],
    *,
    emit_fails: bool,
) -> str:
    """Build a shell script driving launch_chain_tick down the stopped-session
    direct mechanical relaunch (no prior mechanical-relaunch / failed-Kimi
    record), with a recording emit_runtime_transition_event stub.  The stub
    appends event names to CALL_LOG; the tmux stub appends the launch to the
    same log so the test can prove the events precede the launch."""
    if emit_fails:
        emit_stub = (
            "emit_runtime_transition_event() {\n"
            "  printf 'event:%s\\n' \"$1\" >> \"$CALL_LOG\"\n"
            "  return 1\n"
            "}\n"
        )
    else:
        emit_stub = (
            "emit_runtime_transition_event() {\n"
            "  printf 'event:%s\\n' \"$1\" >> \"$CALL_LOG\"\n"
            "  return 0\n"
            "}\n"
        )
    return "\n\n".join(
        [
            _extract_wrapper_function("kimi_dispatch_marker_path"),
            _extract_wrapper_function("kimi_pgid_path"),
            _extract_wrapper_function("kimi_dispatch_marker_set"),
            _extract_wrapper_function("mechanical_relaunch_attempted_previously"),
            _extract_wrapper_function("kimi_dispatch_failed_previously"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            emit_stub,
            f"MARKER_DIR={str(paths['marker_dir'])!r}",
            f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            f"LOG={str(paths['log_path'])!r}",
            f"CALL_LOG={str(paths['call_log'])!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
plan_attention_status_env() { return 0; }
plan_terminal_status() { return 1; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
chain_health_status() {
  CHAIN_HEALTH_STATUS=ok
  CHAIN_HEALTH_SUMMARY=
  CHAIN_HEALTH_ARTIFACT_PATH=
  CHAIN_HEALTH_LOG_MESSAGE=
}
kimi_operator_running() { return 1; }
dispatch_kimi_repair() { echo DISPATCH >&2; return 0; }
repair_unhealthy_session() { echo REPAIR >&2; return 0; }
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH >&2; }
safe_name() { printf '%s\n' "$1"; }
tmux() {
  if [[ "$1" == "has-session" || "$3" == "has-session" ]]; then
    return 1
  fi
  if [[ "$1" == "new-session" || "$3" == "new-session" ]]; then
    printf 'launch:%s\n' "$*" >> "$CALL_LOG"
    echo TMUX_NEW >&2
    return 0
  fi
  echo "TMUX_$1" >&2
  return 0
}
""".strip(),
            (
                f"launch_chain_tick demo-session {str(paths['workspace'])!r} "
                f"{str(paths['spec_path'])!r} {str(paths['report_path'])!r} chain '' ''"
            ),
        ]
    )


def test_watchdog_direct_relaunch_emits_fallback_events_before_launch(tmp_path: Path) -> None:
    """G3 third-run bypass: the stopped-session direct mechanical relaunch must
    journal fallback_considered + fallback_taken BEFORE the kimi-dispatch
    marker write and the tmux launch, and succeed (no relaunch when the ledger
    write fails).  This half proves the events are emitted and ordered before
    the launch side effects."""
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    workspace.mkdir()
    spec_path = workspace / "chain.yaml"
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    _write_live_session_marker(
        marker_dir,
        "demo-session",
        workspace,
        str(spec_path),
        run_kind="chain",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"
    call_log = tmp_path / "call.log"

    paths = {
        "marker_dir": marker_dir,
        "workspace": workspace,
        "spec_path": spec_path,
        "report_path": report_path,
        "log_path": log_path,
        "call_log": call_log,
    }
    script = _build_direct_relaunch_tick_script(paths, emit_fails=False)
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert "TMUX_NEW" in result.stderr

    lines = call_log.read_text(encoding="utf-8").splitlines()
    event_lines = [line for line in lines if line.startswith("event:")]
    assert event_lines == [
        "event:fallback_considered",
        "event:fallback_taken",
    ], lines
    launch_lines = [line for line in lines if line.startswith("launch:")]
    assert len(launch_lines) == 1, lines
    assert lines.index("event:fallback_taken") < lines.index(launch_lines[0]), lines
    # The dispatch marker is still written (relaunch proceeds) — but only
    # AFTER the events.
    marker_path = marker_dir / "demo-session.kimi-dispatch"
    assert marker_path.exists()
    report = report_path.read_text(encoding="utf-8")
    assert "\trestart\trestarted\tstopped session relaunched\t" in report


def test_watchdog_direct_relaunch_ledger_failure_blocks_marker_and_launch(tmp_path: Path) -> None:
    """G3 third-run bypass, fail-closed half: when the runtime transition
    ledger write fails, the direct mechanical relaunch must NOT write the
    kimi-dispatch marker and must NOT execute the relaunch command or tmux
    launch (no event = no side effect)."""
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    workspace.mkdir()
    spec_path = workspace / "chain.yaml"
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    _write_live_session_marker(
        marker_dir,
        "demo-session",
        workspace,
        str(spec_path),
        run_kind="chain",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"
    call_log = tmp_path / "call.log"

    paths = {
        "marker_dir": marker_dir,
        "workspace": workspace,
        "spec_path": spec_path,
        "report_path": report_path,
        "log_path": log_path,
        "call_log": call_log,
    }
    script = _build_direct_relaunch_tick_script(paths, emit_fails=True)
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert "TMUX_NEW" not in result.stderr
    assert "RELAUNCH" not in result.stderr

    lines = call_log.read_text(encoding="utf-8").splitlines()
    # The first event write fails, so fallback_taken is never attempted.
    assert lines == ["event:fallback_considered"], lines
    assert not (marker_dir / "demo-session.kimi-dispatch").exists()
    assert (
        "runtime fallback_considered ledger write failed; blocking direct mechanical relaunch"
        in log_path.read_text(encoding="utf-8")
    )
    report = report_path.read_text(encoding="utf-8")
    assert "\trestart\trestart_blocked\t" in report


def test_watchdog_launch_tick_missing_manifest_pin_fails_closed_before_install_and_tmux(
    tmp_path: Path,
) -> None:
    """G5 round-2 finding 1 / round-6 finding 1b: the watchdog's engine-root
    preflight is the FIRST mutation-gating step in the tick — it runs BEFORE
    the current-target subprocesses and before any marker/install-repair/tmux
    side effect.  With no session manifest pin the tick fails closed (typed
    drift, exit 24) and the spies record ZERO install-repair calls, ZERO tmux
    calls, and no marker/relaunch/dispatch writes."""
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    workspace.mkdir()
    spec_path = workspace / "chain.yaml"
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    _write_live_session_marker(
        marker_dir,
        "demo-session",
        workspace,
        str(spec_path),
        run_kind="chain",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"
    call_log = tmp_path / "call.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("kimi_dispatch_marker_path"),
            _extract_wrapper_function("kimi_pgid_path"),
            _extract_wrapper_function("kimi_dispatch_marker_set"),
            _extract_wrapper_function("mechanical_relaunch_attempted_previously"),
            _extract_wrapper_function("kimi_dispatch_failed_previously"),
            _extract_wrapper_function("chain_engine_root_preflight"),
            _extract_wrapper_function("launch_chain_tick"),
            "LIVE_IMPORT_ROOT=" + repr(str(REPO_ROOT)),
            "unset MANIFEST_RUNTIME_ROOT",
            "unset ARNOLD_RUNTIME_MANIFEST_DIR",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            f"LOG={str(log_path)!r}",
            f"CALL_LOG={str(call_log)!r}",
            """
    report_item() {
  printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\\n' "$*" >> "$LOG"; }
plan_attention_status_env() { return 0; }
plan_terminal_status() { return 1; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
chain_health_status() {
  CHAIN_HEALTH_STATUS=ok
  CHAIN_HEALTH_SUMMARY=
  CHAIN_HEALTH_ARTIFACT_PATH=
  CHAIN_HEALTH_LOG_MESSAGE=
}
kimi_operator_running() { return 1; }
emit_runtime_transition_event() { printf 'event:%s\\n' "$1" >> "$CALL_LOG"; return 0; }
dispatch_kimi_repair() { echo DISPATCH >&2; return 0; }
repair_unhealthy_session() { echo REPAIR >&2; return 0; }
ensure_install_or_repair() { echo INSTALL >&2; return 0; }
resolve_relaunch_command() { echo RELAUNCH >&2; }
safe_name() { printf '%s\\n' "$1"; }
tmux() {
  if [[ "$1" == "has-session" ]]; then
    return 0
  fi
  printf 'tmux:%s\\n' "$*" >> "$CALL_LOG"
  echo TMUX >&2
  return 0
}
""".strip(),
            (
                f"launch_chain_tick demo-session {str(workspace)!r} "
                f"{str(spec_path)!r} {str(report_path)!r} chain '' ''"
            ),
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 24, result.stderr
    assert "chain_runtime_binding_drift" in result.stderr
    assert "session runtime manifest missing" in result.stderr
    call_text = call_log.read_text(encoding="utf-8") if call_log.exists() else ""
    # The manifest preflight itself is the only expected interpreter call;
    # mutation-gating work must still remain entirely absent.
    assert "tmux:kill-session" not in call_text, call_text.splitlines()
    assert "tmux:new-session" not in call_text, call_text.splitlines()
    assert "event:fallback_considered" not in call_text, call_text.splitlines()
    assert "INSTALL" not in result.stderr
    assert "TMUX" not in result.stderr
    assert "RELAUNCH" not in result.stderr
    assert "BABYSITTER" not in result.stderr
    assert "REPAIR" not in result.stderr
    report = report_path.read_text(encoding="utf-8") if report_path.exists() else ""
    assert "\trestart\trestarted\t" not in report
    # No marker/publication/repair side effects: no dispatch/needs-human/
    # repair-data artifacts appear in the marker dir.
    marker_files = sorted(p.name for p in marker_dir.iterdir())
    assert not any(
        name.endswith(
            (".kimi-dispatch", ".meta-dispatch", ".needs-human.json", ".repair-data.json")
        )
        for name in marker_files
    ), marker_files


def test_watchdog_plan_resolver_persisted_command_requires_preflight(tmp_path: Path) -> None:
    """G5 round-6 finding 1b: the default-plan preflight gates ANY persisted
    plan command in the resolver — a persisted command cannot bypass the
    engine-root preflight.  With no SESSION manifest the resolver fails closed
    (typed drift, exit 24) and returns NOTHING; with the session manifest's
    epic.runtime_root pin the persisted command is returned only AFTER the
    preflight passes."""
    workspace = tmp_path / "workspace"
    manifest_dir = tmp_path / "manifests"
    session = "demo-session"
    runtime_root = REPO_ROOT
    spec = workspace / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    spec.parent.mkdir(parents=True, exist_ok=True)
    spec.write_text("milestones: []\n", encoding="utf-8")
    _write_runtime_bound_chain_state(
        workspace,
        spec,
        runtime_root,
        plan_name="demo-plan",
        metadata={
            "execution_binding": {"spec": str(spec)},
            "execution_environment": {"engine_root": str(runtime_root)},
        },
    )
    persisted = "echo persisted-plan-command"

    # Fail-closed half: no session manifest -> typed drift 24, zero output.
    script = "\n\n".join(
        [
            *_extract_relaunch_functions("watchdog"),
            f"SRC_DIR={str(runtime_root)!r}",
            f"ARNOLD_RUNTIME_MANIFEST_DIR={str(manifest_dir)!r}",
            "PYTHONPATH=" + repr(str(REPO_ROOT)),
            "SYNC_BRANCH=editible-install",
            (
                f"resolve_relaunch_command {session} {str(workspace)!r} "
                f"{str(spec)!r} plan demo-plan {shlex.quote(persisted)}"
            ),
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 24, result.stderr
    assert "chain_runtime_binding_drift" in result.stderr
    assert "session runtime manifest missing" in result.stderr
    assert result.stdout.strip() == ""

    # Passing half: session manifest pins the runtime root -> preflight passes
    # and the non-stale persisted command is returned verbatim.
    _write_session_runtime_manifest(manifest_dir, session, runtime_root)
    script = "\n\n".join(
        [
            *_extract_relaunch_functions("watchdog"),
            f"SRC_DIR={str(runtime_root)!r}",
            f"ARNOLD_RUNTIME_MANIFEST_DIR={str(manifest_dir)!r}",
            "PYTHONPATH=" + repr(str(REPO_ROOT)),
            "SYNC_BRANCH=editible-install",
            (
                f"resolve_relaunch_command {session} {str(workspace)!r} "
                f"{str(spec)!r} plan demo-plan {shlex.quote(persisted)}"
            ),
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert result.stdout == persisted


def test_watchdog_plan_resolver_session_manifest_drift_fails_closed(
    tmp_path: Path,
) -> None:
    """T-0022: the plan resolver's preflight binds the SESSION manifest root,
    not the watchdog-global live import root.  A chain state recorded engine
    root that disagrees with the session manifest fails closed (typed drift,
    exit 24) with ZERO persisted-command output."""
    workspace = tmp_path / "workspace"
    manifest_dir = tmp_path / "manifests"
    session = "demo-session"
    spec = workspace / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    spec.parent.mkdir(parents=True, exist_ok=True)
    spec.write_text("milestones: []\n", encoding="utf-8")
    recorded = _relaunch_engine_root(tmp_path, name="recorded-engine")
    manifest_engine = _relaunch_engine_root(tmp_path, name="manifest-engine")
    _write_runtime_bound_chain_state(
        workspace,
        spec,
        recorded,
        plan_name="demo-plan",
        metadata={
            "execution_binding": {"spec": str(spec)},
            "execution_environment": {"engine_root": str(recorded)},
        },
    )
    _write_session_runtime_manifest(manifest_dir, session, manifest_engine)
    persisted = "echo persisted-plan-command"
    script = "\n\n".join(
        [
            *_extract_relaunch_functions("watchdog"),
            f"SRC_DIR={str(manifest_engine)!r}",
            f"ARNOLD_RUNTIME_MANIFEST_DIR={str(manifest_dir)!r}",
            "PYTHONPATH=" + repr(str(REPO_ROOT)),
            "SYNC_BRANCH=editible-install",
            (
                f"resolve_relaunch_command {session} {str(workspace)!r} "
                f"{str(spec)!r} plan demo-plan {shlex.quote(persisted)}"
            ),
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 24, result.stderr
    assert "chain_runtime_binding_drift" in result.stderr, result.stderr
    assert (
        f"engine root mismatch: recorded={recorded.resolve()} "
        f"manifest={manifest_engine.resolve()}"
    ) in result.stderr, result.stderr
    assert result.stdout.strip() == "", result.stdout


def test_watchdog_chain_resolver_session_manifest_drift_fails_closed(
    tmp_path: Path,
) -> None:
    """T-0022: the chain-resume preflight also binds the SESSION manifest root
    — a chain state recorded engine root that disagrees with the session
    manifest fails closed (typed drift, exit 24)."""
    workspace = tmp_path / "workspace"
    manifest_dir = tmp_path / "manifests"
    session = "demo-session"
    spec = workspace / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    spec.parent.mkdir(parents=True, exist_ok=True)
    spec.write_text("milestones: []\n", encoding="utf-8")
    recorded = _relaunch_engine_root(tmp_path, name="recorded-engine")
    manifest_engine = _relaunch_engine_root(tmp_path, name="manifest-engine")
    _write_runtime_bound_chain_state(workspace, spec, recorded)
    _write_session_runtime_manifest(manifest_dir, session, manifest_engine)
    script = "\n\n".join(
        [
            *_extract_relaunch_functions("watchdog"),
            f"SRC_DIR={str(manifest_engine)!r}",
            f"ARNOLD_RUNTIME_MANIFEST_DIR={str(manifest_dir)!r}",
            "PYTHONPATH=" + repr(str(REPO_ROOT)),
            "SYNC_BRANCH=editible-install",
            (
                f"resolve_relaunch_command {session} {str(workspace)!r} "
                f"{str(spec)!r} chain '' 'echo stale-marker-chain-start'"
            ),
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 24, result.stderr
    assert "chain_runtime_binding_drift" in result.stderr, result.stderr
    assert (
        f"engine root mismatch: recorded={recorded.resolve()} "
        f"manifest={manifest_engine.resolve()}"
    ) in result.stderr, result.stderr
    assert result.stdout.strip() == "", result.stdout


def _chain_engine_preflight_run(
    function_text: str,
    workspace: Path,
    *,
    session: str,
    manifest_dir: Path,
    remote_spec: str = "",
    plan_name: str = "",
    watchdog_root: str = "",
) -> subprocess.CompletedProcess[str]:
    """Run the REAL chain_engine_root_preflight identity-scoped to ``session``:
    ARNOLD_RUNTIME_MANIFEST_DIR points at a tmp dir holding ``{session}.json``
    and PYTHONPATH exposes the checked-out repo so find_bound_chain_spec
    resolves.  ``watchdog_root`` (optional) pins the supervisor's own
    manifest/live root, which the preflight must IGNORE (multi-engine identity
    scoping, T-0022)."""
    lines = [
        function_text,
        f"export ARNOLD_RUNTIME_MANIFEST_DIR={shlex.quote(str(manifest_dir))}",
        f"export PYTHONPATH={shlex.quote(str(REPO_ROOT))}",
    ]
    if watchdog_root:
        lines.append(f"export MANIFEST_RUNTIME_ROOT={shlex.quote(watchdog_root)}")
        lines.append(f"export LIVE_IMPORT_ROOT={shlex.quote(watchdog_root)}")
    lines.append(
        f"chain_engine_root_preflight {shlex.quote(str(workspace))} "
        f"{shlex.quote(remote_spec)} {shlex.quote(session)} "
        f"{shlex.quote(plan_name)}"
    )
    return _run_watchdog_shell("\n\n".join(lines))


def _relaunch_engine_root(tmp_path: Path, name: str = "engine") -> Path:
    """A fake engine checkout: a git repo WITH an arnold_pipelines package
    (the preflight's require_engine proves both .git and arnold_pipelines)."""
    root = _relaunch_runtime_root(tmp_path, name=name)
    pkg = root / "arnold_pipelines"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    return root


def _write_session_runtime_manifest(
    manifest_dir: Path, session: str, runtime_root: str | Path
) -> Path:
    """Write {manifest_dir}/{session}.json with epic.runtime_root, the
    canonical per-session runtime manifest the preflight reads."""
    manifest_dir.mkdir(parents=True, exist_ok=True)
    path = manifest_dir / f"{session}.json"
    path.write_text(
        json.dumps({"epic": {"runtime_root": str(runtime_root)}}),
        encoding="utf-8",
    )
    return path


def _plan_bound_chain_workspace(
    tmp_path: Path,
    *,
    plan_name: str,
    engine_root: Path,
) -> tuple[Path, Path]:
    """Workspace with one initiative chain.yaml whose persisted state owns
    ``plan_name`` and records ``engine_root``, so find_bound_chain_spec
    resolves the plan's bound chain and the preflight re-reads the recorded
    root from the canonical ``.chains`` state."""
    workspace = tmp_path / "ws"
    spec = workspace / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    spec.parent.mkdir(parents=True, exist_ok=True)
    spec.write_text("milestones: []\n", encoding="utf-8")
    _write_runtime_bound_chain_state(
        workspace,
        spec,
        engine_root,
        plan_name=plan_name,
        metadata={
            "execution_binding": {"spec": str(spec)},
            "execution_environment": {"engine_root": str(engine_root)},
        },
    )
    return workspace, spec


def test_chain_engine_root_preflight_bound_chain_drift_fails_closed(
    tmp_path: Path,
) -> None:
    """A BOUND chain whose recorded engine root disagrees with the SESSION's
    own manifest epic.runtime_root fails closed (typed drift, exit 24) EVEN
    WHEN find_bound_chain_spec resolves the chain — the recorded==session
    manifest check is not gated on (or skipped by) the bound-spec resolution."""
    plan_name = "demo-plan"
    session = "astrid-first"
    manifest_dir = tmp_path / "manifests"
    recorded = _relaunch_engine_root(tmp_path, name="recorded-engine")
    manifest_engine = _relaunch_engine_root(tmp_path, name="manifest-engine")
    workspace, _spec = _plan_bound_chain_workspace(
        tmp_path, plan_name=plan_name, engine_root=recorded
    )
    _write_session_runtime_manifest(manifest_dir, session, manifest_engine)

    function_text = _extract_wrapper_function("chain_engine_root_preflight")
    result = _chain_engine_preflight_run(
        function_text,
        workspace,
        session=session,
        manifest_dir=manifest_dir,
        plan_name=plan_name,
    )
    assert result.returncode == 24, result.stderr
    assert "chain_runtime_binding_drift" in result.stderr, result.stderr
    assert (
        f"engine root mismatch: recorded={recorded.resolve()} "
        f"manifest={manifest_engine.resolve()}"
    ) in result.stderr, result.stderr
    assert result.stdout == "", result.stdout


def test_chain_engine_root_preflight_standalone_plan_uses_session_manifest(
    tmp_path: Path,
) -> None:
    """A STANDALONE plan (no bound chain, so find_bound_chain_spec returns
    nothing) carries no recorded engine root; the session manifest
    epic.runtime_root IS the binding.  The preflight proves it is a real engine
    checkout: a valid engine returns the manifest root, a dangling root fails
    closed (typed drift, exit 24)."""
    session = "astrid-first"
    manifest_dir = tmp_path / "manifests"
    workspace = tmp_path / "ws"
    workspace.mkdir()
    engine = _relaunch_engine_root(tmp_path, name="engine")
    dangling = tmp_path / "dangling"

    function_text = _extract_wrapper_function("chain_engine_root_preflight")
    # Session manifest pins a dangling path -> drift, NOT an unchecked return.
    _write_session_runtime_manifest(manifest_dir, session, dangling)
    result = _chain_engine_preflight_run(
        function_text,
        workspace,
        session=session,
        manifest_dir=manifest_dir,
        plan_name="demo-plan",
    )
    assert result.returncode == 24, result.stderr
    assert "chain_runtime_binding_drift" in result.stderr, result.stderr
    assert "missing or dangling" in result.stderr, result.stderr
    assert result.stdout == "", result.stdout

    # Session manifest pins a real engine -> proceed and return the root.
    _write_session_runtime_manifest(manifest_dir, session, engine)
    result = _chain_engine_preflight_run(
        function_text,
        workspace,
        session=session,
        manifest_dir=manifest_dir,
        plan_name="demo-plan",
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(engine.resolve()), result.stdout


def test_chain_engine_root_preflight_uses_session_manifest_root(
    tmp_path: Path,
) -> None:
    """T-0022 identity scoping: the preflight binds to the SESSION's own
    manifest epic.runtime_root, never the watchdog process's global root.  A
    multi-engine box (watchdog root A observing session 'astrid-first' whose
    manifest pins B) must PASS when the recorded chain root equals B — the old
    env-scoped check wrongly typed this as drift (exit 24)."""
    plan_name = "demo-plan"
    session = "astrid-first"
    manifest_dir = tmp_path / "manifests"
    engine_a = _relaunch_engine_root(tmp_path, name="engine-a")
    engine_b = _relaunch_engine_root(tmp_path, name="engine-b")
    workspace, _spec = _plan_bound_chain_workspace(
        tmp_path, plan_name=plan_name, engine_root=engine_b
    )
    _write_session_runtime_manifest(manifest_dir, session, engine_b)

    function_text = _extract_wrapper_function("chain_engine_root_preflight")
    result = _chain_engine_preflight_run(
        function_text,
        workspace,
        session=session,
        manifest_dir=manifest_dir,
        plan_name=plan_name,
        watchdog_root=str(engine_a),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(engine_b.resolve()), result.stdout


def test_chain_engine_root_preflight_missing_session_manifest_fails_closed(
    tmp_path: Path,
) -> None:
    """Identity scoping fails closed when the SESSION's own runtime manifest is
    absent: exit 24 + 'session runtime manifest missing'.  The watchdog's own
    manifest/live root is NOT a substitute for the session identity."""
    session = "astrid-first"
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    workspace = tmp_path / "ws"
    workspace.mkdir()

    function_text = _extract_wrapper_function("chain_engine_root_preflight")
    result = _chain_engine_preflight_run(
        function_text,
        workspace,
        session=session,
        manifest_dir=manifest_dir,
    )
    assert result.returncode == 24, result.stderr
    assert "session runtime manifest missing" in result.stderr, result.stderr
    assert result.stdout == "", result.stdout


def test_chain_engine_root_preflight_session_manifest_lacks_root_fails_closed(
    tmp_path: Path,
) -> None:
    """A session manifest WITHOUT epic.runtime_root cannot prove the runtime
    binding: fail closed (exit 24) with 'lacks epic.runtime_root'."""
    session = "astrid-first"
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    (manifest_dir / f"{session}.json").write_text(
        json.dumps({"epic": {}}), encoding="utf-8"
    )
    workspace = tmp_path / "ws"
    workspace.mkdir()

    function_text = _extract_wrapper_function("chain_engine_root_preflight")
    result = _chain_engine_preflight_run(
        function_text,
        workspace,
        session=session,
        manifest_dir=manifest_dir,
    )
    assert result.returncode == 24, result.stderr
    assert "lacks epic.runtime_root" in result.stderr, result.stderr
    assert result.stdout == "", result.stdout


def test_watchdog_fences_mechanical_relaunch_for_phase_contract_failure(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    plan_name = "m6-exact-contract"
    _write_live_session_marker(
        marker_dir,
        "demo-session",
        workspace,
        ".megaplan/initiatives/demo/briefs/demo.md",
        run_kind="plan",
        plan_name=plan_name,
    )
    _write_plan(
        workspace / ".megaplan" / "plans" / plan_name,
        {
            "iteration": 5,
            "current_state": "blocked",
            "active_step": None,
            "resume_cursor": {
                "phase": "critique",
                "retry_strategy": "repair_phase_contract",
            },
            "latest_failure": {
                "kind": "deterministic_phase_failure",
                "phase": "critique",
                "message": "critique contract failed three times",
            },
        },
        events_body="{}\n",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function("plan_terminal_status"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"LOG={str(log_path)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
babysitter_effective_mode() { printf 'superfixer\\t\\n'; }
babysitter_occurrence_digest() { echo a9c062b1cfe5; }
babysitter_running_for_occurrence() { return 1; }
babysitter_after_elapsed() { return 0; }
launch_status_trigger_babysitter() {
  echo BABYSITTER >&2
  return 0
}
babysitter_policy_dispatch() {
  launch_status_trigger_babysitter "$@"
  report_item "$6" "$1" "repair" "babysitter_scheduled" \
    "single-flash babysitter dispatched: $7" "$2" "$3"
}
ensure_install_or_repair() { echo INSTALL >&2; return 0; }
resolve_relaunch_command() { echo RELAUNCH >&2; return 0; }
tmux() { echo TMUX >&2; return 1; }
""".strip(),
            f"launch_chain_tick demo-session {str(workspace)!r} .megaplan/initiatives/demo/briefs/demo.md {str(report_path)!r} plan {plan_name!r} ''",
        ]
    )

    result = _run_watchdog_shell(script)

    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\trepair\tbabysitter_scheduled\t" in report
    assert "BABYSITTER" in result.stderr
    assert "\trestart\trestarted\t" not in report
    assert "RELAUNCH" not in result.stderr
    assert "TMUX" not in result.stderr
    assert "deterministic phase-contract failure (no mechanical relaunch)" in report


def test_phase_contract_failure_dispatches_babysitter_without_claim(
    tmp_path: Path,
) -> None:
    """The deterministic phase-contract fence dispatches the single-flash
    babysitter with the occurrence digest and NEVER enqueues/claims a repair
    request (the layered enqueue/claim path was removed with L1/L2)."""
    marker_dir = tmp_path / ".megaplan" / "cloud-sessions"
    repair_data_dir = marker_dir / "repair-data"
    repair_data_dir.mkdir(parents=True)
    workspace = tmp_path / "workspace"
    plan_name = "cl2-wbc-backed-ledger"
    spec_path = workspace / ".megaplan" / "initiatives" / "critique-ledger" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    session = "critique-r5"
    _write_plan(
        workspace / ".megaplan" / "plans" / plan_name,
        {
            "iteration": 2,
            "current_state": "blocked",
            "active_step": None,
            "resume_cursor": {
                "phase": "critique",
                "retry_strategy": "repair_phase_contract",
            },
            "latest_failure": {
                "kind": "deterministic_phase_failure",
                "phase": "critique",
                "message": "critique contract failed three times",
                "metadata": {"phase_or_step": "critique", "blocked_task_id": "phase:critique"},
            },
        },
        events_body="{}\n",
    )
    (marker_dir / f"{session}.json").write_text(
        json.dumps(
            {
                "session": session,
                "workspace": str(workspace),
                "remote_spec": str(spec_path),
                "run_kind": "plan",
                "plan_name": plan_name,
            }
        ),
        encoding="utf-8",
    )

    script = "\n\n".join(
        [
            _extract_wrapper_function("babysitter_occurrence_digest"),
            _extract_wrapper_function("babysitter_effective_mode"),
            _extract_wrapper_function("babysitter_running_for_occurrence"),
            _extract_wrapper_function("babysitter_after_elapsed"),
            _extract_wrapper_function("launch_status_trigger_babysitter"),
            _extract_wrapper_function("babysitter_policy_dispatch"),
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(repair_data_dir)!r}",
            f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            "export ARNOLD_BABYSITTER_LAUNCH_GRACE_SECS=0.2",
            "export CLOUD_WATCHDOG_BABYSITTER_BIN=" + shlex.quote(str(tmp_path / "missing-babysitter-bin.sh")),
            """
report_item() { :; }
log() { :; }
""".strip(),
            (
                "babysitter_policy_dispatch "
                f"{shlex.quote(session)} {shlex.quote(str(workspace))} "
                f"{shlex.quote(str(spec_path))} plan {shlex.quote(plan_name)} "
                f"{shlex.quote(str(tmp_path / 'report.tsv'))} "
                "'deterministic phase-contract failure'"
            ),
        ]
    )

    result = _run_watchdog_shell(script)

    assert result.returncode == 0, result.stderr
    # The launch fails closed here (no babysitter bin under the test roots),
    # which must be reported as babysitter_launch_failed — the important
    # contract is that NOTHING was enqueued or claimed.
    assert repair_requests.iter_repair_requests(
        repair_requests.repair_queue_dir(marker_dir)
    ) == []


def _prepare_watchdog_superfixer_fixture(
    tmp_path: Path,
) -> dict[str, Path]:
    """Shared status-trigger superfixer fixture (marker, plan, spec, stub bin)."""
    marker_dir = tmp_path / ".megaplan" / "cloud-sessions"
    repair_data_dir = marker_dir / "repair-data"
    repair_data_dir.mkdir(parents=True)
    workspace = tmp_path / "workspace"
    plan_name = "cl2-wbc-backed-ledger"
    spec_path = workspace / ".megaplan" / "initiatives" / "critique-ledger" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    session = "critique-r5"
    _write_plan(
        workspace / ".megaplan" / "plans" / plan_name,
        {
            "iteration": 2,
            "current_state": "blocked",
            "active_step": None,
            "resume_cursor": {
                "phase": "critique",
                "retry_strategy": "repair_phase_contract",
            },
            "latest_failure": {
                "kind": "deterministic_phase_failure",
                "phase": "critique",
                "message": "critique contract failed three times",
            },
        },
        events_body="{}\n",
    )
    (marker_dir / f"{session}.json").write_text(
        json.dumps(
            {
                "session": session,
                "workspace": str(workspace),
                "remote_spec": str(spec_path),
                "run_kind": "plan",
                "plan_name": plan_name,
            }
        ),
        encoding="utf-8",
    )
    stub = tmp_path / "babysitter-stub.sh"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'printf "%s\\n" "$ARNOLD_BABYSITTER_GOAL_FILE" > "$BABYSITTER_TEST_RECORD"\n'
        'exit "${BABYSITTER_TEST_EXIT:-0}"\n',
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return {
        "marker_dir": marker_dir,
        "repair_data_dir": repair_data_dir,
        "workspace": workspace,
        "spec_path": spec_path,
        "session": session,
        "plan_name": plan_name,
        "stub_bin": stub,
    }


def test_watchdog_manual_review_superfixer_journals_runtime_transitions(tmp_path: Path) -> None:
    """The status-trigger babysitter launcher
    (launch_status_trigger_babysitter) journals deviation_declared +
    fallback_considered BEFORE the babysitter launch side effect, then
    dispatches the babysitter DIRECTLY (no schedule-add hop, no enqueue),
    and records an occurrence-scoped dispatch receipt. RC=0 is the
    no-fallthrough signal for the tick."""
    paths = _prepare_watchdog_superfixer_fixture(tmp_path)
    record_path = tmp_path / "babysitter-launched.txt"
    script = "\n\n".join(
        [
            _extract_wrapper_function("babysitter_occurrence_digest"),
            _extract_wrapper_function("launch_status_trigger_babysitter"),
            f"MARKER_DIR={str(paths['marker_dir'])!r}",
            f"REPAIR_DATA_DIR={str(paths['repair_data_dir'])!r}",
            f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            "export CLOUD_WATCHDOG_BABYSITTER_BIN=" + shlex.quote(str(paths['stub_bin'])) + "",
            "export ARNOLD_BABYSITTER_LAUNCH_GRACE_SECS=0.2",
            f"export BABYSITTER_TEST_RECORD={str(record_path)!r}",
            (
                "digest=\"$(babysitter_occurrence_digest "
                f"{shlex.quote(paths['session'])} {shlex.quote(str(paths['workspace']))} "
                f"{shlex.quote(str(paths['spec_path']))} plan {shlex.quote(paths['plan_name'])})\""
            ),
            (
                "launch_status_trigger_babysitter "
                f"{shlex.quote(paths['session'])} {shlex.quote(str(paths['workspace']))} "
                f"{shlex.quote(str(paths['spec_path']))} plan {shlex.quote(paths['plan_name'])} "
                f"{shlex.quote(str(tmp_path / 'report.tsv'))} \"$digest\""
            ),
            'echo "RC=$?"',
        ]
    )

    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert "RC=0" in result.stdout, result.stdout

    payloads = _read_incident_event_payloads(paths["workspace"])
    runtime_events = [
        payload
        for payload in payloads
        if str(payload.get("type") or "").startswith("runtime.")
    ]
    assert [payload["type"] for payload in runtime_events] == [
        "runtime.deviation_declared",
        "runtime.fallback_considered",
    ], runtime_events
    expected_digest = hashlib.sha256(paths["spec_path"].read_bytes()).hexdigest()
    for payload in runtime_events:
        assert payload["actor"] == "arnold-watchdog"
        assert payload["failure_class"] == "availability"
        assert payload["scope"] == f"chain:{paths['session']}"
        assert payload["session_id"] == paths["session"]
        assert payload["chain_spec_sha256"] == f"sha256:{expected_digest}"
    assert runtime_events[0]["error"] == (
        "watchdog observed unhealthy session; status-trigger babysitter dispatch requested"
    )
    assert runtime_events[0]["summary"] == (
        f"watchdog declared runtime deviation session={paths['session']}"
    )
    assert runtime_events[1]["summary"] == (
        f"watchdog considered status-trigger babysitter fallback session={paths['session']}"
    )
    # The enqueue branch must NOT have been taken: no repair request created.
    assert repair_requests.iter_repair_requests(
        repair_requests.repair_queue_dir(paths["marker_dir"])
    ) == []
    # The babysitter was actually launched (stub executed) and a receipt was
    # recorded with an occurrence-scoped one-shot run id.
    deadline = time.monotonic() + 5
    while not record_path.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert record_path.exists(), "babysitter stub was never launched"
    goal_path = Path(record_path.read_text(encoding="utf-8").strip())
    goal_text = goal_path.read_text(encoding="utf-8")
    # The rendered goal is the single-flash babysitter contract (exact
    # renderer wording is pinned in test_babysitter_goal.py).
    assert "BABYSITTER" in goal_text
    assert goal_text.strip().startswith("/goal")
    receipt_path = paths["repair_data_dir"] / f"{paths['session']}.babysitter-receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["schema"] == "arnold.superfixer.watchdog_dispatch_receipt.v1"
    assert receipt["status"] == "launched"
    assert receipt["session"] == paths["session"]
    assert int(receipt["babysitter_pid"]) > 0
    assert receipt["run_id"].startswith(
        "sched_superfixer_status_" + paths["session"].replace("/", "_")
    )
    # Occurrence-scoped: the run id carries the failure fingerprint digest.
    assert re.fullmatch(r"sched_superfixer_status_[A-Za-z0-9_.-]+_[0-9a-f]{12}", receipt["run_id"])
    assert receipt["renderer_path"].endswith(
        "skills/babysitter/scripts/render_babysitter_goal.py"
    )
    assert "arnold-r7-fresh-child-20260805" not in receipt["renderer_path"]
    assert receipt["goal_path"] == str(goal_path)


def test_watchdog_manual_review_superfixer_launch_failure_fails_closed(tmp_path: Path) -> None:
    """A babysitter that dies immediately with a non-zero rc fails closed:
    RC=1, no dispatch receipt, no enqueue — and the caller reports
    babysitter_launch_failed with no L1/L2 fallthrough."""
    paths = _prepare_watchdog_superfixer_fixture(tmp_path)
    script = "\n\n".join(
        [
            _extract_wrapper_function("babysitter_occurrence_digest"),
            _extract_wrapper_function("launch_status_trigger_babysitter"),
            f"MARKER_DIR={str(paths['marker_dir'])!r}",
            f"REPAIR_DATA_DIR={str(paths['repair_data_dir'])!r}",
            f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            "export CLOUD_WATCHDOG_BABYSITTER_BIN=" + shlex.quote(str(paths['stub_bin'])) + "",
            "export ARNOLD_BABYSITTER_LAUNCH_GRACE_SECS=1.5",
            "export BABYSITTER_TEST_EXIT=1",
            (
                "digest=\"$(babysitter_occurrence_digest "
                f"{shlex.quote(paths['session'])} {shlex.quote(str(paths['workspace']))} "
                f"{shlex.quote(str(paths['spec_path']))} plan {shlex.quote(paths['plan_name'])})\""
            ),
            (
                "launch_status_trigger_babysitter "
                f"{shlex.quote(paths['session'])} {shlex.quote(str(paths['workspace']))} "
                f"{shlex.quote(str(paths['spec_path']))} plan {shlex.quote(paths['plan_name'])} "
                f"{shlex.quote(str(tmp_path / 'report.tsv'))} \"$digest\""
            ),
            'echo "RC=$?"',
        ]
    )

    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert "RC=1" in result.stdout, result.stdout
    receipt_path = paths["repair_data_dir"] / f"{paths['session']}.babysitter-receipt.json"
    assert not receipt_path.exists()
    assert "babysitter exited early rc=1" in result.stderr
    assert repair_requests.iter_repair_requests(
        repair_requests.repair_queue_dir(paths["marker_dir"])
    ) == []


def test_watchdog_manual_review_superfixer_resolves_renderer_from_live_engine(
    tmp_path: Path,
) -> None:
    """The status trigger resolves the goal renderer from the LIVE engine
    (the manifest runtime root), never the hardcoded stale arnold-r7 tree."""
    paths = _prepare_watchdog_superfixer_fixture(tmp_path)
    live_root = tmp_path / "live-engine"
    renderer_dir = (
        live_root
        / "arnold_pipelines"
        / "megaplan"
        / "skills"
        / "babysitter"
        / "scripts"
    )
    renderer_dir.mkdir(parents=True)
    marker_file = tmp_path / "renderer-marker.txt"
    manifest_dir = tmp_path / "runtime-manifests"
    manifest_dir.mkdir()
    (manifest_dir / f"{paths['session']}.json").write_text(
        json.dumps({"epic": {"runtime_root": str(live_root)}}),
        encoding="utf-8",
    )
    # The live-engine fixture owns the renderer, while the extracted launcher
    # still imports the checkout's ledger/chain helpers.  Keep that import
    # dependency explicit in the fixture; production binds PYTHONPATH to the
    # session engine and must not fall back to the watchdog's ambient root.
    (live_root / "sitecustomize.py").write_text(
        f"import sys\nsys.path.insert(0, {str(REPO_ROOT)!r})\n",
        encoding="utf-8",
    )
    (renderer_dir / "render_babysitter_goal.py").write_text(
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\n"
        "import os\n"
        "def render_babysitter_goal(target, *, workspace='', plan='', run_kind='', "
        "latest_failure=None, planner_repair=None, occurrence_digest='', recovery_dir=''):\n"
        "    Path(os.environ['LIVE_RENDERER_MARKER']).write_text(target + '\\n')\n"
        "    return '/goal live-engine babysitter swarm Sol recovery_handoff\\n'\n",
        encoding="utf-8",
    )
    script = "\n\n".join(
        [
            _extract_wrapper_function("babysitter_occurrence_digest"),
            _extract_wrapper_function("launch_status_trigger_babysitter"),
            f"MARKER_DIR={str(paths['marker_dir'])!r}",
            f"REPAIR_DATA_DIR={str(paths['repair_data_dir'])!r}",
            f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            f"MANIFEST_RUNTIME_ROOT={str(live_root)!r}",
            f"export ARNOLD_RUNTIME_MANIFEST_DIR={str(manifest_dir)!r}",
            "export CLOUD_WATCHDOG_BABYSITTER_BIN=" + shlex.quote(str(paths['stub_bin'])) + "",
            "export ARNOLD_BABYSITTER_LAUNCH_GRACE_SECS=0.2",
            f"export LIVE_RENDERER_MARKER={str(marker_file)!r}",
            (
                "digest=\"$(babysitter_occurrence_digest "
                f"{shlex.quote(paths['session'])} {shlex.quote(str(paths['workspace']))} "
                f"{shlex.quote(str(paths['spec_path']))} plan {shlex.quote(paths['plan_name'])})\""
            ),
            (
                "launch_status_trigger_babysitter "
                f"{shlex.quote(paths['session'])} {shlex.quote(str(paths['workspace']))} "
                f"{shlex.quote(str(paths['spec_path']))} plan {shlex.quote(paths['plan_name'])} "
                f"{shlex.quote(str(tmp_path / 'report.tsv'))} \"$digest\""
            ),
            'echo "RC=$?"',
        ]
    )

    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert "RC=0" in result.stdout, result.stdout
    assert marker_file.read_text(encoding="utf-8").strip() == paths["session"]
    receipt = json.loads(
        (
            paths["repair_data_dir"] / f"{paths['session']}.babysitter-receipt.json"
        ).read_text(encoding="utf-8")
    )
    assert str(renderer_dir / "render_babysitter_goal.py") == receipt["renderer_path"]
    assert str(live_root) == receipt["engine_root"]
    assert "arnold-r7-fresh-child-20260805" not in receipt["renderer_path"]


def test_watchdog_manual_review_superfixer_ledger_failure_blocks(tmp_path: Path) -> None:
    """A runtime transition ledger write failure aborts
    launch_status_trigger_babysitter BEFORE the babysitter launch side
    effect — no dispatch receipt / repair request is created (no event = no
    side effect)."""
    paths = _prepare_watchdog_superfixer_fixture(tmp_path)
    # Sabotage the ledger: the incident-ledger directory cannot be created.
    (paths["workspace"] / ".megaplan").mkdir(exist_ok=True)
    (paths["workspace"] / ".megaplan" / "incident-ledger").write_text(
        "not a directory", encoding="utf-8"
    )

    script = "\n\n".join(
        [
            _extract_wrapper_function("babysitter_occurrence_digest"),
            _extract_wrapper_function("launch_status_trigger_babysitter"),
            f"MARKER_DIR={str(paths['marker_dir'])!r}",
            f"REPAIR_DATA_DIR={str(paths['repair_data_dir'])!r}",
            f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            "export CLOUD_WATCHDOG_BABYSITTER_BIN=" + shlex.quote(str(paths['stub_bin'])) + "",
            (
                "digest=\"$(babysitter_occurrence_digest "
                f"{shlex.quote(paths['session'])} {shlex.quote(str(paths['workspace']))} "
                f"{shlex.quote(str(paths['spec_path']))} plan {shlex.quote(paths['plan_name'])})\""
            ),
            (
                "launch_status_trigger_babysitter "
                f"{shlex.quote(paths['session'])} {shlex.quote(str(paths['workspace']))} "
                f"{shlex.quote(str(paths['spec_path']))} plan {shlex.quote(paths['plan_name'])} "
                f"{shlex.quote(str(tmp_path / 'report.tsv'))} \"$digest\""
            ),
            'echo "RC=$?"',
        ]
    )

    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert "RC=1" in result.stdout, result.stdout
    assert repair_requests.iter_repair_requests(
        repair_requests.repair_queue_dir(paths["marker_dir"])
    ) == []
    assert _read_incident_event_payloads(paths["workspace"]) == []
    assert not (
        paths["repair_data_dir"] / f"{paths['session']}.babysitter-receipt.json"
    ).exists()


def test_watchdog_chain_session_is_not_short_circuited_by_done_plan_state(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    plan_name = "demo-plan"
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    _write_live_session_marker(
        marker_dir,
        "demo-chain",
        workspace,
        ".megaplan/initiatives/demo-chain/chain.yaml",
        run_kind="chain",
    )
    _write_plan(
        workspace / ".megaplan" / "plans" / plan_name,
        {"iteration": 1, "current_state": "done", "active_step": None},
        events_body="{}\n",
    )
    report_path = tmp_path / "report.tsv"

    script = "\n\n".join(
        [
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function("plan_terminal_status"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { :; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
kimi_operator_running() { return 1; }
kimi_dispatch_marker_set() { :; }
mechanical_relaunch_attempted_previously() { return 1; }
kimi_dispatch_failed_previously() { return 1; }
dispatch_kimi_repair() { echo DISPATCH >&2; return 0; }
repair_unhealthy_session() { echo REPAIR >&2; return 0; }
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH; }
safe_name() { printf '%s\n' "$1"; }
tmux() {
  if [[ "$1" == "has-session" || "$3" == "has-session" ]]; then
    return 1
  fi
  if [[ "$1" == "new-session" || "$3" == "new-session" ]]; then
    echo TMUX_NEW >&2
    return 0
  fi
  echo "TMUX_$1" >&2
  return 0
}
plan_attention_status_env() {
  cat <<'EOF'
PLAN_STATUS_FOUND='0'
PLAN_STATUS_PLAN_NAME=''
PLAN_STATUS_CURRENT_STATE=''
PLAN_STATUS_RETRY_STRATEGY=''
PLAN_STATUS_FAILURE_KIND=''
PLAN_STATUS_FAILURE_MESSAGE=''
PLAN_STATUS_FAILURE_PHASE=''
PLAN_STATUS_FAILURE_RECORDED_AT=''
PLAN_STATUS_TIERS_TRIED=''
PLAN_STATUS_PUSHED_COMMITS=''
PLAN_STATUS_MANUAL_REVIEW='0'
EOF
}
""".strip(),
            f"launch_chain_tick demo-chain {str(workspace)!r} .megaplan/initiatives/demo-chain/chain.yaml {str(report_path)!r} chain '' ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\trestart\trestarted\tstopped session relaunched\t" in report
    assert "\tobserve\tcomplete\t" not in report
    assert "BABYSITTER" not in result.stderr
    assert "REPAIR" not in result.stderr
    assert "TMUX_NEW" in result.stderr


def test_watchdog_unreadable_plan_state_falls_through_to_existing_stopped_path(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    plan_name = "demo-plan"
    _write_live_session_marker(
        marker_dir,
        "demo-session",
        workspace,
        ".megaplan/initiatives/demo/briefs/demo.md",
        run_kind="plan",
        plan_name=plan_name,
    )
    plan_dir = workspace / ".megaplan" / "plans" / plan_name
    plan_dir.mkdir(parents=True, exist_ok=True)
    (plan_dir / "state.json").write_text("{not-json\n", encoding="utf-8")
    report_path = tmp_path / "report.tsv"

    script = "\n\n".join(
        [
            _extract_wrapper_function("kimi_dispatch_marker_path"),
            _extract_wrapper_function("kimi_pgid_path"),
            _extract_wrapper_function("kimi_dispatch_marker_set"),
            _extract_wrapper_function("mechanical_relaunch_attempted_previously"),
            _extract_wrapper_function("kimi_dispatch_failed_previously"),
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function("plan_terminal_status"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { :; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
kimi_operator_running() { return 1; }
dispatch_kimi_repair() { echo DISPATCH >&2; return 0; }
repair_unhealthy_session() { echo REPAIR >&2; return 0; }
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH; }
safe_name() { printf '%s\n' "$1"; }
tmux() {
  if [[ "$1" == "has-session" || "$3" == "has-session" ]]; then
    return 1
  fi
  if [[ "$1" == "new-session" || "$3" == "new-session" ]]; then
    echo TMUX_NEW >&2
    return 0
  fi
  echo "TMUX_$1" >&2
  return 0
}
""".strip(),
            f"launch_chain_tick demo-session {str(workspace)!r} .megaplan/initiatives/demo/briefs/demo.md {str(report_path)!r} chain {plan_name!r} ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\trestart\trestarted\tstopped session relaunched\t" in report
    assert "\tobserve\tcomplete\t" not in report
    assert "BABYSITTER" not in result.stderr
    assert "REPAIR" not in result.stderr
    assert "TMUX_NEW" in result.stderr


def test_watchdog_manual_review_chain_state_reports_needs_human_without_relaunch_or_kimi(
    tmp_path: Path,
) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    plan_name = "demo-plan"
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    _write_live_session_marker(
        marker_dir,
        "demo-chain",
        workspace,
        ".megaplan/initiatives/demo-chain/chain.yaml",
        run_kind="chain",
        plan_name=plan_name,
    )
    _write_plan(
        workspace / ".megaplan" / "plans" / plan_name,
        {
            "iteration": 9,
            "current_state": "blocked",
            "resume_cursor": {"phase": "recover-blocked", "retry_strategy": "manual_review"},
            "latest_failure": {"kind": "iteration_cap", "message": "exceeded max_iterations=200"},
            "history": [
                {
                    "step": "execute",
                    "result": "blocked",
                    "batch_to_tier": [
                        {"actual_agent": "codex", "actual_model": "gpt-5.4"},
                        {"tier_model_spec": "codex:gpt-5.5"},
                    ],
                }
            ],
        },
        events_body="{}\n",
    )
    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    chain_dir.mkdir(parents=True, exist_ok=True)
    import hashlib

    digest = hashlib.sha1(str(spec_path.resolve()).encode("utf-8")).hexdigest()[:12]
    (chain_dir / f"{spec_path.stem}-{digest}.json").write_text(
        json.dumps(
            {
                "current_plan_name": plan_name,
                "last_state": "blocked",
                "last_pushed_commit": "abc123def456",
            }
        ),
        encoding="utf-8",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"
    # This branch intentionally exercises the status-trigger babysitter
    # dispatch boundary.  Keep the child at the test boundary so the
    # candidate checkout cannot run a real continuation probe or publish
    # babysitter receipts into its working tree.
    babysitter_bin = tmp_path / "babysitter-stub"
    babysitter_bin.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    babysitter_bin.chmod(0o755)
    repair_data_dir = tmp_path / "repair-data"
    repair_data_dir.mkdir()
    operation_root = tmp_path / "operation"
    operation_root.mkdir()

    script = "\n\n".join(
        [
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(repair_data_dir)!r}",
            f"LOG={str(log_path)!r}",
            f"export CLOUD_WATCHDOG_BABYSITTER_BIN={shlex.quote(str(babysitter_bin))}",
            f"export ARNOLD_BASE_DIR={shlex.quote(str(operation_root))}",
            "export ARNOLD_CHAIN_SESSION=demo-chain",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() { echo stopped; }
session_terminal_status() { return 0; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
kimi_operator_running() { return 1; }
resolve_existing_remote_spec() { printf '%s\n' "$3"; }
dispatch_kimi_repair() { echo DISPATCH >&2; return 0; }
repair_unhealthy_session() { echo REPAIR >&2; return 0; }
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH; }
notify_needs_human() {
  report_item "$1" "$2" "observe" "needs_human" "$7" "$3" "$4"
  log "needs-human webhook unset"
}
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
""".strip(),
            f"launch_chain_tick demo-chain {str(workspace)!r} .megaplan/initiatives/demo-chain/chain.yaml {str(report_path)!r} chain '' ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\trepair\tbabysitter_" in report
    assert "parked pre-execute stall (plan born, no driver)" in report
    assert "demo-chain" in report
    assert ".megaplan/initiatives/demo-chain/chain.yaml" in report
    assert "BABYSITTER" not in result.stderr
    assert "REPAIR" not in result.stderr
    assert "TMUX" not in result.stderr
    assert "needs-human webhook unset" not in log_path.read_text(encoding="utf-8")


def test_watchdog_manual_review_repairable_fixture_dispatches_l1_without_needs_human(
    tmp_path: Path,
) -> None:
    marker_dir = tmp_path / "markers"
    repair_data_dir = marker_dir / "repair-data"
    marker_dir.mkdir()
    repair_data_dir.mkdir()
    workspace = tmp_path / "ws"
    plan_name = "agentic-replay-viewer"
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    _write_plan(
        workspace / ".megaplan" / "plans" / plan_name,
        {
            "iteration": 4,
            "name": plan_name,
            "current_state": "blocked",
            "resume_cursor": {"phase": "execute", "retry_strategy": "manual_review"},
            "latest_failure": {
                "kind": "blocked_recovery_not_resolved",
                "message": "repairable blocker",
                "phase": "execute",
                "metadata": {"blocked_task_id": "T1"},
            },
        },
        events_body="{}\n",
    )
    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    chain_dir.mkdir(parents=True, exist_ok=True)
    import hashlib

    digest = hashlib.sha1(str(spec_path.resolve()).encode("utf-8")).hexdigest()[:12]
    (chain_dir / f"{spec_path.stem}-{digest}.json").write_text(
        json.dumps({"current_plan_name": plan_name, "last_state": "blocked"}),
        encoding="utf-8",
    )
    _write_live_session_marker(
        marker_dir,
        "demo-chain",
        workspace,
        str(spec_path),
        run_kind="chain",
        plan_name=plan_name,
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(repair_data_dir)!r}",
            f"LOG={str(log_path)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() { echo stopped; }
session_terminal_status() { return 0; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
kimi_operator_running() { return 1; }
repair_loop_busy_state() { echo none; }
resolve_existing_remote_spec() { printf '%s\n' "$3"; }
babysitter_effective_mode() { printf 'superfixer\t\n'; }
babysitter_occurrence_digest() { echo a9c062b1cfe5; }
babysitter_running_for_occurrence() { return 1; }
babysitter_after_elapsed() { return 0; }
launch_status_trigger_babysitter() { echo BABYSITTER >&2; return 0; }
babysitter_policy_dispatch() {
  launch_status_trigger_babysitter "$@"
  report_item "$6" "$1" "repair" "babysitter_scheduled" "single-flash babysitter dispatched: $7" "$2" "$3"
}
repair_unhealthy_session() { echo REPAIR >&2; return 0; }
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH; }
notify_needs_human() {
  report_item "$1" "$2" "observe" "needs_human" "$7" "$3" "$4"
  log "needs-human webhook unset"
}
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
""".strip(),
            f"launch_chain_tick demo-chain {str(workspace)!r} .megaplan/initiatives/demo-chain/chain.yaml {str(report_path)!r} chain '' ''",
        ]
    )
    result = _run_watchdog_shell(script)

    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\trepair\tbabysitter_scheduled\tsingle-flash babysitter dispatched: parked pre-execute stall (plan born, no driver)" in report
    assert "\tobserve\tneeds_human\t" not in report
    assert "BABYSITTER" in result.stderr
    assert "needs-human webhook unset" not in log_path.read_text(encoding="utf-8")


def test_watchdog_execution_blocked_manual_review_dispatches_l1_without_needs_human(
    tmp_path: Path,
) -> None:
    marker_dir = tmp_path / "markers"
    repair_data_dir = marker_dir / "repair-data"
    marker_dir.mkdir()
    repair_data_dir.mkdir()
    workspace = tmp_path / "ws"
    plan_name = "progress-auditor-stage-20260704-1400"
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    _write_plan(
        workspace / ".megaplan" / "plans" / plan_name,
        {
            "iteration": 8,
            "name": plan_name,
            "current_state": "blocked",
            "resume_cursor": {"phase": "execute", "retry_strategy": "manual_review"},
            "latest_failure": {
                "kind": "blocked_recovery_not_resolved",
                "message": "execute reported prerequisite-blocked tasks: T4",
                "phase": "execute",
                "metadata": {"blocking_reasons": ["T4 fixture evidence not surfaced"]},
            },
        },
        events_body="{}\n",
    )
    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    chain_dir.mkdir(parents=True, exist_ok=True)
    import hashlib

    digest = hashlib.sha1(str(spec_path.resolve()).encode("utf-8")).hexdigest()[:12]
    (chain_dir / f"{spec_path.stem}-{digest}.json").write_text(
        json.dumps({"current_plan_name": plan_name, "last_state": "blocked"}),
        encoding="utf-8",
    )
    _write_live_session_marker(
        marker_dir,
        "demo-chain",
        workspace,
        str(spec_path),
        run_kind="chain",
        plan_name=plan_name,
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(repair_data_dir)!r}",
            f"LOG={str(log_path)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() { echo stopped; }
session_terminal_status() { return 0; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
kimi_operator_running() { return 1; }
repair_loop_busy_state() { echo none; }
resolve_existing_remote_spec() { printf '%s\n' "$3"; }
babysitter_effective_mode() { printf 'superfixer\t\n'; }
babysitter_occurrence_digest() { echo a9c062b1cfe5; }
babysitter_running_for_occurrence() { return 1; }
babysitter_after_elapsed() { return 0; }
launch_status_trigger_babysitter() { echo BABYSITTER >&2; return 0; }
babysitter_policy_dispatch() {
  launch_status_trigger_babysitter "$@"
  report_item "$6" "$1" "repair" "babysitter_scheduled" "single-flash babysitter dispatched: $7" "$2" "$3"
}
repair_unhealthy_session() { echo REPAIR >&2; return 0; }
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH; }
notify_needs_human() {
  report_item "$1" "$2" "observe" "needs_human" "$7" "$3" "$4"
  log "needs-human webhook unset"
}
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
""".strip(),
            f"launch_chain_tick demo-chain {str(workspace)!r} .megaplan/initiatives/demo-chain/chain.yaml {str(report_path)!r} chain '' ''",
        ]
    )
    result = _run_watchdog_shell(script)

    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\trepair\tbabysitter_scheduled\tsingle-flash babysitter dispatched: parked pre-execute stall (plan born, no driver)" in report
    assert "\tobserve\tneeds_human\t" not in report
    assert "BABYSITTER" in result.stderr
    assert "needs-human webhook unset" not in log_path.read_text(encoding="utf-8")


def test_watchdog_awaiting_human_chain_state_dispatches_repair_before_needs_human(
    tmp_path: Path,
) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    plan_name = "demo-plan"
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    _write_live_session_marker(
        marker_dir,
        "demo-chain",
        workspace,
        ".megaplan/initiatives/demo-chain/chain.yaml",
        run_kind="chain",
        plan_name=plan_name,
    )
    plan_dir = workspace / ".megaplan" / "plans" / plan_name
    _write_plan(
        plan_dir,
        {
            "iteration": 9,
            "current_state": "finalized",
        },
        events_body="{}\n",
    )
    (plan_dir / "finalize.json").write_text(
        json.dumps(
            {
                "tasks": [
                    {
                        "id": "m7-06-runtime-deletion-target-purge",
                        "description": "Delete runtime targets.",
                        "status": "blocked",
                    }
                ],
                "user_actions": [
                    {
                        "id": "ua-01-reclassify-deletion-targets",
                        "phase": "before_execute",
                        "blocks_task_ids": ["m7-06-runtime-deletion-target-purge"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    chain_dir.mkdir(parents=True, exist_ok=True)
    import hashlib

    digest = hashlib.sha1(str(spec_path.resolve()).encode("utf-8")).hexdigest()[:12]
    (chain_dir / f"{spec_path.stem}-{digest}.json").write_text(
        json.dumps(
            {
                "current_plan_name": plan_name,
                "last_state": "awaiting_human",
            }
        ),
        encoding="utf-8",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            _extract_wrapper_function("repair_needs_human_path"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"LOG={str(log_path)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
babysitter_effective_mode() { printf 'superfixer\t\n'; }
babysitter_occurrence_digest() { echo a9c062b1cfe5; }
babysitter_running_for_occurrence() { return 1; }
babysitter_after_elapsed() { return 0; }
launch_status_trigger_babysitter() { echo BABYSITTER >&2; return 0; }
babysitter_policy_dispatch() {
  launch_status_trigger_babysitter "$@"
  report_item "$6" "$1" "repair" "babysitter_scheduled" "single-flash babysitter dispatched: $7" "$2" "$3"
}
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH; }
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
""".strip(),
            f"launch_chain_tick demo-chain {str(workspace)!r} .megaplan/initiatives/demo-chain/chain.yaml {str(report_path)!r} chain '' ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\trepair\tbabysitter_scheduled\tsingle-flash babysitter dispatched: parked pre-execute stall (plan born, no driver)" in report
    assert "\tobserve\tneeds_human\t" not in report
    assert "BABYSITTER" in result.stderr
    assert "REPAIR" not in result.stderr
    assert "RELAUNCH" not in result.stderr
    assert "TMUX" not in result.stderr
    assert "needs-human webhook unset" not in log_path.read_text(encoding="utf-8")


def test_watchdog_awaiting_human_verify_chain_state_routes_to_notification_before_relaunch(
    tmp_path: Path,
) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    plan_name = "demo-plan"
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    _write_live_session_marker(
        marker_dir,
        "demo-session",
        workspace,
        ".megaplan/initiatives/demo-chain/chain.yaml",
        run_kind="chain",
        plan_name=plan_name,
    )
    _write_plan(
        workspace / ".megaplan" / "plans" / plan_name,
        {
            "iteration": 1,
            "current_state": "awaiting_human_verify",
            "clarification": {
                "intent_summary": "prep surfaced 2 blocking ambiguities; answer and resume",
                "questions": ["Q1", "Q2"],
                "source": "prep",
            },
        },
        events_body="{}\n",
    )
    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    chain_dir.mkdir(parents=True, exist_ok=True)
    import hashlib

    digest = hashlib.sha1(str(spec_path.resolve()).encode("utf-8")).hexdigest()[:12]
    (chain_dir / f"{spec_path.stem}-{digest}.json").write_text(
        json.dumps(
            {
                "current_plan_name": plan_name,
                "last_state": "awaiting_human_verify",
            }
        ),
        encoding="utf-8",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            _extract_wrapper_function("repair_needs_human_path"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"LOG={str(log_path)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
babysitter_effective_mode() { printf 'superfixer\t\n'; }
babysitter_occurrence_digest() { echo a9c062b1cfe5; }
babysitter_running_for_occurrence() { return 1; }
babysitter_after_elapsed() { return 0; }
launch_status_trigger_babysitter() { echo BABYSITTER >&2; return 0; }
babysitter_policy_dispatch() {
  launch_status_trigger_babysitter "$@"
  report_item "$6" "$1" "repair" "babysitter_scheduled" "single-flash babysitter dispatched: $7" "$2" "$3"
}
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH >&2; return 1; }
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
chain_health_status() {
  CHAIN_HEALTH_STATUS=ok
  CHAIN_HEALTH_SUMMARY=
  CHAIN_HEALTH_ARTIFACT_PATH=
  CHAIN_HEALTH_LOG_MESSAGE=
}
""".strip(),
            f"launch_chain_tick demo-session {str(workspace)!r} {str(spec_path)!r} {str(report_path)!r} chain '' ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\trepair\trepair_dispatched\t" not in report
    assert "\tnotify\ttest_notification_suppressed\t" in report
    assert "\trestart\trestarted\tstopped session relaunched\t" not in report
    assert "BABYSITTER" not in result.stderr
    assert "RELAUNCH" not in result.stderr
    assert "TMUX" not in result.stderr
    assert "REPAIR" not in result.stderr


def test_watchdog_completed_chain_state_reports_complete_without_repair(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    chain_dir.mkdir(parents=True, exist_ok=True)
    import hashlib

    digest = hashlib.sha1(str(spec_path.resolve()).encode("utf-8")).hexdigest()[:12]
    (chain_dir / f"{spec_path.stem}-{digest}.json").write_text(
        json.dumps(
            {
                "current_plan_name": "",
                "current_state": "",
                "last_state": "done",
                "events": [{"msg": "all milestones complete"}],
            }
        ),
        encoding="utf-8",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"LOG={str(log_path)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
babysitter_effective_mode() { printf 'superfixer\t\n'; }
babysitter_occurrence_digest() { echo a9c062b1cfe5; }
babysitter_running_for_occurrence() { return 1; }
babysitter_after_elapsed() { return 0; }
launch_status_trigger_babysitter() { echo BABYSITTER >&2; return 0; }
babysitter_policy_dispatch() {
  launch_status_trigger_babysitter "$@"
  report_item "$6" "$1" "repair" "babysitter_scheduled" "single-flash babysitter dispatched: $7" "$2" "$3"
}
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH >&2; return 1; }
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
""".strip(),
            f"launch_chain_tick demo-chain {str(workspace)!r} .megaplan/initiatives/demo-chain/chain.yaml {str(report_path)!r} chain '' ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\tobserve\tcomplete\tchain complete\t" in report
    assert "BABYSITTER" not in result.stderr
    assert "REPAIR" not in result.stderr
    assert "RELAUNCH" not in result.stderr
    assert "TMUX" not in result.stderr


def test_watchdog_partial_done_chain_state_relaunches_next_milestone(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    repair_data_dir = marker_dir / "repair-data"
    repair_data_dir.mkdir()
    workspace = tmp_path / "ws"
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text(
        "milestones:\n"
        "- label: m1\n"
        "- label: m2\n"
        "- label: m3\n"
        "- label: m4\n"
        "- label: m5\n",
        encoding="utf-8",
    )
    _write_live_session_marker(
        marker_dir,
        "demo-chain",
        workspace,
        str(spec_path),
        run_kind="chain",
    )
    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    chain_dir.mkdir(parents=True, exist_ok=True)
    import hashlib

    digest = hashlib.sha1(str(spec_path.resolve()).encode("utf-8")).hexdigest()[:12]
    (chain_dir / f"{spec_path.stem}-{digest}.json").write_text(
        json.dumps(
            {
                "current_milestone_index": 3,
                "current_plan_name": None,
                "last_state": "done",
                "pr_number": None,
                "pr_state": None,
                "completed": [
                    {"label": "m1", "status": "done"},
                    {"label": "m2", "status": "done"},
                    {"label": "m3", "status": "done"},
                ],
            }
        ),
        encoding="utf-8",
    )
    (chain_dir / "chain-stale-complete.json").write_text(
        json.dumps(
            {
                "current_plan_name": "",
                "last_state": "done",
                "events": [{"msg": "all milestones complete"}],
            }
        ),
        encoding="utf-8",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function("session_terminal_status"),
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(repair_data_dir)!r}",
            f"LOG={str(log_path)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
chain_health_status() { CHAIN_HEALTH_STATUS=ok; CHAIN_HEALTH_KIND=; CHAIN_HEALTH_SUMMARY=; return 0; }
kimi_operator_running() { return 1; }
repair_loop_busy_state() { echo none; }
repair_needs_human_path() { printf '%s\n' /no/such/repair-needs-human.json; }
dispatch_kimi_repair() { echo DISPATCH >&2; return 0; }
repair_unhealthy_session() { echo REPAIR >&2; return 0; }
ensure_install_or_repair() { return 0; }
mechanical_relaunch_attempted_previously() { return 1; }
kimi_dispatch_failed_previously() { return 1; }
kimi_dispatch_marker_set() { return 0; }
resolve_relaunch_command() { echo RELAUNCH >&2; return 0; }
babysitter_policy_dispatch() {
  echo BABYSITTER >&2
  report_item "$6" "$1" "repair" "babysitter_scheduled" \
    "single-flash babysitter dispatched: $7" "$2" "$3"
}
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 0; }
""".strip(),
            f"launch_chain_tick demo-chain {str(workspace)!r} .megaplan/initiatives/demo-chain/chain.yaml {str(report_path)!r} chain '' ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\tobserve\tcomplete\tchain complete\t" not in report
    assert "RELAUNCH" not in result.stderr
    assert "BABYSITTER" in result.stderr
    assert "parked pre-execute stall (plan born, no driver)" in report
    assert "REPAIR" not in result.stderr

def test_watchdog_missing_chain_spec_uses_terminal_chain_state_without_repair(
    tmp_path: Path,
) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    chain_dir.mkdir(parents=True, exist_ok=True)
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    import hashlib

    digest = hashlib.sha1(str(spec_path.resolve()).encode("utf-8")).hexdigest()[:12]
    (chain_dir / f"{spec_path.stem}-{digest}.json").write_text(
        json.dumps(
            {
                "current_plan_name": "",
                "current_state": "",
                "last_state": "done",
                "events": [{"msg": "all milestones complete"}],
            }
        ),
        encoding="utf-8",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("session_terminal_status"),
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(marker_dir / 'repair-data')!r}",
            f"LOG={str(log_path)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
babysitter_effective_mode() { printf 'superfixer\t\n'; }
babysitter_occurrence_digest() { echo a9c062b1cfe5; }
babysitter_running_for_occurrence() { return 1; }
babysitter_after_elapsed() { return 0; }
launch_status_trigger_babysitter() { echo BABYSITTER >&2; return 0; }
babysitter_policy_dispatch() {
  launch_status_trigger_babysitter "$@"
  report_item "$6" "$1" "repair" "babysitter_scheduled" "single-flash babysitter dispatched: $7" "$2" "$3"
}
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH >&2; return 1; }
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
""".strip(),
            f"launch_chain_tick demo-chain {str(workspace)!r} .megaplan/initiatives/demo-chain/chain.yaml {str(report_path)!r} chain '' ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\tobserve\tcomplete\tchain complete\t" in report
    assert "BABYSITTER" not in result.stderr
    assert "REPAIR" not in result.stderr
    assert "RELAUNCH" not in result.stderr
    assert "TMUX" not in result.stderr


def test_watchdog_missing_workspace_uses_completed_repair_history_without_repair(
    tmp_path: Path,
) -> None:
    marker_dir = tmp_path / "markers"
    repair_data_dir = marker_dir / "repair-data"
    marker_dir.mkdir()
    repair_data_dir.mkdir()
    workspace = tmp_path / "missing-ws"
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"
    (repair_data_dir / "demo-chain.repair-data.json").write_text(
        json.dumps(
            {
                "session": "demo-chain",
                "attempts": [
                    {
                        "failure_classification": "chain_completed",
                        "chain_state_summary": {
                            "current_plan_name": "",
                            "current_state": "",
                            "last_state": "done",
                            "events": [{"msg": "all milestones complete"}],
                        },
                        "failure_context": {
                            "failure_classification": "chain_completed",
                            "chain_state_summary": {
                                "current_plan_name": "",
                                "current_state": "",
                                "last_state": "done",
                            },
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    script = "\n\n".join(
        [
            _extract_wrapper_function("session_terminal_status"),
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(repair_data_dir)!r}",
            f"LOG={str(log_path)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
babysitter_effective_mode() { printf 'superfixer\t\n'; }
babysitter_occurrence_digest() { echo a9c062b1cfe5; }
babysitter_running_for_occurrence() { return 1; }
babysitter_after_elapsed() { return 0; }
launch_status_trigger_babysitter() { echo BABYSITTER >&2; return 0; }
babysitter_policy_dispatch() {
  launch_status_trigger_babysitter "$@"
  report_item "$6" "$1" "repair" "babysitter_scheduled" "single-flash babysitter dispatched: $7" "$2" "$3"
}
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH >&2; return 1; }
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
""".strip(),
            f"launch_chain_tick demo-chain {str(workspace)!r} /missing/demo-chain.yaml {str(report_path)!r} chain '' ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\tobserve\tcomplete\tchain complete\t" in report
    assert "BABYSITTER" not in result.stderr
    assert "REPAIR" not in result.stderr
    assert "RELAUNCH" not in result.stderr
    assert "TMUX" not in result.stderr


def _env_gone_script_blocks(*, marker_dir: Path, log_path: Path, report_path: Path, workspace: str, remote_spec: str) -> list[str]:
    """Shared script blocks for the env-gone watchdog tests."""
    return [
        _extract_wrapper_function("session_terminal_status"),
        _extract_wrapper_function("plan_attention_status_env"),
        _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
        _extract_wrapper_function("safe_name"),
        _extract_wrapper_function("session_marker_path"),
        _extract_wrapper_function("kimi_dispatch_marker_path"),
        _extract_wrapper_function("kimi_pgid_path"),
        _extract_wrapper_function("kimi_dispatch_marker_clear"),
        _extract_wrapper_function("repair_needs_human_path"),
        _extract_wrapper_function("chain_health_snapshot_path"),
        _extract_wrapper_function("chain_health_artifact_path"),
        _extract_wrapper_function("env_gone_sidecar_path"),
        _extract_wrapper_function("environment_gone_check"),
        _extract_wrapper_function("persist_environment_gone_outcome"),
        _extract_wrapper_function("clear_session_tracking_artifacts"),
        _extract_wrapper_function("launch_chain_tick"),
        "chain_engine_root_preflight() { return 0; }",
        f"MARKER_DIR={str(marker_dir)!r}",
        f"REPAIR_DATA_DIR={str(marker_dir / 'repair-data')!r}",
        f"LOG={str(log_path)!r}",
        """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
babysitter_effective_mode() { printf 'superfixer\t\n'; }
babysitter_occurrence_digest() { echo a9c062b1cfe5; }
babysitter_running_for_occurrence() { return 1; }
babysitter_after_elapsed() { return 0; }
launch_status_trigger_babysitter() { echo BABYSITTER >&2; return 0; }
babysitter_policy_dispatch() {
  launch_status_trigger_babysitter "$@"
  report_item "$6" "$1" "repair" "babysitter_scheduled" "single-flash babysitter dispatched: $7" "$2" "$3"
}
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH >&2; return 1; }
resolve_existing_remote_spec() { printf '%s\n' "$3"; }
safe_name() { printf '%s\\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
""".strip(),
    ]


def test_watchdog_env_gone_clears_artifacts_after_strikes_threshold(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    repair_data_dir = marker_dir / "repair-data"
    marker_dir.mkdir()
    repair_data_dir.mkdir()
    workspace = tmp_path / "wiped-ws"  # intentionally absent
    marker_file = _write_live_session_marker(
        marker_dir,
        "demo-chain",
        workspace,
        "/missing/demo-chain.yaml",
        run_kind="chain",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        _env_gone_script_blocks(
            marker_dir=marker_dir,
            log_path=log_path,
            report_path=report_path,
            workspace=str(workspace),
            remote_spec="/missing/demo-chain.yaml",
        )
        + [
            "ENV_GONE_STRIKES=1",
            f"launch_chain_tick demo-chain {str(workspace)!r} /missing/demo-chain.yaml {str(report_path)!r} chain '' ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\tobserve\tenvironment_gone\t" in report
    assert "BABYSITTER" not in result.stderr
    assert "REPAIR" not in result.stderr
    # Session is retired: marker and env-gone sidecar are gone.
    assert not marker_file.exists()
    assert not (marker_dir / "demo-chain.env-gone").exists()
    # Repair-data carries the environment_gone outcome for audit.
    repair_data = json.loads((repair_data_dir / "demo-chain.repair-data.json").read_text(encoding="utf-8"))
    assert repair_data["outcome"] == "environment_gone"


def test_watchdog_env_gone_below_threshold_does_not_clear(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    repair_data_dir = marker_dir / "repair-data"
    marker_dir.mkdir()
    repair_data_dir.mkdir()
    workspace = tmp_path / "wiped-ws"  # intentionally absent
    marker_file = _write_live_session_marker(
        marker_dir,
        "demo-chain",
        workspace,
        "/missing/demo-chain.yaml",
        run_kind="chain",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        _env_gone_script_blocks(
            marker_dir=marker_dir,
            log_path=log_path,
            report_path=report_path,
            workspace=str(workspace),
            remote_spec="/missing/demo-chain.yaml",
        )
        + [
            "ENV_GONE_STRIKES=3",
            f"launch_chain_tick demo-chain {str(workspace)!r} /missing/demo-chain.yaml {str(report_path)!r} chain '' ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\tobserve\tenv_gone_pending\t" in report
    assert "\tobserve\tenvironment_gone\t" not in report
    assert "BABYSITTER" not in result.stderr
    assert "REPAIR" not in result.stderr
    # Marker stays; sidecar records strike count = 1.
    assert marker_file.exists()
    sidecar = marker_dir / "demo-chain.env-gone"
    assert sidecar.exists()
    assert sidecar.read_text(encoding="utf-8").strip() == "1"
    # No environment_gone outcome is written below threshold.
    assert not (repair_data_dir / "demo-chain.repair-data.json").exists()


def test_watchdog_env_gone_with_completed_history_still_treated_as_complete(tmp_path: Path) -> None:
    """Regression guard: the env-gone gate is strictly below the terminal
    short-circuit, so a completed repair-data fixture wins over a wiped env."""
    marker_dir = tmp_path / "markers"
    repair_data_dir = marker_dir / "repair-data"
    marker_dir.mkdir()
    repair_data_dir.mkdir()
    workspace = tmp_path / "wiped-ws"  # intentionally absent
    (repair_data_dir / "demo-chain.repair-data.json").write_text(
        json.dumps(
            {
                "session": "demo-chain",
                "attempts": [
                    {
                        "failure_classification": "chain_completed",
                        "chain_state_summary": {
                            "current_plan_name": "",
                            "current_state": "",
                            "last_state": "done",
                            "events": [{"msg": "all milestones complete"}],
                        },
                        "failure_context": {
                            "failure_classification": "chain_completed",
                            "chain_state_summary": {
                                "current_plan_name": "",
                                "current_state": "",
                                "last_state": "done",
                            },
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        _env_gone_script_blocks(
            marker_dir=marker_dir,
            log_path=log_path,
            report_path=report_path,
            workspace=str(workspace),
            remote_spec="/missing/demo-chain.yaml",
        )
        + [
            "ENV_GONE_STRIKES=1",
            f"launch_chain_tick demo-chain {str(workspace)!r} /missing/demo-chain.yaml {str(report_path)!r} chain '' ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\tobserve\tcomplete\tchain complete\t" in report
    assert "\tobserve\tenvironment_gone\t" not in report
    assert "\tobserve\tenv_gone_pending\t" not in report


def test_watchdog_env_gone_recovers_when_workspace_returns(tmp_path: Path) -> None:
    """A transient deploy gap records strikes; when the workspace reappears the
    sidecar is cleared and the check signals present (fall-through to normal
    processing). Exercises environment_gone_check directly so the recovery
    contract is isolated from the terminal short-circuit above the gate."""
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    workspace.mkdir()
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    sidecar = marker_dir / "demo-chain.env-gone"
    sidecar.write_text("2\n", encoding="utf-8")
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("safe_name"),
            _extract_wrapper_function("env_gone_sidecar_path"),
            _extract_wrapper_function("environment_gone_check"),
            f"MARKER_DIR={str(marker_dir)!r}",
            f"LOG={str(log_path)!r}",
            """
log() { printf '%s\\n' "$*" >> "$LOG"; }
safe_name() { printf '%s\\n' "$1"; }
""".strip(),
            f"ENV_GONE_STRIKES=3",
            f"environment_gone_check demo-chain {str(workspace)!r} {str(spec_path)!r}",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 1, result.stderr
    assert result.stdout.strip() == "present"
    # Env present: the prior strike sidecar is cleared (transient-deploy recovery).
    assert not sidecar.exists()


def test_watchdog_missing_base_ref_chain_state_reports_needs_human_without_plan_state(
    tmp_path: Path,
) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    chain_dir.mkdir(parents=True, exist_ok=True)
    import hashlib

    digest = hashlib.sha1(str(spec_path.resolve()).encode("utf-8")).hexdigest()[:12]
    (chain_dir / f"{spec_path.stem}-{digest}.json").write_text(
        json.dumps(
            {
                "current_plan_name": None,
                "last_state": "missing_base_ref",
                "metadata": {
                    "missing_base_ref": {
                        "base_branch": "stack/base",
                        "last_known_sha": "abc123def456",
                        "message": "Base branch 'stack/base' is missing on origin and no local ref is available to restore it.",
                        "recorded_at": "2026-06-28T00:00:00Z",
                        "retry_strategy": "manual_review",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"LOG={str(log_path)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
kimi_operator_running() { return 1; }
dispatch_kimi_repair() { echo DISPATCH >&2; return 0; }
repair_unhealthy_session() { echo REPAIR >&2; return 0; }
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH; }
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
""".strip(),
            f"launch_chain_tick demo-chain {str(workspace)!r} .megaplan/initiatives/demo-chain/chain.yaml {str(report_path)!r} chain '' ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\tobserve\tneeds_human\tmanual_review halt;" in report
    assert "state=missing_base_ref" in report
    assert "failure=missing_base_ref" in report
    assert "missing_base_ref" in report
    assert "stack/base" in report
    assert "BABYSITTER" not in result.stderr
    assert "REPAIR" not in result.stderr
    assert "TMUX" not in result.stderr


def test_watchdog_normal_chain_state_does_not_force_missing_base_ref_manual_review(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "ws"
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    chain_dir.mkdir(parents=True, exist_ok=True)
    import hashlib

    digest = hashlib.sha1(str(spec_path.resolve()).encode("utf-8")).hexdigest()[:12]
    (chain_dir / f"{spec_path.stem}-{digest}.json").write_text(
        json.dumps(
            {
                "current_plan_name": None,
                "last_state": "blocked",
                "metadata": {"note": "not missing base ref"},
            }
        ),
        encoding="utf-8",
    )

    script = "\n\n".join(
        [
            _extract_wrapper_function("plan_attention_status_env"),
            f"eval \"$(plan_attention_status_env {str(workspace)!r} {str(spec_path)!r} chain '')\"",
            "printf '%s\\t%s\\t%s\\n' \"$PLAN_STATUS_MANUAL_REVIEW\" \"$PLAN_STATUS_FAILURE_KIND\" \"$PLAN_STATUS_CURRENT_STATE\"",
        ]
    )

    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "0"


def test_watchdog_scan_once_completes_when_chain_state_is_unreadable(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    workspace = tmp_path / "ws"
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    chain_dir.mkdir(parents=True, exist_ok=True)
    marker_path = marker_dir / "demo-session.json"
    marker_path.write_text(
        json.dumps(
            {
                "session": "demo-session",
                "workspace": str(workspace),
                "remote_spec": ".megaplan/initiatives/demo-chain/chain.yaml",
                "run_kind": "chain",
            }
        ),
        encoding="utf-8",
    )
    import hashlib

    digest = hashlib.sha1(str(spec_path.resolve()).encode("utf-8")).hexdigest()[:12]
    (chain_dir / f"{spec_path.stem}-{digest}.json").write_text("{not-json\n", encoding="utf-8")
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("json_field"),
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            _extract_wrapper_function("scan_once_unlocked"),
            _extract_wrapper_function("scan_once"),
            f"MARKER_DIR={str(marker_dir)!r}",
            f"LOG={str(log_path)!r}",
            f"SCAN_LOCK_FILE={str(tmp_path / 'watchdog-scan.lock')!r}",
            "SCAN_LOCK_WAIT_SECS=0",
            "COOPERATIVE_ONCE=0",
            "WATCHDOG_BOOTSTRAP_RECOVERED=0",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
bootstrap_watchdog_observation() { return 0; }
write_watchdog_sweep_health() { return 0; }
write_watchdog_heartbeat() { :; }
write_status_snapshot() { :; }
repair_trigger_scan() { :; }
run_repair_data_maintenance() { :; }
maybe_reexec_updated_watchdog() { :; }
sync_editable_source_branch() { return 0; }
bootstrap_watchdog_observation() { return 0; }
write_status_snapshot() { :; }
adopt_unmarked_tmux_sessions() { return 0; }
reap_stale_repairs() { return 0; }
emit_report() { cp "$1" REPORT_PATH_PLACEHOLDER; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
kimi_operator_running() { return 1; }
mechanical_relaunch_attempted_previously() { return 0; }
dispatch_kimi_repair() { echo DISPATCH >&2; return 0; }
kimi_dispatch_failed_previously() { return 1; }
kimi_dispatch_marker_set() { :; }
kimi_dispatch_marker_clear() { :; }
repair_unhealthy_session() { echo REPAIR >&2; return 0; }
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH; }
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
""".replace("REPORT_PATH_PLACEHOLDER", str(report_path)).strip(),
            "scan_once_unlocked",
        ]
    )

    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    log_text = log_path.read_text(encoding="utf-8")
    assert "current-target canonical-control session=demo-session" in log_text
    assert "scan complete markers=1" in log_text
    report = report_path.read_text(encoding="utf-8")
    assert "\tobserve\tliveness_unknown\t" in report
    assert "needs_human" not in report
    assert "BABYSITTER" not in result.stderr
    assert "REPAIR" not in result.stderr
    assert "TMUX" not in result.stderr


def test_watchdog_needs_human_webhook_is_deferred_to_durable_worker(tmp_path: Path) -> None:
    dm_helper = tmp_path / "arnold-discord-dm"
    dm_helper.write_text(
        "#!/usr/bin/env bash\n"
        "cat >/dev/null\n"
        "printf '%s\\n' '{\"ok\": false, \"reason\": \"send_failed\"}'\n",
        encoding="utf-8",
    )
    dm_helper.chmod(dm_helper.stat().st_mode | stat.S_IXUSR)

    curl_path = tmp_path / "curl"
    curl_path.write_text(
        "#!/usr/bin/env bash\n"
        f"echo called >> {str(tmp_path / 'curl-calls.txt')!r}\n"
        f"for arg in \"$@\"; do\n"
        "  case \"$arg\" in\n"
        f"    @*) cp \"${{arg#@}}\" {str(tmp_path / 'webhook-payload.json')!r} ;;\n"
        "  esac\n"
        "done\n",
        encoding="utf-8",
    )
    curl_path.chmod(curl_path.stat().st_mode | stat.S_IXUSR)

    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"
    notify_line = (
        f"notify_needs_human {str(report_path)!r} demo-session /tmp/ws "
        ".megaplan/initiatives/demo/briefs/demo.md chain stopped 'manual_review halt'"
    )
    script = "\n\n".join(
        [
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            f"LOG={str(log_path)!r}",
            f"DISCORD_DM_BIN={str(dm_helper)!r}",
            "REPORT_WEBHOOK='https://example.test/watchdog'",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
PLAN_STATUS_PLAN_NAME='demo-plan'
PLAN_STATUS_CURRENT_STATE='blocked'
PLAN_STATUS_RETRY_STRATEGY='manual_review'
PLAN_STATUS_FAILURE_KIND='iteration_cap'
PLAN_STATUS_FAILURE_MESSAGE='exceeded max_iterations=200'
PLAN_STATUS_FAILURE_PHASE='recover-blocked'
PLAN_STATUS_FAILURE_RECORDED_AT='2026-06-28T11:29:34Z'
PLAN_STATUS_TIERS_TRIED='codex:gpt-5.4, codex:gpt-5.5'
PLAN_STATUS_PUSHED_COMMITS='abc123def456'
""".strip(),
            notify_line,
        ]
    )
    result = _run_watchdog_shell(
        script, path_prefix=tmp_path, allow_notification_delivery=True
    )
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "curl-calls.txt").exists()
    assert not (tmp_path / "webhook-payload.json").exists()
    report = report_path.read_text(encoding="utf-8")
    assert "\tnotify\tnotification_intent_pending\t" in report


def test_watchdog_log_redacts_stdout_and_log_file(tmp_path: Path) -> None:
    log_path = tmp_path / "watchdog.log"
    script = "\n\n".join(
        [
            _extract_wrapper_function("redact_inline_text"),
            _extract_wrapper_function("log"),
            f"SRC_DIR={shlex.quote(str(REPO_ROOT))}",
            f"LOG={shlex.quote(str(log_path))}",
            "log 'Authorization: Bearer bearer-secret-token-value'",
        ]
    )

    result = _run_watchdog_shell(script)

    assert result.returncode == 0, result.stderr
    assert "bearer-secret-token-value" not in result.stdout
    assert f"Authorization: Bearer {REDACTION}" in result.stdout
    assert "bearer-secret-token-value" not in log_path.read_text(encoding="utf-8")


def test_watchdog_needs_human_launches_resident_diagnostic_instead_of_bare_dm(
    tmp_path: Path,
) -> None:
    diagnostic_helper = tmp_path / "arnold-human-review-diagnostic"
    diagnostic_helper.write_text(
        "#!/usr/bin/env bash\n"
        "payload=''\n"
        "while [[ $# -gt 0 ]]; do\n"
        "  if [[ \"$1\" == --payload-file ]]; then payload=\"$2\"; shift 2; else shift; fi\n"
        "done\n"
        f"cp \"$payload\" {str(tmp_path / 'diagnostic-payload.json')!r}\n"
        "printf '%s\\n' '{\"ok\":true,\"status\":\"launched\",\"run_id\":\"subagent-20260714-120000-abcdef12\",\"manifest_path\":\"/tmp/manifest.json\",\"state_path\":\"/tmp/state.json\",\"fallback_delivery_required\":false}'\n",
        encoding="utf-8",
    )
    diagnostic_helper.chmod(diagnostic_helper.stat().st_mode | stat.S_IXUSR)
    dm_helper = tmp_path / "arnold-discord-dm"
    dm_helper.write_text(
        "#!/usr/bin/env bash\n"
        f"cat > {str(tmp_path / 'dm-called.json')!r}\n"
        "printf '%s\\n' '{\"ok\": true, \"message_count\": 1}'\n",
        encoding="utf-8",
    )
    dm_helper.chmod(dm_helper.stat().st_mode | stat.S_IXUSR)

    curl_path = tmp_path / "curl"
    curl_path.write_text("#!/usr/bin/env bash\nexit 99\n", encoding="utf-8")
    curl_path.chmod(curl_path.stat().st_mode | stat.S_IXUSR)

    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"
    script = "\n\n".join(
        [
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            f"LOG={str(log_path)!r}",
            f"MARKER_DIR={str(tmp_path / 'markers')!r}",
            f"REPAIR_DATA_DIR={str(tmp_path / 'repair-data')!r}",
            f"DISCORD_DM_BIN={str(dm_helper)!r}",
            f"HUMAN_REVIEW_DIAGNOSTIC_BIN={str(diagnostic_helper)!r}",
            "REPORT_WEBHOOK='https://example.test/watchdog'",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
PLAN_STATUS_PLAN_NAME='demo-plan'
PLAN_STATUS_CURRENT_STATE='manual_review'
PLAN_STATUS_RETRY_STRATEGY='manual_review'
PLAN_STATUS_FAILURE_KIND='iteration_cap'
PLAN_STATUS_FAILURE_MESSAGE='exceeded max_iterations=200'
PLAN_STATUS_FAILURE_PHASE='recover-blocked'
PLAN_STATUS_FAILURE_RECORDED_AT='2026-06-28T11:29:34Z'
PLAN_STATUS_TIERS_TRIED='deepseek:flash, codex:gpt-5.4, codex:gpt-5.5'
PLAN_STATUS_PUSHED_COMMITS='abc123def456, fedcba654321'
""".strip(),
            f"notify_needs_human {str(report_path)!r} demo-session /tmp/ws .megaplan/initiatives/demo/briefs/demo.md chain stopped 'manual_review halt'",
        ]
    )

    result = _run_watchdog_shell(
        script, path_prefix=tmp_path, allow_notification_delivery=True
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads((tmp_path / "diagnostic-payload.json").read_text(encoding="utf-8"))
    assert payload["title"] == "Megaplan needs human review - demo-session"
    assert payload["plan"]["tiers_tried"] == ["deepseek:flash", "codex:gpt-5.4", "codex:gpt-5.5"]
    assert payload["plan"]["pushed_commit_shas"] == ["abc123def456", "fedcba654321"]
    assert any(field["label"] == "Tiers tried" and field["joiner"] == " -> " for field in payload["fields"])
    assert not (tmp_path / "dm-called.json").exists()
    report = report_path.read_text(encoding="utf-8")
    assert "\tnotify\tdiagnostic_agent_launched\t" in report
    assert "needs-human webhook delivered" not in log_path.read_text(encoding="utf-8")


def test_watchdog_stable_human_gate_launches_notification_agent_with_exact_gate(
    tmp_path: Path,
) -> None:
    diagnostic_helper = tmp_path / "arnold-human-review-diagnostic"
    diagnostic_helper.write_text(
        "#!/usr/bin/env bash\n"
        "payload=''\n"
        "while [[ $# -gt 0 ]]; do\n"
        "  if [[ \"$1\" == --payload-file ]]; then payload=\"$2\"; shift 2; else shift; fi\n"
        "done\n"
        f"cp \"$payload\" {str(tmp_path / 'stable-gate-payload.json')!r}\n"
        "printf '%s\\n' '{\"ok\":true,\"status\":\"launched\",\"run_id\":\"subagent-20260716-230000-feedface\",\"manifest_path\":\"/tmp/manifest.json\",\"state_path\":\"/tmp/state.json\",\"fallback_delivery_required\":false}'\n",
        encoding="utf-8",
    )
    diagnostic_helper.chmod(diagnostic_helper.stat().st_mode | stat.S_IXUSR)
    dm_helper = tmp_path / "arnold-discord-dm"
    dm_helper.write_text(
        "#!/usr/bin/env bash\n"
        f"cat > {str(tmp_path / 'stable-gate-dm-called.json')!r}\n",
        encoding="utf-8",
    )
    dm_helper.chmod(dm_helper.stat().st_mode | stat.S_IXUSR)
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"
    script = "\n\n".join(
        [
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            f"LOG={str(log_path)!r}",
            "MARKER_DIR=/tmp/stable-human-gate-markers",
            "REPAIR_DATA_DIR=/tmp/stable-human-gate-repair-data",
            f"DISCORD_DM_BIN={str(dm_helper)!r}",
            f"HUMAN_REVIEW_DIAGNOSTIC_BIN={str(diagnostic_helper)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
PLAN_STATUS_PLAN_NAME='demo-plan'
PLAN_STATUS_CURRENT_STATE='awaiting_human_verify'
PLAN_STATUS_RETRY_STRATEGY=''
PLAN_STATUS_FAILURE_KIND=''
PLAN_STATUS_FAILURE_MESSAGE=''
PLAN_STATUS_FAILURE_PHASE='prep'
PLAN_STATUS_FAILURE_RECORDED_AT='2026-07-16T22:06:58Z'
PLAN_STATUS_TIERS_TRIED=''
PLAN_STATUS_PUSHED_COMMITS=''
""".strip(),
            f"notify_needs_human {str(report_path)!r} demo-session /tmp/ws .megaplan/initiatives/demo/chain.yaml chain stopped 'awaiting_human halt; state=awaiting_human_verify; reason=prep clarification requires answer (1 question)' stable_human_gate",
        ]
    )

    result = _run_watchdog_shell(script, allow_notification_delivery=True)

    assert result.returncode == 0, result.stderr
    payload = json.loads((tmp_path / "stable-gate-payload.json").read_text(encoding="utf-8"))
    assert payload["notification_kind"] == "stable_human_gate"
    assert payload["human_gate"]["state_token"] == "awaiting_human_verify"
    assert "prep clarification requires answer" in payload["human_gate"]["reason"]
    assert "supported resume/verify transition" in payload["human_gate"]["required_action"]
    assert not (tmp_path / "stable-gate-dm-called.json").exists()
    assert "\tnotify\tdiagnostic_agent_launched\t" in report_path.read_text(encoding="utf-8")


def test_watchdog_needs_human_launch_failure_only_records_durable_pending_intent(
    tmp_path: Path,
) -> None:
    diagnostic_helper = tmp_path / "arnold-human-review-diagnostic"
    diagnostic_helper.write_text(
        "#!/usr/bin/env bash\n"
        "printf '%s\\n' '{\"ok\":false,\"status\":\"launch_failed\",\"error\":\"resident supervisor unavailable\",\"state_path\":\"\",\"fallback_delivery_required\":true}'\n"
        "exit 1\n",
        encoding="utf-8",
    )
    diagnostic_helper.chmod(diagnostic_helper.stat().st_mode | stat.S_IXUSR)
    dm_helper = tmp_path / "arnold-discord-dm"
    dm_helper.write_text(
        "#!/usr/bin/env bash\n"
        f"cat > {str(tmp_path / 'dm-payload.json')!r}\n"
        "printf '%s\\n' '{\"ok\":true,\"channel_id\":\"34\",\"message_ids\":[\"999\"],\"message_count\":1}'\n",
        encoding="utf-8",
    )
    dm_helper.chmod(dm_helper.stat().st_mode | stat.S_IXUSR)
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"
    script = "\n\n".join(
        [
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            f"LOG={str(log_path)!r}",
            f"MARKER_DIR={str(tmp_path / 'markers')!r}",
            f"REPAIR_DATA_DIR={str(tmp_path / 'repair-data')!r}",
            f"DISCORD_DM_BIN={str(dm_helper)!r}",
            f"HUMAN_REVIEW_DIAGNOSTIC_BIN={str(diagnostic_helper)!r}",
            "REPORT_WEBHOOK=''",
            "report_item() { printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \"$1\" \"$2\" \"$3\" \"$4\" \"$5\" \"$6\" \"$7\" >> \"$1\"; }",
            "log() { printf '%s\\n' \"$*\" >> \"$LOG\"; }",
            "PLAN_STATUS_PLAN_NAME='demo-plan'",
            "PLAN_STATUS_FAILURE_KIND='iteration_cap'",
            "PLAN_STATUS_FAILURE_MESSAGE='bounded repair exhausted'",
            f"notify_needs_human {str(report_path)!r} demo-session /tmp/ws /tmp/spec.yaml chain stopped 'manual_review halt'",
        ]
    )

    result = _run_watchdog_shell(
        script, path_prefix=tmp_path, allow_notification_delivery=True
    )
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "dm-payload.json").exists()
    assert "notification_intent_pending" in report_path.read_text(encoding="utf-8")


def test_watchdog_needs_human_fixture_workspace_cannot_reach_delivery(tmp_path: Path) -> None:
    dm_helper = tmp_path / "arnold-discord-dm"
    dm_helper.write_text(
        "#!/usr/bin/env bash\n"
        f"echo called > {str(tmp_path / 'dm-called')!r}\n",
        encoding="utf-8",
    )
    dm_helper.chmod(dm_helper.stat().st_mode | stat.S_IXUSR)
    curl_path = tmp_path / "curl"
    curl_path.write_text(
        "#!/usr/bin/env bash\n"
        f"echo called > {str(tmp_path / 'webhook-called')!r}\n",
        encoding="utf-8",
    )
    curl_path.chmod(curl_path.stat().st_mode | stat.S_IXUSR)
    fixture_workspace = tmp_path / "ws"
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"
    script = "\n\n".join(
        [
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            f"SRC_DIR={str(REPO_ROOT)!r}",
            f"LOG={str(log_path)!r}",
            f"DISCORD_DM_BIN={str(dm_helper)!r}",
            "REPORT_WEBHOOK='https://example.test/watchdog'",
            "report_item() { printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \"$1\" \"$2\" \"$3\" \"$4\" \"$5\" \"$6\" \"$7\" >> \"$1\"; }",
            "log() { printf '%s\\n' \"$*\" >> \"$LOG\"; }",
            (
                f"notify_needs_human {str(report_path)!r} demo-chain "
                f"{str(fixture_workspace)!r} /tmp/spec.yaml chain stopped 'manual review'"
            ),
        ]
    )

    result = _run_watchdog_shell(script, path_prefix=tmp_path)

    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "dm-called").exists()
    assert not (tmp_path / "webhook-called").exists()
    assert "test_notification_suppressed" in report_path.read_text(encoding="utf-8")
    assert "test_environment:MEGAPLAN_TEST_EXECUTION" in log_path.read_text(encoding="utf-8")


def test_watchdog_needs_human_missing_discord_config_records_durable_intent(tmp_path: Path) -> None:
    dm_helper = tmp_path / "arnold-discord-dm"
    dm_helper.write_text(
        "#!/usr/bin/env bash\n"
        "cat >/dev/null\n"
        "printf '%s\\n' '{\"ok\": false, \"reason\": \"missing_config\", \"missing\": [\"DISCORD_BOT_TOKEN\", \"DISCORD_DM_USER_ID\"]}'\n",
        encoding="utf-8",
    )
    dm_helper.chmod(dm_helper.stat().st_mode | stat.S_IXUSR)

    curl_path = tmp_path / "curl"
    curl_path.write_text(
        "#!/usr/bin/env bash\n"
        f"echo called >> {str(tmp_path / 'curl-calls.txt')!r}\n",
        encoding="utf-8",
    )
    curl_path.chmod(curl_path.stat().st_mode | stat.S_IXUSR)

    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"
    script = "\n\n".join(
        [
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            f"LOG={str(log_path)!r}",
            f"DISCORD_DM_BIN={str(dm_helper)!r}",
            "REPORT_WEBHOOK='https://example.test/watchdog'",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
PLAN_STATUS_PLAN_NAME='demo-plan'
""".strip(),
            f"notify_needs_human {str(report_path)!r} demo-session /tmp/ws .megaplan/initiatives/demo/briefs/demo.md chain stopped 'manual_review halt'",
        ]
    )

    result = _run_watchdog_shell(
        script, path_prefix=tmp_path, allow_notification_delivery=True
    )
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "curl-calls.txt").exists()
    report = report_path.read_text(encoding="utf-8")
    assert "\tobserve\tneeds_human\tmanual_review halt\t" in report
    assert "\tnotify\tnotification_intent_pending\t" in report


def test_arnold_discord_dm_wrapper_redacts_payload_before_rendering(tmp_path: Path) -> None:
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(
        json.dumps(
            {
                "title": "Megaplan needs human review - demo-session",
                "summary": "Authorization: Bearer bearer-secret-token-value",
                "fields": [{"label": "Token", "value": "export API_TOKEN=supersecret"}],
            }
        ),
        encoding="utf-8",
    )

    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    # G5 round-17 finding 3: the wrapper resolves its runtime root from the
    # manifest first, so the harness pins a valid manifest whose
    # epic.runtime_root is this checkout.
    env["ARNOLD_RUNTIME_MANIFEST"] = str(_write_runtime_manifest(tmp_path))
    # T-0015: the wrapper opens the gated resident delivery-effects owner, so
    # point the store at a scratch dir instead of the checkout's .megaplan.
    env["MEGAPLAN_RESIDENT_STORE_ROOT"] = str(tmp_path / "resident-store")
    env.pop("DISCORD_BOT_TOKEN", None)
    env.pop("DISCORD_DM_USER_ID", None)
    env.pop("PYTEST_CURRENT_TEST", None)
    with payload_path.open("r", encoding="utf-8") as payload_input:
        result = subprocess.run(
            ["python3", str(WRAPPER_DIR / "arnold-discord-dm")],
            stdin=payload_input,
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    assert result.returncode == 0, result.stderr
    wrapper_result = json.loads(result.stdout)
    assert wrapper_result["ok"] is False
    assert wrapper_result["reason"] == "missing_config"
    assert "bearer-secret-token-value" not in result.stderr
    assert "supersecret" not in result.stderr


def test_arnold_discord_dm_wrapper_never_enables_direct_transport() -> None:
    """T-0015: the production wrapper must not pass allow_direct_transport.

    The L4 opt-in design is reserved for explicit test/observation callers
    (e.g. tests/arnold_pipelines/megaplan/test_discord_dm.py with fake
    openers).  The packaged production wrapper must route delivery through the
    gated delivery-effects adapter only.
    """
    source = _wrapper("arnold-discord-dm")

    assert "allow_direct_transport" not in source
    assert "delivery_effects=delivery_effects" in source


def test_arnold_discord_dm_wrapper_fails_closed_without_gated_adapter(
    tmp_path: Path,
) -> None:
    """T-0015: no usable gated adapter means a typed denial, never direct
    Discord.  A real token is present so the wrapper must deny at the adapter
    gate (delivery_adapter_unavailable) instead of attempting any provider
    contact or reporting missing config."""
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(
        json.dumps(
            {
                "title": "Megaplan needs human review - demo-session",
                "summary": "needs human review",
            }
        ),
        encoding="utf-8",
    )
    # The configured resident store root is an existing file, so the SQLite
    # ledger cannot be created and adapter construction fails deterministically.
    blocked_root = tmp_path / "blocked-store"
    blocked_root.write_text("not a directory\n", encoding="utf-8")

    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    env["ARNOLD_RUNTIME_MANIFEST"] = str(_write_runtime_manifest(tmp_path))
    env["MEGAPLAN_RESIDENT_STORE_ROOT"] = str(blocked_root)
    env["DISCORD_BOT_TOKEN"] = "fake-token-for-fail-closed-test"
    env["DISCORD_DM_USER_ID"] = "fake-user-id"
    env.pop("PYTEST_CURRENT_TEST", None)
    with payload_path.open("r", encoding="utf-8") as payload_input:
        result = subprocess.run(
            ["python3", str(WRAPPER_DIR / "arnold-discord-dm")],
            stdin=payload_input,
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    assert result.returncode == 0, result.stderr
    wrapper_result = json.loads(result.stdout)
    assert wrapper_result["ok"] is False
    assert wrapper_result["reason"] == "delivery_adapter_unavailable"
    assert wrapper_result["message_count"] == 0
    assert wrapper_result["error"]
    # A direct-transport attempt would surface as send_failed (or hang on the
    # network); the typed adapter denial proves the wrapper never fell through.
    assert wrapper_result["reason"] not in {"send_failed", "missing_config"}


def _write_discord_dm_stub_root(stub_root: Path, marker_path: Path) -> None:
    """Write a complete manifest-root stub whose delivery writes *marker_path*.

    The stub is import-complete (redact + gated delivery-effects adapter), so
    if the wrapper ever imports production code from a root it should have
    rejected, ``send_discord_dm`` runs and the marker appears."""
    pkg = stub_root / "arnold_pipelines" / "megaplan"
    (pkg / "cloud").mkdir(parents=True, exist_ok=True)
    (pkg / "resident").mkdir(parents=True, exist_ok=True)
    (stub_root / "arnold_pipelines" / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "cloud" / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "cloud" / "redact.py").write_text(
        "def redact_payload(payload):\n    return payload\n",
        encoding="utf-8",
    )
    # T-0015: the wrapper opens a gated delivery-effects owner from the
    # resolved root, so the stub root must provide one.  Its presence here
    # also proves the delivery-effects import itself comes from the manifest
    # root rather than this checkout.
    (pkg / "resident" / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "resident" / "delivery_effects.py").write_text(
        "def current_delivery_gate_check(allow):\n"
        "    return lambda _family, _key: None\n"
        "\n"
        "class _StubAdapter:\n"
        "    def close(self):\n"
        "        pass\n"
        "\n"
        "def open_resident_delivery_effects(state_root, *, production_enabled=True, action_gate_check=None):\n"
        "    return _StubAdapter()\n",
        encoding="utf-8",
    )
    (pkg / "discord_dm.py").write_text(
        "import json\n"
        "from pathlib import Path\n"
        "def send_discord_dm(payload, *, env=None, delivery_effects=None, allow_direct_transport=False):\n"
        f"    Path({str(marker_path)!r}).write_text(json.dumps(payload), encoding='utf-8')\n"
        '    return {"ok": True, "root": "manifest-declared-stub"}\n',
        encoding="utf-8",
    )


def _write_discord_dm_manifest(tmp_path: Path, *, runtime_root: Path) -> Path:
    """Write a canonically schema-valid runtime manifest whose
    epic.runtime_root (and worktree_path) point at ``runtime_root``.

    G6 round-2 finding 1: the wrapper validates manifests with the
    supervisor-runtime-lib authority (runtime_manifest.load_manifest), so the
    fixture must be schema-valid — the old schema-less ``{epic:
    {runtime_root}}`` shape is rejected before any import."""
    manifest = _make_authoritative_manifest()
    root = Path(runtime_root)
    manifest["epic"]["runtime_root"] = str(root)
    manifest["epic"]["worktree_path"] = str(root)
    manifest_path = tmp_path / "discord-dm-runtime-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path


def test_arnold_discord_dm_wrapper_resolves_root_from_manifest_not_own_checkout(
    tmp_path: Path,
) -> None:
    """G5 round-17 finding 3: the runtime root comes from the manifest
    (ARNOLD_RUNTIME_MANIFEST -> epic.runtime_root) FIRST — the wrapper's own
    checkout path is never selected, even when it sits on PYTHONPATH."""
    stub_root = tmp_path / "manifest-runtime"
    marker_path = tmp_path / "stub-dm-called.json"
    _write_discord_dm_stub_root(stub_root, marker_path)
    manifest_path = _write_discord_dm_manifest(tmp_path, runtime_root=stub_root)

    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    env["ARNOLD_RUNTIME_MANIFEST"] = str(manifest_path)
    env.pop("DISCORD_BOT_TOKEN", None)
    env.pop("DISCORD_DM_USER_ID", None)
    env.pop("PYTEST_CURRENT_TEST", None)
    result = subprocess.run(
        ["python3", str(WRAPPER_DIR / "arnold-discord-dm")],
        input='{"title": "test"}',
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    # The stub under the manifest-declared root was imported and invoked: the
    # wrapper's own checkout (REPO_ROOT, on PYTHONPATH) was NOT selected.
    assert result.returncode == 0, result.stderr
    assert marker_path.exists(), result.stderr
    assert json.loads(result.stdout) == {"ok": True, "root": "manifest-declared-stub"}
    assert marker_path.read_text(encoding="utf-8") == '{"title": "test"}'


def test_arnold_discord_dm_wrapper_fails_closed_on_schema_less_manifest(
    tmp_path: Path,
) -> None:
    """G6 round-2 finding 1: a schema-less {epic: {runtime_root}} manifest is
    rejected by the canonical authority BEFORE any sys.path insert or
    production import — the wrapper fails closed and the stub's discord_dm
    never runs."""
    stub_root = tmp_path / "schema-less-root"
    marker_path = tmp_path / "schema-less-dm-called.json"
    _write_discord_dm_stub_root(stub_root, marker_path)
    manifest_path = tmp_path / "schema-less-manifest.json"
    manifest_path.write_text(
        json.dumps({"epic": {"runtime_root": str(stub_root)}}), encoding="utf-8"
    )
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    env["ARNOLD_RUNTIME_MANIFEST"] = str(manifest_path)
    env.pop("DISCORD_BOT_TOKEN", None)
    env.pop("DISCORD_DM_USER_ID", None)
    env.pop("PYTEST_CURRENT_TEST", None)
    result = subprocess.run(
        ["python3", str(WRAPPER_DIR / "arnold-discord-dm")],
        input='{"title": "test"}',
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode != 0, result.stdout
    assert "arnold-discord-dm: runtime manifest" in result.stderr
    assert result.stdout.strip() == ""
    # The stub root was never imported (its discord_dm would write the marker).
    assert not marker_path.exists(), result.stderr


def test_arnold_discord_dm_wrapper_fails_closed_on_compatibility_only_pointer(
    tmp_path: Path,
) -> None:
    """G6 round-2 finding 1: a compatibility_only pointer is non-authoritative
    telemetry that can never select a runtime — the wrapper fails closed
    before any sys.path insert or production import."""
    stub_root = tmp_path / "compat-only-root"
    marker_path = tmp_path / "compat-only-dm-called.json"
    _write_discord_dm_stub_root(stub_root, marker_path)
    manifest = _make_authoritative_manifest()
    manifest["epic"]["runtime_root"] = str(stub_root)
    manifest["epic"]["worktree_path"] = str(stub_root)
    manifest["compatibility_only"] = True
    manifest_path = tmp_path / "compat-only-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    env["ARNOLD_RUNTIME_MANIFEST"] = str(manifest_path)
    env.pop("DISCORD_BOT_TOKEN", None)
    env.pop("DISCORD_DM_USER_ID", None)
    env.pop("PYTEST_CURRENT_TEST", None)
    result = subprocess.run(
        ["python3", str(WRAPPER_DIR / "arnold-discord-dm")],
        input='{"title": "test"}',
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode != 0, result.stdout
    assert "arnold-discord-dm: runtime manifest" in result.stderr
    assert result.stdout.strip() == ""
    # The stub root was never imported (its discord_dm would write the marker).
    assert not marker_path.exists(), result.stderr


@pytest.mark.parametrize(
    "manifest_body",
    [
        "not json at all",
        "{}",
        '{"epic": {}}',
        '{"epic": {"runtime_root": ""}}',
        '{"epic": {"runtime_root": 42}}',
    ],
)
def test_arnold_discord_dm_wrapper_fails_closed_on_invalid_manifest(
    tmp_path: Path, manifest_body: str
) -> None:
    manifest_path = tmp_path / "discord-dm-runtime-manifest.json"
    manifest_path.write_text(manifest_body, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    env["ARNOLD_RUNTIME_MANIFEST"] = str(manifest_path)
    env.pop("PYTEST_CURRENT_TEST", None)
    result = subprocess.run(
        ["python3", str(WRAPPER_DIR / "arnold-discord-dm")],
        input='{"title": "test"}',
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode != 0, result.stdout
    assert "arnold-discord-dm: runtime manifest" in result.stderr
    assert result.stdout.strip() == ""


def test_arnold_discord_dm_wrapper_fails_closed_on_missing_manifest(tmp_path: Path) -> None:
    manifest_path = tmp_path / "does-not-exist-runtime-manifest.json"
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    env["ARNOLD_RUNTIME_MANIFEST"] = str(manifest_path)
    env.pop("PYTEST_CURRENT_TEST", None)
    result = subprocess.run(
        ["python3", str(WRAPPER_DIR / "arnold-discord-dm")],
        input='{"title": "test"}',
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode != 0, result.stdout
    assert "arnold-discord-dm: runtime manifest" in result.stderr
    assert result.stdout.strip() == ""


def test_watchdog_resolves_relative_chain_specs_against_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    report_path = tmp_path / "report.tsv"

    script = "\n\n".join(
        [
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { :; }
session_health_status() { echo alive; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
kimi_dispatch_marker_clear() { :; }
""".strip(),
            f"launch_chain_tick demo-chain {str(workspace)!r} .megaplan/initiatives/demo-chain/chain.yaml {str(report_path)!r} chain '' ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "alive" in report
    assert "spec_missing" not in report


def test_watchdog_scan_ignores_progress_snapshot_markers() -> None:
    text = _wrapper("arnold-watchdog")

    assert "*.progress.json|*.reap-progress.json|*.repair-progress.json|*.chain-health.progress.json" in text


def test_watchdog_enforces_single_instance_and_reexecs_after_hot_update() -> None:
    text = _wrapper("arnold-watchdog")
    scan_once = _extract_wrapper_function("scan_once_unlocked")

    assert 'LOCK_FILE="${CLOUD_WATCHDOG_LOCK_FILE:-/workspace/.megaplan/watchdog.lock}"' in text
    assert 'LOCK_HELD="${CLOUD_WATCHDOG_LOCK_HELD:-0}"' in text
    assert 'exec flock -n "$LOCK_FILE" bash "$SELF_PATH" "${WATCHDOG_ARGS[@]}"' in text
    assert "maybe_reexec_updated_watchdog()" in text
    assert 'source_wrapper="$SRC_DIR/arnold_pipelines/megaplan/cloud/wrappers/$(basename "$SELF_PATH")"' in text
    assert 'log "watchdog wrapper updated on disk; re-execing $reexec_reason"' in text
    assert 'exec bash "$reexec_path" "${WATCHDOG_ARGS[@]}"' in text
    assert 'log "scan start marker_dir=$MARKER_DIR"' in scan_once
    assert (
        'sync_editable_source_branch "$report_items" || authority_gap_continue "T29-BYPASS-208"'
        in scan_once
    )
    assert scan_once.count("maybe_reexec_updated_watchdog") == 2
    assert scan_once.index('log "scan start marker_dir=$MARKER_DIR"') < scan_once.index("maybe_reexec_updated_watchdog")
    assert scan_once.index('sync_editable_source_branch "$report_items"') < scan_once.rindex("maybe_reexec_updated_watchdog")


def test_watchdog_refresh_syncs_cloud_runtime_wrappers() -> None:
    text = _wrapper("arnold-watchdog")

    assert "sync_cloud_runtime_wrappers()" in text
    assert 'local wrapper_src_dir="$SRC_DIR/arnold_pipelines/megaplan/cloud/wrappers"' in text
    assert 'local wrapper_dest_dir="/usr/local/bin"' in text
    assert 'local support_dest_dir="/usr/local/share/arnold-watchdog"' in text
    assert 'if [[ -f "$dest" ]] && cmp -s "$wrapper" "$dest"; then' in text
    assert 'install -m 0755 "$wrapper" "$dest"' in text
    assert 'if [[ ! -f "$dest" ]] || ! cmp -s "$wrapper_src_dir/principles.md" "$dest"; then' in text
    assert 'install -m 0644 "$wrapper_src_dir/principles.md" "$dest"' in text
    assert 'sync_cloud_runtime_wrappers >> "$LOG" 2>&1 || return 1' in text


def test_watchdog_hot_update_prefers_newer_editable_source_wrapper(tmp_path: Path) -> None:
    wrapper = tmp_path / "installed" / "arnold-watchdog"
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    wrapper.write_text("#!/usr/bin/env bash\n", encoding="utf-8")

    src_dir = tmp_path / "src"
    source_wrapper = src_dir / "arnold_pipelines" / "megaplan" / "cloud" / "wrappers" / "arnold-watchdog"
    source_wrapper.parent.mkdir(parents=True, exist_ok=True)
    source_wrapper.write_text("#!/usr/bin/env bash\n", encoding="utf-8")

    stale = time.time() - 300
    fresh = time.time()
    os.utime(wrapper, (stale, stale))
    os.utime(source_wrapper, (fresh, fresh))

    fake_bash = tmp_path / "bash"
    fake_bash.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "print('\\n'.join(sys.argv[1:]))\n",
        encoding="utf-8",
    )
    fake_bash.chmod(fake_bash.stat().st_mode | stat.S_IXUSR)

    script = "\n\n".join(
        [
            _extract_wrapper_function("maybe_reexec_updated_watchdog"),
            "log() { :; }",
            f"SELF_PATH={str(wrapper)!r}",
            f"SRC_DIR={str(src_dir)!r}",
            "WATCHDOG_ARGS=(once)",
            f"WATCHDOG_STARTED_AT={int(stale)}",
            "maybe_reexec_updated_watchdog",
        ]
    )

    env = dict(os.environ)
    env["PATH"] = f"{tmp_path}:{env.get('PATH', '')}"
    result = subprocess.run(
        ["/bin/bash", "-c", script],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [str(source_wrapper), "once"]


def _write_babysitter_receipt(
    repair_data: Path,
    *,
    session: str,
    digest: str,
    pid: int,
    run_root: Path,
    launched_at: str,
    status: str = "launched",
) -> Path:
    repair_data.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "arnold.superfixer.watchdog_dispatch_receipt.v1",
        "session": session,
        "occurrence_digest": digest,
        "status": status,
        "babysitter_pid": pid,
        "supervisor_pid": pid,
        "run_root": str(run_root),
        "launched_at": launched_at,
        "dispatched_at": launched_at,
    }
    path = repair_data / f"{session}.babysitter-receipt.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def _fake_proc_pid(
    proc_root: Path,
    pid: int,
    *,
    state: str = "S",
    ppid: int = 1,
    established_inode: str | None = None,
    comm: str = "python",
    cmdline: str = "python -",
    start_seconds_ago: float = 60.0,
) -> None:
    pid_dir = proc_root / str(pid)
    fd_dir = pid_dir / "fd"
    fd_dir.mkdir(parents=True, exist_ok=True)
    # Canonical /proc/<pid>/stat: pid (comm) state ppid pgrp session tty tpgid
    # flags minflt cminflt majflt cmajflt utime stime cutime cstime priority
    # nice num_threads itrealvalue starttime ...  After rsplit(") ") the
    # fields are state(0) ppid(1) ... itrealvalue(18) starttime(19).
    uptime_secs = 3600.0
    hz = 100
    startticks = int((uptime_secs - start_seconds_ago) * hz)
    fields_after_comm = [
        state, str(ppid), "0", "0", "0", "0", "0", "0", "0", "0",
        "0", "0", "0", "0", "0", "0", "0", "0", "0", str(startticks),
    ]
    (pid_dir / "stat").write_text(
        f"{pid} ({comm}) " + " ".join(fields_after_comm) + "\n",
        encoding="utf-8",
    )
    (pid_dir / "comm").write_text(comm + "\n", encoding="utf-8")
    (pid_dir / "cmdline").write_text(cmdline.replace(" ", "\x00"), encoding="utf-8")
    uptime_path = proc_root / "uptime"
    if not uptime_path.exists():
        uptime_path.write_text(f"{uptime_secs} {uptime_secs - 1}\n", encoding="utf-8")
    if established_inode is None:
        return
    os.symlink(f"socket:[{established_inode}]", fd_dir / "3")
    net_dir = pid_dir / "net"
    net_dir.mkdir(parents=True, exist_ok=True)
    header = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr "
        "tm->when retrnsmt   uid  timeout inode\n"
    )
    row = (
        f"   0: 0100007F:C350 0100007F:01BB 01 00000000:00000000 "
        f"00:00000000 00000000     0        0 {established_inode} 1\n"
    )
    (net_dir / "tcp").write_text(header + row, encoding="utf-8")


def _invoke_babysitter_running(
    *,
    repair_data: Path,
    session: str,
    digest: str,
    proc_root: Path | None = None,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    exports = [
        _extract_wrapper_function("babysitter_running_for_occurrence"),
        f"REPAIR_DATA_DIR={str(repair_data)!r}",
    ]
    if proc_root is not None:
        exports.append(
            "export CLOUD_WATCHDOG_BABYSITTER_PROC_ROOT="
            + shlex.quote(str(proc_root))
        )
    for key, value in (extra_env or {}).items():
        exports.append(f"export {key}=" + shlex.quote(value))
    exports.append(
        f"babysitter_running_for_occurrence {shlex.quote(session)} {shlex.quote(digest)}"
    )
    result = _run_watchdog_shell("\n".join(exports))
    return result


def test_babysitter_wedged_ignores_silent_run_log_when_stdout_grew(
    tmp_path: Path,
) -> None:
    """I51: a mid-call babysitter tees to babysitter.stdout.log, not run.log."""
    session = "megaplan-maintenance"
    digest = "a07166d38fbc"
    repair_data = tmp_path / "repair-data"
    run_root = repair_data / "babysitter-runs" / f"sched_superfixer_status_{session}_{digest}"
    run_root.mkdir(parents=True)
    launched = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=20)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    _write_babysitter_receipt(
        repair_data,
        session=session,
        digest=digest,
        pid=os.getpid(),
        run_root=run_root,
        launched_at=launched,
    )
    stale = time.time() - 40 * 60
    (run_root / "nested").mkdir()
    run_log = run_root / "nested" / "run.log"
    run_log.write_text("[tool] read\n", encoding="utf-8")
    os.utime(run_log, (stale, stale))
    stdout_log = run_root / "babysitter.stdout.log"
    stdout_log.write_text("[tool] grep\n", encoding="utf-8")
    proc_root = tmp_path / "proc"
    proc_root.mkdir()
    result = _invoke_babysitter_running(
        repair_data=repair_data,
        session=session,
        digest=digest,
        proc_root=proc_root,
    )
    assert result.returncode == 0, result.stderr


def test_babysitter_wedged_treats_established_socket_as_live_work(
    tmp_path: Path,
) -> None:
    """Mid-model-call: no log growth, but ESTABLISHED TCP → do not reap."""
    session = "megaplan-maintenance"
    digest = "a07166d38fbc"
    repair_data = tmp_path / "repair-data"
    run_root = repair_data / "babysitter-runs" / "run"
    run_root.mkdir(parents=True)
    launched = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=20)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    child = subprocess.Popen(["sleep", "30"])
    try:
        _write_babysitter_receipt(
            repair_data,
            session=session,
            digest=digest,
            pid=child.pid,
            run_root=run_root,
            launched_at=launched,
        )
        stale = time.time() - 40 * 60
        run_log = run_root / "run.log"
        run_log.write_text("[done] old\n", encoding="utf-8")
        os.utime(run_log, (stale, stale))
        proc_root = tmp_path / "proc"
        _fake_proc_pid(
            proc_root, child.pid, state="S", established_inode="4242"
        )
        result = _invoke_babysitter_running(
            repair_data=repair_data,
            session=session,
            digest=digest,
            proc_root=proc_root,
        )
        assert result.returncode == 0, result.stderr
        assert child.poll() is None
    finally:
        child.kill()
        child.wait()


def test_babysitter_wedged_reaps_idle_tree_with_stale_logs(
    tmp_path: Path,
) -> None:
    """I18/I32/I34: detect a true wedge, but defer physical cleanup to WBC."""
    session = "megaplan-maintenance"
    digest = "a07166d38fbc"
    repair_data = tmp_path / "repair-data"
    run_root = repair_data / "babysitter-runs" / "run"
    run_root.mkdir(parents=True)
    launched = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=20)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    child = subprocess.Popen(["sleep", "30"])
    try:
        _write_babysitter_receipt(
            repair_data,
            session=session,
            digest=digest,
            pid=child.pid,
            run_root=run_root,
            launched_at=launched,
        )
        stale = time.time() - 40 * 60
        run_log = run_root / "run.log"
        run_log.write_text("[done] old\n", encoding="utf-8")
        os.utime(run_log, (stale, stale))
        (run_root / "babysitter.stdout.log").write_text("old\n", encoding="utf-8")
        os.utime(run_root / "babysitter.stdout.log", (stale, stale))
        # The two-scan confirmation has already elapsed. This keeps the
        # fixture focused on true wedge detection while the extracted Python
        # observer remains forbidden from issuing an unbound raw signal.
        (run_root / "wedged-since.json").write_text(
            json.dumps({"first_seen": time.time() - 1200, "session": session}),
            encoding="utf-8",
        )
        proc_root = tmp_path / "proc"
        _fake_proc_pid(proc_root, child.pid, state="S")
        result = _invoke_babysitter_running(
            repair_data=repair_data,
            session=session,
            digest=digest,
            proc_root=proc_root,
        )
        assert result.returncode == 75, result.stderr
        assert "cleanup hold required" in result.stderr
        hold = json.loads((run_root / "cleanup-hold.json").read_text(encoding="utf-8"))
        assert hold["kind"] == "cleanup_hold"
        assert hold["status"] == "unresolved"
        assert hold["reconciliation"] == "canonical_reaper_after_marker_binding"
        assert child.poll() is None
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()


def test_babysitter_wedged_treats_child_socket_as_live_work(
    tmp_path: Path,
) -> None:
    """fan.py / nested hermes: parent idle, child ESTABLISHED → do not reap."""
    session = "megaplan-maintenance"
    digest = "a07166d38fbc"
    repair_data = tmp_path / "repair-data"
    run_root = repair_data / "babysitter-runs" / "run"
    run_root.mkdir(parents=True)
    launched = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=20)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    child = subprocess.Popen(["sleep", "30"])
    try:
        _write_babysitter_receipt(
            repair_data,
            session=session,
            digest=digest,
            pid=child.pid,
            run_root=run_root,
            launched_at=launched,
        )
        stale = time.time() - 40 * 60
        (run_root / "run.log").write_text("[tool] fan.py\n", encoding="utf-8")
        os.utime(run_root / "run.log", (stale, stale))
        proc_root = tmp_path / "proc"
        grandchild_pid = child.pid + 100000
        _fake_proc_pid(proc_root, child.pid, state="S")
        _fake_proc_pid(
            proc_root,
            grandchild_pid,
            state="S",
            ppid=child.pid,
            established_inode="7777",
        )
        result = _invoke_babysitter_running(
            repair_data=repair_data,
            session=session,
            digest=digest,
            proc_root=proc_root,
        )
        assert result.returncode == 0, result.stderr
        assert child.poll() is None
    finally:
        child.kill()
        child.wait()


def test_babysitter_wedged_fail_open_without_proc(
    tmp_path: Path,
) -> None:
    """No /proc and no recent logs: do not reap a live pid."""
    session = "megaplan-maintenance"
    digest = "a07166d38fbc"
    repair_data = tmp_path / "repair-data"
    run_root = repair_data / "babysitter-runs" / "run"
    run_root.mkdir(parents=True)
    launched = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=20)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    _write_babysitter_receipt(
        repair_data,
        session=session,
        digest=digest,
        pid=os.getpid(),
        run_root=run_root,
        launched_at=launched,
    )
    missing_proc = tmp_path / "no-proc"
    result = _invoke_babysitter_running(
        repair_data=repair_data,
        session=session,
        digest=digest,
        proc_root=missing_proc,
    )
    assert result.returncode == 0, result.stderr


def test_babysitter_first_call_grace_keeps_silent_12min_run(
    tmp_path: Path,
) -> None:
    """I51b: 12 min in, no [tool] lines, no socket — first model call, keep."""
    session = "megaplan-maintenance"
    digest = "a07166d38fbc"
    repair_data = tmp_path / "repair-data"
    run_root = repair_data / "babysitter-runs" / "run"
    run_root.mkdir(parents=True)
    launched = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=12)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    _write_babysitter_receipt(
        repair_data,
        session=session,
        digest=digest,
        pid=os.getpid(),
        run_root=run_root,
        launched_at=launched,
    )
    # stdout.log exists (created at Popen) but has NO [tool]/[done] lines;
    # its mtime is as old as the launch (12 min)
    (run_root / "babysitter.stdout.log").write_text("", encoding="utf-8")
    old = time.time() - 12 * 60
    os.utime(run_root / "babysitter.stdout.log", (old, old))
    proc_root = tmp_path / "proc"
    proc_root.mkdir()
    _fake_proc_pid(proc_root, os.getpid(), state="S")
    result = _invoke_babysitter_running(
        repair_data=repair_data,
        session=session,
        digest=digest,
        proc_root=proc_root,
    )
    assert result.returncode == 0, result.stderr


def test_babysitter_first_call_grace_expires_after_25min(
    tmp_path: Path,
) -> None:
    """I51b: confirmed wedge records a hold; the observer never raw-signals."""
    session = "megaplan-maintenance"
    digest = "a07166d38fbc"
    repair_data = tmp_path / "repair-data"
    run_root = repair_data / "babysitter-runs" / "run"
    run_root.mkdir(parents=True)
    launched = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=25)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    _write_babysitter_receipt(
        repair_data,
        session=session,
        digest=digest,
        pid=os.getpid(),
        run_root=run_root,
        launched_at=launched,
    )
    (run_root / "babysitter.stdout.log").write_text("", encoding="utf-8")
    # stdout.log is created at Popen, so its mtime is as old as the launch
    old = time.time() - 25 * 60
    os.utime(run_root / "babysitter.stdout.log", (old, old))
    (run_root / "wedged-since.json").write_text(
        json.dumps({"first_seen": time.time() - 1200, "session": session}),
        encoding="utf-8",
    )
    child = subprocess.Popen(["sleep", "30"])
    try:
        _write_babysitter_receipt(
            repair_data,
            session=session,
            digest=digest,
            pid=child.pid,
            run_root=run_root,
            launched_at=launched,
        )
        proc_root = tmp_path / "proc"
        proc_root.mkdir()
        _fake_proc_pid(proc_root, child.pid, state="S")
        result = _invoke_babysitter_running(
            repair_data=repair_data,
            session=session,
            digest=digest,
            proc_root=proc_root,
        )
        assert result.returncode == 75, result.stderr
        assert "cleanup hold required" in result.stderr
        assert (run_root / "cleanup-hold.json").is_file()
        assert child.poll() is None
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()


def test_hung_codex_child_signaled_parent_kept(
    tmp_path: Path,
) -> None:
    """I51b: isolated observer cannot raw-signal an unbound codex child."""
    session = "megaplan-maintenance"
    digest = "a07166d38fbc"
    repair_data = tmp_path / "repair-data"
    run_root = repair_data / "babysitter-runs" / "run"
    run_root.mkdir(parents=True)
    launched = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=40)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    # babysitter pid must be live: use a child of THIS process we can kill
    # safely — a sleep child of the test process.
    parent_pid = os.getpid()
    codex_child = subprocess.Popen(["sleep", "30"])
    try:
        _write_babysitter_receipt(
            repair_data,
            session=session,
            digest=digest,
            pid=parent_pid,
            run_root=run_root,
            launched_at=launched,
        )
        # fresh poll-loop progress: run.log with [tool] lines (fake progress)
        stale = time.time() - 2 * 60
        run_log = run_root / "run.log"
        run_log.write_text("[tool] sleep 180\n", encoding="utf-8")
        os.utime(run_log, (stale, stale))
        # fake proc tree: parent is the babysitter, codex is a real child
        # registered with comm=codex; the isolated observer must not signal it
        proc_root = tmp_path / "proc"
        proc_root.mkdir()
        _fake_proc_pid(proc_root, parent_pid, state="S", start_seconds_ago=40 * 60)
        codex_pid = codex_child.pid
        _fake_proc_pid(
            proc_root,
            codex_pid,
            state="S",
            ppid=parent_pid,
            comm="codex",
            cmdline="codex exec --sandbox danger-full-access",
            start_seconds_ago=40 * 60,
        )
        # babysitter.stdout.log fresh (poll loop writes) — but codex hung
        stdout_log = run_root / "babysitter.stdout.log"
        stdout_log.write_text("[tool] sleep 180\n", encoding="utf-8")
        os.utime(stdout_log, (stale, stale))
        # override the hung-child bound so the fake 40-min-old codex qualifies
        result = _run_watchdog_shell(
            "\n".join(
                [
                    _extract_wrapper_function("babysitter_running_for_occurrence"),
                    f"REPAIR_DATA_DIR={str(repair_data)!r}",
                    "export CLOUD_WATCHDOG_BABYSITTER_PROC_ROOT="
                    + shlex.quote(str(proc_root)),
                    "export CLOUD_WATCHDOG_HUNG_CHILD_MINUTES=5",
                    (
                        f"babysitter_running_for_occurrence {shlex.quote(session)} "
                        f"{shlex.quote(digest)}"
                    ),
                ]
            )
        )
        # parent not reaped: exit 0 (already running)
        assert result.returncode == 0, result.stderr
        assert "hung fixer child; signaling" not in result.stderr, result.stderr
        assert "cleanup hold required" not in result.stderr, result.stderr
        assert codex_child.poll() is None
    finally:
        if codex_child.poll() is None:
            codex_child.kill()
            codex_child.wait()


def test_codex_child_with_socket_left_alone(
    tmp_path: Path,
) -> None:
    """I51b: codex child with ESTABLISHED TCP is thinking — nobody signaled."""
    session = "megaplan-maintenance"
    digest = "a07166d38fbc"
    repair_data = tmp_path / "repair-data"
    run_root = repair_data / "babysitter-runs" / "run"
    run_root.mkdir(parents=True)
    launched = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=40)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    parent_pid = os.getpid()
    _write_babysitter_receipt(
        repair_data,
        session=session,
        digest=digest,
        pid=parent_pid,
        run_root=run_root,
        launched_at=launched,
    )
    stale = time.time() - 2 * 60
    run_log = run_root / "run.log"
    run_log.write_text("[tool] sleep 180\n", encoding="utf-8")
    os.utime(run_log, (stale, stale))
    proc_root = tmp_path / "proc"
    proc_root.mkdir()
    _fake_proc_pid(proc_root, parent_pid, state="S", start_seconds_ago=40 * 60)
    codex_pid = 424243
    _fake_proc_pid(
        proc_root,
        codex_pid,
        state="S",
        ppid=parent_pid,
        comm="codex",
        cmdline="codex exec --sandbox danger-full-access",
        start_seconds_ago=40 * 60,
        established_inode="777001",
    )
    stdout_log = run_root / "babysitter.stdout.log"
    stdout_log.write_text("[tool] sleep 180\n", encoding="utf-8")
    os.utime(stdout_log, (stale, stale))
    result = _run_watchdog_shell(
        "\n".join(
            [
                _extract_wrapper_function("babysitter_running_for_occurrence"),
                f"REPAIR_DATA_DIR={str(repair_data)!r}",
                "export CLOUD_WATCHDOG_BABYSITTER_PROC_ROOT="
                + shlex.quote(str(proc_root)),
                "export CLOUD_WATCHDOG_HUNG_CHILD_MINUTES=5",
                (
                    f"babysitter_running_for_occurrence {shlex.quote(session)} "
                    f"{shlex.quote(digest)}"
                ),
            ]
        )
    )
    assert result.returncode == 0, result.stderr
    assert "hung fixer child" not in result.stderr, result.stderr


def test_arnold_chain_wrapper_reloads_hot_env_before_launch() -> None:
    text = _wrapper("arnold-chain")

    assert "if [[ -f /workspace/.cloud-hot-env ]]; then set -a; . /workspace/.cloud-hot-env; set +a; fi;" in text
    assert "python -P -m arnold_pipelines.megaplan chain start" in text


def test_watchdog_syncs_extra_skills_to_agent_skill_dirs() -> None:
    text = _wrapper("arnold-watchdog")

    assert '"$HOME/.claude/skills"' in text
    assert '"$HOME/.codex/skills"' in text
    assert '"$HOME/.agents/skills"' in text
    assert '"$HOME/.hermes/skills"' not in text


def test_watchdog_health_treats_orphaned_chain_process_as_alive(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / ".megaplan" / "plans").mkdir(parents=True)
    spec_path = workspace / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    spec_path.parent.mkdir(parents=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")

    script = "\n\n".join(
        [
            _extract_wrapper_function("chain_wait_status"),
            _extract_wrapper_function("plan_process_is_alive"),
            _extract_wrapper_function("chain_process_is_alive"),
            _extract_wrapper_function("epic_chain_process_is_alive"),
            _extract_wrapper_function("session_health_status"),
            f"""
tmux() {{ return 1; }}
ps() {{
  cat <<'EOF'
python3 -P -m arnold_pipelines.megaplan chain start --spec {spec_path} --project-dir {workspace}
EOF
}}
session_health_status demo-session {workspace} {spec_path} chain ""
""",
        ]
    )
    result = subprocess.run(["bash", "-lc", script], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "alive"


def test_watchdog_repair_loop_needs_human_sidecar_short_circuits_relaunch(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    repair_data_dir = marker_dir / "repair-data"
    marker_dir.mkdir()
    repair_data_dir.mkdir()
    workspace = tmp_path / "ws"
    workspace.mkdir()
    spec_path = tmp_path / "spec.yaml"
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    report_path = tmp_path / "report.tsv"
    (repair_data_dir / "demo-session.needs-human.json").write_text(
        json.dumps(
            {
                "summary": "i1 dev=zhipu:glm-5.2 sha=abc mechanical=failed:stopped kimi=failed:bad-creds",
                "repair_data_path": str(repair_data_dir / "demo-session.repair-data.json"),
                "discord_status": "delivered",
            }
        ),
        encoding="utf-8",
    )

    script = "\n\n".join(
        [
            _extract_wrapper_function("repair_needs_human_path"),
            _extract_wrapper_function("repair_needs_human_summary"),
            _extract_wrapper_function("repair_needs_human_matches_current_plan"),
            _extract_wrapper_function("workspace_has_other_alive_session"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(repair_data_dir)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { :; }
session_health_status() { echo stopped; }
plan_attention_status_env() { return 0; }
kimi_operator_running() { return 1; }
mechanical_relaunch_attempted_previously() { return 1; }
kimi_dispatch_failed_previously() { return 1; }
dispatch_kimi_repair() { echo DISPATCH >&2; return 0; }
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH; }
safe_name() { printf '%s\n' "$1"; }
chain_current_pr_merged() { echo none; }
tmux() { echo TMUX >&2; return 1; }
""".strip(),
            f"launch_chain_tick demo-session {str(workspace)!r} {str(spec_path)!r} {str(report_path)!r} chain '' ''",
        ]
    )

    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\tobserve\tneeds_human\t" in report
    assert "repair_data=" in report
    assert "discord=delivered" in report
    assert "BABYSITTER" not in result.stderr
    assert "TMUX" not in result.stderr


def test_write_needs_human_marker_preserves_legacy_keys_and_adds_current_pointer_fields(tmp_path: Path) -> None:
    data_path = tmp_path / "demo-session.repair-data.json"
    out_path = tmp_path / "demo-session.needs-human.json"
    payload = {
        "session": "demo-session",
        "workspace": "/tmp/workspace",
        "spec": "/tmp/workspace/.megaplan/initiatives/demo/chain.yaml",
        "run_kind": "chain",
        "plan_name": "m2-current-plan",
        "target": {
            "target_id": "demo-session:m2-current-plan",
            "authoritative_source": "marker",
        },
        "current_failure_context": {
            "resolver_output": {
                "target_id": "demo-session:m2-current-plan",
                "authoritative_source": "chain_state",
                "current_refs": {
                    "current_plan_name": "m2-current-plan",
                    "chain_current_plan_name": "m2-current-plan",
                },
            }
        },
        "iterations": [
            {
                "i": 1,
                "dev_model": "gpt-5.5",
                "dev_fix_sha": "abc1234",
                "mechanical_launch": "running",
                "kimi_launch": "failed:bad-creds",
                "why": "blocked by follow-up",
                "chain_state_summary": {"current_plan_name": "m2-current-plan"},
            }
        ],
    }
    data_path.write_text(json.dumps(payload), encoding="utf-8")

    result = _run_write_needs_human_marker(data_path, out_path)

    assert result.returncode == 0, result.stderr
    marker = json.loads(out_path.read_text(encoding="utf-8"))
    legacy_keys = {
        "session",
        "workspace",
        "spec",
        "plan_name",
        "chain_current_plan_name",
        "summary",
        "repair_data_path",
        "discord_status",
        "recorded_at",
    }
    assert legacy_keys <= set(marker)
    assert marker["session"] == payload["session"]
    assert marker["workspace"] == payload["workspace"]
    assert marker["spec"] == payload["spec"]
    assert marker["plan_name"] == "m2-current-plan"
    assert marker["chain_current_plan_name"] == "m2-current-plan"
    assert marker["repair_data_path"] == str(data_path)
    assert marker["discord_status"] == "delivered"
    assert marker["summary"] == (
        "i1 dev=gpt-5.5 sha=abc1234 mechanical=running kimi=failed:bad-creds why=blocked by follow-up"
    )
    assert marker["current_plan_name"] == "m2-current-plan"
    assert marker["target_id"] == "demo-session:m2-current-plan"
    assert marker["authoritative_source"] == "chain_state"
    assert marker["current"] == {
        "session": "demo-session",
        "workspace": "/tmp/workspace",
        "spec": "/tmp/workspace/.megaplan/initiatives/demo/chain.yaml",
        "repair_data_path": str(data_path),
        "target_id": "demo-session:m2-current-plan",
        "authoritative_source": "chain_state",
        "current_plan_name": "m2-current-plan",
        "chain_current_plan_name": "m2-current-plan",
        "plan_name": "m2-current-plan",
        "run_kind": "chain",
    }


def test_write_needs_human_marker_output_remains_watchdog_reader_compatible(tmp_path: Path) -> None:
    repair_data_dir = tmp_path / "repair-data"
    repair_data_dir.mkdir()
    data_path = repair_data_dir / "demo-session.repair-data.json"
    sidecar_path = repair_data_dir / "demo-session.needs-human.json"
    payload = {
        "session": "demo-session",
        "workspace": str(tmp_path / "ws"),
        "spec": str(tmp_path / "spec.yaml"),
        "plan_name": "m3-current-plan",
        "current_failure_context": {
            "resolver_output": {
                "target_id": "demo-session:m3-current-plan",
                "authoritative_source": "plan_state",
                "current_refs": {
                    "current_plan_name": "m3-current-plan",
                    "chain_current_plan_name": "m3-current-plan",
                },
            }
        },
        "iterations": [
            {
                "i": 1,
                "dev_model": "gpt-5.5",
                "dev_fix_sha": "abc1234",
                "mechanical_launch": "n/a",
                "kimi_launch": "n/a",
                "why": "operator review required",
                "chain_state_summary": {"current_plan_name": "m3-current-plan"},
            }
        ],
    }
    data_path.write_text(json.dumps(payload), encoding="utf-8")
    marker_result = _run_write_needs_human_marker(data_path, sidecar_path, discord_status="queued")
    assert marker_result.returncode == 0, marker_result.stderr

    summary_script = "\n\n".join(
        [
            _extract_wrapper_function("repair_needs_human_path"),
            _extract_wrapper_function("repair_needs_human_summary"),
            f"REPAIR_DATA_DIR={str(repair_data_dir)!r}",
            'repair_needs_human_summary "demo-session"',
        ]
    )
    summary_result = _run_watchdog_shell(f"{summary_script}\n", path_prefix=None)
    assert summary_result.returncode == 0, summary_result.stderr
    assert "repair_data=" in summary_result.stdout
    assert "discord=queued" in summary_result.stdout

    matches_script = "\n\n".join(
        [
            _extract_wrapper_function("repair_needs_human_path"),
            _extract_wrapper_function("repair_needs_human_matches_current_plan"),
            f"REPAIR_DATA_DIR={str(repair_data_dir)!r}",
            'repair_needs_human_matches_current_plan "demo-session" "m3-current-plan"',
        ]
    )
    matches_result = _run_watchdog_shell(f"{matches_script}\n", path_prefix=None)
    assert matches_result.returncode == 0, matches_result.stderr


def test_write_needs_human_marker_redacts_persisted_summary(tmp_path: Path) -> None:
    data_path = tmp_path / "repair-data.json"
    out_path = tmp_path / "demo-session.needs-human.json"
    payload = {
        "session": "demo-session",
        "workspace": "/tmp/workspace",
        "spec": "/tmp/workspace/.megaplan/initiatives/demo/chain.yaml",
        "plan_name": "m2-current-plan",
        "current_failure_context": {
            "resolver_output": {
                "target_id": "demo-session:m2-current-plan",
                "authoritative_source": "chain_state",
                "current_refs": {
                    "current_plan_name": "m2-current-plan",
                    "chain_current_plan_name": "m2-current-plan",
                },
            }
        },
        "iterations": [
            {
                "i": 1,
                "dev_model": "gpt-5.5",
                "dev_fix_sha": "abc1234",
                "mechanical_launch": "running",
                "kimi_launch": "failed",
                "why": "Authorization: Bearer bearer-secret-token-value",
                "chain_state_summary": {"current_plan_name": "m2-current-plan"},
            }
        ],
    }
    data_path.write_text(json.dumps(payload), encoding="utf-8")

    result = _run_write_needs_human_marker(data_path, out_path)

    assert result.returncode == 0, result.stderr
    marker = json.loads(out_path.read_text(encoding="utf-8"))
    assert "bearer-secret-token-value" not in marker["summary"]
    assert marker["summary"].endswith(f"why=Authorization: Bearer {REDACTION}")






def test_watchdog_checks_terminal_status_before_current_needs_human() -> None:
    text = _wrapper("arnold-watchdog")
    launch_start = text.index("launch_chain_tick() {")
    sidecar_check = text.index("emit_current_needs_human_sidecar", launch_start)
    terminal_check = text.index("session_terminal_status", launch_start)

    assert terminal_check < sidecar_check


def test_watchdog_checks_plan_status_terminal_done_before_current_needs_human() -> None:
    text = _wrapper("arnold-watchdog")
    plan_status_eval = text.index('eval "$plan_status_env"')
    complete_check = text.index('PLAN_STATUS_CURRENT_STATE:-}" == "done"', plan_status_eval)
    sidecar_check = text.index("emit_current_needs_human_sidecar", plan_status_eval)

    assert complete_check < sidecar_check


def test_watchdog_current_needs_human_sidecar_reports_every_tick_without_renotify(tmp_path: Path) -> None:
    report_path = tmp_path / "items.jsonl"
    repair_data_dir = tmp_path / "repair-data"
    repair_data_dir.mkdir()
    marker_path = repair_data_dir / "demo-session.needs-human.json"
    marker_path.write_text(
        json.dumps(
            {
                "session": "demo-session",
                "summary": "repair loop exhausted",
                "current_plan_name": "m6-current-plan",
                "discord_status": "delivered",
            }
        ),
        encoding="utf-8",
    )
    script = "\n\n".join(
        [
            "LOG=/dev/null",
            f"REPAIR_DATA_DIR={str(repair_data_dir)!r}",
            "log() { :; }",
            "compare_needs_human_to_resolver() { :; }",
            _extract_wrapper_function_until("report_item", "plan_attention_status_env"),
            _extract_wrapper_function("repair_needs_human_path"),
            _extract_wrapper_function("repair_needs_human_summary"),
            _extract_wrapper_function("repair_needs_human_matches_current_plan"),
            _extract_wrapper_function("emit_current_needs_human_sidecar"),
            f"emit_current_needs_human_sidecar {str(report_path)!r} demo-session /tmp/ws /tmp/spec m6-current-plan",
            f"emit_current_needs_human_sidecar {str(report_path)!r} demo-session /tmp/ws /tmp/spec m6-current-plan",
        ]
    )

    result = _run_watchdog_shell(script)

    assert result.returncode == 0, result.stderr
    lines = [json.loads(line) for line in report_path.read_text(encoding="utf-8").splitlines()]
    assert [item["status"] for item in lines] == ["needs_human", "needs_human"]
    assert all(item["action"] == "observe" for item in lines)
    assert all("repair loop exhausted" in item["message"] for item in lines)
    assert all(item["status"] not in {"discord_dm_sent", "webhook_sent"} for item in lines)


def test_watchdog_report_item_redacts_persisted_lines(tmp_path: Path) -> None:
    items_path = tmp_path / "items.jsonl"
    script = "\n\n".join(
        [
            _extract_wrapper_function_until("report_item", "plan_attention_status_env"),
            (
                f"report_item {str(items_path)!r} demo-session observe needs_human "
                "'Authorization: Bearer bearer-secret-token-value' /tmp/ws demo-spec"
            ),
        ]
    )

    result = _run_watchdog_shell(script)

    assert result.returncode == 0, result.stderr
    payload = json.loads(items_path.read_text(encoding="utf-8").strip())
    assert payload["message"] == f"Authorization: Bearer {REDACTION}"


def test_watchdog_emit_report_redacts_persisted_report_json(tmp_path: Path) -> None:
    items_path = tmp_path / "items.jsonl"
    items_path.write_text(
        json.dumps(
            {
                "session": "demo-session",
                "action": "observe",
                "status": "needs_human",
                "message": "Authorization: Bearer bearer-secret-token-value",
                "workspace": "/tmp/ws",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    report_path = tmp_path / "watchdog-report.json"
    archive_dir = tmp_path / "archive"
    script = "\n\n".join(
        [
            _extract_wrapper_function_until("emit_report", "write_watchdog_heartbeat"),
            _extract_wrapper_function("redact_inline_text"),
            f"REPORT_PATH={str(report_path)!r}",
            f"REPORT_ARCHIVE_DIR={str(archive_dir)!r}",
            'emit_report ' + shlex.quote(str(items_path)) + " 1",
        ]
    )

    result = _run_watchdog_shell(script)

    assert result.returncode == 0, result.stderr
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["items"][0]["message"] == f"Authorization: Bearer {REDACTION}"
    assert payload["issues"][0]["message"] == f"Authorization: Bearer {REDACTION}"


def test_watchdog_clears_stale_parent_sidecar_when_child_session_alive(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    repair_data_dir = marker_dir / "repair-data"
    marker_dir.mkdir()
    repair_data_dir.mkdir()
    workspace = tmp_path / "ws"
    workspace.mkdir()
    parent_spec = workspace / ".megaplan" / "initiatives" / "demo" / "assets" / "epic-chain.yaml"
    child_spec = workspace / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    parent_spec.parent.mkdir(parents=True)
    child_spec.parent.mkdir(parents=True, exist_ok=True)
    parent_spec.write_text("chains: []\n", encoding="utf-8")
    child_spec.write_text("milestones: []\n", encoding="utf-8")
    _write_live_session_marker(
        marker_dir,
        "parent-session",
        workspace,
        str(parent_spec),
        run_kind="chain",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"
    sidecar_path = repair_data_dir / "parent-session.needs-human.json"
    sidecar_path.write_text(
        json.dumps(
            {
                "summary": "old parent repair exhaustion",
                "repair_data_path": str(repair_data_dir / "parent-session.repair-data.json"),
                "discord_status": "delivered",
            }
        ),
        encoding="utf-8",
    )
    (marker_dir / "child-session.json").write_text(
        json.dumps(
            {
                "session": "child-session",
                "workspace": str(workspace),
                "remote_spec": str(child_spec),
                "run_kind": "chain",
            }
        ),
        encoding="utf-8",
    )

    script = "\n\n".join(
        [
            _extract_wrapper_function("repair_needs_human_path"),
            _extract_wrapper_function("repair_needs_human_summary"),
            _extract_wrapper_function("repair_needs_human_matches_current_plan"),
            _extract_wrapper_function("workspace_has_other_alive_session"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(repair_data_dir)!r}",
            f"LOG={str(log_path)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() {
  if [[ "$1" == "child-session" ]]; then
    echo alive
  else
    echo stopped
  fi
}
plan_attention_status_env() { return 0; }
chain_health_status() {
  CHAIN_HEALTH_STATUS=ok
  CHAIN_HEALTH_SUMMARY=
  CHAIN_HEALTH_ARTIFACT_PATH=
  CHAIN_HEALTH_LOG_MESSAGE=
}
chain_current_pr_merged() { echo none; }
kimi_operator_running() { return 1; }
repair_loop_busy_state() { echo none; }
mechanical_relaunch_attempted_previously() { return 0; }
kimi_dispatch_failed_previously() { return 1; }
kimi_dispatch_marker_set() { :; }
kimi_dispatch_marker_clear() { :; }
dispatch_kimi_repair() { echo DISPATCH >&2; return 0; }
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH; }
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
""".strip(),
            f"launch_chain_tick parent-session {str(workspace)!r} {str(parent_spec)!r} {str(report_path)!r} chain '' ''",
        ]
    )

    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    log = log_path.read_text(encoding="utf-8")
    assert "\tobserve\tneeds_human\told parent repair exhaustion" not in report
    assert "\tobserve\tsuperseded\tlive sibling session owns workspace: child-session:alive\t" in report
    assert "stale repair needs-human marker cleared; sibling session is alive" in log
    assert "stopped session superseded by live sibling" in log
    assert not sidecar_path.exists()
    assert "BABYSITTER" not in result.stderr


def test_watchdog_clears_stale_needs_human_sidecar_for_superseded_plan(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    repair_data_dir = marker_dir / "repair-data"
    marker_dir.mkdir()
    repair_data_dir.mkdir()
    workspace = tmp_path / "ws"
    plan_name = "m3-current-plan"
    old_plan_name = "m1-old-plan"
    spec_path = workspace / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    spec_path.parent.mkdir(parents=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    _write_live_session_marker(
        marker_dir,
        "demo-session",
        workspace,
        str(spec_path),
        run_kind="chain",
        plan_name=plan_name,
    )
    digest = hashlib.sha1(str(spec_path.resolve()).encode("utf-8")).hexdigest()[:12]
    _write_chain_state(
        workspace / ".megaplan" / "plans" / ".chains" / f"chain-{digest}.json",
        {"current_plan_name": plan_name, "last_state": "awaiting_human"},
    )
    _write_plan(
        workspace / ".megaplan" / "plans" / plan_name,
        {
            "name": plan_name,
            "current_state": "awaiting_human",
            "latest_failure": {
                "kind": "blocked_by_prereq",
                "message": "execute reported blocked tasks awaiting user action: T1",
            },
        },
        events_body="{}\n",
    )
    repair_data_path = repair_data_dir / "demo-session.repair-data.json"
    repair_data_path.write_text(
        json.dumps(
            {
                "session": "demo-session",
                "iterations": [
                    {
                        "i": 1,
                        "chain_state_summary": {"current_plan_name": old_plan_name},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    sidecar_path = repair_data_dir / "demo-session.needs-human.json"
    sidecar_path.write_text(
        json.dumps(
            {
                "summary": "old repair exhaustion",
                "repair_data_path": str(repair_data_path),
                "chain_current_plan_name": old_plan_name,
            }
        ),
        encoding="utf-8",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function("repair_needs_human_path"),
            _extract_wrapper_function("repair_needs_human_summary"),
            _extract_wrapper_function("repair_needs_human_matches_current_plan"),
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            _extract_wrapper_function("plan_terminal_status"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(repair_data_dir)!r}",
            f"LOG={str(log_path)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
babysitter_effective_mode() { printf 'superfixer\t\n'; }
babysitter_occurrence_digest() { echo a9c062b1cfe5; }
babysitter_running_for_occurrence() { return 1; }
babysitter_after_elapsed() { return 0; }
launch_status_trigger_babysitter() { echo BABYSITTER >&2; return 0; }
babysitter_policy_dispatch() {
  launch_status_trigger_babysitter "$@"
  report_item "$6" "$1" "repair" "babysitter_scheduled" "single-flash babysitter dispatched: $7" "$2" "$3"
}
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH >&2; return 1; }
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
chain_health_status() {
  CHAIN_HEALTH_STATUS=ok
  CHAIN_HEALTH_SUMMARY=
  CHAIN_HEALTH_ARTIFACT_PATH=
  CHAIN_HEALTH_LOG_MESSAGE=
}
""".strip(),
            f"launch_chain_tick demo-session {str(workspace)!r} {str(spec_path)!r} {str(report_path)!r} chain '' ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    log = log_path.read_text(encoding="utf-8")
    assert "\trepair\trepair_dispatched\t" not in report
    assert "\tnotify\ttest_notification_suppressed\t" in report
    assert "\tobserve\tneeds_human\told repair exhaustion" not in report
    assert "stale repair needs-human marker cleared" in log
    assert not sidecar_path.exists()
    assert "BABYSITTER" not in result.stderr
    assert "RELAUNCH" not in result.stderr
    assert "TMUX" not in result.stderr


def test_watchdog_clears_stale_needs_human_sidecar_for_superseded_plan(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    repair_data_dir = marker_dir / "repair-data"
    marker_dir.mkdir()
    repair_data_dir.mkdir()
    workspace = tmp_path / "ws"
    plan_name = "m3-current-plan"
    old_plan_name = "m1-old-plan"
    spec_path = workspace / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    spec_path.parent.mkdir(parents=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    _write_live_session_marker(
        marker_dir,
        "demo-session",
        workspace,
        str(spec_path),
        run_kind="chain",
        plan_name=plan_name,
    )
    digest = hashlib.sha1(str(spec_path.resolve()).encode("utf-8")).hexdigest()[:12]
    _write_chain_state(
        workspace / ".megaplan" / "plans" / ".chains" / f"chain-{digest}.json",
        {"current_plan_name": plan_name, "last_state": "awaiting_human"},
    )
    _write_plan(
        workspace / ".megaplan" / "plans" / plan_name,
        {
            "name": plan_name,
            "current_state": "awaiting_human",
            "latest_failure": {
                "kind": "blocked_by_prereq",
                "message": "execute reported blocked tasks awaiting user action: T1",
            },
        },
        events_body="{}\n",
    )
    repair_data_path = repair_data_dir / "demo-session.repair-data.json"
    repair_data_path.write_text(
        json.dumps(
            {
                "session": "demo-session",
                "iterations": [
                    {"i": 1, "chain_state_summary": {"current_plan_name": old_plan_name}}
                ],
            }
        ),
        encoding="utf-8",
    )
    sidecar_path = repair_data_dir / "demo-session.needs-human.json"
    sidecar_path.write_text(
        json.dumps(
            {
                "summary": "old repair exhaustion",
                "repair_data_path": str(repair_data_path),
                "chain_current_plan_name": old_plan_name,
            }
        ),
        encoding="utf-8",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function("repair_needs_human_path"),
            _extract_wrapper_function("repair_needs_human_summary"),
            _extract_wrapper_function("repair_needs_human_matches_current_plan"),
            _extract_wrapper_function_until("notify_needs_human", "adopt_unmarked_tmux_sessions"),
            _extract_wrapper_function("plan_terminal_status"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(repair_data_dir)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            f"LOG={str(log_path)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
babysitter_effective_mode() { printf 'superfixer\t\n'; }
babysitter_occurrence_digest() { echo a9c062b1cfe5; }
babysitter_running_for_occurrence() { return 1; }
babysitter_after_elapsed() { return 0; }
launch_status_trigger_babysitter() { echo BABYSITTER >&2; return 0; }
babysitter_policy_dispatch() {
  launch_status_trigger_babysitter "$@"
  report_item "$6" "$1" "repair" "babysitter_scheduled" "single-flash babysitter dispatched: $7" "$2" "$3"
}
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH >&2; return 1; }
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
chain_health_status() {
  CHAIN_HEALTH_STATUS=ok
  CHAIN_HEALTH_SUMMARY=
  CHAIN_HEALTH_ARTIFACT_PATH=
  CHAIN_HEALTH_LOG_MESSAGE=
}
""".strip(),
            f"launch_chain_tick demo-session {str(workspace)!r} {str(spec_path)!r} {str(report_path)!r} chain '' ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    log = log_path.read_text(encoding="utf-8")
    report = report_path.read_text(encoding="utf-8")
    # Legacy clears the stale sidecar (old plan != current plan)
    assert "stale repair needs-human marker cleared" in log
    assert not sidecar_path.exists()
    # The stale sidecar is cleared, but the current typed gate notifies instead
    # of entering machine repair.
    assert "\trepair\tbabysitter_scheduled\t" not in report
    assert "\tnotify\ttest_notification_suppressed\t" in report
    assert "\tobserve\tneeds_human\told repair exhaustion" not in report


def _prepare_meta_repair_launch_chain_tick_fixture(
    tmp_path: Path,
    *,
    payload_overrides: dict[str, object] | None = None,
    partial_liveness_ticks: int = 0,
    discord_status: str | None = None,
    true_blocker_plan: str | None = None,
) -> dict[str, Path]:
    marker_dir = tmp_path / "markers"
    repair_data_dir = tmp_path / "repair-data"
    workspace = tmp_path / "ws"
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"
    marker_dir.mkdir()
    repair_data_dir.mkdir()
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")

    payload: dict[str, object] = {
        "session": "demo-session",
        "workspace": str(workspace),
        "spec": str(spec_path),
        "run_kind": "chain",
        "plan_name": true_blocker_plan or "demo-plan",
        "outcome": "repairing",
        "attempts": [],
        "iterations": [],
        "current_failure_context": {},
        "discord_escalation": {},
    }
    if payload_overrides:
        payload.update(payload_overrides)

    repair_data_path = repair_data_dir / "demo-session.repair-data.json"
    repair_data_path.write_text(json.dumps(payload), encoding="utf-8")
    _write_live_session_marker(
        marker_dir,
        "demo-session",
        workspace,
        str(spec_path),
        run_kind="chain",
        plan_name=payload["plan_name"],
    )

    if partial_liveness_ticks:
        events_dir = tmp_path / "repair-data.d" / "events"
        events_dir.mkdir(parents=True)
        records = [
            {
                "session": "demo-session",
                "outcome": "partial_liveness",
                "health": "alive",
                "recorded_at": f"2026-07-02T00:00:0{i}Z",
                "run_kind": "chain",
                "plan_name": payload["plan_name"],
            }
            for i in range(partial_liveness_ticks)
        ]
        (events_dir / "events.jsonl").write_text(
            "\n".join(json.dumps(record) for record in records) + "\n",
            encoding="utf-8",
        )

    if discord_status is not None:
        plan_name = str(payload.get("plan_name") or "")
        digest = hashlib.sha1(str(spec_path.resolve()).encode("utf-8")).hexdigest()[:12]
        _write_chain_state(
            workspace / ".megaplan" / "plans" / ".chains" / f"chain-{digest}.json",
            {"current_plan_name": plan_name, "last_state": "awaiting_human"},
        )
        _write_plan(
            workspace / ".megaplan" / "plans" / plan_name,
            {
                "name": plan_name,
                "current_state": "awaiting_human",
                "latest_failure": {
                    "kind": "blocked_by_prereq",
                    "message": "awaiting human decision",
                },
            },
            events_body="{}\n",
        )
        escalations_dir = tmp_path / "repair-data.d" / "escalations"
        escalations_dir.mkdir(parents=True, exist_ok=True)
        escalation_id = "esc-001"
        records = [
            {
                "session": "demo-session",
                "event": "opened",
                "escalation_id": escalation_id,
                "current_plan": plan_name,
                "target_id": f"demo-session:{plan_name}",
                "blocker_verdict": "TRUE_BLOCKER" if true_blocker_plan else "AMBIGUOUS_BLOCKER",
                "authoritative_source": "chain_state",
            }
        ]
        if discord_status == "delivered":
            records.append(
                {
                    "session": "demo-session",
                    "event": "delivered",
                    "escalation_id": escalation_id,
                    "message_count": 1,
                }
            )
        else:
            records.append(
                {
                    "session": "demo-session",
                    "event": "unavailable",
                    "escalation_id": escalation_id,
                    "reason": discord_status,
                }
            )
        (escalations_dir / "escalations.jsonl").write_text(
            "\n".join(json.dumps(record) for record in records) + "\n",
            encoding="utf-8",
        )

    return {
        "marker_dir": marker_dir,
        "repair_data_dir": repair_data_dir,
        "workspace": workspace,
        "spec_path": spec_path,
        "report_path": report_path,
        "log_path": log_path,
    }


def test_launch_chain_tick_superfixer_skips_kimi_fallthrough(tmp_path: Path) -> None:
    """A successful status-trigger babysitter dispatch in the phase-contract
    fence reports babysitter_scheduled and NEVER falls through to a layered
    L1/L2 path (deleted with the layered stack)."""
    paths = _prepare_meta_repair_launch_chain_tick_fixture(tmp_path)
    stub = tmp_path / "babysitter-stub.sh"
    stub.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    stub.chmod(0o755)
    script = "\n\n".join(
        [
            _extract_wrapper_function("babysitter_occurrence_digest"),
            _extract_wrapper_function("babysitter_effective_mode"),
            _extract_wrapper_function("babysitter_running_for_occurrence"),
            _extract_wrapper_function("babysitter_after_elapsed"),
            _extract_wrapper_function("launch_status_trigger_babysitter"),
            _extract_wrapper_function("babysitter_policy_dispatch"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(paths['marker_dir'])!r}",
            f"REPAIR_DATA_DIR={str(paths['repair_data_dir'])!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}",
            f"LOG={str(paths['log_path'])!r}",
            "export CLOUD_WATCHDOG_BABYSITTER_BIN=" + shlex.quote(str(stub)) + "",
            "export ARNOLD_BABYSITTER_LAUNCH_GRACE_SECS=0.2",
            """
report_item() {
  printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\\n' "$*" >> "$LOG"; }
authority_gap_continue() { echo "AUTHORITY_GAP $*" >&2; }
plan_attention_status_env() {
  printf '%s\\n' "PLAN_STATUS_FAILURE_KIND='deterministic_phase_failure'"
  printf '%s\\n' "PLAN_STATUS_RETRY_STRATEGY='repair_phase_contract'"
  printf '%s\\n' "PLAN_STATUS_PLAN_NAME='demo-plan'"
}
dispatch_kimi_repair() { echo SHOULD_NOT_DISPATCH_KIMI >&2; return 0; }
emit_watchdog_incident_bridge_event() { :; }
""".strip(),
            (
                f"launch_chain_tick demo-session {str(paths['workspace'])!r} "
                f"{str(paths['spec_path'])!r} {str(paths['report_path'])!r} chain '' ''"
            ),
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert "SHOULD_NOT_DISPATCH_KIMI" not in result.stderr
    report = paths["report_path"].read_text(encoding="utf-8")
    assert "\trepair\tbabysitter_scheduled\t" in report
    assert "repair_unavailable" not in report
    assert "babysitter_off" not in report
    assert "single-flash babysitter launched" in paths["log_path"].read_text(encoding="utf-8")
    receipt_path = paths["repair_data_dir"] / "demo-session.babysitter-receipt.json"
    assert receipt_path.exists()


def _extract_phase_program() -> str:
    """Pull the python body of plan_phase_health_status() out of the wrapper."""
    text = _wrapper("arnold-watchdog")
    start = text.index("plan_phase_health_status() {")
    marker = "python3 - \"$workspace\" \"$run_kind\" \"$plan_name\" <<'PY'"
    py_start = text.index(marker, start)
    py_start = text.index("\n", py_start) + 1
    py_end = text.index("\nPY\n", py_start)
    return text[py_start:py_end]


def _run_phase(workspace: Path, run_kind: str = "chain", plan_name: str = "") -> str:
    program = _extract_phase_program()
    prog_path = workspace.parent / "_phase_prog.py"
    prog_path.write_text(program, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(prog_path), str(workspace), run_kind, plan_name],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"phase program failed: {result.stderr}"
    return result.stdout.strip()


def test_plan_phase_health_detects_workspace_drift_without_latest_failure(tmp_path: Path) -> None:
    workspace = tmp_path / "project"
    plan = workspace / ".megaplan" / "plans" / "m2-demo"
    plan.mkdir(parents=True)
    (plan / "state.json").write_text(
        json.dumps(
            {
                "current_state": "finalized",
                "active_step": {"phase": "execute", "worker_pid": 1234},
                "history": [],
            }
        ),
        encoding="utf-8",
    )
    (workspace / ".megaplan" / "cloud-chain-demo.log").write_text(
        "sandbox refused terminal: refusing terminal command: leading `cd /workspace/arnold` "
        "targets /workspace/arnold, which is outside the sandbox root/project directory "
        "/workspace/native-composition-followup/Arnold\n",
        encoding="utf-8",
    )

    result = _run_phase(workspace)

    assert result.startswith("workspace_drift:m2-demo:")
    assert "sandbox_refused_outside_project_root" in result


def test_plan_phase_health_ignores_sandbox_refusal_after_later_progress(tmp_path: Path) -> None:
    workspace = tmp_path / "project"
    plan = workspace / ".megaplan" / "plans" / "m2-demo"
    plan.mkdir(parents=True)
    (plan / "state.json").write_text(
        json.dumps(
            {
                "current_state": "finalized",
                "active_step": {"phase": "execute", "worker_pid": 1234},
                "history": [],
            }
        ),
        encoding="utf-8",
    )
    (workspace / ".megaplan" / "cloud-chain-demo.log").write_text(
        "\n".join(
            [
                "sandbox refused terminal: refusing terminal command: leading `cd /workspace/arnold` "
                "targets /workspace/arnold, which is outside the sandbox root/project directory "
                "/workspace/native-composition-followup/Arnold. Run commands relative to the project "
                "directory; do not `cd` to an absolute path outside the worktree.",
                "  [done] ┊ 💻 $         cd /workspace/arnold && python -c \"...\"  0.0s (0.0s)",
                "  [tool] (◕ᴗ◕✿) 💻 python -m pytest tests/arnold/pipeline/native/test_decorators.py",
                "  [done] ┊ 💻 $         python -m pytest tests/arnold/pipeline/native/test_decorators.py  1.4s (1.6s)",
                "[auto m2-demo] iter 2 state=critiqued next=gate valid_next=['gate', 'step']",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = _run_phase(workspace)

    assert result == "ok"


def test_plan_phase_health_ignores_sandbox_refusal_with_recent_active_step(tmp_path: Path) -> None:
    workspace = tmp_path / "project"
    plan = workspace / ".megaplan" / "plans" / "m2-demo"
    plan.mkdir(parents=True)
    (plan / "state.json").write_text(
        json.dumps(
            {
                "current_state": "finalized",
                "active_step": {
                    "phase": "execute",
                    "worker_pid": 1234,
                    "last_activity_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
                },
                "history": [],
            }
        ),
        encoding="utf-8",
    )
    (workspace / ".megaplan" / "cloud-chain-demo.log").write_text(
        "sandbox refused terminal: refusing terminal command: leading `cd /workspace/arnold` "
        "targets /workspace/arnold, which is outside the sandbox root/project directory "
        "/workspace/native-composition-followup/Arnold\n",
        encoding="utf-8",
    )

    result = _run_phase(workspace)

    assert result == "ok"


def test_plan_phase_health_ignores_sandbox_refusal_with_recent_events_only(tmp_path: Path) -> None:
    workspace = tmp_path / "project"
    plan = workspace / ".megaplan" / "plans" / "m2-demo"
    plan.mkdir(parents=True)
    (plan / "state.json").write_text(
        json.dumps(
            {
                "current_state": "finalized",
                "history": [],
            }
        ),
        encoding="utf-8",
    )
    (plan / "events.ndjson").write_text('{"event":"llm_stream"}\n', encoding="utf-8")
    (workspace / ".megaplan" / "cloud-chain-demo.log").write_text(
        "sandbox refused terminal: refusing terminal command: leading `cd /workspace/arnold` "
        "targets /workspace/arnold, which is outside the sandbox root/project directory "
        "/workspace/native-composition-followup/Arnold\n",
        encoding="utf-8",
    )

    result = _run_phase(workspace)

    assert result == "ok"


def _extract_stall_program() -> str:
    """Pull the python body of plan_progress_stall_status() out of the wrapper."""
    text = _wrapper("arnold-watchdog")
    start = text.index("plan_progress_stall_status() {")
    marker = "python3 - \"$workspace\" \"$MARKER_DIR\" \"$run_kind\" \"$plan_name\" <<'PY'"
    py_start = text.index(marker, start)
    py_start = text.index("\n", py_start) + 1
    py_end = text.index("\nPY\n", py_start)
    return text[py_start:py_end]


def _run_stall(
    workspace: Path,
    marker: Path,
    env_overrides: dict[str, str] | None = None,
    run_kind: str = "chain",
    plan_name: str = "",
) -> str:
    program = _extract_stall_program()
    prog_path = workspace.parent / "_stall_prog.py"
    prog_path.write_text(program, encoding="utf-8")
    env = dict(os.environ)
    if env_overrides:
        env.update(env_overrides)
    result = subprocess.run(
        [sys.executable, str(prog_path), str(workspace), str(marker), run_kind, plan_name],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert result.returncode == 0, f"stall program failed: {result.stderr}"
    return result.stdout.strip()


def _extract_chain_health_program() -> str:
    """Pull the python body of chain_health_status() out of the wrapper."""
    text = _wrapper("arnold-watchdog")
    start = text.index("chain_health_status() {")
    marker = 'eval "$(python3 - "$session" "$workspace" "$remote_spec_path" "$health" "$MARKER_DIR" "$REPAIR_DATA_DIR" <<\'PY\''
    py_start = text.index(marker, start)
    py_start = text.index("\n", py_start) + 1
    py_end = text.index("\nPY\n", py_start)
    return text[py_start:py_end]


def _parse_shell_assignments(stdout: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in stdout.strip().splitlines():
        name, sep, raw_value = line.partition("=")
        if not sep:
            continue
        values = shlex.split(raw_value)
        parsed[name] = values[0] if values else ""
    return parsed


def _run_chain_health(
    workspace: Path,
    marker: Path,
    repair_data_dir: Path,
    *,
    session: str = "demo",
    remote_spec_path: str = "",
    health: str = "stopped",
    env_overrides: dict[str, str] | None = None,
) -> dict[str, str]:
    program = _extract_chain_health_program()
    prog_path = workspace.parent / "_chain_health_prog.py"
    prog_path.write_text(program, encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        part
        for part in (str(REPO_ROOT), env.get("PYTHONPATH", ""))
        if part
    )
    if env_overrides:
        env.update(env_overrides)
    result = subprocess.run(
        [
            sys.executable,
            str(prog_path),
            session,
            str(workspace),
            remote_spec_path,
            health,
            str(marker),
            str(repair_data_dir),
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert result.returncode == 0, f"chain health program failed: {result.stderr}"
    return _parse_shell_assignments(result.stdout)


def _write_plan(plan_dir: Path, state: dict, plan_v_bodies: dict[str, str] | None = None,
                events_body: str = "") -> None:
    plan_dir.mkdir(parents=True, exist_ok=True)
    (plan_dir / "state.json").write_text(json.dumps(state), encoding="utf-8")
    for name, body in (plan_v_bodies or {}).items():
        (plan_dir / name).write_text(body, encoding="utf-8")
    if events_body:
        (plan_dir / "events.ndjson").write_text(events_body, encoding="utf-8")


def _write_chain_state(state_path: Path, state: dict) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state), encoding="utf-8")


def _write_runtime_bound_chain_state(
    workspace: Path,
    spec_path: str | Path,
    engine_root: str | Path,
    *,
    plan_name: str = "",
    metadata: dict[str, object] | None = None,
) -> Path:
    """Write chain state at the canonical ``.chains`` path the wrappers
    re-read on relaunch (digest over the resolved spec path, matching
    chain.spec._state_path_for)."""
    spec = Path(spec_path)
    if not spec.is_absolute():
        spec = Path(workspace) / spec
    spec = spec.resolve()
    digest = hashlib.sha1(str(spec).encode("utf-8")).hexdigest()[:12]
    state: dict[str, object] = {"current_plan_name": plan_name, "last_state": "blocked"}
    if metadata is None:
        metadata = {"execution_environment": {"engine_root": str(engine_root)}}
    state["metadata"] = metadata
    path = workspace / ".megaplan" / "plans" / ".chains" / f"chain-{digest}.json"
    _write_chain_state(path, state)
    return path


def _relaunch_runtime_root(tmp_path: Path, name: str = "runtime") -> Path:
    root = tmp_path / name
    _init_git_repo(root)
    return root


def _init_git_repo(path: Path) -> str:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "tests@example.invalid"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "Watchdog Tests"], cwd=path, check=True)
    (path / "README.md").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=path, check=True)
    subprocess.run(["git", "commit", "-m", "base"], cwd=path, check=True, capture_output=True, text=True)
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()


def test_chain_health_status_is_wired_into_launch_chain_tick() -> None:
    text = _wrapper("arnold-watchdog")

    assert "chain_health_status()" in text
    assert 'chain_health_status "$session" "$workspace" "$remote_spec_path" "$health"' in text
    assert 'babysitter_policy_dispatch "$session" "$workspace" "$remote_spec" "$run_kind" "$plan_name" "$report_items"' in text
    assert '"chain health issue (${CHAIN_HEALTH_STATUS:-chain_issue}); $chain_health_message"' in text


def test_watchdog_scan_once_fails_closed_when_observation_bootstrap_stays_blind(tmp_path: Path) -> None:
    marker_dir = tmp_path / "missing-markers"
    order_path = tmp_path / "order.log"
    status_dir = tmp_path / "status"

    script = "\n\n".join(
        [
            _extract_wrapper_function_until("write_watchdog_observation_error", "watchdog_observation_runtime_check"),
            _extract_wrapper_function("bootstrap_watchdog_observation"),
            f"MARKER_DIR={str(marker_dir)!r}",
            f"STATUS_DIR={str(status_dir)!r}",
            """
log() { printf '%s\n' "$*" >> "$ORDER_PATH"; }
watchdog_observation_runtime_check() { printf '%s\n' broken >&2; return 1; }
sync_editable_source_branch() { printf '%s\n' sync >> "$ORDER_PATH"; return 1; }
report_item() { printf '%s\n' "report:$4" >> "$ORDER_PATH"; }
SRC_DIR=/workspace/arnold
SYNC_BRANCH=editible-install
""".strip(),
            f"ORDER_PATH={str(order_path)!r}",
            'report_items="$(mktemp)"',
            'bootstrap_watchdog_observation "$report_items"',
        ]
    )

    result = _run_watchdog_shell(script)
    assert result.returncode == 1, result.stderr
    lines = order_path.read_text(encoding="utf-8").splitlines()
    assert "report:observation_blind" in lines
    assert "sync" not in lines
    error_payload = json.loads((status_dir / "cloud-status.write-error.json").read_text(encoding="utf-8"))
    assert "observation bootstrap failed" in error_payload["error"]
    atomic_payload = json.loads(
        (status_dir / "watchdog-observation-failure.json").read_text(encoding="utf-8")
    )
    assert atomic_payload["status"] == "failed"


def test_watchdog_session_health_status_treats_live_worker_process_as_alive_without_tmux(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    spec_path = workspace / ".megaplan" / "initiatives" / "demo" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    digest = hashlib.sha1(str(spec_path.resolve()).encode("utf-8")).hexdigest()[:12]
    chain_state_path = workspace / ".megaplan" / "plans" / ".chains" / f"chain-{digest}.json"
    chain_state_path.parent.mkdir(parents=True, exist_ok=True)
    plan_name = "m3-demo-plan"

    worker = subprocess.Popen(["sleep", "30"])
    try:
        chain_state_path.write_text(json.dumps({"current_plan_name": plan_name}), encoding="utf-8")
        plan_dir = workspace / ".megaplan" / "plans" / plan_name
        plan_dir.mkdir(parents=True, exist_ok=True)
        (plan_dir / "state.json").write_text(
            json.dumps({"active_step": {"phase": "execute", "worker_pid": worker.pid}}),
            encoding="utf-8",
        )

        script = "\n\n".join(
            [
                _extract_wrapper_function("matching_runner_process_alive"),
                _extract_wrapper_function("session_health_status"),
                """
tmux() { return 1; }
chain_wait_status() { echo none; }
""".strip(),
                f"session_health_status demo-session {shlex.quote(str(workspace))} {shlex.quote(str(spec_path))} chain ''",
            ]
        )

        result = _run_watchdog_shell(script)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "alive"
    finally:
        worker.terminate()
        worker.wait(timeout=5)


def test_watchdog_chain_health_short_circuits_plan_repair_dispatch(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    repair_dir = tmp_path / "repair-data"
    marker_dir.mkdir()
    repair_dir.mkdir()
    workspace = tmp_path / "ws"
    workspace.mkdir()
    spec_path = workspace / "demo-spec.yaml"
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    _write_live_session_marker(
        marker_dir,
        "demo-session",
        workspace,
        str(spec_path),
        run_kind="chain",
    )
    report_path = tmp_path / "report.tsv"

    script = "\n\n".join(
        [
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(repair_dir)!r}",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { :; }
session_health_status() { echo alive; }
chain_health_status() {
  CHAIN_HEALTH_STATUS=chain_cycle
  CHAIN_HEALTH_SUMMARY='chain cycle detected'
  CHAIN_HEALTH_ARTIFACT_PATH=/tmp/chain-health.json
}
plan_phase_health_status() { echo phase_failure:should-not-run; }
plan_progress_stall_status() { echo progress_stall:should-not-run; }
plan_attention_status_env() { echo SHOULD_NOT_RUN >&2; }
babysitter_effective_mode() { printf 'superfixer\t\n'; }
babysitter_occurrence_digest() { echo a9c062b1cfe5; }
babysitter_running_for_occurrence() { return 1; }
babysitter_after_elapsed() { return 0; }
launch_status_trigger_babysitter() { echo BABYSITTER >&2; return 0; }
babysitter_policy_dispatch() {
  launch_status_trigger_babysitter "$@"
  report_item "$6" "$1" "repair" "babysitter_scheduled" "single-flash babysitter dispatched: $7" "$2" "$3"
}
mechanical_relaunch_attempted_previously() { return 1; }
kimi_dispatch_failed_previously() { return 1; }
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH; }
safe_name() { printf '%s\n' "$1"; }
tmux() { echo TMUX >&2; return 1; }
""".strip(),
            f"launch_chain_tick demo-session {str(workspace)!r} {str(spec_path)!r} {str(report_path)!r} chain '' ''",
        ]
    )

    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\trepair\tbabysitter_scheduled\tsingle-flash babysitter dispatched: chain health issue (chain_cycle); chain cycle detected; artifact=/tmp/chain-health.json\t" in report
    assert "SHOULD_NOT_RUN" not in result.stderr
    assert "TMUX" not in result.stderr


def test_chain_health_status_detects_repeating_merged_pr_completion_guard_cycle() -> None:
    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    repair_dir = tmp / "repair-data"
    spec_path = ws / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    digest = hashlib.sha1(str(spec_path.resolve()).encode("utf-8")).hexdigest()[:12]
    plan_name = "m8-generated-assets-and-merge-20260629-1937"
    _write_plan(
        ws / ".megaplan" / "plans" / plan_name,
        {"current_state": "blocked", "iteration": 1},
        events_body=json.dumps({"kind": "phase_end", "phase": "execute"}) + "\n",
    )
    _write_chain_state(
        ws / ".megaplan" / "plans" / ".chains" / f"chain-{digest}.json",
        {
            "current_milestone_index": 7,
            "current_plan_name": plan_name,
            "last_state": "authority_divergence",
            "pr_number": 128,
            "pr_state": "merged",
            "completed": [{"label": "m1"}, {"label": "m2"}],
        },
    )
    (ws / ".megaplan" / "cloud-chain-demo.log").parent.mkdir(parents=True, exist_ok=True)
    repeated = "\n".join(
        [
            "[chain] PR #128 merged; advancing past m8-generated-assets-merge-result-conformance",
            "[chain] completion guard blocked m8-generated-assets-merge-result-conformance: plan m8-generated-assets-and-merge-20260629-1937 current_state='blocked' is not terminal-success 'done'",
            '[chain] synced last_state for m8-generated-assets-and-merge-20260629-1937: authority_divergence -> blocked',
        ]
        * 3
    )
    (ws / ".megaplan" / "cloud-chain-demo.log").write_text(repeated + "\n", encoding="utf-8")

    payload = _run_chain_health(
        ws,
        marker,
        repair_dir,
        remote_spec_path=str(spec_path),
        env_overrides={"CLOUD_WATCHDOG_CHAIN_CYCLE_REPEATS": "3"},
    )

    assert payload["CHAIN_HEALTH_STATUS"] == "chain_cycle"
    artifact_path = Path(payload["CHAIN_HEALTH_ARTIFACT_PATH"])
    assert artifact_path.exists()
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    assert artifact["issue_kind"] == "chain_cycle"
    assert artifact["completion_guard"]["milestone"] == "m8-generated-assets-merge-result-conformance"
    assert artifact["completion_guard"]["repeat_count"] == 3
    assert "## CHAIN HEALTH EVIDENCE" in artifact["evidence_markdown"]
    assert "Route to arnold_pipelines/megaplan/chain/" in artifact["why_chain_layer_issue"]


def test_chain_health_rejects_incomplete_done_state() -> None:
    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    repair_dir = tmp / "repair-data"
    spec_path = ws / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text(
        "milestones:\n"
        "  - label: m1\n"
        "    idea: m1.md\n"
        "  - label: m2\n"
        "    idea: m2.md\n",
        encoding="utf-8",
    )
    digest = hashlib.sha1(str(spec_path.resolve()).encode("utf-8")).hexdigest()[:12]
    _write_chain_state(
        ws / ".megaplan" / "plans" / ".chains" / f"chain-{digest}.json",
        {
            "current_milestone_index": 1,
            "current_plan_name": "",
            "last_state": "done",
            "completed": [{"label": "m1", "status": "done"}],
        },
    )

    payload = _run_chain_health(
        ws,
        marker,
        repair_dir,
        remote_spec_path=str(spec_path),
    )

    assert payload["CHAIN_HEALTH_STATUS"] == "chain_inconsistent_done"
    assert payload["CHAIN_HEALTH_KIND"] == "chain_inconsistent_done"
    assert "1/2 milestones" in payload["CHAIN_HEALTH_SUMMARY"]
    artifact = json.loads(Path(payload["CHAIN_HEALTH_ARTIFACT_PATH"]).read_text(encoding="utf-8"))
    assert artifact["issue_kind"] == "chain_inconsistent_done"
    assert "last_state=done" in artifact["evidence_markdown"]


def test_chain_health_status_leaves_one_off_completion_guard_repair_eligible() -> None:
    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    repair_dir = tmp / "repair-data"
    plan_name = "sprint-1-safe-compiler-20260630-0033"
    _write_plan(
        ws / ".megaplan" / "plans" / plan_name,
        {"current_state": "blocked", "iteration": 1},
        events_body=json.dumps({"kind": "phase_end", "phase": "execute"}) + "\n",
    )
    _write_chain_state(
        ws / ".megaplan" / "plans" / ".chains" / "chain-demo.json",
        {
            "current_milestone_index": 0,
            "current_plan_name": plan_name,
            "last_state": "authority_divergence",
            "pr_state": "",
            "completed": [],
        },
    )
    (ws / ".megaplan" / "cloud-chain-demo.log").parent.mkdir(parents=True, exist_ok=True)
    (ws / ".megaplan" / "cloud-chain-demo.log").write_text(
        "[chain] completion guard blocked sprint-01-safe-compiler-foundation: "
        "no semantic diff from milestone_base_sha 9d2d53e to local HEAD; "
        "no typed no-op completion waiver found\n",
        encoding="utf-8",
    )

    payload = _run_chain_health(ws, marker, repair_dir, health="stopped")

    assert payload["CHAIN_HEALTH_STATUS"] == "ok"
    assert payload["CHAIN_HEALTH_ARTIFACT_PATH"] == ""


def test_chain_health_status_escalates_recurring_completion_guard_with_zero_git_advancement() -> None:
    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    repair_dir = tmp / "repair-data"
    base_sha = _init_git_repo(ws)
    plan_name = "sprint-1-safe-compiler-20260630-0033"
    _write_plan(
        ws / ".megaplan" / "plans" / plan_name,
        {
            "current_state": "blocked",
            "iteration": 3,
            "meta": {"chain_policy": {"milestone_base_sha": base_sha}},
        },
        events_body=json.dumps({"kind": "phase_end", "phase": "execute"}) + "\n",
    )
    _write_chain_state(
        ws / ".megaplan" / "plans" / ".chains" / "chain-demo.json",
        {
            "current_milestone_index": 0,
            "current_plan_name": plan_name,
            "last_state": "authority_divergence",
            "pr_state": "",
            "completed": [],
        },
    )
    (ws / ".megaplan" / "cloud-chain-demo.log").parent.mkdir(parents=True, exist_ok=True)
    (ws / ".megaplan" / "cloud-chain-demo.log").write_text(
        (
            "[chain] completion guard blocked sprint-01-safe-compiler-foundation: "
            f"no semantic diff from milestone_base_sha {base_sha} to local HEAD; "
            "no typed no-op completion waiver found\n"
        )
        * 3,
        encoding="utf-8",
    )

    payload = _run_chain_health(
        ws,
        marker,
        repair_dir,
        health="stopped",
        env_overrides={"CLOUD_WATCHDOG_CHAIN_COMPLETION_GUARD_REPEATS": "3"},
    )

    assert payload["CHAIN_HEALTH_STATUS"] == "needs_human"
    assert "produces NO code changes" in payload["CHAIN_HEALTH_SUMMARY"]
    assert "Not auto-repairable" in payload["CHAIN_HEALTH_SUMMARY"]
    artifact = json.loads(Path(payload["CHAIN_HEALTH_ARTIFACT_PATH"]).read_text(encoding="utf-8"))
    assert artifact["issue_kind"] == "plan_noop_completion_guard"
    assert artifact["completion_guard"]["repeat_count"] == 3
    assert artifact["details"]["completion_guard_advancement"]["available"] is True
    assert artifact["details"]["completion_guard_advancement"]["ahead_count"] == 0
    assert artifact["details"]["completion_guard_worktree"]["dirty"] is False


def test_chain_health_status_classifies_zero_git_advancement_with_dirty_worktree_as_commit_bug() -> None:
    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    repair_dir = tmp / "repair-data"
    base_sha = _init_git_repo(ws)
    (ws / "compiler.py").write_text("print('uncommitted execute output')\n", encoding="utf-8")
    plan_name = "sprint-1-safe-compiler-20260630-0033"
    _write_plan(
        ws / ".megaplan" / "plans" / plan_name,
        {
            "current_state": "blocked",
            "iteration": 3,
            "meta": {"chain_policy": {"milestone_base_sha": base_sha}},
        },
        events_body=json.dumps({"kind": "phase_end", "phase": "execute"}) + "\n",
    )
    _write_chain_state(
        ws / ".megaplan" / "plans" / ".chains" / "chain-demo.json",
        {
            "current_milestone_index": 0,
            "current_plan_name": plan_name,
            "last_state": "authority_divergence",
            "pr_state": "",
            "completed": [],
        },
    )
    (ws / ".megaplan" / "cloud-chain-demo.log").parent.mkdir(parents=True, exist_ok=True)
    (ws / ".megaplan" / "cloud-chain-demo.log").write_text(
        (
            "[chain] completion guard blocked sprint-01-safe-compiler-foundation: "
            f"no semantic diff from milestone_base_sha {base_sha} to local HEAD; "
            "no typed no-op completion waiver found\n"
        )
        * 3,
        encoding="utf-8",
    )

    payload = _run_chain_health(
        ws,
        marker,
        repair_dir,
        health="stopped",
        env_overrides={"CLOUD_WATCHDOG_CHAIN_COMPLETION_GUARD_REPEATS": "3"},
    )

    assert payload["CHAIN_HEALTH_STATUS"] == "chain_uncommitted_execute_output"
    assert "execute output was not committed" in payload["CHAIN_HEALTH_SUMMARY"]
    assert "no-op waiver" in payload["CHAIN_HEALTH_SUMMARY"]
    assert "CHAIN HEALTH EVIDENCE: working tree has 1 uncommitted files" in payload["CHAIN_HEALTH_LOG_MESSAGE"]
    artifact = json.loads(Path(payload["CHAIN_HEALTH_ARTIFACT_PATH"]).read_text(encoding="utf-8"))
    assert artifact["issue_kind"] == "chain_uncommitted_execute_output"
    worktree = artifact["details"]["completion_guard_worktree"]
    assert worktree["dirty"] is True
    assert worktree["uncommitted_file_count"] == 1
    assert "compiler.py" in "\n".join(worktree["sample"])
    assert "Working tree evidence: 1 uncommitted files" in artifact["evidence_markdown"]
    assert "commit-and-push gating" in artifact["evidence_markdown"]


def test_chain_health_status_classifies_repeated_pr_progression_publish_guard_as_commit_bug() -> None:
    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    repair_dir = tmp / "repair-data"
    base_sha = _init_git_repo(ws)
    (ws / "compiler.py").write_text("print('uncommitted execute output')\n", encoding="utf-8")
    plan_name = "sprint-1-safe-compiler-20260630-0033"
    _write_plan(
        ws / ".megaplan" / "plans" / plan_name,
        {
            "current_state": "finalized",
            "iteration": 3,
            "meta": {"chain_policy": {"milestone_base_sha": base_sha}},
        },
        events_body=json.dumps({"kind": "phase_end", "phase": "execute"}) + "\n",
    )
    _write_chain_state(
        ws / ".megaplan" / "plans" / ".chains" / "chain-demo.json",
        {
            "current_milestone_index": 0,
            "current_plan_name": plan_name,
            "last_state": "authority_divergence",
            "pr_number": 77,
            "pr_state": "merged",
            "completed": [],
        },
    )
    (ws / ".megaplan" / "cloud-chain-demo.log").parent.mkdir(parents=True, exist_ok=True)
    (ws / ".megaplan" / "cloud-chain-demo.log").write_text(
        (
            "[chain] PR progression blocked sprint-01-safe-compiler-foundation: "
            "plan sprint-1-safe-compiler-20260630-0033 has unpublished claimed changes after PR merged: compiler.py\n"
        )
        * 3,
        encoding="utf-8",
    )

    payload = _run_chain_health(
        ws,
        marker,
        repair_dir,
        health="stopped",
        env_overrides={"CLOUD_WATCHDOG_CHAIN_COMPLETION_GUARD_REPEATS": "3"},
    )

    assert payload["CHAIN_HEALTH_STATUS"] == "chain_uncommitted_execute_output"
    assert "unpublished in a dirty worktree" in payload["CHAIN_HEALTH_SUMMARY"]
    assert "publish guards" in payload["CHAIN_HEALTH_LOG_MESSAGE"]
    artifact = json.loads(Path(payload["CHAIN_HEALTH_ARTIFACT_PATH"]).read_text(encoding="utf-8"))
    assert artifact["issue_kind"] == "chain_uncommitted_execute_output"
    assert artifact["details"]["completion_guard_kind"] == "pr_progression"
    worktree = artifact["details"]["completion_guard_worktree"]
    assert worktree["dirty"] is True
    assert worktree["uncommitted_file_count"] == 1
    assert "compiler.py" in "\n".join(worktree["sample"])
    assert "PR progression guard evidence" in artifact["evidence_markdown"]


def test_chain_health_status_keeps_recurring_completion_guard_repair_eligible_when_git_advanced() -> None:
    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    repair_dir = tmp / "repair-data"
    base_sha = _init_git_repo(ws)
    (ws / "compiler.py").write_text("print('work landed')\n", encoding="utf-8")
    subprocess.run(["git", "add", "compiler.py"], cwd=ws, check=True)
    subprocess.run(["git", "commit", "-m", "land work"], cwd=ws, check=True, capture_output=True, text=True)
    plan_name = "sprint-1-safe-compiler-20260630-0033"
    _write_plan(
        ws / ".megaplan" / "plans" / plan_name,
        {
            "current_state": "blocked",
            "iteration": 3,
            "meta": {"chain_policy": {"milestone_base_sha": base_sha}},
        },
        events_body=json.dumps({"kind": "phase_end", "phase": "execute"}) + "\n",
    )
    _write_chain_state(
        ws / ".megaplan" / "plans" / ".chains" / "chain-demo.json",
        {
            "current_milestone_index": 0,
            "current_plan_name": plan_name,
            "last_state": "authority_divergence",
            "pr_state": "",
            "completed": [],
        },
    )
    (ws / ".megaplan" / "cloud-chain-demo.log").parent.mkdir(parents=True, exist_ok=True)
    (ws / ".megaplan" / "cloud-chain-demo.log").write_text(
        (
            "[chain] completion guard blocked sprint-01-safe-compiler-foundation: "
            f"no semantic diff from milestone_base_sha {base_sha} to local HEAD; "
            "no typed no-op completion waiver found\n"
        )
        * 3,
        encoding="utf-8",
    )

    payload = _run_chain_health(
        ws,
        marker,
        repair_dir,
        health="stopped",
        env_overrides={"CLOUD_WATCHDOG_CHAIN_COMPLETION_GUARD_REPEATS": "3"},
    )

    assert payload["CHAIN_HEALTH_STATUS"] == "ok"
    assert payload["CHAIN_HEALTH_ARTIFACT_PATH"] == ""


def test_chain_health_status_detects_stuck_nonterminal_across_ticks() -> None:
    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    repair_dir = tmp / "repair-data"
    _write_chain_state(
        ws / ".megaplan" / "plans" / ".chains" / "chain-demo.json",
        {
            "current_milestone_index": 4,
            "current_plan_name": "demo-plan",
            "last_state": "authority_divergence",
            "pr_state": "merged",
            "completed": [{"label": "m1"}],
        },
    )
    (ws / ".megaplan" / "cloud-chain-demo.log").parent.mkdir(parents=True, exist_ok=True)
    (ws / ".megaplan" / "cloud-chain-demo.log").write_text(
        "[chain] completion guard blocked demo: still blocked\n",
        encoding="utf-8",
    )

    first = _run_chain_health(
        ws,
        marker,
        repair_dir,
        health="alive",
        env_overrides={"CLOUD_WATCHDOG_CHAIN_STUCK_TICKS": "2"},
    )
    second = _run_chain_health(
        ws,
        marker,
        repair_dir,
        health="alive",
        env_overrides={"CLOUD_WATCHDOG_CHAIN_STUCK_TICKS": "2"},
    )

    assert first["CHAIN_HEALTH_STATUS"] == "ok"
    assert second["CHAIN_HEALTH_STATUS"] == "chain_stuck"
    artifact = json.loads(Path(second["CHAIN_HEALTH_ARTIFACT_PATH"]).read_text(encoding="utf-8"))
    assert artifact["issue_kind"] == "chain_stuck_nonterminal"
    assert artifact["details"]["stuck_ticks"] == 2
    assert artifact["chain_state_summary"]["last_state"] == "authority_divergence"


def test_chain_health_status_ignores_stuck_nonterminal_while_plan_step_is_active() -> None:
    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    repair_dir = tmp / "repair-data"
    _write_chain_state(
        ws / ".megaplan" / "plans" / ".chains" / "chain-demo.json",
        {
            "current_milestone_index": 1,
            "current_plan_name": "m1-demo-plan",
            "last_state": "between_milestones",
            "pr_state": "",
            "completed": [{"label": "m0"}],
        },
    )
    _write_plan(
        ws / ".megaplan" / "plans" / "m1-demo-plan",
        {
            "current_state": "finalized",
            "active_step": {"phase": "execute", "started_at": "2026-07-03T16:31:05Z"},
        },
    )
    (ws / ".megaplan" / "cloud-chain-demo.log").parent.mkdir(parents=True, exist_ok=True)
    (ws / ".megaplan" / "cloud-chain-demo.log").write_text(
        "[chain] milestone m1 starting\n",
        encoding="utf-8",
    )

    first = _run_chain_health(
        ws,
        marker,
        repair_dir,
        health="alive",
        env_overrides={"CLOUD_WATCHDOG_CHAIN_STUCK_TICKS": "2"},
    )
    second = _run_chain_health(
        ws,
        marker,
        repair_dir,
        health="alive",
        env_overrides={"CLOUD_WATCHDOG_CHAIN_STUCK_TICKS": "2"},
    )

    assert first["CHAIN_HEALTH_STATUS"] == "ok"
    assert second["CHAIN_HEALTH_STATUS"] == "ok"
    assert second["CHAIN_HEALTH_ARTIFACT_PATH"] == ""


def test_chain_health_status_ignores_stuck_nonterminal_when_chain_last_state_mirrors_blocked_plan() -> None:
    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    repair_dir = tmp / "repair-data"
    _write_chain_state(
        ws / ".megaplan" / "plans" / ".chains" / "chain-demo.json",
        {
            "current_milestone_index": 1,
            "current_plan_name": "m1-demo-plan",
            "last_state": "blocked",
            "pr_state": "open",
            "completed": [{"label": "m0"}],
        },
    )
    _write_plan(
        ws / ".megaplan" / "plans" / "m1-demo-plan",
        {
            "current_state": "blocked",
            "latest_failure": {
                "kind": "execution_blocked",
                "phase": "execute",
                "message": "execute blocked by quality gates",
            },
        },
    )
    (ws / ".megaplan" / "cloud-chain-demo.log").parent.mkdir(parents=True, exist_ok=True)
    (ws / ".megaplan" / "cloud-chain-demo.log").write_text(
        "[chain] resuming existing plan m1-demo-plan for m1\n",
        encoding="utf-8",
    )

    first = _run_chain_health(
        ws,
        marker,
        repair_dir,
        health="alive",
        env_overrides={"CLOUD_WATCHDOG_CHAIN_STUCK_TICKS": "2"},
    )
    second = _run_chain_health(
        ws,
        marker,
        repair_dir,
        health="alive",
        env_overrides={"CLOUD_WATCHDOG_CHAIN_STUCK_TICKS": "2"},
    )

    assert first["CHAIN_HEALTH_STATUS"] == "ok"
    assert second["CHAIN_HEALTH_STATUS"] == "ok"
    assert second["CHAIN_HEALTH_ARTIFACT_PATH"] == ""


def test_chain_health_status_classifies_unclean_base_before_generic_stuck() -> None:
    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    repair_dir = tmp / "repair-data"
    _write_chain_state(
        ws / ".megaplan" / "plans" / ".chains" / "chain-demo.json",
        {
            "current_milestone_index": 1,
            "current_plan_name": "m1-demo-plan",
            "last_state": "blocked",
            "pr_state": "",
            "completed": [{"label": "m0"}],
        },
    )
    (ws / ".megaplan" / "cloud-chain-demo.log").parent.mkdir(parents=True, exist_ok=True)
    (ws / ".megaplan" / "cloud-chain-demo.log").write_text(
        "[chain] retrying milestone m1\n"
        '{"error": "unclean_base", "message": "require_clean_base: working base carries uncommitted WIP"}\n',
        encoding="utf-8",
    )

    payload = _run_chain_health(
        ws,
        marker,
        repair_dir,
        health="stopped",
        env_overrides={"CLOUD_WATCHDOG_CHAIN_STUCK_TICKS": "2"},
    )

    assert payload["CHAIN_HEALTH_STATUS"] == "chain_unclean_base"
    assert "require_clean_base found carried WIP" in payload["CHAIN_HEALTH_SUMMARY"]
    assert "retry-preservation issue" in payload["CHAIN_HEALTH_LOG_MESSAGE"]
    artifact = json.loads(Path(payload["CHAIN_HEALTH_ARTIFACT_PATH"]).read_text(encoding="utf-8"))
    assert artifact["issue_kind"] == "chain_unclean_base"
    assert artifact["details"]["dirty_base_signal"] is True
    assert "Unclean-base evidence" in artifact["evidence_markdown"]


def test_chain_health_status_detects_github_large_file_push_rejection() -> None:
    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    repair_dir = tmp / "repair-data"
    plan_name = "demo-plan"
    _write_plan(
        ws / ".megaplan" / "plans" / plan_name,
        {
            "current_state": "failed",
            "latest_failure": {
                "kind": "phase_callback_failed",
                "phase": "review",
                "message": (
                    "phase-complete callback failed after 'review': "
                    "git push --no-verify origin HEAD:demo exited 1"
                ),
            },
        },
    )
    _write_chain_state(
        ws / ".megaplan" / "plans" / ".chains" / "chain-demo.json",
        {
            "current_milestone_index": 0,
            "current_plan_name": plan_name,
            "last_state": "failed",
            "completed": [],
        },
    )
    (ws / ".megaplan" / "cloud-chain-demo.log").parent.mkdir(parents=True, exist_ok=True)
    (ws / ".megaplan" / "cloud-chain-demo.log").write_text(
        "\n".join(
            [
                "[chain] git push --no-verify origin HEAD:demo -> rc=1",
                "remote: error: GH001: Large files detected.",
                "remote: error: File .megaplan/epics/demo-plan/events.jsonl is 101.74 MB; this exceeds GitHub's file size limit of 100.00 MB",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    payload = _run_chain_health(ws, marker, repair_dir, health="stopped")

    assert payload["CHAIN_HEALTH_STATUS"] == "chain_large_file_push_rejection"
    assert payload["CHAIN_HEALTH_KIND"] == "git_large_file_push_rejection"
    assert "oversized runtime journal" in payload["CHAIN_HEALTH_SUMMARY"]
    assert "large-file limit" in payload["CHAIN_HEALTH_LOG_MESSAGE"]
    artifact = json.loads(Path(payload["CHAIN_HEALTH_ARTIFACT_PATH"]).read_text(encoding="utf-8"))
    assert artifact["issue_kind"] == "git_large_file_push_rejection"
    assert artifact["details"]["runtime_journal_patterns"] == [
        ".megaplan/epics/*/events.jsonl",
        ".megaplan/plans/*/events.ndjson",
        ".megaplan/plans/*/execution_trace.jsonl",
    ]


def test_chain_health_status_detects_busy_no_advance_across_ticks() -> None:
    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    repair_dir = tmp / "repair-data"
    plan_name = "demo-plan"
    _write_plan(
        ws / ".megaplan" / "plans" / plan_name,
        {"current_state": "planning", "iteration": 1},
        events_body=json.dumps({"kind": "phase_started", "phase": "execute"}) + "\n",
    )
    _write_chain_state(
        ws / ".megaplan" / "plans" / ".chains" / "chain-demo.json",
        {
            "current_milestone_index": 2,
            "current_plan_name": plan_name,
            "last_state": "planning",
            "pr_state": "open",
            "completed": [{"label": "m1"}],
        },
    )

    assert _run_chain_health(ws, marker, repair_dir, env_overrides={"CLOUD_WATCHDOG_CHAIN_NO_ADVANCE_TICKS": "2"})["CHAIN_HEALTH_STATUS"] == "ok"
    events_path = ws / ".megaplan" / "plans" / plan_name / "events.ndjson"
    events_path.write_text(
        events_path.read_text(encoding="utf-8") + json.dumps({"kind": "phase_end", "phase": "execute"}) + "\n",
        encoding="utf-8",
    )
    assert _run_chain_health(ws, marker, repair_dir, env_overrides={"CLOUD_WATCHDOG_CHAIN_NO_ADVANCE_TICKS": "2"})["CHAIN_HEALTH_STATUS"] == "ok"
    events_path.write_text(
        events_path.read_text(encoding="utf-8") + json.dumps({"kind": "phase_started", "phase": "review"}) + "\n",
        encoding="utf-8",
    )
    third = _run_chain_health(
        ws,
        marker,
        repair_dir,
        env_overrides={"CLOUD_WATCHDOG_CHAIN_NO_ADVANCE_TICKS": "2"},
    )

    assert third["CHAIN_HEALTH_STATUS"] == "chain_no_advance"
    artifact = json.loads(Path(third["CHAIN_HEALTH_ARTIFACT_PATH"]).read_text(encoding="utf-8"))
    assert artifact["issue_kind"] == "chain_no_advance"
    assert artifact["details"]["no_advance_ticks"] == 2
    assert artifact["chain_state_summary"]["current_milestone_index"] == 2


def test_chain_health_no_advance_ignores_active_plan_step() -> None:
    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    repair_dir = tmp / "repair-data"
    plan_name = "demo-plan"
    _write_plan(
        ws / ".megaplan" / "plans" / plan_name,
        {
            "current_state": "finalized",
            "iteration": 1,
            "active_step": {"phase": "execute", "worker_pid": 1234},
        },
        events_body=json.dumps({"kind": "phase_started", "phase": "execute"}) + "\n",
    )
    _write_chain_state(
        ws / ".megaplan" / "plans" / ".chains" / "chain-demo.json",
        {
            "current_milestone_index": 2,
            "current_plan_name": plan_name,
            "last_state": "prepped",
            "completed": [{"label": "m1"}],
        },
    )

    env = {"CLOUD_WATCHDOG_CHAIN_NO_ADVANCE_TICKS": "2"}
    assert _run_chain_health(ws, marker, repair_dir, env_overrides=env)["CHAIN_HEALTH_STATUS"] == "ok"
    events_path = ws / ".megaplan" / "plans" / plan_name / "events.ndjson"
    for i in range(3):
        events_path.write_text(
            events_path.read_text(encoding="utf-8") + json.dumps({"kind": "stderr", "i": i}) + "\n",
            encoding="utf-8",
        )
        result = _run_chain_health(ws, marker, repair_dir, env_overrides=env)
        assert result["CHAIN_HEALTH_STATUS"] == "ok"


def test_chain_health_no_advance_ignores_existing_counter_after_plan_becomes_live() -> None:
    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    repair_dir = tmp / "repair-data"
    plan_name = "demo-plan"
    _write_plan(
        ws / ".megaplan" / "plans" / plan_name,
        {
            "current_state": "executing",
            "iteration": 2,
            "active_step": {"phase": "execute", "worker_pid": 1234},
        },
        events_body=json.dumps({"kind": "phase_started", "phase": "execute"}) + "\n",
    )
    _write_chain_state(
        ws / ".megaplan" / "plans" / ".chains" / "chain-demo.json",
        {
            "current_milestone_index": 2,
            "current_plan_name": plan_name,
            "last_state": "executing",
            "pr_state": "open",
            "completed": [{"label": "m1"}],
        },
    )
    marker.mkdir(parents=True, exist_ok=True)
    (marker / "demo.chain-health.progress.json").write_text(
        json.dumps(
            {
                "current_milestone_index": 2,
                "completed_count": 1,
                "events_mtime": 1,
                "events_size": 1,
                "last_state": "executing",
                "no_advance_ticks": 3,
            }
        ),
        encoding="utf-8",
    )

    result = _run_chain_health(
        ws,
        marker,
        repair_dir,
        env_overrides={"CLOUD_WATCHDOG_CHAIN_NO_ADVANCE_TICKS": "2"},
    )

    assert result["CHAIN_HEALTH_STATUS"] == "ok"
    assert result["CHAIN_HEALTH_ARTIFACT_PATH"] == ""


def test_chain_health_no_advance_ignores_projected_blocked_plan() -> None:
    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    repair_dir = tmp / "repair-data"
    plan_name = "demo-plan"
    _write_plan(
        ws / ".megaplan" / "plans" / plan_name,
        {"current_state": "blocked", "iteration": 1},
        events_body=json.dumps({"kind": "phase_started", "phase": "execute"}) + "\n",
    )
    _write_chain_state(
        ws / ".megaplan" / "plans" / ".chains" / "chain-demo.json",
        {
            "current_milestone_index": 2,
            "current_plan_name": plan_name,
            "last_state": "blocked",
            "pr_state": "open",
            "completed": [{"label": "m1"}],
        },
    )

    env = {"CLOUD_WATCHDOG_CHAIN_NO_ADVANCE_TICKS": "2"}
    assert _run_chain_health(ws, marker, repair_dir, env_overrides=env)["CHAIN_HEALTH_STATUS"] == "ok"
    events_path = ws / ".megaplan" / "plans" / plan_name / "events.ndjson"
    for i in range(3):
        events_path.write_text(
            events_path.read_text(encoding="utf-8") + json.dumps({"kind": "stderr", "i": i}) + "\n",
            encoding="utf-8",
        )
        result = _run_chain_health(ws, marker, repair_dir, env_overrides=env)
        assert result["CHAIN_HEALTH_STATUS"] == "ok"
        assert result["CHAIN_HEALTH_ARTIFACT_PATH"] == ""


def test_chain_health_no_advance_ignores_progressing_plan_events_without_active_step() -> None:
    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    repair_dir = tmp / "repair-data"
    plan_name = "demo-plan"
    _write_plan(
        ws / ".megaplan" / "plans" / plan_name,
        {"current_state": "finalized", "iteration": 1},
        events_body="\n",
    )
    _write_chain_state(
        ws / ".megaplan" / "plans" / ".chains" / "chain-demo.json",
        {
            "current_milestone_index": 2,
            "current_plan_name": plan_name,
            "last_state": "finalized",
            "pr_state": "open",
            "completed": [{"label": "m1"}],
        },
    )

    env = {"CLOUD_WATCHDOG_CHAIN_NO_ADVANCE_TICKS": "2"}
    assert _run_chain_health(ws, marker, repair_dir, env_overrides=env)["CHAIN_HEALTH_STATUS"] == "ok"
    events_path = ws / ".megaplan" / "plans" / plan_name / "events.ndjson"
    for i in range(3):
        stamp = dt.datetime.now(dt.timezone.utc).isoformat()
        kind = "llm_call_start" if i == 0 else "llm_token_heartbeat"
        payload = {"kind": kind, "ts_utc": stamp}
        if kind == "llm_call_start":
            payload["payload"] = {"request_id": "req-1"}
        events_path.write_text(
            events_path.read_text(encoding="utf-8") + json.dumps(payload) + "\n",
            encoding="utf-8",
        )
        result = _run_chain_health(ws, marker, repair_dir, env_overrides=env)
        assert result["CHAIN_HEALTH_STATUS"] == "ok"
        assert result["CHAIN_HEALTH_ARTIFACT_PATH"] == ""


def test_plan_progress_stall_status_is_wired_into_launch_chain_tick() -> None:
    text = _wrapper("arnold-watchdog")

    assert "plan_progress_stall_status()" in text
    assert 'stall_health="$(plan_progress_stall_status "$workspace" "$run_kind" "$plan_name")"' in text
    # Progress stalls are unintended stops from the operator perspective; they
    # must launch repair instead of only surfacing as passive issues.
    assert 'babysitter_policy_dispatch "$session" "$workspace" "$remote_spec" "$run_kind" "$plan_name" "$report_items"' in text
    assert '"progress stall: $stall_health"' in text
    # The progress_stall status must NOT be in the alive-allowlist so it surfaces
    # in issues[] — the allowlist is the set excluded from issues.
    assert '"progress_stall"' not in text.split('not in {"alive"')[1].split("}")[0]


def test_watchdog_resolves_stale_remote_spec_before_repair_dispatch() -> None:
    text = _wrapper("arnold-watchdog")

    assert "resolve_existing_remote_spec()" in text
    assert 'payload["remote_spec"] = str(selected)' in text
    assert 'resolved_remote_spec="$(resolve_existing_remote_spec "$session" "$workspace" "$remote_spec" "$run_kind"' in text
    assert 'remote_spec="$resolved_remote_spec"' in text
    assert 'remote_spec_path="$resolved_remote_spec"' in text


def test_plan_progress_stall_status_flags_iteration_threshold() -> None:

    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    _write_plan(
        ws / ".megaplan" / "plans" / "m2-x",
        {
            "iteration": 9,
            "current_state": "blocked",
            "active_step": None,
            "latest_failure": {"kind": "stalled", "metadata": {"stall_count": 5, "iteration": 23}},
        },
        plan_v_bodies={"plan_v1.md": "v1"},
        events_body="{}\n",
    )
    out = _run_stall(ws, marker)
    assert out.startswith("progress_stall:m2-x")
    # The milestone iteration (23 from latest_failure.metadata) dominates the
    # top-level value and trips the >=8 threshold.
    assert "iteration=23>=8" in out
    assert "stall_count=5" in out


def test_plan_progress_stall_status_flags_attempt_threshold() -> None:

    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    _write_plan(
        ws / ".megaplan" / "plans" / "m1-y",
        {"iteration": 2, "current_state": "planning",
         "active_step": {"phase": "plan", "attempt": 11}},
        plan_v_bodies={"plan_v1.md": "v1"},
        events_body="{}\n",
    )
    out = _run_stall(ws, marker)
    assert "progress_stall:m1-y" in out
    assert "active_step.attempt=11>=10" in out


def test_watchdog_plan_helpers_use_named_single_plan_in_mixed_workspace() -> None:
    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    target = ws / ".megaplan" / "plans" / "target-plan"
    unrelated = ws / ".megaplan" / "plans" / "newer-unrelated"
    _write_plan(
        target,
        {
            "iteration": 1,
            "current_state": "planning",
            "active_step": {"phase": "plan", "attempt": 0},
            "history": [],
        },
        plan_v_bodies={"plan_v1.md": "target"},
        events_body="{}\n",
    )
    _write_plan(
        unrelated,
        {
            "iteration": 25,
            "current_state": "blocked",
            "active_step": {"phase": "execute", "attempt": 12},
            "latest_failure": {
                "kind": "phase_failed",
                "phase": "execute",
                "message": "unrelated failure should not be inspected",
            },
            "history": [{"step": "execute", "result": "error"}],
        },
        plan_v_bodies={"plan_v1.md": "unrelated"},
        events_body="{}\n",
    )
    old_ts = time.time() - 600
    new_ts = time.time()
    os.utime(target / "state.json", (old_ts, old_ts))
    os.utime(unrelated / "state.json", (new_ts, new_ts))

    assert _run_phase(ws, "plan", "target-plan") == "ok"
    assert _run_stall(ws, marker, run_kind="plan", plan_name="target-plan") == "ok"
    assert _run_phase(ws).startswith("phase_failure:newer-unrelated")
    assert _run_stall(ws, marker).startswith("progress_stall:newer-unrelated")


def test_plan_progress_stall_status_ok_for_healthy_plan() -> None:

    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    _write_plan(
        ws / ".megaplan" / "plans" / "m1-ok",
        {"iteration": 2, "current_state": "planning",
         "active_step": {"phase": "plan", "attempt": 1}},
        plan_v_bodies={"plan_v1.md": "v1"},
        events_body="{}\n",
    )
    assert _run_stall(ws, marker) == "ok"


def test_plan_progress_stall_status_persists_tick_over_tick_snapshot() -> None:

    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    plan_dir = ws / ".megaplan" / "plans" / "m-snap"
    _write_plan(
        plan_dir,
        {"iteration": 4, "current_state": "planning",
         "active_step": {"phase": "plan", "attempt": 0}},
        plan_v_bodies={"plan_v1.md": "v1", "plan_v2.md": "v2"},
        events_body="{}\n",
    )

    # First tick: healthy, snapshot written.
    assert _run_stall(ws, marker) == "ok"
    snap = marker / "m-snap.progress.json"
    assert snap.exists()
    first = json.loads(snap.read_text(encoding="utf-8"))
    assert first["iteration"] == 4
    assert first["plan_v_count"] == 2
    assert "ts" in first

    # Second tick: iteration advances, plan_v count unchanged -> unchanged_ticks
    # increments. With iteration still under threshold this stays ok, but the
    # snapshot must reflect the increment.
    (plan_dir / "state.json").write_text(
        json.dumps({"iteration": 5, "current_state": "planning",
                    "active_step": {"phase": "plan", "attempt": 0}}),
        encoding="utf-8",
    )
    _run_stall(ws, marker)
    second = json.loads(snap.read_text(encoding="utf-8"))
    assert second["unchanged_ticks"] == 1

    # Third tick: still unchanged -> trips the "no growth while iteration
    # advances" signal now that unchanged_ticks >= 2.
    (plan_dir / "state.json").write_text(
        json.dumps({"iteration": 6, "current_state": "planning",
                    "active_step": {"phase": "plan", "attempt": 0}}),
        encoding="utf-8",
    )
    out = _run_stall(ws, marker)
    assert "progress_stall:m-snap" in out
    assert "unchanged-2-ticks" in out


def test_plan_progress_stall_thresholds_are_env_tunable() -> None:

    tmp = Path(tempfile.mkdtemp())
    ws = tmp / "ws"
    marker = tmp / "markers"
    _write_plan(
        ws / ".megaplan" / "plans" / "m-tune",
        {"iteration": 3, "current_state": "planning",
         "active_step": {"phase": "plan", "attempt": 0}},
        plan_v_bodies={"plan_v1.md": "v1"},
        events_body="{}\n",
    )
    # iteration=3 is below the default 8 -> ok.
    assert _run_stall(ws, marker) == "ok"
    # Lower the threshold to 2 -> trips.
    out = _run_stall(ws, marker, {"CLOUD_WATCHDOG_STALL_ITERATIONS": "2"})
    assert "progress_stall:m-tune" in out


def test_arnold_progress_auditor_wrapper_has_bash_n_syntax_and_contract() -> None:
    text = _wrapper("arnold-progress-auditor")

    # bash -n on the actual wrapper file.
    wrapper_path = WRAPPER_DIR / "arnold-progress-auditor"
    result = subprocess.run(
        ["bash", "-n", str(wrapper_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"bash -n failed: {result.stderr}"

    # Host-side: docker-execs into the container like ensure-megaplan-watchdog.
    assert 'CONTAINER="${MEGAPLAN_CLOUD_CONTAINER:-megaplan-cloud-agent}"' in text
    assert "docker inspect" in text

    # In-container: iterates active markers, 5h window, deepseek dispatch.
    assert 'MARKER_DIR="${MEGAPLAN_AUDIT_MARKER_DIR:-/workspace/.megaplan/cloud-sessions}"' in text
    assert 'REPAIR_DATA_DIR="${MEGAPLAN_AUDIT_REPAIR_DATA_DIR:-$MARKER_DIR/repair-data}"' in text
    assert 'DISCOVER_BIN="${MEGAPLAN_AUDIT_DISCOVER_BIN:-$ARNOLD_SRC/arnold_pipelines/megaplan/cloud/wrappers/arnold-cloud-discover}"' in text
    assert 'AUDIT_WINDOW_HOURS="${MEGAPLAN_AUDIT_WINDOW_HOURS:-6}"' in text
    assert 'DEEPSEEK_MODEL="${MEGAPLAN_AUDIT_MODEL:-deepseek:deepseek-v4-pro}"' in text
    assert 'AUDIT_CODEX_MODEL="gpt-5.6-sol"' in text
    assert 'python3 -m arnold_pipelines.megaplan.managed_agent run \\' in text
    assert 'timeout "$CODEX_TIMEOUT" codex exec' in text
    assert '-c model="$AUDIT_CODEX_MODEL"' in text
    assert '"$WATCHDOG_BIN" --audit-sweep' in text
    assert 'CLOUD_WATCHDOG_PROVIDER_RETRY_ONCE=1' in text
    assert '"recovery_sweep": recovery_sweep' in text
    assert 'SUBAGENT_PROFILE="${MEGAPLAN_AUDIT_SUBAGENT_PROFILE:-partnered-5}"' in text
    assert "launch_omp_agent.py" in text
    assert '--model="$DEEPSEEK_MODEL"' in text
    # Report paths.
    assert 'REPORT_DIR="${MEGAPLAN_AUDIT_REPORT_DIR:-/workspace/audit-reports}"' in text
    assert 'REPORT_LOG="${MEGAPLAN_AUDIT_REPORT_LOG:-/workspace/audit-report.log}"' in text
    assert 'JSON_OUT="$REPORT_DIR/${TS}-audit.json"' in text
    assert 'MD_OUT="$REPORT_DIR/${TS}-audit.md"' in text
    # Evidence-citing required output shape.
    assert "hypothesis" in text
    assert "recommendation" in text
    assert "You are reconciling a cloud megaplan SESSION, not just one plan." in text
    assert "Reconciler findings:" in text
    assert "Primary evidence contract:" in text
    assert "Treat bounded incident brief and projection records as the source of truth." in text
    assert "Use live-process discovery, repair-data sidecars, tmux state, and watchdog archives only as corroboration." in text
    assert "Reconcile contradictions explicitly instead of letting corroboration override the ledger." in text
    assert "Superfixer health / repair-the-repairer" in text
    assert "pipeline friction map" in text
    assert "Treat all repair/autofix systems as intended to be enabled by default" in text
    assert "$REPAIR_DATA_DIR/<session>.repair-data.json" in text
    assert "/workspace/.megaplan/meta-runs" in text
    assert "/root/.codex" in text
    assert "periodic audit reviewer is read-only" in text
    assert "Return a typed repair request" in text
    assert "Do not apply patches, create claims, launch repair agents, commit, or push." in text
    assert "Fix the watchdog/babysitter/auditor source" in text
    assert "dead provider/auth path" in text
    assert "argument-size crash" in text
    assert "Return a typed repair request; the central repair authority owns" in text
    assert "any subsequent mutation or managed child launch." in text
    assert "chain log line numbers" in text
    assert "Live failure vs stale state" in text
    assert "Gate resolvability" in text
    assert "stale_state_evidence" in text
    assert "latest_failure_is_stale" in text
    assert "stale_block_replay" in text
    assert "between_milestone_cycling" in text
    assert "STALE" in text
    assert "INEFFICIENT" in text


def test_progress_auditor_rejects_degenerate_dispatch_windows() -> None:
    text = _wrapper("arnold-progress-auditor")

    assert "math.isfinite(hours) and hours > 0" in text
    assert "a non-positive or non-finite window is a probe" in text
    assert "cannot establish health or suppress active repair custody" in text
    assert "exit 64" in text


def test_watchdog_exposes_serialized_audit_recovery_and_paused_guard() -> None:
    text = _wrapper("arnold-watchdog")

    assert 'if [[ "${1:-}" == "--audit-sweep" ]]' in text
    assert 'SCAN_LOCK_FILE="${CLOUD_WATCHDOG_SCAN_LOCK_FILE:-/workspace/.megaplan/watchdog-scan.lock}"' in text
    assert 'flock -w "$SCAN_LOCK_WAIT_SECS" "$scan_lock_fd"' in text
    assert '"${PLAN_STATUS_CURRENT_STATE:-}" == "paused"' in text
    assert '"paused" "durable plan state is paused; no runner expected until explicit resume"' in text


def test_all_recovery_wrappers_fail_closed_for_durable_operator_pause() -> None:
    auditor = _wrapper("arnold-progress-auditor")
    assert 'decision = "skip_paused"' in auditor


def _extract_auditor_worklist_program() -> str:
    text = _wrapper("arnold-progress-auditor")
    marker = (
        "python3 - \"$MARKER_DIR\" \"$WORKLIST\" \"$AUDIT_WINDOW_HOURS\" "
        "\"$DISCOVER_BIN\" \"$AUDIT_WORKSPACE_ROOT\" \"$ARNOLD_SRC\" <<'PY'"
    )
    start = text.index(marker)
    start = text.index("\n", start) + 1
    end = text.index("\nPY\n", start)
    return text[start:end]


def _extract_auditor_gather_program() -> str:
    text = _wrapper("arnold-progress-auditor")
    marker = "python3 - \"$WORKLIST\" \"$GATHER_DIR\" \"$AUDIT_WINDOW_HOURS\" \"$ARNOLD_SRC\" \"$stall_summary\" <<'PY'"
    start = text.index(marker)
    start = text.index("\n", start) + 1
    end = text.index("\nPY\n", start)
    return text[start:end]


def _run_auditor_worklist_builder(
    tmp_path: Path,
    *,
    marker_dir: Path,
    worklist: Path,
    window_hours: float,
    discover_bin: Path,
    workspace_root: Path,
    arnold_src: Path,
) -> list[dict]:
    program = _extract_auditor_worklist_program()
    prog_path = tmp_path / "_auditor_worklist.py"
    prog_path.write_text(program, encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(prog_path),
            str(marker_dir),
            str(worklist),
            str(window_hours),
            str(discover_bin),
            str(workspace_root),
            str(arnold_src),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return [
        json.loads(line)
        for line in worklist.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_repair_runner_defaults_meta_loop_repairs_to_partnered_5() -> None:
    from arnold_pipelines.megaplan.watchdog.repair_runner import RepairRunner

    runner = RepairRunner(executable_search_path=[])
    assert runner._is_dry_run() is True
    # The megaplan-subcommand env pins partnered-5 as the default profile.
    env = runner._megaplan_subcommand_env({"PATH": "/bin"})
    assert env.get("MEGAPLAN_DEFAULT_PROFILE") == "partnered-5"
    assert env.get("MEGAPLAN_REPAIR_PROFILE") == "partnered-5"
    assert env.get("PYTHONSAFEPATH") == "1"
    # A caller-supplied default must win (setdefault semantics).
    env2 = runner._megaplan_subcommand_env(
        {"PATH": "/bin", "MEGAPLAN_DEFAULT_PROFILE": "apex"}
    )
    assert env2.get("MEGAPLAN_DEFAULT_PROFILE") == "apex"


def _run_auditor_with_mocked_deepseek(tmp_path: Path) -> dict:
    """Drive the in-container auditor python with a stubbed launcher.

    We synthesize a marker + a stalled plan, then call the auditor's gather +
    dispatch python in isolation by stubbing the hermes launcher with a script
    that emits a canned hypothesis. This proves the report path end-to-end
    without needing real DeepSeek credentials.
    """
    workspace = tmp_path / "ws"
    plans = workspace / ".megaplan" / "plans" / "m2-mock"
    plans.mkdir(parents=True)
    state = {
        "name": "m2-mock",
        "iteration": 8,
        "current_state": "blocked",
        "active_step": None,
        "latest_failure": {"kind": "stalled",
                           "message": "stalled at 'blocked' for 5 iterations",
                           "metadata": {"stall_count": 5, "iteration": 23}},
        "last_gate": {"recommendation": "ITERATE",
                      "rationale": "score regression 13.5 -> 3.0"},
        "meta": {"weighted_scores": [12.0, 7.0, 14.0, 13.5, 3.0],
                 "plan_deltas": [54.0, 9.0, 9.0, 43.0, 9.0],
                 "significant_counts": [8, 4, 9, 11, 2]},
        "history": [
            {"step": "gate", "result": "iterate", "timestamp": _iso_hours_ago(0.5)},
            {"step": "gate", "result": "iterate", "timestamp": _iso_hours_ago(1.5)},
            {"step": "gate", "result": "blocked", "timestamp": _iso_hours_ago(2.5)},
            {"step": "revise", "result": "success", "timestamp": _iso_hours_ago(0.2)},
        ],
    }
    (plans / "state.json").write_text(json.dumps(state), encoding="utf-8")
    for i, body in enumerate(["v1", "v2longer", "v3different", "v4", "v5"], start=1):
        (plans / f"plan_v{i}.md").write_text(body * (i * 100), encoding="utf-8")
    (plans / "events.ndjson").write_text("{}\n" * 10, encoding="utf-8")

    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    (marker_dir / "m2-mock.json").write_text(json.dumps({
        "session": "m2-mock", "workspace": str(workspace), "updated_at": _iso_hours_ago(0.1),
    }), encoding="utf-8")

    # Stub launcher that returns a canned hypothesis referencing the evidence.
    launcher = tmp_path / "launch_hermes_agent.py"
    canned = (
        "hypothesis: critique loop oscillating over cosmetic import wording; "
        "gate evaluator too strict for phase-0. recommend: tighten gate cosmetic flag."
    )
    launcher.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"print({canned!r})\n",
        encoding="utf-8",
    )
    launcher.chmod(launcher.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    # Reuse the auditor's python by extracting the gather + dispatch steps is
    # fragile; instead invoke the actual wrapper's inner python via a trimmed
    # copy that points at our tmp paths. We assert the report-construction
    # python produces the cited finding by running it against our gather dir.
    gather_dir = tmp_path / "gather"
    gather_dir.mkdir()
    worklist = tmp_path / "worklist"
    worklist.write_text(json.dumps({
        "name": "m2-mock", "plan": "m2-mock", "session": "m2-mock",
        "workspace": str(workspace), "updated": _iso_hours_ago(0.1), "sources": ["marker"],
    }) + "\n", encoding="utf-8")

    wrapper_text = _wrapper("arnold-progress-auditor")
    gather_prog = _extract_auditor_gather_program()
    (gather_dir / "gather.py").write_text(gather_prog, encoding="utf-8")

    env = dict(os.environ)
    r = subprocess.run(
        [sys.executable, str(gather_dir / "gather.py"), str(worklist),
         str(gather_dir), "5", str(workspace.parent), "none"],
        capture_output=True, text=True, env=env, check=False,
    )
    assert r.returncode == 0, f"gather failed: {r.stderr}"
    findings = json.loads((gather_dir / "findings.json").read_text(encoding="utf-8"))
    assert findings["findings"], "expected at least one suspicious finding"
    finding = findings["findings"][0]
    assert finding["plan"] == "m2-mock"
    reasons = " ".join(finding["reasons"])
    # Evidence-cited: plan churn + gate regression both present.
    assert "plan_v refreshed" in reasons
    assert "gate=ITERATE/blocked" in reasons

    # Now drive the report-assembly python against this finding with a canned
    # hypothesis (simulating the DeepSeek dispatch output).
    finding["deepseek_model"] = "deepseek:deepseek-v4-pro"
    finding["hypothesis"] = (
        "hypothesis: critique loop oscillating over cosmetic import wording; "
        "gate evaluator too strict for phase-0. recommend: tighten gate cosmetic flag."
    )
    (gather_dir / "findings.json").write_text(
        json.dumps({"window_hours": 5, "stall_summary": "none",
                    "findings": [finding]}),
        encoding="utf-8",
    )

    # Extract report-assembly python.
    a_marker = "python3 - \"$GATHER_DIR/findings.json\" \"$JSON_OUT\" \"$MD_OUT\" \"$REPORT_LOG\" \"$TS\""
    a_start = wrapper_text.index(a_marker)
    a_start = wrapper_text.index("\n", a_start) + 1
    a_end = wrapper_text.index("\nPY\n", a_start)
    asm_prog = wrapper_text[a_start:a_end]
    json_out = tmp_path / "out.json"
    md_out = tmp_path / "out.md"
    log_path = tmp_path / "audit.log"
    recovery_evidence = tmp_path / "recovery-evidence.json"
    recovery_evidence.write_text(
        json.dumps({"enabled": False, "decisions": []}), encoding="utf-8"
    )
    asm = gather_dir / "asm.py"
    asm.write_text(asm_prog, encoding="utf-8")
    r2 = subprocess.run(
        [sys.executable, str(asm), str(gather_dir / "findings.json"),
         str(json_out), str(md_out), str(log_path), "TESTTS", "0", "0",
         str(recovery_evidence), "gpt-test"],
        capture_output=True, text=True, env=env, check=False,
    )
    assert r2.returncode == 0, f"report asm failed: {r2.stderr}"
    report = json.loads(json_out.read_text(encoding="utf-8"))
    assert report["finding_count"] == 1
    assert report["deepseek_model"] == "deepseek:deepseek-v4-pro"
    md = md_out.read_text(encoding="utf-8")
    assert "m2-mock" in md
    assert "hypothesis:" in md
    assert "tighten gate cosmetic flag" in md
    # Log append is a single greppable line.
    log_line = log_path.read_text(encoding="utf-8").strip().splitlines()[-1]
    assert "findings=1" in log_line
    assert "m2-mock" in log_line
    return report


def _iso_hours_ago(hours: float) -> str:
    when = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)
    return when.isoformat().replace("+00:00", "Z")


def test_auditor_worklist_unions_marker_tmux_and_workspace_activity_and_skips_arnold(
    tmp_path: Path,
) -> None:
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    arnold_src = workspace_root / "arnold"
    (arnold_src / ".megaplan" / "plans" / "should-not-scan").mkdir(parents=True)

    chain_ws = workspace_root / "vibecomfy-god-file-splits"
    bootstrap_ws = workspace_root / "vibecomfy-per-workflow-window-chat-20260628"
    done_ws = workspace_root / "python-shaped-workflow-authoring"
    plan_marker_ws = workspace_root / "single-plan-marker-workspace"
    for ws in (chain_ws, bootstrap_ws, done_ws, plan_marker_ws):
        (ws / ".megaplan" / "plans").mkdir(parents=True)

    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    (marker_dir / "chain-session.json").write_text(
        json.dumps({"session": "chain-session", "workspace": str(chain_ws), "updated_at": _iso_hours_ago(0.2)}),
        encoding="utf-8",
    )
    (marker_dir / "single-plan-session.json").write_text(
        json.dumps(
            {
                "session": "single-plan-session",
                "workspace": str(plan_marker_ws),
                "run_kind": "plan",
                "plan_name": "target-plan",
                "updated_at": _iso_hours_ago(0.2),
            }
        ),
        encoding="utf-8",
    )

    def write_recent_plan(workspace: Path, name: str, *, state_recent: bool = True, events_recent: bool = False) -> None:
        plan_dir = workspace / ".megaplan" / "plans" / name
        state = {"name": name, "current_state": "done", "history": [], "meta": {}}
        _write_plan(plan_dir, state, plan_v_bodies={"plan_v1.md": "v1"}, events_body="{}\n" if events_recent else "")
        recent_ts = time.time() - 300
        stale_ts = time.time() - (9 * 3600)
        state_path = plan_dir / "state.json"
        events_path = plan_dir / "events.ndjson"
        os.utime(state_path, (recent_ts if state_recent else stale_ts, recent_ts if state_recent else stale_ts))
        if events_path.exists():
            os.utime(events_path, (recent_ts if events_recent else stale_ts, recent_ts if events_recent else stale_ts))

    write_recent_plan(chain_ws, "m2-chain", state_recent=True)
    write_recent_plan(bootstrap_ws, "m1-bootstrap", state_recent=False, events_recent=True)
    write_recent_plan(done_ws, "m5-done", state_recent=False, events_recent=True)
    write_recent_plan(done_ws, "m6-done", state_recent=True, events_recent=False)
    write_recent_plan(plan_marker_ws, "target-plan", state_recent=False, events_recent=False)
    write_recent_plan(plan_marker_ws, "stale-unrelated", state_recent=False, events_recent=False)
    write_recent_plan(arnold_src, "should-not-scan", state_recent=True)

    discover_bin = tmp_path / "discover_stub.sh"
    discover_bin.write_text(
        "#!/usr/bin/env bash\n"
        "cat <<'EOF'\n"
        f"bootstrap-session\t{bootstrap_ws}\t.megaplan/initiatives/bootstrap/briefs/bootstrap.md\tplan\tm1-bootstrap\tignored\n"
        f"chain-session-live\t{chain_ws}\t/tmp/spec.yaml\tchain\t\tignored\n"
        "EOF\n",
        encoding="utf-8",
    )
    discover_bin.chmod(discover_bin.stat().st_mode | stat.S_IXUSR)

    worklist = tmp_path / "worklist.jsonl"
    entries = _run_auditor_worklist_builder(
        tmp_path,
        marker_dir=marker_dir,
        worklist=worklist,
        window_hours=6,
        discover_bin=discover_bin,
        workspace_root=workspace_root,
        arnold_src=arnold_src,
    )

    observed = {(entry["workspace"], entry["plan"]): set(entry["sources"]) for entry in entries}
    assert (str(chain_ws), "m2-chain") in observed
    assert observed[(str(chain_ws), "m2-chain")] == {"marker", "tmux", "workspace_activity"}
    assert (str(bootstrap_ws), "m1-bootstrap") in observed
    assert observed[(str(bootstrap_ws), "m1-bootstrap")] == {"tmux", "workspace_activity"}
    assert (str(done_ws), "m5-done") in observed
    assert observed[(str(done_ws), "m5-done")] == {"workspace_activity"}
    assert (str(done_ws), "m6-done") in observed
    assert observed[(str(done_ws), "m6-done")] == {"workspace_activity"}
    assert (str(plan_marker_ws), "target-plan") in observed
    assert observed[(str(plan_marker_ws), "target-plan")] == {"marker"}
    assert (str(plan_marker_ws), "stale-unrelated") not in observed
    assert all(entry["workspace"] != str(arnold_src) for entry in entries)


def test_auditor_missing_workspace_marker_emits_durable_indeterminate_discovery(
    tmp_path: Path,
) -> None:
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    arnold_src = workspace_root / "arnold"
    arnold_src.mkdir()
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    missing_workspace = workspace_root / "missing-chain"
    marker_path = marker_dir / "missing-session.json"
    marker_path.write_text(
        json.dumps(
            {
                "session": "missing-session",
                "workspace": str(missing_workspace),
            }
        ),
        encoding="utf-8",
    )
    discover_bin = tmp_path / "discover.sh"
    discover_bin.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    discover_bin.chmod(discover_bin.stat().st_mode | stat.S_IXUSR)
    worklist = tmp_path / "worklist.jsonl"

    entries = _run_auditor_worklist_builder(
        tmp_path,
        marker_dir=marker_dir,
        worklist=worklist,
        window_hours=6,
        discover_bin=discover_bin,
        workspace_root=workspace_root,
        arnold_src=arnold_src,
    )

    assert entries == []
    discoveries = [
        json.loads(line)
        for line in (tmp_path / "discovery-indeterminate.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert discoveries == [
        {
            "schema_version": "arnold-progress-auditor-discovery-v1",
            "status": "indeterminate",
            "reason": "missing_workspace",
            "session": "missing-session",
            "workspace": str(missing_workspace),
            "marker_path": str(marker_path),
        }
    ]


def test_auditor_gather_includes_done_plan_with_recent_events_mtime(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    plan_dir = workspace / ".megaplan" / "plans" / "m6-done"
    state = {
        "name": "m6-done",
        "iteration": 1,
        "current_state": "done",
        "active_step": {"phase": "review", "attempt": 8},
        "latest_failure": {"kind": "stalled", "message": "stale failure record"},
        "last_gate": {"recommendation": "PASS"},
        "meta": {"weighted_scores": [7.0, 6.0, 4.0], "plan_deltas": [1.0, 1.0, 1.0], "significant_counts": [1, 1, 1]},
        "history": [
            {"step": "gate", "result": "iterate", "timestamp": _iso_hours_ago(1.0)},
            {"step": "gate", "result": "iterate", "timestamp": _iso_hours_ago(2.0)},
            {"step": "gate", "result": "blocked", "timestamp": _iso_hours_ago(3.0)},
        ],
    }
    _write_plan(plan_dir, state, plan_v_bodies={"plan_v1.md": "v1"}, events_body="{}\n{}\n")
    stale_ts = time.time() - (9 * 3600)
    recent_ts = time.time() - 120
    os.utime(plan_dir / "state.json", (stale_ts, stale_ts))
    os.utime(plan_dir / "events.ndjson", (recent_ts, recent_ts))

    gather_dir = tmp_path / "gather"
    gather_dir.mkdir()
    worklist = tmp_path / "worklist.jsonl"
    worklist.write_text(
        json.dumps(
            {
                "workspace": str(workspace),
                "plan": "m6-done",
                "session": "done-session",
                "sources": ["workspace_activity"],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    gather_prog = _extract_auditor_gather_program()
    gather_path = gather_dir / "gather.py"
    gather_path.write_text(gather_prog, encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(gather_path),
            str(worklist),
            str(gather_dir),
            "6",
            str(tmp_path),
            "none",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    findings = json.loads((gather_dir / "findings.json").read_text(encoding="utf-8"))["findings"]
    assert findings, "expected done plan with recent events mtime to be included"
    assert findings[0]["plan"] == "m6-done"
    assert findings[0]["session"] == "done-session"
    assert findings[0]["sources"] == ["workspace_activity"]


def test_auditor_gather_includes_chain_repair_stderr_and_user_action_evidence(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    plan_name = "m7-demo"
    plan_dir = workspace / ".megaplan" / "plans" / plan_name
    state = {
        "name": plan_name,
        "iteration": 21,
        "current_state": "finalized",
        "active_step": {"phase": "execute", "attempt": 2},
        "latest_failure": {
            "kind": "phase_failed",
            "message": "phase 'execute' internal_error",
            "phase": "execute",
            "recorded_at": _iso_hours_ago(2.0),
            "metadata": {
                "exit_code": 2,
                "stderr": "__main__.py: error: unrecognized arguments: --confirm-destructive --user-approved",
            },
        },
        "last_gate": {"recommendation": "PASS"},
        "meta": {
            "weighted_scores": [8.0],
            "plan_deltas": [1.0],
            "significant_counts": [1],
            "user_action_resolutions": {
                "ua-02-cleanup-policy": {"state": "satisfied", "decision": "proceed"}
            },
        },
        "history": [
            {
                "step": "execute",
                "result": "blocked",
                "timestamp": _iso_hours_ago(1.0),
                "duration_ms": 0,
                "artifact_hash": "sha256:stale-block",
                "output_file": "execution.json",
            },
            {
                "step": "execute",
                "result": "blocked",
                "timestamp": _iso_hours_ago(0.5),
                "duration_ms": 0,
                "artifact_hash": "sha256:stale-block",
                "output_file": "execution.json",
            },
        ],
    }
    _write_plan(
        plan_dir,
        state,
        plan_v_bodies={"plan_v1.md": "v1"},
        events_body="\n".join(
            [
                json.dumps(
                    {
                        "seq": 1,
                        "kind": "phase_end",
                        "phase": "execute",
                        "ts_utc": _iso_hours_ago(1.5),
                        "payload": {"phase": "execute", "exit_kind": "success"},
                    }
                ),
                json.dumps(
                    {
                        "seq": 2,
                        "kind": "gate",
                        "phase": "gate",
                        "ts_utc": _iso_hours_ago(1.0),
                        "payload": {"recommendation": "PROCEED"},
                    }
                ),
            ]
        )
        + "\n",
    )
    (plan_dir / "finalize.json").write_text(
        json.dumps(
            {
                "user_actions": [
                    {
                        "id": "ua-01-reclassify-deletion-targets",
                        "phase": "before_execute",
                        "blocks_task_ids": ["m7-06-runtime-deletion-target-purge"],
                        "rationale": "Maintainer must confirm authoritative deletion targets.",
                    },
                    {
                        "id": "ua-02-cleanup-policy",
                        "phase": "before_execute",
                        "blocks_task_ids": ["m7-07-pipeline-deletion-target-purge"],
                        "rationale": "Cleanup policy choice.",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    (plan_dir / "user_actions.md").write_text(
        "# User Actions\n\n"
        "- **ua-01-reclassify-deletion-targets**: Confirm deletion targets.\n"
        "- **ua-02-cleanup-policy**: Cleanup policy.\n",
        encoding="utf-8",
    )

    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    chain_dir.mkdir(parents=True)
    (chain_dir / "chain-demo.json").write_text(
        json.dumps(
            {
                "current_milestone_index": 6,
                "current_plan_name": plan_name,
                "last_state": "awaiting_human",
                "pr_number": 122,
                "pr_state": "open",
                "completed": [
                    {
                        "label": "m6-installed-artifacts",
                        "plan": "m6-demo",
                        "status": "done",
                        "pr_number": 121,
                        "pr_state": "merged",
                        "full_suite_backstop": {
                            "status": "failed",
                            "blocks": False,
                            "failed": 3,
                            "delta_computed": True,
                        },
                    }
                ],
                "events": [{"msg": "milestone m7 starting"}, {"msg": "awaiting_human"}],
            }
        ),
        encoding="utf-8",
    )
    (workspace / ".megaplan" / "cloud-chain-demo-session.log").write_text(
        "\n".join(
            [
                "[chain] milestone m7 starting",
                "[chain] terminal state reached: done",
                "[chain] status: stopped reason=milestone m7 ended awaiting_human",
                "[chain] milestone m7 starting",
                "[chain] terminal state reached: done",
                "[chain] status: stopped reason=milestone m7 ended awaiting_human",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    repair_data_dir = tmp_path / "repair-data"
    repair_data_dir.mkdir()
    (repair_data_dir / "demo-session.repair-data.json").write_text(
        json.dumps(
            {
                "session": "demo-session",
                "outcome": "repairing",
                "iterations": [
                    {
                        "i": 1,
                        "mechanical_launch": "failed:awaiting_human",
                        "chain_state_summary": {"current_plan_name": plan_name, "last_state": "awaiting_human"},
                        "plan_latest_failure": {
                            "kind": "phase_failed",
                            "message": "phase 'execute' internal_error",
                            "metadata": {"stderr": "__main__.py: error: unrecognized arguments: --confirm-destructive"},
                        },
                    },
                    {
                        "i": 2,
                        "mechanical_launch": "failed:awaiting_human",
                        "chain_state_summary": {"current_plan_name": plan_name, "last_state": "awaiting_human"},
                        "plan_latest_failure": {
                            "kind": "phase_failed",
                            "message": "phase 'execute' internal_error",
                            "metadata": {"stderr": "__main__.py: error: unrecognized arguments: --confirm-destructive"},
                        },
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    gather_dir = tmp_path / "gather"
    gather_dir.mkdir()
    worklist = tmp_path / "worklist.jsonl"
    worklist.write_text(
        json.dumps(
            {
                "workspace": str(workspace),
                "plan": plan_name,
                "session": "demo-session",
                "kind": "chain",
                "remote_spec": str(workspace / ".megaplan" / "initiatives" / "demo" / "chain.yaml"),
                "launch_command": "python3 -P -m arnold_pipelines.megaplan chain start --spec demo",
                "log": str(workspace / ".megaplan" / "cloud-chain-demo-session.log"),
                "sources": ["marker"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    gather_path = gather_dir / "gather.py"
    gather_path.write_text(_extract_auditor_gather_program(), encoding="utf-8")
    env = dict(os.environ)
    env["MEGAPLAN_AUDIT_REPAIR_DATA_DIR"] = str(repair_data_dir)
    result = subprocess.run(
        [sys.executable, str(gather_path), str(worklist), str(gather_dir), "6", str(tmp_path), "none"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    findings = json.loads((gather_dir / "findings.json").read_text(encoding="utf-8"))["findings"]
    assert findings, "expected chain-level signals to produce a suspicious finding"
    finding = findings[0]
    assert finding["session_header"]["kind"] == "chain"
    assert finding["chain_log"]["path"].endswith("cloud-chain-demo-session.log")
    assert "L6: [chain] status: stopped" in finding["chain_log"]["tail"]
    assert any(item["signature"] == "awaiting_human" and item["count"] == 2 for item in finding["chain_log"]["repetition_summary"])
    assert finding["chain_state_summary"]["current"]["last_state"] == "awaiting_human"
    assert finding["chain_state_summary"]["current"]["completed_count"] == 1
    assert finding["repair_data_summary"]["iteration_count"] == 2
    assert finding["repair_data_summary"]["repeated_failure_signatures"][0]["count"] == 2
    assert "unrecognized arguments" in finding["plan_latest_failure"]["metadata"]["stderr"]
    stale = finding["stale_state_evidence"]
    assert stale["latest_failure_is_stale"] is True
    assert stale["last_success_after_failure"]
    assert stale["last_success_after_failure_event"]["kind"] == "gate"
    assert stale["stale_block_replay"] is True
    assert stale["stale_block_replay_hash"] == "sha256:stale-block"
    assert finding["latest_failure_is_stale"] is True
    assert finding["stale_block_replay"] is True
    user_action_context = finding["user_action_context"]
    assert "ua-01-reclassify-deletion-targets" in user_action_context["user_actions_md"]
    assert [item["id"] for item in user_action_context["unresolved_user_actions"]] == ["ua-01-reclassify-deletion-targets"]
    reasons = " ".join(finding["reasons"])
    assert "chain last_state=awaiting_human" in reasons
    assert "chain log repeats" in reasons
    assert "repair data has 2 repair iterations" in reasons
    assert "unresolved user actions" in reasons
    assert "latest_failure is stale" in reasons
    assert "stale block replay" in reasons


def test_auditor_gather_does_not_infer_dead_from_unbound_active_step_pid(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    plan_name = "ghost-worker-demo"
    plan_dir = workspace / ".megaplan" / "plans" / plan_name
    _write_plan(
        plan_dir,
        {
            "name": plan_name,
            "iteration": 0,
            "current_state": "initialized",
            "created_at": _iso_hours_ago(0.25),
            "active_step": {
                "phase": "prep",
                "attempt": 1,
                "worker_pid": 99999999,
            },
        },
        events_body=json.dumps({"kind": "llm_token_heartbeat", "phase": "prep"}) + "\n",
    )

    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    chain_dir.mkdir(parents=True)
    (chain_dir / "chain-demo.json").write_text(
        json.dumps(
            {
                "current_milestone_index": 0,
                "current_plan_name": plan_name,
                "last_state": "initialized",
                "pr_state": "open",
                "completed": [],
            }
        ),
        encoding="utf-8",
    )

    gather_dir = tmp_path / "gather"
    gather_dir.mkdir()
    worklist = tmp_path / "worklist.jsonl"
    worklist.write_text(
        json.dumps(
            {
                "workspace": str(workspace),
                "plan": plan_name,
                "session": "ghost-worker-session",
                "kind": "chain",
                "remote_spec": str(workspace / ".megaplan" / "initiatives" / "demo" / "chain.yaml"),
                "launch_command": "python3 -P -m arnold_pipelines.megaplan chain start --spec demo",
                "log": str(workspace / ".megaplan" / "cloud-chain-ghost-worker-session.log"),
                "sources": ["marker"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    gather_path = gather_dir / "gather.py"
    gather_path.write_text(_extract_auditor_gather_program(), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(gather_path), str(worklist), str(gather_dir), "6", str(tmp_path), "none"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    findings = json.loads((gather_dir / "findings.json").read_text(encoding="utf-8"))["findings"]
    assert findings == []


def test_progress_auditor_dispatch_redacts_brief_and_codex_response_files(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    gather_dir = tmp_path / "gather"
    gather_dir.mkdir()
    gather_file = gather_dir / "finding.json"
    gather_file.write_text(
        json.dumps(
            {
                "plan": "m7-demo",
                "workspace": str(workspace),
                "reasons": ["Authorization: Bearer bearer-secret-token-value"],
                "session_header": {"kind": "chain"},
                "plan_latest_failure": {
                    "kind": "phase_failed",
                    "metadata": {"stderr": "Authorization: Bearer bearer-secret-token-value"},
                },
            }
        ),
        encoding="utf-8",
    )

    codex = tmp_path / "codex"
    codex.write_text(
        "#!/usr/bin/env bash\n"
        "printf '%s\\n' \"$*\"\n"
        "cat\n"
        "printf '%s\\n' 'stderr Authorization: Bearer bearer-secret-token-value' >&2\n",
        encoding="utf-8",
    )
    codex.chmod(codex.stat().st_mode | stat.S_IXUSR)

    script = "\n\n".join(
        [
            _extract_auditor_function("redact_inline_text"),
            _extract_auditor_function("redact_file_in_place"),
            _extract_auditor_function("log"),
            _extract_auditor_function("dispatch_one"),
            f"ARNOLD_SRC={shlex.quote(str(REPO_ROOT))}",
            f"GATHER_DIR={shlex.quote(str(gather_dir))}",
            "DEEPSEEK_MODEL=deepseek:deepseek-v4-pro",
            "SUBAGENT_PROFILE=partnered-5",
            "AUDIT_CODEX_MODEL=gpt-5.6-sol",
            "AUDIT_REVIEW_BRIEF_MAX_BYTES=131072",
            "AUDIT_REVIEW_EVIDENCE_MAX_BYTES=65536",
            "CODEX_TIMEOUT=30",
            "AUDIT_REVIEW_EVIDENCE_MAX_BYTES=65536",
            "AUDIT_REVIEW_BRIEF_MAX_BYTES=131072",
            "AUDIT_MUTATION_AUTHORIZED_FLAG=0",
            "dispatch_one " + shlex.quote(str(gather_file)),
        ]
    )
    env = dict(os.environ)
    env["PATH"] = f"{tmp_path}:{env.get('PATH', '')}"
    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env, check=False
    )

    assert result.returncode == 0, result.stderr
    brief = (gather_dir / "brief-m7-demo.md").read_text(encoding="utf-8")
    resp = (gather_dir / "resp-m7-demo.txt").read_text(encoding="utf-8")
    err = (gather_dir / "resp-m7-demo.err").read_text(encoding="utf-8")
    assert "bearer-secret-token-value" not in brief
    assert "bearer-secret-token-value" not in resp
    assert "bearer-secret-token-value" not in err
    assert REDACTION in brief
    assert resp.startswith("PASSIVE\n")
    assert err == ""


def test_auditor_gather_flags_plan_stale_block_without_chain_evidence(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    plan_name = "single-plan"
    plan_dir = workspace / ".megaplan" / "plans" / plan_name
    _write_plan(
        plan_dir,
        {
            "name": plan_name,
            "iteration": 4,
            "current_state": "blocked",
            "active_step": None,
            "latest_failure": {
                "kind": "execution_blocked",
                "message": "blocked replay",
                "phase": "execute",
            },
            "last_gate": {"recommendation": "PASS"},
            "meta": {"weighted_scores": [8.0], "plan_deltas": [1.0], "significant_counts": [1]},
            "history": [
                {
                    "step": "execute",
                    "result": "blocked",
                    "timestamp": _iso_hours_ago(1.0),
                    "duration_ms": 0,
                    "artifact_hash": "sha256:plan-stale",
                    "output_file": "execution.json",
                },
                {
                    "step": "execute",
                    "result": "blocked",
                    "timestamp": _iso_hours_ago(0.5),
                    "duration_ms": 0,
                    "artifact_hash": "sha256:plan-stale",
                    "output_file": "execution.json",
                },
            ],
        },
        plan_v_bodies={"plan_v1.md": "v1"},
        events_body="{}\n",
    )

    gather_dir = tmp_path / "gather"
    gather_dir.mkdir()
    worklist = tmp_path / "worklist.jsonl"
    worklist.write_text(
        json.dumps(
            {
                "workspace": str(workspace),
                "plan": plan_name,
                "session": "single-plan-session",
                "kind": "plan",
                "plan_name": plan_name,
                "sources": ["marker"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    gather_path = gather_dir / "gather.py"
    gather_path.write_text(_extract_auditor_gather_program(), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(gather_path), str(worklist), str(gather_dir), "6", str(tmp_path), "none"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    findings = json.loads((gather_dir / "findings.json").read_text(encoding="utf-8"))["findings"]
    assert findings, "expected plan-level stale block replay to produce a finding"
    finding = findings[0]
    assert finding["session_header"]["kind"] == "plan"
    assert finding["chain_log"]["path"] == ""
    assert finding["chain_state_summary"]["current"] == {}
    stale = finding["stale_state_evidence"]
    assert stale["stale_block_replay"] is True
    assert stale["stale_block_replay_hash"] == "sha256:plan-stale"
    assert stale["between_milestone_cycling"] is False
    assert "stale block replay" in " ".join(finding["reasons"])


def test_auditor_gather_flags_between_milestone_cycling(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    plan_name = "m3-demo"
    plan_dir = workspace / ".megaplan" / "plans" / plan_name
    _write_plan(
        plan_dir,
        {
            "name": plan_name,
            "iteration": 3,
            "current_state": "finalized",
            "active_step": None,
            "last_gate": {"recommendation": "PASS"},
            "meta": {"weighted_scores": [8.0], "plan_deltas": [1.0], "significant_counts": [1]},
            "history": [],
        },
        plan_v_bodies={"plan_v1.md": "v1"},
        events_body="{}\n",
    )

    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    chain_dir.mkdir(parents=True)
    (chain_dir / "chain-demo.json").write_text(
        json.dumps(
            {
                "current_milestone_index": 2,
                "current_plan_name": plan_name,
                "last_state": "stopped",
                "completed": [
                    {"label": "m1", "plan": "m1-demo", "status": "done"},
                    {"label": "m2", "plan": "m2-demo", "status": "done"},
                ],
                "milestones": [{"label": "m1"}, {"label": "m2"}, {"label": "m3"}],
                "events": [{"msg": "m1 done"}, {"msg": "m2 done"}],
            }
        ),
        encoding="utf-8",
    )
    log_path = workspace / ".megaplan" / "cloud-chain-demo-session.log"
    log_path.write_text(
        "\n".join(
            [
                "[chain] milestone m1 starting",
                "[chain] terminal state reached: done",
                "[chain] status: stopped reason=completed one milestone: m1",
                "[chain] milestone m2 starting",
                "[chain] terminal state reached: done",
                "[chain] status: stopped reason=completed one milestone: m2",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    gather_dir = tmp_path / "gather"
    gather_dir.mkdir()
    worklist = tmp_path / "worklist.jsonl"
    worklist.write_text(
        json.dumps(
            {
                "workspace": str(workspace),
                "plan": plan_name,
                "session": "demo-session",
                "kind": "chain",
                "log": str(log_path),
                "sources": ["marker"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    gather_path = gather_dir / "gather.py"
    gather_path.write_text(_extract_auditor_gather_program(), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(gather_path), str(worklist), str(gather_dir), "6", str(tmp_path), "none"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    findings = json.loads((gather_dir / "findings.json").read_text(encoding="utf-8"))["findings"]
    assert findings, "expected between-milestone cycling to produce a finding"
    finding = findings[0]
    stale = finding["stale_state_evidence"]
    assert stale["between_milestone_cycling"] is True
    assert stale["one_milestone_stop_cycle_count"] == 2
    assert finding["between_milestone_cycling"] is True
    assert "between-milestone cycling" in " ".join(finding["reasons"])


def test_auditor_gather_surfaces_missing_meta_repair_run_for_triggered_session(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    plan_name = "m4-demo"
    plan_dir = workspace / ".megaplan" / "plans" / plan_name
    _write_plan(
        plan_dir,
        {
            "name": plan_name,
            "iteration": 4,
            "current_state": "blocked",
            "active_step": None,
            "latest_failure": {
                "kind": "stalled",
                "message": "stalled at blocked",
                "recorded_at": _iso_hours_ago(1.0),
            },
            "last_gate": {"recommendation": "ITERATE"},
            "meta": {"weighted_scores": [5.0, 4.0, 3.0], "plan_deltas": [1.0], "significant_counts": [1]},
            "history": [
                {"step": "gate", "result": "iterate", "timestamp": _iso_hours_ago(1.0)},
                {"step": "gate", "result": "iterate", "timestamp": _iso_hours_ago(2.0)},
                {"step": "gate", "result": "blocked", "timestamp": _iso_hours_ago(3.0)},
            ],
        },
        plan_v_bodies={"plan_v1.md": "v1"},
        events_body="{}\n",
    )

    repair_data_dir = tmp_path / "repair-data"
    repair_data_dir.mkdir()
    (repair_data_dir / "demo-session.repair-data.json").write_text(
        json.dumps(
            {
                "session": "demo-session",
                "outcome": "repair_exhausted",
                "attempts": [
                    {"attempt_id": 1, "failure_classification": "timeout_or_hang"},
                    {"attempt_id": 2, "failure_classification": "timeout_or_hang"},
                    {"attempt_id": 3, "failure_classification": "timeout_or_hang"},
                ],
                "iterations": [],
            }
        ),
        encoding="utf-8",
    )

    gather_dir = tmp_path / "gather"
    gather_dir.mkdir()
    worklist = tmp_path / "worklist.jsonl"
    worklist.write_text(
        json.dumps(
            {
                "workspace": str(workspace),
                "plan": plan_name,
                "session": "demo-session",
                "kind": "chain",
                "sources": ["marker"],
                "session_evidence_scope": True,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    gather_path = gather_dir / "gather.py"
    gather_path.write_text(_extract_auditor_gather_program(), encoding="utf-8")
    env = dict(os.environ)
    env["MEGAPLAN_AUDIT_REPAIR_DATA_DIR"] = str(repair_data_dir)
    env["MEGAPLAN_AUDIT_META_RUN_DIR"] = str(tmp_path / "meta-runs")
    result = subprocess.run(
        [sys.executable, str(gather_path), str(worklist), str(gather_dir), "6", str(tmp_path), "none"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    findings = json.loads((gather_dir / "findings.json").read_text(encoding="utf-8"))["findings"]
    assert findings, "expected missing meta-repair run to produce a finding"
    finding = findings[0]
    meta_summary = finding["meta_repair_summary"]
    assert meta_summary["should_dispatch"] is True
    assert meta_summary["trigger"] in {"repair_timeout", "persistent_recurring_retry"}
    assert meta_summary["missing_meta_run_evidence"] is True
    assert meta_summary["meta_record_count"] == 0
    assert meta_summary["meta_run_log_count"] == 0


def test_auditor_gather_retains_recent_l2_sandbox_failure_after_later_runs(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    plan_name = "m4-sandbox-retro"
    plan_dir = workspace / ".megaplan" / "plans" / plan_name
    _write_plan(
        plan_dir,
        {
            "name": plan_name,
            "iteration": 4,
            "current_state": "blocked",
            "active_step": None,
            "latest_failure": {
                "kind": "stalled",
                "message": "ordinary repair exhausted",
                "recorded_at": _iso_hours_ago(1.0),
            },
        },
        plan_v_bodies={"plan_v1.md": "v1"},
        events_body="{}\n",
    )
    repair_data_dir = tmp_path / "repair-data"
    repair_data_dir.mkdir()
    (repair_data_dir / "demo-session.repair-data.json").write_text(
        json.dumps(
            {
                "session": "demo-session",
                "outcome": "repair_exhausted",
                "attempts": [
                    {"attempt_id": index, "failure_classification": "timeout_or_hang"}
                    for index in range(1, 4)
                ],
            }
        ),
        encoding="utf-8",
    )
    meta_runs = tmp_path / "meta-runs"
    meta_runs.mkdir()
    failed = meta_runs / "20260715T010000Z-demo-session-investigator-receipt.json"
    failed.write_text(
        json.dumps(
            {
                "failure_code": "investigator_read_sandbox_unavailable",
                "observed_error": "bwrap: No permissions to create new namespace",
            }
        ),
        encoding="utf-8",
    )
    for index in range(6):
        path = meta_runs / f"20260715T02{index:02d}00Z-demo-session-success-{index}.log"
        path.write_text("accepted L2 verdict\n", encoding="utf-8")
        advanced_mtime = failed.stat().st_mtime + index + 1
        os.utime(path, (advanced_mtime, advanced_mtime))
    for index in range(2):
        path = meta_runs / f"20260715T030{index}00Z-demo-session-invalid-{index}.log"
        path.write_text(
            (
                "[meta-repair 2026-07-15T03:00:00+00:00] "
                "L2 investigation failed or returned no valid receipt; "
                "refusing all repair mutation\n"
                if index == 0
                else (
                    "[meta-repair 2026-07-15T03:01:00+00:00] "
                    "L2 investigator failed or returned no valid receipt\n"
                )
            ),
            encoding="utf-8",
        )
        advanced_mtime = failed.stat().st_mtime + 10 + index
        os.utime(path, (advanced_mtime, advanced_mtime))
    authority_blocked = meta_runs / "20260715T031000Z-demo-session-authority.log"
    authority_blocked.write_text(
        "[meta-repair 2026-07-15T03:10:00+00:00] observed: "
        "L2 Codex dispatch blocked by master-plus-path authorization gate\n",
        encoding="utf-8",
    )
    advanced_mtime = failed.stat().st_mtime + 20
    os.utime(authority_blocked, (advanced_mtime, advanced_mtime))

    gather_dir = tmp_path / "gather"
    gather_dir.mkdir()
    worklist = tmp_path / "worklist.jsonl"
    worklist.write_text(
        json.dumps(
            {
                "workspace": str(workspace),
                "plan": plan_name,
                "session": "demo-session",
                "kind": "chain",
                "sources": ["marker"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    gather_path = gather_dir / "gather.py"
    gather_path.write_text(_extract_auditor_gather_program(), encoding="utf-8")
    env = dict(os.environ)
    env["MEGAPLAN_AUDIT_REPAIR_DATA_DIR"] = str(repair_data_dir)
    env["MEGAPLAN_AUDIT_META_RUN_DIR"] = str(meta_runs)
    result = subprocess.run(
        [sys.executable, str(gather_path), str(worklist), str(gather_dir), "6", str(tmp_path), "none"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    finding = json.loads(
        (gather_dir / "findings.json").read_text(encoding="utf-8")
    )["findings"][0]
    meta_summary = finding["meta_repair_summary"]
    failure_refs = [
        item for item in meta_summary["meta_run_refs"] if item.get("failure_code")
    ]
    assert {item["failure_code"] for item in failure_refs} == {
        "investigator_invalid_or_missing_receipt",
        "investigator_read_sandbox_unavailable",
        "meta_repair_authority_blocked",
    }
    assert meta_summary["failed_meta_run_count"] == 1
    assert meta_summary["meta_run_refs"][0]["failure_code"] == (
        "meta_repair_authority_blocked"
    )


def test_auditor_gather_flags_running_repair_without_attempt_context(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    plan_name = "m1-demo"
    plan_dir = workspace / ".megaplan" / "plans" / plan_name
    _write_plan(
        plan_dir,
        {
            "name": plan_name,
            "iteration": 0,
            "current_state": "initialized",
            "active_step": None,
            "latest_failure": {
                "kind": "phase_failed",
                "message": "worker_structural_audit_failed: type_mismatch at /suggested_approach",
                "recorded_at": _iso_hours_ago(1.0),
            },
            "history": [{"step": "init", "result": "success", "timestamp": _iso_hours_ago(7.0)}],
        },
        plan_v_bodies={"plan_v1.md": "v1"},
        events_body="{}\n",
    )

    repair_data_dir = tmp_path / "repair-data"
    repair_data_dir.mkdir()
    (repair_data_dir / "demo-session.repair-data.json").write_text(
        json.dumps(
            {
                "session": "demo-session",
                "outcome": "running",
                "repair_run_count": 6,
                "attempt_counter": 0,
                "current_attempt_id": None,
                "current_signature": {},
                "current_recurrence": {},
                "attempts": [],
                "iterations": [],
            }
        ),
        encoding="utf-8",
    )

    gather_dir = tmp_path / "gather"
    gather_dir.mkdir()
    worklist = tmp_path / "worklist.jsonl"
    worklist.write_text(
        json.dumps(
            {
                "workspace": str(workspace),
                "plan": plan_name,
                "session": "demo-session",
                "kind": "chain",
                "sources": ["marker"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    gather_path = gather_dir / "gather.py"
    gather_path.write_text(_extract_auditor_gather_program(), encoding="utf-8")
    env = dict(os.environ)
    env["MEGAPLAN_AUDIT_REPAIR_DATA_DIR"] = str(repair_data_dir)
    env["MEGAPLAN_AUDIT_META_RUN_DIR"] = str(tmp_path / "meta-runs")
    result = subprocess.run(
        [sys.executable, str(gather_path), str(worklist), str(gather_dir), "6", str(tmp_path), "none"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    findings = json.loads((gather_dir / "findings.json").read_text(encoding="utf-8"))["findings"]
    assert findings, "expected running repair without attempt context to produce a finding"
    meta_summary = findings[0]["meta_repair_summary"]
    assert meta_summary["should_dispatch"] is True
    assert meta_summary["trigger"] == "repair_running_without_attempt_context"
    assert meta_summary["missing_meta_run_evidence"] is True
    assert "artifact-quality gap" in " ".join(meta_summary["rationale"])


def test_arnold_progress_auditor_produces_evidence_cited_report_via_mocked_deepseek(tmp_path) -> None:
    report = _run_auditor_with_mocked_deepseek(tmp_path)
    finding = report["findings"][0]
    # The finding cites specific plan_v + gate evidence.
    combined = " ".join(finding["reasons"]) + " " + finding.get("hypothesis", "")
    assert "plan_v refreshed" in combined
    assert "gate=ITERATE/blocked" in combined
    assert "hypothesis:" in finding["hypothesis"]


# ── T9: repair-trigger / watchdog integration tests ──────────────────────


def test_watchdog_chain_runner_detected_as_alive_without_tmux(
    tmp_path: Path,
) -> None:
    """When ``matching_runner_process_alive`` confirms a live chain runner,
    ``session_health_status`` returns *alive* even without tmux."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")

    script = "\n\n".join(
        [
            _extract_wrapper_function("session_health_status"),
            """
matching_runner_process_alive() { return 0; }
chain_wait_status() { echo none; }
tmux() {
  if [[ "$1" == "has-session" ]]; then
    return 1
  fi
  return 0
}
""".strip(),
            f"session_health_status demo-session {str(workspace)!r} {str(spec_path)!r} chain ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "alive"


def test_watchdog_epic_chain_runner_detected_as_alive_without_tmux(
    tmp_path: Path,
) -> None:
    """When ``matching_runner_process_alive`` confirms a live epic-chain runner,
    ``session_health_status`` returns *alive* even without tmux."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    spec_path = workspace / ".megaplan" / "initiatives" / "epic-demo" / "epic-chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")

    script = "\n\n".join(
        [
            _extract_wrapper_function("session_health_status"),
            """
matching_runner_process_alive() { return 0; }
chain_wait_status() { echo none; }
tmux() {
  if [[ "$1" == "has-session" ]]; then
    return 1
  fi
  return 0
}
""".strip(),
            f"session_health_status epic-session {str(workspace)!r} {str(spec_path)!r} epic_chain ''",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "alive"


def test_watchdog_alive_by_process_prevents_relaunch(
    tmp_path: Path,
) -> None:
    """When ``session_health_status`` returns *alive* via process detection the
    watchdog must skip relaunch for that session."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    (marker_dir / "alive-session.json").write_text(
        json.dumps(
            {
                "session": "alive-session",
                "workspace": str(workspace),
                "remote_spec": str(spec_path),
                "run_kind": "chain",
            }
        ),
        encoding="utf-8",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"

    script = "\n\n".join(
        [
            _extract_wrapper_function("json_field"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(tmp_path / 'repair-data')!r}",
            f"LOG={str(log_path)!r}",
            """
report_item() {
  printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \"$1\" \"$2\" \"$3\" \"$4\" \"$5\" \"$6\" \"$7\" >> \"$1\"
}
log() { printf '%s\\n' \"$*\" >> \"$LOG\"; }
maybe_reexec_updated_watchdog() { :; }
sync_editable_source_branch() { return 0; }
adopt_unmarked_tmux_sessions() { :; }
reap_stale_repairs() { :; }
emit_report() { cp \"$1\" REPORT_PATH_PLACEHOLDER; }
# session is alive via process detection (no tmux needed).
session_health_status() { echo alive; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
chain_health_status() { CHAIN_HEALTH_STATUS=ok; }
repair_loop_busy_state() { echo none; }
dispatch_kimi_repair() { echo SHOULD_NOT_DISPATCH >&2; return 0; }
repair_unhealthy_session() { echo SHOULD_NOT_REPAIR >&2; return 0; }
mechanical_relaunch_attempted_previously() { return 0; }
kimi_dispatch_failed_previously() { return 1; }
kimi_dispatch_marker_set() { :; }
kimi_dispatch_marker_clear() { :; }
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH; }
safe_name() { printf '%s\\n' \"$1\"; }
tmux() { return 1; }
""".replace("REPORT_PATH_PLACEHOLDER", str(report_path)).strip(),
            f"launch_chain_tick alive-session {str(workspace)!r} {str(spec_path)!r} {str(report_path)!r} chain '' ''",
        ]
    )

    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    # Alive sessions get an observe report, not a relaunch.
    assert "alive" in report
    assert "restart" not in report
    assert "SHOULD_NOT_DISPATCH" not in result.stderr
    assert "SHOULD_NOT_REPAIR" not in result.stderr


def test_watchdog_marker_only_live_worker_session_prevents_duplicate_repair(
    tmp_path: Path,
) -> None:
    """A session with only a marker (no tmux) whose live worker PID is found
    must be classified alive, preventing duplicate repair dispatch."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    spec_path = workspace / ".megaplan" / "initiatives" / "demo-chain" / "chain.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    digest = hashlib.sha1(str(spec_path.resolve()).encode("utf-8")).hexdigest()[:12]
    chain_state_path = workspace / ".megaplan" / "plans" / ".chains" / f"chain-{digest}.json"
    chain_state_path.parent.mkdir(parents=True, exist_ok=True)
    plan_name = "m3-demo-plan"
    chain_state_path.write_text(
        json.dumps({"current_plan_name": plan_name}),
        encoding="utf-8",
    )
    plan_dir = workspace / ".megaplan" / "plans" / plan_name
    plan_dir.mkdir(parents=True, exist_ok=True)

    worker = subprocess.Popen(["sleep", "30"])
    try:
        (plan_dir / "state.json").write_text(
            json.dumps({"active_step": {"phase": "execute", "worker_pid": worker.pid}}),
            encoding="utf-8",
        )
        marker_dir = tmp_path / "markers"
        marker_dir.mkdir()
        (marker_dir / "demo-session.json").write_text(
            json.dumps(
                {
                    "session": "demo-session",
                    "workspace": str(workspace),
                    "remote_spec": str(spec_path),
                    "run_kind": "chain",
                }
            ),
            encoding="utf-8",
        )
        report_path = tmp_path / "report.tsv"
        log_path = tmp_path / "watchdog.log"

        script = "\n\n".join(
            [
                _extract_wrapper_function("json_field"),
                _extract_wrapper_function("matching_runner_process_alive"),
                _extract_wrapper_function("session_health_status"),
                _extract_wrapper_function("launch_chain_tick"),
                "chain_engine_root_preflight() { return 0; }",
                f"MARKER_DIR={str(marker_dir)!r}",
                f"REPAIR_DATA_DIR={str(tmp_path / 'repair-data')!r}",
                f"LOG={str(log_path)!r}",
                """
report_item() {
  printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \"$1\" \"$2\" \"$3\" \"$4\" \"$5\" \"$6\" \"$7\" >> \"$1\"
}
log() { printf '%s\\n' \"$*\" >> \"$LOG\"; }
maybe_reexec_updated_watchdog() { :; }
sync_editable_source_branch() { return 0; }
adopt_unmarked_tmux_sessions() { :; }
reap_stale_repairs() { :; }
emit_report() { cp \"$1\" REPORT_PATH_PLACEHOLDER; }
chain_wait_status() { echo none; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
chain_health_status() { CHAIN_HEALTH_STATUS=ok; }
repair_loop_busy_state() { echo none; }
dispatch_kimi_repair() { echo SHOULD_NOT_DISPATCH >&2; return 0; }
repair_unhealthy_session() { echo SHOULD_NOT_REPAIR >&2; return 0; }
mechanical_relaunch_attempted_previously() { return 0; }
kimi_dispatch_failed_previously() { return 1; }
kimi_dispatch_marker_set() { :; }
kimi_dispatch_marker_clear() { :; }
ensure_install_or_repair() { return 0; }
resolve_relaunch_command() { echo RELAUNCH; }
safe_name() { printf '%s\\n' \"$1\"; }
tmux() {
  if [[ \"$1\" == \"has-session\" ]]; then
    return 1
  fi
  return 0
}
""".replace("REPORT_PATH_PLACEHOLDER", str(report_path)).strip(),
                f"launch_chain_tick demo-session {str(workspace)!r} {str(spec_path)!r} {str(report_path)!r} chain '' ''",
            ]
        )

        result = _run_watchdog_shell(script)
        assert result.returncode == 0, result.stderr
        report = report_path.read_text(encoding="utf-8")
        # The worker is alive, so session is alive — no relaunch, no repair.
        assert "alive" in report
        assert "restart" not in report
        assert "SHOULD_NOT_DISPATCH" not in result.stderr
        assert "SHOULD_NOT_REPAIR" not in result.stderr
    finally:
        worker.terminate()
        worker.wait(timeout=5)


# ── T11: scan_once session-marker sidecar filtering ─────────────────────


def test_watchdog_scan_once_filters_canonical_sidecar_jsons(tmp_path: Path) -> None:
    """``scan_once`` must use ``is_canonical_session_marker_path`` to exclude
    canonical sidecar JSONs, scanning only real session markers."""
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    (marker_dir / "real-session.json").write_text(
        json.dumps(
            {
                "session": "real-session",
                "workspace": str(tmp_path / "ws"),
                "remote_spec": str(tmp_path / "ws" / "chain.yaml"),
                "run_kind": "chain",
            }
        ),
        encoding="utf-8",
    )
    (marker_dir / "megaplan-resident-discord.json").write_text(
        json.dumps({"session": "megaplan-resident-discord", "run_kind": "chain"}),
        encoding="utf-8",
    )
    # Canonical sidecars that must be skipped
    for suffix in (
        ".repair-progress.json",
        ".reap-progress.json",
        ".chain-health.progress.json",
        ".progress.json",
    ):
        (marker_dir / f"real-session{suffix}").write_text("{}", encoding="utf-8")
        (marker_dir / f"other{suffix}").write_text("{}", encoding="utf-8")

    script = "\n\n".join(
        [
            _extract_wrapper_function("scan_once_unlocked"),
            _extract_wrapper_function("scan_once"),
            f"MARKER_DIR={shlex.quote(str(marker_dir))}",
            f"REPAIR_DATA_DIR={shlex.quote(str(tmp_path / 'repair-data'))}",
            f"SCAN_LOCK_FILE={shlex.quote(str(tmp_path / 'watchdog-scan.lock'))}",
            "SCAN_LOCK_WAIT_SECS=0",
            "COOPERATIVE_ONCE=0",
            "WATCHDOG_BOOTSTRAP_RECOVERED=0",
            (
                "log() { printf '%s\\n' \"$*\" >> \"$LOG_PATH\"; }\n"
                "bootstrap_watchdog_observation() { return 0; }\n"
                "write_watchdog_sweep_health() { return 0; }\n"
                "write_watchdog_heartbeat() { :; }\n"
                "write_status_snapshot() { :; }\n"
                "run_repair_data_maintenance() { :; }\n"
                "maybe_reexec_updated_watchdog() { :; }\n"
                "sync_editable_source_branch() { return 0; }\n"
                "bootstrap_watchdog_observation() { return 0; }\n"
                "write_status_snapshot() { :; }\n"
                "adopt_unmarked_tmux_sessions() { :; }\n"
                "emit_report() { echo \"emit:$2\" >> \"$LOG_PATH\"; }\n"
                "reap_stale_repairs() { :; }\n"
                "json_field() { python3 -c \"import json,sys; d=json.load(open(sys.argv[1])); print(d.get(sys.argv[2],''))\" \"$1\" \"$2\"; }\n"
                "launch_chain_tick() { echo \"tick:$1\" >> \"$LOG_PATH\"; }\n"
            ),
            f"LOG_PATH={shlex.quote(str(tmp_path / 'scan.log'))}",
            "scan_once_unlocked",
        ]
    )

    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    log_text = (tmp_path / "scan.log").read_text(encoding="utf-8")
    # Only the real session should be ticked
    assert "tick:real-session" in log_text
    assert "tick:megaplan-resident-discord" not in log_text
    # Should report exactly 1 marker found (only the canonical session marker)
    assert "scan complete markers=1" in log_text


def test_watchdog_scan_once_excludes_sidecar_only_entries(tmp_path: Path) -> None:
    """When only canonical sidecar files exist (no real session markers),
    the scan must report 0 markers."""
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    # Only sidecar files, no real session markers
    for suffix in (".repair-progress.json", ".progress.json"):
        (marker_dir / f"phantom{suffix}").write_text("{}", encoding="utf-8")

    script = "\n\n".join(
        [
            _extract_wrapper_function("scan_once_unlocked"),
            _extract_wrapper_function("scan_once"),
            f"MARKER_DIR={shlex.quote(str(marker_dir))}",
            f"REPAIR_DATA_DIR={shlex.quote(str(tmp_path / 'repair-data'))}",
            f"SCAN_LOCK_FILE={shlex.quote(str(tmp_path / 'watchdog-scan.lock'))}",
            "SCAN_LOCK_WAIT_SECS=0",
            "COOPERATIVE_ONCE=0",
            "WATCHDOG_BOOTSTRAP_RECOVERED=0",
            (
                "log() { printf '%s\\n' \"$*\" >> \"$LOG_PATH\"; }\n"
                "bootstrap_watchdog_observation() { return 0; }\n"
                "write_watchdog_sweep_health() { return 0; }\n"
                "write_watchdog_heartbeat() { :; }\n"
                "write_status_snapshot() { :; }\n"
                "run_repair_data_maintenance() { :; }\n"
                "maybe_reexec_updated_watchdog() { :; }\n"
                "sync_editable_source_branch() { return 0; }\n"
                "bootstrap_watchdog_observation() { return 0; }\n"
                "write_status_snapshot() { :; }\n"
                "adopt_unmarked_tmux_sessions() { :; }\n"
                "emit_report() { echo \"emit:$2\" >> \"$LOG_PATH\"; }\n"
                "reap_stale_repairs() { :; }\n"
                "json_field() { python3 -c \"import json,sys; d=json.load(open(sys.argv[1])); print(d.get(sys.argv[2],''))\" \"$1\" \"$2\"; }\n"
                "launch_chain_tick() { echo \"tick:$1\" >> \"$LOG_PATH\"; }\n"
            ),
            f"LOG_PATH={shlex.quote(str(tmp_path / 'scan.log'))}",
            "scan_once_unlocked",
        ]
    )

    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    log_text = (tmp_path / "scan.log").read_text(encoding="utf-8")
    assert "scan complete markers=0" in log_text


def test_watchdog_observes_unowned_preserve_live_goal_without_dispatch(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    repair_data_dir = marker_dir / "repair-data"
    marker_dir.mkdir()
    repair_data_dir.mkdir()
    report_path = tmp_path / "report.tsv"
    dispatch_path = tmp_path / "dispatch.log"
    log_path = tmp_path / "watchdog.log"
    script = "\n\n".join(
        [
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(repair_data_dir)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            f"MEGAPLAN_SUPERVISOR_PYTHON={sys.executable!r}",
            f"LOG={str(log_path)!r}",
            f"DISPATCH_PATH={str(dispatch_path)!r}",
            """
log() { printf '%s\n' "$*" >> "$LOG"; }
report_item() { printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"; }
repair_goal_watchdog_status() { printf 'active_unowned\tgoal-healthy\tfresh execute worker is still progressing\tpreserve_live\n'; }
repair_unintended_stop() { printf 'dispatch\n' >> "$DISPATCH_PATH"; }
""".strip(),
            f"launch_chain_tick custody-control-plane {str(tmp_path / 'workspace')!r} {str(tmp_path / 'chain.yaml')!r} {str(report_path)!r} chain '' ''",
        ]
    )

    result = _run_watchdog_shell(script)

    assert result.returncode == 0, result.stderr
    assert not dispatch_path.exists()
    assert "\tobserve\trecovery_observation\tpreserve fresh matching worker" in report_path.read_text(encoding="utf-8")
    assert "observing without repair launch" in log_path.read_text(encoding="utf-8")


def test_watchdog_suppresses_unowned_goal_redispatch_for_authoritative_live_worker(
    tmp_path: Path,
) -> None:
    marker_dir = tmp_path / "markers"
    repair_data_dir = marker_dir / "repair-data"
    marker_dir.mkdir()
    repair_data_dir.mkdir()
    report_path = tmp_path / "report.tsv"
    dispatch_path = tmp_path / "dispatch.log"
    log_path = tmp_path / "watchdog.log"
    script = "\n\n".join(
        [
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(repair_data_dir)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            f"MEGAPLAN_SUPERVISOR_PYTHON={sys.executable!r}",
            f"LOG={str(log_path)!r}",
            f"DISPATCH_PATH={str(dispatch_path)!r}",
            """
log() { printf '%s\n' "$*" >> "$LOG"; }
report_item() { printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"; }
repair_goal_watchdog_status() { printf 'active_unowned\tgoal-live\towner terminalized before review finished\tinvestigate\n'; }
current_target_has_live_worker() { return 0; }
dispatch_meta_repair() { printf 'l2\n' >> "$DISPATCH_PATH"; }
repair_unintended_stop() { printf 'l1\n' >> "$DISPATCH_PATH"; }
""".strip(),
            f"launch_chain_tick custody-control-plane {str(tmp_path / 'workspace')!r} {str(tmp_path / 'chain.yaml')!r} {str(report_path)!r} chain '' ''",
        ]
    )

    result = _run_watchdog_shell(script)

    assert result.returncode == 0, result.stderr
    assert not dispatch_path.exists()
    assert "preserve authoritative live target worker" in report_path.read_text(encoding="utf-8")
    assert "suppressing replacement-owner dispatch" in log_path.read_text(encoding="utf-8")


def test_watchdog_suppresses_unowned_goal_while_runner_finishes_backstop(
    tmp_path: Path,
) -> None:
    """A live canonical runner remains authoritative after active_step clears."""

    marker_dir = tmp_path / "markers"
    repair_data_dir = marker_dir / "repair-data"
    marker_dir.mkdir()
    repair_data_dir.mkdir()
    report_path = tmp_path / "report.tsv"
    dispatch_path = tmp_path / "dispatch.log"
    log_path = tmp_path / "watchdog.log"
    script = "\n\n".join(
        [
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(repair_data_dir)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            f"MEGAPLAN_SUPERVISOR_PYTHON={sys.executable!r}",
            f"LOG={str(log_path)!r}",
            f"DISPATCH_PATH={str(dispatch_path)!r}",
            """
log() { printf '%s\n' "$*" >> "$LOG"; }
report_item() { printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"; }
repair_goal_watchdog_status() { printf 'active_unowned\tgoal-live\tcited fix missing from target history\tinvestigate\ttrue\n'; }
current_target_has_live_worker() { return 1; }
dispatch_meta_repair() { printf 'l2\n' >> "$DISPATCH_PATH"; }
repair_unintended_stop() { printf 'l1\n' >> "$DISPATCH_PATH"; }
""".strip(),
            f"launch_chain_tick custody-control-plane {str(tmp_path / 'workspace')!r} {str(tmp_path / 'chain.yaml')!r} {str(report_path)!r} chain '' ''",
        ]
    )

    result = _run_watchdog_shell(script)

    assert result.returncode == 0, result.stderr
    assert not dispatch_path.exists()
    assert "preserve authoritative live target worker" in report_path.read_text(encoding="utf-8")
    assert "suppressing replacement-owner dispatch" in log_path.read_text(encoding="utf-8")


def test_current_target_live_worker_requires_canonical_bound_record() -> None:
    function = _extract_wrapper_function("current_target_has_live_worker")
    known = {
        "schema": "arnold.megaplan.current_target_liveness.v1",
        "state": "live",
        "live": True,
        "dead": False,
        "known": True,
        "source": "fresh_owner_lease",
        "identity": {},
        "lease": {},
        "diagnostics": [],
        "control_permitted": True,
        "mutation_permitted": True,
        "escalation_permitted": True,
        "retrigger_permitted": True,
    }
    live = json.dumps(
        {
            "current_target_liveness": known,
        }
    )
    legacy_bypass = json.dumps(
        {
            "active_step_heartbeat": {
                "active": True,
                "pid_live": True,
                "worker_pid": "1179344",
            },
            "tmux_process": {"session_live": True, "live_status": "alive"},
        }
    )

    accepted = _run_watchdog_shell(
        f"SRC_DIR={shlex.quote(str(REPO_ROOT))}\n{function}\ncurrent_target_has_live_worker {shlex.quote(live)}"
    )
    rejected = _run_watchdog_shell(
        f"SRC_DIR={shlex.quote(str(REPO_ROOT))}\n{function}\ncurrent_target_has_live_worker {shlex.quote(legacy_bypass)}"
    )

    assert accepted.returncode == 0, accepted.stderr
    assert rejected.returncode == 1, rejected.stderr


def test_watchdog_unknown_canonical_liveness_fences_all_dispatch(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    report_path = tmp_path / "report.tsv"
    dispatch_path = tmp_path / "dispatch"
    script = "\n\n".join(
        [
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(marker_dir / 'repair-data')!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            f"DISPATCH_PATH={str(dispatch_path)!r}",
            """
log() { :; }
report_item() { printf '%s\t%s\t%s\t%s\n' "$2" "$3" "$4" "$5" >> "$1"; }
dispatch_kimi_repair() { : > "$DISPATCH_PATH"; }
dispatch_meta_repair() { : > "$DISPATCH_PATH"; }
repair_unintended_stop() { : > "$DISPATCH_PATH"; }
""".strip(),
            f"launch_chain_tick unbound {str(tmp_path / 'workspace')!r} {str(tmp_path / 'chain.yaml')!r} {str(report_path)!r} chain '' ''",
        ]
    )

    result = _run_watchdog_shell(script)

    assert result.returncode == 0, result.stderr
    assert not dispatch_path.exists()
    assert "\tobserve\tliveness_unknown\t" in report_path.read_text(encoding="utf-8")


def test_meta_repair_marker_and_pgid_helpers(tmp_path: Path) -> None:
    """meta_dispatch_marker_path, meta_pgid_path, meta_dispatch_marker_set/clear work correctly."""
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()

    script = "\n\n".join(
        [
            _extract_wrapper_function("meta_dispatch_marker_path"),
            _extract_wrapper_function("meta_pgid_path"),
            _extract_wrapper_function("meta_dispatch_marker_set"),
            _extract_wrapper_function("meta_dispatch_marker_clear"),
            f"MARKER_DIR={str(marker_dir)!r}",
            "META_PATH=$(meta_dispatch_marker_path demo)",
            'echo "MARKER=$META_PATH"',
            "PGID_PATH=$(meta_pgid_path demo)",
            'echo "PGID=$PGID_PATH"',
            "meta_dispatch_marker_set demo managed-run /tmp/manifest.json",
            "test -f \"$META_PATH\" && echo MARKER_EXISTS",
            "meta_dispatch_marker_clear demo",
            "test ! -f \"$META_PATH\" && echo MARKER_CLEARED",
        ]
    )

    result = subprocess.run(
        ["bash", "-lc", script],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    lines = result.stdout.strip().splitlines()
    assert any("MARKER=" in line and ".meta-dispatch" in line for line in lines), f"stdout: {result.stdout}"
    assert any("PGID=" in line and ".meta-pgid" in line for line in lines), f"stdout: {result.stdout}"
    assert "MARKER_EXISTS" in lines, f"stdout: {result.stdout}"
    assert "MARKER_CLEARED" in lines, f"stdout: {result.stdout}"


def test_repair_data_maintenance_runs_cleanup_once_and_updates_index(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    repair_dir = marker_dir / "repair-data"
    sidecar_dir = marker_dir / "repair-data.d"
    marker_dir.mkdir(parents=True)
    repair_dir.mkdir(parents=True)

    active_marker = marker_dir / "active-session.json"
    active_marker.write_text(
        json.dumps(
            {
                "session": "active-session",
                "workspace": "/tmp/ws",
                "remote_spec": "/tmp/ws/spec.yaml",
            }
        ),
        encoding="utf-8",
    )
    (repair_dir / "active-session.repair-data.json").write_text(
        json.dumps({"session": "active-session", "outcome": "repairing"}),
        encoding="utf-8",
    )
    stale_snapshot = repair_dir / "stale-session.repair-data.json"
    stale_snapshot.write_text(
        json.dumps({"session": "stale-session", "outcome": "complete"}),
        encoding="utf-8",
    )
    stale_ts = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc).timestamp()
    os.utime(stale_snapshot, (stale_ts, stale_ts))

    (repair_dir / "meta").mkdir()
    stale_meta = repair_dir / "meta" / "meta-old.json"
    stale_meta.write_text(json.dumps({"meta_repair_id": "meta-old"}), encoding="utf-8")
    os.utime(stale_meta, (stale_ts, stale_ts))

    from arnold_pipelines.megaplan.cloud import repair_contract

    repair_contract.update_session_index(
        repair_dir / "index.json",
        "active-session",
        {
            "status": "active",
            "latest_meta_repair_id": "meta-old",
            "latest_meta_outcome": "fixed",
            "latest_meta_record_path": str(stale_meta),
            "latest_meta_recorded_at": "2026-01-01T00:00:00+00:00",
            "refs": {"latest-outcome": {"outcome": "repairing"}},
        },
    )
    repair_contract.update_session_index(
        repair_dir / "index.json",
        "stale-session",
        {"status": "complete", "refs": {"latest-outcome": {"outcome": "complete"}}},
    )

    script = "\n\n".join(
        [
            _extract_wrapper_function_until("run_repair_data_maintenance", "reap_stale_repair_candidates"),
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(repair_dir)!r}",
            f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            f"PYTHONPATH={str(REPO_ROOT)!r}",
            "REPAIR_DATA_RETENTION_INTERVAL_SECS=21600",
            'run_repair_data_maintenance; echo "FIRST=$?"',
            'run_repair_data_maintenance; echo "SECOND=$?"',
        ]
    )

    result = subprocess.run(["bash", "-lc", script], capture_output=True, text=True, check=False)
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert "RAN:cleanup-" in result.stdout, f"stdout: {result.stdout}"
    assert "THROTTLED" in result.stdout, f"stdout: {result.stdout}"
    assert not stale_snapshot.exists()
    persisted_index = repair_contract.read_repair_index(repair_dir / "index.json")
    assert "stale-session" not in persisted_index["sessions"]
    assert persisted_index["sessions"]["active-session"]["latest_meta_repair_id"] == ""
    assert (sidecar_dir / "cleanup" / "retention-maintenance.json").exists()


def test_repair_data_maintenance_skips_when_repair_lock_is_busy(tmp_path: Path) -> None:
    marker_dir = tmp_path / "markers"
    repair_dir = marker_dir / "repair-data"
    lock_dir = marker_dir / "demo.repair-loop.lock"
    marker_dir.mkdir(parents=True)
    repair_dir.mkdir(parents=True)
    repair_loop = tmp_path / "arnold-repair-loop"
    repair_loop.write_text("#!/usr/bin/env bash\nsleep 30\n", encoding="utf-8")
    repair_loop.chmod(repair_loop.stat().st_mode | stat.S_IXUSR)
    owner_process = subprocess.Popen([str(repair_loop), "demo"])
    acquired = repair_lock.acquire_repair_lock(
        lock_dir,
        session="demo",
        pid=owner_process.pid,
        command=f"{repair_loop} demo",
        cwd=str(tmp_path),
    )
    assert acquired.acquired

    script = "\n\n".join(
        [
            _extract_wrapper_function_until("run_repair_data_maintenance", "reap_stale_repair_candidates"),
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(repair_dir)!r}",
            f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            f"PYTHONPATH={str(REPO_ROOT)!r}",
            "REPAIR_DATA_RETENTION_INTERVAL_SECS=21600",
            "run_repair_data_maintenance",
        ]
    )

    try:
        result = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, check=False
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "LOCK_BUSY" in result.stdout, f"stdout: {result.stdout}"
        assert not (repair_dir / "index.json").exists()
    finally:
        owner_process.terminate()
        owner_process.wait(timeout=5)


def test_partial_liveness_tick_writes_sidecar_record(tmp_path: Path) -> None:
    """write_partial_liveness_tick appends a correctly-shaped JSONL record."""
    events_dir = tmp_path / "repair-data.d" / "events"
    events_dir.mkdir(parents=True)
    events_path = events_dir / "events.jsonl"

    # Extract write_partial_liveness_tick via _extract_wrapper_function_until
    # because _extract_wrapper_function cannot handle nested braces in heredocs.
    func_body = _extract_wrapper_function_until(
        "write_partial_liveness_tick", "clear_session_tracking_artifacts"
    )

    script = "\n\n".join(
        [
            func_body,
            f"MARKER_DIR={str(tmp_path)!r}",
            f"REPAIR_DATA_DIR={str(tmp_path)!r}/repair-data",
            "SRC_DIR=/workspace/arnold",
            "WRAPPER_REPO_ROOT=/workspace/arnold",
            "PYTHONPATH=/workspace/arnold",
            f"CLOUD_WATCHDOG_REPAIR_SIDECAR_DIR={str(tmp_path)!r}/repair-data.d",
            "write_partial_liveness_tick demo-session /tmp/ws /tmp/ws/spec.yaml chain demo-plan alive",
        ]
    )

    result = subprocess.run(
        ["bash", "-lc", script],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"

    assert events_path.exists(), f"events.jsonl not created at {events_path}"
    lines = events_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= 1, f"expected at least 1 line, got {len(lines)}"

    record = json.loads(lines[0])
    assert record["session"] == "demo-session"
    assert record["outcome"] == "partial_liveness"
    assert record["health"] == "alive"
    assert "recorded_at" in record
    assert record["run_kind"] == "chain"
    assert record["plan_name"] == "demo-plan"


def test_partial_liveness_tick_bounded_history(tmp_path: Path) -> None:
    """write_partial_liveness_tick keeps at most 20 records per sidecar."""
    events_dir = tmp_path / "repair-data.d" / "events"
    events_dir.mkdir(parents=True)
    events_path = events_dir / "events.jsonl"

    # Pre-seed with 25 existing records
    existing = [
        {
            "session": "demo-session",
            "outcome": "partial_liveness",
            "health": "alive",
            "recorded_at": f"2026-07-02T00:{i:02d}:00Z",
            "run_kind": "chain",
            "plan_name": "demo-plan",
        }
        for i in range(25)
    ]
    events_path.write_text(
        "\n".join(json.dumps(e, sort_keys=True) for e in existing) + "\n",
        encoding="utf-8",
    )

    func_body = _extract_wrapper_function_until(
        "write_partial_liveness_tick", "clear_session_tracking_artifacts"
    )

    script = "\n\n".join(
        [
            func_body,
            f"MARKER_DIR={str(tmp_path)!r}",
            f"REPAIR_DATA_DIR={str(tmp_path)!r}/repair-data",
            "SRC_DIR=/workspace/arnold",
            "WRAPPER_REPO_ROOT=/workspace/arnold",
            "PYTHONPATH=/workspace/arnold",
            f"CLOUD_WATCHDOG_REPAIR_SIDECAR_DIR={str(tmp_path)!r}/repair-data.d",
            "write_partial_liveness_tick demo-session /tmp/ws /tmp/ws/spec.yaml chain demo-plan alive",
        ]
    )

    result = subprocess.run(
        ["bash", "-lc", script],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"

    lines = events_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 20, f"expected 20 lines (25 pre-seeded + 1 new, bounded to 20), got {len(lines)}"


def test_partial_liveness_isolated_does_not_trigger_condition_5() -> None:
    """Isolated partial liveness (1 tick) does NOT trigger condition 5."""
    from arnold_pipelines.megaplan.cloud.meta_repair import classify_repair_system_failure

    classification = classify_repair_system_failure(
        "test-session",
        partial_liveness_ticks=1,
    )
    assert not classification.should_dispatch, (
        "Isolated partial liveness (1 tick) should NOT trigger condition 5"
    )
    assert classification.trigger is None


def test_partial_liveness_repeated_triggers_condition_5() -> None:
    """Repeated partial liveness (2 ticks) DOES trigger condition 5."""
    from arnold_pipelines.megaplan.cloud.meta_repair import (
        MetaRepairTrigger,
        classify_repair_system_failure,
    )

    classification = classify_repair_system_failure(
        "test-session",
        partial_liveness_ticks=2,
    )
    assert classification.should_dispatch, (
        "Repeated partial liveness (2 ticks) SHOULD trigger condition 5"
    )
    assert classification.trigger == MetaRepairTrigger.PARTIAL_LIVENESS_RECURRENCE


def test_partial_liveness_three_ticks_triggers_condition_5() -> None:
    """Three partial liveness ticks also trigger condition 5 (>=2 threshold)."""
    from arnold_pipelines.megaplan.cloud.meta_repair import (
        MetaRepairTrigger,
        classify_repair_system_failure,
    )

    classification = classify_repair_system_failure(
        "test-session",
        partial_liveness_ticks=3,
    )
    assert classification.should_dispatch
    assert classification.trigger == MetaRepairTrigger.PARTIAL_LIVENESS_RECURRENCE


def test_child_agent_launch_authority_or_reject_gates_watchdog_child_fanout() -> None:
    """Steps 55-58: watchdog child-agent launches (repair-loop / Kimi,
    meta-repair, and managed-agent families) may NEVER become accepted repair
    outside canonical simple_fixer delegation.  Forbidden authority sources
    emit a typed zero-authority rejection; an exact-F01 occurrence delegates
    to the simple_fixer singleton claim; without an occurrence the launch is a
    non-authoritative materializer that carries no child-agent fan-out (SC38)."""
    text = _wrapper("arnold-watchdog")

    # (0) the gate is defined and wired into all three dispatch families
    assert "child_agent_launch_authority_or_reject() {" in text, \
        "child_agent_launch_authority_or_reject must be defined"
    assert 'child_agent_launch_authority_or_reject live_watchdog arnold-watchdog' in text, \
        "watchdog child-agent launches must be classified by the gate"
    # Step 57 — managed-agent child launch gate (the surviving L1/L2 families
    # were removed with the layered stack; T57 is the sole remaining marker)
    assert "T57-MANAGED-AGENT-FANOUT-01" in text, \
        "managed-agent child launch must fail-closed via T57 gate"

    helper = _extract_wrapper_function("child_agent_launch_authority_or_reject")
    base = "\n\n".join(
        [
            helper,
            "WRAPPER_REPO_ROOT=" + repr(str(REPO_ROOT)),
        ]
    )

    # (a) forbidden authority source (label) -> typed zero-authority rejection
    script_a = base + (
        "\nexport ARNOLD_REPAIR_AUTHORITY_LABEL=forbidden\n"
        'R="$(child_agent_launch_authority_or_reject "live_watchdog" "arnold-watchdog")"\n'
        "printf '%s' \"$R\""
    )
    res_a = _run_watchdog_shell(script_a)
    assert res_a.returncode == 0, res_a.stderr
    out_a = json.loads(res_a.stdout)
    assert out_a["outcome"] == "zero_authority_rejected", out_a
    assert out_a["delegated"] is False
    assert out_a["child_agent_fanout"] is False
    assert out_a["canonical_delegation_path"] == "simple_fixer.singleton_claim.exact_f01_tuple"

    # (b) no F01 occurrence -> no authority claim (non-authoritative materializer)
    script_b = base + (
        "\nunset ARNOLD_REPAIR_AUTHORITY_LABEL ARNOLD_REPAIR_LIVENESS_RECEIPT "
        "ARNOLD_REPAIR_WBC_RECEIPT ARNOLD_REPAIR_REBUILDABLE_PROJECTION "
        "ARNOLD_REPAIR_F01_OCCURRENCE\n"
        'R="$(child_agent_launch_authority_or_reject "live_watchdog" "arnold-watchdog")"\n'
        "printf '%s' \"$R\""
    )
    res_b = _run_watchdog_shell(script_b)
    assert res_b.returncode == 0, res_b.stderr
    out_b = json.loads(res_b.stdout)
    assert out_b["outcome"] == "no_authority_claim", out_b
    assert out_b["delegated"] is False
    assert out_b["child_agent_fanout"] is False
    assert out_b["canonical_delegation_path"] == "simple_fixer.singleton_claim.exact_f01_tuple"

    # (c) exact F01 occurrence -> delegated to simple_fixer singleton claim
    script_c = base + (
        "\nexport ARNOLD_REPAIR_F01_OCCURRENCE=" + shlex.quote(json.dumps(_VALID_F01_OCCURRENCE)) + "\n"
        'R="$(child_agent_launch_authority_or_reject "live_watchdog" "arnold-watchdog")"\n'
        "printf '%s' \"$R\""
    )
    res_c = _run_watchdog_shell(script_c)
    assert res_c.returncode == 0, res_c.stderr
    out_c = json.loads(res_c.stdout)
    assert out_c["outcome"] == "delegated", out_c
    assert out_c["delegated"] is True
    assert out_c["child_agent_fanout"] is False
    assert out_c["occurrence_fingerprint"].startswith("sha256:"), out_c

    # (d) liveness receipt is also a forbidden authority source
    script_d = base + (
        "\nexport ARNOLD_REPAIR_LIVENESS_RECEIPT=forbidden\n"
        'R="$(child_agent_launch_authority_or_reject "live_watchdog" "arnold-watchdog")"\n'
        "printf '%s' \"$R\""
    )
    res_d = _run_watchdog_shell(script_d)
    assert res_d.returncode == 0, res_d.stderr
    out_d = json.loads(res_d.stdout)
    assert out_d["outcome"] == "zero_authority_rejected", out_d
    assert out_d["delegated"] is False
    assert out_d["child_agent_fanout"] is False

    # (e) WBC receipt is also a forbidden authority source
    script_e = base + (
        "\nexport ARNOLD_REPAIR_WBC_RECEIPT=forbidden\n"
        'R="$(child_agent_launch_authority_or_reject "live_watchdog" "arnold-watchdog")"\n'
        "printf '%s' \"$R\""
    )
    res_e = _run_watchdog_shell(script_e)
    assert res_e.returncode == 0, res_e.stderr
    out_e = json.loads(res_e.stdout)
    assert out_e["outcome"] == "zero_authority_rejected", out_e
    assert out_e["delegated"] is False
    assert out_e["child_agent_fanout"] is False

    # (f) rebuildable projection is also a forbidden authority source
    script_f = base + (
        "\nexport ARNOLD_REPAIR_REBUILDABLE_PROJECTION=forbidden\n"
        'R="$(child_agent_launch_authority_or_reject "live_watchdog" "arnold-watchdog")"\n'
        "printf '%s' \"$R\""
    )
    res_f = _run_watchdog_shell(script_f)
    assert res_f.returncode == 0, res_f.stderr
    out_f = json.loads(res_f.stdout)
    assert out_f["outcome"] == "zero_authority_rejected", out_f
    assert out_f["delegated"] is False
    assert out_f["child_agent_fanout"] is False


# ---------------------------------------------------------------------------
# Steps 59-65 (T39): repair-state authority gate for claim writes, adoption,
# existing-owner, stale cleanup, process reaping, retry loops, unchanged-
# fingerprint escalation, and retry-budget mutation.  Each branch must fail
# closed for forbidden authority sources (label / liveness / WBC receipt /
# rebuildable projection) so replay or stale cleanup cannot be counted as
# accepted progress.
# ---------------------------------------------------------------------------

_WATCHDOG_SRC = _wrapper("arnold-watchdog")


def _extract_watchdog_fn(name: str) -> str:
    start = _WATCHDOG_SRC.index(f"{name}() {{")
    end = _WATCHDOG_SRC.index("\n}\n", start) + 3
    return _WATCHDOG_SRC[start:end]


def test_watchdog_repair_state_gate_function_exists() -> None:
    """Step 59-65 prerequisite: the gate function is defined."""
    fn = _extract_watchdog_fn("watchdog_repair_state_authority_or_reject")
    assert "watchdog_repair_state_authority_or_reject" in fn
    # Must check all four forbidden sources.
    assert "ARNOLD_REPAIR_AUTHORITY_LABEL" in fn
    assert "ARNOLD_REPAIR_LIVENESS_RECEIPT" in fn
    assert "ARNOLD_REPAIR_WBC_RECEIPT" in fn
    assert "ARNOLD_REPAIR_REBUILDABLE_PROJECTION" in fn
    # Must emit typed outcomes.
    assert "zero_authority_rejected" in fn


@pytest.mark.parametrize(
    "forbidden_env",
    [
        "ARNOLD_REPAIR_AUTHORITY_LABEL",
        "ARNOLD_REPAIR_LIVENESS_RECEIPT",
        "ARNOLD_REPAIR_WBC_RECEIPT",
        "ARNOLD_REPAIR_REBUILDABLE_PROJECTION",
    ],
)
def test_watchdog_repair_state_gate_rejects_forbidden_sources(
    forbidden_env: str,
) -> None:
    """The gate must return zero_authority_rejected for each forbidden source."""
    out = _run_repair_state_gate({forbidden_env: "forbidden"})
    assert out["outcome"] == "zero_authority_rejected", out


def test_watchdog_process_reaping_gated() -> None:
    """Step 62: reap_stale_repairs calls the state gate and fails closed with
    T62-PROCESS-REAP-01 tag."""
    fn = _extract_watchdog_fn("reap_stale_repairs")
    assert "watchdog_repair_state_authority_or_reject" in fn
    assert "T62-PROCESS-REAP-01" in fn
    assert "zero_authority_rejected" in fn


def test_watchdog_repair_state_gate_neutral_without_forbidden_sources() -> None:
    """Without forbidden sources the gate must not reject (delegated or
    no_authority_claim)."""
    out = _run_repair_state_gate()
    assert out["outcome"] in ("delegated", "no_authority_claim"), out
    assert out["outcome"] != "zero_authority_rejected"


# ── Step 59-65: watchdog repair-state authority gates (T39) ─────────────────
#
# Watchdog repair-state mutations (claim writes, claim adoption/existing-owner,
# stale-state cleanup, process reaping, retry loops, unchanged-fingerprint
# escalation, and retry-budget mutation) may NEVER become accepted repair
# outside canonical simple_fixer delegation.  Authority is never derived from a
# label, a liveness signal, a WBC receipt, or a rebuildable projection (SC39).

_REPAIR_STATE_GATE_FORBIDDEN_VARS = (
    "ARNOLD_REPAIR_AUTHORITY_LABEL",
    "ARNOLD_REPAIR_LIVENESS_RECEIPT",
    "ARNOLD_REPAIR_WBC_RECEIPT",
    "ARNOLD_REPAIR_REBUILDABLE_PROJECTION",
)

_REPAIR_STATE_VALID_F01_OCCURRENCE = {
    "environment": "cloud",
    "session": "demo-session",
    "chain": "origin/main",
    "plan_revision": "rev-1",
    "phase": "build",
    "task": "T39",
    "attempt": "1",
    "normalized_failure_kind": "test_failure",
    "blocker_or_phase_result_hash": "phase-result-hash-1",
    "fence": "fence-1",
}


def _run_repair_state_gate(
    env_overrides: dict[str, str] | None = None,
    *,
    caller_kind: str = "live_watchdog",
    caller_id: str = "arnold-watchdog",
) -> dict[str, object]:
    """Extract and execute the watchdog repair-state authority gate.

    The gate classifies a watchdog repair-state mutation (claim write, claim
    adoption/existing-owner, stale-state cleanup, process reaping, retry loop,
    unchanged-fingerprint escalation, or retry-budget mutation) and emits JSON
    with an ``outcome`` key in
    ``{zero_authority_rejected, delegated, no_authority_claim}``.
    """
    func = _extract_wrapper_function("watchdog_repair_state_authority_or_reject")
    unset_lines = "\n".join(
        ["unset ARNOLD_REPAIR_F01_OCCURRENCE"]
        + [f"unset {name}" for name in _REPAIR_STATE_GATE_FORBIDDEN_VARS]
    )
    export_lines = "\n".join(
        f"export {name}={shlex.quote(value)}"
        for name, value in (env_overrides or {}).items()
    )
    script = "\n".join(
        [
            func,
            "WRAPPER_REPO_ROOT=" + shlex.quote(str(REPO_ROOT)),
            unset_lines,
            export_lines,
            f"watchdog_repair_state_authority_or_reject {caller_kind} {caller_id}",
        ]
    )
    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip())


def _assert_repair_state_never_authorizes_forbidden_sources() -> None:
    """Shared SC39 behavioural proof: a forbidden authority source (label,
    liveness signal, WBC receipt, or rebuildable projection) may NEVER produce
    an accepted repair-state mutation.  Only an exact, complete F01 occurrence
    tuple can delegate a repair-state mutation through the simple_fixer
    singleton claim, and even then without rewriting history."""
    canonical = "simple_fixer.singleton_claim.exact_f01_tuple"

    # Each forbidden source alone rejects with zero authority and no mutation.
    for name in _REPAIR_STATE_GATE_FORBIDDEN_VARS:
        gate = _run_repair_state_gate({name: "forbidden-source-value"})
        assert gate["outcome"] == "zero_authority_rejected", (name, gate)
        assert gate["delegated"] is False, (name, gate)
        assert gate["repair_state_mutation"] is False, (name, gate)
        assert gate["canonical_delegation_path"] == canonical, (name, gate)

    # A forbidden source combined with a valid F01 tuple still rejects — the
    # forbidden authority source wins over any rebuildable projection.
    gate = _run_repair_state_gate(
        {
            "ARNOLD_REPAIR_LIVENESS_RECEIPT": "liveness-receipt",
            "ARNOLD_REPAIR_F01_OCCURRENCE": json.dumps(
                _REPAIR_STATE_VALID_F01_OCCURRENCE
            ),
        }
    )
    assert gate["outcome"] == "zero_authority_rejected", gate
    assert gate["delegated"] is False, gate
    assert gate["repair_state_mutation"] is False, gate

    # A partial F01 tuple (a rebuildable projection) cannot delegate.
    gate = _run_repair_state_gate(
        {
            "ARNOLD_REPAIR_F01_OCCURRENCE": json.dumps(
                {"environment": "cloud", "session": ""}
            )
        }
    )
    assert gate["outcome"] == "zero_authority_rejected", gate
    assert gate["delegated"] is False, gate

    # With no authority claim at all the mutation is a typed no-claim (neither
    # delegated nor mutation), never silently authorized.
    gate = _run_repair_state_gate()
    assert gate["outcome"] == "no_authority_claim", gate
    assert gate["delegated"] is False, gate
    assert gate["repair_state_mutation"] is False, gate
    assert gate["canonical_delegation_path"] == canonical, gate

    # Only an exact, complete F01 occurrence tuple delegates, through the
    # canonical singleton-claim path, binding to the current fence and custody
    # epoch (occurrence fingerprint).
    gate = _run_repair_state_gate(
        {
            "ARNOLD_REPAIR_F01_OCCURRENCE": json.dumps(
                _REPAIR_STATE_VALID_F01_OCCURRENCE
            )
        }
    )
    assert gate["outcome"] == "delegated", gate
    assert gate["delegated"] is True, gate
    assert gate["repair_state_mutation"] is True, gate
    assert gate["canonical_delegation_path"] == canonical, gate
    assert isinstance(gate.get("occurrence_fingerprint"), str)
    assert gate["occurrence_fingerprint"], gate


def test_watchdog_process_reaping_is_bound_to_custody_receipts() -> None:
    """Step 62: the watchdog process-reaping family (``reap_stale_repairs``)
    may NEVER become accepted repair outside canonical simple_fixer delegation.
    Reaping is bound to custody receipts and cannot authorize repair
    acceptance.  Authority is never derived from a label, liveness signal, WBC
    receipt, or rebuildable projection (SC39)."""
    text = _wrapper("arnold-watchdog")
    assert "Step 62: process-reaping family" in text
    assert "T62-PROCESS-REAP-01" in text
    assert "reap_stale_repairs() {" in text
    assert (
        '"$(watchdog_repair_state_authority_or_reject live_watchdog arnold-watchdog)"'
        in text
    )
    _assert_repair_state_never_authorizes_forbidden_sources()


def test_watchdog_runtime_transition_missing_spec_fails_closed(
    tmp_path: Path,
) -> None:
    """emit_runtime_transition_event must FAIL CLOSED (non-zero) when the
    workspace/spec inputs are absent — never succeed eventless (G3 #2)."""
    log_path = tmp_path / "watchdog.log"
    script = "\n\n".join(
        [
            _extract_wrapper_function("emit_runtime_transition_event"),
            f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            f"LOG={str(log_path)!r}",
            """
emit_runtime_transition_event deviation_declared demo-session "" /nonexistent/spec.yaml
echo "RC=$?"
""".strip(),
        ]
    )

    result = _run_watchdog_shell(script)
    assert result.returncode == 0, result.stderr
    assert "RC=1" in result.stdout, result.stdout
    assert (
        "runtime transition ledger input missing (workspace/spec) for deviation_declared; "
        "blocking dispatch session=demo-session"
    ) in log_path.read_text(encoding="utf-8")


def _make_authoritative_manifest(*, epic_id: str = "demo-epic") -> dict[str, object]:
    """A schema-valid authoritative runtime manifest (bootstrap_manifest loads
    it: schema "1", required keys, generation/state invariants)."""
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    return {
        "runtime_id": "demo-runtime",
        "schema": "1",
        "generation": 1,
        "epic_id": epic_id,
        "state": "active",
        "owner": "test",
        "base": {
            "ref": "main",
            "commit": "0" * 40,
            "editable_install_path": "/workspace/.megaplan/editable",
            "venv_path": "/workspace/.megaplan/venv",
        },
        "epic": {
            "branch": "fixer/demo-epic-20260811",
            "worktree_path": "/workspace/demo-epic-worktree",
            "venv_path": "/workspace/.megaplan/venv",
            "runtime_root": "/workspace/demo-epic-worktree",
            "expected_head": "0" * 40,
            "repair_bin": "/usr/local/bin/arnold-repair-loop",
            "deps_lockfile": "requirements.lock",
        },
        "indirection": {
            "host_path": "/tmp/demo",
            "container_path": "/workspace/demo",
            "mount_table": [],
            "execution_namespace": "demo",
            "verified_head": "0" * 40,
            "last_verified_at": now,
            "attestation": {
                "module_file": "arnold_pipelines/megaplan/__init__.py",
                "module_digest": "0" * 64,
                "mount_id": "demo-mount",
            },
        },
        "policy": {
            "policy_sha": "0" * 64,
            "model_policy_sha": "0" * 64,
            "sync_policy": "manifest-only",
        },
        "promotions": [],
        "timestamps": {"created": now, "updated": now, "closed": None},
        "gc_policy": "keep",
        "commands": [],
    }


def _write_runtime_manifest(
    tmp_path: Path,
    *,
    runtime_root: str | Path = REPO_ROOT,
    epic_id: str = "demo-epic",
) -> Path:
    """Write a schema-valid authoritative runtime manifest whose
    epic.runtime_root (and worktree_path) point at ``runtime_root`` —
    the admission shape the wrappers re-read as the manifest runtime pin."""
    manifest = _make_authoritative_manifest(epic_id=epic_id)
    root = Path(runtime_root)
    if root.resolve() == REPO_ROOT.resolve():
        expected_head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        head = expected_head.stdout.strip() if expected_head.returncode == 0 else "0" * 40
    else:
        head = _init_git_repo(root)
    manifest["epic"]["runtime_root"] = str(root)
    manifest["epic"]["worktree_path"] = str(root)
    manifest["epic"]["expected_head"] = head
    manifest_path = tmp_path / "runtime-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path


def _run_arnold_run(
    tmp_path: Path,
    *,
    env_overrides: dict[str, str],
    args: list[str],
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Run the real arnold-run script with a recording fake tmux in PATH.  The
    fake tmux refuses to launch unless both typed transitions are already in
    the incident ledger (ordering proof)."""
    fake_bin_dir = tmp_path / "fake-bin"
    fake_bin_dir.mkdir(exist_ok=True)
    tmux_calls = tmp_path / "tmux-calls.txt"
    tmux_stub = fake_bin_dir / "tmux"
    tmux_stub.write_text(
        "#!/usr/bin/env bash\n"
        f"printf 'tmux:%s\\n' \"$*\" >> {shlex.quote(str(tmux_calls))}\n"
        "if [[ \"$1\" == \"has-session\" ]]; then\n"
        "  exit 1\n"
        "fi\n"
        "if [[ \"$1\" == \"new-session\" ]]; then\n"
        f"  EVENTS_FILE={shlex.quote(str(tmp_path / 'workspace' / '.megaplan' / 'incident-ledger' / 'events.jsonl'))}\n"
        "  if ! grep -q 'runtime.fallback_considered' \"$EVENTS_FILE\" 2>/dev/null \\\n"
        "    || ! grep -q 'runtime.fallback_taken' \"$EVENTS_FILE\" 2>/dev/null; then\n"
        "    echo 'EVENTS_NOT_PRECEDING_LAUNCH' >&2\n"
        "    exit 9\n"
        "  fi\n"
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    tmux_stub.chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = f"{fake_bin_dir}:{env.get('PATH', '')}"
    env["PYTHONPATH"] = f"{REPO_ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}"
    env["ARNOLD_REPAIR_RUNTIME_SRC"] = str(REPO_ROOT)
    env.update(env_overrides)
    result = subprocess.run(
        [str(WRAPPER_DIR / "arnold-run"), *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    return result, tmux_calls


def test_arnold_run_admission_blocks_without_manifest_or_permit(
    tmp_path: Path,
) -> None:
    """arnold-run is an independently gated leaf wrapper: an absent manifest
    with no valid allow_manifestless permit fails closed (exit 78) BEFORE any
    tmux launch side effect."""
    absent_manifest = tmp_path / "absent-manifest.json"
    result, tmux_calls = _run_arnold_run(
        tmp_path,
        env_overrides={"ARNOLD_RUNTIME_MANIFEST": str(absent_manifest)},
        args=["demo-session", "echo", "hi"],
    )
    assert result.returncode == 78, result.stderr
    assert (
        "runtime manifest absent without a valid allow_manifestless permit"
        in result.stderr
    )
    assert not tmux_calls.exists() or "new-session" not in tmux_calls.read_text(
        encoding="utf-8"
    )


def test_arnold_run_journals_fallback_events_before_launch(tmp_path: Path) -> None:
    """With an authoritative manifest + explicit spec binding, arnold-run
    journals fallback_considered + fallback_taken BEFORE the tmux launch with
    the exact actor, failure class, session scope, and chain contract digest."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    spec_path = workspace / "chain.yaml"
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    manifest_path = tmp_path / "runtime-manifest.json"
    manifest_path.write_text(
        json.dumps(_make_authoritative_manifest()), encoding="utf-8"
    )
    result, tmux_calls = _run_arnold_run(
        tmp_path,
        env_overrides={
            "ARNOLD_RUNTIME_MANIFEST": str(manifest_path),
            "ARNOLD_RUN_SPEC": str(spec_path),
            "WORKSPACE_PATH": str(workspace),
        },
        args=["demo-session", "echo", "hi"],
    )
    assert result.returncode == 0, result.stderr
    assert "launched 'demo-session'" in result.stdout

    payloads = _read_incident_event_payloads(workspace)
    assert [p["type"] for p in payloads] == [
        "runtime.fallback_considered",
        "runtime.fallback_taken",
    ], payloads
    expected_digest = "sha256:" + hashlib.sha256(
        spec_path.read_bytes()
    ).hexdigest()
    for payload in payloads:
        assert payload["actor"] == "arnold-run"
        assert payload["failure_class"] == "availability"
        assert payload["scope"] == "chain:demo-session"
        assert payload["session_id"] == "demo-session"
        assert payload["chain_spec_sha256"] == expected_digest
        # G4: candidate_from is the manifest-declared runtime root (ARNOLD_SRC
        # resolves manifest-first), not the local checkout.
        assert payload["candidate_from"] == _make_authoritative_manifest()["epic"][
            "runtime_root"
        ]
    assert payloads[1]["candidate_to"] == "echo hi"
    # The fake tmux proved the events precede the launch; only the launch is
    # recorded on the tmux side.
    calls = tmux_calls.read_text(encoding="utf-8").splitlines()
    assert any(line.startswith("tmux:new-session") for line in calls), calls


def test_arnold_run_ledger_failure_blocks_launch(tmp_path: Path) -> None:
    """A runtime transition ledger write failure aborts arnold-run BEFORE the
    tmux launch (no event = no side effect)."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".megaplan").mkdir()
    (workspace / ".megaplan" / "incident-ledger").write_text(
        "not a directory", encoding="utf-8"
    )
    spec_path = workspace / "chain.yaml"
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    manifest_path = tmp_path / "runtime-manifest.json"
    manifest_path.write_text(
        json.dumps(_make_authoritative_manifest()), encoding="utf-8"
    )
    result, tmux_calls = _run_arnold_run(
        tmp_path,
        env_overrides={
            "ARNOLD_RUNTIME_MANIFEST": str(manifest_path),
            "ARNOLD_RUN_SPEC": str(spec_path),
            "WORKSPACE_PATH": str(workspace),
        },
        args=["demo-session", "echo", "hi"],
    )
    assert result.returncode == 1, result.stderr
    assert (
        "runtime fallback_considered ledger write failed; blocking launch"
        in result.stderr
    )
    assert not tmux_calls.exists() or "new-session" not in tmux_calls.read_text(
        encoding="utf-8"
    )


def _write_in_tmux_command(tmp_path: Path, events_file: Path) -> tuple[Path, Path]:
    """A TMUX-branch payload command that refuses to run unless both typed
    transitions are already in the incident ledger (ordering proof), then
    records its execution."""
    exec_log = tmp_path / "exec-calls.txt"
    in_tmux_cmd = tmp_path / "in-tmux-cmd.sh"
    in_tmux_cmd.write_text(
        "#!/usr/bin/env bash\n"
        f"EVENTS_FILE={shlex.quote(str(events_file))}\n"
        "if ! grep -q 'runtime.fallback_considered' \"$EVENTS_FILE\" 2>/dev/null \\\n"
        "  || ! grep -q 'runtime.fallback_taken' \"$EVENTS_FILE\" 2>/dev/null; then\n"
        "  echo 'EVENTS_NOT_PRECEDING_EXEC' >&2\n"
        "  exit 9\n"
        "fi\n"
        f"printf 'exec:%s\\n' \"$*\" >> {shlex.quote(str(exec_log))}\n",
        encoding="utf-8",
    )
    in_tmux_cmd.chmod(0o755)
    return in_tmux_cmd, exec_log


def test_arnold_run_in_tmux_journals_fallback_events_before_exec(
    tmp_path: Path,
) -> None:
    """G3 fifth run: the in-tmux (TMUX direct-exec) branch journals
    fallback_considered + fallback_taken BEFORE the direct exec, with the
    exact actor, failure class, session scope, and chain contract digest."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    spec_path = workspace / "chain.yaml"
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    manifest_path = tmp_path / "runtime-manifest.json"
    manifest_path.write_text(
        json.dumps(_make_authoritative_manifest()), encoding="utf-8"
    )
    events_file = (
        workspace / ".megaplan" / "incident-ledger" / "events.jsonl"
    )
    in_tmux_cmd, exec_log = _write_in_tmux_command(tmp_path, events_file)
    result, tmux_calls = _run_arnold_run(
        tmp_path,
        env_overrides={
            "TMUX": "/tmp/arnold-demo-session,0,0",
            "ARNOLD_RUNTIME_MANIFEST": str(manifest_path),
            "ARNOLD_RUN_SPEC": str(spec_path),
            "WORKSPACE_PATH": str(workspace),
        },
        args=["demo-session", str(in_tmux_cmd), "via-tmux"],
    )
    assert result.returncode == 0, result.stderr
    # The in-tmux branch executes the command directly; no detached
    # tmux new-session is ever issued.
    assert not tmux_calls.exists() or "new-session" not in tmux_calls.read_text(
        encoding="utf-8"
    )
    # The exec'd command itself verified the events already preceded it.
    assert exec_log.read_text(encoding="utf-8").splitlines() == [
        "exec:via-tmux"
    ], exec_log.read_text(encoding="utf-8")

    payloads = _read_incident_event_payloads(workspace)
    assert [p["type"] for p in payloads] == [
        "runtime.fallback_considered",
        "runtime.fallback_taken",
    ], payloads
    expected_digest = "sha256:" + hashlib.sha256(
        spec_path.read_bytes()
    ).hexdigest()
    for payload in payloads:
        assert payload["actor"] == "arnold-run"
        assert payload["failure_class"] == "availability"
        assert payload["scope"] == "chain:demo-session"
        assert payload["session_id"] == "demo-session"
        assert payload["chain_spec_sha256"] == expected_digest
        # G4: candidate_from is the manifest-declared runtime root (ARNOLD_SRC
        # resolves manifest-first), not the local checkout.
        assert payload["candidate_from"] == _make_authoritative_manifest()["epic"][
            "runtime_root"
        ]
    assert payloads[1]["candidate_to"] == f"{in_tmux_cmd} via-tmux"


def test_arnold_run_in_tmux_ledger_failure_blocks_exec(tmp_path: Path) -> None:
    """A runtime transition ledger write failure aborts the in-tmux
    (TMUX direct-exec) branch BEFORE the exec (no event = no side effect)."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".megaplan").mkdir()
    (workspace / ".megaplan" / "incident-ledger").write_text(
        "not a directory", encoding="utf-8"
    )
    spec_path = workspace / "chain.yaml"
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    manifest_path = tmp_path / "runtime-manifest.json"
    manifest_path.write_text(
        json.dumps(_make_authoritative_manifest()), encoding="utf-8"
    )
    events_file = (
        workspace / ".megaplan" / "incident-ledger" / "events.jsonl"
    )
    in_tmux_cmd, exec_log = _write_in_tmux_command(tmp_path, events_file)
    result, tmux_calls = _run_arnold_run(
        tmp_path,
        env_overrides={
            "TMUX": "/tmp/arnold-demo-session,0,0",
            "ARNOLD_RUNTIME_MANIFEST": str(manifest_path),
            "ARNOLD_RUN_SPEC": str(spec_path),
            "WORKSPACE_PATH": str(workspace),
        },
        args=["demo-session", str(in_tmux_cmd)],
    )
    assert result.returncode == 1, result.stderr
    assert (
        "runtime fallback_considered ledger write failed; blocking in-tmux launch"
        in result.stderr
    )
    # The direct exec never happened.
    assert not exec_log.exists()
    assert not tmux_calls.exists() or "new-session" not in tmux_calls.read_text(
        encoding="utf-8"
    )

def _phase_contract_script(
    *,
    marker_dir: Path,
    workspace: Path,
    plan_name: str,
    session: str,
    report_path: Path,
    log_path: Path,
    queue_root: Path,
    claim_log: Path,
    fake_py_log: Path,
    fake_repair_bin: Path,
    fake_repair_log: Path,
) -> str:
    """Full phase-contract path: launch_chain_tick → plan_attention_status_env
    → babysitter_policy_dispatch → launch_status_trigger_babysitter (stubbed
    bin). The owner-adoption exact-occurrence consumer and the layered
    claim/claim-active path were removed with L1/L2."""
    return "\n\n".join(
        [
            _extract_wrapper_function("babysitter_occurrence_digest"),
            _extract_wrapper_function("babysitter_effective_mode"),
            _extract_wrapper_function("babysitter_running_for_occurrence"),
            _extract_wrapper_function("babysitter_after_elapsed"),
            _extract_wrapper_function("launch_status_trigger_babysitter"),
            _extract_wrapper_function("babysitter_policy_dispatch"),
            _extract_wrapper_function("plan_attention_status_env"),
            _extract_wrapper_function("plan_terminal_status"),
            _extract_wrapper_function("launch_chain_tick"),
            "chain_engine_root_preflight() { return 0; }",
            f"MARKER_DIR={str(marker_dir)!r}",
            f"REPAIR_DATA_DIR={str(marker_dir / 'repair-data')!r}",
            f"LOG={str(log_path)!r}",
            f"WRAPPER_REPO_ROOT={str(REPO_ROOT)!r}",
            f"SRC_DIR={str(REPO_ROOT)!r}",
            f"export CLOUD_WATCHDOG_BABYSITTER_BIN={shlex.quote(str(fake_repair_bin))}",
            "export ARNOLD_BABYSITTER_LAUNCH_GRACE_SECS=0.3",
            f"export ARNOLD_REPAIR_QUEUE_ROOT={shlex.quote(str(queue_root))}",
            f"export ARNOLD_REPAIR_MARKER_DIR={shlex.quote(str(marker_dir))}",
            f"export ARNOLD_REPAIR_SESSION={shlex.quote(session)}",
            "export ARNOLD_REPAIR_RUN_KIND=plan",
            """
report_item() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$1"
}
log() { printf '%s\n' "$*" >> "$LOG"; }
session_health_status() { echo stopped; }
plan_phase_health_status() { echo ok; }
plan_progress_stall_status() { echo ok; }
emit_runtime_transition_event() { return 0; }
authority_fail_closed() { :; }
authority_gap_continue() { :; }
safe_name() { printf '%s\n' "$1"; }
json_field() { echo inc-demo; }
emit_watchdog_incident_bridge_event() { :; }
ensure_install_or_repair() { echo INSTALL >&2; return 0; }
resolve_relaunch_command() { echo RELAUNCH >&2; return 0; }
tmux() { echo TMUX >&2; return 1; }
""".strip(),
            (
                f"launch_chain_tick {shlex.quote(session)} {shlex.quote(str(workspace))} "
                f".megaplan/initiatives/demo/briefs/demo.md {shlex.quote(str(report_path))} "
                f"plan {shlex.quote(plan_name)} ''"
            ),
        ]
    )


def test_watchdog_phase_contract_path_dispatches_single_flash_babysitter(
    tmp_path: Path,
) -> None:
    """The phase-contract fence dispatches the single-flash babysitter (the
    ONLY repair dispatch) and NEVER falls through to a mechanical relaunch
    or a layered claim/consumer path."""
    session = "fence-session"
    marker_dir = tmp_path / ".megaplan" / "cloud-sessions"
    marker_dir.mkdir(parents=True, exist_ok=True)
    workspace = tmp_path / "ws"
    plan_name = "adopt-plan"
    plan_dir = workspace / ".megaplan" / "plans" / plan_name
    _write_live_session_marker(
        marker_dir,
        session,
        workspace,
        ".megaplan/initiatives/demo/briefs/demo.md",
        run_kind="plan",
        plan_name=plan_name,
    )
    _write_plan(
        plan_dir,
        {
            "iteration": 5,
            "current_state": "blocked",
            "active_step": None,
            "resume_cursor": {
                "phase": "gate",
                "retry_strategy": "repair_phase_contract",
            },
            "latest_failure": {
                "kind": "deterministic_phase_failure",
                "phase": "gate",
                "message": "gate contract failed",
            },
        },
        events_body="{}\n",
    )
    # The marker's remote_spec must exist for the runtime-transition ledger
    # (chain_spec_sha256) before the babysitter launch.
    spec_file = workspace / ".megaplan/initiatives/demo/briefs/demo.md"
    spec_file.parent.mkdir(parents=True, exist_ok=True)
    spec_file.write_text("milestones: []\n", encoding="utf-8")
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"
    claim_log = tmp_path / "claim.log"
    fake_py_log = tmp_path / "fake-python.log"
    fake_repair_log = tmp_path / "fake-repair.log"
    fake_repair_bin = tmp_path / "fake-repair-bin"
    fake_repair_bin.write_text(
        "#!/usr/bin/env bash\n"
        f'printf \'%s\\n\' "FAKE-REPAIR $*" >> {str(fake_repair_log)!r}\n'
        "exit 0\n",
        encoding="utf-8",
    )
    fake_repair_bin.chmod(fake_repair_bin.stat().st_mode | stat.S_IXUSR)

    script = _phase_contract_script(
        marker_dir=marker_dir,
        workspace=workspace,
        plan_name=plan_name,
        session=session,
        report_path=report_path,
        log_path=log_path,
        queue_root=tmp_path / "queue",
        claim_log=claim_log,
        fake_py_log=fake_py_log,
        fake_repair_bin=fake_repair_bin,
        fake_repair_log=fake_repair_log,
    )
    result = _run_watchdog_shell(script)

    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\trepair\tbabysitter_scheduled\t" in report, report
    assert "deterministic phase-contract failure (no mechanical relaunch)" in report
    # No layered claim was attempted and no managed-agent L1 child was launched.
    assert not claim_log.exists() or claim_log.read_text(encoding="utf-8") == ""
    assert not fake_py_log.exists(), (
        fake_py_log.read_text(encoding="utf-8") if fake_py_log.exists() else ""
    )
    # No mechanical relaunch.
    assert "RELAUNCH" not in result.stderr
    assert "\trestart\t" not in report
    assert "single-flash babysitter launched" in log_path.read_text(encoding="utf-8")


def test_watchdog_phase_contract_babysitter_launch_failure_fails_closed(
    tmp_path: Path,
) -> None:
    """A babysitter that dies immediately in the phase-contract path reports
    babysitter_launch_failed and NEVER falls through to a mechanical relaunch
    or a layered claim/consumer path."""
    session = "fence-session"
    marker_dir = tmp_path / ".megaplan" / "cloud-sessions"
    marker_dir.mkdir(parents=True, exist_ok=True)
    workspace = tmp_path / "ws"
    plan_name = "adopt-plan"
    plan_dir = workspace / ".megaplan" / "plans" / plan_name
    _write_live_session_marker(
        marker_dir,
        session,
        workspace,
        ".megaplan/initiatives/demo/briefs/demo.md",
        run_kind="plan",
        plan_name=plan_name,
    )
    _write_plan(
        plan_dir,
        {
            "iteration": 5,
            "current_state": "blocked",
            "active_step": None,
            "resume_cursor": {
                "phase": "gate",
                "retry_strategy": "repair_phase_contract",
            },
            "latest_failure": {
                "kind": "deterministic_phase_failure",
                "phase": "gate",
                "message": "gate contract failed",
            },
        },
        events_body="{}\n",
    )
    report_path = tmp_path / "report.tsv"
    log_path = tmp_path / "watchdog.log"
    claim_log = tmp_path / "claim.log"
    fake_py_log = tmp_path / "fake-python.log"
    fake_repair_log = tmp_path / "fake-repair.log"
    fake_repair_bin = tmp_path / "fake-repair-bin"
    fake_repair_bin.write_text(
        "#!/usr/bin/env bash\n"
        f'printf \'%s\\n\' "FAKE-REPAIR $*" >> {str(fake_repair_log)!r}\n'
        "exit 1\n",
        encoding="utf-8",
    )
    fake_repair_bin.chmod(fake_repair_bin.stat().st_mode | stat.S_IXUSR)

    script = _phase_contract_script(
        marker_dir=marker_dir,
        workspace=workspace,
        plan_name=plan_name,
        session=session,
        report_path=report_path,
        log_path=log_path,
        queue_root=tmp_path / "queue",
        claim_log=claim_log,
        fake_py_log=fake_py_log,
        fake_repair_bin=fake_repair_bin,
        fake_repair_log=fake_repair_log,
    )
    result = _run_watchdog_shell(script)

    assert result.returncode == 0, result.stderr
    report = report_path.read_text(encoding="utf-8")
    assert "\trepair\tbabysitter_launch_failed\t" in report, report
    assert "no L1/L2 fallthrough" in report
    # No layered claim was attempted and no managed-agent L1 child was launched.
    assert not claim_log.exists() or claim_log.read_text(encoding="utf-8") == ""
    assert not fake_py_log.exists(), (
        fake_py_log.read_text(encoding="utf-8") if fake_py_log.exists() else ""
    )
    # No mechanical relaunch.
    assert "RELAUNCH" not in result.stderr
    assert "\trestart\t" not in report
