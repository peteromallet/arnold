"""Tests for the status-trigger babysitter goal renderer."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys

RENDERER = (
    pathlib.Path(__file__).resolve().parents[2]
    / "arnold_pipelines"
    / "megaplan"
    / "skills"
    / "babysitter"
    / "scripts"
    / "render_babysitter_goal.py"
)


def _load_renderer():
    spec = importlib.util.spec_from_file_location("render_babysitter_goal", RENDERER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_renderer_requires_single_flash_orchestrator_contract() -> None:
    renderer = _load_renderer()
    goal = renderer.render_babysitter_goal("demo-session")
    for required in (
        "You are the BABYSITTER",
        "omp:deepseek/deepseek-v4-flash",
        "codex exec",
        "codex:gpt-5.6-sol",
        "STEP 1 — DEPLOY THE SWARM",
        "implement",
        "relaunch",
        "prove",
        "last_state",
        "failure_fingerprint",
        "BOUNDED FOREGROUND COMMAND",
    ):
        assert required in goal, f"goal missing {required!r}"


def test_renderer_is_the_single_agent_orchestrator_not_an_external_protocol() -> None:
    renderer = _load_renderer()
    goal = renderer.render_babysitter_goal("demo-session")
    for forbidden in (
        "do NOT collapse the babysitter into a single agent",
        "NOT the single-agent meta-fixer",
        "prompt-only pass is a failure mode",
    ):
        assert forbidden not in goal, f"goal must not contain {forbidden!r}"


def test_continuation_goal_closes_all_roles_to_muse_high() -> None:
    renderer = _load_renderer()
    goal = renderer.render_babysitter_goal(
        "native-build-forward-c2-bb000694-20260903-r4",
        session="native-build-forward-c2-bb000694-20260903-r4",
    )
    assert "omp:deepseek/deepseek-v4-flash" in goal
    assert "STEP 2 — CONSULT CODEX" in goal
    assert "codex exec" in goal
    assert "codex:gpt-5.6-sol" in goal


def test_renderer_coordination_guard_excludes_own_occurrence() -> None:
    renderer = _load_renderer()
    goal = renderer.render_babysitter_goal(
        "demo-session", occurrence_digest="abc123def456"
    )
    assert "Another fixer is already active for this chain; standing down" in goal
    assert "this occurrence's own babysitter-run directory" in goal
    assert "self-standdown bug" in goal
    assert "DIFFERENT" in goal


def test_renderer_embeds_session_workspace_plan_context() -> None:
    renderer = _load_renderer()
    goal = renderer.render_babysitter_goal(
        "demo-session",
        workspace="/workspace/app",
        plan="demo-plan",
        run_kind="chain",
        occurrence_digest="abc123def456",
    )
    assert '"demo-session"' in goal
    assert "- workspace: /workspace/app" in goal
    assert "- plan: demo-plan" in goal
    assert "- run_kind: chain" in goal
    assert "- occurrence_digest: abc123def456" in goal


def test_renderer_embeds_failure_evidence() -> None:
    renderer = _load_renderer()
    goal = renderer.render_babysitter_goal(
        "demo-session",
        plan="demo-plan",
        latest_failure={
            "kind": "deterministic_phase_failure",
            "phase": "finalize",
            "message": "task-graph rejection",
        },
        planner_repair={"schema": "megaplan.planner_repair", "candidate_id": "c-1"},
    )
    assert "latest_failure" in goal
    assert "deterministic_phase_failure" in goal
    assert "task-graph rejection" in goal
    assert "planner_repair" in goal
    assert "candidate_id" in goal


def test_renderer_cli_mentions_single_flash_contract(tmp_path: pathlib.Path) -> None:
    failure = tmp_path / "failure.json"
    failure.write_text(
        json.dumps({"kind": "stall_detected", "message": "driver stalled"}),
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable,
            str(RENDERER),
            "--target",
            "demo-session",
            "--workspace",
            "/workspace/app",
            "--plan",
            "demo-plan",
            "--failure-json",
            str(failure),
            "--occurrence-digest",
            "feedface1234",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "STEP 1 — DEPLOY THE SWARM" in result.stdout
    assert "omp:deepseek/deepseek-v4-flash" in result.stdout
    assert "failure_fingerprint" in result.stdout
    assert "stall_detected" in result.stdout


def test_renderer_embeds_prior_fixer_occurrences(tmp_path: pathlib.Path) -> None:
    """The goal must point the babysitter at prior fixer evidence so it
    continues the lineage instead of re-deriving from scratch."""
    recovery = tmp_path / "recovery"
    prior = recovery / "d58701026410"
    prior.mkdir(parents=True)
    (prior / "handoff.md").write_text("# prior handoff", encoding="utf-8")
    (prior / "codex").mkdir()
    (prior / "codex" / "sol-stage2-proposal.md").write_text(
        "# proposal", encoding="utf-8"
    )
    (recovery / "a102d8d24045").mkdir()  # evidence dir only, no markers

    result = subprocess.run(
        [
            sys.executable,
            str(RENDERER),
            "--target",
            "megaplan-maintenance",
            "--workspace",
            "/workspace/app",
            "--plan",
            "m1",
            "--run-kind",
            "chain",
            "--occurrence-digest",
            "a2c3644905c0",
            "--recovery-dir",
            str(recovery),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "Prior fixer work (READ THIS FIRST" in result.stdout
    assert "d58701026410" in result.stdout
    assert "handoff.md" in result.stdout
    assert "sol-stage2-proposal.md" in result.stdout
    assert "a102d8d24045" in result.stdout
    assert "continue the lineage" in result.stdout
    assert "ship it (cherry-pick/apply + regression) instead of re-authoring" in result.stdout
    assert "PERSIST AND SHIP THE FIX" in result.stdout
    assert "finish delivery" in result.stdout
    assert "push origin" in result.stdout
    assert "REBIND: advance the manifest" in result.stdout
    assert "write handoff.md here" in result.stdout


def test_renderer_absent_recovery_dir_is_orientation_not_error(
    tmp_path: pathlib.Path,
) -> None:
    """Missing recovery root must not hard-fail; the goal names the convention."""
    result = subprocess.run(
        [
            sys.executable,
            str(RENDERER),
            "--target",
            "megaplan-maintenance",
            "--workspace",
            "/workspace/app",
            "--plan",
            "m1",
            "--recovery-dir",
            str(tmp_path / "does-not-exist"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "Recovery evidence root not provided/unreadable" in result.stdout


def test_renderer_noop_guard_teaches_real_health_condition(
    tmp_path: pathlib.Path,
) -> None:
    """The NO-OP guard must not trust latest_failure alone (the auto-driver
    clears it on stall). It must teach the real stuck-condition: stale seed
    revision vs manifest, repeated phase errors, flat events while blocked."""
    result = subprocess.run(
        [
            sys.executable,
            str(RENDERER),
            "--target",
            "megaplan-maintenance",
            "--workspace",
            "/workspace/app",
            "--plan",
            "m1",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "REAL CONDITION" in result.stdout
    assert "auto-driver CLEARS" in result.stdout
    assert "stale seed" in result.stdout
    assert "expected_revision" in result.stdout
    assert "SAME phase erroring" in result.stdout
    assert "events.ndjson is not advancing" in result.stdout
    assert "driver-alive is NOT health" in result.stdout


def test_renderer_drive_custody_contract_pins_persistent_detached_launch() -> None:
    """STEP 4 must enforce the hub custody contract for chain drives.

    Regression for occurrence a1555447f922 (chain native-build-forward, plan
    p2-milestone-gate-bootstrap-20260827-1501, 2026-08-27): a chain drive
    launched persist=false/detached=false was SIGKILLed by hub last-omp
    teardown when the owning babysitter session ended (13m19s uptime, zero log
    output, no failure record, orphaned worker mid-gap between a successful
    plan phase and critique dispatch). Third recurrence of the class. The goal
    must pin the four hub fields, forbid a ready matcher, and forbid
    restart=on-failure (run_chain is synchronous, no singleton lock).
    """
    result = subprocess.run(
        [
            sys.executable,
            str(RENDERER),
            "--target",
            "native-build-forward",
            "--workspace",
            "/workspace/runtime-candidates/native-build-forward",
            "--plan",
            "p2-milestone-gate-bootstrap-20260827-1501",
            "--run-kind",
            "chain",
            "--occurrence-digest",
            "a1555447f922",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    for required in (
        "DRIVE CUSTODY CONTRACT",
        "persist: true",
        "detached: true",
        "pty: false",
        "restart: no",
        "NEVER use restart=on-failure",
    ):
        assert required in result.stdout, f"goal missing {required!r}"
