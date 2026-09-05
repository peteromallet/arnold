"""Static gates for cloud wrapper authority-risk bypasses."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys

import pytest

from arnold_pipelines.megaplan.custody.action_validator import GateResult


REPO_ROOT = Path(__file__).resolve().parents[2]
TARGETED_WRAPPERS = {
    "arnold_pipelines/megaplan/cloud/wrappers/arnold-chain",
    "arnold_pipelines/megaplan/cloud/wrappers/arnold-supervise",
    "arnold_pipelines/megaplan/cloud/wrappers/arnold-watchdog",
}
GATED_CALL_RE = re.compile(
    r"authority_(?:gap_continue|fail_closed|gap_record)\s+\"(T29-BYPASS-\d+)\""
)
RETIRED_AUTHORITY_RISK_IDS = {
    # The permissive arnold-chain acceptance fallback was deleted. The wrapper
    # now validates one schema-bound canonical decision and fails closed before
    # launching, so this historical bypass has no call site to gate.
    "T29-BYPASS-183",
    # Runtime-selector / env-precedence authority gaps were deleted with the
    # P4 selector removal and the mandatory manifest-bound launch gate
    # (T-0011); these call sites no longer exist in any targeted wrapper.
    "T29-BYPASS-063",
    "T29-BYPASS-064",
    "T29-BYPASS-144",
    "T29-BYPASS-145",
    # The layered repair stack wrappers were deleted; every bypass call
    # site they carried is gone with them.
    "T29-BYPASS-024",
    "T29-BYPASS-025",
    "T29-BYPASS-030",
    "T29-BYPASS-031",
    *{f"T29-BYPASS-{number:03d}" for number in range(33, 39)},
    *{f"T29-BYPASS-{number:03d}" for number in range(40, 45)},
    "T29-BYPASS-056",
    "T29-BYPASS-059",
    "T29-BYPASS-061",
    *{f"T29-BYPASS-{number:03d}" for number in range(65, 68)},
    "T29-BYPASS-074",
    "T29-BYPASS-075",
    *{f"T29-BYPASS-{number:03d}" for number in range(77, 80)},
    *{f"T29-BYPASS-{number:03d}" for number in range(90, 93)},
    *{f"T29-BYPASS-{number:03d}" for number in range(95, 116)},
    # The watchdog rewire removed the layered repair-dispatch machinery
    # (dispatch_kimi_repair / dispatch_meta_repair / repair_trigger_scan and
    # owner-adoption); the bypass gates those sections carried are gone.
    "T29-BYPASS-140",
    *{f"T29-BYPASS-{number:03d}" for number in range(160, 163)},
    "T29-BYPASS-164",
    "T29-BYPASS-177",
    *{f"T29-BYPASS-{number:03d}" for number in range(180, 183)},
    "T29-BYPASS-184",
    "T29-BYPASS-189",
    "T29-BYPASS-190",
    "T29-BYPASS-196",
    "T29-BYPASS-199",
    "T29-BYPASS-207",
}
EXPECTED_AUTHORITY_RISK_IDS = ({
    f"T29-BYPASS-{number:03d}"
    for number in (
        24,
        25,
        30,
        31,
        *range(33, 39),
        *range(40, 45),
        56,
        59,
        61,
        *range(63, 68),
        74,
        75,
        *range(77, 80),
        *range(90, 93),
        *range(95, 117),
        122,
        *range(126, 129),
        *range(131, 134),
        136,
        140,
        142,
        *range(144, 150),
        *range(151, 165),
        177,
        *range(180, 206),
        207,
        208,
        *range(212, 215),
    )
} - {"T29-BYPASS-163"}) - RETIRED_AUTHORITY_RISK_IDS


def test_authority_risk_bypass_audit_entries_are_typed_or_fail_closed() -> None:
    gated_ids: set[str] = set()
    for module_path in TARGETED_WRAPPERS:
        text = (REPO_ROOT / module_path).read_text(encoding="utf-8")
        if module_path != "arnold_pipelines/megaplan/cloud/wrappers/arnold-chain":
            assert "schema_version\": \"arnold.megaplan.cloud.wrapper_authority_gap.v1\"" in text
        gated_ids.update(GATED_CALL_RE.findall(text))

    assert EXPECTED_AUTHORITY_RISK_IDS <= gated_ids


def test_no_audited_authority_risk_id_is_silenced_with_naked_true() -> None:
    for module_path in TARGETED_WRAPPERS:
        for line_number, line in enumerate(
            (REPO_ROOT / module_path).read_text(encoding="utf-8").splitlines(),
            start=1,
        ):
            if "T29-BYPASS-" not in line:
                continue
            assert "|| true" not in line, f"{module_path}:{line_number}: {line}"
            assert "authority_gap_continue" in line or "authority_fail_closed" in line or "authority_gap_record" in line


def test_arnold_chain_is_in_the_authority_gate_and_has_no_permissive_fallback() -> None:
    text = (REPO_ROOT / "arnold_pipelines/megaplan/cloud/wrappers/arnold-chain").read_text(
        encoding="utf-8"
    )
    assert "arnold_pipelines/megaplan/cloud/wrappers/arnold-chain" in TARGETED_WRAPPERS
    assert "validate_wrapper_acceptance_decision" in text
    assert "acceptance_gate_empty_output" in text
    assert "acceptance_gate_helper_failed" in text
    assert "get('gate_open',True)" not in text
    assert "echo True" not in text
    assert ".get('gate_open'" not in text


def _chain_gate_fixture(*, spec_path: Path, workspace: Path, **overrides: object) -> str:
    payload: dict[str, object] = {
        "schema": "arnold.megaplan.cloud.wrapper_acceptance_gate.v1",
        "schema_version": 1,
        "decision": "open",
        "gate_open": True,
        "reason": "fixture open",
        "identity": {
            "spec_path": str(spec_path.resolve()),
            "workspace": str(workspace.resolve()),
            "session": "chain",
            "plan_name": None,
        },
    }
    payload.update(overrides)
    return json.dumps(payload, sort_keys=True)


def _chain_runtime_manifest(
    *,
    runtime_root: str,
    expected_head: str = "test-head",
    interpreter_path: str | None = None,
) -> dict[str, object]:
    """Fixture per-session runtime manifest — canonically schema-valid.

    Mirrors the canonical ``runtime_manifest`` schema (schema ``"1"`` with
    every required top-level and nested key, matching the shape
    ``bootstrap_manifest`` accepts) so the launch tests exercise a genuinely
    valid manifest.  The wrapper gate reads ``epic.runtime_root`` +
    ``epic.expected_head``; the remaining keys are required by the canonical
    validator (G5 round-8 finding 4: a three-field payload is schema-invalid
    and must never be labeled 'valid').

    G10 B1 (T-0301): when ``interpreter_path`` is given, the manifest also
    binds a COMPLETE dependency-generation proof — the launch gate requires
    all of id / frozen_spec_sha256 / interpreter_path / venv_digest / created
    and exits 24 on anything less.  Omit ``interpreter_path`` to exercise the
    proof-less fail-closed path."""
    now = datetime.now(timezone.utc).isoformat()
    manifest = {
        "runtime_id": "test-runtime",
        "schema": "1",
        "generation": 1,
        "epic_id": "test-epic",
        "state": "active",
        "owner": "test",
        "base": {
            "ref": "main",
            "commit": "0" * 40,
            "editable_install_path": "/workspace/.megaplan/editable",
            "venv_path": "/workspace/.megaplan/venv",
        },
        "epic": {
            "branch": "fixer/test",
            "worktree_path": runtime_root,
            "venv_path": "/workspace/.megaplan/venv",
            "runtime_root": runtime_root,
            "expected_head": expected_head,
            "repair_bin": "/usr/local/bin/arnold-babysitter",
            "deps_lockfile": "requirements.lock",
        },
        "indirection": {
            "host_path": "/tmp/test",
            "container_path": "/workspace/test",
            "mount_table": [],
            "execution_namespace": "test",
            "verified_head": "0" * 40,
            "last_verified_at": now,
            "attestation": {
                "module_file": "arnold_pipelines/megaplan/__init__.py",
                "module_digest": "0" * 64,
                "mount_id": "test-mount",
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
    if interpreter_path is not None:
        manifest["epic"]["dependency_generation"] = {
            "id": "d" * 64,
            "frozen_spec_sha256": "d" * 64,
            "interpreter_path": interpreter_path,
            "venv_digest": "v" * 64,
            "created": now,
        }
    return manifest


_CHAIN_PYTHON_SHIM = f"""#!{sys.executable}
import os
import subprocess
import sys

source = sys.stdin.read()
if "runtime_provenance" in " ".join(sys.argv[1:]):
    record = os.environ.get("CHAIN_PROVENANCE_RECORD")
    if record:
        with open(record, "a", encoding="utf-8") as fh:
            fh.write(
                "pythonpath=" + os.environ.get("PYTHONPATH", "") + "\\n"
                "manifest=" + os.environ.get("ARNOLD_RUNTIME_MANIFEST", "") + "\\n"
                "argv=" + " ".join(sys.argv[1:]) + "\\n"
            )
    raise SystemExit(int(os.environ.get("CHAIN_PROVENANCE_RC", "0")))
if "check_wrapper_acceptance_gate" in source and os.environ.get("CHAIN_GATE_FIXTURE") is not None:
    sys.stdout.write(os.environ["CHAIN_GATE_FIXTURE"])
    raise SystemExit(int(os.environ.get("CHAIN_GATE_RC", "0")))
if "arnold_pipelines.megaplan.cloud.chain_drive" in " ".join(sys.argv[1:]):
    marker = os.environ.get("CHAIN_LAUNCH_MARKER")
    launch_env = os.environ.get("CHAIN_LAUNCH_ENV")
    if marker:
        with open(marker, "a", encoding="utf-8") as fh:
            fh.write("launch\\n")
    if launch_env:
        with open(launch_env, "a", encoding="utf-8") as fh:
            fh.write(
                "ALL=" + " ".join(sys.argv[1:]) + "\\n"
                "INTERPRETER="
                + os.environ.get("CHAIN_GENERATION_INTERPRETER", os.path.abspath(sys.executable))
                + "\\n"
                "PYTHONPATH=" + os.environ.get("PYTHONPATH", "") + "\\n"
                "ARNOLD_RUNTIME_MANIFEST="
                + os.environ.get("ARNOLD_RUNTIME_MANIFEST", "")
                + "\\n"
            )
    raise SystemExit(0)
delegate = subprocess.run(
    [os.environ["REAL_PYTHON"], *sys.argv[1:]],
    input=source,
    text=True,
    capture_output=True,
    check=False,
)
sys.stdout.write(delegate.stdout)
sys.stderr.write(delegate.stderr)
raise SystemExit(delegate.returncode)
"""


def _run_chain_wrapper_subprocess(
    tmp_path: Path,
    *,
    gate_output: str | None = None,
    helper_rc: int = 0,
    missing_spec: bool = False,
    manifest: dict[str, object] | str | None = "valid",
    provenance_rc: int = 0,
) -> subprocess.CompletedProcess[str]:
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    spec_path = workspace / "chain.yaml"
    if not missing_spec:
        spec_path.write_text("milestones: []\n", encoding="utf-8")

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    # arnold-chain uses `python` for the stdlib manifest-field reads; the
    # provenance probe, the acceptance-gate helpers, and the chain launch all
    # run under the GENERATION interpreter resolved from the manifest
    # (T-0301/G10 B1) — the fixture points it at this same shim so every
    # interception keeps working.
    for name in ("python", "python3"):
        shim = fake_bin / name
        shim.write_text(_CHAIN_PYTHON_SHIM, encoding="utf-8")
        shim.chmod(0o755)
    fake_bash = fake_bin / "bash"
    fake_bash.write_text(
        """#!/bin/sh
printf 'launch\\n' >> "$CHAIN_LAUNCH_MARKER"
{
  printf 'ALL=%s\\n' "$*"
  printf 'PYTHONPATH=%s\\n' "$PYTHONPATH"
  printf 'ARNOLD_RUNTIME_MANIFEST=%s\\n' "$ARNOLD_RUNTIME_MANIFEST"
} >> "$CHAIN_LAUNCH_ENV"
exit 0
""",
        encoding="utf-8",
    )
    fake_bash.chmod(0o755)

    env = dict(os.environ)
    env.update(
        {
            "PATH": f"{fake_bin}:{env.get('PATH', '')}",
            "PYTHONPATH": str(REPO_ROOT),
            "REAL_PYTHON": sys.executable,
            "ARNOLD_CHAIN_LAUNCH_REQUEST_B64": "ZmFrZQ==",
            "CHAIN_GENERATION_INTERPRETER": str(fake_bin / "python"),
            "MEGAPLAN_PROJECT_DIR": str(workspace),
            "CHAIN_LAUNCH_MARKER": str(tmp_path / "chain-launched"),
            "CHAIN_LAUNCH_ENV": str(tmp_path / "chain-launch-env"),
            "CHAIN_GATE_RC": str(helper_rc),
            "CHAIN_PROVENANCE_RC": str(provenance_rc),
            "CHAIN_PROVENANCE_RECORD": str(tmp_path / "provenance-record"),
        }
    )
    if gate_output is None:
        env.pop("CHAIN_GATE_FIXTURE", None)
    else:
        env["CHAIN_GATE_FIXTURE"] = gate_output

    manifest_path = tmp_path / "runtime-manifest.json"
    if manifest is None:
        env.pop("ARNOLD_RUNTIME_MANIFEST", None)
    elif manifest == "valid":
        manifest_path.write_text(
            json.dumps(
                _chain_runtime_manifest(
                    runtime_root=str(REPO_ROOT),
                    interpreter_path=str(fake_bin / "python"),
                )
            ),
            encoding="utf-8",
        )
        env["ARNOLD_RUNTIME_MANIFEST"] = str(manifest_path)
    elif isinstance(manifest, dict):
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        env["ARNOLD_RUNTIME_MANIFEST"] = str(manifest_path)
    else:
        # `manifest` is a path-like string: pin that exact path (may not exist).
        env["ARNOLD_RUNTIME_MANIFEST"] = str(manifest)
    return subprocess.run(
        [
            "/bin/bash",
            str(REPO_ROOT / "arnold_pipelines/megaplan/cloud/wrappers/arnold-chain"),
            str(spec_path),
        ],
        cwd=workspace,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize(
    ("case", "gate_output", "helper_rc"),
    [
        ("nonzero", _chain_gate_fixture(spec_path=Path("/unused/chain.yaml"), workspace=Path("/unused")), 23),
        ("empty", "", 0),
        ("malformed", "not-json", 0),
        ("unknown-schema", json.dumps({"schema": "unknown"}), 0),
        ("missing-fields", json.dumps({"schema": "arnold.megaplan.cloud.wrapper_acceptance_gate.v1"}), 0),
        (
            "identity-mismatch",
            json.dumps(
                {
                    "schema": "arnold.megaplan.cloud.wrapper_acceptance_gate.v1",
                    "schema_version": 1,
                    "decision": "open",
                    "gate_open": True,
                    "reason": "wrong identity",
                    "identity": {
                        "spec_path": "/wrong/chain.yaml",
                        "workspace": "/wrong",
                        "session": "wrong-session",
                        "plan_name": None,
                    },
                }
            ),
            0,
        ),
        (
            "explicit-close",
            json.dumps(
                {
                    "schema": "arnold.megaplan.cloud.wrapper_acceptance_gate.v1",
                    "schema_version": 1,
                    "decision": "closed",
                    "gate_open": False,
                    "reason": "acceptance required",
                    "identity": {
                        "spec_path": "/wrong/chain.yaml",
                        "workspace": "/wrong",
                        "session": "chain",
                        "plan_name": None,
                    },
                }
            ),
            1,
        ),
    ],
)
def test_arnold_chain_invalid_acceptance_results_have_zero_launch_side_effects(
    tmp_path: Path, case: str, gate_output: str, helper_rc: int
) -> None:
    if case == "explicit-close":
        workspace = tmp_path / "workspace"
        gate_output = _chain_gate_fixture(
            spec_path=workspace / "chain.yaml",
            workspace=workspace,
            decision="closed",
            gate_open=False,
            reason="acceptance required",
        )
    result = _run_chain_wrapper_subprocess(
        tmp_path, gate_output=gate_output, helper_rc=helper_rc
    )
    assert result.returncode == 65, (case, result.stdout, result.stderr)
    assert not (tmp_path / "chain-launched").exists(), case
    assert "acceptance" in result.stderr.lower(), (case, result.stderr)


def test_arnold_chain_unreadable_spec_has_zero_launch_side_effects(tmp_path: Path) -> None:
    result = _run_chain_wrapper_subprocess(tmp_path, missing_spec=True)
    assert result.returncode == 65
    assert not (tmp_path / "chain-launched").exists()
    assert "spec unreadable" in result.stderr.lower() or "spec not found" in result.stderr.lower()


def test_arnold_chain_valid_open_result_reaches_exactly_one_launch_boundary(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    spec_path = workspace / "chain.yaml"
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    result = _run_chain_wrapper_subprocess(
        tmp_path,
        gate_output=_chain_gate_fixture(spec_path=spec_path, workspace=workspace),
    )
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "chain-launched").read_text(encoding="utf-8") == "launch\n"


# ── G2 finding 1: mandatory manifest-bound engine dir (T-0011) ──────────────


def test_arnold_chain_unbound_manifest_fails_closed_before_launch(tmp_path: Path) -> None:
    """Without ARNOLD_RUNTIME_MANIFEST the wrapper exits 24 with a typed
    binding-drift error before reaching any launch boundary — there is no
    /workspace/arnold fallback."""
    result = _run_chain_wrapper_subprocess(tmp_path, manifest=None)
    assert result.returncode == 24, (result.stdout, result.stderr)
    assert "isolated_chain_runtime_binding_drift" in result.stderr
    assert "missing runtime manifest pin" in result.stderr
    assert not (tmp_path / "chain-launched").exists()


@pytest.mark.parametrize(
    ("case", "manifest", "provenance_rc", "expect"),
    [
        (
            "missing-file",
            str(Path("/nonexistent/runtime-manifest.json")),
            0,
            "runtime manifest unreadable",
        ),
        (
            "malformed",
            {"epic": {}},
            0,
            "manifest lacks epic.runtime_root",
        ),
        (
            # G6 round-2 finding 2: the field reads are gated on the CANONICAL
            # schema, so a manifest missing ANY epic required key (here
            # expected_head) fails closed at the FIRST read — the pin gate can
            # never derive a dirty ENGINE_DIR from a non-canonical manifest.
            "schema-invalid-missing-expected-head",
            {"epic": {"runtime_root": "/some/root"}},
            0,
            "manifest lacks epic.runtime_root",
        ),
        (
            "provenance-mismatch",
            "valid",
            23,
            "active imports disagree with manifest-bound runtime",
        ),
    ],
)
def test_arnold_chain_invalid_manifest_fails_closed_before_launch(
    tmp_path: Path, case: str, manifest: object, provenance_rc: int, expect: str
) -> None:
    """Every gate rejection is a typed exit 24 with zero launch side effects."""
    result = _run_chain_wrapper_subprocess(
        tmp_path, manifest=manifest, provenance_rc=provenance_rc
    )
    assert result.returncode == 24, (case, result.stdout, result.stderr)
    assert "isolated_chain_runtime_binding_drift" in result.stderr, (case, result.stderr)
    assert expect in result.stderr, (case, result.stderr)
    assert not (tmp_path / "chain-launched").exists(), case


def test_arnold_chain_bound_manifest_launches_with_only_manifest_root(
    tmp_path: Path,
) -> None:
    """A bound manifest admits exactly one launch and the launch engine dir /
    provenance PYTHONPATH are ONLY the manifest runtime_root."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    spec_path = workspace / "chain.yaml"
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    result = _run_chain_wrapper_subprocess(
        tmp_path,
        gate_output=_chain_gate_fixture(spec_path=spec_path, workspace=workspace),
        manifest=_chain_runtime_manifest(
            runtime_root=str(REPO_ROOT),
            interpreter_path=str(tmp_path / "bin" / "python"),
        ),
    )
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "chain-launched").read_text(encoding="utf-8") == "launch\n"
    launch_env = (tmp_path / "chain-launch-env").read_text(encoding="utf-8")
    assert f"ALL=" in launch_env and str(REPO_ROOT) in launch_env, launch_env
    assert "/workspace/arnold" not in launch_env, launch_env
    provenance = (tmp_path / "provenance-record").read_text(encoding="utf-8")
    assert f"pythonpath={REPO_ROOT}" in provenance, provenance
    assert "/workspace/arnold" not in provenance, provenance


# ── G10 B1: generation-interpreter launch gate (T-0301) ─────────────────────


def test_arnold_chain_proof_complete_launch_threads_generation_interpreter(
    tmp_path: Path,
) -> None:
    """G10 B1 positive: with a COMPLETE dependency-generation proof the
    wrapper resolves the generation interpreter from the manifest and threads
    it into the launch boundary — the launch shell now receives
    ENGINE_DIR SPEC PROJECT_DIR GEN_INTERPRETER (the pre-G10 wrapper passed
    only three), so the chain start executes under the generation
    interpreter, never the ambient python.  The launch env records the
    interpreter path; the provenance probe ran with PYTHONPATH = the manifest
    runtime_root only."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    spec_path = workspace / "chain.yaml"
    spec_path.write_text("milestones: []\n", encoding="utf-8")
    result = _run_chain_wrapper_subprocess(
        tmp_path,
        gate_output=_chain_gate_fixture(spec_path=spec_path, workspace=workspace),
        manifest=_chain_runtime_manifest(
            runtime_root=str(REPO_ROOT),
            interpreter_path=str(tmp_path / "bin" / "python"),
        ),
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (tmp_path / "chain-launched").read_text(encoding="utf-8") == "launch\n"
    launch_env = (tmp_path / "chain-launch-env").read_text(encoding="utf-8")
    interpreter_line = next(
        line for line in launch_env.splitlines() if line.startswith("INTERPRETER=")
    )
    # The generation interpreter is the executable that invokes the co-located
    # launch engine; it is not an ambient-python argument or a shell fallback.
    assert str(tmp_path / "bin" / "python") in interpreter_line, launch_env
    assert "PYTHONPATH=" in launch_env, launch_env
    provenance = (tmp_path / "provenance-record").read_text(encoding="utf-8")
    assert f"pythonpath={REPO_ROOT}" in provenance, provenance
    assert "/workspace/arnold" not in provenance, provenance


def test_arnold_chain_missing_generation_proof_fails_closed_before_launch(
    tmp_path: Path,
) -> None:
    """G10 B1 negative: a schema-valid manifest WITHOUT a dependency-
    generation proof (or with an incomplete one) must exit 24 with the typed
    binding-drift message before any provenance probe or launch — a runtime
    without a verifiable immutable dependency generation is never launched
    and there is no ambient-python / editable-install fallback."""
    result = _run_chain_wrapper_subprocess(
        tmp_path,
        manifest=_chain_runtime_manifest(runtime_root=str(REPO_ROOT)),
    )
    assert result.returncode == 24, (result.stdout, result.stderr)
    assert "isolated_chain_runtime_binding_drift" in result.stderr
    assert "manifest lacks dependency generation interpreter" in result.stderr
    assert not (tmp_path / "chain-launched").exists()
    assert not (tmp_path / "provenance-record").exists()


def test_arnold_chain_wrapper_has_no_shared_root_fallback() -> None:
    text = (
        REPO_ROOT / "arnold_pipelines/megaplan/cloud/wrappers/arnold-chain"
    ).read_text(encoding="utf-8")
    assert "MEGAPLAN_ENGINE_DIR" not in text
    assert "/workspace/arnold" not in text
    assert "isolated_chain_runtime_binding_drift" in text
    assert "arnold_pipelines.megaplan.cloud.runtime_provenance" in text
    assert "--expected-root" in text
    assert 'PYTHONPATH="$ENGINE_DIR"' in text


def test_non_authoritative_cleanup_best_effort_remains_allowed() -> None:
    examples = {
        "arnold_pipelines/megaplan/cloud/templates/entrypoint.sh.tmpl": (
            'arnold config set execution.auto_approve true >/dev/null 2>&1 || true'
        ),
        "arnold_pipelines/megaplan/cloud/wrappers/arnold-heartbeat": (
            "pids=$(pgrep -f 'codex exec' || true)"
        ),
    }
    for module_path, snippet in examples.items():
        assert snippet in (REPO_ROOT / module_path).read_text(encoding="utf-8")


# ── T43: Step 81-85 systemd / deploy / hot-upload materializer gates ────────

_LEGACY_REPAIR_BINS = (
    "/usr/local/bin/arnold-watchdog",
    "/usr/local/bin/arnold-heartbeat",
    "/usr/local/bin/arnold-progress-auditor",
    "/usr/local/bin/arnold-supervise",
    "/usr/local/bin/mp-refresh-megaplan",
)

_CANONICAL_WORKSPACE_PREFIX = "/workspace/arnold/arnold_pipelines/megaplan/cloud/"


def _systemd_execstart_lines(unit_path: str) -> list[str]:
    return [
        line.strip()
        for line in (REPO_ROOT / unit_path).read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("ExecStart=")
    ]


def test_progress_audit_systemd_is_three_hour_reconciliation_only() -> None:
    """Step 82: progress-audit systemd uses three-hour reconciliation only."""
    timer_text = (
        REPO_ROOT / "arnold_pipelines/megaplan/cloud/systemd/megaplan-progress-audit.timer"
    ).read_text(encoding="utf-8")
    service_text = (
        REPO_ROOT / "arnold_pipelines/megaplan/cloud/systemd/megaplan-progress-audit.service"
    ).read_text(encoding="utf-8")

    # Timer must use OnUnitActiveSec=3h (next-three-hour reconciliation).
    assert "OnUnitActiveSec=3h" in timer_text

    # Service description must reference next-three-hour, not six-hour.
    assert "next-three-hour" in service_text.lower() or "3h" in service_text.lower()

    # Service must use the workspace checkout wrapper path, not a legacy binary.
    assert "/workspace/arnold/arnold_pipelines/megaplan/cloud/wrappers/arnold-progress-auditor" in service_text

    # No legacy repair bin paths in ExecStart.
    exec_lines = _systemd_execstart_lines(
        "arnold_pipelines/megaplan/cloud/systemd/megaplan-progress-audit.service"
    )
    for line in exec_lines:
        for legacy in _LEGACY_REPAIR_BINS:
            assert legacy not in line, f"legacy bin {legacy!r} found in progress-audit service: {line}"


def test_hot_upload_rejects_legacy_bins_and_session_commands() -> None:
    """Step 85: hot-upload rejects legacy-bin destinations and caller session commands."""
    import importlib.util
    import sys

    # Load the hot-upload module to verify its constants and guards.
    spec = importlib.util.spec_from_file_location(
        "cloud_hot_upload",
        REPO_ROOT / "scripts/cloud_hot_upload.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["cloud_hot_upload"] = module
    spec.loader.exec_module(module)

    # KNOWN_SESSION_COMMANDS must use canonical workspace paths, not legacy bins.
    for session_name, command in module.KNOWN_SESSION_COMMANDS.items():
        assert command not in module.FORBIDDEN_LEGACY_BIN_PATHS, (
            f"KNOWN_SESSION_COMMANDS[{session_name!r}] = {command!r} is a forbidden legacy bin"
        )
        assert command.startswith("/workspace/arnold/"), (
            f"KNOWN_SESSION_COMMANDS[{session_name!r}] = {command!r} must use workspace path"
        )

    # FORBIDDEN_LEGACY_BIN_PATHS covers all known legacy repair surfaces.
    for legacy in _LEGACY_REPAIR_BINS:
        is_covered = legacy in module.FORBIDDEN_LEGACY_BIN_PATHS or any(
            legacy.startswith(prefix) for prefix in module.FORBIDDEN_LEGACY_BIN_PREFIXES
        )
        assert is_covered, f"legacy bin {legacy!r} not covered by forbidden lists"

    # _is_forbidden_legacy_bin rejects all known legacy bins.
    for legacy in _LEGACY_REPAIR_BINS:
        assert module._is_forbidden_legacy_bin(legacy), (
            f"_is_forbidden_legacy_bin should reject {legacy!r}"
        )

    # _is_forbidden_legacy_bin accepts canonical workspace paths.
    assert not module._is_forbidden_legacy_bin(
        "/workspace/arnold/arnold_pipelines/megaplan/cloud/wrappers/arnold-watchdog"
    )
    assert not module._is_forbidden_legacy_bin("/usr/local/bin/some-other-tool")

    # parse_session_commands rejects caller-supplied legacy commands.
    try:
        module.parse_session_commands(["custom=/usr/local/bin/arnold-watchdog"])
        raise AssertionError("expected HotUploadError for legacy session command")
    except module.HotUploadError:
        pass

    # parse_session_commands accepts non-legacy commands.
    result = module.parse_session_commands(["custom=/workspace/arnold/some/tool"])
    assert result["custom"] == "/workspace/arnold/some/tool"

    # parse_upload rejects legacy-bin destinations.
    try:
        module.parse_upload("local.txt:/usr/local/bin/arnold-watchdog")
        raise AssertionError("expected HotUploadError for legacy upload destination")
    except module.HotUploadError:
        pass

    # parse_upload accepts non-legacy destinations.
    upload = module.parse_upload("local.txt:/workspace/arnold/some/file")
    assert upload.dest == "/workspace/arnold/some/file"


# ── T-0017: publication effects close by default ────────────────────────────


def _make_publication_protocol(tmp_path: Path):
    """Real EffectProtocol backed by SQLite stores (publication adapter)."""
    from arnold.workflow.attempt_ledger_store import SqliteAttemptLedgerStore
    from arnold.workflow.effect_protocol import EffectProtocol
    from arnold.workflow.ledger_outbox import SqliteLedgerOutbox

    db_path = str(tmp_path / "test_t0017_publication.db")
    store = SqliteAttemptLedgerStore(db_path)
    # Access conn to trigger lazy schema init.
    _ = store.conn
    outbox = SqliteLedgerOutbox(store)
    return EffectProtocol(store, outbox)


def _publication_adapter_spy(protocol, *, gate):
    """Wrap a real protocol in a recording spy plus the adapter under test."""
    from unittest.mock import Mock

    from arnold_pipelines.megaplan.cloud.publication_adapter import (
        PublicationAdapter,
        PublicationTarget,
    )

    spy = Mock(wraps=protocol)
    adapter = PublicationAdapter(spy, action_gate_check=gate)
    target = PublicationTarget(repo="owner/repo", occurrence_key="prob-1")
    return adapter, spy, target


def _publish_once(adapter, target):
    """Dispatch one publication through the adapter; return (outcome, callbacks)."""
    calls: list[dict[str, object]] = []

    def apply_fn(intent: dict[str, object]) -> dict[str, object]:
        calls.append(intent)
        return {"ok": True, "number": 42, "url": "https://github.com/owner/repo/issues/42"}

    outcome = adapter.publish(
        target=target,
        action="create",
        intent_payload={"title": "T0017", "body": "body"},
        apply_fn=apply_fn,
    )
    return outcome, len(calls)


@pytest.mark.parametrize(
    ("case", "gate", "expected_verdict"),
    [
        ("missing-gate", None, "missing"),
        ("shadow-pass", lambda family, target_key: GateResult.SHADOW_PASS, "shadow_pass"),
        ("blocked-stale-grant", lambda family, target_key: GateResult.BLOCKED_STALE_GRANT, "blocked_stale_grant"),
        ("blocked-stale-epoch", lambda family, target_key: GateResult.BLOCKED_STALE_EPOCH, "blocked_stale_epoch"),
        ("blocked-no-lease", lambda family, target_key: GateResult.BLOCKED_NO_LEASE, "blocked_no_lease"),
        ("blocked-wbc-missing", lambda family, target_key: GateResult.BLOCKED_WBC_MISSING, "blocked_wbc_missing"),
        ("error-verdict", lambda family, target_key: GateResult.ERROR, "error"),
    ],
)
def test_publication_zero_callbacks_for_non_authorized_verdicts(
    tmp_path: Path, case: str, gate: object, expected_verdict: str
) -> None:
    """Missing, shadow, stale, blocked, or error gate evidence admits ZERO
    publication callbacks and ZERO protocol reservations — a typed failed
    outcome is returned before any reservation or callback."""
    from arnold_pipelines.megaplan.custody.action_validator import GateResult

    adapter, spy, target = _publication_adapter_spy(
        _make_publication_protocol(tmp_path),
        gate=gate,
    )
    outcome, callbacks = _publish_once(adapter, target)
    assert callbacks == 0, case
    assert outcome.ok is False, case
    assert outcome.outcome_kind == "FAILED", case
    assert outcome.glek == "", case
    assert spy.reserve_and_start.call_count == 0, case
    assert "gate_verdict" in outcome.evidence, case
    assert outcome.evidence["gate_verdict"] == expected_verdict, case


def test_publication_zero_callbacks_when_gate_raises(tmp_path: Path) -> None:
    """An exceptional gate is a typed denial: no reservation, no callback."""

    def exploding_gate(family: str, target_key: str) -> GateResult:
        raise RuntimeError("gate exploded")

    adapter, spy, target = _publication_adapter_spy(
        _make_publication_protocol(tmp_path),
        gate=exploding_gate,
    )
    outcome, callbacks = _publish_once(adapter, target)
    assert callbacks == 0
    assert outcome.ok is False
    assert outcome.outcome_kind == "FAILED"
    assert outcome.glek == ""
    assert spy.reserve_and_start.call_count == 0
    assert outcome.evidence["gate_verdict"] == "error"
    assert "gate exploded" in outcome.error


def test_publication_zero_callbacks_for_stale_or_malformed_gate_evidence(
    tmp_path: Path,
) -> None:
    """A stale/foreign value (e.g. a bare string) is malformed gate evidence:
    it never authorizes a publication callback."""
    from arnold_pipelines.megaplan.custody.action_validator import GateResult

    adapter, spy, target = _publication_adapter_spy(
        _make_publication_protocol(tmp_path),
        gate=lambda family, target_key: "authorized",  # stale plain string
    )
    outcome, callbacks = _publish_once(adapter, target)
    assert callbacks == 0
    assert outcome.ok is False
    assert outcome.outcome_kind == "FAILED"
    assert spy.reserve_and_start.call_count == 0
    assert outcome.evidence["gate_verdict"] == "str"


def test_publication_exactly_one_callback_for_authorized(tmp_path: Path) -> None:
    """An explicit AUTHORIZED verdict admits exactly one publication callback
    through the normal reservation → intent → dispatch → accept path."""
    from arnold_pipelines.megaplan.custody.action_validator import GateResult

    adapter, spy, target = _publication_adapter_spy(
        _make_publication_protocol(tmp_path),
        gate=lambda family, target_key: GateResult.AUTHORIZED,
    )
    outcome, callbacks = _publish_once(adapter, target)
    assert callbacks == 1
    assert outcome.ok is True
    assert outcome.outcome_kind == "COMPLETED"
    assert spy.reserve_and_start.call_count == 1
    assert outcome.glek != ""


def test_publication_adapter_has_no_shadow_pass_allowlist() -> None:
    """T-0017: the publication adapter admits no SHADOW_PASS — the only
    authority decision is the shared adapter_effect_authorized predicate."""
    text = (
        REPO_ROOT / "arnold_pipelines/megaplan/cloud/publication_adapter.py"
    ).read_text(encoding="utf-8")
    assert "SHADOW_PASS" not in text
    assert "adapter_effect_authorized" in text


# ── T-0017 (G4): production construction requires an explicit gate ──────────


def test_publication_production_without_gate_raises_at_construction(
    tmp_path: Path,
) -> None:
    """T-0017: production_enabled=True without an explicit action_gate_check
    is a wiring error — the constructor raises a typed error before any
    dispatch, so an ungated production adapter can never be installed."""
    from arnold_pipelines.megaplan.cloud.publication_adapter import (
        PublicationAdapter,
        PublicationAdapterGateError,
    )

    with pytest.raises(PublicationAdapterGateError) as excinfo:
        PublicationAdapter(
            _make_publication_protocol(tmp_path),
            production_enabled=True,
        )
    assert "action_gate_check" in str(excinfo.value)


def test_publication_production_with_explicit_gate_constructs_and_dispatches(
    tmp_path: Path,
) -> None:
    """T-0017: production_enabled=True with an explicit gate constructs and
    dispatches through the gate exactly like observation mode."""
    from arnold_pipelines.megaplan.cloud.publication_adapter import (
        PublicationAdapter,
        PublicationTarget,
    )
    from arnold_pipelines.megaplan.custody.action_validator import GateResult

    adapter = PublicationAdapter(
        _make_publication_protocol(tmp_path),
        production_enabled=True,
        action_gate_check=lambda family, target_key: GateResult.AUTHORIZED,
    )
    target = PublicationTarget(repo="owner/repo", occurrence_key="prob-1")
    outcome, callbacks = _publish_once(adapter, target)
    assert callbacks == 1
    assert outcome.ok is True
    assert outcome.outcome_kind == "COMPLETED"
    assert outcome.glek != ""


def test_publication_observation_flag_without_gate_fails_closed(
    tmp_path: Path,
) -> None:
    """T-0017: observation-only construction (production_enabled=False) may
    omit the gate — every dispatch still fails closed as a typed denial."""
    from arnold_pipelines.megaplan.cloud.publication_adapter import (
        PublicationAdapter,
        PublicationTarget,
    )

    adapter = PublicationAdapter(
        _make_publication_protocol(tmp_path),
        production_enabled=False,
    )
    target = PublicationTarget(repo="owner/repo", occurrence_key="prob-1")
    outcome, callbacks = _publish_once(adapter, target)
    assert callbacks == 0
    assert outcome.ok is False
    assert outcome.outcome_kind == "FAILED"
    assert outcome.evidence["gate_verdict"] == "missing"


# ── T-0017 (G4): publish_indeterminate closes by default ────────────────────


@pytest.mark.parametrize(
    ("case", "gate", "expected_verdict"),
    [
        ("missing-gate", None, "missing"),
        ("shadow-pass", lambda family, target_key: GateResult.SHADOW_PASS, "shadow_pass"),
        ("blocked-stale-grant", lambda family, target_key: GateResult.BLOCKED_STALE_GRANT, "blocked_stale_grant"),
        ("blocked-stale-epoch", lambda family, target_key: GateResult.BLOCKED_STALE_EPOCH, "blocked_stale_epoch"),
        ("blocked-no-lease", lambda family, target_key: GateResult.BLOCKED_NO_LEASE, "blocked_no_lease"),
        ("blocked-wbc-missing", lambda family, target_key: GateResult.BLOCKED_WBC_MISSING, "blocked_wbc_missing"),
        ("error-verdict", lambda family, target_key: GateResult.ERROR, "error"),
    ],
)
def test_publish_indeterminate_zero_reservations_for_non_authorized(
    tmp_path: Path, case: str, gate: object, expected_verdict: str
) -> None:
    """T-0017(a): publish_indeterminate is gated — every non-AUTHORIZED
    verdict (including a missing gate) is a typed denial with ZERO
    reserve_and_start calls."""
    adapter, spy, target = _publication_adapter_spy(
        _make_publication_protocol(tmp_path),
        gate=gate,
    )
    outcome = adapter.publish_indeterminate(
        target=target,
        action="create",
        reason="Provider unreachable",
    )
    assert outcome.ok is False, case
    assert outcome.outcome_kind == "FAILED", case
    assert outcome.glek == "", case
    assert spy.reserve_and_start.call_count == 0, case
    assert "gate_verdict" in outcome.evidence, case
    assert outcome.evidence["gate_verdict"] == expected_verdict, case


def test_publish_indeterminate_zero_reservations_for_malformed_gate_evidence(
    tmp_path: Path,
) -> None:
    """A stale/foreign value (e.g. a bare string) never authorizes an
    indeterminate publication record."""
    adapter, spy, target = _publication_adapter_spy(
        _make_publication_protocol(tmp_path),
        gate=lambda family, target_key: "authorized",  # stale plain string
    )
    outcome = adapter.publish_indeterminate(
        target=target,
        action="create",
        reason="Provider unreachable",
    )
    assert outcome.ok is False
    assert outcome.outcome_kind == "FAILED"
    assert spy.reserve_and_start.call_count == 0
    assert outcome.evidence["gate_verdict"] == "str"


def test_publish_indeterminate_zero_reservations_when_gate_raises(
    tmp_path: Path,
) -> None:
    """An exceptional gate is a typed denial: no reservation, no record."""
    from arnold_pipelines.megaplan.custody.action_validator import GateResult

    def exploding_gate(family: str, target_key: str) -> GateResult:
        raise RuntimeError("gate exploded")

    adapter, spy, target = _publication_adapter_spy(
        _make_publication_protocol(tmp_path),
        gate=exploding_gate,
    )
    outcome = adapter.publish_indeterminate(
        target=target,
        action="create",
        reason="Provider unreachable",
    )
    assert outcome.ok is False
    assert outcome.outcome_kind == "FAILED"
    assert spy.reserve_and_start.call_count == 0
    assert outcome.evidence["gate_verdict"] == "error"
    assert "gate exploded" in outcome.error


def test_publish_indeterminate_authorized_records_indeterminate(tmp_path: Path) -> None:
    """An explicit AUTHORIZED verdict admits exactly one reservation and
    returns the INDETERMINATE record."""
    from arnold_pipelines.megaplan.custody.action_validator import GateResult

    adapter, spy, target = _publication_adapter_spy(
        _make_publication_protocol(tmp_path),
        gate=lambda family, target_key: GateResult.AUTHORIZED,
    )
    outcome = adapter.publish_indeterminate(
        target=target,
        action="create",
        reason="Provider unreachable",
    )
    assert outcome.ok is False
    assert outcome.outcome_kind == "INDETERMINATE"
    assert spy.reserve_and_start.call_count == 1
    assert outcome.glek != ""
    assert outcome.error == "Provider unreachable"


# ── T-0017 (G4): github_sync fallbacks close by default ─────────────────────


def _publication_problem_projections(*, problem_id: str = "prob-gate-1") -> dict:
    return {
        "problems": {
            "problems": [
                {
                    "problem_id": problem_id,
                    "title": "T-0017 gating problem",
                    "status": "open",
                    "occurrence_count": 2,
                    "recurred_after_fix": False,
                    "owner_actor": "watchdog",
                    "next_review_ts": "2026-08-11T12:00:00Z",
                    "linked_incident_ids": [],
                    "fix_commits": [],
                }
            ]
        },
        "incidents": {"incidents": []},
    }


def test_github_sync_refuses_publication_without_adapter(tmp_path: Path) -> None:
    """T-0017(b)/(G4): a missing gate (no publication adapter) denies the
    whole sync with ZERO filesystem effects — no rebuild_projections, no
    ledger/bridge append, no ledger files — and zero github_cli calls."""
    from unittest.mock import patch

    from arnold_pipelines.megaplan.cloud import github_sync as module
    from arnold_pipelines.megaplan.cloud.github_sync import GitHubSyncConfig

    with patch("arnold_pipelines.megaplan.cloud.github_sync.rebuild_projections") as rebuild:
        with patch(
            "arnold_pipelines.megaplan.cloud.github_sync.append_github_issue_publish_failed"
        ) as append_failed:
            with patch("arnold_pipelines.megaplan.cloud.github_sync.github_cli.create_issue") as create_issue:
                result = module.sync_persistent_problems(
                    config=GitHubSyncConfig(repo="acme/repo", repo_path=tmp_path),
                    root=tmp_path,
                    # No projections: the gate must deny BEFORE
                    # rebuild_projections is even considered.
                )

    assert result["published"] == []
    assert result["skipped"] == []
    assert len(result["failed"]) == 1
    assert "refused" in result["failed"][0]["error"]
    assert "ledger_event_id" not in result["failed"][0]
    rebuild.assert_not_called()
    append_failed.assert_not_called()
    create_issue.assert_not_called()
    assert not (tmp_path / ".megaplan").exists()


@pytest.mark.parametrize(
    ("case", "gate", "expected_verdict"),
    [
        ("shadow-pass", lambda family, target_key: GateResult.SHADOW_PASS, "shadow_pass"),
        ("blocked-no-lease", lambda family, target_key: GateResult.BLOCKED_NO_LEASE, "blocked_no_lease"),
        ("blocked-stale-grant", lambda family, target_key: GateResult.BLOCKED_STALE_GRANT, "blocked_stale_grant"),
    ],
)
def test_github_sync_gate_denial_performs_zero_filesystem_effects(
    tmp_path: Path, case: str, gate: object, expected_verdict: str
) -> None:
    """T-0017(b)/(G4): a non-AUTHORIZED gate verdict (SHADOW_PASS, blocked)
    denies the whole sync with ZERO filesystem effects — no
    rebuild_projections, no ledger/bridge append, no ledger files — and
    zero provider calls."""
    from unittest.mock import Mock, patch

    from arnold_pipelines.megaplan.cloud import github_sync as module
    from arnold_pipelines.megaplan.cloud.github_sync import GitHubSyncConfig
    from arnold_pipelines.megaplan.cloud.publication_adapter import PublicationAdapter

    adapter = PublicationAdapter(Mock(), action_gate_check=gate)
    with patch("arnold_pipelines.megaplan.cloud.github_sync.rebuild_projections") as rebuild:
        with patch(
            "arnold_pipelines.megaplan.cloud.github_sync.append_github_issue_publish_failed"
        ) as append_failed:
            with patch("arnold_pipelines.megaplan.cloud.github_sync.github_cli.create_issue") as create_issue:
                result = module.sync_persistent_problems(
                    config=GitHubSyncConfig(repo="acme/repo", repo_path=tmp_path),
                    root=tmp_path,
                    publication_adapter=adapter,
                )

    assert result["published"] == [], case
    assert result["skipped"] == [], case
    assert len(result["failed"]) == 1, case
    assert "gate" in result["failed"][0]["error"].lower(), case
    assert expected_verdict in result["failed"][0]["error"], case
    assert "ledger_event_id" not in result["failed"][0], case
    rebuild.assert_not_called()
    append_failed.assert_not_called()
    create_issue.assert_not_called()
    assert not (tmp_path / ".megaplan").exists(), case


def test_github_sync_authorized_publication_writes_ledger(tmp_path: Path) -> None:
    """T-0017(b)/(G4): only an AUTHORIZED publication may write — an
    authorized sync whose provider rejects still records the failure in
    the ledger (normal write path preserved)."""
    from unittest.mock import Mock, patch

    from arnold_pipelines.megaplan.cloud import github_sync as module
    from arnold_pipelines.megaplan.cloud.github_sync import GitHubSyncConfig
    from arnold_pipelines.megaplan.cloud.publication_adapter import PublicationAdapter

    protocol = Mock()
    reservation = Mock()
    reservation.global_logical_effect_key = "glek-test-t0017"
    protocol.reserve_and_start.return_value = reservation
    adapter = PublicationAdapter(
        protocol,
        action_gate_check=lambda family, target_key: GateResult.AUTHORIZED,
    )
    with patch("arnold_pipelines.megaplan.cloud.github_sync.github_cli.create_issue") as create_issue:
        create_issue.return_value = {"ok": False, "error": "rate limited"}
        with patch(
            "arnold_pipelines.megaplan.cloud.github_sync.append_github_issue_publish_failed"
        ) as append_failed:
            result = module.sync_persistent_problems(
                config=GitHubSyncConfig(repo="acme/repo", repo_path=tmp_path),
                root=tmp_path,
                projections=_publication_problem_projections(),
                publication_adapter=adapter,
            )

    assert result["published"] == []
    assert len(result["failed"]) == 1
    assert result["failed"][0]["error"] == "rate limited"
    assert "ledger_event_id" in result["failed"][0]
    append_failed.assert_called_once()
    create_issue.assert_called_once()


def test_github_sync_per_publication_gate_denial_writes_nothing(tmp_path: Path) -> None:
    """T-0017(b)/(G4): a per-publication gate denial (sync probe authorized,
    target denied) returns the typed denial with ZERO filesystem effects —
    no ledger/bridge append, no ledger files — even though the sync-level
    pre-flight passed."""
    from unittest.mock import Mock, patch

    from arnold_pipelines.megaplan.cloud import github_sync as module
    from arnold_pipelines.megaplan.cloud.github_sync import GitHubSyncConfig
    from arnold_pipelines.megaplan.cloud.publication_adapter import PublicationAdapter

    def per_target_gate(family: str, target_key: str) -> GateResult:
        if target_key.endswith(":sync"):
            return GateResult.AUTHORIZED
        return GateResult.SHADOW_PASS

    adapter = PublicationAdapter(Mock(), action_gate_check=per_target_gate)
    with patch("arnold_pipelines.megaplan.cloud.github_sync.github_cli.create_issue") as create_issue:
        with patch(
            "arnold_pipelines.megaplan.cloud.github_sync.append_github_issue_publish_failed"
        ) as append_failed:
            result = module.sync_persistent_problems(
                config=GitHubSyncConfig(repo="acme/repo", repo_path=tmp_path),
                root=tmp_path,
                projections=_publication_problem_projections(),
                publication_adapter=adapter,
            )

    assert result["published"] == []
    assert result["skipped"] == []
    assert len(result["failed"]) == 1
    assert "gate" in result["failed"][0]["error"].lower()
    assert "ledger_event_id" not in result["failed"][0]
    append_failed.assert_not_called()
    create_issue.assert_not_called()
    assert not (tmp_path / ".megaplan").exists()


def test_github_sync_main_fails_closed_without_explicit_gate(
    tmp_path: Path, capsys: object
) -> None:
    """T-0017(c): production main() installs no explicit gate — every
    publication is refused, exit 1, zero github_cli calls."""
    from unittest.mock import patch

    from arnold_pipelines.megaplan.cloud import github_sync as module

    with patch(
        "arnold_pipelines.megaplan.cloud.github_sync.rebuild_projections",
        return_value=_publication_problem_projections(),
    ):
        with patch("arnold_pipelines.megaplan.cloud.github_sync.github_cli.create_issue") as create_issue:
            exit_code = module.main(
                ["--repo", "acme/repo", "--repo-path", str(tmp_path), "--root", str(tmp_path)]
            )

    out, _ = capsys.readouterr()
    assert exit_code == 1
    payload = json.loads(out)
    assert payload["repo"] == "acme/repo"
    assert payload["published"] == []
    assert len(payload["failed"]) == 1
    assert "refused" in payload["failed"][0]["error"]
    create_issue.assert_not_called()


def test_github_sync_has_no_ungated_direct_github_fallback() -> None:
    """T-0017(b): the direct github_cli fallbacks are gone — publication
    without an adapter is a typed refusal, never a provider call."""
    text = (REPO_ROOT / "arnold_pipelines/megaplan/cloud/github_sync.py").read_text(
        encoding="utf-8"
    )
    assert "_create_issue_with_label_fallback" not in text
    assert "_retry_labels_after_missing_label_error" not in text
    assert "_publication_refusal" in text
    assert "no ungated publication path" in text
