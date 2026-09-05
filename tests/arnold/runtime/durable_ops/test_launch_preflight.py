from __future__ import annotations

import json
from pathlib import Path

import pytest

from arnold.runtime.durable_ops.launch_preflight import (
    PREFLIGHT_SECTIONS,
    PreflightResult,
    read_only_capacity_observation,
    run_launch_preflight,
)
from arnold.runtime.durable_ops.launch import (
    LaunchEnvelope,
    LaunchResult,
    evaluate_launch_request,
)


def _observations() -> dict[str, dict[str, object]]:
    return {
        "source": {"status": "valid", "revision": "a" * 40, "ref": "main", "tree": "b" * 40},
        "authority": {"status": "current", "grant": "grant-1", "fence": "fence-1", "decision": "allow"},
        "custody": {"status": "present", "custody_ref": "custody-1", "wbc_ref": "wbc-1"},
        "credentials": {"status": "available", "identity": "credential-1", "transport": "ssh"},
        "runtime": {"status": "valid", "interpreter": "/opt/python", "import_root": "/opt/arnold", "source_revision": "a" * 40},
        "command": {"status": "valid", "argv": ["python", "-m", "worker"], "cwd": "/workspace", "env": {}},
        "namespace": {"status": "valid", "name": "worker-1"},
        "collision": {"status": "clear", "request": None, "session": None, "process": None},
        "capacity": {"status": "available", "disk": 100, "inode": 100, "output": 10, "temp": 100},
        "network": {"status": "available", "transport": "ssh", "host": "example.invalid"},
    }


def test_complete_preflight_is_immutable_and_deterministic() -> None:
    spec = {"cwd": "/workspace", "command": ["python", "-m", "worker"]}
    observations = _observations()
    first = run_launch_preflight(spec, observations)
    reordered = run_launch_preflight(
        dict(reversed(list(spec.items()))),
        {key: observations[key] for key in reversed(PREFLIGHT_SECTIONS)},
    )

    assert first.result is PreflightResult.ACCEPTED
    assert first.preflight_digest == reordered.preflight_digest
    assert json.loads(first.canonical_json())["result"] == "ACCEPTED"
    assert first.to_json()["preflight_digest"].startswith("sha256:")


def test_accepted_preflight_digest_is_the_envelope_admission_identity() -> None:
    report = run_launch_preflight(
        {"command": ["python", "-m", "worker"], "cwd": "/workspace"},
        _observations(),
    )
    assert report.accepted
    envelope = LaunchEnvelope(
        version=1,
        operation_id="operation-1",
        request_id="request-1",
        venue="local",
        launch_spec=report.launch_spec,
        preflight_digest=report.preflight_digest,
    )
    decision = evaluate_launch_request(
        envelope,
        operation_id="operation-1",
        preflight_digest=report.preflight_digest,
    )
    assert decision.result is LaunchResult.ACCEPTED


def test_credentialless_local_preflight_accepts_explicit_not_applicable() -> None:
    observations = _observations()
    observations["credentials"] = {
        "status": "not_applicable",
        "identity": "credentialless_local",
        "transport": "local",
    }
    report = run_launch_preflight({"command": ["local-process"], "cwd": "/workspace"}, observations)
    assert report.result is PreflightResult.ACCEPTED


def test_missing_or_unknown_prerequisite_rejects_without_effects() -> None:
    observations = _observations()
    observations.pop("wbc", None)
    observations["network"] = {"status": "unknown"}
    report = run_launch_preflight({"command": ["worker"]}, observations)

    assert report.result is PreflightResult.REJECTED
    assert "network:unknown" in report.failures
    assert report.preflight_digest.startswith("sha256:")


@pytest.mark.parametrize(
    ("section", "status", "expected"),
    [
        (section, status, PreflightResult.ACCEPTED if section == "collision" else PreflightResult.REJECTED)
        for section in PREFLIGHT_SECTIONS
        for status in ("none", "not_found")
    ]
    + [
        (section, observations[section]["status"], PreflightResult.ACCEPTED)
        for section, observations in [(section, _observations()) for section in PREFLIGHT_SECTIONS]
    ],
)
def test_section_status_matrix_fails_closed_except_for_collision_absence(
    section: str,
    status: str,
    expected: PreflightResult,
) -> None:
    observations = _observations()
    observations[section]["status"] = status

    report = run_launch_preflight({"command": ["worker"]}, observations)

    assert report.result is expected


def test_capacity_observation_reads_only(tmp_path: Path) -> None:
    before = sorted(path.name for path in tmp_path.iterdir())
    result = read_only_capacity_observation(tmp_path, output_bound_bytes=1, temp_path=tmp_path)
    after = sorted(path.name for path in tmp_path.iterdir())

    assert result["status"] == "available"
    assert result["output_bound_proven"] is True
    assert before == after == []
