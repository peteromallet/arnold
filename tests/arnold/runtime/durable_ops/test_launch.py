from __future__ import annotations

from dataclasses import fields
import ast
import importlib
import inspect
from pathlib import Path

import pytest

from arnold.runtime.durable_ops.launch import (
    LAUNCH_ENVELOPE_FIELDS,
    LAUNCH_ENVELOPE_VERSION,
    LAUNCH_SPEC_FIELDS,
    LaunchEnvelope,
    LaunchEnvelopeError,
    LaunchReason,
    LaunchResult,
    canonical_launch_envelope,
    evaluate_launch_request,
    launch_envelope_digest,
    launch_once,
)


def _envelope(**overrides: object) -> LaunchEnvelope:
    values: dict[str, object] = {
        "version": LAUNCH_ENVELOPE_VERSION,
        "operation_id": "operation-1",
        "request_id": "request-1",
        "venue": "local",
        "launch_spec": {
            "command": ["python", "-m", "worker"],
            "cwd": "/tmp/worktree",
        },
        "preflight_digest": "sha256:preflight-1",
    }
    values.update(overrides)
    return LaunchEnvelope(**values)  # type: ignore[arg-type]


def test_launch_envelope_has_exactly_six_immutable_top_level_fields() -> None:
    assert tuple(field.name for field in fields(LaunchEnvelope)) == LAUNCH_ENVELOPE_FIELDS
    envelope = _envelope()
    assert tuple(envelope.to_json()) == LAUNCH_ENVELOPE_FIELDS
    assert "digest" not in envelope.to_json()
    with pytest.raises(TypeError):
        envelope.launch_spec["new"] = "mutation"  # type: ignore[index]


def test_launch_envelope_canonical_round_trip_and_digest_are_deterministic() -> None:
    original = _envelope()
    reordered = _envelope(
        launch_spec={
            "cwd": "/tmp/worktree",
            "command": ["python", "-m", "worker"],
        }
    )

    assert canonical_launch_envelope(original) == canonical_launch_envelope(reordered)
    assert launch_envelope_digest(original) == launch_envelope_digest(reordered)
    assert LaunchEnvelope.from_json(original.to_json()) == original

    changed = _envelope(launch_spec={"command": ["python", "-m", "other"]})
    assert launch_envelope_digest(changed) != launch_envelope_digest(original)


@pytest.mark.parametrize(
    ("payload_change", "reason"),
    [
        ({"version": 999}, LaunchReason.UNKNOWN_VERSION),
        ({"operation_id": "other-operation"}, LaunchReason.OPERATION_MISMATCH),
        ({"preflight_digest": "sha256:tampered"}, LaunchReason.PREFLIGHT_MISMATCH),
    ],
)
def test_identity_validation_rejects_before_admission(
    payload_change: dict[str, object], reason: LaunchReason
) -> None:
    payload = _envelope().to_json()
    payload.update(payload_change)
    calls: list[LaunchEnvelope] = []

    decision = launch_once(
        payload,
        calls.append,
        operation_id="operation-1",
        preflight_digest="sha256:preflight-1",
    )

    assert decision.result is LaunchResult.REJECTED
    assert decision.reason is reason
    assert calls == []


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"version": 1},
        {"version": 1, "operation_id": "op", "request_id": "req", "venue": "local", "launch_spec": {}, "preflight_digest": "p", "extra": True},
        "not-json",
    ],
)
def test_malformed_envelope_is_rejected_without_dispatch(payload: object) -> None:
    calls: list[LaunchEnvelope] = []
    decision = launch_once(
        payload,  # type: ignore[arg-type]
        calls.append,
        operation_id="operation-1",
        preflight_digest="sha256:preflight-1",
    )
    assert decision.result is LaunchResult.REJECTED
    assert decision.reason is LaunchReason.MALFORMED
    assert calls == []


def test_unknown_version_is_rejected_by_strict_decoder() -> None:
    payload = _envelope().to_json()
    payload["version"] = 2
    with pytest.raises(LaunchEnvelopeError):
        LaunchEnvelope.from_json(payload)


@pytest.mark.parametrize(
    "legacy_authority_field",
    (
        "ledger_root",
        "projection_key",
        "expected_projection_version",
        "parent_logical_dispatch_id",
        "authorizing_event_id",
        "parent_terminal_event_id",
        "parent_source_spec",
        "transition_kind",
        "precondition_identity",
        "changed_precondition_event_id",
    ),
)
def test_legacy_ledger_authority_is_not_launch_identity(legacy_authority_field: str) -> None:
    with pytest.raises(LaunchEnvelopeError, match="unknown launch_spec fields"):
        _envelope(launch_spec={legacy_authority_field: "legacy"})


def test_exact_replay_returns_authoritative_result_without_dispatch() -> None:
    envelope = _envelope()
    calls: list[LaunchEnvelope] = []
    decision = launch_once(
        envelope,
        calls.append,
        operation_id="operation-1",
        preflight_digest="sha256:preflight-1",
        existing=envelope,
        authoritative_result=LaunchResult.UNKNOWN,
    )
    assert decision.result is LaunchResult.UNKNOWN
    assert decision.reason is LaunchReason.REPLAY
    assert calls == []


def test_divergent_request_id_reuse_is_conflict_without_dispatch() -> None:
    envelope = _envelope()
    divergent = _envelope(request_id="request-2")
    calls: list[LaunchEnvelope] = []
    decision = launch_once(
        divergent,
        calls.append,
        operation_id="operation-1",
        preflight_digest="sha256:preflight-1",
        existing=envelope,
    )
    assert decision.result is LaunchResult.CONFLICT
    assert decision.reason is LaunchReason.REQUEST_CONFLICT
    assert calls == []


def test_dispatch_success_and_uncertainty_use_only_bounded_results() -> None:
    envelope = _envelope()
    assert launch_once(
        envelope,
        lambda _: None,
        operation_id="operation-1",
        preflight_digest="sha256:preflight-1",
    ).result is LaunchResult.ACCEPTED

    def uncertain(_: LaunchEnvelope) -> None:
        raise RuntimeError("transport unavailable")

    decision = launch_once(
        envelope,
        uncertain,
        operation_id="operation-1",
        preflight_digest="sha256:preflight-1",
    )
    assert decision.result is LaunchResult.UNKNOWN
    assert decision.reason is LaunchReason.DISPATCH_UNCERTAIN
    assert {result.value for result in LaunchResult} == {
        "ACCEPTED",
        "REJECTED",
        "UNKNOWN",
        "CONFLICT",
    }


@pytest.mark.parametrize(
    ("consumer", "members"),
    [
        ("agentbox.host.launch_host", ("command", "repo_names", "base_refs", "cwd", "metadata", "lock_timeout_seconds")),
        ("arnold_pipelines.megaplan.agentbox_adapter.MegaplanChainHandler.launch", ("repo_name", "spec_path", "base_ref", "metadata", "lock_timeout_seconds")),
    ],
)
def test_launch_spec_members_are_current_agentbox_consumer_arguments(
    consumer: str, members: tuple[str, ...]
) -> None:
    parts = consumer.split(".")
    for split in range(len(parts), 0, -1):
        try:
            module = importlib.import_module(".".join(parts[:split]))
        except ModuleNotFoundError:
            continue
        target = module
        for attribute in parts[split:]:
            target = getattr(target, attribute)
        break
    else:  # pragma: no cover - the parameter list names real consumers
        raise AssertionError(f"cannot import consumer {consumer}")
    if inspect.isclass(target):
        target = target.launch
    parameters = inspect.signature(target).parameters
    assert set(members).issubset(parameters)


def test_cloud_dispatch_launch_spec_members_are_named_by_current_request() -> None:
    source_path = Path("arnold_pipelines/megaplan/cloud/worker_dispatch.py")
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    request = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "WorkerAdmissionRequest"
    )
    request_fields = {
        node.target.id
        for node in request.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    }
    for member in {
        "plan_id",
        "phase",
        "dispatch_family_id",
        "logical_dispatch_id",
        "physical_door_id",
        "configured_spec",
        "selected_spec",
        "source_revision",
        "runtime_vector",
        "manifest_identity",
        "seed_identity",
        "dependency_interpreter_identity",
        "prompt_or_phase_input_identity",
        "configured_fallback_chain_identity",
        "authorized_route_identity",
        "configured_fallback_specs",
        "timeout_budget_s",
        "production_intent",
    }:
        assert member in request_fields


@pytest.mark.parametrize("member", sorted(LAUNCH_SPEC_FIELDS))
def test_every_launch_spec_member_is_owned_by_a_current_consumer(member: str) -> None:
    host_consumers = (
        "agentbox.host.launch_host",
        "arnold_pipelines.megaplan.agentbox_adapter.MegaplanChainHandler.launch",
    )
    parameters: set[str] = set()
    for consumer in host_consumers:
        parts = consumer.split(".")
        for split in range(len(parts), 0, -1):
            try:
                module = importlib.import_module(".".join(parts[:split]))
            except ModuleNotFoundError:
                continue
            target = module
            for attribute in parts[split:]:
                target = getattr(target, attribute)
            if inspect.isclass(target):
                target = target.launch
            parameters.update(inspect.signature(target).parameters)
            break

    source_path = Path("arnold_pipelines/megaplan/cloud/worker_dispatch.py")
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    request = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "WorkerAdmissionRequest"
    )
    cloud_fields = {
        node.target.id
        for node in request.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    }
    # The process resource identifier is derived by the co-located durable
    # store from the envelope; no venue adapter owns a caller-facing argument.
    assert member in parameters or member in cloud_fields or member == "process_resource_id"
