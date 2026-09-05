from __future__ import annotations

import hashlib
from pathlib import Path

from arnold.runtime.durable_ops import (
    FileBackedDurableOpsStore,
    LaunchEnvelope,
    LaunchResult,
    ResourceType,
    TypedResource,
    inspect_launch,
    launch_transaction,
    reconcile_launch,
)


class _Preflight:
    accepted = True

    def __init__(self, digest: str = "sha256:preflight") -> None:
        self.preflight_digest = digest


def _envelope(operation_id: str, request_id: str) -> LaunchEnvelope:
    return LaunchEnvelope(
        version=1,
        operation_id=operation_id,
        request_id=request_id,
        venue="local",
        launch_spec={
            "command": ["python", "worker"],
            "process_session_identity": f"process:{operation_id}",
            "expected_session_name": f"session:{operation_id}",
        },
        preflight_digest="sha256:preflight",
    )


def _observation(envelope: LaunchEnvelope) -> dict[str, str]:
    return {
        "operation_id": envelope.operation_id,
        "request_id": envelope.request_id,
        "envelope_digest": envelope.digest,
        "process_session_identity": envelope.launch_spec["process_session_identity"],
        "session_name": envelope.launch_spec["expected_session_name"],
        "liveness": "running",
    }


def _resource(envelope: LaunchEnvelope, observation: dict[str, str]) -> TypedResource:
    return TypedResource(
        id=f"launch-process-session:{envelope.operation_id}:{envelope.request_id}",
        operation_id=envelope.operation_id,
        resource_type=ResourceType.PROCESS_SESSION,
        name=observation["session_name"],
        details=dict(observation),
    )


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file():
            digest.update(str(path.relative_to(root)).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def test_inspection_is_read_only_and_has_no_dispatch_or_store_write(tmp_path: Path) -> None:
    store = FileBackedDurableOpsStore(tmp_path / "ops")
    envelope = _envelope("inspect-op", "inspect-request")
    store.admit_launch(envelope)
    before = _tree_digest(tmp_path)
    writes = 0

    def forbidden_write(_: object) -> None:
        nonlocal writes
        writes += 1
        raise AssertionError("inspection must not write")

    store._write_data = forbidden_write  # type: ignore[method-assign]
    inspection = inspect_launch(
        envelope,
        store=store,
        observe=lambda resource, candidate: _observation(candidate),
    )

    assert inspection.result is LaunchResult.UNKNOWN
    assert writes == 0
    assert _tree_digest(tmp_path) == before


def test_combined_restart_replay_rejects_pending_and_accepts_exact_unknown_once(tmp_path: Path) -> None:
    store_root = tmp_path / "ops"
    store = FileBackedDurableOpsStore(store_root)
    rejected = _envelope("rejected-op", "rejected-request")
    pending = _envelope("pending-op", "pending-request")
    uncertain = _envelope("uncertain-op", "uncertain-request")
    dispatches = {"rejected": 0, "uncertain": 0}

    rejected_result = launch_transaction(
        rejected,
        store=store,
        preflight=type("RejectedPreflight", (), {"accepted": False, "preflight_digest": "sha256:preflight"})(),
        dispatch=lambda _: dispatches.__setitem__("rejected", dispatches["rejected"] + 1),
        observe=lambda value, candidate: _observation(candidate),
        resource_factory=lambda value, observation, candidate: _resource(candidate, dict(observation)),
    )
    assert rejected_result.result is LaunchResult.REJECTED
    assert all(run.id != rejected.operation_id for run in store.list_operation_runs())
    store.admit_launch(pending)

    def uncertain_dispatch(_: LaunchEnvelope) -> object:
        dispatches["uncertain"] += 1
        return object()

    uncertain_result = launch_transaction(
        uncertain,
        store=store,
        preflight=_Preflight(),
        dispatch=uncertain_dispatch,
        observe=lambda value, candidate: (_ for _ in ()).throw(RuntimeError("ack lost")),
        resource_factory=lambda value, observation, candidate: _resource(candidate, dict(observation)),
    )
    assert uncertain_result.result is LaunchResult.UNKNOWN
    assert dispatches == {"rejected": 0, "uncertain": 1}

    reopened = FileBackedDurableOpsStore(store_root)
    assert inspect_launch(rejected, store=reopened).result is LaunchResult.REJECTED
    assert inspect_launch(pending, store=reopened).result is LaunchResult.UNKNOWN
    assert inspect_launch(uncertain, store=reopened).result is LaunchResult.UNKNOWN

    reconciled = reconcile_launch(
        uncertain,
        store=reopened,
        observe=lambda resource, candidate: _observation(candidate),
        resource_factory=lambda value, observation, candidate: _resource(candidate, dict(observation)),
    )
    assert reconciled.result is LaunchResult.ACCEPTED
    assert dispatches == {"rejected": 0, "uncertain": 1}
    assert len(reopened.list_operation_events(uncertain.operation_id)) == 2
    assert len(reopened.list_typed_resources(uncertain.operation_id)) == 1
    assert reopened.load_operation_run(uncertain.operation_id).state.value == "running"
    accepted_resource = reopened.list_typed_resources(uncertain.operation_id)[0]
    assert accepted_resource.details["owner"] == uncertain.venue
    accepted_event = reopened.list_operation_events(uncertain.operation_id)[-1]
    assert accepted_event.payload["owner"] == uncertain.venue

    replay = reconcile_launch(
        uncertain,
        store=FileBackedDurableOpsStore(store_root),
        observe=lambda: (_ for _ in ()).throw(AssertionError("accepted replay must not query or launch")),
    )
    assert replay.result is LaunchResult.ACCEPTED
    assert dispatches == {"rejected": 0, "uncertain": 1}


def test_reconcile_requires_exact_identity_and_never_accepts_dead_or_wrong_process(tmp_path: Path) -> None:
    store = FileBackedDurableOpsStore(tmp_path / "ops")
    envelope = _envelope("identity-op", "identity-request")
    store.admit_launch(envelope)

    wrong = _observation(envelope)
    wrong["process_session_identity"] = "foreign-process"
    result = reconcile_launch(envelope, store=store, observe=lambda *_: wrong)
    assert result.result is LaunchResult.CONFLICT
    assert store.load_operation_run(envelope.operation_id).state.value == "pending"

    dead = _observation(envelope)
    dead["liveness"] = "dead"
    result = reconcile_launch(envelope, store=store, observe=lambda *_: dead)
    assert result.result is LaunchResult.UNKNOWN
    assert store.list_typed_resources(envelope.operation_id) == ()
