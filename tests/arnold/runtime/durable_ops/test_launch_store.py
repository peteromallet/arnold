from __future__ import annotations

import copy
from pathlib import Path

import pytest

from arnold.runtime.durable_ops import (
    FileBackedDurableOpsStore,
    OperationState,
    ResourceType,
    TypedResource,
)
from arnold.runtime.durable_ops.launch import LaunchEnvelope, LaunchReason, LaunchResult


def _envelope(request_id: str = "request-1", **spec: object) -> LaunchEnvelope:
    launch_spec: dict[str, object] = {"command": ["python", "worker"]}
    launch_spec.update(spec)
    return LaunchEnvelope(
        version=1,
        operation_id="operation-1",
        request_id=request_id,
        venue="local",
        launch_spec=launch_spec,
        preflight_digest="sha256:preflight",
    )


def _resource(resource_id: str = "session-1", **details: object) -> TypedResource:
    return TypedResource(
        id=resource_id,
        operation_id="operation-1",
        resource_type=ResourceType.PROCESS_SESSION,
        name="worker-session",
        details={"pid": 42, **details},
    )


def _admit(store: FileBackedDurableOpsStore, envelope: LaunchEnvelope | None = None) -> None:
    result = store.admit_launch(envelope or _envelope())
    assert result.result is LaunchResult.ACCEPTED
    assert result.operation.state is OperationState.PENDING


def test_admission_is_one_identity_event_and_exact_replay_is_a_noop(tmp_path: Path) -> None:
    store = FileBackedDurableOpsStore(tmp_path)
    envelope = _envelope()
    first = store.admit_launch(envelope)
    assert first.reason is LaunchReason.ADMITTED
    assert first.operation.state is OperationState.PENDING
    assert [event.event_type for event in store.list_operation_events(envelope.operation_id)] == [
        "launch.admitted"
    ]

    writes = 0
    original_write = store._write_data

    def count_write(data: object) -> None:
        nonlocal writes
        writes += 1
        original_write(data)  # type: ignore[arg-type]

    store._write_data = count_write  # type: ignore[method-assign]
    replay = store.admit_launch(envelope)
    assert replay.result is LaunchResult.ACCEPTED
    assert replay.reason is LaunchReason.REPLAY
    assert writes == 0

    conflict = store.admit_launch(_envelope(request_id="request-2"))
    assert conflict.result is LaunchResult.CONFLICT
    assert len(store.list_operation_events(envelope.operation_id)) == 1


def test_acceptance_is_one_composite_write_and_exact_replay_is_a_noop(tmp_path: Path) -> None:
    store = FileBackedDurableOpsStore(tmp_path)
    envelope = _envelope()
    _admit(store, envelope)
    resource = _resource()
    accepted = store.accept_launch(
        envelope,
        process_resource=resource,
        owner="alice",
        owner_evidence={"owner": "alice", "source": "session-query"},
    )
    assert accepted.result is LaunchResult.ACCEPTED
    assert accepted.operation.state is OperationState.RUNNING
    assert accepted.process_resource is not None
    assert accepted.process_resource.id == "launch-process-session:operation-1:request-1"
    assert len(store.list_operation_events(envelope.operation_id)) == 2
    assert len(store.list_typed_resources(envelope.operation_id)) == 1

    writes = 0
    original_write = store._write_data

    def count_write(data: object) -> None:
        nonlocal writes
        writes += 1
        original_write(data)  # type: ignore[arg-type]

    store._write_data = count_write  # type: ignore[method-assign]
    replay = store.accept_launch(
        envelope,
        process_resource=resource,
        owner="alice",
        owner_evidence={"owner": "alice", "source": "session-query"},
    )
    assert replay.result is LaunchResult.ACCEPTED
    assert replay.reason is LaunchReason.REPLAY
    assert writes == 0

    conflict = store.accept_launch(
        envelope,
        process_resource=_resource(pid=99),
        owner="alice",
        owner_evidence={"owner": "alice", "source": "session-query"},
    )
    assert conflict.result is LaunchResult.CONFLICT
    assert len(store.list_operation_events(envelope.operation_id)) == 2


def test_pre_replacement_acceptance_fault_leaves_pending_without_facts(tmp_path: Path) -> None:
    store = FileBackedDurableOpsStore(tmp_path)
    envelope = _envelope()
    _admit(store, envelope)

    def fail_before_write(_: object) -> None:
        raise OSError("before replacement")

    store._write_data = fail_before_write  # type: ignore[method-assign]
    with pytest.raises(OSError, match="before replacement"):
        store.accept_launch(
            envelope,
            process_resource=_resource(),
            owner="alice",
            owner_evidence={"owner": "alice"},
        )
    assert store.load_operation_run(envelope.operation_id).state is OperationState.PENDING
    assert len(store.list_operation_events(envelope.operation_id)) == 1
    assert store.list_typed_resources(envelope.operation_id) == ()


def test_post_replacement_acceptance_fault_reads_back_canonical_result(tmp_path: Path) -> None:
    store = FileBackedDurableOpsStore(tmp_path)
    envelope = _envelope()
    _admit(store, envelope)
    original_write = store._write_data

    def replace_then_fail(data: object) -> None:
        original_write(data)  # type: ignore[arg-type]
        raise OSError("commit unknown")

    store._write_data = replace_then_fail  # type: ignore[method-assign]
    result = store.accept_launch(
        envelope,
        process_resource=_resource(),
        owner="alice",
        owner_evidence={"owner": "alice"},
    )
    assert result.result is LaunchResult.ACCEPTED
    assert result.reason is LaunchReason.REPLAY
    assert result.operation.state is OperationState.RUNNING
    assert len(store.list_operation_events(envelope.operation_id)) == 2
    assert len(store.list_typed_resources(envelope.operation_id)) == 1


def test_partial_commit_unknown_is_completed_by_exact_acceptance_replay(tmp_path: Path) -> None:
    store = FileBackedDurableOpsStore(tmp_path)
    envelope = _envelope()
    _admit(store, envelope)
    pending_data = store._read_data()
    original_write = store._write_data

    def write_event_only(data: object) -> None:
        partial = copy.deepcopy(data)
        partial["operation_runs"] = copy.deepcopy(pending_data["operation_runs"])  # type: ignore[index]
        partial["typed_resources"] = {}  # type: ignore[index]
        original_write(partial)  # type: ignore[arg-type]
        raise OSError("commit unknown after acceptance event")

    store._write_data = write_event_only  # type: ignore[method-assign]
    uncertain = store.accept_launch(
        envelope,
        process_resource=_resource(),
        owner="alice",
        owner_evidence={"owner": "alice"},
    )
    assert uncertain.result is LaunchResult.UNKNOWN
    assert store.load_operation_run(envelope.operation_id).state is OperationState.PENDING

    store._write_data = original_write  # type: ignore[method-assign]
    reconciled = store.accept_launch(
        envelope,
        process_resource=_resource(),
        owner="alice",
        owner_evidence={"owner": "alice"},
    )
    assert reconciled.result is LaunchResult.ACCEPTED
    assert reconciled.operation.state is OperationState.RUNNING
    assert len(store.list_operation_events(envelope.operation_id)) == 2
    assert len(store.list_typed_resources(envelope.operation_id)) == 1
