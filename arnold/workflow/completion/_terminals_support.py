"""Private fixture-shape helpers for terminal closure evaluation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

def _fixture_manifest_sets(fixture: Mapping[str, Any]) -> tuple[tuple[Any, ...], tuple[Any, ...], bool]:
    capture = fixture.get("capture") if isinstance(fixture.get("capture"), Mapping) else fixture
    expected = _first_sequence(capture, "expected_manifest_ids", "expected_manifests", "required_manifests", "expected_set")
    captured = _first_sequence(capture, "captured_manifest_ids", "captured_manifests", "observed_manifest_ids", "present_manifests", "captured_set")
    if not expected and isinstance(capture.get("manifest_range"), Sequence):
        bounds = tuple(capture["manifest_range"])
        if len(bounds) == 2:
            expected = tuple(range(int(bounds[0]), int(bounds[1]) + 1))
    complete = bool(capture.get("complete_capture", capture.get("capture_complete", True)))
    return expected, captured, complete


def _fixture_attempts(fixture: Mapping[str, Any]) -> tuple[tuple[str, ...], set[str]]:
    raw = fixture.get("accepted_attempts", fixture.get("accepted_attempt_ids", ()))
    accepted: set[str] = set()
    if isinstance(raw, Mapping):
        for task, value in raw.items():
            if _is_accepted_attempt(value):
                accepted.add(str(task))
    elif isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
        accepted.update(_accepted_sequence(raw))
    required_raw = _first_sequence(fixture, "required_tasks", "task_ids", "subjects")
    dependencies = _fixture_dependencies(fixture)
    required = tuple(dict.fromkeys(str(item) for item in (*required_raw, *dependencies.keys())))
    return required, accepted


def _fixture_dependencies(fixture: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
    raw = fixture.get("dependency_closure", fixture.get("dependencies", {}))
    if not isinstance(raw, Mapping):
        return {}
    result: dict[str, tuple[str, ...]] = {}
    for task, deps in raw.items():
        result[str(task)] = tuple(str(item) for item in deps) if isinstance(deps, Sequence) and not isinstance(deps, (str, bytes)) else ()
    return result


def _closure_cause(missing: tuple[str, ...], unresolved: tuple[str, ...]) -> str:
    return f"no-accepted-attempt:{missing[0]}" if missing else f"dependency-unresolved:{unresolved[0]}"


def _closure_task(missing: tuple[str, ...], unresolved: tuple[str, ...]) -> str:
    if missing:
        return missing[0]
    return unresolved[0].split("->", 1)[0]


def _accepted_sequence(raw: Sequence[Any]) -> set[str]:
    accepted: set[str] = set()
    for item in raw:
        if isinstance(item, Mapping):
            task = item.get("task_id", item.get("subject_id", item.get("id")))
            if task is not None and _is_accepted_attempt(item):
                accepted.add(str(task))
        elif item is not None:
            accepted.add(str(item))
    return accepted


def _first_sequence(mapping: Mapping[str, Any], *keys: str) -> tuple[Any, ...]:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            return tuple(value)
    return ()


def _is_accepted_attempt(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, Mapping):
        if value.get("accepted") is True:
            return True
        return str(value.get("outcome", value.get("status", ""))).lower() in {"accepted", "done", "completed"}
    return bool(value)

