"""Named-exit supersession terminals with complete custody metadata.

Named exits are shadow-only records.  They can describe a supersession but
cannot accept, complete, or otherwise authorize a completion claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from arnold.workflow.completion.hashing import hash_canonical
from arnold.workflow.completion.outcomes import CandidateOutcome


def _sequence(value: Any, field: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise TypeError(f"NamedExit.{field} must be an ordered sequence")
    return tuple(str(item) for item in value)


def _named_exit_hash_payload(
    exit_name: str,
    target_loop_id: str,
    source_declaration_ref: str,
    intervening_bindings: tuple[str, ...],
    ordered_unwind_set: tuple[str, ...],
    superseded_spec_hashes: tuple[str, ...],
    previous_exit_hash: str,
) -> dict[str, Any]:
    """Build the complete content-addressed identity payload for a named exit."""
    return {
        "exit_name": exit_name,
        "target_loop_id": target_loop_id,
        "source_declaration_ref": source_declaration_ref,
        "intervening_bindings": list(intervening_bindings),
        "ordered_unwind_set": list(ordered_unwind_set),
        "superseded_spec_hashes": list(superseded_spec_hashes),
        "previous_exit_hash": previous_exit_hash,
    }


def compute_exit_hash(
    exit_name: str,
    target_loop_id: str,
    source_declaration_ref: str,
    intervening_bindings: tuple[str, ...],
    ordered_unwind_set: tuple[str, ...],
    superseded_spec_hashes: tuple[str, ...] = (),
    previous_exit_hash: str = "",
) -> str:
    """Compute a hash over every custody-bearing field of a named exit."""
    return hash_canonical(
        _named_exit_hash_payload(
            exit_name,
            target_loop_id,
            source_declaration_ref,
            intervening_bindings,
            ordered_unwind_set,
            superseded_spec_hashes,
            previous_exit_hash,
        )
    )


@dataclass(frozen=True)
class NamedExit:
    """A supersession record that carries complete unwind custody.

    No field may be omitted: an exit name alone cannot explain what loop was
    exited, where the claim originated, which bindings were crossed, or which
    occurrences were unwound.  The ordered collections are part of identity,
    not merely diagnostic annotations.
    """

    exit_name: str
    target_loop_id: str
    source_declaration_ref: str
    intervening_bindings: tuple[str, ...]
    """Binding hashes, each in ``sha256:`` + 64-hex format."""

    ordered_unwind_set: tuple[str, ...]
    superseded_spec_hashes: tuple[str, ...] = ()
    """Superseded spec hashes, each in ``sha256:`` + 64-hex format."""

    exit_hash: str = ""
    """This exit's content hash in ``sha256:`` + 64-hex format."""

    previous_exit_hash: str = ""
    """Prior exit-chain hash in ``sha256:`` + 64-hex format, or empty at genesis."""

    def __post_init__(self) -> None:
        required_values = {
            "exit_name": self.exit_name,
            "target_loop_id": self.target_loop_id,
            "source_declaration_ref": self.source_declaration_ref,
        }
        for field_name, value in required_values.items():
            if not value:
                raise ValueError(f"NamedExit.{field_name} must be non-empty")
        intervening_bindings = _sequence(self.intervening_bindings, "intervening_bindings")
        ordered_unwind_set = _sequence(self.ordered_unwind_set, "ordered_unwind_set")
        superseded_spec_hashes = _sequence(self.superseded_spec_hashes, "superseded_spec_hashes")
        object.__setattr__(self, "intervening_bindings", intervening_bindings)
        object.__setattr__(self, "ordered_unwind_set", ordered_unwind_set)
        object.__setattr__(self, "superseded_spec_hashes", superseded_spec_hashes)
        if not self.intervening_bindings:
            raise ValueError("NamedExit.intervening_bindings must be non-empty")
        if not self.ordered_unwind_set:
            raise ValueError("NamedExit.ordered_unwind_set must be non-empty")
        if any(not binding for binding in self.intervening_bindings):
            raise ValueError("NamedExit.intervening_bindings cannot contain empty hashes")
        if any(not instance for instance in self.ordered_unwind_set):
            raise ValueError("NamedExit.ordered_unwind_set cannot contain empty instances")
        if len(set(self.ordered_unwind_set)) != len(self.ordered_unwind_set):
            raise ValueError("NamedExit.ordered_unwind_set cannot contain duplicates")
        if len(self.ordered_unwind_set) != len(self.intervening_bindings):
            raise ValueError("NamedExit.ordered_unwind_set must cover every intervening binding")
        if any(not value for value in self.superseded_spec_hashes):
            raise ValueError("NamedExit.superseded_spec_hashes cannot contain empty hashes")
        if not self.exit_hash:
            object.__setattr__(
                self,
                "exit_hash",
                compute_exit_hash(
                    self.exit_name,
                    self.target_loop_id,
                    self.source_declaration_ref,
                    self.intervening_bindings,
                    self.ordered_unwind_set,
                    self.superseded_spec_hashes,
                    self.previous_exit_hash,
                ),
            )
        if not self.exit_hash.startswith("sha256:"):
            raise ValueError("NamedExit.exit_hash must start with 'sha256:'")
        expected_hash = compute_exit_hash(
            self.exit_name,
            self.target_loop_id,
            self.source_declaration_ref,
            self.intervening_bindings,
            self.ordered_unwind_set,
            self.superseded_spec_hashes,
            self.previous_exit_hash,
        )
        if self.exit_hash != expected_hash:
            raise ValueError("NamedExit exit_hash mismatch")

    def to_dict(self) -> dict[str, Any]:
        """Return a complete deterministic representation."""
        return {
            "exit_name": self.exit_name,
            "target_loop_id": self.target_loop_id,
            "source_declaration_ref": self.source_declaration_ref,
            "intervening_bindings": list(self.intervening_bindings),
            "ordered_unwind_set": list(self.ordered_unwind_set),
            "superseded_spec_hashes": list(self.superseded_spec_hashes),
            "exit_hash": self.exit_hash,
            "previous_exit_hash": self.previous_exit_hash,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> NamedExit:
        """Reconstruct a fully-custodied named exit, rejecting omissions."""
        return cls(
            exit_name=str(data["exit_name"]),
            target_loop_id=str(data["target_loop_id"]),
            source_declaration_ref=str(data["source_declaration_ref"]),
            intervening_bindings=tuple(str(v) for v in data["intervening_bindings"]),
            ordered_unwind_set=tuple(str(v) for v in data["ordered_unwind_set"]),
            superseded_spec_hashes=tuple(
                str(v) for v in data.get("superseded_spec_hashes", ())
            ),
            exit_hash=str(data.get("exit_hash", "")),
            previous_exit_hash=str(data.get("previous_exit_hash", "")),
        )


@dataclass(frozen=True)
class NamedExitVerdict:
    """A non-authoritative result of validating a named-exit claim."""

    named_exit: NamedExit
    outcome: CandidateOutcome = CandidateOutcome.SUPERSEDED_BY_NAMED_EXIT
    accepted: bool = False
    failures: tuple[str, ...] = (
        "shadow_only_named_exit_cannot_satisfy_completion",
    )


def superseded_by_named_exit(
    named_exit: NamedExit,
    prior_bindings: tuple[str, ...],
    *,
    expected_target_loop_id: str | None = None,
    expected_unwind_order: tuple[str, ...] | None = None,
) -> NamedExitVerdict:
    """Validate a named exit and return its shadow-only supersession verdict.

    ``prior_bindings`` must be the complete ordered binding sequence crossed
    before the exit.  A subset would erase custody information and is
    rejected as supersession laundering.
    """
    validate_named_exit(
        named_exit,
        expected_target_loop_id=expected_target_loop_id,
        expected_intervening_bindings=tuple(prior_bindings),
        expected_unwind_order=expected_unwind_order,
    )
    return NamedExitVerdict(named_exit=named_exit)


def validate_named_exit(
    named_exit: NamedExit,
    *,
    expected_target_loop_id: str | None = None,
    expected_intervening_bindings: tuple[str, ...] | None = None,
    expected_unwind_order: tuple[str, ...] | None = None,
) -> None:
    """Validate exact target, complete binding custody, and unwind order."""
    if not isinstance(named_exit, NamedExit):
        raise TypeError("named_exit must be a NamedExit")
    if expected_target_loop_id is not None and named_exit.target_loop_id != expected_target_loop_id:
        raise ValueError("Named-exit supersession rejected: exit target does not match exactly")
    if expected_intervening_bindings is not None and tuple(expected_intervening_bindings) != named_exit.intervening_bindings:
        raise ValueError("Named-exit supersession rejected: intervening bindings are incomplete or reordered")
    if expected_unwind_order is not None and tuple(expected_unwind_order) != named_exit.ordered_unwind_set:
        raise ValueError("Named-exit supersession rejected: unwind order does not match exactly")


def unwind_named_exit(
    named_exit: NamedExit,
    current_bindings: tuple[str, ...] | list[str],
    *,
    target_loop_id: str | None = None,
    unwind_order: tuple[str, ...] | None = None,
    expected_intervening_bindings: tuple[str, ...] | None = None,
    expected_unwind_order: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    """Apply a validated LIFO exit without mutating the caller's bindings.

    Validation happens before deriving the returned stack.  Consequently a
    rejected target, sequence, or unwind order cannot drop bindings from a
    mutable list supplied by a caller.
    """
    snapshot = _sequence(current_bindings, "current_bindings")
    if unwind_order is not None and expected_unwind_order is not None and tuple(unwind_order) != tuple(expected_unwind_order):
        raise ValueError("Named-exit supersession rejected: conflicting unwind orders")
    selected_unwind_order = expected_unwind_order if expected_unwind_order is not None else unwind_order
    validate_named_exit(
        named_exit,
        expected_target_loop_id=target_loop_id,
        expected_intervening_bindings=expected_intervening_bindings,
        expected_unwind_order=selected_unwind_order,
    )
    if len(snapshot) < len(named_exit.intervening_bindings):
        raise ValueError("Named-exit supersession rejected: binding stack is incomplete or reordered")
    suffix = snapshot[-len(named_exit.intervening_bindings):]
    if suffix != named_exit.intervening_bindings:
        raise ValueError("Named-exit supersession rejected: binding stack is not an exact suffix")
    return snapshot[:-len(named_exit.intervening_bindings)]


apply_named_exit = unwind_named_exit


def validate_named_exit_chain(named_exits: tuple[NamedExit, ...]) -> None:
    """Validate custody completeness, content hashes, and chain linkage."""
    previous_hash = ""
    for index, record in enumerate(named_exits):
        expected_hash = compute_exit_hash(
            record.exit_name,
            record.target_loop_id,
            record.source_declaration_ref,
            record.intervening_bindings,
            record.ordered_unwind_set,
            record.superseded_spec_hashes,
            record.previous_exit_hash,
        )
        if record.exit_hash != expected_hash:
            raise ValueError(f"NamedExit hash mismatch at index {index}")
        if record.previous_exit_hash != previous_hash:
            raise ValueError(
                f"NamedExit chain broken at index {index}: expected "
                f"previous_exit_hash={previous_hash!r}, got "
                f"{record.previous_exit_hash!r}"
            )
        previous_hash = record.exit_hash


@dataclass(frozen=True)
class CaptureSetResult:
    """Complete-capture set-equality result used by the M11 fixture."""

    expected_ids: tuple[str, ...]
    captured_ids: tuple[str, ...]
    complete_capture: bool
    status: str
    missing_ids: tuple[str, ...]
    extra_ids: tuple[str, ...]
    duplicate_ids: tuple[str, ...]
    causal_occurrences: tuple[str, ...]
    repair_frontier: tuple[str, ...]

    @property
    def accepted(self) -> bool:
        return self.status == "accepted"

    @property
    def unknown(self) -> bool:
        return self.status == "unknown"

    @property
    def missing_manifest_occurrence(self) -> str | None:
        return self.causal_occurrences[0] if self.causal_occurrences else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "accepted": self.accepted,
            "complete_capture": self.complete_capture,
            "expected_ids": list(self.expected_ids),
            "captured_ids": list(self.captured_ids),
            "missing_ids": list(self.missing_ids),
            "extra_ids": list(self.extra_ids),
            "duplicate_ids": list(self.duplicate_ids),
            "causal_occurrences": list(self.causal_occurrences),
            "repair_frontier": list(self.repair_frontier),
        }


def evaluate_complete_capture_set_equality(
    expected_ids: tuple[Any, ...] | list[Any],
    captured_ids: tuple[Any, ...] | list[Any],
    *,
    complete_capture: bool = True,
) -> CaptureSetResult:
    """Compare complete captured identities and retain one repair cause."""
    expected_raw = tuple(str(value) for value in expected_ids)
    captured_raw = tuple(str(value) for value in captured_ids)
    expected = tuple(sorted(set(expected_raw), key=_natural_id_key))
    captured = tuple(sorted(set(captured_raw), key=_natural_id_key))
    duplicate_ids = tuple(
        sorted(
            {
                value
                for values in (expected_raw, captured_raw)
                for value in values
                if values.count(value) > 1
            },
            key=_natural_id_key,
        )
    )
    missing = tuple(value for value in expected if value not in captured)
    extra = tuple(value for value in captured if value not in expected)
    if not complete_capture:
        return CaptureSetResult(expected, captured, False, "unknown", missing, extra, duplicate_ids, ("incomplete-capture",), ("capture:complete",))
    if duplicate_ids:
        first = duplicate_ids[0]
        return CaptureSetResult(expected, captured, True, "rejected", missing, extra, duplicate_ids, (f"duplicate-manifest:{first}",), (f"manifest:{first}",))
    if not missing and not extra:
        return CaptureSetResult(expected, captured, True, "accepted", (), (), (), (), ())
    if missing:
        first = missing[0]
        return CaptureSetResult(expected, captured, True, "rejected", missing, extra, (), (f"missing-manifest:{first}",), (f"manifest:{first}",))
    return CaptureSetResult(expected, captured, True, "rejected", missing, extra, (), ("unexpected-manifest-set",), ("manifest:set",))


def _natural_id_key(value: str) -> tuple[int, int | str]:
    try:
        return (0, int(value))
    except ValueError:
        return (1, value)


@dataclass(frozen=True)
class DependencyClosureResult:
    """Accepted-attempt and dependency-closure result."""

    accepted: bool
    missing_attempts: tuple[str, ...]
    unresolved_dependencies: tuple[str, ...]
    causal_occurrences: tuple[str, ...]
    repair_frontier: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "missing_attempts": list(self.missing_attempts),
            "unresolved_dependencies": list(self.unresolved_dependencies),
            "causal_occurrences": list(self.causal_occurrences),
            "repair_frontier": list(self.repair_frontier),
        }


@dataclass(frozen=True)
class M11AuthorityClosureResult:
    """Single-cause result for the captured contiguous-authority fixture."""

    accepted: bool
    status: str
    capture: CaptureSetResult
    dependency: DependencyClosureResult
    causal_occurrences: tuple[str, ...]
    repair_frontier: tuple[str, ...]

    @property
    def missing_manifest_occurrence(self) -> str | None:
        return self.causal_occurrences[0] if self.causal_occurrences else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "status": self.status,
            "capture": self.capture.to_dict(),
            "dependency": self.dependency.to_dict(),
            "causal_occurrences": list(self.causal_occurrences),
            "repair_frontier": list(self.repair_frontier),
        }


def evaluate_m11_authority_closure(fixture: Mapping[str, Any]) -> M11AuthorityClosureResult:
    """Evaluate complete capture before accepted-attempt closure.

    A missing interior manifest is the causal frontier.  Downstream missing
    attempts are retained as diagnostics but never multiplied into additional
    repair occurrences for the same captured failure.
    """
    expected, captured, complete = _fixture_manifest_sets(fixture)
    capture = evaluate_complete_capture_set_equality(expected, captured, complete_capture=complete)
    required, accepted = _fixture_attempts(fixture)
    dependencies = _fixture_dependencies(fixture)
    missing_attempts = tuple(task for task in required if task not in accepted)
    unresolved = tuple(f"{task}->{dependency}" for task, deps in dependencies.items() for dependency in deps if dependency not in accepted)
    closure_ok = not missing_attempts and not unresolved
    dependency = DependencyClosureResult(closure_ok, missing_attempts, unresolved, (), ())
    if capture.status == "unknown":
        status, causes, frontier = "unknown", capture.causal_occurrences, capture.repair_frontier
    elif not capture.accepted:
        status, causes, frontier = "rejected", capture.causal_occurrences, capture.repair_frontier
    elif not closure_ok:
        cause = _closure_cause(missing_attempts, unresolved)
        task = _closure_task(missing_attempts, unresolved)
        dependency = DependencyClosureResult(False, missing_attempts, unresolved, (cause,), (f"task:{task}",))
        status, causes, frontier = "rejected", dependency.causal_occurrences, dependency.repair_frontier
    else:
        status, causes, frontier = "accepted", (), ()
    return M11AuthorityClosureResult(status == "accepted", status, capture, dependency, causes, frontier)


evaluate_m11_fixture = evaluate_m11_authority_closure


from ._terminals_support import (_accepted_sequence, _closure_cause, _closure_task, _first_sequence, _fixture_attempts, _fixture_dependencies, _fixture_manifest_sets, _is_accepted_attempt)
