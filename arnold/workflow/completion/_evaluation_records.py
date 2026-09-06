"""Evidence selection and aggregate-rule normalization helpers.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .evaluation import EvidenceRecord, Obligation, ProofMode, _as_tuple, _thaw

def _relevant(
    records: Sequence[EvidenceRecord],
    obligation: Obligation,
) -> tuple[EvidenceRecord, ...]:
    targets = set(obligation.target_evidence_kinds)
    result: list[EvidenceRecord] = []
    for record in records:
        if record.is_capture_marker:
            continue
        if targets and record.kind not in targets:
            continue
        if record.obligation_ids and obligation.obligation_id not in record.obligation_ids:
            continue
        result.append(record)
    return tuple(result)


def _member_id(record: EvidenceRecord) -> str:
    if record.member_id:
        return record.member_id
    content = _thaw(record.content)
    if isinstance(content, Mapping):
        for key in ("member_id", "event_id", "item_id", "id", "key", "name"):
            if key in content:
                return str(content[key])
    return record.evidence_id


def _expected_for(
    obligation: Obligation,
    expected_ids: Any,
    capture_records: Sequence[EvidenceRecord],
) -> tuple[str, ...] | None:
    candidate = expected_ids
    if isinstance(expected_ids, Mapping):
        candidate = expected_ids.get(obligation.obligation_id)
        if candidate is None:
            candidate = expected_ids.get("expected_ids")
        if candidate is None:
            candidate = expected_ids.get("declared_ids")
    if candidate is not None:
        return tuple(dict.fromkeys(_as_tuple(candidate, "expected_ids")))
    for marker in capture_records:
        content = _thaw(marker.content)
        if not isinstance(content, Mapping):
            continue
        raw = content.get("expected_ids", content.get("declared_ids", content.get("members")))
        if isinstance(raw, Mapping):
            raw = raw.get(obligation.obligation_id)
        if raw is not None:
            return tuple(dict.fromkeys(_as_tuple(raw, "expected_ids")))
    return None


def _aggregate_rule(aggregate: Any, obligation: Obligation) -> Any:
    if isinstance(aggregate, Mapping):
        if obligation.obligation_id in aggregate:
            return aggregate[obligation.obligation_id]
        if any(key in aggregate for key in ("operator", "op", "function", "expected", "threshold", "minimum", "maximum")):
            return aggregate
        return None
    return aggregate


def _numeric_value(record: EvidenceRecord) -> Any:
    content = _thaw(record.content)
    if isinstance(content, Mapping):
        for key in ("value", "amount", "contribution", "total"):
            if key in content:
                return content[key]
    return content

__all__ = ["_relevant", "_member_id", "_expected_for", "_aggregate_rule", "_numeric_value"]
