"""Immutable, product-neutral aggregation signatures for the C2 shadow."""
from __future__ import annotations
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
import math
from types import MappingProxyType
from typing import Any
from arnold.workflow.completion.hashing import hash_canonical
ADMITTED_CHILD_SET_SCHEMA_VERSION = "arnold.workflow.completion_admitted_child_set.v1"
CHILD_CONTRIBUTION_SCHEMA_VERSION = "arnold.workflow.completion_child_contribution.v1"
PATH_SELECTION_SCHEMA_VERSION = "arnold.workflow.completion_path_selection.v1"
TOTAL_DISPOSITION_SCHEMA_VERSION = "arnold.workflow.completion_total_disposition.v1"
MULTIPLICITY_SCHEMA_VERSION = "arnold.workflow.completion_multiplicity.v1"
WAIVER_TAINT_SCHEMA_VERSION = "arnold.workflow.completion_waiver_taint.v1"
AGGREGATION_SCHEMA_VERSION = "arnold.workflow.completion_aggregation.v1"
class _FrozenMapping(tuple):
    pass
def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _FrozenMapping((str(k), _freeze(v)) for k, v in sorted(value.items(), key=lambda p: str(p[0])))
    if isinstance(value, (set, frozenset)):
        return tuple(sorted((_freeze(v) for v in value), key=repr))
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return tuple(_freeze(v) for v in value)
    if isinstance(value, Enum):
        return _freeze(value.value)
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise TypeError(f"value must be JSON-like, got {type(value).__name__}")
def _thaw(value: Any) -> Any:
    if isinstance(value, _FrozenMapping):
        return {k: _thaw(v) for k, v in value}
    if isinstance(value, tuple):
        return [_thaw(v) for v in value]
    return value
def _text(value: Any, field: str, *, empty: bool = False) -> str:
    result = "" if value is None else str(value).strip()
    if not empty and not result:
        raise ValueError(f"{field} must be non-empty")
    return result
def _id_values(value: Any) -> tuple[Any, ...]:
    if isinstance(value, bytes):
        return (value.decode(),)
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Mapping):
        return tuple(value.keys())
    try:
        return tuple(value)
    except TypeError:
        return (value,)


def _ids(value: Any, field: str, *, sort: bool = False) -> tuple[str, ...]:
    if value is None or value == "":
        return ()
    values = _id_values(value)
    result = tuple(_text(item, field) for item in values)
    if len(set(result)) != len(result):
        raise ValueError(f"{field} cannot contain duplicates")
    return tuple(sorted(result)) if sort else result
def _record_hash(schema: str, payload: Mapping[str, Any], supplied: str = "") -> str:
    expected = hash_canonical({"schema_version": schema, **dict(payload)})
    if supplied and supplied != expected:
        raise ValueError(f"{schema} hash mismatch")
    return expected


def _taint_ids(value: Any) -> tuple[str, ...]:
    if isinstance(value, (TransitiveWaiverTaint, ChildContribution)):
        return tuple(value.taint)
    if isinstance(value, Mapping) and "taint" in value:
        return _taint_ids(value["taint"])
    return _ids(value, "taint")
def _count(value: Any, field: str, default: int = 0) -> int:
    actual = default if value is None else value
    if isinstance(actual, bool) or not isinstance(actual, int) or actual < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return actual
def _has_proof(proof: Any, proof_ids: tuple[str, ...], reason: str = "") -> bool:
    return bool(proof_ids or reason or (proof is not None and proof not in ("", (), [], {})))
@dataclass(frozen=True, init=False)
class AdmittedChildSet:
    """Frozen identity set of children admitted for one parent scope."""
    parent_id: str
    child_ids: tuple[str, ...]
    binding_hash: str
    complete: bool
    child_set_hash: str
    def __init__(self, parent_id: Any = "", child_ids: Iterable[Any] = (), binding_hash: str = "", complete: bool = True, child_set_hash: str = "", *, children: Iterable[Any] | None = None, set_id: Any = None, digest: str = "", admitted: bool | None = None, hash: str = "") -> None:
        parent = parent_id if set_id is None else set_id
        raw = child_ids if children is None else children
        if children is None and not child_ids and isinstance(parent_id, Iterable) and not isinstance(parent_id, (str, bytes, Mapping)):
            parent, raw = "", parent_id
        ids = _ids(raw, "child_ids", sort=True)
        complete = complete if admitted is None else admitted
        if not isinstance(complete, bool):
            raise TypeError("complete must be bool")
        payload = {"parent_id": _text(parent, "parent_id", empty=True), "child_ids": list(ids), "binding_hash": _text(binding_hash, "binding_hash", empty=True), "complete": complete}
        digest = _record_hash(ADMITTED_CHILD_SET_SCHEMA_VERSION, payload, child_set_hash or hash or digest)
        for name, value in (("parent_id", payload["parent_id"]), ("child_ids", ids), ("binding_hash", payload["binding_hash"]), ("complete", complete), ("child_set_hash", digest)):
            object.__setattr__(self, name, value)
    @property
    def digest(self) -> str:
        return self.child_set_hash
    @property
    def set_hash(self) -> str:
        return self.child_set_hash
    @property
    def hash(self) -> str:
        return self.child_set_hash
    def contains(self, child_id: str) -> bool:
        return child_id in self.child_ids
    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": ADMITTED_CHILD_SET_SCHEMA_VERSION, "parent_id": self.parent_id, "child_ids": list(self.child_ids), "binding_hash": self.binding_hash, "complete": self.complete, "child_set_hash": self.child_set_hash}
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AdmittedChildSet":
        return cls(data.get("parent_id", data.get("set_id", "")), data.get("child_ids", data.get("children", ())), str(data.get("binding_hash", "")), bool(data.get("complete", data.get("admitted", True))), str(data.get("child_set_hash", data.get("set_hash", data.get("hash", "")))))
@dataclass(frozen=True, init=False)
class ChildContribution:
    """Frozen content identity for one admitted child contribution."""
    child_id: str
    disposition: str
    evidence_ids: tuple[str, ...]
    value: Any
    multiplicity: int
    taint: frozenset[str]
    contribution_id: str
    metadata: Any
    contribution_hash: str
    def __init__(self, child_id: Any = "", disposition: Any = "", value: Any = None, evidence_ids: Iterable[Any] = (), multiplicity: int = 1, taint: Iterable[Any] = (), contribution_id: str = "", metadata: Any = None, contribution_hash: str = "", *, evidence_id: Any = None, payload: Any = None, details: Any = None, waiver_taint: Iterable[Any] | None = None, hash: str = "") -> None:
        value = payload if payload is not None and value is None else value
        metadata = details if details is not None and metadata is None else metadata
        evidence = _ids(_ids(evidence_ids, "evidence_ids") + _ids(evidence_id, "evidence_ids"), "evidence_ids", sort=True)
        labels = _ids(taint, "taint", sort=True) + (() if waiver_taint is None else _ids(waiver_taint, "taint", sort=True))
        actual_taint = frozenset(labels) | (frozenset({"waived"}) if labels else frozenset())
        multiplicity = _count(multiplicity, "multiplicity", 1)
        if multiplicity < 1:
            raise ValueError("multiplicity must be positive")
        frozen_value, frozen_metadata = _freeze(value), _freeze(metadata)
        payload_data = {"child_id": _text(child_id, "child_id"), "disposition": _text(disposition, "disposition"), "evidence_ids": list(evidence), "value": _thaw(frozen_value), "multiplicity": multiplicity, "taint": sorted(actual_taint), "metadata": _thaw(frozen_metadata)}
        digest = _record_hash(CHILD_CONTRIBUTION_SCHEMA_VERSION, payload_data, contribution_hash or hash)
        values = (payload_data["child_id"], payload_data["disposition"], evidence, frozen_value, multiplicity, actual_taint, _text(contribution_id, "contribution_id", empty=True) or digest, frozen_metadata, digest)
        for name, item in zip(("child_id", "disposition", "evidence_ids", "value", "multiplicity", "taint", "contribution_id", "metadata", "contribution_hash"), values):
            object.__setattr__(self, name, item)
    @property
    def identity(self) -> str:
        return self.contribution_hash
    @property
    def content_hash(self) -> str:
        return self.contribution_hash
    @property
    def waiver_taint(self) -> frozenset[str]:
        return self.taint
    @property
    def hash(self) -> str:
        return self.contribution_hash
    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": CHILD_CONTRIBUTION_SCHEMA_VERSION, "child_id": self.child_id, "disposition": self.disposition, "evidence_ids": list(self.evidence_ids), "value": _thaw(self.value), "multiplicity": self.multiplicity, "taint": sorted(self.taint), "contribution_id": self.contribution_id, "metadata": _thaw(self.metadata), "contribution_hash": self.contribution_hash}
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ChildContribution":
        return cls(data["child_id"], data["disposition"], data.get("value", data.get("payload")), data.get("evidence_ids", data.get("evidence_id", ())), int(data.get("multiplicity", 1)), data.get("taint", data.get("waiver_taint", ())), str(data.get("contribution_id", "")), data.get("metadata", data.get("details")), str(data.get("contribution_hash", data.get("hash", ""))))
@dataclass(frozen=True, init=False, eq=False)
class PathSelection:
    """One selected path or one path carrying non-selection proof."""
    path_id: str
    selected: bool
    proof: Any
    proof_ids: tuple[str, ...]
    reason: str
    selection_hash: str
    def __init__(self, path_id: Any = "", selected: bool = False, proof: Any = None, proof_ids: Iterable[Any] = (), reason: str = "", selection_hash: str = "", *, applicability_proof: Any = None, evidence_ids: Iterable[Any] = (), not_applicable_proof: Any = None, selected_path: bool | None = None, hash: str = "") -> None:
        proof = applicability_proof if applicability_proof is not None else (not_applicable_proof if not_applicable_proof is not None else proof)
        selected = selected if selected_path is None else selected_path
        ids = _ids(_ids(proof_ids, "proof_ids") + _ids(evidence_ids, "proof_ids"), "proof_ids", sort=True)
        reason = _text(reason, "reason", empty=True)
        if not isinstance(selected, bool):
            raise TypeError("selected must be bool")
        if not selected and not _has_proof(proof, ids, reason):
            raise ValueError("unselected path requires proof")
        frozen = _freeze(proof)
        payload = {"path_id": _text(path_id, "path_id"), "selected": selected, "proof": _thaw(frozen), "proof_ids": list(ids), "reason": reason}
        digest = _record_hash(PATH_SELECTION_SCHEMA_VERSION, payload, selection_hash or hash)
        for name, item in (("path_id", payload["path_id"]), ("selected", selected), ("proof", frozen), ("proof_ids", ids), ("reason", reason), ("selection_hash", digest)):
            object.__setattr__(self, name, item)
    @property
    def has_proof(self) -> bool:
        return _has_proof(self.proof, self.proof_ids, self.reason)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PathSelection) and (self.path_id, self.selected, self.proof, self.proof_ids, self.reason, self.selection_hash) == (other.path_id, other.selected, other.proof, other.proof_ids, other.reason, other.selection_hash)
    @property
    def hash(self) -> str:
        return self.selection_hash
    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": PATH_SELECTION_SCHEMA_VERSION, "path_id": self.path_id, "selected": self.selected, "proof": _thaw(self.proof), "proof_ids": list(self.proof_ids), "reason": self.reason, "selection_hash": self.selection_hash}
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PathSelection":
        return cls(data["path_id"], bool(data.get("selected", False)), data.get("proof"), data.get("proof_ids", data.get("evidence_ids", ())), str(data.get("reason", "")), str(data.get("selection_hash", data.get("hash", ""))))
@dataclass(frozen=True, init=False, eq=False)
class SelectedPath(PathSelection):
    def __init__(self, path_id: Any = "", proof: Any = None, proof_ids: Iterable[Any] = (), reason: str = "", selection_hash: str = "", **kwargs: Any) -> None:
        kwargs.pop("selected", None)
        super().__init__(path_id, True, proof, proof_ids, reason, selection_hash, **kwargs)
@dataclass(frozen=True, init=False, eq=False)
class UnselectedPath(PathSelection):
    def __init__(self, path_id: Any = "", proof: Any = None, proof_ids: Iterable[Any] = (), reason: str = "", selection_hash: str = "", **kwargs: Any) -> None:
        kwargs.pop("selected", None)
        super().__init__(path_id, False, proof, proof_ids, reason, selection_hash, **kwargs)
def validate_path_selection(paths: Iterable[PathSelection | Mapping[str, Any]], *, require_single_selected: bool = True) -> tuple[PathSelection, ...]:
    actual = tuple(item if isinstance(item, PathSelection) else PathSelection.from_dict(item) for item in paths)
    if len({item.path_id for item in actual}) != len(actual):
        raise ValueError("path selection contains duplicate path IDs")
    selected = sum(item.selected for item in actual)
    if require_single_selected and selected != 1:
        raise ValueError("path selection requires exactly one selected path")
    if any(not item.selected and not item.has_proof for item in actual):
        raise ValueError("every unselected path requires proof")
    return actual
def _pairs(value: Any) -> tuple[tuple[Any, Any], ...]:
    if value is None:
        return ()
    if isinstance(value, Mapping):
        return tuple(value.items())
    try:
        values = tuple(value)
    except TypeError as exc:
        raise TypeError("dispositions must be a mapping or pair sequence") from exc
    if any(isinstance(pair, (str, bytes)) or len(pair) != 2 for pair in values):
        raise ValueError("each disposition entry must contain child ID and disposition")
    return tuple((pair[0], pair[1]) for pair in values)
@dataclass(frozen=True, init=False)
class TotalDispositionMapping:
    """Frozen total child-to-disposition mapping for an admitted set."""
    parent_id: str
    child_set_hash: str
    disposition_items: tuple[tuple[str, str], ...]
    mapping_hash: str
    def __init__(self, admitted_child_set: AdmittedChildSet | Mapping[str, Any] | Iterable[Any] | None = None, mapping: Mapping[Any, Any] | Iterable[Sequence[Any]] | None = None, *, child_set: AdmittedChildSet | Mapping[str, Any] | None = None, child_ids: Iterable[Any] = (), dispositions: Mapping[Any, Any] | Iterable[Sequence[Any]] | None = None, parent_id: Any = "", child_set_hash: str = "", mapping_hash: str = "", hash: str = "") -> None:
        admitted_child_set = child_set if child_set is not None else admitted_child_set
        mapping = dispositions if mapping is None else mapping
        if isinstance(admitted_child_set, Mapping) and "child_ids" in admitted_child_set:
            admitted_child_set = AdmittedChildSet.from_dict(admitted_child_set)
        elif admitted_child_set is not None and not isinstance(admitted_child_set, AdmittedChildSet) and mapping is None:
            mapping, admitted_child_set = admitted_child_set, None
        if admitted_child_set is None and child_ids:
            admitted_child_set = AdmittedChildSet(parent_id=parent_id, child_ids=child_ids)
        child_set_record = admitted_child_set if isinstance(admitted_child_set, AdmittedChildSet) else None
        pairs = _pairs(mapping)
        keys = tuple(_text(k, "child_id") for k, _ in pairs)
        if len(set(keys)) != len(keys):
            raise ValueError("disposition mapping contains duplicate child IDs")
        expected = child_set_record.child_ids if child_set_record else tuple(sorted(keys))
        if set(keys) != set(expected):
            raise ValueError(f"disposition mapping is not total; missing={sorted(set(expected) - set(keys))}, extra={sorted(set(keys) - set(expected))}")
        items = tuple(sorted((key, _text(value, "disposition")) for key, (_, value) in zip(keys, pairs)))
        parent = child_set_record.parent_id if child_set_record and not parent_id else parent_id
        child_hash = child_set_record.child_set_hash if child_set_record else _text(child_set_hash, "child_set_hash", empty=True)
        payload = {"parent_id": _text(parent, "parent_id", empty=True), "child_set_hash": child_hash, "dispositions": [[k, v] for k, v in items]}
        digest = _record_hash(TOTAL_DISPOSITION_SCHEMA_VERSION, payload, mapping_hash or hash)
        for name, item in (("parent_id", payload["parent_id"]), ("child_set_hash", child_hash), ("disposition_items", items), ("mapping_hash", digest)):
            object.__setattr__(self, name, item)
    @property
    def mapping(self) -> Mapping[str, str]:
        return MappingProxyType(dict(self.disposition_items))
    @property
    def dispositions(self) -> Mapping[str, str]:
        return self.mapping
    @property
    def child_ids(self) -> tuple[str, ...]:
        return tuple(key for key, _ in self.disposition_items)
    @property
    def is_total(self) -> bool:
        return len(self.child_ids) == len(self.disposition_items)
    @property
    def hash(self) -> str:
        return self.mapping_hash
    def disposition_for(self, child_id: str) -> str:
        return self.mapping[child_id]
    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": TOTAL_DISPOSITION_SCHEMA_VERSION, "parent_id": self.parent_id, "child_set_hash": self.child_set_hash, "mapping": dict(self.disposition_items), "mapping_hash": self.mapping_hash}
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TotalDispositionMapping":
        return cls(mapping=data.get("mapping", data.get("dispositions", ())), parent_id=data.get("parent_id", ""), child_set_hash=str(data.get("child_set_hash", "")), mapping_hash=str(data.get("mapping_hash", data.get("hash", ""))))
def _contribution(value: ChildContribution | Mapping[str, Any]) -> ChildContribution:
    return value if isinstance(value, ChildContribution) else ChildContribution.from_dict(value)
def validate_no_double_count(contributions: Iterable[ChildContribution | Mapping[str, Any]]) -> tuple[ChildContribution, ...]:
    actual = tuple(_contribution(item) for item in contributions)
    hashes: set[str] = set(); ids: set[str] = set(); evidence: set[str] = set()
    for item in actual:
        if item.identity in hashes or item.contribution_id in ids:
            raise ValueError("a child contribution is counted more than once")
        overlap = evidence.intersection(item.evidence_ids)
        if overlap:
            raise ValueError(f"evidence contribution counted more than once: {sorted(overlap)}")
        hashes.add(item.identity); ids.add(item.contribution_id); evidence.update(item.evidence_ids)
    return actual
@dataclass(frozen=True, init=False)
class TransitiveWaiverTaint:
    """Frozen union of waiver labels inherited through composition."""
    taint: frozenset[str]
    sources: tuple[str, ...]
    taint_hash: str
    def __init__(self, taint: Iterable[Any] = (), sources: Iterable[Any] = (), taint_hash: str = "", *, labels: Iterable[Any] | None = None, inherited: Iterable[Any] | None = None, waiver_taint: Iterable[Any] | None = None, hash: str = "") -> None:
        values: list[Any] = list(_taint_ids(taint))
        for alias in (labels, inherited, waiver_taint):
            if alias is not None:
                values.extend(_taint_ids(alias))
        actual = frozenset(_ids(values, "taint", sort=True)); actual |= frozenset({"waived"}) if actual else frozenset()
        sources = _ids(sources, "sources", sort=True)
        digest = _record_hash(WAIVER_TAINT_SCHEMA_VERSION, {"taint": sorted(actual), "sources": list(sources)}, taint_hash or hash)
        object.__setattr__(self, "taint", actual); object.__setattr__(self, "sources", sources); object.__setattr__(self, "taint_hash", digest)
    @property
    def clean(self) -> bool:
        return not self.taint
    @property
    def tainted(self) -> bool:
        return bool(self.taint)
    @property
    def waiver_taint(self) -> frozenset[str]:
        return self.taint
    @property
    def hash(self) -> str:
        return self.taint_hash
    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": WAIVER_TAINT_SCHEMA_VERSION, "taint": sorted(self.taint), "sources": list(self.sources), "taint_hash": self.taint_hash}
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TransitiveWaiverTaint":
        return cls(data.get("taint", data.get("labels", ())), data.get("sources", ()), str(data.get("taint_hash", data.get("hash", ""))))
WaiverTaint = TransitiveWaiverTaint
def _collect_taint(value: Any, labels: set[str]) -> None:
    if isinstance(value, (TransitiveWaiverTaint, ChildContribution)):
        labels.update(value.taint); return
    if isinstance(value, Mapping):
        for key in ("taint", "waiver_taint", "children", "contributions", "proof", "waiver_proof"):
            if key in value: _collect_taint(value[key], labels)
        return
    if isinstance(value, (str, bytes)):
        labels.add(value.decode() if isinstance(value, bytes) else value); return
    if isinstance(value, Iterable):
        for item in value: _collect_taint(item, labels)
        return
    taint = getattr(value, "taint", None)
    if taint is not None: _collect_taint(taint, labels)
def propagate_waiver_taint(*values: Any) -> frozenset[str]:
    labels: set[str] = set()
    for value in values: _collect_taint(value, labels)
    labels.discard("")
    if labels: labels.add("waived")
    return frozenset(labels)
def validate_transitive_waiver_taint(child_values: Iterable[Any], root_taint: Any = (), *, root_accepted: bool = False) -> TransitiveWaiverTaint:
    inherited = propagate_waiver_taint(child_values); root = propagate_waiver_taint(root_taint)
    explicit = isinstance(root_taint, TransitiveWaiverTaint) or (isinstance(root_taint, Mapping) and "taint" in root_taint) or bool(root_taint not in (None, (), [], ""))
    if explicit and not inherited.issubset(root):
        raise ValueError("root waiver taint dropped a child taint")
    combined = inherited | root
    if root_accepted and combined: raise ValueError("waiver-tainted children cannot become clean root acceptance")
    return TransitiveWaiverTaint(combined)
@dataclass(frozen=True, init=False)
class Multiplicity:
    """Frozen cardinality proof for admitted and counted contributions."""
    expected_count: int | None
    admitted_count: int
    counted_count: int
    contribution_ids: tuple[str, ...]
    multiplicity_hash: str
    def __init__(self, expected_count: int | None = None, admitted_count: int | None = None, counted_count: int | None = None, contribution_ids: Iterable[Any] = (), multiplicity_hash: str = "", *, expected: int | None = None, admitted: int | None = None, observed: int | None = None, counted: int | None = None, identities: Iterable[Any] | None = None, contributions: Iterable[ChildContribution | Mapping[str, Any]] | None = None, admitted_child_set: AdmittedChildSet | Mapping[str, Any] | None = None, hash: str = "") -> None:
        expected_count = expected_count if expected_count is not None else expected
        admitted_count = admitted_count if admitted_count is not None else admitted
        counted_count = counted_count if counted_count is not None else (observed if observed is not None else counted)
        ids = _ids(contribution_ids if identities is None else identities, "contribution_ids", sort=True)
        if contributions is not None:
            actual = validate_no_double_count(contributions); counted_count = sum(item.multiplicity for item in actual) if counted_count is None else counted_count; ids = tuple(item.identity for item in actual) if not ids else ids
        if admitted_child_set is not None:
            child_set = admitted_child_set if isinstance(admitted_child_set, AdmittedChildSet) else AdmittedChildSet.from_dict(admitted_child_set); admitted_count = len(child_set.child_ids) if admitted_count is None else admitted_count
        expected_count = None if expected_count is None else _count(expected_count, "expected_count")
        admitted_count, counted_count = _count(admitted_count, "admitted_count"), _count(counted_count, "counted_count")
        payload = {"expected_count": expected_count, "admitted_count": admitted_count, "counted_count": counted_count, "contribution_ids": list(ids)}
        digest = _record_hash(MULTIPLICITY_SCHEMA_VERSION, payload, multiplicity_hash or hash)
        for name, item in (("expected_count", expected_count), ("admitted_count", admitted_count), ("counted_count", counted_count), ("contribution_ids", ids), ("multiplicity_hash", digest)):
            object.__setattr__(self, name, item)
    @property
    def expected(self) -> int | None: return self.expected_count
    @property
    def admitted(self) -> int: return self.admitted_count
    @property
    def observed(self) -> int: return self.counted_count
    @property
    def preserved(self) -> bool: return self.counted_count == self.admitted_count
    @property
    def satisfied(self) -> bool: return self.preserved and (self.expected_count is None or self.counted_count == self.expected_count)
    @property
    def hash(self) -> str: return self.multiplicity_hash
    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": MULTIPLICITY_SCHEMA_VERSION, "expected_count": self.expected_count, "admitted_count": self.admitted_count, "counted_count": self.counted_count, "contribution_ids": list(self.contribution_ids), "multiplicity_hash": self.multiplicity_hash}
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Multiplicity":
        return cls(data.get("expected_count", data.get("expected")), data.get("admitted_count", data.get("admitted")), data.get("counted_count", data.get("observed", data.get("counted"))), data.get("contribution_ids", data.get("identities", ())), str(data.get("multiplicity_hash", data.get("hash", ""))))
def validate_multiplicity(multiplicity: Multiplicity | Mapping[str, Any], contributions: Iterable[ChildContribution | Mapping[str, Any]] = (), admitted_child_set: AdmittedChildSet | Mapping[str, Any] | None = None) -> bool:
    actual = multiplicity if isinstance(multiplicity, Multiplicity) else Multiplicity.from_dict(multiplicity); items = validate_no_double_count(contributions) if contributions else ()
    if items and (sum(item.multiplicity for item in items) != actual.counted_count or (actual.contribution_ids and set(actual.contribution_ids) != {item.identity for item in items})): raise ValueError("multiplicity does not match contributions")
    if admitted_child_set is not None:
        child_set = admitted_child_set if isinstance(admitted_child_set, AdmittedChildSet) else AdmittedChildSet.from_dict(admitted_child_set)
        if actual.admitted_count != len(child_set.child_ids): raise ValueError("multiplicity does not preserve admitted child count")
    if not actual.satisfied: raise ValueError("admitted multiplicity is not preserved")
    return True
def build_multiplicity(admitted_child_set: AdmittedChildSet | Mapping[str, Any], contributions: Iterable[ChildContribution | Mapping[str, Any]], *, expected_count: int | None = None) -> Multiplicity:
    child_set = admitted_child_set if isinstance(admitted_child_set, AdmittedChildSet) else AdmittedChildSet.from_dict(admitted_child_set); items = validate_no_double_count(contributions)
    return Multiplicity(expected_count=len(child_set.child_ids) if expected_count is None else expected_count, admitted_count=len(child_set.child_ids), counted_count=sum(item.multiplicity for item in items), contribution_ids=tuple(item.identity for item in items))
@dataclass(frozen=True, init=False)
class AggregationSignature:
    """Complete generic composition proof for one admitted child set."""
    admitted_child_set: AdmittedChildSet
    disposition_mapping: TotalDispositionMapping
    paths: tuple[PathSelection, ...]
    contributions: tuple[ChildContribution, ...]
    multiplicity: Multiplicity
    waiver_taint: TransitiveWaiverTaint
    root_accepted: bool
    signature_hash: str
    def __init__(self, admitted_child_set: AdmittedChildSet | Mapping[str, Any], disposition_mapping: TotalDispositionMapping | Mapping[str, Any], paths: Iterable[PathSelection | Mapping[str, Any]], contributions: Iterable[ChildContribution | Mapping[str, Any]], multiplicity: Multiplicity | Mapping[str, Any], waiver_taint: TransitiveWaiverTaint | Iterable[Any] | Mapping[str, Any] = (), root_accepted: bool = False, signature_hash: str = "", *, accepted: bool | None = None, hash: str = "") -> None:
        child_set = admitted_child_set if isinstance(admitted_child_set, AdmittedChildSet) else AdmittedChildSet.from_dict(admitted_child_set); mapping = disposition_mapping if isinstance(disposition_mapping, TotalDispositionMapping) else TotalDispositionMapping(child_set, disposition_mapping); validate_total_disposition_mapping(mapping, child_set)
        items = validate_no_double_count(contributions)
        if any(item.child_id not in child_set.child_ids for item in items): raise ValueError("contribution references a child outside the admitted set")
        if any(mapping.disposition_for(item.child_id) != item.disposition for item in items): raise ValueError("child contribution disagrees with total mapping")
        paths = validate_path_selection(paths); multiplicity = multiplicity if isinstance(multiplicity, Multiplicity) else Multiplicity.from_dict(multiplicity); validate_multiplicity(multiplicity, items, child_set)
        accepted = root_accepted if accepted is None else accepted
        if not isinstance(accepted, bool): raise TypeError("root_accepted must be bool")
        taint = validate_transitive_waiver_taint(items, waiver_taint, root_accepted=accepted)
        payload = {"admitted_child_set": child_set.to_dict(), "disposition_mapping": mapping.to_dict(), "paths": [item.to_dict() for item in paths], "contributions": [item.to_dict() for item in items], "multiplicity": multiplicity.to_dict(), "waiver_taint": taint.to_dict(), "root_accepted": accepted}
        digest = _record_hash(AGGREGATION_SCHEMA_VERSION, payload, signature_hash or hash)
        for name, item in (("admitted_child_set", child_set), ("disposition_mapping", mapping), ("paths", paths), ("contributions", items), ("multiplicity", multiplicity), ("waiver_taint", taint), ("root_accepted", accepted), ("signature_hash", digest)):
            object.__setattr__(self, name, item)
    @property
    def root_clean(self) -> bool: return self.waiver_taint.clean
    @property
    def hash(self) -> str: return self.signature_hash
    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": AGGREGATION_SCHEMA_VERSION, "admitted_child_set": self.admitted_child_set.to_dict(), "disposition_mapping": self.disposition_mapping.to_dict(), "paths": [item.to_dict() for item in self.paths], "contributions": [item.to_dict() for item in self.contributions], "multiplicity": self.multiplicity.to_dict(), "waiver_taint": self.waiver_taint.to_dict(), "root_accepted": self.root_accepted, "signature_hash": self.signature_hash}
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AggregationSignature":
        return cls(AdmittedChildSet.from_dict(data["admitted_child_set"]), TotalDispositionMapping.from_dict(data["disposition_mapping"]), tuple(PathSelection.from_dict(item) for item in data.get("paths", ())), tuple(ChildContribution.from_dict(item) for item in data.get("contributions", ())), Multiplicity.from_dict(data["multiplicity"]), TransitiveWaiverTaint.from_dict(data.get("waiver_taint", {})), bool(data.get("root_accepted", False)), str(data.get("signature_hash", data.get("hash", ""))))
def validate_total_disposition_mapping(mapping: TotalDispositionMapping | Mapping[str, Any], admitted_child_set: AdmittedChildSet | Mapping[str, Any] | None = None) -> bool:
    actual = mapping if isinstance(mapping, TotalDispositionMapping) else TotalDispositionMapping(admitted_child_set, mapping)
    if admitted_child_set is not None:
        child_set = admitted_child_set if isinstance(admitted_child_set, AdmittedChildSet) else AdmittedChildSet.from_dict(admitted_child_set)
        if set(actual.child_ids) != set(child_set.child_ids): raise ValueError("disposition mapping is not total for the admitted child set")
    return actual.is_total
def validate_aggregation(admitted_child_set: AdmittedChildSet | Mapping[str, Any] | AggregationSignature, disposition_mapping: TotalDispositionMapping | Mapping[str, Any] | None = None, paths: Iterable[PathSelection | Mapping[str, Any]] = (), contributions: Iterable[ChildContribution | Mapping[str, Any]] = (), multiplicity: Multiplicity | Mapping[str, Any] | None = None, *, waiver_taint: Any = (), root_accepted: bool = False) -> bool:
    if isinstance(admitted_child_set, AggregationSignature): return True
    if disposition_mapping is None or multiplicity is None: raise ValueError("aggregation validation requires mapping and multiplicity")
    AggregationSignature(admitted_child_set, disposition_mapping, paths, contributions, multiplicity, waiver_taint, root_accepted); return True
validate_total_mapping = validate_total_disposition_mapping
validate_no_double_counting = validate_no_double_count
validate_path_proofs = validate_path_selection
validate_waiver_taint = validate_transitive_waiver_taint
transitive_waiver_taint = propagate_waiver_taint
AggregationContract = AggregationSignature
__all__ = ["ADMITTED_CHILD_SET_SCHEMA_VERSION", "CHILD_CONTRIBUTION_SCHEMA_VERSION", "PATH_SELECTION_SCHEMA_VERSION", "TOTAL_DISPOSITION_SCHEMA_VERSION", "MULTIPLICITY_SCHEMA_VERSION", "WAIVER_TAINT_SCHEMA_VERSION", "AGGREGATION_SCHEMA_VERSION", "AdmittedChildSet", "ChildContribution", "PathSelection", "SelectedPath", "UnselectedPath", "TotalDispositionMapping", "Multiplicity", "TransitiveWaiverTaint", "WaiverTaint", "AggregationSignature", "AggregationContract", "validate_path_selection", "validate_total_disposition_mapping", "validate_total_mapping", "validate_no_double_count", "validate_no_double_counting", "validate_path_proofs", "propagate_waiver_taint", "transitive_waiver_taint", "validate_transitive_waiver_taint", "validate_waiver_taint", "validate_multiplicity", "build_multiplicity", "validate_aggregation"]
