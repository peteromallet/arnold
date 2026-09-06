"""Pure proof-mode evaluators for completion obligations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .evaluation import Diagnostic, EvidenceRecord, EvaluationStatus, Obligation, ObligationResult, ProofMode
from ._evaluation_admission import _diagnostic
from ._evaluation_records import _aggregate_rule, _expected_for, _member_id, _numeric_value, _relevant


def _aggregate_actual(obligation, records, rule):
    values = tuple(_numeric_value(r) for r in records for _ in range(r.multiplicity))
    unique = tuple(_numeric_value(r) for r in records)
    if callable(rule):
        try:
            return "callable", None, rule(records), None
        except Exception as exc:
            return "", None, None, _diagnostic("AGGREGATE_EVALUATION_ERROR", f"aggregate rule raised {exc!r}", obligation_id=obligation.obligation_id, cause="aggregate-evaluation-error", repair_frontier=(f"obligation:{obligation.obligation_id}:aggregate",))
    rule_map = rule if isinstance(rule, Mapping) else {"expected": rule}
    operator = str(rule_map.get("operator", rule_map.get("op", rule_map.get("function", "sum")))).lower()
    expected = rule_map.get("expected", rule_map.get("value"))
    if operator in {"threshold", "at_least", "minimum"}:
        expected = rule_map.get("threshold", rule_map.get("minimum", expected))
    if operator in {"at_most", "maximum"}:
        expected = rule_map.get("threshold", rule_map.get("maximum", expected))
    handlers = {
        "sum": lambda: sum(unique), "count": lambda: len(records),
        "min": lambda: min(unique) if unique else None, "max": lambda: max(unique) if unique else None,
        "threshold": lambda: sum(unique), "at_least": lambda: sum(unique), "minimum": lambda: sum(unique),
        "at_most": lambda: sum(unique), "maximum": lambda: sum(unique),
        "any": lambda: any(values), "all": lambda: all(values),
    }
    if operator not in handlers:
        return "", None, None, _diagnostic("AGGREGATE_OPERATOR_UNKNOWN", f"unsupported aggregate operator {operator!r}", obligation_id=obligation.obligation_id, cause="aggregate-operator-unknown", repair_frontier=(f"obligation:{obligation.obligation_id}:aggregate",))
    try:
        actual = handlers[operator]()
    except (TypeError, ValueError) as exc:
        return "", None, None, _diagnostic("AGGREGATE_VALUE_INVALID", f"aggregate values are not reducible: {exc}", obligation_id=obligation.obligation_id, cause="aggregate-value-invalid", repair_frontier=(f"obligation:{obligation.obligation_id}:aggregate",))
    if operator in {"threshold", "at_least", "minimum"}:
        expected = (">=", expected)
    if operator in {"at_most", "maximum"}:
        expected = ("<=", expected)
    return operator, expected, actual, None


def _evaluate_aggregate(obligation: Obligation, records: Sequence[EvidenceRecord], rule: Any):
    if rule is None:
        return EvaluationStatus.UNKNOWN, (_diagnostic("AGGREGATE_RULE_MISSING", "aggregate proof has no deterministic aggregate rule", obligation_id=obligation.obligation_id, cause="aggregate-rule-missing", repair_frontier=(f"obligation:{obligation.obligation_id}:aggregate",)),), None, None
    operator, expected, actual, diagnostic = _aggregate_actual(obligation, records, rule)
    if diagnostic is not None:
        return EvaluationStatus.UNKNOWN, (diagnostic,), None, None
    matches = actual == expected if operator == "callable" or not isinstance(expected, tuple) else (actual >= expected[1] if expected[0] == ">=" else actual <= expected[1])
    if matches:
        return EvaluationStatus.SATISFIED, (), actual, len(records)
    return EvaluationStatus.UNSATISFIED, (_diagnostic("AGGREGATE_MISMATCH", f"aggregate result {actual!r} does not satisfy {expected!r}", obligation_id=obligation.obligation_id, cause="aggregate-mismatch", repair_frontier=(f"obligation:{obligation.obligation_id}:aggregate",), details={"actual": actual, "expected": expected, "operator": operator}),), actual, len(records)


def _required_count(obligation, value, diagnostics):
    if isinstance(value, Mapping):
        result = value.get(obligation.obligation_id, 1)
    elif value is None:
        result = 1
    else:
        result = value
    if isinstance(result, bool) or not isinstance(result, int) or result < 1:
        diagnostics.append(_diagnostic("MULTIPLICITY_RULE_INVALID", "required multiplicity must be a positive integer", obligation_id=obligation.obligation_id, cause="multiplicity-rule-invalid", repair_frontier=(f"obligation:{obligation.obligation_id}:multiplicity",)))
        return 1
    return result


def _multiplicity_diagnostic(obligation, relevant, required, evidence_ids):
    if obligation.kind in {ProofMode.PRESENCE, ProofMode.AGGREGATE} and len(relevant) < required:
        return _diagnostic("MULTIPLICITY_UNSATISFIED", f"only {len(relevant)} distinct admitted evidence item(s) support a required multiplicity of {required}", obligation_id=obligation.obligation_id, evidence_ids=evidence_ids, cause="multiplicity-unsatisfied", repair_frontier=(f"obligation:{obligation.obligation_id}:multiplicity",), details={"required_count": required, "observed_count": len(relevant)})
    return None


def _evaluate_absence(obligation, relevant, evidence_ids, complete, producer):
    if complete is not True:
        return EvaluationStatus.UNKNOWN, [_diagnostic("INCOMPLETE_CAPTURE", "absence cannot be proved from an incomplete evidence capture", obligation_id=obligation.obligation_id, cause="incomplete-capture", repair_frontier=("capture:complete",))]
    if not producer:
        return EvaluationStatus.UNKNOWN, [_diagnostic("CAPTURE_PRODUCER_MISSING", "absence requires a named complete-capture producer", obligation_id=obligation.obligation_id, cause="capture-producer-missing", repair_frontier=("capture:producer",))]
    if relevant:
        return EvaluationStatus.UNSATISFIED, [_diagnostic("UNEXPECTED_EVIDENCE", "complete capture contains evidence matching an absence obligation", obligation_id=obligation.obligation_id, evidence_ids=evidence_ids, cause="unexpected-evidence", repair_frontier=(f"obligation:{obligation.obligation_id}:evidence",))]
    return EvaluationStatus.SATISFIED, []


def _evaluate_set(obligation, relevant, evidence_ids, capture_records, complete, producer, expected_ids):
    if complete is not True:
        return EvaluationStatus.UNKNOWN, [_diagnostic("INCOMPLETE_CAPTURE", "set equality cannot be proved from an incomplete evidence capture", obligation_id=obligation.obligation_id, cause="incomplete-capture", repair_frontier=("capture:complete",))], None, (), ()
    if not producer:
        return EvaluationStatus.UNKNOWN, [_diagnostic("CAPTURE_PRODUCER_MISSING", "set equality requires a named complete-capture producer", obligation_id=obligation.obligation_id, cause="capture-producer-missing", repair_frontier=("capture:producer",))], None, (), ()
    declared = _expected_for(obligation, expected_ids, capture_records)
    if declared is None:
        return EvaluationStatus.UNKNOWN, [_diagnostic("EXPECTED_SET_MISSING", "set equality has no declared expected member set", obligation_id=obligation.obligation_id, cause="expected-set-missing", repair_frontier=(f"obligation:{obligation.obligation_id}:expected-set",))], None, (), ()
    declared_ids = tuple(dict.fromkeys(declared))
    observed = tuple(_member_id(record) for record in relevant)
    duplicates = tuple(dict.fromkeys(item for item in observed if observed.count(item) > 1))
    missing = tuple(item for item in declared_ids if item not in set(observed))
    extra = tuple(item for item in observed if item not in set(declared_ids))
    if duplicates:
        return EvaluationStatus.UNSATISFIED, [_diagnostic("DUPLICATE_EVIDENCE", "set equality cannot use repeated member evidence as multiplicity", obligation_id=obligation.obligation_id, evidence_ids=evidence_ids, cause="duplicate-evidence", repair_frontier=(f"obligation:{obligation.obligation_id}:members",), details={"duplicate_ids": list(duplicates)})], len(declared_ids), observed, declared_ids
    if missing or extra or len(observed) != len(declared_ids):
        return EvaluationStatus.UNSATISFIED, [_diagnostic("SET_MISMATCH", "observed evidence membership does not equal the declared set", obligation_id=obligation.obligation_id, evidence_ids=evidence_ids, cause="set-mismatch", repair_frontier=(f"obligation:{obligation.obligation_id}:members",), details={"missing": list(missing), "extra": list(extra)})], len(declared_ids), observed, declared_ids
    return EvaluationStatus.SATISFIED, [], len(declared_ids), observed, declared_ids


def _evaluate_one(obligation, *, spec_hash, binding_hash, records, capture_records, capture_complete, capture_producer, expected_ids, aggregate, required_multiplicity, base_diagnostics=()):
    relevant = _relevant(records, obligation)
    evidence_ids = tuple(record.evidence_id for record in relevant)
    diagnostics = list(base_diagnostics)
    required = _required_count(obligation, required_multiplicity, diagnostics)
    multiplicity = _multiplicity_diagnostic(obligation, relevant, required, evidence_ids)
    if multiplicity is not None:
        diagnostics.append(multiplicity)
    expected_count = None
    observed_ids = ()
    declared_ids = ()
    aggregate_value = None
    if obligation.kind is ProofMode.PRESENCE:
        status = EvaluationStatus.SATISFIED if len(relevant) >= required else EvaluationStatus.UNSATISFIED
        if status is EvaluationStatus.UNSATISFIED:
            diagnostics.append(_diagnostic("MISSING_EVIDENCE", f"presence obligation requires {required} admitted evidence item(s)", obligation_id=obligation.obligation_id, evidence_ids=evidence_ids, cause="missing-evidence", repair_frontier=(f"obligation:{obligation.obligation_id}:evidence",), details={"required_count": required, "observed_count": len(relevant)}))
    elif obligation.kind is ProofMode.COMPLETE_CAPTURE_ABSENCE:
        status, mode = _evaluate_absence(obligation, relevant, evidence_ids, capture_complete, capture_producer)
        diagnostics.extend(mode)
    elif obligation.kind is ProofMode.SET_EQUALITY:
        status, mode, expected_count, observed_ids, declared_ids = _evaluate_set(obligation, relevant, evidence_ids, capture_records, capture_complete, capture_producer, expected_ids)
        diagnostics.extend(mode)
    else:
        status, mode, aggregate_value, expected_count = _evaluate_aggregate(obligation, relevant, _aggregate_rule(aggregate, obligation))
        diagnostics.extend(mode)
    return ObligationResult(obligation_id=obligation.obligation_id, status=status, kind=obligation.kind, spec_hash=spec_hash, binding_hash=binding_hash, required=obligation.required, evidence_ids=evidence_ids, diagnostics=diagnostics, observed_count=len(relevant), expected_count=expected_count, observed_ids=observed_ids, expected_ids=declared_ids, aggregate_value=aggregate_value)


__all__ = ["_evaluate_aggregate", "_evaluate_one"]
