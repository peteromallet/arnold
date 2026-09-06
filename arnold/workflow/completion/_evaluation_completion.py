"""Completion obligation/orchestration implementations."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .evaluation import (BlockedProof, CompletionBinding, CompletionSpec, CompletionVerdict, Diagnostic, EVIDENCE_SCHEMA_VERSION, EvaluationStatus, EvidenceRecord, Obligation, ObligationResult, ProofMode, TerminalPolicy, VerifierIndependence, WaiverProof, _coerce_binding, _coerce_evidence, _coerce_spec)
from .evaluation import propagate_waiver_taint, select_candidate, verify_verifier_independence
from ._evaluation_admission import _admit_records, _applicable_obligations, _capture_state, _deduplicate, _diagnostic
from ._evaluation_proofs import _evaluate_one


def evaluate_obligation_impl(obligation, evidence, *, spec_hash="", binding_hash="", complete_capture=None, capture_producer=None, expected_ids=None, aggregate=None, required_multiplicity=None):
    records = tuple(_coerce_evidence(item) for item in evidence)
    unique = _deduplicate(records)
    capture_records = tuple(item for item in unique if item.is_capture_marker)
    state, producer, capture_diagnostics = _capture_state(unique, complete_capture=complete_capture, capture_producer=capture_producer)
    return _evaluate_one(obligation, spec_hash=spec_hash, binding_hash=binding_hash, records=unique, capture_records=capture_records, capture_complete=state, capture_producer=producer, expected_ids=expected_ids, aggregate=aggregate, required_multiplicity=required_multiplicity, base_diagnostics=capture_diagnostics)


def _exceptional_inputs(exceptional_proof, blocked_proof, waiver_proof):
    if isinstance(exceptional_proof, WaiverProof):
        return blocked_proof, exceptional_proof
    if isinstance(exceptional_proof, BlockedProof):
        return exceptional_proof, waiver_proof
    if isinstance(exceptional_proof, Mapping):
        is_waiver = "authority_provenance" in exceptional_proof or str(exceptional_proof.get("outcome", "")).lower() == "waived"
        if is_waiver:
            return blocked_proof, exceptional_proof
        return exceptional_proof, waiver_proof
    return blocked_proof, waiver_proof


def _completion_inputs(spec, binding, evidence, candidate_outcome, outcome, expected_sets, expected_ids, aggregate_rules, aggregate, multiplicity, required_multiplicity, inherited_taint, waiver_taint, exceptional_proof, blocked_proof, waiver_proof):
    actual_spec, actual_binding = _coerce_spec(spec), _coerce_binding(binding)
    selected_outcome = outcome if outcome is not None else candidate_outcome
    blocked_proof, waiver_proof = _exceptional_inputs(exceptional_proof, blocked_proof, waiver_proof)
    expected = expected_sets if expected_sets is not None else expected_ids
    aggregate_value = aggregate_rules if aggregate_rules is not None else aggregate
    multiplicity_value = multiplicity if multiplicity is not None else required_multiplicity
    return {"spec": actual_spec, "binding": actual_binding, "evidence": tuple(evidence), "expected": expected, "aggregate": aggregate_value, "multiplicity": multiplicity_value, "outcome": selected_outcome, "taint": propagate_waiver_taint(inherited_taint, waiver_taint), "blocked_proof": blocked_proof, "waiver_proof": waiver_proof}


def _select_and_admit(ctx, declared_candidates, candidates, selected_candidate, applicability):
    spec, binding = ctx["spec"], ctx["binding"]
    selection, selection_diagnostic = None, None
    try:
        selection = select_candidate(ctx["outcome"], declared_candidates=declared_candidates, candidates=candidates, selected_candidate=selected_candidate)
        ctx["outcome"] = selection.selected_candidate
    except (TypeError, ValueError) as exc:
        selection_diagnostic = _diagnostic("CANDIDATE_SELECTION_INVALID", str(exc), cause="candidate-selection-invalid", repair_frontier=("candidate:selection",))
    identity = [selection_diagnostic] if selection_diagnostic is not None else []
    if binding.spec_hash != spec.spec_hash:
        identity.append(_diagnostic("REUSE_IDENTITY_MISMATCH", "binding spec_hash does not match the completion spec", cause="spec-binding-mismatch", repair_frontier=(f"spec:{spec.spec_hash}",), details={"spec_hash": spec.spec_hash, "binding_spec_hash": binding.spec_hash}))
    if not binding.is_canonical:
        identity.append(_diagnostic("LEGACY_BINDING_UNKNOWN", "C1 legacy coordinates cannot establish a C2 evidence scope", cause="legacy-binding-unknown", repair_frontier=("binding:migrate",)))
    admitted, admission = _admit_records(binding, ctx["evidence"])
    diagnostics = identity + list(admission)
    raw = spec.obligations or (Obligation(spec.obligation_id, ProofMode.PRESENCE, "primary completion evidence"),)
    applicable = raw
    if selection is not None:
        applicable, applicable_diagnostic = _applicable_obligations(selection, applicability, raw)
        if applicable_diagnostic is not None:
            diagnostics.append(applicable_diagnostic)
    ctx.update(selection=selection, identity=identity, admitted=admitted, diagnostics=diagnostics, raw_obligations=raw, applicable=applicable)
    return ctx


def _unknown(ctx, applicability=False, verifier="completion-shadow", verifier_version=EVIDENCE_SCHEMA_VERSION):
    spec, binding = ctx["spec"], ctx["binding"]
    diagnostics = ctx["diagnostics"]
    results = tuple(ObligationResult(obligation_id=item.obligation_id, status=EvaluationStatus.UNKNOWN, kind=item.kind, spec_hash=spec.spec_hash, binding_hash=binding.binding_hash, required=item.required, diagnostics=(tuple(d for d in diagnostics if d.obligation_id in {"", item.obligation_id}) if applicability else ctx["identity"])) for item in ctx["raw_obligations"])
    return CompletionVerdict(spec_hash=spec.spec_hash, binding_hash=binding.binding_hash, outcome=ctx["outcome"], obligation_results=results, evidence=ctx["admitted"], diagnostics=diagnostics, candidate_selection=ctx["selection"], taint=ctx["taint"], accepted=False, status=EvaluationStatus.UNKNOWN, verifier=verifier, verifier_version=verifier_version)


def _independence(ctx, verifier, verifier_provenance, required, independence):
    if independence is not None:
        verifier_provenance = independence
    actual = None
    if required or verifier_provenance is not None:
        actual = verify_verifier_independence(verifier_provenance, ctx["admitted"], verifier=verifier)
        if not actual.independent:
            ctx["diagnostics"].append(_diagnostic("VERIFIER_NOT_INDEPENDENT", "shadow verifier does not have independent implementation, producer, trust, and evidence provenance", cause="verifier-not-independent", repair_frontier=("verifier:independence",), details={"reasons": list(actual.reasons)}))
    ctx["independence"] = actual
    return ctx


def _typed_proof(value, proof_type, invalid_code, missing_code, label):
    diagnostic = None
    try:
        proof = value if isinstance(value, proof_type) else proof_type.from_dict(value) if value is not None else None
    except (TypeError, ValueError, KeyError) as exc:
        proof = None
        diagnostic = _diagnostic(invalid_code, str(exc), cause=f"{label}-proof-invalid", repair_frontier=(f"proof:{label}",))
    if proof is None and diagnostic is None:
        diagnostic = _diagnostic(missing_code, f"{label} candidate requires a typed {label} proof", cause=f"{label}-proof-missing", repair_frontier=(f"proof:{label}",))
    return proof, diagnostic


def _terminal_state(outcome, terminal_policy):
    diagnostic = None
    try:
        policy = terminal_policy if isinstance(terminal_policy, TerminalPolicy) else TerminalPolicy.from_dict(terminal_policy) if terminal_policy is not None else None
    except (TypeError, ValueError, KeyError) as exc:
        policy = None
        diagnostic = _diagnostic("TERMINAL_POLICY_INVALID", str(exc), cause="terminal-policy-invalid", repair_frontier=("policy:terminal",))
    if diagnostic is None and (policy is None or not policy.permits(outcome)):
        diagnostic = _diagnostic("NONTERMINAL_OUTCOME", f"{outcome} is nonterminal without an independently admitted terminal policy", cause="terminal-policy-missing", repair_frontier=("policy:terminal",))
    return policy, diagnostic, diagnostic is None


def _proof_state(outcome, blocked_proof, waiver_proof, terminal_policy, selected):
    if outcome == "blocked":
        proof, diagnostic = _typed_proof(blocked_proof, BlockedProof, "BLOCKED_PROOF_INVALID", "BLOCKED_PROOF_MISSING", "blocked")
        return proof, None, diagnostic, False
    if outcome == "waived":
        proof, diagnostic = _typed_proof(waiver_proof, WaiverProof, "WAIVER_PROOF_INVALID", "WAIVER_PROOF_MISSING", "waiver")
        return proof, None, diagnostic, False
    if outcome in {"suspended", "quarantined"}:
        policy, diagnostic, terminal = _terminal_state(outcome, terminal_policy)
        return None, policy, diagnostic, terminal
    if outcome not in {"success", "completed", "complete"}:
        diagnostic = _diagnostic("EXCEPTIONAL_PROOF_MISSING", "non-success candidate requires nontrivial typed proof", cause="exceptional-proof-missing", repair_frontier=(f"candidate:{selected}:proof",))
        return None, None, diagnostic, False
    return None, None, None, False


def _validate_proof(ctx, proof, policy, diagnostic):
    binding, admitted = ctx["binding"], ctx["admitted"]
    if proof is not None:
        ids, admitted_ids = set(proof.evidence_ids), {item.evidence_id for item in admitted}
        proof_binding = getattr(proof, "binding_hash", "")
        if proof_binding and proof_binding != binding.binding_hash:
            diagnostic = _diagnostic("PROOF_BINDING_MISMATCH", "exceptional proof is bound to a different completion binding", cause="proof-binding-mismatch", repair_frontier=(f"binding:{binding.binding_hash}",))
        elif not ids or not ids.issubset(admitted_ids):
            diagnostic = _diagnostic("PROOF_EVIDENCE_NOT_ADMITTED", "exceptional proof must cite admitted evidence in the exact scope", cause="proof-evidence-not-admitted", repair_frontier=(f"scope:{binding.evidence_scope.scope_hash}",), details={"missing_evidence_ids": sorted(ids - admitted_ids)})
    if policy is not None:
        admitted_ids = {item.evidence_id for item in admitted}
        if not set(policy.evidence_ids).issubset(admitted_ids):
            diagnostic = _diagnostic("TERMINAL_POLICY_EVIDENCE_NOT_ADMITTED", "terminal policy must cite admitted evidence in the exact scope", cause="terminal-policy-evidence-not-admitted", repair_frontier=(f"scope:{binding.evidence_scope.scope_hash}",), details={"missing_evidence_ids": sorted(set(policy.evidence_ids) - admitted_ids)})
    return diagnostic


def _exceptional(ctx, outcome, proof, policy, diagnostic, terminal, verifier, verifier_version):
    statuses = {"blocked": EvaluationStatus.BLOCKED, "waived": EvaluationStatus.WAIVED, "suspended": EvaluationStatus.SUSPENDED, "quarantined": EvaluationStatus.QUARANTINED}
    valid = diagnostic is None and not (ctx["independence"] is not None and not ctx["independence"].independent)
    status = statuses.get(outcome, EvaluationStatus.FAILED)
    spec, binding = ctx["spec"], ctx["binding"]
    results = tuple(ObligationResult(obligation_id=item.obligation_id, status=status if valid else EvaluationStatus.UNKNOWN, kind=item.kind, spec_hash=spec.spec_hash, binding_hash=binding.binding_hash, required=item.required, diagnostics=(diagnostic,) if diagnostic else ()) for item in ctx["applicable"])
    return CompletionVerdict(spec_hash=spec.spec_hash, binding_hash=binding.binding_hash, outcome=ctx["outcome"], obligation_results=results, evidence=ctx["admitted"], diagnostics=ctx["diagnostics"], candidate_selection=ctx["selection"], exceptional_proof=proof, terminal_policy=policy, terminal=terminal if outcome in {"suspended", "quarantined"} else valid, taint=ctx["taint"] | (proof.taint if isinstance(proof, WaiverProof) else frozenset()), verifier_independence=ctx["independence"], accepted=outcome == "waived" and valid, status=status if valid else EvaluationStatus.UNKNOWN, verifier=verifier, verifier_version=verifier_version)


def _normal(ctx, complete_capture, capture_producer, verifier, verifier_version):
    spec, binding = ctx["spec"], ctx["binding"]
    state, producer, capture_diagnostics = _capture_state(ctx["admitted"], complete_capture=complete_capture, capture_producer=capture_producer)
    ctx["diagnostics"].extend(capture_diagnostics)
    captures = tuple(item for item in ctx["admitted"] if item.is_capture_marker)
    results = tuple(_evaluate_one(item, spec_hash=spec.spec_hash, binding_hash=binding.binding_hash, records=ctx["admitted"], capture_records=captures, capture_complete=state, capture_producer=producer, expected_ids=ctx["expected"], aggregate=ctx["aggregate"], required_multiplicity=ctx["multiplicity"]) for item in ctx["applicable"])
    for result in results:
        ctx["diagnostics"].extend(result.diagnostics)
    unique = {}
    for item in ctx["diagnostics"]:
        unique.setdefault(item.diagnostic_hash, item)
    return CompletionVerdict(spec_hash=spec.spec_hash, binding_hash=binding.binding_hash, outcome=ctx["outcome"], obligation_results=results, evidence=ctx["admitted"], diagnostics=tuple(unique.values()), candidate_selection=ctx["selection"], taint=ctx["taint"], verifier_independence=ctx["independence"], verifier=verifier, verifier_version=verifier_version)


def evaluate_completion_impl(spec, binding, evidence=(), *, candidate_outcome="success", outcome=None, complete_capture=None, capture_producer=None, expected_ids=None, expected_sets=None, aggregate=None, aggregate_rules=None, required_multiplicity=None, multiplicity=None, verifier="completion-shadow", verifier_version=EVIDENCE_SCHEMA_VERSION, declared_candidates=None, candidates=None, selected_candidate=None, applicability=None, blocked_proof=None, waiver_proof=None, terminal_policy=None, verifier_provenance=None, require_verifier_independence=False, independence=None, inherited_taint=(), waiver_taint=(), exceptional_proof=None):
    ctx = _completion_inputs(spec, binding, evidence, candidate_outcome, outcome, expected_sets, expected_ids, aggregate_rules, aggregate, multiplicity, required_multiplicity, inherited_taint, waiver_taint, exceptional_proof, blocked_proof, waiver_proof)
    ctx = _select_and_admit(ctx, declared_candidates, candidates, selected_candidate, applicability)
    if ctx["identity"] or not ctx["binding"].is_canonical:
        return _unknown(ctx, verifier=verifier, verifier_version=verifier_version)
    if any(item.code.startswith("CIRCULAR_APPLICABILITY") or item.code.startswith("APPLICABILITY_") for item in ctx["diagnostics"]):
        return _unknown(ctx, applicability=True, verifier=verifier, verifier_version=verifier_version)
    ctx = _independence(ctx, verifier, verifier_provenance, require_verifier_independence, independence)
    normalized = str(ctx["outcome"]).strip().lower().replace("-", "_")
    proof, policy, diagnostic, terminal = _proof_state(normalized, ctx["blocked_proof"], ctx["waiver_proof"], terminal_policy, ctx["outcome"])
    diagnostic = _validate_proof(ctx, proof, policy, diagnostic)
    if diagnostic is not None:
        ctx["diagnostics"].append(diagnostic)
    if normalized not in {"success", "completed", "complete"}:
        return _exceptional(ctx, normalized, proof, policy, diagnostic, terminal, verifier, verifier_version)
    return _normal(ctx, complete_capture, capture_producer, verifier, verifier_version)


__all__ = ["evaluate_obligation_impl", "evaluate_completion_impl"]
