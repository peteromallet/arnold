from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone

from arnold_pipelines.megaplan.cloud.worker_dispatch import (
    AdmissionRefusal,
    WorkerAdmissionRequest,
    WorkerAdmissionReceipt,
    require_production_worker_dispatch_runtime,
)
from arnold_pipelines.megaplan.incident.ledger import IncidentLedger
from arnold_pipelines.megaplan.types import CliError
from tests.cloud.dispatch_test_helpers import native_proof


def request(tmp_path: Path, **changes: object) -> WorkerAdmissionRequest:
    values: dict[str, object] = {
        "plan_id": "plan",
        "phase": "execute",
        "dispatch_family_id": "family",
        "logical_dispatch_id": "logical",
        "physical_door_id": "door",
        "configured_spec": "codex:gpt-5.5",
        "selected_spec": "codex:gpt-5.5",
        "source_revision": "a" * 40,
        "runtime_vector": {"runtime": "native"},
        "manifest_identity": "manifest",
        "seed_identity": "seed",
        "dependency_interpreter_identity": "/python",
        "prompt_or_phase_input_identity": "prompt",
        "configured_fallback_chain_identity": "",
        "authorized_route_identity": "codex:gpt-5.5",
        "projection_key": "projection",
        "production_intent": False,
        "ledger_root": tmp_path,
        "route_liveness_resolver": lambda *_: {
            "kind": "native_backend",
            "identity": "backend",
            "digest": "b" * 64,
            "backend": "codex",
            "provider": "codex",
            "normalized_model": "gpt-5.5",
            "capability_registry": "test-native-registry",
            "proof": "test-native-proof",
            "route": "codex:gpt-5.5",
            "observed_at": "2026-01-01T00:00:00+00:00",
        },
        "memory_headroom_reader": lambda _spec: {"ok": True, "available_bytes": 10},
        "source_runtime_validator": lambda _request: {
            "ok": True,
            "source_revision": "a" * 40,
            "runtime_vector": {"runtime": "native"},
            "manifest_identity": "manifest",
            "seed_identity": "seed",
            "dependency_interpreter_identity": "/python",
        },
    }
    values.update(changes)
    return WorkerAdmissionRequest(**values)


def test_invalid_request_is_typed_and_happens_before_reservation(tmp_path: Path) -> None:
    result = require_production_worker_dispatch_runtime({"phase": "execute"})
    assert isinstance(result, AdmissionRefusal)
    assert result.code == "invalid_request"
    assert IncidentLedger(tmp_path).projection()["reservations"] == {}


def test_native_requires_positive_liveness_proof(tmp_path: Path) -> None:
    result = require_production_worker_dispatch_runtime(
        request(tmp_path, route_liveness_resolver=lambda *_: {})
    )
    assert isinstance(result, AdmissionRefusal)
    assert result.code == "route_liveness_invalid"


def test_omp_static_catalog_can_accept_expired_id_but_live_gate_rejects(tmp_path: Path) -> None:
    from arnold_pipelines.megaplan.workers.omp import validate_omp_catalog_model

    assert validate_omp_catalog_model("openrouter", "stealth/ox-alpha") == "openrouter/stealth/ox-alpha"
    result = require_production_worker_dispatch_runtime(
        request(
            tmp_path,
            configured_spec="omp:openrouter/stealth/ox-alpha",
            selected_spec="omp:openrouter/stealth/ox-alpha",
            authorized_route_identity="omp:openrouter/stealth/ox-alpha",
            route_liveness_resolver=lambda *_: (_ for _ in ()).throw(CliError("route_liveness_missing", "expired")),
        )
    )
    assert isinstance(result, AdmissionRefusal)
    assert result.code == "route_liveness_missing"


def test_new_logical_id_is_a_distinct_canonical_operation(tmp_path: Path) -> None:
    ledger = IncidentLedger(tmp_path)
    first = require_production_worker_dispatch_runtime(request(tmp_path, ledger=ledger))
    assert isinstance(first, WorkerAdmissionReceipt)
    second = require_production_worker_dispatch_runtime(
        request(tmp_path, logical_dispatch_id="another", ledger=ledger)
    )
    assert isinstance(second, WorkerAdmissionReceipt)
    assert second.logical_dispatch_id == "another"
    # IncidentLedger is not a launch registry; each physical operation is
    # represented by its own canonical operation identity.
    assert IncidentLedger(tmp_path).projection()["reservations"] == {}


def test_native_proof_recomputes_authoritative_content_generation_and_digest(tmp_path: Path) -> None:
    proof = native_proof(observed_at=datetime.now(timezone.utc).isoformat())
    result = require_production_worker_dispatch_runtime(
        request(
            tmp_path,
            native_construction_seam=lambda *_: proof,
            route_liveness_resolver=lambda *_: proof,
        )
    )
    assert isinstance(result, WorkerAdmissionReceipt)
    assert result.route_liveness_identity == proof["identity"]
    assert result.route_liveness_digest == proof["digest"]
    # Admission is observation-only; OperationRun admission is committed by
    # the physical dispatch transaction, not by this route-proof check.
    assert IncidentLedger(tmp_path).projection()["reservations"] == {}


def test_native_proof_rejects_stale_or_forged_proof_before_reservation(tmp_path: Path) -> None:
    authoritative = native_proof()
    forged = dict(authoritative, observed_at="1900-01-01T00:00:00+00:00", digest="f" * 64)
    result = require_production_worker_dispatch_runtime(
        request(
            tmp_path,
            native_construction_seam=lambda *_: authoritative,
            route_liveness_resolver=lambda *_: forged,
        )
    )
    assert isinstance(result, AdmissionRefusal)
    assert result.code == "route_liveness_invalid"
    assert IncidentLedger(tmp_path).projection()["reservations"] == {}


def test_native_proof_rejects_backend_provider_model_and_route_mismatch(tmp_path: Path) -> None:
    for field, value in (
        ("backend", "claude"),
        ("provider", "other"),
        ("normalized_model", "other-model"),
        ("route", "codex:other-model"),
    ):
        root = tmp_path / field
        proof = native_proof()
        mismatched = dict(proof, **{field: value})
        result = require_production_worker_dispatch_runtime(
            request(
                root,
                native_construction_seam=lambda *_: mismatched,
                route_liveness_resolver=lambda *_: mismatched,
            )
        )
        assert isinstance(result, AdmissionRefusal), field
        assert result.code == "route_liveness_invalid"
        assert IncidentLedger(root).projection()["reservations"] == {}


def test_native_proof_requires_exact_positive_constructability(tmp_path: Path) -> None:
    proof = native_proof()
    negative = dict(proof, proof={**proof["proof"], "constructable": False})
    result = require_production_worker_dispatch_runtime(
        request(
            tmp_path,
            native_construction_seam=lambda *_: negative,
            route_liveness_resolver=lambda *_: negative,
        )
    )
    assert isinstance(result, AdmissionRefusal)
    assert result.code == "route_liveness_invalid"
    assert IncidentLedger(tmp_path).projection()["reservations"] == {}


def test_production_native_proof_requires_construction_seam(tmp_path: Path) -> None:
    result = require_production_worker_dispatch_runtime(
        request(
            tmp_path,
            production_intent=True,
            native_construction_seam=None,
            route_liveness_resolver=lambda *_: native_proof(),
        )
    )
    assert isinstance(result, AdmissionRefusal)
    assert result.code == "production_input_substitution"
    assert IncidentLedger(tmp_path).projection()["reservations"] == {}


def test_native_authoritative_observation_must_be_fresh(tmp_path: Path) -> None:
    stale = native_proof(observed_at="1900-01-01T00:00:00+00:00")
    result = require_production_worker_dispatch_runtime(
        request(
            tmp_path,
            native_construction_seam=lambda *_: stale,
            route_liveness_resolver=lambda *_: stale,
        )
    )
    assert isinstance(result, AdmissionRefusal)
    assert result.code == "route_liveness_stale"
    assert IncidentLedger(tmp_path).projection()["reservations"] == {}
