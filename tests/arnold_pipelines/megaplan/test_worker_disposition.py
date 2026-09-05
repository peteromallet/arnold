from arnold_pipelines.megaplan.incident.schema import WorkerDisposition, ObservedProcessDeath, NonWorkerSignalDisposition, validate_nbf_event
from arnold_pipelines.megaplan.orchestration.phase_result import DispatchOutcome
from arnold_pipelines.megaplan.incident.disposition import observe_confirmation, consume_confirmation
from arnold_pipelines.megaplan.incident.ledger import IncidentLedger
import pytest
import json
import subprocess
import sys

WORKER = {"host": "test-host", "pid": 1234, "boot_id": "boot-1"}


def _d(**kw):
    base = dict(disposition_id="disp", mode="in_band", plan_id="p", phase="ph", dispatch_family_id="fam", logical_dispatch_id="log", admission_receipt_id="receipt", semantic_dispatch_fingerprint="f"*64, selected_spec="spec", killer_kind="watchdog", killer_identity="supervisor", cause_kind="wedge", signal="SIGTERM", elapsed_s=1.0, worker_identity=WORKER, observed_at="2026-01-01T00:00:00Z", evidence={"positive": True}, victim_pid=None, victim_process_start_identity=None, process_group_identity=None, timeout_source=None, ladder_step=None, confirmation_event_id=None)
    base.update(kw); return WorkerDisposition(**base)
def _outcome(kind, *, receipt="r"):
    payload = {
        "kind": kind,
        "launch_state": {
            "no_launch": "not_started",
            "unresolved_launch": "ambiguous",
        }.get(kind, "accepted"),
        "plan_id": "p",
        "phase": "ph",
        "dispatch_family_id": "fam",
        "logical_dispatch_id": "log",
        "admission_receipt_id": receipt,
        "semantic_dispatch_fingerprint": "f" * 64,
        "selected_spec": "spec",
        "worker_identity": WORKER,
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:01Z",
    }
    if kind in {"no_launch", "unresolved_launch"}:
        payload.update({
            "admission_receipt_id": None,
            "semantic_dispatch_fingerprint": None,
            "worker_identity": None,
            "started_at": None,
            "finished_at": None,
        })
    elif kind == "success":
        payload["success_payload"] = {"ok": True}
    elif kind == "ordinary_terminal_failure":
        payload["terminal_failure"] = {"error": "failed"}
    elif kind == "provider_exhausted":
        payload["provider_evidence"] = {
            "observation_id": "observation",
            "retryability_class": "availability",
            "exhausted_attempt_count": 1,
            "terminal_provider_evidence_id": "evidence",
            "precondition_identity": "precondition",
            "provider_epoch_identity": "epoch",
            "provider_failure_key": "a" * 64,
            "observed_at": "2026-01-01T00:00:00Z",
        }
    elif kind == "worker_disposition":
        payload["disposition_id"] = "disp"
    return DispatchOutcome(**payload)


def _terminal(outcome, **overrides):
    terminal = {
        "schema_version": 1,
        "event_type": "worker_terminal_outcome",
        "event_id": "terminal",
        "terminal_outcome_id": "terminal",
        "outcome_kind": outcome.kind,
        "plan_id": outcome.plan_id,
        "phase": outcome.phase,
        "projection_key": "pk",
        "reservation_key": "rk",
        "dispatch_family_id": outcome.dispatch_family_id,
        "logical_dispatch_id": outcome.logical_dispatch_id,
        "admission_receipt_id": outcome.admission_receipt_id,
        "reservation_event_id": "reservation",
        "semantic_dispatch_fingerprint": outcome.semantic_dispatch_fingerprint,
        "selected_spec": outcome.selected_spec,
        "physical_door_id": "door",
        "launch_state": outcome.launch_state,
        "worker_identity": outcome.worker_identity,
        "started_at": outcome.started_at,
        "finished_at": outcome.finished_at,
        "success_payload": outcome.success_payload,
        "terminal_failure": outcome.terminal_failure,
        "provider_evidence": outcome.provider_evidence,
        "provider_failure_key": outcome.provider_failure_key,
        "disposition_id": outcome.disposition_id,
        "execution_context_identity": "",
        "recorded_at": "2026-01-01T00:00:02Z",
        "actor": "test",
    }
    terminal.update(overrides)
    return terminal


def _assert_error(fragment, callback):
    with pytest.raises(ValueError) as exc_info:
        callback()
    assert fragment in str(exc_info.value)


def _terminal_ledger(tmp_path, outcome, suffix="terminal"):
    ledger = IncidentLedger(tmp_path / suffix)
    reservation = ledger.reserve(
        plan_id=outcome.plan_id,
        phase=outcome.phase,
        projection_key="pk",
        semantic_dispatch_fingerprint=outcome.semantic_dispatch_fingerprint,
        logical_dispatch_id=outcome.logical_dispatch_id,
        dispatch_family_id=outcome.dispatch_family_id,
        selected_spec=outcome.selected_spec,
    )
    receipt = reservation["payload"]["admission_receipt_id"]
    return ledger, reservation, receipt


def _observed_args(**overrides):
    args = dict(
        observation_id="observed",
        subject="worker",
        observation_source="watch",
        known_context_fields={"pid": 1},
        unknown_context_fields=(),
        victim_identity_evidence={"pid": 1},
        cause_kind="observed_dead_unknown",
        killer_kind="external_unknown",
        signal=None,
        positive_cgroup_delta=None,
        observed_at="2026-01-01T00:00:00Z",
        evidence={"x": 1},
    )
    args.update(overrides)
    return args


def _non_worker_args(**overrides):
    args = dict(
        disposition_id="nonworker",
        subject="non_worker_lifecycle",
        lifecycle_identity="lifecycle",
        killer_identity="supervisor",
        cause_kind="lifecycle_shutdown",
        signal="SIGTERM",
        victim_pid_or_group="group",
        victim_process_start_identity="start",
        observed_at="2026-01-01T00:00:00Z",
        evidence={"x": 1},
    )
    args.update(overrides)
    return args



def test_worker_disposition_round_trip_and_distinct_outcome():
    d = _d(); assert WorkerDisposition.from_dict(d.to_dict()) == d
    o = DispatchOutcome("worker_disposition", "accepted", "p", "ph", "fam", "log", "receipt", "f"*64, "spec", WORKER, "2026-01-01", "2026-01-02", disposition_id="disp")
    assert DispatchOutcome.from_dict(o.to_dict()).kind == "worker_disposition"


def test_disposition_rejects_oom_without_evidence():
    import pytest
    with pytest.raises(ValueError): _d(killer_kind="kernel_cgroup_oom", evidence={})


def test_term_and_kill_ladder_ids_are_distinct():
    assert WorkerDisposition.deterministic_id(receipt="r", signal="SIGTERM", ladder_step="term") != WorkerDisposition.deterministic_id(receipt="r", signal="SIGKILL", ladder_step="kill")


def test_outcome_never_coerces_disposition_to_failure():
    import pytest
    with pytest.raises(ValueError):
        DispatchOutcome("ordinary_terminal_failure", "accepted", "p", "ph", "fam", "log", "r", "f"*64, "spec", "worker", "start", "finish", disposition_id="disp")


def test_dispatch_outcome_incompatible_payload_matrix(tmp_path):
    cases = (
        ("no_launch", "success_payload", {"unexpected": True}, "no_launch cannot carry"),
        ("unresolved_launch", "provider_evidence", _outcome("provider_exhausted").provider_evidence, "no_launch cannot carry"),
        ("success", "terminal_failure", {"error": "bad"}, "success cannot carry"),
        ("ordinary_terminal_failure", "success_payload", {"bad": True}, "ordinary failure cannot carry"),
        ("provider_exhausted", "disposition_id", "disp", "provider exhaustion cannot carry"),
        ("worker_disposition", "success_payload", {"bad": True}, "worker_disposition cannot carry"),
    )
    for kind, field, value, expected in cases:
        legal = _outcome(kind)
        mutated = {**legal.to_dict(), field: value}
        _assert_error(expected, lambda: DispatchOutcome(**mutated))
        _assert_error(expected, lambda: DispatchOutcome.from_dict(mutated))

        terminal_base = _outcome("success") if kind in {"no_launch", "unresolved_launch"} else legal
        terminal = _terminal(terminal_base, outcome_kind=kind, **{field: value})
        if kind in {"no_launch", "unresolved_launch"}:
            _assert_error("invalid terminal outcome kind", lambda: validate_nbf_event(terminal))
            _assert_error("invalid terminal outcome kind", lambda: IncidentLedger(tmp_path / f"disp-{kind}").append_disposition(terminal))
        else:
            terminal_expected = {
                "success": "invalid success terminal payload",
                "ordinary_terminal_failure": "success_payload is only valid",
                "provider_exhausted": "only worker disposition terminals carry disposition_id",
                "worker_disposition": "invalid worker disposition success payload",
            }[kind]
            _assert_error(terminal_expected, lambda: validate_nbf_event(terminal))
            _assert_error(terminal_expected, lambda: IncidentLedger(tmp_path / f"disp-{kind}").append_disposition(terminal))

        mutated_for_append = {**legal.to_dict(), field: value}
        if kind in {"no_launch", "unresolved_launch"}:
            _assert_error(expected, lambda: IncidentLedger(tmp_path / f"terminal-{kind}").append_terminal_outcome(
                outcome=mutated_for_append,
                reservation_event_id="unused",
                projection_key="pk",
            ))
        else:
            terminal_ledger, reservation, _ = _terminal_ledger(tmp_path, legal, f"terminal-{kind}")
            _assert_error(expected, lambda: terminal_ledger.append_terminal_outcome(
                outcome=mutated_for_append,
                reservation_event_id=reservation["payload"]["event_id"],
                projection_key="pk",
            ))


def test_incompatible_scheduling_outcomes_still_have_no_terminal_event(tmp_path):
    for kind in ("no_launch", "unresolved_launch"):
        outcome = _outcome(kind)
        _assert_error(
            "scheduling outcomes have no worker terminal event",
            lambda outcome=outcome: IncidentLedger(tmp_path / kind).append_terminal_outcome(
                outcome=outcome,
                reservation_event_id="unused",
                projection_key="pk",
            ),
        )



def test_incompatible_matrix_rejects_at_public_terminal_append(tmp_path):
    cases = (
        ("no_launch", "success_payload", {"bad": True}, "no_launch cannot carry"),
        ("unresolved_launch", "provider_evidence", _outcome("provider_exhausted").provider_evidence, "no_launch cannot carry"),
        ("success", "terminal_failure", {"bad": True}, "success cannot carry"),
        ("ordinary_terminal_failure", "success_payload", {"bad": True}, "ordinary failure cannot carry"),
        ("provider_exhausted", "disposition_id", "disp", "provider exhaustion cannot carry"),
        ("worker_disposition", "success_payload", {"bad": True}, "worker_disposition cannot carry"),
    )
    for kind, field, value, expected in cases:
        if kind in {"no_launch", "unresolved_launch"}:
            legal = _outcome(kind)
            _assert_error(expected, lambda legal=legal, field=field, value=value, kind=kind: IncidentLedger(
                tmp_path / f"public-{kind}"
            ).append_terminal_outcome(
                outcome={**legal.to_dict(), field: value},
                reservation_event_id="unused",
                projection_key="pk",
            ))
            continue
        ledger, reservation, receipt = _terminal_ledger(
            tmp_path,
            _outcome(kind, receipt="placeholder"),
            f"public-{kind}",
        )
        legal = _outcome(kind, receipt=receipt)
        _assert_error(expected, lambda legal=legal, field=field, value=value: ledger.append_terminal_outcome(
            outcome={**legal.to_dict(), field: value},
            reservation_event_id=reservation["payload"]["event_id"],
            projection_key="pk",
        ))




def test_typed_identity_matrix_rejects_missing_and_fabricated_worker_at_all_doors(tmp_path):
    identities = (
        (None, "accepted outcome requires receipt, worker, and timing context"),
        ("bare-worker", "accepted outcome requires a typed worker identity"),
        (7, "accepted outcome requires a typed worker identity"),
        ([], "accepted outcome requires a typed worker identity"),
        ({"host": "h", "pid": 1}, "accepted outcome worker identity is incomplete"),
        ({"host": "h", "pid": 0, "boot_id": "b"}, "accepted outcome worker identity pid is malformed"),
        ({"host": 1, "pid": 1, "boot_id": "b"}, "accepted outcome worker identity is malformed"),
        ({"host": "h", "pid": 1, "boot_id": 1}, "accepted outcome worker identity is malformed"),
    )
    for identity, expected in identities:
        legal = _outcome("success")
        mutated = {**legal.to_dict(), "worker_identity": identity}
        _assert_error(expected, lambda mutated=mutated: DispatchOutcome(**mutated))
        _assert_error(expected, lambda mutated=mutated: DispatchOutcome.from_dict(mutated))

        terminal = _terminal(legal, worker_identity=identity)
        _assert_error(
            "worker_terminal_outcome.worker_identity",
            lambda terminal=terminal: validate_nbf_event(terminal),
        )
        _assert_error(
            "worker_terminal_outcome.worker_identity",
            lambda terminal=terminal: IncidentLedger(tmp_path / f"identity-disposition-{repr(identity)}").append_disposition(terminal),
        )

        ledger, reservation, receipt = _terminal_ledger(
            tmp_path,
            _outcome("success", receipt="placeholder"),
            f"identity-terminal-{repr(identity)}",
        )
        outcome_dict = {**_outcome("success", receipt=receipt).to_dict(), "worker_identity": identity}
        _assert_error(
            "accepted outcome",
            lambda outcome_dict=outcome_dict, ledger=ledger, reservation=reservation: ledger.append_terminal_outcome(
                outcome=outcome_dict,
                reservation_event_id=reservation["payload"]["event_id"],
                projection_key="pk",
            ),
        )

    valid = _outcome("success")
    _assert_error(
        "unsupported DispatchOutcome schema_version",
        lambda: DispatchOutcome.from_dict({**valid.to_dict(), "schema_version": 2}),
    )
    _assert_error(
        "unsupported DispatchOutcome schema_version",
        lambda: DispatchOutcome(**{**valid.to_dict(), "schema_version": 2}),
    )
    terminal = _terminal(valid, schema_version=2)
    _assert_error("unsupported NBF schema version", lambda: validate_nbf_event(terminal))
    _assert_error(
        "unsupported NBF schema version",
        lambda: IncidentLedger(tmp_path / "identity-version").append_disposition(terminal),
    )
    ledger, reservation, receipt = _terminal_ledger(
        tmp_path,
        _outcome("success", receipt="placeholder"),
        "identity-terminal-version",
    )
    versioned_outcome = {**_outcome("success", receipt=receipt).to_dict(), "schema_version": 2}
    _assert_error(
        "unsupported DispatchOutcome schema_version",
        lambda: ledger.append_terminal_outcome(
            outcome=versioned_outcome,
            reservation_event_id=reservation["payload"]["event_id"],
            projection_key="pk",
        ),
    )

    disposition = _d()
    disposition_versioned = {**disposition.to_dict(), "schema_version": 2}
    _assert_error(
        "unsupported WorkerDisposition schema_version",
        lambda: WorkerDisposition(**{**disposition.to_dict(), "schema_version": 2}),
    )
    _assert_error(
        "unsupported WorkerDisposition schema_version",
        lambda: WorkerDisposition.from_dict(disposition_versioned),
    )
    _assert_error(
        "unsupported WorkerDisposition schema_version",
        lambda: IncidentLedger(tmp_path / "worker-disposition-version").append_disposition(disposition_versioned),
    )




def test_no_launch_rejects_accepted_launch_state():
    import pytest
    with pytest.raises(ValueError):
        DispatchOutcome("no_launch", "accepted", "p", "ph", "fam", "l", None, None, "spec")


def test_unresolved_launch_rejects_success_provider_failure_disposition_payloads():
    import pytest
    with pytest.raises(ValueError):
        DispatchOutcome("unresolved_launch", "ambiguous", "p", "ph", "fam", "l", None, None, "spec", success_payload={"x": 1})


def test_success_rejects_provider_and_disposition_payloads():
    import pytest
    with pytest.raises(ValueError):
        DispatchOutcome("success", "accepted", "p", "ph", "fam", "l", "r", "f" * 64, "spec", "w", "s", "f", disposition_id="d")


def test_oom_rejects_falsey_or_negative_cgroup_evidence(tmp_path):
    import pytest
    for evidence in ({"positive": False, "delta_bytes": 10}, {"positive": True, "delta_bytes": 0}, {"positive": True, "delta_bytes": -1}):
        with pytest.raises(ValueError): _d(killer_kind="kernel_cgroup_oom", evidence=evidence)
        with pytest.raises(ValueError):
            IncidentLedger(tmp_path).append_disposition({**_d().to_dict(), "killer_kind": "kernel_cgroup_oom", "evidence": evidence})


def test_legal_positive_oom_appends(tmp_path):
    record = IncidentLedger(tmp_path).append_disposition(_d(killer_kind="kernel_cgroup_oom", signal="SIGKILL", cause_kind="cgroup_oom", evidence={"positive": True, "delta_bytes": 10}))
    assert record["payload"]["killer_kind"] == "kernel_cgroup_oom"


def test_legal_unknown_death_remains_unknown_after_append(tmp_path):
    args = dict(observation_id="unknown", subject="external_process", observation_source="watch", known_context_fields={}, unknown_context_fields=("worker",), victim_identity_evidence={"pid": 1}, cause_kind="observed_dead_unknown", killer_kind="external_unknown", signal=None, positive_cgroup_delta=None, observed_at="2026-01-01", evidence={"x": 1})
    ledger = IncidentLedger(tmp_path)
    ledger.append_disposition(ObservedProcessDeath(**args))
    replayed = ledger.projection()
    assert any(item.get("killer_kind") == "external_unknown" and item.get("signal") is None for item in replayed["dispositions"].values()) is False
    assert any(record["payload"].get("event_type") == "observed_process_death" and record["payload"].get("killer_kind") == "external_unknown" and record["payload"].get("signal") is None for record in ledger.read_nbf_events())


def test_unknown_death_rejects_fabricated_killer_and_signal(tmp_path):
    import pytest
    args = dict(observation_id="o", subject="worker", observation_source="watch", known_context_fields={"pid": 1}, unknown_context_fields=(), victim_identity_evidence={"pid": 1}, cause_kind="observed_dead_unknown", killer_kind="external_unknown", signal=None, positive_cgroup_delta=None, observed_at="2026-01-01", evidence={"x": 1})
    ObservedProcessDeath(**args)
    with pytest.raises(ValueError): ObservedProcessDeath(**{**args, "killer_kind": "watchdog"})
    with pytest.raises(ValueError): ObservedProcessDeath(**{**args, "signal": "SIGKILL"})
    with pytest.raises(ValueError): IncidentLedger(tmp_path).append_disposition({**ObservedProcessDeath(**args).to_dict(), "killer_kind": "watchdog"})


def test_worker_disposition_rejects_success_payload_at_append(tmp_path):
    outcome = _outcome("worker_disposition")
    terminal = _terminal(outcome, success_payload={"bad": True})
    _assert_error(
        "invalid worker disposition success payload",
        lambda: IncidentLedger(tmp_path).append_disposition(terminal),
    )



def test_observed_and_non_worker_reject_missing_schema_version_and_identity(tmp_path):
    observed_cases = (
        ("subject", None, "ObservedProcessDeath subject must be worker or external_process"),
        ("subject", "fabricated-subject", "ObservedProcessDeath subject must be worker or external_process"),
        ("cause_kind", None, "observed death must remain an explicit unknown/OOM cause"),
        ("cause_kind", "timeout", "observed death must remain an explicit unknown/OOM cause"),
        ("killer_kind", None, "unknown death must use external_unknown and no signal"),
        ("killer_kind", "watchdog", "unknown death must use external_unknown and no signal"),
        ("victim_identity_evidence", None, "victim identity evidence must be a typed object"),
        ("victim_identity_evidence", "fabricated-victim", "victim identity evidence must be a typed object"),
        ("victim_identity_evidence", [], "victim identity evidence must be a typed object"),
    )
    for field, value, expected in observed_cases:
        args = _observed_args(**{field: value})
        valid = ObservedProcessDeath(**_observed_args())
        mutated = {**valid.to_dict(), field: value}
        _assert_error(expected, lambda args=args: ObservedProcessDeath(**args))
        _assert_error(expected, lambda mutated=mutated: ObservedProcessDeath.from_dict(mutated))
        _assert_error(expected, lambda mutated=mutated: validate_nbf_event(mutated))
        _assert_error(
            expected,
            lambda mutated=mutated, field=field: IncidentLedger(
                tmp_path / f"observed-{field}-{repr(value)}"
            ).append_disposition(mutated),
        )

    observed = ObservedProcessDeath(**_observed_args())
    versioned = {**observed.to_dict(), "schema_version": 2}
    _assert_error("invalid observed process death schema", lambda: ObservedProcessDeath(**{**_observed_args(), "schema_version": 2}))
    _assert_error("invalid observed process death schema", lambda: ObservedProcessDeath.from_dict(versioned))
    _assert_error("invalid observed process death schema", lambda: validate_nbf_event(versioned))
    _assert_error(
        "invalid observed process death schema",
        lambda: IncidentLedger(tmp_path / "observed-version").append_disposition(versioned),
    )

    non_worker_cases = (
        ("lifecycle_identity", None, "lifecycle_identity must be a non-empty string"),
        ("lifecycle_identity", 0, "lifecycle_identity must be a non-empty string"),
        ("lifecycle_identity", {}, "lifecycle_identity must be a non-empty string"),
        ("subject", "worker", "invalid non-worker disposition subject or signal"),
        ("cause_kind", "wedge", "invalid non-worker disposition subject or signal"),
    )
    for field, value, expected in non_worker_cases:
        valid = NonWorkerSignalDisposition(**_non_worker_args())
        mutated = {**valid.to_dict(), field: value}
        args = _non_worker_args(**{field: value})
        _assert_error(expected, lambda args=args: NonWorkerSignalDisposition(**args))
        _assert_error(expected, lambda mutated=mutated: NonWorkerSignalDisposition.from_dict(mutated))
        _assert_error(expected, lambda mutated=mutated: validate_nbf_event(mutated))
        _assert_error(
            expected,
            lambda mutated=mutated, field=field: IncidentLedger(
                tmp_path / f"non-worker-{field}-{repr(value)}"
            ).append_disposition(mutated),
        )

    non_worker = NonWorkerSignalDisposition(**_non_worker_args())
    versioned = {**non_worker.to_dict(), "schema_version": 2}
    _assert_error("invalid non-worker disposition schema", lambda: NonWorkerSignalDisposition(**{**_non_worker_args(), "schema_version": 2}))
    _assert_error("invalid non-worker disposition schema", lambda: NonWorkerSignalDisposition.from_dict(versioned))
    _assert_error("invalid non-worker disposition schema", lambda: validate_nbf_event(versioned))
    _assert_error(
        "invalid non-worker disposition schema",
        lambda: IncidentLedger(tmp_path / "non-worker-version").append_disposition(versioned),
    )



def _run_cli(root, payload):
    return subprocess.run([sys.executable, "-m", "arnold_pipelines.megaplan.incident.disposition", "record", "--ledger-root", str(root), "--json-stdin"], input=json.dumps(payload), text=True, capture_output=True, cwd="/Users/peteromalley/Documents/Arnold-oracle-nbf")


def _cli_worker_payload(*, disposition_id="d", confirmation_id=None):
    return _d(disposition_id=disposition_id, admission_receipt_id="receipt", victim_pid=4, victim_process_start_identity="start", confirmation_event_id=confirmation_id, evidence={"relevant_progress_identity": "progress", "supervisor_incarnation_identity": "incarnation", "alive": True}).to_dict()


def test_cli_status_0_one_json_ack_no_signal(tmp_path):
    ledger = IncidentLedger(tmp_path)
    first = observe_confirmation(ledger, site_id="watch", subject_class="worker", plan_id="p", admission_receipt_id="receipt", victim_pid=4, victim_process_start_identity="start", relevant_progress_identity="progress", supervisor_incarnation_identity="incarnation", cause_kind="wedge", scan_interval_s=1, observed_at="2026-01-01T00:00:00Z", evidence={"relevant_progress_identity": "progress", "supervisor_incarnation_identity": "incarnation", "alive": True})
    cid = first["payload"]["confirmation_id"]
    consume_confirmation(ledger, confirmation_id_value=cid, second_observed_at="2026-01-01T00:00:01Z", second_evidence={"relevant_progress_identity": "progress", "supervisor_incarnation_identity": "incarnation", "alive": True}, victim_pid=4, victim_process_start_identity="start", relevant_progress_identity="progress", supervisor_incarnation_identity="incarnation", cause_kind="wedge", scan_interval_s=1, expires_at=1767225630.0, confirmation_policy_identity="default-v1", schema_version=1, disposition_id="d")
    result = _run_cli(tmp_path, _cli_worker_payload(confirmation_id=cid))
    assert result.returncode == 0
    assert len(result.stdout.splitlines()) == 1
    assert json.loads(result.stdout)["disposition_id"] == "d"
    assert result.stderr == ""


def test_cli_status_2_malformed_or_schema(tmp_path):
    malformed = subprocess.run([sys.executable, "-m", "arnold_pipelines.megaplan.incident.disposition", "record", "--ledger-root", str(tmp_path), "--json-stdin"], input="{", text=True, capture_output=True, cwd="/Users/peteromalley/Documents/Arnold-oracle-nbf")
    invalid = _run_cli(tmp_path, {"event_type": "worker_disposition"})
    assert malformed.returncode == 2 and invalid.returncode == 2


def test_cli_status_3_append_or_lock_failure(tmp_path):
    ledger = IncidentLedger(tmp_path)
    ledger.events_path.parent.mkdir(parents=True, exist_ok=True)
    ledger.events_path.mkdir()
    payload = NonWorkerSignalDisposition("nonworker", "non_worker_lifecycle", "life", "supervisor", "lifecycle_shutdown", "SIGTERM", "group", "start", "2026-01-01T00:00:00Z", {}).to_dict()
    result = _run_cli(tmp_path, payload)
    assert result.returncode == 3


def test_cli_status_4_invalid_ledger_location(tmp_path):
    location = tmp_path / "not-a-directory"
    location.write_text("not a ledger", encoding="utf-8")
    result = _run_cli(location, NonWorkerSignalDisposition("nonworker", "non_worker_lifecycle", "life", "supervisor", "lifecycle_shutdown", "SIGTERM", "group", "start", "2026-01-01T00:00:00Z", {}).to_dict())
    assert result.returncode == 4


def test_cli_status_5_missing_and_already_consumed_confirmation(tmp_path):
    missing = _run_cli(tmp_path, _cli_worker_payload(confirmation_id=None))
    assert missing.returncode == 5
    ledger = IncidentLedger(tmp_path)
    first = observe_confirmation(ledger, site_id="watch", subject_class="worker", plan_id="p", admission_receipt_id="receipt", victim_pid=4, victim_process_start_identity="start", relevant_progress_identity="progress", supervisor_incarnation_identity="incarnation", cause_kind="wedge", scan_interval_s=1, observed_at="2026-01-01T00:00:00Z", evidence={"relevant_progress_identity": "progress", "supervisor_incarnation_identity": "incarnation", "alive": True})
    cid = first["payload"]["confirmation_id"]
    consume_confirmation(ledger, confirmation_id_value=cid, second_observed_at="2026-01-01T00:00:01Z", second_evidence={"relevant_progress_identity": "progress", "supervisor_incarnation_identity": "incarnation", "alive": True}, victim_pid=4, victim_process_start_identity="start", relevant_progress_identity="progress", supervisor_incarnation_identity="incarnation", cause_kind="wedge", scan_interval_s=1, expires_at=1767225630.0, confirmation_policy_identity="default-v1", schema_version=1, disposition_id="different")
    already_used = _run_cli(tmp_path, _cli_worker_payload(confirmation_id=cid))
    assert already_used.returncode == 5


def test_cli_status_5_expired_confirmation(tmp_path):
    ledger = IncidentLedger(tmp_path)
    first = observe_confirmation(ledger, site_id="watch", subject_class="worker", plan_id="p", admission_receipt_id="receipt", victim_pid=4, victim_process_start_identity="start", relevant_progress_identity="progress", supervisor_incarnation_identity="incarnation", cause_kind="wedge", scan_interval_s=1, observed_at="2026-01-01T00:00:00Z", evidence={"relevant_progress_identity": "progress", "supervisor_incarnation_identity": "incarnation", "alive": True})
    cid = first["payload"]["confirmation_id"]
    ledger.expire_confirmation(cid, observed_at="2026-01-01T00:01:00Z")
    result = _run_cli(tmp_path, _cli_worker_payload(confirmation_id=cid))
    assert result.returncode == 5


def test_cli_status_5_distinct_already_consumed_replay(tmp_path):
    ledger = IncidentLedger(tmp_path)
    first = observe_confirmation(ledger, site_id="watch", subject_class="worker", plan_id="p", admission_receipt_id="receipt", victim_pid=4, victim_process_start_identity="start", relevant_progress_identity="progress", supervisor_incarnation_identity="incarnation", cause_kind="wedge", scan_interval_s=1, observed_at="2026-01-01T00:00:00Z", evidence={"relevant_progress_identity": "progress", "supervisor_incarnation_identity": "incarnation", "alive": True})
    cid = first["payload"]["confirmation_id"]
    consume_confirmation(ledger, confirmation_id_value=cid, second_observed_at="2026-01-01T00:00:01Z", second_evidence={"relevant_progress_identity": "progress", "supervisor_incarnation_identity": "incarnation", "alive": True}, victim_pid=4, victim_process_start_identity="start", relevant_progress_identity="progress", supervisor_incarnation_identity="incarnation", cause_kind="wedge", scan_interval_s=1, expires_at=1767225630.0, confirmation_policy_identity="default-v1", schema_version=1, disposition_id="d")
    first_cli = _run_cli(tmp_path, _cli_worker_payload(confirmation_id=cid))
    second_cli = _run_cli(tmp_path, _cli_worker_payload(confirmation_id=cid))
    assert first_cli.returncode == 0 and second_cli.returncode == 5
