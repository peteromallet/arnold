"""Canonical custody fixtures for the resident launch-contract slice.

The resident launch gate is intentionally strict.  These tests therefore issue
their own standalone seed against the temporary Git target and refresh the
current process attestation for every test, instead of depending on a runner
environment or a run-owned pytest plugin.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from arnold_pipelines.megaplan.cloud import runtime_attestation


_C1_TESTS = {
    "test_caller_request_id_cannot_change_discord_launch_identity",
    "test_inherited_discord_custody_commits_pending_outbox_before_process_start",
    "test_launch_time_duplicate_is_idempotent",
    "test_rejected_inbound_never_starts_a_working_reaction",
    "test_resident_runtime_sets_discord_reply_target_on_final_response",
    "test_burst_marks_every_source_but_completes_only_reply_target",
    "test_exhausted_timeout_delivers_specific_bounded_failure",
    "test_non_discord_outbound_has_no_reaction_lifecycle_calls",
    "test_timeout_recovery_records_diagnostics_without_duplicate_delivery",
    "test_working_starts_at_execution_not_receipt_and_duplicate_event_is_fenced",
    "test_receive_intercepts_eligible_discord_reply_before_fresh_resident_turn",
    "test_voice_transcript_is_the_exact_user_message_and_provenance_is_persisted",
    "test_confirmed_escalation_resolution_locks_clears_pointer_and_records_resume",
    "test_escalation_resolution_free_text_requests_confirmation_without_mutation",
    "test_discord_dispatch_preserves_target_provenance_and_launches_once",
    "test_discord_dispatch_rejects_missing_blank_or_duplicate_target",
    "test_unauthorized_or_internal_context_cannot_launch",
    "test_codex_background_launch_writes_durable_manifest",
    "test_discord_origin_flows_from_inbound_turn_into_managed_launch",
    "test_omp_resident_runner_persists_artifacts_and_resumes_exact_session",
    "test_auto_route_creates_one_durable_provider_manifest",
    "test_provider_timeout_is_enforced_and_captured_durably",
    "test_launch_retry_identity_includes_canonical_description",
    "test_direct_message_is_injected_and_response_is_not_normalized",
    "test_empty_authoritative_content_is_represented_without_fallback_request",
    "test_rapid_messages_are_bound_together_in_arrival_order",
    "test_reply_uses_current_reply_not_bounded_history_as_prompt_authority",
    "test_scheduled_audit_propagates_report_only_custody",
    "test_scheduled_turn_needs_no_parallel_request_summary",
    "test_scheduled_turn_uses_exact_inbound_content_without_a_summary_field",
    "test_superfixer_launch_origin_is_scheduled_turn_with_occurrence_custody",
    "test_live_followup_queues_exact_parent_interrupt_and_retry_is_idempotent",
}


def _base_test_name(nodeid: str) -> str:
    return nodeid.rsplit("::", 1)[-1].split("[", 1)[0]


def _git_target(root: Path) -> None:
    (root / ".c1-target-marker").write_text("resident C1 target\n", encoding="utf-8")
    (root / ".gitignore").write_text(".megaplan/\n", encoding="utf-8")
    subprocess.run(["git", "init", "--quiet", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "c1-tests@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "C1 tests"], check=True)
    subprocess.run(["git", "-C", str(root), "add", ".c1-target-marker", ".gitignore"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "--quiet", "-m", "C1 target fixture"], check=True)


@pytest.fixture(autouse=True)
def canonical_c1_launch_custody(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Issue a fresh standalone seed and process receipt for each C1 node."""

    if _base_test_name(request.node.nodeid) not in _C1_TESTS:
        return

    _git_target(tmp_path)
    runtime_root = Path(__file__).resolve().parents[2]
    project_revision = runtime_attestation._git_revision(tmp_path)
    runtime_revision = runtime_attestation._git_revision(runtime_root)
    seed = runtime_attestation.build_standalone_runtime_launch_seed(
        project_root=tmp_path,
        expected_project_revision=project_revision,
        runtime_root=runtime_root,
        expected_runtime_revision=runtime_revision,
    )
    assert seed["ready"] is True, seed
    paths = runtime_attestation.standalone_dispatch_paths(
        tmp_path,
        head=project_revision,
        seed_sha256=seed["content_sha256"],
    )
    runtime_attestation.write_standalone_runtime_publication(
        seed=seed,
        seed_path=paths["seed"],
        root=tmp_path,
    )
    monkeypatch.setenv("MEGAPLAN_RUNTIME_LAUNCH_SEED", str(paths["seed"]))
    monkeypatch.setenv("MEGAPLAN_RUNTIME_ATTESTATION_REQUIRED", "1")
    runtime_attestation.require_configured_runtime_launch("resident", create=True)
