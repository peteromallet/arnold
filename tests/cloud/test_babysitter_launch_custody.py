"""Babysitter completion is independent of the retired chain-drive receipt."""

from __future__ import annotations

from arnold_pipelines.megaplan.cloud.babysitter import launch as babysitter


def test_babysitter_has_no_chain_drive_receipt_authority() -> None:
    assert not hasattr(babysitter, "_chain_drive_custody_error")
    assert not hasattr(babysitter, "_validate_chain_drive_receipt")
    assert not hasattr(babysitter, "CHAIN_DRIVE_RECEIPT_SCHEMA")


def test_terminal_returncode_preserves_watchdog_failure_visibility() -> None:
    assert babysitter._terminal_returncode(0, "failed") == 1
    assert babysitter._terminal_returncode(7, "failed") == 7
    assert babysitter._terminal_returncode(0, "completed") == 0
