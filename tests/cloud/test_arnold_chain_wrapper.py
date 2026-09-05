"""The cloud wrapper is a thin canonical-engine transport shim."""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WRAPPER = REPO_ROOT / "arnold_pipelines/megaplan/cloud/wrappers/arnold-chain"


def test_wrapper_requires_controller_authoritative_request() -> None:
    text = WRAPPER.read_text(encoding="utf-8")
    assert "ARNOLD_CHAIN_LAUNCH_REQUEST_B64" in text
    assert "authoritative launch request missing" in text


def test_wrapper_has_no_foreground_bypass_or_oom_redrive() -> None:
    text = WRAPPER.read_text(encoding="utf-8")
    assert "ARNOLD_CHAIN_REDRIVE_BACKOFF_SECONDS" not in text
    assert "oom_kill" not in text
    assert "redriving" not in text
    assert "chain start --spec" not in text
