from __future__ import annotations

import textwrap
from pathlib import Path

from arnold.conformance.checks import check_legacy_reference_allowlist
from arnold.conformance.suite import run_conformance_suite


def _write(root: Path, relative: str, content: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")
    return path


def test_allowlisted_scanner_target_passes(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "tests/conformance/test_deleted_root.py",
        """
        FORBIDDEN = "arnold.pipelines.megaplan"
        """,
    )

    result = check_legacy_reference_allowlist(
        repo_root=tmp_path,
        allowlist=[
            {
                "path": "tests/conformance/test_deleted_root.py",
                "pattern": "arnold.pipelines.megaplan",
                "category": "scanner-target",
                "reason": "Negative test fixture for the deleted package root.",
            }
        ],
    )

    assert result.passed is True
    assert result.check_id == "legacy-reference-allowlist"
    assert result.details["unallowlisted"] == []
    assert result.details["stale_allowlist"] == []


def test_unallowlisted_live_reference_fails(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "live.py",
        """
        VALUE = "arnold.pipelines.megaplan"
        """,
    )

    result = check_legacy_reference_allowlist(repo_root=tmp_path, allowlist=[])

    assert result.passed is False
    assert "unallowlisted legacy references" in result.message
    assert result.details["unallowlisted"] == [
        {
            "path": "live.py",
            "pattern": "arnold.pipelines.megaplan",
        }
    ]


def test_stale_allowlist_entry_fails(tmp_path: Path) -> None:
    _write(tmp_path, "docs/history.md", "No legacy references here.\n")

    result = check_legacy_reference_allowlist(
        repo_root=tmp_path,
        allowlist=[
            {
                "path": "docs/history.md",
                "pattern": "arnold/pipelines/megaplan",
                "category": "historical-non-shipped",
                "reason": "Historical note from a non-shipped migration document.",
            }
        ],
    )

    assert result.passed is False
    assert "stale legacy reference allowlist entries" in result.message
    assert result.details["stale_allowlist"] == [
        {
            "path": "docs/history.md",
            "pattern": "arnold/pipelines/megaplan",
        }
    ]


def test_malformed_allowlist_entry_fails(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "docs/history.md",
        "Historical note about arnold/pipelines/megaplan.\n",
    )

    result = check_legacy_reference_allowlist(
        repo_root=tmp_path,
        allowlist=[
            {
                "path": "docs/history.md",
                "pattern": "arnold/pipelines/megaplan",
                "category": "live-runtime",
                "reason": "Not an allowed category.",
            }
        ],
    )

    assert result.passed is False
    assert "invalid legacy reference allowlist entries" in result.message
    assert result.details["invalid_entries"][0]["errors"] == [
        "unsupported category 'live-runtime'"
    ]


def test_conformance_suite_includes_legacy_reference_allowlist_check() -> None:
    suite = run_conformance_suite()

    assert "legacy-reference-allowlist" in {check.check_id for check in suite.checks}
