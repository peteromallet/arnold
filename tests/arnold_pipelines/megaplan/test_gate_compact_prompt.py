"""Regression tests: gate prompt compaction fallback must bound the prompt while
staying fail-closed.

R7 superfixer 20260807: the cl2-ledger-replay gate failed fail-closed with
`prompt_oversized` (794,664 chars vs the 600,000 guard) because the gate prompt
embeds the full plan, full plan metadata, the complete gate signals dump (which
already contains the 54 unresolved flags as signals.unresolved_flags AND as a
top-level unresolved_flags duplicate), plus a separate open_flags block with the
same 54 flags.  The `review` phase already had a supported compaction fallback
(compact_review_prompt); gate was the bounded sibling missing it.

The fix adds `compact_gate_prompt` (mirroring compact_review_prompt) and wires it
into the hermes/shannon prompt_oversized fallback.  The 600K guard is NOT
weakened; the compact prompt must (a) fit under the guard, (b) preserve every
blocking flag id/severity/status/category/weight, and (c) keep all fail-closed
decision requirements verbatim.
"""

from __future__ import annotations

import json
from pathlib import Path

from arnold_pipelines.megaplan.prompts.gate import (
    COMPACT_GATE_FLAG_CONCERN_MAX_CHARS,
    COMPACT_GATE_FLAG_DETAIL_MAX_CHARS,
    COMPACT_GATE_META_MAX_CHARS,
    COMPACT_GATE_PLAN_MAX_CHARS,
    COMPACT_GATE_SIGNALS_MAX_CHARS,
    _compact_open_flags,
    _truncate_block,
    compact_gate_prompt,
)
from arnold_pipelines.megaplan.prompts import create_prompt
from arnold_pipelines.megaplan.prompts._projection import check_prompt_size


def _make_plan_dir(tmp_path: Path, flag_count: int = 54) -> Path:
    """Build a plan dir with many flags so the normal gate prompt is oversized."""
    plan_dir = tmp_path / "plans" / "demo-plan"
    plan_dir.mkdir(parents=True)
    plan_text = "# Plan\n\n" + ("## Task {i}\nlong plan body content line\n" * 1000)
    (plan_dir / "plan_v5.md").write_text(plan_text, encoding="utf-8")
    meta = {
        "success_criteria": [{"id": f"sc-{i}", "text": "criterion " * 120} for i in range(60)],
        "tasks": [{"id": f"task-{i}", "title": "task " * 80} for i in range(50)],
    }
    (plan_dir / "plan_v5.meta.json").write_text(json.dumps(meta), encoding="utf-8")
    flags = []
    for i in range(flag_count):
        flags.append(
            {
                "id": f"correctness-{i}",
                "concern": f"concern text for flag {i} " * 60,
                "evidence": f"evidence body {i} " * 50,
                "revise_summary": f"summary {i} " * 40,
                "category": "correctness",
                "severity": "significant",
                "status": "open",
                "weight": 2.0,
            }
        )
    unresolved = [dict(f, status="open") for f in flags]
    # The gate prompt's open_flags block comes from the flag registry (faults.json).
    (plan_dir / "faults.json").write_text(json.dumps({"flags": flags}), encoding="utf-8")
    gate_signals = {
        "robustness": "medium",
        "signals": {
            "iteration": 5,
            "unresolved_flags": [
                {"id": f["id"], "concern": f["concern"], "category": f["category"],
                 "severity": f["severity"], "status": f["status"]}
                for f in flags
            ],
            "resolved_flags": [
                {"id": f"resolved-{i}", "concern": f"resolved concern {i} " * 30,
                 "resolution": f"resolution {i} " * 20}
                for i in range(88)
            ],
            "weighted_score": 12.5,
            "addressed_flags": [],
        },
        "warnings": [],
        "criteria_check": {"passed": True},
        "preflight_results": [],
        "unresolved_flags": unresolved,
        "critique_custody": {"present": True},
    }
    (plan_dir / "gate_signals_v5.json").write_text(json.dumps(gate_signals), encoding="utf-8")
    return plan_dir


def _make_state(plan_dir: Path, project_dir: Path) -> dict:
    return {
        "name": "demo-plan",
        "iteration": 5,
        "plan_versions": [{"file": "plan_v5.md", "iteration": 5}],
        "config": {"project_dir": str(project_dir)},
        "meta": {},
    }


def test_normal_gate_prompt_is_oversized(tmp_path: Path) -> None:
    """The regression premise: with many flags the normal gate prompt exceeds 600K."""
    plan_dir = _make_plan_dir(tmp_path, flag_count=54)
    state = _make_state(plan_dir, tmp_path / "project")
    prompt = create_prompt("omp", "gate", state, plan_dir)
    assert len(prompt) > 600_000
    # and the guard actually fires for the gate phase
    try:
        check_prompt_size(prompt, phase="gate")
        raise AssertionError("expected prompt_oversized for oversized gate prompt")
    except Exception as exc:  # CliError
        assert getattr(exc, "code", "") == "prompt_oversized"


def test_compact_gate_prompt_under_limit_with_all_flag_ids(tmp_path: Path) -> None:
    """The compact fallback must fit under the guard and keep every flag id."""
    plan_dir = _make_plan_dir(tmp_path, flag_count=54)
    state = _make_state(plan_dir, tmp_path / "project")
    compact = compact_gate_prompt(
        state,
        plan_dir,
        tmp_path / "project",
        prompt_size_error={"prompt_size": 794_664, "max_chars": 600_000},
    )
    assert len(compact) <= 600_000
    # every open flag id must remain resolvable (fail-closed)
    for i in range(54):
        assert f"correctness-{i}" in compact
    # all fail-closed requirements remain
    assert "Valid flag IDs are:" in compact
    assert "flag_resolutions" in compact
    assert "PROCEED, ITERATE, ESCALATE, TIEBREAKER" in compact
    assert "baseline_presence" in compact
    assert "git cat-file -e" in compact
    # size note is present
    assert "compact prompt" in compact


def test_compact_gate_prompt_passes_phase_guard_via_workers(tmp_path: Path) -> None:
    """Both worker append paths (shannon contract / hermes file_fill) must stay
    under the gate phase guard after compaction."""
    plan_dir = _make_plan_dir(tmp_path, flag_count=54)
    state = _make_state(plan_dir, tmp_path / "project")
    compact = compact_gate_prompt(state, plan_dir, tmp_path / "project")
    # shannon appends the JSON output contract
    schema_text = json.dumps({"type": "object", "properties": {"recommendation": {"type": "string"}}})
    contract = (
        "\n\nOutput format:\n- Your final answer must be exactly one valid JSON object and nothing else.\n"
        "- Do not wrap the JSON in markdown fences. Do not include prose before or after it.\n"
        "- The JSON object must conform to this schema. If a field is markdown, put the markdown as a JSON string value.\n"
        + schema_text
        + "\n"
    )
    check_prompt_size(compact + contract, phase="gate")
    # hermes appends the file_fill OUTPUT FILE block
    file_fill = (
        f"\n\nOUTPUT FILE: {plan_dir / 'gate_output.json'}\n"
        "This file is your ONLY output. It contains a JSON template with the structure to fill in.\n"
        "Workflow:\n1. Start by reading the file to see the structure\n2. Do your work\n"
        "3. Read the file, add your results, write it back\n\n"
        "Do NOT put your results in a text response. The file is the only output that matters."
    )
    check_prompt_size(compact + file_fill, phase="gate")


def test_truncate_block_bounds_and_points_to_artifact() -> None:
    text = "x" * 10_000
    bounded = _truncate_block(text, limit=100, label="gate_signals_v5.json")
    assert len(bounded) < 10_000
    assert "truncated" in bounded
    assert "gate_signals_v5.json" in bounded


def test_compact_open_flags_preserves_decision_fields() -> None:
    flags = [
        {
            "id": "correctness-1",
            "concern": "c" * 5_000,
            "evidence": "e" * 2_000,
            "revise_summary": "r" * 2_000,
            "category": "correctness",
            "severity": "significant",
            "status": "open",
            "weight": 2.0,
        }
    ]
    compact = _compact_open_flags(flags)
    assert compact[0]["id"] == "correctness-1"
    assert compact[0]["category"] == "correctness"
    assert compact[0]["severity"] == "significant"
    assert compact[0]["status"] == "open"
    assert compact[0]["weight"] == 2.0
    assert len(compact[0]["concern"]) <= COMPACT_GATE_FLAG_CONCERN_MAX_CHARS + 512
    assert len(compact[0]["evidence"]) <= COMPACT_GATE_FLAG_DETAIL_MAX_CHARS + 512
    assert len(compact[0]["revise_summary"]) <= COMPACT_GATE_FLAG_DETAIL_MAX_CHARS + 512


def test_gate_prompt_includes_operator_decisions_block(tmp_path: Path) -> None:
    """The gate prompt must surface recorded source=user operator decisions
    (bd778acabe4d): without them the gate worker re-derives a stale halt on a
    question the operator already settled."""
    from arnold_pipelines.megaplan.prompts.gate import _gate_prompt

    plan_dir = _make_plan_dir(tmp_path, flag_count=1)
    state = _make_state(plan_dir, tmp_path / "project")
    state["meta"]["notes"] = [
        {
            "timestamp": "2026-08-18T10:31:29Z",
            "source": "user",
            "note": (
                "OPERATOR_DISPOSITION question_id=reigh-route-authority decision=DENIED. "
                "OPERATOR DECISION \u2014 reigh-route-authority: DENIED FOR M4."
            ),
        }
    ]
    prompt = _gate_prompt(state, plan_dir)
    assert "Recorded operator decisions (source=user):" in prompt
    assert "question_id: reigh-route-authority" in prompt
    assert "decision: DENIED" in prompt
    assert "mechanically_binding: true" in prompt
    assert "do not re-emit the same add_human_halt" in prompt


def test_compact_gate_prompt_includes_operator_decisions_block(tmp_path: Path) -> None:
    """The compact fallback must preserve every parsed question_id/decision."""
    plan_dir = _make_plan_dir(tmp_path, flag_count=1)
    state = _make_state(plan_dir, tmp_path / "project")
    state["meta"]["notes"] = [
        {
            "timestamp": "2026-08-18T10:31:29Z",
            "source": "user",
            "note": "OPERATOR_DISPOSITION question_id=reigh-route-authority decision=DENIED",
        }
    ]
    compact = compact_gate_prompt(state, plan_dir, tmp_path / "project")
    assert "Recorded operator decisions (source=user):" in compact
    assert "question_id: reigh-route-authority" in compact
    assert "decision: DENIED" in compact
    assert "mechanically_binding: true" in compact


def test_gate_prompt_marks_unparseable_user_note_non_binding(tmp_path: Path) -> None:
    """A source=user note that is NOT a parseable disposition is shown as
    informational (mechanically_binding: false), never as a disposition."""
    from arnold_pipelines.megaplan.prompts.gate import _gate_prompt

    plan_dir = _make_plan_dir(tmp_path, flag_count=1)
    state = _make_state(plan_dir, tmp_path / "project")
    state["meta"]["notes"] = [
        {
            "timestamp": "2026-08-18T10:31:29Z",
            "source": "user",
            "note": "still waiting on the external owner; not approved yet",
        }
    ]
    prompt = _gate_prompt(state, plan_dir)
    assert "mechanically_binding: false" in prompt
    assert "decision: (unparsed)" in prompt


def test_gate_prompt_omits_non_user_notes_from_decisions_block(tmp_path: Path) -> None:
    """Automated notes are not operator decisions and must not render."""
    from arnold_pipelines.megaplan.prompts.gate import _gate_prompt

    plan_dir = _make_plan_dir(tmp_path, flag_count=1)
    state = _make_state(plan_dir, tmp_path / "project")
    state["meta"]["notes"] = [
        {
            "timestamp": "2026-08-18T09:37:13Z",
            "source": "auto_approve_prep_clarification",
            "note": "converted prep clarification into planner assumptions",
        }
    ]
    prompt = _gate_prompt(state, plan_dir)
    assert "Recorded operator decisions (source=user):" not in prompt
