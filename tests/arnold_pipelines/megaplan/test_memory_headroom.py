"""Pre-dispatch cgroup memory headroom gate tests (occurrence 1ac805e5eef9).

Covers the fail-closed/attribution contract of
``arnold_pipelines.megaplan.runtime.memory_headroom``:

* cgroup-unreadable classifies ``ok=None`` (never fabricate headroom);
* fictional swap (``memory.swap.max > 0`` with no host swap) contributes zero;
* insufficient headroom for a high-memory spec selects the configured fallback;
* a scalar unsafe chain returns ``None`` so the caller fails typed;
* a recent proven same-phase/same-spec cgroup OOM forces fallback (learned-death
  cooldown); an aged death expires and the spec re-enters selection;
* an unrelated phase/spec death is never reused.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from arnold_pipelines.megaplan.runtime import memory_headroom as mh
from arnold_pipelines.megaplan.runtime.memory_headroom import (
    classify_memory_headroom,
    death_cause_from_markers,
    is_high_memory_spec,
    memory_cooldown_wait_secs,
    prior_cgroup_oom_deaths,
    read_cgroup_memory_snapshot,
    record_dispatch_memory_marker,
    select_memory_safe_spec,
)

OX_ALPHA = "omp:openrouter/stealth/ox-alpha"
FLASH = "omp:deepseek/deepseek-v4-flash"


def _write_cgroup_v2(
    tmp_path: Path,
    monkeypatch,
    *,
    maximum: str,
    available_kib: int = 25_690_112,
) -> Path:
    cgroup = tmp_path / "cgroup"
    cgroup.mkdir()
    (cgroup / "memory.current").write_text("3139612672\n", encoding="utf-8")
    (cgroup / "memory.max").write_text(f"{maximum}\n", encoding="utf-8")
    (cgroup / "memory.swap.max").write_text("max\n", encoding="utf-8")
    (cgroup / "memory.events").write_text("oom_kill 0\n", encoding="utf-8")
    meminfo = tmp_path / "meminfo"
    meminfo.write_text(
        "MemTotal:       32086424 kB\n"
        f"MemAvailable:   {available_kib} kB\n"
        "SwapTotal:             0 kB\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(mh, "_CGROUP_BASE", cgroup)
    monkeypatch.setattr(mh, "_MEMINFO_PATH", meminfo, raising=False)
    return cgroup


def _snapshot(
    *,
    current: int,
    maximum: int = 8 * 1024**3,
    swap_max: int = 0,
    host_swap: int = 0,
    oom_kill: int = 0,
) -> dict:
    return {
        "memory_current": current,
        "memory_max": maximum,
        "memory_swap_max": swap_max,
        "memory_events": {"oom_kill": oom_kill},
        "host_swap_total": host_swap,
    }


def test_high_memory_tokens_cover_ox_alpha_only() -> None:
    assert is_high_memory_spec(OX_ALPHA)
    assert is_high_memory_spec("omp:stealth/ox-alpha")
    assert not is_high_memory_spec(FLASH)
    assert not is_high_memory_spec("claude:claude-sonnet-4-6")


def test_unreadable_cgroup_fails_closed_for_high_memory() -> None:
    result = classify_memory_headroom(OX_ALPHA, None)
    assert result["ok"] is None
    assert result["reason"] == "unknown_cgroup_data"


def test_cgroup_v2_unlimited_limit_uses_host_memavailable_without_swap(
    tmp_path: Path, monkeypatch
) -> None:
    _write_cgroup_v2(tmp_path, monkeypatch, maximum="max")

    snapshot = read_cgroup_memory_snapshot()

    assert snapshot is not None
    assert snapshot["memory_current"] == 3_139_612_672
    assert snapshot["memory_max"] == "max"
    assert snapshot["memory_swap_max"] == "max"
    assert snapshot["host_mem_available"] == 25_690_112 * 1024
    assert snapshot["host_swap_total"] == 0
    result = classify_memory_headroom(FLASH, snapshot)
    assert result["ok"] is True
    assert result["usable_bytes"] == 25_690_112 * 1024
    assert result["usable_swap_bytes"] == 0
    assert result["memory_limit_unlimited"] is True


def test_cgroup_v2_unlimited_limit_respects_insufficient_host_availability(
    tmp_path: Path, monkeypatch
) -> None:
    _write_cgroup_v2(tmp_path, monkeypatch, maximum="max", available_kib=128 * 1024)

    result = classify_memory_headroom(FLASH, read_cgroup_memory_snapshot())

    assert result["ok"] is False
    assert result["headroom_bytes"] == 128 * 1024**2
    assert result["reason"] == "insufficient_headroom"


def test_cgroup_v2_unlimited_limit_without_memavailable_fails_closed(
    tmp_path: Path, monkeypatch
) -> None:
    _write_cgroup_v2(tmp_path, monkeypatch, maximum="max")
    (tmp_path / "meminfo").write_text("SwapTotal:             0 kB\n", encoding="utf-8")

    assert read_cgroup_memory_snapshot() is None
    assert classify_memory_headroom(FLASH, None) == {
        "ok": None,
        "reason": "unknown_cgroup_data",
    }


@pytest.mark.parametrize("unit", [None, "bytes"])
def test_cgroup_v2_unlimited_limit_rejects_malformed_memavailable_unit(
    tmp_path: Path, monkeypatch, unit: str | None
) -> None:
    _write_cgroup_v2(tmp_path, monkeypatch, maximum="max")
    suffix = "" if unit is None else f" {unit}"
    (tmp_path / "meminfo").write_text(
        f"MemAvailable:   25690112{suffix}\nSwapTotal:             0 kB\n",
        encoding="utf-8",
    )

    assert read_cgroup_memory_snapshot() is None


def test_bounded_limit_arithmetic_is_unchanged(tmp_path: Path, monkeypatch) -> None:
    _write_cgroup_v2(tmp_path, monkeypatch, maximum=str(8 * 1024**3))
    (tmp_path / "meminfo").unlink()
    snapshot = read_cgroup_memory_snapshot()
    assert snapshot is not None
    result = classify_memory_headroom(
        FLASH,
        snapshot,
    )
    assert result["ok"] is True
    assert result["usable_bytes"] == 8 * 1024**3 - 3_139_612_672
    assert result["memory_limit_unlimited"] is False


def test_inert_swap_contributes_zero_headroom() -> None:
    # swap.max = 16 GiB but host SwapTotal = 0 -> fictional swap, zero usable.
    # 1 GiB headroom is enough for a normal spec but NOT for ox-alpha's 1.5 GiB,
    # so the fictional swap must not push it over the line.
    snapshot = _snapshot(current=7 * 1024**3, swap_max=16 * 1024**3, host_swap=0)
    result = classify_memory_headroom(OX_ALPHA, snapshot)
    assert result["ok"] is False
    assert result["usable_swap_bytes"] == 0
    assert result["reason"] == "insufficient_headroom"


def test_real_swap_contributes_headroom() -> None:
    snapshot = _snapshot(
        current=7 * 1024**3, swap_max=16 * 1024**3, host_swap=32 * 1024**3
    )
    result = classify_memory_headroom(FLASH, snapshot)
    assert result["usable_swap_bytes"] == 16 * 1024**3
    assert result["ok"] is True


def test_insufficient_ox_alpha_selects_configured_flash_fallback(tmp_path: Path) -> None:
    # 7.5 GiB used of 8 GiB -> 0.5 GiB headroom < 1.5 GiB required for ox-alpha.
    snapshot = _snapshot(current=int(7.5 * 1024**3))
    spec, decision = select_memory_safe_spec(
        (OX_ALPHA, FLASH), phase="revise", plan_dir=tmp_path, snapshot=snapshot
    )
    assert spec == FLASH
    assert decision["reason"] == "normal_memory_spec"
    assert decision["selected_index"] == 1


def test_scalar_unsafe_chain_returns_no_spec(tmp_path: Path) -> None:
    snapshot = _snapshot(current=int(7.5 * 1024**3))
    spec, decision = select_memory_safe_spec(
        (OX_ALPHA,), phase="revise", plan_dir=tmp_path, snapshot=snapshot
    )
    assert spec is None
    assert decision["reason"] == "insufficient_headroom"


def test_sufficient_headroom_admits_ox_alpha(tmp_path: Path) -> None:
    snapshot = _snapshot(current=int(5 * 1024**3))  # 3 GiB headroom
    spec, decision = select_memory_safe_spec(
        (OX_ALPHA,), phase="revise", plan_dir=tmp_path, snapshot=snapshot
    )
    assert spec == OX_ALPHA
    assert decision["reason"] == "sufficient"


def _write_death(
    tmp_path: Path,
    phase: str,
    spec: str,
    cause: str = "cgroup_oom",
    age_secs: int = 60,
    with_timestamp: bool = True,
) -> None:
    death: dict = {
        "phase": phase,
        "selected_spec": spec,
        "death_cause": cause,
        "worker_pid": 999_999,
    }
    if with_timestamp:
        death["detected_at"] = (
            datetime.now(timezone.utc) - timedelta(seconds=age_secs)
        ).isoformat().replace("+00:00", "Z")
    state = {
        "name": "demo",
        "current_state": "critiqued",
        "meta": {"worker_deaths": [death]},
    }
    (tmp_path / "state.json").write_text(json.dumps(state), encoding="utf-8")


def test_prior_same_phase_same_spec_oom_forces_fallback(tmp_path: Path) -> None:
    _write_death(tmp_path, phase="revise", spec=OX_ALPHA)
    # Even with plenty of headroom, a proven OOM for this phase+spec skips it.
    snapshot = _snapshot(current=int(5 * 1024**3))
    spec, decision = select_memory_safe_spec(
        (OX_ALPHA, FLASH), phase="revise", plan_dir=tmp_path, snapshot=snapshot
    )
    assert spec == FLASH
    # The ox-alpha skip (proven OOM) is recorded; the final decision reason
    # reflects the selection of the fallback, not the skipped spec.
    assert decision["skipped_spec"] == OX_ALPHA
    assert decision["skipped_index"] == 0


def test_unrelated_phase_death_is_not_reused(tmp_path: Path) -> None:
    _write_death(tmp_path, phase="critique", spec=OX_ALPHA)
    deaths = prior_cgroup_oom_deaths(tmp_path, phase="revise", spec=OX_ALPHA)
    assert deaths == []

    snapshot = _snapshot(current=int(5 * 1024**3))
    spec, _ = select_memory_safe_spec(
        (OX_ALPHA,), phase="revise", plan_dir=tmp_path, snapshot=snapshot
    )
    assert spec == OX_ALPHA


def test_unrelated_spec_death_is_not_reused(tmp_path: Path) -> None:
    _write_death(tmp_path, phase="revise", spec=FLASH)
    deaths = prior_cgroup_oom_deaths(tmp_path, phase="revise", spec=OX_ALPHA)
    assert deaths == []


def test_death_cause_requires_oom_kill_delta(
    tmp_path: Path, monkeypatch
) -> None:
    # Marker baseline 10; snapshot reports 10 -> no delta -> unknown cause.
    import arnold_pipelines.megaplan.runtime.memory_headroom as mh

    monkeypatch.setattr(
        mh,
        "read_cgroup_memory_snapshot",
        lambda: {
            "memory_current": 1,
            "memory_max": 8 * 1024**3,
            "memory_swap_max": 0,
            "memory_events": {"oom_kill": 10},
            "host_swap_total": 0,
        },
    )
    record_dispatch_memory_marker(tmp_path, "revise", FLASH)
    marker = (tmp_path / ".worker-dispatch-memory.json").read_text(encoding="utf-8")
    markers = json.loads(marker)
    markers["revise"]["oom_kill"] = 10
    (tmp_path / ".worker-dispatch-memory.json").write_text(
        json.dumps(markers), encoding="utf-8"
    )
    assert death_cause_from_markers(tmp_path, "revise") == "signal_or_exit_unknown"


def test_marker_absent_means_unknown_not_oom() -> None:
    assert death_cause_from_markers(Path("/nonexistent"), "revise") == "signal_or_exit_unknown"


def test_aged_oom_death_expires_and_spec_dispatches(tmp_path: Path) -> None:
    # Default cooldown is 900s: a death older than the cooldown must not
    # block dispatch forever — the precondition (memory pressure) is
    # re-verified against current state instead of frozen at the death.
    _write_death(tmp_path, phase="revise", spec=FLASH, age_secs=901)
    assert prior_cgroup_oom_deaths(tmp_path, phase="revise", spec=FLASH) == []
    snapshot = _snapshot(current=int(1 * 1024**3))
    spec, decision = select_memory_safe_spec(
        (FLASH,), phase="revise", plan_dir=tmp_path, snapshot=snapshot
    )
    assert spec == FLASH
    assert decision["reason"] == "normal_memory_spec"


def test_cooldown_env_override_disables_learned_death(
    tmp_path: Path, monkeypatch
) -> None:
    _write_death(tmp_path, phase="revise", spec=FLASH, age_secs=1)
    monkeypatch.setenv("ARNOLD_MEMORY_OOM_DEATH_COOLDOWN_SECS", "0")
    assert prior_cgroup_oom_deaths(tmp_path, phase="revise", spec=FLASH) == []
    snapshot = _snapshot(current=int(1 * 1024**3))
    spec, _ = select_memory_safe_spec(
        (FLASH,), phase="revise", plan_dir=tmp_path, snapshot=snapshot
    )
    assert spec == FLASH


def test_death_without_timestamp_fails_closed(tmp_path: Path) -> None:
    _write_death(tmp_path, phase="revise", spec=FLASH, with_timestamp=False)
    assert prior_cgroup_oom_deaths(tmp_path, phase="revise", spec=FLASH)
    snapshot = _snapshot(current=int(1 * 1024**3))
    spec, decision = select_memory_safe_spec(
        (FLASH,), phase="revise", plan_dir=tmp_path, snapshot=snapshot
    )
    assert spec is None
    assert decision["reason"] == "prior_cgroup_oom"


def test_cooldown_wait_positive_for_fresh_death(tmp_path: Path) -> None:
    # Default cooldown 900s, death aged 60s: remaining (840) + 2s epsilon.
    _write_death(tmp_path, phase="revise", spec=FLASH, age_secs=60)
    wait = memory_cooldown_wait_secs(tmp_path, "revise")
    assert 840.0 <= wait <= 844.0


def test_cooldown_wait_zero_for_expired_death(tmp_path: Path) -> None:
    _write_death(tmp_path, phase="revise", spec=FLASH, age_secs=901)
    assert memory_cooldown_wait_secs(tmp_path, "revise") == 0.0


def test_cooldown_wait_zero_without_deaths(tmp_path: Path) -> None:
    assert memory_cooldown_wait_secs(tmp_path, "revise") == 0.0


def test_cooldown_wait_fails_closed_on_malformed_timestamp(tmp_path: Path) -> None:
    (tmp_path / "state.json").write_text(
        json.dumps(
            {
                "meta": {
                    "worker_deaths": [
                        {
                            "phase": "revise",
                            "death_cause": "cgroup_oom",
                            "detected_at": "not-a-timestamp",
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    assert memory_cooldown_wait_secs(tmp_path, "revise") == 0.0


def test_cooldown_wait_fails_closed_on_future_timestamp(tmp_path: Path) -> None:
    _write_death(tmp_path, phase="revise", spec=FLASH, age_secs=-100)
    assert memory_cooldown_wait_secs(tmp_path, "revise") == 0.0


def test_cooldown_wait_ignores_unrelated_phase(tmp_path: Path) -> None:
    _write_death(tmp_path, phase="critique", spec=FLASH, age_secs=10)
    assert memory_cooldown_wait_secs(tmp_path, "revise") == 0.0


def test_cooldown_wait_spec_filter(tmp_path: Path) -> None:
    _write_death(tmp_path, phase="revise", spec=OX_ALPHA, age_secs=10)
    assert memory_cooldown_wait_secs(tmp_path, "revise", spec=FLASH) == 0.0
    assert memory_cooldown_wait_secs(tmp_path, "revise", spec=OX_ALPHA) > 0.0


def test_cooldown_wait_respects_cap_env(
    tmp_path: Path, monkeypatch
) -> None:
    _write_death(tmp_path, phase="revise", spec=FLASH, age_secs=60)
    monkeypatch.setenv("ARNOLD_MEMORY_COOLDOWN_WAIT_CAP_SECS", "15")
    assert memory_cooldown_wait_secs(tmp_path, "revise") == 15.0


def test_cooldown_wait_zero_with_cooldown_disabled(
    tmp_path: Path, monkeypatch
) -> None:
    _write_death(tmp_path, phase="revise", spec=FLASH, age_secs=1)
    monkeypatch.setenv("ARNOLD_MEMORY_OOM_DEATH_COOLDOWN_SECS", "0")
    assert memory_cooldown_wait_secs(tmp_path, "revise") == 0.0
