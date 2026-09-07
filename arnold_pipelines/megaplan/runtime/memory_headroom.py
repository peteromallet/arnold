"""Pre-dispatch cgroup memory headroom gate.

Occurrence 1ac805e5eef9 (2026-08-26): the ``native-ox-alpha`` phase profile
routes every phase to the frontier ``stealth/ox-alpha`` model.  Under the
container's 8 GiB ``memory.max`` ceiling that model grew anonymous memory
past the limit six times in a row, and the cgroup OOM killer SIGKILLed the
chain driver (pids 1225229 / 1518468 / 1525415 / 1734837 / 1816031 / 1913264)
with no typed failure record — SIGKILL is uncatchable, so the phase died
silently with an orphaned ``active_step``.

The ceiling cannot be raised from inside the container, so the only
in-container lever is model selection.  This module:

* reads the current cgroup memory snapshot (``memory.current`` /
  ``memory.max`` / ``memory.swap.max`` / ``memory.events`` plus host
  ``MemAvailable`` and ``SwapTotal``);
* classifies usable headroom for the selected spec — a declared
  high-memory spec (frontier) requires more headroom than a normal one, and
  fictional swap (``memory.swap.max > 0`` with host ``SwapTotal == 0``)
  contributes zero headroom;
* selects the first spec from the phase's configured fallback chain that has
  safe headroom, skipping any spec with a *proven* prior cgroup OOM for the
  same phase (learned-death policy — a prior OOM forces fallback even if
  current memory later dropped);
* returns ``None`` when no spec is safe, so the caller can fail with a typed
  ``insufficient_memory_headroom`` error instead of launching a worker that
  will be cgroup-killed.

It also persists a per-dispatch ``oom_kill`` marker so the orphan-recovery
path can attribute a dead worker to ``cgroup_oom`` only when the counter
actually advanced between dispatch and recovery — never from a bare PID
observation.

This is a prevention gate, not a precise per-model RSS predictor: the exact
ox-alpha allocation profile is unknown, so the thresholds are conservative
knobs and the authoritative backstop is the persistent worker-death fallback
cursor.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_CGROUP_BASE = Path("/sys/fs/cgroup")
_MEMINFO_PATH = Path("/proc/meminfo")
_CGROUP_UNLIMITED = "max"

# Evidence-based high-memory classification: the frontier model that OOM'd
# the container resolves as ``omp:openrouter/stealth/ox-alpha`` or
# ``omp:stealth/ox-alpha``.  Any spec containing these tokens is treated as
# high-memory; everything else is a normal-memory spec.
_HIGH_MEMORY_TOKENS = ("ox-alpha", "stealth/")

# Headroom thresholds (bytes).  Conservative prevention knobs, NOT measured
# per-model RSS bounds.
_HIGH_MEMORY_MIN_HEADROOM = int(1.5 * 1024**3)  # 1.5 GiB for frontier models
_NORMAL_MIN_HEADROOM = int(256 * 1024**2)  # 256 MiB otherwise

# Marker file (plan_dir-scoped) recording the oom_kill counter at dispatch,
# so orphan recovery can compute an honest delta.
_MARKER_FILE = ".worker-dispatch-memory.json"

# The learned-death policy must not freeze a single-spec chain forever on a
# transient OOM: a proven death only blocks redispatch within this cooldown
# window, after which the precondition (actual memory pressure) is
# re-verified against CURRENT cgroup state.  Env-overridable for operators
# and tests.
_DEFAULT_OOM_DEATH_COOLDOWN_SECS = 15 * 60


def _oom_death_cooldown_secs() -> int:
    raw = (os.environ.get("ARNOLD_MEMORY_OOM_DEATH_COOLDOWN_SECS") or "").strip()
    if not raw:
        return _DEFAULT_OOM_DEATH_COOLDOWN_SECS
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_OOM_DEATH_COOLDOWN_SECS
    return value if value >= 0 else _DEFAULT_OOM_DEATH_COOLDOWN_SECS


def _death_age_secs(entry: dict[str, Any]) -> float | None:
    raw = entry.get("detected_at")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        stamped = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamped.tzinfo is None:
        stamped = stamped.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - stamped).total_seconds()


def _cooldown_wait_cap_secs(cooldown: int) -> float:
    raw = (os.environ.get("ARNOLD_MEMORY_COOLDOWN_WAIT_CAP_SECS") or "").strip()
    if not raw:
        return float(cooldown + 60)
    try:
        value = int(raw)
    except ValueError:
        return float(cooldown + 60)
    return float(value) if value >= 0 else float(cooldown + 60)


def memory_cooldown_wait_secs(
    plan_dir: Path | None,
    phase: str,
    *,
    spec: str | None = None,
) -> float:
    """Return the bounded wait before re-dispatching *phase* after a
    ``prior_cgroup_oom`` refusal, or ``0.0`` when no unexpired death applies.

    A typed dispatch refusal inside the learned-death cooldown is a
    time-bounded scheduling condition, not a phase contract failure: the
    newest unexpired cgroup-OOM death for the phase fixes when redispatch
    becomes safe. Callers sleep this long and retry instead of feeding the
    refusal to the deterministic-failure / repeated-signature breakers,
    which would permanently block the plan on a condition that expires.
    Malformed or future-skewed timestamps return ``0.0`` (fail closed
    through normal breaker accounting) rather than waiting forever.
    """
    if plan_dir is None:
        return 0.0
    try:
        state_data = json.loads(
            (Path(plan_dir) / "state.json").read_text(encoding="utf-8")
        )
    except (OSError, ValueError, json.JSONDecodeError):
        return 0.0
    meta = state_data.get("meta") if isinstance(state_data, dict) else None
    deaths = meta.get("worker_deaths") if isinstance(meta, dict) else None
    if not isinstance(deaths, list):
        return 0.0
    cooldown = _oom_death_cooldown_secs()
    newest: float | None = None
    for entry in deaths:
        if not isinstance(entry, dict):
            continue
        if entry.get("phase") != phase or entry.get("death_cause") != "cgroup_oom":
            continue
        if spec is not None and entry.get("selected_spec") != spec:
            continue
        age = _death_age_secs(entry)
        if age is None or age < 0 or age > cooldown:
            continue
        newest = age if newest is None else min(newest, age)
    if newest is None:
        return 0.0
    remaining = cooldown - newest
    if remaining <= 0:
        return 0.0
    return min(remaining + 2.0, _cooldown_wait_cap_secs(cooldown))


def read_cgroup_memory_snapshot() -> dict[str, Any] | None:
    """Read the current cgroup memory snapshot.

    Returns ``None`` when the cgroup data is unreadable — headroom then
    classifies as ``unknown``, never fabricated OOM evidence.
    """
    try:
        current = _read_cgroup_int("memory.current")
        maximum = _read_cgroup_limit("memory.max")
        if current is None or maximum is None:
            return None
        swap_max = _read_cgroup_limit("memory.swap.max")
        if swap_max is None:
            return None
        events: dict[str, int] = {}
        try:
            raw = (_CGROUP_BASE / "memory.events").read_text(encoding="utf-8")
        except OSError:
            raw = ""
        for line in raw.splitlines():
            key, _, value = line.partition(" ")
            if key and value.strip().isdigit():
                events[key] = int(value.strip())
        host_memory = _host_memory_info()
        host_available = host_memory.get("MemAvailable")
        if maximum == _CGROUP_UNLIMITED and host_available is None:
            return None
        return {
            "memory_current": current,
            "memory_max": maximum,
            "memory_swap_max": swap_max,
            "memory_events": events,
            "host_mem_available": host_available,
            "host_swap_total": host_memory.get("SwapTotal", 0),
        }
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def _read_cgroup_int(name: str) -> int | None:
    try:
        raw = (_CGROUP_BASE / name).read_text(encoding="utf-8").strip()
        if not raw or raw == _CGROUP_UNLIMITED:
            return None
        value = int(raw)
        return value if value >= 0 else None
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def _read_cgroup_limit(name: str) -> int | str | None:
    try:
        raw = (_CGROUP_BASE / name).read_text(encoding="utf-8").strip()
        if raw == _CGROUP_UNLIMITED:
            return _CGROUP_UNLIMITED
        if not raw:
            return None
        value = int(raw)
        return value if value >= 0 else None
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def _host_memory_info() -> dict[str, int]:
    values: dict[str, int] = {}
    try:
        with _MEMINFO_PATH.open(encoding="utf-8") as handle:
            for line in handle:
                key, separator, rest = line.partition(":")
                if separator and key in {"MemAvailable", "SwapTotal"}:
                    fields = rest.split()
                    if not fields or (len(fields) > 1 and fields[1] != "kB"):
                        continue
                    value = int(fields[0])
                    if value >= 0:
                        values[key] = value * 1024
    except (OSError, ValueError, IndexError):
        return {}
    return values


def _host_swap_total() -> int:
    return _host_memory_info().get("SwapTotal", 0)


def is_high_memory_spec(spec: str) -> bool:
    """Return whether *spec* is a declared high-memory (frontier) spec."""
    lowered = (spec or "").lower()
    return any(token in lowered for token in _HIGH_MEMORY_TOKENS)


def classify_memory_headroom(
    spec: str,
    snapshot: dict[str, Any] | None,
    *,
    min_headroom: int | None = None,
) -> dict[str, Any]:
    """Classify usable headroom for dispatching *spec* under *snapshot*.

    An explicit cgroup-v2 ``memory.max=max`` uses host ``MemAvailable`` as
    its conservative usable-memory signal.  Unlimited swap is never added.
    ``snapshot is None`` (unreadable cgroup data) classifies as
    ``ok=None`` / ``reason=unknown_cgroup_data`` — callers must not treat
    missing data as permission to launch a known-dangerous worker.
    """
    if not snapshot:
        return {"ok": None, "reason": "unknown_cgroup_data"}
    try:
        current = int(snapshot["memory_current"])
        if current < 0:
            raise ValueError
        raw_maximum = snapshot["memory_max"]
        memory_limit_unlimited = raw_maximum == _CGROUP_UNLIMITED
        if memory_limit_unlimited:
            usable = int(snapshot["host_mem_available"])
            if usable < 0:
                raise ValueError
        else:
            maximum = int(raw_maximum)
            if maximum < 0:
                raise ValueError
            usable = max(0, maximum - current)
        raw_swap_max = snapshot.get("memory_swap_max", 0)
        swap_limit_unlimited = raw_swap_max == _CGROUP_UNLIMITED
        swap_max = 0 if swap_limit_unlimited else int(raw_swap_max or 0)
        if swap_max < 0:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        return {"ok": None, "reason": "unknown_cgroup_data"}
    host_swap = int(snapshot.get("host_swap_total") or 0)
    # Fictional swap: a swap.max > 0 with no host swap contributes zero.
    usable_swap = swap_max if host_swap > 0 else 0
    headroom = usable + usable_swap
    need = (
        min_headroom
        if min_headroom is not None
        else (_HIGH_MEMORY_MIN_HEADROOM if is_high_memory_spec(spec) else _NORMAL_MIN_HEADROOM)
    )
    oom_kill = int((snapshot.get("memory_events") or {}).get("oom_kill") or 0)
    ok = headroom >= need
    return {
        "ok": ok,
        "headroom_bytes": headroom,
        "usable_bytes": usable,
        "usable_swap_bytes": usable_swap,
        "memory_limit_unlimited": memory_limit_unlimited,
        "swap_limit_unlimited": swap_limit_unlimited,
        "required_bytes": need,
        "oom_kill_total": oom_kill,
        "reason": "sufficient" if ok else "insufficient_headroom",
    }


def prior_cgroup_oom_deaths(
    plan_dir: Path | None,
    phase: str,
    spec: str,
) -> list[dict[str, Any]]:
    """Return recorded ``meta.worker_deaths[]`` cgroup-OOM entries for *phase*.

    The learned-death policy: a RECENT proven OOM (within the
    ``_DEFAULT_OOM_DEATH_COOLDOWN_SECS`` cooldown, env-overridable) for the
    same phase + spec forces fallback even when current memory later
    dropped; expired deaths re-enter normal selection so a stale block
    cannot freeze a single-spec chain permanently.  Entries without a
    parseable ``detected_at`` fail closed (still blocking).
    """
    if plan_dir is None:
        return []
    try:
        state_data = json.loads((plan_dir / "state.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return []
    meta = state_data.get("meta")
    if not isinstance(meta, dict):
        return []
    deaths = meta.get("worker_deaths")
    if not isinstance(deaths, list):
        return []
    cooldown = _oom_death_cooldown_secs()
    out: list[dict[str, Any]] = []
    for entry in deaths:
        if not isinstance(entry, dict):
            continue
        if entry.get("phase") != phase:
            continue
        if entry.get("selected_spec") != spec:
            continue
        if entry.get("death_cause") != "cgroup_oom":
            continue
        age = _death_age_secs(entry)
        if age is not None and age > cooldown:
            # Expired learned death: memory pressure is re-verified against
            # current state on the next dispatch instead of being frozen at
            # the death timestamp.
            continue
        out.append(entry)
    return out


def select_memory_safe_spec(
    configured_specs: tuple[str, ...] | list[str] | None,
    *,
    phase: str,
    plan_dir: Path | None,
    snapshot: dict[str, Any] | None,
) -> tuple[str | None, dict[str, Any]]:
    """Select the first configured spec that may be safely dispatched.

    Returns ``(selected_spec_or_None, decision)``.  A spec with a recent
    proven prior cgroup OOM for the phase (within the learned-death
    cooldown) is skipped before headroom is even consulted; a high-memory
    spec with insufficient headroom is skipped in
    favor of its configured fallback; no safe spec yields ``None`` so the
    caller can fail closed.
    """
    specs = tuple(configured_specs or ())
    if not specs:
        return None, {"reason": "no_configured_specs"}
    decision: dict[str, Any] = {"configured_specs": list(specs)}
    for index, spec in enumerate(specs):
        prior = prior_cgroup_oom_deaths(plan_dir, phase, spec)
        if prior:
            decision.update(
                {
                    "skipped_spec": spec,
                    "skipped_index": index,
                    "reason": "prior_cgroup_oom",
                    "prior_deaths": len(prior),
                }
            )
            continue
        if not is_high_memory_spec(spec):
            decision.update(
                {
                    "selected_index": index,
                    "selected_spec": spec,
                    "reason": "normal_memory_spec",
                }
            )
            return spec, decision
        result = classify_memory_headroom(spec, snapshot)
        if result.get("ok") is False:
            decision.update(
                {
                    "skipped_spec": spec,
                    "skipped_index": index,
                    "reason": result.get("reason"),
                    "headroom_bytes": result.get("headroom_bytes"),
                    "required_bytes": result.get("required_bytes"),
                    "oom_kill_total": result.get("oom_kill_total"),
                }
            )
            continue
        if result.get("ok") is None:
            # Unknown cgroup data: do not launch a known-dangerous worker on
            # missing evidence — fail closed to the next fallback.
            decision.update(
                {
                    "skipped_spec": spec,
                    "skipped_index": index,
                    "reason": result.get("reason"),
                }
            )
            continue
        decision.update(
            {
                "selected_index": index,
                "selected_spec": spec,
                "reason": result.get("reason"),
                "headroom_bytes": result.get("headroom_bytes"),
                "required_bytes": result.get("required_bytes"),
            }
        )
        return spec, decision
    decision["reason"] = decision.get("reason") or "no_safe_spec"
    return None, decision


def record_dispatch_memory_marker(plan_dir: Path | None, phase: str, spec: str) -> None:
    """Persist the dispatch-time ``oom_kill`` counter for *phase*.

    Orphan recovery compares this baseline against the current counter to
    attribute a dead worker to ``cgroup_oom`` only on an actual delta.
    Best-effort: a marker that cannot be written must not block dispatch.
    """
    if plan_dir is None:
        return
    snapshot = read_cgroup_memory_snapshot() or {}
    oom_kill = int((snapshot.get("memory_events") or {}).get("oom_kill") or 0)
    entry = {
        "phase": phase,
        "spec": spec,
        "oom_kill": oom_kill,
        "memory_current": snapshot.get("memory_current"),
        "at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        marker_path = plan_dir / _MARKER_FILE
        markers: dict[str, Any] = {}
        if marker_path.exists():
            try:
                markers = json.loads(marker_path.read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError):
                markers = {}
        markers[phase] = entry
        tmp = marker_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(markers, separators=(",", ":")), encoding="utf-8")
        os.replace(tmp, marker_path)
    except OSError:
        pass


def read_dispatch_memory_marker(plan_dir: Path | None, phase: str) -> dict[str, Any] | None:
    """Return the last dispatch marker for *phase*, or ``None``."""
    if plan_dir is None:
        return None
    try:
        markers = json.loads((plan_dir / _MARKER_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    entry = markers.get(phase)
    return entry if isinstance(entry, dict) else None


def death_cause_from_markers(
    plan_dir: Path | None,
    phase: str,
) -> str:
    """Attribute a dead worker's cause using dispatch vs recovery OOM deltas.

    ``cgroup_oom`` only when the dispatch marker exists and the current
    ``memory.events.oom_kill`` counter advanced past it.  Otherwise
    ``signal_or_exit_unknown`` — a dead PID is not OOM evidence.
    """
    marker = read_dispatch_memory_marker(plan_dir, phase)
    if marker is None:
        return "signal_or_exit_unknown"
    baseline = int(marker.get("oom_kill") or 0)
    snapshot = read_cgroup_memory_snapshot() or {}
    current = int((snapshot.get("memory_events") or {}).get("oom_kill") or 0)
    if current > baseline:
        return "cgroup_oom"
    return "signal_or_exit_unknown"
