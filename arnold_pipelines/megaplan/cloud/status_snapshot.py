"""Canonical cloud status snapshot — local observation only, never SSH.

This module produces the single "what is running?" truth document for the cloud
worker, ``/workspace/.megaplan/status/cloud-status.json``. Every status consumer
reads this same document: the Discord resident, watchdog notifications,
``megaplan cloud status --all``, and humans debugging the box.

Design rules (see ``docs/ops/elegant-cloud-status-resident-plan.md``):

- Describe the cloud box from inside the cloud box. Never SSH.
- Read only files the watchdog already writes: the canonical session markers in
  ``/workspace/.megaplan/cloud-sessions/*.json``, the chain-health sidecars
  ``*.chain-health.progress.json``, repair markers, ``needs-human`` markers, the
  ``/workspace/watchdog-report.json`` verdicts, and the plan state files. The only
  process namespace touch is best-effort tmux/ps liveness probing.
- Be unit-testable with fixture directories and an injectable liveness probe.
- Know nothing about Discord, resident conversations, or CLI rendering. Those
  live in :mod:`arnold_pipelines.megaplan.cloud.status_format` and the resident.

M9 — canonical projection migration:
  The snapshot now carries a ``source_cursor_vector`` recording every source file
  that was read, plus per-session ``evidence_gaps`` for any stale or degraded
  fields.  Neither field grants dispatch, completion, cancellation, publication,
  or delivery authority — they are display-only projections (see ``status_projection.py``
  for the authority contract).  The format module (:mod:`arnold_pipelines.megaplan.cloud.status_format`)
  renders these gaps as structured evidence annotations.
M7: Projection adapters for cloud status snapshot persistence.
----------------------------------------------------------------------
OLD-READER / NEW-WRITER METADATA:
  - Legacy readers (all callers before M7) use load_cloud_status_snapshot()
    which reads ``cloud-status.json`` directly.  These readers accept the
    file as authority without cursor validation.
  - New writers (M7+) supplement each write_cloud_status_snapshot() and
    build_and_write_snapshot() with cursor-checked projection events
    appended to an append-only history.
  - New readers (M7+) can use rebuild_status_snapshot_projection() or
    status_snapshot_projection_cursor() for cursor-validated reads.
  - UNCERTAINTY: Legacy readers have no cursor validation; divergence
    between the snapshot file and projection history is only detectable by
    the new readers.  Production enforcement remains disabled in M7.
  - The projection history is an append-only ledger; it never erases
    prior records, even on rebuild.
  - The projection is SUPPLEMENTAL evidence, not authority — the
    cloud-status.json file remains the primary source of truth.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from arnold_pipelines.megaplan.cloud.liveness_lease import observe_liveness_lease

from arnold_pipelines.megaplan._core.io import (
    ProjectionCursor,
    ProjectionCursorMismatchError,
    ProjectionRecord,
    append_projection_event,
    deterministic_projection_replay,
    latest_projection_cursor,
    load_projection_history,
    now_utc,
    projection_history_path,
    projection_snapshot_path,
    rebuild_projection_atomically,
    sha256_file,
)

from arnold_pipelines.megaplan.authority.views import (
    PlanExecutionDiagnostic,
    PlanExecutionView,
    derive_human_gate_view,
    derive_megaplan_plan_view,
    derive_megaplan_recovery_view,
    derive_plan_execution_view,
    derive_publication_view,
    derive_runner_view,
)
from arnold_pipelines.megaplan.cloud.current_target import resolve_current_target
from arnold_pipelines.megaplan.cloud.human_blockers import classify_needs_human_blocker
from arnold_pipelines.megaplan.cloud.repair_contract import (
    CloudCustodyClassification,
    classify_cloud_custody,
    classify_repair_dispatch,
    durable_repair_active,
    is_success_outcome,
    project_repair_custody,
)
from arnold_pipelines.megaplan.run_state.resolver import resolve_run_state
from arnold_pipelines.megaplan.cloud.session_markers import (
    is_canonical_session_marker_path,
)
from arnold_pipelines.megaplan.cloud.status_retirement import status_retirement_matches
from arnold_pipelines.megaplan.chain.spec import load_spec as load_chain_spec
from arnold_pipelines.run_authority import canonical_json, reduce_run_authority
import hashlib as _hashlib

from arnold_pipelines.megaplan.status_projection import plan_status_presentation
from arnold_pipelines.megaplan.source_cursor_contract import (
    DimensionCursor,
    SourceCursorVector,
)
from arnold_pipelines.megaplan.chain.advancement import (
    AdvancementPolicy,
    assess_advancement,
    policy_for_spec_path,
)

# --- canonical paths -------------------------------------------------------

DEFAULT_MARKER_DIR = Path("/workspace/.megaplan/cloud-sessions")
DEFAULT_WATCHDOG_REPORT = Path("/workspace/watchdog-report.json")
DEFAULT_FALLBACK_WATCHDOG_REPORT = Path("/workspace/.megaplan/watchdog-report.json")
DEFAULT_STATUS_DIR = Path("/workspace/.megaplan/status")
DEFAULT_SNAPSHOT_PATH = DEFAULT_STATUS_DIR / "cloud-status.json"
DEFAULT_PREVIOUS_SNAPSHOT_PATH = DEFAULT_STATUS_DIR / "cloud-status.previous.json"
DEFAULT_HISTORY_PATH = DEFAULT_STATUS_DIR / "progress-history.jsonl"
DEFAULT_WORKSPACE_ROOT = Path("/workspace")

# Progress-history rotation thresholds. The watchdog appends one compact row per
# sweep; we keep the file bounded so multi-week chains do not grow it unbounded.
HISTORY_TRIM_SIZE_BYTES = 512 * 1024
HISTORY_KEEP_LINES = 2000

STATE_INITIALIZED = "initialized"
PLAN_PROGRESSION_RUNGS: tuple[str, ...] = (
    "prepped",
    "planned",
    "critiqued",
    "gated",
    "finalized",
    "executed",
    "reviewed",
    "done",
)

SNAPSHOT_SOURCE = "cloud-local-observer"

log = logging.getLogger("megaplan")

# ── M7 projection constants ───────────────────────────────────────────────

_STATUS_SNAPSHOT_PROJECTION_ID = "cloud-status-snapshot"
_STATUS_SNAPSHOT_PROJECTION_SCHEMA_VERSION = 1


def _status_projection_dir(snapshot_path: Path) -> Path:
    """Return the projection storage directory for status snapshot events.

    Stores under ``<status_dir>/projections/``.
    """
    return snapshot_path.parent / "projections"


def _cursor_from_snapshot_file(path: Path) -> ProjectionCursor:
    """Build a ProjectionCursor from the current state of a snapshot file."""
    resolved = path.resolve()
    record_count = 0
    if resolved.exists():
        try:
            text = resolved.read_text(encoding="utf-8")
            lines = [line for line in text.splitlines() if line.strip()]
            record_count = len(lines)
        except (FileNotFoundError, OSError):
            pass
    source_digest = (
        sha256_file(resolved)
        if resolved.exists()
        else "sha256:" + hashlib.sha256(b"").hexdigest()
    )
    return ProjectionCursor(
        source_path=str(resolved),
        source_record_count=record_count,
        source_digest=source_digest,
        computed_at=now_utc(),
    )


def _generate_status_event_id(projection_id: str, event_type: str) -> str:
    """Generate a deterministic event ID for status snapshot projection events."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    seed = f"{projection_id}:{event_type}:{ts}"
    return f"status-proj-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:12]}"


# ── Status snapshot projection ────────────────────────────────────────────


def _record_status_snapshot_event(
    snapshot: Mapping[str, Any],
    path: Path,
    *,
    event_type: str = "snapshot_written",
    flock: bool = True,
) -> ProjectionRecord:
    """Append a cursor-checked projection event recording the status snapshot write.

    The event carries the full snapshot payload and a cursor derived from the
    current snapshot file.  This is a shadow-side-effect — it supplements
    the existing atomic file write without replacing it.
    """
    path = Path(path)
    projection_dir = _status_projection_dir(path)

    source_cursor = None
    if path.exists():
        try:
            source_cursor = _cursor_from_snapshot_file(path)
        except (FileNotFoundError, OSError):
            pass

    event_id = _generate_status_event_id(_STATUS_SNAPSHOT_PROJECTION_ID, event_type)
    record = ProjectionRecord(
        event_type=event_type,
        event_id=event_id,
        payload={
            "schema_version": _STATUS_SNAPSHOT_PROJECTION_SCHEMA_VERSION,
            "snapshot_path": str(path),
            "generated_at": snapshot.get("generated_at"),
            "source": snapshot.get("source"),
            "summary": dict(snapshot.get("summary") or {}),
            "session_count": len(snapshot.get("sessions") or []),
        },
        occurred_at=now_utc(),
        cursor=source_cursor,
        idempotency_key=f"status-snapshot-{path.name}-{event_id}",
    )
    return append_projection_event(
        projection_dir,
        _STATUS_SNAPSHOT_PROJECTION_ID,
        record,
        source_path=path,
        flock=flock,
        snapshot_dir=projection_dir,
    )


def rebuild_status_snapshot_projection(
    path: Path | str = DEFAULT_SNAPSHOT_PATH,
    *,
    flock: bool = True,
) -> dict[str, Any]:
    """Atomically rebuild the status snapshot projection from the append-only history.

    Returns a dict with keys:
      - ``status``: ``"rebuilt"`` | ``"no_history"`` | ``"error"``
      - ``snapshot_path``: path to the written snapshot (if rebuilt)
      - ``projection``: the complete projected state (if rebuilt)
      - ``cursor``: the latest source cursor (if available)
      - ``record_count``: number of projection records processed
      - ``diagnostics``: list of diagnostic messages
    """
    path = Path(path)
    projection_dir = _status_projection_dir(path)
    diagnostics: list[str] = []
    records = load_projection_history(projection_dir, _STATUS_SNAPSHOT_PROJECTION_ID)
    if not records:
        return {
            "status": "no_history",
            "snapshot_path": None,
            "projection": None,
            "cursor": None,
            "record_count": 0,
            "diagnostics": [
                "No status snapshot projection history found — nothing to rebuild"
            ],
        }

    def _fold_status_snapshot(
        acc: dict[str, Any], record: ProjectionRecord
    ) -> dict[str, Any]:
        """Fold: last snapshot payload wins."""
        payload = record.payload
        if isinstance(payload, dict):
            acc.update(payload)
        return acc

    try:
        projection_data = deterministic_projection_replay(
            projection_dir,
            _STATUS_SNAPSHOT_PROJECTION_ID,
            fold_fn=_fold_status_snapshot,
        )
    except Exception as exc:
        return {
            "status": "error",
            "snapshot_path": None,
            "projection": None,
            "cursor": None,
            "record_count": len(records),
            "diagnostics": [f"Status snapshot replay failed: {exc}"],
        }

    last_cursor = latest_projection_cursor(
        projection_dir, _STATUS_SNAPSHOT_PROJECTION_ID
    )
    snapshot_path = rebuild_projection_atomically(
        projection_dir,
        _STATUS_SNAPSHOT_PROJECTION_ID,
        projection_data,
        cursor=last_cursor,
    )
    return {
        "status": "rebuilt",
        "snapshot_path": str(snapshot_path),
        "projection": dict(projection_data),
        "cursor": last_cursor.to_dict() if last_cursor else None,
        "record_count": len(records),
        "diagnostics": diagnostics,
    }


def status_snapshot_projection_cursor(
    path: Path | str = DEFAULT_SNAPSHOT_PATH,
) -> ProjectionCursor | None:
    """Return the latest cursor from the status snapshot projection history."""
    path = Path(path)
    projection_dir = _status_projection_dir(path)
    return latest_projection_cursor(projection_dir, _STATUS_SNAPSHOT_PROJECTION_ID)


def status_snapshot_projection_snapshot(
    path: Path | str = DEFAULT_SNAPSHOT_PATH,
) -> dict[str, Any] | None:
    """Return the most recent status snapshot projection snapshot, or None."""
    path = Path(path)
    projection_dir = _status_projection_dir(path)
    snapshot_path = projection_snapshot_path(
        projection_dir, _STATUS_SNAPSHOT_PROJECTION_ID
    )
    if not snapshot_path.exists():
        return None
    try:
        return json.loads(snapshot_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None


def is_trusted_container() -> bool:
    """True when this process is the cloud worker itself (local observation fits).

    The resident, watchdog, and runners set ``MEGAPLAN_TRUSTED_CONTAINER=1`` inside
    the container; combined with the canonical marker directory being present, that
    means a fresh local snapshot can be built on demand with no SSH. Consumers that
    opt into a per-turn fresh view (the resident hot context) use this to decide
    build-vs-read.
    """
    if os.environ.get("MEGAPLAN_TRUSTED_CONTAINER") != "1":
        return False
    return DEFAULT_MARKER_DIR.exists()


def has_local_markers(marker_dir: Path | None = None) -> bool:
    """True when the canonical cloud-session marker directory is present.

    This is the on-box signal independent of the trust env var: when the marker
    dir exists, a fresh local snapshot can be built from it with no SSH. Unlike
    :func:`is_trusted_container`, this does NOT require
    ``MEGAPLAN_TRUSTED_CONTAINER=1`` — so a resident that lost the env var on a
    manual restart still reads live markers instead of a stale cache (see
    ``docs/arnold/watchdog-snapshot-staleness-fix.md`` P0). The canonical path is
    absolute (``/workspace/.megaplan/cloud-sessions``), so a laptop/CLI checkout
    with only a relative ``.megaplan`` cannot falsely trip it.
    """
    directory = Path(marker_dir) if marker_dir else DEFAULT_MARKER_DIR
    return directory.is_dir()

# A session whose latest activity is older than this is not "running" on
# activity alone; it must have a live process or be under active repair.
STALE_ACTIVITY_S = 30 * 60
# A repair-progress marker older than this no longer counts as "repairing".
REPAIR_FRESH_S = 6 * 60 * 60
CHAIN_HEALTH_STALE_GRACE_S = 5

SessionStatus = str  # one of: running | repairing | blocked | paused | complete | attention
LivenessProbe = Callable[[Mapping[str, Any]], dict[str, Any]]


# --- public API ------------------------------------------------------------


def render_maintenance_observation(
    envelope: Any,
    *,
    comparison: Any | None = None,
    projection: Any | None = None,
) -> dict[str, Any]:
    """Render a deterministic, read-only Maintenance observation sibling.

    Inputs are immutable evidence already captured by the caller.  This
    renderer never rereads mutable sources and never infers progress from
    process, activity, status, or repair evidence.
    """
    from arnold_pipelines.megaplan.maintenance.identity import canonical_digest

    if comparison is None:
        bucket = None
        reasons: list[str] = []
        stale_projection = False
        digest_mismatch = False
        missing_denominator = None
        denominator = None
        covered_count = None
        coverage = None
        projection_name = None
        projection_source_digest = None
        projection_output_digest = None
    else:
        bucket = (
            comparison.bucket.value
            if hasattr(comparison.bucket, "value")
            else comparison.bucket
        )
        reasons = list(comparison.reasons)
        stale_projection = comparison.stale_projection
        digest_mismatch = comparison.digest_mismatch
        missing_denominator = comparison.missing_denominator
        denominator = comparison.denominator
        covered_count = comparison.covered_count
        coverage = comparison.coverage
        projection_name = comparison.projection_name
        projection_source_digest = comparison.projection_source_digest
        projection_output_digest = comparison.projection_output_digest

    projection_freshness = None
    if projection is not None:
        projection_freshness = getattr(projection, "freshness", None)
        if hasattr(projection_freshness, "value"):
            projection_freshness = projection_freshness.value

    # Only an explicitly fresh projection supports a positive verdict.  A
    # missing or novel freshness value is unknown and therefore fails closed.
    projection_green = projection_freshness == "fresh" and not stale_projection
    envelope_eligible = bool(envelope.is_eligible)
    comparison_match = comparison is not None and bucket == "match"
    eligible = bool(envelope_eligible and projection_green and comparison_match)
    green = bool(eligible and comparison.green)
    terminal = bool(eligible and comparison.terminal)
    dispatchable = bool(eligible and comparison.dispatchable)

    vectors = [
        {
            "owner": vector.owner,
            "source": vector.source,
            "environment": (
                vector.environment.root if vector.environment is not None else None
            ),
            "before": vector.before,
            "after": vector.after,
        }
        for vector in envelope.version_vectors
    ]

    payload = {
        "schema_version": 1,
        "envelope": {
            "schema_version": envelope.schema_version,
            "observed_at": envelope.observed_at.root.isoformat(),
            "environment": (
                envelope.environment.root if envelope.environment is not None else None
            ),
            "tenant": envelope.tenant.root if envelope.tenant is not None else None,
            "run": envelope.run.root if envelope.run is not None else None,
            "chain": envelope.chain.root if envelope.chain is not None else None,
            "plan": envelope.plan.root if envelope.plan is not None else None,
            "stage": envelope.stage.root if envelope.stage is not None else None,
            "model": envelope.model.root if envelope.model is not None else None,
            "profile": envelope.profile.root if envelope.profile is not None else None,
            "attempt": envelope.attempt.root if envelope.attempt is not None else None,
            "digest": canonical_digest(envelope),
        },
        "states": {
            "completeness": envelope.completeness.value,
            "freshness": envelope.freshness.value,
            "coherence": envelope.coherence.value,
            "coherence_reasons": [reason.value for reason in envelope.coherence_reasons],
        },
        "cross_environment": bool(envelope.cross_environment),
        "source_version_vectors": vectors,
        "projection": {
            "name": projection_name,
            "freshness": projection_freshness,
            "source_digest": projection_source_digest,
            "output_digest": projection_output_digest,
        },
        "comparison": {
            "present": comparison is not None,
            "bucket": bucket,
            "reasons": reasons,
            "stale_projection": stale_projection,
            "digest_mismatch": digest_mismatch,
            "missing_denominator": missing_denominator,
            "denominator": denominator,
            "covered_count": covered_count,
            "coverage": coverage,
        },
        "verdict": {
            "green": green,
            "terminal": terminal,
            "dispatchable": dispatchable,
            "eligible": eligible,
        },
        "progress_inferred_from_process": False,
    }
    view_hash = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    payload["view_hash"] = view_hash
    return payload


def build_cloud_status_snapshot(
    *,
    marker_dir: Path | None = None,
    watchdog_report_path: Path | None = None,
    repair_data_dir: Path | None = None,
    workspace_root: Path = DEFAULT_WORKSPACE_ROOT,
    now: datetime | None = None,
    liveness_probe: LivenessProbe | None = None,
    history_path: Path | str | None = None,
    source_cursor_vector: Mapping[str, Any] | None = None,
    maintenance_observation: Any | None = None,
) -> dict[str, Any]:
    """Build the canonical cloud status snapshot from local observation only.

    All file reads are defensive: a missing or malformed source file degrades a
    session to ``attention`` rather than raising. The function never raises on
    absent inputs — callers may inspect the top-level ``degraded`` field.

    *source_cursor_vector* is an optional M9 canonical projection cursor
    recording which source files were read, their record counts, and digests.
    When supplied, it is attached as ``source_cursor_vector`` in the snapshot
    so downstream consumers (format module, resident) can trace evidence
    provenance without repeating the read.  It never grants authority — this
    is a display-only projection.
    """
    now = now or _utcnow()
    # Resolve defaults at call time so tests (and in-container callers) see the
    # current module-level paths rather than values captured at def time.
    marker_dir = Path(marker_dir) if marker_dir else DEFAULT_MARKER_DIR
    watchdog_report_path = Path(watchdog_report_path) if watchdog_report_path else DEFAULT_WATCHDOG_REPORT
    repair_data_dir = Path(repair_data_dir) if repair_data_dir else marker_dir / "repair-data"
    probe = liveness_probe or default_liveness_probe

    watchdog_report, watchdog_by_session, degraded_reasons = _load_watchdog_report(
        watchdog_report_path, DEFAULT_FALLBACK_WATCHDOG_REPORT
    )
    markers = _load_session_markers(marker_dir)

    sessions: list[dict[str, Any]] = []
    for marker in markers:
        sessions.append(
            _build_session_entry(
                marker,
                marker_dir=marker_dir,
                repair_data_dir=repair_data_dir,
                watchdog_by_session=watchdog_by_session,
                watchdog_report_path=watchdog_report_path,
                now=now,
                liveness_probe=probe,
            )
        )

    sessions.sort(key=lambda entry: (entry["session"] != "editable-install", entry["status"], entry["session"]))

    # Enrich each session's progress block with time-series deltas (epic %
    # gained over 1h/5h, epic/plan start times) from the sweep history. Best
    # effort: missing/unreadable history just leaves the deltas absent.
    hist_path = Path(history_path) if history_path else DEFAULT_HISTORY_PATH
    for entry in sessions:
        progress = entry.get("progress")
        if not isinstance(progress, dict):
            continue
        deltas = compute_progress_deltas(
            history_path=hist_path,
            session=entry.get("session"),
            now=now,
            started_at=entry.get("started_at"),
            now_percent=progress.get("percent"),
        )
        if deltas:
            progress.update(deltas)

    # Attach per-session evidence gaps (stale/degraded display fields as
    # structured evidence annotations — never authority).
    for entry in sessions:
        entry["evidence_gaps"] = _collect_session_evidence_gaps(entry)

    summary = _summarize(sessions)
    snapshot: dict[str, Any] = {
        "generated_at": _isoformat(now),
        "source": SNAPSHOT_SOURCE,
        "marker_dir": str(marker_dir),
        "watchdog_report": str(watchdog_report_path),
        "summary": summary,
        "sessions": sessions,
        "degraded": {"reasons": degraded_reasons} if degraded_reasons else None,
        "source_cursor_vector": _format_source_cursor(source_cursor_vector),
    }
    if maintenance_observation is not None:
        snapshot["maintenance_observation"] = render_maintenance_observation(
            maintenance_observation
        )
    if watchdog_report is not None:
        snapshot["watchdog_generated_at"] = watchdog_report.get("timestamp_utc") or ""
        snapshot["watchdog_sessions_seen"] = watchdog_report.get("sessions_seen")
    return snapshot


def write_cloud_status_snapshot(
    snapshot: Mapping[str, Any],
    path: Path | str = DEFAULT_SNAPSHOT_PATH,
    *,
    previous_path: Path | str | None = DEFAULT_PREVIOUS_SNAPSHOT_PATH,
    _record_projection: bool = True,
) -> Path:
    """Atomically write ``snapshot`` to ``path``, rotating the prior file.

    Writes through a temp file in the same directory and renames, so partial
    writes are never observable. When ``previous_path`` is set, the existing
    snapshot (if any) is moved there first so consumers can diff consecutive
    sweeps. Returns the final path written.

    M7 (shadow): In addition to the atomic write, this function appends a
    cursor-checked projection event to an append-only history.  The projection
    event is recorded *after* the file write succeeds.  Set
    ``_record_projection=False`` to skip this side-effect.
    """
    target = Path(path)
    previous = Path(previous_path) if previous_path else None
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(snapshot, indent=2, sort_keys=True) + "\n"

    fd, tmp_name = tempfile.mkstemp(prefix=".cloud-status.", suffix=".json", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())

        # Preserve the prior snapshot without removing the canonical file.
        # In particular, ENOSPC while staging either file must leave the last
        # complete snapshot readable at ``target``.
        if previous is not None and target.exists():
            previous.parent.mkdir(parents=True, exist_ok=True)
            previous_fd: int | None = None
            previous_tmp: str | None = None
            try:
                previous_fd, previous_tmp = tempfile.mkstemp(
                    prefix=f".{previous.name}.", suffix=".tmp", dir=str(previous.parent)
                )
                with os.fdopen(previous_fd, "wb") as handle:
                    previous_fd = None
                    with target.open("rb") as source:
                        shutil.copyfileobj(source, handle)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(previous_tmp, previous)
                previous_tmp = None
            except OSError:
                # Rotation is best-effort; target still contains the last
                # complete snapshot and the staged replacement is intact.
                pass
            finally:
                if previous_fd is not None:
                    os.close(previous_fd)
                if previous_tmp is not None:
                    try:
                        os.unlink(previous_tmp)
                    except OSError:
                        pass

        os.replace(tmp_name, target)
        dir_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise

    # ── M7 projection side-effect ────────────────────────────────────────
    if _record_projection:
        try:
            _record_status_snapshot_event(snapshot, target)
        except ProjectionCursorMismatchError as exc:
            log.warning(
                "M7 status-snapshot projection append blocked by cursor mismatch: %s. "
                "Snapshot file is intact; projection history may need reconciliation.",
                exc,
            )
        except Exception:
            log.warning(
                "M7 status-snapshot projection append failed (non-fatal). "
                "Snapshot file is intact.",
                exc_info=True,
            )

    return target


def build_and_write_snapshot(
    *,
    marker_dir: Path | None = None,
    watchdog_report_path: Path | None = None,
    path: Path | str = DEFAULT_SNAPSHOT_PATH,
    previous_path: Path | str | None = DEFAULT_PREVIOUS_SNAPSHOT_PATH,
    history_path: Path | str | None = None,
    now: datetime | None = None,
    source_cursor_vector: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the snapshot and atomically write it + the previous rotation.

    Convenience entrypoint for the watchdog: one call after each sweep keeps
    ``cloud-status.json`` fresh and appends one row to the progress-history log
    (sweep cadence, not per-resident-turn). Returns the snapshot that was written.
    """
    snapshot = build_cloud_status_snapshot(
        marker_dir=marker_dir,
        watchdog_report_path=watchdog_report_path,
        now=now,
        history_path=history_path,
        source_cursor_vector=source_cursor_vector,
    )
    write_cloud_status_snapshot(snapshot, path=path, previous_path=previous_path)
    append_progress_history(snapshot, history_path or DEFAULT_HISTORY_PATH, now=now)
    return snapshot


def load_cloud_status_snapshot(
    path: Path | str = DEFAULT_SNAPSHOT_PATH,
    *,
    max_age_s: float | None = None,
    now: datetime | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Read a snapshot from disk, returning ``(snapshot, degraded_reason)``.

    Returns ``(None, reason)`` when the file is missing, unreadable, or — when
    ``max_age_s`` is given — older than the freshness window. This is the single
    entry point consumers use to decide snapshot-first vs. degraded fallback.
    """
    path = Path(path)
    if not path.exists():
        return None, f"snapshot missing at {path}"
    try:
        raw = path.read_text(encoding="utf-8")
        snapshot = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"snapshot unreadable at {path}: {exc.__class__.__name__}"
    if not isinstance(snapshot, dict):
        return None, f"snapshot at {path} is not a JSON object"

    if max_age_s is not None:
        now = now or _utcnow()
        generated_at = _parse_iso(snapshot.get("generated_at"))
        if generated_at is None:
            return snapshot, "snapshot has no generated_at timestamp"
        age = (now - generated_at).total_seconds()
        if age > max_age_s:
            return snapshot, f"snapshot stale ({int(age)}s old, limit {int(max_age_s)}s)"
    return snapshot, None


def plan_activity_summary(snapshot: Mapping[str, Any] | None) -> dict[str, Any]:
    """Derive the resident ``plan_activity_summary`` from a snapshot.

    Returns buckets — ``active_working`` (running),
    ``should_be_working_but_needs_attention`` (repairing + attention + blocked
    that should be running), ``recently_completed``, and
    ``indeterminate_completions`` — plus a ``degraded`` flag when no snapshot
    was supplied.

    M9/T44: ``indeterminate_completions`` surfaces sessions whose status
    claims completion but whose source-cursor evidence (WBC/custody/run
    authority) is stale, unknown, or incoherent — adapter-backed projections
    expose typed indeterminate results instead of collapsing to complete.
    """
    if not snapshot or not isinstance(snapshot, Mapping):
        return {
            "degraded": True,
            "reason": "no cloud status snapshot available",
            "active_working": [],
            "should_be_working_but_needs_attention": [],
            "recently_completed": [],
            "indeterminate_completions": [],
        }
    # A sanitized stale snapshot (P1) carries a stale_banner and intentionally
    # empty buckets; surface it as degraded with the banner so consumers never
    # read "0 running" off a frozen view as "nothing is running".
    if snapshot.get("stale_banner"):
        return {
            "degraded": True,
            "reason": snapshot.get("stale_reason") or "snapshot stale",
            "stale_banner": snapshot.get("stale_banner"),
            "active_working": [],
            "should_be_working_but_needs_attention": [],
            "recently_completed": [],
            "indeterminate_completions": [],
        }
    sessions = snapshot.get("sessions") or []
    active: list[dict[str, Any]] = []
    needs_attention: list[dict[str, Any]] = []
    completed: list[dict[str, Any]] = []
    indeterminate: list[dict[str, Any]] = []
    for entry in sessions:
        if not isinstance(entry, Mapping):
            continue
        compact = {
            "session": entry.get("session"),
            "status": entry.get("status"),
            "current_plan": entry.get("current_plan"),
            "operator_next": entry.get("operator_next"),
            "latest_activity": entry.get("latest_activity"),
            "progress": entry.get("progress"),
            "accepted_progress": entry.get("accepted_progress"),
        }
        status = entry.get("status")
        if status == "running":
            active.append(compact)
        elif status == "complete":
            # M9/T44: Check source-cursor for indeterminate evidence
            if _session_completion_is_indeterminate(entry):
                compact["completion_evidence"] = "indeterminate"
                indeterminate.append(compact)
            else:
                completed.append(compact)
        elif status in {"repairing", "attention", "blocked"}:
            needs_attention.append(compact)
    return {
        "degraded": False,
        "active_working": active,
        "should_be_working_but_needs_attention": needs_attention,
        "recently_completed": completed,
        "indeterminate_completions": indeterminate,
    }


def _session_completion_is_indeterminate(
    session: Mapping[str, Any],
) -> bool:
    """Check whether a session's completion evidence is indeterminate.

    M9/T44: When source-cursor metadata is present and WBC, custody, or
    run_authority dimensions are non-fresh, the completion claim cannot
    be verified — return True (indeterminate) instead of silently
    collapsing to complete.
    """
    source_cursor = session.get("source_cursor")
    if not isinstance(source_cursor, Mapping):
        return False
    cursors = source_cursor.get("cursors")
    if not isinstance(cursors, (list, tuple)):
        return False
    for c in cursors:
        if not isinstance(c, Mapping):
            continue
        dim = c.get("dimension", "")
        state = c.get("state", "")
        if dim in {"wbc", "custody", "run_authority"} and state != "fresh":
            return True
    return False


def append_progress_history(
    snapshot: Mapping[str, Any] | None,
    path: Path | str = DEFAULT_HISTORY_PATH,
    *,
    now: datetime | None = None,
) -> None:
    """Append one compact progress row per sweep to the history log.

    The watchdog calls this once per sweep (via :func:`build_and_write_snapshot`)
    so the file grows on sweep cadence — not on every resident turn. Each row
    records the epic %, in-flight plan %, plan state, and current plan for every
    session carrying a progress block. The resident later reads this series to
    answer "how much has the epic advanced in the past hour?".

    Best-effort and never raises: a write failure simply means one missed
    sample. The file is trimmed to ``HISTORY_KEEP_LINES`` once it exceeds
    ``HISTORY_TRIM_SIZE_BYTES``.
    """
    if not snapshot or not isinstance(snapshot, Mapping):
        return
    now = now or _utcnow()
    samples: list[dict[str, Any]] = []
    for entry in snapshot.get("sessions") or []:
        if not isinstance(entry, Mapping):
            continue
        progress = entry.get("progress")
        if not isinstance(progress, Mapping):
            continue
        samples.append(
            {
                "session": entry.get("session"),
                "epic_percent": progress.get("percent"),
                "plan_percent": progress.get("plan_percent"),
                "plan_state": progress.get("plan_state"),
                "current_plan": progress.get("current_plan"),
            }
        )
    if not samples:
        return
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps({"ts": _isoformat(now), "sessions": samples}, separators=(",", ":")) + "\n"
            )
    except OSError:
        return
    _maybe_trim_history(path)


def _maybe_trim_history(path: Path) -> None:
    """Bound the history log: once it exceeds the size threshold, keep the tail."""
    try:
        if path.stat().st_size < HISTORY_TRIM_SIZE_BYTES:
            return
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    if len(lines) <= HISTORY_KEEP_LINES:
        return
    tail = lines[-HISTORY_KEEP_LINES:]
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text("\n".join(tail) + "\n", encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass


def _load_progress_history(path: Path | str) -> list[dict[str, Any]]:
    """Read the progress-history log as a list of parsed rows."""
    path = Path(path)
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return rows
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def compute_progress_deltas(
    *,
    history_path: Path | str = DEFAULT_HISTORY_PATH,
    session: str | None = None,
    now: datetime | None = None,
    started_at: str | None = None,
    now_percent: Any = None,
) -> dict[str, Any] | None:
    """Compute time-series progress deltas for one session from sweep history.

    Returns ``epic_delta_1h`` / ``epic_delta_5h`` (percentage points the epic
    gained over the last 1h / 5h), plus ``epic_started_at`` and
    ``plan_started_at``. Deltas are reported only when a history sample exists
    from at least that far back — a young epic honestly shows ``None`` until the
    window fills. Returns ``None`` when there is no history for the session.

    ``epic_started_at`` prefers the session marker's ``started_at`` (true chain
    start) and falls back to the first history sample. ``plan_started_at`` is the
    timestamp of the most recent transition into the current plan.
    """
    if not session:
        return None
    now = now or _utcnow()
    rows = _load_progress_history(history_path)
    if not rows:
        return None
    # Sorted timeline of (ts, epic_percent, current_plan, plan_state) for this session.
    points: list[tuple[datetime, Any, Any, Any]] = []
    for row in rows:
        row_dt = _parse_iso(row.get("ts"))
        if row_dt is None:
            continue
        for sample in row.get("sessions") or []:
            if not isinstance(sample, dict) or sample.get("session") != session:
                continue
            points.append(
                (row_dt, sample.get("epic_percent"), sample.get("current_plan"), sample.get("plan_state"))
            )
            break
    if not points:
        return None
    points.sort(key=lambda item: item[0])

    current_percent = now_percent
    if current_percent is None:
        current_percent = points[-1][1]

    def _percent_at_or_before(target: datetime) -> int | None:
        """Epic % at the latest sample at or before ``target`` (None if none)."""
        best: int | None = None
        for sample_dt, percent, _plan, _state in points:
            if sample_dt > target:
                break
            value = _as_int(percent)
            if value is not None:
                best = value
        return best

    def _delta(window_s: int) -> int | None:
        if current_percent is None:
            return None
        reference = _percent_at_or_before(now - timedelta(seconds=window_s))
        if reference is None:
            return None
        return _as_int(current_percent) - reference

    def _stages_advanced(window_s: int) -> list[str]:
        """Ladder rungs newly reached in the window, for "advanced N stages" color.

        Compares the highest ladder rung held at/before the window start against
        rungs first seen inside the window. Off-ladder states (authority_divergence,
        blocked, …) are skipped so transient sub-states don't masquerade as progress.
        """
        window_start = now - timedelta(seconds=window_s)
        prior_idx = -1
        for sample_dt, _pct, _plan, state in points:
            if sample_dt > window_start:
                break
            idx = _ladder_index(state)
            if idx >= 0:
                prior_idx = idx
        reached: list[str] = []
        seen: set[int] = set()
        for sample_dt, _pct, _plan, state in points:
            if sample_dt <= window_start:
                continue
            idx = _ladder_index(state)
            if idx < 0 or idx <= prior_idx or idx in seen:
                continue
            reached.append(PLAN_PROGRESSION_RUNGS[idx])
            seen.add(idx)
        return reached

    # plan_started_at: most recent transition into the current plan.
    current_plan = points[-1][2]
    plan_started_at: str | None = None
    prev_plan: Any = None
    for sample_dt, _percent, plan, _state in points:
        if plan != prev_plan:
            if plan is not None and plan == current_plan:
                plan_started_at = _isoformat(sample_dt)
            prev_plan = plan

    epic_started_at = started_at or _isoformat(points[0][0])
    return {
        "epic_delta_1h": _delta(3600),
        "epic_delta_5h": _delta(5 * 3600),
        "stage_changes_1h": _stages_advanced(3600),
        "epic_started_at": epic_started_at,
        "plan_started_at": plan_started_at,
    }


def _ladder_index(plan_state: Any) -> int:
    """Index of a state in PLAN_PROGRESSION_RUNGS, or -1 if off-ladder/empty."""
    if not plan_state:
        return -1
    try:
        return PLAN_PROGRESSION_RUNGS.index(str(plan_state).strip().lower())
    except ValueError:
        return -1


def _as_int(value: Any) -> int | None:
    """Best-effort int coercion; ``None`` for non-numeric (or bool) values."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _execution_task_progress(
    workspace: Path | None, plan_name: str
) -> tuple[int, int, int] | None:
    """Return ``(completed_weight, total_weight, task_count)`` from finalize.

    Complexity is already the executor's authoritative 1..10 composite weight,
    so progress uses it directly.  Invalid/missing weights fail closed to 1 so
    every task still contributes and malformed artifacts cannot inflate progress.
    """
    if workspace is None or not plan_name:
        return None
    payload = _load_json(workspace / ".megaplan" / "plans" / plan_name / "finalize.json")
    tasks = payload.get("tasks") if isinstance(payload, Mapping) else None
    if not isinstance(tasks, list) or not tasks:
        return None
    completed_weight = 0
    total_weight = 0
    task_count = 0
    for task in tasks:
        if not isinstance(task, Mapping):
            continue
        complexity = task.get("complexity")
        weight = complexity if isinstance(complexity, int) and not isinstance(complexity, bool) and 1 <= complexity <= 10 else 1
        total_weight += weight
        task_count += 1
        if str(task.get("status") or "").strip().lower() in {"done", "completed", "skipped"}:
            completed_weight += weight
    return (completed_weight, total_weight, task_count) if total_weight else None


def _plan_stage_percent(
    plan_state: str,
    *,
    execution_progress: tuple[int, int, int] | None = None,
) -> int | None:
    """Estimate a coarse "% through the in-flight plan" from its lifecycle state.

    Pre-execute work is capped at 30%.  Once finalized, the remaining 70% is
    apportioned across the actual finalized tasks by their 1..10 complexity.
    """
    if not plan_state:
        return None
    if plan_state == STATE_INITIALIZED:
        return 0
    pre_execute = {"prepped": 6, "planned": 12, "critiqued": 18, "gated": 24, "finalized": 30}
    if plan_state == "finalized" and execution_progress is not None:
        completed_weight, total_weight, _task_count = execution_progress
        return round(30 + 70 * completed_weight / total_weight)
    if plan_state in pre_execute:
        return pre_execute[plan_state]
    if plan_state in {"executed", "reviewed", "done"}:
        return 100
    if execution_progress is not None:
        completed_weight, total_weight, _task_count = execution_progress
        return round(30 + 70 * completed_weight / total_weight)
    return None


def _session_progress(
    *,
    completed_count: Any,
    milestone_count: Any,
    current_plan: str | None,
    complete: bool,
    plan_state: str | None = None,
    execution_progress: tuple[int, int, int] | None = None,
    presentation: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Pre-calculate epic/sprint progress for one snapshot session.

    A chain (epic) is a sequence of milestones — the ``s1``/``s2`` plans. The
    chain-health sidecar tells us how many milestones are done and the total;
    from that we derive an overall epic percent and a per-sprint
    done/in-progress/pending breakdown, so the resident can surface a
    pre-calculated number instead of guessing. Returns ``None`` when there is no
    milestone data to score against, so consumers skip cleanly.

    The breakdown follows the chain's standard sequential progression: the first
    ``completed_count`` milestones are done, the next is the in-flight sprint
    (carrying ``current_plan``), and the rest are pending.

    For the in-flight sprint we additionally calculate plan lifecycle/task-weight
    bookkeeping (``plan_percent``) from ``plan_state`` via
    :func:`_plan_stage_percent`, plus the raw ``plan_state`` label. This is not
    implementation acceptance. Both are omitted when there is no in-flight plan
    or no recorded state, so the progress block stays clean.

    The headline ``percent`` is the epic progress **with the in-flight plan's
    stage fraction folded in** — ``(completed + plan_percent/100) / total`` — so
    it advances as the current plan progresses rather than freezing between
    milestones. Without an in-flight plan-stage signal it falls back to plain
    ``completed / total``.
    """
    total = _as_int(milestone_count)
    if total is None or total <= 0:
        return None
    done = _as_int(completed_count)
    if done is None:
        done = 0
    done = max(0, min(done, total))
    if complete:
        done = total
    plan = current_plan or None

    # The in-flight plan's stage estimate is only meaningful while a sprint is
    # actually in progress (chain not complete, milestones remain).
    has_in_flight = (not complete) and done < total
    plan_state_norm = str(plan_state).strip().lower() if plan_state else ""
    plan_percent = (
        _plan_stage_percent(plan_state_norm, execution_progress=execution_progress)
        if has_in_flight
        else None
    )

    # Epic % folds the in-flight plan's stage fraction in, so the headline moves
    # as the current plan advances instead of freezing between milestones. With
    # no in-flight plan (complete) or no plan-stage signal, it is plain
    # completed-milestones / total. The plan fraction counts as up to one
    # milestone's worth of credit.
    if complete:
        percent = 100
    elif plan_percent is not None:
        percent = round((done + plan_percent / 100) / total * 100)
    else:
        percent = round(done / total * 100)

    sprints: list[dict[str, Any]] = []
    for index in range(1, total + 1):
        if complete or index <= done:
            sprints.append({"sprint": f"s{index}", "status": "done"})
        elif index == done + 1:
            sprint: dict[str, Any] = {"sprint": f"s{index}", "status": "in_progress"}
            if plan:
                sprint["plan"] = plan
            if plan_state_norm:
                sprint["plan_state"] = plan_state_norm
            if isinstance(presentation, Mapping):
                sprint.update(
                    {
                        key: presentation.get(key)
                        for key in ("active_phase", "execution_state", "display_state")
                    }
                )
            if plan_percent is not None:
                sprint["plan_percent"] = plan_percent
            sprints.append(sprint)
        else:
            sprints.append({"sprint": f"s{index}", "status": "pending"})

    progress: dict[str, Any] = {
        "completed_milestones": done,
        "total_milestones": total,
        "percent": percent,
        "complete": bool(complete),
        "current_plan": plan,
        "sprints": sprints,
    }
    if has_in_flight and plan_state_norm:
        progress["plan_state"] = plan_state_norm
    if has_in_flight and isinstance(presentation, Mapping):
        progress.update(
            {
                key: presentation.get(key)
                for key in ("active_phase", "execution_state", "display_state")
            }
        )
    if plan_percent is not None:
        progress["plan_percent"] = plan_percent
        progress["plan_percent_basis"] = (
            "plan lifecycle and recorded task-weight bookkeeping; not implementation acceptance"
        )
    if has_in_flight and execution_progress is not None:
        completed_weight, total_weight, task_count = execution_progress
        progress["execution_tasks"] = {
            "completed_weight": completed_weight,
            "total_weight": total_weight,
            "task_count": task_count,
        }
    return progress


def _overlay_newer_chain_state(
    chain_health: Mapping[str, Any] | None,
    *,
    workspace: Path | None,
    remote_spec: str,
) -> Mapping[str, Any] | None:
    state_path, chain_state = _load_latest_chain_state(workspace)
    if state_path is None or not isinstance(chain_state, Mapping):
        return chain_health

    health_mtime = _chain_health_mtime(chain_health)
    try:
        state_mtime = state_path.stat().st_mtime
    except OSError:
        return chain_health
    if health_mtime is not None and state_mtime <= health_mtime + CHAIN_HEALTH_STALE_GRACE_S:
        return chain_health

    milestone_count = _chain_milestone_count(remote_spec)
    if milestone_count is None and isinstance(chain_health, Mapping):
        milestone_count = _as_int(chain_health.get("milestone_count"))
    completed = chain_state.get("completed")
    completed_len = len(completed) if isinstance(completed, list) else 0
    current_index = _as_int(chain_state.get("current_milestone_index"))
    last_state = str(chain_state.get("last_state") or "").strip()
    current_plan_name = str(chain_state.get("current_plan_name") or "").strip()
    chain_complete = _chain_state_complete(
        last_state=last_state,
        completed_len=completed_len,
        milestone_count=milestone_count,
    )
    custody_mismatch = bool(
        last_state.lower() in {"done", "complete", "completed"}
        and not current_plan_name
        and milestone_count is not None
        and completed_len < milestone_count
    )

    merged: dict[str, Any] = dict(chain_health or {})
    merged.update(
        {
            "chain_complete": chain_complete,
            "completed_count": completed_len,
            "current_milestone_index": current_index,
            "custody_mismatch": custody_mismatch,
            "last_state": last_state,
            "updated_at": _isoformat(datetime.fromtimestamp(state_mtime, timezone.utc)),
            "source": "chain_state",
            "chain_state_path": str(state_path),
        }
    )
    if milestone_count is not None:
        merged["milestone_count"] = milestone_count
    if chain_complete:
        merged["current_plan_name"] = ""
    elif isinstance(chain_state.get("current_plan_name"), str):
        merged["current_plan_name"] = chain_state.get("current_plan_name")
    completed_pr = completed[-1] if isinstance(completed, list) and completed else {}
    if chain_state.get("pr_number") is not None:
        merged["pr_number"] = chain_state.get("pr_number")
    elif isinstance(completed_pr, Mapping) and completed_pr.get("pr_number") is not None:
        merged["pr_number"] = completed_pr.get("pr_number")
    if chain_state.get("pr_state") is not None:
        merged["pr_state"] = chain_state.get("pr_state")
    elif isinstance(completed_pr, Mapping) and completed_pr.get("pr_state") is not None:
        merged["pr_state"] = completed_pr.get("pr_state")
    return merged


def _load_latest_chain_state(workspace: Path | None) -> tuple[Path | None, Mapping[str, Any] | None]:
    if workspace is None:
        return None, None
    chain_dir = workspace / ".megaplan" / "plans" / ".chains"
    try:
        candidates = [p for p in chain_dir.glob("*.json") if p.is_file()]
    except OSError:
        return None, None
    if not candidates:
        return None, None
    path = max(candidates, key=lambda p: p.stat().st_mtime)
    payload = _load_json(path)
    if not isinstance(payload, Mapping):
        return None, None
    return path, payload


def _chain_health_mtime(chain_health: Mapping[str, Any] | None) -> float | None:
    if not chain_health:
        return None
    updated = _parse_iso(chain_health.get("updated_at"))
    return updated.timestamp() if updated is not None else None


def _chain_milestone_count(remote_spec: str) -> int | None:
    if not remote_spec:
        return None
    try:
        spec_path = Path(remote_spec)
        if not spec_path.exists():
            return None
        return len(load_chain_spec(spec_path).milestones)
    except Exception:
        return None


def _chain_state_complete(
    *,
    last_state: str,
    completed_len: int,
    milestone_count: int | None,
) -> bool:
    if last_state.strip().lower() not in {"done", "complete", "completed"}:
        return False
    if milestone_count is None:
        return True
    return completed_len >= milestone_count


def _chain_health_explicitly_incomplete(chain_health: Mapping[str, Any] | None) -> bool:
    if not isinstance(chain_health, Mapping) or not chain_health:
        return False
    last_state = str(chain_health.get("last_state") or "").strip().lower()
    if last_state and last_state not in {"done", "complete", "completed"}:
        return True
    try:
        completed_count = int(chain_health.get("completed_count"))
        milestone_count = int(chain_health.get("milestone_count"))
    except (TypeError, ValueError):
        return False
    return milestone_count > 0 and completed_count < milestone_count


# --- per-session classification -------------------------------------------


def _build_session_source_cursor(
    *,
    session: str,
    plan_current_state: str,
    plan_state_doc: Any,
    chain_health: Any,
    watchdog_item: Mapping[str, Any],
    liveness: Mapping[str, Any],
    observed_at_epoch_ms: float,
) -> SourceCursorVector:
    """Build a source-cursor vector from available cloud session context.

    Dimensions that cannot be determined from cloud-local observation are
    explicitly ``unknown`` — never defaulted to fresh or stale.
    """
    now_iso = datetime.fromtimestamp(
        observed_at_epoch_ms / 1000, tz=timezone.utc
    ).isoformat()

    # Lifecycle: version from current_state + chain health
    ch_ver = ""
    if isinstance(chain_health, Mapping):
        ch_ver = f":ch:{chain_health.get('completed_count', '')}:{chain_health.get('chain_complete', '')}"
    lifecycle_version = "sha256:" + _hashlib.sha256(
        f"{session}:{plan_current_state}{ch_ver}".encode("utf-8")
    ).hexdigest()
    lifecycle_cursor = DimensionCursor.fresh(
        "lifecycle", lifecycle_version, now_iso,
        detail=f"session={session} state={plan_current_state or 'unknown'}",
    )

    # Process-correlation: from watchdog/liveness
    has_tmux = bool(liveness.get("tmux")) if isinstance(liveness, Mapping) else False
    has_process = bool(liveness.get("process")) if isinstance(liveness, Mapping) else False
    if has_tmux or has_process:
        pc_version = f"session:{session}:tmux:{has_tmux}:process:{has_process}"
        pc_cursor = DimensionCursor.fresh(
            "process_correlation", pc_version, now_iso,
            detail=f"liveness tmux={has_tmux} process={has_process}",
        )
    else:
        pc_cursor = DimensionCursor.unknown(
            "process_correlation", observed_at=now_iso,
            detail="no liveness signal from cloud session",
        )

    # Custody: from cloud-custody classification (built later, default unknown here)
    custody_cursor = DimensionCursor.unknown(
        "custody", observed_at=now_iso,
        detail="custody classification computed per-session",
    )

    # Run Authority: unavailable from cloud-local observer
    ra_cursor = DimensionCursor.unknown(
        "run_authority", observed_at=now_iso,
        detail="run authority unavailable from cloud-local observer",
    )

    # Work ledger: unavailable from cloud-local observer
    wl_cursor = DimensionCursor.unknown(
        "work_ledger", observed_at=now_iso,
        detail="work ledger unavailable from cloud-local observer",
    )

    # WBC: unavailable from cloud-local observer
    wbc_cursor = DimensionCursor.unknown(
        "wbc", observed_at=now_iso,
        detail="WBC boundary evidence unavailable from cloud-local observer",
    )

    return SourceCursorVector.from_cursors(
        lifecycle_cursor,
        wbc_cursor,
        custody_cursor,
        ra_cursor,
        wl_cursor,
        pc_cursor,
    )


def _build_session_entry(
    marker: Mapping[str, Any],
    *,
    marker_dir: Path,
    repair_data_dir: Path,
    watchdog_by_session: Mapping[str, Mapping[str, Any]],
    watchdog_report_path: Path,
    now: datetime,
    liveness_probe: LivenessProbe,
) -> dict[str, Any]:
    session = str(marker.get("session") or "")
    workspace = _as_path(marker.get("workspace"))
    remote_spec = str(marker.get("remote_spec") or "")
    run_kind = str(marker.get("run_kind") or "chain")
    plan_name = str(marker.get("plan_name") or "")

    marker_path = Path(marker.get("_marker_path") or (marker_dir / f"{session}.json"))
    chain_health = _load_json(marker_dir / f"{session}.chain-health.progress.json")
    chain_health = _overlay_newer_chain_state(
        chain_health,
        workspace=workspace,
        remote_spec=remote_spec,
    )
    repair_progress = _load_json(marker_dir / f"{session}.repair-progress.json")
    needs_human = _load_json(repair_data_dir / f"{session}.needs-human.json")
    watchdog_item = watchdog_by_session.get(session, {})
    watchdog_generated_at = _parse_iso(watchdog_item.get("_report_generated_at"))

    chain_complete = bool(chain_health.get("chain_complete")) if chain_health else False
    completed_count = chain_health.get("completed_count") if chain_health else None
    milestone_count = chain_health.get("milestone_count") if chain_health else None
    current_plan = (
        (chain_health.get("current_plan_name") if chain_health else None)
        or plan_name
        or None
    )
    try:
        current_target_record = resolve_current_target(
            session,
            marker_dir=marker_dir,
            repair_data_dir=repair_data_dir,
        )
    except Exception:
        current_target_record = {}
    current_refs = (
        current_target_record.get("current_refs")
        if isinstance(current_target_record, Mapping)
        else None
    )
    if isinstance(current_refs, Mapping):
        resolved_current_plan = current_refs.get("current_plan_name")
        if isinstance(resolved_current_plan, str) and resolved_current_plan.strip():
            current_plan = resolved_current_plan.strip()
    # Plan lifecycle state for the per-plan stage %. Prefer the plan's own
    # ``current_state`` (from state.json): the chain-health ``last_state`` can be
    # a transient execute sub-state (e.g. ``authority_divergence``, ``error``)
    # that sits off the progression ladder and would under-report the plan's
    # position. Fall back to last_state when state.json is unavailable.
    plan_state_doc = _load_current_plan_state(workspace, str(current_plan or ""))
    review_doc = _load_current_plan_review(workspace, str(current_plan or ""))
    review_verdict = (
        str(review_doc.get("review_verdict") or "").strip().lower()
        if isinstance(review_doc, Mapping)
        else ""
    )
    completed_at = _terminal_completion_at(
        workspace,
        str(current_plan or ""),
        chain_complete=chain_complete,
    )
    plan_current_state = (
        str(plan_state_doc.get("current_state") or "").strip().lower()
        if isinstance(plan_state_doc, Mapping)
        else ""
    )
    plan_state_label = plan_current_state or (
        chain_health.get("last_state") if chain_health else None
    )
    if isinstance(chain_health, Mapping) and chain_health.get("custody_mismatch"):
        plan_state_label = None
    latest_activity = _latest_activity(chain_health, marker, plan_state_doc)
    bound_liveness = (
        current_target_record.get("current_target_liveness")
        if isinstance(current_target_record, Mapping)
        and isinstance(current_target_record.get("current_target_liveness"), Mapping)
        else {}
    )
    liveness = _augment_liveness_with_plan_state(
        _safe_liveness(liveness_probe, marker, marker_dir=marker_dir),
        chain_health=chain_health,
        plan_state=plan_state_doc,
    )
    # Display remains backward compatible, while every control consumer reads
    # this bound tri-state record rather than the injected diagnostic probe.
    liveness["bound"] = dict(bound_liveness)
    superseding_sibling = _find_superseding_sibling(
        marker,
        marker_dir=marker_dir,
        liveness_probe=liveness_probe,
    )

    status, operator_next = _classify_session(
        session=session,
        workspace=workspace,
        remote_spec=remote_spec,
        chain_health=chain_health,
        chain_complete=chain_complete,
        needs_human=needs_human,
        repair_progress=repair_progress,
        watchdog_item=watchdog_item,
        watchdog_generated_at=watchdog_generated_at,
        liveness=liveness,
        superseding_sibling=superseding_sibling,
        latest_activity_dt=_parse_iso(latest_activity),
        marker_dir=marker_dir,
        repair_data_dir=repair_data_dir,
        current_plan=str(current_plan or ""),
        plan_state=plan_state_doc,
        now=now,
    )
    marker_should_run = marker.get("should_run")
    operator_pause = marker.get("operator_pause")
    operator_pause_active = bool(
        isinstance(operator_pause, Mapping) and operator_pause.get("active") is True
    )
    canonical_stop_intent = marker_should_run is False or operator_pause_active
    if canonical_stop_intent and status != "complete":
        # Marker intent is durable operator authority.  Recent activity and a
        # gated lifecycle state (or a process that has not exited yet) are
        # observation only: none may turn an intentionally stopped session
        # back into active/attention status.  Process truth remains available
        # in the orthogonal tmux/process fields.
        status = "paused"
        pause_reason = (
            str(operator_pause.get("reason") or "").strip()
            if isinstance(operator_pause, Mapping)
            else ""
        )
        operator_next = (
            f"intentional operator stop: {pause_reason}; explicit resume required"
            if pause_reason
            else "intentional operator stop; explicit resume required"
        )
    if canonical_stop_intent or status in {"complete", "paused"}:
        projected_should_run = False
    elif marker_should_run is True:
        projected_should_run = True
    else:
        projected_should_run = plan_current_state != "paused"
    watchdog_status = _watchdog_status(watchdog_item, chain_complete)
    if (
        status == "attention"
        and watchdog_status == "alive"
        and not (liveness.get("tmux") or liveness.get("process"))
    ):
        # The report describes an earlier sweep, not current runner truth.
        # Keep the stale observation visible without presenting it as live.
        watchdog_status = "stale"

    try:
        advancement_policy = policy_for_spec_path(remote_spec) if remote_spec else AdvancementPolicy(
            merge_policy="auto",
            clean_milestone_pr="auto",
            auto_approve=True,
            source="plan_default",
        )

    except Exception:
        advancement_policy = AdvancementPolicy(
            merge_policy="unknown",
            clean_milestone_pr="unknown",
            auto_approve=False,
            source="unreadable_spec",
        )
    latest_failure = (
        plan_state_doc.get("latest_failure")
        if isinstance(plan_state_doc, Mapping)
        and isinstance(plan_state_doc.get("latest_failure"), Mapping)
        else {}
    )
    active_step_for_advancement = bool(
        isinstance(plan_state_doc, Mapping) and plan_state_doc.get("active_step")
    ) and bool(liveness.get("tmux") or liveness.get("process"))
    # ── Successor gate parameters ─────────────────────────────────────
    _successors: list = []
    _completion_contract_mode = "shadow"
    _has_final_acceptance_receipt = False
    _final_milestone_label = None
    _final_milestone_plan_name = None
    _chain_state_doc: dict[str, Any] | None = None
    if remote_spec and chain_complete:
        try:
            _spec = load_chain_spec(Path(remote_spec))
            _successors = getattr(_spec, "successors", None) or []
            if chain_health:
                _completion_contract_mode = str(
                    chain_health.get("completion_contract_mode", "shadow")
                )
            if _spec.milestones:
                _final_milestone_label = _spec.milestones[-1].label
                # Load the chain state file directly to check for an
                # acceptance receipt on the final milestone.
                _state_path, _chain_state_doc = _load_latest_chain_state(workspace)
                if isinstance(_chain_state_doc, dict):
                    _completed = _chain_state_doc.get("completed")
                    if isinstance(_completed, list):
                        for _rec in _completed:
                            if isinstance(_rec, dict) and _rec.get("label") == _final_milestone_label:
                                _has_final_acceptance_receipt = isinstance(
                                    _rec.get("acceptance_receipt"), dict
                                )
                                if _has_final_acceptance_receipt:
                                    _final_milestone_plan_name = str(
                                        _rec.get("plan") or ""
                                    ).strip() or None
                                break
        except Exception:
            pass

    # ── Accepted-progress projection ─────────────────────────────────
    # Compute which milestones carry acceptance receipts so consumers
    # (watchdog, resident, human operators) can distinguish authoritative
    # milestone transitions from worker activity, review, repair, custody,
    # and fixer-infrastructure liveness signals.  This is purely a status
    # projection — it never gates transitions.
    _accepted_milestone_labels: list[str] = []
    _acceptance_required = False
    _waiting_for_acceptance = False
    _acceptance_contract_mode = _completion_contract_mode
    if remote_spec and chain_health:
        try:
            _acceptance_contract_mode = str(
                chain_health.get("completion_contract_mode", "shadow")
            )
        except Exception:
            _acceptance_contract_mode = "shadow"

    if _chain_state_doc is None and remote_spec:
        try:
            _state_path2, _chain_state_doc = _load_latest_chain_state(workspace)
        except Exception:
            _chain_state_doc = None

    if isinstance(_chain_state_doc, dict):
        _completed_records = _chain_state_doc.get("completed")
        if isinstance(_completed_records, list):
            for _rec in _completed_records:
                if isinstance(_rec, dict) and isinstance(_rec.get("acceptance_receipt"), dict):
                    _label = _rec.get("label")
                    if isinstance(_label, str) and _label:
                        _accepted_milestone_labels.append(_label)

    # Determine whether acceptance is required for successor chains.
    from arnold_pipelines.megaplan.orchestration.completion_contract import (
        is_fail_closed_mode,
    )
    _is_fail_closed = is_fail_closed_mode(_acceptance_contract_mode)
    if _is_fail_closed:
        try:
            _succ_spec = _successors if _successors else (
                getattr(load_chain_spec(Path(remote_spec)), "successors", None) or []
                if remote_spec else []
            )
            _acceptance_required = any(
                getattr(_s, "require_accepted_transaction", True)
                for _s in _succ_spec
            )
        except Exception:
            _acceptance_required = bool(_successors)

    _waiting_for_acceptance = (
        chain_complete
        and _is_fail_closed
        and _acceptance_required
        and not _has_final_acceptance_receipt
    )

    accepted_progress: dict[str, Any] = {
        "accepted_milestones": _accepted_milestone_labels,
        "final_milestone_accepted": _has_final_acceptance_receipt,
        "mode": _acceptance_contract_mode,
        "acceptance_required": _acceptance_required,
        "waiting_for_acceptance": _waiting_for_acceptance,
    }
    repair_projection = _compose_repair_decision_projection(
        workspace=workspace,
        queue_root=marker_dir.parent / "repair-queue",
        repair_data_dir=repair_data_dir,
        plan_state=plan_state_doc,
        current_target=current_target_record,
    )
    repair_custody = (
        repair_projection.get("repair_custody")
        if isinstance(repair_projection.get("repair_custody"), Mapping)
        else None
    )
    parent_custody: dict[str, Any] | None = None
    if _has_final_acceptance_receipt and isinstance(repair_custody, Mapping):
        active_repair_subject_ids: list[str] = []
        current_target = (
            repair_custody.get("current_target")
            if isinstance(repair_custody.get("current_target"), Mapping)
            else {}
        )
        current_refs = (
            current_target.get("current_refs")
            if isinstance(current_target, Mapping)
            and isinstance(current_target.get("current_refs"), Mapping)
            else {}
        )
        repair_plan_state = (
            repair_custody.get("plan_state")
            if isinstance(repair_custody.get("plan_state"), Mapping)
            else {}
        )
        for value in (
            current_refs.get("current_plan_name"),
            current_refs.get("chain_current_plan_name"),
            repair_plan_state.get("name"),
        ):
            if isinstance(value, str) and value.strip():
                active_repair_subject_ids.append(value.strip())
        blocker_id = repair_custody.get("blocker_id")
        parent_custody = {
            "accepted_subject_ids": (
                [_final_milestone_plan_name] if _final_milestone_plan_name else []
            ),
            "active_repair_subject_ids": list(
                dict.fromkeys(active_repair_subject_ids)
            ),
            "accepted_repair_occurrence_ids": [],
            "active_repair_occurrence_ids": (
                [blocker_id.strip()]
                if durable_repair_active(repair_custody)
                and isinstance(blocker_id, str)
                and blocker_id.strip()
                else []
            ),
        }
    advancement = assess_advancement(
        advancement_policy,
        current_state=plan_current_state,
        chain_last_state=(chain_health.get("last_state") if chain_health else None),
        chain_complete=chain_complete or status == "complete",
        pr_state=(chain_health.get("pr_state") if chain_health else None),
        active_step=active_step_for_advancement,
        explicit_human_gate=(operator_next if status == "blocked" else None),
        failure_kind=latest_failure.get("kind"),
        successors=_successors,
        completion_contract_mode=_completion_contract_mode,
        completed_count=completed_count or 0,
        has_final_acceptance_receipt=_has_final_acceptance_receipt,
        final_milestone_label=_final_milestone_label,
        parent_custody=parent_custody,
    )
    active_step = (
        plan_state_doc.get("active_step")
        if isinstance(plan_state_doc, Mapping)
        and isinstance(plan_state_doc.get("active_step"), Mapping)
        else None
    )
    # ── M9: build source-cursor metadata for this session row ──
    _observed_at_epoch_ms = now.timestamp() * 1000
    _session_source_cursor = _build_session_source_cursor(
        session=session,
        plan_current_state=plan_current_state,
        plan_state_doc=plan_state_doc,
        chain_health=chain_health,
        watchdog_item=watchdog_item,
        liveness=liveness,
        observed_at_epoch_ms=_observed_at_epoch_ms,
    )
    _lifecycle_cursor = _session_source_cursor.cursor("lifecycle")

    presentation = plan_status_presentation(
        plan_state_label,
        active_step=active_step,
        review_verdict=review_verdict,
        completed=chain_complete or status == "complete",
        source_cursor=_session_source_cursor,
        lifecycle_cursor=_lifecycle_cursor,
        observed_at_epoch_ms=_observed_at_epoch_ms,
        evaluation_at_epoch_ms=_observed_at_epoch_ms,
    )

    custody_classification = _classify_session_custody(
        session_id=session,
        supervisor_identity=str(marker.get("supervisor_identity") or ""),
        tmux_live=bool(liveness.get("tmux")),
        process_live=bool(liveness.get("process")),
        active_step_worker_pid_liveness=bool(liveness.get("process")),
        watchdog_status=_watchdog_status(watchdog_item, chain_complete),
        chain_complete=chain_complete,
        relaunch_command=str(marker.get("relaunch_command") or ""),
        needs_human=bool(needs_human),
        repair_active=(status == "repairing"),
        now=now,
    )

    # --- S4: enriched status fields -----------------------------------------
    lifecycle_state = plan_current_state or ""
    activity_phase = _derive_activity_phase(plan_state_doc, plan_current_state, status)
    semantic_health = _derive_semantic_health(
        session=session,
        workspace=workspace,
        current_plan=current_plan,
        plan_state_doc=plan_state_doc,
    )
    repair_state = _derive_repair_state(status, repair_progress)
    custody_state = custody_classification.custody_kind if custody_classification else ""
    repairable_issue = _derive_repairable_issue(plan_state_doc)

    entry = {
        "session": session,
        "display_name": session,
        "workspace": str(workspace) if workspace else "",
        "spec": remote_spec,
        "run_kind": run_kind,
        "started_at": marker.get("started_at"),
        "status": status,
        "should_run": projected_should_run,
        "operator_pause": (
            dict(operator_pause) if isinstance(operator_pause, Mapping) else None
        ),
        "tmux": liveness.get("tmux", False),
        "process": liveness.get("process", False),
        "liveness_state": liveness.get("state", "unknown"),
        "liveness_source": liveness.get("source", "local_probe"),
        "watchdog": watchdog_status,
        "repairing": status == "repairing",
        "current_plan": current_plan,
        # A terminal completion receipt is deliberately distinct from
        # ``latest_activity``.  The latter includes watchdog/health rewrites,
        # which must never make an old completed chain look recently complete.
        "completed_at": completed_at,
        "completed_count": completed_count,
        "milestone_count": milestone_count,
        "chain_complete": chain_complete,
        "plan_state": plan_current_state or None,
        "review_verdict": review_verdict or None,
        # Accepted-progress projection: distinguishes authoritative
        # milestone transitions (backed by acceptance receipts) from
        # worker activity, review, repair, custody, and fixer-infra
        # liveness signals.  Consumers read this to decide whether
        # progress is accepted or merely observed.
        "accepted_progress": accepted_progress,
        **presentation,
        "progress": _session_progress(
            completed_count=completed_count,
            milestone_count=milestone_count,
            current_plan=current_plan,
            complete=chain_complete,
            plan_state=plan_state_label,
            execution_progress=_execution_task_progress(workspace, str(current_plan or "")),
            presentation=presentation,
        ),
        "pr_number": chain_health.get("pr_number") if chain_health else None,
        "pr_state": chain_health.get("pr_state") if chain_health else None,
        "latest_activity": latest_activity,
        "operator_next": operator_next,
        "advancement": advancement.to_dict(),
        "cloud_custody": custody_classification.to_dict(),
        "lifecycle_state": lifecycle_state,
        "activity_phase": activity_phase,
        "semantic_health": semantic_health,
        "repair_state": repair_state,
        "custody_state": custody_state,
        "repairable_issue": repairable_issue,
        # ── M9: source-cursor metadata on the session row ──
        "source_cursor": _session_source_cursor.to_dict() if _session_source_cursor else None,
        "_non_authoritative": True,
        "evidence": {
            "marker": str(marker_path),
            "chain_health": str(marker_dir / f"{session}.chain-health.progress.json"),
            "watchdog_report": str(watchdog_report_path),
            "needs_human": (
                str(repair_data_dir / f"{session}.needs-human.json") if needs_human else None
            ),
            "superseded_by": superseding_sibling,
            "liveness_lease": liveness.get("lease"),
        },
    }
    # ── M9: mark plan-percent bookkeeping as explicitly non-authoritative ──
    if isinstance(entry.get("progress"), dict):
        entry["progress"]["_non_authoritative"] = True
    entry.update(
        _compose_shadow_views(
            session=session,
            marker=marker,
            marker_path=marker_path,
            watchdog_report_path=watchdog_report_path,
            watchdog_item=watchdog_item,
            chain_health=chain_health,
            needs_human=needs_human,
            needs_human_path=repair_data_dir / f"{session}.needs-human.json",
            repair_progress=repair_progress,
            repair_progress_path=marker_dir / f"{session}.repair-progress.json",
            plan_state=plan_state_doc,
            current_target=current_target_record,
            liveness=liveness,
            latest_activity=latest_activity,
            now=now,
        )
    )
    entry.update(repair_projection)
    custody = repair_projection.get("repair_custody")
    # Normal execution classification is authoritative unless the canonical
    # custody projection proves a current durable repair owner/attempt.  Labels,
    # sidecars, broken-superfixer decisions, and projection failures can never
    # upgrade the display to repairing.
    if durable_repair_active(custody if isinstance(custody, Mapping) else None):
        entry["status"] = "repairing"
        entry["repairing"] = True
        entry["operator_next"] = "automated repair dispatched for this session"
    else:
        entry["repairing"] = False
    return entry


def _compose_repair_decision_projection(
    *,
    workspace: Path | None,
    queue_root: Path | None = None,
    repair_data_dir: Path,
    plan_state: Mapping[str, Any] | None,
    current_target: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Use the same custody/dispatch contract consumed by watchdog dispatch."""

    if workspace is None or not isinstance(plan_state, Mapping):
        return {
            "repair_custody": None,
            "repair_dispatch": None,
            "repair_projection_degraded": None,
        }
    effective_queue_root = queue_root or (workspace / ".megaplan" / "repair-queue")
    try:
        canonical = resolve_run_state(current_target or {})
        custody = project_repair_custody(
            plan_state=plan_state,
            current_target=current_target,
            canonical_run_state=canonical,
            queue_root=effective_queue_root,
            repair_data_dir=repair_data_dir,
        )
        dispatch = classify_repair_dispatch(
            canonical_run_state=canonical,
            plan_state=plan_state,
            current_target=current_target,
            custody_projection=custody,
        )
        return {
            "repair_custody": custody,
            "repair_dispatch": {
                "decision": dispatch.decision,
                "dispatch_intent": dispatch.dispatch_intent,
                "request_id": dispatch.request_id,
                "blocker_id": dispatch.blocker_id,
                "failure_kind": dispatch.failure_kind,
                "custody_bucket": dispatch.custody_bucket,
                "rationale": list(dispatch.rationale),
                "evidence_cursor": custody.get("evidence_cursor", {}),
                "request_count": custody.get("request_count", 0),
                "claim_count": custody.get("claim_count", 0),
                "attempt_count": custody.get("attempt_count", 0),
                "retry_budget": custody.get("retry_budget", {}),
            },
            "repair_projection_degraded": None,
        }
    except Exception as exc:
        return {
            "repair_custody": None,
            "repair_dispatch": None,
            "repair_projection_degraded": {
                "status": "degraded",
                "error_type": type(exc).__name__,
                "reason": f"canonical repair projection failed: {type(exc).__name__}",
            },
        }


def _compose_shadow_views(
    *,
    session: str,
    marker: Mapping[str, Any],
    marker_path: Path,
    chain_health: Mapping[str, Any] | None,
    plan_state: Mapping[str, Any] | None,
    current_target: Mapping[str, Any],
    liveness: Mapping[str, bool],
    latest_activity: str | None,
    now: datetime,
    watchdog_report_path: Path | None = None,
    watchdog_item: Mapping[str, Any] | None = None,
    needs_human: Mapping[str, Any] | None = None,
    needs_human_path: Path | None = None,
    repair_progress: Mapping[str, Any] | None = None,
    repair_progress_path: Path | None = None,
) -> dict[str, Any]:
    """Compose sibling diagnostic views from values already collected above.

    These projections are deliberately appended after legacy classification has
    completed.  They perform no reads and are not inputs to ``status``,
    ``operator_next``, or any repair decision.
    """

    plan_record = current_target.get("plan_state")
    plan_record = plan_record if isinstance(plan_record, Mapping) else {}
    chain_record = current_target.get("chain_state")
    chain_record = chain_record if isinstance(chain_record, Mapping) else {}
    run_revision = str(plan_record.get("fingerprint") or chain_record.get("fingerprint") or "unobserved")
    authority = reduce_run_authority((), run_id=session or "unknown-session", run_revision=run_revision)
    execution = derive_plan_execution_view(
        authority,
        plan_state if isinstance(plan_state, Mapping) else (),
        evidence_decisions={},
        plan_source=str(plan_record.get("path") or "observation://plan-state-unavailable"),
    )
    execution = _add_collector_diagnostics(execution, current_target, plan_record)

    marker_source = str(marker_path)
    runner_observations: list[dict[str, Any]] = [{
        "observation_type": "process",
        "source": marker_source,
        "state": "live" if liveness.get("tmux") or liveness.get("process") else "stopped",
        "identity": session or None,
        "expected_identity": session or None,
    }]
    activity_dt = _parse_iso(latest_activity)
    if activity_dt is not None:
        age = max(0, int((now - activity_dt).total_seconds()))
        runner_observations.append({
            "observation_type": "heartbeat",
            "source": str(plan_record.get("path") or chain_record.get("path") or marker_source),
            "state": "live" if age <= STALE_ACTIVITY_S else "unknown",
            "identity": session or None,
            "expected_identity": session or None,
            "heartbeat_age_seconds": age,
            "stale": age > STALE_ACTIVITY_S,
        })
    runner = derive_runner_view(
        runner_observations,
        expected_identity=session or None,
        stale_after_seconds=STALE_ACTIVITY_S,
    )

    marker_publication: dict[str, Any] = {"source": marker_source}
    health_source = str(marker_path.with_name(f"{session}.chain-health.progress.json"))
    health_publication: dict[str, Any] = {"source": health_source}
    for field in ("branch", "dirty_workspace", "pushed_sha", "auth", "no_push"):
        if isinstance(chain_health, Mapping) and field in chain_health:
            health_publication[field] = chain_health[field]
        if field in marker:
            marker_publication[field] = marker[field]
    if isinstance(chain_health, Mapping) and chain_health.get("pr_number") is not None:
        health_publication["pull_request"] = str(chain_health["pr_number"])
    publication = derive_publication_view((marker_publication, health_publication))

    # --- human-gate projection -------------------------------------------------
    human_gate_signals: list[dict[str, Any]] = []
    from arnold_pipelines.megaplan.run_state.decision_contract import typed_human_gate

    if needs_human and isinstance(needs_human, Mapping) and typed_human_gate(needs_human) is not None:
        human_gate_signals.append({
            "gate_type": str(
                needs_human.get("human_gate")
                or needs_human.get("gate_type")
                or needs_human.get("gate_kind")
            ),
            "source": str(needs_human_path or "observation://needs-human"),
            "plan_ref": needs_human.get("plan_ref"),
            "stale_token": needs_human.get("stale_token"),
            "superseded": needs_human.get("superseded"),
            "summary": needs_human.get("summary"),
            "reason": needs_human.get("reason") or needs_human.get("summary"),
        })
    human_gate = derive_human_gate_view(
        human_gate_signals,
        current_plan_revision=run_revision,
    )

    # --- recovery custody projection -------------------------------------------
    recovery = derive_megaplan_recovery_view(
        # Legacy repair-progress is a diagnostic observation, not custody.
        repair_custody=None,
        runner_view=runner,
        execution_view=execution,
        publication_view=publication,
        human_gate_view=human_gate,
        custody_source=str(repair_progress_path or "observation://repair-progress"),
    )

    # --- composition facade ----------------------------------------------------
    megaplan_plan_view = derive_megaplan_plan_view(
        execution_view=execution,
        runner_view=runner,
        publication_view=publication,
        human_gate_view=human_gate,
        recovery_view=recovery,
    )

    return {
        "execution_authority": execution.to_dict(),
        "runner": runner.to_dict(),
        "publication": publication.to_dict(),
        "human_gate": human_gate.to_dict(),
        "recovery": recovery.to_dict(),
        "megaplan_plan_view": megaplan_plan_view.to_dict(),
        "status_authority_shadow": _status_authority_shadow(
            session=session,
            marker=marker,
            marker_path=marker_path,
            watchdog_report_path=watchdog_report_path,
            watchdog_item=watchdog_item or {},
            chain_health=chain_health,
            health_source=health_source,
            needs_human=needs_human,
            needs_human_path=needs_human_path,
            repair_progress=repair_progress,
            repair_progress_path=repair_progress_path,
            plan_record=plan_record,
            chain_record=chain_record,
            runner=runner.to_dict(),
            publication=publication.to_dict(),
            human_gate=human_gate.to_dict(),
            recovery=recovery.to_dict(),
        ),
    }


def _status_authority_shadow(
    *,
    session: str,
    marker: Mapping[str, Any],
    marker_path: Path,
    watchdog_report_path: Path | None,
    watchdog_item: Mapping[str, Any],
    chain_health: Mapping[str, Any] | None,
    health_source: str,
    needs_human: Mapping[str, Any] | None,
    needs_human_path: Path | None,
    repair_progress: Mapping[str, Any] | None,
    repair_progress_path: Path | None,
    plan_record: Mapping[str, Any],
    chain_record: Mapping[str, Any],
    runner: Mapping[str, Any],
    publication: Mapping[str, Any],
    human_gate: Mapping[str, Any] | None = None,
    recovery: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Name status drift sources without feeding them back into classification."""

    marker_source = str(marker_path)
    diagnostics: list[dict[str, str]] = []
    source_paths: set[str] = {marker_source}
    plan_source = str(plan_record.get("path") or "observation://plan-state-unavailable")
    chain_source = str(chain_record.get("path") or health_source)
    source_paths.update({plan_source, chain_source})

    plan_state = str(plan_record.get("current_state") or "").strip().lower()
    chain_state = str(
        chain_record.get("last_state")
        or chain_record.get("current_state")
        or (chain_health.get("last_state") if isinstance(chain_health, Mapping) else "")
        or ""
    ).strip().lower()
    if plan_state and chain_state and plan_state != chain_state:
        diagnostics.append({
            "code": "legacy_status_execution_authority_drift",
            "domain": "execution_authority",
            "reason": (
                f"plan state {plan_state!r} and chain/status state {chain_state!r} "
                "are observations only; execution authority remains the shadow projection"
            ),
            "source": f"{plan_source},{chain_source}",
        })

    runner_source = (
        str(watchdog_report_path)
        if watchdog_report_path is not None and watchdog_item
        else marker_source
    )
    source_paths.add(runner_source)
    diagnostics.append({
        "code": "runner_liveness_separate_from_execution_authority",
        "domain": "runner",
        "reason": (
            f"runner status {runner.get('status')!r} is process liveness and grants no task authority"
        ),
        "source": runner_source,
    })

    publication_sources = set()
    raw_publication_sources = publication.get("source_paths")
    if isinstance(raw_publication_sources, list):
        publication_sources.update(str(item) for item in raw_publication_sources if str(item))
    publication_sources.update({marker_source, health_source})
    source_paths.update(publication_sources)
    diagnostics.append({
        "code": "publication_separate_from_execution_authority",
        "domain": "publication",
        "reason": (
            f"publication status {publication.get('status')!r} is publish readiness and grants no task authority"
        ),
        "source": ",".join(sorted(publication_sources)),
    })

    # --- human-gate diagnostics (read-only shadow) --------------------------
    human_gate_sources: set[str] = set()
    if needs_human:
        human_source = str(needs_human_path or "observation://needs-human")
        human_gate_sources.add(human_source)
    if isinstance(human_gate, Mapping):
        raw_hg_sources = human_gate.get("source_paths")
        if isinstance(raw_hg_sources, (list, tuple)):
            human_gate_sources.update(str(item) for item in raw_hg_sources if str(item))
    if human_gate_sources:
        source_paths.update(human_gate_sources)
        diagnostics.append({
            "code": "human_gate_separate_from_execution_authority",
            "domain": "human_gate",
            "reason": (
                f"human-gate status {human_gate.get('status', 'unknown')!r} "
                "is an observation only and grants no task authority"
            ),
            "source": ",".join(sorted(human_gate_sources)),
        })
    if isinstance(human_gate, Mapping):
        for diag in human_gate.get("diagnostics") or ():
            if isinstance(diag, Mapping) and diag.get("code") and diag.get("source"):
                source_paths.add(str(diag["source"]))
                diagnostics.append({
                    "code": str(diag["code"]),
                    "domain": "human_gate",
                    "reason": str(diag.get("reason") or "no reason provided"),
                    "source": str(diag["source"]),
                })

    # --- recovery diagnostics (read-only shadow) ----------------------------
    recovery_sources: set[str] = set()
    if repair_progress:
        repair_source = str(repair_progress_path or "observation://repair-progress")
        recovery_sources.add(repair_source)
    if isinstance(recovery, Mapping):
        raw_rec_sources = recovery.get("source_paths")
        if isinstance(raw_rec_sources, (list, tuple)):
            recovery_sources.update(str(item) for item in raw_rec_sources if str(item))
    if recovery_sources:
        source_paths.update(recovery_sources)
        diagnostics.append({
            "code": "recovery_custody_separate_from_execution_authority",
            "domain": "recovery",
            "reason": (
                f"recovery status {recovery.get('status', 'unknown')!r} "
                "is read-only custody projection and grants no task authority"
            ),
            "source": ",".join(sorted(recovery_sources)),
        })
    if isinstance(recovery, Mapping):
        for diag in recovery.get("diagnostics") or ():
            if isinstance(diag, Mapping) and diag.get("code") and diag.get("source"):
                source_paths.add(str(diag["source"]))
                diagnostics.append({
                    "code": str(diag["code"]),
                    "domain": "recovery",
                    "reason": str(diag.get("reason") or "no reason provided"),
                    "source": str(diag["source"]),
                })

    values = {
        "schema_version": 1,
        "session": session or "unknown-session",
        "shadow": True,
        "read_only": True,
        "status_consumers_unchanged": True,
        "source_paths": sorted(source_paths),
        "diagnostics": sorted(diagnostics, key=lambda item: canonical_json(item)),
    }
    digest = hashlib.sha256(canonical_json(values).encode("utf-8")).hexdigest()
    return {**values, "view_hash": digest}


def _add_collector_diagnostics(
    view: PlanExecutionView,
    current_target: Mapping[str, Any],
    plan_record: Mapping[str, Any],
) -> PlanExecutionView:
    """Retain source-addressable legacy contradictions without promoting them."""

    diagnostics = list(view.diagnostics)
    plan_state = str(plan_record.get("current_state") or "").strip()
    plan_source = str(plan_record.get("path") or "observation://plan-state-unavailable")
    if plan_state:
        diagnostics.append(PlanExecutionDiagnostic(
            "legacy_plan_state_observation",
            str(plan_record.get("name") or "plan"),
            f"legacy plan state {plan_state!r} is diagnostic only and grants no task authority",
            plan_source,
        ))
    stale_evidence = current_target.get("stale_evidence")
    if isinstance(stale_evidence, list):
        for index, item in enumerate(stale_evidence):
            if not isinstance(item, Mapping):
                continue
            code = str(item.get("kind") or "stale_collector_evidence")
            source = str(item.get("path") or "observation://current-target")
            diagnostics.append(PlanExecutionDiagnostic(
                code,
                str(item.get("plan_name") or item.get("session") or f"collector-{index}"),
                f"current-target collector reported {code.replace('_', ' ')}",
                source,
            ))
    values = {
        "schema_version": view.schema_version,
        "run_id": view.run_id,
        "run_revision": view.run_revision,
        "authority_view_hash": view.authority_view_hash,
        "tasks": view.tasks,
        "accepted_task_ids": view.accepted_task_ids,
        "accepted_task_attempts": view.accepted_task_attempts,
        "dependency_closed_completed_task_ids": view.dependency_closed_completed_task_ids,
        "next_ready_wave": view.next_ready_wave,
        "unresolved_claim_ids": view.unresolved_claim_ids,
        "quarantine_ids": view.quarantine_ids,
        "diagnostics": tuple(sorted(set(diagnostics))),
    }
    unsigned = PlanExecutionView(**values, view_hash="pending")
    digest = hashlib.sha256(canonical_json(unsigned._payload()).encode("utf-8")).hexdigest()
    return PlanExecutionView(**values, view_hash=digest)


def _classify_session(
    *,
    session: str,
    workspace: Path | None,
    remote_spec: str,
    chain_health: Mapping[str, Any],
    chain_complete: bool,
    needs_human: Mapping[str, Any],
    repair_progress: Mapping[str, Any],
    watchdog_item: Mapping[str, Any],
    watchdog_generated_at: datetime | None,
    liveness: Mapping[str, bool],
    superseding_sibling: str | None,
    latest_activity_dt: datetime | None,
    marker_dir: Path,
    repair_data_dir: Path,
    current_plan: str,
    plan_state: Mapping[str, Any] | None,
    now: datetime,
) -> tuple[SessionStatus, str]:
    # Structural problems first: a session we cannot reason about is attention.
    if not session:
        return "attention", "marker has no session name"
    if workspace is None or not workspace.exists():
        return "attention", "workspace missing or unreadable"
    if chain_health is None and not remote_spec and not _is_plan_kind_marker(workspace):
        return "attention", "no chain-health snapshot and no remote spec"

    if superseding_sibling and not (liveness.get("tmux") or liveness.get("process")):
        return (
            "complete",
            f"superseded by sibling session {superseding_sibling}; no runner expected",
        )

    if _canonical_spec_missing(workspace, remote_spec):
        return "attention", "spec missing or unreadable"

    if isinstance(chain_health, Mapping) and chain_health.get("custody_mismatch"):
        completed = chain_health.get("completed_count")
        total = chain_health.get("milestone_count")
        current_index = chain_health.get("current_milestone_index")
        return (
            "attention",
            "chain custody mismatch: terminal state with "
            f"completed={completed}/{total} current_milestone_index={current_index}",
        )

    plan_current_state = (
        str(plan_state.get("current_state") or "").strip().lower()
        if isinstance(plan_state, Mapping)
        else ""
    )
    if plan_current_state == "paused" or str((chain_health or {}).get("last_state") or "").lower() == "paused":
        return "paused", "durable operator pause; explicit resume required"

    # A live runner with activity newer than the needs-human marker means the
    # target has moved since escalation. Do not let that stale marker mask the
    # recovery/retry that is currently executing.
    if _needs_human_superseded_by_live_activity(
        needs_human=needs_human,
        liveness=liveness,
        latest_activity_dt=latest_activity_dt,
    ):
        return "running", "live runner activity supersedes older needs-human marker"

    if _needs_human_superseded_by_authoritative_recovery(
        needs_human=needs_human,
        plan_state=plan_state,
    ):
        return "attention", "newer authoritative recovery evidence supersedes needs-human marker"

    # A current needs-human sidecar is ground truth for non-repairing active
    # work. A complete chain with no active plan has no live repair target, so
    # stale repair exhaustion markers from earlier ticks must not keep it
    # blocked forever.
    if _is_current_needs_human(
        session=session,
        needs_human=needs_human,
        marker_dir=marker_dir,
        repair_data_dir=repair_data_dir,
        current_plan=current_plan,
        chain_complete=chain_complete,
        latest_activity_dt=latest_activity_dt,
    ):
        return "blocked", _needs_human_reason(needs_human)

    if _is_needs_human(needs_human) and not (chain_complete and not current_plan):
        return (
            "attention",
            "needs-human marker lacks current typed decision proof; control-plane evidence needs repair",
        )

    # The watchdog report is the authority on runner truth: it reads the
    # authoritative chain state every tick. The chain-health sidecar can freeze
    # at the last non-complete snapshot for a finished chain (it stops being
    # refreshed once the session goes idle), so defer to the watchdog's verdict
    # when it has already classified the session. Without this the snapshot
    # reports done chains as stalled attention, disagreeing with the watchdog.
    wd_status = str(watchdog_item.get("status") or "").lower()
    if wd_status in {"complete", "completed"}:
        chain_health_updated_at = _parse_iso(chain_health.get("updated_at")) if isinstance(chain_health, Mapping) else None
        if not (
            watchdog_generated_at is not None
            and chain_health_updated_at is not None
            and chain_health_updated_at > watchdog_generated_at
            and _chain_health_explicitly_incomplete(chain_health)
        ):
            return "complete", "watchdog reports chain complete"

    # Terminal success is the strongest signal and beats stale plan failures.
    if chain_complete:
        return "complete", "chain complete; no runner expected"

    if _has_current_repairable_failure(plan_state):
        return "attention", "alive_but_failed: current repairable failure receipt remains"

    if liveness.get("tmux") or liveness.get("process"):
        return "running", "live runner process observed"

    if plan_current_state in {"done", "complete", "completed"} and not chain_complete:
        return (
            "attention",
            "terminal plan has no live runner but chain completion is not recorded; "
            "relaunch/reconciliation required",
        )

    active_step = (
        plan_state.get("active_step")
        if isinstance(plan_state, Mapping)
        and isinstance(plan_state.get("active_step"), Mapping)
        else {}
    )
    if active_step:
        return (
            "attention",
            "active step has no authoritative live runner lease; process state is unknown "
            "and activity sidecars do not establish liveness",
        )

    # Recent activity is useful display context, never liveness authority.
    if latest_activity_dt is not None and (now - latest_activity_dt).total_seconds() <= STALE_ACTIVITY_S:
        return "attention", "recent activity observed but runner liveness is unknown"

    # Not complete, not blocked, not under repair, not live, not recent. That is
    # exactly the "should be working but is not" case the watchdog escalates.
    if latest_activity_dt is None:
        return "attention", "no activity timestamp; cannot confirm liveness"
    return "attention", f"stalled (no live process, last activity {_age_s(latest_activity_dt, now)}s ago)"


def _canonical_spec_missing(workspace: Path, remote_spec: str) -> bool:
    """True when a chain marker points at a spec that should exist locally.

    Many tests and some legacy markers carry placeholder specs outside the
    workspace. Those are not enough to invalidate a session. A spec inside the
    session workspace is canonical durable input, though; if that file is gone,
    old chain-health and needs-human sidecars are stale evidence and must not
    keep the session classified as a live blocker.
    """
    if not remote_spec:
        return False
    try:
        spec_path = Path(remote_spec)
        workspace_resolved = workspace.resolve()
        spec_resolved = spec_path.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return False
    if spec_resolved != workspace_resolved and workspace_resolved not in spec_resolved.parents:
        return False
    return not spec_path.exists()


# --- source file readers ---------------------------------------------------


def _load_watchdog_report(
    primary: Path, fallback: Path
) -> tuple[dict[str, Any] | None, dict[str, dict[str, Any]], list[str]]:
    path = primary if primary.exists() else (fallback if fallback.exists() else None)
    if path is None:
        return None, {}, [f"watchdog report missing (looked for {primary}, {fallback})"]
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, {}, [f"watchdog report unreadable at {path}: {exc.__class__.__name__}"]
    if not isinstance(report, dict):
        return None, {}, [f"watchdog report at {path} is not a JSON object"]
    by_session: dict[str, dict[str, Any]] = {}
    for section in ("items", "issues"):
        items = report.get(section)
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            name = item.get("session")
            if isinstance(name, str) and name:
                stamped = dict(item)
                stamped["_report_generated_at"] = report.get("timestamp_utc")
                # Keep the most informative item per session.
                existing = by_session.get(name)
                if existing is None or _item_signal_rank(stamped) > _item_signal_rank(existing):
                    by_session[name] = stamped
    return report, by_session, []


def _item_signal_rank(item: Mapping[str, Any]) -> int:
    """Rank watchdog items so the most actionable one wins per session."""
    status = str(item.get("status") or "")
    order = [
        "needs_human",
        "restarted",
        "reaped",
        "sync_dirty",
        "sync_failed",
        "alive",
        "skipped",
        "synced",
        "complete",
        "completed",
    ]
    try:
        return len(order) - order.index(status)
    except ValueError:
        return -1


def _load_session_markers(marker_dir: Path) -> list[dict[str, Any]]:
    if not marker_dir.exists():
        return []
    markers: list[dict[str, Any]] = []
    for path in sorted(marker_dir.glob("*.json")):
        if not is_canonical_session_marker_path(path):
            continue
        payload = _load_json(path)
        if not isinstance(payload, dict) or not payload.get("session"):
            continue
        session = str(payload.get("session"))
        if status_retirement_matches(
            marker_dir=marker_dir,
            marker_path=path,
            session=session,
        ):
            continue
        payload["_marker_path"] = str(path)
        markers.append(payload)
    return markers


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _find_superseding_sibling(
    marker: Mapping[str, Any],
    *,
    marker_dir: Path,
    liveness_probe: LivenessProbe,
) -> str | None:
    """Return sibling evidence that makes this stale marker non-actionable.

    The watchdog wrapper has the same operational rule for stopped sessions:
    when another canonical marker in the same workspace owns the live work, the
    older marker is superseded rather than relaunched or escalated. The snapshot
    needs that reconciliation too, otherwise stale needs-human sidecars from a
    parent wrapper continue to appear as active blocked work after a child chain
    has taken over or completed.
    """

    session = str(marker.get("session") or "")
    workspace = str(marker.get("workspace") or "")
    if not session or not workspace:
        return None

    for other in _load_session_markers(marker_dir):
        other_session = str(other.get("session") or "")
        other_workspace = str(other.get("workspace") or "")
        if not other_session or other_session == session or other_workspace != workspace:
            continue
        other_remote_spec = str(other.get("remote_spec") or "")
        if not other_remote_spec:
            continue

        other_health = _load_json(marker_dir / f"{other_session}.chain-health.progress.json")
        if isinstance(other_health, Mapping) and bool(other_health.get("chain_complete")):
            return f"{other_session}:complete"

        other_liveness = _safe_liveness(liveness_probe, other)
        if other_liveness.get("tmux") or other_liveness.get("process"):
            return f"{other_session}:alive"

    return None


# --- classification helpers ------------------------------------------------



def _needs_human_superseded_by_live_activity(
    *,
    needs_human: Mapping[str, Any] | None,
    liveness: Mapping[str, bool],
    latest_activity_dt: datetime | None,
) -> bool:
    if not _is_needs_human(needs_human):
        return False
    if not (liveness.get("tmux") or liveness.get("process")):
        return False
    if latest_activity_dt is None:
        return False
    recorded_at = _parse_iso(str(needs_human.get("recorded_at") or ""))
    return recorded_at is not None and latest_activity_dt > recorded_at


def _needs_human_superseded_by_authoritative_recovery(
    *,
    needs_human: Mapping[str, Any] | None,
    plan_state: Mapping[str, Any] | None,
) -> bool:
    """Prevent a compatibility marker from overriding a newer typed cursor."""

    if not _is_needs_human(needs_human) or not isinstance(plan_state, Mapping):
        return False
    marker_at = _parse_iso(str(needs_human.get("recorded_at") or ""))
    failure = plan_state.get("latest_failure")
    failure = failure if isinstance(failure, Mapping) else {}
    failure_at = _parse_iso(str(failure.get("recorded_at") or ""))
    if marker_at is None or failure_at is None or failure_at <= marker_at:
        return False
    from arnold_pipelines.megaplan.run_state.decision_contract import (
        is_machine_repairable_failure_kind,
    )

    return is_machine_repairable_failure_kind(failure.get("kind"))

def _is_current_needs_human(
    *,
    session: str,
    needs_human: Mapping[str, Any] | None,
    marker_dir: Path,
    repair_data_dir: Path,
    current_plan: str,
    chain_complete: bool,
    latest_activity_dt: datetime | None,
) -> bool:
    if not _is_needs_human(needs_human):
        return False

    if chain_complete and not current_plan:
        return False

    recorded_at = _parse_iso(str(needs_human.get("recorded_at") or ""))
    if chain_complete and recorded_at is not None and latest_activity_dt is not None:
        if recorded_at <= latest_activity_dt:
            return False

    try:
        classification = classify_needs_human_blocker(
            session,
            current_plan=current_plan,
            marker_dir=marker_dir,
            repair_data_dir=repair_data_dir,
            needs_human_payload=needs_human,
        )
    except Exception:
        classification = None
    if classification is not None and classification.is_true_blocker:
        return True

    from arnold_pipelines.megaplan.run_state.decision_contract import typed_human_gate

    marker_plan = str(
        needs_human.get("current_plan_name")
        or needs_human.get("plan_name")
        or needs_human.get("plan_ref")
        or ""
    ).strip()
    return bool(
        typed_human_gate(needs_human) is not None
        and marker_plan
        and marker_plan == current_plan
    )

def _is_needs_human(needs_human: Mapping[str, Any] | None) -> bool:
    return bool(needs_human)


def _needs_human_reason(needs_human: Mapping[str, Any]) -> str:
    summary = needs_human.get("summary") if isinstance(needs_human, Mapping) else None
    if isinstance(summary, str) and summary:
        first = summary.splitlines()[0]
        return f"awaiting human action: {first[:160]}"
    return "awaiting human action"


def _is_repair_active(
    repair_progress: Mapping[str, Any] | None,
    repair_data_dir: Path,
    session: str,
    now: datetime,
) -> bool:
    if not isinstance(repair_progress, Mapping) or not repair_progress:
        return False
    repair_data = _load_json(repair_data_dir / f"{session}.repair-data.json")
    if isinstance(repair_data, Mapping):
        outcome = str(repair_data.get("outcome") or "").strip()
        if is_success_outcome(outcome):
            return False
        if str(repair_data.get("completed_at") or "").strip():
            return False
    recorded_at = _parse_iso(repair_progress.get("updated_at") or repair_progress.get("ts"))
    if recorded_at is None:
        # A repair-progress marker without a timestamp still means a repair ran;
        # treat it as active only if recent repair-data exists alongside.
        return bool(repair_data)
    age = (now - recorded_at).total_seconds()
    return age <= REPAIR_FRESH_S


def _watchdog_status(watchdog_item: Mapping[str, Any], chain_complete: bool) -> str:
    if chain_complete:
        return "complete"
    status = str(watchdog_item.get("status") or "").strip().lower()
    return status or "unknown"


def _active_step_pid_liveness(plan_state: Mapping[str, Any] | None) -> bool:
    """Check whether the active-step worker PID recorded in plan state is live."""
    if not isinstance(plan_state, Mapping):
        return False
    active_step = plan_state.get("active_step")
    if not isinstance(active_step, Mapping):
        return False
    pid = _as_int(active_step.get("worker_pid"))
    if pid is not None and _pid_is_live(pid):
        return True
    return False


def _classify_session_custody(
    *,
    session_id: str,
    supervisor_identity: str,
    tmux_live: bool,
    process_live: bool,
    active_step_worker_pid_liveness: bool,
    watchdog_status: str,
    chain_complete: bool,
    relaunch_command: str,
    needs_human: bool,
    repair_active: bool,
    now: datetime,
) -> CloudCustodyClassification:
    """Classify cloud custody for a single session from local observation evidence.

    Wraps :func:`classify_cloud_custody` with defaults appropriate for the
    status-snapshot producer and an evidence timestamp.
    """
    return classify_cloud_custody(
        session_id=session_id,
        supervisor_identity=supervisor_identity,
        tmux_live=tmux_live,
        process_live=process_live,
        active_step_worker_pid_liveness=active_step_worker_pid_liveness,
        watchdog_status=watchdog_status,
        chain_complete=chain_complete,
        relaunch_command=relaunch_command,
        relaunch_command_available=bool(relaunch_command),
        needs_human=needs_human,
        repair_active=repair_active,
        failure_reasons=None,
        previous_classification=None,
        finding_unchanged_count=0,
    )


def _load_current_plan_state(workspace: Path | None, current_plan: str) -> dict[str, Any] | None:
    if workspace is None or not current_plan:
        return None
    path = workspace / ".megaplan" / "plans" / current_plan / "state.json"
    loaded = _load_json(path)
    return dict(loaded) if isinstance(loaded, Mapping) and loaded else None


def _load_current_plan_review(workspace: Path | None, current_plan: str) -> dict[str, Any] | None:
    if workspace is None or not current_plan:
        return None
    path = workspace / ".megaplan" / "plans" / current_plan / "review.json"
    loaded = _load_json(path)
    return dict(loaded) if isinstance(loaded, Mapping) and loaded else None


_TERMINAL_SUCCESS_STATES = frozenset({"done", "complete", "completed", "finished", "success", "succeeded"})


def _terminal_completion_at(
    workspace: Path | None,
    current_plan: str,
    *,
    chain_complete: bool,
) -> str | None:
    """Return the durable terminal-success receipt time for a completed chain.

    A chain-health sidecar is refreshed by every watchdog sweep, so its
    ``updated_at`` is activity-observation time, not completion time.  The
    plan event journal records the terminal ``plan_finished`` transition with
    its own UTC timestamp and is the only source accepted here.
    """

    if not chain_complete or workspace is None or not current_plan:
        return None
    try:
        from arnold_pipelines.megaplan.observability.event_checkpoint import (
            read_bounded_event_projection,
        )

        projection = read_bounded_event_projection(
            workspace / ".megaplan" / "plans" / current_plan
        )
    except (OSError, RuntimeError):
        return None
    candidates = [
        projection.latest_by_kind.get(f"plan_finished:state={state}")
        for state in _TERMINAL_SUCCESS_STATES
    ]
    event = max(
        (item for item in candidates if isinstance(item, Mapping)),
        key=lambda item: int(item.get("seq") or -1),
        default={},
    )
    payload = event.get("payload") if isinstance(event, Mapping) else None
    state = (
        str(payload.get("state") or "").casefold()
        if isinstance(payload, Mapping)
        else ""
    )
    if state not in _TERMINAL_SUCCESS_STATES:
        return None
    observed_at = _parse_iso(event.get("ts_utc"))
    return _isoformat(observed_at) if observed_at is not None else None


def _has_current_repairable_failure(plan_state: Mapping[str, Any] | None) -> bool:
    if not isinstance(plan_state, Mapping) or not plan_state:
        return False
    latest_failure = plan_state.get("latest_failure")
    if not isinstance(latest_failure, Mapping) or not latest_failure:
        return False
    kind = str(latest_failure.get("kind") or "").strip().lower()
    phase = str(latest_failure.get("phase") or "").strip().lower()
    current_state = str(plan_state.get("current_state") or "").strip().lower()
    if kind == "phase_failed" and phase in {"", "execute"}:
        return True
    if kind in {"execution_blocked", "blocked_recovery_not_resolved"}:
        return True
    if current_state == "failed" and kind == "no_next_step":
        return True
    return current_state in {"blocked", "manual_review", "finalized", "failed"} and kind in {
        "deterministic_phase_failure",
        "phase_failed",
        "step_failed",
        "handler_failed",
        "no_next_step",
    }


# --- S4: enriched status field derivation -----------------------------------


def _derive_activity_phase(
    plan_state_doc: Mapping[str, Any] | None,
    plan_current_state: str,
    status: str,
) -> str:
    """Derive the current activity phase from plan state or status signals.

    Prefers ``current_phase`` from the plan state document, then falls back to
    the ``phase`` field inside ``active_step``, then derives from the legacy
    ``status`` classification.
    """
    if isinstance(plan_state_doc, Mapping):
        phase = str(plan_state_doc.get("current_phase") or plan_state_doc.get("phase") or "")
        if phase:
            return phase.strip().lower()
        active_step = plan_state_doc.get("active_step")
        if isinstance(active_step, Mapping):
            phase = str(active_step.get("phase") or "")
            if phase:
                return phase.strip().lower()

    # Derive from legacy status
    if status == "repairing":
        return "repair"
    if status == "complete":
        return "done"
    if status == "blocked":
        return "blocked"
    if status == "attention":
        return "attention"
    if status == "running":
        return "execute"
    return status


def _derive_semantic_health(
    *,
    session: str,
    workspace: Path | None,
    current_plan: str | None,
    plan_state_doc: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """Derive a semantic-health projection for the session.

    When the plan directory is resolvable, calls
    :func:`inspect_semantic_health` and projects the findings through
    :func:`cloud_counts_summary`.  Returns ``None`` when the plan directory
    cannot be resolved or the inspection fails, so the snapshot remains
    robust against incomplete state.
    """
    if workspace is None or not current_plan:
        return None
    plan_dir = workspace / ".megaplan" / "plans" / str(current_plan)
    if not plan_dir.is_dir():
        return None
    try:
        from arnold_pipelines.megaplan.cloud.semantic_findings import (
            cloud_counts_summary,
        )
        from arnold_pipelines.megaplan.semantic_health import (
            inspect_semantic_health,
        )

        findings = inspect_semantic_health(plan_dir)
        return cloud_counts_summary(findings, session_id=session)
    except Exception:
        return None


def _derive_repair_state(
    status: str,
    repair_progress: Mapping[str, Any] | None,
) -> str:
    """Derive the current repair state for a session.

    Returns one of ``"active"``, ``"stale"``, or ``"none"`` based on the
    legacy status and the presence of repair-progress evidence.
    """
    if status == "repairing":
        return "active"
    if isinstance(repair_progress, Mapping) and repair_progress:
        return "stale"
    return "none"


def _derive_repairable_issue(
    plan_state_doc: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """Derive a repairable-issue detail from plan state when one exists.

    Returns a dict with ``kind``, ``phase``, and ``message`` from the
    ``latest_failure`` block when the plan state indicates a current
    repairable failure.  Returns ``None`` when there is no repairable
    issue.
    """
    if not _has_current_repairable_failure(plan_state_doc):
        return None
    if not isinstance(plan_state_doc, Mapping):
        return None
    latest_failure = plan_state_doc.get("latest_failure")
    if not isinstance(latest_failure, Mapping):
        return None
    issue: dict[str, Any] = {}
    kind = latest_failure.get("kind")
    if kind is not None:
        issue["kind"] = kind
    phase = latest_failure.get("phase")
    if phase is not None:
        issue["phase"] = phase
    message = latest_failure.get("message")
    if message is not None:
        issue["message"] = message
    return issue if issue else None


def _latest_activity(
    chain_health: Mapping[str, Any] | None,
    marker: Mapping[str, Any],
    plan_state: Mapping[str, Any] | None = None,
) -> str:
    candidates: list[datetime] = []
    raw_candidates: list[Any] = []
    if chain_health:
        raw_candidates.append(chain_health.get("updated_at"))
        raw_candidates.append(_iso_from_epoch(chain_health.get("events_mtime")))
    if plan_state:
        active_step = plan_state.get("active_step")
        if isinstance(active_step, Mapping):
            raw_candidates.append(active_step.get("last_activity_at"))
            raw_candidates.append(active_step.get("started_at"))
        raw_candidates.append(plan_state.get("updated_at"))
    raw_candidates.append(marker.get("updated_at"))
    raw_candidates.append(marker.get("started_at"))
    for value in raw_candidates:
        if isinstance(value, (int, float)) and value:
            parsed = _parse_iso(_iso_from_epoch(value))
            if parsed is not None:
                candidates.append(parsed)
        if isinstance(value, str) and value:
            parsed = _parse_iso(value)
            if parsed is not None:
                candidates.append(parsed)
    if candidates:
        return _isoformat(max(candidates))
    return ""


def _augment_liveness_with_plan_state(
    liveness: Mapping[str, Any],
    *,
    chain_health: Mapping[str, Any] | None,
    plan_state: Mapping[str, Any] | None,
) -> dict[str, Any]:
    augmented = dict(liveness)
    augmented["tmux"] = bool(liveness.get("tmux"))
    augmented["process"] = bool(liveness.get("process"))
    # Plan/chain activity and bare worker PIDs are cached breadcrumbs.  A PID is
    # meaningful only in its owning namespace; neither may upgrade liveness.
    return augmented


def _pid_is_live(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _is_plan_kind_marker(workspace: Path | None) -> bool:
    # Plan-kind sessions carry plan_name and need no remote_spec/chain-health.
    return workspace is not None and workspace.exists()


def _safe_liveness(
    probe: LivenessProbe,
    marker: Mapping[str, Any],
    *,
    marker_dir: Path = DEFAULT_MARKER_DIR,
) -> dict[str, Any]:
    try:
        result = probe(marker)
    except Exception:
        result = {}
    if not isinstance(result, dict):
        result = {}
    local = {
        "tmux": bool(result.get("tmux")),
        "process": bool(result.get("process")),
        "state": "live" if result.get("tmux") or result.get("process") else "unknown",
        "source": "local_probe",
    }
    if local["tmux"] or local["process"]:
        return local
    lease = observe_liveness_lease(marker, marker_dir=marker_dir)
    if lease.get("live"):
        return {
            "tmux": False,
            "process": True,
            "state": "remote_live",
            "source": "runner_lease",
            "lease": lease,
        }
    return {**local, "state": str(lease.get("state") or "unknown"), "lease": lease}


def default_liveness_probe(marker: Mapping[str, Any]) -> dict[str, bool]:
    """Best-effort tmux + process liveness from the current namespace.

    Swallows all errors so a fixture directory without tmux/ps still classifies
    sessions from file evidence alone. Returns ``{"tmux": bool, "process": bool}``.
    """
    session = str(marker.get("session") or "")
    workspace = str(marker.get("workspace") or "")
    remote_spec = str(marker.get("remote_spec") or "")
    plan_name = str(marker.get("plan_name") or "")
    relaunch_command = str(marker.get("relaunch_command") or "")

    tmux_alive = False
    if session:
        try:
            proc = subprocess.run(
                ["tmux", "has-session", "-t", session],
                check=False,
                capture_output=True,
                text=True,
                timeout=3,
            )
            tmux_alive = proc.returncode == 0
        except (FileNotFoundError, subprocess.SubprocessError, OSError):
            tmux_alive = False

    process_alive = False
    marker_pid = _as_int(marker.get("pid"))
    marker_pid_namespace = str(
        marker.get("pid_namespace_id") or marker.get("runner_pid_namespace_id") or ""
    )
    try:
        observer_pid_namespace = os.readlink("/proc/self/ns/pid")
    except OSError:
        observer_pid_namespace = ""
    # A bare PID has meaning only in the namespace that recorded it.  PID
    # collisions across containers are common and must not manufacture life.
    if (
        marker_pid is not None
        and marker_pid_namespace
        and marker_pid_namespace == observer_pid_namespace
        and _pid_is_live(marker_pid)
    ):
        process_alive = True
    needles = [value for value in (remote_spec, workspace, plan_name) if value]
    if needles:
        try:
            ps = subprocess.run(
                ["ps", "-eww", "-o", "args="],
                check=False,
                capture_output=True,
                text=True,
                timeout=3,
            )
        except (FileNotFoundError, subprocess.SubprocessError, OSError):
            ps = None
        if ps is not None and ps.returncode == 0:
            for line in ps.stdout.splitlines():
                if session and f"watchdog-{session}" in line:
                    process_alive = True
                    break
                if relaunch_command and relaunch_command in line:
                    process_alive = True
                    break
                if "arnold_pipelines.megaplan" in line and any(needle in line for needle in needles) and (
                    " chain start" in line
                    or " epic-chain start" in line
                    or " auto " in line
                    or " execute " in line
                    or " resume " in line
                ):
                    process_alive = True
                    break

    return {"tmux": tmux_alive, "process": process_alive}


def _summarize(sessions: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    counts = {"running": 0, "blocked": 0, "repairing": 0, "paused": 0, "complete": 0, "attention": 0}
    for entry in sessions:
        status = entry.get("status")
        if status in counts:
            counts[status] += 1
    return counts


# --- time helpers ----------------------------------------------------------


def _utcnow() -> datetime:
    # ``datetime.now(timezone.utc)`` with no arg is allowed here (this is the
    # library, not a workflow script). Callers may inject ``now`` for tests.
    return datetime.now(timezone.utc)


def _isoformat(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _iso_from_epoch(value: object) -> str:
    try:
        epoch = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return ""
    if epoch <= 0:
        return ""
    return _isoformat(datetime.fromtimestamp(epoch, timezone.utc))


def _parse_iso(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _age_s(dt: datetime, now: datetime) -> int:
    return max(0, int((now - dt).total_seconds()))


def _as_path(value: object) -> Path | None:
    if isinstance(value, str) and value.strip():
        return Path(value.strip())
    if isinstance(value, Path):
        return value
    return None


# ── M9: canonical projection helpers ──────────────────────────────────────


def _format_source_cursor(
    cursor_vector: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Format a source cursor vector for the snapshot, never granting authority.

    When no cursor vector is supplied the field is an explicit ``absent``
    sentinel so consumers never mistake a missing cursor for a verified read.
    """
    if isinstance(cursor_vector, Mapping) and cursor_vector:
        return {
            "authority": "evidence_extracted_display_only",
            "value": dict(cursor_vector),
        }
    return {
        "authority": "absent",
        "reason": "no_source_cursor_vector_provided",
    }


def _collect_session_evidence_gaps(
    entry: Mapping[str, Any],
) -> dict[str, Any]:
    """Collect structured evidence gaps for one session entry.

    Returns a dict whose keys name degraded dimensions and whose values are
    ``{gap, reason, evidence_status}`` triples.  Gaps are pure display
    annotations — they never feed dispatch, completion, cancellation,
    publication, or delivery.
    """
    gaps: dict[str, Any] = {}

    # --- tmux liveness gap ---
    tmux_value = entry.get("tmux")
    if tmux_value is None and not isinstance(entry.get("evidence"), Mapping):
        gaps["tmux_liveness"] = {
            "gap": "tmux_liveness_unavailable",
            "reason": "no tmux probe result; process namespace unavailable",
            "evidence_status": "missing",
        }

    # --- process liveness gap ---
    process_value = entry.get("process")
    if process_value is None and not isinstance(entry.get("evidence"), Mapping):
        gaps["process_liveness"] = {
            "gap": "process_liveness_unavailable",
            "reason": "no process probe result; process namespace unavailable",
            "evidence_status": "missing",
        }

    # --- watchdog status gap ---
    watchdog_status = entry.get("watchdog")
    if watchdog_status is None:
        gaps["watchdog_status"] = {
            "gap": "watchdog_status_unavailable",
            "reason": "no watchdog report for this session",
            "evidence_status": "missing",
        }
    elif watchdog_status == "stale":
        gaps["watchdog_status"] = {
            "gap": "watchdog_status_stale",
            "reason": "watchdog report describes an earlier sweep; not current runner truth",
            "evidence_status": "stale",
        }

    # --- chain-health gap ---
    chain_complete = entry.get("chain_complete")
    if chain_complete is None:
        gaps["chain_health"] = {
            "gap": "chain_health_unavailable",
            "reason": "no chain-health sidecar for this session",
            "evidence_status": "missing",
        }

    # --- plan state gap ---
    plan_state = entry.get("plan_state")
    if plan_state is None:
        evidence = entry.get("evidence")
        if isinstance(evidence, Mapping) and evidence.get("marker"):
            gaps["plan_state"] = {
                "gap": "plan_state_unavailable",
                "reason": "plan state file missing or unreadable",
                "evidence_status": "missing",
            }

    # --- custody mismatch ---
    if entry.get("custody_mismatch"):
        gaps["custody_mismatch"] = {
            "gap": "chain_custody_mismatch",
            "reason": (
                "terminal chain state with incomplete milestone count; "
                "plan state label suppressed"
            ),
            "evidence_status": "degraded",
        }

    # --- repair projection degraded ---
    repair_degraded = entry.get("repair_projection_degraded")
    if isinstance(repair_degraded, Mapping) and repair_degraded:
        gaps["repair_projection"] = {
            "gap": "repair_projection_degraded",
            "reason": str(repair_degraded.get("reason") or "canonical repair projection unavailable"),
            "evidence_status": "degraded",
        }

    # --- superseded sibling ---
    evidence = entry.get("evidence")
    if isinstance(evidence, Mapping) and evidence.get("superseded_by"):
        gaps["superseded_by"] = {
            "gap": "session_superseded",
            "reason": f"superseded by sibling: {evidence['superseded_by']}",
            "evidence_status": "superseded",
        }

    return gaps


# ═══════════════════════════════════════════════════════════════════════════
# Step 93 — Recovery SLO projection (display-only, never authoritative)
#
# The status snapshot is the single "what is running?" truth document.
# Recovery SLO state belongs here as a *projection* — it renders the
# acceptance proof (Steps 92-94) for human/dashboard consumption but never
# grants dispatch, completion, publication, or delivery authority.
# The authoritative gate lives in
# :func:`repair_revalidation.compute_recovery_slo_proof`.
# ═══════════════════════════════════════════════════════════════════════════


def recovery_slo_projection(
    route_closure: Mapping[str, Any] | None = None,
    latency_ledger: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Project the recovery SLO state into the cloud status snapshot.

    This is a **display-only** projection. It renders the route-authority
    closure summary (Step 92) and the nearest-rank p95 latency cohort
    (Steps 93-94) for human/dashboard consumption.

    Authority is never granted here — the status snapshot is local
    observation only. The authoritative acceptance gate is
    :func:`~arnold_pipelines.megaplan.cloud.repair_revalidation.compute_recovery_slo_proof`.
    """
    closure_ok = False
    if route_closure is not None:
        closure_ok = (
            bool(route_closure.get("closure_complete", False))
            and int(route_closure.get("unplanned_count", 0)) == 0
            and int(route_closure.get("planned_pending_count", 0)) == 0
        )

    p95: float | None = None
    sample_count = 0
    cohort_ok = False
    if latency_ledger is not None:
        sample_count = int(latency_ledger.get("sample_count", 0))
        p95_val = latency_ledger.get("p95_seconds")
        if isinstance(p95_val, (int, float)):
            p95 = float(p95_val)
        cohort_ok = sample_count >= 20

    slo_met = (
        closure_ok
        and cohort_ok
        and p95 is not None
        and p95 < 300.0
    )

    return {
        "projection_kind": "recovery_slo",
        "authoritative": False,
        "display_only": True,
        "milestone": "M11",
        "routes_closed": closure_ok,
        "cohort_size": sample_count,
        "p95_seconds": p95,
        "p95_method": (
            "nearest-rank ceil(0.95 * N) over sorted ascending latencies"
        ),
        "minimum_cohort_size": 20,
        "slo_threshold_seconds": 300.0,
        "slo_met": slo_met,
        "cohort_definition": (
            "Eligible durable blocked-occurrence or process-exit events "
            "whose occurrence identity has current Run Authority grant/fence, "
            "current Custody lease/epoch, same-occurrence verifier receipts, "
            "and a terminal accepted-repair or typed-escalation receipt."
        ),
        "note": (
            "This is a display-only projection in the status snapshot. "
            "The authoritative recovery SLO gate is "
            "repair_revalidation.compute_recovery_slo_proof."
        ),
    }
