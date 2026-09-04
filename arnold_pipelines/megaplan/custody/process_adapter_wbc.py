"""Process-safe append-only WBC evidence for adapter/process boundaries."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping
import hashlib
import json
import re
import uuid

from arnold_pipelines.megaplan.observability.events import EventWriter


PROCESS_ADAPTER_WBC_SCHEMA = "arnold.megaplan.process_adapter_wbc.v1"
_SANITIZE_RE = re.compile(r"[^a-z0-9._-]+")
_RESERVED_INDETERMINATE_HOOKS = {
    "signal": "reserved_for_m10_hardening",
    "crash": "reserved_for_m10_hardening",
}


def _slug(value: str) -> str:
    text = _SANITIZE_RE.sub("-", str(value).strip().lower()).strip("-")
    return text or "unknown"


def process_adapter_wbc_dir(
    evidence_root: str | Path,
    *,
    producer_family: str,
    adapter_name: str,
) -> Path:
    return (
        Path(evidence_root).resolve()
        / ".process_adapter_wbc"
        / _slug(producer_family)
        / _slug(adapter_name)
    )


def observe_process_adapter_wbc(
    evidence_root: str | Path,
    *,
    producer_family: str,
    adapter_name: str,
) -> dict[str, Any]:
    """Read existing process-adapter WBC evidence without opening a writer.

    Preflight may prove that a prior custody reference exists, but it must not
    reserve an attempt or append a ``started`` event.  This deliberately uses
    ordinary reads and returns a typed unknown result for absent, malformed, or
    unreadable evidence.
    """

    evidence_dir = process_adapter_wbc_dir(
        evidence_root,
        producer_family=producer_family,
        adapter_name=adapter_name,
    )
    events_path = evidence_dir / "events.ndjson"
    base: dict[str, Any] = {
        "schema": PROCESS_ADAPTER_WBC_SCHEMA,
        "producer_family": producer_family,
        "adapter_name": adapter_name,
        "path": str(events_path),
    }
    try:
        if not events_path.is_file():
            return {**base, "status": "missing", "events": [], "reference": None}
        raw = events_path.read_bytes()
        lines = [line for line in raw.splitlines() if line.strip()]
        events = [json.loads(line.decode("utf-8")) for line in lines]
        if not events or any(
            not isinstance(event, Mapping)
            or event.get("kind") != "process_adapter_wbc"
            or not isinstance(event.get("payload"), Mapping)
            or event["payload"].get("schema") != PROCESS_ADAPTER_WBC_SCHEMA
            for event in events
        ):
            return {**base, "status": "unknown", "events": [], "reference": None, "reason": "malformed"}
        return {
            **base,
            "status": "available",
            "events": events,
            "reference": "sha256:" + hashlib.sha256(raw).hexdigest(),
        }
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return {
            **base,
            "status": "unknown",
            "events": [],
            "reference": None,
            "reason": type(exc).__name__,
        }


@dataclass
class ProcessAdapterWbcAttempt:
    evidence_root: str | Path
    producer_family: str
    adapter_name: str
    surface: str
    attempt_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    _evidence_dir: Path = field(init=False, repr=False)
    _writer: EventWriter = field(init=False, repr=False)
    _started: bool = field(default=False, init=False, repr=False)
    _terminal: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        evidence_dir = process_adapter_wbc_dir(
            self.evidence_root,
            producer_family=self.producer_family,
            adapter_name=self.adapter_name,
        )
        object.__setattr__(self, "_evidence_dir", evidence_dir)
        object.__setattr__(self, "_writer", EventWriter(evidence_dir))

    @property
    def events_path(self) -> Path:
        return self._evidence_dir / "events.ndjson"

    def start(self, *, details: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if self._started:
            raise ValueError(f"WBC attempt {self.attempt_id!r} already started")
        self._started = True
        return self._emit("started", status="started", details=details)

    def effect(
        self,
        effect: str,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._require_started()
        if self._terminal:
            raise ValueError(f"WBC attempt {self.attempt_id!r} is already terminal")
        payload = dict(details or {})
        payload["effect"] = str(effect)
        return self._emit("effect", status=str(effect), details=payload)

    def terminal(
        self,
        *,
        status: str,
        outcome: str,
        details: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._require_started()
        if self._terminal:
            raise ValueError(f"WBC attempt {self.attempt_id!r} already has terminal evidence")
        self._terminal = True
        return self._emit(
            "terminal",
            status=str(status),
            outcome=str(outcome),
            details=details,
        )

    def _require_started(self) -> None:
        if not self._started:
            raise ValueError(f"WBC attempt {self.attempt_id!r} has not started")

    def _emit(
        self,
        boundary_event: str,
        *,
        status: str,
        outcome: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema": PROCESS_ADAPTER_WBC_SCHEMA,
            "attempt_id": self.attempt_id,
            "producer_family": self.producer_family,
            "adapter_name": self.adapter_name,
            "surface": self.surface,
            "boundary_event": boundary_event,
            "status": status,
            "indeterminate_hooks": dict(_RESERVED_INDETERMINATE_HOOKS),
            "details": dict(details or {}),
        }
        if outcome is not None:
            payload["outcome"] = outcome
        return self._writer.emit("process_adapter_wbc", phase=self.surface, payload=payload)


def begin_process_adapter_attempt(
    evidence_root: str | Path,
    *,
    producer_family: str,
    adapter_name: str,
    surface: str,
    start_details: Mapping[str, Any] | None = None,
    attempt_id: str | None = None,
) -> ProcessAdapterWbcAttempt:
    attempt = ProcessAdapterWbcAttempt(
        evidence_root=evidence_root,
        producer_family=producer_family,
        adapter_name=adapter_name,
        surface=surface,
        attempt_id=attempt_id or str(uuid.uuid4()),
    )
    attempt.start(details=start_details)
    return attempt


__all__ = [
    "PROCESS_ADAPTER_WBC_SCHEMA",
    "ProcessAdapterWbcAttempt",
    "begin_process_adapter_attempt",
    "observe_process_adapter_wbc",
    "process_adapter_wbc_dir",
]
