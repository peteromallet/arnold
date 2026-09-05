"""Complete, observation-only launch preflight.

The launch engine uses this module as the boundary between facts that can be
observed and effects that are allowed only after admission.  A preflight does
not create an operation, reserve custody, touch a WBC, allocate a provider, or
write a marker/receipt.  Callers supply the observations collected by their
thin venue adapter; this module only validates, freezes, and fingerprints
those facts.

Every required section must be explicitly known.  In particular, an absent
``status`` is not treated as success and a transport/provider error is not
converted into an optimistic answer.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping


PREFLIGHT_SCHEMA = "arnold.runtime.launch_preflight.v1"
PREFLIGHT_VERSION = 1
PREFLIGHT_SECTIONS = (
    "source",
    "authority",
    "custody",
    "credentials",
    "runtime",
    "command",
    "namespace",
    "collision",
    "capacity",
    "network",
)


class PreflightResult(str, Enum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"


class PreflightReason(str, Enum):
    COMPLETE = "complete"
    MISSING_PREREQUISITE = "missing_prerequisite"
    UNKNOWN_PREREQUISITE = "unknown_prerequisite"
    INVALID_OBSERVATION = "invalid_observation"
    SOURCE_MISMATCH = "source_mismatch"
    AUTHORITY_NOT_CURRENT = "authority_not_current"
    CUSTODY_MISSING = "custody_missing"
    CREDENTIALS_UNAVAILABLE = "credentials_unavailable"
    RUNTIME_IDENTITY_UNKNOWN = "runtime_identity_unknown"
    COMMAND_INVALID = "command_invalid"
    NAMESPACE_INVALID = "namespace_invalid"
    COLLISION = "collision"
    CAPACITY_UNSAFE = "capacity_unsafe"
    NETWORK_UNSAFE = "network_unsafe"


_BAD_STATUSES = {
    "missing",
    "unknown",
    "unavailable",
    "error",
    "invalid",
    "stale",
    "conflict",
    "unsafe",
    "no-go",
    "rejected",
}
_GOOD_STATUSES = {
    "ok",
    "available",
    "valid",
    "current",
    "present",
    "ready",
    "clear",
    "observed",
    "stopped",
}
_SECTION_GOOD_STATUSES = {
    section: (_GOOD_STATUSES | {"none", "not_found"} if section == "collision" else _GOOD_STATUSES)
    for section in PREFLIGHT_SECTIONS
}
# A local physical door may not consume model/provider credentials at all.
# Keep that fact explicit in the report instead of treating a path or label as
# proof that credentials exist.  This is intentionally scoped to the
# credentials section; other prerequisite rows must remain positively proven.
_SECTION_GOOD_STATUSES["credentials"] = _GOOD_STATUSES | {
    "not_applicable",
    "n/a",
}
_REQUIRED_FIELD_ALIASES: dict[str, tuple[tuple[str, ...], ...]] = {
    "source": (("revision", "source_revision"), ("ref", "source_ref"), ("tree", "source_tree")),
    "authority": (("grant", "grant_ref", "grant_id"), ("fence", "fence_ref", "fence_id"), ("decision", "decision_ref", "decision_id")),
    "custody": (("custody_ref", "custody_id", "reference"), ("wbc_ref", "wbc_reference", "wbc_id")),
    "credentials": (("identity", "credential_ref", "credential_id"), ("transport", "transport_ref")),
    "runtime": (("interpreter", "runtime_python", "runtime_identity"), ("import_root", "runtime_root"), ("source_revision", "revision")),
    "command": (("argv", "command"), ("cwd", "working_directory"), ("env", "environment")),
    "namespace": (("name", "namespace", "process_namespace"),),
    "capacity": (("disk", "free_bytes", "capacity"), ("inode", "free_inodes"), ("output", "output_bound", "output_bound_bytes"), ("temp", "temp_volume", "temp_free_bytes")),
    "network": (("transport", "transport_ref", "network"),),
}


def _freeze(value: Any) -> Any:
    """Detach caller-owned JSON values without invoking any effect."""

    if isinstance(value, Mapping):
        return MappingProxyType({str(k): _freeze(v) for k, v in sorted(value.items(), key=lambda pair: str(pair[0]))})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"preflight observation is not JSON-safe: {type(value).__name__}")


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _thaw(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [_thaw(v) for v in value]
    return value


def _canonical(value: Any) -> str:
    return json.dumps(_thaw(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _status(value: Mapping[str, Any]) -> str | None:
    raw = value.get("status")
    return raw.lower() if isinstance(raw, str) else None


def _section_reason(section: str, status: str | None) -> PreflightReason:
    if section == "source":
        return PreflightReason.SOURCE_MISMATCH if status == "stale" else PreflightReason.UNKNOWN_PREREQUISITE
    if section == "authority":
        return PreflightReason.AUTHORITY_NOT_CURRENT
    if section == "custody":
        return PreflightReason.CUSTODY_MISSING
    if section == "credentials":
        return PreflightReason.CREDENTIALS_UNAVAILABLE
    if section == "runtime":
        return PreflightReason.RUNTIME_IDENTITY_UNKNOWN
    if section == "command":
        return PreflightReason.COMMAND_INVALID
    if section == "namespace":
        return PreflightReason.NAMESPACE_INVALID
    if section == "collision":
        return PreflightReason.COLLISION
    if section == "capacity":
        return PreflightReason.CAPACITY_UNSAFE
    if section == "network":
        return PreflightReason.NETWORK_UNSAFE
    return PreflightReason.UNKNOWN_PREREQUISITE


@dataclass(frozen=True)
class LaunchPreflightReport:
    """Frozen result of one complete observation pass."""

    result: PreflightResult
    reason: PreflightReason
    launch_spec: Mapping[str, Any]
    observations: Mapping[str, Mapping[str, Any]]
    failures: tuple[str, ...]
    _digest: str

    @property
    def accepted(self) -> bool:
        return self.result is PreflightResult.ACCEPTED

    @property
    def preflight_digest(self) -> str:
        return self._digest

    @property
    def digest(self) -> str:
        return self._digest

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": PREFLIGHT_SCHEMA,
            "version": PREFLIGHT_VERSION,
            "result": self.result.value,
            "reason": self.reason.value,
            "launch_spec": _thaw(self.launch_spec),
            "observations": _thaw(self.observations),
            "failures": list(self.failures),
            "preflight_digest": self._digest,
        }

    def canonical_json(self) -> str:
        payload = self.to_json()
        payload.pop("preflight_digest")
        return _canonical(payload)


def _merge_observations(
    observations: Mapping[str, Any] | None,
    sections: Mapping[str, Any],
) -> dict[str, Any]:
    merged = dict(observations or {})
    for name, value in sections.items():
        if value is not None:
            merged[name] = value
    return merged


def run_launch_preflight(
    launch_spec: Mapping[str, Any],
    observations: Mapping[str, Any] | None = None,
    **sections: Any,
) -> LaunchPreflightReport:
    """Validate a complete set of venue observations without side effects.

    ``observations`` can contain the ten named sections directly; keyword
    sections are a convenience for adapters.  No callback, subprocess, file
    write, lock, or provider API is used here.
    """

    failures: list[str] = []
    try:
        frozen_spec = _freeze(launch_spec)
    except (TypeError, ValueError) as exc:
        frozen_spec = MappingProxyType({})
        failures.append(f"launch_spec:{type(exc).__name__}")
    if not isinstance(launch_spec, Mapping) or not launch_spec:
        failures.append("launch_spec:missing_or_empty")

    merged = _merge_observations(observations, sections)
    frozen_observations: dict[str, Mapping[str, Any]] = {}
    for section in PREFLIGHT_SECTIONS:
        raw = merged.get(section)
        if raw is None:
            failures.append(f"{section}:missing")
            continue
        if not isinstance(raw, Mapping):
            failures.append(f"{section}:unknown")
            continue
        try:
            frozen = _freeze(raw)
        except (TypeError, ValueError) as exc:
            failures.append(f"{section}:invalid:{type(exc).__name__}")
            continue
        if not isinstance(frozen, Mapping):  # pragma: no cover - guarded above
            failures.append(f"{section}:unknown")
            continue
        frozen_observations[section] = frozen
        state = _status(raw)
        if state is None:
            failures.append(f"{section}:unknown_status")
        elif state in _BAD_STATUSES or state not in _SECTION_GOOD_STATUSES[section]:
            failures.append(f"{section}:{state}")
        else:
            for aliases in _REQUIRED_FIELD_ALIASES.get(section, ()):
                if not any(raw.get(key) is not None for key in aliases):
                    failures.append(f"{section}:missing_{aliases[0]}")

    # A collision section is positive only when it explicitly proves an empty
    # namespace; "available" must not silently mean "no duplicate process".
    collision = merged.get("collision")
    if isinstance(collision, Mapping) and _status(collision) not in {"clear", "none", "not_found"}:
        if not any(item.startswith("collision:") for item in failures):
            failures.append("collision:not_clear")

    # Custody and WBC are references, never a request to create them.  A
    # positive status without an existing reference is still incomplete.
    custody = merged.get("custody")
    if isinstance(custody, Mapping) and _status(custody) in _GOOD_STATUSES:
        if not any(
            isinstance(custody.get(key), str) and custody.get(key)
            for key in ("custody_ref", "custody_id", "reference")
        ):
            failures.append("custody:reference_missing")
        if not any(
            isinstance(custody.get(key), str) and custody.get(key)
            for key in ("wbc_ref", "wbc_reference", "wbc_id")
        ):
            failures.append("custody:wbc_reference_missing")

    if failures:
        reason = PreflightReason.MISSING_PREREQUISITE if any(
            item.endswith(":missing") or item.endswith(":missing_or_empty") for item in failures
        ) else PreflightReason.UNKNOWN_PREREQUISITE
        if reason is not PreflightReason.MISSING_PREREQUISITE:
            for section in PREFLIGHT_SECTIONS:
                if any(item.startswith(section + ":") for item in failures):
                    reason = _section_reason(section, _status(merged.get(section, {})) if isinstance(merged.get(section), Mapping) else None)
                    break
        result = PreflightResult.REJECTED
    else:
        reason = PreflightReason.COMPLETE
        result = PreflightResult.ACCEPTED

    frozen_failures = tuple(sorted(set(failures)))
    report_body = {
        "schema": PREFLIGHT_SCHEMA,
        "version": PREFLIGHT_VERSION,
        "result": result.value,
        "reason": reason.value,
        "launch_spec": frozen_spec,
        "observations": frozen_observations,
        "failures": frozen_failures,
    }
    digest = "sha256:" + hashlib.sha256(_canonical(report_body).encode("utf-8")).hexdigest()
    return LaunchPreflightReport(
        result=result,
        reason=reason,
        launch_spec=frozen_spec if isinstance(frozen_spec, Mapping) else MappingProxyType({}),
        observations=MappingProxyType(frozen_observations),
        failures=frozen_failures,
        _digest=digest,
    )


# Explicit aliases make the venue adapters readable while retaining one gate.
observation_only_preflight = run_launch_preflight
preflight_launch = run_launch_preflight


def read_only_capacity_observation(
    path: str | os.PathLike[str],
    *,
    output_bound_bytes: int = 0,
    temp_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Observe capacity and mount identity using stat calls only.

    This helper intentionally does not reserve bytes, create a temporary file,
    open SQLite, fsync, or clean up.  If the requested bound cannot be proven,
    it returns an explicit unknown observation for the caller to reject.
    """

    target = os.fspath(path)
    temp = os.fspath(temp_path) if temp_path is not None else target
    payload: dict[str, Any] = {
        "status": "unknown",
        "path": target,
        "output_bound_bytes": output_bound_bytes,
    }
    try:
        first = os.lstat(target)
        second = os.lstat(temp)
        if stat.S_ISLNK(first.st_mode) or not stat.S_ISDIR(first.st_mode):
            payload["reason"] = "path_not_real_directory"
            return payload
        target_vfs = os.statvfs(target)
        temp_vfs = os.statvfs(temp)
        free_bytes = target_vfs.f_bavail * target_vfs.f_frsize
        free_inodes = target_vfs.f_favail
        payload.update(
            {
                "status": "available",
                "free_bytes": free_bytes,
                "free_inodes": free_inodes,
                "temp_free_bytes": temp_vfs.f_bavail * temp_vfs.f_frsize,
                "temp_free_inodes": temp_vfs.f_favail,
                "mount": {"device": first.st_dev, "inode": first.st_ino},
                "temp_mount": {"device": second.st_dev, "inode": second.st_ino},
                "output_bound_proven": type(output_bound_bytes) is int
                and output_bound_bytes >= 0
                and free_bytes >= output_bound_bytes,
            }
        )
        if not payload["output_bound_proven"]:
            payload["status"] = "unsafe"
            payload["reason"] = "output_bound_not_available"
    except (OSError, ValueError, TypeError) as exc:
        payload["reason"] = f"capacity_observation_failed:{type(exc).__name__}"
    return payload


def read_only_network_observation(
    *,
    transport: str,
    host: str,
    port: int | None = None,
) -> dict[str, Any]:
    """Validate a configured network route without opening a connection."""

    safe_transport = transport in {"local", "ssh", "docker"}
    safe_host = isinstance(host, str) and bool(host.strip()) and not any(
        char in host for char in "\x00\r\n ;|&"
    )
    safe_port = port is None or (type(port) is int and 1 <= port <= 65535)
    if safe_transport and safe_host and safe_port:
        return {"status": "available", "transport": transport, "host": host, "port": port}
    return {
        "status": "unknown",
        "transport": transport,
        "host": host,
        "port": port,
        "reason": "network_route_not_safe",
    }


__all__ = [
    "PREFLIGHT_SCHEMA",
    "PREFLIGHT_SECTIONS",
    "PreflightReason",
    "PreflightResult",
    "LaunchPreflightReport",
    "observation_only_preflight",
    "preflight_launch",
    "read_only_capacity_observation",
    "read_only_network_observation",
    "run_launch_preflight",
]
