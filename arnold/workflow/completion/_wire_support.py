"""Private wire codec helpers; public wire classes/functions remain in wire.py."""

from __future__ import annotations

import json
import re
from typing import Any, Mapping

from arnold.workflow.completion.hashing import canonical_json

_VERSION_RE = re.compile(r"\.v(\d+)(?:$|[-.])")


def _kind(value: Any):
    from . import wire as w
    try:
        return w._KIND_ALIASES[str(value)]
    except KeyError as exc:
        raise w.UnsupportedRecordKindError(f"unsupported record_kind: {value!r}") from exc


def _json_object(value: Any) -> dict[str, Any]:
    from . import wire as w
    if isinstance(value, Mapping):
        result = dict(value)
    else:
        try:
            raw = value
            if isinstance(value, memoryview):
                raw = value.tobytes()
            if isinstance(raw, (bytes, bytearray)):
                raw = bytes(raw).decode("utf-8")
            result = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
            raise w.CorruptWireError("wire payload is not valid UTF-8 JSON") from exc
    if not isinstance(result, dict):
        raise w.CorruptWireError("wire payload must be a JSON object")
    return result


def _future(version: str, supported: frozenset[str]) -> bool:
    if not isinstance(version, str):
        return False
    match = _VERSION_RE.search(version)
    if not match:
        return False
    version_number = int(match.group(1))
    supported_numbers = [int(item.group(1)) for item in (_VERSION_RE.search(item) for item in supported) if item]
    return bool(supported_numbers) and version_number > max(supported_numbers)


def _envelope(kind: Any, record: Mapping[str, Any], schema_version: str) -> bytes:
    return canonical_json({"record_kind": kind.value, "schema_version": schema_version, "payload": dict(record)})


def _split_wire(value: Any, expected_kind: Any):
    from . import wire as w
    data = _json_object(value)
    has_envelope_fields = "record_kind" in data or "payload" in data
    if "record_kind" in data:
        kind = _kind(data["record_kind"])
        if expected_kind is not None and kind is not expected_kind:
            raise w.CorruptWireError(f"expected {expected_kind.value} record, got {kind.value}")
        payload = data.get("payload")
        if not isinstance(payload, Mapping):
            raise w.CorruptWireError("wire envelope payload must be an object")
        version = data.get("schema_version", payload.get("schema_version"))
        if not isinstance(version, str) or not version:
            raise w.CorruptWireError("wire envelope requires schema_version")
        return kind, version, payload, True
    if expected_kind is None:
        raise w.CorruptWireError("wire envelope requires record_kind")
    version = data.get("schema_version")
    if version is None and expected_kind is w.WireRecordKind.BINDING:
        version = w.LEGACY_BINDING_SCHEMA_VERSION
    if version is None:
        version = {w.WireRecordKind.SPEC: w.SPEC_SCHEMA_VERSION, w.WireRecordKind.VERDICT: w.VERDICT_SCHEMA_VERSION, w.WireRecordKind.SHADOW_ACCEPTANCE_REFERENCE: w.ACCEPTANCE_REFERENCE_SCHEMA_VERSION}[expected_kind]
    if not isinstance(version, str) or not version:
        raise w.CorruptWireError("record requires schema_version")
    return expected_kind, version, data, has_envelope_fields


def _strict_result(result: Any) -> Any:
    from . import wire as w
    if result.disposition in {w.DecodeDisposition.DECODED, w.DecodeDisposition.LEGACY_UNKNOWN}:
        return result.record
    if result.disposition is w.DecodeDisposition.UNKNOWN_FUTURE:
        raise w.UnknownFutureVersionError(result.error)
    if result.disposition is w.DecodeDisposition.CHANGED_BINDING:
        raise w.ChangedBindingError(result.error)
    raise w.CorruptWireError(result.error)


def _decode_binding(payload: Mapping[str, Any], version: str, kind_text: str):
    from . import wire as w
    try:
        return w.CompletionBinding.from_dict(payload)
    except (w.AmbiguousBindingError, w.BindingVersionError, ValueError, TypeError) as exc:
        legacy = version == w.LEGACY_BINDING_SCHEMA_VERSION
        legacy = legacy or (version == w.CANONICAL_BINDING_SCHEMA_VERSION and "evidence_window" in payload and "evidence_scope" not in payload)
        if legacy:
            return w.WireDecodeResult(kind_text, version, w.DecodeDisposition.LEGACY_UNKNOWN, error=str(exc))
        raise


def _decode_record(kind: Any, version: str, payload: Mapping[str, Any], kind_text: str):
    from . import wire as w
    if kind is w.WireRecordKind.SPEC:
        return w.CompletionSpec.from_dict(payload)
    if kind is w.WireRecordKind.BINDING:
        return _decode_binding(payload, version, kind_text)
    if kind is w.WireRecordKind.VERDICT:
        return w.CompletionVerdict.from_dict(payload)
    return w.ShadowAcceptanceReference.from_dict(payload)


def decode_record_impl(value: Any, *, expected_kind: Any = None, expected_binding_hash: str | None = None):
    from . import wire as w
    requested_kind = _kind(expected_kind) if expected_kind is not None else None
    kind_text = requested_kind.value if requested_kind else ""
    version = None
    try:
        kind, version, payload, _ = _split_wire(value, requested_kind)
        kind_text = kind.value
        supported = w._SUPPORTED[kind]
        if version not in supported:
            if _future(version, supported):
                return w.WireDecodeResult(kind_text, version, w.DecodeDisposition.UNKNOWN_FUTURE, error=f"unsupported future {kind.value} schema version: {version}")
            return w.WireDecodeResult(kind_text, version, w.DecodeDisposition.CORRUPT, error=f"unsupported {kind.value} schema version: {version}")
        record = _decode_record(kind, version, payload, kind_text)
        if isinstance(record, w.WireDecodeResult):
            return record
        if expected_binding_hash is not None and kind in {w.WireRecordKind.BINDING, w.WireRecordKind.VERDICT, w.WireRecordKind.SHADOW_ACCEPTANCE_REFERENCE}:
            actual = getattr(record, "binding_hash", "")
            if actual != expected_binding_hash:
                return w.WireDecodeResult(kind_text, version, w.DecodeDisposition.CHANGED_BINDING, error=f"{kind.value} binding changed: expected {expected_binding_hash!r}, got {actual!r}")
        disposition = w.DecodeDisposition.LEGACY_UNKNOWN if kind is w.WireRecordKind.BINDING and getattr(record, "is_legacy", False) else w.DecodeDisposition.DECODED
        return w.WireDecodeResult(kind_text, version, disposition, record=record)
    except w.UnknownFutureVersionError:
        raise
    except (w.WireDecodeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return w.WireDecodeResult(kind_text, version, w.DecodeDisposition.CORRUPT, error=str(exc) or exc.__class__.__name__)
