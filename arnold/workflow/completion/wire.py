"""Internal, non-authoritative persisted-wire codecs for completion records.

The completion package is still a shadow implementation.  This module makes
the experimental wire behavior explicit without making it a public API or an
acceptance authority.  Every encoded record carries a record kind and a
schema version; decoding dispatches on those wire values, never on the
Python class of a caller-provided value.

Unknown future versions are rejected before their payload is handed to a
record constructor.  A legacy C1 binding is retained as ``legacy/unknown``;
its two string coordinates are not converted into a C2 evidence scope.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import json
import re
from typing import Any, Mapping

from arnold.workflow.completion.binding import (
    CANONICAL_BINDING_SCHEMA_VERSION,
    LEGACY_BINDING_SCHEMA_VERSION,
    AmbiguousBindingError,
    BindingVersionError,
    CompletionBinding,
)
from arnold.workflow.completion.evaluation import (
    CompletionVerdict,
    VERDICT_SCHEMA_VERSION,
)
from arnold.workflow.completion.hashing import canonical_json, hash_canonical
from arnold.workflow.completion.spec import CompletionSpec
from ._wire_support import _envelope, _future, _json_object, _kind, _strict_result


WIRE_SCHEMA_VERSION = "arnold.workflow.completion_wire.v1"
SPEC_SCHEMA_VERSION = "arnold.workflow.completion_spec.v1"
ACCEPTANCE_REFERENCE_SCHEMA_VERSION = (
    "arnold.workflow.completion_acceptance_reference.v1"
)


class WireRecordKind(StrEnum):
    """Record families addressable by the internal wire contract."""

    SPEC = "spec"
    BINDING = "binding"
    VERDICT = "verdict"
    SHADOW_ACCEPTANCE_REFERENCE = "shadow_acceptance_reference"


RecordKind = WireRecordKind


class DecodeDisposition(StrEnum):
    """The fail-closed outcome of an authoritative decode attempt."""

    DECODED = "decoded"
    LEGACY_UNKNOWN = "legacy/unknown"
    CORRUPT = "corrupt"
    UNKNOWN_FUTURE = "unknown-future"
    CHANGED_BINDING = "changed-binding"
    QUARANTINED = "quarantined"


DecodeStatus = DecodeDisposition
WireDecodeStatus = DecodeDisposition


NON_AUTHORITATIVE_WARNING = (
    "completion records are experimental shadow data and are not authoritative"
)


class WireDecodeError(ValueError):
    """Base error raised by strict record decoders."""


class CorruptWireError(WireDecodeError):
    """The wire envelope or record body is malformed."""


class UnknownFutureVersionError(WireDecodeError):
    """The record declares a newer schema than this reader understands."""


class ChangedBindingError(WireDecodeError):
    """A decoded reference does not match the pinned binding."""


class UnsupportedRecordKindError(CorruptWireError):
    """The record kind is absent or not one of the neutral families."""


@dataclass(frozen=True)
class ShadowAcceptanceReference:
    """A content-addressed, non-authoritative pointer to shadow evaluation.

    The reference points at the exact binding and verdict and may optionally
    carry the identity of the legacy authoritative transaction it shadows.
    It contains no acceptance decision method, effect capability, or write
    operation.  ``reference_hash`` covers every field except itself.
    """

    binding_hash: str
    verdict_hash: str
    acceptance_transaction_hash: str = ""
    authoritative_decision_hash: str = ""
    effect_identity: str = ""
    schema_version: str = ACCEPTANCE_REFERENCE_SCHEMA_VERSION
    reference_hash: str = ""

    def __post_init__(self) -> None:
        for name in (
            "binding_hash",
            "verdict_hash",
            "acceptance_transaction_hash",
            "authoritative_decision_hash",
            "effect_identity",
        ):
            value = getattr(self, name)
            if not isinstance(value, str):
                raise TypeError(f"{name} must be a string")
        if not self.binding_hash or not self.verdict_hash:
            raise ValueError("binding_hash and verdict_hash must be non-empty")
        if self.schema_version != ACCEPTANCE_REFERENCE_SCHEMA_VERSION:
            raise ValueError(
                "unsupported shadow acceptance-reference schema version: "
                f"{self.schema_version!r}"
            )
        expected = hash_canonical(self._hash_payload())
        if self.reference_hash and self.reference_hash != expected:
            raise ValueError("ShadowAcceptanceReference reference_hash mismatch")
        object.__setattr__(self, "reference_hash", expected)

    def _hash_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "binding_hash": self.binding_hash,
            "verdict_hash": self.verdict_hash,
            "acceptance_transaction_hash": self.acceptance_transaction_hash,
            "authoritative_decision_hash": self.authoritative_decision_hash,
            "effect_identity": self.effect_identity,
        }

    @property
    def hash(self) -> str:
        return self.reference_hash

    @property
    def authoritative(self) -> bool:
        """Shadow references can never be authoritative."""

        return False

    @property
    def warning(self) -> str:
        return NON_AUTHORITATIVE_WARNING

    def to_dict(self) -> dict[str, Any]:
        return {**self._hash_payload(), "reference_hash": self.reference_hash}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ShadowAcceptanceReference":
        return cls(
            binding_hash=str(data["binding_hash"]),
            verdict_hash=str(data["verdict_hash"]),
            acceptance_transaction_hash=str(
                data.get("acceptance_transaction_hash", data.get("transaction_hash", ""))
            ),
            authoritative_decision_hash=str(
                data.get("authoritative_decision_hash", data.get("decision_hash", ""))
            ),
            effect_identity=str(data.get("effect_identity", "")),
            schema_version=str(
                data.get("schema_version", ACCEPTANCE_REFERENCE_SCHEMA_VERSION)
            ),
            reference_hash=str(data.get("reference_hash", "")),
        )


AcceptanceReference = ShadowAcceptanceReference
ShadowAcceptanceReferenceRecord = ShadowAcceptanceReference


@dataclass(frozen=True)
class WireDecodeResult:
    """Structured result used by matrix/audit callers.

    ``record`` is populated for a valid record and for a decodable legacy
    binding.  Corrupt, future, and changed-binding outcomes never expose a
    constructed record to callers.
    """

    record_kind: str
    schema_version: str | None
    disposition: DecodeDisposition
    record: Any = None
    error: str = ""
    warning: str = NON_AUTHORITATIVE_WARNING

    @property
    def status(self) -> DecodeDisposition:
        return self.disposition

    @property
    def value(self) -> Any:
        return self.record

    @property
    def ok(self) -> bool:
        return self.disposition in {
            DecodeDisposition.DECODED,
            DecodeDisposition.LEGACY_UNKNOWN,
        }

    @property
    def quarantined(self) -> bool:
        return self.disposition in {
            DecodeDisposition.UNKNOWN_FUTURE,
            DecodeDisposition.CHANGED_BINDING,
            DecodeDisposition.QUARANTINED,
        }


_KIND_ALIASES: dict[str, WireRecordKind] = {
    "spec": WireRecordKind.SPEC,
    "completion_spec": WireRecordKind.SPEC,
    "binding": WireRecordKind.BINDING,
    "completion_binding": WireRecordKind.BINDING,
    "verdict": WireRecordKind.VERDICT,
    "completion_verdict": WireRecordKind.VERDICT,
    "shadow_acceptance_reference": WireRecordKind.SHADOW_ACCEPTANCE_REFERENCE,
    "acceptance_reference": WireRecordKind.SHADOW_ACCEPTANCE_REFERENCE,
    "completion_acceptance_reference": WireRecordKind.SHADOW_ACCEPTANCE_REFERENCE,
}

_SUPPORTED: dict[WireRecordKind, frozenset[str]] = {
    WireRecordKind.SPEC: frozenset({SPEC_SCHEMA_VERSION}),
    WireRecordKind.BINDING: frozenset(
        {LEGACY_BINDING_SCHEMA_VERSION, CANONICAL_BINDING_SCHEMA_VERSION}
    ),
    WireRecordKind.VERDICT: frozenset({VERDICT_SCHEMA_VERSION}),
    WireRecordKind.SHADOW_ACCEPTANCE_REFERENCE: frozenset(
        {ACCEPTANCE_REFERENCE_SCHEMA_VERSION}
    ),
}

_VERSION_RE = re.compile(r"\.v(\d+)(?:$|[-.])")


def encode_spec(spec: CompletionSpec) -> bytes:
    """Encode a spec in canonical, byte-stable wire form."""

    if not isinstance(spec, CompletionSpec):
        raise TypeError("encode_spec requires a CompletionSpec")
    return _envelope(WireRecordKind.SPEC, spec.to_dict(), SPEC_SCHEMA_VERSION)


def encode_binding(binding: CompletionBinding) -> bytes:
    """Encode a canonical or explicitly legacy binding."""

    if not isinstance(binding, CompletionBinding):
        raise TypeError("encode_binding requires a CompletionBinding")
    return _envelope(
        WireRecordKind.BINDING,
        binding.to_dict(),
        binding.schema_version,
    )


def encode_verdict(verdict: CompletionVerdict) -> bytes:
    """Encode a completion verdict without granting it acceptance authority."""

    if not isinstance(verdict, CompletionVerdict):
        raise TypeError("encode_verdict requires a CompletionVerdict")
    return _envelope(WireRecordKind.VERDICT, verdict.to_dict(), VERDICT_SCHEMA_VERSION)


def encode_acceptance_reference(reference: ShadowAcceptanceReference) -> bytes:
    """Encode a non-authoritative shadow acceptance reference."""

    if not isinstance(reference, ShadowAcceptanceReference):
        raise TypeError("encode_acceptance_reference requires a ShadowAcceptanceReference")
    return _envelope(
        WireRecordKind.SHADOW_ACCEPTANCE_REFERENCE,
        reference.to_dict(),
        ACCEPTANCE_REFERENCE_SCHEMA_VERSION,
    )


encode_shadow_acceptance_reference = encode_acceptance_reference


def encode_record(record_kind: WireRecordKind | str, record: Any) -> bytes:
    """Encode *record* after an explicit wire-kind selection."""

    kind = _kind(record_kind)
    if kind is WireRecordKind.SPEC:
        return encode_spec(record)
    if kind is WireRecordKind.BINDING:
        return encode_binding(record)
    if kind is WireRecordKind.VERDICT:
        return encode_verdict(record)
    return encode_acceptance_reference(record)


encode = encode_record


def _split_wire(
    value: bytes | bytearray | memoryview | str | Mapping[str, Any],
    expected_kind: WireRecordKind | None,
) -> tuple[WireRecordKind, str, Mapping[str, Any], bool]:
    data = _json_object(value)
    has_envelope_fields = "record_kind" in data or "payload" in data
    if "record_kind" in data:
        kind = _kind(data["record_kind"])
        if expected_kind is not None and kind is not expected_kind:
            raise CorruptWireError(
                f"expected {expected_kind.value} record, got {kind.value}"
            )
        payload = data.get("payload")
        if not isinstance(payload, Mapping):
            raise CorruptWireError("wire envelope payload must be an object")
        version = data.get("schema_version", payload.get("schema_version"))
        if not isinstance(version, str) or not version:
            raise CorruptWireError("wire envelope requires schema_version")
        return kind, version, payload, True
    if expected_kind is None:
        raise CorruptWireError("wire envelope requires record_kind")
    version = data.get("schema_version")
    if version is None and expected_kind is WireRecordKind.BINDING:
        version = LEGACY_BINDING_SCHEMA_VERSION
    if version is None:
        version = {
            WireRecordKind.SPEC: SPEC_SCHEMA_VERSION,
            WireRecordKind.VERDICT: VERDICT_SCHEMA_VERSION,
            WireRecordKind.SHADOW_ACCEPTANCE_REFERENCE: ACCEPTANCE_REFERENCE_SCHEMA_VERSION,
        }[expected_kind]
    if not isinstance(version, str) or not version:
        raise CorruptWireError("record requires schema_version")
    return expected_kind, version, data, has_envelope_fields


def _strict_result(result: WireDecodeResult) -> Any:
    if result.disposition is DecodeDisposition.DECODED or result.disposition is DecodeDisposition.LEGACY_UNKNOWN:
        return result.record
    if result.disposition is DecodeDisposition.UNKNOWN_FUTURE:
        raise UnknownFutureVersionError(result.error)
    if result.disposition is DecodeDisposition.CHANGED_BINDING:
        raise ChangedBindingError(result.error)
    raise CorruptWireError(result.error)


def decode_record(
    value: bytes | bytearray | memoryview | str | Mapping[str, Any],
    *,
    expected_kind: WireRecordKind | str | None = None,
    expected_binding_hash: str | None = None,
) -> WireDecodeResult:
    """Decode one record and return an explicit matrix disposition."""
    from ._wire_support import decode_record_impl
    return decode_record_impl(value, expected_kind=expected_kind, expected_binding_hash=expected_binding_hash)


def decode_spec(value: bytes | bytearray | memoryview | str | Mapping[str, Any]) -> CompletionSpec:
    return _strict_result(decode_record(value, expected_kind=WireRecordKind.SPEC))


def decode_binding(
    value: bytes | bytearray | memoryview | str | Mapping[str, Any],
    *,
    expected_binding_hash: str | None = None,
) -> CompletionBinding:
    return _strict_result(
        decode_record(
            value,
            expected_kind=WireRecordKind.BINDING,
            expected_binding_hash=expected_binding_hash,
        )
    )


def decode_verdict(
    value: bytes | bytearray | memoryview | str | Mapping[str, Any],
    *,
    expected_binding_hash: str | None = None,
) -> CompletionVerdict:
    return _strict_result(
        decode_record(
            value,
            expected_kind=WireRecordKind.VERDICT,
            expected_binding_hash=expected_binding_hash,
        )
    )


def decode_acceptance_reference(
    value: bytes | bytearray | memoryview | str | Mapping[str, Any],
    *,
    expected_binding_hash: str | None = None,
) -> ShadowAcceptanceReference:
    return _strict_result(
        decode_record(
            value,
            expected_kind=WireRecordKind.SHADOW_ACCEPTANCE_REFERENCE,
            expected_binding_hash=expected_binding_hash,
        )
    )


decode_shadow_acceptance_reference = decode_acceptance_reference
decode_wire = decode_record
decode = decode_record

# Descriptive aliases make the family boundary obvious at call sites while
# keeping the short names convenient for internal use.
encode_completion_spec = encode_spec
encode_completion_binding = encode_binding
encode_completion_verdict = encode_verdict
encode_completion_acceptance_reference = encode_acceptance_reference
decode_completion_spec = decode_spec
decode_completion_binding = decode_binding
decode_completion_verdict = decode_verdict
decode_completion_acceptance_reference = decode_acceptance_reference


__all__ = [
    "WIRE_SCHEMA_VERSION",
    "SPEC_SCHEMA_VERSION",
    "ACCEPTANCE_REFERENCE_SCHEMA_VERSION",
    "WireRecordKind",
    "RecordKind",
    "DecodeDisposition",
    "DecodeStatus",
    "WireDecodeStatus",
    "WireDecodeError",
    "CorruptWireError",
    "UnknownFutureVersionError",
    "ChangedBindingError",
    "UnsupportedRecordKindError",
    "NON_AUTHORITATIVE_WARNING",
    "ShadowAcceptanceReference",
    "AcceptanceReference",
    "ShadowAcceptanceReferenceRecord",
    "WireDecodeResult",
    "encode_spec",
    "encode_binding",
    "encode_verdict",
    "encode_completion_spec",
    "encode_completion_binding",
    "encode_completion_verdict",
    "encode_completion_acceptance_reference",
    "encode_acceptance_reference",
    "encode_shadow_acceptance_reference",
    "encode_record",
    "encode",
    "decode_spec",
    "decode_binding",
    "decode_verdict",
    "decode_completion_spec",
    "decode_completion_binding",
    "decode_completion_verdict",
    "decode_completion_acceptance_reference",
    "decode_acceptance_reference",
    "decode_shadow_acceptance_reference",
    "decode_record",
    "decode_wire",
    "decode",
]
