"""Small immutable-value primitives shared by completion model helpers."""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from enum import StrEnum
from typing import Any

from arnold.workflow.completion.hashing import hash_canonical


class FrozenMapping(tuple):
    """Tagged tuple used so immutable maps can be thawed without ambiguity."""


def freeze(value: Any) -> Any:
    """Return a recursively immutable JSON-like value."""
    if isinstance(value, Mapping):
        return FrozenMapping((str(k), freeze(v)) for k, v in sorted(value.items(), key=lambda p: str(p[0])))
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return tuple(freeze(item) for item in value)
    if isinstance(value, (str, int, bool, float)) or value is None:
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("evidence values must contain finite numbers")
        return value
    if isinstance(value, StrEnum):
        return value.value
    raise TypeError(f"value must be JSON-like, got {type(value).__name__}")


def thaw(value: Any) -> Any:
    if isinstance(value, FrozenMapping):
        return {key: thaw(item) for key, item in value}
    if isinstance(value, tuple):
        return [thaw(item) for item in value]
    return value


def text(value: Any, field: str, *, allow_empty: bool = True) -> str:
    result = "" if value is None else str(value).strip()
    if not allow_empty and not result:
        raise ValueError(f"{field} must be a non-empty string")
    return result


def as_tuple(value: Any, field: str = "value") -> tuple[str, ...]:
    if value is None or value == "":
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Mapping):
        value = value.keys()
    if not isinstance(value, Iterable):
        return (str(value),)
    result = tuple(str(item) for item in value)
    if any(not item for item in result):
        raise ValueError(f"{field} cannot contain empty values")
    return result


def choose_alias(primary: Any, aliases: Sequence[Any], field: str) -> Any:
    values = [value for value in (primary, *aliases) if value is not None and value != "" and value != () and value != []]
    if not values:
        return None
    first = values[0]
    if any(repr(value) != repr(first) for value in values[1:]):
        raise ValueError(f"{field} received conflicting aliases")
    return first


def enum_value(value: Any, enum_type: type[StrEnum], field: str) -> StrEnum:
    try:
        return value if isinstance(value, enum_type) else enum_type(str(value))
    except ValueError as exc:
        raise ValueError(f"unsupported {field}: {value!r}") from exc


def hashed_record(schema_version: str, payload: Mapping[str, Any], supplied: str = "") -> str:
    expected = hash_canonical({"schema_version": schema_version, **dict(payload)})
    if supplied and supplied != expected:
        raise ValueError(f"{schema_version} hash mismatch")
    return expected
