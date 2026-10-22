"""RFC 8785 canonical JSON."""

import math
import re
from collections.abc import Callable, Mapping, Sequence
from typing import cast

import jcs  # pyright: ignore[reportMissingTypeStubs]

type JsonValue = None | bool | int | float | str | Sequence[JsonValue] | Mapping[str, JsonValue]

MAX_SAFE_INTEGER = 2**53 - 1
_jcs_canonicalize = cast(Callable[[object], bytes], jcs.canonicalize)  # pyright: ignore[reportUnknownMemberType]
_SURROGATE = re.compile("[\ud800-\udfff]")


type Container = list[object] | tuple[object, ...] | dict[object, object]


class CanonicalizationError(ValueError):
    """Value has no RFC 8785 canonical form."""


def canonicalize(value: JsonValue) -> bytes:
    """Serialize a JSON value to its RFC 8785 canonical UTF-8 form."""
    try:
        _check(value, set())
        return _jcs_canonicalize(value)
    except RecursionError as error:
        raise CanonicalizationError("nesting too deep") from error


def _check(value: object, ancestors: set[int]) -> None:
    match value:
        case None | bool():
            pass
        case int():
            if abs(value) > MAX_SAFE_INTEGER:
                raise CanonicalizationError("integer outside the interoperable range")
        case float():
            if not math.isfinite(value):
                raise CanonicalizationError("NaN and Infinity are not JSON")
        case str():
            if _SURROGATE.search(value):
                raise CanonicalizationError("lone surrogate")
        case list() | tuple() | dict():
            _check_container(cast(Container, value), ancestors)
        case _:
            raise CanonicalizationError(f"unsupported type {type(value).__name__}")


def _check_container(
    value: list[object] | tuple[object, ...] | dict[object, object], ancestors: set[int]
) -> None:
    if id(value) in ancestors:
        raise CanonicalizationError("circular reference")
    ancestors.add(id(value))
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("object keys must be strings")
            _check(key, ancestors)
            _check(item, ancestors)
    else:
        for item in value:
            _check(item, ancestors)
    ancestors.discard(id(value))
