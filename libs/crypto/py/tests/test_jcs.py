import json
import struct
from typing import Any, cast

import pytest
from conftest import vectors
from fourth_crypto import CanonicalizationError, canonicalize
from hypothesis import given, settings
from hypothesis import strategies as st

V = cast(dict[str, list[dict[str, Any]]], vectors("jcs"))


@pytest.mark.parametrize(
    "case", V["rfc_examples"] + V["structure"] + V["unicode"], ids=lambda c: c["name"]
)
def test_documented_examples(case: dict[str, Any]) -> None:
    assert canonicalize(case["input"]).hex() == case["expected_hex"]


def test_sorting_example_order() -> None:
    case = V["rfc_examples"][1]
    text = canonicalize(case["input"]).decode("utf-8")
    positions = [text.index(value) for value in case["expected_order"]]
    assert positions == sorted(positions)


@pytest.mark.parametrize("case", V["numbers"], ids=lambda c: c["bits"])
def test_appendix_b_numbers(case: dict[str, Any]) -> None:
    (value,) = struct.unpack(">d", bytes.fromhex(case["bits"]))
    assert canonicalize(value) == case["expected"].encode()


def test_keys_sorted_by_utf16_code_units() -> None:
    # U+1F600 is the pair D83D DE00: before U+FB33 in UTF-16, after it by code point.
    emoji, dalet = chr(0x1F600), chr(0xFB33)
    assert canonicalize({dalet: 1, emoji: 2}) == f'{{"{emoji}":2,"{dalet}":1}}'.encode()


def _rejected_value(case: dict[str, Any]) -> Any:
    match case["kind"]:
        case "float_bits":
            return struct.unpack(">d", bytes.fromhex(case["value"]))[0]
        case "integer":
            return int(case["value"])
        case "lone_surrogate":
            text = "a" + chr(int(case["value"], 16)) + "b"
            return {
                "string": text,
                "key": {text: 1},
                "nested": {"k": [1, [text]]},
            }[case["where"]]
        case _:
            raise AssertionError(case["kind"])


@pytest.mark.parametrize("case", V["rejected"], ids=lambda c: c["name"])
def test_rejected_values(case: dict[str, Any]) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize(_rejected_value(case))


@pytest.mark.parametrize("value", [{1: "a"}, {None: 1}, {b"k": 1}, {1.5: 1}, {True: 1}])
def test_non_string_keys_rejected(value: Any) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize(value)


@pytest.mark.parametrize("value", [b"x", {1, 2}, object(), complex(1, 1)])
def test_non_json_types_rejected(value: Any) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize(value)


def test_circular_reference_rejected() -> None:
    loop: list[Any] = []
    loop.append(loop)
    with pytest.raises(CanonicalizationError):
        canonicalize(loop)


def test_negative_zero_is_zero() -> None:
    assert canonicalize(-0.0) == b"0"


@pytest.mark.parametrize("value", [2**53 - 1, -(2**53 - 1), 0, 1, -1])
def test_integers_up_to_2_53_minus_1_round_trip(value: int) -> None:
    assert canonicalize(value) == str(value).encode()


json_values = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(-(2**53 - 1), 2**53 - 1)
    | st.floats(min_value=-(2.0**53 - 1), max_value=2.0**53 - 1)
    | st.text(),
    lambda children: st.lists(children) | st.dictionaries(st.text(), children),
    max_leaves=12,
)


# No example database: stored failures would put non-ASCII text outside the vectors directory.
@settings(database=None)
@given(json_values)
def test_output_is_idempotent(value: Any) -> None:
    once = canonicalize(value)
    assert canonicalize(json.loads(once)) == once


def test_deep_nesting_raises_canonicalization_error() -> None:
    value: Any = 1
    for _ in range(100_000):
        value = [value]
    with pytest.raises(CanonicalizationError):
        canonicalize(value)
