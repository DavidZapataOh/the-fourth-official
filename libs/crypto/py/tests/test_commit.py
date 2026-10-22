from typing import Any, cast

import pytest
from conftest import vectors
from fourth_crypto import chain_hash, commitment

VEC = cast("dict[str, Any]", vectors("commitment"))


@pytest.mark.parametrize("case", VEC["commitments"], ids=lambda c: c["name"])
def test_known_answers(case: dict[str, Any]) -> None:
    parts = [bytes.fromhex(p) for p in case["parts"]]
    assert commitment(case["domain"], *parts).hex() == case["expected"]


@pytest.mark.parametrize("case", VEC["chains"], ids=lambda c: c["name"])
def test_chain_known_answers(case: dict[str, Any]) -> None:
    assert (
        chain_hash(bytes.fromhex(case["prev"]), bytes.fromhex(case["data"])).hex()
        == case["expected"]
    )


def test_concatenation_ambiguity_is_removed() -> None:
    assert commitment("d", b"ab", b"c") != commitment("d", b"a", b"bc")


def test_domains_separate() -> None:
    assert commitment("fourth/seed/v1", b"x") != commitment("fourth/call/v1", b"x")


def test_empty_parts_are_distinct() -> None:
    assert commitment("d", b"", b"a") != commitment("d", b"a", b"")
    assert commitment("d") != commitment("d", b"")


def test_domain_with_nul_is_rejected() -> None:
    with pytest.raises(ValueError, match="NUL"):
        commitment("a\x00b", b"x")


@pytest.mark.parametrize("prev", [b"", b"short", bytes(31), bytes(33)])
def test_chain_hash_requires_32_byte_prev(prev: bytes) -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        chain_hash(prev, b"x")


def test_chain_hash_depends_on_order() -> None:
    a, b = bytes(32), bytes([1]) * 32
    assert chain_hash(a, b) != chain_hash(b, a)
    assert chain_hash(chain_hash(a, b"1"), b"2") != chain_hash(chain_hash(a, b"2"), b"1")


@pytest.mark.parametrize("surrogate", [0xD800, 0xDFFF])
def test_domain_with_lone_surrogate_is_rejected(surrogate: int) -> None:
    with pytest.raises(ValueError, match="surrogate"):
        commitment("a" + chr(surrogate), b"x")


def test_oversized_part_is_rejected() -> None:
    class Huge(bytes):
        def __len__(self) -> int:
            return 2**32

    with pytest.raises(ValueError, match="2\\^32"):
        commitment("d", Huge())
