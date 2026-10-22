from typing import Any, cast

import pytest
from conftest import vectors
from fourth_crypto import (
    generate_keypair,
    public_key,
    sign,
    sign_json,
    verify,
    verify_json,
)

CASES = cast(dict[str, list[dict[str, Any]]], vectors("ed25519"))["cases"]
SEED = bytes.fromhex(CASES[0]["seed"])
PUBLIC = bytes.fromhex(CASES[0]["public"])


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_rfc8032_vectors(case: dict[str, Any]) -> None:
    seed = bytes.fromhex(case["seed"])
    message = bytes.fromhex(case["message"])
    signature = bytes.fromhex(case["signature"])
    public = bytes.fromhex(case["public"])
    assert public_key(seed) == public
    assert sign(seed, message) == signature
    assert verify(public, message, signature)


def _flip(data: bytes, bit: int) -> bytes:
    out = bytearray(data)
    out[bit // 8] ^= 1 << (bit % 8)
    return bytes(out)


def test_verify_rejects_tampering() -> None:
    case = CASES[2]
    public = bytes.fromhex(case["public"])
    message = bytes.fromhex(case["message"])
    signature = bytes.fromhex(case["signature"])
    assert not verify(public, _flip(message, 3), signature)
    assert not verify(public, message, _flip(signature, 7))
    assert not verify(public, message, _flip(signature, 8 * 40))
    assert not verify(bytes.fromhex(CASES[0]["public"]), message, signature)
    assert not verify(public, message, signature[:63])
    assert not verify(public, message, signature + b"\x00")
    assert not verify(public, message, b"")


def test_verify_rejects_malformed_public_keys() -> None:
    case = CASES[2]
    message = bytes.fromhex(case["message"])
    signature = bytes.fromhex(case["signature"])
    assert not verify(b"", message, signature)
    assert not verify(bytes(31), message, signature)
    assert not verify(bytes(33), message, signature)


def test_generate_keypair_round_trip() -> None:
    seed, public = generate_keypair()
    assert len(seed) == 32 and len(public) == 32
    assert public_key(seed) == public
    assert verify(public, b"hello", sign(seed, b"hello"))
    assert generate_keypair()[0] != seed


@pytest.mark.parametrize("size", [0, 31, 33])
def test_wrong_length_seed_rejected(size: int) -> None:
    with pytest.raises(ValueError):
        public_key(bytes(size))
    with pytest.raises(ValueError):
        sign(bytes(size), b"x")


def test_sign_json_is_key_order_independent() -> None:
    assert sign_json(SEED, {"a": 1, "b": 2}) == sign_json(SEED, {"b": 2, "a": 1})


def test_verify_json() -> None:
    value = {"match": "m1", "scores": [1, 2], "ok": True}
    signature = sign_json(SEED, value)
    assert verify_json(PUBLIC, {"ok": True, "scores": [1, 2], "match": "m1"}, signature)
    assert not verify_json(PUBLIC, {**value, "match": "m2"}, signature)
    assert not verify_json(bytes.fromhex(CASES[1]["public"]), value, signature)


@pytest.mark.parametrize(
    "bad",
    ["", "ed25519:", "ed25519:AAAA", "sha256:" + "0" * 64, "garbage", "ed25519:" + "A" * 86 + "="],
)
def test_verify_json_malformed_signature_is_false(bad: str) -> None:
    assert not verify_json(PUBLIC, {}, bad)


def test_signature_string_shape() -> None:
    signature = sign_json(SEED, {})
    assert signature.startswith("ed25519:")
    assert len(signature) == 94
