from typing import Any, cast

import cbor2
import pytest
from conftest import vectors
from fourth_crypto import (
    CoseError,
    cose_kid,
    cose_sign1,
    cose_verify1,
    public_key,
)
from pycose import headers as cose_headers
from pycose.algorithms import EdDSA
from pycose.keys.curves import Ed25519
from pycose.keys.okp import OKPKey
from pycose.messages.sign1message import Sign1Message

WG = cast(dict[str, Any], vectors("cose_sign1_eddsa"))
OURS = cast(dict[str, Any], vectors("cose_sign1_ours"))
SEED = bytes.fromhex(OURS["seed"])
PUBLIC = bytes.fromhex(OURS["public"])
KID = bytes.fromhex(OURS["kid"])
PAYLOAD = bytes.fromhex(OURS["payload"])
MESSAGE = bytes.fromhex(OURS["message"])


def _pycose_verifies(message: bytes, public: bytes) -> bool:
    # pycose 1.1 cannot decode cbor2 6 output (tuples, frozendicts); give it lists and dicts.
    protected, unprotected, payload, signature = cbor2.loads(message).value
    fields = [protected, dict(unprotected), payload, signature]
    decoded = Sign1Message.from_cose_obj(fields, True)  # pyright: ignore[reportUnknownMemberType]
    decoded.key = OKPKey(crv=Ed25519, x=public)  # pyright: ignore[reportAttributeAccessIssue]
    return bool(cast(Any, decoded).verify_signature())


def _named(items: list[dict[str, str]]) -> list[Any]:
    return [pytest.param(bytes.fromhex(i["message"]), id=i["name"]) for i in items]


@pytest.mark.parametrize("case", WG["cases"], ids=lambda c: c["name"])
def test_cose_wg_examples(case: dict[str, Any]) -> None:
    message = bytes.fromhex(case["message"])
    public = bytes.fromhex(case["public"])
    if case["valid"]:
        assert cose_verify1(public, message) == bytes.fromhex(case["payload"])
    else:
        with pytest.raises(CoseError):
            cose_verify1(public, message)


@pytest.mark.parametrize("case", [c for c in WG["cases"] if c["valid"]], ids=lambda c: c["name"])
def test_pycose_agrees_on_cose_wg_examples(case: dict[str, Any]) -> None:
    assert _pycose_verifies(bytes.fromhex(case["message"]), bytes.fromhex(case["public"]))


def test_sign_matches_committed_vector() -> None:
    assert cose_sign1(SEED, PAYLOAD, KID).hex() == OURS["message"]


def test_pycose_verifies_our_message() -> None:
    assert _pycose_verifies(MESSAGE, PUBLIC)


def test_bytes_equal_pycose_output() -> None:
    key = OKPKey(crv=Ed25519, d=SEED, x=PUBLIC)
    reference = Sign1Message(
        phdr={cose_headers.Algorithm: EdDSA, cose_headers.KID: KID},
        uhdr={},
        payload=PAYLOAD,
        key=key,
    )  # pyright: ignore[reportCallIssue]
    assert cast(Any, reference).encode() == MESSAGE


def test_round_trip_returns_payload() -> None:
    assert cose_verify1(PUBLIC, MESSAGE) == PAYLOAD
    assert cose_verify1(PUBLIC, cose_sign1(SEED, b"", b"k")) == b""


def test_accepts_untagged_array() -> None:
    assert cose_verify1(PUBLIC, bytes.fromhex(OURS["untagged"])) == PAYLOAD


def test_cose_kid_reads_protected_header() -> None:
    assert cose_kid(MESSAGE) == KID


@pytest.mark.parametrize("message", _named(OURS["kid_missing"]))
def test_cose_kid_requires_protected_kid(message: bytes) -> None:
    with pytest.raises(CoseError):
        cose_kid(message)


@pytest.mark.parametrize("item", OURS["accepted"], ids=lambda i: i["name"])
def test_accepts_valid_variants(item: dict[str, str]) -> None:
    assert cose_verify1(PUBLIC, bytes.fromhex(item["message"])) == PAYLOAD


@pytest.mark.parametrize("message", _named(OURS["tampered"]))
def test_rejects_tampering(message: bytes) -> None:
    with pytest.raises(CoseError):
        cose_verify1(PUBLIC, message)


@pytest.mark.parametrize("message", _named(OURS["rejected"]))
def test_rejects_misuse(message: bytes) -> None:
    with pytest.raises(CoseError):
        cose_verify1(PUBLIC, message)


def test_rejects_wrong_public_key() -> None:
    with pytest.raises(CoseError):
        cose_verify1(bytes.fromhex(OURS["other_public"]), MESSAGE)
    with pytest.raises(CoseError):
        cose_verify1(PUBLIC[:31], MESSAGE)


@pytest.mark.parametrize("length", range(len(MESSAGE)))
def test_every_truncation_raises_cose_error(length: int) -> None:
    with pytest.raises(CoseError):
        cose_verify1(PUBLIC, MESSAGE[:length])


@pytest.mark.parametrize(
    "garbage",
    [b"", b"\xff", b"\x84", b"\xa0", b"\xd2", b"\x00", b"\x84\x00\x00\x00\x00", b"\x9f\xff"],
)
def test_garbage_raises_cose_error(garbage: bytes) -> None:
    with pytest.raises(CoseError):
        cose_verify1(PUBLIC, garbage)
    with pytest.raises(CoseError):
        cose_kid(garbage)


@pytest.mark.parametrize("bit", range(len(MESSAGE) * 8))
def test_every_bit_flip_is_rejected(bit: int) -> None:
    flipped = bytearray(MESSAGE)
    flipped[bit // 8] ^= 1 << (bit % 8)
    with pytest.raises(CoseError):
        cose_verify1(PUBLIC, bytes(flipped))


def test_public_key_helper_matches_vector() -> None:
    assert public_key(SEED) == PUBLIC


@pytest.mark.parametrize("wrap", [bytes, bytearray, memoryview])
def test_accepts_bytes_like_messages(wrap: Any) -> None:
    assert cose_verify1(PUBLIC, wrap(MESSAGE)) == PAYLOAD
    assert cose_kid(wrap(MESSAGE)) == KID


@pytest.mark.parametrize("message", ["text", 5, None, [1, 2], {"a": 1}])
def test_other_message_types_raise_cose_error(message: Any) -> None:
    with pytest.raises(CoseError):
        cose_verify1(PUBLIC, message)
    with pytest.raises(CoseError):
        cose_kid(message)


def test_deep_nesting_raises_cose_error() -> None:
    nested = b"\x81" * 200
    with pytest.raises(CoseError):
        cose_verify1(PUBLIC, nested)
    with pytest.raises(CoseError):
        cose_kid(nested)
