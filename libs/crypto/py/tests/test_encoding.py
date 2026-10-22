from typing import Any, cast

import pytest
from conftest import vectors
from fourth_crypto import (
    EncodingError,
    b64url_decode,
    b64url_encode,
    format_digest,
    format_signature,
    parse_digest,
    parse_signature,
    sha256,
)
from hypothesis import given
from hypothesis import strategies as st

B64 = cast(dict[str, Any], vectors("base64url"))


def test_sha256_known_answer():
    assert (
        sha256(b"abc").hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


@pytest.mark.parametrize("case", B64["valid"], ids=lambda c: f"{len(c['hex']) // 2}-bytes")
def test_b64url_vectors(case: dict[str, str]):
    raw = bytes.fromhex(case["hex"])
    assert b64url_encode(raw) == case["b64url"]
    assert b64url_decode(case["b64url"]) == raw


@given(st.binary(max_size=64))
def test_b64url_round_trip_all_lengths(data: bytes):
    text = b64url_encode(data)
    assert "=" not in text
    assert b64url_decode(text) == data


def test_b64url_round_trip_covers_every_length():
    for n in range(65):
        data = bytes(range(n))
        assert b64url_decode(b64url_encode(data)) == data


@pytest.mark.parametrize("case", B64["invalid"], ids=lambda c: c["name"])
def test_b64url_rejects_invalid(case: dict[str, str]):
    with pytest.raises(EncodingError):
        b64url_decode(case["text"])


def test_digest_format():
    digest = sha256(b"")
    text = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert format_digest(digest) == text
    assert parse_digest(text) == digest


@pytest.mark.parametrize(
    "text",
    [
        "sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha256:" + "a" * 63,
        "sha256:" + "a" * 65,
        "sha256:" + "g" * 64,
    ],
)
def test_parse_digest_rejects(text: str):
    with pytest.raises(EncodingError):
        parse_digest(text)


def test_format_digest_rejects_wrong_length():
    with pytest.raises(EncodingError):
        format_digest(bytes(31))


def test_signature_format_length():
    text = format_signature(bytes(64))
    assert text.startswith("ed25519:")
    assert len(text) == 8 + 86
    assert parse_signature(text) == bytes(64)
    for n in (63, 65):
        with pytest.raises(EncodingError):
            format_signature(bytes(n))


@pytest.mark.parametrize(
    "text",
    [
        "ed25519:" + "A" * 85,
        "ed25519:" + "A" * 87,
        "sha256:" + "A" * 86,
        "A" * 86,
        "ed25519:" + "A" * 85 + "B",
    ],
)
def test_parse_signature_rejects(text: str):
    with pytest.raises(EncodingError):
        parse_signature(text)
