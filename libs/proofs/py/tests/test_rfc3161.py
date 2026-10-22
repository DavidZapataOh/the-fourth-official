import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from fourth_proofs import ProofError, TimestampInfo, verify_rfc3161

VECTOR = cast(
    "dict[str, Any]",
    json.loads(
        (Path(__file__).resolve().parents[2] / "vectors" / "rfc3161.json").read_text(
            encoding="utf-8"
        )
    ),
)
RESPONSE = base64.b64decode(VECTOR["response"])
TOKEN = base64.b64decode(VECTOR["token"])
DIGEST = bytes.fromhex(VECTOR["data_sha256"])
ROOTS = [VECTOR["root_certificate"]]
SIGNED_AT = datetime.fromisoformat(VECTOR["expected"]["signed_at"])


def expected() -> TimestampInfo:
    return TimestampInfo(
        signed_at=SIGNED_AT,
        authority=VECTOR["expected"]["authority"],
        serial=VECTOR["expected"]["serial"],
    )


@pytest.mark.parametrize("token", [RESPONSE, TOKEN], ids=["response", "token"])
def test_valid_token_returns_time_and_authority(token: bytes):
    assert verify_rfc3161(token, DIGEST, ROOTS) == expected()


def test_token_for_other_data_is_rejected():
    with pytest.raises(ProofError):
        verify_rfc3161(RESPONSE, bytes(32), ROOTS)


def test_digest_of_wrong_length_is_rejected():
    with pytest.raises(ProofError):
        verify_rfc3161(RESPONSE, DIGEST[:31], ROOTS)


def test_untrusted_authority_certificate_is_rejected():
    with pytest.raises(ProofError):
        verify_rfc3161(RESPONSE, DIGEST, [VECTOR["untrusted_root_certificate"]])


def test_no_trusted_certificates_is_rejected():
    with pytest.raises(ProofError):
        verify_rfc3161(RESPONSE, DIGEST, [])


def test_token_signed_in_the_future_is_rejected():
    before = (SIGNED_AT - timedelta(seconds=1)).timestamp()
    with pytest.raises(ProofError):
        verify_rfc3161(RESPONSE, DIGEST, ROOTS, now=before)


def test_authority_certificate_is_checked_at_signing_time_not_now():
    after_expiry = datetime(2040, 1, 1, tzinfo=UTC).timestamp()
    assert verify_rfc3161(RESPONSE, DIGEST, ROOTS, now=after_expiry) == expected()


def test_token_signed_after_authority_certificate_expired_is_rejected():
    response = base64.b64decode(VECTOR["expired_authority_response"])
    with pytest.raises(ProofError):
        verify_rfc3161(response, DIGEST, ROOTS)


def unsigned_cms_fields(token: bytes) -> set[int]:
    """Offsets of the SignedData and SignerInfo versions and the SignerInfo signature algorithm.

    CMS does not sign these; OpenSSL and rfc3161-client both accept any value there, and none of
    them changes what the timestamp attests.
    """
    signature_algorithm = token.rindex(bytes.fromhex("06082a8648ce3d040302")) + 2
    return {
        token.index(bytes.fromhex("02010331")) + 2,
        token.index(bytes.fromhex("02010130")) + 2,
        *range(signature_algorithm, signature_algorithm + 8),
    }


@pytest.mark.parametrize("token", [RESPONSE, TOKEN], ids=["response", "token"])
def test_altered_token_bytes_are_rejected(token: bytes):
    accepted: set[int] = set()
    for index in range(len(token)):
        altered = bytearray(token)
        altered[index] ^= 0x01
        try:
            info = verify_rfc3161(bytes(altered), DIGEST, ROOTS)
        except ProofError:
            continue
        assert info == expected()
        accepted.add(index)
    assert accepted == unsigned_cms_fields(token)


@pytest.mark.parametrize(
    "token",
    [RESPONSE[:1], RESPONSE[:100], RESPONSE[:-1], RESPONSE + b"\x00", b"\x30\xff\x00\x00", b""],
)
def test_truncated_extended_or_garbage_tokens_are_rejected(token: bytes):
    with pytest.raises(ProofError):
        verify_rfc3161(token, DIGEST, ROOTS)


LIVE_PATH = Path(__file__).resolve().parents[2] / "vectors" / "rfc3161_live.json"
live = pytest.mark.skipif(not LIVE_PATH.exists(), reason="no public authority token recorded")


def live_vector() -> dict[str, Any]:
    return cast("dict[str, Any]", json.loads(LIVE_PATH.read_text(encoding="utf-8")))


@live
def test_live_public_authority_token_verifies_against_its_published_root():
    vector = live_vector()
    response = base64.b64decode(vector["response"])
    digest = bytes.fromhex(vector["data_sha256"])
    info = verify_rfc3161(response, digest, [vector["root_certificate"]])
    assert info == TimestampInfo(
        signed_at=datetime.fromisoformat(vector["expected"]["signed_at"]),
        authority=vector["expected"]["authority"],
        serial=vector["expected"]["serial"],
    )
    with pytest.raises(ProofError):
        verify_rfc3161(response, bytes(32), [vector["root_certificate"]])
    with pytest.raises(ProofError):
        verify_rfc3161(response, digest, ROOTS)
