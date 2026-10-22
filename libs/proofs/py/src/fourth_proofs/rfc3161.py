"""RFC 3161 timestamp token verification."""

import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from rfc3161_client import (
    SignedData,
    VerificationError,
    VerifierBuilder,
    decode_timestamp_response,
)

from .ledger import ProofError

_SHA256 = x509.ObjectIdentifier("2.16.840.1.101.3.4.2.1")
_GRANTED = b"\x30\x03\x02\x01\x00"
_OID_TAG = 0x06


@dataclass(frozen=True)
class TimestampInfo:
    """What a verified timestamp token attests."""

    signed_at: datetime
    authority: str
    serial: int


def verify_rfc3161(
    token_der: bytes,
    data_sha256: bytes,
    trusted_certs_pem: Sequence[str],
    *,
    now: float | None = None,
) -> TimestampInfo:
    """Verify an RFC 3161 timestamp over a SHA-256 digest.

    `token_der` is a DER `TimeStampResp` as returned by the authority, or the bare
    `TimeStampToken` it carries. The signing certificate must be embedded in the token and chain
    to one of `trusted_certs_pem`. Certificates are checked at the token's signing time, so tokens
    stay valid after the authority certificate expires, but the signing time may not be later
    than `now` (POSIX seconds, default the current time).
    """
    if len(data_sha256) != 32:  # noqa: PLR2004
        raise ProofError("data digest must be 32 bytes")
    try:
        response = decode_timestamp_response(_as_response(token_der))
        roots = [x509.load_pem_x509_certificate(pem.encode()) for pem in trusted_certs_pem]
        builder = VerifierBuilder()
        for root in roots:
            builder = builder.add_root_certificate(root)
        builder.build().verify(response, data_sha256)
    except (ValueError, VerificationError) as error:
        raise ProofError(f"invalid timestamp: {error}") from error
    info = response.tst_info
    if info.message_imprint.hash_algorithm != _SHA256:
        raise ProofError("timestamp imprint is not a SHA-256 digest")
    if info.gen_time.timestamp() > (time.time() if now is None else now):
        raise ProofError("timestamp is in the future")
    return TimestampInfo(
        signed_at=info.gen_time,
        authority=_signer(response.signed_data).subject.rfc4514_string(),
        serial=info.serial_number,
    )


def _signer(signed_data: SignedData) -> x509.Certificate:
    (signer,) = signed_data.signer_infos
    return next(
        cert
        for cert in map(x509.load_der_x509_certificate, signed_data.certificates)
        if cert.issuer == signer.issuer and cert.serial_number == signer.serial_number
    )


def _as_response(der: bytes) -> bytes:
    if len(der) < 4 or der[0] != 0x30:  # noqa: PLR2004
        raise ProofError("timestamp is not a DER sequence")
    header = 2 + (der[1] & 0x7F if der[1] & 0x80 else 0)
    if header >= len(der) or der[header] != _OID_TAG:
        return der
    body = _GRANTED + der
    return b"\x30" + _length(len(body)) + body


def _length(n: int) -> bytes:
    if n < 0x80:  # noqa: PLR2004
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw
