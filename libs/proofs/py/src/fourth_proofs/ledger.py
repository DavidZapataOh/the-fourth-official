"""Azure Confidential Ledger write transaction receipt verification."""

import base64
import hashlib
import hmac
from collections.abc import Mapping, Sequence
from typing import Any, cast

from azure.confidentialledger.receipt import verify_receipt
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from fourth_crypto import sha256

LEDGER_ENTRY_V1 = "LedgerEntryV1"


class ProofError(ValueError):
    """Raised when a proof does not verify or is malformed."""


def verify_ledger_receipt(
    receipt: Mapping[str, Any],
    service_cert_pem: str,
    *,
    application_claims: Sequence[Mapping[str, Any]] | None = None,
) -> None:
    """Verify a write transaction receipt against the ledger service identity certificate.

    `receipt` is the `receipt` object of a get-receipt response. When `application_claims` is
    non-empty, the claims must hash to the receipt's claims digest. The node certificate must be
    endorsed by `service_cert_pem`, through `serviceEndorsements` when the identity was renewed.
    Certificate validity periods are not checked, so historical receipts keep verifying.
    Certificate signatures must be whole bytes, which the SDK verifier does not require.
    """
    if application_claims:
        leaf: object = receipt.get("leafComponents")
        expected = (
            cast("Mapping[str, object]", leaf).get("claimsDigest")
            if isinstance(leaf, Mapping)
            else None
        )
        if _claims_digest(application_claims).hex() != expected:
            raise ProofError("application claims do not match the receipt claims digest")
    try:
        verify_receipt(dict(receipt), service_cert_pem)
    except (TypeError, ValueError) as error:
        raise ProofError(f"invalid receipt: {error}") from error
    for pem in (receipt["cert"], *(receipt.get("serviceEndorsements") or ()), service_cert_pem):
        cert = x509.load_pem_x509_certificate(pem.encode())
        if cert.public_bytes(Encoding.DER)[-len(cert.signature) - 1] != 0:
            raise ProofError("certificate signature has unused bits")


def _claims_digest(claims: Sequence[Mapping[str, Any]]) -> bytes:
    digests = b"".join(_claim_digest(claim) for claim in claims)
    return sha256(len(claims).to_bytes(4, "little") + digests)


def _claim_digest(claim: Mapping[str, Any]) -> bytes:
    try:
        match claim["kind"]:
            case "LedgerEntry":
                entry = claim["ledgerEntry"]
                protocol = _text(entry["protocol"])
                if protocol != LEDGER_ENTRY_V1:
                    raise ProofError(f"unsupported claim protocol: {protocol}")
                key = base64.b64decode(_text(entry["secretKey"]), validate=True)
                collection = hmac.digest(key, _text(entry["collectionId"]).encode(), hashlib.sha256)
                contents = hmac.digest(key, _text(entry["contents"]).encode(), hashlib.sha256)
                data = sha256(collection + contents)
            case "ClaimDigest":
                protocol = _text(claim["digest"]["protocol"])
                data = bytes.fromhex(_text(claim["digest"]["value"]))
            case kind:
                raise ProofError(f"unsupported claim kind: {kind}")
    except ProofError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise ProofError(f"malformed application claim: {error}") from error
    return sha256(protocol.encode() + data)


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise ProofError("application claim fields must be strings")
    return value
