import base64
import binascii
import hashlib
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import jwt


class AttestationError(ValueError):
    """Raised when an attestation token or policy is not acceptable."""


@dataclass(frozen=True)
class MaaClaims:
    attestation_type: str
    compliance_status: str
    hostdata: str
    is_debuggable: bool
    issuer: str
    expires_at: int


def policy_hash(cce_policy_b64: str) -> str:
    """Return the lowercase SHA-256 hex digest of the decoded CCE policy."""
    try:
        policy = base64.b64decode(cce_policy_b64, validate=True)
    except binascii.Error as error:
        raise AttestationError("policy is not valid base64") from error
    return hashlib.sha256(policy).hexdigest()


def verify_maa_token(
    token: str,
    jwks: Mapping[str, Any],
    *,
    issuer: str,
    expected_hostdata: str,
    now: float | None = None,
) -> MaaClaims:
    """Verify a Microsoft Azure Attestation JWT for a confidential container group.

    Expiry is compared against `now` (default: current time) so the clock is injectable.
    """
    try:
        kid = str(jwt.get_unverified_header(token).get("kid"))
        key = jwt.PyJWKSet.from_dict(dict(jwks))[kid]
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=issuer,
            options={"require": ["exp", "iat", "iss"], "verify_exp": False, "verify_iat": False},
        )
    except KeyError as error:
        raise AttestationError(f"unknown kid: {error}") from error
    except jwt.PyJWTError as error:
        raise AttestationError(f"invalid token: {error}") from error

    expires_at = claims["exp"]
    if not isinstance(expires_at, int) or expires_at <= (time.time() if now is None else now):
        raise AttestationError("token exp is not in the future")
    for claim, expected in (
        ("x-ms-attestation-type", "sevsnpvm"),
        ("x-ms-compliance-status", "azure-compliant-uvm"),
        ("x-ms-sevsnpvm-is-debuggable", False),
        ("x-ms-sevsnpvm-hostdata", expected_hostdata),
    ):
        if claims.get(claim) != expected:
            raise AttestationError(f"unexpected {claim}")
    return MaaClaims(
        attestation_type=claims["x-ms-attestation-type"],
        compliance_status=claims["x-ms-compliance-status"],
        hostdata=claims["x-ms-sevsnpvm-hostdata"],
        is_debuggable=claims["x-ms-sevsnpvm-is-debuggable"],
        issuer=claims["iss"],
        expires_at=expires_at,
    )
