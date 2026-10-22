import base64
import hashlib
import hmac
import json
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fourth_attestation import AttestationError, policy_hash, verify_maa_token
from jwt.algorithms import RSAAlgorithm

ISSUER = "https://sharedneu.neu.attest.azure.net"
HOSTDATA = hashlib.sha256(b"policy").hexdigest()
EXP = 2_000_000_000
NOW = EXP - 100
KID = "key-1"


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks(key: rsa.RSAPrivateKey, kid: str = KID) -> dict[str, Any]:
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    return {"keys": [{**jwk, "kid": kid, "alg": "RS256", "use": "sig"}]}


def _claims(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "iss": ISSUER,
        "iat": EXP - 3600,
        "exp": EXP,
        "x-ms-attestation-type": "sevsnpvm",
        "x-ms-compliance-status": "azure-compliant-uvm",
        "x-ms-sevsnpvm-is-debuggable": False,
        "x-ms-sevsnpvm-hostdata": HOSTDATA,
    }
    return {**base, **over}


def _sign(key: rsa.RSAPrivateKey, kid: str = KID, **over: Any) -> str:
    return jwt.encode(_claims(**over), key, algorithm="RS256", headers={"kid": kid})


def _hs256(claims: dict[str, Any], secret: bytes) -> str:
    def part(value: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    signing_input = f"{part({'alg': 'HS256', 'typ': 'JWT', 'kid': KID})}.{part(claims)}"
    mac = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{base64.urlsafe_b64encode(mac).rstrip(b'=').decode()}"


def _verify(token: str, key: rsa.RSAPrivateKey, **kwargs: Any) -> Any:
    args: dict[str, Any] = {"issuer": ISSUER, "expected_hostdata": HOSTDATA, "now": NOW}
    return verify_maa_token(token, _jwks(key), **{**args, **kwargs})


@pytest.fixture(scope="module")
def key() -> rsa.RSAPrivateKey:
    return _key()


def test_valid_token_returns_claims(key: rsa.RSAPrivateKey):
    claims = _verify(_sign(key), key)
    assert claims.attestation_type == "sevsnpvm"
    assert claims.compliance_status == "azure-compliant-uvm"
    assert claims.hostdata == HOSTDATA
    assert claims.is_debuggable is False
    assert claims.issuer == ISSUER
    assert claims.expires_at == EXP


def test_rejects_signature_by_other_key(key: rsa.RSAPrivateKey):
    with pytest.raises(AttestationError):
        _verify(_sign(_key()), key)


def test_rejects_unknown_kid(key: rsa.RSAPrivateKey):
    with pytest.raises(AttestationError, match="kid"):
        _verify(_sign(key, kid="other"), key)


def test_rejects_alg_none_and_hs256_confusion(key: rsa.RSAPrivateKey):
    unsigned = jwt.encode(_claims(), "", algorithm="none", headers={"kid": KID})
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    forged = _hs256(_claims(), pem)
    for token in (unsigned, forged):
        with pytest.raises(AttestationError):
            _verify(token, key)


def test_rejects_expired_token(key: rsa.RSAPrivateKey):
    with pytest.raises(AttestationError, match="exp"):
        _verify(_sign(key), key, now=EXP + 1)


def test_rejects_wrong_issuer(key: rsa.RSAPrivateKey):
    with pytest.raises(AttestationError, match="iss"):
        _verify(_sign(key, iss="https://evil.example"), key)


def test_rejects_hostdata_mismatch(key: rsa.RSAPrivateKey):
    with pytest.raises(AttestationError, match="hostdata"):
        _verify(_sign(key), key, expected_hostdata=hashlib.sha256(b"other").hexdigest())


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("x-ms-sevsnpvm-is-debuggable", True),
        ("x-ms-compliance-status", "azure-noncompliant-uvm"),
        ("x-ms-attestation-type", "sgx"),
    ],
)
def test_rejects_failed_microsoft_claim(key: rsa.RSAPrivateKey, claim: str, value: Any):
    with pytest.raises(AttestationError, match=claim):
        _verify(_sign(key, **{claim: value}), key)


def test_rejects_malformed_token(key: rsa.RSAPrivateKey):
    with pytest.raises(AttestationError):
        _verify("not-a-jwt", key)


def test_policy_hash_known_answer():
    assert (
        policy_hash(base64.b64encode(b"policy").decode()) == hashlib.sha256(b"policy").hexdigest()
    )


def test_policy_hash_rejects_invalid_base64():
    with pytest.raises(AttestationError):
        policy_hash("not base64!")
