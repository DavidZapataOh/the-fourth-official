import base64
import hashlib
import hmac
import json
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fourth_a2a.entra import EntraClaims, EntraTokenError, validate_entra_token
from jwt.algorithms import RSAAlgorithm

TENANT = "11111111-2222-3333-4444-555555555555"
AUDIENCE = "api://fourth-verdict-agent"
ISSUER_V1 = f"https://sts.windows.net/{TENANT}/"
ISSUER_V2 = f"https://login.microsoftonline.com/{TENANT}/v2.0"
EXP = 2_000_000_000
NOW = EXP - 100
KID = "entra-key-1"


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks(key: rsa.RSAPrivateKey, kid: str = KID) -> dict[str, Any]:
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    return {"keys": [{**jwk, "kid": kid, "alg": "RS256", "use": "sig"}]}


def _claims(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "iss": ISSUER_V2,
        "aud": AUDIENCE,
        "tid": TENANT,
        "nbf": EXP - 3600,
        "exp": EXP,
        "oid": "99999999-0000-0000-0000-000000000001",
        "azp": "client-app-id",
        "roles": ["Foundry Agent Consumer"],
    }
    return {k: v for k, v in {**base, **over}.items() if v is not None}


def _sign(key: rsa.RSAPrivateKey, over: dict[str, Any] | None = None, kid: str = KID) -> str:
    return jwt.encode(_claims(**(over or {})), key, algorithm="RS256", headers={"kid": kid})


def _hs256(claims: dict[str, Any], secret: bytes) -> str:
    def part(value: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    signing_input = f"{part({'alg': 'HS256', 'typ': 'JWT', 'kid': KID})}.{part(claims)}"
    mac = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{base64.urlsafe_b64encode(mac).rstrip(b'=').decode()}"


def _validate(token: str, key: rsa.RSAPrivateKey, **kwargs: Any) -> EntraClaims:
    args: dict[str, Any] = {
        "tenant_id": TENANT,
        "audience": AUDIENCE,
        "jwks": _jwks(key),
        "now": NOW,
    }
    return validate_entra_token(token, **{**args, **kwargs})


@pytest.fixture(scope="module")
def key() -> rsa.RSAPrivateKey:
    return _key()


def test_valid_token_returns_claims(key: rsa.RSAPrivateKey):
    claims = _validate(_sign(key), key)
    assert claims.oid == "99999999-0000-0000-0000-000000000001"
    assert claims.appid == "client-app-id"
    assert claims.roles == ("Foundry Agent Consumer",)


def test_v1_token_uses_appid_and_may_omit_roles(key: rsa.RSAPrivateKey):
    token = _sign(key, {"iss": ISSUER_V1, "appid": "v1-app-id", "azp": None, "roles": None})
    claims = _validate(token, key)
    assert claims.appid == "v1-app-id"
    assert claims.roles == ()


def test_rejects_wrong_issuer_audience_and_tenant(key: rsa.RSAPrivateKey):
    other = "99999999-9999-9999-9999-999999999999"
    for over in (
        {"iss": f"https://sts.windows.net/{other}/"},
        {"iss": f"https://login.microsoftonline.com/{other}/v2.0"},
        {"iss": "https://evil.example/"},
        {"aud": "api://someone-else"},
        {"aud": [AUDIENCE, "api://other"]},
        {"tid": other},
        {"tid": None},
    ):
        with pytest.raises(EntraTokenError):
            _validate(_sign(key, over), key)


def test_rejects_expired_and_not_yet_valid_tokens(key: rsa.RSAPrivateKey):
    with pytest.raises(EntraTokenError):
        _validate(_sign(key), key, now=EXP)
    with pytest.raises(EntraTokenError):
        _validate(_sign(key), key, now=EXP - 3601)
    _validate(_sign(key), key, now=EXP - 3600)


def test_rejects_tokens_missing_required_claims(key: rsa.RSAPrivateKey):
    for claim in ("exp", "nbf", "iss", "aud", "oid"):
        with pytest.raises(EntraTokenError):
            _validate(_sign(key, {claim: None}), key)
    with pytest.raises(EntraTokenError):
        _validate(_sign(key, {"azp": None}), key)


def test_rejects_unknown_kid_and_bad_signature(key: rsa.RSAPrivateKey):
    with pytest.raises(EntraTokenError):
        _validate(_sign(key, kid="other"), key)
    with pytest.raises(EntraTokenError):
        _validate(_sign(_key()), key)
    with pytest.raises(EntraTokenError):
        _validate("not-a-jwt", key)


def test_rejects_alg_none_and_hs256_confusion(key: rsa.RSAPrivateKey):
    unsigned = jwt.encode(_claims(), "", algorithm="none", headers={"kid": KID})
    with pytest.raises(EntraTokenError):
        _validate(unsigned, key)
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(EntraTokenError):
        _validate(_hs256(_claims(), public_pem), key)


def test_accepts_v1_and_v2_issuer_formats(key: rsa.RSAPrivateKey):
    for issuer in (ISSUER_V1, ISSUER_V2):
        assert _validate(_sign(key, {"iss": issuer}), key).oid
