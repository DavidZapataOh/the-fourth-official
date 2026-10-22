import importlib.util
import json
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import jwt
import pytest
from a2a.types import AgentCapabilities, AgentCard, AgentInterface, AgentSkill
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fourth_a2a import EntraClaims, sign_card, validate_entra_token
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "http://agent.test"
KID = "card-key-1"
TENANT = "11111111-2222-3333-4444-555555555555"
AUDIENCE = "api://fourth-verdict-agent"
ENTRA_KID = "entra-key-1"
ROLE = "A2A.Caller"
CLAIM_HASH = "sha256:" + "ab" * 32


def load(name: str, relative: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def jwk(key: ec.EllipticCurvePrivateKey, *, private: bool) -> dict[str, Any]:
    return json.loads(ECAlgorithm.to_jwk(key if private else key.public_key()))


def make_card() -> AgentCard:
    return AgentCard(
        name="Verdict Agent",
        description="Returns a fixed verdict for a claim hash.",
        version="1.0.0",
        supported_interfaces=[
            AgentInterface(
                url=f"{BASE_URL}/a2a",
                protocol_binding="JSONRPC",
                protocol_version="1.0",
            )
        ],
        capabilities=AgentCapabilities(streaming=False),
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain"],
        skills=[
            AgentSkill(
                id="echo-verdict",
                name="Echo verdict",
                description="Returns a fixed JSON verdict for a claim hash.",
                tags=["verdict"],
            )
        ],
    )


@pytest.fixture(scope="session")
def card_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="session")
def trusted_keys(card_key: ec.EllipticCurvePrivateKey) -> dict[str, dict[str, Any]]:
    return {KID: jwk(card_key, private=False)}


@pytest.fixture(scope="session")
def signed_card(card_key: ec.EllipticCurvePrivateKey) -> AgentCard:
    return sign_card(make_card(), jwk(card_key, private=True), KID)


@pytest.fixture(scope="session")
def entra_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def entra_token(entra_key: rsa.RSAPrivateKey) -> Callable[..., str]:
    def mint(**over: Any) -> str:
        claims: dict[str, Any] = {
            "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
            "aud": AUDIENCE,
            "tid": TENANT,
            "nbf": 1_000_000_000,
            "exp": 4_000_000_000,
            "oid": "99999999-0000-0000-0000-000000000001",
            "azp": "client-app-id",
            "roles": [ROLE],
        }
        claims.update(over)
        return jwt.encode(claims, entra_key, algorithm="RS256", headers={"kid": ENTRA_KID})

    return mint


@pytest.fixture(scope="session")
def validator(entra_key: rsa.RSAPrivateKey) -> Callable[[str], EntraClaims]:
    public = json.loads(RSAAlgorithm.to_jwk(entra_key.public_key()))
    jwks = {"keys": [{**public, "kid": ENTRA_KID, "alg": "RS256", "use": "sig"}]}

    def validate(token: str) -> EntraClaims:
        return validate_entra_token(token, tenant_id=TENANT, audience=AUDIENCE, jwks=jwks)

    return validate
