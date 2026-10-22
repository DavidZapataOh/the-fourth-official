import json
from typing import Any

import jwt
import pytest
from a2a.types import AgentCapabilities, AgentCard, AgentInterface, AgentSkill
from a2a.utils.signing import ProtectedHeader, create_agent_card_signer
from cryptography.hazmat.primitives.asymmetric import ec
from fourth_a2a import (
    CardVerificationError,
    card_to_json,
    independent_verify_card,
    sign_card,
    verify_card,
)
from fourth_crypto import b64url_decode
from jwt.algorithms import ECAlgorithm

KID = "card-key-1"


def _jwk(key: ec.EllipticCurvePrivateKey, *, private: bool) -> dict[str, Any]:
    source = key if private else key.public_key()
    return json.loads(ECAlgorithm.to_jwk(source))


@pytest.fixture(scope="module")
def key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="module")
def private_jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, Any]:
    return _jwk(key, private=True)


@pytest.fixture(scope="module")
def keys(key: ec.EllipticCurvePrivateKey) -> dict[str, dict[str, Any]]:
    return {KID: _jwk(key, private=False)}


def _card(tags: list[str] | None = None, input_modes: list[str] | None = None) -> AgentCard:
    return AgentCard(
        name="Verdict Agent",
        description="Returns a fixed verdict for a claim hash.",
        version="1.0.0",
        supported_interfaces=[
            AgentInterface(
                url="https://verdict.example/a2a",
                protocol_binding="JSONRPC",
                protocol_version="1.0",
            )
        ],
        capabilities=AgentCapabilities(streaming=False),
        default_input_modes=["application/json"],
        default_output_modes=["application/json"],
        skills=[
            AgentSkill(
                id="echo-verdict",
                name="Echo verdict",
                description="Returns a fixed JSON verdict.",
                tags=["verdict"] if tags is None else tags,
                input_modes=["application/json"] if input_modes is None else input_modes,
            )
        ],
    )


def _both_accept(card: AgentCard, keys: dict[str, dict[str, Any]]) -> None:
    verify_card(card, keys)
    independent_verify_card(card_to_json(card), keys)


def test_signed_card_verifies_with_sdk_helper(private_jwk: dict[str, Any], keys: dict[str, Any]):
    signed = sign_card(_card(), private_jwk, KID)
    verify_card(signed, keys)


def test_signed_card_verifies_with_independent_verifier(
    private_jwk: dict[str, Any], keys: dict[str, Any]
):
    signed = sign_card(_card(), private_jwk, KID)
    independent_verify_card(card_to_json(signed), keys)
    header = signed.signatures[0].protected
    assert json.loads(b64url_decode(header)) == {
        "alg": "ES256",
        "kid": KID,
        "typ": "JOSE",
    }
    assert len(b64url_decode(signed.signatures[0].signature)) == 64


def test_sdk_signed_card_verifies_with_independent_verifier(
    private_jwk: dict[str, Any], keys: dict[str, Any]
):
    header = ProtectedHeader(kid=KID, alg="ES256", jku=None, typ="JOSE")
    signer = create_agent_card_signer(jwt.PyJWK.from_dict(private_jwk, "ES256"), header)
    _both_accept(signer(_card()), keys)


def test_signing_does_not_mutate_the_input(private_jwk: dict[str, Any]):
    card = _card()
    sign_card(card, private_jwk, KID)
    assert not card.signatures


def test_unsigned_card_is_refused(keys: dict[str, Any]):
    with pytest.raises(CardVerificationError):
        verify_card(_card(), keys)
    with pytest.raises(CardVerificationError):
        independent_verify_card(card_to_json(_card()), keys)


def test_altered_card_is_refused_by_both_verifiers(
    private_jwk: dict[str, Any], keys: dict[str, Any]
):
    signed = sign_card(_card(), private_jwk, KID)
    signed.skills[0].description = "Returns any verdict the caller likes."
    with pytest.raises(CardVerificationError):
        verify_card(signed, keys)
    with pytest.raises(CardVerificationError):
        independent_verify_card(card_to_json(signed), keys)


def test_unknown_kid_is_refused(private_jwk: dict[str, Any], keys: dict[str, Any]):
    signed = sign_card(_card(), private_jwk, "other-key")
    with pytest.raises(CardVerificationError):
        verify_card(signed, keys)
    with pytest.raises(CardVerificationError):
        independent_verify_card(card_to_json(signed), keys)


def test_signature_by_another_key_is_refused(keys: dict[str, Any]):
    stranger = _jwk(ec.generate_private_key(ec.SECP256R1()), private=True)
    signed = sign_card(_card(), stranger, KID)
    with pytest.raises(CardVerificationError):
        verify_card(signed, keys)
    with pytest.raises(CardVerificationError):
        independent_verify_card(card_to_json(signed), keys)


def test_wrong_algorithm_is_refused(keys: dict[str, Any]):
    p384 = ec.generate_private_key(ec.SECP384R1())
    header = ProtectedHeader(kid=KID, alg="ES384", jku=None, typ="JOSE")
    signer = create_agent_card_signer(
        jwt.PyJWK.from_dict(_jwk(p384, private=True), "ES384"), header
    )
    signed = signer(_card())
    with pytest.raises(CardVerificationError):
        verify_card(signed, {KID: _jwk(p384, private=False)})
    with pytest.raises(CardVerificationError):
        independent_verify_card(card_to_json(signed), {KID: _jwk(p384, private=False)})


def test_malformed_signature_is_refused(private_jwk: dict[str, Any], keys: dict[str, Any]):
    signed = sign_card(_card(), private_jwk, KID)
    signed.signatures[0].protected = "not base64 json"
    with pytest.raises(CardVerificationError):
        verify_card(signed, keys)
    with pytest.raises(CardVerificationError):
        independent_verify_card(card_to_json(signed), keys)


@pytest.mark.xfail(
    strict=True,
    raises=CardVerificationError,
    reason="a2a-python #1278: SDK canonicalization drops REQUIRED fields at their default value",
)
def test_required_fields_at_default_values_survive_signing(
    private_jwk: dict[str, Any], keys: dict[str, Any]
):
    card = _card(tags=[], input_modes=[])
    card.description = ""
    signed = sign_card(card, private_jwk, KID)
    assert card_to_json(signed)["skills"][0]["tags"] == []
    assert card_to_json(signed)["description"] == ""
    assert card_to_json(signed)["capabilities"]["streaming"] is False
    independent_verify_card(card_to_json(signed), keys)
    verify_card(signed, keys)
