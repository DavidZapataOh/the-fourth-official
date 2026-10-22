import copy
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from a2a.client.errors import A2AClientError
from a2a.types import AgentCard
from conftest import BASE_URL, CLAIM_HASH, KID, jwk, load, make_card
from cryptography.hazmat.primitives.asymmetric import ec
from fourth_a2a import (
    CardVerificationError,
    EntraClaims,
    card_to_json,
    sign_card,
    verify_card,
)

server = load("a2a_interop_server_for_client", "server/app.py")
client = load("a2a_interop_client", "client/client.py")

pytestmark = pytest.mark.anyio


def _http(app: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL)


async def test_client_accepts_a_card_signed_by_a_trusted_key(
    signed_card: AgentCard, trusted_keys: dict[str, Any]
):
    async with _http(server.build_app(signed_card, None)) as http:
        card = await client.fetch_verified_card(BASE_URL, trusted_keys, http)
    assert card_to_json(card) == card_to_json(signed_card)


async def test_client_refuses_unsigned_and_tampered_cards(
    signed_card: AgentCard,
    trusted_keys: dict[str, Any],
    card_key: ec.EllipticCurvePrivateKey,
):
    tampered = AgentCard()
    tampered.CopyFrom(signed_card)
    tampered.skills[0].description = "Returns a different verdict."

    wrong_kid = sign_card(make_card(), jwk(card_key, private=True), "unknown-kid")

    stranger = sign_card(
        make_card(), jwk(ec.generate_private_key(ec.SECP256R1()), private=True), KID
    )

    for card in (make_card(), tampered, wrong_kid, stranger):
        async with _http(server.build_app(card, None)) as http:
            with pytest.raises(CardVerificationError):
                await client.fetch_verified_card(BASE_URL, trusted_keys, http)


async def test_client_verifies_the_served_bytes_not_a_reserialised_card(
    signed_card: AgentCard, trusted_keys: dict[str, Any]
):
    def altered(request: httpx.Request) -> httpx.Response:
        body = copy.deepcopy(card_to_json(signed_card))
        body["name"] = "Impostor"
        return httpx.Response(200, json=body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(altered)) as http:
        with pytest.raises(CardVerificationError):
            await client.fetch_verified_card(BASE_URL, trusted_keys, http)


async def test_required_field_at_default_value_survives_signing_and_serving(
    trusted_keys: dict[str, Any], card_key: ec.EllipticCurvePrivateKey
):
    card = make_card()
    del card.skills[0].tags[:]
    signed = sign_card(card, jwk(card_key, private=True), KID)
    async with _http(server.build_app(signed, None)) as http:
        fetched = await client.fetch_verified_card(BASE_URL, trusted_keys, http)
    assert card_to_json(fetched)["skills"][0]["tags"] == []
    # a2a-python #1278 on the pinned SDK: its own verifier refuses what the independent one accepts
    with pytest.raises(CardVerificationError):
        verify_card(fetched, trusted_keys)


async def test_echo_verdict_is_deterministic_for_a_claim_hash(
    signed_card: AgentCard, trusted_keys: dict[str, Any]
):
    async with _http(server.build_app(signed_card, None)) as http:
        card = await client.fetch_verified_card(BASE_URL, trusted_keys, http)
        first = await client.call_echo_verdict(card, CLAIM_HASH, None, http)
        second = await client.call_echo_verdict(card, CLAIM_HASH, None, http)
        other = await client.call_echo_verdict(card, "sha256:" + "cd" * 32, None, http)
    assert first == second
    assert first["claimHash"] == CLAIM_HASH
    assert first["verdict"] == "supported"
    assert other["claimHash"] != first["claimHash"]
    assert {k: v for k, v in other.items() if k != "claimHash"} == {
        k: v for k, v in first.items() if k != "claimHash"
    }


async def test_call_carries_the_bearer_token_and_is_refused_without_it(
    signed_card: AgentCard,
    trusted_keys: dict[str, Any],
    validator: Callable[[str], EntraClaims],
    entra_token: Callable[..., str],
):
    async with _http(server.build_app(signed_card, validator)) as http:
        card = await client.fetch_verified_card(BASE_URL, trusted_keys, http)
        verdict = await client.call_echo_verdict(card, CLAIM_HASH, entra_token(), http)
        assert verdict["claimHash"] == CLAIM_HASH
        with pytest.raises(A2AClientError):
            await client.call_echo_verdict(card, CLAIM_HASH, None, http)
        with pytest.raises(A2AClientError):
            await client.call_echo_verdict(card, CLAIM_HASH, entra_token(roles=[]), http)
