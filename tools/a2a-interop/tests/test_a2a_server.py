import json
import logging
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from a2a.types import AgentCard
from conftest import BASE_URL, CLAIM_HASH, KID, load
from fourth_a2a import EntraClaims, EntraTokenError, card_to_json, independent_verify_card
from fourth_crypto import b64url_decode

server = load("a2a_interop_server", "server/app.py")

RPC_BODY = {
    "jsonrpc": "2.0",
    "id": "1",
    "method": "SendMessage",
    "params": {
        "message": {
            "messageId": "m1",
            "role": "ROLE_USER",
            "parts": [{"text": CLAIM_HASH}],
        }
    },
}
RPC_HEADERS = {"A2A-Version": "1.0"}

pytestmark = pytest.mark.anyio


def _http(app: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL)


async def _rpc(app: Any, token: str | None = None) -> httpx.Response:
    headers = dict(RPC_HEADERS)
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    async with _http(app) as http:
        return await http.post("/a2a", json=RPC_BODY, headers=headers)


async def test_server_serves_a_signed_card(signed_card: AgentCard, trusted_keys: dict[str, Any]):
    async with _http(server.build_app(signed_card, None)) as http:
        response = await http.get("/.well-known/agent-card.json")
    assert response.status_code == 200
    body = response.json()
    assert body == card_to_json(signed_card)
    independent_verify_card(body, trusted_keys)
    assert body["supportedInterfaces"][0]["protocolBinding"] == "JSONRPC"
    assert body["supportedInterfaces"][0]["protocolVersion"] == "1.0"
    assert [skill["id"] for skill in body["skills"]] == ["echo-verdict"]
    header = json.loads(b64url_decode(body["signatures"][0]["protected"]))
    assert header == {"alg": "ES256", "kid": KID, "typ": "JOSE"}


async def test_unauthenticated_server_answers_with_the_verdict(signed_card: AgentCard):
    response = await _rpc(server.build_app(signed_card, None))
    assert response.status_code == 200
    assert "error" not in response.json()
    assert CLAIM_HASH in response.text


async def test_server_rejects_missing_or_invalid_bearer_when_validator_is_set(
    signed_card: AgentCard,
    validator: Callable[[str], EntraClaims],
    entra_token: Callable[..., str],
):
    app = server.build_app(signed_card, validator)

    missing = await _rpc(app)
    assert missing.status_code == 401
    assert missing.headers["www-authenticate"].startswith("Bearer")

    assert (await _rpc(app, "not-a-jwt")).status_code == 401
    assert (await _rpc(app, entra_token(aud="api://other"))).status_code == 401
    assert (await _rpc(app, entra_token(exp=1_000_000_001))).status_code == 401

    no_role = await _rpc(app, entra_token(roles=[]))
    assert no_role.status_code == 403
    assert CLAIM_HASH not in no_role.text

    allowed = await _rpc(app, entra_token())
    assert allowed.status_code == 200
    assert CLAIM_HASH in allowed.text

    async with _http(app) as http:
        assert (await http.get("/.well-known/agent-card.json")).status_code == 200


async def test_server_asks_the_validator_for_the_exact_bearer(signed_card: AgentCard):
    seen: list[str] = []

    def validate(token: str) -> EntraClaims:
        seen.append(token)
        raise EntraTokenError("no")

    assert (await _rpc(server.build_app(signed_card, validate), "abc")).status_code == 401
    assert seen == ["abc"]


async def test_server_logs_the_identity_behind_each_validated_token(
    signed_card: AgentCard,
    validator: Callable[[str], EntraClaims],
    entra_token: Callable[..., str],
    caplog: pytest.LogCaptureFixture,
):
    app = server.build_app(signed_card, validator)
    with caplog.at_level(logging.INFO, logger=server.CALLER_LOGGER):
        await _rpc(app, "not-a-jwt")
        await _rpc(app, entra_token(oid="denied-oid", azp="denied-app", roles=[]))
        await _rpc(app, entra_token(oid="caller-oid", azp="caller-app"))
    assert [r.getMessage() for r in caplog.records if r.getMessage().startswith("a2a.caller")] == [
        "a2a.caller oid=denied-oid appid=denied-app allowed=False",
        "a2a.caller oid=caller-oid appid=caller-app allowed=True",
    ]


async def test_server_logs_why_a_bearer_token_was_rejected(
    signed_card: AgentCard,
    validator: Callable[[str], EntraClaims],
    caplog: pytest.LogCaptureFixture,
):
    app = server.build_app(signed_card, validator)
    with caplog.at_level(logging.INFO, logger=server.CALLER_LOGGER):
        await _rpc(app, "not-a-jwt")
    [record] = [r for r in caplog.records if r.getMessage().startswith("a2a.rejected")]
    assert record.levelno == logging.WARNING
    assert "reason=" in record.getMessage()


def test_jwks_are_fetched_on_the_first_validation_regardless_of_the_clock(monkeypatch):
    fetched: list[str] = []

    class Response:
        def raise_for_status(self):
            return self

        def json(self):
            return {"keys": []}

    monkeypatch.setattr(server.httpx, "get", lambda url: fetched.append(url) or Response())
    monkeypatch.setattr(server.time, "monotonic", lambda: 5.0)
    with pytest.raises(Exception, match=""):
        server.entra_validator("tenant", "audience")("not-a-jwt")
    assert len(fetched) == 1


async def test_verdict_is_a_text_part_because_foundry_accepts_only_text(signed_card: AgentCard):
    response = await _rpc(server.build_app(signed_card, None))
    [part] = response.json()["result"]["message"]["parts"]
    assert set(part) == {"text"}
    assert json.loads(part["text"]) == {"claimHash": CLAIM_HASH, "verdict": "supported"}
    assert signed_card.default_output_modes == ["text/plain"]
