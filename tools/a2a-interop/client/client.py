"""A2A client that verifies the Agent Card signature before sending the first message."""

import json
import uuid
from collections.abc import Mapping
from typing import Any

import httpx
from a2a.client import ClientCallContext, ClientConfig, create_client
from a2a.client.card_resolver import parse_agent_card
from a2a.types import AgentCard, Message, Part, Role, SendMessageRequest
from a2a.utils import AGENT_CARD_WELL_KNOWN_PATH
from fourth_a2a import independent_verify_card


async def fetch_verified_card(
    base_url: str, keys: Mapping[str, Mapping[str, Any]], http: httpx.AsyncClient
) -> AgentCard:
    """Fetch the card and verify its signature over the served JSON before parsing it.

    Raises `CardVerificationError` for an unsigned or altered card or an unknown `kid`.
    """
    response = await http.get(base_url.rstrip("/") + AGENT_CARD_WELL_KNOWN_PATH)
    response.raise_for_status()
    card_json = response.json()
    independent_verify_card(card_json, keys)
    return parse_agent_card(card_json)


async def call_echo_verdict(
    card: AgentCard, claim_hash: str, token: str | None, http: httpx.AsyncClient
) -> dict[str, Any]:
    """Send `claim_hash` to the card's `echo-verdict` skill and return the verdict."""
    client = await create_client(
        card,
        ClientConfig(httpx_client=http, streaming=False, supported_protocol_bindings=["JSONRPC"]),
    )
    context = ClientCallContext(
        service_parameters={"Authorization": f"Bearer {token}"} if token else {}
    )
    request = SendMessageRequest(
        message=Message(
            message_id=str(uuid.uuid4()), role=Role.ROLE_USER, parts=[Part(text=claim_hash)]
        )
    )
    async for response in client.send_message(request, context=context):
        if response.HasField("message"):
            return json.loads(response.message.parts[0].text)
    raise RuntimeError("the agent returned no verdict")
