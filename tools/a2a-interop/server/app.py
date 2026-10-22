"""A2A server exposing one skill, `echo-verdict`, that returns a fixed verdict for a claim hash."""

import json
import logging
import math
import os
import time
from collections.abc import Callable
from http import HTTPStatus
from typing import Any

import httpx
import uvicorn
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    Message,
    Part,
    Role,
)
from a2a.utils import AGENT_CARD_WELL_KNOWN_PATH
from fourth_a2a import (
    EntraClaims,
    EntraTokenError,
    card_to_json,
    sign_card,
    validate_entra_token,
)
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

RPC_URL = "/a2a"
REQUIRED_ROLE = "A2A.Caller"
JWKS_TTL_SECONDS = 3600
CALLER_LOGGER = "a2a.caller"

caller_log = logging.getLogger(CALLER_LOGGER)


class EchoVerdictExecutor(AgentExecutor):
    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        verdict = {"claimHash": context.get_user_input().strip(), "verdict": "supported"}
        await event_queue.enqueue_event(
            Message(
                role=Role.ROLE_AGENT,
                message_id=f"verdict-{context.message.message_id}" if context.message else "",
                context_id=context.context_id or "",
                parts=[Part(text=json.dumps(verdict))],
            )
        )

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise NotImplementedError


def build_app(
    card: AgentCard,
    validator: Callable[[str], EntraClaims] | None,
    required_role: str = REQUIRED_ROLE,
) -> Starlette:
    """Serve `card` unchanged and, when `validator` is set, require a valid bearer with a role.

    Every validated token logs its `oid`, `appid` and whether the role allowed the call on the
    `a2a.caller` logger.

    The card route replaces the SDK's, which serialises with `MessageToDict` and drops REQUIRED
    fields at their default value (a2a-python #1278), so it can serve JSON the signature does not
    cover.
    """
    handler = DefaultRequestHandler(
        agent_executor=EchoVerdictExecutor(), task_store=InMemoryTaskStore(), agent_card=card
    )
    served = card_to_json(card)

    async def agent_card(request: Request) -> Response:
        return JSONResponse(served)

    async def require_bearer(request: Request, call_next: RequestResponseEndpoint) -> Response:
        if validator is None or request.url.path == AGENT_CARD_WELL_KNOWN_PATH:
            return await call_next(request)
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            return _deny(HTTPStatus.UNAUTHORIZED, "missing bearer token")
        try:
            claims = validator(token)
        except EntraTokenError as error:
            caller_log.warning("a2a.rejected reason=%s", error)
            return _deny(HTTPStatus.UNAUTHORIZED, "invalid bearer token")
        allowed = required_role in claims.roles
        caller_log.info("a2a.caller oid=%s appid=%s allowed=%s", claims.oid, claims.appid, allowed)
        if not allowed:
            return _deny(HTTPStatus.FORBIDDEN, "missing required role")
        return await call_next(request)

    return Starlette(
        routes=[
            Route(AGENT_CARD_WELL_KNOWN_PATH, agent_card, methods=["GET"]),
            *create_jsonrpc_routes(handler, RPC_URL),
        ],
        middleware=[Middleware(BaseHTTPMiddleware, dispatch=require_bearer)],
    )


def _deny(status: HTTPStatus, detail: str) -> Response:
    headers = {"WWW-Authenticate": "Bearer"} if status == HTTPStatus.UNAUTHORIZED else None
    return JSONResponse({"error": detail}, status_code=status, headers=headers)


def verdict_card(public_url: str) -> AgentCard:
    return AgentCard(
        name="Verdict Agent",
        description="Returns a fixed verdict for a claim hash.",
        version="1.0.0",
        supported_interfaces=[
            AgentInterface(
                url=public_url.rstrip("/") + RPC_URL,
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


def entra_validator(tenant_id: str, audience: str) -> Callable[[str], EntraClaims]:
    keys_url = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
    cache: dict[str, Any] = {"fetched": -math.inf, "jwks": {}}

    def validate(token: str) -> EntraClaims:
        if time.monotonic() - cache["fetched"] > JWKS_TTL_SECONDS:
            cache["jwks"] = httpx.get(keys_url).raise_for_status().json()
            cache["fetched"] = time.monotonic()
        return validate_entra_token(
            token, tenant_id=tenant_id, audience=audience, jwks=cache["jwks"]
        )

    return validate


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    signed = sign_card(
        verdict_card(os.environ["PUBLIC_URL"]),
        json.loads(os.environ["CARD_SIGNING_JWK"]),
        os.environ["CARD_KID"],
    )
    tenant = os.environ.get("ENTRA_TENANT_ID")
    validator = entra_validator(tenant, os.environ["ENTRA_AUDIENCE"]) if tenant else None
    uvicorn.run(build_app(signed, validator), host="0.0.0.0", port=8080)
