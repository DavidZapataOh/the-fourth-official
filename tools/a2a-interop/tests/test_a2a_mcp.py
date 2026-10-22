import pytest
from conftest import load
from fourth_crypto import canonicalize, format_digest, sha256
from mcp import Client

mcp_server = load("a2a_interop_mcp_server", "mcp_server/server.py")
pytestmark = pytest.mark.anyio

CLAIM = {"subject": "player-7", "predicate": "scored", "minute": 88, "tags": ["b", "a"]}


async def _hash(claim: dict) -> str:
    async with Client(mcp_server.mcp) as client:
        result = await client.call_tool("claim_hash", {"claim": claim})
    assert result.structured_content is not None
    return result.structured_content["result"]


async def test_mcp_exposes_only_the_claim_hash_tool():
    async with Client(mcp_server.mcp) as client:
        tools = await client.list_tools()
    assert [tool.name for tool in tools.tools] == ["claim_hash"]


async def test_mcp_claim_hash_matches_the_shared_cryptographic_core():
    assert await _hash(CLAIM) == format_digest(sha256(canonicalize(CLAIM)))


async def test_mcp_claim_hash_ignores_key_order():
    assert await _hash({"b": 1, "a": 2}) == await _hash({"a": 2, "b": 1})
