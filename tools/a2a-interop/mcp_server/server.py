"""MCP server with one tool, `claim_hash`, over streamable HTTP."""

from typing import Any, cast

from fourth_crypto import JsonValue, canonicalize, format_digest, sha256
from mcp.server.mcpserver import MCPServer

mcp = MCPServer("claim-hash")


@mcp.tool()
def claim_hash(claim: dict[str, Any]) -> str:
    """Return the SHA-256 digest of the RFC 8785 canonical form of a claim."""
    return format_digest(sha256(canonicalize(cast(JsonValue, claim))))


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=8080,
        stateless_http=True,
        json_response=True,
    )
