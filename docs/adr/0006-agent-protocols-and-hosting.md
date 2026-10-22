# 0006. Agent protocols and hosting

Status: accepted

## Context

The system has four trust domains that must exchange requests across organizational boundaries: the notary that signs verdicts, the studio agents that explain them, the verifier that checks them and the tools that compute deterministic facts. Each boundary needs a discoverable interface, a verifiable caller identity and a card that a client can trust before it sends anything.

Open protocols fit this. Agent2Agent (A2A) v1.0 describes agents with a signed Agent Card and carries calls over JSON-RPC. The Model Context Protocol (MCP) exposes deterministic tools. Microsoft Foundry supports both: its prompt agents call remote A2A endpoints through the generally available `a2a` tool, any prompt agent can expose an incoming A2A endpoint, and agents can use MCP tools. Incoming calls to Foundry require a Microsoft Entra token.

The risks to settle were whether a signed card survives the official SDK, whether Foundry reaches a server of ours with an Entra identity we can validate, whether our client can call Foundry's incoming endpoint, and what each hop costs in latency.

## Decision

Keep a custom A2A server with signed Agent Cards for the notary, and Foundry prompt agents with incoming A2A for the studio.

- Cards are signed with ES256 over the RFC 8785 canonical card without its signatures, and verified by an independent verifier that uses no SDK code. Clients refuse unsigned cards, altered cards, unknown `kid` values and other algorithms. The server serves the card from its own route because the SDK's serializer drops required fields at their default value (a2a-python issue 1278, still open in the pinned version). `sign_card` canonicalizes with the same rule instead of calling the SDK signer, so cards stay verifiable. The SDK's verifier refuses such cards; our client does not use it.
- Calls into our servers carry an Entra access token with an application role. The server checks signature, issuer, audience, tenant, expiry and the role, and answers 401 without a valid token and 403 without the role. Foundry reaches our server through a project connection with the agentic identity authentication type. The token comes from the calling agent's own identity, and the application role is granted to that identity's object ID.
- The Foundry incoming endpoint is called with an Entra token for the `https://ai.azure.com` audience and needs the `Foundry Agent Consumer` role at project or agent scope.
- The notary's A2A surface runs as a container app that scales to zero and can be hosted next to the confidential container (decision 0004) when the attested path is needed. Foundry's A2A tool accepts text parts only, so verdicts are returned as JSON inside a text part.
- A Foundry account name that has been purged cannot be reused: its project stays unreachable for many minutes. Account names are unique per deployment.

## Measurements

| Measurement | Value | Unit | Command | Date |
| --- | --- | --- | --- | --- |
| client_to_server latency, p50 of 20 warm calls | 170 | ms | `FOURTH_LIVE=1 uv run pytest infra/tests tools/a2a-interop/tests/test_a2a_live.py` | 2026-10-22 |
| client_to_server latency, p95 of 20 warm calls | 175 | ms | `FOURTH_LIVE=1 uv run pytest infra/tests tools/a2a-interop/tests/test_a2a_live.py` | 2026-10-22 |
| client_to_server cold start from zero replicas | 31215 | ms | `FOURTH_LIVE=1 uv run pytest infra/tests tools/a2a-interop/tests/test_a2a_live.py` | 2026-10-22 |
| foundry_to_server latency, p50 of 20 warm calls | 7008 | ms | `FOURTH_LIVE=1 uv run pytest infra/tests tools/a2a-interop/tests/test_a2a_live.py` | 2026-10-22 |
| foundry_to_server latency, p95 of 20 warm calls | 7985 | ms | `FOURTH_LIVE=1 uv run pytest infra/tests tools/a2a-interop/tests/test_a2a_live.py` | 2026-10-22 |
| foundry_to_server cold start from zero replicas | 29881 | ms | `FOURTH_LIVE=1 uv run pytest infra/tests tools/a2a-interop/tests/test_a2a_live.py` | 2026-10-22 |
| foundry_to_server tokens used by the scenario | 25897 | tokens | `FOURTH_LIVE=1 uv run pytest infra/tests tools/a2a-interop/tests/test_a2a_live.py` | 2026-10-22 |
| client_to_foundry latency, p50 of 20 warm calls | 2372 | ms | `FOURTH_LIVE=1 uv run pytest infra/tests tools/a2a-interop/tests/test_a2a_live.py` | 2026-10-22 |
| client_to_foundry latency, p95 of 20 warm calls | 2697 | ms | `FOURTH_LIVE=1 uv run pytest infra/tests tools/a2a-interop/tests/test_a2a_live.py` | 2026-10-22 |
| client_to_foundry first call | 3399 | ms | `FOURTH_LIVE=1 uv run pytest infra/tests tools/a2a-interop/tests/test_a2a_live.py` | 2026-10-22 |
| foundry_to_mcp latency, p50 of 20 warm calls | 3317 | ms | `FOURTH_LIVE=1 uv run pytest infra/tests tools/a2a-interop/tests/test_a2a_live.py` | 2026-10-22 |
| foundry_to_mcp latency, p95 of 20 warm calls | 6874 | ms | `FOURTH_LIVE=1 uv run pytest infra/tests tools/a2a-interop/tests/test_a2a_live.py` | 2026-10-22 |
| foundry_to_mcp cold start from zero replicas | 30237 | ms | `FOURTH_LIVE=1 uv run pytest infra/tests tools/a2a-interop/tests/test_a2a_live.py` | 2026-10-22 |
| foundry_to_mcp tokens used by the scenario | 14294 | tokens | `FOURTH_LIVE=1 uv run pytest infra/tests tools/a2a-interop/tests/test_a2a_live.py` | 2026-10-22 |
| Foundry incoming endpoint without a token | 401 | HTTP status | `FOURTH_LIVE=1 uv run pytest infra/tests tools/a2a-interop/tests/test_a2a_live.py` | 2026-10-22 |
| Foundry incoming endpoint with a token but without the Foundry Agent Consumer role | 404 | HTTP status | `FOURTH_LIVE=1 uv run pytest infra/tests tools/a2a-interop/tests/test_a2a_live.py` | 2026-10-22 |
| Identity behind the Foundry tool call | agentIdentity, equal to the agent's instance identity | Graph object type | `FOURTH_LIVE=1 uv run pytest infra/tests tools/a2a-interop/tests/test_a2a_live.py` | 2026-10-22 |
| Pinned a2a-sdk | 1.2.3 | version | `uv pip list` | 2026-10-22 |
| Pinned azure-ai-projects | 2.9.0 | version | `uv pip list` | 2026-10-22 |
| Pinned mcp | 2.3.0 | version | `uv pip list` | 2026-10-22 |
| a2a-python issue 1278 present in the pinned SDK | yes | boolean | `uv run pytest libs/a2a/py` | 2026-10-22 |

The warm latencies of the two Foundry-to-server paths include the model call that decides to use the tool, not only the network hop. The cold-start figures include scaling a container app from zero replicas.

Decision: keep a custom A2A server with signed Agent Cards for the notary, and Foundry prompt agents with incoming A2A for the studio.

## Consequences

- Incoming A2A on Foundry accepts Entra tokens only. Each caller needs the `Foundry Agent Consumer` role, and a caller without it receives 404, never a response from the agent.
- A caller that has no Entra identity of its own, such as a browser, cannot call a Foundry endpoint directly. It goes through a service of ours that holds an identity.
- Server-to-server auth from Foundry works with the calling agent's identity plus an application role on our API registration. This requires permission to create app registrations and to grant application roles.
- Verdicts must be text parts. Structured data goes inside the text as JSON.
- The cold start of a scale-to-zero container app is about 30 seconds. A demo that includes a Foundry-to-server hop keeps one replica warm.
- Signed cards depend on our canonicalization until the SDK issue is fixed. A strict test fails as soon as the SDK and the independent verifier agree, which is the signal to move back to the SDK signer.
- Foundry A2A tasks and contexts are retained for 60 days. Protocol versions are pinned: v1.0 over JSON-RPC, no streaming.
- Account names are never reused within a purge window, and the model deployment is created after the project because the account rejects concurrent child operations.
