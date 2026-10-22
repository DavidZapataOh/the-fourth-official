"""Deploys the A2A and MCP interoperability scenarios to Foundry and Container Apps.

Run with `uv run python tools/a2a-interop/run.py`. Requires Docker, the Azure CLI with the
`containerapp` extension, and an `az` session that can create resource groups, role assignments
and Microsoft Entra app registrations, and grant app roles.
"""

import asyncio
import datetime
import hashlib
import importlib.metadata
import importlib.util
import json
import re
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, TypedDict

import httpx
from a2a.client import A2ACardResolver, ClientConfig, create_client
from a2a.helpers import new_text_message
from a2a.types import Role, SendMessageRequest
from azure.ai.projects import AIProjectClient
from azure.ai.projects.models import (
    A2AProtocolConfiguration,
    A2AProtocolVersion,
    A2ATool,
    AgentCard,
    AgentCardSkill,
    AgentEndpointConfig,
    MCPTool,
    PromptAgentDefinition,
    ProtocolConfiguration,
    ResponsesProtocolConfiguration,
)
from azure.core.exceptions import ClientAuthenticationError, ResourceNotFoundError
from azure.identity import AzureCliCredential, CertificateCredential
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from fourth_crypto import canonicalize, format_digest, sha256
from jwt.algorithms import ECAlgorithm
from openai import OpenAI

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FOUNDRY_MODULE = ROOT / "infra" / "modules" / "foundry.bicep"
APPS_MODULE = ROOT / "infra" / "modules" / "interop-apps.bicep"

GROUP = "rg-fourth-spike-a2a"
APPS_LOCATION = "northeurope"
FOUNDRY_LOCATION = "swedencentral"
PROJECT = "a2a-interop"
IDENTITY = "id-a2a-pull"
A2A_APP = "ca-a2a-server"
MCP_APP = "ca-mcp-server"
IMAGES = {
    "a2a-server": HERE / "server" / "Dockerfile",
    "mcp-server": HERE / "mcp_server" / "Dockerfile",
}
API_APP = "fourth-spike-a2a-api"
CALLER_APP = "fourth-spike-a2a-caller"
APP_ROLE = "A2A.Caller"
CARD_KID = "card-key-1"
CONNECTION = "fourth-verdict-server"
CALLER_AGENT = "fourth-a2a-caller"
TARGET_AGENT = "fourth-verdict"
MCP_AGENT = "fourth-mcp-caller"
FOUNDRY_AUDIENCE = "https://ai.azure.com"
FOUNDRY_CARD_PATH = "agentCard/v1.0"
AGENT_CONSUMER = "eed3b665-ab3a-47b6-8f48-c9382fb1dad6"
CONNECTIONS_API = "2025-04-01-preview"
GRAPH = "https://graph.microsoft.com/v1.0"
WARM_CALLS = 20
ATTEMPTS = 6
SCALE_TO_ZERO_DEADLINE_S = 600
ACCESS_DEADLINE_S = 900
CREDENTIAL_DEADLINE_S = 180
CLAIM = {"club": "Harbour Town FC", "minute": 63, "event": "offside", "player": "No. 9"}
CLAIM_HASH = format_digest(sha256(canonicalize(CLAIM)))
LOG_LINE = re.compile(r"a2a\.caller oid=([\w-]+) appid=([\w-]+) allowed=(True|False)")
SDK_PACKAGES = ("azure-ai-projects", "a2a-sdk", "mcp", "openai")


class ScenarioResult(TypedDict):
    ok: bool
    latencies_ms: list[float]
    cold_ms: float | None
    tokens: int | None


def percentile(values: list[float], q: int) -> float:
    """Linearly interpolated percentile `q` (1-99) of a non-empty sample."""
    if not values:
        raise ValueError("percentile of an empty sample")
    if len(values) == 1:
        return values[0]
    return statistics.quantiles(values, n=100, method="inclusive")[q - 1]


def summarize(result: ScenarioResult) -> dict[str, Any]:
    """Warm p50 and p95 with the cold call reported apart."""
    warm = result["latencies_ms"]
    return {
        "ok": result["ok"],
        "calls": len(warm),
        "p50_ms": percentile(warm, 50) if warm else None,
        "p95_ms": percentile(warm, 95) if warm else None,
        "cold_ms": result["cold_ms"],
        "tokens": result["tokens"],
    }


def build_report(
    scenarios: dict[str, Any],
    *,
    rejections: dict[str, int],
    identity: dict[str, Any],
    versions: dict[str, str],
) -> dict[str, Any]:
    for name, result in scenarios.items():
        if set(result) != set(ScenarioResult.__annotations__):
            raise ValueError(f"scenario {name} has the wrong shape: {sorted(result)}")
    return {
        "date": datetime.date.today().isoformat(),
        "regions": {"foundry": FOUNDRY_LOCATION, "apps": APPS_LOCATION},
        "scenarios": {name: summarize(result) for name, result in scenarios.items()},
        "rejections": rejections,
        "identity": identity,
        "versions": versions,
    }


def foundry_a2a_base_url(account: str, project: str, agent: str) -> str:
    return (
        f"https://{account}.services.ai.azure.com/api/projects/{project}"
        f"/agents/{agent}/endpoint/protocols/a2a"
    )


def callers_from_logs(text: str) -> list[dict[str, Any]]:
    return [
        {"oid": oid, "appid": appid, "allowed": allowed == "True"}
        for oid, appid, allowed in LOG_LINE.findall(text)
    ]


def _load(name: str, relative: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, HERE / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def az(*args: str, parse: bool = True) -> Any:
    result = subprocess.run(
        ["az", *args, "-o", "json"], check=False, capture_output=True, text=True
    )
    if result.returncode:
        raise RuntimeError(f"az {' '.join(args[:3])} failed: {result.stderr[-1500:]}")
    return json.loads(result.stdout) if parse and result.stdout.strip() else result.stdout


def sh(*args: str) -> str:
    result = subprocess.run(args, check=False, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"{' '.join(args[:3])} failed: {result.stderr[-1500:]}")
    return result.stdout.strip()


STARTED = time.monotonic()
RUN_ID = uuid.uuid4().hex[:6]


def phase(name: str) -> None:
    print(f"[{time.monotonic() - STARTED:6.0f}s] {name}", file=sys.stderr, flush=True)


def retry[T](action: Callable[[], T], attempts: int = ATTEMPTS, delay_s: float = 10) -> T:
    """Retry a call that fails until a new principal or project has replicated."""
    for attempt in range(attempts):
        try:
            return action()
        except (subprocess.CalledProcessError, RuntimeError, ResourceNotFoundError):
            if attempt == attempts - 1:
                raise
            time.sleep(delay_s)
    raise AssertionError("unreachable")


def graph(method: str, path: str, body: dict[str, Any] | None = None) -> Any:
    args = ["rest", "--method", method, "--uri", f"{GRAPH}{path}"]
    if body is not None:
        args += ["--headers", "Content-Type=application/json", "--body", json.dumps(body)]
    return az(*args)


def names(subscription: str) -> tuple[str, str]:
    """Registry and Foundry account names. The account name is unique per run: a purged name
    leaves its project unreachable for a long time when it is created again."""
    digest = hashlib.sha256(subscription.encode()).hexdigest()[:8]
    return f"fourtha2a{digest}", f"fourth-a2a-{digest}-{RUN_ID}"


def assign_role(object_id: str, role: str, scope: str) -> None:
    args = ["role", "assignment", "create", "--assignee-object-id", object_id,
            "--assignee-principal-type", "ServicePrincipal", "--role", role,
            "--scope", scope]  # fmt: skip
    retry(lambda: az(*args))


def provision(acr: str) -> str:
    """Create the group, registry and pull identity; return the identity resource ID."""
    az("group", "create", "-n", GROUP, "-l", APPS_LOCATION)
    az("acr", "create", "-g", GROUP, "-n", acr, "--sku", "Basic", "--admin-enabled", "false")
    identity = az("identity", "create", "-g", GROUP, "-n", IDENTITY)
    assign_role(identity["principalId"], "AcrPull", az("acr", "show", "-n", acr, "--query", "id"))
    return identity["id"]


def build_and_push(acr: str) -> dict[str, str]:
    """Build and push both images; return image names mapped to digest-pinned references."""
    server = f"{acr}.azurecr.io"
    sh("az", "acr", "login", "-n", acr)
    images = {}
    for name, dockerfile in IMAGES.items():
        reference = f"{server}/{name}:1"
        sh("docker", "build", "--platform", "linux/amd64", "-f", str(dockerfile), "-t", reference,
           str(ROOT))  # fmt: skip
        retry(lambda reference=reference: sh("docker", "push", reference))
        digest = az("acr", "repository", "show", "-n", acr, "--image", f"{name}:1",
                    "--query", "digest")  # fmt: skip
        images[name] = f"{server}/{name}@{digest}"
    return images


@dataclass
class Caller:
    app_id: str
    object_id: str
    credential: CertificateCredential


def register_api() -> tuple[str, str, str]:
    """Register the A2A server's API with one application role; return app, SP and role IDs."""
    role_id = str(uuid.uuid4())
    roles = [
        {
            "id": role_id,
            "value": APP_ROLE,
            "displayName": APP_ROLE,
            "description": "Call the verdict agent over A2A.",
            "allowedMemberTypes": ["Application"],
            "isEnabled": True,
        }
    ]
    app = az("ad", "app", "create", "--display-name", API_APP, "--sign-in-audience",
             "AzureADMyOrg", "--requested-access-token-version", "2",
             "--app-roles", json.dumps(roles))  # fmt: skip
    az("ad", "app", "update", "--id", app["appId"], "--identifier-uris", f"api://{app['appId']}")
    principal = retry(lambda: az("ad", "sp", "create", "--id", app["appId"]))
    return app["appId"], principal["id"], role_id


def self_signed(name: str) -> tuple[bytes, bytes]:
    """A one-day certificate for the caller app; return (certificate PEM, key PEM)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return certificate.public_bytes(serialization.Encoding.PEM), key_pem


def register_caller(tenant: str) -> Caller:
    """Register the client identity with a certificate that never leaves this process."""
    app = az("ad", "app", "create", "--display-name", CALLER_APP, "--sign-in-audience",
             "AzureADMyOrg")  # fmt: skip
    principal = retry(lambda: az("ad", "sp", "create", "--id", app["appId"]))
    certificate, key = self_signed(CALLER_APP)
    with tempfile.NamedTemporaryFile("wb", suffix=".pem") as public:
        public.write(certificate)
        public.flush()
        az("ad", "app", "credential", "reset", "--id", app["appId"], "--cert",
           f"@{public.name}", "--append")  # fmt: skip
    credential = CertificateCredential(tenant, app["appId"], certificate_data=key + certificate)
    started = time.monotonic()
    while True:
        try:
            credential.get_token(f"{FOUNDRY_AUDIENCE}/.default")
            break
        except ClientAuthenticationError:
            if time.monotonic() - started > CREDENTIAL_DEADLINE_S:
                raise
            time.sleep(10)
    return Caller(app["appId"], principal["id"], credential)


def grant_app_role(principal_id: str, resource_id: str, role_id: str) -> None:
    body = {"principalId": principal_id, "resourceId": resource_id, "appRoleId": role_id}
    retry(lambda: graph("POST", f"/servicePrincipals/{resource_id}/appRoleAssignedTo", body))


def card_keys() -> tuple[dict[str, Any], dict[str, Any]]:
    key = ec.generate_private_key(ec.SECP256R1())
    private = json.loads(ECAlgorithm.to_jwk(key))
    public = json.loads(ECAlgorithm.to_jwk(key.public_key()))
    return private, public


def deploy(module: Path, parameters: dict[str, Any]) -> dict[str, Any]:
    """Deploy a module from a private parameters file so secure values stay off the command line."""
    with tempfile.NamedTemporaryFile("w", suffix=".json") as file:
        json.dump(
            {
                "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
                "contentVersion": "1.0.0.0",
                "parameters": {k: {"value": v} for k, v in parameters.items()},
            },
            file,
        )
        file.flush()
        result = az("deployment", "group", "create", "-g", GROUP, "-n", module.stem,
                    "--template-file", str(module), "--parameters", f"@{file.name}")  # fmt: skip
    return {k: v["value"] for k, v in result["properties"]["outputs"].items()}


def create_connection(subscription: str, account: str, target: str, audience: str) -> None:
    """Project connection that makes Foundry present the calling agent's Entra token."""
    url = (
        f"https://management.azure.com/subscriptions/{subscription}/resourceGroups/{GROUP}"
        f"/providers/Microsoft.CognitiveServices/accounts/{account}/projects/{PROJECT}"
        f"/connections/{CONNECTION}?api-version={CONNECTIONS_API}"
    )
    body = {
        "properties": {
            "authType": "AgenticIdentityToken",
            "group": "ServicesAndApps",
            "category": "RemoteA2A",
            "target": target,
            "isSharedToAll": True,
            "audience": audience,
            "Credentials": {},
            "metadata": {"ApiType": "Azure"},
        }
    }
    az("rest", "--method", "put", "--uri", url, "--headers", "Content-Type=application/json",
       "--body", json.dumps(body))  # fmt: skip


def create_agents(project: AIProjectClient, model: str, mcp_url: str) -> dict[str, Any]:
    """Create the three prompt agents and expose the target over incoming A2A."""
    connection = retry(lambda: project.connections.get(CONNECTION), attempts=30, delay_s=20)
    definitions = {
        CALLER_AGENT: PromptAgentDefinition(
            model=model,
            instructions=(
                "Send the user's message unchanged to the verdict agent with the A2A tool. "
                "Reply only with the JSON verdict it returns."
            ),
            tools=[
                A2ATool(a2a_version=A2AProtocolVersion.V1_0, project_connection_id=connection.id)
            ],
        ),
        TARGET_AGENT: PromptAgentDefinition(
            model=model,
            instructions="Reply with one short sentence that acknowledges the user's message.",
        ),
        MCP_AGENT: PromptAgentDefinition(
            model=model,
            instructions=(
                "Call the claim_hash tool with the user's JSON object as the claim. "
                "Reply only with the digest it returns."
            ),
            tools=[
                MCPTool(
                    server_label="claim_hash",
                    server_url=f"{mcp_url}/mcp",
                    require_approval="never",
                    allowed_tools=["claim_hash"],
                )
            ],
        ),
    }
    for name, definition in definitions.items():
        project.agents.create_version(agent_name=name, definition=definition)
    project.agents.update_details(
        agent_name=TARGET_AGENT,
        agent_endpoint=AgentEndpointConfig(
            protocol_configuration=ProtocolConfiguration(
                responses=ResponsesProtocolConfiguration(), a2a=A2AProtocolConfiguration()
            )
        ),
        agent_card=AgentCard(
            version="1.0",
            description="Acknowledges a message.",
            skills=[AgentCardSkill(id="acknowledge", name="Acknowledge")],
        ),
    )
    return {name: project.agents.get(name) for name in definitions}


@dataclass
class Environment:
    subscription: str
    account: str
    a2a_url: str
    mcp_url: str
    api_app_id: str
    caller: Caller
    card_public_jwk: dict[str, Any]
    project: AIProjectClient
    openai: OpenAI


def replicas(app: str) -> int:
    return len(az("containerapp", "replica", "list", "-n", app, "-g", GROUP) or [])


def wait_for_zero(app: str) -> None:
    started = time.monotonic()
    while replicas(app):
        if time.monotonic() - started > SCALE_TO_ZERO_DEADLINE_S:
            raise TimeoutError(f"{app} did not scale to zero")
        time.sleep(10)


async def timed[T](call: Awaitable[T]) -> tuple[float, T]:
    started = time.perf_counter()
    value = await call
    return (time.perf_counter() - started) * 1000, value


def respond(env: Environment, agent: str, text: str) -> tuple[float, str, int]:
    """One Responses call to a prompt agent; return latency, output text and total tokens."""
    started = time.perf_counter()
    response = env.openai.responses.create(
        input=text,
        tool_choice="required",
        extra_body={"agent_reference": {"name": agent, "type": "agent_reference"}},
    )
    elapsed = (time.perf_counter() - started) * 1000
    return elapsed, response.output_text, response.usage.total_tokens if response.usage else 0


def run_agent(
    env: Environment, agent: str, text: str, expect: Callable[[str], bool]
) -> ScenarioResult:
    """One cold and `WARM_CALLS` warm calls; cold means the downstream app started at zero."""
    calls = [respond(env, agent, text) for _ in range(WARM_CALLS + 1)]
    return {
        "ok": all(expect(output) for _, output, _ in calls),
        "latencies_ms": [latency for latency, _, _ in calls[1:]],
        "cold_ms": calls[0][0],
        "tokens": sum(tokens for _, _, tokens in calls),
    }


async def _client_to_server(env: Environment) -> ScenarioResult:
    client = _load("a2a_interop_client", "client/client.py")
    token = env.caller.credential.get_token(f"api://{env.api_app_id}/.default").token
    expected = {"claimHash": CLAIM_HASH, "verdict": "supported"}
    keys = {CARD_KID: env.card_public_jwk}
    async with httpx.AsyncClient(timeout=60) as http:

        async def first_contact() -> dict[str, Any]:
            card = await client.fetch_verified_card(env.a2a_url, keys, http)
            return await client.call_echo_verdict(card, CLAIM_HASH, token, http)

        cold_ms, first = await timed(first_contact())
        card = await client.fetch_verified_card(env.a2a_url, keys, http)
        warm = [
            await timed(client.call_echo_verdict(card, CLAIM_HASH, token, http))
            for _ in range(WARM_CALLS)
        ]
    return {
        "ok": first == expected and all(verdict == expected for _, verdict in warm),
        "latencies_ms": [latency for latency, _ in warm],
        "cold_ms": cold_ms,
        "tokens": None,
    }


def scenario_client_to_server(env: Environment) -> ScenarioResult:
    """Our client verifies the signed card and calls our A2A server with an app-role token."""
    wait_for_zero(A2A_APP)
    return asyncio.run(_client_to_server(env))


def scenario_foundry_to_server(env: Environment) -> ScenarioResult:
    """A Foundry prompt agent calls our A2A server through the `a2a` tool."""
    wait_for_zero(A2A_APP)
    return run_agent(
        env, CALLER_AGENT, CLAIM_HASH, lambda out: CLAIM_HASH in out and "supported" in out
    )


async def _client_to_foundry(env: Environment) -> ScenarioResult:
    token = env.caller.credential.get_token(f"{FOUNDRY_AUDIENCE}/.default").token
    base_url = foundry_a2a_base_url(env.account, PROJECT, TARGET_AGENT)
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(headers=headers, timeout=120) as http:
        card = await A2ACardResolver(http, base_url, FOUNDRY_CARD_PATH).get_agent_card()
        client = await create_client(card, ClientConfig(streaming=False, httpx_client=http))

        async def send() -> bool:
            request = SendMessageRequest(message=new_text_message(CLAIM_HASH, role=Role.ROLE_USER))
            replies = [r async for r in client.send_message(request)]
            return any(r.HasField("message") or r.HasField("task") for r in replies)

        calls = [await timed(send()) for _ in range(WARM_CALLS + 1)]
        await client.close()
    return {
        "ok": all(ok for _, ok in calls),
        "latencies_ms": [latency for latency, _ in calls[1:]],
        "cold_ms": calls[0][0],
        "tokens": None,
    }


def scenario_client_to_foundry(env: Environment) -> ScenarioResult:
    """Our client calls the Foundry agent's incoming A2A endpoint with an Entra token."""
    return asyncio.run(_client_to_foundry(env))


def scenario_foundry_to_mcp(env: Environment) -> ScenarioResult:
    """A Foundry prompt agent calls the `claim_hash` tool on our MCP server."""
    wait_for_zero(MCP_APP)
    return run_agent(env, MCP_AGENT, json.dumps(CLAIM), lambda out: CLAIM_HASH in out)


def agent_scope(env: Environment, agent: str) -> str:
    return (
        f"/subscriptions/{env.subscription}/resourceGroups/{GROUP}/providers"
        f"/Microsoft.CognitiveServices/accounts/{env.account}/projects/{PROJECT}/agents/{agent}"
    )


def foundry_card_status(env: Environment, token: str | None) -> int:
    url = f"{foundry_a2a_base_url(env.account, PROJECT, TARGET_AGENT)}/{FOUNDRY_CARD_PATH}"
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return httpx.get(url, headers=headers, timeout=60).status_code


def probe_rejections(env: Environment) -> dict[str, int]:
    """Status codes from the incoming endpoint before the caller holds Foundry Agent Consumer."""
    token = env.caller.credential.get_token(f"{FOUNDRY_AUDIENCE}/.default").token
    return {
        "missing_token": foundry_card_status(env, None),
        "missing_role": foundry_card_status(env, token),
    }


def wait_for_access(env: Environment) -> None:
    started = time.monotonic()
    token = env.caller.credential.get_token(f"{FOUNDRY_AUDIENCE}/.default").token
    while (status := foundry_card_status(env, token)) != httpx.codes.OK:
        if time.monotonic() - started > ACCESS_DEADLINE_S:
            raise TimeoutError(f"Foundry Agent Consumer did not take effect: {status}")
        time.sleep(20)


def record_identity(expected_oid: str) -> dict[str, Any]:
    """The caller identity the A2A server logged for the Foundry tool calls, typed by Graph."""
    logs = az("containerapp", "logs", "show", "-n", A2A_APP, "-g", GROUP, "--type", "console",
              "--tail", "300", "--format", "text", parse=False)  # fmt: skip
    callers = callers_from_logs(logs)
    if not callers:
        return {"oid": None, "appid": None, "type": None, "expected_oid": expected_oid}
    caller = callers[-1]
    entry = graph("GET", f"/directoryObjects/{caller['oid']}")
    return {
        **caller,
        "type": entry.get("@odata.type"),
        "service_principal_type": entry.get("servicePrincipalType"),
        "expected_oid": expected_oid,
        "distinct_callers": sorted({c["oid"] for c in callers}),
    }


def versions() -> dict[str, str]:
    return {name: importlib.metadata.version(name) for name in SDK_PACKAGES}


def main() -> dict[str, Any]:
    subscription = az("account", "show", "--query", "id")
    acr, account = names(subscription)
    tenant = az("account", "show", "--query", "tenantId")
    user = az("ad", "signed-in-user", "show", "--query", "id")
    phase("provision")
    identity_id = provision(acr)
    phase("build and push images")
    images = build_and_push(acr)
    phase("register Entra apps")
    api_app_id, api_principal, role_id = register_api()
    caller = register_caller(tenant)
    grant_app_role(caller.object_id, api_principal, role_id)
    private_jwk, public_jwk = card_keys()
    phase("deploy Foundry")
    foundry = deploy(
        FOUNDRY_MODULE, {"accountName": account, "projectName": PROJECT, "userPrincipalId": user}
    )
    phase("deploy container apps")
    apps = deploy(
        APPS_MODULE,
        {
            "acrLoginServer": f"{acr}.azurecr.io",
            "a2aImage": images["a2a-server"],
            "mcpImage": images["mcp-server"],
            "identityId": identity_id,
            "cardSigningJwk": json.dumps(private_jwk),
            "cardKid": CARD_KID,
            "entraTenantId": tenant,
            "entraAudience": api_app_id,
        },
    )
    phase("create connection and agents")
    create_connection(subscription, account, apps["a2aServerUrl"], f"api://{api_app_id}")
    project = AIProjectClient(endpoint=foundry["projectEndpoint"], credential=AzureCliCredential())
    agents = create_agents(project, foundry["modelDeployment"], apps["mcpServerUrl"])
    agent_oid = agents[CALLER_AGENT].instance_identity.principal_id
    grant_app_role(agent_oid, api_principal, role_id)
    phase("run scenarios")
    env = Environment(
        subscription=subscription,
        account=account,
        a2a_url=apps["a2aServerUrl"],
        mcp_url=apps["mcpServerUrl"],
        api_app_id=api_app_id,
        caller=caller,
        card_public_jwk=public_jwk,
        project=project,
        openai=project.get_openai_client(),
    )
    try:
        scenarios: dict[str, ScenarioResult] = {
            "client_to_server": scenario_client_to_server(env),
            "foundry_to_server": scenario_foundry_to_server(env),
        }
    except Exception:
        print(container_logs(A2A_APP), file=sys.stderr)
        raise
    identity = record_identity(agent_oid)
    rejections = probe_rejections(env)
    scope = agent_scope(env, TARGET_AGENT)
    assign_role(caller.object_id, AGENT_CONSUMER, scope)
    try:
        wait_for_access(env)
        scenarios["client_to_foundry"] = scenario_client_to_foundry(env)
    finally:
        subprocess.run(["az", "role", "assignment", "delete", "--assignee", caller.object_id,
                        "--role", AGENT_CONSUMER, "--scope", scope], check=False)  # fmt: skip
    scenarios["foundry_to_mcp"] = scenario_foundry_to_mcp(env)
    report = build_report(
        dict(scenarios), rejections=rejections, identity=identity, versions=versions()
    )
    print(json.dumps(report, indent=2))
    return report


def container_logs(app: str) -> str:
    result = subprocess.run(
        ["az", "containerapp", "logs", "show", "-g", GROUP, "-n", app, "--tail", "60"],
        check=False, capture_output=True, text=True,
    )  # fmt: skip
    return f"--- {app} logs ---\n{result.stdout or result.stderr}"


def teardown() -> None:
    """Delete the app registrations and the group, then purge the soft-deleted Foundry account."""
    for display_name in (API_APP, CALLER_APP):
        listed = subprocess.run(
            ["az", "ad", "app", "list", "--display-name", display_name, "--query", "[].id",
             "-o", "json"],
            check=False, capture_output=True, text=True,
        ).stdout  # fmt: skip
        for object_id in json.loads(listed or "[]"):
            subprocess.run(["az", "ad", "app", "delete", "--id", object_id], check=False)
    listed = subprocess.run(
        ["az", "cognitiveservices", "account", "list", "-g", GROUP, "--query", "[].name",
         "-o", "json"],
        check=False, capture_output=True, text=True,
    ).stdout  # fmt: skip
    accounts = json.loads(listed or "[]")
    blueprints = subprocess.run(
        ["az", "ad", "app", "list", "--filter", "startswith(displayName,'fourth-a2a-')",
         "--query", "[].id", "-o", "json"],
        check=False, capture_output=True, text=True,
    ).stdout  # fmt: skip
    for object_id in json.loads(blueprints or "[]"):
        subprocess.run(["az", "ad", "app", "delete", "--id", object_id], check=False)
    subprocess.run(["az", "group", "delete", "-n", GROUP, "-y"], check=False)
    for account in accounts:
        subprocess.run(["az", "cognitiveservices", "account", "purge", "-l", FOUNDRY_LOCATION,
                        "-g", GROUP, "-n", account], check=False)  # fmt: skip


if __name__ == "__main__":
    try:
        main()
    finally:
        teardown()
