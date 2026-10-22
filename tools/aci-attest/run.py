"""Deploys the attestation demo to a confidential container group and verifies its token.

Run with `uv run python tools/aci-attest/run.py`. Requires Docker, the Azure CLI with the
`confcom` extension and an authenticated `az` session.
"""

import hashlib
import json
import re
import statistics
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from fourth_attestation import policy_hash, verify_maa_token

ROOT = Path(__file__).resolve().parents[2]
APP_DIR = Path(__file__).resolve().parent / "app"
MODULE = ROOT / "infra" / "modules" / "confidential-aci.bicep"

CLI_IMAGE = "mcr.microsoft.com/azure-cli:latest"
PARAMETERS_SCHEMA = (
    "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#"
)
GROUP = "rg-fourth-spike-aci"
LOCATION = "northeurope"
MAA_HOST = "sharedneu.neu.attest.azure.net"
SKR_REFERENCE = "mcr.microsoft.com/aci/skr:2.12"
DECOY_REFERENCE = "docker.io/library/python:3.13-slim-bookworm"
APP_REPOSITORY = "attest-demo"
IDENTITY = "id-attest-demo"
CONTAINER_GROUP = "attest-demo"
RUNS = 3
TOKEN_DEADLINE_S = 300
TAMPER_DEADLINE_S = 90
PINNED_IMAGE = re.compile(r"@sha256:[0-9a-f]{64}$")
ROLE_ATTEMPTS = 6


def az(*args: str, parse: bool = True) -> Any:
    result = subprocess.run(["az", *args, "-o", "json"], check=True, capture_output=True, text=True)
    return json.loads(result.stdout) if parse and result.stdout.strip() else result.stdout


def sh(*args: str) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def assert_images_pinned(template: dict[str, Any]) -> None:
    """Raise unless every container image in the compiled template is pinned by digest."""
    for resource in template["resources"]:
        for container in resource.get("properties", {}).get("containers", []):
            image = container["properties"]["image"]
            if not PINNED_IMAGE.search(image):
                raise ValueError(f"image is not pinned by digest: {image}")


def registry_name() -> str:
    subscription = az("account", "show")["id"]
    return "fourthaci" + hashlib.sha256(subscription.encode()).hexdigest()[:8]


def provision(acr: str) -> str:
    """Create the group, registry and pull identity; return the identity resource ID."""
    az("group", "create", "-n", GROUP, "-l", LOCATION)
    az("acr", "create", "-g", GROUP, "-n", acr, "--sku", "Basic", "--admin-enabled", "false")
    identity = az("identity", "create", "-g", GROUP, "-n", IDENTITY)
    registry_id = az("acr", "show", "-n", acr, "--query", "id")
    for attempt in range(ROLE_ATTEMPTS):
        try:
            az(
                "role", "assignment", "create", "--assignee-object-id", identity["principalId"],
                "--assignee-principal-type", "ServicePrincipal", "--role", "AcrPull",
                "--scope", registry_id,
            )  # fmt: skip
            break
        except subprocess.CalledProcessError:
            if attempt == ROLE_ATTEMPTS - 1:
                raise
            time.sleep(10)
    return identity["id"]


def amd64_digest(reference: str) -> str:
    """Digest of the linux/amd64 manifest, which is what the policy and the host both resolve."""
    index = json.loads(sh("docker", "buildx", "imagetools", "inspect", "--raw", reference))
    for manifest in index.get("manifests", []):
        platform = manifest.get("platform", {})
        if platform.get("os") == "linux" and platform.get("architecture") == "amd64":
            return manifest["digest"]
    if "manifests" in index:
        raise RuntimeError(f"no linux/amd64 manifest for {reference}")
    manifest = sh(
        "docker", "buildx", "imagetools", "inspect", "--format", "{{json .Manifest}}", reference
    )
    return json.loads(manifest)["digest"]


def build_and_push(acr: str) -> dict[str, str]:
    """Build and push the demo image; return image repositories mapped to their digests."""
    server = f"{acr}.azurecr.io"
    sh("az", "acr", "login", "-n", acr)
    reference = f"{server}/{APP_REPOSITORY}:1"
    sh("docker", "build", "--platform", "linux/amd64", "-t", reference, str(APP_DIR))
    sh("docker", "push", reference)
    digest = az("acr", "repository", "show", "-n", acr, "--image", f"{APP_REPOSITORY}:1",
                "--query", "digest")  # fmt: skip
    return {
        f"{server}/{APP_REPOSITORY}": digest,
        SKR_REFERENCE.rpartition(":")[0]: amd64_digest(SKR_REFERENCE),
    }


def compile_template() -> dict[str, Any]:
    return json.loads(sh("az", "bicep", "build", "--file", str(MODULE), "--stdout"))


def generate_policy(template: dict[str, Any], values: dict[str, str]) -> str:
    """Return the base64 CCE policy for the images the template references.

    `confcom` has no macOS build, so it always runs in the Azure CLI container on the host's
    Docker daemon, where the images are pulled and hashed.
    """
    parameters = {k: {"value": v} for k, v in values.items()}
    with tempfile.TemporaryDirectory() as directory:
        (Path(directory) / "template.json").write_text(json.dumps(template))
        (Path(directory) / "parameters.json").write_text(
            json.dumps(
                {
                    "$schema": PARAMETERS_SCHEMA,
                    "contentVersion": "1.0.0.0",
                    "parameters": parameters,
                }
            )
        )
        command = (
            "az extension add -n confcom -y -o none && "
            "az confcom acipolicygen -a template.json --parameters parameters.json "
            "--print-policy -y"
        )
        result = subprocess.run(
            ["docker", "run", "--rm", "--platform", "linux/amd64",
             "-v", "/var/run/docker.sock:/var/run/docker.sock",
             "-v", f"{directory}:/work", "-w", "/work", CLI_IMAGE, "sh", "-c", command],
            check=False, capture_output=True, text=True,
        )  # fmt: skip
    if result.returncode:
        raise RuntimeError(f"confcom failed: {result.stderr[-2000:]}")
    return result.stdout.strip().splitlines()[-1]


def deploy(parameters: dict[str, str]) -> str:
    """Create the container group and return its public IP."""
    result = az("deployment", "group", "create", "-g", GROUP, "--template-file", str(MODULE),
                "--parameters", *[f"{k}={v}" for k, v in parameters.items()])  # fmt: skip
    return result["properties"]["outputs"]["ipAddress"]["value"]


def fetch_token(ip: str) -> str:
    with urllib.request.urlopen(f"http://{ip}:8080/token", timeout=30) as response:
        return json.load(response)["token"]


def diagnostics() -> str:
    """Container states and logs of the group, for failures."""
    state = subprocess.run(
        ["az", "container", "show", "-g", GROUP, "-n", CONTAINER_GROUP, "--query",
         "{state:instanceView.state,containers:containers[].{name:name,state:instanceView.currentState,"
         "events:instanceView.events}}", "-o", "json"],
        check=False, capture_output=True, text=True,
    ).stdout  # fmt: skip
    logs = [
        subprocess.run(
            ["az", "container", "logs", "-g", GROUP, "-n", CONTAINER_GROUP, "--container-name", c],
            check=False,
            capture_output=True,
            text=True,
        ).stdout[-1500:]  # fmt: skip
        for c in ("app", "skr")
    ]
    return "\n".join([state, *logs])


def wait_for_token(ip: str, started: float, deadline_s: float = TOKEN_DEADLINE_S) -> str:
    delay = 2.0
    last_error = ""
    while time.monotonic() - started < deadline_s:
        try:
            return fetch_token(ip)
        except urllib.error.HTTPError as error:
            last_error = f"{error.code}: {error.read(2000).decode(errors='replace')}"
        except (urllib.error.URLError, OSError, KeyError, ValueError) as error:
            last_error = str(error)
        time.sleep(delay)
        delay = min(delay * 1.5, 10)
    raise TimeoutError(f"no token before the deadline; last error {last_error}\n{diagnostics()}")


def delete_group_instance() -> None:
    subprocess.run(["az", "container", "delete", "-g", GROUP, "-n", CONTAINER_GROUP, "-y"],
                   check=False, capture_output=True)  # fmt: skip


def measure(
    parameters: dict[str, str], jwks: dict[str, Any], expected_hostdata: str
) -> dict[str, Any]:
    started = time.monotonic()
    ip = deploy(parameters)
    running = time.monotonic() - started
    token = wait_for_token(ip, started)
    ready = time.monotonic() - started
    claims = verify_maa_token(
        token, jwks, issuer=f"https://{MAA_HOST}", expected_hostdata=expected_hostdata
    )
    delete_group_instance()
    return {
        "created_to_running_s": round(running, 1),
        "created_to_token_s": round(ready, 1),
        "hostdata": claims.hostdata,
    }


def tamper(parameters: dict[str, str], other_policy: str, jwks: dict[str, Any]) -> dict[str, str]:
    """Deploy with a policy generated for a different image and report what happens."""
    try:
        ip = deploy({**parameters, "ccePolicy": other_policy})
    except subprocess.CalledProcessError:
        return {"outcome": "group_failed"}
    try:
        token = wait_for_token(ip, time.monotonic(), TAMPER_DEADLINE_S)
    except TimeoutError:
        return {"outcome": "no_token"}
    finally:
        delete_group_instance()
    claims = verify_maa_token(
        token, jwks, issuer=f"https://{MAA_HOST}", expected_hostdata=policy_hash(other_policy)
    )
    return {"outcome": "hostdata_differs", "hostdata": claims.hostdata}


def teardown() -> None:
    subprocess.run(["az", "group", "delete", "-n", GROUP, "-y", "--no-wait"], check=False)


def main() -> dict[str, Any]:
    acr = registry_name()
    identity_id = provision(acr)
    digests = build_and_push(acr)
    app_image, skr_image = (f"{repo}@{digest}" for repo, digest in digests.items())
    values = {
        "name": CONTAINER_GROUP,
        "location": LOCATION,
        "acrLoginServer": f"{acr}.azurecr.io",
        "appImage": app_image,
        "skrImage": skr_image,
        "identityId": identity_id,
        "maaEndpoint": f"https://{MAA_HOST}",
    }
    assert_images_pinned(
        {"resources": [{"properties": {"containers": [
            {"properties": {"image": app_image}}, {"properties": {"image": skr_image}}
        ]}}]}
    )  # fmt: skip
    template = compile_template()
    policy = generate_policy(template, values)
    decoy_image = f"{DECOY_REFERENCE.rpartition(':')[0]}@{amd64_digest(DECOY_REFERENCE)}"
    decoy_policy = generate_policy(template, {**values, "appImage": decoy_image})
    parameters = {**values, "ccePolicy": policy}
    with urllib.request.urlopen(f"https://{MAA_HOST}/certs", timeout=30) as response:
        jwks = json.load(response)
    expected = policy_hash(policy)
    runs = [measure(parameters, jwks, expected) for _ in range(RUNS)]
    result = {
        "region": LOCATION,
        "maa_endpoint": MAA_HOST,
        "policy_hash": expected,
        "hostdata": runs[0]["hostdata"],
        "verified": all(r["hostdata"] == expected for r in runs),
        "sidecar_digest": digests[SKR_REFERENCE.rpartition(":")[0]],
        "runs": runs,
        "median_created_to_running_s": statistics.median(r["created_to_running_s"] for r in runs),
        "median_created_to_token_s": statistics.median(r["created_to_token_s"] for r in runs),
        "tamper": tamper(parameters, decoy_policy, jwks),
    }
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    try:
        main()
    finally:
        teardown()
