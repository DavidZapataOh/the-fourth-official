"""Records live proof vectors: a Confidential Ledger receipt, a public RFC 3161 token and an
OpenTimestamps calendar stamp, each verified with `fourth_proofs`.

Run with `uv run python libs/proofs/py/scripts/live_run.py`. Requires an `az` session that can
create resource groups; the signed-in user becomes the ledger's data plane Administrator through
Microsoft Entra ID. The ledger is deleted at the end (ledger deletion is a hard delete, so there is
nothing to purge) and the saved receipt is verified again offline. The OpenTimestamps reference
client is LGPL-3.0 and runs as an external tool through `uvx`; it is never imported.
"""

import base64
import datetime
import hashlib
import importlib.metadata
import json
import re
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable, Mapping, MutableMapping
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

import httpx
from azure.confidentialledger import ConfidentialLedgerClient
from azure.confidentialledger.certificate import ConfidentialLedgerCertificateClient
from azure.confidentialledger.receipt import verify_receipt
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.core.polling import LROPoller
from azure.identity import AzureCliCredential
from fourth_crypto import canonicalize
from fourth_proofs import ProofError, ots_status, verify_ledger_receipt, verify_rfc3161
from rfc3161_client import HashAlgorithm, TimestampRequestBuilder, decode_timestamp_response

ROOT = Path(__file__).resolve().parents[4]
VECTORS = Path(__file__).resolve().parents[2] / "vectors"
LEDGER_LIVE = VECTORS / "ledger_receipt_live.json"
RFC3161_LIVE = VECTORS / "rfc3161_live.json"
OTS_LIVE = VECTORS / "ots_live.json"
PRE_LIVE = frozenset({"ledger_receipt.json", "rfc3161.json", "ots.json"})
MODULE = ROOT / "infra" / "modules" / "ledger.bicep"

GROUP = "rg-fourth-spike-proofs"
LOCATION = "eastus"
ARM_API = "2026-02-23"
DATA_PLANE_API = "2026-02-23"
LEDGER_NAME = re.compile(r"^[^-0-9][A-Za-z0-9-]{1,33}[A-Za-z0-9]$")
PRICES = "https://prices.azure.com/api/retail/prices"
DATA = "The Fourth Official RFC 3161 test vector"
CLAIM: dict[str, Any] = {
    "decision": "goal_stands",
    "incident": "m4-17",
    "match": "Harbour Town v Northbridge",
    "minute": 63,
    "review": "offside",
}
TSA = {
    "name": "FreeTSA",
    "url": "https://freetsa.org/tsr",
    "terms": "https://freetsa.org/freetsa.html",
    "ca_certificate_url": "https://freetsa.org/files/cacert.pem",
    "ca_certificate_sha256": "2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438",
    "tsa_certificate_url": "https://freetsa.org/files/tsa.crt",
    "tsa_certificate_sha256": "8bfb0305bb64e2571ca507552ef3245cb1c2fee8728e0ff8689225081ea13467",
}
OTS_CLIENT = "opentimestamps-client==0.7.2"
OTS = ("uvx", "--from", OTS_CLIENT, "ots")
ATTEMPTS = 12
STARTED = time.monotonic()
RUN_ID = uuid.uuid4().hex[:6]


def phase(name: str) -> None:
    print(f"[{time.monotonic() - STARTED:6.0f}s] {name}", file=sys.stderr, flush=True)


def az(*args: str) -> Any:
    result = subprocess.run(
        ["az", *args, "-o", "json"], check=False, capture_output=True, text=True
    )
    if result.returncode:
        raise RuntimeError(f"az {' '.join(args[:3])} failed: {result.stderr[-1500:]}")
    return json.loads(result.stdout) if result.stdout.strip() else None


def retry[T](action: Callable[[], T], attempts: int = ATTEMPTS, delay_s: float = 10) -> T:
    """Retry a data plane call until the new ledger accepts the administrator's token."""
    for attempt in range(attempts):
        try:
            return action()
        except (ClientAuthenticationError, HttpResponseError):
            if attempt == attempts - 1:
                raise
            time.sleep(delay_s)
    raise AssertionError("unreachable")


def ledger_name(run_id: str) -> str:
    """Globally unique ledger name; deleted names are not reused across runs."""
    name = f"fourth-proofs-{run_id}"
    if not LEDGER_NAME.fullmatch(name):
        raise ValueError(f"invalid ledger name: {name}")
    return name


def verdict_contents() -> str:
    """The ledger entry: the JCS-canonical verdict claim."""
    return canonicalize(CLAIM).decode()


def identity_endpoint(identity_service_uri: str) -> str:
    """Identity service base URL from the ledger's `identityServiceUri`."""
    parts = urlsplit(identity_service_uri)
    if parts.scheme != "https" or not parts.netloc:
        raise ValueError(f"unexpected identity service URI: {identity_service_uri}")
    return f"https://{parts.netloc}"


def hourly_price(items: list[dict[str, Any]], location: str) -> float | None:
    """Retail consumption price per hour of a Standard ledger in `location`."""
    for item in items:
        if (
            item.get("armRegionName") == location
            and item.get("meterName") == "Standard Instance"
            and item.get("type") == "Consumption"
            and item.get("unitOfMeasure") == "1 Hour"
        ):
            return float(item["retailPrice"])
    return None


def retail_price(location: str) -> float | None:
    query = f"serviceName eq 'Azure confidential ledger' and armRegionName eq '{location}'"
    response = httpx.get(PRICES, params={"$filter": query}, timeout=30)
    response.raise_for_status()
    return hourly_price(response.json()["Items"], location)


def deploy_ledger(name: str, principal_id: str) -> tuple[dict[str, str], float]:
    """Create the group and ledger; return the module outputs and the deployment seconds."""
    az("group", "create", "-n", GROUP, "-l", LOCATION)
    started = time.monotonic()
    result = az(
        "deployment", "group", "create", "-g", GROUP, "--template-file", str(MODULE),
        "--parameters", f"name={name}", f"location={LOCATION}", f"principalId={principal_id}",
    )  # fmt: skip
    seconds = time.monotonic() - started
    outputs = {k: v["value"] for k, v in result["properties"]["outputs"].items()}
    return outputs, seconds


def service_certificate(identity_service_uri: str, name: str) -> str:
    client = ConfidentialLedgerCertificateClient(identity_endpoint(identity_service_uri))
    return cast("str", client.get_ledger_identity(ledger_id=name)["ledgerTlsCertificate"])


def append_and_get_receipt(client: ConfidentialLedgerClient, contents: str) -> dict[str, Any]:
    """Append `contents`, wait for commit and return the receipt response with its claims."""
    create = cast(
        "Callable[[dict[str, str]], LROPoller[MutableMapping[str, Any]]]",
        client.begin_create_ledger_entry,  # pyright: ignore[reportUnknownMemberType]
    )
    entry = retry(lambda: create({"contents": contents}).result())
    transaction_id = cast("str", entry["transactionId"])
    response = dict(client.begin_get_receipt(transaction_id).result())
    claims = response.get("applicationClaims")
    if not claims:
        raise RuntimeError(f"receipt for {transaction_id} has no application claims")
    return response


def _flip_b64(text: str) -> str:
    raw = bytearray(base64.b64decode(text))
    raw[-1] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


def build_ledger_vectors(
    response: Mapping[str, Any], service_cert: str, *, source: str, ledger: Mapping[str, Any]
) -> dict[str, Any]:
    """Vector file for one live receipt: the valid case plus one rejection per layer."""
    receipt = cast("dict[str, Any]", response["receipt"])
    claims = cast("list[dict[str, Any]]", response["applicationClaims"])
    base = {
        "source": source,
        "receipt": receipt,
        "service_certificate": service_cert,
        "application_claims": claims,
    }
    index = next(i for i, claim in enumerate(claims) if claim["kind"] == "LedgerEntry")
    entry = claims[index]["ledgerEntry"]
    altered_claims = [*claims]
    altered_claims[index] = {**claims[index], "ledgerEntry": {**entry, "contents": "{}"}}

    def case(name: str, valid: bool, **changes: Any) -> dict[str, Any]:
        return {"name": f"live_receipt/{name}", **base, **changes, "valid": valid}

    return {
        "description": (
            "A receipt from a live Azure Confidential Ledger with the service identity "
            "certificate and application claims, saved before the ledger was deleted."
        ),
        "source": source,
        "ledger": dict(ledger),
        "claim": CLAIM,
        "bases": {"live_receipt": base},
        "cases": [
            case("valid", True),
            case("claims_contents_changed", False, application_claims=altered_claims),
            case(
                "signature_last_byte",
                False,
                receipt={**receipt, "signature": _flip_b64(receipt["signature"])},
            ),
            case("node_cert_as_service_certificate", False, service_certificate=receipt["cert"]),
        ],
    }


def save_vectors(path: Path, vectors: Mapping[str, Any]) -> None:
    """Write a live vector file and format it as the repository does; never a pre-live file."""
    if path.name in PRE_LIVE:
        raise ValueError(f"refusing to overwrite the pre-live vector file {path.name}")
    path.write_text(json.dumps(vectors, indent=2) + "\n", encoding="utf-8")
    subprocess.run(
        ["pnpm", "exec", "biome", "format", "--write", str(path)],
        cwd=ROOT, check=True, capture_output=True,
    )  # fmt: skip


def case_outcome(case: Mapping[str, Any]) -> bool:
    try:
        verify_ledger_receipt(
            case["receipt"],
            case["service_certificate"],
            application_claims=case["application_claims"],
        )
    except ProofError:
        return False
    return True


def verify_python(path: Path) -> dict[str, Any]:
    """Check every case of a saved vector file and time the valid one."""
    vectors = json.loads(path.read_text(encoding="utf-8"))
    cases = cast("list[dict[str, Any]]", vectors["cases"])
    matched = all(case_outcome(case) is case["valid"] for case in cases)
    valid = next(case for case in cases if case["valid"])
    try:
        verify_receipt(
            json.loads(json.dumps(valid["receipt"])),
            valid["service_certificate"],
            application_claims=json.loads(json.dumps(valid["application_claims"])),
        )
        azure_sdk = True
    except ValueError:
        azure_sdk = False
    timings: dict[str, float] = {}
    for runs in (1, 100):
        started = time.perf_counter()
        for _ in range(runs):
            case_outcome(valid)
        timings[f"ms_{runs}"] = round((time.perf_counter() - started) * 1000, 2)
    return {"matched": matched, "azure_sdk": azure_sdk, **timings}


def verify_typescript() -> bool:
    """Run the TypeScript live vector tests; true only if they ran and passed."""
    with tempfile.TemporaryDirectory() as directory:
        report = Path(directory) / "vitest.json"
        subprocess.run(
            ["pnpm", "vitest", "run", "--project", "@fourth/proofs", "-t", "live ledger vector",
             "--reporter=json", f"--outputFile={report}"],
            cwd=ROOT, check=False, capture_output=True,
        )  # fmt: skip
        if not report.exists():
            return False
        result = json.loads(report.read_text(encoding="utf-8"))
    return result["numFailedTests"] == 0 and result["numPassedTests"] >= 4  # noqa: PLR2004


def record_ledger(name: str, principal_id: str) -> dict[str, Any]:
    phase("deploy ledger")
    outputs, created_s = deploy_ledger(name, principal_id)
    phase("fetch service identity")
    service_cert = retry(lambda: service_certificate(outputs["identityServiceUri"], name))
    with tempfile.TemporaryDirectory() as directory:
        cert_path = Path(directory) / "ledger.pem"
        cert_path.write_text(service_cert, encoding="utf-8")
        client = ConfidentialLedgerClient(
            outputs["ledgerUri"],
            credential=AzureCliCredential(),
            ledger_certificate_path=str(cert_path),
            api_version=DATA_PLANE_API,
        )
        phase("append and get receipt")
        response = append_and_get_receipt(client, verdict_contents())
    sku = az("resource", "show", "-g", GROUP, "-n", name, "--resource-type",
             "Microsoft.ConfidentialLedger/ledgers", "--query", "properties.ledgerSku")  # fmt: skip
    ledger = {
        "name": name,
        "region": LOCATION,
        "sku": sku,
        "transaction_id": response["transactionId"],
        "recorded_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "arm_api_version": ARM_API,
        "data_plane_api_version": DATA_PLANE_API,
        "sdk": f"azure-confidentialledger {importlib.metadata.version('azure-confidentialledger')}",
    }
    source = (
        f"Azure Confidential Ledger {name} ({LOCATION}), Public, written with "
        f"{ledger['sdk']} at data plane API {DATA_PLANE_API} by libs/proofs/py/scripts/live_run.py"
    )
    save_vectors(
        LEDGER_LIVE, build_ledger_vectors(response, service_cert, source=source, ledger=ledger)
    )
    phase("verify before deletion")
    return {
        **ledger,
        "created_s": round(created_s, 1),
        "price_usd_per_hour": retail_price(LOCATION),
        "python_before_delete": verify_python(LEDGER_LIVE),
        "typescript_before_delete": verify_typescript(),
    }


def fetch(url: str, sha256_hex: str) -> bytes:
    response = httpx.get(url, timeout=30, follow_redirects=True)
    response.raise_for_status()
    if hashlib.sha256(response.content).hexdigest() != sha256_hex:
        raise RuntimeError(f"{url} does not match its published SHA-256")
    return response.content


def request_rfc3161() -> dict[str, Any]:
    """Timestamp the test data at the public authority and return the verified vector."""
    digest = hashlib.sha256(DATA.encode()).digest()
    root = fetch(TSA["ca_certificate_url"], TSA["ca_certificate_sha256"]).decode()
    authority = fetch(TSA["tsa_certificate_url"], TSA["tsa_certificate_sha256"]).decode()
    request = (
        TimestampRequestBuilder()
        .data(DATA.encode())
        .hash_algorithm(HashAlgorithm.SHA256)
        .cert_request(cert_request=True)
        .nonce(nonce=True)
        .build()
    )
    response = httpx.post(
        TSA["url"],
        content=request.as_bytes(),
        headers={"Content-Type": "application/timestamp-query"},
        timeout=30,
    )
    response.raise_for_status()
    token = response.content
    if decode_timestamp_response(token).tst_info.nonce != request.nonce:
        raise RuntimeError("timestamp response nonce does not match the request")
    started = time.perf_counter()
    info = verify_rfc3161(token, digest, [root])
    verify_ms = (time.perf_counter() - started) * 1000
    return {
        "source": f"{TSA['name']} {TSA['url']}, requested by libs/proofs/py/scripts/live_run.py",
        "authority": TSA,
        "data": DATA,
        "data_sha256": digest.hex(),
        "root_certificate": root,
        "authority_certificate": authority,
        "response": base64.b64encode(token).decode(),
        "size_bytes": len(token),
        "verify_ms": round(verify_ms, 2),
        "expected": {
            "signed_at": info.signed_at.isoformat(),
            "authority": info.authority,
            "serial": info.serial,
        },
    }


def stamp_ots() -> dict[str, Any]:
    """Stamp the test data on the public calendars and return the pending vector."""
    digest = hashlib.sha256(DATA.encode()).digest()
    with tempfile.TemporaryDirectory() as directory:
        data = Path(directory) / "imprint"
        data.write_text(DATA, encoding="utf-8")
        subprocess.run([*OTS, "stamp", str(data)], check=True, capture_output=True)
        proof = data.with_suffix(".ots").read_bytes()
    status = ots_status(proof, digest)
    return {
        "source": f"ots stamp ({OTS_CLIENT}) against the default public calendars",
        "stamped_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "data": DATA,
        "data_sha256": digest.hex(),
        "pending": {"proof": base64.b64encode(proof).decode(), "calendars": status.calendars},
        "upgrades": [],
    }


def teardown() -> bool:
    """Delete the group and wait; return whether it still exists."""
    subprocess.run(["az", "group", "delete", "-n", GROUP, "-y"], check=False)
    exists = subprocess.run(
        ["az", "group", "exists", "-n", GROUP], check=False, capture_output=True, text=True
    )
    return exists.stdout.strip() != "false"


def main() -> dict[str, Any]:
    principal_id = az("ad", "signed-in-user", "show", "--query", "id")
    phase("timestamp authority")
    timestamp = request_rfc3161()
    save_vectors(RFC3161_LIVE, timestamp)
    phase("calendars")
    stamp = stamp_ots()
    save_vectors(OTS_LIVE, stamp)
    try:
        ledger = record_ledger(ledger_name(RUN_ID), principal_id)
    finally:
        phase("teardown")
        deleted_at = time.monotonic()
        group_exists = teardown()
        delete_s = time.monotonic() - deleted_at
    phase("verify after deletion")
    report = {
        "date": datetime.date.today().isoformat(),
        "ledger": {
            **ledger,
            "delete_s": round(delete_s, 1),
            "python_after_delete": verify_python(LEDGER_LIVE),
            "typescript_after_delete": verify_typescript(),
        },
        "group_exists_after_teardown": group_exists,
        "rfc3161": {
            "authority": TSA["name"],
            "url": TSA["url"],
            "size_bytes": timestamp["size_bytes"],
            "verify_ms": timestamp["verify_ms"],
            "signed_at": timestamp["expected"]["signed_at"],
        },
        "ots": {"stamped_at": stamp["stamped_at"], "calendars": stamp["pending"]["calendars"]},
    }
    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    main()
