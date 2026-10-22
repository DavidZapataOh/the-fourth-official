import base64
import copy
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest
from azure.confidentialledger.receipt import verify_receipt
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from fourth_crypto import canonicalize
from fourth_proofs import ProofError, verify_ledger_receipt

VECTORS = cast(
    "dict[str, Any]",
    json.loads(
        (Path(__file__).resolve().parents[2] / "vectors" / "ledger_receipt.json").read_text(
            encoding="utf-8"
        )
    ),
)
BASES = cast("dict[str, dict[str, Any]]", VECTORS["bases"])
CASES = cast("list[dict[str, Any]]", VECTORS["cases"])


def outcome(case: dict[str, Any]) -> bool:
    try:
        verify_ledger_receipt(
            case["receipt"],
            case["service_certificate"],
            application_claims=case["application_claims"],
        )
    except ProofError:
        return False
    return True


def sdk_outcome(case: dict[str, Any]) -> bool:
    try:
        verify_receipt(
            copy.deepcopy(case["receipt"]),
            case["service_certificate"],
            application_claims=copy.deepcopy(case["application_claims"]),
        )
    except ValueError:
        return False
    return True


def cases_named(fragment: str) -> list[dict[str, Any]]:
    selected = [case for case in CASES if fragment in case["name"]]
    assert selected, fragment
    return selected


def flip(data: bytes, index: int) -> bytes:
    out = bytearray(data)
    out[index] ^= 0x01
    return bytes(out)


def pem(der: bytes) -> str:
    body = base64.b64encode(der).decode()
    lines = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"


def single_byte_changes(receipt: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    """Every receipt that differs from `receipt` in exactly one byte of one verified field."""

    def changed(path: str, value: str) -> dict[str, Any]:
        out = copy.deepcopy(receipt)
        target: Any = out
        *parents, last = path.split(".")
        for part in parents:
            target = target[int(part)] if part.isdigit() else target[part]
        target[int(last) if last.isdigit() else last] = value
        return out

    leaf = receipt["leafComponents"]
    hex_fields = {
        f"leafComponents.{name}": leaf[name] for name in ("writeSetDigest", "claimsDigest")
    }
    hex_fields["nodeId"] = receipt["nodeId"]
    for index, element in enumerate(receipt["proof"]):
        ((side, value),) = element.items()
        hex_fields[f"proof.{index}.{side}"] = value
    for path, value in hex_fields.items():
        raw = bytes.fromhex(value)
        for i in range(len(raw)):
            yield f"{path}[{i}]", changed(path, flip(raw, i).hex())
    evidence = leaf["commitEvidence"].encode()
    for i in range(len(evidence)):
        yield (
            f"commitEvidence[{i}]",
            changed("leafComponents.commitEvidence", flip(evidence, i).decode()),
        )
    signature = base64.b64decode(receipt["signature"])
    for i in range(len(signature)):
        yield f"signature[{i}]", changed("signature", base64.b64encode(flip(signature, i)).decode())
    der = x509.load_pem_x509_certificate(receipt["cert"].encode()).public_bytes(Encoding.DER)
    for i in range(len(der)):
        yield f"cert[{i}]", changed("cert", pem(flip(der, i)))


def test_valid_receipt_verifies():
    for name, base in BASES.items():
        verify_ledger_receipt(
            base["receipt"],
            base["service_certificate"],
            application_claims=base["application_claims"],
        )
        assert name


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_vector_outcome(case: dict[str, Any]):
    assert outcome(case) is case["valid"]


@pytest.mark.parametrize("base", ["azure_sdk_receipt_1", "synthetic_receipt_with_endorsement"])
def test_every_single_byte_change_is_rejected(base: str):
    service_cert = BASES[base]["service_certificate"]
    accepted = [
        label
        for label, receipt in single_byte_changes(BASES[base]["receipt"])
        if outcome(
            {"receipt": receipt, "service_certificate": service_cert, "application_claims": None}
        )
    ]
    assert accepted == []


def test_every_mutated_vector_is_rejected():
    families = ("leaf_", "proof_", "signature_", "node_cert_", "node_id_byte")
    mutated = [case for case in CASES if any(f"/{family}" in case["name"] for family in families)]
    assert len(mutated) >= 4 * 16
    assert not any(outcome(case) for case in mutated)


def test_wrong_service_certificate_is_rejected():
    for case in cases_named("wrong_service_certificate") + cases_named("as_service_certificate"):
        assert not outcome(case), case["name"]


def test_broken_endorsement_chain_is_rejected():
    for case in cases_named("/endorsement"):
        assert not outcome(case), case["name"]


def test_application_claims_must_hash_to_the_claims_digest():
    claims_cases = cases_named("/claims_")
    assert {case["valid"] for case in claims_cases} == {True, False}
    for case in claims_cases:
        assert outcome(case) is case["valid"], case["name"]


def test_claims_check_runs_before_the_signature_check():
    base = BASES["azure_sdk_receipt_with_claims"]
    with pytest.raises(ProofError, match="claims"):
        verify_ledger_receipt(
            base["receipt"],
            BASES["azure_sdk_receipt_1"]["service_certificate"],
            application_claims=cases_named("claims_0_contents_byte")[0]["application_claims"],
        )


def test_malformed_receipts_raise_proof_error():
    receipt = BASES["azure_sdk_receipt_1"]["receipt"]
    service_cert = BASES["azure_sdk_receipt_1"]["service_certificate"]
    for broken in (
        {},
        {**receipt, "proof": [{"left": receipt["proof"][0]["left"], "extra": "x"}]},
        {**receipt, "leafComponents": {**receipt["leafComponents"], "extra": "x"}},
        {**receipt, "signature": "not base64!"},
        {**receipt, "nodeId": None},
    ):
        with pytest.raises(ProofError):
            verify_ledger_receipt(broken, service_cert)


def test_python_matches_azure_sdk_verify_receipt_on_all_vectors():
    differ = [case["name"] for case in CASES if "azure_sdk_valid" in case]
    assert all(name.endswith("signature_unused_bits_byte") for name in differ)
    assert [
        case["name"]
        for case in CASES
        if sdk_outcome(case) is not case.get("azure_sdk_valid", case["valid"])
    ] == []
    assert len(differ) == 4


LIVE_PATH = Path(__file__).resolve().parents[2] / "vectors" / "ledger_receipt_live.json"
LIVE = cast(
    "dict[str, Any]",
    json.loads(LIVE_PATH.read_text(encoding="utf-8")) if LIVE_PATH.exists() else {"cases": []},
)
LIVE_CASES = cast("list[dict[str, Any]]", LIVE["cases"])


@pytest.mark.parametrize("case", LIVE_CASES, ids=[case["name"] for case in LIVE_CASES])
def test_live_vector_outcome(case: dict[str, Any]):
    assert outcome(case) is case["valid"]


@pytest.mark.skipif(not LIVE_CASES, reason="no live ledger vector recorded")
def test_live_vector_claims_carry_the_canonical_verdict():
    (base,) = LIVE["bases"].values()
    claim = next(c for c in base["application_claims"] if c["kind"] == "LedgerEntry")
    assert claim["ledgerEntry"]["contents"] == canonicalize(LIVE["claim"]).decode()
    assert {case["valid"] for case in LIVE_CASES} == {True, False}
