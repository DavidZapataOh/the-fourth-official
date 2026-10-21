import json
from pathlib import Path
from typing import Any

import pytest
from fourth_contracts import CONTRACT_NAMES, ContractError, ContractName, validate

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def cases(kind: str) -> list[tuple[ContractName, Path]]:
    return [
        (contract, path)
        for contract in CONTRACT_NAMES
        for path in sorted((FIXTURES / contract / kind).glob("*.json"))
    ]


def load(path: Path) -> Any:
    return json.loads(path.read_text())


@pytest.mark.parametrize(("contract", "path"), cases("valid"), ids=lambda v: getattr(v, "stem", v))
def test_valid_fixture_passes(contract: ContractName, path: Path):
    validate(contract, load(path))


@pytest.mark.parametrize(
    ("contract", "path"), cases("invalid"), ids=lambda v: getattr(v, "stem", v)
)
def test_invalid_fixture_is_rejected(contract: ContractName, path: Path):
    with pytest.raises(ContractError) as raised:
        validate(contract, load(path))
    assert raised.value.contract == contract
    assert raised.value.errors


def count(contract: str, kind: str) -> int:
    return len(list((FIXTURES / contract / kind).glob("*.json")))


@pytest.mark.parametrize("contract", CONTRACT_NAMES)
def test_every_contract_has_fixtures(contract: ContractName):
    assert count(contract, "valid") >= 1
    assert count(contract, "invalid") >= 3


def test_signed_batch_count_is_not_enforced_by_schema():
    batch = load(FIXTURES / "signed-batch" / "valid" / "count-not-enforced.json")
    assert batch["header"]["count"] != len(batch["events"])
    validate("signed-batch", batch)


@pytest.mark.parametrize(
    ("contract", "name"),
    [
        ("signed-batch", "digest-uppercase"),
        ("signed-batch", "digest-no-prefix"),
        ("signed-batch", "signature-short"),
        ("verdict", "timestamp-with-offset"),
        ("sealed-call", "nonce-wrong-length"),
        ("overlay-cue", "credential-status-disputed"),
    ],
)
def test_named_malformed_fixture_is_rejected(contract: ContractName, name: str):
    path = FIXTURES / contract / "invalid" / f"{name}.json"
    with pytest.raises(ContractError):
        validate(contract, load(path))
