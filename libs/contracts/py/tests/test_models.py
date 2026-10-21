import json
from pathlib import Path

import pydantic
import pytest
from fourth_contracts import CONTRACT_NAMES, MODELS, ContractName

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def cases(kind: str) -> list[tuple[ContractName, Path]]:
    return [
        (contract, path)
        for contract in CONTRACT_NAMES
        for path in sorted((FIXTURES / contract / kind).glob("*.json"))
    ]


@pytest.mark.parametrize(("contract", "path"), cases("valid"), ids=lambda v: getattr(v, "stem", v))
def test_models_round_trip_valid_fixtures(contract: ContractName, path: Path):
    data = json.loads(path.read_text())
    model = MODELS[contract].model_validate(data)
    assert model.model_dump(mode="json", by_alias=True, exclude_none=True) == data


@pytest.mark.parametrize(
    ("contract", "path"), cases("invalid"), ids=lambda v: getattr(v, "stem", v)
)
def test_models_reject_invalid_fixtures(contract: ContractName, path: Path):
    with pytest.raises(pydantic.ValidationError):
        MODELS[contract].model_validate(json.loads(path.read_text()))
