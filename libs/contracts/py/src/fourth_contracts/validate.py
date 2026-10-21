"""Validate instances against the published contract schemas."""

# pyright: reportUnknownMemberType=false

import json
from functools import cache
from pathlib import Path
from typing import Any, Literal, get_args

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ContractName = Literal[
    "event",
    "signed-batch",
    "claim",
    "verdict",
    "overlay-cue",
    "scene-package",
    "sealed-call",
    "certificate",
]

CONTRACT_NAMES: tuple[ContractName, ...] = get_args(ContractName)

_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"


class ContractError(ValueError):
    def __init__(self, contract: str, errors: list[str]) -> None:
        super().__init__(f"{contract}: {'; '.join(errors)}")
        self.contract = contract
        self.errors = errors


@cache
def _registry() -> Registry[Any]:
    resources: list[tuple[str, Resource[Any]]] = []
    for path in sorted(_SCHEMAS.glob("*.schema.json")):
        contents = json.loads(path.read_text())
        resources.append((contents["$id"], Resource.from_contents(contents, DRAFT202012)))
    registry: Registry[Any] = Registry()
    return registry.with_resources(resources)


@cache
def _validator(contract: ContractName) -> Draft202012Validator:
    schema = json.loads((_SCHEMAS / f"{contract}.schema.json").read_text())
    return Draft202012Validator(schema, registry=_registry())


def validate(contract: ContractName, instance: Any) -> None:
    errors = [
        f"{'/'.join(str(p) for p in error.absolute_path) or '<root>'}: {error.message}"
        for error in _validator(contract).iter_errors(instance)
    ]
    if errors:
        raise ContractError(contract, errors)
