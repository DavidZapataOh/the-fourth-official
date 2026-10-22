import json
import subprocess
from typing import Any

import pytest
from infra_helpers import INFRA, bicep_build, resources_of_type

MODULE = INFRA / "modules" / "ledger.bicep"
LEDGER_TYPE = "Microsoft.ConfidentialLedger/ledgers"
SECURE_TYPES = {"securestring", "secureobject"}


@pytest.fixture(scope="module")
def template() -> dict[str, Any]:
    return bicep_build(MODULE)


@pytest.fixture(scope="module")
def ledger(template: dict[str, Any]) -> dict[str, Any]:
    found = resources_of_type(template, LEDGER_TYPE)
    assert len(found) == 1
    return found[0]


def test_interface_matches_contract(template):
    assert set(template["parameters"]) == {"name", "location", "principalId"}
    assert set(template["outputs"]) == {"ledgerUri", "identityServiceUri"}


def test_ledger_is_public_on_a_stable_api_version(ledger):
    assert ledger["properties"]["ledgerType"] == "Public"
    assert not ledger["apiVersion"].endswith("-preview")


def test_deploying_principal_is_the_only_administrator(ledger):
    properties = ledger["properties"]
    assert properties["aadBasedSecurityPrincipals"] == [
        {
            "ledgerRoleName": "Administrator",
            "principalId": "[parameters('principalId')]",
            "tenantId": "[tenant().tenantId]",
        }
    ]
    assert "certBasedSecurityPrincipals" not in properties


def test_outputs_are_plain_endpoints_without_secrets(template):
    for name, output in template["outputs"].items():
        assert output["type"] == "string", name
        assert "list" not in output["value"].lower(), name
    assert "ledgerUri" in template["outputs"]["ledgerUri"]["value"]
    assert "identityServiceUri" in template["outputs"]["identityServiceUri"]["value"]
    for parameter in template["parameters"].values():
        assert parameter["type"].lower() not in SECURE_TYPES


def test_module_lints_clean():
    result = subprocess.run(
        ["az", "bicep", "lint", "--file", str(MODULE), "--diagnostics-format", "sarif"],
        check=True,
        capture_output=True,
        text=True,
    )
    findings = [r for run in json.loads(result.stdout)["runs"] for r in run.get("results", [])]
    assert findings == []
