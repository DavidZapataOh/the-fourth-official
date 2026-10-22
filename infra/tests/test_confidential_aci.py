import re
from typing import Any

import pytest
from infra_helpers import INFRA, bicep_build, resources_of_type

MODULE = INFRA / "modules" / "confidential-aci.bicep"


def number(value: Any) -> float:
    """Numeric literal, or the `[json('0.5')]` expression Bicep emits for fractions."""
    match = re.fullmatch(r"\[json\('([\d.]+)'\)\]", value) if isinstance(value, str) else None
    return float(match.group(1)) if match else float(value)


@pytest.fixture(scope="module")
def template() -> dict[str, Any]:
    return bicep_build(MODULE)


@pytest.fixture(scope="module")
def group(template: dict[str, Any]) -> dict[str, Any]:
    return resources_of_type(template, "Microsoft.ContainerInstance/containerGroups")[0]


def test_group_is_confidential_with_policy_parameter(group):
    properties = group["properties"]
    assert properties["sku"] == "Confidential"
    assert properties["osType"] == "Linux"
    assert properties["confidentialComputeProperties"]["ccePolicy"] == "[parameters('ccePolicy')]"


def test_interface_matches_contract(template):
    parameters = template["parameters"]
    assert set(parameters) == {
        "name",
        "location",
        "acrLoginServer",
        "appImage",
        "skrImage",
        "identityId",
        "ccePolicy",
        "maaEndpoint",
    }
    assert parameters["ccePolicy"]["defaultValue"] == ""
    assert set(template["outputs"]) == {"ipAddress"}


def test_single_public_port_8080(group):
    address = group["properties"]["ipAddress"]
    assert address["type"] == "Public"
    assert address["ports"] == [{"port": 8080, "protocol": "TCP"}]


def test_two_containers_with_one_vcpu_and_two_gb_in_total(group):
    containers = group["properties"]["containers"]
    assert len(containers) == 2
    requests = [c["properties"]["resources"]["requests"] for c in containers]
    assert sum(number(r["cpu"]) for r in requests) == 1
    assert sum(number(r["memoryInGB"]) for r in requests) == 2


def test_no_secret_values_in_environment(group):
    for container in group["properties"]["containers"]:
        for variable in container["properties"].get("environmentVariables", []):
            assert "secureValue" not in variable, variable["name"]


def test_acr_pull_uses_managed_identity(group, template):
    credentials = group["properties"]["imageRegistryCredentials"]
    assert credentials
    for credential in credentials:
        assert credential["identity"] == "[parameters('identityId')]"
        assert "password" not in credential
        assert "username" not in credential
    assert group["identity"]["type"] == "UserAssigned"
    assert "identityId" in str(group["identity"]["userAssignedIdentities"])
    assert template["parameters"]["identityId"]["type"] == "string"
