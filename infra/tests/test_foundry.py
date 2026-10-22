from typing import Any

import pytest
from infra_helpers import INFRA, bicep_build, resolve, resources_of_type

FOUNDRY = INFRA / "modules" / "foundry.bicep"
INTEROP = INFRA / "modules" / "interop-apps.bicep"
FOUNDRY_USER = "53ca6127-db72-4b80-b1b0-d745d6d5456d"
SECURE_TYPES = {"securestring", "secureobject"}


@pytest.fixture(scope="module")
def foundry() -> dict[str, Any]:
    return bicep_build(FOUNDRY)


@pytest.fixture(scope="module")
def interop() -> dict[str, Any]:
    return bicep_build(INTEROP)


def only(template: dict[str, Any], type_name: str) -> dict[str, Any]:
    found = resources_of_type(template, type_name)
    assert len(found) == 1, type_name
    return found[0]


def resolve_deep(template: dict[str, Any], value: Any) -> Any:
    value = resolve(template, value)
    if isinstance(value, dict):
        return {k: resolve_deep(template, v) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve_deep(template, v) for v in value]
    return value


def parameter_values(template: dict[str, Any], deployment: dict[str, Any]) -> dict[str, Any]:
    parameters = deployment["properties"]["parameters"]
    return {k: resolve_deep(template, v.get("value")) for k, v in parameters.items()}


def container_apps(template: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Parameters of each container-app module, keyed by the container name it runs."""
    apps = {}
    for deployment in resources_of_type(template, "Microsoft.Resources/deployments"):
        params = parameter_values(template, deployment)
        if "containers" in params:
            apps[params["containers"][0]["name"]] = params
    return apps


def assert_no_secret_outputs(template: dict[str, Any], *secret_params: str) -> None:
    for name, output in template["outputs"].items():
        assert output["type"].lower() not in SECURE_TYPES, name
        text = str(output.get("value", "")).lower()
        assert "listkeys" not in text, name
        for secret in secret_params:
            assert secret.lower() not in text, name


def test_foundry_account_is_ai_services_with_projects_and_entra_only(foundry):
    account = only(foundry, "Microsoft.CognitiveServices/accounts")
    assert account["kind"] == "AIServices"
    assert account["sku"]["name"] == "S0"
    assert account["identity"]["type"] == "SystemAssigned"
    properties = account["properties"]
    assert properties["allowProjectManagement"] is True
    assert properties["disableLocalAuth"] is True
    assert properties["customSubDomainName"] == "[parameters('accountName')]"
    assert properties["publicNetworkAccess"] == "Enabled"


def test_foundry_has_one_project_with_system_identity(foundry):
    project = only(foundry, "Microsoft.CognitiveServices/accounts/projects")
    assert project["identity"]["type"] == "SystemAssigned"


def test_foundry_deploys_only_gpt_5_mini_global_standard(foundry):
    deployment = only(foundry, "Microsoft.CognitiveServices/accounts/deployments")
    assert deployment["sku"]["name"] == "GlobalStandard"
    assert deployment["properties"]["model"]["format"] == "OpenAI"
    assert resolve(foundry, deployment["properties"]["model"]["name"]) == "gpt-5-mini"
    capacity = foundry["parameters"]["modelCapacity"]
    assert deployment["sku"]["capacity"] == "[parameters('modelCapacity')]"
    assert 1 <= capacity["defaultValue"] <= 50


def test_foundry_defaults_to_sweden_central(foundry):
    assert foundry["parameters"]["location"]["defaultValue"] == "swedencentral"


def test_foundry_outputs_match_contract_without_secrets(foundry):
    assert set(foundry["outputs"]) == {"projectEndpoint", "modelDeployment"}
    assert_no_secret_outputs(foundry)


def test_foundry_user_role_for_the_deployer_is_optional(foundry):
    assignment = only(foundry, "Microsoft.Authorization/roleAssignments")
    assert foundry["variables"]["foundryUserRoleId"] == FOUNDRY_USER
    assert "foundryUserRoleId" in assignment["properties"]["roleDefinitionId"]
    assert "userPrincipalId" in assignment["condition"]
    assert foundry["parameters"]["userPrincipalId"]["defaultValue"] == ""


def test_interop_apps_default_to_north_europe(interop):
    assert interop["parameters"]["location"]["defaultValue"] == "northeurope"


def test_interop_card_key_is_a_secure_parameter_without_default(interop):
    parameter = interop["parameters"]["cardSigningJwk"]
    assert parameter["type"] == "securestring"
    assert "defaultValue" not in parameter


def test_interop_outputs_match_contract_without_secrets(interop):
    assert set(interop["outputs"]) == {"a2aServerUrl", "mcpServerUrl"}
    assert_no_secret_outputs(interop, "cardSigningJwk")


def test_interop_runs_two_scale_to_zero_apps_on_8080(interop):
    apps = container_apps(interop)
    assert set(apps) == {"a2a-server", "mcp-server"}
    for params in apps.values():
        assert params["scaleSettings"]["minReplicas"] == 0
        assert params["scaleSettings"]["maxReplicas"] == 1
        assert params["scaleSettings"]["cooldownPeriod"] == "[parameters('cooldownPeriod')]"
        assert params["ingressExternal"] is True
        assert params["ingressAllowInsecure"] is False
        assert params["ingressTargetPort"] == 8080


def test_interop_pulls_images_with_the_user_assigned_identity(interop):
    for params in container_apps(interop).values():
        assert params["managedIdentities"] == {
            "userAssignedResourceIds": ["[parameters('identityId')]"]
        }
        assert params["registries"] == [
            {"server": "[parameters('acrLoginServer')]", "identity": "[parameters('identityId')]"}
        ]


def test_interop_images_come_from_parameters(interop):
    apps = container_apps(interop)
    assert apps["a2a-server"]["containers"][0]["image"] == "[parameters('a2aImage')]"
    assert apps["mcp-server"]["containers"][0]["image"] == "[parameters('mcpImage')]"


def test_interop_card_key_reaches_the_server_only_as_a_secret(interop):
    apps = container_apps(interop)
    server = apps["a2a-server"]
    assert server["secrets"] == [
        {"name": "card-signing-jwk", "value": "[parameters('cardSigningJwk')]"}
    ]
    env = {e["name"]: e for e in server["containers"][0]["env"]}
    assert env["CARD_SIGNING_JWK"] == {"name": "CARD_SIGNING_JWK", "secretRef": "card-signing-jwk"}
    for variable in env.values():
        assert "cardSigningJwk" not in str(variable.get("value", ""))
    assert "secrets" not in apps["mcp-server"]


def test_interop_server_validates_entra_tokens(interop):
    env = {
        e["name"]: e.get("value")
        for e in container_apps(interop)["a2a-server"]["containers"][0]["env"]
    }
    assert env["ENTRA_TENANT_ID"] == "[parameters('entraTenantId')]"
    assert env["ENTRA_AUDIENCE"] == "[parameters('entraAudience')]"
    assert env["CARD_KID"] == "[parameters('cardKid')]"
    assert "PUBLIC_URL" in env


def test_interop_environment_is_consumption_only(interop):
    deployments = resources_of_type(interop, "Microsoft.Resources/deployments")
    environments = [
        params
        for params in (parameter_values(interop, d) for d in deployments)
        if "workloadProfiles" in params
    ]
    assert len(environments) == 1
    profiles = environments[0]["workloadProfiles"]
    assert [p["workloadProfileType"] for p in profiles] == ["Consumption"]


def test_foundry_account_children_deploy_one_after_another(foundry):
    """The account rejects concurrent child operations with a request conflict."""
    deployment = only(foundry, "Microsoft.CognitiveServices/accounts/deployments")
    project_type = "Microsoft.CognitiveServices/accounts/projects"
    assert any(project_type in dependency for dependency in deployment.get("dependsOn", []))
