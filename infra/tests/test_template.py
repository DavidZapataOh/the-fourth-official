import json
import re

from infra_helpers import INFRA, bicep_build, module_params, resolve, resources_of_type


def test_template_compiles_without_errors(compiled_template):
    assert compiled_template["$schema"]


def test_target_scope_is_subscription(compiled_template):
    assert "subscriptionDeploymentTemplate" in compiled_template["$schema"]


def test_resource_group_is_tagged(compiled_template):
    group = resources_of_type(compiled_template, "Microsoft.Resources/resourceGroups")[0]
    assert set(resolve(compiled_template, group["tags"])) >= {"azd-env-name", "project"}


def test_parameters_file_uses_azd_variables():
    parameters = json.loads((INFRA / "main.parameters.json").read_text())["parameters"]
    assert parameters["environmentName"]["value"] == "${AZURE_ENV_NAME}"
    assert parameters["location"]["value"] == "${AZURE_LOCATION}"


def test_every_module_reference_is_pinned():
    pattern = re.compile(r"module\s+\w+\s+'([^']+)'")
    references = [
        ref for path in INFRA.rglob("*.bicep") for ref in pattern.findall(path.read_text())
    ]
    registry = [ref for ref in references if ref.startswith("br/public:")]
    assert registry
    for ref in registry:
        assert re.fullmatch(r"br/public:avm/[a-z0-9/-]+:\d+\.\d+\.\d+", ref), ref


def test_registry_is_basic(compiled_template):
    assert module_params(compiled_template, "registry")["acrSku"] == "Basic"


def test_log_analytics_is_capped_and_short_lived(compiled_template):
    params = module_params(compiled_template, "logAnalytics")
    assert params["dailyQuotaGb"] == "1"
    assert params["dataRetention"] == 30


def test_container_apps_environment_is_public_and_consumption_only(compiled_template):
    params = module_params(compiled_template, "containerAppsEnvironment")
    assert params["publicNetworkAccess"] == "Enabled"
    assert params["zoneRedundant"] is False
    assert [p["workloadProfileType"] for p in params["workloadProfiles"]] == ["Consumption"]


def test_app_insights_is_workspace_based(compiled_template):
    params = module_params(compiled_template, "appInsights")
    assert params["workspaceResourceId"]
    assert params["retentionInDays"] == 30


def test_key_vault_is_premium_with_rbac(compiled_template):
    params = module_params(compiled_template, "keyVault")
    assert params["sku"] == "premium"
    assert params["enableRbacAuthorization"] is True
    assert params["softDeleteRetentionInDays"] == 7


def test_key_vault_purge_protection_is_parameterized(compiled_template):
    assert compiled_template["parameters"]["enablePurgeProtection"]["defaultValue"] is False
    assert "enablePurgeProtection" in str(module_params(compiled_template, "keyVault"))


def test_cosmos_is_serverless_and_entra_only(compiled_template):
    params = module_params(compiled_template, "cosmos")
    assert params["capacityMode"] == "Serverless"
    assert params["disableLocalAuthentication"] is True
    assert params["zoneRedundant"] is False
    assert params["backupPolicyContinuousTier"] == "Continuous7Days"


def test_cosmos_location_override(compiled_template):
    assert compiled_template["parameters"]["cosmosLocation"]["defaultValue"] == ""
    assert "cosmosLocation" in str(module_params(compiled_template, "cosmos")["location"])


def test_storage_is_private_and_local_redundant(compiled_template):
    params = module_params(compiled_template, "storage")
    assert params["skuName"] == "Standard_LRS"
    assert params["allowBlobPublicAccess"] is False
    assert params["allowSharedKeyAccess"] is False
    assert params["minimumTlsVersion"] == "TLS1_2"


def test_deploying_principal_has_cosmos_data_role(compiled_template):
    assignments = str(module_params(compiled_template, "cosmos")["sqlRoleAssignments"])
    assert "principalId" in assignments
    assert "Data Contributor" in assignments


EXPECTED_OUTPUTS = {
    "AZURE_RESOURCE_GROUP",
    "AZURE_CONTAINER_REGISTRY_ENDPOINT",
    "AZURE_CONTAINER_REGISTRY_NAME",
    "AZURE_KEY_VAULT_NAME",
    "AZURE_COSMOS_ENDPOINT",
    "AZURE_STORAGE_ACCOUNT",
    "HEALTH_URL",
}


def test_health_app_scales_to_zero_with_external_https_ingress(compiled_template):
    params = module_params(compiled_template, "healthApp")
    assert params["scaleSettings"] == {"minReplicas": 0, "maxReplicas": 1}
    assert params["ingressExternal"] is True
    assert params["ingressTargetPort"] == 80
    assert params["ingressAllowInsecure"] is False
    assert params["containers"][0]["image"].startswith("mcr.microsoft.com/")


def test_outputs_match_contract(compiled_template):
    assert set(compiled_template["outputs"]) == EXPECTED_OUTPUTS


def test_outputs_contain_no_secrets(compiled_template):
    for name, output in compiled_template["outputs"].items():
        assert output["type"] != "securestring", name
        assert not re.search(r"list(Keys|Connection|Secrets)", str(output["value"])), name


def budget_resource():
    template = bicep_build(INFRA / "modules" / "budget.bicep")
    return resources_of_type(template, "Microsoft.Consumption/budgets")[0]


def test_budget_has_three_notifications():
    notifications = budget_resource()["properties"]["notifications"].values()
    assert sorted((n["threshold"], n["thresholdType"], n["operator"]) for n in notifications) == [
        (50, "Actual", "GreaterThan"),
        (80, "Actual", "GreaterThan"),
        (100, "Forecasted", "GreaterThan"),
    ]


def test_budget_name_matches_existing_budget(compiled_template):
    assert module_params(compiled_template, "budget")["name"] == "fourth-credit-budget"


def test_budget_amount_is_converted_from_string(compiled_template):
    assert compiled_template["parameters"]["budgetAmount"]["type"] == "string"
    assert "int(" in str(module_params(compiled_template, "budget")["amount"])


def test_budget_dates_come_from_parameters():
    sources = [p.read_text() for p in INFRA.rglob("*.bicep")]
    assert not any("utcNow" in source for source in sources)


def test_no_literal_email_in_infrastructure_files():
    email = re.compile(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", re.IGNORECASE)
    files = [
        p for p in INFRA.rglob("*") if p.suffix in {".bicep", ".json"} and "tests" not in p.parts
    ]
    assert [p.name for p in files if email.search(p.read_text())] == []


def test_contact_email_comes_from_parameters_file():
    parameters = json.loads((INFRA / "main.parameters.json").read_text())["parameters"]
    assert parameters["budgetContactEmail"]["value"].startswith("${BUDGET_CONTACT_EMAIL")
