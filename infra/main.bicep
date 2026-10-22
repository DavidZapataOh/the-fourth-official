targetScope = 'subscription'

@minLength(1)
@maxLength(64)
@description('Name of the azd environment, used to derive resource names and tags.')
param environmentName string

@minLength(1)
@description('Primary Azure region for all resources.')
param location string

@description('Object ID of the deploying principal; receives data-plane access to Cosmos DB.')
param principalId string = ''

@description('Region for Cosmos DB when it needs to differ from the primary region (capacity). Empty uses the primary region.')
param cosmosLocation string = ''

@description('Keep deleted Key Vaults reserved for the retention period. Leave off while the environment is torn down and recreated.')
param enablePurgeProtection bool = false

@description('Email that receives budget alerts. Empty skips creating the budget.')
param budgetContactEmail string = ''

@description('Monthly budget amount in the billing currency.')
param budgetAmount string = '200'

@description('First day of the budget period (yyyy-MM-dd), the first of a month.')
param budgetStartDate string = '2026-10-01'

@description('Last day of the budget period (yyyy-MM-dd).')
param budgetEndDate string = '2026-12-31'

var tags = {
  'azd-env-name': environmentName
  project: 'fourth'
}

var resourceToken = toLower(uniqueString(subscription().id, environmentName, location))

resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: 'rg-${environmentName}'
  location: location
  tags: tags
}

module logAnalytics 'br/public:avm/res/operational-insights/workspace:0.16.1' = {
  scope: rg
  params: {
    name: 'log-${resourceToken}'
    location: location
    tags: tags
    dataRetention: 30
    dailyQuotaGb: '1'
  }
}

module appInsights 'br/public:avm/res/insights/component:0.8.0' = {
  scope: rg
  params: {
    name: 'appi-${resourceToken}'
    location: location
    tags: tags
    workspaceResourceId: logAnalytics.outputs.resourceId
    retentionInDays: 30
  }
}

module keyVault 'br/public:avm/res/key-vault/vault:0.14.2' = {
  scope: rg
  params: {
    name: 'kv-${resourceToken}'
    location: location
    tags: tags
    sku: 'premium'
    enableRbacAuthorization: true
    enablePurgeProtection: enablePurgeProtection
    softDeleteRetentionInDays: 7
  }
}

module cosmos 'br/public:avm/res/document-db/database-account:0.21.1' = {
  scope: rg
  params: {
    name: 'cosmos-${resourceToken}'
    location: empty(cosmosLocation) ? location : cosmosLocation
    tags: tags
    capacityMode: 'Serverless'
    disableLocalAuthentication: true
    zoneRedundant: false
    backupPolicyContinuousTier: 'Continuous7Days'
    sqlRoleAssignments: empty(principalId)
      ? []
      : [
          {
            principalId: principalId
            roleDefinitionId: 'Cosmos DB Built-in Data Contributor'
          }
        ]
  }
}

module storage 'br/public:avm/res/storage/storage-account:0.33.1' = {
  scope: rg
  params: {
    name: 'st${resourceToken}'
    location: location
    tags: tags
    skuName: 'Standard_LRS'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
  }
}

module registry 'br/public:avm/res/container-registry/registry:0.13.1' = {
  scope: rg
  params: {
    name: 'cr${resourceToken}'
    location: location
    tags: tags
    acrSku: 'Basic'
    zoneRedundancy: 'Disabled'
  }
}

module containerAppsEnvironment 'br/public:avm/res/app/managed-environment:0.16.0' = {
  scope: rg
  params: {
    name: 'cae-${resourceToken}'
    location: location
    tags: tags
    publicNetworkAccess: 'Enabled'
    zoneRedundant: false
    workloadProfiles: [
      {
        name: 'Consumption'
        workloadProfileType: 'Consumption'
      }
    ]
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsWorkspaceResourceId: logAnalytics.outputs.resourceId
    }
  }
}

module budget 'modules/budget.bicep' = if (!empty(budgetContactEmail)) {
  params: {
    name: 'fourth-credit-budget'
    amount: int(budgetAmount)
    startDate: budgetStartDate
    endDate: budgetEndDate
    contactEmails: [budgetContactEmail]
  }
}

module healthApp 'br/public:avm/res/app/container-app:0.23.0' = {
  scope: rg
  params: {
    name: 'ca-health-${resourceToken}'
    location: location
    tags: tags
    environmentResourceId: containerAppsEnvironment.outputs.resourceId
    workloadProfileName: 'Consumption'
    ingressExternal: true
    ingressTargetPort: 80
    ingressAllowInsecure: false
    scaleSettings: {
      minReplicas: 0
      maxReplicas: 1
    }
    containers: [
      {
        name: 'health'
        image: 'mcr.microsoft.com/azuredocs/containerapps-helloworld:latest'
        resources: {
          cpu: json('0.25')
          memory: '0.5Gi'
        }
      }
    ]
  }
}

output AZURE_RESOURCE_GROUP string = rg.name
output AZURE_CONTAINER_REGISTRY_ENDPOINT string = registry.outputs.loginServer
output AZURE_CONTAINER_REGISTRY_NAME string = registry.outputs.name
output AZURE_KEY_VAULT_NAME string = keyVault.outputs.name
output AZURE_COSMOS_ENDPOINT string = cosmos.outputs.endpoint
output AZURE_STORAGE_ACCOUNT string = storage.outputs.name
output HEALTH_URL string = 'https://${healthApp.outputs.fqdn}'
