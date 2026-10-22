@description('Name of the Foundry resource; also its custom subdomain.')
param accountName string

@description('Name of the Foundry project.')
param projectName string

@description('Region of the Foundry resource.')
param location string = 'swedencentral'

@description('Model deployment capacity in thousands of tokens per minute.')
@minValue(1)
param modelCapacity int = 30

@description('Object ID of the user who builds agents in the project. Empty skips the role assignment.')
param userPrincipalId string = ''

var modelName = 'gpt-5-mini'
var foundryUserRoleId = '53ca6127-db72-4b80-b1b0-d745d6d5456d'

resource account 'Microsoft.CognitiveServices/accounts@2025-06-01' = {
  name: accountName
  location: location
  kind: 'AIServices'
  sku: {
    name: 'S0'
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    allowProjectManagement: true
    customSubDomainName: accountName
    disableLocalAuth: true
    publicNetworkAccess: 'Enabled'
  }
}

resource project 'Microsoft.CognitiveServices/accounts/projects@2025-06-01' = {
  parent: account
  name: projectName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {}
}

resource model 'Microsoft.CognitiveServices/accounts/deployments@2025-06-01' = {
  parent: account
  dependsOn: [project]
  name: modelName
  sku: {
    name: 'GlobalStandard'
    capacity: modelCapacity
  }
  properties: {
    model: {
      format: 'OpenAI'
      name: modelName
      version: '2025-08-07'
    }
  }
}

resource foundryUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(userPrincipalId)) {
  scope: project
  name: guid(project.id, userPrincipalId, foundryUserRoleId)
  properties: {
    principalId: userPrincipalId
    principalType: 'User'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', foundryUserRoleId)
  }
}

output projectEndpoint string = project.properties.endpoints['AI Foundry API']
output modelDeployment string = model.name
