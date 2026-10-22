@description('Region of the Container Apps environment and its apps.')
param location string = 'northeurope'

@description('Name of the Container Apps environment.')
param environmentName string = 'cae-a2a-interop'

@description('Name of the A2A server app.')
param a2aAppName string = 'ca-a2a-server'

@description('Name of the MCP server app.')
param mcpAppName string = 'ca-mcp-server'

@description('Login server of the private Azure Container Registry, for example myregistry.azurecr.io.')
param acrLoginServer string

@description('A2A server image, pinned by digest or tag.')
param a2aImage string

@description('MCP server image, pinned by digest or tag.')
param mcpImage string

@description('Resource ID of the user-assigned managed identity that has AcrPull on the registry.')
param identityId string

@secure()
@description('Private JWK (JSON) that signs the A2A server Agent Card.')
param cardSigningJwk string

@description('Key ID published in the Agent Card signature header.')
param cardKid string

@description('Microsoft Entra tenant whose access tokens the A2A server accepts.')
param entraTenantId string

@description('Audience the A2A server requires in access tokens.')
param entraAudience string

@description('Seconds without traffic before an app scales back to zero.')
param cooldownPeriod int = 60

var cardSecretName = 'card-signing-jwk'
var registries = [
  {
    server: acrLoginServer
    identity: identityId
  }
]
var scaleSettings = {
  minReplicas: 0
  maxReplicas: 1
  cooldownPeriod: cooldownPeriod
  pollingInterval: 15
}
var resources = {
  cpu: json('0.25')
  memory: '0.5Gi'
}

module environment 'br/public:avm/res/app/managed-environment:0.16.0' = {
  params: {
    name: environmentName
    location: location
    publicNetworkAccess: 'Enabled'
    zoneRedundant: false
    workloadProfiles: [
      {
        name: 'Consumption'
        workloadProfileType: 'Consumption'
      }
    ]
  }
}

module a2aServer 'br/public:avm/res/app/container-app:0.23.0' = {
  params: {
    name: a2aAppName
    location: location
    environmentResourceId: environment.outputs.resourceId
    workloadProfileName: 'Consumption'
    managedIdentities: {
      userAssignedResourceIds: [identityId]
    }
    registries: registries
    ingressExternal: true
    ingressTargetPort: 8080
    ingressAllowInsecure: false
    scaleSettings: scaleSettings
    secrets: [
      {
        name: cardSecretName
        value: cardSigningJwk
      }
    ]
    containers: [
      {
        name: 'a2a-server'
        image: a2aImage
        resources: resources
        env: [
          {
            name: 'PUBLIC_URL'
            value: 'https://${a2aAppName}.${environment.outputs.defaultDomain}'
          }
          {
            name: 'CARD_SIGNING_JWK'
            secretRef: cardSecretName
          }
          {
            name: 'CARD_KID'
            value: cardKid
          }
          {
            name: 'ENTRA_TENANT_ID'
            value: entraTenantId
          }
          {
            name: 'ENTRA_AUDIENCE'
            value: entraAudience
          }
        ]
      }
    ]
  }
}

module mcpServer 'br/public:avm/res/app/container-app:0.23.0' = {
  params: {
    name: mcpAppName
    location: location
    environmentResourceId: environment.outputs.resourceId
    workloadProfileName: 'Consumption'
    managedIdentities: {
      userAssignedResourceIds: [identityId]
    }
    registries: registries
    ingressExternal: true
    ingressTargetPort: 8080
    ingressAllowInsecure: false
    scaleSettings: scaleSettings
    containers: [
      {
        name: 'mcp-server'
        image: mcpImage
        resources: resources
      }
    ]
  }
}

output a2aServerUrl string = 'https://${a2aServer.outputs.fqdn}'
output mcpServerUrl string = 'https://${mcpServer.outputs.fqdn}'
