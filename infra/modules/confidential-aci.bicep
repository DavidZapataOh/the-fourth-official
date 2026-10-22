@description('Name of the container group.')
param name string

@description('Region of the container group.')
param location string

@description('Login server of the private Azure Container Registry, for example myregistry.azurecr.io.')
param acrLoginServer string

@description('Demo application image, pinned by digest.')
param appImage string

@description('Secure Key Release sidecar image, pinned by digest.')
param skrImage string

@description('Resource ID of the user-assigned managed identity that has AcrPull on the registry.')
param identityId string

@description('Base64 confidential computing enforcement policy generated for this group.')
param ccePolicy string = ''

@description('Microsoft Azure Attestation endpoint that signs the tokens.')
param maaEndpoint string

var sidecarPort = '8081'
var skrUrl = 'http://localhost:8081/attest/maa'

resource group 'Microsoft.ContainerInstance/containerGroups@2026-07-01' = {
  name: name
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identityId}': {}
    }
  }
  properties: {
    sku: 'Confidential'
    osType: 'Linux'
    restartPolicy: 'Never'
    confidentialComputeProperties: {
      ccePolicy: ccePolicy
    }
    imageRegistryCredentials: [
      {
        server: acrLoginServer
        identity: identityId
      }
    ]
    containers: [
      {
        name: 'app'
        properties: {
          image: appImage
          ports: [
            {
              port: 8080
              protocol: 'TCP'
            }
          ]
          environmentVariables: [
            {
              name: 'MAA_ENDPOINT'
              value: maaEndpoint
            }
            {
              name: 'SKR_URL'
              value: skrUrl
            }
          ]
          resources: {
            requests: {
              cpu: json('0.5')
              memoryInGB: 1
            }
          }
        }
      }
      {
        name: 'skr'
        properties: {
          image: skrImage
          command: ['/skr.sh']
          environmentVariables: [
            {
              name: 'Port'
              value: sidecarPort
            }
          ]
          resources: {
            requests: {
              cpu: json('0.5')
              memoryInGB: 1
            }
          }
        }
      }
    ]
    ipAddress: {
      type: 'Public'
      ports: [
        {
          port: 8080
          protocol: 'TCP'
        }
      ]
    }
  }
}

output ipAddress string = group.properties.ipAddress.ip
