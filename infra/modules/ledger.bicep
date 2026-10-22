@description('Name of the ledger; globally unique, it is also the data plane host name.')
param name string

@description('Region of the ledger.')
param location string

@description('Microsoft Entra object ID of the principal that administers the ledger data plane.')
param principalId string

resource ledger 'Microsoft.ConfidentialLedger/ledgers@2026-02-23' = {
  name: name
  location: location
  properties: {
    ledgerType: 'Public'
    aadBasedSecurityPrincipals: [
      {
        ledgerRoleName: 'Administrator'
        principalId: principalId
        tenantId: tenant().tenantId
      }
    ]
  }
}

output ledgerUri string = ledger.properties.ledgerUri
output identityServiceUri string = ledger.properties.identityServiceUri
