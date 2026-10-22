targetScope = 'subscription'

@description('Budget name. Reusing a name updates the existing budget.')
param name string

@description('Budget amount per month, in the billing currency.')
param amount int

@description('First day of the budget period, as yyyy-MM-dd. Must be the first day of a month.')
param startDate string

@description('Last day of the budget period, as yyyy-MM-dd.')
param endDate string

@description('Recipients of the threshold notifications.')
param contactEmails array

resource budget 'Microsoft.Consumption/budgets@2024-08-01' = {
  name: name
  properties: {
    category: 'Cost'
    amount: amount
    timeGrain: 'Monthly'
    timePeriod: {
      startDate: '${startDate}T00:00:00Z'
      endDate: '${endDate}T00:00:00Z'
    }
    notifications: {
      actual50: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 50
        thresholdType: 'Actual'
        contactEmails: contactEmails
      }
      actual80: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 80
        thresholdType: 'Actual'
        contactEmails: contactEmails
      }
      forecast100: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 100
        thresholdType: 'Forecasted'
        contactEmails: contactEmails
      }
    }
  }
}
