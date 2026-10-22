# The Fourth Official

An independent fourth official for AI-produced football analysis: every verdict is signed, attested and verifiable outside our servers.

## Prerequisites

- [uv](https://docs.astral.sh/uv/) for Python
- [pnpm](https://pnpm.io/) and Node.js 24
- The Azure CLI and Azure Developer CLI for deployment

## Quickstart

```sh
make install
make check
```

## Deploy to Azure

Requires an Azure subscription, the Azure CLI (`az login`) and the Azure Developer CLI (`azd auth login`).

```sh
azd env new fourth-dev
azd env set AZURE_LOCATION northeurope
azd env set BUDGET_CONTACT_EMAIL "<email that receives budget alerts>"
azd up
```

`azd up` provisions the resource group, monitoring, container registry and environment, Key Vault Premium, serverless Cosmos DB, storage and a placeholder health app (`azd env get-value HEALTH_URL`). The budget alert is created at subscription scope and survives `azd down`. Tear everything else down with `azd down --purge` (deleting the Container Apps environment can take around 30 minutes).

If a region does not accept new resources for your subscription, deploy to another one; if only Cosmos DB reports a capacity error, set `COSMOS_LOCATION` to another region.
