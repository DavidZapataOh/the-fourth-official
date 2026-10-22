# 0004. Confidential container hosting

Status: accepted

## Context

The notary signs verdicts, and a verifier must be able to check that the signing code ran unmodified inside hardware-protected memory. That needs a host that produces a hardware attestation bound to the exact container image set, and a verifier that checks it without trusting us.

Azure Container Instances offers a confidential SKU on AMD SEV-SNP. A confidential computing enforcement (CCE) policy lists the allowed image layers, commands and environment variables. The hash of that policy is placed in the guest's launch measurement as host data, and Microsoft Azure Attestation (MAA) returns it as the `x-ms-sevsnpvm-hostdata` claim of a signed token. The Secure Key Release sidecar from `microsoft/confidential-sidecar-containers` requests that token from inside the group.

This subscription cannot create resources in West Europe. Confidential ACI is available in North Europe, West Europe and East US.

## Decision

Keep Azure Container Instances confidential container groups in North Europe as the notary host.

- The group runs the application and the sidecar next to each other; both images are referenced by digest and pulled from a private registry through a user-assigned managed identity.
- `fourth-attestation` verifies the MAA token independently: RS256 signature by a key from the provider's JWKS, issuer, expiry, attestation type `sevsnpvm`, compliance status `azure-compliant-uvm`, non-debuggable guest, and host data equal to the SHA-256 of the decoded policy.
- The policy is generated with `az confcom acipolicygen` from the compiled template and its parameters. The extension has no macOS build, so it runs in the Azure CLI container against the local Docker daemon. Images are hashed from the local daemon, so the policy covers the exact image that was built.
- The sidecar is configured on port 8081 because the application owns 8080 in the shared network namespace. The attestation request body carries `runtime_data` as base64 of a JSON document; MAA rejects any other content.
- Environment values in the template must be literals or plain parameter and variable references. The policy generator does not evaluate template functions such as `format`, and a value it cannot resolve is silently dropped from the container.

## Measurements

| Measurement | Value | Unit | Command | Date |
| --- | --- | --- | --- | --- |
| Region | North Europe | region | `uv run python tools/aci-attest/run.py` | 2026-10-22 |
| MAA endpoint | sharedneu.neu.attest.azure.net | hostname | `uv run python tools/aci-attest/run.py` | 2026-10-22 |
| Policy hash (host data) | 7fc50173bbeb291ae4241298cca7027390d2b4fd646fb494840fe730f525119a | SHA-256 hex | `uv run python tools/aci-attest/run.py` | 2026-10-22 |
| Sidecar image digest | sha256:deb7d4a4462b3df7c8e97e4d23c628ef967b2fb2a8b059afb9e2954e21f4bbe5 | digest | `docker buildx imagetools inspect mcr.microsoft.com/aci/skr:2.12` | 2026-10-22 |
| Deployment request to group running (median of 3) | 67.3 | s | `uv run python tools/aci-attest/run.py` | 2026-10-22 |
| Deployment request to first valid token (median of 3) | 67.7 | s | `uv run python tools/aci-attest/run.py` | 2026-10-22 |
| Tokens accepted by the independent verifier | 3 of 3 | runs | `uv run python tools/aci-attest/run.py` | 2026-10-22 |
| Tamper case: policy generated for another image | group failed to deploy | outcome | `uv run python tools/aci-attest/run.py` | 2026-10-22 |
| Price of 1 vCPU and 2 GB | 0.065208 | USD per hour | Azure retail prices API, serviceName Container Instances, northeurope | 2026-10-22 |
| Confidential cores quota | 4 | cores per region | `az rest` on `Microsoft.ContainerInstance/locations/northeurope/usages` | 2026-10-22 |

Retail meters used for the price: vCPU 0.05346 USD per hour and memory 0.005874 USD per GB-hour.

Decision: keep Azure Container Instances confidential container groups in North Europe.

## Consequences

- The policy binds image layers, so it must be regenerated and the host data re-checked on every image change. Images are referenced by digest and tags are rejected before policy generation.
- A token minted for a different image set carries different host data, and a policy for another image does not let the real image run. Verifiers compare against the policy hash published with each release.
- Cold start is about 68 seconds, so the notary runs as a long-lived group, not per request.
- The quota is 4 confidential cores per region, which bounds the number of concurrent groups.
- West Europe is unavailable to this subscription; East US is the fallback region.
- The attestation proves which image set ran. It does not prove the behavior of the code in the image, which is why the images are built from the public repository with provenance.
