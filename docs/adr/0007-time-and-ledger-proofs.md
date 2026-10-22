# 0007. Time and ledger proofs

Status: accepted

## Context

A verdict has to stay verifiable after our own services are gone. Three independent kinds of evidence cover that: an append-only log whose entries come with a signed receipt, a trusted timestamp that fixes when a digest existed, and an anchor in a public blockchain that no single party can rewrite. Each must be checkable offline, in Python and in a browser, from saved material.

Azure Confidential Ledger is a managed log on confidential computing. Every committed entry has a receipt: the leaf digests, a Merkle proof, a signature by a node of the service and the endorsement chain that ties that node to the service identity certificate. RFC 3161 timestamp authorities sign a digest with a time. OpenTimestamps aggregates digests into Bitcoin transactions through public calendars.

## Decision

Keep Azure Confidential Ledger as the log of record, RFC 3161 at the second level of evidence and OpenTimestamps at the third.

- **Ledger.** Receipts are verified by our own verifier in Python and TypeScript, with identical outcomes on the same vectors. Python delegates the signature and chain check to the Azure SDK after our application-claims check; TypeScript implements the same algorithm with WebCrypto, a minimal X.509 reader and `@noble/curves` for the root signature, which WebCrypto cannot check because the service signs the digest itself. The service identity certificate is exported and stored with every receipt, so verification does not depend on the ledger being alive.
- **Expired certificates.** Verification does not reject an endorsement chain for expiry. Receipts are long-lived evidence and the Azure documentation turns the validity checks off for that reason. Chains that are missing, empty, replaced, repeated or altered are rejected.
- **RFC 3161.** Python verification with `rfc3161-client` (Apache-2.0). The authority certificate is checked at the time of signing, so a token stays valid after the certificate expires; a token signed after it expired or dated in the future is rejected. There is no TypeScript verifier: a general library costs 86 KB gzip, so pages show the standard `openssl ts -verify` command. The budget for a browser RFC 3161 verifier is 10 KB gzip; a hand-written DER verifier is estimated at 3 to 5 KB and is built only if a page needs it. The tokens are from FreeTSA (1 request per second, no service level, commercial use allowed). DigiCert and Sectigo tokens are accepted by OpenSSL and rejected by `rfc3161-client` because their certificate set is not in DER order.
- **OpenTimestamps.** Our own reader in both languages, written from the public binary format. The libraries `opentimestamps`, `opentimestamps-client` and `javascript-opentimestamps` are licensed LGPL-3.0, which we do not ship in a browser bundle. The reference client is used only as an external tool in scripts. A proof is reported `anchored` only when the Merkle root computed through its operations equals a block-header root the caller supplies; otherwise it is `pending`, with the claimed block height reported as unverified.

## Measurements

| Measurement | Value | Unit | Command | Date |
| --- | --- | --- | --- | --- |
| Ledger region | eastus | region | `FOURTH_LIVE=1 uv run pytest libs/proofs/py/tests/test_proofs_live.py` | 2026-10-22 |
| Ledger creation time | 247.3 | s | `FOURTH_LIVE=1 uv run pytest libs/proofs/py/tests/test_proofs_live.py` | 2026-10-22 |
| Ledger deletion time | 137.2 | s | `FOURTH_LIVE=1 uv run pytest libs/proofs/py/tests/test_proofs_live.py` | 2026-10-22 |
| Ledger price, Standard SKU | 0.124 | USD per hour | Azure retail prices API, Confidential Ledger, eastus | 2026-10-22 |
| Python receipt verification, 1 receipt (live receipt) | 0.17 | ms | `FOURTH_LIVE=1 uv run pytest libs/proofs/py/tests/test_proofs_live.py` | 2026-10-22 |
| Python receipt verification, 100 receipts (live receipt) | 14.29 | ms | `FOURTH_LIVE=1 uv run pytest libs/proofs/py/tests/test_proofs_live.py` | 2026-10-22 |
| TypeScript receipt verification, 1 receipt (P-384 receipt with endorsement chain) | 3.83 | ms | `pnpm vitest run --project @fourth/proofs perf` | 2026-10-22 |
| TypeScript receipt verification, 100 receipts (P-384 receipt with endorsement chain) | 353 | ms | `pnpm vitest run --project @fourth/proofs perf` | 2026-10-22 |
| TypeScript ledger verifier bundle | 20219 | bytes gzip | esbuild bundle of `libs/proofs/ts/src/index.ts` | 2026-10-22 |
| Live receipt verified after the ledger was deleted, Python | yes | boolean | `FOURTH_LIVE=1 uv run pytest libs/proofs/py/tests/test_proofs_live.py` | 2026-10-22 |
| Live receipt verified after the ledger was deleted, TypeScript | yes | boolean | `FOURTH_LIVE=1 uv run pytest libs/proofs/py/tests/test_proofs_live.py` | 2026-10-22 |
| RFC 3161 authority | FreeTSA, https://freetsa.org/tsr | name and URL | `FOURTH_LIVE=1 uv run pytest libs/proofs/py/tests/test_proofs_live.py` | 2026-10-22 |
| RFC 3161 token size | 4645 | bytes | `FOURTH_LIVE=1 uv run pytest libs/proofs/py/tests/test_proofs_live.py` | 2026-10-22 |
| RFC 3161 verification time | 19.29 | ms | `FOURTH_LIVE=1 uv run pytest libs/proofs/py/tests/test_proofs_live.py` | 2026-10-22 |
| pkijs bundle cost for parsing one certificate | 86256 | bytes gzip | esbuild bundle of a `Certificate.fromBER` call | 2026-10-22 |
| OpenTimestamps calendars that accepted the stamp | 4 | calendars | `uv run python libs/proofs/py/scripts/upgrade_ots.py` | 2026-10-22 |
| OpenTimestamps state at the time of writing | pending since 2026-10-22T21:41:33Z | state | `uv run python libs/proofs/py/scripts/upgrade_ots.py` | 2026-10-22 |

The Bitcoin confirmation takes hours. The proof was stamped at 21:41 UTC on 2026-10-22 and is checked again with `upgrade_ots.py` at least 6 hours and 24 hours later; the first check that shows a block height is recorded in this table as the time from stamp to confirmation.

Decision: keep Azure Confidential Ledger as the log of record, with RFC 3161 at level 2 and OpenTimestamps at level 3 through our own reader.

## Consequences

- The service identity certificate must be exported before a ledger is deleted and published with the receipts. Without it a receipt cannot be tied to the service.
- The data plane API version `2026-02-23` is required for receipts that carry application claims. The SDK defaults to an older version, so the version is set explicitly.
- Our receipt verifier is stricter than the Azure SDK in one point: a certificate with a changed signature padding byte is rejected, while the SDK accepts it.
- Some bytes of an RFC 3161 token are outside the signature (two version numbers and the signature algorithm identifier). Changing them does not change the time, authority, serial or digest, and OpenSSL accepts the same changes.
- Checking an anchored OpenTimestamps proof offline needs the Merkle root of the Bitcoin block. A page either ships block roots for the heights it needs or asks a block explorer; the stricter option is a Bitcoin node.
- The reader rejects some proofs the reference client accepts: a SHA-1 file hash, keccak256, oversized block numbers and attestations on messages that are not 32 bytes.
- Ledger pricing makes a live ledger an explicit cost. The demo uses saved receipts, and a ledger runs only while records are being written.
- Locations: Confidential Ledger is not offered in North Europe for this subscription, and West Europe rejects new resources, so the ledger lives in East US.
