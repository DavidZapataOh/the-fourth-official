# Proof vectors

## ledger_receipt.json

Azure Confidential Ledger write transaction receipts. `bases` holds complete valid inputs;
`cases` holds every input both verifiers must agree on, each with the expected outcome in
`valid`. A case also carries `azure_sdk_valid` where the Azure SDK verifier
(`azure.confidentialledger.receipt.verify_receipt`) reaches a different outcome: it accepts
certificate signatures encoded with unused bits, which these verifiers reject.

| Base | Source | License |
|---|---|---|
| `azure_sdk_receipt_1`, `azure_sdk_receipt_2` | azure-confidentialledger 1.1.1, `tests/receipt/_shared/receipt_constants.py` | MIT, Copyright (c) Microsoft Corporation |
| `azure_sdk_receipt_with_claims`, `azure_sdk_receipt_with_claim_digest` | azure-confidentialledger 1.1.1, `tests/receipt/test_receipt_verification.py` | MIT, Copyright (c) Microsoft Corporation |
| `synthetic_receipt_with_endorsement` | generated, P-384 keys derived from fixed labels, deterministic ECDSA | Apache-2.0 |

The SDK files are in the source distribution on PyPI and in
https://github.com/Azure/azure-sdk-for-python at tag `azure-confidentialledger_1.1.1` under
`sdk/confidentialledger/azure-confidentialledger/tests/receipt`. Receipt 1 is converted from
snake_case to camelCase keys and its `is_signature_transaction` flag is dropped.

The synthetic base has a node endorsed by a previous service identity, which the current one
endorses, plus a `LedgerEntry` and a `ClaimDigest` application claim. Its certificates expired
on 2026-04-01; validity periods are not checked, as in the SDK verifier.

Regenerate the synthetic base and all cases (output is deterministic):

```sh
uv run python libs/proofs/py/scripts/gen_ledger_mutations.py
```

## rfc3161.json

A timestamp from a throwaway local authority made with OpenSSL (3.4 or later; set `OPENSSL` to
pick the binary). It holds the trusted root, an unrelated root, the authority certificate, the
`TimeStampResp` and the bare `TimeStampToken` over the SHA-256 of `data`, a response signed by an
authority whose certificate expired before signing, and the expected time, authority and serial.
Keys are generated on each run, so the file changes when it is regenerated.

```sh
libs/proofs/py/tests/make_test_authority.sh
```

Certificates are checked at the token's signing time, as `rfc3161-client` and
`openssl ts -verify` do: a token stays valid after its authority certificate expires, and a token
signed outside the certificate's validity is rejected. The CMS fields that the signature does not
cover (the `SignedData` and `SignerInfo` versions and the `SignerInfo` signature algorithm) are not
checked by either verifier; changing them does not change what the token attests.

TypeScript has no RFC 3161 verifier. A token is checked outside the library with:

```sh
openssl ts -verify -digest <sha256 hex> -in token.tsr -CAfile authority-chain.pem
```

## ots.json

OpenTimestamps detached proofs for the SHA-256 of `data`.

| Entry | Source |
|---|---|
| `pending` | `ots stamp` from the reference client against the public calendars; `calendars` is what `ots info` printed |
| `bitcoin` | built from the serialization format through every supported operation; the block root is synthetic and in block header byte order |
| `deepest` | 255 nested operations, the reference client's limit |
| `invalid` | proofs both readers reject, built from the serialization format |

The reference client is LGPL-3.0 and is only run as an external tool, never imported:

```sh
libs/proofs/py/scripts/stamp_test_hash.sh   # new pending proof, then regenerates the file
uv run python libs/proofs/py/scripts/gen_ots_vectors.py   # keeps the stored pending proof
pnpm exec biome format --write libs/proofs/vectors/ots.json
```

The readers are stricter than the reference client on purpose: they require a SHA-256 file hash,
reject `keccak256`, integers above 2^53 - 1 or longer than 8 bytes, Bitcoin attestations on
messages that are not 32 bytes, and proofs with neither a pending nor a Bitcoin attestation.
Unknown attestation types are skipped.

## Live vectors

Written by the live run, which creates a Public Azure Confidential Ledger in East US through
`infra/modules/ledger.bicep`, deletes it at the end and verifies the saved receipt again offline:

```sh
uv run python libs/proofs/py/scripts/live_run.py
FOURTH_LIVE=1 uv run pytest libs/proofs/py/tests/test_proofs_live.py -q -s
```

| File | Source |
|---|---|
| `ledger_receipt_live.json` | one entry, the JCS-canonical verdict in `claim`, written at data plane API `2026-02-23` so the receipt carries application claims; the service identity certificate comes from the identity service. Same `bases` and `cases` layout as `ledger_receipt.json`: the valid receipt plus one changed claim, one changed signature and the node certificate used as the service certificate |
| `rfc3161_live.json` | a `TimeStampResp` from FreeTSA (https://freetsa.org/tsr, usage policy https://freetsa.org/freetsa.html: one request per second per IP, no SLA, commercial use allowed) with its published CA and authority certificates, checked against the SHA-256 values FreeTSA publishes |
| `ots_live.json` | the same test data stamped on the default public OpenTimestamps calendars; `upgrades` and `anchored` are added by the upgrade step |

Upgrade the stamp at least 6 hours later and again after 24 hours. The reference client runs
`ots upgrade` and `ots verify` as an external tool; the readers then check the Bitcoin attestation
against the block's Merkle root from a public Esplora explorer:

```sh
uv run python libs/proofs/py/scripts/upgrade_ots.py [--bitcoin-node URL]
```

DigiCert and Sectigo tokens are not used: `rfc3161-client` rejects their `SignedData`
certificate sets, which are not in DER set order.
