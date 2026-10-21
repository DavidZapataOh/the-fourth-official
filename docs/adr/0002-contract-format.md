# 0002. Contract format

Status: accepted

## Context

Every component exchanges a small set of structured messages: events, signed batches, claims, verdicts, overlay cues, the scene package, sealed calls and certificates. They are produced and consumed in Python and TypeScript, and the public verifier must check them without our servers. A single definition must drive both languages, and a change to it must be impossible to ship in one language only.

## Decision

- JSON Schema 2020-12 is the only hand-written source, in `libs/contracts/schemas`. Every object sets `additionalProperties: false`.
- Formats are patterns, never the `format` keyword, so validators in different languages cannot disagree about them. Timestamps are UTC with a trailing `Z`; digests are `sha256:` plus 64 lowercase hex characters; signatures are `ed25519:` plus unpadded base64url.
- Each schema has an absolute `$id` under a documentation domain and refers to shared definitions with relative `$ref`s.
- Types are generated and committed: Pydantic v2 models with `datamodel-code-generator` and TypeScript declarations with `json-schema-to-typescript` using `--imports`. `make check-generated` fails when regeneration changes a file.
- Fixtures in `libs/contracts/fixtures/<contract>/{valid,invalid}` are shared by both languages. Every contract needs at least one valid and three invalid cases, and every invalid file is named after the reason it is rejected.
- Pydantic models are the hot path for Python services; the schema validator exists for conformance and for untrusted input where exact schema semantics matter.
- Verdict states are `confirmed`, `disputed` and `blocked`. An overlay cue credential can only carry `confirmed`, so a cue for a disputed or blocked verdict cannot be expressed.
- A sealed call and a certificate are separate contracts: the call carries only the commitment, the certificate adds the reveal, the verdict and the proofs.
- A batch header's `count` is not checked by the schema. Producers and verifiers compare it with the number of events.

## Consequences

One edit to a schema updates both languages and breaks the build until fixtures agree. Generated files are committed, so reviews show the effect of a schema change. Contracts evolve by adding optional fields or by bumping `v`; there is no negotiation.
