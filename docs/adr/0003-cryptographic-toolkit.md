# 0003. Cryptographic toolkit

Status: accepted

## Context

Signed event batches, sealed calls and certificates must be produced on our servers and checked by anyone, including in a browser with no connection to us. Python produces and TypeScript verifies, so both languages must accept exactly the same inputs and produce byte-identical outputs. A divergence between them is a security defect, not a bug: one side could accept a message the other rejects.

The toolkit lives in `libs/crypto` as a Python package (`fourth-crypto`) and a TypeScript package (`@fourth/crypto`) with the same function set under idiomatic names. We write encodings, tree structure and message layout only. Every primitive comes from a vetted library: `cryptography` in Python, WebCrypto in TypeScript for Ed25519, and `@noble/hashes` for SHA-256 where WebCrypto's asynchronous digest is unsuitable.

## Decision

Algorithms and formats:

- Hash: SHA-256. Digests are written as `sha256:` plus 64 lowercase hex characters; uppercase and other lengths are rejected.
- Signature: Ed25519 with 32-byte seeds and public keys and 64-byte signatures, written as `ed25519:` plus unpadded base64url. Base64url decoding is strict: no padding, no whitespace, no non-zero trailing bits.
- Canonical JSON: RFC 8785. Numbers outside the safe integer range, `NaN`, `Infinity` and lone surrogates are rejected rather than serialized.
- Signed envelope: COSE_Sign1 (RFC 9052) with CBOR tag 18, protected header `{1: -8, 4: kid}` under CBOR core deterministic encoding, an empty unprotected header and an attached payload. Verification accepts tag 18 or an untagged array and rejects any other tag.
- Merkle tree: RFC 6962 hashing with a `0x00` leaf prefix and a `0x01` node prefix, an empty root of `sha256("")`, inclusion and consistency proofs as in RFC 9162 sections 2.1.3.2 and 2.1.4.2. The tree is built level by level, promoting an unpaired last node unchanged. This is the same tree as the RFC 6962 split at the largest power of two below `n`, and property tests check it against a recursive implementation of the RFC.
- Commitments: `sha256(utf8(domain) || 0x00 || for each part: uint32_be(len(part)) || part)`. Chains: `sha256("fourth/chain/v1" || 0x00 || prev_hash || data)` with a 32-byte `prev_hash`.

Why not a general COSE library. The verifier must ship in a browser, so bundle size and the absence of polyfills matter. WebCrypto supplies Ed25519 natively (Chrome 137, Edge 137, Firefox 129, Safari 17), `@noble/hashes` supplies SHA-256 in a few kilobytes, and `cborg` supplies CBOR. Everything above that is a small, hand-written message layer. General COSE libraries cover many algorithms we do not use and pull in dependencies we would then ship. In Python, `pycose` depends on `ecdsa`, which has an open timing-side-channel advisory, and it accepts and rejects different inputs than our strict profile. It is therefore a development-only cross-check: tests confirm that our messages verify under `pycose` and that its example messages verify under ours.

One strict COSE and CBOR profile in both languages. Libraries such as `cbor2` and `cborg` disagree on tags, simple values, floats, UTF-8 validity and duplicate map keys, so neither decoder is used for verification. Both languages read the message with the same small strict reader. It accepts integers, byte and text strings, arrays, maps with integer or text keys and `null`, with nesting limited to 32 levels. It rejects: tags other than a leading tag 18, floats and simple values other than `null`, indefinite lengths, invalid UTF-8, duplicate map keys, trailing bytes, lengths that exceed the input, an algorithm other than EdDSA (-8), an algorithm outside the protected header, critical headers, a detached (null) payload and signatures that are not 64 bytes. Verification does not require a `kid`: key selection is the caller's job. Callers read the `kid` with `cose_kid` or `coseKid`, which looks only at the protected header and raises `CoseError` when it is absent or not a byte string, select the public key, and then verify. Verification with a key other than the signer's fails.

Length-prefixed commitments. Plain concatenation is ambiguous: `("ab", "c")` and `("a", "bc")` produce the same bytes. A four-byte big-endian length before each part, and a domain string terminated by `0x00`, make the encoding injective, so two different tuples of parts or two different domains can never share a preimage. This is a deliberate refinement over plain concatenation. The domains in use are `fourth/seed/v1` and `fourth/call/v1`.

Caller contract for Merkle verification. `verify_inclusion` and `verify_consistency` check a proof against a root and sizes; they cannot know whether those inputs are trustworthy. Callers must take the tree size from the same signed statement as the root, and must compute leaf hashes themselves from the leaf content, never accept a hash supplied with the proof. Without this, a node hash can be presented as a leaf (a second-preimage attack) or a proof can be checked against a size the signer never stated.

Integer range. Integer fields in signed JSON must stay at or below 2^53-1 in magnitude. Python rejects larger integers during canonicalization. TypeScript parses JSON numbers as doubles and cannot tell that an input exceeded the range, so producers must keep to the limit and carry larger values as strings.

Baselines. Python 3.13 and Node 24. TypeScript uses only browser-safe APIs.

Vector-first testing. `libs/crypto/vectors` holds language-neutral JSON and is the only source of expected values. Vectors come from RFC 8785, RFC 8032, the `transparency-dev/merkle` and `cose-wg/Examples` repositories (recorded in `NOTICE`), plus vectors generated by this project for base64url, commitments and our COSE profile. Both test suites read the same files, and a parity test fails when a vector file is not loaded through the shared `vectors("<name>")` helper in the test suite of either language. Property tests (Hypothesis and fast-check) cover round trips and compare the Merkle code with a simple recursive oracle. Performance tests assert that the Merkle root and an inclusion proof for 100,000 leaves and the canonicalization of a 37-event batch stay within generous budgets (1 s, 1 s and 5 ms in Python; 500 ms, 500 ms and 1 ms in TypeScript) that act as regression tripwires. The tests also print the measured medians, recorded separately: about 33 ms, 34 ms and 0.6 ms in Python and 92 ms, 91 ms and 0.1 ms in TypeScript on an Apple M4.

## Consequences

Both languages can be audited against one set of vectors, and a change that makes one side accept or reject differently fails a test. The browser verifier stays small and has no polyfills. We own a short CBOR reader and encoder, which is a maintenance cost and a place for bugs; the shared vectors, the bit-flip and truncation tests and the `pycose` cross-check are the mitigation.

COSE messages are malleable outside the protected header: the unprotected header is not signed, and CBOR allows several encodings of the same payload in an unsigned position. Two different byte strings can therefore carry the same signed payload and `kid`. Callers must deduplicate on the payload plus the `kid`, never on raw message bytes or a hash of them.

The 2^53-1 limit is a contract on producers rather than something the TypeScript verifier can enforce. A performance test failure should be investigated before its budget is raised. Algorithm agility is deliberately absent: moving to another signature or hash algorithm needs a new profile and a new `v` in the contracts, not a negotiated parameter.
