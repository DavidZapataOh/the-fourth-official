import { ripemd160, sha1 } from "@noble/hashes/legacy.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";
import { ProofError } from "./ledger.ts";

/**
 * What an OpenTimestamps proof shows for a digest.
 *
 * `anchored` means a Bitcoin attestation in the proof commits to the Merkle root supplied for its
 * block, and `blockHeight` is the lowest such block. Otherwise the proof is `pending`;
 * `unverifiedAnchorHeight` is the lowest block a Bitcoin attestation claims when no root was
 * supplied to check it against. `calendars` lists the pending calendar URLs in proof order.
 */
export type OtsStatus = {
  kind: "pending" | "anchored";
  blockHeight: number | null;
  calendars: string[];
  unverifiedAnchorHeight: number | null;
};

/** Block Merkle roots by height, in block header byte order (the reverse of explorer hex). */
export type OtsStatusOptions = { blockMerkleRoots?: ReadonlyMap<number, Uint8Array> };

const MAGIC = Uint8Array.from(
  "\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94",
  (char) => char.charCodeAt(0),
);
const BITCOIN = "0588960d73d71901";
const PENDING = "83dfe30d2ef90c8e";
const MAX_PROOF = 65536;
const MAX_DEPTH = 255;
const MAX_MESSAGE = 4096;
const MAX_PAYLOAD = 8192;
const MAX_URI = 1000;
const MAX_VARUINT_BYTES = 8;
const URI = /^[A-Za-z0-9\-._/:]*$/;

const SHA1 = 0x02;
const RIPEMD160 = 0x03;
const SHA256 = 0x08;
const KECCAK256 = 0x67;
const APPEND = 0xf0;
const PREPEND = 0xf1;
const REVERSE = 0xf2;
const HEXLIFY = 0xf3;
const FORK = 0xff;
const HASHES: Record<number, (msg: Uint8Array) => Uint8Array> = {
  [SHA1]: sha1,
  [RIPEMD160]: ripemd160,
  [SHA256]: sha256,
};
const UNSUPPORTED: Record<number, string> = { [KECCAK256]: "keccak256" };

type Found = { calendars: string[]; anchors: [number, Uint8Array][] };

class Reader {
  pos = 0;
  private readonly data: Uint8Array;

  constructor(data: Uint8Array) {
    this.data = data;
  }

  take(n: number): Uint8Array {
    if (this.pos + n > this.data.length) throw new ProofError("proof is truncated");
    this.pos += n;
    return this.data.subarray(this.pos - n, this.pos);
  }

  byte(): number {
    return this.take(1)[0] as number;
  }

  varuint(): number {
    let value = 0;
    for (let i = 0; i < MAX_VARUINT_BYTES; i++) {
      const b = this.byte();
      value += (b & 0x7f) * 128 ** i;
      if (!(b & 0x80)) {
        if (value > Number.MAX_SAFE_INTEGER) break;
        return value;
      }
    }
    throw new ProofError("integer is too large");
  }

  varbytes(maxLength: number, minLength = 0): Uint8Array {
    const n = this.varuint();
    if (n < minLength || n > maxLength) throw new ProofError(`field length ${n} is out of range`);
    return this.take(n);
  }

  end(): void {
    if (this.pos !== this.data.length) throw new ProofError("unexpected trailing data");
  }
}

/**
 * Read a detached OpenTimestamps proof (`.ots` file) for a SHA-256 digest.
 *
 * A Bitcoin attestation whose computed root differs from the root supplied for its block is
 * rejected; without a supplied root it never counts as anchored. Throws `ProofError` for another
 * digest or a malformed, truncated or unsupported proof.
 */
export function otsStatus(
  proof: Uint8Array,
  dataSha256: Uint8Array,
  options: OtsStatusOptions = {},
): OtsStatus {
  if (proof.length > MAX_PROOF) throw new ProofError("proof is too large");
  const reader = new Reader(proof);
  if (!equal(reader.take(MAGIC.length), MAGIC)) {
    throw new ProofError("not an OpenTimestamps proof");
  }
  if (reader.varuint() !== 1) throw new ProofError("unsupported proof version");
  if (reader.byte() !== SHA256) throw new ProofError("proof is not for a SHA-256 file hash");
  if (dataSha256.length !== 32 || !equal(reader.take(32), dataSha256)) {
    throw new ProofError("proof is for another digest");
  }
  const found: Found = { calendars: [], anchors: [] };
  readTimestamp(reader, dataSha256, 0, found);
  reader.end();
  if (found.calendars.length === 0 && found.anchors.length === 0) {
    throw new ProofError("proof has no pending or Bitcoin attestation");
  }

  const roots = options.blockMerkleRoots ?? new Map<number, Uint8Array>();
  const verified: number[] = [];
  for (const [height, root] of found.anchors) {
    const expected = roots.get(height);
    if (expected === undefined) continue;
    if (!equal(expected, root)) {
      throw new ProofError(`proof does not match the Merkle root of block ${height}`);
    }
    verified.push(height);
  }
  const calendars = [...new Set(found.calendars)];
  if (verified.length > 0) {
    return {
      kind: "anchored",
      blockHeight: Math.min(...verified),
      calendars,
      unverifiedAnchorHeight: null,
    };
  }
  const claimed = found.anchors.map(([height]) => height);
  return {
    kind: "pending",
    blockHeight: null,
    calendars,
    unverifiedAnchorHeight: claimed.length > 0 ? Math.min(...claimed) : null,
  };
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

function readTimestamp(reader: Reader, msg: Uint8Array, depth: number, found: Found): void {
  let tag = reader.byte();
  while (tag === FORK) {
    readBranch(reader, reader.byte(), msg, depth, found);
    tag = reader.byte();
  }
  readBranch(reader, tag, msg, depth, found);
}

function readBranch(
  reader: Reader,
  tag: number,
  msg: Uint8Array,
  depth: number,
  found: Found,
): void {
  if (tag === 0) {
    readAttestation(reader, msg, found);
    return;
  }
  if (depth === MAX_DEPTH) throw new ProofError("proof is too deep");
  readTimestamp(reader, apply(reader, tag, msg), depth + 1, found);
}

function apply(reader: Reader, tag: number, msg: Uint8Array): Uint8Array {
  let result: Uint8Array;
  const hash = HASHES[tag];
  if (hash) {
    result = hash(msg);
  } else if (tag === APPEND || tag === PREPEND) {
    const arg = reader.varbytes(MAX_MESSAGE, 1);
    result = tag === APPEND ? concatBytes(msg, arg) : concatBytes(arg, msg);
  } else if (tag === REVERSE) {
    result = msg.slice().reverse();
  } else if (tag === HEXLIFY) {
    result = new TextEncoder().encode(bytesToHex(msg));
  } else {
    const name = UNSUPPORTED[tag];
    throw new ProofError(
      name ? `unsupported operation: ${name}` : `unknown operation 0x${tag.toString(16)}`,
    );
  }
  if (result.length > MAX_MESSAGE) throw new ProofError("operation result is too long");
  return result;
}

function readAttestation(reader: Reader, msg: Uint8Array, found: Found): void {
  const tag = bytesToHex(reader.take(8));
  const payload = new Reader(reader.varbytes(MAX_PAYLOAD));
  if (tag === PENDING) {
    const uri = new TextDecoder().decode(payload.varbytes(MAX_URI));
    payload.end();
    if (!URI.test(uri)) throw new ProofError("calendar URL has a forbidden character");
    found.calendars.push(uri);
  } else if (tag === BITCOIN) {
    const height = payload.varuint();
    payload.end();
    if (msg.length !== 32) {
      throw new ProofError("Bitcoin attestation is not on a 32-byte Merkle root");
    }
    found.anchors.push([height, msg]);
  }
}
