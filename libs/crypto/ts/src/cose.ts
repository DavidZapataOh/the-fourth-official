import { encode, rfc8949EncodeOptions } from "cborg";
import { sign, verify } from "./ed25519.ts";

/** A COSE_Sign1 message is malformed, uses another profile or fails verification. */
export class CoseError extends Error {
  override name = "CoseError";
}

const TAG_SIGN1 = 0xd2;
const ALG_LABEL = 1;
const CRIT_LABEL = 2;
const KID_LABEL = 4;
const ALG_EDDSA = -8;
const SIGNATURE_SIZE = 64;
const FIELD_COUNT = 4;

type Header = Map<number | bigint | string, unknown>;
type Fields = { protectedBytes: Uint8Array; payload: Uint8Array | null; signature: Uint8Array };

const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const ARG_SIZES: Record<number, number | undefined> = { 24: 1, 25: 2, 26: 4, 27: 8 };
const MIN_EXTENDED = 24;
const NULL_BYTE = 0xf6;
const MAX_DEPTH = 32;
const MAJOR_UINT = 0;
const MAJOR_NINT = 1;
const MAJOR_BYTES = 2;
const MAJOR_TEXT = 3;
const MAJOR_ARRAY = 4;
const MAJOR_TAG = 6;
const MAJOR_SIMPLE = 7;

// A small strict CBOR reader instead of a library decoder: cborg and cbor2 disagree on tags,
// simple values, floats, UTF-8 validity and duplicate keys, and both verifiers must accept
// exactly the same inputs. Accepted: integers, byte and text strings, arrays, maps with
// integer or text keys (no duplicates) and null.
function fail(reason: string): never {
  throw new CoseError(reason);
}

function head(data: Uint8Array, pos: number): [number, number | bigint, number] {
  const byte = data[pos];
  if (byte === undefined) return fail("malformed CBOR");
  const major = byte >> 5;
  const info = byte & 0x1f;
  if (info < MIN_EXTENDED) return [major, info, pos + 1];
  const size = ARG_SIZES[info];
  if (size === undefined) return fail("indefinite or reserved length");
  if (pos + 1 + size > data.length) return fail("malformed CBOR");
  let arg = 0n;
  for (let i = 0; i < size; i++) arg = (arg << 8n) | BigInt(data[pos + 1 + i] as number);
  const value = arg <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(arg) : arg;
  return [major, value, pos + 1 + size];
}

function readString(
  data: Uint8Array,
  major: number,
  length: number,
  pos: number,
): [Uint8Array | string, number] {
  if (length > data.length - pos) return fail("malformed CBOR");
  // Uint8Array.prototype.slice always copies; a Node Buffer overrides slice with a view.
  const chunk = Uint8Array.prototype.slice.call(data, pos, pos + length);
  if (major === MAJOR_BYTES) return [chunk, pos + length];
  try {
    return [UTF8.decode(chunk), pos + length];
  } catch {
    return fail("invalid UTF-8");
  }
}

function readContainer(
  data: Uint8Array,
  major: number,
  count: number,
  start: number,
  depth: number,
): [unknown, number] {
  if (count > data.length - start) return fail("malformed CBOR");
  let pos = start;
  if (major === MAJOR_ARRAY) {
    const items: unknown[] = [];
    for (let i = 0; i < count; i++) {
      const [item, next] = read(data, pos, depth + 1);
      items.push(item);
      pos = next;
    }
    return [items, pos];
  }
  const entries = new Map<unknown, unknown>();
  for (let i = 0; i < count; i++) {
    const [key, afterKey] = read(data, pos, depth + 1);
    if (typeof key !== "number" && typeof key !== "bigint" && typeof key !== "string") {
      return fail("map keys must be integers or text");
    }
    if (entries.has(key)) return fail("duplicate map key");
    const [value, afterValue] = read(data, afterKey, depth + 1);
    entries.set(key, value);
    pos = afterValue;
  }
  return [entries, pos];
}

function read(data: Uint8Array, start: number, depth: number): [unknown, number] {
  if (depth > MAX_DEPTH) return fail("nesting too deep");
  const [major, arg, pos] = head(data, start);
  if (major === MAJOR_TAG) return fail("CBOR tags are not allowed");
  if (major === MAJOR_SIMPLE) {
    if (data[start] !== NULL_BYTE)
      return fail("only null is allowed among simple values and floats");
    return [null, pos];
  }
  if (major === MAJOR_UINT) return [arg, pos];
  if (major === MAJOR_NINT) return [typeof arg === "bigint" ? -1n - arg : -1 - arg, pos];
  if (typeof arg === "bigint") return fail("malformed CBOR");
  if (major === MAJOR_BYTES || major === MAJOR_TEXT) return readString(data, major, arg, pos);
  return readContainer(data, major, arg, pos, depth);
}

function decodeItem(data: Uint8Array): unknown {
  const [value, end] = read(data, 0, 0);
  if (end !== data.length) return fail("trailing bytes after CBOR item");
  return value;
}

// Only tag 18 may precede the array, and it is checked on the raw first byte.
function parse(message: Uint8Array): Fields {
  const body = message[0] === TAG_SIGN1 ? message.subarray(1) : message;
  const fields = decodeItem(body);
  if (!Array.isArray(fields) || fields.length !== FIELD_COUNT) {
    throw new CoseError("COSE_Sign1 must be an array of four items");
  }
  const [protectedBytes, unprotected, payload, signature] = fields as unknown[];
  if (!(protectedBytes instanceof Uint8Array) || !(unprotected instanceof Map)) {
    throw new CoseError("malformed headers");
  }
  if (payload !== null && !(payload instanceof Uint8Array)) {
    throw new CoseError("payload must be a byte string");
  }
  if (!(signature instanceof Uint8Array)) throw new CoseError("signature must be a byte string");
  return { protectedBytes, payload, signature };
}

function protectedHeader(protectedBytes: Uint8Array): Header {
  if (protectedBytes.length === 0) return new Map();
  const header = decodeItem(protectedBytes);
  if (!(header instanceof Map)) throw new CoseError("protected header must be a map");
  return header as Header;
}

function toBeSigned(protectedBytes: Uint8Array, payload: Uint8Array): Uint8Array {
  return encode(["Signature1", protectedBytes, new Uint8Array(0), payload], rfc8949EncodeOptions);
}

/**
 * Return a tag-18 COSE_Sign1 message signed with EdDSA over Ed25519.
 * The protected header is `{1: -8, 4: kid}` under CBOR core deterministic encoding.
 */
export async function coseSign1(
  key: CryptoKey,
  payload: Uint8Array,
  kid: Uint8Array,
): Promise<Uint8Array> {
  const protectedBytes = encode(
    new Map<number, number | Uint8Array>([
      [ALG_LABEL, ALG_EDDSA],
      [KID_LABEL, kid],
    ]),
    rfc8949EncodeOptions,
  );
  const signature = await sign(key, toBeSigned(protectedBytes, payload));
  const body = encode([protectedBytes, new Map(), payload, signature], rfc8949EncodeOptions);
  const message = new Uint8Array(body.length + 1);
  message[0] = TAG_SIGN1;
  message.set(body, 1);
  return message;
}

/**
 * Verify a COSE_Sign1 message and return its payload.
 * Accepts tag 18 or an untagged array. Requires `alg` to be EdDSA (-8) in the protected
 * header, an attached payload and a 64-byte signature. Every failure rejects with `CoseError`.
 * Select the public key by `coseKid` first, then verify. Messages are malleable outside the
 * protected header: deduplicate on payload plus kid, never on raw message bytes.
 */
export async function coseVerify1(publicKey: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const { protectedBytes, payload, signature } = parse(message);
  const header = protectedHeader(protectedBytes);
  if (header.get(ALG_LABEL) !== ALG_EDDSA) {
    throw new CoseError("protected header must carry alg EdDSA (-8)");
  }
  if (header.has(CRIT_LABEL)) throw new CoseError("critical headers are not supported");
  if (payload === null) throw new CoseError("detached payloads are not supported");
  if (signature.length !== SIGNATURE_SIZE) throw new CoseError("signature must be 64 bytes");
  if (!(await verify(publicKey, toBeSigned(protectedBytes, payload), signature))) {
    throw new CoseError("signature verification failed");
  }
  return payload;
}

/** Return the `kid` from the protected header; the signature is not checked. */
export function coseKid(message: Uint8Array): Uint8Array {
  const kid = protectedHeader(parse(message).protectedBytes).get(KID_LABEL);
  if (!(kid instanceof Uint8Array)) throw new CoseError("protected header has no kid");
  return kid;
}
