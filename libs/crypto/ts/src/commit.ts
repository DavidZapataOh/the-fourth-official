import { sha256 } from "./encoding.ts";

const CHAIN_PREFIX = new TextEncoder().encode("fourth/chain/v1\u0000");
const MAX_PART = 0xffffffff;
const HASH_SIZE = 32;
const LONE_SURROGATE = /\p{Surrogate}/u;

/**
 * Domain-separated SHA-256 commitment over length-prefixed parts:
 * `sha256(utf8(domain) || 0x00 || for each part: uint32_be(len(part)) || part)`.
 * The length prefix makes the part boundaries unambiguous.
 *
 * @throws RangeError if `domain` contains a NUL byte or a lone surrogate, or a part exceeds 2^32-1 bytes.
 */
export function commitment(domain: string, ...parts: Uint8Array[]): Uint8Array {
  if (domain.includes("\u0000")) throw new RangeError("domain must not contain a NUL byte");
  if (LONE_SURROGATE.test(domain)) throw new RangeError("domain must not contain a lone surrogate");
  for (const part of parts) {
    if (part.length > MAX_PART) throw new RangeError("part exceeds 2^32-1 bytes");
  }
  const head = new TextEncoder().encode(`${domain}\u0000`);
  const buf = new Uint8Array(head.length + parts.reduce((n, p) => n + 4 + p.length, 0));
  const view = new DataView(buf.buffer);
  buf.set(head);
  let offset = head.length;
  for (const part of parts) {
    view.setUint32(offset, part.length);
    buf.set(part, offset + 4);
    offset += 4 + part.length;
  }
  return sha256(buf);
}

/**
 * Next link of a hash chain: `sha256("fourth/chain/v1\0" || prevHash || data)`.
 *
 * @throws RangeError if `prevHash` is not exactly 32 bytes.
 */
export function chainHash(prevHash: Uint8Array, data: Uint8Array): Uint8Array {
  if (prevHash.length !== HASH_SIZE) throw new RangeError("prevHash must be 32 bytes");
  const buf = new Uint8Array(CHAIN_PREFIX.length + HASH_SIZE + data.length);
  buf.set(CHAIN_PREFIX);
  buf.set(prevHash, CHAIN_PREFIX.length);
  buf.set(data, CHAIN_PREFIX.length + HASH_SIZE);
  return sha256(buf);
}
