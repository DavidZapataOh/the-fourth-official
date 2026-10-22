import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";

const DIGEST_PREFIX = "sha256:";
const SIGNATURE_PREFIX = "ed25519:";
const DIGEST_SIZE = 32;
const SIGNATURE_SIZE = 64;

const BASE64URL = /^[A-Za-z0-9_-]*$/;
const HEX_DIGEST = /^[0-9a-f]{64}$/;

/** Input is not in the exact canonical encoding. */
export class EncodingError extends Error {
  override name = "EncodingError";
}

/** Encode as base64url without padding. */
export function b64urlEncode(data: Uint8Array): string {
  let binary = "";
  for (const byte of data) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

/** Decode canonical unpadded base64url; padding, other alphabets and stray bits are errors. */
export function b64urlDecode(text: string): Uint8Array {
  if (!BASE64URL.test(text) || text.length % 4 === 1) {
    throw new EncodingError("invalid base64url");
  }
  const standard = text.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(standard.padEnd(Math.ceil(standard.length / 4) * 4, "="));
  const data = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  if (b64urlEncode(data) !== text) throw new EncodingError("non-canonical base64url");
  return data;
}

/** Return the SHA-256 digest of `data`. */
export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

/** Format a 32-byte digest as `sha256:` plus lowercase hex. */
export function formatDigest(raw: Uint8Array): string {
  if (raw.length !== DIGEST_SIZE) throw new EncodingError(`digest must be ${DIGEST_SIZE} bytes`);
  return DIGEST_PREFIX + Array.from(raw, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Parse `sha256:` plus 64 lowercase hex digits into the 32 raw bytes. */
export function parseDigest(text: string): Uint8Array {
  const hex = text.slice(DIGEST_PREFIX.length);
  if (!text.startsWith(DIGEST_PREFIX) || !HEX_DIGEST.test(hex)) {
    throw new EncodingError("digest must be 'sha256:' followed by 64 lowercase hex digits");
  }
  return Uint8Array.from(hex.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
}

/** Format a 64-byte signature as `ed25519:` plus base64url. */
export function formatSignature(raw: Uint8Array): string {
  if (raw.length !== SIGNATURE_SIZE) {
    throw new EncodingError(`signature must be ${SIGNATURE_SIZE} bytes`);
  }
  return SIGNATURE_PREFIX + b64urlEncode(raw);
}

/** Parse `ed25519:` plus base64url into the 64 raw signature bytes. */
export function parseSignature(text: string): Uint8Array {
  if (!text.startsWith(SIGNATURE_PREFIX)) {
    throw new EncodingError("signature must start with 'ed25519:'");
  }
  const raw = b64urlDecode(text.slice(SIGNATURE_PREFIX.length));
  if (raw.length !== SIGNATURE_SIZE) {
    throw new EncodingError(`signature must be ${SIGNATURE_SIZE} bytes`);
  }
  return raw;
}
