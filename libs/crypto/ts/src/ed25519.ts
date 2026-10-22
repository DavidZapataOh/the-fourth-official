import { b64urlDecode, EncodingError, formatSignature, parseSignature } from "./encoding.ts";
import { canonicalize, type JsonValue } from "./jcs.ts";

/** A signing key plus its 32-byte raw public key. */
export type Keypair = { privateKey: CryptoKey; publicKey: Uint8Array };

// WebCrypto's BufferSource rejects shared buffers, so inputs are copied into plain ArrayBuffers.
// DER header of an Ed25519 PKCS#8 PrivateKeyInfo; the 32-byte seed follows.
const PKCS8_PREFIX = Uint8Array.of(
  0x30,
  0x2e,
  0x02,
  0x01,
  0x00,
  0x30,
  0x05,
  0x06,
  0x03,
  0x2b,
  0x65,
  0x70,
  0x04,
  0x22,
  0x04,
  0x20,
);
const SEED_SIZE = 32;

async function publicKeyOf(privateKey: CryptoKey): Promise<Uint8Array> {
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  if (jwk.x === undefined) throw new EncodingError("key export has no public part");
  return b64urlDecode(jwk.x);
}

/** Generate an extractable Ed25519 keypair. */
export async function generateKeypair(): Promise<Keypair> {
  const privateKey = (await crypto.subtle.generateKey("Ed25519", true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  return { privateKey: privateKey.privateKey, publicKey: await publicKeyOf(privateKey.privateKey) };
}

/** Import a 32-byte seed as a signing key. Rejects on a wrong-length seed. */
export async function keypairFromSeed(seed: Uint8Array): Promise<Keypair> {
  if (seed.length !== SEED_SIZE) throw new RangeError("seed must be 32 bytes");
  const pkcs8 = new Uint8Array(PKCS8_PREFIX.length + SEED_SIZE);
  pkcs8.set(PKCS8_PREFIX);
  pkcs8.set(seed, PKCS8_PREFIX.length);
  const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", true, ["sign"]);
  return { privateKey, publicKey: await publicKeyOf(privateKey) };
}

/** Return the 64-byte Ed25519 signature of `message`. */
export async function sign(key: CryptoKey, message: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign("Ed25519", key, new Uint8Array(message)));
}

/** Check a signature. Malformed keys or signatures resolve to `false`; this never rejects. */
export async function verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey("raw", new Uint8Array(publicKey), "Ed25519", false, [
      "verify",
    ]);
    return await crypto.subtle.verify(
      "Ed25519",
      key,
      new Uint8Array(signature),
      new Uint8Array(message),
    );
  } catch {
    return false;
  }
}

/**
 * Sign the RFC 8785 canonical bytes of `value`; returns `ed25519:` plus base64url.
 * Integer fields must stay at or below 2^53-1 so that both languages canonicalize them identically.
 */
export async function signJson(key: CryptoKey, value: JsonValue): Promise<string> {
  return formatSignature(await sign(key, canonicalize(value)));
}

/** Verify a `signJson` signature; a malformed signature string resolves to `false`. */
export async function verifyJson(
  publicKey: Uint8Array,
  value: JsonValue,
  signature: string,
): Promise<boolean> {
  let raw: Uint8Array;
  try {
    raw = parseSignature(signature);
  } catch (error) {
    if (error instanceof EncodingError) return false;
    throw error;
  }
  return verify(publicKey, canonicalize(value), raw);
}
