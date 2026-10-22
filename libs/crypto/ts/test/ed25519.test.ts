import { describe, expect, test } from "vitest";
import {
  generateKeypair,
  keypairFromSeed,
  sign,
  signJson,
  verify,
  verifyJson,
} from "../src/index.ts";
import { vectors } from "./vectors.ts";

type Case = { name: string; seed: string; public: string; message: string; signature: string };
const CASES = (vectors("ed25519") as { cases: Case[] }).cases;

const bytes = (hex: string) =>
  Uint8Array.from(hex.match(/../g) ?? [], (p) => Number.parseInt(p, 16));
const hex = (data: Uint8Array) => Array.from(data, (b) => b.toString(16).padStart(2, "0")).join("");
const flip = (data: Uint8Array, bit: number) => {
  const out = data.slice();
  out[bit >> 3] = (out[bit >> 3] ?? 0) ^ (1 << (bit & 7));
  return out;
};

const first = CASES[0] as Case;
const third = CASES[2] as Case;
const keys = await keypairFromSeed(bytes(first.seed));

describe("RFC 8032 vectors", () => {
  test.each(CASES)("$name", async (c) => {
    const pair = await keypairFromSeed(bytes(c.seed));
    expect(hex(pair.publicKey)).toBe(c.public);
    const signature = await sign(pair.privateKey, bytes(c.message));
    expect(hex(signature)).toBe(c.signature);
    expect(await verify(bytes(c.public), bytes(c.message), bytes(c.signature))).toBe(true);
  });
});

test("verify rejects tampering", async () => {
  const publicKey = bytes(third.public);
  const message = bytes(third.message);
  const signature = bytes(third.signature);
  expect(await verify(publicKey, flip(message, 3), signature)).toBe(false);
  expect(await verify(publicKey, message, flip(signature, 7))).toBe(false);
  expect(await verify(publicKey, message, flip(signature, 8 * 40))).toBe(false);
  expect(await verify(bytes(first.public), message, signature)).toBe(false);
  expect(await verify(publicKey, message, signature.slice(0, 63))).toBe(false);
  expect(await verify(publicKey, message, new Uint8Array([...signature, 0]))).toBe(false);
  expect(await verify(publicKey, message, new Uint8Array())).toBe(false);
});

test("verify rejects malformed public keys", async () => {
  const message = bytes(third.message);
  const signature = bytes(third.signature);
  expect(await verify(new Uint8Array(), message, signature)).toBe(false);
  expect(await verify(new Uint8Array(31), message, signature)).toBe(false);
  expect(await verify(new Uint8Array(33), message, signature)).toBe(false);
});

test("generated key exports and re-imports", async () => {
  const pair = await generateKeypair();
  expect(pair.publicKey.length).toBe(32);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const imported = await crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", true, ["sign"]);
  const message = new TextEncoder().encode("hello");
  const signature = await sign(imported, message);
  expect(await verify(pair.publicKey, message, signature)).toBe(true);
  expect(hex(signature)).toBe(hex(await sign(pair.privateKey, message)));
});

test("wrong-length seed rejected", async () => {
  for (const size of [0, 31, 33]) {
    await expect(keypairFromSeed(new Uint8Array(size))).rejects.toThrow();
  }
});

test("signJson is key-order independent", async () => {
  expect(await signJson(keys.privateKey, { a: 1, b: 2 })).toBe(
    await signJson(keys.privateKey, { b: 2, a: 1 }),
  );
});

test("verifyJson rejects changed value and wrong key", async () => {
  const value = { match: "m1", scores: [1, 2], ok: true };
  const signature = await signJson(keys.privateKey, value);
  expect(
    await verifyJson(keys.publicKey, { ok: true, scores: [1, 2], match: "m1" }, signature),
  ).toBe(true);
  expect(await verifyJson(keys.publicKey, { ...value, match: "m2" }, signature)).toBe(false);
  expect(await verifyJson(bytes((CASES[1] as Case).public), value, signature)).toBe(false);
});

test.each([
  "",
  "ed25519:",
  "ed25519:AAAA",
  `sha256:${"0".repeat(64)}`,
  "garbage",
  `ed25519:${"A".repeat(86)}=`,
])("verifyJson malformed signature %j is false", async (bad) => {
  expect(await verifyJson(keys.publicKey, {}, bad)).toBe(false);
});

test("signature string shape", async () => {
  const signature = await signJson(keys.privateKey, {});
  expect(signature.startsWith("ed25519:")).toBe(true);
  expect(signature.length).toBe(94);
});
