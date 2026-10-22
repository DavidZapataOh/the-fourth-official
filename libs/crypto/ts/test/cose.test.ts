import { describe, expect, test } from "vitest";
import { CoseError, coseKid, coseSign1, coseVerify1, keypairFromSeed } from "../src/index.ts";
import { vectors } from "./vectors.ts";

type Named = { name: string; message: string };
type WgCase = { name: string; public: string; message: string; valid: boolean; payload?: string };
const WG = (vectors("cose_sign1_eddsa") as { cases: WgCase[] }).cases;
const OURS = vectors("cose_sign1_ours") as {
  seed: string;
  public: string;
  other_public: string;
  kid: string;
  payload: string;
  message: string;
  untagged: string;
  tampered: Named[];
  rejected: Named[];
  accepted: Named[];
  kid_missing: Named[];
};

const bytes = (hex: string) =>
  Uint8Array.from(hex.match(/../g) ?? [], (p) => Number.parseInt(p, 16));
const hex = (data: Uint8Array) => Array.from(data, (b) => b.toString(16).padStart(2, "0")).join("");
const PUBLIC = bytes(OURS.public);
const MESSAGE = bytes(OURS.message);
const PAYLOAD = bytes(OURS.payload);

describe("cose-wg examples", () => {
  test.each(WG)("$name", async (c) => {
    const verified = coseVerify1(bytes(c.public), bytes(c.message));
    if (c.valid) expect(hex(await verified)).toBe(c.payload);
    else await expect(verified).rejects.toBeInstanceOf(CoseError);
  });
});

describe("our vector", () => {
  test("sign matches the Python bytes", async () => {
    const { privateKey } = await keypairFromSeed(bytes(OURS.seed));
    const message = await coseSign1(privateKey, PAYLOAD, bytes(OURS.kid));
    expect(hex(message)).toBe(OURS.message);
  });

  test("round trip returns the payload", async () => {
    expect(hex(await coseVerify1(PUBLIC, MESSAGE))).toBe(OURS.payload);
    const { privateKey, publicKey } = await keypairFromSeed(bytes(OURS.seed));
    const empty = await coseSign1(privateKey, new Uint8Array(0), Uint8Array.of(1));
    expect((await coseVerify1(publicKey, empty)).length).toBe(0);
  });

  test("accepts an untagged array", async () => {
    expect(hex(await coseVerify1(PUBLIC, bytes(OURS.untagged)))).toBe(OURS.payload);
  });

  test("coseKid reads the protected header", () => {
    expect(hex(coseKid(MESSAGE))).toBe(OURS.kid);
  });

  test.each(OURS.kid_missing)("coseKid requires a protected kid: $name", (c) => {
    expect(() => coseKid(bytes(c.message))).toThrow(CoseError);
  });

  test.each(OURS.accepted)("accepts valid variant: $name", async (c) => {
    expect(hex(await coseVerify1(PUBLIC, bytes(c.message)))).toBe(OURS.payload);
  });

  test.each(OURS.tampered)("rejects tampering: $name", async (c) => {
    await expect(coseVerify1(PUBLIC, bytes(c.message))).rejects.toBeInstanceOf(CoseError);
  });

  test.each(OURS.rejected)("rejects misuse: $name", async (c) => {
    await expect(coseVerify1(PUBLIC, bytes(c.message))).rejects.toBeInstanceOf(CoseError);
  });

  test("rejects the wrong or malformed public key", async () => {
    await expect(coseVerify1(bytes(OURS.other_public), MESSAGE)).rejects.toBeInstanceOf(CoseError);
    await expect(coseVerify1(PUBLIC.slice(0, 31), MESSAGE)).rejects.toBeInstanceOf(CoseError);
  });

  test("every truncation raises CoseError", async () => {
    for (let length = 0; length < MESSAGE.length; length++) {
      await expect(coseVerify1(PUBLIC, MESSAGE.slice(0, length))).rejects.toBeInstanceOf(CoseError);
    }
  });

  test("every bit flip is rejected", async () => {
    for (let bit = 0; bit < MESSAGE.length * 8; bit++) {
      const flipped = MESSAGE.slice();
      flipped[bit >> 3] = (flipped[bit >> 3] ?? 0) ^ (1 << (bit & 7));
      await expect(coseVerify1(PUBLIC, flipped)).rejects.toBeInstanceOf(CoseError);
    }
  });

  test.each([[""], ["ff"], ["84"], ["a0"], ["d2"], ["00"], ["8400000000"], ["9fff"]])(
    "garbage %j raises CoseError",
    async (garbage) => {
      await expect(coseVerify1(PUBLIC, bytes(garbage))).rejects.toBeInstanceOf(CoseError);
      expect(() => coseKid(bytes(garbage))).toThrow(CoseError);
    },
  );

  test("returned payload and kid do not alias the caller's buffer", async () => {
    const buffer = Buffer.from(OURS.message, "hex");
    const payload = await coseVerify1(PUBLIC, buffer);
    const kid = coseKid(buffer);
    buffer.fill(0);
    expect(hex(payload)).toBe(OURS.payload);
    expect(hex(kid)).toBe(OURS.kid);
  });

  test("deeply nested input raises CoseError", async () => {
    const nested = new Uint8Array(200).fill(0x81);
    await expect(coseVerify1(PUBLIC, nested)).rejects.toBeInstanceOf(CoseError);
    expect(() => coseKid(nested)).toThrow(CoseError);
  });
});
