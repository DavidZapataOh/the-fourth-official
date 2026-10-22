import { describe, expect, test } from "vitest";
import {
  b64urlDecode,
  b64urlEncode,
  EncodingError,
  formatDigest,
  formatSignature,
  parseDigest,
  parseSignature,
  sha256,
} from "../src/index.ts";
import { vectors } from "./vectors.ts";

const hex = (data: Uint8Array) => Array.from(data, (b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (text: string) =>
  Uint8Array.from(text.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));

const { valid, invalid } = vectors("base64url") as {
  valid: { hex: string; b64url: string }[];
  invalid: { name: string; text: string }[];
};

test("sha256 known answer", () => {
  expect(hex(sha256(new TextEncoder().encode("abc")))).toBe(
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
});

describe("base64url", () => {
  test.each(valid)("vector $hex", (c) => {
    expect(b64urlEncode(fromHex(c.hex))).toBe(c.b64url);
    expect(hex(b64urlDecode(c.b64url))).toBe(c.hex);
  });

  test("round trips every length from 0 to 64", () => {
    for (let n = 0; n <= 64; n++) {
      const data = Uint8Array.from({ length: n }, (_, i) => (i * 7 + 3) % 256);
      const text = b64urlEncode(data);
      expect(text).not.toContain("=");
      expect(b64urlDecode(text)).toEqual(data);
    }
  });

  test.each(invalid)("rejects $name", (c) => {
    expect(() => b64urlDecode(c.text)).toThrow(EncodingError);
  });
});

describe("digest", () => {
  const empty = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  test("format and parse", () => {
    expect(formatDigest(sha256(new Uint8Array()))).toBe(empty);
    expect(parseDigest(empty)).toEqual(sha256(new Uint8Array()));
  });

  test.each([
    empty.toUpperCase().replace("SHA256", "sha256"),
    empty.slice(7),
    `sha256:${"a".repeat(63)}`,
    `sha256:${"a".repeat(65)}`,
    `sha256:${"g".repeat(64)}`,
  ])("parseDigest rejects %s", (text) => {
    expect(() => parseDigest(text)).toThrow(EncodingError);
  });

  test("formatDigest rejects wrong length", () => {
    expect(() => formatDigest(new Uint8Array(31))).toThrow(EncodingError);
  });
});

describe("signature", () => {
  test("format length and round trip", () => {
    const text = formatSignature(new Uint8Array(64));
    expect(text.startsWith("ed25519:")).toBe(true);
    expect(text).toHaveLength(8 + 86);
    expect(parseSignature(text)).toEqual(new Uint8Array(64));
    for (const n of [63, 65]) {
      expect(() => formatSignature(new Uint8Array(n))).toThrow(EncodingError);
    }
  });

  test.each([
    `ed25519:${"A".repeat(85)}`,
    `ed25519:${"A".repeat(87)}`,
    `sha256:${"A".repeat(86)}`,
    "A".repeat(86),
    `ed25519:${"A".repeat(85)}B`,
  ])("parseSignature rejects %s", (text) => {
    expect(() => parseSignature(text)).toThrow(EncodingError);
  });
});
