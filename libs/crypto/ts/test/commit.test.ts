import { describe, expect, test } from "vitest";
import { chainHash, commitment } from "../src/index.ts";
import { vectors } from "./vectors.ts";

type Named = { name: string };
type CommitmentCase = Named & { domain: string; parts: string[]; expected: string };
type ChainCase = Named & { prev: string; data: string; expected: string };

const VEC = vectors("commitment") as { commitments: CommitmentCase[]; chains: ChainCase[] };

const fromHex = (hex: string) =>
  Uint8Array.from(hex.match(/../g) ?? [], (p) => Number.parseInt(p, 16));
const toHex = (bytes: Uint8Array) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const text = (s: string) => new TextEncoder().encode(s);

describe("commitment", () => {
  test.each(VEC.commitments)("known answer: $name", (c) => {
    expect(toHex(commitment(c.domain, ...c.parts.map(fromHex)))).toBe(c.expected);
  });

  test("removes concatenation ambiguity", () => {
    expect(commitment("d", text("ab"), text("c"))).not.toEqual(
      commitment("d", text("a"), text("bc")),
    );
  });

  test("separates domains", () => {
    expect(commitment("fourth/seed/v1", text("x"))).not.toEqual(
      commitment("fourth/call/v1", text("x")),
    );
  });

  test("distinguishes empty parts", () => {
    expect(commitment("d", text(""), text("a"))).not.toEqual(commitment("d", text("a"), text("")));
    expect(commitment("d")).not.toEqual(commitment("d", text("")));
  });

  test("rejects a domain containing NUL", () => {
    expect(() => commitment("a\u0000b", text("x"))).toThrow(RangeError);
  });

  test.each([0xd800, 0xdbff, 0xdc00, 0xdfff])(
    "rejects a lone surrogate in the domain (%i)",
    (unit) => {
      expect(() => commitment(`a${String.fromCharCode(unit)}`, text("x"))).toThrow(RangeError);
    },
  );

  test("accepts an astral character in the domain", () => {
    expect(commitment("a\u{1F600}", text("x"))).toHaveLength(32);
  });

  test("rejects a part longer than 2^32-1 bytes", () => {
    const huge = Object.defineProperty(new Uint8Array(0), "length", { value: 2 ** 32 });
    expect(() => commitment("d", huge)).toThrow(RangeError);
  });
});

describe("chainHash", () => {
  test.each(VEC.chains)("known answer: $name", (c) => {
    expect(toHex(chainHash(fromHex(c.prev), fromHex(c.data)))).toBe(c.expected);
  });

  test.each([0, 5, 31, 33])("requires a 32-byte previous hash (%i)", (n) => {
    expect(() => chainHash(new Uint8Array(n), text("x"))).toThrow(RangeError);
  });

  test("depends on order", () => {
    const a = new Uint8Array(32);
    const b = new Uint8Array(32).fill(1);
    expect(chainHash(a, b)).not.toEqual(chainHash(b, a));
  });
});
