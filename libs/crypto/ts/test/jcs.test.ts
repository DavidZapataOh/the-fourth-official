import { describe, expect, test } from "vitest";
import { CanonicalizationError, canonicalize, type JsonValue } from "../src/index.ts";
import { vectors } from "./vectors.ts";

const hex = (data: Uint8Array) => Array.from(data, (b) => b.toString(16).padStart(2, "0")).join("");

type Case = { name: string; input: JsonValue; expected_hex: string };
const V = vectors("jcs") as {
  rfc_examples: (Case & { expected_order?: string[] })[];
  structure: Case[];
  unicode: Case[];
  numbers: { bits: string; expected: string }[];
  rejected: { name: string; kind: string; value: string; where?: string }[];
};

describe("documented examples", () => {
  test.each([...V.rfc_examples, ...V.structure, ...V.unicode])("$name", (c) => {
    expect(hex(canonicalize(c.input))).toBe(c.expected_hex);
  });
});

test("sorting example order", () => {
  const c = V.rfc_examples[1] as Case & { expected_order: string[] };
  const text = new TextDecoder().decode(canonicalize(c.input));
  const positions = c.expected_order.map((v) => text.indexOf(v));
  expect(positions).toEqual([...positions].sort((a, b) => a - b));
});

const floatFromBits = (bits: string) =>
  new DataView(
    Uint8Array.from(bits.match(/../g) ?? [], (p) => Number.parseInt(p, 16)).buffer,
  ).getFloat64(0);

describe("Appendix B numbers", () => {
  test.each(V.numbers)("$bits", (c) => {
    expect(new TextDecoder().decode(canonicalize(floatFromBits(c.bits)))).toBe(c.expected);
  });
});

test("keys sorted by UTF-16 code units", () => {
  const emoji = String.fromCodePoint(0x1f600);
  const dalet = String.fromCharCode(0xfb33);
  const text = new TextDecoder().decode(canonicalize({ [dalet]: 1, [emoji]: 2 }));
  expect(text).toBe(`{"${emoji}":2,"${dalet}":1}`);
});

const rejectedValue = (c: (typeof V.rejected)[number]): unknown => {
  switch (c.kind) {
    case "float_bits":
      return floatFromBits(c.value);
    case "integer":
      return BigInt(c.value);
    case "lone_surrogate": {
      const text = `a${String.fromCharCode(Number.parseInt(c.value, 16))}b`;
      if (c.where === "key") return { [text]: 1 };
      if (c.where === "nested") return { k: [1, [text]] };
      return text;
    }
    default:
      throw new Error(c.kind);
  }
};

describe("rejected values", () => {
  test.each(V.rejected)("$name", (c) => {
    expect(() => canonicalize(rejectedValue(c) as JsonValue)).toThrow(CanonicalizationError);
  });
});

test.each([undefined, () => 1, Symbol("s"), new Date(0), new Map(), new Uint8Array(1)])(
  "non-JSON value %#",
  (value) => {
    expect(() => canonicalize(value as unknown as JsonValue)).toThrow(CanonicalizationError);
  },
);

test("circular reference rejected", () => {
  const loop: unknown[] = [];
  loop.push(loop);
  expect(() => canonicalize(loop as JsonValue)).toThrow(CanonicalizationError);
});

test("negative zero is zero", () => {
  expect(new TextDecoder().decode(canonicalize(-0))).toBe("0");
});

test.each([Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, 1, -1])(
  "integer %d round-trips",
  (n) => {
    expect(new TextDecoder().decode(canonicalize(n))).toBe(String(n));
  },
);

test("2^53 is accepted as a number", () => {
  expect(new TextDecoder().decode(canonicalize(2 ** 53))).toBe("9007199254740992");
});

test("deeply nested input raises CanonicalizationError", () => {
  let value: JsonValue = 1;
  for (let i = 0; i < 100_000; i++) value = [value];
  expect(() => canonicalize(value)).toThrow(CanonicalizationError);
});
