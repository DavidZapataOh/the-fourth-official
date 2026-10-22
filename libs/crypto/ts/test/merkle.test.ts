import { sha256 } from "@noble/hashes/sha2.js";
import fc from "fast-check";
import { describe, expect, test } from "vitest";
import {
  canonicalize,
  consistencyProof,
  EMPTY_ROOT,
  inclusionProof,
  jsonLeafHash,
  leafHash,
  merkleRoot,
  nodeHash,
  verifyConsistency,
  verifyInclusion,
} from "../src/index.ts";
import { oracleConsistency, oraclePath, oracleRoot } from "./oracle.ts";
import { vectors } from "./vectors.ts";

type InclusionCase = {
  name: string;
  index: number;
  size: number;
  leaf_hash: string;
  root: string;
  proof: string[];
  valid: boolean;
};
type ConsistencyCase = {
  name: string;
  old_size: number;
  new_size: number;
  old_root: string;
  new_root: string;
  proof: string[];
  valid: boolean;
};
const VEC = vectors("merkle") as {
  leaves: string[];
  roots: string[];
  inclusion: InclusionCase[];
  consistency: ConsistencyCase[];
};

const fromHex = (text: string) =>
  Uint8Array.from(text.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
const hex = (data: Uint8Array) => Array.from(data, (b) => b.toString(16).padStart(2, "0")).join("");
const cat = (...parts: Uint8Array[]) => Uint8Array.from(parts.flatMap((p) => Array.from(p)));
const flip = (data: Uint8Array, bit = 0) => {
  const out = data.slice();
  out[bit >> 3] = (out[bit >> 3] ?? 0) ^ (1 << (bit & 7));
  return out;
};
const digest = (i: number) => sha256(Uint8Array.of(i & 255, i >> 8));
const POOL = Array.from({ length: 300 }, (_, i) => digest(i));
const LEAVES = VEC.leaves.map((d) => leafHash(fromHex(d)));

function mutateProof(proof: Uint8Array[]): Uint8Array[][] {
  return [
    ...proof.map((_, i) => proof.map((node, j) => (i === j ? flip(node, 3) : node))),
    [...proof, digest(1000)],
    [digest(1000), ...proof],
    ...proof.map((_, i) => proof.filter((_node, j) => i !== j)),
  ];
}

test("primitives", () => {
  expect(hex(EMPTY_ROOT)).toBe(hex(sha256(new Uint8Array())));
  expect(leafHash(Uint8Array.of(97))).toEqual(sha256(Uint8Array.of(0, 97)));
  const a = digest(0);
  const b = digest(1);
  expect(nodeHash(a, b)).toEqual(sha256(cat(Uint8Array.of(1), a, b)));
  expect(jsonLeafHash({ b: 1, a: [2] })).toEqual(leafHash(canonicalize({ a: [2], b: 1 })));
  expect(() => nodeHash(new Uint8Array(3), b)).toThrow(RangeError);
});

test("empty tree root", () => {
  expect(merkleRoot([])).toEqual(sha256(new Uint8Array()));
});

test("mutating a returned root does not affect later results", () => {
  const empty = merkleRoot([]);
  empty[0] = (empty[0] ?? 0) ^ 1;
  expect(merkleRoot([])).toEqual(sha256(new Uint8Array()));
  expect(EMPTY_ROOT).toEqual(sha256(new Uint8Array()));
  const leaf = digest(0);
  const single = merkleRoot([leaf]);
  single[0] = (single[0] ?? 0) ^ 1;
  expect(leaf).toEqual(digest(0));
});

test("the size must be bound by the signed statement", () => {
  // RFC 9162 accepts leaf 0 of a 3-leaf tree at size 4 with the same proof (the last leaf
  // stands in for a subtree), so callers must take the size from the same signed
  // statement as the root.
  const leaves = POOL.slice(0, 3);
  const root = merkleRoot(leaves);
  const proof = inclusionProof(leaves, 0);
  expect(verifyInclusion(leaves[0] as Uint8Array, 0, 3, proof, root)).toBe(true);
  expect(verifyInclusion(leaves[0] as Uint8Array, 0, 4, proof, root)).toBe(true);
});

describe("reference vectors", () => {
  test.each(VEC.roots.map((root, size) => ({ root, size })))("root of size $size", (c) => {
    expect(hex(merkleRoot(LEAVES.slice(0, c.size)))).toBe(c.root);
  });

  test.each(VEC.inclusion)("inclusion $name", (c) => {
    const leaf = fromHex(c.leaf_hash);
    const root = fromHex(c.root);
    const proof = c.proof.map(fromHex);
    if (leaf.length !== 32 || root.length !== 32) {
      expect(() => verifyInclusion(leaf, c.index, c.size, proof, root)).toThrow(RangeError);
      return;
    }
    expect(verifyInclusion(leaf, c.index, c.size, proof, root)).toBe(c.valid);
    if (c.valid) expect(inclusionProof(LEAVES.slice(0, c.size), c.index)).toEqual(proof);
  });

  test.each(VEC.consistency)("consistency $name", (c) => {
    const oldRoot = fromHex(c.old_root);
    const newRoot = fromHex(c.new_root);
    const proof = c.proof.map(fromHex);
    if (oldRoot.length !== 32 || newRoot.length !== 32) {
      expect(() => verifyConsistency(c.old_size, c.new_size, oldRoot, newRoot, proof)).toThrow(
        RangeError,
      );
      return;
    }
    expect(verifyConsistency(c.old_size, c.new_size, oldRoot, newRoot, proof)).toBe(c.valid);
    if (c.valid) {
      expect(consistencyProof(LEAVES.slice(0, c.new_size), c.old_size)).toEqual(proof);
    }
  });
});

describe("against the recursive oracle", () => {
  test("every size 0..300", () => {
    for (let n = 0; n <= 300; n++) {
      expect(merkleRoot(POOL.slice(0, n))).toEqual(oracleRoot(POOL.slice(0, n)));
    }
  });

  const digestArb = fc.uint8Array({ minLength: 32, maxLength: 32 });

  test("random leaves, root", () => {
    fc.assert(
      fc.property(fc.array(digestArb, { maxLength: 300 }), (leaves) => {
        expect(merkleRoot(leaves)).toEqual(oracleRoot(leaves));
      }),
      { numRuns: 150 },
    );
  });

  test("random leaves, proofs", () => {
    fc.assert(
      fc.property(
        fc.array(digestArb, { minLength: 1, maxLength: 80 }),
        fc.nat(),
        fc.nat(),
        (leaves, a, b) => {
          const i = a % leaves.length;
          const m = (b % leaves.length) + 1;
          expect(inclusionProof(leaves, i)).toEqual(oraclePath(i, leaves));
          expect(consistencyProof(leaves, m)).toEqual(oracleConsistency(m, leaves));
        },
      ),
      { numRuns: 150 },
    );
  });
});

describe("inclusion", () => {
  test("every index of every size 1..65 round-trips", () => {
    for (let n = 1; n <= 65; n++) {
      const leaves = POOL.slice(0, n);
      const root = merkleRoot(leaves);
      for (let i = 0; i < n; i++) {
        expect(
          verifyInclusion(leaves[i] as Uint8Array, i, n, inclusionProof(leaves, i), root),
        ).toBe(true);
      }
    }
  });

  test("mutations are rejected", () => {
    for (let n = 1; n <= 20; n++) {
      const leaves = POOL.slice(0, n);
      const root = merkleRoot(leaves);
      for (let i = 0; i < n; i++) {
        const leaf = leaves[i] as Uint8Array;
        const proof = inclusionProof(leaves, i);
        for (const bad of mutateProof(proof)) {
          expect(verifyInclusion(leaf, i, n, bad, root)).toBe(false);
        }
        expect(verifyInclusion(flip(leaf), i, n, proof, root)).toBe(false);
        expect(verifyInclusion(leaf, i, n, proof, flip(root))).toBe(false);
        for (let j = 0; j < n; j++) {
          if (j !== i) expect(verifyInclusion(leaf, j, n, proof, root)).toBe(false);
        }
        // Only the proof length is tied to the size: a size with the same path length can
        // collapse a sibling subtree into one node and change which index verifies, so it is
        // checked only when the length differs.
        for (const size of [0, n - 1, n + 1, 2 * n]) {
          if (size <= i || oraclePath(i, POOL.slice(0, size)).length !== proof.length) {
            expect(verifyInclusion(leaf, i, size, proof, root)).toBe(false);
          }
        }
      }
    }
  });

  test("a node hash is not a valid leaf", () => {
    const a = digest(0);
    const b = digest(1);
    const root = merkleRoot([a, b]);
    expect(root).toEqual(nodeHash(a, b));
    expect(verifyInclusion(nodeHash(a, b), 0, 2, [], root)).toBe(false);
    expect(verifyInclusion(nodeHash(a, b), 0, 2, [digest(2)], root)).toBe(false);
    const forged = cat(Uint8Array.of(1), a, b);
    expect(leafHash(forged)).not.toEqual(nodeHash(a, b));
    expect(verifyInclusion(leafHash(forged), 0, 1, [], root)).toBe(false);
  });
});

describe("consistency", () => {
  test("every pair 1 <= old <= new <= 40 round-trips", () => {
    for (let n = 1; n <= 40; n++) {
      const leaves = POOL.slice(0, n);
      const newRoot = merkleRoot(leaves);
      for (let old = 1; old <= n; old++) {
        const proof = consistencyProof(leaves, old);
        expect(verifyConsistency(old, n, merkleRoot(leaves.slice(0, old)), newRoot, proof)).toBe(
          true,
        );
      }
    }
  });

  test("mutations are rejected", () => {
    for (let n = 2; n <= 20; n++) {
      const leaves = POOL.slice(0, n);
      const newRoot = merkleRoot(leaves);
      for (let old = 1; old <= n; old++) {
        const oldRoot = merkleRoot(leaves.slice(0, old));
        const proof = consistencyProof(leaves, old);
        for (const bad of mutateProof(proof)) {
          expect(verifyConsistency(old, n, oldRoot, newRoot, bad)).toBe(false);
        }
        expect(verifyConsistency(old, n, flip(oldRoot), newRoot, proof)).toBe(false);
        expect(verifyConsistency(old, n, oldRoot, flip(newRoot), proof)).toBe(false);
        if (old !== n) expect(verifyConsistency(old, n, newRoot, oldRoot, proof)).toBe(false);
        const wrong: [number, number][] = [];
        for (let o = 0; o <= n + 1; o++) wrong.push([o, n]);
        wrong.push([old, n + 1]);
        for (const [o, m] of wrong) {
          if (o === old && m === n) continue;
          const shape = o >= 1 && o <= m ? oracleConsistency(o, POOL.slice(0, m)) : undefined;
          if (shape === undefined || shape.length !== proof.length) {
            expect(verifyConsistency(o, m, oldRoot, newRoot, proof)).toBe(false);
          }
        }
      }
    }
  });
});

test("out-of-range arguments", () => {
  const leaves = POOL.slice(0, 5);
  const root = merkleRoot(leaves);
  const proof = inclusionProof(leaves, 2);
  const leaf = leaves[2] as Uint8Array;
  expect(() => inclusionProof(leaves, 5)).toThrow(RangeError);
  expect(() => inclusionProof(leaves, -1)).toThrow(RangeError);
  expect(() => inclusionProof(leaves, 1.5)).toThrow(RangeError);
  expect(() => inclusionProof([], 0)).toThrow(RangeError);
  for (const old of [0, 6, -1, Number.NaN]) {
    expect(() => consistencyProof(leaves, old)).toThrow(RangeError);
  }
  expect(() => merkleRoot([new Uint8Array(3)])).toThrow(RangeError);
  expect(() => inclusionProof([new Uint8Array(3)], 0)).toThrow(RangeError);

  expect(verifyInclusion(leaf, 5, 5, proof, root)).toBe(false);
  expect(verifyInclusion(leaf, 2 ** 64, 2 ** 64 + 1, proof, root)).toBe(false);
  expect(verifyInclusion(leaf, 0, 0, [], root)).toBe(false);
  for (const [i, s] of [
    [-1, 5],
    [2, -1],
    [Number.NaN, 5],
    [2, Number.POSITIVE_INFINITY],
    [1.5, 5],
  ] as const) {
    expect(() => verifyInclusion(leaf, i, s, proof, root)).toThrow(RangeError);
  }
  expect(() => verifyInclusion(new Uint8Array(3), 2, 5, proof, root)).toThrow(RangeError);
  expect(() => verifyInclusion(leaf, 2, 5, proof, new Uint8Array(3))).toThrow(RangeError);
  expect(verifyInclusion(leaf, 2, 5, [...proof.slice(0, -1), new Uint8Array(3)], root)).toBe(false);

  const oldRoot = merkleRoot(leaves.slice(0, 3));
  const cproof = consistencyProof(leaves, 3);
  expect(verifyConsistency(3, 5, oldRoot, root, cproof)).toBe(true);
  expect(verifyConsistency(0, 5, oldRoot, root, cproof)).toBe(false);
  expect(verifyConsistency(6, 5, oldRoot, root, cproof)).toBe(false);
  expect(verifyConsistency(3, 3, oldRoot, root, [])).toBe(false);
  expect(verifyConsistency(5, 5, root, root, [])).toBe(true);
  expect(verifyConsistency(5, 5, root, root, [root])).toBe(false);
  expect(verifyConsistency(1, 2 ** 64, oldRoot, root, cproof)).toBe(false);
  expect(() => verifyConsistency(-1, 5, oldRoot, root, cproof)).toThrow(RangeError);
  expect(() => verifyConsistency(3, 5, new Uint8Array(3), root, cproof)).toThrow(RangeError);
});
