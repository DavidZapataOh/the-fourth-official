// Independent RFC 6962 reference: the direct recursive definitions of section 2.1.
import { sha256 } from "@noble/hashes/sha2.js";

const concat = (...parts: Uint8Array[]) => Uint8Array.from(parts.flatMap((p) => Array.from(p)));

function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

export function oracleRoot(leaves: readonly Uint8Array[]): Uint8Array {
  if (leaves.length === 0) return sha256(new Uint8Array());
  if (leaves.length === 1) return leaves[0] as Uint8Array;
  const k = split(leaves.length);
  return sha256(
    concat(Uint8Array.of(1), oracleRoot(leaves.slice(0, k)), oracleRoot(leaves.slice(k))),
  );
}

export function oraclePath(m: number, leaves: readonly Uint8Array[]): Uint8Array[] {
  if (leaves.length === 1) return [];
  const k = split(leaves.length);
  return m < k
    ? [...oraclePath(m, leaves.slice(0, k)), oracleRoot(leaves.slice(k))]
    : [...oraclePath(m - k, leaves.slice(k)), oracleRoot(leaves.slice(0, k))];
}

function subproof(m: number, leaves: readonly Uint8Array[], complete: boolean): Uint8Array[] {
  if (m === leaves.length) return complete ? [] : [oracleRoot(leaves)];
  const k = split(leaves.length);
  return m <= k
    ? [...subproof(m, leaves.slice(0, k), complete), oracleRoot(leaves.slice(k))]
    : [...subproof(m - k, leaves.slice(k), false), oracleRoot(leaves.slice(0, k))];
}

export function oracleConsistency(m: number, leaves: readonly Uint8Array[]): Uint8Array[] {
  return subproof(m, leaves, true);
}
