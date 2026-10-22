import { sha256 } from "./encoding.ts";
import { canonicalize, type JsonValue } from "./jcs.ts";

export const EMPTY_ROOT: Uint8Array = sha256(new Uint8Array());
const EMPTY = sha256(new Uint8Array());

const DIGEST_SIZE = 32;
const LEAF = 0;
const NODE = 1;
// No tree can hold more leaves than this, so larger sizes and indexes never verify.
const MAX_SIZE = Number.MAX_SAFE_INTEGER;

/** Hash leaf data: `sha256(0x00 || data)`. */
export function leafHash(data: Uint8Array): Uint8Array {
  return hashWithPrefix(LEAF, data);
}

/**
 * Hash two child digests: `sha256(0x01 || left || right)`.
 * @throws RangeError A child is not 32 bytes.
 */
export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  checkDigest(left);
  checkDigest(right);
  return hashWithPrefix(NODE, left, right);
}

/** Hash a JSON value as a leaf, through its RFC 8785 canonical form. */
export function jsonLeafHash(value: JsonValue): Uint8Array {
  return leafHash(canonicalize(value));
}

/**
 * Merkle tree hash of leaf hashes; the empty tree hashes to `sha256("")`.
 * @throws RangeError A leaf hash is not 32 bytes.
 */
export function merkleRoot(leafHashes: readonly Uint8Array[]): Uint8Array {
  leafHashes.forEach(checkDigest);
  // A copy, so mutating the result cannot alter an input leaf or shared state.
  return root(leafHashes).slice();
}

/**
 * Audit path from leaf `index` to the root, leaf level first (RFC 9162 section 2.1.3.1).
 * @throws RangeError `index` is outside the tree or a leaf hash is not 32 bytes.
 */
export function inclusionProof(leafHashes: readonly Uint8Array[], index: number): Uint8Array[] {
  if (!Number.isInteger(index) || index < 0 || index >= leafHashes.length) {
    throw new RangeError("index must be within the tree");
  }
  leafHashes.forEach(checkDigest);
  let level = leafHashes;
  let position = index;
  const proof: Uint8Array[] = [];
  while (level.length > 1) {
    const sibling = level[position % 2 === 0 ? position + 1 : position - 1];
    if (sibling) proof.push(sibling);
    level = nextLevel(level);
    position = Math.floor(position / 2);
  }
  return proof;
}

/**
 * Check an inclusion proof (RFC 9162 section 2.1.3.2).
 *
 * Returns false for any invalid proof, including an index outside the tree and proof
 * nodes that are not 32 bytes.
 *
 * Caller contract: `treeSize` must come from the same signed statement as `rootHash`; an
 * unbound size can change which index verifies (leaf 0 of 3 leaves also verifies at 4).
 * Compute `leaf` yourself with `leafHash` or `jsonLeafHash`, never take it from the input
 * being verified.
 * @throws RangeError `index` or `treeSize` is negative or not an integer, or `leaf` or `rootHash` is not 32 bytes.
 */
export function verifyInclusion(
  leaf: Uint8Array,
  index: number,
  treeSize: number,
  proof: readonly Uint8Array[],
  rootHash: Uint8Array,
): boolean {
  checkDigest(leaf);
  checkDigest(rootHash);
  checkSize(index);
  checkSize(treeSize);
  if (index >= treeSize || treeSize > MAX_SIZE || !proof.every(isDigest)) return false;
  let fn = BigInt(index);
  let sn = BigInt(treeSize) - 1n;
  let r = leaf;
  for (const p of proof) {
    if (sn === 0n) return false;
    if (fn & 1n || fn === sn) {
      r = hashWithPrefix(NODE, p, r);
      while (!(fn & 1n) && fn !== 0n) {
        fn >>= 1n;
        sn >>= 1n;
      }
    } else {
      r = hashWithPrefix(NODE, r, p);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && equal(r, rootHash);
}

/**
 * Proof that the first `oldSize` leaves are a prefix of the tree (RFC 6962 section 2.1.2).
 * Empty when `oldSize` equals the tree size.
 * @throws RangeError `oldSize` is not within 1..leafHashes.length or a leaf hash is not 32 bytes.
 */
export function consistencyProof(leafHashes: readonly Uint8Array[], oldSize: number): Uint8Array[] {
  const n = leafHashes.length;
  if (!Number.isInteger(oldSize) || oldSize < 1 || oldSize > n) {
    throw new RangeError("oldSize must be between 1 and the tree size");
  }
  leafHashes.forEach(checkDigest);
  // SUBPROOF unrolled: `lo`/`size` is the current subtree, `m` the old leaves inside it.
  let lo = 0;
  let size = n;
  let m = oldSize;
  let onOldBoundary = true;
  const appended: Uint8Array[] = [];
  while (m !== size) {
    const k = largestPowerOfTwoBelow(size);
    if (m <= k) {
      appended.push(root(leafHashes.slice(lo + k, lo + size)));
      size = k;
    } else {
      appended.push(root(leafHashes.slice(lo, lo + k)));
      lo += k;
      size -= k;
      m -= k;
      onOldBoundary = false;
    }
  }
  const proof = onOldBoundary ? [] : [root(leafHashes.slice(lo, lo + size))];
  return proof.concat(appended.reverse());
}

/**
 * Check that the tree of `oldSize` leaves is a prefix of the tree of `newSize` leaves.
 *
 * Follows RFC 9162 section 2.1.4.2. Equal sizes need an empty proof and equal roots.
 * Returns false for any invalid proof, including `oldSize` of 0 or above `newSize`, and
 * proof nodes that are not 32 bytes.
 *
 * Caller contract: both sizes must come from the same signed statements as their roots.
 * @throws RangeError A size is negative or not an integer, or a root is not 32 bytes.
 */
export function verifyConsistency(
  oldSize: number,
  newSize: number,
  oldRoot: Uint8Array,
  newRoot: Uint8Array,
  proof: readonly Uint8Array[],
): boolean {
  checkDigest(oldRoot);
  checkDigest(newRoot);
  checkSize(oldSize);
  checkSize(newSize);
  if (!(oldSize > 0 && oldSize <= newSize && newSize <= MAX_SIZE) || !proof.every(isDigest)) {
    return false;
  }
  if (oldSize === newSize) return proof.length === 0 && equal(oldRoot, newRoot);
  if (proof.length === 0) return false;
  let fn = BigInt(oldSize) - 1n;
  const path = (fn & (fn + 1n)) === 0n ? [oldRoot, ...proof] : [...proof];
  let sn = BigInt(newSize) - 1n;
  while (fn & 1n) {
    fn >>= 1n;
    sn >>= 1n;
  }
  let fr = path[0] as Uint8Array;
  let sr = fr;
  for (const c of path.slice(1)) {
    if (sn === 0n) return false;
    if (fn & 1n || fn === sn) {
      fr = hashWithPrefix(NODE, c, fr);
      sr = hashWithPrefix(NODE, c, sr);
      while (!(fn & 1n) && fn !== 0n) {
        fn >>= 1n;
        sn >>= 1n;
      }
    } else {
      sr = hashWithPrefix(NODE, sr, c);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && equal(fr, oldRoot) && equal(sr, newRoot);
}

function hashWithPrefix(prefix: number, ...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(1 + parts.reduce((sum, p) => sum + p.length, 0));
  out[0] = prefix;
  let offset = 1;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return sha256(out);
}

/** Pair neighbours; an unpaired last node is promoted unchanged. */
function nextLevel(level: readonly Uint8Array[]): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let i = 0; i + 1 < level.length; i += 2) {
    out.push(hashWithPrefix(NODE, level[i] as Uint8Array, level[i + 1] as Uint8Array));
  }
  if (level.length % 2 === 1) out.push(level[level.length - 1] as Uint8Array);
  return out;
}

function root(leafHashes: readonly Uint8Array[]): Uint8Array {
  if (leafHashes.length === 0) return EMPTY;
  let level = leafHashes;
  while (level.length > 1) level = nextLevel(level);
  return level[0] as Uint8Array;
}

function largestPowerOfTwoBelow(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

function isDigest(value: Uint8Array): boolean {
  return value.length === DIGEST_SIZE;
}

function checkDigest(value: Uint8Array): void {
  if (!isDigest(value)) throw new RangeError(`digest must be ${DIGEST_SIZE} bytes`);
}

function checkSize(value: number): void {
  if (!Number.isInteger(value) || value < 0) {
    throw new RangeError("index and sizes must be non-negative integers");
  }
}
