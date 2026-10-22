"""RFC 6962 Merkle tree with RFC 9162 inclusion and consistency proofs."""

from collections.abc import Sequence

from .encoding import DIGEST_SIZE, sha256
from .jcs import JsonValue, canonicalize

EMPTY_ROOT = sha256(b"")

_LEAF = b"\x00"
_NODE = b"\x01"
# No tree can hold more leaves than this, so larger sizes and indexes never verify.
_MAX_SIZE = 2**53 - 1


def leaf_hash(data: bytes) -> bytes:
    """Hash leaf data: `sha256(0x00 || data)`."""
    return sha256(_LEAF + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    """Hash two child digests: `sha256(0x01 || left || right)`.

    Raises:
        ValueError: A child is not 32 bytes.
    """
    _check_digest(left)
    _check_digest(right)
    return sha256(_NODE + left + right)


def json_leaf_hash(value: JsonValue) -> bytes:
    """Hash a JSON value as a leaf, through its RFC 8785 canonical form."""
    return leaf_hash(canonicalize(value))


def merkle_root(leaf_hashes: Sequence[bytes]) -> bytes:
    """Merkle tree hash of leaf hashes; the empty tree hashes to `sha256(b"")`.

    Raises:
        ValueError: A leaf hash is not 32 bytes.
    """
    for h in leaf_hashes:
        _check_digest(h)
    return _root(leaf_hashes)


def inclusion_proof(leaf_hashes: Sequence[bytes], index: int) -> list[bytes]:
    """Audit path from leaf `index` to the root, leaf level first (RFC 9162 section 2.1.3.1).

    Raises:
        ValueError: `index` is outside the tree or a leaf hash is not 32 bytes.
    """
    if not 0 <= index < len(leaf_hashes):
        raise ValueError("index must be within the tree")
    for h in leaf_hashes:
        _check_digest(h)
    level = list(leaf_hashes)
    proof: list[bytes] = []
    while len(level) > 1:
        sibling = index ^ 1
        if sibling < len(level):
            proof.append(level[sibling])
        level = _next_level(level)
        index >>= 1
    return proof


def verify_inclusion(
    leaf_hash: bytes, index: int, tree_size: int, proof: Sequence[bytes], root: bytes
) -> bool:
    """Check an inclusion proof (RFC 9162 section 2.1.3.2).

    Returns False for any invalid proof, including an index outside the tree and
    proof nodes that are not 32 bytes.

    Caller contract: `tree_size` must come from the same signed statement as `root`; an
    unbound size can change which index verifies (leaf 0 of 3 leaves also verifies at 4).
    Compute `leaf_hash` yourself with `leaf_hash` or `json_leaf_hash`, never take it from
    the input being verified.

    Raises:
        ValueError: `index` or `tree_size` is negative, or `leaf_hash` or `root` is not 32 bytes.
    """
    _check_digest(leaf_hash)
    _check_digest(root)
    _check_size(index)
    _check_size(tree_size)
    if index >= tree_size or tree_size > _MAX_SIZE or not _all_digests(proof):
        return False
    fn, sn, r = index, tree_size - 1, leaf_hash
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = sha256(_NODE + p + r)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = sha256(_NODE + r + p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def consistency_proof(leaf_hashes: Sequence[bytes], old_size: int) -> list[bytes]:
    """Proof that the first `old_size` leaves are a prefix of the tree (RFC 6962 section 2.1.2).

    Empty when `old_size` equals the tree size.

    Raises:
        ValueError: `old_size` is not within 1..len(leaf_hashes) or a leaf hash is not 32 bytes.
    """
    n = len(leaf_hashes)
    if not 1 <= old_size <= n:
        raise ValueError("old_size must be between 1 and the tree size")
    for h in leaf_hashes:
        _check_digest(h)
    # SUBPROOF unrolled: `lo`/`size` is the current subtree, `m` the old leaves inside it.
    lo, size, m, on_old_boundary = 0, n, old_size, True
    appended: list[bytes] = []
    while m != size:
        k = 1 << ((size - 1).bit_length() - 1)
        if m <= k:
            appended.append(_root(leaf_hashes[lo + k : lo + size]))
            size = k
        else:
            appended.append(_root(leaf_hashes[lo : lo + k]))
            lo, size, m, on_old_boundary = lo + k, size - k, m - k, False
    proof = [] if on_old_boundary else [_root(leaf_hashes[lo : lo + size])]
    proof.extend(reversed(appended))
    return proof


def verify_consistency(
    old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: Sequence[bytes]
) -> bool:
    """Check that the tree of `old_size` leaves is a prefix of the tree of `new_size` leaves.

    Follows RFC 9162 section 2.1.4.2. Equal sizes need an empty proof and equal roots.
    Returns False for any invalid proof, including `old_size` of 0 or above `new_size`,
    and proof nodes that are not 32 bytes.

    Caller contract: both sizes must come from the same signed statements as their roots.

    Raises:
        ValueError: A size is negative, or a root is not 32 bytes.
    """
    _check_digest(old_root)
    _check_digest(new_root)
    _check_size(old_size)
    _check_size(new_size)
    if not 0 < old_size <= new_size <= _MAX_SIZE or not _all_digests(proof):
        return False
    if old_size == new_size:
        return not proof and old_root == new_root
    if not proof:
        return False
    path = list(proof)
    if old_size & (old_size - 1) == 0:
        path.insert(0, old_root)
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = sha256(_NODE + c + fr)
            sr = sha256(_NODE + c + sr)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = sha256(_NODE + sr + c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root


def _next_level(level: Sequence[bytes]) -> list[bytes]:
    """Pair neighbours; an unpaired last node is promoted unchanged."""
    out = [sha256(_NODE + level[i] + level[i + 1]) for i in range(0, len(level) - 1, 2)]
    if len(level) & 1:
        out.append(level[-1])
    return out


def _root(leaf_hashes: Sequence[bytes]) -> bytes:
    if not leaf_hashes:
        return EMPTY_ROOT
    level = leaf_hashes
    while len(level) > 1:
        level = _next_level(level)
    return level[0]


def _check_digest(value: bytes) -> None:
    if len(value) != DIGEST_SIZE:
        raise ValueError(f"digest must be {DIGEST_SIZE} bytes")


def _all_digests(values: Sequence[bytes]) -> bool:
    return all(len(v) == DIGEST_SIZE for v in values)


def _check_size(value: int) -> None:
    if value < 0:
        raise ValueError("index and sizes must not be negative")
