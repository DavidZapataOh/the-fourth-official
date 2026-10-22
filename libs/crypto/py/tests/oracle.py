"""Independent RFC 6962 reference: the direct recursive definitions of section 2.1."""

import hashlib
from collections.abc import Sequence


def _h(prefix: bytes, *parts: bytes) -> bytes:
    return hashlib.sha256(prefix + b"".join(parts)).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def oracle_root(leaf_hashes: Sequence[bytes]) -> bytes:
    n = len(leaf_hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hashes[0]
    k = _split(n)
    return _h(b"\x01", oracle_root(leaf_hashes[:k]), oracle_root(leaf_hashes[k:]))


def oracle_path(m: int, leaf_hashes: Sequence[bytes]) -> list[bytes]:
    n = len(leaf_hashes)
    if n == 1:
        return []
    k = _split(n)
    if m < k:
        return [*oracle_path(m, leaf_hashes[:k]), oracle_root(leaf_hashes[k:])]
    return [*oracle_path(m - k, leaf_hashes[k:]), oracle_root(leaf_hashes[:k])]


def _subproof(m: int, leaf_hashes: Sequence[bytes], complete: bool) -> list[bytes]:
    n = len(leaf_hashes)
    if m == n:
        return [] if complete else [oracle_root(leaf_hashes)]
    k = _split(n)
    if m <= k:
        return [*_subproof(m, leaf_hashes[:k], complete), oracle_root(leaf_hashes[k:])]
    return [*_subproof(m - k, leaf_hashes[k:], False), oracle_root(leaf_hashes[:k])]


def oracle_consistency(m: int, leaf_hashes: Sequence[bytes]) -> list[bytes]:
    return _subproof(m, leaf_hashes, True)
