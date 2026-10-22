import hashlib
import random
from typing import Any, cast

import pytest
from conftest import vectors
from fourth_crypto import (
    EMPTY_ROOT,
    canonicalize,
    consistency_proof,
    inclusion_proof,
    json_leaf_hash,
    leaf_hash,
    merkle_root,
    node_hash,
    sha256,
    verify_consistency,
    verify_inclusion,
)
from hypothesis import given, settings
from hypothesis import strategies as st
from oracle import oracle_consistency, oracle_path, oracle_root

VEC = cast("dict[str, Any]", vectors("merkle"))
LEAVES = [leaf_hash(bytes.fromhex(d)) for d in VEC["leaves"]]
ROOTS = [bytes.fromhex(r) for r in VEC["roots"]]
_RNG = random.Random(6962)
POOL = [_RNG.randbytes(32) for _ in range(70)]
DIGEST = st.binary(min_size=32, max_size=32)


def flip(data: bytes, bit: int = 0) -> bytes:
    out = bytearray(data)
    out[bit >> 3] ^= 1 << (bit & 7)
    return bytes(out)


def mutate_proof(proof: list[bytes]) -> list[list[bytes]]:
    """Every single-bit-class mutation of a proof: flipped byte, extra node, missing node."""
    out = [[*proof[:i], flip(proof[i], 3), *proof[i + 1 :]] for i in range(len(proof))]
    out.append([*proof, POOL[0]])
    out.append([POOL[0], *proof])
    out.extend([*proof[:i], *proof[i + 1 :]] for i in range(len(proof)))
    return out


def test_primitives() -> None:
    assert sha256(b"") == EMPTY_ROOT
    assert leaf_hash(b"abc") == hashlib.sha256(b"\x00abc").digest()
    assert node_hash(POOL[0], POOL[1]) == hashlib.sha256(b"\x01" + POOL[0] + POOL[1]).digest()
    assert json_leaf_hash({"b": 1, "a": [2]}) == leaf_hash(canonicalize({"a": [2], "b": 1}))
    with pytest.raises(ValueError, match="32"):
        node_hash(b"short", POOL[1])


def test_empty_tree_root() -> None:
    assert merkle_root([]) == sha256(b"")


@pytest.mark.parametrize("size", range(9))
def test_reference_roots(size: int) -> None:
    assert merkle_root(LEAVES[:size]) == ROOTS[size]


INCLUSION = VEC["inclusion"]
CONSISTENCY = VEC["consistency"]


def _digest_args(*items: str) -> list[bytes]:
    return [bytes.fromhex(i) for i in items]


@pytest.mark.parametrize("case", INCLUSION, ids=[c["name"] for c in INCLUSION])
def test_reference_inclusion(case: dict[str, Any]) -> None:
    leaf, root = _digest_args(case["leaf_hash"], case["root"])
    proof = _digest_args(*case["proof"])
    args = (leaf, case["index"], case["size"], proof, root)
    if len(leaf) != 32 or len(root) != 32:
        with pytest.raises(ValueError, match="32"):
            verify_inclusion(leaf, case["index"], case["size"], proof, root)
        return
    assert verify_inclusion(*args) is case["valid"]
    if case["valid"]:
        assert inclusion_proof(LEAVES[: case["size"]], case["index"]) == proof


@pytest.mark.parametrize("case", CONSISTENCY, ids=[c["name"] for c in CONSISTENCY])
def test_reference_consistency(case: dict[str, Any]) -> None:
    old_root, new_root = _digest_args(case["old_root"], case["new_root"])
    proof = _digest_args(*case["proof"])
    args = (case["old_size"], case["new_size"], old_root, new_root, proof)
    if len(old_root) != 32 or len(new_root) != 32:
        with pytest.raises(ValueError, match="32"):
            verify_consistency(*args)
        return
    assert verify_consistency(*args) is case["valid"]
    if case["valid"]:
        assert consistency_proof(LEAVES[: case["new_size"]], case["old_size"]) == proof


def test_root_matches_oracle_for_every_size() -> None:
    pool = [sha256(i.to_bytes(2, "big")) for i in range(300)]
    for n in range(301):
        assert merkle_root(pool[:n]) == oracle_root(pool[:n])


@settings(database=None, max_examples=200, deadline=None)
@given(st.lists(DIGEST, max_size=300))
def test_root_matches_oracle(leaves: list[bytes]) -> None:
    assert merkle_root(leaves) == oracle_root(leaves)


@settings(database=None, max_examples=100, deadline=None)
@given(st.lists(DIGEST, min_size=1, max_size=80), st.data())
def test_proofs_match_oracle(leaves: list[bytes], data: st.DataObject) -> None:
    n = len(leaves)
    i = data.draw(st.integers(0, n - 1))
    m = data.draw(st.integers(1, n))
    assert inclusion_proof(leaves, i) == oracle_path(i, leaves)
    assert consistency_proof(leaves, m) == oracle_consistency(m, leaves)


def test_proof_lengths_are_logarithmic() -> None:
    leaves = [sha256(bytes([i])) for i in range(64)]
    assert all(len(inclusion_proof(leaves, i)) == 6 for i in range(64))
    assert consistency_proof(leaves, 32) == [merkle_root(leaves[32:])]


@pytest.mark.parametrize("n", range(1, 66))
def test_inclusion_round_trip(n: int) -> None:
    leaves = POOL[:n]
    root = merkle_root(leaves)
    for i in range(n):
        proof = inclusion_proof(leaves, i)
        assert verify_inclusion(leaves[i], i, n, proof, root)


@pytest.mark.parametrize("n", range(1, 21))
def test_inclusion_rejects_mutations(n: int) -> None:
    leaves = POOL[:n]
    root = merkle_root(leaves)
    for i in range(n):
        proof = inclusion_proof(leaves, i)
        for bad in mutate_proof(proof):
            assert not verify_inclusion(leaves[i], i, n, bad, root)
        assert not verify_inclusion(flip(leaves[i]), i, n, proof, root)
        assert not verify_inclusion(leaves[i], i, n, proof, flip(root))
        for wrong in {j for j in range(n) if j != i}:
            assert not verify_inclusion(leaves[i], wrong, n, proof, root)
        # Only the proof length is tied to the size: a size with the same path length can
        # collapse a sibling subtree into one node and change which index verifies, so it is
        # checked only when the length differs.
        for wrong_size in (0, n - 1, n + 1, 2 * n):
            if wrong_size <= i or len(oracle_path(i, POOL[:wrong_size])) != len(proof):
                assert not verify_inclusion(leaves[i], i, wrong_size, proof, root)


@pytest.mark.parametrize("new", range(1, 41))
def test_consistency_round_trip(new: int) -> None:
    leaves = POOL[:new]
    new_root = merkle_root(leaves)
    for old in range(1, new + 1):
        proof = consistency_proof(leaves, old)
        assert verify_consistency(old, new, merkle_root(leaves[:old]), new_root, proof)


@pytest.mark.parametrize("new", range(2, 21))
def test_consistency_rejects_mutations(new: int) -> None:
    leaves = POOL[:new]
    new_root = merkle_root(leaves)
    for old in range(1, new + 1):
        old_root = merkle_root(leaves[:old])
        proof = consistency_proof(leaves, old)
        for bad in mutate_proof(proof):
            assert not verify_consistency(old, new, old_root, new_root, bad)
        assert not verify_consistency(old, new, flip(old_root), new_root, proof)
        assert not verify_consistency(old, new, old_root, flip(new_root), proof)
        for wrong_old, wrong_new in [(o, new) for o in range(new + 2)] + [(old, new + 1)]:
            if (wrong_old, wrong_new) == (old, new):
                continue
            if wrong_old < 1 or wrong_old > wrong_new:
                shape = None
            else:
                shape = oracle_consistency(wrong_old, POOL[:wrong_new])
            if shape is None or len(shape) != len(proof):
                assert not verify_consistency(wrong_old, wrong_new, old_root, new_root, proof)
        if old != new:
            assert not verify_consistency(old, new, new_root, old_root, proof)


def test_node_hash_is_not_a_valid_leaf() -> None:
    a, b = POOL[0], POOL[1]
    root = merkle_root([a, b])
    assert root == node_hash(a, b)
    assert not verify_inclusion(node_hash(a, b), 0, 2, [], root)
    assert not verify_inclusion(node_hash(a, b), 0, 2, [POOL[2]], root)
    # The second-preimage forgery needs leaf data that hashes like an inner node.
    forged = b"\x01" + a + b
    assert leaf_hash(forged) != node_hash(a, b)
    assert not verify_inclusion(leaf_hash(forged), 0, 1, [], root)


def test_out_of_range_arguments() -> None:
    leaves = POOL[:5]
    root = merkle_root(leaves)
    proof = inclusion_proof(leaves, 2)
    with pytest.raises(ValueError, match="index"):
        inclusion_proof(leaves, 5)
    with pytest.raises(ValueError, match="index"):
        inclusion_proof(leaves, -1)
    with pytest.raises(ValueError, match="index"):
        inclusion_proof([], 0)
    for old in (0, 6, -1):
        with pytest.raises(ValueError, match="old_size"):
            consistency_proof(leaves, old)
    with pytest.raises(ValueError, match="32"):
        merkle_root([b"short"])
    with pytest.raises(ValueError, match="32"):
        inclusion_proof([b"short"], 0)

    assert not verify_inclusion(leaves[2], 5, 5, proof, root)
    assert not verify_inclusion(leaves[2], 2**64, 2**64 + 1, proof, root)
    assert not verify_inclusion(leaves[2], 0, 0, [], root)
    for args in ((-1, 5), (2, -1)):
        with pytest.raises(ValueError, match="negative"):
            verify_inclusion(leaves[2], *args, proof, root)
    with pytest.raises(ValueError, match="32"):
        verify_inclusion(b"short", 2, 5, proof, root)
    with pytest.raises(ValueError, match="32"):
        verify_inclusion(leaves[2], 2, 5, proof, b"short")
    assert not verify_inclusion(leaves[2], 2, 5, [*proof[:-1], b"short"], root)

    old_root = merkle_root(leaves[:3])
    cproof = consistency_proof(leaves, 3)
    assert verify_consistency(3, 5, old_root, root, cproof)
    assert not verify_consistency(0, 5, old_root, root, cproof)
    assert not verify_consistency(6, 5, old_root, root, cproof)
    assert not verify_consistency(3, 3, old_root, root, [])
    assert verify_consistency(5, 5, root, root, [])
    assert not verify_consistency(5, 5, root, root, [root])
    assert not verify_consistency(1, 2**64, old_root, root, cproof)
    with pytest.raises(ValueError, match="negative"):
        verify_consistency(-1, 5, old_root, root, cproof)
    with pytest.raises(ValueError, match="32"):
        verify_consistency(3, 5, b"short", root, cproof)


def test_size_must_be_bound_by_the_signed_statement() -> None:
    # RFC 9162 accepts leaf 0 of a 3-leaf tree at size 4 with the same proof (the last leaf
    # stands in for a subtree), so callers must take the size from the same signed
    # statement as the root.
    leaves = POOL[:3]
    root = merkle_root(leaves)
    proof = inclusion_proof(leaves, 0)
    assert verify_inclusion(leaves[0], 0, 3, proof, root)
    assert verify_inclusion(leaves[0], 0, 4, proof, root)
