import base64
import json
from pathlib import Path
from typing import Any, cast

import pytest
from fourth_proofs import OtsStatus, ProofError, ots_status

VECTORS = cast(
    "dict[str, Any]",
    json.loads(
        (Path(__file__).resolve().parents[2] / "vectors" / "ots.json").read_text(encoding="utf-8")
    ),
)
DIGEST = bytes.fromhex(VECTORS["data_sha256"])
PENDING = base64.b64decode(VECTORS["pending"]["proof"])
BITCOIN = cast("dict[str, Any]", VECTORS["bitcoin"])
BITCOIN_PROOF = base64.b64decode(BITCOIN["proof"])
HEIGHT = cast("int", BITCOIN["block_height"])
ROOT = bytes.fromhex(BITCOIN["block_merkle_root"])
INVALID = cast("list[dict[str, str]]", VECTORS["invalid"])


def test_pending_proof_is_reported_pending_with_calendar_urls():
    assert ots_status(PENDING, DIGEST) == OtsStatus(
        kind="pending",
        block_height=None,
        calendars=VECTORS["pending"]["calendars"],
        unverified_anchor_height=None,
    )


def test_deepest_allowed_proof_is_read():
    proof = base64.b64decode(VECTORS["deepest"]["proof"])
    assert ots_status(proof, DIGEST).calendars == VECTORS["deepest"]["calendars"]


@pytest.mark.parametrize("proof", [PENDING, BITCOIN_PROOF], ids=["pending", "bitcoin"])
def test_proof_for_another_hash_is_rejected(proof: bytes):
    with pytest.raises(ProofError):
        ots_status(proof, bytes(32))


def test_bitcoin_attestation_is_anchored_only_when_the_computed_root_matches_the_supplied_block_root():  # noqa: E501
    assert ots_status(BITCOIN_PROOF, DIGEST, block_merkle_roots={HEIGHT: ROOT}) == OtsStatus(
        kind="anchored",
        block_height=HEIGHT,
        calendars=BITCOIN["calendars"],
        unverified_anchor_height=None,
    )
    wrong = bytes([ROOT[0] ^ 1]) + ROOT[1:]
    with pytest.raises(ProofError):
        ots_status(BITCOIN_PROOF, DIGEST, block_merkle_roots={HEIGHT: wrong})
    with pytest.raises(ProofError):
        ots_status(BITCOIN_PROOF, DIGEST, block_merkle_roots={HEIGHT: ROOT[::-1]})


@pytest.mark.parametrize("roots", [None, {}, {HEIGHT + 1: ROOT}])
def test_reader_never_reports_anchored_without_a_block_root(roots: dict[int, bytes] | None):
    assert ots_status(BITCOIN_PROOF, DIGEST, block_merkle_roots=roots) == OtsStatus(
        kind="pending",
        block_height=None,
        calendars=BITCOIN["calendars"],
        unverified_anchor_height=HEIGHT,
    )


@pytest.mark.parametrize("case", INVALID, ids=[case["name"] for case in INVALID])
def test_malformed_proofs_are_rejected(case: dict[str, str]):
    with pytest.raises(ProofError):
        ots_status(base64.b64decode(case["proof"]), DIGEST)


@pytest.mark.parametrize("proof", [PENDING, BITCOIN_PROOF], ids=["pending", "bitcoin"])
def test_truncated_or_unknown_opcode_proofs_are_rejected(proof: bytes):
    for end in range(len(proof)):
        with pytest.raises(ProofError):
            ots_status(proof[:end], DIGEST)
    with pytest.raises(ProofError):
        ots_status(proof + b"\x08", DIGEST)


def test_altered_bitcoin_path_bytes_never_anchor():
    header = range(32, 65)
    branch = range(
        BITCOIN_PROOF.index(bytes.fromhex("f0f1f2f3f4f5f6f70101")) + 10, len(BITCOIN_PROOF)
    )
    for index in [*header, *branch]:
        altered = bytearray(BITCOIN_PROOF)
        altered[index] ^= 0x01
        try:
            status = ots_status(bytes(altered), DIGEST, block_merkle_roots={HEIGHT: ROOT})
        except ProofError:
            continue
        assert status.kind == "pending", index


LIVE_PATH = Path(__file__).resolve().parents[2] / "vectors" / "ots_live.json"
LIVE = cast(
    "dict[str, Any]",
    json.loads(LIVE_PATH.read_text(encoding="utf-8")) if LIVE_PATH.exists() else {},
)
live = pytest.mark.skipif(not LIVE, reason="no live calendar stamp recorded")


@live
def test_live_stamp_is_pending_on_the_recorded_calendars():
    status = ots_status(
        base64.b64decode(LIVE["pending"]["proof"]), bytes.fromhex(LIVE["data_sha256"])
    )
    assert status.kind == "pending"
    assert status.calendars == LIVE["pending"]["calendars"]


@pytest.mark.skipif("anchored" not in LIVE, reason="live stamp not anchored yet")
def test_live_upgraded_stamp_is_anchored_in_the_recorded_block():
    anchored = LIVE["anchored"]
    height = cast("int", anchored["block_height"])
    status = ots_status(
        base64.b64decode(anchored["proof"]),
        bytes.fromhex(LIVE["data_sha256"]),
        block_merkle_roots={height: bytes.fromhex(anchored["block_merkle_root"])},
    )
    assert (status.kind, status.block_height) == ("anchored", height)
