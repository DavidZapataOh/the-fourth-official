import json
import statistics
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from fourth_crypto import (
    canonicalize,
    cose_sign1,
    cose_verify1,
    generate_keypair,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    sign,
    verify,
)

CRYPTO = Path(__file__).resolve().parents[2]
BATCH = (
    CRYPTO.parents[1]
    / "libs"
    / "contracts"
    / "fixtures"
    / "signed-batch"
    / "valid"
    / "three-events.json"
)

# Generous regression tripwires; measured medians are about 33 ms, 34 ms and 0.6 ms.
MERKLE_ROOT_100K_S = 1.0
INCLUSION_100K_S = 1.0
CANONICALIZE_37_S = 0.005


def median_seconds(fn: Callable[[], object], runs: int) -> float:
    samples: list[float] = []
    for _ in range(runs):
        start = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def test_merkle_root_of_100k_leaves_under_budget():
    leaves = [leaf_hash(i.to_bytes(4, "big")) for i in range(100_000)]
    assert median_seconds(lambda: merkle_root(leaves), 5) < MERKLE_ROOT_100K_S


def test_inclusion_proof_for_100k_leaves_under_budget():
    leaves = [leaf_hash(i.to_bytes(4, "big")) for i in range(100_000)]
    assert median_seconds(lambda: inclusion_proof(leaves, 77_777), 5) < INCLUSION_100K_S


def test_canonicalize_37_event_batch_under_budget():
    events = json.loads(BATCH.read_text(encoding="utf-8"))["events"]
    batch = [{**events[0], "seq": events[0]["seq"] + i} for i in range(37)]
    assert median_seconds(lambda: canonicalize(batch), 101) < CANONICALIZE_37_S


def test_report_signature_timings(capsys: pytest.CaptureFixture[str]):
    seed, public = generate_keypair()
    message = b"x" * 256
    ed = median_seconds(lambda: verify(public, message, sign(seed, message)), 101)
    cose = median_seconds(lambda: cose_verify1(public, cose_sign1(seed, message, b"kid")), 101)
    with capsys.disabled():
        print(f"\nperf ed25519 sign+verify {ed * 1e6:.0f} us, cose sign+verify {cose * 1e6:.0f} us")
