import json
import time
from pathlib import Path
from typing import Any, cast

from fourth_proofs import verify_ledger_receipt

BASES = cast(
    "dict[str, dict[str, Any]]",
    json.loads(
        (Path(__file__).resolve().parents[2] / "vectors" / "ledger_receipt.json").read_text(
            encoding="utf-8"
        )
    )["bases"],
)

# Generous regression tripwire; measured about 61 ms for 100 P-384 receipts with one endorsement.
HUNDRED_RECEIPTS_S = 0.5


def test_hundred_receipt_verifications_under_budget():
    base = BASES["synthetic_receipt_with_endorsement"]
    start = time.perf_counter()
    for _ in range(100):
        verify_ledger_receipt(
            base["receipt"],
            base["service_certificate"],
            application_claims=base["application_claims"],
        )
    assert time.perf_counter() - start < HUNDRED_RECEIPTS_S
