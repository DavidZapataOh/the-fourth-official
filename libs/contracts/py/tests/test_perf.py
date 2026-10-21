import copy
import json
import statistics
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fourth_contracts import MODELS, validate

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
RUNS = 200


def batch_of_37() -> dict[str, Any]:
    batch = json.loads((FIXTURES / "signed-batch" / "valid" / "three-events.json").read_text())
    event = batch["events"][0]
    batch["events"] = [{**copy.deepcopy(event), "seq": i} for i in range(37)]
    batch["header"]["count"] = 37
    return batch


def median_ms(work: Callable[[], object]) -> float:
    samples: list[float] = []
    for _ in range(RUNS):
        start = time.perf_counter()
        work()
        samples.append((time.perf_counter() - start) * 1000)
    return statistics.median(samples)


def test_validate_signed_batch_of_37_events_under_budget():
    batch = batch_of_37()
    validate("signed-batch", batch)
    assert median_ms(lambda: validate("signed-batch", batch)) < 10


def test_model_parse_signed_batch_of_37_events_under_budget():
    batch = batch_of_37()
    model = MODELS["signed-batch"]
    model.model_validate(batch)
    assert median_ms(lambda: model.model_validate(batch)) < 1
