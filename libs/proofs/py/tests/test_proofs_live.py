import base64
import importlib.util
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest
from fourth_proofs import ProofError, ots_status, verify_ledger_receipt, verify_rfc3161

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
VECTORS = Path(__file__).resolve().parents[2] / "vectors"


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


live_run = load("live_run")
upgrade_ots = load("upgrade_ots")


def vector(name: str) -> dict[str, Any]:
    return cast("dict[str, Any]", json.loads((VECTORS / name).read_text(encoding="utf-8")))


def test_ledger_names_are_valid_and_unique_per_run():
    assert live_run.ledger_name("a1b2c3") == "fourth-proofs-a1b2c3"
    assert live_run.ledger_name("a1b2c3") != live_run.ledger_name("d4e5f6")
    with pytest.raises(ValueError):
        live_run.ledger_name("x" * 40)


def test_ledger_entry_is_the_jcs_canonical_verdict():
    contents = live_run.verdict_contents()
    assert contents == json.dumps(live_run.CLAIM, sort_keys=True, separators=(",", ":"))
    assert json.loads(contents) == live_run.CLAIM


def test_identity_endpoint_is_the_base_of_the_identity_service_uri():
    uri = "https://identity.confidential-ledger.core.azure.com/ledgerIdentity/fourth-proofs-a1b2c3"
    assert live_run.identity_endpoint(uri) == "https://identity.confidential-ledger.core.azure.com"
    with pytest.raises(ValueError):
        live_run.identity_endpoint("http://identity.example/ledgerIdentity/x")


def test_hourly_price_picks_the_standard_instance_meter():
    items = [
        {"armRegionName": "eastus", "meterName": "Additional Storage Data Stored",
         "type": "Consumption", "unitOfMeasure": "1 GB/Month", "retailPrice": 0.16},
        {"armRegionName": "westus", "meterName": "Standard Instance",
         "type": "Consumption", "unitOfMeasure": "1 Hour", "retailPrice": 0.161},
        {"armRegionName": "eastus", "meterName": "Standard Instance",
         "type": "Consumption", "unitOfMeasure": "1 Hour", "retailPrice": 0.124},
    ]  # fmt: skip
    assert live_run.hourly_price(items, "eastus") == 0.124
    assert live_run.hourly_price(items, "northeurope") is None


def test_built_ledger_vectors_record_one_accepted_and_several_rejected_cases():
    base = vector("ledger_receipt.json")["bases"]["synthetic_receipt_with_endorsement"]
    response = {"receipt": base["receipt"], "applicationClaims": base["application_claims"]}
    built = live_run.build_ledger_vectors(
        response, base["service_certificate"], source="test", ledger={"name": "x"}
    )
    cases = built["cases"]
    assert [case["valid"] for case in cases] == [True, False, False, False]
    for case in cases:
        assert live_run.case_outcome(case) is case["valid"], case["name"]
    assert built["bases"]["live_receipt"]["application_claims"] == base["application_claims"]


def test_save_vectors_never_overwrites_a_pre_live_file(tmp_path: Path):
    for name in ("ledger_receipt.json", "rfc3161.json", "ots.json"):
        with pytest.raises(ValueError):
            live_run.save_vectors(tmp_path / name, {})
        assert not (tmp_path / name).exists()


def test_save_vectors_writes_json_and_formats_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    calls: list[list[str]] = []

    def run(args: list[str], **_: object) -> None:
        calls.append(args)

    monkeypatch.setattr(live_run.subprocess, "run", run)
    path = tmp_path / "ledger_receipt_live.json"
    live_run.save_vectors(path, {"cases": [1, 2]})
    assert json.loads(path.read_text(encoding="utf-8")) == {"cases": [1, 2]}
    assert calls == [["pnpm", "exec", "biome", "format", "--write", str(path)]]


def test_header_order_reverses_the_explorer_root():
    explorer = "0cfb54e522b07bd1a381adc774ec1851590ef4c3add83958135106534569f970"
    assert upgrade_ots.header_order(explorer) == bytes.fromhex(explorer)[::-1]
    with pytest.raises(ValueError):
        upgrade_ots.header_order("00" * 31)


Recorded = list[dict[str, Any]]
StampFile = Callable[[str], tuple[Path, Recorded]]


@pytest.fixture
def stamp_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> StampFile:
    """A live stamp file made from the offline vectors, with the reference client stubbed out."""
    offline = vector("ots.json")
    recorded: Recorded = []

    def run_ots(*_: str) -> dict[str, Any]:
        return {"returncode": 0, "output": ""}

    def save(_: Path, vectors: dict[str, Any]) -> None:
        recorded.append(vectors)

    monkeypatch.setattr(upgrade_ots, "run_ots", run_ots)
    monkeypatch.setattr(upgrade_ots, "save_vectors", save)

    def make(entry: str) -> tuple[Path, Recorded]:
        path = tmp_path / "ots_live.json"
        path.write_text(
            json.dumps(
                {
                    "stamped_at": "2026-10-22T12:00:00+00:00",
                    "data_sha256": offline["data_sha256"],
                    "pending": {"proof": offline[entry]["proof"]},
                    "upgrades": [],
                }
            ),
            encoding="utf-8",
        )
        return path, recorded

    return make


def test_upgrade_of_a_pending_stamp_stays_pending_without_fetching_a_block(stamp_file: StampFile):
    path, recorded = stamp_file("pending")
    result = upgrade_ots.upgrade(path)
    assert (result["kind"], result["block_height"]) == ("pending", None)
    assert recorded[0]["upgrades"] == [result]
    assert "anchored" not in recorded[0]


def test_upgrade_records_anchored_only_when_the_block_root_matches(
    stamp_file: StampFile, monkeypatch: pytest.MonkeyPatch
):
    offline = vector("ots.json")["bitcoin"]
    root = bytes.fromhex(offline["block_merkle_root"])
    path, recorded = stamp_file("bitcoin")
    monkeypatch.setattr(upgrade_ots, "block_merkle_root", {offline["block_height"]: root}.get)
    result = upgrade_ots.upgrade(path)
    assert (result["kind"], result["block_height"]) == ("anchored", offline["block_height"])
    assert recorded[0]["anchored"]["block_merkle_root"] == root.hex()

    monkeypatch.setattr(upgrade_ots, "block_merkle_root", {offline["block_height"]: root[::-1]}.get)
    assert upgrade_ots.upgrade(path, record=False)["kind"].startswith("rejected")


live = pytest.mark.skipif(os.environ.get("FOURTH_LIVE") != "1", reason="live cloud run")


@pytest.fixture(scope="module")
def report() -> dict[str, Any]:
    return cast("dict[str, Any]", live_run.main())


@live
def test_live_receipt_verifies_in_python_and_typescript(report: dict[str, Any]):
    ledger = report["ledger"]
    assert ledger["python_before_delete"]["matched"] is True
    assert ledger["python_before_delete"]["azure_sdk"] is True
    assert ledger["typescript_before_delete"] is True


@live
def test_live_receipt_verifies_after_ledger_deletion(report: dict[str, Any]):
    assert report["group_exists_after_teardown"] is False
    assert report["ledger"]["python_after_delete"]["matched"] is True
    assert report["ledger"]["typescript_after_delete"] is True
    base = vector("ledger_receipt_live.json")["bases"]["live_receipt"]
    verify_ledger_receipt(
        base["receipt"], base["service_certificate"], application_claims=base["application_claims"]
    )


@live
def test_live_rfc3161_token_from_public_authority_verifies(report: dict[str, Any]):
    recorded = vector("rfc3161_live.json")
    info = verify_rfc3161(
        base64.b64decode(recorded["response"]),
        bytes.fromhex(recorded["data_sha256"]),
        [recorded["root_certificate"]],
    )
    assert info.signed_at.isoformat() == report["rfc3161"]["signed_at"]
    with pytest.raises(ProofError):
        verify_rfc3161(
            base64.b64decode(recorded["response"]), bytes(32), [recorded["root_certificate"]]
        )


@live
def test_live_ots_stamp_is_pending_then_upgrade_is_attempted(report: dict[str, Any]):
    recorded = vector("ots_live.json")
    status = ots_status(
        base64.b64decode(recorded["pending"]["proof"]), bytes.fromhex(recorded["data_sha256"])
    )
    assert status.kind == "pending"
    assert status.calendars == report["ots"]["calendars"]
    attempt = upgrade_ots.upgrade(record=False)
    assert attempt["ots_upgrade"]["output"]
    assert attempt["kind"] == "pending"
