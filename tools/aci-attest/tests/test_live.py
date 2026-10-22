import importlib.util
import os
from pathlib import Path

import pytest

RUN = Path(__file__).resolve().parents[1] / "run.py"
spec = importlib.util.spec_from_file_location("aci_attest_run", RUN)
assert spec and spec.loader
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

DIGEST = "sha256:" + "a" * 64


def template(*images: str) -> dict:
    containers = [
        {"name": f"c{i}", "properties": {"image": image}} for i, image in enumerate(images)
    ]
    return {
        "resources": [
            {
                "type": "Microsoft.ContainerInstance/containerGroups",
                "properties": {"containers": containers},
            }
        ]
    }


def test_assert_images_pinned_rejects_tag_references():
    with pytest.raises(ValueError, match="repo:1.0"):
        run.assert_images_pinned(template("repo:1.0"))
    run.assert_images_pinned(template(f"repo@{DIGEST}"))


def test_assert_images_pinned_checks_every_container():
    with pytest.raises(ValueError, match="other:2"):
        run.assert_images_pinned(template(f"repo@{DIGEST}", "other:2", f"third@{DIGEST}"))


live = pytest.mark.skipif(os.environ.get("FOURTH_LIVE") != "1", reason="live cloud run")


@pytest.fixture(scope="module")
def report():
    result = run.main()
    yield result
    run.teardown()


@live
def test_live_attestation_matches_policy_hash(report):
    assert report["verified"] is True
    assert report["hostdata"] == report["policy_hash"]


@live
def test_live_tampered_policy_is_detected(report):
    assert report["tamper"]["outcome"] in {"group_failed", "no_token", "hostdata_differs"}


@live
def test_live_cold_start_is_recorded(report):
    assert len(report["runs"]) == 3
    for timing in report["runs"]:
        assert timing["created_to_running_s"] > 0
        assert timing["created_to_token_s"] >= timing["created_to_running_s"]
