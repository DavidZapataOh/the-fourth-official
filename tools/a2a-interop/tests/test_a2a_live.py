import os
from typing import Any

import pytest
from conftest import load

run = load("a2a_interop_run", "run.py")

SCENARIOS = {"client_to_server", "foundry_to_server", "client_to_foundry", "foundry_to_mcp"}
RESULT_KEYS = {"ok", "latencies_ms", "cold_ms", "tokens"}


def result(**over: Any) -> dict[str, Any]:
    return {"ok": True, "latencies_ms": [10.0, 20.0], "cold_ms": None, "tokens": None, **over}


def test_names_are_unique_per_run_because_a_purged_account_name_stays_unusable():
    other = load("a2a_interop_run_other", "run.py")
    first = run.names("subscription-id")
    assert first == run.names("subscription-id")
    assert first[1] != other.names("subscription-id")[1]
    assert first[1].startswith("fourth-a2a-")


def test_percentile_interpolates_between_ranks():
    values = [float(v) for v in range(1, 21)]
    assert run.percentile(values, 50) == pytest.approx(10.5)
    assert run.percentile(values, 95) == pytest.approx(19.05)
    assert run.percentile([7.0], 95) == 7.0


def test_percentile_rejects_an_empty_sample():
    with pytest.raises(ValueError):
        run.percentile([], 50)


def test_summarize_keeps_cold_out_of_the_warm_percentiles():
    summary = run.summarize(result(latencies_ms=[100.0] * 19 + [200.0], cold_ms=5000.0, tokens=42))
    assert summary == {
        "ok": True,
        "calls": 20,
        "p50_ms": 100.0,
        "p95_ms": pytest.approx(105.0),
        "cold_ms": 5000.0,
        "tokens": 42,
    }


def test_summarize_reports_a_failed_scenario_without_samples():
    summary = run.summarize(result(ok=False, latencies_ms=[]))
    assert summary["ok"] is False
    assert summary["calls"] == 0
    assert summary["p50_ms"] is None
    assert summary["p95_ms"] is None


def test_report_has_every_scenario_and_the_recorded_facts():
    report = run.build_report(
        {name: result() for name in SCENARIOS},
        rejections={"missing_token": 401, "missing_role": 403},
        identity={"oid": "o", "appid": "a", "type": "ServiceIdentity"},
        versions={"azure-ai-projects": "2.9.0"},
    )
    assert set(report["scenarios"]) == SCENARIOS
    assert report["rejections"] == {"missing_token": 401, "missing_role": 403}
    assert report["identity"]["oid"] == "o"
    assert report["versions"] == {"azure-ai-projects": "2.9.0"}


def test_report_refuses_a_scenario_result_with_the_wrong_shape():
    with pytest.raises(ValueError, match="foundry_to_mcp"):
        run.build_report(
            {**{name: result() for name in SCENARIOS}, "foundry_to_mcp": {"ok": True}},
            rejections={},
            identity={},
            versions={},
        )


def test_foundry_a2a_urls_follow_the_documented_paths():
    base = run.foundry_a2a_base_url("acct", "proj", "agent")
    assert base == (
        "https://acct.services.ai.azure.com/api/projects/proj/agents/agent/endpoint/protocols/a2a"
    )
    assert run.FOUNDRY_CARD_PATH == "agentCard/v1.0"


def test_callers_are_parsed_from_server_logs():
    logs = "\n".join(
        [
            '{"Log": "INFO:a2a.caller:a2a.caller oid=11-22 appid=33-44 allowed=False"}',
            "INFO:     10.0.0.1 - POST /a2a 200",
            "INFO:a2a.caller:a2a.caller oid=55 appid=66 allowed=True",
        ]
    )
    assert run.callers_from_logs(logs) == [
        {"oid": "11-22", "appid": "33-44", "allowed": False},
        {"oid": "55", "appid": "66", "allowed": True},
    ]


live = pytest.mark.skipif(os.environ.get("FOURTH_LIVE") != "1", reason="live cloud run")


@pytest.fixture(scope="module")
def report():
    try:
        yield run.main()
    finally:
        run.teardown()


def scenario(report: dict[str, Any], name: str) -> dict[str, Any]:
    found = report["scenarios"][name]
    assert found["ok"] is True, found
    assert found["calls"] == run.WARM_CALLS
    assert found["p50_ms"] <= found["p95_ms"]
    return found


@live
def test_live_client_to_server_verifies_the_card_and_gets_a_verdict(report):
    found = scenario(report, "client_to_server")
    assert found["cold_ms"] is not None


@live
def test_live_foundry_agent_calls_our_server_through_the_a2a_tool(report):
    found = scenario(report, "foundry_to_server")
    assert found["tokens"] and found["tokens"] > 0
    assert found["cold_ms"] is not None


@live
def test_live_client_calls_foundry_incoming_a2a_with_an_entra_token(report):
    scenario(report, "client_to_foundry")


@live
def test_live_foundry_incoming_a2a_rejects_missing_token_and_missing_role(report):
    assert report["rejections"]["missing_token"] == 401
    assert report["rejections"]["missing_role"] in {401, 403, 404}


@live
def test_live_foundry_agent_calls_the_mcp_tool(report):
    found = scenario(report, "foundry_to_mcp")
    assert found["tokens"] and found["tokens"] > 0
    assert found["cold_ms"] is not None


@live
def test_live_agent_identity_is_recorded(report):
    identity = report["identity"]
    assert identity["oid"]
    assert identity["type"]
    assert identity["oid"] == identity["expected_oid"]
