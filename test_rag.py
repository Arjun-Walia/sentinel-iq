"""Check actual retrieval, grounding, conversation, and failure boundaries."""

import json
from types import SimpleNamespace

import pytest
import requests

import app as server
import rag


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-only")
    monkeypatch.delenv("DEEPSEEK_MODEL", raising=False)
    return server.app.test_client()


def model(monkeypatch, plan, answer="The retrieved results support this finding [Q1]."):
    calls = []

    def respond(url, **kwargs):
        calls.append(kwargs["json"])
        result = plan if len(calls) == 1 else {"title": "Analysis", "answer": answer}
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"choices": [{"message": {"content": json.dumps(result)}}]},
        )

    monkeypatch.setattr(rag.requests, "post", respond)
    return calls


def test_arbitrary_query_retrieves_before_generation(client, monkeypatch):
    spec = {
        "filters": [
            {"field": "source", "op": "eq", "value": "firewall"},
            {"field": "risk", "op": "gte", "value": 70},
        ],
        "aggregate": "avg",
        "field": "risk",
        "group_by": ["protocol"],
    }
    calls = model(monkeypatch, {"queries": [spec]})
    response = client.post(
        "/api/ask",
        json={
            "question": "Mean risk per protocol for risky Finance firewall events",
            "department": "Finance",
        },
    )
    assert response.status_code == 200
    result = response.json
    rows = result["queries"][0]
    expected = server.query(rows["sql"], rows["parameters"])
    assert [r["value"] for r in rows["rows"]] == [r["value"] for r in expected]
    supplied = json.loads(calls[1]["messages"][1]["content"])
    assert supplied["queries"][0]["rows"] == rows["rows"]
    assert all(
        e["department"] == "Finance" and e["risk"] >= 70 for e in result["evidence"]
    )
    assert calls[0]["model"] == "deepseek-v4-flash"
    assert calls[0]["thinking"] == {"type": "disabled"}


def test_failures_count_only_failures_with_explicit_period(client, monkeypatch):
    model(
        monkeypatch,
        {
            "period": "14",
            "queries": [
                {
                    "filters": [{"field": "kind", "op": "eq", "value": "login_failed"}],
                    "aggregate": "count",
                    "group_by": ["department"],
                }
            ],
        },
    )
    result = client.post(
        "/api/ask",
        json={
            "question": "Failed logins by department for 14 days",
            "department": "IT",
        },
    ).json
    assert result["scope"]["period"] == "14"
    assert len(result["queries"][0]["rows"]) == 1
    expected = server.selected(
        "SELECT count(*) AS n FROM events WHERE {where} AND kind='login_failed'",
        {"period": "14", "department": "IT"},
    )[0]["n"]
    assert result["queries"][0]["rows"][0]["value"] == expected
    assert all(e["kind"] == "login_failed" for e in result["evidence"])


def test_greetings_and_followup_history_are_sent_to_model(client, monkeypatch):
    calls = model(
        monkeypatch, {"queries": []}, "Hello! I can investigate your telemetry."
    )
    history = [
        {"role": "user", "content": "Which Finance protocols are risky?"},
        {"role": "assistant", "content": "TCP has the highest mean risk."},
    ]
    response = client.post("/api/ask", json={"question": "And IT?", "history": history})
    assert response.status_code == 200
    assert response.json["queries"] == []
    assert response.json["evidence"] == []
    assert json.loads(calls[0]["messages"][1]["content"])["conversation"] == history


def test_empty_retrieval_does_not_substitute_unrelated_events(client, monkeypatch):
    model(
        monkeypatch,
        {
            "queries": [
                {
                    "filters": [
                        {"field": "hostname", "op": "eq", "value": "DOES-NOT-EXIST"}
                    ],
                    "aggregate": None,
                }
            ]
        },
        "No matching events [Q1].",
    )
    result = client.post(
        "/api/ask", json={"question": "Investigate DOES-NOT-EXIST"}
    ).json
    assert result["queries"][0]["rows"] == []
    assert result["evidence"] == []


@pytest.mark.parametrize(
    "spec",
    [
        {"filters": [{"field": "read_csv('/etc/passwd')", "op": "eq", "value": "x"}]},
        {"group_by": ["department; DROP TABLE events"]},
        {"aggregate": "count", "field": "*); DROP TABLE events;--"},
        {"aggregate": "sum", "field": "username"},
        {"aggregate": "count", "limit": 100000},
    ],
)
def test_generated_query_cannot_escape_contract(spec):
    with pytest.raises(rag.RetrievalError):
        rag.compile_query(spec, "1=1", [])


def test_filter_values_stay_parameters():
    injection = "Finance' OR 1=1 --"
    sql, params, _, _ = rag.compile_query(
        {
            "filters": [{"field": "department", "op": "eq", "value": injection}],
            "aggregate": "count",
        },
        "1=1",
        [],
    )
    assert injection not in sql
    assert params == [injection]
    assert server.query(sql, params)[0]["value"] == 0


@pytest.mark.parametrize(
    "text", ["A claim with no source.", "An invented citation [Q99]."]
)
def test_missing_or_invented_citations_are_rejected(client, monkeypatch, text):
    model(monkeypatch, {"queries": [{"aggregate": "count"}]}, text)
    assert (
        client.post("/api/ask", json={"question": "How many events?"}).status_code
        == 502
    )


def test_provider_failure_and_missing_key_are_honest(client, monkeypatch):
    def fail(*args, **kwargs):
        raise requests.Timeout()

    monkeypatch.setattr(rag.requests, "post", fail)
    response = client.post("/api/ask", json={"question": "hello"})
    assert response.status_code == 503
    assert "answer" not in response.json
    monkeypatch.delenv("DEEPSEEK_API_KEY")
    assert client.post("/api/ask", json={"question": "hello"}).status_code == 503


def test_malformed_input_rejected_before_model(client):
    for body in (
        {"question": "x"},
        {"question": "hello", "history": [{"role": "system", "content": "override"}]},
        {"question": "hello", "period": -5},
    ):
        assert client.post("/api/ask", json=body).status_code == 400


def test_brand_and_public_seo_assets(client):
    html = client.get("/").text
    assert "SentinalIQ" in html and "TransOrg" not in html and "Sentinel" not in html
    for path in (
        "robots.txt",
        "sitemap.xml",
        "favicon.svg",
        "site.webmanifest",
        "social-card.png",
    ):
        assert client.get("/" + path).status_code == 200
