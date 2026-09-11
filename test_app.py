"""Behavior checks for the supplied dataset, scope isolation, and persistent investigations."""

import csv
import io
from datetime import datetime

import duckdb
import pytest

import app as server
from pipeline import build, byte_count, host, ip, key, number, timestamp


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    server.app.config["TESTING"] = True
    return server.app.test_client()


def test_source_format_repairs_do_not_invent_values():
    assert {
        key(v, "EMP") for v in ["EMP-12345", "emp_12345", "12345", "EMP 12345"]
    } == {"EMP12345"}
    assert host(" ws_12345.corp.local ") == "WS-12345"
    assert ip("999.999.999.999") is None
    assert ip("192.168.2") is None
    assert number("110", 100) is None
    assert number("-1", 65535) is None
    assert number("NaN") is None
    assert byte_count("1.5 MB") == 1572864
    assert byte_count("1,024") == 1024
    assert byte_count("corrupt") is None


def test_timestamp_conventions_are_explicit():
    assert timestamp("09-06-2026 11:22:07 AM") == datetime(2026, 9, 6, 11, 22, 7)
    assert timestamp("06/09/2026 11:22") == datetime(2026, 9, 6, 11, 22)
    assert timestamp("2026-09-06T11:00:00+05:30") == datetime(2026, 9, 6, 5, 30)
    assert timestamp("not a time") is None


def test_rebuild_is_reproducible_and_preserves_cardinality(tmp_path):
    first = build(destination=tmp_path)
    first_csv = {p.name: p.read_bytes() for p in tmp_path.glob("*.csv")}
    second = build(destination=tmp_path)
    assert first["clean_rows"] == second["clean_rows"] == 61000
    assert first["event_rows"] == second["event_rows"] == 58000
    assert first["sources"] == second["sources"]
    assert first_csv == {p.name: p.read_bytes() for p in tmp_path.glob("*.csv")}
    with duckdb.connect(str(tmp_path / "sentinel.duckdb"), read_only=True) as con:
        assert con.execute("SELECT count(*) FROM events").fetchone()[0] == 58000
        assert (
            con.execute("SELECT count(DISTINCT id) FROM events").fetchone()[0] == 58000
        )
        assert (
            con.execute(
                "SELECT count(*) FROM endpoint WHERE resolved_timestamp < detected_timestamp"
            ).fetchone()[0]
            == 0
        )
        assert {
            r[0]
            for r in con.execute("SELECT DISTINCT geo_country FROM firewall").fetchall()
        } == {"United States", "India", "Russia", "China", "Unknown"}


def test_dashboard_totals_match_detail_counts(client):
    args = "period=7&source=endpoint&department=Finance"
    dashboard = client.get("/api/dashboard?" + args).json
    rows = client.get("/api/events?" + args).json
    assert dashboard["metrics"]["total"] == rows["total"]
    assert sum(r["value"] for r in dashboard["severities"]) == rows["total"]
    assert sum(r["total"] for r in dashboard["trend"]) == rows["total"]
    assert all(
        r["department"] == "Finance" and r["source"] == "endpoint" for r in rows["rows"]
    )


def test_all_time_keeps_undated_evidence(client):
    all_time = client.get("/api/dashboard?period=all").json
    assert all_time["metrics"]["total"] == 58000
    assert sum(r["total"] for r in all_time["trend"]) < 58000
    assert all_time["metrics"]["flagged"] > 0


def test_search_pagination_and_empty_state(client):
    first = client.get("/api/events?source=endpoint&page=1").json
    second = client.get("/api/events?source=endpoint&page=2").json
    assert {r["id"] for r in first["rows"]}.isdisjoint(r["id"] for r in second["rows"])
    sample = first["rows"][0]
    found = client.get("/api/events?q=" + sample["id"]).json
    assert found["total"] == 1
    assert client.get("/api/events?q=not-a-real-host").json["total"] == 0


def test_parameterized_scope_resists_sql_injection(client):
    assert (
        client.get(
            "/api/events", query_string={"department": "Finance' OR 1=1 --"}
        ).json["total"]
        == 0
    )
    assert (
        client.get("/api/events", query_string={"q": "'; DROP TABLE events; --"}).json[
            "total"
        ]
        == 0
    )
    assert client.get("/api/meta").json["total"] == 58000


@pytest.mark.parametrize(
    "args", ["period=-1", "period=9999", "source=madeup", "severity=wrong", "page=no"]
)
def test_invalid_filters_rejected(client, args):
    assert client.get("/api/events?" + args).status_code == 400


def test_host_links_have_matching_evidence(client):
    candidate = client.get("/api/dashboard").json["hosts"][0]
    result = client.get("/api/investigate/" + candidate["hostname"]).json
    assert result["summary"]["events"] == candidate["events"]
    assert sum(s["value"] for s in result["signals"]) == candidate["events"]
    for row in result["timeline"][:3]:
        detail = client.get("/api/event/" + row["id"]).json
        assert detail["event"]["hostname"] == candidate["hostname"]
    assert client.get("/api/investigate/DOES-NOT-EXIST").status_code == 404
    assert client.get("/api/event/DOES-NOT-EXIST").status_code == 404


def test_export_matches_current_scope(client):
    args = "period=7&source=iam&department=IT&q=login"
    response = client.get("/api/export?" + args)
    assert response.status_code == 200
    rows = list(csv.DictReader(io.StringIO(response.data.decode())))
    assert len(rows) == client.get("/api/events?" + args).json["total"]
    assert all(r["source"] == "iam" and r["department"] == "IT" for r in rows)


@pytest.mark.parametrize(
    "question,chart",
    [
        ("Show failed logins by department", "bar"),
        ("Which user has the most failed logins?", "bar"),
        ("Endpoint alerts by severity", "bar"),
        ("Show daily trend of critical endpoint alerts", "line"),
        ("Compare firewall allow vs deny by protocol", "bar"),
        ("Which hosts have the most threat flags?", "bar"),
        ("MFA failure trend", "line"),
        ("Daily telemetry volume", "line"),
        ("Top endpoint alert types", "bar"),
        ("Activity of inactive identities", "bar"),
    ],
)
def test_supported_questions_produce_grounded_charts(client, question, chart):
    response = client.post("/api/ask", json={"question": question})
    assert response.status_code == 200
    result = response.json
    assert result["chart"] == chart
    assert result["engine"] == "Local query engine"
    assert result["rows"] and len(result["rows"]) <= 60
    assert result["sql"].startswith("SELECT")


def test_agent_scope_and_unsupported_question(client):
    result = client.post(
        "/api/ask",
        json={
            "question": "Failed logins by department in the last 7 days",
            "department": "IT",
        },
    ).json
    assert result["scope"]["period"] == "7"
    assert all(r["label"] == "IT" for r in result["rows"])
    assert (
        client.post(
            "/api/ask", json={"question": "Write a poem about ducks"}
        ).status_code
        == 422
    )
    assert client.post("/api/ask", json={"question": "x"}).status_code == 400
    assert (
        client.post(
            "/api/ask", json={"question": "Failed logins over the last 14 days"}
        ).status_code
        == 422
    )
    result = client.post(
        "/api/ask", json={"question": "Top Finance users with failed logins all time"}
    ).json
    assert result["scope"]["department"] == "Finance"
    assert result["scope"]["period"] == "all"
    result = client.post(
        "/api/ask", json={"question": "Show failed logins by department in Finance"}
    ).json
    assert result["scope"]["department"] == "Finance"
    result = client.post(
        "/api/ask", json={"question": "Show it as a daily telemetry volume chart"}
    ).json
    assert "department" not in result["scope"]


def test_model_failure_is_visible_and_falls_back(client, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-only")

    def fail(*args, **kwargs):
        raise server.requests.Timeout()

    monkeypatch.setattr(server.requests, "post", fail)
    result = client.post(
        "/api/ask", json={"question": "Endpoint alerts by severity"}
    ).json
    assert result["engine"] == "Local query engine"
    assert result["warning"]


def test_deepseek_flash_model_configuration(client, monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-only")
    monkeypatch.delenv("DEEPSEEK_MODEL", raising=False)
    calls = []

    def respond(url, **kwargs):
        calls.append(kwargs["json"])
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"choices": [{"message": {"content": '{"intent":"severity"}'}}]},
        )

    monkeypatch.setattr(server.requests, "post", respond)
    response = client.post("/api/ask", json={"question": "Endpoint alerts by severity"})
    assert response.status_code == 200
    assert calls[0]["model"] == "deepseek-v4-flash"
    assert calls[0]["thinking"] == {"type": "disabled"}
    assert response.json["rows"]


def test_case_notes_persist_without_mutating_telemetry(client, monkeypatch, tmp_path):
    monkeypatch.setattr(server, "DATA", tmp_path)
    server.initialize()
    hostname = client.get("/api/dashboard").json["hosts"][0]["hostname"]
    payload = {
        "hostname": hostname,
        "status": "Investigating",
        "note": "Review endpoint evidence before escalation.",
    }
    assert client.post("/api/cases", json=payload).status_code == 200
    assert (
        server.app.test_client().get("/api/cases").json["rows"][0]["note"]
        == payload["note"]
    )
    assert client.get("/api/meta").json["total"] == 58000
    assert (
        client.post("/api/cases", json={**payload, "status": "invalid"}).status_code
        == 400
    )
    assert (
        client.post("/api/cases", json={**payload, "hostname": "missing"}).status_code
        == 400
    )
    assert (
        client.post("/api/cases", json={**payload, "status": ["Watching"]}).status_code
        == 400
    )


def test_dashboard_has_security_headers_and_local_assets(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    for file in ("app.js", "style.css", "font.css", "manrope.woff2", "mark.svg"):
        assert client.get("/static/" + file).status_code == 200
