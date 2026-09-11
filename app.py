"""Sentinel IQ: analytical API and dashboard, with bounded graph-first questions."""

import csv
import io
import json
import os
import re
import shutil
import sqlite3
from datetime import timedelta
from pathlib import Path

import duckdb
import requests
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, render_template, request
from werkzeug.exceptions import BadRequest

from pipeline import DATA as BUNDLED_DATA
from pipeline import DB as BUNDLED_DB
from pipeline import build

load_dotenv()
DATA = BUNDLED_DATA
DB = BUNDLED_DB

if os.getenv("VERCEL"):
    DATA = Path("/tmp/sentinel-iq-data")
    DB = DATA / "sentinel.duckdb"
    if not DB.exists():
        DATA.mkdir(parents=True, exist_ok=True)
        for filename in ("sentinel.duckdb", "quality.json", "cases.sqlite"):
            source = BUNDLED_DATA / filename
            if source.exists():
                shutil.copy2(source, DATA / filename)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


def query(sql, params=None):
    with duckdb.connect(
        str(DB), read_only=True, config={"enable_external_access": False}
    ) as con:
        result = con.execute(sql, params or [])
        names = [c[0] for c in result.description]
        return [dict(zip(names, row)) for row in result.fetchall()]


def initialize():
    if not DB.exists():
        build(destination=DATA)
    with sqlite3.connect(DATA / "cases.sqlite") as con:
        con.execute(
            "CREATE TABLE IF NOT EXISTS cases (hostname TEXT PRIMARY KEY, status TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', updated_at TEXT DEFAULT CURRENT_TIMESTAMP)"
        )


def scope(args):
    clauses, params = ["1=1"], []
    period = str(args.get("period", "30"))
    if period not in {"7", "30", "all"}:
        raise BadRequest("Period must be 7, 30, or all.")
    latest = query("SELECT cast(max(timestamp) AS DATE) AS latest FROM events")[0][
        "latest"
    ]
    if period != "all":
        clauses += ["timestamp >= ?", "timestamp < ?"]
        params += [latest - timedelta(days=int(period) - 1), latest + timedelta(days=1)]
    for field, allowed in {
        "source": {"iam", "firewall", "endpoint"},
        "severity": {"Critical", "High", "Medium", "Low", "Unknown"},
    }.items():
        value = args.get(field)
        if value and value != "all":
            if not isinstance(value, str) or value not in allowed:
                raise BadRequest(f"Invalid {field}.")
            clauses.append(f"{field} = ?")
            params.append(value)
    for field in ("department", "hostname"):
        if args.get(field) and args[field] != "all":
            clauses.append(f"{field} = ?")
            params.append(str(args[field])[:120])
    if args.get("q"):
        clauses.append(
            "(hostname ILIKE ? OR username ILIKE ? OR id ILIKE ? OR kind ILIKE ? OR user_id ILIKE ?)"
        )
        params += ["%" + str(args["q"])[:120] + "%"] * 5
    return " AND ".join(clauses), params


def selected(sql, args):
    where, params = scope(args)
    return query(sql.replace("{where}", where), params)


def case_map():
    with sqlite3.connect(DATA / "cases.sqlite") as con:
        con.row_factory = sqlite3.Row
        return {r["hostname"]: dict(r) for r in con.execute("SELECT * FROM cases")}


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/meta")
def meta():
    bounds = query(
        "SELECT cast(min(timestamp) AS VARCHAR) AS earliest, cast(max(timestamp) AS VARCHAR) AS latest, count(*) AS total FROM events"
    )[0]
    return jsonify(
        **bounds,
        departments=[
            r["department"]
            for r in query("SELECT DISTINCT department FROM events ORDER BY 1")
        ],
        agent="DeepSeek V4 Flash · RAG selector" if os.getenv("DEEPSEEK_API_KEY") else "Local query engine",
        synthetic=True,
    )


@app.get("/api/dashboard")
def dashboard():
    args = request.args
    metrics = selected(
        """SELECT count(*) AS total, count(*) FILTER(WHERE risk >= 70) AS high_risk,
        count(DISTINCT hostname) AS hosts, count(DISTINCT user_id) AS identities,
        count(*) FILTER(WHERE source='endpoint' AND status IN ('Open','Investigating')) AS open_alerts,
        count(*) FILTER(WHERE source='iam' AND kind='login_failed') AS failed_logins,
        count(*) FILTER(WHERE threat) AS threats, count(*) FILTER(WHERE action='Deny') AS denied,
        count(*) FILTER(WHERE source='firewall') AS network_events,
        count(*) FILTER(WHERE quality_flags != '') AS flagged,
        round(avg(resolution_hours),1) AS resolution_hours FROM events WHERE {where}""",
        args,
    )[0]
    trend = selected(
        "SELECT cast(cast(timestamp AS DATE) AS VARCHAR) AS day, count(*) AS total, count(*) FILTER(WHERE risk>=70) AS high_risk FROM events WHERE {where} AND timestamp IS NOT NULL GROUP BY 1 ORDER BY 1",
        args,
    )
    severities = selected(
        "SELECT severity AS label, count(*) AS value FROM events WHERE {where} GROUP BY severity ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END",
        args,
    )
    departments = selected(
        "SELECT department AS label, count(*) FILTER(WHERE risk>=70) AS value, count(*) AS total FROM events WHERE {where} GROUP BY 1 ORDER BY value DESC, label LIMIT 6",
        args,
    )
    countries = selected(
        "SELECT country AS label, count(*) AS value, count(*) FILTER(WHERE threat) AS threats FROM events WHERE {where} AND source='firewall' GROUP BY country ORDER BY value DESC",
        args,
    )
    sources = selected(
        "SELECT source AS label, count(*) AS value FROM events WHERE {where} GROUP BY source ORDER BY value DESC",
        args,
    )
    hosts = selected(
        """SELECT hostname, max(department) AS department, count(*) AS events, count(DISTINCT source) AS sources,
        count(*) FILTER(WHERE kind IN ('login_failed','mfa_failed')) AS failures,
        count(*) FILTER(WHERE source='endpoint') AS endpoint_alerts, count(*) FILTER(WHERE threat) AS threats,
        max(risk) AS risk, count(*) FILTER(WHERE risk>=70) AS high_risk
        FROM events WHERE {where} AND hostname IS NOT NULL GROUP BY hostname
        ORDER BY (count(DISTINCT source)) DESC, high_risk DESC, hostname LIMIT 20""",
        args,
    )
    cases = case_map()
    for h in hosts:
        h["case"] = cases.get(h["hostname"])
    recent = selected(
        "SELECT id, cast(timestamp AS VARCHAR) AS timestamp, hostname, username, kind, severity, source, risk, status FROM events WHERE {where} AND risk >= 70 ORDER BY timestamp DESC NULLS LAST, risk DESC LIMIT 6",
        args,
    )
    return jsonify(
        metrics=metrics,
        trend=trend,
        severities=severities,
        departments=departments,
        countries=countries,
        sources=sources,
        hosts=hosts,
        recent=recent,
    )


@app.get("/api/events")
def events():
    try:
        page = max(1, min(100000, int(request.args.get("page", 1))))
    except ValueError:
        raise BadRequest("Page must be an integer.")
    where, params = scope(request.args)
    total = query(f"SELECT count(*) AS n FROM events WHERE {where}", params)[0]["n"]
    rows = query(
        f"SELECT * EXCLUDE(timestamp), cast(timestamp AS VARCHAR) AS timestamp FROM events WHERE {where} ORDER BY timestamp DESC NULLS LAST, id LIMIT 15 OFFSET ?",
        params + [(page - 1) * 15],
    )
    return jsonify(rows=rows, total=total, page=page, pages=max(1, (total + 14) // 15))


@app.get("/api/investigate/<hostname>")
def investigate(hostname):
    args = request.args.to_dict()
    args["hostname"] = hostname
    summary = selected(
        "SELECT count(*) AS events, count(DISTINCT source) AS sources, max(risk) AS risk, count(*) FILTER(WHERE kind IN ('login_failed','mfa_failed')) AS failures, count(*) FILTER(WHERE source='endpoint') AS endpoint_alerts, count(*) FILTER(WHERE threat) AS threats FROM events WHERE {where}",
        args,
    )[0]
    if not summary["events"]:
        return jsonify(error="No evidence for this host in the selected scope."), 404
    timeline = selected(
        "SELECT id, cast(timestamp AS VARCHAR) AS timestamp, source, kind, risk, severity, user_id, source_ip, quality_flags, session_id FROM events WHERE {where} ORDER BY timestamp DESC NULLS LAST LIMIT 80",
        args,
    )
    identity = query(
        "SELECT user_id, username, full_name, department, role, status, hostname FROM identities WHERE hostname=?",
        [hostname],
    )
    signals = selected(
        "SELECT source AS label, count(*) AS value, count(*) FILTER(WHERE risk>=70) AS high_risk FROM events WHERE {where} GROUP BY source",
        args,
    )
    return jsonify(
        hostname=hostname,
        summary=summary,
        timeline=timeline,
        identity=identity,
        signals=signals,
        case=case_map().get(hostname),
        caveat="Connections show shared host observations, not a proven attack sequence. Timeline is capped at the 80 most recent events.",
    )


@app.get("/api/quality")
def quality():
    return jsonify(json.loads((DATA / "quality.json").read_text(encoding="utf-8")))


@app.get("/api/event/<event_id>")
def event_detail(event_id):
    rows = query(
        "SELECT * EXCLUDE(timestamp), cast(timestamp AS VARCHAR) AS timestamp FROM events WHERE id=?",
        [event_id],
    )
    if not rows:
        return jsonify(error="Event not found."), 404
    event = rows[0]
    source, id_col = {
        "iam": ("iam", "event_id"),
        "endpoint": ("endpoint", "alert_id"),
        "firewall": ("firewall", "log_id"),
    }[event["source"]]
    cleaned = query(f"SELECT * FROM {source} WHERE {id_col}=?", [event_id])[0]
    return jsonify(event=event, cleaned=cleaned)


@app.get("/api/cases")
def cases():
    return jsonify(rows=list(case_map().values()))


@app.post("/api/cases")
def save_case():
    body = request.get_json()
    if not isinstance(body, dict):
        raise BadRequest("Expected an object.")
    hostname, status, note = (
        body.get("hostname"),
        body.get("status"),
        body.get("note", ""),
    )
    if not isinstance(hostname, str) or not query(
        "SELECT 1 FROM events WHERE hostname=? LIMIT 1", [hostname]
    ):
        raise BadRequest("Unknown host.")
    if (
        not isinstance(status, str)
        or status not in {"Watching", "Investigating", "Closed"}
        or not isinstance(note, str)
        or len(note) > 2000
    ):
        raise BadRequest(
            "Choose a valid case status and a note under 2,000 characters."
        )
    with sqlite3.connect(DATA / "cases.sqlite") as con:
        con.execute(
            "INSERT INTO cases(hostname,status,note) VALUES(?,?,?) ON CONFLICT(hostname) DO UPDATE SET status=excluded.status,note=excluded.note,updated_at=CURRENT_TIMESTAMP",
            (hostname, status, note),
        )
    return jsonify(ok=True)


@app.get("/api/export")
def export():
    rows = selected(
        "SELECT * EXCLUDE(timestamp), cast(timestamp AS VARCHAR) AS timestamp FROM events WHERE {where} ORDER BY timestamp DESC NULLS LAST, id",
        request.args,
    )
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    columns = list(rows[0]) if rows else ["id", "source", "timestamp"]
    writer.writerow(columns)
    for row in rows:
        writer.writerow(
            [
                "'" + v
                if isinstance(v, str)
                and v.startswith(("=", "+", "-", "@", "\t", "\r", "\n"))
                else v
                for v in row.values()
            ]
        )
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": 'attachment; filename="sentinel-evidence.csv"'},
    )


QUESTIONS = {
    "failed_departments": (
        "Failed logins by department",
        "bar",
        "department",
        "kind='login_failed'",
    ),
    "failed_users": (
        "Users with the most failed logins",
        "bar",
        "coalesce(user_id,'Unknown')",
        "kind='login_failed'",
    ),
    "severity": ("Endpoint alerts by severity", "bar", "severity", "source='endpoint'"),
    "critical_trend": (
        "Daily critical endpoint alerts",
        "line",
        "cast(cast(timestamp AS DATE) AS VARCHAR)",
        "source='endpoint' AND severity='Critical' AND timestamp IS NOT NULL",
    ),
    "firewall": (
        "Firewall actions by protocol",
        "bar",
        "protocol || ' / ' || action",
        "source='firewall'",
    ),
    "threat_hosts": (
        "Hosts with the most threat flags",
        "bar",
        "coalesce(hostname,'Unknown')",
        "threat",
    ),
    "mfa_trend": (
        "Daily MFA failures",
        "line",
        "cast(cast(timestamp AS DATE) AS VARCHAR)",
        "kind='mfa_failed' AND timestamp IS NOT NULL",
    ),
    "activity_trend": (
        "Daily telemetry volume",
        "line",
        "cast(cast(timestamp AS DATE) AS VARCHAR)",
        "timestamp IS NOT NULL",
    ),
    "alert_types": (
        "Most frequent endpoint alert types",
        "bar",
        "kind",
        "source='endpoint'",
    ),
    "inactive": (
        "Activity associated with inactive identities",
        "bar",
        "coalesce(user_id,'Unknown')",
        "identity_status='Inactive'",
    ),
}


def local_intent(question):
    q = question.lower()
    if "mfa" in q:
        return "mfa_trend"
    if "inactive" in q or "terminated" in q:
        return "inactive"
    if "critical" in q and any(w in q for w in ["trend", "daily", "time"]):
        return "critical_trend"
    if "severity" in q:
        return "severity"
    if any(w in q for w in ["failed", "failure"]):
        return "failed_departments" if "department" in q else "failed_users"
    if "protocol" in q or ("allow" in q and "deny" in q):
        return "firewall"
    if "threat" in q and any(w in q for w in ["host", "hostname"]):
        return "threat_hosts"
    if "alert" in q and any(w in q for w in ["type", "frequent", "top"]):
        return "alert_types"
    if any(w in q for w in ["activity", "volume", "telemetry"]) and any(
        w in q for w in ["trend", "daily", "time"]
    ):
        return "activity_trend"
    return None


@app.post("/api/ask")
def ask():
    body = request.get_json()
    if (
        not isinstance(body, dict)
        or not isinstance(body.get("question"), str)
        or not 3 <= len(body["question"].strip()) <= 500
    ):
        raise BadRequest("Ask a question between 3 and 500 characters.")
    question = body["question"].strip()
    requested_window = re.search(
        r"(?:last|past)\s+(\d+)\s+(days?|hours?|months?|years?)", question.lower()
    )
    if requested_window and (
        requested_window[1] not in {"7", "30"}
        or requested_window[2] not in {"day", "days"}
    ):
        return jsonify(
            error="The query catalog supports last 7 days, last 30 days, or the All time filter. Choose one of these windows."
        ), 422
    intent, engine, warning = local_intent(question), "Local query engine", None
    if os.getenv("DEEPSEEK_API_KEY"):
        # Retrieve the closest supported question templates; the model selects one and never executes SQL.
        catalog = {k: v[0] for k, v in QUESTIONS.items()}
        try:
            response = requests.post(
                "https://api.deepseek.com/chat/completions",
                headers={"Authorization": "Bearer " + os.environ["DEEPSEEK_API_KEY"]},
                json={
                    "model": os.getenv("DEEPSEEK_MODEL", "deepseek-v4-flash"),
                    "thinking": {"type": "disabled"},
                    "response_format": {"type": "json_object"},
                    "max_tokens": 150,
                    "messages": [
                        {
                            "role": "system",
                            "content": 'Return JSON {"intent": "catalog_key"} selecting the supported analytical intent. Use null for unsupported questions. Catalog: '
                            + json.dumps(catalog),
                        },
                        {"role": "user", "content": question},
                    ],
                },
                timeout=20,
            )
            response.raise_for_status()
            candidate = json.loads(
                response.json()["choices"][0]["message"]["content"]
            ).get("intent")
            if candidate in QUESTIONS:
                intent, engine = candidate, "DeepSeek · validated query"
            elif candidate is not None:
                raise ValueError("Unsupported model intent")
            else:
                intent = None
        except (requests.RequestException, ValueError, KeyError, IndexError, TypeError):
            warning = "DeepSeek was unavailable or returned an invalid response. Used the local query engine."
    if not intent:
        return jsonify(
            error="This question is outside the supported query catalog. Try failed logins by department, endpoint severity, critical alert trends, firewall protocols, or top threat hosts.",
            suggestions=[v[0] for v in QUESTIONS.values()],
        ), 422
    args = {
        k: v
        for k, v in body.items()
        if k in {"period", "source", "severity", "department", "q"}
    }
    days = re.search(r"(?:last|past)\s+(7|30)\s+days", question.lower())
    if days:
        args["period"] = days.group(1)
    if "all time" in question.lower():
        args["period"] = "all"
    departments = query(
        "SELECT DISTINCT department FROM events WHERE department!='Unknown'"
    )
    named = [
        r["department"]
        for r in departments
        if re.search(
            r"\b" + re.escape(r["department"].lower()) + r"\b", question.lower()
        )
        and (r["department"] != "IT" or re.search(r"\bIT\b", question))
    ]
    if len(named) > 1:
        return jsonify(
            error="Use the department comparison question with All departments, or select one department in the filters."
        ), 422
    if named:
        args["department"] = named[0]
    title, chart, group, condition = QUESTIONS[intent]
    sql = (
        f"SELECT {group} AS label, count(*) AS value FROM events WHERE {{where}} AND {condition} GROUP BY 1 ORDER BY "
        + ("label" if chart == "line" else "value DESC, label")
        + " LIMIT 60"
    )
    rows = selected(sql, args)
    top = max(rows, key=lambda r: r["value"]) if rows else None
    answer = (
        f"{top['label']} has the highest count: {top['value']:,}. The chart contains {sum(r['value'] for r in rows):,} matching events across {len(rows)} groups."
        if top
        else "No matching events in this scope. Try All sources or a wider time window."
    )
    where, params = scope(args)
    return jsonify(
        title=title,
        chart=chart,
        rows=rows,
        answer=answer,
        engine=engine,
        warning=warning,
        sql=sql.replace("{where}", where),
        parameters=[str(p) for p in params],
        scope=args,
        note="Dates are relative to the latest dataset event, not today. Up to 60 groups. Risk flags are indicators, not confirmed incidents.",
    )


@app.errorhandler(BadRequest)
def bad_request(error):
    return jsonify(error=error.description), 400


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    return response


initialize()

if __name__ == "__main__":
    from waitress import serve

    print(
        "Sentinel IQ running at http://localhost:" + os.getenv("PORT", "5000"),
        flush=True,
    )
    serve(app, host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")))
