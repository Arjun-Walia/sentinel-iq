"""SentinalIQ: analytical API and retrieval-augmented security workspace."""

import csv
import io
import json
import os
import shutil
import sqlite3
from datetime import timedelta
from pathlib import Path

import duckdb
import requests
from dotenv import load_dotenv
from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    send_from_directory,
)
from werkzeug.exceptions import BadRequest

import rag
from pipeline import DATA as BUNDLED_DATA
from pipeline import DB as BUNDLED_DB
from pipeline import build

load_dotenv()
DATA = BUNDLED_DATA
DB = BUNDLED_DB

if os.getenv("VERCEL"):
    DATA = Path("/tmp/sentinaliq-data")
    DB = DATA / "sentinaliq.duckdb"
    if not DB.exists():
        DATA.mkdir(parents=True, exist_ok=True)
        for filename in ("sentinaliq.duckdb", "quality.json", "cases.sqlite"):
            source = BUNDLED_DATA / filename
            if source.exists():
                shutil.copy2(source, DATA / filename)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024


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
    period = str(args.get("period", "30")).strip().lower()
    if period != "all" and (not period.isdigit() or not 1 <= int(period) <= 3650):
        raise BadRequest("Period must be all or a number of days from 1 to 3650.")
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


@app.get("/public/<path:filename>")
def public_asset(filename):
    return send_from_directory(Path(app.root_path) / "public", filename, max_age=86400)


@app.get("/robots.txt")
@app.get("/sitemap.xml")
@app.get("/favicon.svg")
@app.get("/site.webmanifest")
@app.get("/social-card.png")
@app.get("/social-card.svg")
def search_metadata():
    return send_from_directory(Path(app.root_path) / "public", request.path.lstrip("/"))


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
        agent="DeepSeek V4 Flash · RAG"
        if os.getenv("DEEPSEEK_API_KEY")
        else "AI not connected",
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
        headers={
            "Content-Disposition": 'attachment; filename="sentinaliq-evidence.csv"'
        },
    )


@app.post("/api/ask")
def ask():
    body = request.get_json(silent=True)
    if (
        not isinstance(body, dict)
        or not isinstance(body.get("question"), str)
        or not 2 <= len(body["question"].strip()) <= 500
    ):
        raise BadRequest("Ask a question between 2 and 500 characters.")
    history = body.get("history", [])
    if (
        not isinstance(history, list)
        or len(history) > 8
        or any(
            not isinstance(item, dict)
            or item.get("role") not in {"user", "assistant"}
            or not isinstance(item.get("content"), str)
            or len(item["content"]) > 7000
            for item in history
        )
    ):
        raise BadRequest("Invalid conversation history.")
    args = {
        "period": "30",
        **{
            key: body[key]
            for key in ("period", "source", "severity", "department", "hostname", "q")
            if key in body
        },
    }
    scope(args)
    if not os.getenv("DEEPSEEK_API_KEY"):
        return jsonify(
            error="The AI assistant is not connected. Configure DEEPSEEK_API_KEY on the server to enable answers."
        ), 503
    try:
        return jsonify(
            rag.answer(body["question"].strip(), args, history, query, scope)
        )
    except requests.RequestException:
        app.logger.warning(
            "DeepSeek request failed; no substitute answer was generated."
        )
        return jsonify(
            error="DeepSeek is unavailable right now. Please try again in a moment."
        ), 503
    except (ValueError, KeyError, IndexError, TypeError, duckdb.Error):
        app.logger.warning("DeepSeek retrieval or answer validation failed.")
        return jsonify(
            error="I could not verify the retrieved answer. Please rephrase your question or try again."
        ), 502


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
        "SentinalIQ running at http://localhost:" + os.getenv("PORT", "5000"),
        flush=True,
    )
    serve(app, host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")))
