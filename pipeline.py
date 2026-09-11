"""Reproducible normalization: supplied telemetry -> audited DuckDB + clean CSVs."""

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import duckdb
import pandas as pd

ROOT = Path(__file__).resolve().parent
RAW = ROOT / "track2_cybersecurity_dataset_files"
DATA = ROOT / "data"
DB = DATA / "sentinel.duckdb"
MISSING = {
    "",
    "na",
    "n/a",
    "nan",
    "none",
    "null",
    "unknown",
    "not available",
    "nat",
    "-",
}
DEPARTMENTS = {
    "Human Resources": [
        "hr",
        "human resource",
        "human resources",
        "people team",
        "hr dept",
    ],
    "IT": ["it", "it dept", "information technology", "information tech", "it support"],
    "Finance": ["finance", "fin", "accounts", "finance dept"],
    "Operations": ["operations", "ops", "ops team", "operations dept"],
    "Sales": ["sales", "business sales", "sales team", "sales dept"],
    "Marketing": ["marketing", "mkt", "mktg", "brand team", "marketing dept"],
    "Legal": ["legal", "legal dept", "compliance"],
    "Procurement": [
        "procurement",
        "procurement team",
        "purchase",
        "purch",
        "supply chain",
    ],
    "Customer Support": [
        "support",
        "customer support",
        "cs",
        "customer care",
        "call center",
    ],
    "Research & Development": [
        "r&d",
        "rd",
        "rnd",
        "research and development",
        "innovation",
    ],
}
DEPT_MAP = {v: k for k, vs in DEPARTMENTS.items() for v in vs}


def clean_text(value):
    if pd.isna(value):
        return ""
    value = str(value).strip()
    return "" if value.lower() in MISSING else value


def key(value, prefix):
    value = re.sub(r"[\s_-]", "", clean_text(value).upper())
    if not value:
        return None
    if value.isdigit():
        value = prefix + value
    return value if re.fullmatch(prefix + r"\d+", value) else None


def host(value):
    value = clean_text(value).upper().replace(".CORP.LOCAL", "").replace("_", "-")
    value = re.sub(r"\s+", "", value)
    value = re.sub(r"^(WS|LPT|VDR)(\d+)$", r"\1-\2", value)
    return value or None


def timestamp(value):
    value = clean_text(value)
    if not value:
        return None
    try:
        if re.fullmatch(r"\d{10}(\.0)?|\d{13}", value):
            number = float(value)
            return datetime.fromtimestamp(
                number / 1000 if number > 1e12 else number, timezone.utc
            ).replace(tzinfo=None)
        # Slashed day-first dates and US hyphenated 12-hour dates are distinct source formats.
        for fmt in (
            "%m-%d-%Y %I:%M:%S %p",
            "%d/%m/%Y %H:%M",
            "%d/%m/%Y %H:%M:%S",
            "%d/%m/%Y",
            "%d-%b-%Y %H:%M:%S",
            "%Y/%m/%d",
            "%Y/%m/%d %H:%M:%S",
        ):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                pass
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return (
            parsed.astimezone(timezone.utc).replace(tzinfo=None)
            if parsed.tzinfo
            else parsed
        )
    except (ValueError, OverflowError, OSError):
        return None


def ip(value):
    try:
        return str(ipaddress.ip_address(clean_text(value)))
    except ValueError:
        return None


def number(value, maximum=None):
    value = clean_text(value).replace(",", "").replace("/100", "")
    try:
        n = float(value)
        return (
            n
            if pd.notna(n)
            and n != float("inf")
            and n >= 0
            and (maximum is None or n <= maximum)
            else None
        )
    except ValueError:
        return None


def byte_count(value):
    text = clean_text(value).replace(",", "").upper()
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*(KB|MB|GB|B)?", text)
    if not match:
        return None
    return round(
        float(match[1])
        * {None: 1, "B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}[match[2]]
    )


def boolean(value):
    value = clean_text(value).lower()
    return (
        True
        if value in {"true", "yes", "y", "1", "1.0"}
        else False
        if value in {"false", "no", "n", "0", "0.0"}
        else None
    )


def build(raw=RAW, destination=DATA):
    destination = Path(destination)
    destination.mkdir(exist_ok=True, parents=True)
    tables, audits = {}, []
    specs = [
        ("identities", "identity_asset_master.csv", "user_id"),
        ("firewall", "firewall_logs.csv", "log_id"),
        ("iam", "iam_audit_trail.json", "event_id"),
        ("endpoint", "endpoint_alerts.xlsx", "alert_id"),
    ]
    for name, filename, id_col in specs:
        path = Path(raw) / ("track2_" + filename)
        original = (
            pd.read_excel(path)
            if path.suffix == ".xlsx"
            else pd.read_json(path)
            if path.suffix == ".json"
            else pd.read_csv(path, low_memory=False)
        )
        df = original.copy()
        for col in df.columns:
            if col in {"user_id", "device_id", "session_id"}:
                prefix = {"user_id": "EMP", "device_id": "DEV", "session_id": "SID"}[
                    col
                ]
                df[col] = df[col].map(lambda v, prefix=prefix: key(v, prefix))
            elif col == "hostname":
                df[col] = df[col].map(host)
            elif "timestamp" in col or col in {"hire_date", "termination_date"}:
                df[col] = pd.to_datetime(df[col].map(timestamp), errors="coerce")
            elif col in {"src_ip", "dst_ip", "source_ip"}:
                df[col] = df[col].map(ip)
            elif col in {"src_port", "dst_port"}:
                df[col] = (
                    df[col]
                    .map(lambda v: number(v, 65535))
                    .map(lambda v: v if pd.notna(v) and float(v).is_integer() else None)
                )
            elif col in {"bytes_sent", "bytes_received"}:
                df[col] = df[col].map(byte_count)
            elif col == "risk_score":
                df[col] = df[col].map(lambda v: number(v, 100))
            elif col in {"threat_flag", "mfa_passed"}:
                df[col] = df[col].map(boolean)
            elif col == "department":
                df[col] = df[col].map(
                    lambda v: DEPT_MAP.get(clean_text(v).lower(), "Unknown")
                )
            else:
                df[col] = df[col].map(clean_text)
        if name == "identities":
            df["status"] = (
                df.status.str.lower()
                .map(
                    {
                        **dict.fromkeys(
                            ["live", "active", "a", "working", "enabled"], "Active"
                        ),
                        **dict.fromkeys(
                            [
                                "disabled",
                                "deactivated",
                                "exited",
                                "left",
                                "terminated",
                                "d",
                                "resigned",
                                "blocked",
                            ],
                            "Inactive",
                        ),
                        **dict.fromkeys(
                            ["l", "leave", "on leave", "on_leave", "lwp", "ooo"],
                            "On leave",
                        ),
                    }
                )
                .fillna("Unknown")
            )
        if name == "firewall":
            df["action"] = (
                df.action.str.lower()
                .map(
                    {
                        **dict.fromkeys(["allow", "permit", "pass"], "Allow"),
                        **dict.fromkeys(["deny", "drop", "block"], "Deny"),
                    }
                )
                .fillna("Unknown")
            )
            df["protocol"] = (
                df.protocol.str.lower()
                .map(
                    {
                        **dict.fromkeys(["tcp", "tcp/6", "6"], "TCP"),
                        **dict.fromkeys(["udp", "udp/17", "17"], "UDP"),
                        **dict.fromkeys(["icmp", "ping", "1"], "ICMP"),
                    }
                )
                .fillna("Unknown")
            )
            df["geo_country"] = (
                df.geo_country.str.strip()
                .str.title()
                .replace(
                    {
                        "Usa": "United States",
                        "Us": "United States",
                        "Uk": "United Kingdom",
                        "In": "India",
                        "Ind": "India",
                        "Ru": "Russia",
                        "Cn": "China",
                        "": "Unknown",
                    }
                )
            )
        if name == "iam":

            def event(v):
                v = re.sub(r"[\s-]+", "_", v.lower())
                if v == "mfa_failed":
                    return "mfa_failed"
                if "fail" in v or v == "invalid_credentials":
                    return "login_failed"
                if "success" in v:
                    return "login_success"
                return v or "other"

            df["event_type"] = df.event_type.map(event)
        if name == "endpoint":
            df["severity"] = (
                df.severity.str.lower()
                .map(
                    {
                        **dict.fromkeys(
                            ["critical", "crit", "severe", "p1"], "Critical"
                        ),
                        **dict.fromkeys(["high", "h", "major", "p2"], "High"),
                        **dict.fromkeys(["medium", "m", "moderate", "p3"], "Medium"),
                        **dict.fromkeys(["low", "l", "minor", "p4"], "Low"),
                    }
                )
                .fillna("Unknown")
            )
            df["status"] = (
                df.status.str.lower()
                .map(
                    {
                        **dict.fromkeys(
                            ["new", "n", "open", "o", "unassigned", "active"], "Open"
                        ),
                        **dict.fromkeys(["resolved", "r", "closed"], "Resolved"),
                        **dict.fromkeys(
                            ["wip", "in_progress", "in progress", "investigating"],
                            "Investigating",
                        ),
                        **dict.fromkeys(
                            ["not malicious", "false_positive", "false positive", "fp"],
                            "False positive",
                        ),
                    }
                )
                .fillna("Unknown")
            )
            df["alert_name"] = (
                df.alert_name.str.replace("_", " ")
                .str.lower()
                .replace(
                    {
                        "ransomware behavior": "ransomware activity",
                        "suspicious powershell": "suspicious powershell execution",
                        "unauthorized usb": "usb device blocked",
                    }
                )
                .str.capitalize()
            )
            df["invalid_resolution"] = df.resolved_timestamp.lt(df.detected_timestamp)
            df.loc[df.invalid_resolution, "resolved_timestamp"] = pd.NaT
            df["sha256"] = df.sha256.map(
                lambda v: v.lower() if re.fullmatch(r"[a-fA-F0-9]{64}", v) else None
            )
        changed, invalid = {}, {}
        for col in original.columns:
            before = original[col].map(clean_text)
            after = df[col].astype(str).replace({"None": "", "NaT": "", "nan": ""})
            changed[col] = int((before != after).sum())
            invalid[col] = int((before.ne("") & (df[col].isna() | after.eq(""))).sum())
        # Prefer the most complete record for duplicate normalized primary keys; preserve stable ties.
        df["_completeness"] = df.replace("", pd.NA).notna().sum(axis=1)
        missing_ids = int(df[id_col].isna().sum() + df[id_col].eq("").sum())
        df = (
            df[df[id_col].notna() & df[id_col].ne("")]
            .sort_values("_completeness", ascending=False, kind="stable")
            .drop_duplicates(id_col)
            .drop(columns="_completeness")
            .sort_values(id_col)
            .reset_index(drop=True)
        )
        tables[name] = df
        audits.append(
            {
                "source": name,
                "file": path.name,
                "raw": len(original),
                "clean": len(df),
                "duplicates": len(original) - len(df) - missing_ids,
                "missing_ids": missing_ids,
                "changed": changed,
                "invalid": invalid,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    identities = tables["identities"]
    by_user = identities.set_index("user_id").to_dict("index")
    by_host = (
        identities.dropna(subset=["hostname"])
        .drop_duplicates("hostname")
        .set_index("hostname")
        .to_dict("index")
    )
    events = []
    for source in ("firewall", "iam", "endpoint"):
        for r in tables[source].to_dict("records"):
            owner = (
                by_user.get(r.get("user_id")) or by_host.get(r.get("hostname")) or {}
            )
            uid = r.get("user_id") or owner.get("user_id")
            kind = (
                r.get("alert_name")
                or r.get("event_type")
                or ("Firewall " + r["action"])
            )
            score = r.get("risk_score")
            if source == "endpoint":
                score = {"Critical": 95, "High": 75, "Medium": 45, "Low": 20}.get(
                    r["severity"], 0
                )
            elif source == "firewall":
                score = (
                    85
                    if r["threat_flag"] is True
                    else 40
                    if r["action"] == "Deny"
                    else 10
                )
            elif pd.isna(score):
                score = 70 if r["event_type"] in {"login_failed", "mfa_failed"} else 15
            severity = r.get("severity") or (
                "Critical"
                if score >= 90
                else "High"
                if score >= 70
                else "Medium"
                if score >= 40
                else "Low"
            )
            flags = []
            ts = r.get("detected_timestamp", r.get("timestamp"))
            if pd.isna(ts):
                flags.append("Invalid or missing timestamp")
            if not owner:
                flags.append("Unmatched identity")
            if r.get("invalid_resolution"):
                flags.append("Resolution precedes detection")
            if source == "iam" and pd.isna(r.get("risk_score")):
                flags.append("Risk score inferred")
            if (
                source == "endpoint"
                and owner
                and owner.get("hostname") != r.get("hostname")
            ):
                flags.append("Host differs from identity master")
            events.append(
                {
                    "id": r.get("log_id") or r.get("event_id") or r.get("alert_id"),
                    "source": source,
                    "timestamp": ts,
                    "hostname": r.get("hostname"),
                    "user_id": uid,
                    "username": owner.get("username", r.get("username", "Unknown")),
                    "department": owner.get(
                        "department", r.get("department", "Unknown")
                    ),
                    "identity_status": owner.get("status", "Unknown"),
                    "kind": kind,
                    "severity": severity,
                    "risk": int(score),
                    "status": r.get("status", "Observed"),
                    "source_ip": r.get("src_ip", r.get("source_ip")),
                    "country": r.get("geo_country", "Unknown"),
                    "protocol": r.get("protocol", ""),
                    "action": r.get("action", ""),
                    "threat": bool(r.get("threat_flag") is True),
                    "session_id": r.get("session_id"),
                    "quality_flags": " | ".join(flags),
                    "resolution_hours": (r["resolved_timestamp"] - ts).total_seconds()
                    / 3600
                    if source == "endpoint"
                    and pd.notna(r["resolved_timestamp"])
                    and pd.notna(ts)
                    else None,
                }
            )
    tables["events"] = pd.DataFrame(events)
    report = {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "sources": audits,
        "raw_rows": sum(a["raw"] for a in audits),
        "clean_rows": sum(a["clean"] for a in audits),
        "event_rows": len(events),
        "flagged_events": sum(bool(e["quality_flags"]) for e in events),
        "invalid_resolutions": int(tables["endpoint"].invalid_resolution.sum()),
        "unmatched_events": sum(
            "Unmatched identity" in e["quality_flags"] for e in events
        ),
        "timestamp_policy": "Naive source times treated as UTC; dd/mm/YYYY is day-first; mm-dd-YYYY with AM/PM is month-first. Invalid values remain null. No fuzzy or approximate temporal joins.",
    }
    temp_db = destination / "building.duckdb"
    with duckdb.connect(str(temp_db)) as con:
        for name, df in tables.items():
            con.register("frame", df)
            con.execute(f'CREATE OR REPLACE TABLE "{name}" AS SELECT * FROM frame')
            df.to_csv(destination / f"{name}.csv", index=False)
        con.execute(
            "CREATE OR REPLACE VIEW daily_activity AS SELECT cast(timestamp AS DATE) AS day, source, department, count(*) AS events, count(*) FILTER (WHERE risk >= 70) AS high_risk FROM events GROUP BY ALL"
        )
        con.execute(
            "CREATE OR REPLACE VIEW host_exposure AS SELECT hostname, count(*) events, count(DISTINCT source) sources, count(*) FILTER (WHERE risk >= 70) high_risk, max(risk) peak_risk FROM events WHERE hostname IS NOT NULL GROUP BY hostname"
        )
        assert con.execute("SELECT count(*) FROM events").fetchone()[0] == sum(
            len(tables[s]) for s in ("iam", "endpoint", "firewall")
        )
        assert (
            con.execute("SELECT count(*) - count(DISTINCT id) FROM events").fetchone()[
                0
            ]
            == 0
        )
    temp_db.replace(destination / "sentinel.duckdb")
    (destination / "quality.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    return report


if __name__ == "__main__":
    report = build()
    print(json.dumps({k: v for k, v in report.items() if k != "sources"}, indent=2))
