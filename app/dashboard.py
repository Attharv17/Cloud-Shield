"""Administrator overview and parameterized, paginated investigation queries."""
from datetime import datetime, timedelta, timezone

from flask import Blueprint, abort, jsonify, render_template, request

from .auth import admin_required
from .db import get_db
from .risk import policy, severity

bp = Blueprint("dashboard", __name__)
RULE_NAMES = {"failed_login_burst": "Failed login burst", "high_request_frequency": "Rapid requests",
              "restricted_access": "Restricted access", "new_source_context": "New source context"}
KINDS = {
    "entities": ["low", "medium", "high", "critical"],
    "incidents": ["open", "closed"],
    "findings": list(RULE_NAMES),
    "events": ["login_success", "login_failed", "access_denied", "application_request", "request_blocked", "csrf_rejected", "logout"],
    "alerts": ["high", "critical", "unacknowledged", "acknowledged"],
}


def selected_hours():
    value = request.args.get("hours", "24")
    if value not in {"1", "24", "168"}:
        abort(400, "Choose a 1, 24 or 168 hour window.")
    return int(value)


def snapshot(hours=24, now=None):
    connection = get_db()
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    bounds = (start.isoformat(), now.isoformat())
    labels = [(start + timedelta(hours=hours * (index + 1) / 24)).isoformat() for index in range(24)]
    event_series = [0] * 24
    # Exclude routine monitoring traffic from application volume, but retain denied/blocked access.
    event_rows = connection.execute(
        "SELECT e.timestamp FROM events e WHERE julianday(e.timestamp) > julianday(?) "
        "AND julianday(e.timestamp) <= julianday(?) AND (json_extract(e.metadata, '$.rate_eligible') = 1 "
        "OR e.event_type IN ('login_success','login_failed','logout','access_denied','request_blocked','csrf_rejected'))", bounds
    ).fetchall()
    for row in event_rows:
        offset = (datetime.fromisoformat(row[0]) - start).total_seconds()
        event_series[min(23, max(0, int(offset / (hours * 3600 / 24))))] += 1
    threats = {key: 0 for key in RULE_NAMES}
    for row in connection.execute(
        "SELECT rule_id, COUNT(*) FROM findings WHERE julianday(created_at) > julianday(?) "
        "AND julianday(created_at) <= julianday(?) GROUP BY rule_id", bounds
    ):
        threats[row[0]] = row[1]
    flagged = connection.execute(
        "SELECT COUNT(DISTINCT event_id) FROM findings WHERE julianday(created_at) > julianday(?) AND julianday(created_at) <= julianday(?)", bounds
    ).fetchone()[0]
    # Reconstruct per-entity state at each bucket end, including its pre-window baseline.
    scores = {row["entity_id"]: row["after_score"] for row in connection.execute(
        "SELECT c.entity_id, c.after_score FROM risk_changes c JOIN "
        "(SELECT entity_id, MAX(id) AS id FROM risk_changes WHERE julianday(created_at) <= julianday(?) GROUP BY entity_id) b ON b.id = c.id",
        (bounds[0],)
    )}
    changes = connection.execute(
        "SELECT entity_id, after_score, created_at FROM risk_changes WHERE julianday(created_at) > julianday(?) "
        "AND julianday(created_at) <= julianday(?) ORDER BY created_at, id", bounds
    ).fetchall()
    risk_series, cursor = [], 0
    for label in labels:
        while cursor < len(changes) and datetime.fromisoformat(changes[cursor]["created_at"]) <= datetime.fromisoformat(label):
            scores[changes[cursor]["entity_id"]] = changes[cursor]["after_score"]
            cursor += 1
        risk_series.append(max(scores.values(), default=0))
    critical = connection.execute("SELECT COUNT(*) FROM risk_entities WHERE score >= ?", (policy()["critical_threshold"],)).fetchone()[0]
    blocks = [dict(row) for row in connection.execute(
        "SELECT a.id, a.entity_id, r.entity_type, r.entity_key, a.expires_at FROM actions a JOIN risk_entities r "
        "ON r.id=a.entity_id WHERE a.status='active' ORDER BY a.expires_at LIMIT 5"
    )]
    active = connection.execute("SELECT COUNT(*) FROM actions WHERE status='active'").fetchone()[0]
    alerts = [dict(row) for row in connection.execute(
        "SELECT a.*, r.entity_type, r.entity_key FROM alerts a JOIN risk_entities r ON r.id=a.entity_id "
        "WHERE julianday(a.created_at) > julianday(?) AND julianday(a.created_at) <= julianday(?) ORDER BY a.id DESC LIMIT 5", bounds
    )]
    return {
        "hours": hours, "start": bounds[0], "as_of": bounds[1],
        "metrics": {"application_events": len(event_rows), "flagged_events": flagged,
                    "critical_entities": critical, "active_blocks": active},
        "series": {"labels": labels, "events": event_series, "risk": risk_series},
        "threats": [{"rule": key, "label": RULE_NAMES[key], "count": value} for key, value in threats.items()],
        "alerts": alerts, "blocks": blocks,
    }


def investigate(kind, query="", state="", page=1, per_page=25):
    if kind not in KINDS or (state and state not in KINDS[kind]):
        abort(400, "Invalid investigation filter.")
    query = query.strip()[:100]
    pattern = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    tables = {
        "entities": ("risk_entities x LEFT JOIN users u ON x.entity_type='user' AND CAST(u.id AS TEXT)=x.entity_key", "x.entity_key", "COALESCE(u.username,'')"),
        "incidents": ("incidents x", "x.source_ip", "x.status"),
        "findings": ("findings x LEFT JOIN users u ON u.id=x.user_id", "x.source_ip", "COALESCE(u.username,'')"),
        "events": ("events x LEFT JOIN users u ON u.id=x.user_id", "x.source_ip", "COALESCE(u.username,'')"),
        "alerts": ("alerts x JOIN risk_entities r ON r.id=x.entity_id", "r.entity_key", "x.reason"),
    }
    table, first, second = tables[kind]
    where = f"({first} LIKE ? ESCAPE '\\' OR {second} LIKE ? ESCAPE '\\')"
    parameters = [pattern, pattern]
    if state:
        if kind == "entities":
            limits = {"low": (0, policy()["medium_threshold"]), "medium": (policy()["medium_threshold"], policy()["high_threshold"]),
                      "high": (policy()["high_threshold"], policy()["critical_threshold"]), "critical": (policy()["critical_threshold"], 101)}
            where += " AND x.score >= ? AND x.score < ?"
            parameters.extend(limits[state])
        elif kind == "alerts" and state in {"acknowledged", "unacknowledged"}:
            where += " AND x.acknowledged_at IS " + ("NOT NULL" if state == "acknowledged" else "NULL")
        else:
            column = {"incidents": "status", "findings": "rule_id", "events": "event_type", "alerts": "severity"}[kind]
            where += f" AND x.{column} = ?"
            parameters.append(state)
    connection = get_db()
    total = connection.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}", parameters).fetchone()[0]
    extra = ", u.username" if kind in {"entities", "findings", "events"} else ", r.entity_key" if kind == "alerts" else ""
    records = [dict(row) for row in connection.execute(
        f"SELECT x.*{extra} FROM {table} WHERE {where} ORDER BY x.id DESC LIMIT ? OFFSET ?", parameters + [per_page, (page - 1) * per_page]
    )]
    for record in records:
        if kind == "entities":
            record["severity"] = severity(record["score"])
    return {"kind": kind, "query": query, "state": state, "page": page, "per_page": per_page,
            "total": total, "has_next": page * per_page < total, "records": records}


@bp.get("/admin/overview")
@admin_required
def overview():
    return render_template("overview.html", data=snapshot(selected_hours()))


@bp.get("/api/dashboard")
@admin_required
def data():
    return jsonify(snapshot(selected_hours()))


@bp.get("/admin/investigate", endpoint="investigation_page")
@bp.get("/api/investigate")
@admin_required
def investigation():
    result = investigate(request.args.get("kind", "entities"), request.args.get("q", ""), request.args.get("state", ""),
                         min(1000000, max(1, request.args.get("page", 1, type=int))), 25)
    if request.path.startswith("/api/"):
        return jsonify(result)
    return render_template("investigate.html", result=result, kinds=KINDS)


@bp.get("/admin/settings")
@admin_required
def settings_page():
    from flask import current_app
    config = current_app.extensions["detection"]
    risk = current_app.extensions["risk"]
    return render_template("settings.html", settings={
        "version": config["version"],
        "rules": config["rules"],
        "risk_policy": risk["policy"],
        "risk_version": risk["version"],
    })
