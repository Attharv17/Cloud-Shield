import math
from datetime import datetime

from flask import Blueprint, abort, g, jsonify, redirect, render_template, request, url_for

from ..auth import admin_required
from ..db import get_db
from ..detection import stamp
from . import clock, maintain
from . import queries

bp = Blueprint("risk_views", __name__)


def enforce():
    if request.endpoint in {"static", "main.health", "main.ready"}:
        return None
    connection = get_db()
    with connection:
        connection.execute("BEGIN IMMEDIATE")
        moment = clock(connection)
        maintain(connection, moment)
        user_id = str(g.user["id"]) if g.user is not None else ""
        block = connection.execute(
            "SELECT a.* FROM actions a JOIN risk_entities r ON r.id = a.entity_id WHERE a.status = 'active' "
            "AND ((r.entity_type = 'ip' AND r.entity_key = ?) OR (r.entity_type = 'user' AND r.entity_key = ?)) "
            "ORDER BY a.expires_at DESC LIMIT 1", (request.remote_addr or "unknown", user_id)
        ).fetchone()
    if block is not None:
        g.event_type = "request_blocked"
        retry_after = max(1, math.ceil((datetime.fromisoformat(block["expires_at"]) - moment).total_seconds()))
        if request.path.startswith("/api/"):
            response = jsonify(error="Temporarily blocked", expires_at=block["expires_at"])
        else:
            response = render_template("blocked.html", expires_at=block["expires_at"])
        return response, 429, {"Retry-After": str(retry_after)}


def pagination():
    return (min(1000000, max(1, request.args.get("page", 1, type=int))),
            min(100, max(1, request.args.get("per_page", 25, type=int))))


@bp.get("/api/entities")
@admin_required
def entity_list():
    page, per_page = pagination()
    return jsonify(entities=queries.entities(page, per_page), page=page, per_page=per_page)


@bp.get("/api/entities/<int:entity_id>")
@admin_required
def entity(entity_id):
    result = queries.entity_detail(entity_id)
    if result is None:
        abort(404)
    return jsonify(result)


@bp.get("/api/incidents")
@admin_required
def incident_list():
    page, per_page = pagination()
    return jsonify(incidents=queries.incidents(page, per_page), page=page, per_page=per_page)


@bp.get("/api/incidents/<int:incident_id>")
@admin_required
def incident(incident_id):
    result = queries.incident_detail(incident_id)
    if result is None:
        abort(404)
    return jsonify(result)


@bp.get("/api/alerts")
@admin_required
def alert_list():
    page, per_page = pagination()
    return jsonify(alerts=queries.alerts(page, per_page), page=page, per_page=per_page)


@bp.post("/admin/alerts/<int:alert_id>/acknowledge", endpoint="acknowledge_page")
@bp.post("/api/alerts/<int:alert_id>/acknowledge")
@admin_required
def acknowledge(alert_id):
    connection = get_db()
    with connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if row is None:
            abort(404)
        if row["acknowledged_at"] is None:
            connection.execute("UPDATE alerts SET acknowledged_at = ?, acknowledged_by = ? WHERE id = ?",
                               (stamp(clock(connection)), g.user["id"], alert_id))
    if not request.path.startswith("/api/"):
        return redirect(url_for("risk_views.dashboard"), code=303)
    return jsonify(dict(connection.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()))


@bp.get("/admin/risk")
@admin_required
def dashboard():
    page, per_page = pagination()
    return render_template("risk.html", entities=queries.entities(page, per_page),
                           incidents=queries.incidents(page, per_page), alerts=queries.alerts(page, per_page),
                           summary=queries.summary(), page=page)


@bp.get("/admin/entities/<int:entity_id>")
@admin_required
def entity_page(entity_id):
    result = queries.entity_detail(entity_id)
    if result is None:
        abort(404)
    return render_template("entity.html", entity=result)


@bp.get("/admin/incidents/<int:incident_id>")
@admin_required
def incident_page(incident_id):
    result = queries.incident_detail(incident_id)
    if result is None:
        abort(404)
    return render_template("incident.html", incident=result)
