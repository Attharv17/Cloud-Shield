from flask import Blueprint, abort, current_app, jsonify, render_template, request

from .auth import admin_required, login_required
from .models import event_counts, recent_events
from .detection.queries import finding_counts, finding_detail as get_finding, recent_findings

bp = Blueprint("main", __name__)
api = Blueprint("api", __name__, url_prefix="/api")


@bp.get("/")
@login_required
def home():
    return render_template("home.html")


@bp.get("/admin")
@admin_required
def admin():
    page = page_number()
    counts = event_counts()
    return render_template("admin.html", events=recent_events(page), counts=counts, page=page)


@bp.get("/health")
def health():
    return jsonify(status="ok")


@bp.get("/ready")
def ready():
    import sqlite3
    from pathlib import Path
    from .db import get_db
    try:
        applied = {row[0] for row in get_db().execute("SELECT version FROM schema_migrations")}
        expected = {path.stem for path in (Path(current_app.root_path).parent / "migrations").glob("[0-9]*.sql")}
        if not expected.issubset(applied):
            return jsonify(status="unavailable"), 503
        get_db().execute("SELECT id FROM risk_entities LIMIT 1").fetchone()
    except sqlite3.Error:
        return jsonify(status="unavailable"), 503
    return jsonify(status="ready")


@api.get("/events")
@admin_required
def events():
    page = page_number()
    per_page = min(100, max(1, request.args.get("per_page", 25, type=int)))
    return jsonify(events=recent_events(page, per_page), page=page, per_page=per_page)


@api.get("/overview")
@admin_required
def overview():
    from .risk.queries import summary
    return jsonify(**event_counts(), findings=finding_counts(), risk=summary())


def page_number():
    return min(1000000, max(1, request.args.get("page", 1, type=int)))


@bp.get("/admin/findings")
@admin_required
def findings():
    page = page_number()
    return render_template("findings.html", findings=recent_findings(page), counts=finding_counts(), page=page)


@bp.get("/admin/findings/<int:finding_id>")
@admin_required
def finding_detail(finding_id):
    finding = get_finding(finding_id)
    if finding is None:
        abort(404)
    return render_template("finding_detail.html", finding=finding)


@api.get("/findings")
@admin_required
def findings_api():
    page = page_number()
    per_page = min(100, max(1, request.args.get("per_page", 25, type=int)))
    return jsonify(findings=recent_findings(page, per_page), counts=finding_counts(), page=page, per_page=per_page)


@api.get("/findings/<int:finding_id>")
@admin_required
def finding_api(finding_id):
    finding = get_finding(finding_id)
    if finding is None:
        abort(404)
    return jsonify(finding)


@api.get("/settings")
@admin_required
def settings():
    config = current_app.extensions["detection"]
    risk = current_app.extensions["risk"]
    return jsonify(version=config["version"], rules=config["rules"], risk_policy=risk["policy"], risk_version=risk["version"])
