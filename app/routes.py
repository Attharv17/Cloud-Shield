from flask import Blueprint, jsonify, render_template, request

from .auth import admin_required, login_required
from .models import event_counts, recent_events

bp = Blueprint("main", __name__)
api = Blueprint("api", __name__, url_prefix="/api")


@bp.get("/")
@login_required
def home():
    return render_template("home.html")


@bp.get("/admin")
@admin_required
def admin():
    page = max(1, request.args.get("page", 1, type=int))
    counts = event_counts()
    return render_template("admin.html", events=recent_events(page), counts=counts, page=page)


@bp.get("/health")
def health():
    return jsonify(status="ok")


@api.get("/events")
@admin_required
def events():
    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(100, max(1, request.args.get("per_page", 25, type=int)))
    return jsonify(events=recent_events(page, per_page), page=page, per_page=per_page)


@api.get("/overview")
@admin_required
def overview():
    return jsonify(event_counts())
