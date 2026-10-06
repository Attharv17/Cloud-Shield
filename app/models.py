"""Small persistence layer for the foundation's users and events."""

import json
import re
from datetime import datetime, timezone

from werkzeug.security import generate_password_hash

from .db import get_db


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def find_user(username):
    return get_db().execute(
        "SELECT * FROM users WHERE username = ?", (username.strip().lower(),)
    ).fetchone()


def get_user(user_id):
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def create_user(username, password, role="user"):
    username = username.strip().lower()
    if not re.fullmatch(r"[a-z0-9_.-]{3,64}", username):
        raise ValueError("Username must be 3-64 letters, digits, dots, underscores or hyphens.")
    if not 12 <= len(password) <= 256:
        raise ValueError("Password must contain 12-256 characters.")
    if role not in {"admin", "user"}:
        raise ValueError("Role must be admin or user.")
    connection = get_db()
    with connection:
        cursor = connection.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(password), role, utc_now()),
        )
    return cursor.lastrowid


def save_event(event):
    from .detection import evaluate_event

    connection = get_db()
    with connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "INSERT INTO events (request_id, timestamp, event_type, source_ip, user_id, "
            "route, method, status, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(request_id) DO NOTHING",
            (event["request_id"], event["timestamp"], event["event_type"],
             event["source_ip"], event["user_id"], event["route"], event["method"],
             event["status"], json.dumps(event["metadata"], sort_keys=True)),
        )
        event_id = connection.execute(
            "SELECT id FROM events WHERE request_id = ?", (event["request_id"],)
        ).fetchone()[0]
        evaluate_event(connection, event_id)
    return event_id


def recent_events(page=1, per_page=25):
    rows = get_db().execute(
        "SELECT e.*, u.username FROM events e LEFT JOIN users u ON u.id = e.user_id "
        "ORDER BY e.id DESC LIMIT ? OFFSET ?", (per_page, (page - 1) * per_page)
    ).fetchall()
    return [{**dict(row), "metadata": json.loads(row["metadata"])} for row in rows]


def event_counts():
    connection = get_db()
    total = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    types = connection.execute(
        "SELECT event_type, COUNT(*) AS count FROM events GROUP BY event_type"
    ).fetchall()
    return {"total": total, "by_type": {row["event_type"]: row["count"] for row in types}}
