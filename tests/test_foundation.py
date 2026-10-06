import json
import sqlite3
from datetime import datetime

import pytest
from werkzeug.security import check_password_hash

from app import create_app
from app.db import get_db, migrate
from app.models import find_user
from conftest import PASSWORD, login, token


def all_events(app):
    with app.app_context():
        return [dict(row) for row in get_db().execute("SELECT * FROM events ORDER BY id")]


def test_migration_is_repeatable_and_preserves_data(app):
    with app.app_context():
        user = find_user("analyst")
        assert user["password_hash"] != PASSWORD
        assert check_password_hash(user["password_hash"], PASSWORD)
        migrate()
        assert get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 2
        assert get_db().execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 3
        with pytest.raises(sqlite3.IntegrityError):
            get_db().execute("UPDATE users SET role = 'owner' WHERE id = ?", (user["id"],))


def test_login_logout_and_access_lifecycle(app, client):
    assert client.get("/").status_code == 302
    assert login(client).status_code == 302
    page = client.get("/")
    assert b"Welcome, analyst" in page.data
    assert client.post("/auth/logout", data={"csrf_token": token(page)}).status_code == 302
    assert client.get("/").status_code == 302
    events = all_events(app)
    successful = next(e for e in events if e["event_type"] == "login_success")
    logout_event = next(e for e in events if e["event_type"] == "logout")
    assert successful["user_id"] == logout_event["user_id"]
    assert events[-1]["user_id"] is None


@pytest.mark.parametrize("username", ["analyst", "unknown", "' OR 1=1 --"])
def test_failed_login_is_anonymous_and_generic(app, client, username):
    response = login(client, username, "incorrect-password")
    assert response.status_code == 401
    assert b"Invalid username or password." in response.data
    event = all_events(app)[-1]
    assert event["event_type"] == "login_failed"
    assert event["user_id"] is None
    assert event["status"] == 401
    assert client.get("/api/events").status_code == 401


def test_csrf_is_required_for_login_and_logout(app, client):
    assert client.post("/auth/login", data={"username": "analyst", "password": PASSWORD}).status_code == 400
    assert all_events(app)[-1]["event_type"] == "csrf_rejected"
    login(client)
    assert client.post("/auth/logout").status_code == 400
    assert client.get("/").status_code == 200
    assert client.get("/auth/logout").status_code == 405


def test_role_checks_protect_html_and_json(app, client):
    assert client.get("/admin").status_code == 302
    assert client.get("/api/overview").status_code == 401
    login(client)
    for path in ("/admin", "/api/events", "/api/overview"):
        assert client.get(path).status_code == 403
        assert all_events(app)[-1]["event_type"] == "access_denied"
    login(client, "administrator")
    for path in ("/admin", "/api/events", "/api/overview"):
        assert client.get(path).status_code == 200
        assert all_events(app)[-1]["event_type"] == "application_request"


def test_sanitized_logging_and_untrusted_forwarding_headers(app, client):
    csrf_token = token(client.get("/auth/login"))
    response = client.post(
        "/auth/login?token=query-secret", data={
            "username": "analyst", "password": "private-password-value",
            "csrf_token": csrf_token, "extra": "sensitive-body",
        }, headers={"Authorization": "Bearer header-secret", "X-Forwarded-For": "8.8.8.8",
                    "X-Request-ID": "attacker-id"},
        environ_overrides={"REMOTE_ADDR": "192.0.2.42"},
    )
    event = all_events(app)[-1]
    assert event["source_ip"] == "192.0.2.42"
    assert event["route"] == "/auth/login"
    assert event["request_id"] == response.headers["X-Request-ID"]
    assert event["request_id"] != "attacker-id"
    assert datetime.fromisoformat(event["timestamp"]).utcoffset().total_seconds() == 0
    serialized = json.dumps(all_events(app))
    for secret in ["query-secret", "private-password-value", "sensitive-body", "header-secret", csrf_token]:
        assert secret not in serialized
    client.get("/unknown/path-secret")
    assert all_events(app)[-1]["route"] == "(unmatched)"


def test_health_static_and_dashboard_rate_exclusions(app, client):
    assert client.get("/health").json == {"status": "ok"}
    assert client.get("/static/style.css").status_code == 200
    assert all_events(app) == []
    login(client, "administrator")
    client.get("/api/events")
    assert json.loads(all_events(app)[-1]["metadata"])["rate_eligible"] is False
    client.get("/")
    assert json.loads(all_events(app)[-1]["metadata"])["rate_eligible"] is True


def test_admin_pagination_counts_and_security_headers(app, client):
    login(client, "administrator")
    response = client.get("/api/events?page=-1&per_page=1000")
    assert response.json["page"] == 1
    assert response.json["per_page"] == 100
    assert "password_hash" not in response.get_data(as_text=True)
    assert response.headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    expected_total = len(all_events(app))
    overview = client.get("/api/overview")
    assert overview.json["total"] == expected_total
    assert overview.json["by_type"]["login_success"] == 1
    assert client.get("/api/events?page=2&per_page=1").json["events"]


def test_cli_account_creation_and_duplicate_protection(app):
    runner = app.test_cli_runner()
    result = runner.invoke(args=["create-user", "--username", "new-admin", "--role", "admin"],
                           input=f"{PASSWORD}\n{PASSWORD}\n")
    assert result.exit_code == 0, result.output
    with app.app_context():
        assert find_user("new-admin")["role"] == "admin"
    duplicate = runner.invoke(args=["create-user", "--username", "new-admin"],
                              input=f"{PASSWORD}\n{PASSWORD}\n")
    assert duplicate.exit_code != 0
    assert "already exists" in duplicate.output
    assert runner.invoke(args=["init-db"]).exit_code == 0


def test_configuration_rejects_missing_secret_and_insecure_production():
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app({"SECRET_KEY": ""})
    with pytest.raises(RuntimeError, match="HTTPS"):
        create_app({"SECRET_KEY": "x" * 32, "ENVIRONMENT": "production", "SESSION_COOKIE_SECURE": False})


def test_role_changes_take_effect_on_next_request(app, client):
    login(client, "administrator")
    assert client.get("/admin").status_code == 200
    with app.app_context():
        connection = get_db()
        connection.execute("UPDATE users SET role = 'user' WHERE username = 'administrator'")
        connection.commit()
    assert client.get("/admin").status_code == 403
