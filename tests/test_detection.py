import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from app import create_app
from app.db import get_db, migrate
from app.detection import process_event
from app.detection.config import load_rules
from app.models import save_event
from conftest import PASSWORD, login


@pytest.fixture
def clock(monkeypatch):
    state = [datetime(2026, 10, 6, 12, tzinfo=timezone.utc)]
    monkeypatch.setattr("app.detection.detection_now", lambda: state[0])
    return state


def emit(app, event_type="application_request", *, ip="192.0.2.1", user=None,
         device=None, restricted=False, rate=True, request_id=None):
    with app.app_context():
        return save_event({
            "request_id": request_id or str(uuid4()),
            "timestamp": "2026-10-06T12:00:00.000+00:00",
            "event_type": event_type, "source_ip": ip, "user_id": user,
            "route": "/admin" if restricted else "/", "method": "GET", "status": 403 if restricted else 200,
            "metadata": {"authenticated": user is not None, "restricted_access": restricted,
                         "rate_eligible": rate, **({"device_fingerprint": device} if device else {})},
        })


def findings(app, rule=None):
    with app.app_context():
        rows = get_db().execute("SELECT * FROM findings ORDER BY id").fetchall()
        return [dict(row) for row in rows if rule is None or row["rule_id"] == rule]


def test_failed_login_threshold_evidence_and_source_isolation(app, clock):
    for _ in range(4):
        emit(app, "login_failed")
        emit(app, "login_failed", ip="192.0.2.2")
    assert findings(app) == []
    event_id = emit(app, "login_failed")
    result = findings(app)
    assert len(result) == 1
    assert result[0]["rule_id"] == "failed_login_burst"
    assert result[0]["weight"] == 20 and result[0]["observed_count"] == 5
    assert result[0]["user_id"] is None
    assert result[0]["event_id"] == event_id
    with app.app_context():
        rows = get_db().execute("SELECT e.source_ip FROM finding_events f JOIN events e ON e.id = f.event_id").fetchall()
        assert len(rows) == 5 and {row[0] for row in rows} == {"192.0.2.1"}


def test_window_excludes_events_exactly_at_cutoff(app, clock):
    for _ in range(4):
        emit(app, "login_failed")
    clock[0] += timedelta(seconds=60)
    emit(app, "login_failed")
    assert findings(app) == []
    for _ in range(4):
        emit(app, "login_failed")
    assert findings(app)[0]["observed_count"] == 5


def test_cooldown_expires_at_exact_boundary(app, clock):
    for _ in range(5):
        emit(app, "login_failed")
    clock[0] += timedelta(seconds=59)
    for _ in range(5):
        emit(app, "login_failed")
    assert len(findings(app)) == 1
    clock[0] += timedelta(seconds=1)
    emit(app, "login_failed")
    assert len(findings(app)) == 2
    assert findings(app)[1]["observed_count"] == 6


def test_rate_threshold_is_strictly_greater_and_excludes_polling(app, clock):
    for _ in range(100):
        emit(app)
    emit(app, rate=False)
    emit(app, ip="192.0.2.2")
    assert findings(app) == []
    emit(app)
    result = findings(app)
    assert len(result) == 1
    assert result[0]["rule_id"] == "high_request_frequency"
    assert result[0]["observed_count"] == 101 and result[0]["weight"] == 15
    emit(app)
    assert len(findings(app)) == 1


def test_rate_window_expires(app, clock):
    for _ in range(100):
        emit(app)
    clock[0] += timedelta(seconds=60)
    emit(app)
    assert findings(app) == []


def test_restricted_access_does_not_flag_normal_login_redirects(app, client, clock):
    assert client.get("/").status_code == 302
    assert findings(app) == []
    assert client.get("/admin").status_code == 302
    assert len(findings(app, "restricted_access")) == 1
    login(client)
    assert client.get("/admin").status_code == 403
    assert len(findings(app, "restricted_access")) == 1  # Same IP cooldown.
    clock[0] += timedelta(seconds=60)
    client.get("/admin")
    assert len(findings(app, "restricted_access")) == 2
    clock[0] += timedelta(seconds=60)
    login(client, "administrator")
    assert client.get("/admin").status_code == 200
    assert len(findings(app, "restricted_access")) == 2


def test_sources_bootstrap_combine_novelty_and_remember_independent_contexts(app, clock):
    emit(app, "login_success", user=1, device="first")
    emit(app, "login_success", user=1, device="first")
    assert findings(app) == []
    emit(app, "login_success", user=1, ip="192.0.2.2", device="second")
    result = findings(app)
    assert len(result) == 1 and result[0]["weight"] == 10
    assert result[0]["entity_type"] == "user" and result[0]["entity_key"] == "1"
    assert "IP address and browser marker" in result[0]["reason"]
    emit(app, "login_success", user=1, ip="192.0.2.1", device="second")
    emit(app, "login_success", user=1, ip="192.0.2.2", device="first")
    emit(app, "login_success", user=2, ip="192.0.2.2", device="second")
    assert len(findings(app)) == 1  # Known combinations and a different user's first login.
    emit(app, "login_success", user=1, ip="192.0.2.3", device="first")
    assert "unfamiliar IP address." in findings(app)[-1]["reason"]
    emit(app, "login_failed", device="not-a-baseline")
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM source_contexts WHERE fingerprint = 'not-a-baseline'").fetchone()[0] == 0


def test_browser_marker_persists_logout_and_tampering_creates_new_context(app, client, clock):
    login(client)
    cookie = client.get_cookie("cloudshield_device")
    assert cookie.http_only and cookie.same_site == "Lax"
    login(client)
    assert findings(app, "new_source_context") == []
    client.set_cookie("cloudshield_device", "tampered-value")
    login(client)
    assert len(findings(app, "new_source_context")) == 1
    with app.app_context():
        all_metadata = str([tuple(row) for row in get_db().execute("SELECT metadata FROM events")])
        assert cookie.value not in all_metadata and "tampered-value" not in all_metadata


def test_event_retry_and_configuration_change_never_duplicate_findings(app, clock, tmp_path):
    request_id = str(uuid4())
    event_id = emit(app, "access_denied", restricted=True, request_id=request_id)
    with app.app_context():
        initial = process_event(event_id)
        assert process_event(event_id) == initial
    assert emit(app, "access_denied", restricted=True, request_id=request_id) == event_id
    rules = json.loads(app.extensions["detection"]["configuration"])
    rules["restricted_access"]["weight"] = 30
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(rules))
    app.config["DETECTION_RULES_FILE"] = str(path)
    old_version = findings(app)[0]["config_version"]
    load_rules(app)
    with app.app_context():
        assert process_event(event_id) == initial
    assert len(findings(app)) == 1
    assert findings(app)[0]["weight"] == 25
    emit(app, "access_denied", restricted=True)  # Configuration change does not reset cooldown.
    assert len(findings(app)) == 1
    clock[0] += timedelta(seconds=60)
    emit(app, "access_denied", restricted=True)
    assert findings(app)[-1]["weight"] == 30
    assert findings(app)[-1]["config_version"] != old_version


def test_findings_and_events_rollback_together(app, clock, monkeypatch):
    def fail(*args):
        raise RuntimeError("simulated evaluation failure")
    monkeypatch.setattr("app.detection._source_context", fail)
    with pytest.raises(RuntimeError, match="simulated"):
        emit(app, "access_denied", restricted=True)
    with app.app_context():
        for table in ["events", "findings", "finding_events", "detection_evaluations", "detection_configs"]:
            assert get_db().execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_concurrent_events_produce_one_finding_with_complete_evidence(app, clock):
    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(lambda _: emit(app, "login_failed"), range(8)))
    result = findings(app)
    assert len(result) == 1 and result[0]["observed_count"] == 5
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM events").fetchone()[0] == 8
        assert get_db().execute("SELECT COUNT(*) FROM detection_evaluations").fetchone()[0] == 8


def test_restart_keeps_cooldown_and_context_history(app, clock):
    emit(app, "access_denied", restricted=True)
    emit(app, "login_success", user=1, device="first")
    restarted = create_app(dict(app.config))
    emit(restarted, "access_denied", restricted=True)
    emit(restarted, "login_success", user=1, device="first")
    assert len(findings(app)) == 1
    clock[0] -= timedelta(hours=1)
    emit(restarted, "access_denied", restricted=True)
    assert len(findings(app)) == 1


@pytest.mark.parametrize("change", ["missing_rule", "extra_field", "negative", "boolean", "zero"])
def test_invalid_rule_configuration_fails_at_startup(app, tmp_path, change):
    rules = json.loads(app.extensions["detection"]["configuration"])
    if change == "missing_rule":
        rules.pop("new_source_context")
    elif change == "extra_field":
        rules["restricted_access"]["typo"] = 10
    else:
        rules["failed_login_burst"]["threshold"] = {"negative": -1, "boolean": True, "zero": 0}[change]
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(rules))
    with pytest.raises(RuntimeError):
        create_app({**dict(app.config), "DETECTION_RULES_FILE": str(path)})


def test_findings_views_and_apis_enforce_roles_and_show_evidence(app, client, clock):
    paths = ["/admin/findings", "/admin/findings/1", "/api/findings", "/api/findings/1", "/api/settings"]
    for path in paths:
        assert client.get(path).status_code == (401 if path.startswith("/api/") else 302)
    login(client)
    for path in paths:
        assert client.get(path).status_code == 403
    login(client, "administrator")
    for path in paths:
        assert client.get(path).status_code == 200
    result = client.get("/api/findings/1").json
    assert result["rule_id"] == "restricted_access"
    assert len(result["evidence"]) == result["observed_count"] == 1
    assert result["configuration"]["restricted_access"]["weight"] == 25
    assert client.get("/api/findings/99999").status_code == 404
    assert client.get("/admin/findings/99999").status_code == 404
    assert client.get("/api/findings?page=-10&per_page=200").json["per_page"] == 100
    assert client.get("/api/settings").json["version"] == result["config_version"]
    assert client.get("/api/overview").json["findings"]["total"] == 1
    with app.app_context():
        assert json.loads(get_db().execute("SELECT metadata FROM events ORDER BY id DESC LIMIT 1").fetchone()[0])["rate_eligible"] is False


def test_local_demo_generates_all_four_rules_without_network(app, clock, monkeypatch):
    import socket
    def no_network(*args, **kwargs):
        raise AssertionError("Demo must never open a network connection")
    monkeypatch.setattr(socket, "create_connection", no_network)
    app.config["ENVIRONMENT"] = "development"
    result = app.test_cli_runner().invoke(args=["demo-traffic", "--username", "analyst"], input=PASSWORD + "\n")
    assert result.exit_code == 0, result.output
    assert PASSWORD not in result.output
    assert {item["rule_id"] for item in findings(app)} == {
        "failed_login_burst", "restricted_access", "high_request_frequency", "new_source_context",
    }


@pytest.mark.parametrize("case", ["production", "admin", "bad_password", "excessive_threshold"])
def test_demo_rejects_unsupported_use(app, case):
    app.config["ENVIRONMENT"] = "production" if case == "production" else "development"
    if case == "excessive_threshold":
        app.extensions["detection"]["rules"]["failed_login_burst"]["threshold"] = 100
    result = app.test_cli_runner().invoke(
        args=["demo-traffic", "--username", "administrator" if case == "admin" else "analyst"],
        input=("incorrect-password" if case == "bad_password" else PASSWORD) + "\n",
    )
    assert result.exit_code != 0
    assert findings(app) == []


def test_upgrade_preserves_legacy_events_without_retroactive_detection(app, tmp_path, clock):
    database = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(database)
    schema = Path(__file__).resolve().parents[1] / "migrations/001_foundation.sql"
    connection.executescript(schema.read_text(encoding="utf-8"))
    connection.executescript(
        "CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL);"
        "INSERT INTO schema_migrations VALUES ('001_foundation', '2026-10-06T00:00:00Z');"
        "INSERT INTO users VALUES (1, 'legacy', 'preserved-hash', 'user', '2026-10-06T00:00:00Z');"
        "INSERT INTO events VALUES (1, 'legacy-request', '2026-10-06T12:00:00.000+00:00',"
        "'login_failed', '192.0.2.1', NULL, '/auth/login', 'POST', 401, '{}');"
    )
    connection.close()
    upgraded = create_app({**dict(app.config), "DATABASE": str(database)})
    with upgraded.app_context():
        migrate()
        migrate()
        assert get_db().execute("SELECT password_hash FROM users WHERE id = 1").fetchone()[0] == "preserved-hash"
        assert get_db().execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
        assert get_db().execute("SELECT COUNT(*) FROM detection_evaluations").fetchone()[0] == 0
    for _ in range(4):
        emit(upgraded, "login_failed")
    assert findings(upgraded) == []
    emit(upgraded, "login_failed")
    assert findings(upgraded)[0]["observed_count"] == 5
