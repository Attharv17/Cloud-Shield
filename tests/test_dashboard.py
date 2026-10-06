"""Stage 4: dashboard overview, investigation, settings, entity/incident pages, and demo data."""

from app import create_app
from conftest import PASSWORD, login, token
from test_detection import emit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def admin_login(client):
    login(client, "administrator")


def _snapshot_hours(client, hours=24):
    return client.get(f"/api/dashboard?hours={hours}")


def _settings(client):
    return client.get("/api/settings")


# ---------------------------------------------------------------------------
# Overview / dashboard API
# ---------------------------------------------------------------------------

def test_health_static_and_dashboard_endpoints_exist(app, client):
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 200
    admin_login(client)
    response = _snapshot_hours(client)
    assert response.status_code == 200
    data = response.json
    assert "metrics" in data and "series" in data and "threats" in data
    assert set(data["metrics"]) == {"application_events", "flagged_events", "critical_entities", "active_blocks"}
    assert set(data["series"]) == {"labels", "events", "risk"}
    assert all(item["rule"] for item in data["threats"])


def test_overview_page_renders_for_admin(app, client):
    admin_login(client)
    assert client.get("/admin/overview").status_code == 200


def test_overview_rejects_invalid_hours(app, client):
    admin_login(client)
    assert client.get("/api/dashboard?hours=999").status_code == 400
    assert client.get("/api/dashboard?hours=0").status_code == 400
    assert client.get("/api/dashboard?hours=1").status_code == 200


def test_overview_metrics_agree_with_stored_records(app, client, monkeypatch):
    # Space events 61 seconds apart so each bypasses the 60s cooldown
    from datetime import datetime, timedelta, timezone
    clock = [datetime(2026, 10, 6, 12, tzinfo=timezone.utc)]
    monkeypatch.setattr("app.detection.detection_now", lambda: clock[0])
    for _ in range(3):
        emit(app, "access_denied", restricted=True)
        clock[0] += timedelta(seconds=61)
    admin_login(client)
    data = _snapshot_hours(client).json
    assert data["metrics"]["critical_entities"] >= 1
    assert data["metrics"]["flagged_events"] >= 3


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def test_settings_api_returns_current_config(app, client):
    admin_login(client)
    data = _settings(client).json
    assert "version" in data and "rules" in data
    assert "restricted_access" in data["rules"]
    assert "risk_policy" in data and "risk_version" in data
    assert data["risk_policy"]["critical_threshold"] == 75


def test_settings_page_renders(app, client):
    admin_login(client)
    assert client.get("/admin/settings").status_code == 200


def test_settings_requires_admin(app, client):
    login(client)
    assert client.get("/api/settings").status_code == 403
    assert client.get("/admin/settings").status_code == 403


# ---------------------------------------------------------------------------
# Admin panels: entity detail, incident timeline, risk page
# ---------------------------------------------------------------------------

def test_findings_views_and_apis_exist_and_require_admin(app, client):
    emit(app, "access_denied", restricted=True)
    admin_login(client)
    assert client.get("/admin/findings").status_code == 200
    assert client.get("/admin/findings/1").status_code == 200
    assert client.get("/admin/findings/9999").status_code == 404
    assert client.get("/api/findings").status_code == 200
    assert client.get("/api/findings/1").status_code == 200
    login(client)
    assert client.get("/admin/findings").status_code == 403
    assert client.get("/api/findings").status_code == 403


def test_role_checks_protect_html_and_api_views(app, client):
    for _ in range(3):
        emit(app, "access_denied", restricted=True)
    login(client)
    protected = ["/admin", "/admin/risk", "/admin/overview", "/admin/investigate",
                 "/admin/settings", "/admin/entities/1", "/admin/incidents/1",
                 "/api/entities", "/api/entities/1", "/api/incidents", "/api/incidents/1",
                 "/api/alerts", "/api/dashboard"]
    for path in protected:
        assert client.get(path).status_code == 403, f"{path} should be 403 for non-admin"


def test_admin_pagination_counts_and_investigate_filters(app, client):
    for _ in range(3):
        emit(app, "access_denied", restricted=True)
    admin_login(client)
    assert client.get("/admin/investigate?kind=entities&state=critical").status_code == 200
    assert client.get("/admin/investigate?kind=findings&state=restricted_access").status_code == 200
    assert client.get("/admin/investigate?kind=events&state=access_denied").status_code == 200
    assert client.get("/admin/investigate?kind=alerts&state=unacknowledged").status_code == 200
    # Invalid kind should 400
    assert client.get("/admin/investigate?kind=invalid").status_code == 400
    # API path
    response = client.get("/api/investigate?kind=entities")
    assert response.status_code == 200
    assert "records" in response.json


# ---------------------------------------------------------------------------
# Alert acknowledgement
# ---------------------------------------------------------------------------

def test_admin_views_alert_acknowledgement_flow(app, client, monkeypatch):
    # Space events 61 seconds apart so each bypasses the 60s cooldown
    # 1st: +25 → medium, 2nd: +25 → high (alert created), 3rd: +25 → critical (alert created)
    from datetime import datetime, timedelta, timezone
    clock = [datetime(2026, 10, 6, 12, tzinfo=timezone.utc)]
    monkeypatch.setattr("app.detection.detection_now", lambda: clock[0])
    for _ in range(3):
        emit(app, "access_denied", restricted=True)
        clock[0] += timedelta(seconds=61)
    admin_login(client)
    # Confirm alerts exist
    with app.app_context():
        from app.db import get_db
        row = get_db().execute("SELECT id FROM alerts ORDER BY id LIMIT 1").fetchone()
    assert row is not None, "Expected alerts to be created at high/critical thresholds"
    alert_id = row[0]
    csrf = token(client.get("/"))
    # Acknowledge via API
    response = client.post(f"/api/alerts/{alert_id}/acknowledge", data={"csrf_token": csrf})
    assert response.status_code == 200
    ack_at = response.json["acknowledged_at"]
    assert ack_at is not None
    # Idempotent: second acknowledgement returns same timestamp
    response2 = client.post(f"/api/alerts/{alert_id}/acknowledge", data={"csrf_token": csrf})
    assert response2.json["acknowledged_at"] == ack_at
    # HTML acknowledge redirects to risk page (use a second alert if available)
    with app.app_context():
        from app.db import get_db
        row2 = get_db().execute("SELECT id FROM alerts WHERE id != ? ORDER BY id LIMIT 1", (alert_id,)).fetchone()
    if row2:
        html_resp = client.post(f"/admin/alerts/{row2[0]}/acknowledge", data={"csrf_token": csrf})
        assert html_resp.status_code == 303


# ---------------------------------------------------------------------------
# Investigate: paginated across all kinds
# ---------------------------------------------------------------------------

def test_investigate_events_and_incidents_are_searchable(app, client):
    emit(app, "access_denied", restricted=True, ip="192.0.2.99")
    admin_login(client)
    for kind in ("entities", "incidents", "findings", "events", "alerts"):
        assert client.get(f"/admin/investigate?kind={kind}").status_code == 200
    result = client.get("/api/investigate?kind=entities&q=192.0.2.99").json
    assert result["total"] >= 1


# ---------------------------------------------------------------------------
# Demo: deterministic escalation to critical
# ---------------------------------------------------------------------------

def _dev_app(base_app):
    """Return a test-client app configured as development for demo tests."""
    return create_app({k: v for k, v in base_app.config.items()} | {"ENVIRONMENT": "development"})


def test_local_demo_generates_all_four_finding_types(app):
    """demo-traffic command produces a finding for each rule."""
    dev_app = _dev_app(app)
    runner = dev_app.test_cli_runner()
    result = runner.invoke(args=["demo-traffic", "--username", "analyst"], input=PASSWORD + "\n")
    assert result.exit_code == 0, result.output
    output = result.output
    assert "failed_login_burst" in output
    assert "restricted_access" in output
    assert "high_request_frequency" in output
    assert "new_source_context" in output
    assert "4 new findings" in output


def test_demo_rejects_unsupported_credentials(app):
    """demo-traffic refuses admin accounts and invalid passwords."""
    dev_app = _dev_app(app)
    runner = dev_app.test_cli_runner()
    result = runner.invoke(args=["demo-traffic", "--username", "administrator"], input=PASSWORD + "\n")
    assert result.exit_code != 0

    result = runner.invoke(args=["demo-traffic", "--username", "analyst"], input="wrong-password\n")
    assert result.exit_code != 0
