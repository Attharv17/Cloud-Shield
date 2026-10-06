import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from app import create_app
from app.db import get_db
from app.detection import process_event
from app.risk import severity, tick
from app.risk.config import load_policy
from app.risk.queries import entity_detail, incident_detail
from conftest import PASSWORD, login, token
from test_detection import emit


@pytest.fixture
def clock(monkeypatch):
    state = [datetime(2026, 10, 6, 12, tzinfo=timezone.utc)]
    monkeypatch.setattr("app.detection.detection_now", lambda: state[0])
    return state


def rows(app, table):
    with app.app_context():
        return [dict(row) for row in get_db().execute(f"SELECT * FROM {table} ORDER BY id")]


def entity(app, kind="ip", key="192.0.2.1"):
    with app.app_context():
        row = get_db().execute("SELECT id FROM risk_entities WHERE entity_type = ? AND entity_key = ?", (kind, key)).fetchone()
        return entity_detail(row[0])


def attack(app, clock, count=3, user=None):
    for index in range(count):
        if index:
            clock[0] += timedelta(seconds=60)
        emit(app, "access_denied", restricted=True, user=user)


def maintain(app):
    with app.app_context():
        return tick()


@pytest.mark.parametrize("score, expected", [(0, "low"), (24, "low"), (25, "medium"), (49, "medium"),
                                          (50, "high"), (74, "high"), (75, "critical"), (100, "critical")])
def test_severity_boundaries(app, score, expected):
    with app.app_context():
        assert severity(score) == expected


def test_score_ledger_saturates_and_attributes_only_verified_users(app, clock):
    attack(app, clock, 5, user=1)
    ip = entity(app)
    user = entity(app, "user", "1")
    assert ip["score"] == user["score"] == 100
    assert ip["changes"][-1]["requested_delta"] == 25
    assert ip["changes"][-1]["applied_delta"] == 0
    for item in [ip, user]:
        running = 0
        for change in item["changes"]:
            assert change["before_score"] == running
            running += change["applied_delta"]
            assert change["after_score"] == running
        assert running == item["score"]
    for _ in range(5):
        emit(app, "login_failed", ip="192.0.2.2")
    assert entity(app, "user", "1")["score"] == 100
    assert entity(app, "ip", "192.0.2.2")["score"] == 20


def test_retry_does_not_duplicate_scores_incidents_or_actions(app, clock):
    attack(app, clock)
    before = {table: len(rows(app, table)) for table in ["risk_changes", "incidents", "alerts", "actions", "action_audit"]}
    with app.app_context():
        event_ids = [row[0] for row in get_db().execute("SELECT id FROM events")]
        for event_id in event_ids:
            process_event(event_id)
            process_event(event_id)
    assert {table: len(rows(app, table)) for table in before} == before
    assert entity(app)["score"] == 75


def test_blocked_requests_are_logged_without_risk_or_expiry_extension(app, client, clock):
    attack(app, clock)
    active = rows(app, "actions")[0]
    clock[0] += timedelta(seconds=100)
    for path in ["/", "/auth/login", "/api/events", "/admin"]:
        response = client.get(path, environ_overrides={"REMOTE_ADDR": "192.0.2.1"})
        assert response.status_code == 429
        assert int(response.headers["Retry-After"]) == 200
    assert entity(app)["score"] == 75
    assert len(rows(app, "findings")) == 3
    assert rows(app, "actions")[0]["expires_at"] == active["expires_at"]
    assert all(event["event_type"] == "request_blocked" for event in rows(app, "events")[-4:])
    assert client.get("/health", environ_overrides={"REMOTE_ADDR": "192.0.2.1"}).status_code == 200


def test_decay_and_release_at_exact_boundary_without_requests(app, clock):
    attack(app, clock)
    clock[0] += timedelta(seconds=299)
    maintain(app)
    assert entity(app)["score"] == 75
    assert rows(app, "actions")[0]["status"] == "active"
    clock[0] += timedelta(seconds=1)
    maintain(app)
    assert entity(app)["score"] == 65
    assert rows(app, "actions")[0]["status"] == "expired"
    assert rows(app, "action_audit")[-1]["transition"] == "released"
    assert len(rows(app, "alerts")) == 2  # High and critical escalations; no alert on downward transition.


def test_critical_block_renews_only_after_expiry(app, clock):
    attack(app, clock, 4)
    assert entity(app)["score"] == 100
    expiry = datetime.fromisoformat(rows(app, "actions")[0]["expires_at"])
    clock[0] = expiry
    maintain(app)
    actions = rows(app, "actions")
    assert len(actions) == 2 and actions[0]["status"] == "expired" and actions[1]["status"] == "active"
    assert rows(app, "action_audit")[-1]["transition"] == "renewed"
    maintain(app)
    assert len(rows(app, "actions")) == 2


def test_restarted_concurrent_workers_catch_up_decay_once(app, clock):
    attack(app, clock)
    clock[0] += timedelta(seconds=600)
    restarted = create_app(dict(app.config))
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: maintain(restarted), range(4)))
    result = entity(app)
    assert result["score"] == 55
    decay = [change for change in result["changes"] if change["kind"] == "decay"]
    assert len(decay) == 1 and decay[0]["interval_count"] == 2
    clock[0] += timedelta(days=1)
    maintain(app)
    result = entity(app)
    assert result["score"] == 0
    assert result["changes"][-1]["applied_delta"] == -55
    assert result["changes"][-1]["requested_delta"] < -55


def test_normal_reduction_requires_quiet_period_and_cooldown(app, clock):
    emit(app, "access_denied", restricted=True)
    clock[0] += timedelta(seconds=299)
    emit(app)
    assert entity(app)["score"] == 25
    clock[0] += timedelta(seconds=1)
    emit(app)
    assert entity(app)["score"] == 10  # -10 decay, then -5 normal.
    emit(app)
    assert entity(app)["score"] == 10
    assert [change["kind"] for change in entity(app)["changes"]] == ["finding", "decay", "normal"]


def test_suspicious_events_without_new_findings_reset_quiet_period(app, clock):
    emit(app, "access_denied", restricted=True)
    clock[0] += timedelta(seconds=59)
    emit(app, "login_failed")
    clock[0] += timedelta(seconds=241)
    maintain(app)
    assert entity(app)["score"] == 25
    clock[0] += timedelta(seconds=59)
    maintain(app)
    assert entity(app)["score"] == 15


def test_incidents_link_events_findings_and_changes_and_close_independently(app, clock):
    emit(app, "access_denied", restricted=True)
    clock[0] += timedelta(seconds=10)
    emit(app, user=1)
    emit(app, "access_denied", restricted=True, ip="192.0.2.2")
    with app.app_context():
        first = incident_detail(1)
        assert {item["kind"] for item in first["timeline"]} == {"event", "score"}
        assert len(first["findings"]) == 1
        assert first["peak_score"] == 25
        assert {item["entity_type"] for item in first["entities"]} == {"ip", "user"}
    clock[0] += timedelta(seconds=590)
    maintain(app)
    assert rows(app, "incidents")[0]["status"] == "closed"
    assert rows(app, "incidents")[1]["status"] == "open"
    emit(app, "access_denied", restricted=True)
    assert len(rows(app, "incidents")) == 3


def test_effective_response_uses_higher_user_or_ip_score(app, client, clock):
    login(client)  # Establish the user on 127.0.0.1 at zero.
    attack(app, clock, user=1)  # A different source raises the verified user's score to critical.
    assert entity(app, "ip", "127.0.0.1")["score"] == 0
    assert client.get("/").status_code == 429  # User score enforces across source IPs.
    assert entity(app, "ip", "127.0.0.1")["score"] == 0


def test_shared_user_updates_peak_of_all_associated_open_incidents(app, clock):
    emit(app, "access_denied", restricted=True, user=1, ip="192.0.2.1")
    emit(app, "access_denied", restricted=True, user=1, ip="192.0.2.2")
    assert entity(app, "user", "1")["score"] == 50
    assert [incident["peak_score"] for incident in rows(app, "incidents")] == [50, 50]


def test_admin_views_alert_acknowledgement_and_api_authorization(app, client, clock):
    attack(app, clock)
    login(client, "administrator")
    paths = ["/admin/risk", "/admin/entities/1", "/admin/incidents/1", "/api/entities", "/api/entities/1",
             "/api/incidents", "/api/incidents/1", "/api/alerts"]
    for path in paths:
        assert client.get(path).status_code == 200
    assert client.get("/api/entities/9999").status_code == 404
    assert client.get("/api/incidents/9999").status_code == 404
    assert client.post("/api/alerts/1/acknowledge").status_code == 400
    csrf = token(client.get("/"))
    first = client.post("/api/alerts/1/acknowledge", data={"csrf_token": csrf})
    assert first.status_code == 200 and first.json["acknowledged_by"] == 2
    second = client.post("/api/alerts/1/acknowledge", data={"csrf_token": csrf})
    assert second.json["acknowledged_at"] == first.json["acknowledged_at"]
    html_ack = client.post("/admin/alerts/2/acknowledge", data={"csrf_token": csrf})
    assert html_ack.status_code == 303 and html_ack.headers["Location"].endswith("/admin/risk")
    login(client)
    for path in paths:
        assert client.get(path).status_code == 403


def test_authenticated_recovery_is_audited(app, clock):
    attack(app, clock)
    entity_id = entity(app)["id"]
    runner = app.test_cli_runner()
    args = ["recover-entity", "--entity-id", str(entity_id), "--admin-username", "administrator", "--reason", "Reset controlled demo block"]
    assert runner.invoke(args=args, input="wrong-password\n").exit_code != 0
    assert entity(app)["score"] == 75
    result = runner.invoke(args=args, input=PASSWORD + "\n")
    assert result.exit_code == 0, result.output
    assert PASSWORD not in result.output
    assert entity(app)["score"] == 0
    assert rows(app, "actions")[0]["status"] == "revoked"
    assert entity(app)["changes"][-1]["actor_id"] == 2
    assert rows(app, "action_audit")[-1]["actor_id"] == 2
    assert runner.invoke(args=["risk-maintain"]).exit_code == 0


def test_risk_failure_rolls_back_event_finding_and_ledger(app, clock, monkeypatch):
    def fail(*args):
        raise RuntimeError("simulated decision failure")
    monkeypatch.setattr("app.risk._decide", fail)
    with pytest.raises(RuntimeError, match="simulated"):
        emit(app, "access_denied", restricted=True)
    for table in ["events", "findings", "risk_changes", "risk_entities", "incidents", "alerts", "actions"]:
        assert rows(app, table) == []


def test_risk_policy_validation_and_version_retention(app, tmp_path, clock):
    emit(app, "access_denied", restricted=True)
    previous = entity(app)["changes"][0]["policy_version"]
    settings = dict(app.extensions["risk"]["policy"])
    settings["decay_points"] = 3
    path = tmp_path / "risk.json"
    path.write_text(json.dumps(settings))
    app.config["RISK_POLICY_FILE"] = str(path)
    load_policy(app)
    clock[0] += timedelta(seconds=300)
    maintain(app)
    result = entity(app)
    assert result["score"] == 22
    assert result["changes"][0]["policy_version"] == previous
    assert result["changes"][-1]["policy_version"] != previous
    settings["medium_threshold"] = 90
    path.write_text(json.dumps(settings))
    with pytest.raises(RuntimeError, match="increasing"):
        load_policy(app)
