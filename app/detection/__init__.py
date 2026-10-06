"""Transactional, explainable rules over completed and evaluated application events."""

import json
from datetime import datetime, timedelta, timezone

from flask import current_app

from ..db import get_db
from .config import load_rules
from .context import load_device_context, set_device_cookie


def detection_now():
    """UTC processing clock, called after acquiring the database write lock."""
    return datetime.now(timezone.utc)


def stamp(moment):
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _create_finding(connection, event, rule_id, evidence, reason, moment, start, *, entity=None):
    config = current_app.extensions["detection"]
    rule = config["rules"][rule_id]
    entity_type, entity_key = entity or ("ip", event["source_ip"])
    cooldown = rule.get("cooldown_seconds")
    if cooldown:
        previous = connection.execute(
            "SELECT 1 FROM findings WHERE rule_id = ? AND entity_type = ? AND entity_key = ? "
            "AND created_at > ? LIMIT 1",
            (rule_id, entity_type, entity_key, stamp(moment - timedelta(seconds=cooldown))),
        ).fetchone()
        if previous:
            return None
    cursor = connection.execute(
        "INSERT INTO findings (event_id, rule_id, config_version, entity_type, entity_key, "
        "source_ip, user_id, weight, reason, observed_count, window_start, window_end, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (event["id"], rule_id, config["version"], entity_type, str(entity_key),
         event["source_ip"], event["user_id"], rule["weight"], reason, len(evidence),
         stamp(start), stamp(moment), stamp(moment)),
    )
    finding_id = cursor.lastrowid
    connection.executemany(
        "INSERT INTO finding_events (finding_id, event_id) VALUES (?, ?)",
        [(finding_id, event_id) for event_id in evidence],
    )
    return finding_id


def _window_events(connection, event, moment, seconds, *, failures=False):
    # Only evaluated requests count. Legacy Stage 1 events are not retroactively detected.
    condition = "e.event_type = 'login_failed'" if failures else "json_extract(e.metadata, '$.rate_eligible') = 1"
    return [row[0] for row in connection.execute(
        "SELECT e.id FROM events e JOIN detection_evaluations d ON d.event_id = e.id "
        "WHERE e.source_ip = ? AND d.evaluated_at > ? AND d.evaluated_at <= ? AND "
        + condition + " ORDER BY d.evaluated_at, e.id",
        (event["source_ip"], stamp(moment - timedelta(seconds=seconds)), stamp(moment)),
    )]


def _source_context(connection, event, moment):
    metadata = json.loads(event["metadata"])
    device = metadata.get("device_fingerprint")
    if event["event_type"] != "login_success" or event["user_id"] is None or not device:
        return
    user_id = event["user_id"]
    known = {(row["kind"], row["fingerprint"]) for row in connection.execute(
        "SELECT kind, fingerprint FROM source_contexts WHERE user_id = ?", (user_id,)
    )}
    contexts = [("ip", event["source_ip"]), ("device", device)]
    new_kinds = [kind for kind, value in contexts if (kind, value) not in known]
    if known and new_kinds:
        labels = {"ip": "IP address", "device": "browser marker"}
        reason = "Successful login from an unfamiliar " + " and ".join(labels[kind] for kind in new_kinds) + "."
        _create_finding(
            connection, event, "new_source_context", [event["id"]], reason, moment, moment,
            entity=("user", str(user_id)),
        )
    for kind, fingerprint in contexts:
        connection.execute(
            "INSERT INTO source_contexts (user_id, kind, fingerprint, first_seen, last_seen, first_event_id) "
            "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(user_id, kind, fingerprint) "
            "DO UPDATE SET last_seen = excluded.last_seen",
            (user_id, kind, fingerprint, stamp(moment), stamp(moment), event["id"]),
        )


def evaluate_event(connection, event_id):
    """Evaluate once inside the caller's IMMEDIATE transaction; never commit here."""
    if connection.execute("SELECT 1 FROM detection_evaluations WHERE event_id = ?", (event_id,)).fetchone():
        return
    event = connection.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if event is None:
        raise ValueError("Event does not exist.")
    moment = detection_now()
    # A backward system-clock adjustment must not reopen an elapsed cooldown/window.
    previous_time = connection.execute("SELECT MAX(evaluated_at) FROM detection_evaluations").fetchone()[0]
    if previous_time:
        moment = max(moment, datetime.fromisoformat(previous_time))
    from ..risk import apply_event, clock
    moment = clock(connection, moment)
    config = current_app.extensions["detection"]
    connection.execute(
        "INSERT OR IGNORE INTO detection_configs VALUES (?, ?, ?)",
        (config["version"], config["configuration"], stamp(moment)),
    )
    connection.execute(
        "INSERT INTO detection_evaluations VALUES (?, ?, ?)", (event_id, stamp(moment), config["version"])
    )
    metadata = json.loads(event["metadata"])
    if event["event_type"] == "request_blocked":
        apply_event(connection, event_id, moment)
        return
    suspicious = event["event_type"] == "login_failed" or (
        event["event_type"] == "access_denied" and metadata.get("restricted_access") is True
    )
    if event["event_type"] == "login_failed":
        rule = config["rules"]["failed_login_burst"]
        evidence = _window_events(connection, event, moment, rule["window_seconds"], failures=True)
        if len(evidence) >= rule["threshold"]:
            _create_finding(
                connection, event, "failed_login_burst", evidence,
                f"{len(evidence)} failed logins within {rule['window_seconds']} seconds.",
                moment, moment - timedelta(seconds=rule["window_seconds"]),
            )
    if metadata.get("rate_eligible") is True:
        rule = config["rules"]["high_request_frequency"]
        evidence = _window_events(connection, event, moment, rule["window_seconds"])
        if len(evidence) > rule["threshold"]:
            suspicious = True
            _create_finding(
                connection, event, "high_request_frequency", evidence,
                f"{len(evidence)} application requests within {rule['window_seconds']} seconds "
                f"(limit {rule['threshold']}).",
                moment, moment - timedelta(seconds=rule["window_seconds"]),
            )
    if event["event_type"] == "access_denied" and metadata.get("restricted_access") is True:
        _create_finding(
            connection, event, "restricted_access", [event_id],
            f"Unauthorized {event['method']} request to {event['route']}.", moment, moment,
        )
    _source_context(connection, event, moment)
    apply_event(connection, event_id, moment, suspicious)


def process_event(event_id):
    """Retry a persisted event without duplicating findings or source history."""
    connection = get_db()
    with connection:
        connection.execute("BEGIN IMMEDIATE")
        evaluate_event(connection, event_id)
    return [row[0] for row in connection.execute("SELECT id FROM findings WHERE event_id = ?", (event_id,))]


def init_app(app):
    load_rules(app)
    app.before_request(load_device_context)
    app.after_request(set_device_cookie)
