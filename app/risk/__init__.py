"""Atomic risk ledger, incident correlation, decay, and decision lifecycle."""

import json
from datetime import datetime, timedelta
from uuid import uuid4

from flask import current_app

from ..db import get_db
from ..detection import stamp
from .config import load_policy


def policy():
    return current_app.extensions["risk"]["policy"]


def severity(score):
    rules = policy()
    for level in ("critical", "high", "medium"):
        if score >= rules[level + "_threshold"]:
            return level
    return "low"


def recommendation(score):
    return {"low": "allow", "medium": "monitor / recommend CAPTCHA",
            "high": "administrator alert", "critical": "temporary block + administrator alert"}[severity(score)]


def clock(connection, moment=None):
    from ..detection import detection_now
    moment = moment or detection_now()
    latest = connection.execute("SELECT last_tick FROM risk_clock WHERE id = 1").fetchone()[0]
    if latest:
        moment = max(moment, datetime.fromisoformat(latest))
    connection.execute("UPDATE risk_clock SET last_tick = ? WHERE id = 1", (stamp(moment),))
    config = current_app.extensions["risk"]
    connection.execute("INSERT OR IGNORE INTO risk_policies VALUES (?, ?)", (config["version"], config["configuration"]))
    return moment


def _entity(connection, kind, key, moment):
    connection.execute(
        "INSERT OR IGNORE INTO risk_entities (entity_type, entity_key, created_at, decay_anchor) VALUES (?, ?, ?, ?)",
        (kind, str(key), stamp(moment), stamp(moment)),
    )
    return connection.execute("SELECT * FROM risk_entities WHERE entity_type = ? AND entity_key = ?", (kind, str(key))).fetchone()


def _latest_incident(connection, entity_id):
    row = connection.execute(
        "SELECT incident_id FROM incident_entities WHERE entity_id = ? ORDER BY incident_id DESC LIMIT 1", (entity_id,)
    ).fetchone()
    return row[0] if row else None


def _change(connection, entity_id, delta, kind, reason, moment, dedup_key,
            event_id=None, finding_id=None, interval_count=0, actor_id=None):
    if connection.execute("SELECT 1 FROM risk_changes WHERE dedup_key = ?", (dedup_key,)).fetchone():
        return
    before = connection.execute("SELECT score FROM risk_entities WHERE id = ?", (entity_id,)).fetchone()[0]
    after = max(0, min(100, before + delta))
    connection.execute("UPDATE risk_entities SET score = ? WHERE id = ?", (after, entity_id))
    connection.execute(
        "UPDATE incidents SET peak_score = MAX(peak_score, ?) WHERE status = 'open' "
        "AND id IN (SELECT incident_id FROM incident_entities WHERE entity_id = ?)", (after, entity_id)
    )
    cursor = connection.execute(
        "INSERT INTO risk_changes (entity_id, event_id, finding_id, policy_version, created_at, kind, requested_delta, "
        "applied_delta, before_score, after_score, reason, interval_count, actor_id, dedup_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (entity_id, event_id, finding_id, current_app.extensions["risk"]["version"], stamp(moment), kind,
         delta, after - before, before, after, reason, interval_count, actor_id, dedup_key),
    )
    connection.execute(
        "INSERT OR IGNORE INTO incident_changes SELECT ie.incident_id, ? FROM incident_entities ie "
        "JOIN incidents i ON i.id = ie.incident_id WHERE ie.entity_id = ? AND i.status = 'open'", (cursor.lastrowid, entity_id)
    )


def _audit(connection, action_id, moment, transition, reason, actor_id=None):
    connection.execute("INSERT INTO action_audit (action_id, created_at, transition, reason, actor_id) VALUES (?, ?, ?, ?, ?)",
                       (action_id, stamp(moment), transition, reason, actor_id))


def _decide(connection, entity_id, moment):
    entity = connection.execute("SELECT * FROM risk_entities WHERE id = ?", (entity_id,)).fetchone()
    level = severity(entity["score"])
    ranks = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    incident_id = _latest_incident(connection, entity_id)
    if level in {"high", "critical"} and ranks[level] > ranks[entity["decision_level"]]:
        connection.execute(
            "INSERT INTO alerts (entity_id, incident_id, severity, score, reason, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (entity_id, incident_id, level, entity["score"], f"Risk increased to {level}: {entity['score']}/100.", stamp(moment)),
        )
    connection.execute("UPDATE risk_entities SET decision_level = ? WHERE id = ?", (level, entity_id))
    active = connection.execute("SELECT * FROM actions WHERE entity_id = ? AND status = 'active'", (entity_id,)).fetchone()
    expired = active is not None and active["expires_at"] <= stamp(moment)
    if expired:
        connection.execute("UPDATE actions SET status = 'expired' WHERE id = ?", (active["id"],))
        _audit(connection, active["id"], moment, "expired", "Block duration elapsed; current risk reevaluated.")
        active = None
    if level == "critical" and active is None:
        reason = "Risk remains critical at block expiry." if expired else "Critical risk threshold reached."
        cursor = connection.execute(
            "INSERT INTO actions (entity_id, incident_id, policy_version, created_at, expires_at, status, reason) "
            "VALUES (?, ?, ?, ?, ?, 'active', ?)",
            (entity_id, incident_id, current_app.extensions["risk"]["version"], stamp(moment),
             stamp(moment + timedelta(seconds=policy()["block_seconds"])), reason),
        )
        _audit(connection, cursor.lastrowid, moment, "renewed" if expired else "created", reason)
    elif expired:
        # The expired action is retained; its audit records explain release.
        previous = connection.execute("SELECT id FROM actions WHERE entity_id = ? ORDER BY id DESC LIMIT 1", (entity_id,)).fetchone()
        _audit(connection, previous[0], moment, "released", "Risk is below the critical threshold.")


def maintain(connection, moment):
    """Catch up once under the same write lock used by requests and other workers."""
    rules = policy()
    for entity in connection.execute("SELECT * FROM risk_entities").fetchall():
        anchor = datetime.fromisoformat(entity["decay_anchor"])
        count = int((moment - anchor).total_seconds() // rules["decay_interval_seconds"])
        if count > 0:
            end = anchor + timedelta(seconds=count * rules["decay_interval_seconds"])
            if entity["score"] > 0:
                _change(connection, entity["id"], -count * rules["decay_points"], "decay",
                        f"{count} complete quiet interval(s) of {rules['decay_interval_seconds']} seconds.",
                        moment, f"decay:{entity['id']}:{stamp(end)}", interval_count=count)
            connection.execute("UPDATE risk_entities SET decay_anchor = ? WHERE id = ?", (stamp(end), entity["id"]))
        _decide(connection, entity["id"], moment)
    # Incident closure depends on suspicious findings, independently of block expiry.
    cutoff = stamp(moment - timedelta(seconds=rules["incident_quiet_seconds"]))
    for incident in connection.execute("SELECT * FROM incidents WHERE status = 'open' AND last_activity <= ?", (cutoff,)).fetchall():
        closed = datetime.fromisoformat(incident["last_activity"]) + timedelta(seconds=rules["incident_quiet_seconds"])
        connection.execute("UPDATE incidents SET status = 'closed', closed_at = ? WHERE id = ?", (stamp(closed), incident["id"]))


def _incident(connection, event, findings, entity_ids, moment):
    row = connection.execute("SELECT id FROM incidents WHERE source_ip = ? AND status = 'open'", (event["source_ip"],)).fetchone()
    incident_id = row[0] if row else None
    if findings:
        if incident_id is None:
            cursor = connection.execute("INSERT INTO incidents (source_ip, opened_at, last_activity) VALUES (?, ?, ?)",
                                        (event["source_ip"], stamp(moment), stamp(moment)))
            incident_id = cursor.lastrowid
            cutoff = stamp(moment - timedelta(seconds=policy()["incident_context_seconds"]))
            connection.execute(
                "INSERT OR IGNORE INTO incident_events SELECT ?, e.id FROM events e JOIN detection_evaluations d "
                "ON d.event_id = e.id WHERE e.source_ip = ? AND d.evaluated_at > ? AND d.evaluated_at <= ?",
                (incident_id, event["source_ip"], cutoff, stamp(moment)),
            )
        connection.execute("UPDATE incidents SET last_activity = ? WHERE id = ?", (stamp(moment), incident_id))
        for finding in findings:
            connection.execute("INSERT OR IGNORE INTO incident_findings VALUES (?, ?)", (incident_id, finding["id"]))
            connection.execute("INSERT OR IGNORE INTO incident_events SELECT ?, event_id FROM finding_events WHERE finding_id = ?",
                               (incident_id, finding["id"]))
    if incident_id is not None:
        connection.execute("INSERT OR IGNORE INTO incident_events VALUES (?, ?)", (incident_id, event["id"]))
        connection.executemany("INSERT OR IGNORE INTO incident_entities VALUES (?, ?)", [(incident_id, entity_id) for entity_id in entity_ids])
    return incident_id


def apply_event(connection, event_id, moment, suspicious=False):
    if connection.execute("SELECT 1 FROM risk_evaluations WHERE event_id = ?", (event_id,)).fetchone():
        return
    moment = clock(connection, moment)
    maintain(connection, moment)
    connection.execute("INSERT INTO risk_evaluations VALUES (?, ?)", (event_id, stamp(moment)))
    event = connection.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    findings = connection.execute("SELECT * FROM findings WHERE event_id = ? ORDER BY id", (event_id,)).fetchall()
    entities = [_entity(connection, "ip", event["source_ip"], moment)]
    if event["user_id"] is not None:
        entities.append(_entity(connection, "user", event["user_id"], moment))
    ids = [entity["id"] for entity in entities]
    incident_id = _incident(connection, event, findings, ids, moment)
    # Both IP and verified user receive each signal once. Their scores are never summed.
    for entity in entities:
        if suspicious or findings:
            connection.execute("UPDATE risk_entities SET last_suspicious = ?, decay_anchor = ? WHERE id = ?",
                               (stamp(moment), stamp(moment), entity["id"]))
        for finding in findings:
            _change(connection, entity["id"], finding["weight"], "finding", finding["reason"], moment,
                    f"finding:{entity['id']}:{finding['id']}", event_id, finding["id"])
        metadata = json.loads(event["metadata"])
        successful = (event["event_type"] == "login_success" and 200 <= event["status"] < 400) or (
            event["event_type"] == "application_request" and 200 <= event["status"] < 300
        )
        normal = not suspicious and not findings and successful and metadata.get("rate_eligible") is True
        quiet = entity["last_suspicious"] is None or entity["last_suspicious"] <= stamp(moment - timedelta(seconds=policy()["normal_quiet_seconds"]))
        cooldown = entity["last_normal"] is None or entity["last_normal"] <= stamp(moment - timedelta(seconds=policy()["normal_cooldown_seconds"]))
        if normal and quiet and cooldown and entity["score"] > 0:
            _change(connection, entity["id"], -policy()["normal_points"], "normal", "Successful activity after a quiet period.",
                    moment, f"normal:{entity['id']}:{event_id}", event_id)
            connection.execute("UPDATE risk_entities SET last_normal = ? WHERE id = ?", (stamp(moment), entity["id"]))
        _decide(connection, entity["id"], moment)
    if incident_id is not None:
        connection.execute(
            "UPDATE incidents SET peak_score = MAX(peak_score, (SELECT MAX(r.score) FROM risk_entities r "
            "JOIN incident_entities ie ON ie.entity_id = r.id WHERE ie.incident_id = ?)) WHERE id = ?", (incident_id, incident_id)
        )


def tick():
    connection = get_db()
    with connection:
        connection.execute("BEGIN IMMEDIATE")
        moment = clock(connection)
        maintain(connection, moment)
    return stamp(moment)


def recover(entity_id, actor_id, reason):
    connection = get_db()
    with connection:
        connection.execute("BEGIN IMMEDIATE")
        actor = connection.execute("SELECT role FROM users WHERE id = ?", (actor_id,)).fetchone()
        if not actor or actor[0] != "admin":
            raise ValueError("Administrator authentication required.")
        entity = connection.execute("SELECT * FROM risk_entities WHERE id = ?", (entity_id,)).fetchone()
        if entity is None:
            raise ValueError("Risk entity does not exist.")
        moment = clock(connection)
        _change(connection, entity_id, -entity["score"], "administrator_reset", reason, moment,
                f"recovery:{uuid4()}", actor_id=actor_id)
        for action in connection.execute("SELECT id FROM actions WHERE entity_id = ? AND status = 'active'", (entity_id,)).fetchall():
            connection.execute("UPDATE actions SET status = 'revoked' WHERE id = ?", (action[0],))
            _audit(connection, action[0], moment, "revoked", reason, actor_id)
        connection.execute("UPDATE risk_entities SET decision_level = 'low', decay_anchor = ? WHERE id = ?", (stamp(moment), entity_id))


def init_app(app):
    load_policy(app)
    from .cli import maintenance_command, worker_command, recover_command
    from .http import enforce, bp
    app.before_request(enforce)
    app.register_blueprint(bp)
    for command in (maintenance_command, worker_command, recover_command):
        app.cli.add_command(command)
