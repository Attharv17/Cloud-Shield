import json

from ..db import get_db
from . import recommendation, severity


def decorate(entity):
    result = dict(entity)
    result.update(severity=severity(result["score"]), recommendation=recommendation(result["score"]))
    return result


def entities(page=1, per_page=25):
    return [decorate(row) for row in get_db().execute(
        "SELECT * FROM risk_entities ORDER BY score DESC, id LIMIT ? OFFSET ?", (per_page, (page-1)*per_page)
    )]


def entity_detail(entity_id):
    connection = get_db()
    entity = connection.execute("SELECT * FROM risk_entities WHERE id = ?", (entity_id,)).fetchone()
    if entity is None:
        return None
    result = decorate(entity)
    result["changes"] = [dict(row) for row in connection.execute("SELECT * FROM risk_changes WHERE entity_id = ? ORDER BY id", (entity_id,))]
    result["actions"] = [dict(row) for row in connection.execute("SELECT * FROM actions WHERE entity_id = ? ORDER BY id DESC", (entity_id,))]
    result["action_audit"] = [dict(row) for row in connection.execute(
        "SELECT a.* FROM action_audit a JOIN actions b ON b.id = a.action_id WHERE b.entity_id = ? ORDER BY a.id", (entity_id,)
    )]
    versions = {item["policy_version"] for item in result["changes"] + result["actions"]}
    result["policies"] = {version: json.loads(connection.execute(
        "SELECT configuration FROM risk_policies WHERE version = ?", (version,)
    ).fetchone()[0]) for version in versions}
    return result


def incidents(page=1, per_page=25):
    return [dict(row) for row in get_db().execute(
        "SELECT i.*, COALESCE((SELECT MAX(r.score) FROM incident_entities ie JOIN risk_entities r "
        "ON r.id = ie.entity_id WHERE ie.incident_id = i.id), 0) AS current_score "
        "FROM incidents i ORDER BY i.id DESC LIMIT ? OFFSET ?", (per_page, (page-1)*per_page)
    )]


def incident_detail(incident_id):
    connection = get_db()
    row = connection.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["entities"] = [decorate(row) for row in connection.execute(
        "SELECT r.* FROM incident_entities ie JOIN risk_entities r ON r.id = ie.entity_id WHERE ie.incident_id = ?", (incident_id,)
    )]
    result["current_score"] = max((entity["score"] for entity in result["entities"]), default=0)
    result["findings"] = [dict(row) for row in connection.execute(
        "SELECT f.* FROM incident_findings i JOIN findings f ON f.id = i.finding_id WHERE i.incident_id = ? ORDER BY f.id", (incident_id,)
    )]
    events = [{"time": row["timestamp"], "kind": "event", "description": f"{row['event_type']}: {row['method']} {row['route']} ({row['status']})",
               "event_id": row["id"]} for row in connection.execute(
        "SELECT e.* FROM incident_events i JOIN events e ON e.id = i.event_id WHERE i.incident_id = ? ORDER BY e.id", (incident_id,)
    )]
    changes = [{"time": row["created_at"], "kind": "score", "description": f"Entity {row['entity_id']}: {row['before_score']} → {row['after_score']}. {row['reason']}",
                "change_id": row["id"]} for row in connection.execute(
        "SELECT c.* FROM incident_changes i JOIN risk_changes c ON c.id = i.change_id WHERE i.incident_id = ? ORDER BY c.id", (incident_id,)
    )]
    actions = [{"time": row["created_at"], "kind": "action", "description": f"Block {row['transition']}: {row['reason']}", "action_id": row["action_id"]}
               for row in connection.execute("SELECT a.* FROM action_audit a JOIN actions b ON b.id = a.action_id WHERE b.incident_id = ? ORDER BY a.id", (incident_id,))]
    alert_items = [{"time": row["created_at"], "kind": "alert", "description": row["reason"], "alert_id": row["id"]}
                   for row in connection.execute("SELECT * FROM alerts WHERE incident_id = ? ORDER BY id", (incident_id,))]
    result["timeline"] = sorted(events + changes + actions + alert_items, key=lambda item: item["time"])
    return result


def alerts(page=1, per_page=25):
    return [dict(row) for row in get_db().execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ? OFFSET ?", (per_page, (page-1)*per_page))]


def summary():
    connection = get_db()
    return {
        "entities": connection.execute("SELECT COUNT(*) FROM risk_entities").fetchone()[0],
        "open_incidents": connection.execute("SELECT COUNT(*) FROM incidents WHERE status = 'open'").fetchone()[0],
        "active_blocks": connection.execute("SELECT COUNT(*) FROM actions WHERE status = 'active'").fetchone()[0],
        "unacknowledged_alerts": connection.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged_at IS NULL").fetchone()[0],
    }
