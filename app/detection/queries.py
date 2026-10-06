"""Read-only administrator queries; weights are findings, not risk scores."""

import json

from ..db import get_db


def finding_counts():
    connection = get_db()
    row = connection.execute(
        "SELECT COUNT(*) AS total, COUNT(DISTINCT event_id) AS trigger_events FROM findings"
    ).fetchone()
    evidence = connection.execute("SELECT COUNT(DISTINCT event_id) FROM finding_events").fetchone()[0]
    by_rule = {row[0]: row[1] for row in connection.execute("SELECT rule_id, COUNT(*) FROM findings GROUP BY rule_id")}
    return {**dict(row), "evidence_events": evidence, "by_rule": by_rule}


def recent_findings(page=1, per_page=25):
    return [dict(row) for row in get_db().execute(
        "SELECT f.*, u.username FROM findings f LEFT JOIN users u ON u.id = f.user_id "
        "ORDER BY f.id DESC LIMIT ? OFFSET ?", (per_page, (page - 1) * per_page)
    )]


def finding_detail(finding_id):
    connection = get_db()
    row = connection.execute(
        "SELECT f.*, u.username, c.configuration FROM findings f "
        "LEFT JOIN users u ON u.id = f.user_id "
        "JOIN detection_configs c ON c.version = f.config_version WHERE f.id = ?", (finding_id,)
    ).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["configuration"] = json.loads(result["configuration"])
    result["evidence"] = [
        {**dict(item), "metadata": json.loads(item["metadata"])}
        for item in connection.execute(
            "SELECT e.* FROM finding_events fe JOIN events e ON e.id = fe.event_id "
            "WHERE fe.finding_id = ? ORDER BY e.id", (finding_id,)
        )
    ]
    return result

