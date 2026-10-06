CREATE TABLE risk_policies (
    version TEXT PRIMARY KEY,
    configuration TEXT NOT NULL
);
CREATE TABLE risk_clock (id INTEGER PRIMARY KEY CHECK(id = 1), last_tick TEXT);
INSERT INTO risk_clock VALUES (1, NULL);
CREATE TABLE risk_entities (
    id INTEGER PRIMARY KEY,
    entity_type TEXT NOT NULL CHECK(entity_type IN ('ip', 'user')),
    entity_key TEXT NOT NULL,
    score INTEGER NOT NULL DEFAULT 0 CHECK(score BETWEEN 0 AND 100),
    decision_level TEXT NOT NULL DEFAULT 'low',
    created_at TEXT NOT NULL,
    last_suspicious TEXT,
    decay_anchor TEXT NOT NULL,
    last_normal TEXT,
    UNIQUE(entity_type, entity_key)
);
CREATE TABLE risk_evaluations (
    event_id INTEGER PRIMARY KEY REFERENCES events(id),
    processed_at TEXT NOT NULL
);
CREATE TABLE incidents (
    id INTEGER PRIMARY KEY,
    source_ip TEXT NOT NULL,
    opened_at TEXT NOT NULL,
    last_activity TEXT NOT NULL,
    closed_at TEXT,
    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'closed')),
    peak_score INTEGER NOT NULL DEFAULT 0 CHECK(peak_score BETWEEN 0 AND 100)
);
CREATE UNIQUE INDEX one_open_incident_per_ip ON incidents(source_ip) WHERE status = 'open';
CREATE TABLE incident_entities (
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    entity_id INTEGER NOT NULL REFERENCES risk_entities(id),
    PRIMARY KEY(incident_id, entity_id)
);
CREATE TABLE incident_events (
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    event_id INTEGER NOT NULL REFERENCES events(id),
    PRIMARY KEY(incident_id, event_id)
);
CREATE TABLE incident_findings (
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    finding_id INTEGER NOT NULL REFERENCES findings(id),
    PRIMARY KEY(incident_id, finding_id)
);
CREATE TABLE risk_changes (
    id INTEGER PRIMARY KEY,
    entity_id INTEGER NOT NULL REFERENCES risk_entities(id),
    event_id INTEGER REFERENCES events(id),
    finding_id INTEGER REFERENCES findings(id),
    policy_version TEXT NOT NULL REFERENCES risk_policies(version),
    created_at TEXT NOT NULL,
    kind TEXT NOT NULL,
    requested_delta INTEGER NOT NULL,
    applied_delta INTEGER NOT NULL,
    before_score INTEGER NOT NULL,
    after_score INTEGER NOT NULL CHECK(after_score BETWEEN 0 AND 100),
    reason TEXT NOT NULL,
    interval_count INTEGER NOT NULL DEFAULT 0,
    actor_id INTEGER REFERENCES users(id),
    dedup_key TEXT NOT NULL UNIQUE,
    UNIQUE(entity_id, finding_id)
);
CREATE INDEX risk_changes_entity_idx ON risk_changes(entity_id, id);
CREATE TABLE incident_changes (
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    change_id INTEGER NOT NULL REFERENCES risk_changes(id),
    PRIMARY KEY(incident_id, change_id)
);
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
    entity_id INTEGER NOT NULL REFERENCES risk_entities(id),
    incident_id INTEGER REFERENCES incidents(id),
    severity TEXT NOT NULL,
    score INTEGER NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    acknowledged_at TEXT,
    acknowledged_by INTEGER REFERENCES users(id)
);
CREATE TABLE actions (
    id INTEGER PRIMARY KEY,
    entity_id INTEGER NOT NULL REFERENCES risk_entities(id),
    incident_id INTEGER REFERENCES incidents(id),
    policy_version TEXT NOT NULL REFERENCES risk_policies(version),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'expired', 'revoked')),
    reason TEXT NOT NULL
);
CREATE UNIQUE INDEX one_active_block_per_entity ON actions(entity_id) WHERE status = 'active';
CREATE TABLE action_audit (
    id INTEGER PRIMARY KEY,
    action_id INTEGER NOT NULL REFERENCES actions(id),
    created_at TEXT NOT NULL,
    transition TEXT NOT NULL,
    reason TEXT NOT NULL,
    actor_id INTEGER REFERENCES users(id)
);
