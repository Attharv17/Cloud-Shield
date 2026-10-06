CREATE TABLE detection_configs (
    version TEXT PRIMARY KEY,
    configuration TEXT NOT NULL,
    first_used_at TEXT NOT NULL
);

CREATE TABLE detection_evaluations (
    event_id INTEGER PRIMARY KEY REFERENCES events(id),
    evaluated_at TEXT NOT NULL,
    config_version TEXT NOT NULL REFERENCES detection_configs(version)
);
CREATE INDEX evaluation_time_idx ON detection_evaluations(evaluated_at);

CREATE TABLE findings (
    id INTEGER PRIMARY KEY,
    event_id INTEGER NOT NULL REFERENCES events(id),
    rule_id TEXT NOT NULL,
    config_version TEXT NOT NULL REFERENCES detection_configs(version),
    entity_type TEXT NOT NULL CHECK (entity_type IN ('ip', 'user')),
    entity_key TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    weight INTEGER NOT NULL CHECK (weight BETWEEN 0 AND 100),
    reason TEXT NOT NULL,
    observed_count INTEGER NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(event_id, rule_id)
);
CREATE INDEX finding_cooldown_idx ON findings(rule_id, entity_type, entity_key, created_at);
CREATE INDEX finding_created_idx ON findings(created_at);

CREATE TABLE finding_events (
    finding_id INTEGER NOT NULL REFERENCES findings(id),
    event_id INTEGER NOT NULL REFERENCES events(id),
    PRIMARY KEY (finding_id, event_id)
);

CREATE TABLE source_contexts (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('ip', 'device')),
    fingerprint TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    first_event_id INTEGER NOT NULL REFERENCES events(id),
    PRIMARY KEY (user_id, kind, fingerprint)
);

