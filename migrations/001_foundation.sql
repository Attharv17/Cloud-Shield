CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('user', 'admin')),
    created_at TEXT NOT NULL
);

CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    route TEXT NOT NULL,
    method TEXT NOT NULL,
    status INTEGER NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX events_timestamp_idx ON events(timestamp);
CREATE INDEX events_source_time_idx ON events(source_ip, timestamp);
CREATE INDEX events_user_time_idx ON events(user_id, timestamp);
CREATE INDEX events_type_time_idx ON events(event_type, timestamp);
