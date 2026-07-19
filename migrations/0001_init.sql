CREATE TABLE persons (
    id INTEGER PRIMARY KEY,
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    passed_at INTEGER,
    created_at INTEGER NOT NULL
);

CREATE TABLE ssh_keys (
    id INTEGER PRIMARY KEY,
    person_id INTEGER NOT NULL REFERENCES persons(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL UNIQUE,
    key_type TEXT NOT NULL,
    key_base64 TEXT NOT NULL,
    comment TEXT,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL
);

CREATE TABLE login_bindings (
    id INTEGER PRIMARY KEY,
    person_id INTEGER NOT NULL REFERENCES persons(id) ON DELETE CASCADE,
    ssh_key_id INTEGER REFERENCES ssh_keys(id) ON DELETE CASCADE,
    unix_username TEXT NOT NULL,
    access_mode TEXT NOT NULL CHECK (access_mode IN ('shell', 'proxyjump')),
    permitopen_json TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL,
    UNIQUE(person_id, ssh_key_id, unix_username, access_mode)
);

CREATE INDEX login_binding_lookup
    ON login_bindings(unix_username, person_id, ssh_key_id)
    WHERE enabled = 1;

CREATE INDEX enabled_shell_username
    ON login_bindings(unix_username, person_id)
    WHERE enabled = 1 AND access_mode = 'shell';

CREATE TABLE exam_attempts (
    id INTEGER PRIMARY KEY,
    person_id INTEGER NOT NULL REFERENCES persons(id) ON DELETE CASCADE,
    completed_at INTEGER NOT NULL,
    score INTEGER NOT NULL CHECK (score >= 0),
    total INTEGER NOT NULL CHECK (total > 0),
    passed INTEGER NOT NULL CHECK (passed IN (0, 1)),
    answers_json TEXT NOT NULL
);

CREATE INDEX attempts_by_person ON exam_attempts(person_id, completed_at);
