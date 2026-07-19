CREATE TABLE tests (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
    bank_ids_json TEXT NOT NULL,
    pass_threshold_percent INTEGER NOT NULL CHECK (pass_threshold_percent BETWEEN 1 AND 100),
    max_attempts INTEGER NOT NULL CHECK (max_attempts BETWEEN 1 AND 100),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE test_publications (
    id INTEGER PRIMARY KEY,
    test_id TEXT NOT NULL REFERENCES tests(id) ON DELETE RESTRICT,
    revision TEXT NOT NULL CHECK (length(revision) = 64),
    quiz_json TEXT NOT NULL,
    published_at INTEGER NOT NULL,
    UNIQUE(test_id, revision)
);

CREATE TABLE active_test_publication (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    publication_id INTEGER NOT NULL UNIQUE REFERENCES test_publications(id) ON DELETE RESTRICT
);

CREATE TABLE exam_passes (
    person_id INTEGER NOT NULL REFERENCES persons(id) ON DELETE CASCADE,
    test_id TEXT NOT NULL,
    revision TEXT NOT NULL CHECK (length(revision) = 64),
    passed_at INTEGER NOT NULL,
    PRIMARY KEY(person_id, test_id, revision)
);

ALTER TABLE exam_attempts ADD COLUMN test_id TEXT;
ALTER TABLE exam_attempts ADD COLUMN revision TEXT;

CREATE INDEX attempts_by_test_revision
    ON exam_attempts(person_id, test_id, revision, completed_at);

CREATE TABLE login_bindings_v4 (
    id INTEGER PRIMARY KEY,
    person_id INTEGER NOT NULL REFERENCES persons(id) ON DELETE CASCADE,
    ssh_key_id INTEGER REFERENCES ssh_keys(id) ON DELETE CASCADE,
    unix_username TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL
);

INSERT INTO login_bindings_v4(id, person_id, ssh_key_id, unix_username, enabled, created_at)
SELECT id, person_id, ssh_key_id, unix_username, enabled, created_at
FROM login_bindings;

DROP TABLE login_bindings;
ALTER TABLE login_bindings_v4 RENAME TO login_bindings;

CREATE INDEX login_binding_lookup
    ON login_bindings(unix_username, person_id, ssh_key_id)
    WHERE enabled = 1;

CREATE UNIQUE INDEX login_binding_unique_scope
    ON login_bindings(person_id, COALESCE(ssh_key_id, -1), unix_username);
