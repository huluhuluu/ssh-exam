CREATE TABLE login_bindings_v3 (
    id INTEGER PRIMARY KEY,
    person_id INTEGER NOT NULL REFERENCES persons(id) ON DELETE CASCADE,
    ssh_key_id INTEGER REFERENCES ssh_keys(id) ON DELETE CASCADE,
    unix_username TEXT NOT NULL,
    bank_id TEXT NOT NULL DEFAULT 'legacy',
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL
);

-- Legacy mode pairs can describe the same logical key/account mapping. Keep
-- one deterministically, preferring an enabled row and then the former shell
-- row, while preserving distinct people, key scopes, and Unix accounts.
INSERT INTO login_bindings_v3(
    id, person_id, ssh_key_id, unix_username, bank_id, enabled, created_at
)
SELECT
    b.id, b.person_id, b.ssh_key_id, b.unix_username, b.bank_id, b.enabled, b.created_at
FROM login_bindings b
WHERE b.id = (
    SELECT candidate.id
    FROM login_bindings candidate
    WHERE candidate.person_id = b.person_id
      AND candidate.ssh_key_id IS b.ssh_key_id
      AND candidate.unix_username = b.unix_username
    ORDER BY
        candidate.enabled DESC,
        CASE candidate.access_mode WHEN 'shell' THEN 0 ELSE 1 END,
        candidate.id ASC
    LIMIT 1
);

DROP TABLE login_bindings;
ALTER TABLE login_bindings_v3 RENAME TO login_bindings;

CREATE INDEX login_binding_lookup
    ON login_bindings(unix_username, person_id, ssh_key_id)
    WHERE enabled = 1;

CREATE UNIQUE INDEX login_binding_unique_scope
    ON login_bindings(person_id, COALESCE(ssh_key_id, -1), unix_username);
