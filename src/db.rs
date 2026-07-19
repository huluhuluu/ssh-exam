use std::{path::Path, path::PathBuf, str::FromStr, time::Duration};

use nix::unistd::User;
use rusqlite::{params, Connection, ErrorCode, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    keys::{validate_fingerprint, PublicKey},
    quiz::validate_bank_id,
};

#[cfg(test)]
use crate::quiz::LEGACY_BANK_ID;

const MIGRATION_1: &str = include_str!("../migrations/0001_init.sql");
const MIGRATION_2: &str = include_str!("../migrations/0002_mapping_bank.sql");

#[derive(Debug, Error)]
pub enum GateError {
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("record not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("maximum exam attempts reached")]
    AttemptsExhausted,
    #[error("exam is already passed")]
    AlreadyPassed,
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}

pub type GateResult<T> = Result<T, GateError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessMode {
    Shell,
    Proxyjump,
}

impl AccessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shell => "shell",
            Self::Proxyjump => "proxyjump",
        }
    }
}

impl FromStr for AccessMode {
    type Err = GateError;

    fn from_str(value: &str) -> GateResult<Self> {
        match value {
            "shell" => Ok(Self::Shell),
            "proxyjump" => Ok(Self::Proxyjump),
            _ => Err(GateError::Invalid("invalid access mode".to_owned())),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PersonRecord {
    pub id: i64,
    pub display_name: String,
    pub enabled: bool,
    pub passed_at: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct KeyRecord {
    pub id: i64,
    pub person_id: i64,
    pub fingerprint: String,
    pub key_type: String,
    pub key_base64: String,
    pub comment: Option<String>,
    pub enabled: bool,
}

#[derive(Clone, Debug)]
pub struct BindingRecord {
    pub id: i64,
    pub person_id: i64,
    pub ssh_key_id: Option<i64>,
    pub unix_username: String,
    pub access_mode: AccessMode,
    pub permitopen: Vec<String>,
    pub bank_id: String,
    pub enabled: bool,
}

#[derive(Clone, Debug)]
pub struct PersonView {
    pub person: PersonRecord,
    pub keys: Vec<KeyRecord>,
    pub bindings: Vec<BindingRecord>,
    pub attempt_count: u32,
}

#[derive(Clone, Debug)]
pub struct PolicyRecord {
    pub person_id: i64,
    pub unix_username: String,
    pub fingerprint: String,
    pub key_type: String,
    pub key_base64: String,
    pub passed: bool,
    pub access_mode: AccessMode,
    pub permitopen: Vec<String>,
    pub bank_id: String,
}

#[derive(Clone, Debug)]
pub struct PendingIdentity {
    pub person_id: i64,
    pub display_name: String,
    pub passed: bool,
    pub attempt_count: u32,
    pub access_mode: AccessMode,
    pub bank_id: String,
}

#[derive(Clone, Debug)]
pub struct BindingInput {
    pub person_id: i64,
    pub ssh_key_id: Option<i64>,
    pub unix_username: String,
    pub access_mode: AccessMode,
    pub permitopen: Vec<String>,
    pub bank_id: String,
}

#[derive(Clone, Debug)]
pub struct AttemptInput<'a> {
    pub person_id: i64,
    pub score: u32,
    pub total: u32,
    pub passed: bool,
    pub answers_json: &'a str,
    pub max_attempts: u32,
}

#[derive(Clone, Debug)]
pub struct Db {
    path: PathBuf,
    busy_timeout: Duration,
}

impl Db {
    pub fn new(path: impl Into<PathBuf>, busy_timeout: Duration) -> Self {
        Self {
            path: path.into(),
            busy_timeout,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn initialize(&self) -> GateResult<()> {
        let mut connection = self.open_writable()?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY);",
        )?;
        for (version, migration) in [(1, MIGRATION_1), (2, MIGRATION_2)] {
            let applied = transaction
                .query_row(
                    "SELECT 1 FROM schema_migrations WHERE version = ?1",
                    [version],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if !applied {
                transaction.execute_batch(migration)?;
                transaction.execute(
                    "INSERT INTO schema_migrations(version) VALUES (?1)",
                    [version],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn create_person(&self, display_name: &str) -> GateResult<i64> {
        let display_name = validate_display_name(display_name)?;
        let connection = self.open_writable()?;
        connection.execute(
            "INSERT INTO persons(display_name, created_at) VALUES (?1, unixepoch())",
            [display_name],
        )?;
        Ok(connection.last_insert_rowid())
    }

    pub fn set_person_enabled(&self, person_id: i64, enabled: bool) -> GateResult<()> {
        let connection = self.open_writable()?;
        expect_changed(connection.execute(
            "UPDATE persons SET enabled = ?1 WHERE id = ?2",
            params![enabled, person_id],
        )?)
    }

    pub fn add_key(&self, person_id: i64, public_key_line: &str) -> GateResult<KeyRecord> {
        let key = PublicKey::parse(public_key_line)
            .map_err(|error| GateError::Invalid(error.to_string()))?;
        let mut connection = self.open_writable()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let person_exists = transaction
            .query_row("SELECT 1 FROM persons WHERE id = ?1", [person_id], |_| {
                Ok(())
            })
            .optional()?
            .is_some();
        if !person_exists {
            return Err(GateError::NotFound);
        }
        let result = transaction.execute(
            "INSERT INTO ssh_keys(person_id, fingerprint, key_type, key_base64, comment, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, unixepoch())",
            params![
                person_id,
                key.fingerprint,
                key.key_type,
                key.key_base64,
                key.comment
            ],
        );
        if let Err(error) = result {
            if is_constraint(&error) {
                return Err(GateError::Conflict(
                    "that public-key fingerprint is already registered".to_owned(),
                ));
            }
            return Err(error.into());
        }
        let id = transaction.last_insert_rowid();
        transaction.commit()?;
        Ok(KeyRecord {
            id,
            person_id,
            fingerprint: key.fingerprint,
            key_type: key.key_type,
            key_base64: key.key_base64,
            comment: key.comment,
            enabled: true,
        })
    }

    pub fn set_key_enabled(&self, key_id: i64, enabled: bool) -> GateResult<()> {
        let connection = self.open_writable()?;
        expect_changed(connection.execute(
            "UPDATE ssh_keys SET enabled = ?1 WHERE id = ?2",
            params![enabled, key_id],
        )?)
    }

    pub fn remove_key(&self, key_id: i64) -> GateResult<()> {
        let connection = self.open_writable()?;
        expect_changed(connection.execute("DELETE FROM ssh_keys WHERE id = ?1", [key_id])?)
    }

    pub fn add_binding(&self, input: &BindingInput) -> GateResult<i64> {
        validate_unix_username(&input.unix_username)?;
        validate_bank_id(&input.bank_id).map_err(|error| GateError::Invalid(error.to_string()))?;
        let permitopen = validate_permitopen(&input.permitopen)?;
        if input.access_mode == AccessMode::Shell && !permitopen.is_empty() {
            return Err(GateError::Invalid(
                "shell bindings cannot define permitopen values".to_owned(),
            ));
        }
        if input.access_mode == AccessMode::Proxyjump && permitopen.is_empty() {
            return Err(GateError::Invalid(
                "proxyjump bindings require at least one permitopen value".to_owned(),
            ));
        }

        let mut connection = self.open_writable()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let person_exists = transaction
            .query_row(
                "SELECT 1 FROM persons WHERE id = ?1",
                [input.person_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !person_exists {
            return Err(GateError::NotFound);
        }
        if let Some(key_id) = input.ssh_key_id {
            let owner = transaction
                .query_row(
                    "SELECT person_id FROM ssh_keys WHERE id = ?1",
                    [key_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            if owner != Some(input.person_id) {
                return Err(GateError::Invalid(
                    "selected key does not belong to the person".to_owned(),
                ));
            }
        }

        let username_owner = transaction
            .query_row(
                "SELECT person_id FROM login_bindings
                 WHERE enabled = 1 AND unix_username = ?1 AND access_mode = 'shell'
                 LIMIT 1",
                [&input.unix_username],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if username_owner.is_some_and(|owner| owner != input.person_id) {
            return Err(GateError::Conflict(
                "Unix username is reserved by another person's shell binding".to_owned(),
            ));
        }
        if input.access_mode == AccessMode::Shell {
            let other_owner = transaction
                .query_row(
                    "SELECT person_id FROM login_bindings
                     WHERE enabled = 1 AND unix_username = ?1 AND person_id != ?2 LIMIT 1",
                    params![input.unix_username, input.person_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            if other_owner.is_some() {
                return Err(GateError::Conflict(
                    "shell usernames must be dedicated to one person".to_owned(),
                ));
            }
            let other_username = transaction
                .query_row(
                    "SELECT unix_username FROM login_bindings
                     WHERE enabled = 1 AND person_id = ?1 AND access_mode = 'shell'
                       AND unix_username != ?2 LIMIT 1",
                    params![input.person_id, input.unix_username],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if other_username.is_some() {
                return Err(GateError::Conflict(
                    "a person may have only one enabled shell username".to_owned(),
                ));
            }
        }

        let overlapping = transaction
            .query_row(
                "SELECT 1 FROM login_bindings
                 WHERE enabled = 1 AND person_id = ?1 AND unix_username = ?2
                   AND access_mode = ?3
                   AND (ssh_key_id IS NULL OR ?4 IS NULL OR ssh_key_id = ?4)
                 LIMIT 1",
                params![
                    input.person_id,
                    input.unix_username,
                    input.access_mode.as_str(),
                    input.ssh_key_id
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if overlapping {
            return Err(GateError::Conflict(
                "an overlapping enabled binding already exists".to_owned(),
            ));
        }

        transaction.execute(
            "INSERT INTO login_bindings(
                person_id, ssh_key_id, unix_username, access_mode, permitopen_json, bank_id,
                created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, unixepoch())",
            params![
                input.person_id,
                input.ssh_key_id,
                input.unix_username,
                input.access_mode.as_str(),
                serde_json::to_string(&permitopen).expect("serializing strings cannot fail"),
                input.bank_id
            ],
        )?;
        let id = transaction.last_insert_rowid();
        transaction.commit()?;
        Ok(id)
    }

    pub fn set_binding_enabled(&self, binding_id: i64, enabled: bool) -> GateResult<()> {
        let mut connection = self.open_writable()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !enabled {
            expect_changed(transaction.execute(
                "UPDATE login_bindings SET enabled = 0 WHERE id = ?1",
                [binding_id],
            )?)?;
            transaction.commit()?;
            return Ok(());
        }
        let binding = transaction
            .query_row(
                "SELECT person_id, ssh_key_id, unix_username, access_mode, permitopen_json, bank_id
                 FROM login_bindings WHERE id = ?1",
                [binding_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?
            .ok_or(GateError::NotFound)?;
        let mode: AccessMode = binding.3.parse()?;
        let permitopen: Vec<String> = serde_json::from_str(&binding.4).map_err(|error| {
            GateError::Invalid(format!("stored permitopen JSON is invalid: {error}"))
        })?;
        validate_unix_username(&binding.2)?;
        validate_permitopen(&permitopen)?;
        validate_bank_id(&binding.5).map_err(|error| GateError::Invalid(error.to_string()))?;
        if let Some(key_id) = binding.1 {
            let owner = transaction
                .query_row(
                    "SELECT person_id FROM ssh_keys WHERE id = ?1 AND enabled = 1",
                    [key_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            if owner != Some(binding.0) {
                return Err(GateError::Invalid(
                    "selected key is disabled or belongs to another person".to_owned(),
                ));
            }
        }
        let shell_owner = transaction
            .query_row(
                "SELECT person_id FROM login_bindings
                 WHERE id != ?1 AND enabled = 1 AND unix_username = ?2
                   AND access_mode = 'shell' LIMIT 1",
                params![binding_id, binding.2],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if shell_owner.is_some_and(|owner| owner != binding.0) {
            return Err(GateError::Conflict(
                "Unix username is reserved by another person's shell binding".to_owned(),
            ));
        }
        if mode == AccessMode::Shell {
            let conflict = transaction
                .query_row(
                    "SELECT 1 FROM login_bindings
                     WHERE id != ?1 AND enabled = 1
                       AND ((unix_username = ?2 AND person_id != ?3)
                         OR (person_id = ?3 AND access_mode = 'shell' AND unix_username != ?2))
                     LIMIT 1",
                    params![binding_id, binding.2, binding.0],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if conflict {
                return Err(GateError::Conflict(
                    "shell usernames must be a one-to-one person mapping".to_owned(),
                ));
            }
        }
        let overlap = transaction
            .query_row(
                "SELECT 1 FROM login_bindings
                 WHERE id != ?1 AND enabled = 1 AND person_id = ?2
                   AND unix_username = ?3 AND access_mode = ?4
                   AND (ssh_key_id IS NULL OR ?5 IS NULL OR ssh_key_id = ?5)
                 LIMIT 1",
                params![binding_id, binding.0, binding.2, mode.as_str(), binding.1],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if overlap {
            return Err(GateError::Conflict(
                "an overlapping enabled binding already exists".to_owned(),
            ));
        }
        transaction.execute(
            "UPDATE login_bindings SET enabled = 1 WHERE id = ?1",
            [binding_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn reset_exam(&self, person_id: i64) -> GateResult<()> {
        let mut connection = self.open_writable()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        expect_changed(transaction.execute(
            "UPDATE persons SET passed_at = NULL WHERE id = ?1",
            [person_id],
        )?)?;
        transaction.execute(
            "DELETE FROM exam_attempts WHERE person_id = ?1",
            [person_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn resolve_policy(
        &self,
        unix_username: &str,
        fingerprint: &str,
    ) -> GateResult<Option<PolicyRecord>> {
        validate_username_syntax(unix_username)?;
        validate_fingerprint(fingerprint).map_err(|error| GateError::Invalid(error.to_string()))?;
        let connection = self.open_read_only()?;
        let raw = connection
            .query_row(
                "SELECT p.id, b.unix_username, k.fingerprint, k.key_type, k.key_base64,
                        p.passed_at IS NOT NULL, b.access_mode, b.permitopen_json, b.bank_id
                 FROM login_bindings b
                 JOIN persons p ON p.id = b.person_id
                 JOIN ssh_keys k ON k.person_id = p.id
                 WHERE b.enabled = 1 AND p.enabled = 1 AND k.enabled = 1
                   AND b.unix_username = ?1 AND k.fingerprint = ?2
                   AND (b.ssh_key_id IS NULL OR b.ssh_key_id = k.id)
                 ORDER BY b.ssh_key_id IS NOT NULL DESC, b.id ASC
                 LIMIT 1",
                params![unix_username, fingerprint],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, bool>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                    ))
                },
            )
            .optional()?;
        raw.map(
            |(
                person_id,
                username,
                fingerprint,
                key_type,
                key_base64,
                passed,
                mode,
                permits,
                bank_id,
            )| {
                validate_bank_id(&bank_id)
                    .map_err(|error| GateError::Invalid(error.to_string()))?;
                Ok(PolicyRecord {
                    person_id,
                    unix_username: username,
                    fingerprint,
                    key_type,
                    key_base64,
                    passed,
                    access_mode: mode.parse()?,
                    permitopen: serde_json::from_str(&permits).map_err(|error| {
                        GateError::Invalid(format!("stored permitopen JSON is invalid: {error}"))
                    })?,
                    bank_id,
                })
            },
        )
        .transpose()
    }

    pub fn load_identity(
        &self,
        unix_username: &str,
        fingerprint: &str,
    ) -> GateResult<Option<PendingIdentity>> {
        let policy = self.resolve_policy(unix_username, fingerprint)?;
        let Some(policy) = policy else {
            return Ok(None);
        };
        let connection = self.open_read_only()?;
        let identity = connection.query_row(
            "SELECT p.display_name,
                    (SELECT count(*) FROM exam_attempts a WHERE a.person_id = p.id)
             FROM persons p WHERE p.id = ?1",
            [policy.person_id],
            |row| {
                Ok(PendingIdentity {
                    person_id: policy.person_id,
                    display_name: row.get(0)?,
                    passed: policy.passed,
                    attempt_count: row.get(1)?,
                    access_mode: policy.access_mode,
                    bank_id: policy.bank_id.clone(),
                })
            },
        )?;
        Ok(Some(identity))
    }

    pub fn record_attempt(&self, input: &AttemptInput<'_>) -> GateResult<u32> {
        if input.total == 0 || input.score > input.total || input.max_attempts == 0 {
            return Err(GateError::Invalid("invalid exam score".to_owned()));
        }
        let mut connection = self.open_writable()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = transaction
            .query_row(
                "SELECT enabled, passed_at IS NOT NULL FROM persons WHERE id = ?1",
                [input.person_id],
                |row| Ok((row.get::<_, bool>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?
            .ok_or(GateError::NotFound)?;
        if !state.0 {
            return Err(GateError::NotFound);
        }
        if state.1 {
            return Err(GateError::AlreadyPassed);
        }
        let count: u32 = transaction.query_row(
            "SELECT count(*) FROM exam_attempts WHERE person_id = ?1",
            [input.person_id],
            |row| row.get(0),
        )?;
        if count >= input.max_attempts {
            return Err(GateError::AttemptsExhausted);
        }
        transaction.execute(
            "INSERT INTO exam_attempts(
                person_id, completed_at, score, total, passed, answers_json
             ) VALUES (?1, unixepoch(), ?2, ?3, ?4, ?5)",
            params![
                input.person_id,
                input.score,
                input.total,
                input.passed,
                input.answers_json
            ],
        )?;
        if input.passed {
            transaction.execute(
                "UPDATE persons SET passed_at = unixepoch() WHERE id = ?1",
                [input.person_id],
            )?;
        }
        transaction.commit()?;
        Ok(count + 1)
    }

    pub fn list_people(&self) -> GateResult<Vec<PersonView>> {
        let connection = self.open_read_only()?;
        let mut statement = connection.prepare(
            "SELECT id, display_name, enabled, passed_at FROM persons ORDER BY display_name, id",
        )?;
        let persons = statement
            .query_map([], |row| {
                Ok(PersonRecord {
                    id: row.get(0)?,
                    display_name: row.get(1)?,
                    enabled: row.get(2)?,
                    passed_at: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut views = Vec::with_capacity(persons.len());
        for person in persons {
            let keys = load_keys(&connection, person.id)?;
            let bindings = load_bindings(&connection, person.id)?;
            let attempt_count = connection.query_row(
                "SELECT count(*) FROM exam_attempts WHERE person_id = ?1",
                [person.id],
                |row| row.get(0),
            )?;
            views.push(PersonView {
                person,
                keys,
                bindings,
                attempt_count,
            });
        }
        Ok(views)
    }

    fn open_writable(&self) -> GateResult<Connection> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        self.open(flags)
    }

    fn open_read_only(&self) -> GateResult<Connection> {
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        self.open(flags)
    }

    fn open(&self, flags: OpenFlags) -> GateResult<Connection> {
        let connection = Connection::open_with_flags(&self.path, flags)?;
        connection.busy_timeout(self.busy_timeout)?;
        connection.pragma_update(None, "foreign_keys", true)?;
        Ok(connection)
    }
}

fn load_keys(connection: &Connection, person_id: i64) -> GateResult<Vec<KeyRecord>> {
    let mut statement = connection.prepare(
        "SELECT id, person_id, fingerprint, key_type, key_base64, comment, enabled
         FROM ssh_keys WHERE person_id = ?1 ORDER BY id",
    )?;
    let keys = statement
        .query_map([person_id], |row| {
            Ok(KeyRecord {
                id: row.get(0)?,
                person_id: row.get(1)?,
                fingerprint: row.get(2)?,
                key_type: row.get(3)?,
                key_base64: row.get(4)?,
                comment: row.get(5)?,
                enabled: row.get(6)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(keys)
}

fn load_bindings(connection: &Connection, person_id: i64) -> GateResult<Vec<BindingRecord>> {
    let mut statement = connection.prepare(
        "SELECT id, person_id, ssh_key_id, unix_username, access_mode,
                permitopen_json, bank_id, enabled
         FROM login_bindings WHERE person_id = ?1 ORDER BY id",
    )?;
    let rows = statement.query_map([person_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Option<i64>>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, bool>(7)?,
        ))
    })?;
    rows.map(|row| {
        let (id, person_id, ssh_key_id, unix_username, mode, permits, bank_id, enabled) = row?;
        validate_bank_id(&bank_id).map_err(|error| GateError::Invalid(error.to_string()))?;
        Ok(BindingRecord {
            id,
            person_id,
            ssh_key_id,
            unix_username,
            access_mode: mode.parse()?,
            permitopen: serde_json::from_str(&permits).map_err(|error| {
                GateError::Invalid(format!("stored permitopen JSON is invalid: {error}"))
            })?,
            bank_id,
            enabled,
        })
    })
    .collect()
}

fn validate_display_name(value: &str) -> GateResult<&str> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 200 || value.chars().any(char::is_control) {
        return Err(GateError::Invalid(
            "display name must contain 1-200 printable characters".to_owned(),
        ));
    }
    Ok(value)
}

pub fn validate_username_syntax(value: &str) -> GateResult<()> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(GateError::Invalid("invalid Unix username".to_owned()));
    };
    if value.len() > 32
        || !(first.is_ascii_lowercase() || first == b'_')
        || !bytes
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
    {
        return Err(GateError::Invalid("invalid Unix username".to_owned()));
    }
    Ok(())
}

pub fn validate_unix_username(value: &str) -> GateResult<()> {
    validate_username_syntax(value)?;
    match User::from_name(value) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(GateError::Invalid(
            "Unix username does not exist on this host".to_owned(),
        )),
        Err(error) => Err(GateError::Invalid(format!(
            "could not resolve Unix username: {error}"
        ))),
    }
}

pub fn validate_permitopen(values: &[String]) -> GateResult<Vec<String>> {
    if values.len() > 64 {
        return Err(GateError::Invalid(
            "at most 64 permitopen values are allowed".to_owned(),
        ));
    }
    let mut clean = Vec::with_capacity(values.len());
    for value in values {
        if value.is_empty()
            || value.len() > 255
            || value
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'"' | b'\\' | b','))
        {
            return Err(GateError::Invalid(format!(
                "invalid permitopen value: {value}"
            )));
        }
        let (host, port) = value
            .rsplit_once(':')
            .ok_or_else(|| GateError::Invalid(format!("invalid permitopen value: {value}")))?;
        let host_valid = if host.starts_with('[') && host.ends_with(']') {
            let address = &host[1..host.len() - 1];
            !address.is_empty()
                && address
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() || byte == b':')
        } else {
            !host.is_empty()
                && host
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
        };
        let port_valid = port.parse::<u16>().is_ok_and(|port| port != 0);
        if !host_valid || !port_valid {
            return Err(GateError::Invalid(format!(
                "invalid permitopen value: {value}"
            )));
        }
        if !clean.contains(value) {
            clean.push(value.clone());
        }
    }
    Ok(clean)
}

fn expect_changed(changed: usize) -> GateResult<()> {
    if changed == 0 {
        Err(GateError::NotFound)
    } else {
        Ok(())
    }
}

fn is_constraint(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(code, _)
            if code.code == ErrorCode::ConstraintViolation
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const KEY_1: &str = "ssh-ed25519 aGVsbG8= device-one";
    const KEY_2: &str = "ssh-ed25519 d29ybGQ= device-two";

    fn database(timeout: Duration) -> (TempDir, Db) {
        let directory = TempDir::new().unwrap();
        let db = Db::new(directory.path().join("gate.db"), timeout);
        db.initialize().unwrap();
        (directory, db)
    }

    fn shell_binding(person_id: i64) -> BindingInput {
        BindingInput {
            person_id,
            ssh_key_id: None,
            unix_username: "root".to_owned(),
            access_mode: AccessMode::Shell,
            permitopen: vec![],
            bank_id: LEGACY_BANK_ID.to_owned(),
        }
    }

    #[test]
    fn pass_is_inherited_by_every_enabled_key_and_reset_clears_attempts() {
        let (_directory, db) = database(Duration::from_secs(1));
        let person = db.create_person("Alice").unwrap();
        let key_1 = db.add_key(person, KEY_1).unwrap();
        let key_2 = db.add_key(person, KEY_2).unwrap();
        db.add_binding(&shell_binding(person)).unwrap();

        for key in [&key_1, &key_2] {
            assert!(
                !db.resolve_policy("root", &key.fingerprint)
                    .unwrap()
                    .unwrap()
                    .passed
            );
        }
        db.record_attempt(&AttemptInput {
            person_id: person,
            score: 4,
            total: 4,
            passed: true,
            answers_json: "[0,1,0,1]",
            max_attempts: 3,
        })
        .unwrap();
        for key in [&key_1, &key_2] {
            assert!(
                db.resolve_policy("root", &key.fingerprint)
                    .unwrap()
                    .unwrap()
                    .passed
            );
        }

        db.reset_exam(person).unwrap();
        let view = db.list_people().unwrap().pop().unwrap();
        assert!(view.person.passed_at.is_none());
        assert_eq!(view.attempt_count, 0);
    }

    #[test]
    fn disabled_person_or_key_fails_closed() {
        let (_directory, db) = database(Duration::from_secs(1));
        let person = db.create_person("Alice").unwrap();
        let key = db.add_key(person, KEY_1).unwrap();
        db.add_binding(&shell_binding(person)).unwrap();
        assert!(db
            .resolve_policy("root", &key.fingerprint)
            .unwrap()
            .is_some());
        db.set_key_enabled(key.id, false).unwrap();
        assert!(db
            .resolve_policy("root", &key.fingerprint)
            .unwrap()
            .is_none());
        db.set_key_enabled(key.id, true).unwrap();
        db.set_person_enabled(person, false).unwrap();
        assert!(db
            .resolve_policy("root", &key.fingerprint)
            .unwrap()
            .is_none());
    }

    #[test]
    fn duplicate_fingerprint_and_wrong_key_owner_are_rejected() {
        let (_directory, db) = database(Duration::from_secs(1));
        let first = db.create_person("First").unwrap();
        let second = db.create_person("Second").unwrap();
        let key = db.add_key(first, KEY_1).unwrap();
        assert!(matches!(
            db.add_key(second, KEY_1),
            Err(GateError::Conflict(_))
        ));
        let mut binding = shell_binding(second);
        binding.ssh_key_id = Some(key.id);
        assert!(matches!(
            db.add_binding(&binding),
            Err(GateError::Invalid(_))
        ));
    }

    #[test]
    fn attempt_limit_is_transactional() {
        let (_directory, db) = database(Duration::from_secs(1));
        let person = db.create_person("Alice").unwrap();
        for _ in 0..3 {
            db.record_attempt(&AttemptInput {
                person_id: person,
                score: 0,
                total: 1,
                passed: false,
                answers_json: "[0]",
                max_attempts: 3,
            })
            .unwrap();
        }
        assert!(matches!(
            db.record_attempt(&AttemptInput {
                person_id: person,
                score: 1,
                total: 1,
                passed: true,
                answers_json: "[1]",
                max_attempts: 3,
            }),
            Err(GateError::AttemptsExhausted)
        ));
    }

    #[test]
    fn wal_busy_timeout_is_bounded_and_recovers() {
        let (_directory, db) = database(Duration::from_millis(30));
        let inspection = db.open_read_only().unwrap();
        let journal_mode: String = inspection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode, "wal");
        drop(inspection);
        let mut blocker = db.open_writable().unwrap();
        let transaction = blocker
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute(
                "INSERT INTO persons(display_name, created_at) VALUES ('Blocker', unixepoch())",
                [],
            )
            .unwrap();
        let error = db.create_person("Contender").unwrap_err();
        assert!(matches!(
            error,
            GateError::Database(rusqlite::Error::SqliteFailure(code, _))
                if matches!(code.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
        ));
        transaction.rollback().unwrap();
        db.create_person("Recovered").unwrap();
    }

    #[test]
    fn validates_unix_users_and_permitopen() {
        validate_unix_username("root").unwrap();
        assert!(validate_unix_username("definitely_missing_ssh_exam_user").is_err());
        assert_eq!(
            validate_permitopen(&["target.example.org:5432".to_owned()]).unwrap(),
            vec!["target.example.org:5432"]
        );
        assert!(validate_permitopen(&["*:22".to_owned()]).is_err());
        assert!(validate_permitopen(&["host:0".to_owned()]).is_err());
    }

    #[test]
    fn reenable_binding_revalidates_shell_username_ownership() {
        let (_directory, db) = database(Duration::from_secs(1));
        let first = db.create_person("First").unwrap();
        let second = db.create_person("Second").unwrap();
        let shell_id = db.add_binding(&shell_binding(first)).unwrap();
        db.set_binding_enabled(shell_id, false).unwrap();
        db.add_binding(&BindingInput {
            person_id: second,
            ssh_key_id: None,
            unix_username: "root".to_owned(),
            access_mode: AccessMode::Proxyjump,
            permitopen: vec!["target.example.org:22".to_owned()],
            bank_id: LEGACY_BANK_ID.to_owned(),
        })
        .unwrap();
        assert!(matches!(
            db.set_binding_enabled(shell_id, true),
            Err(GateError::Conflict(_))
        ));
    }

    #[test]
    fn migration_adds_legacy_bank_to_existing_mappings() {
        let directory = TempDir::new().unwrap();
        let db = Db::new(directory.path().join("gate.db"), Duration::from_secs(1));
        let connection = db.open_writable().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY);\n\
                 INSERT INTO schema_migrations(version) VALUES (1);",
            )
            .unwrap();
        connection.execute_batch(MIGRATION_1).unwrap();
        connection
            .execute_batch(
                "INSERT INTO persons(id, display_name, created_at) VALUES (1, 'Migrated', 1);\n\
                 INSERT INTO login_bindings(\n\
                     person_id, unix_username, access_mode, permitopen_json, created_at\n\
                 ) VALUES (1, 'root', 'shell', '[]', 1);",
            )
            .unwrap();
        drop(connection);

        db.initialize().unwrap();
        let view = db.list_people().unwrap().pop().unwrap();
        assert_eq!(view.bindings[0].bank_id, LEGACY_BANK_ID);
        let connection = db.open_read_only().unwrap();
        let versions: u32 = connection
            .query_row("SELECT count(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(versions, 2);
    }
}
