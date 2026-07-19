use std::{collections::HashSet, path::PathBuf, time::Duration};

#[cfg(unix)]
use nix::unistd::User;
use rusqlite::{params, Connection, ErrorCode, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    keys::{validate_fingerprint, PublicKey},
    quiz::{validate_bank_id, Quiz, LEGACY_BANK_ID},
};

const MIGRATION_1: &str = include_str!("../migrations/0001_init.sql");
const MIGRATION_2: &str = include_str!("../migrations/0002_mapping_bank.sql");
const MIGRATION_3: &str = include_str!("../migrations/0003_unified_access.sql");
const MIGRATION_4: &str = include_str!("../migrations/0004_tests_and_publications.sql");
const MIGRATION_5: &str = include_str!("../migrations/0005_direct_accounts_and_test_options.sql");

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

#[derive(Clone, Debug)]
pub struct PersonRecord {
    pub id: i64,
    pub display_name: String,
    pub enabled: bool,
    pub passed_at: Option<i64>,
    pub unix_username: Option<String>,
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
pub struct PersonView {
    pub person: PersonRecord,
    pub keys: Vec<KeyRecord>,
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
    pub test_id: String,
    pub revision: String,
}

#[derive(Clone, Debug)]
pub struct PendingIdentity {
    pub person_id: i64,
    pub display_name: String,
    pub passed: bool,
    pub attempt_count: u32,
    pub test_id: String,
    pub revision: String,
}

#[derive(Clone, Debug)]
pub struct AttemptInput<'a> {
    pub person_id: i64,
    pub test_id: &'a str,
    pub revision: &'a str,
    pub score: u32,
    pub total: u32,
    pub passed: bool,
    pub answers_json: &'a str,
    pub max_attempts: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestDefinitionRecord {
    pub id: String,
    pub title: String,
    pub bank_ids: Vec<String>,
    pub pass_threshold_percent: u32,
    pub max_attempts: u32,
    pub question_limit: Option<u32>,
    pub shuffle_questions: bool,
    pub shuffle_choices: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug)]
pub struct TestDefinitionInput {
    pub id: String,
    pub title: String,
    pub bank_ids: Vec<String>,
    pub pass_threshold_percent: u32,
    pub max_attempts: u32,
    pub question_limit: Option<u32>,
    pub shuffle_questions: bool,
    pub shuffle_choices: bool,
}

#[derive(Clone, Debug)]
pub struct PublishedTest {
    pub publication_id: i64,
    pub test_id: String,
    pub revision: String,
    pub quiz: Quiz,
    pub published_at: i64,
}

#[derive(Clone, Debug)]
pub struct PublicationRecord {
    pub publication_id: i64,
    pub test_id: String,
    pub revision: String,
    pub quiz: Quiz,
    pub published_at: String,
    pub active: bool,
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

    pub fn initialize(&self) -> GateResult<()> {
        let mut connection = self.open_writable()?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY);",
        )?;
        for (version, migration) in [
            (1, MIGRATION_1),
            (2, MIGRATION_2),
            (3, MIGRATION_3),
            (4, MIGRATION_4),
            (5, MIGRATION_5),
        ] {
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

    pub fn create_person(
        &self,
        display_name: &str,
        unix_username: Option<&str>,
    ) -> GateResult<i64> {
        let display_name = validate_display_name(display_name)?;
        if let Some(username) = unix_username {
            validate_unix_username(username)?;
        }
        let connection = self.open_writable()?;
        let result = connection.execute(
            "INSERT INTO persons(display_name, unix_username, created_at)
             VALUES (?1, ?2, unixepoch())",
            params![display_name, unix_username],
        );
        if let Err(error) = result {
            if is_constraint(&error) {
                return Err(GateError::Conflict(
                    "that Unix login is already assigned to another person".to_owned(),
                ));
            }
            return Err(error.into());
        }
        Ok(connection.last_insert_rowid())
    }

    pub fn set_person_unix_username(
        &self,
        person_id: i64,
        unix_username: Option<&str>,
    ) -> GateResult<()> {
        if let Some(username) = unix_username {
            validate_unix_username(username)?;
        }
        let connection = self.open_writable()?;
        let result = connection.execute(
            "UPDATE persons SET unix_username = ?1 WHERE id = ?2",
            params![unix_username, person_id],
        );
        match result {
            Ok(changed) => expect_changed(changed),
            Err(error) if is_constraint(&error) => Err(GateError::Conflict(
                "that Unix login is already assigned to another person".to_owned(),
            )),
            Err(error) => Err(error.into()),
        }
    }

    pub fn update_person(
        &self,
        person_id: i64,
        display_name: &str,
        unix_username: Option<&str>,
    ) -> GateResult<()> {
        let display_name = validate_display_name(display_name)?;
        if let Some(username) = unix_username {
            validate_unix_username(username)?;
        }
        let connection = self.open_writable()?;
        let result = connection.execute(
            "UPDATE persons SET display_name = ?1, unix_username = ?2 WHERE id = ?3",
            params![display_name, unix_username, person_id],
        );
        match result {
            Ok(changed) => expect_changed(changed),
            Err(error) if is_constraint(&error) => Err(GateError::Conflict(
                "that Unix login is already assigned to another person".to_owned(),
            )),
            Err(error) => Err(error.into()),
        }
    }

    pub fn set_person_enabled(&self, person_id: i64, enabled: bool) -> GateResult<()> {
        let connection = self.open_writable()?;
        expect_changed(connection.execute(
            "UPDATE persons SET enabled = ?1 WHERE id = ?2",
            params![enabled, person_id],
        )?)
    }

    pub fn delete_person(&self, person_id: i64) -> GateResult<()> {
        let mut connection = self.open_writable()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        expect_changed(transaction.execute("DELETE FROM persons WHERE id = ?1", [person_id])?)?;
        transaction.commit()?;
        Ok(())
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

    pub fn reset_exam(&self, person_id: i64) -> GateResult<()> {
        let mut connection = self.open_writable()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists = transaction
            .query_row("SELECT 1 FROM persons WHERE id = ?1", [person_id], |_| {
                Ok(())
            })
            .optional()?
            .is_some();
        if !exists {
            return Err(GateError::NotFound);
        }
        transaction.execute(
            "UPDATE persons SET passed_at = NULL WHERE id = ?1",
            [person_id],
        )?;
        if let Some((test_id, revision)) = active_test_identity(&transaction)? {
            transaction.execute(
                "DELETE FROM exam_passes
                 WHERE person_id = ?1 AND test_id = ?2 AND revision = ?3",
                params![person_id, test_id, revision],
            )?;
            transaction.execute(
                "DELETE FROM exam_attempts
                 WHERE person_id = ?1 AND test_id = ?2 AND revision = ?3",
                params![person_id, test_id, revision],
            )?;
        }
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
                "SELECT p.id, p.unix_username, k.fingerprint, k.key_type, k.key_base64,
                        EXISTS(
                            SELECT 1 FROM exam_passes pass
                            WHERE pass.person_id = p.id
                              AND pass.test_id = publication.test_id
                              AND pass.revision = publication.revision
                        ), publication.test_id, publication.revision
                 FROM persons p
                 JOIN ssh_keys k ON k.person_id = p.id
                 JOIN active_test_publication active ON active.singleton = 1
                 JOIN test_publications publication ON publication.id = active.publication_id
                 WHERE p.enabled = 1 AND k.enabled = 1
                   AND p.unix_username = ?1 AND k.fingerprint = ?2
                 ORDER BY k.id ASC
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
                test_id,
                revision,
            )| {
                validate_test_id(&test_id)?;
                validate_revision(&revision)?;
                Ok(PolicyRecord {
                    person_id,
                    unix_username: username,
                    fingerprint,
                    key_type,
                    key_base64,
                    passed,
                    test_id,
                    revision,
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
                    (SELECT count(*) FROM exam_attempts a
                     WHERE a.person_id = p.id AND a.test_id = ?2 AND a.revision = ?3)
             FROM persons p WHERE p.id = ?1",
            params![policy.person_id, policy.test_id, policy.revision],
            |row| {
                Ok(PendingIdentity {
                    person_id: policy.person_id,
                    display_name: row.get(0)?,
                    passed: policy.passed,
                    attempt_count: row.get(1)?,
                    test_id: policy.test_id.clone(),
                    revision: policy.revision.clone(),
                })
            },
        )?;
        Ok(Some(identity))
    }

    pub fn record_attempt(&self, input: &AttemptInput<'_>) -> GateResult<u32> {
        if input.total == 0 || input.score > input.total || input.max_attempts == 0 {
            return Err(GateError::Invalid("invalid exam score".to_owned()));
        }
        validate_test_id(input.test_id)?;
        validate_revision(input.revision)?;
        let mut connection = self.open_writable()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = transaction
            .query_row(
                "SELECT p.enabled, EXISTS(
                    SELECT 1 FROM exam_passes pass
                    WHERE pass.person_id = p.id AND pass.test_id = ?2 AND pass.revision = ?3
                 ) FROM persons p WHERE p.id = ?1",
                params![input.person_id, input.test_id, input.revision],
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
            "SELECT count(*) FROM exam_attempts
             WHERE person_id = ?1 AND test_id = ?2 AND revision = ?3",
            params![input.person_id, input.test_id, input.revision],
            |row| row.get(0),
        )?;
        if count >= input.max_attempts {
            return Err(GateError::AttemptsExhausted);
        }
        transaction.execute(
            "INSERT INTO exam_attempts(
                person_id, completed_at, score, total, passed, answers_json, test_id, revision
             ) VALUES (?1, unixepoch(), ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                input.person_id,
                input.score,
                input.total,
                input.passed,
                input.answers_json,
                input.test_id,
                input.revision,
            ],
        )?;
        if input.passed {
            transaction.execute(
                "INSERT INTO exam_passes(person_id, test_id, revision, passed_at)
                 VALUES (?1, ?2, ?3, unixepoch())",
                params![input.person_id, input.test_id, input.revision],
            )?;
        }
        transaction.commit()?;
        Ok(count + 1)
    }

    pub fn list_people(&self) -> GateResult<Vec<PersonView>> {
        let connection = self.open_read_only()?;
        let mut statement = connection.prepare(
            "SELECT p.id, p.display_name, p.enabled,
                    (SELECT pass.passed_at
                     FROM active_test_publication active
                     JOIN test_publications publication ON publication.id = active.publication_id
                     JOIN exam_passes pass
                       ON pass.person_id = p.id
                      AND pass.test_id = publication.test_id
                      AND pass.revision = publication.revision
                     WHERE active.singleton = 1), p.unix_username
             FROM persons p ORDER BY p.display_name, p.id",
        )?;
        let persons = statement
            .query_map([], |row| {
                Ok(PersonRecord {
                    id: row.get(0)?,
                    display_name: row.get(1)?,
                    enabled: row.get(2)?,
                    passed_at: row.get(3)?,
                    unix_username: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut views = Vec::with_capacity(persons.len());
        for person in persons {
            let keys = load_keys(&connection, person.id)?;
            let attempt_count = connection.query_row(
                "SELECT count(*) FROM exam_attempts attempt
                 JOIN active_test_publication active ON active.singleton = 1
                 JOIN test_publications publication ON publication.id = active.publication_id
                 WHERE attempt.person_id = ?1
                   AND attempt.test_id = publication.test_id
                   AND attempt.revision = publication.revision",
                [person.id],
                |row| row.get(0),
            )?;
            views.push(PersonView {
                person,
                keys,
                attempt_count,
            });
        }
        Ok(views)
    }

    pub fn get_person(&self, person_id: i64) -> GateResult<PersonView> {
        self.list_people()?
            .into_iter()
            .find(|view| view.person.id == person_id)
            .ok_or(GateError::NotFound)
    }

    pub fn create_test(&self, input: &TestDefinitionInput) -> GateResult<()> {
        validate_test_input(input)?;
        let bank_ids_json = serde_json::to_string(&input.bank_ids)
            .map_err(|error| GateError::Invalid(error.to_string()))?;
        let connection = self.open_writable()?;
        let result = connection.execute(
            "INSERT INTO tests(
                id, title, bank_ids_json, pass_threshold_percent, max_attempts,
                question_limit, shuffle_questions, shuffle_choices, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, unixepoch(), unixepoch())",
            params![
                input.id,
                input.title.trim(),
                bank_ids_json,
                input.pass_threshold_percent,
                input.max_attempts,
                input.question_limit,
                input.shuffle_questions,
                input.shuffle_choices,
            ],
        );
        match result {
            Ok(_) => Ok(()),
            Err(error) if is_constraint(&error) => Err(GateError::Conflict(
                "that test id already exists".to_owned(),
            )),
            Err(error) => Err(error.into()),
        }
    }

    pub fn update_test(&self, test_id: &str, input: &TestDefinitionInput) -> GateResult<()> {
        validate_test_id(test_id)?;
        validate_test_input(input)?;
        if test_id != input.id {
            return Err(GateError::Invalid("test id cannot be changed".to_owned()));
        }
        let bank_ids_json = serde_json::to_string(&input.bank_ids)
            .map_err(|error| GateError::Invalid(error.to_string()))?;
        let connection = self.open_writable()?;
        expect_changed(connection.execute(
            "UPDATE tests SET title = ?1, bank_ids_json = ?2,
                    pass_threshold_percent = ?3, max_attempts = ?4,
                    question_limit = ?5, shuffle_questions = ?6, shuffle_choices = ?7,
                    updated_at = unixepoch()
             WHERE id = ?8",
            params![
                input.title.trim(),
                bank_ids_json,
                input.pass_threshold_percent,
                input.max_attempts,
                input.question_limit,
                input.shuffle_questions,
                input.shuffle_choices,
                test_id
            ],
        )?)
    }

    pub fn list_tests(&self) -> GateResult<Vec<TestDefinitionRecord>> {
        let connection = self.open_read_only()?;
        let mut statement = connection.prepare(
            "SELECT id, title, bank_ids_json, pass_threshold_percent, max_attempts,
                    question_limit, shuffle_questions, shuffle_choices, created_at, updated_at
             FROM tests ORDER BY title, id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, u32>(4)?,
                    row.get::<_, Option<u32>>(5)?,
                    row.get::<_, bool>(6)?,
                    row.get::<_, bool>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().map(parse_test_row).collect()
    }

    pub fn get_test(&self, test_id: &str) -> GateResult<TestDefinitionRecord> {
        validate_test_id(test_id)?;
        self.list_tests()?
            .into_iter()
            .find(|test| test.id == test_id)
            .ok_or(GateError::NotFound)
    }

    pub fn tests_using_bank(&self, bank_id: &str) -> GateResult<Vec<String>> {
        validate_bank_id(bank_id).map_err(|error| GateError::Invalid(error.to_string()))?;
        Ok(self
            .list_tests()?
            .into_iter()
            .filter(|test| test.bank_ids.iter().any(|candidate| candidate == bank_id))
            .map(|test| test.id)
            .collect())
    }

    pub fn delete_test(&self, test_id: &str) -> GateResult<()> {
        validate_test_id(test_id)?;
        let mut connection = self.open_writable()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active = transaction.query_row(
            "SELECT EXISTS(
                    SELECT 1
                    FROM active_test_publication active
                    JOIN test_publications publication ON publication.id = active.publication_id
                    WHERE active.singleton = 1 AND publication.test_id = ?1
                 )",
            [test_id],
            |row| row.get::<_, bool>(0),
        )?;
        if active {
            return Err(GateError::Conflict(
                "the active test cannot be deleted; activate another test first".to_owned(),
            ));
        }
        let publication_count: u32 = transaction.query_row(
            "SELECT count(*) FROM test_publications WHERE test_id = ?1",
            [test_id],
            |row| row.get(0),
        )?;
        if publication_count > 0 {
            return Err(GateError::Conflict(
                "published test history cannot be deleted".to_owned(),
            ));
        }
        transaction.execute("DELETE FROM exam_attempts WHERE test_id = ?1", [test_id])?;
        transaction.execute("DELETE FROM exam_passes WHERE test_id = ?1", [test_id])?;
        expect_changed(transaction.execute("DELETE FROM tests WHERE id = ?1", [test_id])?)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn publish_test(&self, test_id: &str, quiz: &Quiz) -> GateResult<PublishedTest> {
        let test = self.get_test(test_id)?;
        quiz.validate()
            .map_err(|error| GateError::Invalid(error.to_string()))?;
        if quiz.title != test.title
            || quiz.pass_threshold_percent != test.pass_threshold_percent
            || quiz.max_attempts != test.max_attempts
            || quiz.question_limit != test.question_limit
            || quiz.shuffle_questions != test.shuffle_questions
            || quiz.shuffle_choices != test.shuffle_choices
        {
            return Err(GateError::Invalid(
                "published quiz does not match the saved test definition".to_owned(),
            ));
        }
        let quiz_json =
            serde_json::to_string(quiz).map_err(|error| GateError::Invalid(error.to_string()))?;
        let revision_source = serde_json::to_vec(&serde_json::json!({
            "test_id": test.id,
            "bank_ids": test.bank_ids,
            "quiz": quiz,
        }))
        .map_err(|error| GateError::Invalid(error.to_string()))?;
        let revision = format!("{:x}", Sha256::digest(revision_source));

        let mut connection = self.open_writable()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let publication_id = transaction
            .query_row(
                "SELECT id FROM test_publications WHERE test_id = ?1 AND revision = ?2",
                params![test_id, revision],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let publication_id = match publication_id {
            Some(id) => id,
            None => {
                transaction.execute(
                    "INSERT INTO test_publications(test_id, revision, quiz_json, published_at)
                     VALUES (?1, ?2, ?3, unixepoch())",
                    params![test_id, revision, quiz_json],
                )?;
                transaction.last_insert_rowid()
            }
        };
        transaction.execute(
            "INSERT INTO active_test_publication(singleton, publication_id) VALUES (1, ?1)
             ON CONFLICT(singleton) DO UPDATE SET publication_id = excluded.publication_id",
            [publication_id],
        )?;
        transaction.commit()?;
        self.published_test()?.ok_or(GateError::NotFound)
    }

    pub fn published_test(&self) -> GateResult<Option<PublishedTest>> {
        let connection = self.open_read_only()?;
        let raw = connection
            .query_row(
                "SELECT publication.id, publication.test_id, publication.revision,
                        publication.quiz_json, publication.published_at
                 FROM active_test_publication active
                 JOIN test_publications publication ON publication.id = active.publication_id
                 WHERE active.singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?;
        raw.map(
            |(publication_id, test_id, revision, quiz_json, published_at)| {
                validate_test_id(&test_id)?;
                validate_revision(&revision)?;
                let quiz = Quiz::from_slice(quiz_json.as_bytes())
                    .map_err(|error| GateError::Invalid(error.to_string()))?;
                Ok(PublishedTest {
                    publication_id,
                    test_id,
                    revision,
                    quiz,
                    published_at,
                })
            },
        )
        .transpose()
    }

    pub fn list_publications(&self, test_id: &str) -> GateResult<Vec<PublicationRecord>> {
        validate_test_id(test_id)?;
        let connection = self.open_read_only()?;
        let mut statement = connection.prepare(
            "SELECT publication.id, publication.test_id, publication.revision,
                    publication.quiz_json, datetime(publication.published_at, 'unixepoch'),
                    active.publication_id IS NOT NULL
             FROM test_publications publication
             LEFT JOIN active_test_publication active
               ON active.publication_id = publication.id AND active.singleton = 1
             WHERE publication.test_id = ?1
             ORDER BY publication.published_at DESC, publication.id DESC",
        )?;
        let rows = statement
            .query_map([test_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, bool>(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(
                |(publication_id, test_id, revision, quiz_json, published_at, active)| {
                    validate_test_id(&test_id)?;
                    validate_revision(&revision)?;
                    let quiz = Quiz::from_slice(quiz_json.as_bytes())
                        .map_err(|error| GateError::Invalid(error.to_string()))?;
                    Ok(PublicationRecord {
                        publication_id,
                        test_id,
                        revision,
                        quiz,
                        published_at,
                        active,
                    })
                },
            )
            .collect()
    }

    pub fn activate_publication(
        &self,
        test_id: &str,
        publication_id: i64,
    ) -> GateResult<PublishedTest> {
        validate_test_id(test_id)?;
        let mut connection = self.open_writable()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists = transaction
            .query_row(
                "SELECT 1 FROM test_publications WHERE id = ?1 AND test_id = ?2",
                params![publication_id, test_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !exists {
            return Err(GateError::NotFound);
        }
        transaction.execute(
            "INSERT INTO active_test_publication(singleton, publication_id) VALUES (1, ?1)
             ON CONFLICT(singleton) DO UPDATE SET publication_id = excluded.publication_id",
            [publication_id],
        )?;
        transaction.commit()?;
        self.published_test()?.ok_or(GateError::NotFound)
    }

    pub fn ensure_legacy_test(&self, quiz: &Quiz) -> GateResult<PublishedTest> {
        if let Some(published) = self.published_test()? {
            return Ok(published);
        }
        if self.list_tests()?.is_empty() {
            self.create_test(&TestDefinitionInput {
                id: LEGACY_BANK_ID.to_owned(),
                title: quiz.title.clone(),
                bank_ids: vec![LEGACY_BANK_ID.to_owned()],
                pass_threshold_percent: quiz.pass_threshold_percent,
                max_attempts: quiz.max_attempts,
                question_limit: quiz.question_limit,
                shuffle_questions: quiz.shuffle_questions,
                shuffle_choices: quiz.shuffle_choices,
            })?;
        }
        let published = self.publish_test(LEGACY_BANK_ID, quiz)?;
        let connection = self.open_writable()?;
        connection.execute(
            "INSERT INTO exam_passes(person_id, test_id, revision, passed_at)
             SELECT id, ?1, ?2, passed_at FROM persons WHERE passed_at IS NOT NULL
             ON CONFLICT(person_id, test_id, revision) DO NOTHING",
            params![published.test_id, published.revision],
        )?;
        connection.execute(
            "UPDATE persons SET passed_at = NULL WHERE passed_at IS NOT NULL",
            [],
        )?;
        Ok(published)
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
    #[cfg(not(unix))]
    return Ok(());
    #[cfg(unix)]
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

fn active_test_identity(connection: &Connection) -> GateResult<Option<(String, String)>> {
    connection
        .query_row(
            "SELECT publication.test_id, publication.revision
             FROM active_test_publication active
             JOIN test_publications publication ON publication.id = active.publication_id
             WHERE active.singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(Into::into)
}

fn parse_test_row(
    row: (
        String,
        String,
        String,
        u32,
        u32,
        Option<u32>,
        bool,
        bool,
        i64,
        i64,
    ),
) -> GateResult<TestDefinitionRecord> {
    let (
        id,
        title,
        bank_ids_json,
        threshold,
        attempts,
        question_limit,
        shuffle_questions,
        shuffle_choices,
        created_at,
        updated_at,
    ) = row;
    validate_test_id(&id)?;
    let bank_ids: Vec<String> = serde_json::from_str(&bank_ids_json)
        .map_err(|error| GateError::Invalid(format!("invalid stored bank list: {error}")))?;
    let input = TestDefinitionInput {
        id: id.clone(),
        title: title.clone(),
        bank_ids: bank_ids.clone(),
        pass_threshold_percent: threshold,
        max_attempts: attempts,
        question_limit,
        shuffle_questions,
        shuffle_choices,
    };
    validate_test_input(&input)?;
    Ok(TestDefinitionRecord {
        id,
        title,
        bank_ids,
        pass_threshold_percent: threshold,
        max_attempts: attempts,
        question_limit,
        shuffle_questions,
        shuffle_choices,
        created_at,
        updated_at,
    })
}

fn validate_test_input(input: &TestDefinitionInput) -> GateResult<()> {
    validate_test_id(&input.id)?;
    validate_display_name(&input.title)?;
    if input.bank_ids.is_empty() || input.bank_ids.len() > 50 {
        return Err(GateError::Invalid(
            "a test must contain between 1 and 50 question banks".to_owned(),
        ));
    }
    let mut unique = HashSet::new();
    for bank_id in &input.bank_ids {
        validate_bank_id(bank_id).map_err(|error| GateError::Invalid(error.to_string()))?;
        if !unique.insert(bank_id) {
            return Err(GateError::Invalid(
                "a test cannot contain duplicate question banks".to_owned(),
            ));
        }
    }
    if !(1..=100).contains(&input.pass_threshold_percent) {
        return Err(GateError::Invalid(
            "pass threshold must be between 1 and 100".to_owned(),
        ));
    }
    if !(1..=100).contains(&input.max_attempts) {
        return Err(GateError::Invalid(
            "maximum attempts must be between 1 and 100".to_owned(),
        ));
    }
    if input
        .question_limit
        .is_some_and(|limit| !(1..=200).contains(&limit))
    {
        return Err(GateError::Invalid(
            "question limit must be between 1 and 200".to_owned(),
        ));
    }
    Ok(())
}

fn validate_test_id(value: &str) -> GateResult<()> {
    validate_bank_id(value).map_err(|error| GateError::Invalid(error.to_string()))
}

fn validate_revision(value: &str) -> GateResult<()> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(GateError::Invalid("invalid test revision".to_owned()))
    }
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
        db.ensure_legacy_test(&sample_quiz()).unwrap();
        (directory, db)
    }

    fn sample_quiz() -> Quiz {
        Quiz {
            title: "Safety".to_owned(),
            environment: Default::default(),
            pass_threshold_percent: 80,
            max_attempts: 3,
            question_limit: None,
            shuffle_questions: true,
            shuffle_choices: true,
            questions: vec![crate::quiz::Question {
                prompt: "Ready?".to_owned(),
                choices: vec!["Yes".to_owned(), "No".to_owned()],
                correct_index: 0,
            }],
        }
    }

    #[test]
    fn pass_is_inherited_by_every_enabled_key_and_reset_clears_attempts() {
        let (_directory, db) = database(Duration::from_secs(1));
        let person = db.create_person("Alice", Some("root")).unwrap();
        let key_1 = db.add_key(person, KEY_1).unwrap();
        let key_2 = db.add_key(person, KEY_2).unwrap();

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
            test_id: LEGACY_BANK_ID,
            revision: &db.published_test().unwrap().unwrap().revision,
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
        let person = db.create_person("Alice", Some("root")).unwrap();
        let key = db.add_key(person, KEY_1).unwrap();
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
    fn duplicate_fingerprint_and_unix_account_are_rejected() {
        let (_directory, db) = database(Duration::from_secs(1));
        let first = db.create_person("First", Some("root")).unwrap();
        let second = db.create_person("Second", None).unwrap();
        let key = db.add_key(first, KEY_1).unwrap();
        assert!(matches!(
            db.add_key(second, KEY_1),
            Err(GateError::Conflict(_))
        ));
        assert_eq!(key.person_id, first);
        assert!(matches!(
            db.set_person_unix_username(second, Some("root")),
            Err(GateError::Conflict(_))
        ));
    }

    #[test]
    fn deleting_person_cascades_identity_and_exam_records() {
        let (_directory, db) = database(Duration::from_secs(1));
        let person = db.create_person("Disposable", Some("root")).unwrap();
        let key = db.add_key(person, KEY_1).unwrap();
        let published = db.published_test().unwrap().unwrap();
        db.record_attempt(&AttemptInput {
            person_id: person,
            test_id: &published.test_id,
            revision: &published.revision,
            score: 1,
            total: 1,
            passed: true,
            answers_json: "[0]",
            max_attempts: 3,
        })
        .unwrap();

        db.delete_person(person).unwrap();
        assert!(matches!(db.get_person(person), Err(GateError::NotFound)));
        assert!(db
            .resolve_policy("root", &key.fingerprint)
            .unwrap()
            .is_none());
        let connection = db.open_read_only().unwrap();
        for table in ["ssh_keys", "exam_attempts", "exam_passes"] {
            let count: u32 = connection
                .query_row(
                    &format!("SELECT count(*) FROM {table} WHERE person_id = ?1"),
                    [person],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0);
        }
    }

    #[test]
    fn draft_test_delete_and_bank_reference_rules_are_safe() {
        let (_directory, db) = database(Duration::from_secs(1));
        let legacy_publication = db.published_test().unwrap().unwrap();
        let draft = TestDefinitionInput {
            id: "draft-test".to_owned(),
            title: "Draft".to_owned(),
            bank_ids: vec![LEGACY_BANK_ID.to_owned(), "host-ssh".to_owned()],
            pass_threshold_percent: 80,
            max_attempts: 3,
            question_limit: None,
            shuffle_questions: true,
            shuffle_choices: true,
        };
        db.create_test(&draft).unwrap();
        assert_eq!(db.tests_using_bank("host-ssh").unwrap(), ["draft-test"]);
        db.delete_test("draft-test").unwrap();
        assert!(matches!(
            db.get_test("draft-test"),
            Err(GateError::NotFound)
        ));
        assert!(matches!(
            db.delete_test(LEGACY_BANK_ID),
            Err(GateError::Conflict(_))
        ));

        let archived = TestDefinitionInput {
            id: "archived-test".to_owned(),
            title: "Archived".to_owned(),
            bank_ids: vec![LEGACY_BANK_ID.to_owned()],
            pass_threshold_percent: 80,
            max_attempts: 3,
            question_limit: None,
            shuffle_questions: true,
            shuffle_choices: true,
        };
        db.create_test(&archived).unwrap();
        let mut archived_quiz = sample_quiz();
        archived_quiz.title = archived.title;
        db.publish_test("archived-test", &archived_quiz).unwrap();
        db.activate_publication(LEGACY_BANK_ID, legacy_publication.publication_id)
            .unwrap();
        assert!(matches!(
            db.delete_test("archived-test"),
            Err(GateError::Conflict(_))
        ));
    }

    #[test]
    fn attempt_limit_is_transactional() {
        let (_directory, db) = database(Duration::from_secs(1));
        let person = db.create_person("Alice", None).unwrap();
        for _ in 0..3 {
            db.record_attempt(&AttemptInput {
                person_id: person,
                test_id: LEGACY_BANK_ID,
                revision: &db.published_test().unwrap().unwrap().revision,
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
                test_id: LEGACY_BANK_ID,
                revision: &db.published_test().unwrap().unwrap().revision,
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
        let error = db.create_person("Contender", None).unwrap_err();
        assert!(matches!(
            error,
            GateError::Database(rusqlite::Error::SqliteFailure(code, _))
                if matches!(code.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
        ));
        transaction.rollback().unwrap();
        db.create_person("Recovered", None).unwrap();
    }

    #[test]
    fn validates_unix_users() {
        validate_unix_username("root").unwrap();
        #[cfg(unix)]
        assert!(validate_unix_username("definitely_missing_ssh_exam_user").is_err());
        assert!(validate_unix_username("Invalid!").is_err());
    }

    #[test]
    fn publishing_changed_content_requires_a_new_pass() {
        let (_directory, db) = database(Duration::from_secs(1));
        let person = db.create_person("Alice", Some("root")).unwrap();
        let key = db.add_key(person, KEY_1).unwrap();
        let first = db.published_test().unwrap().unwrap();
        db.record_attempt(&AttemptInput {
            person_id: person,
            test_id: &first.test_id,
            revision: &first.revision,
            score: 1,
            total: 1,
            passed: true,
            answers_json: "[0]",
            max_attempts: 3,
        })
        .unwrap();
        assert!(
            db.resolve_policy("root", &key.fingerprint)
                .unwrap()
                .unwrap()
                .passed
        );

        let mut changed = sample_quiz();
        changed.questions[0].prompt = "Still ready?".to_owned();
        let second = db.publish_test(LEGACY_BANK_ID, &changed).unwrap();
        assert_ne!(first.revision, second.revision);
        assert!(
            !db.resolve_policy("root", &key.fingerprint)
                .unwrap()
                .unwrap()
                .passed
        );

        let republished = db.publish_test(LEGACY_BANK_ID, &changed).unwrap();
        assert_eq!(second.revision, republished.revision);

        let publications = db.list_publications(LEGACY_BANK_ID).unwrap();
        assert_eq!(publications.len(), 2);
        let original = publications
            .iter()
            .find(|publication| publication.revision == first.revision)
            .unwrap();
        assert!(!original.active);
        let restored = db
            .activate_publication(LEGACY_BANK_ID, original.publication_id)
            .unwrap();
        assert_eq!(restored.revision, first.revision);
        assert!(
            db.resolve_policy("root", &key.fingerprint)
                .unwrap()
                .unwrap()
                .passed
        );
    }

    #[test]
    fn unassigned_account_fails_closed_and_can_be_reassigned() {
        let (_directory, db) = database(Duration::from_secs(1));
        let person = db.create_person("First", Some("root")).unwrap();
        let key = db.add_key(person, KEY_1).unwrap();
        assert!(db
            .resolve_policy("root", &key.fingerprint)
            .unwrap()
            .is_some());
        db.set_person_unix_username(person, None).unwrap();
        assert!(db
            .resolve_policy("root", &key.fingerprint)
            .unwrap()
            .is_none());
        db.set_person_unix_username(person, Some("root")).unwrap();
        assert!(db
            .resolve_policy("root", &key.fingerprint)
            .unwrap()
            .is_some());
    }

    #[test]
    fn migration_from_v1_adds_bank_and_unifies_access() {
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
        assert_eq!(view.person.unix_username.as_deref(), Some("root"));
        let connection = db.open_read_only().unwrap();
        let versions: u32 = connection
            .query_row("SELECT count(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(versions, 5);
    }

    #[test]
    fn migration_from_v2_leaves_shared_unix_account_unassigned() {
        let directory = TempDir::new().unwrap();
        let db = Db::new(directory.path().join("gate.db"), Duration::from_secs(1));
        let connection = db.open_writable().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY);\n\
                 INSERT INTO schema_migrations(version) VALUES (1), (2);",
            )
            .unwrap();
        connection.execute_batch(MIGRATION_1).unwrap();
        connection.execute_batch(MIGRATION_2).unwrap();
        connection
            .execute_batch(
                "INSERT INTO persons(id, display_name, created_at) VALUES\n\
                     (1, 'First', 1), (2, 'Second', 1);\n\
                 INSERT INTO login_bindings(\n\
                     person_id, unix_username, access_mode, permitopen_json, bank_id, enabled, created_at\n\
                 ) VALUES\n\
                     (1, 'root', 'shell', '[]', 'legacy', 0, 1),\n\
                     (1, 'root', 'proxyjump', '[\"target.example.org:22\"]', 'host-ssh', 1, 2),\n\
                     (2, 'root', 'proxyjump', '[\"target.example.org:22\"]', 'network-topology', 1, 3);",
            )
            .unwrap();
        drop(connection);

        db.initialize().unwrap();
        let views = db.list_people().unwrap();
        assert_eq!(views.len(), 2);
        assert!(views[0].person.unix_username.is_none());
        assert!(views[1].person.unix_username.is_none());
    }

    #[test]
    fn migration_from_v3_carries_pass_once_then_clears_legacy_state() {
        let directory = TempDir::new().unwrap();
        let db = Db::new(directory.path().join("gate.db"), Duration::from_secs(1));
        let connection = db.open_writable().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY);
                 INSERT INTO schema_migrations(version) VALUES (1), (2), (3);",
            )
            .unwrap();
        connection.execute_batch(MIGRATION_1).unwrap();
        connection.execute_batch(MIGRATION_2).unwrap();
        connection.execute_batch(MIGRATION_3).unwrap();
        connection
            .execute_batch(
                "INSERT INTO persons(id, display_name, passed_at, created_at)
                     VALUES (1, 'Migrated', 1234, 1);
                 INSERT INTO ssh_keys(
                     id, person_id, fingerprint, key_type, key_base64, created_at
                 ) VALUES (
                     1, 1, 'SHA256:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ',
                     'ssh-ed25519', 'aGVsbG8=', 1
                 );
                 INSERT INTO login_bindings(person_id, unix_username, created_at)
                     VALUES (1, 'root', 1);",
            )
            .unwrap();
        drop(connection);

        db.initialize().unwrap();
        db.ensure_legacy_test(&sample_quiz()).unwrap();
        let policy = db
            .resolve_policy("root", "SHA256:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ")
            .unwrap()
            .unwrap();
        assert!(policy.passed);
        let connection = db.open_read_only().unwrap();
        let legacy_pass: Option<i64> = connection
            .query_row("SELECT passed_at FROM persons WHERE id = 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(legacy_pass.is_none());
    }

    #[test]
    fn migration_from_v4_leaves_multiple_person_accounts_unassigned() {
        let directory = TempDir::new().unwrap();
        let db = Db::new(directory.path().join("gate.db"), Duration::from_secs(1));
        let connection = db.open_writable().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY);
                 INSERT INTO schema_migrations(version) VALUES (1), (2), (3), (4);",
            )
            .unwrap();
        connection.execute_batch(MIGRATION_1).unwrap();
        connection.execute_batch(MIGRATION_2).unwrap();
        connection.execute_batch(MIGRATION_3).unwrap();
        connection.execute_batch(MIGRATION_4).unwrap();
        connection
            .execute_batch(
                "INSERT INTO persons(id, display_name, created_at)
                     VALUES (1, 'Ambiguous', 1);
                 INSERT INTO login_bindings(person_id, unix_username, enabled, created_at)
                     VALUES (1, 'account-a', 1, 1), (1, 'account-b', 1, 2);",
            )
            .unwrap();
        drop(connection);

        db.initialize().unwrap();
        let person = db.list_people().unwrap().pop().unwrap().person;
        assert!(person.unix_username.is_none());
        let connection = db.open_read_only().unwrap();
        let old_table_exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'login_bindings')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!old_table_exists);
    }
}
